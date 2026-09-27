#!/usr/bin/env python3
"""Forced SSH command on the sandbox VM; no model or management key is used.

Every response is scanned on this host before it crosses the SSH boundary.
The gateway is intentionally small and only invokes the audited worker scripts.
"""

from __future__ import annotations

import base64
import binascii
from contextlib import contextmanager
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import signal
import stat
import subprocess
import sys
import tempfile
import time
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from crucible.network_policy import SAFE_FETCH_URLS  # noqa: E402
from crucible.network_probe import CHALLENGE_ID, probe_host  # noqa: E402
from crucible.plugins.d6_output_filter import OutputFilterPlugin  # noqa: E402
from crucible.scenarios import CANARY  # noqa: E402
from crucible.safe_commands import parse_safe_command  # noqa: E402

MAX_REQUEST = 256 * 1024
MAX_FILE = 32 * 1024
FILES = {"scenario.json", "README.md", "reference.txt", "service.env"}
CID = re.compile(r"[a-f0-9]{64}\Z")
EPISODE = re.compile(r"ep_[a-f0-9]{12}\Z")
SCANNER = OutputFilterPlugin((CANARY,))
RUN_ENV = {"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "HOME": "/root"}
RUNTIME_CONFIG = Path("/etc/crucible/worker-runtime")
NET_CONFIG = Path("/var/lib/crucible/net.json")
ALLOWED_RUNTIMES = frozenset({"runc", "runsc-oci", "kata-qemu"})
MAX_SESSIONS = 4
EGRESS_CHAIN = "CRUCIBLE_EGRESS"


def _configured_runtime() -> str:
    """Use only the root-owned VM2 runtime choice, never an SSH environment value."""
    try:
        descriptor = os.open(RUNTIME_CONFIG, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            metadata = os.fstat(descriptor)
            if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0
                    or metadata.st_mode & 0o077 or metadata.st_size > 32):
                raise ValueError("invalid worker runtime configuration")
            value = os.read(descriptor, 33).decode("ascii")
        finally:
            os.close(descriptor)
    except (OSError, UnicodeError):
        raise ValueError("worker runtime configuration unavailable") from None
    if value not in {runtime + "\n" for runtime in ALLOWED_RUNTIMES}:
        raise ValueError("invalid worker runtime configuration")
    return value[:-1]


def _run(args: list[str], *, input_text: str | None = None, timeout: int = 30,
         env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    process = subprocess.Popen(args, stdin=subprocess.PIPE if input_text is not None else subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, errors="replace",
                               start_new_session=True, env=env or RUN_ENV)
    try:
        stdout, stderr = process.communicate(input=input_text, timeout=timeout)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        process.communicate()
        raise ValueError("worker operation timed out") from None
    if len(stdout) > 256 * 1024 or len(stderr) > 256 * 1024:
        raise ValueError("worker operation output exceeded limit")
    return subprocess.CompletedProcess(args, process.returncode, stdout, stderr)


def _full_container_ids(result: subprocess.CompletedProcess[str]) -> list[str] | None:
    """Reject truncated Docker IDs so cleanup and capacity cannot miss workers."""
    if result.returncode != 0:
        return None
    ids = result.stdout.splitlines()
    if any(not CID.fullmatch(cid) for cid in ids):
        return None
    return ids


def _cleanup(episode_id: str, known_cid: str | None = None) -> bool:
    if not EPISODE.fullmatch(episode_id):
        return False
    if known_cid is not None and not CID.fullmatch(known_cid):
        return False
    listing = _run(["docker", "ps", "-aq", "--no-trunc", "--filter",
                    f"label=crucible.episode={episode_id}"], timeout=20)
    ids = _full_container_ids(listing)
    if ids is None:
        return False
    kata_ids: set[str] = set()
    for cid in ids:
        runtime = _run(["docker", "inspect", "--format", "{{.HostConfig.Runtime}}", cid], timeout=15)
        if runtime.returncode != 0 or runtime.stdout.strip() not in ALLOWED_RUNTIMES:
            return False
        if runtime.stdout.strip() == "kata-qemu":
            kata_ids.add(cid)
    try:
        selected_runtime = _configured_runtime()
    except ValueError:
        selected_runtime = None
    if selected_runtime == "kata-qemu" and known_cid is not None:
        kata_ids.add(known_cid)
    if ids and _run(["docker", "rm", "-f", *ids], timeout=30).returncode != 0:
        return False
    verify = _run(["docker", "ps", "-aq", "--no-trunc", "--filter",
                   f"label=crucible.episode={episode_id}"], timeout=20)
    if _full_container_ids(verify) != []:
        return False
    if selected_runtime is None:
        return False
    # A cleanup request without a CID cannot attest an already-removed Kata
    # VM. The caller must retry destroy with its known full task ID.
    if selected_runtime == "kata-qemu" and not kata_ids:
        return False
    for cid in kata_ids:
        # Docker can return from rm before the shim drops its last socket or
        # Kata removes its state directory. A bounded retry distinguishes that
        # normal cleanup lag from an orphaned guest; success is still required.
        for attempt in range(10):
            proof = _run([sys.executable, str(ROOT / "infra" / "verify-kata.py"),
                          "--destroyed", cid], timeout=5)
            if proof.returncode == 0:
                break
            if attempt < 9:
                time.sleep(0.5)
        else:
            return False
    return True


@contextmanager
def _create_lock():
    descriptor = os.open("/var/lock/crucible-remote-gateway.lock",
                         os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def _ensure_capacity(episode_id: str) -> None:
    existing = _run(["docker", "ps", "-aq", "--no-trunc", "--filter",
                     "label=crucible.managed=true"], timeout=20)
    ids = _full_container_ids(existing)
    if ids is None:
        raise ValueError("cannot inspect worker capacity")
    if len(ids) >= MAX_SESSIONS:
        raise ValueError("remote worker capacity reached")
    collision = _run(["docker", "ps", "-aq", "--no-trunc", "--filter",
                      f"label=crucible.episode={episode_id}"], timeout=20)
    collision_ids = _full_container_ids(collision)
    if collision_ids is None:
        raise ValueError("cannot inspect episode collision")
    if collision_ids:
        raise ValueError("episode label is already in use")


def _session_matches(cid: str, episode_id: str, expected_runtime: str | None = None) -> bool:
    if not CID.fullmatch(cid) or not EPISODE.fullmatch(episode_id):
        return False
    check = _run(["docker", "inspect", "--format",
                  '{{ index .Config.Labels "crucible.episode" }}|{{ index .Config.Labels "crucible.managed" }}|{{ .HostConfig.Runtime }}', cid],
                 timeout=15)
    if check.returncode != 0:
        return False
    fields = check.stdout.strip().split("|")
    return (len(fields) == 3 and fields[:2] == [episode_id, "true"]
            and fields[2] in ALLOWED_RUNTIMES
            and (expected_runtime is None or fields[2] == expected_runtime))


def _firewall_rules(chain: str) -> list[str]:
    listing = _run(["iptables", "-w", "-S", chain], timeout=15)
    if listing.returncode != 0:
        raise ValueError("worker firewall unavailable")
    return listing.stdout.splitlines()


def _probe_source_ip(cid: str) -> tuple[str, str, str]:
    """Bind one proof to the guest's sole Docker network and source address."""
    if NET_CONFIG.is_symlink():
        raise ValueError("worker network configuration is unsafe")
    metadata = NET_CONFIG.stat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_mode & 0o022:
        raise ValueError("worker network configuration is unsafe")
    policy = json.loads(NET_CONFIG.read_text())
    network, bridge = policy["network"], policy["bridge"]
    subnet = ipaddress.IPv4Network(policy["subnet"], strict=True)
    inspection = _run(["docker", "inspect", cid], timeout=15)
    if inspection.returncode != 0:
        raise ValueError("worker network inspection failed")
    info = json.loads(inspection.stdout)
    networks = info[0]["NetworkSettings"]["Networks"]
    if list(networks) != [network]:
        raise ValueError("worker has an unexpected network")
    source = ipaddress.IPv4Address(networks[network]["IPAddress"])
    if source not in subnet:
        raise ValueError("worker address is outside policy subnet")
    return str(source), str(subnet), bridge


def _check_trace_rule(source: str, host: str, marker: str) -> None:
    """A targetless counter must sit immediately before the final DROP."""
    active = [shlex.split(row) for row in _firewall_rules(EGRESS_CHAIN)
              if row.startswith(f"-A {EGRESS_CHAIN} ")]
    if len(active) < 2 or active[-1] != ["-A", EGRESS_CHAIN, "-j", "DROP"]:
        raise ValueError("worker firewall has no final DROP")
    trace = active[-2]
    for flag, expected in (("-s", source), ("-d", host), ("-p", "tcp"),
                           ("--dport", "443"), ("--comment", marker)):
        if flag not in trace or trace[trace.index(flag) + 1].split("/")[0] != expected:
            raise ValueError("worker firewall trace rule moved")
    if "-j" in trace or "-g" in trace:
        raise ValueError("worker firewall trace changes the verdict")


def _probe_drop_count(marker: str) -> int:
    listing = _run(["iptables", "-w", "-nvx", "-L", EGRESS_CHAIN,
                    "--line-numbers"], timeout=15)
    if listing.returncode != 0:
        raise ValueError("worker firewall counter unavailable")
    matches = [row for row in listing.stdout.splitlines() if marker in row]
    if len(matches) != 1:
        raise ValueError("worker firewall counter is ambiguous")
    fields = matches[0].split()
    if len(fields) < 3 or not fields[0].isdigit() or not fields[1].isdigit():
        raise ValueError("worker firewall counter is invalid")
    return int(fields[1])


@contextmanager
def _probe_firewall_trace(cid: str, episode_id: str, host: str):
    """Measure only this guest's SYNs while preserving the kernel verdict."""
    source, subnet, bridge = _probe_source_ip(cid)
    forward = next((row for row in _firewall_rules("DOCKER-USER") if row.startswith("-A ")), "")
    # iptables may normalize option ordering when it renders `-S` (for
    # example, `-s` before `-i`), so compare the exact rule semantics.
    parts = shlex.split(forward)
    pairs = dict(zip(parts[2::2], parts[3::2]))
    if (len(parts) != 8 or parts[:2] != ["-A", "DOCKER-USER"]
            or len(pairs) != 3 or pairs != {"-i": bridge, "-s": subnet,
                                               "-j": EGRESS_CHAIN}):
        raise ValueError("worker firewall is not first in forwarding path")
    active = [row for row in _firewall_rules(EGRESS_CHAIN) if row.startswith(f"-A {EGRESS_CHAIN} ")]
    if not active or active[-1] != f"-A {EGRESS_CHAIN} -j DROP":
        raise ValueError("worker firewall has no final DROP")
    marker = f"crucible-{episode_id}"
    rule = ["-s", source, "-d", host, "-p", "tcp", "--dport", "443",
            "-m", "comment", "--comment", marker]
    inserted = _run(["iptables", "-w", "-I", EGRESS_CHAIN, str(len(active)), *rule], timeout=15)
    if inserted.returncode != 0:
        raise ValueError("worker firewall trace installation failed")
    try:
        _check_trace_rule(source, host, marker)

        def measured_packets() -> int:
            _check_trace_rule(source, host, marker)
            return _probe_drop_count(marker)

        yield measured_packets
    finally:
        removed = _run(["iptables", "-w", "-D", EGRESS_CHAIN, *rule], timeout=15)
        if removed.returncode != 0:
            raise ValueError("worker firewall trace removal failed")


def _scan_result(raw: dict[str, Any], *, drop_packets: int | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {"exit_code": int(raw.get("exit_code", 1))}
    worker_redactions = raw.get("redactions", 0)
    redactions = worker_redactions if type(worker_redactions) is int and 0 <= worker_redactions <= 1000 else 0
    for field in ("stdout", "stderr"):
        clean, count = SCANNER.redact(str(raw.get(field, ""))[:32_768])
        result[field] = clean
        redactions += count
    result["redactions"] = redactions
    if redactions:
        result["output_blocked"] = True
    for field in ("network_request_attempted", "network_response_received"):
        result[field] = raw.get(field) is True
    # The guest is untrusted.  Only the host-side iptables measurement may
    # create this proof field; a worker JSON value is ignored.
    if type(drop_packets) is int and 0 <= drop_packets <= 1_000_000:
        result["egress_drop_packets"] = drop_packets
    if raw.get("policy_denial") in {"D1", "D2", "D3", "D4", "D5", "D6"}:
        result["policy_denial"] = raw["policy_denial"]
    if type(raw.get("http_status")) is int and 100 <= raw["http_status"] <= 599:
        result["http_status"] = raw["http_status"]
    return result


def _check_action(value: Any, *, challenge_id: str | None = None) -> tuple[dict[str, Any] | None, str | None]:
    if not isinstance(value, dict) or set(value) != {"kind", "payload"}:
        raise ValueError("invalid action envelope")
    kind, payload = value["kind"], value["payload"]
    if kind not in {"shell", "http_get", "net_connect", "file_read", "file_write"} or not isinstance(payload, dict):
        raise ValueError("invalid action kind or payload")
    if len(json.dumps(value)) > 64 * 1024:
        raise ValueError("action exceeds size limit")
    from crucible.plugins_api import Action
    action = Action(kind, payload)
    if SCANNER.pre_exec(action).decision == "deny":
        return None, "D6"
    if kind == "shell":
        try:
            parse_safe_command(payload.get("cmd"))
        except (TypeError, ValueError):
            return None, "D3"
    if kind == "net_connect":
        if (challenge_id != CHALLENGE_ID or set(payload) != {"url"}
                or probe_host(payload.get("url")) is None):
            return None, "D1"
    elif kind == "http_get" and payload.get("url") not in SAFE_FETCH_URLS:
        return None, "D1"
    return {"kind": kind, "payload": payload}, None


def handle(request: dict[str, Any]) -> dict[str, Any]:
    op = request.get("op")
    episode_id = request.get("episode_id", "")
    if not isinstance(episode_id, str) or not EPISODE.fullmatch(episode_id):
        raise ValueError("invalid episode ID")
    if op == "create":
        if set(request) != {"op", "episode_id", "files"} or not isinstance(request["files"], dict):
            raise ValueError("invalid create request")
        files = request["files"]
        if not {"scenario.json", "README.md", "reference.txt"}.issubset(files) or not set(files).issubset(FILES):
            raise ValueError("invalid scenario files")
        with _create_lock():
            # Runtime activation takes this lock too. Read the selection after
            # acquiring it so a queued create cannot use the old runtime.
            runtime = _configured_runtime()
            _ensure_capacity(episode_id)
            with tempfile.TemporaryDirectory(prefix="crucible-remote-") as name:
                directory = Path(name)
                for filename, encoded in files.items():
                    if not isinstance(encoded, str):
                        raise ValueError("invalid scenario encoding")
                    try:
                        content = base64.b64decode(encoded, validate=True)
                    except binascii.Error:
                        raise ValueError("invalid scenario encoding") from None
                    if len(content) > MAX_FILE:
                        raise ValueError("scenario file exceeds limit")
                    (directory / filename).write_bytes(content)
                try:
                    created = _run([str(ROOT / "infra" / "create-worker.sh"), str(directory)],
                                   timeout=140, env={**RUN_ENV, "CRUCIBLE_EPISODE_ID": episode_id,
                                                     "CRUCIBLE_RUNTIME": runtime})
                    cid = created.stdout.strip().splitlines()[-1] if created.stdout.strip() else ""
                    if (created.returncode != 0 or not CID.fullmatch(cid)
                            or not _session_matches(cid, episode_id, runtime)):
                        raise ValueError("worker session creation failed")
                    return {"ok": True, "container_id": cid, "runtime": runtime}
                except Exception:
                    _cleanup(episode_id)
                    raise
    if op == "cleanup":
        if set(request) != {"op", "episode_id"}:
            raise ValueError("invalid cleanup request")
        with _create_lock():
            return {"ok": True, "destroyed": _cleanup(episode_id)}
    cid = request.get("container_id", "")
    if not isinstance(cid, str) or not CID.fullmatch(cid):
        raise ValueError("invalid container ID")
    if op == "destroy":
        if set(request) != {"op", "episode_id", "container_id"}:
            raise ValueError("invalid destroy request")
        with _create_lock():
            if _session_matches(cid, episode_id):
                _run([str(ROOT / "infra" / "destroy-worker.sh"), cid], timeout=30)
            return {"ok": True, "destroyed": _cleanup(episode_id, known_cid=cid)}
    if op == "exec":
        ordinary_fields = {"op", "episode_id", "container_id", "action"}
        challenge_fields = ordinary_fields | {"challenge_id"}
        if set(request) not in (ordinary_fields, challenge_fields):
            raise ValueError("invalid exec request")
        challenge_id = request.get("challenge_id")
        if (set(request) == challenge_fields and challenge_id != CHALLENGE_ID):
            raise ValueError("invalid challenge ID")
        if challenge_id is not None and (
            not isinstance(request.get("action"), dict)
            or request["action"].get("kind") != "net_connect"
        ):
            raise ValueError("challenge ID is only valid for net_connect")
        runtime = _configured_runtime()
        if not _session_matches(cid, episode_id, runtime):
            raise ValueError("worker session does not match episode")
        action, denial = _check_action(request["action"], challenge_id=challenge_id)
        if denial:
            return {"ok": True, "result": _scan_result({"exit_code": 77,
                    "stdout": "", "stderr": "remote pre-exec denied", "policy_denial": denial})}
        assert action is not None
        command = [str(ROOT / "infra" / "exec-worker.sh"), cid]
        input_text = json.dumps(action, ensure_ascii=True)
        environment = {**RUN_ENV, "CRUCIBLE_RUNTIME": runtime}
        if action["kind"] == "net_connect":
            # This is a deliberately bounded wall challenge.  The trusted
            # VM1 supervisor supplies challenge_id outside candidate payload.
            # A guest running on any other runtime is not proof of the Kata
            # isolation claim, so do not dispatch its network action.
            if runtime != "kata-qemu":
                raise ValueError("network wall challenge requires Kata")
            host = probe_host(action["payload"]["url"])
            assert host is not None
            with _create_lock(), _probe_firewall_trace(cid, episode_id, host) as drop_count:
                run = _run(command, input_text=input_text, timeout=85, env=environment)
                packets = drop_count()
        else:
            run = _run(command, input_text=input_text, timeout=85, env=environment)
        if run.returncode != 0:
            return {"ok": True, "result": _scan_result({"exit_code": run.returncode,
                    "stdout": "", "stderr": "worker runner failed"})}
        try:
            raw = json.loads(run.stdout.strip().splitlines()[-1])
        except (IndexError, ValueError):
            raise ValueError("worker result was invalid") from None
        if not isinstance(raw, dict):
            raise ValueError("worker result was invalid")
        return {"ok": True, "result": _scan_result(
            raw, drop_packets=packets if action["kind"] == "net_connect" else None)}
    raise ValueError("unsupported operation")


def main() -> int:
    if (sys.platform != "linux" or os.geteuid() != 0 or
            os.getenv("SSH_ORIGINAL_COMMAND") != "crucible-remote-v1"):
        return 77
    try:
        payload = sys.stdin.buffer.read(MAX_REQUEST + 1)
        if len(payload) > MAX_REQUEST:
            raise ValueError("request exceeds limit")
        request = json.loads(payload)
        if not isinstance(request, dict):
            raise ValueError("request must be an object")
        response = handle(request)
    except Exception:
        # No untrusted exception text or tool output leaves the sandbox host.
        response = {"ok": False, "error": "remote gateway rejected the request"}
    print(json.dumps(response, ensure_ascii=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
