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
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import tempfile
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from crucible.network_policy import SAFE_FETCH_URLS  # noqa: E402
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
ALLOWED_RUNTIMES = frozenset({"runc", "runsc-oci", "kata-qemu"})
MAX_SESSIONS = 4


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
        proof = _run([sys.executable, str(ROOT / "infra" / "verify-kata.py"),
                      "--destroyed", cid], timeout=30)
        if proof.returncode != 0:
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


def _scan_result(raw: dict[str, Any]) -> dict[str, Any]:
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
    if raw.get("policy_denial") in {"D1", "D2", "D3", "D4", "D5", "D6"}:
        result["policy_denial"] = raw["policy_denial"]
    if type(raw.get("http_status")) is int and 100 <= raw["http_status"] <= 599:
        result["http_status"] = raw["http_status"]
    return result


def _check_action(value: Any) -> tuple[dict[str, Any] | None, str | None]:
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
    if kind in {"http_get", "net_connect"} and payload.get("url") not in SAFE_FETCH_URLS:
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
        if set(request) != {"op", "episode_id", "container_id", "action"}:
            raise ValueError("invalid exec request")
        runtime = _configured_runtime()
        if not _session_matches(cid, episode_id, runtime):
            raise ValueError("worker session does not match episode")
        action, denial = _check_action(request["action"])
        if denial:
            return {"ok": True, "result": _scan_result({"exit_code": 77,
                    "stdout": "", "stderr": "remote pre-exec denied", "policy_denial": denial})}
        assert action is not None
        run = _run([str(ROOT / "infra" / "exec-worker.sh"), cid],
                   input_text=json.dumps(action, ensure_ascii=True), timeout=85,
                   env={**RUN_ENV, "CRUCIBLE_RUNTIME": runtime})
        if run.returncode != 0:
            return {"ok": True, "result": _scan_result({"exit_code": run.returncode,
                    "stdout": "", "stderr": "worker runner failed"})}
        try:
            raw = json.loads(run.stdout.strip().splitlines()[-1])
        except (IndexError, ValueError):
            raise ValueError("worker result was invalid") from None
        if not isinstance(raw, dict):
            raise ValueError("worker result was invalid")
        return {"ok": True, "result": _scan_result(raw)}
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
