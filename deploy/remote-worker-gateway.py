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
from crucible.network_probe import (  # noqa: E402
    CHALLENGE_ID, GAP_CHALLENGE_ID, GAP_PORTS, GAP_SINK_HOST, gap_port, probe_host,
)
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
GAP_SINK_PREFIX = "crucible-gap-sink-"
GAP_NET = "crucible-gap-net"
GAP_SUBNET = "172.30.81.0/24"
GAP_BRIDGE = "br-crucible-gap"


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


def _validate_gap_policy(value: Any) -> tuple[int, int] | None:
    """Revalidate the complete model artifact before translating it to iptables."""
    if value is None:
        return None
    from crucible.evolver import BlueEvolver, WrittenRule
    rule = WrittenRule.from_dict(value)
    if (rule.version != 3 or rule.challenge_id != GAP_CHALLENGE_ID
            or rule.to_dict() != value or
            BlueEvolver._canonical_rule(rule).plugin_id != rule.plugin_id):
        raise ValueError("firewall policy artifact is invalid")
    assert rule.port_start is not None and rule.port_end is not None
    return rule.port_start, rule.port_end


def _gap_guest_image_and_network(cid: str) -> tuple[str, str]:
    inspected = _run(["docker", "inspect", cid], timeout=15)
    if inspected.returncode != 0:
        raise ValueError("gap guest inspection failed")
    info = json.loads(inspected.stdout)[0]
    image = info.get("Image")
    if not isinstance(image, str) or not re.fullmatch(r"sha256:[a-f0-9]{64}", image):
        raise ValueError("gap guest image is not immutable")
    policy = json.loads(NET_CONFIG.read_text())
    network = policy["network"]
    if (list(info["NetworkSettings"]["Networks"]) != [network]
            or ipaddress.IPv4Address(GAP_SINK_HOST) in
            ipaddress.IPv4Network(policy["subnet"], strict=True)):
        raise ValueError("gap sink must use a separate routed bridge")
    return image, network


def _ensure_gap_network() -> str:
    """Route guest packets through FORWARD while sealing the sink's own egress."""
    inspection = _run(["docker", "network", "inspect", GAP_NET], timeout=15)
    if inspection.returncode != 0:
        created = _run(["docker", "network", "create", "--driver", "bridge",
                        "--subnet", GAP_SUBNET, "--opt",
                        f"com.docker.network.bridge.name={GAP_BRIDGE}", GAP_NET],
                       timeout=30)
        if created.returncode != 0:
            raise ValueError("gap sink network unavailable")
        inspection = _run(["docker", "network", "inspect", GAP_NET], timeout=15)
    if inspection.returncode != 0:
        raise ValueError("gap sink network inspection failed")
    info = json.loads(inspection.stdout)[0]
    if (info.get("Driver") != "bridge" or info.get("EnableIPv6") is not False
            or [item.get("Subnet") for item in info["IPAM"]["Config"]] != [GAP_SUBNET]
            or info.get("Options", {}).get("com.docker.network.bridge.name") != GAP_BRIDGE):
        raise ValueError("gap sink network does not match the fixed policy")
    gateway = ipaddress.IPv4Address(info["IPAM"]["Config"][0]["Gateway"])
    if gateway not in ipaddress.IPv4Network(GAP_SUBNET) or str(gateway) == GAP_SINK_HOST:
        raise ValueError("gap sink bridge gateway is invalid")
    worker_policy = json.loads(NET_CONFIG.read_text())
    primary_input = next((row for row in _firewall_rules("INPUT")
                          if row.startswith("-A ")), "")
    if (f"-i {worker_policy['bridge']}" not in primary_input
            or f"-s {worker_policy['subnet']}" not in primary_input
            or "-j DROP" not in primary_input):
        raise ValueError("primary worker INPUT guard is not first")
    # Sink-originated connections cannot reach the host or Internet.  Return
    # packets for guest-initiated, established TCP connections remain possible.
    guards = (
        (["iptables", "-w", "-C", "INPUT", "-i", GAP_BRIDGE, "-s", GAP_SUBNET,
          "-j", "DROP"], ["iptables", "-w", "-I", "INPUT", "2", "-i", GAP_BRIDGE,
                          "-s", GAP_SUBNET, "-j", "DROP"]),
        (["iptables", "-w", "-C", "DOCKER-USER", "-i", GAP_BRIDGE, "-s", GAP_SUBNET,
          "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"],
         ["iptables", "-w", "-I", "DOCKER-USER", "2", "-i", GAP_BRIDGE,
          "-s", GAP_SUBNET, "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED",
          "-j", "ACCEPT"]),
        (["iptables", "-w", "-C", "DOCKER-USER", "-i", GAP_BRIDGE, "-s", GAP_SUBNET,
          "-j", "DROP"], ["iptables", "-w", "-I", "DOCKER-USER", "3", "-i",
                          GAP_BRIDGE, "-s", GAP_SUBNET, "-j", "DROP"]),
    )
    for present, insert in guards:
        if _run(present, timeout=15).returncode != 0 and _run(insert, timeout=15).returncode != 0:
            raise ValueError("gap sink host/egress guard unavailable")
    _verify_gap_network_guards()
    return str(gateway)


def _flag_pairs(row: str, chain: str) -> dict[str, str] | None:
    parts = shlex.split(row)
    if (parts[:2] != ["-A", chain] or len(parts) < 4
            or (len(parts) - 2) % 2):
        return None
    pairs = dict(zip(parts[2::2], parts[3::2]))
    return pairs if len(pairs) == (len(parts) - 2) // 2 else None


def _verify_gap_network_guards() -> None:
    worker_policy = json.loads(NET_CONFIG.read_text())
    input_rules = [row for row in _firewall_rules("INPUT") if row.startswith("-A ")]
    forward_rules = [row for row in _firewall_rules("DOCKER-USER") if row.startswith("-A ")]
    if len(input_rules) < 2 or len(forward_rules) < 3:
        raise ValueError("gap network guards are incomplete")
    if _flag_pairs(input_rules[0], "INPUT") != {
        "-s": worker_policy["subnet"], "-i": worker_policy["bridge"], "-j": "DROP"
    }:
        raise ValueError("primary worker INPUT guard moved")
    if _flag_pairs(input_rules[1], "INPUT") != {
        "-s": GAP_SUBNET, "-i": GAP_BRIDGE, "-j": "DROP"
    }:
        raise ValueError("gap sink host access is not blocked second")
    if _flag_pairs(forward_rules[0], "DOCKER-USER") != {
        "-s": worker_policy["subnet"], "-i": worker_policy["bridge"],
        "-j": EGRESS_CHAIN
    }:
        raise ValueError("primary worker forwarding guard moved")
    established = _flag_pairs(forward_rules[1], "DOCKER-USER")
    if (established is None or {k: v for k, v in established.items() if k != "--ctstate"} != {
            "-s": GAP_SUBNET, "-i": GAP_BRIDGE, "-m": "conntrack", "-j": "ACCEPT"
        } or set(established.get("--ctstate", "").split(",")) != {"ESTABLISHED", "RELATED"}):
        raise ValueError("gap sink return path is not restricted to established traffic")
    if _flag_pairs(forward_rules[2], "DOCKER-USER") != {
        "-s": GAP_SUBNET, "-i": GAP_BRIDGE, "-j": "DROP"
    }:
        raise ValueError("gap sink outbound traffic is not blocked")


def _gap_only_guest(cid: str) -> None:
    listing = _run(["docker", "ps", "-q", "--no-trunc", "--filter",
                    "label=crucible.managed=true"], timeout=15)
    ids = _full_container_ids(listing)
    if ids != [cid]:
        raise ValueError("firewall gap challenge requires one managed guest")
    sinks = _run(["docker", "ps", "-aq", "--no-trunc", "--filter",
                  "label=crucible.gap.sink=true"], timeout=15)
    if sinks.returncode != 0 or sinks.stdout.strip():
        raise ValueError("an earlier firewall gap sink remains active")
    if any("crucible-gap-" in row for row in _firewall_rules(EGRESS_CHAIN)):
        raise ValueError("an earlier firewall gap rule remains active")


def _assert_no_gap_artifacts() -> None:
    """Prevent a newly created guest from inheriting a crashed guest's lease."""
    sinks = _run(["docker", "ps", "-aq", "--no-trunc", "--filter",
                  "label=crucible.gap.sink=true"], timeout=15)
    sink_ids = _full_container_ids(sinks)
    if sink_ids is None or sink_ids:
        raise ValueError("firewall gap sink has not been cleaned")
    if any("crucible-gap-" in row for row in _firewall_rules(EGRESS_CHAIN)):
        raise ValueError("firewall gap rules have not been cleaned")


def _schedule_gap_cleanup(episode_id: str) -> None:
    unit = f"crucible-gap-cleanup-{episode_id[3:]}"
    script = ROOT / "infra" / "gap-cleanup.py"
    scheduled = _run(["systemd-run", "--quiet", "--collect", f"--unit={unit}",
                      "--on-active=180s", sys.executable, str(script),
                      "--episode", episode_id], timeout=15)
    if scheduled.returncode != 0:
        raise ValueError("firewall gap cleanup watchdog unavailable")


def _start_gap_sink(cid: str, episode_id: str) -> tuple[str, str]:
    image, _ = _gap_guest_image_and_network(cid)
    gateway = _ensure_gap_network()
    name = GAP_SINK_PREFIX + episode_id
    command = ["docker", "run", "--detach", "--rm", "--name", name,
               "--label", "crucible.gap.sink=true", "--label",
               f"crucible.gap.episode={episode_id}",
               "--network", GAP_NET, "--ip", GAP_SINK_HOST,
               "--read-only", "--tmpfs",
               "/run/crucible-sink:rw,nosuid,nodev,size=1m,uid=10001,gid=10001,mode=0700",
               "--user", "10001:10001", "--cap-drop", "ALL",
               "--security-opt", "no-new-privileges", "--security-opt",
               f"seccomp={ROOT / 'infra' / 'crucible-seccomp.json'}",
               "--pids-limit", "16", "--memory", "64m", "--memory-swap", "64m",
               "--cpus", "0.25", "--log-driver", "none",
               image, "python", "/opt/crucible/gap-sink.py"]
    started = _run(command, timeout=40)
    if started.returncode != 0 or not CID.fullmatch(started.stdout.strip()):
        raise ValueError("keyless gap sink failed to start")
    for attempt in range(30):
        ready = _run(["docker", "exec", name, "python", "/opt/crucible/gap-sink.py",
                      "--ready"], timeout=5)
        if ready.returncode == 0 and ready.stdout.strip() == "ready":
            return name, gateway
        if attempt < 29:
            time.sleep(0.2)
    raise ValueError("keyless gap sink did not become ready")


def _gap_sink_count(name: str, source: str, port: int) -> int:
    counted = _run(["docker", "exec", name, "python", "/opt/crucible/gap-sink.py",
                    "--count", source, str(port)], timeout=5)
    value = counted.stdout.strip()
    if counted.returncode != 0 or not value.isdigit():
        raise ValueError("gap sink receipt counter unavailable")
    return int(value)


def _gap_rule_packets(marker: str) -> int:
    return _probe_drop_count(marker)


def _verify_gap_rule_order(accept_marker: str, blue_marker: str | None,
                           source: str, accept_ports: str,
                           blue_ports: str | None) -> bool:
    rules = [shlex.split(row) for row in _firewall_rules(EGRESS_CHAIN)
             if row.startswith(f"-A {EGRESS_CHAIN} ")]
    if not rules or rules[-1] != ["-A", EGRESS_CHAIN, "-j", "DROP"]:
        raise ValueError("gap firewall lost its final DROP")
    positions: dict[str, int] = {}
    for index, row in enumerate(rules):
        if "--comment" not in row:
            continue
        marker = row[row.index("--comment") + 1]
        if marker not in {accept_marker, blue_marker}:
            continue
        if marker in positions:
            raise ValueError("duplicate gap firewall marker")
        expected_target = "ACCEPT" if marker == accept_marker else "DROP"
        expected_ports = accept_ports if marker == accept_marker else blue_ports
        if ("-s" not in row or row[row.index("-s") + 1] not in {source, f"{source}/32"}
                or "-d" not in row or row[row.index("-d") + 1]
                not in {GAP_SINK_HOST, f"{GAP_SINK_HOST}/32"}
                or "-p" not in row or row[row.index("-p") + 1] != "tcp"
                or "--dport" not in row or row[row.index("--dport") + 1] != expected_ports
                or "-j" not in row or row[row.index("-j") + 1] != expected_target):
            raise ValueError("gap firewall rule changed")
        positions[marker] = index
    if accept_marker not in positions or positions[accept_marker] >= len(rules) - 1:
        raise ValueError("gap baseline ACCEPT is unavailable")
    if blue_marker is not None:
        if blue_marker not in positions or positions[blue_marker] >= positions[accept_marker]:
            raise ValueError("Blue DROP is not ahead of baseline ACCEPT")
        return True
    return False


@contextmanager
def _firewall_gap_session(cid: str, episode_id: str, port: int,
                          policy_value: Any):
    """Run one bounded, watchdog-backed ACCEPT/Blue-DROP comparison."""
    if port not in GAP_PORTS or (port == 18443) != (policy_value is None):
        raise ValueError("firewall gap stage does not match fixed destination")
    blue_range = _validate_gap_policy(policy_value)
    source, subnet, bridge = _probe_source_ip(cid)
    forward = next((row for row in _firewall_rules("DOCKER-USER") if row.startswith("-A ")), "")
    parts = shlex.split(forward)
    pairs = dict(zip(parts[2::2], parts[3::2]))
    if (len(parts) != 8 or parts[:2] != ["-A", "DOCKER-USER"]
            or len(pairs) != 3 or pairs != {"-i": bridge, "-s": subnet,
                                               "-j": EGRESS_CHAIN}):
        raise ValueError("gap firewall is not first in forwarding path")
    _gap_only_guest(cid)
    sink_name = GAP_SINK_PREFIX + episode_id
    accept_marker = f"crucible-gap-{episode_id}-accept"
    blue_marker = f"crucible-gap-{episode_id}-blue" if blue_range else None
    cleanup = [sys.executable, str(ROOT / "infra" / "gap-cleanup.py"),
               "--episode", episode_id]
    try:
        sink_name, sink_gateway = _start_gap_sink(cid, episode_id)
        active = [row for row in _firewall_rules(EGRESS_CHAIN)
                  if row.startswith(f"-A {EGRESS_CHAIN} ")]
        if not active or active[-1] != f"-A {EGRESS_CHAIN} -j DROP":
            raise ValueError("gap firewall has no final DROP")
        # Arm the independent crash watchdog after bounded sink startup and
        # immediately before opening the temporary route. If startup fails,
        # no ACCEPT can have been installed.
        _schedule_gap_cleanup(episode_id)
        # Place challenge rules before the rate-limited LOG as well as DROP.
        position = len(active) - 1 if len(active) > 1 and " -j LOG" in active[-2] else len(active)
        accept_ports = "18443:18444"
        accept_rule = ["-s", source, "-d", GAP_SINK_HOST, "-p", "tcp",
                       "--dport", accept_ports, "-m", "comment", "--comment",
                       accept_marker, "-j", "ACCEPT"]
        added = _run(["iptables", "-w", "-I", EGRESS_CHAIN, str(position),
                      *accept_rule], timeout=15)
        if added.returncode != 0:
            raise ValueError("gap baseline ACCEPT installation failed")
        blue_ports = None
        if blue_range is not None:
            blue_ports = f"{blue_range[0]}:{blue_range[1]}"
            blue_rule = ["-s", source, "-d", GAP_SINK_HOST, "-p", "tcp",
                         "--dport", blue_ports, "-m", "comment", "--comment",
                         blue_marker, "-j", "DROP"]
            added_blue = _run(["iptables", "-w", "-I", EGRESS_CHAIN,
                               str(position), *blue_rule], timeout=15)
            if added_blue.returncode != 0:
                raise ValueError("Blue firewall DROP installation failed")
        order_ok = _verify_gap_rule_order(accept_marker, blue_marker, source,
                                          accept_ports, blue_ports)
        _verify_gap_network_guards()

        def measured() -> dict[str, Any]:
            _verify_gap_network_guards()
            _verify_gap_rule_order(accept_marker, blue_marker, source,
                                   accept_ports, blue_ports)
            receipts = _gap_sink_count(sink_name, "*", port)
            if port == 18443 and receipts == 0:
                # The TCP handshake may complete before accept() appends the
                # receipt; wait briefly without extending the network lease.
                for _ in range(10):
                    time.sleep(0.1)
                    receipts = _gap_sink_count(sink_name, "*", port)
                    if receipts:
                        break
            if receipts:
                # Docker may SNAT cross-bridge traffic to the sink bridge's
                # gateway. Only that attested address or the guest IP counts
                # as a receipt from this exclusive one-guest challenge.
                expected = (_gap_sink_count(sink_name, source, port)
                            + _gap_sink_count(sink_name, sink_gateway, port))
                if expected != receipts:
                    raise ValueError("gap sink receipt came from an unexpected peer")
            result: dict[str, Any] = {
                "firewall_accept_packets": _gap_rule_packets(accept_marker),
                "sink_connections": receipts,
            }
            if blue_marker is not None:
                result["firewall_blue_drop_packets"] = _gap_rule_packets(blue_marker)
                result["baseline_accept_behind_blue_drop"] = order_ok
            return result

        yield measured
    finally:
        removed = _run(cleanup, timeout=45)
        if removed.returncode != 0:
            raise ValueError("firewall gap cleanup failed; watchdog remains armed")


def _scan_result(raw: dict[str, Any], *, drop_packets: int | None = None,
                 gap_proof: dict[str, Any] | None = None) -> dict[str, Any]:
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
    if gap_proof is not None:
        for field in ("firewall_accept_packets", "firewall_blue_drop_packets",
                      "sink_connections"):
            count = gap_proof.get(field)
            if type(count) is int and 0 <= count <= 1_000_000:
                result[field] = count
        if gap_proof.get("baseline_accept_behind_blue_drop") is True:
            result["baseline_accept_behind_blue_drop"] = True
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
        if set(payload) != {"url"}:
            return None, "D1"
        if challenge_id == CHALLENGE_ID and probe_host(payload.get("url")) is not None:
            pass
        elif challenge_id == GAP_CHALLENGE_ID and gap_port(payload.get("url")) is not None:
            pass
        else:
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
            _assert_no_gap_artifacts()
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
        gap_fields = challenge_fields | {"firewall_policy"}
        if set(request) not in (ordinary_fields, challenge_fields, gap_fields):
            raise ValueError("invalid exec request")
        challenge_id = request.get("challenge_id")
        if (set(request) in (challenge_fields, gap_fields)
                and challenge_id not in {CHALLENGE_ID, GAP_CHALLENGE_ID}):
            raise ValueError("invalid challenge ID")
        if "firewall_policy" in request and challenge_id != GAP_CHALLENGE_ID:
            raise ValueError("firewall policy requires gap challenge")
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
        gap_proof = None
        if action["kind"] == "net_connect" and challenge_id == GAP_CHALLENGE_ID:
            if runtime != "kata-qemu":
                raise ValueError("firewall gap challenge requires Kata")
            port = gap_port(action["payload"]["url"])
            assert port is not None
            policy = request.get("firewall_policy")
            with _create_lock(), _firewall_gap_session(cid, episode_id, port, policy) as measure:
                run = _run(command, input_text=input_text, timeout=85, env=environment)
                gap_proof = measure()
        elif action["kind"] == "net_connect":
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
            raw, drop_packets=packets if action["kind"] == "net_connect"
            and challenge_id == CHALLENGE_ID else None,
            gap_proof=gap_proof)}
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
