#!/usr/bin/env bash
# Create one sandbox session for an episode. The caller must destroy the ID
# returned on stdout in a finally block. The idle container self-exits later.
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: create-worker.sh <scenario_dir>" >&2
  exit 2
fi
SCENARIO_DIR="$1"

if [[ "$(uname -s)" != Linux || "${EUID}" -ne 0 ]]; then
  echo "create-worker.sh requires root on the Linux sandbox host" >&2
  exit 77
fi
for binary in docker iptables ip6tables python3; do
  command -v "$binary" >/dev/null || { echo "missing $binary" >&2; exit 77; }
done
INFRA_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STATE_FILE="${CRUCIBLE_STATE_DIR:-/var/lib/crucible}/net.json"

# A remote or rootless daemon would not be protected by this host's firewall.
python3 - <<'PY'
import json
import os
import subprocess
host_override = os.environ.get("DOCKER_HOST")
if host_override and host_override != "unix:///var/run/docker.sock":
    raise SystemExit("remote/rootless DOCKER_HOST is not supported")
context = json.loads(subprocess.check_output(["docker", "context", "inspect"]))[0]
host = context["Endpoints"]["docker"]["Host"]
if host != "unix:///var/run/docker.sock":
    raise SystemExit("Docker context must use the local rootful daemon")
PY

POLICY_ROWS="$(python3 - "$STATE_FILE" <<'PY'
import ipaddress
import json
import os
import re
import stat
import sys
from pathlib import Path

path = Path(sys.argv[1])
for candidate in (path.parent, path):
    info = candidate.stat()
    if info.st_uid != 0 or info.st_mode & 0o022:
        raise SystemExit(f"unsafe network policy ownership/mode: {candidate}")
policy = json.loads(path.read_text())
net, subnet, bridge = (policy[key] for key in ("network", "subnet", "bridge"))
if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,62}", net):
    raise SystemExit("invalid network name in policy")
if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,14}", bridge):
    raise SystemExit("invalid bridge name in policy")
subnet = str(ipaddress.IPv4Network(subnet, strict=True))
print("NET", net)
print("SUBNET", subnet)
print("BRIDGE", bridge)
for host, addresses in policy["allow_hosts"].items():
    if not re.fullmatch(r"[a-z0-9][a-z0-9.-]{0,251}[a-z0-9]", host):
        raise SystemExit("invalid allowlist host in policy")
    for ip in addresses:
        ip = ipaddress.IPv4Address(ip)
        if not ip.is_global:
            raise SystemExit("non-public allowlist IP in policy")
        print("PIN", host, ip)
PY
)"
NET=""
SUBNET=""
BRIDGE=""
HOST_ARGS=()
while read -r kind field value; do
  case "$kind" in
    NET) NET="$field" ;;
    SUBNET) SUBNET="$field" ;;
    BRIDGE) BRIDGE="$field" ;;
    PIN) HOST_ARGS+=(--add-host "$field:$value") ;;
    *) echo "bad policy row" >&2; exit 2 ;;
  esac
done <<< "$POLICY_ROWS"
[[ -n "$NET" && -n "$SUBNET" && -n "$BRIDGE" ]] || {
  echo "incomplete network policy" >&2
  exit 2
}

python3 - "$NET" "$SUBNET" "$BRIDGE" <<'PY'
import json
import subprocess
import sys
net, subnet, bridge = sys.argv[1:]
info = json.loads(subprocess.check_output(["docker", "network", "inspect", net]))[0]
if (info["Driver"] != "bridge" or info["EnableIPv6"] or
        [entry.get("Subnet") for entry in info["IPAM"]["Config"]] != [subnet] or
        info["Options"].get("com.docker.network.bridge.name") != bridge):
    raise SystemExit("Docker network no longer matches the active policy")
PY
iptables -w -C DOCKER-USER -i "$BRIDGE" -s "$SUBNET" -j CRUCIBLE_EGRESS
iptables -w -C INPUT -i "$BRIDGE" -s "$SUBNET" -j DROP
ip6tables -w -C INPUT -i "$BRIDGE" -j DROP
ip6tables -w -C FORWARD -i "$BRIDGE" -j DROP
FIRST_FORWARD="$(iptables -w -S DOCKER-USER | awk '$1 == "-A" {print; exit}')"
FIRST_INPUT="$(iptables -w -S INPUT | awk '$1 == "-A" {print; exit}')"
LAST_EGRESS="$(iptables -w -S CRUCIBLE_EGRESS | tail -n 1)"
if [[ "$FIRST_FORWARD" != *"-i $BRIDGE"* || "$FIRST_FORWARD" != *"-s $SUBNET"* ||
      "$FIRST_FORWARD" != *"-j CRUCIBLE_EGRESS"* ||
      "$FIRST_INPUT" != *"-i $BRIDGE"* || "$FIRST_INPUT" != *"-s $SUBNET"* ||
      "$FIRST_INPUT" != *"-j DROP"* || "$LAST_EGRESS" != *"-j DROP" ]]; then
  echo "network policy is not first/fail-closed; rerun setup-net.sh" >&2
  exit 77
fi

RUNTIME="${CRUCIBLE_RUNTIME:-runc}"
case "$RUNTIME" in
  runc) ;;
  runsc-oci) python3 "$INFRA_DIR/verify-runtime.py" --quiet >&2 ;;
  kata-qemu) python3 "$INFRA_DIR/verify-kata.py" --quiet >&2 ;;
  *) echo "CRUCIBLE_RUNTIME must be runc, runsc-oci, or kata-qemu" >&2; exit 2 ;;
esac

# Build from the current source for every live session, then pin the exact
# result. Docker's cache keeps unchanged builds cheap; a stale mutable tag
# never becomes the worker just because it already exists locally.
IMAGE_ID="$("$INFRA_DIR/build-worker.sh")"

RUN_ID="$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"
NAME="crucible-worker-$RUN_ID"
EPISODE_ID="${CRUCIBLE_EPISODE_ID:-$RUN_ID}"
[[ "$EPISODE_ID" =~ ^[a-zA-Z0-9_.-]{1,64}$ ]] || {
  echo "invalid CRUCIBLE_EPISODE_ID" >&2
  exit 2
}
cleanup() {
  docker rm -f "$NAME" >/dev/null 2>&1 || true
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

CID="$(docker run --detach --rm --name "$NAME" \
  --label crucible.managed=true --label "crucible.episode=$EPISODE_ID" \
  --network "$NET" --dns 127.0.0.1 --dns-opt timeout:1 --dns-opt attempts:1 \
  "${HOST_ARGS[@]}" --runtime "$RUNTIME" \
  --read-only \
  --tmpfs /work:rw,nosuid,nodev,size=64m,uid=10001,gid=10001,mode=0700 \
  --tmpfs /tmp:rw,nosuid,nodev,noexec,size=16m,uid=10001,gid=10001,mode=1777 \
  --user 10001:10001 --cap-drop ALL \
  --security-opt no-new-privileges \
  --security-opt "seccomp=$INFRA_DIR/crucible-seccomp.json" \
  --pids-limit 64 --memory 512m --memory-swap 512m --cpus 1 --shm-size 8m \
  --ulimit nofile=256:256 --init --stop-timeout 2 --log-driver none \
  --env CRUCIBLE_SCENARIO_DIR=/work/scenario \
  "$IMAGE_ID" python -c 'import time; time.sleep(900)')"

# Docker's requested alias alone is insufficient proof of a microVM. Check
# the effective runtime, separate guest kernel, actual KVM-backed QEMU, guest
# seccomp, and guest resource limits before giving it untrusted scenario data.
if [[ "$RUNTIME" == kata-qemu ]]; then
  python3 "$INFRA_DIR/verify-kata.py" "$CID" "$NET" >&2
fi

python3 "$INFRA_DIR/stage-scenario.py" "$SCENARIO_DIR" | \
  docker exec --interactive "$CID" python /opt/crucible/extract-scenario.py

trap - EXIT INT TERM
echo "$CID"
