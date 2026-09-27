#!/usr/bin/env bash
# Produces host, network, syscall, and teardown evidence on the actual VM.
set -euo pipefail

if [[ "$(uname -s)" != Linux || "${EUID}" -ne 0 ]]; then
  echo "UNVERIFIED: prove-wall.sh must run as root on the Linux Vultr host" >&2
  exit 77
fi
for binary in docker iptables python3 timeout; do
  command -v "$binary" >/dev/null || { echo "UNVERIFIED: missing $binary" >&2; exit 77; }
done
INFRA_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STATE_FILE="${CRUCIBLE_STATE_DIR:-/var/lib/crucible}/net.json"
WALL_RUNTIME="${CRUCIBLE_RUNTIME:-runc}"
[[ "$WALL_RUNTIME" == runc || "$WALL_RUNTIME" == runsc-oci || "$WALL_RUNTIME" == kata-qemu ]] || {
  echo "UNVERIFIED: CRUCIBLE_RUNTIME must be runc, runsc-oci, or kata-qemu" >&2
  exit 77
}

echo "[1/5] Host virtualization"
python3 - <<'PY'
import os
from pathlib import Path
cpu = Path('/proc/cpuinfo').read_text()
print('CPU virtualization flag:', 'PRESENT' if (' vmx ' in cpu or ' svm ' in cpu) else 'ABSENT')
try:
    fd = os.open('/dev/kvm', os.O_RDWR)
except OSError as exc:
    print('/dev/kvm read/write:', f'UNAVAILABLE ({exc})')
else:
    os.close(fd)
    print('/dev/kvm read/write: OK')
PY

read -r ALLOW_HOST ALLOW_IP DNS_NAME NET SUBNET BRIDGE < <(python3 - "$STATE_FILE" <<'PY'
import ipaddress
import json
import sys
data = json.load(open(sys.argv[1]))
hosts = data['allow_hosts']
if not hosts:
    raise SystemExit('UNVERIFIED: configure at least one allowed HTTPS host for the positive proof')
if any('1.1.1.1' in addresses for addresses in hosts.values()):
    raise SystemExit('UNVERIFIED: direct-IP test destination is allowlisted')
host = next(iter(hosts))
ip = hosts[host][0]
dns = next(name for name in ('example.com', 'www.python.org', 'www.wikipedia.org') if name not in hosts)
subnet = str(ipaddress.IPv4Network(data['subnet'], strict=True))
print(host, ip, dns, data['network'], subnet, data['bridge'])
PY
)

echo "[2/5] Container and policy probe"
PROBE_ID="proof-$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"
SCENARIO_DIR="$(mktemp -d)"
CID=""
TRACE_INSTALLED=0
TRACE_RULE=()
cleanup() {
  if [[ -n "$CID" ]]; then
    "$INFRA_DIR/destroy-worker.sh" "$CID" >/dev/null 2>&1 || true
  fi
  # A timed-out create script may have started Docker before returning its ID.
  mapfile -t leftovers < <(docker ps -aq --filter "label=crucible.episode=$PROBE_ID" 2>/dev/null)
  if ((${#leftovers[@]})); then
    docker rm -f "${leftovers[@]}" >/dev/null 2>&1 || true
  fi
  if (( TRACE_INSTALLED )); then
    iptables -w -D CRUCIBLE_EGRESS "${TRACE_RULE[@]}" >/dev/null 2>&1 || true
  fi
  rm -rf "$SCENARIO_DIR"
}
trap cleanup EXIT
CID="$(CRUCIBLE_EPISODE_ID="$PROBE_ID" timeout --signal=TERM --kill-after=5s 180 \
  "$INFRA_DIR/create-worker.sh" "$SCENARIO_DIR")"
python3 - "$CID" "$INFRA_DIR/crucible-seccomp.json" "$WALL_RUNTIME" <<'PY'
import json
import re
import subprocess
import sys
from pathlib import Path
info = json.loads(subprocess.check_output(['docker', 'inspect', sys.argv[1]]))[0]
host = info['HostConfig']
security = host['SecurityOpt'] or []
expected_seccomp = json.loads(Path(sys.argv[2]).read_text())
expected_runtime = sys.argv[3]
applied_seccomp = [option.partition('=')[2] for option in security if option.startswith('seccomp=')]
try:
    # Docker's CLI sends the compact profile JSON to the daemon, rather than
    # retaining the source filename in HostConfig.SecurityOpt.
    seccomp_matches = (len(applied_seccomp) == 1 and
                       json.loads(applied_seccomp[0]) == expected_seccomp)
except ValueError:
    seccomp_matches = False
checks = {
    'container ID': bool(re.fullmatch(r'[a-f0-9]{64}', info['Id'])),
    'immutable image ID': bool(re.fullmatch(r'sha256:[a-f0-9]{64}', info['Image'])),
    'read-only rootfs': host['ReadonlyRootfs'] is True,
    'no host binds': not host['Binds'],
    'non-root worker': info['Config']['User'] == '10001:10001',
    'no capabilities': any(cap.lower() == 'all' for cap in host['CapDrop'] or []),
    f'{expected_runtime} runtime': host['Runtime'] == expected_runtime,
    'seccomp profile': seccomp_matches,
    'no new privileges': any(option.startswith('no-new-privileges') for option in security),
    'DNS upstream loopback': host['Dns'] == ['127.0.0.1'],
    'pids limit': host['PidsLimit'] == 64,
}
for name, ok in checks.items():
    print(f'{name}: {"OK" if ok else "FAILED"}')
print('container ID:', info['Id'])
print('image ID:', info['Image'])
print('container runtime:', host['Runtime'])
if not all(checks.values()):
    raise SystemExit(1)
PY
if [[ "$WALL_RUNTIME" == runsc-oci ]]; then
  # HostConfig proves which alias Docker used, while Docker info proves the
  # alias actually maps to runsc with OCI seccomp and sandbox networking.
  python3 "$INFRA_DIR/verify-runtime.py"
elif [[ "$WALL_RUNTIME" == kata-qemu ]]; then
  KATA_PROOF="$(python3 "$INFRA_DIR/verify-kata.py" "$CID" "$NET")"
  python3 - "$KATA_PROOF" <<'PY'
import json
import sys
proof = json.loads(sys.argv[1])
if (proof['runtime'] != 'kata-qemu' or
        proof['guest_kernel'] == proof['host_kernel'] or
        proof['guest_seccomp'] is not True or
        proof['qemu_kvm_pid'] <= 0 or
        int(proof['guest_memory_max']) > 512 * 1024 * 1024):
    raise SystemExit('UNVERIFIED: Kata task attestation failed')
quota, period = map(int, proof['guest_cpu_max'].split())
if not 0 < quota <= period:
    raise SystemExit('UNVERIFIED: Kata guest CPU quota failed')
print('kata-qemu effective Docker runtime: OK')
print('kata-qemu guest kernel differs from host: OK')
print('kata-qemu KVM-backed QEMU: OK')
print('kata-qemu guest seccomp: OK')
print('kata-qemu guest CPU/memory limit: OK')
print('kata-qemu guest kernel:', proof['guest_kernel'])
print('kata-qemu host kernel:', proof['host_kernel'])
PY
fi
CONTAINER_IP="$(python3 - "$CID" "$NET" "$SUBNET" <<'PY'
import ipaddress
import json
import subprocess
import sys

cid, net, subnet = sys.argv[1:]
info = json.loads(subprocess.check_output(['docker', 'inspect', cid]))[0]
networks = info['NetworkSettings']['Networks']
if list(networks) != [net]:
    raise SystemExit('UNVERIFIED: probe is not attached only to the policy network')
ip = ipaddress.IPv4Address(networks[net]['IPAddress'])
if ip not in ipaddress.IPv4Network(subnet):
    raise SystemExit('UNVERIFIED: probe IP is outside the policy subnet')
print(ip)
PY
)"
echo "Policy bridge: $BRIDGE ($NET, $SUBNET)"
echo "Probe container IPv4: $CONTAINER_IP"
TRACE_COMMENT="crucible-$PROBE_ID"
TRACE_RULE=(-s "$CONTAINER_IP" -d 1.1.1.1 -p tcp --dport 443 -m comment --comment "$TRACE_COMMENT")
LAST_RULE="$(iptables -w -S CRUCIBLE_EGRESS | tail -n 1)"
[[ "$LAST_RULE" == '-A CRUCIBLE_EGRESS -j DROP' ]] || {
  echo "UNVERIFIED: CRUCIBLE_EGRESS lacks its final default DROP" >&2
  exit 77
}
DROP_POSITION="$(iptables -w -S CRUCIBLE_EGRESS | awk '$1 == "-A" {count++} END {print count+0}')"
((DROP_POSITION > 0)) || { echo "UNVERIFIED: empty egress chain" >&2; exit 77; }
# A targetless rule immediately before the default DROP counts only this
# container's direct-IP SYNs. It cannot alter the packet's verdict.
iptables -w -I CRUCIBLE_EGRESS "$DROP_POSITION" "${TRACE_RULE[@]}"
TRACE_INSTALLED=1
"$INFRA_DIR/exec-worker.sh" "$CID" python /opt/crucible/wall-probe.py \
  "$ALLOW_HOST" "$ALLOW_IP" "$DNS_NAME"

echo "[3/5] Kernel drop evidence"
python3 - "$TRACE_COMMENT" "$CONTAINER_IP" <<'PY'
import shlex
import subprocess
import sys

marker, ip = sys.argv[1:]
rules = subprocess.check_output(['iptables', '-w', '-S', 'CRUCIBLE_EGRESS'], text=True).splitlines()
active = [shlex.split(rule) for rule in rules if rule.startswith('-A CRUCIBLE_EGRESS ')]
if len(active) < 2 or active[-1] != ['-A', 'CRUCIBLE_EGRESS', '-j', 'DROP']:
    raise SystemExit('UNVERIFIED: default DROP is no longer last')
trace = active[-2]
expected = {'-s': ip, '-d': '1.1.1.1', '-p': 'tcp', '--dport': '443', '--comment': marker}
for flag, value in expected.items():
    if flag not in trace or trace[trace.index(flag) + 1].split('/')[0] != value:
        raise SystemExit(f'UNVERIFIED: probe counter no longer precedes default DROP ({flag})')
if '-j' in trace or '-g' in trace:
    raise SystemExit('UNVERIFIED: probe counter must not alter the verdict')
PY
TRACE_COUNT="$(iptables -w -nvx -L CRUCIBLE_EGRESS --line-numbers | awk -v marker="$TRACE_COMMENT" 'index($0, marker) {print $2}')"
if [[ ! "$TRACE_COUNT" =~ ^[0-9]+$ ]] || (( TRACE_COUNT == 0 )); then
  echo "FAILED: this probe container did not reach the default DROP path" >&2
  exit 1
fi
echo "Direct-IP destination: 1.1.1.1:443"
echo "Probe-specific packets immediately before default DROP: $TRACE_COUNT"
echo "Default DROP remains the next and final egress rule"
"$INFRA_DIR/destroy-worker.sh" "$CID"
DESTROYED_CID="$CID"
CID=""

echo "[4/5] Container teardown"
if [[ -n "$(docker ps -aq --filter "label=crucible.episode=$PROBE_ID")" ]]; then
  echo "FAILED: episode container remains after the runner exited" >&2
  exit 1
fi
echo "No container remains for $PROBE_ID"
if [[ "$WALL_RUNTIME" == kata-qemu ]]; then
  for attempt in {1..10}; do
    if TEARDOWN_RESULT="$(python3 "$INFRA_DIR/verify-kata.py" --destroyed "$DESTROYED_CID" 2>&1)"; then
      break
    fi
    if ((attempt == 10)); then
      echo "$TEARDOWN_RESULT" >&2
      echo "FAILED: task microVM survived teardown" >&2
      exit 1
    fi
    sleep 0.5
  done
  echo "kata-qemu task microVM destroyed: OK"
fi

echo "[5/5] Wall proof complete"
