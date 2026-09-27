#!/usr/bin/env bash
# Install one pinned, SHA-256-verified Kata release without changing Docker's
# default runtime. Run only on the dedicated Ubuntu 24.04 sandbox VM.
set -euo pipefail

INFRA_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
case "${1:-}" in
  --check)
    [[ $# -eq 1 ]] || { echo "usage: install-kata.sh --check|--apply" >&2; exit 2; }
    python3 "$INFRA_DIR/verify-kata.py"
    exit $? ;;
  --apply)
    [[ $# -eq 1 ]] || { echo "usage: install-kata.sh --check|--apply" >&2; exit 2; } ;;
  *) echo "usage: install-kata.sh --check|--apply" >&2; exit 2 ;;
esac

[[ "$(uname -s)" == Linux && "${EUID}" -eq 0 ]] || {
  echo "install-kata.sh requires root on the Linux sandbox host" >&2
  exit 77
}
# shellcheck disable=SC1091
. /etc/os-release
[[ "${ID:-}" == ubuntu && "${VERSION_ID:-}" == 24.04 ]] || {
  echo "Kata installer is scoped to Ubuntu 24.04" >&2
  exit 77
}
for binary in curl docker dpkg flock python3 sha256sum tar systemctl; do
  command -v "$binary" >/dev/null || { echo "missing $binary" >&2; exit 77; }
done
python3 - <<'PY'
import os
import re
import subprocess
from pathlib import Path
version = subprocess.check_output(['docker', 'version', '--format', '{{.Server.Version}}'], text=True).strip()
match = re.match(r'^(\d+)\.', version)
if not match or int(match.group(1)) < 26:
    raise SystemExit('Kata Docker integration requires Docker Engine 26 or newer')
if not re.search(r'\b(vmx|svm)\b', Path('/proc/cpuinfo').read_text()):
    raise SystemExit('host does not expose CPU virtualization')
with open('/dev/kvm', 'rb+'):
    pass
PY
if ! command -v zstd >/dev/null; then
  apt-get update
  DEBIAN_FRONTEND=noninteractive apt-get install -y zstd
fi

KATA_VERSION=4.2.0
case "$(dpkg --print-architecture)" in
  amd64)
    ARCH=amd64
    EXPECTED_SHA256=b828904fa3f1e49ddd7dc799c72cb1503cd1e772d354c3987c8d4189b2a623a8 ;;
  arm64)
    ARCH=arm64
    EXPECTED_SHA256=5dd4e9f2d5ea9e6bdfa2f476b3315335b58252366fcda2775a3094fc8fec376b ;;
  *) echo "Kata release architecture is unsupported" >&2; exit 77 ;;
esac

if [[ -e /opt/kata ]]; then
  if python3 "$INFRA_DIR/verify-kata.py" --quiet; then
    echo "Pinned Kata QEMU runtime is already installed and verified"
    exit 0
  fi
  echo "an unverified /opt/kata already exists; refusing to overwrite it" >&2
  exit 77
fi
if [[ -e /etc/crucible/kata-qemu.toml || -e /etc/crucible/kata-install.json ]]; then
  echo "an unverified Kata configuration already exists; refusing to overwrite it" >&2
  exit 77
fi

DEFAULT_BEFORE="$(docker info --format '{{.DefaultRuntime}}')"
WORK_DIR="$(mktemp -d /opt/.crucible-kata.XXXXXXXX)"
trap 'rm -rf -- "$WORK_DIR"' EXIT
ARCHIVE="$WORK_DIR/kata-static-${KATA_VERSION}-${ARCH}.tar.zst"
URL="https://github.com/kata-containers/kata-containers/releases/download/${KATA_VERSION}/$(basename "$ARCHIVE")"
curl --fail --silent --show-error --location \
  --proto '=https' --proto-redir '=https' --retry 3 \
  "$URL" --output "$ARCHIVE"
printf '%s  %s\n' "$EXPECTED_SHA256" "$ARCHIVE" | sha256sum --check --status || {
  echo "Kata release archive digest did not match the pinned GitHub release" >&2
  exit 77
}

mkdir -p "$WORK_DIR/stage"
tar --zstd -xf "$ARCHIVE" -C "$WORK_DIR/stage"
STAGED_KATA="$WORK_DIR/stage/opt/kata"
STAGED_CONFIG="$STAGED_KATA/share/defaults/kata-containers/runtime-rs/configuration-qemu-runtime-rs.toml"
[[ -f "$STAGED_CONFIG" && -x "$STAGED_KATA/runtime-rs/bin/containerd-shim-kata-v2" ]] || {
  echo "verified Kata archive lacks the QEMU runtime-rs assets" >&2
  exit 77
}

# Kata's packaged default may disable seccomp inside the guest. Make the
# effective per-task configuration explicit before registering the runtime.
python3 - "$STAGED_CONFIG" "$WORK_DIR/kata-qemu.toml" <<'PY'
import re
import sys
import tomllib
from pathlib import Path

source, destination = map(Path, sys.argv[1:])
body = source.read_text()
body, count = re.subn(r'(?m)^(disable_guest_seccomp\s*=\s*)(?:true|false)(\s*)$',
                      r'\g<1>false\2', body)
if count != 1:
    raise SystemExit('expected exactly one Kata guest seccomp setting')
body, count = re.subn(r'(?m)^(seccomp_sandbox\s*=\s*)"[^"]*"(\s*)$',
                      r'\g<1>"on"\2', body)
if count != 1:
    raise SystemExit('expected exactly one QEMU host seccomp setting')
parsed = tomllib.loads(body)
if parsed.get('runtime', {}).get('disable_guest_seccomp') is not False:
    raise SystemExit('Kata guest seccomp was not enabled')
if parsed.get('runtime', {}).get('hypervisor_name') != 'qemu':
    raise SystemExit('Kata configuration does not select QEMU')
if parsed.get('hypervisor', {}).get('qemu', {}).get('seccomp_sandbox') != 'on':
    raise SystemExit('QEMU host seccomp was not enabled')
destination.write_text(body)
PY

# Preflight the named runtime registration before changing the daemon. The
# previous daemon file is retained for an operator-driven rollback.
python3 - "$WORK_DIR" <<'PY'
import json
import os
from pathlib import Path
import sys

work = Path(sys.argv[1])
path = Path('/etc/docker/daemon.json')
current = json.loads(path.read_text()) if path.exists() else {}
runtimes = current.setdefault('runtimes', {})
if not isinstance(runtimes, dict) or 'kata-qemu' in runtimes:
    raise SystemExit('kata-qemu alias already exists or runtimes is malformed')
if current.get('default-runtime') == 'kata-qemu':
    raise SystemExit('Kata cannot become the Docker default runtime')
runtimes['kata-qemu'] = {
    'runtimeType': '/opt/kata/runtime-rs/bin/containerd-shim-kata-v2',
    'options': {'ConfigPath': '/etc/crucible/kata-qemu.toml'},
}
(work / 'daemon.json.new').write_text(json.dumps(current, indent=2, sort_keys=True) + '\n')
(work / 'daemon.json.previous').write_text(path.read_text() if path.exists() else '{}\n')
PY

# The forced gateway holds this same lock across session creation. Acquire it
# only after downloading and checking the release, then keep it until the
# daemon has restarted and its effective runtime has been verified.
umask 077
exec 9<>/var/lock/crucible-remote-gateway.lock
flock -x 9
python3 - <<'PY'
import os
import stat

path = '/var/lock/crucible-remote-gateway.lock'
opened = os.fstat(9)
named = os.lstat(path)
if (not stat.S_ISREG(opened.st_mode) or not stat.S_ISREG(named.st_mode)
        or opened.st_uid != 0 or opened.st_mode & 0o077
        or (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino)):
    raise SystemExit('unsafe gateway creation lock')
PY
MANAGED_CONTAINERS="$(docker ps -aq --filter label=crucible.managed=true)"
[[ -z "$MANAGED_CONTAINERS" ]] || {
  echo "worker tasks exist; refusing Kata install and Docker restart" >&2
  exit 75
}

mv "$STAGED_KATA" /opt/kata
install -d -m 0755 /etc/crucible /etc/docker
install -m 0644 "$WORK_DIR/kata-qemu.toml" /etc/crucible/kata-qemu.toml
python3 - "$ARCH" "$EXPECTED_SHA256" <<'PY'
import hashlib
import json
from pathlib import Path
import tomllib
import sys

arch, archive_sha256 = sys.argv[1:]
def digest(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()

config = Path('/etc/crucible/kata-qemu.toml')
hypervisor = tomllib.loads(config.read_text())['hypervisor']['qemu']
manifest = {
    'version': '4.2.0',
    'arch': arch,
    'archive_sha256': archive_sha256,
    'shim_sha256': digest('/opt/kata/runtime-rs/bin/containerd-shim-kata-v2'),
    'qemu_sha256': digest(hypervisor['path']),
    'virtiofsd_sha256': digest(hypervisor['virtio_fs_daemon']),
    'guest_kernel_sha256': digest(hypervisor['kernel']),
    'guest_image_sha256': digest(hypervisor['image']),
    'config_sha256': digest(config),
}
Path('/etc/crucible/kata-install.json').write_text(json.dumps(manifest, indent=2, sort_keys=True) + '\n')
PY
chmod 0644 /etc/crucible/kata-install.json
if [[ -e /etc/docker/daemon.json ]]; then
  install -m 0600 "$WORK_DIR/daemon.json.previous" /etc/docker/daemon.json.crucible-kata-backup
fi
install -m 0644 "$WORK_DIR/daemon.json.new" /etc/docker/daemon.json.crucible-kata-new
mv -f /etc/docker/daemon.json.crucible-kata-new /etc/docker/daemon.json
MANAGED_CONTAINERS="$(docker ps -aq --filter label=crucible.managed=true)"
[[ -z "$MANAGED_CONTAINERS" ]] || {
  echo "worker tasks appeared before Docker restart; refusing restart" >&2
  exit 75
}
systemctl restart docker

DEFAULT_AFTER="$(docker info --format '{{.DefaultRuntime}}')"
[[ "$DEFAULT_AFTER" == "$DEFAULT_BEFORE" ]] || {
  echo "Docker default runtime changed unexpectedly; restore daemon backup" >&2
  exit 77
}
python3 "$INFRA_DIR/verify-kata.py"
echo "Runtime is registered but not selected for CRUCIBLE tasks. Run a wall proof before activation."
