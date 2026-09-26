#!/usr/bin/env bash
# Apply a committed release to a sandbox-only VM. No model key, bank, or dashboard.
set -euo pipefail

if [[ $# -ne 3 || "$1" != --apply || "$2" != --release ]]; then
  echo "usage: sudo bash deploy/bootstrap-sandbox-vm.sh --apply --release /opt/crucible/releases/<git-sha>" >&2
  exit 2
fi
RELEASE="$3"
[[ "$(uname -s)" == Linux && "$EUID" -eq 0 ]] || { echo "Linux root required" >&2; exit 77; }
[[ "$RELEASE" =~ ^/opt/crucible/releases/[0-9a-f]{40,64}$ ]] || exit 2
[[ -d "$RELEASE" && ! -L "$RELEASE" && "$(realpath "$RELEASE")" == "$RELEASE" ]] || exit 2
[[ -f /etc/os-release ]] || exit 77
# shellcheck disable=SC1091
source /etc/os-release
[[ "${ID:-}" == ubuntu || "${ID:-}" == debian ]] || exit 77
for file in infra/setup-net.sh infra/build-worker.sh infra/prove-wall.sh deploy/remote-worker-gateway.py; do
  [[ -f "$RELEASE/$file" ]] || { echo "missing $file" >&2; exit 2; }
done
PACKAGES=()
command -v docker >/dev/null || PACKAGES+=(docker.io)
command -v iptables >/dev/null || PACKAGES+=(iptables)
command -v ip6tables >/dev/null || PACKAGES+=(iptables)
command -v python3 >/dev/null || PACKAGES+=(python3)
command -v timeout >/dev/null || PACKAGES+=(coreutils)
if ((${#PACKAGES[@]})); then
  apt-get update
  DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "${PACKAGES[@]}"
fi
python3 - <<'PY'
import sys
if sys.version_info < (3, 10):
    raise SystemExit("Python 3.10 or newer required")
PY
systemctl enable --now docker
docker info >/dev/null
iptables -w -S DOCKER-USER >/dev/null 2>&1 || {
  echo "Docker iptables DOCKER-USER chain is required" >&2; exit 77;
}

# VM2 receives no inference.env and has no bank/dashboard service. The proof
# must pass before this release becomes the forced SSH command target.
bash "$RELEASE/infra/setup-net.sh"
bash "$RELEASE/infra/build-worker.sh"
bash "$RELEASE/infra/prove-wall.sh"

install -d -m 0755 /opt/crucible
[[ ! -e /opt/crucible/current.next && ! -L /opt/crucible/current.next ]] || {
  echo "stale release staging link" >&2; exit 2;
}
if [[ -e /opt/crucible/current || -L /opt/crucible/current ]]; then
  [[ -L /opt/crucible/current ]] || { echo "current release is not a symlink" >&2; exit 2; }
fi
ln -s "$RELEASE" /opt/crucible/current.next
mv -Tf /opt/crucible/current.next /opt/crucible/current
echo "Sandbox wall proof passed; active release: $RELEASE"
