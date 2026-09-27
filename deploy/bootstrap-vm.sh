#!/usr/bin/env bash
# Apply a committed CRUCIBLE release on an existing Debian/Ubuntu Linux VM.
set -euo pipefail

usage() {
  echo "usage: sudo bash deploy/bootstrap-vm.sh --apply --release /opt/crucible/releases/<git-sha>" >&2
  exit 2
}

APPLY=0
RELEASE=""
while (($#)); do
  case "$1" in
    --apply) APPLY=1; shift ;;
    --release) (($# >= 2)) || usage; RELEASE="$2"; shift 2 ;;
    *) usage ;;
  esac
done
((APPLY)) || usage
[[ "$(uname -s)" == Linux && "$EUID" -eq 0 ]] || {
  echo "bootstrap requires root on Linux" >&2; exit 77;
}
[[ "$RELEASE" =~ ^/opt/crucible/releases/[0-9a-f]{40,64}$ ]] || usage
[[ -d "$RELEASE" && ! -L "$RELEASE" ]] || {
  echo "release directory missing or a symlink: $RELEASE" >&2; exit 2;
}
[[ "$(realpath "$RELEASE")" == "$RELEASE" ]] || {
  echo "release must use a canonical path" >&2; exit 2;
}
[[ -f /etc/os-release ]] || { echo "unsupported Linux distribution" >&2; exit 77; }
# shellcheck disable=SC1091
source /etc/os-release
[[ "${ID:-}" == ubuntu || "${ID:-}" == debian ]] || {
  echo "bootstrap supports Ubuntu or Debian only" >&2; exit 77;
}
command -v apt-get >/dev/null && command -v systemctl >/dev/null || {
  echo "apt-get and systemd are required" >&2; exit 77;
}
for file in infra/setup-net.sh infra/build-worker.sh infra/prove-wall.sh crucible/dashboard.py; do
  [[ -f "$RELEASE/$file" ]] || { echo "missing $file in release" >&2; exit 2; }
done
if [[ -e "$RELEASE/data" || -L "$RELEASE/data" ]]; then
  [[ -L "$RELEASE/data" && "$(readlink "$RELEASE/data")" == /var/lib/crucible/data ]] || {
    echo "release data path must point only to /var/lib/crucible/data" >&2; exit 2;
  }
fi

# Existing Docker packages and daemon settings are left in place. On a fresh
# Debian/Ubuntu VM the distro package supplies Docker; the firewall backend
# is checked before setup-net can change CRUCIBLE-specific rules.
PACKAGES=()
command -v docker >/dev/null || PACKAGES+=(docker.io)
command -v iptables >/dev/null || PACKAGES+=(iptables)
command -v ip6tables >/dev/null || PACKAGES+=(iptables)
[[ -x /usr/bin/python3 ]] || PACKAGES+=(python3)
if ((${#PACKAGES[@]})); then
  apt-get update
  DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "${PACKAGES[@]}"
fi
python3 - <<'PY'
import sys
if sys.version_info < (3, 10):
    raise SystemExit("Python 3.10 or newer is required")
PY
systemctl enable --now docker
docker info >/dev/null
iptables -w -S DOCKER-USER >/dev/null 2>&1 || {
  echo "Docker's iptables DOCKER-USER chain is required; review daemon firewall backend" >&2
  exit 77
}

if ! getent group crucible >/dev/null 2>&1; then
  groupadd --system crucible
fi
if ! id crucible >/dev/null 2>&1; then
  useradd --system --gid crucible --home-dir /var/lib/crucible --shell /usr/sbin/nologin crucible
fi
install -d -m 0755 /opt/crucible /opt/crucible/releases /var/lib/crucible
install -d -o crucible -g crucible -m 0700 /var/lib/crucible/data
if [[ -f /var/lib/crucible/data/experience.sqlite ]]; then
  [[ ! -L /var/lib/crucible/data/experience.sqlite ]] || {
    echo "experience database cannot be a symlink" >&2; exit 2;
  }
  chown crucible:crucible /var/lib/crucible/data/experience.sqlite
  chmod 0600 /var/lib/crucible/data/experience.sqlite
fi
if [[ ! -L "$RELEASE/data" ]]; then
  ln -s /var/lib/crucible/data "$RELEASE/data"
fi
if [[ ! -f /var/lib/crucible/data/experience.sqlite ]]; then
  command -v runuser >/dev/null || { echo "runuser is required to initialize the private bank" >&2; exit 77; }
  runuser -u crucible -- env PYTHONPATH="$RELEASE" /usr/bin/python3 -c \
    'from crucible.experience import ExperienceBank; ExperienceBank("/var/lib/crucible/data/experience.sqlite")'
fi

# Only these repository scripts alter the dedicated CRUCIBLE bridge and their
# own iptables chain. A failed wall proof stops the release before activation.
bash "$RELEASE/infra/setup-net.sh"
bash "$RELEASE/infra/build-worker.sh"
bash "$RELEASE/infra/prove-wall.sh"

UNIT=/etc/systemd/system/crucible-dashboard.service
if [[ -e "$UNIT" ]] && ! grep -q '^# Managed by CRUCIBLE deploy/bootstrap-vm.sh$' "$UNIT"; then
  echo "refusing to replace an unmanaged $UNIT" >&2
  exit 2
fi
cat > "$UNIT.tmp" <<'UNIT_TEXT'
# Managed by CRUCIBLE deploy/bootstrap-vm.sh
[Unit]
Description=CRUCIBLE local evidence dashboard
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=crucible
Group=crucible
WorkingDirectory=/opt/crucible/current
ExecStart=/usr/bin/python3 -m crucible.dashboard --db /var/lib/crucible/data/experience.sqlite --host 127.0.0.1 --port 8787
Restart=on-failure
RestartSec=2
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/crucible/data
CapabilityBoundingSet=

[Install]
WantedBy=multi-user.target
UNIT_TEXT
chmod 0644 "$UNIT.tmp"
mv -f "$UNIT.tmp" "$UNIT"

PREVIOUS=""
if [[ -e /opt/crucible/current || -L /opt/crucible/current ]]; then
  [[ -L /opt/crucible/current ]] || {
    echo "refusing to replace non-symlink /opt/crucible/current" >&2; exit 2;
  }
  PREVIOUS="$(readlink /opt/crucible/current)"
fi
[[ ! -e /opt/crucible/current.next && ! -L /opt/crucible/current.next ]] || {
  echo "stale /opt/crucible/current.next exists" >&2; exit 2;
}
ln -s "$RELEASE" /opt/crucible/current.next
mv -Tf /opt/crucible/current.next /opt/crucible/current
systemctl daemon-reload
systemctl enable crucible-dashboard.service
systemctl restart crucible-dashboard.service
HEALTHY=0
for _ in 1 2 3 4 5 6 7 8 9 10; do
  if python3 - <<'PY'
from urllib.request import urlopen
with urlopen("http://127.0.0.1:8787/healthz", timeout=2) as response:
    assert response.status == 200 and response.read() == b"ok\n"
with urlopen("http://127.0.0.1:8787/api/snapshot", timeout=2) as response:
    assert response.status == 200
with urlopen("http://127.0.0.1:8787/api/trajectory/snapshot", timeout=2) as response:
    assert response.status == 200
PY
  then
    if systemctl is-active --quiet crucible-dashboard.service; then HEALTHY=1; break; fi
  fi
  sleep 1
done
if (( ! HEALTHY )); then
  echo "dashboard health check failed; restoring previous release" >&2
  if [[ -n "$PREVIOUS" ]]; then
    ln -s "$PREVIOUS" /opt/crucible/current.next
    mv -Tf /opt/crucible/current.next /opt/crucible/current
    systemctl restart crucible-dashboard.service || true
  else
    rm -f /opt/crucible/current
    systemctl stop crucible-dashboard.service || true
  fi
  exit 1
fi

echo "CRUCIBLE wall proof passed and dashboard is healthy on 127.0.0.1:8787"
echo "Active release: $RELEASE"
echo "Dashboard logs: journalctl -u crucible-dashboard.service"
