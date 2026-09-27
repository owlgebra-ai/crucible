#!/usr/bin/env bash
# Apply a committed control-plane release: private broker and loopback UI.
set -euo pipefail

if [[ $# -ne 3 || "$1" != --apply || "$2" != --release ]]; then
  echo "usage: sudo bash deploy/bootstrap-control-vm.sh --apply --release /opt/crucible/releases/<git-sha>" >&2
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
command -v systemctl >/dev/null || exit 77
[[ -f "$RELEASE/crucible/dashboard.py" ]] || exit 2
[[ -f "$RELEASE/crucible/task_broker.py" ]] || exit 2
if [[ ! -x /usr/bin/python3 ]]; then
  apt-get update
  DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends python3
fi
python3 - <<'PY'
import sys
if sys.version_info < (3, 10):
    raise SystemExit("Python 3.10 or newer required")
PY
if ! getent group crucible >/dev/null 2>&1; then groupadd --system crucible; fi
if ! id crucible >/dev/null 2>&1; then
  useradd --system --gid crucible --home-dir /var/lib/crucible --shell /usr/sbin/nologin crucible
fi
install -d -m 0755 /opt/crucible /opt/crucible/releases /var/lib/crucible
install -d -o crucible -g crucible -m 0700 /var/lib/crucible/data
if [[ -f /var/lib/crucible/data/experience.sqlite ]]; then
  [[ ! -L /var/lib/crucible/data/experience.sqlite ]] || exit 2
  chown crucible:crucible /var/lib/crucible/data/experience.sqlite
  chmod 0600 /var/lib/crucible/data/experience.sqlite
fi
if [[ -e "$RELEASE/data" || -L "$RELEASE/data" ]]; then
  [[ -L "$RELEASE/data" && "$(readlink "$RELEASE/data")" == /var/lib/crucible/data ]] || exit 2
else
  ln -s /var/lib/crucible/data "$RELEASE/data"
fi
if [[ ! -f /var/lib/crucible/data/experience.sqlite ]]; then
  runuser -u crucible -- env PYTHONPATH="$RELEASE" /usr/bin/python3 -c \
    'from crucible.experience import ExperienceBank; ExperienceBank("/var/lib/crucible/data/experience.sqlite")'
fi

BROKER_UNIT=/etc/systemd/system/crucible-task-broker.service
DASHBOARD_UNIT=/etc/systemd/system/crucible-dashboard.service
for unit in "$BROKER_UNIT" "$DASHBOARD_UNIT"; do
  if [[ -e "$unit" ]] && ! grep -q '^# Managed by CRUCIBLE deploy/bootstrap-control-vm.sh$' "$unit"; then
    echo "refusing to replace unmanaged control service" >&2; exit 2
  fi
done
cat > "$BROKER_UNIT.tmp" <<'UNIT_TEXT'
# Managed by CRUCIBLE deploy/bootstrap-control-vm.sh
[Unit]
Description=CRUCIBLE bounded remote task broker
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
Group=crucible
WorkingDirectory=/opt/crucible/current
Environment=HOME=/
Environment=CRUCIBLE_ENV_FILE=/etc/crucible/inference.env
Environment=CRUCIBLE_REMOTE_IDENTITY=/etc/crucible/worker_ed25519
Environment=CRUCIBLE_REMOTE_KNOWN_HOSTS=/etc/crucible/worker_known_hosts
ExecStart=/usr/bin/python3 -m crucible.task_broker --socket /run/crucible-task/task.sock --db /var/lib/crucible/data/experience.sqlite
Restart=on-failure
RestartSec=2
RuntimeDirectory=crucible-task
RuntimeDirectoryMode=0750
UMask=0007
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
ProtectClock=true
LockPersonality=true
RestrictSUIDSGID=true
RestrictRealtime=true
RestrictNamespaces=true
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
SystemCallArchitectures=native
ReadWritePaths=/var/lib/crucible/data /run/crucible-task
# The existing private bank is owned by the keyless dashboard user and mode
# 0600. The broker needs this one DAC capability to write it without relaxing
# bank or credential permissions; it has no host administration capabilities.
CapabilityBoundingSet=CAP_DAC_OVERRIDE

[Install]
WantedBy=multi-user.target
UNIT_TEXT
chmod 0644 "$BROKER_UNIT.tmp"
mv -f "$BROKER_UNIT.tmp" "$BROKER_UNIT"
cat > "$DASHBOARD_UNIT.tmp" <<'UNIT_TEXT'
# Managed by CRUCIBLE deploy/bootstrap-control-vm.sh
[Unit]
Description=CRUCIBLE control-plane evidence dashboard
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
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
RestrictNamespaces=true
RestrictAddressFamilies=AF_UNIX AF_INET
CapabilityBoundingSet=

[Install]
WantedBy=multi-user.target
UNIT_TEXT
chmod 0644 "$DASHBOARD_UNIT.tmp"
mv -f "$DASHBOARD_UNIT.tmp" "$DASHBOARD_UNIT"
PREVIOUS=""
if [[ -e /opt/crucible/current || -L /opt/crucible/current ]]; then
  [[ -L /opt/crucible/current ]] || exit 2
  PREVIOUS="$(readlink /opt/crucible/current)"
fi
[[ ! -e /opt/crucible/current.next && ! -L /opt/crucible/current.next ]] || exit 2
ln -s "$RELEASE" /opt/crucible/current.next
mv -Tf /opt/crucible/current.next /opt/crucible/current
systemctl daemon-reload
systemctl enable crucible-task-broker.service
systemctl enable crucible-dashboard.service
# A fast failure still enters the common health gate and release rollback.
systemctl restart crucible-task-broker.service || true
systemctl restart crucible-dashboard.service || true
HEALTHY=0
for _ in 1 2 3 4 5 6 7 8 9 10; do
  if python3 - <<'PY'
import json
import socket
import sys
from urllib.request import urlopen
try:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(2)
        client.connect("/run/crucible-task/task.sock")
        client.sendall(b'{"op":"current"}\n')
        response = client.makefile("rb").readline(4097)
        assert len(response) <= 4096 and json.loads(response).get("ok") is True
    with urlopen("http://127.0.0.1:8787/healthz", timeout=2) as response:
        assert response.status == 200 and response.read() == b"ok\n"
    with urlopen("http://127.0.0.1:8787/api/snapshot", timeout=2) as response:
        assert response.status == 200
    with urlopen("http://127.0.0.1:8787/api/trajectory/snapshot", timeout=2) as response:
        assert response.status == 200
except (OSError, AssertionError, ValueError):
    sys.exit(1)
PY
  then
    if systemctl is-active --quiet crucible-task-broker.service &&
       systemctl is-active --quiet crucible-dashboard.service; then HEALTHY=1; break; fi
  fi
  sleep 1
done
if (( ! HEALTHY )); then
  if [[ -n "$PREVIOUS" ]]; then
    ln -s "$PREVIOUS" /opt/crucible/current.next
    mv -Tf /opt/crucible/current.next /opt/crucible/current
    systemctl restart crucible-task-broker.service || true
    systemctl restart crucible-dashboard.service || true
  else
    rm -f /opt/crucible/current
    systemctl stop crucible-task-broker.service || true
    systemctl stop crucible-dashboard.service || true
  fi
  echo "control services health failed; previous release restored" >&2
  exit 1
fi
echo "Control plane active: $RELEASE; broker on private socket; dashboard on 127.0.0.1:8787"
