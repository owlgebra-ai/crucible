#!/usr/bin/env bash
# Install one source-bound, forced-command SSH key on the sandbox VM.
set -euo pipefail

usage() {
  echo "usage: sudo deploy/authorize-control-key.sh --control-ip PRIVATE_IPV4 --public-key-file FILE --apply" >&2
  exit 2
}
CONTROL_IP=""
KEY_FILE=""
APPLY=0
while (($#)); do
  case "$1" in
    --control-ip) (($# >= 2)) || usage; CONTROL_IP="$2"; shift 2 ;;
    --public-key-file) (($# >= 2)) || usage; KEY_FILE="$2"; shift 2 ;;
    --apply) APPLY=1; shift ;;
    *) usage ;;
  esac
done
((APPLY)) || usage
[[ "$(uname -s)" == Linux && "$EUID" -eq 0 ]] || { echo "Linux root required" >&2; exit 77; }
[[ -f "$KEY_FILE" && ! -L "$KEY_FILE" ]] || { echo "regular public key file required" >&2; exit 2; }
[[ -f /opt/crucible/current/deploy/remote-worker-gateway.py ]] || {
  echo "deploy the sandbox release first" >&2; exit 2;
}
LINE="$(python3 - "$CONTROL_IP" "$KEY_FILE" <<'PY'
import base64
import binascii
import ipaddress
from pathlib import Path
import sys

ip = ipaddress.IPv4Address(sys.argv[1])
if not any(ip in ipaddress.IPv4Network(value) for value in
           ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")):
    raise SystemExit("control IP must be RFC 1918 private IPv4")
path = Path(sys.argv[2])
if path.stat().st_size > 8192:
    raise SystemExit("public key file too large")
parts = path.read_text(encoding="ascii").strip().split()
if len(parts) < 2 or parts[0] != "ssh-ed25519":
    raise SystemExit("one Ed25519 public key required")
try:
    blob = base64.b64decode(parts[1], validate=True)
except binascii.Error:
    raise SystemExit("invalid public key base64") from None
if len(blob) < 32:
    raise SystemExit("public key too short")
print('restrict,from="' + str(ip) + '",command="/usr/bin/python3 /opt/crucible/current/deploy/remote-worker-gateway.py" '
      + parts[0] + ' ' + parts[1] + ' crucible-control')
PY
)"
install -d -m 0700 /root/.ssh
KEYS=/root/.ssh/authorized_keys
[[ ! -L "$KEYS" ]] || { echo "authorized_keys must not be a symlink" >&2; exit 2; }
touch "$KEYS"
chmod 0600 "$KEYS"
if ! grep -Fqx -- "$LINE" "$KEYS"; then
  printf '%s\n' "$LINE" >> "$KEYS"
fi
echo "Installed source-bound forced-command control key for $CONTROL_IP"
