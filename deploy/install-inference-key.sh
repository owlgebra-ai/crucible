#!/usr/bin/env bash
# Transfer only the Serverless Inference key to a trusted VM over SSH.
set -euo pipefail

usage() {
  echo "usage: deploy/install-inference-key.sh --target user@host [--identity key] [--known-hosts file] [--port 22] [--env-file .env.local] --apply" >&2
  exit 2
}

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET=""
IDENTITY=""
KNOWN_HOSTS=""
PORT=22
ENV_FILE="$ROOT/.env.local"
APPLY=0
while (($#)); do
  case "$1" in
    --target) (($# >= 2)) || usage; TARGET="$2"; shift 2 ;;
    --identity) (($# >= 2)) || usage; IDENTITY="$2"; shift 2 ;;
    --known-hosts) (($# >= 2)) || usage; KNOWN_HOSTS="$2"; shift 2 ;;
    --port) (($# >= 2)) || usage; PORT="$2"; shift 2 ;;
    --env-file) (($# >= 2)) || usage; ENV_FILE="$2"; shift 2 ;;
    --apply) APPLY=1; shift ;;
    *) usage ;;
  esac
done
((APPLY)) || usage
[[ "$TARGET" =~ ^[a-zA-Z_][a-zA-Z0-9_.-]*@([a-zA-Z0-9][a-zA-Z0-9.-]*|\[[0-9a-fA-F:]+\])$ ]] || usage
[[ "$PORT" =~ ^[0-9]{1,5}$ ]] && ((PORT >= 1 && PORT <= 65535)) || usage
[[ -z "$IDENTITY" || -f "$IDENTITY" ]] || usage
if [[ -n "$KNOWN_HOSTS" ]]; then
  [[ -f "$KNOWN_HOSTS" && ! -L "$KNOWN_HOSTS" && -s "$KNOWN_HOSTS" ]] || usage
fi
for binary in python3 ssh mktemp; do
  command -v "$binary" >/dev/null || { echo "missing $binary" >&2; exit 77; }
done

TMP_DIR="$(mktemp -d)"
chmod 0700 "$TMP_DIR"
cleanup() {
  rm -f "$TMP_DIR/inference.env"
  rmdir "$TMP_DIR"
}
trap cleanup EXIT
python3 - "$ENV_FILE" > "$TMP_DIR/inference.env" <<'PY'
import os
from pathlib import Path
import sys

path = Path(sys.argv[1])
if path.is_symlink() or not path.is_file() or path.stat().st_mode & 0o077:
    raise SystemExit("inference credential source must be a private regular file")
if path.stat().st_size > 8192:
    raise SystemExit("inference credential source is too large")
values = []
for raw in path.read_text().splitlines():
    line = raw.strip()
    if not line or line.startswith("#") or "=" not in line:
        continue
    name, value = (part.strip() for part in line.split("=", 1))
    if name in {"VULTR_INFERENCE_API_KEY", "VULTR_SERVERLESS_INFERENCE_API_KEY"}:
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        if len(value) < 16 or any(char.isspace() for char in value):
            raise SystemExit("inference key value is invalid")
        values.append(value)
if not values or len(set(values)) != 1:
    raise SystemExit("provide one consistent inference key in the credential source")
sys.stdout.write("VULTR_INFERENCE_API_KEY=" + values[0] + "\n")
PY
chmod 0600 "$TMP_DIR/inference.env"
EXPECTED_BYTES="$(wc -c < "$TMP_DIR/inference.env" | tr -d '[:space:]')"
[[ "$EXPECTED_BYTES" =~ ^[0-9]+$ ]] && ((EXPECTED_BYTES > 16 && EXPECTED_BYTES < 8192)) || {
  echo "filtered inference credential has invalid length" >&2
  exit 2
}

SSH_OPTS=(-o BatchMode=yes -o StrictHostKeyChecking=yes -p "$PORT")
if [[ -n "$IDENTITY" ]]; then
  SSH_OPTS+=(-i "$IDENTITY")
fi
if [[ -n "$KNOWN_HOSTS" ]]; then
  SSH_OPTS+=(-F /dev/null -o "UserKnownHostsFile=$KNOWN_HOSTS" \
             -o GlobalKnownHostsFile=/dev/null -o UpdateHostKeys=no -o ProxyCommand=none)
fi
REMOTE_INSTALL="$(cat <<'REMOTE'
sudo -n install -d -m 0700 /etc/crucible && sudo -n sh -c 'set -eu; umask 077; tmp=$(mktemp /etc/crucible/.inference.XXXXXX); trap "rm -f \"$tmp\"" EXIT; cat > "$tmp"; [ "$(wc -c < "$tmp")" -eq __EXPECTED_BYTES__ ]; chmod 0600 "$tmp"; mv -f "$tmp" /etc/crucible/inference.env; trap - EXIT'
REMOTE
)"
REMOTE_INSTALL="${REMOTE_INSTALL/__EXPECTED_BYTES__/$EXPECTED_BYTES}"
ssh "${SSH_OPTS[@]}" "$TARGET" "$REMOTE_INSTALL" < "$TMP_DIR/inference.env"
echo "Inference-only key installed at /etc/crucible/inference.env on $TARGET"
