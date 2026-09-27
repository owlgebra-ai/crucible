#!/usr/bin/env bash
# Upload a committed CRUCIBLE release to an existing VM and run its wall proof.
set -euo pipefail

usage() {
  echo "usage: deploy/ssh-deploy.sh --target user@host [--identity key] [--known-hosts file] [--port 22] [--target-host-key-alias host] [--jump-target user@host --jump-identity key --jump-known-hosts file [--jump-port 22]] [--control|--sandbox] --apply" >&2
  exit 2
}

TARGET=""
IDENTITY=""
KNOWN_HOSTS=""
PORT=22
TARGET_HOST_KEY_ALIAS=""
JUMP_TARGET=""
JUMP_IDENTITY=""
JUMP_KNOWN_HOSTS=""
JUMP_PORT=22
JUMP_PORT_SET=0
APPLY=0
BOOTSTRAP=bootstrap-vm.sh
while (($#)); do
  case "$1" in
    --target) (($# >= 2)) || usage; TARGET="$2"; shift 2 ;;
    --identity) (($# >= 2)) || usage; IDENTITY="$2"; shift 2 ;;
    --known-hosts) (($# >= 2)) || usage; KNOWN_HOSTS="$2"; shift 2 ;;
    --port) (($# >= 2)) || usage; PORT="$2"; shift 2 ;;
    --target-host-key-alias) (($# >= 2)) || usage; TARGET_HOST_KEY_ALIAS="$2"; shift 2 ;;
    --jump-target) (($# >= 2)) || usage; JUMP_TARGET="$2"; shift 2 ;;
    --jump-identity) (($# >= 2)) || usage; JUMP_IDENTITY="$2"; shift 2 ;;
    --jump-known-hosts) (($# >= 2)) || usage; JUMP_KNOWN_HOSTS="$2"; shift 2 ;;
    --jump-port) (($# >= 2)) || usage; JUMP_PORT="$2"; JUMP_PORT_SET=1; shift 2 ;;
    --control) BOOTSTRAP=bootstrap-control-vm.sh; shift ;;
    --sandbox) BOOTSTRAP=bootstrap-sandbox-vm.sh; shift ;;
    --apply) APPLY=1; shift ;;
    *) usage ;;
  esac
done
((APPLY)) || usage
[[ "$TARGET" =~ ^[a-zA-Z_][a-zA-Z0-9_.-]*@([a-zA-Z0-9][a-zA-Z0-9.-]*|\[[0-9a-fA-F:]+\])$ ]] || usage
[[ "$PORT" =~ ^[0-9]{1,5}$ ]] && ((PORT >= 1 && PORT <= 65535)) || usage
if [[ -n "$TARGET_HOST_KEY_ALIAS" ]]; then
  [[ "$TARGET_HOST_KEY_ALIAS" =~ ^[a-zA-Z0-9][a-zA-Z0-9.-]*$ ]] || usage
  [[ -n "$KNOWN_HOSTS" ]] || usage
fi
[[ -z "$IDENTITY" || -f "$IDENTITY" ]] || { echo "identity file not found" >&2; exit 2; }
if [[ -n "$KNOWN_HOSTS" ]]; then
  [[ -f "$KNOWN_HOSTS" && ! -L "$KNOWN_HOSTS" && -s "$KNOWN_HOSTS" ]] || {
    echo "known-hosts must be a nonempty regular file" >&2; exit 2;
  }
fi
if [[ -n "$JUMP_TARGET" ]]; then
  [[ "$JUMP_TARGET" =~ ^[a-zA-Z_][a-zA-Z0-9_.-]*@([a-zA-Z0-9][a-zA-Z0-9.-]*|\[[0-9a-fA-F:]+\])$ ]] || usage
  [[ "$JUMP_PORT" =~ ^[0-9]{1,5}$ ]] && ((JUMP_PORT >= 1 && JUMP_PORT <= 65535)) || usage
  [[ -n "$IDENTITY" && -n "$KNOWN_HOSTS" && -n "$JUMP_IDENTITY" && -n "$JUMP_KNOWN_HOSTS" ]] || usage
  [[ -f "$JUMP_IDENTITY" && ! -L "$JUMP_IDENTITY" ]] || {
    echo "jump identity must be a regular file" >&2; exit 2;
  }
  [[ -f "$JUMP_KNOWN_HOSTS" && ! -L "$JUMP_KNOWN_HOSTS" && -s "$JUMP_KNOWN_HOSTS" ]] || {
    echo "jump known-hosts must be a nonempty regular file" >&2; exit 2;
  }
  # OpenSSH expands percent tokens and parses option values. Disallow control
  # characters and percent expansion in caller-owned key and pin file names.
  python3 - "$IDENTITY" "$KNOWN_HOSTS" "$JUMP_IDENTITY" "$JUMP_KNOWN_HOSTS" <<'PY'
import sys
for name in sys.argv[1:]:
    if "%" in name or any(ord(char) < 32 or ord(char) == 127 for char in name):
        raise SystemExit("SSH key and known-hosts paths cannot contain control or percent characters")
PY
elif [[ -n "$JUMP_IDENTITY" || -n "$JUMP_KNOWN_HOSTS" || "$JUMP_PORT_SET" == 1 ]]; then
  usage
fi
for binary in git python3 ssh scp od tar; do
  command -v "$binary" >/dev/null || { echo "missing $binary" >&2; exit 77; }
done

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
ARCHIVE="$TMP/crucible.tar.gz"
REV="$(python3 "$ROOT/deploy/package_tracked.py" --output "$ARCHIVE")"
[[ "$REV" =~ ^[0-9a-f]{40,64}$ ]] || { echo "invalid committed revision" >&2; exit 2; }
tar -tzf "$ARCHIVE" | grep -Fx "deploy/$BOOTSTRAP" >/dev/null || {
  echo "selected bootstrap is missing from the committed deployment archive" >&2; exit 2;
}
NONCE="$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"
REMOTE_ARCHIVE="/tmp/crucible-$REV-$NONCE.tar.gz"

SSH_OPTS=(-o BatchMode=yes -o StrictHostKeyChecking=yes -p "$PORT")
SCP_OPTS=(-o BatchMode=yes -o StrictHostKeyChecking=yes -P "$PORT")
if [[ -n "$IDENTITY" ]]; then
  SSH_OPTS+=(-i "$IDENTITY")
  SCP_OPTS+=(-i "$IDENTITY")
fi
if [[ -n "$KNOWN_HOSTS" ]]; then
  SSH_OPTS+=(-F /dev/null -o "UserKnownHostsFile=$KNOWN_HOSTS" \
             -o GlobalKnownHostsFile=/dev/null -o UpdateHostKeys=no)
  SCP_OPTS+=(-F /dev/null -o "UserKnownHostsFile=$KNOWN_HOSTS" \
             -o GlobalKnownHostsFile=/dev/null -o UpdateHostKeys=no)
  if [[ -z "$JUMP_TARGET" ]]; then
    SSH_OPTS+=(-o ProxyCommand=none)
    SCP_OPTS+=(-o ProxyCommand=none)
  fi
fi
if [[ -n "$TARGET_HOST_KEY_ALIAS" ]]; then
  SSH_OPTS+=(-o "HostKeyAlias=$TARGET_HOST_KEY_ALIAS")
  SCP_OPTS+=(-o "HostKeyAlias=$TARGET_HOST_KEY_ALIAS")
fi
if [[ -n "$JUMP_TARGET" ]]; then
  # ProxyCommand is run by a shell. Quote each independently validated argv
  # element with POSIX shlex, including paths supplied by the caller.
  JUMP_ARGS=(ssh -F /dev/null -o BatchMode=yes -o IdentitiesOnly=yes
             -o StrictHostKeyChecking=yes -o "UserKnownHostsFile=$JUMP_KNOWN_HOSTS"
             -o GlobalKnownHostsFile=/dev/null -o UpdateHostKeys=no
             -o ProxyCommand=none -o ForwardAgent=no -o ConnectTimeout=10
             -i "$JUMP_IDENTITY" -p "$JUMP_PORT" -W '%h:%p' "$JUMP_TARGET")
  PROXY_COMMAND="$(python3 - "${JUMP_ARGS[@]}" <<'PY'
import shlex
import sys
print(shlex.join(sys.argv[1:]))
PY
)"
  SSH_OPTS+=(-o IdentitiesOnly=yes -o ForwardAgent=no -o "ProxyCommand=$PROXY_COMMAND")
  SCP_OPTS+=(-o IdentitiesOnly=yes -o ForwardAgent=no -o "ProxyCommand=$PROXY_COMMAND")
fi

echo "Uploading committed release $REV to $TARGET"
ssh "${SSH_OPTS[@]}" "$TARGET" 'sudo -n true'
scp "${SCP_OPTS[@]}" "$ARCHIVE" "$TARGET:$REMOTE_ARCHIVE"
ssh "${SSH_OPTS[@]}" "$TARGET" "sudo -n bash -s -- '$REV' '$REMOTE_ARCHIVE' '$BOOTSTRAP'" <<'REMOTE'
set -euo pipefail
REV="$1"
ARCHIVE="$2"
BOOTSTRAP="$3"
[[ "$REV" =~ ^[0-9a-f]{40,64}$ ]] || exit 2
[[ "$ARCHIVE" =~ ^/tmp/crucible-[0-9a-f]{40,64}-[0-9a-f]{16}\.tar\.gz$ ]] || exit 2
[[ "$BOOTSTRAP" == bootstrap-vm.sh || "$BOOTSTRAP" == bootstrap-control-vm.sh ||
   "$BOOTSTRAP" == bootstrap-sandbox-vm.sh ]] || exit 2
[[ -f "$ARCHIVE" && ! -L "$ARCHIVE" ]] || exit 2
RELEASE="/opt/crucible/releases/$REV"
STAGING="/opt/crucible/releases/.$REV.new"
cleanup() {
  rm -f "$ARCHIVE"
  if [[ -d "$STAGING" && ! -L "$STAGING" ]]; then rm -rf "$STAGING"; fi
}
trap cleanup EXIT
install -d -m 0755 /opt/crucible/releases
command -v flock >/dev/null || { echo "flock is required for serialized deployment" >&2; exit 77; }
exec 9>/var/lock/crucible-deploy.lock
flock -n 9 || { echo "another CRUCIBLE deployment is active" >&2; exit 75; }
if [[ -e "$RELEASE" || -L "$RELEASE" ]]; then
  [[ -d "$RELEASE" && ! -L "$RELEASE" ]] || {
    echo "existing release is not a directory" >&2; exit 2;
  }
  [[ "$(cat "$RELEASE/.crucible-revision" 2>/dev/null)" == "$REV" ]] || {
    echo "existing release lacks matching revision marker" >&2; exit 2;
  }
else
  [[ ! -e "$STAGING" && ! -L "$STAGING" ]] || {
    echo "stale release staging directory exists" >&2; exit 2;
  }
  install -d -m 0755 "$STAGING"
  tar --no-same-owner --no-same-permissions -xzf "$ARCHIVE" -C "$STAGING"
  printf '%s\n' "$REV" > "$STAGING/.crucible-revision"
  chmod 0644 "$STAGING/.crucible-revision"
  mv -T "$STAGING" "$RELEASE"
fi
bash "$RELEASE/deploy/$BOOTSTRAP" --apply --release "$RELEASE"
REMOTE

echo "Deployment complete."
