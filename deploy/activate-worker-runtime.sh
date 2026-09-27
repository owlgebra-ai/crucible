#!/usr/bin/env bash
# Select a VM2 worker runtime only after its live wall proof passes.
set -euo pipefail

usage() {
  echo "usage: activate-worker-runtime.sh --runtime runc|runsc-oci|kata-qemu --apply" >&2
  exit 2
}

[[ $# -eq 3 && "$1" == --runtime && "$3" == --apply ]] || usage
RUNTIME="$2"
[[ "$RUNTIME" == runc || "$RUNTIME" == runsc-oci || "$RUNTIME" == kata-qemu ]] || usage
[[ "$(uname -s)" == Linux && "$EUID" -eq 0 ]] || {
  echo "Linux root required" >&2; exit 77;
}
for binary in docker flock mktemp readlink sha256sum timeout; do
  command -v "$binary" >/dev/null || { echo "missing $binary" >&2; exit 77; }
done
RELEASE="$(readlink -f /opt/crucible/current)"
[[ "$RELEASE" =~ ^/opt/crucible/releases/[0-9a-f]{40,64}$ &&
   -f "$RELEASE/infra/prove-wall.sh" &&
   -f "$RELEASE/deploy/remote-worker-gateway.py" ]] || {
  echo "active committed sandbox release required" >&2; exit 77;
}
RUNTIME_CONFIG=/etc/crucible/worker-runtime
[[ -f "$RUNTIME_CONFIG" && ! -L "$RUNTIME_CONFIG" ]] || {
  echo "root-owned worker runtime configuration missing" >&2; exit 77;
}
python3 - "$RELEASE" <<'PY'
import runpy
import sys
gateway = runpy.run_path(sys.argv[1] + "/deploy/remote-worker-gateway.py")
gateway["_configured_runtime"]()
PY

# The gateway holds the same lock around task creation. No task can start
# while the proof and runtime switch are in progress.
exec 9>/var/lock/crucible-remote-gateway.lock
flock -x 9
[[ -z "$(docker ps -aq --filter label=crucible.managed=true)" ]] || {
  echo "worker tasks are active; runtime unchanged" >&2; exit 75;
}

PROOF_DIR=/var/lib/crucible/isolation-proofs
install -d -m 0700 "$PROOF_DIR"
umask 077
PROOF="$(mktemp "$PROOF_DIR/$(date -u +%Y%m%dT%H%M%SZ)-$RUNTIME.XXXXXX")"
if ! CRUCIBLE_RUNTIME="$RUNTIME" timeout --signal=TERM --kill-after=5s 300 \
    bash "$RELEASE/infra/prove-wall.sh" > "$PROOF" 2>&1; then
  echo "runtime proof failed; selection unchanged; private transcript: $PROOF" >&2
  exit 1
fi
[[ -z "$(docker ps -aq --filter label=crucible.managed=true)" ]] || {
  echo "worker teardown check failed; runtime unchanged; private transcript: $PROOF" >&2
  exit 1
}
TEMP="$(mktemp /etc/crucible/.worker-runtime.XXXXXX)"
trap 'rm -f "$TEMP"' EXIT
chmod 0600 "$TEMP"
printf '%s\n' "$RUNTIME" > "$TEMP"
mv -T "$TEMP" "$RUNTIME_CONFIG"
trap - EXIT
DIGEST="$(sha256sum "$PROOF")"
echo "worker runtime activated: $RUNTIME"
echo "wall proof SHA-256: ${DIGEST%% *}"
echo "private transcript: $PROOF"
