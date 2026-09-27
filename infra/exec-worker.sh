#!/usr/bin/env bash
# Execute a pre-approved action over stdin in an existing worker session.
set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "usage: exec-worker.sh <container_id> [worker command and args...]" >&2
  exit 2
fi
CID="$1"
shift
[[ "$CID" =~ ^[a-f0-9]{64}$ ]] || { echo "invalid container ID" >&2; exit 2; }
[[ "$(uname -s)" == Linux && "${EUID}" -eq 0 ]] || {
  echo "exec-worker.sh requires root on the Linux sandbox host" >&2
  exit 77
}
TIMEOUT="${CRUCIBLE_TIMEOUT_SEC:-60}"
[[ "$TIMEOUT" =~ ^[0-9]+$ ]] && (( TIMEOUT >= 1 && TIMEOUT <= 600 )) || {
  echo "CRUCIBLE_TIMEOUT_SEC must be 1..600" >&2
  exit 2
}
[[ "$(docker inspect --format '{{ index .Config.Labels "crucible.managed" }}' "$CID")" == true ]] || {
  echo "container is not a CRUCIBLE-managed worker" >&2
  exit 2
}
EFFECTIVE_RUNTIME="$(docker inspect --format '{{.HostConfig.Runtime}}' "$CID")"
EXPECTED_RUNTIME="${CRUCIBLE_RUNTIME:-runc}"
[[ "$EXPECTED_RUNTIME" == "$EFFECTIVE_RUNTIME" ]] || {
  echo "worker runtime differs from the selected execution policy" >&2
  exit 77
}
if [[ "$EXPECTED_RUNTIME" == kata-qemu ]]; then
  python3 "$(dirname "${BASH_SOURCE[0]}")/verify-kata.py" "$CID" >/dev/null
fi
if [[ $# -eq 0 ]]; then
  set -- python -m crucible.worker --action-file -
fi
if timeout --signal=TERM --kill-after=5s "$TIMEOUT" \
    docker exec --interactive "$CID" "$@"; then
  exit 0
else
  status=$?
  if [[ "$status" -eq 124 || "$status" -eq 137 ]]; then
    # Killing only the Docker CLI could leave the exec process running.
    # The whole session is tainted after a timeout, so destroy it.
    "$(dirname "${BASH_SOURCE[0]}")/destroy-worker.sh" "$CID" >&2 || true
  fi
  exit "$status"
fi
