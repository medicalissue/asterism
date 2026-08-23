#!/usr/bin/env bash
# Pinned-tree adapter for the exact paid-host NVIDIA E2E driver.
#
# The driver is deliberately a separate executable: it owns the guest,
# provider helper, and lifecycle processes whose PIDs the release judge checks.
# This adapter never manufactures evidence and never falls back to a reference
# or host-direct path.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
DRIVER="${ASTERISM_NVIDIA_E2E_DRIVER:-$ROOT/target/release/asterism-nvidia-e2e-driver}"

case "$DRIVER" in
  "$ROOT"/*) ;;
  *) echo "NVIDIA E2E DRIVER FAIL: driver must come from pinned candidate tree" >&2; exit 1 ;;
esac
[ -x "$DRIVER" ] || {
  echo "NVIDIA E2E DRIVER FAIL: candidate-built driver is missing: $DRIVER" >&2
  exit 1
}
[ "$DRIVER" != "$0" ] || {
  echo "NVIDIA E2E DRIVER FAIL: recursive runner" >&2
  exit 1
}

exec "$DRIVER" "$@"
