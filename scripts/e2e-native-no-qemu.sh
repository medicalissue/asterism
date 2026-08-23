#!/usr/bin/env bash
# Real native lifecycle gate for a clean host whose package inventory and PATH
# contain no QEMU. It refuses to downgrade that condition into a mocked test.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

for tool in qemu-img qemu-system-aarch64 qemu-system-x86_64; do
  if command -v "$tool" >/dev/null 2>&1; then
    echo "native-no-qemu: $tool is present on PATH; run this gate on the clean native lane" >&2
    exit 1
  fi
  for prefix in /opt/homebrew/bin /usr/local/bin /usr/bin; do
    if [ -e "$prefix/$tool" ]; then
      echo "native-no-qemu: $prefix/$tool is installed; package inventory is not clean" >&2
      exit 1
    fi
  done
done

case "$(uname -s)" in
  Darwin)
    E2E_VZ_QEMU_COMPARE=0 exec bash "$ROOT/scripts/e2e-vz.sh"
    ;;
  Linux)
    E2E_BACKEND=chv exec bash "$ROOT/scripts/e2e.sh"
    ;;
  *)
    echo "native-no-qemu: only macOS VZ and Linux Cloud Hypervisor are native lanes" >&2
    exit 1
    ;;
esac
