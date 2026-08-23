#!/usr/bin/env bash
# Slow, networked reference gate: fetch the exact current Ubuntu 24.04 and
# Debian 13 catalog artifacts, verify publisher digests, and compare the
# native materializer's raw bytes with qemu-img. QEMU is reference evidence
# here, never a product/runtime dependency.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

command -v qemu-img >/dev/null 2>&1 || {
  echo "qcow2-catalog-gate: qemu-img is required only as the reference converter" >&2
  exit 1
}

cargo test -p asterism-core current_catalog_images_match_qemu_reference \
  -- --ignored --nocapture
