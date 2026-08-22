#!/usr/bin/env bash
# Reproduce the launch recovery lanes in the `kvmhost` Lima VM.
#
# The archive is the committed tree, the Linux target lives only in a uniquely
# named VM scratch directory, and the trap copies evidence out before removing
# that exact directory.  No host Cargo target or user Asterism home is touched.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if [ "$(uname -s)" = Linux ]; then
  exec "$ROOT/scripts/e2e-network-realms.sh" "$@"
fi

command -v limactl >/dev/null || {
  echo "LIMA RECOVERY E2E FAIL: limactl is required" >&2
  exit 2
}
limactl list --json 2>/dev/null | grep -q '"name":"kvmhost"' || {
  echo "LIMA RECOVERY E2E FAIL: the kvmhost Lima instance is not available" >&2
  exit 2
}
if ! git diff --quiet || ! git diff --cached --quiet; then
  echo "LIMA RECOVERY E2E FAIL: commit the exact tree before archiving it into Lima" >&2
  exit 2
fi

VM_RUN="$(limactl shell kvmhost -- mktemp -d /tmp/asterism-recovery.XXXXXX)"
case "$VM_RUN" in /tmp/asterism-recovery.*) ;; *)
  echo "LIMA RECOVERY E2E FAIL: unsafe VM scratch path: $VM_RUN" >&2
  exit 2
esac
EVIDENCE="$(mktemp -d /private/tmp/asterism-recovery-evidence.XXXXXX)"

cleanup() {
  set +e
  limactl copy "kvmhost:$VM_RUN/artifacts" "$EVIDENCE/" 2>/dev/null || true
  limactl shell kvmhost -- sudo rm -rf "$VM_RUN"
  echo "evidence retained at $EVIDENCE" >&2
}
trap cleanup EXIT

git archive HEAD | limactl shell kvmhost -- tar -xf - -C "$VM_RUN"

# Build once inside the nested-KVM guest.  Both executable lanes below consume
# this exact pair, and `cargo clean` removes only this run's VM-local target.
limactl shell kvmhost -- bash -lc "
  cd '$VM_RUN'
  export CARGO_TARGET_DIR='$VM_RUN/target' CARGO_INCREMENTAL=0
  cargo build --workspace
" 2>&1 | tee "$EVIDENCE/build.log"

limactl shell kvmhost -- bash -lc "
  cd '$VM_RUN'
  export AST_BIN='$VM_RUN/target/debug/ast'
  export ASTD_BIN='$VM_RUN/target/debug/astd'
  scripts/e2e-network-realms.sh
" 2>&1 | tee "$EVIDENCE/network-realms.log"

limactl shell kvmhost -- bash -lc "
  cd '$VM_RUN'
  export AST_BIN='$VM_RUN/target/debug/ast'
  export ASTD_BIN='$VM_RUN/target/debug/astd'
  export ASTERISM_TEST_ARTIFACTS='$VM_RUN/artifacts'
  export E2E_VOLUME_BACKEND=qemu
  scripts/e2e-volume.sh
" 2>&1 | tee "$EVIDENCE/volume-4g.log"

limactl shell kvmhost -- cargo clean --target-dir "$VM_RUN/target" \
  2>&1 | tee "$EVIDENCE/cargo-clean.log"

echo "LIMA RECOVERY E2E GREEN"
