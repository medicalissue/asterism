#!/usr/bin/env bash
# Fail-closed live CUSE gate. This script must run on a real Ubuntu host and
# never substitutes a socket fixture, VM guest, or TCP transport for /dev/cuse.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

TARGET_COMMIT="${ASTERISM_CUSE_TARGET_COMMIT:?ASTERISM_CUSE_TARGET_COMMIT is required}"
TARGET_TREE="${ASTERISM_CUSE_TARGET_TREE:?ASTERISM_CUSE_TARGET_TREE is required}"
EVIDENCE="${ASTERISM_CUSE_EVIDENCE_DIR:-$ROOT/cuse-live-evidence}"
mkdir -p "$EVIDENCE"
SUMMARY="$EVIDENCE/summary.txt"
: >"$SUMMARY"

record() { printf '%s\n' "$*" | tee -a "$SUMMARY"; }
block() { record "verdict=BLOCKED"; record "blocker=$*"; return 1; }

record "target_commit=$TARGET_COMMIT"
record "target_tree=$TARGET_TREE"
record "observer_commit=$(git rev-parse HEAD)"
record "run_url=${GITHUB_SERVER_URL:-local}/${GITHUB_REPOSITORY:-local}/actions/runs/${GITHUB_RUN_ID:-local}"
date -u '+observed_at=%Y-%m-%dT%H:%M:%SZ' | tee -a "$SUMMARY"

gate_rc=0
actual_tree="$(git show -s --format=%T "$TARGET_COMMIT" 2>>"$EVIDENCE/preflight.log")" || gate_rc=1
if [ "$gate_rc" -eq 0 ] && [ "$actual_tree" != "$TARGET_TREE" ]; then
  block "target tree mismatch: expected $TARGET_TREE, got $actual_tree" || gate_rc=1
fi
if [ "$gate_rc" -eq 0 ] && ! git merge-base --is-ancestor "$TARGET_COMMIT" HEAD; then
  block "observer commit is not descended from exact target $TARGET_COMMIT" || gate_rc=1
fi
if [ "$gate_rc" -eq 0 ] && ! git diff --quiet "$TARGET_COMMIT" -- \
  Cargo.toml Cargo.lock crates/asterism-core/Cargo.toml \
  crates/asterism-core/src/remote_gpu_cuse.rs; then
  git diff --name-only "$TARGET_COMMIT" -- \
    Cargo.toml Cargo.lock crates/asterism-core/Cargo.toml \
    crates/asterism-core/src/remote_gpu_cuse.rs >>"$EVIDENCE/preflight.log"
  block "production CUSE inputs differ from immutable target" || gate_rc=1
fi

if [ "$gate_rc" -eq 0 ]; then
  kernel="$(uname -srm)"
  record "kernel=$kernel"
  if [ "$(uname -s)" != Linux ]; then
    block "host kernel is not Linux: $kernel" || gate_rc=1
  elif [ ! -r /etc/os-release ]; then
    block "Linux host has no readable /etc/os-release" || gate_rc=1
  else
    # shellcheck disable=SC1091
    . /etc/os-release
    record "os_id=${ID:-unknown}"
    record "os_version=${VERSION_ID:-unknown}"
    if [ "${ID:-}" != ubuntu ]; then
      block "host distribution is not Ubuntu: ${ID:-unknown}" || gate_rc=1
    fi
  fi
fi

if [ "$gate_rc" -eq 0 ]; then
  set +e
  modprobe_output="$(sudo -n modprobe cuse 2>&1)"
  modprobe_rc=$?
  set -e
  printf '%s\n' "$modprobe_output" >"$EVIDENCE/modprobe.log"
  record "modprobe_cuse_exit=$modprobe_rc"
  if [ "$modprobe_rc" -ne 0 ]; then
    block "sudo -n modprobe cuse failed (exit $modprobe_rc; see modprobe.log)" || gate_rc=1
  elif [ ! -d /sys/module/cuse ]; then
    block "cuse module is not present at /sys/module/cuse after modprobe" || gate_rc=1
  elif [ ! -c /dev/cuse ]; then
    block "/dev/cuse is missing or is not a character device after modprobe" || gate_rc=1
  elif [ ! -r /dev/cuse ] || [ ! -w /dev/cuse ]; then
    stat -Lc 'cuse_mode=%A cuse_owner=%U cuse_group=%G cuse_major_minor=%t:%T' /dev/cuse \
      | tee -a "$SUMMARY" || true
    block "/dev/cuse is not readable and writable by the runner user" || gate_rc=1
  else
    stat -Lc 'cuse_mode=%A cuse_owner=%U cuse_group=%G cuse_major_minor=%t:%T' /dev/cuse \
      | tee -a "$SUMMARY"
    record "preflight=pass"
  fi
fi

run_exact_test() {
  local test_name="$1"
  local log_name="$2"
  set +e
  ASTERISM_BUILD_ID="$TARGET_COMMIT" cargo test -p asterism-core "$test_name" \
    -- --exact --nocapture 2>&1 | tee "$EVIDENCE/$log_name"
  local test_rc=${PIPESTATUS[0]}
  set -e
  return "$test_rc"
}

if [ "$gate_rc" -eq 0 ]; then
  run_exact_test \
    remote_gpu_cuse::tests::kernel_record_is_received_by_one_sufficient_read \
    one-read-framing.log \
    || { block "one-read framing test failed" || gate_rc=1; }
fi
if [ "$gate_rc" -eq 0 ]; then
  run_exact_test \
    remote_gpu_cuse::tests::record_parser_rejects_short_truncated_trailing_and_oversized_frames \
    malformed-oversized.log \
    || { block "malformed/oversized framing test failed" || gate_rc=1; }
fi
if [ "$gate_rc" -eq 0 ]; then
  run_exact_test \
    remote_gpu_cuse::tests::known_request_bodies_are_bounded_before_field_parsing \
    bounded-bodies.log \
    || { block "bounded request-body test failed" || gate_rc=1; }
fi
if [ "$gate_rc" -eq 0 ]; then
  set +e
  ASTERISM_BUILD_ID="$TARGET_COMMIT" \
    cargo run -p asterism-core --example live_cuse_gate 2>&1 \
    | tee "$EVIDENCE/live-lifecycle.log"
  lifecycle_rc=${PIPESTATUS[0]}
  set -e
  if [ "$lifecycle_rc" -ne 0 ]; then
    block "live mount/open/read/write/poll/cancel/interrupt/teardown failed" || gate_rc=1
  fi
fi

if [ "$gate_rc" -eq 0 ]; then
  record "verdict=PASS"
  record "scope=CUSE_only"
  record "nvidia_hardware_claim=false"
fi

checksums="$(mktemp "${TMPDIR:-/tmp}/asterism-cuse-sums.XXXXXX")"
(
  cd "$EVIDENCE"
  find . -type f ! -name SHA256SUMS -print0 \
    | sort -z \
    | xargs -0 sha256sum >"$checksums"
)
mv "$checksums" "$EVIDENCE/SHA256SUMS"
exit "$gate_rc"
