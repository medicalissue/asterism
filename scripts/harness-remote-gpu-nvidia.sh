#!/usr/bin/env bash
# Exact real-NVIDIA release gate.
#
# The paid-host runner is the only component allowed to produce path evidence.
# This wrapper contributes independently observed git and NVIDIA inventory,
# rejects stand-ins, and judges the combined record. It never runs dstack and
# never turns the reference harness or a host-direct CUDA program into PASS.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
# shellcheck source=lib/nvidia-release-gate.sh
. "$ROOT/scripts/lib/nvidia-release-gate.sh"

fail() { echo "NVIDIA GATE FAIL: $*" >&2; exit 1; }
unavailable() { echo "NVIDIA GATE UNAVAILABLE: $*" >&2; exit 2; }
ok() { echo "ok: $*"; }

CANDIDATE_SHA="$(git rev-parse HEAD)"
TREE_DIGEST="$(git rev-parse 'HEAD^{tree}')"
echo "candidate_sha=$CANDIDATE_SHA"
echo "tree_digest=$TREE_DIGEST"
echo "base_sha=f656f017de3a0b34ce710350ee5e55fb2cb2e593"

if [ "${ASTERISM_SOURCE_ONLY:-0}" = 1 ]; then
  echo "hardware_cuda_executed=false"
  echo "nvidia_gate=unavailable"
  unavailable "source-only run; CUDA hardware gate not executed"
fi

PINNED="${ASTERISM_PINNED_SHA:-}"
[ -n "$PINNED" ] || fail "ASTERISM_PINNED_SHA is required"
nvidia_gate_is_oid "$PINNED" || fail "ASTERISM_PINNED_SHA is not a git oid"
[ "$PINNED" = "$CANDIDATE_SHA" ] \
  || fail "HEAD $CANDIDATE_SHA is not pinned candidate $PINNED"

if ! command -v nvidia-smi >/dev/null 2>&1; then
  unavailable "nvidia-smi not present"
fi

DRIVER="$(nvidia-smi --query-gpu=driver_version --format=csv,noheader 2>/dev/null | head -n1 | tr -d '[:space:]')"
CUDA="$(nvidia-smi 2>/dev/null | sed -n 's/.*CUDA Version: \([0-9][0-9.]*\).*/\1/p' | head -n1)"
[ -n "$DRIVER" ] || fail "nvidia-smi did not report a driver version"
[ -n "$CUDA" ] || fail "nvidia-smi did not report a CUDA version"

GPU_ROWS=()
while IFS= read -r row; do
  [ -n "$row" ] && GPU_ROWS+=("$row")
done <<EOF
$(nvidia-smi --query-gpu=index,uuid,name,memory.total,compute_cap --format=csv,noheader,nounits 2>/dev/null || true)
EOF
[ "${#GPU_ROWS[@]}" -ge 2 ] \
  || unavailable "need two NVIDIA GPUs; nvidia-smi listed ${#GPU_ROWS[@]}"

driver_major="${DRIVER%%.*}"
cuda_major="${CUDA%%.*}"
cuda_minor="${CUDA#*.}"
cuda_minor="${cuda_minor%%.*}"
case "$driver_major,$cuda_major,$cuda_minor" in
  *[!0-9,]*) fail "non-numeric driver/CUDA version: $DRIVER / $CUDA" ;;
esac
[ "$driver_major" -ge 550 ] || fail "NVIDIA driver $DRIVER is below 550"
if ! { [ "$cuda_major" -eq 12 ] && [ "$cuda_minor" -ge 4 ]; } \
  && [ "$cuda_major" -ne 13 ]; then
  fail "CUDA $CUDA is outside 12.4..13.x"
fi

UUIDS=()
for row in "${GPU_ROWS[@]}"; do
  uuid="$(printf '%s\n' "$row" | awk -F',' '{gsub(/^ +| +$/,"",$2); print $2}')"
  cc="$(printf '%s\n' "$row" | awk -F',' '{gsub(/^ +| +$/,"",$5); print $5}')"
  cc_major="${cc%%.*}"
  cc_minor="${cc#*.}"
  case "$cc_major,$cc_minor" in *[!0-9,]*) fail "invalid compute capability $cc" ;; esac
  if [ "$cc_major" -lt 7 ] || { [ "$cc_major" -eq 7 ] && [ "$cc_minor" -lt 5 ]; }; then
    fail "GPU $uuid compute capability $cc is below 7.5"
  fi
  UUIDS+=("$uuid")
done
[ "${UUIDS[0]}" != "${UUIDS[1]}" ] || fail "two distinct GPU UUIDs are required"

RUNNER="${ASTERISM_NVIDIA_E2E_RUNNER:-}"
[ -n "$RUNNER" ] || fail "ASTERISM_NVIDIA_E2E_RUNNER is required; no reference fallback"
[ -x "$RUNNER" ] || fail "NVIDIA E2E runner is not executable: $RUNNER"
case "$RUNNER" in
  "$ROOT"/*) ;;
  *) fail "NVIDIA E2E runner must come from pinned candidate tree $ROOT" ;;
esac
RUNNER_DIGEST="$(shasum -a 256 "$RUNNER" | awk '{print "sha256:"$1}')"
echo "runner_digest=$RUNNER_DIGEST"

RUN="$(mktemp -d "${TMPDIR:-/tmp}/asterism-nvidia-release.XXXXXX")"
trap 'rm -rf "$RUN"' EXIT
RUNNER_EVIDENCE="$RUN/runner.evidence"
RUNNER_BUNDLE="$RUN/runner.bundle.json"
RUNNER_VERIFIER="$RUN/runner.evidence.verifier"
EVIDENCE="$RUN/release.evidence"

# Runner contract: run a CUDA application inside the Asterism guest/container,
# across two named authenticated mesh devices, on the live provider. It must
# restart provider astd/helper and the guest, and prove direct, relay, revoke,
# contention, loss, and fresh-session skew. The wrapper supplies no defaults.
"$RUNNER" \
  --evidence "$RUNNER_EVIDENCE" \
  --guest-device-name "${ASTERISM_GPU_GUEST_DEVICE_NAME:-guest-gpu}" \
  --provider-device-name "${ASTERISM_GPU_PROVIDER_DEVICE_NAME:-provider-gpu}" \
  --first-gpu-uuid "${UUIDS[0]}" \
  --second-gpu-uuid "${UUIDS[1]}"
[ -s "$RUNNER_EVIDENCE" ] || fail "runner produced no evidence"
[ -s "$RUNNER_BUNDLE" ] || fail "runner produced no authenticated transcript bundle"
[ -x "$RUNNER_VERIFIER" ] || fail "runner produced no transcript verifier"
nvidia_gate_validate_runner_evidence "$RUNNER_EVIDENCE" \
  || fail "runner evidence is incomplete or contains forbidden keys"
DRIVER_DIGEST="$(nvidia_gate_require_kv "$RUNNER_EVIDENCE" driver_digest)"
VERIFIER_DIGEST="$(shasum -a 256 "$RUNNER_VERIFIER" | awk '{print "sha256:"$1}')"
[ "$DRIVER_DIGEST" = "$VERIFIER_DIGEST" ] \
  || fail "transcript verifier does not match the pinned driver digest"
"$RUNNER_VERIFIER" verify --bundle "$RUNNER_BUNDLE" \
  || fail "authenticated transcript verification failed"

{
  echo "candidate_sha=$CANDIDATE_SHA"
  echo "tree_digest=$TREE_DIGEST"
  echo "runner_digest=$RUNNER_DIGEST"
  echo "first_gpu_uuid=${UUIDS[0]}"
  echo "second_gpu_uuid=${UUIDS[1]}"
  echo "driver_version=$DRIVER"
  echo "cuda_runtime_version=$CUDA"
  echo "provenance_verified=true"
  sed -n '/^[a-z_][a-z_]*=/p' "$RUNNER_EVIDENCE"
} >"$EVIDENCE"

nvidia_gate_judge "$EVIDENCE" || fail "judge refused the real-hardware record"
cat "$EVIDENCE"
echo "nvidia_gate=pass"
ok "exact guest→mesh→provider NVIDIA release gate passed"
