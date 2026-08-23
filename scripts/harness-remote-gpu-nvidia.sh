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
echo "base_sha=c964b8c6bbcc44bfea02cb1f7e46bf6dd861ed18"

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

VERIFIER_IMAGE="${ASTERISM_NVIDIA_VERIFIER_IMAGE:-}"
VERIFIER_DIGEST="${ASTERISM_NVIDIA_VERIFIER_DIGEST:-}"
case "$VERIFIER_IMAGE" in *@sha256:[0-9a-f][0-9a-f]*) ;; *) fail "external verifier image must be digest-pinned" ;; esac
nvidia_gate_is_sha256 "$VERIFIER_DIGEST" || fail "ASTERISM_NVIDIA_VERIFIER_DIGEST must be sha256"
[ "${VERIFIER_IMAGE##*@}" = "$VERIFIER_DIGEST" ] || fail "external verifier image/digest mismatch"

RUN="$(mktemp -d "${TMPDIR:-/tmp}/asterism-nvidia-release.XXXXXX")"
trap 'rm -rf "$RUN"' EXIT
RAW="$RUN/raw"
EVIDENCE="$RUN/release.evidence"
mkdir -p "$RAW"

# Runner contract: run a CUDA application inside the Asterism guest/container,
# across two named authenticated mesh devices, on the live provider. It must
# restart provider astd/helper and the guest, and prove direct, relay, revoke,
# contention, loss, and fresh-session skew. The wrapper supplies no defaults.
export ASTERISM_NVIDIA_FIRST_GPU_UUID="${UUIDS[0]}"
export ASTERISM_NVIDIA_SECOND_GPU_UUID="${UUIDS[1]}"
"$RUNNER" --output-dir "$RAW"
for raw in direct-success active-loss relay-success active-revoke; do
  [ -s "$RAW/$raw.json" ] || fail "runner omitted raw observation $raw"
done

# The candidate can produce observations but cannot accept them. The image is
# supplied and digest-pinned by the independent reviewer, runs read-only and
# offline, and is the only component allowed to emit normalized PASS evidence.
docker run --rm --network none --read-only \
  --mount "type=bind,src=$RAW,dst=/evidence,readonly" \
  "$VERIFIER_IMAGE" /verify \
    --evidence /evidence \
    --candidate-sha "$CANDIDATE_SHA" \
    --tree-digest "$TREE_DIGEST" \
    --runner-digest "$RUNNER_DIGEST" >"$EVIDENCE"
[ -s "$EVIDENCE" ] || fail "external verifier emitted no acceptance record"
nvidia_gate_validate_runner_evidence "$EVIDENCE" \
  || fail "external verifier evidence is incomplete or contains forbidden keys"

{
  echo "candidate_sha=$CANDIDATE_SHA"
  echo "tree_digest=$TREE_DIGEST"
  echo "runner_digest=$RUNNER_DIGEST"
  echo "first_gpu_uuid=${UUIDS[0]}"
  echo "second_gpu_uuid=${UUIDS[1]}"
  echo "driver_version=$DRIVER"
  echo "cuda_runtime_version=$CUDA"
  echo "verifier_image_digest=$VERIFIER_DIGEST"
  sed -n '/^[a-z_][a-z_]*=/p' "$EVIDENCE"
} >"$RUN/release.combined"
mv "$RUN/release.combined" "$EVIDENCE"

nvidia_gate_judge "$EVIDENCE" || fail "judge refused the real-hardware record"
cat "$EVIDENCE"
echo "nvidia_gate=pass"
ok "exact guest→mesh→provider NVIDIA release gate passed"
