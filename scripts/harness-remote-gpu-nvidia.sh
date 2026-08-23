#!/usr/bin/env bash
# Candidate-side live NVIDIA observation producer.
#
# This script records raw facts only. It contains no evidence normalizer,
# release policy, verdict, or acceptance emitter. A reviewer-selected immutable
# image consumes the completed directory read-only with networking disabled.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
# shellcheck source=lib/nvidia-release-gate.sh
. "$ROOT/scripts/lib/nvidia-release-gate.sh"

fail() { echo "NVIDIA OBSERVATION FAIL: $*" >&2; exit 1; }
unavailable() { echo "NVIDIA OBSERVATION UNAVAILABLE: $*" >&2; exit 2; }

CANDIDATE_SHA="$(git rev-parse HEAD)"
TREE_DIGEST="$(git rev-parse 'HEAD^{tree}')"
echo "candidate_sha=$CANDIDATE_SHA"
echo "tree_digest=$TREE_DIGEST"

if [ "${ASTERISM_SOURCE_ONLY:-0}" = 1 ]; then
  echo "hardware_cuda_executed=false"
  unavailable "source-only run; no live observation was attempted"
fi

PINNED="${ASTERISM_PINNED_SHA:-}"
[ -n "$PINNED" ] || fail "ASTERISM_PINNED_SHA is required"
nvidia_gate_is_oid "$PINNED" || fail "ASTERISM_PINNED_SHA is not a git oid"
[ "$PINNED" = "$CANDIDATE_SHA" ] || fail "checkout is not the pinned candidate"
[ -z "$(git status --porcelain --untracked-files=no)" ] || fail "tracked candidate files are dirty"

command -v nvidia-smi >/dev/null 2>&1 || unavailable "nvidia-smi not present"
DRIVER_VERSION="$(nvidia-smi --query-gpu=driver_version --format=csv,noheader 2>/dev/null | head -n1 | tr -d '[:space:]')"
CUDA_VERSION="$(nvidia-smi 2>/dev/null | sed -n 's/.*CUDA Version: \([0-9][0-9.]*\).*/\1/p' | head -n1)"
[ -n "$DRIVER_VERSION" ] || fail "nvidia-smi did not report a driver version"
[ -n "$CUDA_VERSION" ] || fail "nvidia-smi did not report a CUDA version"

GPU_ROWS=()
while IFS= read -r row; do [ -n "$row" ] && GPU_ROWS+=("$row"); done <<EOF
$(nvidia-smi --query-gpu=index,uuid,name,memory.total,compute_cap --format=csv,noheader,nounits 2>/dev/null || true)
EOF
[ "${#GPU_ROWS[@]}" -ge 2 ] || unavailable "two NVIDIA GPUs are required"

driver_major="${DRIVER_VERSION%%.*}"
cuda_major="${CUDA_VERSION%%.*}"
cuda_minor="${CUDA_VERSION#*.}"; cuda_minor="${cuda_minor%%.*}"
case "$driver_major,$cuda_major,$cuda_minor" in *[!0-9,]*) fail "non-numeric driver/CUDA version" ;; esac
[ "$driver_major" -ge 550 ] || fail "NVIDIA driver is below 550"
if ! { [ "$cuda_major" -eq 12 ] && [ "$cuda_minor" -ge 4 ]; } && [ "$cuda_major" -ne 13 ]; then
  fail "CUDA is outside 12.4..13.x"
fi

UUIDS=()
for row in "${GPU_ROWS[@]}"; do
  uuid="$(printf '%s\n' "$row" | awk -F',' '{gsub(/^ +| +$/,"",$2); print $2}')"
  cc="$(printf '%s\n' "$row" | awk -F',' '{gsub(/^ +| +$/,"",$5); print $5}')"
  cc_major="${cc%%.*}"; cc_minor="${cc#*.}"
  case "$cc_major,$cc_minor" in *[!0-9,]*) fail "invalid compute capability $cc" ;; esac
  if [ "$cc_major" -lt 7 ] || { [ "$cc_major" -eq 7 ] && [ "$cc_minor" -lt 5 ]; }; then
    fail "GPU $uuid compute capability $cc is below 7.5"
  fi
  UUIDS+=("$uuid")
done
[ "${UUIDS[0]}" != "${UUIDS[1]}" ] || fail "two distinct GPU UUIDs are required"

RUNNER="${ASTERISM_NVIDIA_E2E_RUNNER:-}"
[ -x "$RUNNER" ] || fail "an executable pinned-tree runner is required"
case "$RUNNER" in "$ROOT"/*) ;; *) fail "runner is outside the pinned candidate tree" ;; esac
RUNNER_DIGEST="$(shasum -a 256 "$RUNNER" | awk '{print "sha256:"$1}')"

RAW="${ASTERISM_NVIDIA_EVIDENCE_DIR:-}"
[ -n "$RAW" ] || fail "ASTERISM_NVIDIA_EVIDENCE_DIR is required"
case "$RAW" in /*) ;; *) fail "evidence directory must be absolute" ;; esac
[ ! -e "$RAW" ] || fail "evidence directory already exists"
mkdir -p "$RAW"

PROVIDER_IMAGE_DIGEST='sha256:435220c0fef35cbf712e11999f8670a83835ef3cdd18564e5e8122f83078c88c'
export ASTERISM_NVIDIA_PROVIDER_IMAGE_DIGEST="$PROVIDER_IMAGE_DIGEST"
export ASTERISM_NVIDIA_FIRST_GPU_UUID="${UUIDS[0]}"
export ASTERISM_NVIDIA_SECOND_GPU_UUID="${UUIDS[1]}"
"$RUNNER" --output-dir "$RAW"

for record in direct-success active-loss relay-success active-revoke contention version-skew-fresh-session; do
  [ -s "$RAW/$record.json" ] || fail "runner omitted raw observation $record"
done

{
  echo "candidate_sha=$CANDIDATE_SHA"
  echo "tree_digest=$TREE_DIGEST"
  echo "runner_digest=$RUNNER_DIGEST"
  echo "provider_image_digest=$PROVIDER_IMAGE_DIGEST"
  echo "first_gpu_uuid=${UUIDS[0]}"
  echo "second_gpu_uuid=${UUIDS[1]}"
  echo "driver_version=$DRIVER_VERSION"
  echo "cuda_runtime_version=$CUDA_VERSION"
  printf 'gpu_inventory=%s\n' "${GPU_ROWS[*]}"
  echo "provider_runtime_kind=in_process_astd_cuda_engine"
} >"$RAW/inventory"

find "$RAW" -type f ! -name manifest.sha256 -print0 \
  | sort -z | xargs -0 shasum -a 256 >"$RAW/manifest.sha256"
chmod -R a-w "$RAW"
echo "raw_evidence_dir=$RAW"
echo "raw_manifest_digest=$(shasum -a 256 "$RAW/manifest.sha256" | awk '{print "sha256:"$1}')"
