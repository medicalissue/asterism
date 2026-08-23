#!/usr/bin/env bash
# Two-device NVIDIA hardware gate for the production remote GPU part.
#
# Exit codes:
#   0  real CUDA evidence on two devices (kernel + contract)
#   1  fail-closed (unsupported driver/CUDA/CC, or a test failed)
#   2  unavailable (no nvidia-smi, or fewer than two GPUs)
#   3  contract-only (reference harness passed; not hardware evidence)
#
# This script never treats the CPU reference executor as NVIDIA evidence,
# never opens a public plaintext listener, and never calls `dstack apply`.
# Provisioning is Sol's paid step; the local dstack server is an external
# execution blocker (root 500 / offers 405-class failure), not a reason to
# weaken these checks.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

fail() { echo "NVIDIA GATE FAIL: $*" >&2; exit 1; }
unavailable() { echo "NVIDIA GATE UNAVAILABLE: $*" >&2; exit 2; }
ok() { echo "ok: $*"; }

echo "guest_visible_device=/dev/nvidia0"
echo "remote_gpu_abi=1"
echo "hardware_cuda_executed=false"

if [ "${ASTERISM_SOURCE_ONLY:-0}" = 1 ]; then
  unavailable "source-only run; CUDA hardware gate not executed"
fi

if ! command -v nvidia-smi >/dev/null 2>&1; then
  unavailable "nvidia-smi not present"
fi

DRIVER="$(nvidia-smi --query-gpu=driver_version --format=csv,noheader 2>/dev/null | head -n1 | tr -d '[:space:]')"
[ -n "$DRIVER" ] || fail "nvidia-smi did not report a driver version"

CUDA="$(nvidia-smi 2>/dev/null | sed -n 's/.*CUDA Version: \([0-9][0-9.]*\).*/\1/p' | head -n1)"
[ -n "$CUDA" ] || fail "nvidia-smi did not report a CUDA version"

GPU_ROWS=()
while IFS= read -r row; do
  [ -n "$row" ] && GPU_ROWS+=("$row")
done <<EOF
$(nvidia-smi --query-gpu=index,uuid,name,memory.total,compute_cap --format=csv,noheader,nounits 2>/dev/null || true)
EOF
GPU_COUNT="${#GPU_ROWS[@]}"
if [ "$GPU_COUNT" -lt 2 ]; then
  unavailable "need 2 NVIDIA GPUs, nvidia-smi listed ${GPU_COUNT:-0}"
fi

driver_major="${DRIVER%%.*}"
cuda_major="${CUDA%%.*}"
cuda_rest="${CUDA#*.}"
cuda_minor="${cuda_rest%%.*}"
case "$cuda_minor" in
  ''|*[!0-9]*) cuda_minor=0 ;;
esac

if [ "$driver_major" -lt 550 ]; then
  fail "NVIDIA driver $DRIVER is unsupported; require 550+"
fi
cuda_ok=0
if [ "$cuda_major" -eq 12 ] && [ "$cuda_minor" -ge 4 ]; then
  cuda_ok=1
elif [ "$cuda_major" -eq 13 ]; then
  cuda_ok=1
fi
if [ "$cuda_ok" -ne 1 ]; then
  fail "CUDA runtime $CUDA is unsupported; require 12.4..13.x"
fi
ok "driver $DRIVER and CUDA $CUDA are inside the fail-closed matrix"

INVENTORY="$(mktemp "${TMPDIR:-/tmp}/asterism-nvidia-inventory.XXXXXX")"
trap 'rm -f "$INVENTORY"' EXIT
{
  echo "driver_version=$DRIVER"
  echo "cuda_runtime_version=$CUDA"
  for row in "${GPU_ROWS[@]}"; do
    index="$(printf '%s\n' "$row" | awk -F',' '{gsub(/^ +| +$/,"",$1); print $1}')"
    uuid="$(printf '%s\n' "$row" | awk -F',' '{gsub(/^ +| +$/,"",$2); print $2}')"
    name="$(printf '%s\n' "$row" | awk -F',' '{gsub(/^ +| +$/,"",$3); print $3}')"
    memory_mib="$(printf '%s\n' "$row" | awk -F',' '{gsub(/^ +| +$/,"",$4); print $4}')"
    memory_mib="${memory_mib%%.*}"
    cc="$(printf '%s\n' "$row" | awk -F',' '{gsub(/^ +| +$/,"",$5); print $5}')"
    cc_major="${cc%%.*}"
    cc_minor="${cc#*.}"
    if [ "$cc_major" -lt 7 ] || { [ "$cc_major" -eq 7 ] && [ "${cc_minor%%.*}" -lt 5 ]; }; then
      fail "GPU $uuid compute capability $cc is unsupported; require 7.5+"
    fi
    memory_bytes=$((memory_mib * 1024 * 1024))
    echo "gpu index=$index uuid=$uuid memory_bytes=$memory_bytes compute_capability=$cc name=$name"
  done
} >"$INVENTORY"
ok "wrote two-device inventory with $GPU_COUNT GPUs"

KERNEL_OK=0
if command -v nvcc >/dev/null 2>&1; then
  KERNEL_BIN="$(mktemp "${TMPDIR:-/tmp}/asterism-nvidia-kernel.XXXXXX")"
  trap 'rm -f "$INVENTORY" "$KERNEL_BIN"' EXIT
  nvcc -o "$KERNEL_BIN" "$ROOT/scripts/lib/remote_gpu_vector_add.cu" \
    || fail "nvcc could not compile scripts/lib/remote_gpu_vector_add.cu"
  "$KERNEL_BIN" 0 || fail "CUDA kernel failed on device 0"
  "$KERNEL_BIN" 1 || fail "CUDA kernel failed on device 1"
  KERNEL_OK=1
  ok "CUDA vector-add kernel verified on devices 0 and 1"
else
  echo "nvcc not present; kernel evidence not collected"
fi

CONTRACT_OK=0
if command -v cargo >/dev/null 2>&1 && [ "${ASTERISM_NVIDIA_ALLOW_CARGO:-1}" = 1 ]; then
  cargo run -q -p asterism-core --example remote_gpu_nvidia_harness -- \
    --inventory "$INVENTORY" \
    || fail "two-device NVIDIA contract harness failed"
  CONTRACT_OK=1
  ok "deterministic two-device contract passed (reference executor)"
else
  echo "cargo skipped; contract evidence not collected in this process"
fi

if [ "$KERNEL_OK" -eq 1 ] && [ "$CONTRACT_OK" -eq 1 ]; then
  echo "hardware_cuda_executed=true"
  echo "nvidia_gate=pass"
  ok "two-device NVIDIA hardware gate passed"
  exit 0
fi

if [ "$CONTRACT_OK" -eq 1 ]; then
  echo "hardware_cuda_executed=false"
  echo "nvidia_gate=contract_only"
  echo "NVIDIA GATE CONTRACT-ONLY: kernel evidence missing; not a hardware pass" >&2
  exit 3
fi

unavailable "two NVIDIA devices present but cargo/nvcc evidence was not collected"
