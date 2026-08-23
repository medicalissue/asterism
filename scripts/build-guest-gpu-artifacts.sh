#!/bin/sh
set -eu

target=${ASTERISM_GPU_GUEST_TARGET:-x86_64-unknown-linux-gnu}
destination=${1:-target/asterism-gpu-guest/$target}

cargo build --release --target "$target" -p asterism-gpu-guest -p asterism-libcuda
mkdir -p "$destination/bin" "$destination/lib"
cp "target/$target/release/asterism-gpu-guest" "$destination/bin/asterism-gpu-guest"
cp "target/$target/release/libcuda.so" "$destination/lib/libcuda.so.1.0.0"
ln -sfn libcuda.so.1.0.0 "$destination/lib/libcuda.so.1"
ln -sfn libcuda.so.1 "$destination/lib/libcuda.so"

readelf_tool=${READELF:-readelf}
nm_tool=${NM:-nm}
command -v "$readelf_tool" >/dev/null 2>&1 || {
  echo "readelf is required to audit the guest libcuda artifact" >&2
  exit 1
}
command -v "$nm_tool" >/dev/null 2>&1 || {
  echo "nm is required to audit the guest libcuda artifact" >&2
  exit 1
}
"$readelf_tool" -d "$destination/lib/libcuda.so.1.0.0" | grep -q 'SONAME.*libcuda.so.1'

exports=$("$nm_tool" -D --defined-only "$destination/lib/libcuda.so.1.0.0" | awk '{print $NF}' | sed 's/@.*//')
expected='cuInit cuDriverGetVersion cuDeviceGetCount cuDeviceGet cuDeviceGetName cuDeviceGetUuid cuDeviceGetAttribute cuCtxCreate cuCtxDestroy cuCtxGetCurrent cuCtxSetCurrent cuCtxSynchronize cuMemAlloc cuMemFree cuMemcpyHtoD cuMemcpyDtoH cuModuleLoadData cuModuleUnload cuModuleGetFunction cuLaunchKernel cuGetErrorString cuGetErrorName cuCtxCreate_v2 cuCtxDestroy_v2 cuMemAlloc_v2 cuMemFree_v2 cuMemcpyHtoD_v2 cuMemcpyDtoH_v2'
for symbol in $expected; do
  printf '%s\n' "$exports" | grep -qx "$symbol" || {
    echo "missing CUDA Driver export: $symbol" >&2
    exit 1
  }
done
for symbol in $exports; do
  case "$symbol" in
    cu*)
      case " $expected " in
        *" $symbol "*) ;;
        *)
          echo "unexpected CUDA Driver export: $symbol" >&2
          exit 1
          ;;
      esac
      ;;
  esac
done

printf '%s\n' "$destination"
