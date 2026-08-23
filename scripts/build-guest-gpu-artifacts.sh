#!/bin/sh
set -eu

root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"

if [ -n "${ASTERISM_GPU_GUEST_TARGET:-}" ]; then
	target=$ASTERISM_GPU_GUEST_TARGET
else
	target=$(rustc -vV | sed -n 's/^host: //p')
fi
[ -n "$target" ] || { echo "could not resolve the native Rust target" >&2; exit 1; }
cargo_target_dir=${CARGO_TARGET_DIR:-target}
case "$cargo_target_dir" in
	/*) ;;
	*) cargo_target_dir="$root/$cargo_target_dir" ;;
esac
destination=${1:-$root/target/asterism-gpu-guest/$target}

CARGO_TARGET_DIR="$cargo_target_dir" \
	cargo build --release --locked --target "$target" \
		-p asterism-gpu-guest -p asterism-libcuda
mkdir -p "$destination/bin" "$destination/lib"
cp "$cargo_target_dir/$target/release/asterism-gpu-guest" "$destination/bin/asterism-gpu-guest"
cp "$cargo_target_dir/$target/release/libcuda.so" "$destination/lib/libcuda.so.1.0.0"
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

exports=$("$nm_tool" -D --defined-only "$destination/lib/libcuda.so.1.0.0" | awk '{print $NF}')
if printf '%s\n' "$exports" | grep -q '@'; then
  echo "unexpected ELF-versioned CUDA Driver export" >&2
  exit 1
fi
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
