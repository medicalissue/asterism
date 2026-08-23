#!/usr/bin/env bash
# Build and run the exact paid-host NVIDIA E2E driver from the pinned checkout.
# Build products live in a private temporary directory and no caller may select
# a replacement driver, ABI shim, guest payload, daemon, or container image.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

fail() { echo "NVIDIA E2E DRIVER FAIL: $*" >&2; exit 1; }

EVIDENCE=''
for ((index = 1; index <= $#; index++)); do
  if [ "${!index}" = "--evidence" ]; then
    next=$((index + 1))
    [ "$next" -le "$#" ] || fail "--evidence has no value"
    EVIDENCE="${!next}"
    break
  fi
done
[ -n "$EVIDENCE" ] || fail "--evidence is required"

PINNED="${ASTERISM_PINNED_SHA:-}"
[ -n "$PINNED" ] || fail "ASTERISM_PINNED_SHA is required"
[ "$(git rev-parse HEAD)" = "$PINNED" ] || fail "checkout is not the pinned candidate"
[ -z "$(git status --porcelain --untracked-files=no)" ] || fail "tracked candidate files are dirty"

for tool in cargo cc docker; do
  command -v "$tool" >/dev/null 2>&1 || fail "$tool is required"
done

GUEST_IMAGE='docker.io/library/ubuntu:24.04@sha256:1e0a86e57d247923571b75e0aaf48a1449cf8c543d51fb3e07a4a7d7bfa79316'
PROVIDER_IMAGE_DIGEST='sha256:435220c0fef35cbf712e11999f8670a83835ef3cdd18564e5e8122f83078c88c'
BUILD="$(mktemp -d "${TMPDIR:-/tmp}/asterism-nvidia-build.XXXXXX")"
trap 'rm -rf "$BUILD"' EXIT
export CARGO_TARGET_DIR="$BUILD/target"

cargo build --locked --release \
  -p asterism-nvidia-e2e-driver \
  -p asterism-libcuda \
  -p asterism-daemon
cc -O2 -Wall -Wextra -Werror \
  "$ROOT/scripts/lib/guest_remote_cuda_vector_add.c" \
  -ldl -o "$BUILD/guest-remote-cuda"

DRIVER="$CARGO_TARGET_DIR/release/asterism-nvidia-e2e-driver"
LIBCUDA="$CARGO_TARGET_DIR/release/libcuda.so"
ASTD="$CARGO_TARGET_DIR/release/astd"
for artifact in "$DRIVER" "$LIBCUDA" "$ASTD" "$BUILD/guest-remote-cuda"; do
  [ -f "$artifact" ] || fail "build did not produce $artifact"
done

docker pull "$GUEST_IMAGE" >/dev/null

export ASTERISM_NVIDIA_LIBCUDA="$LIBCUDA"
export ASTERISM_NVIDIA_GUEST_BINARY="$BUILD/guest-remote-cuda"
export ASTERISM_NVIDIA_ASTD="$ASTD"
export ASTERISM_NVIDIA_GUEST_LAUNCHER="$ROOT/scripts/lib/nvidia-guest-container.sh"
export ASTERISM_NVIDIA_GUEST_IMAGE="$GUEST_IMAGE"
export ASTERISM_NVIDIA_GUEST_IMAGE_DIGEST="${GUEST_IMAGE##*@}"
export ASTERISM_NVIDIA_PROVIDER_IMAGE_DIGEST="$PROVIDER_IMAGE_DIGEST"

"$DRIVER" "$@"
BUNDLE="${EVIDENCE%.*}.bundle.json"
[ -s "$BUNDLE" ] || fail "driver produced no transcript bundle"
"$DRIVER" verify --bundle "$BUNDLE"
cp "$DRIVER" "$EVIDENCE.verifier"
