#!/usr/bin/env bash
# Candidate-side producer of raw observations. It never verifies or accepts
# them: the release wrapper hands the complete directory to an immutable,
# independently supplied verifier image.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
fail() { echo "NVIDIA E2E DRIVER FAIL: $*" >&2; exit 1; }

OUT=''
while [ "$#" -gt 0 ]; do
  case "$1" in --output-dir) OUT="$2"; shift 2 ;; *) fail "unknown argument $1" ;; esac
done
[ -n "$OUT" ] || fail "--output-dir is required"
mkdir -p "$OUT"

PINNED="${ASTERISM_PINNED_SHA:-}"
[ -n "$PINNED" ] || fail "ASTERISM_PINNED_SHA is required"
[ "$(git rev-parse HEAD)" = "$PINNED" ] || fail "checkout is not the pinned candidate"
[ -z "$(git status --porcelain --untracked-files=no)" ] || fail "tracked candidate files are dirty"
for tool in cargo cc docker; do command -v "$tool" >/dev/null 2>&1 || fail "$tool is required"; done

GUEST_IMAGE='docker.io/library/ubuntu:24.04@sha256:1e0a86e57d247923571b75e0aaf48a1449cf8c543d51fb3e07a4a7d7bfa79316'
PROVIDER_IMAGE_DIGEST='sha256:435220c0fef35cbf712e11999f8670a83835ef3cdd18564e5e8122f83078c88c'
BUILD="$(mktemp -d "${TMPDIR:-/tmp}/asterism-nvidia-build.XXXXXX")"
trap 'jobs -pr | xargs -r kill 2>/dev/null || true; rm -rf "$BUILD"' EXIT
export CARGO_TARGET_DIR="$BUILD/target"
cargo build --locked --release -p asterism-nvidia-e2e-driver -p asterism-libcuda -p asterism-daemon -p asterism-cli
cc -O2 -Wall -Wextra -Werror "$ROOT/scripts/lib/guest_remote_cuda_vector_add.c" -ldl -o "$BUILD/guest-remote-cuda"

DRIVER="$CARGO_TARGET_DIR/release/asterism-nvidia-e2e-driver"
LIBCUDA="$CARGO_TARGET_DIR/release/libcuda.so"
ASTD="$CARGO_TARGET_DIR/release/astd"
AST="$CARGO_TARGET_DIR/release/ast"
for artifact in "$DRIVER" "$LIBCUDA" "$ASTD" "$AST" "$BUILD/guest-remote-cuda"; do
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

GUEST_HOME="$BUILD/guest-home"
PROVIDER_HOME="$BUILD/provider-home"
GUEST_NAME="${ASTERISM_GPU_GUEST_DEVICE_NAME:-guest-gpu}"
PROVIDER_NAME="${ASTERISM_GPU_PROVIDER_DEVICE_NAME:-provider-gpu}"
FIRST_UUID="${ASTERISM_NVIDIA_FIRST_GPU_UUID:?first GPU UUID required}"
SECOND_UUID="${ASTERISM_NVIDIA_SECOND_GPU_UUID:?second GPU UUID required}"

start_guest() {
  local mode="$1" log="$2"
  if [ "$mode" = relay ]; then
    ASTERISM_HOME="$GUEST_HOME" ASTERISM_MESH_NO_DIRECT=1 ASTERISM_DISABLE_GPU_PROVIDER=1 "$ASTD" >"$log" 2>&1 &
  else
    ASTERISM_HOME="$GUEST_HOME" ASTERISM_MESH=local ASTERISM_DISABLE_GPU_PROVIDER=1 "$ASTD" >"$log" 2>&1 &
  fi
  GUEST_PID=$!
}
start_provider() {
  local mode="$1" uuid="$2" peer="$3" instance_id="$4" log="$5"
  if [ "$mode" = relay ]; then
    ASTERISM_HOME="$PROVIDER_HOME" ASTERISM_MESH_NO_DIRECT=1 ASTERISM_GPU_UUID="$uuid" \
      ASTERISM_GPU_BOOTSTRAP_PEER="$peer" ASTERISM_GPU_BOOTSTRAP_INSTANCE="$instance_id" \
      ASTERISM_GPU_BOOTSTRAP_MEMORY_BYTES=67108864 "$ASTD" >"$log" 2>&1 &
  else
    ASTERISM_HOME="$PROVIDER_HOME" ASTERISM_MESH=local ASTERISM_GPU_UUID="$uuid" \
      ASTERISM_GPU_BOOTSTRAP_PEER="$peer" ASTERISM_GPU_BOOTSTRAP_INSTANCE="$instance_id" \
      ASTERISM_GPU_BOOTSTRAP_MEMORY_BYTES=67108864 "$ASTD" >"$log" 2>&1 &
  fi
  PROVIDER_PID=$!
}
wait_socket() {
  local socket="$1" pid="$2"
  for _ in $(seq 1 200); do [ -S "$socket" ] && return; kill -0 "$pid" 2>/dev/null || fail "astd exited before socket bind"; sleep 0.05; done
  fail "astd did not bind $socket"
}
stop_pid() { kill "$1" 2>/dev/null || true; wait "$1" 2>/dev/null || true; }
pair_devices() {
  ASTERISM_HOME="$PROVIDER_HOME" "$AST" device invite --name "$PROVIDER_NAME" --yes >"$OUT/invite.log" 2>&1 &
  local invite_pid=$! ticket=''
  for _ in $(seq 1 200); do
    ticket="$(sed -n 's/.*ast device add \([^[:space:]]*\).*/\1/p' "$OUT/invite.log" | head -n1)"
    [ -n "$ticket" ] && break
    kill -0 "$invite_pid" 2>/dev/null || fail "device invite exited before printing a ticket"
    sleep 0.05
  done
  [ -n "$ticket" ] || fail "device invite produced no ticket"
  ASTERISM_HOME="$GUEST_HOME" "$AST" device add "$ticket" --name "$GUEST_NAME" --yes >"$OUT/add.log" 2>&1
  wait "$invite_pid"
}
observe() {
  local name="$1" path="$2" fault="$3" uuid="$4"
  "$DRIVER" observe --output "$OUT/$name.json" --guest-home "$GUEST_HOME" --provider-home "$PROVIDER_HOME" \
    --guest-device-name "$GUEST_NAME" --provider-device-name "$PROVIDER_NAME" --path "$path" --fault "$fault" \
    --gpu-uuid "$uuid" --provider-astd-pid "$PROVIDER_PID" --guest-astd-pid "$GUEST_PID" \
    --guest-astd-log "$OUT/$path-guest-astd.log" --provider-astd-log "$OUT/$path-provider-astd.log"
}

# Generate identities through the real daemons, then pair them through the real
# invitation/SAS exchange. Neither identity is derived from a run label.
ASTERISM_HOME="$PROVIDER_HOME" ASTERISM_MESH=local ASTERISM_DISABLE_GPU_PROVIDER=1 "$ASTD" >"$OUT/bootstrap-provider.log" 2>&1 &
PROVIDER_PID=$!
start_guest direct "$OUT/bootstrap-guest.log"
wait_socket "$PROVIDER_HOME/astd.sock" "$PROVIDER_PID"
wait_socket "$GUEST_HOME/astd.sock" "$GUEST_PID"
pair_devices
GUEST_ID="$($DRIVER identity --home "$GUEST_HOME")"
PROVIDER_ID="$($DRIVER identity --home "$PROVIDER_HOME")"
printf 'guest_device_id=%s\nprovider_device_id=%s\n' "$GUEST_ID" "$PROVIDER_ID" >"$OUT/paired-identities"
stop_pid "$GUEST_PID"; stop_pid "$PROVIDER_PID"

# A direct success and active provider-loss observation on the first GPU.
INSTANCE_ID="$("$DRIVER" prepare --guest-home "$GUEST_HOME" --provider-home "$PROVIDER_HOME" \
  --guest-device-name "$GUEST_NAME" --provider-device-name "$PROVIDER_NAME" --gpu-uuid "$FIRST_UUID" --provider-generation 1 \
  | sed -n 's/^instance_id=//p')"
[ -n "$INSTANCE_ID" ] || fail "prepare produced no orbit instance identity"
start_provider direct "$FIRST_UUID" "$GUEST_ID" "$INSTANCE_ID" "$OUT/direct-provider-astd.log"
wait_socket "$PROVIDER_HOME/astd.sock" "$PROVIDER_PID"
start_guest direct "$OUT/direct-guest-astd.log"; wait_socket "$GUEST_HOME/astd.sock" "$GUEST_PID"
observe direct-success direct none "$FIRST_UUID"
observe active-loss direct loss "$FIRST_UUID"
stop_pid "$GUEST_PID"; stop_pid "$PROVIDER_PID"

# Restart both paired identities with IP transports disabled. A PASS therefore
# requires iroh to report a real relay-selected QUIC path, not a Unix proxy.
INSTANCE_ID="$("$DRIVER" prepare --guest-home "$GUEST_HOME" --provider-home "$PROVIDER_HOME" \
  --guest-device-name "$GUEST_NAME" --provider-device-name "$PROVIDER_NAME" --gpu-uuid "$SECOND_UUID" --provider-generation 1 \
  | sed -n 's/^instance_id=//p')"
start_provider relay "$SECOND_UUID" "$GUEST_ID" "$INSTANCE_ID" "$OUT/relay-provider-astd.log"
wait_socket "$PROVIDER_HOME/astd.sock" "$PROVIDER_PID"
start_guest relay "$OUT/relay-guest-astd.log"; wait_socket "$GUEST_HOME/astd.sock" "$GUEST_PID"
observe relay-success relay none "$SECOND_UUID"
observe active-revoke relay revoke "$SECOND_UUID"
stop_pid "$GUEST_PID"; stop_pid "$PROVIDER_PID"

shasum -a 256 "$DRIVER" "$ASTD" "$AST" "$LIBCUDA" "$BUILD/guest-remote-cuda" \
  "$ROOT/scripts/lib/nvidia-guest-container.sh" >"$OUT/artifacts.sha256"
printf 'candidate_sha=%s\ntree_digest=%s\n' "$(git rev-parse HEAD)" "$(git rev-parse 'HEAD^{tree}')" >"$OUT/candidate"
