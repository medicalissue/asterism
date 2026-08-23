#!/usr/bin/env bash
# Launch the compiled guest payload in the immutable guest image. The only
# projected NVIDIA device is the Asterism Unix endpoint; the host's native
# NVIDIA devices are deliberately not passed through to the container.
set -euo pipefail

[ "$#" -eq 3 ] || { echo "guest launcher requires payload, device, libcuda" >&2; exit 1; }
GUEST_BINARY="$1"
PROJECTED_DEVICE="$2"
LIBCUDA="$3"
IMAGE="${ASTERISM_NVIDIA_GUEST_IMAGE:-}"

case "$IMAGE" in
  *@sha256:[0-9a-f][0-9a-f]*) ;;
  *) echo "guest image must be pinned by sha256 digest" >&2; exit 1 ;;
esac
[ -x "$GUEST_BINARY" ] || { echo "guest payload is not executable" >&2; exit 1; }
[ -S "$PROJECTED_DEVICE" ] || { echo "projected /dev/nvidia0 endpoint is not a socket" >&2; exit 1; }
[ -f "$LIBCUDA" ] || { echo "generated libcuda is missing" >&2; exit 1; }

# The independent verifier runs this launcher in a container while talking to
# the host Docker daemon. Translate only the verifier's explicitly shared
# result directory; refusing every other path prevents an apparently valid
# run whose guest mounts artifacts the daemon cannot actually see.
CONTAINER_RESULT="${ASTERISM_NVIDIA_DOCKER_CONTAINER_RESULT:-}"
HOST_RESULT="${ASTERISM_NVIDIA_DOCKER_HOST_RESULT:-}"
[ -n "$CONTAINER_RESULT" ] && [ -n "$HOST_RESULT" ] \
  || { echo "verifier/host result path mapping is required" >&2; exit 1; }
docker_host_path() {
  case "$1" in
    "$CONTAINER_RESULT"/*) printf '%s/%s\n' "$HOST_RESULT" "${1#"$CONTAINER_RESULT"/}" ;;
    *) echo "path is outside verifier result mount: $1" >&2; return 1 ;;
  esac
}
HOST_GUEST_BINARY="$(docker_host_path "$GUEST_BINARY")"
HOST_PROJECTED_DEVICE="$(docker_host_path "$PROJECTED_DEVICE")"
HOST_LIBCUDA="$(docker_host_path "$LIBCUDA")"

CONTAINER_ID="$(docker create --network none --read-only \
  --mount "type=bind,src=$HOST_GUEST_BINARY,dst=/asterism/guest,readonly" \
  --mount "type=bind,src=$HOST_PROJECTED_DEVICE,dst=/dev/nvidia0" \
  --mount "type=bind,src=$HOST_LIBCUDA,dst=/usr/lib/libcuda.so.1,readonly" \
  --env ASTERISM_GUEST_NVIDIA_DEVICE=/dev/nvidia0 \
  --env ASTERISM_LIBCUDA=/usr/lib/libcuda.so.1 \
  "$IMAGE" /asterism/guest)"
trap 'docker rm -f "$CONTAINER_ID" >/dev/null 2>&1 || true' EXIT
docker start "$CONTAINER_ID" >/dev/null
CONTAINER_PID="$(docker inspect --format '{{.State.Pid}}' "$CONTAINER_ID")"
printf 'guest_container_id=%s\n' "$CONTAINER_ID"
printf 'guest_container_pid=%s\n' "$CONTAINER_PID"
docker logs --follow "$CONTAINER_ID" &
LOG_PID=$!
STATUS="$(docker wait "$CONTAINER_ID")"
wait "$LOG_PID"
exit "$STATUS"
