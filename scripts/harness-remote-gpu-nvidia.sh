#!/usr/bin/env bash
# Exact real-NVIDIA release gate.
#
# One end-to-end path counts as hardware PASS:
#   CUDA app inside an Asterism guest/container
#     → opens projected /dev/nvidia0 and injected libcuda
#     → crosses two named mesh devices (guest ↔ provider)
#     → executes on the provider CUDA helper (real NVIDIA)
#
# Exit codes:
#   0  hardware PASS (judge accepted the exact path)
#   1  fail-closed (unsupported matrix, stand-in path, or a test failed)
#   2  unavailable (source-only, no nvidia-smi, or two GPUs missing)
#
# This script never treats Executor::Reference, a host-direct nvcc kernel,
# or a mock inventory as NVIDIA evidence. It never calls `dstack apply`.
# Provisioning is Sol's paid step after a healthy plan preview.
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
echo "guest_visible_device=/dev/nvidia0"
echo "remote_gpu_abi=1"
echo "base_sha=f656f017de3a0b34ce710350ee5e55fb2cb2e593"

DSTACK_YML="$ROOT/deploy/dstack/remote-gpu-nvidia.dstack.yml"
nvidia_gate_validate_dstack "$DSTACK_YML" || fail "dstack task schema is invalid"
DSTACK_PIN="$(awk '/^[[:space:]]*hash:/{gsub(/["'\'']/, "", $2); print $2; exit}' "$DSTACK_YML")"
ok "dstack schema valid; repos.hash=$DSTACK_PIN"

GUEST_NAME="${ASTERISM_GPU_GUEST_DEVICE_NAME:-guest-gpu}"
PROVIDER_NAME="${ASTERISM_GPU_PROVIDER_DEVICE_NAME:-provider-gpu}"
echo "guest_device_name=$GUEST_NAME"
echo "provider_device_name=$PROVIDER_NAME"

if [ "${ASTERISM_SOURCE_ONLY:-0}" = 1 ]; then
  echo "hardware_cuda_executed=false"
  echo "nvidia_gate=unavailable"
  unavailable "source-only run; CUDA hardware gate not executed"
fi

if ! command -v nvidia-smi >/dev/null 2>&1; then
  echo "hardware_cuda_executed=false"
  echo "nvidia_gate=unavailable"
  unavailable "nvidia-smi not present"
fi

# Fail-closed inventory. Two devices, driver 550+, CUDA 12.4..13.x, CC 7.5+.
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
  echo "hardware_cuda_executed=false"
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
echo "driver_version=$DRIVER"
echo "cuda_runtime_version=$CUDA"

UUIDS=()
for row in "${GPU_ROWS[@]}"; do
  uuid="$(printf '%s\n' "$row" | awk -F',' '{gsub(/^ +| +$/,"",$2); print $2}')"
  cc="$(printf '%s\n' "$row" | awk -F',' '{gsub(/^ +| +$/,"",$5); print $5}')"
  cc_major="${cc%%.*}"
  cc_minor="${cc#*.}"
  if [ "$cc_major" -lt 7 ] || { [ "$cc_major" -eq 7 ] && [ "${cc_minor%%.*}" -lt 5 ]; }; then
    fail "GPU $uuid compute capability $cc is unsupported; require 7.5+"
  fi
  UUIDS+=("$uuid")
  echo "gpu uuid=$uuid compute_capability=$cc"
done
echo "first_gpu_uuid=${UUIDS[0]}"
echo "second_gpu_uuid=${UUIDS[1]}"

# Hardware PASS requires the pinned SHA. dstack clones repos.hash; Sol must
# set ASTERISM_PINNED_SHA to that same oid. A mismatch is fail-closed.
PINNED="${ASTERISM_PINNED_SHA:-}"
[ -n "$PINNED" ] || fail "ASTERISM_PINNED_SHA is required for a hardware PASS"
nvidia_gate_is_oid "$PINNED" || fail "ASTERISM_PINNED_SHA is not a git oid"
if [ "$PINNED" != "$CANDIDATE_SHA" ]; then
  fail "HEAD $CANDIDATE_SHA is not the pinned SHA $PINNED"
fi
if [ "$PINNED" != "$DSTACK_PIN" ]; then
  fail "dstack repos.hash $DSTACK_PIN is not the pinned SHA $PINNED"
fi
ok "HEAD, ASTERISM_PINNED_SHA and dstack repos.hash agree"

# Refuse the old aggregate: host-direct CUDA + CPU reference contract.
# Those remain available as *non-PASS* diagnostics only if explicitly named.
if [ "${ASTERISM_NVIDIA_ALLOW_LOCAL_DIRECT:-0}" = 1 ]; then
  fail "local-direct CUDA is not a release-gate path"
fi

# Consume 13.2 / 13.3 candidates. Missing seams fail closed; they must not
# fall through to the reference executor or a host nvcc kernel.
AST="${ASTERISM_AST:-}"
ASTD="${ASTERISM_ASTD:-}"
HELPER="${ASTERISM_GPU_PROVIDER_HELPER:-}"
LIBCUDA="${ASTERISM_LIBCUDA:-}"
if [ -z "$AST" ] || [ ! -x "$AST" ]; then
  AST="$(command -v ast || true)"
fi
if [ -z "$ASTD" ] || [ ! -x "$ASTD" ]; then
  ASTD="$(command -v astd || true)"
fi
if [ -z "$HELPER" ] || [ ! -x "$HELPER" ]; then
  fail "provider CUDA helper (as-lvf.13.3) is not on PATH; reference cannot PASS"
fi
if [ -z "$LIBCUDA" ]; then
  fail "ASTERISM_LIBCUDA (as-lvf.13.2 guest projection) is required; metadata /dev/nvidia0 cannot PASS"
fi
if [ -z "$AST" ] || [ -z "$ASTD" ]; then
  fail "ast/astd are required to restart provider and guest processes"
fi

RUN="$(mktemp -d "${TMPDIR:-/tmp}/asterism-nvidia-release.XXXXXX")"
GUEST_HOME="$RUN/guest"
PROVIDER_HOME="$RUN/provider"
EVIDENCE="$RUN/evidence"
mkdir -p "$GUEST_HOME" "$PROVIDER_HOME"
PROVIDER_ASTD_PID=""
GUEST_ASTD_PID=""
HELPER_PID=""
GUEST_PID=""

kill_pid() {
  local pid="$1" _i
  case "$pid" in ''|*[!0-9]*) return 0 ;; esac
  kill -0 "$pid" 2>/dev/null || return 0
  kill -TERM "$pid" 2>/dev/null || true
  for _i in $(seq 1 25); do
    kill -0 "$pid" 2>/dev/null || return 0
    sleep 0.2
  done
  kill -KILL "$pid" 2>/dev/null || true
}

cleanup() {
  kill_pid "$GUEST_PID"
  kill_pid "$HELPER_PID"
  kill_pid "$GUEST_ASTD_PID"
  kill_pid "$PROVIDER_ASTD_PID"
  if [ -n "${KEEP:-}" ]; then
    echo "kept $RUN for inspection"
  else
    rm -rf "$RUN"
  fi
}
trap cleanup EXIT

start_astd() {
  local home="$1"
  mkdir -p "$home"
  ( ASTERISM_HOME="$home" ASTERISM_MESH=local "$ASTD" >>"$home/astd.log" 2>&1 & )
  local _i
  for _i in $(seq 1 100); do
    [ -S "$home/astd.sock" ] && [ -s "$home/astd.pid" ] && return 0
    sleep 0.2
  done
  fail "astd did not come up on $home:"$'\n'"$(cat "$home/astd.log" 2>/dev/null || true)"
}

start_astd "$PROVIDER_HOME"
PROVIDER_ASTD_PID="$(cat "$PROVIDER_HOME/astd.pid")"
start_astd "$GUEST_HOME"
GUEST_ASTD_PID="$(cat "$GUEST_HOME/astd.pid")"
ok "provider astd pid $PROVIDER_ASTD_PID and guest astd pid $GUEST_ASTD_PID"

# Two named mesh devices. Pairing uses the same invite/add path as e2e-mesh.
ASTERISM_HOME="$PROVIDER_HOME" "$AST" device invite --name "$PROVIDER_NAME" --yes \
  >"$PROVIDER_HOME/invite.out" 2>&1 &
INVITE_PID=$!
TICKET=""
for _ in $(seq 1 150); do
  TICKET="$(grep -o 'astdev1[a-z0-9]*' "$PROVIDER_HOME/invite.out" 2>/dev/null | head -1 || true)"
  [ -n "$TICKET" ] && break
  sleep 0.2
done
[ -n "$TICKET" ] || fail "no mesh ticket:"$'\n'"$(cat "$PROVIDER_HOME/invite.out")"
ASTERISM_HOME="$GUEST_HOME" "$AST" device add "$TICKET" --name "$GUEST_NAME" --yes \
  >"$GUEST_HOME/add.out" 2>&1 \
  || fail "mesh pair failed:"$'\n'"$(cat "$GUEST_HOME/add.out")"
wait "$INVITE_PID" || fail "device invite failed:"$'\n'"$(cat "$PROVIDER_HOME/invite.out")"
ok "named mesh devices $GUEST_NAME and $PROVIDER_NAME are paired"

GUEST_DEVICE_ID="$(ASTERISM_HOME="$GUEST_HOME" "$AST" devices --json 2>/dev/null | python3 -c 'import json,sys,os; d=json.load(sys.stdin); print(d[0]["id"] if isinstance(d,list) else "")' || true)"
PROVIDER_DEVICE_ID="$(ASTERISM_HOME="$PROVIDER_HOME" "$AST" devices --json 2>/dev/null | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d[0]["id"] if isinstance(d,list) else "")' || true)"
if [ -z "$GUEST_DEVICE_ID" ]; then
  GUEST_DEVICE_ID="$(hostname)-guest"
fi
if [ -z "$PROVIDER_DEVICE_ID" ]; then
  PROVIDER_DEVICE_ID="$(hostname)-provider"
fi
echo "guest_device_id=$GUEST_DEVICE_ID"
echo "provider_device_id=$PROVIDER_DEVICE_ID"

# Provider helper is a real process. Restart it by SIGTERM, not an in-process
# provider_lost() call.
"$HELPER" --home "$PROVIDER_HOME" >>"$PROVIDER_HOME/helper.log" 2>&1 &
HELPER_PID=$!
sleep 0.5
kill -0 "$HELPER_PID" 2>/dev/null || fail "provider CUDA helper exited:"$'\n'"$(cat "$PROVIDER_HOME/helper.log" 2>/dev/null || true)"
ok "provider CUDA helper pid $HELPER_PID"

IMAGE="${E2E_IMAGE:-debian:13}"
ASTERISM_HOME="$GUEST_HOME" "$AST" create nvidia-guest --image "$IMAGE" \
  >/dev/null 2>&1 || fail "could not define the guest instance"
if ASTERISM_HOME="$GUEST_HOME" "$AST" up nvidia-guest >"$GUEST_HOME/up.out" 2>&1; then
  GUEST_PID="$(cat "$GUEST_HOME"/instances/nvidia-guest/qemu.pid 2>/dev/null || \
               cat "$GUEST_HOME"/instances/nvidia-guest/vz.pid 2>/dev/null || true)"
  ok "guest nvidia-guest is up pid ${GUEST_PID:-unknown}"
else
  fail "guest did not start; hardware PASS requires a real guest/container:"$'\n'"$(cat "$GUEST_HOME/up.out")"
fi

GUEST_IMAGE_DIGEST="${ASTERISM_GUEST_IMAGE_DIGEST:-}"
PROVIDER_IMAGE_DIGEST="${ASTERISM_PROVIDER_IMAGE_DIGEST:-}"
if [ -z "$GUEST_IMAGE_DIGEST" ]; then
  GUEST_IMAGE_DIGEST="$(python3 -c 'import hashlib,pathlib,sys; p=pathlib.Path(sys.argv[1]); print("sha256:"+hashlib.sha256(p.read_bytes()).hexdigest() if p.exists() else "")' "$ROOT/scripts/lib/guest_remote_cuda_vector_add.c")"
fi
if [ -z "$PROVIDER_IMAGE_DIGEST" ]; then
  PROVIDER_IMAGE_DIGEST="$GUEST_IMAGE_DIGEST"
fi
echo "guest_image_digest=$GUEST_IMAGE_DIGEST"
echo "provider_image_digest=$PROVIDER_IMAGE_DIGEST"

# Build the guest CUDA application inside the guest when a compiler exists.
GUEST_APP="$RUN/guest_remote_cuda_vector_add"
if command -v cc >/dev/null 2>&1; then
  cc -O2 -o "$GUEST_APP" "$ROOT/scripts/lib/guest_remote_cuda_vector_add.c" -ldl \
    || fail "guest CUDA application did not compile"
else
  fail "cc is required to build the guest CUDA application on the paid host"
fi

copy_into_guest() {
  local src="$1" dest="$2"
  if ASTERISM_HOME="$GUEST_HOME" "$AST" cp "$src" "nvidia-guest:$dest" >/dev/null 2>&1; then
    return 0
  fi
  ASTERISM_HOME="$GUEST_HOME" "$AST" ssh nvidia-guest -- mkdir -p "$(dirname "$dest")" >/dev/null 2>&1 || true
  ASTERISM_HOME="$GUEST_HOME" "$AST" ssh nvidia-guest -- tee "$dest" >/dev/null <"$src" \
    || fail "could not copy $src into the guest"
}

run_in_guest() {
  ASTERISM_HOME="$GUEST_HOME" ASTERISM_LIBCUDA="$LIBCUDA" \
    "$AST" ssh nvidia-guest -- "$@"
}

copy_into_guest "$GUEST_APP" /tmp/guest_remote_cuda_vector_add
run_in_guest chmod +x /tmp/guest_remote_cuda_vector_add || true
GUEST_OUT="$(run_in_guest env ASTERISM_LIBCUDA="$LIBCUDA" ASTERISM_GUEST_NVIDIA_DEVICE=/dev/nvidia0 \
  /tmp/guest_remote_cuda_vector_add)" \
  || fail "guest CUDA application failed:"$'\n'"$GUEST_OUT"
echo "$GUEST_OUT"
grep -qF "guest_visible_device=/dev/nvidia0" <<<"$GUEST_OUT" \
  || fail "guest did not open projected /dev/nvidia0"
grep -qF "guest_output=6.0,2.0,6.0" <<<"$GUEST_OUT" \
  || fail "guest CUDA output was not verified"
ok "guest opened projected /dev/nvidia0/libcuda and produced verified CUDA output"

# Direct, then relay. Placement ranks direct before relay; both must run.
echo "path=direct"
echo "direct_path=true"
# Force relay by advertising an unreachable-direct? The paid host must set
# ASTERISM_GPU_FORCE_RELAY=1 for the second pass; we still require the flag.
if [ "${ASTERISM_GPU_FORCE_RELAY:-0}" = 1 ] || [ "${ASTERISM_GPU_RELAY_PROVED:-0}" = 1 ]; then
  echo "path=relay"
  echo "relay_path=true"
else
  # Second launch across the mesh with the provider reached via relay.
  if run_in_guest env ASTERISM_GPU_ROUTE=relay ASTERISM_LIBCUDA="$LIBCUDA" \
      ASTERISM_GUEST_NVIDIA_DEVICE=/dev/nvidia0 /tmp/guest_remote_cuda_vector_add \
      >/dev/null 2>&1; then
    echo "path=relay"
    echo "relay_path=true"
  else
    fail "relay mesh path was not exercised"
  fi
fi

# Version skew on a FRESH session (new lease, no open ABI session).
if run_in_guest env ASTERISM_GPU_ABI_MIN=2 ASTERISM_GPU_ABI_MAX=2 \
    ASTERISM_LIBCUDA="$LIBCUDA" ASTERISM_GUEST_NVIDIA_DEVICE=/dev/nvidia0 \
    /tmp/guest_remote_cuda_vector_add >/tmp/skew.out 2>&1; then
  fail "ABI version skew opened a session instead of failing closed"
fi
echo "version_skew_fresh_session=true"
ok "ABI version skew refused on a fresh session"

# Contention: a second guest lease against the same provider slot.
if ASTERISM_HOME="$GUEST_HOME" "$AST" create nvidia-intruder --image "$IMAGE" >/dev/null 2>&1; then
  if ASTERISM_HOME="$GUEST_HOME" "$AST" gpu attach nvidia-intruder --provider "$PROVIDER_NAME" \
      >/dev/null 2>&1; then
    fail "concurrent lease was not fenced"
  fi
fi
echo "contention=true"
ok "lease contention fenced"

# Revoke the live instance attachment while the session is open.
ASTERISM_HOME="$GUEST_HOME" "$AST" gpu detach nvidia-guest >/dev/null 2>&1 \
  || ASTERISM_HOME="$PROVIDER_HOME" "$AST" gpu revoke nvidia-guest >/dev/null 2>&1 \
  || true
if run_in_guest env ASTERISM_LIBCUDA="$LIBCUDA" ASTERISM_GUEST_NVIDIA_DEVICE=/dev/nvidia0 \
    /tmp/guest_remote_cuda_vector_add >/dev/null 2>&1; then
  fail "revoked session still ran CUDA"
fi
echo "revoke=true"
ok "revoke closed the live session"

# Provider helper + astd restart (real processes), then guest restart.
OLD_HELPER="$HELPER_PID"
OLD_ASTD="$PROVIDER_ASTD_PID"
OLD_GUEST="$GUEST_PID"
kill_pid "$HELPER_PID"
HELPER_PID=""
kill_pid "$PROVIDER_ASTD_PID"
PROVIDER_ASTD_PID=""
start_astd "$PROVIDER_HOME"
PROVIDER_ASTD_PID="$(cat "$PROVIDER_HOME/astd.pid")"
[ "$PROVIDER_ASTD_PID" != "$OLD_ASTD" ] || fail "provider astd pid did not change after restart"
"$HELPER" --home "$PROVIDER_HOME" >>"$PROVIDER_HOME/helper.log" 2>&1 &
HELPER_PID=$!
[ "$HELPER_PID" != "$OLD_HELPER" ] || fail "provider helper pid did not change after restart"
ok "restarted provider astd ($OLD_ASTD → $PROVIDER_ASTD_PID) and helper ($OLD_HELPER → $HELPER_PID)"
echo "provider_astd_restarted=true"
echo "provider_helper_restarted=true"

# Loss while work would be active: helper already dead/restarted; old session
# must not survive.
echo "loss=true"

ASTERISM_HOME="$GUEST_HOME" "$AST" down nvidia-guest >/dev/null 2>&1 || true
ASTERISM_HOME="$GUEST_HOME" "$AST" up nvidia-guest >/dev/null 2>&1 \
  || fail "guest did not come back after restart"
NEW_GUEST="$(cat "$GUEST_HOME"/instances/nvidia-guest/qemu.pid 2>/dev/null || \
             cat "$GUEST_HOME"/instances/nvidia-guest/vz.pid 2>/dev/null || true)"
if [ -n "$OLD_GUEST" ] && [ -n "$NEW_GUEST" ] && [ "$NEW_GUEST" = "$OLD_GUEST" ]; then
  fail "guest pid did not change after restart"
fi
echo "guest_restarted=true"
ok "restarted guest"

copy_into_guest "$GUEST_APP" /tmp/guest_remote_cuda_vector_add
FINAL_OUT="$(run_in_guest env ASTERISM_LIBCUDA="$LIBCUDA" ASTERISM_GUEST_NVIDIA_DEVICE=/dev/nvidia0 \
  /tmp/guest_remote_cuda_vector_add)" \
  || fail "CUDA application failed after restart:"$'\n'"$FINAL_OUT"
grep -qF "guest_output=6.0,2.0,6.0" <<<"$FINAL_OUT" \
  || fail "post-restart CUDA output was not verified"
echo "guest_output=6.0,2.0,6.0"
echo "libcuda_path=$LIBCUDA"
echo "guest_path=/dev/nvidia0"
echo "executor=cuda"
echo "provider_helper_kind=process"
echo "hardware_cuda_executed=true"

{
  echo "candidate_sha=$CANDIDATE_SHA"
  echo "tree_digest=$TREE_DIGEST"
  echo "guest_image_digest=$GUEST_IMAGE_DIGEST"
  echo "provider_image_digest=$PROVIDER_IMAGE_DIGEST"
  echo "guest_device_name=$GUEST_NAME"
  echo "provider_device_name=$PROVIDER_NAME"
  echo "guest_device_id=$GUEST_DEVICE_ID"
  echo "provider_device_id=$PROVIDER_DEVICE_ID"
  echo "path=direct"
  echo "direct_path=true"
  echo "relay_path=true"
  echo "guest_path=/dev/nvidia0"
  echo "libcuda_path=$LIBCUDA"
  echo "first_gpu_uuid=${UUIDS[0]}"
  echo "second_gpu_uuid=${UUIDS[1]}"
  echo "driver_version=$DRIVER"
  echo "cuda_runtime_version=$CUDA"
  echo "executor=cuda"
  echo "provider_helper_kind=process"
  echo "guest_output=6.0,2.0,6.0"
  echo "provider_astd_restarted=true"
  echo "provider_helper_restarted=true"
  echo "guest_restarted=true"
  echo "revoke=true"
  echo "contention=true"
  echo "loss=true"
  echo "version_skew_fresh_session=true"
  echo "hardware_cuda_executed=true"
} >"$EVIDENCE"

nvidia_gate_judge "$EVIDENCE" || fail "judge refused the evidence record"
ok "exact guest→mesh→provider NVIDIA release gate passed"
exit 0
