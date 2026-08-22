#!/usr/bin/env bash
# Two-role proof of the remote GPU ABI and its fake-local-device seam.
#
# A provider process owns sessions, allocations and the pinned CUDA workload;
# a guest process opens <guest-root>/dev/nvidia0, uses the ABI over a
# loopback-only transport, and verifies returned memory. Loopback is deliberate:
# production messages ride the authenticated, encrypted orbit mesh, which is
# outside this ABI proof. Binding a proof bearer capability to a LAN address
# would be a security bug disguised as a demo.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

RUN="$(mktemp -d "${TMPDIR:-/tmp}/asterism-gpu-proof.XXXXXX")"
READY="$RUN/provider.addr"
PROVIDER_OUT="$RUN/provider.out"
GUEST_OUT="$RUN/guest.out"
GUEST_ROOT="$RUN/linux-guest"
PROVIDER_PID=""

fail() { echo "REMOTE GPU E2E FAIL: $*" >&2; exit 1; }
ok() { echo "ok: $*"; }

cleanup() {
  if [ -n "$PROVIDER_PID" ] && kill -0 "$PROVIDER_PID" 2>/dev/null; then
    kill -TERM "$PROVIDER_PID" 2>/dev/null || true
    wait "$PROVIDER_PID" 2>/dev/null || true
  fi
  if [ -n "${KEEP:-}" ]; then
    echo "kept $RUN for inspection"
  else
    rm -rf "$RUN"
  fi
}
trap cleanup EXIT

cargo build -q -p asterism-core --example remote_gpu_proof
PROOF="$ROOT/target/debug/examples/remote_gpu_proof"

if "$PROOF" provider --listen 0.0.0.0:0 --ready-file "$RUN/unsafe.addr" \
  >"$RUN/unsafe.out" 2>&1; then
  fail "provider accepted a non-loopback proof listener"
fi
grep -qF "must be loopback" "$RUN/unsafe.out" \
  || fail "non-loopback refusal did not explain the transport boundary"
ok "proof transport refuses a network-reachable listener"

"$PROOF" provider --listen 127.0.0.1:0 --ready-file "$READY" >"$PROVIDER_OUT" 2>&1 &
PROVIDER_PID=$!
for _ in $(seq 1 100); do
  [ -s "$READY" ] && break
  kill -0 "$PROVIDER_PID" 2>/dev/null \
    || fail "provider exited before becoming ready:"$'\n'"$(cat "$PROVIDER_OUT" 2>/dev/null || true)"
  sleep 0.05
done
[ -s "$READY" ] || fail "provider did not publish its address"
ADDRESS="$(tr -d '[:space:]' <"$READY")"
case "$ADDRESS" in
  127.0.0.1:*) ;;
  *) fail "provider escaped loopback: $ADDRESS" ;;
esac
ok "provider is a separate loopback-only device role at $ADDRESS"

"$PROOF" guest \
  --connect "$ADDRESS" \
  --guest-root "$GUEST_ROOT" \
  --elements "${GPU_PROOF_ELEMENTS:-65536}" \
  --iterations "${GPU_PROOF_ITERATIONS:-12}" \
  >"$GUEST_OUT" 2>&1 \
  || fail "guest proof failed:"$'\n'"$(cat "$GUEST_OUT")"$'\n'"provider:"$'\n'"$(cat "$PROVIDER_OUT")"

wait "$PROVIDER_PID" \
  || fail "provider failed:"$'\n'"$(cat "$PROVIDER_OUT")"
PROVIDER_PID=""

[ -f "$GUEST_ROOT/dev/nvidia0" ] || fail "guest never got a /dev/nvidia0 projection"
grep -qF "guest_visible_device=/dev/nvidia0" "$GUEST_OUT" \
  || fail "guest did not report opening /dev/nvidia0"
grep -qF "remote_gpu_abi=1" "$GUEST_OUT" || fail "ABI 1 was not negotiated"
grep -qE '^limit_max_provider_bytes=[0-9]+$' "$GUEST_OUT" \
  || fail "provider did not report its aggregate memory limit"
grep -qF "result=verified" "$GUEST_OUT" || fail "returned GPU memory was not verified"
grep -qF "security_replay=refused_invalid_sequence" "$GUEST_OUT" \
  || fail "replayed call was not refused"
grep -qF "security_out_of_bounds=refused_out_of_bounds" "$GUEST_OUT" \
  || fail "out-of-bounds call was not refused"
grep -qF "hardware_cuda_executed=false" "$GUEST_OUT" \
  || fail "portable proof did not disclose its reference executor"
grep -qF "transparent_raw_nvidia_ioctls=no" "$GUEST_OUT" \
  || fail "proof did not report the raw-ioctl compatibility limit"
grep -qE '^e2e_p50_us=[0-9]+$' "$GUEST_OUT" || fail "no measured median latency"
grep -qE '^measured_throughput_mib_s=[0-9]+\.[0-9]+$' "$GUEST_OUT" \
  || fail "no measured throughput"

ok "guest opened its fake /dev/nvidia0 and negotiated ABI 1"
ok "pinned CUDA PTX vector-add returned verified memory"
ok "replay and out-of-bounds calls were refused"
ok "compatibility and measured limits were reported"
echo
cat "$GUEST_OUT"
