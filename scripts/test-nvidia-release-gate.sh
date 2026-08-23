#!/usr/bin/env bash
# Source-only boundary fixtures. No Cargo, GPU, dstack, provisioning, or spend.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
HARNESS="$ROOT/scripts/harness-remote-gpu-nvidia.sh"
RUNNER="$ROOT/scripts/lib/nvidia-e2e-runner.sh"
HELPERS="$ROOT/scripts/lib/nvidia-release-gate.sh"
TASK="$ROOT/deploy/dstack/remote-gpu-nvidia.dstack.yml"
DRIVER="$ROOT/crates/asterism-nvidia-e2e-driver/src/main.rs"

bash -n "$HARNESS" "$RUNNER" "$HELPERS"

# Candidate code may observe, but it has no normalizer, judge, or acceptance
# emitter. The runner is invoked directly in the live provider environment.
! grep -R -q 'nvidia_gate_judge\|nvidia_gate=pass' \
  "$HARNESS" "$RUNNER" "$HELPERS" "$ROOT/crates/asterism-core/src"
grep -q '^"$RUNNER" --output-dir "$RAW"$' "$HARNESS"
! grep -q '/run-and-verify\|/verify' "$HARNESS"

# The reviewer-selected digest-pinned image is a separate offline phase. It
# can only read the completed raw directory and is the sole verdict writer.
grep -q -- '--network none' "$TASK"
grep -q 'src=/dstack/evidence/raw,dst=/evidence,readonly' "$TASK"
grep -q '"$ASTERISM_NVIDIA_VERIFIER_IMAGE" /verify' "$TASK"
grep -q 'src=/dstack/verdict,dst=/verdict' "$TASK"

# Every required lifecycle claim has a corresponding live runner action and
# an independently named raw record. Nothing is synthesized by a combiner.
for record in direct-success active-loss relay-success active-revoke contention version-skew-fresh-session; do
  grep -q "$record.json" "$RUNNER"
done
grep -q 'probe-contention' "$RUNNER"
grep -q 'probe-version-skew' "$RUNNER"
grep -q 'fault_while_active' "$DRIVER"
grep -q 'DeviceRemove' "$DRIVER"

# The real provider is the CUDA engine inside provider astd. Evidence binds
# that process and executable honestly; no fictitious helper PID is claimed.
grep -q 'in_process_astd_cuda_engine' "$DRIVER"
grep -q 'provider_runtime_executable_digest' "$DRIVER"
grep -q 'artifacts/provider-astd' "$RUNNER"
! grep -R -q 'provider_helper_pid\|provider_helper_kind=process' "$HARNESS" "$RUNNER" "$DRIVER"

# ABI ranges cross the local and mesh opening frames, so the skew probe is a
# genuinely fresh provider session that can return UnsupportedVersion.
grep -q 'versions: AbiRange' "$ROOT/crates/asterism-core/src/remote_gpu_path.rs"
grep -q 'versions: AbiRange' "$ROOT/crates/asterism-core/src/protocol/mod.rs"
grep -q 'open.versions' "$ROOT/crates/asterism-core/src/remote_gpu_path.rs"
grep -q 'UnsupportedVersion' "$DRIVER"

# Candidate finalizes a manifest before removing write bits. The verifier sees
# only that finalized tree through a read-only bind.
grep -q 'manifest.sha256' "$HARNESS"
grep -q 'chmod -R a-w "$RAW"' "$HARNESS"

echo "nvidia_release_gate_static_fixtures=ok"
