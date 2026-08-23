#!/usr/bin/env bash
# Source-only fail-closed fixtures. No Cargo, GPU, dstack apply, or spend.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=lib/nvidia-release-gate.sh
. "$ROOT/scripts/lib/nvidia-release-gate.sh"

TMP="$(mktemp -d "${TMPDIR:-/tmp}/asterism-nvidia-gate-test.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT
VALID="$TMP/valid"

cat >"$VALID" <<'EOF'
candidate_sha=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
tree_digest=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
runner_digest=sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
first_gpu_uuid=GPU-aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
second_gpu_uuid=GPU-bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb
driver_version=550.54.15
cuda_runtime_version=12.4
provenance_verified=true
guest_image_digest=sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd
provider_image_digest=sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee
guest_container_id=aaaaaaaaaaaa,bbbbbbbbbbbb
guest_device_name=guest-gpu
provider_device_name=provider-gpu
guest_device_id=11111111111111111111111111111111
provider_device_id=22222222222222222222222222222222
path=guest-mesh-provider
direct_path=true
relay_path=true
guest_path=/dev/nvidia0
libcuda_path=sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
executor=cuda
provider_helper_kind=process
guest_output=6.0,2.0,6.0
provider_astd_pid_before=101
provider_astd_pid_after=102
provider_helper_pid_before=201
provider_helper_pid_after=202
guest_pid_before=301
guest_pid_after=302
provider_astd_restarted=true
provider_helper_restarted=true
guest_restarted=true
revoke=true
contention=true
loss=true
version_skew_fresh_session=true
version_skew_error=unsupported_version
mesh_open_bearer=false
hardware_cuda_executed=true
driver_digest=sha256:abababababababababababababababababababababababababababababababab
astd_digest=sha256:3434343434343434343434343434343434343434343434343434343434343434
libcuda_digest=sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
guest_binary_digest=sha256:cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd
guest_launcher_digest=sha256:5656565656565656565656565656565656565656565656565656565656565656
transcript_root=blake3:1212121212121212121212121212121212121212121212121212121212121212
verifier_image_digest=sha256:7878787878787878787878787878787878787878787878787878787878787878
EOF

nvidia_gate_judge "$VALID" >/dev/null

must_refuse() {
  local key="$1" value="$2" fixture
  fixture="$TMP/${key}-${value}"
  sed "s/^${key}=.*/${key}=${value}/" "$VALID" >"$fixture"
  if nvidia_gate_judge "$fixture" >/dev/null 2>&1; then
    echo "fixture unexpectedly passed: $key=$value" >&2
    exit 1
  fi
}

must_refuse path local-direct
must_refuse executor reference
must_refuse hardware_cuda_executed false
must_refuse version_skew_error conflict
must_refuse provider_helper_pid_after 201
must_refuse guest_container_id aaaaaaaaaaaa,aaaaaaaaaaaa
must_refuse mesh_open_bearer true
must_refuse provenance_verified false
must_refuse transcript_root caller-authored
must_refuse verifier_image_digest candidate-authored

RAW="$TMP/raw.json"
printf '%s\n' '{"schema":"asterism.nvidia.raw-observation/2","hardware_cuda_executed":true}' >"$RAW"
if nvidia_gate_judge "$RAW" >/dev/null 2>&1; then
  echo "candidate raw observation was allowed to accept itself" >&2
  exit 1
fi

RUNNER="$TMP/runner"
sed -n '/^guest_image_digest=/,$p' "$VALID" \
  | sed '/^candidate_sha=/d;/^tree_digest=/d;/^runner_digest=/d;/^first_gpu_uuid=/d;/^second_gpu_uuid=/d;/^driver_version=/d;/^cuda_runtime_version=/d;/^provenance_verified=/d;/^verifier_image_digest=/d' \
  >"$RUNNER"
nvidia_gate_validate_runner_evidence "$RUNNER"
printf 'candidate_sha=%040d\n' 0 >>"$RUNNER"
if nvidia_gate_validate_runner_evidence "$RUNNER" >/dev/null 2>&1; then
  echo "runner was allowed to shadow candidate_sha" >&2
  exit 1
fi

nvidia_gate_validate_dstack "$ROOT/deploy/dstack/remote-gpu-nvidia.dstack.yml" >/dev/null

# The candidate must not regain observation/acceptance authority through a
# direct runner invocation or an unshared nested-Docker artifact path.
grep -q '"$VERIFIER_IMAGE" /run-and-verify' "$ROOT/scripts/harness-remote-gpu-nvidia.sh"
! grep -q '^"$RUNNER"' "$ROOT/scripts/harness-remote-gpu-nvidia.sh"
grep -q 'ASTERISM_NVIDIA_DOCKER_HOST_RESULT=' "$ROOT/scripts/harness-remote-gpu-nvidia.sh"
grep -q 'path is outside verifier result mount' "$ROOT/scripts/lib/nvidia-guest-container.sh"
grep -q 'pair_devices direct-refresh' "$ROOT/scripts/lib/nvidia-e2e-runner.sh"
grep -q 'pair_devices relay-refresh' "$ROOT/scripts/lib/nvidia-e2e-runner.sh"

set +e
ASTERISM_SOURCE_ONLY=1 "$ROOT/scripts/harness-remote-gpu-nvidia.sh" >"$TMP/source.out" 2>&1
status=$?
set -e
[ "$status" -eq 2 ] || { cat "$TMP/source.out" >&2; exit 1; }
grep -q '^hardware_cuda_executed=false$' "$TMP/source.out"
grep -q '^nvidia_gate=unavailable$' "$TMP/source.out"

echo "nvidia_release_gate_source_fixtures=pass"
