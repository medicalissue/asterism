# Candidate-side structural helpers for the NVIDIA observation task.
#
# Deliberately absent: evidence normalization, acceptance logic, and any PASS
# emitter. Only the digest-pinned, reviewer-owned offline verifier may decide
# whether a raw observation bundle satisfies the release policy.

nvidia_gate_is_oid() {
  local value="$1"
  [[ "$value" =~ ^[0-9a-f]{40}$ ]]
}

nvidia_gate_is_sha256() {
  local value="$1"
  [[ "$value" =~ ^sha256:[0-9a-f]{64}$ ]]
}

# Official dstack task schema (https://dstack.ai/docs/reference/dstack.yml/task.md).
# The provider and verifier images are immutable digest pins. This function
# validates checked-in structure only; it does not execute the task or judge
# evidence produced by it.
nvidia_gate_validate_dstack() {
  local yml="$1" image
  grep -q '^type: task$' "$yml" || { echo "dstack: type must be task" >&2; return 1; }
  grep -q '^name: asterism-remote-gpu-nvidia-gate$' "$yml" || {
    echo "dstack: name must be asterism-remote-gpu-nvidia-gate" >&2
    return 1
  }
  image="$(awk '/^image:/{print $2; exit}' "$yml")"
  [[ "$image" =~ @sha256:[0-9a-f]{64}$ ]] || { echo "dstack: provider image must be digest-pinned" >&2; return 1; }
  ! grep -q '^python:' "$yml" || { echo "dstack: python conflicts with pinned image" >&2; return 1; }
  grep -q '^docker: true$' "$yml" || { echo "dstack: nested offline verifier requires Docker" >&2; return 1; }
  grep -q '^spot_policy: on-demand$' "$yml" || { echo "dstack: spot_policy on-demand" >&2; return 1; }
  grep -q '^retry: false$' "$yml" || { echo "dstack: retry must be false" >&2; return 1; }
  grep -q 'vendor: nvidia' "$yml" || { echo "dstack: gpu vendor nvidia" >&2; return 1; }
  grep -q 'count: 2' "$yml" || { echo "dstack: gpu count 2" >&2; return 1; }
  grep -q 'compute_capability: 7.5' "$yml" || { echo "dstack: compute_capability 7.5" >&2; return 1; }
  grep -q 'local_path: ../..' "$yml" || { echo "dstack: exact candidate checkout must be uploaded" >&2; return 1; }
  grep -q 'test "$(git rev-parse HEAD)" = "$ASTERISM_PINNED_SHA"' "$yml" || {
    echo "dstack: runtime must reject a non-exact checkout" >&2; return 1
  }
  grep -q 'ASTERISM_NVIDIA_EVIDENCE_DIR=/dstack/evidence/raw' "$yml" || {
    echo "dstack: immutable raw evidence directory is required" >&2; return 1
  }
  grep -q -- '--network none' "$yml" || { echo "dstack: verifier must run offline" >&2; return 1; }
  grep -q 'dst=/evidence,readonly' "$yml" || { echo "dstack: verifier evidence mount must be read-only" >&2; return 1; }
  grep -q 'ASTERISM_NVIDIA_VERIFIER_IMAGE' "$yml" || { echo "dstack: independent verifier image is required" >&2; return 1; }
  grep -q '/verify --evidence /evidence' "$yml" || { echo "dstack: verifier must exclusively judge raw evidence" >&2; return 1; }
}
