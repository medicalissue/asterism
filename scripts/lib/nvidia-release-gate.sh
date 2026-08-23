# NVIDIA release-gate helpers. Sourced by the hardware wrapper and its
# source-only fixture suite. A hardware PASS is decided here, never by the
# CPU reference harness or a host-direct nvcc kernel.

nvidia_gate_is_oid() {
  local value="$1"
  [[ "$value" =~ ^[0-9a-f]{40}$ ]]
}

nvidia_gate_is_sha256() {
  local value="$1"
  [[ "$value" =~ ^sha256:[0-9a-f]{64}$ ]]
}

nvidia_gate_is_blake3() {
  local value="$1"
  [[ "$value" =~ ^blake3:[0-9a-f]{64}$ ]]
}

nvidia_gate_require_kv() {
  local file="$1" key="$2"
  local value
  value="$(awk -F= -v k="$key" '$1==k {print substr($0, length(k)+2); found=1; exit} END{if(!found) exit 1}' "$file")" || {
    echo "NVIDIA GATE FAIL: missing $key" >&2
    return 1
  }
  printf '%s\n' "$value"
}

nvidia_gate_require_true() {
  local file="$1" key="$2"
  local value
  value="$(nvidia_gate_require_kv "$file" "$key")" || return 1
  if [ "$value" != "true" ]; then
    echo "NVIDIA GATE FAIL: $key=$value (require true)" >&2
    return 1
  fi
}

nvidia_gate_require_false() {
  local file="$1" key="$2" value
  value="$(nvidia_gate_require_kv "$file" "$key")" || return 1
  if [ "$value" != "false" ]; then
    echo "NVIDIA GATE FAIL: $key=$value (require false)" >&2
    return 1
  fi
}

nvidia_gate_require_pid_change() {
  local file="$1" label="$2" before after
  before="$(nvidia_gate_require_kv "$file" "${label}_pid_before")" || return 1
  after="$(nvidia_gate_require_kv "$file" "${label}_pid_after")" || return 1
  case "$before,$after" in
    *[!0-9,]*|0,*|*,0) echo "NVIDIA GATE FAIL: invalid $label pids" >&2; return 1 ;;
  esac
  if [ "$before" = "$after" ]; then
    echo "NVIDIA GATE FAIL: $label pid did not change ($before)" >&2
    return 1
  fi
}

# Runner output is a closed schema. It cannot shadow git, inventory, or runner
# digest fields observed by the wrapper.
nvidia_gate_validate_runner_evidence() {
  local file="$1" line key seen=" " required
  while IFS= read -r line || [ -n "$line" ]; do
    [ -z "$line" ] && continue
    case "$line" in \#*) continue ;; esac
    case "$line" in
      *=*) key="${line%%=*}" ;;
      *) echo "NVIDIA GATE FAIL: runner line is not key=value" >&2; return 1 ;;
    esac
    case "$key" in
      guest_image_digest|provider_image_digest|guest_container_id|guest_device_name|provider_device_name|guest_device_id|provider_device_id|path|direct_path|relay_path|guest_path|libcuda_path|executor|provider_helper_kind|guest_output|provider_astd_pid_before|provider_astd_pid_after|provider_helper_pid_before|provider_helper_pid_after|guest_pid_before|guest_pid_after|provider_astd_restarted|provider_helper_restarted|guest_restarted|revoke|contention|loss|version_skew_fresh_session|version_skew_error|mesh_open_bearer|hardware_cuda_executed|driver_digest|astd_digest|libcuda_digest|guest_binary_digest|guest_launcher_digest|transcript_root) ;;
      *) echo "NVIDIA GATE FAIL: forbidden runner evidence key $key" >&2; return 1 ;;
    esac
    case "$seen" in *" $key "*) echo "NVIDIA GATE FAIL: duplicate runner key $key" >&2; return 1 ;; esac
    seen="$seen$key "
  done <"$file"

  for required in guest_image_digest provider_image_digest guest_container_id guest_device_name provider_device_name guest_device_id provider_device_id path direct_path relay_path guest_path libcuda_path executor provider_helper_kind guest_output provider_astd_pid_before provider_astd_pid_after provider_helper_pid_before provider_helper_pid_after guest_pid_before guest_pid_after provider_astd_restarted provider_helper_restarted guest_restarted revoke contention loss version_skew_fresh_session version_skew_error mesh_open_bearer hardware_cuda_executed driver_digest astd_digest libcuda_digest guest_binary_digest guest_launcher_digest transcript_root; do
    nvidia_gate_require_kv "$file" "$required" >/dev/null || return 1
  done
}

# Judge a key=value evidence file. Exit 0 only for the exact guest →
# projected /dev/nvidia0/libcuda → two named mesh devices → real NVIDIA
# helper path. Reference, mock, and local-direct records fail closed.
nvidia_gate_judge() {
  local file="$1"
  local path executor helper guest_path libcuda guest_name provider_name
  local sha tree runner_digest guest_digest provider_digest first_uuid second_uuid

  path="$(nvidia_gate_require_kv "$file" path)" || return 1
  case "$path" in
    guest-mesh-provider) ;;
    local-direct|reference-loopback|mock)
      echo "NVIDIA GATE FAIL: path=$path cannot hardware-PASS" >&2
      return 1
      ;;
    *)
      echo "NVIDIA GATE FAIL: path=$path is not guest-mesh-provider" >&2
      return 1
      ;;
  esac

  executor="$(nvidia_gate_require_kv "$file" executor)" || return 1
  if [ "$executor" != "cuda" ]; then
    echo "NVIDIA GATE FAIL: executor=$executor cannot hardware-PASS" >&2
    return 1
  fi

  helper="$(nvidia_gate_require_kv "$file" provider_helper_kind)" || return 1
  if [ "$helper" != "process" ]; then
    echo "NVIDIA GATE FAIL: provider_helper_kind=$helper cannot hardware-PASS" >&2
    return 1
  fi

  guest_path="$(nvidia_gate_require_kv "$file" guest_path)" || return 1
  if [ "$guest_path" != "/dev/nvidia0" ]; then
    echo "NVIDIA GATE FAIL: guest_path=$guest_path; require /dev/nvidia0" >&2
    return 1
  fi

  libcuda="$(nvidia_gate_require_kv "$file" libcuda_path)" || return 1
  nvidia_gate_is_sha256 "$libcuda" \
    || { echo "NVIDIA GATE FAIL: libcuda_path is not an audited sha256" >&2; return 1; }

  guest_name="$(nvidia_gate_require_kv "$file" guest_device_name)" || return 1
  provider_name="$(nvidia_gate_require_kv "$file" provider_device_name)" || return 1
  if [ -z "$guest_name" ] || [ -z "$provider_name" ] || [ "$guest_name" = "$provider_name" ]; then
    echo "NVIDIA GATE FAIL: need two distinct named mesh devices" >&2
    return 1
  fi
  case "$guest_name,$provider_name" in
    local,*|*,local|loopback,*|*,loopback|mock,*|*,mock)
      echo "NVIDIA GATE FAIL: mesh device name is a stand-in" >&2
      return 1
      ;;
  esac

  sha="$(nvidia_gate_require_kv "$file" candidate_sha)" || return 1
  tree="$(nvidia_gate_require_kv "$file" tree_digest)" || return 1
  runner_digest="$(nvidia_gate_require_kv "$file" runner_digest)" || return 1
  nvidia_gate_is_oid "$sha" || { echo "NVIDIA GATE FAIL: candidate_sha is not a git oid" >&2; return 1; }
  nvidia_gate_is_oid "$tree" || { echo "NVIDIA GATE FAIL: tree_digest is not a git oid" >&2; return 1; }
  nvidia_gate_is_sha256 "$runner_digest" || { echo "NVIDIA GATE FAIL: runner_digest is not sha256" >&2; return 1; }

  guest_digest="$(nvidia_gate_require_kv "$file" guest_image_digest)" || return 1
  provider_digest="$(nvidia_gate_require_kv "$file" provider_image_digest)" || return 1
  nvidia_gate_is_sha256 "$guest_digest" || { echo "NVIDIA GATE FAIL: guest image digest" >&2; return 1; }
  nvidia_gate_is_sha256 "$provider_digest" || { echo "NVIDIA GATE FAIL: provider image digest" >&2; return 1; }

  local driver_artifact astd_artifact libcuda_artifact guest_artifact launcher_artifact transcript_root
  driver_artifact="$(nvidia_gate_require_kv "$file" driver_digest)" || return 1
  astd_artifact="$(nvidia_gate_require_kv "$file" astd_digest)" || return 1
  libcuda_artifact="$(nvidia_gate_require_kv "$file" libcuda_digest)" || return 1
  guest_artifact="$(nvidia_gate_require_kv "$file" guest_binary_digest)" || return 1
  launcher_artifact="$(nvidia_gate_require_kv "$file" guest_launcher_digest)" || return 1
  transcript_root="$(nvidia_gate_require_kv "$file" transcript_root)" || return 1
  nvidia_gate_is_sha256 "$driver_artifact" || { echo "NVIDIA GATE FAIL: driver artifact digest" >&2; return 1; }
  nvidia_gate_is_sha256 "$astd_artifact" || { echo "NVIDIA GATE FAIL: astd artifact digest" >&2; return 1; }
  nvidia_gate_is_sha256 "$libcuda_artifact" || { echo "NVIDIA GATE FAIL: libcuda artifact digest" >&2; return 1; }
  nvidia_gate_is_sha256 "$guest_artifact" || { echo "NVIDIA GATE FAIL: guest artifact digest" >&2; return 1; }
  nvidia_gate_is_sha256 "$launcher_artifact" || { echo "NVIDIA GATE FAIL: guest launcher digest" >&2; return 1; }
  nvidia_gate_is_blake3 "$transcript_root" || { echo "NVIDIA GATE FAIL: transcript root" >&2; return 1; }
  [ "$libcuda" = "$libcuda_artifact" ] || { echo "NVIDIA GATE FAIL: libcuda digest binding" >&2; return 1; }

  first_uuid="$(nvidia_gate_require_kv "$file" first_gpu_uuid)" || return 1
  second_uuid="$(nvidia_gate_require_kv "$file" second_gpu_uuid)" || return 1
  case "$first_uuid" in GPU-*) ;; *) echo "NVIDIA GATE FAIL: first_gpu_uuid" >&2; return 1 ;; esac
  case "$second_uuid" in GPU-*) ;; *) echo "NVIDIA GATE FAIL: second_gpu_uuid" >&2; return 1 ;; esac
  if [ "$first_uuid" = "$second_uuid" ]; then
    echo "NVIDIA GATE FAIL: GPU UUIDs must be distinct" >&2
    return 1
  fi

  local guest_id provider_id container skew_error guest_output
  guest_id="$(nvidia_gate_require_kv "$file" guest_device_id)" || return 1
  provider_id="$(nvidia_gate_require_kv "$file" provider_device_id)" || return 1
  [[ "$guest_id" =~ ^[0-9a-f]{16,}$ ]] || { echo "NVIDIA GATE FAIL: guest_device_id" >&2; return 1; }
  [[ "$provider_id" =~ ^[0-9a-f]{16,}$ ]] || { echo "NVIDIA GATE FAIL: provider_device_id" >&2; return 1; }
  [ "$guest_id" != "$provider_id" ] || { echo "NVIDIA GATE FAIL: mesh device IDs must differ" >&2; return 1; }
  container="$(nvidia_gate_require_kv "$file" guest_container_id)" || return 1
  case "$container" in ''|mock|local|host) echo "NVIDIA GATE FAIL: guest_container_id" >&2; return 1 ;; esac
  nvidia_gate_require_kv "$file" driver_version >/dev/null || return 1
  nvidia_gate_require_kv "$file" cuda_runtime_version >/dev/null || return 1
  guest_output="$(nvidia_gate_require_kv "$file" guest_output)" || return 1
  [ "$guest_output" = "6.0,2.0,6.0" ] || { echo "NVIDIA GATE FAIL: unexpected guest output" >&2; return 1; }
  skew_error="$(nvidia_gate_require_kv "$file" version_skew_error)" || return 1
  [ "$skew_error" = "unsupported_version" ] || { echo "NVIDIA GATE FAIL: skew was not UnsupportedVersion" >&2; return 1; }
  nvidia_gate_require_false "$file" mesh_open_bearer || return 1
  nvidia_gate_require_pid_change "$file" provider_astd || return 1
  nvidia_gate_require_pid_change "$file" provider_helper || return 1
  nvidia_gate_require_pid_change "$file" guest || return 1

  nvidia_gate_require_true "$file" direct_path || return 1
  nvidia_gate_require_true "$file" relay_path || return 1
  nvidia_gate_require_true "$file" provider_astd_restarted || return 1
  nvidia_gate_require_true "$file" provider_helper_restarted || return 1
  nvidia_gate_require_true "$file" guest_restarted || return 1
  nvidia_gate_require_true "$file" revoke || return 1
  nvidia_gate_require_true "$file" contention || return 1
  nvidia_gate_require_true "$file" loss || return 1
  nvidia_gate_require_true "$file" version_skew_fresh_session || return 1
  nvidia_gate_require_true "$file" hardware_cuda_executed || return 1
  nvidia_gate_require_true "$file" provenance_verified || return 1

  echo "nvidia_gate=pass"
  return 0
}

# Official dstack task schema (https://dstack.ai/docs/reference/dstack.yml/task.md).
# The provider image and repos.hash are immutable digest/OID pins.
nvidia_gate_validate_dstack() {
  local yml="$1"
  local hash image
  grep -q '^type: task$' "$yml" || { echo "dstack: type must be task" >&2; return 1; }
  grep -q '^name: asterism-remote-gpu-nvidia-gate$' "$yml" || {
    echo "dstack: name must be asterism-remote-gpu-nvidia-gate" >&2
    return 1
  }
  image="$(awk '/^image:/{gsub(/["'\'']/, "", $2); print $2; exit}' "$yml")"
  [[ "$image" =~ @sha256:[0-9a-f]{64}$ ]] || { echo "dstack: provider image must be digest-pinned" >&2; return 1; }
  ! grep -q '^python:' "$yml" || { echo "dstack: python conflicts with pinned image" >&2; return 1; }
  ! grep -q '^nvcc:' "$yml" || { echo "dstack: nvcc conflicts with pinned image" >&2; return 1; }
  grep -q '^docker: true$' "$yml" || { echo "dstack: nested guest container support is required" >&2; return 1; }
  grep -q '^spot_policy: on-demand$' "$yml" || { echo "dstack: spot_policy on-demand" >&2; return 1; }
  grep -q '^retry: false$' "$yml" || { echo "dstack: retry must be false" >&2; return 1; }
  grep -q 'vendor: nvidia' "$yml" || { echo "dstack: gpu vendor nvidia" >&2; return 1; }
  grep -q 'count: 2' "$yml" || { echo "dstack: gpu count 2" >&2; return 1; }
  grep -q 'compute_capability: 7.5' "$yml" || { echo "dstack: compute_capability 7.5" >&2; return 1; }
  grep -q 'scripts/harness-remote-gpu-nvidia.sh' "$yml" || {
    echo "dstack: commands must run the release gate" >&2
    return 1
  }
  grep -q 'url: https://github.com/medicalissue/asterism.git' "$yml" || {
    echo "dstack: repos.url must pin the asterism repo" >&2
    return 1
  }
  hash="$(awk '/^[[:space:]]*hash:/{gsub(/["'\'']/, "", $2); print $2; exit}' "$yml")"
  nvidia_gate_is_oid "$hash" || {
    echo "dstack: repos.hash must be a 40-character git oid (got ${hash:-empty})" >&2
    return 1
  }
  grep -q "ASTERISM_PINNED_SHA=$hash" "$yml" || {
    echo "dstack: ASTERISM_PINNED_SHA must equal repos.hash" >&2
    return 1
  }
  grep -q 'ASTERISM_NVIDIA_E2E_RUNNER=/dstack/run/scripts/lib/nvidia-e2e-runner.sh' "$yml" || {
    echo "dstack: exact pinned-tree E2E runner must be selected" >&2
    return 1
  }
  echo "dstack_schema=valid"
  echo "dstack_pinned_sha=$hash"
}
