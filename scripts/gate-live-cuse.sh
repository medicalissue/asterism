#!/usr/bin/env bash
# Fail-closed live CUSE gate. This script must run on a real Ubuntu host and
# never substitutes a socket fixture, VM guest, or TCP transport for /dev/cuse.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

TARGET_COMMIT="${ASTERISM_CUSE_TARGET_COMMIT:?ASTERISM_CUSE_TARGET_COMMIT is required}"
TARGET_TREE="${ASTERISM_CUSE_TARGET_TREE:?ASTERISM_CUSE_TARGET_TREE is required}"
EVIDENCE="${ASTERISM_CUSE_EVIDENCE_DIR:-$ROOT/cuse-live-evidence}"
INSTALL_REF="${ASTERISM_CUSE_INSTALL_REF:-${GITHUB_REF_NAME:-}}"
INSTALL_PREFIX="${ASTERISM_CUSE_INSTALL_PREFIX:-${RUNNER_TEMP:-/tmp}/asterism-cuse-install}"
mkdir -p "$EVIDENCE"
SUMMARY="$EVIDENCE/summary.txt"
: >"$SUMMARY"

record() { printf '%s\n' "$*" | tee -a "$SUMMARY"; }
block() { record "verdict=BLOCKED"; record "blocker=$*"; return 1; }

record "target_commit=$TARGET_COMMIT"
record "target_tree=$TARGET_TREE"
record "observer_commit=$(git rev-parse HEAD)"
record "install_ref=${INSTALL_REF:-missing}"
record "run_url=${GITHUB_SERVER_URL:-local}/${GITHUB_REPOSITORY:-local}/actions/runs/${GITHUB_RUN_ID:-local}"
date -u '+observed_at=%Y-%m-%dT%H:%M:%SZ' | tee -a "$SUMMARY"

gate_rc=0
actual_tree="$(git show -s --format=%T "$TARGET_COMMIT" 2>>"$EVIDENCE/preflight.log")" || gate_rc=1
if [ "$gate_rc" -eq 0 ] && [ "$actual_tree" != "$TARGET_TREE" ]; then
  block "target tree mismatch: expected $TARGET_TREE, got $actual_tree" || gate_rc=1
fi
if [ "$gate_rc" -eq 0 ] && ! git merge-base --is-ancestor "$TARGET_COMMIT" HEAD; then
  block "observer commit is not descended from exact target $TARGET_COMMIT" || gate_rc=1
fi
if [ "$gate_rc" -eq 0 ] && ! git diff --quiet "$TARGET_COMMIT" -- \
  Cargo.toml Cargo.lock crates/asterism-core/Cargo.toml \
  crates/asterism-core/src/remote_gpu_cuse.rs \
  crates/asterism-core/src/remote_gpu_guest.rs \
  crates/asterism-core/assets/70-asterism-cuse.rules; then
  git diff --name-only "$TARGET_COMMIT" -- \
    Cargo.toml Cargo.lock crates/asterism-core/Cargo.toml \
    crates/asterism-core/src/remote_gpu_cuse.rs \
    crates/asterism-core/src/remote_gpu_guest.rs \
    crates/asterism-core/assets/70-asterism-cuse.rules >>"$EVIDENCE/preflight.log"
  block "production CUSE inputs differ from immutable target" || gate_rc=1
fi

if [ "$gate_rc" -eq 0 ]; then
  kernel="$(uname -srm)"
  record "kernel=$kernel"
  if [ "$(uname -s)" != Linux ]; then
    block "host kernel is not Linux: $kernel" || gate_rc=1
  elif [ ! -r /etc/os-release ]; then
    block "Linux host has no readable /etc/os-release" || gate_rc=1
  else
    # shellcheck disable=SC1091
    . /etc/os-release
    record "os_id=${ID:-unknown}"
    record "os_version=${VERSION_ID:-unknown}"
    if [ "${ID:-}" != ubuntu ]; then
      block "host distribution is not Ubuntu: ${ID:-unknown}" || gate_rc=1
    fi
  fi
fi

service_user=asterism-gpu
service_group=asterism-gpu
run_as_service_user() {
  sudo -n -u "$service_user" env \
    HOME=/nonexistent PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    "$@"
}

if [ "$gate_rc" -eq 0 ]; then
  if [ -z "$INSTALL_REF" ]; then
    block "no immutable checkout branch was supplied to the product installer" || gate_rc=1
  else
    rm -rf "$INSTALL_PREFIX"
    set +e
    ASTERISM_METHOD=source \
      ASTERISM_REF="$INSTALL_REF" \
      ASTERISM_PREFIX="$INSTALL_PREFIX" \
      ASTERISM_YES=1 \
      sh packaging/install.sh 2>&1 | tee "$EVIDENCE/product-install.log"
    install_rc=${PIPESTATUS[0]}
    set -e
    record "product_install_exit=$install_rc"
    if [ "$install_rc" -ne 0 ]; then
      block "shipped source install path failed (see product-install.log)" || gate_rc=1
    fi
  fi
fi

# Compilation is not part of the device privilege boundary. Build the exact
# target's observer binaries as the ordinary runner before installing the
# guest policy, then execute only those binaries as the fresh service account.
# This avoids granting that account access to the runner's home/toolchain.
CUSE_OBSERVER_TARGET="${RUNNER_TEMP:-/tmp}/asterism-cuse-observer-target"
CUSE_OBSERVER_INSTALL="/var/tmp/asterism-cuse-observers-${GITHUB_RUN_ID:-$$}"
CUSE_TEST_BINARY=""
CUSE_LIVE_BINARY=""
if [ "$gate_rc" -eq 0 ]; then
  command -v jq >/dev/null 2>&1 \
    || { block "jq is required to resolve exact hosted observer binaries" || gate_rc=1; }
fi
if [ "$gate_rc" -eq 0 ]; then
  rm -rf "$CUSE_OBSERVER_TARGET"
  set +e
  CARGO_TARGET_DIR="$CUSE_OBSERVER_TARGET" ASTERISM_BUILD_ID="$TARGET_COMMIT" \
    cargo test -p asterism-core --lib --no-run --message-format=json \
      >"$EVIDENCE/observer-test-build.jsonl" \
      2>"$EVIDENCE/observer-test-build.log"
  observer_test_build_rc=$?
  set -e
  record "observer_test_build_exit=$observer_test_build_rc"
  if [ "$observer_test_build_rc" -ne 0 ]; then
    block "exact CUSE test observer did not build" || gate_rc=1
  else
    CUSE_TEST_BINARY="$(jq -r 'select(.reason == "compiler-artifact" and .target.name == "asterism_core" and .profile.test == true) | .executable // empty' "$EVIDENCE/observer-test-build.jsonl" | tail -n 1)"
    [ -n "$CUSE_TEST_BINARY" ] && [ -x "$CUSE_TEST_BINARY" ] \
      || { block "exact CUSE test observer binary was not resolved" || gate_rc=1; }
  fi
fi
if [ "$gate_rc" -eq 0 ]; then
  set +e
  CARGO_TARGET_DIR="$CUSE_OBSERVER_TARGET" ASTERISM_BUILD_ID="$TARGET_COMMIT" \
    cargo build -p asterism-core --example live_cuse_gate --message-format=json \
      >"$EVIDENCE/observer-live-build.jsonl" \
      2>"$EVIDENCE/observer-live-build.log"
  observer_live_build_rc=$?
  set -e
  record "observer_live_build_exit=$observer_live_build_rc"
  if [ "$observer_live_build_rc" -ne 0 ]; then
    block "exact live CUSE observer did not build" || gate_rc=1
  else
    CUSE_LIVE_BINARY="$(jq -r 'select(.reason == "compiler-artifact" and .target.name == "live_cuse_gate") | .executable // empty' "$EVIDENCE/observer-live-build.jsonl" | tail -n 1)"
    [ -n "$CUSE_LIVE_BINARY" ] && [ -x "$CUSE_LIVE_BINARY" ] \
      || { block "exact live CUSE observer binary was not resolved" || gate_rc=1; }
  fi
  if [ "$gate_rc" -eq 0 ]; then
    record "observer_compile_identity=ordinary_runner"
    record "observer_execute_identity=guest_service_asterism-gpu"
    record "observer_service_toolchain_access=false"
  fi
fi

# GitHub's tool target lives below /home/runner, which the fresh service
# identity must not be allowed to traverse. Install byte-identical observers
# into a root-owned executable location instead of weakening either account.
if [ "$gate_rc" -eq 0 ]; then
  source_test_sha="$(sha256sum "$CUSE_TEST_BINARY" | awk '{print $1}')"
  source_live_sha="$(sha256sum "$CUSE_LIVE_BINARY" | awk '{print $1}')"
  set +e
  {
    sudo -n install -d -o root -g root -m 0755 "$CUSE_OBSERVER_INSTALL"
    sudo -n install -o root -g root -m 0755 \
      "$CUSE_TEST_BINARY" "$CUSE_OBSERVER_INSTALL/asterism-core-tests"
    sudo -n install -o root -g root -m 0755 \
      "$CUSE_LIVE_BINARY" "$CUSE_OBSERVER_INSTALL/live-cuse-gate"
  } >"$EVIDENCE/observer-install.log" 2>&1
  observer_install_rc=$?
  set -e
  record "observer_install_exit=$observer_install_rc"
  if [ "$observer_install_rc" -ne 0 ]; then
    block "exact CUSE observers could not be staged for the service identity" || gate_rc=1
  else
    CUSE_TEST_BINARY="$CUSE_OBSERVER_INSTALL/asterism-core-tests"
    CUSE_LIVE_BINARY="$CUSE_OBSERVER_INSTALL/live-cuse-gate"
    installed_test_sha="$(sha256sum "$CUSE_TEST_BINARY" | awk '{print $1}')"
    installed_live_sha="$(sha256sum "$CUSE_LIVE_BINARY" | awk '{print $1}')"
    record "observer_test_sha256=$installed_test_sha"
    record "observer_live_sha256=$installed_live_sha"
    if [ "$source_test_sha" != "$installed_test_sha" ] ||
      [ "$source_live_sha" != "$installed_live_sha" ]; then
      block "staged CUSE observer digest differs from the ordinary-runner build" || gate_rc=1
    elif [ "$(stat -Lc '%U:%G:%a' "$CUSE_TEST_BINARY")" != root:root:755 ] ||
      [ "$(stat -Lc '%U:%G:%a' "$CUSE_LIVE_BINARY")" != root:root:755 ]; then
      block "staged CUSE observers are not root-owned mode 0755" || gate_rc=1
    else
      record "observer_staging=root_owned_0755_byte_identical"
    fi
  fi
fi

if [ "$gate_rc" -eq 0 ]; then
  [ -x "$INSTALL_PREFIX/bin/guest-gpu/bin/asterism-gpu-guest" ] \
    || { block "product install did not ship the guest CUSE opener beside astd" || gate_rc=1; }
  installed_libcuda="$INSTALL_PREFIX/bin/guest-gpu/lib/libcuda.so.1.0.0"
  [ -f "$installed_libcuda" ] \
    || { block "product install did not ship the matching guest libcuda" || gate_rc=1; }
  grep -q 'project_guest_device(Path::new("/"))' crates/asterism-gpu-guest/src/main.rs \
    || { block "shipped guest service is not the process that mounts guest /dev/cuse" || gate_rc=1; }
  grep -q 'User=asterism-gpu' crates/asterism-core/src/remote_gpu_guest.rs \
    || { block "guest service unit does not drop to the dedicated identity" || gate_rc=1; }
  record "cuse_opener=guest:asterism-gpu-guest"
  record "host_astd_opens_cuse=false"
  record "udev_placement=guest:/etc/udev/rules.d/70-asterism-cuse.rules"
  record "credential_refresh=system_service_start_no_relogin"
fi

if [ "$gate_rc" -eq 0 ]; then
  readelf -d "$installed_libcuda" >"$EVIDENCE/installed-libcuda.dynamic.log" 2>&1 \
    || { block "installed guest libcuda is not an inspectable ELF shared object" || gate_rc=1; }
fi
if [ "$gate_rc" -eq 0 ]; then
  grep -q 'SONAME.*libcuda.so.1' "$EVIDENCE/installed-libcuda.dynamic.log" \
    || { block "installed guest libcuda has the wrong SONAME" || gate_rc=1; }
  nm -D --defined-only "$installed_libcuda" >"$EVIDENCE/installed-libcuda.exports.log" 2>&1 \
    || { block "installed guest libcuda exports are not inspectable" || gate_rc=1; }
fi
if [ "$gate_rc" -eq 0 ]; then
  installed_cuda_exports="$(awk '{print $NF}' "$EVIDENCE/installed-libcuda.exports.log")"
  if printf '%s\n' "$installed_cuda_exports" | grep -q '@'; then
    block "installed guest libcuda invented an ELF symbol-version requirement" || gate_rc=1
  else
    expected_cuda_exports='cuInit cuDriverGetVersion cuDeviceGetCount cuDeviceGet cuDeviceGetName cuDeviceGetUuid cuDeviceGetAttribute cuCtxCreate cuCtxDestroy cuCtxGetCurrent cuCtxSetCurrent cuCtxSynchronize cuMemAlloc cuMemFree cuMemcpyHtoD cuMemcpyDtoH cuModuleLoadData cuModuleUnload cuModuleGetFunction cuLaunchKernel cuGetErrorString cuGetErrorName cuCtxCreate_v2 cuCtxDestroy_v2 cuMemAlloc_v2 cuMemFree_v2 cuMemcpyHtoD_v2 cuMemcpyDtoH_v2'
    for symbol in $expected_cuda_exports; do
      printf '%s\n' "$installed_cuda_exports" | grep -qx "$symbol" || {
        block "installed guest libcuda is missing exact Driver export $symbol" || gate_rc=1
        break
      }
    done
    for symbol in $installed_cuda_exports; do
      case "$symbol" in
      cu*)
        case " $expected_cuda_exports " in
        *" $symbol "*) ;;
        *) block "installed guest libcuda has unexpected Driver export $symbol" || gate_rc=1 ;;
        esac
        ;;
      esac
    done
  fi
  if [ "$gate_rc" -eq 0 ]; then
    record "libcuda_soname=libcuda.so.1"
    record "libcuda_elf_symbol_versions=none"
    record "libcuda_abi_generations=explicit_export_names"
  fi
fi

if [ "$gate_rc" -eq 0 ]; then
  rule=/etc/udev/rules.d/70-asterism-cuse.rules
  modules=/etc/modules-load.d/asterism-cuse.conf
  set +e
  {
    sudo -n groupadd --system "$service_group"
    sudo -n useradd --system --gid "$service_group" --no-create-home \
      --home-dir /nonexistent --shell /usr/sbin/nologin "$service_user"
    printf 'cuse\n' | sudo -n tee "$modules" >/dev/null
    sudo -n install -m 0644 crates/asterism-core/assets/70-asterism-cuse.rules "$rule"
    sudo -n modprobe cuse
    sudo -n udevadm control --reload-rules
    sudo -n udevadm trigger --action=add /sys/class/misc/cuse
    sudo -n udevadm settle
  } >"$EVIDENCE/guest-boundary-install.log" 2>&1
  reload_rc=$?
  set -e
  record "guest_boundary_install_exit=$reload_rc"
  if [ "$reload_rc" -ne 0 ]; then
    block "guest CUSE least-privilege boundary did not install" || gate_rc=1
  elif [ ! -d /sys/module/cuse ] || [ ! -c /dev/cuse ]; then
    block "real /dev/cuse did not appear for the guest service boundary" || gate_rc=1
  else
    stat -Lc 'cuse_mode=%A cuse_mode_octal=%a cuse_owner=%U cuse_group=%G cuse_major_minor=%t:%T' /dev/cuse \
      | tee -a "$SUMMARY"
    run_as_service_user id | tee "$EVIDENCE/guest-service-id.log"
    if ! run_as_service_user test -r /dev/cuse || ! run_as_service_user test -w /dev/cuse; then
      block "/dev/cuse is not read/write for the freshly started guest service identity" || gate_rc=1
    elif [ -r /dev/cuse ] || [ -w /dev/cuse ]; then
      block "ordinary host account can access guest-service-only /dev/cuse" || gate_rc=1
    elif ! run_as_service_user test -x "$CUSE_TEST_BINARY" ||
      ! run_as_service_user test -x "$CUSE_LIVE_BINARY"; then
      block "fresh guest service identity cannot execute the exact prebuilt observers" || gate_rc=1
    else
      record "least_privilege_preflight=pass"
    fi
  fi
fi

run_exact_test() {
  local test_name="$1"
  local log_name="$2"
  set +e
  run_as_service_user env ASTERISM_BUILD_ID="$TARGET_COMMIT" \
    "$CUSE_TEST_BINARY" "$test_name" --exact --nocapture \
      2>&1 | tee "$EVIDENCE/$log_name"
  local test_rc=${PIPESTATUS[0]}
  set -e
  return "$test_rc"
}

if [ "$gate_rc" -eq 0 ]; then
  run_exact_test \
    remote_gpu_cuse::tests::kernel_record_is_received_by_one_sufficient_read \
    one-read-framing.log \
    || { block "one-read framing test failed" || gate_rc=1; }
fi
if [ "$gate_rc" -eq 0 ]; then
  run_exact_test \
    remote_gpu_cuse::tests::record_parser_rejects_short_truncated_trailing_and_oversized_frames \
    malformed-oversized.log \
    || { block "malformed/oversized framing test failed" || gate_rc=1; }
fi
if [ "$gate_rc" -eq 0 ]; then
  run_exact_test \
    remote_gpu_cuse::tests::known_request_bodies_are_bounded_before_field_parsing \
    bounded-bodies.log \
    || { block "bounded request-body test failed" || gate_rc=1; }
fi
if [ "$gate_rc" -eq 0 ]; then
  set +e
  run_as_service_user env ASTERISM_BUILD_ID="$TARGET_COMMIT" \
    ASTERISM_CUSE_TARGET_COMMIT="$TARGET_COMMIT" \
    "$CUSE_LIVE_BINARY" 2>&1 \
    | tee "$EVIDENCE/live-lifecycle.log"
  lifecycle_rc=${PIPESTATUS[0]}
  set -e
  if [ "$lifecycle_rc" -ne 0 ]; then
    block "live mount/open/read/write/poll/cancel/interrupt/teardown failed" || gate_rc=1
  fi
fi

if [ -f "$INSTALL_PREFIX/share/asterism/install-receipt.env" ]; then
  set +e
  ASTERISM_PREFIX="$INSTALL_PREFIX" ASTERISM_YES=1 \
    sh packaging/install.sh --uninstall 2>&1 | tee "$EVIDENCE/product-uninstall.log"
  uninstall_rc=${PIPESTATUS[0]}
  set -e
  record "product_uninstall_exit=$uninstall_rc"
  if [ "$uninstall_rc" -ne 0 ]; then
    block "product uninstall did not remove the packaged guest GPU unit" || gate_rc=1
  fi
  if [ -e "$INSTALL_PREFIX/bin/guest-gpu" ]; then
    block "product uninstall left packaged guest GPU artifacts behind" || gate_rc=1
  fi
fi

if [ -e /etc/udev/rules.d/70-asterism-cuse.rules ] ||
  id "$service_user" >/dev/null 2>&1 || getent group "$service_group" >/dev/null 2>&1; then
  set +e
  {
    sudo -n rm -f /etc/udev/rules.d/70-asterism-cuse.rules \
      /etc/modules-load.d/asterism-cuse.conf
    id "$service_user" >/dev/null 2>&1 && sudo -n userdel "$service_user"
    getent group "$service_group" >/dev/null 2>&1 && sudo -n groupdel "$service_group"
    sudo -n modprobe -r cuse
    sudo -n modprobe cuse
    sudo -n udevadm control --reload-rules
    sudo -n udevadm trigger --action=add /sys/class/misc/cuse
    sudo -n udevadm settle
  } >"$EVIDENCE/post-uninstall-reload.log" 2>&1
  post_reload_rc=$?
  set -e
  if [ "$post_reload_rc" -ne 0 ]; then
    block "could not verify guest-boundary teardown" || gate_rc=1
  elif [ -e /etc/udev/rules.d/70-asterism-cuse.rules ] ||
    [ -e /etc/modules-load.d/asterism-cuse.conf ]; then
    block "uninstall left persistent CUSE policy behind" || gate_rc=1
  elif [ -r /dev/cuse ] || [ -w /dev/cuse ]; then
    stat -Lc 'post_uninstall_mode=%A post_uninstall_owner=%U post_uninstall_group=%G' /dev/cuse \
      | tee -a "$SUMMARY" || true
    block "guest-boundary teardown left the ordinary host account able to access /dev/cuse" || gate_rc=1
  else
    stat -Lc 'post_uninstall_mode=%A post_uninstall_owner=%U post_uninstall_group=%G' /dev/cuse \
      | tee -a "$SUMMARY"
    record "guest_boundary_teardown=pass"
  fi
fi

if [ -d "$CUSE_OBSERVER_INSTALL" ]; then
  sudo -n rm -rf "$CUSE_OBSERVER_INSTALL"
fi

if [ "$gate_rc" -eq 0 ]; then
  record "verdict=PASS"
  record "scope=CUSE_only"
  record "nvidia_hardware_claim=false"
fi

checksums="$(mktemp "${TMPDIR:-/tmp}/asterism-cuse-sums.XXXXXX")"
(
  cd "$EVIDENCE"
  find . -type f ! -name SHA256SUMS -print0 \
    | sort -z \
    | xargs -0 sha256sum >"$checksums"
)
mv "$checksums" "$EVIDENCE/SHA256SUMS"
exit "$gate_rc"
