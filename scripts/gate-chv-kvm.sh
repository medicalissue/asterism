#!/usr/bin/env bash
# Observer-side Stage 1 gate for an exact Asterism source revision. The script
# may live in a later observer commit, but every executable it operates must
# come from the exact source tree and release archive named below.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SOURCE="${ASTERISM_GATE_SOURCE_DIR:?set ASTERISM_GATE_SOURCE_DIR}"
EXPECTED_SHA="${ASTERISM_GATE_EXPECTED_SHA:?set ASTERISM_GATE_EXPECTED_SHA}"
EXPECTED_TREE="${ASTERISM_GATE_EXPECTED_TREE:?set ASTERISM_GATE_EXPECTED_TREE}"
PARENT_SHA="${ASTERISM_GATE_PARENT_SHA:?set ASTERISM_GATE_PARENT_SHA}"
PARENT_TREE="${ASTERISM_GATE_PARENT_TREE:?set ASTERISM_GATE_PARENT_TREE}"
OBSERVER_SHA="${ASTERISM_GATE_OBSERVER_SHA:-$(git -C "$ROOT" rev-parse HEAD)}"
AST="${AST_BIN:?set AST_BIN to the installed exact-release ast}"
ASTD="${ASTD_BIN:?set ASTD_BIN to the installed exact-release astd}"
ARTIFACTS="${ASTERISM_TEST_ARTIFACTS:-${RUNNER_TEMP:-/tmp}/chv-kvm-evidence}"
mkdir -p "$ARTIFACTS"

# shellcheck source-path=SCRIPTDIR source=lib/harness.sh
. "$ROOT/scripts/lib/harness.sh"
harness_begin chv-kvm-gate

fail() { echo "CHV KVM GATE FAIL: $*" >&2; exit 1; }
for command in git sha256sum pgrep readlink; do
  command -v "$command" >/dev/null || fail "missing prerequisite: $command"
done

actual_sha="$(git -C "$SOURCE" rev-parse HEAD)"
actual_tree="$(git -C "$SOURCE" rev-parse 'HEAD^{tree}')"
actual_parent="$(git -C "$SOURCE" rev-parse 'HEAD^')"
actual_parent_tree="$(git -C "$SOURCE" rev-parse 'HEAD^^{tree}')"
[ "$actual_sha" = "$EXPECTED_SHA" ] \
  || fail "source HEAD is $actual_sha, expected $EXPECTED_SHA"
[ "$actual_tree" = "$EXPECTED_TREE" ] \
  || fail "source tree is $actual_tree, expected $EXPECTED_TREE"
[ "$actual_parent" = "$PARENT_SHA" ] \
  || fail "source parent is $actual_parent, expected immutable $PARENT_SHA"
[ "$actual_parent_tree" = "$PARENT_TREE" ] \
  || fail "source parent tree is $actual_parent_tree, expected immutable $PARENT_TREE"
[ -c /dev/kvm ] || fail "/dev/kvm is absent or is not a character device"
[ -r /dev/kvm ] && [ -w /dev/kvm ] || fail "/dev/kvm is not open read-write"

# shellcheck disable=SC1091
. "$SOURCE/packaging/linux-components.env"
CHV="$(dirname "$ASTD")/cloud-hypervisor"
VIRTIOFSD="$(dirname "$ASTD")/virtiofsd"
[ -x "$CHV" ] || fail "release archive did not install cloud-hypervisor"
[ -x "$VIRTIOFSD" ] || fail "release archive did not install virtiofsd"
case "$(uname -m)" in
  x86_64) expected_chv_digest="$CLOUD_HYPERVISOR_X86_64_SHA256" ;;
  aarch64|arm64) expected_chv_digest="$CLOUD_HYPERVISOR_AARCH64_SHA256" ;;
  *) fail "unsupported KVM gate architecture: $(uname -m)" ;;
esac
actual_chv_digest="$(sha256sum "$CHV" | awk '{print $1}')"
[ "$actual_chv_digest" = "$expected_chv_digest" ] \
  || fail "shipped Cloud Hypervisor digest is $actual_chv_digest, expected $expected_chv_digest"
"$CHV" --version | grep -qF "$CLOUD_HYPERVISOR_VERSION" \
  || fail "shipped Cloud Hypervisor is not $CLOUD_HYPERVISOR_VERSION"
"$VIRTIOFSD" --version | grep -qF "${VIRTIOFSD_VERSION#v}" \
  || fail "shipped virtiofsd is not $VIRTIOFSD_VERSION"

if pgrep -f '(^|/)qemu-system-[^ ]*' >/dev/null 2>&1; then
  fail "a qemu-system process exists before the Cloud Hypervisor gate"
fi

{
  printf 'result=pending\n'
  printf 'source_sha=%s\nsource_tree=%s\nobserver_sha=%s\n' \
    "$actual_sha" "$actual_tree" "$OBSERVER_SHA"
  printf 'immutable_parent_sha=%s\nimmutable_parent_tree=%s\n' \
    "$actual_parent" "$actual_parent_tree"
  printf 'host=%s %s\n' "$(uname -srmo)" "$(stat -c '%A %U:%G %t:%T' /dev/kvm)"
  printf 'cloud_hypervisor_version=%s\ncloud_hypervisor_sha256=%s\n' \
    "$CLOUD_HYPERVISOR_VERSION" "$actual_chv_digest"
  printf 'virtiofsd_version=%s\n' "$VIRTIOFSD_VERSION"
} >"$ARTIFACTS/summary.txt"

export AST_BIN="$AST" ASTD_BIN="$ASTD"
export ASTERISM_CLOUD_HYPERVISOR="$CHV" ASTERISM_VIRTIOFSD="$VIRTIOFSD"
export ASTERISM_TEST_ARTIFACTS="$ARTIFACTS"

# This gate must not inherit or seed from a login home. Bind both the reusable
# pull cache and the lifecycle home to the exact product revision, then let
# e2e.sh perform the visible `ast pull debian:13` in that same owned home
# before create/up. Product verification gates every copied cache artifact at
# pull and again at boot; e2e.sh records the active image provenance and the
# direct-boot payload digests in the exact-run summary.
GATE_RUN_ROOT="${RUNNER_TEMP:-/tmp}/chv-${EXPECTED_SHA:0:12}"
export ASTERISM_TEST_CACHE="$GATE_RUN_ROOT/cache"
export E2E_HOME="$GATE_RUN_ROOT/home"
mkdir -p "$ASTERISM_TEST_CACHE" "$E2E_HOME"
{
  printf 'gate_run_root=%s\n' "$GATE_RUN_ROOT"
  printf 'gate_cache=%s\n' "$ASTERISM_TEST_CACHE"
  printf 'gate_home=%s\n' "$E2E_HOME"
} >>"$ARTIFACTS/summary.txt"

# create/up/vsock-ready/SSH, installed-helper identity, virtiofs, disk
# snapshot/restore, down/rm. E2E_BACKEND is explicit: fallback cannot pass.
E2E_BACKEND=chv E2E_IMAGE=debian:13 E2E_BOOT_IMAGE_BASENAME=debian-13 \
E2E_DISK_GIB=3 \
  bash "$ROOT/scripts/e2e.sh" 2>&1 | tee "$ARTIFACTS/lifecycle.log"

# The same exact binaries now operate a local directory and a remote block
# part across two daemons, including consumer-daemon restart. Keep the hosted
# transfer bounded; identity, byte count, digest and provider allocation are
# still asserted by the lane.
E2E_VOLUME_BACKEND=chv \
E2E_DISK_GIB=3 \
E2E_VOLUME_GIB="${E2E_VOLUME_GIB:-1}" \
E2E_VOLUME_TRANSFER_BYTES="${E2E_VOLUME_TRANSFER_BYTES:-134217728}" \
  bash "$ROOT/scripts/e2e-volume.sh" 2>&1 | tee "$ARTIFACTS/remote-volume.log"

# Force a post-virtiofs/pre-ready failure. The fake helper passes the pinned
# version probe and then exits, so Asterism must retire the already-started
# virtiofsd, sockets, VMM authority and intent without relabelling the guest
# as QEMU or leaving an unowned process behind.
FAIL_RUN="$(mktemp -d "${RUNNER_TEMP:-/tmp}/ast-chv-fail.XXXXXX")"
FAIL_HOME="$FAIL_RUN/home"
BAD_CHV="$FAIL_RUN/cloud-hypervisor"
mkdir -p "$FAIL_HOME" "$FAIL_RUN/share"
chmod 0777 "$FAIL_RUN/share"
# shellcheck disable=SC2016 # ${1-} belongs to the generated helper.
printf '#!/bin/sh\nif [ "${1-}" = --version ]; then echo "cloud-hypervisor v53.0"; exit 0; fi\nexit 86\n' >"$BAD_CHV"
chmod 0755 "$BAD_CHV"
harness_own_home "$FAIL_HOME"
harness_seed_images "$FAIL_HOME"

ASTERISM_HOME="$FAIL_HOME" ASTERISM_MESH=local \
ASTERISM_CLOUD_HYPERVISOR="$BAD_CHV" ASTERISM_VIRTIOFSD="$VIRTIOFSD" \
  "$AST" pull debian:13 >/dev/null
ASTERISM_HOME="$FAIL_HOME" ASTERISM_MESH=local "$AST" create cleanup \
  --backend chv --image debian:13 --mem 1G --disk 3G >/dev/null
ASTERISM_HOME="$FAIL_HOME" ASTERISM_MESH=local "$AST" attach cleanup \
  --volume "$FAIL_RUN/share" >/dev/null
if failure_out="$(ASTERISM_HOME="$FAIL_HOME" ASTERISM_MESH=local \
  "$AST" up cleanup 2>&1)"; then
  fail "the deliberately failing Cloud Hypervisor unexpectedly booted"
fi
printf '%s\n' "$failure_out" >"$ARTIFACTS/failure-cleanup.log"
status="$(ASTERISM_HOME="$FAIL_HOME" ASTERISM_MESH=local "$AST" status cleanup 2>&1)"
grep -q '^status:  stopped' <<<"$status" \
  || fail "failed CHV boot did not remain stopped: $status"
grep -q '^machine: chv' <<<"$status" \
  || fail "failed CHV boot changed backend identity: $status"
inst_dir="$FAIL_HOME/instances/cleanup"
for leftover in "$inst_dir"/chv.pid "$inst_dir"/chv-vmm.proc.json \
  "$inst_dir"/chv-start.json "$inst_dir"/chv-api.sock \
  "$inst_dir"/chv-vsock.sock "$inst_dir"/virtiofs-*.resource.json \
  "$inst_dir"/virtiofs-*.sock; do
  [ ! -e "$leftover" ] || fail "failed CHV boot left $leftover"
done
ASTERISM_HOME="$FAIL_HOME" ASTERISM_MESH=local "$AST" rm cleanup >/dev/null
harness_reap
rm -rf "$FAIL_RUN"

if pgrep -f '(^|/)qemu-system-[^ ]*' >/dev/null 2>&1; then
  fail "a qemu-system process exists after the Cloud Hypervisor gate"
fi
sed -i 's/^result=pending$/result=pass/' "$ARTIFACTS/summary.txt"
printf 'qemu_system_processes=0\nfailure_cleanup=pass\n' >>"$ARTIFACTS/summary.txt"
echo "CHV KVM GATE PASS: exact $actual_sha tree $actual_tree"
