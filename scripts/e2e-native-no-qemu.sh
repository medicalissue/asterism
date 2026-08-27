#!/usr/bin/env bash
# Focused real-host proof for the native image path:
#
#   clean package inventory -> catalog pull leaves verified qcow2 -> first
#   native use materialises sparse raw in-process -> VZ/CHV boots it -> ssh
#   -> down -> rm
#
# No volume, snapshot, OCI-rootfs or QEMU compatibility assertions live here;
# those belong to their own suites. This lane answers one release question:
# can a user install Asterism without QEMU and boot a catalog cloud image on
# the host-native backend?
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export PATH="$HOME/.cargo/bin:$PATH"
cd "$ROOT"

# shellcheck source-path=SCRIPTDIR source=lib/harness.sh
. "$ROOT/scripts/lib/harness.sh"

fail() { echo "NATIVE-NO-QEMU FAIL: $*" >&2; exit 1; }

assert_no_qemu_install() {
  local tool packages
  for tool in qemu-img qemu-system-aarch64 qemu-system-x86_64; do
    if command -v "$tool" >/dev/null 2>&1; then
      fail "$tool is present on PATH; run this gate on a clean native lane"
    fi
    for prefix in /opt/homebrew/bin /usr/local/bin /usr/bin; do
      [ ! -e "$prefix/$tool" ] \
        || fail "$prefix/$tool is installed; package inventory is not clean"
    done
  done

  case "$(uname -s)" in
    Darwin)
      if command -v brew >/dev/null 2>&1; then
        packages="$(brew list --formula 2>/dev/null || true)"
        if printf '%s\n' "$packages" | grep -Eq '^qemu(@[^[:space:]]+)?$'; then
          fail "Homebrew still records a QEMU formula as installed"
        fi
      fi
      ;;
    Linux)
      if command -v dpkg-query >/dev/null 2>&1; then
        packages="$(dpkg-query -W -f='${binary:Package} ${db:Status-Abbrev}\n' \
          'qemu*' 2>/dev/null || true)"
        if printf '%s\n' "$packages" | grep -Eq '(^|:)qemu[^[:space:]]* ii '; then
          fail "dpkg still records a QEMU package as installed"
        fi
      elif command -v rpm >/dev/null 2>&1; then
        packages="$(rpm -qa 'qemu*' 2>/dev/null || true)"
        [ -z "$packages" ] || fail "rpm still records a QEMU package as installed"
      fi
      ;;
  esac
}

case "$(uname -s)" in
  Darwin)
    BACKEND=vz
    ;;
  Linux)
    BACKEND=chv
    if [ ! -r /dev/kvm ] || [ ! -w /dev/kvm ]; then
      fail "/dev/kvm is not readable and writable"
    fi
    ;;
  *)
    fail "only macOS VZ and Linux Cloud Hypervisor are native lanes"
    ;;
esac

assert_no_qemu_install
harness_begin native-no-qemu
harness_binaries "$ROOT"
[ "$BACKEND" != vz ] || [ -n "${AST_BIN:-}" ] || "$ROOT/scripts/sign-vz.sh"

SHORT_TMP=/tmp
[ -d /private/tmp ] && [ -w /private/tmp ] && SHORT_TMP=/private/tmp
export ASTERISM_HOME="${E2E_HOME:-$SHORT_TMP/ast-native-no-qemu-$$}"
export ASTERISM_MESH=local
harness_own_home "$ASTERISM_HOME"

IMAGE="${E2E_IMAGE:-debian:13}"
IMAGE_BASENAME="${E2E_BOOT_IMAGE_BASENAME:-debian-13}"
INST=native-no-qemu

case "$IMAGE_BASENAME" in
  '' | *[!A-Za-z0-9._-]* | *..*) fail "invalid boot image basename" ;;
esac

RAW="$ASTERISM_HOME/images/$IMAGE_BASENAME.raw"
QCOW2="$ASTERISM_HOME/images/$IMAGE_BASENAME.qcow2"

cleanup() {
  harness_keep_home "$ASTERISM_HOME" home
  "$AST" down "$INST" >/dev/null 2>&1 || true
  "$AST" rm "$INST" >/dev/null 2>&1 || true
  harness_reap
  rm -rf "$ASTERISM_HOME"
  harness_artifacts_note
}
trap cleanup EXIT

mkdir -p "$ASTERISM_HOME/images"

# CHV direct-boots the disk with Asterism's separately pinned kernel. Pulling
# the tiny OCI fixture primes only that payload; the cloud disk below is still
# fetched into this fresh store and remains qcow2 until the first native use.
if [ "$BACKEND" = chv ]; then
  "$AST" pull "${E2E_KERNEL_IMAGE:-busybox:musl}" >/dev/null \
    || fail "could not pull the pinned CHV guest kernel payload"
fi

pull_out="$("$AST" pull "$IMAGE" 2>&1)" \
  || fail "pull $IMAGE failed:${pull_out:+$'\n'$pull_out}"
[ -f "$QCOW2" ] || fail "pull did not retain $QCOW2 for lazy native use"
[ -f "$QCOW2.provenance" ] || fail "pull left no verified qcow2 provenance"
[ ! -e "$RAW" ] || fail "pull eagerly materialised raw before a backend needed it"
[ ! -e "$RAW.part" ] || fail "pull left a partial raw image"
echo "ok: pull verified qcow2 without QEMU and deferred raw materialisation"

create_out="$("$AST" create "$INST" --backend "$BACKEND" --image "$IMAGE" \
  --mem 2G --disk 10G 2>&1)" || fail "create failed:"$'\n'"$create_out"
printf '%s\n' "$create_out" | grep -qF "$INST  defined" \
  || fail "create did not define $INST:"$'\n'"$create_out"
status_out="$("$AST" status "$INST" 2>&1)" || fail "status after create failed"
printf '%s\n' "$status_out" | grep -qF "machine: $BACKEND" \
  || fail "instance was not defined for $BACKEND:"$'\n'"$status_out"
echo "ok: create records the explicit $BACKEND backend"

harness_run 240 "native boot and materialisation" "$AST" up "$INST" \
  || fail "up failed:${HARNESS_OUT:+$'\n'$HARNESS_OUT}"
printf '%s\n' "$HARNESS_OUT" | grep -qF "$INST  running" \
  || fail "up did not report a running instance:"$'\n'"$HARNESS_OUT"
harness_assert_backend "$AST" "$INST" "$BACKEND" \
  || fail "the guest is not running on $BACKEND"

[ -f "$RAW" ] || fail "first native use did not publish $RAW"
[ -f "$RAW.provenance" ] || fail "materialised raw has no provenance"
[ ! -e "$RAW.part" ] || fail "materialisation left a partial raw image"
[ ! -e "$QCOW2" ] || fail "verified qcow2 was not retired after raw publication"
[ ! -e "$QCOW2.provenance" ] || fail "retired qcow2 provenance was left behind"

case "$(uname -s)" in
  Darwin)
    LOGICAL="$(stat -f '%z' "$RAW")"
    ALLOCATED="$(( $(stat -f '%b' "$RAW") * 512 ))"
    ;;
  Linux)
    LOGICAL="$(stat -c '%s' "$RAW")"
    ALLOCATED="$(( $(stat -c '%b' "$RAW") * 512 ))"
    ;;
esac
[ "$ALLOCATED" -lt "$LOGICAL" ] \
  || fail "raw image is not sparse (allocated=$ALLOCATED logical=$LOGICAL)"
echo "ok: first $BACKEND use atomically published sparse raw with provenance"

guest_out="$("$AST" ssh "$INST" -- "uname -s; uname -m" 2>&1)" \
  || fail "ssh into the native guest failed:"$'\n'"$guest_out"
printf '%s\n' "$guest_out" | grep -qFx Linux \
  || fail "native guest did not identify as Linux:"$'\n'"$guest_out"
echo "ok: ssh reached the guest running on $BACKEND ($(printf '%s' "$guest_out" | tr '\n' ' '))"

down_out="$("$AST" down "$INST" 2>&1)" || fail "down failed:"$'\n'"$down_out"
printf '%s\n' "$down_out" | grep -qF "$INST  stopped" \
  || fail "down did not stop the instance:"$'\n'"$down_out"
rm_out="$("$AST" rm "$INST" 2>&1)" || fail "rm failed:"$'\n'"$rm_out"
printf '%s\n' "$rm_out" | grep -qF "$INST  removed" \
  || fail "rm did not remove the instance:"$'\n'"$rm_out"

assert_no_qemu_install
echo "NATIVE NO-QEMU GREEN ($BACKEND, $IMAGE; allocated $ALLOCATED of $LOGICAL bytes)"
