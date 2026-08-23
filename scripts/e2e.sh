#!/usr/bin/env bash
# End-to-end: create -> attach -> up -> marker -> down -> snapshot ->
# restore -> snapshot rm -> up -> marker -> rm, asserting on output CONTENT.
#
# Why this exists as a bash script: the previous e2e ran as loose lines in
# the interactive session shell (zsh under the tool harness), where a
# mid-script `set -e` demonstrably did not abort when `ast ssh` exited 1 —
# and compound remote commands (`cat x; hostname`) masked failures with the
# last command's exit code anyway. `ast ssh` itself propagates the remote
# exit status correctly (verified). Running under bash with -euo pipefail
# and grepping for expected strings removes both failure modes.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export PATH="$HOME/.cargo/bin:$PATH"
cd "$ROOT"
# shellcheck source-path=SCRIPTDIR source=lib/harness.sh
. "$ROOT/scripts/lib/harness.sh"
harness_begin lifecycle
harness_binaries "$ROOT"

# Fresh, SHORT home: unix socket paths are capped near 104 bytes. macOS has
# /private/tmp; Linux's equivalent is /tmp.
if [ -d /private/tmp ] && [ -w /private/tmp ]; then
  SHORT_TMP=/private/tmp
else
  SHORT_TMP=/tmp
fi
export ASTERISM_HOME="$SHORT_TMP/ast-e2e-$$"
harness_own_home "$ASTERISM_HOME"

# A single-device test has no orbit, so it has no business publishing a
# throwaway key and this machine's addresses to a public discovery service.
export ASTERISM_MESH=local
IMAGE="${E2E_IMAGE:-debian:13}"
BACKEND="${E2E_BACKEND:-qemu}"
DISK_GIB="${E2E_DISK_GIB:-10}"
INST=e2e
VOL="$ASTERISM_HOME/e2e-vol"   # dash on purpose: covers systemd \x2d escaping
MARKER="marker-$$"

cleanup() {
  # Evidence first: the console log and the daemon log live under the home
  # this trap is about to delete, and they are the only account of why a
  # boot did not happen.
  harness_keep_home "$ASTERISM_HOME" home
  "$AST" down "$INST" >/dev/null 2>&1 || true
  "$AST" rm "$INST" >/dev/null 2>&1 || true
  # Only what this run started. The `pkill -f` that used to be here matched
  # every astd built at this path, which on a machine with a second checkout
  # of this repository is somebody else's daemon and somebody else's guests.
  harness_reap
  rm -rf "$ASTERISM_HOME"
  harness_artifacts_note
}
trap cleanup EXIT

mkdir -p "$ASTERISM_HOME/images" "$VOL"
echo "$MARKER" > "$VOL/MARKER.txt"
# Reuse already-pulled images instead of re-downloading. From the harness's
# own cache, never from ~/.asterism: that directory belongs to the user's
# daemon, which may be writing to it right now.
harness_seed_images "$ASTERISM_HOME"

fail() { echo "E2E FAIL: $*" >&2; exit 1; }
case "$BACKEND" in
  qemu|chv) ;;
  *) fail "unsupported lifecycle backend: $BACKEND" ;;
esac

# expect <desc> <needle> <cmd...>: run cmd, require success AND the needle
# in its combined output.
expect() {
  local desc="$1" needle="$2"; shift 2
  local out
  out="$("$@" 2>&1)" || fail "$desc: command failed:"$'\n'"$out"
  grep -qF "$needle" <<<"$out" || fail "$desc: expected \"$needle\" in:"$'\n'"$out"
  echo "ok: $desc"
}

# The image comes from the harness cache, filled once by the binary under
# test if it is not there yet, so only a first run downloads anything. The
# pull afterwards is what registers the copied file in this home's store; it
# has nothing left to fetch.
harness_cache_image "$AST" "$IMAGE" || fail "could not cache $IMAGE"
harness_seed_images "$ASTERISM_HOME"
"$AST" pull "$IMAGE" >/dev/null 2>&1 || fail "pull $IMAGE"

# The backend is named, not left to the daemon.
#
# The default lane pins QEMU for its 9p implementation. The Linux release gate
# explicitly selects CHV, exercising the same product journey through the
# shipped virtiofsd and Cloud Hypervisor snapshot path.
expect "create"  "$INST  defined"  \
  "$AST" create "$INST" --backend "$BACKEND" --image "$IMAGE" --mem 2G \
    --disk "${DISK_GIB}G"
expect "attach"  "/mnt/ast/e2e-vol" "$AST" attach "$INST" --volume "$VOL"
expect "up"      "$INST  running"  "$AST" up "$INST"

# And what it actually booted on, asserted rather than assumed: `--backend
# backend` is a request, and this is the line that catches a daemon that honours
# it in its output and not in the guest.
harness_assert_backend "$AST" "$INST" "$BACKEND" \
  || fail "the marker below would be proving something about a different backend"
echo "ok: the guest is on $BACKEND"

if [ "$BACKEND" = chv ]; then
  STATUS="$($AST status "$INST" 2>&1)"
  VMM_PID="$(sed -n 's/^running: chv pid \([0-9][0-9]*\),.*/\1/p' <<<"$STATUS")"
  [ -n "$VMM_PID" ] || fail "CHV status did not name its VMM pid:"$'\n'"$STATUS"
  VMM_EXE="$(readlink -f "/proc/$VMM_PID/exe" 2>/dev/null || true)"
  EXPECTED_CHV="$(readlink -f "$(dirname "$ASTD")/cloud-hypervisor")"
  [ "$VMM_EXE" = "$EXPECTED_CHV" ] \
    || fail "CHV pid $VMM_PID executes $VMM_EXE, not shipped $EXPECTED_CHV"
  [ -s "$ASTERISM_HOME/instances/$INST/virtiofs-0.resource.json" ] \
    || fail "CHV boot did not retain precise virtiofsd ownership"
  if pgrep -f '(^|/)qemu-system-[^ ]*' >/dev/null 2>&1; then
    fail "a qemu-system process exists during the CHV lifecycle"
  fi
  echo "ok: CHV pid $VMM_PID is the shipped helper; virtiofsd ownership is durable; no qemu-system exists"
fi

# First boot: sshd can come up before cloud-init has mounted the volumes,
# so give the marker a bounded retry instead of failing on the race.
marker_seen=
for _ in $(seq 1 30); do
  if out="$("$AST" ssh "$INST" -- "cat /mnt/ast/e2e-vol/MARKER.txt" 2>/dev/null)" \
     && grep -qF "$MARKER" <<<"$out"; then
    marker_seen=1; break
  fi
  sleep 3
done
[ -n "$marker_seen" ] || fail "marker not visible in guest after first boot"
echo "ok: marker via the $BACKEND shared-directory transport"

expect "down"     "$INST  stopped"          "$AST" down "$INST"
expect "snapshot" "$INST  snapshot clean"   "$AST" snapshot "$INST" clean
expect "list"     "clean"                   "$AST" snapshots "$INST"
expect "restore"  "restored to clean"       "$AST" restore "$INST" clean

# Deleting one: a file goes, the listing is a directory listing so it says
# so, and the one that was kept is still there to restore from.
expect "a second snapshot" "$INST  snapshot spare" "$AST" snapshot "$INST" spare
expect "both are listed" "spare" "$AST" snapshots "$INST"
expect "snapshot rm" "$INST  snapshot spare deleted" "$AST" snapshot rm "$INST" spare
SNAPS="$("$AST" snapshots "$INST" 2>&1)" || fail "snapshots failed:"$'\n'"$SNAPS"
grep -qF "clean" <<<"$SNAPS" || fail "deleting one took the other:"$'\n'"$SNAPS"
if grep -qF "spare" <<<"$SNAPS"; then fail "the deleted snapshot is still listed:"$'\n'"$SNAPS"; fi
[ ! -e "$ASTERISM_HOME/instances/$INST/snapshots/spare.raw" ] \
  || fail "ast snapshot rm left the file behind"
echo "ok: the snapshot is gone from the listing and from the disk"
OUT="$("$AST" snapshot rm "$INST" spare 2>&1 || true)"
grep -qF 'no snapshot "spare"' <<<"$OUT" || fail "deleting it twice was not refused:"$'\n'"$OUT"
OUT="$("$AST" snapshot rm "$INST" ../escape 2>&1 || true)"
grep -qF "snapshot names are ascii letters" <<<"$OUT" \
  || fail "a tag that leaves the directory was not refused:"$'\n'"$OUT"
echo "ok: deleting a snapshot that is not there, or is not a name, is refused in words"

expect "up again" "$INST  running"          "$AST" up "$INST"
OUT="$("$AST" snapshot rm "$INST" clean 2>&1 || true)"
grep -qF "is running" <<<"$OUT" \
  || fail "deleting a snapshot under a running guest was not refused:"$'\n'"$OUT"
echo "ok: and refused while the guest is running"
# Units were enabled on first boot; the mount must be there on reboot too.
expect "marker after reboot" "$MARKER" \
  "$AST" ssh "$INST" -- "cat /mnt/ast/e2e-vol/MARKER.txt"
expect "down 2"   "$INST  stopped"          "$AST" down "$INST"
expect "rm"       "$INST  removed"          "$AST" rm "$INST"

echo "E2E GREEN ($IMAGE)"
