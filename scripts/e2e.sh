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
cargo build -q
AST="$ROOT/target/debug/ast"

# Fresh, SHORT home: unix socket paths are capped near 104 bytes.
export ASTERISM_HOME="/private/tmp/ast-e2e-$$"

# A single-device test has no orbit, so it has no business publishing a
# throwaway key and this machine's addresses to a public discovery service.
export ASTERISM_MESH=local
IMAGE="${E2E_IMAGE:-debian:13}"
INST=e2e
VOL="$ASTERISM_HOME/e2e-vol"   # dash on purpose: covers systemd \x2d escaping
MARKER="marker-$$"

cleanup() {
  "$AST" down "$INST" >/dev/null 2>&1 || true
  "$AST" rm "$INST" >/dev/null 2>&1 || true
  pkill -f "$ROOT/target/debug/astd" 2>/dev/null || true
  rm -rf "$ASTERISM_HOME"
}
trap cleanup EXIT

mkdir -p "$ASTERISM_HOME/images" "$VOL"
echo "$MARKER" > "$VOL/MARKER.txt"
# Reuse already-pulled images instead of re-downloading.
if [ -d "$HOME/.asterism/images" ]; then
  cp "$HOME/.asterism/images/"*.qcow2 "$ASTERISM_HOME/images/" 2>/dev/null || true
fi

fail() { echo "E2E FAIL: $*" >&2; exit 1; }

# expect <desc> <needle> <cmd...>: run cmd, require success AND the needle
# in its combined output.
expect() {
  local desc="$1" needle="$2"; shift 2
  local out
  out="$("$@" 2>&1)" || fail "$desc: command failed:"$'\n'"$out"
  grep -qF "$needle" <<<"$out" || fail "$desc: expected \"$needle\" in:"$'\n'"$out"
  echo "ok: $desc"
}

"$AST" pull "$IMAGE" >/dev/null 2>&1 || fail "pull $IMAGE"

expect "create"  "$INST  defined"  "$AST" create "$INST" --image "$IMAGE" --mem 2G --disk 10G
expect "attach"  "/mnt/ast/e2e-vol" "$AST" attach "$INST" --volume "$VOL"
expect "up"      "$INST  running"  "$AST" up "$INST"

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
echo "ok: marker via 9p"

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
