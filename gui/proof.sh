#!/usr/bin/env bash
# The main window, proved on a scratch orbit of two daemons.
#
# Nothing here drives a pointer. Every assertion goes through one of the
# app's own headless hooks — `--dump-main` for what a section would draw,
# `--pair-via-window` for what the Devices panel's buttons do — so what is
# proved is the code behind the window rather than a re-implementation of it.
#
# Two homes under /private/tmp, never ~/.asterism. ASTERISM_MESH=local keeps
# both endpoints on loopback: no relay, no discovery service, no packet that
# leaves this machine.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export PATH="$HOME/.cargo/bin:$PATH"
AST="$ROOT/target/debug/ast"
ASTD="$ROOT/target/debug/astd"
GUI="$ROOT/gui/target/debug/asterism-gui"

RUN="/private/tmp/ast-gui3"
A="$RUN/a"
B="$RUN/b"
A_NAME="orbit-a"
B_NAME="orbit-b"

# KEEP=1 leaves the two daemons running, so that shots.sh can photograph the
# orbit this built rather than one reassembled from cold caches.
cleanup() {
  [ "${KEEP:-}" = "1" ] && return 0
  pkill -f "$ASTD" 2>/dev/null || true
}
trap cleanup EXIT

fail() { echo "GUI3 PROOF FAIL: $*" >&2; exit 1; }
ok() { echo "ok: $*"; }

need() {
  local desc="$1" needle="$2" haystack="$3"
  grep -qF "$needle" <<<"$haystack" || fail "$desc: expected \"$needle\" in:"$'\n'"$haystack"
  ok "$desc"
}

rm -rf "$RUN"
mkdir -p "$A" "$B"

for bin in "$AST" "$ASTD" "$GUI"; do
  [ -x "$bin" ] || fail "$bin is not built"
done

start_daemon() {
  local home="$1"
  ( ASTERISM_HOME="$home" ASTERISM_MESH=local "$ASTD" >"$home/astd.log" 2>&1 & )
  for _ in $(seq 1 60); do
    grep -q "on the mesh as" "$home/astd.log" 2>/dev/null && return 0
    sleep 0.2
  done
  fail "astd for $home did not come up:"$'\n'"$(cat "$home/astd.log" 2>/dev/null)"
}

start_daemon "$A"
start_daemon "$B"
ok "two daemons up, one per scratch home"

# The GUI resolves `ast` and `astd` next to itself; in a cargo tree they are
# somewhere else entirely, so it is told.
export ASTERISM_AST="$AST"
export ASTERISM_ASTD="$ASTD"

gui() {
  local home="$1"; shift
  ASTERISM_HOME="$home" "$GUI" "$@"
}

# ---- 1. the window's own pairing, both halves -------------------------------
#
# `--pair-via-window` is the Devices panel's Invite and Add buttons with the
# webview taken out: the same `devices::pair`, the same held-open connection,
# the same PairConfirm frame. The one thing it does that a person would not
# is take the codes as matching, which is why it is a flag.

ASTERISM_HOME="$A" ASTERISM_AST="$AST" ASTERISM_ASTD="$ASTD" \
  "$GUI" --pair-via-window invite --as "$A_NAME" >"$A/invite.out" 2>&1 &
INVITE=$!

TICKET=""
for _ in $(seq 1 150); do
  TICKET="$(grep -o 'astdev1[a-z0-9]*' "$A/invite.out" 2>/dev/null | head -1 || true)"
  [ -n "$TICKET" ] && break
  sleep 0.2
done
[ -n "$TICKET" ] || fail "the Invite panel printed no ticket:"$'\n'"$(cat "$A/invite.out")"
ok "Invite minted a ticket (${TICKET:0:22}…)"

gui "$B" --pair-via-window "add:$TICKET" --as "$B_NAME" >"$B/add.out" 2>&1 \
  || fail "the Add panel failed:"$'\n'"$(cat "$B/add.out")"
wait "$INVITE" || fail "the Invite panel failed:"$'\n'"$(cat "$A/invite.out")"

sas_of() { grep -o 'pairing sas [0-9 ]*' "$1" | sed 's/pairing sas //' | tr -d ' ' | head -1; }
SAS_A="$(sas_of "$A/invite.out")"
SAS_B="$(sas_of "$B/add.out")"
[ -n "$SAS_A" ] || fail "no six digits on the inviting side:"$'\n'"$(cat "$A/invite.out")"
[ "$SAS_A" = "$SAS_B" ] || fail "the two panels showed different codes: A=$SAS_A B=$SAS_B"
ok "both panels showed the same six digits ($SAS_A)"

need "the inviting panel reached paired" "pairing paired" "$(cat "$A/invite.out")"
need "the adding panel reached paired" "pairing paired" "$(cat "$B/add.out")"

# The store is the trust root, so assert on it and not only on the output.
grep -q '"device_id"' "$A/orbit.json" || fail "A's orbit store is empty"
grep -q '"device_id"' "$B/orbit.json" || fail "B's orbit store is empty"
ok "both orbit stores were written"

# ---- 2. the Devices section sees both -------------------------------------

DEVICES="$(gui "$A" --dump-main devices)"
echo "$DEVICES"
need "the Devices model names this device" "self=yes" "$DEVICES"
[ "$(grep -c '^device ' <<<"$DEVICES")" = "2" ] \
  || fail "the Devices model does not have two rows:"$'\n'"$DEVICES"
need "the peer is online over a path" "$B_NAME" "$DEVICES"
ok "the Devices model shows both devices"

# ---- 3. instances on both devices, in one orbit view -----------------------
#
# A 1 MiB qcow2 that is never booted: the registry only needs something to
# list, and a fleet view is a registry view.

DISK="$RUN/tiny.qcow2"
qemu-img create -f qcow2 "$DISK" 1M >/dev/null 2>&1 \
  || fail "qemu-img create failed (is qemu installed?)"

# One instance defined through the New Instance window's own create, and one
# through `ast`, so the orbit view has a row from each device.
WANTED='{"name":"gui-a","image":"'"$DISK"'","cpus":2,"mem_gib":1,"disk_gib":1,
         "backend":"qemu","start":false}'
gui "$A" --create-via-window "$WANTED" >"$A/create.out" 2>&1 \
  || fail "the New Instance window's create failed:"$'\n'"$(cat "$A/create.out")"
ok "the New Instance window defined gui-a on A"

ASTERISM_HOME="$B" "$AST" create gui-b --image "$DISK" --mem 512M --disk 1G >/dev/null \
  || fail "ast create on B failed"
ok "ast defined gui-b on B"

INSTANCES="$(gui "$A" --dump-main instances)"
echo "$INSTANCES"
need "the orbit view has A's instance" "instance gui-a" "$INSTANCES"
need "the orbit view has B's instance" "instance gui-b" "$INSTANCES"
need "a row names the device supplying its cpu" "cpu=$A_NAME" "$INSTANCES"
need "and the other device's" "cpu=$B_NAME" "$INSTANCES"
[ "$(grep -o 'cpu=[a-z0-9-]*' <<<"$INSTANCES" | sort -u | wc -l | tr -d ' ')" = "2" ] \
  || fail "the two rows do not come from two devices:"$'\n'"$INSTANCES"
need "a stopped row offers every verb the daemon would answer" \
  "actions up=enabled down=disabled terminal=disabled logs=enabled snapshot-list=enabled \
snapshot=enabled rename=enabled remove=enabled" "$INSTANCES"
need "a row carries the restart policy the pane reads" "policy restart=always max-attempts=" "$INSTANCES"
need "and the move fence, which is what makes a row read-only" "move-epoch 0" "$INSTANCES"

# The parts table is `Instance::parts()` carried through whole. Published
# ports live on the network row, which is why the window has no separate
# "ports not exposed yet" block to remove a second time.
need "the parts table names the cpu part and the device supplying it" \
  "part cpu/ram  source=$A_NAME" "$INSTANCES"
need "and the disk" "part disk     source=$A_NAME" "$INSTANCES"
need "and the network row, which is where published ports appear" \
  "part network  source=$A_NAME" "$INSTANCES"
need "and the other device's cpu part" "part cpu/ram  source=$B_NAME" "$INSTANCES"

# ---- 4. the Settings section ------------------------------------------------

SETTINGS="$(gui "$A" --dump-main settings)"
echo "$SETTINGS"
grep -qE '^daemon [0-9]' <<<"$SETTINGS" \
  || fail "the daemon's version is not reported:"$'\n'"$SETTINGS"
ok "the daemon's version is reported"
need "the home is the scratch one" "home $A" "$SETTINGS"
need "the service is reported by its mechanism" "service launchd" "$SETTINGS"
need "the login item is reported" "start-at-login" "$SETTINGS"

# The service pair must never have touched the real launchd: this only reads.
[ ! -e "$HOME/Library/LaunchAgents/com.asterism.astd.plist" ] \
  || echo "note: an astd service was already installed on this machine; nothing here changed it"

# ---- 5. the restart policy, through the split Start control -----------------
#
# `--click` is the id a row button posts, parsed by the same `Action::parse`
# and run by the same `perform`. Nothing about this path is the tray's.
#
# The scratch disk is a 1 MiB qcow2 with nothing on it, so a boot is expected
# to fail. What is asserted is the half that does not depend on a guest: the
# daemon records the policy before it tries to start anything, which is what
# makes the Start menu the only way the current wire has of changing one.

policy_of() {
  gui "$1" --dump-main instances | awk "/^instance +$2 /{found=1} found&&/^  policy /{print;exit}"
}

gui "$A" --click "up:gui-a:never" >"$A/up-never.out" 2>&1 || true
grep -qE "(ok|FAIL) *starting gui-a once" "$A/up-never.out" \
  || fail "Start once did not reach the daemon:"$'\n'"$(cat "$A/up-never.out")"
need "Start once records restart: never" "restart=never" "$(policy_of "$A" gui-a)"

gui "$A" --click "up:gui-a" >"$A/up-plain.out" 2>&1 || true
grep -qE "(ok|FAIL) *starting gui-a" "$A/up-plain.out" \
  || fail "the plain Start did not reach the daemon:"$'\n'"$(cat "$A/up-plain.out")"
need "a plain Start preserves the recorded policy" "restart=never" "$(policy_of "$A" gui-a)"

gui "$A" --click "up:gui-a:always" >"$A/up-always.out" 2>&1 || true
need "Start and keep running records restart: always" "restart=always" "$(policy_of "$A" gui-a)"

# ---- 6. the gates on a running guest, and the way out of them ---------------
#
# `up:gui-a:always` above left a booted guest, so the half of the gate matrix
# that needs one can be asserted here rather than only in the unit tests:
# a running instance offers Stop and a terminal, and refuses a rename, a
# snapshot and a removal — in the daemon's own words, reaching this caller
# unchanged rather than as "see the notification".

RUNNING="$(gui "$A" --dump-main instances)"
grep -qE "^instance +gui-a +running" <<<"$RUNNING" \
  || fail "gui-a did not reach a running guest:"$'\n'"$RUNNING"
need "a running row offers Stop and a terminal and nothing that rewrites a disk" \
  "actions up=disabled down=enabled terminal=enabled logs=enabled snapshot-list=enabled \
snapshot=disabled rename=disabled remove=disabled" "$RUNNING"

gui "$A" --click "rename:gui-a:gui-z" >"$A/rename-running.out" 2>&1 || true
need "a running rename is refused in the daemon's own sentence" \
  "FAIL renaming gui-a to gui-z: instance \"gui-a\" is running" "$(cat "$A/rename-running.out")"
need "and the instance keeps its name" "instance gui-a" "$(gui "$A" --dump-main instances)"

gui "$A" --click "snap:gui-a:while-up" >"$A/snap-running.out" 2>&1 || true
grep -q "FAIL snapshotting gui-a as while-up" "$A/snap-running.out" \
  || fail "a snapshot of a running guest was not refused:"$'\n'"$(cat "$A/snap-running.out")"
ok "a running snapshot is refused, and the refusal is the daemon's"

gui "$A" --click "rm:gui-a" --confirm "gui-a" >"$A/rm-running.out" 2>&1 || true
need "and so is a removal, even with the exact word typed" \
  "FAIL removing gui-a" "$(cat "$A/rm-running.out")"
need "the instance is still there" "instance gui-a" "$(gui "$A" --dump-main instances)"

gui "$A" --click "down:gui-a" >"$A/down.out" 2>&1 \
  || fail "the Stop button failed:"$'\n'"$(cat "$A/down.out")"
need "Stop acts immediately, with nothing to confirm" "ok   stopping gui-a" "$(cat "$A/down.out")"

# ---- 6b. rename, on both orbit views ----------------------------------------

gui "$A" --click "rename:gui-a:gui-z" >"$A/rename.out" 2>&1 \
  || fail "the Rename dialog's action failed:"$'\n'"$(cat "$A/rename.out")"
need "the rename is logged by its own name" "ok   renaming gui-a to gui-z" "$(cat "$A/rename.out")"

RENAMED="$(gui "$A" --dump-main instances)"
need "A's window shows the new name" "instance gui-z" "$RENAMED"
grep -qE "^instance +gui-a " <<<"$RENAMED" && fail "the old name is still in A's view:"$'\n'"$RENAMED"
need "and B sees it too — one orbit, one namespace" "instance gui-z" "$(gui "$B" --dump-main instances)"
ok "the rename landed on both orbit views"

# ---- 7. snapshots, and the words that have to be typed ----------------------

need "an instance with no snapshots says so rather than showing nothing" \
  "empty" "$(gui "$A" --dump-snapshots gui-z)"

gui "$A" --click "snap:gui-z:t1" >"$A/snap.out" 2>&1 \
  || fail "the Take snapshot dialog's action failed:"$'\n'"$(cat "$A/snap.out")"
SNAPS="$(gui "$A" --dump-snapshots gui-z)"
echo "$SNAPS"
need "the snapshot table names the tag" "snapshot t1" "$SNAPS"
# `0 B` is the true size of a qcow2 internal snapshot — it stores no guest
# RAM and no copied blocks — so what is asserted is that both columns are the
# daemon's own values rather than that either is non-zero.
grep -qE 'size=.+date=[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}' <<<"$SNAPS" \
  || fail "the snapshot table has no size and date columns:"$'\n'"$SNAPS"
ok "the snapshot table carries the daemon's own size and date"

# The disk as it stands now. A skipped restore must not touch it.
disk_of() { find "$1/instances/$2" -name '*.qcow2' -o -name 'disk*' 2>/dev/null | head -1; }
DISK_PATH="$(disk_of "$A" gui-z)"
[ -n "$DISK_PATH" ] || fail "could not find gui-z's disk under $A/instances/gui-z"
BEFORE="$(shasum -a 256 "$DISK_PATH" | cut -d' ' -f1)"

gui "$A" --click "restore:gui-z:t1" >"$A/restore-none.out" 2>&1 || true
need "a restore with no typed word sends nothing" \
  "skip restoring gui-z to t1: confirmation missing or did not match" \
  "$(cat "$A/restore-none.out")"
gui "$A" --click "restore:gui-z:t1" --confirm "t2" >"$A/restore-wrong.out" 2>&1 || true
need "and neither does one with the wrong word" \
  "skip restoring gui-z to t1: confirmation missing or did not match" \
  "$(cat "$A/restore-wrong.out")"
[ "$(shasum -a 256 "$DISK_PATH" | cut -d' ' -f1)" = "$BEFORE" ] \
  || fail "a skipped restore changed the disk"
ok "a skipped restore left the disk exactly as it was"

gui "$A" --click "restore:gui-z:t1" --confirm "t1" >"$A/restore.out" 2>&1 \
  || fail "the confirmed restore failed:"$'\n'"$(cat "$A/restore.out")"
need "the confirmed restore ran" "ok   restoring gui-z to t1" "$(cat "$A/restore.out")"
need "and the snapshot is kept, not consumed" "snapshot t1" "$(gui "$A" --dump-snapshots gui-z)"

gui "$A" --click "snaprm:gui-z:t1" >"$A/snaprm-none.out" 2>&1 || true
need "a snapshot delete with no typed word sends nothing" \
  "skip deleting gui-z's snapshot t1: confirmation missing or did not match" \
  "$(cat "$A/snaprm-none.out")"
need "and the snapshot is still there" "snapshot t1" "$(gui "$A" --dump-snapshots gui-z)"

gui "$A" --click "snaprm:gui-z:t1" --confirm "t1" >"$A/snaprm.out" 2>&1 \
  || fail "the confirmed snapshot delete failed:"$'\n'"$(cat "$A/snaprm.out")"
need "the snapshot is gone" "empty" "$(gui "$A" --dump-snapshots gui-z)"

# A non-destructive action must not accept a token either: a confirmation on
# a Stop is a habit that teaches people to type past the ones that matter.
gui "$A" --click "down:gui-z" --confirm "gui-z" >"$A/down-token.out" 2>&1 || true
need "a token on something that never asks for one is refused" \
  "skip stopping gui-z: unexpected confirmation" "$(cat "$A/down-token.out")"

# ---- 8. removal -------------------------------------------------------------

gui "$A" --click "rm:gui-z" >"$A/rm-none.out" 2>&1 || true
need "a removal with no typed word sends nothing" \
  "skip removing gui-z: confirmation missing or did not match" "$(cat "$A/rm-none.out")"
gui "$A" --click "rm:gui-z" --confirm "gui-a" >"$A/rm-wrong.out" 2>&1 || true
need "and neither does one with the wrong word" \
  "skip removing gui-z: confirmation missing or did not match" "$(cat "$A/rm-wrong.out")"
need "the instance is still there" "instance gui-z" "$(gui "$A" --dump-main instances)"
need "and the skip is in the log a user would read afterwards" \
  "skip removing gui-z" "$(cat "$A/gui.log")"

gui "$A" --click "rm:gui-z" --confirm "gui-z" >"$A/rm.out" 2>&1 \
  || fail "the confirmed removal failed:"$'\n'"$(cat "$A/rm.out")"
GONE="$(gui "$A" --dump-main instances)"
grep -qE "^instance +gui-z " <<<"$GONE" && fail "gui-z survived its removal:"$'\n'"$GONE"
grep -qE "^instance +gui-z " <<<"$(gui "$B" --dump-main instances)" \
  && fail "gui-z is still in B's view of the orbit"
[ ! -d "$A/instances/gui-z" ] || fail "gui-z's instance directory is still on disk"
# Block-volume bytes are deliberately not asserted deleted: the daemon tries
# to release leases and an offline provider can keep a stale one, which is
# why the dialog does not promise otherwise either.
ok "the confirmed removal took the instance off both orbit views and off the disk"

# A second action on one instance, while the first is in flight, is refused
# in `crate::Busy` before a frame is written. It is a race, so it is proved
# by the deterministic unit test rather than by two racing processes here:
# `cargo test --manifest-path gui/Cargo.toml a_second_action_on_one_instance`.

# ---- 9. the whole window, one dump ------------------------------------------

ALL="$(gui "$A" --dump-main)"
for head in "section instances" "section devices" "section settings"; do
  need "the whole-window dump has $head" "$head" "$ALL"
done

# ---- 10. an orbit worth photographing ---------------------------------------
#
# `KEEP=1 proof.sh && shots.sh --reuse` photographs whatever this leaves
# behind, and section 8 deliberately deleted A's only instance. Put one back,
# with a snapshot on it, so the pictures are of a fleet rather than of a
# half-empty pane.

WANTED='{"name":"gui-a","image":"'"$DISK"'","cpus":2,"mem_gib":1,"disk_gib":1,
         "backend":"qemu","start":false}'
gui "$A" --create-via-window "$WANTED" >"$A/recreate.out" 2>&1 \
  || fail "rebuilding gui-a failed:"$'\n'"$(cat "$A/recreate.out")"
gui "$A" --click "snap:gui-a:before-upgrade" >"$A/snap2.out" 2>&1 \
  || fail "snapshotting the rebuilt gui-a failed:"$'\n'"$(cat "$A/snap2.out")"
ok "left a two-device orbit with a snapshot on it for shots.sh"

echo
echo "GUI3 PROOF OK"
