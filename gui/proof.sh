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
# shellcheck source-path=SCRIPTDIR source=../scripts/lib/harness.sh
. "$ROOT/scripts/lib/harness.sh"
harness_begin gui
harness_binaries "$ROOT"
GUI="${GUI_BIN:-$ROOT/gui/target/debug/asterism-gui}"

RUN="/private/tmp/ast-gui3"
A="$RUN/a"
B="$RUN/b"
A_NAME="orbit-a"
B_NAME="orbit-b"

# KEEP=1 leaves the two daemons running, so that shots.sh can photograph the
# orbit this built rather than one reassembled from cold caches.
cleanup() {
  harness_keep_home "$A" a
  harness_keep_home "$B" b
  harness_artifacts_note
  [ "${KEEP:-}" = "1" ] && return 0
  # Only the two daemons this run started. `pkill -f "$ASTD"` reached every
  # astd built at that path — including a developer's own, running against
  # their own home, with their own guests under it.
  harness_reap
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
  # Registered before it is started, so that a daemon which comes up and then
  # wedges is still something the cleanup trap can reach.
  harness_own_home "$home"
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
need "a stopped row offers Up and a snapshot" \
  "actions up=enabled down=disabled terminal=disabled snapshots=enabled" "$INSTANCES"

# The same two rows from the other device: one orbit, one namespace.
FROM_B="$(gui "$B" --dump-main instances)"
need "B's window shows A's instance too" "instance gui-a" "$FROM_B"
need "B's window shows its own" "instance gui-b" "$FROM_B"
ok "both windows show one orbit rather than one shard"

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

# ---- 5. a row action, through the window's own command path ----------------
#
# `--click` is the id a row button posts, parsed by the same `Action::parse`
# and run by the same `perform`. Nothing about this path is the tray's.

gui "$A" --click "up:gui-a" >"$A/up.out" 2>&1 || true
grep -qE "(ok|FAIL) *starting gui-a" "$A/up.out" \
  || fail "the window's Up button did not reach the daemon:"$'\n'"$(cat "$A/up.out")"
ok "the window's Up button runs the tray's action"

# ---- 6. the whole window, one dump ------------------------------------------

ALL="$(gui "$A" --dump-main)"
for head in "section instances" "section devices" "section settings"; do
  need "the whole-window dump has $head" "$head" "$ALL"
done

echo
echo "GUI3 PROOF OK"
