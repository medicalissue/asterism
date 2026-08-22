#!/usr/bin/env bash
# End-to-end for durable state: real daemons, real `kill -9`, real damage to
# the files on disk, and no hand-editing of JSON to recover from any of it.
#
# The unit tests prove the primitive (crates/asterism-core/src/durable.rs) and
# each store's use of it. What only a running daemon can prove is what this
# asserts:
#
#   1. a `kill -9` between two commits loses nothing that was committed
#   2. a torn state.json is repaired from its last-known-good copy at the
#      next start, out loud, and written back healthy
#   3. a torn state.json with a torn backup is REFUSED — the daemon does not
#      start on an empty registry and quietly forget this device's instances
#   4. the staging file an interrupted commit leaves is swept at start, and
#      whatever is at a staging path — a symlink, a world-readable plant —
#      is cleared rather than opened
#   5. a shard written by a pre-envelope Asterism migrates on read
#   6. a state file from a NEWER Asterism is refused as a downgrade rather
#      than parsed as best it can be
#   7. the volume book gets the same treatment as the registry
#   8. a restore interrupted before it replaced the disk converges at the
#      next start: the disk is untouched and the snapshot is unpinned
#
# No guest is booted. Every claim here is about the daemon's own state, which
# is what makes this cheap enough to run on every change — the boot-shaped
# durability claims live in scripts/e2e-keys.sh and scripts/e2e-persist.sh.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export PATH="$HOME/.cargo/bin:$PATH"
cd "$ROOT"
# shellcheck source-path=SCRIPTDIR source=lib/harness.sh
. "$ROOT/scripts/lib/harness.sh"
harness_begin durability
harness_binaries "$ROOT"

# Fresh, SHORT home: unix socket paths are capped near 104 bytes.
export ASTERISM_HOME="/private/tmp/ast-dur-$$"

# A single-device test has no orbit, so it has no business publishing a
# throwaway key and this machine's addresses to a public discovery service.
export ASTERISM_MESH=local
harness_own_home "$ASTERISM_HOME"
BIN="$ASTERISM_HOME/bin"
LOG="$ASTERISM_HOME/astd.log"
STATE="$ASTERISM_HOME/state.json"
VOLUMES="$ASTERISM_HOME/volumes.json"
IMAGE="${E2E_IMAGE:-debian:13}"
ASTD_PID=

fail() { echo "E2E FAIL: $*" >&2; echo "--- astd log ---" >&2; tail -60 "$LOG" 2>/dev/null >&2 || true; exit 1; }
ok() { echo "ok: $*"; }

cleanup() {
  harness_keep_home "$ASTERISM_HOME" home
  if [ -n "$ASTD_PID" ]; then
    kill -9 "$ASTD_PID" 2>/dev/null || true
    # Reaped here, or the shell reports the SIGKILL as a job-control line
    # after the "E2E GREEN" that the reader is meant to end on.
    wait "$ASTD_PID" 2>/dev/null || true
  fi
  # Only what this run started. `pkill -9 -f "$ASTERISM_HOME"` used to stand
  # here: it matched command lines, so it also reached anything that merely
  # named this directory — and it reached it with SIGKILL. The daemon writes
  # down every process it starts; harness_reap stops those.
  harness_reap
  harness_artifacts_note
  if [ -n "${KEEP:-}" ]; then
    echo "kept $ASTERISM_HOME for inspection"
  else
    rm -rf "$ASTERISM_HOME"
  fi
  return 0
}
trap cleanup EXIT

mkdir -p "$ASTERISM_HOME/images" "$BIN"
# Copied into the home rather than run out of target/, so that a rebuild
# part-way through a long run cannot swap the binary under a live daemon.
cp "$AST" "$ASTD" "$BIN/"
AST="$BIN/ast"
ASTD="$BIN/astd"
harness_seed_images "$ASTERISM_HOME"

# Started here, not by the CLI: `ast` spawns a daemon with its output on
# /dev/null, and the recovery reasons in that output are half the point.
start_astd() {
  "$ASTD" >>"$LOG" 2>&1 &
  ASTD_PID=$!
  for _ in $(seq 1 100); do
    if [ "$(cat "$ASTERISM_HOME/astd.pid" 2>/dev/null || true)" = "$ASTD_PID" ]; then
      return 0
    fi
    sleep 0.2
  done
  fail "astd did not come up"
}

# A daemon that is *meant* to refuse to start. Prints its output and fails
# the test if it comes up instead — bounded, so a daemon that wrongly starts
# is a failure rather than a hang.
start_astd_expecting_refusal() {
  local out="$ASTERISM_HOME/refusal.txt"
  "$ASTD" >"$out" 2>&1 &
  local pid=$!
  for _ in $(seq 1 100); do
    if ! kill -0 "$pid" 2>/dev/null; then
      wait "$pid" 2>/dev/null && fail "astd started when it should have refused"
      tee -a "$LOG" <"$out"
      return 0
    fi
    sleep 0.2
  done
  kill -9 "$pid" 2>/dev/null || true
  fail "astd neither started nor refused within 20s"
}

# kill -9, which is the power cord as far as this daemon is concerned: no
# signal handler runs, no socket is unlinked, nothing is flushed on the way
# out that was not already flushed.
kill_astd() {
  if [ -n "$ASTD_PID" ]; then
    kill -9 "$ASTD_PID" 2>/dev/null || true
    wait "$ASTD_PID" 2>/dev/null || true
    ASTD_PID=
  fi
  rm -f "$ASTERISM_HOME/astd.sock" "$ASTERISM_HOME/astd.pid"
}

expect() {
  local desc="$1" needle="$2"; shift 2
  local out
  out="$("$@" 2>&1)" || fail "$desc: command failed:"$'\n'"$out"
  grep -qF "$needle" <<<"$out" || fail "$desc: expected \"$needle\" in:"$'\n'"$out"
  ok "$desc"
}

listed() { "$AST" ls 2>&1; }
logged() { grep -qF "$1" "$LOG"; }

# <needle> [seconds]: the same question, given time to become true.
#
# Not every repair happens while astd is starting. The volume book, for one,
# is read the first time something asks about volumes — so a `logged` fired
# the instant the pid file appears is asking whether a thing that has not
# been triggered yet has already been announced. It usually has, which is the
# worst version of the bug: a suite that passes on a fast machine and fails
# in CI, for no reason anybody can see in the output.
logged_soon() {
  local needle="$1" budget="${2:-15}" _i
  for _i in $(seq 1 $((budget * 5))); do
    logged "$needle" && return 0
    sleep 0.2
  done
  return 1
}

# `python3` is what the tree already assumes for JSON in scripts, and this
# needs to build a *legacy* shard, which no version of `ast` will write.
json() { python3 -c "$@"; }

# ---- 1. a kill -9 loses nothing that was committed --------------------------

# The image comes from the harness cache, filled once by the binary under
# test if it is not there yet, so only a first run downloads anything. Done
# before the daemon starts, so nothing lands in a store a running daemon may
# be reading.
harness_cache_image "$AST" "$IMAGE" || fail "could not cache $IMAGE"
harness_seed_images "$ASTERISM_HOME"

start_astd
# Registers the copied file in this home's store; it has nothing left to fetch.
"$AST" pull "$IMAGE" >/dev/null 2>&1 || fail "pull $IMAGE"
expect "create one" "one  defined" "$AST" create one --image "$IMAGE" --mem 1G --disk 5G
expect "create two" "two  defined" "$AST" create two --image "$IMAGE" --mem 1G --disk 5G

grep -q '"version"' "$STATE" || fail "the shard is not written in the versioned envelope"
ok "the shard is written in a versioned envelope"

kill_astd
start_astd
OUT="$(listed)"
grep -qF "one" <<<"$OUT" || fail "an instance did not survive kill -9:"$'\n'"$OUT"
grep -qF "two" <<<"$OUT" || fail "an instance did not survive kill -9:"$'\n'"$OUT"
ok "every committed instance survived kill -9"

# ---- 2. a torn shard is repaired from the last-known-good -------------------

kill_astd
[ -f "$STATE.bak" ] || fail "no last-known-good copy was kept beside the shard"
cp "$STATE" "$ASTERISM_HOME/whole.json"
# What a filesystem that lost a page leaves behind: a prefix.
WHOLE="$(wc -c <"$STATE")"
dd if="$ASTERISM_HOME/whole.json" of="$STATE" bs=1 count=$((WHOLE / 2)) 2>/dev/null
: >"$LOG"
start_astd
logged_soon "last-known-good" || fail "the repair was silent"
ok "a torn shard is repaired from its last-known-good copy, out loud"
OUT="$(listed)"
grep -qF "one" <<<"$OUT" || fail "the repair lost an instance:"$'\n'"$OUT"
ok "and the instances are still there"
# Written back healthy, with no editing by hand: the next start is ordinary.
kill_astd
: >"$LOG"
start_astd
if logged "last-known-good"; then fail "the repair was not written back — it happened twice"; fi
ok "the repaired shard was written back, so the next start is an ordinary one"

# ---- 3. two unreadable copies are refused, not guessed ----------------------

kill_astd
cp "$STATE" "$ASTERISM_HOME/good.json"
cp "$STATE.bak" "$ASTERISM_HOME/good.bak.json"
printf '{ "instances": ' >"$STATE"
printf 'neither is this' >"$STATE.bak"
OUT="$(start_astd_expecting_refusal)" || fail "astd started on two unreadable copies"
grep -qF "will not guess" <<<"$OUT" || fail "the refusal does not say it is refusing:"$'\n'"$OUT"
grep -qF "To repair" <<<"$OUT" || fail "the refusal has no repair path:"$'\n'"$OUT"
ok "an unreadable shard with an unreadable backup is refused, with a repair path"

# And the repair path is the one the message describes: put the files back,
# start again. No JSON is edited by hand anywhere in this test.
cp "$ASTERISM_HOME/good.json" "$STATE"
cp "$ASTERISM_HOME/good.bak.json" "$STATE.bak"
start_astd
OUT="$(listed)"
grep -qF "one" <<<"$OUT" || fail "the documented repair did not repair:"$'\n'"$OUT"
ok "and the repair path in the message is the one that works"

# ---- 4. the staging file of an interrupted commit is swept ------------------

kill_astd
printf 'half a value' >"$STATE.tmp"
: >"$LOG"
start_astd
[ ! -e "$STATE.tmp" ] || fail "the interrupted commit's staging file was left behind"
logged_soon "a commit was interrupted before it published" \
  || fail "the sweep was silent about what it swept"
ok "the staging file an interrupted commit left is swept, and said"
[ -f "$STATE.bak" ] || fail "the sweep took the last-known-good copy with it"
ok "and the last-known-good copy is not swept with it"

# ---- 4b. what is already at the staging path is not opened -----------------

# The staging path is predictable and sits in a directory anyone on this
# machine can list. A symlink there would make the daemon write this device's
# state into whatever it points at, and the rename afterwards would move the
# link — so the commit would look entirely successful.
#
# Planted with the daemon ALREADY RUNNING, deliberately: the startup sweep
# would otherwise clear it, and the sweep is not what is being tested here.
# What is being tested is the open that stages the next commit.
kill_astd
start_astd
VICTIM="$ASTERISM_HOME/victim.txt"
printf 'victim' >"$VICTIM"
ln -s "$VICTIM" "$STATE.tmp"
# `create` commits the shard, which is the write that would have gone through
# the link.
expect "a commit with a symlink in the way" "three  defined" \
  "$AST" create three --image "$IMAGE" --mem 1G --disk 5G
[ "$(cat "$VICTIM")" = "victim" ] || fail "the shard was written through the symlink"
if [ -L "$STATE" ]; then fail "the state file is a symlink"; fi
if [ -L "$STATE.tmp" ]; then fail "the symlink is still at the staging path"; fi
OUT="$(listed)"
grep -qF "three" <<<"$OUT" || fail "the commit did not land:"$'\n'"$OUT"
ok "a symlink at the staging path is cleared, not written through"
"$AST" rm three >/dev/null 2>&1 || true

# A world-readable file left at the staging path must not become the mode of
# what is committed: `open(O_CREAT)` on an existing path ignores the mode it
# is given and hands back the file with the permissions it already had.
# Planted with the daemon running, for the same reason as above.
printf 'planted' >"$STATE.tmp"
chmod 0666 "$STATE.tmp"
expect "a commit with a planted file in the way" "four  defined" \
  "$AST" create four --image "$IMAGE" --mem 1G --disk 5G
MODE="$(stat -f '%Lp' "$STATE")"
case "$MODE" in
  *[2367]) fail "the committed shard is group- or world-writable (mode $MODE)" ;;
esac
if grep -qF "planted" "$STATE"; then fail "the planted file became the shard"; fi
ok "a permissive file at the staging path is cleared, not adopted (mode $MODE)"
"$AST" rm four >/dev/null 2>&1 || true

# ---- 5. a pre-envelope shard migrates on read ------------------------------

kill_astd
json "
import json, os
p = os.environ['ASTERISM_HOME'] + '/state.json'
doc = json.load(open(p))
# Exactly what an Asterism before the envelope wrote: the map, alone.
json.dump(doc['instances'], open(p, 'w'), indent=2)
" || fail "could not write a legacy shard"
rm -f "$STATE.bak"
start_astd
OUT="$(listed)"
grep -qF "one" <<<"$OUT" || fail "a pre-envelope shard did not migrate:"$'\n'"$OUT"
grep -q '"version"' "$STATE" || fail "the migrated shard was not written back in the envelope"
ok "a shard written before the envelope existed migrates and is written back"

# ---- 6. a shard from a newer Asterism is refused ---------------------------

kill_astd
cp "$STATE" "$ASTERISM_HOME/good.json"
json "
import json, os
p = os.environ['ASTERISM_HOME'] + '/state.json'
doc = json.load(open(p))
doc['version'] = 99
json.dump(doc, open(p, 'w'), indent=2)
" || fail "could not write a future shard"
# No backup at all, so a repair would have to create one: its continued
# absence afterwards is how we know nothing was written over the future file.
rm -f "$STATE.bak"
OUT="$(start_astd_expecting_refusal)"
grep -qF "version 99" <<<"$OUT" || fail "the refusal does not name the version:"$'\n'"$OUT"
grep -qF "upgrade Asterism" <<<"$OUT" || fail "the refusal does not say what to do:"$'\n'"$OUT"
if [ -f "$STATE.bak" ]; then fail "a refused downgrade must not have been repaired over"; fi
grep -q '"version": 99' "$STATE" || fail "the refused file was modified"
ok "a shard from a newer Asterism is refused as a downgrade, and left untouched"
cp "$ASTERISM_HOME/good.json" "$STATE"

# ---- 7. the volume book gets the same treatment ----------------------------

start_astd
expect "create a volume" "tank" "$AST" volume create tank --size 1G
# A second, because the last-known-good copy is the value the *previous*
# commit replaced: a store that has only ever been written once has nothing
# to have kept.
expect "create a second" "spare" "$AST" volume create spare --size 1G
kill_astd
[ -f "$VOLUMES.bak" ] || fail "no last-known-good copy beside the volume book"
cp "$VOLUMES" "$ASTERISM_HOME/vol-whole.json"
WHOLE="$(wc -c <"$VOLUMES")"
dd if="$ASTERISM_HOME/vol-whole.json" of="$VOLUMES" bs=1 count=$((WHOLE / 2)) 2>/dev/null
: >"$LOG"
start_astd
# The read comes first, and then the assertion about it. Unlike the shard,
# the volume book is not read at startup — it is read when something asks
# about volumes, so asking is what makes the repair happen.
expect "the volume survived" "tank" "$AST" volume ls
logged_soon "last-known-good" || fail "a torn volume book was not repaired out loud"
ok "a torn volume book is repaired rather than read as \"this device has no volumes\""

# ---- 8. an interrupted restore converges at the next start ------------------

kill_astd
SNAPS="$ASTERISM_HOME/instances/one/snapshots"
CLONE="$ASTERISM_HOME/instances/one/disk.raw.restoring"
mkdir -p "$SNAPS"
printf 'the snapshot' >"$SNAPS/clean.raw"
# Exactly what a `kill -9` in the middle of a restore leaves: the marker
# naming the source, and the half-made clone beside the disk. Staged by hand
# because there is no way to schedule a power cut — what must need no hand is
# the *recovery*, which is the assertion below.
printf 'clean' >"$SNAPS/.restoring"
printf 'half a clone' >"$CLONE"
: >"$LOG"
start_astd
logged_soon "interrupted before it replaced the disk" \
  || fail "the interrupted restore was not settled at start"
[ ! -e "$CLONE" ] || fail "the half-made clone was left behind"
[ ! -e "$SNAPS/.restoring" ] || fail "the snapshot is still pinned by a restore that is over"
[ -f "$SNAPS/clean.raw" ] || fail "the convergence took the snapshot with it"
ok "a restore killed before the rename settles at start: clone gone, snapshot unpinned"

"$AST" rm one >/dev/null 2>&1 || true
"$AST" rm two >/dev/null 2>&1 || true

echo "E2E GREEN (durability)"
