#!/usr/bin/env bash
# End-to-end for swapping an instance's cpu part onto another device — the
# offline migration of docs/ROADMAP.md Phase 6.
#
# Two daemons on one host, each with its own ASTERISM_HOME, paired over
# loopback, with REAL guests booted at both ends. Asserting on output CONTENT
# the way scripts/e2e.sh does.
#
#   boot on A, write a marker, snapshot, down
#   -> ast move (base fetched peer-to-peer, disk streamed sparsely)
#   -> ast ls says B, ast up on B boots it, ssh reads the marker back
#   -> the snapshot came along and restoring it on B works
#   -> A's copy is gone and A answers "moved to B" if asked directly
#   -> a move to a paired device whose daemon is down fails, leaving A
#      authoritative
#   -> a move whose target dies mid-transfer leaves A bootable and B with no
#      bootable copy, and the staging directory is swept on B's next start
#
# The image store is deliberately given to A only: the whole point of the base
# being content-addressed is that B fetches it from an orbit peer that has it
# rather than from the internet, and an e2e that pre-seeded both would never
# exercise that.
#
# ASTERISM_MESH=local keeps both endpoints on loopback: no relays, no
# discovery service, no packet that leaves the machine.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export PATH="$HOME/.cargo/bin:$PATH"
cd "$ROOT"
cargo build -q
AST="$ROOT/target/debug/ast"
ASTD="$ROOT/target/debug/astd"

# Fresh, SHORT homes: unix socket paths are capped near 104 bytes.
RUN="/private/tmp/ast-move-$$"
A="$RUN/a"
B="$RUN/b"
C="$RUN/c"           # paired, then shut down: the device that will not answer
A_NAME="move-a-$$"
B_NAME="move-b-$$"
C_NAME="move-c-$$"
INST="mv-e2e"        # the one that really moves, boots at both ends
KILL="mv-kill"       # the one whose target dies mid-transfer
FAIL="mv-fail"       # the small one that proves the refusals and --down
VOL="$RUN/mv-vol"    # a directory volume, stranded by the move
IMAGE="${E2E_IMAGE:-debian:13}"
MARKER="marker-$$"
POST="post-$$"

# ---- the processes this test starts ----------------------------------------
#
# Everything started here writes down its own pid inside its own
# ASTERISM_HOME: astd in $home/astd.pid, each guest's qemu in
# $home/instances/<name>/qemu.pid, each storage daemon in
# $home/volumes/<name>/nbd-e<epoch>.pid. Those files are what cleanup acts
# on, so it can only ever reach a process this run started.
#
# The alternative — `pkill -f` on the astd path — reaches every astd built
# from this tree: the one the developer running this test has open on their
# own ~/.asterism, and any other e2e in this suite running beside it.

# kill_pid <pid> [signal]: bounded and idempotent. A pid that is already
# gone is success; one that will not take a hint gets ~5s and then -KILL.
kill_pid() {
  local pid="$1" sig="${2:--TERM}" _i
  case "$pid" in ''|*[!0-9]*) return 0 ;; esac
  kill -0 "$pid" 2>/dev/null || return 0
  kill "$sig" "$pid" 2>/dev/null || true
  for _i in $(seq 1 25); do
    kill -0 "$pid" 2>/dev/null || return 0
    sleep 0.2
  done
  kill -KILL "$pid" 2>/dev/null || true
}

# kill_pidfile <path>: whatever a pidfile names, and then the file.
kill_pidfile() {
  local f="$1"
  [ -f "$f" ] || return 0
  kill_pid "$(cat "$f" 2>/dev/null || true)"
  rm -f "$f"
}

# Deliberately no `ast` in here. The socket read in the CLI has no timeout,
# so `ast down` against a daemon that is wedged blocks this trap forever —
# and `ast` starts a daemon when the socket does not answer, so a cleanup
# built out of it can resurrect, and re-boot, the very instances it came to
# remove. Killing by pid needs no daemon to be well.
cleanup() {
  if [ -n "${CLEANED:-}" ]; then return 0; fi
  CLEANED=1
  local home f pid
  # The daemons first: astd is what restarts a guest it notices die, so a
  # guest killed while its daemon is up can come straight back.
  for home in "$A" "$B" "$C"; do
    kill_pidfile "$home/astd.pid"
  done
  # Then what they left running. Both outlive astd by design.
  for home in "$A" "$B" "$C"; do
    for f in "$home"/instances/*/qemu.pid; do kill_pidfile "$f"; done
    for f in "$home"/volumes/*/nbd-e*.pid; do kill_pidfile "$f"; done
    # A backend that keeps its guest's pid on the handle rather than in a
    # pidfile of its own — the vz helper on macOS — is written down in the
    # registry instead. Every pid in that file was put there by a daemon
    # this run started, so it is the same exact-pid rule by another route.
    for pid in $(grep -o '"pid":[0-9]*' "$home/state.json" 2>/dev/null | cut -d: -f2 || true); do
      kill_pid "$pid"
    done
  done
  rm -rf "$RUN"
}
trap cleanup EXIT

fail() {
  echo "MOVE E2E FAIL: $*" >&2
  for home in "$A" "$B" "$C"; do
    [ -f "$home/astd.log" ] || continue
    echo "--- tail of $home/astd.log ---" >&2
    tail -30 "$home/astd.log" >&2
  done
  exit 1
}

# expect <desc> <needle> <cmd...>: run cmd, require success AND the needle.
expect() {
  local desc="$1" needle="$2"; shift 2
  local out
  out="$("$@" 2>&1)" || fail "$desc: command failed:"$'\n'"$out"
  grep -qF "$needle" <<<"$out" || fail "$desc: expected \"$needle\" in:"$'\n'"$out"
  echo "ok: $desc"
}

# refute <desc> <needle> <cmd...>: the command must FAIL, and say why.
refute() {
  local desc="$1" needle="$2"; shift 2
  local out
  if out="$("$@" 2>&1)"; then
    fail "$desc: command unexpectedly succeeded:"$'\n'"$out"
  fi
  grep -qF "$needle" <<<"$out" || fail "$desc: expected \"$needle\" in:"$'\n'"$out"
  echo "ok: $desc"
}

# file_size <path>: what the file claims to be, in bytes.
#
# stat(1) is one of the places BSD and GNU never agreed, and this script runs
# on both: macOS asks with -f, Linux with -c. Which one is in front of us is
# asked rather than guessed from `uname`, so a mac with coreutils on its PATH
# answers correctly too. Never as `bsd || gnu`, though: GNU stat reads a -f
# format as a filename, prints filesystem status for the real path to stdout,
# and only then fails — and that junk would land in the answer. Trying it into
# a variable keeps it out.
file_size() {
  local size
  if size="$(stat -f %z "$1" 2>/dev/null)"; then
    echo "$size"
  else
    stat -c %s "$1"
  fi
}

# allocated_bytes <path>: what it actually occupies, holes excluded. This is
# the number the sparse assertions turn on, so it is bytes on both platforms
# rather than each stat's own unit.
allocated_bytes() {
  local blocks unit
  if blocks="$(stat -f %b "$1" 2>/dev/null)"; then
    # BSD reports st_blocks in 512-byte units, always.
    echo "$((blocks * 512))"
  else
    # GNU counts in a unit of its own choosing and %B is which one.
    blocks="$(stat -c %b "$1")" || return 1
    unit="$(stat -c %B "$1")" || return 1
    echo "$((blocks * unit))"
  fi
}

# The log is appended to rather than replaced, so a daemon that is restarted
# leaves its predecessor's lines in it. That makes "has it come up?" a question
# about a *new* line, not about any line — a distinction this script depends on
# twice, because it asserts on what a restarted daemon did on its way up.
start_daemon() {
  local home="$1"
  mkdir -p "$home"
  local before now
  before="$(grep -c "on the mesh as" "$home/astd.log" 2>/dev/null || true)"
  ( ASTERISM_HOME="$home" ASTERISM_MESH=local "$ASTD" >>"$home/astd.log" 2>&1 & )
  for _ in $(seq 1 100); do
    now="$(grep -c "on the mesh as" "$home/astd.log" 2>/dev/null || true)"
    [ "${now:-0}" -gt "${before:-0}" ] && return 0
    sleep 0.2
  done
  fail "astd for $home did not come up:"$'\n'"$(cat "$home/astd.log" 2>/dev/null)"
}

stop_daemon() {
  local home="$1" signal="${2:--TERM}"
  local pid
  pid="$(cat "$home/astd.pid" 2>/dev/null || true)"
  [ -n "$pid" ] || fail "no pid file for the daemon in $home"
  kill "$signal" "$pid" 2>/dev/null || true
  for _ in $(seq 1 50); do
    kill -0 "$pid" 2>/dev/null || return 0
    sleep 0.2
  done
  kill -KILL "$pid" 2>/dev/null || true
}

mkdir -p "$A" "$B" "$C" "$VOL"
echo "$MARKER" > "$VOL/VOLUME.txt"
start_daemon "$A"
start_daemon "$B"

# ---- 1. pair A and B -------------------------------------------------------

ASTERISM_HOME="$A" "$AST" device invite --name "$A_NAME" --yes >"$A/invite.out" 2>&1 &
INVITE_PID=$!
TICKET=""
for _ in $(seq 1 100); do
  TICKET="$(grep -o 'astdev1[a-z0-9]*' "$A/invite.out" 2>/dev/null | head -1 || true)"
  [ -n "$TICKET" ] && break
  sleep 0.2
done
[ -n "$TICKET" ] || fail "no ticket printed:"$'\n'"$(cat "$A/invite.out")"
ASTERISM_HOME="$B" "$AST" device add "$TICKET" --name "$B_NAME" --yes >"$B/add.out" 2>&1 \
  || fail "ast device add failed:"$'\n'"$(cat "$B/add.out")"
wait "$INVITE_PID" || fail "ast device invite failed:"$'\n'"$(cat "$A/invite.out")"
echo "ok: A and B are one orbit"

# ---- 2. a real guest on A, with a marker in it -----------------------------
#
# Only A gets the image store. B will have to get the base from A.

mkdir -p "$A/images"
cp "$HOME/.asterism/images/"*.qcow2 "$A/images/" 2>/dev/null || true
ASTERISM_HOME="$A" "$AST" pull "$IMAGE" >/dev/null 2>&1 \
  || fail "no $IMAGE image available for A (pull it once: ast pull $IMAGE)"
[ -z "$(ls "$B/images" 2>/dev/null || true)" ] \
  || fail "B's image store is not empty, so the peer fetch proves nothing"

expect "create on A" "$INST  defined" \
  env ASTERISM_HOME="$A" "$AST" create "$INST" --image "$IMAGE" --mem 2G --disk 10G
# A directory share: same-device by construction, so the move has to keep the
# row and flag it rather than drop it.
expect "attach a directory volume" "/mnt/ast/mv-vol" \
  env ASTERISM_HOME="$A" "$AST" attach "$INST" --volume "$VOL"
expect "up on A" "$INST  running" env ASTERISM_HOME="$A" "$AST" up "$INST"

marker_written=
for _ in $(seq 1 30); do
  if ASTERISM_HOME="$A" "$AST" ssh "$INST" -- \
       "echo $MARKER | sudo tee /var/lib/asterism-marker >/dev/null && sync" >/dev/null 2>&1; then
    marker_written=1; break
  fi
  sleep 3
done
[ -n "$marker_written" ] || fail "could not write a marker in the guest on A"
expect "the marker is in the guest on A" "$MARKER" \
  env ASTERISM_HOME="$A" "$AST" ssh "$INST" -- "cat /var/lib/asterism-marker"

expect "down on A" "$INST  stopped" env ASTERISM_HOME="$A" "$AST" down "$INST"
expect "snapshot on A" "$INST  snapshot clean" \
  env ASTERISM_HOME="$A" "$AST" snapshot "$INST" clean

DISK_A="$A/instances/$INST/disk.raw"
[ -f "$DISK_A" ] || fail "no root disk at $DISK_A"
VIRTUAL="$(file_size "$DISK_A")"
echo "ok: A's root disk claims $VIRTUAL bytes"

# A provenance record only speaks for the bytes that were actually adopted.
# Exercise the public move command with a same-length replacement and prove
# the refusal happens before either source fencing or target staging. The
# first two bytes are saved and restored so the happy-path move below still
# uses the image this test pulled.
BASE_A="$(ls "$A/images/"*.raw 2>/dev/null | head -1)"
[ -n "$BASE_A" ] || fail "A has no adopted raw base image to mutate"
BASE_PREFIX="$RUN/base-prefix"
MUTATED_PREFIX="$RUN/mutated-prefix"
dd if="$BASE_A" of="$BASE_PREFIX" bs=1 count=2 >/dev/null 2>&1
printf 'XX' | dd of="$BASE_A" bs=1 count=2 conv=notrunc >/dev/null 2>&1
dd if="$BASE_A" of="$MUTATED_PREFIX" bs=1 count=2 >/dev/null 2>&1
if cmp -s "$BASE_PREFIX" "$MUTATED_PREFIX"; then
  printf 'YY' | dd of="$BASE_A" bs=1 count=2 conv=notrunc >/dev/null 2>&1
fi
cp "$A/state.json" "$RUN/state-before-mutated-move.json"
refute "a move refuses a mutated adopted source" "has changed since it was pulled" \
  env ASTERISM_HOME="$A" "$AST" move "$INST" "$B_NAME"
cmp -s "$A/state.json" "$RUN/state-before-mutated-move.json" \
  || fail "the refused move fenced or otherwise changed A's source row"
[ -z "$(ls "$B/instances" 2>/dev/null || true)" ] \
  || fail "the refused move staged an instance directory on B"
[ -z "$(ls "$B/images" 2>/dev/null || true)" ] \
  || fail "the refused move changed B's image store"
dd if="$BASE_PREFIX" of="$BASE_A" bs=1 count=2 conv=notrunc >/dev/null 2>&1
echo "ok: a mutated source is refused before either device is changed"

# ---- 3. the move -----------------------------------------------------------

MOVE_OUT="$RUN/move.out"
ASTERISM_HOME="$A" "$AST" move "$INST" "$B_NAME" >"$MOVE_OUT" 2>&1 \
  || fail "ast move failed:"$'\n'"$(cat "$MOVE_OUT")"
cat "$MOVE_OUT"

# The base image is fetched from the orbit peer that has it, not the internet.
grep -qF "fetching base image $IMAGE" "$MOVE_OUT" \
  || fail "B did not fetch the base image at all:"$'\n'"$(cat "$MOVE_OUT")"
grep -qF "from $A_NAME" "$MOVE_OUT" \
  || fail "the base image did not come from A:"$'\n'"$(cat "$MOVE_OUT")"
grep -qF "not the internet" "$MOVE_OUT" \
  || fail "the peer fetch is not stated as one:"$'\n'"$(cat "$MOVE_OUT")"
grep -qF "base image $IMAGE verified and stored" "$MOVE_OUT" \
  || fail "the fetched base was never verified:"$'\n'"$(cat "$MOVE_OUT")"
echo "ok: B pulled the base image from A over the mesh and verified it"

# Verified is not the same as adopted. Every boot input has to carry a
# provenance record, and the peer fetch is the one adoption path that used to
# write none — leaving an image that passed its digest on arrival and refused
# to boot a second later.
BASE_B="$(ls "$B/images/"*.raw 2>/dev/null | head -1)"
[ -n "$BASE_B" ] || fail "B has no base image after the fetch:"$'\n'"$(ls -la "$B/images" 2>&1)"
[ -f "$BASE_B.provenance" ] \
  || fail "the fetched base has no provenance record, so it cannot be booted from"
grep -q "^kind base-image$" "$BASE_B.provenance" \
  || fail "the fetched base's record does not say what it is:"$'\n'"$(cat "$BASE_B.provenance")"
grep -q "^derived-from " "$BASE_B.provenance" \
  || fail "the record names no parent, so the pin on $IMAGE cannot be answered:"$'\n'"$(cat "$BASE_B.provenance")"
echo "ok: the fetched base carries a provenance record naming what it came from"

# Progress, not a cursor: bytes have to be reported while they move.
PROGRESS="$(grep -c " moved$" "$MOVE_OUT" || true)"
[ "$PROGRESS" -ge 2 ] \
  || fail "only $PROGRESS progress line(s) for a multi-gigabyte move:"$'\n'"$(cat "$MOVE_OUT")"
grep -qE "^disk\.raw: .* carried$" "$MOVE_OUT" \
  || fail "the root disk's cost was never reported:"$'\n'"$(cat "$MOVE_OUT")"
grep -qF "snapshots/clean.raw" "$MOVE_OUT" \
  || fail "the snapshot did not travel:"$'\n'"$(cat "$MOVE_OUT")"
echo "ok: the move reported $PROGRESS progress lines as the bytes went"

# Sparse efficiency: the wire carried the allocated ranges, not the file.
ALLOCATED="$(sed -n 's/.*\[allocated=\([0-9]*\) virtual=\([0-9]*\)\].*/\1/p' "$MOVE_OUT" | head -1)"
CLAIMED="$(sed -n 's/.*\[allocated=\([0-9]*\) virtual=\([0-9]*\)\].*/\2/p' "$MOVE_OUT" | head -1)"
[ -n "$ALLOCATED" ] && [ -n "$CLAIMED" ] \
  || fail "the move never reported its byte counts:"$'\n'"$(cat "$MOVE_OUT")"
[ "$CLAIMED" -gt "$VIRTUAL" ] || [ "$CLAIMED" -eq "$VIRTUAL" ] \
  || fail "the manifest claims $CLAIMED bytes and the disk alone is $VIRTUAL"
# Well under half: a fresh 10 GiB Debian instance holds a small fraction of it.
[ "$((ALLOCATED * 2))" -lt "$CLAIMED" ] \
  || fail "moved $ALLOCATED of $CLAIMED bytes — the sparse walk bought nothing"
echo "ok: sparse transfer moved $ALLOCATED bytes of $CLAIMED claimed ($((ALLOCATED * 100 / CLAIMED))%)"

# ...and the disk landed sparse on B too, rather than being filled in.
DISK_B="$B/instances/$INST/disk.raw"
[ -f "$DISK_B" ] || fail "no root disk on B at $DISK_B"
B_SIZE="$(file_size "$DISK_B")"
B_BLOCKS="$(allocated_bytes "$DISK_B")"
[ "$B_SIZE" = "$VIRTUAL" ] || fail "B's disk is $B_SIZE bytes and A's was $VIRTUAL"
[ "$((B_BLOCKS * 2))" -lt "$B_SIZE" ] \
  || fail "B's disk occupies $B_BLOCKS of $B_SIZE bytes — the holes did not survive"
echo "ok: B's disk is $B_SIZE bytes long and occupies $B_BLOCKS — still a sparse file"

# ---- 4. the orbit agrees, and A has let go ---------------------------------

LS="$(ASTERISM_HOME="$A" "$AST" ls 2>&1)" || fail "ast ls failed:"$'\n'"$LS"
grep -qE "^$INST +stopped .*$B_NAME" <<<"$LS" \
  || fail "ast ls does not show $INST with its cpu on B:"$'\n'"$LS"
[ "$(grep -c "^$INST " <<<"$LS")" = "1" ] \
  || fail "$INST appears more than once — a move left two rows:"$'\n'"$LS"
echo "ok: ast ls shows one row for $INST, cpu on $B_NAME"

[ ! -d "$A/instances/$INST" ] \
  || fail "A still has $A/instances/$INST — the source did not drop its copy"
ASTERISM_HOME="$A" "$AST" ls --local 2>&1 | grep -qF "no instances" \
  || fail "A's shard still holds a row for $INST"
echo "ok: A's copy and A's row are both gone"

# Asked directly, the old device says where it went rather than "no such
# instance", which would be true of that shard and useless to a human. Asked
# from B, because a device does not list itself among its peers.
refute "A says where it went if asked directly" "moved to $B_NAME" \
  env ASTERISM_HOME="$B" "$AST" --device "$A_NAME" status "$INST"

# The move epoch is on the row that landed.
expect "the row carries a move epoch" "moves:   1" \
  env ASTERISM_HOME="$A" "$AST" status "$INST"

# The directory share is same-device only, so it is flagged rather than
# dropped: the row still says what the user asked for.
STATUS="$(ASTERISM_HOME="$A" "$AST" status "$INST" 2>&1)"
grep -qF "$VOL" <<<"$STATUS" || fail "the volume row was dropped by the move:"$'\n'"$STATUS"
grep -qF "stranded by the cpu move" <<<"$STATUS" \
  || fail "the stranded volume is not flagged:"$'\n'"$STATUS"
echo "ok: the 9p volume survived as a row and is flagged in status"

# ---- 5. it boots on B, and the guest is the same guest ---------------------

# The seed travelled rather than being rebuilt, so the key that opens this
# guest is still A's. `ast ssh` has to know that, or the move produces a guest
# nobody can get into.
expect "status names the device whose key opens the guest" "seed:    built on $A_NAME" \
  env ASTERISM_HOME="$A" "$AST" status "$INST"

expect "up through the orbit boots it on B" "$INST  running" \
  env ASTERISM_HOME="$A" "$AST" up "$INST"
# Typed on A, about a guest whose cpu is on B, reached over the ssh splice.
expect "the marker survived the move" "$MARKER" \
  env ASTERISM_HOME="$A" "$AST" ssh "$INST" -- "cat /var/lib/asterism-marker"
echo "ok: the guest that booted on B is the guest that was written to on A"

# ---- 6. the snapshots came along, and restoring one works on B -------------

expect "the snapshot is listed on B" "clean" \
  env ASTERISM_HOME="$A" "$AST" snapshots "$INST"

ASTERISM_HOME="$A" "$AST" ssh "$INST" -- \
  "echo $POST | sudo tee /var/lib/asterism-post >/dev/null && sync" >/dev/null 2>&1 \
  || fail "could not write a second marker on B"
expect "down on B" "$INST  stopped" env ASTERISM_HOME="$A" "$AST" down "$INST"
expect "restore on B" "restored to clean" \
  env ASTERISM_HOME="$A" "$AST" restore "$INST" clean
expect "up after the restore" "$INST  running" env ASTERISM_HOME="$A" "$AST" up "$INST"
expect "the snapshot still has the first marker" "$MARKER" \
  env ASTERISM_HOME="$A" "$AST" ssh "$INST" -- "cat /var/lib/asterism-marker"
if ASTERISM_HOME="$A" "$AST" ssh "$INST" -- "cat /var/lib/asterism-post" >/dev/null 2>&1; then
  fail "the restore did not roll back — the post-move marker is still there"
fi
echo "ok: a snapshot taken on A restores on B and really rolls the disk back"
expect "down again" "$INST  stopped" env ASTERISM_HOME="$A" "$AST" down "$INST"

# ---- 7. the refusals, and --down -------------------------------------------
#
# A small instance that is never really booted: what is under test here is the
# preflight and the shutdown, and neither needs a distro.

DISK="$A/tiny.qcow2"
qemu-img create -f qcow2 "$DISK" 1M >/dev/null 2>&1 \
  || fail "qemu-img create failed (is qemu installed?)"
expect "create a small instance on A" "$FAIL  defined" \
  env ASTERISM_HOME="$A" "$AST" create "$FAIL" --image "$DISK" --mem 512M --disk 1G

refute "moving to the device that already supplies it is refused" "already sources" \
  env ASTERISM_HOME="$A" "$AST" move "$FAIL" "$A_NAME"
refute "moving to a device nobody has heard of is refused" "no device named" \
  env ASTERISM_HOME="$A" "$AST" move "$FAIL" nowhere
refute "moving something that is not in the orbit is refused" "no instance named" \
  env ASTERISM_HOME="$A" "$AST" move ghost "$B_NAME"
refute "there is only one part to set today" "there is no \"gpu\" part to set" \
  env ASTERISM_HOME="$A" "$AST" set "$FAIL" gpu "$B_NAME"

# A running instance is refused without --down, because offline is the only
# kind of move that works on every backend Asterism has.
expect "boot the small instance" "$FAIL  running" env ASTERISM_HOME="$A" "$AST" up "$FAIL"
refute "a running instance will not be moved silently" "pass --down" \
  env ASTERISM_HOME="$A" "$AST" move "$FAIL" "$B_NAME"

DOWN_OUT="$RUN/down.out"
ASTERISM_HOME="$A" "$AST" move "$FAIL" "$B_NAME" --down >"$DOWN_OUT" 2>&1 \
  || fail "ast move --down failed:"$'\n'"$(cat "$DOWN_OUT")"
grep -qF "shutting $FAIL down on $A_NAME first" "$DOWN_OUT" \
  || fail "--down did not shut the guest down:"$'\n'"$(cat "$DOWN_OUT")"
LS="$(ASTERISM_HOME="$A" "$AST" ls 2>&1)"
grep -qE "^$FAIL +stopped .*$B_NAME" <<<"$LS" \
  || fail "--down did not finish the move:"$'\n'"$LS"
echo "ok: --down stops the guest and completes the move"

# It needed no base image: B fetched that once and content addressing did the
# rest — including for an image that is a plain file on both devices.
if grep -qF "fetching base image" "$DOWN_OUT"; then
  fail "B fetched a base image it already had:"$'\n'"$(cat "$DOWN_OUT")"
fi
echo "ok: the second move carried no base image"

# ---- 8. a move to a device that is not answering ---------------------------
#
# A third device, paired and then shut down. Deliberately not "stop B and
# start it again": under ASTERISM_MESH=local a daemon binds an ephemeral port,
# so a restarted peer is at an address its orbit no longer knows — which would
# make the rest of this script test the wrong thing.

start_daemon "$C"
ASTERISM_HOME="$A" "$AST" device invite --name "$A_NAME" --yes >"$A/invite-c.out" 2>&1 &
INVITE_PID=$!
TICKET=""
for _ in $(seq 1 100); do
  TICKET="$(grep -o 'astdev1[a-z0-9]*' "$A/invite-c.out" 2>/dev/null | head -1 || true)"
  [ -n "$TICKET" ] && break
  sleep 0.2
done
[ -n "$TICKET" ] || fail "no ticket for C:"$'\n'"$(cat "$A/invite-c.out")"
ASTERISM_HOME="$C" "$AST" device add "$TICKET" --name "$C_NAME" --yes >"$C/add.out" 2>&1 \
  || fail "C could not join:"$'\n'"$(cat "$C/add.out")"
wait "$INVITE_PID" || fail "the invite to C failed:"$'\n'"$(cat "$A/invite-c.out")"
stop_daemon "$C"
echo "ok: C is in the orbit and its daemon is down"

# The instance that will not move — and, in section 9, the one whose move is
# interrupted. Snapshotting materialises its root disk exactly as `ast up`
# would, without spending a boot on it.
expect "create the instance that will not move" "$KILL  defined" \
  env ASTERISM_HOME="$A" "$AST" create "$KILL" --image "$IMAGE" --mem 2G --disk 10G
expect "materialise its disk" "$KILL  snapshot base" \
  env ASTERISM_HOME="$A" "$AST" snapshot "$KILL" base

refute "a move to a device that is not answering fails cleanly" "is not answering" \
  env ASTERISM_HOME="$A" "$AST" move "$KILL" "$C_NAME"

LOCAL="$(ASTERISM_HOME="$A" "$AST" ls --local 2>&1)"
grep -qE "^$KILL +defined" <<<"$LOCAL" \
  || fail "A did not keep $KILL as its own after the refused move:"$'\n'"$LOCAL"
if grep -qF "moving" <<<"$LOCAL"; then
  fail "the refused move left a fence on A:"$'\n'"$LOCAL"
fi
[ ! -e "$C/instances/$KILL" ] || fail "C staged something for a move that never started"
echo "ok: A is still authoritative and nothing was fenced"

# ---- 9. the target dies mid-transfer ---------------------------------------
#
# The rule a half-move exists to protect: never two bootable copies. The
# target writes into a staging directory that no instance could be named, and
# it becomes an instance only at the commit. Kill the target before that and
# the source is still the only place this instance can boot.

KILL_OUT="$RUN/kill.out"
# `set -e` is inherited by the subshell, so the verdict is recorded with an
# `if` rather than with `$?` — otherwise the failing move takes the subshell
# with it and the exit status is never written down.
(
  if ASTERISM_HOME="$A" "$AST" move "$KILL" "$B_NAME" >"$KILL_OUT" 2>&1; then
    echo moved
  else
    echo refused
  fi > "$RUN/kill.rc"
) &
MOVE_PID=$!

# Wait for real bytes to be on the far side, then pull the plug on it.
staged=
for _ in $(seq 1 600); do
  disk="$(ls "$B"/instances/"$KILL".moving-*/disk.raw 2>/dev/null | head -1 || true)"
  # A disk that cannot be measured yet has not been staged yet: the file is
  # appearing under this loop, so "no answer" is 0 and not a failure.
  if [ -n "$disk" ] \
    && [ "$(allocated_bytes "$disk" 2>/dev/null || echo 0)" -gt $((16 * 1024 * 1024)) ]; then
    staged="$disk"; break
  fi
  sleep 0.2
done
[ -n "$staged" ] || fail "the transfer never got as far as staging bytes on B:"$'\n'"$(cat "$KILL_OUT" 2>/dev/null)"
STAGED_DIR="$(dirname "$staged")"
echo "ok: B is staging $KILL at $STAGED_DIR"
stop_daemon "$B" -KILL
wait "$MOVE_PID" || true
[ "$(cat "$RUN/kill.rc")" = "refused" ] \
  || fail "the move reported success although its target was killed:"$'\n'"$(cat "$KILL_OUT")"
grep -qF "still supplies $KILL's cpu" "$KILL_OUT" \
  || fail "the failed move did not say who still has it:"$'\n'"$(cat "$KILL_OUT")"
echo "ok: the interrupted move failed and named A as the instance's cpu source"

# B has no bootable copy: no instance directory, no row.
[ ! -d "$B/instances/$KILL" ] \
  || fail "B has a bootable copy of $KILL after a killed transfer"
# ...and A is unfenced and still bootable, which is the whole point.
LOCAL="$(ASTERISM_HOME="$A" "$AST" ls --local 2>&1)"
grep -qE "^$KILL +defined" <<<"$LOCAL" \
  || fail "A lost $KILL to an interrupted move:"$'\n'"$LOCAL"
if grep -qF "moving" <<<"$LOCAL"; then
  fail "the interrupted move left a fence on A:"$'\n'"$LOCAL"
fi
expect "A can still boot the instance whose move was interrupted" "$KILL  running" \
  env ASTERISM_HOME="$A" "$AST" up "$KILL"
expect "the guest on A is real" "Linux" \
  env ASTERISM_HOME="$A" "$AST" ssh "$KILL" -- "uname -s"
expect "stop it" "$KILL  stopped" env ASTERISM_HOME="$A" "$AST" down "$KILL"

# The staging directory is swept on B's next start, and B says so. The sweep
# runs before the socket is bound and before the mesh comes up, so a daemon
# that is answering has already done it — no polling here on purpose.
[ -d "$STAGED_DIR" ] || fail "the killed daemon's staging directory vanished before its restart"
start_daemon "$B"
[ ! -d "$STAGED_DIR" ] \
  || fail "B did not sweep $STAGED_DIR when it came back"
grep -qF "swept" "$B/astd.log" || fail "B swept nothing and said nothing:"$'\n'"$(tail -20 "$B/astd.log")"
echo "ok: B swept the staging directory on its next start and said so"

# And A's own shard has exactly one row for the interrupted instance.
LOCAL="$(ASTERISM_HOME="$A" "$AST" ls --local 2>&1)"
[ "$(grep -c "^$KILL " <<<"$LOCAL")" = "1" ] \
  || fail "$KILL appears more than once after an interrupted move:"$'\n'"$LOCAL"
echo "ok: A holds one $KILL and B holds none"

echo "MOVE E2E GREEN ($IMAGE)"
