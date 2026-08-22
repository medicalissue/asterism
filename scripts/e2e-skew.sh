#!/usr/bin/env bash
# End-to-end for version skew: two vintages of Asterism in the same room, and
# what each of them does about the other.
#
# Everything an upgrade can be caught in the middle of, with real daemons and
# real signals:
#
#   1. the whole compatibility matrix, generated from `ast compat --json` and
#      walked row by row. For every protocol a daemon might claim: an OLDER
#      one is replaced and the command then works, one in the window is spoken
#      to and left running, and a NEWER one is refused in words and is still
#      alive afterwards — which is the case an older `ast` used to get wrong
#      by SIGTERMing it and taking its place
#   2. a daemon inside the window that has never heard of a command refuses it
#      by name, and is upgraded at that point and not before
#   3. a home written by a newer Asterism refuses an older daemon BEFORE
#      anything in it is read or changed, and before the socket is bound
#   4. a pre-envelope shard migrates on read and leaves the shape it was in at
#      `.bak`, byte for byte — and a torn shard then comes back from that copy
#   5. a pairing across a skew is refused while a human is still watching and
#      before either device is written to an orbit store — and two devices
#      already paired, one of which is then upgraded, report a version skew
#      rather than reading as a device that has been switched off
#   6. a daemon replaced under a live guest leaves the guest running, and the
#      replacement adopts it
#   7. two successive builds of this tree — the previous release from git, and
#      the working tree — upgrade one into the other without losing an
#      instance or the guest running on it
#
# 6 and 7 boot a real guest and are skipped, loudly, when there is no image or
# no previous ref to build. 1 through 5 need neither and run everywhere.
#
# The matrix in 1 is not written down here. It is printed by the build under
# test, from the same table the negotiation itself reads, so a row added to
# `asterism_core::compat` is a row this script walks on the next commit and a
# row removed stops being asserted. A matrix transcribed beside the code is a
# matrix that is wrong by the second release.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export PATH="$HOME/.cargo/bin:$PATH"
cd "$ROOT"
cargo build -q

# Fresh, SHORT home: unix socket paths are capped near 104 bytes, and this
# script makes one home per matrix row underneath it.
export ASTERISM_HOME="/private/tmp/ast-skew-$$"

# A skew test has no orbit business on the internet: both daemons in step 5
# are on this machine's loopback.
export ASTERISM_MESH=local

# Never exported. Setting it for this shell would set it for `ast` and `astd`
# alike, and the whole point is to run the two at different numbers.
SEAM=ASTERISM_PROTOCOL_VERSION

BIN="$ASTERISM_HOME/bin"
AST="$BIN/ast"
ASTD="$BIN/astd"
IMAGE="${E2E_IMAGE:-debian:13}"
# The previous release to upgrade from, for step 7. Anything `git archive`
# accepts.
OLD_REF="${SKEW_OLD_REF:-origin/main}"

SKIPPED=()
# Rows step 1 cannot walk with a binary from this tree, and which step 7
# covers with a real one. Reported as covered if step 7 runs, and as skipped
# if it does not — a row that nothing walked must not read as a row that
# passed.
DEFERRED=()
STEP7_RAN=

fail() { echo "E2E FAIL: $*" >&2; exit 1; }
ok() { echo "ok: $*"; }
skip() { echo "SKIP: $*"; SKIPPED+=("$*"); }
defer() { echo "DEFERRED: $*"; DEFERRED+=("$*"); }

cleanup() {
  # Only ever our own processes: every one of them names this home on its
  # command line or was started with it in the environment.
  pkill -9 -f "$ASTERISM_HOME" 2>/dev/null || true
  if [ -n "${KEEP:-}" ]; then
    echo "kept $ASTERISM_HOME for inspection"
  else
    rm -rf "$ASTERISM_HOME"
  fi
  return 0
}
trap cleanup EXIT

mkdir -p "$BIN"
# Copied rather than run from target/: a sibling checkout's `pkill -f
# target/debug/astd` must not be able to kill this test's daemon.
cp "$ROOT/target/debug/ast" "$ROOT/target/debug/astd" "$BIN/"

# ---- the primitives --------------------------------------------------------

# Start a daemon on `home`, optionally claiming a protocol. Echoes its pid.
#
# Started here rather than by the CLI, because `ast` spawns a daemon with its
# output on /dev/null and half of what this script asserts is in that output.
start_astd() {
  local home="$1" protocol="${2:-}" astd="${3:-$ASTD}"
  local pid
  if [ -n "$protocol" ]; then
    ASTERISM_HOME="$home" env "$SEAM=$protocol" "$astd" >>"$home/astd.log" 2>&1 &
  else
    ASTERISM_HOME="$home" "$astd" >>"$home/astd.log" 2>&1 &
  fi
  pid=$!
  for _ in $(seq 1 100); do
    if [ "$(cat "$home/astd.pid" 2>/dev/null || true)" = "$pid" ]; then
      echo "$pid"
      return 0
    fi
    kill -0 "$pid" 2>/dev/null || break
    sleep 0.2
  done
  fail "astd did not come up on $home:"$'\n'"$(tail -20 "$home/astd.log" 2>/dev/null)"
}

# A daemon that is *meant* to refuse to start. Bounded, so a daemon that
# wrongly comes up is a failure rather than a hang.
start_astd_expecting_refusal() {
  local home="$1" protocol="${2:-}" out="${3:-$1/refusal.txt}"
  if [ -n "$protocol" ]; then
    ASTERISM_HOME="$home" env "$SEAM=$protocol" "$ASTD" >"$out" 2>&1 &
  else
    ASTERISM_HOME="$home" "$ASTD" >"$out" 2>&1 &
  fi
  local pid=$!
  for _ in $(seq 1 100); do
    if ! kill -0 "$pid" 2>/dev/null; then
      wait "$pid" 2>/dev/null && fail "astd started when it should have refused"
      return 0
    fi
    sleep 0.2
  done
  kill -9 "$pid" 2>/dev/null || true
  fail "astd neither started nor refused within 20s on $home"
}

# Which process is serving a home's socket, by the same evidence `ast` uses:
# a unix socket path has exactly one listener.
serving_pid() {
  lsof -t -- "$1/astd.sock" 2>/dev/null | head -1
}

# `ast`, on a home, optionally claiming a protocol.
run_ast() {
  local home="$1" protocol="$2"; shift 2
  if [ -n "$protocol" ]; then
    ASTERISM_HOME="$home" env "$SEAM=$protocol" "$AST" "$@" 2>&1
  else
    ASTERISM_HOME="$home" "$AST" "$@" 2>&1
  fi
}

json() { python3 -c "$@"; }

# One image cache for the whole run, shared into each home by hard link.
#
# Copying would be the obvious spelling and does not fit on a laptop: this
# script makes a home per step, a base image is a few hundred megabytes as
# qcow2 and about two gigabytes once converted, and four homes of that is
# eight gigabytes of the same bytes. A hard link costs an inode. The base
# image is written once and read forever after — `image.rs` skips a
# conversion whose output is already there — so sharing the inode is sharing
# something nothing writes to.
IMG_CACHE="$ASTERISM_HOME/images-cache"
mkdir -p "$IMG_CACHE"
if [ -d "$HOME/.asterism/images" ]; then
  cp "$HOME/.asterism/images/"*.qcow2 "$HOME/.asterism/images/"*.raw \
     "$IMG_CACHE/" 2>/dev/null || true
fi

seed_images() {
  mkdir -p "$1/images"
  ln "$IMG_CACHE"/* "$1/images/" 2>/dev/null || true
}

# Keep whatever that home converted, so the next home links it instead of
# spending the same minutes and the same two gigabytes again.
harvest_images() {
  ln "$1/images"/*.raw "$IMG_CACHE/" 2>/dev/null || true
}

# Free a home once its step has finished asserting. The hard links go with it;
# the cache keeps the inode.
release_home() {
  harvest_images "$1"
  rm -rf "$1"
}

# Whether this machine can define an instance without going to the network.
have_image() {
  ls "$1/images/"* >/dev/null 2>&1
}

# Every file in a home, and what is in it. The evidence for "nothing was read
# or changed" — which is a claim about the whole directory, not about the one
# file a test happened to think of.
fingerprint() {
  ( cd "$1" && find . -type f | sort | xargs shasum 2>/dev/null )
}

# A guest's pid, as the daemon supervising it reports — not as a command line
# this script would otherwise have to know the shape of.
guest_pid() {
  run_ast "$1" "$2" status dev 2>/dev/null \
    | sed -n 's/^running: .* pid \([0-9]*\),.*/\1/p'
}

echo "=== 1. the generated compatibility matrix ==================================="

MATRIX="$ASTERISM_HOME/matrix.json"
ASTERISM_HOME="$ASTERISM_HOME" "$AST" compat --json >"$MATRIX" \
  || fail "ast compat --json failed:"$'\n'"$(cat "$MATRIX")"
# Removed straight away: `ast compat` reads the home but must not leave this
# one stamped, or row 5's fresh-home assertions start from a stamped home.
rm -f "$ASTERISM_HOME/home.json" "$ASTERISM_HOME/home.json.bak"

OURS="$(json "import json;print(json.load(open('$MATRIX'))['protocol'])")"
[ -n "$OURS" ] || fail "ast compat --json printed no protocol"
ok "this build speaks protocol $OURS"

ROWS="$(json "
import json
for row in json.load(open('$MATRIX'))['matrix']:
    claim = row['peer_protocol']
    print('null' if claim is None else claim, row['verdict'], row['daemon_action'])
")"
[ -n "$ROWS" ] || fail "the generated matrix is empty"

ROW_N=0
while read -r CLAIM VERDICT ACTION; do
  ROW_N=$((ROW_N + 1))
  HOME_DIR="$ASTERISM_HOME/row-$ROW_N"
  mkdir -p "$HOME_DIR"

  if [ "$CLAIM" = "null" ]; then
    # No build in this tree can claim nothing — every one of them sends a
    # protocol. The only thing that can is a binary from before the field
    # existed, which is step 7's business.
    defer "matrix row '$VERDICT': no binary in this tree claims nothing — step 7 builds one that does"
    continue
  fi

  BEFORE="$(start_astd "$HOME_DIR" "$CLAIM")"
  [ "$(serving_pid "$HOME_DIR")" = "$BEFORE" ] \
    || fail "row $CLAIM: the daemon this test started is not the one on the socket"

  OUT="$(run_ast "$HOME_DIR" "" ls || true)"
  AFTER="$(serving_pid "$HOME_DIR")"

  case "$ACTION" in
    speak)
      grep -qE "no instances|NAME" <<<"$OUT" \
        || fail "row $CLAIM ($VERDICT): ast ls did not answer:"$'\n'"$OUT"
      [ "$AFTER" = "$BEFORE" ] \
        || fail "row $CLAIM ($VERDICT): the daemon was replaced when it should have been spoken to"
      ok "protocol $CLAIM: spoken to, and left running as pid $BEFORE"
      ;;
    replace)
      grep -qE "no instances|NAME" <<<"$OUT" \
        || fail "row $CLAIM ($VERDICT): ast ls did not answer after the restart:"$'\n'"$OUT"
      [ -n "$AFTER" ] && [ "$AFTER" != "$BEFORE" ] \
        || fail "row $CLAIM ($VERDICT): the daemon was not replaced (still pid $BEFORE)"
      kill -0 "$BEFORE" 2>/dev/null \
        && fail "row $CLAIM ($VERDICT): the old daemon is still alive after being retired"
      grep -qF "restarting the daemon" <<<"$OUT" \
        || fail "row $CLAIM ($VERDICT): the restart was silent:"$'\n'"$OUT"
      ok "protocol $CLAIM: replaced, said so, and the command then worked"
      ;;
    refuse)
      grep -qF "protocol $CLAIM" <<<"$OUT" \
        || fail "row $CLAIM ($VERDICT): the refusal did not name the protocol:"$'\n'"$OUT"
      grep -qF "upgrade this Asterism" <<<"$OUT" \
        || fail "row $CLAIM ($VERDICT): the refusal did not say what to do:"$'\n'"$OUT"
      # The claim this whole module exists for.
      [ "$AFTER" = "$BEFORE" ] \
        || fail "row $CLAIM ($VERDICT): a newer daemon was replaced by an older ast"
      kill -0 "$BEFORE" 2>/dev/null \
        || fail "row $CLAIM ($VERDICT): a newer daemon was killed by an older ast"
      ok "protocol $CLAIM: refused in words, and pid $BEFORE was left alone"
      ;;
    *)
      fail "the matrix asked for an action this script has no case for: $ACTION"
      ;;
  esac

  kill -9 "$BEFORE" 2>/dev/null || true
  [ -n "$AFTER" ] && kill -9 "$AFTER" 2>/dev/null || true
done <<<"$ROWS"

echo
echo "=== 2. a daemon inside the window that lacks a command ======================"

# The negotiated half of the upgrade: the window is two versions wide, so a
# daemon inside it may still not know the frame being sent. That is the moment
# to replace it, and the only one — not the moment `ast` merely noticed the
# crate versions differ.
WIN="$ASTERISM_HOME/window"
mkdir -p "$WIN"
WIN_PID="$(start_astd "$WIN" "$OURS")"
# A frame no build has, put on the socket by hand: this is what an `ast` two
# releases newer would send.
UNKNOWN="$(json "
import socket
s = socket.socket(socket.AF_UNIX)
s.connect('$WIN/astd.sock')
s.sendall(b'{\"cmd\":\"attach_gpu\",\"name\":\"dev\",\"device\":\"0000:01:00.0\"}\n')
print(s.makefile().readline().strip())
")"
grep -qF "unknown variant" <<<"$UNKNOWN" \
  || fail "a frame from a newer build was not refused by name:"$'\n'"$UNKNOWN"
ok "a daemon in the window refuses an unknown command by name, which is what ast acts on"
[ "$(serving_pid "$WIN")" = "$WIN_PID" ] \
  || fail "the daemon was replaced merely for being asked something it does not have"
ok "and it is still running — a refusal is not on its own a reason to restart it"
kill -9 "$WIN_PID" 2>/dev/null || true

echo
echo "=== 3. a downgrade is refused before anything is read or changed ============"

DOWN="$ASTERISM_HOME/downgrade"
mkdir -p "$DOWN"
seed_images "$DOWN"
NEWER=$((OURS + 1))
NEW_PID="$(start_astd "$DOWN" "$NEWER")"
if have_image "$DOWN"; then
  run_ast "$DOWN" "$NEWER" create dev --image "$IMAGE" --mem 1G --disk 5G >/dev/null \
    || fail "the newer daemon could not define an instance to leave behind"
fi
kill -9 "$NEW_PID" 2>/dev/null || true
rm -f "$DOWN/astd.sock" "$DOWN/astd.pid"

grep -qF "\"protocol\": $NEWER" "$DOWN/home.json" \
  || fail "the newer daemon did not stamp the home:"$'\n'"$(cat "$DOWN/home.json" 2>/dev/null)"
ok "a daemon stamps the home with what it speaks"

# The whole directory, not the one file this test happened to think of: the
# claim is that nothing was read or changed, and a refusal that quietly
# rewrote something else would still be a refusal that lied.
BEFORE_HOME="$(fingerprint "$DOWN")"

# Written outside the home it is a refusal about, so that reading it back is
# not itself a change to the thing under test.
start_astd_expecting_refusal "$DOWN" "$OURS" "$ASTERISM_HOME/refusal.txt"
REFUSAL="$(cat "$ASTERISM_HOME/refusal.txt")"
grep -qF "home.json" <<<"$REFUSAL" || fail "the refusal did not name the file:"$'\n'"$REFUSAL"
grep -qF "has been read or changed" <<<"$REFUSAL" \
  || fail "the refusal did not say nothing was touched:"$'\n'"$REFUSAL"
grep -qF "To repair" <<<"$REFUSAL" || fail "the refusal did not say what to do:"$'\n'"$REFUSAL"
ok "an older daemon refuses a home a newer one wrote, and says which file and why"

[ "$(fingerprint "$DOWN")" = "$BEFORE_HOME" ] \
  || fail "the refused daemon changed something in the home on its way out:"$'\n'"$(
       diff <(echo "$BEFORE_HOME") <(fingerprint "$DOWN") || true)"
ok "and every file in that home is byte-for-byte what it was"
[ ! -f "$DOWN/astd.sock" ] || fail "the refused daemon bound the socket before refusing"
ok "and it never bound the socket, so nothing could have reached it"
release_home "$DOWN"

echo
echo "=== 4. migrations keep the shape they migrated from ========================="

MIG="$ASTERISM_HOME/migrate"
mkdir -p "$MIG"
seed_images "$MIG"
if ! have_image "$MIG"; then
  skip "step 4: no image on this machine to define an instance with, so no shard to migrate"
else
MIG_PID="$(start_astd "$MIG" "")"
run_ast "$MIG" "" create one --image "$IMAGE" --mem 1G --disk 5G >/dev/null \
  || fail "could not define the instance whose shard this step migrates"
kill -9 "$MIG_PID" 2>/dev/null || true
rm -f "$MIG/astd.sock" "$MIG/astd.pid"
[ -f "$MIG/state.json" ] || fail "no registry was written to migrate"

# The pre-envelope shape: the instance map on its own, which no build in this
# tree will write and every build in this tree still reads.
json "
import json
doc = json.load(open('$MIG/state.json'))
json.dump(doc['instances'], open('$MIG/state.json','w'), indent=2)
"
LEGACY="$(shasum "$MIG/state.json" | cut -d' ' -f1)"
rm -f "$MIG/state.json.bak"

MIG_PID="$(start_astd "$MIG" "")"
grep -q '"version"' "$MIG/state.json" || fail "the legacy shard was not migrated on read"
ok "a pre-envelope shard is migrated on read"
[ -f "$MIG/state.json.bak" ] || fail "the migration kept no copy of the shape it replaced"
[ "$(shasum "$MIG/state.json.bak" | cut -d' ' -f1)" = "$LEGACY" ] \
  || fail "the .bak is not the pre-migration value"
ok "and the shape the previous build reads is at state.json.bak, byte for byte"

# Which is exactly what makes the next failure survivable: tear the live file
# and the migration's own backup is what the daemon comes back on.
kill -9 "$MIG_PID" 2>/dev/null || true
rm -f "$MIG/astd.sock" "$MIG/astd.pid"
WHOLE="$(wc -c <"$MIG/state.json")"
cp "$MIG/state.json" "$MIG/whole.json"
dd if="$MIG/whole.json" of="$MIG/state.json" bs=1 count=$((WHOLE / 2)) 2>/dev/null
: >"$MIG/astd.log"
MIG_PID="$(start_astd "$MIG" "")"
grep -qF "last-known-good" "$MIG/astd.log" || fail "the repair from the backup was silent"
run_ast "$MIG" "" ls | grep -qF "one" || fail "the repair lost the instance"
ok "a torn shard comes back from that copy, out loud, with the instance intact"
kill -9 "$MIG_PID" 2>/dev/null || true
release_home "$MIG"
fi

echo
echo "=== 5. two peers that cannot speak say so, rather than going quiet =========="

# pair <a-home> <a-protocol> <a-name> <b-home> <b-protocol> <b-name>
#
# Echoes both terminals' output, so the caller can assert on either. Returns
# non-zero only when no ticket was printed at all, which is the mesh failing
# to come up rather than a pairing being refused.
pair() {
  local ah="$1" ap="$2" an="$3" bh="$4" bp="$5" bn="$6"
  ASTERISM_HOME="$ah" env "$SEAM=$ap" "$AST" device invite --name "$an" --yes \
    >"$ah/invite.out" 2>&1 &
  local invite_pid=$! ticket=""
  for _ in $(seq 1 100); do
    ticket="$(grep -o 'astdev1[a-z0-9]*' "$ah/invite.out" 2>/dev/null | head -1 || true)"
    [ -n "$ticket" ] && break
    sleep 0.2
  done
  if [ -z "$ticket" ]; then
    kill -9 "$invite_pid" 2>/dev/null || true
    return 1
  fi
  ASTERISM_HOME="$bh" env "$SEAM=$bp" "$AST" device add "$ticket" --name "$bn" --yes \
    >"$bh/add.out" 2>&1 || true
  wait "$invite_pid" 2>/dev/null || true
  cat "$ah/invite.out" "$bh/add.out"
}

# ---- 5a. a pairing across a skew, refused while a human is watching --------

A="$ASTERISM_HOME/peer-a"
B="$ASTERISM_HOME/peer-b"
mkdir -p "$A" "$B"
A_PID="$(start_astd "$A" "$OURS")"
B_PID="$(start_astd "$B" $((OURS + 1)))"

if ! BOTH="$(pair "$A" "$OURS" a "$B" $((OURS + 1)) b)"; then
  skip "step 5: no pairing ticket was printed (the mesh did not come up on loopback)"
else
  grep -qF "protocol" <<<"$BOTH" \
    || fail "a pairing across a version skew was not refused by protocol:"$'\n'"$BOTH"
  ok "a pairing across a version skew is refused while a human is still watching"

  # And refused before either side writes the other down: a device in the
  # orbit store is a device every later command tries to reach.
  ASTERISM_HOME="$A" env "$SEAM=$OURS" "$AST" devices 2>&1 | grep -qE '^b ' \
    && fail "the skewed peer was written to the orbit store anyway"
  ok "and neither side wrote the other into its orbit"
fi
kill -9 "$A_PID" "$B_PID" 2>/dev/null || true

# ---- 5b. a rolling upgrade: two devices already paired, one moves ----------
#
# The case a pairing check cannot reach, and the one a rolling upgrade
# actually is. These two agreed when they were enrolled; the skew arrives
# afterwards, when one of them is upgraded and the other is not.

C="$ASTERISM_HOME/peer-c"
D="$ASTERISM_HOME/peer-d"
mkdir -p "$C" "$D"
C_PID="$(start_astd "$C" "$OURS")"
D_PID="$(start_astd "$D" "$OURS")"

if ! BOTH="$(pair "$C" "$OURS" c "$D" "$OURS" d)"; then
  skip "step 5b: no pairing ticket was printed"
else
  grep -qF "paired" <<<"$BOTH" || fail "two same-vintage devices did not pair:"$'\n'"$BOTH"
  run_ast "$C" "$OURS" ping d | grep -qF "pong" \
    || fail "the two paired devices cannot reach each other before the skew"
  ok "two devices of the same vintage pair and reach each other"

  # D is upgraded underneath C.
  kill -9 "$D_PID" 2>/dev/null || true
  rm -f "$D/astd.sock" "$D/astd.pid"
  D_PID="$(start_astd "$D" $((OURS + 1)))"

  OUT="$(run_ast "$C" "$OURS" ping d || true)"
  grep -qF "protocol" <<<"$OUT" \
    || fail "an upgraded peer read as something other than a version skew:"$'\n'"$OUT"
  grep -qF "upgrade this device" <<<"$OUT" \
    || fail "the skew did not say which half to upgrade:"$'\n'"$OUT"
  # The regression this replaces: an unknown frame used to close the stream,
  # and a closed stream reads as a device that is switched off.
  grep -qiE "unreachable|did not answer|connection (closed|refused)" <<<"$OUT" \
    && fail "the skew was reported as unreachability:"$'\n'"$OUT"
  ok "an upgraded peer is reported as a version skew, not as a device that is off"

  # And it is a skew, not a partition: the peer is still in the orbit store,
  # so it comes back by being upgraded rather than by being re-paired.
  run_ast "$C" "$OURS" devices | grep -qF "d" \
    || fail "the skewed peer was dropped from the orbit store"
  ok "and it is still in the orbit, so the repair is an upgrade and not a re-pairing"
fi
kill -9 "$C_PID" "$D_PID" 2>/dev/null || true

echo
echo "=== 6. a daemon replaced under a live guest leaves the guest running ========"

GUEST="$ASTERISM_HOME/guest"
mkdir -p "$GUEST"
seed_images "$GUEST"

if ! have_image "$GUEST"; then
  skip "step 6: no $IMAGE on this machine to boot (set E2E_IMAGE, or ast pull it first)"
else
  # Two numbers three apart, both above this build's own, rather than the
  # obvious `$OURS` and `$OURS - 1`.
  #
  # The window has a floor: it is `max(N - 2, 1)`, because 0 is not a version
  # any build claims. At protocol 1 there is therefore nothing *below* the
  # window to be — a pair at 0 would refuse each other, since a process at 0
  # is below its own floor. Shifting both numbers up gives the older half
  # somewhere to stand that a real release two versions back will stand in
  # for good.
  OLD_N=$((OURS + 1))
  NEW_N=$((OURS + 4))
  G_PID="$(start_astd "$GUEST" "$OLD_N")"
  run_ast "$GUEST" "$OLD_N" create dev --image "$IMAGE" --mem 2G --disk 10G >/dev/null \
    || fail "could not define the guest"
  run_ast "$GUEST" "$OLD_N" up dev >/dev/null || fail "could not boot the guest"
  BEFORE_GUEST="$(guest_pid "$GUEST" "$OLD_N")"
  [ -n "$BEFORE_GUEST" ] || fail "no guest process is running to preserve"
  ok "a guest is running as pid $BEFORE_GUEST under the older daemon"

  # The upgrade: a current `ast` finds a daemon below its window.
  OUT="$(run_ast "$GUEST" "$NEW_N" ls || true)"
  grep -qF "restarting the daemon" <<<"$OUT" \
    || fail "the older daemon was not replaced:"$'\n'"$OUT"
  [ "$(serving_pid "$GUEST")" != "$G_PID" ] || fail "the daemon was not actually replaced"

  AFTER_GUEST="$(guest_pid "$GUEST" "$NEW_N")"
  [ "$AFTER_GUEST" = "$BEFORE_GUEST" ] \
    || fail "the guest was restarted by the daemon replacement ($BEFORE_GUEST -> $AFTER_GUEST)"
  ok "the daemon was replaced and the guest kept running as pid $BEFORE_GUEST"
  run_ast "$GUEST" "$NEW_N" ls | grep -qF "dev" \
    || fail "the instance is gone after the upgrade"
  ok "and the new daemon adopted it rather than forgetting it"

  run_ast "$GUEST" "$NEW_N" down dev >/dev/null 2>&1 || true
  pkill -9 -f "$GUEST" 2>/dev/null || true
  release_home "$GUEST"
fi

echo
echo "=== 7. two successive builds of this tree ==================================="

OLD_SRC="$ASTERISM_HOME/old-src"
OLD_BIN="$ASTERISM_HOME/old-bin"
# `git archive` rather than `git worktree add`: this test must not register a
# worktree against the repository it is run from, and a stale registration is
# exactly what a killed test would leave behind.
if ! git -C "$ROOT" rev-parse --verify --quiet "$OLD_REF" >/dev/null; then
  skip "step 7: no ref $OLD_REF to build the previous release from (set SKEW_OLD_REF)"
else
  mkdir -p "$OLD_SRC" "$OLD_BIN"
  git -C "$ROOT" archive "$OLD_REF" | tar -x -C "$OLD_SRC"
  echo "building $OLD_REF (this takes a few minutes the first time)"
  if ! (cd "$OLD_SRC" && cargo build -q 2>"$ASTERISM_HOME/old-build.log"); then
    skip "step 7: $OLD_REF does not build:"$'\n'"$(tail -5 "$ASTERISM_HOME/old-build.log")"
  else
    cp "$OLD_SRC/target/debug/ast" "$OLD_SRC/target/debug/astd" "$OLD_BIN/"

    UP="$ASTERISM_HOME/upgrade"
    mkdir -p "$UP"
    seed_images "$UP"

    OLD_PID="$(start_astd "$UP" "" "$OLD_BIN/astd")"
    CREATED="$(ASTERISM_HOME="$UP" "$OLD_BIN/ast" create dev --image "$IMAGE" \
      --mem 2G --disk 10G 2>&1)" \
      || fail "the previous release could not define an instance:"$'\n'"$CREATED"$'\n'"--- its astd log ---"$'\n'"$(tail -20 "$UP/astd.log" 2>/dev/null)"
    ok "the previous release is running and holds an instance"

    BOOTED=
    if ASTERISM_HOME="$UP" "$OLD_BIN/ast" up dev >/dev/null 2>&1; then
      BOOTED="$(ASTERISM_HOME="$UP" "$OLD_BIN/ast" status dev 2>/dev/null \
        | sed -n 's/^running: .* pid \([0-9]*\),.*/\1/p')"
      ok "and a guest is running on it as pid $BOOTED"
    else
      skip "step 7: no image to boot, so this leg proves data and not guests"
    fi

    # The upgrade. The previous release answers Ping without a protocol at
    # all, which is the one row of the matrix nothing in this tree can claim.
    OUT="$(run_ast "$UP" "" ls || true)"
    grep -qF "predates the protocol version" <<<"$OUT" \
      || fail "a release from before the protocol field was not recognised:"$'\n'"$OUT"
    grep -qF "dev" <<<"$OUT" || fail "the instance did not survive the upgrade:"$'\n'"$OUT"
    ok "a release from before the protocol version is recognised, replaced, and its data survives"
    kill -0 "$OLD_PID" 2>/dev/null && fail "the previous release is still running"

    if [ -n "$BOOTED" ]; then
      STILL="$(guest_pid "$UP" "")"
      [ "$STILL" = "$BOOTED" ] \
        || fail "the guest did not survive the upgrade ($BOOTED -> $STILL)"
      ok "and the guest it was running is the same process it was"
      ASTERISM_HOME="$UP" "$AST" down dev >/dev/null 2>&1 || true
    fi
    STEP7_RAN=1

    # The reverse direction is deliberately not asserted here. The previous
    # release predates the home stamp, so it has nothing to check and will
    # start on a home this build wrote — which is the behaviour that made the
    # stamp necessary, not a regression this build can fix retroactively. It
    # is refused from the *next* release backwards, and step 3 is that claim.
    pkill -9 -f "$UP" 2>/dev/null || true
  fi
fi

echo
if [ ${#DEFERRED[@]} -gt 0 ]; then
  if [ -n "$STEP7_RAN" ]; then
    for d in "${DEFERRED[@]}"; do ok "$d — covered by step 7"; done
  else
    for d in "${DEFERRED[@]}"; do SKIPPED+=("$d, and step 7 did not run"); done
  fi
fi

if [ ${#SKIPPED[@]} -gt 0 ]; then
  echo "--- ${#SKIPPED[@]} leg(s) skipped, and not covered by this run ---"
  for s in "${SKIPPED[@]}"; do echo "  - $s"; done
  echo
fi
echo "E2E SKEW GREEN"
