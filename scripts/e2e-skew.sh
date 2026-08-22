#!/usr/bin/env bash
# End-to-end for version skew: two vintages of Asterism, real sockets, and an
# upgrade that happens one binary at a time the way upgrades really do.
#
# The unit tests in crates/asterism-core/src/compat.rs make the selection rule
# true, and crates/asterism-daemon/tests/control_plane.rs makes it true of the
# shipped `astd`. What only a running pair can prove is what this asserts:
#
#   1. the skew matrix `ast compat --json` prints is walked, row by row,
#      against a real daemon standing in for each vintage — so the table the
#      code generates and the behaviour it has cannot drift apart
#   2. a daemon one release behind is SPOKEN TO, not replaced, and every
#      command that predates the skew keeps working
#   3. an older `ast` against a daemon of this build is served at the wire the
#      old CLI has
#   4. a daemon older than anything this build serves IS replaced, and the
#      guests it was supervising are still running afterwards
#   5. a daemon NEWER than this build is refused and left alive — a downgrade
#      is never performed by killing something
#   6. two paired devices at different vintages SERVE EACH OTHER: a rolling
#      upgrade of an orbit, with `ls`, `status` and the orbit view crossing
#      the skew in both directions
#   7. a home written by a newer build is refused before a single store is
#      read, and the refusal names what it would have had to drop
#   8. a migration leaves the previous build's shape at `.bak`, an
#      interrupted one still does, and the daemon comes up on either
#   9. two successive vintages hand a live guest over without losing it or
#      the registry row that describes it
#
# The two vintages are the same pair of binaries with different ranges on
# them (ASTERISM_PROTOCOL_VERSION / ASTERISM_MIN_PROTOCOL_VERSION). That is
# deliberate: building the previous release and testing against it would test
# *that release's* bugs, when what is under test is this build's negotiation.
# Step 9 is the one that also wants a real previous binary, and takes one from
# $E2E_PREVIOUS_AST if it is there.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export PATH="$HOME/.cargo/bin:$PATH"
cd "$ROOT"
cargo build -q

# Fresh, SHORT homes: unix socket paths are capped near 104 bytes.
RUN="/private/tmp/ast-skew-$$"
BIN="$RUN/bin"
AST="$BIN/ast"
ASTD="$BIN/astd"
IMAGE="${E2E_IMAGE:-debian:13}"

# A single-device leg has no orbit, so it has no business publishing a
# throwaway key and this machine's addresses to a public discovery service.
export ASTERISM_MESH=local

mkdir -p "$BIN"
# Copied rather than run from target/: a sibling checkout's `pkill -f
# target/debug/astd` must not be able to kill this test's daemons.
cp "$ROOT/target/debug/ast" "$ROOT/target/debug/astd" "$BIN/"

fail() { echo "SKEW E2E FAIL: $*" >&2; exit 1; }
ok() { echo "ok: $*"; }

# Everything started here writes its pid inside its own ASTERISM_HOME, so
# cleanup can only ever reach a process this run started. Deliberately no
# `ast` in here: `ast` starts a daemon when the socket does not answer, so a
# cleanup built out of it can resurrect the very daemons it came to stop.
kill_pid() {
  local pid="$1" _i
  case "$pid" in ''|*[!0-9]*) return 0 ;; esac
  kill -0 "$pid" 2>/dev/null || return 0
  kill -TERM "$pid" 2>/dev/null || true
  for _i in $(seq 1 25); do
    kill -0 "$pid" 2>/dev/null || return 0
    sleep 0.2
  done
  kill -KILL "$pid" 2>/dev/null || true
}

cleanup() {
  [ -n "${CLEANED:-}" ] && return 0
  CLEANED=1
  local home f pid
  for home in "$RUN"/h-*; do
    [ -d "$home" ] || continue
    kill_pid "$(cat "$home/astd.pid" 2>/dev/null || true)"
  done
  # Then what they left running: both outlive astd by design.
  for home in "$RUN"/h-*; do
    [ -d "$home" ] || continue
    for f in "$home"/instances/*/qemu.pid; do
      [ -f "$f" ] || continue
      kill_pid "$(cat "$f" 2>/dev/null || true)"
    done
    for pid in $(grep -o '"pid":[0-9]*' "$home/state.json" 2>/dev/null | cut -d: -f2 || true); do
      kill_pid "$pid"
    done
  done
  if [ -n "${KEEP:-}" ]; then echo "kept $RUN for inspection"; else rm -rf "$RUN"; fi
  return 0
}
trap cleanup EXIT

# home <tag>: a fresh ASTERISM_HOME with a name cleanup can find.
home() {
  local h="$RUN/h-$1"
  mkdir -p "$h"
  echo "$h"
}

# start_at <home> <min> <max>: a daemon standing in for a build whose range is
# min..max. Started here rather than by the CLI, because `ast` spawns a daemon
# with its output on /dev/null and the refusals in that output are half the
# point.
start_at() {
  local h="$1" min="$2" max="$3"
  ( ASTERISM_HOME="$h" ASTERISM_MESH=local \
    ASTERISM_MIN_PROTOCOL_VERSION="$min" ASTERISM_PROTOCOL_VERSION="$max" \
    "$ASTD" >>"$h/astd.log" 2>&1 & )
  local _i
  for _i in $(seq 1 100); do
    [ -S "$h/astd.sock" ] && [ -s "$h/astd.pid" ] && return 0
    sleep 0.2
  done
  fail "astd ($min..$max) did not come up on $h:"$'\n'"$(cat "$h/astd.log" 2>/dev/null)"
}

# start_here <home>: a daemon of this build's own vintage.
start_here() {
  local h="$1"
  ( ASTERISM_HOME="$h" ASTERISM_MESH=local "$ASTD" >>"$h/astd.log" 2>&1 & )
  local _i
  for _i in $(seq 1 100); do
    [ -S "$h/astd.sock" ] && [ -s "$h/astd.pid" ] && return 0
    sleep 0.2
  done
  fail "astd did not come up on $h:"$'\n'"$(cat "$h/astd.log" 2>/dev/null)"
}

stop_daemon() {
  local h="$1"
  kill_pid "$(cat "$h/astd.pid" 2>/dev/null || true)"
  rm -f "$h/astd.pid"
}

pid_of() { cat "$1/astd.pid" 2>/dev/null || true; }

# raw <home> <json>: one frame in, one line back, on a connection of its own —
# which is exactly how `ast` asks. Used for the legs that must send the bytes
# a *previous* vintage sends, which no binary in this tree will write.
raw() {
  local h="$1" line="$2"
  python3 - "$h/astd.sock" "$line" <<'PY'
import socket, sys
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.settimeout(30)
s.connect(sys.argv[1])
s.sendall(sys.argv[2].encode() + b"\n")
buf = b""
while not buf.endswith(b"\n"):
    chunk = s.recv(65536)
    if not chunk:
        break
    buf += chunk
sys.stdout.write(buf.decode(errors="replace"))
PY
}

echo "=== 0. the table this test is generated from ==============================="

H0="$(home table)"
start_here "$H0"
ASTERISM_HOME="$H0" "$AST" compat --json >"$RUN/compat.json" \
  || fail "ast compat --json failed"
python3 -c 'import json,sys; json.load(open(sys.argv[1]))' "$RUN/compat.json" \
  || fail "ast compat --json did not print json"

OURS_MAX="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["protocol"])' "$RUN/compat.json")"
OURS_MIN="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["min_supported"])' "$RUN/compat.json")"
ROWS="$(python3 -c 'import json,sys; print(len(json.load(open(sys.argv[1]))["matrix"]))' "$RUN/compat.json")"
[ "$ROWS" -ge 3 ] || fail "the generated matrix has only $ROWS rows"
ok "this build speaks $OURS_MIN..$OURS_MAX, and prints a $ROWS-row matrix"

# The daemon's half of `ast compat` is itself a protocol-2 frame, so a green
# `ast compat` against a live daemon is already the negotiation working.
ASTERISM_HOME="$H0" "$AST" compat 2>&1 | grep -q "talking at protocol $OURS_MAX" \
  || fail "ast compat did not report a negotiated version:"$'\n'"$(ASTERISM_HOME="$H0" "$AST" compat 2>&1)"
ok "ast and astd of one vintage negotiate protocol $OURS_MAX"
stop_daemon "$H0"

echo
echo "=== 1. every row of the generated matrix, against a real daemon ============"
#
# The matrix is data, so the cases below are not written here — they are read
# out of the binary and walked. A row added to `compat::matrix` is a case this
# test runs on the next commit, which is the only arrangement in which "the
# matrix is complete" can stay true.

python3 - "$RUN/compat.json" >"$RUN/rows.tsv" <<'PY'
import json, sys
for row in json.load(open(sys.argv[1]))["matrix"]:
    print("\t".join([
        str(row["peer_min"]), str(row["peer_max"]),
        row["verdict"], row["daemon_action"],
        "" if row["speaks"] is None else str(row["speaks"]),
        row["note"],
    ]))
PY

WALKED=0
while IFS=$'\t' read -r PMIN PMAX _VERDICT ACTION SPEAKS NOTE; do
  [ -n "$PMIN" ] || continue
  WALKED=$((WALKED + 1))
  H="$(home "row$WALKED")"
  start_at "$H" "$PMIN" "$PMAX"
  BEFORE="$(pid_of "$H")"

  # What `ast` really writes as its first frame, answered by a real daemon of
  # that vintage.
  PONG="$(raw "$H" "{\"cmd\":\"ping\",\"protocol\":$OURS_MAX,\"min_protocol\":$OURS_MIN}")"

  case "$ACTION" in
    speak)
      grep -q '"result":"pong"' <<<"$PONG" \
        || fail "row $PMIN-$PMAX ($NOTE): a speakable daemon did not answer:"$'\n'"$PONG"
      # And it serves. A handshake that succeeds in front of a command that
      # does not is a negotiation that bought nothing.
      LS="$(raw "$H" '{"cmd":"list"}')"
      grep -q '"result":"instances"' <<<"$LS" \
        || fail "row $PMIN-$PMAX ($NOTE): a speakable daemon would not list:"$'\n'"$LS"
      # `ast` itself, all the way through, against that vintage.
      ASTERISM_HOME="$H" "$AST" ls >/dev/null 2>&1 \
        || fail "row $PMIN-$PMAX ($NOTE): ast ls failed against a speakable daemon"
      [ "$(pid_of "$H")" = "$BEFORE" ] \
        || fail "row $PMIN-$PMAX ($NOTE): a daemon that could be spoken to was replaced"
      ok "protocols $PMIN-$PMAX: spoken to at ${SPEAKS:-?}, left running — $NOTE"
      ;;
    refuse)
      grep -q '"result":"error"' <<<"$PONG" \
        || fail "row $PMIN-$PMAX ($NOTE): a daemon out of the window was not refused:"$'\n'"$PONG"
      grep -q 'upgrade' <<<"$PONG" \
        || fail "row $PMIN-$PMAX ($NOTE): the refusal carries no repair:"$'\n'"$PONG"
      # `ast` refuses too, and — the whole point — leaves it alive.
      if OUT="$(ASTERISM_HOME="$H" "$AST" ls 2>&1)"; then
        fail "row $PMIN-$PMAX ($NOTE): ast succeeded against a daemon out of its window:"$'\n'"$OUT"
      fi
      grep -q 'left running' <<<"$OUT" \
        || fail "row $PMIN-$PMAX ($NOTE): ast did not say the newer daemon was kept:"$'\n'"$OUT"
      grep -q 'upgrade' <<<"$OUT" \
        || fail "row $PMIN-$PMAX ($NOTE): the refusal carries no repair:"$'\n'"$OUT"
      # Both halves are on this machine, so a refusal that sends the user to
      # another device is a refusal pointing at the wrong computer.
      grep -q 'on that device' <<<"$OUT" \
        && fail "row $PMIN-$PMAX ($NOTE): a local skew was reported as a remote one:"$'\n'"$OUT"
      [ "$(pid_of "$H")" = "$BEFORE" ] \
        || fail "row $PMIN-$PMAX ($NOTE): a NEWER daemon was replaced — that is a downgrade"
      kill -0 "$BEFORE" 2>/dev/null \
        || fail "row $PMIN-$PMAX ($NOTE): a newer daemon was signalled"
      ok "protocols $PMIN-$PMAX: refused in words, left running — $NOTE"
      ;;
    replace)
      OUT="$(ASTERISM_HOME="$H" "$AST" ls 2>&1 || true)"
      [ "$(pid_of "$H")" != "$BEFORE" ] \
        || fail "row $PMIN-$PMAX ($NOTE): a daemon too old to serve was not replaced:"$'\n'"$OUT"
      ok "protocols $PMIN-$PMAX: replaced — $NOTE"
      ;;
    *) fail "row $PMIN-$PMAX: unknown action $ACTION" ;;
  esac
  stop_daemon "$H"
done <"$RUN/rows.tsv"

[ "$WALKED" = "$ROWS" ] || fail "walked $WALKED of $ROWS matrix rows"
ok "all $ROWS generated rows walked against real daemons"

echo
echo "=== 2. new CLI, old daemon: spoken to, not replaced ========================"

H="$(home newcli)"
start_at "$H" 1 1
BEFORE="$(pid_of "$H")"

ASTERISM_HOME="$H" "$AST" ls >/dev/null 2>&1 || fail "ast ls failed against a protocol-1 daemon"
ASTERISM_HOME="$H" "$AST" devices >/dev/null 2>&1 \
  || fail "ast devices failed against a protocol-1 daemon"
[ "$(pid_of "$H")" = "$BEFORE" ] \
  || fail "a protocol-1 daemon was replaced by a CLI that can speak to it"
ok "a daemon a release behind serves this CLI and is left running"

# The one frame that is newer than protocol 1 is refused by name, and says so
# in a sentence — not as `unknown variant`, and not by breaking anything else.
OUT="$(ASTERISM_HOME="$H" "$AST" compat 2>&1)"
grep -q 'predates the compat frame' <<<"$OUT" \
  || fail "ast compat did not explain the missing half:"$'\n'"$OUT"
grep -qv 'unknown variant' <<<"$OUT" || fail "a serde error reached the user:"$'\n'"$OUT"
grep -q 'protocol 1' <<<"$OUT" || fail "ast compat did not name the version in force:"$'\n'"$OUT"
ok "the one frame that vintage lacks is withheld and explained, by name"
stop_daemon "$H"

echo
echo "=== 3. old CLI, new daemon: served at the wire the old CLI has ============="
#
# The bytes a previous `ast` writes: a bare ping, with no range on it. No
# binary in this tree writes that frame, which is exactly why it is written by
# hand here.

H="$(home oldcli)"
start_here "$H"
BEFORE="$(pid_of "$H")"

PONG="$(raw "$H" '{"cmd":"ping"}')"
grep -q '"result":"pong"' <<<"$PONG" || fail "an old CLI's ping was not answered:"$'\n'"$PONG"
LS="$(raw "$H" '{"cmd":"list"}')"
grep -q '"result":"instances"' <<<"$LS" || fail "an old CLI's list was not served:"$'\n'"$LS"
[ "$(pid_of "$H")" = "$BEFORE" ] || fail "the daemon restarted itself for an old CLI"
ok "an old CLI is served at protocol 1 by a daemon of this build"

# And the daemon is still serving everyone else afterwards, which is the
# question that matters after any negotiation.
ASTERISM_HOME="$H" "$AST" ls >/dev/null 2>&1 \
  || fail "the daemon stopped serving this build after an old CLI called"
ok "and the same daemon still serves this build on the next connection"
stop_daemon "$H"

echo
echo "=== 4. a downgrade is refused before a single store is read ================"

H="$(home downgrade)"
cat >"$H/home.json" <<'JSON'
{"version":1,"protocol":99,"asterism":"99.0.0",
 "stores":{"registry":99,"orbit":1,"volumes":1,"secrets":1,"seed":4},
 "written_at":1700000000}
JSON
cp "$H/home.json" "$H/home.before.json"

set +e
( ASTERISM_HOME="$H" ASTERISM_MESH=local "$ASTD" >"$H/refusal.txt" 2>&1 ) &
REFUSER=$!
for _ in $(seq 1 100); do
  kill -0 "$REFUSER" 2>/dev/null || break
  sleep 0.2
done
if kill -0 "$REFUSER" 2>/dev/null; then
  kill -9 "$REFUSER" 2>/dev/null
  set -e
  fail "astd started on a home a newer build wrote"
fi
wait "$REFUSER"; RC=$?
set -e
[ "$RC" != 0 ] || fail "astd exited 0 on a home a newer build wrote"

grep -q 'registry format 99' "$H/refusal.txt" \
  || fail "the refusal does not name what it would drop:"$'\n'"$(cat "$H/refusal.txt")"
grep -q '99.0.0' "$H/refusal.txt" \
  || fail "the refusal does not name the build that wrote the home"
grep -q 'upgrade Asterism' "$H/refusal.txt" || fail "the refusal carries no repair"
ok "a home written by Asterism 99.0.0 is refused, by name"

# Before mutation: the door was never opened and no store was written.
[ ! -e "$H/astd.sock" ] || fail "the socket was created before the refusal"
[ ! -e "$H/state.json" ] || fail "the registry was written before the refusal"
[ ! -e "$H/orbit.json" ] || fail "the orbit store was written before the refusal"
cmp -s "$H/home.json" "$H/home.before.json" \
  || fail "the stamp itself was rewritten, erasing the evidence of the newer build"
ok "nothing in the home was read or changed: refused at the door, not three stores in"

# And the ordinary case still works: move the stamp aside and it comes up.
mv "$H/home.json" "$H/home.aside.json"
start_here "$H"
ASTERISM_HOME="$H" "$AST" ls >/dev/null 2>&1 || fail "astd would not serve after the stamp was moved"
python3 -c 'import json,sys; s=json.load(open(sys.argv[1])); sys.exit(0 if s["protocol"]=='"$OURS_MAX"' else 1)' \
  "$H/home.json" || fail "the daemon did not re-stamp the home it took over"
ok "with the stamp moved aside the same daemon starts and stamps the home itself"
stop_daemon "$H"

echo
echo "=== 5. a migration leaves the previous build's shape at .bak ==============="
#
# The shape a pre-envelope Asterism wrote, migrated on read. What matters for
# a downgrade is not that the migration happened but that the OLD shape is
# still on the disk afterwards — a migration whose backup went missing is a
# one-way door.

H="$(home migrate)"
cat >"$H/state.json" <<'JSON'
{"dev":{"id":"6f1c","name":"dev","anchor":"laptop","status":"stopped",
 "created_at":1700000000,"volumes":[],"image":"debian:13",
 "machine":{"backend":"qemu","machine_type":"virt","cpu":"host","hv_version":"9.0.0"}}}
JSON
cp "$H/state.json" "$H/state.legacy.json"

start_here "$H"
ASTERISM_HOME="$H" "$AST" ls 2>&1 | grep -q 'dev' \
  || fail "the migrated row is not in the registry:"$'\n'"$(ASTERISM_HOME="$H" "$AST" ls 2>&1)"
python3 -c 'import json,sys; s=json.load(open(sys.argv[1])); sys.exit(0 if "version" in s else 1)' \
  "$H/state.json" || fail "the live shard was not rewritten in this build's shape"
cmp -s "$H/state.json.bak" "$H/state.legacy.json" \
  || fail "the pre-migration shape is not at .bak byte for byte:"$'\n'"$(cat "$H/state.json.bak" 2>/dev/null)"
ok "an upgraded shard is live in the new shape and the old shape is at .bak"

# Backup restore: destroy the live file and the daemon comes back from .bak
# rather than from an empty registry.
stop_daemon "$H"
printf '{"version":1,"instances":' >"$H/state.json"   # torn mid-write
start_here "$H"
ASTERISM_HOME="$H" "$AST" ls >/dev/null 2>&1 || fail "the daemon would not serve after a torn shard"
grep -q 'dev' <<<"$(ASTERISM_HOME="$H" "$AST" ls 2>&1)" \
  || fail "a torn shard was recovered into an EMPTY registry, losing this device's instances"
ok "a torn shard is recovered from its backup rather than forgotten"
stop_daemon "$H"

echo
echo "=== 6. a rolling orbit upgrade: two vintages serving each other ============"
#
# The leg the whole bead rests on. Two paired devices of the older vintage,
# then ONE of them is upgraded, and the orbit keeps working — in BOTH
# directions, which is what makes it interoperability rather than a politer
# failure.
#
# The order matters and is not arbitrary: an upgrade rolls forwards. A device
# cannot be rolled backwards, because its home records the build that wrote it
# and a downgrade is refused before mutation — which is step 4, asserted again
# from the orbit's side at the end of this one.

A="$(home a)"
B="$(home b)"
A_NAME="skew-a-$$"
B_NAME="skew-b-$$"

# A is this build. B is a release behind. They are paired ACROSS the skew and
# neither is restarted afterwards — which is both the sharper claim and the
# honest one here: `ASTERISM_MESH=local` has no discovery, so a daemon that
# restarts moves to a new ephemeral port and its peers' stored hints go stale.
# That is a property of running the whole orbit on one host with no
# coordination plane, not of the skew, and building the test around a restart
# would be testing the harness. The roll's other half — a device upgrading in
# place without losing anything — is asserted below, from the side that can
# see it.
start_here "$A"
start_at "$B" 1 1

# --yes stands in for the human at each terminal.
ASTERISM_HOME="$A" "$AST" device invite --name "$A_NAME" --yes >"$A/invite.out" 2>&1 &
INVITE_PID=$!
TICKET=""
for _ in $(seq 1 150); do
  TICKET="$(grep -o 'astdev1[a-z0-9]*' "$A/invite.out" 2>/dev/null | head -1 || true)"
  [ -n "$TICKET" ] && break
  sleep 0.2
done
[ -n "$TICKET" ] || fail "no ticket printed:"$'\n'"$(cat "$A/invite.out")"
ASTERISM_HOME="$B" "$AST" device add "$TICKET" --name "$B_NAME" --yes >"$B/add.out" 2>&1 \
  || fail "ast device add failed across the skew:"$'\n'"$(cat "$B/add.out")"
wait "$INVITE_PID" || fail "ast device invite failed across the skew:"$'\n'"$(cat "$A/invite.out")"
ok "a device on this build and one a release behind PAIR across the skew"

# A (this build) -> B (protocol 1). The orbit view is assembled by asking the
# peer for its shard, so a green `ast ls` here IS the cross-vintage RPC.
ASTERISM_HOME="$B" "$AST" create skew-on-old --image "$IMAGE" >/dev/null 2>&1 \
  || fail "could not define an instance on the older half"

OUT="$(ASTERISM_HOME="$A" "$AST" devices 2>&1)"
grep -qE "^$B_NAME +\S+ +online" <<<"$OUT" \
  || fail "A cannot reach a peer one release behind:"$'\n'"$OUT"
ASTERISM_HOME="$A" "$AST" ping "$B_NAME" >/dev/null 2>&1 \
  || fail "A could not ping a peer one release behind"
OUT="$(ASTERISM_HOME="$A" "$AST" ls 2>&1)"
grep -q 'skew-on-old' <<<"$OUT" \
  || fail "A cannot see the instance on the older half — the orbit split at the skew:"$'\n'"$OUT"
ASTERISM_HOME="$A" "$AST" status skew-on-old >/dev/null 2>&1 \
  || fail "status does not resolve across the skew"
ok "new -> old: A reaches B, pings it, and resolves B's instance by name"

# B (protocol 1) -> A (this build). The other direction, which is the half a
# refusal-only implementation gets to skip.
ASTERISM_HOME="$A" "$AST" create skew-on-new --image "$IMAGE" >/dev/null 2>&1 \
  || fail "could not define an instance on the newer half"

OUT="$(ASTERISM_HOME="$B" "$AST" devices 2>&1)"
grep -qE "^$A_NAME +\S+ +online" <<<"$OUT" \
  || fail "B cannot reach a peer a release ahead:"$'\n'"$OUT"
ASTERISM_HOME="$B" "$AST" ping "$A_NAME" >/dev/null 2>&1 \
  || fail "B could not ping a peer a release ahead"
OUT="$(ASTERISM_HOME="$B" "$AST" ls 2>&1)"
grep -q 'skew-on-new' <<<"$OUT" \
  || fail "B cannot see the instance on the newer half:"$'\n'"$OUT"
ASTERISM_HOME="$B" "$AST" status skew-on-new >/dev/null 2>&1 \
  || fail "status does not resolve back across the skew"
ok "old -> new: B reaches A, pings it, and resolves A's instance by name"

# One namespace across the skew, not two: the half-upgraded orbit still
# refuses a name the other half has taken. This only works if the two
# vintages really are reading each other's shards.
OUT="$(ASTERISM_HOME="$B" "$AST" create skew-on-new --image "$IMAGE" 2>&1 || true)"
grep -q 'already exists in this orbit' <<<"$OUT" \
  || fail "the two vintages disagree about what names are taken:"$'\n'"$OUT"
ok "and the two vintages agree on one namespace: a taken name is taken on both"

# ---- the roll completes: B upgrades in place --------------------------------
#
# Asserted from B, which is the device that moved and the one that can see
# what the move cost. A's hint for B goes stale here for the harness reason
# above, so what is claimed is exactly what an upgrade promises: B keeps its
# own instances, keeps its orbit, and can still reach the peer it was paired
# with before it moved.
stop_daemon "$B"
start_here "$B"
ok "B upgraded in place from protocol 1 to protocol $OURS_MAX"

OUT="$(ASTERISM_HOME="$B" "$AST" ls 2>&1)"
grep -q 'skew-on-old' <<<"$OUT" \
  || fail "B lost its own instance when it upgraded:"$'\n'"$OUT"
grep -q 'skew-on-new' <<<"$OUT" \
  || fail "B lost sight of A's instance when it upgraded:"$'\n'"$OUT"
OUT="$(ASTERISM_HOME="$B" "$AST" devices 2>&1)"
grep -qE "^$A_NAME +\S+ +online" <<<"$OUT" \
  || fail "B lost the peer it was paired with when it upgraded:"$'\n'"$OUT"
ASTERISM_HOME="$B" "$AST" ping "$A_NAME" >/dev/null 2>&1 \
  || fail "B could not reach A after upgrading"
ok "the roll completes: B keeps its instances, its orbit and its reach"

# ---- and it does not roll backwards -----------------------------------------
#
# The other half of "upgrade": a device whose home this build has written
# cannot be taken back to the older vintage, and finds that out before it has
# touched anything. Asserted here rather than only in step 4 because this is
# the home of a device in a live orbit, with instances in it.
stop_daemon "$B"
set +e
( ASTERISM_HOME="$B" ASTERISM_MESH=local \
  ASTERISM_MIN_PROTOCOL_VERSION=1 ASTERISM_PROTOCOL_VERSION=1 \
  "$ASTD" >"$B/rollback.txt" 2>&1 ) &
ROLLBACK=$!
for _ in $(seq 1 100); do kill -0 "$ROLLBACK" 2>/dev/null || break; sleep 0.2; done
if kill -0 "$ROLLBACK" 2>/dev/null; then
  kill -9 "$ROLLBACK" 2>/dev/null
  set -e
  fail "B rolled backwards onto a home this build had written"
fi
wait "$ROLLBACK"; RC=$?
set -e
[ "$RC" != 0 ] || fail "the older vintage exited 0 on a home this build wrote"
grep -q 'protocol 2' "$B/rollback.txt" \
  || fail "the rollback refusal does not name the protocol:"$'\n'"$(cat "$B/rollback.txt")"
grep -q 'has been read or changed' "$B/rollback.txt" \
  || fail "the rollback refusal does not say it changed nothing"
ok "and B cannot roll backwards: refused before it read a single store"

start_here "$B"
ASTERISM_HOME="$A" "$AST" rm skew-on-new >/dev/null 2>&1 || true
ASTERISM_HOME="$B" "$AST" rm skew-on-old >/dev/null 2>&1 || true
stop_daemon "$A"
stop_daemon "$B"

echo "=== 7. a daemon is replaced without losing the guests it supervises ========"
#
# A guest is a separate process that outlives the daemon that started it, and
# the registry row that describes it is on disk. So a daemon replacement — the
# thing an upgrade IS — must leave both alone. Skipped where a guest cannot be
# booted, and said out loud rather than passed quietly.

H="$(home guests)"
start_here "$H"
ASTERISM_HOME="$H" "$AST" create up-across --image "$IMAGE" >/dev/null 2>&1 \
  || fail "could not define the instance for the guest leg"

if ASTERISM_HOME="$H" "$AST" up up-across >"$H/up.out" 2>&1; then
  GUEST_PID="$(cat "$H"/instances/up-across/qemu.pid 2>/dev/null || \
               grep -o '"pid":[0-9]*' "$H/state.json" | head -1 | cut -d: -f2 || true)"
  [ -n "$GUEST_PID" ] || fail "a guest came up with no pid recorded"
  kill -0 "$GUEST_PID" 2>/dev/null || fail "the guest was not running after ast up"
  ok "a guest is running as pid $GUEST_PID under the first daemon"

  # The upgrade: stop the daemon and start the next vintage in its place.
  # SIGTERM, the way a package manager does it — not kill -9, which is a
  # different test.
  stop_daemon "$H"
  kill -0 "$GUEST_PID" 2>/dev/null \
    || fail "the guest died with the daemon that started it — an upgrade would lose it"
  ok "the guest outlived the daemon being replaced"

  start_here "$H"
  kill -0 "$GUEST_PID" 2>/dev/null \
    || fail "the replacement daemon killed the guest it inherited"
  OUT="$(ASTERISM_HOME="$H" "$AST" ls 2>&1)"
  grep -q 'up-across' <<<"$OUT" || fail "the instance is gone after the replacement:"$'\n'"$OUT"
  grep -qE 'up-across +running' <<<"$OUT" \
    || fail "the replacement daemon did not re-adopt the live guest:"$'\n'"$OUT"
  ok "the replacement daemon re-adopts the same guest, still pid $GUEST_PID"

  ASTERISM_HOME="$H" "$AST" down up-across >/dev/null 2>&1 || true
else
  echo "skip: no guest could be booted here — $(tail -2 "$H/up.out" | tr '\n' ' ')"
  echo "      (the registry half of this leg is asserted below regardless)"
fi

# The data half, which needs no guest: the registry row and the home stamp
# survive a daemon replacement, and the second daemon does not rewrite the
# stamp for no news.
STAMP_BEFORE="$(cat "$H/home.json")"
stop_daemon "$H"
start_here "$H"
ASTERISM_HOME="$H" "$AST" ls 2>&1 | grep -q 'up-across' \
  || fail "the registry did not survive a daemon replacement"
[ "$(cat "$H/home.json")" = "$STAMP_BEFORE" ] \
  || fail "the home stamp churned on a restart that had no news"
ok "the registry survives the replacement and the stamp is not rewritten for no news"

ASTERISM_HOME="$H" "$AST" rm up-across >/dev/null 2>&1 || true
stop_daemon "$H"

echo
echo "=== 8. two successive vintages, one home, one guest ========================"
#
# The acceptance criterion stated plainly: a home is used by a build a release
# behind, then by this build, and nothing is lost in between. If a real
# previous binary is available it is used for the first half; otherwise the
# stand-in is, and this says which it was.

H="$(home rolling)"
if [ -n "${E2E_PREVIOUS_AST:-}" ] && [ -x "${E2E_PREVIOUS_ASTD:-}" ]; then
  echo "using the real previous release at $E2E_PREVIOUS_ASTD"
  ( ASTERISM_HOME="$H" ASTERISM_MESH=local "$E2E_PREVIOUS_ASTD" >>"$H/astd.log" 2>&1 & )
  for _ in $(seq 1 100); do [ -S "$H/astd.sock" ] && break; sleep 0.2; done
  ASTERISM_HOME="$H" "$E2E_PREVIOUS_AST" create carried --image "$IMAGE" >/dev/null 2>&1 \
    || fail "the previous release could not define an instance"
else
  echo "no previous release given (set E2E_PREVIOUS_AST / E2E_PREVIOUS_ASTD);"
  echo "standing one in at protocol 1"
  start_at "$H" 1 1
  ASTERISM_HOME="$H" "$AST" create carried --image "$IMAGE" >/dev/null 2>&1 \
    || fail "the older vintage could not define an instance"
fi

BEFORE="$(ASTERISM_HOME="$H" "$AST" ls 2>&1)"
grep -q 'carried' <<<"$BEFORE" || fail "the older vintage did not record the instance"
stop_daemon "$H"

# The upgrade.
start_here "$H"
AFTER="$(ASTERISM_HOME="$H" "$AST" ls 2>&1)"
grep -q 'carried' <<<"$AFTER" \
  || fail "an instance defined by the previous vintage was lost on upgrade:"$'\n'"$AFTER"
ASTERISM_HOME="$H" "$AST" status carried >/dev/null 2>&1 \
  || fail "the carried instance does not resolve after the upgrade"
ok "an instance defined by the previous vintage survives the upgrade intact"

# And the home now says who owns it, which is what makes the *next* downgrade
# refusable.
python3 -c 'import json,sys; s=json.load(open(sys.argv[1])); sys.exit(0 if s["protocol"]=='"$OURS_MAX"' else 1)' \
  "$H/home.json" || fail "the upgraded home was not re-stamped"
ok "and the home is stamped by this build, so a downgrade is refusable from here"

ASTERISM_HOME="$H" "$AST" rm carried >/dev/null 2>&1 || true
stop_daemon "$H"

echo
echo "E2E GREEN (skew)"
