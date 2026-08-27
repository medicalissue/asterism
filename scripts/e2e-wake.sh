#!/usr/bin/env bash
# End-to-end for waking a sleeping device: three daemons on one host, one of
# them killed, and a real Wake-on-LAN magic packet caught off the wire.
#
# enrollment -> device check -> already-online -> a peer on the target's LAN
# broadcasts -> the packet's 102 bytes -> presence confirms the wake -> the
# same thing with no mesh hop -> nobody awake, in the spec's exact words.
#
# WHAT THIS CANNOT PROVE. No CI can put a machine to sleep and wake it: that
# needs firmware, a NIC that keeps power, and a switch that floods the
# broadcast, none of which exist inside a test. So the test proves the half
# that is software — that the right device is chosen to send, that it sends,
# and that what it sends is byte-for-byte a magic packet for the right MAC —
# and it is honest that the other half is unproven. `ast device check` exists
# for exactly the same reason.
#
# THE HOOKS, and why each is not cheating:
#
#   ASTERISM_LAN_ID    Three daemons on one host really are on one LAN, which
#                      is the one arrangement that cannot exercise the routing
#                      the feature is made of. This makes them disagree. It
#                      overrides the fingerprint, not the comparison — the
#                      code that decides who broadcasts is untouched.
#   ASTERISM_WAKE_MAC  Gives B a MAC nothing else on the machine has, so a
#                      captured packet is provably about B.
#   ASTERISM_WAKE_PORT UDP 9 is privileged and a test listener cannot bind it.
#                      The port a magic packet lands on is not part of it —
#                      the NIC matches the payload — so the 102 bytes are
#                      identical either way, and the 102 bytes are the claim.
#   ASTERISM_WAKE_WAIT How long a wake watches for the device to check in.
#                      Shortened where the test wants the giving-up path, left
#                      long where it wants the it-came-back path.
#
# ASTERISM_MESH=local keeps every endpoint on loopback, exactly as
# scripts/e2e-mesh.sh does.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export PATH="$HOME/.cargo/bin:$PATH"
cd "$ROOT"
# shellcheck source-path=SCRIPTDIR source=lib/harness.sh
. "$ROOT/scripts/lib/harness.sh"
harness_begin wake
harness_binaries "$ROOT"

# Fresh, SHORT homes: unix socket paths are capped near 104 bytes, and these
# are deliberately nowhere near the user's own ~/.asterism.
RUN="/private/tmp/ast-wake-$$"
A="$RUN/a"    # the device the user is sitting at; on another LAN entirely
B="$RUN/b"    # the sleeper
C="$RUN/c"    # awake on the sleeper's LAN — the beacon
A_NAME="wake-a-$$"
B_NAME="wake-b-$$"
C_NAME="wake-c-$$"

# Two pretend broadcast domains. B and C share one; A is somewhere else, so A
# cannot send the packet itself and has to find someone who can.
LAN_HOME="lan-home-$$"
LAN_FAR="lan-far-$$"

B_MAC="de:ad:be:ef:0b:0b"
B_MAC_HEX="deadbeef0b0b"
PORT=$(( 19000 + ($$ % 900) ))
DAEMON_PIDS=()

cleanup() {
  capture_stop
  # Kill only daemons started by this test. A path-wide `pkill -f` can stop a
  # developer's real daemon (or another e2e running beside this one).
  local pid
  for pid in "${DAEMON_PIDS[@]}"; do
    kill -CONT "$pid" 2>/dev/null || true
    kill -TERM "$pid" 2>/dev/null || true
  done
  # Evidence before the homes go, whether or not E2E_KEEP was asked for: a
  # CI run cannot come back later to look at a directory it did not keep.
  local home
  for home in "$RUN"/*/; do
    [ -d "$home" ] && harness_keep_home "$home" "$(basename "$home")"
  done
  # E2E_KEEP=1 leaves the homes and their logs behind, for when a failure
  # needs reading rather than reproducing.
  [ -n "${E2E_KEEP:-}" ] || rm -rf "$RUN"
  harness_artifacts_note
}
trap cleanup EXIT

fail() { echo "WAKE E2E FAIL: $*" >&2; exit 1; }

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

# start_daemon <home> <lan-id> <mac> <wake-wait>
start_daemon() {
  local home="$1" lan="$2" mac="$3" wait="$4"
  mkdir -p "$home"
  ASTERISM_HOME="$home" ASTERISM_MESH=local \
    ASTERISM_LAN_ID="$lan" ASTERISM_WAKE_MAC="$mac" \
    ASTERISM_WAKE_PORT="$PORT" ASTERISM_WAKE_WAIT="$wait" \
    "$ASTD" >>"$home/astd.log" 2>&1 &
  DAEMON_PIDS+=("$!")
  for _ in $(seq 1 50); do
    grep -q "on the mesh as" "$home/astd.log" 2>/dev/null && return 0
    sleep 0.2
  done
  fail "astd for $home did not come up:"$'\n'"$(cat "$home/astd.log" 2>/dev/null)"
}

stop_daemon() {
  local home="$1" pid
  pid="$(cat "$home/astd.pid" 2>/dev/null || true)"
  [ -n "$pid" ] || fail "no pid file for the daemon in $home"
  kill -CONT "$pid" 2>/dev/null || true
  kill -TERM "$pid" 2>/dev/null || true
  for _ in $(seq 1 50); do
    kill -0 "$pid" 2>/dev/null || return 0
    sleep 0.2
  done
  kill -KILL "$pid" 2>/dev/null || true
}

# SIGSTOP/SIGCONT, which is the closest a test can get to a machine falling
# asleep and waking up: the process stops answering the mesh entirely, and —
# the part that matters — it keeps its endpoint address, exactly as a sleeping
# machine keeps its. A killed daemon comes back on a fresh ephemeral port that
# its peers have no way to learn under ASTERISM_MESH=local, so killing it
# would test the discovery gap rather than the wake.
sleep_daemon() { kill -STOP "$(cat "$1/astd.pid")"; }
rouse_daemon() { kill -CONT "$(cat "$1/astd.pid")"; }

# pair <home-inviter> <name-inviter> <home-joiner> <name-joiner>
pair() {
  local ih="$1" iname="$2" jh="$3" jname="$4" ticket=""
  ASTERISM_HOME="$ih" "$AST" device invite --name "$iname" --yes >"$ih/invite.out" 2>&1 &
  local invite_pid=$!
  for _ in $(seq 1 100); do
    ticket="$(grep -o 'astdev1[a-z0-9]*' "$ih/invite.out" 2>/dev/null | head -1 || true)"
    [ -n "$ticket" ] && break
    sleep 0.2
  done
  [ -n "$ticket" ] || fail "no ticket from $iname:"$'\n'"$(cat "$ih/invite.out")"
  ASTERISM_HOME="$jh" "$AST" device add "$ticket" --name "$jname" --yes >"$jh/add.out" 2>&1 \
    || fail "ast device add failed on $jname:"$'\n'"$(cat "$jh/add.out")"
  wait "$invite_pid" || fail "ast device invite failed on $iname:"$'\n'"$(cat "$ih/invite.out")"
  echo "ok: $iname and $jname paired"
}

# wake_facts <orbit.json> <device-name> -> "<mac> <lan-id>"
wake_facts() {
  python3 - "$1" "$2" <<'PY'
import json, sys
store = json.load(open(sys.argv[1]))
for d in store["devices"]:
    if d["name"] == sys.argv[2]:
        w = d.get("wake", {})
        print(w.get("mac", "-"), w.get("lan_id", "-"))
        break
else:
    print("- -")
PY
}

mkdir -p "$A" "$B" "$C"

# A scratch UDP listener on the port the daemons broadcast to. It writes each
# datagram as hex, one per line, so the assertion can be about bytes.
cat >"$RUN/capture.py" <<'PY'
import binascii, socket, sys
port, out, seconds = int(sys.argv[1]), sys.argv[2], float(sys.argv[3])
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", port))
s.settimeout(seconds)
with open(out, "w", buffering=1) as f:
    try:
        while True:
            data, _ = s.recvfrom(4096)
            f.write(binascii.hexlify(data).decode() + "\n")
    except socket.timeout:
        pass
PY

# capture_start <file> <seconds>
capture_start() {
  capture_stop
  python3 "$RUN/capture.py" "$PORT" "$1" "$2" &
  CAPTURE_PID=$!
  # The socket has to be bound before anything broadcasts at it, or the
  # packet goes past an empty port and the assertion blames the daemon.
  for _ in $(seq 1 50); do
    lsof -a -p "$CAPTURE_PID" -iUDP -P 2>/dev/null | grep -q ":$PORT" && return 0
    sleep 0.2
  done
  fail "the capture listener never bound udp/$PORT"
}

# wait_for_packet <file>: the packet is the first thing a wake does, but it is
# behind a couple of probe timeouts, so give it room.
wait_for_packet() {
  for _ in $(seq 1 160); do
    [ -s "$1" ] && return 0
    sleep 0.25
  done
}

# One listener at a time: two would fight over the port, and the second would
# lose silently and then report that nothing was ever broadcast.
capture_stop() {
  [ -n "${CAPTURE_PID:-}" ] || return 0
  kill -TERM "$CAPTURE_PID" 2>/dev/null || true
  wait "$CAPTURE_PID" 2>/dev/null || true
  CAPTURE_PID=""
}

# assert_magic_packet <file> <desc>
assert_magic_packet() {
  local file="$1" desc="$2" want
  want="$(python3 -c 'print("ff"*6 + "'"$B_MAC_HEX"'"*16)')"
  [ -s "$file" ] || fail "$desc: nothing was broadcast to port $PORT"
  grep -qxF "$want" "$file" \
    || fail "$desc: no magic packet for $B_MAC in:"$'\n'"$(cat "$file")"
  # Belt and braces: the frame is 102 bytes, not merely one that starts right.
  local len
  len="$(awk -v w="$want" '$0 == w { print length($0)/2; exit }' "$file")"
  [ "$len" = "102" ] || fail "$desc: the packet is $len bytes, not 102"
  echo "ok: $desc — 102 bytes: 6x ff then $B_MAC sixteen times"
}

# A waits long enough to see a device come back; C gives up quickly, because
# the section C is used for is the one that proves giving up.
start_daemon "$A" "$LAN_FAR"  "de:ad:be:ef:0a:0a" 20
start_daemon "$B" "$LAN_HOME" "$B_MAC"            20
start_daemon "$C" "$LAN_HOME" "de:ad:be:ef:0c:0c" 2

# ---- 1. enrollment records a MAC and a lan-id on both sides ----------------
#
# The facts have to be written down at pairing, because the moment they are
# needed is the moment the device is asleep and cannot be asked for them.

pair "$A" "$A_NAME" "$B" "$B_NAME"
pair "$A" "$A_NAME" "$C" "$C_NAME"
pair "$B" "$B_NAME" "$C" "$C_NAME"

read -r GOT_MAC GOT_LAN <<<"$(wake_facts "$A/orbit.json" "$B_NAME")"
[ "$GOT_MAC" = "$B_MAC" ] || fail "A recorded B's mac as $GOT_MAC:"$'\n'"$(cat "$A/orbit.json")"
[ "$GOT_LAN" = "$LAN_HOME" ] || fail "A recorded B's lan-id as $GOT_LAN"
echo "ok: A's orbit store has B's mac ($GOT_MAC) and lan-id ($GOT_LAN)"

read -r GOT_MAC GOT_LAN <<<"$(wake_facts "$B/orbit.json" "$A_NAME")"
[ "$GOT_MAC" = "de:ad:be:ef:0a:0a" ] || fail "B recorded A's mac as $GOT_MAC"
[ "$GOT_LAN" = "$LAN_FAR" ] || fail "B recorded A's lan-id as $GOT_LAN"
echo "ok: B's orbit store has A's mac ($GOT_MAC) and lan-id ($GOT_LAN)"

# The whole point of a lan-id: A is not on B's network, C is.
read -r _ C_LAN <<<"$(wake_facts "$A/orbit.json" "$C_NAME")"
[ "$C_LAN" = "$LAN_HOME" ] || fail "A recorded C's lan-id as $C_LAN"
[ "$C_LAN" != "$LAN_FAR" ] || fail "the test has not separated the two networks"
echo "ok: A knows C shares a broadcast domain with B, and that it does not"

# ---- 2. ast device check, on this machine and through the mesh ------------

CHECK="$(ASTERISM_HOME="$A" "$AST" device check 2>&1)" || fail "device check failed:"$'\n'"$CHECK"
grep -qF "wake readiness for $A_NAME" <<<"$CHECK" || fail "no heading:"$'\n'"$CHECK"
grep -qE "^wake on magic packet +(ok|no|warn|\?) " <<<"$CHECK" \
  || fail "no wake-on-magic-packet row:"$'\n'"$CHECK"
grep -qE "^(mac address|lan id|broadcast reaches here) " <<<"$CHECK" \
  || fail "the check says nothing about this device's place on the wire:"$'\n'"$CHECK"
# The honesty requirement: at least one row this device admits it cannot check.
grep -qF "means this device cannot check it" <<<"$CHECK" \
  || fail "the check does not explain what ? means:"$'\n'"$CHECK"
if [ "$(uname -s)" = "Darwin" ]; then
  grep -qE "^wake on magic packet +(ok +pmset womp = 1|no +pmset womp = 0|\? )" <<<"$CHECK" \
    || fail "on macOS the check must report pmset womp:"$'\n'"$CHECK"
  grep -qE "^power source " <<<"$CHECK" \
    || fail "on macOS the check must report the power source (battery never wakes):"$'\n'"$CHECK"
  grep -qE "^sleep vs shutdown +warn " <<<"$CHECK" \
    || fail "on macOS the check must warn about full shutdown:"$'\n'"$CHECK"
fi
echo "ok: ast device check reports this device's readiness"
echo "--- ast device check on this Mac ---"
# shellcheck disable=SC2001  # a prefix on every line, which parameter
# expansion cannot do
sed 's/^/    /' <<<"$CHECK"
echo "---"

expect "device check can be asked of another device" "wake readiness for $B_NAME" \
  env ASTERISM_HOME="$A" "$AST" device check --on "$B_NAME"

# ---- 3. waking a device that is already awake ------------------------------

expect "waking an online device is a no-op that says so" \
  "$B_NAME is already online" \
  env ASTERISM_HOME="$A" "$AST" device wake "$B_NAME"

refute "waking a device nobody has heard of is refused locally" \
  "no device named \"nowhere\" in this orbit" \
  env ASTERISM_HOME="$A" "$AST" device wake nowhere

# ---- 4. A is on the wrong LAN, so C sends the packet -----------------------
#
# B stops answering: from A, that is exactly what a sleeping device looks
# like. A cannot broadcast to B's network itself, so it has to find a device
# that can — and C is standing there. The packet C puts on the wire is caught
# and read byte by byte.

sleep_daemon "$B"
capture_start "$RUN/relayed.hex" 45

ASTERISM_HOME="$A" "$AST" device wake "$B_NAME" >"$A/wake.out" 2>&1 &
WAKE_PID=$!

# The packet goes out early; the rest of the command is A watching for B to
# check in, which is section 4's other half.
wait_for_packet "$RUN/relayed.hex"
assert_magic_packet "$RUN/relayed.hex" "C broadcast a magic packet for B"

# B "wakes up". The magic packet is not what woke it — no test can arrange
# that, see the header — but A's half of the conversation is entirely real: it
# is watching mesh presence and reporting what it sees, which is the only
# confirmation a wake ever gets.
rouse_daemon "$B"
wait "$WAKE_PID" || fail "ast device wake did not report success:"$'\n'"$(cat "$A/wake.out")"

grep -qF "$C_NAME is awake on $B_NAME's network ($LAN_HOME)" "$A/wake.out" \
  || fail "A did not pick C as the broadcaster:"$'\n'"$(cat "$A/wake.out")"
grep -qF "magic packet for $B_MAC sent to" "$A/wake.out" \
  || fail "A did not report the packet:"$'\n'"$(cat "$A/wake.out")"
grep -qF "255.255.255.255:$PORT" "$A/wake.out" \
  || fail "the packet did not go to the broadcast address:"$'\n'"$(cat "$A/wake.out")"
grep -qE "$B_NAME is online after [0-9]+s" "$A/wake.out" \
  || fail "A did not notice B checking in:"$'\n'"$(cat "$A/wake.out")"
echo "ok: A found the one peer on B's LAN, it broadcast, and A saw B come back"
echo "--- ast device wake $B_NAME, from A ---"
sed 's/^/    /' "$A/wake.out"
echo "---"

# ---- 5. the requester is on the target's LAN: no mesh hop ------------------
#
# The same command run on C. C is standing on B's network itself, so there is
# nobody to ask and the packet goes out from here. B's daemon is properly
# killed this time, not merely stopped: a device that is gone rather than
# asleep is the case where the report has to stay honest.

stop_daemon "$B"
capture_start "$RUN/local.hex" 20

# C gives up after 2s, so this fails — truthfully, because B is not coming
# back. That is the report, not an error in the sending.
refute "a wake reports honestly that the device did not turn up" \
  "$B_NAME has not come online within 2s" \
  env ASTERISM_HOME="$C" "$AST" device wake "$B_NAME"
capture_stop
assert_magic_packet "$RUN/local.hex" "C broadcast for B with no mesh hop"

CLOCAL="$(ASTERISM_HOME="$C" "$AST" device wake "$B_NAME" 2>&1 || true)"
grep -qF "this device is on $B_NAME's network ($LAN_HOME)" <<<"$CLOCAL" \
  || fail "C went looking for a peer instead of broadcasting itself:"$'\n'"$CLOCAL"
if grep -qF "asking it to broadcast" <<<"$CLOCAL"; then
  fail "C asked somebody else to send a packet it could send itself:"$'\n'"$CLOCAL"
fi
echo "ok: a device on the target's own LAN sends the packet without the mesh"

# ---- 6. nobody awake on that network, in the spec's exact words ------------
#
# With C gone too, A's orbit has no awake device on B's LAN. The message is
# fixed and the assertion is on the whole line: "timed out" would be a lie
# about a working system, and the fix — an always-on beacon — only makes
# sense if the user is told what actually happened.

stop_daemon "$C"
NOPEER="$(ASTERISM_HOME="$A" "$AST" device wake "$B_NAME" 2>&1 || true)"
grep -qxF "error: no awake device on $B_NAME's network" <<<"$NOPEER" \
  || fail "not the spec's message, verbatim:"$'\n'"$NOPEER"
grep -qF "it is the orbit's beacon" <<<"$NOPEER" \
  || fail "the refusal does not point at the beacon that would fix it:"$'\n'"$NOPEER"
echo "ok: no awake device on $B_NAME's network — said exactly, with the remedy"
echo "--- the no-peer path ---"
# shellcheck disable=SC2001  # a prefix on every line, which parameter
# expansion cannot do
sed 's/^/    /' <<<"$NOPEER"
echo "---"

echo
# ---- 7. and the same thing from A, once A is on B's LAN --------------------
#
# Section 6 was A with nowhere to send from. Move A onto B's network — the
# laptop came home — and the same command, unchanged, sends the packet itself.
# B's daemon is still killed and C is still gone, so there is no mesh hop
# available at all here, which is what makes this a clean test of the path
# that does not use one.

stop_daemon "$A"
start_daemon "$A" "$LAN_HOME" "de:ad:be:ef:0a:0a" 2
capture_start "$RUN/from-a.hex" 25

refute "A on B's own LAN sends the packet itself" \
  "$B_NAME has not come online within 2s" \
  env ASTERISM_HOME="$A" "$AST" device wake "$B_NAME"
capture_stop
assert_magic_packet "$RUN/from-a.hex" "A broadcast for B from B's own network"

echo "NOTE: no machine was asleep during this test, and none was woken. A real"
echo "      wake needs firmware, a NIC that keeps power, and a switch that"
echo "      floods the broadcast — none of which a test can supply. What is"
echo "      proved above is the software half: who is chosen to send, that it"
echo "      sends, and that the 102 bytes on the wire are a magic packet for"
echo "      the right MAC."
echo "WAKE E2E GREEN"
