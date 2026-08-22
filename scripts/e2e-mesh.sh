#!/usr/bin/env bash
# End-to-end for the device mesh and for orbit-global instance identity: two
# daemons on one host, each with its own ASTERISM_HOME, pairing over loopback
# and then behaving as one pool of parts.
#
# invite -> add -> devices -> proxied ls/status -> one flat namespace ->
# transparent resolution -> ssh through the mesh -> a collision and its rename
# -> ping -> refusal -> offline, asserting on output CONTENT the way
# scripts/e2e.sh does.
#
# Most of it runs against a 1 MiB qcow2 that is never booted, because the
# registry only needs something to list. Section 8 is the exception and boots a
# real Debian guest on B once, because "ssh a guest whose cpu is on another
# device" is not provable against a fake: the bytes have to reach a real sshd.
# It reuses the image already in ~/.asterism/images rather than downloading
# one, and never writes there.
#
# ASTERISM_MESH=local keeps both endpoints on loopback: no relays, no discovery
# service, no packet that leaves the machine. That is the mode the mesh crate's
# own tests use, and it is also the honest one for these assertions — an orbit's
# semantics do not depend on whose relay is in the middle, and asserting them
# through n0's infrastructure would mean a network hiccup could fail a test
# about instance names.
#
# It is no longer the daemon's default, though: discovery is. What that mode
# does, and the reachability it buys, is scripts/e2e-discovery.sh — which
# deliberately DOES use the public path, because that is the only way to prove
# a device can be found by its key.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export PATH="$HOME/.cargo/bin:$PATH"
cd "$ROOT"
# shellcheck source-path=SCRIPTDIR source=lib/harness.sh
. "$ROOT/scripts/lib/harness.sh"
harness_begin mesh
harness_binaries "$ROOT"

# Fresh, SHORT homes: unix socket paths are capped near 104 bytes, and these
# are deliberately nowhere near the user's own ~/.asterism.
RUN="/private/tmp/ast-mesh-$$"
A="$RUN/a"
B="$RUN/b"
C="$RUN/c"
A_NAME="orbit-a-$$"
B_NAME="orbit-b-$$"
C_NAME="orbit-c-$$"
INST="mesh-e2e"
FAR="far-e2e"       # the one instance that really boots, on B
DUP="dup-e2e"       # the name both devices claim during a partition
IMAGE="${E2E_IMAGE:-debian:13}"

# ---- the processes this test starts ----------------------------------------
#
# Everything started here writes down its own pid inside its own
# ASTERISM_HOME: astd in $home/astd.pid, each guest's qemu in
# $home/instances/<name>/qemu.pid or VZ helper in vz.pid, each storage daemon in
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
  # Evidence before the homes go: a daemon log and a console log are the
  # whole account of a failure, and they live in the directory below.
  for home in "$A" "$B" "$C"; do
    harness_keep_home "$home" "$(basename "$home")"
  done
  local home f pid
  # The daemons first: astd is what restarts a guest it notices die, so a
  # guest killed while its daemon is up can come straight back.
  for home in "$A" "$B" "$C"; do
    kill_pidfile "$home/astd.pid"
  done
  # Then what they left running. Both outlive astd by design.
  for home in "$A" "$B" "$C"; do
    for f in "$home"/instances/*/qemu.pid "$home"/instances/*/vz.pid; do kill_pidfile "$f"; done
    for f in "$home"/volumes/*/nbd-e*.pid; do kill_pidfile "$f"; done
    # Covers older backends whose only record was state.json. New VZ helpers
    # were stopped above through their daemon-independent vz.pid.
    for pid in $(grep -o '"pid":[0-9]*' "$home/state.json" 2>/dev/null | cut -d: -f2 || true); do
      kill_pid "$pid"
    done
  done
  rm -rf "$RUN"
  harness_artifacts_note
}
trap cleanup EXIT

fail() { echo "MESH E2E FAIL: $*" >&2; exit 1; }

# expect <desc> <needle> <cmd...>: run cmd, require success AND the needle
# in its combined output.
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

# Bring a daemon up in the foreground of its own background job, so its log is
# a file we can assert on. `ast` would spawn one on demand, but then its stderr
# would go to /dev/null and step 5 has a refusal to prove.
start_daemon() {
  local home="$1"
  mkdir -p "$home"
  ( ASTERISM_HOME="$home" ASTERISM_MESH=local "$ASTD" >"$home/astd.log" 2>&1 & )
  for _ in $(seq 1 50); do
    grep -q "on the mesh as" "$home/astd.log" 2>/dev/null && return 0
    sleep 0.2
  done
  fail "astd for $home did not come up:"$'\n'"$(cat "$home/astd.log" 2>/dev/null)"
}

stop_daemon() {
  local home="$1"
  local pid
  pid="$(cat "$home/astd.pid" 2>/dev/null || true)"
  [ -n "$pid" ] || fail "no pid file for the daemon in $home"
  kill -TERM "$pid" 2>/dev/null || true
  for _ in $(seq 1 50); do
    kill -0 "$pid" 2>/dev/null || return 0
    sleep 0.2
  done
  kill -KILL "$pid" 2>/dev/null || true
}

mkdir -p "$A" "$B" "$C"
start_daemon "$A"
start_daemon "$B"

# ---- 1. A invites, B redeems the ticket, both stores list each other --------
#
# --yes stands in for the human at each terminal. It is the one thing a script
# cannot honestly do, which is why it is a flag and not the default.

ASTERISM_HOME="$A" "$AST" device invite --name "$A_NAME" --yes >"$A/invite.out" 2>&1 &
INVITE_PID=$!

TICKET=""
for _ in $(seq 1 100); do
  TICKET="$(grep -o 'astdev1[a-z0-9]*' "$A/invite.out" 2>/dev/null | head -1 || true)"
  [ -n "$TICKET" ] && break
  sleep 0.2
done
[ -n "$TICKET" ] || fail "no ticket printed by ast device invite:"$'\n'"$(cat "$A/invite.out")"
echo "ok: invite printed a ticket (${TICKET:0:20}...)"

ASTERISM_HOME="$B" "$AST" device add "$TICKET" --name "$B_NAME" --yes >"$B/add.out" 2>&1 \
  || fail "ast device add failed:"$'\n'"$(cat "$B/add.out")"
wait "$INVITE_PID" || fail "ast device invite failed:"$'\n'"$(cat "$A/invite.out")"

grep -qF "$B_NAME  " "$A/invite.out" || fail "A did not report pairing with B:"$'\n'"$(cat "$A/invite.out")"
grep -qF "paired" "$A/invite.out" || fail "A did not report a pairing:"$'\n'"$(cat "$A/invite.out")"
grep -qF "$A_NAME  " "$B/add.out" || fail "B did not report pairing with A:"$'\n'"$(cat "$B/add.out")"
echo "ok: both sides reported a pairing"

# The SAS is the whole point of the exchange: two terminals, one number.
sas_of() { grep -oE '^ +[0-9]{3} [0-9]{3}$' "$1" | tr -d ' ' | head -1 || true; }
SAS_A="$(sas_of "$A/invite.out")"
SAS_B="$(sas_of "$B/add.out")"
[ -n "$SAS_A" ] || fail "no six-digit code on A:"$'\n'"$(cat "$A/invite.out")"
[ "$SAS_A" = "$SAS_B" ] || fail "the two terminals showed different codes: A=$SAS_A B=$SAS_B"
echo "ok: both terminals showed the same code ($SAS_A)"

# The stores are the trust root, so assert on them and not only on the output.
B_ID="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["devices"][0]["device_id"])' "$A/orbit.json")"
grep -qF "\"name\": \"$B_NAME\"" "$A/orbit.json" || fail "A's orbit does not list B:"$'\n'"$(cat "$A/orbit.json")"
grep -qF "\"name\": \"$A_NAME\"" "$B/orbit.json" || fail "B's orbit does not list A:"$'\n'"$(cat "$B/orbit.json")"
echo "ok: both orbit stores list each other"

# ---- 2. ast devices on A shows B online ------------------------------------

DEVICES="$(ASTERISM_HOME="$A" "$AST" devices 2>&1)" || fail "ast devices failed:"$'\n'"$DEVICES"
grep -qE "^$A_NAME \(this device\) +\S+ +online" <<<"$DEVICES" \
  || fail "A did not mark itself as self and online:"$'\n'"$DEVICES"
grep -qE "^$B_NAME +\S+ +online +direct" <<<"$DEVICES" \
  || fail "A does not see B online over a direct path:"$'\n'"$DEVICES"
echo "ok: ast devices shows this device and B online"

# ---- 3. --device still asks one device directly ----------------------------
#
# A tiny qcow2 that is never booted. `ast create` records an instance against
# the image it is given, and `ls`/`status` read the registry — which is all the
# proxy has to carry.
#
# Nothing here is how a user reaches an instance any more; section 5 is. This
# is the debugging override kept working: aim a frame at one device's daemon
# and get that daemon's own answer back.

DISK="$B/tiny.qcow2"
qemu-img create -f qcow2 "$DISK" 1M >/dev/null 2>&1 || fail "qemu-img create failed (is qemu installed?)"
expect "create on B" "$INST  defined" \
  env ASTERISM_HOME="$B" "$AST" create "$INST" --image "$DISK" --mem 512M --disk 1G

expect "ls proxied from A to B" "$INST" \
  env ASTERISM_HOME="$A" "$AST" --device "$B_NAME" ls
expect "status proxied from A to B" "name:    $INST" \
  env ASTERISM_HOME="$A" "$AST" --device "$B_NAME" status "$INST"

# The proxy must reach B and not answer out of A's own shard, which is the
# failure mode that would otherwise pass every assertion above.
LOCAL_LS="$(ASTERISM_HOME="$A" "$AST" ls --local 2>&1)"
grep -qF "no instances" <<<"$LOCAL_LS" \
  || fail "A supplies instances of its own, so the proxy assertions prove nothing:"$'\n'"$LOCAL_LS"
echo "ok: B supplies the instance's cpu and A supplies none"

# A name that is in nobody's orbit is a local error, with a way out in it.
refute "an unknown device name is refused locally" "no device named" \
  env ASTERISM_HOME="$A" "$AST" --device nowhere ls

# ---- 4. one flat namespace across the orbit --------------------------------
#
# The point of the model: an instance name means one instance in the whole
# orbit. "The laptop's dev" is not something a user can say, so `ast create`
# has to claim a name against every device before admitting it — and the
# refusal has to say where the parts of the existing instance come from,
# because that is the only useful thing left to tell them.

refute "a name already used in the orbit cannot be created again" \
  "instance \"$INST\" already exists in this orbit (cpu/ram on $B_NAME)" \
  env ASTERISM_HOME="$A" "$AST" create "$INST" --image "$DISK" --mem 512M --disk 1G

# ...and the refusal left nothing behind on A.
LOCAL_LS="$(ASTERISM_HOME="$A" "$AST" ls --local 2>&1)"
grep -qF "no instances" <<<"$LOCAL_LS" \
  || fail "the refused create wrote a row on A anyway:"$'\n'"$LOCAL_LS"
echo "ok: a refused claim leaves no half-created instance"

# `ast ls` is the orbit's registry, not this device's shard of it, so the same
# one row appears on both daemons — with a CPU column saying which device is
# supplying it, and no per-device grouping anywhere.
for home in "$A" "$B"; do
  ORBIT_LS="$(ASTERISM_HOME="$home" "$AST" ls 2>&1)" || fail "ast ls failed:"$'\n'"$ORBIT_LS"
  grep -qE "^NAME +STATUS +IMAGE +SHAPE +CPU +AGE +SSH$" <<<"$ORBIT_LS" \
    || fail "ast ls has no CPU column:"$'\n'"$ORBIT_LS"
  grep -qE "^$INST +defined .*$B_NAME" <<<"$ORBIT_LS" \
    || fail "ast ls does not show $INST with its cpu on $B_NAME:"$'\n'"$ORBIT_LS"
  [ "$(grep -c "^$INST " <<<"$ORBIT_LS")" = "1" ] \
    || fail "$INST appears more than once, so the namespace is not flat:"$'\n'"$ORBIT_LS"
done
echo "ok: ast ls shows one namespace from both daemons, with a CPU column"

# --local is the debugging view, and it is the one that differs per device.
expect "ls --local on B holds the row" "$INST" \
  env ASTERISM_HOME="$B" "$AST" ls --local
expect "ls --local on A holds nothing" "no instances" \
  env ASTERISM_HOME="$A" "$AST" ls --local

# ---- 5. resolution without naming a device ---------------------------------
#
# The instance lives on B. Every one of these is typed on A, none of them says
# --device, and none of them has any way to know which device is involved.

expect "status resolves across the orbit" "name:    $INST" \
  env ASTERISM_HOME="$A" "$AST" status "$INST"

# `ast status` renders the parts, and every part names the device it comes
# from. cpu and ram are one part because they are sourced as a pair.
PARTS="$(ASTERISM_HOME="$A" "$AST" status "$INST" 2>&1)"
grep -qE "^  cpu/ram +$B_NAME +2 cores" <<<"$PARTS" \
  || fail "no cpu/ram part sourced from $B_NAME:"$'\n'"$PARTS"
grep -qE "^  disk +$B_NAME +.*\(follows cpu\)" <<<"$PARTS" \
  || fail "the disk does not follow the cpu:"$'\n'"$PARTS"
grep -qE "^  network +$B_NAME +.*\(exit default: same as cpu\)" <<<"$PARTS" \
  || fail "egress is not defaulted to the cpu device:"$'\n'"$PARTS"
grep -qE "^  gpu +- +none$" <<<"$PARTS" \
  || fail "no gpu row:"$'\n'"$PARTS"
# No device has a privileged relationship to an instance, so nothing in the
# output may imply one.
if grep -qi "anchor" <<<"$PARTS"; then fail "ast status still speaks of anchors:"$'\n'"$PARTS"; fi
echo "ok: ast status renders parts, each naming the device that supplies it"

expect "snapshots resolve across the orbit" "no snapshots" \
  env ASTERISM_HOME="$A" "$AST" snapshots "$INST"

# A name nowhere in the orbit is refused in the orbit's words, not one
# device's.
refute "an unknown instance is unknown to the orbit" "no instance named \"ghost\" in this orbit" \
  env ASTERISM_HOME="$A" "$AST" status ghost

# ---- 6. ast ping reports a latency -----------------------------------------

PING="$(ASTERISM_HOME="$A" "$AST" ping "$B_NAME" 2>&1)" || fail "ast ping failed:"$'\n'"$PING"
grep -qE "^pong from $B_NAME \(\S+\) via direct in [0-9]+\.[0-9]ms$" <<<"$PING" \
  || fail "ast ping did not report a latency:"$'\n'"$PING"
echo "ok: ast ping — $PING"

# ---- 7. a real guest on B, booted and reached from A -----------------------
#
# The only section that boots anything, and the only one that can prove the
# ssh splice: `ast ssh` on A has to end up talking to a real sshd on a guest
# whose cpu and ram are being supplied by B. A's daemon binds a loopback port,
# pipes it over a mesh stream to B's daemon, and B's daemon connects that to
# the guest's forwarded ssh port. Neither `ast` nor the user names a device.

# From the harness's own cache, never ~/.asterism: that one belongs to the
# user's daemon and may be written to while this is reading it.
harness_cache_image "$AST" "$IMAGE" || fail "could not cache $IMAGE"
harness_seed_images "$B"
ASTERISM_HOME="$B" "$AST" pull "$IMAGE" >/dev/null 2>&1 \
  || fail "no $IMAGE image available for B (pull it once: ast pull $IMAGE)"

expect "create the bootable instance on B" "$FAR  defined" \
  env ASTERISM_HOME="$B" "$AST" create "$FAR" --image "$IMAGE" --mem 2G --disk 10G

# Typed on A, about an instance A does not hold. No --device anywhere.
expect "up resolves across the orbit" "$FAR  running" \
  env ASTERISM_HOME="$A" "$AST" up "$FAR"

# The guest's own idea of who it is, fetched over the splice. `hostname`
# answering with the instance name is proof the bytes reached the guest and
# not, say, B's daemon being helpful.
SSH_OUT="$(ASTERISM_HOME="$A" "$AST" ssh "$FAR" -- "hostname; uname -s" 2>&1)" \
  || fail "ast ssh from A failed:"$'\n'"$SSH_OUT"
grep -qF "$FAR" <<<"$SSH_OUT" || fail "the guest did not answer with its name:"$'\n'"$SSH_OUT"
grep -qF "Linux" <<<"$SSH_OUT" || fail "that was not a Linux guest:"$'\n'"$SSH_OUT"
echo "ok: ast ssh $FAR from A reached a real guest booted on B"

# ssh's exit status has to survive the splice too, or scripts on top of it
# cannot tell success from failure.
if ASTERISM_HOME="$A" "$AST" ssh "$FAR" -- "exit 7" >/dev/null 2>&1; then
  fail "a failing remote command reported success through the splice"
fi
echo "ok: the guest's exit status survives the splice"

# The loopback listener belongs to the `ast ssh` that asked for it, and to
# nothing else: when ssh exits, ast exits, its socket to the daemon closes and
# the listener goes with it. A's daemon speaks UDP to the mesh and holds no TCP
# listener of its own, so "how many is it listening on" is a clean question.
A_PID="$(cat "$A/astd.pid")"
# lsof exits 1 when it finds nothing, which is the answer we are hoping for.
HELD="$( { lsof -a -p "$A_PID" -iTCP -sTCP:LISTEN -t 2>/dev/null || true; } | wc -l | tr -d ' ')"
[ "$HELD" = "0" ] \
  || fail "A's daemon is still holding $HELD ssh listener(s) after ssh exited"
echo "ok: the spliced listener was torn down when ssh exited"
expect "logs are readable from A over the mesh" "cloud-init" \
  env ASTERISM_HOME="$A" "$AST" logs "$FAR" -n 400
refute "following a log across the orbit says so rather than hanging" \
  "not built yet" env ASTERISM_HOME="$A" "$AST" logs "$FAR" -f

expect "down resolves across the orbit" "$FAR  stopped" \
  env ASTERISM_HOME="$A" "$AST" down "$FAR"
expect "rm resolves across the orbit" "$FAR  removed" \
  env ASTERISM_HOME="$A" "$AST" rm "$FAR"

# ---- 8. a collision the partition hid, and the rename that ends it ---------
#
# `ast create` claims a name against every device it can reach, and a device
# it cannot reach is not a veto: an orbit that stops accepting work because a
# laptop shut its lid is a quorum, not a pool. The cost is that two devices
# out of touch can both admit one name, and the rule for that is that the
# collision is detected when they can see each other again, where the newer
# creation loses and has to be renamed.
#
# The partition is simulated on A's side, by pointing A's orbit store at an
# address B is not on. That is what "B is unreachable" looks like from A, and
# unlike stopping B it does not change B's address underneath the test.

expect "B claims the name first" "$DUP  defined" \
  env ASTERISM_HOME="$B" "$AST" create "$DUP" --image "$DISK" --mem 512M --disk 1G

cp "$A/orbit.json" "$A/orbit.intact.json"
stop_daemon "$A"
python3 - "$A/orbit.json" <<'PY'
import json, sys
store = json.load(open(sys.argv[1]))
for device in store["devices"]:
    device["addrs"] = ["127.0.0.1:1"]   # nothing answers here
json.dump(store, open(sys.argv[1], "w"), indent=2)
PY
start_daemon "$A"

# The whole point of the rule: this succeeds.
expect "a device out of reach does not veto a claim" "$DUP  defined" \
  env ASTERISM_HOME="$A" "$AST" create "$DUP" --image "$DISK" --mem 512M --disk 1G

stop_daemon "$A"
cp "$A/orbit.intact.json" "$A/orbit.json"
start_daemon "$A"

# Assembling the orbit view is the moment the two shards are compared, so it
# is where the collision surfaces.
HEALED="$(ASTERISM_HOME="$A" "$AST" ls 2>&1)" || fail "ast ls failed:"$'\n'"$HEALED"
[ "$(grep -c "^$DUP " <<<"$HEALED")" = "2" ] \
  || fail "the healed orbit does not show both instances called $DUP:"$'\n'"$HEALED"
grep -qE "^$DUP +defined .*$B_NAME" <<<"$HEALED" \
  || fail "B's $DUP should be untouched — it was created first:"$'\n'"$HEALED"
grep -qE "^$DUP +conflict .*$A_NAME" <<<"$HEALED" \
  || fail "A's $DUP is the newer one and should be in conflict:"$'\n'"$HEALED"
grep -qF "ast rename $DUP <new-name>" <<<"$HEALED" \
  || fail "ast ls does not say how to resolve the conflict:"$'\n'"$HEALED"
echo "ok: the healed orbit found the collision and marked the newer creation"

refute "a conflicted instance refuses to boot" \
  "shares its name with another instance in this orbit (cpu/ram on $B_NAME)" \
  env ASTERISM_HOME="$A" "$AST" up "$DUP"
refute "and says which command ends it" "ast rename $DUP <new-name>" \
  env ASTERISM_HOME="$A" "$AST" up "$DUP"

expect "renaming resolves the collision" "$DUP  renamed to $DUP-a" \
  env ASTERISM_HOME="$A" "$AST" rename "$DUP" "$DUP-a"

RESOLVED="$(ASTERISM_HOME="$A" "$AST" ls 2>&1)" || fail "ast ls failed:"$'\n'"$RESOLVED"
grep -qE "^$DUP +defined .*$B_NAME" <<<"$RESOLVED" \
  || fail "B's $DUP did not survive the rename:"$'\n'"$RESOLVED"
grep -qE "^$DUP-a +defined .*$A_NAME" <<<"$RESOLVED" \
  || fail "the renamed instance is not in the orbit under its new name:"$'\n'"$RESOLVED"
if grep -qF "conflict" <<<"$RESOLVED"; then
  fail "the conflict outlived the rename that was supposed to end it:"$'\n'"$RESOLVED"
fi
echo "ok: both instances are usable again under distinct names"

# A rename cannot walk into another collision either.
refute "renaming onto a name the orbit already uses is refused" \
  "already exists in this orbit (cpu/ram on $B_NAME)" \
  env ASTERISM_HOME="$A" "$AST" rename "$DUP-a" "$DUP"

expect "the renamed instance works" "$DUP-a  running" \
  env ASTERISM_HOME="$A" "$AST" up "$DUP-a"
expect "and stops" "$DUP-a  stopped" env ASTERISM_HOME="$A" "$AST" down "$DUP-a"

# ---- 9. an unpaired third daemon is refused --------------------------------
#
# C is given B's key and address by hand — everything a paired device would
# have — but B has never heard of C. Membership is checked against B's store on
# the accept path, so the connection dies before C can ask B anything.

start_daemon "$C"
python3 - "$C/orbit.json" "$C_NAME" "$B_NAME" "$B_ID" "$A/orbit.json" <<'PY'
import json, sys
out, self_name, peer_name, peer_id, donor = sys.argv[1:6]
addrs = json.load(open(donor))["devices"][0]
json.dump({
    "version": 1,
    "self_name": self_name,
    "devices": [{
        "name": peer_name,
        "device_id": peer_id,
        "addrs": addrs["addrs"],
        "relays": addrs["relays"],
        "added_at": addrs["added_at"],
    }],
}, open(out, "w"), indent=2)
PY
# The store is read at startup, so C has to be restarted to pick up the forgery.
stop_daemon "$C"
start_daemon "$C"

refute "an unpaired device cannot reach B" "not in this orbit" \
  env ASTERISM_HOME="$C" "$AST" --device "$B_NAME" ls
grep -qF "not in this orbit" "$B/astd.log" \
  || fail "B did not log a refusal:"$'\n'"$(cat "$B/astd.log")"
echo "ok: B refused the unpaired device and said so in its log"

# And B's orbit is untouched by the attempt.
if grep -qF "$C_NAME" "$B/orbit.json"; then fail "the refused device ended up in B's orbit"; fi
echo "ok: B's orbit is unchanged"

# ---- 10. B goes away, A says so --------------------------------------------

stop_daemon "$B"
DEVICES="$(ASTERISM_HOME="$A" "$AST" devices 2>&1)" || fail "ast devices failed:"$'\n'"$DEVICES"
grep -qE "^$B_NAME +\S+ +offline +-" <<<"$DEVICES" \
  || fail "A still thinks B is online:"$'\n'"$DEVICES"
echo "ok: ast devices shows B offline once its daemon is gone"

# The instances B supplies did not stop existing when B stopped answering, so
# they stay in the listing — from the last-seen cache, with the device still
# named and the state honestly marked unknown. Dropping them would read as
# "deleted", which would be a lie about somebody's data.
GONE="$(ASTERISM_HOME="$A" "$AST" ls 2>&1)" || fail "ast ls failed:"$'\n'"$GONE"
grep -qE "^$INST +unknown .*$B_NAME" <<<"$GONE" \
  || fail "B's instances vanished from the orbit view when B did:"$'\n'"$GONE"
grep -qE "^$DUP +unknown .*$B_NAME" <<<"$GONE" \
  || fail "B's $DUP vanished from the orbit view:"$'\n'"$GONE"
grep -qF "the device supplying that instance's cpu is out of touch" <<<"$GONE" \
  || fail "ast ls does not explain what unknown means:"$'\n'"$GONE"
# A's own instance is still live in the same table: one namespace, two states.
grep -qE "^$DUP-a +stopped .*$A_NAME" <<<"$GONE" \
  || fail "A's own instance lost its live state:"$'\n'"$GONE"
echo "ok: an out-of-touch device's instances are listed as unknown, not dropped"

refute "a command aimed at a dead device says so" "is its astd running?" \
  env ASTERISM_HOME="$A" "$AST" --device "$B_NAME" ls

echo "MESH E2E GREEN"
