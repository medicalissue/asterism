#!/usr/bin/env bash
# End-to-end for the mesh's CONFIGURED mode: discovery. Two daemons on one
# host, each with its own ASTERISM_HOME, both pointed at a relay and a
# directory by the variables below — so they bind relay-backed endpoints and
# publish their addresses, exactly as a logged-in user's two machines would.
#
# WHY THE VARIABLES ARE SET HERE. Discovery is no longer a default. A device
# with no login and no configuration has no relay and no directory and binds
# local-only; that is the product decision AST-119 recorded, and it means this
# suite has to say which servers it is testing against rather than inheriting
# somebody's. The defaults below are n0's public infrastructure, which is a
# convenient public deployment to test against and is *not* what a stock
# Asterism device talks to. Override ASTERISM_RELAY_URL / ASTERISM_PKARR_RELAY
# / ASTERISM_DNS_ORIGIN to run this against your own.
#
# This is the sibling of scripts/e2e-mesh.sh and not a replacement for it.
# e2e-mesh.sh pins ASTERISM_MESH=local and proves the orbit's semantics with no
# packet leaving the machine; this one proves the part that cannot be tested
# that way — that a device can be found by its key alone, over infrastructure
# it does not run.
#
#   1. both daemons reach a relay and say whose infrastructure they joined
#   2. pairing works with the inviter advertising NO usable IP address
#   3. ast devices / ast ping report a real path (direct or relay), not "-"
#   4. a proxied command works end to end over that path
#   5. the orbit store learns where the peer answered from, with a timestamp
#   6. a peer whose stored addresses are WRONG is still reached, by discovery
#   7. a peer whose stored addresses are ABSENT is still reached, by discovery
#
# 6 and 7 are the stale-address gap closing. Under local mode a peer whose
# daemon came back on a different port was simply gone; here it is found under
# its public key wherever it went, and the store is corrected.
#
# WHAT THIS TALKS TO. Unless overridden, n0's public relay fleet and n0's
# pkarr/DNS server, to which it publishes two throwaway device keys and this
# machine's addresses. It needs working internet. It is not hermetic and it is
# not meant to be: an assertion that discovery works, mocked, asserts nothing.
#
# WHAT ONE MACHINE CANNOT PROVE. See the ASTERISM_E2E_REAL_NET section at the
# bottom.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export PATH="$HOME/.cargo/bin:$PATH"
cd "$ROOT"
# shellcheck source-path=SCRIPTDIR source=lib/harness.sh
. "$ROOT/scripts/lib/harness.sh"
harness_begin discovery
harness_binaries "$ROOT"

# The infrastructure under test, stated rather than inherited. See the header.
export ASTERISM_RELAY_URL="${ASTERISM_RELAY_URL:-https://use1-1.relay.n0.iroh.link./}"
export ASTERISM_PKARR_RELAY="${ASTERISM_PKARR_RELAY:-https://dns.iroh.link/pkarr}"
export ASTERISM_DNS_ORIGIN="${ASTERISM_DNS_ORIGIN:-dns.iroh.link.}"
echo "discovery e2e is testing against:"
echo "  relay $ASTERISM_RELAY_URL"
echo "  pkarr $ASTERISM_PKARR_RELAY"
echo "  dns   $ASTERISM_DNS_ORIGIN"

# Fresh, SHORT homes: unix socket paths are capped near 104 bytes, and these
# are deliberately nowhere near the user's own ~/.asterism.
RUN="/private/tmp/ast-disc-$$"
A="$RUN/a"
B="$RUN/b"
A_NAME="disc-a-$$"
B_NAME="disc-b-$$"
INST="disc-e2e"

cleanup() {
  for home in "$A" "$B"; do
    [ -d "$home" ] || continue
    harness_keep_home "$home" "$(basename "$home")"
    ASTERISM_HOME="$home" "$AST" rm "$INST" >/dev/null 2>&1 || true
  done
  # Only these two homes' daemons. The `pkill -f "$ASTD"` that used to be
  # here reached every astd built at that path — a developer's own, running
  # against their own home, with their own guests under it.
  harness_reap
  rm -rf "$RUN"
  harness_artifacts_note
}
trap cleanup EXIT

fail() { echo "DISCOVERY E2E FAIL: $*" >&2; exit 1; }

expect() {
  local desc="$1" needle="$2"; shift 2
  local out
  out="$("$@" 2>&1)" || fail "$desc: command failed:"$'\n'"$out"
  grep -qF "$needle" <<<"$out" || fail "$desc: expected \"$needle\" in:"$'\n'"$out"
  echo "ok: $desc"
}

# start_daemon <home> [extra env assignments...]
#
# ASTERISM_MESH is NOT set: this script is about what an unconfigured device
# does. The daemon prints its discovery line once it has a relay, and that line
# is the readiness signal — a daemon that is merely bound has not yet published
# anything and cannot be found by key.
start_daemon() {
  local home="$1"; shift
  mkdir -p "$home"
  # Registered before it is started, so that a daemon which comes up and then
  # wedges is still something the cleanup trap can reach.
  harness_own_home "$home"
  ( ASTERISM_HOME="$home" "$@" "$ASTD" >>"$home/astd.log" 2>&1 & )
  for _ in $(seq 1 300); do
    grep -q "discovery: published" "$home/astd.log" 2>/dev/null && return 0
    if grep -q "discovery: no relay reachable" "$home/astd.log" 2>/dev/null; then
      fail "no relay reachable from this machine — this test needs internet:"$'\n'"$(cat "$home/astd.log")"
    fi
    sleep 0.2
  done
  fail "astd for $home never reached a relay:"$'\n'"$(cat "$home/astd.log" 2>/dev/null)"
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

# The path column, for one peer, out of `ast devices` on one home.
path_of() {
  ASTERISM_HOME="$1" "$AST" devices 2>&1 | awk -v n="$2" '$1 == n { print $4 }'
}

# The measurement and transition fields for one peer. Device names contain no
# spaces, so these stay stable even though the table is padded for humans.
telemetry_of() {
  ASTERISM_HOME="$1" "$AST" devices 2>&1 \
    | awk -v n="$2" '$1 == n { print $5, $6, $7 }'
}

# A real path is direct or relay. On one machine it will usually be direct —
# the two endpoints share a loopback — and that is a pass: the assertion is
# that the word came off the live connection, not that it is a particular one.
assert_real_path() {
  local desc="$1" got="$2"
  case "$got" in
    direct|relay) echo "ok: $desc — $got" ;;
    "") fail "$desc: no path reported at all" ;;
    *) fail "$desc: expected direct or relay, got \"$got\"" ;;
  esac
}

json_field() {
  python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["devices"][0][sys.argv[2]])' "$1" "$2"
}

mkdir -p "$A" "$B"

# ---- 1. two daemons on the public path -------------------------------------
#
# A pairs while advertising relay hints ONLY. On one host every endpoint can
# reach every other one's loopback address, so hiding A's IPs is the closest a
# single machine gets to "these two devices are on networks that cannot see
# each other": B is handed a ticket it cannot dial directly and has to reach A
# through the relay named in it.

start_daemon "$A" env ASTERISM_MESH_NO_DIRECT=1
start_daemon "$B"

grep -q "ASTERISM_MESH=local opts out" "$A/astd.log" \
  || fail "the daemon did not say that discovery publishes, or how to opt out:"$'\n'"$(cat "$A/astd.log")"
echo "ok: both daemons joined a relay and said whose infrastructure it is"

# ---- 2. pairing across the relay -------------------------------------------

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
  || fail "ast device add failed:"$'\n'"$(cat "$B/add.out")"
wait "$INVITE_PID" || fail "ast device invite failed:"$'\n'"$(cat "$A/invite.out")"

grep -qF "paired" "$A/invite.out" || fail "A did not report a pairing:"$'\n'"$(cat "$A/invite.out")"
grep -qF "$A_NAME  " "$B/add.out" || fail "B did not report pairing with A:"$'\n'"$(cat "$B/add.out")"

# The proof that the direct path was not the one used: what B wrote down about
# A carries a relay and no IP address at all. Nothing in B's store could have
# dialled A over loopback.
A_ADDRS="$(json_field "$B/orbit.json" addrs)"
A_RELAYS="$(json_field "$B/orbit.json" relays)"
[ "$A_ADDRS" = "[]" ] \
  || fail "A advertised IP addresses after all, so this proves nothing: $A_ADDRS"
grep -q "http" <<<"$A_RELAYS" \
  || fail "A advertised no relay either, so B had nothing to reach it by: $A_RELAYS"
echo "ok: B paired with A over a relay hint alone (A's IPs were hidden)"

# ---- 3. a path that is a real observation ----------------------------------

DEVICES="$(ASTERISM_HOME="$B" "$AST" devices 2>&1)" || fail "ast devices failed:"$'\n'"$DEVICES"
grep -qE "^$A_NAME +\S+ +online" <<<"$DEVICES" || fail "B does not see A online:"$'\n'"$DEVICES"
assert_real_path "ast devices reports B's path to A" "$(path_of "$B" "$A_NAME")"
LINK="$(telemetry_of "$B" "$A_NAME")"
grep -qE '^[0-9]+\.[0-9]ms +stored_address +connected$' <<<"$LINK" \
  || fail "ast devices did not expose RTT and the initial path decision (got: $LINK)"
echo "ok: ast devices exposes RTT, transition and recovery — $LINK"

PING="$(ASTERISM_HOME="$B" "$AST" ping "$A_NAME" 2>&1)" || fail "ast ping failed:"$'\n'"$PING"
grep -qE "^pong from $A_NAME \(\S+\) via (direct|relay) in [0-9]+\.[0-9]ms$" <<<"$PING" \
  || fail "ast ping did not report a real path and latency:"$'\n'"$PING"
echo "ok: ast ping — $PING"

# ---- 4. work over that path ------------------------------------------------

DISK="$A/tiny.qcow2"
qemu-img create -f qcow2 "$DISK" 1M >/dev/null 2>&1 || fail "qemu-img create failed"
expect "create on A" "$INST  defined" \
  env ASTERISM_HOME="$A" "$AST" create "$INST" --image "$DISK" --mem 512M --disk 1G
expect "ls proxied from B to A" "$INST" \
  env ASTERISM_HOME="$B" "$AST" --device "$A_NAME" ls
expect "the orbit is one namespace across the relay" "$INST" \
  env ASTERISM_HOME="$B" "$AST" ls
expect "status resolves without naming a device" "name:    $INST" \
  env ASTERISM_HOME="$B" "$AST" status "$INST"

# ---- 5. the store learns where the peer answered ---------------------------
#
# B dialled A several times by now. Every dial that worked is written back, so
# B's record of A carries a confirmation timestamp — the thing that lets a
# later dial know whether the address on file is worth trying first.

SEEN_AT="$(json_field "$B/orbit.json" addrs_seen_at)"
[ "$SEEN_AT" -gt 0 ] 2>/dev/null \
  || fail "B never recorded when it last confirmed A's address (got \"$SEEN_AT\")"
NOW="$(date +%s)"
[ "$((NOW - SEEN_AT))" -lt 600 ] \
  || fail "B's confirmation of A's address is $((NOW - SEEN_AT))s old, which is not 'just now'"
echo "ok: B recorded when it last confirmed A's address ($((NOW - SEEN_AT))s ago)"

# ---- 6. a wrong address is not the end of the story ------------------------
#
# This is the gap that discovery closes. Point B's record of A at an address
# nothing answers on, restart B so it reads the forgery, and ask for A anyway.
# Under ASTERISM_MESH=local this is exactly the shape of scripts/e2e-mesh.sh's
# simulated partition and the command MUST fail. Here it must succeed, because
# A's public key is enough to look it up.

stop_daemon "$B"
python3 - "$B/orbit.json" <<'PY'
import json, sys
store = json.load(open(sys.argv[1]))
for device in store["devices"]:
    device["addrs"] = ["127.0.0.1:1"]   # nothing answers here
    device["relays"] = []               # and no relay to fall back on either
    device["addrs_seen_at"] = 1         # 1970: stale by any measure
json.dump(store, open(sys.argv[1], "w"), indent=2)
PY
start_daemon "$B"

expect "a peer at a wrong address is found by its key" "$INST" \
  env ASTERISM_HOME="$B" "$AST" --device "$A_NAME" ls
assert_real_path "and reports a real path afterwards" "$(path_of "$B" "$A_NAME")"
RECOVERY="$(telemetry_of "$B" "$A_NAME")"
grep -qE '^[0-9]+\.[0-9]ms +stale_address_recovered_by_discovery +recovered$' <<<"$RECOVERY" \
  || fail "stale-address recovery was not explicit and measured (got: $RECOVERY)"
echo "ok: stale-address recovery is explicit and measured — $RECOVERY"

# ...and the forgery has been corrected, rather than being re-learned wrong on
# every command.
FIXED="$(json_field "$B/orbit.json" addrs)"
if grep -q "127.0.0.1:1\"" <<<"$FIXED"; then
  fail "B is still carrying the dead address it was given: $FIXED"
fi
echo "ok: B replaced the dead address with where A actually answered"

# ---- 7. no address at all ---------------------------------------------------
#
# The restart case in its purest form: B knows only A's public key and its
# name. This is what a device that has moved networks looks like to a peer that
# has not heard from it since.

stop_daemon "$B"
python3 - "$B/orbit.json" <<'PY'
import json, sys
store = json.load(open(sys.argv[1]))
for device in store["devices"]:
    device["addrs"] = []
    device["relays"] = []
    device["addrs_seen_at"] = 0
json.dump(store, open(sys.argv[1], "w"), indent=2)
PY
start_daemon "$B"

PING="$(ASTERISM_HOME="$B" "$AST" ping "$A_NAME" 2>&1)" \
  || fail "a peer known only by key could not be reached:"$'\n'"$PING"
grep -qE "via (direct|relay)" <<<"$PING" || fail "no path reported:"$'\n'"$PING"
echo "ok: a peer known only by its public key was found — $PING"
RECOVERY="$(telemetry_of "$B" "$A_NAME")"
grep -qE '^[0-9]+\.[0-9]ms +address_recovered_by_discovery +recovered$' <<<"$RECOVERY" \
  || fail "address recovery from a public key was not explicit and measured (got: $RECOVERY)"
echo "ok: key-only address recovery is explicit and measured — $RECOVERY"

# ---- 8. across two real networks -------------------------------------------
#
# Everything above runs on one machine, which means one NAT, one public
# address, and two endpoints that share a loopback. Three things are therefore
# NOT proved by any of it, and cannot be:
#
#   * hole punching between two different NATs. Both endpoints here are behind
#     the same one, so a "direct" path may be a LAN or loopback path that two
#     real machines would never have found.
#   * relay fallback as a fallback. Section 2 forces traffic through a relay by
#     hiding one side's addresses; it does not prove that a pair of endpoints
#     which genuinely cannot punch will fall back on their own.
#   * roaming. Section 6 fakes a stale address by editing a file. It does not
#     move a machine to a different network and watch discovery catch up.
#
# Set ASTERISM_E2E_REAL_NET=1 with ASTERISM_PEER pointing at a ticket printed
# on a machine on a DIFFERENT network — a phone hotspot is enough — and this
# section redeems it for real. Run it on the machine that did NOT print the
# ticket.
if [ "${ASTERISM_E2E_REAL_NET:-0}" = "1" ]; then
  echo "--- real-network section ---"
  [ -n "${ASTERISM_PEER:-}" ] \
    || fail "ASTERISM_E2E_REAL_NET=1 needs ASTERISM_PEER=<ticket from the other network>"
  C="$RUN/c"
  start_daemon "$C"
  C_NAME="disc-c-$$"
  ASTERISM_HOME="$C" "$AST" device add "$ASTERISM_PEER" --name "$C_NAME" --yes >"$C/add.out" 2>&1 \
    || fail "pairing across two networks failed:"$'\n'"$(cat "$C/add.out")"
  grep -qF "paired" "$C/add.out" || fail "no pairing reported:"$'\n'"$(cat "$C/add.out")"
  REMOTE="$(ASTERISM_HOME="$C" "$AST" devices 2>&1 | awk 'NR>1 && $1 != "'"$C_NAME"'" { print $1; exit }')"
  [ -n "$REMOTE" ] || fail "no peer in the orbit after pairing"
  PING="$(ASTERISM_HOME="$C" "$AST" ping "$REMOTE" 2>&1)" \
    || fail "the far device did not answer:"$'\n'"$PING"
  grep -qE "via (direct|relay)" <<<"$PING" || fail "no path reported:"$'\n'"$PING"
  echo "ok: paired and pinged across two networks — $PING"
  echo "note: the path above is the honest answer for THESE two networks."
  echo "      'direct' means the NATs were punchable; 'relay' means they were not."
  stop_daemon "$C"
else
  echo "skip: two-network section (set ASTERISM_E2E_REAL_NET=1 and ASTERISM_PEER=<ticket>)"
fi

echo "DISCOVERY E2E GREEN"
