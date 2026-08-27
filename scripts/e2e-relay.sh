#!/usr/bin/env bash
# End-to-end for astrelay and per-peer byte metering.
#
# One relay and two daemons, all on this machine, all talking to nothing else.
# The point is not that a relay can forward bytes — iroh's own tests cover that
# — but that THREE independent meters agree about how many:
#
#   1. astrelay --dev comes up, serves its metrics, and forwards for two
#      devices that pair through it
#   2. both daemons are bound RELAY-ONLY, so no direct path can exist and every
#      byte between them is necessarily relayed
#   3. `ast ping` and `ast devices` report relayed bytes, a relay URL, and a
#      connection type, on both sides
#   4. the counters persist to $ASTERISM_HOME/relay-meter.json and survive a
#      daemon restart
#   5. the devices' relayed totals and the relay's own bytes_sent/bytes_recv
#      agree within ±5%
#   6. the relay process never saw plaintext: it holds no orbit key material,
#      and the ciphertext it forwarded is not readable from its metrics
#
# HOW "RELAY ONLY" IS FORCED. iroh has no "relay only" policy knob, but its
# endpoint builder has `clear_ip_transports`, which removes every IP transport
# from the endpoint. With no IP transport there is no direct path for iroh to
# select, so relayed byte counters are the only ones that can move. The mesh
# crate exposes that as ASTERISM_MESH_RELAY_ONLY=1. That is a stronger
# statement than ASTERISM_MESH_NO_DIRECT=1, which only hides the addresses a
# device advertises and still permits an upgrade.
#
# WHAT THIS TALKS TO: nothing outside this machine. The relay is local, and
# pkarr/DNS are pointed at addresses nothing answers on, so no device key and
# no address is published anywhere. The peers find each other from the pairing
# ticket's relay hint, which is what a relay is for.
#
# WHAT ONE MACHINE CANNOT PROVE. See the section at the bottom: two-NAT
# fallback and the relay-to-direct upgrade under real hole punching are out of
# scope for this suite and are named rather than faked.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export PATH="$HOME/.cargo/bin:$PATH"
cd "$ROOT"
# shellcheck source-path=SCRIPTDIR source=lib/harness.sh
. "$ROOT/scripts/lib/harness.sh"
harness_begin relay
harness_binaries "$ROOT"

TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target}"
case "$TARGET_DIR" in
  /*) ;;
  *) TARGET_DIR="$ROOT/$TARGET_DIR" ;;
esac
ASTRELAY="${ASTRELAY_BIN:-$TARGET_DIR/debug/astrelay}"

# Fresh, SHORT homes: unix socket paths are capped near 104 bytes.
RUN="/private/tmp/ast-relay-$$"
A="$RUN/a"
B="$RUN/b"
A_NAME="relay-a-$$"
B_NAME="relay-b-$$"
RELAY_LOG="$RUN/astrelay.log"
RELAY_PID=""

# Ports picked from the private range and offset by the pid, so two runs of
# this suite on one machine do not fight over a listener.
PORT_BASE=$(( 20000 + ($$ % 20000) ))
RELAY_PORT=$(( PORT_BASE ))
METRICS_PORT=$(( PORT_BASE + 1 ))
RELAY_URL="http://127.0.0.1:$RELAY_PORT"
METRICS_URL="http://127.0.0.1:$METRICS_PORT/metrics"

cleanup() {
  for home in "$A" "$B"; do
    [ -d "$home" ] || continue
    harness_keep_home "$home" "$(basename "$home")"
  done
  if [ -n "$RELAY_PID" ]; then
    kill -TERM "$RELAY_PID" 2>/dev/null || true
  fi
  # The relay's log lives beside the homes rather than inside one, so it is
  # copied out by hand before the `rm -rf` below takes the run directory.
  if [ -f "$RELAY_LOG" ]; then
    mkdir -p "$(harness_artifacts_dir)/relay" 2>/dev/null || true
    cp "$RELAY_LOG" "$(harness_artifacts_dir)/relay/astrelay.log" 2>/dev/null || true
  fi
  harness_reap
  rm -rf "$RUN"
  harness_artifacts_note
}
trap cleanup EXIT

fail() { echo "RELAY E2E FAIL: $*" >&2; exit 1; }

mkdir -p "$A" "$B"

# ---- 0. build the relay ------------------------------------------------------

if [ ! -x "$ASTRELAY" ]; then
  cargo build -q -p asterism-relay || fail "could not build astrelay"
fi
[ -x "$ASTRELAY" ] || fail "no astrelay binary at $ASTRELAY"

"$ASTRELAY" --version >/dev/null || fail "astrelay --version failed"
"$ASTRELAY" --help >/dev/null || fail "astrelay --help failed"
echo "ok: astrelay --version / --help — $("$ASTRELAY" --version)"

# ---- 1. a relay of our own ---------------------------------------------------

( "$ASTRELAY" --dev \
    --http-bind "127.0.0.1:$RELAY_PORT" \
    --metrics-bind "127.0.0.1:$METRICS_PORT" \
    --per-client-metrics \
    >"$RELAY_LOG" 2>&1 & echo $! >"$RUN/astrelay.pid" )
sleep 0.2
RELAY_PID="$(cat "$RUN/astrelay.pid")"

for _ in $(seq 1 100); do
  curl -fsS "$METRICS_URL" >/dev/null 2>&1 && break
  sleep 0.1
done
curl -fsS "$METRICS_URL" >/dev/null 2>&1 \
  || fail "astrelay never served metrics on $METRICS_URL:"$'\n'"$(cat "$RELAY_LOG")"
grep -q "forwards ciphertext only" "$RELAY_LOG" \
  || fail "astrelay did not disclose what it forwards:"$'\n'"$(cat "$RELAY_LOG")"
echo "ok: astrelay --dev is up on $RELAY_URL with metrics on $METRICS_URL"

# One counter out of the relay's own metrics.
relay_metric() {
  curl -fsS "$METRICS_URL" 2>/dev/null \
    | awk -v n="$1" '$1 == n { print $2; exit }'
}

for name in relayserver_bytes_sent_total relayserver_bytes_recv_total \
            astrelay_connections_admitted_total; do
  [ -n "$(relay_metric "$name")" ] || fail "the relay does not expose $name"
done
echo "ok: the relay exposes its own byte counters and this binary's accounting"

# ---- 2. two daemons that CANNOT go direct ------------------------------------
#
# ASTERISM_MESH_RELAY_ONLY=1 removes every IP transport from the endpoint, so
# "these bytes were relayed" is a property of the configuration rather than an
# inference from a counter. pkarr and DNS are pointed at a port nothing listens
# on: publication fails harmlessly and no key leaves this machine.

start_daemon() {
  local home="$1"
  mkdir -p "$home"
  harness_own_home "$home"
  (
    ASTERISM_HOME="$home" \
    ASTERISM_RELAY_URL="$RELAY_URL" \
    ASTERISM_PKARR_RELAY="http://127.0.0.1:1/pkarr" \
    ASTERISM_DNS_ORIGIN="relay-e2e.invalid." \
    ASTERISM_MESH_RELAY_ONLY=1 \
    "$ASTD" >>"$home/astd.log" 2>&1 &
  )
  for _ in $(seq 1 300); do
    grep -q "discovery: published" "$home/astd.log" 2>/dev/null && return 0
    if grep -q "discovery: no relay reachable" "$home/astd.log" 2>/dev/null; then
      fail "the daemon in $home could not reach the local relay:"$'\n'"$(cat "$home/astd.log")"
    fi
    sleep 0.2
  done
  fail "astd for $home never reached the relay:"$'\n'"$(cat "$home/astd.log" 2>/dev/null)"
}

stop_daemon() {
  local home="$1" pid
  pid="$(cat "$home/astd.pid" 2>/dev/null || true)"
  [ -n "$pid" ] || fail "no pid file for the daemon in $home"
  kill -TERM "$pid" 2>/dev/null || true
  for _ in $(seq 1 50); do
    kill -0 "$pid" 2>/dev/null || return 0
    sleep 0.2
  done
  kill -KILL "$pid" 2>/dev/null || true
}

start_daemon "$A"
start_daemon "$B"

grep -qF "$RELAY_URL" "$A/astd.log" \
  || fail "A did not say it joined our relay:"$'\n'"$(cat "$A/astd.log")"
grep -q "relay meter at" "$A/astd.log" \
  || fail "A did not disclose that it is metering:"$'\n'"$(cat "$A/astd.log")"
echo "ok: both daemons joined $RELAY_URL, relay-only, and said they are metering"

# ---- 3. pair, and move some bytes -------------------------------------------

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
echo "ok: two devices paired with a relay as the only path between them"

# Enough round trips that the byte counters are unmistakably non-zero and the
# ±5% comparison at the end is not dominated by a single packet.
for _ in $(seq 1 20); do
  ASTERISM_HOME="$B" "$AST" ping "$A_NAME" >/dev/null 2>&1 || true
  ASTERISM_HOME="$A" "$AST" ping "$B_NAME" >/dev/null 2>&1 || true
done

# ---- 4. what the devices say -------------------------------------------------

ping_line() { ASTERISM_HOME="$1" "$AST" ping "$2" 2>&1; }

A_PING="$(ping_line "$B" "$A_NAME")" || fail "ast ping from B failed:"$'\n'"$A_PING"
B_PING="$(ping_line "$A" "$B_NAME")" || fail "ast ping from A failed:"$'\n'"$B_PING"

for out in "$A_PING" "$B_PING"; do
  grep -qE "^pong from \S+ \(\S+\) via relay in [0-9]+\.[0-9]ms$" <<<"$out" \
    || fail "ast ping did not report a relayed path:"$'\n'"$out"
  grep -qE "^  bytes    direct .* relayed .* sent / .* recv$" <<<"$out" \
    || fail "ast ping did not report metered bytes:"$'\n'"$out"
  grep -qE "^  path     relay" <<<"$out" \
    || fail "ast ping did not report the connection type:"$'\n'"$out"
  grep -qF "  relay    $RELAY_URL" <<<"$out" \
    || fail "ast ping did not name the relay carrying the connection:"$'\n'"$out"
done
echo "ok: ast ping names the relay and reports metered bytes on both sides"
printf '    B->A  %s\n' "$A_PING"
printf '    A->B  %s\n' "$B_PING"

DEVICES="$(ASTERISM_HOME="$B" "$AST" devices 2>&1)" || fail "ast devices failed:"$'\n'"$DEVICES"
grep -qF "$RELAY_URL" <<<"$DEVICES" \
  || fail "ast devices does not name the relay:"$'\n'"$DEVICES"
# The peer's row: relayed bytes in the RELAYED column and the relay's URL last.
# `0 B` in RELAYED would mean the table is reading a meter nobody is filling.
awk -v n="$A_NAME" '$1 == n { print }' <<<"$DEVICES" \
  | grep -qE "relay .* (KiB|MiB|GiB) +$RELAY_URL/?$" \
  || fail "ast devices does not carry relayed bytes and the relay url for the peer:"$'\n'"$DEVICES"
echo "ok: ast devices carries the byte columns and the relay url"

# ---- 5. the meter is on disk and survives a restart --------------------------

metered_relayed() {
  # Relayed bytes for the single peer in this home's meter, both directions.
  python3 - "$1/relay-meter.json" <<'PY'
import json, sys
try:
    doc = json.load(open(sys.argv[1]))
except FileNotFoundError:
    print(0); raise SystemExit
total = 0
for peer in doc.get("peers", {}).values():
    total += peer.get("relayed_sent", 0) + peer.get("relayed_recv", 0)
print(total)
PY
}

# The flush is on a timer, and a clean shutdown is the other thing that writes
# it. Stop B, which is the event a restart follows anyway.
stop_daemon "$B"
sleep 0.5
[ -f "$B/relay-meter.json" ] || fail "B never wrote its relay meter to disk"

BEFORE="$(metered_relayed "$B")"
[ "$BEFORE" -gt 0 ] 2>/dev/null \
  || fail "B recorded no relayed bytes at all (got \"$BEFORE\") — the meter is not counting"
echo "ok: B persisted $BEFORE relayed bytes to $B/relay-meter.json"

# No addresses in the file: it is device ids and integers.
grep -q "127.0.0.1" "$B/relay-meter.json" \
  && fail "the meter file leaked an address:"$'\n'"$(cat "$B/relay-meter.json")"
grep -q "relay-meter" /dev/null || true
echo "ok: the meter file records device ids and integers, no addresses"

start_daemon "$B"
for _ in $(seq 1 10); do
  ASTERISM_HOME="$B" "$AST" ping "$A_NAME" >/dev/null 2>&1 || true
done
ASTERISM_HOME="$B" "$AST" ping "$A_NAME" >/dev/null 2>&1 || true
stop_daemon "$B"
sleep 0.5
AFTER="$(metered_relayed "$B")"
[ "$AFTER" -gt "$BEFORE" ] 2>/dev/null \
  || fail "the meter restarted from zero across a daemon restart ($BEFORE then $AFTER)"
echo "ok: the counters continued across a restart — $BEFORE then $AFTER"
start_daemon "$B"

# ---- 6. two meters, one number -----------------------------------------------
#
# The devices count what they sent and received over the relay; the relay
# counts what it forwarded. Every byte the relay forwarded was sent by one
# device and received by the other, so the two devices' summed total and the
# relay's in-plus-out total describe the same traffic and should be the same
# number.
#
# WHY THIS IS A BRACKETED DELTA rather than a comparison of lifetime totals.
# The device meter samples on a timer and takes a connection's counters with it
# when the connection closes, so a connection that lived and died between two
# samples is undercounted — a real limitation, documented in
# `crates/asterism-daemon/src/relay_meter.rs`, and one that section 5's restart
# deliberately provokes. Comparing lifetime totals would therefore measure that
# limitation instead of the thing under test. So both meters are read before a
# burst of traffic and after it, with no connection torn down in between, and
# the *differences* are compared. `ast devices --json` forces a fresh sample on
# the way past, which is what makes the bracket tight.
#
# They are compared with a tolerance rather than for equality, honestly: the
# two meters count at different layers and are read a few milliseconds apart,
# during which a keep-alive can land. ±5% is the tolerance AST-119 set.

# Relayed bytes, both directions, over all peers, live from the daemon.
live_relayed() {
  ASTERISM_HOME="$1" "$AST" devices --json 2>/dev/null | python3 -c '
import json, sys
rows = json.load(sys.stdin)
print(sum(
    r["bytes"]["relayed_sent"] + r["bytes"]["relayed_recv"]
    for r in rows if not r.get("is_self")
))
'
}

relay_forwarded() {
  local sent recv
  sent="$(relay_metric relayserver_bytes_sent_total)"
  recv="$(relay_metric relayserver_bytes_recv_total)"
  echo $(( ${sent%%.*} + ${recv%%.*} ))
}

D0=$(( $(live_relayed "$A") + $(live_relayed "$B") ))
R0="$(relay_forwarded)"

for _ in $(seq 1 40); do
  ASTERISM_HOME="$B" "$AST" ping "$A_NAME" >/dev/null 2>&1 || true
  ASTERISM_HOME="$A" "$AST" ping "$B_NAME" >/dev/null 2>&1 || true
done

D1=$(( $(live_relayed "$A") + $(live_relayed "$B") ))
R1="$(relay_forwarded)"

echo "    devices: $D0 then $D1"
echo "    relay:   $R0 then $R1"

python3 - "$D0" "$D1" "$R0" "$R1" <<'PY'
import sys
d0, d1, r0, r1 = (int(x) for x in sys.argv[1:5])
devices = d1 - d0
relay = r1 - r0
if relay <= 0:
    raise SystemExit("RELAY E2E FAIL: the relay forwarded nothing during the burst")
if devices <= 0:
    raise SystemExit("RELAY E2E FAIL: the devices metered nothing during the burst")

drift = abs(devices - relay) / max(devices, relay)
print(f"    burst: devices {devices} vs relay {relay} — {drift * 100:.2f}% apart")
if drift > 0.05:
    raise SystemExit(
        "RELAY E2E FAIL: the device meters and the relay's own counters "
        f"disagree by {drift * 100:.2f}%, which is more than the 5% tolerance"
    )
print("ok: two independent meters agree within 5%")
PY

stop_daemon "$A"
stop_daemon "$B"

# ---- 7. the relay never held a key -------------------------------------------
#
# The claim is structural rather than statistical: astrelay links no orbit key
# material, generates no device identity and reads no $ASTERISM_HOME. What can
# be checked from outside is the consequence — the relay saw the traffic and
# still cannot say anything about it beyond how much there was.

grep -q "forwards ciphertext only" "$RELAY_LOG" \
  || fail "the relay stopped disclosing what it forwards"
if grep -riE "$A_NAME|$B_NAME" "$RELAY_LOG" >/dev/null 2>&1; then
  fail "a device NAME reached the relay's log — the relay should know keys, not names:"$'\n'"$(cat "$RELAY_LOG")"
fi
# The relay's metrics are counts. If plaintext were reachable, the obvious
# place for it to surface is here, and it does not: every value is a number.
curl -fsS "$METRICS_URL" | grep -v '^#' | awk 'NF && $2 !~ /^-?[0-9.eE+]+$/ { print; exit 1 }' \
  >/dev/null || fail "the relay's metrics carry something that is not a number"
echo "ok: the relay forwarded the traffic and knows only how much there was"

# ---- 8. what one machine cannot prove ----------------------------------------
#
# Named rather than faked, because a suite that claimed these would be lying:
#
#   * TWO-NAT FALLBACK. Both endpoints here are on one host behind one NAT.
#     Relaying is forced by removing IP transports, not discovered by a pair of
#     endpoints that genuinely could not punch. Whether a real pair falls back
#     correctly is a two-network test and is out of scope for this pass.
#   * THE RELAY-TO-DIRECT UPGRADE. `ASTERISM_MESH_RELAY_ONLY=1` exists to stop
#     exactly the upgrade this suite would otherwise want to measure. The
#     upgrade counters (`relayed_before_direct`, `last_upgrade_millis`) are
#     unit-tested in `crates/asterism-daemon/src/relay_meter.rs` and are
#     exercised for real only on two networks.
#   * TLS. This runs `--dev`, which is plain HTTP on loopback. Let's Encrypt
#     and manual certificate paths are configured and unit-tested but not
#     served here; a certificate needs a public hostname.
#
# See docs/RELAY.md for what production still needs.

echo
echo "RELAY E2E PASS"
