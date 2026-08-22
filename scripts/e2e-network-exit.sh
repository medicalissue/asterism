#!/usr/bin/env bash
# Real network-exit acceptance: three authenticated device daemons and one
# booted QEMU guest. The guest stays alive while its packet edge moves through
# local, direct-peer, relay-only, failover, refusal, revocation and detach.
# Run this after the workspace suite: the companion mesh tests send private
# authenticated ExitTcp/ExitUdp frames that intentionally bypass this guest's
# consumer filter, multiply connections against one peer quota, and speak v6
# attachment frames beside refused v7 provider frames. This script supplies
# the real-QEMU traffic, crash, restart, sleep and legacy-upgrade legs.
# E316_ASTD/E316_AST must name binaries built from the fenced e316378 tree.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export PATH="$HOME/.cargo/bin:$PATH"
cd "$ROOT"
# shellcheck source-path=SCRIPTDIR source=lib/harness.sh
. "$ROOT/scripts/lib/harness.sh"
harness_begin network-exit
harness_binaries "$ROOT"

RUN="/private/tmp/ast-exit-$$"
A="$RUN/a"
B="$RUN/b"
C="$RUN/c"
D="$RUN/legacy"
A_NAME="exit-a-$$"
B_NAME="exit-b-$$"
C_NAME="exit-c-$$"
INST="exit-guest"
IMAGE="${E2E_IMAGE:-debian:13}"
PAUSE="$RUN/pause"
E316_ASTD="${E316_ASTD:-}"
E316_AST="${E316_AST:-}"

fail() { echo "NETWORK EXIT E2E FAIL: $*" >&2; exit 1; }

cleanup() {
  local home
  for home in "$A" "$B" "$C" "$D"; do
    [ -d "$home" ] || continue
    harness_keep_home "$home" "$(basename "$home")"
  done
  harness_reap
  rm -rf "$RUN"
  harness_artifacts_note
}
trap cleanup EXIT

[ -x "$E316_ASTD" ] || fail "set E316_ASTD to the preserved e316378 astd binary"
[ -x "$E316_AST" ] || fail "set E316_AST to the preserved e316378 ast binary"

expect() {
  local desc="$1" needle="$2"; shift 2
  local out
  out="$("$@" 2>&1)" || fail "$desc: command failed:"$'\n'"$out"
  grep -qF "$needle" <<<"$out" || fail "$desc: expected $needle in:"$'\n'"$out"
  echo "ok: $desc"
}

refuse() {
  local desc="$1" needle="$2"; shift 2
  local out
  if out="$("$@" 2>&1)"; then
    fail "$desc: command unexpectedly succeeded:"$'\n'"$out"
  fi
  grep -qF "$needle" <<<"$out" || fail "$desc: expected $needle in:"$'\n'"$out"
  echo "ok: $desc"
}

refuse_exit() {
  local desc="$1"; shift
  local out
  if out="$("$@" 2>&1)"; then
    fail "$desc: command unexpectedly succeeded:"$'\n'"$out"
  fi
  echo "ok: $desc"
}

# Discovery is intentional. B advertises direct addresses; C is started with
# ASTERISM_MESH_NO_DIRECT and can be reached only through its advertised relay.
start_daemon() {
  local home="$1"; shift
  local before old_pid new_pid
  mkdir -p "$home"
  harness_own_home "$home"
  if [ -f "$home/astd.log" ]; then before="$(wc -l <"$home/astd.log")"; else before=0; fi
  old_pid="$(cat "$home/astd.pid" 2>/dev/null || true)"
  ( ASTERISM_HOME="$home" "$@" "${DAEMON_BIN:-$ASTD}" >>"$home/astd.log" 2>&1 & )
  for _ in $(seq 1 300); do
    new_pid="$(cat "$home/astd.pid" 2>/dev/null || true)"
    if [ -n "$new_pid" ] && [ "$new_pid" != "$old_pid" ] && kill -0 "$new_pid" 2>/dev/null \
      && tail -n "+$((before + 1))" "$home/astd.log" | grep -q "discovery: published"; then
      return 0
    fi
    if tail -n "+$((before + 1))" "$home/astd.log" 2>/dev/null | grep -q "discovery: no relay reachable"; then
      fail "no relay is reachable; this acceptance lane needs internet:"$'\n'"$(cat "$home/astd.log")"
    fi
    sleep 0.2
  done
  fail "daemon for $home never published:"$'\n'"$(cat "$home/astd.log" 2>/dev/null)"
}

stop_daemon() {
  local home="$1" pid
  pid="$(cat "$home/astd.pid")"
  harness_stop "$pid"
  harness_gone "$pid" || fail "daemon $pid for $home did not stop"
}

crash_daemon() {
  local home="$1" pid
  pid="$(cat "$home/astd.pid")"
  kill -KILL "$pid"
  harness_wait_gone "$pid" 25 || fail "daemon $pid for $home survived SIGKILL"
}

arm_pause() {
  mkdir -p "$PAUSE"
  rm -f "$PAUSE/$1.ready" "$PAUSE/$1.release"
  : >"$PAUSE/$1.arm"
}

wait_pause() {
  for _ in $(seq 1 100); do [ -f "$PAUSE/$1.ready" ] && return 0; sleep 0.1; done
  fail "daemon never reached armed exit pause $1"
}

sleep_daemon() { kill -STOP "$(cat "$1/astd.pid")"; }
rouse_daemon() { kill -CONT "$(cat "$1/astd.pid")"; }

# pair <inviter-home> <inviter-name> <joiner-home> <joiner-name>
pair() {
  local inviter="$1" inviter_name="$2" joiner="$3" joiner_name="$4"
  local invite="$inviter/invite-$joiner_name.out" add="$joiner/add-$inviter_name.out"
  local invite_pid ticket=""
  ASTERISM_HOME="$inviter" "$AST" device invite --name "$inviter_name" --yes >"$invite" 2>&1 &
  invite_pid=$!
  for _ in $(seq 1 150); do
    ticket="$(grep -o 'astdev1[a-z0-9]*' "$invite" 2>/dev/null | head -1 || true)"
    [ -n "$ticket" ] && break
    sleep 0.2
  done
  [ -n "$ticket" ] || fail "no pairing ticket:"$'\n'"$(cat "$invite")"
  ASTERISM_HOME="$joiner" "$AST" device add "$ticket" --name "$joiner_name" --yes >"$add" 2>&1 \
    || fail "pairing failed:"$'\n'"$(cat "$add")"
  wait "$invite_pid" || fail "inviter failed:"$'\n'"$(cat "$invite")"
  grep -qF "paired" "$invite" || fail "inviter did not confirm pairing"
}

path_of() {
  ASTERISM_HOME="$1" "$AST" devices 2>&1 | awk -v n="$2" '$1 == n { print $4 }'
}

wait_path() {
  local home="$1" peer="$2" want="$3" got=""
  for _ in $(seq 1 100); do
    got="$(path_of "$home" "$peer")"
    [ "$got" = "$want" ] && { echo "ok: $peer selected $want mesh path"; return 0; }
    sleep 0.2
  done
  fail "$peer never selected $want path (last: ${got:-none})"
}

status_until() {
  local needle="$1" out=""
  for _ in $(seq 1 40); do
    out="$(ASTERISM_HOME="$A" "$AST" status "$INST" 2>&1 || true)"
    grep -qF "$needle" <<<"$out" && { echo "ok: status reports $needle"; return 0; }
    sleep 0.3
  done
  fail "status never reported $needle:"$'\n'"$out"
}

guest_connect() {
  ASTERISM_HOME="$A" "$AST" ssh "$INST" -- \
    python3 -c "import socket; s=socket.create_connection(('1.1.1.1',443),5); print('CONNECTED',s.getpeername()[0])"
}

guest_connect_until() {
  local out=""
  for _ in $(seq 1 10); do
    out="$(guest_connect 2>&1 || true)"
    grep -qF CONNECTED <<<"$out" && { echo "ok: booted guest opened public TCP"; return 0; }
    sleep 1
  done
  fail "guest public TCP never recovered:"$'\n'"$out"
}

guest_udp_until() {
  local out=""
  for _ in $(seq 1 10); do
    out="$(ASTERISM_HOME="$A" "$AST" ssh "$INST" -- python3 -c \
      "import socket; q=bytes.fromhex('4153010000010000000000000000010001'); s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(3); s.sendto(q,('1.1.1.1',53)); r,_=s.recvfrom(512); assert r[:2]==q[:2] and r[2]&128; print('UDP_OK')" 2>&1 || true)"
    grep -qF UDP_OK <<<"$out" && { echo "ok: booted guest exchanged a public UDP datagram"; return 0; }
    sleep 1
  done
  fail "guest public UDP never recovered:"$'\n'"$out"
}

instance_pid() {
  python3 -c 'import json,sys; h=json.load(open(sys.argv[1]))["instances"][sys.argv[2]]["handle"]; print((h.get("proc") or {}).get("pid",h.get("pid")))' \
    "$1/state.json" "$2"
}

wait_replaced_pid() {
  local home="$1" name="$2" old="$3" now=""
  for _ in $(seq 1 300); do
    now="$(instance_pid "$home" "$name" 2>/dev/null || true)"
    if [ -n "$now" ] && [ "$now" != "$old" ] && kill -0 "$now" 2>/dev/null; then
      printf '%s\n' "$now"
      return 0
    fi
    sleep 0.2
  done
  return 1
}

mkdir -p "$A" "$B" "$C"
start_daemon "$A" env ASTERISM_EXIT_TEST_PAUSE_DIR="$PAUSE"
start_daemon "$B"
start_daemon "$C" env ASTERISM_MESH_NO_DIRECT=1
pair "$A" "$A_NAME" "$B" "$B_NAME"
# C is the inviter so the address A stores for provider C is relay-only.
pair "$C" "$C_NAME" "$A" "$A_NAME"
wait_path "$A" "$B_NAME" direct
wait_path "$A" "$C_NAME" relay

harness_cache_image "$AST" "$IMAGE" || fail "could not cache $IMAGE"
harness_seed_images "$A"
expect "create QEMU guest" "$INST  defined" \
  env ASTERISM_HOME="$A" "$AST" create "$INST" --image "$IMAGE" --backend qemu --mem 2G --disk 10G

# Consent is provider-local and disabled by default.
refuse "remote provider defaults to unauthorized" "exit service is disabled" \
  env ASTERISM_HOME="$A" "$AST" attach "$INST" --exit "$B_NAME"
expect "enable B provider consent" "enabled" env ASTERISM_HOME="$B" "$AST" device exit enable
expect "enable relay provider consent" "enabled" env ASTERISM_HOME="$C" "$AST" device exit enable

# B grants first; the nonexistent second provider then fails. The consumer's
# durable rollback intent must discard B's pending generation immediately.
refuse_exit "partial multi-provider grant rolls back" env ASTERISM_HOME="$A" "$AST" attach "$INST" \
  --exit "$B_NAME" --failover "missing-exit-$$"
expect "partial grant left no B pending generation" "0 grant(s)" \
  env ASTERISM_HOME="$B" "$AST" device exit status

# The local path uses the same packet edge but needs no remote grant.
expect "attach local exit" "network exit $A_NAME" \
  env ASTERISM_HOME="$A" "$AST" attach "$INST" --exit "$A_NAME"
expect "boot once" "$INST  running" env ASTERISM_HOME="$A" "$AST" up "$INST"
QEMU_PID="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["instances"][sys.argv[2]]["handle"]["proc"]["pid"])' "$A/state.json" "$INST")"
status_until "healthy · local"
guest_connect_until
guest_udp_until

# Reconfiguration is live and the direct provider owns both traffic and DNS.
expect "attach direct remote exit" "network exit $B_NAME" \
  env ASTERISM_HOME="$A" "$AST" attach "$INST" --exit "$B_NAME"
status_until "healthy · direct"
guest_connect_until
guest_udp_until
expect "DNS resolves through direct exit" "DNS_OK" env ASTERISM_HOME="$A" "$AST" ssh "$INST" -- \
  python3 -c "import socket; print('DNS_OK',socket.getaddrinfo('example.com',443)[0][4][0])"

# A daemon restart must reattach the exact Unix packet edge without adopting
# an unrestricted/legacy handle or rebooting the live guest.
OLD_ASTD_PID="$(cat "$A/astd.pid")"
stop_daemon "$A"
kill -0 "$QEMU_PID" 2>/dev/null || fail "QEMU died with its consumer daemon"
start_daemon "$A" env ASTERISM_EXIT_TEST_PAUSE_DIR="$PAUSE"
[ "$(cat "$A/astd.pid")" != "$OLD_ASTD_PID" ] || fail "consumer daemon did not restart"
RESTART_PID="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["instances"][sys.argv[2]]["handle"]["proc"]["pid"])' "$A/state.json" "$INST")"
[ "$RESTART_PID" = "$QEMU_PID" ] || fail "daemon restart replaced live QEMU: $QEMU_PID -> $RESTART_PID"
guest_connect_until
echo "ok: consumer daemon restarted beneath live QEMU $QEMU_PID"

# C carries no direct address in A's trust store; successful traffic and the
# runtime path therefore prove the forced relay data plane rather than a label.
expect "attach forced-relay exit" "network exit $C_NAME" \
  env ASTERISM_HOME="$A" "$AST" attach "$INST" --exit "$C_NAME"
status_until "healthy · relay"
guest_connect_until
guest_udp_until

# The booted guest proves the consumer edge refuses an excluded public
# destination. Provider-side enforcement is exercised separately by the
# authenticated raw ExitTcp/ExitUdp acceptance test; this leg must not claim
# that a packet stopped before the mesh proves the provider check.
expect "attach excluded route policy" "network exit $C_NAME" \
  env ASTERISM_HOME="$A" "$AST" attach "$INST" --exit "$C_NAME" --exclude-route 1.1.1.1/32
refuse_exit "excluded public route is refused at the guest edge" env ASTERISM_HOME="$A" "$AST" ssh "$INST" -- \
  python3 -c "import socket; socket.create_connection(('1.1.1.1',443),3)"

# Crash before the consumer shard commit: C's old active policy remains
# authoritative and B's newly issued pending generation is durably rolled
# back on restart.
expect "restore relay policy before crash gates" "network exit $C_NAME" \
  env ASTERISM_HOME="$A" "$AST" attach "$INST" --exit "$C_NAME"
arm_pause before_shard_save
BEFORE_OUT="$RUN/before-shard.out"
( ASTERISM_HOME="$A" "$AST" attach "$INST" --exit "$B_NAME" >"$BEFORE_OUT" 2>&1 ) &
BEFORE_PID=$!
wait_pause before_shard_save
crash_daemon "$A"
wait "$BEFORE_PID" 2>/dev/null && fail "pre-shard attach survived daemon crash" || true
rm -f "$PAUSE/before_shard_save.ready"
start_daemon "$A" env ASTERISM_EXIT_TEST_PAUSE_DIR="$PAUSE"
expect "pre-shard crash revoked new B pending grant" "0 grant(s)" \
  env ASTERISM_HOME="$B" "$AST" device exit status
expect "pre-shard crash retained old C active grant" "1 grant(s)" \
  env ASTERISM_HOME="$C" "$AST" device exit status
status_until "selected exit $C_NAME"
guest_connect_until

# Crash after the shard commit but before activation: restart activates B's
# exact durable generation, then revokes C's superseded active generation.
arm_pause after_shard_save
AFTER_OUT="$RUN/after-shard.out"
( ASTERISM_HOME="$A" "$AST" attach "$INST" --exit "$B_NAME" >"$AFTER_OUT" 2>&1 ) &
AFTER_PID=$!
wait_pause after_shard_save
crash_daemon "$A"
wait "$AFTER_PID" 2>/dev/null && fail "post-shard attach survived daemon crash" || true
rm -f "$PAUSE/after_shard_save.ready"
start_daemon "$A" env ASTERISM_EXIT_TEST_PAUSE_DIR="$PAUSE"
expect "post-shard crash activated durable B grant" "1 grant(s)" \
  env ASTERISM_HOME="$B" "$AST" device exit status
expect "post-shard crash revoked superseded C grant" "0 grant(s)" \
  env ASTERISM_HOME="$C" "$AST" device exit status
status_until "selected exit $B_NAME"
guest_connect_until
[ "$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["instances"][sys.argv[2]]["handle"]["proc"]["pid"])' "$A/state.json" "$INST")" = "$QEMU_PID" ] \
  || fail "shard crash recovery rebooted the guest"
echo "ok: crash recovery reconciled both sides of the shard/activation boundary"

# Primary B and relay C are both granted. Actually suspending B (without
# changing its consent) proves health failover rather than policy revocation.
expect "attach direct primary and relay failover" "failover $C_NAME" \
  env ASTERISM_HOME="$A" "$AST" attach "$INST" --exit "$B_NAME" --failover "$C_NAME"
status_until "selected exit $B_NAME"
sleep_daemon "$B"
status_until "selected exit $C_NAME"
guest_connect_until
guest_udp_until
rouse_daemon "$B"
echo "ok: sleeping primary failed over to relay without changing consent"

# Disable is a separate live-revocation gate. Keep both a TCP pipe and a
# reusable UDP session active on B, then revoke provider consent and require
# both already-open generations to close.
expect "select B alone for live disable" "network exit $B_NAME" \
  env ASTERISM_HOME="$A" "$AST" attach "$INST" --exit "$B_NAME"
status_until "selected exit $B_NAME"
FLOW_OUT="$RUN/disable-tcp.out"
( ASTERISM_HOME="$A" "$AST" ssh "$INST" -- python3 -c \
  "import socket; s=socket.create_connection(('1.1.1.1',443),5); print('FLOW_OPEN',flush=True); print('FLOW_CLOSED',len(s.recv(1)),flush=True)" \
  >"$FLOW_OUT" 2>&1 ) &
FLOW_PID=$!
UDP_OUT="$RUN/disable-udp.out"
( ASTERISM_HOME="$A" "$AST" ssh "$INST" -- python3 -c \
  "import socket,time; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(2); q=bytes.fromhex('4153010000010000000000000000010001'); s.sendto(q,('1.1.1.1',53)); s.recvfrom(512); print('UDP_OPEN',flush=True); [(s.sendto(q,('1.1.1.1',53)),s.recvfrom(512),time.sleep(.2)) for _ in range(100)]" \
  >"$UDP_OUT" 2>&1 ) &
UDP_PID=$!
for _ in $(seq 1 50); do
  grep -qF FLOW_OPEN "$FLOW_OUT" 2>/dev/null && grep -qF UDP_OPEN "$UDP_OUT" 2>/dev/null && break
  sleep 0.2
done
grep -qF FLOW_OPEN "$FLOW_OUT" || fail "TCP flow never opened before disable"
grep -qF UDP_OPEN "$UDP_OUT" || fail "UDP flow never opened before disable"
expect "disable provider with live TCP and UDP" "disabled" env ASTERISM_HOME="$B" "$AST" device exit disable
for _ in $(seq 1 50); do harness_gone "$FLOW_PID" && harness_gone "$UDP_PID" && break; sleep 0.2; done
harness_gone "$FLOW_PID" || fail "active TCP flow survived provider disable"
harness_gone "$UDP_PID" || fail "active UDP flow survived provider disable"
wait "$FLOW_PID" || true
if wait "$UDP_PID"; then
  fail "active UDP loop completed normally instead of observing provider disable"
fi
grep -qF "FLOW_CLOSED 0" "$FLOW_OUT" || fail "guest TCP did not observe provider disable:"$'\n'"$(cat "$FLOW_OUT")"
expect "disabled provider has no surviving grant" "0 grant(s)" env ASTERISM_HOME="$B" "$AST" device exit status

# Keep a real provider TCP flow blocked in recv. Detach revokes the exact
# grant and the provider closes that existing socket before reporting success.
expect "select relay provider for detach" "network exit $C_NAME" \
  env ASTERISM_HOME="$A" "$AST" attach "$INST" --exit "$C_NAME"
FLOW_OUT="$RUN/detach-flow.out"
( ASTERISM_HOME="$A" "$AST" ssh "$INST" -- python3 -c \
  "import socket; s=socket.create_connection(('1.1.1.1',443),5); print('FLOW_OPEN',flush=True); print('FLOW_CLOSED',len(s.recv(1)),flush=True)" \
  >"$FLOW_OUT" 2>&1 ) &
FLOW_PID=$!
for _ in $(seq 1 50); do grep -qF FLOW_OPEN "$FLOW_OUT" 2>/dev/null && break; sleep 0.2; done
grep -qF FLOW_OPEN "$FLOW_OUT" || fail "long-lived provider flow never opened:"$'\n'"$(cat "$FLOW_OUT")"
expect "detach revokes provider grant" "guest configuration unchanged" \
  env ASTERISM_HOME="$A" "$AST" detach "$INST" --exit
for _ in $(seq 1 50); do harness_gone "$FLOW_PID" && break; sleep 0.2; done
harness_gone "$FLOW_PID" || fail "active provider flow survived detach"
wait "$FLOW_PID" || true
grep -qF "FLOW_CLOSED 0" "$FLOW_OUT" || fail "guest did not observe provider socket revocation:"$'\n'"$(cat "$FLOW_OUT")"
expect "relay provider has no surviving grant" "0 grant(s)" env ASTERISM_HOME="$C" "$AST" device exit status

# Default CPU egress is still carried by the stable packet edge. No attach,
# detach, direct/relay transition or revocation may reboot the guest.
guest_connect_until
FINAL_PID="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["instances"][sys.argv[2]]["handle"]["proc"]["pid"])' "$A/state.json" "$INST")"
[ "$FINAL_PID" = "$QEMU_PID" ] || fail "guest rebooted during packet-edge changes: $QEMU_PID -> $FINAL_PID"
echo "ok: one QEMU pid survived local/direct/relay/failover/refusal/revocation/detach ($QEMU_PID)"

# Membership removal on the provider is authority revocation too. Exercise it
# last because the peer is intentionally no longer pairable afterwards.
expect "re-enable relay provider after detach" "enabled" env ASTERISM_HOME="$C" "$AST" device exit enable
expect "attach relay for device-removal revocation" "network exit $C_NAME" \
  env ASTERISM_HOME="$A" "$AST" attach "$INST" --exit "$C_NAME"
REMOVE_OUT="$RUN/remove-flow.out"
( ASTERISM_HOME="$A" "$AST" ssh "$INST" -- python3 -c \
  "import socket; s=socket.create_connection(('1.1.1.1',443),5); print('FLOW_OPEN',flush=True); print('FLOW_CLOSED',len(s.recv(1)),flush=True)" \
  >"$REMOVE_OUT" 2>&1 ) &
REMOVE_PID=$!
for _ in $(seq 1 50); do grep -qF FLOW_OPEN "$REMOVE_OUT" 2>/dev/null && break; sleep 0.2; done
grep -qF FLOW_OPEN "$REMOVE_OUT" || fail "device-removal flow never opened"
expect "provider removes consumer device" "removed from this orbit" \
  env ASTERISM_HOME="$C" "$AST" device rm "$A_NAME"
for _ in $(seq 1 50); do harness_gone "$REMOVE_PID" && break; sleep 0.2; done
harness_gone "$REMOVE_PID" || fail "active exit flow survived provider device removal"
wait "$REMOVE_PID" || true
grep -qF "FLOW_CLOSED 0" "$REMOVE_OUT" || fail "guest did not observe device-removal revocation:"$'\n'"$(cat "$REMOVE_OUT")"
expect "device removal purged provider grants" "0 grant(s)" env ASTERISM_HOME="$C" "$AST" device exit status
[ "$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["instances"][sys.argv[2]]["handle"]["proc"]["pid"])' "$A/state.json" "$INST")" = "$QEMU_PID" ] \
  || fail "device removal rebooted the guest"
echo "ok: provider device removal revoked its active grant and flow"

# Stop the primary lane's guest before the legacy fence lane so host capacity
# still contains exactly one booted QEMU. A preserved e316378 daemon first
# creates an unrestricted/TCP-edge handle; the current daemon must kill and
# replace it. Then an explicit rollback launches another legacy handle and a
# second upgrade must fence it again, proving no stale side marker can bless a
# different process.
expect "stop primary QEMU before sequential legacy lane" "$INST  stopped" \
  env ASTERISM_HOME="$A" "$AST" down "$INST"
mkdir -p "$D"
DAEMON_BIN="$E316_ASTD" start_daemon "$D"
harness_seed_images "$D"
LEGACY_INST="legacy-exit-guest"
expect "legacy e316 creates QEMU guest" "$LEGACY_INST  defined" \
  env ASTERISM_HOME="$D" "$E316_AST" create "$LEGACY_INST" --image "$IMAGE" --backend qemu --mem 2G --disk 10G
expect "legacy e316 boots unrestricted guest" "$LEGACY_INST  running" \
  env ASTERISM_HOME="$D" "$E316_AST" up "$LEGACY_INST"
LEGACY_PID="$(instance_pid "$D" "$LEGACY_INST")"
stop_daemon "$D"
start_daemon "$D"
UPGRADED_PID="$(wait_replaced_pid "$D" "$LEGACY_INST" "$LEGACY_PID")" \
  || fail "current daemon did not fence/restart live e316 QEMU $LEGACY_PID"
harness_gone "$LEGACY_PID" || fail "legacy e316 QEMU survived current-daemon startup"
[ "$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["instances"][sys.argv[2]]["handle"].get("packet_edge_generation"))' "$D/state.json" "$LEGACY_INST")" = "unix-restricted-v1" ] \
  || fail "upgraded QEMU handle lacks process-bound packet edge generation"
echo "ok: live e316 QEMU $LEGACY_PID was fenced and replaced by $UPGRADED_PID"

stop_daemon "$D"
DAEMON_BIN="$E316_ASTD" start_daemon "$D"
expect "rollback stops current safe QEMU" "$LEGACY_INST  stopped" \
  env ASTERISM_HOME="$D" "$E316_AST" down "$LEGACY_INST"
expect "rollback launches a new unsafe QEMU" "$LEGACY_INST  running" \
  env ASTERISM_HOME="$D" "$E316_AST" up "$LEGACY_INST"
ROLLBACK_PID="$(instance_pid "$D" "$LEGACY_INST")"
[ "$ROLLBACK_PID" != "$UPGRADED_PID" ] || fail "rollback did not launch a distinct QEMU identity"
stop_daemon "$D"
start_daemon "$D"
REUPGRADED_PID="$(wait_replaced_pid "$D" "$LEGACY_INST" "$ROLLBACK_PID")" \
  || fail "re-upgrade did not fence rollback QEMU $ROLLBACK_PID"
harness_gone "$ROLLBACK_PID" || fail "rollback QEMU survived re-upgrade"
[ "$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["instances"][sys.argv[2]]["handle"].get("packet_edge_generation"))' "$D/state.json" "$LEGACY_INST")" = "unix-restricted-v1" ] \
  || fail "re-upgraded QEMU handle lacks process-bound packet edge generation"
expect "re-upgraded guest has public traffic" "CONNECTED" env ASTERISM_HOME="$D" "$AST" ssh "$LEGACY_INST" -- \
  python3 -c "import socket; s=socket.create_connection(('1.1.1.1',443),5); print('CONNECTED',s.getpeername()[0])"
echo "ok: rollback/re-upgrade fenced $ROLLBACK_PID and booted safe QEMU $REUPGRADED_PID"
echo "NETWORK EXIT E2E GREEN"
