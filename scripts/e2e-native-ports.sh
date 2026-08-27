#!/usr/bin/env bash
# End-to-end for `ast create -p` on a backend that publishes through astd.
#
# QEMU publishes inside its own user-mode NAT: the mapping becomes a `hostfwd`
# argument and the VMM binds the host port. The product backends have no such
# NAT — a VZ guest holds an address on macOS's NAT and a Cloud Hypervisor guest
# holds one on a per-instance TAP — so `astd` binds `127.0.0.1:HOST` itself and
# splices to the guest's private address. This lane proves the part of that
# which cannot be proved without a real guest:
#
#   * a TCP publication actually carries HTTP to a real nginx in the guest
#   * a UDP publication actually carries datagrams both ways
#   * the listener is on 127.0.0.1 and on nothing else
#   * down/up, a daemon restart, and daemon+VMM loss under restart=always all
#     come back on EXACTLY the declared port, never on another one
#   * a second instance declaring a host port this one holds is refused
#
# The backend is selectable and is forced everywhere, so a device that cannot
# run it fails this lane rather than quietly proving QEMU again:
#
#   E2E_BACKEND=vz  scripts/e2e-native-ports.sh     # macOS default
#   E2E_BACKEND=chv scripts/e2e-native-ports.sh     # Linux default
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export PATH="$HOME/.cargo/bin:$PATH"
cd "$ROOT"

# shellcheck source-path=SCRIPTDIR
. "$ROOT/scripts/lib/harness.sh"
harness_begin native-ports
harness_binaries "$ROOT"

case "${E2E_BACKEND:-}" in
  '')
    case "$(uname -s)" in
      Darwin) BACKEND=vz ;;
      Linux) BACKEND=chv ;;
      *) harness_skip "no native publishing backend on $(uname -s)" ;;
    esac
    ;;
  vz | chv) BACKEND="$E2E_BACKEND" ;;
  *) echo "E2E_BACKEND must be vz or chv (got ${E2E_BACKEND})" >&2; exit 2 ;;
esac

if [ "$BACKEND" = vz ]; then
  [ "$(uname -s)" = Darwin ] \
    || harness_skip "Virtualization.framework is macOS-only"
  # Builds and signs the helper. Without the entitlement `--backend vz`
  # refuses before anything is created. Skipped when the binaries under test
  # came from somewhere else: astd looks for astd-vz beside itself.
  if [ -z "${AST_BIN:-}" ]; then
    "$ROOT/scripts/sign-vz.sh"
  fi
else
  [ "$(uname -s)" = Linux ] || harness_skip "Cloud Hypervisor is Linux-only"
  [ -r /dev/kvm ] || harness_skip "this device has no usable /dev/kvm"
fi

GUEST_ARTIFACT="${ASTERISM_GUEST_AGENT_ARTIFACT:-$(dirname "$ASTD")/guest/bin/asterism-guest}"
[ -x "$GUEST_ARTIFACT" ] \
  || harness_skip "set ASTERISM_GUEST_AGENT_ARTIFACT to a static $(uname -m) Linux asterism-guest"

# Short home on purpose: unix socket paths are capped near 104 bytes, and the
# helper's control socket lives under it.
export ASTERISM_HOME="/private/tmp/ast-ports-$$"
[ -d /private/tmp ] || export ASTERISM_HOME="/tmp/ast-ports-$$"
export ASTERISM_MESH=local
export ASTERISM_TEST_SERVICE_LABEL="com.asterism.astd.test.ports.$$.$RANDOM"
mkdir -p "$ASTERISM_HOME"
harness_own_home "$ASTERISM_HOME"

BIN="$ASTERISM_HOME/bin"
LOG="$ASTERISM_HOME/astd.log"
EVIDENCE="$ASTERISM_HOME/evidence"
IMAGE="${E2E_IMAGE:-docker.io/library/nginx:alpine}"
INST=ports
RIVAL=ports-rival
GUEST_UDP=7777
ASTD_PID=
SERVICE_INSTALLED=

# Two host ports nothing else on this device holds. Taken from the ephemeral
# range by binding and letting go, which is what every other port allocation
# in this tree does; the declaration then owns them for the rest of the run.
free_port() {
  python3 - <<'PY'
import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
PY
}

cleanup() {
  "$AST" down "$INST" >/dev/null 2>&1 || true
  "$AST" rm "$INST" >/dev/null 2>&1 || true
  "$AST" rm "$RIVAL" >/dev/null 2>&1 || true
  if [ -n "$SERVICE_INSTALLED" ]; then
    "$AST" service uninstall >/dev/null 2>&1 || true
  fi
  harness_keep_home "$ASTERISM_HOME" home
  harness_reap
  if [ -n "${KEEP:-}" ]; then
    echo "kept $ASTERISM_HOME for inspection"
  else
    case "$ASTERISM_HOME" in
      /private/tmp/ast-ports-* | /tmp/ast-ports-*) rm -rf -- "$ASTERISM_HOME" ;;
      *) echo "refusing to remove unexpected scratch path: $ASTERISM_HOME" >&2 ;;
    esac
  fi
  harness_artifacts_note
}
trap cleanup EXIT

fail() { echo "NATIVE PORTS E2E FAIL: $*" >&2; exit 1; }
ok() { echo "ok: $*"; }

expect() {
  local desc="$1" needle="$2"; shift 2
  local out
  out="$("$@" 2>&1)" || fail "$desc: command failed:"$'\n'"$out"
  grep -qF "$needle" <<<"$out" || fail "$desc: expected \"$needle\" in:"$'\n'"$out"
  ok "$desc"
}

guest() { "$AST" exec "$INST" -- /bin/sh -c "$1"; }

guest_pid() {
  "$AST" status "$INST" 2>/dev/null | sed -n 's/^running: .* pid \([0-9]*\),.*/\1/p'
}

wait_daemon_pid() {
  local old="$1" now
  for _ in $(seq 1 150); do
    now="$(cat "$ASTERISM_HOME/astd.pid" 2>/dev/null || true)"
    if [ -n "$now" ] && [ "$now" != "$old" ] && kill -0 "$now" 2>/dev/null; then
      ASTD_PID="$now"
      return 0
    fi
    sleep 0.2
  done
  return 1
}

wait_guest_pid() {
  local old="$1" now
  for _ in $(seq 1 120); do
    now="$(guest_pid)"
    if [ -n "$now" ] && [ "$now" != "$old" ] && kill -0 "$now" 2>/dev/null; then
      echo "$now"
      return 0
    fi
    sleep 1
  done
  return 1
}

# ---- the assertions this lane exists for -----------------------------------

# The published TCP endpoint really serves the guest's nginx. `curl` writes
# only the status line, so a proxy that accepted and then hung is a failure
# rather than a pass.
http_status() {
  curl -s -o /dev/null -m 5 -w '%{http_code}' "http://127.0.0.1:$1/" 2>/dev/null || true
}

expect_http_200() {
  local desc="$1" port="$2" code=
  for _ in $(seq 1 60); do
    code="$(http_status "$port")"
    [ "$code" = 200 ] && { ok "$desc (HTTP $code on 127.0.0.1:$port)"; return 0; }
    sleep 2
  done
  fail "$desc: 127.0.0.1:$port answered \"$code\", not 200"
}

expect_no_tcp() {
  local desc="$1" port="$2" code=
  for _ in $(seq 1 30); do
    code="$(http_status "$port")"
    [ "$code" = 000 ] && { ok "$desc"; return 0; }
    sleep 1
  done
  fail "$desc: 127.0.0.1:$port is still answering (\"$code\")"
}

# The listener is loopback and nothing else. A published endpoint that had
# picked 0.0.0.0 would pass every functional assertion above while being
# reachable from the LAN, which is the one thing it must never be.
assert_loopback_only() {
  local desc="$1" port="$2" listeners=
  command -v lsof >/dev/null 2>&1 || { echo "skip: $desc (no lsof)"; return 0; }
  listeners="$(lsof -nP -iTCP:"$port" -sTCP:LISTEN 2>/dev/null | tail -n +2 || true)"
  [ -n "$listeners" ] || fail "$desc: nothing is listening on $port at all"
  if grep -qv '127\.0\.0\.1:' <<<"$(awk '{print $9}' <<<"$listeners")"; then
    printf '%s\n' "$listeners"
    fail "$desc: a published endpoint bound something other than 127.0.0.1"
  fi
  ok "$desc"
}

# One datagram out and one back, through the relay. busybox's nc is what an
# alpine image has; `-e /bin/cat` makes it an echo server for one exchange.
start_guest_udp_echo() {
  guest "(setsid nc -u -l -p $GUEST_UDP -e /bin/cat >/dev/null 2>&1 &) ; sleep 1; echo started" \
    | grep -q started || fail "could not start the guest UDP echo server"
  ok "a UDP echo server is listening on the guest's :$GUEST_UDP"
}

expect_udp_echo() {
  local desc="$1" port="$2" marker="$3" reply=
  for _ in $(seq 1 20); do
    reply="$(printf '%s' "$marker" | nc -u -w 3 127.0.0.1 "$port" 2>/dev/null || true)"
    if grep -qF "$marker" <<<"$reply"; then
      ok "$desc (echoed \"$marker\" through 127.0.0.1:$port/udp)"
      return 0
    fi
    sleep 2
  done
  fail "$desc: 127.0.0.1:$port/udp echoed \"$reply\", not \"$marker\""
}

# ---- the run ---------------------------------------------------------------

mkdir -p "$BIN/guest/bin" "$EVIDENCE"
cp "$AST" "$ASTD" "$BIN/"
if [ "$BACKEND" = vz ]; then
  if [ -x "$(dirname "$ASTD")/astd-vz" ]; then
    cp "$(dirname "$ASTD")/astd-vz" "$BIN/astd-vz"
  else
    fail "no astd-vz beside $ASTD — run scripts/sign-vz.sh"
  fi
fi
cp "$GUEST_ARTIFACT" "$BIN/guest/bin/asterism-guest"
chmod 0755 "$BIN/guest/bin/asterism-guest"
AST="$BIN/ast"
ASTD="$BIN/astd"
export AST ASTD

HTTP_PORT="$(free_port)"
UDP_PORT="$(free_port)"
[ -n "$HTTP_PORT" ] && [ -n "$UDP_PORT" ] || fail "could not pick two free host ports"

echo "== native published ports on $BACKEND, in $ASTERISM_HOME"
echo "== tcp 127.0.0.1:$HTTP_PORT -> :80, udp 127.0.0.1:$UDP_PORT -> :$GUEST_UDP"

harness_cache_image "$AST" "$IMAGE" || fail "could not cache $IMAGE"
harness_seed_images "$ASTERISM_HOME"

"$ASTD" >>"$LOG" 2>&1 &
ASTD_PID=$!
for _ in $(seq 1 100); do
  [ "$(cat "$ASTERISM_HOME/astd.pid" 2>/dev/null || true)" = "$ASTD_PID" ] && break
  sleep 0.2
done
[ "$(cat "$ASTERISM_HOME/astd.pid" 2>/dev/null || true)" = "$ASTD_PID" ] \
  || fail "astd did not come up:"$'\n'"$(cat "$LOG" 2>/dev/null || true)"

# The create that used to be refused on this backend. AST-97's refusal named
# `brew install qemu`; AST-139 is this succeeding instead.
expect "create a published OCI VM on the native $BACKEND backend" "$INST  defined" \
  "$AST" create "$INST" --backend "$BACKEND" --image "$IMAGE" \
    --cpus 2 --mem 1G --disk 4G \
    -p "$HTTP_PORT:80" -p "$UDP_PORT:$GUEST_UDP/udp"
expect "the instance really recorded $BACKEND" "machine: $BACKEND" "$AST" status "$INST"
expect "the declaration is durable and loopback-only" \
  "127.0.0.1:$HTTP_PORT -> :80/tcp" "$AST" status "$INST"
expect "the udp declaration carries its transport" \
  "127.0.0.1:$UDP_PORT -> :$GUEST_UDP/udp" "$AST" status "$INST"

up_out="$("$AST" up "$INST" --restart always 2>&1)" \
  || fail "booting the published OCI VM:"$'\n'"$up_out"
grep -qF "$INST  running" <<<"$up_out" || fail "up did not report running:"$'\n'"$up_out"
ok "boot it with a persistent restart policy"
grep -qF "published: 127.0.0.1:$HTTP_PORT  ->  guest :80/tcp" <<<"$up_out" \
  || fail "up did not name the endpoint it published:"$'\n'"$up_out"
grep -qF "published: 127.0.0.1:$UDP_PORT  ->  guest :$GUEST_UDP/udp" <<<"$up_out" \
  || fail "up did not name the published UDP endpoint:"$'\n'"$up_out"
ok "up names both endpoints it published, on 127.0.0.1"
harness_assert_backend "$AST" "$INST" "$BACKEND"

expect_http_200 "the published TCP endpoint serves the guest's nginx" "$HTTP_PORT"
assert_loopback_only "the TCP listener is bound on 127.0.0.1 and nowhere else" "$HTTP_PORT"

start_guest_udp_echo
expect_udp_echo "the published UDP endpoint relays datagrams both ways" \
  "$UDP_PORT" "ast-udp-$$"

# ---- a second declaration on the same host port ----------------------------
#
# Refused, and refused by name. Two instances quietly sharing a host port
# would mean one of them silently serving the other's clients.
rival_out="$("$AST" create "$RIVAL" --backend "$BACKEND" --image "$IMAGE" \
  --cpus 2 --mem 1G --disk 4G -p "$HTTP_PORT:80" 2>&1)" || true
if grep -qF "$RIVAL  defined" <<<"$rival_out"; then
  up_out="$("$AST" up "$RIVAL" 2>&1)" && fail \
    "a second instance took a host port $INST already publishes:"$'\n'"$up_out"
  grep -qF "$HTTP_PORT" <<<"$up_out" \
    || fail "the collision refusal did not name the port:"$'\n'"$up_out"
  ok "a second instance is refused the host port $INST publishes, by name"
  "$AST" rm "$RIVAL" >/dev/null 2>&1 || true
else
  grep -qF "$HTTP_PORT" <<<"$rival_out" \
    || fail "the second create failed for an unrelated reason:"$'\n'"$rival_out"
  ok "a second declaration of $HTTP_PORT is refused at create"
fi

# ---- down / up -------------------------------------------------------------
expect "take the guest down" "$INST  stopped" "$AST" down "$INST"
expect_no_tcp "the host port is released with the guest behind it" "$HTTP_PORT"
expect "bring it back" "$INST  running" "$AST" up "$INST"
expect_http_200 "up recreated the endpoint on exactly the declared port" "$HTTP_PORT"
start_guest_udp_echo
expect_udp_echo "the UDP endpoint came back on its own port too" \
  "$UDP_PORT" "ast-udp-again-$$"

# ---- daemon restart, guest left alive --------------------------------------
#
# The helper outlives astd, so the guest keeps running and its published
# endpoints are process-local state the new daemon has to rebuild from the
# registry — on the same port, or not at all.
OLD_DAEMON="$ASTD_PID"
kill -9 "$ASTD_PID" 2>/dev/null || true
wait "$ASTD_PID" 2>/dev/null || true
ASTD_PID=
expect_no_tcp "a dead daemon takes its listeners with it" "$HTTP_PORT"
SERVICE_INSTALLED=1
service_report="$("$AST" service install 2>&1)" \
  || fail "installing the scratch astd service:"$'\n'"$service_report"
wait_daemon_pid "$OLD_DAEMON" || fail "the service manager did not start the scratch astd"
expect "the adopted guest is still the same guest" "machine: $BACKEND" \
  "$AST" status "$INST"
expect_http_200 "a restarted daemon recovered the endpoint on its declared port" "$HTTP_PORT"
assert_loopback_only "the recovered listener is still loopback-only" "$HTTP_PORT"

# ---- daemon + VMM loss, restart=always -------------------------------------
BEFORE_DAEMON="$ASTD_PID"
BEFORE_GUEST="$(guest_pid)"
[ -n "$BEFORE_GUEST" ] || fail "no VMM pid before host-equivalent loss"
kill -STOP "$BEFORE_DAEMON"
kill -9 "$BEFORE_GUEST"
kill -9 "$BEFORE_DAEMON"
ASTD_PID=
wait_daemon_pid "$BEFORE_DAEMON" || fail "the service manager did not resurrect astd"
AFTER_GUEST="$(wait_guest_pid "$BEFORE_GUEST")" \
  || fail "the resurrected daemon did not recreate the guest"
ok "astd was resurrected and recreated the VMM as $AFTER_GUEST"
harness_assert_backend "$AST" "$INST" "$BACKEND"
expect_http_200 "the endpoint survived daemon and VMM loss, on the same port" "$HTTP_PORT"
start_guest_udp_echo
expect_udp_echo "so did the UDP endpoint" "$UDP_PORT" "ast-udp-resurrect-$$"

# ---- diagnostics and teardown ----------------------------------------------
bugreport="$("$AST" bugreport 2>&1)" || fail "ast bugreport failed:"$'\n'"$bugreport"
printf '%s\n' "$bugreport" >"$EVIDENCE/bugreport.txt"
grep -qF "$INST" <<<"$bugreport" || fail "bugreport omitted the published instance"

expect "stop the completed lane" "$INST  stopped" "$AST" down "$INST"
expect_no_tcp "removing the guest gives the host port back" "$HTTP_PORT"
expect "remove the completed lane" "$INST  removed" "$AST" rm "$INST"
echo "NATIVE PORTS E2E GREEN ($IMAGE, $BACKEND, tcp $HTTP_PORT/udp $UDP_PORT)"
