#!/usr/bin/env bash
# End-to-end for the persistence pack, with real boots. Proves the four
# claims that make "your agent's home never sleeps" true rather than
# marketing:
#
#   1. kill -9 the guest    -> the supervisor restarts it, ssh answers again
#   2. kill -9 astd + guest -> the next astd resurrects it, nobody types `up`
#   3. while an instance runs this device holds a sleep assertion, and
#      drops it when the instance stops
#   4. `ast service install` produces a unit the OS actually loads, and
#      uninstall leaves nothing behind
#
# Asserts on CONTENT, like scripts/e2e.sh, and for the same reason.
#
# Two deliberate differences from e2e.sh: the binaries are copied into the
# scratch home before use (sibling checkouts run `pkill -f
# target/debug/astd`, and this test's daemon must not be collateral
# damage), and astd is started by this script rather than by the CLI, so
# its log is a file the assertions can read.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export PATH="$HOME/.cargo/bin:$PATH"
cd "$ROOT"
cargo build -q

# Fresh, SHORT home: unix socket paths are capped near 104 bytes.
export ASTERISM_HOME="/private/tmp/ast-persist-$$"

# A single-device test has no orbit, so it has no business publishing a
# throwaway key and this machine's addresses to a public discovery service.
export ASTERISM_MESH=local
BIN="$ASTERISM_HOME/bin"
AST="$BIN/ast"
ASTD="$BIN/astd"
LOG="$ASTERISM_HOME/astd.log"
IMAGE="${E2E_IMAGE:-debian:13}"
INST=persist
LABEL=com.asterism.astd
PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"
ASTD_PID=
WE_INSTALLED=

fail() { echo "E2E FAIL: $*" >&2; exit 1; }
ok() { echo "ok: $*"; }

cleanup() {
  if [ -n "$WE_INSTALLED" ]; then "$AST" service uninstall >/dev/null 2>&1 || true; fi
  if [ -n "$ASTD_PID" ]; then kill -9 "$ASTD_PID" 2>/dev/null || true; fi
  # Only ever our own processes: every one of them names this home on its
  # command line.
  pkill -9 -f "$ASTERISM_HOME" 2>/dev/null || true
  if [ -n "${KEEP:-}" ]; then
    echo "kept $ASTERISM_HOME for inspection"
  else
    rm -rf "$ASTERISM_HOME"
  fi
  return 0
}
trap cleanup EXIT

mkdir -p "$ASTERISM_HOME/images" "$BIN"
cp "$ROOT/target/debug/ast" "$ROOT/target/debug/astd" "$BIN/"
if [ -d "$HOME/.asterism/images" ]; then
  cp "$HOME/.asterism/images/"*.qcow2 "$ASTERISM_HOME/images/" 2>/dev/null || true
fi

# The service half of this test writes to the real ~/Library/LaunchAgents.
# Anything already there is the user's, and this test does not get to
# touch it.
if [ -e "$PLIST" ]; then
  fail "$PLIST already exists — refusing to disturb it"
fi

# expect <desc> <needle> <cmd...>: run cmd, require success AND the needle
# in its combined output.
expect() {
  local desc="$1" needle="$2"; shift 2
  local out
  out="$("$@" 2>&1)" || fail "$desc: command failed:"$'\n'"$out"
  grep -qF "$needle" <<<"$out" || fail "$desc: expected \"$needle\" in:"$'\n'"$out"
  ok "$desc"
}

# Started here, not by the CLI: `ast` spawns a daemon with its output on
# /dev/null, and the restart reasons in that output are half the point.
# Waits on the pid file rather than on `ast ls`, because a CLI call while
# the socket is not up yet would spawn a second daemon.
start_astd() {
  "$ASTD" >>"$LOG" 2>&1 &
  ASTD_PID=$!
  for _ in $(seq 1 100); do
    if [ "$(cat "$ASTERISM_HOME/astd.pid" 2>/dev/null || true)" = "$ASTD_PID" ]; then
      return 0
    fi
    sleep 0.2
  done
  fail "astd did not come up; log:"$'\n'"$(cat "$LOG" 2>/dev/null || true)"
}

stop_astd() {
  if [ -n "$ASTD_PID" ]; then
    kill -9 "$ASTD_PID" 2>/dev/null || true
    wait "$ASTD_PID" 2>/dev/null || true
    ASTD_PID=
  fi
}

guest_pid() {
  "$AST" status "$INST" 2>/dev/null | sed -n 's/^running: .* pid \([0-9]*\),.*/\1/p'
}

dead() {
  if kill -0 "$1" 2>/dev/null; then return 1; fi
  return 0
}

# wait_new_pid <old-pid> <seconds>: a different, live guest pid appears.
wait_new_pid() {
  local old="$1" secs="$2" now
  for _ in $(seq 1 "$secs"); do
    now="$(guest_pid)"
    if [ -n "$now" ] && [ "$now" != "$old" ] && kill -0 "$now" 2>/dev/null; then
      echo "$now"; return 0
    fi
    sleep 1
  done
  return 1
}

# `pmset | grep -q` would be the obvious spelling and is a trap: grep -q
# exits on the first match, pmset dies of SIGPIPE, and `set -o pipefail`
# then reports the whole pipeline as failed even though the assertion is
# there. Matching on a captured string has no pipeline to misread.
assertions() { pmset -g assertions 2>/dev/null || true; }

held_assertion() {
  case "$(assertions)" in *"pid $ASTD_PID("*) return 0 ;; *) return 1 ;; esac
}

waited_for() {
  local desc="$1" secs="$2"; shift 2
  for _ in $(seq 1 "$secs"); do
    if "$@"; then ok "$desc"; return 0; fi
    sleep 1
  done
  fail "$desc: never happened within ${secs}s; astd log:"$'\n'"$(tail -40 "$LOG" 2>/dev/null || true)"
}

logged() { grep -qF "$1" "$LOG"; }

echo "== persistence e2e in $ASTERISM_HOME"
start_astd
"$AST" pull "$IMAGE" >/dev/null 2>&1 || fail "pull $IMAGE"

expect "create" "$INST  defined" "$AST" create "$INST" --image "$IMAGE" --mem 2G --disk 10G
expect "up"     "$INST  running" "$AST" up "$INST"
expect "guest answers" "hello-persist" "$AST" ssh "$INST" -- "echo hello-persist"

PID1="$(guest_pid)"
[ -n "$PID1" ] || fail "no guest pid recorded after up"
ok "guest running as pid $PID1"

# The restart policy is part of the instance, in the registry, and `ast
# status` is where a user reads it. It used to be a policy.json sidecar; if
# one turns up again there are two places it lives and they can disagree.
POLICY="$ASTERISM_HOME/instances/$INST/policy.json"
expect "the default policy is on the instance" "restart: always" "$AST" status "$INST"
[ ! -e "$POLICY" ] || fail "a policy.json sidecar is back beside $INST"
grep -q '"restart": "always"' "$ASTERISM_HOME/state.json" \
  || fail "the registry does not record the restart policy:"$'\n'"$(cat "$ASTERISM_HOME/state.json")"
ok "the registry holds it: $(grep -m1 '"restart"' "$ASTERISM_HOME/state.json" | tr -d ' ')"

# ---- 3. the sleep assertion, while something runs --------------------------
waited_for "astd holds a power assertion while $INST runs" 15 held_assertion
case "$(assertions)" in
  *"Asterism is running instances"*) ;;
  *) fail "the assertion does not say who holds it:"$'\n'"$(assertions)" ;;
esac
ok "pmset: $(grep -F "pid $ASTD_PID(" <<<"$(assertions)" | sed -n '1p' | sed 's/^ *//')"

# ---- 1. crash restart ------------------------------------------------------
#
# Flush the guest first. `kill -9` is a yanked power cord, and this guest
# finished its first boot twenty seconds ago. Whether its ssh host keys
# survive that is a durability property of the seed, not anything the
# supervisor does, and it has a test of its own: scripts/e2e-keys.sh. This
# one is about restarts, so it takes the durability out of the picture.
expect "guest flushes its first-boot writes" "flushed" \
  "$AST" ssh "$INST" -- "sync; echo flushed"
echo "== kill -9 the guest"
kill -9 "$PID1"
sleep 1
dead "$PID1" || fail "qemu $PID1 survived kill -9"
PID2="$(wait_new_pid "$PID1" 90)" || fail "the supervisor never restarted $INST"
ok "supervisor restarted the guest as pid $PID2"
logged "restarting it (attempt 1 of 3)" \
  || fail "the daemon log does not record the restart:"$'\n'"$(cat "$LOG")"
ok "the daemon log says why: $(grep -m1 'restarting it' "$LOG")"
# `sync` again for the same reason: the next step is another power cut.
expect "guest answers after the crash" "back-from-the-dead" \
  "$AST" ssh "$INST" -- "echo back-from-the-dead; sync"
expect "status says running" "status:  running" "$AST" status "$INST"

# ---- 2. host reboot: astd and the guest both die ---------------------------
echo "== kill -9 astd and the guest, then start astd again"
stop_astd
kill -9 "$PID2" 2>/dev/null || true
sleep 1
dead "$PID2" || fail "qemu $PID2 survived kill -9"
grep -q '"status": "running"' "$ASTERISM_HOME/state.json" \
  || fail "the registry forgot that $INST was running"
ok "the registry still records $INST running, with nothing behind it"

start_astd
PID3="$(wait_new_pid "$PID2" 90)" || fail "astd did not resurrect $INST at startup"
ok "astd resurrected the guest as pid $PID3 — nobody ran a command"
logged "was running when this device last had a daemon" \
  || fail "astd did not report a resurrection:"$'\n'"$(cat "$LOG")"
ok "the daemon log: $(grep -m1 'last had a daemon' "$LOG")"
expect "guest answers after the reboot" "risen" "$AST" ssh "$INST" -- "echo risen"

# ---- a deliberate down is not a crash --------------------------------------
expect "down" "$INST  stopped" "$AST" down "$INST"
sleep 12
expect "it stays down" "status:  stopped" "$AST" status "$INST"
dead "$PID3" || fail "the guest is still alive after down"
ok "the supervisor left a deliberately stopped instance alone"

# ---- 3b. and the assertion goes away ---------------------------------------
not_held() { if held_assertion; then return 1; fi; return 0; }
waited_for "the power assertion is released" 20 not_held
logged "this device may sleep" || fail "astd did not log releasing the assertion"
ok "the daemon log: $(grep -m1 'may sleep' "$LOG")"

# ---- a policy.json from an older daemon is folded in and taken away --------
#
# The instance is stopped by now, so this changes what the supervisor would
# do without asking it to do anything.
echo "== an older daemon's policy.json"
printf '{"restart":"never","max_attempts":7}\n' > "$POLICY"
stop_astd
start_astd
[ ! -e "$POLICY" ] || fail "the sidecar survived a daemon that was supposed to fold it in"
expect "the old file's policy is on the instance now" "restart: never" "$AST" status "$INST"
logged "folded into the registry" \
  || fail "astd did not say it had migrated the sidecar:"$'\n'"$(cat "$LOG")"
ok "the daemon log: $(grep -m1 'folded into the registry' "$LOG")"
grep -q '"max_attempts": 7' "$ASTERISM_HOME/state.json" \
  || fail "the whole file was not kept, only half of it"
ok "and the whole file was kept, restart budget included"

# `ast up --restart` is the surface that replaces editing that file.
expect "up --restart always sets it back" "$INST  running" "$AST" up "$INST" --restart always
expect "and ast status says so" "restart: always" "$AST" status "$INST"
expect "down again" "$INST  stopped" "$AST" down "$INST"

expect "rm" "$INST  removed" "$AST" rm "$INST"

# ---- 4. astd as a service --------------------------------------------------
echo "== service install / uninstall"
stop_astd
sleep 1

expect "status before install" "not installed" "$AST" service status
WE_INSTALLED=1
expect "install" "launchctl bootstrap" "$AST" service install
[ -f "$PLIST" ] || fail "no plist at $PLIST"
grep -qF "$BIN/astd" "$PLIST" || fail "the plist does not name the astd it was installed from"
grep -qF "$ASTERISM_HOME" "$PLIST" || fail "the plist does not carry ASTERISM_HOME"
grep -qF "<key>KeepAlive</key>" "$PLIST" || fail "the plist does not ask launchd to keep it alive"
ok "the plist names this astd, this home, and KeepAlive"

launchctl print "gui/$(id -u)/$LABEL" >/dev/null 2>&1 \
  || fail "launchd will not print $LABEL — the plist did not load"
ok "launchctl print loads the service"

# RunAtLoad + KeepAlive means launchd starts it without being asked.
service_running() {
  case "$("$AST" service status 2>/dev/null || true)" in *"running (pid"*) return 0 ;; esac
  return 1
}
waited_for "launchd started astd by itself" 20 service_running
ok "$("$AST" service status | head -1)"

expect "uninstall" "launchctl bootout" "$AST" service uninstall
WE_INSTALLED=
if [ -e "$PLIST" ]; then fail "$PLIST survived uninstall"; fi
# The plist is committed durably, which leaves a last-known-good copy beside
# it. Uninstall means uninstall: that goes too.
if [ -e "$PLIST.bak" ]; then fail "$PLIST.bak survived uninstall"; fi
if [ -e "$PLIST.tmp" ]; then fail "$PLIST.tmp survived uninstall"; fi
if launchctl print "gui/$(id -u)/$LABEL" >/dev/null 2>&1; then
  fail "launchd still has $LABEL loaded after uninstall"
fi
expect "status after uninstall" "not installed" "$AST" service status
ok "~/Library/LaunchAgents is clean"

echo "E2E PERSIST GREEN ($IMAGE)"
