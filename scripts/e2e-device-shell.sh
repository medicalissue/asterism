#!/usr/bin/env bash
# End-to-end for the opt-in device shell: two real daemons pair over the
# loopback mesh, the target refuses by default, local approval survives a
# restart, command/PTY/exit status cross the mesh, and policy or membership
# revocation kills an already-running process without opening a TCP listener.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
. "$ROOT/scripts/lib/harness.sh"
harness_begin device-shell
harness_binaries "$ROOT"

export ASTERISM_MESH=local
RUN="/tmp/ast-device-shell-$$"
A="$RUN/a"
B="$RUN/b"
A_NAME="shell-a-$$"
B_NAME="shell-b-$$"

fail() {
  echo "DEVICE SHELL E2E FAIL: $*" >&2
  exit 1
}

cleanup() {
  harness_keep_home "$A" a
  harness_keep_home "$B" b
  harness_keep "$A/invite.out" a-invite.out
  harness_keep "$B/add.out" b-add.out
  harness_keep "$B/shell.json" b-shell.json
  harness_keep "$B/shell-audit.jsonl" b-shell-audit.jsonl
  harness_reap
  rm -rf "$RUN"
  harness_artifacts_note
}
trap cleanup EXIT

start_daemon() {
  local home="$1"
  mkdir -p "$home"
  ASTERISM_HOME="$home" "$ASTD" >"$home/astd.log" 2>&1 &
  harness_own "$!"
  harness_own_home "$home"
  for _ in $(seq 1 100); do
    grep -q "on the mesh as" "$home/astd.log" 2>/dev/null && return 0
    sleep 0.1
  done
  fail "daemon did not start in $home: $(cat "$home/astd.log" 2>/dev/null)"
}

stop_daemon() {
  local home="$1" pid
  pid="$(cat "$home/astd.pid" 2>/dev/null || true)"
  [ -n "$pid" ] || fail "no daemon pid in $home"
  harness_stop "$pid"
}

refute() {
  local description="$1" needle="$2"
  shift 2
  local output
  if output="$("$@" 2>&1)"; then
    fail "$description unexpectedly succeeded: $output"
  fi
  grep -qF "$needle" <<<"$output" || fail "$description did not say $needle: $output"
  echo "ok: $description"
}

mkdir -p "$A" "$B"
start_daemon "$A"
start_daemon "$B"

# Pair the two authenticated endpoints.
ASTERISM_HOME="$A" "$AST" device invite --name "$A_NAME" --yes >"$A/invite.out" 2>&1 &
INVITE_PID=$!
harness_own "$INVITE_PID"
TICKET=""
for _ in $(seq 1 100); do
  TICKET="$(grep -o 'astdev1[a-z0-9]*' "$A/invite.out" 2>/dev/null | head -1 || true)"
  [ -n "$TICKET" ] && break
  sleep 0.1
done
[ -n "$TICKET" ] || fail "the invite printed no ticket"
ASTERISM_HOME="$B" "$AST" device add "$TICKET" --name "$B_NAME" --yes >"$B/add.out" 2>&1
wait "$INVITE_PID"
A_ID="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["devices"][0]["device_id"])' "$B/orbit.json")"
echo "ok: paired two real daemons"

# Disabled is fail-closed, and policy control itself is local-only.
refute "fresh target refuses a remote shell" "disabled" env ASTERISM_HOME="$A" "$AST" ssh --host "$B_NAME" -- "printf forbidden"
refute "a peer cannot remotely enable the target" "cannot be aimed" env ASTERISM_HOME="$A" "$AST" --device "$B_NAME" device shell enable

ASTERISM_HOME="$B" "$AST" device shell enable >"$B/enable.out"
grep -q "full authority" "$B/enable.out" || fail "enable did not disclose account authority"
echo "ok: target accepted local approval with an explicit warning"

# Non-PTY output and exact exit status.
OUT="$(ASTERISM_HOME="$A" "$AST" ssh --host "$B_NAME" -- "printf mesh-ok")"
[ "$OUT" = "mesh-ok" ] || fail "remote command output was $OUT"
set +e
ASTERISM_HOME="$A" "$AST" ssh --host "$B_NAME" -- "exit 23" >/dev/null 2>&1
STATUS=$?
set -e
[ "$STATUS" -eq 23 ] || fail "remote exit 23 became $STATUS"
echo "ok: command output and exit status crossed the mesh"

# A forced PTY is a real terminal. A non-interactive caller has the documented
# 80x24 fallback; the unit test exercises a live resize to 94x42.
PTY_OUT="$(ASTERISM_HOME="$A" "$AST" ssh --host "$B_NAME" -t -- "stty size")"
tr -d '' <<<"$PTY_OUT" | grep -q "24 80" || fail "remote pty reported $PTY_OUT"
echo "ok: forced command received a real pty"

# The target daemon owns a QUIC/UDP endpoint and unix control socket, not a TCP
# shell or sshd listener.
B_PID="$(cat "$B/astd.pid")"
if command -v lsof >/dev/null 2>&1; then
  LISTENERS="$(lsof -nP -a -p "$B_PID" -iTCP -sTCP:LISTEN 2>/dev/null | tail -n +2 || true)"
  [ -z "$LISTENERS" ] || fail "target opened TCP listeners: $LISTENERS"
fi
echo "ok: device shell opened no TCP listener"

# Disable linearizes before it drains and kills a tracked process group.
ASTERISM_HOME="$A" "$AST" ssh --host "$B_NAME" -- "sleep 30" >/dev/null 2>"$A/disabled-session.out" &
SESSION_PID=$!
harness_own "$SESSION_PID"
for _ in $(seq 1 100); do
  STATUS_OUT="$(ASTERISM_HOME="$B" "$AST" device shell status)"
  grep -q "^device shell: active" <<<"$STATUS_OUT" && break
  sleep 0.05
done
DISABLE_OUT="$(ASTERISM_HOME="$B" "$AST" device shell disable)"
grep -q "1 active session(s) cut" <<<"$DISABLE_OUT" || fail "disable did not report its cut"
set +e
wait "$SESSION_PID"
STATUS=$?
set -e
[ "$STATUS" -ne 0 ] || fail "the revoked session reported success"
refute "disabled target refuses a new stream" "disabled" env ASTERISM_HOME="$A" "$AST" ssh --host "$B_NAME" -- "printf forbidden"
echo "ok: disable revoked an active process group and blocked new opens"

# Re-enable, then prove peer removal has the same live-session effect.
ASTERISM_HOME="$B" "$AST" device shell enable >/dev/null
ASTERISM_HOME="$A" "$AST" ssh --host "$B_NAME" -- "sleep 30" >/dev/null 2>"$A/removed-session.out" &
SESSION_PID=$!
harness_own "$SESSION_PID"
for _ in $(seq 1 100); do
  STATUS_OUT="$(ASTERISM_HOME="$B" "$AST" device shell status)"
  grep -q "^device shell: active" <<<"$STATUS_OUT" && break
  sleep 0.05
done
ASTERISM_HOME="$B" "$AST" device rm "$A_NAME" >/dev/null
set +e
wait "$SESSION_PID"
STATUS=$?
set -e
[ "$STATUS" -ne 0 ] || fail "peer removal left its session successful"
echo "ok: peer removal revoked its active session"

# Audit carries the full authenticated key and lifecycle, but no command,
# environment values, stdin, output or transcript.
grep -qF "$A_ID" "$B/shell-audit.jsonl" || fail "audit omitted the approved full peer id"
grep -q '"event":"start"' "$B/shell-audit.jsonl" || fail "audit omitted start"
grep -q '"event":"revoke"' "$B/shell-audit.jsonl" || fail "audit omitted revoke"
if grep -qE 'mesh-ok|forbidden|sleep 30|stty size' "$B/shell-audit.jsonl"; then
  fail "audit captured command or transcript content"
fi
echo "ok: audit is structured, full-keyed, and content-free"

# Approval is durable. This comes last because ASTERISM_MESH=local deliberately
# has no discovery service through which A could learn B's new ephemeral QUIC
# address after B restarts.
stop_daemon "$B"
start_daemon "$B"
ASTERISM_HOME="$B" "$AST" device shell status | grep -q "enabled for the approved orbit"
echo "ok: approval survived daemon restart"
echo "DEVICE SHELL E2E PASS"
