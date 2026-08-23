#!/usr/bin/env bash
# Observer-side lifecycle and security gate for one immutable Asterism source
# revision. The observer may be newer; every product executable comes from the
# release archive built and installed from SOURCE.
set -Eeuo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SOURCE="${ASTERISM_GATE_SOURCE_DIR:?set ASTERISM_GATE_SOURCE_DIR}"
EXPECTED_SHA="${ASTERISM_GATE_EXPECTED_SHA:?set ASTERISM_GATE_EXPECTED_SHA}"
EXPECTED_TREE="${ASTERISM_GATE_EXPECTED_TREE:?set ASTERISM_GATE_EXPECTED_TREE}"
OBSERVER_SHA="${ASTERISM_GATE_OBSERVER_SHA:?set ASTERISM_GATE_OBSERVER_SHA}"
OBSERVER_REF="${ASTERISM_GATE_OBSERVER_REF:?set ASTERISM_GATE_OBSERVER_REF}"
WORKFLOW_REF="${ASTERISM_GATE_WORKFLOW_REF:?set ASTERISM_GATE_WORKFLOW_REF}"
RUN_ID="${ASTERISM_GATE_RUN_ID:?set ASTERISM_GATE_RUN_ID}"
RUN_ATTEMPT="${ASTERISM_GATE_RUN_ATTEMPT:?set ASTERISM_GATE_RUN_ATTEMPT}"
PREFIX="${ASTERISM_GATE_PREFIX:?set ASTERISM_GATE_PREFIX}"
ARTIFACTS="${ASTERISM_TEST_ARTIFACTS:?set ASTERISM_TEST_ARTIFACTS}"
AST="$PREFIX/bin/ast"
ASTD="$PREFIX/bin/astd"
MAIN_HOME="$(mktemp -d /tmp/asterism-container-gate.XXXXXX)"
export ASTERISM_HOME="$MAIN_HOME"
export ASTERISM_MESH=local
DAEMON_LOG="$ARTIFACTS/daemon.log"
SUMMARY="$ARTIFACTS/summary.txt"
TRANSCRIPT="$ARTIFACTS/transcript.txt"
STAGE=preflight
FAILURES=0
FIRST_FAILURE_STAGE=
DAEMON_PID=
INSTANCE=container-gate
FAILED_INSTANCE=container-failed
SECRET_NAME=container-gate-secret
SECRET_CREATED=
INSTANCE_CREATED=
INSTANCE_RUNNING=
FAILED_CGROUP=

mkdir -p "$ARTIFACTS"
: >"$TRANSCRIPT"

redact() {
  # The raw value is never an argument. This second line of defence prevents
  # an unexpected upstream echo from entering uploaded evidence.
  sed -e "s/${SECRET_VALUE:-__unset_secret__}/[REDACTED]/g"
}

note() {
  printf '%s\n' "$*" | tee -a "$TRANSCRIPT"
}

record_failure() {
  if [ -z "$FIRST_FAILURE_STAGE" ]; then
    FIRST_FAILURE_STAGE="$STAGE"
  fi
  FAILURES=$((FAILURES + 1))
  printf 'FAIL stage=%s detail=%s\n' "$STAGE" "$*" | redact | tee -a "$TRANSCRIPT" >&2
}

fatal() {
  record_failure "$*"
  return 1
}

assert_eq() {
  local description="$1" actual="$2" expected="$3"
  if [ "$actual" != "$expected" ]; then
    record_failure "$description: got [$actual], expected [$expected]"
    return 0
  fi
  note "PASS $description"
}

assert_contains() {
  local description="$1" haystack="$2" needle="$3"
  if ! grep -qF -- "$needle" <<<"$haystack"; then
    record_failure "$description: missing [$needle]"
    return 0
  fi
  note "PASS $description"
}

qemu_absent() {
  local found
  found="$(pgrep -af '[q]emu-system-' || true)"
  if [ -n "$found" ]; then
    record_failure "qemu-system process present: $found"
    return 0
  fi
  note "PASS no qemu-system process ($STAGE)"
}

capture_container_console() {
  local source="$MAIN_HOME/instances/$INSTANCE/console.log"
  if [ -f "$source" ]; then
    redact <"$source" >"$ARTIFACTS/container-console.log"
  fi
}

pid_is_exact_daemon() {
  local pid="$1" exe
  [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null || return 1
  exe="$(readlink -f "/proc/$pid/exe" 2>/dev/null || true)"
  [ "$exe" = "$(readlink -f "$ASTD")" ]
}

stop_daemon() {
  local pid="${DAEMON_PID:-}"
  if ! pid_is_exact_daemon "$pid"; then
    pid="$(cat "$ASTERISM_HOME/astd.pid" 2>/dev/null || true)"
  fi
  if pid_is_exact_daemon "$pid"; then
    kill "$pid" 2>/dev/null || true
    for _ in $(seq 1 100); do
      kill -0 "$pid" 2>/dev/null || break
      sleep 0.05
    done
    if kill -0 "$pid" 2>/dev/null; then
      kill -KILL "$pid" 2>/dev/null || true
    fi
    wait "$pid" 2>/dev/null || true
  fi
  DAEMON_PID=
}

start_daemon() {
  "$ASTD" >>"$DAEMON_LOG" 2>&1 &
  DAEMON_PID=$!
  for _ in $(seq 1 100); do
    if [ "$(cat "$ASTERISM_HOME/astd.pid" 2>/dev/null || true)" = "$DAEMON_PID" ] \
      && [ -S "$ASTERISM_HOME/astd.sock" ]; then
      pid_is_exact_daemon "$DAEMON_PID" || fatal "daemon pid is not installed $ASTD"
      return 0
    fi
    kill -0 "$DAEMON_PID" 2>/dev/null || break
    sleep 0.1
  done
  fatal "installed astd did not become ready; see daemon.log"
}

cleanup() {
  local status=$?
  local failure_stage="$STAGE"
  trap - EXIT ERR INT TERM
  set +e
  STAGE=cleanup
  capture_container_console
  if [ -x "$AST" ]; then
    if [ -n "$INSTANCE_RUNNING" ]; then
      "$AST" down "$INSTANCE" >>"$ARTIFACTS/cleanup.log" 2>&1
    fi
    if [ -n "$INSTANCE_CREATED" ]; then
      "$AST" rm "$INSTANCE" >>"$ARTIFACTS/cleanup.log" 2>&1
    fi
    if [ -n "$SECRET_CREATED" ]; then
      "$AST" secret rm "$SECRET_NAME" >>"$ARTIFACTS/cleanup.log" 2>&1
    fi
  fi
  stop_daemon
  if [ -n "$FAILED_CGROUP" ] && [ -d "$FAILED_CGROUP" ]; then
    [ -w "$FAILED_CGROUP/cgroup.kill" ] && printf '1' >"$FAILED_CGROUP/cgroup.kill"
    rmdir "$FAILED_CGROUP" 2>/dev/null || true
  fi
  case "$MAIN_HOME" in
    /tmp/asterism-container-gate.*) rm -rf -- "$MAIN_HOME" ;;
  esac
  if [ "$status" -ne 0 ] || [ "$FAILURES" -ne 0 ]; then
    {
      echo "result=blocked"
      echo "blocker_stage=${FIRST_FAILURE_STAGE:-$failure_stage}"
      echo "failure_count=$FAILURES"
      echo "exit_status=${status:-1}"
    } >>"$SUMMARY"
  fi
  exit "$status"
}

unexpected_error() {
  local status=$? line="$1" command="$2"
  set +e
  record_failure "unexpected exit $status at line $line: $command"
  return "$status"
}

trap 'unexpected_error "$LINENO" "$BASH_COMMAND"' ERR
trap cleanup EXIT INT TERM

STAGE=preflight
for command in dbus-daemon find git gnome-keyring-daemon grep jq pgrep readlink \
  sha256sum slirp4netns stat systemctl unshare; do
  command -v "$command" >/dev/null || fatal "missing prerequisite: $command"
done
[ "$(uname -s)" = Linux ] || fatal "observer host is not Linux"
[ "$(stat -fc %T /sys/fs/cgroup)" = cgroup2fs ] \
  || fatal "observer host is not using cgroup v2"
[ -x "$AST" ] || fatal "installed ast is absent at $AST"
[ -x "$ASTD" ] || fatal "installed astd is absent at $ASTD"
actual_sha="$(git -C "$SOURCE" rev-parse HEAD)"
actual_tree="$(git -C "$SOURCE" rev-parse 'HEAD^{tree}')"
[ "$actual_sha" = "$EXPECTED_SHA" ] \
  || fatal "source HEAD is $actual_sha, expected $EXPECTED_SHA"
[ "$actual_tree" = "$EXPECTED_TREE" ] \
  || fatal "source tree is $actual_tree, expected $EXPECTED_TREE"
actual_observer="$(git -C "$ROOT" rev-parse HEAD)"
[ "$actual_observer" = "$OBSERVER_SHA" ] \
  || fatal "observer HEAD is $actual_observer, expected $OBSERVER_SHA"
note "PASS exact source SHA and tree"
note "PASS observer HEAD"
qemu_absent

{
  echo "result=pending"
  echo "target_sha=$actual_sha"
  echo "target_tree=$actual_tree"
  echo "observer_sha=$OBSERVER_SHA"
  echo "observer_ref=$OBSERVER_REF"
  echo "workflow_ref=$WORKFLOW_REF"
  echo "run_id=$RUN_ID"
  echo "run_attempt=$RUN_ATTEMPT"
  echo "installed_prefix=$PREFIX"
  echo "host=$(uname -srmo)"
  echo "cgroup_membership=$(cat /proc/self/cgroup)"
  self_cgroup_path="$(sed -n 's/^0:://p' /proc/self/cgroup)"
  echo "cgroup_controllers=$(cat "/sys/fs/cgroup${self_cgroup_path}/cgroup.controllers" 2>/dev/null)"
} >"$SUMMARY"
"$AST" version >"$ARTIFACTS/product-version.txt"
sha256sum "$AST" "$ASTD" >"$ARTIFACTS/product-binaries.sha256"
sha256sum "$ROOT/.github/workflows/container-linux-exact.yml" \
  "$ROOT/scripts/gate-container-linux.sh" >"$ARTIFACTS/observer-files.sha256"

# A disposable, non-empty-password keyring supplies the real Linux Secret
# Service. It is part of host capability; failure is an exact blocker.
STAGE="secret-service"
keyring_env="$(printf '%s\n' asterism-observer-keyring | \
  gnome-keyring-daemon --unlock --components=secrets 2>>"$DAEMON_LOG")" \
  || fatal "FreeDesktop Secret Service could not be unlocked"
eval "$keyring_env"
export GNOME_KEYRING_CONTROL
secret-tool store --label='Asterism observer preflight' \
  asterism observer-preflight <<<"observer-value" >/dev/null \
  || fatal "FreeDesktop Secret Service could not store a preflight value"
secret-tool clear asterism observer-preflight >/dev/null \
  || fatal "FreeDesktop Secret Service could not clear its preflight value"
note "PASS real FreeDesktop Secret Service"

STAGE="daemon-start"
start_daemon
old_daemon="$DAEMON_PID"
installed_version="$("$AST" version 2>&1)"
grep -qF -- "$EXPECTED_SHA" <<<"$installed_version" \
  || fatal "installed product does not report exact build $EXPECTED_SHA"
note "PASS installed build identity"

STAGE="secret-create"
SECRET_VALUE="container-raw-${RUN_ID}-${RUN_ATTEMPT}-$(od -An -N12 -tx1 /dev/urandom | tr -d ' \n')"
SECRET_DIGEST="$(printf %s "$SECRET_VALUE" | sha256sum | awk '{print $1}')"
if ! secret_report="$(printf %s "$SECRET_VALUE" | "$AST" secret create "$SECRET_NAME" 2>&1)"; then
  fatal "creating a secret through stdin and Secret Service failed: $secret_report"
fi
SECRET_CREATED=1
assert_contains "secret creation names metadata only" "$secret_report" "$SECRET_NAME"
printf 'secret_sha256=%s\n' "$SECRET_DIGEST" >>"$SUMMARY"

STAGE="image-create"
IMAGE="${ASTERISM_CONTAINER_GATE_IMAGE:-nginx:1.29.1-bookworm}"
"$AST" pull "$IMAGE" 2>&1 | redact | tee "$ARTIFACTS/image-pull.log"
"$AST" images >"$ARTIFACTS/image-inventory.txt"
PORT="$((20000 + RUN_ID % 20000))"
create_report="$("$AST" create "$INSTANCE" --runtime container --image "$IMAGE" \
  --cpus 1 --mem 512M --disk 2G -p "$PORT:80" 2>&1)" \
  || fatal "native container create failed: $create_report"
INSTANCE_CREATED=1
assert_contains "native create" "$create_report" "$INSTANCE  defined"
attach_report="$("$AST" attach "$INSTANCE" --secret "$SECRET_NAME" \
  --to httpbin.org --as bearer --env ASTERISM_GATE_SECRET 2>&1)" \
  || fatal "binding the opaque secret failed: $attach_report"
assert_contains "secret binding" "$attach_report" "$SECRET_NAME -> httpbin.org"

STAGE=up
up_report="$("$AST" up "$INSTANCE" --restart never 2>&1)" \
  || fatal "native container up failed: $up_report"
INSTANCE_RUNNING=1
assert_contains "native up" "$up_report" "$INSTANCE  running"
status="$("$AST" status "$INSTANCE" 2>&1)" || fatal "status failed after up: $status"
assert_contains "runtime identity" "$status" "runtime: container"
assert_contains "native adapter identity" "$status" "running: linux-rootless pid"
CONTAINER_PID="$(sed -n 's/^running: linux-rootless pid \([0-9][0-9]*\),.*/\1/p' <<<"$status")"
[ -n "$CONTAINER_PID" ] || fatal "status did not expose the native container pid"
if ! kill -0 "$CONTAINER_PID" 2>/dev/null; then
  capture_container_console
  fatal "recorded container pid is not alive"
fi

STAGE="namespace-cgroup"
STATE="$ASTERISM_HOME/state.json"
CGROUP="$(jq -r --arg name "$INSTANCE" \
  '.instances[] | select(.name == $name) | .handle.container_control.cgroup // empty' \
  "$STATE")"
[ -n "$CGROUP" ] && [ -d "$CGROUP" ] || fatal "state did not retain a live delegated cgroup"
for namespace in user mnt pid net; do
  guest_ns="$(readlink "/proc/$CONTAINER_PID/ns/$namespace")"
  host_ns="$(readlink "/proc/self/ns/$namespace")"
  if [ "$guest_ns" = "$host_ns" ]; then
    record_failure "$namespace namespace is shared with observer: $guest_ns"
  else
    note "PASS isolated $namespace namespace ($guest_ns != $host_ns)"
  fi
done
grep -qx "$CONTAINER_PID" "$CGROUP/cgroup.procs" \
  || record_failure "recorded namespace holder is absent from delegated cgroup"
assert_eq "memory.max enforcement" "$(cat "$CGROUP/memory.max")" "536870912"
assert_eq "cpu.max enforcement" "$(cat "$CGROUP/cpu.max")" "100000 100000"
assert_eq "pids.max enforcement" "$(cat "$CGROUP/pids.max")" "512"

STAGE="exec-logs-network"
exec_report="$("$AST" shell "$INSTANCE" -- sh -c \
  'echo container-exec-stdout; echo container-exec-stderr >&2' 2>&1)" \
  || fatal "container exec failed: $exec_report"
assert_contains "exec stdout" "$exec_report" "container-exec-stdout"
assert_contains "exec stderr" "$exec_report" "container-exec-stderr"
for _ in $(seq 1 60); do
  if page="$(curl -fsS --max-time 2 "http://127.0.0.1:$PORT/" 2>/dev/null)" \
    && grep -qF 'Welcome to nginx!' <<<"$page"; then
    break
  fi
  page=
  sleep 0.25
done
[ -n "${page:-}" ] || record_failure "published nginx port never served"
logs="$("$AST" logs "$INSTANCE" -n 400 2>&1)" || record_failure "ast logs failed"
assert_contains "container logs" "$logs" "GET / HTTP/1.1"
qemu_absent

STAGE="down-up"
down_report="$("$AST" down "$INSTANCE" 2>&1)" || fatal "down failed: $down_report"
INSTANCE_RUNNING=
assert_contains "down" "$down_report" "$INSTANCE  stopped"
[ ! -e "$CGROUP" ] || record_failure "down left delegated cgroup $CGROUP"
up_report="$("$AST" up "$INSTANCE" --restart never 2>&1)" \
  || fatal "second up failed: $up_report"
INSTANCE_RUNNING=1
assert_contains "second up" "$up_report" "$INSTANCE  running"
status="$("$AST" status "$INSTANCE" 2>&1)"
CONTAINER_PID="$(sed -n 's/^running: linux-rootless pid \([0-9][0-9]*\),.*/\1/p' <<<"$status")"
CGROUP="$(jq -r --arg name "$INSTANCE" \
  '.instances[] | select(.name == $name) | .handle.container_control.cgroup // empty' \
  "$STATE")"

STAGE="egress-packages"
packages_report="$("$AST" shell "$INSTANCE" -- sh -c \
  'apt-get update >/dev/null && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends curl jq netcat-openbsd perl procps >/dev/null' \
  2>&1)" || record_failure "container could not install egress probes: $packages_report"

STAGE="cpu-enforcement"
throttled_before="$(awk '$1 == "nr_throttled" {print $2}' "$CGROUP/cpu.stat")"
cpu_report="$("$AST" shell "$INSTANCE" -- sh -c \
  'for n in 1 2 3 4; do /.asterism/busybox timeout 3 sh -c "while :; do :; done" & done; wait; true' \
  2>&1)" || record_failure "CPU pressure exec failed: $cpu_report"
throttled_after="$(awk '$1 == "nr_throttled" {print $2}' "$CGROUP/cpu.stat")"
if [ -z "$throttled_before" ] || [ -z "$throttled_after" ] \
  || [ "$throttled_after" -le "$throttled_before" ]; then
  record_failure "cpu.max did not record throttling ($throttled_before -> $throttled_after)"
else
  note "PASS cpu.max throttled real container work ($throttled_before -> $throttled_after)"
fi

STAGE="memory-enforcement"
oom_before="$(awk '$1 == "oom_kill" {print $2}' "$CGROUP/memory.events")"
# shellcheck disable=SC2016 # Perl, not this observer shell, expands $x.
if "$AST" shell "$INSTANCE" -- perl -e \
  '$x = "x" x (768 * 1024 * 1024); sleep 5' \
  >"$ARTIFACTS/memory-pressure.log" 2>&1; then
  record_failure "768 MiB allocation survived a 512 MiB cgroup limit"
else
  note "PASS over-limit allocation was killed"
fi
oom_after="$(awk '$1 == "oom_kill" {print $2}' "$CGROUP/memory.events")"
if [ -z "$oom_before" ] || [ -z "$oom_after" ] || [ "$oom_after" -le "$oom_before" ]; then
  record_failure "memory.max refusal did not increment oom_kill ($oom_before -> $oom_after)"
else
  note "PASS memory.max recorded an OOM kill ($oom_before -> $oom_after)"
fi
"$AST" shell "$INSTANCE" -- sh -c 'echo alive-after-resource-pressure' >/dev/null \
  || record_failure "container did not survive isolated resource pressure"

STAGE="disconnect-drain"
ROOTFS="$ASTERISM_HOME/instances/$INSTANCE/container-rootfs"
rm -f "$ROOTFS/tmp/disconnect-ready" "$ROOTFS/tmp/disconnect-escaped"
"$AST" shell "$INSTANCE" -- sh -c \
  'echo ready >/tmp/disconnect-ready; sleep 60; echo escaped >/tmp/disconnect-escaped' \
  >"$ARTIFACTS/disconnect-client.log" 2>&1 &
CLIENT_PID=$!
ready=
for _ in $(seq 1 100); do
  [ -f "$ROOTFS/tmp/disconnect-ready" ] && { ready=1; break; }
  kill -0 "$CLIENT_PID" 2>/dev/null || break
  sleep 0.05
done
if [ -z "$ready" ]; then
  record_failure "disconnect fixture never entered container exec"
else
  kill "$CLIENT_PID" 2>/dev/null || true
  wait "$CLIENT_PID" 2>/dev/null || true
  sleep 1
  [ ! -e "$ROOTFS/tmp/disconnect-escaped" ] \
    || record_failure "disconnected exec survived and wrote its marker"
  "$AST" shell "$INSTANCE" -- sh -c 'echo control-live-after-disconnect' >/dev/null \
    || record_failure "control channel did not drain after caller disconnect"
  note "PASS caller disconnect drained its exec process group"
fi

STAGE="timeout-drain"
rm -f "$ROOTFS/tmp/timeout-escaped"
started="$(date +%s)"
if timeout_report="$("$AST" shell "$INSTANCE" -- sh -c \
  'sleep 60; echo escaped >/tmp/timeout-escaped' 2>&1)"; then
  record_failure "60-second exec escaped the 30-second lifecycle deadline"
else
  elapsed="$(( $(date +%s) - started ))"
  assert_contains "exec deadline refusal" "$timeout_report" "lifecycle deadline"
  if [ "$elapsed" -lt 25 ] || [ "$elapsed" -gt 40 ]; then
    record_failure "exec deadline took ${elapsed}s, outside the 25-40s bound"
  else
    note "PASS exec deadline returned in ${elapsed}s"
  fi
fi
sleep 1
[ ! -e "$ROOTFS/tmp/timeout-escaped" ] \
  || record_failure "timed-out exec survived and wrote its marker"
"$AST" shell "$INSTANCE" -- sh -c 'echo control-live-after-timeout' >/dev/null \
  || record_failure "control channel did not drain after timeout"

STAGE="secret-egress"
# shellcheck disable=SC2016 # The quoted program expands inside the container.
handle_shape="$("$AST" shell "$INSTANCE" -- sh -c \
  'case "$ASTERISM_GATE_SECRET" in ast-*) echo opaque-handle ;; *) exit 41 ;; esac' 2>&1)" \
  || record_failure "container did not receive an opaque secret handle: $handle_shape"
assert_contains "opaque secret injection" "$handle_shape" "opaque-handle"
# shellcheck disable=SC2016 # The quoted program expands inside the container.
egress_digest="$("$AST" shell "$INSTANCE" -- sh -c \
  'curl -fsS --max-time 25 https://httpbin.org/bearer -H "Authorization: Bearer $ASTERISM_GATE_SECRET" | jq -r .token | sha256sum | awk "{print \\$1}"' \
  2>&1)" || record_failure "bound egress request failed: $egress_digest"
assert_contains "secret substitution in flight" "$egress_digest" "$SECRET_DIGEST"
# shellcheck disable=SC2016 # The quoted program expands inside the container.
wrong_status="$("$AST" shell "$INSTANCE" -- sh -c \
  'wrong_handle="ast-wrong-"handle; curl -sS --max-time 25 -o /tmp/wrong-handle -w "%{http_code}" https://httpbin.org/bearer -H "Authorization: Bearer $wrong_handle" || true' \
  2>&1)" || record_failure "wrong-handle probe could not run"
assert_contains "wrong handle denied" "$wrong_status" "401"
loopback_denial="$("$AST" shell "$INSTANCE" -- sh -c \
  'printf "CONNECT 127.0.0.1:9 HTTP/1.1\r\nHost: 127.0.0.1:9\r\n\r\n" | nc -w 5 127.0.0.1 38123' \
  2>&1)" || true
assert_contains "host loopback denied" "$loopback_denial" "403 Forbidden"
assert_contains "loopback denial reason" "$loopback_denial" "loopback"
unbound_report="$("$AST" shell "$INSTANCE" -- sh -c \
  'curl -fsS --max-time 25 https://example.com >/dev/null && echo unbound-public-egress' 2>&1)" \
  || record_failure "unbound public egress failed: $unbound_report"
assert_contains "unbound public egress allowed" "$unbound_report" "unbound-public-egress"

STAGE="secret-non-leak"
leak_report="$ARTIFACTS/secret-leaks.txt"
: >"$leak_report"
while IFS= read -r -d '' file; do
  grep -a -l -F -- "$SECRET_VALUE" "$file" >>"$leak_report" 2>/dev/null || true
done < <(find "$ASTERISM_HOME" "$HOME" "$ARTIFACTS" -type f -size -256M -print0)
while IFS= read -r -d '' image; do
  if "$SOURCE/scripts/sparse-contains.py" "$image" "$SECRET_VALUE"; then
    printf '%s\n' "$image" >>"$leak_report"
  else
    sparse_status=$?
    [ "$sparse_status" -eq 1 ] \
      || record_failure "sparse secret scan failed for $image with $sparse_status"
  fi
done < <(find "$ASTERISM_HOME" -type f -name '*.raw' -print0)
while read -r member; do
  [ -n "$member" ] || continue
  if tr '\0' '\n' <"/proc/$member/environ" 2>/dev/null | grep -qF -- "$SECRET_VALUE"; then
    printf '/proc/%s/environ\n' "$member" >>"$leak_report"
  fi
done <"$CGROUP/cgroup.procs"
if [ -s "$leak_report" ]; then
  record_failure "raw secret appeared in persisted files or container process environments"
else
  note "PASS raw secret absent from home, keyring files, evidence, images, and container environments"
fi

STAGE="daemon-restart"
before_container="$CONTAINER_PID"
stop_daemon
start_daemon
if [ "$DAEMON_PID" = "$old_daemon" ]; then
  record_failure "daemon restart reused pid $DAEMON_PID"
else
  note "PASS daemon restarted ($old_daemon -> $DAEMON_PID)"
fi
restart_status="$("$AST" status "$INSTANCE" 2>&1)" \
  || record_failure "status failed after daemon restart: $restart_status"
after_container="$(sed -n 's/^running: linux-rootless pid \([0-9][0-9]*\),.*/\1/p' <<<"$restart_status")"
assert_eq "container survived daemon restart" "$after_container" "$before_container"
"$AST" shell "$INSTANCE" -- sh -c 'echo exec-after-daemon-restart' >/dev/null \
  || record_failure "container control did not survive daemon restart"
# shellcheck disable=SC2016 # The quoted program expands inside the container.
restart_egress="$("$AST" shell "$INSTANCE" -- sh -c \
  'curl -fsS --max-time 15 https://httpbin.org/bearer -H "Authorization: Bearer $ASTERISM_GATE_SECRET" | jq -r .token | sha256sum | awk "{print \\$1}"' \
  2>&1)" || record_failure "secret egress did not survive daemon restart: $restart_egress"
assert_contains "secret egress survived daemon restart" "$restart_egress" "$SECRET_DIGEST"
qemu_absent

STAGE="down-rm"
capture_container_console
down_report="$("$AST" down "$INSTANCE" 2>&1)" || record_failure "final down failed: $down_report"
INSTANCE_RUNNING=
assert_contains "final down" "$down_report" "$INSTANCE  stopped"
rm_report="$("$AST" rm "$INSTANCE" 2>&1)" || record_failure "rm failed: $rm_report"
INSTANCE_CREATED=
assert_contains "rm" "$rm_report" "$INSTANCE  removed"
[ ! -e "$ASTERISM_HOME/instances/$INSTANCE" ] \
  || record_failure "rm left the instance directory"
secret_rm="$("$AST" secret rm "$SECRET_NAME" 2>&1)" \
  || record_failure "secret metadata removal failed: $secret_rm"
SECRET_CREATED=

STAGE="failed-launch-drain"
stop_daemon
SHIMS="$ASTERISM_HOME/failure-shims"
mkdir -p "$SHIMS"
cat >"$SHIMS/slirp4netns" <<'SHIM'
#!/bin/sh
if [ "${1-}" = --version ]; then
  echo "slirp4netns observer-failure-shim"
  exit 0
fi
exit 86
SHIM
chmod 0755 "$SHIMS/slirp4netns"
PATH="$SHIMS:$PATH" start_daemon
create_report="$(PATH="$SHIMS:$PATH" "$AST" create "$FAILED_INSTANCE" \
  --runtime container --image "$IMAGE" --cpus 1 --mem 512M --disk 2G 2>&1)" \
  || fatal "failed-launch fixture create failed before launch: $create_report"
failed_id="$(jq -r --arg name "$FAILED_INSTANCE" \
  '.instances[] | select(.name == $name) | .id' "$STATE")"
self_cgroup="$(sed -n 's/^0:://p' "/proc/$DAEMON_PID/cgroup")"
FAILED_CGROUP="/sys/fs/cgroup/${self_cgroup#/}/asterism-${failed_id//-/}"
if failure_report="$(PATH="$SHIMS:$PATH" "$AST" up "$FAILED_INSTANCE" 2>&1)"; then
  record_failure "deliberately failed slirp launch unexpectedly succeeded"
else
  assert_contains "failed launch reports slirp" "$failure_report" "slirp4netns"
fi
failed_dir="$ASTERISM_HOME/instances/$FAILED_INSTANCE"
for leftover in "$FAILED_CGROUP" "$failed_dir/container-control.sock" \
  "$failed_dir/slirp4netns-api.sock"; do
  [ ! -e "$leftover" ] || record_failure "failed launch left $leftover"
done
# shellcheck disable=SC2009 # Both exact helper marker and owned spec path are required.
if ps -eo args= | grep -F '__container-helper' | grep -F "$failed_dir/container.json" \
  | grep -v grep >/dev/null; then
  record_failure "failed launch left its namespace helper alive"
else
  note "PASS failed launch drained cgroup, sockets, wrapper, and namespace holder"
fi
failed_intent="$(jq -r --arg name "$FAILED_INSTANCE" \
  '.instances[] | select(.name == $name) | .boot_intent_id // empty' "$STATE")"
[ -n "$failed_intent" ] \
  || record_failure "failed launch did not retain its conservative durable fence"
qemu_absent

STAGE="final-cleanup"
stop_daemon
case "$MAIN_HOME" in
  /tmp/asterism-container-gate.*) rm -rf -- "$MAIN_HOME" ;;
  *) fatal "refusing to remove unexpected scratch path $MAIN_HOME" ;;
esac
[ ! -e "$MAIN_HOME" ] || record_failure "owned scratch home survived cleanup"

if [ "$FAILURES" -ne 0 ]; then
  STAGE=verdict
  printf 'result=blocked\nblocker_stage=%s\nfailure_count=%s\n' \
    "$FIRST_FAILURE_STAGE" "$FAILURES" >>"$SUMMARY"
  exit 1
fi

STAGE=verdict
printf '%s\n' \
  "result=pass" \
  "failure_count=0" \
  "create=pass" \
  "up=pass" \
  "exec=pass" \
  "logs=pass" \
  "down=pass" \
  "rm=pass" \
  "daemon_restart=pass" \
  "exec_timeout_drain=pass" \
  "exec_disconnect_drain=pass" \
  "failed_launch_drain=pass" \
  "namespace_isolation=pass" \
  "cgroup_enforcement=pass" \
  "egress_allow_deny=pass" \
  "secret_injection_non_leak=pass" \
  "qemu_system_processes=0" >>"$SUMMARY"
note "CONTAINER LINUX GATE PASS: exact $actual_sha tree $actual_tree observed by $OBSERVER_SHA"
