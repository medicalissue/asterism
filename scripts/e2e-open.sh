#!/usr/bin/env bash
# End-to-end for `ast open NAME:PORT` — a port served inside a guest on ONE
# device, reached on the loopback of ANOTHER.
#
# The scene: an agent built a UI overnight on the machine with the RAM, and in
# the morning somebody opens it from their laptop. Nothing about that is
# provable without two daemons and a guest that is really listening, so this
# lane runs two paired daemons with separate homes and a real OCI nginx behind
# one of them.
#
# What it proves:
#
#   * `ast open` on the device WITHOUT the guest binds a loopback port there
#     and carries HTTP to the guest on the other device — 200, not a socket
#     that accepted and hung
#   * the port was never published: the instance is created with no -p at all
#   * the printed line names the instance, the guest port, the device really
#     supplying the compute, and the mesh path
#   * --json says the same thing in one object
#   * --local-port binds exactly that number
#   * Ctrl-C closes the listener and frees the port
#   * every refusal happens before a listener exists: unknown instance (with
#     the orbit's names), guest-control port 1023, instance not running, and
#     the device being offline (with a last-seen)
#
# Two daemons on one host by default, which is the only shape CI can run. That
# is honest about what it does and does not prove: it exercises the mesh
# stream, the resolution and every refusal, but both loopbacks are the same
# kernel's. The two-real-devices run is evidence, not a test — see
# docs/evidence/ast-open-2026-08-27/.
#
# The backend is selectable and forced, so a device that cannot run it fails
# this lane rather than quietly proving QEMU again:
#
#   E2E_BACKEND=vz  scripts/e2e-open.sh     # macOS default
#   E2E_BACKEND=chv scripts/e2e-open.sh     # Linux default
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export PATH="$HOME/.cargo/bin:$PATH"
cd "$ROOT"

# shellcheck source-path=SCRIPTDIR
. "$ROOT/scripts/lib/harness.sh"
harness_begin open
harness_binaries "$ROOT"

case "${E2E_BACKEND:-}" in
  '')
    case "$(uname -s)" in
      Darwin) BACKEND=vz ;;
      Linux) BACKEND=chv ;;
      *) harness_skip "no native backend with a routable guest address on $(uname -s)" ;;
    esac
    ;;
  vz | chv) BACKEND="$E2E_BACKEND" ;;
  *)
    echo "E2E_BACKEND must be vz or chv (got ${E2E_BACKEND})" >&2
    exit 2
    ;;
esac

if [ "$BACKEND" = vz ]; then
  if [ "$(uname -s)" != Darwin ]; then
    harness_skip "Virtualization.framework is macOS-only"
  fi
  # Builds and signs the helper. Without the entitlement `--backend vz`
  # refuses before anything is created. Skipped when the binaries under test
  # came from somewhere else: astd looks for astd-vz beside itself.
  if [ -z "${AST_BIN:-}" ]; then
    "$ROOT/scripts/sign-vz.sh"
  fi
else
  if [ "$(uname -s)" != Linux ]; then
    harness_skip "Cloud Hypervisor is Linux-only"
  fi
  if [ ! -r /dev/kvm ]; then
    harness_skip "this device has no usable /dev/kvm"
  fi
fi

GUEST_ARTIFACT="${ASTERISM_GUEST_AGENT_ARTIFACT:-$(dirname "$ASTD")/guest/bin/asterism-guest}"
if [ ! -x "$GUEST_ARTIFACT" ]; then
  harness_skip "set ASTERISM_GUEST_AGENT_ARTIFACT to a static $(uname -m) Linux asterism-guest"
fi

# Short homes on purpose: unix socket paths are capped near 104 bytes, and a
# VZ helper's control socket lives under one.
RUN="/private/tmp/ast-open-$$"
if [ ! -d /private/tmp ]; then
  RUN="/tmp/ast-open-$$"
fi
LAPTOP="$RUN/l"
COMPUTE="$RUN/c"
LAPTOP_NAME=laptop
COMPUTE_NAME=dev
IMAGE="${E2E_IMAGE:-docker.io/library/nginx:alpine}"
INST=web
GUEST_PORT=80
OPEN_PID=

export ASTERISM_MESH=local
mkdir -p "$LAPTOP" "$COMPUTE"
harness_own_home "$LAPTOP"
harness_own_home "$COMPUTE"

fail() { echo "OPEN E2E FAIL: $*" >&2; exit 1; }
ok() { echo "ok: $*"; }

on_laptop() { env ASTERISM_HOME="$LAPTOP" "$AST" "$@"; }
on_compute() { env ASTERISM_HOME="$COMPUTE" "$AST" "$@"; }

cleanup() {
  if [ -n "$OPEN_PID" ]; then
    kill -INT "$OPEN_PID" 2>/dev/null || true
  fi
  on_compute down "$INST" >/dev/null 2>&1 || true
  on_compute rm "$INST" >/dev/null 2>&1 || true
  harness_keep_home "$LAPTOP" laptop
  harness_keep_home "$COMPUTE" compute
  harness_reap
  if [ -n "${KEEP:-}" ]; then
    echo "kept $RUN for inspection"
  else
    case "$RUN" in
      /private/tmp/ast-open-* | /tmp/ast-open-*) rm -rf -- "$RUN" ;;
      *) echo "refusing to remove unexpected scratch path: $RUN" >&2 ;;
    esac
  fi
  harness_artifacts_note
}
trap cleanup EXIT

# expect <desc> <needle> <cmd...>: run it, require success AND the needle.
expect() {
  local desc="$1" needle="$2"
  shift 2
  local out
  if ! out="$("$@" 2>&1)"; then
    fail "$desc: command failed:"$'\n'"$out"
  fi
  if ! grep -qF "$needle" <<<"$out"; then
    fail "$desc: expected \"$needle\" in:"$'\n'"$out"
  fi
  ok "$desc"
}

# refute <desc> <needle> <cmd...>: it must FAIL, and say why.
refute() {
  local desc="$1" needle="$2"
  shift 2
  local out
  if out="$("$@" 2>&1)"; then
    fail "$desc: command unexpectedly succeeded:"$'\n'"$out"
  fi
  if ! grep -qF "$needle" <<<"$out"; then
    fail "$desc: expected \"$needle\" in:"$'\n'"$out"
  fi
  ok "$desc"
}

start_daemon() {
  local home="$1"
  (ASTERISM_HOME="$home" ASTERISM_MESH=local "$ASTD" >"$home/astd.log" 2>&1 &)
  for _ in $(seq 1 100); do
    if grep -q "on the mesh as" "$home/astd.log" 2>/dev/null; then
      harness_own "$(cat "$home/astd.pid" 2>/dev/null || true)"
      return 0
    fi
    sleep 0.2
  done
  fail "astd for $home did not come up:"$'\n'"$(cat "$home/astd.log" 2>/dev/null)"
}

stop_daemon() {
  local home="$1" pid
  pid="$(cat "$home/astd.pid" 2>/dev/null || true)"
  if [ -z "$pid" ]; then
    fail "no pid file for the daemon in $home"
  fi
  kill -TERM "$pid" 2>/dev/null || true
  for _ in $(seq 1 100); do
    if ! kill -0 "$pid" 2>/dev/null; then
      return 0
    fi
    sleep 0.2
  done
  kill -KILL "$pid" 2>/dev/null || true
}

# The status line of an HTTP request, or 000. `curl` writes nothing else, so a
# tunnel that accepted and then hung is a failure rather than a pass.
http_status() {
  curl -s -o /dev/null -m 5 -w '%{http_code}' "http://127.0.0.1:$1/" 2>/dev/null || true
}

expect_http_200() {
  local desc="$1" port="$2" code=
  for _ in $(seq 1 30); do
    code="$(http_status "$port")"
    if [ "$code" = 200 ]; then
      ok "$desc (HTTP $code on 127.0.0.1:$port)"
      return 0
    fi
    sleep 2
  done
  fail "$desc: 127.0.0.1:$port answered \"$code\", not 200"
}

expect_port_free() {
  local desc="$1" port="$2"
  for _ in $(seq 1 50); do
    if [ "$(http_status "$port")" = 000 ]; then
      ok "$desc"
      return 0
    fi
    sleep 0.2
  done
  fail "$desc: 127.0.0.1:$port is still answering"
}

# ---- 1. two daemons, paired ------------------------------------------------

start_daemon "$LAPTOP"
start_daemon "$COMPUTE"

env ASTERISM_HOME="$LAPTOP" "$AST" device invite --name "$LAPTOP_NAME" --yes \
  >"$LAPTOP/invite.out" 2>&1 &
INVITE_PID=$!
TICKET=""
for _ in $(seq 1 150); do
  TICKET="$(grep -o 'astdev1[a-z0-9]*' "$LAPTOP/invite.out" 2>/dev/null | head -1 || true)"
  if [ -n "$TICKET" ]; then
    break
  fi
  sleep 0.2
done
if [ -z "$TICKET" ]; then
  fail "no ticket printed by ast device invite:"$'\n'"$(cat "$LAPTOP/invite.out")"
fi
if ! env ASTERISM_HOME="$COMPUTE" "$AST" device add "$TICKET" --name "$COMPUTE_NAME" --yes \
  >"$COMPUTE/add.out" 2>&1; then
  fail "ast device add failed:"$'\n'"$(cat "$COMPUTE/add.out")"
fi
if ! wait "$INVITE_PID"; then
  fail "ast device invite failed:"$'\n'"$(cat "$LAPTOP/invite.out")"
fi
ok "the two daemons paired ($LAPTOP_NAME <-> $COMPUTE_NAME)"

# ---- 2. a guest on the compute device, with NOTHING published ---------------
#
# No -p anywhere in this file, on purpose. `ast open` is not a published
# endpoint and must not need one; an instance created with a mapping would
# make this lane pass for the wrong reason.

if ! on_compute pull "$IMAGE" >"$COMPUTE/pull.out" 2>&1; then
  fail "ast pull failed:"$'\n'"$(cat "$COMPUTE/pull.out")"
fi
expect "the guest is created with no published ports" "$INST  defined" \
  on_compute create "$INST" --backend "$BACKEND" --image "$IMAGE" \
    --cpus 2 --mem 1G --disk 4G
expect "the instance really recorded $BACKEND" "machine: $BACKEND" on_compute status "$INST"
expect "the guest is running on $COMPUTE_NAME" "$INST  running" on_compute up "$INST"

# ---- 3. refusals, every one of them before a listener exists ----------------

refute "an unknown name is refused and the orbit's names are listed" \
  "unknown instance \"nope\"" on_laptop open "nope:$GUEST_PORT"
refute "an unknown name lists the instance that does exist" \
  "orbit has: $INST" on_laptop open "nope:$GUEST_PORT"
refute "Asterism's own guest-control port is never opened" \
  "guest-control endpoint" on_laptop open "$INST:1023"
refute "NAME without a port is refused rather than guessed at" \
  "NAME:PORT" on_laptop open "$INST"

# ---- 4. the thing itself ---------------------------------------------------

on_laptop open "$INST:$GUEST_PORT" --json >"$LAPTOP/open.json" 2>&1 &
OPEN_PID=$!
LINE=""
for _ in $(seq 1 150); do
  LINE="$(head -1 "$LAPTOP/open.json" 2>/dev/null || true)"
  if [ -n "$LINE" ]; then
    break
  fi
  sleep 0.2
done
if [ -z "$LINE" ]; then
  fail "ast open --json printed nothing:"$'\n'"$(cat "$LAPTOP/open.json" 2>/dev/null)"
fi
echo "$LINE"

LOCAL_PORT="$(sed -n 's/.*"local":"127\.0\.0\.1:\([0-9]*\)".*/\1/p' <<<"$LINE")"
if [ -z "$LOCAL_PORT" ]; then
  fail "no loopback port in the --json line: $LINE"
fi
for needle in "\"instance\":\"$INST\"" "\"device\":\"$COMPUTE_NAME\"" "\"port\":$GUEST_PORT"; do
  if ! grep -qF "$needle" <<<"$LINE"; then
    fail "expected $needle in the --json line: $LINE"
  fi
done
if ! grep -qE '"path":"(direct|relay|local)"' <<<"$LINE"; then
  fail "the --json line names no mesh path: $LINE"
fi
ok "--json named the instance, the device supplying its compute, and the path"

expect_http_200 "the guest's nginx answers on the laptop's loopback" "$LOCAL_PORT"

# ---- 5. Ctrl-C closes it ---------------------------------------------------

kill -INT "$OPEN_PID" 2>/dev/null || true
wait "$OPEN_PID" 2>/dev/null || true
OPEN_PID=
expect_port_free "Ctrl-C freed 127.0.0.1:$LOCAL_PORT" "$LOCAL_PORT"

# ---- 6. the line a person reads, and --local-port ---------------------------

WANTED="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')"
on_laptop open "$INST:$GUEST_PORT" --no-browser --local-port "$WANTED" \
  >"$LAPTOP/open.txt" 2>&1 &
OPEN_PID=$!
LINE=""
for _ in $(seq 1 150); do
  LINE="$(head -1 "$LAPTOP/open.txt" 2>/dev/null || true)"
  if [ -n "$LINE" ]; then
    break
  fi
  sleep 0.2
done
echo "$LINE"
if ! grep -qF "http://127.0.0.1:$WANTED" <<<"$LINE"; then
  fail "--local-port $WANTED did not bind that port: $LINE"
fi
if ! grep -qF "$INST:$GUEST_PORT on $COMPUTE_NAME" <<<"$LINE"; then
  fail "the line does not name the guest port and the device: $LINE"
fi
ok "--local-port bound exactly the number asked for, and the line reads right"
expect_http_200 "the fixed port serves the guest too" "$WANTED"

kill -INT "$OPEN_PID" 2>/dev/null || true
wait "$OPEN_PID" 2>/dev/null || true
OPEN_PID=
if ! grep -qF "closed $INST:$GUEST_PORT" "$LAPTOP/open.txt"; then
  fail "Ctrl-C printed no closing line:"$'\n'"$(cat "$LAPTOP/open.txt")"
fi
ok "Ctrl-C said what it closed"
expect_port_free "and freed 127.0.0.1:$WANTED" "$WANTED"

# ---- 7. an instance that is down, and a device that is gone ----------------

expect "the guest goes down" "$INST" on_compute down "$INST"
refute "a stopped instance is a refusal about the instance" \
  "is not running" on_laptop open "$INST:$GUEST_PORT"

stop_daemon "$COMPUTE"
refute "an unreachable device is a refusal about the device" \
  "$COMPUTE_NAME is offline" on_laptop open "$INST:$GUEST_PORT"
refute "and it says when that device was last heard from" \
  "last seen" on_laptop open "$INST:$GUEST_PORT"
refute "and it names what became unreachable" \
  "$INST:$GUEST_PORT is unreachable" on_laptop open "$INST:$GUEST_PORT"

echo
echo "OPEN E2E PASS"
