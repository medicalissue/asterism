#!/usr/bin/env bash
# End-to-end for the one orbit-wide namespace: two real daemons pair, a name
# means exactly one thing in both directions, every instance command reaches
# its instance by bare name from either device, `ast ssh <device>` opens the
# target's own host shell once its owner has enabled one, and `--device` is
# gone with the bare-name form named in its place.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
# shellcheck source-path=SCRIPTDIR source=lib/harness.sh
. "$ROOT/scripts/lib/harness.sh"
harness_begin orbit-names
harness_binaries "$ROOT"

export ASTERISM_MESH=local
RUN="/tmp/ast-orbit-names-$$"
A="$RUN/a"
B="$RUN/b"
A_NAME="names-a-$$"
B_NAME="names-b-$$"
INST="web-$$"

fail() {
  echo "ORBIT NAMES E2E FAIL: $*" >&2
  exit 1
}

cleanup() {
  harness_keep_home "$A" a
  harness_keep_home "$B" b
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

on_a() { env ASTERISM_HOME="$A" "$AST" "$@"; }
on_b() { env ASTERISM_HOME="$B" "$AST" "$@"; }

expect() {
  local description="$1" needle="$2"
  shift 2
  local output
  output="$("$@" 2>&1)" || fail "$description failed: $output"
  grep -qF -- "$needle" <<<"$output" || fail "$description did not say $needle: $output"
  echo "ok: $description"
}

refute() {
  local description="$1" needle="$2"
  shift 2
  local output
  if output="$("$@" 2>&1)"; then
    fail "$description unexpectedly succeeded: $output"
  fi
  grep -qF -- "$needle" <<<"$output" || fail "$description did not say $needle: $output"
  echo "ok: $description"
}

mkdir -p "$A" "$B"
start_daemon "$A"
start_daemon "$B"

# ---- 1. one orbit ----------------------------------------------------------

on_a device invite --name "$A_NAME" --yes >"$A/invite.out" 2>&1 &
INVITE_PID=$!
harness_own "$INVITE_PID"
TICKET=""
for _ in $(seq 1 100); do
  TICKET="$(grep -o 'astdev1[a-z0-9]*' "$A/invite.out" 2>/dev/null | head -1 || true)"
  [ -n "$TICKET" ] && break
  sleep 0.1
done
[ -n "$TICKET" ] || fail "the invite printed no ticket"
on_b device add "$TICKET" --name "$B_NAME" --yes >"$B/add.out" 2>&1
wait "$INVITE_PID" || fail "ast device invite failed:"$'\n'"$(cat "$A/invite.out")"
echo "ok: paired two real daemons ($A_NAME <-> $B_NAME)"

# ---- 2. an instance on B, named and reached from A -------------------------

DISK="$B/tiny.qcow2"
if command -v qemu-img >/dev/null 2>&1; then
  qemu-img create -f qcow2 "$DISK" 1M >/dev/null 2>&1 \
    || fail "qemu-img create failed"
else
  # The registry records the image it is given; nothing here boots a guest, so
  # a path that exists is enough to define an instance.
  printf 'not a disk' >"$DISK"
fi
expect "an instance is defined on $B_NAME" "$INST  defined" \
  on_b create "$INST" --image "$DISK" --mem 512M --disk 1G

# The orbit table names the device each instance runs on, from either side.
LS_A="$(on_a ls 2>&1)"
grep -qE "^NAME +STATUS +IMAGE +SHAPE +DEVICE " <<<"$LS_A" \
  || fail "ast ls has no DEVICE column:"$'\n'"$LS_A"
grep -qE "^$INST +\S+ +\S+ +\S+ +$B_NAME" <<<"$LS_A" \
  || fail "ast ls on A does not put $INST on $B_NAME:"$'\n'"$LS_A"
echo "ok: ast ls on $A_NAME lists $INST with DEVICE $B_NAME"

# Typed on A, about an instance A does not hold, with no device named.
expect "status resolves across the orbit by bare name" "name:    $INST" \
  on_a status "$INST"
# The answer is B's own — A's shard does not hold this instance at all, so a
# refusal that talks about *its console* is a refusal that crossed the mesh.
refute "logs resolve across the orbit by bare name" "no console log for" \
  on_a logs "$INST"

# ---- 3. one namespace, refused in both directions --------------------------

CREATE_OUT="$(on_a create "$B_NAME" --image "$DISK" 2>&1 || true)"
grep -qF "is already a device in this orbit" <<<"$CREATE_OUT" \
  || fail "creating an instance named after a device was not refused:"$'\n'"$CREATE_OUT"
grep -qF "Instance and device names share one namespace" <<<"$CREATE_OUT" \
  || fail "the refusal does not name the rule:"$'\n'"$CREATE_OUT"
grep -qF -- "ast create $B_NAME-bot" <<<"$CREATE_OUT" \
  || fail "the refusal offers no fix:"$'\n'"$CREATE_OUT"
# Refused *before* mutation: no such row exists anywhere.
grep -qE "^$B_NAME " <<<"$(on_a ls 2>&1)" \
  && fail "the refused instance was created anyway"
echo "ok: an instance may not take a device's name, and nothing was written"

# The other direction: a third device that wants to join under an instance's
# name is refused before it becomes a member.
C="$RUN/c"
start_daemon "$C"
on_a device invite --name "$A_NAME" --yes >"$A/invite2.out" 2>&1 &
INVITE_PID=$!
harness_own "$INVITE_PID"
TICKET=""
for _ in $(seq 1 100); do
  TICKET="$(grep -o 'astdev1[a-z0-9]*' "$A/invite2.out" 2>/dev/null | head -1 || true)"
  [ -n "$TICKET" ] && break
  sleep 0.1
done
[ -n "$TICKET" ] || fail "the second invite printed no ticket"
JOIN_OUT="$(env ASTERISM_HOME="$C" "$AST" device add "$TICKET" --name "$INST" --yes 2>&1 || true)"
wait "$INVITE_PID" || true
grep -qF "is already an instance in this orbit" <<<"$JOIN_OUT" \
  || fail "pairing under an instance's name was not refused:"$'\n'"$JOIN_OUT"
grep -qF -- "--name $INST-host" <<<"$JOIN_OUT" \
  || fail "the pairing refusal offers no remedy:"$'\n'"$JOIN_OUT"
DEVICES="$(on_a devices 2>&1)"
grep -qE "^$INST " <<<"$DEVICES" \
  && fail "the refused device joined the orbit anyway:"$'\n'"$DEVICES"
echo "ok: a device may not take an instance's name, and nothing was written"
stop_daemon "$C"

# ---- 4. a name that is neither ---------------------------------------------

UNKNOWN="$(on_a ssh nope 2>&1 || true)"
grep -qF 'unknown name "nope"' <<<"$UNKNOWN" \
  || fail "an unknown name was not named as such:"$'\n'"$UNKNOWN"
grep -qF "devices: " <<<"$UNKNOWN" || fail "the refusal lists no devices:"$'\n'"$UNKNOWN"
grep -qF "instances: " <<<"$UNKNOWN" || fail "the refusal lists no instances:"$'\n'"$UNKNOWN"
grep -qF "$B_NAME" <<<"$UNKNOWN" || fail "the refusal omits a device name:"$'\n'"$UNKNOWN"
grep -qF "$INST" <<<"$UNKNOWN" || fail "the refusal omits an instance name:"$'\n'"$UNKNOWN"
echo "ok: an unknown name is refused with both halves of the namespace listed"

# ---- 5. ast ssh <device> is the host shell, and it is gated ----------------

refute "a device that has not enabled its shell refuses" "disabled" \
  on_a ssh "$B_NAME" -- "printf forbidden"
refute "the retired --device names the form that replaced it" "--device is gone" \
  on_a --device "$B_NAME" ls
refute "the retired --host names the bare-name form" "--host is gone" \
  on_a ssh "$B_NAME" --host "$B_NAME"

on_b device shell enable >"$B/enable.out" 2>&1 \
  || fail "ast device shell enable failed:"$'\n'"$(cat "$B/enable.out")"
SHELL_OUT="$(on_a ssh "$B_NAME" -- "printf host-shell-ok" 2>&1)"
[ "$SHELL_OUT" = "host-shell-ok" ] \
  || fail "ast ssh $B_NAME did not run on the target: $SHELL_OUT"
echo "ok: ast ssh $B_NAME opened the target's host shell once its owner enabled it"

on_b device shell disable >/dev/null 2>&1
refute "disabling closes the host shell again" "disabled" \
  on_a ssh "$B_NAME" -- "printf forbidden"

# ---- 6. a device that is not answering is not a typo -----------------------

stop_daemon "$B"
OFFLINE="$(on_a ssh "$INST" 2>&1 || true)"
grep -qF "$B_NAME is offline" <<<"$OFFLINE" \
  || fail "an instance on a stopped device was not reported as offline:"$'\n'"$OFFLINE"
grep -qF "$INST is unreachable" <<<"$OFFLINE" \
  || fail "the offline refusal does not name what became unreachable:"$'\n'"$OFFLINE"
echo "ok: an instance on a stopped device is unreachable, not unknown"

# The row survives: the instance is real, only its state is stale.
LS_STALE="$(on_a ls 2>&1)"
grep -qE "^$INST +unknown .* $B_NAME" <<<"$LS_STALE" \
  || fail "the stale row lost its device:"$'\n'"$LS_STALE"
echo "ok: ast ls keeps the row and its device, with the state marked unknown"

echo "ORBIT NAMES E2E GREEN"
