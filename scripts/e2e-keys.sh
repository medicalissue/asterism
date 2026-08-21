#!/usr/bin/env bash
# End-to-end for guest key durability, with real boots and real power cuts.
#
# A guest's ssh host keys are written by cloud-init on its first boot, and
# for the first seconds of that guest's life they are in its page cache and
# nowhere else. `kill -9` on the hypervisor is a yanked power cord: land one
# in that window and the guest comes back with no host keys, sshd refuses to
# start, and an instance that is meant to be an agent's home is unreachable
# for good — with no way in to fix it.
#
# Two claims, and they are the belt and the braces:
#
#   1. A power cut seconds after the first ssh answers, with nothing typed
#      inside the guest, leaves an instance that boots and answers again.
#      (The seed's runcmd ends in `sync`, so cloud-init's keys are on the
#      disk by the end of cloud-final.)
#   2. A guest that has lost its host keys anyway makes itself a new set at
#      the next boot and starts sshd with them, rather than staying down.
#      That is the case a `sync` cannot cover: a bad shutdown later on, a
#      corrupted /etc/ssh, a disk rolled back to a snapshot taken mid-write.
#
#   3. And it does that with cloud-init disabled, which is the unit doing it
#      alone. Two mechanisms cover claim 2 — an early `bootcmd`, for the one
#      boot a freshly installed unit cannot join, and the unit itself for
#      every boot after — and `bootcmd` runs first, so the unit's half is
#      only visible with cloud-init out of the way.
#
# Claims 2 and 3 are the ones that cannot be tested by hoping: the keys are
# removed on purpose, and the assertion is that the guest answers on a NEW
# key.
#
# Asserts on CONTENT, like scripts/e2e.sh, and for the same reason. The
# binaries are copied into the scratch home before use and astd is started
# by this script rather than by the CLI — both for the reasons e2e-persist.sh
# gives.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export PATH="$HOME/.cargo/bin:$PATH"
cd "$ROOT"
# shellcheck source-path=SCRIPTDIR source=lib/harness.sh
. "$ROOT/scripts/lib/harness.sh"
harness_begin keys
harness_binaries "$ROOT"

# Fresh, SHORT home: unix socket paths are capped near 104 bytes.
export ASTERISM_HOME="/private/tmp/ast-keys-$$"
# A single-device test has no orbit, so it has no business publishing a
# throwaway key and this machine's addresses to a public discovery service.
export ASTERISM_MESH=local
harness_own_home "$ASTERISM_HOME"
BIN="$ASTERISM_HOME/bin"
LOG="$ASTERISM_HOME/astd.log"
IMAGE="${E2E_IMAGE:-debian:13}"
INST=keys
ASTD_PID=

fail() { echo "KEYS E2E FAIL: $*" >&2; exit 1; }
ok() { echo "ok: $*"; }

cleanup() {
  harness_keep_home "$ASTERISM_HOME" home
  if [ -n "$ASTD_PID" ]; then kill -9 "$ASTD_PID" 2>/dev/null || true; fi
  # Only what this run started. `pkill -9 -f "$ASTERISM_HOME"` used to stand
  # here: it matched command lines, so it also reached anything that merely
  # named this directory — and it reached it with SIGKILL. The daemon writes
  # down every process it starts; harness_reap stops those.
  harness_reap
  harness_artifacts_note
  if [ -n "${KEEP:-}" ]; then
    echo "kept $ASTERISM_HOME for inspection"
  else
    rm -rf "$ASTERISM_HOME"
  fi
  return 0
}
trap cleanup EXIT

mkdir -p "$ASTERISM_HOME/images" "$BIN"
# Copied into the home rather than run out of target/, so that a rebuild
# part-way through a long run cannot swap the binary under a live daemon.
cp "$AST" "$ASTD" "$BIN/"
AST="$BIN/ast"
ASTD="$BIN/astd"
harness_seed_images "$ASTERISM_HOME"

# expect <desc> <needle> <cmd...>: run cmd, require success AND the needle.
expect() {
  local desc="$1" needle="$2"; shift 2
  local out
  out="$("$@" 2>&1)" || fail "$desc: command failed:"$'\n'"$out"
  grep -qF "$needle" <<<"$out" || fail "$desc: expected \"$needle\" in:"$'\n'"$out"
  ok "$desc"
}

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

guest_pid() {
  "$AST" status "$INST" 2>/dev/null | sed -n 's/^running: .* pid \([0-9]*\),.*/\1/p'
}

dead() { if kill -0 "$1" 2>/dev/null; then return 1; fi; return 0; }

in_guest() { "$AST" ssh "$INST" -- "$1" 2>&1; }

# The guest's own ed25519 host key, as the guest reports it. This is the
# identity a power cut destroys and the unit rebuilds, so it is the thing to
# compare across boots.
host_key() {
  in_guest 'sudo cat /etc/ssh/ssh_host_ed25519_key.pub 2>/dev/null | cut -d" " -f2'
}

# ssh_answers <seconds>: `ast ssh` returns what we asked it to, within budget.
ssh_answers() {
  local secs="$1" out
  for _ in $(seq 1 "$secs"); do
    out="$("$AST" ssh "$INST" -- "echo alive" 2>&1 || true)"
    case "$out" in *alive*) return 0 ;; esac
    sleep 1
  done
  echo "last ssh attempt said:"$'\n'"$out" >&2
  return 1
}

# The image comes from the harness cache, filled once by the binary under
# test if it is not there yet, so only a first run downloads anything. Done
# before the daemon starts, so nothing lands in a store a running daemon may
# be reading; the pull further down registers what was copied.
harness_cache_image "$AST" "$IMAGE" || fail "could not cache $IMAGE"
harness_seed_images "$ASTERISM_HOME"
echo "== guest key durability e2e in $ASTERISM_HOME"
start_astd
"$AST" pull "$IMAGE" >/dev/null 2>&1 || fail "pull $IMAGE"

# `--restart never` so the supervisor stays out of the way: every boot in
# this test is one this script asked for, at a moment it chose. (It is also
# the flag under test in the policy half of tonight's work, so the policy
# had better be readable back.)
expect "create" "$INST  defined" \
  "$AST" create "$INST" --image "$IMAGE" --mem 2G --disk 10G
expect "up, with the supervisor told to keep its hands off" "$INST  running" \
  "$AST" up "$INST" --restart never
expect "and the policy is on the instance, not in a file beside it" \
  "restart: never" "$AST" status "$INST"
[ ! -e "$ASTERISM_HOME/instances/$INST/policy.json" ] \
  || fail "policy.json is back — the registry is supposed to be the one place it lives"
ok "no policy.json sidecar: the registry holds it"

# ---- the seed carries the insurance ----------------------------------------

expect "the guest answers at all" "hello-keys" "$AST" ssh "$INST" -- "echo hello-keys"
FIRST_KEY="$(host_key)"
[ -n "$FIRST_KEY" ] || fail "the guest has no ed25519 host key on its first boot"
ok "first boot host key: ${FIRST_KEY:0:24}..."

expect "the seed installed the regeneration script" "asterism: no ssh host keys" \
  "$AST" ssh "$INST" -- "cat /usr/local/sbin/asterism-hostkeys"
expect "and enabled the unit that runs it" "enabled" \
  "$AST" ssh "$INST" -- "systemctl is-enabled asterism-hostkeys.service"
# The unit cannot run on the boot that installs it — systemd worked out
# what this boot consists of before cloud-init started — so the first boot
# is covered by `bootcmd` instead, which runs from cloud-init's earliest
# stage on every boot after this one.
expect "and the same check rides bootcmd, for the boot the unit cannot cover" \
  "[ -d /var/lib/cloud/instance ] || exit 0" \
  "$AST" ssh "$INST" -- "sudo cat /var/lib/cloud/instance/user-data.txt"
ok "the guest carries the host key unit, enabled, and the early check besides"

# ---- 1. a power cut in the first seconds, with nothing typed inside --------
#
# Deliberately NO `sync` in the guest. That is the whole point: the last
# thing this test does before pulling the plug is read a file, and the seed
# is what has to have made cloud-init's keys durable.

echo "== kill -9 the guest 15s after its first ssh, with no guest sync"
sleep 15
PID1="$(guest_pid)"
[ -n "$PID1" ] || fail "no guest pid recorded after up"
kill -9 "$PID1"
sleep 1
dead "$PID1" || fail "qemu $PID1 survived kill -9"
ok "pulled the power on pid $PID1"

# The supervisor was told never, so nothing came back on its own.
sleep 8
[ -z "$(guest_pid)" ] || fail "something restarted the guest — --restart never was ignored"
expect "and the registry says so" "status:  stopped" "$AST" status "$INST"
ok "restart=never held: the guest stayed down"

expect "boot it again" "$INST  running" "$AST" up "$INST"
ssh_answers 120 || fail "the guest never answered ssh after the power cut — \
its host keys did not survive, which is the whole bug"
ok "the guest answers ssh after a power cut seconds into its life"

AFTER_CUT="$(host_key)"
[ -n "$AFTER_CUT" ] || fail "no host key after the power cut"
if [ "$AFTER_CUT" = "$FIRST_KEY" ]; then
  ok "the keys survived the cut outright — the sync at the end of cloud-final did it"
else
  ok "the keys were rebuilt by the unit — the guest is reachable either way"
fi
SSHD="$(in_guest 'systemctl is-active ssh.service sshd.service 2>/dev/null | tr "\n" " "')"
grep -qF "active" <<<"$SSHD" || fail "sshd is not active after the power cut: $SSHD"
ok "sshd is active: $SSHD"

# From the second boot on, the unit is in the boot and has run — this is
# where the braces start doing their work.
expect "the unit ran on this boot" "SubState=exited" \
  "$AST" ssh "$INST" -- "systemctl show -p SubState asterism-hostkeys.service"
ok "asterism-hostkeys.service is part of every boot from here on"

# ---- 2. the regeneration path, on purpose ----------------------------------
#
# A `sync` cannot cover every way a guest loses its host keys — a bad
# shutdown a month from now, a half-written /etc, a disk rolled back to a
# snapshot taken mid-write. So the keys are removed deliberately here, made
# durable, and the claim is that the next boot puts a set back and starts
# sshd with them.

echo "== remove the guest's host keys and boot it again"
WIPED="$(in_guest 'sudo rm -f /etc/ssh/ssh_host_*_key /etc/ssh/ssh_host_*_key.pub && \
                   sync && ls /etc/ssh/ | grep -c ssh_host || true')"
grep -qE '^0$' <<<"$(tr -d ' \n' <<<"$WIPED")" \
  || fail "the host keys are still there after rm:"$'\n'"$WIPED"
ok "the guest has no host keys left, and the removal is on its disk"

expect "stop it" "$INST  stopped" "$AST" down "$INST"
expect "boot it" "$INST  running" "$AST" up "$INST"
ssh_answers 120 || fail "a guest that lost its host keys never came back — \
asterism-hostkeys.service did not do its job"
ok "the guest answers ssh with no host keys to start from"

REBUILT="$(host_key)"
[ -n "$REBUILT" ] || fail "the guest answered but has no ed25519 host key, which cannot be"
[ "$REBUILT" != "$AFTER_CUT" ] || fail "the host key did not change, so nothing was regenerated"
ok "a new host key: ${REBUILT:0:24}..."

# It said so, in the guest's own journal, where somebody debugging this at
# 3am would look. Whichever of the two got there first — `bootcmd` runs
# earlier than the unit, so on an ordinary boot it is the one that fires.
JOURNAL="$(in_guest 'sudo journalctl --no-pager -b 2>&1 | grep -F asterism | tail -20')"
grep -qF "no ssh host keys on this guest" <<<"$JOURNAL" \
  || fail "nothing in the boot said what it was doing:"$'\n'"$JOURNAL"
ok "the journal: $(grep -m1 'no ssh host keys' <<<"$JOURNAL")"

COUNT="$(in_guest 'ls /etc/ssh/ssh_host_*_key | wc -l')"
[ "$(tr -d ' \n' <<<"$COUNT")" -ge 1 ] || fail "no host keys were written: $COUNT"
ok "the guest has $(tr -d ' \n' <<<"$COUNT") host key(s) again"

expect "and it is still a working machine" "still-here" \
  "$AST" ssh "$INST" -- "echo still-here"

# ---- 3. the unit on its own, with cloud-init out of the way ----------------
#
# The `bootcmd` half rides cloud-init, and cloud-init running on every boot
# is a thing that is true today rather than a law. So: turn cloud-init off,
# take the host keys away again, and the unit has to carry it alone. This is
# the braces, tested as braces — with nothing else in the guest able to take
# the credit.

echo "== take the host keys again, with cloud-init disabled"
DISABLED="$(in_guest 'sudo touch /etc/cloud/cloud-init.disabled && \
                      sudo rm -f /etc/ssh/ssh_host_*_key /etc/ssh/ssh_host_*_key.pub && \
                      sync && echo DISABLED')"
grep -qF "DISABLED" <<<"$DISABLED" || fail "could not disable cloud-init:"$'\n'"$DISABLED"
ok "cloud-init is off in the guest, and its host keys are gone again"

expect "stop it" "$INST  stopped" "$AST" down "$INST"
expect "boot it" "$INST  running" "$AST" up "$INST"
ssh_answers 120 || fail "with cloud-init disabled the unit did not regenerate the \
host keys — the guest is unreachable, which is the bug this exists to prevent"
ok "the guest answers ssh on keys the unit alone made"

ALONE="$(host_key)"
[ -n "$ALONE" ] || fail "no host key after the unit was left to do it alone"
[ "$ALONE" != "$REBUILT" ] || fail "the host key did not change, so nothing was regenerated"
ok "a third host key: ${ALONE:0:24}..."

UNIT_LOG="$(in_guest 'sudo journalctl -u asterism-hostkeys.service --no-pager -b 2>&1 | tail -20')"
grep -qF "no ssh host keys on this guest" <<<"$UNIT_LOG" \
  || fail "the unit did not report doing the work:"$'\n'"$UNIT_LOG"
ok "the unit's own journal: $(grep -m1 'no ssh host keys' <<<"$UNIT_LOG")"
expect "cloud-init really was out of the picture" "disabled" \
  "$AST" ssh "$INST" -- "cloud-init status 2>&1 | head -1"

in_guest 'sudo rm -f /etc/cloud/cloud-init.disabled && sync' >/dev/null 2>&1 || true

expect "down" "$INST  stopped" "$AST" down "$INST"
expect "rm" "$INST  removed" "$AST" rm "$INST"

echo "E2E KEYS GREEN ($IMAGE)"
