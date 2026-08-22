#!/usr/bin/env bash
# End-to-end for the Virtualization.framework backend, on real boots:
#
#   default selection resolves to vz (no boot)
#   create --backend vz -> up -> ssh -> logs -> daemon restart while running
#   -> down (graceful, delegate-confirmed) -> snapshot -> diverge -> restore
#   -> up -> content proof -> rm
#
# ...and, only when asked for and only when this device can actually run it,
# a boot-time comparison against the same image under qemu.
#
# Same house style as scripts/e2e.sh: bash with -euo pipefail (a mid-script
# `set -e` under zsh demonstrably did not abort on `ast ssh` failures), and
# every step asserts on the CONTENT of what came back rather than on an exit
# code alone.
#
# What is specific to vz, and why each step is here:
#   * the helper must be code-signed, or nothing boots — scripts/sign-vz.sh
#   * `ast up` returns only once the guest has been *found* on the NAT
#     network, so a successful `up` is already proof of an endpoint
#   * `ast logs` proves /dev/hvc0 reached console.log, which no stock cloud
#     image's kernel cmdline does on its own
#   * astd is killed while a guest runs: the guest belongs to astd-vz, not to
#     astd, and must survive its daemon
#
# Selection policy this test holds the product to (backend/mod.rs, capability
# -first since b295fbf): a create with no --backend probes vz first and falls
# through to qemu only when vz cannot probe or lacks a capability the request
# needs. So on a signed macOS 14+ device an ordinary create resolves to vz,
# and QEMU is a fallback that may simply not be installed. This script asserts
# that policy and never requires QEMU to be present.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export PATH="$HOME/.cargo/bin:$PATH"
cd "$ROOT"

if [ "$(uname -s)" != "Darwin" ]; then
  echo "e2e-vz: Virtualization.framework is macOS-only" >&2
  exit 0
fi

# shellcheck source-path=SCRIPTDIR source=lib/harness.sh
. "$ROOT/scripts/lib/harness.sh"
harness_begin vz
harness_binaries "$ROOT"
# Builds and signs the helper. Without the entitlement `ast create --backend
# vz` refuses, which is the first thing this script would trip over.
#
# Skipped when the binaries under test came from somewhere else: `astd` looks
# for `astd-vz` beside itself, so signing this tree's helper would prove
# nothing about theirs — and re-signing a helper somebody shipped is not this
# script's business. scripts/rc.sh will not select this lane at all unless
# there is a helper beside the pair it installed.
if [ -z "${AST_BIN:-}" ]; then
  "$ROOT/scripts/sign-vz.sh"
fi

# Fresh, SHORT home: unix socket paths are capped near 104 bytes, and the vz
# control socket lives under it too.
export ASTERISM_HOME="/private/tmp/ast-vz-$$"

# A single-device test has no orbit, so it has no business publishing a
# throwaway key and this machine's addresses to a public discovery service.
export ASTERISM_MESH=local
IMAGE="${E2E_IMAGE:-debian:13}"
INST=vze2e
DEF=vzdefault        # the create that names no backend at all
REF=vzref            # the qemu instance the timings are compared against
OCI=vzoci             # an OCI rootfs booted by VZLinuxBootLoader
MARKER="marker-$$"
PROOF=/home/ast/PROOF

# The qemu boot-time comparison is opt-in, and gated again on qemu actually
# being runnable here. A Mac with no QEMU installed is the supported
# configuration now, not a broken one, so its absence skips a comparison and
# never fails a run.
QEMU_COMPARE="${E2E_VZ_QEMU_COMPARE:-0}"

# ---- process bookkeeping ---------------------------------------------------
#
# Every process this run is responsible for is tracked by pid, never by a
# pattern. `pkill -f` on a path under this repo would reach a developer's own
# astd started from the same binary against a different ASTERISM_HOME, and
# killing a helper by pattern would kill somebody else's guest — which is the
# exact accident the daemon-restart step below exists to prove cannot happen.
#
# Both pid sources are exact and scoped to this run: astd writes its own pid
# to $ASTERISM_HOME/astd.pid (paths::daemon_pid_path, deliberately never
# relocated), and a running guest's pid is on its own `ast status` line.
GUEST_PIDS=""

track_guest() {
  local pid="$1"
  case " $GUEST_PIDS " in
    *" $pid "*) return 0 ;;
  esac
  GUEST_PIDS="$GUEST_PIDS $pid"
}

# This run's daemon, or nothing. Never another home's.
astd_pid() {
  local pid
  pid="$(cat "$ASTERISM_HOME/astd.pid" 2>/dev/null || true)"
  case "$pid" in
    '' | *[!0-9]*) return 1 ;;
  esac
  kill -0 "$pid" 2>/dev/null || return 1
  printf '%s\n' "$pid"
}

# The helper holding one instance's guest — vz and only vz. A qemu-backed
# instance yields nothing here on purpose: every assertion that wants a
# helper pid must fail loudly rather than quietly accept a qemu process.
vz_helper_pid() {
  "$AST" status "$1" 2>/dev/null |
    sed -n 's/^running: vz pid \([0-9][0-9]*\).*/\1/p'
}

# Whatever process is running one instance's guest, whichever backend it is.
# Used for cleanup bookkeeping, never for an assertion about which backend.
running_pid() {
  "$AST" status "$1" 2>/dev/null |
    sed -n 's/^running: [a-z][a-z]* pid \([0-9][0-9]*\).*/\1/p'
}

# Record whatever is running one instance's guest, so cleanup can reach it by
# pid. Deliberately called in the parent shell rather than from inside
# boot_seconds: that runs in a $( ) subshell, whose GUEST_PIDS would be
# thrown away with it.
track_running() {
  local pid
  pid="$(running_pid "$1" || true)"
  if [ -n "$pid" ]; then
    track_guest "$pid" || true
  fi
}

# <pid> <ticks>: has it gone within ticks * 0.2s?
wait_gone() {
  local pid="$1" budget="$2" _i
  for _i in $(seq 1 "$budget"); do
    kill -0 "$pid" 2>/dev/null || return 0
    sleep 0.2
  done
  return 1
}

# Ask, wait, insist — bounded at each step, and idempotent: a pid that is
# already gone is a success.
stop_pid() {
  local pid="$1" label="$2"
  kill -0 "$pid" 2>/dev/null || return 0
  kill -TERM "$pid" 2>/dev/null || true
  if wait_gone "$pid" 50; then return 0; fi
  kill -KILL "$pid" 2>/dev/null || true
  if wait_gone "$pid" 25; then return 0; fi
  echo "e2e-vz cleanup: $label ($pid) would not exit" >&2
  return 1
}

cleanup() {
  harness_keep_home "$ASTERISM_HOME" home
  # The product's own path first, so a normal run's cleanup is the graceful
  # one and the signals below have nothing left to do.
  local name pid
  for name in "$INST" "$DEF" "$REF" "$OCI"; do
    track_running "$name"
    "$AST" down "$name" >/dev/null 2>&1 || true
    "$AST" rm "$name" >/dev/null 2>&1 || true
  done
  for pid in $GUEST_PIDS; do
    stop_pid "$pid" "guest process" || true
  done
  pid="$(astd_pid || true)"
  if [ -n "$pid" ]; then
    stop_pid "$pid" "astd" || true
  fi
  rm -rf "$ASTERISM_HOME"
  harness_artifacts_note
}
trap cleanup EXIT

mkdir -p "$ASTERISM_HOME/images"
# Reuse already-pulled images instead of re-downloading. The .raw is the one
# that matters: a base already in raw form is what lets `ast pull` below be a
# no-op. Converting a .qcow2 is the one step in this script that still shells
# out to qemu-img (core/image.rs), which is a property of the image store and
# not of the vz backend — hence the message on the pull.
# ...from the harness's own cache, never ~/.asterism: that one belongs to the
# user's daemon and can be written to while this is reading it.
harness_seed_images "$ASTERISM_HOME"

fail() { echo "E2E-VZ FAIL: $*" >&2; exit 1; }

# expect <desc> <needle> <cmd...>: run cmd, require success AND the needle
# in its combined output.
expect() {
  local desc="$1" needle="$2"; shift 2
  local out
  out="$("$@" 2>&1)" || fail "$desc: command failed:"$'\n'"$out"
  grep -qF "$needle" <<<"$out" || fail "$desc: expected \"$needle\" in:"$'\n'"$out"
  echo "ok: $desc"
}

# expect_eventually <desc> <needle> <cmd...>: the same, for things the guest
# writes on its own schedule. The console is the one place a race is real
# rather than sloppy — sshd answers before cloud-init has finished, so `ast
# logs` can legitimately be a second behind the assertion.
expect_eventually() {
  local desc="$1" needle="$2"; shift 2
  local out
  for _ in $(seq 1 20); do
    out="$("$@" 2>&1)" || true
    if grep -qF "$needle" <<<"$out"; then
      echo "ok: $desc"
      return 0
    fi
    sleep 2
  done
  fail "$desc: expected \"$needle\" within 40s in:"$'\n'"$out"
}

# Seconds from `ast up` to the guest answering ssh. On vz `up` already waits
# for the guest's ssh banner; on qemu it returns as soon as the process
# daemonizes, so the ssh is what makes the two numbers mean the same thing.
boot_seconds() {
  local name="$1" started
  started=$(date +%s.%N)
  "$AST" up "$name" >/dev/null 2>&1 || fail "up $name"
  "$AST" ssh "$name" -- true >/dev/null 2>&1 || fail "ssh $name after up"
  python3 -c "print(f'{$(date +%s.%N) - $started:.1f}')"
}

harness_cache_image "$AST" "$IMAGE" || fail "could not cache $IMAGE"
harness_seed_images "$ASTERISM_HOME"
pull_out="$("$AST" pull "$IMAGE" 2>&1)" || fail \
  "pull $IMAGE:"$'\n'"$pull_out"$'\n'"(a base image that is still qcow2 is converted with qemu-img, \
which is the image store's dependency, not the vz backend's — put a raw base in \
$(harness_cache_dir)/images to run this on a device with no QEMU at all)"

# ---- the vz instance -------------------------------------------------------
#
# The explicit create comes first on purpose: on a device vz cannot run at
# all — Intel, macOS < 14, an unsigned helper — this is the line that fails,
# and it fails with the probe's own reason. The default-selection assertion
# below would fail on the same device saying only "it chose qemu", which is
# true and much less useful as a first error.

expect "create --backend vz" "$INST  defined" \
  "$AST" create "$INST" --backend vz --image "$IMAGE" --mem 2G --disk 10G

# The machine an instance was defined against is part of its identity, and
# it is what a live migration would one day have to match on.
expect "status records the backend"  "machine: vz" "$AST" status "$INST"
expect "status records the platform" "generic"     "$AST" status "$INST"

# ---- and the default is the same backend, unasked --------------------------
#
# Not a second boot: `ast create` is a registry operation, and the backend is
# chosen and recorded there (backend::select_for -> Machine). Creating one
# instance and reading it back is the whole proof, and it costs no guest.
#
# What this asserts is the policy, stated honestly: with an ordinary disk
# image and no published ports — a request vz has every capability for — the
# default resolves to vz on this device. It does not assert that qemu was
# refused or absent; it asserts that vz won, which is what the policy says.

expect "create with no --backend" "$DEF  defined" \
  "$AST" create "$DEF" --image "$IMAGE" --mem 2G --disk 10G
expect "an ordinary create resolves to vz" "machine: vz" "$AST" status "$DEF"
expect "rm the default-selection instance" "$DEF  removed" "$AST" rm "$DEF"

# ---- the vz guest, on a real boot ------------------------------------------

VZ_BOOT=$(boot_seconds "$INST")
track_running "$INST"
echo "ok: up (first boot, ${VZ_BOOT}s to ssh)"
expect "status says running under vz" "running: vz" "$AST" status "$INST"
expect "the endpoint is the guest's own address" "192.168." "$AST" status "$INST"

# The guest answers, and is the guest we asked for.
expect "ssh reaches the guest" "$INST" "$AST" ssh "$INST" -- hostname
"$AST" ssh "$INST" -- "echo $MARKER | sudo tee $PROOF >/dev/null && sync" \
  >/dev/null 2>&1 || fail "writing the proof file in the guest"
expect "the guest kept what it wrote" "$MARKER" "$AST" ssh "$INST" -- "cat $PROOF"

# /dev/hvc0 -> console.log. On a first boot this is the cloud-init bootcmd
# line and the getty's login prompt; nothing else in the stack would put
# either there.
expect "logs show the guest console" "asterism: guest console is /dev/hvc0" \
  "$AST" logs "$INST"
expect_eventually "logs show cloud-init finishing" "cloud-init status: done" \
  "$AST" logs "$INST"
# A login prompt means serial-getty@hvc0 is attached to the same console —
# the guest is usable from the transcript, not just visible in it.
expect_eventually "logs show a login prompt" "login:" "$AST" logs "$INST"

# ---- the guest agent, which is how the guest was found ---------------------
#
# The endpoint used to be inferred: a candidate out of /var/db/dhcpd_leases,
# proved by whatever answered on port 22. Now the guest is asked, over an
# authenticated channel on its own virtio socket, and the lease hunt is only
# the fallback. These assertions are about which of the two actually
# happened on this boot — a fallback that silently took over would otherwise
# look exactly like success.

HELPER_LOG="$ASTERISM_HOME/instances/$INST/vz-helper.log"

helper_log_has() {
  local desc="$1" pattern="$2"
  grep -qE "$pattern" "$HELPER_LOG" \
    || fail "$desc: no /$pattern/ in:"$'\n'"$(cat "$HELPER_LOG")"
  echo "ok: $desc"
}

# Waits, because the guest agent and the ssh prober race by design and the
# assertions below are about both of them having finished.
helper_log_eventually() {
  local desc="$1" pattern="$2" _i
  for _i in $(seq 1 30); do
    if grep -qE "$pattern" "$HELPER_LOG"; then
      echo "ok: $desc"
      return 0
    fi
    sleep 1
  done
  fail "$desc: no /$pattern/ within 30s in:"$'\n'"$(cat "$HELPER_LOG")"
}

helper_log_has "the guest agent answered on vsock" \
  "guest agent answered on vsock port 1023 after [0-9.]+s"
helper_log_has "over a negotiated protocol version" "over protocol v[0-9]+"
helper_log_has "and the endpoint came from the guest itself" \
  "is at 192\\.168\\.[0-9.]+ after [0-9.]+s — the guest said so"

# Both paths run on every boot, so both timings are in this log — which
# makes the comparison a measurement rather than a claim. The agent binds
# its port from cloud-init's earliest stage; sshd is reachable only once it
# has host keys and has finished starting.
helper_log_eventually "the ssh banner path also finished, for comparison" \
  "answered at 192\\.168\\.[0-9.]+ after [0-9.]+s — SSH-"
AGENT_AT="$(sed -n 's/.* is at [0-9.]* after \([0-9.]*\)s — the guest said so.*/\1/p' "$HELPER_LOG" | head -1)"
SSH_AT="$(sed -n 's/.* answered at [0-9.]* after \([0-9.]*\)s — SSH-.*/\1/p' "$HELPER_LOG" | head -1)"
if [ -z "$AGENT_AT" ] || [ -z "$SSH_AT" ]; then
  fail "could not read both timings from $HELPER_LOG"
fi
echo "ok: guest found by its agent at ${AGENT_AT}s, by an ssh banner at ${SSH_AT}s"
python3 -c "import sys; sys.exit(0 if $AGENT_AT <= $SSH_AT else 1)" \
  || fail "the guest agent (${AGENT_AT}s) was slower than the ssh banner (${SSH_AT}s), \
which is the thing it replaces"

# ---- authentication, on the real channel -----------------------------------
#
# The handshake exists so that what answers on the port is the guest this
# seed built. Give the guest a key that is not this instance's and the
# helper must refuse it by name — and must go on serving the guest, because
# a control channel it cannot trust is not a reason to take somebody's agent
# down.

"$AST" ssh "$INST" -- \
  "sudo cp /etc/asterism/agent.key /tmp/agent.key.real \
   && printf '%s\n' $(printf 'ab%.0s' $(seq 1 32)) | sudo tee /etc/asterism/agent.key >/dev/null \
   && sudo systemctl restart asterism-guest.service" >/dev/null 2>&1 \
  || fail "could not give the guest a wrong key"
helper_log_eventually "a guest with the wrong key is refused, by name" \
  "did not prove it holds this instance.s key"
expect "and the guest is still reachable while it is refused" "$MARKER" \
  "$AST" ssh "$INST" -- "cat $PROOF"

"$AST" ssh "$INST" -- \
  "sudo cp /tmp/agent.key.real /etc/asterism/agent.key \
   && sudo systemctl restart asterism-guest.service" >/dev/null 2>&1 \
  || fail "could not put the guest's real key back"
# The helper reconnects on its own, on a backoff that has grown while it was
# being refused; a *second* session line is the proof that it did.
sessions=0
for _ in $(seq 1 60); do
  sessions="$(grep -cE "guest agent (re)?answered on vsock port 1023" "$HELPER_LOG" || true)"
  [ "$sessions" -ge 2 ] && break
  sleep 1
done
[ "$sessions" -ge 2 ] \
  || fail "the session did not come back once the key did:"$'\n'"$(cat "$HELPER_LOG")"
echo "ok: and the session comes back on its own once the key does"

# ---- the guest outlives its daemon -----------------------------------------
#
# VZVirtualMachine dies with the process that made it, which is exactly why
# that process is astd-vz and not astd.

VZ_PID="$(vz_helper_pid "$INST" || true)"
[ -n "$VZ_PID" ] || fail "no vz helper pid in: $("$AST" status "$INST")"
track_guest "$VZ_PID"

# By pid, from this run's own pidfile: a pattern would have reached any astd
# built from this checkout, including one serving somebody's real instances.
ASTD_PID="$(astd_pid || true)"
[ -n "$ASTD_PID" ] || fail "no live astd recorded in $ASTERISM_HOME/astd.pid"
kill -TERM "$ASTD_PID" 2>/dev/null || fail "could not signal astd $ASTD_PID"
wait_gone "$ASTD_PID" 50 || fail "astd $ASTD_PID did not die"
kill -0 "$VZ_PID" 2>/dev/null || fail "the vz helper died with its daemon"
echo "ok: helper $VZ_PID survived astd $ASTD_PID"

# The next command starts a fresh astd, which reloads the registry and asks
# the helper — not its own memory — whether the guest is still there.
# Not just "running": running under the *same helper*, which is the only
# thing that could still be holding this guest.
expect "a restarted astd still sees it running" "running: vz pid $VZ_PID" \
  "$AST" status "$INST"
expect "and ssh still works" "$MARKER" "$AST" ssh "$INST" -- "cat $PROOF"

# ---- graceful stop ---------------------------------------------------------

expect "down" "$INST  stopped" "$AST" down "$INST"
# `guest powered off` is the delegate's own word: guestDidStopVirtualMachine:
# fired, which means ACPI shutdown was honoured rather than the VM being torn
# down under the guest's feet.
grep -qF "guest powered off" "$ASTERISM_HOME/instances/$INST/vz-helper.log" \
  || fail "the helper did not report a clean guest shutdown:"$'\n'"$(cat "$ASTERISM_HOME/instances/$INST/vz-helper.log")"
echo "ok: stop was delegate-confirmed (guestDidStopVirtualMachine:)"
kill -0 "$VZ_PID" 2>/dev/null && fail "the helper outlived its guest"
echo "ok: helper exited with its guest"

# ---- snapshot / restore, proved by content ---------------------------------

expect "snapshot" "$INST  snapshot clean" "$AST" snapshot "$INST" clean
expect "list"     "clean"                 "$AST" snapshots "$INST"

expect "up again" "$INST  running" "$AST" up "$INST"
track_running "$INST"
# Every boot, not just the first: the helper's log is written fresh per boot,
# so this is the second boot's own agent session. Readiness that only worked
# once would be indistinguishable from readiness that works, without this.
helper_log_has "the second boot was found by its agent too" \
  "is at 192\\.168\\.[0-9.]+ after [0-9.]+s — the guest said so"
expect "the proof survived the reboot" "$MARKER" "$AST" ssh "$INST" -- "cat $PROOF"
"$AST" ssh "$INST" -- "echo diverged | sudo tee $PROOF >/dev/null && sync" \
  >/dev/null 2>&1 || fail "diverging the guest"
expect "the guest diverged" "diverged" "$AST" ssh "$INST" -- "cat $PROOF"
expect "down 2" "$INST  stopped" "$AST" down "$INST"

expect "restore" "restored to clean" "$AST" restore "$INST" clean
expect "up after restore" "$INST  running" "$AST" up "$INST"
track_running "$INST"
out="$("$AST" ssh "$INST" -- "cat $PROOF" 2>&1)" || fail "reading the proof after restore"
grep -qF "$MARKER" <<<"$out" || fail "restore did not roll the disk back: $out"
grep -qF "diverged" <<<"$out" && fail "the divergence survived the restore: $out"
echo "ok: restore rolled the disk back to the snapshot's contents"

# This stop is the one where astd is still the helper's parent (the earlier
# one followed a daemon restart, which reparents it to init). An unreaped
# child answers `kill -0` for as long as the daemon lives, and `kill -0` is
# how a lost control socket is second-guessed — so a zombie here would read
# as a running guest forever.
VZ_PID2="$(vz_helper_pid "$INST" || true)"
[ -n "$VZ_PID2" ] || fail "no vz helper pid in: $("$AST" status "$INST")"
track_guest "$VZ_PID2"
expect "down 3" "$INST  stopped"  "$AST" down "$INST"
sleep 1
kill -0 "$VZ_PID2" 2>/dev/null && fail "helper $VZ_PID2 still answers kill -0 after down (zombie?)"
echo "ok: the stopped helper left nothing that looks alive"
expect "status agrees it is stopped" "status:  stopped" "$AST" status "$INST"
expect "rm"     "$INST  removed"  "$AST" rm "$INST"

# ---- an OCI rootfs through VZ's native Linux boot loader ------------------

# No ssh and no cloud-init are smuggled into this image. Its generated pid 1
# runs DHCP, the helper resolves that exact lease from the pinned MAC/name,
# and stdout reaches the same hvc0 console as a cloud-image guest.
expect "create an OCI instance on vz" "$OCI  defined" \
  "$AST" create "$OCI" --backend vz --image nginx --mem 1G --disk 10G
expect "the OCI instance really selected vz" "machine: vz" "$AST" status "$OCI"
expect "its source remains an OCI rootfs" "oci rootfs, direct kernel boot" \
  "$AST" status "$OCI"
expect "up the OCI instance on vz" "$OCI  running" "$AST" up "$OCI"
track_running "$OCI"
expect_eventually "the OCI entrypoint reached hvc0" "asterism: starting the image entrypoint" \
  "$AST" logs "$OCI" -n 400
expect_eventually "nginx started inside the VZ microVM" "start worker process" \
  "$AST" logs "$OCI" -n 400
expect "down the OCI instance" "$OCI  stopped" "$AST" down "$OCI"
expect "snapshot the stopped OCI disk" "$OCI  snapshot clean" \
  "$AST" snapshot "$OCI" clean
expect "boot the snapshotted OCI disk again" "$OCI  running" "$AST" up "$OCI"
track_running "$OCI"
expect_eventually "the restored OCI disk runs nginx again" "start worker process" \
  "$AST" logs "$OCI" -n 400
expect "down the OCI instance again" "$OCI  stopped" "$AST" down "$OCI"
expect "remove the OCI instance" "$OCI  removed" "$AST" rm "$OCI"

# ---- the same image under qemu, for the timing -----------------------------
#
# Opt-in, and then capability-gated by the product's own probe: an explicit
# `--backend qemu` either produces a qemu instance or refuses with the reason
# (no qemu-system on this device, no firmware, an accelerator it cannot get).
# The refusal happens before the registry is touched, so a skip leaves
# nothing behind. The timing is only printed for an instance that has been
# *proved* to be on the other backend — a vz instance is never labelled qemu
# to fill in a number.

QEMU_BOOT=""
if [ "$QEMU_COMPARE" != "1" ]; then
  echo "skipped: qemu boot-time comparison — set E2E_VZ_QEMU_COMPARE=1 to run it"
elif ! qemu_create="$("$AST" create "$REF" --backend qemu --image "$IMAGE" --mem 2G --disk 10G 2>&1)"; then
  echo "skipped: qemu boot-time comparison — this device cannot run the qemu backend:"
  # shellcheck disable=SC2001  # a prefix on every line, which parameter
  # expansion cannot do
  sed 's/^/  /' <<<"$qemu_create"
else
  grep -qF "$REF  defined" <<<"$qemu_create" \
    || fail "create --backend qemu said something unexpected:"$'\n'"$qemu_create"
  echo "ok: create --backend qemu"
  # Before any timing: this really is the other backend. Without this line a
  # selection change could quietly time vz twice and call one of them qemu.
  expect "the reference instance really is qemu" "machine: qemu" "$AST" status "$REF"
  QEMU_BOOT=$(boot_seconds "$REF")
  track_running "$REF"
  expect "running under qemu" "running: qemu" "$AST" status "$REF"
  expect "down (qemu)" "$REF  stopped" "$AST" down "$REF"
  expect "rm (qemu)"   "$REF  removed" "$AST" rm "$REF"
fi

echo
echo "boot to ssh, $IMAGE, 2 cpus / 2048 MiB, first boot (cloud-init runs):"
echo "  vz    ${VZ_BOOT}s"
if [ -n "$QEMU_BOOT" ]; then
  echo "  qemu  ${QEMU_BOOT}s"
else
  echo "  qemu  not measured"
fi
echo
echo "E2E-VZ GREEN ($IMAGE)"
