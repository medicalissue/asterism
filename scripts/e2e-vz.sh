#!/usr/bin/env bash
# End-to-end for the Virtualization.framework backend, on real boots:
#
#   create --backend vz -> up -> ssh -> logs -> daemon restart while running
#   -> down (graceful, delegate-confirmed) -> snapshot -> diverge -> restore
#   -> up -> content proof -> rm
#
# ...and a boot-time comparison against the same image under qemu at the end.
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
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export PATH="$HOME/.cargo/bin:$PATH"
cd "$ROOT"

if [ "$(uname -s)" != "Darwin" ]; then
  echo "e2e-vz: Virtualization.framework is macOS-only" >&2
  exit 0
fi

cargo build -q
# Builds and signs the helper. Without the entitlement `ast create --backend
# vz` refuses, which is the first thing this script would trip over.
"$ROOT/scripts/sign-vz.sh"
AST="$ROOT/target/debug/ast"
ASTD="$ROOT/target/debug/astd"

# Fresh, SHORT home: unix socket paths are capped near 104 bytes, and the vz
# control socket lives under it too.
export ASTERISM_HOME="/private/tmp/ast-vz-$$"

# A single-device test has no orbit, so it has no business publishing a
# throwaway key and this machine's addresses to a public discovery service.
export ASTERISM_MESH=local
IMAGE="${E2E_IMAGE:-debian:13}"
INST=vze2e
REF=vzref            # the qemu instance the timings are compared against
MARKER="marker-$$"
PROOF=/home/ast/PROOF

cleanup() {
  "$AST" down "$INST" >/dev/null 2>&1 || true
  "$AST" down "$REF" >/dev/null 2>&1 || true
  "$AST" rm "$INST" >/dev/null 2>&1 || true
  "$AST" rm "$REF" >/dev/null 2>&1 || true
  # -x: match the whole command line, so this never catches `astd-vz`, whose
  # path starts with the same characters. Killing a helper here would kill a
  # guest, which is precisely what the daemon-restart step proves cannot
  # happen by accident.
  pkill -x -f "$ASTD" 2>/dev/null || true
  pkill -f "astd-vz --config $ASTERISM_HOME" 2>/dev/null || true
  rm -rf "$ASTERISM_HOME"
}
trap cleanup EXIT

mkdir -p "$ASTERISM_HOME/images"
# Reuse already-pulled images instead of re-downloading.
if [ -d "$HOME/.asterism/images" ]; then
  cp "$HOME/.asterism/images/"*.qcow2 "$ASTERISM_HOME/images/" 2>/dev/null || true
  cp "$HOME/.asterism/images/"*.raw "$ASTERISM_HOME/images/" 2>/dev/null || true
fi

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

"$AST" pull "$IMAGE" >/dev/null 2>&1 || fail "pull $IMAGE"

# ---- the vz instance -------------------------------------------------------

expect "create --backend vz" "$INST  defined" \
  "$AST" create "$INST" --backend vz --image "$IMAGE" --mem 2G --disk 10G

# The machine an instance was defined against is part of its identity, and
# it is what a live migration would one day have to match on.
expect "status records the backend"  "machine: vz" "$AST" status "$INST"
expect "status records the platform" "generic"     "$AST" status "$INST"

VZ_BOOT=$(boot_seconds "$INST")
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

# ---- the guest outlives its daemon -----------------------------------------
#
# VZVirtualMachine dies with the process that made it, which is exactly why
# that process is astd-vz and not astd.

VZ_PID="$("$AST" status "$INST" | sed -n 's/^running: vz pid \([0-9]*\).*/\1/p')"
[ -n "$VZ_PID" ] || fail "no helper pid in: $("$AST" status "$INST")"
pkill -x -f "$ASTD" || fail "no astd to kill"
for _ in $(seq 1 50); do pgrep -x -f "$ASTD" >/dev/null || break; sleep 0.2; done
pgrep -x -f "$ASTD" >/dev/null && fail "astd did not die"
kill -0 "$VZ_PID" 2>/dev/null || fail "the vz helper died with its daemon"
echo "ok: helper $VZ_PID survived astd"

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
expect "the proof survived the reboot" "$MARKER" "$AST" ssh "$INST" -- "cat $PROOF"
"$AST" ssh "$INST" -- "echo diverged | sudo tee $PROOF >/dev/null && sync" \
  >/dev/null 2>&1 || fail "diverging the guest"
expect "the guest diverged" "diverged" "$AST" ssh "$INST" -- "cat $PROOF"
expect "down 2" "$INST  stopped" "$AST" down "$INST"

expect "restore" "restored to clean" "$AST" restore "$INST" clean
expect "up after restore" "$INST  running" "$AST" up "$INST"
out="$("$AST" ssh "$INST" -- "cat $PROOF" 2>&1)" || fail "reading the proof after restore"
grep -qF "$MARKER" <<<"$out" || fail "restore did not roll the disk back: $out"
grep -qF "diverged" <<<"$out" && fail "the divergence survived the restore: $out"
echo "ok: restore rolled the disk back to the snapshot's contents"

# This stop is the one where astd is still the helper's parent (the earlier
# one followed a daemon restart, which reparents it to init). An unreaped
# child answers `kill -0` for as long as the daemon lives, and `kill -0` is
# how a lost control socket is second-guessed — so a zombie here would read
# as a running guest forever.
VZ_PID2="$("$AST" status "$INST" | sed -n 's/^running: vz pid \([0-9]*\).*/\1/p')"
expect "down 3" "$INST  stopped"  "$AST" down "$INST"
sleep 1
kill -0 "$VZ_PID2" 2>/dev/null && fail "helper $VZ_PID2 still answers kill -0 after down (zombie?)"
echo "ok: the stopped helper left nothing that looks alive"
expect "status agrees it is stopped" "status:  stopped" "$AST" status "$INST"
expect "rm"     "$INST  removed"  "$AST" rm "$INST"

# ---- the same image under qemu, for the timing -----------------------------

expect "create (qemu, the default)" "$REF  defined" \
  "$AST" create "$REF" --image "$IMAGE" --mem 2G --disk 10G
expect "the default backend is still qemu" "machine: qemu" "$AST" status "$REF"
QEMU_BOOT=$(boot_seconds "$REF")
expect "down (qemu)" "$REF  stopped" "$AST" down "$REF"
expect "rm (qemu)"   "$REF  removed" "$AST" rm "$REF"

echo
echo "boot to ssh, $IMAGE, 2 cpus / 2048 MiB, first boot (cloud-init runs):"
echo "  vz    ${VZ_BOOT}s"
echo "  qemu  ${QEMU_BOOT}s"
echo
echo "E2E-VZ GREEN ($IMAGE)"
