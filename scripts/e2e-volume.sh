#!/usr/bin/env bash
# End-to-end for remote block volumes: bytes that live on one device, a guest
# that runs on another, and a filesystem the guest believes is a local disk.
#
# volume create -> attach across the mesh -> a REAL boot -> /dev/vdb in the
# guest -> mkfs + mount + a marker -> down/up and the marker survives -> a
# second instance is refused by name -> detach, reattach elsewhere, epoch
# bumped and the old export socket gone -> the export dies under a live guest
# and comes back at the same epoch -> the consumer's own daemon is killed and
# restarted under that live guest, and the disk keeps working -> the
# provider's daemon is killed and the consumer says something honest.
#
# Nothing here is proved against a mock. The guest really formats the volume,
# the bytes really cross a QUIC stream to another daemon's qemu-storage-daemon,
# and the assertions are on output CONTENT the way scripts/e2e.sh does it.
#
# ASTERISM_MESH=local keeps both endpoints on loopback: no relays, no discovery
# service, no packet that leaves the machine.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export PATH="$HOME/.cargo/bin:$PATH"
cd "$ROOT"
cargo build -q
AST="$ROOT/target/debug/ast"
ASTD="$ROOT/target/debug/astd"

# Fresh, SHORT homes: unix socket paths are capped near 104 bytes, and a volume
# adds an export socket and a bridge socket to the pile. Deliberately nowhere
# near the user's own ~/.asterism.
RUN="/private/tmp/ast-vol-$$"
A="$RUN/a"            # supplies cpu/ram: the guest runs here
B="$RUN/b"            # supplies the bytes: the volume lives here
A_NAME="vol-a-$$"
B_NAME="vol-b-$$"
INST="vol-e2e"        # the instance that really boots, on A
OTHER="vol-e2e-two"   # the second claimant, defined and never booted
VOL="tank"
IMAGE="${E2E_IMAGE:-debian:13}"

cleanup() {
  for home in "$A" "$B"; do
    [ -d "$home" ] || continue
    for inst in "$INST" "$OTHER"; do
      ASTERISM_HOME="$home" "$AST" down "$inst" >/dev/null 2>&1 || true
      ASTERISM_HOME="$home" "$AST" rm "$inst" >/dev/null 2>&1 || true
    done
  done
  pkill -f "$ASTD" 2>/dev/null || true
  # The storage daemons are this test's children too, and they outlive astd.
  pkill -f "qemu-storage-daemon.*$RUN" 2>/dev/null || true
  rm -rf "$RUN"
}
trap cleanup EXIT

fail() { echo "VOLUME E2E FAIL: $*" >&2; exit 1; }

# expect <desc> <needle> <cmd...>: run cmd, require success AND the needle.
expect() {
  local desc="$1" needle="$2"; shift 2
  local out
  out="$("$@" 2>&1)" || fail "$desc: command failed:"$'\n'"$out"
  grep -qF "$needle" <<<"$out" || fail "$desc: expected \"$needle\" in:"$'\n'"$out"
  echo "ok: $desc"
}

# refute <desc> <needle> <cmd...>: the command must FAIL, and say why.
refute() {
  local desc="$1" needle="$2"; shift 2
  local out
  if out="$("$@" 2>&1)"; then
    fail "$desc: command unexpectedly succeeded:"$'\n'"$out"
  fi
  grep -qF "$needle" <<<"$out" || fail "$desc: expected \"$needle\" in:"$'\n'"$out"
  echo "ok: $desc"
}

# file_size <path>: what the file claims to be, in bytes.
#
# stat(1) is one of the places BSD and GNU never agreed, and this script runs
# on both: macOS asks with -f, Linux with -c. Which one is in front of us is
# asked rather than guessed from `uname`, so a mac with coreutils on its PATH
# answers correctly too. Never as `bsd || gnu`, though: GNU stat reads a -f
# format as a filename, prints filesystem status for the real path to stdout,
# and only then fails — and that junk would land in the answer. Trying it into
# a variable keeps it out.
file_size() {
  local size
  if size="$(stat -f %z "$1" 2>/dev/null)"; then
    echo "$size"
  else
    stat -c %s "$1"
  fi
}

start_daemon() {
  local home="$1"
  mkdir -p "$home"
  ( ASTERISM_HOME="$home" ASTERISM_MESH=local "$ASTD" >>"$home/astd.log" 2>&1 & )
  for _ in $(seq 1 50); do
    grep -q "on the mesh as" "$home/astd.log" 2>/dev/null && return 0
    sleep 0.2
  done
  fail "astd for $home did not come up:"$'\n'"$(cat "$home/astd.log" 2>/dev/null)"
}

# Bring a daemon back, waiting on a fact rather than on a log line the
# previous run already wrote: the log is appended to, so `grep` for the
# startup banner would match the old one and return before this daemon is
# anywhere.
restart_daemon() {
  local home="$1" old now
  old="$(cat "$home/astd.pid" 2>/dev/null || true)"
  stop_daemon "$home" -KILL
  ( ASTERISM_HOME="$home" ASTERISM_MESH=local "$ASTD" >>"$home/astd.log" 2>&1 & )
  for _ in $(seq 1 100); do
    now="$(cat "$home/astd.pid" 2>/dev/null || true)"
    if [ -n "$now" ] && [ "$now" != "$old" ] && kill -0 "$now" 2>/dev/null; then
      return 0
    fi
    sleep 0.2
  done
  fail "astd for $home did not come back:"$'\n'"$(tail -20 "$home/astd.log" 2>/dev/null)"
}

stop_daemon() {
  local home="$1" sig="${2:--TERM}"
  local pid
  pid="$(cat "$home/astd.pid" 2>/dev/null || true)"
  [ -n "$pid" ] || fail "no pid file for the daemon in $home"
  kill "$sig" "$pid" 2>/dev/null || true
  for _ in $(seq 1 50); do
    kill -0 "$pid" 2>/dev/null || return 0
    sleep 0.2
  done
  kill -KILL "$pid" 2>/dev/null || true
}

# The epoch B currently has the volume leased at, straight out of its store —
# the fence is a number on disk, so assert on the number on disk.
epoch_now() {
  python3 - "$B/volumes.json" "$VOL" <<'PY'
import json, sys
store = json.load(open(sys.argv[1]))
vol = store["volumes"][sys.argv[2]]
print(vol["epoch"])
PY
}

holder_now() {
  python3 - "$B/volumes.json" "$VOL" <<'PY'
import json, sys
store = json.load(open(sys.argv[1]))
lease = store["volumes"][sys.argv[2]].get("lease")
print(lease["holder"] if lease else "-")
PY
}

# What the guest is running on, so the test can talk about a disk rather than
# about a device name it guessed.
in_guest() {
  ASTERISM_HOME="$A" "$AST" ssh "$INST" -- "$1" 2>&1
}

mkdir -p "$A" "$B"
start_daemon "$A"
start_daemon "$B"

# ---- 1. pair the two devices ------------------------------------------------

ASTERISM_HOME="$A" "$AST" device invite --name "$A_NAME" --yes >"$A/invite.out" 2>&1 &
INVITE_PID=$!
TICKET=""
for _ in $(seq 1 100); do
  TICKET="$(grep -o 'astdev1[a-z0-9]*' "$A/invite.out" 2>/dev/null | head -1 || true)"
  [ -n "$TICKET" ] && break
  sleep 0.2
done
[ -n "$TICKET" ] || fail "no ticket printed:"$'\n'"$(cat "$A/invite.out")"
ASTERISM_HOME="$B" "$AST" device add "$TICKET" --name "$B_NAME" --yes >"$B/add.out" 2>&1 \
  || fail "ast device add failed:"$'\n'"$(cat "$B/add.out")"
wait "$INVITE_PID" || fail "ast device invite failed:"$'\n'"$(cat "$A/invite.out")"
echo "ok: $A_NAME and $B_NAME are in one orbit"

# ---- 2. a volume on B -------------------------------------------------------
#
# 2 GiB, sparse. It is a raw file and nothing else: no filesystem, no
# partition table, and no way for anything but a guest to put one there.

expect "volume create on B" "$VOL  2G  created" \
  env ASTERISM_HOME="$B" "$AST" volume create "$VOL" --size 2G
expect "and it says what an empty disk is" "no filesystem on it yet" \
  env ASTERISM_HOME="$B" "$AST" volume create x-scratch --size 1G

[ -f "$B/volumes/$VOL/disk.raw" ] || fail "no image behind the volume"
SIZE="$(file_size "$B/volumes/$VOL/disk.raw")"
[ "$SIZE" = "$((2 * 1024 * 1024 * 1024))" ] || fail "the volume is $SIZE bytes, not 2 GiB"
USED="$(du -k "$B/volumes/$VOL/disk.raw" | cut -f1)"
[ "$USED" -lt 4096 ] || fail "a fresh 2 GiB volume occupies ${USED}K, so it is not sparse"
echo "ok: the volume is a 2 GiB sparse raw image and nothing else"

VOLS="$(ASTERISM_HOME="$B" "$AST" volume ls 2>&1)" || fail "volume ls failed:"$'\n'"$VOLS"
grep -qE "^NAME +SIZE +AGE +HELD BY$" <<<"$VOLS" || fail "no volume table:"$'\n'"$VOLS"
grep -qE "^$VOL +2G +\S+ +-$" <<<"$VOLS" || fail "$VOL is not listed unheld:"$'\n'"$VOLS"
echo "ok: ast volume ls shows it, held by nobody"

expect "volume rm takes one away" "x-scratch  removed" \
  env ASTERISM_HOME="$B" "$AST" volume rm x-scratch
[ ! -d "$B/volumes/x-scratch" ] || fail "removing a volume left its bytes behind"

refute "one name, one volume" "already has a volume called" \
  env ASTERISM_HOME="$B" "$AST" volume create "$VOL" --size 1G
refute "a name that would not survive a filename is refused" "may hold letters" \
  env ASTERISM_HOME="$B" "$AST" volume create "../etc" --size 1G
refute "a volume nobody has is missing from this device" "on this device" \
  env ASTERISM_HOME="$B" "$AST" volume rm ghost

# A's volume list is its own, which is the point of volumes not being an
# orbit-wide namespace.
expect "A has no volumes of its own" "no volumes on this device" \
  env ASTERISM_HOME="$A" "$AST" volume ls
# ...and A can still see B's, by naming the device that holds the bytes.
expect "A can list B's volumes by naming B" "$VOL" \
  env ASTERISM_HOME="$A" "$AST" --device "$B_NAME" volume ls

# ---- 3. an instance on A, attaching B's volume -----------------------------

mkdir -p "$A/images"
cp "$HOME/.asterism/images/"*.raw "$A/images/" 2>/dev/null || true
cp "$HOME/.asterism/images/"*.qcow2 "$A/images/" 2>/dev/null || true
ASTERISM_HOME="$A" "$AST" pull "$IMAGE" >/dev/null 2>&1 \
  || fail "no $IMAGE image available for A (pull it once: ast pull $IMAGE)"

expect "create the instance on A" "$INST  defined" \
  env ASTERISM_HOME="$A" "$AST" create "$INST" --image "$IMAGE" --mem 2G --disk 10G

ATTACH="$(ASTERISM_HOME="$A" "$AST" attach "$INST" --volume "$B_NAME:$VOL" 2>&1)" \
  || fail "attach failed:"$'\n'"$ATTACH"
grep -qF "$B_NAME:$VOL  ->  a disk in the guest" <<<"$ATTACH" \
  || fail "attach did not describe a disk:"$'\n'"$ATTACH"
grep -qF "the guest gets a plain disk" <<<"$ATTACH" \
  || fail "attach did not say the guest has to format it:"$'\n'"$ATTACH"
echo "ok: attach records a disk and says the guest must format it"

# The lease is on B, taken at attach time, and it names the instance and the
# device supplying that instance's cpu.
[ "$(holder_now)" = "$INST" ] || fail "B does not think $INST holds the lease"
E1="$(epoch_now)"
[ "$E1" = "1" ] || fail "the first lease should be epoch 1, got $E1"
LS_HELD="$(ASTERISM_HOME="$A" "$AST" --device "$B_NAME" volume ls 2>&1)"
grep -qF "$INST on $A_NAME (epoch 1)" <<<"$LS_HELD" \
  || fail "volume ls does not name the holder:"$'\n'"$LS_HELD"
echo "ok: the lease is on B at epoch 1, naming $INST on $A_NAME"

# The export is a unix socket under the volume's own directory, and there is
# no TCP port anywhere near it. That is the whole security posture.
[ -S "$B/volumes/$VOL/nbd-e1.sock" ] || fail "no export socket for epoch 1"
QSD_PID="$(cat "$B/volumes/$VOL/nbd-e1.pid")"
kill -0 "$QSD_PID" || fail "the storage daemon for epoch 1 is not running"
LISTENING="$( { lsof -a -p "$QSD_PID" -iTCP -sTCP:LISTEN -t 2>/dev/null || true; } | wc -l | tr -d ' ')"
[ "$LISTENING" = "0" ] || fail "qemu-storage-daemon is listening on $LISTENING TCP port(s)"
echo "ok: the export is a unix socket and the storage daemon holds no TCP port"

# ast status renders it as a part, sourced from the device with the bytes.
PARTS="$(ASTERISM_HOME="$A" "$AST" status "$INST" 2>&1)"
grep -qE "^  volume +$B_NAME +$VOL \(2G\) -> a disk in the guest" <<<"$PARTS" \
  || fail "the volume is not a part sourced from $B_NAME:"$'\n'"$PARTS"
grep -qF "nbd over the mesh · lease epoch 1" <<<"$PARTS" \
  || fail "ast status does not show the lease:"$'\n'"$PARTS"
echo "ok: ast status shows the volume sourced from $B_NAME with its epoch"

# ---- 4. a real boot, and a real filesystem on it ---------------------------

expect "the instance boots with the volume" "$INST  running" \
  env ASTERISM_HOME="$A" "$AST" up "$INST"

# Booting renews the lease at a higher epoch, and the old export is revoked.
E2="$(epoch_now)"
[ "$E2" = "2" ] || fail "booting should have renewed the lease to epoch 2, got $E2"
[ ! -e "$B/volumes/$VOL/nbd-e1.sock" ] \
  || fail "the epoch-1 export socket outlived the lease it belonged to"
[ -S "$B/volumes/$VOL/nbd-e2.sock" ] || fail "no export socket for epoch 2"
kill -0 "$QSD_PID" 2>/dev/null \
  && fail "the epoch-1 storage daemon is still running after the epoch bump"
echo "ok: the boot renewed the lease to epoch 2 and revoked epoch 1's export"

# The bridge is a unix socket on A, next to the instance. QEMU connects to
# that; it has no idea there is another machine behind it.
BRIDGE="$A/instances/$INST/vol-$B_NAME-$VOL.sock"
[ -S "$BRIDGE" ] || fail "no bridge socket at $BRIDGE"
A_PID="$(cat "$A/astd.pid")"
LISTENING="$( { lsof -a -p "$A_PID" -iTCP -sTCP:LISTEN -t 2>/dev/null || true; } | wc -l | tr -d ' ')"
[ "$LISTENING" = "0" ] || fail "A's daemon is listening on $LISTENING TCP port(s) for a volume"
echo "ok: the consumer end is a local unix socket, not a port"

# The guest's view: a plain virtio disk of the right size, with nothing on it.
LSBLK="$(in_guest 'lsblk -b -n -o NAME,SIZE,FSTYPE /dev/vdb')" \
  || fail "the guest has no /dev/vdb:"$'\n'"$LSBLK"
grep -qF "2147483648" <<<"$LSBLK" || fail "/dev/vdb is not 2 GiB:"$'\n'"$LSBLK"
echo "ok: the guest sees /dev/vdb, 2 GiB, and it is a local disk as far as it knows"

# Nothing in the guest may hint that this disk is on another machine.
MODEL="$(in_guest 'cat /sys/block/vdb/device/../driver/../uevent 2>/dev/null; \
                   ls -l /sys/block/vdb 2>/dev/null')"
if grep -qiE "nbd|network" <<<"$MODEL"; then
  fail "the guest can tell this disk is remote:"$'\n'"$MODEL"
fi
grep -qF "virtio" <<<"$MODEL" || fail "/dev/vdb is not a virtio disk:"$'\n'"$MODEL"
echo "ok: the guest sees a virtio disk, with no mention of a network anywhere"

MARKER="written-by-$INST-at-$(date +%s)"
FS="$(in_guest "sudo mkfs.ext4 -q -F /dev/vdb && sudo mkdir -p /data && \
                sudo mount /dev/vdb /data && \
                echo '$MARKER' | sudo tee /data/marker >/dev/null && \
                sudo umount /data && echo FORMATTED")" \
  || fail "the guest could not make a filesystem on the volume:"$'\n'"$FS"
grep -qF "FORMATTED" <<<"$FS" || fail "mkfs did not finish:"$'\n'"$FS"
echo "ok: the guest formatted the volume, mounted it and wrote a marker"

# The bytes really are on B: the image is no longer sparse-empty, and the
# marker is findable in it from the provider's side.
USED="$(du -k "$B/volumes/$VOL/disk.raw" | cut -f1)"
[ "$USED" -gt 100 ] || fail "the volume on B is still empty (${USED}K) after a mkfs"
grep -qa "$MARKER" "$B/volumes/$VOL/disk.raw" \
  || fail "the marker the guest wrote is not in B's image"
echo "ok: the bytes landed on B — the marker is in its image file (${USED}K used)"

# ---- 5. down, up, and the filesystem is still there ------------------------

expect "the instance stops" "$INST  stopped" env ASTERISM_HOME="$A" "$AST" down "$INST"
[ ! -e "$BRIDGE" ] || fail "the bridge socket outlived the guest that used it"
echo "ok: stopping the guest took the bridge down with it"

# The lease survives a stop: it belongs to the attachment, not to the boot.
[ "$(holder_now)" = "$INST" ] || fail "stopping the guest gave the lease away"

expect "and boots again" "$INST  running" env ASTERISM_HOME="$A" "$AST" up "$INST"
E3="$(epoch_now)"
[ "$E3" -gt "$E2" ] || fail "the second boot did not bump the epoch ($E2 -> $E3)"
[ ! -e "$B/volumes/$VOL/nbd-e$E2.sock" ] || fail "epoch $E2's export socket survived"

SURVIVED="$(in_guest "sudo mkdir -p /data && sudo mount /dev/vdb /data && cat /data/marker")" \
  || fail "the guest could not mount the volume it made:"$'\n'"$SURVIVED"
grep -qF "$MARKER" <<<"$SURVIVED" \
  || fail "the marker did not survive the reboot:"$'\n'"$SURVIVED"
echo "ok: the filesystem and the marker survived down/up (now epoch $E3)"

# ---- 6. one writer, and the refusal names who has it -----------------------

DISK="$A/tiny.qcow2"
qemu-img create -f qcow2 "$DISK" 1M >/dev/null 2>&1 || fail "qemu-img create failed"
expect "a second instance exists" "$OTHER  defined" \
  env ASTERISM_HOME="$A" "$AST" create "$OTHER" --image "$DISK" --mem 512M --disk 1G

refute "a second instance cannot take a held volume" \
  "volume \"$VOL\" is held by instance \"$INST\"" \
  env ASTERISM_HOME="$A" "$AST" attach "$OTHER" --volume "$B_NAME:$VOL"
refute "and the refusal says which device is writing to it" "cpu/ram on $A_NAME" \
  env ASTERISM_HOME="$A" "$AST" attach "$OTHER" --volume "$B_NAME:$VOL"
refute "and how to end it" "ast detach $INST --volume $VOL" \
  env ASTERISM_HOME="$A" "$AST" attach "$OTHER" --volume "$B_NAME:$VOL"
echo "ok: the second claimant is refused by name, by device, and told what to do"

# The refusal changed nothing: the holder still holds it at the same epoch.
[ "$(holder_now)" = "$INST" ] || fail "a refused attach took the lease anyway"
[ "$(epoch_now)" = "$E3" ] || fail "a refused attach moved the epoch"

# Nor can B delete bytes somebody is writing to.
refute "a leased volume cannot be deleted" "is held by instance \"$INST\"" \
  env ASTERISM_HOME="$B" "$AST" volume rm "$VOL"

# ---- 7. detach, and reattach elsewhere -------------------------------------
#
# Detaching a disk from a live guest would be a yanked cable — neither backend
# offers hotplug — so it is refused while the instance is up, and says so.

refute "a running instance will not give up its disk" "is running and its guest has this volume" \
  env ASTERISM_HOME="$A" "$AST" detach "$INST" --volume "$B_NAME:$VOL"

expect "stop it first" "$INST  stopped" env ASTERISM_HOME="$A" "$AST" down "$INST"
expect "detach hands the lease back" "$VOL detached" \
  env ASTERISM_HOME="$A" "$AST" detach "$INST" --volume "$B_NAME:$VOL"

[ "$(holder_now)" = "-" ] || fail "B still thinks somebody holds the volume"
[ ! -e "$B/volumes/$VOL/nbd-e$E3.sock" ] \
  || fail "the export socket for epoch $E3 outlived the lease"
LEFTOVER="$( { ls "$B/volumes/$VOL"/nbd-*.sock 2>/dev/null || true; } | wc -l | tr -d ' ')"
[ "$LEFTOVER" = "0" ] || fail "$LEFTOVER export socket(s) left behind after a detach"
echo "ok: detaching stopped the export and removed its socket"

expect "and the volume goes to the other instance" "a disk in the guest" \
  env ASTERISM_HOME="$A" "$AST" attach "$OTHER" --volume "$B_NAME:$VOL"
E4="$(epoch_now)"
[ "$(holder_now)" = "$OTHER" ] || fail "the lease did not move to $OTHER"
[ "$E4" -gt "$E3" ] || fail "moving the lease did not bump the epoch ($E3 -> $E4)"
[ -S "$B/volumes/$VOL/nbd-e$E4.sock" ] || fail "no export socket for epoch $E4"
echo "ok: reattached elsewhere at epoch $E4, and epoch $E3's door is gone"

# The instance that used to hold it no longer claims it, and refuses to boot
# with a volume it does not have rather than booting without one.
STATUS="$(ASTERISM_HOME="$A" "$AST" status "$INST" 2>&1)"
if grep -qF "$VOL (2G)" <<<"$STATUS"; then fail "$INST still lists the volume:"$'\n'"$STATUS"; fi
echo "ok: the old holder's parts table no longer lists it"

# Give it back to the instance that has the filesystem on it, so the last
# section is about a volume that is really in use.
expect "detach from the second instance" "$VOL detached" \
  env ASTERISM_HOME="$A" "$AST" detach "$OTHER" --volume "$B_NAME:$VOL"
expect "and back to the first" "a disk in the guest" \
  env ASTERISM_HOME="$A" "$AST" attach "$INST" --volume "$B_NAME:$VOL"

# ---- 8. the export dies under a running guest, and comes back --------------
#
# The storage daemon is a process, and processes die. QEMU is told to keep
# retrying for a minute rather than fail the guest's I/O, and the next
# reconnection finds the provider restarting the export at the *same* epoch —
# same epoch because nothing about who may write has changed.

expect "boot with the volume back on the first instance" "$INST  running" \
  env ASTERISM_HOME="$A" "$AST" up "$INST"
E5="$(epoch_now)"
MOUNTED="$(in_guest "sudo mkdir -p /data && sudo mount /dev/vdb /data && cat /data/marker")" \
  || fail "the guest could not mount its volume:"$'\n'"$MOUNTED"
grep -qF "$MARKER" <<<"$MOUNTED" || fail "the marker is gone:"$'\n'"$MOUNTED"

QSD_OLD="$(cat "$B/volumes/$VOL/nbd-e$E5.pid")"
kill -KILL "$QSD_OLD"
echo "ok: killed the storage daemon serving epoch $E5 under a live guest"

MARKER2="survived-a-dead-export-$(date +%s)"
RECOVER="$(in_guest "echo '$MARKER2' | sudo tee /data/marker2 >/dev/null && sync && \
                     sudo umount /data && sudo mount /dev/vdb /data && \
                     cat /data/marker /data/marker2")" \
  || fail "the guest lost its disk when the export died:"$'\n'"$RECOVER"
grep -qF "$MARKER" <<<"$RECOVER" || fail "the old marker is gone:"$'\n'"$RECOVER"
grep -qF "$MARKER2" <<<"$RECOVER" || fail "the new marker did not stick:"$'\n'"$RECOVER"
QSD_NEW="$(cat "$B/volumes/$VOL/nbd-e$E5.pid")"
[ "$QSD_NEW" != "$QSD_OLD" ] || fail "the export was never restarted"
[ "$(epoch_now)" = "$E5" ] \
  || fail "restarting a dead export moved the epoch, which would fence the holder"
echo "ok: the export was restarted at the same epoch and the guest never noticed"

# ---- 8b. the consumer's daemon restarts under a live guest -----------------
#
# The bridge is a unix socket A's astd binds and an accept loop it runs, so
# both die when astd does — and the guest does not. Its QEMU sits there
# retrying a socket with nothing behind it, and after a minute it starts
# failing the guest's I/O for real.
#
# So the next astd puts the bridges back. Not by leasing again: the running
# QEMU has one export name on its command line, and a fresh lease would bump
# the epoch and rename that door out from under a guest doing nothing wrong.
# It reconnects at the epoch it already holds.

echo "== restart A's daemon while its guest keeps running"
GUEST_PID="$(ASTERISM_HOME="$A" "$AST" status "$INST" 2>/dev/null \
  | sed -n 's/^running: .* pid \([0-9]*\),.*/\1/p')"
[ -n "$GUEST_PID" ] || fail "no guest pid to keep alive across the restart"
E_BEFORE="$(epoch_now)"

# The epoch on the instance is the one this boot was granted, not the one
# the attach got. `ast status` reads it, and so does the reconnect below —
# a stale number there would fence the daemon out of its own guest's disk.
PARTS="$(ASTERISM_HOME="$A" "$AST" status "$INST" 2>&1)"
grep -qF "nbd over the mesh · lease epoch $E_BEFORE" <<<"$PARTS" \
  || fail "ast status does not show the epoch this boot is running on ($E_BEFORE):"$'\n'"$PARTS"
echo "ok: the instance records the epoch its guest is actually using ($E_BEFORE)"

restart_daemon "$A"
kill -0 "$GUEST_PID" 2>/dev/null || fail "the guest died while astd was away"
for _ in $(seq 1 50); do [ -S "$BRIDGE" ] && break; sleep 0.2; done
[ -S "$BRIDGE" ] || fail "the new astd did not put the bridge back at $BRIDGE"
grep -qF "is bridged again at epoch $E_BEFORE" "$A/astd.log" \
  || fail "astd did not report re-establishing the bridge:"$'\n'"$(tail -20 "$A/astd.log")"
echo "ok: $(grep -m1 'is bridged again' "$A/astd.log")"

# The epoch did not move, which is the whole reason this is a reconnect and
# not a renewal: the guest's QEMU is still asking for the export it booted
# with.
[ "$(epoch_now)" = "$E_BEFORE" ] \
  || fail "the restart bumped the epoch ($E_BEFORE -> $(epoch_now)) and fenced its own guest"
[ "$(holder_now)" = "$INST" ] || fail "the lease moved during a daemon restart"
echo "ok: the lease is still $INST's, at the same epoch $E_BEFORE"

# And the point of all of it: the guest can still write to the disk. A
# marker written AFTER the restart, read back off B's image file, is the
# proof that these bytes crossed a bridge this daemon raised from nothing.
MARKER3="written-after-astd-restarted-$(date +%s)"
AFTER="$(in_guest "echo '$MARKER3' | sudo tee /data/marker3 >/dev/null && sync && \
                   sudo umount /data && sudo mount /dev/vdb /data && \
                   cat /data/marker /data/marker3")" \
  || fail "the guest lost its volume across the astd restart:"$'\n'"$AFTER"
grep -qF "$MARKER" <<<"$AFTER" || fail "the old marker is gone:"$'\n'"$AFTER"
grep -qF "$MARKER3" <<<"$AFTER" || fail "the new marker did not stick:"$'\n'"$AFTER"
grep -qa "$MARKER3" "$B/volumes/$VOL/disk.raw" \
  || fail "what the guest wrote after the restart is not in B's image"
echo "ok: the guest wrote to the volume after the restart, and the bytes are on B"

# ---- 9. the provider goes away, and the consumer is honest about it --------
#
# The failure that matters is not "it broke" but "what does the user read". A
# volume whose device is not answering must say so in one sentence naming the
# device, not bury it in a hypervisor's error.

expect "stop the guest first" "$INST  stopped" env ASTERISM_HOME="$A" "$AST" down "$INST"
stop_daemon "$B" -KILL
echo "ok: B's daemon was killed"

BOOT="$(ASTERISM_HOME="$A" "$AST" up "$INST" 2>&1 || true)"
grep -qF "could not reach the device holding it: $B_NAME" <<<"$BOOT" \
  || fail "booting with an unreachable provider was not honest:"$'\n'"$BOOT"
grep -qF "leasing volume $B_NAME:$VOL" <<<"$BOOT" \
  || fail "the failure does not name the volume:"$'\n'"$BOOT"
if grep -qiE "qemu-system|blockdev|panicked" <<<"$BOOT"; then
  fail "the user was shown a hypervisor error instead of a sentence:"$'\n'"$BOOT"
fi
echo "ok: booting says which device is out of touch and which volume it wanted"

refute "attaching says the same thing" "could not reach the device holding it: $B_NAME" \
  env ASTERISM_HOME="$A" "$AST" attach "$OTHER" --volume "$B_NAME:$VOL"

# And nothing was half-done: A did not start a guest it could not give a disk.
LS="$(ASTERISM_HOME="$A" "$AST" ls --local 2>&1)"
grep -qE "^$INST +stopped" <<<"$LS" || fail "$INST is not stopped after a failed boot:"$'\n'"$LS"
LEFT="$( { ls "$A/instances/$INST"/vol-*.sock 2>/dev/null || true; } | wc -l | tr -d ' ')"
[ "$LEFT" = "0" ] || fail "$LEFT bridge socket(s) left behind by a failed boot"
echo "ok: the failed boot left no guest and no sockets behind"

# A killed daemon takes no state with it: the lease is a file on B's disk, and
# it says exactly what it said before, so the instance gets its volume back
# when the device comes back.
#
# (This is asserted against B's store rather than by restarting B and booting
# again: under ASTERISM_MESH=local a restarted daemon binds a fresh loopback
# port, and A's orbit store still holds the old one. That is a property of the
# test's no-network mode — real deployments find a peer again through
# discovery — and faking it here would be testing the fake.)
[ "$(holder_now)" = "$INST" ] || fail "B forgot the lease across a hard kill"
[ "$(epoch_now)" = "$E5" ] || fail "the epoch moved while B was dead"
echo "ok: B's lease and its epoch survived the kill, on disk"

echo "VOLUME E2E GREEN"
