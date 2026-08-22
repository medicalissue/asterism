#!/usr/bin/env bash
# End-to-end for the storage parts journey: a same-device directory, remote
# block bytes that live on a peer, and a guest that sees both as local parts.
#
# directory attach + volume create -> block attach across the mesh -> a REAL
# boot -> virtiofs/9p directory and attached disk in the guest -> mkfs + mount
# + markers -> down/up and both survive
# -> a second instance is refused by name -> detach, reattach elsewhere,
# epoch bumped and the old export socket gone -> the export dies under a live
# guest and comes back at the same epoch -> the consumer's own daemon is
# killed and restarted under that live guest, and the disk keeps working ->
# the provider's daemon is killed and the consumer says something honest.
#
# Nothing here is proved against a mock. The guest really formats the volume,
# the bytes really cross a QUIC stream to another daemon's qemu-storage-daemon,
# and the assertions are on output CONTENT the way scripts/e2e.sh does it.
#
# ASTERISM_MESH=local keeps both endpoints on loopback: no relays, no discovery
# service, no packet that leaves the machine.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT="$ROOT/scripts/e2e-volume.sh"
export PATH="$HOME/.cargo/bin:$PATH"
cd "$ROOT"

# The volume assertions are intentionally backend-neutral. Run the complete
# lane once per hypervisor so the backend that users get by default is covered
# as well as the one whose attachment order happens to differ.
if [ -z "${E2E_VOLUME_BACKEND:-}" ]; then
  for backend in qemu vz; do
    echo "== volume e2e backend: $backend =="
    E2E_VOLUME_BACKEND="$backend" "$SCRIPT" "$@"
  done
  exit 0
fi
BACKEND="$E2E_VOLUME_BACKEND"
case "$BACKEND" in
  qemu|vz) ;;
  *) echo "VOLUME E2E FAIL: unknown backend: $BACKEND" >&2; exit 2 ;;
esac

# shellcheck source-path=SCRIPTDIR source=lib/harness.sh
. "$ROOT/scripts/lib/harness.sh"
harness_begin volume
harness_binaries "$ROOT"
# A source-tree VZ helper is unsigned after cargo builds it. The installed
# artifact path is already signed by the RC harness, so only sign the local
# pair here, matching the dedicated VZ lane's setup.
if [ "$BACKEND" = vz ] && [ -z "${AST_BIN:-}" ]; then
  "$ROOT/scripts/sign-vz.sh"
fi

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
SHARED="$A/host-share"
SHARED_GUEST="/workspace"
IMAGE="${E2E_IMAGE:-debian:13}"

# ---- the processes this test starts ----------------------------------------
#
# Everything started here writes down its own pid inside its own
# ASTERISM_HOME: astd in $home/astd.pid, each guest's qemu in
# $home/instances/<name>/qemu.pid or VZ helper in vz.pid, each storage daemon in
# $home/volumes/<name>/nbd-e<epoch>.pid. Those files are what cleanup acts
# on, so it can only ever reach a process this run started.
#
# The alternative — `pkill -f` on the astd path — reaches every astd built
# from this tree: the one the developer running this test has open on their
# own ~/.asterism, and any other e2e in this suite running beside it.

# kill_pid <pid> [signal]: bounded and idempotent. A pid that is already
# gone is success; one that will not take a hint gets ~5s and then -KILL.
kill_pid() {
  local pid="$1" sig="${2:--TERM}" _i
  case "$pid" in ''|*[!0-9]*) return 0 ;; esac
  kill -0 "$pid" 2>/dev/null || return 0
  kill "$sig" "$pid" 2>/dev/null || true
  for _i in $(seq 1 25); do
    kill -0 "$pid" 2>/dev/null || return 0
    sleep 0.2
  done
  kill -KILL "$pid" 2>/dev/null || true
}

# kill_pidfile <path>: whatever a pidfile names, and then the file.
kill_pidfile() {
  local f="$1"
  [ -f "$f" ] || return 0
  kill_pid "$(cat "$f" 2>/dev/null || true)"
  rm -f "$f"
}

# Deliberately no `ast` in here. The socket read in the CLI has no timeout,
# so `ast down` against a daemon that is wedged blocks this trap forever —
# and `ast` starts a daemon when the socket does not answer, so a cleanup
# built out of it can resurrect, and re-boot, the very instances it came to
# remove. Killing by pid needs no daemon to be well.
cleanup() {
  if [ -n "${CLEANED:-}" ]; then return 0; fi
  CLEANED=1
  # Evidence before the homes go: a daemon log and a console log are the
  # whole account of a failure, and they live in the directory below.
  for home in "$A" "$B"; do
    harness_keep_home "$home" "$(basename "$home")"
  done
  local home f pid
  # The daemons first: astd is what restarts a guest it notices die, so a
  # guest killed while its daemon is up can come straight back.
  for home in "$A" "$B"; do
    kill_pidfile "$home/astd.pid"
  done
  # Then what they left running. Both outlive astd by design.
  for home in "$A" "$B"; do
    for f in "$home"/instances/*/qemu.pid "$home"/instances/*/vz.pid; do kill_pidfile "$f"; done
    for f in "$home"/volumes/*/nbd-e*.pid; do kill_pidfile "$f"; done
    # Covers older backends whose only record was state.json. New VZ helpers
    # were stopped above through their daemon-independent vz.pid.
    for pid in $(grep -o '"pid":[0-9]*' "$home/state.json" 2>/dev/null | cut -d: -f2 || true); do
      kill_pid "$pid"
    done
  done
  rm -rf "$RUN"
  harness_artifacts_note
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

# inode_of <path>: which inode is at that path right now, or nothing at all
# if there is no file there. Same BSD/GNU split as file_size, asked the same
# way and for the same reason: a GNU stat handed -f prints filesystem status
# for the real path before it fails, so the answer is taken only from a call
# that succeeded.
#
# A bind always makes a new inode. That is what lets a caller tell a socket
# this daemon just put down from the one the last daemon left behind.
inode_of() {
  local ino
  if ino="$(stat -f %i "$1" 2>/dev/null)"; then
    echo "$ino"
  else
    stat -c %i "$1" 2>/dev/null || true
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

# Find the volume by its invariant properties, not by the backend's device
# naming order. VZ puts its cloud-init seed ahead of the volume, while QEMU
# currently puts the volume immediately after the root disk. The exact 2 GiB
# size is the volume's contract and the TYPE=disk check excludes VZ's seed ISO.
# Keep this as a single-device match:
# silently choosing among two matches would make every later assertion lie.
find_volume_device() {
  local table devices count
  table="$(in_guest 'lsblk -b -dn -o NAME,SIZE,TYPE,SERIAL')" \
    || fail "the guest could not list its block devices:"
  devices="$(awk '$2 == 2147483648 && $3 == "disk" { print "/dev/" $1 }' <<<"$table")"
  count="$(wc -l <<<"$devices" | tr -d ' ')"
  [ "$count" = "1" ] \
    || fail "could not identify the unique 2 GiB volume disk:"$'\n'"$table"
  printf '%s\n' "$devices"
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

# From the harness's own cache, never ~/.asterism: that one belongs to the
# user's daemon and may be written to while this is reading it.
harness_cache_image "$AST" "$IMAGE" || fail "could not cache $IMAGE"
harness_seed_images "$A"
ASTERISM_HOME="$A" "$AST" pull "$IMAGE" >/dev/null 2>&1 \
  || fail "no $IMAGE image available for A (pull it once: ast pull $IMAGE)"

# The disk's guest name is backend-specific, so the assertions below discover
# it from lsblk after each boot. The volume itself is still the same 2 GiB
# block device on both backends.
expect "create the instance on A ($BACKEND)" "$INST  defined" \
  env ASTERISM_HOME="$A" "$AST" create "$INST" --backend "$BACKEND" --image "$IMAGE" \
    --mem 2G --disk 10G

mkdir -p "$SHARED"
chmod 0777 "$SHARED"
HOST_MARKER="host-directory-$BACKEND-$(date +%s)"
printf '%s\n' "$HOST_MARKER" >"$SHARED/host-marker"
expect "attach a same-device directory ($BACKEND)" "$SHARED_GUEST" \
  env ASTERISM_HOME="$A" "$AST" attach "$INST" --volume "$SHARED" --at "$SHARED_GUEST"

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

SHARED_READ="$(in_guest "cat $SHARED_GUEST/host-marker")" \
  || fail "the guest could not read its same-device directory:"$'\n'"$SHARED_READ"
grep -qF "$HOST_MARKER" <<<"$SHARED_READ" \
  || fail "the host marker did not reach the guest:"$'\n'"$SHARED_READ"
GUEST_MARKER="guest-directory-$BACKEND-$(date +%s)"
in_guest "echo '$GUEST_MARKER' > $SHARED_GUEST/guest-marker && sync" >/dev/null \
  || fail "the guest could not write its same-device directory"
grep -qF "$GUEST_MARKER" "$SHARED/guest-marker" \
  || fail "the guest's directory write did not reach the host"
echo "ok: the guest and host see the same writable directory through $BACKEND"

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
VOLUME_DEV="$(find_volume_device)"
LSBLK="$(in_guest "lsblk -b -n -o NAME,SIZE,FSTYPE $VOLUME_DEV")" \
  || fail "the guest has no $VOLUME_DEV:"$'\n'"$LSBLK"
grep -qF "2147483648" <<<"$LSBLK" || fail "$VOLUME_DEV is not 2 GiB:"$'\n'"$LSBLK"
echo "ok: the guest sees $VOLUME_DEV, 2 GiB, and it is a local disk as far as it knows"

# Nothing in the guest may hint that this disk is on another machine.
VOLUME_NAME="${VOLUME_DEV#/dev/}"
MODEL="$(in_guest "cat /sys/block/$VOLUME_NAME/device/../driver/../uevent 2>/dev/null; \
                   ls -l /sys/block/$VOLUME_NAME 2>/dev/null")"
if grep -qiE "nbd|network" <<<"$MODEL"; then
  fail "the guest can tell this disk is remote:"$'\n'"$MODEL"
fi
grep -qF "virtio" <<<"$MODEL" || fail "$VOLUME_DEV is not a virtio disk:"$'\n'"$MODEL"
echo "ok: the guest sees $VOLUME_DEV as a virtio disk, with no mention of a network anywhere"

MARKER="written-by-$INST-at-$(date +%s)"
FS="$(in_guest "sudo mkfs.ext4 -q -F $VOLUME_DEV && sudo mkdir -p /data && \
                sudo mount $VOLUME_DEV /data && \
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
VOLUME_DEV="$(find_volume_device)"

SURVIVED="$(in_guest "sudo mkdir -p /data && sudo mount $VOLUME_DEV /data && cat /data/marker")" \
  || fail "the guest could not mount the volume it made:"$'\n'"$SURVIVED"
grep -qF "$MARKER" <<<"$SURVIVED" \
  || fail "the marker did not survive the reboot:"$'\n'"$SURVIVED"
echo "ok: the filesystem and the marker survived down/up (now epoch $E3)"
expect "the directory mount survives down/up too" "$HOST_MARKER" \
  in_guest "cat $SHARED_GUEST/host-marker"

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
VOLUME_DEV="$(find_volume_device)"
MOUNTED="$(in_guest "sudo mkdir -p /data && sudo mount $VOLUME_DEV /data && cat /data/marker")" \
  || fail "the guest could not mount its volume:"$'\n'"$MOUNTED"
grep -qF "$MARKER" <<<"$MOUNTED" || fail "the marker is gone:"$'\n'"$MOUNTED"

QSD_OLD="$(cat "$B/volumes/$VOL/nbd-e$E5.pid")"
kill -KILL "$QSD_OLD"
echo "ok: killed the storage daemon serving epoch $E5 under a live guest"

MARKER2="survived-a-dead-export-$(date +%s)"
RECOVER="$(in_guest "echo '$MARKER2' | sudo tee /data/marker2 >/dev/null && sync && \
                     sudo umount /data && sudo mount $VOLUME_DEV /data && \
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

# Both of these are read BEFORE the restart, because both are how the next
# daemon is told apart from the one it replaces.
BRIDGE_INO="$(inode_of "$BRIDGE")"
LOG_AT="$(file_size "$A/astd.log")"

restart_daemon "$A"
kill -0 "$GUEST_PID" 2>/dev/null || fail "the guest died while astd was away"

# Nothing unlinked the old bridge socket. astd was killed with -KILL, so the
# file it had bound is still sitting at that path: `[ -S "$BRIDGE" ]` is true
# the instant the restart returns, a loop waiting on it falls straight
# through, and the one-shot grep behind it then races the daemon startup it
# is asking about. Existence at that path proves nothing about who owns it.
#
# So wait — boundedly — on two facts only the NEW daemon can make true.
#
# The socket is one it bound itself: a bind always makes a new inode, so an
# inode that has not moved is the corpse rather than the reattachment.
#
# And it finished, at the epoch its guest is already running on. That line is
# read only past where the log stood a moment ago, because the log is
# appended to across restarts — the same reason restart_daemon waits on a pid
# and not on a banner — and an earlier run's line would otherwise match.
#
# 60s is long for a local reconnect and deliberately so: it is a bound, not a
# schedule, and the cost of one that is too tight is a green test that fails
# on a slow machine for a reason that has nothing to do with volumes.
REATTACHED=""
NEW_LOG=""
for _ in $(seq 1 300); do
  if [ -S "$BRIDGE" ] && [ "$(inode_of "$BRIDGE")" != "$BRIDGE_INO" ]; then
    # Read into a variable rather than piping into grep -q: under pipefail a
    # grep that quits on its first match can leave tail holding a closed pipe,
    # and the whole condition then reports failure for having succeeded early.
    NEW_LOG="$(tail -c "+$((LOG_AT + 1))" "$A/astd.log" 2>/dev/null || true)"
    if grep -qF "is bridged again at epoch $E_BEFORE" <<<"$NEW_LOG"; then
      REATTACHED=1
      break
    fi
  fi
  sleep 0.2
done

if [ -z "$REATTACHED" ]; then
  NEW_LOG="$(tail -c "+$((LOG_AT + 1))" "$A/astd.log" 2>/dev/null || true)"
  BRIDGE_INO_NOW="$(inode_of "$BRIDGE")"
  if [ ! -S "$BRIDGE" ] || [ "$BRIDGE_INO_NOW" = "$BRIDGE_INO" ]; then
    # Two adjacent quoted strings joined across a line break, which is
    # concatenation and not the "A"B"C" quoting mistake it resembles.
    # shellcheck disable=SC2140
    fail "the new astd did not bind its own bridge socket at $BRIDGE"\
" (inode ${BRIDGE_INO:-none} before the restart, ${BRIDGE_INO_NOW:-none} now):"$'\n'"$NEW_LOG"
  fi
  fail "astd bound the bridge but never reported re-establishing it at epoch $E_BEFORE:"$'\n'"$NEW_LOG"
fi
echo "ok: $(grep -m1 -F "is bridged again at epoch $E_BEFORE" <<<"$NEW_LOG")"

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
                   sudo umount /data && sudo mount $VOLUME_DEV /data && \
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
