#!/usr/bin/env bash
# End-to-end for automatic snapshots and `ast rewind` on a real guest.
#
# The claim this lane exists to prove is a product claim, not a mechanism one:
# you can run an agent with every permission granted, because if it goes wrong
# you can put the machine back. So it does exactly what somebody doing that
# would do — leave an instance running, let it write, let the daemon snapshot
# it on its own, destroy the work, and then ask for it back:
#
#   * astd takes a disk snapshot on a timer with nobody typing anything
#   * a local directory volume is snapshotted beside the root disk
#   * `ast rewind <name> <duration>` stops, keeps the current state as
#     `before-rewind`, rolls both back, starts, and republishes the port
#   * the published port answers again afterwards, on exactly the same number
#   * `--to <snapshot>` is deterministic, and a target that does not exist is
#     refused with the timeline and without touching the guest
#   * a named snapshot is on the timeline and is never pruned
#
# The interval is forced to a minute so a lane can watch three passes. In
# production it is ten.
#
#   scripts/e2e-rewind.sh              # vz on macOS, chv on Linux
#   E2E_BACKEND=chv scripts/e2e-rewind.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export PATH="$HOME/.cargo/bin:$PATH"
cd "$ROOT"

# shellcheck source-path=SCRIPTDIR
. "$ROOT/scripts/lib/harness.sh"
harness_begin rewind
harness_binaries "$ROOT"

case "${E2E_BACKEND:-}" in
  '')
    case "$(uname -s)" in
      Darwin) BACKEND=vz ;;
      Linux) BACKEND=chv ;;
      *) harness_skip "no native backend on $(uname -s)" ;;
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

# Short home on purpose: unix socket paths are capped near 104 bytes, and the
# helper's control socket lives under it.
export ASTERISM_HOME="/private/tmp/ast-rewind-$$"
if [ ! -d /private/tmp ]; then
  export ASTERISM_HOME="/tmp/ast-rewind-$$"
fi
export ASTERISM_MESH=local
# The knob this lane turns, and the only reason it can watch three passes
# inside a test run. Retention has to be at least the interval, or the
# settings refuse themselves.
export ASTERISM_REWIND_EVERY=1m
export ASTERISM_REWIND_KEEP=1h
mkdir -p "$ASTERISM_HOME"
harness_own_home "$ASTERISM_HOME"

BIN="$ASTERISM_HOME/bin"
LOG="$ASTERISM_HOME/astd.log"
EVIDENCE="$ASTERISM_HOME/evidence"
WORK="$ASTERISM_HOME/work"
IMAGE="${E2E_IMAGE:-docker.io/library/nginx:alpine}"
INST=bot
SNAPSHOTS="$ASTERISM_HOME/instances/$INST/snapshots"
ASTD_PID=
PORT=

cleanup() {
  "$AST" down "$INST" >/dev/null 2>&1 || true
  "$AST" rm "$INST" >/dev/null 2>&1 || true
  harness_keep_home "$ASTERISM_HOME" home
  harness_reap
  if [ -n "${KEEP:-}" ]; then
    echo "kept $ASTERISM_HOME for inspection"
  else
    case "$ASTERISM_HOME" in
      /private/tmp/ast-rewind-* | /tmp/ast-rewind-*) rm -rf -- "$ASTERISM_HOME" ;;
      *) echo "refusing to remove unexpected scratch path: $ASTERISM_HOME" >&2 ;;
    esac
  fi
  harness_artifacts_note
}
trap cleanup EXIT

fail() {
  echo "REWIND E2E FAIL: $*" >&2
  exit 1
}
ok() { echo "ok: $*"; }

expect() {
  local desc="$1" needle="$2"
  shift 2
  local out
  if ! out="$("$@" 2>&1)"; then
    fail "$desc: command failed:"$'\n'"$out"
  fi
  if ! grep -qF -- "$needle" <<<"$out"; then
    fail "$desc: expected \"$needle\" in:"$'\n'"$out"
  fi
  ok "$desc"
}

refuses() {
  local desc="$1" needle="$2"
  shift 2
  local out
  if out="$("$@" 2>&1)"; then
    fail "$desc: the command succeeded when it had to refuse:"$'\n'"$out"
  fi
  if ! grep -qF -- "$needle" <<<"$out"; then
    fail "$desc: expected \"$needle\" in the refusal:"$'\n'"$out"
  fi
  ok "$desc"
}

# One command inside the guest, retried.
#
# The retry is not this lane's subject and is not papering over its own bug.
# The guest-control handshake on VZ intermittently answers "the host did not
# prove the instance key" and succeeds on the next attempt — reproduced on
# this tree with the snapshot scheduler switched off entirely, so it predates
# `ast rewind` and belongs to whoever owns the guest agent. A lane that made
# a product claim fail on somebody else's flake would tell nobody anything.
guest() {
  local out='' attempt
  for attempt in 1 2 3 4 5; do
    if out="$("$AST" exec "$INST" -- /bin/sh -c "$1" 2>&1)"; then
      printf '%s\n' "$out"
      return 0
    fi
    if ! grep -qF -- "did not prove the instance key" <<<"$out"; then
      printf '%s\n' "$out"
      return 1
    fi
    echo "retrying the guest-control handshake (attempt $attempt): $out" >&2
    sleep 3
  done
  printf '%s\n' "$out"
  return 1
}

free_port() {
  python3 - <<'PY'
import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
PY
}

http_status() {
  curl -s -o /dev/null -m 5 -w '%{http_code}' "http://127.0.0.1:$1/" 2>/dev/null || true
}

expect_http_200() {
  local desc="$1" port="$2" code=
  for _ in $(seq 1 90); do
    code="$(http_status "$port")"
    if [ "$code" = 200 ]; then
      ok "$desc (HTTP $code on 127.0.0.1:$port)"
      return 0
    fi
    sleep 2
  done
  fail "$desc: 127.0.0.1:$port answered \"$code\", not 200"
}

timeline() { "$AST" rewind "$INST" 2>&1; }

auto_count() {
  local out
  out="$(timeline)"
  grep -c '  auto' <<<"$out" || true
}

oldest_auto_tag() {
  find "$SNAPSHOTS" -maxdepth 1 -name 'auto-*.raw' -print 2>/dev/null |
    sed 's|.*/||; s|\.raw$||' | sort | head -n 1
}

# Wait until the scheduler has taken at least N automatic snapshots. Bounded,
# because a lane that hangs is a job cancelled twenty minutes later with
# nothing worth reading in it.
wait_for_autos() {
  local want="$1" have=
  for _ in $(seq 1 90); do
    have="$(auto_count)"
    if [ "${have:-0}" -ge "$want" ]; then
      ok "the daemon has taken $have automatic snapshot(s) on its own"
      return 0
    fi
    sleep 4
  done
  timeline
  fail "waited six minutes for $want automatic snapshots, saw ${have:-0}"
}

mkdir -p "$BIN/guest/bin" "$EVIDENCE" "$WORK"
cp "$AST" "$ASTD" "$BIN/"
if [ "$BACKEND" = vz ]; then
  if [ -x "$(dirname "$ASTD")/astd-vz" ]; then
    cp "$(dirname "$ASTD")/astd-vz" "$BIN/astd-vz"
  else
    fail "no astd-vz beside $ASTD — run scripts/sign-vz.sh"
  fi
fi
cp "$GUEST_ARTIFACT" "$BIN/guest/bin/asterism-guest"
chmod 0755 "$BIN/guest/bin/asterism-guest"
AST="$BIN/ast"
ASTD="$BIN/astd"
export AST ASTD

echo "== rewind e2e in $ASTERISM_HOME (backend $BACKEND, every $ASTERISM_REWIND_EVERY)"

harness_cache_image "$AST" "$IMAGE" || fail "could not cache $IMAGE"
harness_seed_images "$ASTERISM_HOME"

"$ASTD" >>"$LOG" 2>&1 &
ASTD_PID=$!
harness_own "$ASTD_PID"
for _ in $(seq 1 300); do
  if [ "$(cat "$ASTERISM_HOME/astd.pid" 2>/dev/null || true)" = "$ASTD_PID" ]; then
    break
  fi
  sleep 0.2
done
if [ "$(cat "$ASTERISM_HOME/astd.pid" 2>/dev/null || true)" != "$ASTD_PID" ]; then
  fail "astd did not come up:"$'\n'"$(cat "$LOG" 2>/dev/null || true)"
fi
grep -qF -- "automatic snapshots every 1m" "$LOG" \
  || fail "astd did not announce the scheduler:"$'\n'"$(cat "$LOG")"
ok "astd announced automatic snapshots every 1m, kept 1h"

PORT="$(free_port)"
expect "create the agent instance with a published port" "$INST  defined" \
  "$AST" create "$INST" --backend "$BACKEND" --image "$IMAGE" \
  --cpus 2 --mem 1G --disk 4G -p "$PORT:80"
expect "attach a local directory volume as /work" "/work" \
  "$AST" attach "$INST" --volume "$WORK" --at /work

expect "boot it" "$INST  running" "$AST" up "$INST"
expect_http_200 "the published port answers before anything is snapshotted" "$PORT"

# ---- what the agent does ---------------------------------------------------
#
# One marker on the root disk and one in the volume, so the rewind has to put
# both back. Written from inside the guest, which is where an agent writes.
expect "the agent writes t0" t0 \
  guest "mkdir -p /var/lib/asterism && echo t0 > /var/lib/asterism/marker && echo t0 > /work/t0 && sync && cat /work/t0"
wait_for_autos 1
BASELINE_TAG="$(oldest_auto_tag)"
[ -n "$BASELINE_TAG" ] || fail "no automatic snapshot on disk after the first pass"
ok "the first automatic snapshot is $BASELINE_TAG"

expect "the agent writes t1" t1 \
  guest "echo t1 > /var/lib/asterism/marker && echo t1 > /work/t1 && sync && cat /work/t1"
wait_for_autos 2

expect "the agent writes t2" t2 \
  guest "echo t2 > /var/lib/asterism/marker && echo t2 > /work/t2 && sync && cat /work/t2"
wait_for_autos 3

# ---- the volume really was snapshotted beside the disk ---------------------
VOLUME_CLONE="$(find "$SNAPSHOTS" -maxdepth 1 -type d -name 'auto-*.vol0' -print 2>/dev/null | sort | head -n 1)"
[ -n "$VOLUME_CLONE" ] || fail "no directory volume was cloned beside a snapshot in $SNAPSHOTS"
[ -f "$VOLUME_CLONE/t0" ] || fail "the volume clone at $VOLUME_CLONE does not hold t0"
ok "the /work volume was snapshotted beside the root disk ($(basename "$VOLUME_CLONE"))"

DISK_KB="$(du -sk "$ASTERISM_HOME/instances/$INST/disk.raw" | awk '{print $1}')"
SNAP_KB="$(du -sk "$SNAPSHOTS" | awk '{print $1}')"
echo "cow: live disk ${DISK_KB} KiB; du charges the snapshots directory ${SNAP_KB} KiB"

# ---- the agent does something regrettable ----------------------------------
expect "the agent destroys its own work" gone \
  guest "rm -f /work/t0 /work/t1 /work/t2 /var/lib/asterism/marker && sync && echo gone"
if [ -e "$WORK/t0" ]; then
  fail "the guest's delete did not reach the host side of the share"
fi
ok "t0, t1 and t2 are gone from the guest and from the host share"

BEFORE_TIMELINE="$(timeline)"
printf '%s\n' "$BEFORE_TIMELINE" >"$EVIDENCE/timeline-before.txt"
echo "--- ast rewind $INST (before)"
printf '%s\n' "$BEFORE_TIMELINE"

# ---- refusals happen before anything is stopped ----------------------------
refuses "a snapshot that does not exist is refused with the timeline" \
  "no snapshot \"before-refactor\"" "$AST" rewind "$INST" --to before-refactor
expect "the guest was left running by the refusal" "running" "$AST" status "$INST"
refuses "a bare number is not a duration" "20m" "$AST" rewind "$INST" 20

# ---- the rewind itself -----------------------------------------------------
REWIND_OUT="$("$AST" rewind "$INST" 2m 2>&1)" \
  || fail "the rewind failed:"$'\n'"$REWIND_OUT"
printf '%s\n' "$REWIND_OUT" >"$EVIDENCE/rewind.txt"
echo "--- ast rewind $INST 2m"
printf '%s\n' "$REWIND_OUT"
grep -qF -- "$INST rewound to" <<<"$REWIND_OUT" \
  || fail "the rewind did not report what it rewound to:"$'\n'"$REWIND_OUT"
grep -qF 'current state kept as "before-rewind"' <<<"$REWIND_OUT" \
  || fail "the rewind did not keep the state it replaced:"$'\n'"$REWIND_OUT"
grep -qE '\([0-9]+\.[0-9] s\)' <<<"$REWIND_OUT" \
  || fail "the rewind did not report how long it took:"$'\n'"$REWIND_OUT"
ok "the rewind reported its target, its cost and its undo"

expect "the instance is running again" "running" "$AST" status "$INST"
expect_http_200 "the published port answers again on exactly its own number" "$PORT"
expect "the root disk came back" t0 guest "cat /var/lib/asterism/marker"
expect "the volume came back" t0 guest "cat /work/t0"
if [ ! -f "$WORK/t0" ]; then
  fail "the rewound volume is not visible on the host side of the share"
fi
ok "the rewound /work is the same directory the host shares"

AFTER_TIMELINE="$(timeline)"
printf '%s\n' "$AFTER_TIMELINE" >"$EVIDENCE/timeline-after.txt"
echo "--- ast rewind $INST (after)"
printf '%s\n' "$AFTER_TIMELINE"
grep -qF -- "before-rewind" <<<"$AFTER_TIMELINE" \
  || fail "the undo is not on the timeline:"$'\n'"$AFTER_TIMELINE"
ok "the state the rewind replaced is on the timeline as before-rewind"

# ---- a named snapshot, and rewinding to one by name ------------------------
expect "stop for a named snapshot" "$INST  stopped" "$AST" down "$INST"
refuses "a hand-typed tag may not pass for the scheduler's" \
  "automatic snapshots are named" "$AST" snapshot "$INST" auto-mine

# What a copy-on-write clone really costs, measured where it can be: the
# guest is stopped, so the only thing touching this filesystem is the clone
# itself. `du` and the `--usage` footer both report `st_blocks`, which charges
# every shared block to every file that references it — three clones of an
# 80 MiB disk read as 240 MiB and occupy almost nothing. The free-space delta
# is the number that is true.
USED_BEFORE="$(df -k "$ASTERISM_HOME" | awk 'NR==2 {print $3}')"
expect "take a named snapshot" "$INST  snapshot before-migration" \
  "$AST" snapshot "$INST" before-migration
USED_AFTER="$(df -k "$ASTERISM_HOME" | awk 'NR==2 {print $3}')"
GROWTH_KB=$((USED_AFTER - USED_BEFORE))
echo "cow: cloning the ${DISK_KB} KiB root disk cost ${GROWTH_KB} KiB of free space"
printf 'live disk %s KiB\ndu of the snapshots directory %s KiB\nfree space consumed by one clone of the stopped disk %s KiB\n' \
  "$DISK_KB" "$SNAP_KB" "$GROWTH_KB" >"$EVIDENCE/cow-usage.txt"
expect "boot again" "$INST  running" "$AST" up "$INST"
expect "the named snapshot is on the timeline" "named   before-migration" \
  "$AST" rewind "$INST"

expect "rewind to the very first automatic snapshot by name" "rewound to" \
  "$AST" rewind "$INST" --to "$BASELINE_TAG"
expect "the instance is running after the named rewind" "running" "$AST" status "$INST"
expect_http_200 "the published port survived a second rewind" "$PORT"
expect "the baseline snapshot is what came back" t0 guest "cat /work/t0"

# ---- usage, and retention's own rules --------------------------------------
expect "usage is a footer on the listing" "auto every 1m, kept 1h" \
  "$AST" rewind "$INST" --usage
expect "the per-instance interval can be changed" "auto every 5m, kept 2h" \
  "$AST" rewind "$INST" --every 5m --keep 2h
refuses "an interval that would delete every snapshot before the next" \
  "--keep" "$AST" rewind "$INST" --every 10m --keep 1m
expect "the instance can be put back on the device default" "auto every 1m" \
  "$AST" rewind "$INST" --reset
expect "the named snapshot outlived every automatic one" "before-migration" \
  "$AST" rewind "$INST"

expect "stop the completed rewind lane" "$INST  stopped" "$AST" down "$INST"
expect "remove the completed rewind lane" "$INST  removed" "$AST" rm "$INST"
echo "REWIND E2E GREEN ($IMAGE, $BACKEND, snapshots every 1m)"
