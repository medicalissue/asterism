#!/usr/bin/env bash
# End-to-end for volume lifecycles: what a rollback does to an agent's memory
# and to a shared build cache.
#
# The claim under test is one sentence. Rewind the box and `claude --resume`
# still continues the same conversation, because ~/.claude is a volume that
# `ast restore` does not touch — while the root disk really does go back.
#
# So this lane drives a real daemon through the real snapshot and restore
# request path, with three real volumes attached to a real instance, and
# asserts on the bytes afterwards:
#
#   * an `instance` volume rolls back with the root disk
#   * a `memory` volume does not — it is still what the agent last wrote
#   * a `cache` volume never does, with or without --include-memory
#   * `ast restore --include-memory` rolls memory back and leaves cache alone
#   * a cache volume is shared by key: a second instance asking for the same
#     key attaches the volume the first one warmed, not a second copy
#
# Markers are written into the raw images from the host rather than from
# inside a guest, and the instance is never booted. That is deliberate: what
# is being proven here is which bytes a rollback replaces, and a guest would
# add a boot, a filesystem and a cloud-init to a question that is about
# neither. The guest half — that a block volume with a mount point really is
# mounted at ~/.claude before the agent session starts — is asserted in
# asterism-core's seed tests and stated in docs/orbit-storage.md.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export PATH="$HOME/.cargo/bin:$PATH"
cd "$ROOT"

# shellcheck source-path=SCRIPTDIR
. "$ROOT/scripts/lib/harness.sh"
harness_begin volume-lifecycle
harness_binaries "$ROOT"

export ASTERISM_HOME="/private/tmp/ast-vollife-$$"
export ASTERISM_MESH=local
mkdir -p "$ASTERISM_HOME"
harness_own_home "$ASTERISM_HOME"

LOG="$ASTERISM_HOME/astd.log"
IMAGE="${E2E_IMAGE:-debian:13}"
INST=lifebot
TWIN=lifetwin
DATA="$INST-data"
BRAIN="$INST-brain"
WARM="cache-agent-toolchain"
TAG=before
ASTD_PID=

# Far enough into every image to be past a partition table, and aligned, so
# `dd` never has to read-modify-write a sector it does not own.
OFFSET=1048576

cleanup() {
  "$AST" down "$INST" >/dev/null 2>&1 || true
  "$AST" rm "$INST" >/dev/null 2>&1 || true
  "$AST" rm "$TWIN" >/dev/null 2>&1 || true
  harness_keep "$LOG" astd.log
  harness_reap
  if [ -n "${KEEP:-}" ]; then
    echo "kept $ASTERISM_HOME for inspection"
  else
    case "$ASTERISM_HOME" in
      /private/tmp/ast-vollife-*) rm -rf -- "$ASTERISM_HOME" ;;
      *) echo "refusing to remove unexpected scratch path: $ASTERISM_HOME" >&2 ;;
    esac
  fi
  harness_artifacts_note
}
trap cleanup EXIT

fail() { echo "VOLUME LIFECYCLE E2E FAIL: $*" >&2; exit 1; }
ok() { echo "ok: $*"; }

expect() {
  local desc="$1" needle="$2"; shift 2
  local out
  out="$("$@" 2>&1)" || fail "$desc: command failed:"$'\n'"$out"
  grep -qF -- "$needle" <<<"$out" || fail "$desc: expected \"$needle\" in:"$'\n'"$out"
  ok "$desc"
}

refuse() {
  local desc="$1" needle="$2"; shift 2
  local out
  if out="$("$@" 2>&1)"; then
    fail "$desc: expected a refusal, got:"$'\n'"$out"
  fi
  grep -qF -- "$needle" <<<"$out" || fail "$desc: expected \"$needle\" in:"$'\n'"$out"
  ok "$desc"
}

volume_image() { echo "$ASTERISM_HOME/volumes/$1/disk.raw"; }

# The instance's root disk, whatever byte format the selected backend keeps
# it in. VZ reads raw only; a compatibility backend may keep qcow2, and this
# lane is about which file a rollback replaces, not about what is inside it.
root_disk() {
  local dir="$ASTERISM_HOME/instances/$INST" candidate
  for candidate in "$dir/disk.raw" "$dir/disk.qcow2"; do
    if [ -f "$candidate" ]; then
      echo "$candidate"
      return 0
    fi
  done
  fail "$INST has no root disk yet in $dir"
}

# 64 bytes at a fixed offset. A marker, not a filesystem: nothing here boots.
write_marker() {
  local file="$1" text="$2"
  [ -f "$file" ] || fail "no image at $file"
  printf '%-64s' "$text" \
    | dd of="$file" bs=1 seek="$OFFSET" conv=notrunc status=none \
    || fail "could not write a marker into $file"
}

read_marker() {
  local file="$1"
  [ -f "$file" ] || fail "no image at $file"
  dd if="$file" bs=1 skip="$OFFSET" count=64 status=none 2>/dev/null \
    | LC_ALL=C tr -d '\000' | sed 's/ *$//'
}

marker_is() {
  local desc="$1" file="$2" want="$3" got
  got="$(read_marker "$file")"
  [ "$got" = "$want" ] \
    || fail "$desc: $file holds \"$got\", expected \"$want\""
  ok "$desc"
}

# This device's native backend, named rather than inferred, so a run that
# quietly fell through to the QEMU compatibility backend is visible in the
# transcript instead of passing as if it had been the native one.
BACKEND="${E2E_BACKEND:-}"
if [ -z "$BACKEND" ]; then
  case "$(uname -s)" in
    Darwin) BACKEND=vz ;;
    Linux) BACKEND=chv ;;
    *) BACKEND= ;;
  esac
fi
BACKEND_ARGS=()
if [ -n "$BACKEND" ]; then
  BACKEND_ARGS=(--backend "$BACKEND")
fi

echo "== volume lifecycle e2e in $ASTERISM_HOME (backend ${BACKEND:-default})"

if [ "$BACKEND" = vz ] && [ -z "${AST_BIN:-}" ]; then
  "$ROOT/scripts/sign-vz.sh"
fi
if [ "$BACKEND" = vz ] && [ ! -x "$(dirname "$ASTD")/astd-vz" ]; then
  harness_skip "no astd-vz beside $ASTD — run scripts/sign-vz.sh"
fi

harness_cache_image "$AST" "$IMAGE" || fail "could not cache $IMAGE"
harness_seed_images "$ASTERISM_HOME"

"$ASTD" >>"$LOG" 2>&1 &
ASTD_PID=$!
for _ in $(seq 1 100); do
  [ "$(cat "$ASTERISM_HOME/astd.pid" 2>/dev/null || true)" = "$ASTD_PID" ] && break
  sleep 0.2
done
[ "$(cat "$ASTERISM_HOME/astd.pid" 2>/dev/null || true)" = "$ASTD_PID" ] \
  || fail "astd did not come up — see $LOG"
harness_own "$ASTD_PID"

# ---- the three lifecycles exist and say what they are ----------------------

expect "an ordinary volume is instance data" "instance  created" \
  "$AST" volume create "$DATA" --size 64M
expect "a memory volume says a restore will leave it alone" \
  "--include-memory rolls it back too" \
  "$AST" volume create "$BRAIN" --size 64M --lifecycle memory
expect "a cache volume says what it is shared by" \
  "shared by key \"agent-toolchain\"" \
  "$AST" volume create "$WARM" --size 64M --lifecycle cache --key agent-toolchain

expect "ast volume ls has a TYPE column" "TYPE" "$AST" volume ls
expect "the listing names the memory volume's lifecycle" "memory" "$AST" volume ls
expect "the listing names the cache volume's lifecycle" "cache" "$AST" volume ls

refuse "a key on a non-cache volume is refused rather than ignored" \
  "--lifecycle cache" \
  "$AST" volume create rejected --size 64M --lifecycle memory --key k
refuse "an unknown lifecycle lists the ones that exist" \
  "instance, memory, cache" \
  "$AST" volume create rejected --size 64M --lifecycle durable

# ---- attach them to an instance -------------------------------------------

expect "the instance is created" "$INST" \
  "$AST" create "$INST" --image "$IMAGE" --cpus 1 --mem 1G --disk 4G "${BACKEND_ARGS[@]}"

for pair in "$DATA:/srv/data" "$BRAIN:/home/ast/.claude" "$WARM:/var/cache/asterism"; do
  vol="${pair%%:*}"
  at="${pair#*:}"
  "$AST" attach "$INST" --volume "$vol" --at "$at" >/dev/null \
    || fail "could not attach $vol at $at"
done
ok "all three volumes are attached, each with a guest mount point"

expect "ast status names the memory volume and where the guest puts it" \
  "memory · nbd on this device" "$AST" status "$INST"
expect "ast status names the cache volume" \
  "/var/cache/asterism" "$AST" status "$INST"

# ---- markers, a snapshot, and then different markers ------------------------

# The root disk is materialised by the first prepare, which is what taking a
# snapshot does. Take a throwaway one to get the file, then write into it.
"$AST" snapshot "$INST" warmup >/dev/null || fail "could not materialise the root disk"

write_marker "$(root_disk)" root-before
write_marker "$(volume_image "$DATA")" data-before
write_marker "$(volume_image "$BRAIN")" brain-before
write_marker "$(volume_image "$WARM")" warm-before
ok "every image carries a 'before' marker"

"$AST" snapshot "$INST" "$TAG" >/dev/null || fail "could not take snapshot $TAG"
ok "snapshot $TAG taken"

[ -f "$ASTERISM_HOME/volumes/$BRAIN/snapshots/$TAG.raw" ] \
  || fail "the memory volume was not captured — --include-memory would have nothing behind it"
ok "the memory volume was captured beside its bytes"
[ ! -e "$ASTERISM_HOME/volumes/$WARM/snapshots/$TAG.raw" ] \
  || fail "the cache volume was captured; nothing will ever roll it back"
ok "the cache volume was not captured"

write_marker "$(root_disk)" root-after
write_marker "$(volume_image "$DATA")" data-after
write_marker "$(volume_image "$BRAIN")" brain-after
write_marker "$(volume_image "$WARM")" warm-after
ok "every image now carries an 'after' marker"

# ---- the plain rewind ------------------------------------------------------

expect "a plain restore says what it does not touch" \
  "memory and cache volumes are not rolled back" \
  "$AST" restore "$INST" "$TAG"

marker_is "the root disk went back" "$(root_disk)" root-before
marker_is "an instance volume went back with it" "$(volume_image "$DATA")" data-before
marker_is "the agent's memory did not" "$(volume_image "$BRAIN")" brain-after
marker_is "the shared cache did not" "$(volume_image "$WARM")" warm-after

# ---- the deliberate stronger thing ------------------------------------------

write_marker "$(root_disk)" root-after-again
"$AST" restore "$INST" "$TAG" --include-memory >/dev/null \
  || fail "restore --include-memory failed"

marker_is "the root disk went back again" "$(root_disk)" root-before
marker_is "--include-memory rolled the memory volume back" \
  "$(volume_image "$BRAIN")" brain-before
marker_is "--include-memory still left the shared cache alone" \
  "$(volume_image "$WARM")" warm-after

# ---- a tag is not only the instance's disk ----------------------------------

# The clones live beside the volume's own bytes, where the instance's own
# snapshot directory cannot see them. Deleting a tag has to reach them, or an
# automatic snapshot every few minutes leaves a clone per volume per tick that
# nothing ever prunes.
"$AST" snapshot rm "$INST" warmup >/dev/null || fail "could not delete snapshot warmup"
[ ! -e "$ASTERISM_HOME/volumes/$BRAIN/snapshots/warmup.raw" ] \
  || fail "deleting a tag left the memory volume's clone behind"
ok "deleting a tag releases the volume clones it captured"
[ -f "$ASTERISM_HOME/volumes/$BRAIN/snapshots/$TAG.raw" ] \
  || fail "deleting one tag took another tag's clone with it"
ok "and leaves every other tag's alone"

# ---- ast rewind obeys the same predicate ------------------------------------

# `ast rewind` is the other rollback surface, and the whole reason the
# predicate lives in one function is that these two must never disagree. Same
# volumes, same tag, same expectations — reached through `--to` so the
# assertion is about the lifecycle and not about clock arithmetic.
write_marker "$(root_disk)" root-rewound
write_marker "$(volume_image "$DATA")" data-rewound
write_marker "$(volume_image "$BRAIN")" brain-rewound
write_marker "$(volume_image "$WARM")" warm-rewound

expect "a plain rewind says what it does not touch" \
  "memory and cache volumes are not rolled back" \
  "$AST" rewind "$INST" --to "$TAG"

marker_is "the rewind put the root disk back" "$(root_disk)" root-before
marker_is "and an instance volume with it" "$(volume_image "$DATA")" data-before
marker_is "and left the agent's memory where it was" \
  "$(volume_image "$BRAIN")" brain-rewound
marker_is "and left the shared cache where it was" \
  "$(volume_image "$WARM")" warm-rewound

write_marker "$(root_disk)" root-rewound-again
"$AST" rewind "$INST" --to "$TAG" --include-memory >/dev/null \
  || fail "rewind --include-memory failed"

marker_is "rewind --include-memory put the root disk back" "$(root_disk)" root-before
marker_is "rewind --include-memory rolled the memory volume back" \
  "$(volume_image "$BRAIN")" brain-before
marker_is "rewind --include-memory still left the shared cache alone" \
  "$(volume_image "$WARM")" warm-rewound

# ---- a directory share carries a lifecycle too ------------------------------

# The agent presets mount the workspace, the agent's memory and its shared
# caches as host directories rather than block volumes, and `ast rewind` is
# what clones and restores a directory tree. So the lifecycle has to reach
# that path as well, or a preset box would rewind its own conversation away.
WORKDIR="$ASTERISM_HOME/share-work"
MEMDIR="$ASTERISM_HOME/share-memory"
mkdir -p "$WORKDIR" "$MEMDIR"
printf 'work-before\n' >"$WORKDIR/marker"
printf 'memory-before\n' >"$MEMDIR/marker"

"$AST" attach "$INST" --volume "$WORKDIR" --at /work >/dev/null \
  || fail "could not attach the workspace share"
"$AST" attach "$INST" --volume "$MEMDIR" --at /root/.claude --lifecycle memory >/dev/null \
  || fail "could not attach the memory share"
expect "ast status says which share is the agent's memory" "memory" \
  "$AST" status "$INST"

refuse "a block volume's lifecycle is not overridden at attach time" \
  "already has a lifecycle" \
  "$AST" attach "$INST" --volume "$DATA" --at /srv/other --lifecycle memory

"$AST" rewind "$INST" --to shares >/dev/null 2>&1 || true
"$AST" snapshot "$INST" shares >/dev/null || fail "could not snapshot with shares attached"

printf 'work-after\n' >"$WORKDIR/marker"
printf 'memory-after\n' >"$MEMDIR/marker"

"$AST" rewind "$INST" --to shares >/dev/null || fail "rewind with shares attached failed"
[ "$(cat "$WORKDIR/marker")" = work-before ] \
  || fail "the workspace share was not rolled back: $(cat "$WORKDIR/marker")"
ok "a rewind rolls an instance-lifecycle directory share back"
[ "$(cat "$MEMDIR/marker")" = memory-after ] \
  || fail "the memory share was rolled back: $(cat "$MEMDIR/marker")"
ok "and leaves a memory-lifecycle one exactly where the agent left it"

"$AST" rewind "$INST" --to shares --include-memory >/dev/null \
  || fail "rewind --include-memory with shares attached failed"
[ "$(cat "$MEMDIR/marker")" = memory-before ] \
  || fail "--include-memory did not roll the memory share back"
ok "rewind --include-memory rolls the memory share back too"

"$AST" detach "$INST" --volume "$WORKDIR" >/dev/null || fail "could not detach the workspace"
"$AST" detach "$INST" --volume "$MEMDIR" >/dev/null || fail "could not detach the memory share"

# ---- profile defaults, and a cache shared by key ---------------------------

# A second box, created the way a person actually creates one. Its profile
# declares a memory volume at ~/.claude and a cache keyed `agent-toolchain`,
# and the cache is the very volume the first box warmed — the bytes are still
# in it. The first box lets go of it first: a volume still has exactly one
# writable lease, so sharing by key means the second box attaches the same
# warm volume, not that two guests write it at once.
"$AST" detach "$INST" --volume "$WARM" >/dev/null \
  || fail "could not detach the cache from $INST"

expect "a box created with --profile claude is created" "$TWIN" \
  "$AST" create "$TWIN" --image "$IMAGE" --cpus 1 --mem 1G --disk 4G "${BACKEND_ARGS[@]}" \
  --profile claude

expect "the profile made a memory volume for the agent's state directory" \
  "$TWIN-claude-memory" "$AST" volume ls
expect "and attached it where the agent will look" \
  "/home/ast/.claude" "$AST" status "$TWIN"
expect "the profile's memory volume is memory, not ordinary data" \
  "memory · nbd on this device" "$AST" status "$TWIN"
expect "and it attached the cache the first box already warmed" \
  "$WARM" "$AST" status "$TWIN"

marker_is "the shared cache still holds what the first box wrote" \
  "$(volume_image "$WARM")" warm-rewound

refuse "a second volume cannot claim the same name" \
  "already has a volume called" \
  "$AST" volume create "$WARM" --size 64M --lifecycle cache --key agent-toolchain

echo
echo "VOLUME LIFECYCLE E2E PASS"
