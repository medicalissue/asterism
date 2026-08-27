#!/usr/bin/env bash
# End-to-end for `ast fork`, `ast diff` and `ast pick` on real guests.
#
# The claim this lane exists to prove is a product claim: when there are three
# ways to fix a bug you can try all three at once, on three copies of the
# machine that is stuck, and keep the one that worked. So it does exactly what
# somebody doing that would do:
#
#   * one running OCI instance with a git repository shared as /work
#   * `ast fork bot --n 3 --each ...` clones it three ways while it runs
#   * every fork boots with its own hostname and its own guest key, and none
#     of them publishes the parent's port
#   * each fork is edited independently, from inside its own guest
#   * `ast diff <fork>` reports each one's own changes and nobody else's
#   * `ast pick bot-2` puts bot-2's work onto bot, removes bot-1 and bot-3,
#     leaves bot's root disk alone, and keeps a `before-pick` snapshot
#   * a `cache` volume is shared with the forks and a `memory` one is copied
#   * `ast rewind bot --to before-pick` undoes the pick
#   * the clone is measured: wall clock, and the free space it really cost
#
#   scripts/e2e-fork.sh              # vz on macOS, chv on Linux
#   E2E_BACKEND=chv scripts/e2e-fork.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export PATH="$HOME/.cargo/bin:$PATH"
cd "$ROOT"

# shellcheck source-path=SCRIPTDIR
. "$ROOT/scripts/lib/harness.sh"
harness_begin fork
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
if ! command -v git >/dev/null 2>&1; then
  harness_skip "this lane needs git on the host to make the /work repository"
fi

# Short home on purpose: unix socket paths are capped near 104 bytes.
export ASTERISM_HOME="/private/tmp/ast-fork-$$"
if [ ! -d /private/tmp ]; then
  export ASTERISM_HOME="/tmp/ast-fork-$$"
fi
export ASTERISM_MESH=local
# The scheduler is not this lane's subject and a snapshot landing mid-fork
# would only add noise to the disk numbers.
export ASTERISM_REWIND_EVERY=1h
export ASTERISM_REWIND_KEEP=6h
mkdir -p "$ASTERISM_HOME"
harness_own_home "$ASTERISM_HOME"

BIN="$ASTERISM_HOME/bin"
LOG="$ASTERISM_HOME/astd.log"
EVIDENCE="$ASTERISM_HOME/evidence"
WORK="$ASTERISM_HOME/work"
CACHE="$ASTERISM_HOME/cache"
BRAIN="$ASTERISM_HOME/memory"
IMAGE="${E2E_IMAGE:-docker.io/library/nginx:alpine}"
INST=bot
ASTD_PID=
PORT=

cleanup() {
  for name in "$INST-1" "$INST-2" "$INST-3" "$INST"; do
    "$AST" down "$name" >/dev/null 2>&1 || true
    "$AST" rm "$name" >/dev/null 2>&1 || true
  done
  harness_keep_home "$ASTERISM_HOME" home
  harness_reap
  if [ -n "${KEEP:-}" ]; then
    echo "kept $ASTERISM_HOME for inspection"
  else
    case "$ASTERISM_HOME" in
      /private/tmp/ast-fork-* | /tmp/ast-fork-*) rm -rf -- "$ASTERISM_HOME" ;;
      *) echo "refusing to remove unexpected scratch path: $ASTERISM_HOME" >&2 ;;
    esac
  fi
  harness_artifacts_note
}
trap cleanup EXIT

fail() {
  echo "FORK E2E FAIL: $*" >&2
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

# One command inside a named guest, retried.
#
# The retry is not this lane's subject: the guest-control handshake on VZ
# intermittently answers "the host did not prove the instance key" and
# succeeds on the next attempt. It predates this feature — see the same
# paragraph in scripts/e2e-rewind.sh.
guest() {
  local name="$1" script="$2" out='' attempt
  for attempt in 1 2 3 4 5; do
    if out="$("$AST" exec "$name" -- /bin/sh -c "$script" 2>&1)"; then
      printf '%s\n' "$out"
      return 0
    fi
    if ! grep -qF -- "did not prove the instance key" <<<"$out"; then
      printf '%s\n' "$out"
      return 1
    fi
    echo "retrying the guest-control handshake on $name (attempt $attempt): $out" >&2
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

used_kb() { df -k "$ASTERISM_HOME" | awk 'NR==2 {print $3}'; }

mkdir -p "$BIN/guest/bin" "$EVIDENCE" "$WORK" "$CACHE" "$BRAIN"
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

echo "== fork e2e in $ASTERISM_HOME (backend $BACKEND)"

# ---- a /work that is a real git repository ---------------------------------
#
# So `ast diff` takes its git path, which is the one an agent's own numbers
# come from.
git -C "$WORK" init -q
git -C "$WORK" config user.email fork@e2e.invalid
git -C "$WORK" config user.name "fork e2e"
printf 'one\ntwo\nthree\nfour\nfive\n' >"$WORK/parser.txt"
printf 'alpha\nbeta\n' >"$WORK/token.txt"
git -C "$WORK" add -A
git -C "$WORK" commit -qm "the state the agent was stuck at"
ok "the /work share is a git repository at $(git -C "$WORK" rev-parse --short HEAD)"

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

PORT="$(free_port)"
expect "create the agent instance with a published port" "$INST  defined" \
  "$AST" create "$INST" --backend "$BACKEND" --image "$IMAGE" \
  --cpus 2 --mem 1G --disk 4G -p "$PORT:80"
expect "attach the repository as /work" "/work" \
  "$AST" attach "$INST" --volume "$WORK" --at /work
expect "attach a cache the forks are meant to share" "/cache" \
  "$AST" attach "$INST" --volume "$CACHE" --at /cache --lifecycle cache
expect "attach a memory each fork is meant to get its own of" "/memory" \
  "$AST" attach "$INST" --volume "$BRAIN" --at /memory --lifecycle memory
expect "boot it" "$INST  running" "$AST" up "$INST"
expect "the agent can see its work" "three" guest "$INST" "cat /work/parser.txt"

# ---- refusals happen before anything moves ---------------------------------
refuses "a parent that is not here is refused" "no instance named" \
  "$AST" fork nosuch --n 2
refuses "a double-digit fleet wants saying twice" "--yes" \
  "$AST" fork "$INST" --n 12
refuses "--each is one message per fork or none" "3 forks asked for, 2 messages given" \
  "$AST" fork "$INST" --n 3 --each "A" "B"
expect "the guest was left running by every refusal" "running" "$AST" status "$INST"

# ---- the fork itself -------------------------------------------------------
USED_BEFORE="$(used_kb)"
START_NS="$(python3 -c 'import time; print(time.monotonic_ns())')"
FORK_OUT="$("$AST" fork "$INST" --n 3 \
  --each "A: rewrite the parser" "B: patch the tokenizer" "C: add a fallback path" 2>&1)" \
  || fail "the fork failed:"$'\n'"$FORK_OUT"
END_NS="$(python3 -c 'import time; print(time.monotonic_ns())')"
USED_AFTER="$(used_kb)"
GROWTH_KB=$((USED_AFTER - USED_BEFORE))
WALL_MS=$(((END_NS - START_NS) / 1000000))
printf '%s\n' "$FORK_OUT" >"$EVIDENCE/fork.txt"
echo "--- ast fork $INST --n 3 --each ..."
printf '%s\n' "$FORK_OUT"
# Reported, not asserted. This window is `df` around the whole command —
# three guests booting, and whatever else is running on this machine — so it
# is noisy in both directions and has come out negative on a busy host. The
# number measured in the right window, across the clones and before the
# boots, is the one `ast fork` prints for itself.
echo "fork: df around the whole command moved ${GROWTH_KB} KiB (noisy: includes three boots and any other writer); ast took ${WALL_MS} ms end to end"

grep -qF -- "$INST-1 $INST-2 $INST-3 up" <<<"$FORK_OUT" \
  || fail "the fork did not name its three forks:"$'\n'"$FORK_OUT"
grep -qE 'cloned from bot in [0-9]+\.[0-9] s' <<<"$FORK_OUT" \
  || fail "the fork did not report how long it took:"$'\n'"$FORK_OUT"
grep -qF -- "publish no ports" <<<"$FORK_OUT" \
  || fail "the fork did not say the forks publish no ports:"$'\n'"$FORK_OUT"
grep -qF -- "/cache is shared with the forks" <<<"$FORK_OUT" \
  || fail "the fork did not say the cache is shared:"$'\n'"$FORK_OUT"
ok "three forks came up and the line said what they cost"

expect "the parent is still running" "running" "$AST" status "$INST"

# ---- provenance is on the listing ------------------------------------------
LS_OUT="$("$AST" ls 2>&1)"
printf '%s\n' "$LS_OUT" >"$EVIDENCE/ls.txt"
echo "--- ast ls"
printf '%s\n' "$LS_OUT"
grep -qF -- "NOTE" <<<"$LS_OUT" || fail "ast ls grew no NOTE column:"$'\n'"$LS_OUT"
grep -qF -- "fork of $INST @" <<<"$LS_OUT" || fail "ast ls does not say where the forks came from"
grep -qF -- "A: rewrite the parser" <<<"$LS_OUT" || fail "ast ls does not carry the --each note"
ok "ast ls says where each fork came from and what it was told to try"

# ---- each fork is its own machine ------------------------------------------
for n in 1 2 3; do
  HOST="$(guest "$INST-$n" "hostname" | tr -d '\r')"
  [ "$HOST" = "$INST-$n" ] || fail "$INST-$n reports hostname \"$HOST\", not its own"
  NOTE="$(guest "$INST-$n" "cat /work/.asterism-fork-note" | tr -d '\r')"
  [ -n "$NOTE" ] || fail "$INST-$n was not given its --each note"
  echo "  $INST-$n: hostname $HOST, note \"$NOTE\""
done
ok "every fork has its own hostname and its own copy of what it was told to try"

# ---- shared cache, private memory (AST-158 lifecycles) ---------------------
expect "fork 1 warms the shared cache" warmed \
  guest "$INST-1" "echo warm-from-1 > /cache/pkg && sync && echo warmed"
expect "fork 2 sees what fork 1 put in the shared cache" warm-from-1 \
  guest "$INST-2" "cat /cache/pkg"
if [ ! -f "$CACHE/pkg" ]; then
  fail "the shared cache is not the host directory the parent was pointed at"
fi
expect "the parent sees it too" warm-from-1 guest "$INST" "cat /cache/pkg"
ok "a cache volume is one directory the parent and every fork share"

expect "fork 1 writes to its own memory" noted1 \
  guest "$INST-1" "echo from-1 > /memory/notes && sync && echo noted1"
expect "fork 2 writes to its own memory" noted2 \
  guest "$INST-2" "echo from-2 > /memory/notes && sync && echo noted2"
expect "fork 1's memory is still fork 1's" from-1 guest "$INST-1" "cat /memory/notes"
if grep -qF from-1 "$BRAIN/notes" 2>/dev/null || grep -qF from-2 "$BRAIN/notes" 2>/dev/null; then
  fail "a fork's memory reached the parent's own memory volume"
fi
ok "a memory volume is copied, so each fork remembers only what it did"

# Each fork's /work is its own directory: writing in one must not appear in
# another, nor on the parent's share.
expect "fork 1 edits the parser" done1 \
  guest "$INST-1" "printf 'ONE\ntwo\nthree\nfour\nfive\nsix\n' > /work/parser.txt && sync && echo done1"
expect "fork 2 edits both files" done2 \
  guest "$INST-2" "printf 'one\ntwo\nTHREE\nfour\nfive\n' > /work/parser.txt && printf 'alpha\nBETA\ngamma\n' > /work/token.txt && printf 'new\n' > /work/fallback.txt && sync && echo done2"
expect "fork 3 adds a file" done3 \
  guest "$INST-3" "printf 'plan c\n' > /work/plan-c.txt && sync && echo done3"

if grep -qF ONE "$WORK/parser.txt"; then
  fail "fork 1's edit reached the parent's own /work"
fi
if [ -e "$WORK/fallback.txt" ]; then
  fail "fork 2's new file reached the parent's own /work"
fi
if [ -e "$WORK/plan-c.txt" ]; then
  fail "fork 3's new file reached the parent's own /work"
fi
ok "each fork writes into its own /work and nobody else's"

# ---- what each one changed -------------------------------------------------
for n in 1 2 3; do
  DIFF_OUT="$("$AST" diff "$INST-$n" 2>&1)" || fail "ast diff $INST-$n failed:"$'\n'"$DIFF_OUT"
  printf '%s\n' "$DIFF_OUT" >>"$EVIDENCE/diff.txt"
  echo "--- ast diff $INST-$n"
  printf '%s\n' "$DIFF_OUT"
  grep -qE '^/work: [0-9]+ files? changed, \+[0-9]+' <<<"$DIFF_OUT" \
    || fail "ast diff $INST-$n did not summarise /work:"$'\n'"$DIFF_OUT"
  grep -qF -- "vs $INST @" <<<"$DIFF_OUT" \
    || fail "ast diff $INST-$n did not say what it compared against:"$'\n'"$DIFF_OUT"
done
"$AST" diff "$INST-2" 2>&1 | grep -qF "3 files changed" \
  || fail "ast diff $INST-2 did not count the three files fork 2 touched"
ok "every fork's diff is its own, counted against the fork point"

refuses "diffing something that is not a fork says what to do instead" "--against" \
  "$AST" diff "$INST"

# ---- picking a winner ------------------------------------------------------
refuses "picking something that is not a fork is refused" "is not a fork" \
  "$AST" pick "$INST"

PICK_OUT="$("$AST" pick "$INST-2" --yes 2>&1)" || fail "the pick failed:"$'\n'"$PICK_OUT"
printf '%s\n' "$PICK_OUT" >"$EVIDENCE/pick.txt"
echo "--- ast pick $INST-2 --yes"
printf '%s\n' "$PICK_OUT"
grep -qF -- "$INST" <<<"$PICK_OUT" || fail "the pick did not name the parent"
grep -qF -- "/work replaced" <<<"$PICK_OUT" || fail "the pick did not say what it replaced"
grep -qF -- "$INST-1" <<<"$PICK_OUT" || fail "the pick did not name the siblings it removed"
grep -qF -- "before-pick" <<<"$PICK_OUT" || fail "the pick did not name its own undo"
ok "the pick named the parent, the volume, the siblings and the undo"

expect "the parent is running after the pick" "running" "$AST" status "$INST"
expect "the parent now holds fork 2's parser" THREE guest "$INST" "cat /work/parser.txt"
expect "the parent now holds fork 2's new file" new guest "$INST" "cat /work/fallback.txt"
grep -qF THREE "$WORK/parser.txt" || fail "the picked /work is not visible on the host share"
ok "bot-2's work is on bot, on both sides of the share"

LS_AFTER="$("$AST" ls 2>&1)"
printf '%s\n' "$LS_AFTER" >"$EVIDENCE/ls-after-pick.txt"
if grep -qE "^$INST-1 " <<<"$LS_AFTER"; then
  fail "$INST-1 survived the pick"
fi
if grep -qE "^$INST-3 " <<<"$LS_AFTER"; then
  fail "$INST-3 survived the pick"
fi
if ! grep -qE "^$INST-2 " <<<"$LS_AFTER"; then
  fail "$INST-2 was removed; the winner is meant to survive"
fi
ok "the siblings are gone and the winner is still here"

expect "before-pick is on the parent's timeline" "before-pick" "$AST" rewind "$INST"

# ---- and it is undoable ----------------------------------------------------
UNDO_OUT="$("$AST" rewind "$INST" --to before-pick 2>&1)" \
  || fail "undoing the pick failed:"$'\n'"$UNDO_OUT"
printf '%s\n' "$UNDO_OUT" >"$EVIDENCE/undo.txt"
echo "--- ast rewind $INST --to before-pick"
printf '%s\n' "$UNDO_OUT"
expect "the parent is running after the undo" "running" "$AST" status "$INST"
UNDONE="$(guest "$INST" "cat /work/parser.txt" | tr -d '\r')"
if grep -qF THREE <<<"$UNDONE"; then
  fail "the undo did not put the parent's own /work back:"$'\n'"$UNDONE"
fi
if ! grep -qF three <<<"$UNDONE"; then
  fail "the undo left /work as neither state:"$'\n'"$UNDONE"
fi
ok "ast rewind --to before-pick put the parent's own /work back"

printf 'df around the whole fork of %s into 3: %s KiB (noisy — includes three\nguest boots and any other writer on this filesystem; has come out negative)\nast fork wall clock: %s ms\nthe honest clone cost is the figure ast fork prints for itself\n' \
  "$INST" "$GROWTH_KB" "$WALL_MS" >"$EVIDENCE/cost.txt"

expect "stop the completed fork lane" "$INST  stopped" "$AST" down "$INST"
echo "FORK E2E GREEN ($IMAGE, $BACKEND)"
