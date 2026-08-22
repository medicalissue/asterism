#!/usr/bin/env bash
# The harness's own suite.
#
# scripts/lib/harness.sh is where every operational suite in this tree gets
# its process handling, its bounds and its isolation. Nothing else tests it,
# and its failures are the quiet kind: a reaper that misses a pid leaves a
# daemon running and the suite still reports green; a reaper that is too
# broad kills a process it was never given, and the suite still reports
# green. So both directions are asserted here, on real processes.
#
# Hermetic and fast: no daemon, no guest, no network, nothing outside one
# temp directory. It runs on Linux as well as macOS, which is why every
# process it starts is `sleep`.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/asterism-harness-test.XXXXXX")"
# The library writes evidence somewhere; point it inside the sandbox so a run
# of this suite leaves nothing behind either.
export ASTERISM_TEST_ARTIFACTS="$WORK/artifacts"
export ASTERISM_TEST_CACHE="$WORK/cache"

# shellcheck source-path=SCRIPTDIR source=lib/harness.sh
. "$ROOT/scripts/lib/harness.sh"

STRAY=""
cleanup() {
  # This suite's own bystander, if an assertion left it running.
  [ -n "$STRAY" ] && kill -KILL "$STRAY" 2>/dev/null
  rm -rf "$WORK"
  return 0
}
trap cleanup EXIT

pass=0
fail() { echo "HARNESS-TEST FAIL: $*" >&2; exit 1; }
ok() { pass=$((pass + 1)); echo "ok: $*"; }

alive() { kill -0 "$1" 2>/dev/null; }

# A process started the way the harness's real targets are: a daemon put into
# the background from a subshell, so this shell is not its parent. That is
# what the reaper meets in practice, and it keeps job-control notices out of
# this suite's output.
# The redirection is not decoration: command substitution waits for every
# process holding the pipe open, and a backgrounded `sleep` that inherited
# stdout would hold it for two minutes.
spawn() { ( sleep 120 >/dev/null 2>&1 & printf '%s\n' "$!" ); }

harness_begin harness-test

# ---- 1. a bounded step that finishes is not touched -------------------------

harness_run 10 "a quick step" printf 'hello' || fail "a step that works was reported as failing"
[ "$HARNESS_OUT" = "hello" ] || fail "the step's output was lost: got \"$HARNESS_OUT\""
[ "$HARNESS_STATUS" -eq 0 ] || fail "a successful step reported status $HARNESS_STATUS"
ok "a bounded step that finishes keeps its output and its status"

# ---- 2. a bounded step that fails reports why --------------------------------

if harness_run 10 "a failing step" sh -c 'echo "the reason" >&2; exit 3'; then
  fail "a step that exited 3 was reported as passing"
fi
[ "$HARNESS_STATUS" -eq 3 ] || fail "expected status 3, got $HARNESS_STATUS"
grep -qF "the reason" <<<"$HARNESS_OUT" || fail "stderr was not captured: \"$HARNESS_OUT\""
ok "a bounded step that fails keeps its exit status and its stderr"

# ---- 3. a bounded step that hangs is stopped, and says so --------------------
#
# The whole reason for the bound: a suite that hangs in CI is a job cancelled
# with no output. 124 is `timeout(1)`'s spelling, kept even though macOS ships
# no such binary.

start="$(date +%s)"
if harness_run 2 "a hanging step" sleep 60; then
  fail "a step that hangs was reported as passing"
fi
elapsed=$(( $(date +%s) - start ))
[ "$HARNESS_STATUS" -eq 124 ] || fail "a stopped step reported $HARNESS_STATUS, not 124"
[ "$elapsed" -lt 30 ] || fail "the bound did not fire: the step ran for ${elapsed}s"
grep -qF "exceeded its 2s bound" <<<"$HARNESS_OUT" \
  || fail "a stopped step did not say why:"$'\n'"$HARNESS_OUT"
ok "a step past its bound is stopped in time and says which bound it was"

# ---- 4. reaping stops what this run owns ------------------------------------

owned="$(spawn)"
harness_own "$owned"
harness_reap
alive "$owned" && fail "an owned process survived the reaper"
ok "a process this run owns is stopped"

# ---- 5. ...and nothing else --------------------------------------------------
#
# The assertion the old `pkill -f` could not make. The bystander is started
# the same way, from the same shell, running the same program — the only
# difference is that the harness was never given it.

STRAY="$(spawn)"
mine="$(spawn)"
harness_own "$mine"
harness_reap
alive "$mine" && fail "an owned process survived the reaper"
alive "$STRAY" || fail "the reaper killed a process it was never given"
ok "a process this run does not own is left alone"
kill -KILL "$STRAY" 2>/dev/null || true
STRAY=""

# ---- 6. an already-dead pid is not an error ----------------------------------
#
# harness_reap runs from a cleanup trap, which can run twice and can run after
# a suite has already tidied up. Both have to be ordinary.

gone="$(spawn)"
kill -KILL "$gone" 2>/dev/null || true
harness_own "$gone"
harness_reap || fail "reaping an already-dead pid was an error"
harness_reap || fail "reaping twice was an error"
ok "reaping a pid that has already gone, or reaping twice, is not an error"

# ---- 7. the pids come out of the daemon's own records ------------------------
#
# What replaced `pkill -9 -f "$ASTERISM_HOME"`: the daemon writes down every
# process it starts, so the reaper reads that rather than matching command
# lines. This is the parser, on the shape the daemon actually writes.

home="$WORK/home"
mkdir -p "$home"
cat >"$home/state.json" <<'JSON'
{
  "instances": [
    {"name": "one", "handle": {"backend": "qemu", "pid": 4242,
      "proc": {"pid": 4242, "started_at": 17, "exe": "/x/qemu"}}},
    {"name": "two", "handle": {"backend": "vz", "pid": 4243}},
    {"name": "stopped", "handle": null}
  ]
}
JSON
cat >"$home/volumes.json" <<'JSON'
{"volumes": [{"name": "tank", "lease": {"holder": "one", "pid": 4244}}]}
JSON
found="$(harness_home_pids "$home" | sort -n | tr '\n' ' ')"
[ "$found" = "4242 4243 4244 " ] \
  || fail "the recorded pids came back as \"$found\", not \"4242 4243 4244 \""
ok "every pid the daemon recorded is found, guests and volume servers alike"

# A record that is half-written — which is exactly what a crash leaves — is
# nothing to stop, not a crash in the cleanup path.
printf '{"instances": [{"name": "one", "handle": {"pi' >"$home/state.json"
rm -f "$home/volumes.json"
[ -z "$(harness_home_pids "$home")" ] || fail "a truncated record produced pids"
ok "a half-written record yields nothing rather than failing the cleanup"

# And a home that was never created at all.
[ -z "$(harness_home_pids "$WORK/never")" ] || fail "a missing home produced pids"
harness_reap_home "$WORK/never" || fail "reaping a home that does not exist was an error"
ok "a home that does not exist is nothing to reap"

# ---- 8. the image cache is the harness's own, never the user's ---------------

case "$(harness_cache_dir)" in
  *"/.asterism"*) fail "the harness cache is inside the user's ~/.asterism" ;;
esac
[ "$(harness_cache_dir)" = "$WORK/cache" ] \
  || fail "ASTERISM_TEST_CACHE was ignored: $(harness_cache_dir)"
mkdir -p "$WORK/cache/images"
: >"$WORK/cache/images/base.qcow2"
seed="$WORK/seed"
mkdir -p "$seed"
harness_seed_images "$seed"
[ -f "$seed/images/base.qcow2" ] || fail "the cache did not seed a home"
ok "images come from the harness's cache, and it is not under ~/.asterism"

# An empty cache is a first run, not a failure.
empty="$WORK/empty-cache"
ASTERISM_TEST_CACHE="$empty" harness_seed_images "$WORK/seed2" \
  || fail "seeding from an empty cache was an error"
[ -d "$WORK/seed2/images" ] || fail "seeding did not make the image directory"
ok "an empty cache seeds nothing and fails nothing"

# Direct invocations do not share a machine-global diagnostics directory.
# The release-candidate runner overrides this deliberately so its suites are
# collected together; without that override, each shell owns its own path.
default_one="$(env -u ASTERISM_TEST_ARTIFACTS bash -c \
  '. scripts/lib/harness.sh; harness_artifacts_dir')"
default_two="$(env -u ASTERISM_TEST_ARTIFACTS bash -c \
  '. scripts/lib/harness.sh; harness_artifacts_dir')"
[ "$default_one" != "$default_two" ] \
  || fail "two direct runs would share diagnostics at $default_one"
case "$default_one" in
  *asterism-harness-artifacts-[0-9]*) ;;
  *) fail "the default diagnostics path is not run-owned: $default_one" ;;
esac
ok "direct runs get separate diagnostics directories"

# ---- 9. evidence is copied out before the home it lives in goes --------------

mkdir -p "$home/instances/one"
printf 'daemon said this\n' >"$home/astd.log"
printf 'the guest said this\n' >"$home/instances/one/console.log"
harness_keep_home "$home" kept
rm -rf "$home"
grep -qF "daemon said this" "$ASTERISM_TEST_ARTIFACTS/harness-test/kept/astd.log" \
  || fail "the daemon log was not preserved"
grep -qF "the guest said this" \
  "$ASTERISM_TEST_ARTIFACTS/harness-test/kept/instances/one/console.log" \
  || fail "the guest console log was not preserved"
ok "a home's logs outlive the home"

# ---- 10. build ids are compared, not assumed --------------------------------
#
# Two stand-ins for `ast version`, because what is being tested is the
# comparison and not the binary.

mkdir -p "$WORK/bin"
make_ast() {
  cat >"$WORK/bin/$1" <<EOF
#!/bin/sh
echo "version   0.0.2"
echo "build     $2"
echo "artifact  sha256:00  /nowhere"
EOF
  chmod +x "$WORK/bin/$1"
}
make_ast one 0.0.2+aaaaaaaaaaaa
make_ast two 0.0.2+aaaaaaaaaaaa
make_ast odd 0.0.2+bbbbbbbbbbbb

[ "$(harness_build_id "$WORK/bin/one")" = "0.0.2+aaaaaaaaaaaa" ] \
  || fail "the build id was not read"
same="$(harness_assert_same_build "$WORK/bin/one" "$WORK/bin/two")" \
  || fail "two binaries of the same build were reported as different"
[ "$same" = "0.0.2+aaaaaaaaaaaa" ] || fail "the agreed build came back as \"$same\""
if harness_assert_same_build "$WORK/bin/one" "$WORK/bin/odd" >/dev/null 2>&1; then
  fail "two binaries of different builds were reported as the same"
fi
ok "binaries are compared by build id, and a mismatch is caught"

# A binary that says nothing about its build is a mismatch of its own kind:
# it cannot be shown to be the right one.
printf '#!/bin/sh\necho "ast 0.0.2"\n' >"$WORK/bin/mute"
chmod +x "$WORK/bin/mute"
if harness_build_id "$WORK/bin/mute" >/dev/null 2>&1; then
  fail "a binary that reports no build id was accepted"
fi
ok "a binary that will not say which build it is, is not accepted as any"

echo "HARNESS-TEST GREEN ($pass assertions)"
