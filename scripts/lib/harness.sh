# shellcheck shell=bash
# The parts every operational suite in this tree needs, and the reasons the
# obvious spellings of them are wrong.
#
# Source it, do not run it:
#
#   . "$(dirname "$0")/lib/harness.sh"
#   harness_begin lifecycle
#
# It deliberately defines nothing called `ok`, `fail` or `expect`. Every
# suite here already has its own, worded for what it is proving, and a
# library that renamed them would be a rewrite pretending to be a refactor.
# Everything below is prefixed `harness_`.
#
# ---- the three machine-global habits this exists to end --------------------
#
# 1. `pkill -f <path>` matches by command line, and a command line is not an
#    identity. Two checkouts of this repository build astd at paths that
#    share a prefix; a developer running one against their real home is
#    matched by a test's cleanup, and their guests die. Worse, it is silent:
#    the test passes. `harness_own` records a pid the run is responsible for
#    and `harness_reap` stops those and nothing else.
#
# 2. Seeding a scratch home from `~/.asterism/images` reaches into the state
#    the user is running their own instances out of. It is only a read today,
#    but it is a read of a directory a daemon writes to concurrently, and a
#    half-written qcow2 copied out of it fails a test for a reason nobody can
#    reproduce. `harness_seed_images` copies from a cache that belongs to the
#    harness, which the harness is also allowed to fill.
#
# 3. A step with no bound does not fail, it hangs — and a suite that hangs in
#    CI is a job that gets cancelled twenty minutes later with no output
#    worth reading. `harness_run` bounds one command and keeps what it said.
#
# ---- diagnostics -----------------------------------------------------------
#
# Anything worth looking at after a failure has to be copied out before the
# cleanup trap deletes the home it lives in. `harness_keep_home` does that,
# and it is called from a suite's own cleanup — first, before the `rm -rf`,
# because by the time the trap is running the failure has already happened
# and the directory is about to stop existing.

# Where this library and the helpers beside it live. Resolved from the
# library's own path rather than from the caller's, so a suite in any
# directory finds them.
HARNESS_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Fail loudly if this got run instead of sourced: the `set -e` and the traps
# below would apply to a shell that exits immediately, which would look like
# a suite that passed.
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
  echo "harness.sh is a library — source it, do not run it" >&2
  exit 2
fi

# Where the harness keeps images between runs. Never `~/.asterism`: that is
# the user's own state, written by their own daemon. This one is ours to
# fill, ours to read, and safe to delete.
harness_cache_dir() {
  printf '%s\n' "${ASTERISM_TEST_CACHE:-${HOME}/.cache/asterism-harness}"
}

# The directory a failing suite leaves its evidence in. Overridable so a
# runner can collect every suite's under one root and upload the lot.
harness_artifacts_dir() {
  # A direct suite run gets a directory owned by that one shell. Without the
  # pid, two lifecycle runs both called their evidence `.../lifecycle`, and
  # the second one's harness_begin removed the first one's diagnostics.
  local base="${ASTERISM_TEST_ARTIFACTS:-${TMPDIR:-/tmp}/asterism-harness-artifacts-$$}"
  # $TMPDIR ends in a slash on macOS, and a path printed with two of them in
  # the middle reads as a bug in whatever printed it.
  printf '%s\n' "${base%/}"
}

# ---- one suite's lifetime --------------------------------------------------

HARNESS_SUITE=""
HARNESS_OWNED_PIDS=""
HARNESS_OWNED_HOMES=""
HARNESS_ARTIFACTS=""
# Combined output of the last `harness_run`, and how it ended.
HARNESS_OUT=""
HARNESS_STATUS=0

# <suite-name>: name this run and make it somewhere to put evidence. Call it
# once, early, before anything is started.
#
# It installs no trap. A suite's cleanup is its own — it has instances to
# take down and directories to remove in an order only it knows — so what
# this library offers is the pieces that go inside one (`harness_keep_home`,
# `harness_reap`, `harness_artifacts_note`), not a trap that would run beside
# the suite's and race it.
harness_begin() {
  HARNESS_SUITE="$1"
  HARNESS_ARTIFACTS="$(harness_artifacts_dir)/$HARNESS_SUITE"
  rm -rf "$HARNESS_ARTIFACTS"
  mkdir -p "$HARNESS_ARTIFACTS"
  # Deliberately does not touch ASTERISM_MESH. Most suites want `local` and
  # set it themselves; e2e-discovery.sh wants it *unset*, because what it is
  # proving is what an unconfigured device does. A library that helpfully set
  # a default here would silently delete that suite's subject.
}

# <pid>: this run started it, so this run stops it. A non-numeric or empty
# argument is ignored, because the usual caller is a `$(cat some.pid)` that
# may have found nothing.
harness_own() {
  local pid="${1:-}"
  case "$pid" in
    '' | *[!0-9]*) return 0 ;;
  esac
  case " $HARNESS_OWNED_PIDS " in
    *" $pid "*) return 0 ;;
  esac
  HARNESS_OWNED_PIDS="$HARNESS_OWNED_PIDS $pid"
}

# <home>: an ASTERISM_HOME whose daemon this run started. The pid is read
# from the home's own `astd.pid` at reap time rather than now, because a
# daemon that was restarted mid-suite has a different pid than the one that
# was started — and it is the current one that has to be stopped.
harness_own_home() {
  local home="${1:-}"
  [ -n "$home" ] || return 0
  case " $HARNESS_OWNED_HOMES " in
    *" $home "*) return 0 ;;
  esac
  HARNESS_OWNED_HOMES="$HARNESS_OWNED_HOMES $home"
}

# <pid>: has it stopped running?
#
# `kill -0` alone answers a different question. A process that has exited and
# has not been waited for still answers it: that is a zombie, a slot in the
# process table holding an exit status, running nothing. A suite that
# backgrounds a daemon and does not reap it leaves exactly that behind, and a
# reaper that believed `kill -0` would escalate to SIGKILL against a process
# that had already done as it was asked. The kernel's own view of the process
# state is what distinguishes them — the same distinction `ProcId::check`
# makes in the daemon, for the same reason.
harness_gone() {
  local pid="$1" state
  kill -0 "$pid" 2>/dev/null || return 0
  state="$(ps -o state= -p "$pid" 2>/dev/null | tr -d ' ')"
  case "$state" in
    '') return 0 ;;
    Z*) return 0 ;;
  esac
  return 1
}

# <pid> <ticks>: has it gone within ticks * 0.2s?
harness_wait_gone() {
  local pid="$1" budget="${2:-25}" _i
  for _i in $(seq 1 "$budget"); do
    harness_gone "$pid" && return 0
    sleep 0.2
  done
  return 1
}

# Ask, wait, insist. Bounded at each step, and idempotent: a pid that is
# already gone is a success, which is what makes this safe in a trap that can
# run twice.
harness_stop() {
  local pid="${1:-}" budget="${2:-25}"
  case "$pid" in
    '' | *[!0-9]*) return 0 ;;
  esac
  harness_gone "$pid" && return 0
  kill -TERM "$pid" 2>/dev/null || true
  harness_wait_gone "$pid" "$budget" && return 0
  kill -KILL "$pid" 2>/dev/null || true
  harness_wait_gone "$pid" 10 || true
}

# <home>: every pid one home's daemon wrote down as a process it started.
#
# This is the exact replacement for `pkill -9 -f "$ASTERISM_HOME"`. That
# spelling matched command lines, so it reached anything that merely
# mentioned the path — an editor with the state file open, a `tail` on a
# console log, a sibling script naming the same directory — and it reached
# them with SIGKILL. What it was reaching *for* is written down: the daemon
# records the pid of every guest it boots on the instance's handle, and the
# pid of every volume server on the lease. Reading them back asks the product
# what it started instead of asking the process table what looks similar.
harness_home_pids() {
  local home="$1"
  local f
  for f in "$home/state.json" "$home/volumes.json"; do
    [ -f "$f" ] || continue
    python3 "$HARNESS_LIB_DIR/recorded-pids.py" "$f" 2>/dev/null || true
  done
}

# <home>: stop that home's daemon and everything it recorded starting.
#
# Order matters. The daemon goes first, so that nothing restarts a guest
# while the guests are being stopped — `--restart always` is a real setting
# and a supervisor racing a teardown is a flaky suite.
harness_reap_home() {
  local home="$1" pid f
  [ -d "$home" ] || return 0
  harness_stop "$(cat "$home/astd.pid" 2>/dev/null || true)"
  # Every VMM backend leaves its guest alive when astd exits.
  # Their pidfiles are independent of a daemon flush, so consume them before
  # the registry fallback below. The paths are inside this owned home: this
  # is precise ownership, never a process-table pattern match.
  for f in "$home"/instances/*/qemu.pid "$home"/instances/*/vz.pid \
    "$home"/instances/*/chv.pid; do
    [ -f "$f" ] || continue
    harness_stop "$(cat "$f" 2>/dev/null || true)"
    rm -f "$f"
  done
  for pid in $(harness_home_pids "$home"); do
    harness_stop "$pid"
  done
  return 0
}

# Stop everything this run owns, and nothing else. Safe to call more than
# once; safe to call when nothing was ever started.
harness_reap() {
  local home pid
  for home in $HARNESS_OWNED_HOMES; do
    harness_reap_home "$home"
  done
  for pid in $HARNESS_OWNED_PIDS; do
    harness_stop "$pid"
  done
  HARNESS_OWNED_PIDS=""
  HARNESS_OWNED_HOMES=""
}

# ---- a suite that cannot run here ------------------------------------------

# 77, which is what autotools test suites have meant by "skipped" for thirty
# years. A suite that refuses to run because this machine is not the right
# machine has not failed, and a runner that could not tell the two apart
# would either report red on a healthy tree or swallow real failures to
# avoid it.
HARNESS_SKIP_STATUS=77

# <reason>: this machine cannot run this suite. Says so and stops.
harness_skip() {
  echo "skipped: $*" >&2
  exit "$HARNESS_SKIP_STATUS"
}

# ---- the binaries under test -----------------------------------------------

# <repo-root>: set AST and ASTD to the pair this run is exercising.
#
# The default is this tree's debug build, which is what a developer wants.
# `AST_BIN` points the same suite at a different pair, and that is the whole
# point of the variable: a release-candidate run installs the published
# artifact into a prefix of its own and runs these suites against *that*, so
# what gets proved is the thing users receive rather than a build that
# happens to share its source. `astd` is taken from beside `ast` — that is
# where `ast` itself looks for it, so anything else would be testing a pair
# that cannot occur.
harness_binaries() {
  local root="$1"
  if [ -n "${AST_BIN:-}" ]; then
    AST="$AST_BIN"
    ASTD="${ASTD_BIN:-$(dirname "$AST_BIN")/astd}"
    [ -x "$AST" ] || { echo "harness: AST_BIN=$AST is not executable" >&2; return 1; }
    [ -x "$ASTD" ] || { echo "harness: no executable astd beside $AST" >&2; return 1; }
  else
    ( cd "$root" && cargo build -q ) || return 1
    # Keep the binaries under test paired with the cargo invocation above.
    # Worktrees commonly share a target cache through CARGO_TARGET_DIR; using
    # a hard-coded tree-local path after Cargo wrote elsewhere either runs a
    # stale build or claims the freshly built binaries do not exist.
    local target_dir="${CARGO_TARGET_DIR:-$root/target}"
    case "$target_dir" in
      /*) ;;
      *) target_dir="$root/$target_dir" ;;
    esac
    AST="$target_dir/debug/ast"
    ASTD="$target_dir/debug/astd"
  fi
  export AST ASTD
}

# ---- bounded steps ---------------------------------------------------------

# <pid>: wait for a background job without the shell announcing how it died.
#
# When the watchdog below fires, bash prints its own "Terminated: 15" line for
# the job — on the shell's stderr, in the middle of a suite's output, saying
# nothing the bounded-step message that follows does not say better. The
# redirection is around `wait` and nothing else, so a real error from the
# command itself is untouched: that went to the capture file long before.
harness_wait() {
  local status=0
  { wait "$1" || status=$?; } 2>/dev/null
  return "$status"
}

# <seconds> <label> <cmd...>: run it with a bound, keep what it said.
#
# Sets HARNESS_OUT to the combined output and HARNESS_STATUS to the exit
# status; returns that status, so it composes with `||` and with `set -e`.
# On expiry the status is 124 — `timeout(1)`'s spelling, which is not on a
# stock macOS but whose convention is worth keeping — and the output carries
# a line saying so, because a bounded step that failed silently reads exactly
# like one that failed on its merits.
#
# The bound covers the direct child. A daemon the command started outlives it
# and is stopped by `harness_reap`, which is the right division: this bounds
# a step, that owns a process.
harness_run() {
  local secs="$1" label="$2"
  shift 2
  local out
  out="$(mktemp "${TMPDIR:-/tmp}/harness-run.XXXXXX")"

  "$@" >"$out" 2>&1 &
  local child=$!

  # The watchdog is a plain subshell rather than a `timeout` binary: macOS
  # ships none, and requiring coreutils to run the suite would put the
  # harness's own dependency between a developer and their first green run.
  (
    sleep "$secs"
    kill -TERM "$child" 2>/dev/null || true
    sleep 2
    kill -KILL "$child" 2>/dev/null || true
  ) >/dev/null 2>&1 &
  local watchdog=$!

  HARNESS_STATUS=0
  harness_wait "$child" || HARNESS_STATUS=$?
  kill "$watchdog" 2>/dev/null || true
  harness_wait "$watchdog" || true

  HARNESS_OUT="$(cat "$out")"
  rm -f "$out"

  # 143 is SIGTERM, which here means the watchdog fired: nothing else in
  # these suites terminates a step politely.
  if [ "$HARNESS_STATUS" -eq 143 ] || [ "$HARNESS_STATUS" -eq 137 ]; then
    HARNESS_OUT="$HARNESS_OUT
harness: ${label} exceeded its ${secs}s bound and was stopped"
    HARNESS_STATUS=124
  fi
  return "$HARNESS_STATUS"
}

# <seconds> <label> <cmd...>: the same bound, output straight to the terminal.
# For a long suite, where watching it is the point and capturing it is not.
harness_run_live() {
  local secs="$1" label="$2"
  shift 2
  "$@" &
  local child=$!
  (
    sleep "$secs"
    kill -TERM "$child" 2>/dev/null || true
    sleep 5
    kill -KILL "$child" 2>/dev/null || true
  ) >/dev/null 2>&1 &
  local watchdog=$!
  HARNESS_STATUS=0
  harness_wait "$child" || HARNESS_STATUS=$?
  kill "$watchdog" 2>/dev/null || true
  harness_wait "$watchdog" || true
  if [ "$HARNESS_STATUS" -eq 143 ] || [ "$HARNESS_STATUS" -eq 137 ]; then
    echo "harness: ${label} exceeded its ${secs}s bound and was stopped" >&2
    HARNESS_STATUS=124
  fi
  return "$HARNESS_STATUS"
}

# ---- evidence --------------------------------------------------------------

# <path> [name]: copy something out of a scratch home before the home goes.
# Missing paths are skipped in silence — a suite that failed before it wrote
# a console log should report the failure, not an error about the log.
harness_keep() {
  local src="$1" name="${2:-}"
  [ -e "$src" ] || return 0
  [ -n "$HARNESS_ARTIFACTS" ] || return 0
  [ -n "$name" ] || name="$(basename "$src")"
  cp -R "$src" "$HARNESS_ARTIFACTS/$name" 2>/dev/null || true
}

# <home> [label]: everything one scratch home has to say. Called from a
# cleanup trap, so every step is best-effort and none of them can fail the
# run they are trying to explain.
harness_keep_home() {
  local home="$1" label="${2:-$(basename "$1")}"
  [ -d "$home" ] || return 0
  [ -n "$HARNESS_ARTIFACTS" ] || return 0
  local dest="$HARNESS_ARTIFACTS/$label"
  mkdir -p "$dest"
  local f
  for f in "$home"/*.log "$home"/*.out "$home"/state.json "$home"/astd.pid; do
    [ -e "$f" ] && cp -R "$f" "$dest/" 2>/dev/null
  done
  # An instance's console log is the one file that says why a guest did not
  # come up, and it is the first thing anyone asks for.
  if [ -d "$home/instances" ]; then
    local inst
    for inst in "$home"/instances/*/; do
      [ -d "$inst" ] || continue
      local name
      name="$(basename "$inst")"
      mkdir -p "$dest/instances/$name"
      for f in "$inst"console.log "$inst"*.json "$inst"*.log; do
        [ -e "$f" ] && cp "$f" "$dest/instances/$name/" 2>/dev/null
      done
    done
  fi
  return 0
}

# Say where the evidence went, because a path nobody was told about is a path
# nobody looks in.
#
# Worded as "kept" rather than "diagnostics": this runs from a cleanup trap,
# which runs on a green run too, and a green run that announces diagnostics
# reads as one that found something.
harness_artifacts_note() {
  [ -n "$HARNESS_ARTIFACTS" ] || return 0
  # An empty directory is not evidence and saying otherwise sends people to
  # look at nothing.
  if [ -n "$(ls -A "$HARNESS_ARTIFACTS" 2>/dev/null)" ]; then
    echo "kept: $HARNESS_ARTIFACTS" >&2
  fi
}

# ---- images ----------------------------------------------------------------

# <home>: fill a scratch home's image store from the harness cache.
#
# Never from `~/.asterism`. The cache is a home of the harness's own —
# `harness_cache_image` pulls into it with the binary under test — so what is
# copied here was fetched and verified by the product, into a directory no
# daemon of the user's is writing to.
harness_seed_images() {
  local home="$1" cache
  cache="$(harness_cache_dir)/images"
  mkdir -p "$home/images"
  [ -d "$cache" ] || return 0
  # The whole store, not a glob of the two extensions somebody remembered.
  # A base image is not one file: beside `debian-13.raw` sits the provenance
  # record naming the publisher digest it was verified against, and an OCI
  # image is a directory of blobs and a kernel. Copying two extensions leaves
  # an image that looks present and is not adoptable, so every run
  # re-downloads a gigabyte and the cache silently buys nothing.
  #
  # `cp -c` clones instead of copying — one APFS metadata operation for a
  # three-gigabyte base image rather than three gigabytes of reads and
  # writes. It is macOS-only and it fails on a filesystem that cannot clone,
  # hence the fallback rather than a hard dependency.
  cp -Rc "$cache/." "$home/images/" 2>/dev/null ||
    cp -R "$cache/." "$home/images/" 2>/dev/null ||
    true
  return 0
}

# <ast-binary> <image>: make sure the harness cache holds an image, pulling
# it with the binary under test if it does not.
#
# The cache directory *is* an ASTERISM_HOME, so the pull lands in it directly
# and nothing is copied to get it there. The earlier shape — a separate pull
# home, copied in and copied back — moved six gigabytes per call to cache
# three, which took longer than the download it was meant to avoid.
#
# One home, so one pull at a time: suites are run in sequence by
# scripts/rc.sh, and two of these racing would be two daemons on one socket.
harness_cache_image() {
  local ast="$1" image="$2" cache status=0
  cache="$(harness_cache_dir)"
  mkdir -p "$cache/images"
  ASTERISM_HOME="$cache" ASTERISM_MESH=local "$ast" pull "$image" >/dev/null 2>&1 || status=1
  # The daemon the pull started belongs to the cache, not to a suite, and
  # leaving it running would leave a daemon holding the user's cache open
  # long after the suite that filled it has gone.
  harness_stop "$(cat "$cache/astd.pid" 2>/dev/null || true)"
  return "$status"
}

# ---- assertions the suites share ------------------------------------------

# <ast> <instance> <backend>: the guest is running, and it is running on the
# backend that was asked for.
#
# Spelled out rather than inferred from "it booted": both backends boot the
# same image, so a request for vz that silently fell through to qemu passes
# every other assertion in a lifecycle suite. `ast status` names the backend
# on its `running:` line, which is the only place the two are distinguishable
# from outside.
harness_assert_backend() {
  local ast="$1" inst="$2" want="$3" line
  line="$("$ast" status "$inst" 2>&1 | sed -n 's/^running: \([a-z][a-z]*\) .*/\1/p')"
  if [ -z "$line" ]; then
    echo "harness: ${inst} is not running, so no backend can be asserted" >&2
    return 1
  fi
  if [ "$line" != "$want" ]; then
    echo "harness: ${inst} is running on ${line}, not ${want}" >&2
    return 1
  fi
  return 0
}

# <binary...>: every binary named reports the same build id, or say which
# ones did not.
#
# This is the assertion the whole exact-artifact idea rests on: `ast`, `astd`
# and the app are built together and shipped apart, and a machine running two
# of the three from different builds is the failure that produces the least
# comprehensible bug reports.
harness_assert_same_build() {
  local first="" first_bin="" bin id
  for bin in "$@"; do
    id="$(harness_build_id "$bin")" || return 1
    if [ -z "$first" ]; then
      first="$id"
      first_bin="$bin"
      continue
    fi
    if [ "$id" != "$first" ]; then
      echo "harness: ${bin} is build ${id}, but ${first_bin} is build ${first}" >&2
      return 1
    fi
  done
  printf '%s\n' "$first"
}

# <ast> <astd-vz>: the installed VZ helper is part of this exact build and
# carries a valid signature with the entitlement the framework requires.
#
# This is deliberately one assertion rather than three optional observations.
# A release with no helper cannot exercise VZ; a helper from another build is
# not the artifact under test; and an unsigned or unentitled helper cannot
# create a VZVirtualMachine. Any one of those makes an exact-artifact VZ lane
# unavailable, which is a failed release candidate rather than a reason to
# substitute a binary from the source tree.
harness_assert_vz_helper() {
  local ast="$1" helper="$2" ast_build helper_build
  if [ ! -x "$helper" ]; then
    echo "harness: the installed artifact has no executable astd-vz at $helper" >&2
    return 1
  fi
  ast_build="$(harness_build_id "$ast")" || return 1
  helper_build="$(harness_build_id "$helper" --version)" || return 1
  if [ "$helper_build" != "$ast_build" ]; then
    echo "harness: ${helper} is build ${helper_build}, but ${ast} is build ${ast_build}" >&2
    return 1
  fi
  command -v codesign >/dev/null 2>&1 || {
    echo "harness: codesign is required to verify the installed astd-vz" >&2
    return 1
  }
  codesign --verify --strict "$helper" >/dev/null 2>&1 || {
    echo "harness: the installed astd-vz does not have a valid code signature" >&2
    return 1
  }
  codesign -d --entitlements - "$helper" 2>&1 |
    grep -q 'com.apple.security.virtualization' || {
      echo "harness: the installed astd-vz has no virtualization entitlement" >&2
      return 1
    }
  printf '%s\n' "$helper_build"
}

# <binary> [identity-command]: the build id it reports, or nothing. `ast`
# uses the `version` subcommand; the helper uses `--version` because it has no
# user-facing subcommands of its own.
harness_build_id() {
  local binary="$1" command="${2:-version}" out
  out="$("$binary" "$command" 2>/dev/null | sed -n 's/^build  *//p')"
  if [ -z "$out" ]; then
    echo "harness: $binary does not report a build id" >&2
    return 1
  fi
  printf '%s\n' "$out"
}
