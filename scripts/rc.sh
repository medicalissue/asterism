#!/usr/bin/env bash
# The release-candidate run: install the exact artifact users will get, then
# operate it.
#
#   scripts/rc.sh                     # what runs anywhere, including CI
#   scripts/rc.sh --all               # everything this device can run
#   scripts/rc.sh lifecycle vz        # named suites
#   scripts/rc.sh --artifact dist     # a release directory built elsewhere
#   scripts/rc.sh --list              # the suites, and what each one needs
#
# ---- why an artifact and not a cargo build ---------------------------------
#
# Everything else in scripts/ runs `target/debug/ast`. That proves the source
# works. It does not prove the *release* works, and the gap between them is
# where release bugs live: a `--release` build with different optimisation
# behaviour, a tarball missing a binary, a helper that lost its code
# signature on the way through tar, an installer that put the pair in a
# directory nothing is going to look in.
#
# So this builds (or takes) a release directory — tarball plus SHA256SUMS,
# exactly what a publish uploads — checks the tarball against the digest
# beside it, installs it with the script users pipe into sh, and runs the
# suites against the installed pair. `AST_BIN` is how a suite is pointed at
# it; every suite in this tree honours that (scripts/lib/harness.sh).
#
# ---- what "exact" is checked against ---------------------------------------
#
# Two independent claims, and both are checked, because either alone can be
# satisfied by the wrong thing:
#
#   * the BYTES are the published bytes — the sha256 of what landed in the
#     prefix appears in the SHA256SUMS that came with it;
#   * the BUILD is one build — `ast`, `astd`, the vz helper and, when it is
#     installed, the desktop app all report the same immutable build id. A
#     tarball assembled from two builds passes a digest check and fails this
#     one.
#
# The cache the image lanes pull through is shared between runs and lives
# under ~/.cache, not ~/.asterism: a base image is a gigabyte and a harness
# that re-downloads one per suite is a harness nobody runs.
#
# ---- isolation -------------------------------------------------------------
#
# Nothing here touches ~/.asterism, ~/.local, or a daemon that was already
# running. The prefix and every suite's home are under directories this run
# made, and the image cache is the harness's own. Every process is stopped by
# the pid its own daemon wrote down, never by matching a command line.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export PATH="$HOME/.cargo/bin:$PATH"
cd "$ROOT"

# shellcheck source-path=SCRIPTDIR source=lib/harness.sh
. "$ROOT/scripts/lib/harness.sh"

# ---- the suites ------------------------------------------------------------
#
# One row each: name, what it needs, its bound in seconds, and the command.
# The bound is not a guess at how long it takes — it is the point past which
# a run has stopped making progress and should be killed with its logs
# intact, which is the difference between a failing suite and a cancelled CI
# job with nothing in it.
#
# NEEDS is what the row cannot run without:
#   any    — runs on any machine, and is what CI runs
#   vm     — boots a real guest, so it needs a hypervisor this device can use
#   net    — talks to a public relay, so it needs working internet
#   helper — needs a signed, entitled `astd-vz` from the installed artifact,
#            with the same build id as ast. Absence or mismatch is red.
#   gui    — the desktop app has to have been built
SUITES="
identity   any    180   rc_suite_identity
install    any    900   bash scripts/install-test.sh
unit       any    2400  rc_suite_unit
lifecycle  vm     1500  bash scripts/e2e.sh
oci        vm     1200  bash scripts/e2e-oci.sh
durability vm     1200  bash scripts/e2e-durability.sh
persist    vm     1200  bash scripts/e2e-persist.sh
keys       vm     1200  bash scripts/e2e-keys.sh
vz         helper 1800  bash scripts/e2e-vz.sh
volume     vm     2400  bash scripts/e2e-volume.sh
move       vm     2400  bash scripts/e2e-move.sh
mesh       vm     2400  bash scripts/e2e-mesh.sh
discovery  net    900   bash scripts/e2e-discovery.sh
wake       net    900   bash scripts/e2e-wake.sh
gui        gui    1200  bash gui/proof.sh
"

# What runs with no suite named: everything that needs nothing. This is the
# set CI runs, and the set a contributor can run on any machine.
DEFAULT_SUITES="identity install unit"

usage() {
  cat <<'USAGE'
scripts/rc.sh [options] [suite ...]

  --artifact DIR   use a release directory built elsewhere, instead of
                   building one from this tree
  --version V      the version to build and install (default: the workspace's,
                   prefixed with v)
  --out DIR        where this run's prefix, homes and evidence go
  --all            every suite this device can run
  --list           print the suites and what each one needs
  --keep           leave the prefix and the run directory behind
  -h, --help       this

With no suite named, runs: identity install unit
USAGE
}

list_suites() {
  printf '%-11s %-6s %-7s %s\n' SUITE NEEDS BOUND RUNS
  local name needs bound rest
  while read -r name needs bound rest; do
    [ -n "$name" ] || continue
    printf '%-11s %-6s %-7s %s\n' "$name" "$needs" "${bound}s" "$rest"
  done <<<"$SUITES"
}

suite_field() {
  local want="$1" field="$2" name needs bound rest
  while read -r name needs bound rest; do
    [ "$name" = "$want" ] || continue
    case "$field" in
      needs) printf '%s\n' "$needs" ;;
      bound) printf '%s\n' "$bound" ;;
      runs) printf '%s\n' "$rest" ;;
    esac
    return 0
  done <<<"$SUITES"
  return 1
}

all_suites() {
  local name rest
  while read -r name rest; do
    [ -n "$name" ] || continue
    printf '%s\n' "$name"
  done <<<"$SUITES"
}

# ---- arguments -------------------------------------------------------------

ARTIFACT_DIR=""
VERSION=""
OUT=""
KEEP=""
WANTED=""

while [ $# -gt 0 ]; do
  case "$1" in
    --artifact) ARTIFACT_DIR="${2:?--artifact needs a directory}"; shift 2 ;;
    --version) VERSION="${2:?--version needs a version}"; shift 2 ;;
    --out) OUT="${2:?--out needs a directory}"; shift 2 ;;
    --all) WANTED="$(all_suites | tr '\n' ' ')"; shift ;;
    --list) list_suites; exit 0 ;;
    --keep) KEEP=1; shift ;;
    -h | --help) usage; exit 0 ;;
    -*) echo "rc: unknown option $1" >&2; usage >&2; exit 2 ;;
    *)
      suite_field "$1" needs >/dev/null || {
        echo "rc: no suite called \"$1\" — try --list" >&2
        exit 2
      }
      WANTED="$WANTED $1"
      shift
      ;;
  esac
done
[ -n "$WANTED" ] || WANTED="$DEFAULT_SUITES"

say() { printf '%s\n' "$*"; }
fail() { echo "RC FAIL: $*" >&2; exit 1; }

if [ -z "$VERSION" ]; then
  VERSION="v$(sed -n 's/^version = "\(.*\)"$/\1/p' Cargo.toml | head -n 1)"
fi
# The one target that is published today. Derived rather than written down,
# so that the day a second one is published this says which machine it is on
# instead of quietly building a tarball named for the wrong architecture.
case "$(uname -s)-$(uname -m)" in
  Darwin-arm64) TARGET="darwin-arm64" ;;
  *) fail "no release is published for $(uname -s) on $(uname -m)" ;;
esac
TARBALL="asterism-${VERSION}-${TARGET}.tar.gz"

# Short, because a unix socket path under a suite's home is capped near 104
# bytes and every one of them starts here. More importantly, cleanup may
# remove this directory, so it must be one this process created. An existing
# --out is rejected rather than treated as harness-owned data.
if [ -n "$OUT" ]; then
  RUN="$OUT"
  [ ! -e "$RUN" ] || fail "--out must not already exist: $RUN"
  [ ! -e "$RUN.evidence" ] || fail "evidence path must not already exist: $RUN.evidence"
  mkdir "$RUN" || fail "could not create --out directory: $RUN"
else
  RUN="$(mktemp -d "${TMPDIR:-/tmp}/ast-rc.XXXXXX")" \
    || fail "could not create the run directory"
fi
PREFIX="$RUN/prefix"
EVIDENCE="$RUN/evidence"

# Every suite writes its diagnostics under this run rather than under a
# global default, so one directory holds the whole story and CI can upload it
# as one artifact.
export ASTERISM_TEST_ARTIFACTS="$EVIDENCE"
# ...and pulls images from a cache that belongs to the harness. Shared
# between runs on purpose: a base image is a gigabyte and re-downloading it
# per suite is what makes people stop running these.
export ASTERISM_TEST_CACHE="${ASTERISM_TEST_CACHE:-$HOME/.cache/asterism-harness}"
harness_begin rc

cleanup() {
  # The prefix is put back the way an uninstall would leave it, because a
  # release-candidate run that left a half-installed Asterism behind would be
  # the first thing to break the next one.
  if [ -x "$PREFIX/bin/ast" ]; then
    ASTERISM_YES=1 ASTERISM_PREFIX="$PREFIX" sh packaging/install.sh --uninstall \
      >/dev/null 2>&1 || true
  fi
  harness_reap
  if [ -n "$KEEP" ]; then
    say "kept $RUN"
  else
    # The evidence outlives the run directory it was collected into: it is
    # the only thing anyone wants afterwards.
    if [ -d "$EVIDENCE" ] && [ -n "$(ls -A "$EVIDENCE" 2>/dev/null)" ]; then
      mkdir -p "$RUN.evidence"
      cp -R "$EVIDENCE/." "$RUN.evidence/" 2>/dev/null || true
      say "evidence in $RUN.evidence"
    fi
    rm -rf "$RUN"
  fi
}
trap cleanup EXIT

# Registered in this shell, not inside the suite: a suite runs down a pipe
# into `tee`, which is a subshell, and a pid registered there would be
# forgotten by the time the cleanup trap runs.
harness_own_home "$RUN/identity"

# ---- the artifact ----------------------------------------------------------

# Build a release directory that is byte-for-byte what the release workflow
# uploads. The steps are the same ones, in the same order, on purpose: a
# difference here would mean this run proves something nobody receives.
# Sets BASE rather than printing it: everything in here also has progress to
# report, and a function whose stdout is its return value cannot say anything
# to the person waiting on a two-minute release build.
build_artifact() {
  local dist="$RUN/dist/$VERSION"
  mkdir -p "$dist"
  say "building $VERSION from this tree"
  cargo build --release --locked --package asterism-cli --package asterism-daemon \
    --package asterism-vz \
    || fail "the release build did not succeed"
  # Stripped, then packed with COPYFILE_DISABLE so macOS does not smuggle
  # ._ AppleDouble entries into the tarball and change its digest for a
  # reason nobody can see. Both are what release.yml does.
  cp target/release/ast target/release/astd target/release/astd-vz "$RUN/dist/"
  strip -x "$RUN/dist/ast" "$RUN/dist/astd" "$RUN/dist/astd-vz"
  # Stripping changes signed bytes, so the helper is signed only after its
  # release shape is final. Sign the copy that enters the tarball, not a
  # neighboring build output that users never receive.
  codesign --force --sign - --entitlements crates/asterism-vz/vz.entitlements \
    "$RUN/dist/astd-vz" || fail "could not sign the release VZ helper"
  codesign --verify --strict "$RUN/dist/astd-vz" \
    || fail "the release VZ helper signature does not verify"
  COPYFILE_DISABLE=1 tar -czf "$dist/$TARBALL" -C "$RUN/dist" ast astd astd-vz \
    || fail "could not pack $TARBALL"
  ( cd "$dist" && shasum -a 256 "$TARBALL" >SHA256SUMS ) \
    || fail "could not checksum $TARBALL"
  BASE="$RUN/dist"
}

BASE=""
if [ -n "$ARTIFACT_DIR" ]; then
  BASE="$(cd "$ARTIFACT_DIR" && pwd)"
else
  build_artifact
fi
[ -f "$BASE/$VERSION/$TARBALL" ] || fail "no $TARBALL under $BASE/$VERSION"
[ -f "$BASE/$VERSION/SHA256SUMS" ] || fail "no SHA256SUMS under $BASE/$VERSION"

# The digest the release publishes. Everything that follows is checked
# against this one line, so it is read once and named.
PUBLISHED="$(awk -v f="$TARBALL" '$2 == f || $2 == "*" f { print $1 }' \
  "$BASE/$VERSION/SHA256SUMS" | head -n 1)"
[ -n "$PUBLISHED" ] || fail "SHA256SUMS does not mention $TARBALL"

# ---- install it ------------------------------------------------------------

say "installing $VERSION into $PREFIX"
ASTERISM_YES=1 \
ASTERISM_PREFIX="$PREFIX" \
ASTERISM_BASE_URL="file://$BASE" \
ASTERISM_VERSION="$VERSION" \
  sh packaging/install.sh >"$EVIDENCE/install.log" 2>&1 \
  || { cat "$EVIDENCE/install.log" >&2; fail "the installer refused $VERSION"; }

AST_BIN="$PREFIX/bin/ast"
ASTD_BIN="$PREFIX/bin/astd"
export AST_BIN ASTD_BIN
[ -x "$AST_BIN" ] || fail "the installer produced no ast"
[ -x "$ASTD_BIN" ] || fail "the installer produced no astd"

# ---- suites that live here -------------------------------------------------

# Is this the artifact that was published, and is it one build?
#
# Every other suite proves the product does what it says. This one proves
# that what the other suites just operated is what a user would receive —
# which is the claim nothing else in this tree makes.
rc_suite_identity() {
  local home="$RUN/identity"
  mkdir -p "$home"

  # 1. The bytes. The installer checked the tarball's digest on the way in;
  #    this checks it again from outside, so a passing run does not depend on
  #    the installer being the thing that is right.
  local got
  got="$(shasum -a 256 "$BASE/$VERSION/$TARBALL" | awk '{print $1}')"
  [ "$got" = "$PUBLISHED" ] \
    || { echo "the tarball hashes to $got, but SHA256SUMS says $PUBLISHED" >&2; return 1; }
  echo "ok: the artifact is the published bytes ($PUBLISHED)"

  # 2. The receipt. The installer writes down the digest it verified; a
  #    receipt naming a different one means the prefix and the release have
  #    come apart, which is what an interrupted upgrade leaves behind.
  local receipt="$PREFIX/share/asterism/install-receipt.env"
  if [ -f "$receipt" ]; then
    local recorded
    recorded="$(sed -n 's/^sha256=//p' "$receipt" | tail -n 1)"
    [ "$recorded" = "$PUBLISHED" ] \
      || { echo "the receipt records $recorded, not $PUBLISHED" >&2; return 1; }
    echo "ok: the installed receipt names the published digest"
  fi

  # 3. The version. `ast --version` is what a package manager parses, so it
  #    is asserted exactly rather than searched.
  local reported
  reported="$("$AST_BIN" --version 2>&1)"
  [ "$reported" = "ast ${VERSION#v}" ] \
    || { echo "ast --version says \"$reported\", not \"ast ${VERSION#v}\"" >&2; return 1; }
  echo "ok: ast reports ${VERSION#v}"

  # 4. The build. `ast` and `astd` are packed together and can still be two
  #    builds; the daemon is asked over the socket rather than read off disk,
  #    so what answers is the process, not the file.
  local ast_build daemon
  ast_build="$(harness_build_id "$AST_BIN")" || return 1
  echo "ok: ast is build $ast_build"

  ASTERISM_HOME="$home" ASTERISM_MESH=local "$ASTD_BIN" >"$home/astd.log" 2>&1 &
  harness_own $!
  # `astd-running <version>  <build>` when one answered, and
  # `astd-running none  (...)` when none did — so this pattern matches the
  # first and cannot match the second.
  local _i
  for _i in $(seq 1 100); do
    daemon="$(ASTERISM_HOME="$home" ASTERISM_MESH=local "$AST_BIN" bugreport 2>/dev/null |
      sed -n 's/^astd-running   *[0-9][^ ]*  *//p')"
    [ -n "$daemon" ] && break
    sleep 0.2
  done
  if [ -n "$daemon" ]; then
    :
  else
    echo "the installed astd never answered" >&2
    cat "$home/astd.log" >&2 || true
    return 1
  fi
  [ "$daemon" != "build-unknown" ] \
    || { echo "the installed astd does not report a build id" >&2; return 1; }
  [ "$daemon" = "$ast_build" ] \
    || { echo "the running astd is build $daemon, but ast is $ast_build" >&2; return 1; }
  echo "ok: the running astd is the same build"

  # 5. The vz helper. It is the fourth binary in the set and the only one that
  #    also has to be code-signed. Missing, mismatched or unsigned all mean
  #    the installed artifact cannot run VZ, so all are release failures.
  local helper="$PREFIX/bin/astd-vz"
  local helper_build
  helper_build="$(harness_assert_vz_helper "$AST_BIN" "$helper")" || return 1
  echo "ok: the installed astd-vz is signed, entitled, and build $helper_build"

  # 6. The app, when there is one. It is a separate download, so its absence
  #    is not a failure — but a mismatched one is exactly the failure this
  #    whole suite exists to catch.
  local app="/Applications/Asterism.app/Contents/MacOS/asterism-gui"
  if [ -x "$app" ]; then
    local app_build
    app_build="$(ASTERISM_HOME="$home" "$app" --dump-main settings 2>/dev/null |
      sed -n 's/^app build //p' | head -n 1)"
    if [ -z "$app_build" ]; then
      echo "note: the installed app is too old to report a build id"
    elif [ "$app_build" != "$ast_build" ]; then
      echo "the installed app is build $app_build, but ast is $ast_build" >&2
      return 1
    else
      echo "ok: the installed app is the same build"
    fi
  else
    echo "note: no desktop app installed, so nothing to compare it to"
  fi

  # 7. The bug report runs, and says which build it is about. A report that
  #    cannot name the build is a report nobody can act on.
  local report
  report="$(ASTERISM_HOME="$home" "$AST_BIN" bugreport 2>&1)" \
    || { echo "ast bugreport failed:"; echo "$report" >&2; return 1; }
  grep -qF "$ast_build" <<<"$report" \
    || { echo "ast bugreport does not name the build:"; echo "$report" >&2; return 1; }
  printf '%s\n' "$report" >"$EVIDENCE/bugreport.txt"
  echo "ok: ast bugreport names the build it is about"

  harness_reap_home "$home"
  return 0
}

# The source-level gates, run here so that one command is the whole story.
rc_suite_unit() {
  cargo test --workspace || return 1
  cargo clippy --workspace --all-targets -- -D warnings || return 1

  # The desktop app is a separate cargo workspace, and its crate cannot even
  # be compiled without its built frontend: `tauri::generate_context!` reads
  # `gui/ui/dist` at macro-expansion time and panics when it is not there. So
  # this half runs when the frontend has been built and says so when it has
  # not — a checkout with no `npm run build` in it is an ordinary state of
  # the tree, not a failing one.
  if [ -d "$ROOT/gui/ui/dist" ]; then
    ( cd "$ROOT/gui" && cargo test ) || return 1
  else
    echo "note: gui/ui/dist is not built, so the desktop app's tests did not run"
    echo "      (npm --prefix gui/ui ci && npm --prefix gui/ui run build)"
  fi
  return 0
}

# ---- what this device can run ----------------------------------------------

have_vm() {
  # Only the categorical part is decided here: both backends this tree has
  # are macOS-only, so a Linux runner cannot boot a guest at all. Whether a
  # *particular* Mac can run a *particular* backend is the product's own
  # question, and it answers it at create time with a probe and a reason —
  # which is a better error than anything this could invent.
  [ "$(uname -s)" = "Darwin" ]
}

have_net() {
  # A bounded probe, because the alternative is a suite that hangs for its
  # whole budget on a machine with no route out.
  harness_run 10 "network probe" \
    curl -fsS -o /dev/null --max-time 8 https://api.github.com >/dev/null 2>&1
}

can_run() {
  case "$(suite_field "$1" needs)" in
    any) return 0 ;;
    vm) have_vm ;;
    # The helper is macOS-only, and so is everything that needs it. Whether
    # the *artifact* carries a usable one is a separate question, and it is
    # not answered by stepping aside: on a Mac the lane runs, and the gate
    # where it runs fails the release if the installed helper is absent,
    # from another build, or unsigned. Nothing here falls back to the tree.
    helper) have_vm ;;
    net) have_net ;;
    # The desktop app is built by the tauri CLI rather than by this run, so
    # its absence is an ordinary state of the tree and not a failure.
    gui) [ -x "${GUI_BIN:-$ROOT/gui/target/debug/asterism-gui}" ] ;;
    *) return 0 ;;
  esac
}

# ---- run them --------------------------------------------------------------

PASSED=""
FAILED=""
SKIPPED=""

for suite in $WANTED; do
  needs="$(suite_field "$suite" needs)"
  bound="$(suite_field "$suite" bound)"
  runs="$(suite_field "$suite" runs)"

  if ! can_run "$suite"; then
    say "---- $suite: skipped (needs $needs, which this run has not got)"
    SKIPPED="$SKIPPED $suite"
    continue
  fi

  against="the installed artifact"
  say "---- $suite (bound ${bound}s, against $against)"
  log="$EVIDENCE/$suite.log"
  # The VZ lane has a hard preflight because failing deep in `ast create`
  # would diagnose only availability, not whether the installed helper was
  # absent, from another build, or had lost its signature. This check never
  # consults the source tree and never changes AST_BIN/ASTD_BIN.
  if [ "$needs" = helper ]; then
    helper="$(dirname "$AST_BIN")/astd-vz"
    if helper_build="$(harness_assert_vz_helper "$AST_BIN" "$helper" 2>&1)"; then
      say "exact-artifact helper gate: $helper_build" | tee "$log"
    else
      printf '%s\n' "$helper_build" | tee "$log" >&2
      say "---- $suite: FAILED (installed artifact helper gate)"
      FAILED="$FAILED $suite"
      continue
    fi
  fi
  # A row either names a function defined above or a command to run. Both are
  # split on whitespace, which is what the table's last column is written
  # for.
  # shellcheck disable=SC2206  # the split is the point
  cmd=($runs)
  # Built as a whole array because macOS ships bash 3.2, where expanding an
  # empty array under `set -u` is an error rather than nothing. AST_BIN and
  # ASTD_BIN remain exported: every lane runs the installed artifact.
  run=("${cmd[@]}")
  # Live output, because a suite that boots guests takes minutes and silence
  # for minutes is indistinguishable from a hang. The tee keeps a copy for
  # the evidence directory whether it passed or not.
  if harness_run_live "$bound" "$suite" "${run[@]}" 2>&1 | tee "$log"; then
    say "---- $suite: green"
    PASSED="$PASSED $suite"
  else
    status=$?
    case "$status" in
      124)
        say "---- $suite: TIMED OUT after ${bound}s"
        FAILED="$FAILED $suite"
        ;;
      # A suite that stepped aside because this machine is not the right
      # machine. Reported as what it is rather than as red: see
      # harness_skip.
      "$HARNESS_SKIP_STATUS")
        say "---- $suite: skipped (it said why above)"
        SKIPPED="$SKIPPED $suite"
        ;;
      *)
        say "---- $suite: FAILED ($status)"
        FAILED="$FAILED $suite"
        ;;
    esac
  fi
done

# ---- and say what happened -------------------------------------------------

say ""
say "release candidate $VERSION  ($PUBLISHED)"
[ -n "$PASSED" ] && say "  green:   ${PASSED# }"
[ -n "$SKIPPED" ] && say "  skipped: ${SKIPPED# }"
[ -n "$FAILED" ] && say "  FAILED:  ${FAILED# }"
say "  evidence: $EVIDENCE"

[ -z "$FAILED" ] || exit 1
say "RC GREEN"
