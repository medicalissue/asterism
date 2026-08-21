#!/usr/bin/env bash
# Photograph the built app: three sections, two schemes.
#
# Runs the binary inside Asterism.app rather than a cargo build, against the
# scratch orbit proof.sh leaves behind, and never ~/.asterism. The appearance
# comes from `--theme`, so the machine's own setting is not touched.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export PATH="$HOME/.cargo/bin:$PATH"
# shellcheck source-path=SCRIPTDIR source=../scripts/lib/harness.sh
. "$ROOT/scripts/lib/harness.sh"
harness_begin shots
AST="$ROOT/target/debug/ast"
ASTD="$ROOT/target/debug/astd"
APP="$ROOT/gui/target/release/bundle/macos/Asterism.app/Contents/MacOS/asterism-gui"
RUN="/private/tmp/ast-gui3"
A="$RUN/a"
B="$RUN/b"
SHOTS="${SHOTS:-$ROOT/gui/shots}"
# The window is 760x480 and opens centred on a 1920x1080 display.
RECT="${RECT:-580,248,760,480}"

mkdir -p "$SHOTS"
[ -x "$APP" ] || { echo "no built app at $APP" >&2; exit 1; }

start_daemon() {
  local home="$1"
  harness_own_home "$home"
  ( ASTERISM_HOME="$home" ASTERISM_MESH=local "$ASTD" >>"$home/astd.log" 2>&1 & )
  for _ in $(seq 1 60); do
    ASTERISM_HOME="$home" "$AST" ls --local >/dev/null 2>&1 && return 0
    sleep 0.2
  done
  echo "astd for $home did not come up" >&2; exit 1
}

# Every app this script launches, so that closing one is closing ours.
# `pkill -f "$APP"` used to do it, which also reached a copy of the app the
# person running this had open for their own reasons.
APP_PID=

close_app() {
  [ -n "$APP_PID" ] || return 0
  harness_stop "$APP_PID"
  APP_PID=
}

close_app
# `--reuse` keeps the daemons `KEEP=1 proof.sh` left running. A restarted
# daemon comes up on a new endpoint and its peer's cached address is stale,
# so a Devices table photographed after a cold restart would be a picture of
# a partition rather than of an orbit.
if [ "${1:-}" != "--reuse" ]; then
  # Only the two scratch homes' daemons. The `pkill -f "$ASTD"` that stood
  # here stopped every astd built at that path, a developer's own included.
  harness_reap_home "$A"
  harness_reap_home "$B"
  sleep 0.5
  start_daemon "$A"
  start_daemon "$B"
fi
ASTERISM_HOME="$A" "$AST" devices || true

shoot() {
  local theme="$1" section="$2"
  close_app
  sleep 0.6
  ASTERISM_HOME="$A" ASTERISM_AST="$AST" ASTERISM_ASTD="$ASTD" \
    "$APP" --main --section "$section" --theme "$theme" \
    >"$RUN/app-$theme-$section.log" 2>&1 &
  APP_PID=$!
  # Long enough for the first orbit-wide read to come back, which on an
  # orbit with a device out of touch is the daemon's mesh timeout.
  sleep 13
  screencapture -x -R "$RECT" "$SHOTS/$theme-$section.png"
  echo "  $theme $section"
}

for theme in dark light; do
  for section in instances devices settings; do
    shoot "$theme" "$section"
  done
done

# And the dialog the Instances button opens, in the same skin.
close_app
sleep 0.6
ASTERISM_HOME="$A" ASTERISM_AST="$AST" ASTERISM_ASTD="$ASTD" \
  "$APP" --new-instance --theme dark >"$RUN/app-dialog.log" 2>&1 &
APP_PID=$!
sleep 5
screencapture -x -R "710,377,500,326" "$SHOTS/dark-new-instance.png"
echo "  dark new-instance"
close_app

echo "shots in $SHOTS"
