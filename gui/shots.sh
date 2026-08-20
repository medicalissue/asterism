#!/usr/bin/env bash
# Photograph the built app: three sections, two schemes.
#
# Runs the binary inside Asterism.app rather than a cargo build, against the
# scratch orbit proof.sh leaves behind, and never ~/.asterism. The appearance
# comes from `--theme`, so the machine's own setting is not touched.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export PATH="$HOME/.cargo/bin:$PATH"
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
  ( ASTERISM_HOME="$home" ASTERISM_MESH=local "$ASTD" >>"$home/astd.log" 2>&1 & )
  for _ in $(seq 1 60); do
    ASTERISM_HOME="$home" "$AST" ls --local >/dev/null 2>&1 && return 0
    sleep 0.2
  done
  echo "astd for $home did not come up" >&2; exit 1
}

pkill -f "$APP" 2>/dev/null || true
# `--reuse` keeps the daemons `KEEP=1 proof.sh` left running. A restarted
# daemon comes up on a new endpoint and its peer's cached address is stale,
# so a Devices table photographed after a cold restart would be a picture of
# a partition rather than of an orbit.
if [ "${1:-}" != "--reuse" ]; then
  pkill -f "$ASTD" 2>/dev/null || true
  sleep 0.5
  start_daemon "$A"
  start_daemon "$B"
fi
ASTERISM_HOME="$A" "$AST" devices || true

shoot() {
  local theme="$1" section="$2"
  pkill -f "$APP" 2>/dev/null || true
  sleep 0.6
  ASTERISM_HOME="$A" ASTERISM_AST="$AST" ASTERISM_ASTD="$ASTD" \
    "$APP" --main --section "$section" --theme "$theme" \
    >"$RUN/app-$theme-$section.log" 2>&1 &
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
pkill -f "$APP" 2>/dev/null || true
sleep 0.6
ASTERISM_HOME="$A" ASTERISM_AST="$AST" ASTERISM_ASTD="$ASTD" \
  "$APP" --new-instance --theme dark >"$RUN/app-dialog.log" 2>&1 &
sleep 5
screencapture -x -R "710,377,500,326" "$SHOTS/dark-new-instance.png"
echo "  dark new-instance"
pkill -f "$APP" 2>/dev/null || true

echo "shots in $SHOTS"
