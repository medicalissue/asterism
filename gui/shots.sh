#!/usr/bin/env bash
# Photograph the built app: every section and dialog, in both schemes.
#
# Runs the binary inside Asterism.app rather than a cargo build, against the
# scratch orbit proof.sh leaves behind, and never ~/.asterism. The appearance
# comes from `--theme`, so the machine's own setting is not touched.
#
# The dialogs are opened by `--instance <name> --intent <spec>`, which queues
# the same route a tray click queues. Nothing here drives a pointer, and no
# picture is of a state the app cannot reach on its own.
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
# The main window is 1080x700 (`mainwindow.rs`) and opens centred, so this is
# where it lands on a 1920x1080 display — measured, not computed: macOS
# centres on the visible frame, which the menu bar and the Dock both shrink.
# Any other display wants RECT set. To re-measure: run the app with `--main`,
# `screencapture -x /tmp/full.png`, and read the window's top-left corner off
# it.
RECT="${RECT:-420,138,1080,700}"
# The instance proof.sh leaves behind on A, and the snapshot it leaves on it.
INSTANCE="${INSTANCE:-gui-a}"

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

# One picture: open the window as asked, wait for the first orbit-wide read,
# and photograph the rect the window is in.
shoot() {
  local name="$1"; shift
  pkill -f "$APP" 2>/dev/null || true
  sleep 0.6
  ASTERISM_HOME="$A" ASTERISM_AST="$AST" ASTERISM_ASTD="$ASTD" \
    "$APP" --main "$@" >"$RUN/app-$name.log" 2>&1 &
  # Long enough for the first orbit-wide read to come back, which on an
  # orbit with a device out of touch is the daemon's mesh timeout.
  sleep 13
  screencapture -x -R "$RECT" "$SHOTS/$name.png"
  echo "  $name"
}

for theme in dark light; do
  # The Instances pane is the instance controller now: lifecycle policy,
  # rename/remove, snapshots, the parts table and the fence states.
  shoot "$theme-instances-control" --section instances --theme "$theme"
  shoot "$theme-snapshots" --section instances --instance "$INSTANCE" --intent snapshots --theme "$theme"
  shoot "$theme-remove-confirm" --section instances --instance "$INSTANCE" --intent remove --theme "$theme"
  shoot "$theme-devices" --section devices --theme "$theme"
  shoot "$theme-settings" --section settings --theme "$theme"
done

# And the dialog the Instances button opens, in the same skin.
pkill -f "$APP" 2>/dev/null || true
sleep 0.6
ASTERISM_HOME="$A" ASTERISM_AST="$AST" ASTERISM_ASTD="$ASTD" \
  "$APP" --new-instance --theme dark >"$RUN/app-dialog.log" 2>&1 &
sleep 5
# The New Instance window is 760x640 (`window.rs`), centred on the same
# display and by the same rule.
screencapture -x -R "580,168,760,640" "$SHOTS/dark-new-instance.png"
echo "  dark new-instance"
pkill -f "$APP" 2>/dev/null || true

echo "shots in $SHOTS"
