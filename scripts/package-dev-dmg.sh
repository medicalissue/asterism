#!/usr/bin/env bash
# Build a self-contained *internal* Apple Silicon bundle of Asterism and put
# it in a DMG.
#
# WHY THIS EXISTS: the app on its own is not usable. The GUI is a client of
# `astd` and finds `ast` and `astd` by looking next to its own executable
# (gui/src/client.rs::tool_path), and `astd` finds the VZ helper the same way
# (crates/asterism-daemon/src/backend/vz.rs::helper_path). A bundle that ships
# only asterism-gui therefore falls back to $HOME/.cargo/bin and friends —
# i.e. to whatever the machine already had. Putting all four binaries in
# Contents/MacOS is what makes the .app answer for itself.
#
# The signature is ad-hoc (`-s -`) throughout: this is an internal build, not
# a distributable one. astd-vz still gets crates/asterism-vz/vz.entitlements,
# because Virtualization.framework refuses to create a VZVirtualMachine in a
# process without com.apple.security.virtualization, and that entitlement is
# unrestricted — an ad-hoc signature carrying it is enough locally. A build
# for anyone else's machine needs a Developer ID and notarization on top
# (see scripts/sign-vz.sh).
#
# NOT bundled: qemu. The qemu backend shells out to qemu-system-aarch64 and
# qemu-img, which stay a `brew install qemu` prerequisite; vendoring them
# would drag a GPL runtime into an internal artifact for no gain.
#
#   scripts/package-dev-dmg.sh [OUT.dmg]
#
# Nothing here reads or writes ~/.asterism.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export PATH="$HOME/.cargo/bin:$PATH"

REV="$(git -C "$ROOT" rev-parse --short=7 HEAD)"
OUT="${1:-$ROOT/target/dmg/Asterism-dev-$REV-arm64.dmg}"
STAGE="$ROOT/target/dmg/stage"
APP_SRC="$ROOT/gui/target/release/bundle/macos/Asterism.app"
ENTITLEMENTS="$ROOT/crates/asterism-vz/vz.entitlements"

# The tauri CLI is not a workspace dependency (the GUI is driven by it, not
# the other way round), so it is either already on PATH or fetched on demand.
TAURI_CLI="${TAURI_CLI:-}"
if [ -z "$TAURI_CLI" ]; then
  if command -v cargo-tauri >/dev/null 2>&1; then
    TAURI_CLI="cargo-tauri"
  else
    TAURI_CLI="npx --yes @tauri-apps/cli@2"
  fi
fi

say() { printf '\n== %s\n' "$*"; }
fail() { echo "package-dev-dmg: $*" >&2; exit 1; }

[ "$(uname -s)" = Darwin ] || fail "this packages a macOS .app; nothing to do here"
[ "$(uname -m)" = arm64 ] || fail "this builds an Apple Silicon bundle and does not cross-compile"

# ---- 1. the three command line binaries ------------------------------------

say "cargo build --release (ast, astd, astd-vz)"
cargo build --release -p asterism-cli -p asterism-daemon -p asterism-vz

# Signs astd-vz with the entitlements and proves the signature took. Cargo
# rewrites the binary on every build, so this has to come after it.
say "sign astd-vz"
"$ROOT/scripts/sign-vz.sh" --release

# ---- 2. the app ------------------------------------------------------------
#
# The frontend is built by hand rather than through the config's
# beforeBuildCommand, which assumes a cwd this script does not promise.

say "build the frontend"
( cd "$ROOT/gui/ui" && npm install --no-audit --no-fund && npm run build )

say "tauri build --bundles app"
( cd "$ROOT/gui" && $TAURI_CLI build --bundles app \
    --config '{"build":{"beforeBuildCommand":""}}' )
[ -d "$APP_SRC" ] || fail "the bundler produced no $APP_SRC"

# ---- 3. the four binaries in one directory ---------------------------------

say "stage Asterism.app"
rm -rf "$STAGE"
mkdir -p "$STAGE"
cp -R "$APP_SRC" "$STAGE/Asterism.app"
APP="$STAGE/Asterism.app"

for bin in ast astd astd-vz; do
  cp "$ROOT/target/release/$bin" "$APP/Contents/MacOS/$bin"
done

# ---- 4. signatures ---------------------------------------------------------
#
# Inside out: copying a binary into the bundle is a write, and a write
# invalidates whatever signature it had, so every nested executable is signed
# here and the bundle is sealed over the result. No --deep on the outer
# signature — --deep would re-sign the nested code and drop astd-vz's
# entitlements on the floor.

say "sign the nested binaries"
codesign --force --sign - --entitlements "$ENTITLEMENTS" "$APP/Contents/MacOS/astd-vz"
codesign --force --sign - "$APP/Contents/MacOS/astd"
codesign --force --sign - "$APP/Contents/MacOS/ast"

say "seal the bundle"
codesign --force --sign - "$APP"

say "verify"
codesign --verify --deep --strict --verbose=2 "$APP"
codesign -d --entitlements - "$APP/Contents/MacOS/astd-vz" 2>&1 \
  | grep -q 'com.apple.security.virtualization' \
  || fail "the helper lost com.apple.security.virtualization during bundling"
codesign -d --entitlements - "$APP/Contents/MacOS/astd-vz" 2>&1 \
  | grep -q 'com.apple.security.network.client' \
  || fail "the helper lost com.apple.security.network.client during bundling"

# ---- 5. the disk image -----------------------------------------------------

say "hdiutil create $OUT"
mkdir -p "$(dirname "$OUT")"
ln -sf /Applications "$STAGE/Applications"
rm -f "$OUT"
hdiutil create -volname "Asterism dev $REV" -srcfolder "$STAGE" \
  -fs HFS+ -format UDZO -ov "$OUT" >/dev/null

shasum -a 256 "$OUT"
du -h "$OUT" | awk '{print $1}'
echo "packaged $OUT"
