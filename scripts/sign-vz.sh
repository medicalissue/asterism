#!/usr/bin/env bash
# Build and code-sign astd-vz, the helper that owns Virtualization.framework
# guests.
#
# WHY THIS EXISTS: VZ refuses to create a VZVirtualMachine in a process that
# does not carry com.apple.security.virtualization, and cargo emits an
# unsigned binary. So `cargo build` alone produces a helper that cannot boot
# anything, and `astd` refuses the vz backend until this script has run.
#
# Cargo rewrites the binary on every rebuild, which invalidates the
# signature — run this after every build, not once. It is cheap and
# idempotent.
#
#   scripts/sign-vz.sh            # debug
#   scripts/sign-vz.sh --release  # release
#
# The signature is ad-hoc (`-s -`), which is all a local build needs. A
# release build for distribution wants `-s "Developer ID Application: ..."`
# plus notarization, i.e. a paid Apple Developer account (BACKENDS.md §4) —
# which is also why `cargo install asterism-cli` keeps people on the qemu
# path on macOS.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export PATH="$HOME/.cargo/bin:$PATH"

PROFILE=debug
if [ "${1:-}" = "--release" ]; then
  PROFILE=release
fi

BIN="$ROOT/target/$PROFILE/astd-vz"
ENTITLEMENTS="$ROOT/crates/asterism-vz/vz.entitlements"

if [ "$(uname -s)" != "Darwin" ]; then
  echo "sign-vz: Virtualization.framework is macOS-only; nothing to sign here" >&2
  exit 0
fi

if [ "$PROFILE" = release ]; then
  cargo build --release -q -p asterism-vz --bin astd-vz
else
  cargo build -q -p asterism-vz --bin astd-vz
fi
codesign --force --sign - --entitlements "$ENTITLEMENTS" "$BIN"

# Prove it rather than trust it: the daemon's probe() runs this same check,
# so a silent failure here would surface as "vz is unavailable" later.
if codesign -d --entitlements - "$BIN" 2>&1 | grep -q 'com.apple.security.virtualization'; then
  echo "signed $BIN (com.apple.security.virtualization)"
else
  echo "SIGNING FAILED: $BIN does not carry com.apple.security.virtualization" >&2
  exit 1
fi
