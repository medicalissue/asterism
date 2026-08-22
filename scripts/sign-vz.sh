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
#   scripts/sign-vz.sh                     # debug
#   scripts/sign-vz.sh --release           # release
#   scripts/sign-vz.sh --release --sign-only   # sign what is already built
#
# --sign-only is for the release workflow, which builds --locked and strips
# the binary before signing: `strip` rewrites the file and so invalidates
# whatever signature was on it, which makes signing strictly the last thing
# done to these bytes.
#
# The identity is ad-hoc (`-`) by default, which is all a local build needs
# and all a `curl | sh` install needs — a file this machine downloaded and
# checksummed itself is not quarantined, so Gatekeeper never assesses it,
# and both entitlements here are unrestricted (see vz.entitlements). Set
#
#   ASTERISM_SIGN_IDENTITY="Developer ID Application: ..."
#
# to sign for distribution instead; that adds the hardened runtime and a
# trusted timestamp, which are what notarization requires. That is the path
# a release takes when the repository holds a certificate, and it is the
# only way a helper that arrives through a *browser* download — quarantined,
# and therefore assessed — will run at all.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export PATH="$HOME/.cargo/bin:$PATH"
# cargo builds the workspace it is standing in, so where this was called
# from must not decide what gets built. The installer calls it from the
# clone it just made, which is not the directory it was run in.
cd "$ROOT"

PROFILE=debug
BUILD=1
for arg in "$@"; do
  case "$arg" in
  --release) PROFILE=release ;;
  --sign-only) BUILD=0 ;;
  *)
    echo "sign-vz: unknown argument $arg" >&2
    exit 2
    ;;
  esac
done

BIN="$ROOT/target/$PROFILE/astd-vz"
ENTITLEMENTS="$ROOT/crates/asterism-vz/vz.entitlements"
IDENTITY="${ASTERISM_SIGN_IDENTITY:--}"

if [ "$(uname -s)" != "Darwin" ]; then
  echo "sign-vz: Virtualization.framework is macOS-only; nothing to sign here" >&2
  exit 0
fi

if [ "$BUILD" = 1 ]; then
  # --locked because this is the build a source install and a Homebrew
  # build run, and both promise the dependency graph CI tested. Cargo.lock
  # is committed, so this is a no-op for anyone who has not just edited a
  # Cargo.toml without updating it.
  if [ "$PROFILE" = release ]; then
    cargo build --release --locked -q -p asterism-vz --bin astd-vz
  else
    cargo build --locked -q -p asterism-vz --bin astd-vz
  fi
fi
[ -f "$BIN" ] || {
  echo "sign-vz: $BIN is not there — build it first, or drop --sign-only" >&2
  exit 1
}

# Ad-hoc signatures cannot be timestamped and have no hardened runtime to
# opt into; a Developer ID signature needs both, or notarization rejects it.
sign=(codesign --force --sign "$IDENTITY" --entitlements "$ENTITLEMENTS")
if [ "$IDENTITY" != "-" ]; then
  sign+=(--options runtime --timestamp)
fi
"${sign[@]}" "$BIN"

# Prove it rather than trust it: the daemon's probe() runs this same check,
# so a silent failure here would surface as "vz is unavailable" later.
if codesign -d --entitlements - "$BIN" 2>&1 | grep -q 'com.apple.security.virtualization'; then
  echo "signed $BIN as ${IDENTITY} (com.apple.security.virtualization)"
else
  echo "SIGNING FAILED: $BIN does not carry com.apple.security.virtualization" >&2
  exit 1
fi

# And that the signature covers the bytes as they now stand. `strip` after
# signing, or a partial write, leaves a signature that verifies as broken —
# which is a binary macOS will refuse to execute, not merely one VZ turns
# down.
codesign --verify --strict "$BIN" || {
  echo "SIGNING FAILED: the signature on $BIN does not verify" >&2
  exit 1
}
