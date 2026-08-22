#!/usr/bin/env bash
# Prove that every Rust source in the Cargo workspace was an input to
# rustc. `cargo metadata` only knows each target's root, so it cannot catch a
# stray module file beside main.rs; rustc's dep-info has the full module graph.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# An isolated target directory matters: a dep-info file from a previous build
# could otherwise make a deleted module look as though it was still compiled.
TARGET_DIR="$(mktemp -d "${TMPDIR:-/tmp}/asterism-source-graph.XXXXXX")"
cleanup() {
  rm -rf "$TARGET_DIR"
}
trap cleanup EXIT

CARGO_TARGET_DIR="$TARGET_DIR" CARGO_INCREMENTAL=0 \
  cargo test --locked --workspace --all-targets --no-run

REACHABLE="$TARGET_DIR/reachable"
TRACKED="$TARGET_DIR/tracked"
AUDITED="$TARGET_DIR/audited"
PLATFORM_EXCLUDED="$TARGET_DIR/platform-excluded"
MISSING="$TARGET_DIR/missing"

# Dep-info is a makefile rule. Joining its escaped continuations then splitting
# on whitespace leaves one absolute input path per line, including build.rs,
# integration tests, examples, and every module rustc followed from them.
find "$TARGET_DIR" -name '*.d' -type f -exec \
  awk '/\\\\$/ { sub(/\\\\$/, ""); printf "%s", $0; next } { print }' {} + |
  tr ' ' '\n' |
  sed -e "s#^$ROOT/##" |
  sed -n '/^crates\/.*\.rs$/p' |
  sort -u >"$REACHABLE"

find crates -type f -name '*.rs' -print | sort -u >"$TRACKED"

# The astd-vz entry point builds a diagnostic stub away from macOS. Its four
# implementation modules are consequently absent from rustc's dep-info there.
# Keep this list exact, and prove each exclusion is still guarded by the
# adjacent macOS cfg in the binary root before removing it from the audit.
: >"$PLATFORM_EXCLUDED"
if ! rustc --print cfg | grep -qx 'target_os="macos"'; then
  HELPER_MAIN="crates/asterism-vz/src/helper/main.rs"
  for module in agent ctl net vm; do
    if ! awk -v module="$module" '
      /^[[:space:]]*#\[cfg\(target_os[[:space:]]*=[[:space:]]*"macos"\)\][[:space:]]*$/ {
        macos_cfg = 1
        next
      }
      macos_cfg && $0 ~ "^[[:space:]]*mod[[:space:]]+" module "[[:space:]]*;[[:space:]]*$" {
        found = 1
      }
      { macos_cfg = 0 }
      END { exit !found }
    ' "$HELPER_MAIN"; then
      echo "source-graph exclusion is not proven macOS-only: $module.rs" >&2
      exit 1
    fi
    printf 'crates/asterism-vz/src/helper/%s.rs\n' "$module"
  done | sort -u >"$PLATFORM_EXCLUDED"
fi

comm -23 "$TRACKED" "$PLATFORM_EXCLUDED" >"$AUDITED"
comm -23 "$AUDITED" "$REACHABLE" >"$MISSING"

if [ -s "$MISSING" ]; then
  echo 'Rust sources outside the Cargo build graph:' >&2
  cat "$MISSING" >&2
  exit 1
fi
