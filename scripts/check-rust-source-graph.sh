#!/usr/bin/env bash
# Prove that every Rust source in the Cargo workspace was an input to
# rustc. `cargo metadata` only knows each target's root, so it cannot catch a
# stray module file beside main.rs; rustc's dep-info has the full module graph.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

MACOS_ONLY_HELPER_MODULES='crates/asterism-vz/src/helper/agent.rs
crates/asterism-vz/src/helper/ctl.rs
crates/asterism-vz/src/helper/net.rs
crates/asterism-vz/src/helper/vm.rs'

target_os() {
  local rustc_bin="${RUSTC:-rustc}"
  "$rustc_bin" --print cfg | sed -n 's/^target_os="\([^"]*\)"$/\1/p'
}

# Keep the exception tied to the source-level reason these files are absent
# from non-macOS dep-info. If a declaration loses or changes its cfg, fail
# instead of silently turning this list into a dead-source allowlist.
verify_macos_only_helper_modules() {
  local path module
  while IFS= read -r path; do
    module="${path##*/}"
    module="${module%.rs}"
    awk -v declaration="mod ${module};" '
      previous == "#[cfg(target_os = \"macos\")]" && $0 == declaration {
        found = 1
      }
      { previous = $0 }
      END { exit !found }
    ' crates/asterism-vz/src/helper/main.rs || {
      echo "$path is not declared as an immediately cfg-gated macOS module" >&2
      return 1
    }
  done <<<"$MACOS_ONLY_HELPER_MODULES"
}

write_audited_sources() {
  local platform="$1" tracked="$2" audited="$3"
  if [ "$platform" = macos ]; then
    cp "$tracked" "$audited"
  else
    comm -23 "$tracked" \
      <(printf '%s\n' "$MACOS_ONLY_HELPER_MODULES" | sort -u) >"$audited"
  fi
}

self_test() (
  local scratch tracked audited expected
  scratch="$(mktemp -d "${TMPDIR:-/tmp}/asterism-source-graph-test.XXXXXX")"
  trap 'rm -rf "$scratch"' EXIT
  tracked="$scratch/tracked"
  audited="$scratch/audited"
  expected="$scratch/expected"

  printf '%s\n%s\n' \
    "$MACOS_ONLY_HELPER_MODULES" \
    'crates/asterism-vz/src/helper/main.rs' | sort -u >"$tracked"

  write_audited_sources linux "$tracked" "$audited"
  printf '%s\n' 'crates/asterism-vz/src/helper/main.rs' >"$expected"
  cmp "$expected" "$audited"

  write_audited_sources macos "$tracked" "$audited"
  cmp "$tracked" "$audited"

  verify_macos_only_helper_modules
)

if [ "${1:-}" = --self-test ]; then
  self_test
  exit
elif [ "$#" -ne 0 ]; then
  echo "usage: $0 [--self-test]" >&2
  exit 2
fi

# An isolated target directory matters: a dep-info file from a previous build
# could otherwise make a deleted module look as though it was still compiled.
TARGET_DIR="$(mktemp -d "${TMPDIR:-/tmp}/asterism-source-graph.XXXXXX")"
cleanup() {
  rm -rf "$TARGET_DIR"
}
trap cleanup EXIT

CARGO_INCREMENTAL=0 CARGO_TARGET_DIR="$TARGET_DIR" \
  cargo test --locked --workspace --all-targets --no-run

REACHABLE="$TARGET_DIR/reachable"
TRACKED="$TARGET_DIR/tracked"
AUDITED="$TARGET_DIR/audited"
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
verify_macos_only_helper_modules

TARGET_OS="$(target_os)"
if [ -z "$TARGET_OS" ]; then
  echo 'rustc did not report a target_os cfg' >&2
  exit 1
fi

# The helper binary's four implementation modules are declared only on macOS.
# Its non-macOS stub is still compiled, and every other Rust source remains
# required to appear in rustc dep-info.
write_audited_sources "$TARGET_OS" "$TRACKED" "$AUDITED"

comm -23 "$AUDITED" "$REACHABLE" >"$MISSING"

if [ -s "$MISSING" ]; then
  echo 'Rust sources outside the Cargo build graph:' >&2
  cat "$MISSING" >&2
  exit 1
fi
