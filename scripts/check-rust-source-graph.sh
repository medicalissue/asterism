#!/usr/bin/env bash
# Prove that every Rust source in the Cargo workspace was an input to
# rustc. `cargo metadata` only knows each target's root, so it cannot catch a
# stray module file beside main.rs; rustc's dep-info has the full module graph.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

MACOS_ONLY_HELPER_MODULES='crates/asterism-vz/src/helper/agent.rs
crates/asterism-vz/src/helper/ctl.rs
crates/asterism-vz/src/helper/gpu.rs
crates/asterism-vz/src/helper/net.rs
crates/asterism-vz/src/helper/vm.rs'

UNIX_ONLY_MODULES='crates/asterism-core/src/ipc_unix.rs
crates/asterism-daemon/src/device_shell_unix.rs
crates/asterism-daemon/src/backend/qemu.rs
crates/asterism-daemon/src/backend/qmp.rs
crates/asterism-daemon/src/backend/vz.rs'

WINDOWS_ONLY_MODULES='crates/asterism-hyperv/src/windows.rs
crates/asterism-core/src/ipc_windows.rs
crates/asterism-daemon/src/device_shell_windows.rs
crates/asterism-daemon/src/nbd_windows.rs'

target_os() {
  local rustc_bin="${RUSTC:-rustc}"
  "$rustc_bin" --print cfg | sed -n 's/^target_os="\([^"]*\)"$/\1/p'
}

# Keep the exception tied to the source-level reason these files are absent
# from other platforms' dep-info. If a declaration loses or changes its cfg,
# fail instead of silently turning this list into a dead-source allowlist.
verify_cfg_modules() {
  local cfg="$1" parent="$2"
  shift 2
  local path module file
  for path in "$@"; do
    [ -n "$path" ] || continue
    module="${path##*/}"
    module="${module%.rs}"
    file="${path##*/}"
    awk -v module="$module" -v file="$file" -v cfg="$cfg" '
      $0 == cfg { gated = 1; next }
      gated && $0 ~ /^#\[path = "[^"]+"\]$/ { path_matches = ($0 == "#[path = \"" file "\"]"); next }
      gated && ((path_matches && $0 ~ "^(pub )?mod [[:alnum:]_]+;") || (!path_matches && $0 ~ ("^(pub )?mod " module ";"))) {
        found = 1
      }
      { gated = 0 }
      END { exit !found }
    ' "$parent" || {
      echo "$path is not declared as a cfg-gated module in $parent" >&2
      return 1
    }
  done
}

verify_macos_only_helper_modules() {
  local path
  while IFS= read -r path; do
    verify_cfg_modules '#[cfg(target_os = "macos")]' crates/asterism-vz/src/helper/main.rs "$path"
  done <<<"$MACOS_ONLY_HELPER_MODULES"
}

verify_unix_only_modules() {
  verify_cfg_modules '#[cfg(unix)]' crates/asterism-core/src/ipc.rs \
    crates/asterism-core/src/ipc_unix.rs
  verify_cfg_modules '#[cfg(unix)]' crates/asterism-daemon/src/device_shell.rs \
    crates/asterism-daemon/src/device_shell_unix.rs
  verify_cfg_modules '#[cfg(unix)]' crates/asterism-daemon/src/backend/mod.rs \
    crates/asterism-daemon/src/backend/qemu.rs \
    crates/asterism-daemon/src/backend/qmp.rs \
    crates/asterism-daemon/src/backend/vz.rs
}

verify_windows_only_modules() {
  verify_cfg_modules '#[cfg(target_os = "windows")]' crates/asterism-hyperv/src/main.rs \
    crates/asterism-hyperv/src/windows.rs
  verify_cfg_modules '#[cfg(windows)]' crates/asterism-core/src/ipc.rs \
    crates/asterism-core/src/ipc_windows.rs
  verify_cfg_modules '#[cfg(windows)]' crates/asterism-daemon/src/device_shell.rs \
    crates/asterism-daemon/src/device_shell_windows.rs
  verify_cfg_modules '#[cfg(windows)]' crates/asterism-daemon/src/main.rs \
    crates/asterism-daemon/src/nbd_windows.rs
}

write_audited_sources() {
  local platform="$1" tracked="$2" audited="$3"
  local exclude="$audited.exclude"
  : >"$exclude"
  if [ "$platform" != macos ]; then
    printf '%s\n' "$MACOS_ONLY_HELPER_MODULES" >>"$exclude"
  fi
  if [ "$platform" != linux ] && [ "$platform" != macos ]; then
    printf '%s\n' "$UNIX_ONLY_MODULES" >>"$exclude"
  fi
  if [ "$platform" != windows ]; then
    printf '%s\n' "$WINDOWS_ONLY_MODULES" >>"$exclude"
  fi
  if [ ! -s "$exclude" ]; then
    cp "$tracked" "$audited"
  else
    comm -23 "$tracked" <(sort -u "$exclude") >"$audited"
  fi
}

self_test() (
  local scratch tracked audited expected
  scratch="$(mktemp -d "${TMPDIR:-/tmp}/asterism-source-graph-test.XXXXXX")"
  trap 'rm -rf "$scratch"' EXIT
  tracked="$scratch/tracked"
  audited="$scratch/audited"
  expected="$scratch/expected"

  printf '%s\n%s\n%s\n%s\n%s\n%s\n' \
    "$MACOS_ONLY_HELPER_MODULES" \
    "$UNIX_ONLY_MODULES" \
    "$WINDOWS_ONLY_MODULES" \
    'crates/asterism-vz/src/helper/main.rs' \
    'crates/asterism-hyperv/src/main.rs' \
    'crates/asterism-core/src/ipc.rs' | sort -u >"$tracked"

  write_audited_sources linux "$tracked" "$audited"
  printf '%s\n' \
    "$UNIX_ONLY_MODULES" \
    'crates/asterism-core/src/ipc.rs' \
    'crates/asterism-hyperv/src/main.rs' \
    'crates/asterism-vz/src/helper/main.rs' | sort >"$expected"
  cmp "$expected" "$audited"

  write_audited_sources macos "$tracked" "$audited"
  printf '%s\n' \
    "$MACOS_ONLY_HELPER_MODULES" \
    "$UNIX_ONLY_MODULES" \
    'crates/asterism-core/src/ipc.rs' \
    'crates/asterism-hyperv/src/main.rs' \
    'crates/asterism-vz/src/helper/main.rs' | sort >"$expected"
  cmp "$expected" "$audited"

  write_audited_sources windows "$tracked" "$audited"
  printf '%s\n' \
    "$WINDOWS_ONLY_MODULES" \
    'crates/asterism-core/src/ipc.rs' \
    'crates/asterism-hyperv/src/main.rs' \
    'crates/asterism-vz/src/helper/main.rs' | sort >"$expected"
  cmp "$expected" "$audited"

  verify_macos_only_helper_modules
  verify_unix_only_modules
  verify_windows_only_modules
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
verify_unix_only_modules
verify_windows_only_modules

TARGET_OS="$(target_os)"
if [ -z "$TARGET_OS" ]; then
  echo 'rustc did not report a target_os cfg' >&2
  exit 1
fi

# The VZ helper's implementation modules are declared only on macOS, the
# Hyper-V helper's Windows adapters only on Windows, and Unix-only daemon
# backends only on Unix. Stubs still compile on other hosts, and every other
# Rust source remains required in rustc dep-info.
write_audited_sources "$TARGET_OS" "$TRACKED" "$AUDITED"

comm -23 "$AUDITED" "$REACHABLE" >"$MISSING"

if [ -s "$MISSING" ]; then
  echo 'Rust sources outside the Cargo build graph:' >&2
  cat "$MISSING" >&2
  exit 1
fi
