#!/usr/bin/env bash
# Hermetic installed-artifact tests for the signed transactional updater.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
UPDATE="$ROOT/packaging/update.sh"
RENDER="$ROOT/scripts/render-release-manifest.sh"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/asterism-update-test.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

pass=0
fail() { echo "UPDATE-TEST FAIL: $*" >&2; exit 1; }
ok() { pass=$((pass + 1)); echo "ok: $*"; }
sha() { shasum -a 256 "$1" | awk '{print $1}'; }

VERIFIER="$WORK/verifier"
cat >"$VERIFIER" <<'SH'
#!/bin/sh
[ "$(cat "$2")" = valid ] && [ "$3" = test-public-key ]
SH
chmod +x "$VERIFIER"

make_program() {
  local path="$1" name="$2" version="$3" build="$4"
  cat >"$path" <<SH
#!/bin/sh
case "\${1:-}" in
version|-V|--version)
  echo "version   $version"
  echo "build     $build"
  ;;
__activate-update)
  shift
  [ "\${1:-}" = --build ] && [ "\${2:-}" = "$build" ] || exit 1
  echo "$build" >>"$WORK/activations"
  ;;
*) echo "$name $version" ;;
esac
SH
  chmod +x "$path"
}

make_updater() {
  cp "$UPDATE" "$1"
  chmod +x "$1"
}

make_release() {
  local version="$1" build="$2" dir stage
  dir="$WORK/releases/$version"
  stage="$WORK/stage-$version"
  rm -rf "$dir" "$stage"
  mkdir -p "$dir" "$stage" "$WORK/app-$version/Asterism.app/Contents/MacOS"
  make_program "$stage/ast" ast "$version" "$build"
  make_program "$stage/astd" astd "$version" "$build"
  make_program "$stage/astd-vz" astd-vz "$version" "$build"
  make_updater "$stage/asterism-update"
  tar -czf "$dir/unit.tar.gz" -C "$stage" ast astd astd-vz asterism-update
  make_program "$WORK/app-$version/Asterism.app/Contents/MacOS/asterism-gui" app "$version" "$build"
  tar -czf "$dir/app.tar.gz" -C "$WORK/app-$version" Asterism.app
  "$RENDER" stable "$version" "$build" test \
    "file://$dir/unit.tar.gz" "$(sha "$dir/unit.tar.gz")" \
    "file://$dir/app.tar.gz" "$(sha "$dir/app.tar.gz")" >"$dir/RELEASE.json"
  printf valid >"$dir/RELEASE.json.sig"
}

install_old() {
  PREFIX="$WORK/prefix"
  HOME_STATE="$WORK/home"
  APP="$WORK/Applications/Asterism.app"
  rm -rf "$PREFIX" "$HOME_STATE" "$APP" "$WORK/activations"
  mkdir -p "$PREFIX/bin" "$PREFIX/libexec/asterism" "$APP/Contents/MacOS"
  make_program "$PREFIX/bin/ast" ast 0.0.1 0.0.1+old
  make_program "$PREFIX/bin/astd" astd 0.0.1 0.0.1+old
  make_program "$PREFIX/bin/astd-vz" astd-vz 0.0.1 0.0.1+old
  make_updater "$PREFIX/libexec/asterism/asterism-update"
  make_program "$APP/Contents/MacOS/asterism-gui" app 0.0.1 0.0.1+old
}

run_update() {
  env \
    ASTERISM_UPDATE_AST_PATH="$PREFIX/bin/ast" \
    ASTERISM_UPDATE_PREFIX="$PREFIX" \
    ASTERISM_UPDATE_TARGET=test \
    ASTERISM_HOME="$HOME_STATE" \
    ASTERISM_APP_PATH="$APP" \
    ASTERISM_UPDATE_MANIFEST_URL="file://$MANIFEST" \
    ASTERISM_UPDATE_VERIFIER="$VERIFIER" \
    ASTERISM_UPDATE_PUBKEY=test-public-key \
    "$PREFIX/libexec/asterism/asterism-update" "$@"
}

build_of() { "$1" version 2>/dev/null | sed -n 's/^build[[:space:]]*//p'; }

sh -n "$UPDATE" || fail "update.sh is not valid POSIX sh"
sh -n "$RENDER" || fail "render-release-manifest.sh is not valid POSIX sh"
if command -v shellcheck >/dev/null 2>&1; then
	shellcheck -s sh "$UPDATE" "$RENDER" || fail "shellcheck found an updater problem"
	shellcheck -s bash "$0" || fail "shellcheck found an updater-test problem"
fi
ok "updater and manifest renderer are valid shell"

make_release 0.0.2 0.0.2+new
MANIFEST="$WORK/releases/0.0.2/RELEASE.json"
install_old

out=$(run_update status)
grep -q '^channel   stable$' <<<"$out" || fail "status did not report stable: $out"
grep -q '^build     0.0.1+old$' <<<"$out" || fail "status did not report the installed build: $out"
ok "status exposes one channel/version/build model"

mv "$WORK/releases/0.0.2/unit.tar.gz" "$WORK/releases/0.0.2/unit.saved"
out=$(run_update check)
grep -q 'channel   0.0.2  0.0.2+new' <<<"$out" || fail "check did not name the signed build: $out"
mv "$WORK/releases/0.0.2/unit.saved" "$WORK/releases/0.0.2/unit.tar.gz"
ok "check authenticates metadata without downloading artifacts"

printf tampered >"$MANIFEST.sig"
if run_update check >"$WORK/bad-sig" 2>&1; then fail "tampered signature was accepted"; fi
[ "$(build_of "$PREFIX/bin/ast")" = 0.0.1+old ] || fail "signature refusal mutated ast"
printf valid >"$MANIFEST.sig"
ok "a tampered manifest is refused before mutation"

cp "$MANIFEST" "$MANIFEST.good"
sed 's/"schema":"1"/"schema":"2"/' "$MANIFEST.good" >"$MANIFEST"
if run_update check >"$WORK/bad-schema" 2>&1; then fail "an unsupported signed schema was accepted"; fi
[ "$(build_of "$PREFIX/bin/ast")" = 0.0.1+old ] || fail "schema refusal mutated ast"
mv "$MANIFEST.good" "$MANIFEST"
ok "an unsupported signed manifest schema is refused before mutation"

cp "$WORK/releases/0.0.2/unit.tar.gz" "$WORK/releases/0.0.2/unit.good"
printf tampered >>"$WORK/releases/0.0.2/unit.tar.gz"
if run_update apply --yes >"$WORK/bad-archive" 2>&1; then fail "tampered archive was accepted"; fi
[ "$(build_of "$PREFIX/bin/astd")" = 0.0.1+old ] || fail "archive refusal mutated astd"
mv "$WORK/releases/0.0.2/unit.good" "$WORK/releases/0.0.2/unit.tar.gz"
ok "a tampered artifact is refused before mutation"

if ASTERISM_UPDATE_FAIL_AFTER=Asterism.app run_update apply --yes >"$WORK/partial" 2>&1; then
  fail "injected partial activation succeeded"
fi
for binary in ast astd astd-vz; do
  [ "$(build_of "$PREFIX/bin/$binary")" = 0.0.1+old ] || fail "$binary did not roll back"
done
[ "$(build_of "$APP/Contents/MacOS/asterism-gui")" = 0.0.1+old ] || fail "app changed during rolled-back activation"
ok "partial activation rolls every installed component back"

brew_prefix="$WORK/Homebrew/Cellar/asterism/0.0.1"
mkdir -p "$brew_prefix/bin"
cp "$PREFIX/bin/ast" "$brew_prefix/bin/ast"
if env ASTERISM_UPDATE_AST_PATH="$brew_prefix/bin/ast" ASTERISM_HOME="$HOME_STATE" \
	"$UPDATE" apply --yes >"$WORK/brew-apply" 2>&1; then
	fail "an in-app update replaced a Homebrew-owned installation"
fi
grep -q 'brew upgrade asterism' "$WORK/brew-apply" || fail "Homebrew refusal gave no upgrade command"
[ "$(build_of "$PREFIX/bin/ast")" = 0.0.1+old ] || fail "Homebrew refusal mutated the installation"
ok "Homebrew-owned installs delegate activation to brew"

run_update apply --yes >"$WORK/applied"
for binary in ast astd astd-vz; do
  [ "$(build_of "$PREFIX/bin/$binary")" = 0.0.2+new ] || fail "$binary did not activate"
done
[ "$(build_of "$APP/Contents/MacOS/asterism-gui")" = 0.0.2+new ] || fail "app did not activate"
grep -q '^0.0.2+new$' "$WORK/activations" || fail "new daemon was not activated"
grep -q '^last_build=0.0.2+new$' "$HOME_STATE/update-state.env" || fail "activation was not recorded"
ok "N-1 to N activates app, CLI, daemon and helper as one build"

make_release 0.0.1 0.0.1+older
MANIFEST="$WORK/releases/0.0.1/RELEASE.json"
if run_update apply --yes >"$WORK/downgrade" 2>&1; then fail "downgrade was accepted"; fi
[ "$(build_of "$PREFIX/bin/ast")" = 0.0.2+new ] || fail "downgrade refusal mutated ast"
ok "downgrade policy runs before artifact download or mutation"

echo "UPDATE TEST GREEN — $pass checks"
