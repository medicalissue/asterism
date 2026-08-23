#!/usr/bin/env bash
# Hermetic installed-artifact tests for the signed transactional updater.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
UPDATE="$ROOT/packaging/update.sh"
RENDER="$ROOT/scripts/render-release-manifest.sh"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/asterism-update-test.XXXXXX")"
race_pid=""
cleanup_test() {
  [ -z "$race_pid" ] || kill "$race_pid" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup_test EXIT

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
__sync-update-path)
  printf '%s\n' "\$*" >>"$WORK/syncs"
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
  rm -rf "$PREFIX" "$HOME_STATE" "$APP" "$WORK/activations" "$WORK/syncs"
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

assert_old_converged() {
  local context="$1" binary
  for binary in ast astd astd-vz; do
    [ "$(build_of "$PREFIX/bin/$binary")" = 0.0.1+old ] ||
      fail "$context: $binary did not converge to the old build"
  done
  [ "$(build_of "$APP/Contents/MacOS/asterism-gui")" = 0.0.1+old ] ||
    fail "$context: app did not converge to the old build"
  [ ! -e "$HOME_STATE/update-transaction.claim" ] || fail "$context: transaction claim remains"
  [ -z "$(find "$HOME_STATE" -maxdepth 1 -name 'update-transaction.*' -print -quit 2>/dev/null)" ] ||
    fail "$context: private transaction directory remains"
  for path in \
    "$PREFIX/bin/ast" "$PREFIX/bin/astd" "$PREFIX/bin/astd-vz" \
    "$PREFIX/libexec/asterism/asterism-update" "$APP"; do
    [ ! -e "${path}.previous.update" ] || fail "$context: backup remains for $path"
    [ ! -e "${path}.previous.update.absent" ] || fail "$context: absence marker remains for $path"
  done
}

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

# The fixed claim is created as a hard link to a fully populated identity,
# so there is no observable claim-without-owner window. Hold updater A at
# the first instruction after that atomic link, start B, and prove B cannot
# remove, recover, or replace A's transaction before A alone completes it.
install_old
claim_pause="$WORK/claim-resume"
mkfifo "$claim_pause"
ASTERISM_UPDATE_PAUSE_AFTER_CLAIM="$claim_pause" run_update apply --yes \
  >"$WORK/claim-winner" 2>&1 &
race_pid=$!
for _ in {1..500}; do
  [ -f "${claim_pause}.ready" ] && break
  sleep 0.01
done
[ -f "${claim_pause}.ready" ] || fail "winner never reached the post-claim pause"
[ -f "$HOME_STATE/update-transaction.claim" ] || fail "winner published no atomic claim"
claim_before=$(sed -n '1p' "$HOME_STATE/update-transaction.claim")
owner_before="$HOME_STATE/$claim_before/owner-pid"
[ -s "$owner_before" ] || fail "claim identity was visible without its owner"
[ "$(sed -n '2p' "$HOME_STATE/update-transaction.claim")" = "$(sed -n '1p' "$owner_before")" ] ||
  fail "atomic claim did not publish the winner identity and owner together"
if run_update status >"$WORK/claim-loser" 2>&1; then
  fail "loser entered a live winner's transaction"
fi
grep -q 'another updater process' "$WORK/claim-loser" ||
  fail "loser did not identify the live transaction owner"
[ "$(sed -n '1p' "$HOME_STATE/update-transaction.claim")" = "$claim_before" ] ||
  fail "loser replaced the winner's claim"
[ -s "$owner_before" ] || fail "loser removed the winner's private journal"
printf 'resume\n' >"$claim_pause"
wait "$race_pid" || fail "winner did not complete after loser refusal"
race_pid=""
for binary in ast astd astd-vz; do
  [ "$(build_of "$PREFIX/bin/$binary")" = 0.0.2+new ] ||
    fail "atomic-claim winner did not activate $binary"
done
[ "$(build_of "$APP/Contents/MacOS/asterism-gui")" = 0.0.2+new ] ||
  fail "atomic-claim winner did not activate the app"
[ ! -e "$HOME_STATE/update-transaction.claim" ] || fail "winner left its claim behind"
grep -q "component-ast" "$WORK/syncs" || fail "component intent was not fsynced"
grep -q "phase" "$WORK/syncs" || fail "transaction phase was not fsynced"
ok "an atomic claim cannot be stolen during a paused two-updater race"

# Each component is a placement boundary. Exercise one process signal, one
# uncatchable death, and one failed destination rename at every boundary. A
# following updater invocation is the startup recovery path after SIGKILL.
for component in astd-vz astd asterism-update ast Asterism.app; do
  install_old
  if ASTERISM_UPDATE_FAULT="signal:$component:journal" run_update apply --yes \
    >"$WORK/fault-signal-$component" 2>&1; then
    fail "signal at $component journal boundary succeeded"
  fi
  assert_old_converged "signal at $component journal boundary"

  install_old
  if ASTERISM_UPDATE_FAULT="kill:$component:backed-up" run_update apply --yes \
    >"$WORK/fault-kill-$component" 2>&1; then
    fail "kill at $component backup boundary succeeded"
  fi
  run_update status >"$WORK/recover-kill-$component"
  assert_old_converged "startup recovery after kill at $component backup boundary"

  install_old
  if ASTERISM_UPDATE_FAULT="rename:$component:activate" run_update apply --yes \
    >"$WORK/fault-rename-$component" 2>&1; then
    fail "rename fault at $component activation boundary succeeded"
  fi
  assert_old_converged "rename fault at $component activation boundary"
done
ok "signal, kill, and rename faults converge at every component placement boundary"

# Once activation is durably committed, recovery must finish N rather than
# roll back to N-1 even if the process dies while deleting backups.
install_old
if ASTERISM_UPDATE_FAULT='kill:transaction:committed' run_update apply --yes \
  >"$WORK/fault-kill-committed" 2>&1; then
  fail "kill after durable commit succeeded"
fi
run_update status >"$WORK/recover-committed"
for binary in ast astd astd-vz; do
  [ "$(build_of "$PREFIX/bin/$binary")" = 0.0.2+new ] ||
    fail "committed recovery rolled $binary back"
done
[ "$(build_of "$APP/Contents/MacOS/asterism-gui")" = 0.0.2+new ] ||
  fail "committed recovery rolled the app back"
[ ! -e "$HOME_STATE/update-transaction.claim" ] || fail "committed claim was not finalized"
[ -z "$(find "$HOME_STATE" -maxdepth 1 -name 'update-transaction.*' -print -quit 2>/dev/null)" ] ||
  fail "committed private journal was not finalized"
grep -q '^last_build=0.0.2+new$' "$HOME_STATE/update-state.env" ||
  fail "committed recovery did not record the new build"
ok "startup recovery finishes a durably committed activation"

install_old
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

# Linux payload: signed manifest, no vz helper, no app, transactional CHV.
make_linux_release() {
  local version="$1" build="$2" dir stage
  dir="$WORK/releases/linux-$version"
  stage="$WORK/stage-linux-$version"
  rm -rf "$dir" "$stage"
  mkdir -p "$dir" "$stage"
  make_program "$stage/ast" ast "$version" "$build"
  make_program "$stage/astd" astd "$version" "$build"
  printf '#!/bin/sh\necho "cloud-hypervisor v53.0"\n' >"$stage/cloud-hypervisor"
  printf '#!/bin/sh\necho "virtiofsd 1.14.0"\n' >"$stage/virtiofsd"
  chmod +x "$stage/cloud-hypervisor" "$stage/virtiofsd"
  mkdir -p "$stage/guest-gpu/bin" "$stage/guest-gpu/lib"
  printf '#!/bin/sh\necho guest-gpu-%s\n' "$build" >"$stage/guest-gpu/bin/asterism-gpu-guest"
  printf 'libcuda-%s\n' "$build" >"$stage/guest-gpu/lib/libcuda.so.1.0.0"
  ln -s libcuda.so.1.0.0 "$stage/guest-gpu/lib/libcuda.so.1"
  ln -s libcuda.so.1 "$stage/guest-gpu/lib/libcuda.so"
  chmod +x "$stage/guest-gpu/bin/asterism-gpu-guest"
  make_updater "$stage/asterism-update"
  tar -czf "$dir/unit.tar.gz" -C "$stage" ast astd cloud-hypervisor virtiofsd guest-gpu asterism-update
  "$RENDER" stable "$version" "$build" linux-x86_64 \
    "file://$dir/unit.tar.gz" "$(sha "$dir/unit.tar.gz")" \
    "" "" >"$dir/RELEASE.json"
  printf valid >"$dir/RELEASE.json.sig"
}

install_linux_old() {
  PREFIX="$WORK/prefix-linux"
  HOME_STATE="$WORK/home-linux"
  rm -rf "$PREFIX" "$HOME_STATE" "$WORK/activations"
  mkdir -p "$PREFIX/bin" "$PREFIX/libexec/asterism"
  make_program "$PREFIX/bin/ast" ast 0.0.1 0.0.1+old
  make_program "$PREFIX/bin/astd" astd 0.0.1 0.0.1+old
  printf '#!/bin/sh\necho "cloud-hypervisor v53.0 old"\n' >"$PREFIX/bin/cloud-hypervisor"
  printf '#!/bin/sh\necho "virtiofsd 1.14.0 old"\n' >"$PREFIX/bin/virtiofsd"
  chmod +x "$PREFIX/bin/cloud-hypervisor" "$PREFIX/bin/virtiofsd"
  mkdir -p "$PREFIX/bin/guest-gpu/bin" "$PREFIX/bin/guest-gpu/lib"
  printf '#!/bin/sh\necho guest-gpu-old\n' >"$PREFIX/bin/guest-gpu/bin/asterism-gpu-guest"
  printf 'libcuda-old\n' >"$PREFIX/bin/guest-gpu/lib/libcuda.so.1.0.0"
  chmod +x "$PREFIX/bin/guest-gpu/bin/asterism-gpu-guest"
  make_updater "$PREFIX/libexec/asterism/asterism-update"
}

run_linux_update() {
  env \
    ASTERISM_UPDATE_AST_PATH="$PREFIX/bin/ast" \
    ASTERISM_UPDATE_PREFIX="$PREFIX" \
    ASTERISM_UPDATE_TARGET=linux-x86_64 \
    ASTERISM_HOME="$HOME_STATE" \
    ASTERISM_UPDATE_MANIFEST_URL="file://$MANIFEST" \
    ASTERISM_UPDATE_VERIFIER="$VERIFIER" \
    ASTERISM_UPDATE_PUBKEY=test-public-key \
    "$PREFIX/libexec/asterism/asterism-update" "$@"
}

make_linux_release 0.0.2 0.0.2+new
MANIFEST="$WORK/releases/linux-0.0.2/RELEASE.json"
install_linux_old
run_linux_update apply --yes >"$WORK/linux-applied"
[ "$(build_of "$PREFIX/bin/ast")" = 0.0.2+new ] || fail "linux ast did not activate"
[ "$(build_of "$PREFIX/bin/astd")" = 0.0.2+new ] || fail "linux astd did not activate"
[ -x "$PREFIX/bin/cloud-hypervisor" ] || fail "linux update dropped cloud-hypervisor"
[ -x "$PREFIX/bin/virtiofsd" ] || fail "linux update dropped virtiofsd"
[ "$(cat "$PREFIX/bin/guest-gpu/lib/libcuda.so.1.0.0")" = 'libcuda-0.0.2+new' ] \
  || fail "linux update did not activate the matching guest GPU unit"
[ ! -e "$PREFIX/bin/astd-vz" ] || fail "linux update planted a vz helper"
ok "Linux signed update activates ast, astd, CHV and virtiofsd as one unit"

install_linux_old
if ASTERISM_UPDATE_FAIL_AFTER=cloud-hypervisor \
  run_linux_update apply --yes >"$WORK/linux-guest-rollback" 2>&1; then
  fail "injected Linux activation failure unexpectedly succeeded"
fi
[ "$(cat "$PREFIX/bin/guest-gpu/lib/libcuda.so.1.0.0")" = 'libcuda-old' ] \
  || fail "Linux rollback left the new guest GPU unit beside the old daemon"
[ "$(build_of "$PREFIX/bin/astd")" = 0.0.1+old ] \
  || fail "Linux rollback did not restore the old daemon with its guest unit"
ok "Linux update rollback restores guest GPU artifacts with the matching daemon"

install_linux_old
mkdir -p "$PREFIX/share/asterism/artifact.lock"
sleep 30 &
lock_pid=$!
printf '%s\n' "$lock_pid" >"$PREFIX/share/asterism/artifact.lock/owner"
if run_linux_update apply --yes >"$WORK/linux-lock" 2>&1; then
  kill "$lock_pid" >/dev/null 2>&1 || true
  fail "linux update stole the shared artifact lock"
fi
kill "$lock_pid" >/dev/null 2>&1 || true
wait "$lock_pid" >/dev/null 2>&1 || true
grep -q 'artifact lock' "$WORK/linux-lock" || fail "linux lock refusal was silent"
[ "$(build_of "$PREFIX/bin/ast")" = 0.0.1+old ] || fail "lock refusal mutated linux ast"
ok "install/update share one cross-process artifact lock"

echo "UPDATE TEST GREEN — $pass checks"
