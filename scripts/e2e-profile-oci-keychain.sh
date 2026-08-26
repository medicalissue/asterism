#!/usr/bin/env bash
# End-to-end for the macOS Keychain -> opaque handle -> OCI VM path.
#
# This is intentionally narrower than e2e-profile.sh's cloud-image lane. It
# proves the OCI-specific seam that lane cannot: a value held by the login
# Keychain remains outside an OCI root disk, snapshot, backup and diagnostic
# output while an authenticated guest-control command uses its handle before
# and after daemon+VM resurrection and snapshot restore.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export PATH="$HOME/.cargo/bin:$PATH"
cd "$ROOT"

# shellcheck source-path=SCRIPTDIR
. "$ROOT/scripts/lib/harness.sh"
harness_begin profile-oci-keychain
harness_binaries "$ROOT"

[ "$(uname -s)" = Darwin ] \
  || harness_skip "the OCI secret source in this lane is the macOS login Keychain"
case "$(uname -m)" in
  arm64) QEMU_SYSTEM=qemu-system-aarch64 ;;
  x86_64) QEMU_SYSTEM=qemu-system-x86_64 ;;
  *) harness_skip "no QEMU system binary is known for $(uname -m)" ;;
esac
command -v "$QEMU_SYSTEM" >/dev/null 2>&1 \
  || harness_skip "$QEMU_SYSTEM is required for the macOS OCI compatibility lane"

GUEST_ARTIFACT="${ASTERISM_GUEST_AGENT_ARTIFACT:-$(dirname "$ASTD")/guest/bin/asterism-guest}"
[ -x "$GUEST_ARTIFACT" ] \
  || harness_skip "set ASTERISM_GUEST_AGENT_ARTIFACT to a static $(uname -m) Linux asterism-guest"

TMP_BASE="${TMPDIR:-/private/tmp}"
TMP_BASE="${TMP_BASE%/}"
export ASTERISM_HOME
ASTERISM_HOME="$(mktemp -d "$TMP_BASE/ast-profile-oci.XXXXXX")"
export ASTERISM_MESH=local
export ASTERISM_TEST_SERVICE_LABEL="com.asterism.astd.test.profile-oci.$$.$RANDOM"
harness_own_home "$ASTERISM_HOME"

BIN="$ASTERISM_HOME/bin"
LOG="$ASTERISM_HOME/astd.log"
EVIDENCE="$ASTERISM_HOME/evidence"
IMAGE="${E2E_IMAGE:-docker.io/library/nginx:alpine}"
INST=profile-oci
SECRET="profile-oci-sentinel-$$-$RANDOM"
SENTINEL="raw-profile-oci-sentinel-$$-$RANDOM-$RANDOM"
SENTINEL_DIGEST="$(printf %s "$SENTINEL" | shasum -a 256 | awk '{print $1}')"
PROFILE_TIMEOUT="${E2E_PROFILE_TIMEOUT:-300}"
HANDLE=
ASTD_PID=
SERVICE_INSTALLED=
SECRET_CREATED=

cleanup() {
  "$AST" down "$INST" >/dev/null 2>&1 || true
  "$AST" rm "$INST" >/dev/null 2>&1 || true
  if [ -n "$SECRET_CREATED" ]; then
    "$AST" secret rm "$SECRET" >/dev/null 2>&1 || true
  fi
  if [ -n "$SERVICE_INSTALLED" ]; then
    "$AST" service uninstall >/dev/null 2>&1 || true
  fi
  harness_keep_home "$ASTERISM_HOME" home
  harness_keep "$EVIDENCE/backup.json" backup.json
  harness_keep "$EVIDENCE/bugreport.txt" bugreport.txt
  harness_reap
  if [ -n "${KEEP:-}" ]; then
    echo "kept $ASTERISM_HOME for inspection"
  elif [ "$(dirname "$ASTERISM_HOME")" = "$TMP_BASE" ]; then
    case "$(basename "$ASTERISM_HOME")" in
      ast-profile-oci.*) rm -rf -- "$ASTERISM_HOME" ;;
      *) echo "refusing to remove unexpected scratch path: $ASTERISM_HOME" >&2 ;;
    esac
  fi
  harness_artifacts_note
}
trap cleanup EXIT

fail() { echo "PROFILE OCI KEYCHAIN E2E FAIL: $*" >&2; exit 1; }
ok() { echo "ok: $*"; }

expect() {
  local desc="$1" needle="$2"; shift 2
  local out
  out="$("$@" 2>&1)" || fail "$desc: command failed:"$'\n'"$out"
  grep -qF "$needle" <<<"$out" || fail "$desc: expected \"$needle\" in:"$'\n'"$out"
  ok "$desc"
}

eventually() {
  local desc="$1" needle="$2"; shift 2
  local out=
  for _ in $(seq 1 60); do
    out="$("$@" 2>&1)" || true
    if grep -qF "$needle" <<<"$out"; then ok "$desc"; return 0; fi
    sleep 3
  done
  fail "$desc: waited three minutes for \"$needle\" in:"$'\n'"$out"
}

absent_from_sparse() {
  local desc="$1" file="$2" needle="$3" status
  if "$ROOT/scripts/sparse-contains.py" "$file" "$needle"; then
    fail "$desc: found forbidden bytes in $file"
  else
    status=$?
  fi
  [ "$status" -eq 1 ] \
    || fail "$desc: sparse inspection could not prove absence (status $status)"
  ok "$desc"
}

guest() { "$AST" exec "$INST" -- /bin/sh -c "$1"; }

guest_pid() {
  "$AST" status "$INST" 2>/dev/null | sed -n 's/^running: .* pid \([0-9]*\),.*/\1/p'
}

wait_daemon_pid() {
  local old="$1" now
  for _ in $(seq 1 150); do
    now="$(cat "$ASTERISM_HOME/astd.pid" 2>/dev/null || true)"
    if [ -n "$now" ] && [ "$now" != "$old" ] && kill -0 "$now" 2>/dev/null; then
      ASTD_PID="$now"
      return 0
    fi
    sleep 0.2
  done
  return 1
}

wait_guest_pid() {
  local old="$1" now
  for _ in $(seq 1 120); do
    now="$(guest_pid)"
    if [ -n "$now" ] && [ "$now" != "$old" ] && kill -0 "$now" 2>/dev/null; then
      echo "$now"
      return 0
    fi
    sleep 1
  done
  return 1
}

handle_works() {
  guest "case \"\$ASTERISM_SENTINEL\" in ast-*) ;; *) exit 41 ;; esac
    curl -fsS https://httpbin.org/bearer \\
      -H \"Authorization: Bearer \$ASTERISM_SENTINEL\" \\
      | jq -j .token | sha256sum | grep -q '$SENTINEL_DIGEST'
    echo sentinel-handle-works"
}

scan_metadata_absence() {
  local file
  while IFS= read -r file; do
    case "$file" in
      *.raw|*.qcow2|*.vhdx) continue ;;
    esac
    if LC_ALL=C grep -aFq "$SENTINEL" "$file"; then
      fail "the raw sentinel entered Asterism metadata or logs: $file"
    fi
  done < <(find "$ASTERISM_HOME" -type f -print)
  ok "the raw sentinel is absent from registry, metadata and logs"
}

mkdir -p "$BIN/guest/bin" "$EVIDENCE"
cp "$AST" "$ASTD" "$BIN/"
cp "$GUEST_ARTIFACT" "$BIN/guest/bin/asterism-guest"
chmod 0755 "$BIN/guest/bin/asterism-guest"
AST="$BIN/ast"
ASTD="$BIN/astd"
export AST ASTD

SERVICE_UNIT="$HOME/Library/LaunchAgents/$ASTERISM_TEST_SERVICE_LABEL.plist"
[ ! -e "$SERVICE_UNIT" ] \
  || fail "$SERVICE_UNIT already exists — refusing to disturb it"

echo "== OCI profile + Keychain e2e in $ASTERISM_HOME"
expect "doctor names the login Keychain with no file fallback" \
  "macOS login Keychain answered list-keychains; no file fallback" "$AST" doctor

harness_cache_image "$AST" "$IMAGE" || fail "could not cache $IMAGE"
harness_seed_images "$ASTERISM_HOME"

"$ASTD" >>"$LOG" 2>&1 &
ASTD_PID=$!
for _ in $(seq 1 100); do
  [ "$(cat "$ASTERISM_HOME/astd.pid" 2>/dev/null || true)" = "$ASTD_PID" ] && break
  sleep 0.2
done
[ "$(cat "$ASTERISM_HOME/astd.pid" 2>/dev/null || true)" = "$ASTD_PID" ] \
  || fail "astd did not come up:"$'\n'"$(cat "$LOG" 2>/dev/null || true)"

expect "create an OCI VM on the QEMU compatibility backend" "$INST  defined" \
  "$AST" create "$INST" --backend qemu --image "$IMAGE" \
    --cpus 4 --mem 2G --disk 4G --profile base

secret_report="$(printf %s "$SENTINEL" | "$AST" secret create "$SECRET" 2>&1)" \
  || fail "creating the Keychain sentinel:"$'\n'"$secret_report"
SECRET_CREATED=1
grep -qF "$SECRET" <<<"$secret_report" \
  || fail "secret creation did not name $SECRET"
ok "the raw sentinel entered the login Keychain through stdin"

expect "bind only an opaque guest handle" "$SECRET -> httpbin.org" \
  "$AST" attach "$INST" --secret "$SECRET" --to httpbin.org \
    --as bearer --env ASTERISM_SENTINEL
expect "boot the bound OCI VM with persistent restart policy" "$INST  running" \
  "$AST" up "$INST" --restart always

echo "waiting up to ${PROFILE_TIMEOUT}s for the OCI base profile ..."
deadline=$(( $(date +%s) + PROFILE_TIMEOUT ))
profile_report=
while :; do
  if profile_report="$("$AST" profile "$INST" --check 2>&1)"; then break; fi
  if [ "$(date +%s)" -ge "$deadline" ]; then
    echo "$profile_report"
    fail "the OCI base profile did not become ready"
  fi
  sleep 5
done
for needle in "ok    git" "ok    tmux" "not applicable (guest control)" \
              "no agent credential file" "this guest is ready"; do
  grep -qF "$needle" <<<"$profile_report" \
    || fail "the OCI profile verifier did not report '$needle':"$'\n'"$profile_report"
done
ok "base@2 verifies over authenticated OCI guest control"

HANDLE="$(guest 'printenv ASTERISM_SENTINEL')" \
  || fail "the OCI guest did not expose its sentinel handle"
case "$HANDLE" in ast-*) ;; *) fail "the OCI guest got something other than an opaque handle" ;; esac
[ "$HANDLE" != "$SENTINEL" ] \
  || fail "the raw sentinel entered the OCI guest instead of a handle"
ok "the OCI guest sees an opaque handle, not the Keychain value"
eventually "the OCI egress proxy substitutes the Keychain value in flight" \
  "sentinel-handle-works" handle_works

ROOT_DISK="$ASTERISM_HOME/instances/$INST/disk.raw"
[ -f "$ROOT_DISK" ] || fail "the OCI VM has no raw root disk at $ROOT_DISK"
absent_from_sparse "the raw sentinel is absent from the live OCI root disk" \
  "$ROOT_DISK" "$SENTINEL"
"$ROOT/scripts/sparse-contains.py" "$ROOT_DISK" "$HANDLE" \
  || fail "the OCI root disk does not contain its useful opaque handle"
ok "the live OCI root disk contains the handle but not the Keychain value"
scan_metadata_absence

# Move ownership to the isolated launchd label, then make both daemon and VMM
# disappear. The lane recorded restart=always at the first boot, so neither an
# explicit `ast up` nor a new secret attachment should be needed.
OLD_DAEMON="$ASTD_PID"
kill -9 "$ASTD_PID" 2>/dev/null || true
wait "$ASTD_PID" 2>/dev/null || true
ASTD_PID=
SERVICE_INSTALLED=1
service_report="$("$AST" service install 2>&1)" \
  || fail "installing the scratch astd service:"$'\n'"$service_report"
grep -qF "is installed as" <<<"$service_report" \
  || fail "service install did not report its mechanism:"$'\n'"$service_report"
wait_daemon_pid "$OLD_DAEMON" || fail "launchd did not start the scratch astd"

BEFORE_DAEMON="$ASTD_PID"
BEFORE_GUEST="$(guest_pid)"
[ -n "$BEFORE_GUEST" ] || fail "no QEMU pid before host-equivalent loss"
kill -STOP "$BEFORE_DAEMON"
kill -9 "$BEFORE_GUEST"
kill -9 "$BEFORE_DAEMON"
ASTD_PID=
wait_daemon_pid "$BEFORE_DAEMON" || fail "launchd did not resurrect astd"
AFTER_GUEST="$(wait_guest_pid "$BEFORE_GUEST")" \
  || fail "the resurrected daemon did not recreate the OCI VM"
ok "launchd resurrected astd; astd recreated QEMU as $AFTER_GUEST"
expect "the resurrected OCI profile still verifies" "this guest is ready" \
  "$AST" profile "$INST" --check
eventually "the opaque handle survives daemon and OCI VM resurrection" \
  "sentinel-handle-works" handle_works

expect "write the snapshot control marker" "before-snapshot" \
  guest "mkdir -p /var/lib/asterism && echo before-snapshot > /var/lib/asterism/profile-snapshot-control && sync && cat /var/lib/asterism/profile-snapshot-control"
expect "stop for a consistent snapshot" "$INST  stopped" "$AST" down "$INST"
expect "snapshot the bound OCI root" "$INST  snapshot credential-bound-oci" \
  "$AST" snapshot "$INST" credential-bound-oci
expect "inspect the OCI snapshot" "credential-bound-oci" "$AST" snapshots "$INST"

SNAPSHOT_DIR="$ASTERISM_HOME/instances/$INST/snapshots"
SNAPSHOT="$(find "$SNAPSHOT_DIR" -maxdepth 1 -type f \
  \( -name 'credential-bound-oci.raw' -o -name 'credential-bound-oci.qcow2' \
     -o -name 'credential-bound-oci.vhdx' \) -print 2>/dev/null || true)"
[ -n "$SNAPSHOT" ] && [ "$(printf '%s\n' "$SNAPSHOT" | wc -l | tr -d ' ')" = 1 ] \
  || fail "the OCI snapshot did not resolve to one disk image: $SNAPSHOT"
absent_from_sparse "the raw sentinel is absent from the OCI snapshot" \
  "$SNAPSHOT" "$SENTINEL"
"$ROOT/scripts/sparse-contains.py" "$SNAPSHOT" "$HANDLE" \
  || fail "the OCI snapshot lost the opaque handle control"
ok "the OCI snapshot contains the handle but not the Keychain value"

BACKUP="$EVIDENCE/backup"
expect "export the stopped bound OCI instance" "exported" \
  "$AST" backup export "$INST" "$BACKUP"
"$AST" backup inspect "$BACKUP" --json >"$EVIDENCE/backup.json"
if LC_ALL=C grep -R -aFq "$SENTINEL" "$BACKUP"; then
  fail "the portable backup's content-addressed chunks contain the raw sentinel"
fi
ok "the raw sentinel is absent from the portable OCI backup chunks"
if grep -aFq "$SENTINEL" "$EVIDENCE/backup.json"; then
  fail "the portable backup manifest contains the raw sentinel"
fi
if grep -aFq "$HANDLE" "$EVIDENCE/backup.json"; then
  fail "the portable backup manifest contains the host-bound handle"
fi
ok "the portable backup manifest exports neither value nor handle"

expect "boot after the snapshot" "$INST  running" "$AST" up "$INST"
expect "change the live OCI disk" "after-snapshot" \
  guest "echo after-snapshot > /var/lib/asterism/profile-snapshot-control && sync && cat /var/lib/asterism/profile-snapshot-control"
expect "stop before restore" "$INST  stopped" "$AST" down "$INST"
expect "restore the OCI snapshot" "$INST  restored to credential-bound-oci" \
  "$AST" restore "$INST" credential-bound-oci
expect "boot the restored OCI VM" "$INST  running" "$AST" up "$INST"
expect "restore returned the OCI disk marker" "before-snapshot" \
  guest "cat /var/lib/asterism/profile-snapshot-control"
expect "the restored OCI profile still verifies" "this guest is ready" \
  "$AST" profile "$INST" --check
eventually "the restored OCI handle still resolves through the proxy" \
  "sentinel-handle-works" handle_works

bugreport="$("$AST" bugreport 2>&1)" || fail "ast bugreport failed:"$'\n'"$bugreport"
printf '%s\n' "$bugreport" >"$EVIDENCE/bugreport.txt"
grep -qF "$INST" <<<"$bugreport" || fail "bugreport omitted the OCI instance"
grep -qF "profiles=base" <<<"$bugreport" || fail "bugreport omitted the base profile"
if grep -qF "$SENTINEL" <<<"$bugreport"; then fail "bugreport contains the raw sentinel"; fi
if grep -qF "$HANDLE" <<<"$bugreport"; then fail "bugreport contains a guest handle"; fi
scan_metadata_absence
ok "bugreport contains neither value nor handle; persisted metadata contains no Keychain value"

expect "stop the completed OCI lane" "$INST  stopped" "$AST" down "$INST"
expect "remove the completed OCI lane" "$INST  removed" "$AST" rm "$INST"
echo "PROFILE OCI KEYCHAIN E2E GREEN ($IMAGE, qemu)"
