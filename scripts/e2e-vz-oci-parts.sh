#!/usr/bin/env bash
# End-to-end for the native VZ OCI parts lane: directory part, base@2, and a
# bound Keychain secret served through the guest's own virtio-socket door.
#
# This is the VZ half of what scripts/e2e-profile-oci-keychain.sh proved on
# the QEMU compatibility backend. Everything about the secret contract is the
# same; the one thing that is different is the only thing this lane exists
# for. QEMU's door is its user-mode NAT gateway, proxied to host loopback. VZ
# has no such path — its guests share a NAT bridge — so the door is the
# guest's own loopback, carried out over this instance's virtio socket to the
# signed helper and spliced onto a private unix socket. See
# docs/adr/0003-vz-egress-door.md.
#
# So this script additionally asserts, and would fail without:
#
#   * the VMM process really is astd-vz, never a QEMU fallback
#   * the guest's proxy is 127.0.0.1, not a bridge address
#   * the host end of the door is a unix socket, and NOTHING on this device
#     is listening on a TCP port for it
#   * real HTTPS to a real endpoint is substituted only through that door
#
# `--backend vz` is forced everywhere, so a device that cannot run VZ fails
# this lane rather than quietly proving QEMU again.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export PATH="$HOME/.cargo/bin:$PATH"
cd "$ROOT"

# shellcheck source-path=SCRIPTDIR
. "$ROOT/scripts/lib/harness.sh"
harness_begin vz-oci-parts
harness_binaries "$ROOT"

[ "$(uname -s)" = Darwin ] \
  || harness_skip "Virtualization.framework and the login Keychain are macOS-only"

# Builds and signs the helper. Without the entitlement `--backend vz` refuses
# before anything is created. Skipped when the binaries under test came from
# somewhere else: astd looks for astd-vz beside itself, so signing this tree's
# helper would prove nothing about theirs.
if [ -z "${AST_BIN:-}" ]; then
  "$ROOT/scripts/sign-vz.sh"
fi

GUEST_ARTIFACT="${ASTERISM_GUEST_AGENT_ARTIFACT:-$(dirname "$ASTD")/guest/bin/asterism-guest}"
[ -x "$GUEST_ARTIFACT" ] \
  || harness_skip "set ASTERISM_GUEST_AGENT_ARTIFACT to a static $(uname -m) Linux asterism-guest"

# Short home on purpose: unix socket paths are capped near 104 bytes, and both
# the helper's control socket and this lane's egress door live under it.
export ASTERISM_HOME="/private/tmp/ast-vzparts-$$"
export ASTERISM_MESH=local
export ASTERISM_TEST_SERVICE_LABEL="com.asterism.astd.test.vzparts.$$.$RANDOM"
mkdir -p "$ASTERISM_HOME"
harness_own_home "$ASTERISM_HOME"

BIN="$ASTERISM_HOME/bin"
LOG="$ASTERISM_HOME/astd.log"
EVIDENCE="$ASTERISM_HOME/evidence"
SHARE="$ASTERISM_HOME/part"
IMAGE="${E2E_IMAGE:-docker.io/library/nginx:alpine}"
INST=vzparts
SECRET="vzparts-sentinel-$$-$RANDOM"
SENTINEL="raw-vzparts-sentinel-$$-$RANDOM-$RANDOM"
SENTINEL_DIGEST="$(printf %s "$SENTINEL" | shasum -a 256 | awk '{print $1}')"
HOST_MARKER="vzparts-host-$$-$RANDOM"
GUEST_MARKER="vzparts-guest-$$-$RANDOM"
PROFILE_TIMEOUT="${E2E_PROFILE_TIMEOUT:-300}"
DOOR_PORT=1021
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
  harness_keep "$EVIDENCE/bugreport.txt" bugreport.txt
  harness_reap
  if [ -n "${KEEP:-}" ]; then
    echo "kept $ASTERISM_HOME for inspection"
  else
    case "$ASTERISM_HOME" in
      /private/tmp/ast-vzparts.*|/private/tmp/ast-vzparts-*) rm -rf -- "$ASTERISM_HOME" ;;
      *) echo "refusing to remove unexpected scratch path: $ASTERISM_HOME" >&2 ;;
    esac
  fi
  harness_artifacts_note
}
trap cleanup EXIT

fail() { echo "VZ OCI PARTS E2E FAIL: $*" >&2; exit 1; }
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

# The VMM is the signed helper and nothing else. A lane that silently ran on
# QEMU would pass every other assertion in this file.
assert_native_vmm() {
  local pid comm
  pid="$(guest_pid)"
  [ -n "$pid" ] || fail "$1: no running VMM pid"
  comm="$(ps -o comm= -p "$pid" 2>/dev/null || true)"
  case "$comm" in
    *astd-vz) ok "$1: the VMM process is $comm ($pid)" ;;
    *) fail "$1: the VMM is $comm, not astd-vz — this lane never falls back to QEMU" ;;
  esac
}

handle_works() {
  guest "case \"\$ASTERISM_SENTINEL\" in ast-*) ;; *) exit 41 ;; esac
    curl -fsS https://httpbin.org/bearer \\
      -H \"Authorization: Bearer \$ASTERISM_SENTINEL\" \\
      | jq -j .token | sha256sum | grep -q '$SENTINEL_DIGEST' \\
      && echo sentinel-handle-works"
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

mkdir -p "$BIN/guest/bin" "$EVIDENCE" "$SHARE"
cp "$AST" "$ASTD" "$BIN/"
if [ -x "$(dirname "$ASTD")/astd-vz" ]; then
  cp "$(dirname "$ASTD")/astd-vz" "$BIN/astd-vz"
else
  fail "no astd-vz beside $ASTD — run scripts/sign-vz.sh"
fi
cp "$GUEST_ARTIFACT" "$BIN/guest/bin/asterism-guest"
chmod 0755 "$BIN/guest/bin/asterism-guest"
AST="$BIN/ast"
ASTD="$BIN/astd"
export AST ASTD

SERVICE_UNIT="$HOME/Library/LaunchAgents/$ASTERISM_TEST_SERVICE_LABEL.plist"
[ ! -e "$SERVICE_UNIT" ] \
  || fail "$SERVICE_UNIT already exists — refusing to disturb it"

echo "== VZ OCI parts + Keychain e2e in $ASTERISM_HOME"
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

expect "create an OCI VM on the native VZ backend" "$INST  defined" \
  "$AST" create "$INST" --backend vz --image "$IMAGE" \
    --cpus 4 --mem 2G --disk 4G --profile base
expect "the instance really recorded vz" "machine: vz" "$AST" status "$INST"
expect "its source remains an OCI rootfs" "oci rootfs, direct kernel boot" \
  "$AST" status "$INST"

# ---- the directory part ----------------------------------------------------
#
# Mounted over nginx's entrypoint hook directory so the image itself does both
# halves of the proof before the server starts: read host bytes, write a guest
# marker the host can then see.
printf '%s\n' "$HOST_MARKER" >"$SHARE/host-marker"
cat >"$SHARE/10-asterism-virtiofs-proof.sh" <<EOF
#!/bin/sh
set -eu
cd /docker-entrypoint.d
grep -qF '$HOST_MARKER' host-marker
printf '%s\n' '$GUEST_MARKER' > guest-marker
sync
echo 'asterism: virtiofs part read-write succeeded'
EOF
chmod +x "$SHARE/10-asterism-virtiofs-proof.sh"
expect "attach a same-device directory part" "/docker-entrypoint.d" \
  "$AST" attach "$INST" --volume "$SHARE" --at /docker-entrypoint.d

# ---- the bound secret ------------------------------------------------------
secret_report="$(printf %s "$SENTINEL" | "$AST" secret create "$SECRET" 2>&1)" \
  || fail "creating the Keychain sentinel:"$'\n'"$secret_report"
SECRET_CREATED=1
grep -qF "$SECRET" <<<"$secret_report" \
  || fail "secret creation did not name $SECRET"
ok "the raw sentinel entered the login Keychain through stdin"

# The refusal this whole change removes. If it comes back, everything below
# it is meaningless, so it is asserted as an affordance rather than assumed.
expect "bind only an opaque guest handle on vz" "$SECRET -> httpbin.org" \
  "$AST" attach "$INST" --secret "$SECRET" --to httpbin.org \
    --as bearer --env ASTERISM_SENTINEL

expect "boot the bound OCI VM with persistent restart policy" "$INST  running" \
  "$AST" up "$INST" --restart always
assert_native_vmm "first boot"

eventually "the VZ guest read and wrote through the directory part" \
  "asterism: virtiofs part read-write succeeded" "$AST" logs "$INST" -n 400
expect "the guest marker reached the host through virtiofs" "$GUEST_MARKER" \
  cat "$SHARE/guest-marker"

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
ok "base@2 verifies over authenticated OCI guest control on vz"

# ---- the door itself -------------------------------------------------------
GUEST_PROXY="$(guest 'printenv HTTPS_PROXY')" \
  || fail "the VZ guest has no HTTPS_PROXY"
[ "$GUEST_PROXY" = "http://127.0.0.1:$DOOR_PORT" ] \
  || fail "the guest was pointed at $GUEST_PROXY, not its own loopback"
ok "the guest reaches the door at its own loopback ($GUEST_PROXY)"

DOOR_SOCKET="$ASTERISM_HOME/instances/$INST/egress/proxy.sock"
[ -S "$DOOR_SOCKET" ] \
  || fail "the host end of the door is not a unix socket at $DOOR_SOCKET"
ok "the host end of the door is a unix socket, not a port"

# The whole reason this door exists. A listener on the VZ bridge address would
# be reachable by every other guest on it; there must be no TCP listener at
# all, on any address, for the door's port.
if lsof -nP -iTCP:"$DOOR_PORT" -sTCP:LISTEN 2>/dev/null | grep -q .; then
  lsof -nP -iTCP:"$DOOR_PORT" -sTCP:LISTEN
  fail "something on this device is listening on TCP $DOOR_PORT"
fi
ok "nothing on this device listens on TCP $DOOR_PORT — the door is not on the wire"

HANDLE="$(guest 'printenv ASTERISM_SENTINEL')" \
  || fail "the OCI guest did not expose its sentinel handle"
case "$HANDLE" in ast-*) ;; *) fail "the OCI guest got something other than an opaque handle" ;; esac
[ "$HANDLE" != "$SENTINEL" ] \
  || fail "the raw sentinel entered the OCI guest instead of a handle"
ok "the VZ OCI guest sees an opaque handle, not the Keychain value"

eventually "real HTTPS is substituted only through the vsock door" \
  "sentinel-handle-works" handle_works

ROOT_DISK="$ASTERISM_HOME/instances/$INST/disk.raw"
[ -f "$ROOT_DISK" ] || fail "the VZ OCI VM has no raw root disk at $ROOT_DISK"
absent_from_sparse "the raw sentinel is absent from the live OCI root disk" \
  "$ROOT_DISK" "$SENTINEL"
"$ROOT/scripts/sparse-contains.py" "$ROOT_DISK" "$HANDLE" \
  || fail "the OCI root disk does not contain its useful opaque handle"
ok "the live OCI root disk contains the handle but not the Keychain value"
scan_metadata_absence

# ---- daemon and VMM loss ---------------------------------------------------
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

# A daemon restart alone, with the guest left alive: the helper outlives astd
# and the door has to be reclaimed under a still-running guest.
expect "the adopted guest is still the same VZ guest" "machine: vz" \
  "$AST" status "$INST"
assert_native_vmm "after daemon adoption"
eventually "the door still serves the adopted guest" \
  "sentinel-handle-works" handle_works

BEFORE_DAEMON="$ASTD_PID"
BEFORE_GUEST="$(guest_pid)"
[ -n "$BEFORE_GUEST" ] || fail "no astd-vz pid before host-equivalent loss"
kill -STOP "$BEFORE_DAEMON"
kill -9 "$BEFORE_GUEST"
kill -9 "$BEFORE_DAEMON"
ASTD_PID=
wait_daemon_pid "$BEFORE_DAEMON" || fail "launchd did not resurrect astd"
AFTER_GUEST="$(wait_guest_pid "$BEFORE_GUEST")" \
  || fail "the resurrected daemon did not recreate the VZ OCI VM"
ok "launchd resurrected astd; astd recreated astd-vz as $AFTER_GUEST"
assert_native_vmm "after daemon+VMM loss"
expect "the resurrected OCI profile still verifies" "this guest is ready" \
  "$AST" profile "$INST" --check
eventually "the opaque handle survives daemon and VZ guest resurrection" \
  "sentinel-handle-works" handle_works

# ---- snapshot and restore --------------------------------------------------
expect "write the snapshot control marker" "before-snapshot" \
  guest "mkdir -p /var/lib/asterism && echo before-snapshot > /var/lib/asterism/vzparts-control && sync && cat /var/lib/asterism/vzparts-control"
expect "stop for a consistent snapshot" "$INST  stopped" "$AST" down "$INST"
expect "snapshot the bound OCI root" "$INST  snapshot credential-bound-vz" \
  "$AST" snapshot "$INST" credential-bound-vz

SNAPSHOT_DIR="$ASTERISM_HOME/instances/$INST/snapshots"
SNAPSHOT="$(find "$SNAPSHOT_DIR" -maxdepth 1 -type f -name 'credential-bound-vz.raw' -print 2>/dev/null || true)"
if [ -z "$SNAPSHOT" ] \
  || [ "$(printf '%s\n' "$SNAPSHOT" | wc -l | tr -d ' ')" != 1 ]; then
  fail "the OCI snapshot did not resolve to one raw disk: $SNAPSHOT"
fi
absent_from_sparse "the raw sentinel is absent from the OCI snapshot" \
  "$SNAPSHOT" "$SENTINEL"
"$ROOT/scripts/sparse-contains.py" "$SNAPSHOT" "$HANDLE" \
  || fail "the OCI snapshot lost the opaque handle control"
ok "the OCI snapshot contains the handle but not the Keychain value"

expect "boot after the snapshot" "$INST  running" "$AST" up "$INST"
assert_native_vmm "after snapshot"
expect "change the live OCI disk" "after-snapshot" \
  guest "echo after-snapshot > /var/lib/asterism/vzparts-control && sync && cat /var/lib/asterism/vzparts-control"
expect "stop before restore" "$INST  stopped" "$AST" down "$INST"
expect "restore the OCI snapshot" "$INST  restored to credential-bound-vz" \
  "$AST" restore "$INST" credential-bound-vz
expect "boot the restored OCI VM" "$INST  running" "$AST" up "$INST"
assert_native_vmm "after restore"
expect "restore returned the OCI disk marker" "before-snapshot" \
  guest "cat /var/lib/asterism/vzparts-control"
expect "the restored OCI profile still verifies" "this guest is ready" \
  "$AST" profile "$INST" --check
eventually "the restored handle still resolves through the vsock door" \
  "sentinel-handle-works" handle_works

# ---- detach fails closed ---------------------------------------------------
expect "detach the secret" "$SECRET" "$AST" detach "$INST" --secret "$SECRET"
REFUSED=
for _ in $(seq 1 20); do
  if ! handle_works >/dev/null 2>&1; then
    REFUSED=1
    break
  fi
  sleep 3
done
[ -n "$REFUSED" ] || fail "the door still honoured a detached handle"
ok "the detached handle is no longer substituted by the door"
still="$(guest 'printenv ASTERISM_SENTINEL')" || still=
[ "$still" != "$SENTINEL" ] \
  || fail "detach left the raw value in the running guest"
ok "the running guest still holds only its opaque handle, which now means nothing"

# ---- diagnostics -----------------------------------------------------------
bugreport="$("$AST" bugreport 2>&1)" || fail "ast bugreport failed:"$'\n'"$bugreport"
printf '%s\n' "$bugreport" >"$EVIDENCE/bugreport.txt"
grep -qF "$INST" <<<"$bugreport" || fail "bugreport omitted the OCI instance"
grep -qF "profiles=base" <<<"$bugreport" || fail "bugreport omitted the base profile"
if grep -qF "$SENTINEL" <<<"$bugreport"; then fail "bugreport contains the raw sentinel"; fi
if grep -qF "$HANDLE" <<<"$bugreport"; then fail "bugreport contains a guest handle"; fi
scan_metadata_absence
ok "bugreport contains neither value nor handle"

expect "stop the completed VZ OCI lane" "$INST  stopped" "$AST" down "$INST"
expect "remove the completed VZ OCI lane" "$INST  removed" "$AST" rm "$INST"
echo "VZ OCI PARTS E2E GREEN ($IMAGE, vz, vsock egress door)"
