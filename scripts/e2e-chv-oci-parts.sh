#!/usr/bin/env bash
# End-to-end for the Linux/KVM native OCI parts lane:
#
#   Secret Service -> opaque handle -> Cloud Hypervisor OCI guest -> the
#   guest-only egress door -> real HTTPS substituted in flight
#
# This is the native counterpart of e2e-profile-oci-keychain.sh, which proves
# the same seam on the macOS/QEMU compatibility lane. What is specific here:
#
#   * the backend is forced to chv, and the gate refuses to run in a
#     userspace where QEMU is installed, so nothing can silently fall back;
#   * the secret source is the FreeDesktop Secret Service, and `ast doctor`
#     has to name it before anything is stored;
#   * the door the bound guest reaches is `GuestEgress::AgentVsock` — the
#     guest's own loopback over this instance's virtio socket — so a value
#     that arrives upstream proves that door and nothing else carried it;
#   * a writable directory part rides along, because parts have to compose.
#
# Scope boundary, deliberate and stated rather than worked around: the
# *remote* volume provider still materialises through qemu-storage-daemon
# until AST-109 lands, so this lane attaches a local directory part only. Two
# device volume fencing over native NBD is its own gate.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export PATH="$HOME/.cargo/bin:$PATH"
cd "$ROOT"

# shellcheck source-path=SCRIPTDIR source=lib/harness.sh
. "$ROOT/scripts/lib/harness.sh"

fail() { echo "CHV OCI PARTS E2E FAIL: $*" >&2; exit 1; }
ok() { echo "ok: $*"; }

[ "$(uname -s)" = Linux ] \
  || harness_skip "the Cloud Hypervisor OCI parts lane is Linux/KVM only"
if [ ! -r /dev/kvm ] || [ ! -w /dev/kvm ]; then
  fail "/dev/kvm is not readable and writable"
fi

# The point of this lane is that the native backend needs nothing from QEMU.
# Asserted before and after, so a lane that quietly grew a dependency during
# the run is caught too.
assert_no_qemu_install() {
  local tool packages prefix
  for tool in qemu-img qemu-system-x86_64 qemu-system-aarch64 \
              qemu-storage-daemon qemu-nbd; do
    if command -v "$tool" >/dev/null 2>&1; then
      fail "$tool is present on PATH; run this gate on a clean native lane"
    fi
    for prefix in /usr/local/bin /usr/bin /usr/sbin; do
      [ ! -e "$prefix/$tool" ] \
        || fail "$prefix/$tool is installed; package inventory is not clean"
    done
  done
  if command -v dpkg-query >/dev/null 2>&1; then
    packages="$(dpkg-query -W -f='${binary:Package} ${db:Status-Abbrev}\n' \
      'qemu*' 2>/dev/null || true)"
    if printf '%s\n' "$packages" | grep -Eq '(^|:)qemu[^[:space:]]* ii '; then
      fail "dpkg still records a QEMU package as installed"
    fi
  fi
}
assert_no_qemu_install

harness_begin chv-oci-parts
harness_binaries "$ROOT"

GUEST_ARTIFACT="${ASTERISM_GUEST_AGENT_ARTIFACT:-$(dirname "$ASTD")/guest/bin/asterism-guest}"
[ -x "$GUEST_ARTIFACT" ] \
  || harness_skip "set ASTERISM_GUEST_AGENT_ARTIFACT to a static $(uname -m) Linux asterism-guest"

export ASTERISM_HOME="${E2E_HOME:-/tmp/ast-chv-oci-parts-$$}"
export ASTERISM_MESH=local
harness_own_home "$ASTERISM_HOME"

BIN="$ASTERISM_HOME/bin"
LOG="$ASTERISM_HOME/astd.log"
EVIDENCE="$ASTERISM_HOME/evidence"
WORKDIR="$ASTERISM_HOME/dirpart"
IMAGE="${E2E_IMAGE:-docker.io/library/nginx:alpine}"
INST=chv-oci-parts
GUEST_DIR=/mnt/asterism-work
SECRET="chv-oci-sentinel-$$-$RANDOM"
SENTINEL="raw-chv-oci-sentinel-$$-$RANDOM-$RANDOM"
SENTINEL_DIGEST="$(printf %s "$SENTINEL" | sha256sum | awk '{print $1}')"
PROFILE_TIMEOUT="${E2E_PROFILE_TIMEOUT:-420}"
HANDLE=
ASTD_PID=
SECRET_CREATED=

cleanup() {
  "$AST" down "$INST" >/dev/null 2>&1 || true
  "$AST" rm "$INST" >/dev/null 2>&1 || true
  if [ -n "$SECRET_CREATED" ]; then
    "$AST" secret rm "$SECRET" >/dev/null 2>&1 || true
  fi
  if [ -n "$ASTD_PID" ]; then
    kill "$ASTD_PID" >/dev/null 2>&1 || true
    wait "$ASTD_PID" 2>/dev/null || true
  fi
  harness_keep_home "$ASTERISM_HOME" home
  harness_keep "$EVIDENCE/backup.json" backup.json
  harness_keep "$EVIDENCE/bugreport.txt" bugreport.txt
  harness_reap
  if [ -n "${KEEP:-}" ]; then
    echo "kept $ASTERISM_HOME for inspection"
  else
    case "$ASTERISM_HOME" in
      /tmp/ast-chv-oci-parts-*|/work/*) rm -rf -- "$ASTERISM_HOME" ;;
      *) echo "refusing to remove unexpected scratch path: $ASTERISM_HOME" >&2 ;;
    esac
  fi
  harness_artifacts_note
}
trap cleanup EXIT

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

start_daemon() {
  "$ASTD" >>"$LOG" 2>&1 &
  ASTD_PID=$!
  local _
  for _ in $(seq 1 150); do
    [ "$(cat "$ASTERISM_HOME/astd.pid" 2>/dev/null || true)" = "$ASTD_PID" ] && return 0
    sleep 0.2
  done
  fail "astd did not come up:"$'\n'"$(tail -40 "$LOG" 2>/dev/null || true)"
}

handle_works() {
  guest "case \"\$ASTERISM_SENTINEL\" in ast-*) ;; *) exit 41 ;; esac
    curl -fsS https://httpbin.org/bearer \\
      -H \"Authorization: Bearer \$ASTERISM_SENTINEL\" \\
      | sed -n 's/.*\"token\": *\"\\([^\"]*\\)\".*/\\1/p' \\
      | tr -d '\\n' | sha256sum | grep -q '$SENTINEL_DIGEST'
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

mkdir -p "$BIN/guest/bin" "$EVIDENCE" "$WORKDIR"
cp "$AST" "$ASTD" "$BIN/"
cp "$GUEST_ARTIFACT" "$BIN/guest/bin/asterism-guest"
chmod 0755 "$BIN/guest/bin/asterism-guest"
AST="$BIN/ast"
ASTD="$BIN/astd"
export AST ASTD

echo "== Cloud Hypervisor OCI parts e2e in $ASTERISM_HOME"

# The store is probed by name on the session bus, and refuses rather than
# falling back to a file. Without a provider there is nothing to gate.
doctor_out="$("$AST" doctor 2>&1)" || true
grep -qF "FreeDesktop Secret Service" <<<"$doctor_out" \
  || fail "doctor did not name the Secret Service store:"$'\n'"$doctor_out"
grep -qE "org.freedesktop.secrets|Secret Service (answered|is on)" <<<"$doctor_out" \
  || fail "doctor did not probe the Secret Service bus name:"$'\n'"$doctor_out"
ok "doctor probes org.freedesktop.secrets and names it as the only store"

harness_cache_image "$AST" "$IMAGE" || fail "could not cache $IMAGE"
harness_seed_images "$ASTERISM_HOME"
start_daemon

expect "create an OCI VM on the native Cloud Hypervisor backend" "$INST  defined" \
  "$AST" create "$INST" --backend chv --image "$IMAGE" \
    --cpus 4 --mem 2G --disk 4G --profile base
expect "the instance records chv and not a compatibility fallback" "machine: chv" \
  "$AST" status "$INST"

expect "attach a writable directory part" "$GUEST_DIR" \
  "$AST" attach "$INST" --volume "$WORKDIR" --at "$GUEST_DIR"

secret_report="$(printf %s "$SENTINEL" | "$AST" secret create "$SECRET" 2>&1)" \
  || fail "creating the Secret Service sentinel:"$'\n'"$secret_report"
SECRET_CREATED=1
grep -qF "$SECRET" <<<"$secret_report" || fail "secret creation did not name $SECRET"
ok "the raw sentinel entered Secret Service through stdin"

expect "bind only an opaque guest handle" "$SECRET -> httpbin.org" \
  "$AST" attach "$INST" --secret "$SECRET" --to httpbin.org \
    --as bearer --env ASTERISM_SENTINEL
expect "boot the bound OCI VM with persistent restart policy" "$INST  running" \
  "$AST" up "$INST" --restart always
harness_assert_backend "$AST" "$INST" chv \
  || fail "the guest is not running on chv"

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

expect "the writable directory part is writable from the guest" "dir-part-ok" \
  guest "echo dir-part-ok > $GUEST_DIR/marker && sync && cat $GUEST_DIR/marker"
[ "$(cat "$WORKDIR/marker" 2>/dev/null || true)" = dir-part-ok ] \
  || fail "the guest's write did not reach the host directory part"
ok "the directory part is shared, not copied"

HANDLE="$(guest 'printenv ASTERISM_SENTINEL')" \
  || fail "the OCI guest did not expose its sentinel handle"
case "$HANDLE" in ast-*) ;; *) fail "the OCI guest got something other than an opaque handle" ;; esac
[ "$HANDLE" != "$SENTINEL" ] \
  || fail "the raw sentinel entered the OCI guest instead of a handle"
ok "the OCI guest sees an opaque handle, not the Secret Service value"

# The proxy for this instance binds no host interface at all: its host end is
# a unix socket, and the guest reaches it through the door on the guest's own
# loopback. Prove both halves before trusting the substitution below.
DOOR="$ASTERISM_HOME/instances/$INST/chv-vsock.sock_1021"
[ -S "$DOOR" ] || fail "the guest egress door is not bound at $DOOR"
PLANE="$ASTERISM_HOME/instances/$INST/egress/proxy.sock"
[ -S "$PLANE" ] || fail "the egress plane bound no unix socket at $PLANE"
if command -v ss >/dev/null 2>&1; then
  if ss -Hltn 2>/dev/null | awk '{print $4}' | grep -qE '(^|:)1021$'; then
    fail "something published TCP port 1021 on this device; the door must not be on the wire"
  fi
  ok "no TCP listener for the door exists on this device"
fi
expect "the guest is pointed at its own loopback, not at a shared address" \
  "http://127.0.0.1:1021" guest 'printenv HTTPS_PROXY'

eventually "the OCI egress proxy substitutes the Secret Service value in flight" \
  "sentinel-handle-works" handle_works

ROOT_DISK="$ASTERISM_HOME/instances/$INST/disk.raw"
[ -f "$ROOT_DISK" ] || fail "the OCI VM has no raw root disk at $ROOT_DISK"
absent_from_sparse "the raw sentinel is absent from the live OCI root disk" \
  "$ROOT_DISK" "$SENTINEL"
"$ROOT/scripts/sparse-contains.py" "$ROOT_DISK" "$HANDLE" \
  || fail "the OCI root disk does not contain its useful opaque handle"
ok "the live OCI root disk contains the handle but not the Secret Service value"
scan_metadata_absence

# Daemon adoption. The VMM keeps running across a daemon it did not notice
# leaving; the new daemon has to re-bind the door from the path the VMM
# already holds, or the next bound request has nowhere to land.
BEFORE_GUEST="$(guest_pid)"
[ -n "$BEFORE_GUEST" ] || fail "no Cloud Hypervisor pid before daemon loss"
kill -9 "$ASTD_PID" 2>/dev/null || true
wait "$ASTD_PID" 2>/dev/null || true
ASTD_PID=
start_daemon
AFTER_GUEST="$(guest_pid)"
[ "$AFTER_GUEST" = "$BEFORE_GUEST" ] \
  || fail "the new daemon did not adopt the running VMM ($BEFORE_GUEST -> $AFTER_GUEST)"
ok "a restarted daemon adopted Cloud Hypervisor pid $AFTER_GUEST in place"
[ -S "$DOOR" ] || fail "adoption did not re-bind the egress door at $DOOR"
expect "the adopted OCI profile still verifies" "this guest is ready" \
  "$AST" profile "$INST" --check
eventually "the opaque handle survives daemon adoption" \
  "sentinel-handle-works" handle_works

expect "write the snapshot control marker" "before-snapshot" \
  guest "mkdir -p /var/lib/asterism && echo before-snapshot > /var/lib/asterism/parts-snapshot-control && sync && cat /var/lib/asterism/parts-snapshot-control"
expect "stop for a consistent snapshot" "$INST  stopped" "$AST" down "$INST"
[ ! -e "$DOOR" ] || fail "stopping the guest left its egress door bound at $DOOR"
ok "stopping the guest takes its egress door down with it"
expect "snapshot the bound OCI root" "$INST  snapshot credential-bound-chv" \
  "$AST" snapshot "$INST" credential-bound-chv
expect "inspect the OCI snapshot" "credential-bound-chv" "$AST" snapshots "$INST"

SNAPSHOT_DIR="$ASTERISM_HOME/instances/$INST/snapshots"
SNAPSHOT="$(find "$SNAPSHOT_DIR" -maxdepth 1 -type f \
  \( -name 'credential-bound-chv.raw' -o -name 'credential-bound-chv.qcow2' \) \
  -print 2>/dev/null || true)"
if [ -z "$SNAPSHOT" ] \
  || [ "$(printf '%s\n' "$SNAPSHOT" | wc -l | tr -d ' ')" != 1 ]; then
  fail "the OCI snapshot did not resolve to one disk image: $SNAPSHOT"
fi
absent_from_sparse "the raw sentinel is absent from the OCI snapshot" \
  "$SNAPSHOT" "$SENTINEL"
"$ROOT/scripts/sparse-contains.py" "$SNAPSHOT" "$HANDLE" \
  || fail "the OCI snapshot lost the opaque handle control"
ok "the OCI snapshot contains the handle but not the Secret Service value"

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
  guest "echo after-snapshot > /var/lib/asterism/parts-snapshot-control && sync && cat /var/lib/asterism/parts-snapshot-control"
expect "stop before restore" "$INST  stopped" "$AST" down "$INST"
expect "restore the OCI snapshot" "$INST  restored to credential-bound-chv" \
  "$AST" restore "$INST" credential-bound-chv
expect "boot the restored OCI VM" "$INST  running" "$AST" up "$INST"
expect "restore returned the OCI disk marker" "before-snapshot" \
  guest "cat /var/lib/asterism/parts-snapshot-control"
expect "the restored OCI profile still verifies" "this guest is ready" \
  "$AST" profile "$INST" --check
eventually "the restored OCI handle still resolves through the door" \
  "sentinel-handle-works" handle_works

# Detach revokes before the plane is rebuilt: the door survives, the socket it
# would splice onto does not, and the guest's handle stops resolving.
expect "detach the secret part" "$SECRET" "$AST" detach "$INST" --secret "$SECRET"
[ ! -e "$PLANE" ] \
  || fail "detach left the egress plane's socket in place at $PLANE"
ok "detach removed the plane's socket, so the door now splices onto nothing"

bugreport="$("$AST" bugreport 2>&1)" || fail "ast bugreport failed:"$'\n'"$bugreport"
printf '%s\n' "$bugreport" >"$EVIDENCE/bugreport.txt"
grep -qF "$INST" <<<"$bugreport" || fail "bugreport omitted the OCI instance"
grep -qF "profiles=base" <<<"$bugreport" || fail "bugreport omitted the base profile"
if grep -qF "$SENTINEL" <<<"$bugreport"; then fail "bugreport contains the raw sentinel"; fi
if grep -qF "$HANDLE" <<<"$bugreport"; then fail "bugreport contains a guest handle"; fi
scan_metadata_absence
ok "bugreport contains neither value nor handle; persisted metadata contains no Secret Service value"

expect "stop the completed OCI lane" "$INST  stopped" "$AST" down "$INST"
expect "remove the completed OCI lane" "$INST  removed" "$AST" rm "$INST"

assert_no_qemu_install
echo "CHV OCI PARTS GREEN ($IMAGE, chv; door 127.0.0.1:1021 over vsock 1021)"
