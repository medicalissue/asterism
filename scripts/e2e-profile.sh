#!/usr/bin/env bash
# End-to-end for bootstrap profiles, with a real boot and a real install.
#
# The claim a profile makes is not "cloud-init was handed a file". It is that
# a fresh instance becomes somewhere an agent can actually work, that it says
# so out of its own mouth, and that it stays that way across a reboot. None
# of those can be checked from the host side of the seam, so this script
# boots a guest and asks it.
#
# Nine claims:
#
#   1. A mistyped profile is refused before an instance exists, and the
#      refusal names the catalog.
#   2. `--profile claude` records the two profiles it needs as well as the
#      one that was asked for, and the guest is reachable while the install
#      is still running — the work is a unit, not something cloud-init's last
#      stage blocks on.
#   3. The guest's own verifier passes: git, tmux, node, npm and the Claude
#      Code CLI all answer, and the bootstrap stamp matches what the seed
#      asked for.
#   4. Work started in the `agent` session outlives the ssh connection that
#      started it. That is the whole point of a machine that never sleeps,
#      and it is the one thing a laptop cannot do.
#   5. The credential check is a real search: plant a credential file where
#      an agent would write one and the verifier fails, because a key on that
#      disk is a key in every snapshot of it.
#   6. A reboot does not redo the work, and a *changed* profile set does. The
#      first is the stamp doing its job; the second is what makes `ast
#      profile` mean anything on an instance that already exists.
#   7. A service-managed daemon and the running guest can disappear together;
#      the service resurrects astd, astd resurrects the profiled instance, and
#      the guest still verifies itself without somebody typing `ast up`.
#   8. A sentinel credential bound through the handle path remains usable
#      before and after that resurrection and after a snapshot restore, while
#      the raw value is absent from the snapshot's allocated bytes.
#   9. `ast bugreport` reports the recovered instance but neither the raw
#      sentinel nor its guest handle.
#
# Asserts on CONTENT, like scripts/e2e.sh, and for the same reasons.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export PATH="$HOME/.cargo/bin:$PATH"
cd "$ROOT"

# The cloud-image lane below deliberately tests cloud-init, sshd and a changed
# multi-profile set. OCI guests have a different control and bootstrap path;
# keep that proof readable instead of scattering mode checks through all nine
# cloud-image assertions.
if [ "${E2E_PROFILE_OCI:-0}" = 1 ]; then
  exec "$ROOT/scripts/e2e-profile-oci-keychain.sh" "$@"
fi

cargo build -q

# Fresh, SHORT and harness-owned: unix socket paths are capped near 104 bytes,
# and cleanup is allowed to remove exactly this mktemp directory and no other.
TMP_BASE="${TMPDIR:-/private/tmp}"
TMP_BASE="${TMP_BASE%/}"
export ASTERISM_HOME
ASTERISM_HOME="$(mktemp -d "$TMP_BASE/ast-profile.XXXXXX")"
# A single-device test has no orbit, so it has no business publishing a
# throwaway key and this machine's addresses to a public discovery service.
export ASTERISM_MESH=local
# The OS service slot is outside ASTERISM_HOME. Give this run a validated,
# unique label so install/restart/uninstall cannot touch the user's service.
export ASTERISM_TEST_SERVICE_LABEL="com.asterism.astd.test.profile.$$.$RANDOM"
BIN="$ASTERISM_HOME/bin"
AST="$BIN/ast"
ASTD="$BIN/astd"
LOG="$ASTERISM_HOME/astd.log"
EVIDENCE="$ASTERISM_HOME/evidence"
IMAGE="${E2E_IMAGE:-debian:13}"
INST=profile
MARKER="marker-$$"
SECRET="profile-sentinel-$$-$RANDOM"
SENTINEL="raw-profile-sentinel-$$-$RANDOM-$RANDOM"
SENTINEL_DIGEST="$(printf %s "$SENTINEL" | shasum -a 256 | awk '{print $1}')"
HANDLE=
ASTD_PID=
SERVICE_INSTALLED=
SECRET_CREATED=
# Two package installs and two npm downloads, on two emulated cores and
# whatever connection this machine has. Debian's `npm` alone is several
# hundred packages, so this is generous — and still bounded.
BOOTSTRAP_TIMEOUT="${E2E_BOOTSTRAP_TIMEOUT:-1800}"

cleanup() {
  "$AST" down "$INST" >/dev/null 2>&1 || true
  "$AST" rm "$INST" >/dev/null 2>&1 || true
  if [ -n "$SECRET_CREATED" ]; then
    "$AST" secret rm "$SECRET" >/dev/null 2>&1 || true
  fi
  if [ -n "$SERVICE_INSTALLED" ]; then
    "$AST" service uninstall >/dev/null 2>&1 || true
  fi
  if [ -n "$ASTD_PID" ]; then kill -9 "$ASTD_PID" 2>/dev/null || true; fi
  local recorded
  recorded="$(cat "$ASTERISM_HOME/astd.pid" 2>/dev/null || true)"
  if [ -n "$recorded" ]; then kill -9 "$recorded" 2>/dev/null || true; fi
  if [ -n "${KEEP:-}" ]; then
    echo "kept $ASTERISM_HOME for inspection"
  elif [ "$(dirname "$ASTERISM_HOME")" = "$TMP_BASE" ]; then
    case "$(basename "$ASTERISM_HOME")" in
      ast-profile.*) rm -rf -- "$ASTERISM_HOME" ;;
      *) echo "refusing to remove unexpected scratch path: $ASTERISM_HOME" >&2 ;;
    esac
  fi
  return 0
}
trap cleanup EXIT

mkdir -p "$ASTERISM_HOME/images" "$BIN" "$EVIDENCE"
cp "$ROOT/target/debug/ast" "$ROOT/target/debug/astd" "$BIN/"

# The service slot belongs to the login, not ASTERISM_HOME. The test-only
# label above gives this run its own unit, which cleanup can safely own.
case "$(uname -s)" in
  Darwin) SERVICE_UNIT="$HOME/Library/LaunchAgents/$ASTERISM_TEST_SERVICE_LABEL.plist" ;;
  Linux) SERVICE_UNIT="$HOME/.config/systemd/user/$ASTERISM_TEST_SERVICE_LABEL.service" ;;
  *) SERVICE_UNIT= ;;
esac
[ -n "$SERVICE_UNIT" ] || { echo "PROFILE E2E FAIL: no service manager on this host" >&2; exit 1; }
[ ! -e "$SERVICE_UNIT" ] || {
  echo "PROFILE E2E FAIL: $SERVICE_UNIT already exists — refusing to disturb it" >&2
  exit 1
}

fail() { echo "PROFILE E2E FAIL: $*" >&2; exit 1; }
ok() { echo "ok: $*"; }

# expect <desc> <needle> <cmd...>: run cmd, require success AND the needle.
expect() {
  local desc="$1" needle="$2"; shift 2
  local out
  out="$("$@" 2>&1)" || fail "$desc: command failed:"$'\n'"$out"
  grep -qF "$needle" <<<"$out" || fail "$desc: expected \"$needle\" in:"$'\n'"$out"
  ok "$desc"
}

# refuse <desc> <needle> <cmd...>: the opposite — the command must fail, and
# it must fail in words.
refuse() {
  local desc="$1" needle="$2"; shift 2
  local out
  if out="$("$@" 2>&1)"; then fail "$desc: this was supposed to be refused:"$'\n'"$out"; fi
  grep -qF "$needle" <<<"$out" || fail "$desc: expected \"$needle\" in:"$'\n'"$out"
  ok "$desc"
}

guest() { "$AST" ssh "$INST" -- "$@"; }

start_astd() {
  "$ASTD" >>"$LOG" 2>&1 &
  ASTD_PID=$!
  for _ in $(seq 1 100); do
    if [ "$(cat "$ASTERISM_HOME/astd.pid" 2>/dev/null || true)" = "$ASTD_PID" ]; then
      return 0
    fi
    sleep 0.2
  done
  fail "astd did not come up:"$'\n'"$(cat "$LOG" 2>/dev/null || true)"
}

stop_astd() {
  if [ -n "$ASTD_PID" ]; then
    kill -9 "$ASTD_PID" 2>/dev/null || true
    wait "$ASTD_PID" 2>/dev/null || true
    ASTD_PID=
  fi
}

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
  guest "case \"\$ASTERISM_SENTINEL\" in ast-*) ;; *) exit 41 ;; esac; \
    curl -fsS https://httpbin.org/bearer \
      -H \"Authorization: Bearer \$ASTERISM_SENTINEL\" \
      | jq -j .token | sha256sum | grep -q '$SENTINEL_DIGEST' \
    && echo sentinel-handle-works"
}

absent_from_sparse() {
  local desc="$1" file="$2" needle="$3" status
  if "$ROOT/scripts/sparse-contains.py" "$file" "$needle"; then
    fail "$desc: found forbidden bytes in $file"
  else
    status=$?
  fi
  [ "$status" -eq 1 ] || fail "$desc: sparse inspection could not prove absence (status $status)"
  ok "$desc"
}

# eventually <desc> <needle> <cmd...>: the same claim as `expect`, for
# something that becomes true rather than being true. A guest answers ssh
# long before cloud-init has finished writing its files, so "not yet" and
# "never" look identical for the first minute of every boot.
eventually() {
  local desc="$1" needle="$2"; shift 2
  local out=
  for _ in $(seq 1 40); do
    out="$("$@" 2>&1)" || true
    if grep -qF "$needle" <<<"$out"; then ok "$desc"; return 0; fi
    sleep 3
  done
  fail "$desc: waited two minutes for \"$needle\" in:"$'\n'"$out"
}

echo "== profile e2e in $ASTERISM_HOME"
start_astd
"$AST" pull "$IMAGE" >/dev/null 2>&1 || fail "pull $IMAGE"

# ---- 1. the catalog, and a name that is not in it ---------------------------

expect "the catalog lists what can be applied" "claude" "$AST" profiles
refuse "a mistyped profile is refused, with the catalog" \
  "no bootstrap profile called \"cladue\"" \
  "$AST" create "$INST" --image "$IMAGE" --profile cladue
[ ! -d "$ASTERISM_HOME/instances/$INST" ] || fail "the refused create left an instance behind"
ok "and it is refused before an instance exists"

# ---- 2. create, and a guest that is reachable while it installs -------------

expect "create with a profile" "$INST  defined" \
  "$AST" create "$INST" --image "$IMAGE" --cpus 4 --mem 2G --disk 10G --profile claude
# `claude` on its own is three profiles: the one asked for, and the two it is
# nothing without.
expect "the profiles it needs come with it" "base node claude" "$AST" profile "$INST"

# The raw sentinel goes from this pipe to the platform secret store. It is
# never argv, never a seed input, and never a file under ASTERISM_HOME.
secret_report="$(printf %s "$SENTINEL" | "$AST" secret create "$SECRET" 2>&1)" \
  || fail "creating the sentinel secret:"$'\n'"$secret_report"
SECRET_CREATED=1
grep -qF "$SECRET" <<<"$secret_report" || fail "secret creation did not name $SECRET"
ok "the sentinel entered the platform store through stdin"
expect "bind the sentinel as an opaque guest handle" "$SECRET -> httpbin.org" \
  "$AST" attach "$INST" --secret "$SECRET" --to httpbin.org \
    --as bearer --env ASTERISM_SENTINEL
expect "up" "$INST  running" "$AST" up "$INST"

# ssh answering at all is the claim here: the install is a unit, so
# cloud-init's last stage did not sit on it.
expect "the guest answers before the install has finished" "$INST" guest hostname
eventually "the bootstrap is a unit" "oneshot" \
  guest "systemctl show -p Type --value asterism-bootstrap.service"

# ---- 3. the guest's own verifier -------------------------------------------

echo "waiting for the bootstrap (up to ${BOOTSTRAP_TIMEOUT}s: two package \
installs and an npm download) ..."
deadline=$(( $(date +%s) + BOOTSTRAP_TIMEOUT ))
report=
while :; do
  if report="$(guest "sudo /usr/local/sbin/asterism-check" 2>&1)"; then break; fi
  if [ "$(date +%s)" -ge "$deadline" ]; then
    # On stdout, not stderr: this is the evidence for why the run failed, and
    # it has to be in the same place as everything else that was printed.
    echo "the last report was:"; echo "$report"
    guest "sudo journalctl -u asterism-bootstrap --no-pager | tail -40" || true
    fail "the bootstrap did not finish within ${BOOTSTRAP_TIMEOUT}s"
  fi
  sleep 10
done
echo "$report"
for needle in "ok    git" "ok    tmux" "ok    node" "ok    npm" "ok    claude" \
              "ok    applied" "this guest is ready"; do
  grep -qF "$needle" <<<"$report" || fail "the verifier did not report \"$needle\""
done
ok "the guest verifies itself: git, tmux, node, npm, claude"
# Same thing through the CLI, which is how a person will actually run it.
expect "ast profile --check" "this guest is ready" "$AST" profile "$INST" --check

HANDLE="$(guest 'printenv ASTERISM_SENTINEL' 2>/dev/null)" \
  || fail "the guest did not expose its sentinel handle"
case "$HANDLE" in ast-*) ;; *) fail "the guest got something other than an opaque handle" ;; esac
[ "$HANDLE" != "$SENTINEL" ] || fail "the raw sentinel entered the guest instead of a handle"
ok "the guest has an opaque handle, not the sentinel"
eventually "the proxy replaces the handle with the sentinel in flight" \
  "sentinel-handle-works" handle_works

# ---- 4. a session that outlives the connection that started it -------------

# Started detached, in the session the base profile's helper opens, by an ssh
# that exits immediately afterwards. Nothing is holding it up.
guest "agent -d \"sh -c 'sleep 20; echo $MARKER >/tmp/agent-marker'\"" \
  || fail "the agent session would not start"
expect "the session is there" "agent" guest "tmux ls"
sleep 30
expect "work started in it survived the disconnect" "$MARKER" guest "cat /tmp/agent-marker"

# ---- 5. the credential check is a real search ------------------------------

guest "sudo mkdir -p /root/.claude && \
  echo '{\"key\":\"sk-ant-not-a-real-key\"}' | sudo tee /root/.claude/.credentials.json >/dev/null" \
  || fail "could not plant a credential file"
refuse "a credential on the disk fails the check" \
  "a credential is on this disk" guest "sudo /usr/local/sbin/asterism-check"
guest "sudo rm -rf /root/.claude" || fail "could not remove the planted credential"
expect "and passes again once it is gone" "this guest is ready" \
  guest "sudo /usr/local/sbin/asterism-check"

# ---- 6. a reboot, and a changed set ----------------------------------------

expect "down" "$INST  stopped" "$AST" down "$INST"
expect "up again" "$INST  running" "$AST" up "$INST"
# The unit runs after cloud-final and sshd answers well before that, so an
# empty journal a second after `ast up` returns means the unit has not been
# reached yet rather than that it did nothing.
eventually "the second boot recognises its own stamp" "bootstrap already applied" \
  guest "sudo journalctl -b -u asterism-bootstrap --no-pager"
journal="$(guest "sudo journalctl -b -u asterism-bootstrap --no-pager" 2>&1)"
if grep -qF "applying bootstrap profiles" <<<"$journal"; then
  fail "the second boot applied the profiles again:"$'\n'"$journal"
fi
ok "and does not redo the work"
expect "and the guest is still what it was" "this guest is ready" \
  guest "sudo /usr/local/sbin/asterism-check"

# ---- 7. service and daemon resurrection ------------------------------------

# Move responsibility from this shell to the OS service, then stop both astd
# and the guest as one host-equivalent event. SIGSTOP closes the race: the old
# daemon cannot observe the guest dying and restart it before the service
# manager has had to resurrect the daemon itself.
OLD_DAEMON="$ASTD_PID"
stop_astd
SERVICE_INSTALLED=1
service_report="$("$AST" service install 2>&1)" \
  || fail "installing the scratch astd service:"$'\n'"$service_report"
grep -qF "is installed as" <<<"$service_report" \
  || fail "service install did not report its mechanism:"$'\n'"$service_report"
wait_daemon_pid "$OLD_DAEMON" || fail "the installed service did not start astd"
expect "the OS service owns the scratch daemon" "running (pid" "$AST" service status

BEFORE_HOST_DAEMON="$ASTD_PID"
BEFORE_HOST_GUEST="$(guest_pid)"
[ -n "$BEFORE_HOST_GUEST" ] || fail "no guest pid before the host-equivalent restart"
kill -STOP "$BEFORE_HOST_DAEMON"
kill -9 "$BEFORE_HOST_GUEST"
kill -9 "$BEFORE_HOST_DAEMON"
ASTD_PID=
wait_daemon_pid "$BEFORE_HOST_DAEMON" \
  || fail "the service did not resurrect astd after it was killed"
AFTER_HOST_GUEST="$(wait_guest_pid "$BEFORE_HOST_GUEST")" \
  || fail "the resurrected daemon did not resurrect the profiled instance"
ok "service resurrected astd as $ASTD_PID; astd resurrected the guest as $AFTER_HOST_GUEST"
expect "the resurrected profiled guest verifies itself" "this guest is ready" \
  "$AST" profile "$INST" --check
eventually "the handle path survives daemon and guest resurrection" \
  "sentinel-handle-works" handle_works

# ---- 8. snapshot absence, inspection and restore ---------------------------

expect "write the snapshot control marker" "before-snapshot" \
  guest "echo before-snapshot | sudo tee /var/lib/asterism/profile-snapshot-control; sync"
expect "stop for a consistent snapshot" "$INST  stopped" "$AST" down "$INST"
expect "create the bound-instance snapshot" "$INST  snapshot credential-bound" \
  "$AST" snapshot "$INST" credential-bound
expect "inspect the snapshot through the CLI" "credential-bound" \
  "$AST" snapshots "$INST"
SNAPSHOT_DIR="$ASTERISM_HOME/instances/$INST/snapshots"
SNAPSHOT="$(find "$SNAPSHOT_DIR" -maxdepth 1 -type f \
  \( -name 'credential-bound.raw' -o -name 'credential-bound.qcow2' -o -name 'credential-bound.vhdx' \) \
  -print 2>/dev/null || true)"
case "$SNAPSHOT" in
  *$'\n'*) fail "snapshot credential-bound resolved to more than one disk image:"$'\n'"$SNAPSHOT" ;;
  "")
    # Pre-file-snapshot QEMU instances keep the snapshot table and its data
    # inside disk.qcow2. The listing above proved the tag exists; scan the
    # owning image in that case, because it is the snapshot's byte store.
    SNAPSHOT="$ASTERISM_HOME/instances/$INST/disk.qcow2"
    [ -f "$SNAPSHOT" ] || fail \
      "snapshot listing exists but neither a portable snapshot image nor an internal qcow2 store exists"
    ok "the legacy internal snapshot is stored in its qcow2 root image"
    ;;
esac
[ -f "$SNAPSHOT" ] || fail "snapshot listing exists but $SNAPSHOT does not"
absent_from_sparse "the raw sentinel is absent from the snapshot" "$SNAPSHOT" "$SENTINEL"
"$ROOT/scripts/sparse-contains.py" "$SNAPSHOT" "$HANDLE" \
  || fail "the snapshot does not contain the guest handle, so it is not a useful control"
ok "the snapshot contains the handle but not the value it stands in for"

expect "boot after the snapshot" "$INST  running" "$AST" up "$INST"
expect "change the live disk after the snapshot" "after-snapshot" \
  guest "echo after-snapshot | sudo tee /var/lib/asterism/profile-snapshot-control; sync"
expect "stop before restore" "$INST  stopped" "$AST" down "$INST"
expect "restore the inspected snapshot" "$INST  restored to credential-bound" \
  "$AST" restore "$INST" credential-bound
expect "boot the restored guest" "$INST  running" "$AST" up "$INST"
expect "restore returned the disk to its control marker" "before-snapshot" \
  guest "cat /var/lib/asterism/profile-snapshot-control"
expect "the restored profile is still usable" "this guest is ready" \
  "$AST" profile "$INST" --check
eventually "the restored handle still resolves through the proxy" \
  "sentinel-handle-works" handle_works

# ---- 9. bug report redaction ------------------------------------------------

bugreport="$("$AST" bugreport 2>&1)" || fail "ast bugreport failed:"$'\n'"$bugreport"
printf '%s\n' "$bugreport" >"$EVIDENCE/bugreport.txt"
grep -qF "[instances]" <<<"$bugreport" || fail "bugreport has no instance section"
grep -qF "$INST" <<<"$bugreport" || fail "bugreport omitted the profiled instance"
grep -qF "profiles=claude" <<<"$bugreport" || fail "bugreport omitted the selected profile"
if grep -qF "$SENTINEL" <<<"$bugreport"; then fail "bugreport contains the raw sentinel"; fi
if grep -qF "$HANDLE" <<<"$bugreport"; then fail "bugreport contains a guest handle"; fi
ok "ast bugreport reports the profile without the sentinel or handle"

# Adding one is recorded now and applied by the next boot, which is what the
# seed being the carrier means.
expect "adding a profile" "base node claude codex" "$AST" profile "$INST" claude codex
expect "down 2" "$INST  stopped" "$AST" down "$INST"
expect "up 3" "$INST  running" "$AST" up "$INST"

echo "waiting for the added profile (up to ${BOOTSTRAP_TIMEOUT}s) ..."
deadline=$(( $(date +%s) + BOOTSTRAP_TIMEOUT ))
while :; do
  if report="$(guest "sudo /usr/local/sbin/asterism-check" 2>&1)"; then break; fi
  if [ "$(date +%s)" -ge "$deadline" ]; then
    echo "the last report was:"; echo "$report"
    fail "the added profile did not arrive within ${BOOTSTRAP_TIMEOUT}s"
  fi
  sleep 10
done
grep -qF "ok    codex" <<<"$report" || fail "codex did not arrive:"$'\n'"$report"
grep -qF "base@2 node@1 claude@1 codex@1" <<<"$report" \
  || fail "the stamp did not move with the set:"$'\n'"$report"
ok "a changed profile set reaches a guest that already exists"

expect "down 3" "$INST  stopped" "$AST" down "$INST"
expect "rm" "$INST  removed" "$AST" rm "$INST"

echo "PROFILE E2E GREEN ($IMAGE)"
