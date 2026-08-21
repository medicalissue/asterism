#!/usr/bin/env bash
# End-to-end for bootstrap profiles, with a real boot and a real install.
#
# The claim a profile makes is not "cloud-init was handed a file". It is that
# a fresh instance becomes somewhere an agent can actually work, that it says
# so out of its own mouth, and that it stays that way across a reboot. None
# of those can be checked from the host side of the seam, so this script
# boots a guest and asks it.
#
# Six claims:
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
#
# Asserts on CONTENT, like scripts/e2e.sh, and for the same reasons.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export PATH="$HOME/.cargo/bin:$PATH"
cd "$ROOT"
cargo build -q
AST="$ROOT/target/debug/ast"

# Fresh, SHORT home: unix socket paths are capped near 104 bytes.
export ASTERISM_HOME="/private/tmp/ast-profile-$$"
# A single-device test has no orbit, so it has no business publishing a
# throwaway key and this machine's addresses to a public discovery service.
export ASTERISM_MESH=local
IMAGE="${E2E_IMAGE:-debian:13}"
INST=profile
MARKER="marker-$$"
# Two package installs and two npm downloads, on two emulated cores and
# whatever connection this machine has. Debian's `npm` alone is several
# hundred packages, so this is generous — and still bounded.
BOOTSTRAP_TIMEOUT="${E2E_BOOTSTRAP_TIMEOUT:-1800}"

cleanup() {
  "$AST" down "$INST" >/dev/null 2>&1 || true
  "$AST" rm "$INST" >/dev/null 2>&1 || true
  pkill -f "$ROOT/target/debug/astd" 2>/dev/null || true
  rm -rf "$ASTERISM_HOME"
}
trap cleanup EXIT

mkdir -p "$ASTERISM_HOME/images"
# Reuse already-pulled images instead of re-downloading.
if [ -d "$HOME/.asterism/images" ]; then
  cp "$HOME/.asterism/images/"*.qcow2 "$ASTERISM_HOME/images/" 2>/dev/null || true
fi

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
grep -qF "base@1 node@1 claude@1 codex@1" <<<"$report" \
  || fail "the stamp did not move with the set:"$'\n'"$report"
ok "a changed profile set reaches a guest that already exists"

expect "down 3" "$INST  stopped" "$AST" down "$INST"
expect "rm" "$INST  removed" "$AST" rm "$INST"

echo "PROFILE E2E GREEN ($IMAGE)"
