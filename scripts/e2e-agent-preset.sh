#!/usr/bin/env bash
# End-to-end for the agent scene: `ast create --agent`, `ast attach`, `ast logs`.
#
# This is the transcript AST-150 exists to produce, run against a real VZ
# guest on this device:
#
#   ast secret add ANTHROPIC_API_KEY
#   ast create bot --agent claude-code --repo <url>
#   ast attach bot
#   ast create bot2 --agent codex        # refused, by name, before anything
#
# and then the claim underneath it: the key never enters the box. The guest
# holds an opaque handle, the door swaps it on the way to exactly one
# authority, and the dummy value used here is absent from the guest's live
# disk, from a snapshot of it, and from every file Asterism wrote.
#
# The image comes from a registry this script starts, because there is no GHCR
# publishing credential on this device (see docs/agents.md). Asterism pulls it
# over HTTPS, by digest, exactly as it would pull a published one — the only
# thing that differs is which host is serving the bytes, and a user preset in
# the scratch home is what points at it, which exercises the override path
# users have for pinning their own build.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export PATH="$HOME/.cargo/bin:$PATH"
cd "$ROOT"

# shellcheck source-path=SCRIPTDIR
. "$ROOT/scripts/lib/harness.sh"
harness_begin agent-preset
harness_binaries "$ROOT"

[ "$(uname -s)" = Darwin ] \
  || harness_skip "this lane runs the VZ backend, which is macOS-only"
command -v docker >/dev/null 2>&1 \
  || harness_skip "docker builds the agent image and serves it"

if [ -z "${AST_BIN:-}" ]; then
  "$ROOT/scripts/sign-vz.sh"
fi

GUEST_ARTIFACT="${ASTERISM_GUEST_AGENT_ARTIFACT:-$(dirname "$ASTD")/guest/bin/asterism-guest}"
[ -x "$GUEST_ARTIFACT" ] \
  || harness_skip "set ASTERISM_GUEST_AGENT_ARTIFACT to a static $(uname -m) Linux asterism-guest"

export ASTERISM_HOME="/private/tmp/ast-agent-$$"
export ASTERISM_MESH=local
mkdir -p "$ASTERISM_HOME"
harness_own_home "$ASTERISM_HOME"

BIN="$ASTERISM_HOME/bin"
LOG="$ASTERISM_HOME/astd.log"
EVIDENCE="$ASTERISM_HOME/evidence"
CERTS="$ASTERISM_HOME/certs"
INST=bot
REPO="${E2E_AGENT_REPO:-https://github.com/octocat/Hello-World.git}"
# Never a real key. The point of the run is that this value is absent from
# everything the guest can see, so it has to be a value nothing else knows.
DUMMY="sk-ant-test-0000-$$-$RANDOM"
REGISTRY_HTTP=localhost:5100
REGISTRY_HTTPS=localhost:5443
IMAGE_TAG=0.1.0-e2e
ASTD_PID=
SECRET_CREATED=
HANDLE=

cleanup() {
  "$AST" down "$INST" >/dev/null 2>&1 || true
  "$AST" rm "$INST" >/dev/null 2>&1 || true
  if [ -n "$SECRET_CREATED" ]; then
    "$AST" secret rm ANTHROPIC_API_KEY >/dev/null 2>&1 || true
  fi
  docker rm -f ast150-reg-http ast150-reg-https >/dev/null 2>&1 || true
  harness_keep_home "$ASTERISM_HOME" home
  harness_reap
  if [ -n "${KEEP:-}" ]; then
    echo "kept $ASTERISM_HOME for inspection"
  else
    case "$ASTERISM_HOME" in
      /private/tmp/ast-agent-*) rm -rf -- "$ASTERISM_HOME" ;;
      *) echo "refusing to remove unexpected scratch path: $ASTERISM_HOME" >&2 ;;
    esac
  fi
  harness_artifacts_note
}
trap cleanup EXIT

fail() { echo "AGENT PRESET E2E FAIL: $*" >&2; exit 1; }
ok() { echo "ok: $*"; }

guest() { "$AST" exec "$INST" -- /bin/sh -c "$1"; }

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

mkdir -p "$BIN/guest/bin" "$EVIDENCE" "$CERTS" "$ASTERISM_HOME/presets"
cp "$AST" "$ASTD" "$BIN/"
[ -x "$(dirname "$ASTD")/astd-vz" ] || fail "no astd-vz beside $ASTD — run scripts/sign-vz.sh"
cp "$(dirname "$ASTD")/astd-vz" "$BIN/astd-vz"
cp "$GUEST_ARTIFACT" "$BIN/guest/bin/asterism-guest"
chmod 0755 "$BIN/guest/bin/asterism-guest"
AST="$BIN/ast"
ASTD="$BIN/astd"
export AST ASTD

# ---- the image and where it is served --------------------------------------
echo "== building the agent image"
docker build --platform linux/arm64 \
  -f "$ROOT/images/agent-claude-code/Dockerfile" \
  -t "ast150-agent-claude-code:$IMAGE_TAG" "$ROOT/images" >"$EVIDENCE/docker-build.log" 2>&1 \
  || { tail -30 "$EVIDENCE/docker-build.log"; fail "the agent image did not build"; }
ok "built the agent image"

openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout "$CERTS/registry.key" -out "$CERTS/registry.crt" \
  -days 2 -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" >/dev/null 2>&1
docker rm -f ast150-reg-http ast150-reg-https >/dev/null 2>&1 || true
docker volume create ast150-registry >/dev/null
docker run -d --name ast150-reg-http -p 5100:5000 \
  -v ast150-registry:/var/lib/registry registry:2 >/dev/null
docker run -d --name ast150-reg-https -p 5443:443 \
  -v ast150-registry:/var/lib/registry -v "$CERTS":/certs:ro \
  -e REGISTRY_HTTP_ADDR=0.0.0.0:443 \
  -e REGISTRY_HTTP_TLS_CERTIFICATE=/certs/registry.crt \
  -e REGISTRY_HTTP_TLS_KEY=/certs/registry.key \
  registry:2 >/dev/null
for _ in $(seq 1 60); do
  if curl -fsS "http://$REGISTRY_HTTP/v2/" >/dev/null 2>&1 \
    && curl -fsS --cacert "$CERTS/registry.crt" "https://$REGISTRY_HTTPS/v2/" >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
curl -fsS --cacert "$CERTS/registry.crt" "https://$REGISTRY_HTTPS/v2/" >/dev/null \
  || fail "the https registry did not come up"
ok "a local registry pair is serving on $REGISTRY_HTTP and $REGISTRY_HTTPS"

docker tag "ast150-agent-claude-code:$IMAGE_TAG" "$REGISTRY_HTTP/agent-claude-code:$IMAGE_TAG"
docker push "$REGISTRY_HTTP/agent-claude-code:$IMAGE_TAG" >"$EVIDENCE/docker-push.log" 2>&1 \
  || { tail -20 "$EVIDENCE/docker-push.log"; fail "the agent image did not push"; }
DIGEST="$(awk '/digest: sha256:/ {print $3}' "$EVIDENCE/docker-push.log" | tail -1)"
case "$DIGEST" in
  sha256:*) ok "pushed the agent image as $DIGEST" ;;
  *) fail "could not read the pushed manifest digest" ;;
esac

# The user-preset override, which is also how anyone pins their own build.
cat >"$ASTERISM_HOME/presets/claude-code.json" <<EOF
{
  "name": "claude-code",
  "summary": "Anthropic's Claude Code CLI, in a tmux session that outlives your terminal.",
  "image": "$REGISTRY_HTTPS/agent-claude-code:$IMAGE_TAG",
  "digest": "$DIGEST",
  "start": "claude",
  "workdir": "/work",
  "version_probe": "claude --version",
  "docs": "https://docs.claude.com/en/docs/claude-code",
  "experimental": false,
  "secrets": [
    { "name": "ANTHROPIC_API_KEY", "authority": "api.anthropic.com",
      "placement": "x-api-key", "env": "ANTHROPIC_API_KEY", "required": true },
    { "name": "GITHUB_TOKEN", "authority": "github.com",
      "placement": "bearer", "env": "GITHUB_TOKEN", "required": false }
  ]
}
EOF
ok "a user preset points claude-code at the locally built image, pinned by digest"

# ---- the daemon ------------------------------------------------------------
#
# CURL_CA_BUNDLE is how the product's own puller is told to trust this run's
# throwaway registry certificate. Nothing about the pull path changes: the
# manifest is still fetched by digest and every blob is still verified against
# the digest the manifest named.
export CURL_CA_BUNDLE="$CERTS/registry.crt"
"$ASTD" >>"$LOG" 2>&1 &
ASTD_PID=$!
for _ in $(seq 1 100); do
  [ "$(cat "$ASTERISM_HOME/astd.pid" 2>/dev/null || true)" = "$ASTD_PID" ] && break
  sleep 0.2
done
[ "$(cat "$ASTERISM_HOME/astd.pid" 2>/dev/null || true)" = "$ASTD_PID" ] \
  || fail "astd did not come up:"$'\n'"$(cat "$LOG" 2>/dev/null || true)"

# ---- the refusal, before anything else -------------------------------------
#
# First, because it has to hold when the orbit has no secrets at all, and
# because a refusal that only works after a successful create is not a
# refusal, it is an accident.
refusal="$("$AST" create bot2 --agent codex 2>&1 || true)"
printf '%s\n' "$refusal" >"$EVIDENCE/refusal.txt"
[ "$(printf '%s\n' "$refusal" | head -1)" \
  = "error: preset codex needs secret OPENAI_API_KEY — run \`ast secret add OPENAI_API_KEY\` first" ] \
  || fail "the missing-secret refusal is not the sentence it should be:"$'\n'"$refusal"
grep -qF 'fix: ast secret add OPENAI_API_KEY' <<<"$refusal" \
  || fail "the refusal did not carry the command that repairs it:"$'\n'"$refusal"
"$AST" status bot2 >/dev/null 2>&1 \
  && fail "the refusal created an instance anyway"
ok "a missing required secret is refused by name, and nothing is created"

# ---- the transcript --------------------------------------------------------
printf %s "$DUMMY" | "$AST" secret add ANTHROPIC_API_KEY >"$EVIDENCE/secret-add.txt" 2>&1 \
  || { cat "$EVIDENCE/secret-add.txt"; fail "ast secret add"; }
SECRET_CREATED=1
ok "the dummy key entered this device's credential store through stdin"

started=$(date +%s)
"$AST" create "$INST" --agent claude-code --repo "$REPO" \
  --backend vz --cpus 4 --mem 4G --disk 12G \
  >"$EVIDENCE/create.txt" 2>"$EVIDENCE/create.err" \
  || { cat "$EVIDENCE/create.txt" "$EVIDENCE/create.err"; fail "ast create --agent"; }
elapsed=$(( $(date +%s) - started ))
cat "$EVIDENCE/create.txt"
echo "(create took ${elapsed}s)"
grep -q "^pulling $REGISTRY_HTTPS/agent-claude-code@$DIGEST … done (" "$EVIDENCE/create.txt" \
  || fail "the pull line is not the transcript's:"$'\n'"$(cat "$EVIDENCE/create.txt")"
grep -q "^$INST is up — claude-code .*, repo cloned to /work/Hello-World, session \"$INST\" running$" \
  "$EVIDENCE/create.txt" \
  || fail "the ready line is not the transcript's:"$'\n'"$(cat "$EVIDENCE/create.txt")"
ok "the transcript's two lines are the two lines"

# ---- what is actually inside -----------------------------------------------
"$AST" status "$INST" >"$EVIDENCE/status.txt" 2>&1
grep -q "machine: vz" "$EVIDENCE/status.txt" || fail "this lane did not run on vz"
ok "the instance really is a native VZ guest"

guest "test -d /work/Hello-World/.git && echo cloned" | grep -q cloned \
  || fail "the repository is not in the workspace"
guest "grep ' /work ' /proc/mounts" | grep -q virtiofs \
  || fail "/work is not the shared workspace directory"
# The other end of the same bytes. This is the property a block volume does
# not have and the reason the workspace is a share: the clone is a directory
# on the host, openable in an editor while the agent works in it.
[ -d "$ASTERISM_HOME/work/$INST/Hello-World/.git" ] \
  || fail "the clone is not visible on the host side of the share"
ok "the repository is in the shared workspace, and the host can see it too"

guest "tmux list-sessions" >"$EVIDENCE/tmux.txt" 2>&1 \
  || { cat "$EVIDENCE/tmux.txt"; fail "no tmux session in the guest"; }
grep -q "^$INST:" "$EVIDENCE/tmux.txt" || fail "the tmux session is not named $INST"
ok "the agent's tmux session is running in the guest"

# ---- the key is not in the box ---------------------------------------------
HANDLE="$(guest 'printenv ANTHROPIC_API_KEY')" || fail "the guest has no handle"
case "$HANDLE" in
  sk-ant-ast-*) ok "the guest holds an opaque handle ($HANDLE)" ;;
  *) fail "the guest got something other than an Anthropic-shaped handle" ;;
esac
[ "$HANDLE" != "$DUMMY" ] || fail "the raw value entered the guest"

api_status="$(guest "curl -sS -o /dev/null -w '%{http_code}' \
  -X POST https://api.anthropic.com/v1/messages \
  -H \"x-api-key: \$ANTHROPIC_API_KEY\" \
  -H 'anthropic-version: 2023-06-01' \
  -H 'content-type: application/json' \
  -d '{\"model\":\"claude-3-5-haiku-latest\",\"max_tokens\":1,\"messages\":[{\"role\":\"user\",\"content\":\"hi\"}]}'")"
printf '%s\n' "$api_status" >"$EVIDENCE/anthropic-status.txt"
[ "$api_status" = 401 ] \
  || fail "the guest's call to api.anthropic.com answered $api_status, not the 401 a dummy key earns"
ok "the guest reached api.anthropic.com through the door and got 401"

ROOT_DISK="$ASTERISM_HOME/instances/$INST/disk.raw"
absent_from_sparse "the dummy key is absent from the live root disk" "$ROOT_DISK" "$DUMMY"
"$ROOT/scripts/sparse-contains.py" "$ROOT_DISK" "$HANDLE" \
  || fail "the root disk does not contain the handle it is supposed to"
ok "the root disk contains the handle and not the value"

while IFS= read -r file; do
  case "$file" in
    *.raw|*.qcow2|*.vhdx) continue ;;
  esac
  if LC_ALL=C grep -aFq "$DUMMY" "$file"; then
    fail "the dummy key entered Asterism metadata or logs: $file"
  fi
done < <(find "$ASTERISM_HOME" -type f -print)
ok "the dummy key is absent from every file Asterism wrote"

# ---- attach ----------------------------------------------------------------
#
# Driven through a pty with a tmux detach keystroke on stdin, because that is
# what a person does: attach, look, Ctrl-b d, walk away.
# A real tty, a real wait, and a real detach keystroke — with a hard stop
# behind it, because an attach that works is an attach that does not return
# until somebody detaches, and a suite must never be the somebody who forgot.
attach_once() {
  local verb="$1" out="$2" pid killer
  ( sleep 8; printf '\002d'; sleep 4 ) \
    | script -q /dev/null "$AST" "$verb" "$INST" >"$out" 2>&1 &
  pid=$!
  ( sleep 60; kill -TERM "$pid" 2>/dev/null || true ) >/dev/null 2>&1 &
  killer=$!
  wait "$pid" 2>/dev/null || true
  kill "$killer" 2>/dev/null || true
  pkill -f "ssh -i $ASTERISM_HOME" >/dev/null 2>&1 || true
}

for verb in attach session; do
  attach_once "$verb" "$EVIDENCE/$verb.txt"
  if grep -qF 'Permission denied' "$EVIDENCE/$verb.txt"; then
    fail "ast $verb could not authenticate to the guest:"$'\n'"$(cat "$EVIDENCE/$verb.txt")"
  fi
  # What comes back is the agent's own screen being redrawn for a new client,
  # which is the only thing that proves the tty landed in the session rather
  # than in a shell. Matched a word at a time on purpose: tmux redraws a pane
  # with cursor moves between words, so the banner is never one substring.
  for word in Welcome Claude Code; do
    grep -qF "$word" "$EVIDENCE/$verb.txt" \
      || fail "ast $verb did not land in the agent's session (no \"$word\"):"$'\n'"$(cat "$EVIDENCE/$verb.txt")"
  done
  ok "ast $verb reached the running agent and detached from it"
done

guest "tmux list-sessions" | grep -q "^$INST:" \
  || fail "detaching killed the session"
ok "the agent kept running after the detach"

"$AST" logs "$INST" -n 40 >"$EVIDENCE/logs.txt" 2>&1 || fail "ast logs"
ok "ast logs read the agent's own pane"

# ---- the workspace survives a restore --------------------------------------
guest "echo before-snapshot > /work/marker && sync" >/dev/null
grep -q before-snapshot "$ASTERISM_HOME/work/$INST/marker" \
  || fail "what the guest wrote to /work did not reach the host"
ok "what the agent writes in /work is on the host, outside the root disk"
"$AST" down "$INST" >/dev/null || fail "ast down"
"$AST" snapshot "$INST" agent-scene >/dev/null || fail "ast snapshot"
SNAPSHOT="$ASTERISM_HOME/instances/$INST/snapshots/agent-scene.raw"
absent_from_sparse "the dummy key is absent from the snapshot" "$SNAPSHOT" "$DUMMY"
"$AST" up "$INST" >/dev/null || fail "ast up"
for _ in $(seq 1 90); do
  if guest "test -f /run/asterism-agent.ready && echo ready" 2>/dev/null | grep -q ready; then
    break
  fi
  sleep 2
done
guest "cat /work/marker" | grep -q before-snapshot \
  || fail "the workspace did not survive the reboot"
guest "tmux list-sessions" | grep -q "^$INST:" \
  || fail "the agent session did not come back after the reboot"
ok "the workspace and the session both came back on their own after a reboot"

"$AST" down "$INST" >/dev/null || true
echo "AGENT PRESET E2E GREEN (vz, $REGISTRY_HTTPS/agent-claude-code@$DIGEST, ${elapsed}s to ready)"
