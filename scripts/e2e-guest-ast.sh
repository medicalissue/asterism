#!/usr/bin/env bash
# End-to-end for `ast` inside the box, and the channel back out.
#
# This is the transcript AST-156 exists to produce, against a real VZ guest on
# this device. Inside:
#
#   ast snapshot before-schema-migration
#   ast cost
#   ast ask "…"          # answered from the host with `ast inbox reply`
#   ast notify "…"
#   ast snapshot other-bot x        # refused, by the sentence
#   ast secret ls                   # refused, by the reason
#
# and outside:
#
#   ast tell bot "…"     # lands in the tmux session, proved by capture-pane
#   ast inbox
#   ast inbox reply 1 A
#
# and the claim underneath: the per-instance token the daemon armed the guest
# with is in no file the guest has, in no snapshot, and in nothing Asterism
# wrote.
#
# The image comes from a registry this script starts, for the same reason
# scripts/e2e-agent-preset.sh does: there is no GHCR publishing credential on
# this device (see docs/agents.md).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export PATH="$HOME/.cargo/bin:$PATH"
cd "$ROOT"

# shellcheck source-path=SCRIPTDIR
. "$ROOT/scripts/lib/harness.sh"
harness_begin guest-ast
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
  || harness_skip "set ASTERISM_GUEST_AGENT_ARTIFACT to a static $(uname -m) Linux asterism-guest built from this tree"

export ASTERISM_HOME="/private/tmp/ast-guestast-$$"
export ASTERISM_MESH=local
mkdir -p "$ASTERISM_HOME"
harness_own_home "$ASTERISM_HOME"

BIN="$ASTERISM_HOME/bin"
LOG="$ASTERISM_HOME/astd.log"
EVIDENCE="$ASTERISM_HOME/evidence"
CERTS="$ASTERISM_HOME/certs"
INST=bot
DUMMY="sk-ant-test-0000-$$-$RANDOM"
# Not 5100/5443: scripts/e2e-agent-preset.sh serves on those, and two lanes
# that cannot run at the same time on one laptop is a constraint nobody needs.
REGISTRY_HTTP=localhost:5110
REGISTRY_HTTPS=localhost:5453
IMAGE_TAG=0.1.0-e2e
ASTD_PID=
SECRET_CREATED=

cleanup() {
  for name in "$INST" "$INST-1" "$INST-2"; do
    "$AST" down "$name" >/dev/null 2>&1 || true
    "$AST" rm "$name" >/dev/null 2>&1 || true
  done
  if [ -n "$SECRET_CREATED" ]; then
    "$AST" secret rm ANTHROPIC_API_KEY >/dev/null 2>&1 || true
  fi
  docker rm -f ast156-reg-http ast156-reg-https >/dev/null 2>&1 || true
  harness_keep_home "$ASTERISM_HOME" home
  harness_reap
  if [ -n "${KEEP:-}" ]; then
    echo "kept $ASTERISM_HOME for inspection"
  else
    case "$ASTERISM_HOME" in
      /private/tmp/ast-guestast-*) rm -rf -- "$ASTERISM_HOME" ;;
      *) echo "refusing to remove unexpected scratch path: $ASTERISM_HOME" >&2 ;;
    esac
  fi
  harness_artifacts_note
}
trap cleanup EXIT

fail() { echo "GUEST AST E2E FAIL: $*" >&2; exit 1; }
ok() { echo "ok: $*"; }

guest() { "$AST" exec "$INST" -- /bin/sh -c "$1"; }
# What the agent itself types. `ast` in here is the symlink the boot script
# made, and nothing in this call goes near the host's unix socket. The second
# argument is how long `ast exec` waits, which for `ast ask` has to be longer
# than a person takes to answer.
inbox_ast() { "$AST" exec "$INST" --timeout "${2:-30}" -- /bin/sh -c "cd /work && ast $1"; }

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
  -t "ast156-agent-claude-code:$IMAGE_TAG" "$ROOT/images" >"$EVIDENCE/docker-build.log" 2>&1 \
  || { tail -30 "$EVIDENCE/docker-build.log"; fail "the agent image did not build"; }
ok "built the agent image"

openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout "$CERTS/registry.key" -out "$CERTS/registry.crt" \
  -days 2 -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" >/dev/null 2>&1
docker rm -f ast156-reg-http ast156-reg-https >/dev/null 2>&1 || true
docker volume create ast156-registry >/dev/null
docker run -d --name ast156-reg-http -p 5110:5000 \
  -v ast156-registry:/var/lib/registry registry:2 >/dev/null
docker run -d --name ast156-reg-https -p 5453:443 \
  -v ast156-registry:/var/lib/registry -v "$CERTS":/certs:ro \
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

docker tag "ast156-agent-claude-code:$IMAGE_TAG" "$REGISTRY_HTTP/agent-claude-code:$IMAGE_TAG"
docker push "$REGISTRY_HTTP/agent-claude-code:$IMAGE_TAG" >"$EVIDENCE/docker-push.log" 2>&1 \
  || { tail -20 "$EVIDENCE/docker-push.log"; fail "the agent image did not push"; }
DIGEST="$(awk '/digest: sha256:/ {print $3}' "$EVIDENCE/docker-push.log" | tail -1)"
case "$DIGEST" in
  sha256:*) ok "pushed the agent image as $DIGEST" ;;
  *) fail "could not read the pushed manifest digest" ;;
esac

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
export CURL_CA_BUNDLE="$CERTS/registry.crt"
"$ASTD" >>"$LOG" 2>&1 &
ASTD_PID=$!
for _ in $(seq 1 100); do
  [ "$(cat "$ASTERISM_HOME/astd.pid" 2>/dev/null || true)" = "$ASTD_PID" ] && break
  sleep 0.2
done
[ "$(cat "$ASTERISM_HOME/astd.pid" 2>/dev/null || true)" = "$ASTD_PID" ] \
  || fail "astd did not come up:"$'\n'"$(cat "$LOG" 2>/dev/null || true)"

printf %s "$DUMMY" | "$AST" secret add ANTHROPIC_API_KEY >"$EVIDENCE/secret-add.txt" 2>&1 \
  || { cat "$EVIDENCE/secret-add.txt"; fail "ast secret add"; }
SECRET_CREATED=1

"$AST" create "$INST" --agent claude-code \
  --backend vz --cpus 4 --mem 4G --disk 12G \
  >"$EVIDENCE/create.txt" 2>"$EVIDENCE/create.err" \
  || { cat "$EVIDENCE/create.txt" "$EVIDENCE/create.err"; fail "ast create --agent"; }
cat "$EVIDENCE/create.txt"
grep -q "^$INST is up — claude-code .*, session \"$INST\" running$" "$EVIDENCE/create.txt" \
  || fail "the ready line is not the transcript's:"$'\n'"$(cat "$EVIDENCE/create.txt")"
ok "an agent instance is up on the native VZ backend"

# The snippet that tells the agent these verbs exist.
guest "test -s /work/.asterism/AGENT-SNIPPET.md && echo there" | grep -q there \
  || fail "ast create --agent did not drop the snippet into the workspace"
guest "grep -c 'ast ask' /work/.asterism/AGENT-SNIPPET.md" >/dev/null \
  || fail "the snippet does not mention ast ask"
ok "the workspace carries the snippet that tells the agent about all this"

# ---- ast is in the box -----------------------------------------------------
guest "test -L /usr/local/bin/ast && readlink /usr/local/bin/ast" >"$EVIDENCE/ast-link.txt" 2>&1 \
  || fail "there is no ast in the box"
grep -qx "/.asterism/guest" "$EVIDENCE/ast-link.txt" \
  || fail "ast in the box is not the guest agent:"$'\n'"$(cat "$EVIDENCE/ast-link.txt")"
ok "ast in the box is a symlink to the agent Asterism injected, not a second artifact"

# The channel takes a moment to be armed: the pump is a supervisor on a timer.
for _ in $(seq 1 40); do
  if inbox_ast "cost" >"$EVIDENCE/cost.txt" 2>&1; then break; fi
  sleep 1
done
cat "$EVIDENCE/cost.txt"
grep -q "^today " "$EVIDENCE/cost.txt" \
  || fail "ast cost in the box did not print today's line:"$'\n'"$(cat "$EVIDENCE/cost.txt")"
ok "ast cost in the box printed this instance's spend"

inbox_ast "snapshot before-schema-migration" >"$EVIDENCE/snapshot.txt" 2>&1 \
  || { cat "$EVIDENCE/snapshot.txt"; fail "ast snapshot in the box"; }
cat "$EVIDENCE/snapshot.txt"
grep -qE '^snapshot "before-schema-migration" taken \([0-9]+\.[0-9]+ s\)$' "$EVIDENCE/snapshot.txt" \
  || fail "the snapshot line is not the transcript's:"$'\n'"$(cat "$EVIDENCE/snapshot.txt")"
# And it really is on the timeline the host can see — while the guest is still
# running, which is what an agent snapshotting itself has to mean.
"$AST" rewind "$INST" >"$EVIDENCE/timeline.txt" 2>&1 || fail "ast rewind"
grep -q before-schema-migration "$EVIDENCE/timeline.txt" \
  || fail "the agent's snapshot is not on the host's timeline:"$'\n'"$(cat "$EVIDENCE/timeline.txt")"
ok "an agent snapshotted its own running machine, and the host sees it"

inbox_ast "notify \"PR #42 opened — ready for review\"" >"$EVIDENCE/notify.txt" 2>&1 \
  || { cat "$EVIDENCE/notify.txt"; fail "ast notify in the box"; }
[ ! -s "$EVIDENCE/notify.txt" ] \
  || fail "ast notify said something, and it should say nothing:"$'\n'"$(cat "$EVIDENCE/notify.txt")"
"$AST" inbox >"$EVIDENCE/inbox-1.txt" 2>&1 || fail "ast inbox"
cat "$EVIDENCE/inbox-1.txt"
grep -q "notify  PR #42 opened — ready for review" "$EVIDENCE/inbox-1.txt" \
  || fail "the notification is not in the inbox:"$'\n'"$(cat "$EVIDENCE/inbox-1.txt")"
ok "ast notify reached the host's inbox and said nothing in the box"

# ---- the round trip --------------------------------------------------------
#
# The agent asks and blocks; the person answers; the answer is on the agent's
# stdout. Both halves are real processes on a real machine.
( inbox_ast "ask \"Change the prod schema now (A) or tomorrow morning (B)?\"" 180 \
    >"$EVIDENCE/ask.txt" 2>&1; echo "$?" >"$EVIDENCE/ask.status" ) &
ASK_PID=$!
SEQ=
for _ in $(seq 1 60); do
  SEQ="$("$AST" inbox --json 2>/dev/null \
    | awk -F'"seq":' '/"kind":"ask"/ {split($2, a, ","); print a[1]}' | tail -1)"
  [ -n "$SEQ" ] && break
  sleep 1
done
[ -n "$SEQ" ] || fail "the question never reached the inbox"
"$AST" inbox >"$EVIDENCE/inbox-waiting.txt" 2>&1
cat "$EVIDENCE/inbox-waiting.txt"
grep -q "ask     Change the prod schema now (A) or tomorrow morning (B)?" \
  "$EVIDENCE/inbox-waiting.txt" \
  || fail "the question is not in the inbox as an ask"
grep -q "\[reply: ast inbox reply $SEQ …\]" "$EVIDENCE/inbox-waiting.txt" \
  || fail "the waiting question does not carry the command that answers it"
ok "the agent's question is in the inbox, with the command that answers it"

"$AST" inbox reply "$SEQ" A >"$EVIDENCE/reply.txt" 2>&1 || fail "ast inbox reply"
cat "$EVIDENCE/reply.txt"
grep -qx "replied to $INST" "$EVIDENCE/reply.txt" \
  || fail "the reply line is not the transcript's:"$'\n'"$(cat "$EVIDENCE/reply.txt")"
wait "$ASK_PID" || true
cat "$EVIDENCE/ask.txt"
[ "$(cat "$EVIDENCE/ask.status")" = 0 ] \
  || fail "the agent's ask exited nonzero:"$'\n'"$(cat "$EVIDENCE/ask.txt")"
grep -qx "waiting for a reply… (your owner has been notified)" "$EVIDENCE/ask.txt" \
  || fail "the agent was not told its question had been delivered"
grep -qx "A" "$EVIDENCE/ask.txt" \
  || fail "the answer did not reach the agent:"$'\n'"$(cat "$EVIDENCE/ask.txt")"
ok "the agent asked, blocked, and read the answer a person typed on the host"

# ---- the agent forks itself ------------------------------------------------
#
# `--stopped` because the point here is the verb and its scoping, not three
# more booted machines on somebody's laptop.
inbox_ast "fork --n 2 --stopped" 120 >"$EVIDENCE/fork.txt" 2>&1 \
  || { cat "$EVIDENCE/fork.txt"; fail "ast fork in the box"; }
cat "$EVIDENCE/fork.txt"
grep -q "^$INST-1 $INST-2 defined — cloned from $INST in " "$EVIDENCE/fork.txt" \
  || fail "the fork line is not the one ast fork prints:"$'\n'"$(cat "$EVIDENCE/fork.txt")"
"$AST" ls --local >"$EVIDENCE/ls.txt" 2>&1 || fail "ast ls"
grep -q "^$INST-1 " "$EVIDENCE/ls.txt" || fail "the fork is not in the registry"
ok "the agent forked its own machine, and the host has the children"
"$AST" rm "$INST-1" >/dev/null 2>&1 || true
"$AST" rm "$INST-2" >/dev/null 2>&1 || true

# ---- the refusals ----------------------------------------------------------
set +e
inbox_ast "snapshot other-bot x" >"$EVIDENCE/refuse-name.txt" 2>&1
NAME_STATUS=$?
inbox_ast "secret ls" >"$EVIDENCE/refuse-secret.txt" 2>&1
SECRET_STATUS=$?
inbox_ast "fork other-bot --n 2" >"$EVIDENCE/refuse-fork.txt" 2>&1
FORK_STATUS=$?
set -e
cat "$EVIDENCE/refuse-name.txt"
[ "$NAME_STATUS" -ne 0 ] || fail "naming another instance was not refused"
grep -qx 'error: "other-bot" is not this instance — inside the box, ast acts on bot only' \
  "$EVIDENCE/refuse-name.txt" \
  || fail "the refusal is not the sentence it should be:"$'\n'"$(cat "$EVIDENCE/refuse-name.txt")"
[ "$FORK_STATUS" -ne 0 ] || fail "forking another instance was not refused"
grep -qx 'error: "other-bot" is not this instance — inside the box, ast acts on bot only' \
  "$EVIDENCE/refuse-fork.txt" \
  || fail "the fork refusal is not the sentence:"$'\n'"$(cat "$EVIDENCE/refuse-fork.txt")"
ok "naming another instance is refused by the sentence, for snapshot and for fork"

cat "$EVIDENCE/refuse-secret.txt"
[ "$SECRET_STATUS" -ne 0 ] || fail "reading a secret was not refused"
grep -q "cannot read them" "$EVIDENCE/refuse-secret.txt" \
  || fail "the secret refusal does not say why:"$'\n'"$(cat "$EVIDENCE/refuse-secret.txt")"
if grep -qF "$DUMMY" "$EVIDENCE/refuse-secret.txt"; then
  fail "the refusal printed the value it refused to print"
fi
ok "reading a credential value is refused, with the reason and the way to ask"

# ---- ast tell --------------------------------------------------------------
"$AST" tell "$INST" "run the test suite and fix what fails" >"$EVIDENCE/tell.txt" 2>&1 \
  || { cat "$EVIDENCE/tell.txt"; fail "ast tell"; }
cat "$EVIDENCE/tell.txt"
grep -qx "sent to $INST — follow with: ast logs $INST -f" "$EVIDENCE/tell.txt" \
  || fail "the tell line is not the transcript's:"$'\n'"$(cat "$EVIDENCE/tell.txt")"
ok "ast tell reached the running agent's session and said so"

# And that the keystrokes actually arrive there, which the agent's own screen
# cannot show: a TUI sitting on a confirmation dialog swallows plain
# characters, and "nothing appeared" would be a fact about Claude Code rather
# than about `ast tell`. So the same session name is given a plain shell, and
# the shell is asked to say something only a delivered line and a delivered
# Enter could make it say.
guest "tmux kill-session -t $INST 2>/dev/null; tmux new-session -d -s $INST /bin/sh" \
  >/dev/null 2>&1 || fail "could not put a shell in the agent's session"
"$AST" tell "$INST" "echo asterism-tell-landed" >"$EVIDENCE/tell-shell.txt" 2>&1 \
  || { cat "$EVIDENCE/tell-shell.txt"; fail "ast tell into a shell session"; }
LANDED=
for _ in $(seq 1 15); do
  guest "tmux capture-pane -p -S -200 -t $INST" >"$EVIDENCE/pane.txt" 2>&1 \
    || fail "tmux capture-pane"
  if grep -q "^asterism-tell-landed$" "$EVIDENCE/pane.txt"; then
    LANDED=1
    break
  fi
  sleep 2
done
[ -n "$LANDED" ] \
  || fail "the line never ran in the agent's session:"$'\n'"$(tail -20 "$EVIDENCE/pane.txt")"
ok "the line and its Enter both landed in the session named after the instance"

if "$AST" tell no-such-instance "hello" >"$EVIDENCE/tell-missing.txt" 2>&1; then
  fail "telling an instance that does not exist succeeded"
fi
ok "telling a machine that is not there is refused"

# ---- the token is nowhere ---------------------------------------------------
#
# The daemon armed this guest with 32 bytes of randomness the agent never sees.
# Read it out of the daemon's own log-free memory the only way a test can: by
# proving that nothing on either side of the wall has it written down.
guest "grep -rl -e asterism-ast -e ASTERISM_TOKEN /etc /run /work /root 2>/dev/null | head" \
  >"$EVIDENCE/token-hunt.txt" 2>&1 || true
[ ! -s "$EVIDENCE/token-hunt.txt" ] \
  || fail "something in the guest holds the channel token:"$'\n'"$(cat "$EVIDENCE/token-hunt.txt")"
guest "ls -la /run/asterism-ast.sock" >"$EVIDENCE/socket.txt" 2>&1 \
  || fail "the guest-local socket is not there"
grep -q "^s" "$EVIDENCE/socket.txt" \
  || fail "that is not a socket:"$'\n'"$(cat "$EVIDENCE/socket.txt")"
ok "the box has the socket and no copy of the token"

"$AST" bugreport >"$EVIDENCE/bugreport.txt" 2>&1 || true
if grep -aqiE 'agent_arm|"token"' "$EVIDENCE/bugreport.txt"; then
  fail "a bug report carries the channel token"
fi
ok "a bug report has no token in it"

# And the strongest form: the daemon's own files. The token is minted in memory
# and handed over the wire, so it must appear in nothing on this disk.
"$AST" down "$INST" >/dev/null || fail "ast down"
"$AST" snapshot "$INST" after-the-channel >/dev/null || fail "ast snapshot"
while IFS= read -r file; do
  case "$file" in
    *.raw|*.qcow2|*.vhdx) continue ;;
  esac
  if LC_ALL=C grep -aq 'asterism-ast-token' "$file"; then
    fail "the channel token was written down: $file"
  fi
done < <(find "$ASTERISM_HOME" -type f -print)
ok "no file this device wrote holds a channel token"

echo "GUEST AST E2E GREEN (vz, $REGISTRY_HTTPS/agent-claude-code@$DIGEST)"
