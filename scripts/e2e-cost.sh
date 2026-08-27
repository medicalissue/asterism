#!/usr/bin/env bash
# End-to-end for the token and cost ledger (AST-151) on a real VZ guest.
#
# WHY THIS SHAPE. The counters `ast cost` reports come out of the response
# body of an API call the guest made through its bound egress door. Proving
# that needs an upstream that answers in the shapes Anthropic and OpenAI
# answer in — and it must not need an API key, because a lane that needed one
# could not run.
#
# The trick is that the door reads the *answer*, so any server that returns
# the right bytes is a complete test of the reading. `httpbin.org/base64/<b64>`
# is a real, public, properly certificated endpoint that returns exactly the
# bytes this script hands it. So the guest asks a real HTTPS host, over the
# real vsock door, through the real secrets plane, for a body that looks like
# an Anthropic answer — and the ledger has to fill.
#
# That is also why detection in `asterism_core::usage` is shape-first rather
# than keyed on `api.anthropic.com`: an agent pointed at a gateway is the
# ordinary case, and this lane is the same case.
#
# WHAT IT DOES NOT PROVE. Not a real Anthropic or OpenAI endpoint, and not
# their TLS. The exact wire shapes are covered by fixtures in
# `crates/asterism-core/src/usage.rs` and by the mock-upstream integration
# test in `crates/asterism-daemon/src/egress.rs`, which drives the same
# shapes through a real CONNECT and a real TLS termination.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export PATH="$HOME/.cargo/bin:$PATH"
cd "$ROOT"

# shellcheck source-path=SCRIPTDIR
. "$ROOT/scripts/lib/harness.sh"
harness_begin cost
harness_binaries "$ROOT"

[ "$(uname -s)" = Darwin ] \
  || harness_skip "this lane drives the VZ door and the login Keychain, both macOS-only"

if [ -z "${AST_BIN:-}" ]; then
  "$ROOT/scripts/sign-vz.sh"
fi

GUEST_ARTIFACT="${ASTERISM_GUEST_AGENT_ARTIFACT:-$(dirname "$ASTD")/guest/bin/asterism-guest}"
[ -x "$GUEST_ARTIFACT" ] \
  || harness_skip "set ASTERISM_GUEST_AGENT_ARTIFACT to a static $(uname -m) Linux asterism-guest"

UPSTREAM="${E2E_COST_UPSTREAM:-httpbin.org}"
curl -fsS --max-time 20 "https://$UPSTREAM/base64/YXN0ZXJpc20K" >/dev/null 2>&1 \
  || harness_skip "$UPSTREAM did not answer /base64 — this lane needs a public byte echo"

export ASTERISM_HOME="/private/tmp/ast-cost-$$"
export ASTERISM_MESH=local
export ASTERISM_TEST_SERVICE_LABEL="com.asterism.astd.test.cost.$$.$RANDOM"
mkdir -p "$ASTERISM_HOME"
harness_own_home "$ASTERISM_HOME"

BIN="$ASTERISM_HOME/bin"
LOG="$ASTERISM_HOME/astd.log"
EVIDENCE="$ASTERISM_HOME/evidence"
IMAGE="${E2E_IMAGE:-docker.io/library/nginx:alpine}"
INST=bot
SECRET="cost-sentinel-$$-$RANDOM"
SENTINEL="raw-cost-sentinel-$$-$RANDOM-$RANDOM"
PROFILE_TIMEOUT="${E2E_PROFILE_TIMEOUT:-300}"
ASTD_PID=
SECRET_CREATED=
HANDLE=

cleanup() {
  "$AST" down "$INST" >/dev/null 2>&1 || true
  "$AST" rm "$INST" >/dev/null 2>&1 || true
  if [ -n "$SECRET_CREATED" ]; then
    "$AST" secret rm "$SECRET" >/dev/null 2>&1 || true
  fi
  harness_keep_home "$ASTERISM_HOME" home
  harness_reap
  if [ -n "${KEEP:-}" ]; then
    echo "kept $ASTERISM_HOME for inspection"
  else
    case "$ASTERISM_HOME" in
      /private/tmp/ast-cost-*) rm -rf -- "$ASTERISM_HOME" ;;
      *) echo "refusing to remove unexpected scratch path: $ASTERISM_HOME" >&2 ;;
    esac
  fi
  harness_artifacts_note
}
trap cleanup EXIT

fail() { echo "COST E2E FAIL: $*" >&2; exit 1; }
ok() { echo "ok: $*"; }

expect() {
  local desc="$1" needle="$2"; shift 2
  local out
  out="$("$@" 2>&1)" || fail "$desc: command failed:"$'\n'"$out"
  grep -qF "$needle" <<<"$out" || fail "$desc: expected \"$needle\" in:"$'\n'"$out"
  ok "$desc"
}

guest() { "$AST" exec "$INST" -- /bin/sh -c "$1"; }

# ---- the bodies the guest will ask the public echo to hand back ------------
#
# Written out in full rather than generated, because what is being tested is
# that these exact published shapes are read correctly. Base64 is urlsafe
# because that is what the endpoint decodes.
b64() { printf %s "$1" | base64 | tr '+/' '-_' | tr -d '\n'; }

ANTHROPIC_BODY='{"id":"msg_costlane","type":"message","role":"assistant","model":"claude-sonnet-5","content":[{"type":"text","text":"the-body-marker"}],"stop_reason":"end_turn","usage":{"input_tokens":1000,"output_tokens":200,"cache_creation_input_tokens":300,"cache_read_input_tokens":4000}}'

ANTHROPIC_STREAM='event: message_start
data: {"type":"message_start","message":{"id":"msg_coststream","type":"message","role":"assistant","model":"claude-opus-5","content":[],"usage":{"input_tokens":2000,"output_tokens":1,"cache_creation_input_tokens":0,"cache_read_input_tokens":50000}}}

event: content_block_delta
data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"the-body-marker"}}

event: message_delta
data: {"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":500}}

event: message_stop
data: {"type":"message_stop"}
'

OPENAI_BODY='{"id":"chatcmpl-costlane","object":"chat.completion","model":"gpt-4o","choices":[],"usage":{"prompt_tokens":900,"completion_tokens":90,"total_tokens":990,"prompt_tokens_details":{"cached_tokens":400}}}'

UNKNOWN_BODY='{"answer":"an API this device has never heard of"}'

# The counters above, summed the way the ledger must sum them. OpenAI's
# `prompt_tokens` is a total that includes its cached part, so the fresh
# input from that call is 900 - 400.
EXPECT_INPUT=$((1000 + 2000 + 500))
EXPECT_OUTPUT=$((200 + 500 + 90))
EXPECT_CACHE_WRITE=300
EXPECT_CACHE_READ=$((4000 + 50000 + 400))
EXPECT_CALLS=4

mkdir -p "$BIN/guest/bin" "$EVIDENCE"
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

echo "== cost ledger e2e in $ASTERISM_HOME"
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

# A ledger that reported something before a single call was made would be the
# worst possible bug in this feature, so it is asserted before anything else.
expect "an instance that has made no calls reports none" "no model API calls recorded" \
  "$AST" cost --all --today

expect "create the agent VM" "$INST  defined" \
  "$AST" create "$INST" --backend vz --image "$IMAGE" \
    --cpus 4 --mem 2G --disk 4G --profile base

secret_report="$(printf %s "$SENTINEL" | "$AST" secret create "$SECRET" 2>&1)" \
  || fail "creating the Keychain sentinel:"$'\n'"$secret_report"
SECRET_CREATED=1
ok "the sentinel entered the login Keychain through stdin"

expect "bind the secret to the upstream the guest will call" "$SECRET -> $UPSTREAM" \
  "$AST" attach "$INST" --secret "$SECRET" --to "$UPSTREAM" \
    --as bearer --env ASTERISM_SENTINEL

expect "boot the bound guest" "$INST  running" "$AST" up "$INST"

echo "waiting up to ${PROFILE_TIMEOUT}s for the base profile ..."
deadline=$(( $(date +%s) + PROFILE_TIMEOUT ))
while :; do
  if "$AST" profile "$INST" --check >/dev/null 2>&1; then break; fi
  [ "$(date +%s)" -lt "$deadline" ] || fail "the base profile did not become ready"
  sleep 5
done
ok "the guest is ready and reachable over authenticated guest control"

HANDLE="$(guest 'printenv ASTERISM_SENTINEL')" || fail "the guest exposes no handle"
case "$HANDLE" in ast-*) ;; *) fail "the guest got something other than an opaque handle" ;; esac
ok "the guest holds an opaque handle, not the Keychain value"

# ---- four real calls through the real door ---------------------------------
call() {
  local desc="$1" body="$2" encoded
  encoded="$(b64 "$body")"
  guest "curl -fsS 'https://$UPSTREAM/base64/$encoded' >/dev/null" \
    || fail "$desc: the guest's call did not complete"
  ok "$desc"
}

call "an Anthropic Messages answer crosses the door" "$ANTHROPIC_BODY"
call "an Anthropic streaming answer crosses the door" "$ANTHROPIC_STREAM"
call "an OpenAI Chat Completions answer crosses the door" "$OPENAI_BODY"
call "an answer this device cannot read crosses the door" "$UNKNOWN_BODY"

# ---- the ledger ------------------------------------------------------------
LEDGER_DIR="$ASTERISM_HOME/instances/$INST/cost"
[ -d "$LEDGER_DIR" ] || fail "no ledger directory at $LEDGER_DIR"
LEDGER="$(find "$LEDGER_DIR" -maxdepth 1 -name '*.jsonl' -print)"
[ -n "$LEDGER" ] || fail "the ledger directory holds no day file"
cp "$LEDGER" "$EVIDENCE/ledger.jsonl"
ok "the ledger rotated into $(basename "$LEDGER")"

lines="$(wc -l <"$LEDGER" | tr -d ' ')"
[ "$lines" = "$EXPECT_CALLS" ] \
  || fail "the ledger has $lines line(s), not $EXPECT_CALLS:"$'\n'"$(cat "$LEDGER")"
ok "one line per call, and only per call"

# Nothing from any of the four bodies, and neither credential, reached disk.
for forbidden in "the-body-marker" "msg_costlane" "chatcmpl-costlane" "end_turn" \
                 "$SENTINEL" "$HANDLE"; do
  if LC_ALL=C grep -aqF "$forbidden" "$LEDGER"; then
    fail "the ledger contains $forbidden"
  fi
done
ok "no body byte, no handle and no Keychain value is in the ledger"

# The whole home, not only the ledger: a counter written somewhere else would
# pass the check above and still be a leak.
while IFS= read -r file; do
  case "$file" in *.raw|*.qcow2|*.vhdx) continue ;; esac
  if LC_ALL=C grep -aqF "$SENTINEL" "$file"; then
    fail "the raw sentinel entered Asterism metadata: $file"
  fi
done < <(find "$ASTERISM_HOME" -type f -print)
ok "the raw sentinel is absent from every file this lane wrote"

# ---- what the user sees ----------------------------------------------------
cost_json="$("$AST" cost "$INST" --today --json)" || fail "ast cost --json failed"
printf '%s\n' "$cost_json" >"$EVIDENCE/cost.json"
field() {
  python3 -c 'import json,sys; print(json.loads(sys.stdin.read())[sys.argv[1]])' \
    "$1" <<<"$cost_json"
}

for pair in "calls:$EXPECT_CALLS" "input_tokens:$EXPECT_INPUT" \
            "output_tokens:$EXPECT_OUTPUT" "cache_write_tokens:$EXPECT_CACHE_WRITE" \
            "cache_read_tokens:$EXPECT_CACHE_READ" "unpriced_calls:1"; do
  key="${pair%%:*}"; want="${pair##*:}"
  got="$(field "$key")"
  [ "$got" = "$want" ] || fail "cost --json $key is $got, not $want:"$'\n'"$cost_json"
done
ok "ast cost --json reports the providers' own counters"

report="$("$AST" cost "$INST" 2>&1)" || fail "ast cost failed:"$'\n'"$report"
printf '%s\n' "$report" >"$EVIDENCE/cost.txt"
for needle in "today" "this week" "claude-opus-5" "+2 more" "in ·" "cache "; do
  grep -qF "$needle" <<<"$report" || fail "ast cost omitted '$needle':"$'\n'"$report"
done
grep -qE '\$[0-9]+\.[0-9]{2}' <<<"$report" || fail "ast cost printed no dollar figure:"$'\n'"$report"
grep -qF "1 call used a model this device has no rate for" <<<"$report" \
  || fail "ast cost did not say the total is a floor:"$'\n'"$report"
ok "ast cost prints today, this week, the busiest model and an honest caveat"

all="$("$AST" cost --all --today 2>&1)" || fail "ast cost --all failed:"$'\n'"$all"
printf '%s\n' "$all" >"$EVIDENCE/cost-all.txt"
grep -qE "^$INST +\\\$[0-9]+\.[0-9]{2}$" <<<"$all" \
  || fail "ast cost --all did not list $INST with a figure:"$'\n'"$all"
ok "ast cost --all lists every instance this device pays for"

ls_out="$("$AST" ls 2>&1)" || fail "ast ls failed:"$'\n'"$ls_out"
printf '%s\n' "$ls_out" >"$EVIDENCE/ls.txt"
grep -qF "TODAY" <<<"$ls_out" || fail "ast ls has no TODAY column:"$'\n'"$ls_out"
grep -qE "^$INST .*\\\$[0-9]+\.[0-9]{2}" <<<"$ls_out" \
  || fail "ast ls shows no spend for $INST:"$'\n'"$ls_out"
ok "ast ls carries today's spend beside the instance"

# ---- the ledger is portable ------------------------------------------------
expect "stop for a consistent export" "$INST  stopped" "$AST" down "$INST"
expect "export the instance" "exported" "$AST" backup export "$INST" "$ASTERISM_HOME/backup"
manifest="$("$AST" backup inspect "$ASTERISM_HOME/backup" --json)" \
  || fail "inspecting the backup failed"
grep -qF "cost/" <<<"$manifest" \
  || fail "the backup manifest does not carry the ledger:"$'\n'"$manifest"
if grep -qF "egress/" <<<"$manifest"; then
  fail "the backup manifest carries host plumbing it must not"
fi
ok "the ledger travels with a backup and the egress directory does not"

echo "COST E2E GREEN ($EXPECT_CALLS calls, $UPSTREAM, vz, vsock egress door)"
