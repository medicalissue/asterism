#!/usr/bin/env bash
# End-to-end for credential parts (AST-157) on a real VZ guest.
#
#   login Keychain -> credential part -> opaque handle in the guest ->
#   the guest-only vsock egress door -> a real, authenticated GitHub API call
#
# WHY THIS SHAPE. The claim credential parts make is not "a token can be
# stored". It is that an agent's tools arrive already logged in while the
# token never enters the machine the agent runs on. Proving that needs a real
# provider, a real token, and a real answer that could only have come from an
# authenticated call — so this lane imports the token this Mac's own `gh`
# already holds, binds it as a credential part, and asks the guest to fetch
# `api.github.com/user`. The login it gets back is the proof: an unauthenticated
# call to that endpoint returns 401, and no fixture can produce a name.
#
# The token is read into a shell variable so the plaintext sweep has something
# to search for. It is never echoed, never written to a file, and never put in
# argv — `ast login gh` runs `gh auth token` itself.
#
# WHAT IT DOES NOT PROVE. Not a real Google OAuth grant: that needs a human in
# a browser and cannot run unattended, so the `refresh` rule — the exchange of
# a refresh token for an access token and the Bearer substitution that follows
# — is proved instead by
# `crates/asterism-daemon/src/egress.rs::a_refresh_rule_spends_a_grant_and_sends_only_what_it_bought`,
# which drives the production door against a local mock token endpoint over
# real TLS. The `sign` rule (AWS SigV4) is likewise proved by
# `a_sign_rule_signs_the_request_the_guest_actually_made` and by AWS's own
# published vector in `crates/asterism-core/src/sigv4.rs`. Neither is exercised
# here, and this lane says so rather than implying otherwise.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export PATH="$HOME/.cargo/bin:$PATH"
cd "$ROOT"

# shellcheck source-path=SCRIPTDIR source=lib/harness.sh
. "$ROOT/scripts/lib/harness.sh"
harness_begin credentials
harness_binaries "$ROOT"

fail() { echo "CREDENTIALS E2E FAIL: $*" >&2; exit 1; }
ok() { echo "ok: $*"; }

if [ "$(uname -s)" != Darwin ]; then
  harness_skip "this lane drives the VZ door and the login Keychain, both macOS-only"
fi

if [ -z "${AST_BIN:-}" ]; then
  "$ROOT/scripts/sign-vz.sh"
fi

GUEST_ARTIFACT="${ASTERISM_GUEST_AGENT_ARTIFACT:-$(dirname "$ASTD")/guest/bin/asterism-guest}"
if [ ! -x "$GUEST_ARTIFACT" ]; then
  harness_skip "set ASTERISM_GUEST_AGENT_ARTIFACT to a static $(uname -m) Linux asterism-guest"
fi

if ! command -v gh >/dev/null 2>&1; then
  harness_skip "this lane imports the token the host's own gh holds, and gh is not installed"
fi

# Read once, here, so the sweep below has something to look for. Never printed.
HOST_TOKEN="$(gh auth token 2>/dev/null || true)"
if [ -z "$HOST_TOKEN" ]; then
  harness_skip "gh is installed but not signed in on this host — run: gh auth login"
fi
EXPECT_LOGIN="$(gh api user --jq .login 2>/dev/null || true)"
if [ -z "$EXPECT_LOGIN" ]; then
  harness_skip "the host's gh token cannot read api.github.com/user"
fi

export ASTERISM_HOME="/private/tmp/ast-credentials-$$"
export ASTERISM_MESH=local
export ASTERISM_TEST_SERVICE_LABEL="com.asterism.astd.test.credentials.$$.$RANDOM"
mkdir -p "$ASTERISM_HOME"
harness_own_home "$ASTERISM_HOME"

BIN="$ASTERISM_HOME/bin"
LOG="$ASTERISM_HOME/astd.log"
EVIDENCE="$ASTERISM_HOME/evidence"
IMAGE="${E2E_IMAGE:-docker.io/library/nginx:alpine}"
INST=bot
# A name of its own, so this lane can never remove a credential part the
# person running it actually uses.
PART="gh-e2e-$$-$RANDOM"
PROFILE_TIMEOUT="${E2E_PROFILE_TIMEOUT:-300}"
ASTD_PID=
PART_CREATED=
HANDLE=

cleanup() {
  "$AST" down "$INST" >/dev/null 2>&1 || true
  "$AST" rm "$INST" >/dev/null 2>&1 || true
  if [ -n "$PART_CREATED" ]; then
    "$AST" secret rm "$PART" >/dev/null 2>&1 || true
  fi
  harness_keep_home "$ASTERISM_HOME" home
  harness_reap
  if [ -n "${KEEP:-}" ]; then
    echo "kept $ASTERISM_HOME for inspection"
  else
    case "$ASTERISM_HOME" in
      /private/tmp/ast-credentials-*) rm -rf -- "$ASTERISM_HOME" ;;
      *) echo "refusing to remove unexpected scratch path: $ASTERISM_HOME" >&2 ;;
    esac
  fi
  harness_artifacts_note
}
trap cleanup EXIT

expect() {
  local desc="$1" needle="$2"
  shift 2
  local out
  if ! out="$("$@" 2>&1)"; then
    fail "$desc: command failed:"$'\n'"$out"
  fi
  if ! grep -qF "$needle" <<<"$out"; then
    fail "$desc: expected \"$needle\" in:"$'\n'"$out"
  fi
  ok "$desc"
}

guest() { "$AST" exec "$INST" -- /bin/sh -c "$1"; }

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

echo "== credential parts e2e in $ASTERISM_HOME"
harness_cache_image "$AST" "$IMAGE" || fail "could not cache $IMAGE"
harness_seed_images "$ASTERISM_HOME"

"$ASTD" >>"$LOG" 2>&1 &
ASTD_PID=$!
for _ in $(seq 1 100); do
  if [ "$(cat "$ASTERISM_HOME/astd.pid" 2>/dev/null || true)" = "$ASTD_PID" ]; then
    break
  fi
  sleep 0.2
done
if [ "$(cat "$ASTERISM_HOME/astd.pid" 2>/dev/null || true)" != "$ASTD_PID" ]; then
  fail "astd did not come up:"$'\n'"$(cat "$LOG" 2>/dev/null || true)"
fi

# ---- what this build declares ---------------------------------------------
providers="$("$AST" credential providers 2>&1)" || fail "ast credential providers failed"
printf '%s\n' "$providers" >"$EVIDENCE/providers.txt"
for needle in "github" "google" "npm" "aws"; do
  if ! grep -qF "$needle" <<<"$providers"; then
    fail "ast credential providers omits $needle:"$'\n'"$providers"
  fi
done
if ! grep -qE '^google +oauth +refresh' <<<"$providers"; then
  fail "google is not declared as an oauth part with a refresh rule:"$'\n'"$providers"
fi
if ! grep -qE '^aws +login +sign' <<<"$providers"; then
  fail "aws is not declared with a sign rule:"$'\n'"$providers"
fi
ok "the provider catalog declares all three door rules"

# ---- sign in ---------------------------------------------------------------
login_report="$("$AST" login gh --as "$PART" 2>&1)" || fail "ast login gh:"$'\n'"$login_report"
PART_CREATED=1
if ! grep -qF "signed in as $EXPECT_LOGIN" <<<"$login_report"; then
  fail "ast login gh did not name the account:"$'\n'"$login_report"
fi
if grep -qF "$HOST_TOKEN" <<<"$login_report"; then
  fail "ast login printed the token"
fi
ok "ast login gh reused the host's own gh token and named the account"

ls_out="$("$AST" credential ls 2>&1)" || fail "ast credential ls failed"
printf '%s\n' "$ls_out" >"$EVIDENCE/credential-ls.txt"
if ! grep -qE "^$PART +login +github +substitute" <<<"$ls_out"; then
  fail "ast credential ls does not describe the part:"$'\n'"$ls_out"
fi
ok "ast credential ls names the kind, the provider and the door rule"

# ---- attach ----------------------------------------------------------------
expect "create the agent VM" "$INST  defined" \
  "$AST" create "$INST" --backend vz --image "$IMAGE" \
  --cpus 4 --mem 2G --disk 4G --profile base

attach="$("$AST" attach "$INST" --credential "$PART" 2>&1)" \
  || fail "ast attach --credential:"$'\n'"$attach"
printf '%s\n' "$attach" >"$EVIDENCE/attach.txt"
for needle in "api.github.com" "codeload.github.com" "raw.githubusercontent.com" \
              "GH_TOKEN" "GITHUB_TOKEN"; do
  if ! grep -qF "$needle" <<<"$attach"; then
    fail "attaching the credential did not bind $needle:"$'\n'"$attach"
  fi
done
ok "one --credential bound every authority the provider declares, under one handle"

expect "boot the bound guest" "$INST  running" "$AST" up "$INST"

echo "waiting up to ${PROFILE_TIMEOUT}s for the base profile ..."
deadline=$(($(date +%s) + PROFILE_TIMEOUT))
while :; do
  if "$AST" profile "$INST" --check >/dev/null 2>&1; then
    break
  fi
  if [ "$(date +%s)" -ge "$deadline" ]; then
    fail "the base profile did not become ready"
  fi
  sleep 5
done
ok "the guest is ready and reachable over authenticated guest control"

# ---- what the guest holds --------------------------------------------------
HANDLE="$(guest 'printenv GH_TOKEN')" || fail "the guest exposes no GH_TOKEN"
case "$HANDLE" in
  sk-ast-gh-*) ;;
  *) fail "the guest got something other than a gh-shaped handle" ;;
esac
if [ "$HANDLE" = "$HOST_TOKEN" ]; then
  fail "the guest was given the real token"
fi
ok "the guest holds sk-ast-gh-… — a handle in the provider's own shape"

also="$(guest 'printenv GITHUB_TOKEN')" || fail "the guest exposes no GITHUB_TOKEN"
if [ "$also" != "$HANDLE" ]; then
  fail "the provider's second variable does not carry the same handle"
fi
ok "every variable the provider declares carries the one handle"

# ---- the call that could only have been authenticated ----------------------
who="$(guest "curl -sS -H \"Authorization: Bearer \$GH_TOKEN\" \
  -H 'User-Agent: asterism-e2e' https://api.github.com/user")" \
  || fail "the guest's GitHub call did not complete"
printf '%s\n' "$who" >"$EVIDENCE/api-user.json"
# Whitespace-insensitive, because GitHub pretty-prints and a lane should not
# fail on an indentation change somewhere else.
if ! grep -qF "\"login\":\"$EXPECT_LOGIN\"" <<<"$(tr -d ' \n' <<<"$who")"; then
  fail "api.github.com/user did not answer as $EXPECT_LOGIN:"$'\n'"$who"
fi
ok "the guest's unmodified curl reached api.github.com as $EXPECT_LOGIN"

# The older `token` scheme, which `gh` itself still sends to some endpoints.
# A door that recognised only Bearer would refuse the tool it exists to serve.
token_scheme="$(guest "curl -sS -H \"Authorization: token \$GH_TOKEN\" \
  -H 'User-Agent: asterism-e2e' https://api.github.com/user")" \
  || fail "the guest's token-scheme call did not complete"
if ! grep -qF "$EXPECT_LOGIN" <<<"$token_scheme"; then
  fail "the door refused the older token scheme:"$'\n'"$token_scheme"
fi
ok "the door accepts the handle under both schemes GitHub's own tools send"

# A credential the guest made up is refused rather than swapped. The value is
# put in a variable rather than written inline so a secret scanner does not
# have to decide whether a deliberately invalid handle is a leaked one.
FORGED_HANDLE="sk-ast-gh-NOTTHISINSTANCES"
forged="$(guest "FORGED='$FORGED_HANDLE'; curl -s -o /dev/null -w '%{http_code}' \
  -H \"Authorization: Bearer \$FORGED\" \
  https://api.github.com/user")" || fail "the forged-handle call did not complete"
if [ "$forged" != "401" ]; then
  fail "a forged handle got $forged, not 401"
fi
ok "a handle this instance did not mint is refused at the door"

# ---- the token is nowhere the guest can reach ------------------------------
GUEST_SWEEP="/etc /root /home /var /tmp /run /usr/local /.asterism"
found="$(guest "grep -rlaF '$HOST_TOKEN' $GUEST_SWEEP 2>/dev/null | head -5" || true)"
if [ -n "$found" ]; then
  fail "the real token is on the guest's disk: $found"
fi
found="$(guest "tr '\\0' '\\n' </proc/1/environ | grep -aF '$HOST_TOKEN'" || true)"
if [ -n "$found" ]; then
  fail "the real token is in the guest's own environment"
fi
ok "the real token is absent from the guest's writable tree and from pid 1's environment"

logs="$("$AST" logs "$INST" 2>&1 || true)"
printf '%s\n' "$logs" >"$EVIDENCE/logs.txt"
if LC_ALL=C grep -aqF "$HOST_TOKEN" <<<"$logs"; then
  fail "the real token is in ast logs"
fi
bugreport="$("$AST" bugreport 2>&1)" || fail "ast bugreport failed"
printf '%s\n' "$bugreport" >"$EVIDENCE/bugreport.txt"
if LC_ALL=C grep -aqF "$HOST_TOKEN" <<<"$bugreport"; then
  fail "the real token is in ast bugreport"
fi
ok "the real token is absent from ast logs and ast bugreport"

# The whole home, including the guest's disk image and every snapshot in it.
while IFS= read -r file; do
  if LC_ALL=C grep -aqF "$HOST_TOKEN" "$file"; then
    fail "the real token entered $file"
  fi
done < <(find "$ASTERISM_HOME" -type f -print)
ok "the real token is absent from every byte this lane wrote, disk images included"

# And the handle is not the token, which is the other half of the claim.
if [ -z "$HANDLE" ]; then
  fail "no handle to check"
fi
if LC_ALL=C grep -aqF "$HANDLE" <<<"$HOST_TOKEN"; then
  fail "the handle is derived from the token"
fi
ok "the handle is not the token and carries none of it"

# ---- revocation ------------------------------------------------------------
expect "revoke the credential part" "$PART revoked" \
  "$AST" detach "$INST" --credential "$PART"

status="$("$AST" status "$INST" 2>&1)" || fail "ast status failed"
printf '%s\n' "$status" >"$EVIDENCE/status-after-detach.txt"
if grep -qF "github.com" <<<"$status"; then
  fail "a binding survived the revocation:"$'\n'"$status"
fi
ok "every binding the credential made went at once"

after="$(guest "curl -s -o /dev/null -w '%{http_code}' \
  -H \"Authorization: Bearer \$GH_TOKEN\" https://api.github.com/user")" \
  || fail "the post-revocation call did not complete"
if [ "$after" = "200" ]; then
  fail "the handle is still honoured after detach"
fi
ok "the handle the guest still holds stops being honoured immediately (got $after)"

# ---- what this lane did not do --------------------------------------------
cat >"$EVIDENCE/not-executed.txt" <<'NOTE'
Not executed by this lane:
  * a real Google OAuth grant. `ast oauth add google` opens a browser and
    needs a human; the refresh -> access exchange and the Bearer substitution
    that follow it are proved instead by the daemon test
    egress::tests::a_refresh_rule_spends_a_grant_and_sends_only_what_it_bought,
    against a local mock token endpoint over real TLS.
  * a real AWS call. The SigV4 signer is proved against AWS's own published
    get-vanilla vector and against a mock verifier that recomputes the
    signature from the canonical request, in
    crates/asterism-core/src/sigv4.rs; the door-side rule is proved by
    egress::tests::a_sign_rule_signs_the_request_the_guest_actually_made.
  * npm, docker, slack, notion and linear. Declared, marked experimental, and
    not proved against the real service.
NOTE
ok "what was not proved is written down beside what was"

echo "CREDENTIALS E2E GREEN (gh login part, vz, vsock egress door, $EXPECT_LOGIN)"
