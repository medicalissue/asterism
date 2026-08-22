#!/bin/sh
# Regression for the easy-to-miss distinction between an event commit range
# and the repository's complete reachable history. The synthetic credential
# is assembled only inside an isolated temporary repository; this source tree
# never contains the complete fixture value.
set -eu

command -v gitleaks >/dev/null 2>&1 || {
  echo "gitleaks-history-test: gitleaks is required" >&2
  exit 2
}

fixture="$(mktemp -d "${TMPDIR:-/tmp}/asterism-gitleaks.XXXXXX")"
trap 'rm -rf "$fixture"' EXIT HUP INT TERM

git -C "$fixture" init -q
git -C "$fixture" config user.name "Asterism CI"
git -C "$fixture" config user.email "ci@invalid.example"

# Split the inert fixture so the project checkout does not itself match the
# default aws-access-token rule. The resulting value is intentionally fake.
fixture_secret="AKIA$(printf '%s' '0123456789ABCDEF')"
printf 'AWS_ACCESS_KEY_ID=%s\n' "$fixture_secret" >"$fixture/old.env"
git -C "$fixture" add old.env
GIT_AUTHOR_DATE='2000-01-01T00:00:00Z' GIT_COMMITTER_DATE='2000-01-01T00:00:00Z' \
  git -C "$fixture" commit -qm 'seed old-history fixture'

rm "$fixture/old.env"
git -C "$fixture" add -u
GIT_AUTHOR_DATE='2000-01-02T00:00:00Z' GIT_COMMITTER_DATE='2000-01-02T00:00:00Z' \
  git -C "$fixture" commit -qm 'remove fixture before event delta'
GIT_AUTHOR_DATE='2000-01-03T00:00:00Z' GIT_COMMITTER_DATE='2000-01-03T00:00:00Z' \
  git -C "$fixture" commit -q --allow-empty -m 'simulated event commit'

# The latest-commit range is clean by construction. This establishes that the
# finding really is outside the range an event-scoped scan would inspect.
gitleaks git --no-banner --redact=100 --config "$PWD/.gitleaks.toml" \
  --log-opts='HEAD^..HEAD' "$fixture" >"$fixture/event.log" 2>&1

set +e
gitleaks git --no-banner --redact=100 --config "$PWD/.gitleaks.toml" \
  --log-opts=--all --report-format=json --report-path="$fixture/report.json" \
  "$fixture" >"$fixture/all-history.log" 2>&1
status=$?
set -e

[ "$status" -eq 1 ] || {
  echo "gitleaks-history-test: complete-history scan did not detect the seeded finding" >&2
  exit 1
}

FIXTURE_SECRET="$fixture_secret" node - "$fixture/report.json" <<'NODE'
const { readFileSync } = require("node:fs");
const reportPath = process.argv[2];
const raw = readFileSync(reportPath, "utf8");
const findings = JSON.parse(raw);
if (!Array.isArray(findings) || findings.length === 0) {
  throw new Error("complete-history report contains no findings");
}
if (raw.includes(process.env.FIXTURE_SECRET)) {
  throw new Error("complete-history report contains an unredacted fixture value");
}
NODE

echo "gitleaks-history-test: complete-history scan detected one redacted old-history fixture outside the event delta"
