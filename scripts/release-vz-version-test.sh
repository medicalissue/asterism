#!/usr/bin/env bash
# Focused regression test for the release workflow's astd-vz identity check.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/asterism-release-vz-test.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

CHECK="$ROOT/scripts/check-release-vz-version.sh"
FAKE="$WORK/astd-vz"
cat >"$FAKE" <<'SH'
#!/bin/sh
printf '%s\n' "version   0.0.2" "build     0.0.2+test-sha"
SH
chmod +x "$FAKE"

"$CHECK" "$FAKE" 0.0.2 0.0.2+test-sha

if "$CHECK" "$FAKE" 0.0.3 0.0.2+test-sha >/dev/null 2>&1; then
	echo "accepted an unexpected astd-vz version" >&2
	exit 1
fi
if "$CHECK" "$FAKE" 0.0.2 0.0.2+other-sha >/dev/null 2>&1; then
	echo "accepted an unexpected astd-vz build" >&2
	exit 1
fi

cat >"$FAKE" <<'SH'
#!/bin/sh
printf '%s\n' "version   0.0.2" "build     0.0.2+test-sha" "extra output"
SH
if "$CHECK" "$FAKE" 0.0.2 0.0.2+test-sha >/dev/null 2>&1; then
	echo "accepted extra astd-vz version output" >&2
	exit 1
fi

cat >"$FAKE" <<'SH'
#!/bin/sh
printf '%s\n' "astd-vz 0.0.2"
SH
if "$CHECK" "$FAKE" 0.0.2 0.0.2+test-sha >/dev/null 2>&1; then
	echo "accepted legacy one-line astd-vz output" >&2
	exit 1
fi

echo "ok: astd-vz structured version/build output is verified exactly"
