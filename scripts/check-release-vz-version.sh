#!/bin/sh
# Verify the structured version output from an installed release helper.
set -eu

binary=${1:?usage: check-release-vz-version.sh BINARY VERSION BUILD}
expected_version=${2:?usage: check-release-vz-version.sh BINARY VERSION BUILD}
expected_build=${3:?usage: check-release-vz-version.sh BINARY VERSION BUILD}

got="$("$binary" --version)"
expected=$(printf 'version   %s\nbuild     %s' "$expected_version" "$expected_build")

if [ "$got" != "$expected" ]; then
	echo "unexpected astd-vz version output:" >&2
	printf '%s\n' "$got" >&2
	echo "expected:" >&2
	printf '%s\n' "$expected" >&2
	exit 1
fi
