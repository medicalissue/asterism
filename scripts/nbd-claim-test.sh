#!/usr/bin/env bash
# Source fixture for the root-side NBD claim publisher. It deliberately uses
# an empty fake sysfs and a fake nbd-client: the point is to exercise every
# crash/write/publication boundary without loading the kernel's nbd module.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
HELPER="${ROOT}/packaging/asterism-nbd"

if [ "$(id -u)" -ne 0 ]; then
	echo "nbd-claim-test: skipped (root is required to exercise the installed boundary)"
	exit 0
fi

WORK="$(mktemp -d "${TMPDIR:-/tmp}/asterism-nbd-claim.XXXXXX")"
STATE="${WORK}/state"
SYSFS="${WORK}/sys/block"
LOCK="${WORK}/lock"
CLIENT="${WORK}/nbd-client"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$STATE" "$SYSFS/nbd0"
: >"$LOCK"

cat >"$CLIENT" <<'EOF'
#!/bin/sh
set -eu
case "${1-}" in
-d)
	rm -f "${ASTERISM_NBD_SYSFS}/nbd0/pid"
	;;
*)
	# The attach path is intentionally unsuccessful. Publication and rollback
	# must still remove every private or final claim it created.
	exit 1
	;;
esac
EOF
chmod 0755 "$CLIENT"

run_helper() {
	ASTERISM_NBD_STATE="$STATE" \
	ASTERISM_NBD_SYSFS="$SYSFS" \
	ASTERISM_NBD_LOCK="$LOCK" \
	ASTERISM_NBD_CLIENT="$CLIENT" \
	SUDO_UID=1000 SUDO_GID=1000 "$@"
}

for point in mkdir owner helper-pid publish; do
	if run_helper env ASTERISM_NBD_FAIL_POINT="$point" "$HELPER" \
		-unix /tmp/fixture.sock /dev/nbd0 -N fixture; then
		echo "nbd-claim-test: fail point ${point} unexpectedly succeeded" >&2
		exit 1
	fi
	[ ! -e "$STATE/nbd0" ] || {
		echo "nbd-claim-test: fail point ${point} left a final claim" >&2
		exit 1
	}
	[ -z "$(find "$STATE" -mindepth 1 -maxdepth 1 -print -quit)" ] || {
		echo "nbd-claim-test: fail point ${point} left a staging claim" >&2
		exit 1
	}
done

# A signal between private publication and the final directory rename leaves
# only a staging directory. A later owner retires that private state before it
# attempts a new claim.
mkdir "$STATE/nbd0.new.999999"
run_helper "$HELPER" -unix /tmp/fixture.sock /dev/nbd0 -N fixture >/dev/null 2>&1 || true
[ -z "$(find "$STATE" -mindepth 1 -maxdepth 1 -print -quit)" ] || {
	echo "nbd-claim-test: stale staging claim was not reclaimed" >&2
	exit 1
}

# An interrupted legacy mkdir-to-owner publication is recoverable when no
# attachment exists; it must not block a later owner forever.
mkdir "$STATE/nbd0"
run_helper "$HELPER" -unix /tmp/fixture.sock /dev/nbd0 -N fixture >/dev/null 2>&1 || true
[ ! -e "$STATE/nbd0" ] || {
	echo "nbd-claim-test: ownerless detached claim was not reclaimed" >&2
	exit 1
}

# If that interrupted publication did reach the kernel, recovery detaches it
# before removing the ownerless claim. This is the attach/detach recovery path.
mkdir "$STATE/nbd0"
printf '4242\n' >"$SYSFS/nbd0/pid"
run_helper "$HELPER" -d /dev/nbd0
[ ! -e "$STATE/nbd0" ] || {
	echo "nbd-claim-test: ownerless attached claim was not retired" >&2
	exit 1
}
[ ! -e "$SYSFS/nbd0/pid" ] || {
	echo "nbd-claim-test: ownerless attachment was not detached" >&2
	exit 1
}

# A complete claim remains authoritative even when the device is currently
# detached: a different account may not steal it by observing a quiet kernel.
mkdir "$STATE/nbd0"
printf '2000:2000\n' >"$STATE/nbd0/owner"
printf '999999\n' >"$STATE/nbd0/helper-pid"
if run_helper "$HELPER" -unix /tmp/fixture.sock /dev/nbd0 -N fixture; then
	echo "nbd-claim-test: a foreign complete claim was stolen" >&2
	exit 1
fi
[ -e "$STATE/nbd0/owner" ] || {
	echo "nbd-claim-test: foreign claim was erased" >&2
	exit 1
}

echo "nbd-claim-test: atomic publication and all recovery fixtures passed"
