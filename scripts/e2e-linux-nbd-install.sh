#!/usr/bin/env bash
# Prove the privileged NBD slice of a binary Linux install on a clean host.
# The release payload is tiny because this test exercises installer-owned host
# integration, not VMM execution; every privileged transition is real.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/asterism-nbd-install.XXXXXX")"
VERSION=v0.0.0-nbd-e2e
PREFIX="${WORK}/prefix"
RELEASES="${WORK}/releases/${VERSION}"
STAGE="${WORK}/stage"
SOCKET="${WORK}/volume.sock"
IMAGE="${WORK}/volume.raw"
MOUNT="${WORK}/mount"
NBD_PID=""
DEVICE=""
POLICY=""

cleanup() {
	set +e
	if mountpoint -q "$MOUNT" 2>/dev/null; then sudo -n umount "$MOUNT"; fi
	if [ -n "$DEVICE" ]; then
		name="${DEVICE#/dev/}"
		if [ -s "/sys/block/${name}/pid" ]; then
			sudo -n /usr/local/libexec/asterism/asterism-nbd -d "$DEVICE"
		fi
	fi
	if [ -n "$NBD_PID" ]; then
		kill "$NBD_PID" 2>/dev/null
		wait "$NBD_PID" 2>/dev/null
	fi
	if [ -n "$POLICY" ] && sudo -n test -e "$POLICY" 2>/dev/null; then
		sudo -n rm -f "$POLICY"
	fi
	rm -rf "$WORK"
}
trap cleanup EXIT INT HUP TERM

for command in qemu-nbd mkfs.ext4 mountpoint sudo tar; do
	command -v "$command" >/dev/null || {
		echo "missing test prerequisite: $command" >&2
		exit 1
	}
done

mkdir -p "$PREFIX/bin" "$RELEASES" "$STAGE/share/asterism/licenses" "$MOUNT"
for binary in ast astd cloud-hypervisor virtiofsd; do
	printf '#!/bin/sh\nprintf "%%s test\\n" "%s"\n' "$binary" >"${STAGE}/${binary}"
	chmod 0755 "${STAGE}/${binary}"
done
cp "$ROOT/packaging/linux-components.env" "$ROOT/packaging/asterism-nbd" \
	"$STAGE/share/asterism/"
for license in cloud-hypervisor-Apache-2.0 cloud-hypervisor-BSD-3-Clause \
		virtiofsd-Apache-2.0 virtiofsd-BSD-3-Clause; do
	printf 'installer lifecycle test fixture\n' >"$STAGE/share/asterism/licenses/${license}.txt"
done
for license in LICENSE-APACHE LICENSE-MIT NOTICE; do
	printf 'installer lifecycle test fixture\n' >"$STAGE/share/asterism/licenses/${license}"
done
artifact="asterism-${VERSION}-linux-$(uname -m)"
case "$artifact" in *-linux-aarch64) artifact="${artifact%-aarch64}-arm64" ;; esac
tar -czf "${RELEASES}/${artifact}.tar.gz" -C "$STAGE" \
	ast astd cloud-hypervisor virtiofsd share
(cd "$RELEASES" && sha256sum "${artifact}.tar.gz" >SHA256SUMS)

# shellcheck disable=SC1091
echo "host: $(. /etc/os-release && printf '%s' "$PRETTY_NAME"); $(uname -r); $(uname -m)"
ASTERISM_VERSION="$VERSION" \
	ASTERISM_PREFIX="$PREFIX" \
	ASTERISM_BASE_URL="file://${WORK}/releases" \
	ASTERISM_YES=1 \
	sh "$ROOT/packaging/install.sh"

helper=/usr/local/libexec/asterism/asterism-nbd
policy="/etc/sudoers.d/asterism-nbd-$(id -u)"
POLICY="$policy"
sudo -n test -x "$helper"
sudo -n test -r "$policy"
sudo -n grep -qF "NOPASSWD: $helper" "$policy"
echo "install: helper=root-owned policy=non-interactive module=$(cat /sys/module/nbd/parameters/nbds_max)"

truncate -s 64M "$IMAGE"
mkfs.ext4 -q -F "$IMAGE"
qemu-nbd --socket="$SOCKET" --format=raw --export-name=asterism-e2e "$IMAGE" &
NBD_PID=$!
for _ in $(seq 1 100); do [ -S "$SOCKET" ] && break; sleep 0.05; done
[ -S "$SOCKET" ] || { echo "qemu-nbd did not create $SOCKET" >&2; exit 1; }

for candidate in /dev/nbd{0..63}; do
	[ -b "$candidate" ] || continue
	name="${candidate#/dev/}"
	if [ ! -s "/sys/block/${name}/pid" ]; then DEVICE="$candidate"; break; fi
done
[ -n "$DEVICE" ] || { echo "no free NBD device" >&2; exit 1; }

sudo -n "$helper" -unix "$SOCKET" "$DEVICE" -N asterism-e2e
name="${DEVICE#/dev/}"
[ -s "/sys/block/${name}/pid" ]
echo "attach: $DEVICE kernel_pid=$(cat "/sys/block/${name}/pid")"

sudo -n mount "$DEVICE" "$MOUNT"
printf 'installed-product-nbd\n' | sudo -n tee "$MOUNT/proof" >/dev/null
sudo -n sync
sudo -n umount "$MOUNT"
echo "write: guest-side block write synced"

sudo -n "$helper" -d "$DEVICE"
for _ in $(seq 1 100); do [ ! -s "/sys/block/${name}/pid" ] && break; sleep 0.05; done
[ ! -s "/sys/block/${name}/pid" ]
echo "down: $DEVICE detached"
DEVICE=""
kill "$NBD_PID" 2>/dev/null || true
wait "$NBD_PID" 2>/dev/null || true
NBD_PID=""

sudo -n mount -o loop,ro "$IMAGE" "$MOUNT"
proof="$(cat "$MOUNT/proof")"
sudo -n umount "$MOUNT"
[ "$proof" = installed-product-nbd ]
echo "verify: provider image contains $proof"

ASTERISM_PREFIX="$PREFIX" ASTERISM_YES=1 sh "$ROOT/packaging/install.sh" --uninstall
sudo -n test ! -e "$policy"
POLICY=""
echo "uninstall: account policy removed"
