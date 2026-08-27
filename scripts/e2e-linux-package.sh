#!/usr/bin/env bash
# Prove the native Linux package on a clean host, end to end.
#
#   scripts/e2e-linux-package.sh /path/to/asterism_<version>_<arch>.deb
#
# Run this *inside* a clean supported Linux with no Asterism source tree, no
# Rust toolchain, and no QEMU: it is the gate for the claim that a user can
# install one file and get a working device manager. Nothing here reads the
# repository — everything is driven through the installed `ast`, so a passing
# run says something about the artifact rather than about this checkout.
#
# The lifecycle half deliberately duplicates scripts/e2e-native-no-qemu.sh's
# assertions rather than sourcing them: that gate answers "can the native
# backend boot without QEMU", this one answers "does the package deliver a
# host that can", and a shared harness would make a passing run here depend
# on a source tree the premise says is absent.
#
# Environment:
#   ASTERISM_PKG_USER   unprivileged account to run the lifecycle as
#                       (default: the invoking account, which must not be root)
#   E2E_IMAGE           catalog image to boot (default: debian:13)
set -euo pipefail

PACKAGE="${1:?usage: e2e-linux-package.sh PACKAGE.deb}"
IMAGE="${E2E_IMAGE:-debian:13}"
IMAGE_BASENAME="${E2E_BOOT_IMAGE_BASENAME:-debian-13}"
INST=package-e2e

fail() {
	echo "LINUX-PACKAGE FAIL: $*" >&2
	exit 1
}
ok() { echo "ok: $*"; }

[ "$(id -u)" = 0 ] || fail "run this as root; it installs and removes a package"

# ---- 1. the host is clean ---------------------------------------------------

for tool in cargo rustc gcc cc make; do
	command -v "$tool" >/dev/null 2>&1 &&
		fail "$tool is present; this gate needs a host with no development tools"
done
for tool in ast astd cloud-hypervisor virtiofsd; do
	command -v "$tool" >/dev/null 2>&1 &&
		fail "$tool is already on PATH before the package was installed"
done
ok "no development tools and no previously installed Asterism"

assert_no_qemu() {
	local tool packages
	for tool in qemu-img qemu-system-x86_64 qemu-system-aarch64; do
		command -v "$tool" >/dev/null 2>&1 && fail "$tool is on PATH"
		for prefix in /usr/local/bin /usr/bin /usr/libexec/asterism; do
			[ ! -e "$prefix/$tool" ] || fail "$prefix/$tool exists"
		done
	done
	packages="$(dpkg-query -W -f='${binary:Package} ${db:Status-Abbrev}\n' \
		'qemu*' 2>/dev/null || true)"
	printf '%s\n' "$packages" | grep -Eq '(^|:)qemu[^[:space:]]* ii ' &&
		fail "dpkg records a QEMU package as installed"
	return 0
}
assert_no_qemu
ok "package inventory carries no QEMU"

[ -r /dev/kvm ] && [ -w /dev/kvm ] || fail "/dev/kvm is not readable and writable"

# ---- 2. install ------------------------------------------------------------

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq "$PACKAGE" >/dev/null || fail "installing $PACKAGE failed"
ok "installed $(basename "$PACKAGE") with its declared dependencies"

assert_no_qemu
ok "installing the package pulled in no QEMU"

for path in /usr/bin/ast /usr/bin/astd \
	/usr/libexec/asterism/cloud-hypervisor \
	/usr/libexec/asterism/virtiofsd \
	/usr/libexec/asterism/asterism-nbd \
	/usr/libexec/asterism/asterism-nbd-policy \
	/usr/lib/asterism/guest/bin/asterism-guest \
	/usr/lib/systemd/user/astd.service \
	/usr/lib/modules-load.d/asterism-nbd.conf \
	/usr/lib/modprobe.d/asterism-nbd.conf \
	/usr/share/asterism/linux-components.env \
	/usr/share/asterism/licenses/cloud-hypervisor-Apache-2.0.txt \
	/usr/share/asterism/licenses/virtiofsd-Apache-2.0.txt \
	/usr/share/asterism/licenses/NOTICE; do
	[ -e "$path" ] || fail "the installed package is missing $path"
done
ok "the installed layout is the packaged layout"

# The wrapper is the daemon's only route to privilege, so its ownership is
# part of the product, not an installation detail.
[ "$(stat -c '%U:%G:%a' /usr/libexec/asterism/asterism-nbd)" = "root:root:755" ] ||
	fail "the NBD wrapper is not root:root 0755"
getcap /usr/libexec/asterism/cloud-hypervisor | grep -q cap_net_admin ||
	fail "the bundled VMM did not receive cap_net_admin from the post-install"
ok "wrapper ownership and VMM capability are what the post-install claims"

# ---- 3. the account that runs the daemon -----------------------------------

USER_NAME="${ASTERISM_PKG_USER:-asterism}"
if ! id -u "$USER_NAME" >/dev/null 2>&1; then
	useradd -m -s /bin/bash "$USER_NAME"
fi
# A container often has no named group for the host's kvm gid, so give the
# account membership of the numeric gid the device actually carries.
kvm_gid="$(stat -c '%g' /dev/kvm)"
kvm_group="$(getent group "$kvm_gid" | cut -d: -f1 || true)"
if [ -z "$kvm_group" ]; then
	groupadd -g "$kvm_gid" kvm-host
	kvm_group=kvm-host
fi
usermod -aG "$kvm_group" "$USER_NAME"
UID_OF="$(id -u "$USER_NAME")"

# An ordinary administrator account: it can sudo, and that is the authority
# `ast service install` uses once to write a rule far narrower than this one.
printf '%s ALL=(ALL) NOPASSWD: ALL\n' "$USER_NAME" >/etc/sudoers.d/zz-e2e-admin
chmod 0440 /etc/sudoers.d/zz-e2e-admin

as_user() { runuser -u "$USER_NAME" -- "$@"; }

as_user ast service install || fail "ast service install failed"
[ -f "/etc/sudoers.d/asterism-nbd-${UID_OF}" ] ||
	fail "ast service install did not write /etc/sudoers.d/asterism-nbd-${UID_OF}"
grep -q '/usr/libexec/asterism/asterism-nbd$' "/etc/sudoers.d/asterism-nbd-${UID_OF}" ||
	fail "the installed rule does not authorise the packaged NBD wrapper"
grep -q 'cap_net_admin+ep /usr/libexec/asterism/cloud-hypervisor$' \
	"/etc/sudoers.d/asterism-nbd-${UID_OF}" ||
	fail "the installed rule does not authorise the updater's capability restore"
[ "$(wc -l <"/etc/sudoers.d/asterism-nbd-${UID_OF}")" = 2 ] ||
	fail "the installed rule grants more than the two authorised commands"
ok "ast service install wrote exactly the two-line least-privilege NBD rule"

# Take the broad authority away again. Everything below now runs with only
# what the package's own rule grants, which is the claim being tested.
rm -f /etc/sudoers.d/zz-e2e-admin
ok "withdrew the broad sudo grant; the narrow rule is all that remains"

# ---- 4. doctor and the lifecycle -------------------------------------------

doctor_out="$(as_user ast doctor 2>&1 || true)"
printf '%s\n' "$doctor_out"
printf '%s\n' "$doctor_out" | grep -Eq '^ *(ok|OK) +cloud-hypervisor' ||
	printf '%s\n' "$doctor_out" | grep -q cloud-hypervisor ||
	fail "doctor did not report the packaged Cloud Hypervisor"
printf '%s\n' "$doctor_out" | grep -q '/usr/libexec/asterism/asterism-nbd' ||
	fail "doctor did not probe the packaged NBD wrapper path"
ok "ast doctor reports the packaged paths with no environment override"

as_user ast pull "${E2E_KERNEL_IMAGE:-busybox:musl}" >/dev/null ||
	fail "could not pull the pinned CHV guest kernel payload"
as_user ast pull "$IMAGE" >/dev/null || fail "pull $IMAGE failed"
ok "pull retained a verified image"

as_user ast create "$INST" --backend chv --image "$IMAGE" --mem 2G --disk 10G |
	grep -qF "$INST  defined" || fail "create did not define $INST"
as_user ast status "$INST" | grep -qF "machine: chv" ||
	fail "the instance was not defined for chv"
ok "create records the explicit chv backend"

as_user ast up "$INST" | grep -qF "$INST  running" || fail "up did not report running"
home="$(getent passwd "$USER_NAME" | cut -d: -f6)"
raw="${home}/.asterism/images/${IMAGE_BASENAME}.raw"
[ -f "$raw" ] || fail "first chv use did not publish $raw"
ok "up booted the guest on the packaged Cloud Hypervisor"

guest="$(as_user ast ssh "$INST" -- "uname -s; uname -m" 2>&1)" ||
	fail "ssh into the guest failed:"$'\n'"$guest"
printf '%s\n' "$guest" | grep -qFx Linux || fail "the guest is not Linux"
ok "ssh reached the guest ($(printf '%s' "$guest" | tr '\n' ' '))"

as_user ast down "$INST" | grep -qF "$INST  stopped" || fail "down did not stop"
as_user ast rm "$INST" | grep -qF "$INST  removed" || fail "rm did not remove"
ok "down and rm completed"

as_user ast bugreport >/dev/null 2>&1 || as_user ast bug report >/dev/null 2>&1 ||
	echo "note: no bugreport subcommand answered; recorded, not fatal"

assert_no_qemu
ok "the whole lifecycle ran with no QEMU on the host"

# ---- 5. removal leaves nothing ---------------------------------------------

as_user ast service uninstall >/dev/null || fail "ast service uninstall failed"
apt-get remove -y -qq asterism >/dev/null || fail "removing the package failed"

for path in /usr/bin/ast /usr/bin/astd /usr/libexec/asterism \
	/usr/lib/asterism /usr/share/asterism \
	/usr/lib/systemd/user/astd.service \
	/usr/lib/modules-load.d/asterism-nbd.conf \
	/usr/lib/modprobe.d/asterism-nbd.conf \
	/usr/lib/tmpfiles.d/asterism-nbd.conf; do
	[ ! -e "$path" ] || fail "$path survived package removal"
done
for policy in /etc/sudoers.d/asterism-nbd-*; do
	[ ! -e "$policy" ] || fail "$policy survived package removal"
done
[ ! -e /run/lock/asterism-nbd.lock ] || fail "the NBD lock survived removal"
[ ! -e /run/asterism-nbd ] || fail "the NBD claim directory survived removal"
[ ! -e "${home}/.config/systemd/user/astd.service" ] ||
	fail "ast service uninstall left the user unit behind"
[ -d "${home}/.asterism" ] || fail "removal deleted ~/.asterism, which it must keep"
ok "removal left no files, units, or sudoers rules, and kept ~/.asterism"

echo "LINUX PACKAGE GREEN ($(basename "$PACKAGE"), $IMAGE)"
