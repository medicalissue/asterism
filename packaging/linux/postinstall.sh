#!/bin/sh
# Configure the host integration a package cannot express as a file.
#
# Runs as root, from dpkg's `postinst configure` and rpm's `%post`. Three
# things happen here and nothing else: the bundled VMM gets the one
# capability it needs, the NBD kernel client is loaded with the device count
# Asterism selects from, and the root-owned NBD critical-section paths are
# materialised on tmpfs.
#
# What deliberately does *not* happen here is the sudoers rule. It names one
# account, and at package-install time the only account present is root.
# `ast service install` writes it, through
# /usr/libexec/asterism/asterism-nbd-policy, from the account that will
# actually run the daemon.
#
# Nothing in here is allowed to fail the installation. A container without
# module-loading rights, a host whose kernel has no nbd module, a
# CAP_SETFCAP-less build environment — each of those makes one Asterism
# feature unavailable, and `ast doctor` says which. None of them makes the
# installed package wrong.
set -eu

VMM=/usr/libexec/asterism/cloud-hypervisor

warn() {
	printf 'asterism: %s\n' "$1" >&2
}

# Only CAP_NET_ADMIN, and only on the bundled VMM: it needs it to create the
# per-instance TAP device. Access to KVM itself stays governed by /dev/kvm
# ownership, which this does not touch and cannot bypass.
if command -v setcap >/dev/null 2>&1; then
	if ! setcap cap_net_admin+ep "$VMM" 2>/dev/null; then
		warn "could not set cap_net_admin on ${VMM}; instance networking will not come up."
		warn "re-run: sudo setcap cap_net_admin+ep ${VMM}"
	fi
else
	warn "setcap is missing; install libcap2-bin (Debian) or libcap (Fedora), then:"
	warn "  sudo setcap cap_net_admin+ep ${VMM}"
fi

# The lock inode and the claim directory are the root-owned boundary the NBD
# wrapper serialises on. systemd-tmpfiles recreates them at every boot from
# the shipped snippet; do it now too, so the first attach after installation
# does not have to wait for one.
if command -v systemd-tmpfiles >/dev/null 2>&1 &&
	systemd-tmpfiles --create /usr/lib/tmpfiles.d/asterism-nbd.conf 2>/dev/null; then
	:
else
	install -d -m 0755 /run/lock
	install -d -m 0700 -o root -g root /run/asterism-nbd 2>/dev/null || true
	if [ ! -e /run/lock/asterism-nbd.lock ]; then
		: >/run/lock/asterism-nbd.lock
	fi
	chown root:root /run/lock/asterism-nbd.lock 2>/dev/null || true
	chmod 0600 /run/lock/asterism-nbd.lock 2>/dev/null || true
fi

# 64 devices, now and after every reboot. The reboot half is the shipped
# modules-load.d and modprobe.d pair; this is the now half.
if command -v modprobe >/dev/null 2>&1; then
	if ! modprobe nbd nbds_max=64 2>/dev/null; then
		warn "could not load the nbd module; remote block volumes are unavailable until it loads."
	fi
else
	warn "modprobe is missing; install kmod for remote block volumes."
fi

cat <<'EOF'
Asterism is installed. Two commands finish the setup, run as the account
that will own the instances — not as root:

    ast service install     # systemd --user unit, lingering, NBD sudo policy
    ast doctor              # KVM, pinned helpers, Secret Service, lingering

Instances run on the bundled Cloud Hypervisor over KVM. That account needs
read-write /dev/kvm, which usually means membership of the kvm group.
EOF

exit 0
