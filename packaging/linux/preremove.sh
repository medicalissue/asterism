#!/bin/sh
# Refuse to remove the package out from under a live NBD attachment.
#
# `packaging/install.sh --uninstall` makes exactly this refusal, for exactly
# this reason: the root-owned wrapper and the sudoers rule authorising it are
# the only way an attached device can be detached again. Deleting them while
# a claim is live would leave a kernel NBD device connected with nothing left
# on the host permitted to disconnect it.
#
# dpkg calls this as `prerm remove|upgrade|deconfigure|failed-upgrade`; rpm
# calls it as `%preun` with 1 on upgrade and 0 on the last removal. An
# upgrade keeps the wrapper, so it is never blocked.
set -eu

STATE=/run/asterism-nbd

case "${1:-}" in
upgrade | deconfigure | failed-upgrade | 1)
	exit 0
	;;
esac

live=""
if [ -d "$STATE" ]; then
	for claim in "$STATE"/nbd*; do
		[ -e "$claim" ] || continue
		name="$(basename "$claim")"
		case "$name" in
		nbd[0-9] | nbd[0-9][0-9]) ;;
		*) continue ;;
		esac
		if [ -s "/sys/block/${name}/pid" ]; then
			live="${live} ${name}"
		fi
	done
fi

if [ -n "$live" ]; then
	cat >&2 <<EOF
asterism: refusing to remove the package while NBD devices are attached:${live}

Those devices can only be detached through the root-owned wrapper this
package installs, and through the sudoers rule that authorises it. Stop the
instances that own them first:

    ast ls
    ast down <instance>

then remove the package again.
EOF
	exit 1
fi

exit 0
