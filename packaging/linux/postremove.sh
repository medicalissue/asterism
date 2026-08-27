#!/bin/sh
# Put the host back the way the package found it.
#
# The files the package owns are already gone by the time this runs; what is
# left is the state the package *caused* — the per-account sudoers rules the
# policy helper wrote, and the root-owned NBD lock and claim directory on
# tmpfs. Both go here.
#
# What is deliberately left alone:
#
#   ~/.asterism            instances, images, and keys. Removing the manager
#                          is not removing the machines.
#   the loaded nbd module  other software may be using it now. The shipped
#                          modules-load.d snippet went with the package, so
#                          Asterism stops loading it at the next boot; the
#                          currently loaded module is the kernel's, not ours
#                          to unload.
#   ~/.config/systemd/user/astd.service and lingering
#                          root cannot disable another account's user unit,
#                          and doing so would need to guess which accounts
#                          ran one. `ast service uninstall` is that command,
#                          and it is per account by construction.
#
# dpkg calls this as `postrm remove|purge|upgrade|...`; rpm calls it as
# `%postun` with 1 on upgrade and 0 on the last removal.
set -eu

case "${1:-}" in
remove | purge | 0)
	final=1
	;;
*)
	final=0
	;;
esac

[ "$final" = 1 ] || exit 0

# Every account that ran `ast service install` from this package has one of
# these, named for its uid, and the wrapper it authorised no longer exists.
for policy in /etc/sudoers.d/asterism-nbd-*; do
	[ -e "$policy" ] || continue
	rm -f "$policy"
	printf 'asterism: removed %s\n' "$policy"
done

rm -f /run/lock/asterism-nbd.lock
rmdir /run/asterism-nbd 2>/dev/null || true
rmdir /usr/libexec/asterism /usr/lib/asterism /usr/share/asterism 2>/dev/null || true

cat <<'EOF'
asterism: removed. Instance data under ~/.asterism was left alone.
Each account that ran `ast service install` still has a systemd user unit;
remove it with `ast service uninstall` before the binaries go, or delete
~/.config/systemd/user/astd.service and run `systemctl --user daemon-reload`.
EOF

exit 0
