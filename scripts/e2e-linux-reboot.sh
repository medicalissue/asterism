#!/usr/bin/env bash
# Prove that a packaged Asterism comes back by itself after the host reboots.
#
#   scripts/e2e-linux-reboot.sh prepare /path/to/asterism_<version>_<arch>.deb
#   <reboot the machine>
#   scripts/e2e-linux-reboot.sh verify
#
# scripts/e2e-linux-package.sh answers "does one file install into a working
# device manager, and does removing it put the host back". It cannot answer
# this one: it runs in a container with no init, so `ast service install`
# writes the unit and reports that systemctl is absent, and nothing about
# lingering, boot ordering or resurrection is exercised. That is why the AST-41
# evidence lists reboot recovery under "does not prove".
#
# This gate is the other half, and it needs a machine that can actually boot:
# a systemd host, a VM, or a container running systemd as PID 1 that the
# harness restarts between the two phases. It refuses to run anywhere else,
# because a green run on a host with no init would be a lie about the one
# thing it exists to check.
#
# What the two phases assert:
#
#   prepare  the package installs, `loginctl enable-linger` plus
#            `ast service install` produce an enabled user unit, and an
#            instance created with `--restart always` and a published port
#            is running, reachable over SSH, and reachable through the
#            published port.
#   verify   after the reboot, with nobody logged in and no command typed:
#            astd is up under the user manager, the instance is running
#            again, `ast status` says `restart=always resurrection`, and the
#            published port answers on the same host port as before.
#
# Environment:
#   ASTERISM_PKG_USER   account that owns the daemon (default: asterism)
#   E2E_IMAGE           image to boot (default: debian:13)
#   E2E_PUBLISH_HOST    host port for the published endpoint (default: 18022)
#   E2E_PUBLISH_GUEST   guest port to publish (default: 22)
#   E2E_REBOOT_STUB     1 to skip the guest entirely and assert only the
#                       daemon half (a host with no usable /dev/kvm)
set -euo pipefail

STATE=/var/lib/asterism-reboot-e2e.env
INST="${E2E_REBOOT_INSTANCE:-reboot-e2e}"
IMAGE="${E2E_IMAGE:-debian:13}"
PUBLISH_HOST="${E2E_PUBLISH_HOST:-18022}"
PUBLISH_GUEST="${E2E_PUBLISH_GUEST:-22}"
USER_NAME="${ASTERISM_PKG_USER:-asterism}"
STUB="${E2E_REBOOT_STUB:-0}"

fail() {
	echo "LINUX-REBOOT FAIL: $*" >&2
	exit 1
}
ok() { echo "ok: $*"; }

[ "$(id -u)" = 0 ] || fail "run this as root; it installs a package and drives systemd"

# ---- the environment has to be able to boot --------------------------------

require_systemd() {
	[ -d /run/systemd/system ] ||
		fail "this host has no running systemd; there is nothing here that can reboot"
	command -v systemctl >/dev/null 2>&1 || fail "systemctl is not on PATH"
	command -v loginctl >/dev/null 2>&1 || fail "loginctl is not on PATH"
	# `degraded` is fine: a container's systemd fails units that want
	# hardware it does not have, and none of them are Asterism's.
	state="$(systemctl is-system-running 2>/dev/null || true)"
	case "$state" in
	running | degraded | starting) ok "systemd is PID 1 and $state" ;;
	*) fail "systemd reports '$state'; this gate needs a booted system" ;;
	esac
}

user_env() {
	# Everything a command needs to talk to *that account's* systemd, without
	# opening a login session for it: the whole point of lingering is that
	# the user manager is already there.
	runuser -u "$USER_NAME" -- env \
		XDG_RUNTIME_DIR="/run/user/$(id -u "$USER_NAME")" \
		DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$(id -u "$USER_NAME")/bus" \
		"$@"
}

as_user() { user_env "$@"; }

# A TCP connection that reads whatever the far side says first. Used on the
# published port, where the guest's SSH server announces itself: a listener
# that accepts and then hangs would pass a `ss` check and fail a user.
port_banner() {
	local port="$1" out
	out="$(timeout 10 bash -c "
		exec 3<>/dev/tcp/127.0.0.1/${port} || exit 1
		head -c 32 <&3
	" 2>/dev/null || true)"
	printf '%s' "$out"
}

wait_for() {
	local what="$1" seconds="$2"
	shift 2
	local waited=0
	while [ "$waited" -lt "$seconds" ]; do
		if "$@" >/dev/null 2>&1; then
			return 0
		fi
		sleep 2
		waited=$((waited + 2))
	done
	fail "$what did not happen within ${seconds}s"
}

instance_running() {
	as_user ast status "$INST" 2>/dev/null | grep -qE '^status: +running'
}

published_answers() {
	[ -n "$(port_banner "$PUBLISH_HOST")" ]
}

# ---- prepare ---------------------------------------------------------------

prepare() {
	local package="${1:?usage: e2e-linux-reboot.sh prepare PACKAGE.deb}"
	require_systemd

	export DEBIAN_FRONTEND=noninteractive
	apt-get update -qq
	apt-get install -y -qq "$package" >/dev/null || fail "installing $package failed"
	[ -x /usr/bin/ast ] || fail "the package did not install /usr/bin/ast"
	[ -f /usr/lib/systemd/user/astd.service ] ||
		fail "the package did not ship the user unit"
	ok "installed $(basename "$package")"

	if ! id -u "$USER_NAME" >/dev/null 2>&1; then
		useradd -m -s /bin/bash "$USER_NAME"
	fi
	local uid
	uid="$(id -u "$USER_NAME")"
	if [ -e /dev/kvm ]; then
		local kvm_gid kvm_group
		kvm_gid="$(stat -c '%g' /dev/kvm)"
		kvm_group="$(getent group "$kvm_gid" | cut -d: -f1 || true)"
		if [ -z "$kvm_group" ]; then
			groupadd -g "$kvm_gid" kvm-host
			kvm_group=kvm-host
		fi
		usermod -aG "$kvm_group" "$USER_NAME"
	fi

	# The same one-time administrator grant e2e-linux-package.sh uses: it is
	# the authority `ast service install` spends once to write a rule far
	# narrower than itself.
	printf '%s ALL=(ALL) NOPASSWD: ALL\n' "$USER_NAME" >/etc/sudoers.d/zz-e2e-admin
	chmod 0440 /etc/sudoers.d/zz-e2e-admin

	# Lingering first, and by hand. `ast service install` enables it too, but
	# `systemctl --user` needs a user manager to talk to, and on a machine
	# where this account has never logged in there is none until lingering
	# starts one. This is the command `ast doctor` names on its `linger` row.
	loginctl enable-linger "$USER_NAME" || fail "loginctl enable-linger failed"
	wait_for "the user manager for $USER_NAME" 60 test -S "/run/user/${uid}/bus"
	ok "loginctl enable-linger started a user manager with no login"

	as_user ast service install || fail "ast service install failed"
	as_user systemctl --user is-enabled astd.service |
		grep -qx enabled || fail "astd.service is not enabled for $USER_NAME"
	as_user systemctl --user is-active astd.service |
		grep -qx active || fail "astd.service is not active"
	ok "ast service install enabled and started the user unit"

	local doctor
	doctor="$(as_user ast doctor 2>&1 || true)"
	printf '%s\n' "$doctor"
	printf '%s\n' "$doctor" | grep -Eq '^ok +receipt +installed by package' ||
		fail "doctor did not recognise the package as this tree's owner"
	printf '%s\n' "$doctor" | grep -Eq '^ok +linger' ||
		fail "doctor did not report lingering as on"
	ok "doctor reports the package receipt and lingering"

	# `ast update apply` must refuse: these files belong to dpkg.
	local refusal=0 update_out
	update_out="$(as_user ast update apply --yes 2>&1)" || refusal=1
	printf '%s\n' "$update_out"
	[ "$refusal" = 1 ] || fail "ast update apply did not refuse a package-managed install"
	printf '%s\n' "$update_out" | grep -q 'belongs to dpkg' ||
		fail "the refusal does not name dpkg"
	printf '%s\n' "$update_out" | grep -q 'fix: sudo apt-get install --only-upgrade' ||
		fail "the refusal does not name the distribution upgrade command as a fix"
	ok "ast update apply refused and named the apt-get command"

	rm -f /etc/sudoers.d/zz-e2e-admin
	ok "withdrew the broad sudo grant"

	if [ "$STUB" = 1 ]; then
		ok "E2E_REBOOT_STUB=1: no guest is created; only the daemon half is under test"
		printf 'USER_NAME=%s\nINST=\nPUBLISH_HOST=\nSTUB=1\n' "$USER_NAME" >"$STATE"
		echo "LINUX REBOOT PREPARED (daemon only)"
		return 0
	fi

	as_user ast pull "${E2E_KERNEL_IMAGE:-busybox:musl}" >/dev/null ||
		fail "could not pull the pinned CHV guest kernel payload"
	as_user ast pull "$IMAGE" >/dev/null || fail "pull $IMAGE failed"
	as_user ast create "$INST" --backend chv --image "$IMAGE" \
		--mem 2G --disk 10G -p "${PUBLISH_HOST}:${PUBLISH_GUEST}" |
		grep -qF "$INST  defined" || fail "create did not define $INST"
	as_user ast up "$INST" --restart always | grep -qF "$INST  running" ||
		fail "up did not report running"
	as_user ast status "$INST" | grep -q '^restart: always' ||
		fail "the instance did not record restart=always"
	ok "created $INST with --restart always and -p ${PUBLISH_HOST}:${PUBLISH_GUEST}"

	local guest
	guest="$(as_user ast ssh "$INST" -- "uname -s; uname -m" 2>&1)" ||
		fail "ssh into the guest failed:"$'\n'"$guest"
	printf '%s\n' "$guest" | grep -qFx Linux || fail "the guest is not Linux"
	ok "ssh reached the guest ($(printf '%s' "$guest" | tr '\n' ' '))"

	wait_for "the published port to answer" 120 published_answers
	ok "published 127.0.0.1:${PUBLISH_HOST} answers: $(port_banner "$PUBLISH_HOST" | tr -d '\r\n')"

	printf 'USER_NAME=%s\nINST=%s\nPUBLISH_HOST=%s\nSTUB=0\n' \
		"$USER_NAME" "$INST" "$PUBLISH_HOST" >"$STATE"
	echo "LINUX REBOOT PREPARED ($INST on ${IMAGE}, published ${PUBLISH_HOST})"
}

# ---- verify ----------------------------------------------------------------

verify() {
	# Read before anything else runs: what this phase is allowed to observe
	# is what the machine did on its own, not what this script provoked.
	local astd_pid_at_entry
	astd_pid_at_entry="$(pgrep -u "$USER_NAME" -x astd | head -n1 || true)"

	[ -f "$STATE" ] || fail "$STATE is missing; run the prepare phase first"
	# shellcheck disable=SC1090
	. "$STATE"
	require_systemd

	[ -n "$astd_pid_at_entry" ] ||
		fail "astd was not already running when this phase started; nothing resurrected it"
	ok "astd was already running at pid ${astd_pid_at_entry} before this phase typed anything"

	# It is the *user manager's* astd, not a stray process: a daemon started
	# by an interactive command would not be in the unit's cgroup.
	local cgroup
	cgroup="$(cat "/proc/${astd_pid_at_entry}/cgroup" 2>/dev/null || true)"
	printf '%s' "$cgroup" | grep -q 'astd.service' ||
		fail "pid ${astd_pid_at_entry} is not in astd.service's cgroup: ${cgroup}"
	ok "astd is running inside astd.service's cgroup, started by systemd at boot"

	as_user systemctl --user is-active astd.service | grep -qx active ||
		fail "systemd does not consider astd.service active"
	local since
	since="$(as_user systemctl --user show astd.service -p ActiveEnterTimestamp \
		--value 2>/dev/null || true)"
	ok "astd.service is active (since ${since:-unknown}) with nobody logged in"

	local linger
	linger="$(loginctl show-user "$USER_NAME" -p Linger --value 2>/dev/null || true)"
	[ "$linger" = yes ] || fail "lingering is not on after the reboot (Linger=${linger:-unset})"
	ok "lingering survived the reboot"

	if [ "${STUB:-0}" = 1 ]; then
		echo "LINUX REBOOT GREEN (daemon only; no guest was under test)"
		return 0
	fi

	wait_for "$INST to come back" 300 instance_running
	ok "$INST is running again without anybody typing ast up"

	local status
	status="$(as_user ast status "$INST" 2>&1)"
	printf '%s\n' "$status"
	printf '%s\n' "$status" | grep -q 'restart=always resurrection' ||
		fail "ast status does not attribute the boot to restart=always resurrection"
	ok "ast status names the reason: restart=always resurrection"

	local guest
	guest="$(as_user ast ssh "$INST" -- "uname -s" 2>&1)" ||
		fail "ssh into the resurrected guest failed:"$'\n'"$guest"
	printf '%s\n' "$guest" | grep -qFx Linux || fail "the resurrected guest is not Linux"
	ok "ssh reached the resurrected guest"

	wait_for "the published port to come back" 180 published_answers
	ok "published 127.0.0.1:${PUBLISH_HOST} answers again: $(port_banner "$PUBLISH_HOST" | tr -d '\r\n')"

	echo "LINUX REBOOT GREEN ($INST resurrected, ${PUBLISH_HOST} re-established)"
}

case "${1:-}" in
prepare)
	shift
	prepare "$@"
	;;
verify)
	verify
	;;
*)
	echo "usage: e2e-linux-reboot.sh prepare PACKAGE.deb | verify" >&2
	exit 2
	;;
esac
