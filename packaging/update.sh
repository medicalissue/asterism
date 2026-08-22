#!/bin/sh
# Signed, transactional Asterism updater.
#
# This program is shipped with the CLI release and is invoked by `ast update`.
# It deliberately has no private network or UI policy: the CLI and desktop app
# both call this one implementation, so they cannot disagree about a channel,
# a build, or whether a release is safe to activate.
set -eu

say() { printf 'asterism update: %s\n' "$*"; }
err() { printf 'asterism update: %s\n' "$*" >&2; }
die() { err "$*"; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

command_name="${1:-status}"
[ $# -eq 0 ] || shift

AST="${ASTERISM_UPDATE_AST_PATH:-}"
if [ -z "$AST" ]; then
	self_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
	case "$self_dir" in
	*/libexec/asterism) AST="${self_dir%/libexec/asterism}/bin/ast" ;;
	*) AST="${ASTERISM_UPDATE_PREFIX:-${HOME}/.local}/bin/ast" ;;
	esac
fi
[ -x "$AST" ] || die "cannot find ast at ${AST}; set ASTERISM_UPDATE_AST_PATH to the installed binary"

if [ -n "${ASTERISM_UPDATE_PREFIX:-}" ]; then
	PREFIX="$ASTERISM_UPDATE_PREFIX"
else
	PREFIX=$(CDPATH='' cd -- "$(dirname -- "$AST")/.." && pwd)
fi
BIN="$PREFIX/bin"
LIBEXEC="$PREFIX/libexec/asterism"
STATE_DIR="${ASTERISM_HOME:-${HOME}/.asterism}"
CHANNEL_FILE="$STATE_DIR/update-channel"
LAST_FILE="$STATE_DIR/update-state.env"

channel="${ASTERISM_UPDATE_CHANNEL:-}"
if [ -z "$channel" ] && [ -f "$CHANNEL_FILE" ]; then
	channel=$(sed -n '1p' "$CHANNEL_FILE")
fi
channel="${channel:-stable}"
case "$channel" in
stable | beta | nightly) ;;
*) die "unknown channel ${channel}; choose stable, beta, or nightly" ;;
esac

tmp=""
app_staged=""
cleanup() {
	[ -z "$tmp" ] || rm -rf "$tmp"
	# A failed copy or activation may leave verified staging bytes beside an
	# install destination. They are never active, but do not accumulate them.
	for name in ast astd astd-vz; do rm -f "$BIN/.${name}.update.$$"; done
	rm -f "$LIBEXEC/.asterism-update.update.$$"
	[ -z "$app_staged" ] || rm -rf "$app_staged"
}
trap cleanup EXIT
trap 'exit 130' INT HUP TERM

fetch() {
	if have curl; then
		curl -fsSL "$1" -o "$2"
	elif have wget; then
		wget -qO "$2" "$1"
	else
		die "curl or wget is required to check for updates"
	fi
}

sha256_of() {
	if have shasum; then
		shasum -a 256 "$1" | awk '{print $1}'
	elif have sha256sum; then
		sha256sum "$1" | awk '{print $1}'
	else
		die "no sha256 tool is installed; refusing to verify an update"
	fi
}

# RELEASE.json is intentionally flat. Keeping its security-critical reader
# this small avoids making an updater depend on jq or Python being installed.
field() {
	value=$(sed -n "s/.*\"$1\"[[:space:]]*:[[:space:]]*\"\([^\"]*\)\".*/\1/p" "$2" | head -n 1)
	[ -n "$value" ] || die "signed manifest has no $1"
	printf '%s' "$value"
}

verify_manifest() {
	manifest="$1" signature="$2"
	pubkey="${ASTERISM_UPDATE_PUBKEY:-}"
	[ -n "$pubkey" ] || die "no update public key is configured; refusing an unauthenticated channel"
	[ -s "$signature" ] || die "the release manifest has no detached signature"
	if [ -n "${ASTERISM_UPDATE_VERIFIER:-}" ]; then
		"$ASTERISM_UPDATE_VERIFIER" "$manifest" "$signature" "$pubkey" ||
			die "the signature on the release manifest does not verify"
	elif have minisign; then
		minisign -Vm "$manifest" -x "$signature" -P "$pubkey" >/dev/null ||
			die "the signature on the release manifest does not verify"
	elif have signify; then
		printf '%s\n' "$pubkey" >"${tmp}/update.pub"
		signify -V -p "${tmp}/update.pub" -x "$signature" -m "$manifest" >/dev/null ||
			die "the signature on the release manifest does not verify"
	else
		die "minisign or signify is required to authenticate the update channel"
	fi
}

current_version() { "$AST" version | sed -n 's/^version[[:space:]]*//p' | head -n 1; }
current_build() { "$AST" version | sed -n 's/^build[[:space:]]*//p' | head -n 1; }

# Compare the numeric release triplet. Pre-release selection is a channel
# concern; it never turns a numerically older release into an upgrade.
version_cmp() {
	awk -v a="${1#v}" -v b="${2#v}" 'BEGIN {
		split(a, av, /[^0-9]+/); split(b, bv, /[^0-9]+/);
		for (i=1; i<=3; i++) {
			an=av[i]+0; bn=bv[i]+0;
			if (an<bn) { print -1; exit }
			if (an>bn) { print 1; exit }
		}
		print 0
	}'
}

managed_by_brew() {
	case "$AST" in
	*/Cellar/asterism/*) return 0 ;;
	esac
	return 1
}

resolve_manifest_url() {
	if [ -n "${ASTERISM_UPDATE_MANIFEST_URL:-}" ]; then
		printf '%s' "$ASTERISM_UPDATE_MANIFEST_URL"
		return
	fi
	case "$channel" in
	stable) printf '%s' 'https://github.com/medicalissue/asterism/releases/latest/download/RELEASE.json' ;;
	*) printf 'https://github.com/medicalissue/asterism/releases/download/channel-%s/RELEASE.json' "$channel" ;;
	esac
}

load_manifest() {
	tmp=$(mktemp -d "${TMPDIR:-/tmp}/asterism-update.XXXXXX")
	manifest_url=$(resolve_manifest_url)
	signature_url="${ASTERISM_UPDATE_SIGNATURE_URL:-${manifest_url}.sig}"
	say "checking ${channel} channel"
	fetch "$manifest_url" "$tmp/RELEASE.json" || die "could not download ${manifest_url}"
	fetch "$signature_url" "$tmp/RELEASE.json.sig" || die "could not download ${signature_url}"
	verify_manifest "$tmp/RELEASE.json" "$tmp/RELEASE.json.sig"

	schema=$(field schema "$tmp/RELEASE.json")
	[ "$schema" = "1" ] || die "signed manifest schema ${schema} is not supported"
	manifest_channel=$(field channel "$tmp/RELEASE.json")
	[ "$manifest_channel" = "$channel" ] ||
		die "signed manifest is for ${manifest_channel}, not requested channel ${channel}"
	version=$(field version "$tmp/RELEASE.json")
	build=$(field build_id "$tmp/RELEASE.json")
	target=$(field target "$tmp/RELEASE.json")
	archive_url=$(field archive_url "$tmp/RELEASE.json")
	archive_sha=$(field archive_sha256 "$tmp/RELEASE.json")
	minimum=$(field minimum_updater_version "$tmp/RELEASE.json")
	app_url=$(sed -n 's/.*"app_url"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$tmp/RELEASE.json" | head -n 1)
	app_sha=$(sed -n 's/.*"app_sha256"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$tmp/RELEASE.json" | head -n 1)
	case "$archive_sha" in *[!0-9a-f]* | '') die "signed manifest has an invalid archive digest" ;; esac
	[ ${#archive_sha} -eq 64 ] || die "signed manifest archive digest is not sha256"
	if [ -n "$app_url" ]; then
		case "$app_sha" in *[!0-9a-f]* | '') die "signed manifest has an invalid app digest" ;; esac
		[ ${#app_sha} -eq 64 ] || die "signed manifest app digest is not sha256"
	fi

	ours=$(current_version)
	ours_build=$(current_build)
	[ -n "$ours" ] && [ -n "$ours_build" ] || die "the installed ast cannot report its exact identity"
	if [ -n "${ASTERISM_UPDATE_TARGET:-}" ]; then
		host_target="$ASTERISM_UPDATE_TARGET"
	else
		case "$(uname -s)-$(uname -m)" in
		Darwin-arm64 | Darwin-aarch64) host_target=darwin-arm64 ;;
		*) host_target=unsupported ;;
		esac
	fi
	[ "$target" = "$host_target" ] || die "signed release target ${target} cannot run on ${host_target}"
	[ "$(version_cmp "$ours" "$minimum")" -ge 0 ] ||
		die "${version} needs updater ${minimum} or newer; install an intermediate release first"
}

print_status() {
	ours=$(current_version)
	ours_build=$(current_build)
	printf 'channel   %s\n' "$channel"
	printf 'version   %s\n' "$ours"
	printf 'build     %s\n' "$ours_build"
	if managed_by_brew; then
		printf 'manager   homebrew\n'
	else
		printf 'manager   asterism\n'
	fi
	if [ -f "$LAST_FILE" ]; then
		sed -n 's/^last_result=/last      /p; s/^last_build=/last build /p' "$LAST_FILE"
	fi
}

check_update() {
	load_manifest
	cmp=$(version_cmp "$ours" "$version")
	if [ "$cmp" -gt 0 ]; then
		printf 'current   %s  %s\n' "$ours" "$ours_build"
		printf 'channel   %s  %s\n' "$version" "$build"
		die "the channel points backwards; downgrade refused before download or mutation"
	fi
	printf 'current   %s  %s\n' "$ours" "$ours_build"
	printf 'channel   %s  %s\n' "$version" "$build"
	if [ "$ours_build" = "$build" ]; then
		say "already current"
		return 0
	fi
	if managed_by_brew; then
		say "update available; this installation belongs to Homebrew — run: brew upgrade asterism"
	else
		say "update available"
	fi
}

binary_build() {
	case "$1" in
	ast) "$2" version ;;
	asterism-gui) "$2" --version ;;
	*) "$2" --version ;;
	esac | sed -n 's/^build[[:space:]]*//p' | head -n 1
}

verify_binary() {
	name="$1" path="$2"
	[ -x "$path" ] || die "the update archive has no executable ${name}"
	got=$(binary_build "$name" "$path")
	[ "$got" = "$build" ] || die "${name} is build ${got:-unknown}, manifest names ${build}"
}

place_one() {
	name="$1" src="$2" dst="$3"
	backup="${dst}.previous.$$"
	if [ -e "$dst" ]; then mv "$dst" "$backup"; else : >"${backup}.absent"; fi
	mv "$src" "$dst"
	activated="$activated $name"
	[ "${ASTERISM_UPDATE_FAIL_AFTER:-}" != "$name" ] || return 97
}

rollback() {
	err "activation failed; rolling every component back"
	for name in $activated; do
		case "$name" in
		ast | astd | astd-vz) dst="$BIN/$name" ;;
		asterism-update) dst="$LIBEXEC/asterism-update" ;;
		Asterism.app) dst="$app_path" ;;
		esac
		backup="${dst}.previous.$$"
		rm -rf "$dst"
		if [ ! -e "${backup}.absent" ]; then mv "$backup" "$dst"; fi
		rm -f "${backup}.absent"
	done
	# Best effort: after a failed new daemon activation, put the old daemon
	# back in front of the still-running guests. A rollback remains a failure
	# even if this succeeds, so diagnostics above are not hidden.
	"$AST" __activate-update --build "$ours_build" >/dev/null 2>&1 || true
}

discard_backups() {
	for name in $activated; do
		case "$name" in
		ast | astd | astd-vz) dst="$BIN/$name" ;;
		asterism-update) dst="$LIBEXEC/asterism-update" ;;
		Asterism.app) dst="$app_path" ;;
		esac
		rm -rf "${dst}.previous.$$" "${dst}.previous.$$.absent"
	done
}

apply_update() {
	managed_by_brew && die "this installation belongs to Homebrew; run: brew upgrade asterism"
	load_manifest
	cmp=$(version_cmp "$ours" "$version")
	[ "$cmp" -le 0 ] || die "downgrade ${ours} -> ${version} refused before download or mutation"
	if [ "$ours_build" = "$build" ]; then
		say "already current: ${version} ${build}"
		return 0
	fi

	say "downloading ${version} (${build})"
	fetch "$archive_url" "$tmp/release.tar.gz" || die "could not download ${archive_url}"
	got=$(sha256_of "$tmp/release.tar.gz")
	[ "$got" = "$archive_sha" ] || die "archive digest mismatch: expected ${archive_sha}, got ${got}"
	mkdir -p "$tmp/stage"
	tar -xzf "$tmp/release.tar.gz" -C "$tmp/stage" || die "could not unpack the verified update"
	for name in ast astd astd-vz; do verify_binary "$name" "$tmp/stage/$name"; done
	[ -x "$tmp/stage/asterism-update" ] || die "the update archive has no executable asterism-update"

	app_path="${ASTERISM_APP_PATH:-}"
	if [ -z "$app_path" ]; then
		for candidate in /Applications/Asterism.app "${HOME}/Applications/Asterism.app"; do
			[ -d "$candidate" ] && { app_path="$candidate"; break; }
		done
	fi
	if [ -n "$app_path" ]; then
		[ -n "$app_url" ] && [ -n "$app_sha" ] ||
			die "a desktop app is installed, but this signed release does not carry its matching app"
		fetch "$app_url" "$tmp/app.tar.gz" || die "could not download ${app_url}"
		got=$(sha256_of "$tmp/app.tar.gz")
		[ "$got" = "$app_sha" ] || die "app digest mismatch: expected ${app_sha}, got ${got}"
		mkdir -p "$tmp/app-stage"
		tar -xzf "$tmp/app.tar.gz" -C "$tmp/app-stage" || die "could not unpack the verified app"
		verify_binary asterism-gui "$tmp/app-stage/Asterism.app/Contents/MacOS/asterism-gui"
	fi

	mkdir -p "$BIN" "$LIBEXEC"
	# Copy bytes beside their destinations before the transaction begins. The
	# following moves are consequently same-filesystem renames; a slow copy or
	# a full disk cannot expose a half-written program as the active one.
	for name in ast astd astd-vz; do
		cp "$tmp/stage/$name" "$BIN/.${name}.update.$$"
		chmod 755 "$BIN/.${name}.update.$$"
	done
	cp "$tmp/stage/asterism-update" "$LIBEXEC/.asterism-update.update.$$"
	chmod 755 "$LIBEXEC/.asterism-update.update.$$"
	if [ -n "$app_path" ]; then
		app_parent=$(dirname "$app_path")
		app_staged="${app_parent}/.Asterism.app.update.$$"
		rm -rf "$app_staged"
		cp -R "$tmp/app-stage/Asterism.app" "$app_staged"
	fi
	activated=""
	if ! {
		place_one astd-vz "$BIN/.astd-vz.update.$$" "$BIN/astd-vz" &&
		place_one astd "$BIN/.astd.update.$$" "$BIN/astd" &&
		place_one asterism-update "$LIBEXEC/.asterism-update.update.$$" "$LIBEXEC/asterism-update" &&
		place_one ast "$BIN/.ast.update.$$" "$BIN/ast" &&
		if [ -n "$app_path" ]; then
			place_one Asterism.app "$app_staged" "$app_path"
		fi &&
		"$BIN/ast" __activate-update --build "$build"
	}; then
		rollback
		die "the new build did not activate; the previous compatible unit was restored"
	fi
	discard_backups

	mkdir -p "$STATE_DIR"
	{
		printf 'last_result=updated %s -> %s\n' "$ours_build" "$build"
		printf 'last_build=%s\n' "$build"
	} >"$LAST_FILE"
	say "updated ${ours} ${ours_build} -> ${version} ${build}"
	say "the daemon restarted; its guest processes were left running and re-adopted"
}

case "$command_name" in
status) [ $# -eq 0 ] || die "status takes no arguments"; print_status ;;
check) [ $# -eq 0 ] || die "check takes no arguments"; check_update ;;
apply)
	[ "${1:-}" = "--yes" ] || die "activation replaces the installed compatible unit; re-run: ast update apply --yes"
	shift
	[ $# -eq 0 ] || die "unknown apply argument: $1"
	apply_update
	;;
channel)
	if [ $# -eq 0 ]; then printf '%s\n' "$channel"; exit 0; fi
	[ $# -eq 1 ] || die "channel takes one of: stable, beta, nightly"
	case "$1" in stable | beta | nightly) ;; *) die "unknown channel $1" ;; esac
	mkdir -p "$STATE_DIR"
	printf '%s\n' "$1" >"$CHANNEL_FILE"
	say "channel is now $1"
	;;
*) die "usage: ast update status|check|apply --yes|channel [stable|beta|nightly]" ;;
esac
