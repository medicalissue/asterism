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
TRANSACTION_CLAIM="$STATE_DIR/update-transaction.claim"
TRANSACTION_DIR=""
TRANSACTION_ID=""
activation_failure=""

tmp=""
app_staged=""
recovering=0
owns_transaction=0
ARTIFACT_LOCK=""
ARTIFACT_LOCK_HELD=0
cleanup() {
	if [ "$recovering" = 0 ] && [ "$owns_transaction" = 1 ]; then
		recover_interrupted force
	fi
	release_artifact_lock
	[ -z "$tmp" ] || rm -rf "$tmp"
	# A failed copy or activation may leave verified staging bytes beside an
	# install destination. They are never active, but do not accumulate them.
	for name in ast astd astd-vz cloud-hypervisor virtiofsd; do rm -f "$BIN/.${name}.update.$$"; done
	rm -rf "$BIN/.guest-gpu.update.$$"
	rm -f "$LIBEXEC/.asterism-update.update.$$"
	[ -z "$app_staged" ] || rm -rf "$app_staged"
}
trap cleanup EXIT

artifact_lock_path() {
	printf '%s' "${PREFIX}/share/asterism/artifact.lock"
}

acquire_artifact_lock() {
	ARTIFACT_LOCK="$(artifact_lock_path)"
	mkdir -p "$(dirname "$ARTIFACT_LOCK")"
	tries=0
	while [ "$tries" -lt 50 ]; do
		if mkdir "$ARTIFACT_LOCK" 2>/dev/null; then
			printf '%s\n' "$$" >"$ARTIFACT_LOCK/owner"
			ARTIFACT_LOCK_HELD=1
			return 0
		fi
		owner=$(cat "$ARTIFACT_LOCK/owner" 2>/dev/null || true)
		if [ -n "$owner" ] && ! ps -p "$owner" >/dev/null 2>&1; then
			rm -rf "$ARTIFACT_LOCK"
			tries=$((tries + 1))
			continue
		fi
		sleep 0.1
		tries=$((tries + 1))
	done
	die "another install, update, or uninstall holds the artifact lock at ${ARTIFACT_LOCK}"
}

release_artifact_lock() {
	[ "$ARTIFACT_LOCK_HELD" = "1" ] || return 0
	[ -n "$ARTIFACT_LOCK" ] || return 0
	owner=$(cat "$ARTIFACT_LOCK/owner" 2>/dev/null || true)
	if [ "$owner" = "$$" ]; then
		rm -rf "$ARTIFACT_LOCK"
	fi
	ARTIFACT_LOCK_HELD=0
}

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

optional_field() {
	sed -n "s/.*\"$1\"[[:space:]]*:[[:space:]]*\"\([^\"]*\)\".*/\1/p" "$2" | head -n 1
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
		Linux-x86_64 | Linux-amd64) host_target=linux-x86_64 ;;
		Linux-aarch64 | Linux-arm64) host_target=linux-arm64 ;;
		MINGW*-x86_64 | MSYS*-x86_64 | CYGWIN*-x86_64 | Windows_NT-x86_64) host_target=windows-x86_64 ;;
		MINGW*-arm64 | MSYS*-arm64 | CYGWIN*-arm64 | Windows_NT-arm64) host_target=windows-arm64 ;;
		*) host_target=unsupported ;;
		esac
	fi
	if [ "$target" != "$host_target" ]; then
		case "$host_target" in
		linux-x86_64)
			alt_url=$(optional_field linux_x86_64_archive_url "$tmp/RELEASE.json")
			alt_sha=$(optional_field linux_x86_64_archive_sha256 "$tmp/RELEASE.json")
			;;
		linux-arm64)
			alt_url=$(optional_field linux_arm64_archive_url "$tmp/RELEASE.json")
			alt_sha=$(optional_field linux_arm64_archive_sha256 "$tmp/RELEASE.json")
			;;
		*)
			alt_url=""
			alt_sha=""
			;;
		esac
		if [ -n "$alt_url" ] && [ -n "$alt_sha" ]; then
			archive_url="$alt_url"
			archive_sha="$alt_sha"
		else
			die "signed release target ${target} cannot run on ${host_target}"
		fi
	fi
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

durable_path() {
	"$AST" __sync-update-path "$1"
}

durable_tree() {
	"$AST" __sync-update-path --recursive "$1"
}

durable_parent() {
	"$AST" __sync-update-path --parent-only "$1"
}

restore_chv_capability() {
	chv="$BIN/cloud-hypervisor"
	[ -f "$chv" ] || return 1
	if [ -n "${ASTERISM_UPDATE_SETCAP:-}" ]; then
		"$ASTERISM_UPDATE_SETCAP" cap_net_admin+ep "$chv"
	elif [ "$(id -u)" = 0 ]; then
		setcap cap_net_admin+ep "$chv"
	else
		# install.sh grants this account exactly this fixed setcap invocation.
		# `-n` keeps an unattended updater from hanging on a password prompt.
		sudo -n setcap cap_net_admin+ep "$chv"
	fi || return 1
	durable_path "$chv"
}

activate_chv_capability() {
	if restore_chv_capability; then
		return 0
	fi
	activation_failure="could not apply cap_net_admin to the new Cloud Hypervisor"
	return 1
}

atomic_record() {
	path="$1" value="$2"
	record_tmp="${path}.tmp.$$"
	(umask 077 && printf '%s\n' "$value" >"$record_tmp") || return 1
	# Bytes first, then the rename, then the directory entry. A process crash
	# cannot expose a partial record, and a power loss cannot forget the name
	# after a destination mutation has relied on it.
	durable_path "$record_tmp" || return 1
	mv -f "$record_tmp" "$path" || return 1
	durable_path "$path"
}

resolve_transaction() {
	[ -f "$TRANSACTION_CLAIM" ] || return 1
	transaction_id=$(sed -n '1p' "$TRANSACTION_CLAIM" 2>/dev/null || true)
	claimed_owner=$(sed -n '2p' "$TRANSACTION_CLAIM" 2>/dev/null || true)
	case "$transaction_id" in
	update-transaction.*) ;;
	*) die "the update transaction claim has an invalid identity" ;;
	esac
	case "$transaction_id" in */* | *..*) die "the update transaction claim escapes its state directory" ;; esac
	case "$claimed_owner" in *[!0-9]* | '') die "the update transaction claim has an invalid owner" ;; esac
	TRANSACTION_ID="$transaction_id"
	TRANSACTION_DIR="$STATE_DIR/$TRANSACTION_ID"
	if [ ! -d "$TRANSACTION_DIR" ]; then
		rm -f "$TRANSACTION_CLAIM"
		durable_parent "$TRANSACTION_CLAIM"
		TRANSACTION_ID="" TRANSACTION_DIR=""
		return 1
	fi
	journal_owner=$(sed -n '1p' "$TRANSACTION_DIR/owner-pid" 2>/dev/null || true)
	[ "$journal_owner" = "$claimed_owner" ] || die "the update transaction claim does not match its owner journal"
	return 0
}

release_transaction() {
	claimed=$(sed -n '1p' "$TRANSACTION_CLAIM" 2>/dev/null || true)
	[ "$claimed" = "$TRANSACTION_ID" ] || die "update transaction ownership changed during recovery"
	rm -f "$TRANSACTION_CLAIM"
	# From this unlink onward no destination needs the journal. Drop the
	# in-process ownership flag before syncing/removing private leftovers so a
	# signal cannot recursively recover a claim that has already been released.
	owns_transaction=0
	durable_parent "$TRANSACTION_CLAIM"
	rm -rf "$TRANSACTION_DIR"
	durable_parent "$TRANSACTION_DIR"
	TRANSACTION_ID="" TRANSACTION_DIR="" owns_transaction=0
}

component_destination() {
	case "$1" in
	ast | astd | astd-vz | cloud-hypervisor | virtiofsd) printf '%s/%s' "$BIN" "$1" ;;
	guest-gpu) printf '%s' "$BIN/guest-gpu" ;;
	asterism-update) printf '%s' "$LIBEXEC/asterism-update" ;;
	Asterism.app) [ -n "$transaction_app_path" ] && printf '%s' "$transaction_app_path" ;;
	*) return 1 ;;
	esac
}

cleanup_transaction_staging() {
	owner=$(sed -n '1p' "$TRANSACTION_DIR/owner-pid" 2>/dev/null || true)
	case "$owner" in *[!0-9]* | '') return ;; esac
	for name in ast astd astd-vz cloud-hypervisor virtiofsd; do rm -f "$BIN/.${name}.update.${owner}"; done
	rm -rf "$BIN/.guest-gpu.update.${owner}"
	rm -f "$LIBEXEC/.asterism-update.update.${owner}"
	[ -z "$transaction_app_path" ] || rm -rf "$(dirname "$transaction_app_path")/.Asterism.app.update.${owner}"
	durable_parent "$BIN/.ast.update.${owner}"
	durable_parent "$LIBEXEC/.asterism-update.update.${owner}"
	[ -z "$transaction_app_path" ] || durable_parent "$(dirname "$transaction_app_path")/.Asterism.app.update.${owner}"
}

write_last_state() {
	result="$1" last_build="$2"
	mkdir -p "$STATE_DIR"
	atomic_record "$LAST_FILE" "last_result=${result}
last_build=${last_build}"
}

discard_transaction_backups() {
	for name in astd-vz astd asterism-update ast Asterism.app cloud-hypervisor virtiofsd guest-gpu; do
		[ -f "$TRANSACTION_DIR/component-$name" ] || continue
		dst=$(component_destination "$name") || continue
		rm -rf "${dst}.previous.update" "${dst}.previous.update.absent"
		durable_parent "$dst"
	done
}

rollback_transaction() {
	err "recovering an interrupted update; restoring the previous compatible unit"
	# Reverse activation order. A marker is durable before the first rename.
	# If no backup exists, the destination was never moved and is left alone.
	for name in Asterism.app ast asterism-update astd astd-vz cloud-hypervisor virtiofsd guest-gpu; do
		[ -f "$TRANSACTION_DIR/component-$name" ] || continue
		dst=$(component_destination "$name") || continue
		backup="${dst}.previous.update"
		if [ -e "$backup" ]; then
			rm -rf "$dst"
			mv "$backup" "$dst" || die "could not restore $name from interrupted update"
			if [ -d "$dst" ]; then durable_tree "$dst"; else durable_path "$dst"; fi
			# Cloud Hypervisor's backup is the original inode, including its
			# capability xattr. Re-running setcap here can repeat the activation
			# failure and strand the transaction before journal cleanup.
		elif [ -e "${backup}.absent" ]; then
			rm -rf "$dst"
			durable_parent "$dst"
		fi
		rm -rf "$backup" "${backup}.absent"
		durable_parent "$dst"
	done
	cleanup_transaction_staging
	old_build=$(sed -n '1p' "$TRANSACTION_DIR/old-build" 2>/dev/null || true)
	if [ -n "$old_build" ] && [ -x "$BIN/ast" ]; then
		"$BIN/ast" __activate-update --build "$old_build" >/dev/null 2>&1 || true
		write_last_state "recovered interrupted activation" "$old_build"
	fi
	release_transaction
}

finish_committed_transaction() {
	old_build=$(sed -n '1p' "$TRANSACTION_DIR/old-build" 2>/dev/null || true)
	new_build=$(sed -n '1p' "$TRANSACTION_DIR/new-build" 2>/dev/null || true)
	discard_transaction_backups
	cleanup_transaction_staging
	[ -z "$new_build" ] || write_last_state "updated ${old_build} -> ${new_build}" "$new_build"
	release_transaction
}

recover_interrupted() {
	if [ -z "$TRANSACTION_DIR" ]; then
		resolve_transaction || return 0
	fi
	[ -d "$TRANSACTION_DIR" ] || return 0
	owner=$(sed -n '1p' "$TRANSACTION_DIR/owner-pid" 2>/dev/null || true)
	if [ "${1:-}" != force ] && [ -n "$owner" ] && [ "$owner" != "$$" ] && kill -0 "$owner" 2>/dev/null; then
		die "another updater process (${owner}) owns the activation transaction"
	fi
	owns_transaction=1
	transaction_app_path=$(sed -n '1p' "$TRANSACTION_DIR/app-path" 2>/dev/null || true)
	phase=$(sed -n '1p' "$TRANSACTION_DIR/phase" 2>/dev/null || true)
	recovering=1
	if [ "$phase" = committed ]; then
		finish_committed_transaction
	else
		rollback_transaction
	fi
	recovering=0
}

begin_transaction() {
	mkdir -p "$STATE_DIR"
	durable_path "$STATE_DIR"
	while :; do
		TRANSACTION_DIR=$(mktemp -d "$STATE_DIR/update-transaction.XXXXXX") ||
			die "could not prepare the update transaction"
		TRANSACTION_ID=${TRANSACTION_DIR##*/}
		atomic_record "$TRANSACTION_DIR/owner-pid" "$$"
		# Both the private journal identity and its process owner are in the inode
		# linked into the fixed name. Acquisition therefore publishes the complete
		# ownership claim in one link(2), rather than relying on a later metadata
		# write that a concurrent updater could mistake for a stale transaction.
		atomic_record "$TRANSACTION_DIR/claim" "${TRANSACTION_ID}
$$"
		if ln "$TRANSACTION_DIR/claim" "$TRANSACTION_CLAIM" 2>/dev/null; then
			# The fixed claim is a hard link to a fully written identity. There is
			# no state in which the claim exists but its owner is unpublished.
			durable_path "$TRANSACTION_CLAIM"
			owns_transaction=1
			break
		fi
		rm -rf "$TRANSACTION_DIR"
		durable_parent "$TRANSACTION_DIR"
		TRANSACTION_ID="" TRANSACTION_DIR=""
		resolve_transaction || continue
		recover_interrupted
	done
	if [ -n "${ASTERISM_UPDATE_PAUSE_AFTER_CLAIM:-}" ]; then
		atomic_record "${ASTERISM_UPDATE_PAUSE_AFTER_CLAIM}.ready" "$TRANSACTION_ID"
		IFS= read -r resume <"$ASTERISM_UPDATE_PAUSE_AFTER_CLAIM" ||
			die "claim pause ended without a resume"
		[ "$resume" = resume ] || die "claim pause received an invalid resume"
	fi
	transaction_app_path="$app_path"
	atomic_record "$TRANSACTION_DIR/old-build" "$ours_build"
	atomic_record "$TRANSACTION_DIR/new-build" "$build"
	atomic_record "$TRANSACTION_DIR/app-path" "$transaction_app_path"
	atomic_record "$TRANSACTION_DIR/phase" activating
}

journal_component() {
	atomic_record "$TRANSACTION_DIR/component-$1" planned
}

inject_fault() {
	name="$1" boundary="$2"
	case "${ASTERISM_UPDATE_FAULT:-}" in
	signal:"$name":"$boundary") kill -TERM "$$"; return 97 ;;
	kill:"$name":"$boundary") kill -KILL "$$"; return 97 ;;
	rename:"$name":"$boundary") return 97 ;;
	esac
	return 0
}

place_one() {
	name="$1" src="$2" dst="$3"
	backup="${dst}.previous.update"
	rm -rf "$backup" "${backup}.absent"
	durable_parent "$dst" || return 97
	journal_component "$name" || return 97
	inject_fault "$name" journal || return 97
	if [ -e "$dst" ]; then
		inject_fault "$name" backup || return 97
		if [ -d "$dst" ]; then
			mv "$dst" "$backup" || return 97
			durable_tree "$backup" || return 97
		elif ln "$dst" "$backup" 2>/dev/null; then
			durable_path "$backup" || return 97
		elif [ "$name" = cloud-hypervisor ]; then
			# If hard-link protection rejects a capable root-owned binary, move
			# the old inode rather than copying it and losing its capability xattr.
			mv "$dst" "$backup" || return 97
			durable_path "$backup" || return 97
		else
			backup_tmp="${backup}.tmp.$$"
			rm -f "$backup_tmp"
			cp -p "$dst" "$backup_tmp" || return 97
			durable_path "$backup_tmp" || return 97
			mv "$backup_tmp" "$backup" || return 97
			durable_path "$backup" || return 97
		fi
	else
		atomic_record "${backup}.absent" absent || return 97
	fi
	inject_fault "$name" backed-up || return 97
	inject_fault "$name" activate || return 97
	mv "$src" "$dst" || return 97
	if [ -d "$dst" ]; then durable_tree "$dst"; else durable_path "$dst"; fi || return 97
	inject_fault "$name" activated || return 97
	# Backward-compatible failure injection retained for downstream harnesses.
	[ "${ASTERISM_UPDATE_FAIL_AFTER:-}" != "$name" ] || return 97
}

on_signal() {
	code="$1"
	trap - INT HUP TERM
	[ "$recovering" != 0 ] || recover_interrupted force
	exit "$code"
}

apply_update() {
	activation_failure=""
	managed_by_brew && die "this installation belongs to Homebrew; run: brew upgrade asterism"
	acquire_artifact_lock
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
	for name in ast astd; do verify_binary "$name" "$tmp/stage/$name"; done
	[ -x "$tmp/stage/asterism-update" ] || die "the update archive has no executable asterism-update"
	linux_payload=0
	if [ -x "$tmp/stage/cloud-hypervisor" ] && [ -x "$tmp/stage/virtiofsd" ]; then
		linux_payload=1
	fi
	if [ "$linux_payload" = 1 ]; then
		[ -x "$tmp/stage/cloud-hypervisor" ] || die "the Linux update archive has no executable cloud-hypervisor"
		[ -x "$tmp/stage/virtiofsd" ] || die "the Linux update archive has no executable virtiofsd"
		[ -x "$tmp/stage/guest-gpu/bin/asterism-gpu-guest" ] || die "the Linux update archive has no guest GPU service"
		[ -f "$tmp/stage/guest-gpu/lib/libcuda.so.1.0.0" ] || die "the Linux update archive has no guest libcuda"
	else
		verify_binary astd-vz "$tmp/stage/astd-vz"
	fi

	app_path="${ASTERISM_APP_PATH:-}"
	if [ "$linux_payload" != 1 ]; then
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
	else
		app_path=""
	fi

	mkdir -p "$BIN" "$LIBEXEC"
	begin_transaction
	# Copy bytes beside their destinations before placement begins. The moves
	# are consequently same-filesystem renames; a slow copy or a full disk
	# cannot expose a half-written program as the active one. The transaction
	# already owns these staging paths, so a killed copy is swept at startup.
	if [ "$linux_payload" = 1 ]; then
		place_names="ast astd cloud-hypervisor virtiofsd"
	else
		place_names="ast astd astd-vz"
	fi
	for name in $place_names; do
		cp "$tmp/stage/$name" "$BIN/.${name}.update.$$"
		chmod 755 "$BIN/.${name}.update.$$"
		durable_path "$BIN/.${name}.update.$$"
	done
	if [ "$linux_payload" = 1 ]; then
		cp -R "$tmp/stage/guest-gpu" "$BIN/.guest-gpu.update.$$"
		durable_tree "$BIN/.guest-gpu.update.$$"
	fi
	cp "$tmp/stage/asterism-update" "$LIBEXEC/.asterism-update.update.$$"
	chmod 755 "$LIBEXEC/.asterism-update.update.$$"
	durable_path "$LIBEXEC/.asterism-update.update.$$"
	if [ -n "$app_path" ]; then
		app_parent=$(dirname "$app_path")
		app_staged="${app_parent}/.Asterism.app.update.$$"
		rm -rf "$app_staged"
		cp -R "$tmp/app-stage/Asterism.app" "$app_staged"
		durable_tree "$app_staged"
	fi
	if ! {
		if [ "$linux_payload" = 1 ]; then
			place_one guest-gpu "$BIN/.guest-gpu.update.$$" "$BIN/guest-gpu" &&
			place_one cloud-hypervisor "$BIN/.cloud-hypervisor.update.$$" "$BIN/cloud-hypervisor" &&
			activate_chv_capability &&
			place_one virtiofsd "$BIN/.virtiofsd.update.$$" "$BIN/virtiofsd" &&
			place_one astd "$BIN/.astd.update.$$" "$BIN/astd" &&
			place_one asterism-update "$LIBEXEC/.asterism-update.update.$$" "$LIBEXEC/asterism-update" &&
			place_one ast "$BIN/.ast.update.$$" "$BIN/ast"
		else
			place_one astd-vz "$BIN/.astd-vz.update.$$" "$BIN/astd-vz" &&
			place_one astd "$BIN/.astd.update.$$" "$BIN/astd" &&
			place_one asterism-update "$LIBEXEC/.asterism-update.update.$$" "$LIBEXEC/asterism-update" &&
			place_one ast "$BIN/.ast.update.$$" "$BIN/ast" &&
			if [ -n "$app_path" ]; then
				place_one Asterism.app "$app_staged" "$app_path"
			fi
		fi &&
		"$BIN/ast" __activate-update --build "$build"
	}; then
		recover_interrupted force
		die "${activation_failure:-the new build did not activate}; the previous compatible unit was restored"
	fi
	atomic_record "$TRANSACTION_DIR/phase" committed
	inject_fault transaction committed
	finish_committed_transaction
	say "updated ${ours} ${ours_build} -> ${version} ${build}"
	say "the daemon restarted; its guest processes were left running and re-adopted"
}

trap 'on_signal 130' INT
trap 'on_signal 129' HUP
trap 'on_signal 143' TERM
[ -x "$AST" ] || die "cannot find ast at ${AST}; set ASTERISM_UPDATE_AST_PATH to the installed binary"
recover_interrupted

channel="${ASTERISM_UPDATE_CHANNEL:-}"
if [ -z "$channel" ] && [ -f "$CHANNEL_FILE" ]; then
	channel=$(sed -n '1p' "$CHANNEL_FILE")
fi
channel="${channel:-stable}"
case "$channel" in
stable | beta | nightly) ;;
*) die "unknown channel ${channel}; choose stable, beta, or nightly" ;;
esac

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
