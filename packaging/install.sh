#!/bin/sh
# Asterism installer.
#
#   curl -fsSL https://asterism.run/install.sh | sh
#
# What it installs, by default and always: one tagged release. A release is
# a tag, a tarball built from that tag, and a SHA256SUMS file listing that
# tarball's digest. Every one of those is immutable — re-running this script
# a year from now with the same ASTERISM_VERSION puts the same bytes on the
# machine, or fails saying why it could not. It never builds from a moving
# branch unless you name one, never runs sudo without printing the command
# and asking, and never installs a byte it has not checksummed.
#
# This is the CLI: `ast`, the `astd` daemon it starts, and `astd-vz`, the
# code-signed helper that owns Virtualization.framework guests on macOS, or
# the pinned Cloud Hypervisor and virtiofsd helpers on Linux. The desktop app
# is a separate DMG — see
# https://asterism.run/download.
#
# Environment:
#   ASTERISM_VERSION=v0.1.0   install exactly this tag (default: latest release)
#   ASTERISM_METHOD=release   release (default) | source | brew
#   ASTERISM_PREFIX=DIR       install prefix (default: ~/.local)
#   ASTERISM_SYSTEM_ROOT=DIR  test harness only: stage host files under DIR
#   ASTERISM_YES=1            answer yes to every prompt (for CI)
#   ASTERISM_FORCE=1          reinstall even when that version is already here
#   ASTERISM_SHA256=HEX       expected digest of the tarball, pinned by hand
#   ASTERISM_REQUIRE_SIGNATURE=1  refuse to install unless the signature verifies
#   ASTERISM_PUBKEY=KEY       minisign/signify public key to verify with
#   ASTERISM_REF=main         source/brew only: build this git ref instead of a tag
#   ASTERISM_TAP=user/tap     brew only: tap to install from
#   ASTERISM_PIN_TAP=user/tap brew only: tap to build when the one above
#                             does not pin the version asked for
#
#   --uninstall               remove exactly what a previous run installed
#
# Overrides for mirrors and for the release test harness:
#   ASTERISM_BASE_URL=URL     where release assets live (default: GitHub releases)
#   ASTERISM_INDEX_URL=URL    JSON naming the latest tag (default: GitHub API)
set -eu

REPO="medicalissue/asterism"
REPO_URL="https://github.com/${REPO}.git"

VERSION="${ASTERISM_VERSION:-}"
METHOD="${ASTERISM_METHOD:-release}"
if [ -n "${ASTERISM_PREFIX:-}" ]; then
	PREFIX="$ASTERISM_PREFIX"
else
	case "$(uname -s 2>/dev/null || echo unknown)" in
	MINGW* | MSYS* | CYGWIN* | Windows_NT)
		PREFIX="${LOCALAPPDATA:-${HOME}/AppData/Local}/Asterism"
		;;
	*)
		PREFIX="${HOME}/.local"
		;;
	esac
fi
# Test harnesses may stage host integration beneath a disposable root. Real
# installs leave this empty and therefore use the fixed, root-owned paths that
# the daemon and sudoers both name.
SYSTEM_ROOT="${ASTERISM_SYSTEM_ROOT:-}"
ASSUME_YES="${ASTERISM_YES:-0}"
FORCE="${ASTERISM_FORCE:-0}"
REF="${ASTERISM_REF:-}"
TAP="${ASTERISM_TAP:-medicalissue/asterism}"
# Where a version the published tap does not pin gets installed from. Never
# the published tap, always one this script created and stamped.
PIN_TAP="${ASTERISM_PIN_TAP:-${TAP}-pin}"
PINNED_SHA="${ASTERISM_SHA256:-}"
REQUIRE_SIG="${ASTERISM_REQUIRE_SIGNATURE:-0}"
PUBKEY="${ASTERISM_PUBKEY:-}"

BASE_URL="${ASTERISM_BASE_URL:-https://github.com/${REPO}/releases/download}"
INDEX_URL="${ASTERISM_INDEX_URL:-https://api.github.com/repos/${REPO}/releases/latest}"

# The receipt is the whole reason uninstall and upgrade can be exact: it
# records the version, the digest, and the literal list of files this script
# wrote. Nothing else in the prefix is ever this script's to touch.
RECEIPT_REL="share/asterism/install-receipt.env"

say() { printf 'asterism: %s\n' "$*"; }
err() { printf 'asterism: %s\n' "$*" >&2; }
die() {
	err "$*"
	exit 1
}
have() { command -v "$1" >/dev/null 2>&1; }

TMPDIR_SELF=""
INSTALL_TXN_ACTIVE=0
ARTIFACT_LOCK=""
ARTIFACT_LOCK_HELD=0
cleanup() {
	status=$?
	trap - EXIT INT HUP TERM
	if [ "$INSTALL_TXN_ACTIVE" = "1" ]; then
		set +e
		err "installation did not commit; rolling back the durable install intent"
		rollback_incomplete_install
		set -e
	fi
	release_artifact_lock
	[ -n "$TMPDIR_SELF" ] && rm -rf "$TMPDIR_SELF"
	exit "$status"
}
trap cleanup EXIT INT HUP TERM

# Install, update, and uninstall share this one prefix lock so a second
# process cannot replace artifacts while another still owns them.
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
		# A live owner, or an empty lock still being published.
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

nbd_state_dir() {
	printf '%s' "${SYSTEM_ROOT}/run/asterism-nbd"
}

nbd_helper_path() {
	printf '%s' "${SYSTEM_ROOT}/usr/local/libexec/asterism/asterism-nbd"
}

# Complete claims are owner+helper-pid. Staging directories and ownerless
# leftovers are recovery work, not live attachments.
live_nbd_claims() {
	state="$(nbd_state_dir)"
	[ -d "$state" ] || return 1
	for claim in "$state"/nbd*; do
		[ -d "$claim" ] || continue
		case "$claim" in *.new.*) continue ;; esac
		if [ -f "$claim/owner" ] && [ -f "$claim/helper-pid" ]; then
			return 0
		fi
	done
	return 1
}

drain_own_nbd_claims() {
	state="$(nbd_state_dir)"
	helper="$(nbd_helper_path)"
	[ -d "$state" ] || return 0
	our="$(id -u):$(id -g)"
	for claim in "$state"/nbd*; do
		[ -d "$claim" ] || continue
		case "$claim" in *.new.*) continue ;; esac
		if [ ! -f "$claim/owner" ] || [ ! -f "$claim/helper-pid" ]; then
			continue
		fi
		owner=$(cat "$claim/owner" 2>/dev/null || true)
		name=$(basename "$claim")
		case "$name" in
		nbd[0-9] | nbd[0-9][0-9]) ;;
		*) continue ;;
		esac
		if [ "$owner" != "$our" ]; then
			err "NBD claim ${name} belongs to ${owner}, not ${our}"
			return 1
		fi
		if [ ! -x "$helper" ]; then
			err "cannot drain ${name}: NBD helper is missing"
			return 1
		fi
		run_root "$helper" -d "/dev/${name}" || {
			err "could not detach live NBD claim on /dev/${name}"
			return 1
		}
	done
	return 0
}

# Ask out loud, on the terminal — not on stdin, which is this script itself
# under `curl | sh`. No tty and no ASTERISM_YES means we cannot get consent,
# so we do not act.
confirm() {
	if [ "$ASSUME_YES" = "1" ]; then
		say "$1 — yes (ASTERISM_YES=1)"
		return 0
	fi
	# `[ -r /dev/tty ]` is true even with no controlling terminal, where the
	# open then fails noisily. Opening it is the only honest test.
	if ! { : 2>/dev/null >/dev/tty; }; then
		err "$1"
		err "no terminal to ask on. Re-run with ASTERISM_YES=1, or run the command above by hand."
		return 1
	fi
	printf 'asterism: %s [y/N] ' "$1" >/dev/tty
	read -r reply </dev/tty || return 1
	case "$reply" in
	y | Y | yes | Yes | YES) return 0 ;;
	*) return 1 ;;
	esac
}

# Run a command as root, having printed it first. Never silent, never piped.
run_root() {
	if [ "$(id -u)" = "0" ]; then
		say "running: $*"
		"$@"
		return 0
	fi
	have sudo || die "this needs root and sudo is not installed. Run as root: $*"
	say "this needs root:"
	printf '    sudo %s\n' "$*"
	confirm "run it?" || die "declined. Run the command above yourself, then re-run this script."
	sudo "$@"
}

fetch() {
	# $1 url, $2 destination. Curl and wget both fail loudly on 404 here,
	# and both understand file:// so the release tests can run offline.
	if have curl; then
		curl -fsSL "$1" -o "$2"
	elif have wget; then
		wget -qO "$2" "$1"
	else
		die "curl or wget is required to download releases."
	fi
}

sha256_of() {
	if have shasum; then
		shasum -a 256 "$1" | cut -d' ' -f1
	elif have sha256sum; then
		sha256sum "$1" | cut -d' ' -f1
	else
		die "no sha256 tool (shasum or sha256sum) — cannot verify the download, so cannot install."
	fi
}

# The prefix is a directory in $HOME by default and this script never asks
# for root to write a binary. Say so plainly rather than letting cp fail with
# a permission error the user has to interpret.
ensure_writable_prefix() {
	mkdir -p "${PREFIX}/bin" 2>/dev/null ||
		die "cannot create ${PREFIX}/bin. Pick a prefix you own with ASTERISM_PREFIX, or create it yourself."
	[ -w "${PREFIX}/bin" ] ||
		die "${PREFIX}/bin is not writable by $(id -un). This script does not install as root; set ASTERISM_PREFIX to somewhere you own."
}

# Put one binary in place: staged beside its destination and renamed, so an
# upgrade never leaves a half-written binary where a working one used to be
# — and so replacing a running `astd` is a rename, not a truncation.
place() {
	# $1 file to install, $2 name under bin/
	place_at "$1" "bin/$2"
}

place_at() {
	# $1 source, $2 prefix-relative destination
	dest="${PREFIX}/$2"
	mkdir -p "$(dirname "$dest")"
	staged="$(dirname "$dest")/.$(basename "$dest").new.$$"
	cp "$1" "$staged"
	chmod 755 "$staged"
	mv -f "$staged" "$dest"
	say "installed ${dest}"
}

linux_guest_files() {
	printf '%s' 'bin/guest-gpu/bin/asterism-gpu-guest bin/guest-gpu/lib/libcuda.so.1.0.0 bin/guest-gpu/lib/libcuda.so.1 bin/guest-gpu/lib/libcuda.so'
}

validate_linux_guest_artifacts() {
	source_dir="${1:-}"
	[ -n "$source_dir" ] || die "guest GPU artifact root is empty. Refusing to copy from an ambient /bin path."
	case "$source_dir" in
	/*) ;;
	*) die "guest GPU artifact root is not absolute: ${source_dir}" ;;
	esac
	[ -x "${source_dir}/bin/asterism-gpu-guest" ] ||
		die "guest GPU artifact root has no executable service: ${source_dir}"
	[ -f "${source_dir}/lib/libcuda.so.1.0.0" ] ||
		die "guest GPU artifact root has no generated libcuda: ${source_dir}"
	[ "$(readlink "${source_dir}/lib/libcuda.so.1" 2>/dev/null || true)" = libcuda.so.1.0.0 ] ||
		die "guest GPU artifact root has no exact libcuda.so.1 link: ${source_dir}"
	[ "$(readlink "${source_dir}/lib/libcuda.so" 2>/dev/null || true)" = libcuda.so.1 ] ||
		die "guest GPU artifact root has no exact libcuda.so link: ${source_dir}"
}

place_linux_guest() {
	source_dir="${1:-}"
	validate_linux_guest_artifacts "$source_dir"
	for rel in bin/asterism-gpu-guest lib/libcuda.so.1.0.0 lib/libcuda.so.1 lib/libcuda.so; do
		place_at "${source_dir}/${rel}" "bin/guest-gpu/${rel}"
	done
}

# macOS marks a file a *browser* downloaded with com.apple.quarantine, and
# tar hands that mark to every file it extracts. Gatekeeper then assesses
# what execs, and an ad-hoc signature does not pass an assessment — so the
# one binary that must be signed to work at all, `astd-vz`, is the one that
# gets killed at exec.
#
# In practice nothing reaches here marked: this script re-fetches the
# archive with curl or wget, and neither carries the flag onto the file it
# writes, even when ASTERISM_BASE_URL points at a directory someone
# downloaded by hand. This runs anyway, so that a working helper is
# something this script guarantees rather than something it inherits from
# how curl happens to write files.
#
# The flag records "these bytes came from the internet and nobody checked
# them". By this point they have been checked, against a digest published
# under an immutable tag — which is a stronger claim than the flag makes. So
# it goes, out loud, and only from files this script wrote.
unquarantine() {
	[ "$(uname -s)" = "Darwin" ] || return 0
	have xattr || return 0
	for f in "$@"; do
		xattr -p com.apple.quarantine "$f" >/dev/null 2>&1 || continue
		xattr -d com.apple.quarantine "$f" >/dev/null 2>&1 || continue
		say "cleared the quarantine flag macOS put on ${f} — its digest was checked above"
	done
}

# ---- what machine is this --------------------------------------------------

# Binary releases exist for exactly the targets named here. Anything else is
# refused by name, with the source escape hatch spelled out; guessing a close
# enough target is how people end up with a binary that cannot run.
detect_target() {
	os="$(uname -s)"
	arch="$(uname -m)"
	case "$arch" in
	arm64 | aarch64) arch="arm64" ;;
	x86_64 | amd64) arch="x86_64" ;;
	esac

	case "${os}-${arch}" in
	Darwin-arm64) printf 'darwin-arm64' ;;
	Linux-x86_64) printf 'linux-x86_64' ;;
	Linux-arm64) printf 'linux-arm64' ;;
	Windows_NT-x86_64 | MINGW*-x86_64 | MSYS*-x86_64 | CYGWIN*-x86_64) printf 'windows-x86_64' ;;
	Windows_NT-arm64 | MINGW*-arm64 | MSYS*-arm64 | CYGWIN*-arm64) printf 'windows-arm64' ;;
	*) return 1 ;;
	esac
}

is_windows_uname() {
	case "$(uname -s)" in
	MINGW* | MSYS* | CYGWIN* | Windows_NT) return 0 ;;
	*) return 1 ;;
	esac
}

unsupported_target() {
	err "no binary release for $(uname -s) $(uname -m)."
	err ""
	err "Asterism publishes binaries for macOS on Apple silicon (darwin-arm64),"
	err "Linux on x86-64 or arm64, and Windows 11 Pro/Enterprise."
	err "Everything else builds from source, which needs Rust and a few minutes:"
	err ""
	err "    curl -fsSL https://asterism.run/install.sh | ASTERISM_METHOD=source sh"
	err "    irm https://asterism.run/install.ps1 | iex   # native Windows"
	err ""
	exit 1
}

# ---- the receipt -----------------------------------------------------------

receipt_path() { printf '%s/%s' "$PREFIX" "$RECEIPT_REL"; }

# Read one field out of the receipt without sourcing it: a file in the user's
# prefix is not something to execute.
receipt_field() {
	r="$(receipt_path)"
	[ -f "$r" ] || return 1
	value="$(sed -n "s/^$1=//p" "$r" | tail -n 1)"
	[ -n "$value" ] || return 1
	printf '%s' "$value"
}

write_receipt() {
	# $1 version, $2 target, $3 method, $4 sha256, rest: files, prefix-relative
	r="$(receipt_path)"
	v="$1" t="$2" m="$3" s="$4"
	shift 4
	write_receipt_document "$r" complete "$v" "$t" "$m" "$s" "$*" "${RECEIPT_SYSTEM_FILES:-}"
	INSTALL_TXN_ACTIVE=0
	say "wrote ${r}"
}

# A receipt is also the transaction journal. It is published before the first
# product or privileged path is changed, then replaced with phase=complete only
# after every change succeeds. A killed installer therefore leaves enough
# durable information for --uninstall or the next install to converge.
write_install_intent() {
	r="$(receipt_path)"
	v="$1" t="$2" m="$3" s="$4"
	RECEIPT_SYSTEM_FILES="$5"
	shift 5
	# An upgrade may fail after replacing a path from the previous release.
	# The recovery authority therefore owns the union of old and new paths:
	# rollback converges to fully uninstalled rather than leaving a mixture of
	# versions, and the stale-helper cleanup below can still see what the prior
	# receipt owned after this journal replaces it.
	previous_files="$(receipt_field files || true)"
	previous_system_files="$(receipt_field system_files || true)"
	if [ -z "$previous_system_files" ]; then
		case " $previous_files " in
		*" bin/cloud-hypervisor "*) previous_system_files="$(linux_system_files)" ;;
		esac
	fi
	write_receipt_document "$r" installing "$v" "$t" "$m" "$s" \
		"$* $previous_files" "$RECEIPT_SYSTEM_FILES $previous_system_files"
	INSTALL_TXN_ACTIVE=1
	say "wrote durable install intent ${r}"
}

write_receipt_document() {
	r="$1" phase="$2" v="$3" t="$4" m="$5" s="$6" files="$7" system_files="$8"
	dir="$(dirname "$r")"
	mkdir -p "$dir"
	staged="${r}.new.$$"
	{
		printf '# Written by the Asterism installer. Uninstall reads it; do not edit.\n'
		printf 'phase=%s\n' "$phase"
		printf 'version=%s\n' "$v"
		printf 'target=%s\n' "$t"
		printf 'method=%s\n' "$m"
		printf 'sha256=%s\n' "$s"
		printf 'files=%s\n' "$files"
		printf 'system_files=%s\n' "$system_files"
	} >"$staged"
	chmod 0644 "$staged"
	# Linux coreutils can sync one path; other supported hosts still get a
	# global sync rather than publishing an unflushed journal.
	if ! sync -f "$staged" 2>/dev/null; then sync; fi
	mv -f "$staged" "$r"
	if ! sync -f "$dir" 2>/dev/null; then sync; fi
}

# Is everything the receipt names still on the machine?
#
# "Already installed" is a claim about the machine, not about the receipt.
# A binary someone deleted, or one an interrupted upgrade never wrote,
# leaves the version field saying yes while the prefix says no.
receipt_complete() {
	phase="$(receipt_field phase || true)"
	[ -z "$phase" ] || [ "$phase" = "complete" ] || return 1
	files="$(receipt_field files || true)"
	[ -n "$files" ] || return 1
	for rel in $files; do
		[ -e "${PREFIX}/${rel}" ] || return 1
		case "$rel" in bin/*) [ -x "${PREFIX}/${rel}" ] || return 1 ;; esac
	done
	return 0
}

linux_system_files() {
	uid="$(id -u)"
	printf '%s' "${SYSTEM_ROOT}/etc/modules-load.d/asterism-nbd.conf ${SYSTEM_ROOT}/etc/modprobe.d/asterism-nbd.conf ${SYSTEM_ROOT}/run/lock/asterism-nbd.lock ${SYSTEM_ROOT}/run/asterism-nbd ${SYSTEM_ROOT}/usr/local/libexec/asterism/asterism-nbd ${SYSTEM_ROOT}/etc/sudoers.d/asterism-nbd-${uid}"
}

remove_receipt_files() {
	files="$(receipt_field files || true)"
	for rel in $files; do
		f="${PREFIX}/${rel}"
		if [ -e "$f" ] || [ -L "$f" ]; then
			rm -f "$f" || return 1
			say "removed ${f}"
		else
			say "already gone: ${f}"
		fi
	done
	# Releases predating the packaged guest projection do not name this unit
	# in their receipt. The presence of the installer-owned Cloud Hypervisor
	# entry identifies that Linux ownership lane; a signed update may then
	# have added guest-gpu atomically without rewriting the bootstrap receipt.
	if receipt_lists bin/cloud-hypervisor; then
		for rel in bin/guest-gpu/bin/asterism-gpu-guest \
			bin/guest-gpu/lib/libcuda.so.1.0.0 \
			bin/guest-gpu/lib/libcuda.so.1 bin/guest-gpu/lib/libcuda.so; do
			receipt_lists "$rel" && continue
			f="${PREFIX}/${rel}"
			if [ -e "$f" ] || [ -L "$f" ]; then
				rm -f "$f" || return 1
				say "removed ${f} — adopted from a signed Linux update"
			fi
		done
	fi
	rmdir "${PREFIX}/bin/guest-gpu/lib" 2>/dev/null || true
	rmdir "${PREFIX}/bin/guest-gpu/bin" 2>/dev/null || true
	rmdir "${PREFIX}/bin/guest-gpu" 2>/dev/null || true
}

remove_receipt_system_files() {
	system_files="$(receipt_field system_files || true)"
	# Legacy Linux receipts from the rejected builds did not name host files.
	# Their cloud-hypervisor entry is nevertheless an unambiguous installer
	# ownership marker, so recovery can remove the exact historical residue.
	if [ -z "$system_files" ] && receipt_lists bin/cloud-hypervisor; then
		system_files="$(linux_system_files)"
	fi
	for f in $system_files; do
		if [ -d "$f" ]; then
			# This is the exact root-owned state directory created by the
			# installer; remove only its claims, never a caller-selected path.
			run_root rm -rf "$f" || return 1
		else
			run_root rm -f "$f" || return 1
		fi
		say "removed ${f}"
	done
}

retire_receipt() {
	r="$(receipt_path)"
	rm -f "$r" "${r}.new" "${r}.new.$$"
	if ! sync -f "$(dirname "$r")" 2>/dev/null; then sync; fi
}

rollback_incomplete_install() {
	[ -f "$(receipt_path)" ] || return 0
	remove_receipt_system_files || return 1
	remove_receipt_files || return 1
	retire_receipt
	INSTALL_TXN_ACTIVE=0
}

# Does the receipt name this file among the ones this script wrote?
receipt_lists() {
	files="$(receipt_field files || true)"
	for rel in $files; do
		if [ "$rel" = "$1" ]; then
			return 0
		fi
	done
	return 1
}

# A move to a build with no helper must take the old helper with it: `astd`
# spawns whatever `astd-vz` sits beside it, and a helper from another build
# answers a control protocol this daemon may not speak — so leaving it there
# is worse than not having one at all. Only ever a helper this script
# installed; the receipt is what says so.
drop_stale_helper() {
	[ -e "${PREFIX}/bin/astd-vz" ] || return 0
	receipt_lists bin/astd-vz || return 0
	rm -f "${PREFIX}/bin/astd-vz"
	say "removed ${PREFIX}/bin/astd-vz — this build ships no helper, and one from another build must not answer for it"
}

drop_stale_linux_helpers() {
	for rel in bin/cloud-hypervisor bin/virtiofsd \
		bin/guest-gpu/bin/asterism-gpu-guest \
		bin/guest-gpu/lib/libcuda.so.1.0.0 bin/guest-gpu/lib/libcuda.so.1 \
		bin/guest-gpu/lib/libcuda.so \
		share/asterism/linux-components.env \
		share/asterism/asterism-nbd \
		share/asterism/licenses/cloud-hypervisor-Apache-2.0.txt \
		share/asterism/licenses/cloud-hypervisor-BSD-3-Clause.txt \
		share/asterism/licenses/virtiofsd-Apache-2.0.txt \
		share/asterism/licenses/virtiofsd-BSD-3-Clause.txt \
		share/asterism/licenses/LICENSE-APACHE share/asterism/licenses/LICENSE-MIT \
		share/asterism/licenses/NOTICE; do
		receipt_lists "$rel" || continue
		[ -e "${PREFIX}/${rel}" ] || continue
		rm -f "${PREFIX}/${rel}"
		say "removed ${PREFIX}/${rel} — this target ships no Linux helper"
	done
	rmdir "${PREFIX}/share/asterism/licenses" 2>/dev/null || true
	rmdir "${PREFIX}/bin/guest-gpu/lib" 2>/dev/null || true
	rmdir "${PREFIX}/bin/guest-gpu/bin" 2>/dev/null || true
	rmdir "${PREFIX}/bin/guest-gpu" 2>/dev/null || true
}

# ---- resolving a version ---------------------------------------------------

# "Latest" is resolved once, here, into a tag — and every URL after this point
# is built from that tag. Nothing downstream ever fetches a "latest" alias,
# so a release cut halfway through an install cannot swap the bytes underneath
# it.
resolve_version() {
	if [ -n "$VERSION" ]; then
		printf '%s' "$VERSION"
		return 0
	fi
	index="${TMPDIR_SELF}/latest.json"
	if ! fetch "$INDEX_URL" "$index" 2>/dev/null; then
		err "could not reach ${INDEX_URL} to find the latest release."
		err ""
		err "If this machine is offline, name the version and the digest yourself:"
		err ""
		err "    ASTERISM_VERSION=v0.1.0 ASTERISM_SHA256=<digest> sh install.sh"
		err ""
		exit 1
	fi
	tag="$(sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$index" | head -n 1)"
	[ -n "$tag" ] || die "no release tag in the answer from ${INDEX_URL}. Asterism may have no tagged release yet; pass ASTERISM_VERSION to name one."
	printf '%s' "$tag"
}

# ---- verification ----------------------------------------------------------

# The digest comes from SHA256SUMS, published beside the tarball under the
# same immutable tag — or from ASTERISM_SHA256, which is how you install with
# no trust in the host serving the files at all.
expected_digest() {
	# $1 sums file, $2 artifact name
	# Match the filename field exactly. A grep pattern would treat every dot
	# in "asterism-v0.1.0-darwin-arm64.tar.gz" as a wildcard, and the whole
	# point of this lookup is that it is not approximate.
	digest="$(awk -v want="$2" '$2 == want || $2 == "*" want { print $1; exit }' "$1")"
	[ -n "$digest" ] || die "SHA256SUMS does not list ${2}. Refusing to install an unlisted artifact."
	printf '%s' "$digest"
}

# Signatures are a seam, not yet a promise: Asterism does not publish a
# signing key today. When SHA256SUMS.sig is there and a verifier and key are
# too, it is checked. ASTERISM_REQUIRE_SIGNATURE=1 turns "not there" into a
# refusal, which is the flag to set once the key exists.
verify_signature() {
	sums="$1" sig="$2"
	if [ ! -f "$sig" ]; then
		if [ "$REQUIRE_SIG" = "1" ]; then
			die "no signature published for this release, and ASTERISM_REQUIRE_SIGNATURE=1."
		fi
		return 0
	fi
	if [ -z "$PUBKEY" ]; then
		[ "$REQUIRE_SIG" = "1" ] &&
			die "a signature is published but ASTERISM_PUBKEY is unset, so it cannot be checked."
		say "a signature is published; set ASTERISM_PUBKEY to have it checked."
		return 0
	fi
	if have minisign; then
		say "minisign -Vm SHA256SUMS"
		minisign -Vm "$sums" -x "$sig" -P "$PUBKEY" >/dev/null ||
			die "the signature on SHA256SUMS does not verify. Refusing to install."
	elif have signify; then
		say "signify -V SHA256SUMS"
		printf '%s\n' "$PUBKEY" >"${TMPDIR_SELF}/pubkey"
		signify -V -p "${TMPDIR_SELF}/pubkey" -x "$sig" -m "$sums" >/dev/null ||
			die "the signature on SHA256SUMS does not verify. Refusing to install."
	else
		[ "$REQUIRE_SIG" = "1" ] &&
			die "a signature is published but neither minisign nor signify is installed."
		say "a signature is published; install minisign to have it checked."
		return 0
	fi
	say "signature verified"
}

# ---- the default path: a tagged binary release -----------------------------

install_release() {
	target="$(detect_target)" || unsupported_target
	version="$(resolve_version)"
	say "release ${version} for ${target}"

	installed="$(receipt_field version || true)"
	if [ "$installed" = "$version" ] && [ "$FORCE" != "1" ] && receipt_complete; then
		say "already installed: ${version} in ${PREFIX}/bin"
		say "re-run with ASTERISM_FORCE=1 to reinstall it, or ASTERISM_VERSION to move to another."
		return 0
	fi

	artifact="asterism-${version}-${target}.tar.gz"
	url="${BASE_URL}/${version}/${artifact}"
	tarball="${TMPDIR_SELF}/${artifact}"

	say "downloading ${url}"
	fetch "$url" "$tarball" || die "could not download ${url}. Nothing was installed."

	if [ -n "$PINNED_SHA" ]; then
		want="$PINNED_SHA"
		say "digest pinned by ASTERISM_SHA256"
	else
		sums="${TMPDIR_SELF}/SHA256SUMS"
		say "downloading ${BASE_URL}/${version}/SHA256SUMS"
		fetch "${BASE_URL}/${version}/SHA256SUMS" "$sums" ||
			die "could not download SHA256SUMS for ${version}. Refusing to install unverified bytes."
		fetch "${BASE_URL}/${version}/SHA256SUMS.sig" "${TMPDIR_SELF}/SHA256SUMS.sig" 2>/dev/null || true
		verify_signature "$sums" "${TMPDIR_SELF}/SHA256SUMS.sig"
		want="$(expected_digest "$sums" "$artifact")"
	fi

	got="$(sha256_of "$tarball")"
	if [ "$got" != "$want" ]; then
		err "checksum mismatch on ${artifact}:"
		err "    expected ${want}"
		err "    got      ${got}"
		die "refusing to install. Nothing was written."
	fi
	say "sha256 ok: ${got}"

	unpack="${TMPDIR_SELF}/unpack"
	mkdir -p "$unpack"
	tar -xzf "$tarball" -C "$unpack" || die "could not unpack ${artifact}."
	exe=""
	case "$target" in
	windows-*) exe=".exe" ;;
	esac
	for bin in ast astd; do
		[ -f "${unpack}/${bin}${exe}" ] || die "${artifact} has no ${bin}${exe} in it. Refusing to install a partial release."
	done
	# `astd-vz` is the Virtualization.framework helper, and it is not
	# required here the way `ast` and `astd` are: this script installs any
	# tag it is pointed at, and the tarballs cut before the helper shipped
	# do not contain one. Refusing those would make the current installer
	# unable to install half the releases it can name. So it is installed
	# when the release has it, and its absence is said out loud rather than
	# discovered later as "vz is unavailable on this machine".
	#
	# Windows releases instead ship `astd-hyperv`, and that helper *is*
	# required: a Windows tarball without it is not a supported artifact.
	if [ -f "${unpack}/astd-vz" ]; then
		vz=1
	else
		vz=0
	fi
	hyperv=0
	if [ -f "${unpack}/astd-hyperv${exe}" ]; then
		hyperv=1
	fi
	if [ "$target" != "${target#windows-}" ] && [ "$hyperv" != "1" ]; then
		die "${artifact} has no astd-hyperv${exe}. A Windows release without the helper is not installable."
	fi
	if [ -f "${unpack}/asterism-update${exe}" ]; then updater=1; else updater=0; fi
	if [ -f "${unpack}/asterism-update" ]; then updater_sh=1; else updater_sh=0; fi
	if [ -f "${unpack}/asterism-update.ps1" ]; then updater_ps1=1; else updater_ps1=0; fi
	if [ -f "${unpack}/install.ps1" ]; then installer_ps1=1; else installer_ps1=0; fi
	if [ "$target" != "${target#windows-}" ] && { [ "$updater_ps1" != "1" ] || [ "$installer_ps1" != "1" ]; }; then
		die "${artifact} must package asterism-update.ps1 and install.ps1 together. Refusing a Windows updater that cannot apply."
	fi
	case "$target" in
	linux-*)
		for helper in cloud-hypervisor virtiofsd; do
			[ -f "${unpack}/${helper}" ] || die "${artifact} has no ${helper}. Refusing to install a Linux release without its pinned native backend."
		done
		[ -f "${unpack}/share/asterism/asterism-nbd" ] || die "${artifact} has no checked NBD privilege wrapper. Refusing a partial Linux runtime."
		[ -x "${unpack}/guest-gpu/bin/asterism-gpu-guest" ] || die "${artifact} has no Linux guest GPU service. Refusing an unprojectable GPU runtime."
		[ -f "${unpack}/guest-gpu/lib/libcuda.so.1.0.0" ] || die "${artifact} has no generated guest libcuda. Refusing an unprojectable GPU runtime."
		linux_helpers=1
		;;
	*) linux_helpers=0 ;;
	esac
	receipt_files="bin/ast${exe} bin/astd${exe}"
	if [ "$vz" = "1" ]; then
		receipt_files="${receipt_files} bin/astd-vz"
	elif [ "$linux_helpers" = "1" ]; then
		receipt_files="${receipt_files} bin/cloud-hypervisor bin/virtiofsd $(linux_guest_files) share/asterism/linux-components.env share/asterism/asterism-nbd share/asterism/licenses/cloud-hypervisor-Apache-2.0.txt share/asterism/licenses/cloud-hypervisor-BSD-3-Clause.txt share/asterism/licenses/virtiofsd-Apache-2.0.txt share/asterism/licenses/virtiofsd-BSD-3-Clause.txt share/asterism/licenses/LICENSE-APACHE share/asterism/licenses/LICENSE-MIT share/asterism/licenses/NOTICE"
	fi
	if [ "$hyperv" = "1" ]; then
		receipt_files="${receipt_files} bin/astd-hyperv${exe}"
	fi
	if [ "$updater" = "1" ]; then
		receipt_files="${receipt_files} libexec/asterism/asterism-update${exe}"
	elif [ "$updater_sh" = "1" ]; then
		receipt_files="${receipt_files} libexec/asterism/asterism-update"
	fi
	if [ "$updater_ps1" = "1" ]; then
		receipt_files="${receipt_files} libexec/asterism/asterism-update.ps1"
	fi
	if [ "$installer_ps1" = "1" ]; then
		receipt_files="${receipt_files} libexec/asterism/install.ps1"
	fi
	if [ "$linux_helpers" = "1" ]; then
		intent_system_files="$(linux_system_files)"
	else
		intent_system_files=""
	fi
	# This journal is durable before `place` or any root-side configuration.
	write_install_intent "$version" "$target" release "$got" "$intent_system_files" "$receipt_files"

	ensure_writable_prefix
	place "${unpack}/ast${exe}" "ast${exe}"
	place "${unpack}/astd${exe}" "astd${exe}"
	if [ "$linux_helpers" = "1" ]; then
		place "${unpack}/cloud-hypervisor" cloud-hypervisor
		place "${unpack}/virtiofsd" virtiofsd
		place_linux_guest "${unpack}/guest-gpu"
		if [ -d "${unpack}/share/asterism" ]; then
			mkdir -p "${PREFIX}/share/asterism"
			cp -R "${unpack}/share/asterism/." "${PREFIX}/share/asterism/"
		fi
		configure_chv_linux "${unpack}/share/asterism/asterism-nbd"
	fi
	if [ "$vz" = "1" ]; then
		[ "$linux_helpers" = "1" ] || drop_stale_linux_helpers
		place "${unpack}/astd-vz" astd-vz
		unquarantine "${PREFIX}/bin/ast" "${PREFIX}/bin/astd" "${PREFIX}/bin/astd-vz"
	elif [ "$linux_helpers" = "1" ]; then
		drop_stale_helper
	else
		drop_stale_linux_helpers
		unquarantine "${PREFIX}/bin/ast${exe}" "${PREFIX}/bin/astd${exe}"
		drop_stale_helper
	fi
	if [ "$hyperv" = "1" ]; then
		place "${unpack}/astd-hyperv${exe}" "astd-hyperv${exe}"
		verify_windows_authenticode "${PREFIX}/bin/ast${exe}" "${PREFIX}/bin/astd${exe}" "${PREFIX}/bin/astd-hyperv${exe}"
	fi
	if [ "$updater" = "1" ]; then
		place_at "${unpack}/asterism-update${exe}" "libexec/asterism/asterism-update${exe}"
	elif [ "$updater_sh" = "1" ]; then
		place_at "${unpack}/asterism-update" libexec/asterism/asterism-update
	fi
	if [ "$updater_ps1" = "1" ]; then
		place_at "${unpack}/asterism-update.ps1" libexec/asterism/asterism-update.ps1
	fi
	if [ "$installer_ps1" = "1" ]; then
		place_at "${unpack}/install.ps1" libexec/asterism/install.ps1
	fi
	# shellcheck disable=SC2086
	write_receipt "$version" "$target" release "$got" $receipt_files

	if [ "$installed" != "" ] && [ "$installed" != "$version" ]; then
		say "upgraded ${installed} -> ${version}"
	fi
	note_vz "$vz"
	if [ "$linux_helpers" = "1" ]; then note_chv; note_linger; else note_qemu; fi
	note_path
}

# ---- the escape hatch: build the source ------------------------------------

# The only place a moving branch can enter, and only when asked for by name.
# With no ASTERISM_REF this still builds a tag, so "build it yourself" does
# not quietly mean "build whatever main is this afternoon".
install_source() {
	if [ -n "$REF" ]; then
		ref="$REF"
		say "building from ${ref} — a git ref, not a release: what you get depends on when you run this"
	else
		ref="$(resolve_version)"
		say "building from ${ref}"
	fi

	have git || die "git is required to build from source. Install git and re-run."
	if ! have cargo; then
		err "Rust is required to build from source, and cargo is not on PATH."
		err ""
		err "Install Rust the way rustup documents, then re-run this script:"
		err ""
		err "    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs -o rustup-init.sh"
		err "    sh rustup-init.sh"
		err ""
		exit 1
	fi
	src="${XDG_CACHE_HOME:-${HOME}/.cache}/asterism/src"
	if [ -d "${src}/.git" ]; then
		say "updating ${src} to ${ref}"
		git -C "$src" fetch --depth 1 origin "$ref"
		git -C "$src" checkout --detach FETCH_HEAD
	else
		say "cloning ${REPO_URL} into ${src} at ${ref}"
		mkdir -p "$(dirname "$src")"
		rm -rf "$src"
		git clone --depth 1 --branch "$ref" "$REPO_URL" "$src"
	fi

	say "cargo build --release --locked (a few minutes)"
	(cd "$src" && cargo build --release --locked \
		--package asterism-cli --package asterism-daemon)
	linux_helpers=0
	if [ "$(uname -s)" = "Linux" ]; then
		# The destination is installer-owned and absolute. Never derive a copy
		# root from build output: an empty line would otherwise collapse the
		# service source to /bin/asterism-gpu-guest. Build and validate the exact
		# checked-out ref before prepare_chv_source performs any root mutation.
		guest_artifacts="${TMPDIR_SELF}/guest-gpu"
		"${src}/scripts/build-guest-gpu-artifacts.sh" "$guest_artifacts"
		validate_linux_guest_artifacts "$guest_artifacts"
		prepare_chv_source "$src"
		linux_helpers=1
	fi

	# The vz helper is built by the script in the tree that knows how to
	# sign it, because building it is not enough: an unsigned helper carries
	# no virtualization entitlement, and VZ refuses to create a machine in a
	# process without one. That script is the same one a release build runs,
	# so a source install lands the same entitled helper a release does.
	vz=0
	if [ "$(uname -s)" = "Darwin" ]; then
		if [ -x "${src}/scripts/sign-vz.sh" ]; then
			say "building and signing astd-vz, the Virtualization.framework helper"
			"${src}/scripts/sign-vz.sh" --release ||
				die "astd-vz could not be built and signed. Nothing was installed."
			vz=1
		else
			say "this tree has no scripts/sign-vz.sh, so no vz helper was built — the qemu backend still works"
		fi
	fi
	if [ "$vz" = "1" ]; then
		intent_files="bin/ast bin/astd bin/astd-vz libexec/asterism/asterism-update"
	elif [ "$linux_helpers" = "1" ]; then
		intent_files="bin/ast bin/astd bin/cloud-hypervisor bin/virtiofsd libexec/asterism/asterism-update $(linux_guest_files)"
	else
		intent_files="bin/ast bin/astd libexec/asterism/asterism-update"
	fi
	if [ "$linux_helpers" = "1" ]; then
		intent_system_files="$(linux_system_files)"
	else
		intent_system_files=""
	fi
	write_install_intent "$ref" source source "" "$intent_system_files" "$intent_files"

	ensure_writable_prefix
	# ast finds astd as a sibling, and astd finds astd-vz the same way, so
	# they install together.
	place "${src}/target/release/ast" ast
	place "${src}/target/release/astd" astd
	place_at "${src}/packaging/update.sh" libexec/asterism/asterism-update
	if [ "$linux_helpers" = "1" ]; then
		place "$CHV_SOURCE_BIN" cloud-hypervisor
		place "$VIRTIOFSD_SOURCE_BIN" virtiofsd
		place_linux_guest "$guest_artifacts"
		configure_chv_linux "${src}/packaging/asterism-nbd"
	fi
	if [ "$vz" = "1" ]; then
		place "${src}/target/release/astd-vz" astd-vz
		write_receipt "$ref" "source" source "" bin/ast bin/astd bin/astd-vz libexec/asterism/asterism-update
	elif [ "$linux_helpers" = "1" ]; then
		drop_stale_helper
		write_receipt "$ref" "source" source "" \
			bin/ast bin/astd bin/cloud-hypervisor bin/virtiofsd \
			libexec/asterism/asterism-update \
			bin/guest-gpu/bin/asterism-gpu-guest \
			bin/guest-gpu/lib/libcuda.so.1.0.0 \
			bin/guest-gpu/lib/libcuda.so.1 bin/guest-gpu/lib/libcuda.so
	else
		drop_stale_helper
		write_receipt "$ref" "source" source "" bin/ast bin/astd libexec/asterism/asterism-update
	fi
	note_vz "$vz"
	if [ "$linux_helpers" = "1" ]; then note_chv; note_linger; else note_qemu; fi
	note_path
}

prepare_chv_source() {
	source_root="$1"
	# This is data from the checked-out tag/ref, not code from the network.
	# shellcheck disable=SC1090,SC1091
	. "${source_root}/packaging/linux-components.env"
	# Building the pinned virtiofsd source needs only these two native
	# development libraries. Install them before spending time compiling so
	# the source lane either has its complete declared toolchain or refuses
	# without leaving a half-built runtime.
	if ! have pkg-config || ! pkg-config --exists libseccomp libcap-ng; then
		if have apt-get; then
			run_root apt-get update
			run_root apt-get install -y pkg-config libseccomp-dev libcap-ng-dev
		elif have dnf; then
			run_root dnf install -y pkgconf-pkg-config libseccomp-devel libcap-ng-devel
		elif have zypper; then
			run_root zypper --non-interactive install pkg-config libseccomp-devel libcap-ng-devel
		else
			die "building the pinned virtiofsd needs pkg-config, libseccomp, and libcap-ng development files"
		fi
	fi
	if ! have pkg-config || ! pkg-config --exists libseccomp libcap-ng; then
		die "the package manager completed but virtiofsd's libseccomp/libcap-ng build inputs are unavailable"
	fi
	case "$(uname -m)" in
	x86_64 | amd64)
		chv_url="$CLOUD_HYPERVISOR_X86_64_URL"
		chv_sha="$CLOUD_HYPERVISOR_X86_64_SHA256"
		;;
	aarch64 | arm64)
		chv_url="$CLOUD_HYPERVISOR_AARCH64_URL"
		chv_sha="$CLOUD_HYPERVISOR_AARCH64_SHA256"
		;;
	*) die "Cloud Hypervisor has no pinned helper for $(uname -m)" ;;
	esac
	CHV_SOURCE_BIN="${TMPDIR_SELF}/cloud-hypervisor"
	fetch "$chv_url" "$CHV_SOURCE_BIN" || die "could not download pinned Cloud Hypervisor"
	[ "$(sha256_of "$CHV_SOURCE_BIN")" = "$chv_sha" ] || die "pinned Cloud Hypervisor digest mismatch"
	chmod 0755 "$CHV_SOURCE_BIN"

	virtio_tar="${TMPDIR_SELF}/virtiofsd.tar.gz"
	fetch "$VIRTIOFSD_TARBALL" "$virtio_tar" || die "could not download pinned virtiofsd source"
	[ "$(sha256_of "$virtio_tar")" = "$VIRTIOFSD_TARBALL_SHA256" ] || die "pinned virtiofsd source digest mismatch"
	tar -xzf "$virtio_tar" -C "$TMPDIR_SELF"
	virtio_target="${TMPDIR_SELF}/virtiofsd-target"
	CARGO_TARGET_DIR="$virtio_target" cargo build --release --locked \
		--manifest-path "${TMPDIR_SELF}/virtiofsd-${VIRTIOFSD_VERSION}/Cargo.toml"
	VIRTIOFSD_SOURCE_BIN="${virtio_target}/release/virtiofsd"
}

# Grant only what the bundled VMM needs to create its per-instance TAP. KVM
# itself remains protected by /dev/kvm ownership; this does not bypass it.
configure_chv_linux() {
	nbd_helper_source="$1"
	[ "$(uname -s)" = "Linux" ] || return 0

	# The native container adapter preserves the uid/gid model carried by an
	# OCI image. `--map-root-user` alone maps one ID and breaks as soon as a
	# service switches to (for example) nginx uid 101. Install the standard
	# subordinate-ID helpers and the remaining namespace tools together; the
	# daemon probe still fails closed when this account has no /etc/subuid or
	# /etc/subgid range.
	if ! have newuidmap || ! have newgidmap || ! have slirp4netns || \
	   ! have debugfs || ! have ip || ! have unshare; then
		if have apt-get; then
			run_root apt-get install -y uidmap slirp4netns e2fsprogs iproute2 util-linux
		elif have dnf; then
			run_root dnf install -y shadow-utils slirp4netns e2fsprogs iproute util-linux
		elif have zypper; then
			run_root zypper --non-interactive install shadow slirp4netns e2fsprogs iproute2 util-linux
		else
			die "native containers need uidmap, slirp4netns, e2fsprogs, iproute2 and util-linux; install them, then re-run."
		fi
	fi
	for command in newuidmap newgidmap slirp4netns debugfs ip unshare; do
		have "$command" || die "the package manager completed but ${command} is still unavailable"
	done

	# nbd-client is named nbd-client on Debian/Ubuntu and nbd on Fedora/RHEL.
	# kmod provides modprobe on both families. Install only when the host does
	# not already carry the required command, so an existing administrator-
	# managed package remains authoritative.
	if ! have nbd-client || ! have modprobe; then
		if have apt-get; then
			run_root apt-get install -y nbd-client kmod
		elif have dnf; then
			run_root dnf install -y nbd kmod
		elif have zypper; then
			run_root zypper --non-interactive install nbd kmod
		else
			die "remote block volumes need nbd-client and modprobe; install the nbd and kmod packages, then re-run."
		fi
	fi
	have nbd-client || die "the package manager completed but nbd-client is still unavailable"
	have modprobe || die "the package manager completed but modprobe is still unavailable"

	modules_load="${TMPDIR_SELF}/asterism-nbd.modules-load"
	modprobe_options="${TMPDIR_SELF}/asterism-nbd.modprobe"
	printf 'nbd\n' >"$modules_load"
	printf 'options nbd nbds_max=64\n' >"$modprobe_options"
	run_root install -d -m 0755 "${SYSTEM_ROOT}/etc/modules-load.d" "${SYSTEM_ROOT}/etc/modprobe.d"
	run_root install -m 0644 "$modules_load" "${SYSTEM_ROOT}/etc/modules-load.d/asterism-nbd.conf"
	run_root install -m 0644 "$modprobe_options" "${SYSTEM_ROOT}/etc/modprobe.d/asterism-nbd.conf"
	run_root modprobe nbd nbds_max=64

	# The root-only helper owns the host-wide flock boundary for
	# check/claim/attach/owner-capture. The daemon must not be able to write or
	# replace either the lock or the ownership claims.
	run_root install -d -m 0755 "${SYSTEM_ROOT}/run/lock"
	# Preserve the lock inode across upgrades; replacing it would let an
	# in-flight helper and the next helper believe they hold different locks.
	run_root touch "${SYSTEM_ROOT}/run/lock/asterism-nbd.lock"
	run_root chown root:root "${SYSTEM_ROOT}/run/lock/asterism-nbd.lock"
	run_root chmod 0600 "${SYSTEM_ROOT}/run/lock/asterism-nbd.lock"
	run_root install -d -m 0700 "${SYSTEM_ROOT}/run/asterism-nbd"

	# The daemon never gets general nbd-client access. It may invoke only this
	# root-owned argument-checking wrapper, and only without an environment-
	# supplied command path.
	nbd_helper="${SYSTEM_ROOT}/usr/local/libexec/asterism/asterism-nbd"
	run_root install -d -m 0755 "$(dirname "$nbd_helper")"
	run_root install -m 0755 "$nbd_helper_source" "$nbd_helper"
	nbd_user="$(id -un)"
	case "$nbd_user" in *[!A-Za-z0-9_.-]*) die "cannot safely write sudoers policy for account ${nbd_user}" ;; esac
	if ! have setcap; then
		if have apt-get; then
			run_root apt-get install -y libcap2-bin
		elif have dnf; then
			run_root dnf install -y libcap
		else
			die "setcap is required to configure Cloud Hypervisor networking (install libcap, then re-run)."
		fi
	fi
	run_root setcap cap_net_admin+ep "${PREFIX}/bin/cloud-hypervisor"
	setcap_bin=$(command -v setcap) || die "setcap disappeared while configuring Cloud Hypervisor"
	sudoers="${TMPDIR_SELF}/asterism-nbd.sudoers"
	printf '%s ALL=(root) NOPASSWD: %s\n' "$nbd_user" "$nbd_helper" >"$sudoers"
	# The updater replaces the CHV inode transactionally, so Linux drops the
	# file capability with the old inode. Permit only restoring this one
	# capability on this one installed path; rollback itself restores the old
	# capable inode from the transaction backup.
	printf '%s ALL=(root) NOPASSWD: %s cap_net_admin+ep %s\n' \
		"$nbd_user" "$setcap_bin" "${PREFIX}/bin/cloud-hypervisor" >>"$sudoers"
	have visudo || die "visudo is required to validate Asterism's least-privilege NBD policy"
	run_root visudo -cf "$sudoers"
	run_root install -d -m 0750 "${SYSTEM_ROOT}/etc/sudoers.d"
	run_root install -m 0440 "$sudoers" "${SYSTEM_ROOT}/etc/sudoers.d/asterism-nbd-$(id -u)"
	if [ ! -r /dev/kvm ] || [ ! -w /dev/kvm ]; then
		err "/dev/kvm is not read-write for this user. Add the user to the kvm group and log in again before starting an instance."
	fi
}

remove_chv_linux_policy() {
	[ "$(uname -s)" = "Linux" ] || return 0
	policy="${SYSTEM_ROOT}/etc/sudoers.d/asterism-nbd-$(id -u)"
	run_root rm -f "$policy"
	say "removed ${policy}"
}

note_chv() {
	say "Linux instances default to bundled Cloud Hypervisor v53.0 over KVM."
	say "QEMU is used only when selected explicitly as a compatibility backend."
	say "next: ast service install   # persist astd across login"
	say "      ast doctor            # linger, KVM, Secret Service, helpers"
}

note_linger() {
	[ "$(uname -s)" = "Linux" ] || return 0
	user="$(id -un 2>/dev/null || printf '%s' "$USER")"
	if have loginctl; then
		linger="$(loginctl show-user "$user" -p Linger 2>/dev/null || true)"
		case "$linger" in
		Linger=yes)
			say "lingering is on: astd survives logout and starts at boot."
			return 0
			;;
		esac
	fi
	say "astd is a systemd --user unit. It dies at logout unless lingering is on:"
	say "    loginctl enable-linger ${user}"
}

# ---- Homebrew --------------------------------------------------------------

find_brew() {
	for candidate in brew /opt/homebrew/bin/brew /usr/local/bin/brew; do
		if have "$candidate"; then
			printf '%s' "$candidate"
			return 0
		fi
	done
	return 1
}

no_homebrew() {
	err "ASTERISM_METHOD=brew, and Homebrew is not here."
	err ""
	err "Install it with the command Homebrew publishes, then re-run this script:"
	err ""
	err "    /bin/bash -c \"\$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)\""
	err ""
	err "We will not install Homebrew for you. What owns /opt/homebrew on your"
	err "machine is your decision, not ours. Or drop the method and take the"
	err "release binary instead:  curl -fsSL https://asterism.run/install.sh | sh"
	exit 1
}

# Homebrew only installs formulae that live in a tap — a loose .rb file or a
# raw URL is rejected outright — so an install through Homebrew is really a
# question of which tap, holding which formula.
#
# The formula in the repository is HEAD-only, so a plain `brew install` of it
# has no stable version to resolve and fails. The one published with the
# release has the tag and its digest rendered in, and is listed in that
# release's SHA256SUMS like every other artifact — so that is the one
# fetched, and it is checksummed before Homebrew is pointed at it. The
# repository copy is only ever used for an explicitly requested HEAD.
STAMP_NAME=".asterism-local-tap"

# Fetch the formula for one version into $2, verified.
fetch_release_formula() {
	version="$1" dest="$2"

	if [ -n "$REF" ]; then
		formula_url="https://raw.githubusercontent.com/${REPO}/${REF}/packaging/asterism.rb"
		say "fetching ${formula_url}"
		fetch "$formula_url" "$dest" ||
			die "could not fetch the formula from ${formula_url}"
		return 0
	fi

	formula_url="${BASE_URL}/${version}/asterism.rb"
	say "fetching ${formula_url}"
	fetch "$formula_url" "$dest" ||
		die "could not fetch the release formula from ${formula_url}. Refusing to fall back to the moving branch."
	sums="${TMPDIR_SELF}/SHA256SUMS.brew"
	fetch "${BASE_URL}/${version}/SHA256SUMS" "$sums" 2>/dev/null ||
		die "could not download SHA256SUMS for ${version}. Refusing to install an unverified formula."
	want="$(expected_digest "$sums" asterism.rb)"
	got="$(sha256_of "$dest")"
	[ "$got" = "$want" ] ||
		die "checksum mismatch on asterism.rb: expected ${want}, got ${got}. Refusing."
	say "sha256 ok: ${got}"
}

# Does this formula's stable url name this tag?
formula_pins() {
	grep -q "/tags/${2}\.tar\.gz" "$1" 2>/dev/null
}

# Stand up, or refresh, a tap this script owns, holding the release formula
# for one version. The stamp records what it was built for: a tap built for
# v0.1.0 reused when v0.2.0 is the version being installed would have
# Homebrew install v0.1.0 again, which is the stale resolution this whole
# script exists to prevent. A ref is never cached — a branch moves.
build_local_tap() {
	brew_bin="$1" tap="$2" want_stamp="$3" version="$4"

	if ! "$brew_bin" tap | grep -qx "$tap"; then
		# A failed tap can leave the directory behind; clear it before
		# creating the local one, or tap-new refuses.
		"$brew_bin" untap "$tap" >/dev/null 2>&1 || true
		say "building a local tap ${tap} for ${want_stamp}"
		"$brew_bin" tap-new --no-git "$tap" >/dev/null
	fi

	dir="$("$brew_bin" --repository "$tap")"
	formula="${dir}/Formula/asterism.rb"
	stamp="${dir}/${STAMP_NAME}"

	# Belt and braces: this function only ever writes into taps this script
	# stamped, and it says so rather than clobbering someone else's file.
	if [ -f "$formula" ] && [ ! -f "$stamp" ]; then
		die "${formula} was not written by this script. Refusing to overwrite it."
	fi
	if [ -f "$formula" ] && [ -f "$stamp" ] && [ -z "$REF" ] &&
		[ "$(cat "$stamp")" = "$want_stamp" ]; then
		return 0
	fi
	if [ -f "$stamp" ]; then
		say "${tap} holds $(cat "$stamp") — refreshing it for ${want_stamp}"
	fi

	staged="${TMPDIR_SELF}/asterism.rb"
	fetch_release_formula "$version" "$staged"
	mkdir -p "${dir}/Formula"
	cp "$staged" "$formula"
	printf '%s\n' "$want_stamp" >"$stamp"
	say "wrote ${formula}"
}

# Decide which tap the install comes from, and leave $SELECTED_TAP naming it.
#
# A published tap is the distributor of record: Homebrew keeps it current and
# this script never writes to it. But a published tap pins one version, and a
# user who named another one is owed that version, not the tap's. When the
# two disagree the install comes from a second tap this script owns and
# stamps — and the published tap is left exactly as it was found.
select_tap() {
	brew_bin="$1" version="$2"

	if [ -n "$REF" ]; then
		build_local_tap "$brew_bin" "$TAP" "head:${REF}" "$version"
		SELECTED_TAP="$TAP"
		return 0
	fi

	# Tap the published tap if it exists and is not tapped yet; it may well
	# be the one that pins what was asked for.
	if ! "$brew_bin" tap | grep -qx "$TAP"; then
		if "$brew_bin" tap "$TAP" 2>/dev/null; then
			say "tapped ${TAP}"
		fi
	fi

	if "$brew_bin" tap | grep -qx "$TAP"; then
		dir="$("$brew_bin" --repository "$TAP")"
		formula="${dir}/Formula/asterism.rb"
		if [ -f "$formula" ] && [ ! -f "${dir}/${STAMP_NAME}" ]; then
			if formula_pins "$formula" "$version"; then
				say "${TAP} is a published tap and pins ${version}"
				SELECTED_TAP="$TAP"
				return 0
			fi
			say "${TAP} is a published tap and does not pin ${version} — leaving it untouched"
			say "installing ${version} from ${PIN_TAP} instead, a tap this script owns"
			build_local_tap "$brew_bin" "$PIN_TAP" "$version" "$version"
			SELECTED_TAP="$PIN_TAP"
			return 0
		fi
	fi

	build_local_tap "$brew_bin" "$TAP" "$version" "$version"
	SELECTED_TAP="$TAP"
}

# QEMU arrives as a formula dependency: Homebrew builds and ships it, we only
# declare it. Asterism never bundles QEMU.
install_brew() {
	brew_bin="$(find_brew)" || no_homebrew

	if [ -n "$REF" ]; then
		version="$REF"
		say "${REF} is a git ref, not a release — Homebrew gets --HEAD"
	else
		version="$(resolve_version)"
		say "release ${version} through Homebrew"
	fi

	# The tap is settled before anything is decided, because what Homebrew
	# resolves is whatever the formula in the tap says. Reading the installed
	# version first and deciding against a stale formula is how a machine
	# ends up pinned to whichever release it happened to see first.
	select_tap "$brew_bin" "$version"
	formula_ref="${SELECTED_TAP}/asterism"

	installed="$("$brew_bin" list --formula --versions asterism 2>/dev/null |
		head -n 1 | awk '{ print $2 }')"

	if [ -n "$REF" ]; then
		replace_brew_install "$brew_bin" "$installed" "$formula_ref" --HEAD
		return 0
	fi

	if [ -z "$installed" ]; then
		say "brew install ${formula_ref}"
		"$brew_bin" install "$formula_ref"
		return 0
	fi

	if [ "$installed" = "${version#v}" ] && [ "$FORCE" != "1" ]; then
		say "already installed by Homebrew: asterism ${installed}"
		say "re-run with ASTERISM_FORCE=1 to reinstall it, or ASTERISM_VERSION to move to another."
		return 0
	fi

	if [ "$installed" != "${version#v}" ]; then
		say "moving ${installed} -> ${version#v}"
	fi
	replace_brew_install "$brew_bin" "$installed" "$formula_ref"
}

# Uninstall then install, rather than `brew reinstall`: the formula being
# installed can live in a different tap from the one the installed copy came
# from, and reinstall reinstalls what is already there. Uninstalling first
# makes the tap that wins unambiguous, and works the same going backwards
# between versions as forwards — `brew upgrade` does not.
replace_brew_install() {
	brew_bin="$1" installed="$2" formula_ref="$3"
	shift 3

	if [ -n "$installed" ]; then
		say "brew uninstall asterism"
		"$brew_bin" uninstall asterism
	fi
	if [ $# -gt 0 ]; then
		say "brew install $* ${formula_ref}"
	else
		say "brew install ${formula_ref}"
	fi
	"$brew_bin" install "$@" "$formula_ref"
}

# ---- uninstall -------------------------------------------------------------

# Removes the files the receipt names and nothing else. No globbing over the
# prefix, no rm -rf of a directory this script does not own, and instance
# state is left alone and said out loud.
uninstall() {
	r="$(receipt_path)"
	if [ ! -f "$r" ]; then
		err "no install receipt at ${r} — nothing to uninstall from ${PREFIX}."
		err "If Asterism came from Homebrew, remove it with:  brew uninstall asterism"
		exit 1
	fi
	files="$(receipt_field files || true)"
	[ -n "$files" ] || die "the receipt at ${r} lists no files. Refusing to guess what to delete."
	version="$(receipt_field version || true)"
	target="$(receipt_field target || true)"
	method="$(receipt_field method || true)"
	sha="$(receipt_field sha256 || true)"
	system_files="$(receipt_field system_files || true)"
	if [ -z "$system_files" ] && receipt_lists bin/cloud-hypervisor; then
		system_files="$(linux_system_files)"
	fi
	if live_nbd_claims; then
		if ! drain_own_nbd_claims || live_nbd_claims; then
			err "live NBD claims remain under $(nbd_state_dir)."
			err "refusing to uninstall: the NBD helper and sudoers cleanup authority were kept so the attachment can still be detached."
			exit 1
		fi
	fi
	# Preserve the only ownership manifest until every deletion has completed.
	write_receipt_document "$r" uninstalling "$version" "$target" "$method" "$sha" "$files" "$system_files"
	remove_receipt_system_files
	remove_receipt_files
	retire_receipt
	say "removed ${r}"
	# Only if empty: someone else's files are not ours to sweep up.
	rmdir "${PREFIX}/share/asterism/licenses" 2>/dev/null || true
	rmdir "${PREFIX}/share/asterism" 2>/dev/null || true
	rmdir "${PREFIX}/libexec/asterism" 2>/dev/null || true

	say "instance state in ${ASTERISM_HOME:-${HOME}/.asterism} was left alone."
	say "delete it by hand if you want it gone."
}

# ---- notes -----------------------------------------------------------------

# What the machine can actually run, said at install time rather than left
# for `ast create --backend vz` to discover.
verify_windows_authenticode() {
	# Optional: a pinned thumbprint turns "unsigned" into a refusal. A
	# Windows Git Bash install without Authenticode tools still checksums.
	[ -n "${ASTERISM_AUTHENTICODE_THUMBPRINT:-}" ] || return 0
	have powershell.exe || have pwsh || die "ASTERISM_AUTHENTICODE_THUMBPRINT is set but PowerShell is not on PATH."
	ps=powershell.exe
	have pwsh && ps=pwsh
	for f in "$@"; do
		[ -f "$f" ] || continue
		status="$($ps -NoProfile -Command "try { (Get-AuthenticodeSignature -FilePath '$f').Status.ToString() } catch { 'Missing' }")"
		thumb="$($ps -NoProfile -Command "try { (Get-AuthenticodeSignature -FilePath '$f').SignerCertificate.Thumbprint } catch { '' }")"
		case "$status" in
		Valid) ;;
		*) die "${f} Authenticode status is ${status}, not Valid. Refusing to install." ;;
		esac
		want="$(printf '%s' "$ASTERISM_AUTHENTICODE_THUMBPRINT" | tr '[:upper:]' '[:lower:]')"
		got="$(printf '%s' "$thumb" | tr '[:upper:]' '[:lower:]')"
		[ "$want" = "$got" ] || die "${f} is signed by ${thumb}, not the pinned thumbprint."
		say "authenticode ok: ${f}"
	done
}

note_vz() {
	# $1: 1 if a helper was installed
	if is_windows_uname 2>/dev/null; then
		say ""
		say "Windows persistence is a Windows Service. After install:"
		say "    ast doctor"
		say "    ast service install"
		return 0
	fi
	[ "$(uname -s)" = "Darwin" ] || return 0
	if [ "$1" != "1" ]; then
		say ""
		if [ "$METHOD" = "release" ]; then
			say "This release ships no astd-vz, so Virtualization.framework is not"
			say "available and Asterism will use the QEMU backend. A newer release, or"
			say "ASTERISM_METHOD=source, builds and signs the helper."
		else
			say "No astd-vz was installed, so Virtualization.framework is not"
			say "available and Asterism will use the QEMU backend."
		fi
		return 0
	fi
	have codesign || return 0
	if codesign -d --entitlements - "${PREFIX}/bin/astd-vz" 2>&1 |
		grep -q 'com.apple.security.virtualization' &&
		codesign --verify --strict "${PREFIX}/bin/astd-vz" >/dev/null 2>&1; then
		return 0
	fi
	say ""
	say "astd-vz is installed but its signature does not carry the virtualization"
	say "entitlement, so Virtualization.framework will refuse it and Asterism will"
	say "fall back to the QEMU backend. Re-run with ASTERISM_FORCE=1; if it stays"
	say "this way, the release itself is at fault — please report it."
}

note_qemu() {
	have qemu-system-aarch64 && return 0
	have qemu-system-x86_64 && return 0
	[ "$(uname -s)" = "Darwin" ] || return 0
	say ""
	say "QEMU is not installed. Asterism uses Virtualization.framework where it"
	say "can and QEMU where it cannot, so install it when you need the QEMU"
	say "backend:  brew install qemu"
}

note_path() {
	case ":${PATH}:" in
	*":${PREFIX}/bin:"*) ;;
	*)
		say ""
		say "${PREFIX}/bin is not on your PATH. Add it:"
		say "    export PATH=\"${PREFIX}/bin:\$PATH\""
		;;
	esac
}

# ---- entry -----------------------------------------------------------------

usage() {
	# Under `curl | sh` there is no file at $0 to read the header out of, so
	# say the short version rather than printing whatever $0 happens to be.
	if [ -r "$0" ] && head -n 1 "$0" | grep -q '^#!/bin/sh'; then
		# From the line after the shebang to the last comment line of the
		# header, however long that header grows.
		awk 'NR > 1 { if ($0 !~ /^#/) exit; sub(/^# ?/, ""); print }' "$0"
	else
		printf 'asterism installer: installs the latest tagged release into ~/.local/bin.\n'
		printf '  ASTERISM_VERSION=vX.Y.Z   install exactly that tag\n'
		printf '  ASTERISM_METHOD=source    build a tag from source instead\n'
		printf '  ASTERISM_PREFIX=DIR       install somewhere else\n'
		printf '  --uninstall               remove what a previous run installed\n'
		printf 'Full documentation: https://github.com/%s/blob/main/packaging/README.md\n' "$REPO"
	fi
	exit "${1:-0}"
}

main() {
	action=install
	while [ $# -gt 0 ]; do
		case "$1" in
		--uninstall) action=uninstall ;;
		-h | --help) usage 0 ;;
		*) die "unknown argument: $1 (try --help)" ;;
		esac
		shift
	done

	TMPDIR_SELF="$(mktemp -d "${TMPDIR:-/tmp}/asterism-install.XXXXXX")"
	acquire_artifact_lock

	if [ "$action" = "uninstall" ]; then
		uninstall
		return 0
	fi
	if [ -f "$(receipt_path)" ]; then
		phase="$(receipt_field phase || true)"
		case "$phase" in
		installing | uninstalling)
			say "recovering interrupted ${phase%ing} transaction before installing"
			rollback_incomplete_install || die "could not converge the interrupted install; its receipt was kept for retry"
			;;
		esac
	fi

	case "$METHOD" in
	release) install_release ;;
	source) install_source ;;
	brew) install_brew ;;
	*) die "unknown ASTERISM_METHOD=${METHOD}. It is one of: release, source, brew." ;;
	esac

	if have ast; then
		say "done — $(ast --version 2>/dev/null || echo ast)"
		say "next:  ast images"
	else
		say "done. Open a new shell so ast lands on your PATH, then: ast images"
	fi
}

main "$@"
