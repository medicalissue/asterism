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
# code-signed helper that owns Virtualization.framework guests — without it
# on the machine, `--backend vz` has nothing to run and Asterism falls back
# to QEMU. The desktop app is a separate DMG — see
# https://asterism.run/download.
#
# Environment:
#   ASTERISM_VERSION=v0.1.0   install exactly this tag (default: latest release)
#   ASTERISM_METHOD=release   release (default) | source | brew
#   ASTERISM_PREFIX=DIR       install prefix (default: ~/.local)
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
cleanup() {
	[ -n "$TMPDIR_SELF" ] && rm -rf "$TMPDIR_SELF"
	return 0
}
trap cleanup EXIT INT HUP TERM

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
	err "Asterism publishes binaries for macOS on Apple silicon (darwin-arm64)"
	err "and Windows 11 Pro/Enterprise (windows-x86_64, windows-arm64)."
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
	mkdir -p "$(dirname "$r")"
	v="$1" t="$2" m="$3" s="$4"
	shift 4
	{
		printf '# Written by the Asterism installer. Uninstall reads it; do not edit.\n'
		printf 'version=%s\n' "$v"
		printf 'target=%s\n' "$t"
		printf 'method=%s\n' "$m"
		printf 'sha256=%s\n' "$s"
		printf 'files=%s\n' "$*"
	} >"$r"
	say "wrote ${r}"
}

# Is everything the receipt names still on the machine?
#
# "Already installed" is a claim about the machine, not about the receipt.
# A binary someone deleted, or one an interrupted upgrade never wrote,
# leaves the version field saying yes while the prefix says no.
receipt_complete() {
	files="$(receipt_field files || true)"
	[ -n "$files" ] || return 1
	for rel in $files; do
		[ -x "${PREFIX}/${rel}" ] || return 1
	done
	return 0
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

	ensure_writable_prefix
	place "${unpack}/ast${exe}" "ast${exe}"
	place "${unpack}/astd${exe}" "astd${exe}"
	receipt_files="bin/ast${exe} bin/astd${exe}"
	if [ "$vz" = "1" ]; then
		place "${unpack}/astd-vz" astd-vz
		receipt_files="${receipt_files} bin/astd-vz"
		unquarantine "${PREFIX}/bin/ast" "${PREFIX}/bin/astd" "${PREFIX}/bin/astd-vz"
	else
		unquarantine "${PREFIX}/bin/ast${exe}" "${PREFIX}/bin/astd${exe}"
		drop_stale_helper
	fi
	if [ "$hyperv" = "1" ]; then
		place "${unpack}/astd-hyperv${exe}" "astd-hyperv${exe}"
		receipt_files="${receipt_files} bin/astd-hyperv${exe}"
		verify_windows_authenticode "${PREFIX}/bin/ast${exe}" "${PREFIX}/bin/astd${exe}" "${PREFIX}/bin/astd-hyperv${exe}"
	fi
	if [ "$updater" = "1" ]; then
		place_at "${unpack}/asterism-update${exe}" "libexec/asterism/asterism-update${exe}"
		receipt_files="${receipt_files} libexec/asterism/asterism-update${exe}"
	elif [ "$updater_sh" = "1" ]; then
		place_at "${unpack}/asterism-update" libexec/asterism/asterism-update
		receipt_files="${receipt_files} libexec/asterism/asterism-update"
	fi
	if [ "$updater_ps1" = "1" ]; then
		place_at "${unpack}/asterism-update.ps1" libexec/asterism/asterism-update.ps1
		receipt_files="${receipt_files} libexec/asterism/asterism-update.ps1"
	fi
	if [ "$installer_ps1" = "1" ]; then
		place_at "${unpack}/install.ps1" libexec/asterism/install.ps1
		receipt_files="${receipt_files} libexec/asterism/install.ps1"
	fi
	# shellcheck disable=SC2086
	write_receipt "$version" "$target" release "$got" $receipt_files

	if [ "$installed" != "" ] && [ "$installed" != "$version" ]; then
		say "upgraded ${installed} -> ${version}"
	fi
	note_vz "$vz"
	note_qemu
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
	if [ "$(uname -s)" = "Linux" ]; then
		ensure_qemu_linux
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

	ensure_writable_prefix
	# ast finds astd as a sibling, and astd finds astd-vz the same way, so
	# they install together.
	place "${src}/target/release/ast" ast
	place "${src}/target/release/astd" astd
	place_at "${src}/packaging/update.sh" libexec/asterism/asterism-update
	if [ "$vz" = "1" ]; then
		place "${src}/target/release/astd-vz" astd-vz
		write_receipt "$ref" "source" source "" bin/ast bin/astd bin/astd-vz libexec/asterism/asterism-update
	else
		drop_stale_helper
		write_receipt "$ref" "source" source "" bin/ast bin/astd libexec/asterism/asterism-update
	fi
	note_vz "$vz"
	note_qemu
	note_path
}

# QEMU comes from the system package manager, with consent. Asterism never
# bundles QEMU — see the licensing notes in packaging/README.md.
ensure_qemu_linux() {
	if have qemu-system-x86_64 || have qemu-system-aarch64; then
		return 0
	fi
	say "QEMU is missing, and Asterism needs it to run virtual machines."
	if have apt-get; then
		run_root apt-get install -y qemu-system qemu-utils
	elif have dnf; then
		run_root dnf install -y qemu-kvm qemu-img
	else
		err "This script only knows apt and dnf."
		err "Install QEMU with your package manager, then re-run this script."
		exit 1
	fi
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

	for rel in $files; do
		f="${PREFIX}/${rel}"
		if [ -e "$f" ]; then
			rm -f "$f"
			say "removed ${f}"
		else
			say "already gone: ${f}"
		fi
	done
	rm -f "$r"
	say "removed ${r}"
	# Only if empty: someone else's files are not ours to sweep up.
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

	if [ "$action" = "uninstall" ]; then
		uninstall
		return 0
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
