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
# This is the CLI: `ast` and the `astd` daemon it starts. The desktop app is
# a separate DMG — see https://asterism.run/download.
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
PREFIX="${ASTERISM_PREFIX:-${HOME}/.local}"
ASSUME_YES="${ASTERISM_YES:-0}"
FORCE="${ASTERISM_FORCE:-0}"
REF="${ASTERISM_REF:-}"
TAP="${ASTERISM_TAP:-medicalissue/asterism}"
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
	*) return 1 ;;
	esac
}

unsupported_target() {
	err "no binary release for $(uname -s) $(uname -m)."
	err ""
	err "Asterism publishes binaries for macOS on Apple silicon (darwin-arm64)."
	err "Everything else builds from source, which needs Rust and a few minutes:"
	err ""
	err "    curl -fsSL https://asterism.run/install.sh | ASTERISM_METHOD=source sh"
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
	if [ "$installed" = "$version" ] && [ "$FORCE" != "1" ] &&
		[ -x "${PREFIX}/bin/ast" ] && [ -x "${PREFIX}/bin/astd" ]; then
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
	for bin in ast astd; do
		[ -f "${unpack}/${bin}" ] || die "${artifact} has no ${bin} in it. Refusing to install a partial release."
	done

	ensure_writable_prefix
	# Write beside the target and rename, so an upgrade never leaves a
	# half-written binary where a working one used to be — and so replacing
	# a running `astd` is a rename, not a truncation.
	for bin in ast astd; do
		staged="${PREFIX}/bin/.${bin}.new.$$"
		cp "${unpack}/${bin}" "$staged"
		chmod 755 "$staged"
		mv -f "$staged" "${PREFIX}/bin/${bin}"
		say "installed ${PREFIX}/bin/${bin}"
	done

	write_receipt "$version" "$target" release "$got" bin/ast bin/astd

	if [ "$installed" != "" ] && [ "$installed" != "$version" ]; then
		say "upgraded ${installed} -> ${version}"
	fi
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

	ensure_writable_prefix
	# ast finds astd as a sibling, so they install together.
	for bin in ast astd; do
		staged="${PREFIX}/bin/.${bin}.new.$$"
		cp "${src}/target/release/${bin}" "$staged"
		chmod 755 "$staged"
		mv -f "$staged" "${PREFIX}/bin/${bin}"
		say "installed ${PREFIX}/bin/${bin}"
	done

	write_receipt "$ref" "source" source "" bin/ast bin/astd
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
# raw URL is rejected outright. Use the published tap when it exists, and
# until it does, stand up a local tap holding this one formula.
#
# Which formula matters. The copy in the repository is HEAD-only, so a plain
# `brew install` of it has no stable version to resolve and fails. The one
# published with the release has the tag and its digest rendered in, and is
# listed in that release's SHA256SUMS like every other artifact — so that is
# the one fetched, and it is checksummed before Homebrew is pointed at it.
# The repository copy is only ever used for an explicitly requested HEAD.
ensure_tap() {
	brew_bin="$1" version="$2"

	if ! "$brew_bin" tap | grep -qx "$TAP"; then
		if "$brew_bin" tap "$TAP" 2>/dev/null; then
			say "tapped ${TAP}"
			return 0
		fi
		# A failed tap can leave the directory behind; clear it before
		# creating the local one, or tap-new refuses.
		"$brew_bin" untap "$TAP" >/dev/null 2>&1 || true
		say "${TAP} is not published yet — building a local tap from ${version}"
		"$brew_bin" tap-new --no-git "$TAP" >/dev/null
	fi

	tapdir="$("$brew_bin" --repository "$TAP")"
	if [ -f "${tapdir}/Formula/asterism.rb" ]; then
		return 0
	fi
	mkdir -p "${tapdir}/Formula"
	staged="${TMPDIR_SELF}/asterism.rb"

	if [ -n "$REF" ]; then
		formula_url="https://raw.githubusercontent.com/${REPO}/${REF}/packaging/asterism.rb"
		say "fetching ${formula_url}"
		fetch "$formula_url" "$staged" ||
			die "could not fetch the formula from ${formula_url}"
	else
		formula_url="${BASE_URL}/${version}/asterism.rb"
		say "fetching ${formula_url}"
		fetch "$formula_url" "$staged" ||
			die "could not fetch the release formula from ${formula_url}. Refusing to fall back to the moving branch."
		sums="${TMPDIR_SELF}/SHA256SUMS.brew"
		if fetch "${BASE_URL}/${version}/SHA256SUMS" "$sums" 2>/dev/null; then
			want="$(expected_digest "$sums" asterism.rb)"
			got="$(sha256_of "$staged")"
			[ "$got" = "$want" ] ||
				die "checksum mismatch on asterism.rb: expected ${want}, got ${got}. Refusing."
			say "sha256 ok: ${got}"
		else
			die "could not download SHA256SUMS for ${version}. Refusing to install an unverified formula."
		fi
	fi
	cp "$staged" "${tapdir}/Formula/asterism.rb"
	say "wrote ${tapdir}/Formula/asterism.rb"
}

install_brew() {
	brew_bin="$(find_brew)" || no_homebrew

	if [ -n "$REF" ]; then
		version="$REF"
		head_flag="--HEAD"
		say "${REF} is a git ref, not a release — Homebrew gets --HEAD"
	else
		version="$(resolve_version)"
		head_flag=""
	fi

	if "$brew_bin" list --formula --versions asterism >/dev/null 2>&1; then
		if [ "$FORCE" != "1" ]; then
			say "already installed by Homebrew: $("$brew_bin" list --formula --versions asterism)"
			say "run 'brew upgrade ${TAP}/asterism', or re-run with ASTERISM_FORCE=1 to reinstall."
			return 0
		fi
		action="reinstall"
	else
		action="install"
	fi

	ensure_tap "$brew_bin" "$version"

	# QEMU arrives as a formula dependency: Homebrew builds and ships it, we
	# only declare it. Asterism never bundles QEMU.
	if [ -n "$head_flag" ]; then
		say "brew ${action} ${head_flag} ${TAP}/asterism"
		"$brew_bin" "$action" "$head_flag" "${TAP}/asterism"
	else
		say "brew ${action} ${TAP}/asterism"
		"$brew_bin" "$action" "${TAP}/asterism"
	fi
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

	say "instance state in ${ASTERISM_HOME:-${HOME}/.asterism} was left alone."
	say "delete it by hand if you want it gone."
}

# ---- notes -----------------------------------------------------------------

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
		sed -n '2,33p' "$0" | sed 's/^# \{0,1\}//'
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
