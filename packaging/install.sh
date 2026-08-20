#!/bin/sh
# Asterism installer.
#
#   curl -fsSL https://asterism.run/install.sh | sh
#
# What it does, and nothing more: works out what machine this is, hands the
# install to a package manager, and shows you every command it is about to run
# as root. It never installs Homebrew for you, never pipes anything into a
# shell, and never runs sudo without asking. Re-running it on a machine that
# already has Asterism is a no-op.
#
# Environment:
#   ASTERISM_YES=1        answer yes to every prompt (for CI)
#   ASTERISM_FORCE=1      reinstall even if Asterism is already installed
#   ASTERISM_BRANCH=name  branch to build from HEAD (default: master)
#   ASTERISM_TAP=user/tap Homebrew tap to install from
#   ASTERISM_FORMULA=X    path or URL of the formula, when the tap is not published
#   ASTERISM_PREFIX=DIR   Linux install prefix (default: ~/.local)
set -eu

REPO="medicalissue/asterism"
REPO_URL="https://github.com/${REPO}.git"
BRANCH="${ASTERISM_BRANCH:-master}"
TAP="${ASTERISM_TAP:-medicalissue/asterism}"
FORMULA="${ASTERISM_FORMULA:-https://raw.githubusercontent.com/${REPO}/${BRANCH}/packaging/asterism.rb}"
PREFIX="${ASTERISM_PREFIX:-${HOME}/.local}"
ASSUME_YES="${ASTERISM_YES:-0}"
FORCE="${ASTERISM_FORCE:-0}"

say() { printf 'asterism: %s\n' "$*"; }
err() { printf 'asterism: %s\n' "$*" >&2; }
die() {
	err "$*"
	exit 1
}
have() { command -v "$1" >/dev/null 2>&1; }

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

# ---- macOS -----------------------------------------------------------------

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
	err "Asterism installs through Homebrew on macOS, and Homebrew is not here."
	err ""
	err "Install it with the command Homebrew publishes, then re-run this script:"
	err ""
	err "    /bin/bash -c \"\$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)\""
	err ""
	err "We will not install Homebrew for you. What owns /opt/homebrew on your"
	err "machine is your decision, not ours."
	exit 1
}

# Homebrew only installs formulae that live in a tap — a loose .rb file or a
# raw URL is rejected outright. So: use the published tap when it exists, and
# until it does, stand up a local tap holding this one formula. Either way the
# install command below is the same one that will keep working afterwards.
ensure_tap() {
	brew_bin="$1"

	if ! "$brew_bin" tap | grep -qx "$TAP"; then
		if "$brew_bin" tap "$TAP" 2>/dev/null; then
			say "tapped ${TAP}"
			return 0
		fi
		# A failed tap can leave the directory behind; clear it before
		# creating the local one, or tap-new refuses.
		"$brew_bin" untap "$TAP" >/dev/null 2>&1 || true
		say "${TAP} is not published yet — building a local tap from ${BRANCH}"
		"$brew_bin" tap-new --no-git "$TAP" >/dev/null
	fi

	tapdir="$("$brew_bin" --repository "$TAP")"
	if [ -f "${tapdir}/Formula/asterism.rb" ]; then
		return 0
	fi

	mkdir -p "${tapdir}/Formula"
	case "$FORMULA" in
	http://* | https://*)
		have curl || die "curl is required to fetch the formula."
		curl -fsSL "$FORMULA" -o "${tapdir}/Formula/asterism.rb" ||
			die "could not fetch the formula from ${FORMULA}"
		;;
	*)
		if [ ! -f "$FORMULA" ]; then
			die "no formula at ${FORMULA}"
		fi
		cp "$FORMULA" "${tapdir}/Formula/asterism.rb"
		;;
	esac
}

install_macos() {
	brew_bin="$(find_brew)" || no_homebrew

	if "$brew_bin" list --formula --versions asterism >/dev/null 2>&1; then
		if [ "$FORCE" != "1" ]; then
			say "already installed: $(ast --version 2>/dev/null || echo ast)"
			say "re-run with ASTERISM_FORCE=1 to rebuild from ${BRANCH}."
			return 0
		fi
		say "reinstalling from ${BRANCH} (ASTERISM_FORCE=1)"
		action="reinstall"
	else
		action="install"
	fi

	ensure_tap "$brew_bin"

	# QEMU arrives as a formula dependency: Homebrew builds and ships it, we
	# only declare it. Asterism never bundles QEMU — see docs/LICENSING.md.
	say "brew ${action} --HEAD ${TAP}/asterism"
	say "this compiles Asterism and pulls in QEMU; give it a few minutes."
	"$brew_bin" "$action" --HEAD "${TAP}/asterism"
}

# ---- Linux (best effort) ---------------------------------------------------

# There is no Asterism package for Linux yet, so build from source into
# $PREFIX/bin. QEMU comes from the system package manager, with consent.
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

install_linux() {
	if [ -x "${PREFIX}/bin/ast" ] && [ "$FORCE" != "1" ]; then
		say "already installed: $("${PREFIX}/bin/ast" --version 2>/dev/null || echo ast)"
		say "re-run with ASTERISM_FORCE=1 to rebuild from ${BRANCH}."
		return 0
	fi

	say "Linux has no Asterism package yet; building from source."
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

	ensure_qemu_linux

	src="${XDG_CACHE_HOME:-${HOME}/.cache}/asterism/src"
	if [ -d "${src}/.git" ]; then
		say "updating ${src}"
		git -C "$src" fetch --depth 1 origin "$BRANCH"
		git -C "$src" checkout --detach FETCH_HEAD
	else
		say "cloning ${REPO_URL} into ${src}"
		mkdir -p "$(dirname "$src")"
		rm -rf "$src"
		git clone --depth 1 --branch "$BRANCH" "$REPO_URL" "$src"
	fi

	say "cargo build --release (a few minutes)"
	(cd "$src" && cargo build --release --locked \
		--package asterism-cli --package asterism-daemon)

	mkdir -p "${PREFIX}/bin"
	# ast finds astd as a sibling, so they install together.
	install -m 755 "${src}/target/release/ast" "${PREFIX}/bin/ast"
	install -m 755 "${src}/target/release/astd" "${PREFIX}/bin/astd"
	say "installed ast and astd into ${PREFIX}/bin"

	case ":${PATH}:" in
	*":${PREFIX}/bin:"*) ;;
	*) say "add it to your PATH:  export PATH=\"${PREFIX}/bin:\$PATH\"" ;;
	esac
}

# ---- entry -----------------------------------------------------------------

main() {
	os="$(uname -s)"
	arch="$(uname -m)"

	case "$arch" in
	arm64 | aarch64) arch="arm64" ;;
	x86_64 | amd64) arch="x86_64" ;;
	*) die "unsupported architecture: ${arch}. Asterism builds for arm64 and x86_64." ;;
	esac

	case "$os" in
	Darwin)
		say "macOS ${arch}"
		install_macos
		;;
	Linux)
		say "Linux ${arch}"
		install_linux
		;;
	*)
		die "unsupported platform: ${os}. Asterism runs on macOS today, Linux by hand."
		;;
	esac

	if have ast; then
		say "done — $(ast --version 2>/dev/null || echo ast)"
		say "next:  ast images"
	else
		say "done. Open a new shell so ast lands on your PATH, then: ast images"
	fi
}

main "$@"
