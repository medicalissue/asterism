#!/usr/bin/env bash
# Install the pinned nfpm into a directory, verifying it before it runs.
#
#   scripts/install-nfpm.sh [BINDIR]      # default: ./.tools/bin
#
# nfpm renders the .deb and the .rpm from one description. It is a build
# tool, not a shipped runtime component, so it is not in
# packaging/linux-components.env — but it is still pinned by digest here,
# because a packaging tool that changes underneath a release changes the
# release.
set -euo pipefail

NFPM_VERSION=2.47.0
NFPM_X86_64_SHA256=0660ca602b2d2d2ae4781a06c692b3eeb9d437ffea05b831d76e41f4a3188783
NFPM_ARM64_SHA256=1c0f5f2999b9a974bfb04fdb0cc3306096de530ac5dbb25d739cc5f5219c919c

BINDIR="${1:-$(pwd)/.tools/bin}"

case "$(uname -m)" in
x86_64) slug=Linux_x86_64; want="$NFPM_X86_64_SHA256" ;;
aarch64 | arm64) slug=Linux_arm64; want="$NFPM_ARM64_SHA256" ;;
*)
	echo "no pinned nfpm for $(uname -m)" >&2
	exit 1
	;;
esac

archive="nfpm_${NFPM_VERSION}_${slug}.tar.gz"
url="https://github.com/goreleaser/nfpm/releases/download/v${NFPM_VERSION}/${archive}"

work="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/asterism-nfpm.XXXXXX")"
trap 'rm -rf "$work"' EXIT

curl --proto '=https' --tlsv1.2 -fsSL "$url" -o "${work}/${archive}"
got="$(sha256sum "${work}/${archive}" | cut -d' ' -f1)"
[ "$got" = "$want" ] || {
	echo "nfpm digest mismatch: ${got} != ${want}" >&2
	exit 1
}

mkdir -p "$BINDIR"
tar -xzf "${work}/${archive}" -C "$work" nfpm
install -m 0755 "${work}/nfpm" "${BINDIR}/nfpm"
"${BINDIR}/nfpm" --version
