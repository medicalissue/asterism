#!/usr/bin/env bash
# Build the native Linux packages from a flat Asterism release payload.
#
#   scripts/build-linux-packages.sh PAYLOAD OUT [VERSION]
#
# PAYLOAD is either the directory a Linux release archive unpacks to, or the
# archive itself. OUT is where asterism_<version>_<arch>.deb and
# asterism-<version>-1.<arch>.rpm are written.
#
# The packages are built from the *released* payload rather than from a fresh
# compile on purpose. A package built from a second build of the same source
# is a second artifact with the same version number and different bytes; this
# way the binary in the .deb is the binary in the tarball is the binary the
# checksum in SHA256SUMS covers.
#
# nfpm is the tool because one description has to produce both families. A
# .deb and an .rpm that were written separately drift separately, and the
# whole claim being made here is that Ubuntu and Fedora receive the same
# files with the same modes and the same maintainer scripts.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

usage() {
	echo "usage: build-linux-packages.sh PAYLOAD OUT [VERSION]" >&2
	exit 2
}

[ "$#" -ge 2 ] || usage
PAYLOAD_INPUT="$1"
OUT="$2"
VERSION_INPUT="${3:-}"

WORK="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/asterism-linux-packages.XXXXXX")"
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT

if [ -d "$PAYLOAD_INPUT" ]; then
	PAYLOAD="$(cd "$PAYLOAD_INPUT" && pwd)"
elif [ -f "$PAYLOAD_INPUT" ]; then
	mkdir -p "$WORK/payload"
	tar -xzf "$PAYLOAD_INPUT" -C "$WORK/payload"
	PAYLOAD="$WORK/payload"
else
	echo "no such release payload: $PAYLOAD_INPUT" >&2
	exit 1
fi

# A package built from half a payload is worse than no package: it installs,
# and then refuses to boot anything with a message about a missing helper.
# Refuse here, where the operator is still holding the release.
missing=0
for member in ast astd cloud-hypervisor virtiofsd asterism-update \
	guest/bin/asterism-guest \
	guest-gpu/bin/asterism-gpu-guest guest-gpu/lib/libcuda.so.1.0.0 \
	share/asterism/asterism-nbd share/asterism/linux-components.env \
	share/asterism/licenses/cloud-hypervisor-Apache-2.0.txt \
	share/asterism/licenses/cloud-hypervisor-BSD-3-Clause.txt \
	share/asterism/licenses/virtiofsd-Apache-2.0.txt \
	share/asterism/licenses/virtiofsd-BSD-3-Clause.txt \
	share/asterism/licenses/LICENSE-APACHE \
	share/asterism/licenses/LICENSE-MIT \
	share/asterism/licenses/NOTICE; do
	if [ ! -e "${PAYLOAD}/${member}" ]; then
		echo "release payload is missing ${member}" >&2
		missing=1
	fi
done
[ "$missing" = 0 ] || {
	echo "refusing to package a partial Linux runtime" >&2
	exit 1
}

# The package's architecture is the payload's architecture, read out of the
# ELF header of the binary being shipped. Trusting `uname -m` would happily
# label an arm64 payload amd64 when a release is cross-assembled.
elf_machine="$(od -An -t x1 -j 18 -N 2 "${PAYLOAD}/ast" | tr -d ' \n')"
case "$elf_machine" in
3e00) ARCH=amd64 ;;
b700) ARCH=arm64 ;;
*)
	echo "unsupported ELF machine 0x${elf_machine} in ${PAYLOAD}/ast" >&2
	exit 1
	;;
esac

# Debian and RPM both order versions, and both take a leading `v` for part of
# the version string rather than a marker. `v0.1.0` would sort above `0.2.0`.
if [ -n "$VERSION_INPUT" ]; then
	VERSION="${VERSION_INPUT#v}"
else
	VERSION="$(sed -n 's/^version = "\(.*\)"$/\1/p' "$ROOT/Cargo.toml" | head -n 1)"
fi
[ -n "$VERSION" ] || {
	echo "could not determine a package version" >&2
	exit 1
}
case "$VERSION" in
[0-9]*) ;;
*)
	echo "package version ${VERSION} does not start with a digit" >&2
	exit 1
	;;
esac

NFPM="${NFPM:-nfpm}"
command -v "$NFPM" >/dev/null 2>&1 || {
	cat >&2 <<'EOF'
nfpm is not on PATH. It renders both package families from one description:

    go install github.com/goreleaser/nfpm/v2/cmd/nfpm@latest

or download a release binary and point NFPM at it.
EOF
	exit 1
}

mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"

# nfpm expands environment variables in some fields and not in others, so
# the description is rendered here instead. One substitution pass, four
# variables, and the rendered file is what is fed to both packagers — so the
# .deb and the .rpm cannot disagree about which payload they came from.
config="${WORK}/nfpm.yaml"
sed \
	-e "s|\${ASTERISM_PKG_ARCH}|${ARCH}|g" \
	-e "s|\${ASTERISM_PKG_VERSION}|${VERSION}|g" \
	-e "s|\${ASTERISM_PKG_PAYLOAD}|${PAYLOAD}|g" \
	-e "s|\${ASTERISM_PKG_SOURCE}|${ROOT}|g" \
	"$ROOT/packaging/linux/nfpm.yaml" >"$config"
if grep -q 'ASTERISM_PKG_' "$config"; then
	echo "packaging/linux/nfpm.yaml has an unrendered variable" >&2
	grep -n 'ASTERISM_PKG_' "$config" >&2
	exit 1
fi

for packager in deb rpm; do
	"$NFPM" package \
		--config "$config" \
		--packager "$packager" \
		--target "$OUT"
done

echo "built from ${PAYLOAD} (${ARCH}, ${VERSION}):"
ls -1 "$OUT"
