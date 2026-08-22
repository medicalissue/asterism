#!/usr/bin/env bash
# Build one self-contained Linux release archive from pinned runtime inputs.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target}"
# shellcheck disable=SC1091
. "$ROOT/packaging/linux-components.env"

VERSION="${1:?usage: package-linux.sh VERSION DIST_DIR}"
DIST="${2:?usage: package-linux.sh VERSION DIST_DIR}"
ARCH="$(uname -m)"
case "$ARCH" in
  x86_64)
    TARGET=linux-x86_64
    CHV_URL="$CLOUD_HYPERVISOR_X86_64_URL"
    CHV_SHA="$CLOUD_HYPERVISOR_X86_64_SHA256"
    ;;
  aarch64 | arm64)
    TARGET=linux-arm64
    CHV_URL="$CLOUD_HYPERVISOR_AARCH64_URL"
    CHV_SHA="$CLOUD_HYPERVISOR_AARCH64_SHA256"
    ;;
  *) echo "unsupported Linux release architecture: $ARCH" >&2; exit 1 ;;
esac

WORK="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/asterism-linux-package.XXXXXX")"
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT
mkdir -p "$WORK/root/share/asterism/licenses" "$DIST"

fetch() { curl --proto '=https' --tlsv1.2 -fsSL "$1" -o "$2"; }
verify() {
  got="$(sha256sum "$1" | cut -d' ' -f1)"
  [ "$got" = "$2" ] || { echo "digest mismatch for $1: $got != $2" >&2; exit 1; }
}

fetch "$CHV_URL" "$WORK/root/cloud-hypervisor"
verify "$WORK/root/cloud-hypervisor" "$CHV_SHA"
chmod 0755 "$WORK/root/cloud-hypervisor"
"$WORK/root/cloud-hypervisor" --version | grep -F "$CLOUD_HYPERVISOR_VERSION"

fetch "$VIRTIOFSD_TARBALL" "$WORK/virtiofsd.tar.gz"
verify "$WORK/virtiofsd.tar.gz" "$VIRTIOFSD_TARBALL_SHA256"
tar -xzf "$WORK/virtiofsd.tar.gz" -C "$WORK"
VIRTIOFSD_TARGET="$WORK/virtiofsd-target"
CARGO_TARGET_DIR="$VIRTIOFSD_TARGET" cargo build --release --locked \
  --manifest-path "$WORK/virtiofsd-${VIRTIOFSD_VERSION}/Cargo.toml"
cp "$VIRTIOFSD_TARGET/release/virtiofsd" "$WORK/root/virtiofsd"
strip "$WORK/root/virtiofsd"
"$WORK/root/virtiofsd" --version | grep -F "${VIRTIOFSD_VERSION#v}"

fetch "$CLOUD_HYPERVISOR_SOURCE_TARBALL" "$WORK/cloud-hypervisor.tar.xz"
verify "$WORK/cloud-hypervisor.tar.xz" "$CLOUD_HYPERVISOR_SOURCE_SHA256"
tar -xJf "$WORK/cloud-hypervisor.tar.xz" -C "$WORK" \
  "cloud-hypervisor-${CLOUD_HYPERVISOR_VERSION}/LICENSES/Apache-2.0.txt" \
  "cloud-hypervisor-${CLOUD_HYPERVISOR_VERSION}/LICENSES/BSD-3-Clause.txt"
cp "$WORK/cloud-hypervisor-${CLOUD_HYPERVISOR_VERSION}/LICENSES/Apache-2.0.txt" \
  "$WORK/root/share/asterism/licenses/cloud-hypervisor-Apache-2.0.txt"
cp "$WORK/cloud-hypervisor-${CLOUD_HYPERVISOR_VERSION}/LICENSES/BSD-3-Clause.txt" \
  "$WORK/root/share/asterism/licenses/cloud-hypervisor-BSD-3-Clause.txt"
cp "$WORK/virtiofsd-${VIRTIOFSD_VERSION}/LICENSE-APACHE" \
  "$WORK/root/share/asterism/licenses/virtiofsd-Apache-2.0.txt"
cp "$WORK/virtiofsd-${VIRTIOFSD_VERSION}/LICENSE-BSD-3-Clause" \
  "$WORK/root/share/asterism/licenses/virtiofsd-BSD-3-Clause.txt"
cp "$ROOT/packaging/linux-components.env" "$WORK/root/share/asterism/linux-components.env"

cp "$CARGO_TARGET_DIR/release/ast" "$CARGO_TARGET_DIR/release/astd" "$WORK/root/"
strip "$WORK/root/ast" "$WORK/root/astd"
tar -czf "$DIST/asterism-${VERSION}-${TARGET}.tar.gz" -C "$WORK/root" \
  ast astd cloud-hypervisor virtiofsd share
sha256sum "$DIST/asterism-${VERSION}-${TARGET}.tar.gz" \
  >"$DIST/SHA256SUMS.${TARGET}"
