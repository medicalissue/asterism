#!/bin/sh
# Build the Linux binary injected into every OCI-sourced microVM.
set -eu

root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"

[ "$(uname -s)" = Linux ] || {
	echo "the OCI guest-control artifact must be built on Linux" >&2
	exit 1
}

if [ -n "${ASTERISM_GUEST_TARGET:-}" ]; then
	target=$ASTERISM_GUEST_TARGET
else
	case "$(uname -m)" in
	x86_64 | amd64) target=x86_64-unknown-linux-musl ;;
	aarch64 | arm64) target=aarch64-unknown-linux-musl ;;
	*) echo "unsupported OCI guest architecture: $(uname -m)" >&2; exit 1 ;;
	esac
fi
case "$target" in
x86_64-unknown-linux-musl | aarch64-unknown-linux-musl) ;;
*) echo "guest target must be a supported static Linux target, got $target" >&2; exit 1 ;;
esac

cargo_target_dir=${CARGO_TARGET_DIR:-target}
case "$cargo_target_dir" in
	/*) ;;
	*) cargo_target_dir="$root/$cargo_target_dir" ;;
esac
destination=${1:-$root/target/asterism-guest/$target}

rustup target list --installed | grep -qx "$target" || {
	echo "Rust target $target is not installed (rustup target add $target)" >&2
	exit 1
}
command -v musl-gcc >/dev/null 2>&1 || {
	echo "musl-gcc is required to build the static OCI guest agent" >&2
	exit 1
}

CARGO_TARGET_DIR="$cargo_target_dir" \
	cargo build --release --locked --target "$target" -p asterism-guest
mkdir -p "$destination/bin"
cp "$cargo_target_dir/$target/release/asterism-guest" "$destination/bin/asterism-guest"
${STRIP:-strip} "$destination/bin/asterism-guest"
chmod 0755 "$destination/bin/asterism-guest"

readelf_tool=${READELF:-readelf}
command -v "$readelf_tool" >/dev/null 2>&1 || {
	echo "readelf is required to audit the OCI guest artifact" >&2
	exit 1
}
"$readelf_tool" -h "$destination/bin/asterism-guest" | grep -q 'Class:.*ELF64'
if "$readelf_tool" -l "$destination/bin/asterism-guest" | grep -q 'INTERP'; then
	echo "OCI guest agent is dynamically linked; FROM scratch images could not run it" >&2
	exit 1
fi
case "$target" in
x86_64-*) "$readelf_tool" -h "$destination/bin/asterism-guest" | grep -q 'Machine:.*X86-64' ;;
aarch64-*) "$readelf_tool" -h "$destination/bin/asterism-guest" | grep -q 'Machine:.*AArch64' ;;
esac

printf '%s\n' "$destination"
