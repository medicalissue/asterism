#!/bin/sh
# Render the release formula: packaging/asterism.rb with a `stable` block
# pinned to one tag and one digest.
#
#   scripts/render-formula.sh v0.1.0 > asterism.rb
#
# The formula in the tree is the source of truth for everything except which
# release is current, and that is the one thing a tap has to be told. So this
# does not keep a second copy of the formula body: it substitutes the marker
# line for a stable block and leaves the rest of the file alone.
#
# With no digest given it downloads the tag's source tarball and hashes it,
# which is the same tarball Homebrew will download.
set -eu

TAG="${1:-}"
SHA="${2:-}"
REPO="${FORMULA_REPO:-medicalissue/asterism}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC="${ROOT}/packaging/asterism.rb"
MARKER="# release:stable-block"

[ -n "$TAG" ] || {
	echo "usage: $0 <tag> [sha256]" >&2
	exit 2
}
grep -q "$MARKER" "$SRC" || {
	echo "render-formula: no ${MARKER} marker in ${SRC}" >&2
	exit 1
}

URL="https://github.com/${REPO}/archive/refs/tags/${TAG}.tar.gz"

CLEAN_DIR=""
CLEAN_FILE=""
cleanup() {
	[ -n "$CLEAN_DIR" ] && rm -rf "$CLEAN_DIR"
	[ -n "$CLEAN_FILE" ] && rm -f "$CLEAN_FILE"
	return 0
}
trap cleanup EXIT

if [ -z "$SHA" ]; then
	tmp="$(mktemp -d "${TMPDIR:-/tmp}/asterism-formula.XXXXXX")"
	CLEAN_DIR="$tmp"
	echo "render-formula: hashing ${URL}" >&2
	curl -fsSL "$URL" -o "${tmp}/src.tar.gz"
	if command -v shasum >/dev/null 2>&1; then
		SHA="$(shasum -a 256 "${tmp}/src.tar.gz" | cut -d' ' -f1)"
	else
		SHA="$(sha256sum "${tmp}/src.tar.gz" | cut -d' ' -f1)"
	fi
fi

# The block goes through a file, not through `awk -v`: the awk macOS ships
# rejects a newline inside a -v assignment.
blockfile="$(mktemp "${TMPDIR:-/tmp}/asterism-block.XXXXXX")"
CLEAN_FILE="$blockfile"
cat >"$blockfile" <<EOF
  stable do
    url "${URL}"
    sha256 "${SHA}"
  end

  livecheck do
    url :stable
    strategy :github_latest
  end
EOF

awk -v marker="$MARKER" -v blockfile="$blockfile" '
	index($0, marker) {
		while ((getline line < blockfile) > 0) print line
		close(blockfile)
		next
	}
	{ print }
' "$SRC"
