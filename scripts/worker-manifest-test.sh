#!/usr/bin/env bash
# Prove `asterism-release-manifest.json` against the Worker's own acceptance
# rules, without a Worker and without a release.
#
# Renders an envelope over fixture artifacts with a throwaway key, runs the
# transcription of worker/artifacts.ts over it, and checks the two refusals
# that matter: no key means no manifest, and a rendered manifest must not
# leave a stale unsigned file behind.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/asterism-worker-manifest.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

TAG="${1:-v0.1.0}"
REPO="${WORKER_MANIFEST_REPO:-medicalissue/asterism}"
KEY="worker-manifest-test-key-not-a-secret"

# Stand-in artifacts. Only their names, digests and sizes reach the manifest,
# so fixture bytes prove the renderer exactly as well as real ones do.
mkdir -p "$WORK/dist"
for name in "asterism-${TAG}-darwin-arm64.tar.gz" \
	"asterism-${TAG}-linux-x86_64.tar.gz" \
	"asterism-${TAG}-linux-arm64.tar.gz" \
	"asterism-${TAG}-windows-x86_64.tar.gz" \
	"asterism-${TAG}-windows-arm64.tar.gz" \
	SHA256SUMS RELEASE.json RELEASE.json.sig; do
	printf 'fixture %s\n' "$name" >"$WORK/dist/$name"
done

RELEASE_MANIFEST_HMAC_KEY="$KEY" "$ROOT/scripts/render-worker-manifest.sh" \
	stable "$TAG" "$REPO" "$WORK"/dist/* >"$WORK/asterism-release-manifest.json"

RELEASE_MANIFEST_HMAC_KEY="$KEY" node "$ROOT/scripts/verify-worker-manifest.mjs" \
	"$WORK/asterism-release-manifest.json" "$TAG" "$REPO"

# The wrong key must not verify, or the signature is decoration.
if RELEASE_MANIFEST_HMAC_KEY="a-different-key-entirely" node "$ROOT/scripts/verify-worker-manifest.mjs" \
	"$WORK/asterism-release-manifest.json" "$TAG" "$REPO" >/dev/null 2>&1; then
	echo "a manifest verified under the wrong key" >&2
	exit 1
fi
echo "worker manifest refuses the wrong key"

# A manifest for one tag must not be servable from another: the Worker checks
# both the payload tag and every download URL against its configured tag.
if RELEASE_MANIFEST_HMAC_KEY="$KEY" node "$ROOT/scripts/verify-worker-manifest.mjs" \
	"$WORK/asterism-release-manifest.json" "v9.9.9" "$REPO" >/dev/null 2>&1; then
	echo "a manifest verified against the wrong tag" >&2
	exit 1
fi
echo "worker manifest refuses the wrong tag"

# And the fail-closed contract: no key, no manifest. An unsigned envelope is
# not a degraded release, it is one the Worker refuses to serve.
if RELEASE_MANIFEST_HMAC_KEY="" "$ROOT/scripts/render-worker-manifest.sh" \
	stable "$TAG" "$REPO" "$WORK"/dist/SHA256SUMS >/dev/null 2>&1; then
	echo "render-worker-manifest.sh signed without a key" >&2
	exit 1
fi
echo "worker manifest refuses to render unsigned"
