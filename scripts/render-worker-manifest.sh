#!/bin/sh
# Render `asterism-release-manifest.json`: the signed envelope the asterism.run
# Worker fetches from one immutable release tag.
#
#   RELEASE_MANIFEST_HMAC_KEY=... scripts/render-worker-manifest.sh \
#       stable v0.1.0 medicalissue/asterism dist/v0.1.0/asterism-v0.1.0-darwin-arm64.tar.gz ...
#
# This is NOT RELEASE.json. The two manifests are different documents with
# different readers, different schemas and different signatures:
#
#   RELEASE.json                     read by packaging/update.sh (`ast update`),
#                                    flat schema-1 scalars, minisign detached
#                                    signature in RELEASE.json.sig.
#   asterism-release-manifest.json   read by the Worker's worker/artifacts.ts,
#                                    {payload,signature} envelope, HMAC-SHA256
#                                    over the compact payload, base64url.
#
# The Worker verifies with `hmacVerify(JSON.stringify(value.payload), ...)`, so
# the bytes signed here must be exactly what JSON.stringify produces after the
# envelope is parsed. That is why the payload is emitted compact, in one fixed
# key order, ASCII only: for such a document JSON.stringify(JSON.parse(x)) is x.
# Do not "pretty print" the payload — it would sign bytes the Worker never
# reconstructs, and every request would 502 invalid_manifest_signature.
#
# The key is a shared secret, not a public-key pair: it must be byte-identical
# to the site's Secrets Store entry ASTERISM_RELEASE_SIGNING_KEY, bound in the
# Worker as RELEASE_SIGNING_KEY. Absent, this refuses. An unsigned envelope is
# not a degraded release, it is an unservable one.
set -eu

usage() {
	echo "usage: RELEASE_MANIFEST_HMAC_KEY=... $0 CHANNEL TAG REPOSITORY FILE [FILE...]" >&2
	exit 2
}

[ $# -ge 4 ] || usage
channel=$1 tag=$2 repository=$3
shift 3

case "$channel" in stable | beta | nightly) ;; *) echo "bad channel: $channel" >&2; exit 2 ;; esac
# The same shapes worker/artifacts.ts enforces. Failing here is a legible
# packaging error; failing there is a 502 nobody can read.
case "$repository" in
*/*) ;;
*) echo "repository must be owner/name: $repository" >&2; exit 2 ;;
esac
printf '%s' "$repository" | grep -Eq '^[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+$' ||
	{ echo "repository is not a bare owner/name: $repository" >&2; exit 2; }
printf '%s' "$tag" | grep -Eq '^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$' ||
	{ echo "tag is not a release tag the Worker will accept: $tag" >&2; exit 2; }

key="${RELEASE_MANIFEST_HMAC_KEY:-}"
[ -n "$key" ] || {
	echo "render-worker-manifest: RELEASE_MANIFEST_HMAC_KEY is not set." >&2
	echo "  This secret is the site Worker's RELEASE_SIGNING_KEY. Without it the" >&2
	echo "  envelope cannot be signed, and an unsigned envelope is refused by the" >&2
	echo "  Worker with invalid_manifest_signature. Provision it (AST-91) and" >&2
	echo "  re-run; do not publish a placeholder." >&2
	exit 1
}
# readSecret() rejects anything shorter than 8 characters, so a stub secret
# would fail at request time rather than here. Catch it here instead.
[ "${#key}" -ge 8 ] || { echo "RELEASE_MANIFEST_HMAC_KEY is shorter than the 8 characters the Worker requires" >&2; exit 1; }

command -v openssl >/dev/null || { echo "openssl is required to sign the release manifest" >&2; exit 1; }

sha256_of() {
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$1" | cut -d' ' -f1
	else
		shasum -a 256 "$1" | cut -d' ' -f1
	fi
}

size_of() {
	# BSD and GNU stat disagree on flags; wc is on every host either way.
	wc -c <"$1" | tr -d ' '
}

base="https://github.com/${repository}/releases/download/${tag}/"

assets=""
for file in "$@"; do
	[ -f "$file" ] || { echo "no such release artifact: $file" >&2; exit 1; }
	name="$(basename "$file")"
	printf '%s' "$name" | grep -Eq '^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$' ||
		{ echo "artifact name is not one the Worker will accept: $name" >&2; exit 1; }
	digest="$(sha256_of "$file")"
	case "$digest" in
	*[!0-9a-f]*) echo "digest for ${name} is not lowercase hex" >&2; exit 1 ;;
	esac
	[ "${#digest}" -eq 64 ] || { echo "digest for ${name} is not 64 hex characters" >&2; exit 1; }
	entry="$(printf '{"name":"%s","url":"%s%s","sha256":"%s","size":%s}' \
		"$name" "$base" "$name" "$digest" "$(size_of "$file")")"
	if [ -z "$assets" ]; then assets="$entry"; else assets="${assets},${entry}"; fi
done

payload="$(printf '{"channel":"%s","tag":"%s","assets":[%s]}' "$channel" "$tag" "$assets")"

# hexkey rather than key: the secret is arbitrary UTF-8 and openssl's key: form
# would mangle anything with a colon or a non-ASCII byte in it.
hexkey="$(printf '%s' "$key" | od -An -v -tx1 | tr -d ' \n')"
signature="$(
	printf '%s' "$payload" |
		openssl dgst -sha256 -mac HMAC -macopt "hexkey:${hexkey}" -binary |
		openssl base64 -A | tr '+/' '-_' | tr -d '='
)"
[ -n "$signature" ] || { echo "signing the release manifest produced nothing" >&2; exit 1; }

printf '{"payload":%s,"signature":"%s"}\n' "$payload" "$signature"
