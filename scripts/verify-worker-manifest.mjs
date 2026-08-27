// Accept or reject `asterism-release-manifest.json` exactly as the
// asterism.run Worker does.
//
//   RELEASE_MANIFEST_HMAC_KEY=... node scripts/verify-worker-manifest.mjs \
//       dist/v0.1.0/asterism-release-manifest.json v0.1.0 medicalissue/asterism
//
// This is a transcription of `getReleaseManifest` / `isReleasePayload` in
// worker/artifacts.ts in the site repository (medicalissue/asterism-site) —
// the same regexes, the same size limit, the same `JSON.stringify(payload)`
// re-serialisation, the same WebCrypto HMAC-SHA256 verify. It exists so a
// format drift fails in the release job, where the message is legible,
// instead of at request time as an unexplained 502.
//
// If the site's copy changes, this is the file that changes with it.
import fs from "node:fs";

const [file, tag, repository] = process.argv.slice(2);
if (!file || !tag || !repository) {
  console.error("usage: verify-worker-manifest.mjs MANIFEST TAG REPOSITORY");
  process.exit(2);
}
const secret = process.env.RELEASE_MANIFEST_HMAC_KEY ?? "";
if (secret.length < 8) {
  console.error("RELEASE_MANIFEST_HMAC_KEY is unset or shorter than the 8 characters the Worker requires");
  process.exit(2);
}

const SHA256 = /^[a-f0-9]{64}$/u;
const RELEASE_ASSET = /^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$/u;
const MANIFEST_LIMIT = 256_000;
const CHANNEL = "stable";

function fail(message) {
  console.error(`worker manifest rejected: ${message}`);
  process.exit(1);
}

const source = fs.readFileSync(file, "utf8");
if (source.length > MANIFEST_LIMIT) fail(`the manifest is ${source.length} bytes, over the Worker's ${MANIFEST_LIMIT} limit`);

let envelope;
try {
  envelope = JSON.parse(source);
} catch (error) {
  fail(`the manifest is not JSON: ${error.message}`);
}
if (typeof envelope.signature !== "string") fail("no signature string");

const payload = envelope.payload;
if (!payload || typeof payload !== "object") fail("no payload object");
if (payload.channel !== CHANNEL) fail(`channel ${payload.channel} is not ${CHANNEL}`);
if (payload.tag !== tag) fail(`payload tag ${payload.tag} is not ${tag}`);
if (!Array.isArray(payload.assets) || payload.assets.length === 0) fail("the payload lists no assets");

// The Worker requires every download URL to be under this exact release, so a
// manifest can never point a user at bytes from another tag or another
// repository — which is also why Desktop artifacts from the private
// asterism-gui repository cannot be listed here. See docs/RELEASE.md.
const prefix = `https://github.com/${repository}/releases/download/${encodeURIComponent(tag)}/`;
for (const asset of payload.assets) {
  if (!asset || typeof asset !== "object") fail("an asset is not an object");
  if (typeof asset.name !== "string" || !RELEASE_ASSET.test(asset.name)) fail(`asset name ${asset.name} is not one the Worker accepts`);
  if (typeof asset.url !== "string" || !asset.url.startsWith(prefix)) fail(`asset ${asset.name} has a url outside ${prefix}`);
  if (!SHA256.test(asset.sha256 ?? "")) fail(`asset ${asset.name} has no lowercase-hex sha256`);
  if (asset.size !== undefined && !(Number.isSafeInteger(asset.size) && asset.size >= 0)) fail(`asset ${asset.name} has a bad size`);
}

// The Worker signs and serves this string, not the file's bytes. A manifest
// whose signature covers anything else 502s with invalid_manifest_signature.
const canonical = JSON.stringify(payload);

const key = await crypto.subtle.importKey(
  "raw",
  new TextEncoder().encode(secret),
  { name: "HMAC", hash: "SHA-256" },
  false,
  ["verify"],
);

function decodeBase64Url(value) {
  const normalized = value.replaceAll("-", "+").replaceAll("_", "/");
  const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "=");
  return Uint8Array.from(atob(padded), (character) => character.charCodeAt(0));
}

let signature;
try {
  signature = decodeBase64Url(envelope.signature);
} catch {
  fail("the signature is not base64url");
}
if (!(await crypto.subtle.verify("HMAC", key, signature, new TextEncoder().encode(canonical)))) {
  fail("HMAC verification failed: the signed bytes are not JSON.stringify(payload)");
}

// A signature that does not actually bind the digests would pass everything
// above and protect nothing.
const tampered = JSON.parse(source);
tampered.payload.assets[0].sha256 = "0".repeat(64);
if (await crypto.subtle.verify("HMAC", key, signature, new TextEncoder().encode(JSON.stringify(tampered.payload)))) {
  fail("a tampered payload verified against the same signature");
}

console.log(`worker manifest ok: ${payload.assets.length} assets for ${payload.tag}`);
