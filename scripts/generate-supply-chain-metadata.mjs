#!/usr/bin/env node
// Generate release metadata from the committed dependency graphs. This avoids
// a hosted inventory service and deliberately omits timestamps and UUIDs, so
// the same source and release version always produce byte-identical files.

import { execFileSync } from "node:child_process";
import { mkdirSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";

function fail(message) {
  process.stderr.write(`generate-supply-chain-metadata: ${message}\n`);
  process.exit(2);
}

function arg(name) {
  const index = process.argv.indexOf(name);
  return index === -1 ? undefined : process.argv[index + 1];
}

const output = arg("--out");
const releaseVersion = arg("--version");
if (!output || !releaseVersion || process.argv.length !== 6) {
  fail("usage: generate-supply-chain-metadata.mjs --out DIRECTORY --version VERSION");
}

function json(value) {
  return `${JSON.stringify(value, null, 2)}\n`;
}

const components = [];

for (const manifest of ["Cargo.toml"]) {
  const cargo = JSON.parse(execFileSync(
    "cargo",
    ["metadata", "--format-version", "1", "--locked", "--manifest-path", manifest],
    { encoding: "utf8", maxBuffer: 16 * 1024 * 1024 },
  ));
  for (const pkg of cargo.packages) {
    // Workspace packages are the product, not third-party material.
    if (!pkg.source) continue;
    components.push({
      ecosystem: "cargo",
      name: pkg.name,
      version: pkg.version,
      license: pkg.license ?? "NOASSERTION",
      purl: `pkg:cargo/${pkg.name}@${pkg.version}`,
    });
  }
}

components.sort((a, b) => (a.purl < b.purl ? -1 : a.purl > b.purl ? 1 : 0));
const uniqueComponents = components.filter((component, index) =>
  index === 0 || component.purl !== components[index - 1].purl,
);

const licenses = {
  format: "asterism-third-party-license-manifest-v1",
  release: releaseVersion,
  artifacts: ["ast", "astd", "astd-vz", "asterism-update"],
  components: uniqueComponents,
};
const sbom = {
  bomFormat: "CycloneDX",
  specVersion: "1.5",
  version: 1,
  metadata: {
    component: {
      type: "application",
      name: "asterism",
      version: releaseVersion,
      properties: [{
        name: "asterism:release-artifacts",
        value: "ast,astd,astd-vz,asterism-update",
      }],
    },
  },
  components: uniqueComponents.map(({ ecosystem, name, version, license, purl }) => ({
    type: "library",
    name,
    version,
    purl,
    licenses: license === "NOASSERTION" ? undefined : [{ expression: license }],
    properties: [{ name: "asterism:ecosystem", value: ecosystem }],
  })),
};

// JSON.stringify omits undefined optional fields, leaving components with an
// unknown license visibly unlicensed rather than falsely claiming a license.
const out = resolve(output);
mkdirSync(out, { recursive: true });
writeFileSync(resolve(out, `asterism-${releaseVersion}-sbom.cdx.json`), json(sbom));
writeFileSync(resolve(out, `asterism-${releaseVersion}-licenses.json`), json(licenses));
