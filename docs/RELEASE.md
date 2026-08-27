# Releases

How a release is cut, what it contains, how each part is signed, and which
reader reads which file. This is the single place those four questions are
answered; `packaging/README.md` describes what an *install* does with the
result.

GitHub Releases on `medicalissue/asterism` is the canonical store (AST-106).
Nothing else serves bytes: the asterism.run Worker fetches one small signed
manifest from an immutable tag and never proxies a binary.

## Three readers, three signatures

The most important thing to know about an Asterism release is that there is
more than one manifest, they are not interchangeable, and they are signed with
different keys under different schemes. Confusing them is how an update
channel goes dark.

| File | Read by | Shape | Signature |
| --- | --- | --- | --- |
| `RELEASE.json` | `packaging/update.sh`, which is what `ast update` execs | flat schema-1 scalars on one line | minisign detached, in `RELEASE.json.sig`, verified against `ASTERISM_UPDATE_PUBKEY` |
| `asterism-release-manifest.json` | the asterism.run Worker (`worker/artifacts.ts`) | `{"payload":{channel,tag,assets[]},"signature":"…"}` | HMAC-SHA256 over `JSON.stringify(payload)`, base64url, shared secret |
| `SHA256SUMS` | `packaging/install.sh` and `packaging/install.ps1` | `sha256␠␠name` lines | none — it is fetched over TLS from the same release as the artifact |

`asterism.rb` has no signature of its own; its digest is in `SHA256SUMS`, and
the tap's copy is byte-identical to the released one.

### Why the Worker's signature is symmetric

`worker/artifacts.ts` calls `hmacVerify(JSON.stringify(value.payload), value.signature, await readSecret(env.RELEASE_SIGNING_KEY))`.
That is an HMAC with a **shared secret**, not a public-key verification. The
release job must therefore hold the same secret the Worker holds. It is not
the minisign key and it cannot be derived from it.

Two consequences that are easy to get wrong:

- The signed bytes are `JSON.stringify(payload)` **after the envelope is
  parsed**, not the bytes of the file. `scripts/render-worker-manifest.sh`
  emits the payload compact, ASCII, in one fixed key order, precisely so that
  `JSON.stringify(JSON.parse(x)) === x` and the two agree. Pretty-printing the
  payload would produce a manifest that parses, validates, and then fails
  every signature check with `invalid_manifest_signature`.
- Every asset URL must start with
  `https://github.com/<RELEASE_REPOSITORY>/releases/download/<tag>/`. The
  Worker rejects the whole manifest otherwise. This is what makes a second
  repository impossible to smuggle in — see *Desktop artifacts* below.

## The gap list

Measured against `main` at `bc54419` (2026-08-27), before this document
existed. `(a)` is what the Worker expects, `(b)` is what the CLI updater
expects, `(c)` is what `release.yml` produced.

### 1. The Worker's manifest was never produced at all — **fixed**

The site is configured with `RELEASE_MANIFEST_ASSET=asterism-release-manifest.json`.
No release job wrote a file by that name; `gh release create` never uploaded
one. Even with tag `v0.1.0` present, `GET /api/releases/stable/manifest` would have returned
`404 not_found` for the asset fetch, forever.

Three separate mismatches sat behind that one missing file:

| | (a) Worker | (c) `release.yml` before |
| --- | --- | --- |
| asset name | `asterism-release-manifest.json` | `RELEASE.json` |
| shape | `{payload:{channel,tag,assets[{name,url,sha256,size?}]},signature}` | flat `{schema,channel,version,build_id,target,archive_url,…}` |
| signature | HMAC-SHA256 over `JSON.stringify(payload)`, base64url, shared secret | minisign detached signature over the file, separate `.sig` asset |
| tag field | `payload.tag` must equal the configured tag exactly | `version`, same value, different key |
| digests | `sha256` per asset, all assets | `archive_sha256` / `app_sha256` / `linux_*_archive_sha256`, CLI archives only |

Fixed by `scripts/render-worker-manifest.sh` plus a `publish` step that renders
and self-verifies the envelope, and `scripts/verify-worker-manifest.mjs` — a
transcription of the Worker's acceptance rules that runs in CI and in the
release job. `scripts/worker-manifest-test.sh` is its round-trip suite.

### 2. (a) and (b) genuinely disagree, and that is by design — **document, do not "unify"**

This is the one that looks like a bug and is not, so it is written down here
to stop someone "fixing" it:

- **The Worker's manifest describes a release.** It is a list of assets with
  digests, for one tag, for a browser and a website. It is signed with a
  secret the Worker holds so that the Worker can trust it.
- **`RELEASE.json` describes an upgrade.** It is a target triple, an archive
  URL, a minimum updater version and a build id, for one machine, and it is
  signed with a key whose public half ships in the installer so that a
  *client* can trust it without asking any server.

They must not be merged. Serving the update manifest through the Worker would
make asterism.run a trusted party in the update path, which the minisign
scheme exists to avoid; giving `update.sh` the Worker's envelope would require
shipping the HMAC secret to every client, which would make the signature
meaningless. Two documents, two trust domains.

What *was* a real inconsistency, and is fixed: they described different sets
of bytes. `RELEASE.json` covered the CLI archives; nothing covered the
Windows archive because no Windows archive existed.

### 3. No Windows artifact existed — **fixed**

`packaging/install.ps1` downloads `asterism-$Version-windows-x86_64.tar.gz`
(or `-arm64`) and refuses it unless it contains `ast.exe`, `astd.exe`,
`astd-hyperv.exe`, `asterism-update.ps1` and `install.ps1`.
`packaging/update.ps1 apply` re-invokes that installer.
`packaging/README.md` documents the tarball. `docs/PLATFORM.md` lists Windows
install as native. `release.yml` built no Windows binary and published no
Windows asset, so every one of those paths ended in a 404.

Fixed by `scripts/package-windows.ps1` and the `windows` / `verify-windows`
jobs, for both `windows-x86_64` (windows-latest) and `windows-arm64`
(windows-11-arm).

### 4. `RELEASE.json` targets only darwin-arm64

`render-release-manifest.sh` takes one `target` and the release job passes
`darwin-arm64` always, with Linux carried in optional
`linux_x86_64_*` / `linux_arm64_*` fields that `update.sh` swaps in by host
architecture. There are no Windows fields, which is consistent: Windows
updates through `update.ps1`, which re-runs `install.ps1` against
`SHA256SUMS` and never reads `RELEASE.json`. Left as is, recorded here so the
asymmetry is not mistaken for an omission.

### 5. `SHA256SUMS.sig` is documented but not produced

`packaging/README.md` lists `SHA256SUMS.sig` "when a signing key exists". No
job produces it and no reader reads it. Either produce it or drop the line;
not addressed here.

### 6. `update.sh` resolves stable through `releases/latest`, the Worker through a pinned tag

`update.sh` fetches
`https://github.com/medicalissue/asterism/releases/latest/download/RELEASE.json`,
while the Worker is pinned to `RELEASE_TAG_STABLE`. They will disagree the
moment a newer release is published and the site variable is not bumped. That
is deliberate — the site pins so a bad release cannot be served to the website
automatically — but bumping `RELEASE_TAG_STABLE` is a required post-cut step,
not an optional one. It is in the runbook below.

### 7. macOS code signing does not fail closed — **open, and a blocker for v0.1.0**

The `Import the signing certificate, if there is one` step falls back to an
**ad-hoc signature** when `MACOS_SIGN_CERT_P12` is absent, on a tagged push as
much as on a dry run. An ad-hoc-signed `astd-vz` carries the virtualization
entitlement and works for a locally built binary, but a tarball downloaded by
a browser is quarantined, and Gatekeeper blocks an ad-hoc binary that has no
notarization ticket. Cutting `v0.1.0` without the AST-91 macOS credentials
therefore produces a release that installs and then cannot start a VZ guest on
any machine that downloaded it through a browser.

This behaviour was left unchanged rather than turned into a hard failure,
because tightening it is a release-policy decision. Treat the macOS
credentials as a prerequisite, not an optimisation.

### 8. `install.ps1`'s checksum lookup has never been executed — **suspected defect**

`scripts/windows-host-test.sh` runs the PowerShell *parser* over `install.ps1`
and packages it into fixtures, but never executes its download-and-verify
path. The SHA256SUMS lookup in `Install-Release` — the thing standing between
a user and an unverified binary — has therefore never run in CI.

The first `verify-windows` job written for this document copied that lookup
idiom verbatim:

```powershell
$parts = $line.Split(@(' ', "`t"), [StringSplitOptions]::RemoveEmptyEntries)
if ($parts.Count -ge 2 -and ($parts[1] -eq $archive -or $parts[1] -eq "*$archive")) { … }
```

Against a real `SHA256SUMS` on a real runner — a file since confirmed
byte-for-byte correct, `<64 hex><space><space><name>\n`, LF, no BOM — it
matched nothing and the job failed with "SHA256SUMS does not list …" on both
`windows-x86_64` and `windows-arm64`. Replacing it with a single regex made
the same job pass against the same file. The root cause was not chased
further here, and the failure has not been reproduced against `install.ps1`
itself, so this is a strong suspicion rather than a proven defect — but
`install.ps1` would fail exactly this way, refusing every Windows release as
"unlisted", and nothing in CI would notice.

**This should be its own issue**: execute `install.ps1`'s verify path in CI,
and fix the parse if it reproduces. It is not fixed here because changing the
installer's security-critical path on a suspicion, without a test that runs
it, is the same mistake in the other direction.

### 9. Windows verification is weaker than macOS and Linux

The macOS and Linux lanes install the artifacts they just built with the real
installer over `file://`. The Windows lane cannot: `install.ps1` downloads
with `Invoke-WebRequest`, which has no `file://` transport. `verify-windows`
does the digest lookup the installer would do and runs the binaries the
installer would place, but the install/upgrade/uninstall path itself is
unproven in CI. Giving `install.ps1` a local-source branch would close this;
it was not done here because an untested change to the installer is worse than
a known gap in its test.

Two things about running Windows binaries from a workflow, both learned by
hanging a job on them, are worth keeping:

- **`astd-hyperv.exe` takes no arguments.** `main()` goes straight to
  `serve_once(stdin, stdout, …)` and blocks for a protocol frame, so
  `--help`, `--version` and every other flag hang forever rather than
  printing anything. Check the file, never invoke it; the protocol has its own
  suite in the `windows-hyperv` workflow.
- **Invoke through `Start-Process` with a deadline, not through `&`.** The
  call operator waits for the inherited stdout pipe to close, so a child that
  outlives the command hangs the step, and with no deadline that consumes the
  runner's entire budget while reporting nothing. `verify-windows` wraps every
  invocation in a bounded helper that kills and names whatever stalled.

## What a release contains

```
v0.1.0/
  asterism-v0.1.0-darwin-arm64.tar.gz    ast, astd, entitled astd-vz, asterism-update, guest/
  asterism-v0.1.0-linux-x86_64.tar.gz    ast, astd, Cloud Hypervisor v53.0, virtiofsd v1.14.0, updater, share/
  asterism-v0.1.0-linux-arm64.tar.gz     same layout, aarch64 Cloud Hypervisor pin
  asterism-v0.1.0-windows-x86_64.tar.gz  ast.exe, astd.exe, astd-hyperv.exe, asterism-update.ps1, install.ps1
  asterism-v0.1.0-windows-arm64.tar.gz   same layout
  SHA256SUMS                             every archive and every metadata file
  RELEASE.json                           the update manifest `ast update` reads
  RELEASE.json.sig                       its mandatory minisign detached signature
  asterism-release-manifest.json         the signed envelope the Worker reads
  asterism-v0.1.0-sbom.cdx.json          deterministic CycloneDX SBOM (AST-100)
  asterism-v0.1.0-licenses.json          deterministic third-party license manifest
  asterism.rb                            the Homebrew formula pinned to this tag
```

The Linux payloads carry the versions and digests pinned in
`packaging/linux-components.env`; `scripts/package-linux.sh` verifies each
download against that lock before it goes in the tarball, and a truncated lock
is a packaging failure rather than a partial install.

The `publish` job asserts this exact set by name before `gh release create`
runs. Adding an artifact means adding it to that list.

## Desktop artifacts — recommendation: a separate manifest

Desktop binaries are released by the private `medicalissue/asterism-gui`
repository. They cannot go in this manifest, and the reason is structural
rather than a matter of taste:

`isReleasePayload` requires every asset URL to begin with
`https://github.com/${env.RELEASE_REPOSITORY}/releases/download/${tag}/`. One
repository, one tag, checked per asset. A `medicalissue/asterism-gui` URL in
this manifest fails that check and takes the **entire** manifest down with it —
the CLI update endpoint included. There is no partial acceptance.

Even if the Worker were changed to allow a second repository, the URLs would
point into a private repository, where an unauthenticated download is a 404.
A public manifest advertising URLs no public client can fetch is worse than no
manifest.

The two products also version independently. Coupling them into one document
means a Desktop release cannot ship without re-cutting the CLI release.

**Recommendation: Desktop keeps its own manifest, its own asset name and its
own configured tag, served from its own route.** No change to this repository
is needed. The change the site repository would need, when Desktop is ready
(do not make it now — it is written here so it does not have to be
rediscovered):

1. `wrangler.jsonc` vars: `RELEASE_DESKTOP_REPOSITORY`,
   `RELEASE_DESKTOP_MANIFEST_ASSET`, `RELEASE_DESKTOP_TAG_STABLE`.
2. `worker/artifacts.ts`: lift the three configuration reads in
   `configuredRelease` into a parameter — a `{repository, asset, tags}` lane
   record — and thread the lane's `repository` through to
   `isReleasePayload`, which already takes it as an argument. Both the
   URL-prefix check and the 503 `release_not_configured` behaviour then apply
   per lane unchanged.
3. A `/release/desktop/:channel` route calling `getReleaseManifest` with the
   desktop lane.
4. A second Secrets Store entry only if the Desktop release job is a different
   trust domain; otherwise reuse `RELEASE_SIGNING_KEY`.

The signing scheme, the size limit and the digest requirements are identical,
so `scripts/render-worker-manifest.sh` renders a Desktop manifest as-is —
pass the Desktop repository and tag.

## Homebrew

`packaging/asterism.rb` is the source of truth and is deliberately HEAD-only:
`head` is a moving branch and no plain `brew install` should ever resolve to
it. The line `# release:stable-block` is a marker, and
`scripts/render-formula.sh <tag> [sha256]` replaces it with the `stable` and
`livecheck` blocks pinned to one tag and one source-tarball digest, leaving
the rest of the file untouched. The build job renders it; a dry run renders
with a placeholder digest, because GitHub only serves a tag's source tarball
once the tag is pushed.

The release job then opens a pull request against
`medicalissue/homebrew-asterism` with that exact file as
`Formula/asterism.rb`, after checking its digest against the release's own
`SHA256SUMS`. A pull request rather than a push: the tap's `brew audit
--strict` is what decides a formula is installable, and a release job should
not be able to bypass it. Merging is a human action.

That step needs `HOMEBREW_TAP_TOKEN` — a fine-grained PAT scoped to
`medicalissue/homebrew-asterism` with `contents:write` and
`pull_requests:write`. Without it the release still succeeds and the step
emits a warning telling you to copy the formula by hand; a published release
is never failed over a tap update.

Until the tap carries a stable block, `brew install
medicalissue/asterism/asterism` has nothing to resolve to and `--HEAD` is the
only thing that works. That is the placeholder the tap README describes.

## Cutting v0.1.0

### Prerequisites

All of these are AST-91 and none of them exist yet. Names are exact; a
misspelled secret name is an empty string, and several steps treat an empty
string as "not configured" rather than as an error.

| Name | Kind | Where | What it is |
| --- | --- | --- | --- |
| `UPDATE_MINISIGN_SECRET_KEY` | secret | `medicalissue/asterism` | base64 of the minisign `.key` file. Tagged builds **fail** without it. |
| `ASTERISM_UPDATE_PUBKEY` | **variable** | `medicalissue/asterism` | the minisign public key line. Required whenever the secret above is set. |
| `RELEASE_MANIFEST_HMAC_KEY` | secret | `medicalissue/asterism` | the Worker's shared signing secret, ≥8 characters. Tagged builds **fail** without it. |
| `ASTERISM_RELEASE_SIGNING_KEY` | Secrets Store entry | Cloudflare, store `5d74a5b1c50c4c388833812001e02bd6` | **byte-identical** to `RELEASE_MANIFEST_HMAC_KEY`. Bound in the Worker as `RELEASE_SIGNING_KEY`. |
| `MACOS_SIGN_CERT_P12` | secret | `medicalissue/asterism` | base64 Developer ID Application `.p12`. Absent, the release ships an ad-hoc signature — see gap 7. |
| `MACOS_SIGN_CERT_PASSWORD` | secret | `medicalissue/asterism` | its password. |
| `MACOS_SIGN_IDENTITY` | secret | `medicalissue/asterism` | the identity name; required if the `.p12` is set. |
| `APPLE_NOTARY_KEY_P8` | secret | `medicalissue/asterism` | base64 App Store Connect `.p8`. Required once a real identity is set — the notarize step fails without it rather than shipping a blocked binary. |
| `APPLE_NOTARY_KEY_ID` | secret | `medicalissue/asterism` | its key id. |
| `APPLE_NOTARY_ISSUER_ID` | secret | `medicalissue/asterism` | its issuer id. |
| `HOMEBREW_TAP_TOKEN` | secret | `medicalissue/asterism` | fine-grained PAT on the tap. Optional; its absence only skips the tap PR. |

Also check, before tagging:

- **`Cargo.toml` says `0.1.0`.** It says `0.0.2` today. The build job compares
  the tag against the workspace version and refuses the tag if they disagree,
  so the version bump is a separate, merged pull request that lands *before*
  the tag — not part of the cut. A dry run for `v0.1.0` fails at the first
  step until it lands, which is the gate working.
- The site's `RELEASE_TAG_STABLE` is `v0.1.0` (it already is), so the Worker
  starts serving the moment the release exists.
- No `v0.1.0` tag or release exists. The draft `v0.0.1` name-reservation stub
  is unrelated and can stay.

### Prove it first

```console
$ gh workflow run release.yml -f version=v0.1.0
```

Builds, packages and verifies every platform; the `publish` job is gated on
`github.event_name == 'push'` and does not run. This creates no tag, no
release and no tap PR. Do this and let it go green before tagging.

### The one command

Once the version bump above is merged to `main` and the dry run is green:

```console
$ git tag v0.1.0 && git push origin v0.1.0
```

That is the whole cut. The workflow refuses the tag if the tree's version
disagrees, builds macOS/Linux/Windows, installs the exact artifacts it built
with the exact scripts users run, signs both manifests, publishes the release,
and opens the tap pull request.

### After the cut

```console
# 1. The Worker serves the manifest it was pinned to.
$ curl -fsS https://asterism.run/api/releases/stable/manifest | jq '.tag, (.assets | length)'
$ curl -fsSI https://asterism.run/api/releases/stable/manifest | grep -i x-asterism-release-tag
```

`503 release_not_configured` means the site variables are unset;
`502 invalid_manifest` means the shape drifted; `502
invalid_manifest_signature` means `RELEASE_MANIFEST_HMAC_KEY` and
`ASTERISM_RELEASE_SIGNING_KEY` are not the same bytes.

```console
# 2. Homebrew, on a prefix that has never seen Asterism.
$ brew untap medicalissue/asterism 2>/dev/null; brew install medicalissue/asterism/asterism
$ ast --version && ast images | grep debian:13
```

This only works once the tap pull request is merged.

```console
# 3. `ast update` from a prior build.
$ ast update check     # reports the channel and the version it would move to
$ ast update apply
$ ast --version        # 0.1.0
```

`ast update` execs the installed `libexec/asterism/asterism-update`, so an
installation older than that layout has nothing to exec and must be
reinstalled once.

```console
# 4. And the plain installer, on each platform.
$ curl -fsSL https://asterism.run/install.sh | ASTERISM_VERSION=v0.1.0 sh
PS> irm https://asterism.run/install.ps1 | iex
```

### Rollback

A tag is immutable and a published release is a distribution event; the honest
rollback is forward. In order of preference:

1. **Before anyone has it** — within minutes, and only then:
   `gh release delete v0.1.0 --yes` and `git push --delete origin v0.1.0`.
   Point the site's `RELEASE_TAG_STABLE` back to nothing (`""` disables the
   channel and the Worker answers `503`) and redeploy.
2. **After it is out** — cut `v0.1.1`. Do not mutate `v0.1.0`'s assets:
   `update.sh` and `install.sh` both pin digests, and replacing bytes under a
   published digest turns every existing install's verification into a
   tamper error.
3. **To stop new installs immediately** without a new release — set the site's
   `RELEASE_TAG_STABLE` to `""` and redeploy the Worker. The website's update
   metadata goes to `503`; `install.sh` and `ast update`, which go straight to
   GitHub, are unaffected.
4. **To un-recommend a Homebrew version** — revert the tap's
   `Formula/asterism.rb` to the previous tag's copy. The tap is the only lane
   where "the current version" is a mutable statement.

If the Worker is serving a bad manifest but the release is fine, nothing needs
re-cutting: re-render the manifest from the released artifacts with
`scripts/render-worker-manifest.sh` and replace only that asset with
`gh release upload --clobber`. It is the one asset no digest covers.

## Testing the release machinery

```console
$ bash scripts/worker-manifest-test.sh          # the Worker envelope, end to end
$ bash scripts/install-test.sh                  # the installer's own suite
$ bash scripts/update-test.sh                   # the signed-transaction suite
$ bash scripts/release-vz-version-test.sh       # the astd-vz version/build gate
$ scripts/render-formula.sh v0.1.0 DRY-RUN-NO-DIGEST | head -20
```

`worker-manifest-test.sh` is the one that would catch the site and this
repository drifting apart. It transcribes `worker/artifacts.ts`; when that
file changes in `medicalissue/asterism-site`, change
`scripts/verify-worker-manifest.mjs` with it.
