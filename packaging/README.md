# Packaging

Two things ship from this repository and they ship separately:

| | what it is | how it is installed |
|---|---|---|
| **CLI** | `ast`, the `astd` daemon, and the code-signed `astd-vz` helper | `install.sh`, or Homebrew |
| **Desktop app** | the menu bar app in `gui/` | a signed `.dmg`, dragged to Applications |

They are deliberately not one artifact. The CLI is a pair of binaries that
belong on `PATH` and get upgraded from a shell; the app is a bundle macOS
wants to notarize and quarantine. Bundling the CLI inside the app would put
the daemon somewhere `brew upgrade` could not reach. The app tarball is
reserved for the authenticated updater; the DMG supplies the notarized,
stapled container and familiar Applications shortcut expected for a manual
install. The installer never touches the DMG and the DMG never writes to
`~/.local/bin`.

After installation they do, however, upgrade as one compatible unit. Both the
desktop app's Updates controls and `ast update` invoke the same updater and the
same signed manifest. The updater verifies exact build identities for `ast`,
`astd`, `astd-vz`, and the app before replacing anything; it then activates
them with same-filesystem renames. Any partial replacement or daemon restart
failure restores the entire previous unit. Running guests are left alive for
the restarted daemon to re-adopt, and a signed channel is never allowed to
downgrade an installed release.

```console
$ ast update status
$ ast update channel stable       # also beta or nightly
$ ast update check                # verifies metadata only
$ ast update apply --yes          # downloads, verifies, activates atomically
```

Homebrew remains a separate ownership lane: status reports `manager homebrew`,
check may report an available signed release, and apply refuses with the exact
`brew upgrade asterism` command instead of writing into the Cellar.

## What an install resolves to

`install.sh` installs **one tagged release**, always:

1. A version is resolved — `ASTERISM_VERSION` if set, otherwise the latest
   release tag, read once from the GitHub API.
2. Every URL after that is built from that tag. Nothing downstream fetches a
   `latest` alias, so a release cut mid-install cannot swap bytes underneath
   it.
3. The tarball is checksummed against `SHA256SUMS`, published beside it under
   the same tag. A mismatch, a missing `SHA256SUMS`, or an artifact not listed
   in it is a refusal, and nothing is written.
4. Every binary is staged beside its destination and renamed into place, so
   an interrupted upgrade cannot leave half a binary where a working one was.
5. A receipt lands in `<prefix>/share/asterism/install-receipt.env` recording
   the version, target, method, digest, and the exact files written.

The receipt is what makes upgrade and uninstall exact. Re-running the script
on an up-to-date machine downloads nothing and says so; `--uninstall` deletes
the files the receipt names and nothing else, and leaves `~/.asterism` alone.

```console
$ curl -fsSL https://asterism.run/install.sh | sh                    # latest release
$ curl -fsSL https://asterism.run/install.sh | ASTERISM_VERSION=v0.1.0 sh
$ sh install.sh --uninstall
```

### Everything it takes from the environment

| variable | effect |
|---|---|
| `ASTERISM_VERSION=v0.1.0` | install exactly this tag (default: the latest release) |
| `ASTERISM_METHOD=` | `release` (default), `source`, or `brew` |
| `ASTERISM_PREFIX=DIR` | install prefix (default: `~/.local`) |
| `ASTERISM_FORCE=1` | reinstall a version that is already there |
| `ASTERISM_YES=1` | answer yes to prompts, for CI |
| `ASTERISM_SHA256=HEX` | pin the tarball digest by hand; `SHA256SUMS` is then not fetched at all |
| `ASTERISM_REQUIRE_SIGNATURE=1` | refuse unless the signature on `SHA256SUMS` verifies |
| `ASTERISM_PUBKEY=KEY` | minisign/signify public key to verify with |
| `ASTERISM_REF=main` | `source`/`brew` only: build this git ref instead of a tag |
| `ASTERISM_TAP=user/tap` | brew only: the tap to install from |
| `ASTERISM_PIN_TAP=user/tap` | brew only: the tap to build when the one above does not pin the requested version |
| `ASTERISM_BASE_URL=URL` | where release assets live — a mirror, or a local directory for tests |
| `ASTERISM_INDEX_URL=URL` | JSON naming the latest tag |

### What a release contains

```
v0.1.0/
  asterism-v0.1.0-darwin-arm64.tar.gz   # ast, astd, astd-vz, asterism-update — flat
  asterism-v0.1.0-linux-x86_64.tar.gz   # ast, astd, cloud-hypervisor, virtiofsd, asterism-update, share/
  asterism-v0.1.0-linux-arm64.tar.gz    # same layout, aarch64 Cloud Hypervisor pin
  Asterism-v0.1.0-darwin-arm64.app.tar.gz # signed app payload used by the updater
  Asterism-v0.1.0-darwin-arm64.dmg      # signed manual installer; drag to Applications
  RELEASE.json                          # exact build, URLs, digests, minimum updater
  RELEASE.json.sig                      # mandatory detached update signature
  asterism.rb                           # the Homebrew formula for this tag
  asterism-v0.1.0-sbom.cdx.json         # deterministic CycloneDX dependency SBOM
  asterism-v0.1.0-licenses.json         # deterministic third-party license manifest
  SHA256SUMS                            # hashes payloads, metadata, DMG, and formula
  SHA256SUMS.sig                        # when a signing key exists
```

The CLI tarball is flat on purpose: the installer unpacks it and expects `ast` and
`astd` at the top, and refuses a tarball missing either rather than installing
half a release.

### Supply-chain metadata

Every release also publishes a CycloneDX 1.5 SBOM and a compact third-party
license manifest. Both are generated only from the committed CLI/daemon and GUI
Rust lockfiles plus the GUI npm lockfile, sorted by package URL, and
intentionally contain neither a timestamp nor a generated UUID. Re-running
`node scripts/generate-supply-chain-metadata.mjs --out DIR --version vX.Y.Z`
against the same locks produces byte-identical files. `SHA256SUMS` covers both
metadata files alongside the shipped binaries and app artifacts.

The CI supply-chain job audits those exact lockfiles, scans all reachable Git
history and the checked-out tree locally for secrets, and tests the generator
twice for deterministic output. Its exception policy is documented in
[`docs/supply-chain-exceptions.md`](../docs/supply-chain-exceptions.md).

The app tarball remains the signed update channel's payload; it is not the
manual installer. For a first desktop install, open the DMG and drag
`Asterism.app` to its Applications shortcut. Both app artifacts are made from
the same signed bundle. With Developer ID and notary credentials the workflow
notarizes and staples both the app and its DMG container; a credential-free dry
run uses an ad-hoc signature and still mounts the DMG and runs the bundled app's
version and immutable build-id checks.

### The vz helper

`astd-vz` is the third binary, and it is the only one that has to be
code-signed. Virtualization.framework refuses to create a machine in a process
that does not carry `com.apple.security.virtualization`, and it refuses the
NBD attachment behind network disks without `com.apple.security.network.client`
— so an unsigned helper is not a degraded helper, it is one that cannot boot
anything. `astd` checks both entitlements in `probe()` and declines the vz
backend in words rather than failing inside the framework later.

`scripts/sign-vz.sh` is the one signing recipe: a developer runs it after every
`cargo build`, the source and Homebrew install paths run it as they build, and
the release workflow runs it with `--sign-only` on the stripped release binary.
`strip` rewrites a binary and so invalidates whatever signature was on it,
which is why signing is always the last thing done to these bytes.

Both entitlements are unrestricted, so **an ad-hoc signature carrying them is
enough** — no Apple account is involved, and that is what a release is signed
with by default. What ad-hoc does not survive is Gatekeeper *assessment*, and
assessment is triggered by the quarantine flag:

* `curl -fsSL https://asterism.run/install.sh | sh` — neither curl nor wget
  sets the flag, so nothing installed this way is ever assessed. The helper
  runs.
* Downloading the tarball in a **browser** and unpacking it by hand — the
  archive is quarantined, `tar` hands the flag to every file it extracts, and
  Gatekeeper kills the helper at `exec`. Not "vz is unavailable": signal 9, and
  nothing printed. `astd` refuses such a helper in `probe()` rather than let
  that happen, which is why the message names the flag.
* Pointing `ASTERISM_BASE_URL` at that same downloaded directory is fine. The
  installer re-fetches the archive into a workspace of its own, and neither
  curl nor wget carries the flag onto what they write; it then clears the flag
  from the binaries it installed anyway, so the guarantee does not rest on that
  behaviour. Either way nothing is written before the bytes have been checked
  against the release's `SHA256SUMS` — a stronger statement about them than the
  flag was making.

Setting `MACOS_SIGN_CERT_P12`, `MACOS_SIGN_CERT_PASSWORD` and
`MACOS_SIGN_IDENTITY` on the repository moves the release onto a Developer ID
signature — hardened runtime, trusted timestamp — and then
`APPLE_NOTARY_KEY_P8`, `APPLE_NOTARY_KEY_ID` and `APPLE_NOTARY_ISSUER_ID`
notarize the binaries, which is what makes the browser-download path work too.
A bare Mach-O cannot be stapled, so that ticket is fetched online; the tarball
stays exactly what it is today either way.

### Platforms

Binaries are published for **macOS on Apple silicon** (`darwin-arm64`),
**Linux on x86-64 and arm64** (`linux-x86_64`, `linux-arm64`). Windows 11
Pro/Enterprise (`windows-x86_64`, `windows-arm64`) is a release-integration
target: the installer, updater, SCM, doctor, firewall, and native Hyper-V
helper seams are in this tree. Real-host lifecycle remains a separate
evidence gate. Every other host is refused by name and pointed at the source
build; there is no near-enough target, because a near-enough binary is one
that does not run.

A Linux archive is flat and self-contained: `ast`, `astd`, the pinned
Cloud Hypervisor v53.0 static binary, virtiofsd v1.14.0, the signed
updater, the NBD privilege wrapper, component lock file, and licenses.
Installation needs neither a Rust toolchain nor a separately installed VMM.
The installer grants the bundled VMM only `CAP_NET_ADMIN`, loads `nbd`
with 64 devices, and installs a least-privilege sudoers rule for the
argument-checking NBD helper. `ast service install` writes the systemd
user unit; lingering (`loginctl enable-linger`) is what keeps that unit
alive after logout. `ast doctor` executes the pinned helpers, NBD wrapper,
and Secret Service rather than checking that files exist.

Windows installs with the native PowerShell installer or the POSIX script
under Git Bash:

```console
irm https://asterism.run/install.ps1 | iex
curl -fsSL https://asterism.run/install.sh | sh     # Git Bash; detects MINGW/MSYS
```

A Windows tarball is `ast.exe`, `astd.exe`, `astd-hyperv.exe`, and the
updater. The helper is required: there is no WHPX/QEMU product fallback.
SHA-256 is mandatory. Authenticode is checked when
`ASTERISM_AUTHENTICODE_THUMBPRINT` is set or `ASTERISM_REQUIRE_SIGNATURE=1`.
An elevated install lands in Program Files so SCM may use LocalSystem; a
per-user prefix is refused as a service ImagePath. `ast doctor` Probes
`astd-hyperv` and matches the inbound firewall rule named
`Asterism device daemon` for `astd.exe`. The updater claims a transaction
and rolls back on failure.

```console
$ curl -fsSL https://asterism.run/install.sh | sh
$ ast service install
$ loginctl enable-linger "$USER"
$ ast doctor
```

The source path still builds a **tag** by default. `ASTERISM_REF=main` is the
only way to get the moving branch, and the script says out loud that that is
what you asked for.

### Installer signatures

Asterism does not publish a signing key yet, so the signature check is a seam
rather than a promise: if `SHA256SUMS.sig` is published and both a verifier
(`minisign` or `signify`) and `ASTERISM_PUBKEY` are present, it is checked.
`ASTERISM_REQUIRE_SIGNATURE=1` turns every absence in that sentence into a
refusal — which is the flag to make the default once a key exists.

Until then, `ASTERISM_SHA256` is the strong option: it verifies the download
against a digest you brought yourself, so nothing the release host says is
trusted.

### Update-channel signatures

In-app updates are stricter than the bootstrap installer: `RELEASE.json.sig`
and an embedded minisign/signify public key are mandatory. The release workflow
renders the flat manifest only after both archives have been assembled and
hashed, signs it with the base64-encoded `UPDATE_MINISIGN_SECRET_KEY`, and compiles
`ASTERISM_UPDATE_PUBKEY` into both CLI and app-facing builds. A missing key or
signature is a refusal, as are a digest mismatch, wrong target, build-identity
mismatch, unsupported minimum updater, or downgrade. Tagged publishing fails
closed when the signing secret is absent.
Verification uses `minisign` (or the compatible `signify` command); its
absence is a fail-closed refusal. The Homebrew formula installs `minisign` as
a runtime dependency, while other installation lanes must provide one of the
two verifiers.

## Homebrew

The formula here is **HEAD-only on purpose**. `head` points at `main`, which
moves, and no plain `brew install` should ever resolve to it. The tap's copy
is this file with a `stable` block rendered in:

```console
$ scripts/render-formula.sh v0.1.0 > Formula/asterism.rb
```

That pins one tag and one source-tarball digest. The release workflow renders
it and attaches it to the release, so updating the tap is a copy, not an edit.

Until the tap is published, `ASTERISM_METHOD=brew` stands up a local tap
holding this one formula — the **rendered** one published with the release,
checked against that release's `SHA256SUMS` before Homebrew is pointed at it.
The repository's HEAD-only copy is used only for an explicitly requested
`ASTERISM_REF`.

That local tap is refreshed on every version change, and a stamp file beside
the formula records which release it was rendered for. Without it, a tap built
for v0.1.0 would be reused when v0.2.0 is the version being installed, and
Homebrew — which resolves whatever the formula in the tap says — would
install v0.1.0 again.

A tap with no stamp was not built here. It is a published tap: the distributor
of record, kept current by Homebrew, and never written to by this script. But
a published tap pins exactly one version, and someone who names a different
one with `ASTERISM_VERSION` is owed that version rather than the tap's. So
when the two disagree, the install comes from `ASTERISM_PIN_TAP` (`<tap>-pin`
by default) — a second tap this script builds, stamps and verifies the same
way — and the published tap is left exactly as it was found. Asking again for
the version the published tap does pin goes back to using it directly.

Moving between releases is an uninstall followed by an install, not a
`brew upgrade` or a `brew reinstall`. Upgrade refuses to go backwards, and a
named version has to be reachable from either direction; reinstall reinstalls
what is already there, which is the wrong formula when the version being
installed lives in a different tap. Every command is printed before it runs.

## Cutting a release

```console
$ gh workflow run release.yml -f version=v0.1.0    # dry run: build, checksum, test
$ git tag v0.1.0 && git push origin v0.1.0         # the real thing
```

The workflow refuses a tag whose version does not match `Cargo.toml`, builds
the binaries, writes `SHA256SUMS`, and then installs **those exact artifacts**
with **this exact script** on a clean runner — over `file://`, from the
download directory — before anything is published. It checks that `ast
--version` reports the tagged version, that re-running is a no-op, that
uninstall puts the machine back, and that a tampered tarball is refused. If
any of that fails, there is no release.

## Testing the installer

```console
$ bash scripts/install-test.sh
$ bash scripts/update-test.sh
```

Both are hermetic. The ten-check update suite covers signature and artifact tampering,
metadata-only checks, full app/CLI/daemon/helper activation, injected partial
activation rollback, downgrade refusal, and Homebrew delegation. The installer
suite builds a fake release on disk, serves it over `file://`, and
shims `uname`, `git` and `cargo` where a test needs the machine to be a
machine it is not. No network, and nothing is written outside one temp
directory. The suite covers the default install, an explicit version,
a pinned digest, upgrade, downgrade, reinstall, `ASTERISM_FORCE`, uninstall
and uninstalling twice, a tampered tarball, an unlisted artifact, a missing
`SHA256SUMS`, an unreachable index, unreachable assets, unsupported
hosts, a Linux exact-artifact install of the pinned Cloud Hypervisor and
virtiofsd helpers plus NBD policy (including live-claim uninstall refusal
and the shared artifact lock), an unwritable prefix, and the source
escape hatch with and without `ASTERISM_REF`.

The Homebrew path gets its own eight, all asserting on the version the tap's
formula actually pinned rather than on what the script said it would do —
which is the only way to catch a tap quietly serving a version nobody asked
for. A first install, a no-op re-run, a two-release upgrade and downgrade,
and then the published-tap cases: a published tap that pins the resolved
version is used as it stands; one that does not is left byte-for-byte
unchanged and unstamped while the requested version is installed from the pin
tap; asking again for the published version goes back to the published tap;
an unstamped formula in either tap is refused rather than overwritten; and a
tampered formula is refused before Homebrew sees it.

It also asserts the script still passes `sh -n` and `shellcheck`, still names
no `master` branch, and still has exactly one `sudo` in it.

## Licensing

`depends_on "qemu"` asks Homebrew to install QEMU under its own terms.
Asterism never ships a QEMU binary and never links QEMU code; on the release
path QEMU is not installed at all, only mentioned when it is missing.
The formula likewise obtains the standalone `minisign` verifier from Homebrew;
neither verifier code nor its binary is bundled into Asterism.
