# Packaging

The CLI ships from this repository:

| | what it is | how it is installed |
|---|---|---|
| **CLI** | `ast`, the `astd` daemon, and the code-signed `astd-vz` helper | `install.sh`, or Homebrew |
The CLI binaries belong on `PATH` and get upgraded from a shell. Desktop is
released privately and is not built or packaged from this source tree. The
updater deliberately retains its authenticated Desktop-manifest boundary: a
private manifest can provide matching app metadata, which the updater verifies
and activates with the CLI unit using same-filesystem renames. Any partial
replacement or daemon restart failure restores the entire previous unit.
Running guests are left alive for the restarted daemon to re-adopt, and a
signed channel is never allowed to downgrade an installed release.

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
  asterism-v0.1.0-linux-x86_64.tar.gz   # ast, astd, guest-gpu/, cloud-hypervisor, virtiofsd, updater, share/
  asterism-v0.1.0-linux-arm64.tar.gz    # same layout, aarch64 Cloud Hypervisor pin
  asterism-v0.1.0-windows-x86_64.tar.gz # ast.exe, astd.exe, astd-hyperv.exe, both update scripts
  asterism-v0.1.0-windows-arm64.tar.gz  # same layout
  RELEASE.json                          # exact build, URLs, digests, minimum updater
  RELEASE.json.sig                      # mandatory detached update signature
  asterism-release-manifest.json        # the signed envelope the asterism.run Worker reads
  asterism.rb                           # the Homebrew formula for this tag
  asterism-v0.1.0-sbom.cdx.json         # deterministic CycloneDX dependency SBOM
  asterism-v0.1.0-licenses.json         # deterministic third-party license manifest
  SHA256SUMS                            # hashes payloads, metadata, and formula
```

`RELEASE.json` and `asterism-release-manifest.json` are two different
documents for two different readers, signed with two different keys under two
different schemes — see [`docs/RELEASE.md`](../docs/RELEASE.md), which is the
single reference for how a release is cut and what signs what.

The CLI tarball is flat on purpose: the installer unpacks it and expects `ast` and
`astd` at the top, and refuses a tarball missing either rather than installing
half a release.

### Supply-chain metadata

Every release also publishes a CycloneDX 1.5 SBOM and a compact third-party
license manifest. Both are generated only from the committed Rust lockfile,
sorted by package URL, and intentionally contain neither a timestamp nor a
generated UUID. Re-running
`node scripts/generate-supply-chain-metadata.mjs --out DIR --version vX.Y.Z`
against the same lockfile produces byte-identical files. `SHA256SUMS` covers
both metadata files alongside the shipped binaries.

The CI supply-chain job audits those exact lockfiles, scans all reachable Git
history and the checked-out tree locally for secrets, and tests the generator
twice for deterministic output. Its exception policy is documented in
[`docs/supply-chain-exceptions.md`](../docs/supply-chain-exceptions.md).

Desktop artifacts and their signed manifest are published by the private
Desktop release process. The public updater consumes that authenticated
manifest boundary without rebuilding or redistributing Desktop source.

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
argument-checking NBD helper plus the exact `setcap cap_net_admin+ep`
invocation the transactional updater needs for that one installed VMM path.
`ast service install` writes the systemd
user unit; lingering (`loginctl enable-linger`) is what keeps that unit
alive after logout. `ast doctor` executes the pinned helpers, NBD wrapper,
and Secret Service rather than checking that files exist.

Windows installs with the native PowerShell installer or the POSIX script
under Git Bash:

```console
irm https://asterism.run/install.ps1 | iex
curl -fsSL https://asterism.run/install.sh | sh     # Git Bash; detects MINGW/MSYS
```

A Windows tarball is `ast.exe`, `astd.exe`, `astd-hyperv.exe`, the updater,
and the matching `install.ps1` that the installed updater invokes. The helper
and both update scripts are required: there is no WHPX/QEMU product fallback.
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
renders the flat manifest only after the CLI archive has been assembled and
hashed, signs it with the base64-encoded `UPDATE_MINISIGN_SECRET_KEY`, and
compiles `ASTERISM_UPDATE_PUBKEY` into the CLI. The private Desktop release
uses the same authenticated manifest contract. A missing key or signature is a
refusal, as are a digest mismatch, wrong target, build-identity mismatch,
unsupported minimum updater, or downgrade. Tagged publishing fails closed when
the signing secret is absent.
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

The runbook — prerequisites by exact secret name, post-cut verification and
rollback — is [`docs/RELEASE.md`](../docs/RELEASE.md). In short:

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

## OCI VM guest-control artifact

Direct-kernel OCI images cannot be assumed to contain Python, systemd, SSH, or
even a shell. Release archives therefore carry an architecture-matched static
Linux ELF at `guest/bin/asterism-guest`. The installer places it at
`bin/guest/bin/asterism-guest` beside `astd`; the updater treats it as a
transactional component and rolls it back with the CLI and daemon.

Linux release packaging builds and audits the agent for the release
architecture. The Apple arm64 release consumes the audited Linux arm64
artifact from the matching Linux release job, because the binary runs inside
the Linux guest rather than on macOS. A missing or wrong-architecture artifact
is an OCI boot refusal, never a VM silently launched without control.

Linux source installs build the artifact with the matching musl target. macOS
source installs do not yet cross-build it; OCI/VZ source-tree testing there
must provide an audited matching Linux ELF through
`ASTERISM_GUEST_AGENT_ARTIFACT`. Tagged macOS releases include it.

## Licensing

The Homebrew formula and release installer do not install QEMU. Native VZ and
Cloud Hypervisor are the product paths, and qcow2-to-raw materialisation is
implemented in Rust. QEMU remains an optional compatibility backend installed
separately under its own terms; Asterism never ships or links its code.
The formula likewise obtains the standalone `minisign` verifier from Homebrew;
neither verifier code nor its binary is bundled into Asterism.
