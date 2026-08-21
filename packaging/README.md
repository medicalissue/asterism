# Packaging

Two things ship from this repository and they ship separately:

| | what it is | how it is installed |
|---|---|---|
| **CLI** | `ast` and the `astd` daemon | `install.sh`, or Homebrew |
| **Desktop app** | the menu bar app in `gui/` | a signed `.dmg`, dragged to Applications |

They are deliberately not one artifact. The CLI is a pair of binaries that
belong on `PATH` and get upgraded from a shell; the app is a bundle macOS
wants to notarize and quarantine. Bundling the CLI inside the app would put
the daemon somewhere `brew upgrade` could not reach, and shipping the app
through a tarball would strip the signature people are relying on. The
installer never touches the DMG and the DMG never writes to `~/.local/bin`.

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
4. Both binaries are staged beside their destination and renamed into place,
   so an interrupted upgrade cannot leave half a binary where a working one
   was.
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
| `ASTERISM_BASE_URL=URL` | where release assets live — a mirror, or a local directory for tests |
| `ASTERISM_INDEX_URL=URL` | JSON naming the latest tag |

### What a release contains

```
v0.1.0/
  asterism-v0.1.0-darwin-arm64.tar.gz   # ast and astd, flat, no directory prefix
  asterism.rb                           # the Homebrew formula for this tag
  SHA256SUMS                            # shasum -a 256 of both of the above
  SHA256SUMS.sig                        # when a signing key exists
```

The tarball is flat on purpose: the installer unpacks it and expects `ast` and
`astd` at the top, and refuses a tarball missing either rather than installing
half a release.

### Platforms

Binaries are published for **macOS on Apple silicon** (`darwin-arm64`), and
that is the whole list. Every other host is refused by name and pointed at
the source build; there is no near-enough target, because a near-enough
binary is one that does not run.

```console
$ curl -fsSL https://asterism.run/install.sh | ASTERISM_METHOD=source sh
```

The source path still builds a **tag** by default. `ASTERISM_REF=main` is the
only way to get the moving branch, and the script says out loud that that is
what you asked for.

### Signatures

Asterism does not publish a signing key yet, so the signature check is a seam
rather than a promise: if `SHA256SUMS.sig` is published and both a verifier
(`minisign` or `signify`) and `ASTERISM_PUBKEY` are present, it is checked.
`ASTERISM_REQUIRE_SIGNATURE=1` turns every absence in that sentence into a
refusal — which is the flag to make the default once a key exists.

Until then, `ASTERISM_SHA256` is the strong option: it verifies the download
against a digest you brought yourself, so nothing the release host says is
trusted.

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
```

Hermetic: it builds a fake release on disk, serves it over `file://`, and
shims `uname`, `git` and `cargo` where a test needs the machine to be a
machine it is not. No network, and nothing is written outside one temp
directory. Twenty-five checks: the default install, an explicit version,
a pinned digest, upgrade, downgrade, reinstall, `ASTERISM_FORCE`, uninstall
and uninstalling twice, a tampered tarball, an unlisted artifact, a missing
`SHA256SUMS`, an unreachable index, unreachable assets, four unsupported
hosts, an unwritable prefix, the source escape hatch with and without
`ASTERISM_REF`, and the Homebrew path with a tampered formula. It also
asserts the script still passes `sh -n` and `shellcheck`, still names no
`master` branch, and still has exactly one `sudo` in it.

## Licensing

`depends_on "qemu"` asks Homebrew to install QEMU under its own terms.
Asterism never ships a QEMU binary and never links QEMU code; on the release
path QEMU is not installed at all, only mentioned when it is missing.
