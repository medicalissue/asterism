# Native catalog lifecycle without QEMU — macOS VZ, 2026-08-27

This is the macOS half of AST-108's real-host acceptance gate. It proves that
an arm64 Mac whose PATH and Homebrew inventory contain no QEMU can pull a
catalog qcow2, materialise sparse raw in-process, boot it with
Virtualization.framework, reach the guest over SSH, and clean it up.

## Build and host

- source: `edf2267c58673de3679ff1d4080b73bc3cb436c2`
- build id: `0.0.2+edf2267c5867`
- `ast` SHA-256:
  `0093e6cf83da13309ad333cadaaae9255d30ad198b755a0fd8499248cb02d17b`
- host: macOS 26.5.2 build 25F84, arm64 Apple silicon
- backend: the source-built `astd-vz`, ad-hoc signed with the
  `com.apple.security.virtualization` entitlement
- image: the catalog's current `debian:13` arm64 cloud image

Homebrew QEMU 11.1.0 had no installed reverse dependency. Its bottle was
fetched first, then the formula was uninstalled. Homebrew also removed six
now-unneeded QEMU dependencies. Before doing any build or pull, the gate
confirmed that `qemu-img` and `qemu-system-*` were absent from PATH and their
fixed Homebrew/system locations, and that `brew list --formula` contained no
`qemu` formula.

## Command and result

A new Cargo target directory prevented an older workspace artifact from being
mistaken for the source under test. The gate ran outside the tool sandbox
because the sandbox deliberately forbids the local Unix socket the real daemon
owns:

```sh
CARGO_TARGET_DIR=/private/tmp/asterism-ast108-vz-target \
bash scripts/e2e-native-no-qemu.sh
```

Its successful terminal record was:

```text
signed /private/tmp/asterism-ast108-vz-target/debug/astd-vz as - (com.apple.security.virtualization)
ok: pull verified qcow2 without QEMU and deferred raw materialisation
ok: create records the explicit vz backend
ok: first vz use atomically published sparse raw with provenance
ok: ssh reached the guest running on vz (Linux aarch64)
NATIVE NO-QEMU GREEN (vz, debian:13; allocated 1239728128 of 3221225472 bytes)
```

The gate completed `down` and `rm`, rechecked the clean QEMU inventory, and
exited 0. QEMU 11.1.0 was then reinstalled from Homebrew together with its
dependencies; `qemu-img --version` again reports 11.1.0. The validation did
not leave the developer machine without its compatibility backend.

## Does not prove

- Developer ID signing, notarization, a Homebrew bottle install, or another
  macOS release;
- Intel macOS or foreign-architecture emulation;
- VZ NBD terminal-failure, directory, secret-egress, or endpoint parity;
- Linux CHV, Windows Hyper-V, or a multi-device lifecycle.

The Linux/CHV half is recorded separately in
`docs/evidence/native-no-qemu-dev5-2026-08-27/README.md`.
