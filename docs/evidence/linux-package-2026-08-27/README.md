# Native Linux package install and lifecycle — dev5, 2026-08-27

Real-host evidence for AST-41. It answers one question: can a user on a clean
supported Linux install a single file, with no Rust toolchain and no QEMU, and
get a device manager that boots a catalog image on real KVM — and does
removing that file put the host back?

**Result: green, after the gate found and forced the fix of a real packaging
defect (a missing `curl` dependency, below).**

## Artifact and host

- source: `claude/ast-41-evidence`, on top of `eb320a08` ("Ship native Linux
  .deb and .rpm packages (AST-41) (#28)")
- release payload: `asterism-0.0.2-ast41-linux-x86_64.tar.gz`, built by
  `scripts/package-linux.sh` in a `rust:bookworm` container
  - SHA-256 `ce36fd63e8d8889b2af5cf610e189e4a9885be3d24d6c2826d2599533709630d`
- packages: built from that payload by `scripts/build-linux-packages.sh` with
  nfpm 2.47.0, in an `ubuntu:22.04` container
  - `asterism_0.0.2-1_amd64.deb` SHA-256
    `c5c60085cd6f54b6cd0ed17ddb551cf4588a5e3ee848e6138704b2b64b96047e`
  - `asterism-0.0.2-1.x86_64.rpm` SHA-256
    `6b3d6c858aa4a2a67b7de8323d4e9a846d43b3bf6082f920aa4764062f29c8e4`
- host kernel: Linux `6.6.87.2-microsoft-standard-WSL2`, x86_64 (dev5)
- clean userspace: Ubuntu 26.04 container
  `ubuntu@sha256:2260313b31c8c011cd2eebe728008efac1b3982be73eb71348ea2648d2c0e09b`,
  the same base image the AST-108 evidence used
- hardware boundary: the container received only `/dev/kvm`, `/dev/net/tun`,
  `NET_ADMIN` and `NET_RAW`; it was not privileged and did not share the
  host's PID or network namespace
- no source tree was mounted into the container under test: only the `.deb`
  and the gate script

## Command under test

```sh
docker run --rm --device /dev/kvm --device /dev/net/tun \
  --cap-add NET_ADMIN --cap-add NET_RAW \
  -v .../packages:/pkg:ro -v .../e2e-linux-package.sh:/e2e.sh:ro \
  ubuntu:26.04 bash /e2e.sh /pkg/asterism_0.0.2-1_amd64.deb
```

`scripts/e2e-linux-package.sh` is the reproducible protocol. It refuses to
start on a host that has `cargo`, `rustc`, `gcc`, `cc` or `make`, or any
`qemu*` package, and re-checks the QEMU inventory after installation and
again after the lifecycle. Its terminal record:

```text
ok: no development tools and no previously installed Asterism
ok: package inventory carries no QEMU
ok: installed asterism_0.0.2-1_amd64.deb with its declared dependencies
ok: installing the package pulled in no QEMU
ok: the installed layout is the packaged layout
ok: wrapper ownership and VMM capability are what the post-install claims
ok: ast service install wrote exactly the two-line least-privilege NBD rule
ok: withdrew the broad sudo grant; the narrow rule is all that remains
ok: ast doctor reports the packaged paths with no environment override
ok: pull retained a verified image
ok: create records the explicit chv backend
ok: up booted the guest on the packaged Cloud Hypervisor
ok: ssh reached the guest (Linux x86_64)
ok: down and rm completed
ok: the whole lifecycle ran with no QEMU on the host
ok: removal left no files, units, or sudoers rules, and kept ~/.asterism
LINUX PACKAGE GREEN (asterism_0.0.2-1_amd64.deb, debian:13)
```

`ast doctor`, run by the unprivileged account with no environment override,
reported against the packaged paths:

```text
ok    kvm                 /dev/kvm opens read-write
ok    cloud-hypervisor    cloud-hypervisor v53.0 (/usr/libexec/asterism/cloud-hypervisor)
ok    virtiofsd           virtiofsd 1.14.0 (/usr/libexec/asterism/virtiofsd)
ok    linux-pins          Cloud Hypervisor v53.0 and virtiofsd v1.14.0
ok    nbd-helper          privileged helper probe succeeded through sudo (/usr/libexec/asterism/asterism-nbd)
```

## What the gate found: the missing `curl` dependency

The first full run installed cleanly, passed every layout and permission
check, passed `ast doctor` — and then could not pull a single byte:

```text
Error: fetching the guest kernel from https://cloud-images.ubuntu.com/.../vmlinuz-generic
```

That is not flakiness, and it was not diagnosed by guessing. `curl` fetched
the same URL from the same host in four seconds (`http=200 size=15055240`),
so the mirror was fine. A retry around the fetch failed three times. Two
controlled A/B runs in fresh containers settled it:

| variable | pull |
|---|---|
| `ca-certificates` absent vs. installed | fails either way (and it is already in the dependency closure) |
| `curl` absent | `rc_without_curl=1` |
| `curl` installed | `rc_with_curl=0` — resolved, kernel, layers, stored |

`asterism_core::oci` resolves `tool("curl")` and execs it for every image
layer and for the pinned guest kernel. Neither package declared it.
`packaging/install.sh` never had to: nobody who runs
`curl -fsSL https://asterism.run/install.sh | sh` can be missing curl. A
package installed with `apt-get install ./asterism.deb` on a minimal image
absolutely can be, and the failure mode is a host that looks healthy in
`doctor` and cannot fetch an image.

The fix is `curl` in `depends` for both families, and a CI assertion on both
so it cannot regress. The first hypothesis — missing CA certificates — was
wrong, and the A/B is what disproved it rather than reasoning.

Two adjacent findings are recorded as their own issues rather than fixed
here: the CLI printed only the outermost context and swallowed anyhow's
`Caused by:` chain, so `curl not found — is it installed and on PATH?` never
reached the operator (**AST-141**), and `doctor`'s receipt check warns "this
tree was not installed by install.sh" for a perfectly good packaged install
(**AST-140**).

## Proves

- a `.deb` built from the release payload installs on a clean Ubuntu 26.04
  with no development tools present, resolving only its declared
  dependencies, and pulls in no `qemu*` package — checked against the dpkg
  inventory and the fixed paths before, after install, and after the
  lifecycle;
- the installed layout is the packaged layout: `/usr/bin/{ast,astd}`,
  `/usr/libexec/asterism/{cloud-hypervisor,virtiofsd,asterism-nbd,asterism-nbd-policy}`,
  `/usr/lib/asterism/guest/bin/asterism-guest`,
  `/usr/lib/systemd/user/astd.service`, the `modules-load.d` and
  `modprobe.d` snippets, `/usr/share/asterism/linux-components.env`, and the
  bundled components' license texts;
- the NBD privilege wrapper is installed `root:root` mode `0755`, and the
  post-install granted the bundled Cloud Hypervisor `cap_net_admin` and
  nothing else;
- `ast service install`, run by an unprivileged account, wrote exactly the
  two-line least-privilege rule at `/etc/sudoers.d/asterism-nbd-<uid>`,
  naming the packaged wrapper and the packaged VMM path — and the broad
  admin grant was then withdrawn, so everything below ran on that rule alone;
- `ast doctor` resolved every pinned component by its packaged path with no
  environment override, and its `nbd-helper` probe executed the root-owned
  wrapper through sudo under that narrow rule;
- `create --backend chv --image debian:13`, `up`, `ssh`, `down` and `rm`
  completed against the packaged install: a real guest booted on the bundled
  Cloud Hypervisor over KVM and answered over SSH as `Linux x86_64`;
- package removal left no Asterism files, no unit, no `tmpfiles`/module
  snippets, no NBD lock or claim directory, and no sudoers rule, while
  `~/.asterism` was kept.

## Does not prove

- **reboot recovery.** A container has no init, no `systemd --user`, and no
  `loginctl`, so `ast service install` writes the unit and reports that
  `systemctl` is absent rather than enabling it. Lingering, restart after
  logout, and persistent instances coming back after a host reboot are out
  of scope for a container and remain an open gate against a real
  installation. `doctor` correctly reported `fail linger` and `fail sleep`
  here for exactly that reason.
- **the `.rpm` on a Fedora host.** It is built from the same description and
  the same payload, and its file list and requirements — including `curl` —
  are asserted in CI, but no Fedora host installed it.
- **the signed updater over a package.** `ast update apply` refuses a
  package-managed install by design and names the distribution command; that
  refusal was not exercised against a published signed channel.
- **Secret Service.** The container has no session bus and no provider, so
  the secret paths were not exercised; `doctor` reported the absence rather
  than falling back, which is the designed behaviour and not evidence about
  a desktop host.
- **arm64.** Only `linux-x86_64` was built and installed.
- **a physical machine, another distribution, another kernel, or another
  filesystem.**

Those remain independent gates; this result must not be promoted into them.
