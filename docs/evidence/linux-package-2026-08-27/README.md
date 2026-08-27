# Native Linux package install and lifecycle — dev5, 2026-08-27

Bounded real-host evidence for AST-41. It answers one question: can a user on
a clean supported Linux install a single file, with no Rust toolchain and no
QEMU, and get a device manager that boots a catalog image on real KVM — and
does removing that file put the host back?

## Artifact and host

- source: `claude/ast-41-linux-packages` at the tree this evidence was
  committed with
- release payload: `asterism-0.0.2-ast41-linux-x86_64.tar.gz`, built by
  `scripts/package-linux.sh` in a `rust:bookworm` container
  - SHA-256 `f81ca0d1ec9ba075d12bd5d2728a6102d4610222463e27622a5b25847bc47666`
- packages: built from that payload by `scripts/build-linux-packages.sh` with
  nfpm 2.47.0, in an `ubuntu:22.04` container
  - `asterism_0.0.2-1_amd64.deb` SHA-256
    `dd58122cf109c43797e4b13716b6aa435165fe79cd027ab9965833785ad74725`
  - `asterism-0.0.2-1.x86_64.rpm` SHA-256
    `08a8a9ba10f3cfc9d51def21abd7975748eb59c0a1e05301f25523a984f21192`
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
again after the lifecycle.

## Result — partial, and the interruption is not a pass

The gate reached the end of its installation phase and then stopped, twice,
for two different reasons. Both are recorded here rather than retried into
silence.

The first run, with `bash -x`, produced:

```text
ok: no development tools and no previously installed Asterism
ok: package inventory carries no QEMU
ok: installed asterism_0.0.2-1_amd64.deb with its declared dependencies
ok: installing the package pulled in no QEMU
ok: the installed layout is the packaged layout
ok: wrapper ownership and VMM capability are what the post-install claims
```

and then exited 2 inside the gate script itself: `getent group 991` returns
2 when the container has no named group for the host's `kvm` gid, and under
`set -o pipefail` that failed the assignment rather than falling through to
`groupadd`. That is a defect in `scripts/e2e-linux-package.sh`, not in the
package; it is fixed in this branch (`|| true` on that substitution).

The second run, with the fix, got as far as `apt-get install` of the `.deb`
and was cut short when dev5's WSL VM went offline — the host had been asked
to run a 12-core `cargo clippy --workspace --all-targets` alongside the
guest, and did not survive it. The host did not come back within this
session, so the lifecycle half of the gate has **not** run to completion on
a real host.

What the interrupted runs do establish, on real hardware with `/dev/kvm`
present, is everything up to and including the installed permission model.
What they do not establish is anything from `ast service install` onward.
The `## Does not prove` list below is written accordingly and must be read
as the authority on this evidence.

## Proves

- a `.deb` built from the release payload installs on a clean Ubuntu 26.04
  with no development tools present, resolving only its declared
  dependencies, and pulls in no `qemu*` package — checked against the dpkg
  inventory and the fixed paths both before and after;
- the installed layout is the packaged layout: `/usr/bin/{ast,astd}`,
  `/usr/libexec/asterism/{cloud-hypervisor,virtiofsd,asterism-nbd,asterism-nbd-policy}`,
  `/usr/lib/asterism/guest/bin/asterism-guest`,
  `/usr/lib/systemd/user/astd.service`, the `modules-load.d` and
  `modprobe.d` snippets, `/usr/share/asterism/linux-components.env`, and the
  bundled components' license texts;
- the NBD privilege wrapper is installed `root:root` mode `0755` —
  executable by the daemon's account through sudo, writable by neither;
- the post-install granted the bundled Cloud Hypervisor `cap_net_admin`, and
  nothing else, on a host where `/dev/kvm` was present and read-write.

## Does not prove

- **the lifecycle.** `ast service install`, `ast doctor`, `create`, `up`,
  `ssh`, `down`, `rm`, and package removal were not reached on a real host in
  this session. The sudoers rule `ast service install` writes, the
  packaged-path resolution inside a running daemon, the boot on Cloud
  Hypervisor, and the claim that removal leaves nothing behind are therefore
  **unverified against hardware** here. They are asserted by
  `scripts/e2e-linux-package.sh`, which is committed and ready to run; a
  green run of it on a real Linux host is the outstanding gate for AST-41.
- **reboot recovery.** A container has no init, no `systemd --user`, and no
  `loginctl`, so `ast service install` writes the unit and reports that
  `systemctl` is absent rather than enabling it. Lingering, restart after
  logout, and persistent instances coming back after a host reboot are out
  of scope for a container and remain an open gate against a real
  installation.
- **the `.rpm` on a Fedora host.** It is built from the same description and
  the same payload, and its file list and requirements are asserted in CI,
  but no Fedora host installed it.
- **the signed updater over a package.** `ast update apply` refuses a
  package-managed install by design and names the distribution command; that
  refusal was not exercised against a published signed channel.
- **Secret Service.** The container has no session bus and no provider, so
  the secret paths were not exercised.
- **arm64.** Only `linux-x86_64` was built and installed.
- **a physical machine, another distribution, another kernel, or another
  filesystem.**

Those remain independent gates; this result must not be promoted into them.

## Host state after the session

dev5's WSL VM went offline mid-run and did not return, so the working
directory `/root/ast41` (source copy, build target, payload, packages) and
the stopped `ast41-build` and `ast41-check` containers were **not** cleaned
up. They should be removed on the next visit:

```sh
docker rm -f ast41-build ast41-check
rm -rf /root/ast41
```
