<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/logo/asterism-wordmark-dark.svg">
    <img src="assets/logo/asterism-wordmark.svg" alt="Asterism" width="360">
  </picture>
</p>

<p align="center"><b>Run your AI agents 24/7 on hardware you already own.</b></p>

<p align="center">
  <a href="https://github.com/medicalissue/asterism/actions/workflows/ci.yml"><img src="https://github.com/medicalissue/asterism/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="LICENSE-MIT"><img src="https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-1a7f37" alt="License: MIT OR Apache-2.0"></a>
  <a href="https://asterism.run"><img src="https://img.shields.io/badge/web-asterism.run-101114" alt="asterism.run"></a>
</p>

<p align="center">
  <img src="assets/demo.gif" width="880"
       alt="Terminal session: ast create agent --image debian:13, ast up agent, ast ssh agent -- uname -a printing the guest kernel, ast down agent, ast snapshot agent clean, ast ls.">
</p>

```console
$ curl -fsSL https://asterism.run/install.sh | sh
```

One tagged release, checksummed against the `SHA256SUMS` published beside it,
into `~/.local/bin`. Re-running upgrades; `--uninstall` puts the machine back.
Building it yourself, from a tag or from a branch you name, is
`ASTERISM_METHOD=source` — see [packaging/README.md](packaging/README.md) for
that and for the Homebrew tap.

macOS today. Asterism probes the host when an instance is created and uses
Virtualization.framework (VZ) when it can satisfy the request, otherwise QEMU.
Pass `--backend vz` or `--backend qemu` to force one and get its exact probe or
capability refusal immediately.

An agent has to stay up, and your laptop sleeps. That is why you rent
a VPS: two vCPUs, no GPU, a monthly bill. A better machine already sits
on your desk. Asterism gives the agent a permanent home there, a real VM
that stays up when your laptop lid closes and answers from anywhere. The
agent keeps its own kernel and its own disk, your real computer stays
yours, and snapshots give you restore points when you want them.

Asterism assembles one computer from your scattered machines. An
instance's CPU and RAM anchor on one device; its disk, volumes, and
eventually its GPU attach from the others over an encrypted mesh. You
install a daemon on each device and pair them once. Nothing asks you to
forward a port or install a new OS.

## What works today

Real virtual machines on macOS (native Virtualization.framework when capable,
otherwise QEMU with Hypervisor.framework acceleration) behind a pluggable
hypervisor interface: pick an image
from the catalog (Ubuntu, Debian, Fedora, Alpine) or point at any
cloud-image URL or local qcow2. Instances get copy-on-write disks,
cloud-init provisioning with your SSH keys, host-directory passthrough
(virtio-9p), disk snapshots with restore, console logs, and graceful
shutdown. `ast` talks to a local `astd` daemon and starts it on demand.

```
ast images                    # what you can boot
ast create dev --image debian:13 --cpus 4 --mem 8G
ast attach dev --volume ~/work
ast up dev · ast ssh dev · ast down dev
ast snapshot dev clean · ast restore dev clean · ast logs dev -f
ast backup export dev ~/Backups/dev · ast backup inspect ~/Backups/dev · ast backup import ~/Backups/dev
ast ls · ast status dev · ast rm dev
```

## What's next

The mesh. You pair devices into an **orbit** with one command and a
six-digit confirmation; after that you can address any device by name
(`ast --device desktop ls` works today on a shared network). Volumes,
GPUs, and instance migration ride the same rails next. We keep every
client in this repository open source and plan to charge for a hosted
coordination service.

The versioned CUDA-semantic boundary and its runnable two-role fake
`/dev/nvidia0` proof are documented in
[docs/remote-gpu-abi.md](docs/remote-gpu-abi.md).

## Building

```console
$ cargo build      # binaries: target/debug/{ast,astd}
$ cargo test
```

State lives in `~/.asterism` (override with `ASTERISM_HOME`).
Workspace: `asterism-core` · `asterism-daemon` (`astd`) ·
`asterism-cli` (`ast`) · `asterism-mesh`.

### Proving a release

`cargo test` proves the source. It does not prove the release, and the
gap between them is where release bugs live — a tarball missing a
binary, a helper that lost its signature on the way through `tar`, two
binaries from two different builds packed together.

```console
$ scripts/rc.sh          # build the artifact, install it, operate it
$ scripts/rc.sh --all    # ...and every suite this machine can run
$ scripts/rc.sh --list   # the suites, and what each one needs
```

It builds the exact tarball a publish would upload, checks it against
its own `SHA256SUMS`, installs it with the script users pipe into `sh`,
and runs the suites against **that** pair rather than `target/debug`.
The bare form is what CI runs on every pull request; `--all` adds the
lanes that need a hypervisor or a network, which a GitHub runner has
not got. Nothing it does touches `~/.asterism` or a daemon that was
already running.

Which build a binary is, is a question a version number cannot answer:

```console
$ ast version     # version, immutable build id, and the sha256 of the file
$ ast bugreport   # that, plus this device's state — what to paste into an issue
```

`ast`, `astd` and the desktop app all report the same id when they are
one build, and `scripts/rc.sh identity` is the assertion that they are.

## The mesh, and what it publishes

Paired devices find each other by public key, so an orbit works when the
two machines are on different networks with no port forwarded. Reaching
that far needs relay servers and a directory to look a key up in, and we
do not run those yet: today the daemon uses **n0's public iroh
infrastructure** (their relays, and `dns.iroh.link` for lookups). That
means each device publishes **its public key and its current addresses**
to a public directory. Relays forward ciphertext they cannot read and
the directory holds nothing about your instances, but the existence of
the device, and roughly where it is, is readable by anyone with its key.
`astd` prints this on startup.

```console
$ ASTERISM_MESH=local astd     # no relay, no directory, nothing published
```

`local` reaches peers only at addresses already on file — the mode to use
if you already have a working route (a tailnet, a VPN, a LAN). To point
at other servers instead, set `ASTERISM_RELAY_URL`, `ASTERISM_PKARR_RELAY`
or `ASTERISM_DNS_ORIGIN`; the servers we run will arrive through the same
seam.

---

Early development. Licensed under [MIT](LICENSE-MIT) or
[Apache-2.0](LICENSE-APACHE), at your option; contributions are accepted
under the same terms (DCO).
