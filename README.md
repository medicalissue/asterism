<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/logo/asterism-wordmark-dark.svg">
    <img src="assets/logo/asterism-wordmark.svg" alt="Asterism" width="360">
  </picture>
</p>

<p align="center"><b>Run your AI agents 24/7 on hardware you already own.</b></p>

<p align="center">
  <b>Everything your agent needs. Made local. Always on.</b>
</p>

<p align="center">
  <a href="https://github.com/medicalissue/asterism/actions/workflows/ci.yml"><img src="https://github.com/medicalissue/asterism/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="LICENSE-MIT"><img src="https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-1a7f37" alt="License: MIT OR Apache-2.0"></a>
  <a href="https://asterism.run"><img src="https://img.shields.io/badge/web-asterism.run-090A0D" alt="asterism.run"></a>
</p>

<p align="center">
  <img src="assets/demo.gif" width="880"
       alt="Terminal session: ast create agent --image debian:13, ast up agent, ast ssh agent -- uname -a printing the guest kernel, ast down agent, ast snapshot agent clean, ast ls.">
</p>

Asterism gives an agent a box of its own on a machine you already have, and
keeps it running. The `ast` CLI drives a local `astd` daemon and boots
isolated instances from cloud or OCI images. An instance runs on one device
and uses that device's CPU, RAM, and GPU — the same hardware you would have
run the agent on directly, with a kernel and a disk of its own around it.

A set of devices becomes an **orbit**: a trusted pool your instances draw
*data* from — block volumes over NBD, secrets by handle — and reach you
through, by one orbit-wide name. Asterism runs persistent agents in real VMs,
keeps each guest isolated behind its own kernel and disk, and lets you operate
every instance by name from any device in the orbit.

No Asterism account or hosted control plane is required. Devices pair
directly, trust device keys, and communicate over an authenticated, encrypted
mesh.

## Why not tmux and ssh?

You can already leave Claude Code, Codex, OpenClaw, or Hermes running under
`tmux` behind `ssh` and a mesh VPN. What running it on Asterism gives you:

- **A box it can break, at full speed.** Every instance is a real VM with its
  own kernel and disk. Let the agent `sudo`, rewrite the toolchain, install
  whatever it wants — it is working on its own machine, not yours.
- **Rewind, and fork.** `ast snapshot` takes the machine as it stands and
  costs almost nothing (copy-on-write); `ast restore` puts a bad hour back and
  lets you run the next attempt from exactly the same starting point.
  `ast backup export` and `ast backup import` turn that starting point into a
  second instance, so several agents can work the same problem at once.
- **Hand it every key you own.** The guest gets an opaque `sk-ast-…` handle;
  the real value stays in your Keychain or Secret Service and is substituted
  at the host's egress door on the way out. It is never in the guest disk, the
  seed, or a snapshot — which is what makes giving an always-on agent your
  real credentials a thing you can actually do.
- **An agent ready in a minute.** `ast create … --profile codex` boots a guest
  with the tools already provisioned, not a machine you now have to set up.
- **It stays up.** `ast service install` plus `--restart always` survives
  logout and reboot; the daemon keeps the device awake while a guest is running.
- **Dispatch from anywhere.** `ast ssh agent` resolves the name orbit-wide, so
  you send work to the agent from whichever device you have on you and pick up
  the results later.
- **Many agents, one pool of storage.** Run as many isolated guests as the
  device will hold; a block volume lives on whichever device has the disk for
  it and is handed from one instance to the next by a lease, fenced by a
  durable epoch, so no two agents can quietly write the same bytes.

What it does *not* do: pool CPU, RAM, or GPUs across devices. Compute is the
device an instance runs on.

## Install

```console
$ curl -fsSL https://asterism.run/install.sh | sh
```

The script chooses the available path for this machine. On macOS it installs
through Homebrew. On Linux it builds from source into `~/.local/bin`; that path
is experimental. The script prints every privileged command and waits for
confirmation. It does not install Homebrew or Rust.

```console
$ brew install --HEAD medicalissue/asterism/asterism
```

See the [platform-aware install guide](https://asterism.run/install) for the
current path and [packaging/README.md](packaging/README.md) for version pinning,
alternate prefixes, source refs, Homebrew, and update verification.

## Start an agent

```console
$ ast images
$ ast create agent --image debian:13 --cpus 4 --mem 8G --profile codex
$ ast up agent
$ ast ssh agent
$ ast status agent
```

`ast create` accepts catalog images, pinned cloud-image URLs, local qcow2 or
raw images, and OCI references such as `nginx` or
`ghcr.io/owner/app:v1`. Asterism creates a copy-on-write root disk, provisions
SSH keys with cloud-init, and applies optional bootstrap profiles for tools
such as git, tmux, Node, Claude Code, and Codex.

OCI is an image format, not a second kind of Instance. Asterism selects the
guest architecture's verified manifest, materialises it as a Linux rootfs,
adds a pinned guest kernel and initrd, and boots it as a VM/microVM. The
recorded choice is the hypervisor backend, never a host-namespace runtime.
Architecture-specific mutations and snapshots do not become
cross-architecture portable merely because their source was OCI.

Direct-kernel OCI guests also receive Asterism's static Linux guest-control
agent. `ast up` returns only after that agent proves the per-Instance key; it
does not pretend an arbitrary OCI image contains SSH. Commands are argv-only,
bounded, and preserve their exit status and separate output streams:

```console
$ ast create web --image nginx:alpine -p 8080:80
$ ast up web
$ ast exec web -- /bin/sh -c 'nginx -t'
$ ast logs web -n 20
```

`ast exec ... -- /bin/sh -c ...` covers non-interactive shell work. A PTY and
interactive stdin are not part of this command.

Published endpoints are loopback-only on the device the instance runs on. TCP
is the default; append `/udp` when the service uses UDP, for example
`-p 5353:53/udp`. Every product backend supplies this endpoint: QEMU forwards
inside its own user-mode NAT, while Virtualization.framework and Cloud
Hypervisor hand the guest a private address and `astd` binds
`127.0.0.1:HOST` itself and carries traffic to it. The declaration is durable
and is recovered on exactly its own port across `down`/`up`, a VMM crash and a
daemon restart — never on a different one. A backend with neither path refuses
the create before an Instance row is written. See
[Instance networking and egress](docs/instance-network.md).

On macOS the product backend is Virtualization.framework, through the signed
`astd-vz` helper that every install lane installs beside `astd`. QEMU is not an
install dependency: the Homebrew formula does not declare it, nothing bundles
it, and it is never selected ahead of VZ. It is the opt-in compatibility and
development fallback for what VZ does not do — reading a qcow2 base image you
point at directly, and running a guest of a foreign architecture. Install it
yourself and ask for it by name when you want it:

```console
$ brew install qemu
$ ast create dev --image debian:13 --backend qemu
```

`--backend vz` likewise pins VZ, so a create that VZ cannot serve is a specific
capability refusal rather than a quiet substitution.

On Linux, a tagged release ships pinned Cloud Hypervisor v53.0 and virtiofsd
v1.14.0 beside `ast` and `astd`. QEMU remains an explicit compatibility
backend. After install, persist the daemon across logout and reboot:

```console
$ ast service install
$ loginctl enable-linger $USER
$ ast doctor
$ ast up agent --restart always
$ ast service status
```

On macOS, install `astd` as the user service that keeps instances running:

```console
$ ast service install
$ ast up agent --restart always
$ ast service status
```

Snapshots, backups, logs, and lifecycle commands use the same instance name:

```console
$ ast snapshot agent clean
$ ast snapshots agent
$ ast restore agent clean
$ ast backup export agent ~/Backups/agent
$ ast backup inspect ~/Backups/agent
$ ast backup import ~/Backups/agent
$ ast logs agent --follow
$ ast down agent
```

Backup format 2 records guest architecture, backend, disk formats, and OCI
provenance. Cross-backend import is explicit with `--backend`; a different CPU
architecture requires an OCI source pinned to an immutable index and
`--re-materialize`. See [target-aware backups](docs/backup-v2.md).

## Add devices to an orbit

On the first device, create a single-use invitation:

```console
desktop$ ast device invite --name desktop
```

Paste its ticket on the other device:

```console
laptop$ ast device add <ticket> --name laptop
```

Both terminals show the same six-digit confirmation code before either device
is trusted. Pairing needs no coordinator. Once paired:

```console
$ ast devices
$ ast ping desktop
$ ast ls
```

Instance names form one orbit-wide namespace. `ast create` and `ast rename`
claim a name across the orbit, and ordinary commands such as `ast up agent`,
`ast ssh agent`, and `ast status agent` locate it and forward the request to
the device it runs on. `ast ls` combines every device's registry shard into one
view and marks the state from an unreachable device as `unknown`.
The global `--device` option is for device-local administration and debugging,
not for reaching an instance.

## Give an instance its parts

An instance runs on one device and uses that device's hardware. What it can
draw from the rest of the orbit is **data**: block volumes and secrets. Root
disk, remote block volumes, and orbit-scoped secret egress are represented as
parts today; backend capability gates keep unavailable guest projections from
being recorded as if they worked.

`ast status` shows where an instance's parts come from. A guest sees an
ordinary local disk even when the bytes live on another device and Asterism
carries the block operations across the mesh.

See [Compute is the device an instance runs on](docs/compute-device.md) for
the architecture and compatibility contract.

- **Compute** is not a part Asterism places, splits, or borrows. An instance
  gets the CPU, physical RAM, and GPU of the device it runs on; `--cpus` and
  `--mem` are quotas on that device. The recorded hypervisor backend is an
  internal detail; every new Instance is a VM. Asterism does not present CPU
  and RAM from two devices as one machine, and there is no scheduler choosing
  a device for you.

  Relocating an instance to another device does exist, as an offline
  migration, and it is parked rather than part of the core story:

  ```console
  $ ast set agent compute desktop --down
  ```

  `ast set agent cpu desktop` and `ast move agent desktop` remain aliases.

- **GPU** is the GPU of the device the instance runs on. Projecting another
  device's NVIDIA GPU into a guest over the mesh is an **experimental
  appendix**, not a shipped promise: one CUDA kernel launch becomes one
  network round trip where PCIe takes sub-microseconds. See
  [Roadmap](#roadmap).

- **Directory shares** expose a directory from the instance's own device
  through 9p on QEMU or virtiofs on VZ. They are local to that device; there
  is no network transport for them.

  ```console
  $ ast attach agent --volume ~/work --at /workspace
  ```

- **Block volumes** can live on any device. They are leased to one instance
  at a time and appear in the guest as a normal disk such as `/dev/vdb`;
  the guest does not need to know which device holds the bytes.

  ```console
  $ ast --device storage volume create data --size 100G
  $ ast volume ls
  $ ast attach agent --volume data
  ```

  `ast volume ls` is one orbit catalog: each row identifies the owning device,
  measured access latency, single-device durability, single-writer sharing and
  current lease. Asterism prefers an eligible local part, then the lowest
  measured latency. Use `storage:data` to constrain an attach to one owner, or
  `--max-latency-ms` to refuse a path before any lease or guest state changes.

- **Secrets** let you give an agent the real keys without putting them in the
  box. Values stay in a source device's macOS login Keychain or FreeDesktop
  Secret Service on Linux; the guest gets an opaque handle, and Asterism swaps
  it for the value at the egress door on its way to the authority you bound it
  to. The value never enters the guest disk or a snapshot; platforms without a
  credential-store implementation refuse secret storage instead of writing a
  plaintext fallback.

  ```console
  $ printf '%s' "$ANTHROPIC_API_KEY" | ast secret create anthropic
  $ ast attach agent --secret anthropic --to api.anthropic.com
  ```

Remote block volumes need no QEMU on either device. The device holding the
bytes serves them from a native NBD exporter inside `astd`, and the consumer
side is VZ's own network block device on macOS or the kernel NBD client below
Cloud Hypervisor on Linux; QEMU remains an optional consumer, never a
prerequisite. Directory shares must be on the device the instance runs on, and
an attach to an instance whose backend has no share transport is refused with
the install command it would need rather than silently dropped.

## Reach guests and devices

`ast ssh <instance>` works from any orbit device. The local daemon resolves
the name and returns a loopback endpoint whether the guest is local or across
the mesh, so SSH itself does not need an exposed guest port or a device name.

A paired device can also offer its own user shell. This is disabled by
default and grants approved peers the full authority of that user account:

```console
desktop$ ast device shell enable
laptop$ ast ssh --host desktop
laptop$ ast ssh --host desktop -- uname -a
desktop$ ast device shell disable
```

Read [docs/device-shell.md](docs/device-shell.md) before enabling it; the
document covers approval scope, audit records, and revocation limits.

## Network and privacy

**A fresh install talks to nobody's servers.** There is no default relay and no
default directory: an unconfigured, not-logged-in device is local-only, reaches
peers wherever a direct path already works, and publishes nothing about itself
anywhere. That is the default because cross-network reachability is something a
device should be given, not something an installer helps itself to.

Two ways to go further, and they use the same code path.

**Log in.** The coordination plane supplies the relays and the account's own
device directory, so devices behind different NATs can find each other. Relays
forward ciphertext; the directory holds a device's public key and current
addresses, and no instance metadata.

**Run your own.** `astrelay` is in this repository under the same licence as
everything else:

```console
relay-host$ astrelay --tls lets-encrypt --acme-domain relay.example.com \
                     --acme-contact ops@example.com --acme-cache /var/lib/astrelay
laptop$     ASTERISM_RELAY_URL=https://relay.example.com astd
```

`ASTERISM_PKARR_RELAY` and `ASTERISM_DNS_ORIGIN` select a directory the same
way, and any of the three overrides what a login supplied.
`ASTERISM_MESH=local` forces local-only regardless.

`ast ping` and `ast devices` report per-peer bytes split into direct and
relayed, and name the relay carrying each connection.
[docs/RELAY.md](docs/RELAY.md) is the guide.

## Updates

The CLI uses a signed update channel. Its updater retains the authenticated
Desktop-manifest boundary: when a private Desktop release supplies matching
app metadata, it verifies the app, CLI, daemon, and helper before atomically
activating them. Public Asterism releases contain only the CLI, daemon, and VZ
helper; Homebrew installations remain owned by Homebrew.

```console
$ ast update status
$ ast update channel stable       # stable, beta, or nightly
$ ast update check
$ ast update apply --yes
```

## Roadmap

### Remote GPU — experimental appendix

Projecting another device's NVIDIA GPU into an instance is checked in and it
is **experimental**, not a shipped product promise and not part of the core
story. The reason is physics: one CUDA kernel launch becomes one round trip
over the mesh, against sub-microsecond PCIe on the device's own bus. A GPU an
instance can actually depend on is the one in the machine it runs on.

The experiment presents `/dev/nvidia0` inside an instance as a projected local
endpoint (CUSE character device plus generated `libcuda.so.1`) and carries
CUDA-semantic frames over the authenticated orbit mesh. See
[docs/remote-gpu-guest.md](docs/remote-gpu-guest.md),
[docs/remote-gpu-abi.md](docs/remote-gpu-abi.md), and
[docs/remote-gpu-production.md](docs/remote-gpu-production.md). The portable
reference executor is not NVIDIA hardware evidence.

### Next at the egress door

Every bound request already passes through a door this device owns, which is
the natural place to tell you what an agent actually called and what it spent,
per agent and per task. That ledger is not built yet: today the secrets plane
handles HTTP/1.1 CONNECT and selective TLS termination, and per-call usage
records are not written. See
[Instance networking and egress](docs/instance-network.md) for the built
boundary.

### Parked

- **Moving an instance between devices** (`ast move`, `ast set … compute`)
  works as an offline migration and stays in the tree, but it is parked as a
  product direction. Reason: product focus. Compute is the device an instance
  runs on.

## Build from source

```console
$ cargo build
$ cargo test
```

State lives in `~/.asterism`; set `ASTERISM_HOME` to override it. The Rust
workspace contains `asterism-core`, `asterism-daemon` (`astd`),
`asterism-cli` (`ast`), `asterism-mesh`, and `asterism-vz`.

## Contributing

Sign off each commit with `git commit -s`. That `Signed-off-by` line is the
DCO; there is no CLA. Before opening a pull request, run
`cargo fmt --all --check`,
`cargo clippy --workspace --all-targets -- -D warnings`, and
`cargo test --workspace`. Changes to the wire protocol keep compatibility
with released clients. The license footer below states the terms your
contribution arrives under.

Licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your
option. Contributions are accepted under the same terms (DCO).
