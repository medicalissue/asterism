# ADR 0001 — Linux virtualization: Cloud Hypervisor is the default VMM; Firecracker is a benchmark-gated OCI lane, or nothing

| | |
|---|---|
| Status | **Proposed** — for Sol review (as-lvf.4, AST-19) |
| Date | 2026-08-22 |
| Deciders | owner (medicalissue); evidence by asterism/polecats/furiosa |
| Supersedes | `BACKENDS.md` §3 row "Linux" and §5 ("QEMU/KVM stays the default, Cloud Hypervisor opt-in") in the spec rig, which predate the 2026-08-22 owner narrowing on as-lvf.4 |
| Unblocks | as-lvf.9 (native Linux `chv` backend), as-lvf.19 (Firecracker OCI lane — gated by §6 of this ADR) |

## 1. Decision

1. **On Linux, Asterism consumes Cloud Hypervisor as its default VMM** behind the
   existing `hv::Hypervisor` trait, with backend id `chv`, selected by probe and
   `Caps` exactly as `vz` is on macOS. KVM stays the accelerator; Asterism does
   not own a device model. QEMU/KVM remains the compatibility floor
   (foreign-arch guests, user-mode NAT `-p` publishing, anything `chv` refuses
   by capability), reached by refusal, never by name.
2. **Firecracker is not a general backend and will not become one by default.**
   It may only enter the tree as a separate *OCI fast lane* — an `ImageKind::OciRootfs`-only
   backend — and only after the benchmark gate in §6 is passed on a
   non-nested host. Until then as-lvf.19 stays open and unworked.
3. **Direct KVM is rejected.** Writing against `/dev/kvm` would make Asterism own
   a VMM and a device model, which is the one thing this decision exists to
   avoid.

## 2. Why this needed validating rather than asserting

The hypothesis was written from documentation. This ADR tried to break it in
three ways and records what survived:

* **"Firecracker's device model is too minimal for a durable instance."** Partly
  stale. Firecracker 1.14–1.16 added virtio-mem memory hotplug, virtio-pmem,
  a PCI transport, and *developer-preview* hot-plug/unplug of PCI virtio block,
  pmem and net devices (CHANGELOG 1.14.0, 1.16.0; `docs/device-hotplug.md`).
  The refutation fails on the parts that matter to the product, not on
  hotplug: **no shared filesystem of any kind** (virtio-fs "not currently on
  our roadmap", firecracker-microvm/firecracker#1180, maintainer comment
  2023-10-30; 9p rejected in the same thread), **no live migration** (the
  only attempt, PR #4762, closed unmerged), **no guest reboot on x86_64**
  (FAQ: "Firecracker does not currently support guest reboot" — a `reboot`
  inside a durable agent's VM ends the VM), and a **host-kernel support
  policy of exactly 5.10 / 6.1 / 6.18** (`docs/kernel-policy.md`), which
  excludes the GA kernel of the LTS distribution this bench ran on (Ubuntu
  24.04, 6.8). Firecracker is honest that other kernels "are not periodically
  validated in our test suite, and using them might result in unexpected
  behaviour".
* **"Cloud Hypervisor's feature list is marketing; the matrix will not hold on
  a real host."** It held on a real KVM host (nested, see §3): vsock both
  ways, virtio-fs through the distro's `virtiofsd`, local block hot-add and
  hot-remove, an NBD-over-unix export consumed as a host block device,
  pause/snapshot/restore/resume with guest state intact, memory hot-add, SIGKILL
  recovery, and the VMM surviving its spawner. The two refusals are
  documented ones: **CPU hotplug is x86-only** (`docs/hotplug.md`), and
  virtio-fs / vhost-user needs `--memory shared=on`, which is a boot-time
  property of the guest, not something a running guest can be given.
* **"Cloud Hypervisor is too immature / too fast-moving to bet a product on."**
  Real cost, not a refutation. Releases every ~6 weeks, bug fixes for two
  cycles (~12 weeks) then EOL, and **snapshot/restore and live migration are
  not compatible across major versions** (`docs/releases.md`). This is the
  same constraint `BACKENDS.md` §5 already imposed on QEMU and is why
  `Machine` records `hv_version`. No distro packages it (Ubuntu noble: none;
  Fedora: none) — Asterism ships the static binary, which the license allows
  (`LICENSING.md`).

What did not survive on *our* side: the spec's claim that QEMU is "the only
backend on the table with mature live migration". Cloud Hypervisor v53.0
ships remote TCP migration with mutual TLS, userfaultfd postcopy and an
offloaded snapshot/restore daemon (`docs/live_migration.md`, v53.0 release
notes). It is younger than QEMU's, and cross-major-version moves are refused,
but it exists and is the direction the project is investing in.

## 3. Evidence: what was actually run

**Host.** No bare-metal Linux host was reachable from this session (the one
EC2 host in reach timed out, and EC2 exposes `/dev/kvm` on `.metal` types
only). The bench therefore ran on a **nested KVM host**: Lima 2.1.1,
`vmType: vz`, `nestedVirtualization: true`, on an Apple M4 / macOS 15.6.1,
guest Ubuntu 24.04.4 arm64, kernel 6.8.0-137-generic, `/dev/kvm` present,
Landlock "Up and running", `vhost_vsock` / `virtio_mem` / `virtio_fs` as
modules. `systemd-detect-virt` reports `apple`.

**Consequence for the numbers.** Every feature result below is a real KVM
result and stands. Every *timing and RSS* number is indicative only: a
nested aarch64 guest on a laptop-class host with a disk that had 3 GiB free
is not the product's target, and the ADR does not quote them as product
performance. §5 is the spec for reproducing them on a supported host.

**Pinned inputs (identical for both VMMs).**

| Input | Pin |
|---|---|
| Cloud image | `ubuntu-24.04-server-cloudimg-arm64.img` sha256 `4a281a921b8d7db952895ab619736f10efe9f63e111fa5b5779ed18f023818aa`, converted to raw with `qemu-img` |
| Kernel | Ubuntu noble unpacked `…-arm64-vmlinuz-generic` sha256 `9ff21f2798055943e5a28da044a5eb701bc85e1f1817c34bd1bd62729cdeca25` (gunzipped to a 59,079,048 B `Image`) — the same pin `crates/asterism-core/src/oci.rs` `KERNELS` carries |
| Initrd | `…-arm64-initrd-generic` sha256 `66b3257ccc43c088f7b7c14ebf74dee30172a9a0eb0e6ccd8db1374e18a281de`, 29,239,653 B — same pin as `oci.rs` |
| Cloud Hypervisor | v53.0 (2026-07-12), `cloud-hypervisor-static-aarch64` sha256 `f192b510eea1c710cbc439d716bb0573c223fc463dbe3e6523788a2b7ef62850`, `ch-remote-static-aarch64` sha256 `ade26617f74264467e1381f146fd1face6b8b0fb13c5ec84f4acedd72f972596` |
| Firecracker | v1.16.1 (2026-07-02), `firecracker-v1.16.1-aarch64.tgz` sha256 `8d0e69f6d6f9a1724551f607f18504052c16c1828ee3d4d7b6e6c73380871e0e` |
| virtiofsd | Ubuntu noble package 1.10.0-1ubuntu0.1 (upstream is 1.14.0; Fedora ships 1.14.0) |
| Guest shape | 2 vCPU, 1024 MiB, no NIC, `systemd-networkd-wait-online` masked on the cmdline for both, NoCloud seed with a python vsock agent started from `runcmd` |
| Bench | `scripts/bench-linux-vmm.sh` in this tree |

**Artifact footprint (bytes the product would ship).**

| | aarch64 | x86_64 |
|---|---|---|
| `cloud-hypervisor` static | 5,468,264 | 7,062,256 |
| `ch-remote` static (optional; the daemon speaks the HTTP API directly) | 1,490,952 | 1,798,776 |
| `virtiofsd` (distro package, not shipped) | 2,951,472 (noble) | — |
| `firecracker` | 3,254,360 | 3,527,456 |
| `jailer` (required in production per `docs/prod-host-setup.md`) | 1,916,808 | 2,181,264 |

Firecracker's binary is smaller; with the jailer it is within 0.3 MB of Cloud
Hypervisor on aarch64. Neither number decides anything.

### 3.1 Results

RESULTS_PLACEHOLDER

## 4. Requirements recorded (package, kernel, privilege, jail, update)

| | Cloud Hypervisor | Firecracker |
|---|---|---|
| Package | No distro package (Ubuntu noble, Fedora). Ship the static binary + `LICENSE-APACHE`/`LICENSE-BSD-3-Clause`/`NOTICE` | No Ubuntu package; Fedora has 1.13.1. Ship the release tarball's `firecracker` + `jailer` |
| Host kernel | Recommended ≥ 5.13 (CI on 5.15); virtio-fs needs ≥ 5.10 guest; ACPI hotplug needs GED (≥ 5.5) | Supported: 5.10, 6.1, 6.18 only; other kernels explicitly unvalidated |
| Host modules / nodes | `/dev/kvm` rw. vsock is implemented in the VMM over a unix socket — no `/dev/vhost-vsock` needed (bench host had `vhost_vsock` *unloaded*). Remote block via host `nbd` module + `nbd-client` (root / CAP_SYS_ADMIN once per attach) | same `/dev/kvm`; same nbd path for remote block |
| Privilege | Runs as an ordinary user in the `kvm` group; seccomp on by default per thread; optional Landlock (`--landlock`, rules must pre-declare every path a later hot-add will touch) | `firecracker` itself runs unprivileged; the **jailer needs root** ("We run the jailer as the root user"), builds a chroot under `/srv/jailer/<exe>/<id>/root`, and every drive the VM may see must be hard-linked or copied inside that chroot |
| Guest kernel | Direct kernel boot (`--kernel Image`) or UEFI via `CLOUDHV_EFI.fd`; PCI transport only; virtio-fs, virtio-mem, vsock as modules in stock Ubuntu | Direct kernel boot only, *uncompressed* `Image` on aarch64; MMIO transport by default, `--enable-pci` for hotplug (dev preview, guest must rescan the bus by hand) |
| Shared dir | virtio-fs via `virtiofsd` (vhost-user, needs `--memory shared=on`) — maps to `Caps::shared_dir = Some(ShareKind::Virtiofs)` | none — `Caps::shared_dir = None`; every volume would be a block device |
| Snapshot / restore | `pause` → `snapshot file://` → new VMM `--restore` → `resume`; 3 files (`config.json`, `memory-ranges`, `state.json`); not across major versions | `Paused` → `PUT /snapshot/create` → new VMM `PUT /snapshot/load`; restoring one snapshot twice duplicates guest secrets/IDs unless the original is killed; TAP names collide across clones |
| Live migration | unix-socket local, TCP remote with mTLS, precopy/postcopy; same major version both ends | none |
| Update cadence | major every ~6 weeks, fixes for ~12 weeks; API/CLI breaking changes announced 2 releases ahead | ~quarterly minors, two host kernels maintained at a time, 2-year kernel support floor |
| Guest reboot | yes (ACPI) | aarch64 yes; **x86_64 no** (FAQ) |

## 5. Reproducing on a supported host (the part this session could not do)

Run `scripts/bench-linux-vmm.sh` on:

* one **x86_64** Linux host with bare-metal KVM (no nesting), ≥ 8 GiB free RAM,
  ≥ 16 GiB free disk, Ubuntu 24.04 *and* one host on a Firecracker-supported
  kernel (6.1 or 6.18 — e.g. Amazon Linux 2023 on a `.metal` instance, or
  Ubuntu with the 6.18 HWE kernel when it lands), and
* one **aarch64** bare-metal KVM host (Graviton `.metal`, Ampere, or an
  Apple-silicon Linux host with KVM), because the product's first Linux
  devices are as likely to be aarch64 as x86_64.

Inputs are the pins in §3 (swap the `amd64` kernel/initrd/image pins from
`oci.rs` on x86_64). Set `ROUNDS=10`. Record `out/summary.txt` and the
`out/*/` logs on the bead. The host must have > 2× the image's allocated
size free: this bench was first corrupted by a host whose disk filled while
the nested VM's sparse image grew (`EXT4-fs warning … I/O error 10`), which
is why the script reuses one root disk and reruns cloud-init with a fresh
instance-id instead of cloning the image per boot.

Additionally, for the §6 gate only, the OCI workload: build the rootfs the
way `oci.rs` does (`mke2fs -d`), from a pinned `python:3.12-alpine` digest,
with `/lib/modules/<kernel>` copied in from the cloud image so the vsock
transport can load, and the bench agent as `init`. Boot it through both VMMs
with the same `Image`/initrd and measure the same two numbers.

## 6. The Firecracker gate (as-lvf.19)

A separate Firecracker OCI lane is worth its maintenance cost — a second
backend in `backend/mod.rs`, a jailer that needs root, a chroot-per-VM
layout, a kernel-version policy to track, a second snapshot format, and one
more row in every future feature's matrix — **only if all of the following
hold, measured per §5 on a non-nested host of each architecture, with the
same OCI rootfs, kernel, initrd and guest shape:**

1. **Boot.** Median boot-to-vsock-ready under Firecracker ≤ **50 %** of Cloud
   Hypervisor's (direct kernel boot on both, 10 rounds, same host).
2. **Density.** With 20 concurrent idle OCI microVMs, Firecracker's summed
   VMM RSS is at least **256 MiB** (≥ 12.8 MiB/VM) below Cloud Hypervisor's.
3. **Need.** A roadmap item exists that requires ≥ 10 concurrent *disposable*
   OCI instances per device. Durable agents, which are the product, do not
   create that need (`BACKENDS.md` §7: "Scratch VMs are not the trigger").
4. **Fit.** The lane never needs directory sharing, live migration, or
   x86_64 guest reboot — the three things Firecracker does not offer.

Any one failing ends the lane. If the gate passes, the lane is an
`OciRootfs`-only backend: `Caps { shared_dir: None, live_migration: false,
direct_kernel: true, … }`, selected only when the request is an OCI image
*and* the create asks for the lane, never as a fallback for a cloud image.

## 7. Consequences

* `backend::by_id` gains `chv` (as-lvf.9). `ControlChannel::HttpApi` already
  exists for it; `Handle.ctl` carries the API socket path.
* `Caps` for `chv`, as proven here: `disk_snapshot: true` (file-level, as on
  vz), `live_snapshot: true`, `live_migration: true` (same major version,
  enforced through `Machine.hv_version`), `disk_hotplug: true`,
  `shared_dir: Some(Virtiofs)` (only when the instance booted with shared
  memory — so `chv` boots *every* guest with `shared=on`; cost is `MAP_SHARED`
  backing, not extra RSS), `nbd_disks: false` (NBD is consumed by the host
  kernel, handed over as `DiskSpec::Block`), `foreign_arch: false`,
  `direct_kernel: true`, `port_forward: false` (no user-mode NAT — the
  `-p` path stays on QEMU until the mesh-side publish exists),
  `guest_egress: None` until a tap/bridge design gives a safe answer,
  `disk_formats: [Raw, Qcow2]`.
* `virtiofsd` is a host dependency the installer must check for, the way it
  checks for QEMU today; the probe reports its absence as a missing
  capability, not a failed backend.
* Spec: `BACKENDS.md` §3 Linux row and §5 are to be rewritten to point here;
  §7 "Phase 3" loses its trigger (the owner decision of 2026-08-20 already
  made native backends the destination).
* CPU hotplug is a `Caps` the `chv` backend must report per architecture
  (x86 only), not assume.

## 8. Sources

* Cloud Hypervisor: README, `docs/hotplug.md`, `docs/live_migration.md`,
  `docs/snapshot_restore.md`, `docs/fs.md`, `docs/memory.md`,
  `docs/device_model.md`, `docs/vsock.md`, `docs/seccomp.md`,
  `docs/landlock.md`, `docs/threat-model.md`, `docs/releases.md`,
  `docs/api.md`, `block/src/formats/{raw,qcow,vhd,vhdx,vmdk}`, release v53.0
  (2026-07-12), issue #1125 (AArch64 tracking).
* Firecracker: README, `docs/design.md`, `docs/device-api.md`,
  `docs/device-hotplug.md`, `docs/memory-hotplug.md`,
  `docs/api_requests/patch-block.md`, `docs/snapshotting/snapshot-support.md`,
  `docs/snapshotting/network-for-clones.md`, `docs/vsock.md`,
  `docs/jailer.md`, `docs/prod-host-setup.md`, `docs/kernel-policy.md`, FAQ,
  CHANGELOG (1.14.0–1.16.0), release v1.16.1 (2026-07-02), issue #1180,
  PR #4762.
* Packaging: Launchpad API (noble arm64: `virtiofsd` 1.10.0-1ubuntu0.1,
  `nbd-client`, `qemu-utils`; no `cloud-hypervisor`, no `firecracker`), Fedora
  Bodhi (`firecracker` 1.13.1, `virtiofsd` 1.14.0), gitlab virtio-fs/virtiofsd
  v1.14.0 (2026-07-06, source-only releases).
* This tree: `crates/asterism-core/src/hv.rs` (`Caps`, `ControlChannel`,
  `DiskSpec`), `crates/asterism-core/src/oci.rs` (`KERNELS` pins),
  `scripts/bench-linux-vmm.sh`, and the spec rig's `BACKENDS.md` §3/§5/§7.
