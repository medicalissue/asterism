# Hyper-V OCI boot and the AF_HYPERV secret door — 2026-08-27

AST-47, slices 1 and 2. What this directory records is what was *executed*,
by whom, and on what. Where nothing ran, it says so in the same words it
would have used to claim a pass.

## The host

`destop-dev5`, Windows 11 Home, build `10.0.26200`, Hyper-V enabled,
elevated. The helper's own probe, verbatim:

```json
{"result":"ready","host":{"protocol":1,"build":"0.0.2+unknown",
 "windows":"10.0.26200","edition":"Windows 11 Home (product 101)",
 "elevated":true,"hcs_running":true,"hcn_running":true}}
```

The edition is in that line because the helper reports it as diagnostics. It
is not a qualification on anything below: the gate is whether Hyper-V is
present and enabled, and on this device it is.

## What ran on the host

One VM at a time, 2 vCPU / 2 GiB, name-scoped to `ast47-*`, built from the
branch at `355098d7`. Everything created was removed afterwards — the
compute system, its HCN endpoint, the NAT network, the working directory and
the scripts; `state` reports `missing` and `Get-VM` lists nothing.

### An OCI guest is handed its kernel, and gets its command line

`Chipset.LinuxKernelDirect` with the pinned Ubuntu 24.04 kernel and initrd
(digests `76a7f2ef…` and `194f73c1…`, matching `oci::KERNELS` exactly), the
root VHDX on SCSI, and the command line this backend builds. From the
guest's serial console:

```text
[    0.000000] Command line: root=LABEL=asterism rw console=ttyS0 net.ifnames=0
panic=10 init=/asterism-init asterism.ip=172.29.64.55/20 asterism.gw=172.29.64.1
asterism.dns=1.1.1.1 asterism.time=1787000000
```

Every claim in the boot design is visible in that transcript and what
follows it:

* the kernel started — there is no bootloader, no firmware and no Secure
  Boot policy in the path;
* the **initrd was loaded** — the Ubuntu initramfs ran, which is what
  produced the `mdadm` and `Gave up waiting for root file system device`
  lines;
* the **command line arrived verbatim**, including every `asterism.*` key
  the generated init reads;
* `console=ttyS0` reached a real COM port, which is how any of this was read;
* `panic=10` reached it too: `Rebooting automatically due to panic= boot
  argument`;
* the root VHDX was attached and enumerated: `sd 0:0:0:0: [sda]`.

The guest then stopped at `ALERT! LABEL=asterism does not exist`, which is
correct: the root disk in this run was **8 MiB of zeros, not an OCI root
filesystem**. See "What did not run".

### The door binds against one compute system

`Request::ServeEgress` was started before HCS created the VM, as `astd` does
it. The helper's own line:

```text
astd-hyperv: ast47: egress door open on hv_sock port 1021 -> \\.\pipe\ast47-egress
```

That is an `AF_HYPERV` listener bound to `(VmId = this compute system,
ServiceId = 000003fd-facb-11e6-bd58-64006a7986d3)`, admitted by the per-VM
`HvSocketConfig` service table with `AllowWildcardBinds: false` — no
machine-wide registry key was created, and none was needed.

The first attempt at this **failed on the real host** with
`WSAEADDRNOTAVAIL`: the door was starting before the compute system existed,
exactly as designed, but the code had no retry to go with the design. That
is now `bind_egress_listener`, and the line above is the fixed version.

### What the host also corrected

* **The grant list.** HCS refused the first boot with
  `granting the VM access to a backing file: HRESULT 0x80070002` — the helper
  was granting a NoCloud seed an OCI guest never had. `backing_files()` now
  derives that list beside `hcs_document()`, with a test that the two agree.

## The design this replaced, and why

The first implementation assumed "Hyper-V has no direct kernel boot" and
built an EFI System Partition in Rust to work around it. The host refuted it,
and the two screenshots here are the refutation:

* `esp-secure-boot-off-kernel-panic.png` — with Secure Boot **off**, that ESP
  boots a real Linux kernel (`6.8.0-137-generic`). The partition was sound:
  Windows' own GPT parser and FAT driver mounted it, reported the ESP type
  GUID and FAT32, and `Get-FileHash` on `\EFI\BOOT\BOOTX64.EFI` matched the
  pinned `vmlinuz` byte for byte.
* `esp-secure-boot-on-refused.png` — with Secure Boot **on**, the same disk is
  refused: *"SCSI Disk (0,0) — The signed image's hash is not allowed (DB)"*.
  A Canonical-signed `vmlinuz` booted directly is not in the firmware's `db`;
  only `shim` is.

And on the HCS path the command line never arrived: `OptionalData` was tried
base64 and raw, with `ScsiDrive` and `VmbFs` boot entries, and the guest's
serial console carried 29 bytes of firmware escape codes and nothing else
every time. `LinuxKernelDirect` has none of these problems, so the EFI
partition writer was deleted rather than left in the tree.

## Host-neutral gates

| Gate | Result |
|---|---|
| `cargo fmt --all --check` | pass |
| `cargo clippy -p asterism-core -p asterism-daemon -p asterism-hyperv --all-targets -- -D warnings` | pass |
| `cargo test -p asterism-core -p asterism-hyperv` | pass |
| `cargo test -p asterism-daemon` | pass except one pre-existing failure unrelated to this change (`backend::qemu::tests::an_oci_rootfs_is_prepared_for_a_direct_kernel_boot`, which fails identically on `origin/main` on this development machine because its cached guest kernel no longer verifies) |
| `cargo check -p asterism-core -p asterism-hyperv --target x86_64-pc-windows-msvc` | pass |
| `cargo check -p asterism-daemon --target x86_64-pc-windows-gnu` | pass (mingw-w64; the msvc target cannot cross-link `ring` from macOS) |
| `scripts/check-hyperv-boundary.sh` | pass — the daemon seam carries no Windows API |
| `scripts/check-windows-host.sh` | pass |
| `scripts/check-rust-source-graph.sh --self-test` | pass |

The tests that carry the load rather than the count: the HCS document is
asserted arm by arm (an OCI guest gets `LinuxKernelDirect` and no seed ISO; a
cloud image keeps its firmware and its seed; a config written before this
change deserializes onto the cloud-image arm); `backing_files()` is asserted
to cover everything the document names; both Hyper-V Socket service GUIDs are
asserted to be the `hv_sock` template with the vsock port in the first double
word and to be registered per VM; and the generated init for a Hyper-V guest
is asserted to load `vsock` then `hv_sock`, in that order, before the agent
that opens the door starts — and to load no virtio transport at all.

## What did not run

**No OCI image was pulled or booted, and nothing crossed the door.**

Building an OCI root filesystem needs `mke2fs` and `debugfs` from e2fsprogs,
which this Windows host does not have and which no Windows install lane ships
yet. So the boot above used the pinned kernel and initrd with an empty disk
in place of a real OCI rootfs, and these remain **unproven**:

* that `nginx:alpine` — or any pulled image — comes up as pid 1 under the
  generated init on this backend;
* that the guest agent answers over `AF_HYPERV` (nothing was listening in the
  guest to answer);
* that an HTTPS request through the door reaches upstream with the handle
  substituted, and that the plaintext credential appears in neither the VHDX
  nor any log.

## Proves / does not prove

**Proves.** Hyper-V boots an OCI guest's kernel and initrd directly, and the
command line this backend builds arrives in the guest verbatim. The door's
`AF_HYPERV` listener binds against one compute system through its own service
table, with no machine-wide registration. The document `astd` submits and the
files it grants agree with each other. All of that ran on a real Windows
host, on a Home edition, and every object it created was removed.

**Does not prove.** Anything above the boot: no image, no agent, no byte
through the door. The guest half of the door is unchanged code that is proved
on two other backends, and the transcript it speaks is shared — but "unchanged
and shared" is an argument, not a run, and this file does not confuse the two.

## How to finish it

On the same host, once e2fsprogs (`mke2fs`, `debugfs`) is on `PATH` and
`astd.exe` from this branch is installed beside `astd-hyperv.exe`:

```text
ast pull nginx:alpine
ast create web --image nginx:alpine --backend hyperv --cpus 2 --mem 2048
ast secret add demo-token
ast attach web --secret demo-token
ast up web
ast exec web -- wget -qO- https://api.example.com/whoami
ast down web && ast rm web
```

What to capture: `/proc/cmdline` from inside the guest; the upstream's view of
the substituted credential; and a search of `instances\web\disk.vhdx` and
every log for the plaintext value, which must find nothing. Then confirm no
Asterism-owned HCS system, HCN endpoint or `hyperv-egress.json` survives the
`ast rm`.
