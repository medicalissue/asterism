# ADR 0005 — Hyper-V boots an OCI guest with a direct kernel, and its secret door is an AF_HYPERV socket bound to one VM

| | |
|---|---|
| Status | **Accepted** for the AST-47 implementation |
| Date | 2026-08-27 |
| Context | ADR 0002 (the helper boundary), ADR 0003 (the VZ door), ADR 0004 (the CHV door); `docs/OCI-RUNTIME.md`; `docs/SECRETS.md` §1 and §4 |
| Supersedes | the `direct_kernel: false` and `guest_egress: None` rows for `hyperv` in `crates/asterism-daemon/src/backend/hyperv.rs` |
| Does not change | the helper boundary. HCS, HCN, VirtDisk and WinSock still stop at `astd-hyperv.exe`; `astd` gained no Windows API |
| Evidence | `docs/evidence/hyperv-oci-boot-2026-08-27/` — executed on a real Windows host |

## 1. The problem this decides

Two things were missing from the native Windows backend, and they are
independent problems that happen to share a guest.

**An OCI image has no bootloader.** It is a root filesystem. Every other
backend boots one by being handed a kernel and an initrd — QEMU's `-kernel`,
Cloud Hypervisor's `--kernel`, `VZLinuxBootLoader`. `hyperv` declared
`direct_kernel: false`, so `ast create --image <oci ref> --backend hyperv`
was refused before the instance row was written.

**A bound secret needs a door only one guest can reach.** Every Hyper-V guest
has its own address on the private HCN NAT, so the NAT's gateway address is
shared by every guest on it. Binding the secrets proxy there would put an
unauthenticated proxy for somebody's API keys where every other guest — and,
depending on the profile, the LAN — can reach it. That is the same problem
`vz` and `chv` have, and it has the same answer.

## 2. Hyper-V does have direct kernel boot

The compute service takes a kernel, an initrd and a command line directly:

```json
"Chipset": {
  "LinuxKernelDirect": {
    "KernelFilePath": "…/x86_64-vmlinuz",
    "InitRdPath":     "…/x86_64-initrd",
    "KernelCmdLine":  "root=LABEL=asterism rw console=ttyS0 …"
  }
}
```

This is the entry point Linux containers on Windows boot through, and it is
what `astd` now uses for an OCI guest: the same pinned kernel and initrd every
other backend loads, the same `asterism.*` keys on the command line, and no
firmware in the path at all.

```text
root=LABEL=asterism rw console=ttyS0 net.ifnames=0 panic=10
init=/asterism-init asterism.ip=<addr>/20 asterism.gw=172.29.64.1
asterism.dns=1.1.1.1 asterism.time=<unix>
```

`root=LABEL=asterism` rather than `/dev/sda`: the label is what
`mke2fs -L asterism` wrote when the OCI rootfs was built, which is a fact
about the filesystem rather than about the order a SCSI controller happened
to enumerate. A cloud image keeps the UEFI arm it already had, seed ISO and
all — `BootSource` in the helper protocol is what selects between them, and a
config written before this change deserializes onto the UEFI arm.

### 2.1 What was tried first, and why it is not what shipped

The first design assumed the sentence "Hyper-V has no direct kernel boot" and
built around it: write the pinned kernel — Ubuntu's x86-64 `vmlinuz` is an
EFI-stub PE — to `\EFI\BOOT\BOOTX64.EFI` on an EFI System Partition built in
Rust, and pass the command line as the loaded image's UEFI load options
(`Chipset.Uefi.BootThis.OptionalData`). It is recorded here because the real
host is what refuted it, and because the refutation is the useful part:

* The partition itself was sound. Windows' own GPT parser and FAT driver
  mounted the disk `astd` wrote, with the kernel at the fallback path and its
  bytes identical to the pinned artifact.
* A stock Hyper-V Generation 2 VM booted that disk to a running Linux kernel
  with **Secure Boot off**, and refused it with **Secure Boot on**:
  *"SCSI Disk (0,0) — The signed image's hash is not allowed (DB)"*. A
  Canonical-signed `vmlinuz` booted directly is not in the firmware's `db`;
  only `shim` is. Turning Secure Boot off for every OCI guest, and shipping
  somebody else's signed `shim` to avoid that, are both worse than not
  needing a firmware at all.
* `OptionalData` never reached the kernel as its command line on the ESP
  path, base64 or raw, so the boot would have had no `root=` even if the
  firmware had started it.

`LinuxKernelDirect` has none of those problems: no firmware, so no Secure
Boot policy, and the command line is a field rather than a load option. The
EFI-partition writer that was built for the first design has been removed
rather than left in the tree as an unused alternative.

## 3. The door: an AF_HYPERV socket bound to one VM

Identical in shape to ADR 0003 and ADR 0004, and identical on the wire:

```text
 guest                        astd-hyperv.exe            astd
 -----                        ---------------            ----
 HTTPS_PROXY=http://127.0.0.1:1021
 the agent listens on the
 guest's own loopback --------.
                              | AF_VSOCK connect(CID 2, port 1021)
                              |   which on Linux/Hyper-V is hv_sock
                              v
                     AF_HYPERV listener bound to
                     (VmId = this compute system,
                      ServiceId = 000003fd-facb-11e6-…)
                     prove the per-Instance key
                     (HMAC-SHA256, asterism-guest-egress)
                                                         |
                                                         v
                                              \\.\pipe\asterism-egress-<hash>
                                              a named pipe whose descriptor
                                              names only astd's own identity
```

**The guest needed no change.** Linux presents Hyper-V sockets through the
same AF_VSOCK ABI with the host fixed at CID 2, so `asterism-guest` dials the
same address it dials on `vz` and `chv`. What differs is one kernel module:
the init loads `hv_sock` instead of `vmw_vsock_virtio_transport`, which is a
backend-declared `oci::VsockTransport`, never inferred in the guest.

**The service GUID.** `hv_sock` maps an AF_VSOCK port to a service GUID by
substituting the port into the first double word of the VSOCK template GUID
`00000000-facb-11e6-bd58-64006a7986d3` (Linux
`Documentation/virt/hyperv/vmbus.rst`). Port 1021 is therefore
`000003fd-facb-11e6-bd58-64006a7986d3`, derived by the same
`service_guid(port)` this backend already used for the guest-control channel
on port 1023.

**No registry key.** The obvious way to register a Hyper-V Socket service is
a machine-wide value under
`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization\GuestCommunicationServices`.
This does not use it, and the reason is not tidiness: a machine-wide
registration is machine-wide. The HCS document instead carries a **per-VM**
`Devices.HvSocket.HvSocketConfig.ServiceTable` entry with
`AllowWildcardBinds: false`, which admits a host listener bound to *this VM's
id* and refuses one bound to the wildcard. That is what makes the door
instance-only by construction rather than by an HMAC alone, and it is why
there is nothing to clean up on `ast rm`.

**The host end is a named pipe, not a socket file.** On Unix the egress plane
owns a socket under `$ASTERISM_HOME` and filesystem permissions keep it
private. Windows has no such file, so `astd` creates a kernel named pipe with
a security descriptor naming only its own SID —
`O:<astd>D:P(A;;GA;;;<astd>)` — and tells the helper the name. The helper
`astd` spawned runs as that identity and nothing else on the device does.
The pipe's name follows a hash of the instance rather than the instance
itself: pipe names are a flat machine-wide namespace with a much narrower
character set, and what keeps this one private is its descriptor, not its
spelling.

### 3.1 One request that does not return

Every other helper request is one round trip over stdio, because HCS owns the
VM and a later helper reopens its GUID (ADR 0002 §4). A listener cannot work
that way. `Request::ServeEgress` is the exception: the helper binds, answers
`Serving`, and then serves until it is killed. `astd` records its `ProcId`
beside the VM config and kills it on `stop`, `kill` and `rm`; a daemon that
restarts adopts the recorded process rather than binding a second listener
against the same VM.

The helper is started **before** the compute system exists and retries its
bind until HCS has created the VM whose service table admits it. Opening the
door after the guest was already running would be a guest holding a handle
nothing honours, which is the failure mode this whole feature is written to
avoid.

### 3.2 What the splice does not do

The named pipe has no half-close. When the guest hangs up, the host end
cannot signal end-of-stream to `astd` without closing the whole pipe, so the
direction still reading from `astd` polls with a short deadline and stops
when the other direction has finished. That is a 500 ms tail on a closing
connection and nothing else; the alternative was a thread blocked in a
synchronous `ReadFile` that only a handle close would break.

### 3.3 The grant list follows the document

HCS refuses to create a VM whose backing files the VM identity cannot open,
and the set of those files is decided by the boot source: an OCI guest is
handed a kernel and an initrd and has no NoCloud seed. Granting a seed that
was never built fails the create with `ERROR_FILE_NOT_FOUND` — which is how
the real host found the first version of this, and why `backing_files()` now
lives beside `hcs_document()` with a test that the two agree.

## 4. What this does not decide

* **Directory shares, NBD disks, published ports and GPU projection.**
  `hyperv` still declares none of them and still refuses before mutation, in
  the same words. Nothing here made any of them closer.
* **arm64.** There is no arm64 Hyper-V host in this project's matrix.
* **`ast pull` on Windows.** Building an OCI root filesystem needs
  `mke2fs`/`debugfs` from e2fsprogs, exactly as it does on macOS and Linux.
  That is an install-lane question this ADR does not answer; it is unchanged
  by anything here, and it is why the evidence for this change boots the
  pinned kernel and initrd rather than a pulled image.

## 5. The gate is Hyper-V, not the Windows edition

Nothing in this backend asks what edition of Windows it is on. The gate is
whether Hyper-V is present and enabled — `vmcompute` and `hns` answering, an
elevated token, build 22000 or newer — and a device that answers those runs
the same native contract whichever edition it is. The evidence for this ADR
was produced on Windows 11 Home with Hyper-V enabled, which is a device like
any other. The refusal names how to enable it — `ast doctor`'s row carries
`Enable-WindowsOptionalFeature -Online -All -FeatureName Microsoft-Hyper-V`
as its `fix`, with `bcdedit /set hypervisorlaunchtype auto` in the note for
the machines where the hypervisor itself was turned off — rather than naming
a SKU to go buy. The edition is reported as diagnostics.
