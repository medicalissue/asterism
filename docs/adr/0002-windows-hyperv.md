# ADR 0002: native Windows virtualization boundary

- Status: accepted for the `as-lvf.8` implementation
- Date: 2026-08-22
- Supersedes: no earlier Windows backend decision
- Context: `as-lvf.3` was not merged when implementation began

## Decision

The Windows product backend is `hyperv`. It is a native Hyper-V backend built
on the Windows Host Compute System (HCS), Host Compute Network (HCN), Virtual
Disk API, and Hyper-V Socket. It is not QEMU accelerated by WHPX, and it does
not contain a userspace VMM or device model.

`astd` continues to depend only on `asterism_core::hv::Hypervisor`. A small
`astd-hyperv` helper is the only component allowed to call Windows
virtualization APIs. The daemon and helper exchange versioned serde messages;
HCS configuration JSON, HCN policy JSON, Win32 handles, registry paths,
PowerShell, and WMI types never cross that protocol.

```text
product control plane
  astd -> Hypervisor { prepare, boot, state, stop, kill, snapshot, restore }
             |
             | asterism-hyperv protocol (JSON over inherited stdio)
             v
  astd-hyperv helper
       | HCS                 create/open/start/query/shutdown/terminate/save
       | HCN                 private NAT network + per-VM endpoint
       | VirtDisk            create/attach/write VHDX
       | AF_HYPERV           authenticated guest readiness/control
       ` WMI v2 adapter      only the fallbacks listed below
```

The helper is one-shot. A running VM is owned by HCS, not by the helper or
daemon process. Its stable compute-system GUID is persisted in the instance
directory. A later helper uses `HcsOpenComputeSystem`, so restarting `astd` or
the helper does not stop or orphan the guest. HCS configuration sets
`ShouldTerminateOnLastHandleClosed` to false.

### Exact API ownership

| Concern | Owner | Pinned API/schema |
|---|---|---|
| availability and mutation gate | helper | Windows 11 Pro/Enterprise; `vmcompute` and `hns` services; elevation; HCS service properties |
| VM lifecycle and adoption | helper HCS adapter | ComputeCore/HCS v2.1: create, open, start, properties, shutdown, terminate, save |
| network | helper HCN adapter | ComputeNetwork/HCN v2: one private NAT network and one endpoint per VM |
| boot/storage devices | HCS configuration | Generation 2 UEFI, synthetic SCSI, synthetic NIC, serial console, built-in devices only |
| local root/data disks | helper VirtDisk adapter | VirtDisk v2 VHDX create/open/attach/detach plus `HcsGrantVmAccess` |
| guest control | helper Hyper-V Socket adapter | `AF_HYPERV`/`HV_PROTOCOL_RAW`; Linux `AF_VSOCK`; Asterism port 1023 service-template GUID |
| stopped snapshots | common backend helper | filesystem clone/copy of a closed VHDX; same tag semantics as other backends |
| live save/restore | helper HCS adapter | `HcsSaveComputeSystem` to VMRS and HCS restore configuration |

The Rust binding is pinned to `windows-sys = 0.61.2`, already present in the
workspace lockfile. Only these feature groups are enabled in the helper:
`Win32_Foundation`, `Win32_Networking_WinSock`, `Win32_Security`,
`Win32_Storage_FileSystem`, `Win32_Storage_Vhd`,
`Win32_System_HostComputeNetwork`, `Win32_System_HostComputeSystem`,
`Win32_System_Hypervisor`, `Win32_System_Registry`, and
`Win32_System_SystemInformation`. No downloaded VMM, QEMU executable, WHPX
wrapper, or mutable installer-time component is part of this path.

### Disk and image contract

Asterism's common image store remains raw. `prepare` asks the helper to create
a dynamic VHDX through `CreateVirtualDisk`, attaches it without a drive letter,
and writes the raw whole-disk image to the exposed physical-disk path. This is
a byte-preserving container conversion performed by Windows' virtual-disk
driver, not by `qemu-img` or a handwritten VHDX encoder. A pre-existing VHDX
may be cloned directly. The NoCloud seed is attached as a virtual DVD and
additional local block parts are VHDX attachments.

OCI root filesystems have no firmware-visible bootloader. HCS can describe a
Generation 2 VM, but this implementation does not invent a Windows-hosted
kernel/bootloader supply chain. Therefore `direct_kernel` remains false and
OCI references are refused before instance mutation by the common capability
gate. This is explicit partial coverage of the attached request, not a QEMU
fallback hidden behind `hyperv`.

### Guest control boundary

The seed installs the existing authenticated Asterism guest agent. Linux sees
the built-in Hyper-V socket transport as `AF_VSOCK`; the Windows helper connects
with `AF_HYPERV` using the compute-system GUID and the service GUID derived from
port 1023 (`000003ff-facb-11e6-bd58-64006a7986d3`). The HMAC session and status
request are shared protocol, while socket address construction and the host
registry registration live only in the helper. Boot does not return until the
agent reports an address and an SSH listener.

### WMI v2 fallback list

The list is deliberately closed. Adding an entry requires updating this ADR
and a test that proves the HCS/HCN/VirtDisk route cannot supply the operation.

1. `Msvm_VirtualSystemManagementService` checkpoint graph operations may be
   used only if real-host testing shows the HCS save/restore document cannot
   restore across a helper/daemon process lifetime. HCS save is the primary
   implementation; the WMI adapter is not called on the current path.
2. `Msvm_ImageManagementService` may inspect or repair a VHDX parent chain
   created by Hyper-V checkpoints. It is not used for raw conversion, VHDX
   creation, or ordinary attach; those stay on VirtDisk.

There are no WMI fallbacks for create/start/open/state/stop, network creation,
disk creation, guest readiness, edition detection, or privilege detection.
PowerShell is not an API dependency. It is permitted only in the operator
real-host harness as a transparent way to enable/check Windows features and
to independently assert what the direct API created.

### Availability, privilege, and mutation order

The supported client floor is Windows 11 Pro or Enterprise, build 22000 or
newer, x86-64 or arm64, with SLAT, VM monitor extensions, DEP, and firmware
virtualization. Windows Home is unsupported. Hyper-V and Containers optional
features must already be enabled and the host must have rebooted. The daemon
must be elevated or run under an account delegated equivalent access; the
initial implementation requires membership in local Administrators and emits
that requirement rather than attempting elevation.

`probe` is read-only and ordered before every mutation:

1. reject a non-Windows host;
2. reject an unsupported product edition/build;
3. reject a non-elevated token;
4. reject disabled or pending-reboot Hyper-V/HCS/HCN services;
5. query HCS service properties and HCN API availability;
6. check helper protocol/build identity.

No network, endpoint, VHDX, registry service key, compute system, instance
record, or snapshot is created until all six pass. Error text names the failed
precondition and the operator action; it never silently selects WHPX/QEMU.

## Verification boundary

Portable unit tests validate protocol compatibility, configuration documents,
stable IDs, capability gates, disk snapshot semantics, and pre-mutation probe
ordering. Windows CI must compile the helper and daemon seam and runs the
non-mutating tests. A dedicated elevated Windows 11 Pro/Enterprise real-host
harness is the only evidence accepted for VM creation, Linux boot, Hyper-V
Socket readiness, daemon-restart adoption, stop/restart, save/restore, and
cleanup.

As of this decision's commit, no Windows host evidence has been recorded.
Those real-host claims must remain marked **unverified**, even if cross-compile
and mocked conformance are green. The harness writes an evidence directory
with OS edition/build, feature/service state, helper build ID, each operation's
result, and the final absence of Asterism-owned HCS/HCN objects.

## Consequences

- Windows-specific mechanisms stay behind one executable seam and common
  capability gates remain the only product branching.
- Running guests can outlive both daemon and helper processes.
- Installation adds one pinned Rust helper binary and no VMM runtime.
- Cloud-disk images are implementable without QEMU. OCI direct boot remains a
  stated unsupported capability until a native, pinned boot input exists.
- A green macOS/Linux suite is not proof that Hyper-V works; the Windows host
  lane is a release gate for advertising this backend as supported.

## Primary references

- Microsoft Host Compute System API reference and compute-system samples:
  <https://learn.microsoft.com/en-us/virtualization/api/hcs/reference/apioverview>
- Microsoft HCS quick start (schema 2.1 Generation 2 VM):
  <https://learn.microsoft.com/en-us/virtualization/api/hcs/reference/tutorial>
- Microsoft Hyper-V Socket integration service guide:
  <https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/make-integration-service>
- Microsoft Hyper-V host and edition requirements:
  <https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/host-hardware-requirements>
