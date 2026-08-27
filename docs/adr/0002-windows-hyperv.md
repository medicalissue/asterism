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
| availability and mutation gate | helper | Windows build 22000+; `vmcompute` and `hns` services; elevation; HCS service properties. The gate is capability, never edition: see ADR 0005 §5. |
| VM lifecycle and adoption | helper HCS adapter | ComputeCore/HCS v2.1: create, open, start, properties, shutdown, terminate, save |
| network | helper HCN adapter | ComputeNetwork/HCN v2: create/open/delete one private NAT network per device and one endpoint per VM |
| boot/storage devices | HCS configuration | Generation 2 UEFI, synthetic SCSI, synthetic NIC, serial console, built-in devices only |
| local root/data disks | helper VirtDisk adapter | VirtDisk v2 VHDX create/open/attach/detach plus `HcsGrantVmAccess` |
| guest control | helper Hyper-V Socket adapter | `AF_HYPERV`/`HV_PROTOCOL_RAW`; Linux `AF_VSOCK`; Asterism port 1023 service-template GUID |
| stopped snapshots | common backend helper | filesystem clone/copy of a closed VHDX; same tag semantics as other backends |
| live save/restore seam | helper HCS adapter | `HcsSaveComputeSystem` to VMRS and HCS restore configuration; not advertised until real-host validation |

The Rust binding is pinned to `windows-sys = 0.61.2`, already present in the
workspace lockfile. Only these feature groups are enabled in the helper:
`Win32_Foundation`, `Win32_Networking_WinSock`, `Win32_Security`,
`Win32_Storage_FileSystem`, `Win32_Storage_Vhd`,
`Win32_System_Com`,
`Win32_System_HostComputeNetwork`, `Win32_System_HostComputeSystem`,
`Win32_System_Hypervisor`, `Win32_System_IO`, `Win32_System_Services`,
`Win32_System_SystemInformation`, and `Win32_System_Threading`. No downloaded VMM, QEMU executable, WHPX
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
request are shared protocol, while socket address construction and the HCS
per-VM service table live only in the helper. Boot does not return until the
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

The floor is Windows 11 build 22000 or newer, x86-64 or arm64, with SLAT, VM
monitor extensions, DEP, and firmware virtualization — and Hyper-V present and
enabled. The edition is not part of that floor and never was part of the
check: mutation is allowed exactly when the HCS/HCN services and direct API
probes really pass, on whichever Windows the device is running, and the
refusal names how to enable Hyper-V rather than a SKU (ADR 0005 §5). The
daemon must be elevated or run under an account delegated equivalent access;
the initial implementation requires membership in local Administrators and
emits that requirement rather than attempting elevation.

`probe` is read-only and ordered before every mutation:

1. reject a non-Windows host;
2. reject an unsupported Windows build (the edition is recorded for
   diagnostics and decides nothing);
3. reject a non-elevated token;
4. reject disabled or pending-reboot Hyper-V/HCS/HCN services;
5. query HCS service properties and HCN API availability;
6. check helper protocol/build identity (release builds pin the source commit;
   unlabelled source builds report the weaker `+unknown` identity).

No network, endpoint, VHDX, compute system, instance
record, or snapshot is created until all six pass. Error text names the failed
precondition and the operator action; it never silently selects WHPX/QEMU.

Stopping preserves the HCS system and HCN endpoint so a later `ast up` can
adopt them. Removing a stopped instance terminates its HCS system, deletes its
endpoint, and deletes the shared Asterism NAT network only when no other
instance configuration still references it. A cleanup failure leaves the
instance row and directory intact rather than reporting a successful removal.

## Verification boundary

Portable unit tests validate protocol compatibility, configuration documents,
stable IDs, capability gates, disk snapshot semantics, and pre-mutation probe
ordering. Windows CI compiles every Windows-only helper adapter against the
pinned SDK bindings, while the host-neutral daemon seam remains in the common
workspace/conformance lanes; a static gate (POSIX python3 or PowerShell,
not `rg`) rejects QEMU/WHPX/PowerShell paths inside the helper and Windows
API leakage into the daemon. A dedicated elevated Windows host
real-host harness (`scripts/hyperv-real-host-harness.ps1`, opt-in via
`ASTERISM_HYPERV_REAL_HOST=1`) is the only evidence accepted for VM creation,
Linux boot, Hyper-V Socket readiness, daemon-restart adoption, stop/restart,
save/restore, and cleanup.

GitHub hosted `windows-latest` cannot run that harness. It is Windows Server
Datacenter without nested Hyper-V, so create/boot/control/snapshot/restart/
adoption/stop of a real Linux guest remain **unverified** even when the
source, cross-compile, and protocol lanes are green.

Evidence records the exact edition, build, and feature/service states, because
those are the facts about the host a reader needs — not because the edition
qualifies the result. The harness writes an evidence directory
with OS edition/build, feature/service state, helper build ID, each operation's
result, and the final absence of Asterism-owned HCS/HCN objects.

## Consequences

- Windows-specific mechanisms stay behind one executable seam and common
  capability gates remain the only product branching.
- Running guests can outlive both daemon and helper processes.
- A supported Windows artifact must add the pinned `astd-hyperv` binary and no
  VMM runtime; this change does not claim a Windows release artifact exists.
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
