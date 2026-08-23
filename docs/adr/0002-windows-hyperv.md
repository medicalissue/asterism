# ADR 0002 — Windows virtualization: HCS + HCN + Hyper-V Socket is the native backend; WMI v2 is a closed fallback list; WHPX/QEMU is reached only by refusal

| | |
|---|---|
| Status | **Proposed** — source-only architecture decision for independent adversarial review (as-lvf.3). Nothing in this document has been executed on a Windows host. |
| Date | 2026-08-23 |
| Deciders | owner (medicalissue); proposal by asterism/polecats/furiosa |
| Base | `origin/main` `3becc153a9e71e43f6a1dd899bedc4fdd50f8c73` |
| Relates to | ADR 0001 (the Linux decision, same shape: consume a native hypervisor behind `hv::Hypervisor`, never own a VMM) |
| Gates | as-lvf.8 (implementation) must not advertise `hyperv` as supported until §8 has real-host evidence. An earlier, unmerged draft of this file exists on `origin/polecat/*/as-lvf.8*` branches; this proposal replaces it on `main` and differs from it where §10 says so. |

## 1. Decision

1. **On Windows, Asterism's product backend is `hyperv`: a native backend on
   the Windows Host Compute System (HCS, `computecore.dll`, schema 2.1),
   Host Compute Network (HCN, `computenetwork.dll`, schema 2), the Virtual
   Disk API (`virtdisk.dll`, VHDX) and Hyper-V Socket (`AF_HYPERV` on the
   host, `AF_VSOCK` in the guest).** Windows supplies the VMM, the device
   model, the virtual switch and the disk driver. Asterism supplies
   configuration documents and a small helper process, exactly as `vz` does
   on macOS.
2. **Hyper-V WMI v2 (`root\virtualization\v2`) is permitted only through one
   narrow adapter, for the closed list in §5.** Anything not on that list is
   not a fallback; it is a capability the backend refuses.
3. **WHPX is rejected as a product backend.** Writing against
   `WHvCreatePartition` makes Asterism own a VMM and a device model — the
   one thing ADR 0001 already refused on Linux. **QEMU + WHPX remains the
   explicit compatibility floor** (foreign-arch guests, qcow2 a user points
   at, anything `hyperv` refuses by `Caps`), selected exactly as it is on the
   other hosts: by refusal of a capability, never by backend name, and never
   silently when `hyperv` fails a precondition.
4. **PowerShell is not an API dependency.** The `Hyper-V` PowerShell module
   and `Get-VM` cannot even see HCS-owned systems (§2), so a PowerShell path
   inside the product would be a second, divergent backend. PowerShell is
   allowed only in the operator-run proof harness (§7) to enable optional
   features and to assert independently what the direct APIs created.

## 2. Why this needed a decision rather than a sentence

The hypothesis on the epic was "HCS + HCN + Hyper-V Socket, WMI only where
HCS cannot". The following are the ways it could be wrong, what the sources
say, and what survives. Every "survives" here is documentation-level until §8
is run; none is hardware evidence.

* **"HCS is a container API; a real Generation 2 Linux VM is not its job."**
  Does not survive. HCS schema 2.x has a `VirtualMachine` system type with
  `Chipset.Uefi` (Generation 2 boot), `Devices.Scsi`, `Devices.NetworkAdapter`
  (bound to an HCN endpoint), `Devices.ComPorts`, `Devices.HvSocket`, `Memory`,
  `Processor` and `Chipset.LinuxKernelDirect`. It is the API WSL 2, Windows
  Sandbox and Docker Desktop's WSL/Hyper-V backends use for exactly a Linux
  VM, and Microsoft documents schema 2.1 VM creation as the HCS tutorial.
* **"HCS systems are invisible to the rest of Hyper-V, so WMI cannot be a
  fallback for them."** *Survives, and it shapes §5.* A compute system created
  by `HcsCreateComputeSystem` is owned by the `vmcompute` service and is not
  registered with VMMS: `Get-VM`, Hyper-V Manager and `Msvm_ComputerSystem`
  do not list it (this is why WSL 2's VM is not in Hyper-V Manager).
  Consequence: WMI v2 can never be a fallback for *per-VM* operations on an
  `hyperv` instance — no WMI checkpoints, no WMI save, no WMI device
  hot-add. The only WMI fallbacks that can exist are ones that take a file
  or a host object, not a VM. §5 is written under that constraint; the
  earlier draft's "checkpoint graph via `Msvm_VirtualSystemSnapshotService`"
  is struck for this reason.
* **"Save/restore needs Hyper-V checkpoints, which need WMI."** Does not
  survive. `HcsSaveComputeSystem` writes a VMRS-style save file; restore is a
  create with `VirtualMachine.RestoreState.SaveStateFilePath` (schema 2.1).
  Disk state comes from Asterism's own stopped-disk snapshot path, not from a
  Hyper-V differencing chain. Cross-host-build compatibility of that save
  file is **unknown** (§8 H7) and is the reason `live_snapshot` ships `false`
  until proven, mirroring how ADR 0001 treated Cloud Hypervisor snapshots.
* **"A Linux guest cannot use Hyper-V Socket without a host-wide registry
  registration that needs Administrator."** Partly survives. The host-wide
  `GuestCommunicationServices` registry key is what *VMMS-managed* VMs need.
  HCS systems instead carry a per-VM `Devices.HvSocket.HvSocketConfig.
  ServiceTable`, so the Asterism service GUID is registered on the compute
  system, not on the host. The daemon still needs Administrator for HCS
  itself (§4), so this is not a privilege reduction; it is a containment of
  host-global state, which the earlier draft already relied on.
* **"Windows Home has no Hyper-V, so Home is out."** *Does not fully survive,
  and is left open on purpose.* Home lacks the `Microsoft-Hyper-V` feature
  (Hyper-V Manager, VMMS, the PowerShell module, WMI v2), but it has
  `VirtualMachinePlatform`, which is what WSL 2 and Docker Desktop's WSL
  backend run on — and that is HCS + HCN. Whether `VirtualMachinePlatform`
  alone is sufficient for a third-party HCS `VirtualMachine` with UEFI boot is
  **unverified** (§8 H2). §4 therefore lists Home as *not supported until
  proven*, not *unsupported*. If H2 passes, Home support costs nothing in
  architecture because §5's WMI list is already not required for the
  lifecycle.
* **"OCI images cannot boot on Hyper-V because there is no direct kernel
  boot."** Does not survive on paper. `Chipset.LinuxKernelDirect`
  (`KernelFilePath`, `InitRdPath`, `KernelCmdLine`) is the mechanism WSL 2
  uses, and the tree already pins per-architecture Ubuntu kernels for OCI
  (`crates/asterism-core/src/oci.rs` `KERNELS`). The earlier draft set
  `direct_kernel: false` and refused OCI; this proposal sets the
  *architecture* to `direct_kernel: true` gated on §8 H8, so that OCI parity
  is a proof item rather than a design exclusion. Until H8 passes the
  implementation reports `false`.
* **"Windows has no `clonefile`, so disk snapshots are full copies."**
  Survives on NTFS, not on ReFS. `FSCTL_DUPLICATE_EXTENTS_TO_FILE` gives
  block cloning on ReFS, which is also what Windows 11 Dev Drive is. The
  backend's `disk_snapshot` semantics are unchanged (whole-file clone of a
  stopped disk, identical tag semantics to `vz`/`qemu`); only the cost
  differs by filesystem and the probe records which one the instance root is
  on. No VHDX differencing chains are created by Asterism (§5 explains why).
* **"GitHub-hosted Windows runners can prove this."** Survives as a
  limitation. `windows-latest` is Windows Server Datacenter on an Azure VM;
  whether nested virtualization is exposed is a property of the runner SKU
  that Microsoft does not contract for. §7 treats hosted CI as a
  compile/static/protocol lane only; real-host evidence comes from §7.3.

## 3. Architecture

```text
astd (host-neutral)                      astd-hyperv helper (Windows-only)
  Hypervisor::{probe,caps,prepare,boot,    ─ the only code that links
    state,stop,kill,snapshot,restore,        computecore / computenetwork /
    disk_*,attach_disk}                      virtdisk / ws2_32 AF_HYPERV / WMI
        │  versioned JSON over the
        │  helper's stdio, then              HCS      create/open/start/props/
        │  ControlChannel::Rpc{path}                  shutdown/terminate/save/modify
        ▼                                    HCN      one NAT network per device,
  Handle { backend:"hyperv",                          one endpoint per instance
           pid: None, proc: None,            VirtDisk create/attach/detach VHDX,
           ctl: Rpc{..}, endpoint:                    HcsGrantVmAccess
           GuestAddr{..} }                   HvSock   AF_HYPERV → guest :1023
                                             WMI v2   §5 only, one adapter module
```

* **Process model.** As with `vz`, one helper per operation family, no
  Windows API linked into `astd`. Unlike `vz`, the running guest is **not**
  owned by the helper process: an HCS compute system is owned by the
  `vmcompute` service and is configured with
  `ShouldTerminateOnLastHandleClosed: false`, so the helper exits after
  `boot` and a later helper re-attaches with `HcsOpenComputeSystem` by the
  stable compute-system id persisted in the instance directory. `Handle.pid`
  and `Handle.proc` are therefore `None`; the proof of identity is the HCS
  id, which is a GUID Asterism chose and `state()` queries, never a pid it
  remembered. **That HCS keeps the guest alive across helper and daemon exit
  is the single most important unverified claim in this ADR (§8 H5).**
* **What crosses the seam.** Only the existing `hv` types and one new
  helper protocol. HCS/HCN JSON documents, `HRESULT`s, handles, registry
  paths, WMI class names and PowerShell never appear above the helper.
  `ControlChannel::Rpc { path }` is reused with a named-pipe path
  (`\\.\pipe\asterism-<instance>`) — the conformance profile for `hyperv` is
  `ControlKind::Rpc`, the same row `vz` occupies.
* **Network.** One HCN `NAT` network per device (Asterism-owned name and
  GUID, created on first create, deleted on last remove) and one HCN endpoint
  per instance attached to the VM's synthetic NIC. The guest has its own
  address (`GuestEndpoint::GuestAddr`), so readiness is learned from the
  guest agent over Hyper-V Socket, as on `vz`, never by scanning leases.
* **Disks.** The image store stays raw. `prepare` creates a dynamic VHDX
  through `CreateVirtualDisk`, attaches it with
  `ATTACH_VIRTUAL_DISK_FLAG_NO_DRIVE_LETTER`, writes the raw image through the
  exposed physical-disk path, detaches, and grants the compute system access
  with `HcsGrantVmAccess`. No `qemu-img`, no hand-written VHDX encoder.
  The NoCloud seed is attached as a virtual DVD (`Devices.Scsi` attachment
  `Type: Iso`). Extra local disks are additional VHDX attachments on the
  same SCSI controller. Remote (`NbdUnix`) disks have no native consumer on
  Windows and are refused (§6).
* **Guest control.** The seed installs the existing authenticated guest
  agent unchanged; it listens on `AF_VSOCK` port 1023 exactly as under `vz`
  (Linux `hv_sock` presents Hyper-V Socket as `AF_VSOCK`). The helper
  connects with `AF_HYPERV`/`HV_PROTOCOL_RAW` to `{VmId, ServiceId}` where
  `ServiceId` is the Linux VSOCK template with the port in the first field:
  `000003ff-facb-11e6-bd58-64006a7986d3`. That GUID is listed in the VM's
  per-system `ServiceTable`. The HMAC handshake and the status protocol are
  shared code; only socket address construction is Windows-specific.
* **Console.** `Devices.ComPorts` COM1 to a named pipe, relayed to the
  caller's `console` path by the helper. The guest's console is `ttyS0` on
  x86-64 (Hyper-V Gen 2 exposes a UART via VMBus on recent guests) — §8 H4
  records that this, not `hvc0`, is what has to be proven for the seed's
  console unit.

## 4. Privilege and edition matrix

Every row is a **read-only probe precondition**, checked in the order
listed, before any HCN, VHDX, HCS, instance-record or snapshot mutation. A
failing row names the row and the operator action; it never selects
`qemu`. "Required" rows are what the implementation initially demands;
"proof" rows are what §8 must answer before the row can be relaxed.

| # | Precondition | Windows 11 Pro / Enterprise / Education | Windows 11 Home | Windows Server 2022+ | arm64 (any edition) |
|---|---|---|---|---|---|
| E1 | Product build ≥ 22000 (Windows 11) | required | required | supported floor for CI only; not a product target | required |
| E2 | `Microsoft-Hyper-V` feature enabled, host rebooted | **required** | not available — see E3 | required | required; **unverified** (§8 H3) |
| E3 | `VirtualMachinePlatform` (HCS/HCN without VMMS) | implied by E2 | **unverified whether sufficient** (§8 H2); Home is *not supported until proven* | implied by E2 | as E2 |
| E4 | `vmcompute` service running; `HcsGetServiceProperties` succeeds | required | as E3 | required | required |
| E5 | HCN API reachable (`HcnEnumerateNetworks` succeeds) | required | as E3 | required | required |
| E6 | SLAT, VMX/SVM, DEP, firmware virtualization enabled (`Get-ComputerInfo HyperVRequirement*` is the operator-side check; the probe reads `IsProcessorFeaturePresent` and HCS service properties) | required | required | required | required |
| E7 | Process token elevated **and** member of local Administrators | **required** | required | required | required |
| E8 | Membership in *Hyper-V Administrators* group instead of Administrators | **not accepted** until §8 H6 shows HCS honours it for create/start | same | same | same |
| E9 | Running as a Windows Service account (LocalSystem) rather than an interactive elevated token | accepted once as-lvf.10's service host is the launcher; interactive elevation is the initial path | same | same | same |
| E10 | Instance root filesystem is NTFS or ReFS/Dev Drive | either; ReFS enables block-clone snapshots, NTFS copies | same | same | same |
| E11 | Windows Sandbox / WSL 2 / Docker Desktop concurrently using HCS | allowed; Asterism must not assume it is the only HCS client or the only HCN NAT network | same | same | same |

What this table deliberately does not do: it does not attempt elevation, does
not enable features, and does not distinguish editions by string-matching a
product name. E2/E3 are detected by `HcsGetServiceProperties` and
`HcnEnumerateNetworks` succeeding, with the feature state read only to
produce a better error message.

## 5. WMI v2 fallback inventory (closed)

Constraint from §2: HCS-owned compute systems are not `Msvm_ComputerSystem`
instances, so no WMI class can act on an `hyperv` VM. The list is therefore
limited to operations on **files** and **host objects**, and every entry has
a direct-API replacement that is preferred when it proves sufficient.

| # | Capability | Direct API first | WMI v2 fallback | Status |
|---|---|---|---|---|
| W1 | Inspect / repair a VHDX that an operator attached from a Hyper-V checkpoint chain (`--image ./theirs.vhdx` with a parent) | `GetVirtualDiskInformation`, `OpenVirtualDisk` with `OPEN_VIRTUAL_DISK_FLAG_NO_PARENTS` refuses chained disks cleanly | `Msvm_ImageManagementService.GetVirtualHardDiskSettingData` / `MergeVirtualHardDisk` | **Candidate only.** Asterism never creates differencing VHDX; this fallback exists so that a user-supplied chained disk gets a named refusal or an explicit merge, not a silent boot of the wrong layer. Not required for §8. |
| W2 | Compact / resize a VHDX | `CompactVirtualDisk`, `ResizeVirtualDisk` (VirtDisk v2) | `Msvm_ImageManagementService.CompactVirtualHardDisk`, `ResizeVirtualHardDisk` | Direct API expected sufficient; fallback retained only if §8 finds the VirtDisk path requires a mounted disk Asterism cannot provide. |
| W3 | Bridged/external networking (guest on the LAN, not NAT) | HCN `Transparent` network bound to an external adapter | `Msvm_VirtualEthernetSwitchManagementService` to create an External switch | **Out of scope for this decision.** ADR 0001 left bridged egress undesigned on Linux too; `guest_egress`/bridging stays `None`/unsupported. Recorded so the adversarial review can see it was considered and excluded, not forgotten. |
| W4 | Host capability report for the doctor (`ast doctor`) — VM limits, nested-virt, SLAT | `HcsGetServiceProperties`, `IsProcessorFeaturePresent`, `GetSystemFirmwareTable` | `Msvm_VirtualSystemManagementServiceSettingData`, `Win32_ComputerSystem.HypervisorPresent` | Read-only diagnostics; permitted in the doctor only, never in the mutation path. |

**Explicitly not WMI fallbacks (refused by capability instead):** VM create,
open, start, state, shutdown, terminate, save, restore; device hot-add;
network or endpoint creation; VHDX creation, attach, detach; guest readiness;
edition, feature or privilege detection; checkpoints of any kind. If §8
finds that one of these cannot be done through HCS/HCN/VirtDisk, the answer
is a `Caps` field set to `false` and a named refusal — not a row added here.

## 6. `Caps` for `hyperv`, and what each value is waiting on

| Capability | Proposed value | Mechanism | Proof item |
|---|---|---|---|
| `disk_snapshot` | `true` | whole-file clone of the stopped VHDX (ReFS block clone where available) | H9 |
| `live_snapshot` | `false` → `true` only after proof | `HcsSaveComputeSystem` + `RestoreState.SaveStateFilePath` + disk clone | H7 |
| `live_migration` | `false` | no HCS mechanism for third parties | — |
| `disk_hotplug` | `true` expected | `HcsModifyComputeSystem` `Add` on `VirtualMachine/Devices/Scsi/<ctl>/Attachments/<lun>` | H10 |
| `shared_dir` | `None` | Hyper-V has no virtiofs; HCS `Devices.Plan9` is 9p-over-Hyper-V-Socket, which needs a guest 9p transport that is **not in mainline Linux** (WSL 2 carries it); `ShareKind::NinePfs` in this tree assumes `trans=virtio`. An SMB-over-NAT design is the only mainline path and is future work. | H11 records the check |
| `nbd_disks` | `false` | no native NBD consumer; no host-kernel NBD block device to hand over as `DiskSpec::Block` | — |
| `foreign_arch` | `false` | Hyper-V runs host-arch guests only | — |
| `direct_kernel` | `true` gated on proof; implementation reports `false` until then | `Chipset.LinuxKernelDirect` with the pinned `oci::KERNELS` | H8 |
| `port_forward` | `false` initially | HCN endpoint `PortMapping` policy can publish a guest port on the host; binds on all host interfaces, not loopback, so it does not satisfy `HostForward`'s "loopback only" promise without further design | H12 |
| `guest_egress` | `None` | the NAT gateway is a real host interface (`vEthernet`), not a loopback proxy; `LoopbackGateway` semantics would be false | — |
| `disk_formats` | `[Raw]` from the store; VHDX is a backend container, never a user-facing format | — | — |

`Ready { accel: "hyperv", version: <HCS service version from
HcsGetServiceProperties>, machine_type: "hcs-2.1-gen2", cpu: "host" }`.
`Machine.hv_version` records the host build and HCS schema so that a save
file or VHDX made under one host build is refused, not assumed, under
another.

## 7. Conformance and proof plan

### 7.1 Host-neutral, runs everywhere today

* `hyperv` joins `backend::backends()` behind `cfg(windows)`, and the
  conformance suite's `control_kind` match gains `hyperv::ID => Rpc`. On
  non-Windows builds the registry is unchanged; on Windows builds every
  existing conformance test (`registration_identity_readiness_and_capabilities_share_one_contract`,
  `reloaded_crash_handles_are_stopped_and_never_silently_signalled`,
  `raw_disk_snapshots_have_identical_end_to_end_semantics`,
  `every_capability_gated_method_has_exact_failure_language`,
  `log_share_and_sleep_inputs_stay_outside_host_specific_backends`) runs
  against it with no backend-name conditionals added.
* Helper protocol: versioned request/response types with round-trip tests,
  and a golden-file test for each HCS/HCN document the helper emits (system
  create, endpoint create, save, modify-add-disk), so a schema change is a
  reviewed diff.
* Pre-mutation ordering test: a fake host that fails row *n* of §4 must
  produce zero mutations and an error naming row *n*.
* Static seam gate (`scripts/check-rust-source-graph.sh` extension):
  `windows-sys` HCS/HCN/VirtDisk/WMI features are allowed only in the
  helper crate; `computecore`, `Msvm_`, `powershell`, `whpx`, `qemu` strings
  are forbidden in `asterism-daemon/src/backend/hyperv.rs`.

### 7.2 Hosted Windows CI lane (new `windows-latest` job)

Compile the helper crate against the pinned `windows-sys 0.61.2` feature set,
run the host-neutral suite, run the static seam gate. This lane proves the
source, not the hypervisor; a green run is **not** evidence for any row of
§8. A separate, non-blocking probe step records whether the runner exposes
virtualization (`HcsGetServiceProperties` result) so that the CI limitation
in §2 is measured instead of assumed.

### 7.3 Real-host harness (the only accepted lifecycle evidence)

`scripts/hyperv-real-host-harness.ps1`, opt-in (`ASTERISM_HYPERV_REAL_HOST=1`),
run by an operator on an elevated Windows 11 Pro/Enterprise machine with
§4 E1–E7 already satisfied. It drives the product path (`ast create` /
`ast up` / `ast stop` / `ast snapshot` / `ast rm`) and independently asserts
each step with PowerShell where a direct read exists (`Get-HnsNetwork`,
`Get-VHD`, `Get-Process vmwp`), writing the evidence directory described in
`docs/evidence/windows-hyperv-2026-08-23/README.md`. Acceptance is the bead's
criterion, item by item:

| Step | Asserts | Maps to |
|---|---|---|
| P1 | probe passes; feature/edition/privilege rows recorded | §4 |
| P2 | raw Ubuntu 24.04 cloud image → VHDX via VirtDisk; byte-identical first/last 16 MiB | §3 disks |
| P3 | HCS `VirtualMachine` Gen 2 created; `vmwp.exe` for its id appears; `Get-VM` does **not** list it | §2 invisibility |
| P4 | guest agent handshake over `AF_HYPERV` within the boot deadline; `GuestAddr` learned from the agent | §3 guest control, H1 |
| P5 | kill the helper and restart `astd`; `state()` still `Running`; agent still answers | H5 |
| P6 | `stop` (ACPI via `HcsShutdownComputeSystem`) then `up` re-adopts the same HCS id | acceptance "stops and restarts" |
| P7 | `HcsSaveComputeSystem` → save file; restore → agent answers with uptime continuing | H7, acceptance "save or checkpoint" |
| P8 | stopped-disk snapshot, restore, remove; tag semantics identical to conformance fixture | H9 |
| P9 | hot-add a second VHDX; guest sees a new `sd*` | H10 |
| P10 | `rm` leaves zero Asterism-owned HCS systems, HCN endpoints, and — when last — the NAT network; failure leaves the instance row intact | §3 cleanup |
| P11 | OCI rootfs via `LinuxKernelDirect` with the pinned kernel boots to agent readiness | H8 |
| P12 | repeat P1–P6 with `VirtualMachinePlatform` only (Home-equivalent) and, separately, on arm64 | H2, H3 |

## 8. Unresolved hardware evidence (explicit)

None of the following has been observed on a Windows host by this proposal.
Each is a claim the implementation depends on and the adversarial review
should treat as open.

| # | Claim | Why it matters | If false |
|---|---|---|---|
| H1 | A stock Ubuntu 24.04 cloud image loads `hv_sock` at boot and the agent's `AF_VSOCK` listener on port 1023 is reachable via `AF_HYPERV` with the VSOCK-template service GUID | readiness and all guest control | seed must `modprobe hv_sock`; if the template GUID is wrong, the helper needs a registered custom service GUID in the per-VM `ServiceTable` |
| H2 | `VirtualMachinePlatform` alone (Windows 11 Home) allows a third-party HCS `VirtualMachine` with UEFI boot | edition support claim | Home is unsupported; §4 E3 becomes a hard refusal |
| H3 | HCS Gen 2 Linux VM on Windows 11 arm64 | arm64 host support | `hyperv` refuses on arm64; QEMU+WHPX does not exist on arm64 either, so arm64 Windows has no backend |
| H4 | The guest console is `ttyS0` over COM1 and Ubuntu's cloud image attaches a getty there | console capture, seed console unit | seed console unit for `hyperv` names a different device; no architecture change |
| H5 | An HCS compute system with `ShouldTerminateOnLastHandleClosed: false` survives exit of the creating process and `HcsOpenComputeSystem` re-attaches from a new process under the same elevated account | helper-exits-after-boot model; daemon restart/upgrade without killing guests | the helper must become a long-lived per-instance process like `astd-vz`, `Handle.pid/proc` become `Some`, and the as-lvf.10 service must supervise it — a process-model change, not a backend change |
| H6 | HCS honours *Hyper-V Administrators* group membership for create/start without full Administrators | least privilege for the daemon account | §4 E7 stays as written |
| H7 | `HcsSaveComputeSystem` + `RestoreState` restores a Linux guest with VMBus devices and the Hyper-V Socket session intact, and the save file is refused (not corrupted) across host builds | `live_snapshot` | `live_snapshot: false` permanently; stopped-disk snapshots remain |
| H8 | `Chipset.LinuxKernelDirect` boots the pinned Ubuntu generic kernel/initrd with an OCI rootfs on SCSI, and the initrd finds the root without Hyper-V-specific modules missing | OCI parity (`direct_kernel`) | `direct_kernel: false`; OCI refused on Windows by capability |
| H9 | VHDX files cloned with `FSCTL_DUPLICATE_EXTENTS_TO_FILE` on ReFS/Dev Drive and with `CopyFileEx` on NTFS boot identically | snapshot cost model | NTFS-only full copies; `Caps` unchanged |
| H10 | `HcsModifyComputeSystem` `Add` of a SCSI attachment is accepted on a `VirtualMachine` (not only on a container) | `disk_hotplug` | `disk_hotplug: false` |
| H11 | Mainline Linux has no 9p-over-Hyper-V-Socket transport (confirm against the 6.8+ kernel the cloud image ships) | `shared_dir: None` justification | if a transport exists, a `ShareKind` variant with its mount options becomes possible |
| H12 | HCN `PortMapping` policy can be constrained to the host loopback | `port_forward` | `port_forward: false`; `-p` stays on QEMU as on `chv` |
| H13 | GitHub `windows-latest` exposes virtualization to the runner | whether any hosted lane can run P1–P3 | hosted CI stays compile/static only (already the assumption) |

## 9. Consequences

* `backend::by_id` gains `hyperv` on Windows builds; the conformance profile
  gains one row; no OS conditional appears in create, attach or snapshot
  paths. Selection is `Caps` against `CreateRequirements`, as today.
* A supported Windows artifact ships `astd-hyperv` and no VMM runtime. The
  QEMU+WHPX floor is installed by the as-lvf.10 installer only when the user
  asks for the compatibility path; it is never downloaded because `hyperv`
  failed a probe.
* `Handle.pid: None` on `hyperv` is a new shape for the daemon's crash and
  sleep handling (`asterism_core::proc`, `power`); the conformance test for
  reloaded handles must be satisfied by HCS state queries, and this is the
  first backend where "the VMM process" is a Windows service rather than a
  child.
* The parent epic cannot advertise Windows lifecycle acceptance on this ADR
  alone. **as-lvf.3's acceptance criterion ("on Windows 11, a proof creates
  and boots…") is not met by this document and must not be marked met until
  the §7.3 evidence directory is committed from a real host.**
* If H5 is false, the process model changes (long-lived helper) but the API
  choice (HCS/HCN/Hyper-V Socket) does not; this decision is robust to that
  outcome, which is why it is taken now.

## 10. Differences from the unmerged as-lvf.8 draft of this file

1. WMI checkpoint fallback (`Msvm_VirtualSystemSnapshotService`) removed:
   HCS systems are not WMI-visible, so it could never have applied.
2. `direct_kernel` changed from a design exclusion to a proof item (H8) via
   `LinuxKernelDirect`, using the kernels the tree already pins.
3. Windows Home changed from "unsupported" to "not supported until H2 is
   run", because `VirtualMachinePlatform` is HCS.
4. Privilege row E8 (Hyper-V Administrators) and E9 (service account) added
   as explicit unknowns rather than folded into "Administrators".
5. Every lifecycle claim carries a proof id; the draft's "accepted" status
   is replaced by "proposed, source-only".

## 11. Sources

* Microsoft, *Host Compute System API* — overview, `HcsCreateComputeSystem`,
  `HcsOpenComputeSystem`, `HcsSaveComputeSystem`, `HcsModifyComputeSystem`,
  `HcsGrantVmAccess`, `HcsGetServiceProperties`; schema 2.1 reference
  (`VirtualMachine`, `Chipset.Uefi`, `Chipset.LinuxKernelDirect`,
  `Devices.{Scsi,NetworkAdapter,ComPorts,HvSocket,Plan9}`, `RestoreState`,
  `ShouldTerminateOnLastHandleClosed`); HCS tutorial (Gen 2 VM, schema 2.1).
  <https://learn.microsoft.com/en-us/virtualization/api/hcs/>
* Microsoft, *Host Compute Network (HCN) API* — `HcnCreateNetwork`,
  `HcnCreateEndpoint`, network types (`NAT`, `ICS`, `Transparent`,
  `L2Bridge`, `Private`), endpoint policies (`PortMapping`).
  <https://learn.microsoft.com/en-us/virtualization/api/hcn/>
* Microsoft, *Virtual Disk API* — `CreateVirtualDisk`, `AttachVirtualDisk`,
  `GetVirtualDiskPhysicalPath`, `CompactVirtualDisk`, `ResizeVirtualDisk`.
* Microsoft, *Make your own integration services* (Hyper-V Socket; Linux
  VSOCK service template `xxxxxxxx-facb-11e6-bd58-64006a7986d3`;
  `GuestCommunicationServices` registry key).
  <https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/make-integration-service>
* Microsoft, *Hyper-V requirements* and *Windows 11 edition feature
  availability* (Hyper-V not on Home; `VirtualMachinePlatform` on all
  editions for WSL 2).
* Microsoft, *Windows Hypervisor Platform* (`WHvCreatePartition`) — the API
  a VMM uses; cited as the reason WHPX is a VMM dependency, not a backend.
* Microsoft, *Hyper-V WMI provider (v2)* — `Msvm_ImageManagementService`,
  `Msvm_VirtualEthernetSwitchManagementService`, `Msvm_ComputerSystem`.
* Linux kernel, `net/vmw_vsock/hyperv_transport.c` (`hv_sock`), `drivers/hv/`;
  WSL 2 kernel tree for the out-of-tree 9p Hyper-V transport.
* `windows-sys 0.61.2` (already in `Cargo.lock`): feature groups
  `Win32_System_HostComputeSystem`, `Win32_System_HostComputeNetwork`,
  `Win32_Storage_Vhd`, `Win32_Networking_WinSock`.
* This tree: `crates/asterism-core/src/hv.rs` (`Caps`, `Capability::ALL`,
  `ControlChannel`, `Handle`), `crates/asterism-daemon/src/backend/{mod,conformance,vz}.rs`,
  `crates/asterism-vz/src/guest.rs` (agent port 1023, HMAC handshake),
  `crates/asterism-core/src/oci.rs` (`KERNELS`), ADR 0001.
