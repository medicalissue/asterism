# Windows Hyper-V backend — evidence ledger (opened 2026-08-23)

## Status: NO REAL-HOST EVIDENCE RECORDED

This directory exists so that the absence of evidence is visible in the tree
rather than implied by silence. ADR 0002 (`docs/adr/0002-windows-hyperv.md`)
is a source-only proposal; every row of its §8 is open, and the acceptance
criterion of as-lvf.3 (create, boot, readiness over Hyper-V Socket,
stop/restart, save or checkpoint on Windows 11) has **not** been met.

No Windows host was available to the session that wrote this. Nothing below
was executed. The earlier as-lvf.8 branches also recorded no host evidence.

## What a completed run must contain

`scripts/hyperv-real-host-harness.ps1` (to be written under as-lvf.8) writes
one subdirectory per run, `run-<utc-timestamp>/`, with:

| File | Content |
|---|---|
| `host.json` | `OsBuild`, `ProductName`, edition SKU id, architecture, `Microsoft-Hyper-V` / `VirtualMachinePlatform` feature state, `vmcompute` and `hns` service state, `HcsGetServiceProperties` output, whether the token was elevated, group SIDs of the running account, instance-root filesystem (NTFS/ReFS) |
| `helper.json` | `astd-hyperv` build id (source commit) and `windows-sys` version |
| `steps.jsonl` | one line per P-step of ADR 0002 §7.3: `step`, `started`, `ended`, `ok`, `detail`, and the independent PowerShell assertion output where one exists |
| `hypotheses.json` | each ADR 0002 §8 id (H1–H13) → `confirmed` / `refuted` / `not-exercised` with a pointer into `steps.jsonl` |
| `cleanup.json` | enumeration of HCS systems, HCN networks, HCN endpoints after `rm`, filtered to Asterism-owned ids; must be empty |
| `console-*.log`, `astd.log`, `astd-hyperv-*.log` | raw logs for the run |

A run is accepted as lifecycle evidence only if `host.json` shows an elevated
token on Windows 11 (build ≥ 22000), the H5 row is `confirmed`, and
`cleanup.json` is empty. A hosted CI run on `windows-latest` never qualifies.

## Open hypotheses (copied from ADR 0002 §8 for tracking)

| Id | Claim | State |
|---|---|---|
| H1 | stock Ubuntu 24.04 cloud image reaches the agent over Hyper-V Socket, port-1023 VSOCK template GUID | not-exercised |
| H2 | `VirtualMachinePlatform` alone suffices (Windows Home) | not-exercised |
| H3 | HCS Gen 2 Linux VM on Windows 11 arm64 | not-exercised |
| H4 | console is `ttyS0`/COM1 with a getty | not-exercised |
| H5 | HCS system survives helper and daemon exit; `HcsOpenComputeSystem` re-attaches | not-exercised |
| H6 | Hyper-V Administrators group is enough for HCS create/start | not-exercised |
| H7 | HCS save/restore round-trips a Linux guest; save file refused across host builds | not-exercised |
| H8 | `LinuxKernelDirect` boots pinned kernel + OCI rootfs | not-exercised |
| H9 | ReFS block-clone and NTFS copy snapshots boot identically | not-exercised |
| H10 | `HcsModifyComputeSystem` SCSI attachment add on a VM | not-exercised |
| H11 | no mainline 9p-over-Hyper-V-Socket transport | not-exercised |
| H12 | HCN `PortMapping` can be loopback-only | not-exercised |
| H13 | GitHub `windows-latest` exposes virtualization | not-exercised |
