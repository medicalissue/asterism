# Compute is the device an instance runs on

An instance runs on exactly one orbit device and uses that device's CPU,
physical RAM, GPU, and execution state. Asterism does not compose a machine
out of hardware from several devices, does not schedule an instance onto a
device for you, and does not present CPU and physical RAM from different
devices as one cache-coherent machine.

Which device that is can change. Compute is not a part Asterism splits,
borrows, or places for you, but the whole instance moves to another device
when you ask it to — see [Moving an instance between devices](#moving-an-instance-between-devices)
below.

The `--cpus` and `--mem` shape values are quotas on that device, not
independently sourced resources. The selected hypervisor is an internal detail
recorded for deterministic restart and recovery. Every new Instance is a VM;
Asterism never selects a host-namespace runtime.

What *does* come from elsewhere in the orbit is data: block volumes over NBD,
secrets by handle, and services by orbit name. Directory shares and GPU are
local to the device the instance runs on.

## Moving an instance between devices

An instance is not welded to the device it was created on. Moving its compute
to another orbit device is implemented and shipped, as an **offline** (cold)
move: the guest is shut down, the instance's own written bytes are
transferred, the cut-over is fenced, and the instance starts again on the new
device. Its name and id do not move at all, because they were never on a
device.

Live migration — transferring a *running* guest with the RAM it is holding —
is **not** implemented and is not planned. On macOS it is not possible on
either backend: Hypervisor.framework supports neither migration nor `savevm`,
and Virtualization.framework's saved state is a same-host resume format with
no wire protocol.

The canonical command is:

```console
$ ast set NAME compute DEVICE
```

Two compatibility aliases have the same semantics:

```console
$ ast set NAME cpu DEVICE
$ ast move NAME DEVICE
```

Use `--down` to shut down a running instance before moving it; a running
instance is refused without it, because the move is offline on every backend
Asterism has. Status, list output, errors, and help always call this part
`compute`.

What travels and what does not:

- The **root disk and snapshots** transfer peer-to-peer, sparsely: what
  crosses is the blocks the instance actually allocated, not the disk's
  declared size. The base image is content-addressed, so the target fetches
  it from an orbit peer that already has it rather than re-downloading it.
- The **name and id** stay as they are. Instance names resolve across the
  orbit, so `ast ssh NAME` reaches the instance from any device and needs no
  retyping after a move.
- A **remote block volume** is not copied. It stays on the device that owns
  it and is re-attached from the new device; the bridge becomes local or
  remote as required. See
  [Orbit storage](orbit-storage.md).
- A **directory share** is local to a device by construction (there is no
  network transport for virtiofs or 9p), so it stays behind on the device
  that holds the directory. The move keeps the record and flags it rather
  than silently dropping it.
- **Secrets** never travelled: the guest holds a per-destination handle and
  the orbit re-resolves it after the move.

Crossing backends — a Mac on `vz` storing raw images to a Linux host on QEMU
storing qcow2 — converts the disk and reboots the guest rather than resuming
it. The capability check runs before any bytes move.
