# Compute is the device an instance runs on

An instance runs on exactly one orbit device and uses that device's CPU,
physical RAM, GPU, and execution state. Asterism does not compose a machine
out of hardware from several devices, does not schedule an instance onto a
device for you, and does not present CPU and physical RAM from different
devices as one cache-coherent machine.

The `--cpus` and `--mem` shape values are quotas on that device, not
independently sourced resources. The selected hypervisor is an internal detail
recorded for deterministic restart and recovery. Every new Instance is a VM;
Asterism never selects a host-namespace runtime.

What *does* come from elsewhere in the orbit is data: block volumes over NBD,
secrets by handle, and services by orbit name. Directory shares and GPU are
local to the device the instance runs on.

## Parked: relocating an instance

Moving an instance's compute to another device is implemented and shipped as
an offline migration, and is kept for people who already rely on it. It is
**parked** as a product direction — reason: product focus. It is not part of
the core story, and nothing else in the product is designed around it.

The canonical command is:

```console
$ ast set NAME compute DEVICE
```

Two compatibility aliases have the same semantics:

```console
$ ast set NAME cpu DEVICE
$ ast move NAME DEVICE
```

Use `--down` to shut down a running instance before relocating it. Status,
list output, errors, and help always call this part `compute`. The instance's
name, id, and snapshots do not move, because they were never on a device; its
root disk and snapshots transfer peer-to-peer.
