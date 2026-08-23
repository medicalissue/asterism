# Compute placement

Compute is one placement unit. At any moment an instance's compute comes from
**one** orbit device, and that device supplies CPU, physical RAM, and the VM
or container execution state together.

GPU, storage, network, and exit points are independent parts. They may attach
from other devices. Asterism does not promise cache-coherent CPU and physical
RAM from two devices as one shared machine.

`cpus` and `memory` on an instance shape are quotas on the selected compute
device, not a split of those two resources across the orbit.

## Commands

Canonical:

```console
$ ast set NAME compute DEVICE
```

Aliases with the same semantics:

```console
$ ast set NAME cpu DEVICE
$ ast move NAME DEVICE
```

`--down` is still required to move a running instance. Live and offline
migration, seed-key trust, and independent parts are unchanged.

## Compatibility

User-facing status, list, help, and docs say **compute**. On disk and on the
wire the names stay what older readers already know:

| Surface | Canonical now | Still written | Also accepted |
|---|---|---|---|
| CLI part | `compute` | — | `cpu`, `cpu/ram`, `ram`, `ast move` |
| Protocol command | `set_cpu` | `set_cpu` | `set_compute` |
| Instance JSON | `cpu_device` | `cpu_device` | `compute_device`, `anchor` |
| Conflict JSON | `other_cpu_device` | `other_cpu_device` | `other_compute_device` |

Existing shards keep loading. New shards keep writing `cpu_device`, so an
older daemon or tool can still read them.
