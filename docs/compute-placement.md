# Compute placement

Compute is one placement unit. At any moment an instance's compute comes from
one orbit device. That device supplies CPU, physical RAM, and execution state
together. Hypervisor and namespace adapters are internal placement details;
both appear and behave as an Instance.

GPU, storage, network, and exit points are independent parts and may attach
from other devices. Asterism does not present CPU and physical RAM from
different devices as one cache-coherent machine.

The `--cpus` and `--mem` shape values are quotas on the selected compute
device, not independently placeable resources.

## Commands

The canonical command is:

```console
$ ast set NAME compute DEVICE
```

Two compatibility aliases have the same semantics:

```console
$ ast set NAME cpu DEVICE
$ ast move NAME DEVICE
```

Use `--down` to shut down a running instance before moving its compute.
Status, list output, errors, and help always describe this placement as
`compute`.
