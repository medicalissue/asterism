# Remote GPU production control plane

> **Status: experimental appendix.** Projecting another device's GPU into an
> instance is not a shipped product promise and is not part of Asterism's core
> story. The reason is physics, not effort: one CUDA kernel launch becomes one
> round trip over the mesh, against sub-microsecond PCIe on a local bus. No
> amount of protocol work removes that. The GPU an instance can depend on is
> the one in the device it runs on; everything below documents the experiment.


The remote GPU ABI now has a production control-plane seam in
`asterism_core::remote_gpu`. It makes a GPU an orbit part while preserving the
guest contract: software inside an attached Linux instance sees
`/dev/nvidia0` as a projected local endpoint (CUSE character device plus
generated `libcuda.so.1`), not a provider hostname, relay URL, or mesh
session. The durable `GpuAttachment` record is still token-free metadata;
the executable projection lives in [`remote-gpu-guest.md`](remote-gpu-guest.md).

`Executor::Reference` remains the portable semantic executor. A provider may
advertise `Executor::Cuda` only when its executor actually launches the
pinned work on NVIDIA hardware. This document does not claim that hardware
path.

## Admission and placement

Each authenticated provider advertises its stable mesh device identity, human
device name, NVIDIA GPU UUID, ABI range, executor, total and leased memory,
lease slots, provider generation, health, and observed mesh route. Placement
first filters every hard constraint and only then ranks eligible providers:

1. direct mesh path before relay;
2. lower observed RTT;
3. lower lease-slot pressure;
4. stable mesh identity and GPU UUID as deterministic tie-breakers.

An explicit device name restricts the candidate set but cannot override
health, reachability, CUDA execution, memory, or session quotas. A refusal
names every failed constraint and does not mutate provider or instance state.

## Security boundary

The mesh completes device authentication before constructing an
`AuthenticatedPeer`. Diagnostic names in ABI messages never authorize work.
A live lease is bound to all of:

- the authenticated consumer public key;
- one orbit-global instance ID;
- one provider generation;
- a memory reservation and expiry;
- an opaque random bearer capability.

`ProductionProvider` is the only adapter from this authorization state into
the ABI state machine. It checks the peer, capability, lease health, expiry and
generation before allowing the ABI to consume a sequence or touch memory.
Opening a second ABI session for one lease is refused. Removing a peer or
revoking an instance closes its ABI session immediately and returns all
provider memory.

The bearer capability is redacted from `Debug` and never appears in
`GpuAttachment`. The attachment record stored in `state.json`, printed by
status, consumed by GUI clients, and copied into backup rebind requirements is
token-free. Backups clear the active attachment and require placement and a
fresh lease after restore.

## Loss, health, and recovery

Providers admit and serve work only in `ready` health. `draining`, `unhealthy`
and `offline` carry a diagnostic reason. A provider-loss transition:

1. tombstones every bearer capability;
2. closes every ABI session and releases its allocations;
3. clears live lease and instance claims;
4. increments the provider generation;
5. reports `offline` with the observed reason.

Recovery starts ready and empty at the new generation. Consumers use the
durable, token-free attachment metadata to request a new lease; an old token
or ABI session cannot cross the restart fence. Expired leases are reaped by a
bounded health loop. Revocation tombstones are also bounded; eviction changes
an old refusal from `revoked` to `unknown` but never makes it valid.

## Evidence and remaining hardware gate

The checked-in unit and integration tests cover deterministic direct/relay
placement, actionable degraded-provider refusal, quota contention,
refusal-before-mutation, authenticated-peer isolation, active revocation,
provider loss, generation-fenced recovery, expiry, token redaction, durable
attachment status, and backup rebinding.

The product acceptance gate still requires two real NVIDIA provider devices.
The fail-closed matrix, deterministic two-device harness, `nvcc` kernel,
no-cost dstack task (do not apply until Sol's server is healthy), and
cost-input live in [remote-gpu-nvidia-gate.md](remote-gpu-nvidia-gate.md).
It must record, from the exact commit under test:

- CUDA result bytes through the guest-local `/dev/nvidia0` adapter;
- provider-process and provider-device loss while work is active;
- peer and instance revocation during an active session;
- memory and lease-slot contention;
- daemon and provider restart with a new generation and lease;
- direct and relay end-to-end latency/throughput from identical pinned work.

Those results must name both stable mesh device IDs, both NVIDIA GPU UUIDs,
driver/runtime versions, route kind, sample count, payload size, and exact Git
SHA. CI without two NVIDIA devices must report this gate as unavailable; a CPU
reference run is never accepted as hardware evidence.
