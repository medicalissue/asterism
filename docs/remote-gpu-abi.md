# Remote GPU ABI proof

The remote GPU boundary is a small, versioned CUDA-semantic ABI. Software in
an instance sees an attached GPU at `/dev/nvidia0`; the device supplying the
GPU owns the session, allocations, workload cache, and execution. The ABI does
not expose which host or transport supplies those parts.

This is the data-plane seam, plus a portable proof of it. The production
admission, placement, lease, revocation, health and recovery control plane is
described in [remote-gpu-production.md](remote-gpu-production.md). It is not
yet a production NVIDIA device implementation. The proof projects a regular file at
`<guest-root>/dev/nvidia0`, opens it as guest software would, and carries the
device operations to a separate provider process. A production Linux guest
projection still needs a guest driver/CUSE device and CUDA library adapter,
and production execution still needs a CUDA-backed provider.

## Run the proof

```console
$ scripts/e2e-remote-gpu.sh
ok: provider is a separate loopback-only device role at 127.0.0.1:…
ok: guest opened its fake /dev/nvidia0 and negotiated ABI 1
ok: pinned CUDA PTX vector-add returned verified memory
```

The script builds `remote_gpu_proof`, starts its `provider` and `guest` roles
as separate processes, and then asserts all of the following:

- the guest opens its projected `/dev/nvidia0` path;
- both roles negotiate the newest common ABI version;
- the provider issues opaque session and allocation IDs;
- PTX bytes match their BLAKE3 content pin before the provider admits them;
- allocation, write, vector-add launch, and read return the expected f32
  memory;
- a repeated call sequence and an in-allocation-ID but out-of-range write are
  rejected; and
- latency, throughput, executor type, and transparency limits are printed from
  that run.

`GPU_PROOF_ELEMENTS` and `GPU_PROOF_ITERATIONS` change the measured workload.
The default moves 256 KiB per vector per iteration and runs twelve iterations.
No checked-in latency number is a product claim: the proof prints what this
machine and this build measured.

The proof transport refuses every non-loopback address. Its session ID is a
bearer capability inside that transport. Production must carry the same ABI
over the authenticated, encrypted orbit mesh; exposing the proof listener on a
LAN would skip the orbit's device authentication.

The `consumer` string in `hello` is diagnostic, not authorization. The mesh
identity authenticates and authorizes the consuming device before an adapter
creates a provider session. A production adapter also owns connection-loss and
idle-session expiry; neither policy is encoded as a pretend GPU operation.

## ABI 1

The Rust types and provider state machine live in
`asterism-core::remote_gpu`. The wire is transport-independent tagged JSON in
the proof; a mesh adapter may encode the same typed messages differently.

| Operation | Provider invariant |
| --- | --- |
| `hello` | Select the newest overlap of bounded, non-zero ABI ranges and issue a fresh session ID. |
| `allocate` | Enforce advertised byte/count limits and issue a session-scoped allocation ID. |
| `write` / `read` | Check the allocation owner, copy ceiling, `offset + bytes` overflow, and allocation bounds before slicing memory. |
| `load_workload` | Hash the received artifact and require both its declared pin and an admitted CUDA semantic. |
| `launch_vector_add` | Require a loaded pin and three equal, bounded f32 ranges; report provider execution time. |
| `free` / `close` | Retire provider-owned capabilities. Closed IDs cannot be reused. |

Limits cover allocation bytes, aggregate bytes per session and provider, copy
bytes, launch bytes, allocation count, workload bytes, and concurrent session
count. The provider's persistent allocations and launch/read buffers reserve
fallibly after checking those ceilings, and free/close return their live budget.

After `hello`, call sequences are exactly monotonic. A valid session consumes a
sequence before operation validation. That means rejected bytes cannot be
changed and retried under the same authenticated call number. Gaps are also
rejected, so loss and reordering are visible rather than silently changing the
program.

ABI versions are independent of the Asterism package and CLI/daemon protocol
versions. A package release that does not change GPU messages does not move the
GPU ABI. A provider reports explicit limits and capabilities in the handshake;
a consumer does not probe compatibility by exhausting resources.

## Where transparency ends

The local illusion should be judged at a boundary, not described as a blanket
property.

| Boundary | Can it look local across devices? | Why / limit |
| --- | --- | --- |
| Linux syscall forwarding | No, in general | File descriptors, process address spaces, page faults, signals, and blocking semantics belong to one kernel. The proof only demonstrates an ordinary open of the projected path. |
| Raw NVIDIA `ioctl` forwarding | No, safely or stably | Requests embed host pointers, driver-private structures and version-specific command numbers. `mmap`, events, fences, and callbacks require shared kernel/driver state. ABI 1 rejects this boundary instead of pretending to preserve it. |
| CUDA Driver/Runtime API semantics | Yes, for an explicit subset | Allocation, copies, content-pinned module loading, launches, and synchronization have transportable meanings. Unsupported symbols, graph/event behavior, unified memory, peer access, IPC handles, and timing behavior must be reported rather than guessed. ABI 1 proves synchronous vector-add only. |
| Mediated device / VFIO / SR-IOV | Close to native on supported topology | A vendor device assignment can preserve the vendor ABI, but depends on IOMMU, hardware partitioning, matching guest drivers, reset isolation, and a GPU physically reachable from that host. It does not make memory or interrupts transparently remote across an orbit. |

The proof's `Reference` executor evaluates the pinned PTX workload's vector-add
semantics on CPU so every development and CI machine can run it. Its output
therefore says `hardware_cuda_executed=false`. A CUDA executor must produce the
same ABI replies while honestly advertising `executor=cuda`; until that exists,
the proof establishes the distributed ABI, validation, and fake-local path—not
hardware CUDA performance or application-wide CUDA compatibility.

Measurements include end-to-end p50/p95 time for two writes, a launch, and a
read; provider-only launch p50; and payload MiB/s. They include JSON/base64 and
loopback overhead in this proof. Production mesh framing, encryption, network
RTT, hardware compilation/cache misses, asynchronous streams, page migration,
and kernel projection overhead are explicitly outside those numbers and must be
measured by the production part rather than inferred from loopback.
