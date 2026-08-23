# Exact real-NVIDIA release gate

The production GPU part presents `/dev/nvidia0` inside an attached instance.
Transport, authentication, leases, revocation, device loss and ABI version
skew stay behind that part seam. This document is the paid NVIDIA evidence
plan for that part. It is not itself hardware evidence.

The portable CPU loopback proof (`scripts/e2e-remote-gpu.sh`,
`Executor::Reference`) remains ABI v1 reference proof. It must never be
filed as NVIDIA hardware evidence.

## What is checked in

| Path | Role |
| --- | --- |
| `crates/asterism-core/src/remote_gpu.rs` | ABI v1 + production control plane (`ProductionProvider`, leases, placement, generation fencing, token-free `/dev/nvidia0` attachment metadata) |
| `crates/asterism-core/src/remote_gpu_guest.rs` | CUSE + generated libcuda guest projection |
| `crates/asterism-core/src/remote_gpu_path.rs` | Authenticated instance-bound mesh path |
| `crates/asterism-core/src/remote_gpu_cuda.rs` | NVIDIA CUDA driver executor (`libcuda` via dlopen). Simulated driver for source tests; live driver is the only hardware-PASS path. |
| `crates/asterism-daemon/src/gpu.rs` | Daemon/mesh routing into the in-process CUDA engine. The provider runtime is the provider `astd` process; there is no separate helper process. |
| `crates/asterism-core/src/remote_gpu_nvidia.rs` | Fail-closed driver/CUDA/CC matrix and deterministic two-device harness |
| `crates/asterism-core/examples/remote_gpu_nvidia_harness.rs` | Source runner for the contract; always prints `hardware_cuda_executed=false` |
| `scripts/harness-remote-gpu-nvidia.sh` | Candidate-side live observer: records SHA/tree/GPU inventory and invokes the pinned-tree E2E runner. It cannot normalize or accept evidence. |
| `crates/asterism-nvidia-e2e-driver` | Guest projection adapter. It talks to the guest `astd` local socket and emits raw observations; it contains no provider, relay, or acceptance verifier. |
| `scripts/lib/nvidia-e2e-runner.sh` | Builds the exact candidate, pairs two real daemon identities through invite/SAS, then performs direct/relay success, active revoke/loss, live contention, and fresh-session skew actions. It records raw JSON and cannot accept it. |
| `scripts/lib/nvidia-guest-container.sh` | Runs the payload in a digest-pinned read-only container with only projected `/dev/nvidia0` and the audited libcuda mounted |
| `scripts/lib/guest_remote_cuda_vector_add.c` | CUDA application payload intended to execute inside the Asterism guest/container |
| `scripts/test-nvidia-release-gate.sh` | Source-only structural fixtures proving observation and acceptance remain separate and every required claim maps to a runner action |
| `deploy/dstack/remote-gpu-nvidia.dstack.yml` | Provider-side dstack **task** config. Do not apply from development machines. |

## Fail-closed matrix

A provider is refused, not skipped, unless all of the following hold:

- NVIDIA driver **550+**
- CUDA runtime **12.4 through 13.x**
- Compute capability **7.5+** (Turing T4 and newer)
- Unique `GPU-` UUIDs
- **Two** admitted devices for the hardware gate

CUDA 11, driver 470, Volta 7.0, a single GPU, or a truncated inventory are
errors. CI without two NVIDIA devices must report the gate **unavailable**
(script exit 2). Exit 0 is reserved for the single complete
guest→projection→mesh→provider record; reference and local-direct diagnostics
remain non-PASS evidence.

## Source-only contract harness

`prove_two_device_nvidia_contract` uses two admitted GPU identities and the
reference ABI executor. It proves:

1. CUDA-inventory enumeration of two devices
2. a small pinned vector-add kernel through the ABI
3. buffer transfer of the result
4. concurrent lease fencing (one live lease per provider)
5. provider daemon restart (generation fence; old capability dies)
6. guest restart (`guest_lost` returns ABI memory; the live lease reopens)
7. revoke (active session and lease die together)
8. unsupported ABI range fail-closed
9. unsupported driver/CUDA matrix fail-closed

Guest software still sees `/dev/nvidia0`. The harness never binds a
non-loopback plaintext listener and has no cloud-only dependency.

## dstack plan (do not apply here)

The checked-in task requests:

- 1 on-demand host
- 2× NVIDIA GPUs, 16 GB+ each, CC 7.5+
- driver 550+, CUDA 12.4–13.x (the provider image is pinned to the CUDA 13.0 development-image digest)
- `max_price: 2.50` USD/hour
- `max_duration: 1h`, `idle_duration: 5m`, `retry: false`
- a one-hour hard duration cap and no retries

No successful plan or hardware execution is claimed. Two earlier
`dstack apply --help` attempts failed locally during CLI import with a pydantic
`ModelMetaclass` ImportError. Neither reached a server, plan, provisioning,
hardware, or spend. Apply must start from a detached checkout of the exact
candidate under review and supply `ASTERISM_PINNED_SHA`; the task rejects any
different `HEAD`. The runner builds in a private temporary target directory.

Execution observation and acceptance are two distinct phases. Candidate code
runs in the digest-pinned provider environment and writes raw JSON, logs,
artifact hashes, inventory, and a manifest. It then removes write bits. It has
no normalizer, judge, verifier subcommand, or acceptance emitter.

The independent reviewer supplies `ASTERISM_NVIDIA_VERIFIER_IMAGE` and its
exact sha256 digest. Only after live processes have stopped does dstack launch
that immutable image with `--network none`, a read-only root filesystem, and
the completed raw directory mounted read-only at `/evidence`. The verifier has
no candidate-tree mount and writes its verdict to a separate `/verdict` mount.
Its closed schema must bind every record to the same exact SHA/tree, runner and
artifact digests, image/runtime identity, GPU and device identities, and
manifest. Unknown, duplicate, missing, mismatched, or unobserved fields fail
closed. `provenance_verified` is reviewer-owned verdict metadata, not a field
candidate records or validates.

The raw boundary has two closed record kinds. JSON records with schema
`asterism.nvidia.raw-observation/3` bind one CUDA application attempt to the
candidate SHA/tree, paired device identities, selected mesh path, requested
fault and active-fault timing, GPU UUID, guest container, provider/guest astd
PIDs, the honest `in_process_astd_cuda_engine` runtime kind, provider-runtime
executable and image digests, artifact/log digests, crossed frames, and whether
CUDA work completed. Records with schema `asterism.nvidia.runtime-probe/1`
bind live contention or fresh-session skew to those same process, image,
candidate, and tree identities plus the exact observed refusal. The external
verifier must reject unknown fields and require all fields for each kind; it
must also require exactly the six named records and recompute every manifest
entry before considering reviewer-owned provenance metadata.

Preferred SKUs when offers are healthy: 2× L4 24 GB, 2× RTX 4090 24 GB, or
2× A10 24 GB. Do not use V100/P100; CUDA 13 images do not support them and
the matrix refuses CC < 7.5.

Sol applies only after a plan preview (`echo n | dstack apply --project main -f deploy/dstack/remote-gpu-nvidia.dstack.yml`)
shows two NVIDIA GPUs under the price cap. Never apply from this tree as a
side effect of CI.

## Evidence Sol must record

From the **exact Git SHA** under test, with both GPU UUIDs, both mesh device
IDs, driver, CUDA runtime, and route kind:

- CUDA result bytes through the guest-local `/dev/nvidia0` adapter
- guest application output `6.0,2.0,6.0` from projected `/dev/nvidia0` and injected libcuda
- direct and relay traversal reported by iroh across the same two paired daemon
  keys; relay evidence disables IP transports and never uses a Unix proxy
- provider-process / provider-device loss while work is active
- peer and instance revocation during an active session
- a second fresh session contending while the first holds the in-process CUDA engine
- provider `astd` and guest/container PID changes across real restarts; no separate helper PID is claimed
- fresh-session version skew returning `UnsupportedVersion`, never `Conflict`
- exact candidate SHA, tree digest, runner digest, guest/provider image digests
- exact driver, ABI shim, and guest-binary digests plus a hash-chained transcript root
- an immutable external verifier-image digest selected by the independent reviewer
- unsupported driver/CUDA matrix fail-closed
- `hardware_cuda_executed=true` only from that run

A CPU reference printout of `hardware_cuda_executed=false` is kept as ABI
proof, not as this gate.
