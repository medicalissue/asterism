# Two-device NVIDIA hardware gate

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
| `crates/asterism-core/src/remote_gpu.rs` | ABI v1 + production control plane (`ProductionProvider`, leases, placement, generation fencing, guest-local `/dev/nvidia0` metadata, per-lease and aggregate quotas) |
| `crates/asterism-core/src/remote_gpu_cuda.rs` | NVIDIA CUDA driver executor (`libcuda` via dlopen). Simulated driver for source tests; live driver is the only hardware-PASS path. |
| `crates/asterism-daemon/src/gpu.rs` | Daemon/mesh routing into the CUDA helper. Unix helper socket, no public listener, no token persistence. |
| `crates/asterism-core/src/remote_gpu_nvidia.rs` | Fail-closed driver/CUDA/CC matrix and deterministic two-device harness |
| `crates/asterism-core/examples/remote_gpu_nvidia_harness.rs` | Source runner for the contract; always prints `hardware_cuda_executed=false` |
| `scripts/harness-remote-gpu-nvidia.sh` | Hardware wrapper: inventory, matrix, `nvcc` kernel on two devices, contract runner |
| `scripts/lib/remote_gpu_vector_add.cu` | Tiny host CUDA kernel used only on the paid gate |
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
(script exit 2). A contract-only reference run is exit 3 and still not a
hardware pass. Exit 0 is reserved for two-device CUDA kernel evidence plus
the production contract.

## Deterministic harness

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

Local server status at recovery time:

- `GET /` → HTTP 500
- offers path → HTTP 500 (previously 405)

That is Sol's external execution blocker. The task file is still the
cost-input:

- 1 on-demand host
- 2× NVIDIA GPUs, 16 GB+ each, CC 7.5+
- driver 550+, CUDA 12.4–13.x (dstack default image is CUDA 13.0 + `nvcc: true`)
- `max_price: 2.50` USD/hour
- `max_duration: 1h`, `idle_duration: 5m`, `retry: false`
- expected wall clock 20–40 minutes including rustup
- expected spend **about 1–3 USD** if applied once and stopped

Preferred SKUs when offers are healthy: 2× L4 24 GB, 2× RTX 4090 24 GB, or
2× A10 24 GB. Do not use V100/P100; CUDA 13 images do not support them and
the matrix refuses CC < 7.5.

Sol applies only after a plan preview (`echo n | dstack apply -f deploy/dstack/remote-gpu-nvidia.dstack.yml`)
shows two NVIDIA GPUs under the price cap. Never apply from this tree as a
side effect of CI.

## Evidence Sol must record

From the **exact Git SHA** under test, with both GPU UUIDs, both mesh device
IDs, driver, CUDA runtime, and route kind:

- CUDA result bytes through the guest-local `/dev/nvidia0` adapter
- `scripts/lib/remote_gpu_vector_add.cu` passing on device 0 and device 1
- provider-process / provider-device loss while work is active
- peer and instance revocation during an active session
- concurrent lease-slot fencing
- daemon and provider restart with a new generation
- unsupported driver/CUDA matrix fail-closed
- `hardware_cuda_executed=true` only from that run

A CPU reference printout of `hardware_cuda_executed=false` is kept as ABI
proof, not as this gate.
