# Guest NVIDIA projection and mesh data path

Unmodified CUDA applications inside an attached Linux instance resolve an
Asterism-injected driver shim and a local device node. `/dev/nvidia0` is a
projected local endpoint, not a string in instance status.

## What is implemented

| Layer | Mechanism |
| --- | --- |
| Guest-visible device | **CUSE character device** at `/dev/nvidia0` on Linux when `/dev/cuse` exists. Portable source fixtures bind a **Unix-domain socket** at `<guest-root>/dev/nvidia0` so `connect(2)` is a real local endpoint. |
| CUDA API | **Generated `libcuda.so.1`** (`crates/asterism-libcuda`) exporting the exact Driver API matrix below. |
| Guest control | Instance-bound virtio-socket port **1022**, HMAC-authenticated with the per-instance guest key and a distinct `asterism-guest-gpu` proof label. No hypervisor-id branch: a backend without virtio-socket fails closed. |
| Local astd | Unix-socket frames `gpu_guest_open` / `gpu_guest_frame` (protocol 8). Never a LAN listener. |
| Mesh | Dedicated iroh stream `kind=gpu` carrying typed, length-prefixed frames. Opening frame is `{instance_id, provider_generation}` only. |
| Provider | `ProductionProvider` authorizes by authenticated mesh peer + instance + generation. The lease bearer stays in provider memory. |

## Exact CUDA Driver API matrix (ABI 1)

Supported symbols:

`cuInit`, `cuDriverGetVersion`, `cuDeviceGetCount`, `cuDeviceGet`,
`cuDeviceGetName`, `cuDeviceGetUuid`, `cuDeviceGetAttribute` (only
`COMPUTE_CAPABILITY_MAJOR`, `COMPUTE_CAPABILITY_MINOR`,
`MULTIPROCESSOR_COUNT`), `cuCtxCreate`, `cuCtxDestroy`, `cuCtxGetCurrent`,
`cuCtxSetCurrent`, `cuCtxSynchronize`, `cuMemAlloc`, `cuMemFree`,
`cuMemcpyHtoD`, `cuMemcpyDtoH`, `cuModuleLoadData`, `cuModuleUnload`,
`cuModuleGetFunction`, `cuLaunchKernel` (the pinned `vector_add_f32`
entrypoint only), `cuGetErrorString`, `cuGetErrorName`.

Everything else fails closed with `CUDA_ERROR_NOT_SUPPORTED`, including
`cuMemAllocManaged`, streams, events, graphs, IPC, peer access, GL/VDPAU,
and the CUDA Runtime API (`cudaMalloc` and friends). Raw NVIDIA ioctls on
the CUSE node (`'F'` magic) return `ENOTTY`.

## Security

- No plaintext LAN listener. The proof TCP loopback path remains a separate
  ABI fixture and still refuses non-loopback addresses.
- No bearer in argv, environment, disk (`GpuAttachment` is token-free),
  logs (`GpuLease` redacts `capability`), or mesh metadata.
- No `backend=` ad hoc branch in the GPU path.
- Typed frames are bounded by `MAX_WIRE_FRAME_BYTES` (4 MiB).
- Credit window (default 4) supplies backpressure. Cancel drops a
  not-yet-applied call.
- Device loss, instance/peer revoke, and generation skew fail closed
  without mutating ABI memory.

## Honesty

This is source for the guest projection and authenticated mesh path. It does
not claim NVIDIA hardware execution. `Executor::Reference` remains the
portable semantic executor. Hardware CUDA is `as-lvf.13.3` / `as-lvf.13.4`.
