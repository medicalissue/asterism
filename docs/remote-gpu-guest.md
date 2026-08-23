# Guest NVIDIA projection and mesh data path

Unmodified CUDA applications inside an attached Linux instance resolve an
Asterism-injected driver shim and a local device node. `/dev/nvidia0` is a
projected local endpoint, not a string in instance status.

## What is implemented

| Layer | Mechanism |
| --- | --- |
| Guest-visible device | **CUSE character-device service** at `/dev/nvidia0` on Linux when `/dev/cuse` exists (open/read/write/release plus fail-closed NVIDIA ioctl). Portable source fixtures bind a **Unix-domain socket** at `<guest-root>/dev/nvidia0` so `connect(2)` is a real local endpoint. |
| CUDA API | Injected ELF `libcuda.so.1.0.0` (`crates/asterism-libcuda`) with SONAME `libcuda.so.1`, versioned/unversioned Driver API exports, and the exact matrix below. |
| Guest control | Injected `asterism-gpu-guest` runs as the guest-only `asterism-gpu` system account, owns CUSE through a root-owned 0660 udev rule, and listens on instance-bound AF_VSOCK port **1022**. It authenticates with the per-instance guest key and distinct `asterism-guest-gpu` proof label. There is no TCP listener. |
| Local astd | Unix-socket frames `gpu_guest_open` / `gpu_guest_frame` (protocol 8). Startup registers only NVIDIA devices discovered and admitted from live `nvidia-smi`; CPU-only hosts advertise zero providers. |
| Mesh | Dedicated iroh stream `kind=gpu` carrying typed, length-prefixed frames. Opening frame is `{instance_id, provider_generation}` only. |
| Provider | Attach placement uses live provider advertisements and persists a token-free `GpuAttachment`; detach revokes at the selected provider before deleting metadata. `ProductionProvider` authorizes by authenticated mesh peer + instance + generation, re-evaluating time on every call. Multiple calls may be in flight, queued work is cancellable before apply, and credit bounds backpressure. |

## Packaging and injection

Run `scripts/build-guest-gpu-artifacts.sh`. The script cross-builds the Linux
guest service and shim, verifies the shim SONAME and export set, and writes:

```text
dist/guest-gpu/bin/asterism-gpu-guest
dist/guest-gpu/lib/libcuda.so.1.0.0
dist/guest-gpu/lib/libcuda.so.1 -> libcuda.so.1.0.0
dist/guest-gpu/lib/libcuda.so -> libcuda.so.1
```

Install that directory beside `astd` as `guest-gpu`, install it at
`/usr/local/lib/asterism/guest-gpu`, or set
`ASTERISM_GPU_GUEST_ARTIFACT_DIR`. Cloud images receive the artifacts through
cloud-init plus a systemd unit. Direct-kernel OCI guests materialize and start
the same service before the container entrypoint. Attached boot fails closed
if artifacts, `/dev/cuse`, the instance key, or backend projection capability
are missing.

Cloud guests persist `cuse` module loading and the udev rule inside the guest,
not on the host. The service starts with a fresh primary group, an empty
capability bounding set, device access restricted to `/dev/cuse`, and only
AF_UNIX/AF_VSOCK address families. OCI guests have no udev/systemd, so their
generated pid 1 applies the same numeric service ownership on every boot and
drops privileges with BusyBox `setuidgid`. Destroying the guest removes this
policy; uninstalling Asterism removes the packaged guest unit beside `astd` and
does not leave or revoke any host `/dev/cuse` grant because none is installed.

Attach with `asterism attach INSTANCE --gpu DEVICE[:GPU-UUID]` and optionally
`--gpu-memory BYTES`. Detach with `asterism detach INSTANCE --gpu`.

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
- Pre-authentication vsock lines are bounded while reading (64 KiB).
- Only the exact Asterism ABI-query ioctl is accepted; all other `'A'` and
  NVIDIA `'F'` requests return `ENOTTY`.
- Credit window (default 4) supplies backpressure. Cancel drops a
  not-yet-applied call.
- Device loss, instance/peer revoke, and generation skew fail closed
  without mutating ABI memory.

## Test fixtures versus production

Portable tests may project a Unix socket and use `Executor::Reference` to
exercise deterministic ABI semantics. Those fixtures never enter daemon
inventory. Production advertisements are `Executor::Cuda` and exist only for
live, admitted NVIDIA UUIDs.
