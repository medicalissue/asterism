//! Guest-local NVIDIA projection: a real `/dev/nvidia0` endpoint plus the
//! generated CUDA Driver ABI unmodified applications resolve.
//!
//! Production Linux guests materialize `/dev/nvidia0` with **CUSE** (a
//! character device in userspace, not a kernel NVIDIA module) and inject
//! **generated `libcuda.so.1`**. The CUSE node accepts `open`/`close` and
//! length-prefixed Asterism frames on `read`/`write`. Every NVIDIA ioctl
//! number, `mmap`, eventfd, and undocumented driver command is refused.
//!
//! The generated libcuda is the executable CUDA surface. It implements the
//! exact Driver API matrix below and maps those calls onto the framed
//! device contract. Symbols outside the matrix return `CUDA_ERROR_NOT_SUPPORTED`.
//! Runtime API (`cudaMalloc` and friends), unified memory, graphs, IPC,
//! peer access, and GL/VDPAU interop are not implemented.
//!
//! The guest control hop is instance-bound virtio-socket port
//! [`GUEST_GPU_VSOCK_PORT`], authenticated with the same per-instance key as
//! the guest agent and a distinct HMAC side label so a control-channel proof
//! cannot be replayed here. That hop does not name a hypervisor id: any
//! backend that attaches virtio-socket speaks the same frames, and a backend
//! without the socket fails closed.
//!
//! Nothing here is a LAN listener. The projected node is local to the guest
//! root. The host adapter talks to local `astd` over the existing unix
//! socket. `astd` carries the work over the authenticated orbit mesh.

use std::collections::{HashMap, VecDeque};
use std::fs::{self, File};
use std::io::{self, BufRead, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::FileTypeExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;

use data_encoding::BASE64;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::remote_gpu::{
    self as gpu, AbiRange, BufferRange, ErrorCode, Reply, Request, Response, MAX_WIRE_FRAME_BYTES,
};
use crate::remote_gpu_cuse;

/// How status and diagnostics name the projection that is actually running.
pub const PROJECTION_KIND: &str = "cuse_char_device_plus_generated_libcuda";
/// Guest-visible device path promised to CUDA software.
pub const GUEST_DEVICE_PATH: &str = gpu::GUEST_DEVICE_PATH;
/// Dedicated vsock port for GPU frames. Distinct from the 64 KiB guest-agent
/// control port so a 4 MiB copy does not share that ceiling.
pub const GUEST_GPU_VSOCK_PORT: u32 = 1022;
/// HMAC transcript prefix. The `gpu` label keeps these proofs from standing
/// in for [`crate`] guest-agent proofs on port 1023.
pub const GUEST_GPU_PROOF_LABEL: &str = "asterism-guest-gpu";
/// Guest-local identity that alone may open `/dev/cuse` and read the GPU key.
/// It is created inside an attached guest, never on the Asterism host.
pub const GUEST_GPU_SERVICE_USER: &str = "asterism-gpu";
pub const GUEST_GPU_SERVICE_GROUP: &str = "asterism-gpu";
pub const GUEST_CUSE_UDEV_RULE: &str = include_str!("../assets/70-asterism-cuse.rules");
/// NVIDIA's historical ioctl magic (`'F'`). Every request with this magic is
/// refused: we do not forward host-pointer driver commands.
pub const NVIDIA_IOCTL_MAGIC: u8 = b'F';
/// Asterism's own ioctl magic for a one-word contract query on a CUSE node.
pub const ASTERISM_IOCTL_MAGIC: u8 = b'A';
/// The sole ioctl implemented by the projection: return the Asterism GPU ABI
/// version. Matching the magic byte alone is deliberately insufficient;
/// every other command, including future Asterism commands, fails closed.
pub const ASTERISM_IOCTL_GET_ABI: u64 = (ASTERISM_IOCTL_MAGIC as u64) << 8 | 1;
/// In-flight CUDA calls permitted before the consumer must wait for credit.
pub const DEFAULT_CREDIT_WINDOW: u32 = 4;
const MAX_GUEST_ARTIFACT_BYTES: u64 = 64 * 1024 * 1024;

/// Audited Linux payload injected only when an instance has durable GPU
/// metadata and its backend advertises the guest-projection capability.
#[derive(Debug, Clone)]
pub struct GuestProjectionArtifacts {
    service: Vec<u8>,
    libcuda: Vec<u8>,
}

impl GuestProjectionArtifacts {
    pub fn from_dir(directory: &Path) -> io::Result<Self> {
        let service = read_guest_artifact(&directory.join("bin/asterism-gpu-guest"))?;
        let libcuda = read_guest_artifact(&directory.join("lib/libcuda.so.1.0.0"))?;
        if !service.starts_with(b"\x7fELF") || !libcuda.starts_with(b"\x7fELF") {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "GPU guest service and libcuda payloads must be ELF artifacts",
            ));
        }
        Ok(Self { service, libcuda })
    }

    /// Discover artifacts from explicit packaging configuration, then from
    /// the installed daemon layout. Absence refuses the boot; it never
    /// silently starts an attached instance without its projected device.
    pub fn discover() -> io::Result<Self> {
        if let Some(directory) = std::env::var_os("ASTERISM_GPU_GUEST_ARTIFACT_DIR") {
            return Self::from_dir(Path::new(&directory));
        }
        let beside_daemon = std::env::current_exe()?
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join("guest-gpu");
        match Self::from_dir(&beside_daemon) {
            Ok(found) => Ok(found),
            Err(first) if first.kind() == io::ErrorKind::NotFound => {
                Self::from_dir(Path::new("/usr/local/lib/asterism/guest-gpu"))
            }
            Err(err) => Err(err),
        }
    }

    pub fn cloud_config(&self) -> String {
        let service = BASE64.encode(&self.service);
        let libcuda = BASE64.encode(&self.libcuda);
        let udev_rule = GUEST_CUSE_UDEV_RULE.trim();
        format!(
            "write_files:\n\
             \x20- path: /usr/local/sbin/asterism-gpu-guest\n\
             \x20  owner: root:root\n\
             \x20  permissions: '0755'\n\
             \x20  encoding: b64\n\
             \x20  content: {service}\n\
             \x20- path: /usr/local/lib/asterism/libcuda.so.1.0.0\n\
             \x20  owner: root:root\n\
             \x20  permissions: '0755'\n\
             \x20  encoding: b64\n\
             \x20  content: {libcuda}\n\
             \x20- path: /etc/modules-load.d/asterism-cuse.conf\n\
             \x20  owner: root:root\n\
             \x20  permissions: '0644'\n\
             \x20  content: |\n\
             \x20    cuse\n\
             \x20- path: /etc/udev/rules.d/70-asterism-cuse.rules\n\
             \x20  owner: root:root\n\
             \x20  permissions: '0644'\n\
             \x20  content: |\n\
             \x20    {udev_rule}\n\
             \x20- path: /etc/systemd/system/asterism-gpu-guest.service\n\
             \x20  owner: root:root\n\
             \x20  permissions: '0644'\n\
             \x20  content: |\n\
             \x20    [Unit]\n\
             \x20    Description=Asterism guest GPU projection\n\
             \x20    After=systemd-modules-load.service\n\
             \x20    [Service]\n\
             \x20    User={service_user}\n\
             \x20    Group={service_group}\n\
             \x20    ExecStart=/usr/local/sbin/asterism-gpu-guest\n\
             \x20    Restart=on-failure\n\
             \x20    RestartSec=1\n\
             \x20    NoNewPrivileges=true\n\
             \x20    PrivateTmp=true\n\
             \x20    ProtectHome=true\n\
             \x20    ProtectSystem=strict\n\
             \x20    ProtectKernelModules=true\n\
             \x20    DevicePolicy=closed\n\
             \x20    DeviceAllow=/dev/cuse rw\n\
             \x20    CapabilityBoundingSet=\n\
             \x20    RestrictAddressFamilies=AF_UNIX AF_VSOCK\n\
             \x20    [Install]\n\
             \x20    WantedBy=multi-user.target\n\
             runcmd:\n\
             \x20- |\n\
             \x20  getent group {service_group} >/dev/null || groupadd --system {service_group}\n\
             \x20  id -u {service_user} >/dev/null 2>&1 || useradd --system --gid {service_group} --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin {service_user}\n\
             \x20  chown root:{service_group} /etc/asterism/agent.key\n\
             \x20  chmod 0640 /etc/asterism/agent.key\n\
             \x20  modprobe cuse\n\
             \x20  udevadm control --reload-rules\n\
             \x20  udevadm trigger --action=add /sys/class/misc/cuse\n\
             \x20  udevadm settle\n\
             \x20  test -c /dev/cuse\n\
             \x20  test \"$(stat -c '%U:%G:%a' /dev/cuse)\" = \"root:{service_group}:660\"\n\
             \x20  install -d -m 0755 /usr/local/lib/asterism\n\
             \x20  ln -sfn libcuda.so.1.0.0 /usr/local/lib/asterism/libcuda.so.1\n\
             \x20  ln -sfn libcuda.so.1 /usr/local/lib/asterism/libcuda.so\n\
             \x20  printf '%s\\n' /usr/local/lib/asterism > /etc/ld.so.conf.d/asterism-gpu.conf\n\
             \x20  ldconfig\n\
             \x20  systemctl daemon-reload\n\
             \x20  systemctl enable --now asterism-gpu-guest.service\n",
            service_user = GUEST_GPU_SERVICE_USER,
            service_group = GUEST_GPU_SERVICE_GROUP,
        )
    }

    /// Boot fragment for direct-kernel OCI guests, which have no cloud-init
    /// or systemd. BusyBox materializes the same two verified artifacts and
    /// starts the service before the image entrypoint.
    pub fn oci_boot_script(&self, key_hex: &str) -> String {
        format!(
            "$BB mkdir -p /etc/asterism /usr/local/sbin /usr/local/lib/asterism /var/log\n\
             if $BB grep -q '^[^:]*:[^:]*:65532:' /etc/group 2>/dev/null; then\n\
             \x20 $BB grep -qx '{service_group}:x:65532:' /etc/group || exit 1\n\
             else printf '%s\\n' '{service_group}:x:65532:' >> /etc/group; fi\n\
             if $BB grep -q '^[^:]*:[^:]*:65532:' /etc/passwd 2>/dev/null; then\n\
             \x20 $BB grep -qx '{service_user}:x:65532:65532:Asterism GPU service:/nonexistent:/bin/false' /etc/passwd || exit 1\n\
             else printf '%s\\n' '{service_user}:x:65532:65532:Asterism GPU service:/nonexistent:/bin/false' >> /etc/passwd; fi\n\
             printf '%s\\n' '{}' > /etc/asterism/agent.key\n\
             $BB chown 0:65532 /etc/asterism/agent.key\n\
             chmod 0640 /etc/asterism/agent.key\n\
             [ -c /dev/cuse ] || {{ echo 'asterism: guest CUSE device is missing' >&2; exit 1; }}\n\
             $BB chown 0:65532 /dev/cuse\n\
             chmod 0660 /dev/cuse\n\
             printf '%s' '{}' | $BB base64 -d > /usr/local/sbin/asterism-gpu-guest\n\
             chmod 0755 /usr/local/sbin/asterism-gpu-guest\n\
             printf '%s' '{}' | $BB base64 -d > /usr/local/lib/asterism/libcuda.so.1.0.0\n\
             chmod 0755 /usr/local/lib/asterism/libcuda.so.1.0.0\n\
             $BB ln -sfn libcuda.so.1.0.0 /usr/local/lib/asterism/libcuda.so.1\n\
             $BB ln -sfn libcuda.so.1 /usr/local/lib/asterism/libcuda.so\n\
             export LD_LIBRARY_PATH=/usr/local/lib/asterism${{LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}}\n\
             $BB setuidgid {service_user} /usr/local/sbin/asterism-gpu-guest >/var/log/asterism-gpu.log 2>&1 &\n",
            key_hex,
            BASE64.encode(&self.service),
            BASE64.encode(&self.libcuda),
            service_user = GUEST_GPU_SERVICE_USER,
            service_group = GUEST_GPU_SERVICE_GROUP,
        )
    }
}

fn read_guest_artifact(path: &Path) -> io::Result<Vec<u8>> {
    let metadata = fs::metadata(path)?;
    if metadata.len() == 0 || metadata.len() > MAX_GUEST_ARTIFACT_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "guest artifact {} has invalid size {}",
                path.display(),
                metadata.len()
            ),
        ));
    }
    fs::read(path)
}

/// CUDA Driver API error codes the shim returns. Values match CUDA 12/13
/// `CUresult` so an unmodified application can print them.
pub const CUDA_SUCCESS: i32 = 0;
pub const CUDA_ERROR_INVALID_VALUE: i32 = 1;
pub const CUDA_ERROR_OUT_OF_MEMORY: i32 = 2;
pub const CUDA_ERROR_NOT_INITIALIZED: i32 = 3;
pub const CUDA_ERROR_DEINITIALIZED: i32 = 4;
pub const CUDA_ERROR_NO_DEVICE: i32 = 100;
pub const CUDA_ERROR_INVALID_DEVICE: i32 = 101;
pub const CUDA_ERROR_INVALID_CONTEXT: i32 = 201;
pub const CUDA_ERROR_INVALID_HANDLE: i32 = 400;
pub const CUDA_ERROR_NOT_FOUND: i32 = 500;
pub const CUDA_ERROR_NOT_SUPPORTED: i32 = 801;
pub const CUDA_ERROR_UNKNOWN: i32 = 999;
/// CUDA 12.0 driver version encoding (`major * 1000`).
pub const CUDA_DRIVER_VERSION: i32 = 12000;
/// `CU_DEVICE_ATTRIBUTE_MULTIPROCESSOR_COUNT`
pub const CU_DEVICE_ATTRIBUTE_MULTIPROCESSOR_COUNT: i32 = 16;
/// `CU_DEVICE_ATTRIBUTE_COMPUTE_CAPABILITY_MAJOR`
pub const CU_DEVICE_ATTRIBUTE_COMPUTE_CAPABILITY_MAJOR: i32 = 75;
/// `CU_DEVICE_ATTRIBUTE_COMPUTE_CAPABILITY_MINOR`
pub const CU_DEVICE_ATTRIBUTE_COMPUTE_CAPABILITY_MINOR: i32 = 76;

/// How `/dev/nvidia0` is materialized in this guest root.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GuestDeviceKind {
    /// Linux production: CUSE character device at `/dev/nvidia0`.
    Cuse,
    /// Portable projection used when `/dev/cuse` is absent: a Unix-domain
    /// socket bound at the nvidia0 path. Still a real local endpoint.
    UnixEndpoint,
}

/// Exact CUDA Driver API matrix ABI 1 implements.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CudaDriverSymbol {
    CuInit,
    CuDriverGetVersion,
    CuDeviceGetCount,
    CuDeviceGet,
    CuDeviceGetName,
    CuDeviceGetUuid,
    CuDeviceGetAttribute,
    CuCtxCreate,
    CuCtxDestroy,
    CuCtxGetCurrent,
    CuCtxSetCurrent,
    CuCtxSynchronize,
    CuMemAlloc,
    CuMemFree,
    CuMemcpyHtoD,
    CuMemcpyDtoH,
    CuModuleLoadData,
    CuModuleUnload,
    CuModuleGetFunction,
    CuLaunchKernel,
    CuGetErrorString,
    CuGetErrorName,
}

impl CudaDriverSymbol {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CuInit => "cuInit",
            Self::CuDriverGetVersion => "cuDriverGetVersion",
            Self::CuDeviceGetCount => "cuDeviceGetCount",
            Self::CuDeviceGet => "cuDeviceGet",
            Self::CuDeviceGetName => "cuDeviceGetName",
            Self::CuDeviceGetUuid => "cuDeviceGetUuid",
            Self::CuDeviceGetAttribute => "cuDeviceGetAttribute",
            Self::CuCtxCreate => "cuCtxCreate",
            Self::CuCtxDestroy => "cuCtxDestroy",
            Self::CuCtxGetCurrent => "cuCtxGetCurrent",
            Self::CuCtxSetCurrent => "cuCtxSetCurrent",
            Self::CuCtxSynchronize => "cuCtxSynchronize",
            Self::CuMemAlloc => "cuMemAlloc",
            Self::CuMemFree => "cuMemFree",
            Self::CuMemcpyHtoD => "cuMemcpyHtoD",
            Self::CuMemcpyDtoH => "cuMemcpyDtoH",
            Self::CuModuleLoadData => "cuModuleLoadData",
            Self::CuModuleUnload => "cuModuleUnload",
            Self::CuModuleGetFunction => "cuModuleGetFunction",
            Self::CuLaunchKernel => "cuLaunchKernel",
            Self::CuGetErrorString => "cuGetErrorString",
            Self::CuGetErrorName => "cuGetErrorName",
        }
    }

    pub fn parse(name: &str) -> Option<Self> {
        SUPPORTED_CUDA_DRIVER_SYMBOLS
            .iter()
            .copied()
            .find(|symbol| symbol.as_str() == name)
    }
}

/// Supported CUDA Driver API symbols. This is the entire ABI 1 surface.
pub const SUPPORTED_CUDA_DRIVER_SYMBOLS: &[CudaDriverSymbol] = &[
    CudaDriverSymbol::CuInit,
    CudaDriverSymbol::CuDriverGetVersion,
    CudaDriverSymbol::CuDeviceGetCount,
    CudaDriverSymbol::CuDeviceGet,
    CudaDriverSymbol::CuDeviceGetName,
    CudaDriverSymbol::CuDeviceGetUuid,
    CudaDriverSymbol::CuDeviceGetAttribute,
    CudaDriverSymbol::CuCtxCreate,
    CudaDriverSymbol::CuCtxDestroy,
    CudaDriverSymbol::CuCtxGetCurrent,
    CudaDriverSymbol::CuCtxSetCurrent,
    CudaDriverSymbol::CuCtxSynchronize,
    CudaDriverSymbol::CuMemAlloc,
    CudaDriverSymbol::CuMemFree,
    CudaDriverSymbol::CuMemcpyHtoD,
    CudaDriverSymbol::CuMemcpyDtoH,
    CudaDriverSymbol::CuModuleLoadData,
    CudaDriverSymbol::CuModuleUnload,
    CudaDriverSymbol::CuModuleGetFunction,
    CudaDriverSymbol::CuLaunchKernel,
    CudaDriverSymbol::CuGetErrorString,
    CudaDriverSymbol::CuGetErrorName,
];

/// Representative Driver/Runtime symbols that must fail closed.
pub const FAIL_CLOSED_CUDA_SYMBOLS: &[&str] = &[
    "cuMemAllocManaged",
    "cuMemAllocHost",
    "cuMemHostRegister",
    "cuMemcpyAsync",
    "cuMemPrefetchAsync",
    "cuEventCreate",
    "cuStreamCreate",
    "cuGraphCreate",
    "cuIpcGetMemHandle",
    "cuCtxEnablePeerAccess",
    "cuLinkCreate",
    "cuGraphicsMapResources",
    "cuGLCtxCreate",
    "cudaMalloc",
    "cudaMemcpy",
    "cudaLaunchKernel",
];

/// Device attributes ABI 1 will answer. Anything else is not supported.
pub const SUPPORTED_DEVICE_ATTRIBUTES: &[&str] = &[
    "COMPUTE_CAPABILITY_MAJOR",
    "COMPUTE_CAPABILITY_MINOR",
    "MULTIPROCESSOR_COUNT",
];

/// One framed call from the generated libcuda onto the projected device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum GuestFrame {
    Open { versions: AbiRange },
    Cuda { id: u64, call: CudaCall },
    Cancel { id: u64 },
    Close,
}

/// CUDA-semantic operations the generated shim is allowed to issue.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "call", rename_all = "snake_case")]
pub enum CudaCall {
    Init,
    DriverGetVersion,
    DeviceCount,
    DeviceGet {
        ordinal: u32,
    },
    DeviceName {
        ordinal: u32,
    },
    DeviceUuid {
        ordinal: u32,
    },
    DeviceAttribute {
        ordinal: u32,
        attribute: String,
    },
    CtxCreate {
        flags: u32,
        device: u32,
    },
    CtxDestroy {
        context: u64,
    },
    CtxGetCurrent,
    CtxSetCurrent {
        context: u64,
    },
    CtxSynchronize,
    MemAlloc {
        bytes: u64,
    },
    MemcpyHtoD {
        allocation: String,
        offset: u64,
        #[serde(with = "b64")]
        data: Vec<u8>,
    },
    MemcpyDtoH {
        allocation: String,
        offset: u64,
        bytes: u64,
    },
    ModuleLoadData {
        #[serde(with = "b64")]
        image: Vec<u8>,
    },
    ModuleUnload {
        module: String,
    },
    ModuleGetFunction {
        module: String,
        name: String,
    },
    LaunchKernel {
        function: String,
        grid_x: u32,
        grid_y: u32,
        grid_z: u32,
        block_x: u32,
        block_y: u32,
        block_z: u32,
        shared_mem: u32,
        lhs: String,
        rhs: String,
        output: String,
        elements: u64,
    },
    LaunchVectorAdd {
        workload_pin: String,
        lhs: String,
        rhs: String,
        output: String,
        elements: u64,
    },
    MemFree {
        allocation: String,
    },
    Synchronize,
    GetErrorName {
        code: i32,
    },
    GetErrorString {
        code: i32,
    },
    /// Any symbol not in [`SUPPORTED_CUDA_DRIVER_SYMBOLS`].
    Unsupported {
        symbol: String,
    },
}

/// Reply to one [`GuestFrame`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum GuestReply {
    Accepted {
        abi: u32,
        projection_kind: String,
        device_kind: GuestDeviceKind,
        executor: gpu::Executor,
        credit: u32,
    },
    Refused {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        id: Option<u64>,
        code: String,
        message: String,
    },
    Cuda {
        id: u64,
        result: CudaResult,
    },
    Cancelled {
        id: u64,
    },
    Closed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum CudaResult {
    Init,
    DriverVersion {
        version: i32,
    },
    DeviceCount {
        count: u32,
    },
    Device {
        ordinal: u32,
    },
    DeviceName {
        name: String,
    },
    DeviceUuid {
        uuid: String,
    },
    DeviceAttribute {
        value: i32,
    },
    Context {
        context: u64,
    },
    CurrentContext {
        context: u64,
    },
    Alloc {
        allocation: String,
    },
    Copied {
        bytes: u64,
    },
    Data {
        #[serde(with = "b64")]
        data: Vec<u8>,
    },
    Module {
        pin: String,
    },
    Unloaded,
    Function {
        function: String,
    },
    Launched {
        provider_elapsed_ns: u64,
    },
    Freed,
    Synced,
    ErrorName {
        name: String,
    },
    ErrorString {
        text: String,
    },
    Error {
        cuda: i32,
        message: String,
    },
}

/// Disposition of an ioctl against the projected node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IoctlDisposition {
    /// Asterism contract ioctl: returns ABI version.
    Contract,
    /// NVIDIA or unknown ioctl: fail closed.
    FailClosed,
}

/// Decide an ioctl on the projected `/dev/nvidia0`. Raw NVIDIA commands
/// never become a mesh frame.
pub fn ioctl_disposition(request: u64) -> IoctlDisposition {
    if request == ASTERISM_IOCTL_GET_ABI {
        IoctlDisposition::Contract
    } else {
        IoctlDisposition::FailClosed
    }
}

pub fn nvidia_ioctl_is_refused(request: u64) -> bool {
    ioctl_disposition(request) == IoctlDisposition::FailClosed
}

/// True when this host could register a CUSE node. Absence is not a skip of
/// the Unix-endpoint fixture; production Linux guests require CUSE.
pub fn linux_cuse_available() -> bool {
    Path::new("/dev/cuse").exists()
}

/// Bind a real local endpoint at `<guest-root>/dev/nvidia0`.
///
/// When `/dev/cuse` exists this starts a CUSE character-device service and
/// materializes the guest-visible node. When `/dev/cuse` is absent the
/// portable Unix-domain fixture is bound. The kind always names the
/// mechanism that is actually running.
pub fn project_guest_device(guest_root: &Path) -> io::Result<GuestDevice> {
    let directory = guest_root.join("dev");
    fs::create_dir_all(&directory)?;
    let path = directory.join("nvidia0");
    match fs::remove_file(&path) {
        Ok(()) => {}
        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
        Err(err) => return Err(err),
    }
    if linux_cuse_available() {
        let cuse = remote_gpu_cuse::CuseService::mount(&path)?;
        return Ok(GuestDevice {
            path,
            kind: GuestDeviceKind::Cuse,
            inner: GuestInner::Cuse(cuse),
        });
    }
    let listener = UnixListener::bind(&path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o666))?;
    }
    Ok(GuestDevice {
        path,
        kind: GuestDeviceKind::UnixEndpoint,
        inner: GuestInner::Unix(listener),
    })
}

enum GuestInner {
    Unix(UnixListener),
    Cuse(remote_gpu_cuse::CuseService),
}

/// A projected `/dev/nvidia0` that can be connected to.
pub struct GuestDevice {
    pub path: PathBuf,
    pub kind: GuestDeviceKind,
    inner: GuestInner,
}

impl GuestDevice {
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn kind(&self) -> GuestDeviceKind {
        self.kind
    }

    /// Accept one libcuda connection. The caller serves [`GuestFrame`]s.
    pub fn accept(&self) -> io::Result<UnixStream> {
        match &self.inner {
            GuestInner::Unix(listener) => listener.accept().map(|(stream, _)| stream),
            GuestInner::Cuse(cuse) => cuse.accept(),
        }
    }
}

impl Drop for GuestDevice {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

enum ShimTransport {
    Unix(UnixStream),
    Char(File),
}

impl ShimTransport {
    fn try_clone(&self) -> io::Result<Self> {
        match self {
            Self::Unix(stream) => stream.try_clone().map(Self::Unix),
            Self::Char(file) => file.try_clone().map(Self::Char),
        }
    }

    fn raw_fd(&self) -> i32 {
        match self {
            Self::Unix(stream) => stream.as_raw_fd(),
            Self::Char(file) => file.as_raw_fd(),
        }
    }

    fn wait(&self, events: i16) -> io::Result<()> {
        loop {
            let mut fd = libc::pollfd {
                fd: self.raw_fd(),
                events,
                revents: 0,
            };
            let ready = unsafe { libc::poll(&mut fd, 1, -1) };
            if ready > 0 {
                return Ok(());
            }
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error);
            }
        }
    }
}

impl Read for ShimTransport {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            let result = match self {
                Self::Unix(stream) => stream.read(buf),
                Self::Char(file) => file.read(buf),
            };
            match result {
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    self.wait(libc::POLLIN)?;
                }
                other => return other,
            }
        }
    }
}

impl Write for ShimTransport {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        loop {
            let result = match self {
                Self::Unix(stream) => stream.write(buf),
                Self::Char(file) => file.write(buf),
            };
            match result {
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    self.wait(libc::POLLOUT)?;
                }
                other => return other,
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Unix(stream) => stream.flush(),
            Self::Char(file) => file.flush(),
        }
    }
}

/// Generated libcuda client: connects to the projected endpoint and issues
/// CUDA Driver calls as framed [`GuestFrame`]s.
pub struct GuestShim {
    writer: Arc<Mutex<ShimTransport>>,
    reader: Option<ShimTransport>,
    next_id: AtomicU64,
    pending: Arc<Mutex<PendingReplies>>,
    flow: Arc<(Mutex<FlowControl>, Condvar)>,
    control_rx: Mutex<Receiver<GuestReply>>,
    control_tx: Option<SyncSender<GuestReply>>,
}

#[derive(Default)]
struct PendingReplies {
    by_id: HashMap<u64, SyncSender<GuestReply>>,
    order: VecDeque<u64>,
}

#[derive(Default)]
struct FlowControl {
    available: u32,
    closed: bool,
}

impl GuestShim {
    pub fn connect(device: &Path) -> io::Result<Self> {
        let metadata = fs::metadata(device)?;
        let stream = if metadata.file_type().is_socket() {
            ShimTransport::Unix(UnixStream::connect(device)?)
        } else {
            ShimTransport::Char(File::options().read(true).write(true).open(device)?)
        };
        let reader = stream.try_clone()?;
        let (control_tx, control_rx) = mpsc::sync_channel(4);
        Ok(Self {
            writer: Arc::new(Mutex::new(stream)),
            reader: Some(reader),
            next_id: AtomicU64::new(0),
            pending: Arc::new(Mutex::new(PendingReplies::default())),
            flow: Arc::new((Mutex::new(FlowControl::default()), Condvar::new())),
            control_rx: Mutex::new(control_rx),
            control_tx: Some(control_tx),
        })
    }

    pub fn open(&mut self) -> Result<GuestReply, GuestError> {
        {
            let mut writer = self
                .writer
                .lock()
                .map_err(|_| GuestError::new("guest GPU writer lock poisoned"))?;
            write_frame(
                &mut *writer,
                &GuestFrame::Open {
                    versions: AbiRange::ours(),
                },
            )?;
        }
        let reader = self
            .reader
            .as_mut()
            .ok_or_else(|| GuestError::new("guest GPU shim was already opened"))?;
        let reply = read_frame(reader)?;
        let GuestReply::Accepted { credit, .. } = reply else {
            return Ok(reply);
        };
        {
            let (flow, _) = &*self.flow;
            flow.lock()
                .map_err(|_| GuestError::new("guest GPU flow lock poisoned"))?
                .available = credit;
        }
        let reader = self.reader.take().expect("reader checked above");
        let pending = self.pending.clone();
        let flow = self.flow.clone();
        let control = self.control_tx.take().expect("dispatcher starts once");
        thread::Builder::new()
            .name("asterism-libcuda-replies".into())
            .spawn(move || dispatch_replies(reader, pending, flow, control))
            .map_err(|error| GuestError::new(format!("starting GPU reply dispatcher: {error}")))?;
        Ok(reply)
    }

    pub fn call(&self, call: CudaCall) -> Result<CudaResult, GuestError> {
        take_credit(&self.flow)?;
        let id = self
            .next_id
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |id| id.checked_add(1))
            .map(|previous| previous + 1)
            .map_err(|_| GuestError::new("guest CUDA call id space exhausted"))?;
        let (tx, rx) = mpsc::sync_channel(1);
        {
            let mut pending = self
                .pending
                .lock()
                .map_err(|_| GuestError::new("guest GPU pending-call lock poisoned"))?;
            pending.by_id.insert(id, tx);
            pending.order.push_back(id);
        }
        let written = self
            .writer
            .lock()
            .map_err(|_| GuestError::new("guest GPU writer lock poisoned"))
            .and_then(|mut writer| write_frame(&mut *writer, &GuestFrame::Cuda { id, call }));
        if let Err(error) = written {
            remove_pending(&self.pending, id);
            return_credit(&self.flow);
            return Err(error);
        }
        match rx
            .recv()
            .map_err(|_| GuestError::new("guest GPU reply dispatcher stopped"))?
        {
            GuestReply::Cuda {
                id: reply_id,
                result,
            } if reply_id == id => Ok(result),
            GuestReply::Cancelled { id: cancelled } if cancelled == id => Err(GuestError::new(
                format!("guest CUDA call {id} was cancelled"),
            )),
            GuestReply::Refused { message, .. } => Err(GuestError::new(message)),
            other => Err(GuestError::new(format!(
                "unexpected guest reply while calling CUDA: {other:?}"
            ))),
        }
    }

    pub fn last_id(&self) -> u64 {
        self.next_id.load(Ordering::SeqCst)
    }

    /// Cancel an in-flight call from another application thread. The waiting
    /// call receives the provider's actual `Cancelled` reply; this method
    /// only confirms that the cancellation frame reached the local device.
    pub fn cancel(&self, id: u64) -> Result<GuestReply, GuestError> {
        if !self
            .pending
            .lock()
            .map_err(|_| GuestError::new("guest GPU pending-call lock poisoned"))?
            .by_id
            .contains_key(&id)
        {
            return Err(GuestError::new("cancel names a call that is not in flight"));
        }
        let mut writer = self
            .writer
            .lock()
            .map_err(|_| GuestError::new("guest GPU writer lock poisoned"))?;
        write_frame(&mut *writer, &GuestFrame::Cancel { id })?;
        Ok(GuestReply::Cancelled { id })
    }

    pub fn close(&self) -> Result<GuestReply, GuestError> {
        let mut writer = self
            .writer
            .lock()
            .map_err(|_| GuestError::new("guest GPU writer lock poisoned"))?;
        write_frame(&mut *writer, &GuestFrame::Close)?;
        drop(writer);
        self.control_rx
            .lock()
            .map_err(|_| GuestError::new("guest GPU control lock poisoned"))?
            .recv()
            .map_err(|_| GuestError::new("guest GPU reply dispatcher stopped"))
    }

    pub fn dispatch_symbol(
        &self,
        symbol: &str,
        call: Option<CudaCall>,
    ) -> Result<CudaResult, GuestError> {
        if CudaDriverSymbol::parse(symbol).is_none() {
            return self.call(CudaCall::Unsupported {
                symbol: symbol.to_owned(),
            });
        }
        let call = call.unwrap_or_else(|| cuda_call_for_symbol(symbol));
        self.call(call)
    }
}

fn take_credit(flow: &Arc<(Mutex<FlowControl>, Condvar)>) -> Result<(), GuestError> {
    let (state, ready) = &**flow;
    let mut state = state
        .lock()
        .map_err(|_| GuestError::new("guest GPU flow lock poisoned"))?;
    while state.available == 0 && !state.closed {
        state = ready
            .wait(state)
            .map_err(|_| GuestError::new("guest GPU flow lock poisoned"))?;
    }
    if state.closed {
        return Err(GuestError::new("guest GPU session is closed"));
    }
    state.available -= 1;
    Ok(())
}

fn return_credit(flow: &Arc<(Mutex<FlowControl>, Condvar)>) {
    let (state, ready) = &**flow;
    if let Ok(mut state) = state.lock() {
        state.available = state.available.saturating_add(1);
        ready.notify_one();
    }
}

fn remove_pending(pending: &Arc<Mutex<PendingReplies>>, id: u64) {
    if let Ok(mut pending) = pending.lock() {
        pending.by_id.remove(&id);
        if let Some(at) = pending.order.iter().position(|queued| *queued == id) {
            pending.order.remove(at);
        }
    }
}

fn dispatch_replies(
    mut reader: ShimTransport,
    pending: Arc<Mutex<PendingReplies>>,
    flow: Arc<(Mutex<FlowControl>, Condvar)>,
    control: SyncSender<GuestReply>,
) {
    while let Ok(reply) = read_frame::<GuestReply>(&mut reader) {
        let id = match &reply {
            GuestReply::Cuda { id, .. } | GuestReply::Cancelled { id } => Some(*id),
            GuestReply::Refused { id, .. } => id.or_else(|| {
                pending
                    .lock()
                    .ok()
                    .and_then(|pending| pending.order.front().copied())
            }),
            GuestReply::Closed | GuestReply::Accepted { .. } => {
                let closed = matches!(reply, GuestReply::Closed);
                let _ = control.send(reply);
                if closed {
                    break;
                }
                continue;
            }
        };
        if let Some(id) = id {
            let sender = pending.lock().ok().and_then(|mut pending| {
                if let Some(at) = pending.order.iter().position(|queued| *queued == id) {
                    pending.order.remove(at);
                }
                pending.by_id.remove(&id)
            });
            return_credit(&flow);
            if let Some(sender) = sender {
                let _ = sender.send(reply);
            }
        }
    }
    let (state, ready) = &*flow;
    if let Ok(mut state) = state.lock() {
        state.closed = true;
        ready.notify_all();
    }
    let stranded = pending
        .lock()
        .map(|mut pending| std::mem::take(&mut pending.by_id))
        .unwrap_or_default();
    for (id, sender) in stranded {
        let _ = sender.send(GuestReply::Refused {
            id: Some(id),
            code: "closed".into(),
            message: format!("guest GPU session closed with call {id} in flight"),
        });
    }
}

/// Map a CUDA Driver symbol onto the guest frame, failing closed outside the
/// implemented surface.
pub fn cuda_call_for_symbol(symbol: &str) -> CudaCall {
    match CudaDriverSymbol::parse(symbol) {
        Some(CudaDriverSymbol::CuInit) => CudaCall::Init,
        Some(CudaDriverSymbol::CuDriverGetVersion) => CudaCall::DriverGetVersion,
        Some(CudaDriverSymbol::CuDeviceGetCount) => CudaCall::DeviceCount,
        Some(CudaDriverSymbol::CuDeviceGet) => CudaCall::DeviceGet { ordinal: 0 },
        Some(CudaDriverSymbol::CuDeviceGetName) => CudaCall::DeviceName { ordinal: 0 },
        Some(CudaDriverSymbol::CuDeviceGetUuid) => CudaCall::DeviceUuid { ordinal: 0 },
        Some(CudaDriverSymbol::CuDeviceGetAttribute) => CudaCall::DeviceAttribute {
            ordinal: 0,
            attribute: "COMPUTE_CAPABILITY_MAJOR".into(),
        },
        Some(CudaDriverSymbol::CuCtxCreate) => CudaCall::CtxCreate {
            flags: 0,
            device: 0,
        },
        Some(CudaDriverSymbol::CuCtxDestroy) => CudaCall::CtxDestroy { context: 0 },
        Some(CudaDriverSymbol::CuCtxGetCurrent) => CudaCall::CtxGetCurrent,
        Some(CudaDriverSymbol::CuCtxSetCurrent) => CudaCall::CtxSetCurrent { context: 0 },
        Some(CudaDriverSymbol::CuCtxSynchronize) => CudaCall::CtxSynchronize,
        Some(CudaDriverSymbol::CuMemAlloc) => CudaCall::MemAlloc { bytes: 0 },
        Some(CudaDriverSymbol::CuMemFree) => CudaCall::MemFree {
            allocation: String::new(),
        },
        Some(CudaDriverSymbol::CuMemcpyHtoD) => CudaCall::MemcpyHtoD {
            allocation: String::new(),
            offset: 0,
            data: Vec::new(),
        },
        Some(CudaDriverSymbol::CuMemcpyDtoH) => CudaCall::MemcpyDtoH {
            allocation: String::new(),
            offset: 0,
            bytes: 0,
        },
        Some(CudaDriverSymbol::CuModuleLoadData) => CudaCall::ModuleLoadData { image: Vec::new() },
        Some(CudaDriverSymbol::CuModuleUnload) => CudaCall::ModuleUnload {
            module: String::new(),
        },
        Some(CudaDriverSymbol::CuModuleGetFunction) => CudaCall::ModuleGetFunction {
            module: String::new(),
            name: "vector_add_f32".into(),
        },
        Some(CudaDriverSymbol::CuLaunchKernel) => CudaCall::LaunchKernel {
            function: "vector_add_f32".into(),
            grid_x: 1,
            grid_y: 1,
            grid_z: 1,
            block_x: 1,
            block_y: 1,
            block_z: 1,
            shared_mem: 0,
            lhs: String::new(),
            rhs: String::new(),
            output: String::new(),
            elements: 0,
        },
        Some(CudaDriverSymbol::CuGetErrorString) => CudaCall::GetErrorString { code: 0 },
        Some(CudaDriverSymbol::CuGetErrorName) => CudaCall::GetErrorName { code: 0 },
        None => CudaCall::Unsupported {
            symbol: symbol.to_owned(),
        },
    }
}

fn cstr(text: &'static str) -> &'static str {
    text
}

pub fn cuda_error_name(code: i32) -> &'static str {
    match code {
        CUDA_SUCCESS => cstr("CUDA_SUCCESS\0"),
        CUDA_ERROR_INVALID_VALUE => cstr("CUDA_ERROR_INVALID_VALUE\0"),
        CUDA_ERROR_OUT_OF_MEMORY => cstr("CUDA_ERROR_OUT_OF_MEMORY\0"),
        CUDA_ERROR_NOT_INITIALIZED => cstr("CUDA_ERROR_NOT_INITIALIZED\0"),
        CUDA_ERROR_DEINITIALIZED => cstr("CUDA_ERROR_DEINITIALIZED\0"),
        CUDA_ERROR_NO_DEVICE => cstr("CUDA_ERROR_NO_DEVICE\0"),
        CUDA_ERROR_INVALID_DEVICE => cstr("CUDA_ERROR_INVALID_DEVICE\0"),
        CUDA_ERROR_INVALID_CONTEXT => cstr("CUDA_ERROR_INVALID_CONTEXT\0"),
        CUDA_ERROR_INVALID_HANDLE => cstr("CUDA_ERROR_INVALID_HANDLE\0"),
        CUDA_ERROR_NOT_FOUND => cstr("CUDA_ERROR_NOT_FOUND\0"),
        CUDA_ERROR_NOT_SUPPORTED => cstr("CUDA_ERROR_NOT_SUPPORTED\0"),
        CUDA_ERROR_UNKNOWN => cstr("CUDA_ERROR_UNKNOWN\0"),
        _ => cstr("CUDA_ERROR_UNKNOWN\0"),
    }
}

pub fn cuda_error_string(code: i32) -> &'static str {
    match code {
        CUDA_SUCCESS => cstr("no error\0"),
        CUDA_ERROR_INVALID_VALUE => cstr("invalid argument\0"),
        CUDA_ERROR_OUT_OF_MEMORY => cstr("out of memory\0"),
        CUDA_ERROR_NOT_INITIALIZED => cstr("driver not initialized\0"),
        CUDA_ERROR_DEINITIALIZED => cstr("driver deinitialized\0"),
        CUDA_ERROR_NO_DEVICE => cstr("no CUDA-capable device is detected\0"),
        CUDA_ERROR_INVALID_DEVICE => cstr("invalid device ordinal\0"),
        CUDA_ERROR_INVALID_CONTEXT => cstr("invalid context\0"),
        CUDA_ERROR_INVALID_HANDLE => cstr("invalid handle\0"),
        CUDA_ERROR_NOT_FOUND => cstr("named symbol not found\0"),
        CUDA_ERROR_NOT_SUPPORTED => cstr("operation not supported\0"),
        _ => cstr("unknown error\0"),
    }
}

pub fn cuda_error_is_named(code: i32) -> bool {
    matches!(
        code,
        CUDA_SUCCESS
            | CUDA_ERROR_INVALID_VALUE
            | CUDA_ERROR_OUT_OF_MEMORY
            | CUDA_ERROR_NOT_INITIALIZED
            | CUDA_ERROR_DEINITIALIZED
            | CUDA_ERROR_NO_DEVICE
            | CUDA_ERROR_INVALID_DEVICE
            | CUDA_ERROR_INVALID_CONTEXT
            | CUDA_ERROR_INVALID_HANDLE
            | CUDA_ERROR_NOT_FOUND
            | CUDA_ERROR_NOT_SUPPORTED
            | CUDA_ERROR_UNKNOWN
    )
}

pub fn device_attribute_name(code: i32) -> Option<&'static str> {
    match code {
        CU_DEVICE_ATTRIBUTE_MULTIPROCESSOR_COUNT => Some("MULTIPROCESSOR_COUNT"),
        CU_DEVICE_ATTRIBUTE_COMPUTE_CAPABILITY_MAJOR => Some("COMPUTE_CAPABILITY_MAJOR"),
        CU_DEVICE_ATTRIBUTE_COMPUTE_CAPABILITY_MINOR => Some("COMPUTE_CAPABILITY_MINOR"),
        _ => None,
    }
}

/// HMAC-SHA256 over the GPU vsock transcript. Same per-instance key as the
/// guest agent; the [`GUEST_GPU_PROOF_LABEL`] keeps a control-channel proof
/// from standing in for this hop.
pub fn gpu_hmac_proof(
    key: &[u8; 32],
    version: u32,
    side: &str,
    guest_nonce: &str,
    host_nonce: &str,
) -> String {
    let message = format!("{GUEST_GPU_PROOF_LABEL}/{version} {side} {guest_nonce} {host_nonce}");
    hex(&hmac_sha256(key, message.as_bytes()))
}

pub fn verify_gpu_proof(
    key: &[u8; 32],
    version: u32,
    side: &str,
    guest_nonce: &str,
    host_nonce: &str,
    proof: &str,
) -> bool {
    let expected = gpu_hmac_proof(key, version, side, guest_nonce, host_nonce);
    same_proof(proof, &expected)
}

pub fn guest_agent_style_proof(
    key: &[u8; 32],
    version: u32,
    side: &str,
    guest_nonce: &str,
    host_nonce: &str,
) -> String {
    let message = format!("asterism-guest/{version} {side} {guest_nonce} {host_nonce}");
    hex(&hmac_sha256(key, message.as_bytes()))
}

fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut padded = [0u8; BLOCK];
    if key.len() > BLOCK {
        padded[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        padded[..key.len()].copy_from_slice(key);
    }
    let mut inner = Sha256::new();
    inner.update(padded.map(|b| b ^ 0x36));
    inner.update(message);
    let inner = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(padded.map(|b| b ^ 0x5c));
    outer.update(inner);
    outer.finalize().into()
}

fn hex(bytes: &[u8]) -> String {
    const TABLE: &[u8] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(TABLE[(byte >> 4) as usize] as char);
        out.push(TABLE[(byte & 0x0f) as usize] as char);
    }
    out
}

fn same_proof(left: &str, right: &str) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.bytes()
        .zip(right.bytes())
        .fold(0u8, |acc, (a, b)| acc | (a ^ b))
        == 0
}

/// Opening hello on guest GPU vsock port [`GUEST_GPU_VSOCK_PORT`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GpuVsockHello {
    pub agent: String,
    pub versions: Vec<u32>,
    pub nonce: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GpuVsockAccept {
    pub version: u32,
    pub nonce: String,
    pub proof: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GpuVsockWelcome {
    pub ok: bool,
    pub proof: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

const GPU_VSOCK_MAX_LINE: usize = 64 * 1024;

/// Host half of the instance-HMAC GPU vsock hop. After this returns, the
/// stream carries length-prefixed [`GuestFrame`]s, not a LAN listener.
pub fn gpu_vsock_host_handshake(
    reader: &mut impl BufRead,
    writer: &mut impl Write,
    key: &[u8; 32],
    host_nonce: &str,
) -> Result<u32, GuestError> {
    let hello: GpuVsockHello = read_vsock_line(reader)?;
    if hello.agent != "asterism-gpu" {
        return Err(GuestError::new(format!(
            "the service on vsock port {GUEST_GPU_VSOCK_PORT} calls itself {:?}, not asterism-gpu",
            hello.agent
        )));
    }
    if !hello.versions.contains(&1) {
        return Err(GuestError::new(
            "no GPU vsock protocol version in common with this helper",
        ));
    }
    let proof = gpu_hmac_proof(key, 1, "host", &hello.nonce, host_nonce);
    write_vsock_line(
        writer,
        &GpuVsockAccept {
            version: 1,
            nonce: host_nonce.to_owned(),
            proof,
        },
    )?;
    let welcome: GpuVsockWelcome = read_vsock_line(reader)?;
    if !welcome.ok {
        return Err(GuestError::new(
            welcome
                .error
                .unwrap_or_else(|| "guest GPU vsock refused the helper".into()),
        ));
    }
    if !verify_gpu_proof(key, 1, "guest", &hello.nonce, host_nonce, &welcome.proof) {
        return Err(GuestError::new(
            "the guest GPU hop did not prove it holds this instance's key",
        ));
    }
    Ok(1)
}

/// Guest half of the same hop. Distinct HMAC side label from the guest agent.
pub fn gpu_vsock_guest_handshake(
    reader: &mut impl BufRead,
    writer: &mut impl Write,
    key: &[u8; 32],
    guest_nonce: &str,
) -> Result<u32, GuestError> {
    write_vsock_line(
        writer,
        &GpuVsockHello {
            agent: "asterism-gpu".into(),
            versions: vec![1],
            nonce: guest_nonce.to_owned(),
        },
    )?;
    let accept: GpuVsockAccept = read_vsock_line(reader)?;
    if accept.version != 1 {
        return Err(GuestError::new(format!(
            "GPU vsock helper picked unsupported version {}",
            accept.version
        )));
    }
    if !verify_gpu_proof(key, 1, "host", guest_nonce, &accept.nonce, &accept.proof) {
        return Err(GuestError::new(
            "GPU vsock helper did not prove it holds this instance's key",
        ));
    }
    write_vsock_line(
        writer,
        &GpuVsockWelcome {
            ok: true,
            proof: gpu_hmac_proof(key, 1, "guest", guest_nonce, &accept.nonce),
            error: None,
        },
    )?;
    Ok(1)
}

fn read_vsock_line<T: for<'de> Deserialize<'de>>(
    reader: &mut impl BufRead,
) -> Result<T, GuestError> {
    // Bound the read itself, not just the post-read validation. `read_line`
    // grows its String until newline and therefore lets an unauthenticated
    // peer allocate an arbitrary amount before the old limit was checked.
    let mut line = Vec::with_capacity(1024);
    let n = reader
        .take((GPU_VSOCK_MAX_LINE + 1) as u64)
        .read_until(b'\n', &mut line)?;
    if n == 0 {
        return Err(GuestError::new("GPU vsock peer closed during handshake"));
    }
    if line.len() > GPU_VSOCK_MAX_LINE || !line.ends_with(b"\n") {
        return Err(GuestError::new("GPU vsock handshake line exceeds 64 KiB"));
    }
    while matches!(line.last(), Some(b'\n' | b'\r')) {
        line.pop();
    }
    serde_json::from_slice(&line).map_err(|err| GuestError::new(err.to_string()))
}

fn write_vsock_line(writer: &mut impl Write, value: &impl Serialize) -> Result<(), GuestError> {
    let mut line = serde_json::to_vec(value).map_err(|err| GuestError::new(err.to_string()))?;
    if line.len() > GPU_VSOCK_MAX_LINE {
        return Err(GuestError::new("GPU vsock handshake line exceeds 64 KiB"));
    }
    line.push(b'\n');
    writer.write_all(&line)?;
    writer.flush()?;
    Ok(())
}

pub fn uuid_bytes_from_text(text: &str) -> [u8; 16] {
    let mut out = [0u8; 16];
    let hex: String = text.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    let bytes = hex.as_bytes();
    for (i, byte) in out.iter_mut().enumerate() {
        let start = i * 2;
        if start + 1 < bytes.len() {
            let pair = std::str::from_utf8(&bytes[start..start + 2]).unwrap_or("00");
            *byte = u8::from_str_radix(pair, 16).unwrap_or(0);
        }
    }
    out
}

#[derive(Debug)]
pub struct GuestError {
    pub message: String,
}

impl GuestError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl std::fmt::Display for GuestError {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        out.write_str(&self.message)
    }
}

impl std::error::Error for GuestError {}

impl From<io::Error> for GuestError {
    fn from(err: io::Error) -> Self {
        Self::new(err.to_string())
    }
}

pub fn write_frame(writer: &mut impl Write, value: &impl Serialize) -> Result<(), GuestError> {
    let body = serde_json::to_vec(value).map_err(|err| GuestError::new(err.to_string()))?;
    if body.len() > MAX_WIRE_FRAME_BYTES {
        return Err(GuestError::new(format!(
            "guest GPU frame is {} bytes, above the {MAX_WIRE_FRAME_BYTES} byte limit",
            body.len()
        )));
    }
    let len =
        u32::try_from(body.len()).map_err(|_| GuestError::new("guest GPU frame too large"))?;
    writer.write_all(&len.to_be_bytes())?;
    writer.write_all(&body)?;
    writer.flush()?;
    Ok(())
}

pub fn read_frame<T: for<'de> Deserialize<'de>>(reader: &mut impl Read) -> Result<T, GuestError> {
    let mut len = [0u8; 4];
    reader.read_exact(&mut len)?;
    let len = u32::from_be_bytes(len) as usize;
    if len > MAX_WIRE_FRAME_BYTES {
        return Err(GuestError::new(format!(
            "guest GPU frame of {len} bytes exceeds the {MAX_WIRE_FRAME_BYTES} byte limit"
        )));
    }
    let mut body = vec![0u8; len];
    reader.read_exact(&mut body)?;
    serde_json::from_slice(&body).map_err(|err| GuestError::new(err.to_string()))
}

/// Map a guest CUDA call onto one ABI request. The adapter owns session and
/// sequence so libcuda never sees a mesh identity.
pub fn abi_request_for(
    session: &str,
    sequence: u64,
    call: &CudaCall,
) -> Result<Request, GuestError> {
    match call {
        CudaCall::Init
        | CudaCall::DriverGetVersion
        | CudaCall::DeviceCount
        | CudaCall::DeviceGet { .. }
        | CudaCall::DeviceName { .. }
        | CudaCall::DeviceUuid { .. }
        | CudaCall::DeviceAttribute { .. }
        | CudaCall::CtxCreate { .. }
        | CudaCall::CtxDestroy { .. }
        | CudaCall::CtxGetCurrent
        | CudaCall::CtxSetCurrent { .. }
        | CudaCall::GetErrorName { .. }
        | CudaCall::GetErrorString { .. } => Err(GuestError::new(
            "init/device queries are session-local and do not become ABI mutations",
        )),
        CudaCall::MemAlloc { bytes } => Ok(Request::Allocate {
            session: session.to_owned(),
            sequence,
            bytes: *bytes,
        }),
        CudaCall::MemcpyHtoD {
            allocation,
            offset,
            data,
        } => Ok(Request::Write {
            session: session.to_owned(),
            sequence,
            destination: BufferRange {
                allocation: allocation.clone(),
                offset: *offset,
                bytes: data.len() as u64,
            },
            data: data.clone(),
        }),
        CudaCall::MemcpyDtoH {
            allocation,
            offset,
            bytes,
        } => Ok(Request::Read {
            session: session.to_owned(),
            sequence,
            source: BufferRange {
                allocation: allocation.clone(),
                offset: *offset,
                bytes: *bytes,
            },
        }),
        CudaCall::ModuleLoadData { image } => {
            let descriptor = gpu::vector_add_workload();
            Ok(Request::LoadWorkload {
                session: session.to_owned(),
                sequence,
                descriptor,
                image: image.clone(),
            })
        }
        CudaCall::LaunchVectorAdd {
            workload_pin,
            lhs,
            rhs,
            output,
            elements,
        } => {
            let bytes = elements
                .checked_mul(4)
                .ok_or_else(|| GuestError::new("vector-add element count overflows"))?;
            Ok(Request::LaunchVectorAdd {
                session: session.to_owned(),
                sequence,
                workload_pin: workload_pin.clone(),
                lhs: BufferRange {
                    allocation: lhs.clone(),
                    offset: 0,
                    bytes,
                },
                rhs: BufferRange {
                    allocation: rhs.clone(),
                    offset: 0,
                    bytes,
                },
                output: BufferRange {
                    allocation: output.clone(),
                    offset: 0,
                    bytes,
                },
                elements: *elements,
            })
        }
        CudaCall::MemFree { allocation } => Ok(Request::Free {
            session: session.to_owned(),
            sequence,
            allocation: allocation.clone(),
        }),
        CudaCall::LaunchKernel {
            function,
            lhs,
            rhs,
            output,
            elements,
            shared_mem,
            ..
        } => {
            if function != "vector_add_f32" || *shared_mem != 0 {
                return Err(GuestError::new(
                    "cuLaunchKernel only launches the pinned vector_add_f32 entrypoint",
                ));
            }
            abi_request_for(
                session,
                sequence,
                &CudaCall::LaunchVectorAdd {
                    workload_pin: gpu::content_pin(gpu::VECTOR_ADD_PTX.as_bytes()),
                    lhs: lhs.clone(),
                    rhs: rhs.clone(),
                    output: output.clone(),
                    elements: *elements,
                },
            )
        }
        CudaCall::ModuleUnload { .. } => Err(GuestError::new(
            "cuModuleUnload is session-local and does not become an ABI mutation",
        )),
        CudaCall::ModuleGetFunction { .. } => Err(GuestError::new(
            "cuModuleGetFunction is session-local and does not become an ABI mutation",
        )),
        CudaCall::CtxSynchronize | CudaCall::Synchronize => Err(GuestError::new(
            "cuCtxSynchronize is a local barrier after the last ABI reply",
        )),
        CudaCall::Unsupported { symbol } => Err(GuestError::new(format!(
            "{symbol} is outside the implemented CUDA Driver surface"
        ))),
    }
}

pub fn cuda_result_for(call: &CudaCall, reply: Reply) -> CudaResult {
    match (call, reply) {
        (
            CudaCall::MemAlloc { .. },
            Reply::Ok {
                response: Response::Allocated { allocation, .. },
            },
        ) => CudaResult::Alloc { allocation },
        (
            CudaCall::MemcpyHtoD { .. },
            Reply::Ok {
                response: Response::Written { bytes, .. },
            },
        ) => CudaResult::Copied { bytes },
        (
            CudaCall::MemcpyDtoH { .. },
            Reply::Ok {
                response: Response::Data { data, .. },
            },
        ) => CudaResult::Data { data },
        (
            CudaCall::ModuleLoadData { .. },
            Reply::Ok {
                response: Response::WorkloadLoaded { content_blake3, .. },
            },
        ) => CudaResult::Module {
            pin: content_blake3,
        },
        (
            CudaCall::LaunchVectorAdd { .. },
            Reply::Ok {
                response:
                    Response::Launched {
                        provider_elapsed_ns,
                        ..
                    },
            },
        ) => CudaResult::Launched {
            provider_elapsed_ns,
        },
        (
            CudaCall::MemFree { .. },
            Reply::Ok {
                response: Response::Freed { .. },
            },
        ) => CudaResult::Freed,
        (
            CudaCall::LaunchKernel { .. },
            Reply::Ok {
                response:
                    Response::Launched {
                        provider_elapsed_ns,
                        ..
                    },
            },
        ) => CudaResult::Launched {
            provider_elapsed_ns,
        },
        (_, Reply::Error { error }) => CudaResult::Error {
            cuda: match error.code {
                ErrorCode::LimitExceeded | ErrorCode::OutOfBounds => CUDA_ERROR_INVALID_VALUE,
                ErrorCode::UnknownAllocation | ErrorCode::InvalidSession => CUDA_ERROR_NOT_FOUND,
                ErrorCode::WorkloadMismatch | ErrorCode::InvalidLaunch => CUDA_ERROR_NOT_SUPPORTED,
                _ => CUDA_ERROR_UNKNOWN,
            },
            message: error.message,
        },
        (_, other) => CudaResult::Error {
            cuda: CUDA_ERROR_UNKNOWN,
            message: format!("unexpected ABI reply: {other:?}"),
        },
    }
}

pub(crate) mod b64 {
    use data_encoding::BASE64;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&BASE64.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        let encoded = String::deserialize(deserializer)?;
        BASE64
            .decode(encoded.as_bytes())
            .map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::BufReader;
    use std::os::unix::net::UnixStream;

    #[test]
    fn the_supported_matrix_is_exact_and_fail_closed_outside_it() {
        assert_eq!(SUPPORTED_CUDA_DRIVER_SYMBOLS.len(), 22);
        for symbol in SUPPORTED_CUDA_DRIVER_SYMBOLS {
            if let CudaCall::Unsupported { symbol: name } = cuda_call_for_symbol(symbol.as_str()) {
                panic!("{name} is supported and must not fail closed")
            }
        }
        assert!(CudaDriverSymbol::parse("cuMemAlloc").is_some());
        assert!(CudaDriverSymbol::parse("cuMemAllocManaged").is_none());
        assert!(CudaDriverSymbol::parse("cudaMalloc").is_none());
        match cuda_call_for_symbol("cuMemAllocManaged") {
            CudaCall::Unsupported { symbol } => assert_eq!(symbol, "cuMemAllocManaged"),
            other => panic!("expected fail-closed, got {other:?}"),
        }
    }

    #[test]
    fn cuda_status_strings_are_nul_terminated() {
        for code in [
            CUDA_SUCCESS,
            CUDA_ERROR_INVALID_VALUE,
            CUDA_ERROR_NOT_INITIALIZED,
            CUDA_ERROR_NOT_SUPPORTED,
            CUDA_ERROR_UNKNOWN,
            123456,
        ] {
            let name = cuda_error_name(code);
            let text = cuda_error_string(code);
            assert!(name.ends_with('\0'), "{name:?}");
            assert!(text.ends_with('\0'), "{text:?}");
            assert!(!name[..name.len() - 1].contains('\0'));
            assert!(!text[..text.len() - 1].contains('\0'));
        }
        assert!(!cuda_error_is_named(123456));
    }

    #[test]
    fn gpu_hmac_proof_cannot_be_replayed_as_guest_agent_proof() {
        let key = [9u8; 32];
        let gpu = gpu_hmac_proof(&key, 1, "host", "guest-nonce", "host-nonce");
        let agent = guest_agent_style_proof(&key, 1, "host", "guest-nonce", "host-nonce");
        assert_ne!(gpu, agent);
        assert!(verify_gpu_proof(
            &key,
            1,
            "host",
            "guest-nonce",
            "host-nonce",
            &gpu
        ));
        assert!(!verify_gpu_proof(
            &key,
            1,
            "guest",
            "guest-nonce",
            "host-nonce",
            &gpu
        ));
        assert!(!verify_gpu_proof(
            &key,
            1,
            "host",
            "guest-nonce",
            "host-nonce",
            &agent
        ));
    }

    #[test]
    fn gpu_vsock_handshake_proves_instance_key() {
        let key = [3u8; 32];
        let (guest, host) = UnixStream::pair().unwrap();
        let guest_thread = std::thread::spawn(move || {
            let mut reader = BufReader::new(guest.try_clone().unwrap());
            let mut writer = guest;
            gpu_vsock_guest_handshake(&mut reader, &mut writer, &key, "g-nonce")
        });
        let mut reader = BufReader::new(host.try_clone().unwrap());
        let mut writer = host;
        gpu_vsock_host_handshake(&mut reader, &mut writer, &key, "h-nonce").unwrap();
        guest_thread.join().unwrap().unwrap();
    }

    #[test]
    fn nvidia_ioctls_are_refused_and_asterism_contract_ioctl_is_named() {
        let nvidia = (u64::from(NVIDIA_IOCTL_MAGIC) << 8) | 0x2a;
        assert!(nvidia_ioctl_is_refused(nvidia));
        assert_eq!(ioctl_disposition(nvidia), IoctlDisposition::FailClosed);
        let contract = (u64::from(ASTERISM_IOCTL_MAGIC) << 8) | 1;
        assert_eq!(ioctl_disposition(contract), IoctlDisposition::Contract);
        assert!(!nvidia_ioctl_is_refused(contract));
        let unknown_contract = (u64::from(ASTERISM_IOCTL_MAGIC) << 8) | 2;
        assert_eq!(
            ioctl_disposition(unknown_contract),
            IoctlDisposition::FailClosed
        );
    }

    #[test]
    fn pre_auth_handshake_read_is_bounded_before_json_parsing() {
        let oversized = vec![b'x'; GPU_VSOCK_MAX_LINE * 8];
        let mut cursor = std::io::Cursor::new(oversized);
        let result = read_vsock_line::<GpuVsockHello>(&mut cursor);
        assert!(result.is_err());
        assert_eq!(cursor.position(), (GPU_VSOCK_MAX_LINE + 1) as u64);
    }

    #[test]
    fn guest_artifacts_render_cloud_and_oci_installation() {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir_all(root.path().join("bin")).unwrap();
        fs::create_dir_all(root.path().join("lib")).unwrap();
        fs::write(root.path().join("bin/asterism-gpu-guest"), b"\x7fELFguest").unwrap();
        fs::write(root.path().join("lib/libcuda.so.1.0.0"), b"\x7fELFcuda").unwrap();

        let artifacts = GuestProjectionArtifacts::from_dir(root.path()).unwrap();
        let cloud = artifacts.cloud_config();
        assert!(cloud.contains("asterism-gpu-guest.service"));
        assert!(cloud.contains("libcuda.so.1.0.0"));
        assert!(cloud.contains("User=asterism-gpu"));
        assert!(cloud.contains("Group=asterism-gpu"));
        assert!(cloud.contains(GUEST_CUSE_UDEV_RULE.trim()));
        assert!(cloud.contains("DeviceAllow=/dev/cuse rw"));
        assert!(cloud.contains("CapabilityBoundingSet="));
        assert!(!cloud.contains("MODE=\"0666\""));
        assert!(cloud.contains("enable --now asterism-gpu-guest.service"));
        let oci = artifacts.oci_boot_script("0011");
        assert!(oci.contains("/etc/asterism/agent.key"));
        assert!(oci.contains("export LD_LIBRARY_PATH="));
        assert!(oci.contains("setuidgid asterism-gpu /usr/local/sbin/asterism-gpu-guest"));
        assert!(oci.contains("chmod 0660 /dev/cuse"));
    }

    #[test]
    fn projecting_nvidia0_creates_a_connectable_local_endpoint_not_a_marker_file() {
        use std::os::unix::fs::FileTypeExt;
        let root = tempfile::tempdir().unwrap();
        let device = project_guest_device(root.path()).unwrap();
        assert_eq!(device.path().file_name().unwrap(), "nvidia0");
        let metadata = fs::metadata(device.path()).unwrap();
        assert!(
            metadata.file_type().is_socket() || metadata.file_type().is_char_device(),
            "projected nvidia0 must be a socket or CUSE node, not a regular file"
        );
        match device.kind() {
            GuestDeviceKind::Cuse => assert!(linux_cuse_available()),
            GuestDeviceKind::UnixEndpoint => assert!(!linux_cuse_available()),
        }
        let client = std::thread::scope(|scope| {
            let server = scope.spawn(|| device.accept().unwrap());
            let connected = GuestShim::connect(device.path()).unwrap();
            drop(server.join().unwrap());
            connected
        });
        drop(client);
        assert!(device.path().exists());
    }

    #[test]
    fn guest_shim_pipelines_and_routes_out_of_order_replies_by_id() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("nvidia0");
        let listener = UnixListener::bind(&path).unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            assert!(matches!(
                read_frame::<GuestFrame>(&mut stream).unwrap(),
                GuestFrame::Open { .. }
            ));
            write_frame(
                &mut stream,
                &GuestReply::Accepted {
                    abi: gpu::ABI_VERSION,
                    projection_kind: PROJECTION_KIND.into(),
                    device_kind: GuestDeviceKind::UnixEndpoint,
                    executor: gpu::Executor::Cuda,
                    credit: 2,
                },
            )
            .unwrap();
            let first = read_frame::<GuestFrame>(&mut stream).unwrap();
            let second = read_frame::<GuestFrame>(&mut stream).unwrap();
            let reply_for = |frame: GuestFrame| match frame {
                GuestFrame::Cuda {
                    id,
                    call: CudaCall::DeviceCount,
                } => GuestReply::Cuda {
                    id,
                    result: CudaResult::DeviceCount { count: 7 },
                },
                GuestFrame::Cuda {
                    id,
                    call: CudaCall::DriverGetVersion,
                } => GuestReply::Cuda {
                    id,
                    result: CudaResult::DriverVersion { version: 12_345 },
                },
                other => panic!("unexpected call: {other:?}"),
            };
            write_frame(&mut stream, &reply_for(second)).unwrap();
            write_frame(&mut stream, &reply_for(first)).unwrap();
        });

        let mut shim = GuestShim::connect(&path).unwrap();
        assert!(matches!(shim.open().unwrap(), GuestReply::Accepted { .. }));
        let shim = Arc::new(shim);
        thread::scope(|scope| {
            let count_shim = shim.clone();
            let count = scope.spawn(move || count_shim.call(CudaCall::DeviceCount).unwrap());
            let version_shim = shim.clone();
            let version =
                scope.spawn(move || version_shim.call(CudaCall::DriverGetVersion).unwrap());
            assert_eq!(count.join().unwrap(), CudaResult::DeviceCount { count: 7 });
            assert_eq!(
                version.join().unwrap(),
                CudaResult::DriverVersion { version: 12_345 }
            );
        });
        server.join().unwrap();
    }

    #[test]
    fn guest_shim_cancel_is_reachable_while_call_waits() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("nvidia0");
        let listener = UnixListener::bind(&path).unwrap();
        let (id_tx, id_rx) = mpsc::sync_channel(1);
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let _ = read_frame::<GuestFrame>(&mut stream).unwrap();
            write_frame(
                &mut stream,
                &GuestReply::Accepted {
                    abi: gpu::ABI_VERSION,
                    projection_kind: PROJECTION_KIND.into(),
                    device_kind: GuestDeviceKind::UnixEndpoint,
                    executor: gpu::Executor::Cuda,
                    credit: 1,
                },
            )
            .unwrap();
            let GuestFrame::Cuda { id, .. } = read_frame::<GuestFrame>(&mut stream).unwrap() else {
                panic!("expected CUDA call")
            };
            id_tx.send(id).unwrap();
            assert_eq!(
                read_frame::<GuestFrame>(&mut stream).unwrap(),
                GuestFrame::Cancel { id }
            );
            write_frame(&mut stream, &GuestReply::Cancelled { id }).unwrap();
        });

        let mut shim = GuestShim::connect(&path).unwrap();
        let _ = shim.open().unwrap();
        let shim = Arc::new(shim);
        thread::scope(|scope| {
            let caller = shim.clone();
            let call = scope.spawn(move || caller.call(CudaCall::DeviceCount));
            let id = id_rx.recv().unwrap();
            assert_eq!(shim.cancel(id).unwrap(), GuestReply::Cancelled { id });
            assert!(call
                .join()
                .unwrap()
                .unwrap_err()
                .message
                .contains("cancelled"));
        });
        server.join().unwrap();
    }

    #[test]
    fn pipelined_refusal_is_delivered_to_its_exact_call_id() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("nvidia0");
        let listener = UnixListener::bind(&path).unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let _ = read_frame::<GuestFrame>(&mut stream).unwrap();
            write_frame(
                &mut stream,
                &GuestReply::Accepted {
                    abi: gpu::ABI_VERSION,
                    projection_kind: PROJECTION_KIND.into(),
                    device_kind: GuestDeviceKind::UnixEndpoint,
                    executor: gpu::Executor::Cuda,
                    credit: 2,
                },
            )
            .unwrap();
            let calls = [
                read_frame::<GuestFrame>(&mut stream).unwrap(),
                read_frame::<GuestFrame>(&mut stream).unwrap(),
            ];
            let id_for = |wanted: fn(&CudaCall) -> bool| {
                calls
                    .iter()
                    .find_map(|frame| match frame {
                        GuestFrame::Cuda { id, call } if wanted(call) => Some(*id),
                        _ => None,
                    })
                    .unwrap()
            };
            let version_id = id_for(|call| matches!(call, CudaCall::DriverGetVersion));
            let count_id = id_for(|call| matches!(call, CudaCall::DeviceCount));
            write_frame(
                &mut stream,
                &GuestReply::Refused {
                    id: Some(version_id),
                    code: "refused".into(),
                    message: "version refused".into(),
                },
            )
            .unwrap();
            write_frame(
                &mut stream,
                &GuestReply::Cuda {
                    id: count_id,
                    result: CudaResult::DeviceCount { count: 1 },
                },
            )
            .unwrap();
        });

        let mut shim = GuestShim::connect(&path).unwrap();
        let _ = shim.open().unwrap();
        let shim = Arc::new(shim);
        thread::scope(|scope| {
            let count = {
                let shim = shim.clone();
                scope.spawn(move || shim.call(CudaCall::DeviceCount))
            };
            let version = {
                let shim = shim.clone();
                scope.spawn(move || shim.call(CudaCall::DriverGetVersion))
            };
            assert_eq!(
                count.join().unwrap().unwrap(),
                CudaResult::DeviceCount { count: 1 }
            );
            assert!(version
                .join()
                .unwrap()
                .unwrap_err()
                .message
                .contains("version refused"));
        });
        server.join().unwrap();
    }
}
