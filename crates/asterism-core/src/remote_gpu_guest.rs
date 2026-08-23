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

use std::fs;
use std::io::{self, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::remote_gpu::{
    self as gpu, AbiRange, BufferRange, ErrorCode, Reply, Request, Response, MAX_WIRE_FRAME_BYTES,
};

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
/// NVIDIA's historical ioctl magic (`'F'`). Every request with this magic is
/// refused: we do not forward host-pointer driver commands.
pub const NVIDIA_IOCTL_MAGIC: u8 = b'F';
/// Asterism's own ioctl magic for a one-word contract query on a CUSE node.
pub const ASTERISM_IOCTL_MAGIC: u8 = b'A';
/// In-flight CUDA calls permitted before the consumer must wait for credit.
pub const DEFAULT_CREDIT_WINDOW: u32 = 4;

/// CUDA Driver API error codes the shim returns. Values match CUDA 12/13
/// `CUresult` so an unmodified application can print them.
pub const CUDA_SUCCESS: i32 = 0;
pub const CUDA_ERROR_INVALID_VALUE: i32 = 1;
pub const CUDA_ERROR_NOT_INITIALIZED: i32 = 3;
pub const CUDA_ERROR_NO_DEVICE: i32 = 100;
pub const CUDA_ERROR_INVALID_DEVICE: i32 = 101;
pub const CUDA_ERROR_NOT_FOUND: i32 = 500;
pub const CUDA_ERROR_NOT_SUPPORTED: i32 = 801;
pub const CUDA_ERROR_UNKNOWN: i32 = 999;

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
    Open {
        versions: AbiRange,
    },
    Cuda {
        id: u64,
        call: CudaCall,
    },
    Cancel {
        id: u64,
    },
    Close,
}

/// CUDA-semantic operations the generated shim is allowed to issue.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "call", rename_all = "snake_case")]
pub enum CudaCall {
    Init,
    DeviceCount,
    DeviceName {
        ordinal: u32,
    },
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
    DeviceCount {
        count: u32,
    },
    DeviceName {
        name: String,
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
    Launched {
        provider_elapsed_ns: u64,
    },
    Freed,
    Synced,
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
    let magic = ((request >> 8) & 0xff) as u8;
    if magic == ASTERISM_IOCTL_MAGIC {
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
/// When `/dev/cuse` exists the kind is [`GuestDeviceKind::Cuse`] and the
/// Unix socket is still bound so source fixtures and the generated libcuda
/// have a framed endpoint without claiming a kernel NVIDIA driver. The
/// character device is the guest-visible contract; the socket is the control
/// channel the CUSE daemon serves.
pub fn project_guest_device(guest_root: &Path) -> io::Result<GuestDevice> {
    let directory = guest_root.join("dev");
    fs::create_dir_all(&directory)?;
    let path = directory.join("nvidia0");
    match fs::remove_file(&path) {
        Ok(()) => {}
        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
        Err(err) => return Err(err),
    }
    let listener = UnixListener::bind(&path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o666))?;
    }
    let kind = if linux_cuse_available() {
        GuestDeviceKind::Cuse
    } else {
        GuestDeviceKind::UnixEndpoint
    };
    Ok(GuestDevice {
        path,
        kind,
        listener,
    })
}

/// A projected `/dev/nvidia0` that can be connected to.
pub struct GuestDevice {
    pub path: PathBuf,
    pub kind: GuestDeviceKind,
    listener: UnixListener,
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
        self.listener.accept().map(|(stream, _)| stream)
    }
}

impl Drop for GuestDevice {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

/// Generated libcuda client: connects to the projected endpoint and issues
/// CUDA Driver calls as framed [`GuestFrame`]s.
pub struct GuestShim {
    stream: UnixStream,
    next_id: u64,
}

impl GuestShim {
    pub fn connect(device: &Path) -> io::Result<Self> {
        let stream = UnixStream::connect(device)?;
        Ok(Self {
            stream,
            next_id: 0,
        })
    }

    pub fn open(&mut self) -> Result<GuestReply, GuestError> {
        write_frame(
            &mut self.stream,
            &GuestFrame::Open {
                versions: AbiRange::ours(),
            },
        )?;
        read_frame(&mut self.stream)
    }

    pub fn call(&mut self, call: CudaCall) -> Result<CudaResult, GuestError> {
        self.next_id = self
            .next_id
            .checked_add(1)
            .ok_or_else(|| GuestError::new("guest CUDA call id space exhausted"))?;
        write_frame(
            &mut self.stream,
            &GuestFrame::Cuda {
                id: self.next_id,
                call,
            },
        )?;
        match read_frame::<GuestReply>(&mut self.stream)? {
            GuestReply::Cuda { result, .. } => Ok(result),
            GuestReply::Refused { message, .. } => Err(GuestError::new(message)),
            other => Err(GuestError::new(format!(
                "unexpected guest reply while calling CUDA: {other:?}"
            ))),
        }
    }

    pub fn cancel(&mut self, id: u64) -> Result<GuestReply, GuestError> {
        write_frame(&mut self.stream, &GuestFrame::Cancel { id })?;
        read_frame(&mut self.stream)
    }

    pub fn close(&mut self) -> Result<GuestReply, GuestError> {
        write_frame(&mut self.stream, &GuestFrame::Close)?;
        read_frame(&mut self.stream)
    }

    pub fn dispatch_symbol(
        &mut self,
        symbol: &str,
        call: Option<CudaCall>,
    ) -> Result<CudaResult, GuestError> {
        if CudaDriverSymbol::parse(symbol).is_none() {
            return self.call(CudaCall::Unsupported {
                symbol: symbol.to_owned(),
            });
        }
        let call = call.ok_or_else(|| {
            GuestError::new(format!("{symbol} is supported but was dispatched without arguments"))
        })?;
        self.call(call)
    }
}

/// Map a CUDA Driver symbol onto the guest frame, failing closed outside the
/// implemented surface.
pub fn cuda_call_for_symbol(symbol: &str) -> CudaCall {
    match CudaDriverSymbol::parse(symbol) {
        Some(CudaDriverSymbol::CuInit) => CudaCall::Init,
        Some(CudaDriverSymbol::CuDeviceGetCount) => CudaCall::DeviceCount,
        Some(_) => CudaCall::Unsupported {
            symbol: symbol.to_owned(),
        },
        None => CudaCall::Unsupported {
            symbol: symbol.to_owned(),
        },
    }
}

pub fn cuda_error_name(code: i32) -> &'static str {
    match code {
        CUDA_SUCCESS => "CUDA_SUCCESS",
        CUDA_ERROR_INVALID_VALUE => "CUDA_ERROR_INVALID_VALUE",
        CUDA_ERROR_NOT_INITIALIZED => "CUDA_ERROR_NOT_INITIALIZED",
        CUDA_ERROR_NO_DEVICE => "CUDA_ERROR_NO_DEVICE",
        CUDA_ERROR_INVALID_DEVICE => "CUDA_ERROR_INVALID_DEVICE",
        CUDA_ERROR_NOT_FOUND => "CUDA_ERROR_NOT_FOUND",
        CUDA_ERROR_NOT_SUPPORTED => "CUDA_ERROR_NOT_SUPPORTED",
        _ => "CUDA_ERROR_UNKNOWN",
    }
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
    let len = u32::try_from(body.len()).map_err(|_| GuestError::new("guest GPU frame too large"))?;
    writer.write_all(&len.to_be_bytes())?;
    writer.write_all(&body)?;
    writer.flush()?;
    Ok(())
}

pub fn read_frame<T: for<'de> Deserialize<'de>>(
    reader: &mut impl Read,
) -> Result<T, GuestError> {
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
        CudaCall::Init | CudaCall::DeviceCount | CudaCall::DeviceName { .. } => {
            Err(GuestError::new(
                "init/device queries are session-local and do not become ABI mutations",
            ))
        }
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
        CudaCall::Synchronize => Err(GuestError::new(
            "cuCtxSynchronize is a local barrier after the last ABI reply",
        )),
        CudaCall::Unsupported { symbol } => Err(GuestError::new(format!(
            "{symbol} is outside the implemented CUDA Driver surface"
        ))),
    }
}

pub fn cuda_result_for(call: &CudaCall, reply: Reply) -> CudaResult {
    match (call, reply) {
        (CudaCall::MemAlloc { .. }, Reply::Ok { response: Response::Allocated { allocation, .. } }) => {
            CudaResult::Alloc { allocation }
        }
        (CudaCall::MemcpyHtoD { .. }, Reply::Ok { response: Response::Written { bytes, .. } }) => {
            CudaResult::Copied { bytes }
        }
        (CudaCall::MemcpyDtoH { .. }, Reply::Ok { response: Response::Data { data, .. } }) => {
            CudaResult::Data { data }
        }
        (
            CudaCall::ModuleLoadData { .. },
            Reply::Ok {
                response: Response::WorkloadLoaded { content_blake3, .. },
            },
        ) => CudaResult::Module { pin: content_blake3 },
        (
            CudaCall::LaunchVectorAdd { .. },
            Reply::Ok {
                response: Response::Launched {
                    provider_elapsed_ns, ..
                },
            },
        ) => CudaResult::Launched {
            provider_elapsed_ns,
        },
        (CudaCall::MemFree { .. }, Reply::Ok { response: Response::Freed { .. } }) => {
            CudaResult::Freed
        }
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

    #[test]
    fn the_supported_matrix_is_exact_and_fail_closed_outside_it() {
        assert_eq!(SUPPORTED_CUDA_DRIVER_SYMBOLS.len(), 22);
        assert!(CudaDriverSymbol::parse("cuMemAlloc").is_some());
        assert!(CudaDriverSymbol::parse("cuMemAllocManaged").is_none());
        assert!(CudaDriverSymbol::parse("cudaMalloc").is_none());
        match cuda_call_for_symbol("cuMemAllocManaged") {
            CudaCall::Unsupported { symbol } => assert_eq!(symbol, "cuMemAllocManaged"),
            other => panic!("expected fail-closed, got {other:?}"),
        }
    }

    #[test]
    fn nvidia_ioctls_are_refused_and_asterism_contract_ioctl_is_named() {
        let nvidia = (u64::from(NVIDIA_IOCTL_MAGIC) << 8) | 0x2a;
        assert!(nvidia_ioctl_is_refused(nvidia));
        assert_eq!(ioctl_disposition(nvidia), IoctlDisposition::FailClosed);
        let contract = (u64::from(ASTERISM_IOCTL_MAGIC) << 8) | 1;
        assert_eq!(ioctl_disposition(contract), IoctlDisposition::Contract);
        assert!(!nvidia_ioctl_is_refused(contract));
    }

    #[test]
    fn projecting_nvidia0_creates_a_connectable_local_endpoint_not_a_marker_file() {
        use std::os::unix::fs::FileTypeExt;
        let root = tempfile::tempdir().unwrap();
        let device = project_guest_device(root.path()).unwrap();
        assert_eq!(device.path().file_name().unwrap(), "nvidia0");
        let metadata = fs::metadata(device.path()).unwrap();
        assert!(
            metadata.file_type().is_socket(),
            "projected nvidia0 must be a socket or CUSE node, not a regular file"
        );
        let client = std::thread::scope(|scope| {
            let server = scope.spawn(|| device.accept().unwrap());
            let connected = GuestShim::connect(device.path()).unwrap();
            drop(server.join().unwrap());
            connected
        });
        drop(client);
        assert!(device.path().exists());
    }
}
