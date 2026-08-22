//! The versioned ABI behind a GPU that looks local to a guest and executes on
//! another device in the orbit.
//!
//! This is deliberately a CUDA-*semantic* boundary, not an NVIDIA ioctl
//! forwarder. Driver ioctls contain host pointers, private structure layouts,
//! mmap offsets and event/fence semantics that only make sense inside one
//! kernel/driver pair. The stable things are higher-level operations: allocate,
//! copy, load a content-pinned workload, launch it, and read the result.
//!
//! Nothing here chooses a transport. Production carries these messages over
//! the authenticated, encrypted orbit mesh. The runnable proof uses loopback
//! TCP and refuses non-loopback addresses, so it cannot accidentally turn a
//! session ID into a network-reachable bearer capability.

use std::collections::{HashMap, HashSet};
use std::time::Instant;

use data_encoding::BASE64;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use uuid::Uuid;

/// Newest ABI implemented by this build.
pub const ABI_VERSION: u32 = 1;
/// Oldest ABI this build still serves.
pub const MIN_ABI_VERSION: u32 = 1;
/// An encoded request or reply must fit beneath this ceiling.
pub const MAX_WIRE_FRAME_BYTES: usize = 4 * 1024 * 1024;
/// The one workload the proof sends to the provider.
pub const VECTOR_ADD_WORKLOAD_NAME: &str = "asterism.vector_add_f32.v1";

/// CUDA PTX is the pinned provider-side artifact in the proof. A production
/// executor may compile it, cache it by its pin, and launch it on a physical
/// GPU. The proof's reference executor evaluates the same vector-add semantics
/// on the CPU so it runs on development machines without an NVIDIA device.
pub const VECTOR_ADD_PTX: &str = r#".version 7.0
.target sm_50
.address_size 64

.visible .entry vector_add_f32(
    .param .u64 lhs,
    .param .u64 rhs,
    .param .u64 output,
    .param .u32 elements
)
{
    .reg .pred %p;
    .reg .b32 %r<6>;
    .reg .b64 %rd<8>;
    .reg .f32 %f<4>;
    ld.param.u64 %rd1, [lhs];
    ld.param.u64 %rd2, [rhs];
    ld.param.u64 %rd3, [output];
    ld.param.u32 %r1, [elements];
    mov.u32 %r2, %ctaid.x;
    mov.u32 %r3, %ntid.x;
    mov.u32 %r4, %tid.x;
    mad.lo.s32 %r5, %r2, %r3, %r4;
    setp.ge.u32 %p, %r5, %r1;
    @%p bra done;
    mul.wide.u32 %rd4, %r5, 4;
    add.s64 %rd5, %rd1, %rd4;
    add.s64 %rd6, %rd2, %rd4;
    add.s64 %rd7, %rd3, %rd4;
    ld.global.f32 %f1, [%rd5];
    ld.global.f32 %f2, [%rd6];
    add.f32 %f3, %f1, %f2;
    st.global.f32 [%rd7], %f3;
done:
    ret;
}
"#;

/// A contiguous, hole-free range of ABI versions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AbiRange {
    pub min: u32,
    pub max: u32,
}

impl AbiRange {
    pub const fn ours() -> Self {
        Self {
            min: MIN_ABI_VERSION,
            max: ABI_VERSION,
        }
    }

    /// Select the newest ABI spoken by both ends.
    pub fn negotiate(self, peer: Self) -> Result<u32, GpuError> {
        if self.min == 0 || peer.min == 0 || self.min > self.max || peer.min > peer.max {
            return Err(GpuError::new(
                ErrorCode::InvalidRequest,
                None,
                "ABI ranges must be non-zero and ordered",
            ));
        }
        let floor = self.min.max(peer.min);
        let ceiling = self.max.min(peer.max);
        (floor <= ceiling).then_some(ceiling).ok_or_else(|| {
            GpuError::new(
                ErrorCode::UnsupportedVersion,
                None,
                format!(
                    "no remote GPU ABI is common to consumer {}..{} and provider {}..{}",
                    peer.min, peer.max, self.min, self.max
                ),
            )
        })
    }
}

/// Hard provider limits advertised during the handshake and enforced on every
/// call. A consumer never has to discover them by exhausting provider memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Limits {
    pub max_allocation_bytes: u64,
    pub max_session_bytes: u64,
    pub max_provider_bytes: u64,
    pub max_copy_bytes: u64,
    pub max_launch_bytes: u64,
    pub max_allocations: u32,
    pub max_workload_bytes: u64,
    pub max_sessions: u32,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_allocation_bytes: 64 * 1024 * 1024,
            max_session_bytes: 256 * 1024 * 1024,
            max_provider_bytes: 512 * 1024 * 1024,
            // Base64 plus JSON must remain below MAX_WIRE_FRAME_BYTES.
            max_copy_bytes: 2 * 1024 * 1024,
            max_launch_bytes: 8 * 1024 * 1024,
            max_allocations: 64,
            max_workload_bytes: 256 * 1024,
            max_sessions: 128,
        }
    }
}

/// What executes launches on the provider. `Reference` makes the ABI proof
/// portable; it is not presented as hardware CUDA in compatibility output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Executor {
    Cuda,
    Reference,
}

/// Capabilities returned with the provider-issued session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Capabilities {
    pub executor: Executor,
    pub device_name: String,
    pub semantic_boundary: String,
    pub workload_formats: Vec<WorkloadFormat>,
    pub limits: Limits,
}

impl Capabilities {
    pub fn reference(device_name: impl Into<String>, limits: Limits) -> Self {
        Self {
            executor: Executor::Reference,
            device_name: device_name.into(),
            semantic_boundary: "cuda_semantic_v1".into(),
            workload_formats: vec![WorkloadFormat::CudaPtx],
            limits,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkloadFormat {
    CudaPtx,
}

/// Identity and declared semantics of an artifact. The provider checks the
/// bytes against `content_blake3` before making the workload launchable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkloadDescriptor {
    pub name: String,
    pub format: WorkloadFormat,
    pub entrypoint: String,
    pub content_blake3: String,
}

/// Descriptor for the checked-in PTX above.
pub fn vector_add_workload() -> WorkloadDescriptor {
    WorkloadDescriptor {
        name: VECTOR_ADD_WORKLOAD_NAME.into(),
        format: WorkloadFormat::CudaPtx,
        entrypoint: "vector_add_f32".into(),
        content_blake3: content_pin(VECTOR_ADD_PTX.as_bytes()),
    }
}

/// A stable textual content address used on the wire and in logs.
pub fn content_pin(bytes: &[u8]) -> String {
    format!("blake3:{}", blake3::hash(bytes).to_hex())
}

/// One range in a provider-owned allocation. The checked `offset + bytes`
/// arithmetic is the gate before any slice is formed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BufferRange {
    pub allocation: String,
    pub offset: u64,
    pub bytes: u64,
}

/// Transport-independent consumer -> provider frames.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Request {
    Hello {
        versions: AbiRange,
        consumer: String,
    },
    Allocate {
        session: String,
        sequence: u64,
        bytes: u64,
    },
    Write {
        session: String,
        sequence: u64,
        destination: BufferRange,
        #[serde(with = "base64")]
        data: Vec<u8>,
    },
    LoadWorkload {
        session: String,
        sequence: u64,
        descriptor: WorkloadDescriptor,
        #[serde(with = "base64")]
        image: Vec<u8>,
    },
    LaunchVectorAdd {
        session: String,
        sequence: u64,
        workload_pin: String,
        lhs: BufferRange,
        rhs: BufferRange,
        output: BufferRange,
        elements: u64,
    },
    Read {
        session: String,
        sequence: u64,
        source: BufferRange,
    },
    Free {
        session: String,
        sequence: u64,
        allocation: String,
    },
    Close {
        session: String,
        sequence: u64,
    },
}

impl Request {
    fn session_and_sequence(&self) -> Option<(&str, u64)> {
        match self {
            Request::Hello { .. } => None,
            Request::Allocate {
                session, sequence, ..
            }
            | Request::Write {
                session, sequence, ..
            }
            | Request::LoadWorkload {
                session, sequence, ..
            }
            | Request::LaunchVectorAdd {
                session, sequence, ..
            }
            | Request::Read {
                session, sequence, ..
            }
            | Request::Free {
                session, sequence, ..
            }
            | Request::Close { session, sequence } => Some((session, *sequence)),
        }
    }
}

/// Provider -> consumer success frames.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum Response {
    SessionOpened {
        abi: u32,
        session: String,
        capabilities: Capabilities,
    },
    Allocated {
        sequence: u64,
        allocation: String,
        bytes: u64,
    },
    Written {
        sequence: u64,
        bytes: u64,
    },
    WorkloadLoaded {
        sequence: u64,
        content_blake3: String,
    },
    Launched {
        sequence: u64,
        elements: u64,
        provider_elapsed_ns: u64,
    },
    Data {
        sequence: u64,
        #[serde(with = "base64")]
        data: Vec<u8>,
    },
    Freed {
        sequence: u64,
    },
    SessionClosed {
        sequence: u64,
    },
}

/// Every wire request gets one explicitly tagged reply.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Reply {
    Ok { response: Response },
    Error { error: GpuError },
}

impl Reply {
    pub fn into_result(self) -> Result<Response, GpuError> {
        match self {
            Reply::Ok { response } => Ok(response),
            Reply::Error { error } => Err(error),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    UnsupportedVersion,
    InvalidSession,
    InvalidSequence,
    LimitExceeded,
    UnknownAllocation,
    OutOfBounds,
    WorkloadMismatch,
    InvalidLaunch,
    InvalidRequest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GpuError {
    pub code: ErrorCode,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sequence: Option<u64>,
    pub message: String,
}

impl GpuError {
    fn new(code: ErrorCode, sequence: Option<u64>, message: impl Into<String>) -> Self {
        Self {
            code,
            sequence,
            message: message.into(),
        }
    }
}

impl std::fmt::Display for GpuError {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(out, "{}", self.message)
    }
}

impl std::error::Error for GpuError {}

#[derive(Debug, Default)]
struct Session {
    last_sequence: u64,
    allocated_bytes: u64,
    allocations: HashMap<String, Vec<u8>>,
    workloads: HashSet<String>,
}

/// Provider-side ABI state machine. Transport adapters feed it decoded
/// requests; it owns every session/allocation ID and all validation.
#[derive(Debug)]
pub struct Provider {
    versions: AbiRange,
    capabilities: Capabilities,
    committed_bytes: u64,
    sessions: HashMap<String, Session>,
}

impl Provider {
    pub fn reference(device_name: impl Into<String>) -> Self {
        Self::reference_with_limits(device_name, Limits::default())
    }

    /// Reference executor with deliberately chosen ceilings. Production
    /// providers use this seam to advertise the budget they actually enforce;
    /// tests use small ceilings without allocating production-sized buffers.
    pub fn reference_with_limits(device_name: impl Into<String>, limits: Limits) -> Self {
        Self {
            versions: AbiRange::ours(),
            capabilities: Capabilities::reference(device_name, limits),
            committed_bytes: 0,
            sessions: HashMap::new(),
        }
    }

    pub fn capabilities(&self) -> &Capabilities {
        &self.capabilities
    }

    /// Apply one decoded frame. A valid session consumes its sequence number
    /// before operation validation: retrying rejected bytes with the same
    /// sequence is still a replay, rather than a second interpretation of one
    /// authenticated call.
    pub fn handle(&mut self, request: Request) -> Reply {
        match self.apply(request) {
            Ok(response) => Reply::Ok { response },
            Err(error) => Reply::Error { error },
        }
    }

    fn apply(&mut self, request: Request) -> Result<Response, GpuError> {
        if let Request::Hello { versions, consumer } = &request {
            if consumer.trim().is_empty() || consumer.len() > 128 {
                return Err(GpuError::new(
                    ErrorCode::InvalidRequest,
                    None,
                    "consumer identity must contain 1..128 bytes",
                ));
            }
            let abi = self.versions.negotiate(*versions)?;
            if self.sessions.len() >= self.capabilities.limits.max_sessions as usize {
                return Err(GpuError::new(
                    ErrorCode::LimitExceeded,
                    None,
                    format!(
                        "provider permits {} live sessions",
                        self.capabilities.limits.max_sessions
                    ),
                ));
            }
            let session = Uuid::new_v4().to_string();
            self.sessions.insert(session.clone(), Session::default());
            return Ok(Response::SessionOpened {
                abi,
                session,
                capabilities: self.capabilities.clone(),
            });
        }

        let (session_id, sequence) = request.session_and_sequence().expect("non-hello request");
        let session_id = session_id.to_owned();
        let session = self.sessions.get_mut(&session_id).ok_or_else(|| {
            GpuError::new(
                ErrorCode::InvalidSession,
                Some(sequence),
                "remote GPU session is unknown or closed",
            )
        })?;
        let expected = session.last_sequence.checked_add(1).ok_or_else(|| {
            GpuError::new(
                ErrorCode::InvalidSequence,
                Some(sequence),
                "remote GPU sequence space is exhausted; open a new session",
            )
        })?;
        if sequence != expected {
            return Err(GpuError::new(
                ErrorCode::InvalidSequence,
                Some(sequence),
                format!("remote GPU call sequence {sequence} rejected; expected {expected}"),
            ));
        }
        session.last_sequence = sequence;

        let limits = self.capabilities.limits;
        match request {
            Request::Hello { .. } => unreachable!(),
            Request::Allocate { bytes, .. } => {
                if bytes == 0 || bytes > limits.max_allocation_bytes {
                    return Err(GpuError::new(
                        ErrorCode::LimitExceeded,
                        Some(sequence),
                        format!(
                            "allocation is {bytes} bytes; provider permits 1..{}",
                            limits.max_allocation_bytes
                        ),
                    ));
                }
                if session.allocations.len() >= limits.max_allocations as usize {
                    return Err(GpuError::new(
                        ErrorCode::LimitExceeded,
                        Some(sequence),
                        format!(
                            "provider permits {} live allocations",
                            limits.max_allocations
                        ),
                    ));
                }
                let size = usize::try_from(bytes).map_err(|_| {
                    GpuError::new(
                        ErrorCode::LimitExceeded,
                        Some(sequence),
                        "allocation does not fit this provider's address space",
                    )
                })?;
                let requested = session.allocated_bytes.checked_add(bytes).ok_or_else(|| {
                    GpuError::new(
                        ErrorCode::LimitExceeded,
                        Some(sequence),
                        "session allocation byte count overflows",
                    )
                })?;
                if requested > limits.max_session_bytes {
                    return Err(GpuError::new(
                        ErrorCode::LimitExceeded,
                        Some(sequence),
                        format!(
                            "session would hold {requested} bytes; provider permits {}",
                            limits.max_session_bytes
                        ),
                    ));
                }
                let provider_requested =
                    self.committed_bytes.checked_add(bytes).ok_or_else(|| {
                        GpuError::new(
                            ErrorCode::LimitExceeded,
                            Some(sequence),
                            "provider allocation byte count overflows",
                        )
                    })?;
                if provider_requested > limits.max_provider_bytes {
                    return Err(GpuError::new(
                        ErrorCode::LimitExceeded,
                        Some(sequence),
                        format!(
                            "provider would hold {provider_requested} bytes; it permits {}",
                            limits.max_provider_bytes
                        ),
                    ));
                }
                let allocation = Uuid::new_v4().to_string();
                let mut memory = Vec::new();
                memory.try_reserve_exact(size).map_err(|_| {
                    GpuError::new(
                        ErrorCode::LimitExceeded,
                        Some(sequence),
                        "provider could not reserve the requested allocation",
                    )
                })?;
                memory.resize(size, 0);
                session.allocations.insert(allocation.clone(), memory);
                session.allocated_bytes = requested;
                self.committed_bytes = provider_requested;
                Ok(Response::Allocated {
                    sequence,
                    allocation,
                    bytes,
                })
            }
            Request::Write {
                destination, data, ..
            } => {
                if data.len() as u64 > limits.max_copy_bytes {
                    return Err(GpuError::new(
                        ErrorCode::LimitExceeded,
                        Some(sequence),
                        format!(
                            "copy exceeds provider limit of {} bytes",
                            limits.max_copy_bytes
                        ),
                    ));
                }
                if data.len() as u64 != destination.bytes {
                    return Err(GpuError::new(
                        ErrorCode::InvalidRequest,
                        Some(sequence),
                        format!(
                            "write declared {} bytes but carried {}",
                            destination.bytes,
                            data.len()
                        ),
                    ));
                }
                let memory = allocation_mut(session, &destination, sequence)?;
                let (start, end) = checked_range(&destination, memory.len(), sequence)?;
                memory[start..end].copy_from_slice(&data);
                Ok(Response::Written {
                    sequence,
                    bytes: destination.bytes,
                })
            }
            Request::LoadWorkload {
                descriptor, image, ..
            } => {
                if image.is_empty() || image.len() as u64 > limits.max_workload_bytes {
                    return Err(GpuError::new(
                        ErrorCode::LimitExceeded,
                        Some(sequence),
                        format!(
                            "workload is {} bytes; provider permits 1..{}",
                            image.len(),
                            limits.max_workload_bytes
                        ),
                    ));
                }
                let actual = content_pin(&image);
                if actual != descriptor.content_blake3 {
                    return Err(GpuError::new(
                        ErrorCode::WorkloadMismatch,
                        Some(sequence),
                        format!(
                            "workload content pin mismatch: descriptor says {}, bytes are {actual}",
                            descriptor.content_blake3
                        ),
                    ));
                }
                let known = vector_add_workload();
                if descriptor != known || image != VECTOR_ADD_PTX.as_bytes() {
                    return Err(GpuError::new(
                        ErrorCode::WorkloadMismatch,
                        Some(sequence),
                        "reference provider only admits the checked-in vector-add CUDA PTX",
                    ));
                }
                session.workloads.insert(actual.clone());
                Ok(Response::WorkloadLoaded {
                    sequence,
                    content_blake3: actual,
                })
            }
            Request::LaunchVectorAdd {
                workload_pin,
                lhs,
                rhs,
                output,
                elements,
                ..
            } => {
                if !session.workloads.contains(&workload_pin) {
                    return Err(GpuError::new(
                        ErrorCode::WorkloadMismatch,
                        Some(sequence),
                        "workload pin was not loaded in this session",
                    ));
                }
                let bytes = elements.checked_mul(4).ok_or_else(|| {
                    GpuError::new(
                        ErrorCode::InvalidLaunch,
                        Some(sequence),
                        "vector element count overflows its byte range",
                    )
                })?;
                if bytes > limits.max_launch_bytes {
                    return Err(GpuError::new(
                        ErrorCode::LimitExceeded,
                        Some(sequence),
                        format!(
                            "launch touches {bytes} bytes per vector; provider permits {}",
                            limits.max_launch_bytes
                        ),
                    ));
                }
                if elements == 0
                    || lhs.bytes != bytes
                    || rhs.bytes != bytes
                    || output.bytes != bytes
                {
                    return Err(GpuError::new(
                        ErrorCode::InvalidLaunch,
                        Some(sequence),
                        "vector-add needs three equal non-empty f32 ranges",
                    ));
                }
                let lhs_bytes =
                    copy_fallibly(allocation_slice(session, &lhs, sequence)?, sequence)?;
                let rhs_bytes =
                    copy_fallibly(allocation_slice(session, &rhs, sequence)?, sequence)?;
                let started = Instant::now();
                let result_bytes = usize::try_from(bytes).map_err(|_| {
                    GpuError::new(
                        ErrorCode::LimitExceeded,
                        Some(sequence),
                        "launch does not fit this provider's address space",
                    )
                })?;
                let mut result = Vec::new();
                result.try_reserve_exact(result_bytes).map_err(|_| {
                    GpuError::new(
                        ErrorCode::LimitExceeded,
                        Some(sequence),
                        "provider could not reserve launch result memory",
                    )
                })?;
                for (a, b) in lhs_bytes.chunks_exact(4).zip(rhs_bytes.chunks_exact(4)) {
                    let a = f32::from_le_bytes(a.try_into().expect("four-byte chunk"));
                    let b = f32::from_le_bytes(b.try_into().expect("four-byte chunk"));
                    result.extend_from_slice(&(a + b).to_le_bytes());
                }
                let memory = allocation_mut(session, &output, sequence)?;
                let (start, end) = checked_range(&output, memory.len(), sequence)?;
                memory[start..end].copy_from_slice(&result);
                Ok(Response::Launched {
                    sequence,
                    elements,
                    provider_elapsed_ns: started.elapsed().as_nanos().min(u64::MAX as u128) as u64,
                })
            }
            Request::Read { source, .. } => {
                if source.bytes > limits.max_copy_bytes {
                    return Err(GpuError::new(
                        ErrorCode::LimitExceeded,
                        Some(sequence),
                        format!(
                            "copy exceeds provider limit of {} bytes",
                            limits.max_copy_bytes
                        ),
                    ));
                }
                let data = copy_fallibly(allocation_slice(session, &source, sequence)?, sequence)?;
                Ok(Response::Data { sequence, data })
            }
            Request::Free { allocation, .. } => {
                let memory = session.allocations.remove(&allocation).ok_or_else(|| {
                    GpuError::new(
                        ErrorCode::UnknownAllocation,
                        Some(sequence),
                        "allocation is not owned by this session",
                    )
                })?;
                let released = memory.len() as u64;
                session.allocated_bytes = session.allocated_bytes.saturating_sub(released);
                self.committed_bytes = self.committed_bytes.saturating_sub(released);
                Ok(Response::Freed { sequence })
            }
            Request::Close { .. } => {
                let released = session.allocated_bytes;
                self.sessions.remove(&session_id);
                self.committed_bytes = self.committed_bytes.saturating_sub(released);
                Ok(Response::SessionClosed { sequence })
            }
        }
    }
}

fn allocation_mut<'a>(
    session: &'a mut Session,
    range: &BufferRange,
    sequence: u64,
) -> Result<&'a mut Vec<u8>, GpuError> {
    session
        .allocations
        .get_mut(&range.allocation)
        .ok_or_else(|| {
            GpuError::new(
                ErrorCode::UnknownAllocation,
                Some(sequence),
                "allocation is not owned by this session",
            )
        })
}

fn allocation_slice<'a>(
    session: &'a Session,
    range: &BufferRange,
    sequence: u64,
) -> Result<&'a [u8], GpuError> {
    let memory = session.allocations.get(&range.allocation).ok_or_else(|| {
        GpuError::new(
            ErrorCode::UnknownAllocation,
            Some(sequence),
            "allocation is not owned by this session",
        )
    })?;
    let (start, end) = checked_range(range, memory.len(), sequence)?;
    Ok(&memory[start..end])
}

fn checked_range(
    range: &BufferRange,
    allocation_len: usize,
    sequence: u64,
) -> Result<(usize, usize), GpuError> {
    let end = range.offset.checked_add(range.bytes).ok_or_else(|| {
        GpuError::new(
            ErrorCode::OutOfBounds,
            Some(sequence),
            "memory range offset plus length overflows",
        )
    })?;
    if end > allocation_len as u64 {
        return Err(GpuError::new(
            ErrorCode::OutOfBounds,
            Some(sequence),
            format!(
                "memory range {}..{end} exceeds allocation size {allocation_len}",
                range.offset
            ),
        ));
    }
    Ok((range.offset as usize, end as usize))
}

fn copy_fallibly(bytes: &[u8], sequence: u64) -> Result<Vec<u8>, GpuError> {
    let mut copied = Vec::new();
    copied.try_reserve_exact(bytes.len()).map_err(|_| {
        GpuError::new(
            ErrorCode::LimitExceeded,
            Some(sequence),
            "provider could not reserve response memory",
        )
    })?;
    copied.extend_from_slice(bytes);
    Ok(copied)
}

mod base64 {
    use super::*;

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

    struct Consumer {
        provider: Provider,
        session: String,
        sequence: u64,
    }

    impl Consumer {
        fn new() -> Self {
            let mut provider = Provider::reference("provider-test");
            let response = provider
                .handle(Request::Hello {
                    versions: AbiRange::ours(),
                    consumer: "consumer-test".into(),
                })
                .into_result()
                .unwrap();
            let Response::SessionOpened { session, .. } = response else {
                panic!("hello opens a session")
            };
            Self {
                provider,
                session,
                sequence: 0,
            }
        }

        fn call(
            &mut self,
            make: impl FnOnce(String, u64) -> Request,
        ) -> Result<Response, GpuError> {
            self.sequence += 1;
            self.provider
                .handle(make(self.session.clone(), self.sequence))
                .into_result()
        }

        fn allocate(&mut self, bytes: u64) -> String {
            let response = self
                .call(|session, sequence| Request::Allocate {
                    session,
                    sequence,
                    bytes,
                })
                .unwrap();
            let Response::Allocated { allocation, .. } = response else {
                panic!("allocate returns an allocation")
            };
            allocation
        }
    }

    fn range(allocation: &str, offset: u64, bytes: u64) -> BufferRange {
        BufferRange {
            allocation: allocation.into(),
            offset,
            bytes,
        }
    }

    #[test]
    fn version_ranges_choose_the_newest_overlap_and_refuse_a_gap() {
        assert_eq!(
            AbiRange { min: 1, max: 3 }
                .negotiate(AbiRange { min: 2, max: 4 })
                .unwrap(),
            3
        );
        let err = AbiRange { min: 3, max: 4 }
            .negotiate(AbiRange { min: 1, max: 2 })
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::UnsupportedVersion);
        assert!(AbiRange { min: 0, max: 1 }
            .negotiate(AbiRange::ours())
            .is_err());
    }

    #[test]
    fn replay_and_gaps_are_rejected_without_moving_the_sequence() {
        let mut consumer = Consumer::new();
        consumer.allocate(16);

        let replay = consumer.provider.handle(Request::Allocate {
            session: consumer.session.clone(),
            sequence: 1,
            bytes: 16,
        });
        let Reply::Error { error } = replay else {
            panic!("replay must fail")
        };
        assert_eq!(error.code, ErrorCode::InvalidSequence);

        let gap = consumer.provider.handle(Request::Allocate {
            session: consumer.session.clone(),
            sequence: 3,
            bytes: 16,
        });
        let Reply::Error { error } = gap else {
            panic!("gap must fail")
        };
        assert_eq!(error.code, ErrorCode::InvalidSequence);

        consumer.allocate(16);
    }

    #[test]
    fn an_out_of_bounds_call_is_refused_and_still_consumes_its_sequence() {
        let mut consumer = Consumer::new();
        let allocation = consumer.allocate(8);
        let err = consumer
            .call(|session, sequence| Request::Write {
                session,
                sequence,
                destination: range(&allocation, 6, 4),
                data: vec![1, 2, 3, 4],
            })
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::OutOfBounds);

        // Sequence three succeeds. Reinterpreting sequence two is impossible.
        let read = consumer
            .call(|session, sequence| Request::Read {
                session,
                sequence,
                source: range(&allocation, 0, 8),
            })
            .unwrap();
        assert!(matches!(read, Response::Data { data, .. } if data == vec![0; 8]));
    }

    #[test]
    fn workload_bytes_must_match_the_declared_and_known_pin() {
        let mut consumer = Consumer::new();
        let mut descriptor = vector_add_workload();
        descriptor.content_blake3 = content_pin(b"forged");
        let err = consumer
            .call(|session, sequence| Request::LoadWorkload {
                session,
                sequence,
                descriptor,
                image: VECTOR_ADD_PTX.as_bytes().to_vec(),
            })
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::WorkloadMismatch);
    }

    #[test]
    fn aggregate_session_and_session_count_limits_are_enforced() {
        let limits = Limits {
            max_allocation_bytes: 8,
            max_session_bytes: 12,
            max_provider_bytes: 16,
            max_copy_bytes: 8,
            max_launch_bytes: 8,
            max_allocations: 4,
            max_workload_bytes: 1024,
            max_sessions: 2,
        };
        let mut provider = Provider::reference_with_limits("small", limits);
        let Response::SessionOpened { session, .. } = provider
            .handle(Request::Hello {
                versions: AbiRange::ours(),
                consumer: "first".into(),
            })
            .into_result()
            .unwrap()
        else {
            panic!("hello opens a session")
        };
        let Response::SessionOpened {
            session: second, ..
        } = provider
            .handle(Request::Hello {
                versions: AbiRange::ours(),
                consumer: "second".into(),
            })
            .into_result()
            .unwrap()
        else {
            panic!("second hello opens a session")
        };
        let another = provider.handle(Request::Hello {
            versions: AbiRange::ours(),
            consumer: "third".into(),
        });
        let Reply::Error { error } = another else {
            panic!("second session must hit the cap")
        };
        assert_eq!(error.code, ErrorCode::LimitExceeded);

        let first_allocation = provider
            .handle(Request::Allocate {
                session: session.clone(),
                sequence: 1,
                bytes: 8,
            })
            .into_result()
            .unwrap();
        let Response::Allocated {
            allocation: first_allocation,
            ..
        } = first_allocation
        else {
            panic!("allocate returns an ID")
        };
        provider
            .handle(Request::Allocate {
                session: second.clone(),
                sequence: 1,
                bytes: 8,
            })
            .into_result()
            .unwrap();
        let aggregate = provider.handle(Request::Allocate {
            session: session.clone(),
            sequence: 2,
            bytes: 8,
        });
        let Reply::Error { error } = aggregate else {
            panic!("aggregate bytes must hit the cap")
        };
        assert_eq!(error.code, ErrorCode::LimitExceeded);

        let provider_total = provider.handle(Request::Allocate {
            session: second.clone(),
            sequence: 2,
            bytes: 1,
        });
        let Reply::Error { error } = provider_total else {
            panic!("provider bytes must hit the cap")
        };
        assert_eq!(error.code, ErrorCode::LimitExceeded);

        // Both refusals consumed sequence two. Releasing the first session's
        // bytes lets the second grow, and closing the second returns its
        // session slot. The limits are live accounting, not lifetime totals.
        provider
            .handle(Request::Free {
                session: session.clone(),
                sequence: 3,
                allocation: first_allocation,
            })
            .into_result()
            .unwrap();
        provider
            .handle(Request::Allocate {
                session: second.clone(),
                sequence: 3,
                bytes: 1,
            })
            .into_result()
            .unwrap();
        provider
            .handle(Request::Close {
                session: second,
                sequence: 4,
            })
            .into_result()
            .unwrap();
        assert!(matches!(
            provider
                .handle(Request::Hello {
                    versions: AbiRange::ours(),
                    consumer: "replacement".into(),
                })
                .into_result(),
            Ok(Response::SessionOpened { .. })
        ));
    }

    #[test]
    fn the_pinned_cuda_semantics_round_trip_memory() {
        let mut consumer = Consumer::new();
        let lhs = consumer.allocate(12);
        let rhs = consumer.allocate(12);
        let output = consumer.allocate(12);

        let encode = |values: &[f32]| {
            values
                .iter()
                .flat_map(|value| value.to_le_bytes())
                .collect::<Vec<_>>()
        };
        for (allocation, data) in [
            (&lhs, encode(&[1.0, 2.5, -4.0])),
            (&rhs, encode(&[5.0, -0.5, 10.0])),
        ] {
            consumer
                .call(|session, sequence| Request::Write {
                    session,
                    sequence,
                    destination: range(allocation, 0, 12),
                    data,
                })
                .unwrap();
        }
        let descriptor = vector_add_workload();
        let pin = descriptor.content_blake3.clone();
        consumer
            .call(|session, sequence| Request::LoadWorkload {
                session,
                sequence,
                descriptor,
                image: VECTOR_ADD_PTX.as_bytes().to_vec(),
            })
            .unwrap();
        consumer
            .call(|session, sequence| Request::LaunchVectorAdd {
                session,
                sequence,
                workload_pin: pin,
                lhs: range(&lhs, 0, 12),
                rhs: range(&rhs, 0, 12),
                output: range(&output, 0, 12),
                elements: 3,
            })
            .unwrap();
        let response = consumer
            .call(|session, sequence| Request::Read {
                session,
                sequence,
                source: range(&output, 0, 12),
            })
            .unwrap();
        let Response::Data { data, .. } = response else {
            panic!("read returns data")
        };
        let values = data
            .chunks_exact(4)
            .map(|bytes| f32::from_le_bytes(bytes.try_into().unwrap()))
            .collect::<Vec<_>>();
        assert_eq!(values, vec![6.0, 2.0, 6.0]);
    }

    #[test]
    fn a_session_cannot_name_another_sessions_allocation() {
        let mut first = Consumer::new();
        let allocation = first.allocate(16);
        let Response::SessionOpened {
            session: second, ..
        } = first
            .provider
            .handle(Request::Hello {
                versions: AbiRange::ours(),
                consumer: "second".into(),
            })
            .into_result()
            .unwrap()
        else {
            panic!("hello opens a session")
        };
        let reply = first.provider.handle(Request::Read {
            session: second,
            sequence: 1,
            source: range(&allocation, 0, 4),
        });
        let Reply::Error { error } = reply else {
            panic!("cross-session read must fail")
        };
        assert_eq!(error.code, ErrorCode::UnknownAllocation);
    }

    #[test]
    fn byte_payloads_are_base64_and_the_frame_has_a_known_version() {
        let request = Request::Write {
            session: "s".into(),
            sequence: 7,
            destination: range("a", 0, 4),
            data: vec![0, 1, 2, 255],
        };
        let wire = serde_json::to_string(&request).unwrap();
        assert!(wire.contains(r#""data":"AAEC/w==""#), "{wire}");
        assert_eq!(ABI_VERSION, 1);
    }

    #[test]
    fn maximum_copy_frames_fit_the_advertised_wire_ceiling() {
        let bytes = Limits::default().max_copy_bytes as usize;
        let request = Request::Write {
            session: Uuid::new_v4().to_string(),
            sequence: 1,
            destination: range("allocation", 0, bytes as u64),
            data: vec![0; bytes],
        };
        let reply = Reply::Ok {
            response: Response::Data {
                sequence: 1,
                data: vec![0; bytes],
            },
        };
        assert!(serde_json::to_vec(&request).unwrap().len() <= MAX_WIRE_FRAME_BYTES);
        assert!(serde_json::to_vec(&reply).unwrap().len() <= MAX_WIRE_FRAME_BYTES);
    }
}
