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
/// The stable path promised to software inside an attached Linux guest.
pub const GUEST_DEVICE_PATH: &str = "/dev/nvidia0";
/// Revocation tombstones improve diagnostics but carry no authority. Bounding
/// them keeps an attach/revoke workload from becoming an unbounded memory
/// sink; an evicted token is still refused as unknown.
const MAX_REVOKED_TOMBSTONES: usize = 4_096;

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
    pub(crate) fn session_and_sequence(&self) -> Option<(&str, u64)> {
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

// ---- production control plane ---------------------------------------------

/// Provider health is an admission decision, not decoration. Only `ready`
/// providers receive new leases or execute calls from existing ones.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum ProviderHealth {
    Ready,
    Draining { reason: String },
    Unhealthy { reason: String },
    Offline { reason: String },
}

impl ProviderHealth {
    pub fn is_ready(&self) -> bool {
        matches!(self, Self::Ready)
    }

    fn description(&self) -> &str {
        match self {
            Self::Ready => "ready",
            Self::Draining { reason } | Self::Unhealthy { reason } | Self::Offline { reason } => {
                reason
            }
        }
    }
}

/// The observed mesh path to a provider. An unreachable provider is retained
/// in diagnostics, but cannot win placement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ProviderRoute {
    Direct { rtt_us: u64 },
    Relay { rtt_us: u64 },
    Unreachable,
}

impl ProviderRoute {
    fn placement_key(self) -> Option<(u8, u64)> {
        match self {
            Self::Direct { rtt_us } => Some((0, rtt_us)),
            Self::Relay { rtt_us } => Some((1, rtt_us)),
            Self::Unreachable => None,
        }
    }
}

/// One GPU advertised by an authenticated orbit device.
///
/// `device_id` is the stable mesh public identity. `device_name` is only the
/// human label and never authorizes a session. Live usage is included so a
/// planner can refuse before asking a provider to mutate its budget.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderAdvertisement {
    pub device_id: String,
    pub device_name: String,
    pub gpu_uuid: String,
    pub device_name_cuda: String,
    pub executor: Executor,
    pub versions: AbiRange,
    pub total_memory_bytes: u64,
    pub leased_memory_bytes: u64,
    pub max_leases: u32,
    pub active_leases: u32,
    pub generation: u64,
    pub health: ProviderHealth,
    pub route: ProviderRoute,
    pub observed_at: u64,
}

/// Constraints for attaching a GPU part. `provider_device` is an explicit
/// override by orbit device name; without it the deterministic cheapest
/// eligible provider wins.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlacementRequest<'a> {
    pub memory_bytes: u64,
    pub provider_device: Option<&'a str>,
    pub require_cuda: bool,
}

/// The selected provider and the reason surfaced by status/GUI.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Placement {
    pub provider: ProviderAdvertisement,
    pub reason: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlErrorCode {
    InvalidRequest,
    Unavailable,
    LimitExceeded,
    Unauthorized,
    InvalidLease,
    Revoked,
    StaleGeneration,
    Conflict,
    UnsupportedVersion,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControlError {
    pub code: ControlErrorCode,
    pub message: String,
}

impl ControlError {
    pub(crate) fn new(code: ControlErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

impl std::fmt::Display for ControlError {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        out.write_str(&self.message)
    }
}

impl std::error::Error for ControlError {}

/// Select a provider without changing any provider or instance state.
///
/// Ranking is stable across callers: direct before relay, lower observed RTT,
/// lower lease pressure, then stable device identity and GPU UUID. An explicit
/// device remains an override, but never an override of health or quota.
pub fn place_provider(
    candidates: &[ProviderAdvertisement],
    request: PlacementRequest<'_>,
) -> Result<Placement, ControlError> {
    if request.memory_bytes == 0 {
        return Err(ControlError::new(
            ControlErrorCode::InvalidRequest,
            "a GPU attachment must reserve at least one byte",
        ));
    }

    let named = |candidate: &&ProviderAdvertisement| {
        request
            .provider_device
            .map(|name| candidate.device_name == name)
            .unwrap_or(true)
    };
    let matching = candidates.iter().filter(named).collect::<Vec<_>>();
    if matching.is_empty() {
        return Err(ControlError::new(
            ControlErrorCode::Unavailable,
            match request.provider_device {
                Some(name) => format!(
                    "device {name:?} advertises no GPU — see GPU diagnostics for orbit providers"
                ),
                None => "no device in this orbit advertises a GPU".to_owned(),
            },
        ));
    }

    let mut eligible = Vec::new();
    let mut refusals = Vec::new();
    for candidate in matching {
        let available = candidate
            .total_memory_bytes
            .saturating_sub(candidate.leased_memory_bytes);
        let refusal = if !candidate.health.is_ready() {
            Some(format!(
                "{} is not ready: {}",
                candidate.device_name,
                candidate.health.description()
            ))
        } else if candidate.route.placement_key().is_none() {
            Some(format!("{} is unreachable", candidate.device_name))
        } else if request.require_cuda && candidate.executor != Executor::Cuda {
            Some(format!(
                "{} offers the reference executor, not CUDA",
                candidate.device_name
            ))
        } else if candidate.active_leases >= candidate.max_leases {
            Some(format!(
                "{} has all {} GPU lease slots in use",
                candidate.device_name, candidate.max_leases
            ))
        } else if available < request.memory_bytes {
            Some(format!(
                "{} has {available} GPU bytes available; {} requested",
                candidate.device_name, request.memory_bytes
            ))
        } else {
            None
        };
        match refusal {
            Some(refusal) => refusals.push(refusal),
            None => eligible.push(candidate),
        }
    }

    eligible.sort_by_key(|candidate| {
        let route = candidate.route.placement_key().expect("eligible route");
        let pressure = u64::from(candidate.active_leases).saturating_mul(1_000_000)
            / u64::from(candidate.max_leases.max(1));
        (
            route.0,
            route.1,
            pressure,
            candidate.device_id.as_str(),
            candidate.gpu_uuid.as_str(),
        )
    });
    let provider = eligible.first().copied().ok_or_else(|| {
        ControlError::new(
            ControlErrorCode::Unavailable,
            format!(
                "no GPU provider can satisfy the attachment: {}",
                refusals.join("; ")
            ),
        )
    })?;
    let reason = match provider.route {
        ProviderRoute::Direct { rtt_us } => format!("direct mesh path · {rtt_us} us observed RTT"),
        ProviderRoute::Relay { rtt_us } => format!("relay mesh path · {rtt_us} us observed RTT"),
        ProviderRoute::Unreachable => unreachable!("unreachable providers are not eligible"),
    };
    Ok(Placement {
        provider: provider.clone(),
        reason,
    })
}

/// A mesh identity already authenticated by the transport.
///
/// This type does not perform the cryptographic handshake. Its constructor is
/// the narrow adapter seam used *after* the mesh has authenticated the peer;
/// the control plane then binds every lease and call to this exact key rather
/// than accepting a diagnostic device name from a GPU frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedPeer {
    device_id: String,
}

impl AuthenticatedPeer {
    pub fn from_mesh_identity(device_id: impl Into<String>) -> Result<Self, ControlError> {
        let device_id = device_id.into();
        if device_id.len() != 64 || !device_id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(ControlError::new(
                ControlErrorCode::InvalidRequest,
                "an authenticated GPU peer identity must be a 32-byte public key in hex",
            ));
        }
        Ok(Self {
            device_id: device_id.to_ascii_lowercase(),
        })
    }

    pub fn device_id(&self) -> &str {
        &self.device_id
    }
}

/// Provider-enforced production lease limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeaseLimits {
    pub total_memory_bytes: u64,
    pub max_memory_per_lease: u64,
    pub max_leases: u32,
    pub lease_ttl_secs: u64,
}

impl Default for LeaseLimits {
    fn default() -> Self {
        Self {
            total_memory_bytes: 16 * 1024 * 1024 * 1024,
            max_memory_per_lease: 8 * 1024 * 1024 * 1024,
            max_leases: 8,
            lease_ttl_secs: 30,
        }
    }
}

/// A live bearer capability. It belongs in memory in the mesh/GPU adapter;
/// [`GpuAttachment`] is the token-free durable instance record.
#[derive(Clone, PartialEq, Eq)]
pub struct GpuLease {
    capability: String,
    pub consumer_device_id: String,
    pub instance_id: String,
    pub memory_bytes: u64,
    pub provider_generation: u64,
    pub expires_at: u64,
}

impl std::fmt::Debug for GpuLease {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        out.debug_struct("GpuLease")
            .field("capability", &"<redacted>")
            .field("consumer_device_id", &self.consumer_device_id)
            .field("instance_id", &self.instance_id)
            .field("memory_bytes", &self.memory_bytes)
            .field("provider_generation", &self.provider_generation)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

impl GpuLease {
    pub fn capability(&self) -> &str {
        &self.capability
    }
}

/// Token-free attachment metadata safe to persist in an instance registry and
/// expose through CLI/GUI diagnostics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GpuAttachment {
    pub provider_device: String,
    pub provider_device_id: String,
    pub provider_gpu_uuid: String,
    pub memory_bytes: u64,
    pub provider_generation: u64,
    pub attached_at: u64,
}

impl GpuAttachment {
    pub fn guest_path(&self) -> &'static str {
        GUEST_DEVICE_PATH
    }

    /// How `/dev/nvidia0` is materialized. Status still prints the path, but
    /// the path is a projected local endpoint, not this record itself.
    pub fn projection_kind(&self) -> &'static str {
        crate::remote_gpu_guest::PROJECTION_KIND
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderDiagnostics {
    pub provider_device: String,
    pub provider_device_id: String,
    pub gpu_uuid: String,
    pub generation: u64,
    pub health: ProviderHealth,
    pub active_leases: u32,
    pub leased_memory_bytes: u64,
    pub total_memory_bytes: u64,
    pub revoked_capabilities: u64,
}

/// Provider-side authority for attachment, revocation, quota and restart
/// fencing. The authenticated mesh owns transport; this owns capability state.
#[derive(Debug)]
pub struct LeaseAuthority {
    provider_device: String,
    provider_device_id: String,
    gpu_uuid: String,
    generation: u64,
    limits: LeaseLimits,
    health: ProviderHealth,
    leased_memory_bytes: u64,
    leases: HashMap<String, GpuLease>,
    instances: HashMap<String, String>,
    revoked: HashSet<String>,
}

impl LeaseAuthority {
    pub fn new(
        provider_device: impl Into<String>,
        provider_device_id: impl Into<String>,
        gpu_uuid: impl Into<String>,
        generation: u64,
        limits: LeaseLimits,
    ) -> Result<Self, ControlError> {
        let provider_device = provider_device.into();
        let provider_device_id = provider_device_id.into();
        let gpu_uuid = gpu_uuid.into();
        if provider_device.trim().is_empty() || gpu_uuid.trim().is_empty() || generation == 0 {
            return Err(ControlError::new(
                ControlErrorCode::InvalidRequest,
                "GPU provider name, GPU UUID and non-zero generation are required",
            ));
        }
        AuthenticatedPeer::from_mesh_identity(provider_device_id.clone())?;
        if limits.total_memory_bytes == 0
            || limits.max_memory_per_lease == 0
            || limits.max_memory_per_lease > limits.total_memory_bytes
            || limits.max_leases == 0
            || limits.lease_ttl_secs == 0
        {
            return Err(ControlError::new(
                ControlErrorCode::InvalidRequest,
                "GPU lease limits must be non-zero and per-lease memory cannot exceed total memory",
            ));
        }
        Ok(Self {
            provider_device,
            provider_device_id: provider_device_id.to_ascii_lowercase(),
            gpu_uuid,
            generation,
            limits,
            health: ProviderHealth::Ready,
            leased_memory_bytes: 0,
            leases: HashMap::new(),
            instances: HashMap::new(),
            revoked: HashSet::new(),
        })
    }

    /// Validate the full request, then make one atomic in-memory mutation.
    pub fn attach(
        &mut self,
        peer: &AuthenticatedPeer,
        instance_id: &str,
        memory_bytes: u64,
        now: u64,
    ) -> Result<(GpuLease, GpuAttachment), ControlError> {
        if !self.health.is_ready() {
            return Err(ControlError::new(
                ControlErrorCode::Unavailable,
                format!("GPU provider is not ready: {}", self.health.description()),
            ));
        }
        if instance_id.trim().is_empty() || instance_id.len() > 128 {
            return Err(ControlError::new(
                ControlErrorCode::InvalidRequest,
                "orbit-global instance identity must contain 1..128 bytes",
            ));
        }
        if memory_bytes == 0 || memory_bytes > self.limits.max_memory_per_lease {
            return Err(ControlError::new(
                ControlErrorCode::LimitExceeded,
                format!(
                    "GPU lease requests {memory_bytes} bytes; provider permits 1..{} per lease",
                    self.limits.max_memory_per_lease
                ),
            ));
        }
        if self.instances.contains_key(instance_id) {
            return Err(ControlError::new(
                ControlErrorCode::Conflict,
                format!("instance {instance_id:?} already holds a GPU lease on this provider"),
            ));
        }
        if self.leases.len() >= self.limits.max_leases as usize {
            return Err(ControlError::new(
                ControlErrorCode::LimitExceeded,
                format!(
                    "provider permits {} live GPU leases",
                    self.limits.max_leases
                ),
            ));
        }
        let committed = self
            .leased_memory_bytes
            .checked_add(memory_bytes)
            .filter(|bytes| *bytes <= self.limits.total_memory_bytes)
            .ok_or_else(|| {
                ControlError::new(
                    ControlErrorCode::LimitExceeded,
                    format!(
                        "GPU provider has {} bytes free; {memory_bytes} requested",
                        self.limits
                            .total_memory_bytes
                            .saturating_sub(self.leased_memory_bytes)
                    ),
                )
            })?;
        let expires_at = now.checked_add(self.limits.lease_ttl_secs).ok_or_else(|| {
            ControlError::new(
                ControlErrorCode::InvalidRequest,
                "GPU lease expiry overflows the provider clock",
            )
        })?;

        let capability = Uuid::new_v4().to_string();
        let lease = GpuLease {
            capability: capability.clone(),
            consumer_device_id: peer.device_id.clone(),
            instance_id: instance_id.to_owned(),
            memory_bytes,
            provider_generation: self.generation,
            expires_at,
        };
        let attachment = GpuAttachment {
            provider_device: self.provider_device.clone(),
            provider_device_id: self.provider_device_id.clone(),
            provider_gpu_uuid: self.gpu_uuid.clone(),
            memory_bytes,
            provider_generation: self.generation,
            attached_at: now,
        };
        self.leases.insert(capability.clone(), lease.clone());
        self.instances.insert(instance_id.to_owned(), capability);
        self.leased_memory_bytes = committed;
        Ok((lease, attachment))
    }

    /// Authorize one ABI call. Names and session payloads have no authority;
    /// the live bearer must still be bound to this authenticated peer and the
    /// current provider generation.
    pub fn authorize(
        &self,
        peer: &AuthenticatedPeer,
        capability: &str,
        now: u64,
    ) -> Result<&GpuLease, ControlError> {
        if self.revoked.contains(capability) {
            return Err(ControlError::new(
                ControlErrorCode::Revoked,
                "GPU lease was revoked",
            ));
        }
        let lease = self.leases.get(capability).ok_or_else(|| {
            ControlError::new(ControlErrorCode::InvalidLease, "GPU lease is unknown")
        })?;
        if lease.consumer_device_id != peer.device_id {
            return Err(ControlError::new(
                ControlErrorCode::Unauthorized,
                "GPU lease belongs to another authenticated orbit device",
            ));
        }
        if lease.provider_generation != self.generation {
            return Err(ControlError::new(
                ControlErrorCode::StaleGeneration,
                "GPU lease belongs to an earlier provider generation",
            ));
        }
        if now > lease.expires_at {
            return Err(ControlError::new(
                ControlErrorCode::Revoked,
                "GPU lease expired",
            ));
        }
        if !self.health.is_ready() {
            return Err(ControlError::new(
                ControlErrorCode::Unavailable,
                format!("GPU provider is not ready: {}", self.health.description()),
            ));
        }
        Ok(lease)
    }

    /// Authorize by the instance identity that crossed the mesh, never by a
    /// bearer capability in the opening frame. The live token stays in this
    /// process's memory.
    pub fn authorize_instance(
        &self,
        peer: &AuthenticatedPeer,
        instance_id: &str,
        generation: u64,
        now: u64,
    ) -> Result<&GpuLease, ControlError> {
        if generation != self.generation {
            return Err(ControlError::new(
                ControlErrorCode::StaleGeneration,
                format!(
                    "GPU attachment named provider generation {generation}; provider is at {}",
                    self.generation
                ),
            ));
        }
        let capability = self.instances.get(instance_id).ok_or_else(|| {
            ControlError::new(
                ControlErrorCode::InvalidLease,
                "instance has no live GPU lease on this provider",
            )
        })?;
        self.authorize(peer, capability, now)
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn renew(
        &mut self,
        peer: &AuthenticatedPeer,
        capability: &str,
        now: u64,
    ) -> Result<u64, ControlError> {
        self.authorize(peer, capability, now)?;
        let expires_at = now.checked_add(self.limits.lease_ttl_secs).ok_or_else(|| {
            ControlError::new(
                ControlErrorCode::InvalidRequest,
                "GPU lease expiry overflows the provider clock",
            )
        })?;
        self.leases
            .get_mut(capability)
            .expect("authorize established the lease")
            .expires_at = expires_at;
        Ok(expires_at)
    }

    pub fn revoke_instance(&mut self, instance_id: &str) -> bool {
        let Some(capability) = self.instances.remove(instance_id) else {
            return false;
        };
        if let Some(lease) = self.leases.remove(&capability) {
            self.leased_memory_bytes = self.leased_memory_bytes.saturating_sub(lease.memory_bytes);
        }
        self.remember_revoked(capability);
        true
    }

    /// Removing a device from the orbit cuts every lease authenticated as
    /// that identity before another GPU frame from it can be served.
    pub fn revoke_peer(&mut self, device_id: &str) -> u32 {
        let capabilities = self
            .leases
            .iter()
            .filter(|(_, lease)| lease.consumer_device_id == device_id)
            .map(|(capability, _)| capability.clone())
            .collect::<Vec<_>>();
        for capability in &capabilities {
            if let Some(lease) = self.leases.remove(capability) {
                self.instances.remove(&lease.instance_id);
                self.leased_memory_bytes =
                    self.leased_memory_bytes.saturating_sub(lease.memory_bytes);
                self.remember_revoked(capability.clone());
            }
        }
        capabilities.len().min(u32::MAX as usize) as u32
    }

    /// Fence every live capability on provider loss/restart. Recovery starts
    /// empty at a new generation; consumers must reattach from their durable,
    /// token-free [`GpuAttachment`] records.
    pub fn provider_lost(&mut self, reason: impl Into<String>) -> u32 {
        let count = self.leases.len().min(u32::MAX as usize) as u32;
        for capability in self.leases.keys().cloned().collect::<Vec<_>>() {
            self.remember_revoked(capability);
        }
        self.leases.clear();
        self.instances.clear();
        self.leased_memory_bytes = 0;
        self.generation = self.generation.saturating_add(1).max(1);
        self.health = ProviderHealth::Offline {
            reason: reason.into(),
        };
        count
    }

    /// Release expired leases. The caller drives this from its bounded health
    /// loop; request validation itself never performs surprise cleanup.
    pub fn reap_expired(&mut self, now: u64) -> u32 {
        let expired = self
            .leases
            .iter()
            .filter(|(_, lease)| now > lease.expires_at)
            .map(|(capability, _)| capability.clone())
            .collect::<Vec<_>>();
        for capability in &expired {
            if let Some(lease) = self.leases.remove(capability) {
                self.instances.remove(&lease.instance_id);
                self.leased_memory_bytes =
                    self.leased_memory_bytes.saturating_sub(lease.memory_bytes);
                self.remember_revoked(capability.clone());
            }
        }
        expired.len().min(u32::MAX as usize) as u32
    }

    pub fn recover(&mut self) -> Result<u64, ControlError> {
        if !matches!(self.health, ProviderHealth::Offline { .. }) {
            return Err(ControlError::new(
                ControlErrorCode::Conflict,
                "only an offline GPU provider can enter recovery",
            ));
        }
        self.health = ProviderHealth::Ready;
        Ok(self.generation)
    }

    pub fn set_health(&mut self, health: ProviderHealth) {
        self.health = health;
    }

    pub fn diagnostics(&self) -> ProviderDiagnostics {
        ProviderDiagnostics {
            provider_device: self.provider_device.clone(),
            provider_device_id: self.provider_device_id.clone(),
            gpu_uuid: self.gpu_uuid.clone(),
            generation: self.generation,
            health: self.health.clone(),
            active_leases: self.leases.len().min(u32::MAX as usize) as u32,
            leased_memory_bytes: self.leased_memory_bytes,
            total_memory_bytes: self.limits.total_memory_bytes,
            revoked_capabilities: self.revoked.len().min(u64::MAX as usize) as u64,
        }
    }

    fn remember_revoked(&mut self, capability: String) {
        if self.revoked.len() >= MAX_REVOKED_TOMBSTONES {
            if let Some(oldest_available) = self.revoked.iter().next().cloned() {
                self.revoked.remove(&oldest_available);
            }
        }
        self.revoked.insert(capability);
    }
}

#[derive(Debug, Clone)]
struct SessionBinding {
    capability: String,
    consumer_device_id: String,
}

/// The production adapter between authenticated mesh streams, lease policy,
/// and the versioned GPU ABI state machine.
///
/// Callers cannot reach [`Provider::handle`] through this type without first
/// passing identity/capability authorization. That ordering is the security
/// property: a refused call cannot consume an ABI sequence, allocate bytes,
/// or launch work. Revocation closes the ABI session and releases its memory,
/// rather than merely making the next control-plane renewal fail.
#[derive(Debug)]
pub struct ProductionProvider {
    authority: LeaseAuthority,
    abi: Provider,
    sessions: HashMap<String, SessionBinding>,
}

impl ProductionProvider {
    pub fn new(authority: LeaseAuthority, abi: Provider) -> Self {
        Self {
            authority,
            abi,
            sessions: HashMap::new(),
        }
    }

    pub fn authority(&self) -> &LeaseAuthority {
        &self.authority
    }

    pub fn authority_mut(&mut self) -> &mut LeaseAuthority {
        &mut self.authority
    }

    /// Negotiate one ABI session for one live lease. A lease owns at most one
    /// provider session, keeping its memory/session quota a real upper bound.
    pub fn open_session(
        &mut self,
        peer: &AuthenticatedPeer,
        capability: &str,
        versions: AbiRange,
        now: u64,
    ) -> Result<Response, ControlError> {
        let lease = self.authority.authorize(peer, capability, now)?;
        if self
            .sessions
            .values()
            .any(|binding| binding.capability == capability)
        {
            return Err(ControlError::new(
                ControlErrorCode::Conflict,
                "GPU lease already has an open ABI session",
            ));
        }
        let consumer = lease.instance_id.clone();
        let response = self
            .abi
            .handle(Request::Hello { versions, consumer })
            .into_result()
            .map_err(|error| {
                let code = match error.code {
                    ErrorCode::UnsupportedVersion => ControlErrorCode::UnsupportedVersion,
                    _ => ControlErrorCode::Unavailable,
                };
                ControlError::new(code, error.message)
            })?;
        let Response::SessionOpened { session, .. } = &response else {
            unreachable!("hello has one success response")
        };
        self.sessions.insert(
            session.clone(),
            SessionBinding {
                capability: capability.to_owned(),
                consumer_device_id: peer.device_id.clone(),
            },
        );
        Ok(response)
    }

    /// Apply one post-handshake ABI request after control-plane authorization.
    pub fn handle(
        &mut self,
        peer: &AuthenticatedPeer,
        capability: &str,
        request: Request,
        now: u64,
    ) -> Result<Reply, ControlError> {
        let (session, _) = request.session_and_sequence().ok_or_else(|| {
            ControlError::new(
                ControlErrorCode::InvalidRequest,
                "open GPU sessions with ProductionProvider::open_session",
            )
        })?;
        let session = session.to_owned();
        let binding = self.sessions.get(&session).ok_or_else(|| {
            ControlError::new(
                ControlErrorCode::InvalidLease,
                "GPU ABI session is unknown or revoked",
            )
        })?;
        if binding.capability != capability || binding.consumer_device_id != peer.device_id {
            return Err(ControlError::new(
                ControlErrorCode::Unauthorized,
                "GPU ABI session belongs to another authenticated lease",
            ));
        }
        self.authority.authorize(peer, capability, now)?;
        let closes = matches!(request, Request::Close { .. });
        let reply = self.abi.handle(request);
        if closes
            && matches!(
                reply,
                Reply::Ok {
                    response: Response::SessionClosed { .. }
                }
            )
        {
            self.sessions.remove(&session);
        }
        Ok(reply)
    }

    /// Open an ABI session from an instance-bound mesh stream. The opening
    /// frame names the instance and generation; the bearer never leaves this
    /// provider process.
    pub fn open_session_for_instance(
        &mut self,
        peer: &AuthenticatedPeer,
        instance_id: &str,
        generation: u64,
        versions: AbiRange,
        now: u64,
    ) -> Result<Response, ControlError> {
        let capability = self
            .authority
            .authorize_instance(peer, instance_id, generation, now)?
            .capability()
            .to_owned();
        self.open_session(peer, &capability, versions, now)
    }

    /// Apply one ABI request authorized by instance identity rather than a
    /// capability that arrived on the wire.
    pub fn handle_for_instance(
        &mut self,
        peer: &AuthenticatedPeer,
        instance_id: &str,
        generation: u64,
        request: Request,
        now: u64,
    ) -> Result<Reply, ControlError> {
        let capability = self
            .authority
            .authorize_instance(peer, instance_id, generation, now)?
            .capability()
            .to_owned();
        self.handle(peer, &capability, request, now)
    }

    pub fn revoke_instance(&mut self, instance_id: &str) -> bool {
        let capability = self.authority.instances.get(instance_id).cloned();
        let revoked = self.authority.revoke_instance(instance_id);
        if let Some(capability) = capability {
            self.revoke_abi_capability(&capability);
        }
        revoked
    }

    pub fn revoke_peer(&mut self, device_id: &str) -> u32 {
        let capabilities = self
            .authority
            .leases
            .iter()
            .filter(|(_, lease)| lease.consumer_device_id == device_id)
            .map(|(capability, _)| capability.clone())
            .collect::<Vec<_>>();
        let revoked = self.authority.revoke_peer(device_id);
        for capability in capabilities {
            self.revoke_abi_capability(&capability);
        }
        revoked
    }

    pub fn provider_lost(&mut self, reason: impl Into<String>) -> u32 {
        let revoked = self.authority.provider_lost(reason);
        self.sessions.clear();
        self.abi.revoke_all_sessions();
        revoked
    }

    /// A guest process restart drops the in-memory ABI session while the
    /// durable, token-free attachment and live lease remain. The restarted
    /// guest may open a new session on the same capability; an old session
    /// ID cannot be reused and cannot keep provider memory reserved.
    pub fn guest_lost(&mut self, instance_id: &str) -> bool {
        let Some(capability) = self.authority.instances.get(instance_id).cloned() else {
            return false;
        };
        self.revoke_abi_capability(&capability);
        true
    }

    /// Bytes currently reserved by ABI allocations. Control-plane leases are
    /// a separate budget; this is the data-plane remainder a restart must
    /// return.
    pub fn live_abi_bytes(&self) -> u64 {
        self.abi.committed_bytes
    }

    fn revoke_abi_capability(&mut self, capability: &str) {
        let sessions = self
            .sessions
            .iter()
            .filter(|(_, binding)| binding.capability == capability)
            .map(|(session, _)| session.clone())
            .collect::<Vec<_>>();
        for session in sessions {
            self.sessions.remove(&session);
            self.abi.revoke_session(&session);
        }
    }
}

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

    /// Administrative close used by the authenticated production adapter.
    /// It has no wire form: a consumer cannot revoke somebody else's session.
    pub fn revoke_session(&mut self, session_id: &str) -> bool {
        let Some(session) = self.sessions.remove(session_id) else {
            return false;
        };
        self.committed_bytes = self.committed_bytes.saturating_sub(session.allocated_bytes);
        true
    }

    pub fn revoke_all_sessions(&mut self) -> u32 {
        let count = self.sessions.len().min(u32::MAX as usize) as u32;
        self.sessions.clear();
        self.committed_bytes = 0;
        count
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
                for (a, b) in lhs_bytes.chunks(4).zip(rhs_bytes.chunks(4)) {
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

    fn peer(byte: char) -> AuthenticatedPeer {
        AuthenticatedPeer::from_mesh_identity(byte.to_string().repeat(64)).unwrap()
    }

    fn advertised(name: &str, route: ProviderRoute) -> ProviderAdvertisement {
        ProviderAdvertisement {
            device_id: format!("{name:0<64}"),
            device_name: name.into(),
            gpu_uuid: format!("GPU-{name}"),
            device_name_cuda: "NVIDIA test GPU".into(),
            executor: Executor::Cuda,
            versions: AbiRange::ours(),
            total_memory_bytes: 16 * 1024,
            leased_memory_bytes: 0,
            max_leases: 4,
            active_leases: 0,
            generation: 1,
            health: ProviderHealth::Ready,
            route,
            observed_at: 100,
        }
    }

    fn authority(limits: LeaseLimits) -> LeaseAuthority {
        LeaseAuthority::new("desktop", "a".repeat(64), "GPU-01234567", 7, limits).unwrap()
    }

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
            .chunks(4)
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

    #[test]
    fn placement_is_deterministic_and_prefers_direct_over_a_faster_relay() {
        let relay = advertised("relay", ProviderRoute::Relay { rtt_us: 10 });
        let direct = advertised("direct", ProviderRoute::Direct { rtt_us: 500 });
        let request = PlacementRequest {
            memory_bytes: 1024,
            provider_device: None,
            require_cuda: true,
        };
        let first = place_provider(&[relay.clone(), direct.clone()], request.clone()).unwrap();
        let reversed = place_provider(&[direct, relay.clone()], request).unwrap();
        assert_eq!(first.provider.device_name, "direct");
        assert_eq!(first, reversed);

        let explicit = place_provider(
            &[relay],
            PlacementRequest {
                memory_bytes: 1024,
                provider_device: Some("relay"),
                require_cuda: true,
            },
        )
        .unwrap();
        assert_eq!(explicit.provider.device_name, "relay");
    }

    #[test]
    fn placement_refusal_names_every_failed_constraint() {
        let mut busy = advertised("busy", ProviderRoute::Direct { rtt_us: 5 });
        busy.active_leases = busy.max_leases;
        let mut offline = advertised("offline", ProviderRoute::Direct { rtt_us: 1 });
        offline.health = ProviderHealth::Offline {
            reason: "heartbeat timed out".into(),
        };
        let error = place_provider(
            &[busy, offline],
            PlacementRequest {
                memory_bytes: 1024,
                provider_device: None,
                require_cuda: true,
            },
        )
        .unwrap_err();
        assert_eq!(error.code, ControlErrorCode::Unavailable);
        assert!(error
            .message
            .contains("busy has all 4 GPU lease slots in use"));
        assert!(error
            .message
            .contains("offline is not ready: heartbeat timed out"));
    }

    #[test]
    fn refused_attach_does_not_mutate_quota_or_instance_claims() {
        let mut provider = authority(LeaseLimits {
            total_memory_bytes: 8,
            max_memory_per_lease: 8,
            max_leases: 1,
            lease_ttl_secs: 30,
        });
        let before = provider.diagnostics();
        let error = provider
            .attach(&peer('b'), "instance-a", 9, 100)
            .unwrap_err();
        assert_eq!(error.code, ControlErrorCode::LimitExceeded);
        assert_eq!(provider.diagnostics(), before);

        provider.attach(&peer('b'), "instance-a", 8, 100).unwrap();
        let full = provider.diagnostics();
        let error = provider
            .attach(&peer('c'), "instance-b", 1, 100)
            .unwrap_err();
        assert_eq!(error.code, ControlErrorCode::LimitExceeded);
        assert_eq!(provider.diagnostics(), full);
        assert!(!provider.revoke_instance("instance-b"));
    }

    #[test]
    fn lease_is_bound_to_mesh_identity_and_revocation_cuts_active_calls() {
        let mut provider = authority(LeaseLimits {
            total_memory_bytes: 32,
            max_memory_per_lease: 16,
            max_leases: 2,
            lease_ttl_secs: 30,
        });
        let owner = peer('b');
        let stranger = peer('c');
        let (lease, attachment) = provider
            .attach(&owner, "orbit-instance-id", 16, 100)
            .unwrap();
        assert_eq!(attachment.guest_path(), GUEST_DEVICE_PATH);
        assert_eq!(attachment.provider_generation, 7);
        assert!(!serde_json::to_string(&attachment)
            .unwrap()
            .contains(lease.capability()));

        let denied = provider
            .authorize(&stranger, lease.capability(), 101)
            .unwrap_err();
        assert_eq!(denied.code, ControlErrorCode::Unauthorized);
        assert_eq!(provider.diagnostics().active_leases, 1);

        assert_eq!(provider.revoke_peer(owner.device_id()), 1);
        let revoked = provider
            .authorize(&owner, lease.capability(), 102)
            .unwrap_err();
        assert_eq!(revoked.code, ControlErrorCode::Revoked);
        assert_eq!(provider.diagnostics().leased_memory_bytes, 0);
    }

    #[test]
    fn provider_loss_fences_old_generation_and_recovery_starts_empty() {
        let mut provider = authority(LeaseLimits {
            total_memory_bytes: 32,
            max_memory_per_lease: 16,
            max_leases: 2,
            lease_ttl_secs: 30,
        });
        let consumer = peer('b');
        let (old, old_attachment) = provider.attach(&consumer, "instance-a", 16, 100).unwrap();
        assert_eq!(provider.provider_lost("CUDA context reset"), 1);
        let lost = provider
            .authorize(&consumer, old.capability(), 101)
            .unwrap_err();
        assert_eq!(lost.code, ControlErrorCode::Revoked);
        assert_eq!(
            provider.diagnostics().generation,
            old_attachment.provider_generation + 1
        );
        assert_eq!(provider.diagnostics().active_leases, 0);

        let generation = provider.recover().unwrap();
        let (fresh, fresh_attachment) = provider.attach(&consumer, "instance-a", 16, 102).unwrap();
        assert_ne!(fresh.capability(), old.capability());
        assert_eq!(fresh_attachment.provider_generation, generation);
        assert!(provider
            .authorize(&consumer, fresh.capability(), 103)
            .is_ok());
    }

    #[test]
    fn health_and_expiry_refuse_before_renewal_mutates_the_lease() {
        let mut provider = authority(LeaseLimits {
            total_memory_bytes: 32,
            max_memory_per_lease: 16,
            max_leases: 2,
            lease_ttl_secs: 10,
        });
        let consumer = peer('b');
        let (lease, _) = provider.attach(&consumer, "instance-a", 16, 100).unwrap();
        provider.set_health(ProviderHealth::Draining {
            reason: "operator maintenance".into(),
        });
        let before = provider.leases[lease.capability()].expires_at;
        let error = provider
            .renew(&consumer, lease.capability(), 101)
            .unwrap_err();
        assert_eq!(error.code, ControlErrorCode::Unavailable);
        assert_eq!(provider.leases[lease.capability()].expires_at, before);

        provider.set_health(ProviderHealth::Ready);
        let expired = provider
            .renew(&consumer, lease.capability(), 111)
            .unwrap_err();
        assert_eq!(expired.code, ControlErrorCode::Revoked);
        assert_eq!(provider.leases[lease.capability()].expires_at, before);

        assert_eq!(provider.reap_expired(111), 1);
        assert_eq!(provider.diagnostics().active_leases, 0);
        assert_eq!(provider.diagnostics().leased_memory_bytes, 0);
    }

    #[test]
    fn bearer_capabilities_are_redacted_from_debug_output() {
        let mut provider = authority(LeaseLimits::default());
        let (lease, _) = provider.attach(&peer('b'), "instance-a", 16, 100).unwrap();
        let debug = format!("{lease:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains(lease.capability()));
    }

    #[test]
    fn production_adapter_refuses_before_abi_mutation_and_revocation_frees_memory() {
        let authority = authority(LeaseLimits {
            total_memory_bytes: 32,
            max_memory_per_lease: 32,
            max_leases: 1,
            lease_ttl_secs: 30,
        });
        let mut production =
            ProductionProvider::new(authority, Provider::reference("reference-test"));
        let owner = peer('b');
        let stranger = peer('c');
        let (lease, _) = production
            .authority_mut()
            .attach(&owner, "instance-a", 32, 100)
            .unwrap();
        let Response::SessionOpened { session, .. } = production
            .open_session(&owner, lease.capability(), AbiRange::ours(), 100)
            .unwrap()
        else {
            panic!("session should open")
        };

        let allocate = || Request::Allocate {
            session: session.clone(),
            sequence: 1,
            bytes: 8,
        };
        let refused = production
            .handle(&stranger, lease.capability(), allocate(), 101)
            .unwrap_err();
        assert_eq!(refused.code, ControlErrorCode::Unauthorized);
        assert_eq!(production.abi.committed_bytes, 0);

        let response = production
            .handle(&owner, lease.capability(), allocate(), 101)
            .unwrap()
            .into_result()
            .unwrap();
        assert!(matches!(response, Response::Allocated { bytes: 8, .. }));
        assert_eq!(production.abi.committed_bytes, 8);

        assert!(production.revoke_instance("instance-a"));
        assert_eq!(production.abi.committed_bytes, 0);
        assert_eq!(production.authority().diagnostics().leased_memory_bytes, 0);
        let refused = production
            .handle(
                &owner,
                lease.capability(),
                Request::Read {
                    session,
                    sequence: 2,
                    source: range("irrelevant", 0, 1),
                },
                102,
            )
            .unwrap_err();
        assert_eq!(refused.code, ControlErrorCode::InvalidLease);
    }

    #[test]
    fn guest_restart_closes_the_abi_session_and_keeps_the_lease() {
        let authority = authority(LeaseLimits {
            total_memory_bytes: 32,
            max_memory_per_lease: 32,
            max_leases: 1,
            lease_ttl_secs: 30,
        });
        let mut production =
            ProductionProvider::new(authority, Provider::reference("reference-test"));
        let owner = peer('b');
        let (lease, attachment) = production
            .authority_mut()
            .attach(&owner, "instance-a", 32, 100)
            .unwrap();
        let Response::SessionOpened { session, .. } = production
            .open_session(&owner, lease.capability(), AbiRange::ours(), 100)
            .unwrap()
        else {
            panic!("session should open")
        };
        production
            .handle(
                &owner,
                lease.capability(),
                Request::Allocate {
                    session: session.clone(),
                    sequence: 1,
                    bytes: 8,
                },
                101,
            )
            .unwrap()
            .into_result()
            .unwrap();
        assert_eq!(production.live_abi_bytes(), 8);
        assert_eq!(attachment.guest_path(), GUEST_DEVICE_PATH);

        assert!(production.guest_lost("instance-a"));
        assert_eq!(production.live_abi_bytes(), 0);
        let stale = production
            .handle(
                &owner,
                lease.capability(),
                Request::Read {
                    session,
                    sequence: 2,
                    source: range("irrelevant", 0, 1),
                },
                102,
            )
            .unwrap_err();
        assert_eq!(stale.code, ControlErrorCode::InvalidLease);

        let Response::SessionOpened {
            session: restarted, ..
        } = production
            .open_session(&owner, lease.capability(), AbiRange::ours(), 103)
            .unwrap()
        else {
            panic!("restarted guest reopens on the live lease")
        };
        let allocated = production
            .handle(
                &owner,
                lease.capability(),
                Request::Allocate {
                    session: restarted,
                    sequence: 1,
                    bytes: 8,
                },
                104,
            )
            .unwrap()
            .into_result()
            .unwrap();
        assert!(matches!(allocated, Response::Allocated { bytes: 8, .. }));
        assert_eq!(production.authority().diagnostics().active_leases, 1);
    }
}
