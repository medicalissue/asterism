//! Authenticated instance-bound GPU path:
//! guest control → local astd → iroh mesh → provider GPU service.
//!
//! The mesh opening frame names the orbit-global instance and the provider
//! generation. It does not carry a lease bearer, a backend id, or a
//! diagnostic consumer string used as authority. Typed frames are
//! length-prefixed and bounded by [`gpu::MAX_WIRE_FRAME_BYTES`]. A credit
//! window supplies backpressure; cancel drops a not-yet-applied call.
//! Device loss, revocation, and generation skew fail closed without
//! touching ABI memory.
//!
//! This module is the production adapter. Source fixtures encode and decode
//! the same bytes a mesh stream would carry. They never bind a LAN TCP
//! listener.

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

use crate::remote_gpu::{
    self as gpu, AbiRange, AuthenticatedPeer, ControlError, ControlErrorCode, Executor,
    ProductionProvider, Reply, Request, Response, MAX_WIRE_FRAME_BYTES,
};
use crate::remote_gpu_guest::{
    self as guest, CudaCall, CudaResult, GuestDeviceKind, GuestFrame, GuestReply,
    CUDA_ERROR_NOT_SUPPORTED, DEFAULT_CREDIT_WINDOW, PROJECTION_KIND,
};

/// Protocol version that introduced the GPU mesh stream.
pub const GPU_MESH_PROTOCOL: u32 = 8;

/// Opening frame of a dedicated GPU mesh stream. QUIC already authenticated
/// the peer; this only names which instance and generation the stream is for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GpuMeshOpen {
    pub instance_id: String,
    pub provider_generation: u64,
}

impl GpuMeshOpen {
    pub fn new(
        instance_id: impl Into<String>,
        provider_generation: u64,
    ) -> Result<Self, PathError> {
        let instance_id = instance_id.into();
        if instance_id.trim().is_empty() || instance_id.len() > 128 {
            return Err(PathError::new(
                "gpu mesh open requires an orbit-global instance id of 1..128 bytes",
            ));
        }
        if provider_generation == 0 {
            return Err(PathError::new(
                "gpu mesh open requires a non-zero provider generation",
            ));
        }
        Ok(Self {
            instance_id,
            provider_generation,
        })
    }

    /// JSON object keys this frame is allowed to carry. A bearer, backend id,
    /// or capability field is a protocol bug, not an extension.
    pub fn allowed_keys() -> &'static [&'static str] {
        &["instance_id", "provider_generation"]
    }
}

/// Typed frames after [`GpuMeshOpen`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum GpuMeshFrame {
    Accepted {
        abi: u32,
        executor: Executor,
        credit: u32,
        session: String,
    },
    Refused {
        code: ControlErrorCode,
        message: String,
    },
    Credit {
        window: u32,
    },
    Call {
        id: u64,
        request: Request,
    },
    Reply {
        id: u64,
        reply: Reply,
    },
    Cancel {
        id: u64,
    },
    Cancelled {
        id: u64,
    },
    DeviceLost {
        reason: String,
    },
    Revoked {
        instance_id: String,
    },
    Skew {
        expected_generation: u64,
        observed: u64,
    },
    Close,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathError {
    pub message: String,
}

impl PathError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl std::fmt::Display for PathError {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        out.write_str(&self.message)
    }
}

impl std::error::Error for PathError {}

impl From<ControlError> for PathError {
    fn from(err: ControlError) -> Self {
        Self::new(err.message)
    }
}

impl From<guest::GuestError> for PathError {
    fn from(err: guest::GuestError) -> Self {
        Self::new(err.message)
    }
}

/// Encode one bounded length-prefixed JSON frame. This is the mesh byte
/// layout; fixtures assert these bytes, not just in-memory structs.
pub fn encode_frame(value: &impl Serialize) -> Result<Vec<u8>, PathError> {
    let body = serde_json::to_vec(value).map_err(|err| PathError::new(err.to_string()))?;
    if body.len() > MAX_WIRE_FRAME_BYTES {
        return Err(PathError::new(format!(
            "GPU mesh frame is {} bytes, above the {MAX_WIRE_FRAME_BYTES} byte limit",
            body.len()
        )));
    }
    let len = u32::try_from(body.len()).map_err(|_| PathError::new("GPU mesh frame too large"))?;
    let mut frame = Vec::with_capacity(4 + body.len());
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(&body);
    Ok(frame)
}

pub fn decode_frame<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T, PathError> {
    if bytes.len() < 4 {
        return Err(PathError::new("GPU mesh frame is truncated"));
    }
    let len = u32::from_be_bytes(bytes[0..4].try_into().expect("four-byte length")) as usize;
    if len > MAX_WIRE_FRAME_BYTES {
        return Err(PathError::new(format!(
            "GPU mesh frame of {len} bytes exceeds the {MAX_WIRE_FRAME_BYTES} byte limit"
        )));
    }
    if bytes.len() != 4 + len {
        return Err(PathError::new(
            "GPU mesh frame length does not match the prefix",
        ));
    }
    serde_json::from_slice(&bytes[4..]).map_err(|err| PathError::new(err.to_string()))
}

/// Consumer-side hop: guest frames in, mesh frames out. Owns the credit
/// window and call ids. Never holds a lease bearer.
#[derive(Debug)]
pub struct ConsumerHop {
    pub instance_id: String,
    pub provider_generation: u64,
    credits: u32,
    next_id: u64,
    inflight: HashSet<u64>,
    session: Option<String>,
    sequence: u64,
}

impl ConsumerHop {
    pub fn new(
        instance_id: impl Into<String>,
        provider_generation: u64,
    ) -> Result<Self, PathError> {
        let open = GpuMeshOpen::new(instance_id, provider_generation)?;
        Ok(Self {
            instance_id: open.instance_id,
            provider_generation: open.provider_generation,
            credits: 0,
            next_id: 0,
            inflight: HashSet::new(),
            session: None,
            sequence: 0,
        })
    }

    pub fn open_bytes(&self) -> Result<Vec<u8>, PathError> {
        let open = GpuMeshOpen::new(&self.instance_id, self.provider_generation)?;
        encode_frame(&open)
    }

    pub fn apply_mesh(&mut self, frame: GpuMeshFrame) -> Result<(), PathError> {
        match frame {
            GpuMeshFrame::Accepted { credit, .. } | GpuMeshFrame::Credit { window: credit } => {
                self.credits = credit;
                Ok(())
            }
            GpuMeshFrame::Reply { id, .. } | GpuMeshFrame::Cancelled { id } => {
                self.inflight.remove(&id);
                self.credits = self.credits.saturating_add(1);
                Ok(())
            }
            GpuMeshFrame::Refused { .. }
            | GpuMeshFrame::DeviceLost { .. }
            | GpuMeshFrame::Revoked { .. }
            | GpuMeshFrame::Skew { .. } => Err(PathError::new(format_fail_closed(
                &frame,
                "GPU mesh call failed closed",
            ))),
            GpuMeshFrame::Close => Ok(()),
            GpuMeshFrame::Call { .. } | GpuMeshFrame::Cancel { .. } => Err(PathError::new(
                "consumer received a provider-originated call frame",
            )),
        }
    }

    fn take_credit(&mut self) -> Result<u64, PathError> {
        if self.credits == 0 {
            return Err(PathError::new(
                "GPU mesh credit window is empty; wait for a reply or a credit frame",
            ));
        }
        self.next_id = self
            .next_id
            .checked_add(1)
            .ok_or_else(|| PathError::new("GPU mesh call id space exhausted"))?;
        self.credits -= 1;
        self.inflight.insert(self.next_id);
        Ok(self.next_id)
    }

    pub fn encode_call(&mut self, request: Request) -> Result<(u64, Vec<u8>), PathError> {
        let id = self.take_credit()?;
        Ok((id, encode_frame(&GpuMeshFrame::Call { id, request })?))
    }

    pub fn encode_cancel(&mut self, id: u64) -> Result<Vec<u8>, PathError> {
        if !self.inflight.contains(&id) {
            return Err(PathError::new("cancel names a call that is not in flight"));
        }
        encode_frame(&GpuMeshFrame::Cancel { id })
    }

    pub fn next_sequence(&mut self) -> Result<u64, PathError> {
        self.sequence = self
            .sequence
            .checked_add(1)
            .ok_or_else(|| PathError::new("ABI sequence exhausted"))?;
        Ok(self.sequence)
    }

    pub fn set_session(&mut self, session: String) {
        self.session = Some(session);
    }

    pub fn session(&self) -> Result<&str, PathError> {
        self.session
            .as_deref()
            .ok_or_else(|| PathError::new("GPU ABI session is not open"))
    }
}

fn format_fail_closed(frame: &GpuMeshFrame, fallback: &str) -> String {
    match frame {
        GpuMeshFrame::Skew {
            expected_generation,
            observed,
        } => format!("GPU generation skew: attachment {expected_generation}, provider {observed}"),
        GpuMeshFrame::DeviceLost { reason } => format!("GPU device lost: {reason}"),
        GpuMeshFrame::Revoked { instance_id } => format!("GPU lease revoked for {instance_id}"),
        GpuMeshFrame::Refused { message, .. } => message.clone(),
        _ => fallback.to_owned(),
    }
}

/// Provider-side hop. Authorizes by authenticated peer + instance +
/// generation, then feeds [`ProductionProvider`].
#[derive(Debug)]
pub struct ProviderHop {
    peer: AuthenticatedPeer,
    production: ProductionProvider,
    instance_id: Option<String>,
    generation: Option<u64>,
    abi_session: Option<String>,
    executor: Executor,
    queued: HashMap<u64, Request>,
    now: u64,
}

impl ProviderHop {
    pub fn new(peer: AuthenticatedPeer, production: ProductionProvider, now: u64) -> Self {
        Self {
            peer,
            production,
            instance_id: None,
            generation: None,
            abi_session: None,
            executor: Executor::Reference,
            queued: HashMap::new(),
            now,
        }
    }

    pub fn production_mut(&mut self) -> &mut ProductionProvider {
        &mut self.production
    }

    pub fn abi_session(&self) -> Option<&str> {
        self.abi_session.as_deref()
    }

    pub fn executor(&self) -> Executor {
        self.executor
    }

    pub fn into_production(self) -> ProductionProvider {
        self.production
    }

    pub fn accept_open(&mut self, open: GpuMeshOpen) -> Result<GpuMeshFrame, PathError> {
        match self.production.open_session_for_instance(
            &self.peer,
            &open.instance_id,
            open.provider_generation,
            AbiRange::ours(),
            self.now,
        ) {
            Ok(Response::SessionOpened {
                abi,
                session,
                capabilities,
            }) => {
                self.instance_id = Some(open.instance_id);
                self.generation = Some(open.provider_generation);
                self.abi_session = Some(session.clone());
                self.executor = capabilities.executor;
                Ok(GpuMeshFrame::Accepted {
                    abi,
                    executor: capabilities.executor,
                    credit: DEFAULT_CREDIT_WINDOW,
                    session,
                })
            }
            Ok(_) => Err(PathError::new(
                "provider hello returned a non-session reply",
            )),
            Err(err) if err.code == ControlErrorCode::StaleGeneration => Ok(GpuMeshFrame::Skew {
                expected_generation: open.provider_generation,
                observed: self.production.authority().generation(),
            }),
            Err(err) if err.code == ControlErrorCode::Revoked => Ok(GpuMeshFrame::Revoked {
                instance_id: open.instance_id,
            }),
            Err(err) if err.code == ControlErrorCode::Unavailable => Ok(GpuMeshFrame::DeviceLost {
                reason: err.message,
            }),
            Err(err) => Ok(GpuMeshFrame::Refused {
                code: err.code,
                message: err.message,
            }),
        }
    }

    pub fn handle_frame(&mut self, frame: GpuMeshFrame) -> Result<GpuMeshFrame, PathError> {
        let instance_id = self
            .instance_id
            .clone()
            .ok_or_else(|| PathError::new("GPU mesh stream is not accepted"))?;
        let generation = self
            .generation
            .ok_or_else(|| PathError::new("GPU mesh stream is not accepted"))?;
        match frame {
            GpuMeshFrame::Call { id, request } => {
                if self.queued.len() as u32 >= DEFAULT_CREDIT_WINDOW {
                    return Ok(GpuMeshFrame::Refused {
                        code: ControlErrorCode::LimitExceeded,
                        message: "GPU mesh credit window is exhausted".into(),
                    });
                }
                self.queued.insert(id, request);
                self.apply_queued(id, &instance_id, generation)
            }
            GpuMeshFrame::Cancel { id } => {
                if self.queued.remove(&id).is_some() {
                    Ok(GpuMeshFrame::Cancelled { id })
                } else {
                    Ok(GpuMeshFrame::Refused {
                        code: ControlErrorCode::InvalidRequest,
                        message: "GPU call already executed or unknown".into(),
                    })
                }
            }
            GpuMeshFrame::Close => Ok(GpuMeshFrame::Close),
            other => Ok(GpuMeshFrame::Refused {
                code: ControlErrorCode::InvalidRequest,
                message: format!("provider rejected unexpected mesh frame {other:?}"),
            }),
        }
    }

    fn apply_queued(
        &mut self,
        id: u64,
        instance_id: &str,
        generation: u64,
    ) -> Result<GpuMeshFrame, PathError> {
        let Some(request) = self.queued.remove(&id) else {
            return Ok(GpuMeshFrame::Refused {
                code: ControlErrorCode::InvalidRequest,
                message: "GPU call is not queued".into(),
            });
        };
        match self.production.handle_for_instance(
            &self.peer,
            instance_id,
            generation,
            request,
            self.now,
        ) {
            Ok(reply) => Ok(GpuMeshFrame::Reply { id, reply }),
            Err(err) if err.code == ControlErrorCode::StaleGeneration => Ok(GpuMeshFrame::Skew {
                expected_generation: generation,
                observed: self.production.authority().generation(),
            }),
            Err(err) if err.code == ControlErrorCode::Revoked => Ok(GpuMeshFrame::Revoked {
                instance_id: instance_id.to_owned(),
            }),
            Err(err) if err.code == ControlErrorCode::Unavailable => Ok(GpuMeshFrame::DeviceLost {
                reason: err.message,
            }),
            Err(err) => Ok(GpuMeshFrame::Refused {
                code: err.code,
                message: err.message,
            }),
        }
    }
}

/// In-process path that still serializes every hop to bytes. This is the
/// source fixture: CUDA calls enter as guest frames, cross encoded mesh
/// frames, and come back as CUDA results.
pub struct GuestMeshPath {
    consumer: ConsumerHop,
    provider: ProviderHop,
    session: String,
    /// Encoded frames that actually crossed the mesh direction, for proofs.
    pub crossed: Vec<Vec<u8>>,
}

impl GuestMeshPath {
    /// Attach a lease, then open the mesh path. Returns the token-free
    /// attachment and the in-memory capability string so tests can prove the
    /// capability never appears in crossed bytes.
    pub fn attach(
        peer: AuthenticatedPeer,
        mut production: ProductionProvider,
        instance_id: &str,
        memory_bytes: u64,
        now: u64,
    ) -> Result<(Self, gpu::GpuAttachment, String), PathError> {
        let (lease, attachment) =
            production
                .authority_mut()
                .attach(&peer, instance_id, memory_bytes, now)?;
        let capability = lease.capability().to_owned();
        let generation = attachment.provider_generation;
        let mut consumer = ConsumerHop::new(instance_id, generation)?;
        let mut provider = ProviderHop::new(peer, production, now);
        let open_bytes = consumer.open_bytes()?;
        let open: GpuMeshOpen = decode_frame(&open_bytes)?;
        assert_open_has_no_bearer(&open_bytes)?;
        let accepted = provider.accept_open(open)?;
        let accepted_bytes = encode_frame(&accepted)?;
        consumer.apply_mesh(accepted)?;
        let session = provider
            .abi_session()
            .ok_or_else(|| PathError::new("provider did not capture an ABI session"))?
            .to_owned();
        consumer.set_session(session.clone());
        Ok((
            Self {
                consumer,
                provider,
                session,
                crossed: vec![open_bytes, accepted_bytes],
            },
            attachment,
            capability,
        ))
    }

    pub fn crossed_text(&self) -> String {
        self.crossed
            .iter()
            .filter_map(|frame| std::str::from_utf8(&frame[4.min(frame.len())..]).ok())
            .collect::<Vec<_>>()
            .join("\n")
    }

    pub fn guest_open_reply(&self, kind: GuestDeviceKind) -> GuestReply {
        GuestReply::Accepted {
            abi: gpu::ABI_VERSION,
            projection_kind: PROJECTION_KIND.into(),
            device_kind: kind,
            executor: self.provider.executor(),
            credit: DEFAULT_CREDIT_WINDOW,
        }
    }

    pub fn apply_guest(&mut self, frame: GuestFrame) -> Result<GuestReply, PathError> {
        match frame {
            GuestFrame::Open { .. } => Ok(self.guest_open_reply(GuestDeviceKind::UnixEndpoint)),
            GuestFrame::Cuda { id, call } => {
                let result = self.apply_cuda(call)?;
                Ok(GuestReply::Cuda { id, result })
            }
            GuestFrame::Cancel { id } => {
                let bytes = self.consumer.encode_cancel(id)?;
                self.crossed.push(bytes.clone());
                let frame: GpuMeshFrame = decode_frame(&bytes)?;
                let reply = self.provider.handle_frame(frame)?;
                let reply_bytes = encode_frame(&reply)?;
                self.crossed.push(reply_bytes);
                self.consumer.apply_mesh(reply.clone())?;
                match reply {
                    GpuMeshFrame::Cancelled { id } => Ok(GuestReply::Cancelled { id }),
                    GpuMeshFrame::Refused { message, .. } => Ok(GuestReply::Refused {
                        code: "cancel".into(),
                        message,
                    }),
                    other => Err(PathError::new(format!("unexpected cancel reply {other:?}"))),
                }
            }
            GuestFrame::Close => {
                if !self.session.is_empty() {
                    let sequence = self.consumer.next_sequence()?;
                    let request = Request::Close {
                        session: self.session.clone(),
                        sequence,
                    };
                    let _ = self.round_trip(request)?;
                }
                Ok(GuestReply::Closed)
            }
        }
    }

    pub fn cuda(&mut self, call: CudaCall) -> Result<CudaResult, PathError> {
        self.apply_cuda(call)
    }

    fn apply_cuda(&mut self, call: CudaCall) -> Result<CudaResult, PathError> {
        match &call {
            CudaCall::Init => Ok(CudaResult::Init),
            CudaCall::DeviceCount => Ok(CudaResult::DeviceCount { count: 1 }),
            CudaCall::DeviceName { ordinal } if *ordinal == 0 => Ok(CudaResult::DeviceName {
                name: "Asterism remote NVIDIA (projected)".into(),
            }),
            CudaCall::DeviceName { .. } => Ok(CudaResult::Error {
                cuda: guest::CUDA_ERROR_INVALID_DEVICE,
                message: "only device ordinal 0 is projected".into(),
            }),
            CudaCall::Synchronize => Ok(CudaResult::Synced),
            CudaCall::Unsupported { symbol } => Ok(CudaResult::Error {
                cuda: CUDA_ERROR_NOT_SUPPORTED,
                message: format!("{symbol} is outside the implemented CUDA Driver surface"),
            }),
            other => {
                let sequence = self.consumer.next_sequence()?;
                let request = guest::abi_request_for(&self.session, sequence, other)?;
                let reply = self.round_trip(request)?;
                if let Reply::Ok {
                    response: Response::Allocated { allocation, .. },
                } = &reply
                {
                    let _ = allocation;
                }
                Ok(guest::cuda_result_for(other, reply))
            }
        }
    }

    fn round_trip(&mut self, request: Request) -> Result<Reply, PathError> {
        let (id, call_bytes) = self.consumer.encode_call(request)?;
        self.crossed.push(call_bytes.clone());
        let frame: GpuMeshFrame = decode_frame(&call_bytes)?;
        let reply_frame = self.provider.handle_frame(frame)?;
        let reply_bytes = encode_frame(&reply_frame)?;
        self.crossed.push(reply_bytes.clone());
        self.consumer.apply_mesh(reply_frame.clone())?;
        match reply_frame {
            GpuMeshFrame::Reply {
                id: reply_id,
                reply,
            } if reply_id == id => Ok(reply),
            other => Err(fail_closed_error(&other)),
        }
    }

    pub fn revoke_instance(&mut self, instance_id: &str) -> bool {
        self.provider.production_mut().revoke_instance(instance_id)
    }

    pub fn provider_lost(&mut self, reason: &str) -> u32 {
        self.provider.production_mut().provider_lost(reason)
    }
}

fn fail_closed_error(frame: &GpuMeshFrame) -> PathError {
    PathError::new(format_fail_closed(frame, "GPU mesh call failed closed"))
}

fn assert_open_has_no_bearer(bytes: &[u8]) -> Result<(), PathError> {
    let body = std::str::from_utf8(&bytes[4..]).map_err(|err| PathError::new(err.to_string()))?;
    for forbidden in ["capability", "bearer", "lease_token", "token", "backend"] {
        if body.contains(forbidden) {
            return Err(PathError::new(format!(
                "GPU mesh open must not carry {forbidden}: {body}"
            )));
        }
    }
    let value: serde_json::Value =
        serde_json::from_str(body).map_err(|err| PathError::new(err.to_string()))?;
    let keys: Vec<_> = value
        .as_object()
        .ok_or_else(|| PathError::new("GPU mesh open is not a JSON object"))?
        .keys()
        .cloned()
        .collect();
    for key in &keys {
        if !GpuMeshOpen::allowed_keys().contains(&key.as_str()) {
            return Err(PathError::new(format!(
                "GPU mesh open carries unexpected key {key}"
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::remote_gpu::{LeaseAuthority, LeaseLimits, Provider};

    fn peer(label: u8) -> AuthenticatedPeer {
        AuthenticatedPeer::from_mesh_identity(format!("{label:064x}")).unwrap()
    }

    fn production(name: &str) -> ProductionProvider {
        let authority = LeaseAuthority::new(
            name,
            "a".repeat(64),
            "GPU-01234567",
            7,
            LeaseLimits::default(),
        )
        .unwrap();
        ProductionProvider::new(authority, Provider::reference(name))
    }

    fn path() -> (GuestMeshPath, gpu::GpuAttachment, String) {
        GuestMeshPath::attach(
            peer(1),
            production("desktop"),
            "inst-1",
            64 * 1024 * 1024,
            1_000,
        )
        .unwrap()
    }

    fn alloc(path: &mut GuestMeshPath, bytes: u64) -> String {
        match path.cuda(CudaCall::MemAlloc { bytes }).unwrap() {
            CudaResult::Alloc { allocation } => allocation,
            other => panic!("allocate failed: {other:?}"),
        }
    }

    #[test]
    fn vector_add_bytes_cross_the_authenticated_mesh_path() {
        let (mut path, attachment, capability) = path();
        assert_eq!(attachment.guest_path(), gpu::GUEST_DEVICE_PATH);
        assert_eq!(attachment.projection_kind(), PROJECTION_KIND);
        assert!(!capability.is_empty());
        assert!(!path.crossed_text().contains(&capability));
        assert!(!format!("{:?}", path.crossed).contains(&capability));

        path.cuda(CudaCall::Init).unwrap();
        let lhs = alloc(&mut path, 16);
        let rhs = alloc(&mut path, 16);
        let output = alloc(&mut path, 16);
        let lhs_bytes: Vec<u8> = [1.0f32, 2.0, 3.0, 4.0]
            .into_iter()
            .flat_map(f32::to_le_bytes)
            .collect();
        let rhs_bytes: Vec<u8> = [10.0f32, 20.0, 30.0, 40.0]
            .into_iter()
            .flat_map(f32::to_le_bytes)
            .collect();
        path.cuda(CudaCall::MemcpyHtoD {
            allocation: lhs.clone(),
            offset: 0,
            data: lhs_bytes,
        })
        .unwrap();
        path.cuda(CudaCall::MemcpyHtoD {
            allocation: rhs.clone(),
            offset: 0,
            data: rhs_bytes,
        })
        .unwrap();
        let loaded = path
            .cuda(CudaCall::ModuleLoadData {
                image: gpu::VECTOR_ADD_PTX.as_bytes().to_vec(),
            })
            .unwrap();
        let CudaResult::Module { pin } = loaded else {
            panic!("module load failed: {loaded:?}");
        };
        path.cuda(CudaCall::LaunchVectorAdd {
            workload_pin: pin,
            lhs,
            rhs,
            output: output.clone(),
            elements: 4,
        })
        .unwrap();
        let data = path
            .cuda(CudaCall::MemcpyDtoH {
                allocation: output,
                offset: 0,
                bytes: 16,
            })
            .unwrap();
        let CudaResult::Data { data } = data else {
            panic!("read failed: {data:?}");
        };
        let values: Vec<f32> = data
            .chunks(4)
            .map(|chunk| f32::from_le_bytes(chunk.try_into().unwrap()))
            .collect();
        assert_eq!(values, vec![11.0, 22.0, 33.0, 44.0]);
        assert!(path.crossed.len() >= 4);
        assert!(!path.crossed_text().contains(&capability));
        assert!(!path.crossed_text().contains("backend"));
    }

    #[test]
    fn unsupported_cuda_symbols_fail_closed_without_a_mesh_mutation() {
        let (mut path, _, _) = path();
        let before = path.crossed.len();
        let result = path
            .cuda(CudaCall::Unsupported {
                symbol: "cuMemAllocManaged".into(),
            })
            .unwrap();
        assert!(matches!(
            result,
            CudaResult::Error {
                cuda: CUDA_ERROR_NOT_SUPPORTED,
                ..
            }
        ));
        assert_eq!(path.crossed.len(), before);
    }

    #[test]
    fn revoke_and_device_loss_fail_closed() {
        let (mut revoked_path, _, _) = path();
        let allocation = alloc(&mut revoked_path, 8);
        assert!(revoked_path.revoke_instance("inst-1"));
        let err = revoked_path
            .cuda(CudaCall::MemcpyDtoH {
                allocation,
                offset: 0,
                bytes: 8,
            })
            .unwrap_err();
        assert!(
            err.message.contains("revoked")
                || err.message.contains("no live GPU lease")
                || err.message.contains("unknown"),
            "{err}"
        );

        let (mut lost_path, _, _) = path();
        alloc(&mut lost_path, 8);
        lost_path.provider_lost("provider process gone");
        let err = lost_path.cuda(CudaCall::MemAlloc { bytes: 8 }).unwrap_err();
        assert!(
            err.message.contains("lost")
                || err.message.contains("not ready")
                || err.message.contains("offline")
                || err.message.contains("no live GPU lease")
                || err.message.contains("generation skew"),
            "{err}"
        );
    }

    #[test]
    fn generation_skew_fails_closed() {
        let peer = peer(2);
        let mut production = production("desktop");
        let (_, attachment) = production
            .authority_mut()
            .attach(&peer, "inst-skew", 64 * 1024 * 1024, 1_000)
            .unwrap();
        production.authority_mut().provider_lost("restart");
        production.authority_mut().recover().unwrap();
        let consumer = ConsumerHop::new("inst-skew", attachment.provider_generation).unwrap();
        let mut provider = ProviderHop::new(peer, production, 1_000);
        let open: GpuMeshOpen = decode_frame(&consumer.open_bytes().unwrap()).unwrap();
        let reply = provider.accept_open(open).unwrap();
        assert!(
            matches!(
                reply,
                GpuMeshFrame::Skew { .. }
                    | GpuMeshFrame::Revoked { .. }
                    | GpuMeshFrame::Refused { .. }
            ),
            "{reply:?}"
        );
    }

    #[test]
    fn credit_window_supplies_backpressure() {
        let mut hop = ConsumerHop::new("inst-1", 7).unwrap();
        let err = hop
            .encode_call(Request::Close {
                session: "s".into(),
                sequence: 1,
            })
            .unwrap_err();
        assert!(err.message.contains("credit window"), "{err}");
        hop.apply_mesh(GpuMeshFrame::Credit { window: 1 }).unwrap();
        let _ = hop
            .encode_call(Request::Close {
                session: "s".into(),
                sequence: 1,
            })
            .unwrap();
        let err = hop
            .encode_call(Request::Close {
                session: "s".into(),
                sequence: 2,
            })
            .unwrap_err();
        assert!(err.message.contains("credit window"), "{err}");
    }

    #[test]
    fn mesh_open_json_is_only_instance_and_generation() {
        let open = GpuMeshOpen::new("inst-1", 7).unwrap();
        let bytes = encode_frame(&open).unwrap();
        assert_open_has_no_bearer(&bytes).unwrap();
        let decoded: GpuMeshOpen = decode_frame(&bytes).unwrap();
        assert_eq!(decoded, open);
    }
}
