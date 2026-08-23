//! Guest NVIDIA projection adapter for `astd`.
//!
//! Local unix-socket frames from the instance-bound guest control hop are
//! forwarded onto a dedicated authenticated mesh stream. The opening frame
//! names the instance and provider generation only — no bearer, no backend
//! id, no LAN listener.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, bail, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use uuid::Uuid;

use asterism_core::instance::now_unix;
use asterism_core::protocol::{Request, Response};
use asterism_core::remote_gpu::{
    AuthenticatedPeer, ControlErrorCode, LeaseAuthority, LeaseLimits, ProductionProvider, Provider,
};
use asterism_core::remote_gpu_guest::{
    self as guest, GuestFrame, GuestReply, DEFAULT_CREDIT_WINDOW, PROJECTION_KIND,
};
use asterism_core::remote_gpu_path::{
    decode_frame, encode_frame, GpuMeshFrame, GpuMeshOpen, ProviderHop,
};
use asterism_mesh::iroh_types::{RecvStream, SendStream};
use asterism_mesh::{DeviceId, MeshStream};

use crate::mesh::{ClientIo, Mesh};
use crate::Node;

/// In-memory provider GPU services on this device. The real CUDA executor
/// is a later part; this registry is how the mesh path finds a
/// [`ProductionProvider`] without a public listener.
#[derive(Default)]
pub struct Manager {
    providers: Mutex<HashMap<String, ProductionProvider>>,
}

impl Manager {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn insert(&self, gpu_uuid: impl Into<String>, provider: ProductionProvider) {
        self.providers
            .lock()
            .expect("GPU provider registry")
            .insert(gpu_uuid.into(), provider);
    }

    /// Register a source-only reference provider so daemon-path Init and
    /// device queries execute. No CUDA crate, no public listener.
    pub fn register_reference(&self, device_name: &str, device_id: &str) -> Result<()> {
        if self
            .providers
            .lock()
            .map(|p| !p.is_empty())
            .unwrap_or(false)
        {
            return Ok(());
        }
        let authority = LeaseAuthority::new(
            device_name,
            device_id,
            "GPU-ASTERISM-REFERENCE",
            1,
            LeaseLimits::default(),
        )
        .map_err(|err| anyhow!(err.message))?;
        self.insert(
            "GPU-ASTERISM-REFERENCE",
            ProductionProvider::new(authority, Provider::reference(device_name)),
        );
        Ok(())
    }

    fn take(&self) -> Option<(String, ProductionProvider)> {
        let mut providers = self.providers.lock().ok()?;
        let key = providers.keys().next().cloned()?;
        providers.remove(&key).map(|provider| (key, provider))
    }

    fn put(&self, gpu_uuid: String, provider: ProductionProvider) {
        if let Ok(mut providers) = self.providers.lock() {
            providers.insert(gpu_uuid, provider);
        }
    }
}

pub(crate) fn local_only_request(request: &Request) -> bool {
    matches!(
        request,
        Request::GpuGuestOpen { .. } | Request::GpuGuestFrame { .. } | Request::GpuGuestClose
    )
}

/// Serve one authenticated GPU mesh stream on the provider device.
pub(crate) async fn serve_mesh(
    mut stream: MeshStream,
    peer: DeviceId,
    node: &Node,
    instance_id: String,
    provider_generation: u64,
) -> Result<()> {
    let open = match GpuMeshOpen::new(instance_id, provider_generation) {
        Ok(open) => open,
        Err(err) => {
            write_gpu_frame(
                &mut stream.send,
                &GpuMeshFrame::Refused {
                    code: ControlErrorCode::InvalidRequest,
                    message: err.message,
                },
            )
            .await?;
            return Ok(());
        }
    };
    let Some((gpu_uuid, production)) = node.gpu.take() else {
        write_gpu_frame(
            &mut stream.send,
            &GpuMeshFrame::DeviceLost {
                reason: "this device has no GPU provider service".into(),
            },
        )
        .await?;
        return Ok(());
    };
    let peer = match AuthenticatedPeer::from_mesh_identity(peer.to_string()) {
        Ok(peer) => peer,
        Err(err) => {
            node.gpu.put(gpu_uuid, production);
            write_gpu_frame(
                &mut stream.send,
                &GpuMeshFrame::Refused {
                    code: ControlErrorCode::Unauthorized,
                    message: err.message,
                },
            )
            .await?;
            return Ok(());
        }
    };
    let mut hop = ProviderHop::new(peer, production, now_unix());
    hop.set_now(now_unix());
    let accepted = hop.accept_open(open).map_err(|err| anyhow!(err))?;
    write_gpu_frame(&mut stream.send, &accepted).await?;
    if !matches!(accepted, GpuMeshFrame::Accepted { .. }) {
        hop.shutdown("refused", false);
        node.gpu.put(gpu_uuid, hop.into_production());
        return Ok(());
    }
    let result = pump_provider(&mut stream, &mut hop).await;
    match &result {
        Ok(()) => hop.shutdown("close", false),
        Err(_) => hop.shutdown("eof", true),
    }
    node.gpu.put(gpu_uuid, hop.into_production());
    result
}

async fn pump_provider(stream: &mut MeshStream, hop: &mut ProviderHop) -> Result<()> {
    loop {
        let frame: GpuMeshFrame = read_gpu_frame(&mut stream.recv).await?;
        hop.set_now(now_unix());
        let closing = matches!(frame, GpuMeshFrame::Close);
        let reply = hop.handle_frame(frame).map_err(|err| anyhow!(err))?;
        write_gpu_frame(&mut stream.send, &reply).await?;
        while let Some(applied) = hop.apply_next().map_err(|err| anyhow!(err))? {
            write_gpu_frame(&mut stream.send, &applied).await?;
        }
        if closing {
            break;
        }
    }
    Ok(())
}

/// Bridge local guest-control frames onto the provider mesh stream.
pub(crate) async fn serve_local<'a, 'b>(
    name: &str,
    node: &Node,
    mesh: Option<&Arc<Mesh>>,
    io: &'a mut ClientIo<'b>,
) -> Result<()> {
    let Some(mesh) = mesh else {
        io.send(&Response::GpuGuestRefused {
            code: "no_mesh".into(),
            message: crate::orbit::NO_MESH.into(),
        })
        .await?;
        return Ok(());
    };
    let instance = {
        let shard = node.shard.lock().await;
        shard.get(name).ok().cloned()
    };
    let Some(instance) = instance else {
        io.send(&Response::GpuGuestRefused {
            code: "unknown_instance".into(),
            message: format!("no instance named {name:?}"),
        })
        .await?;
        return Ok(());
    };
    let Some(attachment) = instance.gpu.clone() else {
        io.send(&Response::GpuGuestRefused {
            code: "no_gpu".into(),
            message: format!("instance {name:?} has no attached GPU"),
        })
        .await?;
        return Ok(());
    };
    io.send(&Response::GpuGuestAccepted {
        session_id: Uuid::new_v4().to_string(),
        projection_kind: PROJECTION_KIND.into(),
    })
    .await?;
    let here = node.device_name().await;
    if attachment.provider_device == here {
        return serve_local_provider(
            node,
            mesh.device_id(),
            &instance.id,
            attachment.provider_generation,
            attachment.memory_bytes,
            io,
        )
        .await;
    }
    mesh.gpu_session(
        &attachment.provider_device,
        &instance.id,
        attachment.provider_generation,
        io,
    )
    .await
}

/// Consumer-side bridge: local unix-socket guest frames onto an already
/// opened GPU mesh stream.
pub(crate) async fn bridge_client<'a, 'b>(
    mut stream: MeshStream,
    io: &'a mut ClientIo<'b>,
) -> Result<()> {
    let accepted: GpuMeshFrame = read_gpu_frame(&mut stream.recv).await?;
    let GpuMeshFrame::Accepted {
        session, credit, ..
    } = accepted
    else {
        io.send(&Response::GpuGuestRefused {
            code: "refused".into(),
            message: format!("{accepted:?}"),
        })
        .await?;
        return Ok(());
    };
    let mut sequence = 0u64;
    let mut credits = credit;
    loop {
        match io.next_request().await? {
            Request::GpuGuestFrame { frame } => {
                let reply = match frame {
                    GuestFrame::Open { .. } => GuestReply::Accepted {
                        abi: asterism_core::remote_gpu::ABI_VERSION,
                        projection_kind: PROJECTION_KIND.into(),
                        device_kind: guest::GuestDeviceKind::UnixEndpoint,
                        executor: asterism_core::remote_gpu::Executor::Reference,
                        credit: credits,
                    },
                    GuestFrame::Close => {
                        write_gpu_frame(&mut stream.send, &GpuMeshFrame::Close).await?;
                        let _ = read_gpu_frame(&mut stream.recv).await;
                        GuestReply::Closed
                    }
                    GuestFrame::Cancel { id } => {
                        write_gpu_frame(&mut stream.send, &GpuMeshFrame::Cancel { id }).await?;
                        match read_gpu_frame(&mut stream.recv).await? {
                            GpuMeshFrame::Cancelled { id } => {
                                credits = credits.saturating_add(1);
                                GuestReply::Cancelled { id }
                            }
                            GpuMeshFrame::Refused { message, .. } => GuestReply::Refused {
                                code: "cancel".into(),
                                message,
                            },
                            other => GuestReply::Refused {
                                code: "cancel".into(),
                                message: format!("{other:?}"),
                            },
                        }
                    }
                    GuestFrame::Cuda {
                        id,
                        call: guest::CudaCall::Unsupported { symbol },
                    } => GuestReply::Cuda {
                        id,
                        result: guest::CudaResult::Error {
                            cuda: guest::CUDA_ERROR_NOT_SUPPORTED,
                            message: format!(
                                "{symbol} is outside the implemented CUDA Driver surface"
                            ),
                        },
                    },
                    GuestFrame::Cuda { id, call } => {
                        match guest::abi_request_for(&session, sequence.saturating_add(1), &call) {
                            Err(_) => GuestReply::Cuda {
                                id,
                                result: match &call {
                                    guest::CudaCall::Init => guest::CudaResult::Init,
                                    guest::CudaCall::DriverGetVersion => {
                                        guest::CudaResult::DriverVersion {
                                            version: guest::CUDA_DRIVER_VERSION,
                                        }
                                    }
                                    guest::CudaCall::DeviceCount => {
                                        guest::CudaResult::DeviceCount { count: 1 }
                                    }
                                    guest::CudaCall::Synchronize
                                    | guest::CudaCall::CtxSynchronize => guest::CudaResult::Synced,
                                    other => guest::CudaResult::Error {
                                        cuda: guest::CUDA_ERROR_NOT_SUPPORTED,
                                        message: format!("{other:?} is session-local"),
                                    },
                                },
                            },
                            Ok(request) => {
                                if credits == 0 {
                                    GuestReply::Refused {
                                        code: "backpressure".into(),
                                        message: "GPU mesh credit window is empty".into(),
                                    }
                                } else {
                                    sequence = sequence
                                        .checked_add(1)
                                        .ok_or_else(|| anyhow!("GPU ABI sequence exhausted"))?;
                                    credits -= 1;
                                    write_gpu_frame(
                                        &mut stream.send,
                                        &GpuMeshFrame::Call { id, request },
                                    )
                                    .await?;
                                    let mut frame = read_gpu_frame(&mut stream.recv).await?;
                                    if let GpuMeshFrame::Credit { window } = frame {
                                        credits = window;
                                        frame = read_gpu_frame(&mut stream.recv).await?;
                                    }
                                    match frame {
                                        GpuMeshFrame::Reply { reply, .. } => {
                                            credits = credits.saturating_add(1);
                                            GuestReply::Cuda {
                                                id,
                                                result: guest::cuda_result_for(&call, reply),
                                            }
                                        }
                                        other => GuestReply::Refused {
                                            code: "mesh".into(),
                                            message: format!("{other:?}"),
                                        },
                                    }
                                }
                            }
                        }
                    }
                };
                io.send(&Response::GpuGuestReply { reply }).await?;
            }
            Request::GpuGuestClose => {
                write_gpu_frame(&mut stream.send, &GpuMeshFrame::Close).await?;
                break;
            }
            other => bail!("unexpected request during a GPU guest session: {other:?}"),
        }
    }
    Ok(())
}

async fn serve_local_provider<'a, 'b>(
    node: &Node,
    self_id: DeviceId,
    instance_id: &str,
    _generation: u64,
    memory_bytes: u64,
    io: &'a mut ClientIo<'b>,
) -> Result<()> {
    let Some((gpu_uuid, mut production)) = node.gpu.take() else {
        io.send(&Response::GpuGuestRefused {
            code: "device_lost".into(),
            message: "this device has no GPU provider service".into(),
        })
        .await?;
        return Ok(());
    };
    let peer = AuthenticatedPeer::from_mesh_identity(self_id.to_string())
        .map_err(|err| anyhow!(err.message))?;
    let now = now_unix();
    if let Err(err) = production.ensure_attached(&peer, instance_id, memory_bytes.max(1), now) {
        node.gpu.put(gpu_uuid, production);
        io.send(&Response::GpuGuestRefused {
            code: "attach".into(),
            message: err.message,
        })
        .await?;
        return Ok(());
    }
    let generation = production.authority().generation();
    let mut hop = ProviderHop::new(peer, production, now);
    hop.set_now(now);
    let open = GpuMeshOpen::new(instance_id, generation).map_err(|err| anyhow!(err))?;
    match hop.accept_open(open).map_err(|err| anyhow!(err))? {
        GpuMeshFrame::Accepted { .. } => {}
        GpuMeshFrame::Refused { message, .. }
        | GpuMeshFrame::DeviceLost { reason: message }
        | GpuMeshFrame::Revoked {
            instance_id: message,
        } => {
            node.gpu.put(gpu_uuid, hop.into_production());
            io.send(&Response::GpuGuestRefused {
                code: "refused".into(),
                message,
            })
            .await?;
            return Ok(());
        }
        GpuMeshFrame::Skew {
            expected_generation,
            observed,
        } => {
            node.gpu.put(gpu_uuid, hop.into_production());
            io.send(&Response::GpuGuestRefused {
                code: "skew".into(),
                message: format!(
                    "GPU generation skew: attachment {expected_generation}, provider {observed}"
                ),
            })
            .await?;
            return Ok(());
        }
        other => {
            node.gpu.put(gpu_uuid, hop.into_production());
            io.send(&Response::GpuGuestRefused {
                code: "refused".into(),
                message: format!("{other:?}"),
            })
            .await?;
            return Ok(());
        }
    }
    let result = pump_local(io, &mut hop, 0).await;
    match &result {
        Ok(()) => hop.shutdown("close", false),
        Err(_) => hop.shutdown("eof", true),
    }
    node.gpu.put(gpu_uuid, hop.into_production());
    result
}

async fn pump_local<'a, 'b>(
    io: &'a mut ClientIo<'b>,
    hop: &mut ProviderHop,
    mut sequence: u64,
) -> Result<()> {
    loop {
        match io.next_request().await? {
            Request::GpuGuestFrame { frame } => {
                hop.set_now(now_unix());
                let reply = apply_guest_on_hop(hop, frame, &mut sequence)?;
                io.send(&Response::GpuGuestReply { reply }).await?;
            }
            Request::GpuGuestClose => break,
            other => bail!("unexpected request during a GPU guest session: {other:?}"),
        }
    }
    Ok(())
}

fn apply_guest_on_hop(
    hop: &mut ProviderHop,
    frame: GuestFrame,
    sequence: &mut u64,
) -> Result<GuestReply> {
    match frame {
        GuestFrame::Open { .. } => Ok(GuestReply::Accepted {
            abi: asterism_core::remote_gpu::ABI_VERSION,
            projection_kind: PROJECTION_KIND.into(),
            device_kind: guest::GuestDeviceKind::UnixEndpoint,
            executor: hop.executor(),
            credit: DEFAULT_CREDIT_WINDOW,
        }),
        GuestFrame::Close => {
            hop.shutdown("close", false);
            Ok(GuestReply::Closed)
        }
        GuestFrame::Cancel { id } => {
            let reply = hop
                .handle_frame(GpuMeshFrame::Cancel { id })
                .map_err(|err| anyhow!(err))?;
            match reply {
                GpuMeshFrame::Cancelled { id } => Ok(GuestReply::Cancelled { id }),
                GpuMeshFrame::Refused { message, .. } => Ok(GuestReply::Refused {
                    code: "cancel".into(),
                    message,
                }),
                other => Ok(GuestReply::Refused {
                    code: "cancel".into(),
                    message: format!("{other:?}"),
                }),
            }
        }
        GuestFrame::Cuda { id, call } => match hop.session_cuda(&call) {
            Ok(result) => Ok(GuestReply::Cuda { id, result }),
            Err(_) => {
                let session = hop
                    .abi_session()
                    .ok_or_else(|| anyhow!("GPU ABI session is not open"))?
                    .to_owned();
                *sequence = sequence
                    .checked_add(1)
                    .ok_or_else(|| anyhow!("GPU ABI sequence exhausted"))?;
                let request = guest::abi_request_for(&session, *sequence, &call)
                    .map_err(|err| anyhow!(err))?;
                let _ack = hop
                    .handle_frame(GpuMeshFrame::Call { id, request })
                    .map_err(|err| anyhow!(err))?;
                match hop.apply_next().map_err(|err| anyhow!(err))? {
                    Some(GpuMeshFrame::Reply { reply, .. }) => Ok(GuestReply::Cuda {
                        id,
                        result: guest::cuda_result_for(&call, reply),
                    }),
                    Some(other) => Ok(GuestReply::Refused {
                        code: "mesh".into(),
                        message: format!("{other:?}"),
                    }),
                    None => Ok(GuestReply::Cancelled { id }),
                }
            }
        },
    }
}

async fn write_gpu_frame(send: &mut SendStream, frame: &GpuMeshFrame) -> Result<()> {
    let bytes = encode_frame(frame).map_err(|err| anyhow!(err))?;
    send.write_all(&bytes).await?;
    Ok(())
}

async fn read_gpu_frame(recv: &mut RecvStream) -> Result<GpuMeshFrame> {
    let mut len = [0u8; 4];
    recv.read_exact(&mut len).await?;
    let n = u32::from_be_bytes(len) as usize;
    if n > asterism_core::remote_gpu::MAX_WIRE_FRAME_BYTES {
        bail!("GPU mesh frame of {n} bytes exceeds the limit");
    }
    let mut body = vec![0u8; n];
    recv.read_exact(&mut body).await?;
    let mut framed = Vec::with_capacity(4 + n);
    framed.extend_from_slice(&len);
    framed.extend_from_slice(&body);
    decode_frame(&framed).map_err(|err| anyhow!(err))
}
