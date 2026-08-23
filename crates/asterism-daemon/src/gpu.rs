//! Guest NVIDIA projection adapter for `astd`.
//!
//! Local unix-socket frames from the instance-bound guest control hop are
//! forwarded onto a dedicated authenticated mesh stream. The opening frame
//! names the instance and provider generation only — no bearer, no backend
//! id, no LAN listener.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, bail, Result};
use uuid::Uuid;

use asterism_core::instance::now_unix;
use asterism_core::protocol::{Request, Response};
use asterism_core::remote_gpu::{
    AuthenticatedPeer, ControlErrorCode, Executor, LeaseAuthority, LeaseLimits, ProductionProvider,
};
use asterism_core::remote_gpu_cuda::CudaEngine;
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

/// In-memory provider GPU services on this device. Only the live CUDA
/// constructor is installed in production; reference providers are fixtures.
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

    /// Load the real NVIDIA driver and put that exact executor behind the
    /// token-free, instance-bound mesh path. A host without admitted hardware
    /// remains unavailable; it never falls back to the reference executor.
    pub fn install_live(
        &self,
        device_name: String,
        device_id: String,
        gpu_uuid: Option<&str>,
        bootstrap: Option<(&str, &str, u64)>,
    ) -> Result<()> {
        let engine = CudaEngine::open_live(gpu_uuid).map_err(|error| anyhow!(error))?;
        let identity = engine.identity().clone();
        let lease_ttl_secs = if bootstrap.is_some() { 300 } else { 30 };
        let authority = LeaseAuthority::new(
            device_name,
            device_id,
            identity.uuid.clone(),
            1,
            LeaseLimits {
                total_memory_bytes: identity.memory_bytes,
                max_memory_per_lease: identity.memory_bytes,
                max_leases: 8,
                lease_ttl_secs,
            },
        )
        .map_err(|error| anyhow!(error))?;
        let mut provider =
            ProductionProvider::connect(authority, engine).map_err(|error| anyhow!(error))?;
        if let Some((consumer_device_id, instance_id, memory_bytes)) = bootstrap {
            let peer = AuthenticatedPeer::from_mesh_identity(consumer_device_id)
                .map_err(|error| anyhow!(error))?;
            provider
                .authority_mut()
                .attach(&peer, instance_id, memory_bytes, now_unix())
                .map_err(|error| anyhow!(error))?;
        }
        self.insert(identity.uuid, provider);
        Ok(())
    }

    fn status(&self) -> Response {
        let providers = self.providers.lock().expect("GPU provider registry");
        match providers.values().next() {
            Some(provider) => Response::GpuProvider {
                available: true,
                executor: match provider.executor() {
                    Executor::Cuda => "cuda".into(),
                    Executor::Reference => "reference".into(),
                },
                gpu_uuid: provider.authority().gpu_uuid().to_owned(),
                generation: provider.authority().generation(),
                hardware_cuda_executed: provider.hardware_cuda_executed(),
                helper_socket: asterism_core::paths::socket_path().display().to_string(),
            },
            None => Response::GpuProvider {
                available: false,
                executor: "none".into(),
                gpu_uuid: String::new(),
                generation: 0,
                hardware_cuda_executed: false,
                helper_socket: String::new(),
            },
        }
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

pub(crate) fn claims(request: &Request) -> bool {
    matches!(request, Request::GpuProviderStatus)
}

pub(crate) fn serve(request: Request, node: &Node) -> Response {
    match request {
        Request::GpuProviderStatus => node.gpu.status(),
        _ => Response::Error {
            message: "not a GPU provider request".into(),
        },
    }
}

/// Serve one authenticated GPU mesh stream on the provider device.
pub(crate) async fn serve_mesh(
    mut stream: MeshStream,
    peer: DeviceId,
    node: &Node,
    instance_id: String,
    provider_generation: u64,
    versions: asterism_core::remote_gpu::AbiRange,
) -> Result<()> {
    let open = match GpuMeshOpen::new(instance_id, provider_generation, versions) {
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
    let accepted = hop.accept_open(open).map_err(|err| anyhow!(err))?;
    write_gpu_frame(&mut stream.send, &accepted).await?;
    if !matches!(accepted, GpuMeshFrame::Accepted { .. }) {
        node.gpu.put(gpu_uuid, hop.into_production());
        return Ok(());
    }
    let result = pump_provider(&mut stream, &mut hop).await;
    node.gpu.put(gpu_uuid, hop.into_production());
    result
}

async fn pump_provider(stream: &mut MeshStream, hop: &mut ProviderHop) -> Result<()> {
    loop {
        let frame: GpuMeshFrame = read_gpu_frame(&mut stream.recv).await?;
        let closing = matches!(frame, GpuMeshFrame::Close);
        let reply = hop.handle_frame(frame).map_err(|err| anyhow!(err))?;
        write_gpu_frame(&mut stream.send, &reply).await?;
        if closing {
            break;
        }
    }
    Ok(())
}

/// Bridge local guest-control frames onto the provider mesh stream.
pub(crate) async fn serve_local<'a, 'b>(
    name: &str,
    versions: asterism_core::remote_gpu::AbiRange,
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
            versions,
            io,
        )
        .await;
    }
    mesh.gpu_session(
        &attachment.provider_device,
        &instance.id,
        attachment.provider_generation,
        versions,
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
                        if credits == 0 {
                            GuestReply::Refused {
                                code: "backpressure".into(),
                                message: "GPU mesh credit window is empty".into(),
                            }
                        } else {
                            sequence = sequence
                                .checked_add(1)
                                .ok_or_else(|| anyhow!("GPU ABI sequence exhausted"))?;
                            let request = guest::abi_request_for(&session, sequence, &call)
                                .map_err(|err| anyhow!(err))?;
                            credits -= 1;
                            write_gpu_frame(&mut stream.send, &GpuMeshFrame::Call { id, request })
                                .await?;
                            match read_gpu_frame(&mut stream.recv).await? {
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
    generation: u64,
    versions: asterism_core::remote_gpu::AbiRange,
    io: &'a mut ClientIo<'b>,
) -> Result<()> {
    let Some((gpu_uuid, production)) = node.gpu.take() else {
        io.send(&Response::GpuGuestRefused {
            code: "device_lost".into(),
            message: "this device has no GPU provider service".into(),
        })
        .await?;
        return Ok(());
    };
    let peer = AuthenticatedPeer::from_mesh_identity(self_id.to_string())
        .map_err(|err| anyhow!(err.message))?;
    let mut hop = ProviderHop::new(peer, production, now_unix());
    let open = GpuMeshOpen::new(instance_id, generation, versions).map_err(|err| anyhow!(err))?;
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
        GuestFrame::Close => Ok(GuestReply::Closed),
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
        GuestFrame::Cuda { id, call } => match call {
            guest::CudaCall::Init => Ok(GuestReply::Cuda {
                id,
                result: guest::CudaResult::Init,
            }),
            guest::CudaCall::DeviceCount => Ok(GuestReply::Cuda {
                id,
                result: guest::CudaResult::DeviceCount { count: 1 },
            }),
            guest::CudaCall::DeviceName { ordinal } if ordinal == 0 => Ok(GuestReply::Cuda {
                id,
                result: guest::CudaResult::DeviceName {
                    name: "Asterism remote NVIDIA (projected)".into(),
                },
            }),
            guest::CudaCall::Synchronize => Ok(GuestReply::Cuda {
                id,
                result: guest::CudaResult::Synced,
            }),
            guest::CudaCall::Unsupported { symbol } => Ok(GuestReply::Cuda {
                id,
                result: guest::CudaResult::Error {
                    cuda: guest::CUDA_ERROR_NOT_SUPPORTED,
                    message: format!("{symbol} is outside the implemented CUDA Driver surface"),
                },
            }),
            call => {
                let session = hop
                    .abi_session()
                    .ok_or_else(|| anyhow!("GPU ABI session is not open"))?
                    .to_owned();
                *sequence = sequence
                    .checked_add(1)
                    .ok_or_else(|| anyhow!("GPU ABI sequence exhausted"))?;
                let request = guest::abi_request_for(&session, *sequence, &call)
                    .map_err(|err| anyhow!(err))?;
                let reply = hop
                    .handle_frame(GpuMeshFrame::Call { id, request })
                    .map_err(|err| anyhow!(err))?;
                match reply {
                    GpuMeshFrame::Reply { reply, .. } => Ok(GuestReply::Cuda {
                        id,
                        result: guest::cuda_result_for(&call, reply),
                    }),
                    other => Ok(GuestReply::Refused {
                        code: "mesh".into(),
                        message: format!("{other:?}"),
                    }),
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
