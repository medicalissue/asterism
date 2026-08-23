//! Guest NVIDIA projection adapter for `astd`.
//!
//! Local unix-socket frames from the instance-bound guest control hop are
//! forwarded onto a dedicated authenticated mesh stream. The opening frame
//! names the instance and provider generation only — no bearer, no backend
//! id, no LAN listener.

use std::collections::HashMap;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, bail, Result};
use uuid::Uuid;

use asterism_core::instance::now_unix;
use asterism_core::protocol::{Request, Response};
use asterism_core::remote_gpu::{
    AbiRange, AuthenticatedPeer, ControlErrorCode, Executor, GpuAttachment, ProductionProvider,
    ProviderAdvertisement, ProviderRoute,
};
use asterism_core::remote_gpu_guest::{
    self as guest, GuestFrame, GuestReply, DEFAULT_CREDIT_WINDOW, PROJECTION_KIND,
};
use asterism_core::remote_gpu_nvidia::{
    admit_cuda_inventory, production_for, CudaInventory, NvidiaDevice,
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

    /// Register providers admitted from live `nvidia-smi` inventory. Missing
    /// tooling or zero devices means zero providers; the reference executor
    /// is test-only and can never enter this registry.
    pub async fn register_hardware(&self, device_name: &str, device_id: &str) -> Result<usize> {
        let Some(inventory) = live_nvidia_inventory().await? else {
            return Ok(0);
        };
        let admitted = admit_cuda_inventory(&inventory).map_err(|err| anyhow!(err.message))?;
        let count = admitted.len();
        let mut providers = self
            .providers
            .lock()
            .map_err(|_| anyhow!("GPU provider registry lock poisoned"))?;
        for gpu in admitted {
            let uuid = gpu.device.uuid.clone();
            let provider = production_for(&gpu, device_name, device_id, 1)
                .map_err(|err| anyhow!(err.message))?;
            providers.insert(uuid, provider);
        }
        Ok(count)
    }

    fn take(&self, gpu_uuid: &str) -> Option<(String, ProductionProvider)> {
        let mut providers = self.providers.lock().ok()?;
        providers
            .remove(gpu_uuid)
            .map(|provider| (gpu_uuid.to_owned(), provider))
    }

    fn put(&self, gpu_uuid: String, provider: ProductionProvider) {
        if let Ok(mut providers) = self.providers.lock() {
            providers.insert(gpu_uuid, provider);
        }
    }

    fn advertisements(&self) -> Vec<ProviderAdvertisement> {
        let Ok(providers) = self.providers.lock() else {
            return Vec::new();
        };
        providers
            .values()
            .map(|provider| {
                let diagnostic = provider.authority().diagnostics();
                let limits = provider.authority().limits();
                ProviderAdvertisement {
                    device_id: diagnostic.provider_device_id,
                    device_name: diagnostic.provider_device,
                    gpu_uuid: diagnostic.gpu_uuid,
                    device_name_cuda: provider.capabilities().device_name.clone(),
                    executor: provider.capabilities().executor,
                    versions: AbiRange::ours(),
                    total_memory_bytes: diagnostic.total_memory_bytes,
                    leased_memory_bytes: diagnostic.leased_memory_bytes,
                    max_leases: limits.max_leases,
                    active_leases: diagnostic.active_leases,
                    generation: diagnostic.generation,
                    health: diagnostic.health,
                    route: ProviderRoute::Direct { rtt_us: 0 },
                    observed_at: now_unix(),
                }
            })
            .collect()
    }

    fn revoke(&self, gpu_uuid: &str, instance_id: &str) -> bool {
        let Ok(mut providers) = self.providers.lock() else {
            return false;
        };
        providers
            .get_mut(gpu_uuid)
            .is_some_and(|provider| provider.revoke_instance(instance_id))
    }

    fn attach(
        &self,
        gpu_uuid: &str,
        consumer_device_id: &str,
        instance_id: &str,
        memory_bytes: u64,
    ) -> Result<GpuAttachment> {
        let peer = AuthenticatedPeer::from_mesh_identity(consumer_device_id.to_owned())
            .map_err(|err| anyhow!(err.message))?;
        let mut providers = self
            .providers
            .lock()
            .map_err(|_| anyhow!("GPU provider registry lock poisoned"))?;
        let provider = providers
            .get_mut(gpu_uuid)
            .ok_or_else(|| anyhow!("no NVIDIA provider with UUID {gpu_uuid:?}"))?;
        provider
            .authority_mut()
            .attach(&peer, instance_id, memory_bytes, now_unix())
            .map(|(_, attachment)| attachment)
            .map_err(|err| anyhow!(err.message))
    }
}

pub(crate) fn is_plane_request(request: &Request) -> bool {
    matches!(
        request,
        Request::GpuProviderList
            | Request::GpuProviderAttach { .. }
            | Request::GpuProviderRevoke { .. }
    )
}

pub(crate) fn serve_plane(request: Request, node: &Node) -> Response {
    match request {
        Request::GpuProviderList => Response::GpuProviders {
            providers: node.gpu.advertisements(),
        },
        Request::GpuProviderAttach {
            gpu_uuid,
            consumer_device_id,
            instance_id,
            memory_bytes,
        } => match node
            .gpu
            .attach(&gpu_uuid, &consumer_device_id, &instance_id, memory_bytes)
        {
            Ok(attachment) => Response::GpuProviderAttached { attachment },
            Err(err) => Response::Error {
                message: format!("{err:#}"),
            },
        },
        Request::GpuProviderRevoke {
            gpu_uuid,
            instance_id,
        } => Response::GpuProviders {
            providers: {
                node.gpu.revoke(&gpu_uuid, &instance_id);
                node.gpu.advertisements()
            },
        },
        _ => Response::Error {
            message: "not a GPU provider-plane request".into(),
        },
    }
}

pub(crate) async fn resolve_attach(
    name: String,
    provider_device: Option<String>,
    gpu_uuid: Option<String>,
    memory_bytes: u64,
    node: &Node,
    mesh: Option<&Arc<Mesh>>,
) -> Result<Request> {
    if memory_bytes == 0 {
        bail!("a GPU attachment must reserve at least one byte");
    }
    let here = node.device_name().await;
    let mesh = mesh.ok_or_else(|| anyhow!(crate::orbit::NO_MESH))?;
    let instance = control_instance(&name, node, Some(mesh)).await?;
    if instance.status == asterism_core::instance::Status::Running {
        bail!("instance {name:?} is running — `ast down {name}` before attaching a GPU");
    }
    if instance.gpu.is_some() {
        bail!("instance {name:?} already has a GPU attached");
    }
    let consumer_device_id = if instance.cpu_device == here {
        mesh.device_id().to_string()
    } else {
        mesh.devices()
            .await
            .into_iter()
            .find(|device| device.name == instance.cpu_device)
            .map(|device| device.device_id)
            .ok_or_else(|| {
                anyhow!(
                    "instance CPU device {:?} is not in this orbit",
                    instance.cpu_device
                )
            })?
    };
    let target = provider_device.unwrap_or_else(|| here.clone());
    let response = if target == here {
        serve_plane(Request::GpuProviderList, node)
    } else {
        mesh.proxy(&target, Request::GpuProviderList).await?
    };
    let Response::GpuProviders { providers } = response else {
        bail!("device {target:?} did not answer GPU inventory")
    };
    let provider = providers
        .into_iter()
        .filter(|candidate| candidate.executor == Executor::Cuda)
        .filter(|candidate| {
            gpu_uuid
                .as_ref()
                .is_none_or(|uuid| candidate.gpu_uuid == *uuid)
        })
        .filter(|candidate| candidate.health.is_ready())
        .filter(|candidate| {
            candidate
                .total_memory_bytes
                .saturating_sub(candidate.leased_memory_bytes)
                >= memory_bytes
                && candidate.active_leases < candidate.max_leases
        })
        .min_by(|left, right| left.gpu_uuid.cmp(&right.gpu_uuid))
        .ok_or_else(|| anyhow!("device {target:?} has no eligible NVIDIA GPU provider"))?;
    let attach = Request::GpuProviderAttach {
        gpu_uuid: provider.gpu_uuid,
        consumer_device_id,
        instance_id: instance.id,
        memory_bytes,
    };
    let response = if target == here {
        serve_plane(attach, node)
    } else {
        mesh.proxy(&target, attach).await?
    };
    match response {
        Response::GpuProviderAttached { attachment } => {
            Ok(Request::AttachGpuResolved { name, attachment })
        }
        Response::Error { message } => bail!(message),
        other => bail!("device {target:?} answered GPU attach with {other:?}"),
    }
}

async fn control_instance(
    name: &str,
    node: &Node,
    mesh: Option<&Arc<Mesh>>,
) -> Result<asterism_core::instance::Instance> {
    if node.shard.lock().await.holds(name) {
        return Ok(node.shard.lock().await.get(name)?.clone());
    }
    let mesh = mesh.ok_or_else(|| anyhow!(crate::orbit::NO_MESH))?;
    let owner = mesh
        .locate(name)
        .await?
        .ok_or_else(|| anyhow!("no instance named {name:?}"))?;
    match mesh
        .proxy(
            &owner,
            Request::Status {
                name: name.to_owned(),
            },
        )
        .await?
    {
        Response::Instance { instance, .. } => Ok(instance),
        Response::Error { message } => bail!(message),
        other => bail!("instance owner answered GPU control with {other:?}"),
    }
}

pub(crate) async fn revoke_for_detach(
    name: &str,
    node: &Node,
    mesh: Option<&Arc<Mesh>>,
) -> Result<()> {
    let instance = control_instance(name, node, mesh).await?;
    instance
        .gpu
        .as_ref()
        .ok_or_else(|| anyhow!("instance {name:?} has no GPU attached"))?;
    revoke_attachment(&instance, node, mesh).await
}

/// Instance removal is also a detach boundary. Return a live provider lease
/// before deleting the immutable instance identity, while treating an
/// instance with no GPU as the ordinary remove path.
pub(crate) async fn revoke_for_remove(
    name: &str,
    node: &Node,
    mesh: Option<&Arc<Mesh>>,
) -> Result<()> {
    let instance = control_instance(name, node, mesh).await?;
    if instance.gpu.is_none() {
        return Ok(());
    }
    revoke_attachment(&instance, node, mesh).await
}

async fn revoke_attachment(
    instance: &asterism_core::instance::Instance,
    node: &Node,
    mesh: Option<&Arc<Mesh>>,
) -> Result<()> {
    let here = node.device_name().await;
    let attachment = instance
        .gpu
        .as_ref()
        .expect("caller checked GPU attachment");
    let request = Request::GpuProviderRevoke {
        gpu_uuid: attachment.provider_gpu_uuid.clone(),
        instance_id: instance.id.clone(),
    };
    let response = if attachment.provider_device == here {
        serve_plane(request, node)
    } else {
        let mesh = mesh.ok_or_else(|| anyhow!(crate::orbit::NO_MESH))?;
        mesh.proxy(&attachment.provider_device, request).await?
    };
    match response {
        Response::GpuProviders { .. } => Ok(()),
        Response::Error { message } => bail!(message),
        other => bail!("GPU provider answered detach with {other:?}"),
    }
}

async fn nvidia_smi(args: &[&str]) -> Result<Option<String>> {
    let output = match tokio::time::timeout(
        std::time::Duration::from_secs(3),
        tokio::process::Command::new("nvidia-smi")
            .args(args)
            .output(),
    )
    .await
    {
        Err(_) => bail!("nvidia-smi inventory timed out after 3 seconds"),
        Ok(Err(err)) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Ok(Err(err)) => return Err(err.into()),
        Ok(Ok(output)) => output,
    };
    if !output.status.success() {
        // A present tool with no driver/device is absence, never a synthetic
        // provider. Keep startup operational on CPU-only machines.
        return Ok(None);
    }
    String::from_utf8(output.stdout)
        .map(Some)
        .map_err(|err| anyhow!("nvidia-smi returned non-UTF-8 inventory: {err}"))
}

async fn live_nvidia_inventory() -> Result<Option<CudaInventory>> {
    let Some(rows) = nvidia_smi(&[
        "--query-gpu=index,uuid,name,memory.total,compute_cap,driver_version",
        "--format=csv,noheader,nounits",
    ])
    .await?
    else {
        return Ok(None);
    };
    let Some(summary) = nvidia_smi(&[]).await? else {
        return Ok(None);
    };
    parse_live_inventory(&rows, &summary).map(Some)
}

fn parse_live_inventory(rows: &str, summary: &str) -> Result<CudaInventory> {
    let cuda_runtime_version = summary
        .split("CUDA Version:")
        .nth(1)
        .and_then(|tail| tail.split_whitespace().next())
        .ok_or_else(|| anyhow!("nvidia-smi did not report a CUDA Version"))?
        .trim_end_matches('|')
        .to_owned();
    let mut driver_version = None;
    let mut devices = Vec::new();
    for (line_no, row) in rows
        .lines()
        .filter(|line| !line.trim().is_empty())
        .enumerate()
    {
        let fields = row.split(',').map(str::trim).collect::<Vec<_>>();
        if fields.len() != 6 {
            bail!(
                "nvidia-smi row {} has {} fields, expected 6",
                line_no + 1,
                fields.len()
            );
        }
        match &driver_version {
            Some(expected) if expected != fields[5] => {
                bail!("NVIDIA devices report inconsistent driver versions")
            }
            None => driver_version = Some(fields[5].to_owned()),
            _ => {}
        }
        let parsed = asterism_core::remote_gpu_nvidia::parse_nvidia_smi_gpu_csv(&format!(
            "{}, {}, {}, {}, {}",
            fields[0], fields[1], fields[2], fields[3], fields[4]
        ))
        .map_err(|err| anyhow!(err.message))?;
        devices.push(NvidiaDevice { ..parsed });
    }
    Ok(CudaInventory {
        driver_version: driver_version.ok_or_else(|| anyhow!("NVIDIA inventory is empty"))?,
        cuda_runtime_version,
        devices,
    })
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
    provider_gpu_uuid: String,
    provider_generation: u64,
    _memory_bytes: u64,
) -> Result<()> {
    let open = match GpuMeshOpen::new(&instance_id, provider_generation) {
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
    let Some((gpu_uuid, production)) = node.gpu.take(&provider_gpu_uuid) else {
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
    if let Err(err) = production.authority().authorize_instance(
        &peer,
        &instance_id,
        provider_generation,
        now_unix(),
    ) {
        node.gpu.put(gpu_uuid, production);
        write_gpu_frame(
            &mut stream.send,
            &GpuMeshFrame::Refused {
                code: err.code,
                message: err.message,
            },
        )
        .await?;
        return Ok(());
    }
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
        // Keep receiving while work is queued. A Call is acknowledged and
        // left cancellable for at least one scheduler turn; buffered Calls
        // and Cancels win the biased select before execution. This is the
        // production path, not merely the split-step unit seam.
        if hop.queued_len() > 0 {
            tokio::select! {
                biased;
                incoming = read_gpu_frame(&mut stream.recv) => {
                    let frame = incoming?;
                    hop.set_now(now_unix());
                    let closing = matches!(frame, GpuMeshFrame::Close);
                    let reply = hop.handle_frame(frame).map_err(|err| anyhow!(err))?;
                    write_gpu_frame(&mut stream.send, &reply).await?;
                    if closing { break; }
                }
                _ = tokio::task::yield_now() => {
                    if let Some(applied) = hop.apply_next().map_err(|err| anyhow!(err))? {
                        write_gpu_frame(&mut stream.send, &applied).await?;
                    }
                }
            }
        } else {
            let frame: GpuMeshFrame = read_gpu_frame(&mut stream.recv).await?;
            hop.set_now(now_unix());
            let closing = matches!(frame, GpuMeshFrame::Close);
            let reply = hop.handle_frame(frame).map_err(|err| anyhow!(err))?;
            write_gpu_frame(&mut stream.send, &reply).await?;
            if closing {
                break;
            }
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
            &attachment.provider_gpu_uuid,
            attachment.provider_generation,
            attachment.memory_bytes,
            io,
        )
        .await;
    }
    mesh.gpu_session(
        &attachment.provider_device,
        &instance.id,
        &attachment.provider_gpu_uuid,
        attachment.provider_generation,
        attachment.memory_bytes,
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
        session,
        credit,
        executor,
        ..
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
    let mut pending: HashMap<u64, guest::CudaCall> = HashMap::new();
    let mut pending_cancels = VecDeque::new();
    loop {
        tokio::select! {
            request = io.next_request() => match request? {
                Request::GpuGuestFrame { frame } => match frame {
                    GuestFrame::Open { .. } => {
                        let reply = GuestReply::Accepted {
                            abi: asterism_core::remote_gpu::ABI_VERSION,
                            projection_kind: PROJECTION_KIND.into(),
                            device_kind: guest::GuestDeviceKind::UnixEndpoint,
                            executor,
                            credit: credits,
                        };
                        io.send(&Response::GpuGuestReply { reply }).await?;
                    }
                    GuestFrame::Close => {
                        write_gpu_frame(&mut stream.send, &GpuMeshFrame::Close).await?;
                        io.send(&Response::GpuGuestReply { reply: GuestReply::Closed }).await?;
                        break;
                    }
                    GuestFrame::Cancel { id } => {
                        write_gpu_frame(&mut stream.send, &GpuMeshFrame::Cancel { id }).await?;
                        pending_cancels.push_back(id);
                    }
                    GuestFrame::Cuda {
                        id,
                        call: guest::CudaCall::Unsupported { symbol },
                    } => {
                        let reply = GuestReply::Cuda { id, result: guest::CudaResult::Error {
                            cuda: guest::CUDA_ERROR_NOT_SUPPORTED,
                            message: format!("{symbol} is outside the implemented CUDA Driver surface"),
                        }};
                        io.send(&Response::GpuGuestReply { reply }).await?;
                    }
                    GuestFrame::Cuda { id, call } => {
                        match guest::abi_request_for(&session, sequence.saturating_add(1), &call) {
                            Err(_) => {
                                let result = match &call {
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
                                };
                                io.send(&Response::GpuGuestReply { reply: GuestReply::Cuda { id, result } }).await?;
                            }
                            Ok(request) => {
                                if credits == 0 || pending.contains_key(&id) {
                                    io.send(&Response::GpuGuestReply { reply: GuestReply::Refused {
                                        code: "backpressure".into(),
                                        message: "GPU mesh credit window is empty or call id is already in flight".into(),
                                    }}).await?;
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
                                    pending.insert(id, call);
                                }
                            }
                        }
                    }
                },
                Request::GpuGuestClose => {
                    write_gpu_frame(&mut stream.send, &GpuMeshFrame::Close).await?;
                    break;
                }
                other => bail!("unexpected request during a GPU guest session: {other:?}"),
            },
            incoming = read_gpu_frame(&mut stream.recv) => {
                match incoming? {
                    GpuMeshFrame::Credit { window } => credits = window,
                    GpuMeshFrame::Reply { id, reply } => {
                        let Some(call) = pending.remove(&id) else {
                            bail!("GPU provider replied to unknown call id {id}");
                        };
                        credits = credits.saturating_add(1).min(DEFAULT_CREDIT_WINDOW);
                        io.send(&Response::GpuGuestReply {
                            reply: GuestReply::Cuda { id, result: guest::cuda_result_for(&call, reply) }
                        }).await?;
                    }
                    GpuMeshFrame::Cancelled { id } => {
                        pending.remove(&id);
                        if let Some(at) = pending_cancels.iter().position(|pending| *pending == id) {
                            pending_cancels.remove(at);
                        }
                        credits = credits.saturating_add(1).min(DEFAULT_CREDIT_WINDOW);
                        io.send(&Response::GpuGuestReply { reply: GuestReply::Cancelled { id } }).await?;
                    }
                    GpuMeshFrame::Refused { message, .. } => {
                        let id = pending_cancels.pop_front();
                        io.send(&Response::GpuGuestReply { reply: GuestReply::Refused {
                            code: if id.is_some() { "cancel" } else { "mesh" }.into(),
                            message,
                        }}).await?;
                    }
                    GpuMeshFrame::Close => break,
                    other => bail!("unexpected GPU provider frame: {other:?}"),
                }
            }
        }
    }
    Ok(())
}

async fn serve_local_provider<'a, 'b>(
    node: &Node,
    self_id: DeviceId,
    instance_id: &str,
    provider_gpu_uuid: &str,
    generation: u64,
    _memory_bytes: u64,
    io: &'a mut ClientIo<'b>,
) -> Result<()> {
    let Some((gpu_uuid, production)) = node.gpu.take(provider_gpu_uuid) else {
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
    if let Err(err) = production
        .authority()
        .authorize_instance(&peer, instance_id, generation, now)
    {
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
    let result = pump_local(io, &mut hop).await;
    match &result {
        Ok(()) => hop.shutdown("close", false),
        Err(_) => hop.shutdown("eof", true),
    }
    node.gpu.put(gpu_uuid, hop.into_production());
    result
}

async fn pump_local<'a, 'b>(io: &'a mut ClientIo<'b>, hop: &mut ProviderHop) -> Result<()> {
    let mut sequence = 0u64;
    let mut pending = VecDeque::new();
    loop {
        if hop.queued_len() > 0 {
            tokio::select! {
                biased;
                request = io.next_request() => {
                    hop.set_now(now_unix());
                    if !handle_local_request(io, hop, request?, &mut sequence, &mut pending).await? {
                        break;
                    }
                }
                _ = tokio::task::yield_now() => {
                    apply_local_next(io, hop, &mut pending).await?;
                }
            }
        } else {
            let request = io.next_request().await?;
            hop.set_now(now_unix());
            if !handle_local_request(io, hop, request, &mut sequence, &mut pending).await? {
                break;
            }
        }
    }
    Ok(())
}

async fn handle_local_request(
    io: &mut ClientIo<'_>,
    hop: &mut ProviderHop,
    request: Request,
    sequence: &mut u64,
    pending: &mut VecDeque<(u64, guest::CudaCall)>,
) -> Result<bool> {
    let Request::GpuGuestFrame { frame } = request else {
        if matches!(request, Request::GpuGuestClose) {
            return Ok(false);
        }
        bail!("unexpected request during a GPU guest session: {request:?}");
    };
    match frame {
        GuestFrame::Open { .. } => {
            io.send(&Response::GpuGuestReply {
                reply: GuestReply::Accepted {
                    abi: asterism_core::remote_gpu::ABI_VERSION,
                    projection_kind: PROJECTION_KIND.into(),
                    device_kind: guest::GuestDeviceKind::UnixEndpoint,
                    executor: hop.executor(),
                    credit: DEFAULT_CREDIT_WINDOW,
                },
            })
            .await?;
        }
        GuestFrame::Close => {
            hop.shutdown("close", false);
            io.send(&Response::GpuGuestReply {
                reply: GuestReply::Closed,
            })
            .await?;
            return Ok(false);
        }
        GuestFrame::Cancel { id } => {
            let reply = hop
                .handle_frame(GpuMeshFrame::Cancel { id })
                .map_err(|err| anyhow!(err))?;
            let reply = match reply {
                GpuMeshFrame::Cancelled { id } => {
                    if let Some(at) = pending.iter().position(|(pending, _)| *pending == id) {
                        pending.remove(at);
                    }
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
            };
            io.send(&Response::GpuGuestReply { reply }).await?;
        }
        GuestFrame::Cuda { id, call } => match hop.session_cuda(&call) {
            Ok(result) => {
                io.send(&Response::GpuGuestReply {
                    reply: GuestReply::Cuda { id, result },
                })
                .await?;
            }
            Err(_) => {
                let session = hop
                    .abi_session()
                    .ok_or_else(|| anyhow!("GPU ABI session is not open"))?
                    .to_owned();
                let next_sequence = sequence
                    .checked_add(1)
                    .ok_or_else(|| anyhow!("GPU ABI sequence exhausted"))?;
                let request = guest::abi_request_for(&session, next_sequence, &call)
                    .map_err(|err| anyhow!(err))?;
                match hop
                    .handle_frame(GpuMeshFrame::Call { id, request })
                    .map_err(|err| anyhow!(err))?
                {
                    GpuMeshFrame::Credit { .. } => {
                        *sequence = next_sequence;
                        pending.push_back((id, call));
                    }
                    GpuMeshFrame::Refused { message, .. } => {
                        io.send(&Response::GpuGuestReply {
                            reply: GuestReply::Refused {
                                code: "backpressure".into(),
                                message,
                            },
                        })
                        .await?;
                    }
                    other => {
                        io.send(&Response::GpuGuestReply {
                            reply: GuestReply::Refused {
                                code: "mesh".into(),
                                message: format!("{other:?}"),
                            },
                        })
                        .await?
                    }
                }
            }
        },
    }
    Ok(true)
}

async fn apply_local_next(
    io: &mut ClientIo<'_>,
    hop: &mut ProviderHop,
    pending: &mut VecDeque<(u64, guest::CudaCall)>,
) -> Result<()> {
    let Some(applied) = hop.apply_next().map_err(|err| anyhow!(err))? else {
        return Ok(());
    };
    let reply = match applied {
        GpuMeshFrame::Reply { id, reply } => {
            let Some(at) = pending.iter().position(|(pending, _)| *pending == id) else {
                bail!("local GPU provider replied to unknown call id {id}");
            };
            let (_, call) = pending.remove(at).expect("position checked");
            GuestReply::Cuda {
                id,
                result: guest::cuda_result_for(&call, reply),
            }
        }
        other => {
            let id = pending.pop_front().map(|(id, _)| id);
            GuestReply::Refused {
                code: "mesh".into(),
                message: match id {
                    Some(id) => format!("GPU call {id} failed: {other:?}"),
                    None => format!("{other:?}"),
                },
            }
        }
    };
    io.send(&Response::GpuGuestReply { reply }).await?;
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_live_nvidia_inventory_without_synthetic_devices() {
        let rows = "0, GPU-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee, NVIDIA L4, 23034, 8.9, 550.54.15\n\
                    1, GPU-11111111-2222-3333-4444-555555555555, NVIDIA L4, 23034, 8.9, 550.54.15\n";
        let summary = "NVIDIA-SMI 550.54.15  Driver Version: 550.54.15  CUDA Version: 12.4 |";
        let inventory = parse_live_inventory(rows, summary).unwrap();
        assert_eq!(inventory.driver_version, "550.54.15");
        assert_eq!(inventory.cuda_runtime_version, "12.4");
        assert_eq!(inventory.devices.len(), 2);
        assert_eq!(inventory.devices[0].index, 0);
        assert_eq!(inventory.devices[0].memory_bytes, 23_034 * 1024 * 1024);
        assert_eq!(inventory.devices[1].compute_capability, (8, 9));
    }

    #[test]
    fn malformed_or_empty_inventory_fails_closed() {
        assert!(parse_live_inventory("", "CUDA Version: 12.4").is_err());
        assert!(
            parse_live_inventory("0, GPU-a, NVIDIA L4, 23034, 8.9", "CUDA Version: 12.4").is_err()
        );
        assert!(Manager::default().advertisements().is_empty());
    }

    #[test]
    fn provider_control_attach_reserves_before_durable_metadata() {
        let inventory = parse_live_inventory(
            "0, GPU-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee, NVIDIA L4, 23034, 8.9, 550.54.15",
            "CUDA Version: 12.4",
        )
        .unwrap();
        let admitted = admit_cuda_inventory(&inventory).unwrap().remove(0);
        let manager = Manager::default();
        manager.providers.lock().unwrap().insert(
            admitted.device.uuid.clone(),
            production_for(&admitted, "desktop", &"a".repeat(64), 1).unwrap(),
        );

        let attachment = manager
            .attach(&admitted.device.uuid, &"b".repeat(64), "instance-id", 1024)
            .unwrap();
        assert_eq!(attachment.provider_gpu_uuid, admitted.device.uuid);
        let advertised = manager.advertisements();
        assert_eq!(advertised[0].active_leases, 1);
        assert_eq!(advertised[0].leased_memory_bytes, 1024);
        assert!(manager
            .attach(
                &attachment.provider_gpu_uuid,
                &"b".repeat(64),
                "other-instance",
                1024,
            )
            .is_err());
        assert!(manager.revoke(&attachment.provider_gpu_uuid, "instance-id"));
        assert_eq!(manager.advertisements()[0].active_leases, 0);
    }
}
