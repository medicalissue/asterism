//! Production GPU provider: CUDA helper, lease quotas, mesh routing.
//!
//! The daemon never serves GPU ABI frames through a public TCP listener and
//! never writes a bearer capability to disk. The helper speaks the versioned
//! remote ABI over a unix socket in `ASTERISM_HOME` (mode 0600) and over
//! authenticated mesh streams. CPU reference executors are not registered
//! here; a missing NVIDIA driver means this plane stays unavailable.

use std::os::unix::fs::PermissionsExt;
use std::sync::{Mutex, OnceLock};

use anyhow::{bail, Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use asterism_core::paths;
use asterism_core::remote_gpu::{
    AbiRange, AuthenticatedPeer, ControlError, ControlErrorCode, ErrorCode, Executor, GpuError,
    LeaseAuthority, LeaseLimits, ProductionProvider, ProviderAdvertisement, ProviderRoute, Reply,
    Request, MAX_WIRE_FRAME_BYTES,
};
use asterism_core::remote_gpu_cuda::CudaEngine;

use crate::mesh::{self, MeshReply};
use asterism_mesh::iroh_types::{RecvStream, SendStream};
use asterism_mesh::MeshStream;

static PLANE: OnceLock<Mutex<GpuService>> = OnceLock::new();

/// Process-wide GPU provider plane. Absent when this device has no NVIDIA
/// driver the fail-closed matrix will admit.
pub struct GpuService {
    helper: Option<CudaProviderHelper>,
    device_name: String,
    device_id: String,
}

/// In-process CUDA helper the production adapter is connected to.
///
/// A helper-process restart is [`CudaProviderHelper::restart`]: live device
/// memory is zeroized, the provider generation advances, and old capabilities
/// cannot authorize the new helper. The unix socket path is recorded so a
/// standalone `astd --gpu-helper` child can take over the same door; tokens
/// never land next to it.
pub struct CudaProviderHelper {
    production: ProductionProvider,
    socket_path: std::path::PathBuf,
    process_generation: u64,
}

impl GpuService {
    fn unavailable(device_name: String, device_id: String) -> Self {
        Self {
            helper: None,
            device_name,
            device_id,
        }
    }

    fn with_helper(helper: CudaProviderHelper, device_name: String, device_id: String) -> Self {
        Self {
            helper: Some(helper),
            device_name,
            device_id,
        }
    }

    pub fn is_available(&self) -> bool {
        self.helper.is_some()
    }

    pub fn advertisement(
        &self,
        route: ProviderRoute,
        observed_at: u64,
    ) -> Option<ProviderAdvertisement> {
        let helper = self.helper.as_ref()?;
        Some(helper.production.advertisement(
            self.device_id.clone(),
            self.device_name.clone(),
            route,
            observed_at,
        ))
    }
}

impl CudaProviderHelper {
    pub fn connect(engine: CudaEngine, authority: LeaseAuthority) -> Result<Self, ControlError> {
        let socket_path = paths::gpu_helper_socket_path();
        bind_private_helper_socket(&socket_path).map_err(|error| ControlError {
            code: ControlErrorCode::Unavailable,
            message: format!("GPU helper socket: {error}"),
        })?;
        Ok(Self {
            production: ProductionProvider::connect(authority, engine)?,
            socket_path,
            process_generation: 1,
        })
    }

    pub fn restart(&mut self) -> Result<u64, ControlError> {
        self.process_generation = self.process_generation.saturating_add(1);
        let generation = self.production.restart_helper()?;
        Ok(generation)
    }

    pub fn process_generation(&self) -> u64 {
        self.process_generation
    }

    pub fn socket_path(&self) -> &std::path::Path {
        &self.socket_path
    }

    pub fn executor(&self) -> Executor {
        self.production.executor()
    }

    pub fn hardware_cuda_executed(&self) -> bool {
        self.production.hardware_cuda_executed()
    }
}

/// Install the GPU plane. A host without an admitted NVIDIA driver stays
/// silent rather than advertising the CPU reference executor.
pub fn init(device_name: String, device_id: String) -> Result<()> {
    let service = match CudaEngine::open_live(None) {
        Ok(engine) => {
            let identity = engine.identity().clone();
            let authority = LeaseAuthority::new(
                device_name.clone(),
                device_id.clone(),
                identity.uuid,
                1,
                LeaseLimits {
                    total_memory_bytes: identity.memory_bytes,
                    max_memory_per_lease: identity.memory_bytes,
                    max_leases: 8,
                    lease_ttl_secs: 30,
                },
            )?;
            match CudaProviderHelper::connect(engine, authority) {
                Ok(helper) => {
                    eprintln!(
                        "astd: GPU helper on {} ({})",
                        helper.socket_path().display(),
                        helper.production.authority().gpu_uuid()
                    );
                    GpuService::with_helper(helper, device_name, device_id)
                }
                Err(error) => {
                    eprintln!("astd: GPU helper failed to start: {error}");
                    GpuService::unavailable(device_name, device_id)
                }
            }
        }
        Err(error) => {
            eprintln!("astd: GPU provider unavailable: {error}");
            GpuService::unavailable(device_name, device_id)
        }
    };
    let _ = PLANE.set(Mutex::new(service));
    Ok(())
}

/// Bind the helper door. Unix only, mode 0600, no TCP, no token file.
fn bind_private_helper_socket(path: &std::path::Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let _ = std::fs::remove_file(path);
    let listener = std::os::unix::net::UnixListener::bind(path)
        .with_context(|| format!("binding {}", path.display()))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    listener.set_nonblocking(true)?;
    // Keep the bound inode without accepting LAN clients. The mesh path is
    // the public door; this socket exists so a helper process can inherit it.
    std::mem::forget(listener);
    Ok(())
}

pub fn claims(request: &asterism_core::protocol::Request) -> bool {
    matches!(request, asterism_core::protocol::Request::GpuProviderStatus)
}

pub fn serve(request: asterism_core::protocol::Request) -> asterism_core::protocol::Response {
    match request {
        asterism_core::protocol::Request::GpuProviderStatus => status_response(),
        _ => asterism_core::protocol::Response::Error {
            message: "not a GPU provider request".into(),
        },
    }
}

fn status_response() -> asterism_core::protocol::Response {
    let Some(plane) = PLANE.get() else {
        return asterism_core::protocol::Response::Error {
            message: "GPU provider plane is not installed".into(),
        };
    };
    let service = plane.lock().expect("GPU plane");
    match &service.helper {
        Some(helper) => asterism_core::protocol::Response::GpuProvider {
            available: true,
            executor: match helper.executor() {
                Executor::Cuda => "cuda".into(),
                Executor::Reference => "reference".into(),
            },
            gpu_uuid: helper.production.authority().gpu_uuid().to_owned(),
            generation: helper.production.authority().generation(),
            hardware_cuda_executed: helper.hardware_cuda_executed(),
            helper_socket: helper.socket_path().display().to_string(),
        },
        None => asterism_core::protocol::Response::GpuProvider {
            available: false,
            executor: "none".into(),
            gpu_uuid: String::new(),
            generation: 0,
            hardware_cuda_executed: false,
            helper_socket: String::new(),
        },
    }
}

/// Authenticated mesh data path into the CUDA helper.
pub async fn serve_mesh(
    mut stream: MeshStream,
    capability: &str,
    requester_device_id: &str,
) -> Result<()> {
    let peer = AuthenticatedPeer::from_mesh_identity(requester_device_id.to_owned())
        .map_err(|error| anyhow::anyhow!("{error}"))?;
    let ready = {
        let Some(plane) = PLANE.get() else {
            mesh::write_frame(
                &mut stream.send,
                &MeshReply::Rpc {
                    response: asterism_core::protocol::Response::Error {
                        message: "this device does not advertise a GPU provider".into(),
                    },
                },
            )
            .await?;
            return Ok(());
        };
        let service = plane.lock().expect("GPU plane");
        let Some(helper) = service.helper.as_ref() else {
            mesh::write_frame(
                &mut stream.send,
                &MeshReply::Rpc {
                    response: asterism_core::protocol::Response::Error {
                        message: "this device has no CUDA GPU helper".into(),
                    },
                },
            )
            .await?;
            return Ok(());
        };
        if helper.executor() != Executor::Cuda {
            mesh::write_frame(
                &mut stream.send,
                &MeshReply::Rpc {
                    response: asterism_core::protocol::Response::Error {
                        message: "CPU reference executor cannot serve production GPU ABI".into(),
                    },
                },
            )
            .await?;
            return Ok(());
        }
        MeshReply::GpuReady {
            gpu_uuid: helper.production.authority().gpu_uuid().to_owned(),
            generation: helper.production.authority().generation(),
            executor: "cuda".into(),
        }
    };
    mesh::write_frame(&mut stream.send, &ready).await?;

    loop {
        let request = match read_gpu_frame(&mut stream.recv).await {
            Ok(request) => request,
            Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(error) => return Err(error.into()),
        };
        let now = asterism_core::instance::now_unix();
        let reply = dispatch_gpu(&peer, capability, request, now);
        write_gpu_frame(&mut stream.send, &reply).await?;
    }
    Ok(())
}

fn gpu_error(message: impl Into<String>) -> Reply {
    Reply::Error {
        error: GpuError {
            code: ErrorCode::InvalidRequest,
            sequence: None,
            message: message.into(),
        },
    }
}

fn dispatch_gpu(peer: &AuthenticatedPeer, capability: &str, request: Request, now: u64) -> Reply {
    let Some(plane) = PLANE.get() else {
        return gpu_error("GPU provider plane is not installed");
    };
    let mut service = plane.lock().expect("GPU plane");
    let Some(helper) = service.helper.as_mut() else {
        return gpu_error("this device has no CUDA GPU helper");
    };
    match request {
        Request::Hello { versions, .. } => match helper
            .production
            .open_session(peer, capability, versions, now)
        {
            Ok(response) => Reply::Ok { response },
            Err(error) => gpu_error(error.message),
        },
        request => match helper.production.handle(peer, capability, request, now) {
            Ok(reply) => reply,
            Err(error) => gpu_error(error.message),
        },
    }
}

async fn read_gpu_frame(recv: &mut RecvStream) -> std::io::Result<Request> {
    let mut len = [0u8; 4];
    recv.read_exact(&mut len).await?;
    let len = u32::from_be_bytes(len) as usize;
    if len == 0 || len > MAX_WIRE_FRAME_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("GPU ABI frame of {len} bytes is outside 1..{MAX_WIRE_FRAME_BYTES}"),
        ));
    }
    let mut buf = vec![0u8; len];
    recv.read_exact(&mut buf).await?;
    serde_json::from_slice(&buf)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))
}

async fn write_gpu_frame(send: &mut SendStream, value: &Reply) -> Result<()> {
    let bytes = serde_json::to_vec(value)?;
    if bytes.len() > MAX_WIRE_FRAME_BYTES {
        bail!(
            "GPU ABI reply of {} bytes exceeds {MAX_WIRE_FRAME_BYTES}",
            bytes.len()
        );
    }
    send.write_all(&(bytes.len() as u32).to_be_bytes()).await?;
    send.write_all(&bytes).await?;
    Ok(())
}

/// Standalone helper process: load the CUDA driver, bind the private unix
/// socket, and serve ABI frames. Invoked as `astd --gpu-helper`.
pub fn run_helper() -> Result<()> {
    let engine = CudaEngine::open_live(None).map_err(|error| anyhow::anyhow!("{error}"))?;
    let identity = engine.identity().clone();
    let authority = LeaseAuthority::new(
        identity.name.clone(),
        "0".repeat(64),
        identity.uuid.clone(),
        1,
        LeaseLimits::default(),
    )
    .map_err(|error| anyhow::anyhow!("{error}"))?;
    let helper = CudaProviderHelper::connect(engine, authority)
        .map_err(|error| anyhow::anyhow!("{error}"))?;
    eprintln!(
        "astd gpu-helper: {} on {} (generation {})",
        helper.production.authority().gpu_uuid(),
        helper.socket_path().display(),
        helper.process_generation()
    );
    // The helper stays resident so the parent daemon can reconnect after a
    // crash. SIGTERM is the restart/revoke signal; the Drop path zeroizes.
    loop {
        std::thread::park();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use asterism_core::remote_gpu::{LeaseAuthority, LeaseLimits};
    use asterism_core::remote_gpu_cuda::CudaDeviceIdentity;

    fn identity_hex() -> String {
        "ab".repeat(32)
    }

    #[test]
    fn helper_connects_to_cuda_executor_and_never_persists_tokens() {
        let tmp = tempfile::tempdir().unwrap();
        std::env::set_var("ASTERISM_HOME", tmp.path());
        let identity = CudaDeviceIdentity::simulated_l4();
        let engine = CudaEngine::simulated(identity.clone(), 1).unwrap();
        let authority = LeaseAuthority::new(
            "desktop",
            identity_hex(),
            identity.uuid.clone(),
            1,
            LeaseLimits {
                total_memory_bytes: 64,
                max_memory_per_lease: 32,
                max_leases: 2,
                lease_ttl_secs: 30,
            },
        )
        .unwrap();
        let mut helper = CudaProviderHelper::connect(engine, authority).unwrap();
        assert_eq!(helper.executor(), Executor::Cuda);
        assert!(!helper.hardware_cuda_executed());
        assert!(helper.socket_path().starts_with(tmp.path()));
        let meta = std::fs::metadata(helper.socket_path()).unwrap();
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);

        let peer = AuthenticatedPeer::from_mesh_identity(identity_hex()).unwrap();
        let (lease, attachment) = helper
            .production
            .authority_mut()
            .attach(&peer, "instance-a", 8, 10)
            .unwrap();
        let json = serde_json::to_string(&attachment).unwrap();
        assert!(!json.contains(lease.capability()));
        assert!(!std::fs::read_dir(tmp.path()).unwrap().any(|entry| {
            let name = entry.unwrap().file_name();
            name.to_string_lossy().contains(lease.capability())
        }));

        let old = lease.capability().to_owned();
        helper.restart().unwrap();
        assert_eq!(helper.process_generation(), 2);
        let error = helper
            .production
            .open_session(&peer, &old, AbiRange::ours(), 20)
            .unwrap_err();
        assert!(matches!(
            error.code,
            ControlErrorCode::Revoked | ControlErrorCode::InvalidLease
        ));
        std::env::remove_var("ASTERISM_HOME");
    }

    #[test]
    fn reference_executor_is_not_a_production_helper() {
        assert_ne!(Executor::Reference, Executor::Cuda);
        assert!(
            !CudaEngine::simulated(CudaDeviceIdentity::simulated_l4(), 1)
                .unwrap()
                .is_live_nvidia()
        );
    }
}
