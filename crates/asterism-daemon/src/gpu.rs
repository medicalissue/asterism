//! Production GPU provider: CUDA helper, lease quotas, mesh routing.
//!
//! The daemon never serves GPU ABI frames through a public TCP listener and
//! never writes a bearer capability to disk. The helper speaks the versioned
//! remote ABI over a unix socket in `ASTERISM_HOME` (mode 0600) and over
//! authenticated mesh streams. CPU reference executors are not registered
//! here; a missing NVIDIA driver means this plane stays unavailable.
//!
//! Inbound and outbound [`crate::mesh::MeshRequest::GpuAbi`] frames are
//! proxied through a helper accept/client protocol on that socket. Each
//! accepted unix client is served on a bounded worker so a persistent local
//! session cannot starve later local or inbound-mesh clients. The listener is
//! not left idle and ABI dispatch is not duplicated in-process.

use std::io::{Read, Write};
use std::net::Shutdown;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread::{self, JoinHandle};
use std::time::Duration;

/// Concurrent unix ABI clients the helper will serve at once. Extra accepts
/// are refused so the accept thread cannot grow an unbounded worker set.
const MAX_HELPER_WORKERS: usize = 8;

use anyhow::{bail, Context, Result};

use asterism_core::paths;
use asterism_core::remote_gpu::{
    AuthenticatedPeer, ControlError, ControlErrorCode, ErrorCode, Executor, GpuError, HelperHello,
    HelperReady, LeaseAuthority, LeaseLimits, ProductionProvider, ProviderAdvertisement,
    ProviderRoute, Reply, Request, MAX_WIRE_FRAME_BYTES,
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

/// CUDA helper bound to `gpu.sock` (mode 0600).
///
/// A helper-process restart is [`CudaProviderHelper::restart`]: live device
/// memory is zeroized, the public generation advances only after a successful
/// wipe/restart, and old capabilities cannot authorize the new helper. A wipe
/// failure rolls the public generation back and keeps accounting. ABI clients
/// connect to the unix socket; tokens never land next to it.
pub struct CudaProviderHelper {
    pub production: Arc<Mutex<ProductionProvider>>,
    socket_path: PathBuf,
    process_generation: u64,
    shutdown: Arc<AtomicBool>,
    server: Option<JoinHandle<()>>,
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
        let production = helper.production.lock().expect("GPU helper");
        Some(production.advertisement(
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
        let listener = bind_private_helper_socket(&socket_path).map_err(|error| ControlError {
            code: ControlErrorCode::Unavailable,
            message: format!("GPU helper socket: {error}"),
        })?;
        let production = Arc::new(Mutex::new(ProductionProvider::connect(authority, engine)?));
        let process_generation = production
            .lock()
            .expect("GPU helper")
            .authority()
            .generation();
        let shutdown = Arc::new(AtomicBool::new(false));
        let server = spawn_accept_loop(listener, Arc::clone(&production), Arc::clone(&shutdown));
        Ok(Self {
            production,
            socket_path,
            process_generation,
            shutdown,
            server: Some(server),
        })
    }

    pub fn restart(&mut self) -> Result<u64, ControlError> {
        let previous = self.process_generation;
        let mut production = self.production.lock().expect("GPU helper");
        match production.restart_helper() {
            Ok(generation) => {
                self.process_generation = generation;
                Ok(generation)
            }
            Err(error) => {
                self.process_generation = previous;
                Err(error)
            }
        }
    }

    pub fn process_generation(&self) -> u64 {
        self.process_generation
    }

    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    pub fn executor(&self) -> Executor {
        self.production.lock().expect("GPU helper").executor()
    }

    pub fn hardware_cuda_executed(&self) -> bool {
        self.production
            .lock()
            .expect("GPU helper")
            .hardware_cuda_executed()
    }
}

impl Drop for CudaProviderHelper {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        let _ = UnixStream::connect(&self.socket_path);
        if let Some(server) = self.server.take() {
            let _ = server.join();
        }
        let _ = std::fs::remove_file(&self.socket_path);
    }
}

/// Client for the helper unix protocol. Used by inbound and outbound GpuAbi
/// routing so mesh streams never call the in-process provider directly.
pub struct GpuHelperClient {
    stream: UnixStream,
    pub gpu_uuid: String,
    pub generation: u64,
    pub executor: String,
    pub hardware_cuda_executed: bool,
}

impl GpuHelperClient {
    pub fn connect(path: &Path, peer_device_id: &str, capability: &str) -> Result<Self> {
        let mut stream = UnixStream::connect(path)
            .with_context(|| format!("connecting to GPU helper {}", path.display()))?;
        stream.set_nonblocking(false)?;
        stream.set_read_timeout(Some(Duration::from_secs(30)))?;
        stream.set_write_timeout(Some(Duration::from_secs(30)))?;
        write_unix_frame(
            &mut stream,
            &HelperHello::Open {
                peer_device_id: peer_device_id.to_owned(),
                capability: capability.to_owned(),
            },
        )?;
        match read_unix_frame::<HelperReady>(&mut stream)? {
            HelperReady::Ok {
                gpu_uuid,
                generation,
                executor,
                hardware_cuda_executed,
            } => {
                if executor != "cuda" {
                    bail!("CPU reference executor cannot serve production GPU ABI");
                }
                Ok(Self {
                    stream,
                    gpu_uuid,
                    generation,
                    executor,
                    hardware_cuda_executed,
                })
            }
            HelperReady::Error { message } => bail!(message),
        }
    }

    pub fn exchange(&mut self, request: Request) -> Result<Reply> {
        write_unix_frame(&mut self.stream, &request)?;
        read_unix_frame(&mut self.stream)
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
                        helper
                            .production
                            .lock()
                            .expect("GPU helper")
                            .authority()
                            .gpu_uuid()
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
fn bind_private_helper_socket(path: &Path) -> Result<UnixListener> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let _ = std::fs::remove_file(path);
    let listener =
        UnixListener::bind(path).with_context(|| format!("binding {}", path.display()))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    listener.set_nonblocking(true)?;
    Ok(listener)
}

fn spawn_accept_loop(
    listener: UnixListener,
    production: Arc<Mutex<ProductionProvider>>,
    shutdown: Arc<AtomicBool>,
) -> JoinHandle<()> {
    thread::spawn(move || {
        let active_workers = Arc::new(AtomicUsize::new(0));
        let mut workers = Vec::with_capacity(MAX_HELPER_WORKERS);
        while !shutdown.load(Ordering::Relaxed) {
            reap_helper_workers(&mut workers);
            match listener.accept() {
                Ok((stream, _)) => {
                    if shutdown.load(Ordering::Relaxed) {
                        break;
                    }
                    let Some(permit) = HelperWorkerPermit::try_acquire(Arc::clone(&active_workers))
                    else {
                        let _ = stream.shutdown(Shutdown::Both);
                        continue;
                    };
                    let control = match stream.try_clone() {
                        Ok(control) => control,
                        Err(_) => continue,
                    };
                    let production = Arc::clone(&production);
                    if let Ok(handle) = thread::Builder::new()
                        .name("asterism-gpu-helper".into())
                        .spawn(move || {
                            let _permit = permit;
                            serve_helper_connection(stream, &production);
                        })
                    {
                        workers.push(HelperWorker { control, handle });
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(20));
                }
                Err(_) => {
                    if shutdown.load(Ordering::Relaxed) {
                        break;
                    }
                    thread::sleep(Duration::from_millis(50));
                }
            }
        }
        for worker in &workers {
            let _ = worker.control.shutdown(Shutdown::Both);
        }
        for worker in workers {
            let _ = worker.handle.join();
        }
    })
}

struct HelperWorker {
    control: UnixStream,
    handle: JoinHandle<()>,
}

struct HelperWorkerPermit {
    active: Arc<AtomicUsize>,
}

impl HelperWorkerPermit {
    fn try_acquire(active: Arc<AtomicUsize>) -> Option<Self> {
        active
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                (current < MAX_HELPER_WORKERS).then_some(current + 1)
            })
            .ok()?;
        Some(Self { active })
    }
}

impl Drop for HelperWorkerPermit {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::Release);
    }
}

fn reap_helper_workers(workers: &mut Vec<HelperWorker>) {
    let mut index = 0;
    while index < workers.len() {
        if workers[index].handle.is_finished() {
            let worker = workers.swap_remove(index);
            let _ = worker.handle.join();
        } else {
            index += 1;
        }
    }
}

fn serve_helper_connection(mut stream: UnixStream, production: &Mutex<ProductionProvider>) {
    let _ = stream.set_nonblocking(false);
    let _ = stream.set_read_timeout(Some(Duration::from_secs(30)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(30)));
    let hello = match read_unix_frame::<HelperHello>(&mut stream) {
        Ok(hello) => hello,
        Err(_) => return,
    };
    let HelperHello::Open {
        peer_device_id,
        capability,
    } = hello;
    let peer = match AuthenticatedPeer::from_mesh_identity(peer_device_id) {
        Ok(peer) => peer,
        Err(error) => {
            let _ = write_unix_frame(
                &mut stream,
                &HelperReady::Error {
                    message: error.message,
                },
            );
            return;
        }
    };
    let ready = {
        let helper = production.lock().expect("GPU helper");
        if helper.executor() != Executor::Cuda {
            HelperReady::Error {
                message: "CPU reference executor cannot serve production GPU ABI".into(),
            }
        } else {
            HelperReady::Ok {
                gpu_uuid: helper.authority().gpu_uuid().to_owned(),
                generation: helper.authority().generation(),
                executor: "cuda".into(),
                hardware_cuda_executed: helper.hardware_cuda_executed(),
            }
        }
    };
    if write_unix_frame(&mut stream, &ready).is_err() {
        return;
    }
    if matches!(ready, HelperReady::Error { .. }) {
        return;
    }
    loop {
        let request = match read_unix_frame::<Request>(&mut stream) {
            Ok(request) => request,
            Err(_) => break,
        };
        let now = asterism_core::instance::now_unix();
        let reply = dispatch_gpu(production, &peer, &capability, request, now);
        if write_unix_frame(&mut stream, &reply).is_err() {
            break;
        }
    }
}

fn write_unix_frame<T: serde::Serialize>(stream: &mut UnixStream, value: &T) -> Result<()> {
    let bytes = serde_json::to_vec(value)?;
    if bytes.len() > MAX_WIRE_FRAME_BYTES {
        bail!(
            "GPU helper frame of {} bytes exceeds {MAX_WIRE_FRAME_BYTES}",
            bytes.len()
        );
    }
    stream.write_all(&(bytes.len() as u32).to_be_bytes())?;
    stream.write_all(&bytes)?;
    stream.flush()?;
    Ok(())
}

fn read_unix_frame<T: serde::de::DeserializeOwned>(stream: &mut UnixStream) -> Result<T> {
    let mut len = [0u8; 4];
    stream.read_exact(&mut len)?;
    let len = u32::from_be_bytes(len) as usize;
    if len == 0 || len > MAX_WIRE_FRAME_BYTES {
        bail!("GPU helper frame of {len} bytes is outside 1..{MAX_WIRE_FRAME_BYTES}");
    }
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf)?;
    Ok(serde_json::from_slice(&buf)?)
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
        Some(helper) => {
            let production = helper.production.lock().expect("GPU helper");
            asterism_core::protocol::Response::GpuProvider {
                available: true,
                executor: match production.executor() {
                    Executor::Cuda => "cuda".into(),
                    Executor::Reference => "reference".into(),
                },
                gpu_uuid: production.authority().gpu_uuid().to_owned(),
                generation: production.authority().generation(),
                hardware_cuda_executed: production.hardware_cuda_executed(),
                helper_socket: helper.socket_path().display().to_string(),
            }
        }
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

fn helper_socket_path() -> Result<PathBuf> {
    let Some(plane) = PLANE.get() else {
        bail!("GPU provider plane is not installed");
    };
    let service = plane.lock().expect("GPU plane");
    let Some(helper) = service.helper.as_ref() else {
        bail!("this device has no CUDA GPU helper");
    };
    if helper.executor() != Executor::Cuda {
        bail!("CPU reference executor cannot serve production GPU ABI");
    }
    Ok(helper.socket_path().to_path_buf())
}

/// Authenticated mesh data path into the CUDA helper via the unix client.
pub async fn serve_mesh(
    mut stream: MeshStream,
    capability: &str,
    requester_device_id: &str,
) -> Result<()> {
    let path = match helper_socket_path() {
        Ok(path) => path,
        Err(error) => {
            mesh::write_frame(
                &mut stream.send,
                &MeshReply::Rpc {
                    response: asterism_core::protocol::Response::Error {
                        message: error.to_string(),
                    },
                },
            )
            .await?;
            return Ok(());
        }
    };
    let client = match GpuHelperClient::connect(&path, requester_device_id, capability) {
        Ok(client) => client,
        Err(error) => {
            mesh::write_frame(
                &mut stream.send,
                &MeshReply::Rpc {
                    response: asterism_core::protocol::Response::Error {
                        message: error.to_string(),
                    },
                },
            )
            .await?;
            return Ok(());
        }
    };
    mesh::write_frame(
        &mut stream.send,
        &MeshReply::GpuReady {
            gpu_uuid: client.gpu_uuid.clone(),
            generation: client.generation,
            executor: client.executor.clone(),
        },
    )
    .await?;
    proxy_mesh_to_helper(stream, client).await
}

/// Outbound GpuAbi: local helper unix client when this device is the
/// provider, otherwise the caller opens a mesh `GpuAbi` stream.
#[allow(dead_code)]
pub fn open_local_helper(peer_device_id: &str, capability: &str) -> Result<GpuHelperClient> {
    let path = helper_socket_path()?;
    GpuHelperClient::connect(&path, peer_device_id, capability)
}

async fn proxy_mesh_to_helper(mut stream: MeshStream, mut client: GpuHelperClient) -> Result<()> {
    loop {
        let request = match read_gpu_frame(&mut stream.recv).await {
            Ok(request) => request,
            Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(error) => return Err(error.into()),
        };
        let reply = client.exchange(request)?;
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

fn dispatch_gpu(
    production: &Mutex<ProductionProvider>,
    peer: &AuthenticatedPeer,
    capability: &str,
    request: Request,
    now: u64,
) -> Reply {
    let mut helper = production.lock().expect("GPU helper");
    match request {
        Request::Hello { versions, .. } => {
            match helper.open_session(peer, capability, versions, now) {
                Ok(response) => Reply::Ok { response },
                Err(error) => gpu_error(error.message),
            }
        }
        request => match helper.handle(peer, capability, request, now) {
            Ok(reply) => reply,
            Err(error) => gpu_error(error.message),
        },
    }
}

fn gpu_io(error: impl std::fmt::Display, kind: std::io::ErrorKind) -> std::io::Error {
    std::io::Error::new(kind, error.to_string())
}

async fn read_gpu_frame(recv: &mut RecvStream) -> std::io::Result<Request> {
    let mut len = [0u8; 4];
    recv.read_exact(&mut len)
        .await
        .map_err(|error| gpu_io(error, std::io::ErrorKind::UnexpectedEof))?;
    let len = u32::from_be_bytes(len) as usize;
    if len == 0 || len > MAX_WIRE_FRAME_BYTES {
        return Err(gpu_io(
            format!("GPU ABI frame of {len} bytes is outside 1..{MAX_WIRE_FRAME_BYTES}"),
            std::io::ErrorKind::InvalidData,
        ));
    }
    let mut buf = vec![0u8; len];
    recv.read_exact(&mut buf)
        .await
        .map_err(|error| gpu_io(error, std::io::ErrorKind::UnexpectedEof))?;
    serde_json::from_slice(&buf).map_err(|error| gpu_io(error, std::io::ErrorKind::InvalidData))
}

async fn write_gpu_frame(send: &mut SendStream, value: &Reply) -> Result<()> {
    let bytes = serde_json::to_vec(value)?;
    if bytes.len() > MAX_WIRE_FRAME_BYTES {
        bail!(
            "GPU ABI reply of {} bytes exceeds {MAX_WIRE_FRAME_BYTES}",
            bytes.len()
        );
    }
    send.write_all(&(bytes.len() as u32).to_be_bytes())
        .await
        .map_err(|error| anyhow::anyhow!("{error}"))?;
    send.write_all(&bytes)
        .await
        .map_err(|error| anyhow::anyhow!("{error}"))?;
    Ok(())
}

/// Standalone helper process: load the CUDA driver, bind the private unix
/// socket, and accept ABI clients. Invoked as `astd --gpu-helper`.
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
        helper
            .production
            .lock()
            .expect("GPU helper")
            .authority()
            .gpu_uuid(),
        helper.socket_path().display(),
        helper.process_generation()
    );
    while !helper.shutdown.load(Ordering::Relaxed) {
        thread::park_timeout(Duration::from_secs(1));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use asterism_core::remote_gpu::{
        AbiRange, AuthenticatedPeer, LeaseAuthority, LeaseLimits, Request, Response,
    };
    use asterism_core::remote_gpu_cuda::CudaDeviceIdentity;
    use std::sync::mpsc;

    static TEST_HOME_LOCK: Mutex<()> = Mutex::new(());

    fn identity_hex() -> String {
        "ab".repeat(32)
    }

    fn wait_for_socket(path: &Path) {
        for _ in 0..50 {
            if path.exists() {
                return;
            }
            thread::sleep(Duration::from_millis(10));
        }
        panic!("helper socket {} did not appear", path.display());
    }

    #[test]
    fn helper_connects_to_cuda_executor_and_never_persists_tokens() {
        let _home = TEST_HOME_LOCK.lock().unwrap();
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
        wait_for_socket(helper.socket_path());
        let meta = std::fs::metadata(helper.socket_path()).unwrap();
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);

        let peer = AuthenticatedPeer::from_mesh_identity(identity_hex()).unwrap();
        let (lease, attachment) = helper
            .production
            .lock()
            .unwrap()
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
            .lock()
            .unwrap()
            .open_session(&peer, &old, AbiRange::ours(), 20)
            .unwrap_err();
        assert!(matches!(
            error.code,
            ControlErrorCode::Revoked | ControlErrorCode::InvalidLease
        ));
        std::env::remove_var("ASTERISM_HOME");
    }

    #[test]
    fn helper_unix_client_routes_abi_not_an_idle_listener() {
        let _home = TEST_HOME_LOCK.lock().unwrap();
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
        let helper = CudaProviderHelper::connect(engine, authority).unwrap();
        wait_for_socket(helper.socket_path());

        let peer = AuthenticatedPeer::from_mesh_identity(identity_hex()).unwrap();
        let now = asterism_core::instance::now_unix();
        let (lease, _) = helper
            .production
            .lock()
            .unwrap()
            .authority_mut()
            .attach(&peer, "instance-a", 16, now)
            .unwrap();

        let mut client =
            GpuHelperClient::connect(helper.socket_path(), &identity_hex(), lease.capability())
                .unwrap();
        assert_eq!(client.executor, "cuda");
        assert!(!client.hardware_cuda_executed);
        let opened = client
            .exchange(Request::Hello {
                versions: AbiRange::ours(),
                consumer: "instance-a".into(),
            })
            .unwrap()
            .into_result()
            .unwrap();
        let Response::SessionOpened { session, .. } = opened else {
            panic!("session")
        };
        let allocated = client
            .exchange(Request::Allocate {
                session,
                sequence: 1,
                bytes: 8,
            })
            .unwrap()
            .into_result()
            .unwrap();
        assert!(matches!(allocated, Response::Allocated { bytes: 8, .. }));
        assert!(!helper.hardware_cuda_executed());
        std::env::remove_var("ASTERISM_HOME");
    }

    #[test]
    fn persistent_helper_client_does_not_starve_later_clients_or_shutdown() {
        let _home = TEST_HOME_LOCK.lock().unwrap();
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
        let helper = CudaProviderHelper::connect(engine, authority).unwrap();
        wait_for_socket(helper.socket_path());

        let peer = AuthenticatedPeer::from_mesh_identity(identity_hex()).unwrap();
        let (lease, _) = helper
            .production
            .lock()
            .unwrap()
            .authority_mut()
            .attach(&peer, "instance-a", 16, asterism_core::instance::now_unix())
            .unwrap();
        let first =
            GpuHelperClient::connect(helper.socket_path(), &identity_hex(), lease.capability())
                .unwrap();

        let socket_path = helper.socket_path().to_owned();
        let capability = lease.capability().to_owned();
        let peer_id = identity_hex();
        let (connected_tx, connected_rx) = mpsc::channel();
        let connect_thread = thread::spawn(move || {
            let result = GpuHelperClient::connect(&socket_path, &peer_id, &capability);
            let _ = connected_tx.send(result);
        });
        let second = match connected_rx.recv_timeout(Duration::from_secs(2)) {
            Ok(result) => result.expect("later helper client should connect"),
            Err(error) => {
                drop(first);
                let _ = connect_thread.join();
                panic!("persistent helper client starved a later client: {error}");
            }
        };
        connect_thread.join().unwrap();

        let (stopped_tx, stopped_rx) = mpsc::channel();
        let stop_thread = thread::spawn(move || {
            drop(helper);
            let _ = stopped_tx.send(());
        });
        if let Err(error) = stopped_rx.recv_timeout(Duration::from_secs(2)) {
            drop(first);
            drop(second);
            let _ = stop_thread.join();
            panic!("helper shutdown did not join persistent workers: {error}");
        }
        stop_thread.join().unwrap();
        drop(first);
        drop(second);
        std::env::remove_var("ASTERISM_HOME");
    }

    #[test]
    fn helper_worker_admission_is_bounded() {
        let active = Arc::new(AtomicUsize::new(0));
        let mut permits = (0..MAX_HELPER_WORKERS)
            .map(|_| HelperWorkerPermit::try_acquire(Arc::clone(&active)).unwrap())
            .collect::<Vec<_>>();
        assert!(HelperWorkerPermit::try_acquire(Arc::clone(&active)).is_none());
        permits.pop();
        assert!(HelperWorkerPermit::try_acquire(active).is_some());
    }

    #[test]
    fn helper_restart_rolls_back_public_generation_when_wipe_fails() {
        let _home = TEST_HOME_LOCK.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        std::env::set_var("ASTERISM_HOME", tmp.path());
        let identity = CudaDeviceIdentity::simulated_l4();
        let engine = CudaEngine::simulated(identity.clone(), 1).unwrap();
        let authority = LeaseAuthority::new(
            "desktop",
            identity_hex(),
            identity.uuid,
            1,
            LeaseLimits {
                total_memory_bytes: 32,
                max_memory_per_lease: 16,
                max_leases: 1,
                lease_ttl_secs: 30,
            },
        )
        .unwrap();
        let mut helper = CudaProviderHelper::connect(engine, authority).unwrap();
        let peer = AuthenticatedPeer::from_mesh_identity(identity_hex()).unwrap();
        let now = asterism_core::instance::now_unix();
        let (lease, _) = helper
            .production
            .lock()
            .unwrap()
            .authority_mut()
            .attach(&peer, "instance-a", 16, now)
            .unwrap();
        let Response::SessionOpened { session, .. } = helper
            .production
            .lock()
            .unwrap()
            .open_session(&peer, lease.capability(), AbiRange::ours(), now)
            .unwrap()
        else {
            panic!("session should open")
        };
        helper
            .production
            .lock()
            .unwrap()
            .handle(
                &peer,
                lease.capability(),
                Request::Allocate {
                    session,
                    sequence: 1,
                    bytes: 8,
                },
                now,
            )
            .unwrap()
            .into_result()
            .unwrap();
        let before = helper.process_generation();
        helper.production.lock().unwrap().fail_next_zeroize();

        let blocked = helper.restart().unwrap_err();
        assert_eq!(blocked.code, ControlErrorCode::Unavailable);
        assert_eq!(helper.process_generation(), before);
        let production = helper.production.lock().unwrap();
        assert_eq!(production.authority().generation(), before);
        assert_eq!(production.live_abi_bytes(), 8);
        drop(production);

        assert_eq!(helper.restart().unwrap(), before + 1);
        assert_eq!(helper.process_generation(), before + 1);
        assert_eq!(helper.production.lock().unwrap().live_abi_bytes(), 0);
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
        assert!(
            !CudaEngine::simulated(CudaDeviceIdentity::simulated_l4(), 1)
                .unwrap()
                .hardware_cuda_executed()
        );
    }
}
