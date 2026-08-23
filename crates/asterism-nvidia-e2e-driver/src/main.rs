//! Real NVIDIA release-gate adapter.
//!
//! This program deliberately does not implement a mesh, relay, provider, or
//! verifier. It projects the guest-local device onto the local control socket
//! of a paired `astd`; that daemon owns the authenticated QUIC path. An
//! immutable external observer owns process/image inspection and acceptance.

use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, ensure, Context, Result};
use asterism_core::hv::Machine;
use asterism_core::instance::Shape;
use asterism_core::protocol::{Request, Response};
use asterism_core::registry::Shard;
use asterism_core::remote_gpu::GpuAttachment;
use asterism_core::remote_gpu_guest::{
    project_guest_device, read_frame, write_frame, CudaCall, GuestFrame,
};
use asterism_mesh::DeviceIdentity;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

const SCHEMA: &str = "asterism.nvidia.raw-observation/2";
const INSTANCE: &str = "nvidia-release-guest";
const MEMORY_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawObservation {
    schema: String,
    run_id: String,
    candidate_sha: String,
    tree_digest: String,
    path_observed: String,
    fault_requested: String,
    fault_while_active: bool,
    guest_device_name: String,
    provider_device_name: String,
    guest_device_id: String,
    provider_device_id: String,
    gpu_uuid: String,
    provider_astd_pid: u32,
    guest_astd_pid: u32,
    guest_container_id: String,
    guest_container_pid: u32,
    guest_output: String,
    guest_succeeded: bool,
    hardware_cuda_executed: bool,
    driver_digest: String,
    astd_digest: String,
    libcuda_digest: String,
    guest_binary_digest: String,
    guest_launcher_digest: String,
    guest_image_digest: String,
    provider_image_digest: String,
    guest_astd_log_digest: String,
    provider_astd_log_digest: String,
    crossed_frames: Vec<String>,
    crossed_digest: String,
}

fn main() -> Result<()> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    match args.first().map(String::as_str) {
        Some("identity") => {
            println!("{}", identity(Path::new(required(&args[1..], "--home")?))?);
            Ok(())
        }
        Some("prepare") => prepare(&args[1..]),
        Some("observe") => observe(&args[1..]),
        Some(other) => bail!("unknown command {other:?}; expected prepare or observe"),
        None => bail!("expected prepare or observe"),
    }
}

/// Persist only token-free metadata from the identities generated and paired
/// by the two daemons. The provider's live bearer never enters this process.
fn prepare(args: &[String]) -> Result<()> {
    let guest_home = PathBuf::from(required(args, "--guest-home")?);
    let provider_home = PathBuf::from(required(args, "--provider-home")?);
    let guest_name = required(args, "--guest-device-name")?;
    let provider_name = required(args, "--provider-device-name")?;
    let gpu_uuid = required(args, "--gpu-uuid")?;
    let generation = required(args, "--provider-generation")?.parse::<u64>()?;
    ensure!(generation > 0, "provider generation must be non-zero");
    let guest_id = identity(&guest_home)?;
    let provider_id = identity(&provider_home)?;
    prove_pair(&guest_home, provider_name, &provider_id)?;
    prove_pair(&provider_home, guest_name, &guest_id)?;

    let mut shard = Shard::load(&guest_home.join("state.json"))?;
    if shard.holds(INSTANCE) {
        if shard.get(INSTANCE)?.gpu.is_some() { shard.detach_gpu(INSTANCE)?; }
    } else {
        shard.create(
            INSTANCE,
            guest_name,
            "nvidia-release-gate-only",
            Shape::default(),
            Machine {
                backend: "release-gate".into(),
                machine_type: "container".into(),
                cpu: "host".into(),
                hv_version: "external-observer/1".into(),
            },
        )?;
    }
    shard.attach_gpu(INSTANCE, GpuAttachment {
        provider_device: provider_name.into(),
        provider_device_id: provider_id,
        provider_gpu_uuid: gpu_uuid.into(),
        memory_bytes: MEMORY_BYTES,
        provider_generation: generation,
        attached_at: now(),
    })?;
    shard.save()?;
    println!("instance_id={}", shard.get(INSTANCE)?.id);
    Ok(())
}

fn observe(args: &[String]) -> Result<()> {
    let output = PathBuf::from(required(args, "--output")?);
    let guest_home = PathBuf::from(required(args, "--guest-home")?);
    let provider_home = PathBuf::from(required(args, "--provider-home")?);
    let guest_name = required(args, "--guest-device-name")?.to_owned();
    let provider_name = required(args, "--provider-device-name")?.to_owned();
    let expected_path = required(args, "--path")?.to_owned();
    ensure!(matches!(expected_path.as_str(), "direct" | "relay"));
    let fault = optional(args, "--fault").unwrap_or("none").to_owned();
    ensure!(matches!(fault.as_str(), "none" | "revoke" | "loss"));
    let gpu_uuid = required(args, "--gpu-uuid")?.to_owned();
    let provider_pid = required(args, "--provider-astd-pid")?.parse::<u32>()?;
    let guest_pid = required(args, "--guest-astd-pid")?.parse::<u32>()?;
    let guest_log = PathBuf::from(required(args, "--guest-astd-log")?);
    let provider_log = PathBuf::from(required(args, "--provider-astd-log")?);
    let guest_id = identity(&guest_home)?;
    let provider_id = identity(&provider_home)?;
    prove_pair(&guest_home, &provider_name, &provider_id)?;
    prove_pair(&provider_home, &guest_name, &guest_id)?;
    ensure!(process_alive(guest_pid) && process_alive(provider_pid));

    let path_observed = mesh_path(&guest_home, &provider_name, &provider_id)?;
    ensure!(path_observed == expected_path,
        "authenticated mesh selected {path_observed}, expected {expected_path}");
    let root = scratch()?;
    let device = project_guest_device(&root)?;
    let device_path = device.path().to_path_buf();
    let socket = guest_home.join("astd.sock");
    let fault_for_bridge = fault.clone();
    let provider_name_for_bridge = provider_name.clone();
    let guest_home_for_bridge = guest_home.clone();
    let bridge = thread::spawn(move || bridge_guest(
        device, &socket, &fault_for_bridge, provider_pid,
        &guest_home_for_bridge, &provider_name_for_bridge,
    ));

    let guest_binary = env_path("ASTERISM_NVIDIA_GUEST_BINARY")?;
    let libcuda = env_path("ASTERISM_NVIDIA_LIBCUDA")?;
    let launcher = env_path("ASTERISM_NVIDIA_GUEST_LAUNCHER")?;
    let child = Command::new(&launcher).arg(&guest_binary).arg(&device_path).arg(&libcuda)
        .stdout(Stdio::piped()).stderr(Stdio::piped()).spawn()?;
    let result = child.wait_with_output()?;
    let stdout = String::from_utf8(result.stdout)?;
    let stderr = String::from_utf8_lossy(&result.stderr);
    let bridge = bridge.join().map_err(|_| anyhow!("guest-to-astd bridge panicked"))??;
    let succeeded = result.status.success();
    if fault == "none" {
        ensure_success(result.status, stderr.as_bytes(), "guest CUDA application")?;
        ensure!(stdout.contains("hardware_path=guest_libcuda_mesh"));
        ensure!(stdout.contains("guest_output=6.0,2.0,6.0"));
    } else {
        ensure!(!succeeded, "active {fault} fixture unexpectedly completed");
        ensure!(bridge.fault_while_active, "{fault} was not injected during CUDA work");
    }

    let candidate_sha = git("rev-parse", "HEAD")?;
    ensure!(candidate_sha == env_required("ASTERISM_PINNED_SHA")?);
    let executable = std::env::current_exe()?;
    let astd = env_path("ASTERISM_NVIDIA_ASTD")?;
    let observation = RawObservation {
        schema: SCHEMA.into(), run_id: Uuid::new_v4().to_string(), candidate_sha,
        tree_digest: git("rev-parse", "HEAD^{tree}")?, path_observed,
        fault_requested: fault, fault_while_active: bridge.fault_while_active,
        guest_device_name: guest_name, provider_device_name: provider_name,
        guest_device_id: guest_id, provider_device_id: provider_id, gpu_uuid,
        provider_astd_pid: provider_pid, guest_astd_pid: guest_pid,
        guest_container_id: output_value(&stdout, "guest_container_id")?,
        guest_container_pid: output_value(&stdout, "guest_container_pid")?.parse()?,
        guest_output: if succeeded { "6.0,2.0,6.0".into() } else { String::new() },
        guest_succeeded: succeeded,
        hardware_cuda_executed: succeeded && bridge.saw_cuda,
        driver_digest: sha256_file(&executable)?, astd_digest: sha256_file(&astd)?,
        libcuda_digest: sha256_file(&libcuda)?, guest_binary_digest: sha256_file(&guest_binary)?,
        guest_launcher_digest: sha256_file(&launcher)?,
        guest_image_digest: env_required("ASTERISM_NVIDIA_GUEST_IMAGE_DIGEST")?,
        provider_image_digest: env_required("ASTERISM_NVIDIA_PROVIDER_IMAGE_DIGEST")?,
        guest_astd_log_digest: sha256_file(&guest_log)?,
        provider_astd_log_digest: sha256_file(&provider_log)?,
        crossed_digest: digest_frames(&bridge.frames), crossed_frames: bridge.frames,
    };
    fs::write(output, serde_json::to_vec_pretty(&observation)?)?;
    Ok(())
}

struct BridgeResult { frames: Vec<String>, saw_cuda: bool, fault_while_active: bool }

fn bridge_guest(
    device: asterism_core::remote_gpu_guest::GuestDevice,
    socket: &Path, fault: &str, provider_pid: u32,
    guest_home: &Path, provider_name: &str,
) -> Result<BridgeResult> {
    let mut daemon = JsonConnection::open(socket)?;
    match daemon.call(&Request::GpuGuestOpen { name: INSTANCE.into() })? {
        Response::GpuGuestAccepted { .. } => {}
        Response::GpuGuestRefused { code, message } => bail!("GPU guest refused: {code}: {message}"),
        other => bail!("unexpected GPU open response: {other:?}"),
    }
    let mut local = device.accept()?;
    let mut frames = Vec::new();
    let mut saw_cuda = false;
    let mut provider_work_completed = false;
    let mut fault_while_active = false;
    loop {
        let frame: GuestFrame = match read_frame(&mut local) { Ok(frame) => frame, Err(_) => break };
        let closing = matches!(frame, GuestFrame::Close);
        let provider_work = matches!(
            &frame,
            GuestFrame::Cuda { call, .. }
                if !matches!(call, CudaCall::Init | CudaCall::DeviceCount
                    | CudaCall::DeviceName { .. } | CudaCall::Synchronize
                    | CudaCall::Unsupported { .. })
        );
        if provider_work {
            saw_cuda = true;
            if provider_work_completed && !fault_while_active && fault != "none" {
                fault_while_active = true;
                match fault {
                    "loss" => { unsafe { libc_kill(provider_pid as i32, 15); } }
                    "revoke" => {
                        let mut admin = JsonConnection::open(&guest_home.join("astd.sock"))?;
                        let response = admin.call(&Request::DeviceRemove { name: provider_name.into() })?;
                        ensure!(!matches!(response, Response::Error { .. }), "device revoke failed");
                    }
                    _ => {}
                }
            }
        }
        let request = Request::GpuGuestFrame { frame };
        let request_json = serde_json::to_string(&request)?;
        let response = match daemon.call(&request) {
            Ok(response) => response,
            Err(error) if fault != "none" => {
                frames.push(format!("{request_json}\ntransport_error={error:#}"));
                break;
            }
            Err(error) => return Err(error),
        };
        frames.push(format!("{request_json}\n{}", serde_json::to_string(&response)?));
        match response {
            Response::GpuGuestReply { reply } => {
                write_frame(&mut local, &reply)?;
                if provider_work { provider_work_completed = true; }
            }
            Response::GpuGuestRefused { code, message } if fault != "none" => {
                frames.push(format!("refused={code}:{message}")); break;
            }
            Response::GpuGuestRefused { code, message } => bail!("GPU frame refused: {code}: {message}"),
            other if fault != "none" => { frames.push(format!("terminal={other:?}")); break; }
            other => bail!("unexpected GPU frame response: {other:?}"),
        }
        if closing { break; }
    }
    let _ = daemon.call(&Request::GpuGuestClose);
    Ok(BridgeResult { frames, saw_cuda, fault_while_active })
}

struct JsonConnection { reader: BufReader<UnixStream>, writer: UnixStream }
impl JsonConnection {
    fn open(path: &Path) -> Result<Self> {
        let writer = UnixStream::connect(path).with_context(|| format!("connecting to {}", path.display()))?;
        Ok(Self { reader: BufReader::new(writer.try_clone()?), writer })
    }
    fn call(&mut self, request: &Request) -> Result<Response> {
        serde_json::to_writer(&mut self.writer, request)?;
        self.writer.write_all(b"\n")?; self.writer.flush()?;
        let mut line = String::new();
        ensure!(self.reader.read_line(&mut line)? != 0, "astd closed the control socket");
        Ok(serde_json::from_str(&line)?)
    }
}

fn mesh_path(home: &Path, peer: &str, expected_id: &str) -> Result<String> {
    let mut conn = JsonConnection::open(&home.join("astd.sock"))?;
    match conn.call(&Request::DevicePing { device: peer.into() })? {
        Response::DevicePong { device_id, path, .. } => {
            ensure!(device_id == expected_id, "ping answered with an unpaired identity"); Ok(path)
        }
        Response::Error { message } => bail!("mesh ping failed: {message}"),
        other => bail!("unexpected mesh ping response: {other:?}"),
    }
}

fn identity(home: &Path) -> Result<String> {
    Ok(DeviceIdentity::load(home.join("id_device"))?.device_id().to_string())
}
fn prove_pair(home: &Path, peer_name: &str, peer_id: &str) -> Result<()> {
    let orbit = asterism_core::orbit::Orbit::load(&home.join("orbit.json"))?;
    let peer = orbit.get(peer_name).with_context(|| format!("{peer_name} is not paired"))?;
    ensure!(peer.device_id == peer_id, "paired identity mismatch for {peer_name}"); Ok(())
}
fn required<'a>(args: &'a [String], name: &str) -> Result<&'a str> {
    let i = args.iter().position(|arg| arg == name).with_context(|| format!("missing {name}"))?;
    args.get(i + 1).map(String::as_str).with_context(|| format!("missing value for {name}"))
}
fn optional<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter().position(|arg| arg == name).and_then(|i| args.get(i + 1)).map(String::as_str)
}
fn env_required(name: &str) -> Result<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty()).with_context(|| format!("{name} is required"))
}
fn env_path(name: &str) -> Result<PathBuf> { Ok(PathBuf::from(env_required(name)?)) }
fn output_value(text: &str, key: &str) -> Result<String> {
    text.lines().find_map(|line| line.strip_prefix(&format!("{key}="))).filter(|v| !v.is_empty())
        .map(str::to_owned).with_context(|| format!("guest output is missing {key}"))
}
fn git(command: &str, argument: &str) -> Result<String> {
    let output = Command::new("git").arg(command).arg(argument).output()?;
    ensure_success(output.status, &output.stderr, "git")?;
    Ok(String::from_utf8(output.stdout)?.trim().to_owned())
}
fn ensure_success(status: ExitStatus, stderr: &[u8], label: &str) -> Result<()> {
    ensure!(status.success(), "{label} failed with {status}: {}", String::from_utf8_lossy(stderr)); Ok(())
}
fn sha256_file(path: &Path) -> Result<String> {
    let mut file = fs::File::open(path)?; let mut hasher = Sha256::new(); let mut buffer = [0_u8; 65536];
    loop { let n = file.read(&mut buffer)?; if n == 0 { break; } hasher.update(&buffer[..n]); }
    Ok(format!("sha256:{:x}", hasher.finalize()))
}
fn digest_frames(frames: &[String]) -> String {
    format!("blake3:{}", blake3::hash(frames.join("\0").as_bytes()).to_hex())
}
fn scratch() -> Result<PathBuf> {
    let path = std::env::temp_dir().join(format!("asterism-nvidia-{}-{}", std::process::id(), Uuid::new_v4()));
    fs::create_dir_all(&path)?; Ok(path)
}
fn now() -> u64 { SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() }
fn process_alive(pid: u32) -> bool { unsafe { libc_kill(pid as i32, 0) == 0 } }
unsafe fn libc_kill(pid: i32, signal: i32) -> i32 {
    unsafe extern "C" { fn kill(pid: i32, signal: i32) -> i32; }
    unsafe { kill(pid, signal) }
}
