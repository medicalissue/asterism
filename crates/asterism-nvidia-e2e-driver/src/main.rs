//! Exact real-NVIDIA E2E process driver.
//!
//! The release wrapper builds this binary, the generated libcuda, and the
//! guest application from a clean pinned checkout into a private target
//! directory. This binary then owns the live CUDA helper processes and guest
//! processes. Its evidence is a hash-chained JSON event bundle; the verifier
//! derives the release fields from those events. It never accepts a verdict,
//! lifecycle boolean, PID, path label, or hardware claim from a caller.

use std::fs;
use std::io::{self, Read};
use std::net::Shutdown;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, ensure, Context, Result};
use asterism_core::remote_gpu::{
    AbiRange, AuthenticatedPeer, ControlErrorCode, LeaseAuthority, LeaseLimits, ProductionProvider,
    ABI_VERSION,
};
use asterism_core::remote_gpu_cuda::CudaEngine;
use asterism_core::remote_gpu_guest::{project_guest_device, read_frame, write_frame, GuestFrame};
use asterism_core::remote_gpu_path::GuestMeshPath;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

const SCHEMA: &str = "asterism.nvidia.e2e.bundle/1";
const INSTANCE: &str = "nvidia-release-guest";
const MEMORY_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Bundle {
    schema: String,
    run_id: String,
    candidate_sha: String,
    tree_digest: String,
    driver_digest: String,
    astd_digest: String,
    libcuda_digest: String,
    guest_binary_digest: String,
    guest_launcher_digest: String,
    guest_image_digest: String,
    provider_image_digest: String,
    guest_device_name: String,
    provider_device_name: String,
    guest_device_id: String,
    provider_device_id: String,
    first_guest_container_id: String,
    second_guest_container_id: String,
    first_gpu_uuid: String,
    second_gpu_uuid: String,
    events: Vec<Event>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Event {
    sequence: u64,
    actor: String,
    pid: u32,
    generation: u64,
    kind: String,
    detail: String,
    previous: String,
    digest: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Observation {
    path: String,
    gpu_uuid: String,
    helper_pid: u32,
    route_pid: u32,
    guest_pid: u32,
    guest_container_id: String,
    guest_output: String,
    crossed_digest: String,
    mesh_open_bearer: bool,
    hardware_cuda_executed: bool,
    revoke_refused: bool,
    loss_refused: bool,
    contention_refused: bool,
    fresh_skew_refused: bool,
}

fn main() -> Result<()> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.first().map(String::as_str) == Some("--execute-one") {
        return execute_one(&args[1..]);
    }
    if args.first().map(String::as_str) == Some("verify") {
        return verify_command(&args[1..]);
    }
    if args.first().map(String::as_str) == Some("--relay-proxy") {
        return relay_proxy(&args[1..]);
    }
    run(&args)
}

fn run(args: &[String]) -> Result<()> {
    let evidence = PathBuf::from(required(args, "--evidence")?);
    let guest_name = required(args, "--guest-device-name")?.to_owned();
    let provider_name = required(args, "--provider-device-name")?.to_owned();
    ensure!(
        guest_name != provider_name,
        "mesh device names must be distinct"
    );
    let first_uuid = required(args, "--first-gpu-uuid")?.to_owned();
    let second_uuid = required(args, "--second-gpu-uuid")?.to_owned();
    ensure!(first_uuid != second_uuid, "GPU UUIDs must be distinct");

    let candidate_sha = git("rev-parse", "HEAD")?;
    let pinned = env_required("ASTERISM_PINNED_SHA")?;
    ensure!(
        candidate_sha == pinned,
        "checkout is not the pinned candidate"
    );
    let tree_digest = git("rev-parse", "HEAD^{tree}")?;
    ensure!(
        git("status", "--porcelain --untracked-files=no")?.is_empty(),
        "tracked candidate files are dirty"
    );

    let executable = std::env::current_exe()?;
    let libcuda = PathBuf::from(env_required("ASTERISM_NVIDIA_LIBCUDA")?);
    let guest_binary = PathBuf::from(env_required("ASTERISM_NVIDIA_GUEST_BINARY")?);
    let astd = PathBuf::from(env_required("ASTERISM_NVIDIA_ASTD")?);
    let guest_launcher = PathBuf::from(env_required("ASTERISM_NVIDIA_GUEST_LAUNCHER")?);
    for (label, path) in [
        ("driver", executable.as_path()),
        ("libcuda", libcuda.as_path()),
        ("guest binary", guest_binary.as_path()),
        ("astd", astd.as_path()),
        ("guest launcher", guest_launcher.as_path()),
    ] {
        ensure!(
            path.is_file(),
            "{label} is not a regular file: {}",
            path.display()
        );
    }

    let scratch = scratch("driver")?;
    let run_id = Uuid::new_v4().to_string();
    let guest_id = device_id(&format!("{run_id}:{guest_name}"));
    let provider_id = device_id(&format!("{run_id}:{provider_name}"));

    let provider_astd_before = start_astd(&astd, &scratch.join("astd-before"), &provider_name)?;
    let provider_astd_pid_before = provider_astd_before.id();
    stop(provider_astd_before)?;
    let provider_astd_after = start_astd(&astd, &scratch.join("astd-after"), &provider_name)?;
    let provider_astd_pid_after = provider_astd_after.id();

    let direct = child_observation(
        &executable,
        &scratch,
        "direct",
        &first_uuid,
        &guest_name,
        &provider_name,
        &guest_id,
        &provider_id,
    )?;
    let relay = child_observation(
        &executable,
        &scratch,
        "relay",
        &second_uuid,
        &guest_name,
        &provider_name,
        &guest_id,
        &provider_id,
    )?;
    stop(provider_astd_after)?;

    ensure!(direct.hardware_cuda_executed && relay.hardware_cuda_executed);
    ensure!(direct.guest_output == "6.0,2.0,6.0");
    ensure!(relay.guest_output == "6.0,2.0,6.0");
    ensure!(direct.revoke_refused, "live revoke did not fail closed");
    ensure!(relay.loss_refused, "live provider loss did not fail closed");
    ensure!(
        direct.contention_refused,
        "live lease contention was not refused"
    );
    ensure!(
        relay.fresh_skew_refused,
        "fresh-session ABI skew was not refused"
    );

    let mut bundle = Bundle {
        schema: SCHEMA.into(),
        run_id,
        candidate_sha,
        tree_digest,
        driver_digest: sha256_file(&executable)?,
        astd_digest: sha256_file(&astd)?,
        libcuda_digest: sha256_file(&libcuda)?,
        guest_binary_digest: sha256_file(&guest_binary)?,
        guest_launcher_digest: sha256_file(&guest_launcher)?,
        guest_image_digest: env_required("ASTERISM_NVIDIA_GUEST_IMAGE_DIGEST")?,
        provider_image_digest: env_required("ASTERISM_NVIDIA_PROVIDER_IMAGE_DIGEST")?,
        guest_device_name: guest_name,
        provider_device_name: provider_name,
        guest_device_id: guest_id,
        provider_device_id: provider_id,
        first_guest_container_id: direct.guest_container_id.clone(),
        second_guest_container_id: relay.guest_container_id.clone(),
        first_gpu_uuid: first_uuid,
        second_gpu_uuid: second_uuid,
        events: Vec::new(),
    };

    append(
        &mut bundle,
        "provider_astd",
        provider_astd_pid_before,
        1,
        "started",
        "authenticated_mesh_daemon",
    )?;
    append_observation(&mut bundle, &direct, 1)?;
    append(
        &mut bundle,
        "provider_astd",
        provider_astd_pid_after,
        2,
        "restarted",
        "authenticated_mesh_daemon",
    )?;
    append_observation(&mut bundle, &relay, 2)?;
    let bundle_path = evidence.with_extension("bundle.json");
    fs::write(&bundle_path, serde_json::to_vec_pretty(&bundle)?)?;
    verify_bundle(&bundle)?;
    write_evidence(&evidence, &bundle)?;
    Ok(())
}

fn execute_one(args: &[String]) -> Result<()> {
    let output = PathBuf::from(required(args, "--output")?);
    let path_kind = required(args, "--path")?.to_owned();
    ensure!(matches!(path_kind.as_str(), "direct" | "relay"));
    let gpu_uuid = required(args, "--gpu-uuid")?.to_owned();
    let guest_name = required(args, "--guest-device-name")?.to_owned();
    let provider_name = required(args, "--provider-device-name")?.to_owned();
    ensure!(guest_name != provider_name, "mesh device names must differ");
    let guest_id = required(args, "--guest-device-id")?.to_owned();
    let provider_id = required(args, "--provider-device-id")?.to_owned();

    let engine = CudaEngine::open_live(Some(&gpu_uuid)).map_err(|error| anyhow!(error))?;
    ensure!(
        engine.is_live_nvidia(),
        "helper did not load a live NVIDIA driver"
    );
    let identity = engine.identity().clone();
    ensure!(identity.uuid == gpu_uuid, "helper opened the wrong GPU");
    let authority = LeaseAuthority::new(
        provider_name,
        provider_id,
        identity.uuid,
        1,
        LeaseLimits {
            total_memory_bytes: identity.memory_bytes,
            max_memory_per_lease: MEMORY_BYTES,
            max_leases: 1,
            lease_ttl_secs: 120,
        },
    )
    .map_err(|error| anyhow!(error))?;
    let mut production =
        ProductionProvider::connect(authority, engine).map_err(|error| anyhow!(error))?;
    let peer = AuthenticatedPeer::from_mesh_identity(guest_id).map_err(|error| anyhow!(error))?;

    let (contention_lease, _) = production
        .authority_mut()
        .attach(&peer, "release-contention-holder", MEMORY_BYTES, now())
        .map_err(|error| anyhow!(error))?;
    let contention_refused = production
        .authority_mut()
        .attach(&peer, "release-contention-second", MEMORY_BYTES, now())
        .is_err_and(|error| error.code == ControlErrorCode::LimitExceeded);
    ensure!(
        production
            .authority_mut()
            .revoke_instance("release-contention-holder"),
        "contention lease was not released"
    );
    ensure!(
        production
            .authority()
            .lease(contention_lease.capability())
            .is_none(),
        "revoked contention capability remained live"
    );

    let (skew_lease, _) = production
        .authority_mut()
        .attach(&peer, "release-fresh-skew", MEMORY_BYTES, now())
        .map_err(|error| anyhow!(error))?;
    let fresh_skew_refused = production
        .open_session(
            &peer,
            skew_lease.capability(),
            AbiRange {
                min: ABI_VERSION + 1,
                max: ABI_VERSION + 1,
            },
            now(),
        )
        .is_err_and(|error| error.code == ControlErrorCode::UnsupportedVersion);
    ensure!(
        production.revoke_instance("release-fresh-skew"),
        "fresh-skew lease was not released"
    );
    let (mut mesh_path, _, capability) =
        GuestMeshPath::attach(peer, production, INSTANCE, MEMORY_BYTES, now())?;
    ensure!(
        !mesh_path.crossed_text().contains(&capability),
        "mesh opening leaked lease bearer"
    );

    let root = scratch("guest")?;
    let device = project_guest_device(&root)?;
    let provider_endpoint = device.path().to_path_buf();
    let (device_path, mut relay) = if path_kind == "relay" {
        let relay_endpoint = root.join("relay-dev-nvidia0");
        let child = Command::new(std::env::current_exe()?)
            .arg("--relay-proxy")
            .arg("--listen")
            .arg(&relay_endpoint)
            .arg("--upstream")
            .arg(&provider_endpoint)
            .spawn()?;
        wait_for_socket(&relay_endpoint, &child)?;
        (relay_endpoint, Some(child))
    } else {
        (provider_endpoint, None)
    };
    let route_pid = relay.as_ref().map(Child::id).unwrap_or(0);
    let server = thread::spawn(move || -> Result<GuestMeshPath> {
        let mut stream = device.accept()?;
        loop {
            let frame: GuestFrame = match read_frame(&mut stream) {
                Ok(frame) => frame,
                Err(_) => break,
            };
            let closing = matches!(frame, GuestFrame::Close);
            let reply = mesh_path
                .apply_guest(frame)
                .map_err(|error| anyhow!(error))?;
            write_frame(&mut stream, &reply)?;
            if closing {
                break;
            }
        }
        Ok(mesh_path)
    });

    let guest_binary = PathBuf::from(env_required("ASTERISM_NVIDIA_GUEST_BINARY")?);
    let libcuda = PathBuf::from(env_required("ASTERISM_NVIDIA_LIBCUDA")?);
    let launcher = env_required("ASTERISM_NVIDIA_GUEST_LAUNCHER")?;
    let mut command = Command::new(launcher);
    command.arg(&guest_binary).arg(&device_path).arg(&libcuda);
    let guest = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let guest_pid = guest.id();
    let guest_output = guest.wait_with_output()?;
    ensure_success(
        guest_output.status,
        &guest_output.stderr,
        "guest CUDA application",
    )?;
    let stdout = String::from_utf8(guest_output.stdout)?;
    ensure!(stdout.contains("hardware_path=guest_libcuda_mesh"));
    ensure!(stdout.contains("guest_output=6.0,2.0,6.0"));
    let guest_container_id = output_value(&stdout, "guest_container_id")?;
    ensure!(
        guest_container_id.len() >= 12
            && guest_container_id
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()),
        "guest launcher did not report a Docker container ID"
    );

    let mut mesh_path = server
        .join()
        .map_err(|_| anyhow!("guest projection thread panicked"))??;
    if let Some(child) = relay.as_mut() {
        let status = child.wait()?;
        ensure!(status.success(), "relay proxy failed with {status}");
    }
    let crossed_digest = digest_bytes(
        &mesh_path
            .crossed
            .iter()
            .flat_map(|frame| frame.iter().copied())
            .collect::<Vec<_>>(),
    );
    let mesh_open_bearer = mesh_path.crossed_text().contains(&capability);
    let revoke_refused = if path_kind == "direct" {
        mesh_path.revoke_instance(INSTANCE)
    } else {
        false
    };
    let loss_refused = if path_kind == "relay" {
        mesh_path.provider_lost("release gate device loss") > 0
    } else {
        false
    };
    let observation = Observation {
        path: path_kind,
        gpu_uuid,
        helper_pid: std::process::id(),
        route_pid,
        guest_pid,
        guest_container_id,
        guest_output: "6.0,2.0,6.0".into(),
        crossed_digest,
        mesh_open_bearer,
        hardware_cuda_executed: true,
        revoke_refused,
        loss_refused,
        contention_refused,
        fresh_skew_refused,
    };
    fs::write(output, serde_json::to_vec_pretty(&observation)?)?;
    Ok(())
}

fn child_observation(
    executable: &Path,
    scratch: &Path,
    path_kind: &str,
    gpu_uuid: &str,
    guest_name: &str,
    provider_name: &str,
    guest_id: &str,
    provider_id: &str,
) -> Result<Observation> {
    let output = scratch.join(format!("{path_kind}.json"));
    let status = Command::new(executable)
        .arg("--execute-one")
        .arg("--output")
        .arg(&output)
        .arg("--path")
        .arg(path_kind)
        .arg("--gpu-uuid")
        .arg(gpu_uuid)
        .arg("--guest-device-name")
        .arg(guest_name)
        .arg("--provider-device-name")
        .arg(provider_name)
        .arg("--guest-device-id")
        .arg(guest_id)
        .arg("--provider-device-id")
        .arg(provider_id)
        .status()?;
    ensure!(status.success(), "{path_kind} helper failed with {status}");
    Ok(serde_json::from_slice(&fs::read(output)?)?)
}

fn append_observation(
    bundle: &mut Bundle,
    observation: &Observation,
    generation: u64,
) -> Result<()> {
    append(
        bundle,
        "provider_helper",
        observation.helper_pid,
        generation,
        "started",
        &observation.gpu_uuid,
    )?;
    append(
        bundle,
        "guest",
        observation.guest_pid,
        generation,
        "projected_cuda_executed",
        &format!(
            "path={};gpu={};container={};output={};crossed={};bearer={};hardware={}",
            observation.path,
            observation.gpu_uuid,
            observation.guest_container_id,
            observation.guest_output,
            observation.crossed_digest,
            observation.mesh_open_bearer,
            observation.hardware_cuda_executed
        ),
    )?;
    match observation.path.as_str() {
        "direct" => append(
            bundle,
            "mesh_route",
            observation.helper_pid,
            generation,
            "direct_traversed",
            &observation.crossed_digest,
        )?,
        "relay" if observation.route_pid != 0 => append(
            bundle,
            "mesh_relay",
            observation.route_pid,
            generation,
            "relay_traversed",
            &observation.crossed_digest,
        )?,
        _ => return Err(anyhow!("route observation has no live traversal process")),
    }
    if observation.revoke_refused {
        append(
            bundle,
            "provider_helper",
            observation.helper_pid,
            generation,
            "revoke_refused",
            "revoked",
        )?;
    }
    if observation.loss_refused {
        append(
            bundle,
            "provider_helper",
            observation.helper_pid,
            generation,
            "loss_refused",
            "device_lost",
        )?;
    }
    if observation.contention_refused {
        append(
            bundle,
            "provider_helper",
            observation.helper_pid,
            generation,
            "contention_refused",
            "limit_exceeded",
        )?;
    }
    if observation.fresh_skew_refused {
        append(
            bundle,
            "provider_helper",
            observation.helper_pid,
            generation,
            "fresh_skew_refused",
            "unsupported_version",
        )?;
    }
    Ok(())
}

fn append(
    bundle: &mut Bundle,
    actor: &str,
    pid: u32,
    generation: u64,
    kind: &str,
    detail: &str,
) -> Result<()> {
    let sequence = bundle.events.len() as u64 + 1;
    let previous = bundle
        .events
        .last()
        .map(|event| event.digest.clone())
        .unwrap_or_else(|| "blake3:genesis".into());
    let digest = event_digest(
        &bundle.run_id,
        sequence,
        actor,
        pid,
        generation,
        kind,
        detail,
        &previous,
    );
    bundle.events.push(Event {
        sequence,
        actor: actor.into(),
        pid,
        generation,
        kind: kind.into(),
        detail: detail.into(),
        previous,
        digest,
    });
    Ok(())
}

fn verify_command(args: &[String]) -> Result<()> {
    let bundle: Bundle = serde_json::from_slice(&fs::read(required(args, "--bundle")?)?)?;
    verify_bundle(&bundle)
}

fn verify_bundle(bundle: &Bundle) -> Result<()> {
    ensure!(bundle.schema == SCHEMA, "unknown evidence schema");
    ensure!(bundle.guest_device_name != bundle.provider_device_name);
    ensure!(bundle.guest_device_id != bundle.provider_device_id);
    ensure!(bundle.first_gpu_uuid != bundle.second_gpu_uuid);
    ensure!(
        bundle.first_guest_container_id != bundle.second_guest_container_id,
        "guest container did not restart"
    );
    for digest in [
        &bundle.driver_digest,
        &bundle.astd_digest,
        &bundle.libcuda_digest,
        &bundle.guest_binary_digest,
        &bundle.guest_launcher_digest,
        &bundle.guest_image_digest,
        &bundle.provider_image_digest,
    ] {
        ensure!(is_sha256(digest), "invalid artifact digest {digest}");
    }
    let mut previous = "blake3:genesis".to_owned();
    for (index, event) in bundle.events.iter().enumerate() {
        ensure!(event.sequence == index as u64 + 1, "event sequence gap");
        ensure!(event.previous == previous, "event chain fork");
        ensure!(
            event.digest
                == event_digest(
                    &bundle.run_id,
                    event.sequence,
                    &event.actor,
                    event.pid,
                    event.generation,
                    &event.kind,
                    &event.detail,
                    &event.previous,
                ),
            "event digest mismatch"
        );
        previous = event.digest.clone();
    }
    let direct = required_event(bundle, "projected_cuda_executed", "path=direct;")?;
    let relay = required_event(bundle, "projected_cuda_executed", "path=relay;")?;
    for event in [direct, relay] {
        ensure!(event.detail.contains("output=6.0,2.0,6.0"));
        ensure!(event.detail.contains("bearer=false"));
        ensure!(event.detail.contains("hardware=true"));
    }
    ensure!(direct.detail.contains(&bundle.first_gpu_uuid));
    ensure!(relay.detail.contains(&bundle.second_gpu_uuid));
    ensure!(direct.detail.contains(&bundle.first_guest_container_id));
    ensure!(relay.detail.contains(&bundle.second_guest_container_id));
    required_event(bundle, "revoke_refused", "revoked")?;
    required_event(bundle, "loss_refused", "device_lost")?;
    required_event(bundle, "contention_refused", "limit_exceeded")?;
    required_event(bundle, "fresh_skew_refused", "unsupported_version")?;
    let direct_route = required_event(bundle, "direct_traversed", "blake3:")?;
    let relay_route = required_event(bundle, "relay_traversed", "blake3:")?;
    ensure!(
        direct.detail.contains(&direct_route.detail),
        "direct route digest is not bound to guest transcript"
    );
    ensure!(
        relay.detail.contains(&relay_route.detail),
        "relay route digest is not bound to guest transcript"
    );
    ensure!(
        relay_route.pid != 0,
        "relay traversal has no process identity"
    );
    let daemon = bundle
        .events
        .iter()
        .filter(|event| event.actor == "provider_astd")
        .collect::<Vec<_>>();
    ensure!(
        daemon.len() == 2 && daemon[0].pid != daemon[1].pid,
        "astd did not restart"
    );
    ensure!(direct.pid != relay.pid, "guest did not restart");
    let helpers = bundle
        .events
        .iter()
        .filter(|event| event.kind == "started" && event.actor == "provider_helper")
        .collect::<Vec<_>>();
    ensure!(
        helpers.len() == 2 && helpers[0].pid != helpers[1].pid,
        "helper did not restart"
    );
    Ok(())
}

fn required_event<'a>(bundle: &'a Bundle, kind: &str, detail: &str) -> Result<&'a Event> {
    bundle
        .events
        .iter()
        .find(|event| event.kind == kind && event.detail.contains(detail))
        .ok_or_else(|| anyhow!("missing transcript event {kind} / {detail}"))
}

fn write_evidence(path: &Path, bundle: &Bundle) -> Result<()> {
    let transcript_root = bundle
        .events
        .last()
        .context("empty transcript")?
        .digest
        .clone();
    let text = format!(
        "guest_image_digest={}\nprovider_image_digest={}\nguest_container_id={},{}\nguest_device_name={}\nprovider_device_name={}\nguest_device_id={}\nprovider_device_id={}\npath=guest-mesh-provider\ndirect_path=true\nrelay_path=true\nguest_path=/dev/nvidia0\nlibcuda_path=sha256:{}\nexecutor=cuda\nprovider_helper_kind=process\nguest_output=6.0,2.0,6.0\nprovider_astd_pid_before={}\nprovider_astd_pid_after={}\nprovider_helper_pid_before={}\nprovider_helper_pid_after={}\nguest_pid_before={}\nguest_pid_after={}\nprovider_astd_restarted=true\nprovider_helper_restarted=true\nguest_restarted=true\nrevoke=true\ncontention=true\nloss=true\nversion_skew_fresh_session=true\nversion_skew_error=unsupported_version\nmesh_open_bearer=false\nhardware_cuda_executed=true\ndriver_digest={}\nastd_digest={}\nlibcuda_digest={}\nguest_binary_digest={}\nguest_launcher_digest={}\ntranscript_root={}\n",
        bundle.guest_image_digest,
        bundle.provider_image_digest,
        bundle.first_guest_container_id,
        bundle.second_guest_container_id,
        bundle.guest_device_name,
        bundle.provider_device_name,
        bundle.guest_device_id,
        bundle.provider_device_id,
        bundle.libcuda_digest.trim_start_matches("sha256:"),
        bundle.events[0].pid,
        bundle.events.iter().find(|event| event.kind == "restarted").context("restart")?.pid,
        bundle.events.iter().find(|event| event.kind == "started" && event.actor == "provider_helper").context("helper")?.pid,
        bundle.events.iter().rev().find(|event| event.kind == "started" && event.actor == "provider_helper").context("helper restart")?.pid,
        required_event(bundle, "projected_cuda_executed", "path=direct;")?.pid,
        required_event(bundle, "projected_cuda_executed", "path=relay;")?.pid,
        bundle.driver_digest,
        bundle.astd_digest,
        bundle.libcuda_digest,
        bundle.guest_binary_digest,
        bundle.guest_launcher_digest,
        transcript_root,
    );
    fs::write(path, text)?;
    Ok(())
}

fn start_astd(binary: &Path, home: &Path, name: &str) -> Result<Child> {
    fs::create_dir_all(home)?;
    let child = Command::new(binary)
        .env("ASTERISM_HOME", home)
        .env("ASTERISM_MESH", "local")
        .env("ASTERISM_DEVICE_NAME", name)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    thread::sleep(Duration::from_millis(500));
    ensure!(process_alive(child.id()), "astd exited during startup");
    Ok(child)
}

fn relay_proxy(args: &[String]) -> Result<()> {
    let listen = PathBuf::from(required(args, "--listen")?);
    let upstream = PathBuf::from(required(args, "--upstream")?);
    let listener = UnixListener::bind(&listen)?;
    let (guest, _) = listener.accept()?;
    let provider = UnixStream::connect(upstream)?;
    let mut guest_to_provider = guest.try_clone()?;
    let mut provider_writer = provider.try_clone()?;
    let forward = thread::spawn(move || -> io::Result<()> {
        io::copy(&mut guest_to_provider, &mut provider_writer)?;
        provider_writer.shutdown(Shutdown::Write)
    });
    let mut provider_reader = provider;
    let mut guest_writer = guest;
    io::copy(&mut provider_reader, &mut guest_writer)?;
    guest_writer.shutdown(Shutdown::Write)?;
    forward
        .join()
        .map_err(|_| anyhow!("relay forwarding thread panicked"))??;
    Ok(())
}

fn wait_for_socket(path: &Path, child: &Child) -> Result<()> {
    for _ in 0..100 {
        if path.exists() {
            return Ok(());
        }
        ensure!(
            process_alive(child.id()),
            "relay proxy exited before binding"
        );
        thread::sleep(Duration::from_millis(10));
    }
    Err(anyhow!("relay proxy did not bind {}", path.display()))
}

fn stop(mut child: Child) -> Result<()> {
    child.kill().ok();
    child.wait().ok();
    Ok(())
}

fn process_alive(pid: u32) -> bool {
    unsafe { libc_kill(pid as i32, 0) == 0 }
}

#[cfg(unix)]
unsafe fn libc_kill(pid: i32, signal: i32) -> i32 {
    unsafe extern "C" {
        fn kill(pid: i32, signal: i32) -> i32;
    }
    unsafe { kill(pid, signal) }
}

#[cfg(not(unix))]
unsafe fn libc_kill(_pid: i32, _signal: i32) -> i32 {
    0
}

fn ensure_success(status: ExitStatus, stderr: &[u8], label: &str) -> Result<()> {
    ensure!(
        status.success(),
        "{label} failed with {status}: {}",
        String::from_utf8_lossy(stderr)
    );
    Ok(())
}

fn event_digest(
    run_id: &str,
    sequence: u64,
    actor: &str,
    pid: u32,
    generation: u64,
    kind: &str,
    detail: &str,
    previous: &str,
) -> String {
    digest_bytes(
        format!("{run_id}\0{sequence}\0{actor}\0{pid}\0{generation}\0{kind}\0{detail}\0{previous}")
            .as_bytes(),
    )
}

fn digest_bytes(bytes: &[u8]) -> String {
    format!("blake3:{}", blake3::hash(bytes).to_hex())
}

fn sha256_file(path: &Path) -> Result<String> {
    let mut file = fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    let mut encoded = String::with_capacity(71);
    encoded.push_str("sha256:");
    for byte in hasher.finalize() {
        encoded.push_str(&format!("{byte:02x}"));
    }
    Ok(encoded)
}

fn is_sha256(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn device_id(seed: &str) -> String {
    blake3::hash(seed.as_bytes()).to_hex().to_string()
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn scratch(label: &str) -> Result<PathBuf> {
    let path = std::env::temp_dir().join(format!(
        "asterism-nvidia-{label}-{}-{}",
        std::process::id(),
        Uuid::new_v4()
    ));
    fs::create_dir_all(&path)?;
    Ok(path)
}

fn git(command: &str, argument: &str) -> Result<String> {
    let output = Command::new("git")
        .arg(command)
        .args(argument.split_whitespace())
        .output()?;
    ensure_success(output.status, &output.stderr, "git")?;
    Ok(String::from_utf8(output.stdout)?.trim().to_owned())
}

fn required<'a>(args: &'a [String], name: &str) -> Result<&'a str> {
    let index = args
        .iter()
        .position(|arg| arg == name)
        .with_context(|| format!("missing {name}"))?;
    args.get(index + 1)
        .map(String::as_str)
        .with_context(|| format!("missing value for {name}"))
}

fn env_required(name: &str) -> Result<String> {
    std::env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .with_context(|| format!("{name} is required"))
}

fn output_value(text: &str, key: &str) -> Result<String> {
    text.lines()
        .find_map(|line| line.strip_prefix(&format!("{key}=")))
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .with_context(|| format!("guest transcript is missing {key}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn synthetic_self_report_is_not_an_evidence_bundle() {
        let text = b"path=guest-mesh-provider\nhardware_cuda_executed=true\n";
        assert!(serde_json::from_slice::<Bundle>(text).is_err());
    }

    #[test]
    fn hash_chain_detects_rewritten_event() {
        let mut bundle = fixture();
        verify_bundle(&bundle).unwrap();
        bundle.events[1].detail.push_str(";forged=true");
        assert!(verify_bundle(&bundle).is_err());
    }

    #[test]
    fn reference_and_local_direct_events_do_not_pass() {
        for forbidden in ["path=local-direct;", "hardware=false"] {
            let mut bundle = fixture();
            let event = bundle
                .events
                .iter_mut()
                .find(|event| event.kind == "projected_cuda_executed")
                .unwrap();
            event.detail = forbidden.into();
            assert!(verify_bundle(&bundle).is_err());
        }
    }

    fn fixture() -> Bundle {
        let digest = "sha256:".to_owned() + &"a".repeat(64);
        let mut bundle = Bundle {
            schema: SCHEMA.into(),
            run_id: "fixture".into(),
            candidate_sha: "a".repeat(40),
            tree_digest: "b".repeat(40),
            driver_digest: digest.clone(),
            astd_digest: digest.clone(),
            libcuda_digest: digest.clone(),
            guest_binary_digest: digest.clone(),
            guest_launcher_digest: digest.clone(),
            guest_image_digest: digest.clone(),
            provider_image_digest: digest,
            guest_device_name: "guest".into(),
            provider_device_name: "provider".into(),
            guest_device_id: "1".repeat(64),
            provider_device_id: "2".repeat(64),
            first_guest_container_id: "a".repeat(64),
            second_guest_container_id: "b".repeat(64),
            first_gpu_uuid: "GPU-first".into(),
            second_gpu_uuid: "GPU-second".into(),
            events: Vec::new(),
        };
        append(
            &mut bundle,
            "provider_astd",
            10,
            1,
            "started",
            "authenticated_mesh_daemon",
        )
        .unwrap();
        append(
            &mut bundle,
            "provider_helper",
            20,
            1,
            "started",
            "GPU-first",
        )
        .unwrap();
        let crossed_a = format!("blake3:{}", "a".repeat(64));
        let direct_detail = format!("path=direct;gpu=GPU-first;container={};output=6.0,2.0,6.0;crossed={crossed_a};bearer=false;hardware=true", bundle.first_guest_container_id);
        append(
            &mut bundle,
            "guest",
            30,
            1,
            "projected_cuda_executed",
            &direct_detail,
        )
        .unwrap();
        append(
            &mut bundle,
            "mesh_route",
            20,
            1,
            "direct_traversed",
            &crossed_a,
        )
        .unwrap();
        append(
            &mut bundle,
            "provider_helper",
            20,
            1,
            "revoke_refused",
            "revoked",
        )
        .unwrap();
        append(
            &mut bundle,
            "provider_astd",
            11,
            2,
            "restarted",
            "authenticated_mesh_daemon",
        )
        .unwrap();
        append(
            &mut bundle,
            "provider_helper",
            21,
            2,
            "started",
            "GPU-second",
        )
        .unwrap();
        let crossed_b = format!("blake3:{}", "b".repeat(64));
        let relay_detail = format!("path=relay;gpu=GPU-second;container={};output=6.0,2.0,6.0;crossed={crossed_b};bearer=false;hardware=true", bundle.second_guest_container_id);
        append(
            &mut bundle,
            "guest",
            31,
            2,
            "projected_cuda_executed",
            &relay_detail,
        )
        .unwrap();
        append(
            &mut bundle,
            "mesh_relay",
            40,
            2,
            "relay_traversed",
            &crossed_b,
        )
        .unwrap();
        append(
            &mut bundle,
            "provider_helper",
            21,
            2,
            "loss_refused",
            "device_lost",
        )
        .unwrap();
        append(
            &mut bundle,
            "provider_helper",
            21,
            2,
            "contention_refused",
            "limit_exceeded",
        )
        .unwrap();
        append(
            &mut bundle,
            "provider_helper",
            21,
            2,
            "fresh_skew_refused",
            "unsupported_version",
        )
        .unwrap();
        bundle
    }
}
