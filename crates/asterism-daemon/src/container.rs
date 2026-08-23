//! Native container runtime boundary.
//!
//! Linux uses a rootless user/mount/pid/network namespace plus a delegated
//! cgroup-v2 leaf. The namespace holder exposes one private Unix control
//! socket for state, exec and stop. Other hosts have typed adapters that
//! refuse until their managed utility-VM implementation exists.

use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use asterism_core::hv::{
    ContainerControlEndpoint, ControlChannel, Handle, ImageKind, Machine, RunState,
};
use asterism_core::instance::{Instance, RuntimeKind};
use asterism_core::proc::{ProcId, Signal};
use asterism_core::{paths, tools};

pub const LINUX_ID: &str = "linux-rootless";
pub const MACOS_ID: &str = "macos-vz-container-utility-vm";
pub const WINDOWS_ID: &str = "windows-hyperv-container-utility-vm";
const MAX_EXEC_OUTPUT: usize = 1024 * 1024;

trait Adapter: Send + Sync {
    fn id(&self) -> &'static str;
    fn probe(&self) -> Result<Machine>;
}

struct LinuxRootless;
struct MacosVzUtilityVm;
struct WindowsHyperVUtilityVm;

impl Adapter for LinuxRootless {
    fn id(&self) -> &'static str {
        LINUX_ID
    }

    fn probe(&self) -> Result<Machine> {
        #[cfg(target_os = "linux")]
        {
            let unshare = tools::tool("unshare")
                .context("the Linux rootless container adapter needs util-linux unshare")?;
            tools::tool("debugfs")
                .context("the Linux rootless container adapter needs e2fsprogs debugfs")?;
            tools::run(Command::new(unshare).args([
                "--user",
                "--map-root-user",
                "--mount",
                "--",
                "true",
            ]))
            .context("this host does not permit an unprivileged user/mount namespace")?;
            let probe = delegated_cgroup(&format!("probe{}", std::process::id()), 1, 16)?;
            fs::remove_dir(probe).context("removing the container delegation probe")?;
            Ok(Machine {
                backend: self.id().into(),
                machine_type: "linux-userns-cgroup-v2".into(),
                cpu: std::env::consts::ARCH.into(),
                hv_version: "native".into(),
            })
        }
        #[cfg(not(target_os = "linux"))]
        bail!("the {LINUX_ID} adapter is unavailable on this host")
    }
}

impl Adapter for MacosVzUtilityVm {
    fn id(&self) -> &'static str {
        MACOS_ID
    }

    fn probe(&self) -> Result<Machine> {
        bail!("the {} adapter is typed but unsupported: the managed VZ utility VM lifecycle is not implemented", self.id())
    }
}

impl Adapter for WindowsHyperVUtilityVm {
    fn id(&self) -> &'static str {
        WINDOWS_ID
    }

    fn probe(&self) -> Result<Machine> {
        bail!("the {} adapter is typed but unsupported: the managed Hyper-V utility VM lifecycle is not implemented", self.id())
    }
}

fn host_adapter() -> &'static dyn Adapter {
    #[cfg(target_os = "linux")]
    return &LinuxRootless;
    #[cfg(target_os = "macos")]
    return &MacosVzUtilityVm;
    #[cfg(target_os = "windows")]
    return &WindowsHyperVUtilityVm;
    #[allow(unreachable_code)]
    &MacosVzUtilityVm
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BindMount {
    source: PathBuf,
    target: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Spec {
    rootfs: PathBuf,
    control: PathBuf,
    cgroup: PathBuf,
    console: PathBuf,
    argv: Vec<String>,
    env: Vec<String>,
    workdir: Option<String>,
    binds: Vec<BindMount>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case")]
enum ControlRequest {
    Hello,
    Exec { argv: Vec<String> },
    Stop,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
enum ControlResponse {
    Ready {
        host_pid: u32,
    },
    Exec {
        status: i32,
        stdout: String,
        stderr: String,
    },
    Stopping,
    Error {
        message: String,
    },
}

#[derive(Debug)]
pub struct Prepared {
    spec: PathBuf,
}

pub fn machine() -> Result<Machine> {
    host_adapter().probe()
}

pub fn prepare(inst: &Instance) -> Result<Prepared> {
    if inst.machine.backend != host_adapter().id() {
        bail!(
            "instance {:?} was created for the {} container adapter, but this host exposes {}",
            inst.name,
            inst.machine.backend,
            host_adapter().id()
        );
    }
    if host_adapter().id() != LINUX_ID {
        return host_adapter().probe().map(|_| unreachable!());
    }
    if inst.runtime != RuntimeKind::Container {
        bail!("instance {:?} is not a container", inst.name);
    }
    if inst.image_kind != ImageKind::OciRootfs {
        bail!("runtime=container requires an OCI image, not a bootable disk image");
    }
    if !inst.publish.is_empty() {
        bail!("rootless container port publishing is unsupported until the slirp control adapter is present; no port was published");
    }
    if inst.volumes.iter().any(|v| v.is_block()) {
        bail!("native container block volumes are unsupported; no NBD disk is exposed as a placeholder");
    }
    if !inst.profiles.is_empty() {
        bail!("native container bootstrap profiles are unsupported; refusing to start an unconfigured container");
    }
    if !inst.secrets.is_empty() {
        bail!("native container secret egress is unsupported; refusing to start without the requested bindings");
    }

    let req = crate::backend::disk_req(inst)?;
    let dir = paths::instance_dir(&inst.name);
    fs::create_dir_all(&dir)?;
    let rootfs = dir.join("container-rootfs");
    if !rootfs.exists() {
        let stage = dir.join(format!(".container-rootfs-{}", std::process::id()));
        let _ = fs::remove_dir_all(&stage);
        fs::create_dir_all(&stage)?;
        let debugfs = tools::tool("debugfs").context("extracting the verified OCI filesystem")?;
        let destination = stage
            .to_str()
            .context("container rootfs staging path is not UTF-8")?
            .replace('\\', "\\\\")
            .replace('"', "\\\"");
        let command = format!("rdump / \"{destination}\"");
        tools::run(
            Command::new(debugfs)
                .args(["-R", &command])
                .arg(&req.base.path),
        )
        .context("extracting the OCI ext4 image without a privileged mount")?;
        fs::rename(&stage, &rootfs).context("publishing the extracted container rootfs")?;
    }

    let config: serde_json::Value = serde_json::from_slice(
        &fs::read(req.base.path.with_extension("json"))
            .context("reading the OCI config sidecar")?,
    )?;
    let image = &config["config"];
    let strings = |key: &str| -> Vec<String> {
        image[key]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|v| v.as_str().map(str::to_owned))
            .collect()
    };
    let mut argv = strings("Entrypoint");
    argv.extend(strings("Cmd"));
    if argv.is_empty() {
        bail!("the OCI image declares neither Entrypoint nor Cmd");
    }
    if image["User"]
        .as_str()
        .is_some_and(|user| !user.is_empty() && user != "0" && user != "root")
    {
        bail!("the rootless adapter does not yet map the OCI image's non-root User; refusing to run it as another identity");
    }
    let cgroup = delegated_cgroup(&inst.id, inst.shape.cpus, inst.shape.mem_mib)?;
    let control = dir.join("container-control.sock");
    let spec = dir.join("container.json");
    let binds = asterism_core::seed::shares(inst)
        .into_iter()
        .map(|share| BindMount {
            source: PathBuf::from(share.host_path),
            target: PathBuf::from(share.guest_path),
        })
        .collect();
    let value = Spec {
        rootfs,
        control,
        cgroup,
        console: dir.join("console.log"),
        argv,
        env: strings("Env"),
        workdir: image["WorkingDir"].as_str().map(str::to_owned),
        binds,
    };
    fs::write(&spec, serde_json::to_vec_pretty(&value)?)?;
    Ok(Prepared { spec })
}

#[cfg(target_os = "linux")]
fn delegated_cgroup(id: &str, cpus: u32, mem_mib: u32) -> Result<PathBuf> {
    let relative = fs::read_to_string("/proc/self/cgroup")?
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .context("this host is not using the unified cgroup-v2 hierarchy")?;
    let leaf = Path::new("/sys/fs/cgroup")
        .join(relative.trim_start_matches('/'))
        .join(format!("asterism-{}", id.replace('-', "")));
    fs::create_dir(&leaf).with_context(|| {
        format!(
            "creating delegated cgroup {} (rootless cgroup delegation is required)",
            leaf.display()
        )
    })?;
    let configured = (|| -> Result<()> {
        fs::write(
            leaf.join("memory.max"),
            (u64::from(mem_mib) * 1024 * 1024).to_string(),
        )?;
        fs::write(
            leaf.join("cpu.max"),
            format!("{} 100000", u64::from(cpus.max(1)) * 100000),
        )?;
        fs::write(leaf.join("pids.max"), "512")?;
        Ok(())
    })();
    if let Err(error) = configured {
        let _ = fs::remove_dir(&leaf);
        return Err(error).context("configuring delegated memory/cpu cgroup controllers");
    }
    Ok(leaf)
}

#[cfg(not(target_os = "linux"))]
fn delegated_cgroup(_id: &str, _cpus: u32, _mem_mib: u32) -> Result<PathBuf> {
    bail!("cgroup-v2 lifecycle is only available in the Linux adapter")
}

pub fn start(prepared: &Prepared) -> Result<Handle> {
    let spec: Spec = serde_json::from_slice(&fs::read(&prepared.spec)?)?;
    let _ = fs::remove_file(&spec.control);
    let unshare = tools::tool("unshare")?;
    let exe = std::env::current_exe()?;
    let mut child = Command::new(unshare)
        .args([
            "--user",
            "--map-root-user",
            "--mount",
            "--propagation",
            "private",
            "--pid",
            "--fork",
            "--uts",
            "--ipc",
            "--net",
        ])
        .arg(exe)
        .arg("__container-helper")
        .arg(&prepared.spec)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .context("starting the rootless namespace helper")?;
    let wrapper = ProcId::capture(child.id())?;
    std::thread::spawn(move || {
        let _ = child.wait();
    });
    let deadline = Instant::now() + Duration::from_secs(5);
    let host_pid = loop {
        match call(
            &spec.control,
            &ControlRequest::Hello,
            Some(Duration::from_secs(1)),
        ) {
            Ok(ControlResponse::Ready { host_pid }) => break host_pid,
            Ok(ControlResponse::Error { message }) => bail!(message),
            _ if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(25)),
            _ => bail!(
                "container helper did not establish its control socket at {}",
                spec.control.display()
            ),
        }
    };
    let proc = ProcId::capture(host_pid).context("capturing the namespace holder identity")?;
    // The wrapper merely waits for the namespace holder. Capture both during
    // launch, but persist and signal only the process that owns the socket.
    let _ = wrapper;
    if !cgroup_populated(&spec.cgroup)? {
        bail!(
            "container control answered, but delegated cgroup {} contains no process",
            spec.cgroup.display()
        );
    }
    let ns = |kind: &str| PathBuf::from(format!("/proc/{host_pid}/ns/{kind}"));
    Ok(Handle {
        backend: LINUX_ID.into(),
        pid: Some(host_pid),
        proc: Some(proc),
        ctl: ControlChannel::Rpc {
            path: spec.control.clone(),
        },
        endpoint: None,
        container_control: Some(ContainerControlEndpoint {
            socket: spec.control,
            user_namespace: ns("user"),
            mount_namespace: ns("mnt"),
            pid_namespace: ns("pid"),
            network_namespace: ns("net"),
            cgroup: spec.cgroup,
        }),
        started_at: asterism_core::instance::now_unix(),
    })
}

pub fn state(handle: &Handle) -> Result<RunState> {
    let Some(control) = &handle.container_control else {
        bail!("container handle has no container control endpoint");
    };
    match call(
        &control.socket,
        &ControlRequest::Hello,
        Some(Duration::from_secs(1)),
    ) {
        Ok(ControlResponse::Ready { .. }) if cgroup_populated(&control.cgroup)? => {
            Ok(RunState::Running)
        }
        Ok(ControlResponse::Ready { .. }) => {
            bail!("container control answered outside its recorded cgroup; refusing the inconsistent handle")
        }
        Ok(ControlResponse::Error { message }) => bail!(message),
        Ok(_) => bail!("container control returned the wrong response to a liveness probe"),
        Err(error) if cgroup_populated(&control.cgroup)? => Err(error).context(
            "container cgroup is populated but its control channel is unavailable; refusing to declare it stopped",
        ),
        Err(_) => {
            let _ = fs::remove_file(&control.socket);
            let _ = fs::remove_dir(&control.cgroup);
            Ok(RunState::Stopped)
        }
    }
}

pub fn stop(handle: &Handle, deadline: Duration) -> Result<()> {
    let control = handle
        .container_control
        .as_ref()
        .context("container handle has no control endpoint")?;
    let _ = call(
        &control.socket,
        &ControlRequest::Stop,
        Some(Duration::from_secs(2)),
    )?;
    let until = Instant::now() + deadline;
    while Instant::now() < until {
        if !cgroup_populated(&control.cgroup)? {
            let _ = fs::remove_dir(&control.cgroup);
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    if let Some(proc) = handle.owned() {
        proc.signal(Signal::Kill)?;
        let killed = Instant::now() + Duration::from_secs(5);
        while Instant::now() < killed {
            if !cgroup_populated(&control.cgroup)? {
                let _ = fs::remove_dir(&control.cgroup);
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(25));
        }
    }
    bail!("container did not stop before its lifecycle deadline")
}

pub fn exec(handle: &Handle, argv: Vec<String>) -> Result<(i32, String, String)> {
    if argv.is_empty() {
        bail!("container exec needs a command");
    }
    let control = handle
        .container_control
        .as_ref()
        .context("container handle has no control endpoint")?;
    match call(&control.socket, &ControlRequest::Exec { argv }, None)? {
        ControlResponse::Exec {
            status,
            stdout,
            stderr,
        } => Ok((status, stdout, stderr)),
        ControlResponse::Error { message } => bail!(message),
        _ => bail!("container control returned the wrong response to exec"),
    }
}

fn call(
    socket: &Path,
    request: &ControlRequest,
    timeout: Option<Duration>,
) -> Result<ControlResponse> {
    let mut stream = UnixStream::connect(socket)?;
    stream.set_read_timeout(timeout)?;
    stream.set_write_timeout(timeout)?;
    serde_json::to_writer(&mut stream, request)?;
    stream.write_all(b"\n")?;
    let mut line = String::new();
    BufReader::new(stream).read_line(&mut line)?;
    Ok(serde_json::from_str(&line)?)
}

fn cgroup_populated(cgroup: &Path) -> Result<bool> {
    let events = match fs::read_to_string(cgroup.join("cgroup.events")) {
        Ok(events) => events,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("reading lifecycle state from {}", cgroup.display()))
        }
    };
    events
        .lines()
        .find_map(|line| line.strip_prefix("populated "))
        .map(|value| value == "1")
        .context("cgroup.events has no populated field")
}

/// Entry point invoked only under `unshare`; never starts the daemon.
pub fn helper_main(spec_path: &Path) -> Result<()> {
    let spec: Spec = serde_json::from_slice(&fs::read(spec_path)?)?;
    let _ = fs::remove_file(&spec.control);
    let listener = UnixListener::bind(&spec.control)?;
    fs::write(spec.cgroup.join("cgroup.procs"), "0")
        .context("moving the namespace holder into its delegated cgroup")?;
    for bind in &spec.binds {
        let target = safe_mount_target(&spec.rootfs, &bind.target)?;
        bind_mount(&bind.source, &target)?;
    }
    for device in ["null", "zero", "random", "urandom"] {
        bind_device(&spec.rootfs, device)?;
    }
    safe_mount_target(&spec.rootfs, Path::new("/proc"))?;
    let console = fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&spec.console)?;
    let host_pid = host_pid()?;
    chroot(&spec.rootfs)?;
    mount_proc()?;
    let mut child = spawn(
        &spec.argv,
        &spec.env,
        spec.workdir.as_deref(),
        Some(&console),
    )?;
    for incoming in listener.incoming() {
        if child.try_wait()?.is_some() {
            break;
        }
        let mut stream = incoming?;
        let mut line = String::new();
        BufReader::new(stream.try_clone()?).read_line(&mut line)?;
        let response = match serde_json::from_str::<ControlRequest>(&line) {
            Ok(ControlRequest::Hello) => ControlResponse::Ready { host_pid },
            Ok(ControlRequest::Exec { argv }) => {
                let env = spec.env.clone();
                let workdir = spec.workdir.clone();
                std::thread::spawn(move || {
                    let response =
                        match spawn(&argv, &env, workdir.as_deref(), None).and_then(wait_bounded) {
                            Ok((status, stdout, stderr)) => ControlResponse::Exec {
                                status,
                                stdout,
                                stderr,
                            },
                            Err(error) => ControlResponse::Error {
                                message: format!("{error:#}"),
                            },
                        };
                    let _ = serde_json::to_writer(&mut stream, &response);
                    let _ = stream.write_all(b"\n");
                });
                continue;
            }
            Ok(ControlRequest::Stop) => {
                unsafe {
                    libc::kill(child.id() as i32, libc::SIGTERM);
                }
                ControlResponse::Stopping
            }
            Err(error) => ControlResponse::Error {
                message: format!("bad container control request: {error}"),
            },
        };
        serde_json::to_writer(&mut stream, &response)?;
        stream.write_all(b"\n")?;
        if matches!(response, ControlResponse::Stopping) {
            let _ = child.wait();
            break;
        }
    }
    let _ = fs::remove_file(&spec.control);
    Ok(())
}

fn spawn(
    argv: &[String],
    env: &[String],
    workdir: Option<&str>,
    console: Option<&fs::File>,
) -> Result<std::process::Child> {
    let (program, args) = argv
        .split_first()
        .context("container image has no command")?;
    let mut command = Command::new(program);
    command.args(args).env_clear();
    for assignment in env {
        if let Some((name, value)) = assignment.split_once('=') {
            command.env(name, value);
        }
    }
    command.env(
        "PATH",
        "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    );
    command.current_dir(workdir.filter(|p| !p.is_empty()).unwrap_or("/"));
    if let Some(console) = console {
        command
            .stdout(console.try_clone()?)
            .stderr(console.try_clone()?)
            .stdin(Stdio::null());
    } else {
        command
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .stdin(Stdio::null());
    }
    command
        .spawn()
        .with_context(|| format!("executing {program:?} in the container"))
}

fn wait_bounded(mut child: std::process::Child) -> Result<(i32, String, String)> {
    let stdout = child
        .stdout
        .take()
        .context("container exec has no stdout pipe")?;
    let stderr = child
        .stderr
        .take()
        .context("container exec has no stderr pipe")?;
    let read = |reader: Box<dyn Read + Send>| {
        std::thread::spawn(move || -> Result<String> {
            let mut bytes = Vec::new();
            reader
                .take((MAX_EXEC_OUTPUT + 1) as u64)
                .read_to_end(&mut bytes)?;
            if bytes.len() > MAX_EXEC_OUTPUT {
                bytes.truncate(MAX_EXEC_OUTPUT);
                bytes.extend_from_slice(b"\n[output truncated by astd]\n");
            }
            Ok(String::from_utf8_lossy(&bytes).into_owned())
        })
    };
    let stdout = read(Box::new(stdout));
    let stderr = read(Box::new(stderr));
    let status = child.wait()?.code().unwrap_or(128);
    let stdout = stdout
        .join()
        .map_err(|_| anyhow::anyhow!("stdout reader panicked"))??;
    let stderr = stderr
        .join()
        .map_err(|_| anyhow::anyhow!("stderr reader panicked"))??;
    Ok((status, stdout, stderr))
}

/// Resolve a guest mount point without following image-controlled symlinks.
/// A malicious rootfs must not turn `/data` into a host path before the bind
/// happens, even though the bind itself is private to the mount namespace.
fn safe_mount_target(rootfs: &Path, guest: &Path) -> Result<PathBuf> {
    use std::path::Component;
    if !guest.is_absolute() {
        bail!("container mount point {} is not absolute", guest.display());
    }
    let mut target = rootfs.to_path_buf();
    for component in guest.components() {
        match component {
            Component::RootDir => continue,
            Component::Normal(name) => target.push(name),
            _ => bail!(
                "container mount point {} is not an absolute normalized path",
                guest.display()
            ),
        }
        match fs::symlink_metadata(&target) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                bail!(
                    "container mount point {} crosses an image symlink",
                    guest.display()
                )
            }
            Ok(metadata) if !metadata.is_dir() => {
                bail!(
                    "container mount point {} crosses a non-directory",
                    guest.display()
                )
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => fs::create_dir(&target)?,
            Err(error) => return Err(error.into()),
        }
    }
    if target == rootfs {
        bail!("refusing to bind a volume over the container root");
    }
    Ok(target)
}

fn bind_device(rootfs: &Path, name: &str) -> Result<()> {
    let dev = safe_mount_target(rootfs, Path::new("/dev"))?;
    let target = dev.join(name);
    match fs::symlink_metadata(&target) {
        Ok(metadata) if metadata.file_type().is_symlink() || metadata.is_dir() => {
            bail!(
                "container device target {} is not a regular file",
                target.display()
            )
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::File::create(&target)?;
        }
        Err(error) => return Err(error.into()),
    }
    bind_mount(&Path::new("/dev").join(name), &target)
}

#[cfg(target_os = "linux")]
fn chroot(root: &Path) -> Result<()> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    let root = CString::new(root.as_os_str().as_bytes())?;
    if unsafe { libc::chroot(root.as_ptr()) } != 0 || unsafe { libc::chdir(c"/".as_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error()).context("entering the container rootfs");
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn chroot(_root: &Path) -> Result<()> {
    bail!("container helper is Linux-only")
}

#[cfg(target_os = "linux")]
fn bind_mount(source: &Path, target: &Path) -> Result<()> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    let source = CString::new(source.as_os_str().as_bytes())?;
    let target = CString::new(target.as_os_str().as_bytes())?;
    let result = unsafe {
        libc::mount(
            source.as_ptr(),
            target.as_ptr(),
            std::ptr::null(),
            libc::MS_BIND | libc::MS_REC,
            std::ptr::null(),
        )
    };
    if result != 0 {
        return Err(std::io::Error::last_os_error())
            .context("binding a container directory volume");
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn bind_mount(_source: &Path, _target: &Path) -> Result<()> {
    bail!("container bind mounts are Linux-only")
}

#[cfg(target_os = "linux")]
fn mount_proc() -> Result<()> {
    let result = unsafe {
        libc::mount(
            c"proc".as_ptr(),
            c"/proc".as_ptr(),
            c"proc".as_ptr(),
            libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
            std::ptr::null(),
        )
    };
    if result != 0 {
        return Err(std::io::Error::last_os_error())
            .context("mounting the container proc filesystem");
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn mount_proc() -> Result<()> {
    bail!("container proc mount is Linux-only")
}

fn host_pid() -> Result<u32> {
    let status = fs::read_to_string("/proc/self/status")?;
    status
        .lines()
        .find_map(|line| line.strip_prefix("NSpid:"))
        .and_then(|pids| pids.split_whitespace().next())
        .context("the kernel did not report the namespace holder's host pid")?
        .parse()
        .context("parsing the namespace holder's host pid")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_wire_has_no_tcp_or_ssh_placeholder() {
        let endpoint = ContainerControlEndpoint {
            socket: "/run/user/1000/asterism/dev/container-control.sock".into(),
            user_namespace: "/proc/42/ns/user".into(),
            mount_namespace: "/proc/42/ns/mnt".into(),
            pid_namespace: "/proc/42/ns/pid".into(),
            network_namespace: "/proc/42/ns/net".into(),
            cgroup: "/sys/fs/cgroup/user.slice/asterism-dev".into(),
        };
        let wire = serde_json::to_string(&endpoint).unwrap();
        assert!(wire.contains("container-control.sock"));
        assert!(!wire.contains("127.0.0.1"));
        assert!(!wire.contains("ssh"));
    }

    #[test]
    fn container_handle_uses_only_the_typed_control_endpoint() {
        let control = ContainerControlEndpoint {
            socket: "/run/user/1000/asterism/dev/container-control.sock".into(),
            user_namespace: "/proc/42/ns/user".into(),
            mount_namespace: "/proc/42/ns/mnt".into(),
            pid_namespace: "/proc/42/ns/pid".into(),
            network_namespace: "/proc/42/ns/net".into(),
            cgroup: "/sys/fs/cgroup/user.slice/asterism-dev".into(),
        };
        let handle = Handle {
            backend: LINUX_ID.into(),
            pid: Some(42),
            proc: None,
            ctl: ControlChannel::Rpc {
                path: control.socket.clone(),
            },
            endpoint: None,
            container_control: Some(control),
            started_at: 1,
        };
        assert!(handle.endpoint.is_none());
        assert_eq!(handle.ctl.path(), handle.container_control.unwrap().socket);
    }

    #[test]
    fn unsupported_platform_adapters_are_named_contracts() {
        let macos: &dyn Adapter = &MacosVzUtilityVm;
        let windows: &dyn Adapter = &WindowsHyperVUtilityVm;
        assert_eq!(macos.id(), "macos-vz-container-utility-vm");
        assert_eq!(windows.id(), "windows-hyperv-container-utility-vm");
        assert!(macos.probe().is_err());
        assert!(windows.probe().is_err());
    }

    #[test]
    fn volume_targets_cannot_follow_image_symlinks() {
        let root = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink("/tmp", root.path().join("data")).unwrap();
        assert!(safe_mount_target(root.path(), Path::new("/data/work")).is_err());
        assert!(safe_mount_target(root.path(), Path::new("/../escape")).is_err());
    }
}
