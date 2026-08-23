//! Native container runtime boundary.
//!
//! Linux uses a rootless user/mount/pid/network namespace plus a delegated
//! cgroup-v2 leaf. The namespace holder exposes one private Unix control
//! socket for state, exec and stop. Other hosts have typed adapters that
//! refuse until their managed utility-VM implementation exists.

use std::fs;
#[cfg(any(target_os = "linux", all(test, target_family = "unix")))]
use std::io::Read;
use std::io::{BufRead, BufReader, Write};
#[cfg(any(target_os = "linux", all(test, target_family = "unix")))]
use std::net::Shutdown;
#[cfg(any(target_os = "linux", all(test, target_family = "unix")))]
use std::os::unix::net::UnixListener;
#[cfg(target_family = "unix")]
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
#[cfg(target_os = "linux")]
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use asterism_core::hv::{
    ContainerControlEndpoint, ContainerNetworkEndpoint, ContainerRuntimeIdentity, ControlChannel,
    Handle, ImageKind, KernelObjectIdentity, Machine, RunState,
};
use asterism_core::instance::{Instance, RuntimeKind};
use asterism_core::proc::{Ownership, ProcId, Signal};
use asterism_core::{paths, tools};

pub const LINUX_ID: &str = "linux-rootless";
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub const MACOS_ID: &str = "macos-vz-container-utility-vm";
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
pub const WINDOWS_ID: &str = "windows-hyperv-container-utility-vm";
#[cfg(target_os = "linux")]
const MAX_EXEC_OUTPUT: usize = 1024 * 1024;
pub const EXEC_DEADLINE: Duration = Duration::from_secs(30);
const CONTROL_DEADLINE: Duration = Duration::from_secs(2);
#[cfg(target_os = "linux")]
const CONTROL_CGROUP: &str = "asterism-control";
/// Map the caller to container root while assigning the remaining container
/// IDs from its subordinate ranges. A one-ID map makes ordinary OCI images
/// fail as soon as a service changes to its declared uid (nginx uses 101).
const ROOTLESS_USER_ARGS: &[&str] = &["--user", "--map-auto", "--map-root-user"];

trait Adapter: Send + Sync {
    fn id(&self) -> &'static str;
    fn probe(&self) -> Result<Machine>;
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
struct LinuxRootless;
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
struct MacosVzUtilityVm;
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
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
            tools::tool("newuidmap").context(
                "native containers need uidmap and an /etc/subuid range for this account",
            )?;
            tools::tool("newgidmap").context(
                "native containers need uidmap and an /etc/subgid range for this account",
            )?;
            tools::tool("debugfs")
                .context("the Linux rootless container adapter needs e2fsprogs debugfs")?;
            tools::tool("slirp4netns").context(
                "the Linux rootless container adapter needs slirp4netns for outbound networking",
            )?;
            tools::tool("ip").context("the Linux rootless container adapter needs iproute2 ip")?;
            tools::run(
                Command::new(unshare)
                    .args(ROOTLESS_USER_ARGS)
                    .args(["--mount", "--", "true"]),
            )
            .context(
                "this host does not permit a subordinate-ID user namespace; assign this account ranges in /etc/subuid and /etc/subgid",
            )?;
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
    network: Network,
    bootstrap: Option<String>,
}

/// slirp4netns owns both the outbound NAT and loopback-only publishing.
/// Its API socket is private instance state, never a TCP control endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Network {
    api: PathBuf,
    publish: Vec<asterism_core::instance::PortForward>,
    #[serde(default)]
    egress: Option<EgressBridge>,
}

/// The one host service a container may reach while slirp host-loopback access
/// stays disabled. Only this socket directory is mounted into the namespace.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct EgressBridge {
    source: PathBuf,
    target: PathBuf,
    guest_port: u16,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case")]
enum ControlRequest {
    Hello,
    Exec { argv: Vec<String>, timeout_ms: u64 },
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
    if inst.volumes.iter().any(|v| v.is_block()) {
        bail!("native container block volumes need a rootless block-device mapper; refusing to expose a regular-file placeholder as a disk");
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
    let egress = crate::egress::seed_config(inst)
        .context("starting the container's secret-egress projection")?;
    let bootstrap = asterism_core::profile::Bootstrap::resolve(&inst.profiles)
        .context("resolving the container's bootstrap profiles")?;
    install_bootstrap(&rootfs, &bootstrap)?;
    let mut env = strings("Env");
    env.extend(
        asterism_core::seed::egress_environment(&egress)
            .into_iter()
            .map(|(name, value)| format!("{name}={value}")),
    );
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
        env,
        workdir: image["WorkingDir"].as_str().map(str::to_owned),
        binds,
        network: Network {
            api: dir.join("slirp4netns-api.sock"),
            publish: inst.publish.clone(),
            egress: (!egress.is_empty()).then(|| EgressBridge {
                source: crate::egress::container_transport_dir(&inst.name),
                target: PathBuf::from("/run/asterism-egress"),
                guest_port: crate::egress::CONTAINER_EGRESS_PORT,
            }),
        },
        bootstrap: (!bootstrap.is_empty()).then(|| bootstrap.runcmd()),
    };
    fs::write(&spec, serde_json::to_vec_pretty(&value)?)?;
    Ok(Prepared { spec })
}

/// Place generated profile files in the extracted OCI root without ever
/// resolving an image-controlled symlink.  Profile content is public guest
/// configuration; secret handles remain in the process environment instead.
fn install_bootstrap(rootfs: &Path, bootstrap: &asterism_core::profile::Bootstrap) -> Result<()> {
    for (guest, mode, contents) in bootstrap.files() {
        let target = safe_file_target(rootfs, Path::new(&guest))?;
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&target, contents)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = u32::from_str_radix(mode, 8)
                .with_context(|| format!("parsing profile mode {mode:?}"))?;
            fs::set_permissions(&target, fs::Permissions::from_mode(mode))?;
        }
    }
    Ok(())
}

fn safe_file_target(rootfs: &Path, guest: &Path) -> Result<PathBuf> {
    use std::path::Component;
    if !guest.is_absolute() {
        bail!(
            "container configuration file {} is not absolute",
            guest.display()
        );
    }
    let mut target = rootfs.to_path_buf();
    let components: Vec<_> = guest.components().collect();
    for (index, component) in components.iter().enumerate() {
        match component {
            Component::RootDir => continue,
            Component::Normal(name) => target.push(name),
            _ => bail!(
                "container configuration file {} is not normalized",
                guest.display()
            ),
        }
        if index + 1 == components.len() {
            match fs::symlink_metadata(&target) {
                Ok(metadata) if metadata.file_type().is_symlink() || metadata.is_dir() => {
                    bail!(
                        "container configuration target {} is not a regular file",
                        guest.display()
                    )
                }
                Ok(_) | Err(_) => {}
            }
        } else if let Ok(metadata) = fs::symlink_metadata(&target) {
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                bail!(
                    "container configuration file {} crosses an image symlink",
                    guest.display()
                );
            }
        }
    }
    Ok(target)
}

#[cfg(target_os = "linux")]
fn delegated_cgroup(id: &str, cpus: u32, mem_mib: u32) -> Result<PathBuf> {
    static DELEGATION: OnceLock<Mutex<()>> = OnceLock::new();
    let _guard = DELEGATION
        .get_or_init(|| Mutex::new(()))
        .lock()
        .map_err(|_| anyhow::anyhow!("container cgroup delegation lock was poisoned"))?;
    let membership = fs::read_to_string("/proc/self/cgroup")?;
    let relative = membership
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .context("this host is not using the unified cgroup-v2 hierarchy")?;
    let root = delegation_root(relative)?;
    prepare_delegated_root(&root)?;
    let leaf = root.join(format!("asterism-{}", id.replace('-', "")));
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

#[cfg(target_os = "linux")]
fn delegation_root(relative: &str) -> Result<PathBuf> {
    let relative = relative.trim();
    if relative.is_empty() || relative == "/" {
        bail!("rootless container cgroups require a delegated service subtree");
    }
    let current = Path::new("/sys/fs/cgroup").join(relative.trim_start_matches('/'));
    if current.file_name().and_then(|name| name.to_str()) == Some(CONTROL_CGROUP) {
        return current
            .parent()
            .map(Path::to_path_buf)
            .context("the Asterism control cgroup has no delegated parent");
    }
    Ok(current)
}

#[cfg(target_os = "linux")]
fn prepare_delegated_root(root: &Path) -> Result<()> {
    let control = root.join(CONTROL_CGROUP);
    match fs::create_dir(&control) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "creating the manager leaf under delegated cgroup {}",
                    root.display()
                )
            })
        }
    }

    // A cgroup-v2 domain may not both contain processes and distribute CPU or
    // memory to children. Move every process in this one delegated unit into
    // the manager leaf; descendants they spawn inherit that leaf, while each
    // container runtime later moves into an instance sibling.
    for _ in 0..16 {
        let members = fs::read_to_string(root.join("cgroup.procs"))?;
        if members.trim().is_empty() {
            break;
        }
        for pid in members.lines().filter(|pid| !pid.trim().is_empty()) {
            if let Err(error) = fs::write(control.join("cgroup.procs"), format!("{pid}\n")) {
                if error.raw_os_error() != Some(libc::ESRCH) {
                    return Err(error).with_context(|| {
                        format!("moving process {pid} into {}", control.display())
                    });
                }
            }
        }
    }
    if !fs::read_to_string(root.join("cgroup.procs"))?
        .trim()
        .is_empty()
    {
        bail!(
            "delegated cgroup {} kept receiving manager processes while it was being split",
            root.display()
        );
    }

    let available = fs::read_to_string(root.join("cgroup.controllers"))?;
    let available: std::collections::HashSet<_> = available.split_whitespace().collect();
    for controller in ["cpu", "memory", "pids"] {
        if !available.contains(controller) {
            bail!(
                "delegated cgroup {} does not offer the {controller} controller",
                root.display()
            );
        }
    }
    fs::write(root.join("cgroup.subtree_control"), "+cpu +memory +pids").with_context(|| {
        format!(
            "enabling cpu/memory/pids in delegated cgroup {}",
            root.display()
        )
    })?;
    Ok(())
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
        .args(ROOTLESS_USER_ARGS)
        .args([
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
    let wrapper = match ProcId::capture(child.id()) {
        Ok(wrapper) => wrapper,
        Err(error) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(error).context("capturing the namespace wrapper identity");
        }
    };
    std::thread::spawn(move || {
        let _ = child.wait();
    });
    let deadline = Instant::now() + Duration::from_secs(5);
    let host_pid = loop {
        let timeout = deadline
            .checked_duration_since(Instant::now())
            .unwrap_or_default()
            .min(Duration::from_secs(1));
        match startup_call(
            &spec.control,
            &ControlRequest::Hello,
            Some(timeout),
        ) {
            Ok((ControlResponse::Ready { host_pid }, peer_pid)) if host_pid == peer_pid => {
                break Ok(host_pid)
            }
            Ok((ControlResponse::Ready { host_pid }, peer_pid)) => break Err(anyhow::anyhow!(
                "container control claimed pid {host_pid}, but the connected Unix peer is pid {peer_pid}"
            )),
            Ok((ControlResponse::Error { message }, _)) => break Err(anyhow::anyhow!(message)),
            _ if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(25)),
            _ => break Err(anyhow::anyhow!(
                "container helper did not establish its control socket at {}",
                spec.control.display()
            )),
        }
    };
    let host_pid = match host_pid {
        Ok(host_pid) => host_pid,
        Err(error) => {
            return Err(failed_start(error, &spec, &wrapper, None));
        }
    };
    let proc = match ProcId::capture(host_pid).context("capturing the namespace holder identity") {
        Ok(proc) => proc,
        Err(error) => {
            return Err(failed_start(error, &spec, &wrapper, None));
        }
    };
    match cgroup_populated(&spec.cgroup) {
        Ok(true) => {}
        Ok(false) => {
            let error = anyhow::anyhow!(
                "container control answered, but delegated cgroup {} contains no process",
                spec.cgroup.display()
            );
            return Err(failed_start(error, &spec, &wrapper, Some(&proc)));
        }
        Err(error) => {
            let error = error.context("validating the launched container cgroup");
            return Err(failed_start(error, &spec, &wrapper, Some(&proc)));
        }
    }
    let ns = |kind: &str| PathBuf::from(format!("/proc/{host_pid}/ns/{kind}"));
    let user_namespace = ns("user");
    let mount_namespace = ns("mnt");
    let pid_namespace = ns("pid");
    let network_namespace = ns("net");
    let identity = (|| -> Result<ContainerRuntimeIdentity> {
        if !cgroup_contains(&spec.cgroup, host_pid)? {
            bail!(
                "container control peer pid {host_pid} is not a member of delegated cgroup {}",
                spec.cgroup.display()
            );
        }
        runtime_identity(
            &user_namespace,
            &mount_namespace,
            &pid_namespace,
            &network_namespace,
            &spec.cgroup,
        )
    })();
    let identity = match identity {
        Ok(identity) => identity,
        Err(error) => {
            let error = error.context("capturing the native-container runtime identity");
            return Err(failed_start(error, &spec, &wrapper, Some(&proc)));
        }
    };
    let network_process = match start_slirp(host_pid, &spec.network, deadline) {
        Ok(process) => process,
        Err(error) => {
            let error = error.context("configuring rootless container networking");
            return Err(failed_start(error, &spec, &wrapper, Some(&proc)));
        }
    };
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
            user_namespace,
            mount_namespace,
            pid_namespace,
            network_namespace,
            cgroup: spec.cgroup,
            identity: Some(identity),
            network: Some(ContainerNetworkEndpoint {
                api: spec.network.api,
                process: network_process,
            }),
        }),
        started_at: asterism_core::instance::now_unix(),
    })
}

/// No failed launch may return while its namespace holder is still alive.
/// Otherwise a caller sees an error while durable-looking cgroup/socket state
/// remains for reconciliation to fence forever.
fn failed_start(
    launch: anyhow::Error,
    spec: &Spec,
    wrapper: &ProcId,
    holder: Option<&ProcId>,
) -> anyhow::Error {
    match abort_start(spec, wrapper, holder) {
        Ok(()) => launch,
        Err(cleanup) => anyhow::anyhow!(
            "container launch failed: {launch:#}; failed launch was not clean: {cleanup:#}"
        ),
    }
}

fn abort_start(spec: &Spec, wrapper: &ProcId, holder: Option<&ProcId>) -> Result<()> {
    let _ = startup_call(&spec.control, &ControlRequest::Stop, Some(CONTROL_DEADLINE));
    let graceful = Instant::now() + Duration::from_millis(500);
    while cgroup_populated(&spec.cgroup).unwrap_or(true) && Instant::now() < graceful {
        std::thread::sleep(Duration::from_millis(25));
    }

    // The helper may have failed before joining the cgroup, so both exact
    // identities are retired whether or not cgroup state is already visible.
    if let Some(holder) = holder {
        let _ = holder.signal(Signal::Kill);
    }
    let _ = wrapper.signal(Signal::Kill);
    let kill_error = if cgroup_populated(&spec.cgroup).unwrap_or(true) {
        fs::write(spec.cgroup.join("cgroup.kill"), "1")
            .err()
            .map(|error| error.to_string())
    } else {
        None
    };

    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let populated = cgroup_populated(&spec.cgroup)?;
        let holder_alive = holder.is_some_and(ProcId::alive);
        if !populated && !holder_alive && !wrapper.alive() {
            let _ = fs::remove_file(&spec.control);
            let _ = fs::remove_dir(&spec.cgroup);
            return Ok(());
        }
        if Instant::now() >= deadline {
            bail!(
                "container cleanup deadline expired (cgroup populated={populated}, holder alive={holder_alive}, wrapper alive={}, cgroup.kill error={})",
                wrapper.alive(),
                kill_error.as_deref().unwrap_or("none")
            );
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

/// Start slirp after the namespace holder exists, then ask its control API to
/// install every published loopback forward. No shell command or host firewall
/// rule can create a listener here; a successful API response is required.
#[cfg(target_os = "linux")]
fn start_slirp(host_pid: u32, network: &Network, deadline: Instant) -> Result<ProcId> {
    let _ = fs::remove_file(&network.api);
    let slirp = tools::tool("slirp4netns")?;
    let mut child = Command::new(slirp)
        .args(["--configure", "--disable-host-loopback", "--api-socket"])
        .arg(&network.api)
        .arg(host_pid.to_string())
        .arg("tap0")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .context("starting slirp4netns for the rootless container")?;
    let process = match ProcId::capture(child.id()) {
        Ok(process) => process,
        Err(error) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(error).context("capturing the slirp4netns process identity");
        }
    };
    while !network.api.exists() {
        if let Some(status) = child.try_wait()? {
            bail!("slirp4netns exited before its control API was ready ({status})");
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            bail!(
                "slirp4netns did not create its control API at {}",
                network.api.display()
            );
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    for forward in &network.publish {
        let result = slirp_call(
            &network.api,
            serde_json::json!({
                "execute": "add_hostfwd",
                "arguments": {
                    "proto": "tcp",
                    "host_addr": "127.0.0.1",
                    "host_port": forward.host,
                    "guest_addr": "10.0.2.100",
                    "guest_port": forward.guest,
                }
            }),
            deadline,
        )
        .with_context(|| format!("publishing {forward} through slirp4netns"));
        if let Err(error) = result {
            let _ = child.kill();
            let _ = child.wait();
            return Err(error);
        }
    }
    std::thread::spawn(move || {
        let _ = child.wait();
    });
    Ok(process)
}

#[cfg(not(target_os = "linux"))]
fn start_slirp(_host_pid: u32, _network: &Network, _deadline: Instant) -> Result<ProcId> {
    bail!("slirp4netns is only available to the Linux rootless adapter")
}

#[cfg(any(target_os = "linux", all(test, target_family = "unix")))]
fn slirp_call(socket: &Path, request: serde_json::Value, deadline: Instant) -> Result<()> {
    let mut stream = connect_unix_deadline(socket, deadline)
        .with_context(|| format!("connecting to slirp4netns API {}", socket.display()))?;
    let mut encoded = serde_json::to_vec(&request)?;
    encoded.push(b'\n');
    write_deadline(&mut stream, &encoded, deadline)?;
    // slirp4netns processes one request per connection and waits for EOF on
    // the write half before responding; retaining a duplex stream deadlocks
    // a successful port publication.
    stream.shutdown(Shutdown::Write)?;
    let response = read_line_deadline(&mut stream, deadline)?;
    let response: serde_json::Value =
        serde_json::from_str(&response).context("parsing slirp4netns control response")?;
    if let Some(error) = response.get("error") {
        bail!("slirp4netns refused the request: {error}");
    }
    if response.get("return").is_none() {
        bail!("slirp4netns returned no success value: {response}");
    }
    Ok(())
}

#[cfg(any(target_os = "linux", all(test, target_family = "unix")))]
fn connect_unix_deadline(socket: &Path, deadline: Instant) -> Result<UnixStream> {
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;

    if Instant::now() >= deadline {
        bail!("slirp4netns control exceeded the container launch deadline");
    }
    let path = socket.as_os_str().as_bytes();
    let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    if path.is_empty() || path.len() >= address.sun_path.len() || path.contains(&0) {
        bail!("invalid slirp4netns Unix socket path {}", socket.display());
    }
    address.sun_family = libc::AF_UNIX as libc::sa_family_t;
    #[cfg(target_os = "macos")]
    {
        address.sun_len = std::mem::size_of::<libc::sockaddr_un>() as u8;
    }
    for (target, source) in address.sun_path.iter_mut().zip(path) {
        *target = *source as libc::c_char;
    }
    // Linux can set both properties atomically at creation. The flags are not
    // portable Unix constants, so the macOS-hosted test build uses fcntl below.
    #[cfg(target_os = "linux")]
    let socket_type = libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC;
    #[cfg(not(target_os = "linux"))]
    let socket_type = libc::SOCK_STREAM;
    let fd = unsafe { libc::socket(libc::AF_UNIX, socket_type, 0) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error()).context("creating slirp API socket");
    }
    let stream = unsafe { UnixStream::from_raw_fd(fd) };
    #[cfg(not(target_os = "linux"))]
    {
        let status_flags = unsafe { libc::fcntl(stream.as_raw_fd(), libc::F_GETFL) };
        if status_flags < 0
            || unsafe {
                libc::fcntl(
                    stream.as_raw_fd(),
                    libc::F_SETFL,
                    status_flags | libc::O_NONBLOCK,
                )
            } < 0
        {
            return Err(std::io::Error::last_os_error())
                .context("making the slirp API socket nonblocking");
        }
        let descriptor_flags = unsafe { libc::fcntl(stream.as_raw_fd(), libc::F_GETFD) };
        if descriptor_flags < 0
            || unsafe {
                libc::fcntl(
                    stream.as_raw_fd(),
                    libc::F_SETFD,
                    descriptor_flags | libc::FD_CLOEXEC,
                )
            } < 0
        {
            return Err(std::io::Error::last_os_error())
                .context("making the slirp API socket close-on-exec");
        }
    }
    let result = unsafe {
        libc::connect(
            stream.as_raw_fd(),
            (&address as *const libc::sockaddr_un).cast(),
            std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t,
        )
    };
    if result != 0 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EINPROGRESS) {
            return Err(error).context("opening slirp API socket");
        }
        poll_deadline(stream.as_raw_fd(), libc::POLLOUT, deadline)?;
        let mut socket_error = 0;
        let mut length = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        if unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_ERROR,
                (&mut socket_error as *mut libc::c_int).cast(),
                &mut length,
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error()).context("checking slirp API connect");
        }
        if socket_error != 0 {
            return Err(std::io::Error::from_raw_os_error(socket_error))
                .context("opening slirp API socket");
        }
    }
    Ok(stream)
}

#[cfg(any(target_os = "linux", all(test, target_family = "unix")))]
fn poll_deadline(fd: std::os::fd::RawFd, events: libc::c_short, deadline: Instant) -> Result<()> {
    loop {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .context("slirp4netns control exceeded the container launch deadline")?;
        let millis = remaining.as_millis().max(1).min(i32::MAX as u128) as i32;
        let mut descriptor = libc::pollfd {
            fd,
            events,
            revents: 0,
        };
        let result = unsafe { libc::poll(&mut descriptor, 1, millis) };
        if result > 0 {
            return Ok(());
        }
        if result == 0 {
            bail!("slirp4netns control exceeded the container launch deadline");
        }
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::Interrupted {
            return Err(error).context("waiting for slirp4netns control");
        }
    }
}

#[cfg(any(target_os = "linux", all(test, target_family = "unix")))]
fn write_deadline(stream: &mut UnixStream, mut bytes: &[u8], deadline: Instant) -> Result<()> {
    use std::os::fd::AsRawFd;
    while !bytes.is_empty() {
        if Instant::now() >= deadline {
            bail!("slirp4netns control exceeded the container launch deadline");
        }
        match stream.write(bytes) {
            Ok(0) => bail!("slirp4netns closed its control socket while reading a request"),
            Ok(written) => bytes = &bytes[written..],
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                poll_deadline(stream.as_raw_fd(), libc::POLLOUT, deadline)?;
            }
            Err(error) => return Err(error).context("writing slirp4netns control request"),
        }
    }
    Ok(())
}

#[cfg(any(target_os = "linux", all(test, target_family = "unix")))]
fn read_line_deadline(stream: &mut UnixStream, deadline: Instant) -> Result<String> {
    use std::os::fd::AsRawFd;
    const MAX_SLIRP_RESPONSE: usize = 64 * 1024;
    let mut bytes = Vec::new();
    let mut chunk = [0_u8; 4096];
    loop {
        if Instant::now() >= deadline {
            bail!("slirp4netns control exceeded the container launch deadline");
        }
        match stream.read(&mut chunk) {
            Ok(0) if bytes.is_empty() => {
                bail!("slirp4netns closed its control socket without a response")
            }
            Ok(0) => {
                return String::from_utf8(bytes)
                    .context("slirp4netns control response is not UTF-8")
            }
            Ok(read) => {
                bytes.extend_from_slice(&chunk[..read]);
                if bytes.len() > MAX_SLIRP_RESPONSE {
                    bail!("slirp4netns control response exceeded {MAX_SLIRP_RESPONSE} bytes");
                }
                if let Some(newline) = bytes.iter().position(|byte| *byte == b'\n') {
                    bytes.truncate(newline);
                    return String::from_utf8(bytes)
                        .context("slirp4netns control response is not UTF-8");
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                poll_deadline(stream.as_raw_fd(), libc::POLLIN, deadline)?;
            }
            Err(error) => return Err(error).context("reading slirp4netns control response"),
        }
    }
}

pub fn state(handle: &Handle) -> Result<RunState> {
    let Some(control) = &handle.container_control else {
        bail!("container handle has no container control endpoint");
    };
    match call(handle, &ControlRequest::Hello, Some(Duration::from_secs(1))) {
        Ok(ControlResponse::Ready { host_pid })
            if handle.owned().is_some_and(|proc| proc.pid == host_pid) =>
        {
            Ok(RunState::Running)
        }
        Ok(ControlResponse::Ready { host_pid }) => {
            bail!("container control answered as pid {host_pid}, not the recorded namespace holder")
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
    let _ = call(handle, &ControlRequest::Stop, Some(CONTROL_DEADLINE))?;
    stop_network(control)?;
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

fn stop_network(control: &ContainerControlEndpoint) -> Result<()> {
    let Some(network) = &control.network else {
        return Ok(());
    };
    let _ = network.process.signal(Signal::Term)?;
    let graceful = Instant::now() + Duration::from_millis(500);
    while network.process.alive() && Instant::now() < graceful {
        std::thread::sleep(Duration::from_millis(25));
    }
    if network.process.alive() {
        let _ = network.process.signal(Signal::Kill)?;
    }
    let deadline = Instant::now() + Duration::from_secs(2);
    while network.process.alive() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(25));
    }
    if network.process.alive() {
        bail!(
            "slirp4netns pid {} did not stop before its lifecycle deadline",
            network.process.pid
        );
    }
    let _ = fs::remove_file(&network.api);
    Ok(())
}

pub fn exec(
    handle: &Handle,
    argv: Vec<String>,
    deadline: Duration,
) -> Result<(i32, String, String)> {
    if argv.is_empty() {
        bail!("container exec needs a command");
    }
    let timeout_ms = u64::try_from(deadline.as_millis()).unwrap_or(u64::MAX);
    match call(
        handle,
        &ControlRequest::Exec { argv, timeout_ms },
        Some(deadline + CONTROL_DEADLINE),
    )? {
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
    handle: &Handle,
    request: &ControlRequest,
    timeout: Option<Duration>,
) -> Result<ControlResponse> {
    let control = handle
        .container_control
        .as_ref()
        .context("container handle has no control endpoint")?;
    let proc = handle
        .owned()
        .context("container handle has no persisted process identity")?;
    match proc.check() {
        Ownership::Ours => {}
        Ownership::Gone => bail!("recorded container process {proc} is gone"),
        Ownership::Foreign(why) | Ownership::Unknown(why) => {
            bail!("refusing container control for {proc}: {why}")
        }
    }
    let mut stream = connect(&control.socket, timeout)?;
    let peer_pid = peer_pid(&stream)?;
    if peer_pid != proc.pid {
        bail!(
            "refusing container control socket {}: peer pid {peer_pid} is not recorded {proc}",
            control.socket.display()
        );
    }
    validate_runtime(control, proc.pid)?;
    exchange(&mut stream, request)
}

#[cfg(target_family = "unix")]
fn connect(socket: &Path, timeout: Option<Duration>) -> Result<UnixStream> {
    let stream = UnixStream::connect(socket)?;
    stream.set_read_timeout(timeout)?;
    stream.set_write_timeout(timeout)?;
    Ok(stream)
}

#[cfg(not(target_family = "unix"))]
fn connect(_socket: &Path, _timeout: Option<Duration>) -> Result<()> {
    bail!("native-container Unix control transport is unavailable on this host")
}

#[cfg(target_family = "unix")]
fn exchange(stream: &mut UnixStream, request: &ControlRequest) -> Result<ControlResponse> {
    serde_json::to_writer(&mut *stream, request)?;
    stream.write_all(b"\n")?;
    let mut line = String::new();
    BufReader::new(stream.try_clone()?).read_line(&mut line)?;
    Ok(serde_json::from_str(&line)?)
}

#[cfg(not(target_family = "unix"))]
fn exchange(_stream: &mut (), _request: &ControlRequest) -> Result<ControlResponse> {
    bail!("native-container Unix control transport is unavailable on this host")
}

/// The launch handshake has no persisted identity yet.  Its Unix peer PID is
/// therefore the authority from which the first `ProcId` is captured; the
/// helper's claimed PID must match it before a handle is ever returned.
#[cfg(target_family = "unix")]
fn startup_call(
    socket: &Path,
    request: &ControlRequest,
    timeout: Option<Duration>,
) -> Result<(ControlResponse, u32)> {
    let mut stream = connect(socket, timeout)?;
    let peer_pid = peer_pid(&stream)?;
    Ok((exchange(&mut stream, request)?, peer_pid))
}

#[cfg(not(target_family = "unix"))]
fn startup_call(
    _socket: &Path,
    _request: &ControlRequest,
    _timeout: Option<Duration>,
) -> Result<(ControlResponse, u32)> {
    bail!("native-container Unix control transport is unavailable on this host")
}

#[cfg(target_os = "linux")]
fn peer_pid(stream: &UnixStream) -> Result<u32> {
    use std::os::fd::AsRawFd;

    let mut credentials = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut credentials as *mut libc::ucred).cast(),
            &mut length,
        )
    };
    if result != 0 {
        return Err(std::io::Error::last_os_error())
            .context("reading native-container Unix peer credentials");
    }
    u32::try_from(credentials.pid).context("native-container Unix peer reported an invalid pid")
}

#[cfg(all(target_family = "unix", not(target_os = "linux")))]
fn peer_pid(_stream: &UnixStream) -> Result<u32> {
    bail!("native-container peer PID authentication is only available in the Linux adapter")
}

#[cfg(not(target_family = "unix"))]
fn peer_pid(_stream: &()) -> Result<u32> {
    bail!("native-container Unix peer authentication is unavailable on this host")
}

fn validate_runtime(control: &ContainerControlEndpoint, pid: u32) -> Result<()> {
    if !cgroup_contains(&control.cgroup, pid)? {
        bail!(
            "recorded container pid {pid} is not in delegated cgroup {}",
            control.cgroup.display()
        );
    }
    let expected = control
        .identity
        .as_ref()
        .context("container handle predates persisted cgroup/namespace identity")?;
    let actual = runtime_identity(
        &control.user_namespace,
        &control.mount_namespace,
        &control.pid_namespace,
        &control.network_namespace,
        &control.cgroup,
    )?;
    if &actual != expected {
        bail!(
            "container cgroup or namespace identity changed; refusing the stale control endpoint"
        );
    }
    Ok(())
}

#[cfg(target_family = "unix")]
fn runtime_identity(
    user_namespace: &Path,
    mount_namespace: &Path,
    pid_namespace: &Path,
    network_namespace: &Path,
    cgroup: &Path,
) -> Result<ContainerRuntimeIdentity> {
    use std::os::unix::fs::MetadataExt;

    let identity = |path: &Path| -> Result<KernelObjectIdentity> {
        let metadata = fs::metadata(path)
            .with_context(|| format!("reading kernel identity for {}", path.display()))?;
        Ok(KernelObjectIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    };
    Ok(ContainerRuntimeIdentity {
        user_namespace: identity(user_namespace)?,
        mount_namespace: identity(mount_namespace)?,
        pid_namespace: identity(pid_namespace)?,
        network_namespace: identity(network_namespace)?,
        cgroup: identity(cgroup)?,
    })
}

#[cfg(not(target_family = "unix"))]
fn runtime_identity(
    _user_namespace: &Path,
    _mount_namespace: &Path,
    _pid_namespace: &Path,
    _network_namespace: &Path,
    _cgroup: &Path,
) -> Result<ContainerRuntimeIdentity> {
    bail!("native-container namespace identity is unavailable on this host")
}

fn cgroup_contains(cgroup: &Path, pid: u32) -> Result<bool> {
    let members = match fs::read_to_string(cgroup.join("cgroup.procs")) {
        Ok(members) => members,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("reading cgroup membership from {}", cgroup.display()))
        }
    };
    Ok(members
        .lines()
        .any(|member| member.trim() == pid.to_string()))
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
#[cfg(target_os = "linux")]
pub fn helper_main(spec_path: &Path) -> Result<()> {
    let spec: Spec = serde_json::from_slice(&fs::read(spec_path)?)?;
    let _ = fs::remove_file(&spec.control);
    let listener = UnixListener::bind(&spec.control)?;
    fs::write(spec.cgroup.join("cgroup.procs"), "0")
        .context("moving the namespace holder into its delegated cgroup")?;
    bring_loopback_up()?;
    for bind in &spec.binds {
        let target = safe_mount_target(&spec.rootfs, &bind.target)?;
        bind_mount(&bind.source, &target)?;
    }
    if let Some(egress) = &spec.network.egress {
        let target = safe_mount_target(&spec.rootfs, &egress.target)?;
        bind_mount_readonly(&egress.source, &target)
            .context("mounting the container's narrow secret-egress transport")?;
    }
    for device in ["null", "zero", "random", "urandom"] {
        bind_device(&spec.rootfs, device)?;
    }
    install_fd_links(&spec.rootfs)?;
    safe_mount_target(&spec.rootfs, Path::new("/proc"))?;
    let console = fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&spec.console)?;
    let host_pid = host_pid()?;
    chroot(&spec.rootfs)?;
    mount_proc()?;
    if let Some(egress) = &spec.network.egress {
        start_egress_bridge(egress)?;
    }
    if let Some(bootstrap) = &spec.bootstrap {
        Command::new("/bin/sh")
            .args(["-c", bootstrap])
            .status()
            .context("starting the generated container bootstrap profile")?
            .success()
            .then_some(())
            .context("the generated container bootstrap profile was refused")?;
    }
    let mut child = spawn(
        &spec.argv,
        &spec.env,
        spec.workdir.as_deref(),
        Some(&console),
        false,
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
            Ok(ControlRequest::Exec { argv, timeout_ms }) => {
                let env = spec.env.clone();
                let workdir = spec.workdir.clone();
                std::thread::spawn(move || {
                    let budget = Duration::from_millis(timeout_ms).min(EXEC_DEADLINE);
                    let response = match spawn(&argv, &env, workdir.as_deref(), None, true)
                        .and_then(|child| wait_bounded(child, &stream, budget))
                    {
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

#[cfg(any(target_os = "linux", all(test, target_family = "unix")))]
fn install_fd_links(rootfs: &Path) -> Result<()> {
    use std::os::unix::fs::symlink;

    let dev = safe_mount_target(rootfs, Path::new("/dev"))?;
    for (name, target) in [
        ("fd", "/proc/self/fd"),
        ("stdin", "/proc/self/fd/0"),
        ("stdout", "/proc/self/fd/1"),
        ("stderr", "/proc/self/fd/2"),
    ] {
        let path = dev.join(name);
        match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.is_dir() => {
                bail!(
                    "container device link target {} is a directory",
                    path.display()
                )
            }
            Ok(_) => fs::remove_file(&path)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        symlink(target, &path)?;
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn helper_main(_spec_path: &Path) -> Result<()> {
    bail!("the native-container namespace helper is only available on Linux")
}

#[cfg(target_os = "linux")]
fn bring_loopback_up() -> Result<()> {
    let ip = tools::tool("ip")?;
    tools::run(Command::new(ip).args(["link", "set", "lo", "up"]))
        .context("bringing up the container loopback interface")
}

#[cfg(target_os = "linux")]
fn spawn(
    argv: &[String],
    env: &[String],
    workdir: Option<&str>,
    console: Option<&fs::File>,
    isolate_process_group: bool,
) -> Result<std::process::Child> {
    let (program, args) = argv
        .split_first()
        .context("container image has no command")?;
    let mut command = Command::new(program);
    if isolate_process_group {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
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

#[cfg(target_os = "linux")]
fn wait_bounded(
    mut child: std::process::Child,
    caller: &UnixStream,
    budget: Duration,
) -> Result<(i32, String, String)> {
    let stdout = child
        .stdout
        .take()
        .context("container exec has no stdout pipe")?;
    let stderr = child
        .stderr
        .take()
        .context("container exec has no stderr pipe")?;
    set_nonblocking(&stdout)?;
    set_nonblocking(&stderr)?;
    let (mut stdout, mut stderr) = (stdout, stderr);
    let (mut stdout_bytes, mut stderr_bytes) = (Vec::new(), Vec::new());
    let (mut stdout_truncated, mut stderr_truncated) = (false, false);
    let (mut stdout_eof, mut stderr_eof) = (false, false);
    let deadline = Instant::now() + budget;
    let mut status = None;
    loop {
        stdout_eof |= drain_exec_pipe(&mut stdout, &mut stdout_bytes, &mut stdout_truncated)?;
        stderr_eof |= drain_exec_pipe(&mut stderr, &mut stderr_bytes, &mut stderr_truncated)?;
        if status.is_none() {
            status = child.try_wait()?;
        }
        if let Some(status) = status.filter(|_| stdout_eof && stderr_eof) {
            return Ok((
                status.code().unwrap_or(128),
                captured_output(stdout_bytes, stdout_truncated),
                captured_output(stderr_bytes, stderr_truncated),
            ));
        }
        let cancellation = if caller_disconnected(caller)? {
            Some("container exec caller disconnected")
        } else if Instant::now() >= deadline {
            Some("container exec exceeded its lifecycle deadline")
        } else {
            None
        };
        if let Some(message) = cancellation {
            // The shell may already have exited while a descendant retains
            // its pipes. Killing the exec process group and dropping both
            // nonblocking readers makes this return independent of that
            // descendant's lifetime.
            let pid = i32::try_from(child.id()).context("container exec pid exceeds i32")?;
            let _ = unsafe { libc::kill(-pid, libc::SIGKILL) };
            let _ = child.kill();
            if status.is_none() {
                let _ = child.wait();
            }
            bail!(message);
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

#[cfg(target_os = "linux")]
fn set_nonblocking(pipe: &impl std::os::fd::AsRawFd) -> Result<()> {
    let fd = pipe.as_raw_fd();
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(std::io::Error::last_os_error())
            .context("making container exec capture nonblocking");
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn drain_exec_pipe(
    pipe: &mut impl Read,
    captured: &mut Vec<u8>,
    truncated: &mut bool,
) -> Result<bool> {
    let mut chunk = [0_u8; 16 * 1024];
    for _ in 0..64 {
        match pipe.read(&mut chunk) {
            Ok(0) => return Ok(true),
            Ok(read) => {
                let room = MAX_EXEC_OUTPUT.saturating_sub(captured.len());
                captured.extend_from_slice(&chunk[..read.min(room)]);
                *truncated |= read > room;
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return Ok(false),
            Err(error) => return Err(error).context("capturing container exec output"),
        }
    }
    Ok(false)
}

#[cfg(target_os = "linux")]
fn captured_output(mut bytes: Vec<u8>, truncated: bool) -> String {
    if truncated {
        bytes.extend_from_slice(b"\n[output truncated by astd]\n");
    }
    String::from_utf8_lossy(&bytes).into_owned()
}

#[cfg(target_os = "linux")]
fn caller_disconnected(stream: &UnixStream) -> Result<bool> {
    use std::os::fd::AsRawFd;

    let mut descriptor = libc::pollfd {
        fd: stream.as_raw_fd(),
        events: libc::POLLHUP | libc::POLLERR | libc::POLLRDHUP,
        revents: 0,
    };
    let result = unsafe { libc::poll(&mut descriptor, 1, 0) };
    if result < 0 {
        return Err(std::io::Error::last_os_error())
            .context("polling native-container exec caller");
    }
    Ok(result > 0 && descriptor.revents & (libc::POLLHUP | libc::POLLERR | libc::POLLRDHUP) != 0)
}

/// Resolve a guest mount point without following image-controlled symlinks.
/// A malicious rootfs must not turn `/data` into a host path before the bind
/// happens, even though the bind itself is private to the mount namespace.
#[cfg(any(target_os = "linux", test))]
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

#[cfg(target_os = "linux")]
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

#[cfg(target_os = "linux")]
fn bind_mount_readonly(source: &Path, target: &Path) -> Result<()> {
    bind_mount(source, target)?;
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    let target = CString::new(target.as_os_str().as_bytes())?;
    let result = unsafe {
        libc::mount(
            std::ptr::null(),
            target.as_ptr(),
            std::ptr::null(),
            libc::MS_BIND
                | libc::MS_REMOUNT
                | libc::MS_RDONLY
                | libc::MS_NOSUID
                | libc::MS_NODEV
                | libc::MS_NOEXEC,
            std::ptr::null(),
        )
    };
    if result != 0 {
        return Err(std::io::Error::last_os_error())
            .context("making the container egress transport read-only");
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn start_egress_bridge(egress: &EgressBridge) -> Result<()> {
    let listener = std::net::TcpListener::bind(("127.0.0.1", egress.guest_port))
        .context("binding the namespace-local secret-egress bridge")?;
    let socket = egress.target.join("proxy.sock");
    std::thread::spawn(move || {
        for incoming in listener.incoming() {
            let Ok(client) = incoming else { continue };
            let socket = socket.clone();
            std::thread::spawn(move || {
                if let Err(error) = bridge_egress_connection(client, &socket) {
                    eprintln!("asterism container egress bridge ended: {error:#}");
                }
            });
        }
    });
    Ok(())
}

#[cfg(target_os = "linux")]
fn bridge_egress_connection(mut client: std::net::TcpStream, socket: &Path) -> Result<()> {
    let mut proxy = UnixStream::connect(socket)
        .with_context(|| format!("connecting container egress to {}", socket.display()))?;
    let mut client_read = client.try_clone()?;
    let mut proxy_write = proxy.try_clone()?;
    let upload = std::thread::spawn(move || {
        let result = std::io::copy(&mut client_read, &mut proxy_write);
        let _ = proxy_write.shutdown(Shutdown::Write);
        result
    });
    std::io::copy(&mut proxy, &mut client)?;
    let _ = client.shutdown(std::net::Shutdown::Write);
    upload
        .join()
        .map_err(|_| anyhow::anyhow!("container egress upload bridge panicked"))??;
    Ok(())
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

#[cfg(target_os = "linux")]
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
    fn rootless_namespaces_map_ordinary_oci_service_accounts() {
        assert!(ROOTLESS_USER_ARGS.contains(&"--map-root-user"));
        assert!(
            ROOTLESS_USER_ARGS.contains(&"--map-auto"),
            "a one-ID map cannot represent nginx uid 101 or other image users"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn the_manager_leaf_resolves_back_to_one_delegated_root() {
        assert_eq!(
            delegation_root("/user.slice/asterism.service").unwrap(),
            Path::new("/sys/fs/cgroup/user.slice/asterism.service")
        );
        assert_eq!(
            delegation_root("/user.slice/asterism.service/asterism-control").unwrap(),
            Path::new("/sys/fs/cgroup/user.slice/asterism.service")
        );
        assert!(delegation_root("/").is_err());
    }

    #[cfg(target_family = "unix")]
    fn control_fixture(dir: &Path, pid: u32) -> ContainerControlEndpoint {
        let cgroup = dir.join("cgroup");
        fs::create_dir(&cgroup).unwrap();
        fs::write(cgroup.join("cgroup.procs"), format!("{pid}\n")).unwrap();
        fs::write(cgroup.join("cgroup.events"), "populated 1\n").unwrap();
        let namespace = |name: &str| {
            let path = dir.join(name);
            fs::write(&path, name).unwrap();
            path
        };
        let user_namespace = namespace("user.ns");
        let mount_namespace = namespace("mount.ns");
        let pid_namespace = namespace("pid.ns");
        let network_namespace = namespace("network.ns");
        let identity = runtime_identity(
            &user_namespace,
            &mount_namespace,
            &pid_namespace,
            &network_namespace,
            &cgroup,
        )
        .unwrap();
        ContainerControlEndpoint {
            socket: dir.join("control.sock"),
            user_namespace,
            mount_namespace,
            pid_namespace,
            network_namespace,
            cgroup,
            identity: Some(identity),
            network: None,
        }
    }

    #[cfg(target_os = "linux")]
    fn control_handle(control: ContainerControlEndpoint, proc: ProcId) -> Handle {
        Handle {
            backend: LINUX_ID.into(),
            pid: Some(proc.pid),
            proc: Some(proc),
            ctl: ControlChannel::Rpc {
                path: control.socket.clone(),
            },
            endpoint: None,
            container_control: Some(control),
            started_at: 1,
        }
    }

    #[test]
    fn control_wire_has_no_tcp_or_ssh_placeholder() {
        let endpoint = ContainerControlEndpoint {
            socket: "/run/user/1000/asterism/dev/container-control.sock".into(),
            user_namespace: "/proc/42/ns/user".into(),
            mount_namespace: "/proc/42/ns/mnt".into(),
            pid_namespace: "/proc/42/ns/pid".into(),
            network_namespace: "/proc/42/ns/net".into(),
            cgroup: "/sys/fs/cgroup/user.slice/asterism-dev".into(),
            identity: None,
            network: None,
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
            identity: None,
            network: None,
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
    #[cfg(target_family = "unix")]
    fn standard_fd_links_make_container_stdout_reachable() {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir(root.path().join("dev")).unwrap();
        install_fd_links(root.path()).unwrap();
        assert_eq!(
            fs::read_link(root.path().join("dev/fd")).unwrap(),
            Path::new("/proc/self/fd")
        );
        assert_eq!(
            fs::read_link(root.path().join("dev/stdout")).unwrap(),
            Path::new("/proc/self/fd/1")
        );
        assert_eq!(
            fs::read_link(root.path().join("dev/stderr")).unwrap(),
            Path::new("/proc/self/fd/2")
        );
    }

    #[test]
    #[cfg(target_family = "unix")]
    fn stopping_a_container_retires_its_exact_network_process_and_api() {
        let dir = tempfile::tempdir().unwrap();
        let mut child = Command::new("sleep").arg("30").spawn().unwrap();
        let process = ProcId::capture(child.id()).unwrap();
        let api = dir.path().join("slirp.sock");
        fs::write(&api, "owned").unwrap();
        let mut control = control_fixture(dir.path(), std::process::id());
        control.network = Some(ContainerNetworkEndpoint {
            api: api.clone(),
            process: process.clone(),
        });
        stop_network(&control).unwrap();
        let _ = child.wait();
        assert!(!process.alive());
        assert!(!api.exists());
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
    #[cfg(target_os = "linux")]
    fn ready_requires_the_recorded_peer_cgroup_and_namespaces() {
        let dir = tempfile::tempdir().unwrap();
        let proc = ProcId::capture(std::process::id()).unwrap();
        let control = control_fixture(dir.path(), proc.pid);
        let listener = UnixListener::bind(&control.socket).unwrap();
        let host_pid = proc.pid;
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = String::new();
            BufReader::new(stream.try_clone().unwrap())
                .read_line(&mut request)
                .unwrap();
            assert!(request.contains("hello"));
            serde_json::to_writer(&mut stream, &ControlResponse::Ready { host_pid }).unwrap();
            stream.write_all(b"\n").unwrap();
        });
        let handle = control_handle(control, proc);
        assert_eq!(state(&handle).unwrap(), RunState::Running);
        server.join().unwrap();
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn same_uid_stale_socket_cannot_impersonate_replaced_namespace() {
        let dir = tempfile::tempdir().unwrap();
        let proc = ProcId::capture(std::process::id()).unwrap();
        let control = control_fixture(dir.path(), proc.pid);
        fs::rename(
            &control.network_namespace,
            dir.path().join("old-network.ns"),
        )
        .unwrap();
        fs::write(&control.network_namespace, "replacement").unwrap();
        let listener = UnixListener::bind(&control.socket).unwrap();
        let server = std::thread::spawn(move || {
            let _ = listener.accept().unwrap();
        });
        let handle = control_handle(control, proc);
        let error = call(&handle, &ControlRequest::Hello, Some(CONTROL_DEADLINE)).unwrap_err();
        assert!(error.to_string().contains("identity changed"));
        server.join().unwrap();
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn exec_is_killed_when_its_caller_disconnects() {
        let (server, client) = UnixStream::pair().unwrap();
        drop(client);
        let child = Command::new("sh")
            .args(["-c", "sleep 5"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let pid = child.id();
        let started = Instant::now();
        let error = wait_bounded(child, &server, Duration::from_secs(5)).unwrap_err();
        assert!(error.to_string().contains("caller disconnected"));
        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(ProcId::capture(pid).is_err());
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn exec_is_killed_at_its_explicit_deadline() {
        let (server, _client) = UnixStream::pair().unwrap();
        let child = Command::new("sh")
            .args(["-c", "sleep 5"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let started = Instant::now();
        let error = wait_bounded(child, &server, Duration::from_millis(50)).unwrap_err();
        assert!(error.to_string().contains("lifecycle deadline"));
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[cfg(unix)]
    #[test]
    fn volume_targets_cannot_follow_image_symlinks() {
        let root = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink("/tmp", root.path().join("data")).unwrap();
        assert!(safe_mount_target(root.path(), Path::new("/data/work")).is_err());
        assert!(safe_mount_target(root.path(), Path::new("/../escape")).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn bootstrap_files_cannot_escape_through_an_image_symlink() {
        let root = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink("/tmp", root.path().join("etc")).unwrap();
        assert!(safe_file_target(root.path(), Path::new("/etc/profile.d/asterism.sh")).is_err());
        assert!(safe_file_target(root.path(), Path::new("/../../escape")).is_err());
    }

    #[test]
    fn slirp_network_spec_keeps_publishing_on_private_control_state() {
        let network = Network {
            api: "/run/user/1000/asterism/dev/slirp4netns-api.sock".into(),
            publish: vec!["8080:80".parse().unwrap()],
            egress: None,
        };
        let wire = serde_json::to_string(&network).unwrap();
        assert!(wire.contains("slirp4netns-api.sock"));
        assert!(wire.contains("8080"));
        assert!(!wire.contains("0.0.0.0"));
    }

    #[test]
    #[cfg(target_family = "unix")]
    fn slirp_control_request_closes_its_write_half_before_reading() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("slirp.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = String::new();
            stream.read_to_string(&mut request).unwrap();
            assert!(request.contains("add_hostfwd"));
            stream.write_all(b"{\"return\":{}}\n").unwrap();
        });
        slirp_call(
            &socket,
            serde_json::json!({ "execute": "add_hostfwd" }),
            Instant::now() + Duration::from_secs(1),
        )
        .unwrap();
        server.join().unwrap();
    }

    #[test]
    #[cfg(target_family = "unix")]
    fn slirp_control_accepts_an_eof_terminated_json_response() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("slirp-eof.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = String::new();
            stream.read_to_string(&mut request).unwrap();
            assert!(request.contains("add_hostfwd"));
            stream.write_all(b"{\"return\":{}}").unwrap();
        });
        slirp_call(
            &socket,
            serde_json::json!({ "execute": "add_hostfwd" }),
            Instant::now() + Duration::from_secs(1),
        )
        .unwrap();
        server.join().unwrap();
    }

    #[test]
    #[cfg(target_family = "unix")]
    fn slirp_control_refuses_an_empty_eof_response() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("slirp-empty.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = String::new();
            stream.read_to_string(&mut request).unwrap();
            assert!(request.contains("add_hostfwd"));
        });
        let error = slirp_call(
            &socket,
            serde_json::json!({ "execute": "add_hostfwd" }),
            Instant::now() + Duration::from_secs(1),
        )
        .unwrap_err();
        assert!(
            error.to_string().contains("without a response"),
            "{error:#}"
        );
        server.join().unwrap();
    }

    #[test]
    #[cfg(target_family = "unix")]
    fn slirp_control_refuses_malformed_eof_terminated_json() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("slirp-malformed.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = String::new();
            stream.read_to_string(&mut request).unwrap();
            stream.write_all(b"not-json").unwrap();
        });
        let error = slirp_call(
            &socket,
            serde_json::json!({ "execute": "add_hostfwd" }),
            Instant::now() + Duration::from_secs(1),
        )
        .unwrap_err();
        assert!(error.to_string().contains("parsing"), "{error:#}");
        server.join().unwrap();
    }

    #[test]
    #[cfg(target_family = "unix")]
    fn slirp_control_refuses_an_oversized_eof_response() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("slirp-oversized.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = String::new();
            stream.read_to_string(&mut request).unwrap();
            stream.write_all(&vec![b'x'; 64 * 1024 + 1]).unwrap();
        });
        let error = slirp_call(
            &socket,
            serde_json::json!({ "execute": "add_hostfwd" }),
            Instant::now() + Duration::from_secs(1),
        )
        .unwrap_err();
        assert!(error.to_string().contains("exceeded"), "{error:#}");
        server.join().unwrap();
    }

    #[test]
    #[cfg(target_family = "unix")]
    fn slirp_control_response_is_bounded_by_the_launch_deadline() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("slirp-unresponsive.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = String::new();
            stream.read_to_string(&mut request).unwrap();
            assert!(request.contains("add_hostfwd"));
            std::thread::sleep(Duration::from_millis(250));
        });
        let started = Instant::now();
        let error = slirp_call(
            &socket,
            serde_json::json!({ "execute": "add_hostfwd" }),
            Instant::now() + Duration::from_millis(50),
        )
        .unwrap_err();
        assert!(error.to_string().contains("launch deadline"), "{error:#}");
        assert!(started.elapsed() < Duration::from_millis(200));
        server.join().unwrap();
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn inherited_pipe_descendant_cannot_outlive_exec_deadline() {
        use std::os::unix::process::CommandExt;
        let (server, _client) = UnixStream::pair().unwrap();
        let child = Command::new("sh")
            .args(["-c", "sleep 5 & exit 0"])
            .process_group(0)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let started = Instant::now();
        let error = wait_bounded(child, &server, Duration::from_millis(50)).unwrap_err();
        assert!(
            error.to_string().contains("lifecycle deadline"),
            "{error:#}"
        );
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn failed_post_handshake_launch_drains_holder_and_wrapper() {
        let dir = tempfile::tempdir().unwrap();
        let cgroup = dir.path().join("cgroup");
        fs::create_dir(&cgroup).unwrap();
        fs::write(cgroup.join("cgroup.events"), "populated 1\n").unwrap();
        fs::write(cgroup.join("cgroup.kill"), "").unwrap();
        let spawn_sleeper = || {
            let mut child = Command::new("sleep").arg("30").spawn().unwrap();
            let proc = ProcId::capture(child.id()).unwrap();
            std::thread::spawn(move || {
                let _ = child.wait();
            });
            proc
        };
        let wrapper = spawn_sleeper();
        let holder = spawn_sleeper();
        let events = cgroup.join("cgroup.events");
        let kill = cgroup.join("cgroup.kill");
        let kernel = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(2);
            while Instant::now() < deadline {
                if fs::read_to_string(&kill).unwrap_or_default().trim() == "1" {
                    fs::write(&events, "populated 0\n").unwrap();
                    return;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            panic!("cleanup never requested cgroup.kill");
        });
        let spec = Spec {
            rootfs: dir.path().join("rootfs"),
            control: dir.path().join("missing-control.sock"),
            cgroup,
            console: dir.path().join("console"),
            argv: vec!["true".into()],
            env: Vec::new(),
            workdir: None,
            binds: Vec::new(),
            network: Network {
                api: dir.path().join("slirp.sock"),
                publish: Vec::new(),
                egress: None,
            },
            bootstrap: None,
        };
        abort_start(&spec, &wrapper, Some(&holder)).unwrap();
        kernel.join().unwrap();
        assert!(!wrapper.alive());
        assert!(!holder.alive());
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn namespace_bridge_reaches_only_its_unix_proxy() {
        use std::net::{TcpListener, TcpStream};
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("proxy.sock");
        let unix = UnixListener::bind(&socket).unwrap();
        let proxy = std::thread::spawn(move || {
            let (mut stream, _) = unix.accept().unwrap();
            let mut request = String::new();
            stream.read_to_string(&mut request).unwrap();
            assert_eq!(request, "narrow");
            stream.write_all(b"reachable").unwrap();
        });
        let tcp = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = tcp.local_addr().unwrap().port();
        let bridge = std::thread::spawn(move || {
            let (client, _) = tcp.accept().unwrap();
            bridge_egress_connection(client, &socket).unwrap();
        });
        let mut client = TcpStream::connect(("127.0.0.1", port)).unwrap();
        client.write_all(b"narrow").unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        let mut response = String::new();
        client.read_to_string(&mut response).unwrap();
        assert_eq!(response, "reachable");
        bridge.join().unwrap();
        proxy.join().unwrap();
    }
}
