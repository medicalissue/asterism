//! Native Windows Hyper-V backend, expressed only in helper protocol terms.
//!
//! The daemon deliberately knows none of the APIs that implement this. It
//! selects capabilities, materialises disks, and sends versioned requests to
//! `astd-hyperv`. HCS/HCN/VirtDisk/Hyper-V Socket types stop at that process
//! boundary (ADR 0002).

use std::io::{BufRead, BufReader, Write};
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::OnceLock;
use std::time::Duration;

use anyhow::{bail, Context, Result};

use asterism_core::egress_door;
use asterism_core::guest;
use asterism_core::hv::{
    BootReq, Caps, ControlChannel, DirectKernel, DiskFormat, DiskSpec, GuestEgress, GuestEndpoint,
    Handle, Hypervisor, ImageKind, Prepared, Ready, RunState, SnapshotId,
};
use asterism_core::instance::Instance;
use asterism_core::oci;
use asterism_core::paths;
use asterism_core::proc::{ProcId, Signal};
use asterism_core::snapshot::{self, Snapshot};
use asterism_hyperv::{
    BootSource, DiskAttachment, EgressDoor, HostReady, Reply, Request, VmConfig, VmState,
    HELPER_BIN, OWNER, PROTOCOL_VERSION,
};

pub const ID: &str = "hyperv";
const NETWORK_ID: &str = "a57e1210-1e64-4a83-b48f-95dbe093e18a";

/// The HCN NAT's gateway and prefix, fixed by `hcn_network_document`.
const GATEWAY: &str = "172.29.64.1";

/// How long `astd` waits to be told this instance's egress door is open.
///
/// The helper binds the door against a compute system that HCS creates a
/// moment later, so it retries; this covers that plus the guest's own start.
const DOOR_DEADLINE: Duration = Duration::from_secs(120);

#[derive(Default)]
pub struct HyperV {
    probe: OnceLock<Probe>,
}

#[derive(Clone)]
struct Probe {
    helper: PathBuf,
    host: HostReady,
}

impl HyperV {
    pub fn new() -> Self {
        Self::default()
    }

    fn probed(&self) -> Result<&Probe> {
        if let Some(probe) = self.probe.get() {
            return Ok(probe);
        }
        let helper = helper_path()?;
        let host = match call(&helper, &Request::Probe)? {
            Reply::Ready { host } => host,
            other => bail!("{HELPER_BIN} answered probe with {other:?}"),
        };
        host.require_supported()?;
        Ok(self.probe.get_or_init(|| Probe { helper, host }))
    }

    fn request(&self, request: &Request) -> Result<Reply> {
        call(&self.probed()?.helper, request)?.into_result()
    }

    fn materialize(&self, source: &Path, destination: &Path, size_bytes: u64) -> Result<()> {
        if destination.exists() {
            return Ok(());
        }
        match self.request(&Request::MaterializeVhdx {
            source_raw: source.to_owned(),
            dest_vhdx: destination.to_owned(),
            size_bytes,
        })? {
            Reply::Materialized => Ok(()),
            other => bail!("{HELPER_BIN} answered VHDX materialization with {other:?}"),
        }
    }

    fn config(&self, req: &BootReq, prep: &Prepared) -> Result<VmConfig> {
        let path = config_path(&req.dir);
        if path.exists() {
            let mut config = VmConfig::read(&path)?;
            if config.instance != req.instance.name || config.system_id != req.instance.id {
                bail!(
                    "{} belongs to instance {:?} ({}) rather than {:?} ({})",
                    path.display(),
                    config.instance,
                    config.system_id,
                    req.instance.name,
                    req.instance.id
                );
            }
            config.seed_iso = req.seed.clone();
            config.root_vhdx = prep.root_path()?.to_owned();
            config.boot = boot_source(prep)?;
            config.console = console_pipe(&config.system_id).into();
            config.data_vhdx = self.data_disks(req)?;
            config.write(&path)?;
            return Ok(config);
        }

        let endpoint_id = uuid::Uuid::new_v4().to_string();
        let config = VmConfig {
            protocol: PROTOCOL_VERSION,
            owner: OWNER.into(),
            system_id: req.instance.id.clone(),
            instance: req.instance.name.clone(),
            root_vhdx: prep.root_path()?.to_owned(),
            data_vhdx: self.data_disks(req)?,
            seed_iso: req.seed.clone(),
            boot: boot_source(prep)?,
            console: console_pipe(&req.instance.id).into(),
            cpus: req.instance.shape.cpus,
            mem_mib: u64::from(req.instance.shape.mem_mib),
            network_id: NETWORK_ID.into(),
            // Network-config is built before the helper config exists, so
            // the address follows the durable Instance id, not this freshly
            // allocated endpoint id. Recreating an HCN endpoint cannot move
            // the guest's address.
            guest_ip: guest_ip(&req.instance.id)?,
            endpoint_id,
            mac: asterism_hyperv::mac_for(&req.instance.name),
            agent_key: paths::guest_agent_key_path(&req.instance.name),
            restore_state: None,
        };
        config.write(&path)?;
        Ok(config)
    }

    fn data_disks(&self, req: &BootReq) -> Result<Vec<DiskAttachment>> {
        req.extra_disks
            .iter()
            .enumerate()
            .map(|(index, disk)| {
                let (source, readonly) = match disk {
                    DiskSpec::File {
                        path,
                        format: DiskFormat::Raw,
                        readonly,
                    }
                    | DiskSpec::Block { path, readonly } => (path, *readonly),
                    DiskSpec::File {
                        path,
                        format: DiskFormat::Vhdx,
                        readonly,
                    } => {
                        return Ok(DiskAttachment {
                            path: path.clone(),
                            readonly: *readonly,
                        })
                    }
                    DiskSpec::File { format, .. } => {
                        bail!("the hyperv backend cannot attach a {format} data disk")
                    }
                    DiskSpec::Nbd { .. } | DiskSpec::NbdUnix { .. } => {
                        bail!("the hyperv backend cannot attach an NBD data disk")
                    }
                };
                let destination = req.dir.join(format!("data-{index}.vhdx"));
                let size = std::fs::metadata(source)
                    .with_context(|| format!("reading data disk {}", source.display()))?
                    .len();
                self.materialize(source, &destination, size)?;
                Ok(DiskAttachment {
                    path: destination,
                    readonly,
                })
            })
            .collect()
    }

    /// The kernel this instance boots, and the command line it boots with.
    ///
    /// An OCI image is a root filesystem with no bootloader. HCS takes the
    /// kernel and initrd as host files and starts the guest on them directly
    /// (`Chipset.LinuxKernelDirect`), so this backend needs no bootloader, no
    /// EFI partition and no firmware policy — the same shape every other
    /// backend has, expressed in the one field the compute service takes.
    fn direct_kernel(&self, req: &BootReq) -> Result<DirectKernel> {
        let (kernel, initrd) = oci::kernel()?;
        Ok(DirectKernel {
            kernel,
            initrd: Some(initrd),
            cmdline: oci_cmdline(req)?,
        })
    }

    /// Fold this instance's own parts into its private root filesystem.
    ///
    /// The same call every backend that boots an OCI image makes, with one
    /// backend-declared difference: this guest's door is carried over a
    /// Hyper-V Socket, so its init loads `hv_sock` rather than the virtio
    /// transport. Everything above the driver is identical, because the
    /// guest dials the same AF_VSOCK address either way.
    fn configure_oci_root(&self, req: &BootReq, prep: &Prepared) -> Result<()> {
        let inst = req.instance;
        let key = guest::Key::ensure(&paths::guest_agent_key_path(&inst.name))
            .with_context(|| format!("minting {:?}'s OCI guest-control key", inst.name))?;
        let agent = asterism_core::guest::Artifact::discover()
            .context("finding the packaged Linux OCI guest-control agent")?;
        let guest_control_boot = agent.oci_boot_script(&key);
        oci::configure_instance(
            &req.base.path,
            prep.root_path()?,
            &oci::InstanceParts {
                egress_over_vsock: true,
                vsock_transport: oci::VsockTransport::HyperV,
                shares: &req.shares,
                share_kind: None,
                egress: &req.egress,
                bootstrap: &req.bootstrap,
                gpu_boot: None,
                guest_control_boot: Some(&guest_control_boot),
            },
        )
    }

    /// Start this instance's secret-egress door, if it has a secret bound.
    ///
    /// Returns `None` for an unbound instance: no listener at all is the
    /// difference between a door that is shut and a door that is not there.
    fn open_door(&self, req: &BootReq, config: &VmConfig) -> Result<Option<Door>> {
        let inst = req.instance;
        if inst.secrets.is_empty() {
            return Ok(None);
        }
        let record = door_record_path(&config_path(&req.dir));
        if let Some(existing) = read_door_record(&record) {
            if existing.check().is_ours() {
                // A door this daemon opened for this instance and never
                // closed. Binding a second one against the same VM would
                // fail, and it would be the wrong fix for a door that works.
                return Ok(Some(Door {
                    proc: existing,
                    child: None,
                    record,
                }));
            }
        }
        let key = paths::guest_agent_key_path(&inst.name);
        guest::Key::ensure(&key)
            .with_context(|| format!("minting {:?}'s egress door key", inst.name))?;
        let request = Request::ServeEgress {
            door: Box::new(EgressDoor {
                system_id: config.system_id.clone(),
                instance: inst.name.clone(),
                pipe: crate::egress::vm_transport_name(&inst.name),
                key,
            }),
        };
        let helper = &self.probed()?.helper;
        let mut child = Command::new(helper)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .with_context(|| format!("starting {}", helper.display()))?;
        let mut stdin = child
            .stdin
            .take()
            .context("opening the door helper stdin")?;
        serde_json::to_writer(&mut stdin, &request)?;
        stdin.write_all(b"\n")?;
        drop(stdin);
        let proc = ProcId::capture(child.id()).context("recording the door helper's identity")?;
        write_door_record(&record, &proc)?;
        Ok(Some(Door {
            proc,
            child: Some(child),
            record,
        }))
    }

    fn handle_config(h: &Handle) -> Result<Option<VmConfig>> {
        if !matches!(h.ctl, ControlChannel::Helper { .. }) {
            bail!("a hyperv handle does not carry a helper config");
        }
        if !h.ctl.path().exists() {
            return Ok(None);
        }
        VmConfig::read(h.ctl.path()).map(Some)
    }
}

impl Hypervisor for HyperV {
    fn id(&self) -> &'static str {
        ID
    }

    fn probe(&self) -> Result<Ready> {
        let probe = self.probed()?;
        Ok(Ready {
            version: probe.host.windows.clone(),
            accel: "hyperv".into(),
            machine_type: "hcs-v2.1-generation-2".into(),
            cpu: "host".into(),
        })
    }

    fn caps(&self) -> Caps {
        Caps {
            live_snapshot: false,
            disk_snapshot: true,
            live_migration: false,
            disk_hotplug: false,
            shared_dir: None,
            nbd_disks: false,
            foreign_arch: false,
            // Not "direct kernel": Hyper-V has no such entry point. What it
            // has is UEFI, so `prepare` writes the same pinned kernel and
            // initrd onto a small EFI System Partition and lets the firmware
            // load them. Same capability, different mechanism (ADR 0005).
            direct_kernel: true,
            port_forward: false,
            // Every Hyper-V guest has its own address on the private HCN NAT,
            // so there is no host address only one guest can reach and the
            // door is built inside the guest instead: its agent listens on
            // the guest's own loopback and what it accepts leaves over this
            // VM's Hyper-V Socket, bound to this VM alone. Nothing binds a
            // host interface. See `asterism_core::egress_door` and ADR 0005.
            guest_egress: Some(GuestEgress::AgentVsock {
                gateway: egress_door::EGRESS_GUEST_GATEWAY,
                vsock_port: egress_door::EGRESS_VSOCK_PORT,
            }),
            disk_formats: &[DiskFormat::Raw],
            guest_gpu_projection: false,
        }
    }

    fn restore_disk_formats(&self) -> &'static [DiskFormat] {
        &[DiskFormat::Vhdx]
    }

    fn guest_config(&self, inst: &asterism_core::instance::Instance) -> Result<String> {
        let key = guest::Key::ensure(&paths::guest_agent_key_path(&inst.name))
            .with_context(|| format!("minting {:?}'s guest agent key", inst.name))?;
        Ok(guest::cloud_config(&key))
    }

    fn guest_network_config(
        &self,
        inst: &asterism_core::instance::Instance,
    ) -> Result<Option<String>> {
        // The private HCN NAT does not run DHCP. NoCloud has to configure the
        // synthetic NIC before the guest agent can answer on its control channel or SSH.
        Ok(Some(network_config(
            guest_ip(&inst.id)?,
            &asterism_hyperv::mac_for(&inst.name),
        )))
    }

    fn prepare(&self, req: &BootReq) -> Result<Prepared> {
        self.probed()?;
        if req.base.format != DiskFormat::Raw {
            bail!(
                "the hyperv backend consumes a raw base image and materialises a native VHDX; {} is {}",
                req.base.name,
                req.base.format
            );
        }
        let destination = req.dir.join("disk.vhdx");
        self.materialize(
            &req.base.path,
            &destination,
            u64::from(req.instance.shape.disk_gib) * (1 << 30),
        )?;
        let kernel = if req.base.kind == ImageKind::OciRootfs {
            Some(self.direct_kernel(req)?)
        } else {
            None
        };
        Ok(Prepared {
            root: DiskSpec::File {
                path: destination,
                format: DiskFormat::Vhdx,
                readonly: false,
            },
            firmware: None,
            kernel,
        })
    }

    fn boot(&self, req: &BootReq, prep: &Prepared) -> Result<Handle> {
        let oci = req.base.kind == ImageKind::OciRootfs;
        if !oci && !req.seed.is_file() {
            bail!("no cloud-init seed at {}", req.seed.display());
        }
        if oci {
            self.configure_oci_root(req, prep)?;
        }
        let config = self.config(req, prep)?;

        // The door is opened before the compute system exists, not after it
        // is running: a guest that came up before its door did would be a
        // guest holding a handle nothing honours. The helper retries its bind
        // until HCS has created the VM whose service table admits it.
        let door = self.open_door(req, &config)?;
        let booted = self.request(&Request::Boot {
            config: Box::new(config.clone()),
        });
        let guest_addr = match booted {
            Ok(Reply::Booted { guest_addr }) => guest_addr,
            Ok(other) => bail!("{HELPER_BIN} answered boot with {other:?}"),
            Err(error) => {
                if let Some(door) = door {
                    close_door(&door);
                }
                return Err(error);
            }
        };
        if let Some(door) = door {
            door.confirm(&config.instance)?;
        }
        Ok(Handle {
            backend: ID.into(),
            pid: None,
            proc: None,
            ctl: ControlChannel::Helper {
                path: config_path(&req.dir),
            },
            endpoint: Some(GuestEndpoint::GuestAddr { addr: guest_addr }),
            container_control: None,
            started_at: asterism_core::instance::now_unix(),
        })
    }

    fn stop(&self, h: &Handle, deadline: Duration) -> Result<()> {
        let Some(config) = Self::handle_config(h)? else {
            return Ok(());
        };
        shut_door(&door_record_path(h.ctl.path()));
        match self.request(&Request::Shutdown {
            system_id: config.system_id,
            timeout_ms: deadline.as_millis().min(u32::MAX as u128) as u32,
        })? {
            Reply::Stopped => Ok(()),
            other => bail!("{HELPER_BIN} answered shutdown with {other:?}"),
        }
    }

    fn kill(&self, h: &Handle) -> Result<()> {
        let Some(config) = Self::handle_config(h)? else {
            return Ok(());
        };
        shut_door(&door_record_path(h.ctl.path()));
        match self.request(&Request::Terminate {
            system_id: config.system_id,
            endpoint_id: Some(config.endpoint_id),
            network_id: None,
        })? {
            Reply::Stopped => Ok(()),
            other => bail!("{HELPER_BIN} answered terminate with {other:?}"),
        }
    }

    fn remove_instance_resources(&self, inst: &Instance) -> Result<()> {
        let path = config_path(&paths::instance_dir(&inst.name));
        let config = match VmConfig::read(&path) {
            Ok(config) => config,
            Err(_) if !path.exists() => return Ok(()),
            Err(error) => return Err(error),
        };
        shut_door(&door_record_path(&path));
        let network_id = if network_in_use_elsewhere(&inst.name, &config.network_id)? {
            None
        } else {
            Some(config.network_id.clone())
        };
        match self.request(&Request::Terminate {
            system_id: config.system_id,
            endpoint_id: Some(config.endpoint_id),
            network_id,
        })? {
            Reply::Stopped => Ok(()),
            other => bail!("{HELPER_BIN} answered cleanup with {other:?}"),
        }
    }

    fn state(&self, h: &Handle) -> Result<RunState> {
        let Some(config) = Self::handle_config(h)? else {
            return Ok(RunState::Stopped);
        };
        match self.request(&Request::State {
            system_id: config.system_id,
        })? {
            Reply::State {
                state: VmState::Running,
            } => Ok(RunState::Running),
            Reply::State { .. } => Ok(RunState::Stopped),
            other => bail!("{HELPER_BIN} answered state with {other:?}"),
        }
    }

    fn disk_snapshot(&self, prep: &Prepared, tag: &str) -> Result<SnapshotId> {
        snapshot::validate_tag(tag)?;
        let disk = prep.root_path()?;
        snapshot::take(instance_dir(disk)?, disk, tag)
    }

    fn disk_snapshot_list(&self, prep: &Prepared) -> Result<Vec<Snapshot>> {
        snapshot::list(instance_dir(prep.root_path()?)?)
    }

    fn disk_restore(&self, prep: &Prepared, snap: &SnapshotId) -> Result<()> {
        snapshot::validate_tag(&snap.0)?;
        let disk = prep.root_path()?;
        snapshot::restore(instance_dir(disk)?, disk, &snap.0)
    }

    fn disk_snapshot_remove(&self, prep: &Prepared, snap: &SnapshotId) -> Result<()> {
        snapshot::validate_tag(&snap.0)?;
        snapshot::remove(instance_dir(prep.root_path()?)?, &snap.0)
    }
}

// ---- the egress door -------------------------------------------------------

/// A door helper this daemon started, or adopted from its own earlier self.
struct Door {
    proc: ProcId,
    /// Present only for a helper this call spawned; the reply is read off it.
    child: Option<std::process::Child>,
    record: PathBuf,
}

impl Door {
    /// Wait to be told the door is open.
    ///
    /// The helper answers `Serving` only once its Hyper-V Socket is bound
    /// against this VM, so this is the point at which a guest's handle is
    /// backed by something. An adopted door has already said it.
    fn confirm(mut self, instance: &str) -> Result<()> {
        let Some(mut child) = self.child.take() else {
            return Ok(());
        };
        let stdout = child
            .stdout
            .take()
            .context("opening the door helper stdout")?;
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut line = String::new();
            let read = BufReader::new(stdout).read_line(&mut line);
            let _ = tx.send(read.map(|_| line));
        });
        let answer = match rx.recv_timeout(DOOR_DEADLINE) {
            Ok(Ok(line)) => line,
            Ok(Err(error)) => {
                let _ = self.proc.signal(Signal::Kill);
                return Err(error)
                    .with_context(|| format!("reading {instance:?}'s egress door helper reply"));
            }
            Err(_) => {
                let _ = self.proc.signal(Signal::Kill);
                let _ = std::fs::remove_file(&self.record);
                bail!(
                    "{instance:?}'s secret-egress door did not open within {}s",
                    DOOR_DEADLINE.as_secs()
                );
            }
        };
        match serde_json::from_str::<Reply>(answer.trim()) {
            Ok(Reply::Serving) => Ok(()),
            Ok(other) => {
                let _ = self.proc.signal(Signal::Kill);
                let _ = std::fs::remove_file(&self.record);
                bail!("{HELPER_BIN} answered the egress door with {other:?}")
            }
            Err(error) => {
                let _ = self.proc.signal(Signal::Kill);
                let _ = std::fs::remove_file(&self.record);
                Err(error).context("parsing the egress door helper reply")
            }
        }
    }
}

fn close_door(door: &Door) {
    let _ = door.proc.signal(Signal::Kill);
    let _ = std::fs::remove_file(&door.record);
}

/// Where a running door helper's identity is written, beside the VM config
/// it belongs to.
fn door_record_path(config: &Path) -> PathBuf {
    config.with_file_name("hyperv-egress.json")
}

fn read_door_record(path: &Path) -> Option<ProcId> {
    serde_json::from_slice(&std::fs::read(path).ok()?).ok()
}

fn write_door_record(path: &Path, proc: &ProcId) -> Result<()> {
    std::fs::write(path, serde_json::to_vec_pretty(proc)?)
        .with_context(|| format!("recording the egress door helper at {}", path.display()))
}

/// Close a door whose guest is going away. Only a process this daemon
/// recorded and still owns is signalled.
fn shut_door(record: &Path) {
    if let Some(proc) = read_door_record(record) {
        if proc.check().is_ours() {
            let _ = proc.signal(Signal::Kill);
        }
    }
    let _ = std::fs::remove_file(record);
}

// ---- OCI boot --------------------------------------------------------------

/// What HCS is asked to start, from what `prepare` resolved.
///
/// [`Prepared::kernel`] means the same thing here as on every other backend:
/// this guest boots a kernel rather than a disk with a bootloader on it.
fn boot_source(prep: &Prepared) -> Result<BootSource> {
    let Some(kernel) = &prep.kernel else {
        return Ok(BootSource::Uefi);
    };
    let initrd = kernel
        .initrd
        .clone()
        .context("a direct kernel boot on this backend needs an initrd")?;
    Ok(BootSource::LinuxKernel {
        kernel: kernel.kernel.clone(),
        initrd,
        cmdline: kernel.cmdline.clone(),
    })
}

/// The kernel command line, carrying everything this guest cannot discover
/// for itself.
///
/// `root=LABEL=asterism` rather than a device name: the label is what
/// `mke2fs -L asterism` wrote when the OCI rootfs was built, which is a fact
/// about the filesystem rather than about the order a SCSI controller
/// happened to enumerate its disks. The `asterism.*` keys are the same ones
/// every other backend passes, read by the generated init.
fn oci_cmdline(req: &BootReq) -> Result<String> {
    let address = guest_ip(&req.instance.id)?;
    Ok(format!(
        "root=LABEL=asterism rw console=ttyS0 net.ifnames=0 panic=10 init={init} \
         asterism.ip={address}/20 asterism.gw={GATEWAY} asterism.dns=1.1.1.1 \
         asterism.time={now}",
        init = oci::INIT_PATH,
        now = asterism_core::instance::now_unix(),
    ))
}

fn call(helper: &Path, request: &Request) -> Result<Reply> {
    let mut child = Command::new(helper)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("starting {}", helper.display()))?;
    let mut stdin = child.stdin.take().context("opening Hyper-V helper stdin")?;
    serde_json::to_writer(&mut stdin, request)?;
    stdin.write_all(b"\n")?;
    drop(stdin);
    let output = child.wait_with_output()?;
    if !output.status.success() {
        bail!(
            "{} failed: {}",
            helper.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    serde_json::from_slice(&output.stdout)
        .with_context(|| format!("parsing {} reply", helper.display()))
}

fn helper_path() -> Result<PathBuf> {
    asterism_core::hyperv::discover_helper()
}

fn config_path(dir: &Path) -> PathBuf {
    dir.join("hyperv.json")
}

fn network_in_use_elsewhere(instance: &str, network_id: &str) -> Result<bool> {
    let root = paths::home_dir().join("instances");
    let entries = match std::fs::read_dir(&root) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error).with_context(|| format!("reading {}", root.display())),
    };
    for entry in entries {
        let entry = entry?;
        if entry.file_name().to_string_lossy() == instance {
            continue;
        }
        let candidate = entry.path().join("hyperv.json");
        if !candidate.is_file() {
            continue;
        }
        let other = VmConfig::read(&candidate)?;
        if other.network_id == network_id {
            return Ok(true);
        }
    }
    Ok(false)
}

fn console_pipe(system_id: &str) -> String {
    format!(r"\\.\pipe\asterism-{system_id}-console")
}

fn guest_ip(identity_id: &str) -> Result<IpAddr> {
    let bytes = asterism_hyperv::parse_guid(identity_id)?;
    let host = (u16::from_be_bytes([bytes[14], bytes[15]]) % 4093) + 2;
    Ok(Ipv4Addr::new(172, 29, 64 + (host >> 8) as u8, host as u8).into())
}

fn network_config(address: IpAddr, mac: &str) -> String {
    format!(
        "version: 2\n\
         ethernets:\n\
         \x20 eth0:\n\
         \x20   match:\n\
         \x20     macaddress: \"{mac}\"\n\
         \x20   set-name: eth0\n\
         \x20   addresses:\n\
         \x20     - {address}/20\n\
         \x20   routes:\n\
         \x20     - to: default\n\
         \x20       via: 172.29.64.1\n\
         \x20   nameservers:\n\
         \x20     addresses:\n\
         \x20       - 1.1.1.1\n\
         \x20       - 8.8.8.8\n"
    )
}

fn instance_dir(disk: &Path) -> Result<&Path> {
    disk.parent()
        .with_context(|| format!("{} has no instance directory", disk.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hcn_addresses_are_stable_inside_the_private_prefix() {
        let address = guest_ip("83f8639b-3c23-4b07-b229-144314489fd0").unwrap();
        let IpAddr::V4(address) = address else {
            panic!("not v4")
        };
        assert_eq!(address.octets()[..2], [172, 29]);
        assert!((64..=79).contains(&address.octets()[2]));
        assert_ne!(address, Ipv4Addr::new(172, 29, 64, 1));
        let config = network_config(address.into(), "02:15:5d:01:02:03");
        assert!(config.contains("macaddress: \"02:15:5d:01:02:03\""));
        assert!(config.contains(&format!("- {address}/20")));
        assert!(config.contains("via: 172.29.64.1"));
    }

    /// What the kernel is started with. Every field the guest cannot discover
    /// for itself is here, because an OCI guest has no seed to put it in.
    #[test]
    fn the_oci_command_line_names_the_root_by_label_and_the_initrd_by_path() {
        let instance = oci_instance();
        let dir = tempfile::tempdir().unwrap();
        let cmdline = oci_cmdline(&boot_req(&instance, &dir)).unwrap();

        // A label is a fact about the filesystem `mke2fs -L asterism` built,
        // rather than about the order a controller enumerated its disks.
        assert!(cmdline.contains("root=LABEL=asterism"), "{cmdline}");
        // The initrd is a host file HCS loads, not a path in the guest.
        assert!(!cmdline.contains("initrd="), "{cmdline}");
        assert!(cmdline.contains("init=/asterism-init"), "{cmdline}");
        // Gen 2 gives the guest one COM port, and the HCS document wires it.
        assert!(cmdline.contains("console=ttyS0"), "{cmdline}");
        let address = guest_ip(&instance.id).unwrap();
        assert!(
            cmdline.contains(&format!("asterism.ip={address}/20")),
            "{cmdline}"
        );
        assert!(
            cmdline.contains(&format!("asterism.gw={GATEWAY}")),
            "{cmdline}"
        );
        assert!(cmdline.contains("asterism.time="), "{cmdline}");
    }

    /// A prepared OCI guest is started on its kernel; a cloud image is
    /// started on the firmware that reads the bootloader it already has.
    #[test]
    fn the_boot_source_follows_what_prepare_resolved() {
        let dir = tempfile::tempdir().unwrap();
        let root = DiskSpec::File {
            path: dir.path().join("disk.vhdx"),
            format: DiskFormat::Vhdx,
            readonly: false,
        };
        let cloud = Prepared {
            root: root.clone(),
            firmware: None,
            kernel: None,
        };
        assert_eq!(boot_source(&cloud).unwrap(), BootSource::Uefi);

        let oci = Prepared {
            root: root.clone(),
            firmware: None,
            kernel: Some(DirectKernel {
                kernel: dir.path().join("vmlinuz"),
                initrd: Some(dir.path().join("initrd")),
                cmdline: "root=LABEL=asterism".into(),
            }),
        };
        assert_eq!(
            boot_source(&oci).unwrap(),
            BootSource::LinuxKernel {
                kernel: dir.path().join("vmlinuz"),
                initrd: dir.path().join("initrd"),
                cmdline: "root=LABEL=asterism".into(),
            }
        );

        // A kernel with no initrd would boot to a kernel that cannot mount
        // its own root, so it is refused here rather than discovered there.
        let no_initrd = Prepared {
            root,
            firmware: None,
            kernel: Some(DirectKernel {
                kernel: dir.path().join("vmlinuz"),
                initrd: None,
                cmdline: String::new(),
            }),
        };
        assert!(boot_source(&no_initrd).is_err());
    }

    /// The door's host end is per-instance and never a path something else
    /// on this device could guess its way onto by knowing an instance name.
    #[test]
    fn the_door_record_lives_beside_the_vm_it_belongs_to() {
        let config = Path::new("C:/state/dev/hyperv.json");
        assert_eq!(
            door_record_path(config),
            Path::new("C:/state/dev/hyperv-egress.json")
        );
    }

    /// Everything this backend still cannot do says so in the same words it
    /// did before the OCI and door work, and says it before it mutates.
    #[test]
    fn the_refusals_that_remain_are_unchanged() {
        let caps = HyperV::new().caps();
        assert!(
            caps.shared_dir.is_none(),
            "no directory share transport yet"
        );
        assert!(!caps.nbd_disks, "no native NBD consumer yet");
        assert!(!caps.guest_gpu_projection, "no GPU projection yet");
        assert!(
            !caps.port_forward,
            "guests have their own address on the NAT"
        );
        assert!(caps.direct_kernel, "an OCI rootfs is handed its kernel");
    }

    fn oci_instance() -> Instance {
        let mut instance = Instance::new(
            "dev",
            "laptop",
            "nginx:alpine",
            asterism_core::instance::Shape::default(),
            asterism_core::hv::Machine {
                backend: ID.into(),
                machine_type: "hcs-v2.1-generation-2".into(),
                cpu: "host".into(),
                hv_version: "11.0.26100".into(),
            },
        );
        instance.image_kind = ImageKind::OciRootfs;
        instance
    }

    fn boot_req<'a>(instance: &'a Instance, dir: &tempfile::TempDir) -> BootReq<'a> {
        BootReq {
            instance,
            dir: dir.path().to_path_buf(),
            base: asterism_core::hv::ImageRef {
                name: "nginx:alpine".into(),
                path: dir.path().join("oci.raw"),
                format: DiskFormat::Raw,
                kind: ImageKind::OciRootfs,
            },
            seed: dir.path().join("seed.iso"),
            shares: Vec::new(),
            egress: Default::default(),
            bootstrap: Default::default(),
            extra_disks: Vec::new(),
            console: dir.path().join("console.log"),
        }
    }

    #[test]
    fn helper_control_is_a_durable_config_not_a_host_api() {
        let channel = ControlChannel::Helper {
            path: PathBuf::from("C:/state/dev/hyperv.json"),
        };
        assert_eq!(channel.path(), Path::new("C:/state/dev/hyperv.json"));
        assert_eq!(HyperV::new().caps().disk_formats, &[DiskFormat::Raw]);
    }
}
