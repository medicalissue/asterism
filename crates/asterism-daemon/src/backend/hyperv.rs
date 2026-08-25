//! Native Windows Hyper-V backend, expressed only in helper protocol terms.
//!
//! The daemon deliberately knows none of the APIs that implement this. It
//! selects capabilities, materialises disks, and sends versioned requests to
//! `astd-hyperv`. HCS/HCN/VirtDisk/Hyper-V Socket types stop at that process
//! boundary (ADR 0002).

use std::io::Write;
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::OnceLock;
use std::time::Duration;

use anyhow::{bail, Context, Result};

use asterism_core::guest;
use asterism_core::hv::{
    BootReq, Caps, ControlChannel, DiskFormat, DiskSpec, GuestEndpoint, Handle, Hypervisor,
    Prepared, Ready, RunState, SnapshotId,
};
use asterism_core::instance::Instance;
use asterism_core::paths;
use asterism_core::snapshot::{self, Snapshot};
use asterism_hyperv::{
    DiskAttachment, HostReady, Reply, Request, VmConfig, VmState, HELPER_BIN, OWNER,
    PROTOCOL_VERSION,
};

pub const ID: &str = "hyperv";
const NETWORK_ID: &str = "a57e1210-1e64-4a83-b48f-95dbe093e18a";

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
            console: console_pipe(&req.instance.id).into(),
            cpus: req.instance.shape.cpus,
            mem_mib: u64::from(req.instance.shape.mem_mib),
            network_id: NETWORK_ID.into(),
            guest_ip: guest_ip(&endpoint_id)?,
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
            direct_kernel: false,
            port_forward: false,
            guest_egress: None,
            disk_formats: &[DiskFormat::Raw],
            guest_gpu_projection: false,
        }
    }

    fn guest_config(&self, inst: &asterism_core::instance::Instance) -> Result<String> {
        let key = guest::Key::ensure(&paths::guest_agent_key_path(&inst.name))
            .with_context(|| format!("minting {:?}'s guest agent key", inst.name))?;
        Ok(guest::cloud_config(&key))
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
        Ok(Prepared {
            root: DiskSpec::File {
                path: destination,
                format: DiskFormat::Vhdx,
                readonly: false,
            },
            firmware: None,
            kernel: None,
        })
    }

    fn boot(&self, req: &BootReq, prep: &Prepared) -> Result<Handle> {
        if !req.seed.is_file() {
            bail!("no cloud-init seed at {}", req.seed.display());
        }
        let config = self.config(req, prep)?;
        let guest_addr = match self.request(&Request::Boot {
            config: Box::new(config.clone()),
        })? {
            Reply::Booted { guest_addr } => guest_addr,
            other => bail!("{HELPER_BIN} answered boot with {other:?}"),
        };
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

fn guest_ip(endpoint_id: &str) -> Result<IpAddr> {
    let bytes = asterism_hyperv::parse_guid(endpoint_id)?;
    let host = (u16::from_be_bytes([bytes[14], bytes[15]]) % 4093) + 2;
    Ok(Ipv4Addr::new(172, 29, 64 + (host >> 8) as u8, host as u8).into())
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
