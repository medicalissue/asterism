//! Native Linux/KVM backend powered by the pinned Cloud Hypervisor helper.
//!
//! Linux details stop in this file.  The rest of the daemon sees the same
//! [`Hypervisor`] contract, an HTTP control channel and capability data it
//! already uses for every other backend.

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::OnceLock;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};

use asterism_core::hv::{
    BootReq, Caps, ControlChannel, DirectKernel, DiskFormat, DiskSpec, GuestEndpoint, Handle,
    Hypervisor, ImageKind, MigrationSource, MigrationTarget, Prepared, Ready, RunState, ShareKind,
    SnapshotId,
};
use asterism_core::proc::{ProcId, Signal};
use asterism_core::snapshot::{self, Snapshot};
use asterism_core::{cow, image, oci, paths};
use asterism_vz::guest::{self, Key, Session};

use super::{grow, observed_running, owned};

pub const ID: &str = "chv";
pub const VERSION: &str = "v53.0";

const KVM: &str = "/dev/kvm";
const API_NAME: &str = "chv-api.sock";
const VSOCK_NAME: &str = "chv-vsock.sock";
const PID_NAME: &str = "chv.pid";
const LOG_NAME: &str = "chv.log";
const NBD_RECORD_PREFIX: &str = "chv-nbd-";
const NBD_RECORD_SUFFIX: &str = ".device";
const NBD_HELPER: &str = "/usr/local/libexec/asterism/asterism-nbd";
const BOOT_TIMEOUT: Duration = Duration::from_secs(240);
const API_TIMEOUT: Duration = Duration::from_secs(10);
const API_START_TIMEOUT: Duration = Duration::from_secs(60);
const LONG_API_TIMEOUT: Duration = Duration::from_secs(60 * 60);
const MAX_API_BODY: usize = 16 * 1024 * 1024;

#[derive(Default)]
pub struct Chv {
    probed: OnceLock<Probe>,
}

struct Probe {
    helper: PathBuf,
    virtiofsd: Option<PathBuf>,
}

impl Chv {
    pub fn new() -> Self {
        Self::default()
    }

    fn probed(&self) -> Result<&Probe> {
        if let Some(probe) = self.probed.get() {
            return Ok(probe);
        }
        let probe = Probe::run()?;
        Ok(self.probed.get_or_init(|| probe))
    }

    fn create_root(&self, req: &BootReq, path: &Path) -> Result<DiskSpec> {
        if !req.base.path.exists() {
            bail!(
                "image {} is not pulled yet — run: ast pull {}",
                req.base.name,
                req.base.name
            );
        }
        cow::clone_file(&req.base.path, path)
            .with_context(|| format!("making {}'s Cloud Hypervisor disk", req.instance.name))?;
        if req.base.format == DiskFormat::Raw {
            if let Err(error) = grow(path, u64::from(req.instance.shape.disk_gib)) {
                let _ = std::fs::remove_file(path);
                return Err(error);
            }
        }
        Ok(DiskSpec::File {
            path: path.to_owned(),
            format: req.base.format,
            readonly: false,
        })
    }

    fn spawn(&self, req: &BootReq, prep: &Prepared, restore: Option<&Path>) -> Result<Handle> {
        let probe = self.probed()?;
        std::fs::create_dir_all(&req.dir)?;
        let mut cleanup = SpawnCleanup::new(&req.dir);
        let api = req.dir.join(API_NAME);
        let vsock = req.dir.join(VSOCK_NAME);
        let pidfile = req.dir.join(PID_NAME);
        for stale in [&api, &vsock, &pidfile] {
            let _ = std::fs::remove_file(stale);
        }

        // Cloud Hypervisor deliberately consumes ordinary host files and
        // block devices rather than speaking NBD itself.  The volume plane
        // always presents remote volumes as authenticated Unix-NBD sockets;
        // materialising those below this backend seam keeps that transport
        // out of the rest of the product.
        let extra_disks = if restore.is_none() {
            materialize_remote_disks(&req.extra_disks, &req.dir)?
        } else {
            Vec::new()
        };

        let mut fs_helpers = Vec::new();
        if restore.is_none() {
            for (index, share) in req.shares.iter().enumerate() {
                let virtiofsd = probe.virtiofsd.as_ref().with_context(|| {
                    "this instance has a shared directory, but the pinned virtiofsd helper is missing"
                })?;
                if !Path::new(&share.host_path).is_dir() {
                    bail!(
                        "volume {} is not a directory on this device",
                        share.host_path
                    );
                }
                let socket = req.dir.join(format!("virtiofs-{index}.sock"));
                let record = req.dir.join(format!("virtiofs-{index}.proc.json"));
                let _ = std::fs::remove_file(&socket);
                let log = std::fs::File::create(req.dir.join(format!("virtiofs-{index}.log")))?;
                let mut child = Command::new(virtiofsd)
                    .arg(format!("--socket-path={}", socket.display()))
                    .arg(format!("--shared-dir={}", share.host_path))
                    .arg("--cache=never")
                    .stdin(Stdio::null())
                    .stdout(Stdio::from(log.try_clone()?))
                    .stderr(Stdio::from(log))
                    .spawn()
                    .with_context(|| format!("starting {}", virtiofsd.display()))?;
                let proc = record_helper(&mut child, &record)?;
                reap(child);
                wait_for_path(&socket, &proc, Duration::from_secs(10))?;
                fs_helpers.push((share.tag.clone(), socket));
            }
        }

        let log = std::fs::File::create(req.dir.join(LOG_NAME))?;
        let mut command = Command::new(&probe.helper);
        command
            .arg("--api-socket")
            .arg(&api)
            .stdin(Stdio::null())
            .stdout(Stdio::from(log.try_clone()?))
            .stderr(Stdio::from(log));

        if let Some(snapshot) = restore {
            command.arg("--restore").arg(format!(
                "source_url=file://{},resume=true",
                snapshot.display()
            ));
        } else {
            command
                .arg("--cpus")
                .arg(format!(
                    "boot={},max={}",
                    req.instance.shape.cpus,
                    req.instance.shape.cpus.max(4)
                ))
                .arg("--memory")
                .arg(format!("size={}M,shared=on", req.instance.shape.mem_mib));

            let direct = prep.kernel.as_ref().context(
                "the chv backend direct-boots every image, but prepare produced no kernel",
            )?;
            command.arg("--kernel").arg(&direct.kernel);
            if let Some(initrd) = &direct.initrd {
                command.arg("--initramfs").arg(initrd);
            }
            command.arg("--cmdline").arg(&direct.cmdline);

            command.arg("--disk").arg(disk_arg(&prep.root, "root")?);
            if req.base.kind == ImageKind::Disk {
                command.arg("--disk").arg(format!(
                    "path={},readonly=on,image_type=raw,id=seed",
                    req.seed.display()
                ));
            }
            for (index, disk) in extra_disks.iter().enumerate() {
                command
                    .arg("--disk")
                    .arg(disk_arg(disk, &format!("astvol{index}"))?);
            }
            for (tag, socket) in fs_helpers {
                command
                    .arg("--fs")
                    .arg(format!("tag={tag},socket={}", socket.display()));
            }

            let net = Network::for_instance(&req.instance.name);
            command
                .arg("--net")
                .arg(net.arg())
                .arg("--vsock")
                .arg(format!("cid={},socket={}", net.cid, vsock.display()))
                .arg("--serial")
                .arg(format!("file={}", req.console.display()))
                .arg("--console")
                .arg("off");
        }

        let mut child = command
            .spawn()
            .with_context(|| format!("starting {}", probe.helper.display()))?;
        let proc = match ProcId::capture(child.id()) {
            Ok(proc) => proc,
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(error).context("cloud-hypervisor exited during startup");
            }
        };
        cleanup.vmm = Some(proc.clone());
        std::fs::write(&pidfile, format!("{}\n", proc.pid))?;
        reap(child);
        if let Err(error) = wait_for_api(&api, &proc, API_START_TIMEOUT) {
            return Err(error).context("waiting for the Cloud Hypervisor API");
        }

        let endpoint = if req.base.kind == ImageKind::Disk {
            wait_for_guest(&vsock, &req.dir, req.instance, &proc, BOOT_TIMEOUT)?
        } else {
            // OCI instances run their image entrypoint as pid 1 and do not
            // carry cloud-init or sshd.  Their deterministic address is still
            // recorded for status and future service routing.
            GuestEndpoint::GuestAddr {
                addr: Network::for_instance(&req.instance.name).guest.parse()?,
            }
        };
        let handle = Handle::owning(ID, proc, ControlChannel::HttpApi { path: api }, endpoint);
        cleanup.disarm();
        Ok(handle)
    }
}

impl Probe {
    fn run() -> Result<Self> {
        if !cfg!(target_os = "linux") {
            bail!("the chv backend is Linux-only — this device uses its native host backend");
        }
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(KVM)
            .with_context(|| format!("opening {KVM} read-write for the KVM substrate"))?;
        let helper = sibling_or_path("ASTERISM_CLOUD_HYPERVISOR", "cloud-hypervisor")?;
        let version = command_output(Command::new(&helper).arg("--version"))?;
        if !version.split_whitespace().any(|word| word == VERSION) {
            bail!(
                "{} is {}, but this build requires the pinned Cloud Hypervisor {} helper",
                helper.display(),
                version.trim(),
                VERSION
            );
        }
        let virtiofsd = sibling_or_path("ASTERISM_VIRTIOFSD", "virtiofsd").ok();
        Ok(Self { helper, virtiofsd })
    }

    fn ready(&self) -> Ready {
        Ready {
            version: VERSION.trim_start_matches('v').to_owned(),
            accel: "kvm".to_owned(),
            machine_type: "cloud-hypervisor".to_owned(),
            cpu: "host".to_owned(),
        }
    }
}

impl Hypervisor for Chv {
    fn id(&self) -> &'static str {
        ID
    }

    fn probe(&self) -> Result<Ready> {
        Ok(self.probed()?.ready())
    }

    fn caps(&self) -> Caps {
        Caps {
            live_snapshot: true,
            disk_snapshot: true,
            live_migration: true,
            disk_hotplug: true,
            shared_dir: self
                .probed()
                .ok()
                .and_then(|probe| probe.virtiofsd.as_ref())
                .map(|_| ShareKind::Virtiofs),
            // CHV consumes local files and block devices.  Remote NBD is
            // intentionally converted to DiskSpec::Block by the Linux volume
            // attachment lane; raw NBD URLs must not leak into this VMM.
            // The common volume plane emits Unix-NBD.  CHV materialises it
            // as a local /dev/nbd device before passing it to the VMM.
            nbd_disks: true,
            foreign_arch: false,
            direct_kernel: true,
            port_forward: false,
            guest_egress: None,
            disk_formats: &[DiskFormat::Raw, DiskFormat::Qcow2],
        }
    }

    fn guest_config(&self, inst: &asterism_core::instance::Instance) -> Result<String> {
        let key = Key::ensure(&paths::guest_agent_key_path(&inst.name))?;
        Ok(guest::cloud_config(&key))
    }

    fn guest_network_config(
        &self,
        inst: &asterism_core::instance::Instance,
    ) -> Result<Option<String>> {
        Ok(Some(network_config(&Network::for_instance(&inst.name))))
    }

    fn prepare(&self, req: &BootReq) -> Result<Prepared> {
        self.probed()?;
        std::fs::create_dir_all(&req.dir)?;
        let raw = req.dir.join("disk.raw");
        let qcow = req.dir.join("disk.qcow2");
        let root = if raw.exists() {
            DiskSpec::File {
                path: raw,
                format: DiskFormat::Raw,
                readonly: false,
            }
        } else if qcow.exists() {
            DiskSpec::File {
                path: qcow,
                format: DiskFormat::Qcow2,
                readonly: false,
            }
        } else {
            let path = match req.base.format {
                DiskFormat::Raw => raw,
                DiskFormat::Qcow2 => qcow,
                DiskFormat::Asif => bail!("the chv backend cannot read an asif disk"),
            };
            self.create_root(req, &path)?
        };
        let (kernel, initrd) = oci::kernel()?;
        let kernel = direct_kernel_payload(&kernel)?;
        let net = Network::for_instance(&req.instance.name);
        let root_device = if req.base.kind == ImageKind::OciRootfs {
            "/dev/vda"
        } else {
            "/dev/vda1"
        };
        let init = if req.base.kind == ImageKind::OciRootfs {
            format!(" init={}", oci::INIT_PATH)
        } else {
            " systemd.mask=systemd-networkd-wait-online.service".to_owned()
        };
        let console = if image::host_arch() == "aarch64" {
            "ttyAMA0"
        } else {
            "ttyS0"
        };
        Ok(Prepared {
            root,
            firmware: None,
            kernel: Some(DirectKernel {
                kernel,
                initrd: Some(initrd),
                cmdline: format!(
                    "root={root_device} rw console={console} net.ifnames=0 panic=10{init} \
                     asterism.ip={}/24 asterism.gw={} asterism.dns={} asterism.time={}",
                    net.guest,
                    net.host,
                    net.host,
                    asterism_core::instance::now_unix()
                ),
            }),
        })
    }

    fn boot(&self, req: &BootReq, prep: &Prepared) -> Result<Handle> {
        self.spawn(req, prep, None)
    }

    fn stop(&self, handle: &Handle, deadline: Duration) -> Result<()> {
        let graceful = deadline.mul_f32(0.75);
        let Some(proc) = owned(handle) else {
            return Ok(());
        };
        let _ = guest_session(
            &vsock_from_api(handle.ctl.path()),
            handle,
            Duration::from_secs(3),
        )
        .and_then(|mut session| session.stop());
        let _ = api(handle.ctl.path(), "PUT", "/vm.power-button", None);
        if proc.wait_gone(graceful) {
            cleanup_fs_helpers(instance_dir_from_api(handle.ctl.path()));
            cleanup_remote_blocks(instance_dir_from_api(handle.ctl.path()));
            return Ok(());
        }
        let _ = api(handle.ctl.path(), "PUT", "/vmm.shutdown", None);
        if proc.wait_gone(deadline.saturating_sub(graceful)) {
            cleanup_fs_helpers(instance_dir_from_api(handle.ctl.path()));
            cleanup_remote_blocks(instance_dir_from_api(handle.ctl.path()));
            return Ok(());
        }
        proc.signal(Signal::Kill)?;
        cleanup_fs_helpers(instance_dir_from_api(handle.ctl.path()));
        cleanup_remote_blocks(instance_dir_from_api(handle.ctl.path()));
        Ok(())
    }

    fn kill(&self, handle: &Handle) -> Result<()> {
        let _ = api(handle.ctl.path(), "PUT", "/vmm.shutdown", None);
        if let Some(proc) = owned(handle) {
            if !proc.wait_gone(Duration::from_secs(2)) {
                proc.signal(Signal::Kill)?;
            }
        }
        cleanup_fs_helpers(instance_dir_from_api(handle.ctl.path()));
        cleanup_remote_blocks(instance_dir_from_api(handle.ctl.path()));
        Ok(())
    }

    fn state(&self, handle: &Handle) -> Result<RunState> {
        let state = if observed_running(handle)
            && api(handle.ctl.path(), "GET", "/vmm.ping", None).is_ok()
        {
            RunState::Running
        } else {
            RunState::Stopped
        };
        if state == RunState::Stopped {
            let dir = instance_dir_from_api(handle.ctl.path());
            cleanup_fs_helpers(dir);
            cleanup_remote_blocks(dir);
        }
        Ok(state)
    }

    fn snapshot(&self, handle: &Handle, tag: &str) -> Result<SnapshotId> {
        snapshot::validate_tag(tag)?;
        let dir = instance_dir_from_api(handle.ctl.path())
            .join("live-snapshots")
            .join(tag);
        if dir.exists() {
            bail!("snapshot {tag:?} already exists");
        }
        std::fs::create_dir_all(&dir)?;
        if let Ok(mut session) = guest_session(
            &vsock_from_api(handle.ctl.path()),
            handle,
            Duration::from_secs(3),
        ) {
            session.sync()?;
        }
        api(handle.ctl.path(), "PUT", "/vm.pause", None)?;
        let result = api_with_timeout(
            handle.ctl.path(),
            "PUT",
            "/vm.snapshot",
            Some(&serde_json::json!({"destination_url": format!("file://{}", dir.display())})),
            BOOT_TIMEOUT,
        );
        if result.is_err() {
            let _ = api(handle.ctl.path(), "PUT", "/vm.resume", None);
            let _ = std::fs::remove_dir_all(&dir);
        }
        result?;
        api(handle.ctl.path(), "PUT", "/vm.resume", None)?;
        Ok(SnapshotId(tag.to_owned()))
    }

    fn restore(&self, req: &BootReq, snap: &SnapshotId) -> Result<Handle> {
        snapshot::validate_tag(&snap.0)?;
        let dir = req.dir.join("live-snapshots").join(&snap.0);
        if !dir.join("state.json").exists() {
            bail!("no live snapshot {:?}", snap.0);
        }
        let prep = Prepared {
            root: DiskSpec::File {
                path: req.dir.join("disk.raw"),
                format: DiskFormat::Raw,
                readonly: false,
            },
            firmware: None,
            kernel: None,
        };
        self.spawn(req, &prep, Some(&dir))
    }

    fn disk_snapshot(&self, prep: &Prepared, tag: &str) -> Result<SnapshotId> {
        let disk = prep.root_path()?;
        snapshot::take(parent(disk)?, disk, tag)
    }

    fn disk_snapshot_list(&self, prep: &Prepared) -> Result<Vec<Snapshot>> {
        snapshot::list(parent(prep.root_path()?)?)
    }

    fn disk_restore(&self, prep: &Prepared, snap: &SnapshotId) -> Result<()> {
        let disk = prep.root_path()?;
        snapshot::restore(parent(disk)?, disk, &snap.0)
    }

    fn disk_snapshot_remove(&self, prep: &Prepared, snap: &SnapshotId) -> Result<()> {
        snapshot::remove(parent(prep.root_path()?)?, &snap.0)
    }

    fn attach_disk(&self, handle: &Handle, disk: &DiskSpec) -> Result<()> {
        let body = disk_json(disk, "hot")?;
        api(handle.ctl.path(), "PUT", "/vm.add-disk", Some(&body)).map(|_| ())
    }

    fn migrate_out(&self, handle: &Handle, target: MigrationTarget) -> Result<()> {
        let local = target.url.starts_with("unix:");
        api_with_timeout(
            handle.ctl.path(),
            "PUT",
            "/vm.send-migration",
            Some(&serde_json::json!({
                "destination_url": target.url,
                "local": local,
            })),
            LONG_API_TIMEOUT,
        )
        .map(|_| ())
    }

    fn migrate_in(&self, req: &BootReq, source: MigrationSource) -> Result<Handle> {
        let probe = self.probed()?;
        std::fs::create_dir_all(&req.dir)?;
        let api_path = req.dir.join(API_NAME);
        let vsock = req.dir.join(VSOCK_NAME);
        let pidfile = req.dir.join(PID_NAME);
        for stale in [&api_path, &vsock, &pidfile] {
            let _ = std::fs::remove_file(stale);
        }

        let log = std::fs::File::create(req.dir.join(LOG_NAME))?;
        let child = Command::new(&probe.helper)
            .arg("--api-socket")
            .arg(&api_path)
            .stdin(Stdio::null())
            .stdout(Stdio::from(log.try_clone()?))
            .stderr(Stdio::from(log))
            .spawn()
            .with_context(|| {
                format!(
                    "starting {} as a migration receiver",
                    probe.helper.display()
                )
            })?;
        let proc = ProcId::capture(child.id())
            .context("cloud-hypervisor migration receiver exited during startup")?;
        std::fs::write(&pidfile, format!("{}\n", proc.pid))?;
        reap(child);

        let receive = wait_for_api(&api_path, &proc, API_START_TIMEOUT).and_then(|()| {
            api_with_timeout(
                &api_path,
                "PUT",
                "/vm.receive-migration",
                Some(&serde_json::json!({"receiver_url": source.url})),
                LONG_API_TIMEOUT,
            )
            .map(|_| ())
        });
        if let Err(error) = receive {
            let _ = proc.signal(Signal::Kill);
            return Err(error).context("receiving a Cloud Hypervisor migration");
        }

        Ok(Handle::owning(
            ID,
            proc,
            ControlChannel::HttpApi { path: api_path },
            GuestEndpoint::GuestAddr {
                addr: Network::for_instance(&req.instance.name).guest.parse()?,
            },
        ))
    }
}

fn parent(path: &Path) -> Result<&Path> {
    path.parent()
        .with_context(|| format!("{} has no instance directory", path.display()))
}

fn disk_arg(disk: &DiskSpec, id: &str) -> Result<String> {
    let (path, format, readonly) = match disk {
        DiskSpec::File {
            path,
            format,
            readonly,
        } => (path, *format, *readonly),
        DiskSpec::Block { path, readonly } => (path, DiskFormat::Raw, *readonly),
        DiskSpec::Nbd { .. } | DiskSpec::NbdUnix { .. } => {
            bail!("the chv backend accepts remote volumes only after they are exposed as a host block device")
        }
    };
    if format == DiskFormat::Asif {
        bail!("Cloud Hypervisor cannot read an asif disk");
    }
    Ok(format!(
        "path={},readonly={},image_type={},id={id}",
        path.display(),
        if readonly { "on" } else { "off" },
        format.as_str()
    ))
}

fn disk_json(disk: &DiskSpec, id: &str) -> Result<serde_json::Value> {
    let (path, format, readonly) = match disk {
        DiskSpec::File {
            path,
            format,
            readonly,
        } => (path, *format, *readonly),
        DiskSpec::Block { path, readonly } => (path, DiskFormat::Raw, *readonly),
        _ => bail!("Cloud Hypervisor hotplug needs a local file or block device"),
    };
    Ok(serde_json::json!({
        "path": path,
        "readonly": readonly,
        "image_type": api_image_type(format)?,
        "id": id,
    }))
}

fn api_image_type(format: DiskFormat) -> Result<&'static str> {
    match format {
        DiskFormat::Raw => Ok("Raw"),
        DiskFormat::Qcow2 => Ok("Qcow2"),
        DiskFormat::Asif => bail!("Cloud Hypervisor cannot read an asif disk"),
    }
}

/// Cloud Hypervisor's aarch64 loader needs the raw Linux `Image`, while the
/// immutable Ubuntu artifact shared with the other backends is a compressed
/// `vmlinuz`.  Derive the raw payload beside the verified input once, then
/// reuse it until the input is replaced. x86_64's loader consumes its bzImage
/// directly and must not be decompressed.
fn direct_kernel_payload(kernel: &Path) -> Result<PathBuf> {
    if image::host_arch() != "aarch64" {
        return Ok(kernel.to_owned());
    }

    let image = kernel.with_extension("chv-Image");
    let source_mtime = std::fs::metadata(kernel)?.modified()?;
    if std::fs::metadata(&image)
        .and_then(|metadata| metadata.modified().map(|mtime| (metadata.len(), mtime)))
        .is_ok_and(|(len, mtime)| len > 0 && mtime >= source_mtime)
    {
        return Ok(image);
    }

    static DERIVATION: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let derivation = DERIVATION.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let staging = image.with_extension(format!(
        "chv-Image.{}.{derivation}.part",
        std::process::id()
    ));
    let output = std::fs::File::create(&staging)
        .with_context(|| format!("creating derived guest kernel at {}", staging.display()))?;
    let status = Command::new("gzip")
        .args(["-dc"])
        .arg(kernel)
        .stdout(Stdio::from(output))
        .status()
        .context("decompressing the aarch64 guest kernel with gzip")?;
    if !status.success() {
        let _ = std::fs::remove_file(&staging);
        bail!("gzip could not decompress {}", kernel.display());
    }
    std::fs::rename(&staging, &image).with_context(|| {
        format!(
            "publishing the derived aarch64 guest kernel at {}",
            image.display()
        )
    })?;
    Ok(image)
}

struct Network {
    host: String,
    guest: String,
    mac: String,
    cid: u32,
}

impl Network {
    fn for_instance(name: &str) -> Self {
        let hash = blake3::hash(name.as_bytes());
        let bytes = hash.as_bytes();
        let second = 64 + bytes[0] % 64;
        let third = bytes[1];
        Self {
            host: format!("10.{second}.{third}.1"),
            guest: format!("10.{second}.{third}.2"),
            mac: format!(
                "02:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                bytes[2], bytes[3], bytes[4], bytes[5], bytes[6]
            ),
            cid: 3 + u32::from_le_bytes([bytes[7], bytes[8], bytes[9], bytes[10]]) % (u32::MAX - 3),
        }
    }

    fn arg(&self) -> String {
        format!("tap=,mac={},ip={},mask=255.255.255.0", self.mac, self.host)
    }
}

/// Cloud Hypervisor creates the TAP and gives its host side a deterministic
/// address, but deliberately does not run a DHCP server. Stock cloud images
/// therefore receive a NoCloud network-config document, which cloud-init
/// applies before its Network Stage and before the guest agent starts.
fn network_config(net: &Network) -> String {
    format!(
        "version: 2\n\
         ethernets:\n\
         \x20 eth0:\n\
         \x20   match:\n\
         \x20     macaddress: \"{}\"\n\
         \x20   set-name: eth0\n\
         \x20   addresses:\n\
         \x20     - {}/24\n\
         \x20   routes:\n\
         \x20     - to: default\n\
         \x20       via: {}\n\
         \x20   nameservers:\n\
         \x20     addresses:\n\
         \x20       - {}\n",
        net.mac, net.guest, net.host, net.host
    )
}

fn sibling_or_path(env: &str, name: &str) -> Result<PathBuf> {
    if let Some(path) = std::env::var_os(env) {
        let path = PathBuf::from(path);
        if path.is_file() {
            return Ok(path);
        }
        bail!("{env} names {}, which is not a file", path.display());
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let sibling = dir.join(name);
            if sibling.is_file() {
                return Ok(sibling);
            }
        }
    }
    asterism_core::tools::tool(name).with_context(|| format!("finding the pinned {name} helper"))
}

fn command_output(command: &mut Command) -> Result<String> {
    let output = command.output()?;
    if !output.status.success() {
        bail!(
            "command failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

fn wait_for_path(path: &Path, proc: &ProcId, timeout: Duration) -> Result<()> {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if path.exists() {
            return Ok(());
        }
        if !proc.alive() {
            bail!("helper exited before creating {}", path.display());
        }
        thread::sleep(Duration::from_millis(25));
    }
    bail!(
        "helper did not create {} within {timeout:?}",
        path.display()
    )
}

fn wait_for_api(path: &Path, proc: &ProcId, timeout: Duration) -> Result<()> {
    let start = Instant::now();
    loop {
        if api(path, "GET", "/vmm.ping", None).is_ok() {
            return Ok(());
        }
        if !proc.alive() {
            bail!("cloud-hypervisor exited before its API answered");
        }
        if start.elapsed() >= timeout {
            bail!("Cloud Hypervisor API at {} did not answer", path.display());
        }
        thread::sleep(Duration::from_millis(25));
    }
}

fn api(
    socket: &Path,
    method: &str,
    endpoint: &str,
    body: Option<&serde_json::Value>,
) -> Result<Vec<u8>> {
    api_with_timeout(socket, method, endpoint, body, API_TIMEOUT)
}

fn api_with_timeout(
    socket: &Path,
    method: &str,
    endpoint: &str,
    body: Option<&serde_json::Value>,
    timeout: Duration,
) -> Result<Vec<u8>> {
    let mut stream = UnixStream::connect(socket)
        .with_context(|| format!("connecting to Cloud Hypervisor API at {}", socket.display()))?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    let payload = body
        .map(serde_json::to_vec)
        .transpose()?
        .unwrap_or_default();
    write!(
        stream,
        "{method} /api/v1{endpoint} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        payload.len()
    )?;
    stream.write_all(&payload)?;
    stream.flush()?;
    let mut reader = BufReader::new(stream);
    let mut status_line = String::new();
    if reader.read_line(&mut status_line)? == 0 {
        bail!("Cloud Hypervisor API returned no status line");
    }
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|value| value.parse::<u16>().ok())
        .context("Cloud Hypervisor API returned an invalid status line")?;
    let mut content_length = 0usize;
    let mut header_bytes = status_line.len();
    loop {
        let mut line = String::new();
        let read = reader.read_line(&mut line)?;
        if read == 0 || line == "\r\n" || line == "\n" {
            break;
        }
        header_bytes += read;
        if header_bytes > 64 * 1024 {
            bail!("Cloud Hypervisor API returned headers larger than 64 KiB");
        }
        if let Some((name, value)) = line.split_once(':') {
            if name.eq_ignore_ascii_case("content-length") {
                content_length = value
                    .trim()
                    .parse()
                    .context("Cloud Hypervisor API returned an invalid Content-Length")?;
            }
        }
    }
    if content_length > MAX_API_BODY {
        bail!("Cloud Hypervisor API returned a body larger than 16 MiB");
    }
    let mut response = vec![0; content_length];
    reader.read_exact(&mut response)?;
    if !(200..300).contains(&status) {
        bail!(
            "Cloud Hypervisor {method} {endpoint} returned HTTP {status}: {}",
            String::from_utf8_lossy(&response).trim()
        );
    }
    Ok(response)
}

fn wait_for_guest(
    vsock: &Path,
    instance_dir: &Path,
    instance: &asterism_core::instance::Instance,
    proc: &ProcId,
    timeout: Duration,
) -> Result<GuestEndpoint> {
    let start = Instant::now();
    let handle = Handle {
        backend: ID.to_owned(),
        pid: Some(proc.pid),
        proc: Some(proc.clone()),
        ctl: ControlChannel::HttpApi {
            path: instance_dir.join(API_NAME),
        },
        endpoint: GuestEndpoint::GuestAddr {
            addr: "192.0.2.1".parse().unwrap(),
        },
        started_at: 0,
    };
    loop {
        if !proc.alive() {
            bail!(
                "cloud-hypervisor exited before {:?}'s guest became ready",
                instance.name
            );
        }
        if let Ok(mut session) = guest_session(vsock, &handle, Duration::from_secs(3)) {
            if let Ok(status) = session.ready_within(Duration::from_secs(5)) {
                if let Some(addr) = status.endpoint() {
                    return Ok(GuestEndpoint::GuestAddr { addr });
                }
            }
        }
        if start.elapsed() >= timeout {
            bail!(
                "guest {:?} did not answer on vsock port {} with a reachable ssh address within {timeout:?}",
                instance.name,
                guest::PORT
            );
        }
        thread::sleep(Duration::from_millis(100));
    }
}

fn guest_session(
    vsock: &Path,
    handle: &Handle,
    timeout: Duration,
) -> Result<Session<BufReader<UnixStream>, UnixStream>> {
    let mut stream = UnixStream::connect(vsock)
        .with_context(|| format!("connecting to guest vsock at {}", vsock.display()))?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    writeln!(stream, "CONNECT {}", guest::PORT)?;
    stream.flush()?;
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut answer = String::new();
    reader.read_line(&mut answer)?;
    if !answer.starts_with("OK ") {
        bail!(
            "Cloud Hypervisor refused guest vsock port {}: {}",
            guest::PORT,
            answer.trim()
        );
    }
    let instance_dir = instance_dir_from_api(handle.ctl.path());
    let key = Key::read(&instance_dir.join("agent.key"))?
        .context("this Cloud Hypervisor guest has no agent key")?;
    Session::open(reader, stream, &key)
}

fn vsock_from_api(api: &Path) -> PathBuf {
    instance_dir_from_api(api).join(VSOCK_NAME)
}

fn instance_dir_from_api(api: &Path) -> &Path {
    api.parent().unwrap_or_else(|| Path::new("."))
}

/// Resources started while assembling one VMM command.  A `BootReq` has no
/// owner until [`spawn`](Chv::spawn) returns its handle, so every fallible
/// pre-VMM step must be rolled back here rather than hoping a later stop path
/// will run.
struct SpawnCleanup<'a> {
    dir: &'a Path,
    vmm: Option<ProcId>,
    armed: bool,
}

impl<'a> SpawnCleanup<'a> {
    fn new(dir: &'a Path) -> Self {
        Self {
            dir,
            vmm: None,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for SpawnCleanup<'_> {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        if let Some(proc) = &self.vmm {
            stop_with_fallback(proc);
        }
        cleanup_fs_helpers(self.dir);
        cleanup_remote_blocks(self.dir);
    }
}

fn stop_with_fallback(proc: &ProcId) {
    if !proc.alive() {
        return;
    }
    let _ = proc.signal(Signal::Term);
    if !proc.wait_gone(Duration::from_secs(2)) {
        let _ = proc.signal(Signal::Kill);
        let _ = proc.wait_gone(Duration::from_secs(2));
    }
}

/// Persist a just-started helper before handing it to the background reaper.
///
/// [`SpawnCleanup`] retires helpers from their durable record.  That record
/// therefore has to be an all-or-nothing hand-off: if either capturing process
/// identity or writing the record fails, this function still owns `child` and
/// synchronously retires it.  In particular, a full/read-only instance
/// directory must not turn into an untracked virtiofsd on a failed boot.
fn record_helper(child: &mut Child, record: &Path) -> Result<ProcId> {
    let proc = match ProcId::capture(child.id()) {
        Ok(proc) => proc,
        Err(error) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(error).context("virtiofsd exited during startup");
        }
    };
    if let Err(error) = (|| -> Result<()> {
        std::fs::write(record, serde_json::to_vec(&proc)?)?;
        Ok(())
    })() {
        stop_with_fallback(&proc);
        let _ = child.wait();
        return Err(error).with_context(|| format!("recording {}", record.display()));
    }
    Ok(proc)
}

#[derive(serde::Serialize, serde::Deserialize)]
struct NbdRecord {
    device: PathBuf,
    /// `/sys/block/nbdN/pid` after attach.  Cleanup only detaches when this
    /// still matches, so a reused device can never be disconnected by an old
    /// instance record.
    kernel_pid: String,
}

fn materialize_remote_disks(disks: &[DiskSpec], dir: &Path) -> Result<Vec<DiskSpec>> {
    disks
        .iter()
        .enumerate()
        .map(|(index, disk)| materialize_remote_disk(disk, dir, index))
        .collect()
}

fn materialize_remote_disk(disk: &DiskSpec, dir: &Path, index: usize) -> Result<DiskSpec> {
    match disk {
        DiskSpec::NbdUnix {
            socket,
            export,
            readonly,
        } => {
            let device = attach_nbd(dir, index, *readonly, |device| {
                Ok(nbd_unix_args(socket, export, device))
            })?;
            Ok(DiskSpec::Block {
                path: device,
                readonly: *readonly,
            })
        }
        // User-supplied NBD URLs remain supported as a host block device.
        // The volume plane itself always takes the Unix route above.
        DiskSpec::Nbd { url, readonly } => {
            let device = attach_nbd(dir, index, *readonly, |device| nbd_url_args(url, device))?;
            Ok(DiskSpec::Block {
                path: device,
                readonly: *readonly,
            })
        }
        other => Ok(other.clone()),
    }
}

fn attach_nbd(
    dir: &Path,
    index: usize,
    readonly: bool,
    args_for: impl FnOnce(&Path) -> Result<Vec<String>>,
) -> Result<PathBuf> {
    let device = free_nbd_device()?;
    let mut args = args_for(&device)?;
    if readonly {
        args.push("-readonly".to_owned());
    }
    run_nbd_client(&args).with_context(|| {
        format!(
            "attaching the remote volume as {}; Cloud Hypervisor consumes host block devices",
            device.display()
        )
    })?;

    let Some(kernel_pid) = nbd_kernel_pid(&device) else {
        let _ = detach_nbd(&device);
        bail!(
            "nbd-client reported success for {}, but the host did not expose an attached NBD pid",
            device.display()
        );
    };
    let record = NbdRecord {
        device: device.clone(),
        kernel_pid,
    };
    let record_path = nbd_record_path(dir, index);
    if let Err(error) = std::fs::write(&record_path, serde_json::to_vec(&record)?) {
        let _ = detach_nbd(&device);
        return Err(error).with_context(|| format!("recording {}", record_path.display()));
    }
    Ok(device)
}

fn nbd_unix_args(socket: &Path, export: &str, device: &Path) -> Vec<String> {
    vec![
        "-unix".to_owned(),
        socket.display().to_string(),
        device.display().to_string(),
        "-N".to_owned(),
        export.to_owned(),
    ]
}

fn nbd_url_args(url: &str, device: &Path) -> Result<Vec<String>> {
    let rest = url
        .strip_prefix("nbd://")
        .context("an NBD URL must start with nbd://")?;
    let (host_port, export) = rest
        .split_once('/')
        .context("an NBD URL needs a host and export name")?;
    let (host, port) = host_port.split_once(':').unwrap_or((host_port, "10809"));
    if host.is_empty() || export.is_empty() {
        bail!("an NBD URL needs a non-empty host and export name");
    }
    Ok(vec![
        host.to_owned(),
        port.to_owned(),
        device.display().to_string(),
        "-N".to_owned(),
        export.to_owned(),
    ])
}

fn free_nbd_device() -> Result<PathBuf> {
    for index in 0..64 {
        let device = PathBuf::from(format!("/dev/nbd{index}"));
        if device.exists() && nbd_kernel_pid(&device).is_none() {
            return Ok(device);
        }
    }
    bail!("no unused /dev/nbd device is available for a remote block volume")
}

fn nbd_kernel_pid(device: &Path) -> Option<String> {
    let name = device.file_name()?.to_str()?;
    let pid = std::fs::read_to_string(format!("/sys/block/{name}/pid")).ok()?;
    let pid = pid.trim();
    (!pid.is_empty() && pid != "0").then(|| pid.to_owned())
}

fn nbd_record_path(dir: &Path, index: usize) -> PathBuf {
    dir.join(format!("{NBD_RECORD_PREFIX}{index}{NBD_RECORD_SUFFIX}"))
}

fn run_nbd_client(args: &[String]) -> Result<()> {
    let helper = std::env::var_os("ASTERISM_NBD_HELPER")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(NBD_HELPER));
    if !helper.is_file() {
        bail!(
            "remote block volumes need the installed Asterism NBD helper at {}; re-run the Linux installer",
            helper.display()
        );
    }
    let status = Command::new("sudo")
        .arg("-n")
        .arg(&helper)
        .args(args)
        .status()
        .with_context(|| format!("starting privileged NBD helper {}", helper.display()))?;
    if !status.success() {
        bail!(
            "the Asterism NBD helper failed; re-run the Linux installer to repair its non-interactive least-privilege policy"
        );
    }
    Ok(())
}

fn detach_nbd(device: &Path) -> Result<()> {
    run_nbd_client(&["-d".to_owned(), device.display().to_string()])
}

fn cleanup_remote_blocks(dir: &Path) {
    cleanup_remote_blocks_with(dir, nbd_kernel_pid, detach_nbd);
}

fn cleanup_remote_blocks_with(
    dir: &Path,
    kernel_pid: impl Fn(&Path) -> Option<String>,
    mut detach: impl FnMut(&Path) -> Result<()>,
) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if !path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| {
                name.starts_with(NBD_RECORD_PREFIX) && name.ends_with(NBD_RECORD_SUFFIX)
            })
        {
            continue;
        }
        let Some(record) = std::fs::read(&path)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<NbdRecord>(&bytes).ok())
        else {
            // An unreadable ownership record is still our only durable clue.
            // Never erase it merely because this cleanup attempt cannot use it.
            continue;
        };
        if kernel_pid(&record.device).as_deref() == Some(record.kernel_pid.as_str())
            && detach(&record.device).is_err()
        {
            // The same attachment is still ours. Keep the record so a later
            // stop/state pass can retry instead of leaking an unowned device.
            continue;
        }
        let _ = std::fs::remove_file(path);
    }
}

fn cleanup_fs_helpers(dir: &Path) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if name.starts_with("virtiofs-") && name.ends_with(".proc.json") {
            if let Ok(bytes) = std::fs::read(&path) {
                if let Ok(proc) = serde_json::from_slice::<ProcId>(&bytes) {
                    stop_with_fallback(&proc);
                }
            }
            let _ = std::fs::remove_file(path);
        } else if name.starts_with("virtiofs-") && name.ends_with(".sock") {
            let _ = std::fs::remove_file(path);
        }
    }
}

fn reap(mut child: Child) {
    thread::spawn(move || {
        let _ = child.wait();
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn instance_networks_are_stable_private_and_locally_administered() {
        let a = Network::for_instance("agent-one");
        let again = Network::for_instance("agent-one");
        let b = Network::for_instance("agent-two");
        assert_eq!(a.host, again.host);
        assert_eq!(a.guest, again.guest);
        assert_eq!(a.mac, again.mac);
        assert_ne!(a.host, b.host);
        assert!(a.host.starts_with("10."));
        assert!(a.mac.starts_with("02:"));
        assert!(a.cid >= 3);
        assert!(a.arg().contains("tap="));
    }

    #[test]
    fn disk_arguments_never_pass_nbd_through_to_cloud_hypervisor() {
        let raw = DiskSpec::File {
            path: "/images/root.raw".into(),
            format: DiskFormat::Raw,
            readonly: false,
        };
        assert_eq!(
            disk_arg(&raw, "root").unwrap(),
            "path=/images/root.raw,readonly=off,image_type=raw,id=root"
        );
        let remote = DiskSpec::NbdUnix {
            socket: "/tmp/volume.sock".into(),
            export: "vol-e3".into(),
            readonly: false,
        };
        assert!(disk_arg(&remote, "vol")
            .unwrap_err()
            .to_string()
            .contains("host block"));
    }

    #[test]
    fn unix_nbd_is_materialized_with_its_export_before_chv_sees_it() {
        assert_eq!(
            nbd_unix_args(
                Path::new("/run/asterism/volume.sock"),
                "tank-e7",
                Path::new("/dev/nbd7"),
            ),
            [
                "-unix",
                "/run/asterism/volume.sock",
                "/dev/nbd7",
                "-N",
                "tank-e7",
            ]
        );
        assert_eq!(
            nbd_url_args("nbd://storage:10810/tank-e7", Path::new("/dev/nbd7")).unwrap(),
            ["storage", "10810", "/dev/nbd7", "-N", "tank-e7"]
        );
        assert!(nbd_url_args("https://not-nbd", Path::new("/dev/nbd7")).is_err());
    }

    #[test]
    fn failed_nbd_detach_retains_ownership_for_a_later_retry() {
        let dir = tempfile::tempdir().unwrap();
        let record_path = nbd_record_path(dir.path(), 0);
        let record = NbdRecord {
            device: "/dev/nbd7".into(),
            kernel_pid: "4242".to_owned(),
        };
        std::fs::write(&record_path, serde_json::to_vec(&record).unwrap()).unwrap();

        cleanup_remote_blocks_with(
            dir.path(),
            |_| Some("4242".to_owned()),
            |_| Err(anyhow::anyhow!("injected detach failure")),
        );
        assert!(record_path.exists());

        cleanup_remote_blocks_with(dir.path(), |_| Some("4242".to_owned()), |_| Ok(()));
        assert!(!record_path.exists());
    }

    #[test]
    fn failed_boot_cleanup_removes_stale_virtiofs_socket_records() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("virtiofs-0.sock");
        std::fs::write(&socket, b"stale").unwrap();
        cleanup_fs_helpers(dir.path());
        assert!(!socket.exists());
    }

    #[test]
    fn failed_boot_cleanup_terminates_started_virtiofsd_before_removing_its_record() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("virtiofs-0.sock");
        let record = dir.path().join("virtiofs-0.proc.json");
        let mut child = Command::new("sh")
            .args(["-c", "trap '' TERM; while :; do sleep 1; done"])
            .spawn()
            .unwrap();
        let proc = ProcId::capture(child.id()).unwrap();
        std::fs::write(&socket, b"stale").unwrap();
        std::fs::write(&record, serde_json::to_vec(&proc).unwrap()).unwrap();

        cleanup_fs_helpers(dir.path());

        assert!(proc.wait_gone(Duration::from_secs(1)));
        let _ = child.wait();
        assert!(!record.exists());
        assert!(!socket.exists());
    }

    #[test]
    fn helper_record_failure_retires_the_started_virtiofsd() {
        let dir = tempfile::tempdir().unwrap();
        let record = dir.path().join("virtiofs-0.proc.json");
        // A directory at the record path makes the durable hand-off fail
        // after the helper has started but before SpawnCleanup can discover it.
        std::fs::create_dir(&record).unwrap();
        let mut child = Command::new("sh")
            .args(["-c", "trap '' TERM; while :; do sleep 1; done"])
            .spawn()
            .unwrap();
        let pid = child.id();

        assert!(record_helper(&mut child, &record).is_err());
        assert!(ProcId::capture(pid).map_or(true, |proc| !proc.alive()));
        let _ = child.wait();
    }

    #[test]
    fn hotplug_uses_the_api_image_type_spelling() {
        let raw = DiskSpec::File {
            path: "/images/data.raw".into(),
            format: DiskFormat::Raw,
            readonly: false,
        };
        assert_eq!(disk_json(&raw, "data").unwrap()["image_type"], "Raw");
        let qcow = DiskSpec::File {
            path: "/images/data.qcow2".into(),
            format: DiskFormat::Qcow2,
            readonly: true,
        };
        assert_eq!(disk_json(&qcow, "data").unwrap()["image_type"], "Qcow2");
    }

    #[test]
    fn cloud_guest_network_is_a_deterministic_nocloud_document() {
        let net = Network::for_instance("agent-one");
        let config = network_config(&net);
        assert!(config.starts_with("version: 2\n"));
        assert!(config.contains(&format!("macaddress: \"{}\"", net.mac)));
        assert!(config.contains(&format!("- {}/24", net.guest)));
        assert!(config.contains(&format!("via: {}", net.host)));
        assert!(config.contains(&format!("      - {}", net.host)));
    }

    #[test]
    fn aarch64_cloud_hypervisor_gets_a_raw_linux_image() {
        if image::host_arch() != "aarch64" {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let kernel = dir.path().join("guest-vmlinuz");
        let mut gzip = Command::new("gzip")
            .args(["-c"])
            .stdin(Stdio::piped())
            .stdout(Stdio::from(std::fs::File::create(&kernel).unwrap()))
            .spawn()
            .unwrap();
        gzip.stdin
            .as_mut()
            .unwrap()
            .write_all(b"raw-linux-image")
            .unwrap();
        assert!(gzip.wait().unwrap().success());

        let payload = direct_kernel_payload(&kernel).unwrap();
        assert_eq!(std::fs::read(&payload).unwrap(), b"raw-linux-image");
        assert_eq!(direct_kernel_payload(&kernel).unwrap(), payload);
    }

    #[test]
    fn api_finishes_at_content_length_without_waiting_for_socket_close() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("api.sock");
        let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = BufReader::new(stream.try_clone().unwrap());
            loop {
                let mut line = String::new();
                request.read_line(&mut line).unwrap();
                if line == "\r\n" {
                    break;
                }
            }
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\npong")
                .unwrap();
            stream.flush().unwrap();
            thread::sleep(Duration::from_millis(250));
        });

        let start = Instant::now();
        assert_eq!(
            api_with_timeout(&socket, "GET", "/vmm.ping", None, Duration::from_secs(1),).unwrap(),
            b"pong"
        );
        assert!(start.elapsed() < Duration::from_millis(200));
        server.join().unwrap();
    }

    #[test]
    fn capabilities_match_the_linux_decision() {
        let caps = Chv::new().caps();
        assert!(caps.live_snapshot && caps.disk_snapshot && caps.live_migration);
        assert!(caps.disk_hotplug && caps.direct_kernel);
        assert!(caps.nbd_disks);
        assert!(!caps.port_forward && caps.guest_egress.is_none());
        assert_eq!(caps.disk_formats, &[DiskFormat::Raw, DiskFormat::Qcow2]);
    }
}
