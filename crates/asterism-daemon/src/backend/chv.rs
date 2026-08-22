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
use asterism_core::{cow, durable, image, oci, paths};
use asterism_vz::guest::{self, Key, Session};

use super::{grow, observed_running, owned};

pub const ID: &str = "chv";
pub const VERSION: &str = "v53.0";

const KVM: &str = "/dev/kvm";
const API_NAME: &str = "chv-api.sock";
const VSOCK_NAME: &str = "chv-vsock.sock";
const PID_NAME: &str = "chv.pid";
const LOG_NAME: &str = "chv.log";
const VMM_RECORD_NAME: &str = "chv-vmm.proc.json";
const START_INTENT_NAME: &str = "chv-start.json";
const SNAPSHOT_RESOURCES_NAME: &str = "asterism-resources.json";
const VIRTIOFS_RESOURCE_PREFIX: &str = "virtiofs-";
const VIRTIOFS_RESOURCE_SUFFIX: &str = ".resource.json";
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
        let operation = if restore.is_some() {
            StartOperation::Restore
        } else {
            StartOperation::Boot
        };
        let operation_source = restore.map(|snapshot| snapshot.display().to_string());
        if let Some(handle) =
            recover_interrupted_spawn(req, operation, operation_source.as_deref())?
        {
            return Ok(handle);
        }
        let restored_resources = restore
            .map(|snapshot| {
                load_snapshot_resources(snapshot, &req.extra_disks, &req.shares, &req.dir)
            })
            .transpose()?;
        // A prior daemon may have died after claiming or attaching NBD.  Its
        // durable intent is the authority for retrying cleanup before this
        // boot chooses another device.
        if !cleanup_fs_helpers(&req.dir) {
            bail!(
                "an earlier Cloud Hypervisor boot left a virtiofs helper whose ownership cannot yet be retired; retry after the host can verify it"
            );
        }
        if !cleanup_remote_blocks(&req.dir) {
            bail!(
                "an earlier Cloud Hypervisor boot left an NBD attachment whose ownership cannot yet be retired; retry after the host can detach it"
            );
        }
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
        let extra_disks = match restored_resources.as_ref() {
            Some(resources) => {
                materialize_remote_disks_exact(&req.extra_disks, &req.dir, &resources.nbd_devices)?
            }
            None => materialize_remote_disks(&req.extra_disks, &req.dir)?,
        };

        let fs_helpers = spawn_fs_helpers(probe, req)?;

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

        let intent = StartIntent {
            version: 1,
            operation,
            source: operation_source,
            helper: probe.helper.clone(),
            api: api.clone(),
            started_at: asterism_core::instance::now_unix(),
        };
        durable::commit_json(&req.dir.join(START_INTENT_NAME), &intent)
            .context("recording Cloud Hypervisor start intent")?;

        let mut child = command
            .spawn()
            .with_context(|| format!("starting {}", probe.helper.display()))?;
        let proc = match capture_execed_child(&mut child, &probe.helper) {
            Ok(proc) => proc,
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(error).context("cloud-hypervisor exited during startup");
            }
        };
        cleanup.vmm = Some(proc.clone());
        durable::commit_json(&req.dir.join(VMM_RECORD_NAME), &proc)
            .context("recording Cloud Hypervisor process identity")?;
        durable::commit(&pidfile, format!("{}\n", proc.pid).as_bytes())?;
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
            if handle.pid.is_some() {
                bail!(
                    "refusing to mark this Cloud Hypervisor guest stopped: its recorded process identity is not proven"
                );
            }
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
            cleanup_stopped(instance_dir_from_api(handle.ctl.path()));
            return Ok(());
        }
        let _ = api(handle.ctl.path(), "PUT", "/vmm.shutdown", None);
        if proc.wait_gone(deadline.saturating_sub(graceful)) {
            cleanup_stopped(instance_dir_from_api(handle.ctl.path()));
            return Ok(());
        }
        proc.signal(Signal::Kill)?;
        if !proc.wait_gone(Duration::from_secs(2)) {
            bail!(
                "Cloud Hypervisor pid {} did not exit after SIGKILL",
                proc.pid
            );
        }
        cleanup_stopped(instance_dir_from_api(handle.ctl.path()));
        Ok(())
    }

    fn kill(&self, handle: &Handle) -> Result<()> {
        let _ = api(handle.ctl.path(), "PUT", "/vmm.shutdown", None);
        if let Some(proc) = owned(handle) {
            if !proc.wait_gone(Duration::from_secs(2)) {
                proc.signal(Signal::Kill)?;
                if !proc.wait_gone(Duration::from_secs(2)) {
                    bail!(
                        "Cloud Hypervisor pid {} did not exit after SIGKILL",
                        proc.pid
                    );
                }
            }
        } else if handle.pid.is_some() {
            bail!(
                "refusing to mark this Cloud Hypervisor guest stopped: its recorded process identity is not proven"
            );
        }
        cleanup_stopped(instance_dir_from_api(handle.ctl.path()));
        Ok(())
    }

    fn state(&self, handle: &Handle) -> Result<RunState> {
        let state = if observed_running(handle) {
            RunState::Running
        } else {
            RunState::Stopped
        };
        if state == RunState::Stopped {
            let dir = instance_dir_from_api(handle.ctl.path());
            cleanup_fs_helpers(dir);
            cleanup_remote_blocks(dir);
            clear_vmm_authority(dir);
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
        if let Err(error) =
            record_snapshot_resources(instance_dir_from_api(handle.ctl.path()), &dir)
        {
            let _ = api(handle.ctl.path(), "PUT", "/vm.resume", None);
            let _ = std::fs::remove_dir_all(&dir);
            return Err(error).context("recording snapshot external resources");
        }
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
        ensure_migration_resources_portable(instance_dir_from_api(handle.ctl.path()))?;
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
        if let Some(proc) =
            recover_interrupted_process(req, StartOperation::MigrationReceive, Some(&source.url))?
        {
            ensure_recovered_resources(req, true)?;
            return finish_migration_receive(req, &proc, &source);
        }
        let mut cleanup = SpawnCleanup::new(&req.dir);
        let api_path = req.dir.join(API_NAME);
        let vsock = req.dir.join(VSOCK_NAME);
        let pidfile = req.dir.join(PID_NAME);
        for stale in [&api_path, &vsock, &pidfile] {
            let _ = std::fs::remove_file(stale);
        }

        if !cleanup_fs_helpers(&req.dir) {
            bail!(
                "an earlier Cloud Hypervisor migration left a virtiofs helper whose ownership cannot yet be retired; retry after the host can verify it"
            );
        }
        if !cleanup_remote_blocks(&req.dir) {
            bail!(
                "an earlier Cloud Hypervisor migration left an NBD attachment whose ownership cannot yet be retired; retry after the host can detach it"
            );
        }
        let _extra_disks = materialize_remote_disks_deterministic(&req.extra_disks, &req.dir)?;
        let _fs_helpers = spawn_fs_helpers(probe, req)?;

        durable::commit_json(
            &req.dir.join(START_INTENT_NAME),
            &StartIntent {
                version: 1,
                operation: StartOperation::MigrationReceive,
                source: Some(source.url.clone()),
                helper: probe.helper.clone(),
                api: api_path.clone(),
                started_at: asterism_core::instance::now_unix(),
            },
        )
        .context("recording Cloud Hypervisor migration-receiver intent")?;
        let log = std::fs::File::create(req.dir.join(LOG_NAME))?;
        let mut child = Command::new(&probe.helper)
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
        let proc = match capture_execed_child(&mut child, &probe.helper) {
            Ok(proc) => proc,
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(error)
                    .context("cloud-hypervisor migration receiver exited during startup");
            }
        };
        cleanup.vmm = Some(proc.clone());
        durable::commit_json(&req.dir.join(VMM_RECORD_NAME), &proc)
            .context("recording Cloud Hypervisor migration-receiver identity")?;
        durable::commit(&pidfile, format!("{}\n", proc.pid).as_bytes())?;
        reap(child);

        let handle = finish_migration_receive(req, &proc, &source)?;
        cleanup.disarm();
        Ok(handle)
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

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
enum StartOperation {
    #[default]
    Boot,
    Restore,
    MigrationReceive,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct StartIntent {
    version: u32,
    #[serde(default)]
    operation: StartOperation,
    #[serde(default)]
    source: Option<String>,
    helper: PathBuf,
    api: PathBuf,
    started_at: u64,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Default)]
struct SnapshotResources {
    version: u32,
    nbd_devices: std::collections::BTreeMap<usize, NbdResource>,
    #[serde(default)]
    virtiofs: std::collections::BTreeMap<usize, VirtiofsResource>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
struct VirtiofsResource {
    socket: PathBuf,
    tag: String,
    host_path: String,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
struct NbdResource {
    device: PathBuf,
    source: String,
}

/// Recover a VMM started by an `ast up` whose daemon died before the handle
/// reached the registry. The start intent is committed before spawn, so even
/// the spawn-to-process-record crash window can be resolved from the unique
/// API path on the candidate's own command line.
fn recover_interrupted_spawn(
    req: &BootReq,
    operation: StartOperation,
    source: Option<&str>,
) -> Result<Option<Handle>> {
    let Some(proc) = recover_interrupted_process(req, operation, source)? else {
        return Ok(None);
    };
    ensure_recovered_resources(req, operation == StartOperation::MigrationReceive)?;
    Ok(Some(recovered_handle(req, proc)?))
}

fn recover_interrupted_process(
    req: &BootReq,
    operation: StartOperation,
    source: Option<&str>,
) -> Result<Option<ProcId>> {
    let record_path = req.dir.join(VMM_RECORD_NAME);
    let intent_path = req.dir.join(START_INTENT_NAME);
    let intent = load_start_intent(&intent_path)?;
    let mut proc = load_process_record(&record_path, "Cloud Hypervisor process identity")?;

    if proc.is_none() {
        let Some(intent) = intent.as_ref() else {
            return Ok(None);
        };
        proc = scan_start_intent(intent)?;
        if let Some(found) = &proc {
            durable::commit_json(&record_path, found)
                .context("recovering Cloud Hypervisor process identity from start intent")?;
        } else {
            remove_durable_record(&intent_path);
            return Ok(None);
        }
    }

    let proc = proc.expect("resolved above");
    match proc.check() {
        asterism_core::proc::Ownership::Gone
        | asterism_core::proc::Ownership::Foreign(_) => {
            clear_vmm_authority(&req.dir);
            Ok(None)
        }
        asterism_core::proc::Ownership::Unknown(why) => bail!(
            "a prior Cloud Hypervisor process may still own {:?}, but this host cannot verify it ({why}); refusing a second VMM",
            req.instance.name
        ),
        asterism_core::proc::Ownership::Ours => {
            let Some(intent) = &intent else {
                bail!(
                    "a live Cloud Hypervisor process still owns {:?}, but its operation intent is missing; refusing to guess or spawn a replacement",
                    req.instance.name
                );
            };
            if intent.operation != operation || intent.source.as_deref() != source {
                bail!(
                    "a prior Cloud Hypervisor {:?} operation for {:?} still owns {:?}; refusing to replace it with {:?} for {:?}",
                    intent.operation,
                    intent.source,
                    req.instance.name,
                    operation,
                    source
                );
            }
            Ok(Some(proc))
        }
    }
}

fn recovered_handle(req: &BootReq, proc: ProcId) -> Result<Handle> {
    let api = req.dir.join(API_NAME);
    let endpoint = recovered_endpoint(req, &proc)?;
    Ok(Handle::owning(
        ID,
        proc,
        ControlChannel::HttpApi { path: api },
        endpoint,
    ))
}

fn recovered_endpoint(req: &BootReq, proc: &ProcId) -> Result<GuestEndpoint> {
    if req.base.kind == ImageKind::Disk {
        wait_for_guest(
            &req.dir.join(VSOCK_NAME),
            &req.dir,
            req.instance,
            proc,
            BOOT_TIMEOUT,
        )
    } else {
        Ok(GuestEndpoint::GuestAddr {
            addr: Network::for_instance(&req.instance.name).guest.parse()?,
        })
    }
}

/// Continue an incoming migration on its already-recorded receiver, or adopt
/// it when the migration crossed the side-effect boundary before the daemon
/// could persist the returned handle. Querying the receiver state first is
/// what makes the retry idempotent: a Running/Paused VM is the migrated guest,
/// while Created is still waiting for `/vm.receive-migration`.
fn finish_migration_receive(
    req: &BootReq,
    proc: &ProcId,
    source: &MigrationSource,
) -> Result<Handle> {
    let api_path = req.dir.join(API_NAME);
    wait_for_api(&api_path, proc, API_START_TIMEOUT)?;
    let state = match vm_state(&api_path) {
        Ok(state) => state,
        Err(error) if error.to_string().contains("HTTP 404") => "NotCreated".to_owned(),
        Err(error) => return Err(error).context("inspecting the recovered migration receiver"),
    };
    match state.as_str() {
        "Running" => {}
        "Paused" => {
            api(&api_path, "PUT", "/vm.resume", None)
                .context("resuming the recovered migrated guest")?;
        }
        "Created" | "NotCreated" => {
            api_with_timeout(
                &api_path,
                "PUT",
                "/vm.receive-migration",
                Some(&serde_json::json!({"receiver_url": source.url})),
                LONG_API_TIMEOUT,
            )
            .context("receiving a Cloud Hypervisor migration")?;
        }
        state => bail!(
            "the recovered Cloud Hypervisor migration receiver is in state {state:?}; retaining its exact process authority rather than spawning a replacement"
        ),
    }
    recovered_handle(req, proc.clone())
}

fn vm_state(api_path: &Path) -> Result<String> {
    let body = api(api_path, "GET", "/vm.info", None)?;
    vm_state_from_body(&body)
}

fn vm_state_from_body(body: &[u8]) -> Result<String> {
    let value: serde_json::Value =
        serde_json::from_slice(body).context("Cloud Hypervisor vm.info returned invalid JSON")?;
    value
        .get("state")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
        .context("Cloud Hypervisor vm.info omitted its VM state")
}

fn load_process_record(path: &Path, what: &str) -> Result<Option<ProcId>> {
    Ok(durable::load_json(path, what)?.map(|loaded| {
        if let Some(repaired) = loaded.repaired {
            eprintln!("astd: {repaired}");
        }
        loaded.value
    }))
}

fn load_start_intent(path: &Path) -> Result<Option<StartIntent>> {
    Ok(
        durable::load_json(path, "Cloud Hypervisor start intent")?.map(|loaded| {
            if let Some(repaired) = loaded.repaired {
                eprintln!("astd: {repaired}");
            }
            loaded.value
        }),
    )
}

#[cfg(target_os = "linux")]
fn scan_start_intent(intent: &StartIntent) -> Result<Option<ProcId>> {
    use std::os::unix::ffi::OsStrExt;

    let mut found = Vec::new();
    for entry in std::fs::read_dir("/proc")? {
        let entry = entry?;
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse().ok())
        else {
            continue;
        };
        if !child_argv0(pid)
            .as_deref()
            .is_some_and(|path| helper_path_matches(path, &intent.helper))
        {
            continue;
        }
        let Ok(cmdline) = std::fs::read(format!("/proc/{pid}/cmdline")) else {
            continue;
        };
        if !cmdline
            .split(|byte| *byte == 0)
            .any(|arg| arg == intent.api.as_os_str().as_bytes())
        {
            continue;
        }
        if let Ok(proc) = ProcId::capture(pid) {
            found.push(proc);
        }
    }
    match found.len() {
        0 => Ok(None),
        1 => Ok(found.pop()),
        count => bail!(
            "{count} Cloud Hypervisor processes claim the unique API path {}; refusing to guess",
            intent.api.display()
        ),
    }
}

#[cfg(not(target_os = "linux"))]
fn scan_start_intent(_intent: &StartIntent) -> Result<Option<ProcId>> {
    Ok(None)
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
        let ownership = proc.check();
        if ownership.is_ended() {
            bail!(
                "cloud-hypervisor exited before {:?}'s guest became ready: {ownership:?}",
                instance.name,
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
        let vmm_retired = self.vmm.as_ref().is_none_or(retire_owned_process);
        if vmm_retired {
            clear_vmm_authority(self.dir);
            cleanup_fs_helpers(self.dir);
            cleanup_remote_blocks(self.dir);
        }
    }
}

/// Retire exactly the recorded process. `false` retains durable authority for
/// a later retry; an unreadable identity or failed signal is never papered
/// over by deleting the only record that can safely target the helper.
fn retire_owned_process(proc: &ProcId) -> bool {
    use asterism_core::proc::Ownership;

    match proc.check() {
        Ownership::Gone | Ownership::Foreign(_) => return true,
        Ownership::Unknown(_) => return false,
        Ownership::Ours => {}
    }
    if proc.signal(Signal::Term).is_err() {
        return false;
    }
    if proc.wait_gone(Duration::from_secs(2)) {
        return true;
    }
    if proc.signal(Signal::Kill).is_err() {
        return false;
    }
    proc.wait_gone(Duration::from_secs(2))
}

/// Persist a just-started helper before handing it to the background reaper.
///
/// [`SpawnCleanup`] retires helpers from their durable record.  That record
/// therefore has to be an all-or-nothing hand-off: if either capturing process
/// identity or writing the record fails, this function still owns `child` and
/// synchronously retires it.  In particular, a full/read-only instance
/// directory must not turn into an untracked virtiofsd on a failed boot.
fn record_helper(child: &mut Child, executable: &Path, record: &Path) -> Result<ProcId> {
    let proc = match capture_execed_child(child, executable) {
        Ok(proc) => proc,
        Err(error) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(error).context("virtiofsd exited during startup");
        }
    };
    if let Err(error) = (|| -> Result<()> {
        durable::commit_json(record, &proc)?;
        Ok(())
    })() {
        // We still hold the Child, so this kill targets the child handle
        // directly rather than depending on the durable hand-off that just
        // failed.
        let _ = child.kill();
        let _ = child.wait();
        return Err(error).with_context(|| format!("recording {}", record.display()));
    }
    Ok(proc)
}

/// Recreate the external virtiofs endpoints before either a fresh boot, a
/// restore, or an incoming migration starts its VMM. Snapshot and migration
/// state remember these deterministic socket paths; the helper processes are
/// deliberately outside Cloud Hypervisor and therefore must be rehydrated by
/// Asterism first.
fn spawn_fs_helpers(probe: &Probe, req: &BootReq) -> Result<Vec<(String, PathBuf)>> {
    let mut helpers = Vec::new();
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
        let proc = record_helper(&mut child, virtiofsd, &record)?;
        reap(child);
        wait_for_path(&socket, &proc, Duration::from_secs(10))?;
        durable::commit_json(
            &virtiofs_resource_path(&req.dir, index),
            &VirtiofsResource {
                socket: socket.clone(),
                tag: share.tag.clone(),
                host_path: share.host_path.clone(),
            },
        )
        .context("recording the virtiofs endpoint identity")?;
        helpers.push((share.tag.clone(), socket));
    }
    Ok(helpers)
}

/// Capture a child only after it has crossed the fork-to-exec boundary.
///
/// `Command::spawn` returns as soon as the fork succeeds. Capturing in that
/// window records the daemon executable; once the child execs its helper the
/// otherwise-stable pid/start-time pair is then (correctly) classified as a
/// foreign process. Cloud Hypervisor reaches this window on real KVM hosts,
/// and a file-capability helper makes `/proc/<pid>/exe` unreadable after exec,
/// so the command line is the only reliable readiness witness here.
fn capture_execed_child(child: &mut Child, executable: &Path) -> Result<ProcId> {
    let pid = child.id();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if child_argv0(pid)
            .as_deref()
            .is_some_and(|observed| helper_path_matches(observed, executable))
        {
            return ProcId::capture(pid);
        }
        match child.try_wait()? {
            Some(status) => bail!("helper exited before exec: {status}"),
            None if Instant::now() >= deadline => {
                bail!(
                    "helper pid {pid} did not exec {} within five seconds",
                    executable.display()
                )
            }
            None => thread::sleep(Duration::from_millis(10)),
        }
    }
}

fn helper_path_matches(observed: &Path, expected: &Path) -> bool {
    if expected.components().count() > 1 {
        observed == expected
    } else {
        observed.file_name() == expected.file_name()
    }
}

#[cfg(target_os = "linux")]
fn child_argv0(pid: u32) -> Option<PathBuf> {
    use std::os::unix::ffi::OsStringExt;

    let bytes = std::fs::read(format!("/proc/{pid}/cmdline")).ok()?;
    let first = bytes.split(|byte| *byte == 0).next()?;
    (!first.is_empty()).then(|| PathBuf::from(std::ffi::OsString::from_vec(first.to_vec())))
}

#[cfg(not(target_os = "linux"))]
fn child_argv0(pid: u32) -> Option<PathBuf> {
    // The backend is Linux-only. This fallback keeps its process-lifecycle
    // tests honest on developer Macs, where ProcId's executable is readable.
    ProcId::capture(pid).ok()?.exec
}

#[derive(serde::Serialize, serde::Deserialize)]
struct NbdRecord {
    device: PathBuf,
    /// Digest of the remote DiskSpec. Device-path recovery is not exact if a
    /// retry can silently attach a different export there; hashing keeps any
    /// URL credentials out of the root-owned attachment record.
    #[serde(default)]
    source: Option<String>,
    /// `/sys/block/nbdN/pid` after attach.  Cleanup only detaches when this
    /// still matches, so a reused device can never be disconnected by an old
    /// instance record.
    #[serde(default)]
    kernel_pid: Option<String>,
}

fn materialize_remote_disks(disks: &[DiskSpec], dir: &Path) -> Result<Vec<DiskSpec>> {
    disks
        .iter()
        .enumerate()
        .map(|(index, disk)| materialize_remote_disk(disk, dir, index, None))
        .collect()
}

fn materialize_remote_disks_exact(
    disks: &[DiskSpec],
    dir: &Path,
    devices: &std::collections::BTreeMap<usize, NbdResource>,
) -> Result<Vec<DiskSpec>> {
    disks
        .iter()
        .enumerate()
        .map(|(index, disk)| {
            let desired = if matches!(disk, DiskSpec::Nbd { .. } | DiskSpec::NbdUnix { .. }) {
                let resource = devices.get(&index).with_context(|| {
                    format!(
                        "the snapshot omitted the host block path for remote disk {index}; refusing a restore whose device graph would point elsewhere"
                    )
                })?;
                let source = remote_disk_identity(disk)?;
                if resource.source != source {
                    bail!(
                        "the snapshot's remote disk {index} names a different export; refusing to restore substituted block content"
                    );
                }
                Some(&resource.device)
            } else {
                None
            };
            materialize_remote_disk(disk, dir, index, desired.map(PathBuf::as_path))
        })
        .collect()
}

fn materialize_remote_disks_deterministic(disks: &[DiskSpec], dir: &Path) -> Result<Vec<DiskSpec>> {
    disks
        .iter()
        .enumerate()
        .map(|(index, disk)| {
            let desired = matches!(disk, DiskSpec::Nbd { .. } | DiskSpec::NbdUnix { .. })
                .then(|| preferred_nbd_device(dir, index));
            materialize_remote_disk(disk, dir, index, desired.as_deref())
        })
        .collect()
}

fn materialize_remote_disk(
    disk: &DiskSpec,
    dir: &Path,
    index: usize,
    desired: Option<&Path>,
) -> Result<DiskSpec> {
    match disk {
        DiskSpec::NbdUnix {
            socket,
            export,
            readonly,
        } => {
            let source = remote_disk_identity(disk)?;
            let device = attach_nbd(dir, index, *readonly, desired, &source, |device| {
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
            let source = remote_disk_identity(disk)?;
            let device = attach_nbd(dir, index, *readonly, desired, &source, |device| {
                nbd_url_args(url, device)
            })?;
            Ok(DiskSpec::Block {
                path: device,
                readonly: *readonly,
            })
        }
        other => Ok(other.clone()),
    }
}

fn remote_disk_identity(disk: &DiskSpec) -> Result<String> {
    if !matches!(disk, DiskSpec::Nbd { .. } | DiskSpec::NbdUnix { .. }) {
        bail!("only a remote block volume has an NBD source identity");
    }
    let serialized =
        serde_json::to_vec(disk).context("serializing the remote block source identity")?;
    Ok(blake3::hash(&serialized).to_hex().to_string())
}

fn attach_nbd(
    dir: &Path,
    index: usize,
    readonly: bool,
    desired: Option<&Path>,
    source: &str,
    args_for: impl FnOnce(&Path) -> Result<Vec<String>>,
) -> Result<PathBuf> {
    let device = match desired {
        Some(device) => {
            if !device.exists() {
                bail!(
                    "the required snapshot/migration device {} does not exist",
                    device.display()
                );
            }
            if nbd_kernel_pid(device).is_some() {
                bail!(
                    "the required snapshot/migration device {} is already attached; refusing to restore onto another owner",
                    device.display()
                );
            }
            device.to_owned()
        }
        None => free_nbd_device_from(preferred_nbd_index(dir, index))?,
    };
    attach_nbd_at(
        dir,
        index,
        readonly,
        device,
        source,
        args_for,
        run_nbd_client,
        nbd_kernel_pid,
    )
}

/// Claim an NBD device durably before crossing the privileged attach boundary.
///
/// `nbd-client` can report failure after the kernel accepted an attach, and a
/// successful attach can be followed by ENOSPC while recording ownership.  A
/// pre-attach intent makes both outcomes retryable: cleanup treats a claimed
/// device with no recorded kernel pid as ours iff the device is now attached.
fn attach_nbd_at(
    dir: &Path,
    index: usize,
    readonly: bool,
    device: PathBuf,
    source: &str,
    args_for: impl FnOnce(&Path) -> Result<Vec<String>>,
    run: impl FnOnce(&[String]) -> Result<()>,
    kernel_pid: impl Fn(&Path) -> Option<String>,
) -> Result<PathBuf> {
    let mut args = args_for(&device)?;
    if readonly {
        args.push("-readonly".to_owned());
    }
    let record_path = nbd_record_path(dir, index);
    persist_nbd_record(
        &record_path,
        &NbdRecord {
            device: device.clone(),
            source: Some(source.to_owned()),
            kernel_pid: None,
        },
    )
    .with_context(|| format!("claiming {} before attach", device.display()))?;

    let attach = run(&args);
    let observed_pid = kernel_pid(&device);
    if let Some(kernel_pid) = observed_pid.as_ref() {
        persist_nbd_record(
            &record_path,
            &NbdRecord {
                device: device.clone(),
                source: Some(source.to_owned()),
                kernel_pid: Some(kernel_pid.clone()),
            },
        )
        .with_context(|| format!("recording attached ownership of {}", device.display()))?;
    }

    if let Err(error) = attach {
        if observed_pid.is_none() {
            remove_nbd_record(&record_path);
        }
        return Err(error).with_context(|| {
            format!(
                "attaching the remote volume as {}; Cloud Hypervisor consumes host block devices",
                device.display()
            )
        });
    }
    if observed_pid.is_none() {
        // Keep the intent. SpawnCleanup (or the next daemon) will remove it
        // after confirming the device is unattached, or detach it if the
        // kernel attachment becomes visible after this ambiguous boundary.
        bail!(
            "nbd-client reported success for {}, but the host did not expose an attached NBD pid",
            device.display()
        );
    }
    Ok(device)
}

fn persist_nbd_record(path: &Path, record: &NbdRecord) -> Result<()> {
    durable::commit_json(path, record)
}

fn remove_nbd_record(path: &Path) {
    for candidate in [
        path.to_owned(),
        durable::tmp_path(path),
        durable::backup_path(path),
    ] {
        match std::fs::remove_file(candidate) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return,
        }
    }
    if let Some(parent) = path.parent() {
        let _ = durable::sync_dir(parent);
    }
}

fn read_nbd_record(path: &Path) -> Option<NbdRecord> {
    durable::load_json(path, "Cloud Hypervisor NBD ownership")
        .ok()
        .flatten()
        .map(|loaded| loaded.value)
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

fn preferred_nbd_index(dir: &Path, disk_index: usize) -> usize {
    let mut input = dir
        .file_name()
        .unwrap_or_default()
        .as_encoded_bytes()
        .to_vec();
    input.extend_from_slice(&disk_index.to_le_bytes());
    usize::from(blake3::hash(&input).as_bytes()[0]) % 64
}

fn preferred_nbd_device(dir: &Path, disk_index: usize) -> PathBuf {
    PathBuf::from(format!("/dev/nbd{}", preferred_nbd_index(dir, disk_index)))
}

fn free_nbd_device_from(first: usize) -> Result<PathBuf> {
    for offset in 0..64 {
        let index = (first + offset) % 64;
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

fn virtiofs_resource_path(dir: &Path, index: usize) -> PathBuf {
    dir.join(format!(
        "{VIRTIOFS_RESOURCE_PREFIX}{index}{VIRTIOFS_RESOURCE_SUFFIX}"
    ))
}

fn virtiofs_resource_index(path: &Path) -> Option<usize> {
    path.file_name()?
        .to_str()?
        .strip_prefix(VIRTIOFS_RESOURCE_PREFIX)?
        .strip_suffix(VIRTIOFS_RESOURCE_SUFFIX)?
        .parse()
        .ok()
}

fn durable_record_index(path: &Path, prefix: &str, suffix: &str) -> Option<usize> {
    let name = path.file_name()?.to_str()?;
    let canonical = name.strip_suffix(durable::BAK_SUFFIX).unwrap_or(name);
    canonical
        .strip_prefix(prefix)?
        .strip_suffix(suffix)?
        .parse()
        .ok()
}

/// A recovered VMM is only the same instance if every external endpoint it
/// retained is also the exact endpoint this retry describes. Process identity
/// alone prevents double boot; these checks prevent exact process adoption
/// from silently substituting a directory or remote export underneath it.
fn ensure_recovered_resources(req: &BootReq, deterministic_nbd: bool) -> Result<()> {
    let expected_virtiofs: std::collections::BTreeMap<usize, VirtiofsResource> = req
        .shares
        .iter()
        .enumerate()
        .map(|(index, share)| {
            (
                index,
                VirtiofsResource {
                    socket: req.dir.join(format!("virtiofs-{index}.sock")),
                    tag: share.tag.clone(),
                    host_path: share.host_path.clone(),
                },
            )
        })
        .collect();
    let expected_nbd: std::collections::BTreeMap<usize, String> = req
        .extra_disks
        .iter()
        .enumerate()
        .filter_map(|(index, disk)| {
            matches!(disk, DiskSpec::Nbd { .. } | DiskSpec::NbdUnix { .. })
                .then(|| remote_disk_identity(disk).map(|source| (index, source)))
        })
        .collect::<Result<_>>()?;

    let mut recorded_virtiofs = std::collections::BTreeSet::new();
    let mut recorded_nbd = std::collections::BTreeSet::new();
    for entry in std::fs::read_dir(&req.dir)? {
        let path = entry?.path();
        if let Some(index) =
            durable_record_index(&path, VIRTIOFS_RESOURCE_PREFIX, VIRTIOFS_RESOURCE_SUFFIX)
        {
            recorded_virtiofs.insert(index);
        }
        if let Some(index) = durable_record_index(&path, NBD_RECORD_PREFIX, NBD_RECORD_SUFFIX) {
            recorded_nbd.insert(index);
        }
    }
    if recorded_virtiofs != expected_virtiofs.keys().copied().collect()
        || recorded_nbd != expected_nbd.keys().copied().collect()
    {
        bail!(
            "the recovered Cloud Hypervisor's external-resource records do not match this retry; retaining its exact process authority rather than guessing a device graph"
        );
    }

    for (index, expected) in expected_virtiofs {
        let path = virtiofs_resource_path(&req.dir, index);
        let resource =
            durable::load_json::<VirtiofsResource>(&path, "Cloud Hypervisor virtiofs endpoint")?
                .with_context(|| {
                    format!("the live resource record {} disappeared", path.display())
                })?
                .value;
        let proc_path = req.dir.join(format!("virtiofs-{index}.proc.json"));
        let proc = load_process_record(&proc_path, "virtiofs helper process identity")?
            .with_context(|| {
                format!("the live helper record {} disappeared", proc_path.display())
            })?;
        if resource != expected || !proc.alive() || !resource.socket.exists() {
            bail!(
                "the recovered virtiofs endpoint {index} is not the exact live directory share this retry requested; retaining VMM authority"
            );
        }
    }
    for (index, expected_source) in expected_nbd {
        let path = nbd_record_path(&req.dir, index);
        let record = durable::load_json::<NbdRecord>(&path, "Cloud Hypervisor NBD ownership")?
            .with_context(|| format!("the live NBD record {} disappeared", path.display()))?
            .value;
        let Some(expected_pid) = record.kernel_pid.as_deref() else {
            bail!(
                "the recovered remote disk {index} has only a pre-attach intent; retaining VMM authority"
            );
        };
        if record.source.as_deref() != Some(expected_source.as_str())
            || nbd_kernel_pid(&record.device).as_deref() != Some(expected_pid)
            || (deterministic_nbd && record.device != preferred_nbd_device(&req.dir, index))
        {
            bail!(
                "the recovered remote disk {index} is not the exact live export and host device this retry requested; retaining VMM authority"
            );
        }
    }
    Ok(())
}

fn record_snapshot_resources(instance_dir: &Path, snapshot_dir: &Path) -> Result<()> {
    let mut resources = SnapshotResources {
        version: 1,
        ..SnapshotResources::default()
    };
    for entry in std::fs::read_dir(instance_dir)? {
        let path = entry?.path();
        if let Some(index) =
            durable_record_index(&path, VIRTIOFS_RESOURCE_PREFIX, VIRTIOFS_RESOURCE_SUFFIX)
        {
            let resource_path = virtiofs_resource_path(instance_dir, index);
            let resource = durable::load_json::<VirtiofsResource>(
                &resource_path,
                "Cloud Hypervisor virtiofs endpoint",
            )?
            .with_context(|| {
                format!(
                    "the live resource record {} disappeared",
                    resource_path.display()
                )
            })?
            .value;
            let proc_path = instance_dir.join(format!("virtiofs-{index}.proc.json"));
            let proc = load_process_record(&proc_path, "virtiofs helper process identity")?
                .with_context(|| {
                    format!("the live helper record {} disappeared", proc_path.display())
                })?;
            if !proc.alive() || !resource.socket.exists() {
                bail!(
                    "virtiofs helper {index} is not serving {}; refusing a snapshot whose external filesystem endpoint cannot be restored",
                    resource.socket.display()
                );
            }
            if resource.socket != instance_dir.join(format!("virtiofs-{index}.sock")) {
                bail!(
                    "virtiofs helper {index} recorded a non-deterministic socket {}; refusing a snapshot that could not be restored exactly",
                    resource.socket.display()
                );
            }
            resources.virtiofs.insert(index, resource);
            continue;
        }
        let Some(index) = durable_record_index(&path, NBD_RECORD_PREFIX, NBD_RECORD_SUFFIX) else {
            continue;
        };
        let record_path = nbd_record_path(instance_dir, index);
        let loaded =
            durable::load_json::<NbdRecord>(&record_path, "Cloud Hypervisor NBD ownership")?
                .with_context(|| {
                    format!("the live NBD record {} disappeared", record_path.display())
                })?;
        let record = loaded.value;
        let Some(expected_pid) = record.kernel_pid.as_deref() else {
            bail!(
                "remote disk {index} has only a pre-attach intent; refusing a snapshot that could not restore its device graph"
            );
        };
        if nbd_kernel_pid(&record.device).as_deref() != Some(expected_pid) {
            bail!(
                "remote disk {index} no longer owns {}; refusing to snapshot stale block authority",
                record.device.display()
            );
        }
        let Some(source) = record.source else {
            bail!(
                "remote disk {index} predates durable source identity; refusing a snapshot that could later attach a different export"
            );
        };
        resources.nbd_devices.insert(
            index,
            NbdResource {
                device: record.device,
                source,
            },
        );
    }
    durable::commit_json(&snapshot_dir.join(SNAPSHOT_RESOURCES_NAME), &resources)
}

fn load_snapshot_resources(
    snapshot_dir: &Path,
    disks: &[DiskSpec],
    shares: &[asterism_core::seed::Share],
    instance_dir: &Path,
) -> Result<SnapshotResources> {
    let expected_nbd: std::collections::BTreeSet<usize> = disks
        .iter()
        .enumerate()
        .filter_map(|(index, disk)| {
            matches!(disk, DiskSpec::Nbd { .. } | DiskSpec::NbdUnix { .. }).then_some(index)
        })
        .collect();
    let path = snapshot_dir.join(SNAPSHOT_RESOURCES_NAME);
    let Some(loaded) = durable::load_json::<SnapshotResources>(
        &path,
        "Cloud Hypervisor snapshot external resources",
    )?
    else {
        if !expected_nbd.is_empty() || !shares.is_empty() {
            bail!(
                "this snapshot predates durable external-resource mapping; refusing to restore a device graph whose host paths cannot be reproduced"
            );
        }
        return Ok(SnapshotResources::default());
    };
    if loaded.value.version != 1 {
        bail!(
            "Cloud Hypervisor snapshot resource version {} is newer than this build understands",
            loaded.value.version
        );
    }
    let resources = loaded.value;
    let recorded_nbd: std::collections::BTreeSet<usize> =
        resources.nbd_devices.keys().copied().collect();
    if recorded_nbd != expected_nbd {
        bail!(
            "the snapshot's remote block indices do not match this instance's attached volumes; refusing to restore a different device graph"
        );
    }
    for (index, disk) in disks.iter().enumerate() {
        if !expected_nbd.contains(&index) {
            continue;
        }
        let expected_source = remote_disk_identity(disk)?;
        let recorded = resources
            .nbd_devices
            .get(&index)
            .expect("the index sets were compared above");
        if recorded.source != expected_source {
            bail!(
                "the snapshot's remote disk {index} names a different export; refusing to restore substituted block content"
            );
        }
    }
    let expected_virtiofs: std::collections::BTreeMap<usize, VirtiofsResource> = shares
        .iter()
        .enumerate()
        .map(|(index, share)| {
            (
                index,
                VirtiofsResource {
                    socket: instance_dir.join(format!("virtiofs-{index}.sock")),
                    tag: share.tag.clone(),
                    host_path: share.host_path.clone(),
                },
            )
        })
        .collect();
    if resources.virtiofs != expected_virtiofs {
        bail!(
            "the snapshot's virtiofs endpoints or source directories do not match this instance's attached directories; refusing to restore a different device graph"
        );
    }
    Ok(resources)
}

fn ensure_migration_resources_portable(instance_dir: &Path) -> Result<()> {
    let mut recorded_resources = std::collections::BTreeSet::new();
    let mut recorded_helpers = std::collections::BTreeSet::new();
    for entry in std::fs::read_dir(instance_dir)? {
        let path = entry?.path();
        if let Some(index) =
            durable_record_index(&path, VIRTIOFS_RESOURCE_PREFIX, VIRTIOFS_RESOURCE_SUFFIX)
        {
            let resource_path = virtiofs_resource_path(instance_dir, index);
            let resource = durable::load_json::<VirtiofsResource>(
                &resource_path,
                "Cloud Hypervisor virtiofs endpoint",
            )?
            .with_context(|| {
                format!(
                    "the live resource record {} disappeared",
                    resource_path.display()
                )
            })?
            .value;
            let proc_path = instance_dir.join(format!("virtiofs-{index}.proc.json"));
            let proc = load_process_record(&proc_path, "virtiofs helper process identity")?
                .with_context(|| {
                    format!("the live helper record {} disappeared", proc_path.display())
                })?;
            let expected_socket = instance_dir.join(format!("virtiofs-{index}.sock"));
            if !proc.alive() || resource.socket != expected_socket || !resource.socket.exists() {
                bail!(
                    "virtiofs helper {index} is not serving its deterministic socket {}; refusing to migrate a broken external endpoint",
                    expected_socket.display()
                );
            }
            recorded_resources.insert(index);
            continue;
        }
        if let Some(index) = durable_record_index(&path, "virtiofs-", ".proc.json") {
            recorded_helpers.insert(index);
            continue;
        }
        let Some(index) = durable_record_index(&path, NBD_RECORD_PREFIX, NBD_RECORD_SUFFIX) else {
            continue;
        };
        let record_path = nbd_record_path(instance_dir, index);
        let loaded =
            durable::load_json::<NbdRecord>(&record_path, "Cloud Hypervisor NBD ownership")?
                .with_context(|| {
                    format!("the live NBD record {} disappeared", record_path.display())
                })?;
        let required = preferred_nbd_device(instance_dir, index);
        if loaded.value.device != required {
            bail!(
                "remote disk {index} is attached at {}, but migration requires deterministic {}; stop the guest, free that device, and start it again before migrating",
                loaded.value.device.display(),
                required.display()
            );
        }
        let Some(expected_pid) = loaded.value.kernel_pid.as_deref() else {
            bail!(
                "remote disk {index} has only a pre-attach intent; refusing to migrate an ambiguous external endpoint"
            );
        };
        if nbd_kernel_pid(&loaded.value.device).as_deref() != Some(expected_pid) {
            bail!(
                "remote disk {index} no longer owns {}; refusing to migrate stale block authority",
                loaded.value.device.display()
            );
        }
        if loaded.value.source.is_none() {
            bail!(
                "remote disk {index} predates durable source identity; refusing a migration that could attach a different export on the target"
            );
        }
    }
    if recorded_helpers != recorded_resources {
        bail!(
            "the live virtiofs process and endpoint records disagree; refusing to migrate without complete external-resource authority"
        );
    }
    Ok(())
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

fn cleanup_remote_blocks(dir: &Path) -> bool {
    cleanup_remote_blocks_with(dir, nbd_kernel_pid, detach_nbd);
    !has_nbd_records(dir)
}

fn cleanup_remote_blocks_with(
    dir: &Path,
    kernel_pid: impl Fn(&Path) -> Option<String>,
    mut detach: impl FnMut(&Path) -> Result<()>,
) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let mut records = std::collections::BTreeSet::new();
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if name.starts_with(NBD_RECORD_PREFIX) && name.ends_with(NBD_RECORD_SUFFIX) {
            records.insert(path);
        } else if name.starts_with(NBD_RECORD_PREFIX)
            && name.ends_with(&format!("{NBD_RECORD_SUFFIX}{}", durable::BAK_SUFFIX))
        {
            records.insert(PathBuf::from(
                path.to_string_lossy()
                    .strip_suffix(durable::BAK_SUFFIX)
                    .unwrap_or_default(),
            ));
        }
    }
    for path in records {
        let Some(record) = read_nbd_record(&path) else {
            // An unreadable ownership record is still our only durable clue.
            // Never erase it merely because this cleanup attempt cannot use it.
            continue;
        };
        match (record.kernel_pid.as_deref(), kernel_pid(&record.device)) {
            (Some(expected), Some(actual)) if actual == expected => {
                if detach(&record.device).is_err() {
                    // The same attachment is still ours. Keep the record so a
                    // later stop/state pass retries it.
                    continue;
                }
            }
            (Some(_), Some(_)) => {
                // The device has been reused. This record is stale authority,
                // never permission to detach the new owner.
            }
            (None, Some(_)) => {
                // Intent was durable before attach. A live device at recovery
                // is therefore the ambiguous side effect this intent owns.
                if detach(&record.device).is_err() {
                    continue;
                }
            }
            (_, None) => {}
        }
        remove_nbd_record(&path);
    }
}

fn cleanup_fs_helpers(dir: &Path) -> bool {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return true;
    };
    let mut records = std::collections::BTreeSet::new();
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if name.starts_with("virtiofs-") && name.ends_with(".proc.json") {
            records.insert(path);
        } else if name.starts_with("virtiofs-")
            && name.ends_with(&format!(".proc.json{}", durable::BAK_SUFFIX))
        {
            records.insert(PathBuf::from(
                path.to_string_lossy()
                    .strip_suffix(durable::BAK_SUFFIX)
                    .unwrap_or_default(),
            ));
        }
    }

    let mut all_retired = true;
    for record in records {
        let proc = match load_process_record(&record, "virtiofs helper process identity") {
            Ok(Some(proc)) => proc,
            Ok(None) => continue,
            Err(error) => {
                eprintln!("astd: {error:#}");
                all_retired = false;
                continue;
            }
        };
        if !retire_owned_process(&proc) {
            all_retired = false;
            continue;
        }
        remove_durable_record(&record);
        let socket = record.with_file_name(
            record
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or_default()
                .trim_end_matches(".proc.json")
                .to_owned()
                + ".sock",
        );
        let _ = std::fs::remove_file(socket);
    }
    if all_retired {
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if virtiofs_resource_index(&path).is_some() {
                    remove_durable_record(&path);
                    continue;
                }
                if path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| {
                        name.starts_with(VIRTIOFS_RESOURCE_PREFIX)
                            && name.ends_with(&format!(
                                "{VIRTIOFS_RESOURCE_SUFFIX}{}",
                                durable::BAK_SUFFIX
                            ))
                    })
                {
                    if let Some(primary) = path
                        .to_string_lossy()
                        .strip_suffix(durable::BAK_SUFFIX)
                        .map(PathBuf::from)
                    {
                        remove_durable_record(&primary);
                    }
                    continue;
                }
                let remove_socket =
                    path.file_name()
                        .and_then(|name| name.to_str())
                        .is_some_and(|name| {
                            name.starts_with(VIRTIOFS_RESOURCE_PREFIX) && name.ends_with(".sock")
                        });
                if remove_socket {
                    let _ = std::fs::remove_file(path);
                }
            }
        }
    }
    all_retired
}

fn cleanup_stopped(dir: &Path) {
    cleanup_fs_helpers(dir);
    cleanup_remote_blocks(dir);
    clear_vmm_authority(dir);
}

fn clear_vmm_authority(dir: &Path) {
    remove_durable_record(&dir.join(VMM_RECORD_NAME));
    remove_durable_record(&dir.join(START_INTENT_NAME));
    remove_durable_record(&dir.join(PID_NAME));
}

fn remove_durable_record(path: &Path) {
    for candidate in [
        path.to_owned(),
        durable::tmp_path(path),
        durable::backup_path(path),
    ] {
        match std::fs::remove_file(candidate) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return,
        }
    }
    if let Some(parent) = path.parent() {
        let _ = durable::sync_dir(parent);
    }
}

fn has_nbd_records(dir: &Path) -> bool {
    std::fs::read_dir(dir).is_ok_and(|entries| {
        entries.flatten().any(|entry| {
            entry.file_name().to_str().is_some_and(|name| {
                name.starts_with(NBD_RECORD_PREFIX)
                    && (name.ends_with(NBD_RECORD_SUFFIX)
                        || name.ends_with(&format!("{NBD_RECORD_SUFFIX}{}", durable::BAK_SUFFIX)))
            })
        })
    })
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
            source: Some("test-source".into()),
            kernel_pid: Some("4242".to_owned()),
        };
        persist_nbd_record(&record_path, &record).unwrap();

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
    fn ambiguous_nbd_attach_failure_keeps_durable_retry_authority() {
        let dir = tempfile::tempdir().unwrap();
        let record_path = nbd_record_path(dir.path(), 0);
        let device = PathBuf::from("/dev/nbd7");

        let error = attach_nbd_at(
            dir.path(),
            0,
            false,
            device.clone(),
            "test-source",
            |_| Ok(vec!["attach".to_owned()]),
            |_| {
                let claimed = read_nbd_record(&record_path).unwrap();
                assert_eq!(claimed.device, device);
                assert_eq!(claimed.source.as_deref(), Some("test-source"));
                assert_eq!(claimed.kernel_pid, None);
                Err(anyhow::anyhow!("injected ambiguous attach error"))
            },
            |_| Some("4242".to_owned()),
        )
        .unwrap_err();
        assert!(error.to_string().contains("attaching the remote volume"));

        let attached = read_nbd_record(&record_path).unwrap();
        assert_eq!(attached.kernel_pid.as_deref(), Some("4242"));
        cleanup_remote_blocks_with(
            dir.path(),
            |_| Some("4242".to_owned()),
            |_| Err(anyhow::anyhow!("injected detach failure")),
        );
        assert!(record_path.exists());
        cleanup_remote_blocks_with(dir.path(), |_| Some("4242".to_owned()), |_| Ok(()));
        assert!(!record_path.exists());
        assert!(!durable::backup_path(&record_path).exists());
    }

    #[test]
    fn pre_attach_intent_converges_without_detaching_an_unused_device() {
        let dir = tempfile::tempdir().unwrap();
        let record_path = nbd_record_path(dir.path(), 0);
        persist_nbd_record(
            &record_path,
            &NbdRecord {
                device: "/dev/nbd7".into(),
                source: None,
                kernel_pid: None,
            },
        )
        .unwrap();
        let mut detached = false;
        cleanup_remote_blocks_with(
            dir.path(),
            |_| None,
            |_| {
                detached = true;
                Ok(())
            },
        );
        assert!(!detached);
        assert!(!record_path.exists());
    }

    #[test]
    fn stale_nbd_pid_never_detaches_a_reused_device() {
        let dir = tempfile::tempdir().unwrap();
        let record_path = nbd_record_path(dir.path(), 0);
        persist_nbd_record(
            &record_path,
            &NbdRecord {
                device: "/dev/nbd7".into(),
                source: None,
                kernel_pid: Some("old-owner".to_owned()),
            },
        )
        .unwrap();
        let mut detached = false;
        cleanup_remote_blocks_with(
            dir.path(),
            |_| Some("new-owner".to_owned()),
            |_| {
                detached = true;
                Ok(())
            },
        );
        assert!(!detached);
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
    fn child_identity_is_captured_after_exec() {
        let mut child = Command::new("sleep").arg("300").spawn().unwrap();
        let proc = capture_execed_child(&mut child, Path::new("sleep")).unwrap();

        assert!(proc.check().is_ours());
        proc.signal(Signal::Kill).unwrap();
        let _ = child.wait();
    }

    #[test]
    fn api_outage_never_declares_a_proven_live_vmm_stopped_or_cleans_helpers() {
        let dir = tempfile::tempdir().unwrap();
        let mut vmm = Command::new("sleep").arg("300").spawn().unwrap();
        let vmm_proc = capture_execed_child(&mut vmm, Path::new("sleep")).unwrap();
        let mut helper = Command::new("sleep").arg("300").spawn().unwrap();
        let helper_proc = capture_execed_child(&mut helper, Path::new("sleep")).unwrap();
        durable::commit_json(&dir.path().join("virtiofs-0.proc.json"), &helper_proc).unwrap();
        std::fs::write(dir.path().join("virtiofs-0.sock"), b"socket").unwrap();
        let handle = Handle::owning(
            ID,
            vmm_proc.clone(),
            ControlChannel::HttpApi {
                path: dir.path().join(API_NAME),
            },
            GuestEndpoint::GuestAddr {
                addr: "192.0.2.1".parse().unwrap(),
            },
        );

        assert_eq!(Chv::new().state(&handle).unwrap(), RunState::Running);
        assert!(helper_proc.alive());
        assert!(dir.path().join("virtiofs-0.proc.json").exists());

        vmm_proc.signal(Signal::Kill).unwrap();
        helper_proc.signal(Signal::Kill).unwrap();
        let _ = vmm.wait();
        let _ = helper.wait();
    }

    #[test]
    fn truncated_helper_record_recovers_from_backup_before_cleanup() {
        let dir = tempfile::tempdir().unwrap();
        let record = dir.path().join("virtiofs-0.proc.json");
        let mut helper = Command::new("sleep").arg("300").spawn().unwrap();
        let proc = capture_execed_child(&mut helper, Path::new("sleep")).unwrap();
        durable::commit_json(&record, &proc).unwrap();
        durable::commit_json(&record, &proc).unwrap();
        std::fs::write(&record, b"{torn").unwrap();

        assert!(cleanup_fs_helpers(dir.path()));
        assert!(proc.wait_gone(Duration::from_secs(1)));
        assert!(!record.exists());
        assert!(!durable::backup_path(&record).exists());
        let _ = helper.wait();
    }

    #[test]
    fn unreadable_helper_authority_is_retained_and_blocks_replacement() {
        let dir = tempfile::tempdir().unwrap();
        let record = dir.path().join("virtiofs-0.proc.json");
        std::fs::write(&record, b"{torn").unwrap();

        assert!(!cleanup_fs_helpers(dir.path()));
        assert!(record.exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn start_intent_finds_the_exact_unrecorded_vmm() {
        let dir = tempfile::tempdir().unwrap();
        let api = dir.path().join(API_NAME);
        let mut child = Command::new("sh")
            .args(["-c", "while :; do sleep 1; done", "sh"])
            .arg(&api)
            .spawn()
            .unwrap();
        let shell = PathBuf::from("sh");
        let intent = StartIntent {
            version: 1,
            operation: StartOperation::Boot,
            source: None,
            helper: shell,
            api,
            started_at: asterism_core::instance::now_unix(),
        };

        let proc = scan_start_intent(&intent).unwrap().unwrap();
        assert_eq!(proc.pid, child.id());
        proc.signal(Signal::Kill).unwrap();
        let _ = child.wait();
    }

    #[test]
    fn start_intents_distinguish_boot_restore_and_migration_receivers() {
        let legacy: StartIntent = serde_json::from_str(
            r#"{"version":1,"helper":"/bin/cloud-hypervisor","api":"/tmp/api.sock","started_at":1}"#,
        )
        .unwrap();
        assert_eq!(legacy.operation, StartOperation::Boot);
        assert_eq!(legacy.source, None);

        for operation in [
            StartOperation::Boot,
            StartOperation::Restore,
            StartOperation::MigrationReceive,
        ] {
            let intent = StartIntent {
                version: 1,
                operation,
                source: (operation != StartOperation::Boot).then(|| "exact-source".into()),
                helper: "/bin/cloud-hypervisor".into(),
                api: "/tmp/api.sock".into(),
                started_at: 1,
            };
            let round_trip: StartIntent =
                serde_json::from_slice(&serde_json::to_vec(&intent).unwrap()).unwrap();
            assert_eq!(round_trip.operation, operation);
            assert_eq!(round_trip.source, intent.source);
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn migration_retry_recovers_its_exact_receiver_and_refuses_cross_operation_adoption() {
        let dir = tempfile::tempdir().unwrap();
        let api = dir.path().join(API_NAME);
        let mut child = Command::new("sh")
            .args(["-c", "while :; do sleep 1; done", "sh"])
            .arg(&api)
            .spawn()
            .unwrap();
        let instance = asterism_core::instance::Instance::new(
            "migration-recovery",
            "device",
            "test:raw",
            asterism_core::instance::Shape::default(),
            asterism_core::hv::Machine {
                backend: ID.into(),
                machine_type: "cloud-hypervisor".into(),
                cpu: "host".into(),
                hv_version: VERSION.into(),
            },
        );
        let request = BootReq {
            instance: &instance,
            dir: dir.path().to_owned(),
            base: ImageRef {
                name: "test:raw".into(),
                path: dir.path().join("base.raw"),
                format: DiskFormat::Raw,
                kind: ImageKind::Disk,
            },
            seed: dir.path().join("seed.iso"),
            shares: Vec::new(),
            egress: Default::default(),
            bootstrap: Default::default(),
            extra_disks: Vec::new(),
            console: dir.path().join("console.log"),
        };
        durable::commit_json(
            &dir.path().join(START_INTENT_NAME),
            &StartIntent {
                version: 1,
                operation: StartOperation::MigrationReceive,
                source: Some("unix:/run/source.sock".into()),
                helper: "sh".into(),
                api,
                started_at: asterism_core::instance::now_unix(),
            },
        )
        .unwrap();

        let recovered = recover_interrupted_process(
            &request,
            StartOperation::MigrationReceive,
            Some("unix:/run/source.sock"),
        )
        .unwrap()
        .unwrap();
        assert_eq!(recovered.pid, child.id());
        let error = recover_interrupted_process(&request, StartOperation::Boot, None)
            .unwrap_err()
            .to_string();
        assert!(error.contains("MigrationReceive"), "{error}");
        let error = recover_interrupted_process(
            &request,
            StartOperation::MigrationReceive,
            Some("unix:/run/different.sock"),
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("different.sock"), "{error}");
        assert!(
            recovered.alive(),
            "the refused retry did not retire authority"
        );

        recovered.signal(Signal::Kill).unwrap();
        let _ = child.wait();
    }

    #[test]
    fn failed_boot_cleanup_terminates_started_virtiofsd_before_removing_its_record() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("virtiofs-0.sock");
        let record = dir.path().join("virtiofs-0.proc.json");
        // Use the final executable directly. Capturing a shell while it is
        // still execing a script can deliberately turn the later identity
        // into `Foreign`, which tests the refusal seam rather than helper
        // cleanup and leaves Child::wait with a live fixture.
        let mut child = Command::new("sleep").arg("300").spawn().unwrap();
        let proc = ProcId::capture(child.id()).unwrap();
        std::fs::write(&socket, b"stale").unwrap();
        std::fs::write(&record, serde_json::to_vec(&proc).unwrap()).unwrap();

        cleanup_fs_helpers(dir.path());

        let gone = proc.wait_gone(Duration::from_secs(1));
        if !gone {
            // Keep a failing assertion from leaking the fixture or blocking
            // forever in wait(); the product cleanup remains the thing under
            // test, so this fallback does not turn a failure into a pass.
            let _ = child.kill();
        }
        let _ = child.wait();
        assert!(gone);
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

        assert!(record_helper(&mut child, Path::new("sh"), &record).is_err());
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
    fn migration_state_is_read_from_vm_info_and_never_guessed() {
        assert_eq!(
            vm_state_from_body(br#"{"state":"Created","config":{}}"#).unwrap(),
            "Created"
        );
        assert!(vm_state_from_body(br#"{"config":{}}"#)
            .unwrap_err()
            .to_string()
            .contains("omitted"));
        assert!(vm_state_from_body(b"not-json")
            .unwrap_err()
            .to_string()
            .contains("invalid JSON"));
    }

    #[test]
    fn snapshot_remote_devices_round_trip_and_old_snapshots_fail_closed() {
        let dir = tempfile::tempdir().unwrap();
        let snapshot = dir.path().join("snap");
        std::fs::create_dir(&snapshot).unwrap();
        let disks = [DiskSpec::NbdUnix {
            socket: "/run/asterism/volume.sock".into(),
            export: "tank-e7".into(),
            readonly: false,
        }];

        let error = load_snapshot_resources(&snapshot, &disks, &[], dir.path())
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("predates durable external-resource mapping"),
            "{error}"
        );

        let mut resources = SnapshotResources {
            version: 1,
            ..SnapshotResources::default()
        };
        resources.nbd_devices.insert(
            0,
            NbdResource {
                device: "/dev/nbd7".into(),
                source: remote_disk_identity(&disks[0]).unwrap(),
            },
        );
        durable::commit_json(&snapshot.join(SNAPSHOT_RESOURCES_NAME), &resources).unwrap();
        let loaded = load_snapshot_resources(&snapshot, &disks, &[], dir.path()).unwrap();
        assert_eq!(
            loaded.nbd_devices.get(&0).map(|resource| &resource.device),
            Some(&PathBuf::from("/dev/nbd7"))
        );
        let substituted = [DiskSpec::NbdUnix {
            socket: "/run/asterism/volume.sock".into(),
            export: "different-e8".into(),
            readonly: false,
        }];
        let error = load_snapshot_resources(&snapshot, &substituted, &[], dir.path())
            .unwrap_err()
            .to_string();
        assert!(error.contains("different export"), "{error}");
        let shares = [asterism_core::seed::Share {
            host_path: "/srv/source".into(),
            guest_path: "/mnt/source".into(),
            tag: "ast-source".into(),
            label: "device:/srv/source".into(),
        }];
        let error = load_snapshot_resources(&snapshot, &disks, &shares, dir.path())
            .unwrap_err()
            .to_string();
        assert!(error.contains("virtiofs endpoints"), "{error}");

        resources.virtiofs.insert(
            0,
            VirtiofsResource {
                socket: dir.path().join("virtiofs-0.sock"),
                tag: shares[0].tag.clone(),
                host_path: shares[0].host_path.clone(),
            },
        );
        durable::commit_json(&snapshot.join(SNAPSHOT_RESOURCES_NAME), &resources).unwrap();
        load_snapshot_resources(&snapshot, &disks, &shares, dir.path()).unwrap();

        let mut changed = shares[0].clone();
        changed.host_path = "/srv/substituted".into();
        let error = load_snapshot_resources(&snapshot, &disks, &[changed], dir.path())
            .unwrap_err()
            .to_string();
        assert!(error.contains("source directories"), "{error}");
    }

    #[test]
    fn migration_nbd_placement_is_stable_and_nonpreferred_owners_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let instance = dir.path().join("stable-instance");
        std::fs::create_dir(&instance).unwrap();
        let preferred = preferred_nbd_device(&instance, 0);
        assert_eq!(preferred, preferred_nbd_device(&instance, 0));

        persist_nbd_record(
            &nbd_record_path(&instance, 0),
            &NbdRecord {
                device: "/dev/nbd63".into(),
                source: Some("test-source".into()),
                kernel_pid: Some("4242".into()),
            },
        )
        .unwrap();
        if preferred != PathBuf::from("/dev/nbd63") {
            let error = ensure_migration_resources_portable(&instance)
                .unwrap_err()
                .to_string();
            assert!(
                error.contains("migration requires deterministic"),
                "{error}"
            );
        }
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
