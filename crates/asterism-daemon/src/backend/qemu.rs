//! The QEMU backend.
//!
//! Everything QEMU-specific lives behind [`Hypervisor`]: tool discovery,
//! EDK2 firmware, the argv, and QMP. Nothing outside this backend names a
//! QEMU concept. QMP is the one piece with a file of its own ([`super::qmp`]):
//! it holds a connection and a thread per running guest, which is state, and
//! this backend is stateless by design.
//!
//! Per-instance files, in `~/.asterism/instances/<name>/`:
//!   disk.raw     — `clonefile(2)` clone of the raw base image
//!   snapshots/   — clones of that disk, one file per snapshot
//!   efi-vars.fd  — UEFI variable store
//!   qemu.pid     — written by `qemu -daemonize`
//!   qmp.sock     — the control channel recorded on the Handle
//!
//! (`seed.iso` and `console.log` are named by the caller; see
//! `asterism_core::seed`.)
//!
//! The disk used to be a qcow2 overlay on the base image, carrying its
//! snapshots inside it. Raw plus filesystem-level copy-on-write buys the
//! same thing (BACKENDS.md §4) and is the only thing
//! Virtualization.framework will ever be able to boot, so QEMU gets there
//! first and exercises it. Instances that already have a `disk.qcow2` keep
//! it, and keep qcow2 internal snapshots with it: a disk in use is not
//! something to rewrite under its owner.
//!
//! Two ways into a guest, decided by what the image is. A cloud image is a
//! whole disk, so EDK2 goes in front of it and finds the bootloader. An OCI
//! image is a root filesystem with no bootloader at all (MODEL.md: container
//! images are an image *source*), so it gets `-kernel/-initrd/-append`
//! instead — no pflash, no variable store, and no cloud-init seed either,
//! because there is nothing in the image that would read one. Everything
//! after that point is identical: the same clone of the same raw base, the
//! same snapshots, the same QMP socket, the same shutdown.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;
use std::time::Duration;

use anyhow::{bail, Context, Result};

use asterism_core::hv::{
    BootReq, Caps, ControlChannel, DirectKernel, DiskFormat, DiskSpec, Firmware, GuestEndpoint,
    Handle, Hypervisor, ImageKind, Prepared, Ready, RunState, ShareKind, SnapshotId,
};
use asterism_core::instance::{now_unix, PortForward};
use asterism_core::snapshot::{self, Snapshot};
use asterism_core::tools::{output, run, tool};
use asterism_core::{cow, image, oci, paths};

use super::{alive, grow, qmp, signal, wait_gone};

pub const ID: &str = "qemu";

#[derive(Default)]
pub struct Qemu {
    probed: OnceLock<Probe>,
}

/// The facts about this host's QEMU that every other method needs, worked
/// out once. `probe()` is called on the `ast create` path, so it stays
/// cheap: three subprocess runs, cached for the life of the daemon.
struct Probe {
    system: PathBuf,
    img: PathBuf,
    firmware: PathBuf,
    version: String,
    /// virtio-9p is a build-time option, and some builds ship without it.
    virtfs: bool,
}

impl Qemu {
    pub fn new() -> Self {
        Self::default()
    }

    /// Cached probe, or the reason this host cannot run QEMU.
    ///
    /// `OnceLock` cannot cache a failure, which is the behaviour we want:
    /// installing qemu should fix a running daemon without a restart.
    fn probed(&self) -> Result<&Probe> {
        if let Some(p) = self.probed.get() {
            return Ok(p);
        }
        let probe = Probe::run()?;
        Ok(self.probed.get_or_init(|| probe))
    }

    /// Materialise an instance's root disk for the first time.
    ///
    /// A raw base is cloned: on APFS `clonefile(2)` shares every block with
    /// the image until the guest writes, which is what a qcow2 backing file
    /// bought us, at the same cost and with better read performance
    /// (BACKENDS.md §4). A qcow2 base cannot be cloned into something QEMU
    /// would boot as raw, so it keeps the overlay — that is the path a
    /// user's own `--image ./mine.qcow2` takes.
    fn create_root(&self, req: &BootReq, raw: &Path, legacy: &Path) -> Result<DiskSpec> {
        let base = &req.base;
        if !base.path.exists() {
            bail!("image {} is not pulled yet — run: ast pull {}", base.name, base.name);
        }
        let gib = u64::from(req.instance.shape.disk_gib);
        match base.format {
            DiskFormat::Raw => {
                let how = cow::clone_file(&base.path, raw)
                    .with_context(|| format!("making {}'s disk", req.instance.name))?;
                if let Some(warning) = how.warning(&base.path, raw) {
                    eprintln!("astd: {warning}");
                }
                if let Err(e) = grow(raw, gib) {
                    // Half a disk is worse than none: the next `up` would
                    // boot an instance that is not the size it was asked for.
                    let _ = std::fs::remove_file(raw);
                    return Err(e);
                }
                Ok(DiskSpec::File {
                    path: raw.to_owned(),
                    format: DiskFormat::Raw,
                    readonly: false,
                })
            }
            DiskFormat::Qcow2 => {
                run(Command::new(&self.probed()?.img)
                    .args(["create", "-f", "qcow2", "-F", "qcow2", "-b"])
                    .arg(&base.path)
                    .arg(legacy)
                    .arg(format!("{gib}G")))?;
                Ok(DiskSpec::File {
                    path: legacy.to_owned(),
                    format: DiskFormat::Qcow2,
                    readonly: false,
                })
            }
            DiskFormat::Asif => bail!(
                "{} is an ASIF image, which qemu cannot read — it is a \
                 Virtualization.framework format (macOS 26+)",
                base.name
            ),
        }
    }
}

impl Probe {
    fn run() -> Result<Self> {
        let system = tool(&format!("qemu-system-{}", image::host_arch()))?;
        let img = tool("qemu-img")?;
        let firmware = firmware_path(&system)?;
        let version = parse_version(&output(Command::new(&system).arg("--version"))?)
            .unwrap_or_else(|| "unknown".to_owned());
        let virtfs = supports_virtfs(&system);
        Ok(Probe { system, img, firmware, version, virtfs })
    }

    /// Machine type is per-arch: "virt" exists only on aarch64; x86 wants q35.
    fn machine_type(&self) -> &'static str {
        match image::host_arch() {
            "aarch64" => "virt,highmem=on",
            _ => "q35",
        }
    }

    fn accel(&self) -> &'static str {
        if cfg!(target_os = "macos") {
            "hvf"
        } else {
            "kvm"
        }
    }

    fn ready(&self) -> Ready {
        Ready {
            version: self.version.clone(),
            accel: self.accel().to_owned(),
            machine_type: self.machine_type().to_owned(),
            cpu: CPU_MODEL.to_owned(),
        }
    }
}

/// `-cpu host` passes the host's own CPU through. Named as data because it
/// is recorded on the instance, and because it is the first thing that has
/// to change for a foreign-arch guest.
const CPU_MODEL: &str = "host";

impl Hypervisor for Qemu {
    fn id(&self) -> &'static str {
        ID
    }

    fn probe(&self) -> Result<Ready> {
        Ok(self.probed()?.ready())
    }

    fn caps(&self) -> Caps {
        // 9p support is asked of the binary in front of us rather than
        // assumed, so an unsupported build refuses volumes with an
        // explanation instead of a raw QEMU error. An unprobeable host
        // reports no sharing; `up` will fail on the missing tool anyway.
        let shared_dir = match self.probed() {
            Ok(p) if p.virtfs => Some(ShareKind::NinePfs),
            _ => None,
        };
        Caps {
            // qemu-img snapshots are disk-only; `savevm` over QMP would be
            // the live one and is not wired up.
            live_snapshot: false,
            disk_snapshot: true,
            // QEMU can live-migrate, but this backend does not implement
            // migrate_out/in yet, and Caps describes what is offered.
            live_migration: false,
            disk_hotplug: false,
            shared_dir,
            nbd_disks: true,
            // TCG could, but never with -cpu host and -accel hvf.
            foreign_arch: false,
            // `-kernel/-initrd/-append`, which is how an OCI rootfs boots:
            // it has no bootloader for the firmware to find.
            direct_kernel: true,
            // User-mode networking, so every guest port that is reachable
            // at all is reachable as a hostfwd on this device's loopback.
            port_forward: true,
            // Raw first: it is what new instances get, and what a VZ host
            // would be able to boot. qcow2 stays readable for the instances
            // and the hand-supplied images that are already in it.
            disk_formats: &[DiskFormat::Raw, DiskFormat::Qcow2],
        }
    }

    /// Idempotent, and the disk it settles on is the disk every other
    /// operation uses: boot and the snapshot commands both come through
    /// here, so an instance that has never booted still has a well-defined
    /// disk and can be snapshotted in its pristine state.
    fn prepare(&self, req: &BootReq) -> Result<Prepared> {
        // Deliberately not probed up front: making a raw disk and taking a
        // snapshot of it need no qemu at all, and only the firmware half of
        // this function does. `boot` probes, which is where it matters.
        std::fs::create_dir_all(&req.dir)?;

        let raw = req.dir.join("disk.raw");
        let legacy = req.dir.join("disk.qcow2");
        let root = if raw.exists() {
            DiskSpec::File { path: raw, format: DiskFormat::Raw, readonly: false }
        } else if legacy.exists() {
            DiskSpec::File { path: legacy, format: DiskFormat::Qcow2, readonly: false }
        } else {
            self.create_root(req, &raw, &legacy)?
        };

        // An OCI rootfs is a filesystem, not a disk: no partition table, no
        // ESP, nothing for EDK2 to find. It boots a kernel instead of
        // firmware — the two are alternatives, so this instance gets no
        // pflash and no variable store at all.
        if req.base.kind == ImageKind::OciRootfs {
            let (kernel, initrd) = oci::kernel()?;
            return Ok(Prepared {
                root,
                firmware: None,
                kernel: Some(DirectKernel { kernel, initrd: Some(initrd), cmdline: cmdline() }),
            });
        }

        let vars = req.dir.join("efi-vars.fd");
        if !vars.exists() {
            // AArch64 EDK2 wants a 64 MiB variable store matching the code flash.
            std::fs::write(&vars, vec![0u8; 64 * 1024 * 1024])?;
        }

        Ok(Prepared {
            root,
            firmware: Some(Firmware { code: self.probed()?.firmware.clone(), vars }),
            kernel: None,
        })
    }

    fn boot(&self, req: &BootReq, prep: &Prepared) -> Result<Handle> {
        let p = self.probed()?;
        let inst = req.instance;

        for share in &req.shares {
            if !Path::new(&share.host_path).is_dir() {
                bail!(
                    "volume {} is not a directory on this device — \
                     the guest cannot mount what is not there",
                    share.host_path
                );
            }
        }
        if !req.shares.is_empty() && !p.virtfs {
            bail!(
                "{} was built without virtio-9p, so volumes cannot reach the guest — \
                 detach them or install a qemu with 9p support",
                p.system.display()
            );
        }
        if prep.kernel.is_none() && !req.seed.exists() {
            bail!("no cloud-init seed at {}", req.seed.display());
        }

        let ssh_port = free_port()?;
        let pidfile = req.dir.join("qemu.pid");
        let _ = std::fs::remove_file(&pidfile);
        let qmp = paths::qmp_socket_path(&inst.name);
        // A guest that died leaves its socket path behind and the next one
        // binds it. Any connection still held to the old one belongs to a
        // process that is gone.
        qmp::forget(&qmp);

        let mut cmd = Command::new(&p.system);
        cmd.arg("-machine").arg(p.machine_type())
            .arg("-accel").arg(p.accel())
            .arg("-cpu").arg(CPU_MODEL)
            .arg("-smp").arg(inst.shape.cpus.to_string())
            .arg("-m").arg(format!("{}M", inst.shape.mem_mib));

        // Firmware or a kernel, never both: a machine either finds a
        // bootloader on its disk or is handed the kernel to start. Disks are
        // emitted below as explicit nodes either way.
        match &prep.kernel {
            Some(direct) => {
                cmd.arg("-kernel").arg(&direct.kernel);
                if let Some(initrd) = &direct.initrd {
                    cmd.arg("-initrd").arg(initrd);
                }
                cmd.arg("-append").arg(&direct.cmdline);
            }
            None => {
                let firmware = prep
                    .firmware
                    .as_ref()
                    .context("the qemu backend needs firmware, and prepare() produced none")?;
                cmd.arg("-drive").arg(format!(
                    "if=pflash,format=raw,readonly=on,file={}",
                    firmware.code.display()
                ))
                .arg("-drive")
                .arg(format!("if=pflash,format=raw,file={}", firmware.vars.display()));
            }
        }

        // Every disk is given as an explicit node plus an explicit device, in
        // the order the guest should see them: the root is /dev/vda, attached
        // volumes are /dev/vdb onwards in attach order, and the cloud-init
        // ISO — which nothing ever addresses by name — takes the last slot.
        //
        // `-drive if=virtio` would be shorter, and it is what this used to
        // say, but QEMU turns those into devices *after* every explicit
        // `-device`, so one attached volume was enough to make the root disk
        // /dev/vdb. Device names a user can predict are worth four arguments.
        for arg in disk_args(&prep.root, ROOT_NODE)? {
            cmd.arg(arg);
        }
        for (index, disk) in req.extra_disks.iter().enumerate() {
            for arg in disk_args(disk, &format!("astvol{index}"))? {
                cmd.arg(arg);
            }
        }
        if prep.kernel.is_none() {
            for arg in disk_args(
                &DiskSpec::File {
                    path: req.seed.clone(),
                    format: DiskFormat::Raw,
                    readonly: true,
                },
                SEED_NODE,
            )? {
                cmd.arg(arg);
            }
        }

        cmd.arg("-netdev").arg(netdev_arg(ssh_port, &inst.publish))
            .arg("-device").arg("virtio-net-pci,netdev=n0")
            .arg("-device").arg("virtio-rng-pci")
            .arg("-qmp").arg(format!("unix:{},server,nowait", qmp.display()))
            .arg("-display").arg("none")
            .arg("-serial").arg(format!("file:{}", req.console.display()))
            .arg("-daemonize")
            .arg("-pidfile").arg(&pidfile);

        for share in &req.shares {
            // mapped-xattr keeps guest ownership and permissions in host
            // xattrs, so a guest chown never has to become a host chown
            // (which would need root). Files the host already had keep
            // their real ids, since they simply carry no such xattr.
            cmd.arg("-virtfs").arg(format!(
                "local,path={},mount_tag={},security_model=mapped-xattr",
                qemu_escape(&share.host_path),
                share.tag,
            ));
        }

        run(&mut cmd).context("starting qemu")?;

        let pid: u32 = std::fs::read_to_string(&pidfile)
            .context("qemu did not write its pidfile")?
            .trim()
            .parse()
            .context("unparseable qemu pidfile")?;

        Ok(Handle {
            backend: ID.to_owned(),
            pid: Some(pid),
            ctl: ControlChannel::Qmp { path: qmp },
            endpoint: GuestEndpoint::HostForward { ssh_port },
            started_at: now_unix(),
        })
    }

    /// Ask the guest to power down cleanly via QMP (ACPI power button); a
    /// killed QEMU is a yanked power cord — the overlay needs journal
    /// recovery on the next boot and recent guest writes are lost. Only if
    /// the guest ignores the request do we escalate to SIGTERM/SIGKILL.
    ///
    /// The QMP socket comes off the handle. It used to be rebuilt from the
    /// instance name, which quietly made "the control channel" a naming
    /// convention every future backend would have had to honour.
    fn stop(&self, h: &Handle, deadline: Duration) -> Result<()> {
        let Some(pid) = h.pid else {
            bail!("handle for a {} guest carries no pid", h.backend);
        };
        // Most of the budget goes to the guest; the rest to SIGTERM before
        // SIGKILL. At the default 40s that is the historical 30s then 10s.
        let graceful = deadline.mul_f32(0.75);
        if powerdown(h.ctl.path()).is_ok() && wait_gone(pid, graceful) {
            return Ok(());
        }
        signal(pid, "-TERM")?;
        if wait_gone(pid, deadline - graceful) {
            return Ok(());
        }
        signal(pid, "-KILL")?;
        Ok(())
    }

    fn kill(&self, h: &Handle) -> Result<()> {
        let Some(pid) = h.pid else {
            bail!("handle for a {} guest carries no pid", h.backend);
        };
        qmp::forget(h.ctl.path());
        signal(pid, "-KILL")
    }

    fn state(&self, h: &Handle) -> Result<RunState> {
        Ok(match h.pid.map(alive).unwrap_or(false) {
            true => RunState::Running,
            false => RunState::Stopped,
        })
    }

    // ---- disk snapshots ----------------------------------------------------
    //
    // A snapshot is a clone of the root disk, kept in the instance's own
    // directory (`asterism_core::snapshot`). Taking and restoring one needs
    // a stopped instance (the daemon enforces that): the guest's in-flight
    // writes would otherwise land in the middle of the copy, or on top of
    // the result. Listing only reads, so it stays available while the guest
    // runs.
    //
    // A legacy `disk.qcow2` instance keeps qcow2 *internal* snapshots — the
    // ones it already has are in there, and they must go on working.

    fn disk_snapshot(&self, prep: &Prepared, tag: &str) -> Result<SnapshotId> {
        snapshot::validate_tag(tag)?;
        let disk = prep.root_path()?;
        if !is_legacy_qcow2(prep) {
            return snapshot::take(instance_dir(disk)?, disk, tag);
        }
        // qemu-img will happily record a second snapshot under a tag it
        // already has, leaving `ast restore` to pick between them. Refuse.
        if self.disk_snapshot_list(prep)?.iter().any(|s| s.tag == tag) {
            bail!("snapshot {tag:?} already exists");
        }
        run(Command::new(&self.probed()?.img)
            .args(["snapshot", "-c", tag])
            .arg(disk))?;
        Ok(SnapshotId(tag.to_owned()))
    }

    fn disk_snapshot_list(&self, prep: &Prepared) -> Result<Vec<Snapshot>> {
        let disk = prep.root_path()?;
        if !is_legacy_qcow2(prep) {
            return snapshot::list(instance_dir(disk)?);
        }
        // -U: don't take the image lock. A running guest holds it, and this
        // only ever reads the qcow2 snapshot table.
        let table = output(
            Command::new(&self.probed()?.img)
                .args(["snapshot", "-U", "-l"])
                .arg(disk),
        )?;
        Ok(snapshot::parse_list(&table))
    }

    fn disk_restore(&self, prep: &Prepared, snap: &SnapshotId) -> Result<()> {
        let tag = &snap.0;
        snapshot::validate_tag(tag)?;
        let disk = prep.root_path()?;
        if !is_legacy_qcow2(prep) {
            return snapshot::restore(instance_dir(disk)?, disk, tag);
        }
        // qemu-img's own miss reads "Failed to load snapshot: No such file or
        // directory", which sends people looking for a missing file.
        if !self.disk_snapshot_list(prep)?.iter().any(|s| &s.tag == tag) {
            bail!("no snapshot {tag:?}");
        }
        run(Command::new(&self.probed()?.img)
            .args(["snapshot", "-a", tag])
            .arg(disk))
    }

    fn disk_snapshot_remove(&self, prep: &Prepared, snap: &SnapshotId) -> Result<()> {
        let tag = &snap.0;
        snapshot::validate_tag(tag)?;
        let disk = prep.root_path()?;
        if !is_legacy_qcow2(prep) {
            return snapshot::remove(instance_dir(disk)?, tag);
        }
        // The same miss the restore path guards: `qemu-img snapshot -d` on a
        // tag that is not there reports a missing file, which sends people
        // looking for one.
        if !self.disk_snapshot_list(prep)?.iter().any(|s| &s.tag == tag) {
            bail!("no snapshot {tag:?}");
        }
        run(Command::new(&self.probed()?.img)
            .args(["snapshot", "-d", tag])
            .arg(disk))
    }
}

// ---- disks -----------------------------------------------------------------

/// Is this one of the instances whose root is still a qcow2 overlay?
/// Snapshots are the one place the two disk layouts genuinely differ, so
/// this is the only thing that branches on it.
fn is_legacy_qcow2(prep: &Prepared) -> bool {
    matches!(prep.root, DiskSpec::File { format: DiskFormat::Qcow2, .. })
}

/// The instance directory a root disk sits in — where its snapshots go.
fn instance_dir(disk: &Path) -> Result<&Path> {
    disk.parent()
        .with_context(|| format!("{} has no directory to keep snapshots in", disk.display()))
}

// ---- argv helpers ----------------------------------------------------------

/// The arguments for one disk: a node, and the virtio device in front of it.
///
/// `id` is both the block node's name and the drive the device points at, so
/// it has to be a QEMU identifier — letters, digits, dash, underscore — and
/// not, say, a volume's name off the wire.
fn disk_args(disk: &DiskSpec, id: &str) -> Result<Vec<String>> {
    let node = match disk {
        DiskSpec::File { path, format, readonly } => format!(
            "if=none,id={id},format={},{}file={}",
            format.as_str(),
            if *readonly { "readonly=on," } else { "" },
            qemu_escape(&path.display().to_string()),
        ),
        DiskSpec::Block { path, readonly } => format!(
            "if=none,id={id},format=raw,{}file={}",
            if *readonly { "readonly=on," } else { "" },
            qemu_escape(&path.display().to_string()),
        ),
        DiskSpec::Nbd { url, readonly } => format!(
            "if=none,id={id},{}file={}",
            if *readonly { "readonly=on," } else { "" },
            qemu_escape(url),
        ),
        // A block volume needs `-blockdev` rather than `-drive`: the two
        // options that make a remote disk survive a network blip —
        // `reconnect-delay` and `open-timeout` — are properties of the nbd
        // node, and `-drive` has no way to express them.
        DiskSpec::NbdUnix { socket, export, readonly } => {
            return Ok(vec![
                "-blockdev".to_owned(),
                format!(
                    "nbd,node-name={id},server.type=unix,server.path={},export={},\
                     {}reconnect-delay={},open-timeout={}",
                    qemu_escape(&socket.display().to_string()),
                    qemu_escape(export),
                    if *readonly { "read-only=on," } else { "" },
                    RECONNECT_DELAY_SECS,
                    OPEN_TIMEOUT_SECS,
                ),
                "-device".to_owned(),
                format!("virtio-blk-pci,drive={id}"),
            ])
        }
    };
    Ok(vec![
        "-drive".to_owned(),
        node,
        "-device".to_owned(),
        format!("virtio-blk-pci,drive={id}"),
    ])
}

/// Node names for the two disks every instance has. Attached volumes take
/// `astvol0`, `astvol1`, ... in the order they were attached.
const ROOT_NODE: &str = "astroot";
const SEED_NODE: &str = "astseed";

/// How long QEMU keeps retrying a dropped NBD connection before it starts
/// failing the guest's I/O.
///
/// Networks blip, and the difference between a blip and a disaster is what
/// the guest sees: a stall it rides out, or an I/O error that remounts a
/// filesystem read-only and needs a reboot to undo. A minute buys the daemon
/// on the other end time to be restarted, or the mesh time to find a new path
/// (docs/ROADMAP.md Phase 3, "Reconnection").
const RECONNECT_DELAY_SECS: u32 = 60;

/// How long the *first* connection may take. The lease has already been
/// granted and the bridge already bound by the time QEMU starts, so this is
/// slack for a slow first dial rather than a wait for anything to be set up.
const OPEN_TIMEOUT_SECS: u32 = 30;

/// QEMU's option parser splits on commas; a literal one is written twice.
fn qemu_escape(value: &str) -> String {
    value.replace(',', ",,")
}

// ---- user-mode networking --------------------------------------------------
//
// QEMU's user-net is a NAT with a fixed, documented layout: the guest is
// 10.0.2.15, the gateway is 10.0.2.2 and the DNS proxy is 10.0.2.3. A cloud
// image learns all three by DHCP. An OCI image has no DHCP client — it has
// whatever the image shipped, which is usually nothing — so the numbers are
// written on the kernel cmdline for the generated init to apply. They are
// spelled out here rather than in the image because they are a fact about
// the machine this backend builds, and the image is shared between instances.

const GUEST_IP: &str = "10.0.2.15/24";
const GUEST_GATEWAY: &str = "10.0.2.2";
const GUEST_DNS: &str = "10.0.2.3";

/// The kernel cmdline for a guest booted from an OCI rootfs.
///
/// `root=/dev/vda` because the image *is* the filesystem: it has no partition
/// table to look inside. `net.ifnames=0` keeps the interface called `eth0`,
/// which is what container images expect to find. `panic=10` means a guest
/// that cannot boot reboots instead of sitting there, and `ast logs` has the
/// reason either way.
fn cmdline() -> String {
    // The serial device is per-architecture, and it has to be right: it is
    // where the kernel talks, where the image's stdout goes, and what
    // `ast logs` reads.
    let console = match image::host_arch() {
        "aarch64" => "ttyAMA0",
        _ => "ttyS0",
    };
    format!(
        "root=/dev/vda rw console={console} net.ifnames=0 panic=10 \
         init={init} asterism.ip={GUEST_IP} asterism.gw={GUEST_GATEWAY} \
         asterism.dns={GUEST_DNS} asterism.time={now}",
        init = oci::INIT_PATH,
        // The guest has no RTC driver loaded this early and no network time;
        // this host knows what time it is, and it is the one booting it.
        now = now_unix(),
    )
}

/// The user-net device, with ssh and everything `ast create -p` published.
///
/// Both are the same mechanism — a loopback port on this device forwarded
/// into the guest — which is the point: an OCI instance's port is reached
/// exactly where its ssh would have been, so nothing else in Asterism has to
/// learn a second way in.
fn netdev_arg(ssh_port: u16, publish: &[PortForward]) -> String {
    let mut arg = format!("user,id=n0,hostfwd=tcp:127.0.0.1:{ssh_port}-:22");
    for p in publish {
        arg.push_str(&format!(",hostfwd=tcp:127.0.0.1:{}-:{}", p.host, p.guest));
    }
    arg
}

// ---- QMP -------------------------------------------------------------------

/// Press the guest's ACPI power button.
///
/// The command returns as soon as QEMU has pressed it; whether the guest
/// acts on it is what [`wait_gone`] is for. The connection stays open
/// behind this, so the `SHUTDOWN` that follows lands on a reader rather
/// than on a closed socket.
fn powerdown(sock: &Path) -> Result<()> {
    qmp::on(sock)?.execute("system_powerdown", serde_json::Value::Null)?;
    Ok(())
}

// ---- processes -------------------------------------------------------------
//
// `alive`, `signal` and `wait_gone` live in `backend::mod` now: every
// out-of-process backend needs the same three, and the vz helper is a
// process this daemon reasons about in exactly the same way.

fn free_port() -> Result<u16> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    Ok(listener.local_addr()?.port())
}

// ---- discovery -------------------------------------------------------------

/// EDK2 firmware ships next to the qemu binary under ../share/qemu/.
fn firmware_path(qemu: &Path) -> Result<PathBuf> {
    let file = match image::host_arch() {
        "aarch64" => "edk2-aarch64-code.fd",
        "x86_64" => "edk2-x86_64-code.fd",
        other => bail!("no firmware mapping for {other}"),
    };
    let mut candidates = vec![
        PathBuf::from("/opt/homebrew/share/qemu").join(file),
        PathBuf::from("/usr/local/share/qemu").join(file),
        PathBuf::from("/usr/share/qemu").join(file),
    ];
    if let Some(bin_dir) = qemu.parent() {
        candidates.insert(0, bin_dir.join("../share/qemu").join(file));
    }
    candidates
        .into_iter()
        .find(|p| p.exists())
        .with_context(|| format!("{file} not found near {}", qemu.display()))
}

/// 9p host support is a build-time option, and on some platforms it has
/// historically been left out. Ask the binary in front of us rather than
/// assuming.
fn supports_virtfs(qemu: &Path) -> bool {
    let Ok(out) = Command::new(qemu).args(["-device", "help"]).output() else {
        return false;
    };
    let listed = String::from_utf8_lossy(&out.stdout).into_owned()
        + &String::from_utf8_lossy(&out.stderr);
    listed.contains("virtio-9p-pci")
}

/// Pull the version out of `qemu-system-* --version`, whose first line reads
/// `QEMU emulator version 11.0.0`. Recorded on every instance, so a miss
/// must not be fatal — the caller falls back to "unknown".
fn parse_version(banner: &str) -> Option<String> {
    let line = banner.lines().next()?;
    let v = line.split_whitespace().find(|w| {
        w.starts_with(|c: char| c.is_ascii_digit()) && w.contains('.')
    })?;
    // Homebrew and distro builds suffix the version: "9.1.0(v9.1.0-mac)".
    Some(v.split(['(', '-']).next().unwrap_or(v).to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    use asterism_core::hv::ImageRef;
    use asterism_core::instance::{local_host, Instance, Shape};

    /// An instance record, without a registry file to keep it in.
    fn instance(disk_gib: u32) -> Instance {
        asterism_core::registry::Shard::load(
            &std::env::temp_dir().join("nonexistent-registry.json"),
        )
        .unwrap()
        .create(
            "disky",
            &local_host(),
            "debian:13",
            Shape { cpus: 1, mem_mib: 512, disk_gib },
            None,
        )
        .unwrap()
    }

    fn req<'a>(inst: &'a Instance, dir: &Path, base: ImageRef) -> BootReq<'a> {
        BootReq {
            instance: inst,
            dir: dir.to_owned(),
            base,
            seed: dir.join("seed.iso"),
            shares: Vec::new(),
            extra_disks: Vec::new(),
            console: dir.join("console.log"),
        }
    }

    /// A raw base image, standing in for a pulled one. Its contents only
    /// have to survive being cloned.
    fn raw_base(dir: &Path) -> ImageRef {
        let path = dir.join("debian-13.raw");
        std::fs::write(&path, vec![0xab; 64 * 1024]).unwrap();
        ImageRef { name: "debian:13".into(), path, format: DiskFormat::Raw, kind: ImageKind::Disk }
    }

    /// The Phase 1 disk: a clone of the raw base, truncated up to the
    /// instance's shape, occupying almost nothing until it is written to.
    #[test]
    fn a_raw_base_becomes_a_clone_grown_to_the_shape() {
        let home = tempfile::tempdir().unwrap();
        let inst = instance(2);
        let dir = home.path().join("instances/disky");
        std::fs::create_dir_all(&dir).unwrap();
        let base = raw_base(home.path());

        let root = Qemu::new()
            .create_root(
                &req(&inst, &dir, base),
                &dir.join("disk.raw"),
                &dir.join("disk.qcow2"),
            )
            .unwrap();
        let DiskSpec::File { path, format, .. } = &root else {
            panic!("the root disk is a file: {root:?}");
        };
        assert_eq!(*format, DiskFormat::Raw);
        assert!(path.ends_with("disk.raw"), "{path:?}");
        assert_eq!(std::fs::metadata(path).unwrap().len(), 2 << 30, "2 GiB as asked");
        assert!(
            cow::usage(path).unwrap() < 8 << 20,
            "a clone of a 64 KiB base costs nothing like 2 GiB"
        );
        // ...and it is a clone of the base, not an empty file.
        assert_eq!(std::fs::read(path).unwrap()[..4], [0xab; 4]);
    }

    /// Snapshots of a raw disk are files, need no qemu-img, and roll the
    /// disk back byte for byte.
    #[test]
    fn snapshots_of_a_raw_disk_are_clones_in_the_instance_directory() {
        let dir = tempfile::tempdir().unwrap();
        let disk = dir.path().join("disk.raw");
        std::fs::write(&disk, b"pristine").unwrap();
        let prep = Prepared {
            root: DiskSpec::File { path: disk.clone(), format: DiskFormat::Raw, readonly: false },
            firmware: None,
            kernel: None,
        };
        assert!(!is_legacy_qcow2(&prep));

        let hv = Qemu::new();
        assert!(hv.disk_snapshot_list(&prep).unwrap().is_empty());
        let id = hv.disk_snapshot(&prep, "clean").unwrap();
        assert_eq!(id.0, "clean");
        assert!(dir.path().join("snapshots/clean.raw").exists());

        let listed = hv.disk_snapshot_list(&prep).unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].tag, "clean");
        assert!(hv.disk_snapshot(&prep, "clean").is_err(), "one tag, one snapshot");

        std::fs::write(&disk, b"diverged").unwrap();
        hv.disk_restore(&prep, &id).unwrap();
        assert_eq!(std::fs::read(&disk).unwrap(), b"pristine");
        assert!(hv.disk_restore(&prep, &SnapshotId("absent".into())).is_err());
    }

    /// An instance created before raw disks keeps its overlay, and with it
    /// the qcow2 internal snapshots it already has.
    #[test]
    fn a_legacy_overlay_is_recognised_as_one() {
        let legacy = Prepared {
            root: DiskSpec::File {
                path: "/i/disky/disk.qcow2".into(),
                format: DiskFormat::Qcow2,
                readonly: false,
            },
            firmware: None,
            kernel: None,
        };
        assert!(is_legacy_qcow2(&legacy));
        assert_eq!(instance_dir(Path::new("/i/disky/disk.raw")).unwrap(), Path::new("/i/disky"));
    }

    /// An OCI rootfs gets a kernel and no firmware; a cloud image gets
    /// firmware and no kernel. They are alternatives, and `prepare` is where
    /// that is decided once for both `boot` and the snapshot commands.
    #[test]
    fn an_oci_rootfs_is_prepared_for_a_direct_kernel_boot() {
        let home = tempfile::tempdir().unwrap();
        let inst = instance(2);
        let dir = home.path().join("instances/disky");
        std::fs::create_dir_all(&dir).unwrap();
        let path = home.path().join("oci-abc.raw");
        std::fs::write(&path, vec![0xcd; 64 * 1024]).unwrap();
        let base = ImageRef {
            name: "docker.io/library/nginx:latest".into(),
            path,
            format: DiskFormat::Raw,
            kind: ImageKind::OciRootfs,
        };

        // Whether this device has fetched a guest kernel is not this test's
        // business — both answers are asserted, because both are the
        // contract: a kernel boot, or a refusal that says how to get one.
        match Qemu::new().prepare(&req(&inst, &dir, base)) {
            Ok(prep) => {
                let kernel = prep.kernel.expect("an oci rootfs boots a kernel");
                assert!(prep.firmware.is_none(), "and gets no firmware with it");
                assert!(kernel.initrd.is_some(), "the initrd carries virtio_blk and ext4");
                assert!(kernel.cmdline.contains("root=/dev/vda"));
                assert!(!dir.join("efi-vars.fd").exists(), "no variable store either");
            }
            Err(e) => {
                let e = e.to_string();
                assert!(e.contains("no kernel of its own"), "{e}");
                assert!(e.contains("ast pull"), "the way out is in the message: {e}");
            }
        }
    }

    /// The cmdline is the whole conversation with a guest that has no
    /// cloud-init: where its root is, where its console is, who its init is,
    /// and what its address is.
    #[test]
    fn the_kernel_cmdline_tells_the_guest_everything_it_cannot_discover() {
        let line = cmdline();
        assert!(line.contains("root=/dev/vda rw"), "{line}");
        assert!(line.contains("init=/sbin/asterism-init"), "{line}");
        assert!(line.contains("net.ifnames=0"), "eth0 is what images expect: {line}");
        assert!(line.contains("asterism.ip=10.0.2.15/24"), "{line}");
        assert!(line.contains("asterism.gw=10.0.2.2"), "{line}");
        assert!(line.contains("asterism.dns=10.0.2.3"), "{line}");
        assert!(line.contains("asterism.time="), "{line}");
        // One console, and the right one for this architecture.
        let console = match image::host_arch() {
            "aarch64" => "console=ttyAMA0",
            _ => "console=ttyS0",
        };
        assert_eq!(line.matches("console=").count(), 1, "{line}");
        assert!(line.contains(console), "{line}");
    }

    /// Published ports ride the same user-net as ssh, which is the point:
    /// there is one way into a guest and `-p` does not invent a second.
    #[test]
    fn published_ports_are_forwards_on_the_same_netdev_as_ssh() {
        assert_eq!(
            netdev_arg(22022, &[]),
            "user,id=n0,hostfwd=tcp:127.0.0.1:22022-:22"
        );
        assert_eq!(
            netdev_arg(
                22022,
                &[PortForward { host: 8080, guest: 80 }, PortForward { host: 5432, guest: 5432 }]
            ),
            "user,id=n0,hostfwd=tcp:127.0.0.1:22022-:22,\
             hostfwd=tcp:127.0.0.1:8080-:80,hostfwd=tcp:127.0.0.1:5432-:5432"
        );
    }

    #[test]
    fn commas_in_host_paths_survive_qemus_option_parser() {
        assert_eq!(qemu_escape("/tank/a,b"), "/tank/a,,b");
        assert_eq!(qemu_escape("/tank/media"), "/tank/media");
    }

    #[test]
    fn versions_come_off_the_banner() {
        assert_eq!(
            parse_version("QEMU emulator version 11.0.0\nCopyright (c) 2003-2026").as_deref(),
            Some("11.0.0")
        );
        assert_eq!(
            parse_version("QEMU emulator version 9.1.0(v9.1.0-mac)").as_deref(),
            Some("9.1.0")
        );
        assert_eq!(
            parse_version("qemu-img version 8.2.2\n").as_deref(),
            Some("8.2.2")
        );
        assert_eq!(parse_version(""), None);
        assert_eq!(parse_version("no version here"), None);
    }

    /// Every disk gets a node and a device, in that order — and the *order*
    /// of the devices is the guest's device names, which is why they are
    /// built as a list rather than emitted ad hoc.
    #[test]
    fn every_disk_kind_becomes_a_node_and_a_virtio_device() {
        let file = DiskSpec::File {
            path: "/i/disk.qcow2".into(),
            format: DiskFormat::Qcow2,
            readonly: false,
        };
        assert_eq!(
            disk_args(&file, ROOT_NODE).unwrap(),
            vec![
                "-drive",
                "if=none,id=astroot,format=qcow2,file=/i/disk.qcow2",
                "-device",
                "virtio-blk-pci,drive=astroot",
            ]
        );

        let ro = DiskSpec::File {
            path: "/i/seed.iso".into(),
            format: DiskFormat::Raw,
            readonly: true,
        };
        assert_eq!(
            disk_args(&ro, SEED_NODE).unwrap()[1],
            "if=none,id=astseed,format=raw,readonly=on,file=/i/seed.iso"
        );

        // A url someone runs an NBD server behind goes to QEMU's built-in
        // client, which is why Caps::nbd_disks is true.
        let nbd = DiskSpec::Nbd { url: "nbd://desktop:10809/vol".into(), readonly: false };
        assert_eq!(
            disk_args(&nbd, "astvol0").unwrap()[1],
            "if=none,id=astvol0,file=nbd://desktop:10809/vol"
        );

        let odd = DiskSpec::File {
            path: "/tank/a,b.qcow2".into(),
            format: DiskFormat::Qcow2,
            readonly: false,
        };
        assert!(disk_args(&odd, "astvol0").unwrap()[1].ends_with("file=/tank/a,,b.qcow2"));
    }

    /// A block volume arrives on a unix socket that this daemon is holding
    /// open, and it must arrive as an ordinary virtio-blk disk — the guest is
    /// not told, and has no way to find out, that the bytes are on another
    /// machine. That is the local illusion, spelled as a command line.
    #[test]
    fn a_volume_becomes_a_blockdev_node_and_a_virtio_disk() {
        let vol = DiskSpec::NbdUnix {
            socket: "/i/dev/vol-desktop-tank.sock".into(),
            export: "tank-e7".into(),
            readonly: false,
        };
        let args = disk_args(&vol, "astvol0").unwrap();
        assert_eq!(args[0], "-blockdev");
        assert_eq!(
            args[1],
            "nbd,node-name=astvol0,server.type=unix,\
             server.path=/i/dev/vol-desktop-tank.sock,export=tank-e7,\
             reconnect-delay=60,open-timeout=30"
        );
        // The guest sees a plain disk, not a network device.
        assert_eq!(args[2], "-device");
        assert_eq!(args[3], "virtio-blk-pci,drive=astvol0");
        // Nothing anywhere in it is a TCP address.
        assert!(!args.join(" ").contains("inet"), "{args:?}");

        // Two volumes get two nodes.
        let second = disk_args(&vol, "astvol1").unwrap();
        assert!(second[1].contains("node-name=astvol1"));
        assert_eq!(second[3], "virtio-blk-pci,drive=astvol1");

        // Read-only rides the node.
        let ro = DiskSpec::NbdUnix {
            socket: "/i/dev/v.sock".into(),
            export: "tank-e1".into(),
            readonly: true,
        };
        assert!(disk_args(&ro, "astvol0").unwrap()[1].contains("read-only=on"));
    }

    /// The capability table is what the daemon gates on, so the shape of it
    /// matters more than any single flag.
    #[test]
    fn qemu_offers_disk_snapshots_but_not_live_ones() {
        let caps = Qemu::new().caps();
        assert!(caps.disk_snapshot);
        assert!(!caps.live_snapshot);
        assert!(caps.disk_formats.contains(&DiskFormat::Qcow2));
    }

    /// The trait's default impls must stay reachable for what this backend
    /// does not offer, and must name the backend when they refuse.
    #[test]
    fn unoffered_capabilities_refuse_by_name() {
        let hv = Qemu::new();
        let h = Handle {
            backend: ID.into(),
            pid: Some(1),
            ctl: ControlChannel::Qmp { path: "/tmp/x.sock".into() },
            endpoint: GuestEndpoint::HostForward { ssh_port: 22 },
            started_at: 0,
        };
        let err = hv.snapshot(&h, "t").unwrap_err().to_string();
        assert!(err.contains("qemu"), "{err}");
        assert!(hv.migrate_out(&h, asterism_core::hv::MigrationTarget { url: "x".into() }).is_err());
    }

    #[test]
    fn a_handle_with_no_pid_cannot_be_stopped() {
        let hv = Qemu::new();
        let h = Handle {
            backend: ID.into(),
            pid: None,
            ctl: ControlChannel::Qmp { path: "/tmp/x.sock".into() },
            endpoint: GuestEndpoint::HostForward { ssh_port: 22 },
            started_at: 0,
        };
        assert!(hv.stop(&h, Duration::from_millis(1)).is_err());
        assert!(hv.kill(&h).is_err());
        // ...and it is not running, which is what reconcile needs to know.
        assert_eq!(hv.state(&h).unwrap(), RunState::Stopped);
    }
}
