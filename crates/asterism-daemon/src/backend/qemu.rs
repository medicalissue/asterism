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
//!   efi-vars.fd  — UEFI variable store, cut from this host's firmware
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
    BootReq, Caps, ControlChannel, DirectKernel, DiskFormat, DiskSpec, Firmware, GuestEgress,
    GuestEndpoint, Handle, Hypervisor, ImageKind, Prepared, Ready, RunState, ShareKind, SnapshotId,
};
use asterism_core::instance::{now_unix, PortForward};
use asterism_core::proc::{ProcId, Signal};
use asterism_core::snapshot::{self, Snapshot};
use asterism_core::tools::{output, run, tool};
use asterism_core::{cow, image, oci, paths};

use super::{grow, observed_running, owned, qmp};

pub const ID: &str = "qemu";

#[derive(Default)]
pub struct Qemu {
    probed: OnceLock<Probe>,
    /// Firmware discovery, cached separately from the host probe because it
    /// is a different question asked at a different time — see
    /// [`Qemu::firmware`].
    firmware: OnceLock<FirmwareFiles>,
}

/// The facts about this host's QEMU that every other method needs, worked
/// out once. `probe()` is called on the `ast create` path, so it stays
/// cheap: three subprocess runs and one device open, cached for the life of
/// the daemon.
///
/// Firmware is deliberately not in here. Whether this host has EDK2 is a
/// question about one *kind of boot*, not about whether QEMU runs at all: an
/// OCI rootfs is handed a kernel and never maps pflash, so a host with qemu
/// and no EDK2 runs container images perfectly well and must not be told it
/// has no working backend. [`Qemu::firmware`] asks it, once, where it is
/// actually needed.
struct Probe {
    system: PathBuf,
    img: PathBuf,
    version: String,
    /// What this host accelerates guests with — a fact asked of the host,
    /// not read off the target triple: on Linux it is `Kvm` only once
    /// `/dev/kvm` has actually been opened read-write.
    accel: Accel,
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

    /// The UEFI firmware this host boots cloud images with, found once.
    ///
    /// Separate from [`Qemu::probed`] on purpose. A cloud image is a whole
    /// disk and needs EDK2 in front of it to find the bootloader; an OCI
    /// rootfs is handed `-kernel/-initrd` and needs none. Asking for both at
    /// probe time made a missing EDK2 look like a missing *backend*, so a
    /// host that could have run container images was told to install
    /// firmware it would never map. Now the two probes answer independently
    /// and each is asked by exactly what needs it.
    ///
    /// Cached the same way, and for the same reason: the search is a
    /// dozen-odd `stat`s, so it costs nothing to repeat while it is failing,
    /// and `OnceLock` records only the hit — installing OVMF fixes a running
    /// daemon without a restart.
    fn firmware(&self) -> Result<&FirmwareFiles> {
        if let Some(fw) = self.firmware.get() {
            return Ok(fw);
        }
        // Through the cached probe, so the qemu binary is discovered once:
        // where firmware lives is partly a fact about where that binary is.
        let found = find_firmware(&self.probed()?.system)?;
        Ok(self.firmware.get_or_init(|| found))
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
            bail!(
                "image {} is not pulled yet — run: ast pull {}",
                base.name,
                base.name
            );
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
        // The binaries, then the accelerator: a host with no KVM cannot run
        // a guest at all, whatever else it has, and each of these is asked
        // of the host in its own right rather than standing in for another.
        let accel = probe_accel()?;
        let version = parse_version(&output(Command::new(&system).arg("--version"))?)
            .unwrap_or_else(|| "unknown".to_owned());
        let virtfs = supports_virtfs(&system);
        Ok(Probe {
            system,
            img,
            version,
            accel,
            virtfs,
        })
    }

    /// Machine type is per-arch: "virt" exists only on aarch64; x86 wants q35.
    fn machine_type(&self) -> &'static str {
        match image::host_arch() {
            "aarch64" => "virt,highmem=on",
            _ => "q35",
        }
    }

    fn ready(&self) -> Ready {
        Ready {
            version: self.version.clone(),
            accel: self.accel.as_arg().to_owned(),
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
            // The same user-net, seen from the other side: connections the
            // guest makes to 10.0.2.2 are proxied to this host's loopback, so
            // a listener on 127.0.0.1 is reachable from the guest and from
            // nothing on the wire. That is the whole of what the secrets
            // egress proxy needs, and it is why it works here and not on vz.
            guest_egress: Some(GuestEgress::LoopbackGateway {
                gateway: GUEST_GATEWAY,
            }),
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
            DiskSpec::File {
                path: raw,
                format: DiskFormat::Raw,
                readonly: false,
            }
        } else if legacy.exists() {
            DiskSpec::File {
                path: legacy,
                format: DiskFormat::Qcow2,
                readonly: false,
            }
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
                kernel: Some(DirectKernel {
                    kernel,
                    initrd: Some(initrd),
                    cmdline: cmdline(),
                }),
            });
        }

        // Found before the store is cut, because what the store has to be is
        // a fact about the firmware this host turned out to have. This is the
        // only caller: the OCI path above has already returned, and it is the
        // whole reason firmware is asked for here rather than at probe time.
        let fw = self.firmware()?;
        let vars = req.dir.join("efi-vars.fd");
        if !vars.exists() {
            cut_vars(fw, &vars)?;
        }

        Ok(Prepared {
            root,
            firmware: Some(Firmware {
                code: fw.code.clone(),
                vars,
            }),
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
        if req.base.kind == ImageKind::OciRootfs {
            oci::configure_instance(
                &req.base.path,
                prep.root_path()?,
                &req.shares,
                (!req.shares.is_empty()).then_some(ShareKind::NinePfs),
                &req.egress,
                &req.bootstrap,
            )?;
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
        cmd.arg("-machine")
            .arg(p.machine_type())
            .arg("-accel")
            .arg(p.accel.as_arg())
            .arg("-cpu")
            .arg(CPU_MODEL)
            .arg("-smp")
            .arg(inst.shape.cpus.to_string())
            .arg("-m")
            .arg(format!("{}M", inst.shape.mem_mib));

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
                cmd.arg("-drive")
                    .arg(format!(
                        "if=pflash,format=raw,readonly=on,file={}",
                        firmware.code.display()
                    ))
                    .arg("-drive")
                    .arg(format!(
                        "if=pflash,format=raw,file={}",
                        firmware.vars.display()
                    ));
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

        cmd.arg("-netdev")
            .arg(netdev_arg(ssh_port, &inst.publish))
            .arg("-device")
            .arg("virtio-net-pci,netdev=n0")
            .arg("-device")
            .arg("virtio-rng-pci")
            .arg("-qmp")
            .arg(format!("unix:{},server,nowait", qmp.display()))
            .arg("-display")
            .arg("none")
            .arg("-serial")
            .arg(format!("file:{}", req.console.display()))
            .arg("-daemonize")
            .arg("-pidfile")
            .arg(&pidfile);

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
        // Captured now, while the process is known to be the one `run` just
        // started. This is the only moment at which that is knowable, and
        // everything the daemon later does to this guest — including SIGKILL
        // — is authorised by what is captured here.
        let proc = ProcId::capture(pid).with_context(|| {
            format!("qemu wrote pid {pid} to its pidfile and was gone before it could be recorded")
        })?;

        Ok(Handle::owning(
            ID,
            proc,
            ControlChannel::Qmp { path: qmp },
            GuestEndpoint::HostForward { ssh_port },
        ))
    }

    /// Ask the guest to power down cleanly via QMP (ACPI power button); a
    /// killed QEMU is a yanked power cord — the overlay needs journal
    /// recovery on the next boot and recent guest writes are lost. Only if
    /// the guest ignores the request do we escalate to SIGTERM/SIGKILL.
    ///
    /// The QMP socket comes off the handle. It used to be rebuilt from the
    /// instance name, which quietly made "the control channel" a naming
    /// convention every future backend would have had to honour.
    ///
    /// Every escalation here is gated on [`ProcId`]: a handle whose process
    /// cannot be proven to be this guest's has nothing for SIGTERM to reach,
    /// and the guest it named is by definition already gone. Saying so and
    /// returning is the whole of the safe behaviour — the alternative, which
    /// this used to do, is aiming SIGKILL at a recycled pid.
    fn stop(&self, h: &Handle, deadline: Duration) -> Result<()> {
        // Most of the budget goes to the guest; the rest to SIGTERM before
        // SIGKILL. At the default 40s that is the historical 30s then 10s.
        let graceful = deadline.mul_f32(0.75);
        let Some(proc) = owned(h) else {
            return powerdown_only(h, graceful);
        };
        if powerdown(h.ctl.path()).is_ok() && proc.wait_gone(graceful) {
            return Ok(());
        }
        if !proc.signal(Signal::Term)? {
            return Ok(());
        }
        if proc.wait_gone(deadline - graceful) {
            return Ok(());
        }
        proc.signal(Signal::Kill)?;
        Ok(())
    }

    fn kill(&self, h: &Handle) -> Result<()> {
        let Some(proc) = owned(h) else {
            // The power cord is a signal, and a signal needs a process this
            // daemon can name. What is left is the monitor, which is not a
            // hard stop — and saying so beats pretending the guest is down.
            let asked = powerdown_only(h, Duration::from_secs(5));
            qmp::forget(h.ctl.path());
            return asked;
        };
        qmp::forget(h.ctl.path());
        proc.signal(Signal::Kill)?;
        Ok(())
    }

    fn state(&self, h: &Handle) -> Result<RunState> {
        Ok(match observed_running(h) {
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
    matches!(
        prep.root,
        DiskSpec::File {
            format: DiskFormat::Qcow2,
            ..
        }
    )
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
        DiskSpec::File {
            path,
            format,
            readonly,
        } => format!(
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
        DiskSpec::NbdUnix {
            socket,
            export,
            readonly,
        } => {
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

/// Take a guest down using only what is instance-bound: its own monitor.
///
/// The path for a handle this daemon cannot prove owns any process — one
/// written before identities existed whose evidence has since gone. There is
/// nothing here it may signal, and the monitor is not a substitute: ACPI is
/// a request the guest is free to ignore, and there is no escalation behind
/// it.
///
/// So this either works or says it did not, and the difference matters. A
/// silent `Ok` would leave the registry saying stopped over a guest still
/// writing to its disk, which is the state the next boot would corrupt.
fn powerdown_only(h: &Handle, budget: Duration) -> Result<()> {
    let ctl = h.ctl.path();
    if powerdown(ctl).is_err() && !ctl.exists() {
        // No monitor and no process: there is nothing here at all, which is
        // what the caller wanted.
        return Ok(());
    }
    let deadline = std::time::Instant::now() + budget;
    while std::time::Instant::now() < deadline {
        if !observed_running(h) {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    bail!(
        "this guest is still running and nothing proves which process it is, so it \
         cannot be signalled. Its monitor is {}; it was recorded at pid {}. Check that \
         pid is really the guest and stop it by hand.",
        ctl.display(),
        h.pid
            .map(|p| p.to_string())
            .unwrap_or_else(|| "none".into())
    )
}

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

// ---- acceleration ----------------------------------------------------------

/// What this host runs guests on.
///
/// There is no TCG arm and there will not be one: this backend boots with
/// `-cpu host`, which means nothing without hardware underneath it, and an
/// agent host emulated instruction by instruction would not be worth the
/// electricity. A host with neither is a host this backend refuses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Accel {
    /// Hypervisor.framework, which every supported macOS has.
    Hvf,
    /// KVM, reached through `/dev/kvm`.
    Kvm,
}

impl Accel {
    fn as_arg(self) -> &'static str {
        match self {
            Accel::Hvf => "hvf",
            Accel::Kvm => "kvm",
        }
    }
}

const KVM_DEVICE: &str = "/dev/kvm";

/// Whether this host can accelerate a guest — asked of the host, not assumed
/// from the target it was built for.
///
/// On Linux the question is exactly the one QEMU asks a moment later: can
/// this process open `/dev/kvm` read-write. A module that was never loaded,
/// a CPU with virtualisation switched off in its firmware, a user outside
/// the `kvm` group, a container that did not pass the device through — all
/// four answer here, at `ast create`, instead of as a QEMU exit code with a
/// guest that never appeared.
fn probe_accel() -> Result<Accel> {
    if cfg!(target_os = "macos") {
        return Ok(Accel::Hvf);
    }
    match std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(KVM_DEVICE)
    {
        Ok(_) => Ok(Accel::Kvm),
        Err(e) => bail!("{}", kvm_advice(&e)),
    }
}

/// Why `/dev/kvm` could not be opened, and what to do about it.
///
/// Pure, and separate from the open, so the way out of each fault is
/// something a test pins down rather than something a user finds out on the
/// one host that has it.
fn kvm_advice(e: &std::io::Error) -> String {
    use std::io::ErrorKind;
    match e.kind() {
        ErrorKind::NotFound => format!(
            "{KVM_DEVICE} is not there, so this host cannot accelerate a guest — \
             turn virtualisation (VT-x or AMD-V) on in its firmware and load the \
             module with `sudo modprobe kvm_intel` (or `kvm_amd`). If this host is \
             itself a virtual machine or a WSL distro, nested virtualisation has \
             to be turned on where it runs."
        ),
        ErrorKind::PermissionDenied => format!(
            "{KVM_DEVICE} is there, but this user cannot open it — join the group \
             that owns it with `sudo usermod -aG kvm $USER` and log out and back \
             in, or grant this user alone with \
             `sudo setfacl -m u:$USER:rw {KVM_DEVICE}`."
        ),
        _ => format!(
            "{KVM_DEVICE} is there and could not be opened: {e}. A CPU with no \
             virtualisation extensions reports itself this way."
        ),
    }
}

// ---- firmware --------------------------------------------------------------

/// The UEFI firmware this host boots cloud images with: read-only code, and
/// the template an instance's own variable store is cut from.
///
/// Two files, because they are a matched pair. A distro's OVMF is linked
/// against a variable store of a particular size and ships that store beside
/// the code; QEMU's own AArch64 build ships code alone and formats a
/// zero-filled store on first boot.
#[derive(Debug, Clone, PartialEq, Eq)]
struct FirmwareFiles {
    code: PathBuf,
    /// `None` for firmware that ships no template, which is a fact about the
    /// firmware and not a failure to look.
    vars_template: Option<PathBuf>,
}

/// One place firmware might live, and what it is called there.
///
/// Every distro packages EDK2 under its own name in its own directory, so
/// discovery is a table rather than a rule. Naming a variable store is what
/// makes one mandatory: a layout that names templates has to have one of
/// them, and a layout that names none boots on a store this backend fills
/// with zeroes.
#[derive(Debug)]
struct FirmwareLayout {
    dir: PathBuf,
    code: &'static str,
    /// Variable-store templates that pair with that code, best first.
    vars: &'static [&'static str],
}

impl FirmwareLayout {
    fn code_path(&self) -> PathBuf {
        self.dir.join(self.code)
    }

    /// This layout as files on this host, if it is here at all.
    fn resolve(&self) -> Option<FirmwareFiles> {
        let code = self.code_path();
        if !code.exists() {
            return None;
        }
        let vars_template = self
            .vars
            .iter()
            .map(|v| self.dir.join(v))
            .find(|p| p.exists());
        if vars_template.is_none() && !self.vars.is_empty() {
            // The code is here and the store it was built against is not.
            // Handing that firmware a zero-filled store of the wrong size is
            // a QEMU error with no explanation in it, so keep looking.
            return None;
        }
        Some(FirmwareFiles {
            code,
            vars_template,
        })
    }
}

/// Everywhere EDK2 lives on the hosts this runs on, best first.
///
/// QEMU's own `share/qemu` leads on every platform: it is what Homebrew
/// installs beside the binary, it is the firmware macOS instances have
/// always booted, and a host that has it has a build matched to its qemu.
/// The distro packages follow, because a Linux host usually has only those —
/// Debian and Ubuntu ship `/usr/share/OVMF` and `/usr/share/AAVMF`, Fedora
/// and Arch ship under `/usr/share/edk2` — and each of them names the
/// variable store it was built against.
fn firmware_layouts(qemu: &Path, arch: &str) -> Result<Vec<FirmwareLayout>> {
    // AArch64 names no template on purpose: `edk2-aarch64-code.fd` is padded
    // to the 64 MiB flash the `virt` machine has, EDK2 formats a zero-filled
    // store of the same size on first boot, and that is the store every
    // macOS instance in the field is already running on. x86 has no such
    // luxury — its flash window is 8 MiB, so a 64 MiB store is not a store
    // QEMU will map, and the paired `edk2-i386-vars.fd` is the only one.
    let (qemu_code, qemu_vars): (&'static str, &'static [&'static str]) = match arch {
        "aarch64" => ("edk2-aarch64-code.fd", &[]),
        "x86_64" => ("edk2-x86_64-code.fd", &["edk2-i386-vars.fd"]),
        other => bail!(
            "no UEFI firmware is mapped for {other} — this backend boots \
             aarch64 and x86_64 guests"
        ),
    };
    let mut dirs = vec![
        PathBuf::from("/opt/homebrew/share/qemu"),
        PathBuf::from("/usr/local/share/qemu"),
        PathBuf::from("/usr/share/qemu"),
    ];
    if let Some(bin_dir) = qemu.parent() {
        dirs.insert(0, bin_dir.join("../share/qemu"));
    }
    let mut layouts: Vec<FirmwareLayout> = dirs
        .into_iter()
        .map(|dir| FirmwareLayout {
            dir,
            code: qemu_code,
            vars: qemu_vars,
        })
        .collect();

    let distro: &[(&str, &'static str, &'static [&'static str])] = match arch {
        "aarch64" => &[
            (
                "/usr/share/AAVMF",
                "AAVMF_CODE_4M.fd",
                &["AAVMF_VARS_4M.fd"],
            ),
            (
                "/usr/share/AAVMF",
                "AAVMF_CODE.no-secboot.fd",
                &["AAVMF_VARS.fd"],
            ),
            ("/usr/share/AAVMF", "AAVMF_CODE.fd", &["AAVMF_VARS.fd"]),
            (
                "/usr/share/edk2/aarch64",
                "QEMU_EFI-silent-pflash.raw",
                &["vars-template-pflash.raw"],
            ),
            (
                "/usr/share/edk2/aarch64",
                "QEMU_EFI-pflash.raw",
                &["vars-template-pflash.raw"],
            ),
            ("/usr/share/edk2/aarch64", "QEMU_CODE.fd", &["QEMU_VARS.fd"]),
        ],
        _ => &[
            // Debian and Ubuntu ship both the 4 MiB build and the older
            // 2 MiB one in the same directory, and the store that goes with
            // each is the one named after it — never the other.
            ("/usr/share/OVMF", "OVMF_CODE_4M.fd", &["OVMF_VARS_4M.fd"]),
            ("/usr/share/OVMF", "OVMF_CODE.fd", &["OVMF_VARS.fd"]),
            ("/usr/share/edk2/ovmf", "OVMF_CODE.fd", &["OVMF_VARS.fd"]),
            (
                "/usr/share/edk2/x64",
                "OVMF_CODE.4m.fd",
                &["OVMF_VARS.4m.fd"],
            ),
            ("/usr/share/edk2/x64", "OVMF_CODE.fd", &["OVMF_VARS.fd"]),
            (
                "/usr/share/qemu",
                "ovmf-x86_64-code.bin",
                &["ovmf-x86_64-vars.bin"],
            ),
        ],
    };
    layouts.extend(distro.iter().map(|(dir, code, vars)| FirmwareLayout {
        dir: PathBuf::from(*dir),
        code,
        vars,
    }));
    Ok(layouts)
}

/// The first layout this host actually has. Existence is the whole test:
/// nothing here reads a firmware file and nothing here runs qemu.
fn pick_firmware(layouts: &[FirmwareLayout]) -> Option<FirmwareFiles> {
    layouts.iter().find_map(FirmwareLayout::resolve)
}

fn find_firmware(qemu: &Path) -> Result<FirmwareFiles> {
    let arch = image::host_arch();
    let layouts = firmware_layouts(qemu, arch)?;
    pick_firmware(&layouts).with_context(|| {
        let looked: Vec<String> = layouts
            .iter()
            .map(|l| l.code_path().display().to_string())
            .collect();
        format!(
            "no UEFI firmware for {arch} guests near {} — install it with {}. \
             Looked for: {}",
            qemu.display(),
            firmware_package_hint(arch),
            looked.join(", ")
        )
    })
}

/// What to install, in the words of the package managers that have it.
fn firmware_package_hint(arch: &str) -> &'static str {
    match arch {
        "aarch64" => {
            "`sudo apt install qemu-efi-aarch64`, `sudo dnf install edk2-aarch64`, \
             or `brew install qemu`"
        }
        _ => {
            "`sudo apt install ovmf`, `sudo dnf install edk2-ovmf`, \
             `sudo pacman -S edk2-ovmf`, or `brew install qemu`"
        }
    }
}

/// AArch64 EDK2's flash device is 64 MiB and its variable store has to
/// match. Only reached for firmware that ships no template of its own.
const VARS_BYTES: usize = 64 * 1024 * 1024;

/// Cut an instance its own UEFI variable store, the way this host's firmware
/// wants one.
///
/// A distro's OVMF ships the store it was built against: the size is the one
/// its code flash was linked for, and the contents are the empty variable
/// database that build expects, so the instance's store is a copy of it.
/// Firmware that ships no template gets the zero-filled store EDK2 formats
/// on first boot, which is what every instance had when QEMU's own build was
/// the only firmware this backend could find.
fn cut_vars(fw: &FirmwareFiles, vars: &Path) -> Result<()> {
    let Some(template) = &fw.vars_template else {
        std::fs::write(vars, vec![0u8; VARS_BYTES])?;
        return Ok(());
    };
    std::fs::copy(template, vars)
        .with_context(|| format!("cutting {} from {}", vars.display(), template.display()))?;
    // The template is a package file, owned by root and often read-only. The
    // copy takes its mode, and pflash opens a variable store read-write.
    use std::os::unix::fs::PermissionsExt;
    let mut perms = std::fs::metadata(vars)?.permissions();
    perms.set_mode(0o600);
    std::fs::set_permissions(vars, perms)?;
    Ok(())
}

// ---- discovery -------------------------------------------------------------

/// 9p host support is a build-time option, and on some platforms it has
/// historically been left out. Ask the binary in front of us rather than
/// assuming.
fn supports_virtfs(qemu: &Path) -> bool {
    let Ok(out) = Command::new(qemu).args(["-device", "help"]).output() else {
        return false;
    };
    let listed =
        String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr);
    listed.contains("virtio-9p-pci")
}

/// Pull the version out of `qemu-system-* --version`, whose first line reads
/// `QEMU emulator version 11.0.0`. Recorded on every instance, so a miss
/// must not be fatal — the caller falls back to "unknown".
fn parse_version(banner: &str) -> Option<String> {
    let line = banner.lines().next()?;
    let v = line
        .split_whitespace()
        .find(|w| w.starts_with(|c: char| c.is_ascii_digit()) && w.contains('.'))?;
    // Homebrew and distro builds suffix the version: "9.1.0(v9.1.0-mac)".
    Some(v.split(['(', '-']).next().unwrap_or(v).to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    use asterism_core::hv::ImageRef;
    use asterism_core::instance::{local_host, Instance, Shape};
    use std::process::{Child, Command};
    use std::time::Instant;

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
            Shape {
                cpus: 1,
                mem_mib: 512,
                disk_gib,
            },
            asterism_core::hv::Machine {
                backend: ID.into(),
                machine_type: "virt".into(),
                cpu: "host".into(),
                hv_version: "test".into(),
            },
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
            egress: Default::default(),
            bootstrap: Default::default(),
            extra_disks: Vec::new(),
            console: dir.join("console.log"),
        }
    }

    /// A raw base image, standing in for a pulled one. Its contents only
    /// have to survive being cloned.
    fn raw_base(dir: &Path) -> ImageRef {
        let path = dir.join("debian-13.raw");
        std::fs::write(&path, vec![0xab; 64 * 1024]).unwrap();
        ImageRef {
            name: "debian:13".into(),
            path,
            format: DiskFormat::Raw,
            kind: ImageKind::Disk,
        }
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
        assert_eq!(
            std::fs::metadata(path).unwrap().len(),
            2 << 30,
            "2 GiB as asked"
        );
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
            root: DiskSpec::File {
                path: disk.clone(),
                format: DiskFormat::Raw,
                readonly: false,
            },
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
        assert!(
            hv.disk_snapshot(&prep, "clean").is_err(),
            "one tag, one snapshot"
        );

        std::fs::write(&disk, b"diverged").unwrap();
        hv.disk_restore(&prep, &id).unwrap();
        assert_eq!(std::fs::read(&disk).unwrap(), b"pristine");
        assert!(hv
            .disk_restore(&prep, &SnapshotId("absent".into()))
            .is_err());
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
        assert_eq!(
            instance_dir(Path::new("/i/disky/disk.raw")).unwrap(),
            Path::new("/i/disky")
        );
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
                assert!(
                    kernel.initrd.is_some(),
                    "the initrd carries virtio_blk and ext4"
                );
                assert!(kernel.cmdline.contains("root=/dev/vda"));
                assert!(
                    !dir.join("efi-vars.fd").exists(),
                    "no variable store either"
                );
            }
            Err(e) => {
                let e = e.to_string();
                assert!(e.contains("no kernel of its own"), "{e}");
                assert!(e.contains("ast pull"), "the way out is in the message: {e}");
            }
        }
    }

    /// The two boots ask this host for different things, which is why they
    /// are probed apart. A cloud image is a whole disk and needs EDK2 in
    /// front of it; an OCI rootfs is handed `-kernel/-initrd` and never maps
    /// pflash. Firmware was once part of `probe()`, so a host with qemu and
    /// no EDK2 reported no working backend at all and could not create the
    /// container instances it was perfectly able to run.
    ///
    /// The firmware cache is the evidence: it is only ever filled by the
    /// path that actually maps firmware.
    #[test]
    fn only_a_firmware_boot_asks_this_host_for_firmware() {
        let home = tempfile::tempdir().unwrap();
        let inst = instance(2);
        let dir = home.path().join("instances/disky");
        std::fs::create_dir_all(&dir).unwrap();

        let path = home.path().join("oci-abc.raw");
        std::fs::write(&path, vec![0xcd; 64 * 1024]).unwrap();
        let oci = ImageRef {
            name: "docker.io/library/nginx:latest".into(),
            path,
            format: DiskFormat::Raw,
            kind: ImageKind::OciRootfs,
        };

        let hv = Qemu::new();
        // Probing the host is a question about tooling and acceleration, and
        // it answers without a firmware search — which is exactly what it
        // could not do when EDK2 was one of the things `probe()` demanded.
        let _ = hv.probe();
        assert!(
            hv.firmware.get().is_none(),
            "probing this host is not a firmware search"
        );

        // Whether this device has fetched a guest kernel is not this test's
        // business — either way, the OCI path must not have gone looking for
        // firmware on the way there.
        let _ = hv.prepare(&req(&inst, &dir, oci));
        assert!(
            hv.firmware.get().is_none(),
            "an OCI boot never asks for EDK2"
        );
        assert!(
            !dir.join("efi-vars.fd").exists(),
            "and cuts no variable store"
        );

        // A cloud image on the same host does ask, and gets either the
        // firmware this host has or the reason it has none.
        match hv.prepare(&req(&inst, &dir, raw_base(home.path()))) {
            Ok(prep) => {
                let fw = prep.firmware.expect("a cloud image boots firmware");
                assert!(
                    prep.kernel.is_none(),
                    "firmware and a kernel are alternatives"
                );
                assert!(fw.code.exists(), "{}", fw.code.display());
                assert!(fw.vars.exists(), "the instance got a store of its own");
                assert_eq!(
                    hv.firmware.get().map(|f| &f.code),
                    Some(&fw.code),
                    "found once and kept: the second cloud image runs no search"
                );
            }
            Err(e) => {
                let e = format!("{e:#}");
                if hv.probe().is_ok() {
                    // The case the split exists for: qemu runs here, EDK2 is
                    // not installed, and this host is still a working backend
                    // for every instance that boots a kernel instead.
                    assert!(e.contains("UEFI firmware"), "{e}");
                    assert!(e.contains("install it with"), "the way out: {e}");
                } else {
                    assert!(
                        e.contains("not found"),
                        "no qemu on this device at all: {e}"
                    );
                }
                assert!(
                    hv.firmware.get().is_none(),
                    "a miss is never cached, so installing firmware fixes a running daemon"
                );
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
        assert!(line.contains("init=/asterism-init"), "{line}");
        assert!(
            line.contains("net.ifnames=0"),
            "eth0 is what images expect: {line}"
        );
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
                &[
                    PortForward {
                        host: 8080,
                        guest: 80
                    },
                    PortForward {
                        host: 5432,
                        guest: 5432
                    }
                ]
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

    /// Each way `/dev/kvm` can be unusable has a different way out, and the
    /// message is the only place a user meets it. Wrong advice — telling
    /// someone to load a module they already have — costs more than none.
    #[test]
    fn each_kvm_fault_carries_its_own_way_out() {
        use std::io::{Error, ErrorKind};

        let absent = kvm_advice(&Error::from(ErrorKind::NotFound));
        assert!(absent.contains("/dev/kvm"), "{absent}");
        assert!(absent.contains("modprobe kvm_intel"), "{absent}");
        assert!(
            absent.contains("nested virtualisation"),
            "a WSL host needs this: {absent}"
        );
        assert!(
            !absent.contains("usermod"),
            "nothing to join a group over: {absent}"
        );

        let denied = kvm_advice(&Error::from(ErrorKind::PermissionDenied));
        assert!(denied.contains("usermod -aG kvm"), "{denied}");
        assert!(
            denied.contains("setfacl"),
            "the way out for one login: {denied}"
        );
        assert!(
            !denied.contains("modprobe"),
            "the module is loaded already: {denied}"
        );

        // Anything else still names the device and carries the OS's own words.
        let odd = kvm_advice(&Error::other("boom"));
        assert!(odd.contains("/dev/kvm"), "{odd}");
        assert!(odd.contains("boom"), "{odd}");
    }

    /// Acceleration is a fact about the host, so both answers are the
    /// contract: hvf on macOS, and on Linux either kvm or the reason why not.
    #[test]
    fn acceleration_is_asked_of_the_host() {
        assert_eq!(Accel::Hvf.as_arg(), "hvf");
        assert_eq!(Accel::Kvm.as_arg(), "kvm");

        match probe_accel() {
            Ok(accel) => {
                let expected = if cfg!(target_os = "macos") {
                    Accel::Hvf
                } else {
                    Accel::Kvm
                };
                assert_eq!(accel, expected);
            }
            Err(e) => {
                // Only Linux can answer no, and only by naming the device.
                assert_eq!(std::env::consts::OS, "linux", "macOS always has hvf: {e}");
                assert!(e.to_string().contains("/dev/kvm"), "{e}");
            }
        }
    }

    /// A layout with several builds in one directory: the store that goes
    /// with a code file is the one named after it, never the neighbour.
    #[test]
    fn firmware_is_found_as_a_code_and_vars_pair() {
        let dir = tempfile::tempdir().unwrap();
        for f in [
            "OVMF_CODE_4M.fd",
            "OVMF_VARS_4M.fd",
            "OVMF_CODE.fd",
            "OVMF_VARS.fd",
        ] {
            std::fs::write(dir.path().join(f), f.as_bytes()).unwrap();
        }
        let layouts = vec![
            FirmwareLayout {
                dir: dir.path().to_owned(),
                code: "OVMF_CODE_4M.fd",
                vars: &["OVMF_VARS_4M.fd"],
            },
            FirmwareLayout {
                dir: dir.path().to_owned(),
                code: "OVMF_CODE.fd",
                vars: &["OVMF_VARS.fd"],
            },
        ];
        let found = pick_firmware(&layouts).expect("the 4M build is there");
        assert_eq!(found.code, dir.path().join("OVMF_CODE_4M.fd"));
        assert_eq!(
            found.vars_template,
            Some(dir.path().join("OVMF_VARS_4M.fd"))
        );
    }

    /// Firmware whose store is missing is not firmware this host can boot:
    /// the search passes over it rather than pairing it with a zero-filled
    /// store of the wrong size. Firmware that never wanted one is taken as it
    /// is — that is the AArch64 build every macOS instance runs on.
    #[test]
    fn a_layout_missing_the_store_it_needs_is_passed_over() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("OVMF_CODE_4M.fd"), b"code").unwrap();
        std::fs::write(dir.path().join("edk2-aarch64-code.fd"), b"code").unwrap();

        let needs_a_store = FirmwareLayout {
            dir: dir.path().to_owned(),
            code: "OVMF_CODE_4M.fd",
            vars: &["OVMF_VARS_4M.fd"],
        };
        let needs_none = FirmwareLayout {
            dir: dir.path().to_owned(),
            code: "edk2-aarch64-code.fd",
            vars: &[],
        };
        let absent = FirmwareLayout {
            dir: dir.path().join("nowhere"),
            code: "edk2-aarch64-code.fd",
            vars: &[],
        };

        assert!(pick_firmware(std::slice::from_ref(&needs_a_store)).is_none());
        let found = pick_firmware(&[needs_a_store, needs_none]).expect("the second one");
        assert_eq!(found.code, dir.path().join("edk2-aarch64-code.fd"));
        assert_eq!(found.vars_template, None, "and it is cut zero-filled");

        assert!(pick_firmware(&[absent]).is_none());
        assert!(pick_firmware(&[]).is_none());
    }

    /// The order is the policy: qemu's own firmware, next to the binary that
    /// will boot it, before anything a distro packages. macOS never leaves
    /// the first group, which is why its instances keep the store they have.
    #[test]
    fn qemus_own_firmware_is_searched_before_the_distros() {
        let layouts =
            firmware_layouts(Path::new("/opt/homebrew/bin/qemu-system-x86_64"), "x86_64").unwrap();
        assert_eq!(layouts[0].dir, Path::new("/opt/homebrew/bin/../share/qemu"));
        assert_eq!(layouts[0].code, "edk2-x86_64-code.fd");
        assert_eq!(
            layouts[0].vars,
            &["edk2-i386-vars.fd"],
            "x86 flash is 8 MiB, not 64"
        );

        let names: Vec<_> = layouts.iter().map(|l| l.code_path()).collect();
        let qemus = names
            .iter()
            .filter(|p| p.ends_with("edk2-x86_64-code.fd"))
            .count();
        let distro = names
            .iter()
            .position(|p| p.ends_with("OVMF/OVMF_CODE_4M.fd"))
            .unwrap();
        assert_eq!(distro, qemus, "every qemu path comes first: {names:?}");
        assert!(names.contains(&PathBuf::from("/usr/share/OVMF/OVMF_CODE_4M.fd")));
        assert!(names.contains(&PathBuf::from("/usr/share/edk2/ovmf/OVMF_CODE.fd")));
        assert_eq!(layouts[distro].vars, &["OVMF_VARS_4M.fd"]);

        // AArch64 keeps the mapping macOS has always had, and keeps asking
        // for no template with it.
        let arm = firmware_layouts(
            Path::new("/opt/homebrew/bin/qemu-system-aarch64"),
            "aarch64",
        )
        .unwrap();
        assert_eq!(arm[0].code, "edk2-aarch64-code.fd");
        assert!(
            arm[0].vars.is_empty(),
            "the 64 MiB zero fill is the store here"
        );
        assert!(arm
            .iter()
            .any(|l| l.code_path() == Path::new("/usr/share/AAVMF/AAVMF_CODE_4M.fd")));
        assert!(
            arm.iter().skip(4).all(|l| !l.vars.is_empty()),
            "every distro layout names the store it was built against"
        );

        let err = firmware_layouts(Path::new("/usr/bin/qemu-system-riscv64"), "riscv64")
            .unwrap_err()
            .to_string();
        assert!(err.contains("riscv64"), "{err}");
    }

    /// The store an instance boots on is the one its firmware was built
    /// against — a copy of the template, writable, whatever mode the
    /// package file had. Firmware with no template keeps the zero fill.
    #[test]
    fn a_variable_store_is_cut_from_the_template_when_there_is_one() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let template = dir.path().join("OVMF_VARS_4M.fd");
        std::fs::write(&template, b"an empty variable database").unwrap();
        // Package files are root-owned and read-only; the copy must not be.
        std::fs::set_permissions(&template, std::fs::Permissions::from_mode(0o444)).unwrap();

        let paired = FirmwareFiles {
            code: dir.path().join("OVMF_CODE_4M.fd"),
            vars_template: Some(template),
        };
        let vars = dir.path().join("efi-vars.fd");
        cut_vars(&paired, &vars).unwrap();
        assert_eq!(std::fs::read(&vars).unwrap(), b"an empty variable database");
        let mode = std::fs::metadata(&vars).unwrap().permissions().mode();
        assert_eq!(
            mode & 0o200,
            0o200,
            "pflash opens the store read-write: {mode:o}"
        );

        let alone = FirmwareFiles {
            code: dir.path().join("edk2-aarch64-code.fd"),
            vars_template: None,
        };
        let zeroed = dir.path().join("zeroed.fd");
        cut_vars(&alone, &zeroed).unwrap();
        let meta = std::fs::metadata(&zeroed).unwrap();
        assert_eq!(
            meta.len(),
            VARS_BYTES as u64,
            "64 MiB, matching the code flash"
        );
        assert!(std::fs::read(&zeroed).unwrap().iter().all(|b| *b == 0));
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
        let nbd = DiskSpec::Nbd {
            url: "nbd://desktop:10809/vol".into(),
            readonly: false,
        };
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
        let h = handle(Some(ProcId {
            pid: 1,
            started_us: 1,
            boot_id: None,
            started_ticks: None,
            exec: None,
        }));
        let err = hv.snapshot(&h, "t").unwrap_err().to_string();
        assert!(err.contains("qemu"), "{err}");
        assert!(hv
            .migrate_out(&h, asterism_core::hv::MigrationTarget { url: "x".into() })
            .is_err());
    }

    /// A handle built the way one arrives off disk.
    fn handle(proc: Option<ProcId>) -> Handle {
        Handle {
            backend: ID.into(),
            pid: proc.as_ref().map(|p| p.pid),
            proc,
            ctl: ControlChannel::Qmp {
                path: "/tmp/x.sock".into(),
            },
            endpoint: Some(GuestEndpoint::HostForward { ssh_port: 22 }),
            container_control: None,
            started_at: 0,
        }
    }

    /// A pid nothing is holding: a child that has already been waited for.
    fn dead_pid() -> u32 {
        let mut child = Command::new("true").spawn().unwrap();
        let pid = child.id();
        let _ = child.wait();
        pid
    }

    /// A process that has exec'd `sleep` and stays available while the stale
    /// identity is exercised.
    ///
    /// `Command::spawn` can return while the child is still between fork and
    /// exec. Capturing there records the test binary rather than `sleep`, so
    /// the later executable check correctly calls the same pid foreign. The
    /// guard waits for the intended executable before returning its identity,
    /// and owns cleanup on success, early exit, timeout, and panic alike.
    struct Sleeper(Child);

    impl Sleeper {
        fn spawn() -> Self {
            Self(Command::new("sleep").arg("30").spawn().unwrap())
        }

        fn identity(&mut self) -> ProcId {
            let pid = self.0.id();
            let deadline = Instant::now() + Duration::from_secs(5);

            loop {
                let last_probe = match ProcId::capture(pid) {
                    Ok(identity) => {
                        let is_sleep = identity
                            .exec
                            .as_deref()
                            .and_then(Path::file_name)
                            .is_some_and(|name| name == "sleep");
                        if is_sleep && identity.check().is_ours() {
                            return identity;
                        }
                        format!("observed executable {:?}", identity.exec)
                    }
                    Err(error) => format!("identity capture failed: {error:#}"),
                };

                let failure = match self.0.try_wait() {
                    Ok(Some(status)) => Some(format!(
                        "sleep fixture {pid} exited before readiness: {status}"
                    )),
                    Ok(None) if Instant::now() >= deadline => Some(format!(
                        "sleep fixture {pid} did not exec within five seconds; {last_probe}"
                    )),
                    Ok(None) => None,
                    Err(error) => Some(format!("checking sleep fixture {pid}: {error}")),
                };
                if let Some(failure) = failure {
                    self.reap();
                    panic!("{failure}");
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        }

        fn reap(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    impl Drop for Sleeper {
        fn drop(&mut self) {
            self.reap();
        }
    }

    /// The `pid: None` case, which used to be an error and is now the plain
    /// truth: there is no process here, so there is nothing to take down and
    /// nothing is running.
    #[test]
    fn a_handle_that_owns_no_process_is_stopped_and_stays_unsignalled() {
        let hv = Qemu::new();
        let h = handle(None);
        assert!(hv.stop(&h, Duration::from_millis(1)).is_ok());
        assert!(hv.kill(&h).is_ok());
        assert_eq!(hv.state(&h).unwrap(), RunState::Stopped);
    }

    /// The whole point of the pack. A registry written by an older daemon
    /// carries a bare pid, that pid has since been handed to something else,
    /// and `ast down` used to answer by SIGKILLing it.
    #[test]
    fn a_pre_identity_handle_is_stopped_and_never_signalled() {
        let hv = Qemu::new();
        // Our own pid stands in for the recycled one: definitely alive, and
        // definitely not a guest. `kill -0` — the old test — says running.
        let json = format!(
            r#"{{"backend":"qemu","pid":{},
                 "ctl":{{"kind":"qmp","path":"/tmp/x.sock"}},
                 "endpoint":{{"kind":"host_forward","ssh_port":22}},
                 "started_at":0}}"#,
            std::process::id()
        );
        let h: Handle = serde_json::from_str(&json).unwrap();
        assert_eq!(hv.state(&h).unwrap(), RunState::Stopped);
        // And the test process is still here to assert it.
        assert!(hv.stop(&h, Duration::from_millis(1)).is_ok());
        assert!(hv.kill(&h).is_ok());
        assert!(ProcId::capture(std::process::id()).unwrap().alive());
    }

    /// A handle whose pid has been recycled: same number, a process that
    /// started later. Nothing may be signalled and nothing is running.
    #[test]
    fn a_recycled_pid_is_stopped_and_refuses_the_signals() {
        let hv = Qemu::new();
        let mut sleeper = Sleeper::spawn();
        let real = sleeper.identity();
        assert!(
            real.alive(),
            "the foreign process is alive before the check"
        );
        let mut stale = real.clone();
        if let Some(ticks) = stale.started_ticks.as_mut() {
            *ticks -= 1;
        } else {
            stale.started_us -= 1;
        }
        let h = handle(Some(stale));

        assert_eq!(hv.state(&h).unwrap(), RunState::Stopped);
        // Down succeeds — there is nothing of this guest left to take down —
        // and the process wearing its number is not touched. Before this,
        // `stop` sent it SIGTERM and then SIGKILL.
        assert!(hv.stop(&h, Duration::from_millis(10)).is_ok());
        assert!(hv.kill(&h).is_ok());
        assert!(
            real.alive(),
            "the process that owns that pid is alive and untouched through the assertion"
        );
    }

    /// Crash cleanup: the guest is gone, so every path is a no-op that
    /// succeeds. This is what `persist::boot_again` runs into.
    #[test]
    fn a_dead_guest_is_stopped_and_stopping_it_again_succeeds() {
        let hv = Qemu::new();
        let pid = dead_pid();
        let h = handle(Some(ProcId {
            pid,
            started_us: 1,
            boot_id: None,
            started_ticks: None,
            exec: None,
        }));
        assert_eq!(hv.state(&h).unwrap(), RunState::Stopped);
        assert!(hv.stop(&h, Duration::from_millis(10)).is_ok());
        assert!(hv.kill(&h).is_ok());
    }
}
