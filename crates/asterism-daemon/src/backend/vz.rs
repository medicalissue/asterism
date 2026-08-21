//! The Virtualization.framework backend.
//!
//! Everything VZ-specific that `astd` itself needs lives here — and that is
//! deliberately *not* very much, because the framework work happens in a
//! separate process. This file knows how to find the helper, how to check
//! it is allowed to run VMs, what to write in front of it, and how to ask
//! it questions. It never links Virtualization.framework and never needs an
//! entitlement (BACKENDS.md §4).
//!
//! Per-instance files, in `~/.asterism/instances/<name>/`:
//!   disk.raw        — `clonefile(2)` clone of the raw base image
//!   snapshots/      — clones of that disk, one file per snapshot
//!   efi-vars.bin    — EFI variable store, created by the helper on first boot
//!   vz.json         — the config the running helper was started from
//!   vz.sock         — the helper's control socket, recorded on the Handle
//!   vz-helper.log   — the helper's own stderr, for when a boot goes wrong
//!
//! (`seed.iso` and `console.log` are named by the caller.)
//!
//! ## Why a helper process
//!
//! `VZVirtualMachine` dies with the process that created it. In-process
//! would mean every `astd` restart or upgrade killed every running guest,
//! and would put `com.apple.security.virtualization` on the whole daemon.
//! Out-of-process keeps `Handle::pid` meaningful, keeps the entitlement on
//! a ~1 MB binary, and makes "is it still running?" a question asked down a
//! socket rather than something the daemon has to remember.
//!
//! ## What VZ makes different from QEMU
//!
//! * **Raw disks only.** No qcow2, ever. The base image is converted at
//!   pull time and cloned per instance, which is the Phase 1 work QEMU
//!   already exercises.
//! * **The guest has its own address.** NAT, not a forwarded loopback port,
//!   so `boot()` does not return until the guest has been *found* — see
//!   [`Vz::boot`].
//! * **The console is `/dev/hvc0`.** VZ has no 16550; see [`GUEST_CONFIG`].

use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};

use asterism_core::hv::{
    BootReq, Caps, ControlChannel, DiskFormat, DiskSpec, GuestEndpoint, Handle, Hypervisor,
    Prepared, Ready, RunState, SnapshotId,
};
use asterism_core::instance::now_unix;
use asterism_core::snapshot::{self, Snapshot};
use asterism_core::{cow, paths, tools};
use asterism_vz::{Command as VzCommand, Config, Disk as VzDisk, Reply, StopReason};

use super::{alive, grow, signal, wait_gone};

pub const ID: &str = "vz";

/// Oldest macOS this backend will run on.
///
/// 14 rather than 13 (which is where `VZEFIBootLoader` landed) because it
/// is the floor for the rest of what this backend is for — `nbd://`
/// attachments and save/restore both arrived in 14, and BACKENDS.md §3
/// recommends VZ from 14 up. Below it, the qemu backend is still there and
/// still correct.
const MIN_MACOS: u32 = 14;

/// How long `boot()` waits for the guest to answer on port 22 before
/// giving up and taking the helper down with it.
///
/// Long, because this covers a first boot running cloud-init on a slow
/// machine. The number is not a promise about speed: a warm vz boot reaches
/// sshd in about four seconds.
const BOOT_TIMEOUT: Duration = Duration::from_secs(180);

/// How long the *helper* gets to bind its socket and answer. Short,
/// because this is a local process starting: exceeding it means the binary
/// is wrong, not that a guest is slow.
const HELPER_TIMEOUT: Duration = Duration::from_secs(30);

/// Cloud-config every vz guest gets, on top of the backend-neutral seed.
///
/// The problem it solves: a stock cloud image's kernel cmdline names
/// `ttyAMA0`/`ttyS0`, and **VZ's only serial device is a virtio console at
/// `/dev/hvc0`** (VZ-SPIKE-NOTES landmine 6). The two never meet, so out of
/// the box a vz boot writes an almost empty `console.log` — no kernel ring
/// buffer, no systemd, no cloud-init — and `ast logs` shows nothing.
///
/// Fixing it at pull time was ruled out: the cmdline lives in
/// `/boot/grub/grub.cfg` inside an ext4 root, and macOS has neither an ext4
/// driver nor libguestfs (BACKENDS.md §4). So the guest fixes it for us:
///
/// * `bootcmd` echoes a line straight to `/dev/hvc0`. The *device* is there
///   as soon as virtio-console probes, even while the kernel is not logging
///   to it, so this lands on the very first boot.
/// * `runcmd` starts `serial-getty@hvc0`, which is what puts a login prompt
///   in the log.
/// * `runcmd` also adds `console=hvc0` to the guest's own GRUB config, so
///   every *later* boot has a real kernel-to-userspace transcript.
///
/// The `cloud-init status --wait` call is backgrounded on purpose: `runcmd`
/// runs inside `cloud-final.service`, so a foreground wait waits for the
/// stage it is running in and deadlocks until cloud-init's own timeout
/// (VZ-SPIKE-NOTES landmine 7).
pub const GUEST_CONFIG: &str = r#"final_message: "asterism: cloud-init $version finished at $timestamp after $uptime seconds"
bootcmd:
 - [ sh, -c, "echo 'asterism: guest console is /dev/hvc0' > /dev/hvc0 2>/dev/null || true" ]
runcmd:
 - |
   systemctl enable --now serial-getty@hvc0.service 2>/dev/null || true
   if ! grep -q 'console=hvc0' /etc/default/grub 2>/dev/null; then
     sed -i 's/^GRUB_CMDLINE_LINUX_DEFAULT="\(.*\)"/GRUB_CMDLINE_LINUX_DEFAULT="\1 console=hvc0"/' /etc/default/grub
     echo 'GRUB_TERMINAL=serial' >> /etc/default/grub
     update-grub >/dev/null 2>&1 || true
   fi
   setsid sh -c 'cloud-init status --wait >/dev/null 2>&1; echo "asterism: cloud-init $(cloud-init status 2>/dev/null | tr "\n" " ")" > /dev/hvc0' &
"#;

#[derive(Default)]
pub struct Vz {
    probed: OnceLock<Probe>,
}

/// What this host can tell us about running VZ guests, worked out once.
struct Probe {
    /// The signed helper binary.
    helper: PathBuf,
    /// macOS product version. Virtualization.framework ships with the OS,
    /// so the OS version *is* the hypervisor version — which is what gets
    /// recorded on the instance as `Machine::hv_version`.
    os_version: String,
}

impl Vz {
    pub fn new() -> Self {
        Self::default()
    }

    /// Cached probe, or the reason this host cannot run vz guests.
    ///
    /// `OnceLock` cannot cache a failure, which is exactly right here:
    /// signing the helper must fix a running daemon without restarting it.
    fn probed(&self) -> Result<&Probe> {
        if let Some(p) = self.probed.get() {
            return Ok(p);
        }
        let probe = Probe::run()?;
        Ok(self.probed.get_or_init(|| probe))
    }

    /// Materialise an instance's root disk for the first time: a
    /// `clonefile(2)` clone of the raw base, grown to the shape.
    ///
    /// No qcow2 branch, because there is nothing to branch to — VZ cannot
    /// read one. Reaching here with a qcow2 base means the lazy conversion
    /// in `backend::materialised_image_ref` did not happen, so the message
    /// says what to do about it.
    fn create_root(&self, req: &BootReq, raw: &Path) -> Result<DiskSpec> {
        let base = &req.base;
        if !base.path.exists() {
            bail!(
                "image {} is not pulled yet — run: ast pull {}",
                base.name,
                base.name
            );
        }
        if base.format != DiskFormat::Raw {
            bail!(
                "{} is a {} image, and Virtualization.framework only attaches raw \
                 disks — re-pull it so the store holds a raw base: ast pull {}",
                base.name,
                base.format,
                base.name
            );
        }
        let how = cow::clone_file(&base.path, raw)
            .with_context(|| format!("making {}'s disk", req.instance.name))?;
        if let Some(warning) = how.warning(&base.path, raw) {
            eprintln!("astd: {warning}");
        }
        if let Err(e) = grow(raw, u64::from(req.instance.shape.disk_gib)) {
            // Half a disk is worse than none: the next `up` would boot an
            // instance that is not the size it was asked for.
            let _ = std::fs::remove_file(raw);
            return Err(e);
        }
        Ok(DiskSpec::File {
            path: raw.to_owned(),
            format: DiskFormat::Raw,
            readonly: false,
        })
    }

    /// Ask the running helper for its view of the guest.
    fn info(&self, h: &Handle, timeout: Duration) -> Result<asterism_vz::Info> {
        asterism_vz::info(h.ctl.path(), timeout)
    }
}

impl Probe {
    fn run() -> Result<Self> {
        if !cfg!(target_os = "macos") {
            bail!("Virtualization.framework is macOS-only — this device runs the qemu backend");
        }
        let os_version = macos_version()?;
        if major(&os_version) < MIN_MACOS {
            bail!(
                "the vz backend needs macOS {MIN_MACOS} or newer (this is {os_version}) — \
                 use the qemu backend on this device"
            );
        }
        let helper = helper_path()?;
        // The entitlement is the difference between a helper that boots and
        // one that fails deep inside the framework with "Internal
        // Virtualization error". Check it here, where the message can say
        // what to run.
        if !is_entitled(&helper) {
            bail!(
                "{} is not code-signed with the required {} and {} entitlements — \
                 VZ refuses to create the machine or its NBD client without them, \
                 and cargo emits unsigned binaries. Run: scripts/sign-vz.sh",
                helper.display(),
                asterism_vz::ENTITLEMENT,
                asterism_vz::NETWORK_CLIENT_ENTITLEMENT,
            );
        }
        Ok(Probe { helper, os_version })
    }

    fn ready(&self) -> Ready {
        Ready {
            version: self.os_version.clone(),
            // There is one accelerator and it has no name of its own; VZ is
            // the hypervisor and the accelerator both.
            accel: "vz".to_owned(),
            // VZGenericPlatformConfiguration — the only Linux-guest
            // platform VZ offers. Named because it is recorded on the
            // instance and is half of what a live migration would have to
            // match on.
            machine_type: "generic".to_owned(),
            cpu: "host".to_owned(),
        }
    }
}

impl Hypervisor for Vz {
    fn id(&self) -> &'static str {
        ID
    }

    fn probe(&self) -> Result<Ready> {
        Ok(self.probed()?.ready())
    }

    fn caps(&self) -> Caps {
        Caps {
            // VZ has saveMachineStateToURL/restoreMachineStateFromURL on
            // macOS 14+, and this backend does not drive them yet. `Caps`
            // describes what is *offered*, so this stays false until it is.
            live_snapshot: false,
            // File-level: a clone of the raw disk, exactly as on QEMU. The
            // mechanism is the filesystem's, so it is backend-neutral.
            disk_snapshot: true,
            live_migration: false,
            disk_hotplug: false,
            // VZ's directory sharing is virtiofs
            // (`VZVirtioFileSystemDevice`), not the 9p the seed writes
            // mount units for, so honestly: not yet. `boot_req` turns this
            // into a refusal that names the instance and its volumes rather
            // than a guest that silently has no /mnt/ast.
            shared_dir: None,
            // Both DiskSpec NBD transports are translated to
            // VZNetworkBlockDeviceStorageDeviceAttachment: TCP URLs pass
            // through, while local volume bridges use standard nbd+unix
            // URIs assembled and validated by the signed helper.
            nbd_disks: true,
            // Rosetta translates x86-64 *user binaries* inside an arm64
            // guest; it is not a foreign-arch machine.
            foreign_arch: false,
            // Virtualization.framework can boot a Linux kernel directly, but
            // this backend wires up EFI only — so an OCI rootfs, which has no
            // bootloader, is refused rather than half-supported.
            direct_kernel: false,
            // The guest gets an address of its own on the NAT, so there is
            // nothing to forward from this host's loopback.
            port_forward: false,
            disk_formats: &[DiskFormat::Raw],
        }
    }

    fn guest_config(&self) -> &'static str {
        GUEST_CONFIG
    }

    /// Idempotent, and the disk it settles on is the disk every other
    /// operation uses — so an instance that has never booted can still be
    /// snapshotted in its pristine state.
    ///
    /// No firmware in the result: VZ's EFI code lives inside the framework
    /// rather than in a file, and its variable store can only be created by
    /// `VZEFIVariableStore`, which means the helper creates it on first
    /// boot (`efi-vars.bin`) and reuses it after. A zeroed file written
    /// here would be worse than none — the firmware would reject it and the
    /// guest would lose the boot entry GRUB installed.
    fn prepare(&self, req: &BootReq) -> Result<Prepared> {
        self.probed()?;
        std::fs::create_dir_all(&req.dir)?;

        let raw = req.dir.join("disk.raw");
        let root = if raw.exists() {
            DiskSpec::File {
                path: raw,
                format: DiskFormat::Raw,
                readonly: false,
            }
        } else {
            self.create_root(req, &raw)?
        };
        Ok(Prepared {
            root,
            firmware: None,
            kernel: None,
        })
    }

    /// Start the helper, then wait until the guest is *found*.
    ///
    /// QEMU's `boot` can return the moment the process daemonizes, because
    /// its endpoint — a forwarded loopback port — is known before the guest
    /// exists. A vz guest has its own address on macOS's NAT, and the only
    /// public record of it is `bootpd`'s lease file, which yields candidates
    /// rather than an answer (VZ-SPIKE-NOTES landmine 8). So the endpoint is
    /// not knowable until something answers on port 22, and this returns
    /// when it has. `ast up` on vz therefore takes as long as the guest
    /// takes to boot — and hands back a `GuestEndpoint` that is already
    /// proven rather than one `ast ssh` has to wait on.
    fn boot(&self, req: &BootReq, prep: &Prepared) -> Result<Handle> {
        let p = self.probed()?;
        let inst = req.instance;

        if !req.seed.exists() {
            bail!("no cloud-init seed at {}", req.seed.display());
        }
        if !req.shares.is_empty() {
            // Belt and braces: `backend::boot_req` gates on `Caps` and
            // refuses first. Faking a share here would be the one failure
            // mode worth being loud about.
            bail!(
                "the {ID} backend cannot share host directories, so {:?}'s volumes \
                 cannot reach the guest",
                inst.name
            );
        }

        let config = Config {
            instance: inst.name.clone(),
            root: prep.root_path()?.to_owned(),
            seed: req.seed.clone(),
            efi_vars: req.dir.join("efi-vars.bin"),
            console: req.console.clone(),
            ctl: paths::vz_socket_path(&inst.name),
            extra_disks: req
                .extra_disks
                .iter()
                .map(extra_disk)
                .collect::<Result<Vec<_>>>()?,
            cpus: inst.shape.cpus,
            mem_mib: inst.shape.mem_mib,
            mac: asterism_vz::mac_for(&inst.name),
        };
        let config_path = req.dir.join("vz.json");
        config.write(&config_path)?;

        // The helper's stderr is the only account of a boot that fails
        // before the socket answers, so it goes to a file rather than to
        // the daemon's own log, where it would be interleaved with every
        // other instance's.
        let log_path = req.dir.join("vz-helper.log");
        let log = std::fs::File::create(&log_path)
            .with_context(|| format!("opening {}", log_path.display()))?;
        let child = Command::new(&p.helper)
            .arg("--config")
            .arg(&config_path)
            .stdin(Stdio::null())
            .stdout(Stdio::from(log.try_clone()?))
            .stderr(Stdio::from(log))
            .spawn()
            .with_context(|| format!("spawning {}", p.helper.display()))?;
        let pid = child.id();
        reap_in_background(child);

        match wait_for_guest(&config.ctl, pid, &log_path) {
            Ok(addr) => Ok(Handle {
                backend: ID.to_owned(),
                pid: Some(pid),
                ctl: ControlChannel::Rpc { path: config.ctl },
                endpoint: GuestEndpoint::GuestAddr { addr },
                started_at: now_unix(),
            }),
            Err(e) => {
                // A half-started guest is nobody's idea of running. Take
                // the helper with us so the next `up` starts clean.
                if alive(pid) {
                    let _ = signal(pid, "-KILL");
                }
                let _ = std::fs::remove_file(&config.ctl);
                Err(e)
            }
        }
    }

    /// Ask the guest to power down, and let the helper's delegate say
    /// whether it did.
    ///
    /// This is `system_powerdown` and `kill -0` in one round trip: the
    /// helper answers when `guestDidStopVirtualMachine:` has fired (or when
    /// it has escalated to `stopWithCompletionHandler:`), so a clean stop is
    /// something we are *told*, not something inferred from a process going
    /// away. The signals are still here for the case the socket cannot
    /// carry the request at all.
    fn stop(&self, h: &Handle, deadline: Duration) -> Result<()> {
        let Some(pid) = h.pid else {
            bail!("handle for a {} guest carries no pid", h.backend);
        };
        // Most of the budget belongs to the guest; the rest to the signals.
        let graceful = deadline.mul_f32(0.75);
        let asked = asterism_vz::call(
            h.ctl.path(),
            &VzCommand::Stop {
                timeout_secs: Some(graceful.as_secs()),
            },
            // The helper takes `graceful` to give up on the guest, then up
            // to ten seconds to force it; outliving that is what the
            // signals below are for.
            graceful + Duration::from_secs(15),
        );
        match asked {
            // A clean stop is unremarkable and says nothing; anything else
            // is worth a line, because it means a guest lost whatever it
            // had not written down.
            Ok(Reply::Stopped { reason, seconds }) => {
                if !matches!(reason, StopReason::GuestStopped) {
                    eprintln!(
                        "astd: the vz guest did not stop cleanly after {seconds:.1}s — {reason}"
                    );
                }
                if wait_gone(pid, deadline - graceful) {
                    return Ok(());
                }
            }
            Ok(Reply::Error { message }) => eprintln!("astd: vz helper refused to stop: {message}"),
            Ok(other) => eprintln!("astd: vz helper answered stop with {other:?}"),
            // No helper on the socket: either it is already gone (in which
            // case the signals below are no-ops and this is a success) or
            // it is wedged badly enough that only a signal will do.
            Err(e) => {
                if !alive(pid) {
                    return Ok(());
                }
                eprintln!("astd: vz control socket did not answer ({e:#}) — signalling");
            }
        }
        signal(pid, "-TERM")?;
        if wait_gone(pid, Duration::from_secs(5)) {
            return Ok(());
        }
        signal(pid, "-KILL")?;
        Ok(())
    }

    /// The power cord: the helper dies, and the guest dies with it. That
    /// equivalence is the reason `Handle::pid` is meaningful for this
    /// backend at all.
    fn kill(&self, h: &Handle) -> Result<()> {
        let Some(pid) = h.pid else {
            bail!("handle for a {} guest carries no pid", h.backend);
        };
        signal(pid, "-KILL")?;
        wait_gone(pid, Duration::from_secs(2));
        let _ = std::fs::remove_file(h.ctl.path());
        Ok(())
    }

    /// Liveness for a handle reloaded from the registry — after an `astd`
    /// restart, an upgrade, or a host reboot.
    ///
    /// The socket is authoritative, and it answers with the helper's own
    /// pid: a helper that died and had its pid reused by something else
    /// cannot fake that. Only when nothing answers does this fall back to
    /// asking whether the pid is alive, which covers a helper that was
    /// SIGKILLed and left its socket file behind.
    fn state(&self, h: &Handle) -> Result<RunState> {
        match self.info(h, Duration::from_secs(2)) {
            Ok(info) => {
                let ours = h.pid.is_none_or(|pid| pid == info.pid);
                Ok(match ours && info.state.is_live() {
                    true => RunState::Running,
                    false => RunState::Stopped,
                })
            }
            Err(_) => Ok(match h.pid.map(alive).unwrap_or(false) {
                true => RunState::Running,
                false => RunState::Stopped,
            }),
        }
    }

    // ---- disk snapshots ----------------------------------------------------
    //
    // Identical to the QEMU backend's raw path, and deliberately so: a
    // snapshot is a `clonefile(2)` clone of the root disk in the instance's
    // own directory (`asterism_core::snapshot`), which involves no
    // hypervisor at all. That is what makes `ast snapshot` mean the same
    // thing on both backends, and what makes a snapshot survive the
    // instance being moved between them.

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

// ---- boot ------------------------------------------------------------------

/// Wait for the helper to come up and for its guest to answer on port 22.
///
/// Two waits with different meanings: the first is "did the helper start at
/// all", which fails fast and quotes the helper's own log; the second is
/// "has the guest finished booting", which is slow by nature and is the
/// wait a user experiences as `ast up`.
fn wait_for_guest(ctl: &Path, pid: u32, log: &Path) -> Result<IpAddr> {
    let started = Instant::now();
    let helper_deadline = started + HELPER_TIMEOUT;
    let deadline = started + BOOT_TIMEOUT;
    let mut seen_helper = false;
    loop {
        if !alive(pid) {
            bail!(
                "the vz helper exited before its guest came up — {}:\n{}",
                log.display(),
                tail(log, 20)
            );
        }
        match asterism_vz::info(ctl, Duration::from_secs(2)) {
            Ok(info) => {
                seen_helper = true;
                if let Some(addr) = info.guest_ip {
                    return Ok(addr);
                }
                if !info.state.is_live() {
                    bail!(
                        "the vz guest stopped while booting (state {:?}) — {}:\n{}",
                        info.state,
                        log.display(),
                        tail(log, 20)
                    );
                }
            }
            // Before the helper binds its socket there is nothing to talk
            // to. Normal for a few milliseconds; a problem if it lasts,
            // and a *different* problem from a guest that is slow to boot.
            Err(e) if !seen_helper => {
                if Instant::now() >= helper_deadline {
                    bail!(
                        "the vz helper never answered on {}: {e:#} — {}:\n{}",
                        ctl.display(),
                        log.display(),
                        tail(log, 20)
                    );
                }
            }
            Err(e) => bail!(
                "the vz helper stopped answering on {}: {e:#}",
                ctl.display()
            ),
        }
        if Instant::now() >= deadline {
            bail!(
                "the vz guest did not answer on port 22 within {}s — its console is {}",
                BOOT_TIMEOUT.as_secs(),
                log.with_file_name("console.log").display()
            );
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// Wait for a helper on a thread of its own, so a guest that has gone does
/// not leave a zombie behind.
///
/// Not tidiness: `alive()` is `kill -0`, and a zombie answers it. Unreaped,
/// a helper that exited would go on looking alive for as long as `astd`
/// ran, and `state()` would report a stopped guest as running — which is
/// exactly the mistake this backend exists to avoid. QEMU never needed
/// this because it double-forks itself; a helper that did would take its
/// pid with it, and the pid is what `Handle` is built on.
fn reap_in_background(mut child: std::process::Child) {
    std::thread::spawn(move || {
        let _ = child.wait();
    });
}

/// One extra volume, as the helper wants it. Everything VZ cannot attach as
/// a plain raw file is refused here by name rather than left to fail inside
/// the framework.
fn extra_disk(disk: &DiskSpec) -> Result<VzDisk> {
    match disk {
        DiskSpec::File {
            path,
            format: DiskFormat::Raw,
            readonly,
        }
        | DiskSpec::Block { path, readonly } => Ok(VzDisk::File {
            path: path.clone(),
            readonly: *readonly,
        }),
        DiskSpec::File { path, format, .. } => bail!(
            "{} is a {format} image, and the {ID} backend attaches raw disks only",
            path.display()
        ),
        DiskSpec::Nbd { url, readonly } => Ok(VzDisk::Nbd {
            url: url.clone(),
            readonly: *readonly,
        }),
        DiskSpec::NbdUnix {
            socket,
            export,
            readonly,
        } => Ok(VzDisk::NbdUnix {
            socket: socket.clone(),
            export: export.clone(),
            readonly: *readonly,
        }),
    }
}

/// The instance directory a root disk sits in — where its snapshots go.
fn instance_dir(disk: &Path) -> Result<&Path> {
    disk.parent()
        .with_context(|| format!("{} has no directory to keep snapshots in", disk.display()))
}

/// The last `lines` lines of a file, for quoting a failure back at a user.
fn tail(path: &Path, lines: usize) -> String {
    let text = std::fs::read_to_string(path).unwrap_or_default();
    let all: Vec<&str> = text.lines().collect();
    all[all.len().saturating_sub(lines)..].join("\n")
}

// ---- discovery -------------------------------------------------------------

/// Where the signed helper is.
///
/// Next to `astd` first, which is where both a release layout and a
/// `cargo build` put it, then `$ASTERISM_VZ_HELPER` for a developer running
/// a helper from somewhere else, then the usual install locations.
fn helper_path() -> Result<PathBuf> {
    if let Some(path) = std::env::var_os("ASTERISM_VZ_HELPER") {
        let path = PathBuf::from(path);
        if path.is_file() {
            return Ok(path);
        }
        bail!(
            "$ASTERISM_VZ_HELPER points at {}, which is not a file",
            path.display()
        );
    }
    if let Ok(me) = std::env::current_exe() {
        let sibling = me.with_file_name(asterism_vz::HELPER_BIN);
        if sibling.is_file() {
            return Ok(sibling);
        }
    }
    tools::tool(asterism_vz::HELPER_BIN).with_context(|| {
        format!(
            "{} is not installed next to astd — the vz backend cannot run without it",
            asterism_vz::HELPER_BIN
        )
    })
}

/// Does this binary carry both entitlements required by the helper?
///
/// `codesign -d --entitlements -` prints the entitlement plist; an unsigned
/// binary, or one cargo has rewritten since it was signed, prints an error
/// instead. Either way the answer is the same: it cannot create a VM.
fn is_entitled(bin: &Path) -> bool {
    let Ok(out) = Command::new("codesign")
        .args(["-d", "--entitlements", "-"])
        .arg(bin)
        .output()
    else {
        return false;
    };
    // Older codesign writes the plist to stderr, newer to stdout.
    let printed =
        String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr);
    printed.contains(asterism_vz::ENTITLEMENT)
        && printed.contains(asterism_vz::NETWORK_CLIENT_ENTITLEMENT)
}

/// `sw_vers -productVersion`, e.g. `15.6.1`.
fn macos_version() -> Result<String> {
    let out = tools::output(Command::new("sw_vers").arg("-productVersion"))
        .context("asking sw_vers for the macOS version")?;
    Ok(out.trim().to_owned())
}

/// Leading integer of a dotted version, or 0 when it does not start with
/// one — which fails the version check rather than passing it by accident.
fn major(version: &str) -> u32 {
    version.split('.').next().unwrap_or("").parse().unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    use asterism_core::hv::{ImageKind, ImageRef};
    use asterism_core::instance::{local_host, Instance, Shape};

    /// This backend's guest config and the seed's own half both claim
    /// `bootcmd` and `runcmd`. They are merged rather than pasted, and this
    /// is where that stops being a thing anybody has to remember: a key
    /// added here that the seed cannot absorb fails now rather than at
    /// somebody's first vz boot.
    #[test]
    fn what_this_backend_asks_of_a_guest_fits_in_a_seed() {
        asterism_core::seed::mergeable(GUEST_CONFIG).unwrap();
    }

    fn instance(disk_gib: u32) -> Instance {
        asterism_core::registry::Shard::load(
            &std::env::temp_dir().join("nonexistent-registry.json"),
        )
        .unwrap()
        .create(
            "vzdisky",
            &local_host(),
            "debian:13",
            Shape {
                cpus: 1,
                mem_mib: 512,
                disk_gib,
            },
            asterism_core::hv::Machine {
                backend: ID.into(),
                machine_type: "generic".into(),
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
            extra_disks: Vec::new(),
            console: dir.join("console.log"),
        }
    }

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

    /// The same disk the QEMU backend builds, by the same mechanism —
    /// which is the point of Phase 1: the disk stopped being a hypervisor's
    /// business before VZ ever saw one.
    #[test]
    fn a_raw_base_becomes_a_clone_grown_to_the_shape() {
        let home = tempfile::tempdir().unwrap();
        let inst = instance(2);
        let dir = home.path().join("instances/vzdisky");
        std::fs::create_dir_all(&dir).unwrap();

        let root = Vz::new()
            .create_root(
                &req(&inst, &dir, raw_base(home.path())),
                &dir.join("disk.raw"),
            )
            .unwrap();
        let DiskSpec::File { path, format, .. } = &root else {
            panic!("the root disk is a file: {root:?}");
        };
        assert_eq!(*format, DiskFormat::Raw);
        assert_eq!(
            std::fs::metadata(path).unwrap().len(),
            2 << 30,
            "2 GiB as asked"
        );
        assert!(
            cow::usage(path).unwrap() < 8 << 20,
            "a clone of a 64 KiB base costs nothing"
        );
        assert_eq!(
            std::fs::read(path).unwrap()[..4],
            [0xab; 4],
            "and it is the base"
        );
    }

    /// A qcow2 base is not something to fail on deep inside the framework:
    /// VZ will never read one, and the fix is a re-pull.
    #[test]
    fn a_qcow2_base_is_refused_with_the_way_out() {
        let home = tempfile::tempdir().unwrap();
        let inst = instance(2);
        let dir = home.path().join("instances/vzdisky");
        std::fs::create_dir_all(&dir).unwrap();
        let path = home.path().join("debian-13.qcow2");
        std::fs::write(&path, b"QFI\xfb").unwrap();
        let base = ImageRef {
            name: "debian:13".into(),
            path,
            format: DiskFormat::Qcow2,
            kind: ImageKind::Disk,
        };

        let err = Vz::new()
            .create_root(&req(&inst, &dir, base), &dir.join("disk.raw"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("raw disks"), "{err}");
        assert!(err.contains("ast pull debian:13"), "{err}");
    }

    /// Snapshots of a raw disk are files, need no hypervisor, and roll the
    /// disk back byte for byte — the same assertions the QEMU backend
    /// makes, because it is the same code underneath.
    #[test]
    fn snapshots_are_clones_in_the_instance_directory() {
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

        let hv = Vz::new();
        assert!(hv.disk_snapshot_list(&prep).unwrap().is_empty());
        let id = hv.disk_snapshot(&prep, "clean").unwrap();
        assert!(dir.path().join("snapshots/clean.raw").exists());
        assert_eq!(hv.disk_snapshot_list(&prep).unwrap()[0].tag, "clean");

        std::fs::write(&disk, b"diverged").unwrap();
        hv.disk_restore(&prep, &id).unwrap();
        assert_eq!(std::fs::read(&disk).unwrap(), b"pristine");
        assert!(hv
            .disk_restore(&prep, &SnapshotId("absent".into()))
            .is_err());
    }

    /// The capability table is what the daemon gates on. Everything false
    /// here is something VZ can do and this backend does not yet — said
    /// plainly rather than implied.
    #[test]
    fn the_capabilities_are_what_is_implemented_not_what_vz_could_do() {
        let caps = Vz::new().caps();
        assert!(
            caps.disk_snapshot,
            "file-level, so it works on every backend"
        );
        assert!(!caps.live_snapshot);
        assert!(!caps.live_migration);
        assert!(
            caps.shared_dir.is_none(),
            "virtiofs is a follow-up, and 9p is QEMU's"
        );
        assert!(caps.nbd_disks);
        assert_eq!(caps.disk_formats, &[DiskFormat::Raw], "no qcow2, ever");
    }

    /// Everything the guest is asked to do about `/dev/hvc0`, and the two
    /// traps in doing it.
    #[test]
    fn the_guest_config_fixes_the_console_the_image_does_not_know_about() {
        assert!(
            GUEST_CONFIG.contains("serial-getty@hvc0"),
            "a login prompt in the log"
        );
        assert!(
            GUEST_CONFIG.contains("console=hvc0"),
            "and a kernel transcript next boot"
        );
        // `cloud-init status --wait` in the foreground would deadlock:
        // runcmd *is* cloud-final (VZ-SPIKE-NOTES landmine 7).
        assert!(GUEST_CONFIG.contains("setsid sh -c 'cloud-init status --wait"));
        // It must be valid to append to a cloud-config document, which
        // means every line is either a top-level key or indented under one.
        for line in GUEST_CONFIG.lines() {
            assert!(
                line.starts_with(' ') || line.contains(':') || line.is_empty(),
                "unindented non-key line in the guest config: {line:?}"
            );
        }
    }

    #[test]
    fn raw_and_nbd_extra_disks_reach_the_helper_config() {
        let raw = DiskSpec::File {
            path: "/vol/data.raw".into(),
            format: DiskFormat::Raw,
            readonly: true,
        };
        assert_eq!(
            extra_disk(&raw).unwrap(),
            VzDisk::File {
                path: "/vol/data.raw".into(),
                readonly: true
            }
        );

        let qcow2 = DiskSpec::File {
            path: "/vol/data.qcow2".into(),
            format: DiskFormat::Qcow2,
            readonly: false,
        };
        assert!(extra_disk(&qcow2)
            .unwrap_err()
            .to_string()
            .contains("raw disks only"));

        let nbd = DiskSpec::Nbd {
            url: "nbd://desktop:10809/vol".into(),
            readonly: false,
        };
        assert_eq!(
            extra_disk(&nbd).unwrap(),
            VzDisk::Nbd {
                url: "nbd://desktop:10809/vol".into(),
                readonly: false
            }
        );

        let unix = DiskSpec::NbdUnix {
            socket: "/tmp/asterism.sock".into(),
            export: "team/data".into(),
            readonly: true,
        };
        assert_eq!(
            extra_disk(&unix).unwrap(),
            VzDisk::NbdUnix {
                socket: "/tmp/asterism.sock".into(),
                export: "team/data".into(),
                readonly: true,
            }
        );
    }

    #[test]
    fn versions_are_compared_by_their_major() {
        assert_eq!(major("15.6.1"), 15);
        assert_eq!(major("14"), 14);
        assert!(major("15.6.1") >= MIN_MACOS);
        assert!(major("13.7") < MIN_MACOS);
        // Unparseable is not "new enough".
        assert_eq!(major("sonoma"), 0);
        assert_eq!(major(""), 0);
    }

    /// An unsigned binary — which is what `cargo build` produces, every
    /// time — must not look entitled.
    #[test]
    fn an_unsigned_binary_is_not_entitled() {
        let dir = tempfile::tempdir().unwrap();
        let fake = dir.path().join("astd-vz");
        std::fs::write(&fake, b"#!/bin/sh\ntrue\n").unwrap();
        assert!(!is_entitled(&fake));
        assert!(!is_entitled(&dir.path().join("absent")));
    }

    #[test]
    fn a_handle_with_no_pid_cannot_be_stopped_or_killed() {
        let hv = Vz::new();
        let h = Handle {
            backend: ID.into(),
            pid: None,
            ctl: ControlChannel::Rpc {
                path: "/tmp/nothing-here.sock".into(),
            },
            endpoint: GuestEndpoint::GuestAddr {
                addr: "192.168.64.3".parse().unwrap(),
            },
            started_at: 0,
        };
        assert!(hv.stop(&h, Duration::from_millis(1)).is_err());
        assert!(hv.kill(&h).is_err());
        // ...and with nothing answering its socket, it is not running,
        // which is what `reconcile` needs to know after a restart.
        assert_eq!(hv.state(&h).unwrap(), RunState::Stopped);
    }

    /// The one thing a live snapshot would be, refused by name.
    #[test]
    fn unoffered_capabilities_refuse_by_name() {
        let hv = Vz::new();
        let h = Handle {
            backend: ID.into(),
            pid: Some(1),
            ctl: ControlChannel::Rpc {
                path: "/tmp/x.sock".into(),
            },
            endpoint: GuestEndpoint::GuestAddr {
                addr: "192.168.64.3".parse().unwrap(),
            },
            started_at: 0,
        };
        let err = hv.snapshot(&h, "t").unwrap_err().to_string();
        assert!(err.contains("vz"), "{err}");
    }
}
