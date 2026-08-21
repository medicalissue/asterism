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
//! Out-of-process gives the guest a process of its own to be identified by
//! ([`Handle::proc`]), keeps the entitlement on a ~1 MB binary, and makes
//! "is it still running?" a question asked down a socket rather than
//! something the daemon has to remember.
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

use std::collections::HashSet;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};

use asterism_core::hv::{
    BootReq, Caps, ControlChannel, DiskFormat, DiskSpec, GuestEndpoint, Handle, Hypervisor,
    Prepared, Ready, RunState, SnapshotId,
};
use asterism_core::instance::Instance;
use asterism_core::proc::{ProcId, Signal};
use asterism_core::snapshot::{self, Snapshot};
use asterism_core::{cow, paths, tools};
use asterism_vz::guest;
use asterism_vz::{Command as VzCommand, Config, Disk as VzDisk, Discovery, Reply, StopReason};

use super::{alive, grow, owned};

pub const ID: &str = "vz";

/// How long the framework's own hard stop gets when there is no signal
/// behind it. `kill` is the power cord and has to stay quick: a helper that
/// will not take this is one a human has to be told about, not one to wait
/// out.
const HARD_STOP: Duration = Duration::from_secs(5);

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

/// How long a boot waits for the *previous* helper to let go of the control
/// socket. See [`await_helper_exit`].
///
/// Sized from the longest a helper can take to go on its own: the fifteen
/// seconds it gives a guest to power off after losing a disk, the ten the
/// framework's forced stop can take after that, and room to spare. A cap
/// rather than a wait — an ordinary boot spends none of it.
const HELPER_HANDOVER: Duration = Duration::from_secs(45);

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
    /// Helpers that have told us their guest lost a disk.
    ///
    /// Two jobs, and the second is why this is a set rather than a log
    /// line. The first is not turning one dead volume into a page of
    /// identical lines: the supervisor asks [`Hypervisor::state`] every few
    /// seconds. The second is answering a question `info` stops being able
    /// to answer — a helper taking its guest down spends up to ten seconds
    /// inside the framework's forced stop with nothing draining its control
    /// queue, and a helper that is still alive must not read back as a
    /// healthy guest for the length of it.
    ///
    /// Keyed by the helper's identity rather than by instance, because that
    /// is what the failed path has: it names the exact helper that said so.
    /// A *pid* would not do — this daemon can outlive many helpers, and a
    /// number handed back out would make a fresh helper inherit a dead one's
    /// verdict and read as stopped from its first tick.
    lost_disks: Mutex<HashSet<ProcId>>,
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

    /// Remember that this helper's guest lost a disk, and say so once.
    ///
    /// Worth a line because it is the whole explanation for a guest the
    /// supervisor is about to restart, and because the alternative is a
    /// human reading `vz-helper.log` to find out that a volume server went
    /// away. Worth *remembering* because the helper is about to stop
    /// answering — see [`Vz::lost_a_disk`].
    fn report_lost_disk(&self, proc: &ProcId, instance: &str, lost: &asterism_vz::StorageError) {
        if self.lost_disks_mut().insert(proc.clone()) {
            eprintln!("astd: {instance} lost a disk and is going down — {lost}");
        }
    }

    /// Is a helper answering on this handle's socket, and is it the one the
    /// handle names?
    ///
    /// The observation a handle with no proven process falls back to. The
    /// socket path belongs to one instance, and a helper answers it with its
    /// own pid — so a reply carrying the recorded pid says the guest is
    /// still up. It says nothing about what may be done to that process,
    /// which is why it lives here and not in [`Hypervisor::stop`].
    fn answers_for(&self, h: &Handle) -> bool {
        let Some(pid) = h.pid else { return false };
        self.info(h, Duration::from_secs(2))
            .is_ok_and(|info| info.pid == pid && info.state.is_live())
    }

    /// Has this helper already told us its guest lost a disk?
    ///
    /// The one thing that makes a silent control socket mean something.
    fn lost_a_disk(&self, proc: &ProcId) -> bool {
        self.lost_disks_mut().contains(proc)
    }

    fn lost_disks_mut(&self) -> std::sync::MutexGuard<'_, HashSet<ProcId>> {
        // A poisoned lock here would mean a panic inside this bookkeeping,
        // and the worst taking it anyway can cost is a repeated log line.
        // Refusing it would cost a guest being called healthy.
        match self.lost_disks.lock() {
            Ok(seen) => seen,
            Err(poisoned) => poisoned.into_inner(),
        }
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
            // And for the same reason, no guest-only door into this host.
            // macOS's NAT puts the guest on a shared bridge with an address
            // of its own; a listener the guest could reach would have to be
            // bound on that bridge's host address, which is a real interface
            // that other guests — and, on some configurations, the LAN — can
            // reach too. There is no loopback path here, so this says so and
            // the secrets data plane refuses to bind on vz rather than
            // opening an unauthenticated proxy for somebody's API keys.
            guest_egress: None,
            disk_formats: &[DiskFormat::Raw],
        }
    }

    /// The console fix every vz guest needs, plus the agent that answers on
    /// its virtio socket.
    ///
    /// The key is minted here, on the way into the seed, and read again by
    /// the helper at boot — so `ast up` on an instance that has never had
    /// one is what gives it one. It is stable after that: the seed's
    /// fingerprint covers everything in here, and a key that moved would
    /// reissue the seed and make the guest redo its first boot.
    fn guest_config(&self, inst: &Instance) -> Result<String> {
        let key = guest::Key::ensure(&paths::guest_agent_key_path(&inst.name))
            .with_context(|| format!("minting {:?}'s guest agent key", inst.name))?;
        Ok(format!("{GUEST_CONFIG}{}", guest::cloud_config(&key)))
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

    /// Start the helper, then wait until the guest says where it is.
    ///
    /// QEMU's `boot` can return the moment the process daemonizes, because
    /// its endpoint — a forwarded loopback port — is known before the guest
    /// exists. A vz guest has its own address on macOS's NAT and nothing
    /// outside the guest knows it, so `boot` waits to be told: the guest's
    /// agent answers on the virtio socket and names its own address
    /// (`asterism_vz::guest`). A guest with no agent falls back to what
    /// this did before — a `bootpd` lease candidate proved by an ssh banner
    /// (VZ-SPIKE-NOTES landmine 8), which is inference and slower.
    ///
    /// Either way `ast up` on vz takes as long as the guest takes to come
    /// up, and hands back a `GuestEndpoint` that is already known good
    /// rather than one `ast ssh` has to wait on.
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
            // The key, not the bytes: `vz.json` is what a human reads to
            // find out what a running guest was built from, and a secret
            // does not belong in it. Only named when it is actually there —
            // an instance whose seed predates the agent has no key file,
            // and telling the helper to look for one would be a boot that
            // complains instead of one that falls back.
            agent_key: Some(paths::guest_agent_key_path(&inst.name))
                .filter(|path| path.exists()),
        };
        let config_path = req.dir.join("vz.json");
        config.write(&config_path)?;

        // A helper taking its own guest down still owns this socket, and
        // the new one will not steal it. Let it finish first.
        await_helper_exit(&config.ctl, HELPER_HANDOVER);

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
        // Captured before anything else is done with the child, while it is
        // still provably the process this backend just spawned. Everything
        // the daemon may later do to this helper — up to SIGKILL, possibly
        // days from now and across a daemon restart — is authorised by this.
        let proc = ProcId::capture(pid).with_context(|| {
            format!(
                "the vz helper exited immediately — {}:\n{}",
                log_path.display(),
                tail(&log_path, 20)
            )
        });
        reap_in_background(child);
        let proc = proc?;

        match wait_for_guest(&config.ctl, &proc, &log_path, &inst.name) {
            Ok(addr) => Ok(Handle::owning(
                ID,
                proc,
                ControlChannel::Rpc { path: config.ctl },
                GuestEndpoint::GuestAddr { addr },
            )),
            Err(e) => {
                // A half-started guest is nobody's idea of running. Take
                // the helper with us so the next `up` starts clean.
                let _ = proc.signal(Signal::Kill);
                let _ = std::fs::remove_file(&config.ctl);
                Err(e)
            }
        }
    }

    /// Ask the guest to power down, and let the helper's delegate say
    /// whether it did.
    ///
    /// This is `system_powerdown` and a liveness check in one round trip: the
    /// helper answers when `guestDidStopVirtualMachine:` has fired (or when
    /// it has escalated to `stopWithCompletionHandler:`), so a clean stop is
    /// something we are *told*, not something inferred from a process going
    /// away. The signals are still here for the case the socket cannot
    /// carry the request at all.
    fn stop(&self, h: &Handle, deadline: Duration) -> Result<()> {
        let Some(proc) = owned(h) else {
            // Nothing here is provably this guest's helper, so nothing here
            // may be signalled. The socket still can be: it belongs to this
            // instance, and a helper answering on it takes its *own* guest
            // down. That is the whole of what is left, and it either works
            // or is reported — never quietly reported as a stop.
            return take_down_over_the_socket(
                h,
                VzCommand::Stop { timeout_secs: Some(deadline.mul_f32(0.75).as_secs()) },
                deadline,
            );
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
                if proc.wait_gone(deadline - graceful) {
                    return Ok(());
                }
            }
            Ok(Reply::Error { message }) => eprintln!("astd: vz helper refused to stop: {message}"),
            Ok(other) => eprintln!("astd: vz helper answered stop with {other:?}"),
            // No helper on the socket: either it is already gone (in which
            // case the signals below are no-ops and this is a success) or
            // it is wedged badly enough that only a signal will do.
            Err(e) => {
                if !proc.alive() {
                    return Ok(());
                }
                eprintln!("astd: vz control socket did not answer ({e:#}) — signalling");
            }
        }
        if !proc.signal(Signal::Term)? {
            return Ok(());
        }
        if proc.wait_gone(Duration::from_secs(5)) {
            return Ok(());
        }
        proc.signal(Signal::Kill)?;
        Ok(())
    }

    /// The power cord: the helper dies, and the guest dies with it. That
    /// equivalence is the reason a process identity means anything for this
    /// backend at all — killing the helper *is* killing the guest, which is
    /// why the helper has to be the right process before anything is sent.
    fn kill(&self, h: &Handle) -> Result<()> {
        let Some(proc) = owned(h) else {
            // SIGKILL needs a process this daemon can name. The framework's
            // own hard stop does not — it is a request down this instance's
            // socket, answered by the helper that owns the guest.
            return take_down_over_the_socket(h, VzCommand::Kill, HARD_STOP);
        };
        proc.signal(Signal::Kill)?;
        proc.wait_gone(Duration::from_secs(2));
        let _ = std::fs::remove_file(h.ctl.path());
        Ok(())
    }

    /// Liveness for a handle reloaded from the registry — after an `astd`
    /// restart, an upgrade, or a host reboot.
    ///
    /// The socket is authoritative, and it answers with the helper's own
    /// pid: a socket that outlived its helper answers nothing at all, and a
    /// *different* helper answering names itself. Only when nothing answers
    /// does this fall back to the recorded process identity, which covers a
    /// helper that was SIGKILLed and left its socket file behind.
    ///
    /// Neither half trusts a bare number. The reply's pid is only accepted
    /// when it is the pid of the process this handle owns *and* that process
    /// is still the one that was recorded ([`ProcId`]) — otherwise a helper
    /// whose pid had been handed back out to something else that happened to
    /// bind this path would read as our guest.
    ///
    /// A guest that has lost a disk for good is `Stopped` here even though
    /// its helper is still up: the helper is in the middle of taking it
    /// down (see the `astd-vz` module docs), and `Running` for that window
    /// is what would let the supervisor leave a guest sitting on storage it
    /// cannot write to. `RunState` has no rung between running and stopped,
    /// and inventing one is not what a caller wants anyway — restarting is.
    ///
    /// ## Why an unexplained silence is still `Running`
    ///
    /// A helper that has stopped answering is not thereby dead, and the
    /// difference matters more than it looks. Every caller reads this the
    /// same way — `matches!(hv.state(h), Ok(RunState::Running))`, in
    /// `persist::alive` and `instance::is_running` — so `Err` and `Stopped`
    /// are one answer to all of them, and it is an answer they *act* on:
    /// `note_died` owes the instance a restart, `reconcile` rewrites the
    /// registry, and `boot_again` runs `clear_stale_control`, which unlinks
    /// the control socket. Unlinking a *live* helper's socket removes the
    /// only thing stopping the next helper binding the same path, and the
    /// second guest boots on the first one's `disk.raw`.
    ///
    /// Silence alone is easy to come by: `ast down` produces thirty seconds
    /// of it, because the helper spends the guest's shutdown budget inside
    /// `graceful_stop` without draining its control queue, and any request
    /// arriving meanwhile runs `reconcile`. So silence alone does not make
    /// a guest dead here. Silence *from a helper that has already said its
    /// disk is gone* does — that helper is finishing a shutdown it started
    /// itself, and it is the only window in which nothing answering and
    /// nothing wrong are different things.
    fn state(&self, h: &Handle) -> Result<RunState> {
        // A handle with no proven process cannot be answered by an identity,
        // but it can still be answered — by the socket, which belongs to
        // this instance and which a helper answers with its own pid. That is
        // enough to know the guest is there and deliberately not enough to
        // signal it: see `backend::observed_running`.
        let Some(proc) = h.proc.as_ref().filter(|_| alive(h)) else {
            return Ok(match self.answers_for(h) {
                true => RunState::Running,
                false => RunState::Stopped,
            });
        };
        match self.info(h, Duration::from_secs(2)) {
            Ok(info) => {
                let ours = info.pid == proc.pid;
                match &info.storage_error {
                    // Whatever state a helper puts beside a lost disk, the
                    // guest is on its way out. Only for *our* helper: a
                    // socket answering with another pid is another
                    // instance's, and its troubles are not ours to report.
                    Some(lost) if ours => {
                        self.report_lost_disk(proc, &info.instance, lost);
                        Ok(RunState::Stopped)
                    }
                    _ => Ok(match ours && info.state.is_live() {
                        true => RunState::Running,
                        false => RunState::Stopped,
                    }),
                }
            }
            // Nothing answered, so the recorded process is all there is to
            // go on — and what it settles is narrower than it looks.
            Err(_) => {
                if !proc.alive() {
                    // Gone, or a number that now belongs to somebody else:
                    // either way the helper is gone and the guest with it. A
                    // helper that was SIGKILLed and left its socket file
                    // behind lands here too, which is what this fallback was
                    // always for.
                    return Ok(RunState::Stopped);
                }
                Ok(match self.lost_a_disk(proc) {
                    // Told, then silent: this is the forced stop it started
                    // when the disk went, not a guest anyone can use.
                    true => RunState::Stopped,
                    // Live, and nothing has said otherwise.
                    false => RunState::Running,
                })
            }
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

/// Wait for a helper that is on its way out to let go of its socket.
///
/// A helper binds `vz.sock` for as long as it has a guest, and refuses to
/// take one another helper is still answering on — rightly, because that
/// other helper owns a running guest. But a helper that is taking its own
/// guest down after losing a disk goes on answering for the whole of that
/// shutdown, and `astd`'s supervisor is trying to restart the instance the
/// entire time. Spawning into that window fails on the socket, and an
/// instance's restart budget is three attempts.
///
/// Returns the moment nothing answers, which is every ordinary boot: a path
/// with no socket, and a stale file a killed helper left behind, both
/// refuse the connection immediately. A helper with a *live* guest is a
/// real conflict rather than a handover, and is left to fail exactly as it
/// always has.
fn await_helper_exit(ctl: &Path, budget: Duration) {
    let deadline = Instant::now() + budget;
    while Instant::now() < deadline {
        match asterism_vz::info(ctl, Duration::from_secs(2)) {
            Ok(info) if info.state.is_live() && info.storage_error.is_none() => return,
            Ok(_) => std::thread::sleep(Duration::from_millis(200)),
            Err(_) => return,
        }
    }
    eprintln!(
        "astd: a vz helper still holds {} after {}s — starting anyway",
        ctl.display(),
        budget.as_secs()
    );
}

/// Take a guest down over its own control socket, with no signal behind it.
///
/// The path for a handle written before identities existed that could not be
/// adopted. The socket is instance-bound — it is this instance's path, and a
/// helper answering on it is the process that owns this instance's guest —
/// so asking it to stop is a request aimed at exactly one guest. What is
/// missing is the escalation: no SIGTERM, no SIGKILL, because there is no
/// process this daemon can prove is the one to send them to.
///
/// A helper that will not go therefore has to be reported rather than
/// assumed gone. The registry saying stopped over a guest still writing to
/// its disk is the state the next boot corrupts.
fn take_down_over_the_socket(h: &Handle, command: VzCommand, budget: Duration) -> Result<()> {
    let ctl = h.ctl.path();
    if !ctl.exists() {
        // No socket and no provable process: nothing of this guest is left.
        return Ok(());
    }
    // Everything here fits inside the caller's budget, including the wait
    // for an answer. The owned path can afford to overrun it because it has
    // SIGKILL behind it; this one has nothing behind it, so a caller that
    // said forty seconds gets an answer in forty seconds.
    let round_trip = budget.max(Duration::from_millis(100));
    match asterism_vz::call(ctl, &command, round_trip) {
        Ok(Reply::Stopped { reason, seconds }) => {
            if !matches!(reason, StopReason::GuestStopped) {
                eprintln!("astd: the vz guest did not stop cleanly after {seconds:.1}s — {reason}");
            }
        }
        Ok(other) => eprintln!("astd: vz helper answered {command:?} with {other:?}"),
        // Nothing on the socket at all: the helper is gone, and with it the
        // guest — that equivalence is what this backend is built on.
        Err(_) if !ctl.exists() => return Ok(()),
        Err(e) => eprintln!("astd: vz control socket did not answer ({e:#})"),
    }
    // Proven by the socket falling silent, which is the same evidence the
    // request was sent on.
    let until = Instant::now() + round_trip;
    while Instant::now() < until {
        if asterism_vz::info(ctl, round_trip).is_err() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    bail!(
        "this guest's helper is still answering on {} and nothing proves which process \
         it is, so it cannot be signalled. It was recorded at pid {}. Check that pid is \
         really the helper and stop it by hand.",
        ctl.display(),
        h.pid.map(|p| p.to_string()).unwrap_or_else(|| "none".into())
    )
}

/// Wait for the helper to come up and for its guest to answer on port 22.
///
/// Two waits with different meanings: the first is "did the helper start at
/// all", which fails fast and quotes the helper's own log; the second is
/// "has the guest finished booting", which is slow by nature and is the
/// wait a user experiences as `ast up`.
fn wait_for_guest(ctl: &Path, proc: &ProcId, log: &Path, instance: &str) -> Result<IpAddr> {
    let started = Instant::now();
    let helper_deadline = started + HELPER_TIMEOUT;
    let deadline = started + BOOT_TIMEOUT;
    let mut seen_helper = false;
    // Said once, whatever the boot goes on to do: a guest whose agent
    // refused the helper, or speaks a protocol it does not, boots on the
    // fallback and must not do so silently.
    let mut said_agent_trouble = false;
    loop {
        if !proc.alive() {
            bail!(
                "the vz helper exited before its guest came up — {}:\n{}",
                log.display(),
                tail(log, 20)
            );
        }
        match asterism_vz::info(ctl, Duration::from_secs(2)) {
            Ok(info) => {
                seen_helper = true;
                if let Some(trouble) = info.agent_error.as_deref() {
                    if !said_agent_trouble {
                        said_agent_trouble = true;
                        eprintln!(
                            "astd: {instance}: the guest agent is not usable, so this boot \
                             falls back to finding the guest on the NAT — {trouble}"
                        );
                    }
                }
                if let Some(addr) = info.guest_ip {
                    if matches!(info.endpoint_via, Some(Discovery::Ssh) | None) {
                        // Worth a line because it is the slower, weaker
                        // path: an address out of the lease file that
                        // something answered on. A guest that keeps landing
                        // here has no agent, and that is a thing to fix.
                        eprintln!(
                            "astd: {instance} was found at {addr} by an ssh banner rather \
                             than by asking it — this guest has no agent on vsock port {}",
                            guest::PORT
                        );
                    }
                    return Ok(addr);
                }
                if !info.state.is_live() {
                    bail!(
                        "the vz guest stopped while booting (state {:?}{}) — {}:\n{}",
                        info.state,
                        // The one state that has a plainer explanation than
                        // the helper's log: a volume that never came up, or
                        // one that went away mid-boot.
                        info.storage_error
                            .as_ref()
                            .map(|lost| format!(" — {lost}"))
                            .unwrap_or_default(),
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
                "the vz guest never said where it is within {}s — neither its agent on \
                 vsock port {} nor an ssh banner on the NAT — its console is {}",
                BOOT_TIMEOUT.as_secs(),
                guest::PORT,
                log.with_file_name("console.log").display()
            );
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// Wait for a helper on a thread of its own, so a guest that has gone does
/// not leave a zombie behind.
///
/// This used to be load-bearing: `alive()` was `kill -0`, a zombie answers
/// it, and an unreaped helper would have gone on reading as a running guest
/// for as long as `astd` did. [`ProcId`] reads the kernel's own process
/// state and calls a zombie gone, so liveness no longer depends on this. It
/// stays because a process table slot held for the life of the daemon is
/// still a leak, and because the child handle has to go somewhere.
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

    /// What a vz guest actually gets: the console fix and the agent, as one
    /// document the seed builder can fold into its own half.
    ///
    /// `Vz::guest_config` is exactly this concatenation with a key minted
    /// on the way past; it is spelled out here rather than called because
    /// minting one writes into `ASTERISM_HOME`, which is process-wide and
    /// shared with every other test in this binary.
    #[test]
    fn the_guest_config_carries_the_agent_and_still_merges_into_a_seed() {
        let key = guest::Key::parse(&"7c".repeat(32)).unwrap();
        let config = format!("{GUEST_CONFIG}{}", guest::cloud_config(&key));
        // The check a backend is held to, run here rather than at boot.
        asterism_core::seed::mergeable(&config).expect("a seed can carry this");

        assert!(config.contains(&key.hex()), "the guest is given the key");
        assert!(
            config.contains("asterism-guest.service"),
            "and something to keep the agent running"
        );
        // Two `bootcmd:` keys, one from each half. The seed builder merges
        // by key, so this is legal — and it is what makes adding the agent
        // an addition rather than a rewrite of the console fix.
        assert_eq!(
            config.lines().filter(|l| *l == "bootcmd:").count(),
            2,
            "{config}"
        );
        for line in config.lines() {
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

    /// A handle that owns no process: nothing to take down, and nothing
    /// running. This used to be an error; it is now simply the truth, and
    /// the truth every path that cannot prove ownership falls back to.
    #[test]
    fn a_handle_that_owns_no_process_is_stopped_and_stays_unsignalled() {
        let hv = Vz::new();
        let h = Handle {
            backend: ID.into(),
            pid: None,
            proc: None,
            ctl: ControlChannel::Rpc {
                path: "/tmp/nothing-here.sock".into(),
            },
            endpoint: GuestEndpoint::GuestAddr {
                addr: "192.168.64.3".parse().unwrap(),
            },
            started_at: 0,
        };
        assert!(hv.stop(&h, Duration::from_millis(1)).is_ok());
        assert!(hv.kill(&h).is_ok());
        // ...and with nothing answering its socket, it is not running,
        // which is what `reconcile` needs to know after a restart.
        assert_eq!(hv.state(&h).unwrap(), RunState::Stopped);
    }

    // ---- talking to a helper ---------------------------------------------

    /// A stand-in for a running `astd-vz`: answers every `info` on `sock`
    /// with the same reply, on the same one-JSON-object-per-line wire.
    fn fake_helper(sock: &Path, info: asterism_vz::Info) {
        use std::io::{BufRead, BufReader, Write};
        let listener = std::os::unix::net::UnixListener::bind(sock).unwrap();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let Ok(reading) = stream.try_clone() else {
                    continue;
                };
                let mut asked = String::new();
                if BufReader::new(reading).read_line(&mut asked).is_err() {
                    continue;
                }
                let mut said = serde_json::to_string(&Reply::Info(info.clone())).unwrap();
                said.push('\n');
                let _ = stream.write_all(said.as_bytes());
            }
        });
    }

    /// This process's own pid, so the handle and the reply agree and the
    /// liveness fallback would answer *running* — which is what makes
    /// these tests about `info` rather than about liveness.
    fn helper_info(
        state: asterism_vz::State,
        lost: Option<asterism_vz::StorageError>,
    ) -> asterism_vz::Info {
        asterism_vz::Info {
            instance: "vzdisky".into(),
            pid: std::process::id(),
            state,
            mac: asterism_vz::mac_for("vzdisky"),
            guest_ip: Some("192.168.64.3".parse().unwrap()),
            endpoint_via: Some(Discovery::Agent),
            agent: None,
            agent_error: None,
            started_at: 1,
            boot_secs: Some(4.0),
            console: "/i/vzdisky/console.log".into(),
            storage_error: lost,
        }
    }

    /// A handle owning this test process, which is the live helper these
    /// tests stand in for.
    fn handle_on(sock: &Path) -> Handle {
        owning(sock, Some(ProcId::capture(std::process::id()).unwrap()))
    }

    fn owning(sock: &Path, proc: Option<ProcId>) -> Handle {
        Handle {
            backend: ID.into(),
            pid: proc.as_ref().map(|p| p.pid),
            proc,
            ctl: ControlChannel::Rpc {
                path: sock.to_owned(),
            },
            endpoint: GuestEndpoint::GuestAddr {
                addr: "192.168.64.3".parse().unwrap(),
            },
            started_at: 0,
        }
    }

    fn lost_disk() -> asterism_vz::StorageError {
        asterism_vz::StorageError {
            uri: "nbd+unix:///team%2Fdata?socket=%2Ftmp%2Fv.sock".into(),
            message: "Connection reset by peer".into(),
        }
    }

    /// A helper that answers `answers` times and then goes quiet without
    /// letting go of its socket.
    ///
    /// What `stopWithCompletionHandler:` looks like from out here: the
    /// process is up, the socket is bound and still accepting, and nothing
    /// behind it is draining the queue — so a client connects, writes, and
    /// waits out its read timeout. Accepted connections are held rather
    /// than dropped, because a dropped one would answer with EOF, which is
    /// a different failure from no answer at all.
    fn fake_helper_going_quiet(sock: &Path, info: asterism_vz::Info, answers: usize) {
        use std::io::{BufRead, BufReader, Write};
        let listener = std::os::unix::net::UnixListener::bind(sock).unwrap();
        std::thread::spawn(move || {
            let mut held = Vec::new();
            let mut answered = 0;
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                if answered >= answers {
                    held.push(stream);
                    continue;
                }
                let Ok(reading) = stream.try_clone() else {
                    continue;
                };
                let mut asked = String::new();
                if BufReader::new(reading).read_line(&mut asked).is_err() {
                    continue;
                }
                let mut said = serde_json::to_string(&Reply::Info(info.clone())).unwrap();
                said.push('\n');
                let _ = stream.write_all(said.as_bytes());
                answered += 1;
            }
        });
    }

    /// A pid nothing is holding: a child that has already been waited for.
    /// Every test using it asserts it really is dead first, so a reused
    /// number fails the test rather than passing it for the wrong reason.
    fn dead_pid() -> u32 {
        let mut child = Command::new("true").spawn().unwrap();
        let pid = child.id();
        child.wait().unwrap();
        pid
    }

    /// Sol P2. The helper answers `info` throughout the fifteen seconds it
    /// gives the guest to power off, then spends up to ten more inside the
    /// framework's forced stop with nothing draining the control queue. Its
    /// pid is alive for all of it — and before this, that silence read back
    /// as a healthy running guest, which is the one thing this whole path
    /// exists to prevent.
    #[test]
    fn a_helper_that_went_quiet_after_losing_a_disk_is_not_running() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("dying.sock");
        // One answer — the last `info` of the shutdown grace — then silence.
        fake_helper_going_quiet(
            &sock,
            helper_info(asterism_vz::State::Error, Some(lost_disk())),
            1,
        );
        let hv = Vz::new();
        let h = handle_on(&sock);

        assert_eq!(
            hv.state(&h).unwrap(),
            RunState::Stopped,
            "the answer that says the disk is gone"
        );
        assert!(
            h.owned().unwrap().alive(),
            "and the helper is still very much up"
        );
        assert_eq!(
            hv.state(&h).unwrap(),
            RunState::Stopped,
            "so is the silence that follows it"
        );
    }

    /// ...but only because we were told. Silence on its own is not death:
    /// every caller reads `Stopped` and `Err` alike as "restart it", and
    /// the restart runs `clear_stale_control`, which unlinks the socket a
    /// live helper is still holding — after which nothing stops a second
    /// guest booting on the same disk. `ast down` alone produces up to
    /// thirty seconds of exactly this silence.
    #[test]
    fn an_unexplained_silence_from_a_live_helper_is_left_alone() {
        let dir = tempfile::tempdir().unwrap();
        let hv = Vz::new();

        // Bound, accepting, answering nothing.
        let quiet = dir.path().join("quiet.sock");
        fake_helper_going_quiet(&quiet, helper_info(asterism_vz::State::Running, None), 0);
        assert_eq!(hv.state(&handle_on(&quiet)).unwrap(), RunState::Running);

        // Not bound at all — a helper that has not got there yet.
        let absent = dir.path().join("absent.sock");
        assert_eq!(hv.state(&handle_on(&absent)).unwrap(), RunState::Running);
    }

    /// The case the identity fallback was always for: a helper that was
    /// killed leaves its socket file behind, and a process that is gone
    /// settles it whatever the socket does.
    #[test]
    fn a_dead_helper_is_stopped_whatever_its_socket_is_doing() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("orphan.sock");
        fake_helper_going_quiet(&sock, helper_info(asterism_vz::State::Running, None), 0);
        let hv = Vz::new();

        let dead = ProcId { pid: dead_pid(), started_us: 1, exec: None };
        let h = owning(&sock, Some(dead.clone()));
        assert!(!dead.alive(), "the pid really is nobody's");
        assert_eq!(hv.state(&h).unwrap(), RunState::Stopped);

        // ...and a handle owning nothing has nothing to fall back on.
        assert_eq!(hv.state(&owning(&sock, None)).unwrap(), RunState::Stopped);
    }

    /// The same silent socket, but the recorded pid has been handed to a
    /// live process that is not our helper. `kill -0` says running; the
    /// identity says the helper is gone, which is the only answer that
    /// keeps `stop` from signalling a stranger.
    #[test]
    fn a_recycled_helper_pid_is_stopped_and_is_never_signalled() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("recycled.sock");
        fake_helper_going_quiet(&sock, helper_info(asterism_vz::State::Running, None), 0);
        let hv = Vz::new();

        let mut sleeper = Command::new("sleep").arg("30").spawn().unwrap();
        let real = ProcId::capture(sleeper.id()).unwrap();
        let stale = ProcId { started_us: real.started_us - 1, ..real.clone() };
        let h = owning(&sock, Some(stale));

        assert_eq!(hv.state(&h).unwrap(), RunState::Stopped);
        // Down reaches for the socket, which is instance-bound, and never
        // for the pid, which is not ours. The process wearing that number is
        // untouched either way — before this it was SIGTERMed and SIGKILLed.
        let _ = hv.stop(&h, Duration::from_millis(10));
        assert!(real.alive(), "the process that owns that pid is untouched");

        let _ = sleeper.kill();
        let _ = sleeper.wait();
    }

    /// The other half of that: a handle nobody can prove owns anything is
    /// still taken down through its own control socket, and a helper that
    /// answers goes. No signal is involved at any point.
    #[test]
    fn an_unprovable_handle_is_taken_down_over_its_own_socket() {
        let dir = tempfile::tempdir().unwrap();
        let hv = Vz::new();

        // Nothing bound at all: nothing of this guest is left, and saying so
        // is not a failure.
        let absent = dir.path().join("absent.sock");
        assert!(hv.stop(&owning(&absent, None), Duration::from_millis(50)).is_ok());
        assert!(hv.kill(&owning(&absent, None)).is_ok());

        // A helper that answers `stop` the way a real one does. It is asked,
        // it says the guest powered off, and its socket is gone afterwards —
        // which is the evidence the takedown worked.
        let sock = dir.path().join("obliging.sock");
        obliging_helper(&sock);
        let h = owning(&sock, None);
        assert_eq!(hv.state(&h).unwrap(), RunState::Stopped, "no live info reply");
        assert!(hv.stop(&h, Duration::from_millis(500)).is_ok());
    }

    /// A helper that answers one `stop` with a clean shutdown and then takes
    /// its socket with it, exactly as `astd-vz` does on the way out.
    fn obliging_helper(sock: &Path) {
        use std::io::{BufRead, BufReader, Write};
        let listener = std::os::unix::net::UnixListener::bind(sock).unwrap();
        let path = sock.to_owned();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let Ok(reading) = stream.try_clone() else { continue };
                let mut asked = String::new();
                if BufReader::new(reading).read_line(&mut asked).is_err() {
                    continue;
                }
                let mut said = serde_json::to_string(&Reply::Stopped {
                    reason: StopReason::GuestStopped,
                    seconds: 0.2,
                })
                .unwrap();
                said.push('\n');
                let _ = stream.write_all(said.as_bytes());
                break;
            }
            let _ = std::fs::remove_file(&path);
        });
    }

    /// A helper answering with a pid that is not the one on the handle is a
    /// *different* helper — the instance was restarted while this daemon was
    /// away, and this handle is stale. Its socket answering healthily must
    /// not make the stale handle look alive.
    #[test]
    fn a_helper_restart_leaves_the_old_handle_stopped() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("restarted.sock");
        // The replacement helper answers with its own pid, not ours.
        fake_helper(
            &sock,
            asterism_vz::Info {
                pid: std::process::id() + 1,
                ..helper_info(asterism_vz::State::Running, None)
            },
        );
        assert_eq!(
            Vz::new().state(&handle_on(&sock)).unwrap(),
            RunState::Stopped,
            "somebody else's helper is not this handle's guest"
        );
    }

    /// One helper going quiet says nothing about another. The memory is
    /// keyed by identity, so it cannot leak between guests — nor from a
    /// dead helper to a fresh one that inherited its pid — and a live
    /// helper still answering is read from its answer, never from the
    /// memory.
    #[test]
    fn a_lost_disk_is_remembered_against_one_helper_not_all_of_them() {
        let dir = tempfile::tempdir().unwrap();
        let hv = Vz::new();

        let lost = dir.path().join("lost.sock");
        fake_helper_going_quiet(
            &lost,
            helper_info(asterism_vz::State::Error, Some(lost_disk())),
            1,
        );
        assert_eq!(hv.state(&handle_on(&lost)).unwrap(), RunState::Stopped);

        // A different helper, just as silent, whose pid never said
        // anything. A real live process, so the pid genuinely resolves.
        let mut sleeper = Command::new("sleep").arg("30").spawn().unwrap();
        let other = dir.path().join("other.sock");
        fake_helper_going_quiet(&other, helper_info(asterism_vz::State::Running, None), 0);
        let second = ProcId::capture(sleeper.id()).unwrap();
        let elsewhere = owning(&other, Some(second.clone()));
        assert!(
            second.alive(),
            "the second helper stands in for one that is up"
        );
        assert_eq!(
            hv.state(&elsewhere).unwrap(),
            RunState::Running,
            "one guest's dead disk is not another's"
        );
        let _ = sleeper.kill();
        let _ = sleeper.wait();

        // And one that is still answering is read from its answer.
        let healthy = dir.path().join("healthy.sock");
        fake_helper(&healthy, helper_info(asterism_vz::State::Running, None));
        assert_eq!(hv.state(&handle_on(&healthy)).unwrap(), RunState::Running);
    }

    /// The bug this exists to prevent: VZ reports a guest whose network
    /// disk has failed for good as `Running`, so a helper that only counted
    /// the failure left `astd` supervising a guest writing into nothing.
    ///
    /// The two halves are told apart by what the helper sends, not by
    /// anything guessed here: VZ's own reconnect loop is transparent and
    /// never reaches the wire, so ordinary NBD churn is a plain running
    /// `info` — while a `didEncounterError:` arrives as a state that is not
    /// live *and* the disk that caused it.
    #[test]
    fn nbd_churn_is_running_and_a_lost_disk_is_not() {
        let dir = tempfile::tempdir().unwrap();
        let hv = Vz::new();

        // Reconnecting under the guest's feet: still a running guest.
        let churning = dir.path().join("churn.sock");
        fake_helper(&churning, helper_info(asterism_vz::State::Running, None));
        assert_eq!(hv.state(&handle_on(&churning)).unwrap(), RunState::Running);

        // The disk is gone for good. The helper is still up — it is in the
        // middle of powering the guest down — so `alive(pid)` would say
        // running, and this must not.
        let lost = dir.path().join("lost.sock");
        fake_helper(
            &lost,
            helper_info(asterism_vz::State::Error, Some(lost_disk())),
        );
        let h = handle_on(&lost);
        assert!(
            h.owned().unwrap().alive(),
            "the helper answering has not exited"
        );
        assert_eq!(
            hv.state(&h).unwrap(),
            RunState::Stopped,
            "a guest that lost a disk is never reported as running"
        );
        // Idempotent, because the supervisor asks over and over.
        assert_eq!(hv.state(&h).unwrap(), RunState::Stopped);
    }

    /// Belt and braces: even if a future helper still called itself live
    /// while reporting a lost disk, the disk wins.
    #[test]
    fn a_lost_disk_outranks_a_live_state() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("confused.sock");
        fake_helper(
            &sock,
            helper_info(asterism_vz::State::Running, Some(lost_disk())),
        );
        assert_eq!(
            Vz::new().state(&handle_on(&sock)).unwrap(),
            RunState::Stopped
        );
    }

    /// A volume that never came up, or went away mid-boot: `ast up` should
    /// say which disk rather than leaving a human to read the helper's log.
    #[test]
    fn a_boot_that_loses_its_disk_names_it() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("booting.sock");
        let log = dir.path().join("vz-helper.log");
        std::fs::write(&log, "astd-vz: vzdisky started in 0.30s\n").unwrap();
        fake_helper(
            &sock,
            asterism_vz::Info {
                // Nothing has answered on port 22 yet, so `boot` is still
                // waiting when the disk goes.
                guest_ip: None,
                ..helper_info(asterism_vz::State::Error, Some(lost_disk()))
            },
        );

        let me = ProcId::capture(std::process::id()).unwrap();
        let err = wait_for_guest(&sock, &me, &log, "vzdisky")
            .unwrap_err()
            .to_string();
        assert!(err.contains("stopped while booting"), "{err}");
        assert!(err.contains("nbd+unix:///team%2Fdata"), "{err}");
        assert!(err.contains("Connection reset by peer"), "{err}");
        assert!(err.contains("astd-vz: vzdisky started"), "{err}");
    }

    /// The other half of taking a guest down over a lost disk: for as long
    /// as the helper is doing it, it still owns `vz.sock` — and the
    /// supervisor is already trying to bring the instance back.
    #[test]
    fn a_boot_waits_out_a_helper_that_is_still_letting_go() {
        let dir = tempfile::tempdir().unwrap();
        let budget = Duration::from_millis(600);

        // Nothing listening — every ordinary boot, and a stale socket file
        // a killed helper left behind. Neither is waited on.
        let t = Instant::now();
        await_helper_exit(&dir.path().join("absent.sock"), budget);
        assert!(t.elapsed() < budget, "took {:?}", t.elapsed());

        // A live guest is a genuine conflict, not a handover: `ctl::listen`
        // refuses it by name, and waiting first would only delay saying so.
        let live = dir.path().join("live.sock");
        fake_helper(&live, helper_info(asterism_vz::State::Running, None));
        let t = Instant::now();
        await_helper_exit(&live, budget);
        assert!(t.elapsed() < budget, "took {:?}", t.elapsed());

        // One that has lost a disk and is powering its guest off: waited
        // for, so the restart lands on a socket that is free.
        let dying = dir.path().join("dying.sock");
        fake_helper(
            &dying,
            helper_info(asterism_vz::State::Error, Some(lost_disk())),
        );
        let t = Instant::now();
        await_helper_exit(&dying, budget);
        assert!(t.elapsed() >= budget, "took {:?}", t.elapsed());
    }

    /// The one thing a live snapshot would be, refused by name.
    #[test]
    fn unoffered_capabilities_refuse_by_name() {
        let hv = Vz::new();
        let h = owning(
            Path::new("/tmp/x.sock"),
            Some(ProcId { pid: 1, started_us: 1, exec: None }),
        );
        let err = hv.snapshot(&h, "t").unwrap_err().to_string();
        assert!(err.contains("vz"), "{err}");
    }
}
