//! The hypervisor boundary.
//!
//! Everything the rest of Asterism is allowed to know about a running guest
//! lives in this module. `astd` holds a `dyn Hypervisor`, hands it a
//! [`BootReq`], gets back a [`Handle`], and gates optional behaviour on
//! [`Caps`] — never on [`Hypervisor::id`]. Adding a backend means
//! implementing this trait and nothing else.
//!
//! See `docs/BACKENDS.md` for why the boundary sits exactly here.

use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};

use crate::instance::Instance;
use crate::seed::Share;
use crate::snapshot::Snapshot;

// ---- disks -----------------------------------------------------------------

/// On-disk format of a virtual disk. Not every backend reads every format:
/// Virtualization.framework has no qcow2 at all, which is why this is data
/// on the disk rather than an assumption in the boot code.
///
/// * `Raw` is the one every backend can read, and what Asterism stores and
///   creates: copy-on-write comes from the filesystem (`clonefile(2)` on
///   APFS) rather than from the format.
/// * `Qcow2` is legacy — instances created before that, and disk images a
///   user points at directly. QEMU still boots them; VZ never will.
/// * `Asif` is Apple's own sparse format (macOS 26+), an opportunistic
///   upgrade for VZ hosts and not created yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiskFormat {
    Raw,
    Qcow2,
    Asif,
}

impl DiskFormat {
    /// The name a `format=` option knows this by.
    pub fn as_str(self) -> &'static str {
        match self {
            DiskFormat::Raw => "raw",
            DiskFormat::Qcow2 => "qcow2",
            DiskFormat::Asif => "asif",
        }
    }
}

impl std::fmt::Display for DiskFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A disk to put in front of the guest.
///
/// `Nbd` and `NbdUnix` are how a volume on another device arrives — QEMU has
/// a built-in NBD client and VZ has
/// `VZNetworkBlockDeviceStorageDeviceAttachment`, so it is the one remote
/// disk mechanism both backends can serve.
///
/// `NbdUnix` is the one Asterism actually issues, and the difference is the
/// whole security story: the export never binds a TCP port anywhere. The
/// provider serves it on a unix socket, `astd` splices that socket over an
/// authenticated QUIC stream, and the consumer's `astd` presents *another*
/// unix socket on the machine the guest is running on. Nothing on either
/// device is reachable from the LAN. `Nbd` stays for a url a user hands us
/// for an NBD server they already run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DiskSpec {
    File { path: PathBuf, format: DiskFormat, readonly: bool },
    Nbd { url: String, readonly: bool },
    /// An NBD export reached over a local unix socket, under a named export.
    /// The export name carries the volume's lease epoch, so a socket that
    /// outlives its lease serves nothing.
    NbdUnix { socket: PathBuf, export: String, readonly: bool },
    Block { path: PathBuf, readonly: bool },
}

/// What a base image *is*, which decides how a machine gets into it.
///
/// A cloud image is a whole disk: partition table, bootloader, kernel, the
/// firmware finds it and that is the end of the backend's involvement. An OCI
/// image is a root filesystem and nothing else — MODEL.md makes container
/// images an image *source*, not a second kind of instance — so a backend
/// booting one has to supply the kernel itself ([`crate::oci`]).
///
/// Data on the image and recorded on the instance, rather than inferred from
/// the reference: what a name meant when the instance was created is not
/// something to re-derive at every boot.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImageKind {
    /// A bootable disk. Everything that is not a container image.
    #[default]
    Disk,
    /// An unpacked OCI/Docker image: a filesystem with no bootloader.
    OciRootfs,
}

impl ImageKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ImageKind::Disk => "disk",
            ImageKind::OciRootfs => "oci",
        }
    }
}

impl std::fmt::Display for ImageKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A base image that has already been pulled, and the format its bytes are in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageRef {
    /// Canonical name, for error messages.
    pub name: String,
    pub path: PathBuf,
    pub format: DiskFormat,
    /// Whether this is a disk to boot or a filesystem needing a kernel.
    pub kind: ImageKind,
}

/// Firmware and its per-instance variable store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Firmware {
    /// Read-only firmware code.
    pub code: PathBuf,
    /// Writable variable store belonging to this instance.
    pub vars: PathBuf,
}

/// A kernel to boot directly, for a root filesystem that carries none.
///
/// The alternative to firmware, not a companion to it: a machine either finds
/// a bootloader on its disk or is handed a kernel. `cmdline` is the backend's
/// to write, because half of what goes on it — the root device, the console,
/// the guest's address — is a fact about the machine the backend just built.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectKernel {
    pub kernel: PathBuf,
    pub initrd: Option<PathBuf>,
    pub cmdline: String,
}

/// What [`Hypervisor::prepare`] materialised on disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Prepared {
    pub root: DiskSpec,
    pub firmware: Option<Firmware>,
    /// Set when this guest boots a kernel rather than firmware — an OCI
    /// rootfs, which has no bootloader of its own.
    pub kernel: Option<DirectKernel>,
}

impl Prepared {
    /// The root disk's path, for the disk-level operations that work on a
    /// stopped instance.
    pub fn root_path(&self) -> Result<&std::path::Path> {
        match &self.root {
            DiskSpec::File { path, .. } | DiskSpec::Block { path, .. } => Ok(path),
            DiskSpec::Nbd { url, .. } => bail!("the root disk is remote ({url}), not a local file"),
            DiskSpec::NbdUnix { export, .. } => {
                bail!("the root disk is a remote volume ({export}), not a local file")
            }
        }
    }
}

// ---- handles ---------------------------------------------------------------

/// How the daemon talks to a running guest's monitor.
///
/// This is *data on the handle*, deliberately: reconstructing it from the
/// instance name (as the pre-refactor `stop(name, pid)` did) hardcodes one
/// backend's naming convention into the rest of the daemon.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ControlChannel {
    Qmp { path: PathBuf },
    HttpApi { path: PathBuf },
    Rpc { path: PathBuf },
}

impl ControlChannel {
    pub fn path(&self) -> &std::path::Path {
        match self {
            ControlChannel::Qmp { path }
            | ControlChannel::HttpApi { path }
            | ControlChannel::Rpc { path } => path,
        }
    }
}

/// How `ast ssh` reaches the guest — the hostfwd assumption, generalized.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum GuestEndpoint {
    /// QEMU user-net / gvproxy: a loopback port on this host.
    HostForward { ssh_port: u16 },
    /// VZ NAT, bridged, or mesh-routed: the guest has its own address.
    GuestAddr { addr: IpAddr },
}

impl GuestEndpoint {
    /// Where an ssh client should connect: host and port.
    pub fn ssh_target(&self) -> (String, u16) {
        match self {
            GuestEndpoint::HostForward { ssh_port } => ("127.0.0.1".to_owned(), *ssh_port),
            GuestEndpoint::GuestAddr { addr } => (addr.to_string(), 22),
        }
    }
}

impl std::fmt::Display for GuestEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (host, port) = self.ssh_target();
        write!(f, "{host}:{port}")
    }
}

/// A running guest, as persisted in the registry. Replaces the old
/// `Booted { pid, ssh_port }`, which hardcoded "a process on this host
/// reachable on a loopback port".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Handle {
    /// Backend that owns this guest — the id it was booted with.
    pub backend: String,
    /// `None` for a backend with no child process of its own.
    #[serde(default)]
    pub pid: Option<u32>,
    pub ctl: ControlChannel,
    pub endpoint: GuestEndpoint,
    /// Unix seconds, matching `Instance::created_at`.
    pub started_at: u64,
}

/// Liveness of a handle reloaded from the registry. A handle is never
/// assumed valid: astd may have restarted, the host may have rebooted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunState {
    Running,
    Stopped,
}

// ---- capability and identity ----------------------------------------------

/// Kind of host-directory sharing a backend offers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShareKind {
    Virtiofs,
    NinePfs,
}

/// What a backend can do. Callers gate on this, never on [`Hypervisor::id`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Caps {
    /// Save RAM + device state of a *running* guest.
    pub live_snapshot: bool,
    /// Clone or roll back a *stopped* disk cheaply.
    pub disk_snapshot: bool,
    pub live_migration: bool,
    pub disk_hotplug: bool,
    pub shared_dir: Option<ShareKind>,
    /// Can consume [`DiskSpec::Nbd`] natively.
    pub nbd_disks: bool,
    /// Can run a guest of a non-host architecture.
    pub foreign_arch: bool,
    /// Can boot a kernel handed to it, for a root filesystem that has no
    /// bootloader of its own. What an OCI image needs
    /// ([`ImageKind::OciRootfs`]).
    pub direct_kernel: bool,
    /// Can publish a guest port on this host's loopback. True where the
    /// guest is reached through a host forward rather than at an address of
    /// its own.
    pub port_forward: bool,
    pub disk_formats: &'static [DiskFormat],
}

/// What [`Hypervisor::probe`] found: this host can run this backend, and
/// these are the facts worth recording on an instance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ready {
    /// Hypervisor version, e.g. `11.0.0`.
    pub version: String,
    /// Accelerator in use: `hvf`, `kvm`, `whpx`.
    pub accel: String,
    pub machine_type: String,
    pub cpu: String,
}

/// The machine an instance was defined against, recorded at create time.
///
/// Live migration only ever works between compatible pairs — same backend,
/// same major hypervisor version (BACKENDS.md §5) — so this is part of an
/// instance's identity, not incidental runtime detail.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Machine {
    pub backend: String,
    pub machine_type: String,
    pub cpu: String,
    pub hv_version: String,
}

impl Machine {
    pub fn new(backend: &str, ready: &Ready) -> Self {
        Machine {
            backend: backend.to_owned(),
            machine_type: ready.machine_type.clone(),
            cpu: ready.cpu.clone(),
            hv_version: ready.version.clone(),
        }
    }
}

impl std::fmt::Display for Machine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} {} ({}, cpu {})",
            self.backend, self.hv_version, self.machine_type, self.cpu
        )
    }
}

// ---- requests --------------------------------------------------------------

/// Everything a backend needs to prepare and boot one instance.
///
/// Note what is *already resolved* here: the image is pulled, the seed is
/// built. Backends consume these, they do not go looking for them.
pub struct BootReq<'a> {
    pub instance: &'a Instance,
    /// `~/.asterism/instances/<name>`.
    pub dir: PathBuf,
    pub base: ImageRef,
    /// cloud-init NoCloud ISO, built backend-neutrally by [`crate::seed`].
    /// Required by [`Hypervisor::boot`]; [`Hypervisor::prepare`] and the
    /// disk-level operations never read it, so paths that only touch disks
    /// may name a seed that has not been built.
    pub seed: PathBuf,
    /// Host directories to share into the guest. Only meaningful when
    /// [`Caps::shared_dir`] is `Some`.
    pub shares: Vec<Share>,
    /// Attached volumes that arrive as disks, including remote ones.
    pub extra_disks: Vec<DiskSpec>,
    pub console: PathBuf,
}

/// Opaque snapshot identity. For QEMU this is a qcow2 internal snapshot tag.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotId(pub String);

impl std::fmt::Display for SnapshotId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Where a live migration sends its stream. Placeholder until the mesh
/// exists (BACKENDS.md §5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrationTarget {
    pub url: String,
}

/// Where a live migration arrives from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrationSource {
    pub url: String,
}

/// Total budget `stop()` has to get a guest down before it is killed.
/// Split three ways: a graceful request, then SIGTERM, then SIGKILL.
pub const STOP_DEADLINE: Duration = Duration::from_secs(40);

/// The error every capability-gated method returns when it is not offered.
/// Phrased for a user, since it reaches one.
pub fn unsupported<T>(backend: &str, what: &str) -> Result<T> {
    bail!("the {backend} backend cannot {what}")
}

// ---- the trait -------------------------------------------------------------

pub trait Hypervisor: Send + Sync {
    /// Stable id persisted on the instance: "qemu", "vz", "chv", "whpx".
    fn id(&self) -> &'static str;

    /// Tooling present, accelerator usable, entitlements in place.
    /// Cheap: implementations cache.
    fn probe(&self) -> Result<Ready>;

    /// What this backend can do — callers must gate on this, never on `id()`.
    fn caps(&self) -> Caps;

    /// Cloud-config every guest of this backend needs, appended to the seed
    /// [`crate::seed`] builds.
    ///
    /// Empty for a backend whose devices a stock cloud image already knows
    /// about, which is the normal case and the default. It exists for the
    /// one thing that is genuinely a property of the *hypervisor* rather
    /// than of the image: Virtualization.framework's only serial device is
    /// a virtio console at `/dev/hvc0`, and no cloud image's kernel cmdline
    /// mentions it (BACKENDS.md §4, "What pull time cannot fix"), so the vz
    /// backend has the guest put back what the image is missing.
    ///
    /// Backend-neutral callers reach this through the trait rather than
    /// asking which backend they hold, for the same reason they gate on
    /// [`Caps`] rather than on [`Hypervisor::id`].
    fn guest_config(&self) -> &'static str {
        ""
    }

    /// Create anything missing on disk: root overlay, firmware vars.
    /// Idempotent.
    fn prepare(&self, req: &BootReq) -> Result<Prepared>;

    /// Start the guest. Must not return until it is running (or failed).
    fn boot(&self, req: &BootReq, prep: &Prepared) -> Result<Handle>;

    /// Graceful shutdown request, then escalate, then hard kill by `deadline`.
    fn stop(&self, h: &Handle, deadline: Duration) -> Result<()>;

    /// Immediate termination — for `ast down --force` and crash cleanup.
    fn kill(&self, h: &Handle) -> Result<()>;

    /// Liveness for a handle reloaded from the registry after an astd
    /// restart. Never assumes the handle is still valid.
    fn state(&self, h: &Handle) -> Result<RunState>;

    // ---- capability-gated; default impls refuse ----------------------------

    /// Live snapshot: RAM + device state of a running guest.
    /// Gated on [`Caps::live_snapshot`].
    fn snapshot(&self, _h: &Handle, _tag: &str) -> Result<SnapshotId> {
        unsupported(self.id(), "snapshot a running guest")
    }

    /// Resume from a live snapshot, booting the guest.
    /// Gated on [`Caps::live_snapshot`].
    fn restore(&self, _req: &BootReq, _snap: &SnapshotId) -> Result<Handle> {
        unsupported(self.id(), "restore a running guest from a snapshot")
    }

    /// Disk snapshot of a *stopped* instance. Takes the prepared disks
    /// rather than a [`Handle`], because by definition there is no running
    /// guest to hold one (BACKENDS.md §4 splits the two).
    /// Gated on [`Caps::disk_snapshot`].
    fn disk_snapshot(&self, _prep: &Prepared, _tag: &str) -> Result<SnapshotId> {
        unsupported(self.id(), "snapshot a stopped disk")
    }

    /// Snapshots on a prepared disk. Reads only, so it stays available
    /// while a guest runs. Gated on [`Caps::disk_snapshot`].
    fn disk_snapshot_list(&self, _prep: &Prepared) -> Result<Vec<Snapshot>> {
        unsupported(self.id(), "list disk snapshots")
    }

    /// Roll a stopped disk back. Gated on [`Caps::disk_snapshot`].
    fn disk_restore(&self, _prep: &Prepared, _snap: &SnapshotId) -> Result<()> {
        unsupported(self.id(), "roll a disk back to a snapshot")
    }

    /// Delete one snapshot, leaving the disk and the others alone.
    /// Gated on [`Caps::disk_snapshot`].
    fn disk_snapshot_remove(&self, _prep: &Prepared, _snap: &SnapshotId) -> Result<()> {
        unsupported(self.id(), "delete a disk snapshot")
    }

    /// Gated on [`Caps::disk_hotplug`].
    fn attach_disk(&self, _h: &Handle, _disk: &DiskSpec) -> Result<()> {
        unsupported(self.id(), "attach a disk to a running guest")
    }

    /// Gated on [`Caps::live_migration`].
    fn migrate_out(&self, _h: &Handle, _to: MigrationTarget) -> Result<()> {
        unsupported(self.id(), "migrate a running guest out")
    }

    /// Gated on [`Caps::live_migration`].
    fn migrate_in(&self, _req: &BootReq, _from: MigrationSource) -> Result<Handle> {
        unsupported(self.id(), "receive a migrating guest")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ssh_targets_come_from_the_endpoint_not_the_backend() {
        let fwd = GuestEndpoint::HostForward { ssh_port: 22022 };
        assert_eq!(fwd.ssh_target(), ("127.0.0.1".to_owned(), 22022));
        assert_eq!(fwd.to_string(), "127.0.0.1:22022");

        let direct = GuestEndpoint::GuestAddr { addr: "192.168.64.7".parse().unwrap() };
        assert_eq!(direct.ssh_target(), ("192.168.64.7".to_owned(), 22));
        assert_eq!(direct.to_string(), "192.168.64.7:22");
    }

    #[test]
    fn a_handle_round_trips_through_the_registry_format() {
        let h = Handle {
            backend: "qemu".into(),
            pid: Some(4242),
            ctl: ControlChannel::Qmp { path: "/tmp/qmp.sock".into() },
            endpoint: GuestEndpoint::HostForward { ssh_port: 22022 },
            started_at: 1_700_000_000,
        };
        let json = serde_json::to_string(&h).unwrap();
        assert_eq!(h, serde_json::from_str::<Handle>(&json).unwrap());
        // The control path is data on the handle, not a naming convention.
        assert!(json.contains("/tmp/qmp.sock"));
    }

    #[test]
    fn the_default_impls_refuse_by_name() {
        struct Bare;
        impl Hypervisor for Bare {
            fn id(&self) -> &'static str {
                "bare"
            }
            fn probe(&self) -> Result<Ready> {
                unimplemented!()
            }
            fn caps(&self) -> Caps {
                Caps {
                    live_snapshot: false,
                    disk_snapshot: false,
                    live_migration: false,
                    disk_hotplug: false,
                    shared_dir: None,
                    nbd_disks: false,
                    foreign_arch: false,
                    direct_kernel: false,
                    port_forward: false,
                    disk_formats: &[DiskFormat::Raw],
                }
            }
            fn prepare(&self, _: &BootReq) -> Result<Prepared> {
                unimplemented!()
            }
            fn boot(&self, _: &BootReq, _: &Prepared) -> Result<Handle> {
                unimplemented!()
            }
            fn stop(&self, _: &Handle, _: Duration) -> Result<()> {
                unimplemented!()
            }
            fn kill(&self, _: &Handle) -> Result<()> {
                unimplemented!()
            }
            fn state(&self, _: &Handle) -> Result<RunState> {
                unimplemented!()
            }
        }

        let prep = Prepared {
            root: DiskSpec::File {
                path: "/tmp/d.raw".into(),
                format: DiskFormat::Raw,
                readonly: false,
            },
            firmware: None,
            kernel: None,
        };
        let err = Bare.disk_snapshot(&prep, "x").unwrap_err().to_string();
        assert!(err.contains("bare"), "the message names the backend: {err}");
        assert!(Bare.disk_snapshot_list(&prep).is_err());
        // A backend whose guests need nothing added says nothing, and the
        // seed builder folds that in as no change at all.
        assert_eq!(Bare.guest_config(), "");
    }

    #[test]
    fn a_remote_root_disk_has_no_local_path() {
        let prep = Prepared {
            root: DiskSpec::Nbd { url: "nbd://desktop/dev".into(), readonly: false },
            firmware: None,
            kernel: None,
        };
        assert!(prep.root_path().is_err());
    }
}
