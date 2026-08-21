//! Backend selection, and the backend-neutral work that happens either
//! side of the [`Hypervisor`] boundary.
//!
//! Backends are stateless and per-host; per-instance state lives in
//! `~/.asterism/instances/<name>/`. Everything else in the daemon holds
//! `&dyn Hypervisor` and gates on [`Caps`](asterism_core::hv::Caps), so
//! adding a third backend is a change to [`by_id`] and nothing else.
//!
//! Which backend runs an instance is decided **once, at create**, and
//! recorded on the instance ([`asterism_core::hv::Machine`]). Two things
//! follow: a device can run qemu and vz instances side by side, and an
//! instance never silently changes hypervisor underneath its disks.

use std::path::Path;
use std::process::Command;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use anyhow::{bail, Context, Result};

use asterism_core::hv::{BootReq, DiskFormat, Hypervisor, ImageKind, ImageRef, Machine};
use asterism_core::instance::{Instance, PortForward};
use asterism_core::{image, paths, seed};

pub mod qemu;
pub mod qmp;
pub mod vz;

/// The backends this build has, constructed once.
///
/// Once, because [`Hypervisor::probe`] caches: rebuilding them per call
/// would re-run tool discovery and `codesign` on every request the daemon
/// serves.
struct Backends {
    qemu: Arc<dyn Hypervisor>,
    vz: Arc<dyn Hypervisor>,
}

fn backends() -> &'static Backends {
    static BACKENDS: OnceLock<Backends> = OnceLock::new();
    BACKENDS.get_or_init(|| Backends {
        qemu: Arc::new(qemu::Qemu::new()),
        vz: Arc::new(vz::Vz::new()),
    })
}

/// A backend by its stable id, or the list of the ones that exist.
pub fn by_id(id: &str) -> Result<Arc<dyn Hypervisor>> {
    let b = backends();
    match id {
        qemu::ID => Ok(b.qemu.clone()),
        vz::ID => Ok(b.vz.clone()),
        other => bail!(
            "no {other:?} backend in this build — there is {} and {}",
            qemu::ID,
            vz::ID
        ),
    }
}

/// The capabilities a backend must have for one create request.
///
/// This is intentionally backend-neutral. Image resolution and CLI parsing
/// turn image kind, on-disk format and published ports into facts here;
/// selection only compares those facts to [`Hypervisor::caps`]. Directory
/// shares are added later and are checked at attach time by
/// [`check_can_share`]. Adding another host OS therefore does not add OS
/// conditionals to creation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CreateRequirements {
    image_kind: ImageKind,
    /// The format the base image's bytes are *actually* in, from
    /// [`ImageRef::format`]. Every image this store manages is raw by the
    /// time it can be booted, so this only ever varies for a local file the
    /// user pointed at — `--image ./mine.qcow2`, which is theirs and is
    /// never rewritten in place.
    disk_format: DiskFormat,
    port_forward: bool,
}

impl CreateRequirements {
    pub fn new(image: &ImageRef, publish: &[PortForward]) -> Self {
        Self {
            image_kind: image.kind,
            disk_format: image.format,
            port_forward: !publish.is_empty(),
        }
    }

    fn check(self, hv: &dyn Hypervisor) -> Result<()> {
        let caps = hv.caps();
        if self.image_kind == ImageKind::OciRootfs && !caps.direct_kernel {
            bail!(
                "the {} backend cannot boot an OCI image: it is a root filesystem with \
                 no bootloader, so it needs direct kernel boot, which this backend \
                 does not provide",
                hv.id()
            );
        }
        // The format is a property of the bytes, and a backend either reads
        // them or does not: Virtualization.framework has no qcow2 at all.
        // Checked here, before a backend is recorded on the instance, because
        // an instance pinned to a backend that cannot read its own base image
        // is one that will never boot and cannot be repointed.
        if !caps.disk_formats.contains(&self.disk_format) {
            bail!(
                "the {} backend cannot read a {} disk, and this base image is one — \
                 it boots {}, so the image would have to be converted first \
                 (`qemu-img convert -O raw`)",
                hv.id(),
                self.disk_format,
                readable(caps.disk_formats)
            );
        }
        if self.port_forward && !caps.port_forward {
            bail!(
                "the {} backend gives each guest an address of its own, so there is \
                 nothing for -p to forward from this device's loopback",
                hv.id()
            );
        }
        Ok(())
    }
}

/// The disk formats a backend reads, as a phrase a refusal can end on:
/// "raw", or "raw and qcow2".
fn readable(formats: &[DiskFormat]) -> String {
    match formats {
        [] => "no disk format at all".to_owned(),
        [only] => only.to_string(),
        [rest @ .., last] => {
            let rest: Vec<String> = rest.iter().map(|f| f.to_string()).collect();
            format!("{} and {last}", rest.join(", "))
        }
    }
}

fn runnable(hv: Arc<dyn Hypervisor>, requirements: CreateRequirements) -> Result<Machine> {
    let ready = hv
        .probe()
        .with_context(|| format!("the {} backend is not runnable on this device", hv.id()))?;
    requirements.check(&*hv)?;
    Ok(Machine::new(hv.id(), &ready))
}

fn select_with(
    requested: Option<&str>,
    requirements: CreateRequirements,
    mut resolve: impl FnMut(&str) -> Result<Arc<dyn Hypervisor>>,
) -> Result<Machine> {
    if let Some(id) = requested {
        let hv = resolve(id)?;
        return runnable(hv, requirements).with_context(|| {
            format!("the explicitly requested {id} backend cannot create this instance")
        });
    }

    // VZ is the lightest path on a capable host. Capability mismatches are
    // ordinary reasons to try QEMU: OCI direct boot, loopback publishing and
    // qcow2 base images all need facilities VZ does not currently expose.
    let mut refusals = Vec::new();
    for id in [vz::ID, qemu::ID] {
        match resolve(id).and_then(|hv| runnable(hv, requirements)) {
            Ok(selection) => return Ok(selection),
            Err(error) => refusals.push(format!("{id}: {error:#}")),
        }
    }
    bail!(
        "no runnable backend can create this instance ({})",
        refusals.join("; ")
    )
}

/// Select and probe the backend for a create request.
///
/// An explicit `--backend` is forced: its own probe or capability refusal is
/// returned. The default tries the fastest/lightest capable backend now — VZ
/// first, then QEMU — and returns both reasons if neither can run the request.
pub fn select_for(requested: Option<&str>, requirements: CreateRequirements) -> Result<Machine> {
    select_with(requested, requirements, by_id)
}

/// The backend that should run `inst`: the one it was created against.
///
/// An instance records its backend, so a vz instance keeps booting under vz
/// on a device whose default is qemu. A backend this build has never heard
/// of is an error rather than a silent fallback: its disks are in whatever
/// format that backend chose.
pub fn for_instance(inst: &Instance) -> Result<Arc<dyn Hypervisor>> {
    by_id(&inst.machine.backend).with_context(|| {
        format!(
            "instance {:?} was created for the {} backend",
            inst.name, inst.machine.backend
        )
    })
}

/// The backend that booted a running guest, named on its handle.
///
/// Liveness and shutdown go through this rather than through the host
/// default: after an `astd` restart the handle is all there is, and a guest
/// booted by one backend must never be asked about by another.
pub fn for_handle(backend: &str) -> Result<Arc<dyn Hypervisor>> {
    by_id(backend)
}

/// Refuse a volume that the instance's backend could never show the guest.
///
/// Attach time is where this belongs: recording a volume that `ast up` will
/// then refuse to boot with leaves an instance that looks configured and is
/// not. Gated on [`Caps::shared_dir`](asterism_core::hv::Caps::shared_dir)
/// rather than on which backend it is.
/// Only a backend we could actually ask is allowed to refuse: on a device
/// where the hypervisor is not installed yet, `caps()` says "no sharing"
/// because it knows nothing, and that must not turn into a refusal to
/// record a volume the instance will be able to use once it is.
pub fn check_can_share(inst: &Instance) -> Result<()> {
    let hv = for_instance(inst)?;
    // An OCI guest runs the image's entrypoint under a generated init and
    // nothing else: there is no cloud-init in it to act on a mount unit, and
    // no 9p module in the kernel's initrd to mount one with.
    if inst.image_kind == ImageKind::OciRootfs {
        bail!(
            "{:?} boots an OCI image, which has no init system to mount a volume \
             with — put the volume on an instance built from a cloud image",
            inst.name
        );
    }
    if hv.probe().is_ok() && hv.caps().shared_dir.is_none() {
        bail!(
            "the {} backend on this device cannot share host directories, so a \
             volume attached to {:?} could never reach the guest — put it on an \
             instance whose backend can (qemu with 9p support, today)",
            hv.id(),
            inst.name
        );
    }
    Ok(())
}

/// Refuse, at create, an instance this backend could never boot.
///
/// Gated on [`Caps`](asterism_core::hv::Caps) rather than on which backend it
/// is, like everything else: a backend that grows direct kernel boot starts
/// accepting OCI images by saying so in its capabilities and changing nothing
/// here. Create time is where this belongs, for the same reason a volume is
/// refused at attach — an instance that looks defined and cannot boot is
/// worse than a command that says no.
pub fn check_can_boot(
    hv: &dyn Hypervisor,
    image: &ImageRef,
    publish: &[PortForward],
) -> Result<()> {
    CreateRequirements::new(image, publish).check(hv)
}

/// Resolve an image reference into the backend-neutral [`ImageRef`].
/// Image resolution is deliberately outside the backend: what a reference
/// means is a property of the catalog, not of the hypervisor.
///
/// Pure — it reports what the store holds and changes nothing. Backend
/// probing happens immediately afterwards, before the registry is changed.
pub fn image_ref(reference: &str) -> Result<ImageRef> {
    let resolved = image::resolve(reference)?;
    Ok(ImageRef {
        kind: resolved.kind(),
        name: resolved.name,
        path: resolved.path,
        format: resolved.format,
    })
}

/// The same, plus writing down what a local file currently is.
///
/// Used where an instance is being *created*: the identity of a file the
/// user pointed at has to be captured at the moment they point at it, so
/// that the boot gate has something to compare against. Recording it is
/// best-effort — a `--image` that names a file on a disk this daemon cannot
/// write next to is still a legitimate instance, and the boot gate will say
/// so plainly when it comes to it rather than failing the create.
pub fn image_ref_recording(reference: &str) -> Result<ImageRef> {
    let resolved = image::resolve(reference)?;
    if let Err(e) = resolved.record_local() {
        eprintln!("astd: could not record what {} is: {e:#}", resolved.name);
    }
    Ok(ImageRef {
        kind: resolved.kind(),
        name: resolved.name,
        path: resolved.path,
        format: resolved.format,
    })
}

/// The same, having first made sure the base image is in the format an
/// instance can actually be built from.
///
/// This is where the lazy qcow2 migration happens: a store filled by an
/// older Asterism holds `<slug>.qcow2` and no raw image, and the first `up`
/// or `snapshot` after the upgrade converts it once (BACKENDS.md §4).
/// Failing here is right — the alternative is telling the user their image
/// is not pulled when it plainly is. On a vz host it is not optional at
/// all: Virtualization.framework cannot read qcow2.
fn materialised_image_ref(reference: &str) -> Result<ImageRef> {
    let resolved = image::resolve(reference)?;
    if resolved.materialise()? {
        eprintln!("astd: converted {} to a raw base image", resolved.name);
    }
    // The last gate before a hypervisor is handed a path, and the reason
    // every other check in `verify` is worth having: an image is verified
    // when it is pulled, and then it sits in a store for weeks. This is
    // where "still the image that was pulled" is established, for a cloud
    // image, an OCI rootfs and a file the user pointed at alike.
    resolved.verify_bootable()?;
    Ok(ImageRef {
        kind: resolved.kind(),
        name: resolved.name,
        path: resolved.path,
        format: resolved.format,
    })
}

/// Assemble everything a backend needs for `inst`, without building a seed.
///
/// Enough for `prepare()` and the disk-level snapshot operations, which
/// never read the seed — so the snapshot commands do not pay for an ISO
/// build they would throw away.
pub fn disk_req(inst: &Instance) -> Result<BootReq<'_>> {
    let reference = inst
        .image
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("instance has no image — recreate it with --image"))?;
    let dir = paths::instance_dir(&inst.name);
    Ok(BootReq {
        instance: inst,
        base: materialised_image_ref(reference)?,
        seed: dir.join("seed.iso"),
        console: dir.join("console.log"),
        shares: Vec::new(),
        extra_disks: Vec::new(),
        dir,
    })
}

/// Assemble a full boot request: resolve the image, work out the shares,
/// and build the cloud-init seed. All of it backend-neutral, all of it
/// done before any backend is asked to do anything (BACKENDS.md §2).
pub fn boot_req<'a>(inst: &'a Instance, hv: &dyn Hypervisor) -> Result<BootReq<'a>> {
    let mut req = disk_req(inst)?;

    // An OCI guest has no cloud-init to hand a seed to: what a cloud image
    // learns from one — its hostname, its ssh keys, its mounts — an OCI image
    // has no way to act on. The generated init is the whole of its
    // configuration, and it was written into the filesystem at pull time.
    if req.base.kind == ImageKind::OciRootfs {
        check_can_boot(hv, &req.base, &inst.publish)?;
        return Ok(req);
    }

    let shares = seed::shares(inst);

    // Gate on the capability, not on which backend this is.
    if !shares.is_empty() && hv.caps().shared_dir.is_none() {
        anyhow::bail!(
            "the {} backend on this device cannot share host directories, so the \
             {} volume(s) attached to {:?} cannot reach the guest — detach them, \
             or run this instance on a device that can",
            hv.id(),
            shares.len(),
            inst.name
        );
    }

    // A bound instance's proxy comes up here, before the seed is written,
    // because the port it settles on is one of the things the seed has to
    // say. An instance with no bindings gets an empty config and no listener.
    let egress = crate::egress::seed_config(inst)?;

    // The backend gets to add what its own devices need — for vz, the
    // `/dev/hvc0` console no stock cloud image knows about.
    seed::ensure(&inst.name, &req.seed, &shares, hv.guest_config(), &egress)
        .context("building cloud-init seed")?;
    req.shares = shares;
    Ok(req)
}

// ---- shared with every backend ---------------------------------------------
//
// Two things every out-of-process backend needs and neither owns: growing a
// raw disk to an instance's shape, and handling the process that holds the
// guest. Both used to live in `qemu.rs`, where the second backend would
// have had to copy them.

/// Grow a raw disk to the instance's shape by truncating up.
///
/// A hole, not a write: the file claims `disk_gib` and occupies nothing
/// until the guest fills it, which is the same deal a qcow2 overlay offered
/// and the reason a 20 GiB instance costs about a gigabyte on APFS.
pub(crate) fn grow(disk: &Path, disk_gib: u64) -> Result<()> {
    let want = disk_gib * (1 << 30);
    let file = std::fs::OpenOptions::new().write(true).open(disk)?;
    let have = file.metadata()?.len();
    if have > want {
        bail!(
            "this image is {:.1} GiB, so it does not fit a {disk_gib} GiB disk — \
             create the instance with a larger --disk",
            have as f64 / (1u64 << 30) as f64
        );
    }
    file.set_len(want)?;
    Ok(())
}

/// Is the process holding this guest still there?
pub(crate) fn alive(pid: u32) -> bool {
    Command::new("kill")
        .args(["-0", &pid.to_string()])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

pub(crate) fn signal(pid: u32, sig: &str) -> Result<()> {
    Command::new("kill")
        .arg(sig)
        .arg(pid.to_string())
        .status()?;
    Ok(())
}

/// Poll until the process is gone, or the budget runs out.
pub(crate) fn wait_gone(pid: u32, budget: Duration) -> bool {
    let deadline = std::time::Instant::now() + budget;
    loop {
        if !alive(pid) {
            return true;
        }
        if std::time::Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use asterism_core::hv::{Caps, Handle, Prepared, Ready, RunState};

    struct Fake {
        id: &'static str,
        probe_error: Option<&'static str>,
        direct_kernel: bool,
        port_forward: bool,
        disk_formats: &'static [DiskFormat],
    }

    impl Hypervisor for Fake {
        fn id(&self) -> &'static str {
            self.id
        }

        fn probe(&self) -> Result<Ready> {
            if let Some(error) = self.probe_error {
                bail!(error);
            }
            Ok(Ready {
                version: "test".into(),
                accel: "test".into(),
                machine_type: format!("{}-machine", self.id),
                cpu: "host".into(),
            })
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
                direct_kernel: self.direct_kernel,
                port_forward: self.port_forward,
                guest_egress: None,
                disk_formats: self.disk_formats,
            }
        }

        fn prepare(&self, _req: &BootReq) -> Result<Prepared> {
            bail!("unused fake")
        }

        fn boot(&self, _req: &BootReq, _prep: &Prepared) -> Result<Handle> {
            bail!("unused fake")
        }

        fn stop(&self, _handle: &Handle, _deadline: Duration) -> Result<()> {
            bail!("unused fake")
        }

        fn kill(&self, _handle: &Handle) -> Result<()> {
            bail!("unused fake")
        }

        fn state(&self, _handle: &Handle) -> Result<RunState> {
            bail!("unused fake")
        }
    }

    /// A backend that reads raw disks and nothing else, which is VZ's real
    /// answer and the conservative one for a fake.
    fn fake(
        id: &'static str,
        probe_error: Option<&'static str>,
        direct_kernel: bool,
        port_forward: bool,
    ) -> Arc<dyn Hypervisor> {
        fake_reading(
            id,
            probe_error,
            direct_kernel,
            port_forward,
            &[DiskFormat::Raw],
        )
    }

    fn fake_reading(
        id: &'static str,
        probe_error: Option<&'static str>,
        direct_kernel: bool,
        port_forward: bool,
        disk_formats: &'static [DiskFormat],
    ) -> Arc<dyn Hypervisor> {
        Arc::new(Fake {
            id,
            probe_error,
            direct_kernel,
            port_forward,
            disk_formats,
        })
    }

    /// The two-backend host every selection test runs on.
    fn host(
        vz: Arc<dyn Hypervisor>,
        qemu: Arc<dyn Hypervisor>,
    ) -> impl Fn(&str) -> Result<Arc<dyn Hypervisor>> {
        move |id| match id {
            "vz" => Ok(vz.clone()),
            "qemu" => Ok(qemu.clone()),
            other => bail!("unknown backend {other:?}"),
        }
    }

    fn image(kind: ImageKind) -> ImageRef {
        ImageRef {
            name: "test-image".into(),
            path: "/images/test.raw".into(),
            format: DiskFormat::Raw,
            kind,
        }
    }

    /// The one image the store never converts: a local file the user pointed
    /// at, booted in the format it is in.
    fn local_qcow2() -> ImageRef {
        ImageRef {
            name: "/home/u/mine.qcow2".into(),
            path: "/home/u/mine.qcow2".into(),
            format: DiskFormat::Qcow2,
            kind: ImageKind::Disk,
        }
    }

    /// An image that will not fit the shape says so, rather than handing a
    /// hypervisor a disk that has silently lost its tail.
    #[test]
    fn a_disk_is_never_truncated_down() {
        let dir = tempfile::tempdir().unwrap();
        let disk = dir.path().join("disk.raw");
        std::fs::write(&disk, vec![0u8; 3 * (1 << 20)]).unwrap();
        grow(&disk, 4).unwrap();
        assert_eq!(std::fs::metadata(&disk).unwrap().len(), 4 << 30);

        let err = grow(&disk, 1).unwrap_err().to_string();
        assert!(err.contains("larger --disk"), "{err}");
        assert_eq!(
            std::fs::metadata(&disk).unwrap().len(),
            4 << 30,
            "left alone"
        );
    }

    #[test]
    fn backends_are_reached_by_id_and_unknown_ones_are_named() {
        assert_eq!(by_id("qemu").unwrap().id(), "qemu");
        assert_eq!(by_id("vz").unwrap().id(), "vz");
        let err = format!("{:#}", by_id("xen").err().expect("no xen backend"));
        assert!(err.contains("xen"), "{err}");
        assert!(err.contains("qemu") && err.contains("vz"), "{err}");
    }

    /// An OCI image is a filesystem with no bootloader, so it can only be
    /// created against a backend that boots a kernel itself — and the refusal
    /// is by capability, so a backend that grows direct kernel boot starts
    /// accepting them without a line changing here.
    #[test]
    fn an_oci_image_needs_a_backend_that_boots_a_kernel() {
        let oci = ImageRef {
            name: "docker.io/library/nginx:latest".into(),
            path: "/images/oci-abc.raw".into(),
            format: asterism_core::hv::DiskFormat::Raw,
            kind: ImageKind::OciRootfs,
        };
        let disk = ImageRef {
            kind: ImageKind::Disk,
            ..oci.clone()
        };
        let port = [PortForward {
            host: 8080,
            guest: 80,
        }];

        let qemu = by_id("qemu").unwrap();
        assert!(qemu.caps().direct_kernel && qemu.caps().port_forward);
        check_can_boot(&*qemu, &oci, &port).expect("qemu boots a kernel and forwards ports");

        let vz = by_id("vz").unwrap();
        assert!(!vz.caps().direct_kernel, "vz wires up EFI only");
        let err = check_can_boot(&*vz, &oci, &[]).unwrap_err().to_string();
        assert!(err.contains("vz"), "{err}");
        assert!(
            err.contains("direct kernel"),
            "the missing capability is named: {err}"
        );
        // ...and a cloud image on vz is exactly as fine as it ever was.
        check_can_boot(&*vz, &disk, &[]).unwrap();
        // Publishing to loopback needs a guest that is reached that way.
        assert!(check_can_boot(&*vz, &disk, &port).is_err());
    }

    #[test]
    fn the_default_prefers_runnable_capable_vz_then_falls_back_to_qemu() {
        let vz = fake("vz", None, false, false);
        let qemu = fake("qemu", None, true, true);
        let resolve = |id: &str| match id {
            "vz" => Ok(vz.clone()),
            "qemu" => Ok(qemu.clone()),
            _ => bail!("unknown backend"),
        };

        let disk = image(ImageKind::Disk);
        let selected = select_with(None, CreateRequirements::new(&disk, &[]), resolve).unwrap();
        assert_eq!(selected.backend, "vz", "the lighter capable backend wins");

        let vz = fake("vz", None, false, false);
        let qemu = fake("qemu", None, true, true);
        let oci = image(ImageKind::OciRootfs);
        let selected = select_with(None, CreateRequirements::new(&oci, &[]), |id| match id {
            "vz" => Ok(vz.clone()),
            "qemu" => Ok(qemu.clone()),
            _ => bail!("unknown backend"),
        })
        .unwrap();
        assert_eq!(selected.backend, "qemu", "capability refusal falls through");

        let vz = fake("vz", None, false, false);
        let qemu = fake("qemu", None, true, true);
        let port = [PortForward {
            host: 8080,
            guest: 80,
        }];
        let selected = select_with(None, CreateRequirements::new(&disk, &port), |id| match id {
            "vz" => Ok(vz.clone()),
            "qemu" => Ok(qemu.clone()),
            _ => bail!("unknown backend"),
        })
        .unwrap();
        assert_eq!(
            selected.backend, "qemu",
            "port forwarding is a create requirement"
        );

        let vz = fake("vz", Some("helper is unsigned"), false, false);
        let qemu = fake("qemu", None, true, true);
        let selected = select_with(None, CreateRequirements::new(&disk, &[]), |id| match id {
            "vz" => Ok(vz.clone()),
            "qemu" => Ok(qemu.clone()),
            _ => bail!("unknown backend"),
        })
        .unwrap();
        assert_eq!(selected.backend, "qemu", "probe refusal falls through");

        let vz = fake("vz", Some("unsigned helper"), false, false);
        let qemu = fake("qemu", Some("qemu missing"), true, true);
        let error = select_with(None, CreateRequirements::new(&disk, &[]), |id| match id {
            "vz" => Ok(vz.clone()),
            "qemu" => Ok(qemu.clone()),
            _ => bail!("unknown backend"),
        })
        .expect_err("neither backend is runnable");
        let error = format!("{error:#}");
        assert!(
            error.contains("vz") && error.contains("unsigned helper"),
            "{error}"
        );
        assert!(
            error.contains("qemu") && error.contains("qemu missing"),
            "{error}"
        );
    }

    #[test]
    fn an_explicit_backend_is_forced_and_explains_probe_or_capability_failure() {
        let disk = image(ImageKind::Disk);
        let broken = fake("vz", Some("helper is unsigned"), false, false);
        let error = select_with(Some("vz"), CreateRequirements::new(&disk, &[]), |_| {
            Ok(broken.clone())
        })
        .expect_err("the forced broken backend must fail");
        let error = format!("{error:#}");
        assert!(error.contains("explicitly requested vz"), "{error}");
        assert!(error.contains("helper is unsigned"), "{error}");

        let oci = image(ImageKind::OciRootfs);
        let vz = fake("vz", None, false, false);
        let error = select_with(Some("vz"), CreateRequirements::new(&oci, &[]), |_| {
            Ok(vz.clone())
        })
        .expect_err("the forced incapable backend must fail");
        let error = format!("{error:#}");
        assert!(error.contains("explicitly requested vz"), "{error}");
        assert!(error.contains("direct kernel"), "{error}");

        assert!(select_for(
            Some("nothing-like-this"),
            CreateRequirements::new(&disk, &[])
        )
        .is_err());
    }

    /// The format of the bytes is a create requirement like any other.
    ///
    /// A local `--image ./mine.qcow2` is the one image the store never
    /// rewrites, and Virtualization.framework cannot read qcow2 at all — so
    /// on a Mac, where VZ is tried first and probes perfectly well, the
    /// default has to fall through to QEMU rather than record a backend that
    /// could never open the instance's own base image. Forcing VZ is refused
    /// at create, where it can still be acted on.
    #[test]
    fn a_local_qcow2_chooses_the_backend_that_reads_it() {
        // The fakes are shaped like the real backends on that host.
        assert_eq!(by_id("vz").unwrap().caps().disk_formats, &[DiskFormat::Raw]);
        assert!(by_id("qemu")
            .unwrap()
            .caps()
            .disk_formats
            .contains(&DiskFormat::Qcow2));

        let vz = fake("vz", None, false, false);
        let qemu = fake_reading(
            "qemu",
            None,
            true,
            true,
            &[DiskFormat::Raw, DiskFormat::Qcow2],
        );
        let qcow2 = local_qcow2();

        let selected = select_with(
            None,
            CreateRequirements::new(&qcow2, &[]),
            host(vz.clone(), qemu.clone()),
        )
        .unwrap();
        assert_eq!(
            selected.backend, "qemu",
            "the backend that can read the image wins"
        );

        // ...and a raw image on the same host still goes to VZ, so this is a
        // fall-through and not a preference that has quietly changed.
        let raw = image(ImageKind::Disk);
        let selected = select_with(
            None,
            CreateRequirements::new(&raw, &[]),
            host(vz.clone(), qemu.clone()),
        )
        .unwrap();
        assert_eq!(selected.backend, "vz");

        // Explicit means explicit: VZ refuses, naming the format it cannot
        // read and the ones it can, instead of being silently swapped out.
        let error = select_with(
            Some("vz"),
            CreateRequirements::new(&qcow2, &[]),
            host(vz.clone(), qemu.clone()),
        )
        .expect_err("vz cannot read qcow2");
        let error = format!("{error:#}");
        assert!(error.contains("explicitly requested vz"), "{error}");
        assert!(
            error.contains("qcow2"),
            "the format that was refused: {error}"
        );
        assert!(error.contains("raw"), "and the one it does read: {error}");

        // A host where nothing reads the image says so once, with both
        // reasons, rather than recording a backend and failing at boot.
        let error = select_with(
            None,
            CreateRequirements::new(&qcow2, &[]),
            host(vz, fake("qemu", None, true, true)),
        )
        .expect_err("neither backend reads qcow2");
        let error = format!("{error:#}");
        assert!(error.contains("vz") && error.contains("qemu"), "{error}");
        assert_eq!(
            error.matches("qcow2").count(),
            2,
            "one reason per backend: {error}"
        );
    }

    /// The phrase a refusal ends on lists what the backend does read, so a
    /// user is told what would work rather than only what did not.
    #[test]
    fn the_formats_a_backend_reads_are_named_in_its_refusal() {
        assert_eq!(readable(&[DiskFormat::Raw]), "raw");
        assert_eq!(
            readable(&[DiskFormat::Raw, DiskFormat::Qcow2]),
            "raw and qcow2"
        );
        assert_eq!(
            readable(&[DiskFormat::Raw, DiskFormat::Qcow2, DiskFormat::Asif]),
            "raw, qcow2 and asif"
        );
        assert!(readable(&[]).contains("no disk format"));
    }

    /// An instance carries its backend, and that is what runs it — not the
    /// device's default, which may well be something else.
    #[test]
    fn an_instance_is_run_by_the_backend_it_was_created_against() {
        let mut inst = asterism_core::registry::Shard::load(
            &std::env::temp_dir().join("nonexistent-registry.json"),
        )
        .unwrap()
        .create(
            "dev",
            &asterism_core::instance::local_host(),
            "debian:13",
            Default::default(),
            Machine {
                backend: "qemu".into(),
                machine_type: "virt".into(),
                cpu: "host".into(),
                hv_version: "11.0.0".into(),
            },
        )
        .unwrap();

        assert_eq!(for_instance(&inst).unwrap().id(), "qemu");

        inst.machine = Machine {
            backend: "vz".into(),
            machine_type: "generic".into(),
            cpu: "host".into(),
            hv_version: "15.6.1".into(),
        };
        assert_eq!(for_instance(&inst).unwrap().id(), "vz");
        assert_eq!(for_handle("vz").unwrap().id(), "vz");

        // A vz instance cannot take a volume — but only a device that can
        // actually run vz is entitled to say so.
        inst.volumes.push(asterism_core::instance::Volume::dir(
            "/tank/media",
            &asterism_core::instance::local_host(),
            None,
        ));
        if by_id("vz").unwrap().probe().is_ok() {
            let err = check_can_share(&inst).unwrap_err().to_string();
            assert!(err.contains("vz"), "{err}");
            assert!(err.contains("9p"), "{err}");
        } else {
            assert!(
                check_can_share(&inst).is_ok(),
                "a backend we cannot ask cannot refuse"
            );
        }

        inst.machine = Machine {
            backend: "qemu".into(),
            machine_type: "virt".into(),
            cpu: "host".into(),
            hv_version: "11.0.0".into(),
        };
        assert_eq!(for_instance(&inst).unwrap().id(), "qemu");

        inst.machine.backend = "xen".into();
        let error = for_instance(&inst)
            .err()
            .expect("xen is not available")
            .to_string();
        assert!(error.contains("created for the xen backend"), "{error}");
    }
}
