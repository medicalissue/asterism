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

use asterism_core::hv::{BootReq, Hypervisor, ImageKind, ImageRef, Machine};
use asterism_core::instance::{Instance, PortForward};
use asterism_core::{image, paths, seed};

pub mod qemu;
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
        other => bail!("no {other:?} backend in this build — there is {} and {}", qemu::ID, vz::ID),
    }
}

/// The backend a new instance gets when nobody asks for one.
///
/// QEMU everywhere, deliberately: BACKENDS.md §7 ships vz opt-in
/// (`ast create --backend vz`) and promotes it to the macOS default only
/// after it has survived a release. `$ASTERISM_BACKEND` moves the default
/// for a whole daemon, which is what the vz end-to-end test uses and what
/// anyone trying vz on everything wants.
pub fn select() -> Arc<dyn Hypervisor> {
    match std::env::var("ASTERISM_BACKEND").ok().and_then(|id| by_id(&id).ok()) {
        Some(hv) => hv,
        None => backends().qemu.clone(),
    }
}

/// The backend to create an instance against.
///
/// An explicit `--backend` is probed here, at create, so that asking for a
/// backend this device cannot run says why immediately — the unsigned
/// helper, the too-old macOS — rather than at the first `ast up`. The
/// default path deliberately does not probe: defining instances on a device
/// with no hypervisor installed yet has always worked, and should.
pub fn select_for(requested: Option<&str>) -> Result<Arc<dyn Hypervisor>> {
    let Some(id) = requested else {
        return Ok(select());
    };
    let hv = by_id(id)?;
    hv.probe()
        .with_context(|| format!("this device cannot run the {id} backend"))?;
    Ok(hv)
}

/// The backend that should run `inst`: the one it was created against.
///
/// An instance records its backend, so a vz instance keeps booting under vz
/// on a device whose default is qemu. A backend this build has never heard
/// of is an error rather than a silent fallback: its disks are in whatever
/// format that backend chose.
pub fn for_instance(inst: &Instance) -> Result<Arc<dyn Hypervisor>> {
    match &inst.machine {
        Some(machine) => by_id(&machine.backend).with_context(|| {
            format!("instance {:?} was created for the {} backend", inst.name, machine.backend)
        }),
        None => Ok(select()),
    }
}

/// The backend that booted a running guest, named on its handle.
///
/// Liveness and shutdown go through this rather than through the host
/// default: after an `astd` restart the handle is all there is, and a guest
/// booted by one backend must never be asked about by another.
pub fn for_handle(backend: &str) -> Result<Arc<dyn Hypervisor>> {
    by_id(backend)
}

/// The machine identity to record on a new instance.
///
/// Best effort: a host with no hypervisor installed can still define
/// instances, and finds out at `ast up`. That keeps `ast create` working
/// exactly as it did before this was recorded at all.
pub fn machine_identity(hv: &dyn Hypervisor) -> Option<Machine> {
    hv.probe().ok().map(|ready| Machine::new(hv.id(), &ready))
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
pub fn check_can_boot(hv: &dyn Hypervisor, image: &ImageRef, publish: &[PortForward]) -> Result<()> {
    let caps = hv.caps();
    if image.kind == ImageKind::OciRootfs && !caps.direct_kernel {
        bail!(
            "the {} backend cannot boot {} — an OCI image is a root filesystem with \
             no bootloader, so it needs a kernel booted directly, which this backend \
             does not do yet: create it with --backend qemu",
            hv.id(),
            image.name
        );
    }
    if !publish.is_empty() && !caps.port_forward {
        bail!(
            "the {} backend gives each guest an address of its own, so there is \
             nothing for -p to forward from this device's loopback",
            hv.id()
        );
    }
    Ok(())
}

/// Resolve an image reference into the backend-neutral [`ImageRef`].
/// Image resolution is deliberately outside the backend: what a reference
/// means is a property of the catalog, not of the hypervisor.
///
/// Pure — it reports what the store holds and changes nothing, so
/// `ast create` still works on a device with no hypervisor installed.
pub fn image_ref(reference: &str) -> Result<ImageRef> {
    let resolved = image::resolve(reference)?;
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

    // The backend gets to add what its own devices need — for vz, the
    // `/dev/hvc0` console no stock cloud image knows about.
    seed::ensure(&inst.name, &req.seed, &shares, hv.guest_config())
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
    Command::new("kill").arg(sig).arg(pid.to_string()).status()?;
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
        assert_eq!(std::fs::metadata(&disk).unwrap().len(), 4 << 30, "left alone");
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
        let disk = ImageRef { kind: ImageKind::Disk, ..oci.clone() };
        let port = [PortForward { host: 8080, guest: 80 }];

        let qemu = by_id("qemu").unwrap();
        assert!(qemu.caps().direct_kernel && qemu.caps().port_forward);
        check_can_boot(&*qemu, &oci, &port).expect("qemu boots a kernel and forwards ports");

        let vz = by_id("vz").unwrap();
        assert!(!vz.caps().direct_kernel, "vz wires up EFI only");
        let err = check_can_boot(&*vz, &oci, &[]).unwrap_err().to_string();
        assert!(err.contains("vz"), "{err}");
        assert!(err.contains("--backend qemu"), "the way out is in the message: {err}");
        // ...and a cloud image on vz is exactly as fine as it ever was.
        check_can_boot(&*vz, &disk, &[]).unwrap();
        // Publishing to loopback needs a guest that is reached that way.
        assert!(check_can_boot(&*vz, &disk, &port).is_err());
    }

    /// The default has to stay qemu until vz has survived a release
    /// (BACKENDS.md §7), whatever host this is built on.
    #[test]
    fn the_default_backend_is_qemu() {
        assert_eq!(select().id(), "qemu");
        assert_eq!(select_for(None).unwrap().id(), "qemu");
        assert!(select_for(Some("nothing-like-this")).is_err());
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
            None,
        )
        .unwrap();

        // Nothing recorded: an instance from before this existed falls back
        // to the device default rather than refusing to boot.
        assert_eq!(for_instance(&inst).unwrap().id(), select().id());

        inst.machine = Some(Machine {
            backend: "vz".into(),
            machine_type: "generic".into(),
            cpu: "host".into(),
            hv_version: "15.6.1".into(),
        });
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
            assert!(check_can_share(&inst).is_ok(), "a backend we cannot ask cannot refuse");
        }

        inst.machine = Some(Machine {
            backend: "qemu".into(),
            machine_type: "virt".into(),
            cpu: "host".into(),
            hv_version: "11.0.0".into(),
        });
        assert_eq!(for_instance(&inst).unwrap().id(), "qemu");
    }
}
