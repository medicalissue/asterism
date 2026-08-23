//! Swapping an instance's cpu part onto another device — the offline
//! migration of `docs/ROADMAP.md` Phase 6, in the vocabulary of
//! `docs/MODEL.md`.
//!
//! An instance is a computer assembled from a pool of parts, and cpu/ram is
//! one part of it. Which device supplies that part is a mutable attribute of
//! the instance, not a relationship the device has to it, so
//! `ast set dev cpu desktop` changes one line of a parts table. The
//! instance's identity — its name, its id, its snapshots — is orbit-global
//! and does not move, because it was never on a device to begin with.
//!
//! What *does* move is bytes. The disk defaults to the device supplying
//! cpu/ram and follows it, one copy and one writer throughout.
//!
//! # What crosses the wire
//!
//! Not the distro. Base images are content-addressed and cached per device,
//! so the target either has the same base already or fetches it **from the
//! source over the mesh** rather than from the internet — a peer fetch, which
//! is what MODEL.md's storage rule asks for. What is left is the instance
//! directory: the root disk, the EFI variable store, the cloud-init seed and
//! its fingerprint, and the snapshots.
//!
//! The root disk is where the size is, and it is nearly all hole. It was made
//! with `clonefile(2)` from the base and then truncated up to the instance's
//! shape, so a 10 GiB disk holds what the guest has actually written plus
//! what it shares with the base. [`asterism_core::cow::extents`] walks it with
//! `SEEK_DATA`/`SEEK_HOLE` and only the allocated ranges are sent; the holes
//! are reconstructed on the far side by creating the file at the same length
//! and writing only where there was data. That is the honest v1 delta: it is
//! the divergence *plus* whatever the clone still shares with the base, and
//! the obvious next step is to skip ranges the target could read out of its
//! own copy of that base. It is not the naive answer, which would be to send
//! ten gigabytes of zeroes.
//!
//! Snapshots cost the same way, and for now they cost it separately: locally a
//! snapshot is a `clonefile(2)` of the disk and occupies almost nothing, but
//! on the wire it is its own set of allocated ranges. Sending a range once and
//! cloning it on the far side is the same optimisation as the one above,
//! wearing a different hat.
//!
//! # Two phases, and an epoch
//!
//! There must never be two bootable copies. So:
//!
//! 1. **Prepare.** The source marks the instance [`Moving`] at `epoch + 1`
//!    and refuses to boot it. Its row is still the authoritative one.
//! 2. **Transfer.** The target writes into a *staging* directory whose name
//!    no instance can have. Nothing lists it, nothing boots it, and a daemon
//!    that dies in the middle leaves it there to be swept.
//! 3. **Commit, target.** The target checks what arrived against the manifest
//!    — every file's length, every file's allocated byte count — renames the
//!    staging directory into place and writes its shard row with itself
//!    supplying cpu, at the new epoch. Only now does a second copy exist, and
//!    the source's is already fenced.
//! 4. **Commit, source.** The source drops its row and its bytes, and leaves
//!    a note so that asking it directly gets "moved to desktop" rather than
//!    "no such instance".
//!
//! Any failure before step 3's ack is an abort: the target's staging
//! directory goes, the source's fence comes off, and the source's row — which
//! never stopped being the authoritative one — is authoritative again. The
//! epoch is what settles the case nothing else can: two rows for one instance
//! id, from two devices that could not see each other, are decided by the
//! higher number.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};

use asterism_core::cow;
use asterism_core::durable;
use asterism_core::instance::{now_unix, Instance, Moving, Status, VolumeKind};
use asterism_core::paths;
use asterism_core::protocol::{BaseImage, MoveFile, MoveManifest, Request, Response};
use asterism_core::registry::Shard;
use asterism_core::verify::Digest;
use asterism_core::{image, verify};

use crate::backend;
use crate::mesh::{ClientIo, Mesh};
use crate::Node;

/// Marks a directory that holds a half-arrived instance. Instance names are
/// ascii letters, digits and `-`, so a name with this in it can never be one
/// — which is exactly why the staging directory is safe to leave lying
/// around: nothing can resolve to it.
pub const STAGING: &str = ".moving-";

/// How long a device remembers that an instance left it.
///
/// A cache note and nothing more. It exists so that `ast --device laptop
/// status dev` says "moved to desktop" for a while instead of "no instance
/// named dev in this orbit", which would be true of that shard and useless to
/// the person reading it. Every path that matters resolves across the orbit
/// and finds the real row.
const NOTE_TTL_SECS: u64 = 24 * 60 * 60;

// ---- the plane -------------------------------------------------------------
//
// Same shape as `crate::volume`'s, and for the same reason: the target's half
// of a move is reached from a mesh stream, which is served far from anywhere
// that could have been handed a `Node` and a `Mesh` as arguments.

struct Ctx {
    mesh: Option<Arc<Mesh>>,
}

static CTX: OnceLock<Ctx> = OnceLock::new();

/// Install this device's half of the move machinery. Called once, from
/// `main`, once the mesh is up.
///
/// The sweep is deliberately *not* here: it runs before anything is served
/// (see [`sweep_staging`]), because a transfer this device was receiving when
/// it died should be gone before the first request arrives, not shortly
/// after.
pub fn init(mesh: Option<Arc<Mesh>>) {
    let _ = CTX.set(Ctx { mesh });
}

fn ctx() -> Result<&'static Ctx> {
    CTX.get()
        .context("this daemon's move machinery was never started")
}

/// This device's mesh presence, for the half of a move that is reached from
/// a mesh stream and so has nothing to be handed one by.
pub fn mesh() -> Result<Arc<Mesh>> {
    ctx()?
        .mesh
        .clone()
        .context("this daemon has no mesh endpoint, so it cannot take an instance")
}

// ---- staging ---------------------------------------------------------------

/// Where a half-arrived instance lives until it is committed.
///
/// Under `instances/`, next to the real ones, so it is on the same filesystem
/// and the commit is a rename rather than a copy — and named so that no
/// instance could ever be called that.
pub fn staging_dir(name: &str, epoch: u64) -> PathBuf {
    paths::instance_dir(&format!("{name}{STAGING}{epoch}"))
}

/// Delete every staging directory on this device.
///
/// Run at daemon start — before the socket is bound, before the mesh comes
/// up — which is the "next contact" a killed transfer gets.
/// A staging directory is by construction not referenced by any shard row, so
/// there is nothing to consult before removing one: if it were committed it
/// would not be called this any more.
pub fn sweep_staging() {
    let dir = paths::home_dir().join("instances");
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if !name.contains(STAGING) {
            continue;
        }
        match std::fs::remove_dir_all(entry.path()) {
            Ok(()) => eprintln!(
                "astd: swept {} — an interrupted move left it, and it was never bootable",
                entry.path().display()
            ),
            Err(e) => eprintln!("astd: could not sweep {}: {e}", entry.path().display()),
        }
    }
}

/// What the target counted as it wrote, kept inside the staging directory.
///
/// The commit turns on this rather than on the importer's word, so a commit
/// that arrives after the importing daemon was restarted still checks the
/// same numbers — and a staging directory with no receipt is a transfer that
/// never finished, whatever else it looks like.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Receipt {
    pub epoch: u64,
    pub from_device: String,
    /// Total bytes written.
    pub bytes: u64,
    /// Per file, relative path to bytes written.
    pub files: BTreeMap<String, u64>,
}

impl Receipt {
    fn path(dir: &Path) -> PathBuf {
        dir.join(".move-receipt.json")
    }

    pub fn save(&self, dir: &Path) -> Result<()> {
        std::fs::write(Self::path(dir), serde_json::to_vec_pretty(self)?)
            .context("recording what arrived")
    }

    fn load(dir: &Path) -> Result<Self> {
        let bytes = std::fs::read(Self::path(dir))
            .context("this transfer never finished — there is no record of what arrived")?;
        Ok(serde_json::from_slice(&bytes)?)
    }
}

// ---- the manifest ----------------------------------------------------------

/// Files in an instance directory that a move does not carry.
///
/// Everything here is about *this* device's copy of the guest rather than
/// about the guest: a console log belongs to the boot that wrote it, and a
/// pid or a socket describes a process on a machine the instance is leaving.
/// Anything else in the directory travels, so a file a future backend adds
/// comes along without this list having to learn about it.
fn is_plumbing(name: &str) -> bool {
    name == "console.log"
        || name.starts_with('.')
        || name.ends_with(".pid")
        || name.ends_with(".sock")
        || name.ends_with(".tmp")
        // The last-known-good copy a durable commit leaves is this device's
        // recovery artifact, not part of the instance — and for the egress
        // CA key it is a *superseded private key*, which is the last thing
        // that should ride to another machine.
        || name.ends_with(".bak")
        || name.ends_with(".part")
}

/// Everything a move of this instance would carry, with the two numbers that
/// matter per file: what it claims to be, and what it actually holds.
pub fn manifest(inst: &Instance) -> Result<MoveManifest> {
    let dir = paths::instance_dir(&inst.name);
    let mut files = Vec::new();
    collect(&dir, &dir, &mut files)?;
    files.sort_by(|a, b| a.path.cmp(&b.path));

    let local_volumes = inst
        .volumes
        .iter()
        .filter(|v| v.kind == VolumeKind::Dir)
        .map(|v| v.guest_path())
        .collect();

    Ok(MoveManifest {
        instance: inst.clone(),
        arch: std::env::consts::ARCH.to_owned(),
        base: base_image(inst)?,
        files,
        local_volumes,
    })
}

fn collect(root: &Path, dir: &Path, out: &mut Vec<MoveFile>) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        // An instance that has never booted has no directory, and moving it
        // is moving a record. That is legal and cheap.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e).with_context(|| format!("reading {}", dir.display())),
    };
    for entry in entries {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let path = entry.path();
        let meta = entry.metadata()?;
        if meta.is_dir() {
            if !is_plumbing(name) {
                collect(root, &path, out)?;
            }
            continue;
        }
        if !meta.is_file() || is_plumbing(name) {
            continue;
        }
        let relative = path
            .strip_prefix(root)
            .map_err(|_| anyhow!("{} is not under {}", path.display(), root.display()))?
            .to_string_lossy()
            .into_owned();
        out.push(MoveFile {
            path: relative,
            len: meta.len(),
            allocated: cow::allocated(&cow::extents(&path)?),
            mode: meta.permissions().mode() & 0o777,
        });
    }
    Ok(())
}

/// The base image this instance's disk was cloned from, content-addressed.
///
/// An instance whose image reference names nothing this device has is not an
/// error here: the disk is a complete file and boots without the base. The
/// zero length says "nothing to fetch" and the target's probe decides what
/// that means for it.
fn base_image(inst: &Instance) -> Result<BaseImage> {
    let Some(reference) = inst.image.clone() else {
        bail!(
            "instance {:?} has no image recorded — there is nothing to move it to",
            inst.name
        );
    };
    let base = match image::resolve(&reference) {
        Ok(base) => base,
        // The reference does not resolve *here* either; the manifest says so
        // and the target refuses, rather than this failing in the abstract.
        Err(_) => return Ok(BaseImage::absent(reference)),
    };
    if !base.path.exists() {
        return Ok(BaseImage::absent(reference));
    }
    // A provenance record is evidence about particular bytes, not a label
    // that may be copied onto whatever happens to occupy the path today.
    // Hash the source in full before repeating its parents in a manifest,
    // and keep the exact record that was checked rather than reading it a
    // second time after the check. The target will independently check the
    // bytes it receives against `digest` below.
    let provenance = verify::verified_provenance(&base.path, &base.record, verify::Depth::Full)
        .with_context(|| {
            format!(
                "refusing to move {:?} from base image {} because its source bytes cannot be verified",
                inst.name, reference
            )
        })?;
    // Use the address from that same checked record. Hashing again here
    // would reopen a gap: bytes replaced between the verification and the
    // second hash could be sent under a fresh address while carrying the old
    // record's parents. Bare BLAKE3 is the manifest's historical wire shape;
    // other algorithms name themselves, which `wire_digest` accepts.
    let digest = if provenance.content.algo() == verify::OWN_ALGO {
        provenance.content.hex().to_owned()
    } else {
        provenance.content.to_string()
    };
    // Keep every identity field on the same checked snapshot. A later stat
    // would let a concurrent replacement advertise a different length under
    // the record's address (the target would still reject its bytes, but the
    // manifest would no longer describe one coherent artifact).
    let len = provenance.size;
    Ok(BaseImage {
        reference,
        len,
        allocated: cow::allocated(&cow::extents(&base.path)?),
        digest,
        // These are from the record just proved against these bytes. A record
        // that is missing, malformed, or belongs to older bytes refuses above
        // instead of lending an unproved parent to the target's new record.
        derived_from: provenance.derived_from,
    })
}

/// Read a manifest's content address as the verifier's [`Digest`].
///
/// Move manifests historically carry this project's BLAKE3 address as bare
/// hex, so the algorithm is supplied here. A peer that names an algorithm is
/// understood too. A digest this build cannot check is refused before
/// anything is adopted, which is [`asterism_core::verify::Digest::parse`]'s
/// job and the reason this is not a `format!` at the call site.
pub fn wire_digest(digest: &str) -> Result<Digest> {
    let spelled = if digest.contains(':') {
        digest.to_owned()
    } else {
        format!("blake3:{digest}")
    };
    Digest::parse(&spelled).with_context(|| {
        format!("the base image's content address {digest:?} is not one Asterism can check")
    })
}

// ---- the steps, as frames --------------------------------------------------

/// Is this one of the steps of a move, aimed at this device's shard?
///
/// [`Request::SetCpu`] is deliberately absent. It is the *whole* move rather
/// than a step of one, it is driven from the connection that asked so that it
/// can report as it goes, and a shard that was handed one would have nowhere
/// to send the progress — so it falls through to the refusal at the end of
/// [`crate::handle`]'s chain, which is the true thing to say about it.
pub(crate) fn is_step(req: &Request) -> bool {
    matches!(
        req,
        Request::MoveOffer { .. }
            | Request::MoveProbe { .. }
            | Request::MovePrepare { .. }
            | Request::MoveCommitTarget { .. }
            | Request::MoveCommitSource { .. }
            | Request::MoveAbortSource { .. }
            | Request::MoveAbortTarget { .. }
    )
}

/// Run one step of a move against this device's shard.
///
/// Each step saves (or refuses) itself, which is why none of them goes
/// through the mutation path the instance commands share: a fence that was
/// persisted by somebody else's `reg.save()` would be a fence whose ordering
/// against the transfer nobody had thought about.
pub(crate) fn serve(req: Request, reg: &mut Shard, cpu_device: &str) -> Response {
    match req {
        Request::MoveOffer { name } => tokio::task::block_in_place(|| offer(reg, &name)),
        Request::MoveProbe { manifest } => {
            let already_here = reg.holds(&manifest.instance.name);
            tokio::task::block_in_place(|| probe(&manifest, cpu_device, already_here))
        }
        Request::MovePrepare {
            name,
            to_device,
            epoch,
        } => tokio::task::block_in_place(|| prepare(reg, &name, &to_device, epoch)),
        Request::MoveCommitTarget { manifest, epoch } => {
            tokio::task::block_in_place(|| commit_target(reg, &manifest, epoch, cpu_device))
        }
        Request::MoveCommitSource { name, epoch } => {
            tokio::task::block_in_place(|| commit_source(reg, &name, epoch))
        }
        Request::MoveAbortSource { name, epoch } => abort_source(reg, &name, epoch),
        Request::MoveAbortTarget { name, epoch } => abort_target(reg, &name, epoch),
        other => Response::Error {
            message: format!("{other:?} is not a step of a move"),
        },
    }
}

// ---- the source's half -----------------------------------------------------

/// What a move of this instance would carry. Read-only: nothing is fenced.
///
/// Answers for a *running* instance too, deliberately. Whether a running
/// guest may be moved is the caller's question — `--down` is an answer to it
/// — and the preflight has to be able to see the instance before it can tell
/// the user what it would take.
pub fn offer(reg: &Shard, name: &str) -> Response {
    match reg
        .get(name)
        .cloned()
        .and_then(|inst| unconflicted(&inst).map(|()| inst))
    {
        Ok(inst) => match manifest(&inst) {
            Ok(manifest) => Response::MoveOffer {
                manifest: Box::new(manifest),
            },
            Err(e) => error(e),
        },
        Err(e) => error(e),
    }
}

/// Fence the instance and answer with the manifest as it stands now.
///
/// From here this device holds the only bootable copy and will not boot it.
/// A fence already in place is superseded rather than refused: the epoch only
/// ever goes up, so a move that was interrupted with nobody left to abort it
/// does not strand the instance for good.
pub fn prepare(reg: &mut Shard, name: &str, to_device: &str, epoch: u64) -> Response {
    let inst = match reg
        .get(name)
        .cloned()
        .and_then(|inst| movable(&inst).map(|()| inst))
    {
        Ok(inst) => inst,
        Err(e) => return error(e),
    };
    if epoch <= inst.move_epoch {
        return error(anyhow!(
            "instance {name:?} is already at move epoch {} — a move to {to_device} at \
             epoch {epoch} is stale and will not be served",
            inst.move_epoch
        ));
    }
    // Rebuild and verify the offer before the first mutation. The base may
    // have changed between the read-only preflight and this request; if so,
    // neither this source row nor anything on the target is touched. Once
    // fenced, only the instance field differs from this manifest.
    let mut manifest = match manifest(&inst) {
        Ok(manifest) => manifest,
        Err(e) => return error(e),
    };
    let fenced = reg.set_moving(
        name,
        Some(Moving {
            to_device: to_device.to_owned(),
            epoch,
            started_at: now_unix(),
        }),
    );
    match fenced.and_then(|inst| reg.save().map(|()| inst)) {
        Ok(inst) => {
            manifest.instance = inst;
            Response::MoveOffer {
                manifest: Box::new(manifest),
            }
        }
        Err(e) => error(e),
    }
}

/// The target has the bytes and has said so. Drop the row, drop the disk,
/// leave a note.
pub fn commit_source(reg: &mut Shard, name: &str, epoch: u64) -> Response {
    let inst = match reg.get(name).cloned() {
        Ok(inst) => inst,
        // The durable moved note is written before the source row is removed.
        // It is therefore also the receipt for a repeated source commit after
        // a reply was lost, or after a coordinator restarted at precisely the
        // wrong point.  A different note is not evidence about this move.
        Err(_) if moved_to(name, epoch).is_some() => return Response::Ok,
        Err(e) => return error(e),
    };
    let Some(moving) = inst.moving.clone() else {
        return error(anyhow!(
            "instance {name:?} is not being moved from this device — refusing to \
             delete a copy nothing has taken over from"
        ));
    };
    if moving.epoch != epoch {
        return error(anyhow!(
            "instance {name:?} is being moved at epoch {}, not {epoch} — refusing to \
             commit a move this device is not the source of",
            moving.epoch
        ));
    }

    // This is the source's durable acknowledgement.  Do it before removing
    // the row: a crash anywhere after it is safe to retry, while a crash
    // before it still leaves the source fenced.
    if let Err(e) = remember_move(name, &moving.to_device, epoch) {
        return error(e);
    }
    if let Err(e) = reg.remove(name).and_then(|_| reg.save()) {
        return error(e);
    }
    crate::persist::forget(name);
    let _ = std::fs::remove_dir_all(paths::instance_dir(name));
    Response::Ok
}

/// The move did not happen. Take the fence off; this row never stopped being
/// the authoritative one.
pub fn abort_source(reg: &mut Shard, name: &str, epoch: u64) -> Response {
    match reg.get(name).cloned() {
        // Nothing to unfence is not a failure: an abort is sent on paths that
        // may never have got as far as fencing anything.
        Err(_) => Response::Ok,
        Ok(inst) => {
            if inst.moving.as_ref().is_some_and(|m| m.epoch != epoch) {
                return error(anyhow!(
                    "instance {name:?} is being moved at a different epoch — leaving \
                     that move's fence alone"
                ));
            }
            match reg.set_moving(name, None).and_then(|_| reg.save()) {
                Ok(()) => Response::Ok,
                Err(e) => error(e),
            }
        }
    }
}

/// An instance in a name collision answers nothing but the rename that ends
/// it, and that includes being looked at by a move.
fn unconflicted(inst: &Instance) -> Result<()> {
    if let Some(conflict) = &inst.conflict {
        bail!("{}", asterism_core::registry::conflicted(inst, conflict));
    }
    Ok(())
}

/// Whether this instance can be moved at all, in the words the refusal needs.
fn movable(inst: &Instance) -> Result<()> {
    unconflicted(inst)?;
    if inst.status == Status::Running {
        bail!(
            "instance {:?} is running — an offline move needs it stopped: \
             `ast down {}`, or pass --down",
            inst.name,
            inst.name
        );
    }
    Ok(())
}

// ---- the target's half -----------------------------------------------------

/// Could this device take the instance described by `manifest`?
///
/// Everything checkable is checked before the instance is taken out of
/// service, and everything that is merely *true* is reported as a note rather
/// than dressed up as a problem.
pub fn probe(manifest: &MoveManifest, device: &str, already_here: bool) -> Response {
    let mut notes = Vec::new();
    let mut refusal = probe_refusal(manifest, device, already_here, &mut notes);
    let needs_base = if refusal.is_none() {
        let (base_refusal, wanted) = probe_base(&manifest.base, device);
        refusal = base_refusal;
        wanted
    } else {
        false
    };
    Response::MoveProbe {
        device: device.to_owned(),
        refusal,
        notes,
        needs_base,
    }
}

fn probe_base(base: &BaseImage, device: &str) -> (Option<String>, bool) {
    match base_wanted(base) {
        Ok(wanted) => (None, wanted),
        Err(e) => (
            Some(format!(
                "device {device} cannot receive base image {:?}: {e:#}",
                base.reference
            )),
            false,
        ),
    }
}

fn probe_refusal(
    manifest: &MoveManifest,
    device: &str,
    already_here: bool,
    notes: &mut Vec<String>,
) -> Option<String> {
    let inst = &manifest.instance;
    if already_here {
        return Some(format!(
            "device {device} already has a row for instance {:?} — one name means one \
             instance in this orbit",
            inst.name
        ));
    }
    if manifest.arch != std::env::consts::ARCH {
        return Some(format!(
            "device {device} is {}, and {:?} was built for {} — a guest does not \
             change instruction set by being copied",
            std::env::consts::ARCH,
            inst.name,
            manifest.arch
        ));
    }

    // The backend an instance was created against is the one that keeps
    // booting it, so the target has to have that one working — not merely a
    // hypervisor.
    let machine = &inst.machine;
    let hv = match backend::by_id(&machine.backend) {
        Ok(hv) => hv,
        Err(e) => {
            return Some(format!(
                "device {device} has no {} backend: {e:#}",
                machine.backend
            ))
        }
    };
    match hv.probe() {
        Ok(ready) => {
            if ready.version != machine.hv_version {
                notes.push(format!(
                    "{device} runs {} {} and {:?} was defined against {} — an \
                     offline move rewrites nothing, and the guest reboots rather \
                     than resumes",
                    machine.backend, ready.version, inst.name, machine.hv_version
                ));
            }
            if ready.machine_type != machine.machine_type {
                notes.push(format!(
                    "{device}'s {} machine type is {} and this instance records \
                     {} — the virtual hardware differs and the guest will see it",
                    machine.backend, ready.machine_type, machine.machine_type
                ));
            }
        }
        Err(e) => {
            return Some(format!(
                "device {device} cannot run the {} backend that {:?} was created \
                 against: {e:#}",
                machine.backend, inst.name
            ))
        }
    }

    // The image reference has to mean something here, or the first `ast up`
    // fails looking for a base this device cannot name.
    if let Err(e) = backend::image_ref(&manifest.base.reference) {
        return Some(format!(
            "device {device} cannot resolve image {:?}: {e:#} — a move needs the \
             reference to name the same base image on both devices",
            manifest.base.reference
        ));
    }
    if manifest.base.len == 0 {
        notes.push(format!(
            "the source has no copy of base image {:?} to hand over; the disk is a \
             complete file and boots without it",
            manifest.base.reference
        ));
    }

    for path in &manifest.local_volumes {
        notes.push(format!(
            "the volume at {path} is a directory share, which is same-device only — \
             it will be kept on the instance and flagged in `ast status`"
        ));
    }
    None
}

/// Does the base image have to be fetched from the source?
///
/// Absent, or here at a different length. Length is the cheap check and the
/// honest one to make *here*: the content address is verified on what
/// arrives, before it is put in the image store, so a fetch cannot install
/// the wrong bytes however this answers. A copy already here at the right
/// length is left alone — other instances on this device are cloned from it,
/// and rewriting it to settle a doubt about one move would be the wrong
/// trade. If a fetch would land outside the replaceable image store, this is
/// an error: the target has to provide that path itself.
pub fn base_wanted(base: &BaseImage) -> Result<bool> {
    if base.len == 0 {
        return Ok(false);
    }
    let resolved = image::resolve(&base.reference)?;
    let wanted = !resolved.path.exists() || std::fs::metadata(&resolved.path)?.len() != base.len;
    if !wanted {
        return Ok(false);
    }

    // A reference can resolve on both devices while naming different bytes
    // (most importantly, a local `--image` path). Anything outside the image
    // store is not a cache entry Asterism may refresh: the target's file may
    // be the user's only copy, and replacing it would be data loss. Refuse
    // during the probe, before the source is fenced, and tell the user how to
    // make the move possible.
    if !resolved.is_ours() {
        bail!(
            "this device needs base image {:?} at {}, but that path is outside \
             Asterism's replaceable image store and does not hold the {}-byte image the \
             move requires. Asterism will not overwrite it with bytes fetched from a \
             peer; put that image at {} on this device and retry the move",
            base.reference,
            resolved.path.display(),
            base.len,
            resolved.path.display()
        );
    }
    Ok(true)
}

/// Where a fetched base image lands on this device, and where the provenance
/// record for it has to go.
///
/// Two paths rather than one because an artifact and its provenance record
/// are separate durable writes. Only an image-store artifact may be returned:
/// a peer fetch must never adopt onto a local file the user pointed
/// `--image` at, even if that file changed after the move probe.
pub fn base_landing(reference: &str) -> Result<(PathBuf, PathBuf)> {
    let resolved = image::resolve(reference)?;
    if !resolved.is_ours() {
        bail!(
            "base image {reference:?} resolves outside Asterism's replaceable image \
             store at {}; Asterism will not overwrite that path with bytes fetched \
             from a peer. Put the required image there on this device and retry the \
             move",
            resolved.path.display()
        );
    }
    Ok((resolved.path, resolved.record))
}

/// Adopt a staged transfer: check it, rename it into place, write the row.
///
/// This is the only moment a second copy of the instance exists, and by the
/// time it does the source has been fenced for the whole transfer.
pub fn commit_target(
    reg: &mut Shard,
    manifest: &MoveManifest,
    epoch: u64,
    device: &str,
) -> Response {
    let name = manifest.instance.name.clone();
    let staging = staging_dir(&name, epoch);
    let live = paths::instance_dir(&name);

    // A reply can disappear after the target durably adopted the row.  The
    // retry must acknowledge that exact adoption rather than treating the
    // now-absent staging directory as a failed transfer and reopening the
    // source.  Anything else at this name remains a hard refusal.
    if let Ok(existing) = reg.get(&name) {
        if existing.id == manifest.instance.id
            && existing.cpu_device == device
            && existing.move_epoch == epoch
            && existing.moving.is_none()
            && live.is_dir()
        {
            return Response::Instance {
                instance: existing.clone(),
                guest_health: None,
            };
        }
        return error(anyhow!(
            "device {device} already has a different move state for {name:?}; refusing to adopt it again"
        ));
    }
    if let Err(e) = verify(&staging, manifest, epoch) {
        return error(e);
    }

    if live.exists() {
        return error(anyhow!(
            "device {device} already has an instance directory at {} — refusing to \
             put a second copy of {name:?} on top of it",
            live.display()
        ));
    }
    if let Some(parent) = live.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            return error(anyhow!("{e}"));
        }
    }
    // The rename first, then the receipt: a rename that fails leaves the
    // staging directory exactly as it was, receipt included, so the move can
    // be aborted or retried against something that still adds up.
    //
    // Every byte of the tree is forced down before the rename. This is the
    // one moment a second copy of the instance exists, and the source is
    // about to be told it can stop existing: a disk still sitting in the page
    // cache when the power goes is a move that lost the instance.
    if let Err(e) = durable::publish_dir(&staging, &live) {
        return error(anyhow!(
            "could not adopt {}: {e:#} — it is still staged and still not bootable",
            staging.display()
        ));
    }
    // Keep the durable transition receipt in the live directory.  It is the
    // target's fence while the source still owns a fenced row, and deleting
    // it before the source's durable revoke would turn a lost reply into an
    // indistinguishable failed move.  It is plumbing, so it never migrates
    // again with a later move.

    let mut adopted = manifest.instance.clone();
    adopted.cpu_device = device.to_owned();
    // A guest that was running was shut down before any of this; anything
    // else keeps the state it had, so an instance that had never been booted
    // does not arrive claiming to have been.
    if adopted.status == Status::Running {
        adopted.status = Status::Stopped;
    }
    adopted.handle = None;
    adopted.moving = None;
    adopted.conflict = None;
    adopted.move_epoch = epoch;
    adopted.stranded = manifest.local_volumes.clone();
    match reg
        .adopt(adopted)
        .and_then(|inst| reg.save().map(|()| inst))
    {
        Ok(instance) => Response::Instance {
            instance,
            guest_health: None,
        },
        Err(e) => error(e),
    }
}

/// The completeness check the commit turns on.
fn verify(staging: &Path, manifest: &MoveManifest, epoch: u64) -> Result<()> {
    if !staging.is_dir() {
        bail!(
            "nothing arrived for {:?} at epoch {epoch} — there is no staging \
             directory to adopt",
            manifest.instance.name
        );
    }
    let receipt = Receipt::load(staging)?;
    if receipt.epoch != epoch {
        bail!(
            "what is staged for {:?} came from epoch {}, not {epoch}",
            manifest.instance.name,
            receipt.epoch
        );
    }
    for file in &manifest.files {
        let path = staging.join(&file.path);
        let meta =
            std::fs::metadata(&path).with_context(|| format!("{} did not arrive", file.path))?;
        if meta.len() != file.len {
            bail!(
                "{} arrived {} bytes long and should be {}",
                file.path,
                meta.len(),
                file.len
            );
        }
        match receipt.files.get(&file.path) {
            Some(&written) if written == file.allocated => {}
            Some(&written) => bail!(
                "{} carried {written} allocated bytes and should have carried {}",
                file.path,
                file.allocated
            ),
            None => bail!("{} is not in the record of what arrived", file.path),
        }
    }
    let expected = manifest.allocated();
    if receipt.bytes != expected {
        bail!(
            "{} bytes arrived and {expected} were expected",
            receipt.bytes
        );
    }
    Ok(())
}

/// Delete a staging directory. What an abort owes the target.
///
/// A successful abort is the proof the coordinator needs before it may ask
/// the source to lift its fence.  Never manufacture that proof once this
/// target has adopted a row, a live directory, or either has survived a
/// crash independently of the other.
pub fn abort_target(reg: &Shard, name: &str, epoch: u64) -> Response {
    let live = paths::instance_dir(name);
    if reg.get(name).is_ok() || live.exists() {
        return error(anyhow!(
            "target still owns {name:?} at move epoch {epoch}; refusing to report a rollback that did not happen"
        ));
    }
    let staging = staging_dir(name, epoch);
    match std::fs::remove_dir_all(&staging) {
        Ok(()) | Err(_) => Response::Ok,
    }
}

// ---- what a device remembers about an instance that left -------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MovedNote {
    pub to_device: String,
    pub epoch: u64,
    pub at: u64,
}

fn notes_path() -> PathBuf {
    paths::home_dir().join("moved.json")
}

fn load_notes() -> BTreeMap<String, MovedNote> {
    std::fs::read(notes_path())
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default()
}

fn moved_to(name: &str, epoch: u64) -> Option<MovedNote> {
    let note = load_notes().get(name).cloned()?;
    (note.epoch == epoch && now_unix().saturating_sub(note.at) < NOTE_TTL_SECS).then_some(note)
}

fn remember_move(name: &str, to_device: &str, epoch: u64) -> Result<()> {
    let mut notes = load_notes();
    let now = now_unix();
    notes.retain(|_, note| now.saturating_sub(note.at) < NOTE_TTL_SECS);
    notes.insert(
        name.to_owned(),
        MovedNote {
            to_device: to_device.to_owned(),
            epoch,
            at: now,
        },
    );
    // Best effort by design: a note is a courtesy to whoever types
    // `ast status` at the old device, and losing it costs a redirect, not an
    // instance. It is still committed durably, because the alternative is a
    // torn file that the next read has to treat as a lost note anyway.
    durable::commit_json(&notes_path(), &notes)
        .context("recording the source's durable move acknowledgement")
}

/// What this device has to say about an instance it no longer holds.
///
/// Only ever reached when a request was aimed at this device directly: the
/// ordinary path resolves the name across the orbit and lands on whoever
/// holds the row now.
pub fn moved_note(name: &str) -> Option<String> {
    let note = load_notes().get(name).cloned()?;
    if now_unix().saturating_sub(note.at) >= NOTE_TTL_SECS {
        return None;
    }
    Some(format!(
        "instance {name:?} moved to {} — its cpu is sourced there now, and \
         `ast status {name}` from anywhere in this orbit will find it",
        note.to_device
    ))
}

// ---- the orchestrator ------------------------------------------------------

/// `ast set <instance> cpu <device>`, driven from the daemon in front of the
/// user.
///
/// This daemon is neither end of the transfer unless it happens to be: the
/// bytes go source-to-target directly, and what runs here is the sequence.
/// Every step is one frame aimed at one named device, so the same code drives
/// a move between two other machines as drives one off this one.
pub async fn run(
    name: &str,
    device: &str,
    down: bool,
    node: &Node,
    mesh: Option<&Arc<Mesh>>,
    io: &mut ClientIo<'_>,
) -> Result<()> {
    let mesh = mesh.context(
        "this daemon has no mesh endpoint, so it cannot move an instance between devices \
         — see the astd log for why",
    )?;
    asterism_core::registry::check_name(name)?;

    // ---- preflight ---------------------------------------------------------
    let here = node.device_name().await;
    let source = locate(name, node, mesh).await?;
    if source == device {
        bail!("instance {name:?} already sources its cpu and ram from {device}");
    }
    // Refuse a device nobody has heard of, and one that is not answering,
    // before anything has been fenced. A device does not list itself among
    // its peers, so moving *here* skips both: this daemon is demonstrably up.
    if device != here {
        if !mesh.knows(device).await {
            bail!("no device named {device:?} in this orbit — see: ast devices");
        }
        if !mesh.online(device).await {
            bail!(
                "device {device} is not answering, so it cannot take {name:?} — the move \
                 has not started and {source} still supplies its cpu"
            );
        }
    }

    let mut manifest = offer_of(name, &source, node, mesh).await?;
    if manifest.instance.status == Status::Running {
        if !down {
            bail!(
                "instance {name:?} is running on {source}. Moving cpu/ram is an offline \
                 operation on every backend Asterism has — pass --down to shut the guest \
                 down first"
            );
        }
        io.send(&line(format!("shutting {name} down on {source} first")))
            .await?;
        expect_ok(
            ask(
                &source,
                Request::Down {
                    name: name.to_owned(),
                },
                node,
                mesh,
            )
            .await?,
        )
        .with_context(|| format!("could not shut {name:?} down on {source}"))?;
        manifest = offer_of(name, &source, node, mesh).await?;
    }

    let probed = ask(
        device,
        Request::MoveProbe {
            manifest: Box::new(manifest.clone()),
        },
        node,
        mesh,
    )
    .await?;
    let needs_base = match probed {
        Response::MoveProbe {
            refusal: Some(refusal),
            ..
        } => bail!("{refusal}"),
        Response::MoveProbe {
            notes, needs_base, ..
        } => {
            for note in notes {
                io.send(&line(format!("note: {note}"))).await?;
            }
            needs_base
        }
        Response::Error { message } => bail!(message),
        other => bail!("device {device:?} answered a move probe with {other:?}"),
    };

    // The exact byte counts, not only the rounded ones. Transfer paths get
    // measured in this project and the numbers live where they can be
    // checked; a reader who wants to know whether the sparse walk earned its
    // keep should not have to work it out from "1.23 GiB".
    io.send(&line(format!(
        "moving {name} from {source} to {device}: {} of {} across {} file(s) \
         [allocated={} virtual={}]",
        cow::human(manifest.allocated()),
        cow::human(manifest.virtual_size()),
        manifest.files.len(),
        manifest.allocated(),
        manifest.virtual_size(),
    )))
    .await?;
    if needs_base {
        io.send(&line(format!(
            "{device} does not have base image {} ({}) — it will fetch it from {source} \
             rather than from the internet",
            manifest.base.reference,
            cow::human(manifest.base.cost()),
        )))
        .await?;
    }

    // ---- phase one: fence the source, then move the bytes ------------------
    let epoch = manifest.instance.move_epoch + 1;
    let prepared = ask(
        &source,
        Request::MovePrepare {
            name: name.to_owned(),
            to_device: device.to_owned(),
            epoch,
        },
        node,
        mesh,
    )
    .await?;
    let manifest = match prepared {
        Response::MoveOffer { manifest } => *manifest,
        Response::Error { message } => bail!(message),
        other => bail!("device {source:?} answered a move prepare with {other:?}"),
    };
    io.send(&line(format!(
        "{source} is holding {name} at move epoch {epoch}"
    )))
    .await?;

    let outcome = transfer_and_commit(&manifest, &source, device, epoch, node, mesh, io).await;
    if let Err(e) = outcome {
        // Nothing the target staged is bootable and nothing has been written
        // to its shard, so this is a tidy-up rather than a rollback.
        // The source fence is authority, not cosmetic cleanup.  Only lift it
        // after the target has *proved* it rolled back.  In particular, a
        // lost target success reply makes MoveAbortTarget refuse (the adopted
        // row/live directory remains), which deliberately leaves the source
        // fenced for an idempotent commit retry instead of creating two live
        // authorities.
        let rolled_back = match ask(
            device,
            Request::MoveAbortTarget {
                name: name.to_owned(),
                epoch,
            },
            node,
            mesh,
        )
        .await
        {
            Ok(response) => expect_ok(response).is_ok(),
            Err(_) => false,
        };
        if rolled_back {
            let _ = ask(
                &source,
                Request::MoveAbortSource {
                    name: name.to_owned(),
                    epoch,
                },
                node,
                mesh,
            )
            .await;
            io.send(&line(format!(
                "the move did not happen — {source} still supplies {name}'s cpu"
            )))
            .await?;
        } else {
            io.send(&line(format!(
                "{name} remains fenced on {source}: target recovery must be retried before any source rollback"
            )))
            .await?;
        }
        return Err(e);
    }

    io.send(&Response::Move {
        text: format!(
            "{name}: cpu/ram now sourced from {device} (move epoch {epoch}) — \
             `ast up {name}` boots it there"
        ),
        done: true,
    })
    .await
}

/// Phases two and three: the bytes, then the two commits in order.
#[allow(clippy::too_many_arguments)]
async fn transfer_and_commit(
    manifest: &MoveManifest,
    source: &str,
    device: &str,
    epoch: u64,
    node: &Node,
    mesh: &Arc<Mesh>,
    io: &mut ClientIo<'_>,
) -> Result<()> {
    let name = manifest.instance.name.clone();

    mesh.move_import(device, source, manifest, epoch, io)
        .await?;

    // The target checks what arrived against the manifest and only then does
    // a second copy of this instance exist anywhere.
    let target_reply = ask(
        device,
        Request::MoveCommitTarget {
            manifest: Box::new(manifest.clone()),
            epoch,
        },
        node,
        mesh,
    )
    .await?;
    move_failpoint("lost-target-ack")?;
    expect_instance(target_reply).with_context(|| format!("{device} would not adopt {name:?}"))?;
    io.send(&line(format!(
        "{device} has it, verified against the manifest"
    )))
    .await?;
    move_failpoint("post-target-ack-crash")?;

    // Past this point the move has happened. A source that will not answer
    // now leaves a stale copy rather than losing one, and the epoch on the
    // target's row is what settles which is which.
    expect_ok(
        ask(
            source,
            Request::MoveCommitSource {
                name: name.clone(),
                epoch,
            },
            node,
            mesh,
        )
        .await?,
    )
    .with_context(|| {
        format!(
            "{device} has {name:?} at epoch {epoch} and {source} would not let go of \
             its copy — the higher epoch is the live one, and {source}'s copy is stale"
        )
    })?;
    io.send(&line(format!("{source} has dropped its copy")))
        .await?;
    Ok(())
}

/// Deterministic recovery injection for the two acknowledgement windows.
/// It is opt-in and deliberately narrow: a comma-separated value in
/// `ASTERISM_MOVE_FAILPOINT` makes the named boundary return an error, which
/// exercises the ordinary recovery path without a timing race.
fn move_failpoint(name: &str) -> Result<()> {
    let enabled = std::env::var("ASTERISM_MOVE_FAILPOINT").unwrap_or_default();
    if enabled.split(',').map(str::trim).any(|point| point == name) {
        bail!("injected move failpoint: {name}");
    }
    Ok(())
}

/// Which device holds this instance's row, in the orbit's own words.
async fn locate(name: &str, node: &Node, mesh: &Arc<Mesh>) -> Result<String> {
    let local_authoritative = {
        let local = node.shard.lock().await;
        // A fenced source is deliberately suppressed after restart: it is
        // evidence of an in-flight handoff, not permission to reactivate the
        // old authority.  The orbit lookup can then find an adopted target;
        // if none answers, the caller gets a safe refusal rather than the
        // source row being selected merely because it is local.
        matches!(local.get(name), Ok(instance) if instance.moving.is_none())
    };
    if local_authoritative {
        return Ok(node.device_name().await);
    }
    mesh.locate(name)
        .await?
        .ok_or_else(|| anyhow!("no instance named {name:?} in this orbit"))
}

async fn offer_of(name: &str, source: &str, node: &Node, mesh: &Arc<Mesh>) -> Result<MoveManifest> {
    match ask(
        source,
        Request::MoveOffer {
            name: name.to_owned(),
        },
        node,
        mesh,
    )
    .await?
    {
        Response::MoveOffer { manifest } => Ok(*manifest),
        Response::Error { message } => bail!(message),
        other => bail!("device {source:?} answered a move offer with {other:?}"),
    }
}

/// One frame, aimed at one device — this one included.
///
/// The local short-circuit is not an optimisation: `ast move dev desktop`
/// typed on the device that currently supplies `dev`'s cpu must reach its own
/// shard, and putting that through the mesh would mean dialling ourselves.
pub(crate) async fn ask(
    device: &str,
    request: Request,
    node: &Node,
    mesh: &Arc<Mesh>,
) -> Result<Response> {
    if device == node.device_name().await {
        return Ok(crate::handle(request, node).await);
    }
    mesh.proxy(device, request).await
}

/// A step that either worked or has a sentence explaining why not.
///
/// `Instance` counts as a yes: `down` answers with the row it changed, and a
/// move does not care what the row looks like, only that the guest stopped.
fn expect_ok(response: Response) -> Result<()> {
    match response {
        Response::Ok | Response::Instance { .. } => Ok(()),
        Response::Error { message } => bail!(message),
        other => bail!("unexpected answer: {other:?}"),
    }
}

fn expect_instance(response: Response) -> Result<Instance> {
    match response {
        Response::Instance { instance, .. } => Ok(instance),
        Response::Error { message } => bail!(message),
        other => bail!("unexpected answer: {other:?}"),
    }
}

pub(crate) fn line(text: String) -> Response {
    Response::Move { text, done: false }
}

fn error(e: anyhow::Error) -> Response {
    Response::Error {
        message: format!("{e:#}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_machine() -> asterism_core::hv::Machine {
        asterism_core::hv::Machine {
            backend: "qemu".into(),
            machine_type: "virt".into(),
            cpu: "host".into(),
            hv_version: "test".into(),
        }
    }

    #[test]
    fn a_staging_directory_can_never_be_an_instance() {
        // Instance names are ascii letters, digits and '-'; the staging
        // marker is neither, which is what makes an abandoned one harmless.
        let staged = staging_dir("dev", 7);
        let leaf = staged.file_name().unwrap().to_string_lossy().into_owned();
        assert_eq!(leaf, "dev.moving-7");
        assert!(
            asterism_core::registry::check_name(&leaf).is_err(),
            "{leaf}"
        );
        assert_ne!(staged, paths::instance_dir("dev"));
        // Same parent, so the commit is a rename rather than a copy.
        assert_eq!(staged.parent(), paths::instance_dir("dev").parent());
    }

    /// The manifest carries bare hex, because that is what [`digest_of`]
    /// writes and what every build that has ever sent one sends. The
    /// algorithm is supplied on the way back in — and a peer that starts
    /// naming its own is understood rather than refused.
    #[test]
    fn a_manifest_digest_is_read_as_the_hash_the_manifest_was_written_with() {
        use asterism_core::verify::Algo;

        let hex = "ab".repeat(32);
        let parsed = wire_digest(&hex).unwrap();
        assert_eq!(
            parsed.algo(),
            Algo::Blake3,
            "bare hex is what digest_of computes"
        );
        assert_eq!(parsed.hex(), hex);
        assert_eq!(
            wire_digest(&format!("sha256:{hex}")).unwrap().algo(),
            Algo::Sha256
        );

        // And one this build cannot compute is refused here, which is before
        // a byte of a multi-gigabyte base image has been asked for.
        let err = format!(
            "{:#}",
            wire_digest(&format!("md5:{}", "a".repeat(32))).unwrap_err()
        );
        assert!(err.contains("is not one Asterism can check"), "{err}");
    }

    /// A local `--image` file is the user's only copy, not a cache entry a
    /// peer fetch may refresh. A different length is enough to know it is not
    /// the source's base, but never permission to replace it.
    #[test]
    fn a_peer_fetch_never_lands_on_a_user_owned_image() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mine.raw");
        let original = b"the target user's own image";
        std::fs::write(&path, original).unwrap();
        let reference = path.display().to_string();
        let base = BaseImage {
            reference: reference.clone(),
            len: original.len() as u64 + 1,
            allocated: original.len() as u64 + 1,
            digest: "ab".repeat(32),
            derived_from: Vec::new(),
        };

        let (refusal, needs_base) = probe_base(&base, "desktop");
        assert!(!needs_base, "an unsafe landing is a refusal, not a fetch");
        let wanted = refusal.unwrap();
        assert!(
            wanted.contains("device desktop cannot receive base image"),
            "{wanted}"
        );
        assert!(
            wanted.contains("outside Asterism's replaceable image store"),
            "{wanted}"
        );
        assert!(wanted.contains("will not overwrite it"), "{wanted}");
        assert!(wanted.contains("put that image at"), "{wanted}");
        assert!(wanted.contains(&reference), "{wanted}");

        let mut already_there = base.clone();
        already_there.len = original.len() as u64;
        assert!(
            !base_wanted(&already_there).unwrap(),
            "a target that has the image itself needs no peer fetch"
        );

        // The adoption boundary repeats the ownership check, closing the
        // race where the path changes after the probe but before transfer.
        let landing = format!("{:#}", base_landing(&reference).unwrap_err());
        assert!(
            landing.contains("will not overwrite that path"),
            "{landing}"
        );
        assert!(landing.contains("retry the move"), "{landing}");
        assert_eq!(std::fs::read(&path).unwrap(), original);
    }

    /// The chain in `crate::handle` runs whichever area claims a frame, so a
    /// step this module claims and does not answer would be refused by the
    /// module that owns it — and, worse, a step it does *not* claim would be
    /// told it is not answered by a shard, which is exactly what a move's
    /// steps are.
    #[test]
    fn every_step_of_a_move_is_claimed_by_the_module_that_runs_it() {
        for req in [
            Request::MoveOffer { name: "dev".into() },
            Request::MovePrepare {
                name: "dev".into(),
                to_device: "desktop".into(),
                epoch: 1,
            },
            Request::MoveCommitSource {
                name: "dev".into(),
                epoch: 1,
            },
            Request::MoveAbortSource {
                name: "dev".into(),
                epoch: 1,
            },
            Request::MoveAbortTarget {
                name: "dev".into(),
                epoch: 1,
            },
        ] {
            assert!(is_step(&req), "{req:?}");
        }
        // `set cpu` is the move, not a step of it: it reports as it goes, on
        // the connection that asked, and a shard has nowhere to send that.
        assert!(!is_step(&Request::SetCpu {
            name: "dev".into(),
            device: "desktop".into(),
            down: false,
        }));
        assert!(!is_step(&Request::Up {
            name: "dev".into(),
            restart: None
        }));
    }

    #[test]
    fn the_files_a_move_carries_leave_this_devices_plumbing_behind() {
        for junk in [
            "console.log",
            "qemu.pid",
            "vz.pid",
            "qmp.sock",
            "disk.raw.part",
            "egress-ca.key.bak",
            ".move-receipt.json",
        ] {
            assert!(
                is_plumbing(junk),
                "{junk} belongs to this device, not to the guest"
            );
        }
        for carried in [
            "disk.raw",
            "efi-vars.fd",
            "seed.iso",
            "seed.stamp",
            "clean.raw",
        ] {
            assert!(!is_plumbing(carried), "{carried} has to travel");
        }
    }

    fn manifest_of(files: Vec<MoveFile>) -> MoveManifest {
        MoveManifest {
            instance: Instance::new(
                "dev",
                "laptop",
                "debian:13",
                Default::default(),
                test_machine(),
            ),
            arch: std::env::consts::ARCH.to_owned(),
            base: BaseImage::absent("debian:13".to_owned()),
            files,
            local_volumes: Vec::new(),
        }
    }

    /// The completeness check is the whole of what the commit rests on, so
    /// every way of arriving short has to be a refusal.
    #[test]
    fn a_transfer_that_arrived_short_is_not_adopted() {
        let dir = tempfile::tempdir().unwrap();
        let staging = dir.path().join("dev.moving-1");
        std::fs::create_dir_all(&staging).unwrap();
        std::fs::write(staging.join("disk.raw"), vec![0u8; 4096]).unwrap();

        let manifest = manifest_of(vec![MoveFile {
            path: "disk.raw".into(),
            len: 4096,
            allocated: 4096,
            mode: 0o600,
        }]);

        // No receipt at all: the transfer never finished.
        let err = verify(&staging, &manifest, 1).unwrap_err().to_string();
        assert!(err.contains("never finished"), "{err}");

        // A receipt from another epoch is somebody else's transfer.
        Receipt {
            epoch: 2,
            from_device: "laptop".into(),
            bytes: 4096,
            files: [("disk.raw".to_owned(), 4096u64)].into_iter().collect(),
        }
        .save(&staging)
        .unwrap();
        let err = verify(&staging, &manifest, 1).unwrap_err().to_string();
        assert!(err.contains("epoch"), "{err}");

        // The right epoch and the right bytes is the one that passes.
        Receipt {
            epoch: 1,
            from_device: "laptop".into(),
            bytes: 4096,
            files: [("disk.raw".to_owned(), 4096u64)].into_iter().collect(),
        }
        .save(&staging)
        .unwrap();
        verify(&staging, &manifest, 1).unwrap();

        // A file that arrived the wrong length is refused even though the
        // byte count adds up — sparse means those are different questions.
        std::fs::write(staging.join("disk.raw"), vec![0u8; 2048]).unwrap();
        let err = verify(&staging, &manifest, 1).unwrap_err().to_string();
        assert!(err.contains("2048") && err.contains("4096"), "{err}");

        // And a file that never turned up at all.
        std::fs::remove_file(staging.join("disk.raw")).unwrap();
        let err = verify(&staging, &manifest, 1).unwrap_err().to_string();
        assert!(err.contains("did not arrive"), "{err}");

        // A staging directory that is not there is the crashed-mid-move case.
        let err = verify(&dir.path().join("nope"), &manifest, 1)
            .unwrap_err()
            .to_string();
        assert!(err.contains("no staging directory"), "{err}");
    }
}
