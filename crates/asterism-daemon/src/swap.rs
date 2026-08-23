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
//! # Durable authority, and an epoch
//!
//! There must never be two bootable copies. So:
//!
//! 1. **Prepare.** The source marks the instance [`Moving`] at `epoch + 1`
//!    and refuses to boot it. Its row is still the authoritative one.
//! 2. **Transfer.** The target writes into a *staging* directory whose name
//!    no instance can have. Nothing lists it, nothing boots it, and a daemon
//!    that dies in the middle leaves it there to be swept.
//! 3. **Reserve, target (live only).** After dirty disk and RAM reach their
//!    backend boundaries, the target durably chooses `Reserved` against the
//!    only competing `Aborted` transition.
//! 4. **Decide, source (live only).** Only after that exact token-bound
//!    reservation, the source durably records its no-return decision before
//!    releasing either switchover.
//! 5. **Commit, target.** The target checks that source decision, both stream
//!    EOF records and its incoming backend completion before it renames the
//!    staging directory and writes its higher-epoch shard row.
//! 6. **Commit, source.** The source writes a permanent completion WAL, drops
//!    its row and bytes, and separately leaves an expiring courtesy note.
//!
//! A live abort is legal only before step 3 and only after the target records
//! durable Aborted proof. After the source decision, recovery drives target
//! commit forward and never makes the old row bootable again. The immutable
//! id/epoch/token makes a late commit, abort or reply replay harmless.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, Weak};

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};

use asterism_core::cow;
use asterism_core::durable;
use asterism_core::hv::{ControlChannel, Handle, MigrationDiskExport, MigrationSource, Ready};
use asterism_core::instance::{now_unix, Instance, MoveSourcePhase, Moving, Status, VolumeKind};
use asterism_core::paths;
use asterism_core::protocol::{
    BaseImage, MoveAuthorityPhase, MoveFile, MoveManifest, Request, Response,
};
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
const LIVE_SOCKET: &str = ".live-migration.sock";
const LIVE_HANDLE: &str = ".live-migration-handle.json";
const LIVE_AUTHORITY: &str = ".move-authority.json";
const AUTHORITY_DIR: &str = "move-authority";
const SOURCE_COMPLETION_DIR: &str = "move-source-completion";

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

/// Serialize every target authority read/modify/write, including EOF writes
/// made by mesh pump tasks that do not hold the shard mutex.  There is one
/// daemon per device, so this is the target-local CAS boundary: a stale EOF
/// callback cannot overwrite Aborted/Committing and disk/RAM EOF callbacks
/// cannot lose one another's bit.
fn with_authority_txn<T>(f: impl FnOnce() -> T) -> T {
    static SERIAL: OnceLock<Mutex<()>> = OnceLock::new();
    let _guard = SERIAL
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    f()
}

fn source_decision_lock(instance_id: &str, epoch: u64) -> Arc<tokio::sync::Mutex<()>> {
    type Key = (String, u64);
    type Lock = tokio::sync::Mutex<()>;
    static LOCKS: OnceLock<Mutex<BTreeMap<Key, Weak<Lock>>>> = OnceLock::new();

    let mut locks = LOCKS
        .get_or_init(|| Mutex::new(BTreeMap::new()))
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    locks.retain(|_, lock| lock.strong_count() > 0);
    let key = (instance_id.to_owned(), epoch);
    if let Some(lock) = locks.get(&key).and_then(Weak::upgrade) {
        return lock;
    }
    let lock = Arc::new(Lock::new(()));
    locks.insert(key, Arc::downgrade(&lock));
    lock
}

// ---- staging ---------------------------------------------------------------

/// Where a half-arrived instance lives until it is committed.
///
/// Under `instances/`, next to the real ones, so it is on the same filesystem
/// and the commit is a rename rather than a copy — and named so that no
/// instance could ever be called that.
pub fn staging_dir(name: &str, instance_id: &str, epoch: u64, token: &str) -> PathBuf {
    // A name and epoch fence the normal move protocol, but they do not
    // identify an attempted move by themselves.  In particular, a stale
    // attempt must not be able to remove or adopt bytes staged by a newer
    // id/token winner while recovery is running.  Keep the human-readable
    // name/epoch prefix and add a stable, filesystem-safe identity suffix so
    // replay and restart still locate the same tree.
    let identity = blake3::hash(format!("{instance_id}\0{token}").as_bytes()).to_hex();
    paths::instance_dir(&format!("{name}{STAGING}{epoch}-{}", &identity[..12]))
}

fn staging_for(txn: &AuthorityTxn) -> Result<PathBuf> {
    recoverable_staging_dir(&txn.name, &txn.instance_id, txn.epoch, &txn.token)
}

fn legacy_staging_dir(name: &str, epoch: u64) -> PathBuf {
    paths::instance_dir(&format!("{name}{STAGING}{epoch}"))
}

fn is_legacy_staging_name(name: &str) -> bool {
    name.rsplit_once(STAGING)
        .is_some_and(|(_, epoch)| epoch.parse::<u64>().is_ok())
}

/// Locate a staged tree created by this protocol revision, or an old-format
/// tree whose durable receipt proves it belongs to this exact attempt.
///
/// The old `name + epoch` spelling is only a locator, never authority.  In
/// particular, a restarted name may refer to a different instance that won
/// the same epoch, so an absent, corrupt, or foreign receipt is a refusal
/// rather than permission to touch that directory.
fn recoverable_staging_dir(
    name: &str,
    instance_id: &str,
    epoch: u64,
    token: &str,
) -> Result<PathBuf> {
    let scoped = staging_dir(name, instance_id, epoch, token);
    if scoped.exists() {
        return Ok(scoped);
    }
    let legacy = legacy_staging_dir(name, epoch);
    if legacy.exists() {
        Receipt::load(&legacy)?.matches_attempt(instance_id, epoch, token)?;
        Ok(legacy)
    } else {
        Ok(scoped)
    }
}

/// Identity-scoped staging for a different token is invisible to
/// [`recoverable_staging_dir`]. A missing path is therefore not proof that
/// nothing is staged, and a successful abort is resume proof, so the no-WAL
/// arm must refuse when a name/epoch sibling's receipt is not this attempt.
fn refuse_unmatched_staging_siblings(
    name: &str,
    instance_id: &str,
    epoch: u64,
    token: &str,
) -> Result<()> {
    let dir = paths::home_dir().join("instances");
    let entries = match std::fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e).with_context(|| format!("reading {}", dir.display())),
    };
    let legacy = format!("{name}{STAGING}{epoch}");
    let scoped_prefix = format!("{name}{STAGING}{epoch}-");
    for entry in entries {
        let path = entry?.path();
        let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if file_name != legacy && !file_name.starts_with(&scoped_prefix) {
            continue;
        }
        if !path.is_dir() {
            continue;
        }
        if Receipt::load(&path)
            .and_then(|receipt| receipt.matches_attempt(instance_id, epoch, token))
            .is_err()
        {
            bail!(
                "staging {} does not match id/epoch/token; refusing to abort another move",
                path.display()
            );
        }
    }
    Ok(())
}

pub(crate) fn live_socket(
    name: &str,
    instance_id: &str,
    epoch: u64,
    token: &str,
) -> Result<PathBuf> {
    Ok(paths::migration_socket_in(&recoverable_staging_dir(
        name,
        instance_id,
        epoch,
        token,
    )?))
}

pub(crate) fn authorize_live_splice(
    instance_id: &str,
    name: &str,
    epoch: u64,
    source_device: &str,
    source_device_id: &str,
    token: &str,
    lane: u64,
) -> Result<()> {
    let txn = load_authority(instance_id, epoch)?.with_context(|| {
        format!("no durable target intent exists for id {instance_id:?} epoch {epoch}")
    })?;
    if !txn.live {
        bail!("target authority is not a live migration");
    }
    if txn.name != name {
        bail!("target intent is for {:?}, not {name:?}", txn.name);
    }
    if txn.token != token {
        bail!("live migration token does not match the durable target claim");
    }
    if txn.lane != lane || !txn.lane_ready {
        bail!(
            "live migration lane {lane} is stale; target expects lane {}",
            txn.lane
        );
    }
    if txn.source_device != source_device || txn.source_device_id != source_device_id {
        bail!(
            "live migration for {name:?} expects authenticated source {:?} ({}) but arrived from {:?} ({})",
            txn.source_device,
            txn.source_device_id,
            source_device,
            source_device_id
        );
    }
    if !matches!(
        txn.phase,
        MoveAuthorityPhase::Prepared | MoveAuthorityPhase::Reserved
    ) {
        bail!(
            "live migration for {name:?} is {:?}, not prepared to accept a stream",
            txn.phase
        );
    }
    Ok(())
}

pub(crate) fn authorize_disk_splice(
    instance_id: &str,
    name: &str,
    epoch: u64,
    token: &str,
    source_device: &str,
    source_device_id: &str,
    lane: u64,
) -> Result<MigrationDiskExport> {
    let txn = load_authority(instance_id, epoch)?
        .with_context(|| format!("no target disk claim for id {instance_id:?} epoch {epoch}"))?;
    if !txn.live
        || txn.name != name
        || txn.token != token
        || txn.source_device != source_device
        || txn.source_device_id != source_device_id
        || txn.lane != lane
        || !txn.lane_ready
        || !matches!(
            txn.phase,
            MoveAuthorityPhase::DiskPrepared | MoveAuthorityPhase::Reserved
        )
    {
        bail!("dirty-disk splice does not match the durable id/epoch/token/source claim");
    }
    txn.disk_export
        .filter(|export| export.proc.alive())
        .context("target disk export is absent or dead")
}

pub(crate) fn authorize_live_import(
    manifest: &MoveManifest,
    epoch: u64,
    token: &str,
    source_device: &str,
    source_device_id: &str,
) -> Result<()> {
    with_authority_txn(|| {
        validate_live_import_locked(manifest, epoch, token, source_device, source_device_id)
    })
}

fn validate_live_import_locked(
    manifest: &MoveManifest,
    epoch: u64,
    token: &str,
    source_device: &str,
    source_device_id: &str,
) -> Result<()> {
    let txn = load_authority(&manifest.instance.id, epoch)?
        .context("target live-import authority is absent")?;
    if !txn.live
        || txn.phase != MoveAuthorityPhase::Intent
        || txn.name != manifest.instance.name
        || txn.token != token
        || txn.source_device != source_device
        || txn.source_device_id != source_device_id
        || serde_json::to_vec(&txn.manifest)? != serde_json::to_vec(manifest)?
    {
        bail!("live import does not match the durable id/epoch/token/source/device intent");
    }
    Ok(())
}

pub(crate) fn save_live_import_receipt(
    manifest: &MoveManifest,
    epoch: u64,
    token: &str,
    source_device: &str,
    source_device_id: &str,
    receipt: &Receipt,
) -> Result<()> {
    with_authority_txn(|| {
        validate_live_import_locked(manifest, epoch, token, source_device, source_device_id)?;
        receipt.save(&staging_dir(
            &manifest.instance.name,
            &manifest.instance.id,
            epoch,
            token,
        ))
    })
}

pub(crate) fn mark_target_stream_eof(
    instance_id: &str,
    epoch: u64,
    token: &str,
    lane: u64,
    disk: bool,
) -> Result<()> {
    with_authority_txn(|| mark_target_stream_eof_locked(instance_id, epoch, token, lane, disk))
}

fn mark_target_stream_eof_locked(
    instance_id: &str,
    epoch: u64,
    token: &str,
    lane: u64,
    disk: bool,
) -> Result<()> {
    let mut txn =
        load_authority(instance_id, epoch)?.context("target claim vanished at stream EOF")?;
    if txn.token != token {
        bail!("stream EOF token does not match the target claim");
    }
    if !txn.live {
        bail!("stream EOF does not belong to a live migration");
    }
    if txn.lane != lane || !txn.lane_ready {
        bail!(
            "stream EOF lane {lane} is stale; durable target lane is {}",
            txn.lane
        );
    }
    if !matches!(
        txn.phase,
        MoveAuthorityPhase::Prepared | MoveAuthorityPhase::Reserved
    ) {
        bail!(
            "stream EOF cannot update target authority in phase {:?}",
            txn.phase
        );
    }
    if disk {
        txn.disk_eof = true;
    } else {
        txn.ram_eof = true;
    }
    save_authority(&txn)
}

fn live_sessions() -> MutexGuard<'static, BTreeMap<(String, u64), Handle>> {
    static SESSIONS: OnceLock<Mutex<BTreeMap<(String, u64), Handle>>> = OnceLock::new();
    SESSIONS
        .get_or_init(|| Mutex::new(BTreeMap::new()))
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

/// Delete every staging directory on this device.
///
/// Run at daemon start — before the socket is bound, before the mesh comes
/// up — which is the "next contact" a killed transfer gets.
/// A staging directory is by construction not referenced by any shard row, so
/// there is nothing to consult before removing one: if it were committed it
/// would not be called this any more.
pub fn sweep_staging() {
    let mut claimed = BTreeSet::new();
    let mut verified_legacy = BTreeSet::new();
    let authority_dir = paths::home_dir().join(AUTHORITY_DIR);
    if let Ok(entries) = std::fs::read_dir(authority_dir) {
        for entry in entries.flatten() {
            if let Ok(Some(loaded)) =
                durable::load_json::<AuthorityTxn>(&entry.path(), "a move authority transaction")
            {
                let staging = match staging_for(&loaded.value) {
                    Ok(staging) => staging,
                    Err(e) => {
                        eprintln!(
                            "astd: retaining legacy staging for {:?} epoch {}: {e:#}",
                            loaded.value.name, loaded.value.epoch
                        );
                        continue;
                    }
                };
                if staging == legacy_staging_dir(&loaded.value.name, loaded.value.epoch) {
                    verified_legacy.insert(staging.clone());
                }
                if !matches!(
                    loaded.value.phase,
                    MoveAuthorityPhase::Committed | MoveAuthorityPhase::Aborted
                ) {
                    claimed.insert(staging);
                }
            }
        }
    }
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
        let path = entry.path();
        if claimed.contains(&path) {
            continue;
        }
        if is_legacy_staging_name(name) && !verified_legacy.contains(&path) {
            eprintln!(
                "astd: retaining {} — legacy staging has no matching durable identity receipt",
                path.display()
            );
            continue;
        }
        let handle_path = path.join(LIVE_HANDLE);
        if let Ok(bytes) = std::fs::read(&handle_path) {
            if let Ok(handle) = serde_json::from_slice::<Handle>(&bytes) {
                let _ = backend::for_handle(&handle.backend).and_then(|hv| hv.kill(&handle));
            }
        }
        // A deep home uses a short runtime path outside staging, so removing
        // the directory alone would leave the backend socket behind.
        let _ = std::fs::remove_file(paths::migration_socket_in(&path));
        match std::fs::remove_dir_all(&path) {
            Ok(()) => eprintln!(
                "astd: swept {} — an interrupted move left it, and it was never bootable",
                entry.path().display()
            ),
            Err(e) => eprintln!("astd: could not sweep {}: {e}", entry.path().display()),
        }
    }
}

/// Reconcile target authority before generic staging cleanup or guest
/// resurrection. A prepared transaction lost its stream with the daemon and
/// is durably aborted; a transaction that crossed `Committing` is completed.
pub fn reconcile_target_startup(reg: &mut Shard, device: &str) {
    let dir = paths::home_dir().join(AUTHORITY_DIR);
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let txn = match durable::load_json::<AuthorityTxn>(&path, "a move authority transaction") {
            Ok(Some(loaded)) => loaded.value,
            Ok(None) => continue,
            Err(e) => {
                eprintln!("astd: cannot reconcile {}: {e:#}", path.display());
                continue;
            }
        };
        let published = published_for(&txn)
            || reg
                .get(&txn.name)
                .ok()
                .is_some_and(|i| i.id == txn.instance_id && i.move_epoch == txn.epoch);
        match txn.phase {
            MoveAuthorityPhase::Intent
            | MoveAuthorityPhase::DiskPrepared
            | MoveAuthorityPhase::Prepared
            | MoveAuthorityPhase::Reserved
                if !published =>
            {
                eprintln!(
                    "astd: target preparation for {:?} epoch {} remains fenced until source reconciliation",
                    txn.name, txn.epoch
                );
            }
            _ => {
                let response = with_authority_txn(|| {
                    target_status(
                        reg,
                        &txn.instance_id,
                        &txn.name,
                        txn.epoch,
                        &txn.token,
                        device,
                    )
                });
                if let Response::Error { message } = response {
                    eprintln!(
                        "astd: target authority for {:?} epoch {} remains fenced: {message}",
                        txn.name, txn.epoch
                    );
                }
            }
        }
    }
}

/// Settle a source guest left at a live pre-switchover boundary. The target's
/// durable transaction is the only fact that may resume or destroy it. If the
/// target is unreachable or indeterminate the source stays fenced.
pub async fn reconcile_source_startup(node: &Node, mesh: &Arc<Mesh>) {
    let pending: Vec<(String, String, String, u64, String, MoveSourcePhase)> = {
        let reg = node.shard.lock().await;
        reg.list()
            .into_iter()
            .filter_map(|inst| {
                let moving = inst.moving.as_ref()?;
                moving.live.then(|| {
                    (
                        inst.id.clone(),
                        inst.name.clone(),
                        moving.to_device.clone(),
                        moving.epoch,
                        moving.token.clone(),
                        moving.phase,
                    )
                })
            })
            .collect()
    };

    for (instance_id, name, target, epoch, token, source_phase) in pending {
        if source_phase == MoveSourcePhase::Committed {
            let manifest = {
                let reg = node.shard.lock().await;
                match reg.get(&name).and_then(manifest) {
                    Ok(manifest) => manifest,
                    Err(e) => {
                        eprintln!("astd: cannot rebuild committed live move {name:?}: {e:#}");
                        continue;
                    }
                }
            };
            if let Response::Error { message } =
                decide_source(node, &instance_id, &name, epoch, &token).await
            {
                eprintln!("astd: committed live source {name:?} remains fenced: {message}");
                continue;
            }
            match ask(
                &target,
                Request::MoveCommitTarget {
                    manifest: Box::new(manifest),
                    epoch,
                    token: token.clone(),
                },
                node,
                mesh,
            )
            .await
            {
                Ok(response) => {
                    if let Err(e) = exact_target_commit(response, &instance_id, epoch, &token) {
                        eprintln!(
                            "astd: committed live source {name:?} remains fenced; target commit proof is invalid: {e:#}"
                        );
                        continue;
                    }
                    let mut reg = node.shard.lock().await;
                    if let Response::Error { message } = commit_source_checked(
                        &mut reg,
                        &instance_id,
                        &name,
                        epoch,
                        &token,
                    )
                    .await
                    {
                        eprintln!("astd: releasing committed live source {name:?}: {message}");
                    }
                }
                Err(e) => eprintln!(
                    "astd: committed live source {name:?} remains fenced until {target} is reachable: {e:#}"
                ),
            }
            continue;
        }
        let status = ask(
            &target,
            Request::MoveTargetStatus {
                instance_id: instance_id.clone(),
                name: name.clone(),
                epoch,
                token: token.clone(),
            },
            node,
            mesh,
        )
        .await;
        let phase = match status {
            Ok(response) => match exact_target_authority(response, &instance_id, epoch, &token) {
                Ok(proof) => proof.phase,
                Err(e) => {
                    eprintln!(
                        "astd: live source {name:?} remains fenced; target authority is invalid: {e:#}"
                    );
                    continue;
                }
            },
            Err(e) => {
                eprintln!(
                    "astd: live source {name:?} remains fenced until {target} is reachable: {e:#}"
                );
                continue;
            }
        };

        if phase == MoveAuthorityPhase::Reserved {
            let manifest = {
                let reg = node.shard.lock().await;
                match reg.get(&name).and_then(manifest) {
                    Ok(manifest) => manifest,
                    Err(e) => {
                        eprintln!("astd: cannot rebuild reserved live move {name:?}: {e:#}");
                        continue;
                    }
                }
            };
            if let Response::Error { message } =
                decide_source(node, &instance_id, &name, epoch, &token).await
            {
                eprintln!("astd: reserved live source {name:?} remains fenced: {message}");
                continue;
            }
            match ask(
                &target,
                Request::MoveCommitTarget {
                    manifest: Box::new(manifest),
                    epoch,
                    token: token.clone(),
                },
                node,
                mesh,
            )
            .await
            {
                Ok(response) => {
                    if let Err(e) = exact_target_commit(response, &instance_id, epoch, &token) {
                        eprintln!(
                            "astd: reserved live source {name:?} remains fenced; target commit proof is invalid: {e:#}"
                        );
                        continue;
                    }
                    let mut reg = node.shard.lock().await;
                    if let Response::Error { message } = commit_source_checked(
                        &mut reg,
                        &instance_id,
                        &name,
                        epoch,
                        &token,
                    )
                    .await
                    {
                        eprintln!("astd: releasing recovered live source {name:?}: {message}");
                    }
                }
                Err(e) => eprintln!(
                    "astd: reserved live source {name:?} remains fenced until {target} is reachable: {e:#}"
                ),
            }
            continue;
        }

        let commit = phase == MoveAuthorityPhase::Committed;
        let abort = if matches!(
            phase,
            MoveAuthorityPhase::Intent
                | MoveAuthorityPhase::DiskPrepared
                | MoveAuthorityPhase::Prepared
        ) {
            target_abort_proof(&target, &instance_id, &name, epoch, &token, node, mesh)
                .await
                .unwrap_or(false)
        } else {
            phase == MoveAuthorityPhase::Aborted
        };
        let mut reg = node.shard.lock().await;
        let response = if commit {
            commit_source_after_proof(&mut reg, &instance_id, &name, epoch, &token)
        } else if abort {
            abort_source_checked(&mut reg, &instance_id, &name, epoch, &token).await
        } else {
            continue;
        };
        if let Response::Error { message } = response {
            eprintln!("astd: reconciling live source {name:?}: {message}");
        }
    }
}

/// Reconcile target-side precommit WALs after the authenticated mesh exists.
/// A target never guesses across an unreachable source: Fenced is the only
/// abort proof, and Committed is the only direction that may finish publish.
pub async fn reconcile_target_mesh(node: &Node, mesh: &Arc<Mesh>) {
    let dir = paths::home_dir().join(AUTHORITY_DIR);
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return;
    };
    let mut pending = Vec::new();
    for entry in entries.flatten() {
        match durable::load_json::<AuthorityTxn>(&entry.path(), "a move authority transaction") {
            Ok(Some(loaded))
                if matches!(
                    loaded.value.phase,
                    MoveAuthorityPhase::Intent
                        | MoveAuthorityPhase::DiskPrepared
                        | MoveAuthorityPhase::Prepared
                        | MoveAuthorityPhase::Reserved
                ) =>
            {
                pending.push(loaded.value)
            }
            Ok(_) => {}
            Err(e) => eprintln!("astd: cannot read target reconciliation WAL: {e:#}"),
        }
    }
    let target = mesh.self_name().await;
    for txn in pending {
        let decision = ask(
            &txn.source_device,
            Request::MoveSourceStatus {
                instance_id: txn.instance_id.clone(),
                name: txn.name.clone(),
                epoch: txn.epoch,
                token: txn.token.clone(),
            },
            node,
            mesh,
        )
        .await;
        let source_phase = match decision {
            Ok(response) => {
                match exact_source_phase(response, &txn.instance_id, txn.epoch, &txn.token) {
                    Ok(phase) => phase,
                    Err(e) => {
                        eprintln!(
                        "astd: target {:?} epoch {} remains fenced; source proof is invalid: {e:#}",
                        txn.name, txn.epoch
                    );
                        continue;
                    }
                }
            }
            Err(e) => {
                eprintln!(
                    "astd: target {:?} epoch {} remains fenced until source is reachable: {e:#}",
                    txn.name, txn.epoch
                );
                continue;
            }
        };
        let request = match source_phase {
            MoveSourcePhase::Fenced if txn.phase == MoveAuthorityPhase::Reserved => {
                match ask(
                    &txn.source_device,
                    Request::MoveDecideSource {
                        instance_id: txn.instance_id.clone(),
                        name: txn.name.clone(),
                        epoch: txn.epoch,
                        token: txn.token.clone(),
                    },
                    node,
                    mesh,
                )
                .await
                {
                    Ok(response) => {
                        match exact_source_phase(response, &txn.instance_id, txn.epoch, &txn.token)
                        {
                            Ok(MoveSourcePhase::Committed) => Request::MoveCommitTarget {
                                manifest: Box::new(txn.manifest.clone()),
                                epoch: txn.epoch,
                                token: txn.token.clone(),
                            },
                            _ => {
                                eprintln!(
                                "astd: reserved target {:?} epoch {} remains fenced; source did not replay the exact committed winner",
                                txn.name, txn.epoch
                            );
                                continue;
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!(
                            "astd: reserved target {:?} epoch {} remains fenced until source recovery: {e:#}",
                            txn.name, txn.epoch
                        );
                        continue;
                    }
                }
            }
            MoveSourcePhase::Fenced => Request::MoveAbortTarget {
                instance_id: txn.instance_id.clone(),
                name: txn.name.clone(),
                epoch: txn.epoch,
                token: txn.token.clone(),
            },
            MoveSourcePhase::Committed => Request::MoveCommitTarget {
                manifest: Box::new(txn.manifest.clone()),
                epoch: txn.epoch,
                token: txn.token.clone(),
            },
        };
        if let Err(e) = ask(&target, request, node, mesh).await {
            eprintln!(
                "astd: target {:?} epoch {} reconciliation remains pending: {e:#}",
                txn.name, txn.epoch
            );
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
    #[serde(default)]
    pub instance_id: String,
    pub epoch: u64,
    #[serde(default)]
    pub token: String,
    pub from_device: String,
    /// Total bytes written.
    pub bytes: u64,
    /// Per file, relative path to bytes written.
    pub files: BTreeMap<String, u64>,
}

/// Write-ahead record for the target half of an authority transfer.
///
/// It deliberately lives outside both the staging and live instance trees.
/// Publishing either tree therefore cannot hide the evidence startup needs
/// to finish or reject the transaction. The filename is the immutable
/// instance id plus epoch; the name is only descriptive and may never select
/// another transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct AuthorityTxn {
    version: u32,
    instance_id: String,
    name: String,
    epoch: u64,
    phase: MoveAuthorityPhase,
    manifest: MoveManifest,
    live: bool,
    #[serde(default)]
    source_device: String,
    #[serde(default)]
    source_device_id: String,
    #[serde(default)]
    token: String,
    #[serde(default)]
    coordinator_id: String,
    #[serde(default)]
    handle: Option<Handle>,
    #[serde(default)]
    disk_export: Option<MigrationDiskExport>,
    #[serde(default)]
    disk_eof: bool,
    #[serde(default)]
    ram_eof: bool,
    #[serde(default = "initial_lane")]
    lane: u64,
    #[serde(default = "default_true")]
    lane_ready: bool,
}

fn initial_lane() -> u64 {
    1
}

fn default_true() -> bool {
    true
}

/// Identity evidence that moves with the staging tree when it is published.
///
/// A directory name alone is not authority: another instance may have
/// claimed that name while a daemon was down. This marker makes the
/// rename-before-row crash boundary distinguishable from such a collision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct AuthorityMarker {
    version: u32,
    instance_id: String,
    epoch: u64,
}

impl AuthorityMarker {
    fn of(txn: &AuthorityTxn) -> Self {
        Self {
            version: 1,
            instance_id: txn.instance_id.clone(),
            epoch: txn.epoch,
        }
    }
}

fn authority_key(instance_id: &str, epoch: u64) -> String {
    let mut encoded = String::with_capacity(instance_id.len() * 2 + 24);
    for byte in instance_id.as_bytes() {
        use std::fmt::Write as _;
        let _ = write!(encoded, "{byte:02x}");
    }
    format!("{encoded}-{epoch}.json")
}

fn authority_path(instance_id: &str, epoch: u64) -> PathBuf {
    paths::home_dir()
        .join(AUTHORITY_DIR)
        .join(authority_key(instance_id, epoch))
}

fn load_authority(instance_id: &str, epoch: u64) -> Result<Option<AuthorityTxn>> {
    let path = authority_path(instance_id, epoch);
    let Some(loaded) = durable::load_json(&path, "a move authority transaction")? else {
        return Ok(None);
    };
    let txn: AuthorityTxn = loaded.value;
    if txn.instance_id != instance_id || txn.epoch != epoch {
        bail!(
            "move authority transaction {} is for id {:?} epoch {}, not {:?} epoch {epoch}",
            path.display(),
            txn.instance_id,
            txn.epoch,
            instance_id
        );
    }
    Ok(Some(txn))
}

fn load_authority_for_name_epoch(name: &str, epoch: u64) -> Result<Option<AuthorityTxn>> {
    let dir = paths::home_dir().join(AUTHORITY_DIR);
    let entries = match std::fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).with_context(|| format!("reading {}", dir.display())),
    };
    let mut winner = None;
    for entry in entries {
        let path = entry?.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
            continue;
        }
        let Some(loaded) =
            durable::load_json::<AuthorityTxn>(&path, "a move authority transaction")?
        else {
            continue;
        };
        let txn = loaded.value;
        if txn.name != name || txn.epoch != epoch {
            continue;
        }
        if winner.is_some() {
            bail!("multiple target authority transactions claim {name:?} at epoch {epoch}");
        }
        winner = Some(txn);
    }
    Ok(winner)
}

fn save_authority(txn: &AuthorityTxn) -> Result<()> {
    durable::commit_json(&authority_path(&txn.instance_id, txn.epoch), txn)
        .context("committing the target authority transaction")
}

fn save_authority_marker(dir: &Path, txn: &AuthorityTxn) -> Result<()> {
    durable::commit_json(&dir.join(LIVE_AUTHORITY), &AuthorityMarker::of(txn))
        .context("recording the immutable authority of the tree being published")
}

fn published_for(txn: &AuthorityTxn) -> bool {
    let path = paths::instance_dir(&txn.name).join(LIVE_AUTHORITY);
    durable::load_json::<AuthorityMarker>(&path, "a published move authority marker")
        .ok()
        .flatten()
        .is_some_and(|loaded| loaded.value == AuthorityMarker::of(txn))
}

fn validate_target_replay(
    txn: &AuthorityTxn,
    manifest: &MoveManifest,
    epoch: u64,
    source_device: &str,
    source_device_id: &str,
    token: &str,
    coordinator_id: Option<&str>,
) -> Result<()> {
    if !txn.live
        || txn.epoch != epoch
        || txn.instance_id != manifest.instance.id
        || txn.name != manifest.instance.name
        || txn.source_device != source_device
        || txn.source_device_id != source_device_id
        || txn.token != token
        || coordinator_id.is_some_and(|id| txn.coordinator_id != id)
        || serde_json::to_vec(&txn.manifest)? != serde_json::to_vec(manifest)?
    {
        bail!(
            "live migration replay does not match the durable target authority for id {:?} epoch {epoch}",
            manifest.instance.id
        );
    }
    Ok(())
}

fn authority_response(txn: &AuthorityTxn, reg: &Shard) -> Response {
    let instance = if txn.phase == MoveAuthorityPhase::Committed {
        reg.get(&txn.name)
            .ok()
            .filter(|i| i.id == txn.instance_id && i.move_epoch == txn.epoch)
            .cloned()
            .map(Box::new)
    } else {
        None
    };
    Response::MoveAuthority {
        instance_id: txn.instance_id.clone(),
        epoch: txn.epoch,
        token: txn.token.clone(),
        lane: txn.lane,
        disk_eof: txn.disk_eof,
        ram_eof: txn.ram_eof,
        phase: txn.phase,
        instance,
    }
}

fn authority_phase_response(txn: &AuthorityTxn) -> Response {
    Response::MoveAuthority {
        instance_id: txn.instance_id.clone(),
        epoch: txn.epoch,
        token: txn.token.clone(),
        lane: txn.lane,
        disk_eof: txn.disk_eof,
        ram_eof: txn.ram_eof,
        phase: txn.phase,
        instance: None,
    }
}

fn disk_ready_response(txn: &AuthorityTxn) -> Response {
    Response::MoveDiskReady {
        instance_id: txn.instance_id.clone(),
        epoch: txn.epoch,
        token: txn.token.clone(),
        lane: txn.lane,
    }
}

fn live_ready_response(txn: &AuthorityTxn) -> Response {
    Response::MoveLiveReady {
        instance_id: txn.instance_id.clone(),
        epoch: txn.epoch,
        token: txn.token.clone(),
        lane: txn.lane,
    }
}

impl Receipt {
    fn path(dir: &Path) -> PathBuf {
        dir.join(".move-receipt.json")
    }

    pub fn save(&self, dir: &Path) -> Result<()> {
        durable::commit_json(&Self::path(dir), self).context("recording what arrived")
    }

    fn load(dir: &Path) -> Result<Self> {
        let bytes = std::fs::read(Self::path(dir))
            .context("this transfer never finished — there is no record of what arrived")?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    /// Prove that a legacy `name + epoch` directory belongs to one exact
    /// authority transaction before it is used for recovery or cleanup.
    fn matches_attempt(&self, instance_id: &str, epoch: u64, token: &str) -> Result<()> {
        if self.instance_id != instance_id || self.epoch != epoch || self.token != token {
            bail!(
                "legacy staging receipt does not match id/epoch/token; refusing to touch another move"
            );
        }
        Ok(())
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
            | Request::MoveBeginTarget { .. }
            | Request::MoveLivePrepareDisk { .. }
            | Request::MoveLiveDiskReady { .. }
            | Request::MoveLivePrepareTarget { .. }
            | Request::MoveReserveTarget { .. }
            | Request::MoveRecoverTarget { .. }
            | Request::MoveCommitTarget { .. }
            | Request::MoveTargetStatus { .. }
            | Request::MoveSourceStatus { .. }
            | Request::MoveDecideSource { .. }
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
            instance_id,
            name,
            to_device,
            to_device_id,
            epoch,
            token,
            coordinator_id,
            live,
        } => tokio::task::block_in_place(|| {
            prepare(
                reg,
                &instance_id,
                &name,
                &to_device,
                &to_device_id,
                epoch,
                &token,
                &coordinator_id,
                live,
            )
        }),
        Request::MoveBeginTarget {
            manifest,
            epoch,
            source_device,
            source_device_id,
            token,
            coordinator_id,
        } => tokio::task::block_in_place(|| {
            with_authority_txn(|| {
                begin_target(
                    &manifest,
                    epoch,
                    cpu_device,
                    &source_device,
                    &source_device_id,
                    &token,
                    &coordinator_id,
                )
            })
        }),
        Request::MoveLivePrepareDisk {
            instance_id,
            name,
            epoch,
            token,
        } => tokio::task::block_in_place(|| {
            with_authority_txn(|| prepare_disk_target(&instance_id, &name, epoch, &token))
        }),
        Request::MoveLiveDiskReady {
            instance_id,
            name,
            epoch,
            token,
        } => tokio::task::block_in_place(|| {
            with_authority_txn(|| disk_ready_target(&instance_id, &name, epoch, &token))
        }),
        Request::MoveLivePrepareTarget {
            manifest,
            epoch,
            source_device,
            source_device_id,
            token,
        } => tokio::task::block_in_place(|| {
            with_authority_txn(|| {
                live_prepare_target(
                    &manifest,
                    epoch,
                    cpu_device,
                    &source_device,
                    &source_device_id,
                    &token,
                )
            })
        }),
        Request::MoveReserveTarget {
            instance_id,
            name,
            epoch,
            token,
        } => tokio::task::block_in_place(|| {
            with_authority_txn(|| reserve_target(reg, &instance_id, &name, epoch, &token))
        }),
        Request::MoveRecoverTarget {
            instance_id,
            name,
            epoch,
            token,
            from_lane,
        } => tokio::task::block_in_place(|| {
            with_authority_txn(|| {
                recover_target(reg, &instance_id, &name, epoch, &token, from_lane)
            })
        }),
        Request::MoveCommitTarget {
            manifest,
            epoch,
            token,
        } => tokio::task::block_in_place(|| {
            with_authority_txn(|| commit_target(reg, &manifest, epoch, &token, cpu_device))
        }),
        Request::MoveTargetStatus {
            instance_id,
            name,
            epoch,
            token,
        } => tokio::task::block_in_place(|| {
            with_authority_txn(|| {
                target_status(reg, &instance_id, &name, epoch, &token, cpu_device)
            })
        }),
        Request::MoveSourceStatus {
            instance_id,
            name,
            epoch,
            token,
        } => tokio::task::block_in_place(|| source_status(reg, &instance_id, &name, epoch, &token)),
        Request::MoveDecideSource { .. } => Response::Error {
            message: "source decision must run through the asynchronous node handler".into(),
        },
        Request::MoveCommitSource {
            instance_id,
            name,
            epoch,
            token,
        } => tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(commit_source_checked(
                reg,
                &instance_id,
                &name,
                epoch,
                &token,
            ))
        }),
        Request::MoveAbortSource {
            instance_id,
            name,
            epoch,
            token,
        } => tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(abort_source_checked(
                reg,
                &instance_id,
                &name,
                epoch,
                &token,
            ))
        }),
        Request::MoveAbortTarget {
            instance_id,
            name,
            epoch,
            token,
        } => tokio::task::block_in_place(|| {
            with_authority_txn(|| abort_target(reg, &instance_id, &name, epoch, &token))
        }),
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
/// A fence already in place is replayed only for the exact same attempt.
/// Recovery must settle it before a newer coordinator can begin.
#[allow(clippy::too_many_arguments)]
pub fn prepare(
    reg: &mut Shard,
    instance_id: &str,
    name: &str,
    to_device: &str,
    to_device_id: &str,
    epoch: u64,
    token: &str,
    coordinator_id: &str,
    live: bool,
) -> Response {
    let inst = match reg
        .get(name)
        .cloned()
        .and_then(|inst| movable(&inst, live).map(|()| inst))
    {
        Ok(inst) => inst,
        Err(e) => return error(e),
    };
    let instance_id = if !live && instance_id.is_empty() {
        inst.id.as_str()
    } else {
        instance_id
    };
    if inst.id != instance_id {
        return error(anyhow!(
            "instance name {name:?} identifies {}, not requested id {instance_id}",
            inst.id
        ));
    }
    if live && (token.is_empty() || to_device_id.is_empty() || coordinator_id.is_empty()) {
        return error(anyhow!(
            "live migration requires immutable target, token and coordinator identities"
        ));
    }
    if let Some(existing) = &inst.moving {
        if existing.epoch == epoch
            && existing.to_device == to_device
            && existing.to_device_id == to_device_id
            && existing.token == token
            && existing.coordinator_id == coordinator_id
            && existing.live == live
        {
            return match manifest(&inst) {
                Ok(manifest) => Response::MoveOffer {
                    manifest: Box::new(manifest),
                },
                Err(e) => error(e),
            };
        }
        return error(anyhow!(
            "instance {name:?} already has an active move at epoch {} with another immutable token",
            existing.epoch
        ));
    }
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
            to_device_id: to_device_id.to_owned(),
            epoch,
            started_at: now_unix(),
            token: token.to_owned(),
            lane: 0,
            coordinator_id: coordinator_id.to_owned(),
            phase: MoveSourcePhase::Fenced,
            live,
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

/// Verify the target's durable authority before dropping the source.
///
/// The coordinator's commit request is not proof: it may be replayed, forged
/// by another orbit member, or arrive after a reply was lost. The target's
/// id/epoch transaction is the only fact that authorizes deletion.
pub fn source_status(
    reg: &Shard,
    instance_id: &str,
    name: &str,
    epoch: u64,
    token: &str,
) -> Response {
    let inst = match reg.get(name) {
        Ok(inst) if inst.id == instance_id => inst,
        Ok(inst) => {
            return error(anyhow!(
                "source name belongs to id {}, not {instance_id}",
                inst.id
            ))
        }
        Err(e) => return error(e),
    };
    let Some(moving) = inst.moving.as_ref() else {
        return error(anyhow!("source has no durable move transaction"));
    };
    if moving.epoch != epoch || moving.token != token {
        return error(anyhow!(
            "source move identity does not match id/epoch/token"
        ));
    }
    Response::MoveSource {
        instance_id: instance_id.to_owned(),
        epoch,
        token: token.to_owned(),
        phase: moving.phase,
    }
}

#[derive(Debug, Clone, Copy)]
struct TargetProof {
    phase: MoveAuthorityPhase,
    lane: u64,
    disk_eof: bool,
    ram_eof: bool,
}

fn exact_source_phase(
    response: Response,
    instance_id: &str,
    epoch: u64,
    token: &str,
) -> Result<MoveSourcePhase> {
    match response {
        Response::MoveSource {
            instance_id: winner_id,
            epoch: winner_epoch,
            token: winner_token,
            phase,
        } if winner_id == instance_id && winner_epoch == epoch && winner_token == token => {
            Ok(phase)
        }
        Response::MoveSource { .. } => bail!("source decision reply does not match id/epoch/token"),
        Response::Error { message } => bail!(message),
        other => bail!("unexpected source decision: {other:?}"),
    }
}

async fn target_proof(
    target: &Arc<Mesh>,
    device: &str,
    instance_id: &str,
    name: &str,
    epoch: u64,
    token: &str,
) -> Result<TargetProof> {
    exact_target_authority(
        target
            .proxy(
                device,
                Request::MoveTargetStatus {
                    instance_id: instance_id.to_owned(),
                    name: name.to_owned(),
                    epoch,
                    token: token.to_owned(),
                },
            )
            .await?,
        instance_id,
        epoch,
        token,
    )
}

fn exact_target_authority(
    response: Response,
    instance_id: &str,
    epoch: u64,
    token: &str,
) -> Result<TargetProof> {
    match response {
        Response::MoveAuthority {
            instance_id: winner_id,
            epoch: winner_epoch,
            token: winner_token,
            phase,
            lane,
            disk_eof,
            ram_eof,
            ..
        } if winner_id == instance_id && winner_epoch == epoch && winner_token == token => {
            Ok(TargetProof {
                phase,
                lane,
                disk_eof,
                ram_eof,
            })
        }
        Response::MoveAuthority { .. } => {
            bail!("target authority reply does not match id/epoch/token")
        }
        Response::Error { message } => bail!(message),
        other => bail!("unexpected target authority reply: {other:?}"),
    }
}

fn exact_target_commit(
    response: Response,
    instance_id: &str,
    epoch: u64,
    token: &str,
) -> Result<()> {
    match response {
        Response::Instance { instance, .. }
            if instance.id == instance_id && instance.move_epoch == epoch =>
        {
            Ok(())
        }
        Response::MoveAuthority {
            instance_id: winner_id,
            epoch: winner_epoch,
            token: winner_token,
            phase: MoveAuthorityPhase::Committed,
            ..
        } if winner_id == instance_id && winner_epoch == epoch && winner_token == token => Ok(()),
        Response::Error { message } => bail!(message),
        other => bail!("target commit reply does not match id/epoch/token: {other:?}"),
    }
}

pub async fn decide_source(
    node: &Node,
    instance_id: &str,
    name: &str,
    epoch: u64,
    token: &str,
) -> Response {
    // Reply loss can run two copies of this handler concurrently. Serialize
    // one source transaction across target CAS, source WAL and stream work;
    // otherwise both copies could attach producers to the same accepted lane.
    // Status proof deliberately bypasses this lock, so target recovery never
    // waits on the source while the source waits on the target.
    let decision_lock = source_decision_lock(instance_id, epoch);
    let _decision_guard = decision_lock.lock().await;
    let mut reg = node.shard.lock().await;
    let inst = match reg.get(name).cloned() {
        Ok(inst) if inst.id == instance_id => inst,
        Ok(inst) => {
            return error(anyhow!(
                "source name belongs to id {}, not {instance_id}",
                inst.id
            ))
        }
        Err(e) => return error(e),
    };
    let Some(mut moving) = inst.moving.clone() else {
        return error(anyhow!("source has no durable move transaction"));
    };
    if moving.epoch != epoch || moving.token != token || !moving.live {
        return error(anyhow!(
            "source move identity does not match id/epoch/token"
        ));
    }
    let handle = inst.handle.as_ref().filter(|handle| backend::alive(handle));
    if handle.is_none() && moving.phase == MoveSourcePhase::Committed {
        drop(reg);
        let target = match mesh() {
            Ok(mesh) => mesh,
            Err(e) => return error(e),
        };
        match target_proof(
            &target,
            &moving.to_device,
            instance_id,
            name,
            epoch,
            token,
        )
        .await
        {
            Ok(TargetProof {
                phase: MoveAuthorityPhase::Committing | MoveAuthorityPhase::Committed,
                ..
            }) => {
                return Response::MoveSource {
                    instance_id: instance_id.to_owned(),
                    epoch,
                    token: token.to_owned(),
                    phase: MoveSourcePhase::Committed,
                }
            }
            Ok(proof) => {
                return error(anyhow!(
                    "source backend is dead while target authority is {:?}; forward recovery cannot continue",
                    proof.phase
                ))
            }
            Err(e) => return error(e.context("proving target authority after source exit")),
        }
    }
    let Some(handle) = handle else {
        return error(anyhow!(
            "source backend is not alive at the commit boundary"
        ));
    };
    let hv = match backend::for_handle(&handle.backend) {
        Ok(hv) => hv,
        Err(e) => return error(e),
    };

    if moving.phase == MoveSourcePhase::Fenced {
        if let Err(e) = hv
            .migration_disk_ready(handle)
            .and_then(|_| hv.migration_source_ready(handle))
        {
            return error(e.context("source is not ready for its durable no-return decision"));
        }
        let target = match mesh() {
            Ok(mesh) => mesh,
            Err(e) => return error(e),
        };
        match target.device_id_of(&moving.to_device).await {
            Ok(id) if id == moving.to_device_id => {}
            Ok(_) => {
                return error(anyhow!(
                    "live target identity changed after the durable source fence"
                ))
            }
            Err(e) => return error(e.context("resolving the fenced live target")),
        }
        let reservation = target
            .proxy(
                &moving.to_device,
                Request::MoveReserveTarget {
                    instance_id: instance_id.to_owned(),
                    name: name.to_owned(),
                    epoch,
                    token: token.to_owned(),
                },
            )
            .await;
        let reserved_lane = match reservation {
            Ok(Response::MoveAuthority {
                instance_id: winner_id,
                epoch: winner_epoch,
                token: winner_token,
                phase: MoveAuthorityPhase::Reserved,
                lane,
                ..
            }) if winner_id == instance_id
                && winner_epoch == epoch
                && winner_token == token
                && lane > 0 =>
            {
                lane
            }
            Ok(Response::MoveAuthority { phase, .. }) => {
                return error(anyhow!(
                    "target decision winner is {phase:?}, not Reserved; source remains Fenced"
                ))
            }
            Ok(Response::Error { message }) => return error(anyhow!(message)),
            Ok(other) => return error(anyhow!("unexpected target reservation: {other:?}")),
            Err(e) => {
                return error(
                    e.context("target reservation is indeterminate; source remains Fenced"),
                )
            }
        };
        moving.lane = reserved_lane;
        if let Err(e) = persist_source_decision(&mut reg, name, &mut moving) {
            return error(e.context("persisting the source no-return marker"));
        }
    }

    // The source marker is now durable. Stream work must not retain the
    // shard mutex: local lane reconstruction reads this row through `Node`,
    // and source cleanup/status must remain responsive during a long drain.
    drop(reg);

    let target = match mesh() {
        Ok(mesh) => mesh,
        Err(e) => return error(e),
    };

    // The ordinary, no-crash path drains the generation already opened by
    // the coordinator. Missing tasks are not success: they mean this daemon
    // restarted and must consult/rebuild the durable target lane below.
    if crate::mesh::has_live_disk_pump(name, epoch) {
        let _ = hv.migration_disk_commit(handle);
        let _ = crate::mesh::finish_live_disk_pump(name, epoch).await;
    }
    let disk_proof =
        target_proof(&target, &moving.to_device, instance_id, name, epoch, token).await;
    if disk_proof.as_ref().is_ok_and(|proof| proof.disk_eof)
        && crate::mesh::has_live_pump(name, epoch)
    {
        let _ = hv.migration_commit(handle);
        let _ = crate::mesh::finish_live_pump(name, epoch).await;
    }

    let mut proof =
        match target_proof(&target, &moving.to_device, instance_id, name, epoch, token).await {
            Ok(proof) => proof,
            Err(e) => return error(e.context("reading target stream completion")),
        };
    if matches!(
        proof.phase,
        MoveAuthorityPhase::Committing | MoveAuthorityPhase::Committed
    ) {
        return Response::MoveSource {
            instance_id: instance_id.to_owned(),
            epoch,
            token: token.to_owned(),
            phase: MoveSourcePhase::Committed,
        };
    }
    if proof.phase != MoveAuthorityPhase::Reserved {
        return error(anyhow!(
            "target authority is {:?}, not Reserved during source completion",
            proof.phase
        ));
    }

    if !proof.disk_eof || !proof.ram_eof {
        let recovery = target
            .proxy(
                &moving.to_device,
                Request::MoveRecoverTarget {
                    instance_id: instance_id.to_owned(),
                    name: name.to_owned(),
                    epoch,
                    token: token.to_owned(),
                    from_lane: moving.lane,
                },
            )
            .await;
        proof = match recovery {
            Ok(Response::MoveAuthority {
                instance_id: winner_id,
                epoch: winner_epoch,
                token: winner_token,
                phase: MoveAuthorityPhase::Reserved,
                lane,
                disk_eof,
                ram_eof,
                ..
            }) if winner_id == instance_id && winner_epoch == epoch && winner_token == token => {
                TargetProof {
                    phase: MoveAuthorityPhase::Reserved,
                    lane,
                    disk_eof,
                    ram_eof,
                }
            }
            Ok(Response::Error { message }) => return error(anyhow!(message)),
            Ok(other) => return error(anyhow!("unexpected target recovery reply: {other:?}")),
            Err(e) => return error(e.context("rebuilding target stream endpoints")),
        };
        let mut reg = node.shard.lock().await;
        if let Err(e) = persist_source_lane(
            &mut reg,
            instance_id,
            name,
            epoch,
            token,
            proof.lane,
            &mut moving,
        ) {
            return error(e.context("persisting the replacement target stream lane"));
        }
        drop(reg);
    }

    let source_device = target.self_name().await;
    if !proof.disk_eof {
        let _ = hv.migration_disk_abort(handle);
        if let Err(e) = target
            .live_disk_mirror(
                &source_device,
                &moving.to_device,
                instance_id,
                name,
                epoch,
                token,
                proof.lane,
                node,
            )
            .await
            .and_then(|_| hv.migration_disk_ready(handle))
        {
            return error(e.context("restarting the committed dirty-disk lane"));
        }
        if let Err(e) = hv.migration_disk_commit(handle) {
            return error(e.context("cutting the recovered dirty-disk mirror"));
        }
        if let Err(e) = crate::mesh::finish_live_disk_pump(name, epoch).await {
            return error(e.context("draining the recovered dirty-disk lane"));
        }
    }
    if !proof.ram_eof {
        if let Err(e) = hv.migration_source_reset(handle) {
            return error(e.context("resetting the stale committed source lane"));
        }
        if let Err(e) = target
            .live_migrate(
                &source_device,
                &moving.to_device,
                name,
                instance_id,
                epoch,
                token,
                proof.lane,
                node,
            )
            .await
        {
            return error(e.context("restarting committed RAM/device migration"));
        }
        if let Err(e) = hv.migration_commit(handle) {
            return error(e.context("releasing recovered RAM/device switchover"));
        }
        if let Err(e) = crate::mesh::finish_live_pump(name, epoch).await {
            return error(e.context("draining the recovered RAM/device lane"));
        }
    }

    proof = match target_proof(&target, &moving.to_device, instance_id, name, epoch, token).await {
        Ok(proof) => proof,
        Err(e) => return error(e.context("confirming recovered stream completion")),
    };
    if proof.phase != MoveAuthorityPhase::Reserved || !proof.disk_eof || !proof.ram_eof {
        return error(anyhow!(
            "target lane {} is {:?} with disk_eof={} ram_eof={}; source remains committed and fenced",
            proof.lane,
            proof.phase,
            proof.disk_eof,
            proof.ram_eof
        ));
    }
    Response::MoveSource {
        instance_id: instance_id.to_owned(),
        epoch,
        token: token.to_owned(),
        phase: MoveSourcePhase::Committed,
    }
}

fn persist_source_decision(reg: &mut Shard, name: &str, moving: &mut Moving) -> Result<()> {
    moving.phase = MoveSourcePhase::Committed;
    reg.set_moving(name, Some(moving.clone()))?;
    match reg.save() {
        Ok(()) => Ok(()),
        Err(save_error) => {
            if let Err(reload_error) = reload_source_moving(reg, name, moving) {
                return Err(save_error.context(format!(
                    "the source decision save also could not be reconciled from disk: {reload_error:#}"
                )));
            }
            Err(save_error)
        }
    }
}

fn reload_source_moving(reg: &mut Shard, name: &str, moving: &mut Moving) -> Result<()> {
    reg.reload()?;
    *moving = reg
        .get(name)?
        .moving
        .clone()
        .context("durable source row has no move after a failed save")?;
    Ok(())
}

fn persist_source_lane(
    reg: &mut Shard,
    instance_id: &str,
    name: &str,
    epoch: u64,
    token: &str,
    lane: u64,
    moving: &mut Moving,
) -> Result<()> {
    let current = reg.get(name)?;
    if current.id != instance_id {
        bail!(
            "source lane belongs to id {}, not {instance_id}",
            current.id
        );
    }
    let durable = current
        .moving
        .as_ref()
        .context("source move vanished while persisting its stream lane")?;
    if durable.epoch != epoch
        || durable.token != token
        || !durable.live
        || durable.phase != MoveSourcePhase::Committed
    {
        bail!("source stream lane does not match a committed id/epoch/token");
    }
    if durable.lane > lane {
        bail!(
            "target recovery replied with stale lane {lane}; source already records {}",
            durable.lane
        );
    }
    if durable.lane == lane {
        *moving = durable.clone();
        return Ok(());
    }
    let mut updated = durable.clone();
    updated.lane = lane;
    reg.set_moving(name, Some(updated.clone()))?;
    match reg.save() {
        Ok(()) => {
            *moving = updated;
            Ok(())
        }
        Err(save_error) => {
            if let Err(reload_error) = reload_source_moving(reg, name, moving) {
                return Err(save_error.context(format!(
                    "the source lane save also could not be reconciled from disk: {reload_error:#}"
                )));
            }
            Err(save_error)
        }
    }
}

fn validate_live_publish_state(
    txn: &AuthorityTxn,
    source_phase: MoveSourcePhase,
    target_complete: bool,
) -> Result<()> {
    if txn.phase != MoveAuthorityPhase::Reserved {
        bail!("live target is {:?}, not reserved to commit", txn.phase);
    }
    if source_phase != MoveSourcePhase::Committed {
        bail!("source decision is {source_phase:?}, not durably committed");
    }
    if !txn.lane_ready {
        bail!("live target replacement lane is not ready");
    }
    if !txn.disk_eof || !txn.ram_eof {
        bail!("live target has not durably observed both disk and RAM stream EOF");
    }
    if !target_complete {
        bail!("incoming backend has not completed migration");
    }
    Ok(())
}

pub async fn commit_source_checked(
    reg: &mut Shard,
    instance_id: &str,
    name: &str,
    epoch: u64,
    token: &str,
) -> Response {
    let inst = match reg.get(name).cloned() {
        Ok(inst) => inst,
        // A replay after the row was durably removed is already complete.
        Err(_) => {
            match load_source_completion(instance_id, name, epoch, token) {
                Ok(Some(completion)) => return replay_source_completion(&completion),
                Ok(None) => {}
                Err(e) => return error(e),
            }
            return match moved_note_full(name) {
                Some(note)
                    if note.epoch == epoch
                        && note.token == token
                        && (note.instance_id == instance_id
                            || (instance_id.is_empty() && token.is_empty())) =>
                {
                    Response::Ok
                }
                _ => error(anyhow!(
                    "no matching source row or moved note for commit replay"
                )),
            };
        }
    };
    if !instance_id.is_empty() && inst.id != instance_id {
        return error(anyhow!(
            "source name belongs to id {}, not {instance_id}",
            inst.id
        ));
    }
    let Some(moving) = inst.moving.as_ref().filter(|moving| moving.epoch == epoch) else {
        return error(anyhow!(
            "instance {name:?} is not fenced for move epoch {epoch}"
        ));
    };
    if moving.token != token || (moving.live && moving.phase != MoveSourcePhase::Committed) {
        return error(anyhow!(
            "source has not durably committed this id/epoch/token"
        ));
    }
    if moving.live {
        let mesh = match mesh() {
            Ok(mesh) => mesh,
            Err(e) => return error(e),
        };
        match target_proof(&mesh, &moving.to_device, &inst.id, name, epoch, token).await {
            Ok(TargetProof {
                phase: MoveAuthorityPhase::Committed,
                ..
            }) => {}
            Ok(proof) => {
                return error(anyhow!(
                    "target authority is {:?}, not durably committed; source remains fenced",
                    proof.phase
                ))
            }
            Err(e) => {
                return error(
                    e.context("target commit proof is unavailable; source remains fenced"),
                )
            }
        }
    }
    commit_source_after_proof(reg, instance_id, name, epoch, token)
}

/// The target has durably committed. Drop the row, drop the disk, leave a
/// note. Idempotent across a dead source process and a replayed request.
fn commit_source_after_proof(
    reg: &mut Shard,
    instance_id: &str,
    name: &str,
    epoch: u64,
    token: &str,
) -> Response {
    let inst = match reg.get(name).cloned() {
        Ok(inst) => inst,
        Err(_) => {
            match load_source_completion(instance_id, name, epoch, token) {
                Ok(Some(completion)) => return replay_source_completion(&completion),
                Ok(None) => {}
                Err(e) => return error(e),
            }
            return match moved_note_full(name) {
                Some(note)
                    if note.epoch == epoch
                        && note.token == token
                        && (note.instance_id == instance_id
                            || (instance_id.is_empty() && token.is_empty())) =>
                {
                    Response::Ok
                }
                _ => error(anyhow!("no matching moved note for source commit replay")),
            };
        }
    };
    if !instance_id.is_empty() && inst.id != instance_id {
        return error(anyhow!(
            "source name belongs to id {}, not {instance_id}",
            inst.id
        ));
    }
    let Some(moving) = inst.moving.clone() else {
        return error(anyhow!(
            "instance {name:?} is not being moved from this device — refusing to \
             delete a copy nothing has taken over from"
        ));
    };
    if moving.epoch != epoch
        || moving.token != token
        || (moving.live && moving.phase != MoveSourcePhase::Committed)
    {
        return error(anyhow!(
            "instance {name:?} is being moved at epoch {}, not {epoch} — refusing to \
             commit a move this device is not the source of",
            moving.epoch
        ));
    }

    if let Some(handle) = &inst.handle.filter(backend::alive) {
        if let Err(e) = backend::for_handle(&handle.backend).and_then(|hv| hv.kill(handle)) {
            return error(e.context("the migrated source guest could not be fenced off"));
        }
    }
    if let Err(e) = reg.set_stopped(name) {
        return error(e);
    }
    let completion = SourceCompletion {
        version: 1,
        instance_id: inst.id.clone(),
        name: name.to_owned(),
        to_device: moving.to_device.clone(),
        epoch,
        token: token.to_owned(),
    };
    match load_source_completion(instance_id, name, epoch, token) {
        Ok(Some(existing)) if existing == completion => {}
        Ok(Some(_)) => {
            return error(anyhow!(
                "source completion winner differs from the current durable move"
            ))
        }
        Ok(None) => {
            if let Err(e) = save_source_completion(&completion) {
                return error(e);
            }
        }
        Err(e) => return error(e),
    }
    if let Err(e) = reg.remove(name) {
        return error(e);
    }
    if let Err(save_error) = reg.save() {
        if let Err(reload_error) = reg.reload() {
            return error(save_error.context(format!(
                "the source row save also could not be reconciled from disk: {reload_error:#}"
            )));
        }
        return error(save_error);
    }
    replay_source_completion(&completion)
}

/// The move did not happen. Take the fence off; this row never stopped being
/// the authoritative one.
pub async fn abort_source_checked(
    reg: &mut Shard,
    instance_id: &str,
    name: &str,
    epoch: u64,
    token: &str,
) -> Response {
    if let Ok(inst) = reg.get(name).cloned() {
        if !instance_id.is_empty() && inst.id != instance_id {
            return error(anyhow!(
                "source name belongs to id {}, not {instance_id}",
                inst.id
            ));
        }
        if let Some(moving) = inst
            .moving
            .as_ref()
            .filter(|m| m.epoch == epoch && m.token == token && m.live)
        {
            if moving.phase == MoveSourcePhase::Committed {
                return error(anyhow!(
                    "source no-return marker is committed; abort is permanently refused"
                ));
            }
            let mesh = match mesh() {
                Ok(mesh) => mesh,
                Err(e) => return error(e),
            };
            match target_proof(&mesh, &moving.to_device, &inst.id, name, epoch, token).await {
                Ok(TargetProof {
                    phase: MoveAuthorityPhase::Aborted,
                    ..
                }) => {}
                Ok(proof) => {
                    return error(anyhow!(
                        "target authority is {:?}, not durably aborted; source remains fenced",
                        proof.phase
                    ))
                }
                Err(e) => {
                    return error(
                        e.context("target abort proof is unavailable; source remains fenced"),
                    )
                }
            }
        }
    }
    abort_source_after_proof(reg, instance_id, name, epoch, token).await
}

async fn abort_source_after_proof(
    reg: &mut Shard,
    instance_id: &str,
    name: &str,
    epoch: u64,
    token: &str,
) -> Response {
    match reg.get(name).cloned() {
        // Nothing to unfence is not a failure: an abort is sent on paths that
        // may never have got as far as fencing anything.
        Err(_) => Response::Ok,
        Ok(inst) => {
            if inst.moving.is_none() {
                return if inst.move_epoch >= epoch {
                    Response::Ok
                } else {
                    error(anyhow!(
                        "instance {name:?} has no move at epoch {epoch} to abort"
                    ))
                };
            }
            if (!instance_id.is_empty() && inst.id != instance_id)
                || inst
                    .moving
                    .as_ref()
                    .is_some_and(|m| m.epoch != epoch || m.token != token)
            {
                return error(anyhow!(
                    "instance {name:?} is being moved at a different epoch — leaving \
                     that move's fence alone"
                ));
            }
            if inst
                .moving
                .as_ref()
                .is_some_and(|m| m.phase == MoveSourcePhase::Committed)
            {
                return error(anyhow!("source no-return marker forbids abort"));
            }
            if let Some(handle) = &inst.handle {
                let stopped = backend::for_handle(&handle.backend).and_then(|hv| {
                    hv.migration_disk_abort(handle)?;
                    hv.migration_abort(handle)
                });
                if let Err(e) = stopped {
                    return error(
                        e.context("the source backend could not resume after migration abort"),
                    );
                }
                let _ = crate::mesh::abort_live_disk_pump(name, epoch).await;
                let _ = crate::mesh::abort_live_pump(name, epoch).await;
            }
            match persist_source_abort(reg, name, epoch) {
                Ok(()) => Response::Ok,
                Err(e) => error(e),
            }
        }
    }
}

fn persist_source_abort(reg: &mut Shard, name: &str, epoch: u64) -> Result<()> {
    if reg
        .get(name)
        .is_ok_and(|instance| instance.moving.is_none() && instance.move_epoch >= epoch)
    {
        return Ok(());
    }
    reg.finish_aborted_move(name, epoch)?;
    if let Err(save_error) = reg.save() {
        if let Err(reload_error) = reg.reload() {
            return Err(save_error.context(format!(
                "the source abort save also could not be reconciled from disk: {reload_error:#}"
            )));
        }
        return Err(save_error);
    }
    Ok(())
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
fn movable(inst: &Instance, live: bool) -> Result<()> {
    unconflicted(inst)?;
    if inst.status == Status::Running && !live {
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
            if let Some(refusal) = live_refusal(inst, hv.caps().live_migration, &ready, device) {
                return Some(refusal);
            }
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

fn major(version: &str) -> &str {
    version.split('.').next().unwrap_or(version)
}

fn live_refusal(
    inst: &Instance,
    live_capability: bool,
    ready: &Ready,
    device: &str,
) -> Option<String> {
    if inst.status != Status::Running {
        return None;
    }
    let machine = &inst.machine;
    if !live_capability {
        return Some(format!(
            "device {device}'s {} backend cannot receive a running guest — use --down \
             for the offline move",
            machine.backend
        ));
    }
    if major(&ready.version) != major(&machine.hv_version)
        || ready.machine_type != machine.machine_type
        || ready.cpu != machine.cpu
    {
        return Some(format!(
            "device {device}'s live-migration machine is incompatible: source is \
             {machine}, target is {} {} ({}, cpu {}). Use --down for the portable \
             offline move",
            machine.backend, ready.version, ready.machine_type, ready.cpu
        ));
    }
    if !inst.volumes.is_empty() {
        return Some(format!(
            "instance {:?} has attached volumes whose live lease handoff is not supported \
             — use --down",
            inst.name
        ));
    }
    None
}

fn begin_target(
    manifest: &MoveManifest,
    epoch: u64,
    device: &str,
    source_device: &str,
    source_device_id: &str,
    token: &str,
    coordinator_id: &str,
) -> Response {
    if manifest.instance.cpu_device != source_device {
        return error(anyhow!(
            "instance record names source {:?}, not {source_device:?}",
            manifest.instance.cpu_device
        ));
    }
    if let Some(refusal) = probe_refusal(manifest, device, false, &mut Vec::new()) {
        return error(anyhow!(refusal));
    }
    let txn = AuthorityTxn {
        version: 1,
        instance_id: manifest.instance.id.clone(),
        name: manifest.instance.name.clone(),
        epoch,
        phase: MoveAuthorityPhase::Intent,
        manifest: manifest.clone(),
        live: true,
        source_device: source_device.to_owned(),
        source_device_id: source_device_id.to_owned(),
        token: token.to_owned(),
        coordinator_id: coordinator_id.to_owned(),
        handle: None,
        disk_export: None,
        disk_eof: false,
        ram_eof: false,
        lane: initial_lane(),
        lane_ready: true,
    };
    match load_authority(&txn.instance_id, epoch) {
        Ok(Some(existing)) => {
            match validate_target_replay(
                &existing,
                manifest,
                epoch,
                source_device,
                source_device_id,
                token,
                Some(coordinator_id),
            ) {
                Ok(()) => authority_phase_response(&existing),
                Err(e) => error(e),
            }
        }
        Ok(None) => match load_authority_for_name_epoch(&txn.name, epoch) {
            Ok(Some(existing)) => error(anyhow!(
                "target name/epoch is already claimed by instance id {:?} and token {:?}",
                existing.instance_id,
                existing.token
            )),
            Ok(None) => match save_authority(&txn) {
                Ok(()) => authority_phase_response(&txn),
                Err(e) => error(e),
            },
            Err(e) => error(e),
        },
        Err(e) => error(e),
    }
}

fn prepare_disk_target(instance_id: &str, name: &str, epoch: u64, token: &str) -> Response {
    let mut txn = match load_authority(instance_id, epoch) {
        Ok(Some(txn)) if txn.name == name && txn.token == token && txn.live => txn,
        Ok(Some(_)) => return error(anyhow!("target disk request does not match id/epoch/token")),
        Ok(None) => return error(anyhow!("target intent is absent")),
        Err(e) => return error(e),
    };
    if txn.phase == MoveAuthorityPhase::DiskPrepared {
        return if txn
            .disk_export
            .as_ref()
            .is_some_and(|export| export.proc.alive())
        {
            disk_ready_response(&txn)
        } else {
            error(anyhow!("recorded target disk export is not alive"))
        };
    }
    if matches!(
        txn.phase,
        MoveAuthorityPhase::Prepared
            | MoveAuthorityPhase::Reserved
            | MoveAuthorityPhase::Committing
            | MoveAuthorityPhase::Committed
            | MoveAuthorityPhase::Aborted
    ) {
        return authority_phase_response(&txn);
    }
    if txn.phase != MoveAuthorityPhase::Intent {
        return error(anyhow!(
            "target disk cannot be prepared in phase {:?}",
            txn.phase
        ));
    }
    let staging = match staging_for(&txn) {
        Ok(staging) => staging,
        Err(e) => return error(e.context("refusing to export unverified legacy staging")),
    };
    let export = (|| -> Result<MigrationDiskExport> {
        let hv = backend::for_instance(&txn.manifest.instance)?;
        let req = backend::migration_req(&txn.manifest.instance, staging)?;
        hv.migration_disk_export(&req)
    })();
    let export = match export {
        Ok(export) => export,
        Err(e) => return error(e.context("starting the staged root-disk NBD export")),
    };
    txn.disk_export = Some(export.clone());
    txn.phase = MoveAuthorityPhase::DiskPrepared;
    if let Err(e) = save_authority(&txn) {
        if let Ok(hv) = backend::for_instance(&txn.manifest.instance) {
            let _ = hv.migration_disk_export_stop(&export);
        }
        return error(e.context("recording target disk export before accepting a mirror"));
    }
    disk_ready_response(&txn)
}

fn disk_ready_target(instance_id: &str, name: &str, epoch: u64, token: &str) -> Response {
    let txn = match load_authority(instance_id, epoch) {
        Ok(Some(txn)) if txn.name == name && txn.token == token && txn.live => txn,
        Ok(Some(_)) => {
            return error(anyhow!(
                "target disk-ready request does not match id/epoch/token"
            ))
        }
        Ok(None) => return error(anyhow!("target intent is absent")),
        Err(e) => return error(e),
    };
    if txn.phase != MoveAuthorityPhase::DiskPrepared {
        return if matches!(
            txn.phase,
            MoveAuthorityPhase::Prepared
                | MoveAuthorityPhase::Reserved
                | MoveAuthorityPhase::Committing
                | MoveAuthorityPhase::Committed
                | MoveAuthorityPhase::Aborted
        ) {
            authority_phase_response(&txn)
        } else {
            error(anyhow!("target disk is not exported for mirroring"))
        };
    }
    let staging = match staging_for(&txn) {
        Ok(staging) => staging,
        Err(e) => return error(e.context("refusing to read unverified legacy staging")),
    };
    let mut receipt = match Receipt::load(&staging) {
        Ok(receipt) => receipt,
        Err(e) => return error(e),
    };
    for file in txn
        .manifest
        .files
        .iter()
        .filter(|file| matches!(file.path.as_str(), "disk.raw" | "disk.qcow2"))
    {
        let path = staging.join(&file.path);
        if !std::fs::metadata(&path).is_ok_and(|meta| meta.len() == file.len) {
            return error(anyhow!("mirrored root disk has the wrong length"));
        }
        if !receipt.files.contains_key(&file.path) {
            receipt.files.insert(file.path.clone(), file.allocated);
            receipt.bytes = receipt.bytes.saturating_add(file.allocated);
        }
    }
    match receipt.save(&staging) {
        Ok(()) => authority_phase_response(&txn),
        Err(e) => error(e.context("recording root-disk mirror readiness")),
    }
}

/// Start the target backend in incoming mode against the unlisted staged
/// directory. The returned handle stays process-local until the epoch commit
/// publishes both the directory and registry row.
fn live_prepare_target(
    manifest: &MoveManifest,
    epoch: u64,
    device: &str,
    source_device: &str,
    source_device_id: &str,
    token: &str,
) -> Response {
    if manifest.instance.status != Status::Running {
        return error(anyhow!(
            "live target preparation requires a running source guest"
        ));
    }
    if let Some(refusal) = probe_refusal(manifest, device, false, &mut Vec::new()) {
        return error(anyhow!(refusal));
    }
    if manifest.instance.cpu_device != source_device {
        return error(anyhow!(
            "live migration claims source {source_device:?}, but the instance record names {:?}",
            manifest.instance.cpu_device
        ));
    }
    let staging = staging_dir(&manifest.instance.name, &manifest.instance.id, epoch, token);
    if let Err(e) = verify(&staging, manifest, epoch, token) {
        return error(e.context("the live pre-copy is incomplete"));
    }
    let receipt = match Receipt::load(&staging) {
        Ok(receipt) => receipt,
        Err(e) => return error(e),
    };
    if receipt.from_device != source_device {
        return error(anyhow!(
            "the staged bytes came from {:?}, not authenticated source {source_device:?}",
            receipt.from_device
        ));
    }
    let mut txn = AuthorityTxn {
        version: 1,
        instance_id: manifest.instance.id.clone(),
        name: manifest.instance.name.clone(),
        epoch,
        phase: MoveAuthorityPhase::Intent,
        manifest: manifest.clone(),
        live: true,
        source_device: source_device.to_owned(),
        source_device_id: source_device_id.to_owned(),
        token: token.to_owned(),
        coordinator_id: String::new(),
        handle: None,
        disk_export: None,
        disk_eof: false,
        ram_eof: false,
        lane: initial_lane(),
        lane_ready: true,
    };
    match load_authority(&txn.instance_id, epoch) {
        Ok(Some(existing)) => {
            if let Err(e) = validate_target_replay(
                &existing,
                manifest,
                epoch,
                source_device,
                source_device_id,
                token,
                None,
            ) {
                return error(e);
            }
            if existing.phase == MoveAuthorityPhase::Prepared {
                return live_ready_response(&existing);
            }
            if matches!(
                existing.phase,
                MoveAuthorityPhase::Reserved
                    | MoveAuthorityPhase::Committing
                    | MoveAuthorityPhase::Committed
                    | MoveAuthorityPhase::Aborted
            ) {
                return authority_phase_response(&existing);
            }
            if existing.phase != MoveAuthorityPhase::DiskPrepared {
                return error(anyhow!(
                    "live target transaction is already {:?}",
                    existing.phase
                ));
            }
            txn = existing;
        }
        Ok(None) => return error(anyhow!("target intent must precede live preparation")),
        Err(e) => return error(e),
    }
    let socket = match live_socket(&manifest.instance.name, &manifest.instance.id, epoch, token) {
        Ok(socket) => socket,
        Err(e) => return error(e.context("refusing to recover an unverified legacy socket")),
    };
    let _ = std::fs::remove_file(&socket);
    let started = (|| -> Result<Handle> {
        let hv = backend::for_instance(&manifest.instance)?;
        let req = backend::migration_req(&manifest.instance, staging.clone())?;
        hv.migrate_in(
            &req,
            MigrationSource {
                url: format!("unix:{}", socket.display()),
            },
        )
    })();
    match started {
        Ok(handle) => {
            if let Err(e) = durable::commit_json(&staging.join(LIVE_HANDLE), &handle) {
                let _ = backend::for_handle(&handle.backend).and_then(|hv| hv.kill(&handle));
                return error(
                    e.context("recording the incoming guest so restart cleanup can fence it"),
                );
            }
            txn.handle = Some(handle.clone());
            txn.phase = MoveAuthorityPhase::Prepared;
            if let Err(e) = save_authority(&txn) {
                let _ = backend::for_handle(&handle.backend).and_then(|hv| hv.kill(&handle));
                return error(
                    e.context("recording the prepared target before accepting migration bytes"),
                );
            }
            live_sessions().insert((manifest.instance.name.clone(), epoch), handle);
            live_ready_response(&txn)
        }
        Err(e) => error(e.context("starting the incoming live-migration guest")),
    }
}

/// Durably choose the forward/commit leg on the target.
///
/// This function runs under both the target shard mutex and
/// [`with_authority_txn`].  Target abort uses the same serialization point,
/// so `Prepared -> Reserved` and `Prepared -> Aborted` are a real CAS with
/// one durable winner.  The source is forbidden to write its own no-return
/// marker until this exact id/epoch/token replays `Reserved`.
fn reserve_target(reg: &Shard, instance_id: &str, name: &str, epoch: u64, token: &str) -> Response {
    let mut txn = match load_authority(instance_id, epoch) {
        Ok(Some(txn))
            if txn.live && txn.name == name && txn.token == token && txn.epoch == epoch =>
        {
            txn
        }
        Ok(Some(txn)) => {
            return error(anyhow!(
                "target reservation does not match durable id/epoch/token winner {:?}",
                txn.name
            ))
        }
        Ok(None) => return error(anyhow!("no target authority transaction exists")),
        Err(e) => return error(e),
    };
    match txn.phase {
        MoveAuthorityPhase::Prepared => {
            if !txn.lane_ready {
                return error(anyhow!("target stream lane is not ready for reservation"));
            }
            if published_for(&txn)
                || reg.get(name).ok().is_some_and(|instance| {
                    instance.id == instance_id && instance.move_epoch == epoch
                })
            {
                return error(anyhow!(
                    "prepared target has publication evidence before reservation"
                ));
            }
            txn.phase = MoveAuthorityPhase::Reserved;
            match save_authority(&txn) {
                Ok(()) => authority_response(&txn, reg),
                Err(e) => error(e.context("recording the target commit reservation")),
            }
        }
        MoveAuthorityPhase::Reserved
        | MoveAuthorityPhase::Committing
        | MoveAuthorityPhase::Committed
        | MoveAuthorityPhase::Aborted => authority_response(&txn, reg),
        MoveAuthorityPhase::Intent | MoveAuthorityPhase::DiskPrepared => error(anyhow!(
            "target is {:?}, not prepared to reserve commit",
            txn.phase
        )),
    }
}

fn record_completed_incoming(txn: &mut AuthorityTxn) -> Result<bool> {
    if txn.ram_eof {
        return Ok(true);
    }
    let Some(handle) = txn.handle.as_ref() else {
        return Ok(false);
    };
    let hv = backend::for_handle(&handle.backend)?;
    if hv.migration_target_complete(handle).is_err() {
        return Ok(false);
    }
    txn.ram_eof = true;
    save_authority(txn).context("recording backend-proved RAM migration completion")?;
    Ok(true)
}

/// Rebuild a lost mesh lane after the source no-return marker.
///
/// `from_lane` is a generation CAS. The first request durably advances the
/// lane with `lane_ready = false`; a reply-loss replay finishes that same
/// generation instead of allocating another. Old bulk opens and EOF writers
/// carry the prior generation and are refused by the target WAL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RecoveryLane {
    Replay,
    Rebuild,
}

fn select_recovery_lane(txn: &mut AuthorityTxn, from_lane: u64) -> Result<RecoveryLane> {
    if txn.lane < from_lane {
        bail!(
            "recovery lane {from_lane} is newer than durable lane {}",
            txn.lane
        );
    }
    if txn.lane == from_lane && txn.lane_ready {
        txn.lane = txn
            .lane
            .checked_add(1)
            .context("live stream lane counter is exhausted")?;
        txn.lane_ready = false;
        save_authority(txn).context("allocating the replacement live stream lane")?;
        return Ok(RecoveryLane::Rebuild);
    }
    if txn.lane_ready {
        return Ok(RecoveryLane::Replay);
    }
    Ok(RecoveryLane::Rebuild)
}

fn recover_target(
    reg: &Shard,
    instance_id: &str,
    name: &str,
    epoch: u64,
    token: &str,
    from_lane: u64,
) -> Response {
    let mut txn = match load_authority(instance_id, epoch) {
        Ok(Some(txn))
            if txn.live && txn.name == name && txn.token == token && txn.epoch == epoch =>
        {
            txn
        }
        Ok(Some(_)) => return error(anyhow!("live recovery does not match id/epoch/token")),
        Ok(None) => return error(anyhow!("no target authority transaction exists")),
        Err(e) => return error(e),
    };
    if txn.phase != MoveAuthorityPhase::Reserved {
        return if matches!(
            txn.phase,
            MoveAuthorityPhase::Committing
                | MoveAuthorityPhase::Committed
                | MoveAuthorityPhase::Aborted
        ) {
            authority_response(&txn, reg)
        } else {
            error(anyhow!(
                "target is {:?}, not reserved for forward recovery",
                txn.phase
            ))
        };
    }

    let source = match mesh() {
        Ok(mesh) => mesh,
        Err(e) => return error(e),
    };
    let proof = tokio::runtime::Handle::current().block_on(source.proxy(
        &txn.source_device,
        Request::MoveSourceStatus {
            instance_id: txn.instance_id.clone(),
            name: txn.name.clone(),
            epoch: txn.epoch,
            token: txn.token.clone(),
        },
    ));
    match proof
        .and_then(|response| exact_source_phase(response, &txn.instance_id, txn.epoch, &txn.token))
    {
        Ok(MoveSourcePhase::Committed) => {}
        Ok(phase) => {
            return error(anyhow!(
                "source decision is {phase:?}; target recovery requires Committed"
            ))
        }
        Err(e) => return error(e.context("source recovery proof is unavailable")),
    }

    if let Err(e) = record_completed_incoming(&mut txn) {
        return error(e);
    }
    if txn.disk_eof && txn.ram_eof {
        return authority_response(&txn, reg);
    }
    match select_recovery_lane(&mut txn, from_lane) {
        Ok(RecoveryLane::Replay) => return authority_response(&txn, reg),
        Ok(RecoveryLane::Rebuild) => {}
        Err(e) => return error(e),
    }

    let staging = match staging_for(&txn) {
        Ok(staging) => staging,
        Err(e) => return error(e.context("refusing to recover unverified legacy staging")),
    };
    let hv = match backend::for_instance(&txn.manifest.instance) {
        Ok(hv) => hv,
        Err(e) => return error(e),
    };
    let req = match backend::migration_req(&txn.manifest.instance, staging.clone()) {
        Ok(req) => req,
        Err(e) => return error(e),
    };

    if !txn.ram_eof {
        if let Err(e) = hv.migration_target_reset(&req) {
            return error(e.context("fencing the stale incoming migration lane"));
        }
        live_sessions().remove(&(name.to_owned(), epoch));
        txn.handle = None;
    }
    if !txn.disk_eof
        && !txn
            .disk_export
            .as_ref()
            .is_some_and(|export| export.proc.alive())
    {
        match hv.migration_disk_export(&req) {
            Ok(export) => txn.disk_export = Some(export),
            Err(e) => return error(e.context("restarting the target disk export")),
        }
    }
    if !txn.ram_eof {
        let socket = match live_socket(name, instance_id, epoch, token) {
            Ok(socket) => socket,
            Err(e) => return error(e.context("refusing to recover an unverified legacy socket")),
        };
        let _ = std::fs::remove_file(&socket);
        let handle = match hv.migrate_in(
            &req,
            MigrationSource {
                url: format!("unix:{}", socket.display()),
            },
        ) {
            Ok(handle) => handle,
            Err(e) => return error(e.context("restarting the incoming migration backend")),
        };
        if let Err(e) = durable::commit_json(&staging.join(LIVE_HANDLE), &handle) {
            let _ = backend::for_handle(&handle.backend).and_then(|backend| backend.kill(&handle));
            return error(e.context("recording the recovered incoming backend"));
        }
        txn.handle = Some(handle.clone());
        live_sessions().insert((name.to_owned(), epoch), handle);
    }
    txn.lane_ready = true;
    match save_authority(&txn) {
        Ok(()) => authority_response(&txn, reg),
        Err(e) => error(e.context("publishing the replacement live stream lane")),
    }
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
    token: &str,
    device: &str,
) -> Response {
    let name = manifest.instance.name.clone();
    let staging = staging_dir(&name, &manifest.instance.id, epoch, token);
    let mut txn = match load_authority(&manifest.instance.id, epoch) {
        Ok(Some(txn)) => txn,
        Ok(None) => {
            match load_authority_for_name_epoch(&name, epoch) {
                Ok(Some(existing)) => {
                    return error(anyhow!(
                        "target name/epoch is already claimed by instance id {:?} and token {:?}",
                        existing.instance_id,
                        existing.token
                    ))
                }
                Ok(None) => {}
                Err(e) => return error(e),
            }
            if let Err(e) = verify(&staging, manifest, epoch, token) {
                return error(e);
            }
            let receipt = match Receipt::load(&staging) {
                Ok(receipt) => receipt,
                Err(e) => return error(e),
            };
            let txn = AuthorityTxn {
                version: 1,
                instance_id: manifest.instance.id.clone(),
                name: name.clone(),
                epoch,
                phase: MoveAuthorityPhase::Intent,
                manifest: manifest.clone(),
                live: false,
                source_device: receipt.from_device,
                source_device_id: String::new(),
                token: token.to_owned(),
                coordinator_id: String::new(),
                handle: None,
                disk_export: None,
                disk_eof: false,
                ram_eof: false,
                lane: initial_lane(),
                lane_ready: true,
            };
            if let Err(e) = save_authority(&txn) {
                return error(e.context("recording target intent before adoption"));
            }
            txn
        }
        Err(e) => return error(e),
    };
    if txn.name != name || txn.manifest.instance.id != manifest.instance.id {
        return error(anyhow!(
            "authority transaction id/epoch belongs to {:?}, not {name:?}",
            txn.name
        ));
    }
    if txn.token != token {
        return error(anyhow!(
            "target commit token does not match the durable transaction"
        ));
    }
    match txn.phase {
        MoveAuthorityPhase::Committed => return committed_response(reg, &txn),
        MoveAuthorityPhase::Aborted => {
            return error(anyhow!("target authority transaction was durably aborted"))
        }
        MoveAuthorityPhase::Intent
        | MoveAuthorityPhase::DiskPrepared
        | MoveAuthorityPhase::Prepared
        | MoveAuthorityPhase::Reserved => {
            if txn.live {
                if txn.phase != MoveAuthorityPhase::Reserved {
                    return error(anyhow!(
                        "live target is {:?}; commit has not won the durable reservation",
                        txn.phase
                    ));
                }
                let Some(handle) = txn.handle.as_ref() else {
                    return error(anyhow!(
                        "live target has no recorded incoming backend handle"
                    ));
                };
                let hv = match backend::for_handle(&handle.backend) {
                    Ok(hv) => hv,
                    Err(e) => return error(e),
                };
                let target_complete = match hv.migration_target_complete(handle) {
                    Ok(()) => true,
                    Err(e) => {
                        return error(e.context("incoming backend has not completed migration"))
                    }
                };
                let source = match mesh() {
                    Ok(mesh) => mesh,
                    Err(e) => return error(e),
                };
                let proof = tokio::runtime::Handle::current().block_on(source.proxy(
                    &txn.source_device,
                    Request::MoveSourceStatus {
                        instance_id: txn.instance_id.clone(),
                        name: txn.name.clone(),
                        epoch: txn.epoch,
                        token: txn.token.clone(),
                    },
                ));
                let source_phase = match proof.and_then(|response| {
                    exact_source_phase(response, &txn.instance_id, txn.epoch, &txn.token)
                }) {
                    Ok(phase) => phase,
                    Err(e) => return error(e.context("source no-return proof is unavailable")),
                };
                if let Err(e) = validate_live_publish_state(&txn, source_phase, target_complete) {
                    return error(e);
                }
                if let Some(export) = txn.disk_export.as_ref() {
                    if let Err(e) = hv.migration_disk_export_stop(export) {
                        return error(e.context("stopping the completed target disk export"));
                    }
                }
            }
            // This durable one-way transition precedes *every* publish and
            // row mutation. From here, abort is forbidden and recovery
            // finishes adoption after any error or crash.
            txn.phase = MoveAuthorityPhase::Committing;
            if let Err(e) = save_authority(&txn) {
                return error(e.context("recording the point of no return before adoption"));
            }
        }
        MoveAuthorityPhase::Committing => {}
    }
    match finish_target_commit(reg, &mut txn, device) {
        Ok(instance) => Response::Instance {
            instance,
            guest_health: None,
        },
        Err(e) => error(e.context(
            "target commit is in progress and cannot be aborted; retry or query its authority",
        )),
    }
}

fn committed_response(reg: &Shard, txn: &AuthorityTxn) -> Response {
    match reg.get(&txn.name).ok().filter(|i| {
        i.id == txn.instance_id && i.move_epoch == txn.epoch
    }) {
        Some(instance) => Response::Instance {
            instance: instance.clone(),
            guest_health: None,
        },
        None => error(anyhow!(
            "transaction says committed but its target row is missing; startup reconciliation is required"
        )),
    }
}

fn qmp_path_after_publish(current: &Path, staging: &Path, name: &str) -> PathBuf {
    if current == staging.join("qmp.sock") {
        paths::qmp_socket_path(name)
    } else {
        // `qmp_socket_in` shortened this path into the runtime directory.
        // Publishing staging does not move that socket, so its handle must
        // keep naming the exact path the backend bound.
        current.to_path_buf()
    }
}

/// Complete the one-way half of target adoption. Every step is idempotent:
/// startup and an RPC replay use this same function after any crash boundary.
fn finish_target_commit(reg: &mut Shard, txn: &mut AuthorityTxn, device: &str) -> Result<Instance> {
    let name = txn.name.clone();
    let staging = staging_for(txn)?;
    let live = paths::instance_dir(&name);

    if !live.exists() {
        verify(&staging, &txn.manifest, txn.epoch, &txn.token)?;
        save_authority_marker(&staging, txn)?;
        if let Some(parent) = live.parent() {
            std::fs::create_dir_all(parent)?;
        }
        durable::publish_dir(&staging, &live)
            .with_context(|| format!("publishing {}", live.display()))?;
    } else if !published_for(txn) {
        bail!(
            "{} exists but is not the published tree for id {:?} epoch {}",
            live.display(),
            txn.instance_id,
            txn.epoch
        );
    }

    let existing = reg.get(&name).ok().cloned();
    let instance = if let Some(instance) = existing {
        if instance.id != txn.instance_id
            || instance.move_epoch != txn.epoch
            || instance.cpu_device != device
        {
            bail!(
                "target row for {name:?} does not match transaction id {:?} epoch {} on {device}",
                txn.instance_id,
                txn.epoch
            );
        }
        if txn.live
            && instance.status == Status::Running
            && !instance.handle.as_ref().is_some_and(backend::alive)
        {
            bail!("target row for {name:?} still says Running but its migrated backend is dead");
        }
        instance
    } else {
        let live_handle = txn
            .handle
            .clone()
            .or_else(|| live_sessions().get(&(name.clone(), txn.epoch)).cloned());
        if txn.live && !live_handle.as_ref().is_some_and(backend::alive) {
            bail!(
                "live target backend handle is absent or dead; refusing to publish a stopped row"
            );
        }
        let mut adopted = txn.manifest.instance.clone();
        adopted.cpu_device = device.to_owned();
        if !txn.live && adopted.status == Status::Running && live_handle.is_none() {
            adopted.status = Status::Stopped;
        }
        adopted.handle = live_handle.map(|mut handle| {
            if let ControlChannel::Qmp { path } = &mut handle.ctl {
                *path = qmp_path_after_publish(path, &staging, &name);
            }
            handle
        });
        adopted.moving = None;
        adopted.conflict = None;
        adopted.move_epoch = txn.epoch;
        adopted.stranded = txn.manifest.local_volumes.clone();
        reg.adopt(adopted)?
    };

    // A save that returns an error may nevertheless have reached rename;
    // never remove the row or kill the target here. The Committing WAL makes
    // a retry save and inspect exactly this state before it can mark itself
    // Committed.
    reg.save()?;

    txn.phase = MoveAuthorityPhase::Committed;
    save_authority(txn)?;
    live_sessions().remove(&(name.clone(), txn.epoch));
    let _ = std::fs::remove_file(Receipt::path(&live));
    let _ = std::fs::remove_file(live.join(LIVE_HANDLE));
    let _ = std::fs::remove_file(live_socket(&name, &txn.instance_id, txn.epoch, &txn.token)?);
    let _ = std::fs::remove_file(live.join(LIVE_SOCKET));
    let _ = std::fs::remove_file(live.join(LIVE_AUTHORITY));
    Ok(instance)
}

/// The completeness check the commit turns on.
fn verify(staging: &Path, manifest: &MoveManifest, epoch: u64, token: &str) -> Result<()> {
    if !staging.is_dir() {
        bail!(
            "nothing arrived for {:?} at epoch {epoch} — there is no staging \
             directory to adopt",
            manifest.instance.name
        );
    }
    let receipt = Receipt::load(staging)?;
    if receipt.instance_id != manifest.instance.id || receipt.token != token {
        bail!(
            "what is staged for {:?} belongs to another instance or move token",
            manifest.instance.name
        );
    }
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

fn target_status(
    reg: &mut Shard,
    instance_id: &str,
    name: &str,
    epoch: u64,
    token: &str,
    device: &str,
) -> Response {
    let mut txn = match load_authority(instance_id, epoch) {
        Ok(Some(txn)) if txn.name == name && txn.token == token => txn,
        Ok(Some(txn)) => {
            return error(anyhow!(
                "authority key belongs to another name or token ({:?})",
                txn.name,
            ))
        }
        Ok(None) => return error(anyhow!("no target authority transaction exists")),
        Err(e) => return error(e),
    };

    if txn.phase == MoveAuthorityPhase::Reserved {
        if let Err(e) = record_completed_incoming(&mut txn) {
            return error(e.context("reconciling completed incoming migration"));
        }
    }

    // A published tree or matching row is authority evidence even if the
    // last WAL save was lost. Bias permanently toward completing target
    // authority; never manufacture an abort proof around it.
    let matching_row = reg
        .get(name)
        .ok()
        .is_some_and(|i| i.id == instance_id && i.move_epoch == epoch && i.cpu_device == device);
    if matches!(
        txn.phase,
        MoveAuthorityPhase::Intent
            | MoveAuthorityPhase::DiskPrepared
            | MoveAuthorityPhase::Prepared
            | MoveAuthorityPhase::Reserved
    ) && (published_for(&txn) || matching_row)
    {
        return error(anyhow!(
            "precommit target has publication evidence without a no-return WAL; refusing to infer authority"
        ));
    }
    if matches!(
        txn.phase,
        MoveAuthorityPhase::Committing | MoveAuthorityPhase::Committed
    ) {
        if let Err(e) = finish_target_commit(reg, &mut txn, device) {
            return error(e.context("reconciling target authority"));
        }
    }
    if txn.phase == MoveAuthorityPhase::Aborted {
        if let Err(e) = finish_target_abort(&mut txn) {
            return error(e.context("finishing the durable target abort"));
        }
    }
    authority_response(&txn, reg)
}

/// Conditional abort. A successful response is the durable proof the source
/// needs before it may resume. Committing and Committed are never abortable.
pub fn abort_target(
    reg: &mut Shard,
    instance_id: &str,
    name: &str,
    epoch: u64,
    token: &str,
) -> Response {
    let mut txn = match load_authority(instance_id, epoch) {
        Ok(Some(txn)) if txn.name == name && txn.token == token => txn,
        Ok(Some(txn)) => {
            return error(anyhow!(
                "authority key belongs to another name or token ({:?})",
                txn.name,
            ))
        }
        Ok(None) => {
            // Offline moves and peers from before protocol 6 have no target
            // authority WAL before adoption. A legacy name/epoch directory is
            // nevertheless never ours merely because it has the same name:
            // prove its receipt before any socket or recursive cleanup.
            match load_authority_for_name_epoch(name, epoch) {
                Ok(Some(existing)) => {
                    return error(anyhow!(
                        "target name/epoch is claimed by instance id {:?} and token {:?}",
                        existing.instance_id,
                        existing.token
                    ))
                }
                Ok(None) => {}
                Err(e) => return error(e),
            }
            let staging = match recoverable_staging_dir(name, instance_id, epoch, token) {
                Ok(staging) => staging,
                Err(e) => return error(e.context("refusing to abort unverified legacy staging")),
            };
            if !staging.exists() {
                if let Err(e) = refuse_unmatched_staging_siblings(name, instance_id, epoch, token) {
                    return error(e);
                }
                return Response::Ok;
            }
            let _ = std::fs::remove_file(paths::migration_socket_in(&staging));
            if let Err(e) = std::fs::remove_dir_all(&staging) {
                if e.kind() != std::io::ErrorKind::NotFound {
                    return error(e.into());
                }
            }
            return Response::Ok;
        }
        Err(e) => return error(e),
    };
    if matches!(
        txn.phase,
        MoveAuthorityPhase::Reserved
            | MoveAuthorityPhase::Committing
            | MoveAuthorityPhase::Committed
    ) || published_for(&txn)
        || reg
            .get(name)
            .ok()
            .is_some_and(|i| i.id == instance_id && i.move_epoch == epoch)
    {
        return authority_response(&txn, reg);
    }
    if txn.phase == MoveAuthorityPhase::Aborted {
        return match finish_target_abort(&mut txn) {
            Ok(()) => authority_response(&txn, reg),
            Err(e) => error(e.context("finishing the durable target abort")),
        };
    }
    if txn.live {
        let source = match mesh() {
            Ok(mesh) => mesh,
            Err(e) => return error(e),
        };
        let proof = tokio::runtime::Handle::current().block_on(source.proxy(
            &txn.source_device,
            Request::MoveSourceStatus {
                instance_id: txn.instance_id.clone(),
                name: txn.name.clone(),
                epoch: txn.epoch,
                token: txn.token.clone(),
            },
        ));
        match proof.and_then(|response| {
            exact_source_phase(response, &txn.instance_id, txn.epoch, &txn.token)
        }) {
            Ok(MoveSourcePhase::Fenced) => {}
            Ok(MoveSourcePhase::Committed) => {
                return error(anyhow!(
                    "source no-return marker is committed; target abort is permanently refused"
                ))
            }
            Err(e) => return error(e.context("source abort proof is unavailable")),
        }
    }

    choose_target_abort_after_fenced(reg, instance_id, name, epoch, token)
}

/// Complete the abort leg after a Fenced source proof. The caller still owns
/// the target shard mutex and authority serialization guard, so the reload is
/// a CAS revalidation rather than a stale remote-read write.
fn choose_target_abort_after_fenced(
    reg: &Shard,
    instance_id: &str,
    name: &str,
    epoch: u64,
    token: &str,
) -> Response {
    // Re-read under the same target serialization point after the remote
    // proof.  This makes the proof advisory rather than a stale write
    // authorization: only a still-Prepared transaction may choose Aborted.
    let mut txn = match load_authority(instance_id, epoch) {
        Ok(Some(current)) if current.name == name && current.token == token => current,
        Ok(Some(_)) => return error(anyhow!("target abort winner changed identity")),
        Ok(None) => return error(anyhow!("target abort transaction disappeared")),
        Err(e) => return error(e),
    };
    if matches!(
        txn.phase,
        MoveAuthorityPhase::Reserved
            | MoveAuthorityPhase::Committing
            | MoveAuthorityPhase::Committed
    ) {
        return authority_response(&txn, reg);
    }
    if txn.phase == MoveAuthorityPhase::Aborted {
        return match finish_target_abort(&mut txn) {
            Ok(()) => authority_response(&txn, reg),
            Err(e) => error(e.context("finishing the durable target abort")),
        };
    }

    // The decision WAL precedes every destructive action.  A crash after
    // this save can only replay cleanup; it can never leave a Prepared WAL
    // whose incoming process was already killed and then let reservation win.
    txn.phase = MoveAuthorityPhase::Aborted;
    if let Err(e) = save_authority(&txn) {
        return error(e.context("recording the durable target abort winner"));
    }
    match finish_target_abort(&mut txn) {
        Ok(()) => authority_response(&txn, reg),
        Err(e) => error(e.context("target is durably aborted but cleanup remains pending")),
    }
}

/// Fence every process and byte owned by a durable Aborted target.  Cleanup
/// is idempotent and its final WAL rewrite merely drops the now-dead handle;
/// the Aborted decision itself was persisted before this function is called.
fn finish_target_abort(txn: &mut AuthorityTxn) -> Result<()> {
    if txn.phase != MoveAuthorityPhase::Aborted {
        bail!("target cleanup requires a durable Aborted decision");
    }
    let name = txn.name.clone();
    let epoch = txn.epoch;
    let staging = staging_for(txn)?;
    let handle = live_sessions()
        .remove(&(name.to_owned(), epoch))
        .or_else(|| txn.handle.clone())
        .or_else(|| {
            std::fs::read(staging.join(LIVE_HANDLE))
                .ok()
                .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        });
    let has_recorded_handle = handle.is_some();
    if let Some(handle) = handle {
        if let Err(e) = backend::for_handle(&handle.backend).and_then(|hv| hv.kill(&handle)) {
            return Err(e.context("fencing the uncommitted target guest"));
        }
    }
    // A durable Prepared record normally has a staging tree, a recorded
    // incoming handle, or a disk export to retire. A direct replay can find
    // only the decision WAL: there is then no target-owned process or byte
    // to fence, so asking a backend to abort a phantom target would turn a
    // valid durable Aborted winner into an error and keep the source fenced.
    let has_target_resources = staging.exists() || has_recorded_handle || txn.disk_export.is_some();
    if txn.live && has_target_resources {
        let cleanup = (|| -> Result<()> {
            let hv = backend::for_instance(&txn.manifest.instance)?;
            let req = backend::migration_req(&txn.manifest.instance, staging.clone())?;
            hv.migration_target_abort(&req)
        })();
        if let Err(e) = cleanup {
            return Err(e.context("fencing an incoming target without a recorded handle"));
        }
    }
    if let Some(export) = txn.disk_export.as_ref() {
        if let Ok(hv) = backend::for_instance(&txn.manifest.instance) {
            if let Err(e) = hv.migration_disk_export_stop(export) {
                return Err(e.context("stopping the uncommitted target disk export"));
            }
        }
    }
    let _ = std::fs::remove_file(paths::migration_socket_in(&staging));
    if let Err(e) = std::fs::remove_dir_all(&staging) {
        if e.kind() != std::io::ErrorKind::NotFound {
            return Err(e.into());
        }
    }
    txn.handle = None;
    txn.disk_export = None;
    save_authority(txn).context("recording completed target abort cleanup")
}

// ---- what a device remembers about an instance that left -------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MovedNote {
    #[serde(default)]
    pub instance_id: String,
    pub to_device: String,
    pub epoch: u64,
    #[serde(default)]
    pub token: String,
    pub at: u64,
}

/// Permanent source-side completion proof.
///
/// Unlike [`MovedNote`], this is not a display cache and never expires.  It
/// is written before the source row is removed, so a lost commit reply or a
/// crash during byte cleanup can replay the exact id/epoch/token forever.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct SourceCompletion {
    version: u32,
    instance_id: String,
    name: String,
    to_device: String,
    epoch: u64,
    token: String,
}

fn hex_key(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len() * 2);
    for byte in value.as_bytes() {
        use std::fmt::Write as _;
        let _ = write!(encoded, "{byte:02x}");
    }
    encoded
}

fn source_completion_path(instance_id: &str, epoch: u64, token: &str) -> PathBuf {
    paths::home_dir().join(SOURCE_COMPLETION_DIR).join(format!(
        "{}-{epoch}-{}.json",
        hex_key(instance_id),
        hex_key(token)
    ))
}

fn load_source_completion(
    instance_id: &str,
    name: &str,
    epoch: u64,
    token: &str,
) -> Result<Option<SourceCompletion>> {
    let path = source_completion_path(instance_id, epoch, token);
    let Some(loaded) = durable::load_json::<SourceCompletion>(&path, "a source move completion")?
    else {
        return Ok(None);
    };
    let completion = loaded.value;
    if completion.instance_id != instance_id
        || completion.name != name
        || completion.epoch != epoch
        || completion.token != token
    {
        bail!("source completion WAL does not match id/name/epoch/token");
    }
    Ok(Some(completion))
}

fn save_source_completion(completion: &SourceCompletion) -> Result<()> {
    durable::commit_json(
        &source_completion_path(&completion.instance_id, completion.epoch, &completion.token),
        completion,
    )
    .context("committing the permanent source completion WAL")
}

fn replay_source_completion(completion: &SourceCompletion) -> Response {
    crate::persist::forget(&completion.name);
    let source_dir = paths::instance_dir(&completion.name);
    if let Err(e) = std::fs::remove_dir_all(&source_dir) {
        if e.kind() != std::io::ErrorKind::NotFound {
            return error(anyhow!(e).context(format!(
                "removing migrated source bytes at {}",
                source_dir.display()
            )));
        }
    }
    remember_move(
        &completion.name,
        &completion.instance_id,
        &completion.to_device,
        completion.epoch,
        &completion.token,
    );
    Response::Ok
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

fn remember_move(name: &str, instance_id: &str, to_device: &str, epoch: u64, token: &str) {
    let mut notes = load_notes();
    let now = now_unix();
    notes.retain(|_, note| now.saturating_sub(note.at) < NOTE_TTL_SECS);
    notes.insert(
        name.to_owned(),
        MovedNote {
            instance_id: instance_id.to_owned(),
            to_device: to_device.to_owned(),
            epoch,
            token: token.to_owned(),
            at: now,
        },
    );
    // Best effort by design: a note is a courtesy to whoever types
    // `ast status` at the old device, and losing it costs a redirect, not an
    // instance. It is still committed durably, because the alternative is a
    // torn file that the next read has to treat as a lost note anyway.
    let _ = durable::commit_json(&notes_path(), &notes);
}

/// What this device has to say about an instance it no longer holds.
///
/// Only ever reached when a request was aimed at this device directly: the
/// ordinary path resolves the name across the orbit and lands on whoever
/// holds the row now.
pub fn moved_note(name: &str) -> Option<String> {
    let note = moved_note_full(name)?;
    if now_unix().saturating_sub(note.at) >= NOTE_TTL_SECS {
        return None;
    }
    Some(format!(
        "instance {name:?} moved to {} — its cpu is sourced there now, and \
         `ast status {name}` from anywhere in this orbit will find it",
        note.to_device
    ))
}

fn moved_note_full(name: &str) -> Option<MovedNote> {
    let note = load_notes().get(name).cloned()?;
    (now_unix().saturating_sub(note.at) < NOTE_TTL_SECS).then_some(note)
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
    let live = manifest.instance.status == Status::Running && !down;
    if manifest.instance.status == Status::Running && down {
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
        "{} {name} from {source} to {device}: {} of {} across {} file(s) \
         [allocated={} virtual={}]",
        if live { "pre-copying" } else { "moving" },
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
    let token = uuid::Uuid::new_v4().to_string();
    let coordinator_id = mesh.device_id().to_string();
    let source_device_id = mesh.device_id_of(&source).await?;
    let target_device_id = mesh.device_id_of(device).await?;
    let prepared = ask(
        &source,
        Request::MovePrepare {
            instance_id: manifest.instance.id.clone(),
            name: name.to_owned(),
            to_device: device.to_owned(),
            to_device_id: target_device_id,
            epoch,
            token: token.clone(),
            coordinator_id: coordinator_id.clone(),
            live,
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

    let outcome = transfer_and_commit_target(
        &manifest,
        &source,
        device,
        &source_device_id,
        &coordinator_id,
        epoch,
        &token,
        live,
        node,
        mesh,
        io,
    )
    .await;
    if let Err(e) = outcome {
        let may_resume = if live {
            match ask(
                &source,
                Request::MoveSourceStatus {
                    instance_id: manifest.instance.id.clone(),
                    name: name.to_owned(),
                    epoch,
                    token: token.clone(),
                },
                node,
                mesh,
            )
            .await
            {
                Ok(response) => {
                    match exact_source_phase(response, &manifest.instance.id, epoch, &token) {
                        Ok(MoveSourcePhase::Fenced) => {
                            target_abort_proof(
                                device,
                                &manifest.instance.id,
                                name,
                                epoch,
                                &token,
                                node,
                                mesh,
                            )
                            .await
                        }
                        Ok(MoveSourcePhase::Committed) => Ok(false),
                        Err(error) => Err(error),
                    }
                }
                Err(error) => Err(error),
            }
        } else {
            // Offline migration predates the authority protocol. Its source
            // guest is stopped and the existing --down semantics remain.
            let _ = ask(
                device,
                Request::MoveAbortTarget {
                    instance_id: manifest.instance.id.clone(),
                    name: name.to_owned(),
                    epoch,
                    token: token.clone(),
                },
                node,
                mesh,
            )
            .await;
            Ok(true)
        };
        if matches!(may_resume, Ok(true)) {
            expect_ok(
                ask(
                    &source,
                    Request::MoveAbortSource {
                        instance_id: manifest.instance.id.clone(),
                        name: name.to_owned(),
                        epoch,
                        token: token.clone(),
                    },
                    node,
                    mesh,
                )
                .await?,
            )?;
            io.send(&line(format!(
                "the move was durably aborted — {source} still supplies {name}'s cpu"
            )))
            .await?;
            return Err(e);
        }
        return Err(e.context(format!(
            "target authority could not be proven aborted; {source}'s guest remains fenced and must not be resumed"
        )));
    }

    // The target commit is the point of no return. From here an error must
    // never run either abort: the target row is authoritative at the higher
    // epoch, and clearing the source fence would create two runnable copies.
    expect_ok(
        ask(
            &source,
            Request::MoveCommitSource {
                instance_id: manifest.instance.id.clone(),
                name: name.to_owned(),
                epoch,
                token: token.clone(),
            },
            node,
            mesh,
        )
        .await?,
    )
    .with_context(|| {
        format!(
            "{device} has {name:?} at epoch {epoch} and {source} would not let go of \
             its copy — the higher epoch is authoritative; the source remains fenced"
        )
    })?;
    io.send(&line(format!("{source} has dropped its copy")))
        .await?;

    io.send(&Response::Move {
        text: format!(
            "{name}: cpu/ram now sourced from {device} (move epoch {epoch}){}",
            if live {
                " — the running guest and its control channel continued there"
            } else {
                " — `ast up` boots it there"
            }
        ),
        done: true,
    })
    .await
}

/// Phases two and three: the bytes, then the two commits in order.
#[allow(clippy::too_many_arguments)]
async fn transfer_and_commit_target(
    manifest: &MoveManifest,
    source: &str,
    device: &str,
    source_device_id: &str,
    coordinator_id: &str,
    epoch: u64,
    token: &str,
    live: bool,
    node: &Node,
    mesh: &Arc<Mesh>,
    io: &mut ClientIo<'_>,
) -> Result<()> {
    let name = manifest.instance.name.clone();

    if live {
        let begun = ask(
            device,
            Request::MoveBeginTarget {
                manifest: Box::new(manifest.clone()),
                epoch,
                source_device: source.to_owned(),
                source_device_id: source_device_id.to_owned(),
                token: token.to_owned(),
                coordinator_id: coordinator_id.to_owned(),
            },
            node,
            mesh,
        )
        .await?;
        match exact_target_authority(begun, &manifest.instance.id, epoch, token)? {
            TargetProof {
                phase:
                    MoveAuthorityPhase::Intent
                    | MoveAuthorityPhase::DiskPrepared
                    | MoveAuthorityPhase::Prepared,
                ..
            } => {}
            other => bail!("device {device:?} began live migration with {other:?}"),
        }
    }

    mesh.move_import(device, source, manifest, epoch, token, live, io)
        .await?;

    if live {
        let lane = expect_move_disk_ready(
            ask(
                device,
                Request::MoveLivePrepareDisk {
                    instance_id: manifest.instance.id.clone(),
                    name: name.clone(),
                    epoch,
                    token: token.to_owned(),
                },
                node,
                mesh,
            )
            .await?,
            &manifest.instance.id,
            epoch,
            token,
        )?;
        mesh.live_disk_mirror(
            source,
            device,
            &manifest.instance.id,
            &name,
            epoch,
            token,
            lane,
            node,
        )
        .await
        .context("the dirty-disk mirror did not reach READY")?;
        let disk_recorded = ask(
            device,
            Request::MoveLiveDiskReady {
                instance_id: manifest.instance.id.clone(),
                name: name.clone(),
                epoch,
                token: token.to_owned(),
            },
            node,
            mesh,
        )
        .await?;
        match exact_target_authority(disk_recorded, &manifest.instance.id, epoch, token)? {
            TargetProof {
                phase: MoveAuthorityPhase::DiskPrepared,
                ..
            } => {}
            other => bail!("device {device:?} recorded dirty-disk readiness as {other:?}"),
        }
        let ram_lane = match ask(
            device,
            Request::MoveLivePrepareTarget {
                manifest: Box::new(manifest.clone()),
                epoch,
                source_device: source.to_owned(),
                source_device_id: source_device_id.to_owned(),
                token: token.to_owned(),
            },
            node,
            mesh,
        )
        .await?
        {
            Response::MoveLiveReady {
                instance_id,
                epoch: winner_epoch,
                token: winner_token,
                lane,
            } if instance_id == manifest.instance.id
                && winner_epoch == epoch
                && winner_token == token =>
            {
                lane
            }
            Response::Error { message } => bail!(message),
            other => bail!("device {device:?} prepared live migration with {other:?}"),
        };
        if ram_lane != lane {
            bail!("target changed live stream lane during initial preparation");
        }
        io.send(&line(format!(
            "{device}'s compatible backend is waiting on the staged pre-copy"
        )))
        .await?;
        mesh.live_migrate(
            source,
            device,
            &name,
            &manifest.instance.id,
            epoch,
            token,
            lane,
            node,
        )
        .await
        .context("the backend migration stream failed before authority transferred")?;
        let decision = ask(
            source,
            Request::MoveDecideSource {
                instance_id: manifest.instance.id.clone(),
                name: name.clone(),
                epoch,
                token: token.to_owned(),
            },
            node,
            mesh,
        )
        .await?;
        if exact_source_phase(decision, &manifest.instance.id, epoch, token)?
            != MoveSourcePhase::Committed
        {
            bail!("device {source:?} did not durably commit live migration");
        }
        io.send(&line(
            "dirty disk, memory and device state converged; source execution is fenced".into(),
        ))
        .await?;
    }

    // The target checks what arrived against the manifest and only then does
    // a second copy of this instance exist anywhere.
    commit_target_with_recovery(device, manifest, epoch, token, node, mesh)
        .await
        .with_context(|| format!("{device} would not adopt {name:?}"))?;
    io.send(&line(format!(
        "{device} has it, verified against the manifest"
    )))
    .await?;

    Ok(())
}

async fn commit_target_with_recovery(
    device: &str,
    manifest: &MoveManifest,
    epoch: u64,
    token: &str,
    node: &Node,
    mesh: &Arc<Mesh>,
) -> Result<()> {
    let mut last = None;
    for _ in 0..3 {
        match ask(
            device,
            Request::MoveCommitTarget {
                manifest: Box::new(manifest.clone()),
                epoch,
                token: token.to_owned(),
            },
            node,
            mesh,
        )
        .await
        {
            Ok(Response::Instance { instance, .. })
                if instance.id == manifest.instance.id && instance.move_epoch == epoch =>
            {
                return Ok(())
            }
            Ok(Response::Error { message }) => last = Some(anyhow!(message)),
            Ok(other) => last = Some(anyhow!("unexpected target commit answer: {other:?}")),
            Err(e) => last = Some(e),
        }

        match ask(
            device,
            Request::MoveTargetStatus {
                instance_id: manifest.instance.id.clone(),
                name: manifest.instance.name.clone(),
                epoch,
                token: token.to_owned(),
            },
            node,
            mesh,
        )
        .await
        {
            Ok(response) => {
                match exact_target_authority(response, &manifest.instance.id, epoch, token) {
                    Ok(TargetProof {
                        phase: MoveAuthorityPhase::Committed,
                        ..
                    }) => return Ok(()),
                    Ok(TargetProof {
                        phase: MoveAuthorityPhase::Aborted,
                        ..
                    }) => bail!("target transaction was durably aborted"),
                    Ok(_) => continue,
                    Err(e) => last = Some(e),
                }
            }
            Err(e) => last = Some(e),
        }
    }
    Err(last.unwrap_or_else(|| anyhow!("target authority remained indeterminate")))
}

async fn target_abort_proof(
    device: &str,
    instance_id: &str,
    name: &str,
    epoch: u64,
    token: &str,
    node: &Node,
    mesh: &Arc<Mesh>,
) -> Result<bool> {
    let response = ask(
        device,
        Request::MoveAbortTarget {
            instance_id: instance_id.to_owned(),
            name: name.to_owned(),
            epoch,
            token: token.to_owned(),
        },
        node,
        mesh,
    )
    .await?;
    Ok(
        exact_target_authority(response, instance_id, epoch, token)?.phase
            == MoveAuthorityPhase::Aborted,
    )
}

/// Which device holds this instance's row, in the orbit's own words.
async fn locate(name: &str, node: &Node, mesh: &Arc<Mesh>) -> Result<String> {
    if node.shard.lock().await.holds(name) {
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

fn expect_move_disk_ready(
    response: Response,
    instance_id: &str,
    epoch: u64,
    token: &str,
) -> Result<u64> {
    match response {
        Response::MoveDiskReady {
            instance_id: winner_id,
            epoch: winner_epoch,
            token: winner_token,
            lane,
        } if winner_id == instance_id && winner_epoch == epoch && winner_token == token => Ok(lane),
        Response::Error { message } => bail!(message),
        other => bail!("expected dirty-disk readiness, got {other:?}"),
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

    fn running_instance() -> Instance {
        let mut instance = Instance::new(
            "dev",
            "laptop",
            "debian:13",
            Default::default(),
            asterism_core::hv::Machine {
                backend: "qemu".into(),
                machine_type: "virt-9.0".into(),
                cpu: "host".into(),
                hv_version: "9.2.1".into(),
            },
        );
        instance.status = Status::Running;
        instance
    }

    fn ready(version: &str, machine_type: &str, cpu: &str) -> Ready {
        Ready {
            version: version.into(),
            accel: "kvm".into(),
            machine_type: machine_type.into(),
            cpu: cpu.into(),
        }
    }

    #[test]
    fn live_migration_negotiates_capability_and_machine_compatibility() {
        let instance = running_instance();
        assert!(live_refusal(
            &instance,
            true,
            &ready("9.7.0", "virt-9.0", "host"),
            "desktop"
        )
        .is_none());

        for (candidate, needle) in [
            (ready("10.0.0", "virt-9.0", "host"), "incompatible"),
            (ready("9.2.1", "virt-10.0", "host"), "incompatible"),
            (ready("9.2.1", "virt-9.0", "max"), "incompatible"),
        ] {
            let refusal = live_refusal(&instance, true, &candidate, "desktop").unwrap();
            assert!(refusal.contains(needle), "{refusal}");
            assert!(refusal.contains("--down"), "{refusal}");
        }

        let refusal = live_refusal(
            &instance,
            false,
            &ready("9.2.1", "virt-9.0", "host"),
            "desktop",
        )
        .unwrap();
        assert!(
            refusal.contains("cannot receive a running guest"),
            "{refusal}"
        );
    }

    #[test]
    fn a_live_fence_admits_the_running_source_but_the_offline_fence_does_not() {
        let instance = running_instance();
        assert!(movable(&instance, true).is_ok());
        let refusal = movable(&instance, false).unwrap_err().to_string();
        assert!(
            refusal.contains("offline move needs it stopped"),
            "{refusal}"
        );
    }

    #[test]
    fn a_staging_directory_can_never_be_an_instance() {
        // Instance names are ascii letters, digits and '-'; the staging
        // marker is neither, which is what makes an abandoned one harmless.
        let staged = staging_dir("dev", "instance-id", 7, "move-token");
        let leaf = staged.file_name().unwrap().to_string_lossy().into_owned();
        assert!(leaf.starts_with("dev.moving-7-"));
        assert_ne!(
            staged,
            staging_dir("dev", "replacement-id", 7, "replacement-token"),
            "a stale move may not share the newer move's staging tree"
        );
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
                instance_id: "instance-id".into(),
                name: "dev".into(),
                to_device: "desktop".into(),
                to_device_id: "target-id".into(),
                epoch: 1,
                token: "token".into(),
                coordinator_id: "coordinator-id".into(),
                live: false,
            },
            Request::MoveCommitSource {
                instance_id: "instance-id".into(),
                name: "dev".into(),
                epoch: 1,
                token: "token".into(),
            },
            Request::MoveAbortSource {
                instance_id: "instance-id".into(),
                name: "dev".into(),
                epoch: 1,
                token: "token".into(),
            },
            Request::MoveAbortTarget {
                instance_id: "instance-id".into(),
                name: "dev".into(),
                epoch: 1,
                token: "token".into(),
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
    fn final_source_commit_dispatch_keeps_asks_four_argument_shape() {
        let source = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/swap.rs"));
        assert!(
            source.contains(
                "Request::MoveCommitSource {\n                instance_id: manifest.instance.id.clone(),\n                name: name.to_owned(),\n                epoch,\n                token: token.clone(),\n            },\n            node,\n            mesh,"
            ),
            "the final source commit must call ask(device, request, node, mesh)"
        );
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
            LIVE_SOCKET,
            LIVE_HANDLE,
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
        let err = verify(&staging, &manifest, 1, "token")
            .unwrap_err()
            .to_string();
        assert!(err.contains("never finished"), "{err}");

        // A receipt from another epoch is somebody else's transfer.
        Receipt {
            instance_id: manifest.instance.id.clone(),
            epoch: 2,
            token: "token".into(),
            from_device: "laptop".into(),
            bytes: 4096,
            files: [("disk.raw".to_owned(), 4096u64)].into_iter().collect(),
        }
        .save(&staging)
        .unwrap();
        let err = verify(&staging, &manifest, 1, "token")
            .unwrap_err()
            .to_string();
        assert!(err.contains("epoch"), "{err}");

        // The right epoch and the right bytes is the one that passes.
        Receipt {
            instance_id: manifest.instance.id.clone(),
            epoch: 1,
            token: "token".into(),
            from_device: "laptop".into(),
            bytes: 4096,
            files: [("disk.raw".to_owned(), 4096u64)].into_iter().collect(),
        }
        .save(&staging)
        .unwrap();
        verify(&staging, &manifest, 1, "token").unwrap();

        let mut wrong_identity = Receipt::load(&staging).unwrap();
        wrong_identity.instance_id = "stale-instance-id".into();
        wrong_identity.save(&staging).unwrap();
        let err = verify(&staging, &manifest, 1, "token")
            .unwrap_err()
            .to_string();
        assert!(err.contains("another instance"), "{err}");
        wrong_identity.instance_id = manifest.instance.id.clone();
        wrong_identity.token = "stale-token".into();
        wrong_identity.save(&staging).unwrap();
        let err = verify(&staging, &manifest, 1, "token")
            .unwrap_err()
            .to_string();
        assert!(err.contains("move token"), "{err}");
        wrong_identity.token = "token".into();
        wrong_identity.save(&staging).unwrap();

        // A file that arrived the wrong length is refused even though the
        // byte count adds up — sparse means those are different questions.
        std::fs::write(staging.join("disk.raw"), vec![0u8; 2048]).unwrap();
        let err = verify(&staging, &manifest, 1, "token")
            .unwrap_err()
            .to_string();
        assert!(err.contains("2048") && err.contains("4096"), "{err}");

        // And a file that never turned up at all.
        std::fs::remove_file(staging.join("disk.raw")).unwrap();
        let err = verify(&staging, &manifest, 1, "token")
            .unwrap_err()
            .to_string();
        assert!(err.contains("did not arrive"), "{err}");

        // A staging directory that is not there is the crashed-mid-move case.
        let err = verify(&dir.path().join("nope"), &manifest, 1, "token")
            .unwrap_err()
            .to_string();
        assert!(err.contains("no staging directory"), "{err}");
    }

    /// Exercise the authority handoff at the two filesystem boundaries that
    /// used to be ambiguous: publication before the row, and the row before
    /// the final WAL phase. Both failures are replayed from only durable
    /// state, as a restarted daemon would see them.
    #[test]
    fn target_authority_recovers_every_publish_boundary_and_aborts_conditionally() {
        use asterism_core::durable::faults::{self, Point};
        use std::ffi::OsString;
        use std::io;

        static HOME_ENV: OnceLock<Mutex<()>> = OnceLock::new();
        let _serial = HOME_ENV
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        struct RestoreHome(Option<OsString>);
        impl Drop for RestoreHome {
            fn drop(&mut self) {
                match self.0.take() {
                    Some(value) => std::env::set_var("ASTERISM_HOME", value),
                    None => std::env::remove_var("ASTERISM_HOME"),
                }
            }
        }

        let home = tempfile::tempdir().unwrap();
        let _restore = RestoreHome(std::env::var_os("ASTERISM_HOME"));
        std::env::set_var("ASTERISM_HOME", home.path());

        fn staged(manifest: &MoveManifest, epoch: u64) {
            let dir = staging_dir(
                &manifest.instance.name,
                &manifest.instance.id,
                epoch,
                "token",
            );
            std::fs::create_dir_all(&dir).unwrap();
            Receipt {
                instance_id: manifest.instance.id.clone(),
                epoch,
                token: "token".into(),
                from_device: manifest.instance.cpu_device.clone(),
                bytes: 0,
                files: BTreeMap::new(),
            }
            .save(&dir)
            .unwrap();
        }

        fn txn(manifest: &MoveManifest, epoch: u64, phase: MoveAuthorityPhase) -> AuthorityTxn {
            AuthorityTxn {
                version: 1,
                instance_id: manifest.instance.id.clone(),
                name: manifest.instance.name.clone(),
                epoch,
                phase,
                manifest: manifest.clone(),
                live: false,
                source_device: manifest.instance.cpu_device.clone(),
                source_device_id: "source-id".into(),
                token: "token".into(),
                coordinator_id: "coordinator-id".into(),
                handle: None,
                disk_export: None,
                disk_eof: false,
                ram_eof: false,
                lane: initial_lane(),
                lane_ready: true,
            }
        }

        fn set_phase_locked(
            instance_id: &str,
            epoch: u64,
            phase: MoveAuthorityPhase,
        ) -> Result<()> {
            let mut authority = load_authority(instance_id, epoch)?
                .context("test authority transaction disappeared")?;
            authority.phase = phase;
            save_authority(&authority)
        }

        let state = paths::state_path();
        let mut reg = Shard::load(&state).unwrap();

        // The source decision is an atomic durable choice at every write
        // boundary. A rename failure leaves Fenced; a directory-sync failure
        // may report an error after the Committed bytes became live. Reload,
        // rather than the caller's return value, is the recovery oracle.
        for (index, point, expected) in [
            (0, Point::Rename, MoveSourcePhase::Fenced),
            (1, Point::SyncDir, MoveSourcePhase::Committed),
        ] {
            let mut source = manifest_of(Vec::new()).instance;
            source.name = format!("source-marker-{index}");
            source.id = format!("source-marker-id-{index}");
            let mut moving = Moving {
                to_device: "desktop".into(),
                to_device_id: "target-id".into(),
                epoch: 7,
                started_at: now_unix(),
                token: format!("source-token-{index}"),
                lane: initial_lane(),
                coordinator_id: "coordinator-id".into(),
                phase: MoveSourcePhase::Fenced,
                live: true,
            };
            source.moving = Some(moving.clone());
            reg.adopt(source).unwrap();
            reg.save().unwrap();
            let armed = faults::arm_once(
                if index == 0 {
                    "source-marker-rename"
                } else {
                    "source-marker-sync"
                },
                point,
                home.path().display().to_string(),
                io::ErrorKind::Other,
            );
            assert!(persist_source_decision(
                &mut reg,
                &format!("source-marker-{index}"),
                &mut moving
            )
            .is_err());
            drop(armed);
            assert_eq!(
                reg.get(&format!("source-marker-{index}"))
                    .unwrap()
                    .moving
                    .as_ref()
                    .unwrap()
                    .phase,
                expected,
                "failed source saves must immediately restore the in-memory durability oracle"
            );
            reg = Shard::load(&state).unwrap();
            assert_eq!(
                reg.get(&format!("source-marker-{index}"))
                    .unwrap()
                    .moving
                    .as_ref()
                    .unwrap()
                    .phase,
                expected
            );
        }

        // Reply loss and crash replay cannot create a second authority. The
        // immutable source marker selects exactly one owner: before it, the
        // source; from it onward, the target. Publication is a discoverability
        // step and never transfers authority in the opposite direction.
        let gate_manifest = manifest_of(Vec::new());
        let mut gate = txn(&gate_manifest, 11, MoveAuthorityPhase::Reserved);
        gate.live = true;
        gate.disk_eof = true;
        gate.ram_eof = true;
        assert!(validate_live_publish_state(&gate, MoveSourcePhase::Fenced, true).is_err());
        gate.disk_eof = false;
        assert!(validate_live_publish_state(&gate, MoveSourcePhase::Committed, true).is_err());
        gate.disk_eof = true;
        assert!(validate_live_publish_state(&gate, MoveSourcePhase::Committed, false).is_err());
        for _reply_replay in 0..3 {
            assert!(validate_live_publish_state(&gate, MoveSourcePhase::Committed, true).is_ok());
        }
        for (source_phase, target_published) in [
            (MoveSourcePhase::Fenced, false),
            (MoveSourcePhase::Committed, false),
            (MoveSourcePhase::Committed, true),
        ] {
            let source_authority = source_phase == MoveSourcePhase::Fenced;
            let target_authority = source_phase == MoveSourcePhase::Committed;
            assert_eq!(
                usize::from(source_authority) + usize::from(target_authority),
                1,
                "source={source_phase:?} target_published={target_published}"
            );
        }

        // The target shard mutex and authority serializer form the single
        // decision CAS.  Hold the abort handler immediately after its remote
        // Fenced observation: a real reservation handler blocks, then
        // deterministically replays Aborted after the abort WAL wins.
        use std::sync::Barrier;
        use std::thread;

        let mut abort_manifest = manifest_of(Vec::new());
        abort_manifest.instance.name = "decision-abort-wins".into();
        abort_manifest.instance.id = "decision-abort-id".into();
        let abort_epoch = 21;
        let mut abort_txn = txn(&abort_manifest, abort_epoch, MoveAuthorityPhase::Prepared);
        abort_txn.live = true;
        save_authority(&abort_txn).unwrap();
        let shared = Arc::new(Mutex::new(Shard::load(&state).unwrap()));
        let observed = Arc::new(Barrier::new(2));
        let release = Arc::new(Barrier::new(2));
        let abort_thread = {
            let shared = shared.clone();
            let observed = observed.clone();
            let release = release.clone();
            let id = abort_manifest.instance.id.clone();
            thread::spawn(move || {
                let reg = shared.lock().unwrap_or_else(|e| e.into_inner());
                with_authority_txn(|| {
                    observed.wait();
                    release.wait();
                    choose_target_abort_after_fenced(
                        &reg,
                        &id,
                        "decision-abort-wins",
                        abort_epoch,
                        "token",
                    )
                })
            })
        };
        observed.wait();
        let reserve_thread = {
            let shared = shared.clone();
            let id = abort_manifest.instance.id.clone();
            thread::spawn(move || {
                let reg = shared.lock().unwrap_or_else(|e| e.into_inner());
                with_authority_txn(|| {
                    reserve_target(&reg, &id, "decision-abort-wins", abort_epoch, "token")
                })
            })
        };
        release.wait();
        assert!(matches!(
            abort_thread.join().unwrap(),
            Response::MoveAuthority {
                phase: MoveAuthorityPhase::Aborted,
                ..
            }
        ));
        assert!(matches!(
            reserve_thread.join().unwrap(),
            Response::MoveAuthority {
                phase: MoveAuthorityPhase::Aborted,
                ..
            }
        ));
        assert_eq!(
            load_authority(&abort_manifest.instance.id, abort_epoch)
                .unwrap()
                .unwrap()
                .phase,
            MoveAuthorityPhase::Aborted
        );

        // Reverse the barriers: reservation persists while holding the
        // target mutex, and the delayed abort handler can only replay that
        // non-abortable winner. This is the source-Committed/target-forward
        // leg; the opposite leg above leaves the source Fenced and runnable.
        let mut reserve_manifest = manifest_of(Vec::new());
        reserve_manifest.instance.name = "decision-reserve-wins".into();
        reserve_manifest.instance.id = "decision-reserve-id".into();
        let reserve_epoch = 22;
        let mut reserve_txn = txn(
            &reserve_manifest,
            reserve_epoch,
            MoveAuthorityPhase::Prepared,
        );
        reserve_txn.live = true;
        save_authority(&reserve_txn).unwrap();
        let shared = Arc::new(Mutex::new(Shard::load(&state).unwrap()));
        let observed = Arc::new(Barrier::new(2));
        let release = Arc::new(Barrier::new(2));
        let reserve_thread = {
            let shared = shared.clone();
            let observed = observed.clone();
            let release = release.clone();
            let id = reserve_manifest.instance.id.clone();
            thread::spawn(move || {
                let reg = shared.lock().unwrap_or_else(|e| e.into_inner());
                with_authority_txn(|| {
                    observed.wait();
                    release.wait();
                    reserve_target(&reg, &id, "decision-reserve-wins", reserve_epoch, "token")
                })
            })
        };
        observed.wait();
        let abort_thread = {
            let shared = shared.clone();
            let id = reserve_manifest.instance.id.clone();
            thread::spawn(move || {
                let reg = shared.lock().unwrap_or_else(|e| e.into_inner());
                with_authority_txn(|| {
                    choose_target_abort_after_fenced(
                        &reg,
                        &id,
                        "decision-reserve-wins",
                        reserve_epoch,
                        "token",
                    )
                })
            })
        };
        release.wait();
        assert!(matches!(
            reserve_thread.join().unwrap(),
            Response::MoveAuthority {
                phase: MoveAuthorityPhase::Reserved,
                ..
            }
        ));
        assert!(matches!(
            abort_thread.join().unwrap(),
            Response::MoveAuthority {
                phase: MoveAuthorityPhase::Reserved,
                ..
            }
        ));

        // Disk and RAM callbacks race outside the shard mutex, but the
        // authority updater serializes their whole load/modify/save. Both
        // proofs remain set, and a callback delayed past either terminal
        // decision is refused instead of rolling the phase backward.
        let mut eof_manifest = manifest_of(Vec::new());
        eof_manifest.instance.name = "concurrent-eof".into();
        eof_manifest.instance.id = "concurrent-eof-id".into();
        let eof_epoch = 23;
        let mut eof_txn = txn(&eof_manifest, eof_epoch, MoveAuthorityPhase::Reserved);
        eof_txn.live = true;
        save_authority(&eof_txn).unwrap();
        let disk = {
            let id = eof_manifest.instance.id.clone();
            thread::spawn(move || {
                mark_target_stream_eof(&id, eof_epoch, "token", initial_lane(), true)
            })
        };
        let ram = {
            let id = eof_manifest.instance.id.clone();
            thread::spawn(move || {
                mark_target_stream_eof(&id, eof_epoch, "token", initial_lane(), false)
            })
        };
        disk.join().unwrap().unwrap();
        ram.join().unwrap().unwrap();
        let both = load_authority(&eof_manifest.instance.id, eof_epoch)
            .unwrap()
            .unwrap();
        assert!(both.disk_eof && both.ram_eof);
        let mut terminal = both.clone();
        terminal.phase = MoveAuthorityPhase::Committing;
        save_authority(&terminal).unwrap();
        assert!(mark_target_stream_eof(
            &eof_manifest.instance.id,
            eof_epoch,
            "token",
            initial_lane(),
            true
        )
        .is_err());
        assert_eq!(
            load_authority(&eof_manifest.instance.id, eof_epoch)
                .unwrap()
                .unwrap()
                .phase,
            MoveAuthorityPhase::Committing
        );

        // EOF and abort use the same target-local transaction boundary. Test
        // both orders with barriers: an abort that wins first makes the late
        // callback fail, while an EOF that wins first is retained by the
        // subsequently durable Aborted winner.
        let mut abort_eof_manifest = manifest_of(Vec::new());
        abort_eof_manifest.instance.name = "abort-before-eof".into();
        abort_eof_manifest.instance.id = "abort-before-eof-id".into();
        let abort_eof_epoch = 24;
        let mut abort_eof = txn(
            &abort_eof_manifest,
            abort_eof_epoch,
            MoveAuthorityPhase::Prepared,
        );
        abort_eof.live = true;
        save_authority(&abort_eof).unwrap();
        let observed = Arc::new(Barrier::new(2));
        let release = Arc::new(Barrier::new(2));
        let abort_thread = {
            let observed = observed.clone();
            let release = release.clone();
            let id = abort_eof_manifest.instance.id.clone();
            let state = state.clone();
            thread::spawn(move || {
                let reg = Shard::load(&state).unwrap();
                with_authority_txn(|| {
                    observed.wait();
                    release.wait();
                    choose_target_abort_after_fenced(
                        &reg,
                        &id,
                        "abort-before-eof",
                        abort_eof_epoch,
                        "token",
                    )
                })
            })
        };
        observed.wait();
        let eof_thread = {
            let id = abort_eof_manifest.instance.id.clone();
            thread::spawn(move || {
                mark_target_stream_eof(&id, abort_eof_epoch, "token", initial_lane(), true)
            })
        };
        release.wait();
        assert!(matches!(
            abort_thread.join().unwrap(),
            Response::MoveAuthority {
                phase: MoveAuthorityPhase::Aborted,
                ..
            }
        ));
        assert!(eof_thread.join().unwrap().is_err());
        let winner = load_authority(&abort_eof_manifest.instance.id, abort_eof_epoch)
            .unwrap()
            .unwrap();
        assert_eq!(winner.phase, MoveAuthorityPhase::Aborted);
        assert!(!winner.disk_eof);

        let mut eof_abort_manifest = manifest_of(Vec::new());
        eof_abort_manifest.instance.name = "eof-before-abort".into();
        eof_abort_manifest.instance.id = "eof-before-abort-id".into();
        let eof_abort_epoch = 25;
        let mut eof_abort = txn(
            &eof_abort_manifest,
            eof_abort_epoch,
            MoveAuthorityPhase::Prepared,
        );
        eof_abort.live = true;
        save_authority(&eof_abort).unwrap();
        let observed = Arc::new(Barrier::new(2));
        let release = Arc::new(Barrier::new(2));
        let eof_thread = {
            let observed = observed.clone();
            let release = release.clone();
            let id = eof_abort_manifest.instance.id.clone();
            thread::spawn(move || {
                with_authority_txn(|| {
                    observed.wait();
                    release.wait();
                    mark_target_stream_eof_locked(
                        &id,
                        eof_abort_epoch,
                        "token",
                        initial_lane(),
                        true,
                    )
                })
            })
        };
        observed.wait();
        let abort_thread = {
            let id = eof_abort_manifest.instance.id.clone();
            let state = state.clone();
            thread::spawn(move || {
                let reg = Shard::load(&state).unwrap();
                with_authority_txn(|| {
                    choose_target_abort_after_fenced(
                        &reg,
                        &id,
                        "eof-before-abort",
                        eof_abort_epoch,
                        "token",
                    )
                })
            })
        };
        release.wait();
        eof_thread.join().unwrap().unwrap();
        assert!(matches!(
            abort_thread.join().unwrap(),
            Response::MoveAuthority {
                phase: MoveAuthorityPhase::Aborted,
                ..
            }
        ));
        let winner = load_authority(&eof_abort_manifest.instance.id, eof_abort_epoch)
            .unwrap()
            .unwrap();
        assert_eq!(winner.phase, MoveAuthorityPhase::Aborted);
        assert!(winner.disk_eof);

        // The same serialization prevents a stale callback from restoring
        // Prepared after the commit point of no return. Exercise both winner
        // orders, then both atomic-file failure results before Committing.
        for eof_first in [false, true] {
            let mut manifest = manifest_of(Vec::new());
            manifest.instance.name = format!("eof-commit-{eof_first}");
            manifest.instance.id = format!("eof-commit-id-{eof_first}");
            let epoch = if eof_first { 27 } else { 26 };
            let mut authority = txn(&manifest, epoch, MoveAuthorityPhase::Reserved);
            authority.live = true;
            save_authority(&authority).unwrap();
            let observed = Arc::new(Barrier::new(2));
            let release = Arc::new(Barrier::new(2));
            let first = {
                let observed = observed.clone();
                let release = release.clone();
                let id = manifest.instance.id.clone();
                thread::spawn(move || {
                    with_authority_txn(|| {
                        observed.wait();
                        release.wait();
                        if eof_first {
                            mark_target_stream_eof_locked(&id, epoch, "token", initial_lane(), true)
                        } else {
                            set_phase_locked(&id, epoch, MoveAuthorityPhase::Committing)
                        }
                    })
                })
            };
            observed.wait();
            let second = {
                let id = manifest.instance.id.clone();
                thread::spawn(move || {
                    with_authority_txn(|| {
                        if eof_first {
                            set_phase_locked(&id, epoch, MoveAuthorityPhase::Committing)
                        } else {
                            mark_target_stream_eof_locked(&id, epoch, "token", initial_lane(), true)
                        }
                    })
                })
            };
            release.wait();
            first.join().unwrap().unwrap();
            let second_result = second.join().unwrap();
            assert_eq!(second_result.is_ok(), eof_first);
            let durable = load_authority(&manifest.instance.id, epoch)
                .unwrap()
                .unwrap();
            assert_eq!(durable.phase, MoveAuthorityPhase::Committing);
            assert_eq!(durable.disk_eof, eof_first);
        }

        for (index, point, expected_eof) in [(0, Point::Rename, false), (1, Point::SyncDir, true)] {
            let mut manifest = manifest_of(Vec::new());
            manifest.instance.name = format!("eof-phase-fault-{index}");
            manifest.instance.id = format!("eof-phase-fault-id-{index}");
            let epoch = 28 + index;
            let mut authority = txn(&manifest, epoch, MoveAuthorityPhase::Reserved);
            authority.live = true;
            save_authority(&authority).unwrap();
            let armed = faults::arm_once(
                if index == 0 {
                    "eof-phase-rename"
                } else {
                    "eof-phase-sync"
                },
                point,
                if index == 0 {
                    authority_key(&manifest.instance.id, epoch)
                } else {
                    paths::home_dir().join(AUTHORITY_DIR).display().to_string()
                },
                io::ErrorKind::Other,
            );
            assert!(mark_target_stream_eof(
                &manifest.instance.id,
                epoch,
                "token",
                initial_lane(),
                true,
            )
            .is_err());
            drop(armed);
            with_authority_txn(|| {
                set_phase_locked(&manifest.instance.id, epoch, MoveAuthorityPhase::Committing)
            })
            .unwrap();
            let durable = load_authority(&manifest.instance.id, epoch)
                .unwrap()
                .unwrap();
            assert_eq!(durable.phase, MoveAuthorityPhase::Committing);
            assert_eq!(durable.disk_eof, expected_eof);
        }

        // Lost reservation replies at both atomic-file boundaries replay the
        // durable winner. Rename failure leaves Prepared and retries the CAS;
        // SyncDir may report failure after Reserved became visible, and the
        // retry returns that exact id/epoch/token winner.
        for (index, point, expected_after_fault) in [
            (0, Point::Rename, MoveAuthorityPhase::Prepared),
            (1, Point::SyncDir, MoveAuthorityPhase::Reserved),
        ] {
            let mut manifest = manifest_of(Vec::new());
            manifest.instance.name = format!("reservation-fault-{index}");
            manifest.instance.id = format!("reservation-fault-id-{index}");
            let epoch = 30 + index;
            let mut authority = txn(&manifest, epoch, MoveAuthorityPhase::Prepared);
            authority.live = true;
            save_authority(&authority).unwrap();
            let armed = faults::arm_once(
                if index == 0 {
                    "reservation-rename"
                } else {
                    "reservation-sync"
                },
                point,
                if index == 0 {
                    authority_key(&manifest.instance.id, epoch)
                } else {
                    paths::home_dir().join(AUTHORITY_DIR).display().to_string()
                },
                io::ErrorKind::Other,
            );
            assert!(matches!(
                with_authority_txn(|| reserve_target(
                    &reg,
                    &manifest.instance.id,
                    &manifest.instance.name,
                    epoch,
                    "token"
                )),
                Response::Error { .. }
            ));
            drop(armed);
            assert_eq!(
                load_authority(&manifest.instance.id, epoch)
                    .unwrap()
                    .unwrap()
                    .phase,
                expected_after_fault
            );
            assert!(matches!(
                with_authority_txn(|| reserve_target(
                    &reg,
                    &manifest.instance.id,
                    &manifest.instance.name,
                    epoch,
                    "token"
                )),
                Response::MoveAuthority {
                    phase: MoveAuthorityPhase::Reserved,
                    ..
                }
            ));
        }

        for (index, point, expected_after_fault) in [
            (0, Point::Rename, MoveAuthorityPhase::Prepared),
            (1, Point::SyncDir, MoveAuthorityPhase::Aborted),
        ] {
            let mut manifest = manifest_of(Vec::new());
            manifest.instance.name = format!("abort-fault-{index}");
            manifest.instance.id = format!("abort-fault-id-{index}");
            let epoch = 32 + index;
            let mut authority = txn(&manifest, epoch, MoveAuthorityPhase::Prepared);
            authority.live = true;
            save_authority(&authority).unwrap();
            let armed = faults::arm_once(
                if index == 0 {
                    "abort-rename"
                } else {
                    "abort-sync"
                },
                point,
                if index == 0 {
                    authority_key(&manifest.instance.id, epoch)
                } else {
                    paths::home_dir().join(AUTHORITY_DIR).display().to_string()
                },
                io::ErrorKind::Other,
            );
            assert!(matches!(
                with_authority_txn(|| choose_target_abort_after_fenced(
                    &reg,
                    &manifest.instance.id,
                    &manifest.instance.name,
                    epoch,
                    "token",
                )),
                Response::Error { .. }
            ));
            drop(armed);
            assert_eq!(
                load_authority(&manifest.instance.id, epoch)
                    .unwrap()
                    .unwrap()
                    .phase,
                expected_after_fault
            );
            assert!(matches!(
                with_authority_txn(|| choose_target_abort_after_fenced(
                    &reg,
                    &manifest.instance.id,
                    &manifest.instance.name,
                    epoch,
                    "token",
                )),
                Response::MoveAuthority {
                    phase: MoveAuthorityPhase::Aborted,
                    ..
                }
            ));
        }

        // Replacement-lane allocation is a durable CAS against the lane the
        // source last recorded. A rename failure retries the allocation;
        // SyncDir reply loss finishes the already-allocated generation; and
        // a replay after lane publication never allocates lane three.
        for (index, point, expected_lane_after_fault) in
            [(0, Point::Rename, 1), (1, Point::SyncDir, 2)]
        {
            let mut manifest = manifest_of(Vec::new());
            manifest.instance.name = format!("lane-fault-{index}");
            manifest.instance.id = format!("lane-fault-id-{index}");
            let epoch = 35 + index;
            let mut authority = txn(&manifest, epoch, MoveAuthorityPhase::Reserved);
            authority.live = true;
            save_authority(&authority).unwrap();
            let armed = faults::arm_once(
                if index == 0 {
                    "lane-rename"
                } else {
                    "lane-sync"
                },
                point,
                if index == 0 {
                    authority_key(&manifest.instance.id, epoch)
                } else {
                    paths::home_dir().join(AUTHORITY_DIR).display().to_string()
                },
                io::ErrorKind::Other,
            );
            let mut attempted = authority.clone();
            assert!(select_recovery_lane(&mut attempted, initial_lane()).is_err());
            drop(armed);
            let mut durable = load_authority(&manifest.instance.id, epoch)
                .unwrap()
                .unwrap();
            assert_eq!(durable.lane, expected_lane_after_fault);
            assert_eq!(
                select_recovery_lane(&mut durable, initial_lane()).unwrap(),
                RecoveryLane::Rebuild
            );
            assert_eq!(durable.lane, 2);
            assert!(!durable.lane_ready);

            durable.lane_ready = true;
            save_authority(&durable).unwrap();
            let mut lost_reply = load_authority(&manifest.instance.id, epoch)
                .unwrap()
                .unwrap();
            assert_eq!(
                select_recovery_lane(&mut lost_reply, initial_lane()).unwrap(),
                RecoveryLane::Replay
            );
            assert_eq!(lost_reply.lane, 2);
        }

        // The source records the replacement generation before bulk opens.
        // Its in-memory row is reconciled from disk at both atomic-save fault
        // boundaries, so retry uses exactly the durability result a restart
        // would observe and a stale reply cannot move the lane backward.
        for (index, point, expected_lane_after_fault) in
            [(0, Point::Rename, 1), (1, Point::SyncDir, 2)]
        {
            let mut source = manifest_of(Vec::new()).instance;
            source.name = format!("source-lane-fault-{index}");
            source.id = format!("source-lane-fault-id-{index}");
            let mut moving = Moving {
                to_device: "desktop".into(),
                to_device_id: "target-id".into(),
                epoch: 38 + index,
                started_at: now_unix(),
                token: format!("source-lane-token-{index}"),
                lane: initial_lane(),
                coordinator_id: "coordinator-id".into(),
                phase: MoveSourcePhase::Committed,
                live: true,
            };
            source.moving = Some(moving.clone());
            let move_epoch = moving.epoch;
            let move_token = moving.token.clone();
            reg.adopt(source.clone()).unwrap();
            reg.save().unwrap();
            let armed = faults::arm_once(
                if index == 0 {
                    "source-lane-rename"
                } else {
                    "source-lane-sync"
                },
                point,
                if index == 0 {
                    state.display().to_string()
                } else {
                    home.path().display().to_string()
                },
                io::ErrorKind::Other,
            );
            assert!(persist_source_lane(
                &mut reg,
                &source.id,
                &source.name,
                move_epoch,
                &move_token,
                2,
                &mut moving,
            )
            .is_err());
            drop(armed);
            assert_eq!(moving.lane, expected_lane_after_fault);
            assert_eq!(
                reg.get(&source.name).unwrap().moving.as_ref().unwrap().lane,
                expected_lane_after_fault
            );
            persist_source_lane(
                &mut reg,
                &source.id,
                &source.name,
                move_epoch,
                &move_token,
                2,
                &mut moving,
            )
            .unwrap();
            assert_eq!(moving.lane, 2);
            assert!(persist_source_lane(
                &mut reg,
                &source.id,
                &source.name,
                move_epoch,
                &move_token,
                1,
                &mut moving,
            )
            .is_err());
        }

        // Source completion is a permanent WAL, not the 24-hour moved-note
        // cache. Faults before its rename leave the row; faults after the WAL
        // but before row publication replay deletion, and an absent row with
        // leftover bytes is still cleanable indefinitely.
        reg = Shard::load(&state).unwrap();
        let mut source = manifest_of(Vec::new()).instance;
        source.name = "source-completion-rename".into();
        source.id = "source-completion-rename-id".into();
        source.moving = Some(Moving {
            to_device: "desktop".into(),
            to_device_id: "target-id".into(),
            epoch: 40,
            started_at: now_unix(),
            token: "completion-token".into(),
            lane: 0,
            coordinator_id: "coordinator-id".into(),
            phase: MoveSourcePhase::Fenced,
            live: false,
        });
        reg.adopt(source.clone()).unwrap();
        reg.save().unwrap();
        let armed = faults::arm_once(
            "source-completion-rename",
            Point::Rename,
            source_completion_path(&source.id, 40, "completion-token")
                .display()
                .to_string(),
            io::ErrorKind::Other,
        );
        assert!(matches!(
            commit_source_after_proof(&mut reg, &source.id, &source.name, 40, "completion-token"),
            Response::Error { .. }
        ));
        drop(armed);
        assert!(reg.get(&source.name).is_ok());
        assert!(matches!(
            commit_source_after_proof(&mut reg, &source.id, &source.name, 40, "completion-token"),
            Response::Ok
        ));

        // Once the completion WAL exists, row-removal faults reconcile the
        // live registry from disk before returning. Rename failure retains
        // the row; SyncDir reply loss observes it absent. Either retry then
        // removes the row and bytes without relying on the courtesy note.
        for (index, point, row_after_fault) in
            [(0, Point::Rename, true), (1, Point::SyncDir, false)]
        {
            let mut source = manifest_of(Vec::new()).instance;
            source.name = format!("source-row-fault-{index}");
            source.id = format!("source-row-fault-id-{index}");
            let epoch = 42 + index;
            let token = format!("source-row-token-{index}");
            source.moving = Some(Moving {
                to_device: "desktop".into(),
                to_device_id: "target-id".into(),
                epoch,
                started_at: now_unix(),
                token: token.clone(),
                lane: 0,
                coordinator_id: "coordinator-id".into(),
                phase: MoveSourcePhase::Fenced,
                live: false,
            });
            reg.adopt(source.clone()).unwrap();
            reg.save().unwrap();
            let source_dir = paths::instance_dir(&source.name);
            std::fs::create_dir_all(&source_dir).unwrap();
            std::fs::write(source_dir.join("disk.raw"), b"source bytes").unwrap();
            save_source_completion(&SourceCompletion {
                version: 1,
                instance_id: source.id.clone(),
                name: source.name.clone(),
                to_device: "desktop".into(),
                epoch,
                token: token.clone(),
            })
            .unwrap();
            let armed = faults::arm_once(
                if index == 0 {
                    "source-row-rename"
                } else {
                    "source-row-sync"
                },
                point,
                if index == 0 {
                    state.display().to_string()
                } else {
                    home.path().display().to_string()
                },
                io::ErrorKind::Other,
            );
            assert!(matches!(
                commit_source_after_proof(&mut reg, &source.id, &source.name, epoch, &token,),
                Response::Error { .. }
            ));
            drop(armed);
            assert_eq!(reg.get(&source.name).is_ok(), row_after_fault);
            assert!(
                load_source_completion(&source.id, &source.name, epoch, &token)
                    .unwrap()
                    .is_some()
            );
            assert!(matches!(
                commit_source_after_proof(&mut reg, &source.id, &source.name, epoch, &token,),
                Response::Ok
            ));
            assert!(reg.get(&source.name).is_err());
            assert!(!source_dir.exists());
        }

        // An abort consumes its epoch on the source. A retry therefore gets
        // a distinct authority key and fresh token; stale frames keep
        // replaying the old Aborted winner without poisoning the new attempt.
        let mut retry_source = manifest_of(Vec::new()).instance;
        retry_source.name = "abort-retry".into();
        retry_source.id = "abort-retry-id".into();
        retry_source.moving = Some(Moving {
            to_device: "desktop".into(),
            to_device_id: "target-id".into(),
            epoch: 50,
            started_at: now_unix(),
            token: "old-token".into(),
            lane: initial_lane(),
            coordinator_id: "coordinator-id".into(),
            phase: MoveSourcePhase::Fenced,
            live: true,
        });
        reg.adopt(retry_source.clone()).unwrap();
        persist_source_abort(&mut reg, &retry_source.name, 50).unwrap();
        persist_source_abort(&mut reg, &retry_source.name, 50).unwrap();
        assert_eq!(reg.get(&retry_source.name).unwrap().move_epoch, 50);
        let mut next = reg.get(&retry_source.name).unwrap().clone();
        next.moving = Some(Moving {
            to_device: "desktop".into(),
            to_device_id: "target-id".into(),
            epoch: 51,
            started_at: now_unix(),
            token: "new-token".into(),
            lane: initial_lane(),
            coordinator_id: "coordinator-id".into(),
            phase: MoveSourcePhase::Fenced,
            live: true,
        });
        reg.set_moving(&next.name, next.moving.clone()).unwrap();
        reg.save().unwrap();
        let mut old_manifest = manifest_of(Vec::new());
        old_manifest.instance.name = retry_source.name.clone();
        old_manifest.instance.id = retry_source.id.clone();
        let mut old = txn(&old_manifest, 50, MoveAuthorityPhase::Aborted);
        old.live = true;
        old.token = "old-token".into();
        save_authority(&old).unwrap();
        let mut new = txn(&old_manifest, 51, MoveAuthorityPhase::Prepared);
        new.live = true;
        new.token = "new-token".into();
        save_authority(&new).unwrap();
        assert!(matches!(
            with_authority_txn(|| reserve_target(
                &reg,
                &retry_source.id,
                &retry_source.name,
                51,
                "new-token"
            )),
            Response::MoveAuthority {
                phase: MoveAuthorityPhase::Reserved,
                ..
            }
        ));
        assert!(matches!(
            with_authority_txn(|| reserve_target(
                &reg,
                &retry_source.id,
                &retry_source.name,
                50,
                "old-token"
            )),
            Response::MoveAuthority {
                phase: MoveAuthorityPhase::Aborted,
                ..
            }
        ));

        for (index, point, moving_after_fault) in
            [(0, Point::Rename, true), (1, Point::SyncDir, false)]
        {
            let mut source = manifest_of(Vec::new()).instance;
            source.name = format!("source-abort-fault-{index}");
            source.id = format!("source-abort-fault-id-{index}");
            let epoch = 52 + index;
            source.moving = Some(Moving {
                to_device: "desktop".into(),
                to_device_id: "target-id".into(),
                epoch,
                started_at: now_unix(),
                token: format!("source-abort-token-{index}"),
                lane: initial_lane(),
                coordinator_id: "coordinator-id".into(),
                phase: MoveSourcePhase::Fenced,
                live: true,
            });
            reg.adopt(source.clone()).unwrap();
            reg.save().unwrap();
            let armed = faults::arm_once(
                if index == 0 {
                    "source-abort-rename"
                } else {
                    "source-abort-sync"
                },
                point,
                if index == 0 {
                    state.display().to_string()
                } else {
                    home.path().display().to_string()
                },
                io::ErrorKind::Other,
            );
            assert!(persist_source_abort(&mut reg, &source.name, epoch).is_err());
            drop(armed);
            let durable = reg.get(&source.name).unwrap();
            assert_eq!(durable.moving.is_some(), moving_after_fault);
            assert_eq!(
                durable.move_epoch,
                if moving_after_fault { 0 } else { epoch }
            );
            persist_source_abort(&mut reg, &source.name, epoch).unwrap();
            assert!(reg.get(&source.name).unwrap().moving.is_none());
            assert_eq!(reg.get(&source.name).unwrap().move_epoch, epoch);
        }

        // A name/epoch has one target transaction even when a stale frame
        // changes the instance id (and therefore the authority filename).
        // The staged receipt independently binds id/epoch/token, so neither
        // commit nor the legacy no-WAL abort path can mutate another attempt.
        let mut stale_manifest = manifest_of(Vec::new());
        stale_manifest.instance.name = "stale-frame-matrix".into();
        stale_manifest.instance.id = "stale-frame-winner-id".into();
        let stale_epoch = 60;
        staged(&stale_manifest, stale_epoch);
        let mut stale_authority = txn(&stale_manifest, stale_epoch, MoveAuthorityPhase::Reserved);
        stale_authority.live = true;
        save_authority(&stale_authority).unwrap();
        assert_eq!(
            load_authority_for_name_epoch(&stale_manifest.instance.name, stale_epoch)
                .unwrap()
                .unwrap()
                .instance_id,
            stale_manifest.instance.id
        );
        let mut wrong_manifest = stale_manifest.clone();
        wrong_manifest.instance.id = "stale-frame-wrong-id".into();
        assert!(matches!(
            commit_target(&mut reg, &wrong_manifest, stale_epoch, "token", "desktop",),
            Response::Error { .. }
        ));
        assert!(staging_dir(
            &stale_manifest.instance.name,
            &stale_manifest.instance.id,
            stale_epoch,
            "token"
        )
        .exists());
        assert!(matches!(
            abort_target(
                &mut reg,
                &wrong_manifest.instance.id,
                &stale_manifest.instance.name,
                stale_epoch,
                "token",
            ),
            Response::Error { .. }
        ));
        assert!(matches!(
            abort_target(
                &mut reg,
                &stale_manifest.instance.id,
                &stale_manifest.instance.name,
                stale_epoch,
                "wrong-token",
            ),
            Response::Error { .. }
        ));
        assert!(staging_dir(
            &stale_manifest.instance.name,
            &stale_manifest.instance.id,
            stale_epoch,
            "token"
        )
        .exists());

        let mut offline_stale = manifest_of(Vec::new());
        offline_stale.instance.name = "offline-stale-abort".into();
        offline_stale.instance.id = "offline-stale-abort-id".into();
        let offline_stale_epoch = 61;
        staged(&offline_stale, offline_stale_epoch);
        assert!(matches!(
            abort_target(
                &mut reg,
                &offline_stale.instance.id,
                &offline_stale.instance.name,
                offline_stale_epoch,
                "wrong-token",
            ),
            Response::Error { .. }
        ));
        assert!(staging_dir(
            &offline_stale.instance.name,
            &offline_stale.instance.id,
            offline_stale_epoch,
            "token"
        )
        .exists());
        assert!(matches!(
            abort_target(
                &mut reg,
                &offline_stale.instance.id,
                &offline_stale.instance.name,
                offline_stale_epoch,
                "token",
            ),
            Response::Ok
        ));
        assert!(!staging_dir(
            &offline_stale.instance.name,
            &offline_stale.instance.id,
            offline_stale_epoch,
            "token"
        )
        .exists());

        // Every target-side RPC and both live bulk splice authorizers reject
        // stale identity components before process or filesystem mutation.
        let id = &stale_manifest.instance.id;
        let name = &stale_manifest.instance.name;
        for response in [
            prepare_disk_target("wrong-id", name, stale_epoch, "token"),
            prepare_disk_target(id, "wrong-name", stale_epoch, "token"),
            prepare_disk_target(id, name, stale_epoch + 1, "token"),
            prepare_disk_target(id, name, stale_epoch, "wrong-token"),
            disk_ready_target("wrong-id", name, stale_epoch, "token"),
            disk_ready_target(id, "wrong-name", stale_epoch, "token"),
            disk_ready_target(id, name, stale_epoch + 1, "token"),
            disk_ready_target(id, name, stale_epoch, "wrong-token"),
            reserve_target(&reg, "wrong-id", name, stale_epoch, "token"),
            reserve_target(&reg, id, "wrong-name", stale_epoch, "token"),
            reserve_target(&reg, id, name, stale_epoch + 1, "token"),
            reserve_target(&reg, id, name, stale_epoch, "wrong-token"),
            recover_target(&reg, "wrong-id", name, stale_epoch, "token", 1),
            recover_target(&reg, id, "wrong-name", stale_epoch, "token", 1),
            recover_target(&reg, id, name, stale_epoch + 1, "token", 1),
            recover_target(&reg, id, name, stale_epoch, "wrong-token", 1),
            target_status(&mut reg, "wrong-id", name, stale_epoch, "token", "desktop"),
            target_status(&mut reg, id, "wrong-name", stale_epoch, "token", "desktop"),
            target_status(&mut reg, id, name, stale_epoch + 1, "token", "desktop"),
            target_status(&mut reg, id, name, stale_epoch, "wrong-token", "desktop"),
        ] {
            assert!(matches!(response, Response::Error { .. }), "{response:?}");
        }
        for result in [
            authorize_live_splice(
                "wrong-id",
                name,
                stale_epoch,
                "laptop",
                "source-id",
                "token",
                initial_lane(),
            ),
            authorize_live_splice(
                id,
                "wrong-name",
                stale_epoch,
                "laptop",
                "source-id",
                "token",
                initial_lane(),
            ),
            authorize_live_splice(
                id,
                name,
                stale_epoch + 1,
                "laptop",
                "source-id",
                "token",
                initial_lane(),
            ),
            authorize_live_splice(
                id,
                name,
                stale_epoch,
                "wrong-device",
                "source-id",
                "token",
                initial_lane(),
            ),
            authorize_live_splice(
                id,
                name,
                stale_epoch,
                "laptop",
                "wrong-device-id",
                "token",
                initial_lane(),
            ),
            authorize_live_splice(
                id,
                name,
                stale_epoch,
                "laptop",
                "source-id",
                "wrong-token",
                initial_lane(),
            ),
            authorize_live_splice(
                id,
                name,
                stale_epoch,
                "laptop",
                "source-id",
                "token",
                initial_lane() + 1,
            ),
            authorize_disk_splice(
                "wrong-id",
                name,
                stale_epoch,
                "token",
                "laptop",
                "source-id",
                initial_lane(),
            )
            .map(|_| ()),
            authorize_disk_splice(
                id,
                "wrong-name",
                stale_epoch,
                "token",
                "laptop",
                "source-id",
                initial_lane(),
            )
            .map(|_| ()),
            authorize_disk_splice(
                id,
                name,
                stale_epoch + 1,
                "token",
                "laptop",
                "source-id",
                initial_lane(),
            )
            .map(|_| ()),
            authorize_disk_splice(
                id,
                name,
                stale_epoch,
                "wrong-token",
                "laptop",
                "source-id",
                initial_lane(),
            )
            .map(|_| ()),
            authorize_disk_splice(
                id,
                name,
                stale_epoch,
                "token",
                "wrong-device",
                "source-id",
                initial_lane(),
            )
            .map(|_| ()),
            authorize_disk_splice(
                id,
                name,
                stale_epoch,
                "token",
                "laptop",
                "wrong-device-id",
                initial_lane(),
            )
            .map(|_| ()),
            authorize_disk_splice(
                id,
                name,
                stale_epoch,
                "token",
                "laptop",
                "source-id",
                initial_lane() + 1,
            )
            .map(|_| ()),
        ] {
            assert!(result.is_err());
        }
        assert!(authorize_live_splice(
            id,
            name,
            stale_epoch,
            "laptop",
            "source-id",
            "token",
            initial_lane(),
        )
        .is_ok());
        let correct_disk = authorize_disk_splice(
            id,
            name,
            stale_epoch,
            "token",
            "laptop",
            "source-id",
            initial_lane(),
        )
        .unwrap_err()
        .to_string();
        assert!(correct_disk.contains("absent or dead"), "{correct_disk}");

        let mut import_manifest = manifest_of(Vec::new());
        import_manifest.instance.name = "live-import-fence".into();
        import_manifest.instance.id = "live-import-fence-id".into();
        let import_epoch = 62;
        let mut import_authority = txn(&import_manifest, import_epoch, MoveAuthorityPhase::Intent);
        import_authority.live = true;
        save_authority(&import_authority).unwrap();
        assert!(authorize_live_import(
            &import_manifest,
            import_epoch,
            "token",
            "laptop",
            "source-id",
        )
        .is_ok());
        let mut wrong_import = import_manifest.clone();
        wrong_import.instance.id = "wrong-import-id".into();
        for result in [
            authorize_live_import(&wrong_import, import_epoch, "token", "laptop", "source-id"),
            authorize_live_import(
                &import_manifest,
                import_epoch + 1,
                "token",
                "laptop",
                "source-id",
            ),
            authorize_live_import(
                &import_manifest,
                import_epoch,
                "wrong-token",
                "laptop",
                "source-id",
            ),
            authorize_live_import(
                &import_manifest,
                import_epoch,
                "token",
                "wrong-source",
                "source-id",
            ),
            authorize_live_import(
                &import_manifest,
                import_epoch,
                "token",
                "laptop",
                "wrong-source-id",
            ),
        ] {
            assert!(result.is_err());
        }
        let import_staging = staging_dir(
            &import_manifest.instance.name,
            &import_manifest.instance.id,
            import_epoch,
            "token",
        );
        std::fs::create_dir_all(&import_staging).unwrap();
        let import_receipt = Receipt {
            instance_id: import_manifest.instance.id.clone(),
            epoch: import_epoch,
            token: "token".into(),
            from_device: "laptop".into(),
            bytes: 0,
            files: BTreeMap::new(),
        };
        save_live_import_receipt(
            &import_manifest,
            import_epoch,
            "token",
            "laptop",
            "source-id",
            &import_receipt,
        )
        .unwrap();
        std::fs::remove_file(Receipt::path(&import_staging)).unwrap();
        import_authority.phase = MoveAuthorityPhase::Aborted;
        save_authority(&import_authority).unwrap();
        assert!(save_live_import_receipt(
            &import_manifest,
            import_epoch,
            "token",
            "laptop",
            "source-id",
            &import_receipt,
        )
        .is_err());
        assert!(!Receipt::path(&import_staging).exists());
        assert!(reg.get(&source.name).is_err());
        assert!(
            load_source_completion(&source.id, &source.name, 40, "completion-token")
                .unwrap()
                .is_some()
        );

        let stranded = SourceCompletion {
            version: 1,
            instance_id: "stranded-source-id".into(),
            name: "stranded-source".into(),
            to_device: "desktop".into(),
            epoch: 41,
            token: "stranded-token".into(),
        };
        save_source_completion(&stranded).unwrap();
        let stranded_dir = paths::instance_dir(&stranded.name);
        std::fs::create_dir_all(&stranded_dir).unwrap();
        std::fs::write(stranded_dir.join("disk.raw"), b"left after row save").unwrap();
        assert!(matches!(
            commit_source_after_proof(
                &mut reg,
                &stranded.instance_id,
                &stranded.name,
                stranded.epoch,
                &stranded.token
            ),
            Response::Ok
        ));
        assert!(!stranded_dir.exists());
        let _ = std::fs::remove_file(notes_path());
        assert!(matches!(
            commit_source_after_proof(
                &mut reg,
                &stranded.instance_id,
                &stranded.name,
                stranded.epoch,
                &stranded.token
            ),
            Response::Ok
        ));

        // Failure after the directory rename but before the registry row:
        // the immutable marker turns the published tree back into a row.
        let first = manifest_of(Vec::new());
        let first_epoch = 1;
        staged(&first, first_epoch);
        save_authority(&txn(&first, first_epoch, MoveAuthorityPhase::Prepared)).unwrap();
        let state_filter = state.display().to_string();
        let armed = faults::arm_once(
            "move-row-after-publish",
            Point::Rename,
            state_filter,
            io::ErrorKind::Other,
        );
        let failed = commit_target(&mut reg, &first, first_epoch, "token", "desktop");
        assert!(matches!(failed, Response::Error { .. }), "{failed:?}");
        drop(armed);
        assert!(paths::instance_dir("dev").is_dir());
        assert!(published_for(
            &load_authority(&first.instance.id, first_epoch)
                .unwrap()
                .unwrap()
        ));

        let mut restarted = Shard::load(&state).unwrap();
        assert!(restarted.get("dev").is_err(), "the row save was injected");
        let recovered = target_status(
            &mut restarted,
            &first.instance.id,
            "dev",
            first_epoch,
            "token",
            "desktop",
        );
        assert!(matches!(
            recovered,
            Response::MoveAuthority {
                phase: MoveAuthorityPhase::Committed,
                ..
            }
        ));
        assert_eq!(restarted.get("dev").unwrap().move_epoch, first_epoch);
        assert!(
            !paths::instance_dir("dev").join(LIVE_AUTHORITY).exists(),
            "the committed WAL supersedes the in-tree recovery marker"
        );
        assert!(matches!(
            commit_target(&mut restarted, &first, first_epoch, "token", "desktop"),
            Response::Instance { .. }
        ));

        // Failure after the row save but before the WAL says Committed: a
        // query replays Committing and the conditional abort cannot win.
        let mut second = manifest_of(Vec::new());
        second.instance.name = "dev-two".into();
        second.instance.id = "instance-two".into();
        let second_epoch = 4;
        staged(&second, second_epoch);
        let mut second_txn = txn(&second, second_epoch, MoveAuthorityPhase::Committing);
        save_authority(&second_txn).unwrap();
        let wal_filter = authority_key(&second.instance.id, second_epoch);
        let armed = faults::arm_once(
            "move-wal-after-row",
            Point::Rename,
            wal_filter,
            io::ErrorKind::Other,
        );
        assert!(finish_target_commit(&mut restarted, &mut second_txn, "desktop").is_err());
        drop(armed);
        let mut restarted = Shard::load(&state).unwrap();
        assert_eq!(restarted.get("dev-two").unwrap().move_epoch, second_epoch);
        assert_eq!(
            load_authority(&second.instance.id, second_epoch)
                .unwrap()
                .unwrap()
                .phase,
            MoveAuthorityPhase::Committing
        );
        assert!(matches!(
            abort_target(
                &mut restarted,
                &second.instance.id,
                "dev-two",
                second_epoch,
                "token"
            ),
            Response::MoveAuthority {
                phase: MoveAuthorityPhase::Committing,
                ..
            }
        ));
        assert!(matches!(
            target_status(
                &mut restarted,
                &second.instance.id,
                "dev-two",
                second_epoch,
                "token",
                "desktop"
            ),
            Response::MoveAuthority {
                phase: MoveAuthorityPhase::Committed,
                ..
            }
        ));

        // Before publication, abort is durable and replayable. A directory
        // with the same human name but no matching id/epoch marker does not
        // impersonate this transaction.
        let mut third = manifest_of(Vec::new());
        third.instance.name = "claimed-name".into();
        third.instance.id = "instance-three".into();
        let third_epoch = 2;
        staged(&third, third_epoch);
        let mut third_txn = txn(&third, third_epoch, MoveAuthorityPhase::Prepared);
        third_txn.live = true;
        save_authority(&third_txn).unwrap();
        std::fs::create_dir_all(paths::instance_dir("claimed-name")).unwrap();
        assert!(authorize_live_splice(
            &third.instance.id,
            "claimed-name",
            third_epoch,
            "laptop",
            "source-id",
            "token",
            initial_lane()
        )
        .is_ok());
        assert!(authorize_live_splice(
            &third.instance.id,
            "claimed-name",
            third_epoch,
            "laptop",
            "impostor-id",
            "token",
            initial_lane()
        )
        .is_err());
        let mut mismatched = third.clone();
        mismatched.instance.name = "other-name".into();
        assert!(validate_target_replay(
            &third_txn,
            &mismatched,
            third_epoch,
            "laptop",
            "source-id",
            "token",
            None,
        )
        .is_err());
        assert!(validate_target_replay(
            &third_txn,
            &third,
            third_epoch,
            "laptop",
            "source-id",
            "token",
            Some("wrong-coordinator-id"),
        )
        .is_err());
        // Live splice checks above need a live WAL. abort_target's live arm
        // requires a mesh source proof, which this test does not start.
        third_txn.live = false;
        save_authority(&third_txn).unwrap();
        assert!(matches!(
            abort_target(
                &mut restarted,
                &third.instance.id,
                "claimed-name",
                third_epoch,
                "token"
            ),
            Response::MoveAuthority {
                phase: MoveAuthorityPhase::Aborted,
                ..
            }
        ));
        assert!(!staging_dir("claimed-name", &third.instance.id, third_epoch, "token").exists());
        assert!(
            paths::instance_dir("claimed-name").is_dir(),
            "conditional abort must not remove an unrelated live tree"
        );
        assert!(matches!(
            abort_target(
                &mut restarted,
                &third.instance.id,
                "claimed-name",
                third_epoch,
                "token"
            ),
            Response::MoveAuthority {
                phase: MoveAuthorityPhase::Aborted,
                ..
            }
        ));
        assert_ne!(
            authority_path(&third.instance.id, third_epoch),
            authority_path(&third.instance.id, third_epoch + 1),
            "authority is keyed by immutable id and epoch"
        );

        // A matching higher-epoch row is not sufficient completion proof for
        // a live move. Under either restart policy, a dead handle keeps the
        // WAL at Committing and source deletion remains forbidden.
        for (index, restart) in [
            (0, asterism_core::instance::Restart::Always),
            (1, asterism_core::instance::Restart::Never),
        ] {
            let mut manifest = manifest_of(Vec::new());
            manifest.instance.name = format!("dead-committing-{index}");
            manifest.instance.id = format!("dead-committing-id-{index}");
            manifest.instance.status = Status::Running;
            manifest.instance.policy.restart = restart;
            let epoch = 70 + index;
            staged(&manifest, epoch);
            let dead_handle = Handle {
                backend: "qemu".into(),
                pid: None,
                proc: None,
                ctl: ControlChannel::Qmp {
                    path: home.path().join(format!("dead-qmp-{index}.sock")),
                },
                endpoint: asterism_core::hv::GuestEndpoint::HostForward { ssh_port: 0 },
                started_at: now_unix(),
            };
            let mut authority = txn(&manifest, epoch, MoveAuthorityPhase::Committing);
            authority.live = true;
            authority.handle = Some(dead_handle.clone());
            save_authority(&authority).unwrap();
            let staging = staging_dir(
                &manifest.instance.name,
                &manifest.instance.id,
                epoch,
                "token",
            );
            save_authority_marker(&staging, &authority).unwrap();
            durable::publish_dir(&staging, &paths::instance_dir(&manifest.instance.name)).unwrap();
            let mut row = manifest.instance.clone();
            row.cpu_device = "desktop".into();
            row.handle = Some(dead_handle);
            row.move_epoch = epoch;
            restarted.adopt(row).unwrap();
            restarted.save().unwrap();
            assert!(matches!(
                target_status(
                    &mut restarted,
                    &manifest.instance.id,
                    &manifest.instance.name,
                    epoch,
                    "token",
                    "desktop",
                ),
                Response::Error { .. }
            ));
            assert_eq!(
                load_authority(&manifest.instance.id, epoch)
                    .unwrap()
                    .unwrap()
                    .phase,
                MoveAuthorityPhase::Committing
            );
        }

        // An offline or protocol-5 abort has no authority WAL. Its old
        // name/epoch staging spelling is usable only when the receipt binds
        // it to this exact id and token: never let a same-name/epoch tree
        // donate a handle, socket, or recursive delete to a replacement.
        let legacy_epoch = 9;
        let legacy = legacy_staging_dir("legacy", legacy_epoch);
        std::fs::create_dir_all(&legacy).unwrap();
        let foreign_handle = legacy.join(LIVE_HANDLE);
        std::fs::write(&foreign_handle, b"foreign handle must survive").unwrap();
        std::fs::write(Receipt::path(&legacy), b"not-json").unwrap();
        assert!(recoverable_staging_dir("legacy", "replacement", legacy_epoch, "token").is_err());
        assert!(matches!(
            abort_target(
                &mut restarted,
                "replacement",
                "legacy",
                legacy_epoch,
                "token"
            ),
            Response::Error { .. }
        ));
        sweep_staging();
        assert!(
            foreign_handle.exists(),
            "corrupt legacy receipt must retain its handle"
        );

        Receipt {
            instance_id: "foreign".into(),
            epoch: legacy_epoch,
            token: "foreign-token".into(),
            from_device: "laptop".into(),
            bytes: 0,
            files: BTreeMap::new(),
        }
        .save(&legacy)
        .unwrap();
        assert!(recoverable_staging_dir("legacy", "replacement", legacy_epoch, "token").is_err());
        assert!(matches!(
            abort_target(
                &mut restarted,
                "replacement",
                "legacy",
                legacy_epoch,
                "token"
            ),
            Response::Error { .. }
        ));
        assert!(
            foreign_handle.exists(),
            "foreign legacy tree must not be aborted"
        );
        sweep_staging();
        assert!(
            foreign_handle.exists(),
            "foreign legacy tree must not be swept"
        );

        Receipt {
            instance_id: "replacement".into(),
            epoch: legacy_epoch,
            token: "token".into(),
            from_device: "laptop".into(),
            bytes: 0,
            files: BTreeMap::new(),
        }
        .save(&legacy)
        .unwrap();
        assert_eq!(
            recoverable_staging_dir("legacy", "replacement", legacy_epoch, "token").unwrap(),
            legacy
        );
        assert!(matches!(
            abort_target(
                &mut restarted,
                "replacement",
                "legacy",
                legacy_epoch,
                "token"
            ),
            Response::Ok
        ));
        assert!(!legacy.exists());

        // Runtime-shortened QMP sockets do not move with a directory rename;
        // ordinary sockets inside staging do.
        let stage = PathBuf::from("/state/instances/dev.moving-1");
        assert_eq!(
            qmp_path_after_publish(&stage.join("qmp.sock"), &stage, "dev"),
            paths::qmp_socket_path("dev")
        );
        let shortened = PathBuf::from("/runtime/0123456789abcdef.sock");
        assert_eq!(qmp_path_after_publish(&shortened, &stage, "dev"), shortened);
    }
}
