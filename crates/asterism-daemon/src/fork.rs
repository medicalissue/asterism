//! `ast fork`, `ast diff`, `ast pick` — one agent becomes five.
//!
//! # What a fork is
//!
//! A crash-consistent snapshot of a running instance, cloned copy-on-write
//! into N new instances that boot beside it. The same engine
//! [`crate::rewind`] uses to put an instance back onto its own past, pointed
//! sideways: [`crate::rewind::take`] makes the snapshot, and
//! [`asterism_core::rewind::clone_tree`] and `cow::clone_file` make the
//! copies. Five forks of a two-gigabyte agent cost two gigabytes and change.
//!
//! The parent keeps running throughout. Nothing here stops it, because
//! nothing here writes to it — a fork only ever reads.
//!
//! # What a fork is *not*
//!
//! It is not the parent. It gets its own identity and only its own:
//!
//! * **its own name**, and with it its own hostname, its own cloud-init
//!   `instance-id`, and its own MAC — all three are derived from the name, so
//!   a fork that is called something else is something else on the network;
//! * **its own guest-control key**, minted at its first boot because
//!   `agent.key` is deliberately not copied;
//! * **its own uuid**, because a fork goes through
//!   [`asterism_core::instance::Instance::new`] rather than being a cloned
//!   record;
//! * **no published ports.** A host port is one number on one device and two
//!   instances cannot both have it. A fork asks for none, so five forks of a
//!   published instance boot rather than four of them refusing.
//!
//! What it *does* carry is the parent's secret bindings, verbatim — the same
//! authority, the same env name, the same guest handle. The handle is baked
//! into the disk the fork was cloned from, and it is honoured only by that
//! instance's own egress door, so carrying it is what makes the agent inside
//! the fork keep working. Minting a new one would leave the guest holding a
//! stand-in nothing answered. Credential parts (AST-157) ride the same
//! bindings, so they come along for the same reason and by the same line: a
//! forked agent's `gh` still works because its guest still holds the handle
//! its own door still honours.
//!
//! A block volume is not carried: it is single-writer and epoch-fenced, and
//! two instances cannot hold one. Neither is a GPU, for the same reason. Both
//! are said out loud in the report rather than dropped quietly.
//!
//! # Refusals happen before anything moves
//!
//! A parent that does not exist, more forks than somebody meant to ask for, a
//! disk that cannot hold the clones, a name already spoken for: all of them
//! are refused before the snapshot is taken. What is left after that is the
//! clone itself, and a clone that fails takes its own half-made instance
//! directory with it.

use std::path::{Path, PathBuf};
use std::time::Instant;

use anyhow::{anyhow, bail, Context, Result};

use asterism_core::cow;
use asterism_core::fork as model;
use asterism_core::instance::{Instance, RestartReason, Status, Volume, VolumeKind};
use asterism_core::paths;
use asterism_core::protocol::{Request, Response};
use asterism_core::registry::Shard;
use asterism_core::rewind::{self as timeline, Kind, Meta};
use asterism_core::snapshot;

/// Is this one of the frames this module answers?
pub(crate) fn claims(req: &Request) -> bool {
    matches!(
        req,
        Request::Fork { .. } | Request::ForkDiff { .. } | Request::ForkPick { .. }
    )
}

pub(crate) async fn serve(req: Request, reg: &mut Shard, cpu_device: &str) -> Response {
    match req {
        Request::Fork {
            name,
            count,
            each,
            stopped,
            yes,
        } => match fork(reg, &name, count, &each, stopped, yes).await {
            Ok(report) => Response::Forked { report },
            Err(e) => error(e),
        },
        Request::ForkDiff { name, against } => {
            match tokio::task::block_in_place(|| diff(reg, &name, against.as_deref())) {
                Ok(diff) => Response::ForkDiff { diff },
                Err(e) => error(e),
            }
        }
        Request::ForkPick { name, apply } => match pick(reg, &name, apply, cpu_device).await {
            Ok(pick) => Response::Picked { pick },
            Err(e) => error(e),
        },
        other => Response::Error {
            message: format!("{other:?} is not a fork request"),
        },
    }
}

fn error(e: anyhow::Error) -> Response {
    Response::Error {
        message: format!("{e:#}"),
    }
}

// ---- the volume a fork is about --------------------------------------------

/// The volume `ast diff` measures and `ast pick` replaces.
///
/// The instance's `/work` when it has one, because that is what the agent was
/// told its working directory is; otherwise the first local directory volume,
/// which on an instance with exactly one is the same answer by a longer road.
/// A block volume is never it — its bytes are on some device's NBD export and
/// there is nothing here to compare.
fn primary_volume(inst: &Instance) -> Option<(usize, &Volume)> {
    // A cache is never it. Its bytes are rebuildable by definition — that is
    // what declaring one says — and it is shared with the parent rather than
    // copied, so "what this fork changed in it" and "replace the parent's
    // with this one's" are both questions about the same directory.
    let candidate =
        |v: &&Volume| v.kind == VolumeKind::Dir && v.is_local() && !is_shared_on_fork(v);
    inst.volumes
        .iter()
        .enumerate()
        .find(|(_, v)| candidate(v) && v.mount_point.as_deref() == Some(WORK))
        .or_else(|| inst.volumes.iter().enumerate().find(|(_, v)| candidate(v)))
}

/// Does this volume come along by reference rather than by copy?
///
/// The one rule AST-158's lifecycles decide here, and it is the same rule
/// [`asterism_core::volume::captured_by_snapshot`] applies for the same
/// reason: a `cache` holds bytes that can be rebuilt, so three forks should
/// warm one of it rather than three, and nothing will ever want to roll one
/// back. `instance` and `memory` are copied — a fork that shared its parent's
/// `/work` would not be a fork at all, and a shared `memory` would have three
/// agents writing one set of notes.
fn is_shared_on_fork(volume: &Volume) -> bool {
    !asterism_core::volume::captured_by_snapshot(volume.lifecycle())
}

/// The mount point everything in this module reports by.
const WORK: &str = "/work";

/// What `ast create --agent` leaves in an instance's directory to say there
/// is an agent session inside. Written and read by the CLI
/// (`asterism-cli/src/agent.rs`); copied, never interpreted, here.
const AGENT_RECORD: &str = "agent.json";

fn guest_path(volume: &Volume) -> String {
    volume.guest_path()
}

/// Where a fork's copy of its parent's directory volume lives.
///
/// Inside the fork's own instance directory, so `ast rm` takes it with it.
/// A fork is a thing you make three of and keep one of; its working copy
/// belongs to it and not to whatever host directory the parent was pointed
/// at, which is somebody's real checkout.
fn fork_volume_dir(child: &str, index: usize) -> PathBuf {
    paths::instance_dir(child)
        .join("volumes")
        .join(format!("vol{index}"))
}

// ---- forking ---------------------------------------------------------------

async fn fork(
    reg: &mut Shard,
    name: &str,
    count: usize,
    each: &[String],
    stopped: bool,
    yes: bool,
) -> Result<model::Report> {
    let parent = reg.get(name)?.clone();
    let dir = paths::instance_dir(name);

    // ---- everything that can be refused, refused ---------------------------
    if let Some(conflict) = &parent.conflict {
        bail!("{}", asterism_core::registry::conflicted(&parent, conflict));
    }
    if parent.moving.is_some() {
        bail!("{name} is being moved to another device — its bytes are in flight and there is nothing here to clone");
    }
    if let Some(note) = crate::rewind::unsupported(&parent, &dir) {
        bail!(note);
    }
    if model::needs_confirmation(count) && !yes {
        bail!("{}", model::too_many(name, count));
    }
    let notes = model::notes(count, each)?;
    let held: Vec<String> = reg.list().into_iter().map(|inst| inst.name).collect();
    let children = model::allocate(name, count, &held)?;
    for child in &children {
        let leftover = paths::instance_dir(child);
        if leftover.exists() {
            bail!(
                "{} is not in this orbit but {} is still on disk — remove it before forking \
                 {name} onto that name",
                child,
                leftover.display()
            );
        }
    }
    let per_fork = tokio::task::block_in_place(|| footprint(&parent, &dir))?;
    tokio::task::block_in_place(|| headroom(&dir, name, count, per_fork))?;

    // ---- the snapshot every fork is cut from -------------------------------
    let started = Instant::now();
    let before = model::free_bytes(&paths::home_dir());
    let at = asterism_core::instance::now_unix();
    let tag = model::fork_tag(at);
    // Named, so retention never removes the thing `ast diff` measures against
    // and `ast pick` is undone with.
    let meta = tokio::task::block_in_place(|| crate::rewind::take(&parent, &tag, Kind::Named))
        .with_context(|| format!("snapshotting {name} to fork it"))?;

    let mut warnings = Vec::new();
    warn_about_parts(&parent, &mut warnings);
    let mut apparent = tokio::task::block_in_place(|| clone_usage(&dir, &meta));
    let mut made: Vec<String> = Vec::new();
    for (child, note) in children.iter().zip(notes.iter()) {
        let origin = model::Origin {
            parent: name.to_owned(),
            snapshot: tag.clone(),
            at,
            note: note.clone(),
        };
        let built = tokio::task::block_in_place(|| {
            materialize(&parent, &meta, child, origin, &mut warnings)
        });
        match built {
            Ok((inst, bytes)) => {
                apparent = apparent.saturating_add(bytes);
                reg.adopt(inst)?;
                made.push(child.clone());
            }
            Err(error) => {
                // A half-made fork is not a fork. Take its directory with it
                // and refuse, rather than leaving a name in the registry
                // pointing at a disk that is not all there.
                let _ = std::fs::remove_dir_all(paths::instance_dir(child));
                return Err(error).with_context(|| format!("cloning {name} into {child}"));
            }
        }
    }
    reg.save_confirmed()
        .context("saving the registry after forking")?;
    let grew = before
        .zip(model::free_bytes(&paths::home_dir()))
        .map(|(before, after)| before.saturating_sub(after));

    if !stopped {
        for child in &made {
            if let Err(error) = crate::instance::up(reg, child, None, RestartReason::User) {
                warnings.push(format!(
                    "{child} was cloned but did not boot: {error:#} — `ast up {child}` is the retry"
                ));
            }
        }
    }

    Ok(model::Report {
        parent: name.to_owned(),
        children: made,
        snapshot: tag,
        elapsed_ms: started.elapsed().as_millis() as u64,
        apparent_bytes: apparent,
        grew_bytes: grew,
        started: !stopped,
        warnings,
    })
}

/// What one copy of this instance's clonable state occupies today.
fn footprint(parent: &Instance, dir: &Path) -> Result<u64> {
    let disk = timeline::root_disk(dir)?;
    let mut bytes = cow::usage(&disk).unwrap_or(0);
    for volume in &parent.volumes {
        // A shared volume is not copied, so it is not a cost.
        if volume.kind == VolumeKind::Dir && volume.is_local() && !is_shared_on_fork(volume) {
            bytes = bytes.saturating_add(timeline::tree_usage(Path::new(&volume.path)));
        }
    }
    Ok(bytes)
}

/// What the snapshot itself occupies, which is the first of the copies.
fn clone_usage(dir: &Path, meta: &Meta) -> u64 {
    let snapshots = snapshot::dir(dir);
    let mut bytes = 0u64;
    for name in ["raw", "qcow2", "vhdx"] {
        let candidate = snapshots.join(format!("{}.{name}", meta.tag));
        if candidate.is_file() {
            bytes = bytes.saturating_add(cow::usage(&candidate).unwrap_or(0));
        }
    }
    for shot in &meta.volumes {
        if let Some(clone) = &shot.clone_dir {
            bytes = bytes.saturating_add(timeline::tree_usage(&snapshots.join(clone)));
        }
    }
    bytes
}

/// Refuse a fork this disk cannot hold — but only where the disk really has
/// to hold it.
///
/// On a filesystem that shares blocks, five clones of a two-gigabyte disk
/// cost kilobytes, and refusing them because ten gigabytes are not free would
/// be refusing the feature on the machines it works best on. So the estimate
/// is only applied where a probe proves this filesystem copies rather than
/// clones. Where it does clone, the check is a floor: enough room for the
/// divergence the forks are about to write.
fn headroom(dir: &Path, name: &str, count: usize, per_fork: u64) -> Result<()> {
    let Some(free) = model::free_bytes(&paths::home_dir()) else {
        return Ok(()); // said in the report as "cloned" rather than "shared"
    };
    // The snapshot plus one copy per fork.
    let needed = per_fork.saturating_mul(count as u64 + 1);
    if clones_here(dir) {
        const FLOOR: u64 = 512 * 1024 * 1024;
        if free < FLOOR {
            bail!("{}", model::no_headroom(name, count, FLOOR, free));
        }
        return Ok(());
    }
    if free < needed {
        bail!("{}", model::no_headroom(name, count, needed, free));
    }
    Ok(())
}

/// Does this filesystem share blocks between a file and its copy?
///
/// Asked with a three-byte file rather than inferred from the platform,
/// because the answer is a property of the filesystem `$ASTERISM_HOME` is on
/// and not of the operating system: APFS clones and an exFAT stick on the
/// same Mac does not.
fn clones_here(dir: &Path) -> bool {
    let probe = dir.join(".fork-clone-probe");
    let copy = dir.join(".fork-clone-probe.clone");
    let _ = std::fs::remove_file(&probe);
    let _ = std::fs::remove_file(&copy);
    let shared = std::fs::create_dir_all(dir)
        .and_then(|()| std::fs::write(&probe, b"ast"))
        .ok()
        .and_then(|()| cow::clone_file(&probe, &copy).ok())
        .is_some_and(|how| how == cow::Cloned::Shared);
    let _ = std::fs::remove_file(&probe);
    let _ = std::fs::remove_file(&copy);
    shared
}

/// The parts a fork cannot be given, said out loud.
fn warn_about_parts(parent: &Instance, warnings: &mut Vec<String>) {
    if !parent.publish.is_empty() {
        warnings.push(format!(
            "the forks publish no ports: {} host port{} belong{} to {} and cannot be in two \
             places — `ast exec <fork>` and `ast ssh <fork>` reach them",
            parent.publish.len(),
            if parent.publish.len() == 1 { "" } else { "s" },
            if parent.publish.len() == 1 { "s" } else { "" },
            parent.name,
        ));
    }
    for volume in &parent.volumes {
        if volume.kind == VolumeKind::Block {
            warnings.push(format!(
                "the block volume {:?} is not forked: it is single-writer and its lease is \
                 held by {}",
                volume.path, parent.name
            ));
        } else if !volume.is_local() {
            warnings.push(format!(
                "{:?} is not forked: it is a directory on {}, which this device cannot clone",
                volume.path, volume.host
            ));
        } else if is_shared_on_fork(volume) {
            warnings.push(format!(
                "{} is shared with the forks rather than copied: it is a {} volume, so \
                 they warm one of it between them",
                volume.guest_path(),
                volume.lifecycle(),
            ));
        }
    }
    if parent.gpu.is_some() {
        warnings.push(format!(
            "the GPU is not forked: {}'s projection is a lease on a provider and there is \
             one of it",
            parent.name
        ));
    }
}

/// Build one fork's directory and its registry row. Nothing is saved here —
/// the caller adopts and commits, so a failure halfway leaves no row.
fn materialize(
    parent: &Instance,
    meta: &Meta,
    child: &str,
    origin: model::Origin,
    warnings: &mut Vec<String>,
) -> Result<(Instance, u64)> {
    let parent_dir = paths::instance_dir(&parent.name);
    let snapshots = snapshot::dir(&parent_dir);
    let child_dir = paths::instance_dir(child);
    std::fs::create_dir_all(&child_dir)
        .with_context(|| format!("creating {}", child_dir.display()))?;
    let mut apparent = 0u64;

    // ---- the root disk -----------------------------------------------------
    //
    // From the snapshot rather than from the live disk, so every fork of one
    // `ast fork` is the same instant — and so the parent may keep running
    // while this happens.
    let live = timeline::root_disk(&parent_dir)?;
    let source = snapshot::path_for_disk(&parent_dir, &live, &meta.tag)?;
    let extension = live
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("raw")
        .to_owned();
    let target = child_dir.join(format!("disk.{extension}"));
    apparent = apparent.saturating_add(cow::usage(&source).unwrap_or(0));
    let how = cow::clone_file(&source, &target)
        .with_context(|| format!("cloning {}'s root disk", parent.name))?;
    if let Some(said) = how.warning(&source, &target) {
        warnings.push(said);
    }
    // Deliberately not copied: `agent.key`, so the fork mints its own
    // guest-control key at its first boot; `seed.iso`/`seed.stamp`, so the
    // seed is rebuilt under the fork's own name and the guest comes up with
    // its own hostname and cloud-init instance-id; `vz.json`, `console.log`
    // and every other artefact of a running guest, which belong to a guest
    // this fork is not.

    // ---- what makes it an agent --------------------------------------------
    //
    // `agent.json` is what `ast session`, `ast logs` and `ast fork --each`
    // read to know there is a tmux session in there and what it is called. A
    // fork of an agent is an agent — same preset, same workdir, same start
    // command — so it is copied rather than re-derived.
    //
    // The session name inside it is left alone deliberately. It names a tmux
    // session inside the guest, and the guest's own entrypoint starts that
    // session under the name it was created with; renaming the file's copy
    // would point `ast session bot-1` at a session no guest has.
    let record = parent_dir.join(AGENT_RECORD);
    if record.is_file() {
        if let Err(error) = std::fs::copy(&record, child_dir.join(AGENT_RECORD)) {
            warnings.push(format!(
                "{child} is not recorded as an agent: {} could not be copied ({error}) — \
                 `ast session {child}` will not know what to attach to",
                record.display()
            ));
        }
    }

    // ---- the volumes -------------------------------------------------------
    let primary = primary_volume(parent).map(|(index, _)| index);
    let mut volumes = Vec::new();
    for (index, volume) in parent.volumes.iter().enumerate() {
        if volume.kind == VolumeKind::Block || !volume.is_local() {
            continue; // already said in `warn_about_parts`
        }
        // A cache is attached where the parent has it, not copied beside it:
        // three forks sharing one warm package cache is the whole point of
        // having declared it a cache.
        if is_shared_on_fork(volume) {
            volumes.push(volume.clone());
            continue;
        }
        let Some(shot) = meta.volumes.get(index) else {
            warnings.push(format!(
                "{:?} is not on {child}: the snapshot did not record it",
                volume.path
            ));
            continue;
        };
        let Some(clone) = &shot.clone_dir else {
            warnings.push(format!(
                "{:?} is not on {child}: {}",
                volume.path,
                shot.not_snapshotted
                    .as_deref()
                    .unwrap_or("it was not cloned")
            ));
            continue;
        };
        let target = fork_volume_dir(child, index);
        apparent = apparent.saturating_add(timeline::tree_usage(&snapshots.join(clone)));
        timeline::clone_tree(&snapshots.join(clone), &target)
            .with_context(|| format!("cloning {:?} into {child}", volume.path))?;
        if primary == Some(index) {
            if let Some(note) = &origin.note {
                // Until a fork can be told something through a live session,
                // this is the thing that is true on every guest: a file in
                // the working directory, in the working directory's own
                // volume, readable the moment the fork boots.
                if let Err(error) =
                    std::fs::write(target.join(model::NOTE_FILE), format!("{note}\n"))
                {
                    warnings.push(format!(
                        "{child} was not given its --each note: {error} — it is in \
                         `ast ls` either way"
                    ));
                }
            }
        }
        // Same mount point, same lifecycle, its own bytes: a `memory` volume
        // copied onto a fork is still that fork's memory, and would be rolled
        // back by `ast rewind --include-memory` on the fork exactly as the
        // parent's is on the parent.
        volumes.push(
            Volume::dir(&target.display().to_string(), &volume.host, None)
                .placed(volume.mount_point.clone(), volume.lifecycle()),
        );
    }

    // ---- the row -----------------------------------------------------------
    let mut inst = Instance::new(
        child,
        &parent.cpu_device,
        parent.image.as_deref().unwrap_or_default(),
        parent.shape.clone(),
        parent.machine.clone(),
    );
    inst.runtime = parent.runtime;
    inst.image_kind = parent.image_kind;
    inst.policy = parent.policy;
    inst.profiles = parent.profiles.clone();
    // Verbatim: the handle in each binding is baked into the disk this fork
    // was just cloned from, and only this instance's own egress door honours
    // it. See the module header.
    inst.secrets = parent.secrets.clone();
    inst.rewind = parent.rewind;
    inst.volumes = volumes;
    // Never the parent's. A host port is one number on one device.
    inst.publish = Vec::new();
    // It has a disk, so it is a stopped instance rather than a defined one —
    // which is the difference between `ast up` booting it and `ast up`
    // creating it.
    inst.status = Status::Stopped;
    inst.fork_of = Some(origin);
    Ok((inst, apparent))
}

// ---- diffing ---------------------------------------------------------------

fn diff(reg: &Shard, name: &str, against: Option<&str>) -> Result<model::Diff> {
    let inst = reg.get(name)?.clone();
    let (index, volume) = primary_volume(&inst).ok_or_else(|| {
        anyhow!("{name} has no local directory volume, so there is nothing to compare")
    })?;
    let mine = PathBuf::from(&volume.path);
    let offset = timeline::local_offset(asterism_core::instance::now_unix());
    let (base, label) = base_tree(reg, &inst, index, against, offset)?;

    let mut warnings = Vec::new();
    let (method, files, added, removed) = summarize(&base, &mine, &mut warnings);
    Ok(model::Diff {
        instance: name.to_owned(),
        against: label,
        path: guest_path(volume),
        files,
        added,
        removed,
        method,
        warnings,
    })
}

/// What this instance's volume is measured against, and what to call it.
fn base_tree(
    reg: &Shard,
    inst: &Instance,
    index: usize,
    against: Option<&str>,
    offset: i64,
) -> Result<(PathBuf, String)> {
    let mount = inst.volumes[index].mount_point.clone();
    match against {
        // The fork point: the snapshot this instance was cut from.
        None => {
            let origin = inst.fork_of.as_ref().ok_or_else(|| {
                anyhow!(
                    "{} is not a fork — say what to compare it against: \
                     `ast diff {} --against <instance>`",
                    inst.name,
                    inst.name
                )
            })?;
            let dir = paths::instance_dir(&origin.parent);
            let path = snapshot_volume(&dir, &origin.snapshot, &mount).ok_or_else(|| {
                anyhow!(
                    "the snapshot {:?} that {} was forked from no longer holds a copy of {}",
                    origin.snapshot,
                    inst.name,
                    guest_path(&inst.volumes[index]),
                )
            })?;
            Ok((path, origin.against(offset)))
        }
        // Another instance, live: its own volume as it stands right now.
        Some(other) if reg.holds(other) => {
            let peer = reg.get(other)?;
            let (_, volume) = primary_volume(peer).ok_or_else(|| {
                anyhow!("{other} has no local directory volume to compare against")
            })?;
            Ok((PathBuf::from(&volume.path), other.to_owned()))
        }
        // A snapshot tag on this fork's parent, or on this instance itself.
        Some(tag) => {
            let parent = inst
                .fork_of
                .as_ref()
                .map(|origin| origin.parent.clone())
                .unwrap_or_else(|| inst.name.clone());
            let dir = paths::instance_dir(&parent);
            let path = snapshot_volume(&dir, tag, &mount).ok_or_else(|| {
                anyhow!(
                    "no instance or snapshot named {tag:?} holding a copy of {}",
                    guest_path(&inst.volumes[index])
                )
            })?;
            Ok((path, format!("{parent} @ {tag}")))
        }
    }
}

/// The cloned tree a snapshot holds for the volume mounted at `mount`.
///
/// Matched by mount point rather than by index: a volume attached to the
/// parent since the fork would shift every index after it, and a diff that
/// silently compared `/work` against `/cache` would be worse than no diff.
fn snapshot_volume(dir: &Path, tag: &str, mount: &Option<String>) -> Option<PathBuf> {
    let meta = timeline::read_meta(dir, tag)?;
    let shot = meta
        .volumes
        .iter()
        .find(|shot| shot.mount_point == *mount && shot.clone_dir.is_some())
        .or_else(|| meta.volumes.iter().find(|shot| shot.clone_dir.is_some()))?;
    Some(snapshot::dir(dir).join(shot.clone_dir.as_ref()?))
}

/// Count what changed, with `git` when it is here and by walking when it is
/// not.
///
/// `git` is preferred because it is what the agent's own numbers come from:
/// it honours the repository's ignore rules, so a `/work` with a build
/// directory in it reports the source that changed rather than the artefacts
/// that were rebuilt. Both trees are on this device's disk — the fork's
/// volume and the parent's snapshot of it — so this is the same bytes the
/// guest sees, read from the host side, and no guest has to be running.
fn summarize(
    base: &Path,
    mine: &Path,
    warnings: &mut Vec<String>,
) -> (model::Method, usize, u64, u64) {
    if let Some(counted) = git_summary(base, mine) {
        return counted;
    }
    if mine.join(".git").exists() {
        warnings.push(
            "counted by walking both trees rather than with git, so ignored files count too"
                .to_owned(),
        );
    }
    let (files, added, removed) = model::tree_diff(base, mine);
    (model::Method::Trees, files, added, removed)
}

fn git_summary(base: &Path, mine: &Path) -> Option<(model::Method, usize, u64, u64)> {
    if !mine.join(".git").is_dir() {
        return None;
    }
    // The commit the parent was on at the fork point. It is in this fork's
    // own object store, because the store was cloned with everything else —
    // so a fork whose agent has *committed* is still measured against where
    // it started rather than against its own last commit.
    let from = git(base, &["rev-parse", "--verify", "HEAD"])
        .or_else(|| git(mine, &["rev-parse", "--verify", "HEAD"]))?;
    let from = from.trim().to_owned();
    // The pathspec keeps the `--each` note out of the count even in the
    // unusual case of somebody having committed it.
    let hide = format!(":(exclude){}", model::NOTE_FILE);
    let numstat = git(mine, &["diff", "--numstat", &from, "--", ".", &hide])?;
    let (mut files, mut added, removed) = model::parse_numstat(&numstat);
    // Untracked and not ignored: a new file an agent has written is the
    // whole point and `git diff` does not see it.
    let untracked = git(mine, &["ls-files", "--others", "--exclude-standard"])?;
    for line in untracked.lines().filter(|line| !line.is_empty()) {
        if model::is_ours(Path::new(line)) {
            continue; // the `--each` note is not the agent's work
        }
        files += 1;
        added = added.saturating_add(lines_in(&mine.join(line)));
    }
    Some((model::Method::Git, files, added, removed))
}

/// One `git` invocation in a directory. `None` for anything that is not a
/// clean success, which is what sends the caller to the tree walk.
fn git(dir: &Path, args: &[&str]) -> Option<String> {
    let out = std::process::Command::new("git")
        .arg("-C")
        .arg(dir)
        .arg("--no-optional-locks")
        .args(args)
        .output()
        .ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}

fn lines_in(path: &Path) -> u64 {
    let Ok(bytes) = std::fs::read(path) else {
        return 0;
    };
    if bytes.iter().take(8_000).any(|b| *b == 0) {
        return 0; // binary, like git counts one
    }
    let lines = bytes.iter().filter(|b| **b == b'\n').count() as u64;
    // A file with no trailing newline still holds a last line.
    if bytes.is_empty() || bytes.ends_with(b"\n") {
        lines
    } else {
        lines + 1
    }
}

// ---- picking ---------------------------------------------------------------

/// Replace the parent's working volume with this fork's, keep what it
/// replaced, and retire the siblings.
///
/// The parent's *root disk* is deliberately untouched. What the agent
/// produced is in `/work`; the rest of the fork's disk is a copy of the
/// parent's own an hour ago, and putting that back would undo everything the
/// parent did while the forks ran.
async fn pick(reg: &mut Shard, name: &str, apply: bool, cpu_device: &str) -> Result<model::Pick> {
    let winner = reg.get(name)?.clone();
    let origin = winner.fork_of.clone().ok_or_else(|| {
        anyhow!("{name} is not a fork — `ast pick` puts a fork's work back onto the instance it was cloned from")
    })?;
    let parent = reg
        .get(&origin.parent)
        .with_context(|| {
            format!(
                "{name} was forked from {:?}, which is not in this orbit any more",
                origin.parent
            )
        })?
        .clone();
    let (_, mine) = primary_volume(&winner)
        .ok_or_else(|| anyhow!("{name} has no local directory volume to hand back"))?;
    let (_, theirs) = primary_volume(&parent).ok_or_else(|| {
        anyhow!(
            "{} has no local directory volume for {name}'s work to replace",
            parent.name
        )
    })?;
    let (from, onto) = (PathBuf::from(&mine.path), PathBuf::from(&theirs.path));
    let path = guest_path(theirs);
    // Every other fork cut from the same snapshot of the same parent.
    let siblings: Vec<String> = reg
        .list()
        .into_iter()
        .filter(|inst| inst.name != winner.name)
        .filter(|inst| {
            inst.fork_of.as_ref().is_some_and(|other| {
                other.parent == origin.parent && other.snapshot == origin.snapshot
            })
        })
        .map(|inst| inst.name)
        .collect();

    let mut plan = model::Pick {
        parent: parent.name.clone(),
        winner: name.to_owned(),
        path,
        removed: siblings.clone(),
        kept_as: Some(model::BEFORE_PICK.to_owned()),
        applied: false,
        elapsed_ms: 0,
        warnings: Vec::new(),
    };
    if !apply {
        return Ok(plan);
    }

    let started = Instant::now();
    let was_running = parent.status == Status::Running;
    if was_running {
        // The whole stop, for the reason a rewind does it: a directory
        // replaced under a live guest is a directory the guest has cached.
        crate::instance::down_completely(reg, &parent.name)
            .await
            .with_context(|| format!("stopping {} to replace its {}", parent.name, plan.path))?;
    }
    // What is being replaced, kept — so `ast rewind <parent> --to before-pick`
    // undoes this. Named, so it never expires.
    let kept = tokio::task::block_in_place(|| {
        let dir = paths::instance_dir(&parent.name);
        let _ = snapshot::remove(&dir, model::BEFORE_PICK);
        crate::rewind::take(&parent, model::BEFORE_PICK, Kind::Named)
    });
    if let Err(error) = kept {
        plan.kept_as = None;
        plan.warnings.push(format!(
            "the {} being replaced could not be kept as {:?}: {error:#}",
            plan.path,
            model::BEFORE_PICK
        ));
    }
    let replaced = tokio::task::block_in_place(|| timeline::restore_tree(&from, &onto));

    // Whatever happened, the parent goes back up if it was up.
    if was_running {
        if let Err(error) = crate::instance::up(reg, &parent.name, None, RestartReason::Picked) {
            plan.warnings.push(format!(
                "{} did not start again: {error:#} — `ast up {}` is the retry",
                parent.name, parent.name
            ));
        }
    }
    replaced.with_context(|| format!("replacing {}'s {}", parent.name, plan.path))?;

    for sibling in &siblings {
        if let Err(error) = retire(reg, sibling, cpu_device).await {
            plan.warnings.push(format!(
                "{sibling} is still here: {error:#} — `ast rm {sibling}` removes it"
            ));
        }
    }
    plan.applied = true;
    plan.elapsed_ms = started.elapsed().as_millis() as u64;
    Ok(plan)
}

/// Stop and remove one sibling, through the ordinary instance path.
///
/// Not a shortcut around `ast rm`: a fork holds an egress door, a
/// guest-control key and possibly a leased disk, and the one place that knows
/// how to give all of those back is [`crate::instance::serve`].
async fn retire(reg: &mut Shard, name: &str, cpu_device: &str) -> Result<()> {
    if reg.get(name)?.status == Status::Running {
        crate::instance::down_completely(reg, name).await?;
    }
    match crate::instance::serve(
        Request::Remove {
            name: name.to_owned(),
        },
        reg,
        cpu_device,
    )
    .await
    {
        Response::Error { message } => bail!(message),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use asterism_core::hv::Machine;
    use asterism_core::instance::Shape;

    /// The device name a volume has to carry to be one this device can
    /// clone: `Volume::is_local` compares against the running host's own.
    fn here() -> String {
        asterism_core::instance::local_host()
    }

    fn instance(name: &str) -> Instance {
        Instance::new(
            name,
            "dev",
            "docker.io/library/nginx:alpine",
            Shape::default(),
            Machine {
                backend: "vz".into(),
                machine_type: "virt".into(),
                cpu: "host".into(),
                hv_version: "15".into(),
            },
        )
    }

    /// [`claims`] and [`serve`] have to agree: a frame claimed here and not
    /// matched there would be answered "is not a fork request" by the very
    /// module that owns it.
    #[test]
    fn every_frame_this_module_claims_is_one_it_answers() {
        for req in [
            Request::Fork {
                name: "bot".into(),
                count: 3,
                each: Vec::new(),
                stopped: false,
                yes: false,
            },
            Request::ForkDiff {
                name: "bot-2".into(),
                against: None,
            },
            Request::ForkPick {
                name: "bot-2".into(),
                apply: true,
            },
        ] {
            assert!(claims(&req), "{req:?} is claimed nowhere");
            assert!(!crate::rewind::claims(&req), "{req:?} is also a rewind");
            assert!(!crate::snapshot::claims(&req), "{req:?} is also a snapshot");
        }
    }

    /// A fork lives on the same device as its parent, and all three frames
    /// name the instance they are about — which is what routes them there.
    #[test]
    fn a_fork_is_addressed_to_the_instance_it_names() {
        assert_eq!(
            Request::Fork {
                name: "bot".into(),
                count: 2,
                each: Vec::new(),
                stopped: false,
                yes: false,
            }
            .subject(),
            Some("bot")
        );
        assert_eq!(
            Request::ForkPick {
                name: "bot-2".into(),
                apply: false,
            }
            .subject(),
            Some("bot-2")
        );
    }

    /// `/work` wins over a volume that merely came first, because `/work` is
    /// what the agent was told its working directory is.
    #[test]
    fn the_primary_volume_is_work_when_there_is_one() {
        let mut inst = instance("bot");
        inst.volumes = vec![
            Volume::dir("/host/cache", &here(), Some("/cache".into())),
            Volume::dir("/host/work", &here(), Some(WORK.into())),
        ];
        let (index, volume) = primary_volume(&inst).unwrap();
        assert_eq!(index, 1);
        assert_eq!(volume.path, "/host/work");
    }

    #[test]
    fn one_volume_is_the_primary_one_whatever_it_is_called() {
        let mut inst = instance("bot");
        inst.volumes = vec![Volume::dir("/host/src", &here(), Some("/src".into()))];
        assert_eq!(primary_volume(&inst).unwrap().0, 0);
    }

    /// AST-158's rule, at the one place a fork asks it: a cache is warmed
    /// between the forks, everything else is each fork's own.
    #[test]
    fn a_cache_is_shared_and_everything_else_is_copied() {
        use asterism_core::volume::Lifecycle;
        let cache = Volume::dir("/host/cache", &here(), None).placed(None, Lifecycle::Cache);
        let memory = Volume::dir("/host/memory", &here(), None).placed(None, Lifecycle::Memory);
        let work = Volume::dir("/host/work", &here(), None).placed(None, Lifecycle::Instance);
        assert!(is_shared_on_fork(&cache));
        assert!(!is_shared_on_fork(&memory));
        assert!(!is_shared_on_fork(&work));
        // A volume from a registry written before lifecycles existed is
        // instance data, which is what it has always been treated as.
        assert!(!is_shared_on_fork(&Volume::dir("/host/old", &here(), None)));
    }

    /// A cache is rebuildable by definition and shared with the parent, so
    /// "what did this fork change in it" is a question about a directory the
    /// fork does not own. `ast diff` and `ast pick` must never land on one.
    #[test]
    fn a_cache_is_never_the_volume_a_fork_is_judged_on() {
        use asterism_core::volume::Lifecycle;
        let mut inst = instance("bot");
        inst.volumes = vec![
            Volume::dir("/host/cache", &here(), None).placed(None, Lifecycle::Cache),
            Volume::dir("/host/notes", &here(), None).placed(None, Lifecycle::Memory),
        ];
        let (index, volume) = primary_volume(&inst).unwrap();
        assert_eq!(index, 1);
        assert_eq!(volume.path, "/host/notes");

        // And an instance whose only local directory is a cache has nothing
        // to be judged on at all, which is a refusal rather than a guess.
        inst.volumes.truncate(1);
        assert!(primary_volume(&inst).is_none());
    }

    /// A block volume's bytes are on some device's export. There is nothing
    /// on this disk to compare or to replace.
    #[test]
    fn a_block_volume_is_never_the_primary_one() {
        let mut inst = instance("bot");
        inst.volumes = vec![Volume::block("data", "dev", 1, 1 << 30)];
        assert!(primary_volume(&inst).is_none());
    }

    /// The refusal a fork of a bare instance gets, before anything moves.
    #[test]
    fn an_instance_with_no_volume_has_nothing_to_diff() {
        let inst = instance("bot");
        assert!(primary_volume(&inst).is_none());
    }

    /// Every part that cannot be forked is named, not dropped quietly.
    #[test]
    fn the_parts_a_fork_cannot_have_are_said_out_loud() {
        let mut inst = instance("bot");
        inst.publish = vec![asterism_core::instance::PortForward {
            host: 8080,
            guest: 80,
            protocol: Default::default(),
        }];
        inst.volumes = vec![Volume::block("data", "other", 1, 1 << 30)];
        let mut warnings = Vec::new();
        warn_about_parts(&inst, &mut warnings);
        assert!(
            warnings.iter().any(|w| w.contains("publish no ports")),
            "{warnings:?}"
        );
        assert!(
            warnings.iter().any(|w| w.contains("single-writer")),
            "{warnings:?}"
        );
    }

    /// A fork's working copy belongs to the fork: `ast rm` takes it with it,
    /// and no two forks ever point at one directory.
    #[test]
    fn each_fork_gets_its_own_copy_of_the_volume() {
        let one = fork_volume_dir("bot-1", 0);
        let two = fork_volume_dir("bot-2", 0);
        assert_ne!(one, two);
        assert!(one.starts_with(paths::instance_dir("bot-1")));
    }

    #[test]
    fn a_file_with_no_trailing_newline_still_has_a_last_line() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("a.txt");
        std::fs::write(&path, b"one\ntwo").unwrap();
        assert_eq!(lines_in(&path), 2);
        std::fs::write(&path, b"one\ntwo\n").unwrap();
        assert_eq!(lines_in(&path), 2);
        std::fs::write(&path, b"").unwrap();
        assert_eq!(lines_in(&path), 0);
        std::fs::write(&path, b"\x00\x01binary").unwrap();
        assert_eq!(lines_in(&path), 0);
    }
}
