//! `ast rewind` — the timeline, and putting an instance back onto it.
//!
//! The product this belongs to is speed, not caution. An agent is worth more
//! running `--dangerously-skip-permissions` than stopping to ask, and the
//! thing that makes that a reasonable trade is being able to say "go back
//! twenty minutes" and have it be true twenty seconds later. Everything here
//! is in service of that one sentence.
//!
//! # What a rewind is
//!
//! Stop the guest, keep what it currently has as `before-rewind`, roll the
//! root disk and any local directory volume back to a snapshot, start it
//! again, and put its published ports back. Five steps, in that order, and
//! the order is the whole design:
//!
//! * **Stop first.** A disk rolled back under a live guest is a disk the
//!   guest has cached pages of. There is no version of this that is safe
//!   while it runs.
//! * **Keep before rolling.** A rewind is undoable, because the state it
//!   replaced is snapshotted first. It is rolling — only the latest is
//!   kept — because the interesting undo is always the last one, and keeping
//!   every one of them would be a second retention policy nobody asked for.
//! * **Republish last.** [`crate::instance::up`] re-establishes the
//!   declaration, so the port that answered before the rewind answers after
//!   it. That is done by going through `up` rather than around it.
//!
//! # Refusals happen before anything moves
//!
//! A target that does not exist, an instance whose snapshots live inside a
//! legacy qcow2, an instance that has never been booted: all of them are
//! refused while the guest is still running and the disk is still whole.
//! [`asterism_core::rewind::select`] is what makes that possible — it reads
//! the timeline and picks, and picking is the only thing that can fail for a
//! reason the user can fix.
//!
//! # Where the snapshots come from
//!
//! [`crate::autosnap`] takes them on a timer. This module takes exactly two
//! kinds itself: the `before-rewind` a rewind keeps, and — through
//! [`take`] — whatever the scheduler asks for. Both go through
//! [`asterism_core::snapshot`], which is the same copy-on-write clone
//! `ast snapshot` has always made, so a snapshot is a snapshot whoever asked
//! for it.

use std::path::{Path, PathBuf};
use std::time::Instant;

use anyhow::{bail, Context, Result};

use asterism_core::instance::{Instance, RestartReason, Status, VolumeKind};
use asterism_core::paths;
use asterism_core::protocol::{Request, Response};
use asterism_core::registry::Shard;
use asterism_core::rewind::{self as model, Kind, Meta, Settings, Target, VolumeShot};
use asterism_core::snapshot;

/// Is this one of the frames this module answers?
///
/// Separate from [`serve`] for the reason every area's is: [`crate::handle`]
/// asks it before deciding whose match to run, and the two agreeing is what
/// stops a frame claimed here being answered with "not a rewind request".
pub(crate) fn claims(req: &Request) -> bool {
    matches!(
        req,
        Request::RewindTimeline { .. } | Request::Rewind { .. } | Request::RewindSettings { .. }
    )
}

/// Answer one rewind request against this device's shard.
pub(crate) async fn serve(req: Request, reg: &mut Shard) -> Response {
    match req {
        Request::RewindTimeline { name } => match reg.get(&name).cloned() {
            Ok(inst) => match tokio::task::block_in_place(|| timeline(&inst)) {
                Ok(timeline) => Response::RewindTimeline { timeline },
                Err(e) => error(e),
            },
            Err(e) => error(e),
        },
        Request::RewindSettings {
            name,
            every_secs,
            keep_secs,
            reset,
        } => match settings(reg, &name, every_secs, keep_secs, reset) {
            Ok(timeline) => Response::RewindTimeline { timeline },
            Err(e) => error(e),
        },
        Request::Rewind {
            name,
            to,
            include_memory,
        } => match rewind(reg, &name, &to, include_memory).await {
            Ok(report) => Response::Rewound { report },
            Err(e) => error(e),
        },
        other => Response::Error {
            message: format!("{other:?} is not a rewind request"),
        },
    }
}

fn error(e: anyhow::Error) -> Response {
    Response::Error {
        message: format!("{e:#}"),
    }
}

// ---- the timeline ----------------------------------------------------------

/// Everything `ast rewind <instance>` prints, read off the instance's own
/// directory.
///
/// Reads only, so it answers while the guest runs — which is the state an
/// instance worth rewinding is almost always in.
pub(crate) fn timeline(inst: &Instance) -> Result<model::Timeline> {
    let dir = paths::instance_dir(&inst.name);
    let settings = Settings::resolve(inst.rewind);
    if let Some(note) = unsupported(inst, &dir) {
        return Ok(model::Timeline {
            instance: inst.name.clone(),
            entries: Vec::new(),
            settings,
            note: Some(note),
        });
    }
    Ok(model::Timeline {
        instance: inst.name.clone(),
        entries: model::read_entries(&dir)?,
        settings,
        note: None,
    })
}

/// Why this instance cannot be on a timeline, when it cannot.
///
/// One case, and it is a compatibility one: an instance created before raw
/// disks whose root is still a `disk.qcow2` overlay keeps its snapshots
/// *inside* the disk, where the QEMU backend puts and finds them. Those are
/// real snapshots and `ast snapshot`/`ast restore` still work on them; they
/// are simply not files this module can clone, date or prune, so it says so
/// rather than showing an empty timeline for an instance that has snapshots.
fn unsupported(inst: &Instance, dir: &Path) -> Option<String> {
    if inst.machine.backend == "qemu" && dir.join("disk.qcow2").is_file() {
        return Some(format!(
            "{} is a legacy qcow2 instance: its snapshots live inside the disk rather \
             than beside it, so there is no timeline to walk. `ast snapshots {}` lists \
             them and `ast restore {} <tag>` rolls back to one",
            inst.name, inst.name, inst.name
        ));
    }
    None
}

fn settings(
    reg: &mut Shard,
    name: &str,
    every_secs: Option<u64>,
    keep_secs: Option<u64>,
    reset: bool,
) -> Result<model::Timeline> {
    let current = Settings::resolve(reg.get(name)?.rewind);
    let wanted = if reset {
        None
    } else {
        Some(Settings {
            every_secs: every_secs.unwrap_or(current.every_secs),
            keep_secs: keep_secs.unwrap_or(current.keep_secs),
        })
    };
    let inst = reg.set_rewind(name, wanted)?;
    reg.save()
        .context("saving the registry after changing the snapshot interval")?;
    timeline(&inst)
}

// ---- taking one ------------------------------------------------------------

/// Take a snapshot of `inst` — its root disk, and any local directory volume
/// beside it — under `tag`.
///
/// Used by the scheduler and by the rewind engine, which is why it does not
/// care whether the instance is running. `ast snapshot` refuses a running
/// one; an automatic snapshot cannot, so what this produces while a guest is
/// live is crash consistent and says so in
/// [`asterism_core::rewind`]'s own documentation.
///
/// A volume that cannot be cloned does not fail the snapshot. The root disk
/// is the thing being kept, and a `/work` that could not be copied is worth
/// recording in the sidecar and printing on the timeline — not worth
/// throwing the disk away over.
pub(crate) fn take(inst: &Instance, tag: &str, kind: Kind) -> Result<Meta> {
    let dir = paths::instance_dir(&inst.name);
    if let Some(note) = unsupported(inst, &dir) {
        bail!(note);
    }
    let disk = model::root_disk(&dir)?;
    let started = Instant::now();
    let print = model::fingerprint(&disk)?;
    snapshot::take(&dir, &disk, tag)?;

    let mut volumes = Vec::new();
    for (index, volume) in inst.volumes.iter().enumerate() {
        volumes.push(shoot_volume(&dir, tag, index, volume));
    }
    // Block volumes on this device are captured beside their own bytes,
    // under this same tag, by the module that also knows how to put them
    // back. Never fatal: an automatic snapshot that refused because a volume
    // could not be cloned would be an instance that stops being snapshotted.
    if let Err(error) = crate::snapshot::capture_volumes(inst, tag) {
        eprintln!("astd: {error:#}");
    }

    let meta = Meta {
        tag: tag.to_owned(),
        kind,
        taken_at: asterism_core::instance::now_unix(),
        disk: print,
        volumes,
        elapsed_ms: started.elapsed().as_millis() as u64,
    };
    // Written last: a sidecar is only true once the bytes it describes are
    // there, and a snapshot without one still lists, still restores and
    // still says what kind it is — the tag carries that.
    model::write_meta(&dir, &meta)?;
    Ok(meta)
}

/// One volume's part of a snapshot: a clone, or a sentence saying why not.
fn shoot_volume(
    dir: &Path,
    tag: &str,
    index: usize,
    volume: &asterism_core::instance::Volume,
) -> VolumeShot {
    let mut shot = VolumeShot {
        source: volume.path.clone(),
        mount_point: volume.mount_point.clone(),
        clone_dir: None,
        not_snapshotted: None,
        print: model::Fingerprint::default(),
    };
    // A block volume is bytes on whichever device holds them, reached over
    // NBD. The volume protocol has no snapshot request — there is nothing to
    // send — so this records the fact rather than pretending the rewind was
    // complete. Saying it here is what lets the timeline and the rewind
    // report both say it.
    if volume.kind == VolumeKind::Block {
        // A block volume on this device is captured — beside its own bytes
        // rather than inside this instance's snapshot directory, because a
        // volume outlives every instance that ever mounted it. There is
        // nothing for this shot to point at, and nothing missing to report:
        // `crate::snapshot` owns both halves of it.
        //
        // A cache volume is deliberately not captured and is deliberately
        // not reported as missing either. Nothing will ever roll one back,
        // so "not snapshotted" would be a warning about the design working.
        if volume.is_local() {
            return shot;
        }
        // Somebody else's bytes, reached over NBD. The volume protocol has
        // no snapshot request — there is nothing to send — so this records
        // the fact rather than pretending the rewind was complete.
        shot.not_snapshotted = Some(format!(
            "volume not snapshotted: {:?} is a block volume on {} and its provider \
             has no snapshot request",
            volume.path, volume.host
        ));
        return shot;
    }
    if !volume.is_local() {
        shot.not_snapshotted = Some(format!(
            "volume not snapshotted: {:?} is a directory on {}, which this device \
             cannot clone",
            volume.path, volume.host
        ));
        return shot;
    }
    let source = PathBuf::from(&volume.path);
    let name = model::volume_clone_name(tag, index);
    let target = snapshot::dir(dir).join(&name);
    match model::clone_tree(&source, &target) {
        Ok(()) => {
            shot.clone_dir = Some(name);
            shot.print = model::tree_fingerprint(&source).unwrap_or_default();
        }
        Err(error) => {
            let _ = std::fs::remove_dir_all(&target);
            shot.not_snapshotted = Some(format!(
                "volume not snapshotted: {:?} could not be cloned ({error:#})",
                volume.path
            ));
        }
    }
    shot
}

/// Has anything changed since the newest automatic snapshot?
///
/// The cheap check the scheduler makes before spending a clone. What each
/// backend can actually tell us is written down in
/// [`asterism_core::rewind::Fingerprint`]: nothing exposes a dirty bitmap
/// through the hypervisor boundary, so this is the root disk's length and
/// mtime, plus the same for each cloned directory volume.
pub(crate) fn changed_since(inst: &Instance, previous: &Meta) -> Result<bool> {
    let dir = paths::instance_dir(&inst.name);
    let disk = model::root_disk(&dir)?;
    if model::fingerprint(&disk)? != previous.disk {
        return Ok(true);
    }
    for volume in &inst.volumes {
        if volume.kind == VolumeKind::Block || !volume.is_local() {
            continue;
        }
        let now = model::tree_fingerprint(Path::new(&volume.path)).unwrap_or_default();
        let then = previous
            .volumes
            .iter()
            .find(|shot| shot.source == volume.path);
        match then {
            // A volume that has been attached since the last snapshot is a
            // change: the next snapshot has to include it.
            None => return Ok(true),
            Some(shot) if shot.print != now => return Ok(true),
            Some(_) => {}
        }
    }
    Ok(false)
}

// ---- rolling back ----------------------------------------------------------

/// Stop, keep, roll back, start, republish.
async fn rewind(
    reg: &mut Shard,
    name: &str,
    to: &Target,
    include_memory: bool,
) -> Result<model::Report> {
    let inst = reg.get(name)?.clone();
    let dir = paths::instance_dir(name);
    if let Some(note) = unsupported(&inst, &dir) {
        bail!(note);
    }
    let now = asterism_core::instance::now_unix();
    let line = tokio::task::block_in_place(|| timeline(&inst))?;
    // Before a byte moves. Every reason a rewind cannot happen that the user
    // could do something about is a reason to pick a target, and picking is
    // pure.
    let chosen = model::select(&line, to, now)?.clone();

    let started = Instant::now();
    let was_running = inst.status == Status::Running;
    if was_running {
        // The whole stop, not just the guest: a rewind that let the guest go
        // while this daemon kept holding its published host port made the
        // boot on the other side of the rollback refuse its own declaration
        // as taken.
        crate::instance::down_completely(reg, name)
            .await
            .with_context(|| {
                format!("stopping {name} to roll its disk back to {:?}", chosen.tag)
            })?;
    }

    let mut warnings = Vec::new();
    let staged =
        tokio::task::block_in_place(|| keep_current(&inst, &dir)).unwrap_or_else(|error| {
            // The rewind still happens. Losing the undo is worth a loud line,
            // not worth refusing the thing the user asked for after the guest
            // has already been stopped.
            warnings.push(format!(
                "the state being replaced could not be kept as {:?}: {error:#}",
                model::BEFORE_REWIND
            ));
            false
        });

    let rolled = tokio::task::block_in_place(|| {
        roll_back(&inst, &dir, &chosen, include_memory, &mut warnings)
    });
    // Whatever happened to the disk, the guest goes back up if it was up:
    // an instance left stopped by a failed rewind is the worst of both.
    let mut restarted = false;
    if was_running {
        // Its own reason: a guest that is up again because its disk was
        // rolled back has not crashed and nobody typed `ast up`, and
        // `ast status` should not imply either.
        match crate::instance::up(reg, name, None, RestartReason::Rewound) {
            Ok(_) => restarted = true,
            Err(error) => warnings.extend(boot_failure(reg, name, &error)),
        }
    }
    rolled?;

    Ok(model::Report {
        instance: name.to_owned(),
        tag: chosen.tag,
        taken_at: chosen.taken_at,
        elapsed_ms: started.elapsed().as_millis() as u64,
        kept_as: staged.then(|| model::BEFORE_REWIND.to_owned()),
        restarted,
        republished: if restarted { inst.publish.len() } else { 0 },
        volumes: chosen.volumes,
        warnings,
    })
}

/// What to tell somebody whose rewound instance would not start again.
///
/// The disk *was* rolled back — that part succeeded, and saying so matters,
/// because the next thing they will try is rewinding again and there is no
/// reason to. What did not happen is the boot, and the reason is the
/// backend's own.
///
/// The second line is the case worth naming out loud. `up` compensates every
/// failure it can prove, but a backend launch whose outcome is *ambiguous*
/// deliberately leaves the durable boot fence in place rather than risk a
/// second guest on one disk — and an instance in that state disagrees with
/// itself about whether it is running (AST-161). Clearing the fence from here
/// would be exactly the compensation the fence exists to prevent, so this
/// says what state the row is in instead.
fn boot_failure(reg: &Shard, name: &str, error: &anyhow::Error) -> Vec<String> {
    let mut said = vec![format!(
        "boot failed: {error:#} — the disk is rolled back, so `ast up {name}` is the \
         retry, not another rewind"
    )];
    if reg
        .get(name)
        .is_ok_and(|inst| inst.boot_intent_id.is_some())
    {
        said.push(format!(
            "{name} is left holding a durable boot fence: the backend's launch outcome \
             could not be proven either way, and clearing it from here could admit a \
             second guest onto one disk. Check for a running VMM before retrying"
        ));
    }
    said
}

/// Snapshot what is on the disk right now, so the rewind can be undone.
///
/// Staged under [`asterism_core::rewind::STAGING`] and renamed into place
/// afterwards, because the snapshot being rewound *to* may itself be
/// `before-rewind` — undoing the last rewind is the second thing anybody
/// does with this, and overwriting the source of a rollback on the way to
/// performing it would make that impossible.
fn keep_current(inst: &Instance, dir: &Path) -> Result<bool> {
    if model::root_disk(dir).is_err() {
        return Ok(false);
    }
    // A rewind interrupted halfway leaves this behind. It is a copy of a
    // state that was superseded before it was ever claimed, and the next
    // rewind is the right moment to be rid of it.
    let _ = snapshot::remove(dir, model::STAGING);
    take(inst, model::STAGING, Kind::Rewind)?;
    Ok(true)
}

/// Put the root disk, and every volume this snapshot holds, back.
fn roll_back(
    inst: &Instance,
    dir: &Path,
    chosen: &model::Entry,
    include_memory: bool,
    warnings: &mut Vec<String>,
) -> Result<()> {
    let disk = model::root_disk(dir)?;
    snapshot::restore(dir, &disk, &chosen.tag)?;
    for shot in &chosen.volumes {
        let Some(clone) = &shot.clone_dir else {
            continue; // already reported on the timeline and in the report
        };
        // Only a volume that is still attached where it was is put back, and
        // only one whose lifecycle says a rewind may touch it. One that has
        // been detached or re-pointed since is not this snapshot's to write
        // over; one holding the agent's memory is not this rewind's to undo
        // unless the user asked with --include-memory. The predicate lives
        // in `asterism_core::volume` so this and `ast restore` cannot drift
        // into two different answers to the same question.
        let attached = inst.volumes.iter().any(|v| {
            v.path == shot.source
                && v.kind == VolumeKind::Dir
                && v.is_local()
                && asterism_core::volume::reverts_with_instance(v.lifecycle(), include_memory)
        });
        if !attached {
            warnings.push(format!(
                "{:?} was not put back: it is no longer attached to {} as a local \
                 directory a rewind may roll back",
                shot.source, inst.name
            ));
            continue;
        }
        if let Err(error) =
            model::restore_tree(&snapshot::dir(dir).join(clone), Path::new(&shot.source))
        {
            warnings.push(format!("{:?} was not put back: {error:#}", shot.source));
        }
    }
    // Block volumes are not clones inside this instance's snapshot
    // directory: a volume outlives every instance that ever mounted it, so
    // its clones live beside its own bytes. Same tag, same predicate, one
    // function that `ast restore` calls too.
    if let Err(error) = crate::snapshot::revert_volumes(inst, &chosen.tag, include_memory) {
        warnings.push(format!("{error:#}"));
    }

    // The disk is the snapshot now, so the staged copy of what it replaced
    // is the undo — and only now is it safe to claim the name, because the
    // rollback may have been reading from the snapshot that name refers to.
    if snapshot::path_for_disk(dir, &disk, model::STAGING)
        .map(|p| p.is_file())
        .unwrap_or(false)
    {
        let _ = snapshot::remove(dir, model::BEFORE_REWIND);
        model::rename(dir, model::STAGING, model::BEFORE_REWIND)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// [`claims`] and [`serve`] have to agree: a frame claimed here and not
    /// matched there would be answered "is not a rewind request" by the very
    /// module that owns it.
    #[test]
    fn every_frame_this_module_claims_is_one_it_answers() {
        for req in [
            Request::RewindTimeline { name: "bot".into() },
            Request::Rewind {
                name: "bot".into(),
                to: Target::Back { seconds: 1_200 },
                include_memory: false,
            },
            Request::RewindSettings {
                name: "bot".into(),
                every_secs: Some(60),
                keep_secs: None,
                reset: false,
            },
        ] {
            assert!(claims(&req), "{req:?}");
        }
    }

    /// The two rollback surfaces have to agree, and the only way to be sure
    /// is that they ask the same function. This is the seam: a directory
    /// part a rewind may put back is one whose lifecycle says so, and
    /// `ast restore` reads the same table.
    #[test]
    fn a_rewind_and_a_restore_ask_the_same_question_about_a_volume() {
        use asterism_core::volume::{reverts_with_instance, Lifecycle};
        // A part written before lifecycles existed is instance data, and a
        // rewind puts it back exactly as it always did.
        assert!(reverts_with_instance(Lifecycle::default(), false));
        // The agent's memory is the one thing the flag moves...
        assert!(!reverts_with_instance(Lifecycle::Memory, false));
        assert!(reverts_with_instance(Lifecycle::Memory, true));
        // ...and a shared cache is never a rewind's to undo, because the
        // instances sharing it are not the ones being rewound.
        assert!(!reverts_with_instance(Lifecycle::Cache, true));
    }

    /// A rewind is about one instance, so it resolves across the orbit like
    /// every other instance command: `ast rewind bot` typed on a laptop must
    /// reach the device holding `bot`.
    #[test]
    fn a_rewind_is_addressed_to_the_instance_it_names() {
        assert_eq!(
            Request::RewindTimeline { name: "bot".into() }.subject(),
            Some("bot")
        );
        assert_eq!(
            Request::Rewind {
                name: "bot".into(),
                to: Target::Tag {
                    tag: "before-refactor".into()
                },
                include_memory: false,
            }
            .subject(),
            Some("bot")
        );
    }

    /// The snapshot area's frames are not this one's, and the other way
    /// round. Both are matched from the same chain.
    #[test]
    fn the_snapshot_commands_are_left_where_they_are() {
        assert!(!claims(&Request::SnapshotList { name: "bot".into() }));
        assert!(!claims(&Request::List));
        assert!(!crate::snapshot::claims(&Request::RewindTimeline {
            name: "bot".into()
        }));
    }

    fn instance(backend: &str) -> Instance {
        serde_json::from_str(&format!(
            r#"{{"id":"i","name":"bot","cpu_device":"laptop","status":"stopped",
                "created_at":0,"volumes":[],
                "machine":{{"backend":"{backend}","machine_type":"virt","cpu":"host",
                            "hv_version":"t"}}}}"#
        ))
        .unwrap()
    }

    /// A legacy qcow2 instance has real snapshots that this engine cannot
    /// see, so it is told where they are rather than shown an empty
    /// timeline.
    #[test]
    fn a_legacy_qcow2_instance_is_pointed_at_the_commands_that_work_on_it() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("disk.qcow2"), b"").unwrap();
        let note = unsupported(&instance("qemu"), dir.path()).expect("a note");
        assert!(note.contains("ast snapshots bot"), "{note}");
        assert!(note.contains("ast restore bot"), "{note}");
    }

    /// Cloud Hypervisor may keep a qcow2 root and still snapshots it by
    /// cloning the file, so the refusal is about the backend that puts its
    /// snapshots inside the disk, not about the format.
    #[test]
    fn a_qcow2_root_on_a_backend_that_clones_files_is_fine() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("disk.qcow2"), b"").unwrap();
        assert!(unsupported(&instance("chv"), dir.path()).is_none());
        assert!(unsupported(&instance("vz"), dir.path()).is_none());
    }

    /// The undo a rewind leaves behind is named for the person reading the
    /// timeline, not for the machinery that staged it.
    /// A rewind whose guest would not come back has still rolled the disk
    /// back, and the person reading the report has to be told which half
    /// happened — or they will rewind again and lose the state they wanted.
    #[test]
    fn a_failed_boot_says_the_disk_is_already_back() {
        let dir = tempfile::tempdir().unwrap();
        let reg = Shard::load(&dir.path().join("state.json")).unwrap();
        let said = boot_failure(&reg, "bot", &anyhow::anyhow!("the helper would not start"));
        assert_eq!(said.len(), 1, "{said:?}");
        assert!(
            said[0].contains("boot failed: the helper would not start"),
            "{said:?}"
        );
        assert!(said[0].contains("ast up bot"), "{said:?}");
    }

    #[test]
    fn the_kept_snapshot_is_the_one_the_timeline_will_show() {
        assert_ne!(model::BEFORE_REWIND, model::STAGING);
        assert_eq!(model::kind_of(model::BEFORE_REWIND), Kind::Rewind);
    }
}
