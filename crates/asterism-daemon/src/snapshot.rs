//! Taking, listing, rolling back to and deleting an instance's disk
//! snapshots.
//!
//! Its own module rather than an arm of [`crate::instance`] because a
//! snapshot is not a row: it lives in the instance's disk, so every request
//! here reads the shard and none of them writes it. That is the whole reason
//! these answer without a save, and keeping them apart is what stops somebody
//! adding a `reg.save()` to the mutation path and quietly making a snapshot a
//! registry operation.
//!
//! Everything is capability-gated at the top of each call. A backend without
//! `disk_snapshot` says so in one sentence here, rather than failing deeper
//! with a hypervisor's own error about a file format nobody asked about.

use anyhow::{Context, Result};

use asterism_core::hv::SnapshotId;
use asterism_core::instance::{Instance, Status};
use asterism_core::protocol::{Request, Response};
use asterism_core::registry::Shard;

use crate::backend;

/// Is this one of the frames this module answers?
///
/// The predicate is separate from [`serve`] because [`crate::handle`] asks it
/// before deciding whose match to run — the same shape [`crate::volume`] uses
/// for the volume plane, and the reason adding a snapshot command is an edit
/// to this file and to nothing else.
pub(crate) fn claims(req: &Request) -> bool {
    matches!(
        req,
        Request::Snapshot { .. }
            | Request::SnapshotList { .. }
            | Request::SnapshotRestore { .. }
            | Request::SnapshotRemove { .. }
    )
}

/// Answer one snapshot request against this device's shard.
///
/// Synchronous, and deliberately so: every call below is a file operation on
/// this device's disk, wrapped in `block_in_place` so a large qcow2 does not
/// stall the runtime's other tasks.
pub(crate) fn serve(req: Request, reg: &Shard) -> Response {
    match req {
        Request::Snapshot { name, tag } => reply(
            stopped(reg, &name)
                .and_then(|inst| tokio::task::block_in_place(|| create(&inst, &tag))),
        ),
        Request::SnapshotList { name } => {
            let listed = reg
                .get(&name)
                .cloned()
                .and_then(|inst| tokio::task::block_in_place(|| list(&inst)));
            match listed {
                Ok(snapshots) => Response::Snapshots { snapshots },
                Err(e) => Response::Error {
                    message: format!("{e:#}"),
                },
            }
        }
        Request::SnapshotRestore {
            name,
            tag,
            include_memory,
        } => {
            reply(stopped(reg, &name).and_then(|inst| {
                tokio::task::block_in_place(|| restore(&inst, &tag, include_memory))
            }))
        }
        // Stopped, like taking one and rolling one back. For a raw instance
        // the file being unlinked is not the one the guest has open, but a
        // legacy `disk.qcow2` keeps its snapshots *inside* the disk, and
        // rewriting that table under a live guest is not a thing to offer on
        // one disk layout and refuse on the other.
        Request::SnapshotRemove { name, tag } => reply(
            stopped(reg, &name)
                .and_then(|inst| tokio::task::block_in_place(|| remove(&inst, &tag))),
        ),
        other => Response::Error {
            message: format!("{other:?} is not a snapshot request"),
        },
    }
}

/// For requests whose whole answer is "it worked" or why it didn't.
fn reply(result: Result<()>) -> Response {
    match result {
        Ok(()) => Response::Ok,
        Err(e) => Response::Error {
            message: format!("{e:#}"),
        },
    }
}

/// The instance, refused if a guest is currently running on its disk.
fn stopped(reg: &Shard, name: &str) -> Result<Instance> {
    let inst = reg.get(name)?.clone();
    if inst.status == Status::Running {
        anyhow::bail!("instance {name:?} is running — `ast down {name}` first");
    }
    Ok(inst)
}

fn create(inst: &Instance, tag: &str) -> Result<()> {
    // A snapshot taken by hand is kept forever, and that promise is carried
    // by the name: retention deletes what is called `auto-…` and nothing
    // else. So a hand-typed tag that would pass for the scheduler's is
    // refused here rather than silently becoming a snapshot that expires.
    asterism_core::rewind::check_human_tag(tag)?;
    let hv = backend::for_instance(inst)?;
    if !hv.caps().disk_snapshot {
        anyhow::bail!(
            "the {} backend cannot snapshot {:?}'s disk",
            hv.id(),
            inst.name
        );
    }
    // Materialise the root disk if this instance has never been booted:
    // `ast snapshot` on a freshly created instance has always worked, and the
    // engine below takes the disk as a given rather than making one.
    let req = backend::disk_req(inst)?;
    hv.prepare(&req)
        .with_context(|| format!("preparing {:?}'s disk", inst.name))?;
    // Through the same engine the scheduler uses, and that is the point: a
    // tag is a tag. A hand-typed snapshot that captured only the root disk
    // would appear on the timeline beside the automatic ones and then roll
    // back less than they do — `ast rewind --to <it>` would leave every
    // attached directory where it was, silently.
    crate::rewind::take(inst, tag, asterism_core::rewind::Kind::Named)
        .map(|_| ())
        .with_context(|| format!("snapshotting {:?}", inst.name))
}

/// Clone the volumes a later restore could be asked to roll back.
///
/// Only volumes whose bytes are on *this* device: a snapshot is a
/// copy-on-write clone of a file, and a file on somebody else's disk is not
/// one this device can clone. A memory volume served from another device is
/// therefore not captured, and it is said out loud rather than silently
/// producing a snapshot that `--include-memory` would find nothing behind.
///
/// A failure here is not fatal to the snapshot. The root disk is already
/// cloned and rolling it back is the thing the user asked for; a memory
/// volume that could not be captured makes `--include-memory` unavailable
/// for this tag, which is a smaller loss than refusing the snapshot.
pub(crate) fn capture_volumes(inst: &Instance, tag: &str) -> Result<()> {
    for vol in rollback_volumes(inst) {
        let dir = asterism_core::paths::volume_dir(&vol.path);
        let disk = asterism_core::paths::volume_image_path(&vol.path);
        if !disk.is_file() {
            eprintln!(
                "astd: {}'s {} volume {:?} has no image on this device, so snapshot {tag:?} \
                 cannot include it",
                inst.name,
                vol.lifecycle(),
                vol.path
            );
            continue;
        }
        std::fs::create_dir_all(asterism_core::snapshot::dir(&dir))
            .with_context(|| format!("preparing snapshots for volume {:?}", vol.path))?;
        // Idempotent for the same reason the root disk's is not: two
        // instances may snapshot under the same timestamp tag, and a volume
        // is a device-wide object. An existing clone of this tag is this
        // tag's clone.
        if asterism_core::snapshot::path(&dir, tag)?.is_file() {
            continue;
        }
        if let Err(e) = asterism_core::snapshot::take(&dir, &disk, tag) {
            eprintln!(
                "astd: could not capture {:?} in snapshot {tag:?}, so restoring it will not \
                 be offered: {e:#}",
                vol.path
            );
        }
    }
    Ok(())
}

/// Delete the volume clones one tag captured.
///
/// The other half of [`capture_volumes`], and it has to exist: a volume's
/// clones live beside the volume's own bytes rather than inside the
/// instance's snapshot directory, so deleting the instance's snapshot does
/// not reach them. Without this, an automatic snapshot every few minutes
/// would leave a clone per volume per tick that nothing ever pruned.
///
/// Never fatal. A clone that could not be deleted is disk somebody has to
/// reclaim by hand, not a reason to fail the prune that was reclaiming the
/// rest.
pub(crate) fn release_volumes(inst: &Instance, tag: &str) {
    for vol in rollback_volumes(inst) {
        let dir = asterism_core::paths::volume_dir(&vol.path);
        match asterism_core::snapshot::path(&dir, tag) {
            Ok(path) if !path.is_file() => continue,
            Ok(_) => {}
            Err(_) => continue,
        }
        if let Err(e) = asterism_core::snapshot::remove(&dir, tag) {
            eprintln!(
                "astd: {}: volume {:?} still holds the clone taken for snapshot {tag:?}: {e:#}",
                inst.name, vol.path
            );
        }
    }
}

/// The instance's block volumes a snapshot captures and a restore may roll
/// back, in the order they are attached.
///
/// Two filters that are not the same rule. Locality is a fact about this
/// device: a snapshot is a copy-on-write clone of a file, and a file on
/// another device's disk is not one this device can clone. The lifecycle
/// filter is the policy, and it lives in `asterism_core::volume` so that
/// `ast rewind` (AST-153) reads the same table this does rather than
/// reimplementing "which volumes does a rewind touch" a second time.
pub(crate) fn rollback_volumes(
    inst: &Instance,
) -> impl Iterator<Item = &asterism_core::instance::Volume> {
    inst.volumes.iter().filter(|v| {
        v.is_block() && v.is_local() && asterism_core::volume::captured_by_snapshot(v.lifecycle())
    })
}

fn list(inst: &Instance) -> Result<Vec<asterism_core::snapshot::Snapshot>> {
    let hv = backend::for_instance(inst)?;
    if !hv.caps().disk_snapshot {
        return Ok(Vec::new());
    }
    let req = backend::disk_req(inst)?;
    let prep = hv.prepare(&req)?;
    hv.disk_snapshot_list(&prep)
}

fn restore(inst: &Instance, tag: &str, include_memory: bool) -> Result<()> {
    let hv = backend::for_instance(inst)?;
    if !hv.caps().disk_snapshot {
        anyhow::bail!(
            "the {} backend cannot roll {:?}'s disk back",
            hv.id(),
            inst.name
        );
    }
    let req = backend::disk_req(inst)?;
    let prep = hv.prepare(&req)?;
    hv.disk_restore(&prep, &SnapshotId(tag.to_owned()))
        .with_context(|| {
            format!(
                "restoring {:?} — see: ast snapshots {}",
                inst.name, inst.name
            )
        })?;
    revert_volumes(inst, tag, include_memory)
}

/// Roll back the volumes this restore was asked to include.
///
/// The default is to include none of them, and that is the whole feature: an
/// instance rewound twenty minutes comes back with its root disk as it was
/// and its `~/.claude` as it *is*, so `claude --resume` continues the same
/// conversation across the rewind. `--include-memory` is the deliberate
/// stronger thing, for a rewind meant to undo what the agent learned as well
/// as what it did.
///
/// The root disk is already back at this point. A volume that fails to roll
/// back is therefore reported and not unwound — leaving the disk half in the
/// past would be worse than leaving one volume in the present, and the user
/// can run the restore again.
pub(crate) fn revert_volumes(inst: &Instance, tag: &str, include_memory: bool) -> Result<()> {
    let mut failed: Vec<String> = Vec::new();
    for vol in rollback_volumes(inst) {
        if !asterism_core::volume::reverts_with_instance(vol.lifecycle(), include_memory) {
            continue;
        }
        let dir = asterism_core::paths::volume_dir(&vol.path);
        let disk = asterism_core::paths::volume_image_path(&vol.path);
        if !asterism_core::snapshot::path(&dir, tag)?.is_file() {
            failed.push(format!(
                "{:?} was not captured in snapshot {tag:?}, so there is nothing to roll it \
                 back to",
                vol.path
            ));
            continue;
        }
        if let Err(e) = asterism_core::snapshot::restore(&dir, &disk, tag) {
            failed.push(format!("{:?}: {e:#}", vol.path));
        }
    }
    if failed.is_empty() {
        return Ok(());
    }
    anyhow::bail!(
        "{:?}'s root disk is back at {tag:?}, but {} — run the restore again once that is \
         fixed",
        inst.name,
        failed.join("; ")
    )
}

fn remove(inst: &Instance, tag: &str) -> Result<()> {
    // Before the instance's own, so a failure to delete the root disk's
    // snapshot leaves nothing claiming to be part of a tag that is gone.
    release_volumes(inst, tag);
    let hv = backend::for_instance(inst)?;
    if !hv.caps().disk_snapshot {
        anyhow::bail!("the {} backend keeps no disk snapshots to delete", hv.id());
    }
    let req = backend::disk_req(inst)?;
    let prep = hv.prepare(&req)?;
    hv.disk_snapshot_remove(&prep, &SnapshotId(tag.to_owned()))
        .with_context(|| {
            format!(
                "deleting a snapshot of {:?} — see: ast snapshots {}",
                inst.name, inst.name
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// [`claims`] and [`serve`] have to agree, because the first decides
    /// whether the second ever runs: a frame claimed here and not matched
    /// there would be answered with "is not a snapshot request" by the very
    /// module that owns it.
    #[test]
    fn every_frame_this_module_claims_is_one_it_answers() {
        for req in [
            Request::Snapshot {
                name: "dev".into(),
                tag: "t".into(),
            },
            Request::SnapshotList { name: "dev".into() },
            Request::SnapshotRestore {
                name: "dev".into(),
                tag: "t".into(),
                include_memory: false,
            },
            Request::SnapshotRemove {
                name: "dev".into(),
                tag: "t".into(),
            },
        ] {
            assert!(claims(&req), "{req:?}");
        }
        // A snapshot is about one instance, so it resolves across the orbit
        // like every other instance command — `ast snapshots dev` typed on a
        // laptop must reach the device holding `dev`.
        assert_eq!(
            Request::SnapshotList { name: "dev".into() }.subject(),
            Some("dev")
        );
    }

    fn instance_with(volumes: Vec<asterism_core::instance::Volume>) -> Instance {
        let mut inst = Instance::new(
            "bot",
            &asterism_core::instance::local_host(),
            "debian:13",
            Default::default(),
            asterism_core::hv::Machine {
                backend: "vz".into(),
                machine_type: "virt".into(),
                cpu: "host".into(),
                hv_version: "test".into(),
            },
        );
        inst.volumes = volumes;
        inst
    }

    /// Which of an instance's parts a snapshot even looks at.
    ///
    /// A cache is excluded here rather than at restore time, and that is the
    /// deliberate half: a cache clone would be the largest file in the orbit
    /// and nothing would ever roll it back.
    #[test]
    fn a_snapshot_captures_memory_and_never_a_cache() {
        use asterism_core::instance::Volume;
        use asterism_core::volume::Lifecycle;
        let here = asterism_core::instance::local_host();
        let inst = instance_with(vec![
            Volume::dir("/tank/media", &here, None),
            Volume::block("tank", &here, 1, 1 << 30),
            Volume::block("bot-claude-memory", &here, 1, 1 << 30)
                .placed(Some("/home/ast/.claude".into()), Lifecycle::Memory),
            Volume::block("cache-agent-toolchain", &here, 1, 1 << 30)
                .placed(Some("/var/cache/asterism".into()), Lifecycle::Cache),
            // Somebody else's disk: this device has no file to clone.
            Volume::block("far-memory", "desktop", 1, 1 << 30)
                .placed(Some("/home/ast/.codex".into()), Lifecycle::Memory),
        ]);
        let captured: Vec<&str> = rollback_volumes(&inst).map(|v| v.path.as_str()).collect();
        assert_eq!(captured, vec!["tank", "bot-claude-memory"]);
    }

    /// The whole point, as a table: what a restore actually rolls back.
    #[test]
    fn a_restore_leaves_memory_alone_unless_it_is_asked_not_to() {
        use asterism_core::instance::Volume;
        use asterism_core::volume::{reverts_with_instance, Lifecycle};
        let here = asterism_core::instance::local_host();
        let inst = instance_with(vec![
            Volume::block("tank", &here, 1, 1 << 30),
            Volume::block("bot-claude-memory", &here, 1, 1 << 30)
                .placed(Some("/home/ast/.claude".into()), Lifecycle::Memory),
            Volume::block("cache-agent-toolchain", &here, 1, 1 << 30)
                .placed(Some("/var/cache/asterism".into()), Lifecycle::Cache),
        ]);
        let reverted = |include_memory: bool| -> Vec<&str> {
            rollback_volumes(&inst)
                .filter(|v| reverts_with_instance(v.lifecycle(), include_memory))
                .map(|v| v.path.as_str())
                .collect()
        };
        assert_eq!(
            reverted(false),
            vec!["tank"],
            "a plain rewind takes the instance's own data back and leaves the \
             conversation where it is"
        );
        assert_eq!(reverted(true), vec!["tank", "bot-claude-memory"]);
    }

    /// The shard's own commands are not this module's, or `ast up` would be
    /// answered by a match that has never heard of it.
    #[test]
    fn the_shards_own_commands_are_left_alone() {
        assert!(!claims(&Request::List));
        assert!(!claims(&Request::Up {
            name: "dev".into(),
            restart: None
        }));
        assert!(!claims(&Request::Status { name: "dev".into() }));
        assert!(!claims(&Request::VolumeList));
    }
}
