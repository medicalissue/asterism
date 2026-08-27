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
        Request::SnapshotRestore { name, tag } => reply(
            stopped(reg, &name)
                .and_then(|inst| tokio::task::block_in_place(|| restore(&inst, &tag))),
        ),
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
    let caps = hv.caps();
    if !caps.disk_snapshot {
        anyhow::bail!(
            "the {} backend cannot snapshot {:?}'s disk",
            hv.id(),
            inst.name
        );
    }
    let req = backend::disk_req(inst)?;
    let prep = hv.prepare(&req)?;
    hv.disk_snapshot(&prep, tag)
        .map(|_| ())
        .with_context(|| format!("snapshotting {:?}", inst.name))
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

fn restore(inst: &Instance, tag: &str) -> Result<()> {
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
        })
}

fn remove(inst: &Instance, tag: &str) -> Result<()> {
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
