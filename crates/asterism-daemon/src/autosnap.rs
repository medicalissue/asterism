//! The snapshot scheduler: a snapshot every N minutes, and a day of them
//! kept.
//!
//! This is the half of `ast rewind` that runs when nobody is typing. It hangs
//! off the daemon the same way the crash supervisor does — one task, one
//! timer, started once in `main` and running for the life of the process —
//! and it exists so that the answer to "can I go back twenty minutes" is yes
//! without anybody having thought about it in advance.
//!
//! # One pass
//!
//! For every instance this device is running:
//!
//! 1. Work out its settings: its own if it has any,
//!    [`Settings::device_default`] otherwise.
//! 2. Prune the automatic snapshots that have outlived retention. Named ones
//!    and `before-rewind` are never touched — see
//!    [`asterism_core::rewind::expired`], which owns that rule and is tested
//!    on its own.
//! 3. If one is due, and the disk has moved since the last one, take it.
//!
//! Pruning happens before taking rather than after, so an instance at its
//! retention limit does not briefly hold one more snapshot than it was
//! configured for.
//!
//! # Why "has the disk moved" is a question worth asking
//!
//! An agent waiting on a human overnight writes nothing for eight hours. At
//! ten minutes apiece that is forty-eight identical clones, each of which is
//! a directory entry, a sidecar and a `clonefile(2)` — cheap, but forty-eight
//! rows of noise on a timeline whose whole job is to be readable. The check
//! is the root disk's length and mtime, which is the honest limit of what the
//! hypervisor boundary exposes; [`asterism_core::rewind::Fingerprint`] says
//! exactly what each backend can and cannot tell us.
//!
//! # Failures are logged, never fatal
//!
//! A snapshot that will not be taken is a line in the daemon log and a
//! retry at the next tick. There is no state in which this task stops
//! running, and no failure here that may stop a guest: an instance whose
//! disk is full should lose its next snapshot, not its next hour of work.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Mutex;

use asterism_core::instance::{Instance, Status};
use asterism_core::paths;
use asterism_core::registry::Shard;
use asterism_core::rewind::{self as model, Kind, Settings};
use asterism_core::snapshot;

/// How often the scheduler looks. Not how often a snapshot is taken — that
/// is the instance's own interval — but the granularity at which "due" is
/// noticed. Fifteen seconds keeps a one-minute interval honest (which the
/// e2e lane depends on) and costs a registry read.
const TICK: Duration = Duration::from_secs(15);

/// Start the scheduler. Runs for the life of the daemon.
pub(crate) fn supervise(registry: Arc<Mutex<Shard>>) -> tokio::task::JoinHandle<()> {
    let settings = Settings::device_default();
    eprintln!(
        "astd: automatic snapshots every {}, kept {} (per-instance: ast rewind <name> --every)",
        model::human_duration(settings.every_secs),
        model::human_duration(settings.keep_secs)
    );
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(TICK).await;
            tick(&registry).await;
        }
    })
}

/// One pass over everything this device is running.
async fn tick(registry: &Arc<Mutex<Shard>>) {
    // The list is taken under the lock and the work is done outside it. A
    // clone of a gigabyte disk is fast on a filesystem with reflinks and is
    // not fast on one without, and neither case is a reason for `ast ls` to
    // block behind it.
    let running: Vec<Instance> = {
        let reg = registry.lock().await;
        reg.list()
            .into_iter()
            .filter(|inst| inst.status == Status::Running && inst.boot_intent_id.is_none())
            .collect()
    };
    for inst in running {
        tokio::task::block_in_place(|| pass(&inst));
    }
}

/// Prune, then snapshot if one is due and anything has changed.
fn pass(inst: &Instance) {
    let settings = Settings::resolve(inst.rewind);
    let dir = paths::instance_dir(&inst.name);
    let entries = match model::read_entries(&dir) {
        Ok(entries) => entries,
        Err(error) => {
            eprintln!(
                "astd: {}: could not read its timeline: {error:#}",
                inst.name
            );
            return;
        }
    };
    let now = asterism_core::instance::now_unix();

    for tag in model::expired(&entries, now, settings.keep_secs) {
        // A tag is not only the instance's disk. Block volumes captured
        // under it are clones beside their own bytes, which this directory's
        // prune cannot see, so they are released by name here.
        crate::snapshot::release_volumes(inst, &tag);
        match snapshot::remove(&dir, &tag) {
            Ok(()) => {}
            Err(error) => eprintln!(
                "astd: {}: could not prune the expired snapshot {tag:?}: {error:#}",
                inst.name
            ),
        }
    }

    let newest_auto = entries
        .iter()
        .filter(|entry| entry.kind == Kind::Auto)
        .map(|entry| entry.taken_at)
        .max();
    if !model::due(newest_auto, now, settings.every_secs) {
        return;
    }
    if let Some(previous) = newest_auto.and_then(|_| newest_auto_meta(&dir, &entries)) {
        match crate::rewind::changed_since(inst, &previous) {
            Ok(false) => return, // nothing has been written since the last one
            Ok(true) => {}
            Err(error) => eprintln!(
                "astd: {}: could not tell whether its disk changed, snapshotting anyway: \
                 {error:#}",
                inst.name
            ),
        }
    }

    let tag = model::auto_tag(now);
    match crate::rewind::take(inst, &tag, Kind::Auto) {
        Ok(meta) => {
            for volume in meta.volumes.iter().filter(|v| v.not_snapshotted.is_some()) {
                // Said once per snapshot, because a rewind that leaves a
                // volume where it is must never be a surprise.
                eprintln!(
                    "astd: {}: {}",
                    inst.name,
                    volume.not_snapshotted.as_deref().unwrap_or_default()
                );
            }
        }
        Err(error) => eprintln!("astd: {}: no snapshot this pass: {error:#}", inst.name),
    }
}

/// The sidecar of the newest automatic snapshot, which is what the change
/// check compares against.
///
/// A snapshot with no sidecar — one taken by a build before this existed —
/// answers `None`, and the caller takes a snapshot rather than guessing that
/// nothing has changed since a disk state it has no record of.
fn newest_auto_meta(
    dir: &std::path::Path,
    entries: &[model::Entry],
) -> Option<asterism_core::rewind::Meta> {
    let newest = entries
        .iter()
        .filter(|entry| entry.kind == Kind::Auto)
        .max_by_key(|entry| entry.taken_at)?;
    model::read_meta(dir, &newest.tag)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The scheduler has to look often enough that the shortest interval it
    /// will accept is actually honoured, or `--every 30s` would be `--every
    /// whenever`.
    #[test]
    fn the_tick_is_finer_than_the_shortest_interval_settings_allow() {
        assert!(
            TICK.as_secs() < model::MIN_EVERY_SECS,
            "a {}s tick cannot deliver a {}s interval",
            TICK.as_secs(),
            model::MIN_EVERY_SECS
        );
    }

    /// The change check needs the previous snapshot's sidecar. Without one
    /// there is nothing to compare against, and the safe answer is to take
    /// the snapshot rather than to assume the disk is idle.
    #[test]
    fn a_snapshot_with_no_sidecar_does_not_stand_in_for_a_disk_state() {
        let dir = tempfile::tempdir().unwrap();
        let entries = vec![model::Entry {
            tag: "auto-x".into(),
            kind: Kind::Auto,
            taken_at: 10,
            bytes: 0,
            volumes: Vec::new(),
        }];
        assert!(newest_auto_meta(dir.path(), &entries).is_none());
    }

    /// Named snapshots are not the scheduler's, so the newest *automatic*
    /// one is what "when was the last pass" means — a `ast snapshot` taken a
    /// minute ago must not postpone the next automatic one.
    #[test]
    fn a_named_snapshot_does_not_count_as_the_last_automatic_pass() {
        let dir = tempfile::tempdir().unwrap();
        let entries = vec![
            model::Entry {
                tag: "release".into(),
                kind: Kind::Named,
                taken_at: 1_000,
                bytes: 0,
                volumes: Vec::new(),
            },
            model::Entry {
                tag: "auto-old".into(),
                kind: Kind::Auto,
                taken_at: 100,
                bytes: 0,
                volumes: Vec::new(),
            },
        ];
        let newest_auto = entries
            .iter()
            .filter(|entry| entry.kind == Kind::Auto)
            .map(|entry| entry.taken_at)
            .max();
        assert_eq!(newest_auto, Some(100));
        assert!(model::due(newest_auto, 1_001, 600));
        assert!(newest_auto_meta(dir.path(), &entries).is_none());
    }
}
