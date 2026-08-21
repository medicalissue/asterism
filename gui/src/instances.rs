//! The Instances section: the orbit registry as rows.
//!
//! `ast ls` and this table are the same question — [`Request::ListOrbit`] —
//! so a row here says what a row there says: the name, what it is doing, the
//! device supplying its cpu and ram, the backend it was defined against and
//! the shape it was cut to. What it is *assembled from* is
//! [`Instance::parts`], carried through whole rather than restated: the
//! orbit's own vocabulary for a disk, a share, a lease and a published port
//! is more accurate than any second one this window could invent.
//!
//! The gates live here too, and only here. `astd` refuses `Up` on a running
//! guest, refuses `Snapshot` and `SnapshotRestore` on anything that is *not*
//! stopped, answers almost nothing on an instance whose name turned out not
//! to be unique, and answers only reads on one whose bytes are in flight to
//! another device. The tray greys its items on those rules and the window
//! disables its buttons on them, and both read them from [`Gates`] rather
//! than each keeping a copy that could drift from the daemon's.
//!
//! [`Request::ListOrbit`]: asterism_core::protocol::Request::ListOrbit

use serde::Serialize;

use asterism_core::instance::{Instance, Policy, Restart, Shape, Status};
use asterism_core::registry::OrbitRow;

use crate::client;

// ---- the gates -------------------------------------------------------------
//
// One statement of the daemon's rules, consumed by both surfaces. A window
// that offered a snapshot on a running guest would only be arranging for an
// error, and a tray that refused one on a never-booted instance would be
// hiding something the daemon allows.

/// What an instance will answer, resolved once from its whole state.
///
/// Four things decide these and they are all the daemon's: whether the
/// device holding the instance answered at all, what the guest is doing,
/// whether the name turned out not to be unique, and whether the bytes are
/// in flight to another device. Nothing above this module restates them.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Gates {
    pub can_start: bool,
    pub can_stop: bool,
    pub can_shell: bool,
    /// `Logs` is a read, and a read is what a fenced or conflicted instance
    /// is still worth having: it is the only current evidence of why a
    /// guest is not running.
    pub can_read_logs: bool,
    pub can_read_snapshots: bool,
    /// Take, restore *and* delete. The daemon refuses all three on a
    /// running guest, because all three rewrite a disk it is holding open.
    pub can_snapshot: bool,
    pub can_rename: bool,
    pub can_remove: bool,
}

impl Gates {
    /// The gates for one instance on a device that either answered or did
    /// not.
    ///
    /// Nothing that mutates is offered on a row whose device is out of
    /// touch: the request would be forwarded to a daemon that is not there.
    pub fn of(instance: &Instance, live: bool) -> Gates {
        let running = instance.status == Status::Running;
        let conflicted = instance.conflict.is_some();
        let moving = instance.moving.is_some();
        // A move fences everything that could write, on either side of the
        // transfer: there is one copy of these bytes and it is being carried.
        let settled = live && !moving;
        let read_snapshots = settled && !conflicted;
        Gates {
            can_start: settled && !running && !conflicted,
            // `Down` survives a conflict on purpose: `Rename` is the remedy
            // and it will not touch a running guest, so an instance that is
            // both conflicted and running would otherwise have no legal move.
            can_stop: settled && running,
            can_shell: settled && running && !conflicted,
            can_read_logs: live,
            can_read_snapshots: read_snapshots,
            can_snapshot: read_snapshots && !running,
            // Rename is the one thing a conflicted instance answers, because
            // it is the only thing that ends the conflict.
            can_rename: settled && !running,
            can_remove: settled && !running && !conflicted,
        }
    }
}

// ---- the rows --------------------------------------------------------------

/// One instance, as the table sees it.
///
/// The `can_*` fields are [`Gates`], resolved once here so that the webview
/// never restates a rule: it draws a disabled button because Rust said so,
/// the same way the tray greys an item because Rust said so.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Row {
    /// The instance's own id. Stable across a rename, which is what makes
    /// it worth carrying alongside the name.
    pub id: String,
    pub name: String,
    /// `running`, `stopped` or `defined`, in the daemon's own words, or
    /// `unknown` when the device holding it did not answer.
    pub status: String,
    /// What the registry last recorded, when `status` is `unknown`. A
    /// memory presented as a memory: "Last known: running" is true where
    /// "running" would not be.
    pub last_status: Option<String>,
    /// Whether the shard this row came from answered just now. A stale row
    /// is still worth showing — the alternative reads as "deleted" — but it
    /// must not claim to know what the instance is doing.
    pub live: bool,
    /// The device supplying its cpu and ram.
    pub cpu_device: String,
    /// The backend it was defined against. Creation records this before the
    /// instance enters the registry.
    pub backend: String,
    /// `2 CPU · 2 GB · 20 GB`, formatted once so the dump and the table
    /// cannot disagree.
    pub shape: String,
    /// The source used to define this machine. Kept as a reference rather
    /// than guessed into a friendlier product name.
    pub image: String,
    /// Unix seconds.
    pub created_at: u64,
    /// `always` or `never`, the daemon's own words for what its supervisor
    /// does when this guest dies.
    pub policy_restart: String,
    pub policy_max_attempts: u32,
    /// What that policy actually promises, in one sentence. Written here
    /// rather than in the webview, because getting it wrong is the easiest
    /// untruth in this pane to tell (see [`policy_sentence`]).
    pub policy_sentence: String,
    /// Everything this instance is assembled from, in [`Instance::parts`]
    /// order and wording.
    pub parts: Vec<PartRow>,
    /// Set when this name turned out not to be unique in the orbit.
    pub conflict: Option<ConflictRow>,
    /// Set while the cpu part is being carried to another device.
    pub moving: Option<MovingRow>,
    /// How many times the cpu part has already been carried.
    pub move_epoch: u64,
    #[serde(flatten)]
    pub gates: Gates,
}

/// One row of [`Instance::parts`], on its way to a table.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PartRow {
    /// `cpu/ram`, `disk`, `volume`, `secret`, `network`, `gpu`.
    pub kind: String,
    /// The device supplying it, or `-` when nothing does.
    pub source: String,
    pub detail: String,
    pub note: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ConflictRow {
    /// The device supplying cpu/ram to the other instance of this name.
    pub other_cpu_device: String,
    /// When the orbit noticed, Unix seconds.
    pub found_at: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct MovingRow {
    pub to_device: String,
    /// The epoch this move will land on. A fence number, not a progress
    /// value — the wire carries no byte count, so nothing here may look
    /// like one.
    pub epoch: u64,
    /// When the fence went up, Unix seconds.
    pub started_at: u64,
}

impl Row {
    pub fn of(instance: &Instance, live: bool) -> Row {
        // An unreachable device's row is a memory of a status, not a
        // status. Saying `running` about a machine nobody can reach is the
        // one lie a fleet view must not tell.
        let word = instance.status.to_string();
        let (status, last_status) =
            if live { (word, None) } else { ("unknown".to_owned(), Some(word)) };
        Row {
            id: instance.id.clone(),
            name: instance.name.clone(),
            status,
            last_status,
            live,
            cpu_device: instance.cpu_device.clone(),
            backend: instance.machine.backend.clone(),
            shape: shape(&instance.shape),
            image: instance.image.clone().unwrap_or_else(|| "unknown".to_owned()),
            created_at: instance.created_at,
            policy_restart: instance.policy.restart.to_string(),
            policy_max_attempts: instance.policy.max_attempts,
            policy_sentence: policy_sentence(instance.policy),
            parts: instance
                .parts()
                .into_iter()
                .map(|part| PartRow {
                    kind: part.kind,
                    source: part.source,
                    detail: part.detail,
                    note: part.note,
                })
                .collect(),
            conflict: instance.conflict.as_ref().map(|c| ConflictRow {
                other_cpu_device: c.other_cpu_device.clone(),
                found_at: c.found_at,
            }),
            moving: instance.moving.as_ref().map(|m| MovingRow {
                to_device: m.to_device.clone(),
                epoch: m.epoch,
                started_at: m.started_at,
            }),
            move_epoch: instance.move_epoch,
            gates: Gates::of(instance, live),
        }
    }

}

/// What a restart policy actually promises, in one sentence.
///
/// `always` does not mean "starts on every reboot", and this is the sentence
/// that must not say it does: a deliberate `Down` stays down across one.
/// What it means is that a guest that *was* running is brought back — after
/// an unexpected death, and after the device it runs on reboots.
///
/// What it also does not say is why a stopped instance is stopped. The wire
/// carries no restart-attempt count, so `always` plus `stopped` describes a
/// deliberate shutdown exactly as well as it describes a supervisor that
/// gave up, and this pane is not entitled to guess which. The console and
/// the daemon log are the evidence.
fn policy_sentence(policy: Policy) -> String {
    match policy.restart {
        Restart::Never => "Asterism starts it only when you ask.".to_owned(),
        Restart::Always => format!(
            "If it was running, astd restarts it after an unexpected stop or device \
             reboot, up to {} attempts. Stop remains stopped.",
            policy.max_attempts
        ),
    }
}

/// `2 CPU · 2 GB · 20 GB`. Memory is stored in MiB and shown in GB, because
/// nobody sizes a machine in mebibytes; a half-gigabyte guest keeps its
/// fraction rather than rounding to a number that is not what it has.
fn shape(shape: &Shape) -> String {
    format!(
        "{} CPU · {} · {} GB",
        shape.cpus,
        gigabytes(shape.mem_mib),
        shape.disk_gib
    )
}

fn gigabytes(mib: u32) -> String {
    if mib.is_multiple_of(1024) {
        return format!("{} GB", mib / 1024);
    }
    format!("{:.1} GB", f64::from(mib) / 1024.0)
}

/// What the daemon has to say, which is the whole section.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Fleet {
    /// The daemon could not be reached, with the reason. Not an error path:
    /// a window that emptied itself when its daemon hiccupped would be
    /// reporting a deleted fleet.
    Unreachable { reason: String },
    /// What the orbit registry says it has; may be empty.
    Rows { rows: Vec<Row> },
}

/// The Instances section, whole.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Instances {
    pub fleet: Fleet,
}

impl Instances {
    /// Ask the daemon for the orbit registry.
    pub fn load() -> Instances {
        match client::list_orbit() {
            Ok(rows) => Instances::of(&rows),
            Err(e) => Instances { fleet: Fleet::Unreachable { reason: format!("{e:#}") } },
        }
    }

    /// Build a section out of rows somebody else already has.
    pub fn of(rows: &[OrbitRow]) -> Instances {
        Instances {
            fleet: Fleet::Rows { rows: rows.iter().map(|r| Row::of(&r.instance, r.live)).collect() },
        }
    }

    /// The section as text, one line per row, for `--dump-main instances`.
    /// Generated from the data the table renders, so it cannot describe a
    /// table other than the one on screen.
    pub fn lines(&self) -> Vec<String> {
        let mut out = vec!["section instances".to_owned()];
        match &self.fleet {
            Fleet::Unreachable { reason } => out.push(format!("unreachable {reason}")),
            Fleet::Rows { rows } if rows.is_empty() => out.push("empty".to_owned()),
            Fleet::Rows { rows } => {
                for row in rows {
                    out.push(format!(
                        "instance {:<16} {:<8} cpu={:<14} backend={:<6} shape={}",
                        row.name,
                        row.status,
                        row.cpu_device,
                        if row.backend.is_empty() { "-" } else { &row.backend },
                        row.shape
                    ));
                    out.push(format!(
                        "  policy restart={} max-attempts={}",
                        row.policy_restart, row.policy_max_attempts
                    ));
                    if let Some(conflict) = &row.conflict {
                        out.push(format!(
                            "  conflict other-cpu={} found-at={}",
                            conflict.other_cpu_device, conflict.found_at
                        ));
                    }
                    if let Some(moving) = &row.moving {
                        out.push(format!(
                            "  moving to={} epoch={} started-at={}",
                            moving.to_device, moving.epoch, moving.started_at
                        ));
                    }
                    out.push(format!("  move-epoch {}", row.move_epoch));
                    out.push(format!(
                        "  actions up={} down={} terminal={} logs={} snapshot-list={} \
                         snapshot={} rename={} remove={}",
                        on(row.gates.can_start),
                        on(row.gates.can_stop),
                        on(row.gates.can_shell),
                        on(row.gates.can_read_logs),
                        on(row.gates.can_read_snapshots),
                        on(row.gates.can_snapshot),
                        on(row.gates.can_rename),
                        on(row.gates.can_remove),
                    ));
                    for part in &row.parts {
                        out.push(format!(
                            "  part {:<8} source={:<14} {}{}",
                            part.kind,
                            part.source,
                            part.detail,
                            part.note.as_deref().map(|n| format!(" — {n}")).unwrap_or_default()
                        ));
                    }
                }
            }
        }
        out
    }
}

fn on(enabled: bool) -> &'static str {
    if enabled {
        "enabled"
    } else {
        "disabled"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use asterism_core::hv::Machine;
    use asterism_core::instance::{Conflict, Moving};

    fn machine(backend: &str) -> Machine {
        Machine {
            backend: backend.into(),
            machine_type: "virt".into(),
            cpu: "host".into(),
            hv_version: "test".into(),
        }
    }

    fn instance(name: &str, status: Status) -> Instance {
        let mut instance =
            Instance::new(name, "laptop", "debian:13", Shape::default(), machine("qemu"));
        instance.status = status;
        instance
    }

    fn conflicted(name: &str, status: Status) -> Instance {
        let mut instance = instance(name, status);
        instance.conflict =
            Some(Conflict { other_cpu_device: "desktop".into(), found_at: 1_700_000_000 });
        instance
    }

    fn moving(name: &str, status: Status) -> Instance {
        let mut instance = instance(name, status);
        instance.moving =
            Some(Moving { to_device: "desktop".into(), epoch: 3, started_at: 1_700_000_000 });
        instance
    }

    /// The eight gates, spelled out for every state that changes one. This
    /// is the whole matrix: both surfaces read it, so a change here is a
    /// change to the tray and the window at once.
    #[test]
    fn the_gate_matrix_is_the_daemons_and_not_a_narrower_one() {
        // A stopped, reachable, unencumbered instance: everything but Stop
        // and a terminal.
        let g = Gates::of(&instance("dev", Status::Stopped), true);
        assert!(g.can_start && !g.can_stop && !g.can_shell);
        assert!(g.can_read_logs && g.can_read_snapshots && g.can_snapshot);
        assert!(g.can_rename && g.can_remove);

        // A never-booted instance has a disk, so it may be snapshotted.
        let g = Gates::of(&instance("dev", Status::Defined), true);
        assert!(g.can_start && g.can_snapshot && g.can_rename && g.can_remove);

        // Running: stop it and shell into it. Its disk is held open, and a
        // rename or a removal would go through that disk too.
        let g = Gates::of(&instance("dev", Status::Running), true);
        assert!(!g.can_start && g.can_stop && g.can_shell);
        assert!(g.can_read_logs && g.can_read_snapshots && !g.can_snapshot);
        assert!(!g.can_rename && !g.can_remove);
    }

    /// A conflicted instance answers `Down`, `Status` and `Rename`, and
    /// nothing else. Running, the only move is to stop it; stopped, the
    /// only move is to rename it — which is exactly what ends the conflict.
    #[test]
    fn a_conflicted_row_offers_the_way_out_of_the_conflict_and_nothing_else() {
        let running = Gates::of(&conflicted("dev", Status::Running), true);
        assert!(running.can_stop, "stopping it is the first half of the remedy");
        assert!(!running.can_start && !running.can_shell);
        assert!(!running.can_rename, "rename will not touch a running guest");
        assert!(!running.can_remove && !running.can_snapshot);
        assert!(!running.can_read_snapshots, "SnapshotList does not survive a conflict");
        assert!(running.can_read_logs, "the console is the evidence, and it is a read");

        let stopped = Gates::of(&conflicted("dev", Status::Stopped), true);
        assert!(stopped.can_rename, "renaming it is the remedy");
        assert!(!stopped.can_start && !stopped.can_stop && !stopped.can_shell);
        assert!(!stopped.can_remove, "Remove does not survive a conflict");
        assert!(!stopped.can_snapshot && !stopped.can_read_snapshots);
    }

    /// An instance whose bytes are in flight answers only what cannot
    /// change them: there is one copy and it is being carried.
    #[test]
    fn a_moving_row_is_read_only_whatever_its_guest_was_doing() {
        for status in [Status::Running, Status::Stopped, Status::Defined] {
            let g = Gates::of(&moving("dev", status), true);
            assert!(!g.can_start && !g.can_stop && !g.can_shell, "{status}");
            assert!(!g.can_snapshot && !g.can_read_snapshots, "{status}");
            assert!(!g.can_rename && !g.can_remove, "{status}");
            assert!(g.can_read_logs, "{status}: a fence is a state you may look at");
        }
    }

    /// A row from a device that did not answer is a memory. Reporting the
    /// last known status as the current one, and offering actions that would
    /// be forwarded to a daemon nobody can reach, are the same mistake.
    #[test]
    fn a_row_from_a_silent_device_claims_nothing_and_offers_nothing() {
        let row = Row::of(&instance("dev", Status::Running), false);
        assert_eq!(row.status, "unknown");
        assert_eq!(row.last_status.as_deref(), Some("running"));
        let g = row.gates;
        assert!(!g.can_start && !g.can_stop && !g.can_shell);
        assert!(!g.can_snapshot && !g.can_read_snapshots);
        assert!(!g.can_rename && !g.can_remove);
        assert!(!g.can_read_logs, "the read is routed through the daemon that is not there");

        // A reachable row says what it is doing and remembers nothing,
        // because there is nothing to remember.
        let live = Row::of(&instance("dev", Status::Running), true);
        assert_eq!(live.status, "running");
        assert_eq!(live.last_status, None);
    }

    #[test]
    fn a_row_names_the_device_supplying_its_cpu_and_the_backend_it_was_cut_against() {
        let mut inst = instance("dev", Status::Stopped);
        inst.machine = machine("vz");
        let row = Row::of(&inst, true);
        assert_eq!(row.cpu_device, "laptop");
        assert_eq!(row.backend, "vz");

        assert_eq!(Row::of(&instance("dev", Status::Stopped), true).backend, "qemu");
    }

    #[test]
    fn a_shape_reads_in_the_units_a_person_sizes_a_machine_in() {
        let row = Row::of(&instance("dev", Status::Stopped), true);
        assert_eq!(row.shape, "2 CPU · 2 GB · 20 GB");

        let mut half = instance("dev", Status::Stopped);
        half.shape = Shape { cpus: 1, mem_mib: 512, disk_gib: 5 };
        assert_eq!(Row::of(&half, true).shape, "1 CPU · 0.5 GB · 5 GB");
    }

    /// The parts table is `Instance::parts()`, carried through in its own
    /// order and its own words. A window that rewrote them would be
    /// inventing a second vocabulary for the same machine.
    #[test]
    fn the_parts_are_the_instances_own_in_its_own_order() {
        let mut inst = instance("dev", Status::Stopped);
        inst.publish = vec!["8080:80".parse().expect("a port forward")];
        let row = Row::of(&inst, true);

        let kinds: Vec<&str> = row.parts.iter().map(|p| p.kind.as_str()).collect();
        assert_eq!(kinds, ["cpu/ram", "disk", "network", "gpu"]);

        let wire = inst.parts();
        assert_eq!(row.parts.len(), wire.len());
        for (got, want) in row.parts.iter().zip(&wire) {
            assert_eq!((&got.kind, &got.source, &got.detail, &got.note), (
                &want.kind,
                &want.source,
                &want.detail,
                &want.note
            ));
        }

        // Published ports are already on the network row, which is why the
        // window has no separate "not exposed yet" block to show.
        let network = row.parts.iter().find(|p| p.kind == "network").expect("a network part");
        assert!(network.detail.contains("8080"), "{}", network.detail);
    }

    /// `always` is not "starts on every reboot", and the sentence must not
    /// say it is: a deliberate Stop survives one.
    #[test]
    fn the_policy_sentence_promises_what_the_supervisor_actually_does() {
        let row = Row::of(&instance("dev", Status::Stopped), true);
        assert_eq!(row.policy_restart, "always");
        let says = &row.policy_sentence;
        assert!(says.contains("If it was running"), "{says}");
        assert!(says.contains("Stop remains stopped."), "{says}");
        assert!(says.contains(&row.policy_max_attempts.to_string()), "{says}");
        // Never the two things the wire cannot support.
        assert!(!says.contains("every reboot"), "{says}");
        for guess in ["crashed", "gave up", "exhausted"] {
            assert!(!says.contains(guess), "{says}");
        }

        let mut once = instance("dev", Status::Stopped);
        once.policy = Policy::never();
        let row = Row::of(&once, true);
        assert_eq!(row.policy_restart, "never");
        assert_eq!(row.policy_sentence, "Asterism starts it only when you ask.");
    }

    #[test]
    fn an_empty_orbit_and_an_unreachable_daemon_do_not_look_alike() {
        assert_eq!(Instances::of(&[]).lines(), vec!["section instances", "empty"]);

        let down = Instances { fleet: Fleet::Unreachable { reason: "no socket".into() } };
        assert_eq!(down.lines()[1], "unreachable no socket");
    }

    #[test]
    fn dumping_the_section_names_every_row_what_it_offers_and_what_it_is_made_of() {
        let rows = vec![
            OrbitRow { instance: instance("dev", Status::Running), live: true },
            OrbitRow { instance: instance("build", Status::Stopped), live: false },
        ];
        let lines = Instances::of(&rows).lines().join("\n");
        assert!(lines.contains("instance dev              running "), "{lines}");
        assert!(lines.contains("cpu=laptop"), "{lines}");
        assert!(lines.contains("shape=2 CPU · 2 GB · 20 GB"), "{lines}");
        assert!(lines.contains("policy restart=always max-attempts="), "{lines}");
        assert!(lines.contains("move-epoch 0"), "{lines}");
        assert!(
            lines.contains(
                "actions up=disabled down=enabled terminal=enabled logs=enabled \
                 snapshot-list=enabled snapshot=disabled rename=disabled remove=disabled"
            ),
            "{lines}"
        );
        assert!(lines.contains("part cpu/ram  source=laptop"), "{lines}");
        assert!(lines.contains("part disk     source=laptop"), "{lines}");
        assert!(lines.contains("part network  source=laptop"), "{lines}");
        assert!(lines.contains("instance build            unknown "), "{lines}");
    }

    /// The fence states have to reach the dump, or a two-device proof
    /// cannot assert on them.
    #[test]
    fn a_conflict_and_a_move_are_named_in_the_dump() {
        let rows = vec![OrbitRow { instance: conflicted("dev", Status::Running), live: true }];
        let lines = Instances::of(&rows).lines().join("\n");
        assert!(lines.contains("conflict other-cpu=desktop found-at=1700000000"), "{lines}");

        let rows = vec![OrbitRow { instance: moving("dev", Status::Stopped), live: true }];
        let lines = Instances::of(&rows).lines().join("\n");
        assert!(lines.contains("moving to=desktop epoch=3 started-at=1700000000"), "{lines}");
    }

    /// The rows cross to the webview as JSON, so their field names are an
    /// interface; renaming one silently would leave a table drawing blanks.
    #[test]
    fn a_row_reaches_the_webview_under_the_names_it_reads() {
        let json = serde_json::to_value(Row::of(&instance("dev", Status::Running), true)).unwrap();
        for key in [
            "id",
            "name",
            "status",
            "live",
            "cpu_device",
            "backend",
            "shape",
            "image",
            "created_at",
            "policy_restart",
            "policy_max_attempts",
            "policy_sentence",
            "parts",
            "conflict",
            "moving",
            "move_epoch",
            "can_start",
            "can_stop",
            "can_shell",
            "can_read_logs",
            "can_read_snapshots",
            "can_snapshot",
            "can_rename",
            "can_remove",
        ] {
            assert!(json.get(key).is_some(), "a row has no {key:?}: {json}");
        }
        // The gates are flattened rather than nested: the webview reads
        // `row.can_start`, which is also how the tray reads it.
        assert_eq!(json["can_stop"], serde_json::json!(true));
        assert!(json.get("gates").is_none(), "the gates are not a sub-object: {json}");

        // The fleet is tagged, so the webview tells "nothing here" from
        // "nobody answered" by looking at one field.
        let down = serde_json::to_value(Instances {
            fleet: Fleet::Unreachable { reason: "no socket".into() },
        })
        .unwrap();
        assert_eq!(down["fleet"]["kind"], serde_json::json!("unreachable"));
        assert_eq!(
            serde_json::to_value(Instances::of(&[])).unwrap()["fleet"]["kind"],
            serde_json::json!("rows")
        );
    }
}
