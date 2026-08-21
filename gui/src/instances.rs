//! The Instances section: the orbit registry as rows.
//!
//! `ast ls` and this table are the same question — [`Request::ListOrbit`] —
//! so a row here says what a row there says: the name, what it is doing, the
//! device supplying its cpu and ram, the backend it was defined against and
//! the shape it was cut to.
//!
//! The gates live here too, and only here. `astd` refuses `Up` on a running
//! guest and refuses `Snapshot` and `SnapshotRestore` on anything that is
//! *not* stopped; the tray greys its items on those rules and the window
//! disables its buttons on them, and both read them from this module rather
//! than each keeping a copy that could drift from the daemon's.
//!
//! [`Request::ListOrbit`]: asterism_core::protocol::Request::ListOrbit

use serde::Serialize;

use asterism_core::instance::{Instance, Shape, Status, VolumeKind};
use asterism_core::registry::OrbitRow;

use crate::client;

// ---- the gates -------------------------------------------------------------
//
// One statement of the daemon's rule, consumed by both surfaces. A window
// that offered a snapshot on a running guest would only be arranging for an
// error, and a tray that refused one on a never-booted instance would be
// hiding something the daemon allows.

/// `Up` is for anything that is not already up.
pub fn can_start(status: Status) -> bool {
    status != Status::Running
}

/// `Down` is for a guest there is something to stop.
pub fn can_stop(status: Status) -> bool {
    status == Status::Running
}

/// A terminal needs an sshd, which needs a booted guest.
pub fn can_shell(status: Status) -> bool {
    status == Status::Running
}

/// Taking or restoring a snapshot rewrites a disk the hypervisor may be
/// holding open, so the daemon refuses both while the guest is running.
pub fn can_touch_disk(status: Status) -> bool {
    status != Status::Running
}

// ---- the rows --------------------------------------------------------------

/// One instance, as the table sees it.
///
/// The four `can_*` fields are the gates above, resolved once here so that
/// the webview never restates a rule: it draws a disabled button because
/// Rust said so, the same way the tray greys an item because Rust said so.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Row {
    pub name: String,
    /// `running`, `stopped` or `defined`, in the daemon's own words.
    pub status: String,
    /// Whether the shard this row came from answered just now. A stale row
    /// is still worth showing — the alternative reads as "deleted" — but it
    /// must not claim to know what the instance is doing.
    pub live: bool,
    /// The device supplying its cpu and ram.
    pub cpu_device: String,
    /// The backend it was defined against, or empty where the registry
    /// predates the field or no backend could be probed at create.
    pub backend: String,
    /// `2 CPU · 2 GB · 20 GB`, formatted once so the dump and the table
    /// cannot disagree.
    pub shape: String,
    /// The source used to define this machine. Kept as a reference rather
    /// than guessed into a friendlier product name.
    pub image: String,
    /// Storage parts already attached to this instance.
    pub volumes: Vec<VolumeRow>,
    pub can_start: bool,
    pub can_stop: bool,
    pub can_shell: bool,
    pub can_snapshot: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct VolumeRow {
    pub kind: String,
    pub name: String,
    pub source_device: String,
    pub guest_path: String,
    pub size: String,
}

impl Row {
    pub fn of(instance: &Instance, live: bool) -> Row {
        // An unreachable device's row is a memory of a status, not a
        // status. Saying `running` about a machine nobody can reach is the
        // one lie a fleet view must not tell.
        let status = if live { instance.status.to_string() } else { "unknown".to_owned() };
        Row {
            name: instance.name.clone(),
            status,
            live,
            cpu_device: instance.cpu_device.clone(),
            backend: instance.machine.as_ref().map(|m| m.backend.clone()).unwrap_or_default(),
            shape: shape(&instance.shape),
            image: instance.image.clone().unwrap_or_else(|| "unknown".to_owned()),
            volumes: instance
                .volumes
                .iter()
                .map(|volume| VolumeRow {
                    kind: match volume.kind {
                        VolumeKind::Dir => "directory".to_owned(),
                        VolumeKind::Block => "block".to_owned(),
                    },
                    name: volume.path.clone(),
                    source_device: volume.host.clone(),
                    guest_path: if volume.is_block() {
                        "guest-managed disk".to_owned()
                    } else {
                        volume.guest_path()
                    },
                    size: volume
                        .size_bytes
                        .map(asterism_core::volume::format_size)
                        .unwrap_or_default(),
                })
                .collect(),
            // Nothing is offered on a row whose device is out of touch: the
            // request would be forwarded to a daemon that is not there.
            can_start: live && can_start(instance.status),
            can_stop: live && can_stop(instance.status),
            can_shell: live && can_shell(instance.status),
            can_snapshot: live && can_touch_disk(instance.status),
        }
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
                        "  actions up={} down={} terminal={} snapshots={}",
                        on(row.can_start),
                        on(row.can_stop),
                        on(row.can_shell),
                        on(row.can_snapshot)
                    ));
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

    fn instance(name: &str, status: Status) -> Instance {
        let mut instance = Instance::new(name, "laptop", "debian:13", Shape::default(), None);
        instance.status = status;
        instance
    }

    /// The daemon refuses `Up` on a running guest and `Snapshot` on one that
    /// is not stopped, and nothing narrower. Both surfaces read these, so a
    /// change here is a change to the tray and the window at once.
    #[test]
    fn the_gates_are_the_daemons_and_not_a_narrower_pair() {
        assert!(!can_start(Status::Running));
        assert!(can_start(Status::Stopped) && can_start(Status::Defined));

        assert!(can_stop(Status::Running));
        assert!(!can_stop(Status::Stopped) && !can_stop(Status::Defined));

        assert!(can_shell(Status::Running));
        assert!(!can_shell(Status::Stopped));

        // A never-booted instance has a disk, so it may be snapshotted.
        assert!(can_touch_disk(Status::Defined));
        assert!(can_touch_disk(Status::Stopped));
        assert!(!can_touch_disk(Status::Running));
    }

    #[test]
    fn a_running_row_offers_down_and_a_terminal_and_no_snapshot() {
        let row = Row::of(&instance("dev", Status::Running), true);
        assert_eq!(row.status, "running");
        assert!(!row.can_start && row.can_stop && row.can_shell && !row.can_snapshot);
    }

    #[test]
    fn a_stopped_row_offers_up_and_a_snapshot_and_no_terminal() {
        let row = Row::of(&instance("dev", Status::Stopped), true);
        assert!(row.can_start && !row.can_stop && !row.can_shell && row.can_snapshot);
    }

    /// A row from a device that did not answer is a memory. Reporting the
    /// last known status as the current one, and offering actions that would
    /// be forwarded to a daemon nobody can reach, are the same mistake.
    #[test]
    fn a_row_from_a_silent_device_claims_nothing_and_offers_nothing() {
        let row = Row::of(&instance("dev", Status::Running), false);
        assert_eq!(row.status, "unknown");
        assert!(!row.can_start && !row.can_stop && !row.can_shell && !row.can_snapshot);
    }

    #[test]
    fn a_row_names_the_device_supplying_its_cpu_and_the_backend_it_was_cut_against() {
        let mut inst = instance("dev", Status::Stopped);
        inst.machine = Some(Machine {
            backend: "vz".into(),
            machine_type: "virt".into(),
            cpu: "host".into(),
            hv_version: "15.0".into(),
        });
        let row = Row::of(&inst, true);
        assert_eq!(row.cpu_device, "laptop");
        assert_eq!(row.backend, "vz");

        // A registry written before backends were recorded says nothing
        // rather than guessing qemu.
        assert_eq!(Row::of(&instance("dev", Status::Stopped), true).backend, "");
    }

    #[test]
    fn a_shape_reads_in_the_units_a_person_sizes_a_machine_in() {
        let row = Row::of(&instance("dev", Status::Stopped), true);
        assert_eq!(row.shape, "2 CPU · 2 GB · 20 GB");

        let mut half = instance("dev", Status::Stopped);
        half.shape = Shape { cpus: 1, mem_mib: 512, disk_gib: 5 };
        assert_eq!(Row::of(&half, true).shape, "1 CPU · 0.5 GB · 5 GB");
    }

    #[test]
    fn an_empty_orbit_and_an_unreachable_daemon_do_not_look_alike() {
        assert_eq!(Instances::of(&[]).lines(), vec!["section instances", "empty"]);

        let down = Instances { fleet: Fleet::Unreachable { reason: "no socket".into() } };
        assert_eq!(down.lines()[1], "unreachable no socket");
    }

    #[test]
    fn dumping_the_section_names_every_row_and_what_it_offers() {
        let rows = vec![
            OrbitRow { instance: instance("dev", Status::Running), live: true },
            OrbitRow { instance: instance("build", Status::Stopped), live: false },
        ];
        let lines = Instances::of(&rows).lines().join("\n");
        assert!(lines.contains("instance dev              running "), "{lines}");
        assert!(lines.contains("cpu=laptop"), "{lines}");
        assert!(lines.contains("shape=2 CPU · 2 GB · 20 GB"), "{lines}");
        assert!(
            lines.contains("actions up=disabled down=enabled terminal=enabled snapshots=disabled"),
            "{lines}"
        );
        assert!(lines.contains("instance build            unknown "), "{lines}");
    }

    /// The rows cross to the webview as JSON, so their field names are an
    /// interface; renaming one silently would leave a table drawing blanks.
    #[test]
    fn a_row_reaches_the_webview_under_the_names_it_reads() {
        let json = serde_json::to_value(Row::of(&instance("dev", Status::Running), true)).unwrap();
        for key in
            ["name", "status", "live", "cpu_device", "backend", "shape", "can_start", "can_stop"]
        {
            assert!(json.get(key).is_some(), "a row has no {key:?}: {json}");
        }

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
