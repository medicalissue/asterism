//! The tables and the detail view — the output shared by more than one
//! command.
//!
//! Here rather than beside a command because two commands print the same
//! table: `ast ls` prints the orbit's registry and `ast ls --local` prints
//! one device's shard, and they are one table on purpose. The columns are the
//! argument this project is making — that an instance is assembled from parts
//! sourced across the orbit — so they have to look the same however the rows
//! were gathered, and a second copy of this would drift.
//!
//! Anything only one command prints lives with that command instead.

use asterism_core::instance::{now_unix, Instance, Restart};
use asterism_core::paths;
use asterism_core::registry::OrbitRow;
use asterism_core::cow;

/// `ast ls`: one table, one namespace.
///
/// The CPU column says which device is supplying each instance's cpu and ram.
/// It is a column and not a grouping on purpose — the rows are one flat list
/// because the namespace is one flat namespace, and where the cpu comes from
/// is a property of the instance, like its shape or its age.
pub(crate) fn print_table(rows: &[OrbitRow]) {
    if rows.is_empty() {
        println!("no instances — start with: ast create <name>");
        return;
    }
    println!(
        "{:<14} {:<9} {:<14} {:<16} {:<12} {:<6} SSH",
        "NAME", "STATUS", "IMAGE", "SHAPE", "CPU", "AGE"
    );
    let mut stale = false;
    let mut conflicts = Vec::new();
    for row in rows {
        let inst = &row.instance;
        let shape = format!(
            "{}c/{}M/{}G",
            inst.shape.cpus, inst.shape.mem_mib, inst.shape.disk_gib
        );
        // A device out of touch still has its instances, and they are still
        // real; what we do not have is their current state.
        let status = if inst.conflict.is_some() {
            conflicts.push(inst.name.clone());
            "conflict".to_owned()
        } else if inst.moving.is_some() {
            // Not a lifecycle state: the guest is stopped and its bytes are
            // on their way somewhere. Saying "stopped" would invite an
            // `ast up` that this device is going to refuse.
            "moving".to_owned()
        } else if row.live {
            inst.status.to_string()
        } else {
            stale = true;
            "unknown".to_owned()
        };
        let ssh = match (row.live, inst.endpoint()) {
            (true, Some(e)) => e.to_string(),
            _ => "-".into(),
        };
        println!(
            "{:<14} {:<9} {:<14} {:<16} {:<12} {:<6} {}",
            inst.name,
            status,
            short_image(inst.image.as_deref().unwrap_or("-")),
            shape,
            inst.cpu_device,
            age(inst.created_at),
            ssh,
        );
    }
    if stale {
        println!("\nunknown: the device supplying that instance's cpu is out of touch");
    }
    for name in conflicts {
        println!("\nconflict: {name} shares its name — rename it: ast rename {name} <new-name>");
    }
}

/// `ast status`: the instance, then the parts it is assembled from and where
/// in the pool each of them is sourced.
pub(crate) fn print_detail(inst: &Instance) {
    println!("name:    {}", inst.name);
    println!("id:      {}", inst.id);
    println!("status:  {}", inst.status);
    // What happens when the guest dies, which is half of what "never
    // sleeps" means. Printed always, because the answer matters most for
    // the instance nobody has thought about since they created it.
    println!(
        "restart: {}{}",
        inst.policy.restart,
        match inst.policy.restart {
            Restart::Always => format!(" (up to {} tries after a crash)", inst.policy.max_attempts),
            Restart::Never => String::new(),
        }
    );
    println!("age:     {}", age(inst.created_at));
    if let Some(disk) = local_disk(inst) {
        println!("disk:    {disk}");
    }
    // The machine this instance was defined against. Recorded at create
    // time, and what a live migration would have to match on.
    println!("machine: {}", inst.machine);
    if let Some(h) = &inst.handle {
        let pid = h.pid.map(|p| p.to_string()).unwrap_or_else(|| "-".into());
        println!("running: {} pid {pid}, ssh {}", h.backend, h.endpoint);
        println!("control: {}", h.ctl.path().display());
    }
    if let Some(conflict) = &inst.conflict {
        println!(
            "conflict: another instance in this orbit is also called {:?} \
             (cpu/ram on {}) — rename this one: ast rename {} <new-name>",
            inst.name, conflict.other_cpu_device, inst.name
        );
    }
    // Only worth a line once it has happened: an instance that has never had
    // its cpu part swapped is the ordinary case and does not need telling.
    if inst.move_epoch > 0 {
        println!("moves:   {} (cpu/ram has been re-sourced that many times)", inst.move_epoch);
    }
    // Worth a line only when it is not the obvious answer: a guest trusts
    // the key in its seed, and after a move that is not the device running it.
    if inst.seeded_by() != inst.cpu_device {
        println!(
            "seed:    built on {} — its guest key is the one this guest trusts",
            inst.seeded_by()
        );
    }
    if let Some(moving) = &inst.moving {
        println!(
            "moving:  to {} at epoch {} — this device holds the only bootable copy \
             and will not boot it until the move lands",
            moving.to_device, moving.epoch
        );
    }

    // Every row names the device the part comes from. Most of them name the
    // same device, and say why: the disk follows the cpu because that is the
    // cheapest place for it, not because that device owns the instance.
    println!("\nparts:");
    let parts = inst.parts();
    let kind = parts.iter().map(|p| p.kind.len()).max().unwrap_or(0);
    let source = parts.iter().map(|p| p.source.len()).max().unwrap_or(0);
    for p in &parts {
        let note = p.note.as_ref().map(|n| format!("  ({n})")).unwrap_or_default();
        println!("  {:<kind$}  {:<source$}  {}{note}", p.kind, p.source, p.detail);
    }
}

/// What an instance's root disk is, and what it actually costs today.
///
/// Read off the filesystem rather than the registry, because both halves
/// are facts about the file: a disk cloned from a raw base occupies almost
/// nothing until the guest writes to it, and a `disk.qcow2` says this
/// instance predates raw disks and still takes the old snapshot path
/// (BACKENDS.md §4). Only when this device supplies the cpu/ram; another
/// device's disks are not ours to stat.
fn local_disk(inst: &Instance) -> Option<String> {
    if inst.cpu_device != asterism_core::instance::local_host() {
        return None;
    }
    let dir = paths::instance_dir(&inst.name);
    let (path, format) = [("disk.raw", "raw"), ("disk.qcow2", "qcow2 (legacy)")]
        .into_iter()
        .map(|(file, format)| (dir.join(file), format))
        .find(|(path, _)| path.exists())?;
    let used = cow::usage(&path).ok()?;
    Some(format!(
        "{format}, {} of {} GiB used",
        cow::human(used),
        inst.shape.disk_gib
    ))
}

/// An image reference short enough for a table column.
///
/// Only the part every Docker Hub library image shares is dropped, and only
/// for display: `docker.io/library/nginx:latest` is what is recorded, what
/// `ast status` prints, and what `--image` accepts, because it is the name
/// that means one thing everywhere. `nginx:latest` is what a column has room
/// for.
pub(crate) fn short_image(reference: &str) -> String {
    reference
        .strip_prefix("docker.io/library/")
        .unwrap_or(reference)
        .to_owned()
}

pub(crate) fn age(created_at: u64) -> String {
    let secs = now_unix().saturating_sub(created_at);
    match secs {
        0..=59 => format!("{secs}s"),
        60..=3599 => format!("{}m", secs / 60),
        3600..=86_399 => format!("{}h", secs / 3600),
        _ => format!("{}d", secs / 86_400),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The one prefix that is dropped is the one every Docker Hub library
    /// image carries, and it is dropped for the column and nowhere else:
    /// what gets recorded, printed by `ast status` and accepted by `--image`
    /// is still the name that means one thing everywhere.
    #[test]
    fn only_the_prefix_every_library_image_shares_is_shortened() {
        assert_eq!(short_image("docker.io/library/nginx:latest"), "nginx:latest");
        assert_eq!(short_image("ghcr.io/owner/app:v1"), "ghcr.io/owner/app:v1");
        assert_eq!(short_image("debian:13"), "debian:13");
    }

    /// An age is a column six characters wide, so it is one unit and never
    /// two — and it rounds down, because "1h" for something 119 minutes old
    /// is a smaller lie than "2h" for something 61 minutes old.
    #[test]
    fn an_age_is_the_largest_unit_that_fits_a_column() {
        let now = now_unix();
        assert_eq!(age(now), "0s");
        assert_eq!(age(now - 59), "59s");
        assert_eq!(age(now - 60), "1m");
        assert_eq!(age(now - 3_599), "59m");
        assert_eq!(age(now - 3_600), "1h");
        assert_eq!(age(now - 86_400), "1d");
        // A clock that went backwards is not a negative age.
        assert_eq!(age(now + 500), "0s");
    }
}
