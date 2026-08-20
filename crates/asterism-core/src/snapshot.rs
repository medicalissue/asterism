//! Disk snapshots.
//!
//! A snapshot is a copy-on-write clone of the instance's root disk, taken
//! while it is stopped, living in `instances/<name>/snapshots/<tag>.raw`.
//! On APFS the clone costs nothing until the two diverge, so this is as
//! cheap as the qcow2 internal snapshots it replaces and, unlike them, it
//! works on a raw disk — which is what every instance now has, because
//! Virtualization.framework cannot read anything else (BACKENDS.md §4).
//!
//! Two consequences worth stating:
//!
//! * Snapshots still disappear with the instance: they are files inside its
//!   directory, which `ast rm` removes wholesale.
//! * The format is nobody's private business. A snapshot is a disk image; a
//!   future backend, or a human with `cp`, can do something useful with one.
//!
//! Instances created before this — the ones whose root disk is still a
//! `disk.qcow2` overlay — keep using qcow2 *internal* snapshots, which is
//! why [`parse_list`] is still here: it reads the table `qemu-img snapshot
//! -l` prints for those.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::cow;
use crate::hv::SnapshotId;
use crate::instance::now_unix;

/// One snapshot, as `ast snapshots` shows it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Snapshot {
    /// Position in the listing. qcow2 gives these out itself; for file
    /// snapshots it is the row number, since the tag is the real identity.
    pub id: String,
    pub tag: String,
    /// What the snapshot occupies: blocks actually allocated to the clone,
    /// which starts at almost nothing and grows as the live disk diverges
    /// from it. `0 B` for a qcow2 internal snapshot, which stores no guest
    /// RAM either.
    pub size: String,
    /// `YYYY-MM-DD HH:MM:SS`, UTC (with a `Z`) for file snapshots, and in
    /// local time for the qcow2 rows qemu-img formats.
    pub date: String,
}

/// Snapshot names become file names and `qemu-img` argv, and come back
/// through a whitespace-separated table, so keep them boring: nothing that
/// splits a row in two, nothing that could pass for a flag, and nothing
/// that could walk out of the snapshots directory.
pub fn validate_tag(tag: &str) -> Result<()> {
    let allowed = |c: char| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.');
    if tag.is_empty() || tag.starts_with('-') || tag.starts_with('.') || !tag.chars().all(allowed) {
        bail!("snapshot names are ascii letters, digits, '-', '_' and '.' (got {tag:?})");
    }
    Ok(())
}

/// Name used when `ast snapshot` is called without one: `snap-<ISO 8601
/// basic UTC>`, which orders the same lexically as chronologically. The
/// trailing `Z` earns its keep — it says which clock the name is on, and
/// the DATE column of a file snapshot carries the same one.
pub fn timestamped_tag() -> String {
    tag_at(now_unix())
}

fn tag_at(unix_secs: u64) -> String {
    let (year, month, day) = civil_from_days((unix_secs / 86_400) as i64);
    let secs = unix_secs % 86_400;
    format!(
        "snap-{year:04}{month:02}{day:02}T{:02}{:02}{:02}Z",
        secs / 3600,
        (secs % 3600) / 60,
        secs % 60
    )
}

/// `YYYY-MM-DD HH:MM:SSZ` — the shape qemu-img prints in its DATE column,
/// plus the `Z` that says this one is UTC.
fn date_at(unix_secs: u64) -> String {
    let (year, month, day) = civil_from_days((unix_secs / 86_400) as i64);
    let secs = unix_secs % 86_400;
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02}:{:02}Z",
        secs / 3600,
        (secs % 3600) / 60,
        secs % 60
    )
}

/// Days since the unix epoch to a civil date (Howard Hinnant's algorithm);
/// cheaper than taking on a calendar crate for one filename.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

// ---- file snapshots --------------------------------------------------------

/// Suffix every snapshot file carries. They are disk images, and naming
/// them as such is what lets anything else — another backend, `qemu-img`,
/// a human — make sense of one.
const SUFFIX: &str = ".raw";

/// Where an instance's snapshots live, given its directory.
pub fn dir(instance_dir: &Path) -> PathBuf {
    instance_dir.join("snapshots")
}

/// The file one tag names. Tags are validated first, so this cannot be
/// talked into pointing outside the snapshots directory.
pub fn path(instance_dir: &Path, tag: &str) -> Result<PathBuf> {
    validate_tag(tag)?;
    Ok(dir(instance_dir).join(format!("{tag}{SUFFIX}")))
}

/// Clone the stopped root disk into a new snapshot.
///
/// The instance being stopped is the caller's business (the daemon refuses
/// otherwise): a clone taken under a running guest would capture a disk
/// mid-write, exactly as `qemu-img snapshot -c` would have.
pub fn take(instance_dir: &Path, disk: &Path, tag: &str) -> Result<SnapshotId> {
    let target = path(instance_dir, tag)?;
    if target.exists() {
        bail!("snapshot {tag:?} already exists");
    }
    let how = cow::clone_file(disk, &target).with_context(|| format!("taking snapshot {tag:?}"))?;
    if let Some(warning) = how.warning(disk, &target) {
        eprintln!("astd: {warning}");
    }
    Ok(SnapshotId(tag.to_owned()))
}

/// Every snapshot in the instance's directory, oldest first.
///
/// A directory listing, so it stays truthful even if someone drops an image
/// in by hand — and unlike the qcow2 table, it reads fine while a guest is
/// running, because it never touches the live disk.
pub fn list(instance_dir: &Path) -> Result<Vec<Snapshot>> {
    let Ok(entries) = std::fs::read_dir(dir(instance_dir)) else {
        return Ok(Vec::new()); // no snapshots taken yet
    };
    let mut rows: Vec<(u64, String, u64)> = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let Some(tag) = name.strip_suffix(SUFFIX) else { continue };
        if validate_tag(tag).is_err() {
            continue;
        }
        let taken = entry
            .metadata()
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);
        rows.push((taken, tag.to_owned(), cow::usage(&entry.path()).unwrap_or(0)));
    }
    rows.sort();
    Ok(rows
        .into_iter()
        .enumerate()
        .map(|(i, (taken, tag, used))| Snapshot {
            id: (i + 1).to_string(),
            tag,
            size: cow::human(used),
            date: date_at(taken),
        })
        .collect())
}

/// Roll the stopped root disk back to a snapshot.
///
/// Clone beside the disk and rename over it: a failed clone then leaves the
/// instance exactly as it was, and the disk is never half-replaced. The
/// snapshot itself survives the restore, so the same one can be rolled back
/// to again.
pub fn restore(instance_dir: &Path, disk: &Path, tag: &str) -> Result<()> {
    let source = path(instance_dir, tag)?;
    if !source.exists() {
        bail!("no snapshot {tag:?}");
    }
    let staged = disk.with_extension("restoring");
    let _ = std::fs::remove_file(&staged);
    // Say which snapshot is being read from before a byte of it is, and
    // keep saying it until the disk has been replaced. A daemon killed
    // halfway through leaves this behind, and it is what stops the next
    // `ast snapshot rm` deleting the source of a restore that has not
    // finished.
    mark_restoring(instance_dir, tag);
    let cloned =
        cow::clone_file(&source, &staged).with_context(|| format!("restoring snapshot {tag:?}"));
    let result = cloned.and_then(|how| {
        if let Some(warning) = how.warning(&source, &staged) {
            eprintln!("astd: {warning}");
        }
        std::fs::rename(&staged, disk)
            .with_context(|| format!("replacing {} with snapshot {tag:?}", disk.display()))
    });
    if result.is_ok() {
        clear_restoring(instance_dir);
    }
    result
}

/// Delete one snapshot.
///
/// A file, unlinked — which is the whole of it for a raw instance, and the
/// reason the format being nobody's private business is worth something.
/// Refused for a tag a restore is in the middle of reading: the disk that
/// restore is building is not finished, and the bytes it is copying from
/// are the only copy of what it is building.
pub fn remove(instance_dir: &Path, tag: &str) -> Result<()> {
    let target = path(instance_dir, tag)?;
    if !target.exists() {
        bail!("no snapshot {tag:?}");
    }
    if restoring(instance_dir).as_deref() == Some(tag) {
        bail!(
            "snapshot {tag:?} is being restored right now — the disk is halfway \
             through being rebuilt from it. Let the restore finish, or run it \
             again if it was interrupted, then delete it"
        );
    }
    std::fs::remove_file(&target)
        .with_context(|| format!("deleting snapshot {tag:?} at {}", target.display()))
}

/// Where the in-flight restore records the tag it is reading from. Named
/// with a leading dot so [`list`] passes over it: a marker is not a
/// snapshot, and the listing is a directory listing.
fn restoring_path(instance_dir: &Path) -> PathBuf {
    dir(instance_dir).join(".restoring")
}

/// The tag a restore is in the middle of, if one is.
pub fn restoring(instance_dir: &Path) -> Option<String> {
    let tag = std::fs::read_to_string(restoring_path(instance_dir)).ok()?;
    let tag = tag.trim().to_owned();
    (!tag.is_empty()).then_some(tag)
}

fn mark_restoring(instance_dir: &Path, tag: &str) {
    let path = restoring_path(instance_dir);
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::write(path, tag);
}

fn clear_restoring(instance_dir: &Path) {
    let _ = std::fs::remove_file(restoring_path(instance_dir));
}

// ---- qcow2 internal snapshots (legacy instances) ---------------------------

/// Parse what `qemu-img snapshot -l` prints:
///
/// ```text
/// Snapshot list:
/// ID      TAG               VM_SIZE                DATE      VM_CLOCK     ICOUNT
/// 1       nightly               0 B 2026-08-20 20:40:40  0000:00:00.000          0
/// ```
///
/// Still needed for instances created before raw disks, whose root is a
/// qcow2 overlay carrying its snapshots inside it.
///
/// The columns are padded to fixed widths, but a long tag overflows its
/// column and shoves the rest of the row along, so counting characters is
/// no good. Anchor on the date instead: every data row carries a
/// `YYYY-MM-DD` token, no header line does, and the fields on either side
/// of it are positional. Rows that do not look like rows are skipped —
/// qemu-img has grown a column before (ICOUNT) and may again.
pub fn parse_list(output: &str) -> Vec<Snapshot> {
    output.lines().filter_map(parse_row).collect()
}

fn parse_row(line: &str) -> Option<Snapshot> {
    let fields: Vec<&str> = line.split_whitespace().collect();
    let at = fields.iter().position(|f| looks_like_date(f))?;
    // Everything left of the date is id, tag, then the size and its unit.
    if at < 3 {
        return None;
    }
    Some(Snapshot {
        id: fields[0].to_owned(),
        tag: fields[1].to_owned(),
        size: fields[2..at].join(" "),
        date: match fields.get(at + 1) {
            Some(time) => format!("{} {time}", fields[at]),
            None => fields[at].to_owned(),
        },
    })
}

fn looks_like_date(field: &str) -> bool {
    let b = field.as_bytes();
    b.len() == 10
        && b[4] == b'-'
        && b[7] == b'-'
        && b.iter()
            .enumerate()
            .all(|(i, c)| i == 4 || i == 7 || c.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A stand-in for an instance directory with a root disk in it.
    fn instance_with_disk(bytes: &[u8]) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let disk = dir.path().join("disk.raw");
        std::fs::write(&disk, bytes).unwrap();
        (dir, disk)
    }

    #[test]
    fn a_snapshot_is_a_file_beside_the_disk() {
        let (dir, disk) = instance_with_disk(b"pristine");
        let id = take(dir.path(), &disk, "clean").unwrap();
        assert_eq!(id.0, "clean");
        assert_eq!(path(dir.path(), "clean").unwrap(), dir.path().join("snapshots/clean.raw"));
        assert!(dir.path().join("snapshots/clean.raw").exists());

        // Snapshots live under the instance, so removing it removes them.
        let root = dir.path().to_owned();
        std::fs::remove_dir_all(&root).unwrap();
        assert!(!root.exists());
    }

    #[test]
    fn taking_the_same_tag_twice_is_refused() {
        let (dir, disk) = instance_with_disk(b"pristine");
        take(dir.path(), &disk, "clean").unwrap();
        let err = take(dir.path(), &disk, "clean").unwrap_err().to_string();
        assert!(err.contains("already exists"), "{err}");
        assert!(take(dir.path(), &disk, "two words").is_err());
        // ...and a tag can never name a file outside the snapshots dir.
        assert!(path(dir.path(), "../../escape").is_err());
        assert!(path(dir.path(), ".hidden").is_err());
    }

    #[test]
    fn restoring_puts_the_snapshotted_bytes_back() {
        let (dir, disk) = instance_with_disk(b"pristine");
        take(dir.path(), &disk, "clean").unwrap();

        std::fs::write(&disk, b"diverged").unwrap();
        restore(dir.path(), &disk, "clean").unwrap();
        assert_eq!(std::fs::read(&disk).unwrap(), b"pristine");

        // The snapshot survives its own restore, and can be used again.
        std::fs::write(&disk, b"diverged again").unwrap();
        restore(dir.path(), &disk, "clean").unwrap();
        assert_eq!(std::fs::read(&disk).unwrap(), b"pristine");

        let err = restore(dir.path(), &disk, "never-taken").unwrap_err().to_string();
        assert!(err.contains("no snapshot"), "{err}");
        // A failed restore leaves the disk untouched.
        assert_eq!(std::fs::read(&disk).unwrap(), b"pristine");
    }

    #[test]
    fn removing_one_takes_its_file_and_leaves_the_rest() {
        let (dir, disk) = instance_with_disk(b"pristine");
        take(dir.path(), &disk, "keep").unwrap();
        take(dir.path(), &disk, "drop").unwrap();

        remove(dir.path(), "drop").unwrap();
        assert!(!dir.path().join("snapshots/drop.raw").exists());
        assert!(dir.path().join("snapshots/keep.raw").exists());
        // The disk it was cloned from is not what was deleted.
        assert_eq!(std::fs::read(&disk).unwrap(), b"pristine");

        // The listing is a directory listing, so it is truthful by
        // construction: what is gone is gone from it.
        let listed: Vec<String> =
            list(dir.path()).unwrap().into_iter().map(|s| s.tag).collect();
        assert_eq!(listed, vec!["keep".to_owned()]);

        // Deleting the same one twice says what is true rather than
        // succeeding at nothing.
        let err = remove(dir.path(), "drop").unwrap_err().to_string();
        assert!(err.contains("no snapshot \"drop\""), "{err}");
    }

    #[test]
    fn a_tag_that_could_name_a_file_elsewhere_is_refused_before_anything_is_unlinked() {
        let (dir, disk) = instance_with_disk(b"pristine");
        take(dir.path(), &disk, "keep").unwrap();
        // The same validation `path` does for every other operation: a tag
        // is a name, never a route out of the snapshots directory.
        assert!(remove(dir.path(), "../../../etc/passwd").is_err());
        assert!(remove(dir.path(), "-f").is_err());
        assert!(remove(dir.path(), "two words").is_err());
        assert!(dir.path().join("snapshots/keep.raw").exists());
    }

    /// A restore that was interrupted leaves a disk that is not finished and
    /// a snapshot that is the only copy of what it was being rebuilt from.
    /// Deleting that snapshot would leave the instance with neither.
    #[test]
    fn a_snapshot_a_restore_is_reading_from_cannot_be_deleted() {
        let (dir, disk) = instance_with_disk(b"pristine");
        take(dir.path(), &disk, "clean").unwrap();
        take(dir.path(), &disk, "other").unwrap();

        // A successful restore leaves no marker, and nothing is pinned.
        restore(dir.path(), &disk, "clean").unwrap();
        assert_eq!(restoring(dir.path()), None);

        // A restore that died halfway leaves one, naming its source.
        std::fs::write(dir.path().join("snapshots/.restoring"), "clean").unwrap();
        assert_eq!(restoring(dir.path()).as_deref(), Some("clean"));
        let err = remove(dir.path(), "clean").unwrap_err().to_string();
        assert!(err.contains("is being restored right now"), "{err}");
        assert!(dir.path().join("snapshots/clean.raw").exists());

        // Only that one: the others are nobody's source.
        remove(dir.path(), "other").unwrap();

        // Running the restore again finishes it and unpins the snapshot.
        restore(dir.path(), &disk, "clean").unwrap();
        remove(dir.path(), "clean").unwrap();

        // And the marker is not a snapshot, however the listing is read.
        std::fs::write(dir.path().join("snapshots/.restoring"), "clean").unwrap();
        assert!(list(dir.path()).unwrap().is_empty());
    }

    #[test]
    fn listing_is_the_directory_oldest_first() {
        let (dir, disk) = instance_with_disk(&vec![0u8; 8192]);
        assert!(list(dir.path()).unwrap().is_empty(), "nothing taken yet");

        take(dir.path(), &disk, "first").unwrap();
        take(dir.path(), &disk, "second").unwrap();
        // Backdate one so the order is the one we asked for, not the one
        // two clones in the same second happen to land in.
        assert!(backdate(dir.path(), "first", 1_700_000_000));

        let snaps = list(dir.path()).unwrap();
        assert_eq!(snaps.len(), 2);
        assert_eq!(snaps[0].tag, "first");
        assert_eq!(snaps[0].id, "1");
        assert_eq!(snaps[0].date, "2023-11-14 22:13:20Z");
        assert_eq!(snaps[1].tag, "second");
        assert_eq!(snaps[1].id, "2");
        // Sizes are what the clone occupies, formatted like qemu-img's.
        assert!(snaps[0].size.ends_with('B'), "{}", snaps[0].size);

        // Anything that is not a snapshot image is not a row.
        std::fs::write(dir.path().join("snapshots/notes.txt"), "hi").unwrap();
        assert_eq!(list(dir.path()).unwrap().len(), 2);
    }

    /// Backdate a snapshot file's mtime so ordering is deterministic.
    /// Pure Rust: shelling out to `date`/`touch` differs between BSD and
    /// GNU (`date -r` means epoch on one and reference-file on the other).
    fn backdate(instance_dir: &Path, tag: &str, unix_secs: u64) -> bool {
        let Ok(p) = path(instance_dir, tag) else { return false };
        let t = std::time::UNIX_EPOCH + std::time::Duration::from_secs(unix_secs);
        std::fs::File::options()
            .write(true)
            .open(p)
            .and_then(|f| f.set_modified(t))
            .is_ok()
    }

    /// Verbatim from qemu-img 11.0.0 — what a legacy instance's overlay
    /// still answers with.
    const REAL: &str = "\
Snapshot list:
ID      TAG               VM_SIZE                DATE      VM_CLOCK     ICOUNT
1       first-snap            0 B 2026-08-20 20:40:40  0000:00:00.000          0
2       second.snap_2         0 B 2026-08-20 20:40:40  0000:00:00.000          0
";

    #[test]
    fn parses_qemu_img_table() {
        let snaps = parse_list(REAL);
        assert_eq!(snaps.len(), 2, "headers must not become rows");
        assert_eq!(snaps[0].id, "1");
        assert_eq!(snaps[0].tag, "first-snap");
        assert_eq!(snaps[0].size, "0 B");
        assert_eq!(snaps[0].date, "2026-08-20 20:40:40");
        assert_eq!(snaps[1].tag, "second.snap_2");
    }

    #[test]
    fn long_tag_overflowing_its_column_still_parses() {
        let line = "3       a-very-long-snapshot-tag-name-here      0 B 2026-08-20 20:41:17  0000:00:00.000          0";
        let snaps = parse_list(line);
        assert_eq!(snaps.len(), 1);
        assert_eq!(snaps[0].tag, "a-very-long-snapshot-tag-name-here");
        assert_eq!(snaps[0].size, "0 B");
        assert_eq!(snaps[0].date, "2026-08-20 20:41:17");
    }

    #[test]
    fn multi_token_sizes_and_missing_icount_survive() {
        let line = "7       big-one            1.05 GiB 2026-01-02 03:04:05  0000:12:34.567";
        let snaps = parse_list(line);
        assert_eq!(snaps[0].size, "1.05 GiB");
        assert_eq!(snaps[0].date, "2026-01-02 03:04:05");
    }

    #[test]
    fn a_disk_without_snapshots_lists_nothing() {
        assert!(parse_list("").is_empty());
        assert!(parse_list("Snapshot list:\n").is_empty());
    }

    #[test]
    fn tags_are_checked() {
        assert!(validate_tag("nightly").is_ok());
        assert!(validate_tag("snap-20260820T204040Z").is_ok());
        assert!(validate_tag("v1.2_ok").is_ok());
        assert!(validate_tag("").is_err());
        assert!(validate_tag("two words").is_err());
        assert!(validate_tag("-c").is_err(), "must not pass for a flag");
        assert!(validate_tag("what?").is_err());
        assert!(validate_tag("../escape").is_err(), "must not leave the directory");
    }

    #[test]
    fn default_tags_are_timestamps() {
        assert_eq!(tag_at(0), "snap-19700101T000000Z");
        assert_eq!(tag_at(1_700_000_000), "snap-20231114T221320Z");
        // Leap day, and the tag it produces is one we would accept back.
        assert_eq!(tag_at(1_709_164_800), "snap-20240229T000000Z");
        validate_tag(&timestamped_tag()).unwrap();
        // A tag and the row it will appear as are on the same clock.
        assert_eq!(date_at(1_700_000_000), "2023-11-14 22:13:20Z");
    }
}
