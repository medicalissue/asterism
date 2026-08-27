//! `ast fork` — one agent becomes five, and then one of them wins.
//!
//! # What this is for
//!
//! An agent running on Asterism is a whole machine, not a process. That is
//! the thing tmux and ssh cannot give you: a machine can be *copied*. So when
//! there are three plausible ways to fix a bug, you do not pick one and find
//! out in an hour — you run all three at once, on three copies of the exact
//! machine that was stuck, and keep the one that worked.
//!
//! ```text
//! $ ast fork bot --n 3 --each "A: rewrite the parser" "B: patch the tokenizer" "C: add a fallback path"
//! bot-1 bot-2 bot-3 up — cloned from bot in 6.4 s, 1.9 GiB shared
//! $ ast diff bot-2
//! /work: 3 files changed, +41 −7 (vs bot @ 17:12)
//! $ ast pick bot-2
//! bot ← bot-2 (/work replaced; bot-1, bot-3 removed)
//! ```
//!
//! # Why it is cheap
//!
//! A fork is [`crate::rewind`]'s copy-on-write engine pointed sideways
//! instead of backwards. Rewind clones the root disk into `snapshots/` and
//! rolls it back onto the same instance; a fork clones the same snapshot into
//! *another* instance's directory and boots it. Same `clonefile(2)`, same
//! reflink, same near-zero cost — five forks of a two-gigabyte agent are two
//! gigabytes and change, not ten.
//!
//! # What this module is
//!
//! The data and the rendering, so that name allocation, provenance,
//! refusals, the diff summary and every printed line are decided here and
//! tested without a daemon, a hypervisor or a disk. The daemon side is
//! `asterism-daemon/src/fork.rs`.

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};

use crate::cow;

/// Where a fork came from, recorded on the fork's own registry row.
///
/// Provenance rather than a link: the parent may be renamed or removed and
/// this still says what the fork is, which is what `ast ls` needs to print a
/// row that means something a day later.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Origin {
    /// The instance this was cloned from.
    pub parent: String,
    /// The snapshot of the parent this was cloned at. Taken as a named
    /// snapshot, so retention never removes the thing `ast diff` and
    /// `ast pick` measure against.
    pub snapshot: String,
    /// When the fork was taken, unix seconds.
    pub at: u64,
    /// What this fork was told to try — the `--each` message.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

impl Origin {
    /// The NOTE column of `ast ls`:
    ///
    /// ```text
    /// fork of bot @ 17:12 · A: rewrite the parser
    /// ```
    pub fn line(&self, offset: i64) -> String {
        let mut out = format!("fork of {} @ {}", self.parent, hhmm(self.at, offset));
        if let Some(note) = &self.note {
            out.push_str(&format!(" · {note}"));
        }
        out
    }

    /// How `ast diff` names what it measured against.
    pub fn against(&self, offset: i64) -> String {
        format!("{} @ {}", self.parent, hhmm(self.at, offset))
    }
}

/// `17:12` in the reader's own timezone.
///
/// Deliberately not [`crate::rewind`]'s `clock`, which switches to
/// `08-26 14:20` for anything older than today. A provenance note is read
/// beside a date-less table and the hour is the useful half; the full moment
/// is in `ast status`.
fn hhmm(unix_secs: u64, offset: i64) -> String {
    let local = (unix_secs as i64) + offset;
    let secs = local.rem_euclid(86_400);
    format!("{:02}:{:02}", secs / 3600, (secs % 3600) / 60)
}

/// Prefix of the snapshot a fork is taken at.
pub const FORK_PREFIX: &str = "fork-";

/// The snapshot `ast pick` keeps of the `/work` it replaced.
///
/// Named rather than rolling, so it never expires: a pick is exactly the
/// moment somebody is least sure, and `ast rewind <parent> --to before-pick`
/// is the undo.
pub const BEFORE_PICK: &str = "before-pick";

/// The file `--each` is delivered as, inside the fork's own volume.
///
/// A file rather than a message into a live session, because the fork boots
/// from a cloned disk: whatever the agent is, it comes up fresh and reads its
/// working directory. When the session mechanism lands the note moves into
/// it; until then this is the thing that is true on every guest.
pub const NOTE_FILE: &str = ".asterism-fork-note";

/// The tag a fork taken at `unix_secs` is snapshotted under.
pub fn fork_tag(unix_secs: u64) -> String {
    format!("{FORK_PREFIX}{unix_secs}")
}

/// How many forks may be asked for without saying so twice.
///
/// Nine because the names are `<parent>-1` to `<parent>-9` and a
/// double-digit fleet is a different kind of decision — it is a device's
/// whole memory, and the refusal is the moment to notice.
pub const SOFT_LIMIT: usize = 9;

/// How many may be asked for at all. A hard stop, so a typo in a script
/// cannot ask for four thousand machines.
pub const HARD_LIMIT: usize = 64;

// ---- names -----------------------------------------------------------------

/// The names `ast fork <parent> --n <count>` will use.
///
/// `<parent>-1`, `<parent>-2`, … skipping any number already spoken for —
/// forking twice in a row gives `bot-1 bot-2 bot-3` and then `bot-4 bot-5
/// bot-6`, rather than refusing the second one or renumbering the first.
///
/// `taken` is every name this orbit already holds.
pub fn allocate(parent: &str, count: usize, taken: &[String]) -> Result<Vec<String>> {
    if count == 0 {
        bail!("--n has to be at least 1");
    }
    if count > HARD_LIMIT {
        bail!("--n is capped at {HARD_LIMIT} (asked for {count})");
    }
    crate::registry::check_name(parent)?;
    let mut names = Vec::with_capacity(count);
    // Bounded on purpose: a parent with a thousand live forks is a state
    // worth refusing rather than one worth searching past.
    for suffix in 1..=(HARD_LIMIT * 16) {
        if names.len() == count {
            break;
        }
        let candidate = format!("{parent}-{suffix}");
        if taken.iter().any(|name| name == &candidate) {
            continue;
        }
        names.push(candidate);
    }
    if names.len() != count {
        bail!(
            "no free names left for forks of {parent:?} — remove some with \
             `ast rm {parent}-<n>`"
        );
    }
    Ok(names)
}

/// Pair each fork with the `--each` message meant for it.
///
/// Either one message per fork or none at all. A partial list is a typo, and
/// silently leaving the last two forks without instructions is the kind of
/// thing found out an hour later.
pub fn notes(count: usize, each: &[String]) -> Result<Vec<Option<String>>> {
    if each.is_empty() {
        return Ok(vec![None; count]);
    }
    if each.len() != count {
        bail!(
            "--each takes one message per fork: {count} fork{} asked for, {} message{} given",
            if count == 1 { "" } else { "s" },
            each.len(),
            if each.len() == 1 { "" } else { "s" },
        );
    }
    Ok(each.iter().cloned().map(Some).collect())
}

// ---- what `ast fork` prints ------------------------------------------------

/// Everything `ast fork` says, as data.
///
/// A report rather than a rendered line, for the reason
/// [`crate::rewind::Report`] is one: the daemon says what happened and the
/// CLI decides how it reads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Report {
    pub parent: String,
    /// The forks, in the order they were made.
    pub children: Vec<String>,
    /// The snapshot of the parent they were all cloned from.
    pub snapshot: String,
    /// Wall clock for the whole thing, from the snapshot to the last boot.
    pub elapsed_ms: u64,
    /// What the clones would have cost had every byte been copied: the sum
    /// of the source files' allocated blocks, once per fork.
    pub apparent_bytes: u64,
    /// What they actually cost, measured as the drop in this filesystem's
    /// free space across the clone. `None` when free space could not be read
    /// — then the report says what was cloned rather than what was shared.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grew_bytes: Option<u64>,
    /// Whether the forks were booted. `--stopped` leaves them defined.
    pub started: bool,
    /// Anything the user has to know that is not a failure: a part that was
    /// not carried over, a note that could not be written.
    #[serde(default)]
    pub warnings: Vec<String>,
}

impl Report {
    /// Bytes the forks share with their parent rather than occupy.
    ///
    /// `None` when it cannot be measured honestly — either free space is
    /// unreadable, or something else on this filesystem moved it further
    /// than the clone could have. Reporting a negative share as zero would
    /// be a guess wearing a number.
    pub fn shared_bytes(&self) -> Option<u64> {
        let grew = self.grew_bytes?;
        (grew <= self.apparent_bytes).then(|| self.apparent_bytes - grew)
    }

    /// The line the transcript promised:
    ///
    /// ```text
    /// bot-1 bot-2 bot-3 up — cloned from bot in 6.4 s, 1.9 GiB shared
    /// ```
    pub fn render(&self) -> String {
        let seconds = self.elapsed_ms as f64 / 1000.0;
        let cost = match self.shared_bytes() {
            Some(shared) => format!("{} shared", cow::human(shared)),
            // No reflink here, or no way to ask: say what was written
            // instead of claiming a share that did not happen.
            None => format!("{} cloned", cow::human(self.apparent_bytes)),
        };
        let mut out = format!(
            "{} {} — cloned from {} in {seconds:.1} s, {cost}",
            self.children.join(" "),
            if self.started { "up" } else { "defined" },
            self.parent,
        );
        for warning in &self.warnings {
            out.push_str(&format!("\n{warning}"));
        }
        out
    }
}

// ---- what `ast diff` prints ------------------------------------------------

/// How a diff was measured, because the two ways do not mean quite the same
/// thing and the reader deserves to know which one they are looking at.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Method {
    /// `git` compared the fork's tree against the commit the parent was on
    /// at the fork point, plus whatever is untracked and not ignored. This
    /// is the number the agent would see, ignore rules and all.
    Git,
    /// The two directory trees were walked and compared file by file. Every
    /// file counts, including the ones a `.gitignore` would have hidden.
    Trees,
}

/// The summary `ast diff` prints.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Diff {
    pub instance: String,
    /// What it was measured against, already rendered: `bot @ 17:12`.
    pub against: String,
    /// Where the volume appears inside the guest: `/work`.
    pub path: String,
    pub files: usize,
    pub added: u64,
    pub removed: u64,
    pub method: Method,
    #[serde(default)]
    pub warnings: Vec<String>,
}

impl Diff {
    /// ```text
    /// /work: 3 files changed, +41 −7 (vs bot @ 17:12)
    /// ```
    pub fn render(&self) -> String {
        let mut out = if self.files == 0 {
            format!("{}: no changes (vs {})", self.path, self.against)
        } else {
            format!(
                "{}: {} file{} changed, +{} \u{2212}{} (vs {})",
                self.path,
                self.files,
                if self.files == 1 { "" } else { "s" },
                self.added,
                self.removed,
                self.against,
            )
        };
        for warning in &self.warnings {
            out.push_str(&format!("\n{warning}"));
        }
        out
    }
}

/// One `git diff --numstat` line: added, removed, path.
///
/// A binary file is `-\t-\t<path>`, which counts as a changed file and as no
/// lines — which is exactly what it is. A rename arrives as
/// `<a>\t<b>\t<old> => <new>` and counts once, like git counts it.
pub fn parse_numstat(output: &str) -> (usize, u64, u64) {
    let (mut files, mut added, mut removed) = (0usize, 0u64, 0u64);
    for line in output.lines() {
        let mut parts = line.split('\t');
        let (Some(plus), Some(minus), Some(_path)) = (parts.next(), parts.next(), parts.next())
        else {
            continue;
        };
        files += 1;
        added += plus.parse::<u64>().unwrap_or(0);
        removed += minus.parse::<u64>().unwrap_or(0);
    }
    (files, added, removed)
}

// ---- comparing two directory trees -----------------------------------------

/// Directory name never compared: it is the repository's own bookkeeping,
/// and a commit would otherwise read as a thousand changed files.
const GIT_DIR: &str = ".git";

/// Is this a path Asterism put there itself?
///
/// The `--each` note is written into the fork's volume by the fork, so it is
/// present in every fork and in none of their parents — and counting it would
/// mean every fork reported one more changed file than its agent touched. A
/// diff is about what the agent did.
pub fn is_ours(relative: &std::path::Path) -> bool {
    relative.file_name().is_some_and(|name| name == NOTE_FILE)
}

/// Compare two directory trees, file by file.
///
/// The fallback for when `git` is not on this device, and the only answer at
/// all for a volume that is not a repository. Every file counts — there are
/// no ignore rules to consult — so a `/work` full of build output will say
/// so, which is honest rather than flattering.
///
/// Lines are counted as a multiset difference: a line present three times in
/// the fork and once in the base is two additions. That is not a minimal
/// edit script and does not claim to be — it is the number of lines that are
/// in one side and not the other, which is what `+41 −7` means to somebody
/// deciding which fork to keep. A file holding a NUL byte is binary and
/// counts as changed with no lines, exactly as `git` reports it.
pub fn tree_diff(base: &std::path::Path, fork: &std::path::Path) -> (usize, u64, u64) {
    let (mut files, mut added, mut removed) = (0usize, 0u64, 0u64);
    let mut paths: std::collections::BTreeSet<std::path::PathBuf> = Default::default();
    collect(base, std::path::Path::new(""), &mut paths);
    collect(fork, std::path::Path::new(""), &mut paths);
    for relative in paths {
        let (left, right) = (base.join(&relative), fork.join(&relative));
        let (before, after) = (std::fs::read(&left).ok(), std::fs::read(&right).ok());
        match (before, after) {
            (None, None) => {}
            (Some(before), Some(after)) if before == after => {}
            (before, after) => {
                files += 1;
                let (plus, minus) = line_delta(before.as_deref(), after.as_deref());
                added += plus;
                removed += minus;
            }
        }
    }
    (files, added, removed)
}

/// Every file under `root`, as paths relative to it. Symlinks are compared
/// as the files they name where they resolve and skipped where they do not,
/// which is what reading them does.
fn collect(
    root: &std::path::Path,
    prefix: &std::path::Path,
    into: &mut std::collections::BTreeSet<std::path::PathBuf>,
) {
    let Ok(entries) = std::fs::read_dir(root.join(prefix)) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        if name == GIT_DIR || name == NOTE_FILE {
            continue;
        }
        let relative = prefix.join(&name);
        match entry.file_type() {
            Ok(kind) if kind.is_dir() => collect(root, &relative, into),
            Ok(_) => {
                into.insert(relative);
            }
            Err(_) => {}
        }
    }
}

/// Lines in `after` that are not in `before`, and the other way round.
fn line_delta(before: Option<&[u8]>, after: Option<&[u8]>) -> (u64, u64) {
    if before.is_some_and(is_binary) || after.is_some_and(is_binary) {
        return (0, 0);
    }
    let mut counts: std::collections::HashMap<&[u8], i64> = Default::default();
    for line in before.unwrap_or_default().split(|b| *b == b'\n') {
        *counts.entry(line).or_default() -= 1;
    }
    for line in after.unwrap_or_default().split(|b| *b == b'\n') {
        *counts.entry(line).or_default() += 1;
    }
    let (mut plus, mut minus) = (0i64, 0i64);
    for delta in counts.values() {
        if *delta > 0 {
            plus += delta;
        } else {
            minus -= delta;
        }
    }
    (plus.max(0) as u64, minus.max(0) as u64)
}

fn is_binary(bytes: &[u8]) -> bool {
    // What git does: a NUL in the first few kilobytes settles it.
    bytes.iter().take(8_000).any(|b| *b == 0)
}

// ---- what `ast pick` prints ------------------------------------------------

/// What `ast pick` is about to do, or has just done.
///
/// The same type for both, because the confirmation has to describe exactly
/// the thing that will happen — a plan the user agrees to and a report of
/// something slightly different is how a destructive command loses trust.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pick {
    pub parent: String,
    pub winner: String,
    /// The guest path being replaced: `/work`.
    pub path: String,
    /// The sibling forks that go away.
    #[serde(default)]
    pub removed: Vec<String>,
    /// The snapshot of the parent kept so this can be undone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kept_as: Option<String>,
    /// False for the plan, true once it has happened.
    #[serde(default)]
    pub applied: bool,
    #[serde(default)]
    pub elapsed_ms: u64,
    #[serde(default)]
    pub warnings: Vec<String>,
}

impl Pick {
    /// ```text
    /// bot ← bot-2 (/work replaced; bot-1, bot-3 removed)
    /// ```
    pub fn render(&self) -> String {
        let what = if self.removed.is_empty() {
            format!("{} replaced", self.path)
        } else {
            format!(
                "{} replaced; {} removed",
                self.path,
                self.removed.join(", ")
            )
        };
        let mut out = format!("{} \u{2190} {} ({what})", self.parent, self.winner);
        if self.applied {
            if let Some(kept) = &self.kept_as {
                out.push_str(&format!(
                    "\nthe {} it replaced is kept as {kept:?} — `ast rewind {} --to {kept}` undoes this",
                    self.path, self.parent,
                ));
            }
        }
        for warning in &self.warnings {
            out.push_str(&format!("\n{warning}"));
        }
        out
    }
}

// ---- refusals --------------------------------------------------------------

/// Is this many forks more than somebody should get without saying so twice?
pub fn needs_confirmation(count: usize) -> bool {
    count > SOFT_LIMIT
}

/// What to say when it is.
pub fn too_many(parent: &str, count: usize) -> String {
    format!(
        "{count} forks of {parent:?} is more than {SOFT_LIMIT} whole machines — \
         pass --yes if that is what you meant"
    )
}

/// What to say when the disk cannot hold what was asked for.
pub fn no_headroom(parent: &str, count: usize, needed: u64, free: u64) -> String {
    format!(
        "forking {parent:?} {count} way{} needs about {} and this filesystem has {} free — \
         this device cannot share blocks between the clones, so each fork costs what its \
         parent holds",
        if count == 1 { "" } else { "s" },
        cow::human(needed),
        cow::human(free),
    )
}

/// Free bytes on the filesystem holding `path`.
///
/// `None` rather than an error: not knowing is a reason to skip the headroom
/// check and say the clone cost what it wrote, not a reason to refuse a fork.
/// Windows has no `statvfs` and this tree does not link a second way of
/// asking, so there it is honestly unknown.
pub fn free_bytes(path: &std::path::Path) -> Option<u64> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        let c_path = std::ffi::CString::new(path.as_os_str().as_bytes()).ok()?;
        // SAFETY: `statvfs` fills a caller-owned struct and touches nothing
        // else; the zeroed struct is a valid target and is only read after
        // the call reports success.
        unsafe {
            let mut stat: libc::statvfs = std::mem::zeroed();
            if libc::statvfs(c_path.as_ptr(), &mut stat) != 0 {
                return None;
            }
            // `f_frsize` is the fragment size the counts are in; `f_bavail`
            // is what an unprivileged process may actually have, which is
            // the number a refusal has to be about.
            Some((stat.f_bavail as u64).saturating_mul(stat.f_frsize as u64))
        }
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn taken(names: &[&str]) -> Vec<String> {
        names.iter().map(|n| (*n).to_owned()).collect()
    }

    #[test]
    fn three_forks_of_a_fresh_parent_are_one_two_three() {
        assert_eq!(
            allocate("bot", 3, &taken(&["bot"])).unwrap(),
            vec!["bot-1", "bot-2", "bot-3"]
        );
    }

    /// `taken` is the whole namespace, not only the instances in it. A
    /// device called `bot-2` would make `ast ssh bot-2` mean two things, and
    /// a name generator has nobody to refuse — so it steps over the name.
    /// The caller supplies the device names; see `fork::held` in the daemon.
    #[test]
    fn a_fork_steps_over_a_name_a_device_in_the_orbit_answers_to() {
        let held = taken(&["bot", "bot-2", "bot-3"]);
        assert_eq!(allocate("bot", 2, &held).unwrap(), vec!["bot-1", "bot-4"]);
    }

    /// The whole reason numbers are skipped rather than reused: forking a
    /// second time while the first three are still running has to produce
    /// three more machines, not a refusal and not a collision.
    #[test]
    fn a_second_fork_carries_on_past_the_first() {
        let held = taken(&["bot", "bot-1", "bot-2", "bot-3"]);
        assert_eq!(
            allocate("bot", 3, &held).unwrap(),
            vec!["bot-4", "bot-5", "bot-6"]
        );
    }

    /// A hole left by `ast rm bot-2` is filled, because the numbers are a
    /// way of naming three machines and not a history of how many there
    /// have ever been.
    #[test]
    fn a_removed_fork_gives_its_number_back() {
        let held = taken(&["bot", "bot-1", "bot-3"]);
        assert_eq!(allocate("bot", 2, &held).unwrap(), vec!["bot-2", "bot-4"]);
    }

    #[test]
    fn zero_forks_and_more_than_the_hard_limit_are_both_refused() {
        assert!(allocate("bot", 0, &[]).is_err());
        assert!(allocate("bot", HARD_LIMIT + 1, &[]).is_err());
        assert!(allocate("bot", HARD_LIMIT, &[]).is_ok());
    }

    /// The fork names become directory names on every device in the orbit,
    /// so a parent whose name would not survive that is refused before any
    /// of them is created.
    #[test]
    fn a_parent_name_that_is_not_a_name_is_refused() {
        assert!(allocate("bot/../etc", 1, &[]).is_err());
    }

    #[test]
    fn each_is_all_the_forks_or_none_of_them() {
        assert_eq!(notes(3, &[]).unwrap(), vec![None, None, None]);
        let messages = taken(&["A", "B", "C"]);
        assert_eq!(
            notes(3, &messages).unwrap(),
            vec![
                Some("A".to_owned()),
                Some("B".to_owned()),
                Some("C".to_owned())
            ]
        );
        let two = taken(&["A", "B"]);
        let refusal = notes(3, &two).unwrap_err().to_string();
        assert!(
            refusal.contains("3 forks asked for, 2 messages given"),
            "{refusal}"
        );
    }

    #[test]
    fn the_fork_line_is_the_one_the_transcript_promised() {
        let report = Report {
            parent: "bot".into(),
            children: vec!["bot-1".into(), "bot-2".into(), "bot-3".into()],
            snapshot: fork_tag(1_700_000_000),
            elapsed_ms: 6_400,
            apparent_bytes: 2 * 1024 * 1024 * 1024,
            grew_bytes: Some(107_374_182),
            started: true,
            warnings: Vec::new(),
        };
        assert_eq!(
            report.render(),
            "bot-1 bot-2 bot-3 up — cloned from bot in 6.4 s, 1.90 GiB shared"
        );
    }

    /// A filesystem with no reflink is not made to look like one. There is
    /// nothing shared to report, so the line reports what was written.
    #[test]
    fn a_clone_that_really_copied_says_so() {
        let report = Report {
            parent: "bot".into(),
            children: vec!["bot-1".into()],
            snapshot: fork_tag(1),
            elapsed_ms: 12_000,
            apparent_bytes: 1024 * 1024 * 1024,
            grew_bytes: Some(1024 * 1024 * 1024),
            started: false,
            warnings: Vec::new(),
        };
        assert_eq!(report.shared_bytes(), Some(0));
        assert!(report.render().contains("0 B shared"));
    }

    /// Free space that moved further than the clone could account for is
    /// somebody else writing to this disk at the same time. That is not a
    /// share and must not be printed as one.
    #[test]
    fn an_unmeasurable_share_is_not_invented() {
        let mut report = Report {
            parent: "bot".into(),
            children: vec!["bot-1".into()],
            snapshot: fork_tag(1),
            elapsed_ms: 1_000,
            apparent_bytes: 1_000,
            grew_bytes: Some(9_000),
            started: true,
            warnings: Vec::new(),
        };
        assert_eq!(report.shared_bytes(), None);
        assert!(report.render().contains("1000 B cloned"));
        report.grew_bytes = None;
        assert_eq!(report.shared_bytes(), None);
    }

    #[test]
    fn the_diff_line_is_the_one_the_transcript_promised() {
        let diff = Diff {
            instance: "bot-2".into(),
            against: "bot @ 17:12".into(),
            path: "/work".into(),
            files: 3,
            added: 41,
            removed: 7,
            method: Method::Git,
            warnings: Vec::new(),
        };
        assert_eq!(
            diff.render(),
            "/work: 3 files changed, +41 \u{2212}7 (vs bot @ 17:12)"
        );
    }

    /// A fork nobody has touched yet is a common state — it is what every
    /// fork is for the first minute — and "0 files changed" reads like a
    /// broken measurement.
    #[test]
    fn a_fork_that_has_changed_nothing_says_so_in_words() {
        let diff = Diff {
            instance: "bot-1".into(),
            against: "bot @ 17:12".into(),
            path: "/work".into(),
            files: 0,
            added: 0,
            removed: 0,
            method: Method::Trees,
            warnings: Vec::new(),
        };
        assert_eq!(diff.render(), "/work: no changes (vs bot @ 17:12)");
    }

    #[test]
    fn numstat_counts_text_renames_and_binaries() {
        let (files, added, removed) = parse_numstat(
            "12\t3\tsrc/parser.rs\n\
             29\t4\tsrc/token.rs\n\
             -\t-\tassets/logo.png\n\
             0\t0\tsrc/a.rs => src/b.rs\n\
             not a numstat line\n",
        );
        assert_eq!((files, added, removed), (4, 41, 7));
    }

    fn write(dir: &std::path::Path, name: &str, body: &[u8]) {
        let path = dir.join(name);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, body).unwrap();
    }

    #[test]
    fn two_identical_trees_have_not_changed() {
        let (base, fork) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        write(base.path(), "src/a.rs", b"one\ntwo\n");
        write(fork.path(), "src/a.rs", b"one\ntwo\n");
        assert_eq!(tree_diff(base.path(), fork.path()), (0, 0, 0));
    }

    #[test]
    fn an_added_a_removed_and_an_edited_file_are_three_changed_files() {
        let (base, fork) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        write(base.path(), "keep.txt", b"same\n");
        write(base.path(), "gone.txt", b"a\nb\n");
        write(base.path(), "edit.txt", b"one\ntwo\nthree\n");
        write(fork.path(), "keep.txt", b"same\n");
        write(fork.path(), "new.txt", b"x\ny\nz\n");
        write(fork.path(), "edit.txt", b"one\nTWO\nthree\n");
        let (files, added, removed) = tree_diff(base.path(), fork.path());
        assert_eq!(files, 3);
        // new.txt three, edit.txt one; gone.txt two, edit.txt one. The
        // trailing newline is a line terminator on both sides and cancels,
        // which is how many lines `git` says those files are too.
        assert_eq!((added, removed), (4, 3));
    }

    /// The `--each` note is written by the fork, so it is in every fork and
    /// in no parent. Counting it would make every fork report one more
    /// changed file than its agent touched.
    #[test]
    fn the_fork_note_is_not_the_agents_work() {
        let (base, fork) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        write(fork.path(), NOTE_FILE, b"A: rewrite the parser\n");
        assert!(is_ours(std::path::Path::new(NOTE_FILE)));
        assert!(!is_ours(std::path::Path::new("parser.txt")));
        assert_eq!(tree_diff(base.path(), fork.path()), (0, 0, 0));
    }

    /// A repository's own object store is not the agent's work. Counting it
    /// would make one commit read as a thousand changed files.
    #[test]
    fn the_git_directory_is_never_compared() {
        let (base, fork) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        write(base.path(), ".git/objects/ab/cdef", b"one\n");
        write(fork.path(), ".git/objects/ab/cdef", b"something else\n");
        write(fork.path(), ".git/HEAD", b"ref: refs/heads/other\n");
        assert_eq!(tree_diff(base.path(), fork.path()), (0, 0, 0));
    }

    /// A changed binary is a changed file and no lines, which is what it is
    /// and what `git diff --numstat` says about one.
    #[test]
    fn a_binary_file_counts_as_changed_and_as_no_lines() {
        let (base, fork) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        write(base.path(), "logo.png", b"\x89PNG\x00\x01");
        write(fork.path(), "logo.png", b"\x89PNG\x00\x02");
        assert_eq!(tree_diff(base.path(), fork.path()), (1, 0, 0));
    }

    #[test]
    fn the_pick_line_is_the_one_the_transcript_promised() {
        let pick = Pick {
            parent: "bot".into(),
            winner: "bot-2".into(),
            path: "/work".into(),
            removed: vec!["bot-1".into(), "bot-3".into()],
            kept_as: Some(BEFORE_PICK.to_owned()),
            applied: false,
            elapsed_ms: 0,
            warnings: Vec::new(),
        };
        assert_eq!(
            pick.render(),
            "bot \u{2190} bot-2 (/work replaced; bot-1, bot-3 removed)"
        );
    }

    /// The plan and the report are the same sentence, so agreeing to one is
    /// agreeing to the other. The undo is added only once it exists.
    #[test]
    fn the_applied_pick_names_its_own_undo() {
        let pick = Pick {
            parent: "bot".into(),
            winner: "bot-2".into(),
            path: "/work".into(),
            removed: Vec::new(),
            kept_as: Some(BEFORE_PICK.to_owned()),
            applied: true,
            elapsed_ms: 900,
            warnings: Vec::new(),
        };
        let rendered = pick.render();
        assert!(
            rendered.starts_with("bot \u{2190} bot-2 (/work replaced)"),
            "{rendered}"
        );
        assert!(
            rendered.contains("ast rewind bot --to before-pick"),
            "{rendered}"
        );
    }

    #[test]
    fn provenance_reads_as_a_sentence_in_the_note_column() {
        let origin = Origin {
            parent: "bot".into(),
            snapshot: fork_tag(1_700_000_000),
            // 17:12 UTC, read at UTC.
            at: 1_700_000_000 - (1_700_000_000 % 86_400) + 17 * 3600 + 12 * 60,
            note: Some("A: rewrite the parser".into()),
        };
        assert_eq!(
            origin.line(0),
            "fork of bot @ 17:12 · A: rewrite the parser"
        );
        assert_eq!(origin.against(0), "bot @ 17:12");
    }

    #[test]
    fn a_fork_with_no_message_still_says_where_it_came_from() {
        let origin = Origin {
            parent: "bot".into(),
            snapshot: fork_tag(0),
            at: 0,
            note: None,
        };
        assert_eq!(origin.line(0), "fork of bot @ 00:00");
    }

    /// The tag has to be one `ast snapshot` would accept, or the snapshot a
    /// fork is measured against could not be taken at all.
    #[test]
    fn the_fork_tag_is_a_snapshot_tag() {
        crate::snapshot::validate_tag(&fork_tag(1_700_000_000)).unwrap();
        crate::snapshot::validate_tag(BEFORE_PICK).unwrap();
    }

    #[test]
    fn nine_is_fine_and_ten_wants_saying_twice() {
        assert!(!needs_confirmation(9));
        assert!(needs_confirmation(10));
        assert!(too_many("bot", 12).contains("--yes"));
    }

    #[test]
    fn free_space_is_a_number_or_an_honest_nothing() {
        let dir = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        assert!(free_bytes(dir.path()).is_some());
        assert_eq!(free_bytes(&dir.path().join("no-such-place")), None);
    }
}
