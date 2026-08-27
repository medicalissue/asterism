//! Automatic snapshots, and the timeline `ast rewind` walks back along.
//!
//! This is the part that makes full autonomy affordable. An agent told to
//! run with `--dangerously-skip-permissions` is worth more than one that
//! stops to ask, and the only thing that makes the first one reasonable is
//! being able to put the machine back the way it was. So the daemon takes a
//! disk snapshot on a timer, keeps a day of them, and `ast rewind` picks one.
//!
//! Everything here is either pure or a file operation on one instance's
//! directory. The scheduler that calls it lives in the daemon
//! (`astd`'s `autosnap`), and the engine that stops, rolls back and starts a
//! guest lives beside it (`rewind`); neither of those can be tested without a
//! hypervisor, and all of *this* can.
//!
//! # What a snapshot is here
//!
//! Exactly what [`crate::snapshot`] already made it: a copy-on-write clone of
//! the root disk in `instances/<name>/snapshots/<tag>.<format>`. Auto
//! snapshots add three things to that:
//!
//! * **A name that says where they came from.** `auto-<ISO 8601 basic UTC>`,
//!   which sorts chronologically, is unmistakably not something a human
//!   typed, and is what retention is allowed to delete. A tag without the
//!   prefix is a named snapshot and is kept forever, which is the whole
//!   contract of `ast snapshot dev before-migration`.
//! * **A sidecar.** `<tag>.meta`, JSON, holding when it was taken, what the
//!   disk looked like at the time, and what happened to the instance's
//!   volumes. The disk files stay exactly what they were — a snapshot is
//!   still a disk image anybody can `cp` — and the sidecar is skipped by
//!   [`crate::snapshot::list`] because its extension is not a disk format.
//! * **The volumes beside it.** A local directory volume is cloned into
//!   `<tag>.vol<N>/` alongside, because rewinding a root disk and leaving
//!   `/work` at the state the agent left it in would rewind nothing that
//!   matters. A block volume served over NBD is *not* snapshotted — the
//!   volume protocol has no request for it — and the sidecar records that in
//!   so many words, so the timeline and the CLI can both say so.
//!
//! # Crash consistency, said plainly
//!
//! `ast snapshot` refuses a running instance: a clone taken under a live
//! guest catches its disk mid-write. An automatic snapshot has no such
//! option — an agent that runs for a day is running when every one of them is
//! due — so it takes the clone anyway and the result is *crash consistent*:
//! exactly the disk a power cut would have left. A journalling filesystem
//! replays and comes up, which is why this is a reasonable thing to offer;
//! an unjournalled one, or a database with its own write-ahead log, gets
//! whatever a power cut would have given it. Nothing here pretends otherwise,
//! and quiescing the guest through its control agent before the clone is the
//! obvious next improvement rather than something this claims to do.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::cow;
use crate::snapshot;

// ---- settings --------------------------------------------------------------

/// How often an instance is snapshotted, and how long the automatic ones are
/// kept.
///
/// Two numbers rather than a policy object because there are exactly two
/// questions, and every answer to either is a duration. Named snapshots are
/// deliberately absent: they are never on a timer and never expire, so there
/// is nothing about them to configure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Settings {
    /// Gap between automatic snapshots, in seconds.
    pub every_secs: u64,
    /// How long an automatic snapshot survives, in seconds.
    pub keep_secs: u64,
}

/// Ten minutes: short enough that the work an agent loses to a rewind is a
/// coffee's worth, long enough that a copy-on-write clone every tick is free.
pub const DEFAULT_EVERY_SECS: u64 = 600;

/// A day. Long enough to cover "I went to bed and it did something strange",
/// which is the case this feature exists for.
pub const DEFAULT_KEEP_SECS: u64 = 86_400;

/// The shortest interval that is not a busy loop on somebody's disk.
pub const MIN_EVERY_SECS: u64 = 30;

/// Overrides the device-wide default interval. The e2e lane sets this to a
/// minute; there is no reason for anything else to.
const EVERY_ENV: &str = "ASTERISM_REWIND_EVERY";

/// Overrides the device-wide default retention.
const KEEP_ENV: &str = "ASTERISM_REWIND_KEEP";

impl Default for Settings {
    fn default() -> Self {
        Settings {
            every_secs: DEFAULT_EVERY_SECS,
            keep_secs: DEFAULT_KEEP_SECS,
        }
    }
}

impl Settings {
    /// This device's default, which an instance of its own overrides.
    ///
    /// Read from the environment the daemon was started with rather than from
    /// a file, because that is the whole of what a device-wide default needs
    /// to be: a value the person running `astd` can set once. A malformed
    /// value is reported and the default is used — a daemon that refuses to
    /// start because a duration has a typo in it would be a worse answer than
    /// snapshotting every ten minutes.
    pub fn device_default() -> Settings {
        let mut settings = Settings::default();
        if let Some(value) = env_duration(EVERY_ENV) {
            settings.every_secs = value;
        }
        if let Some(value) = env_duration(KEEP_ENV) {
            settings.keep_secs = value;
        }
        settings.clamped()
    }

    /// What an instance actually runs on: its own settings if it has any,
    /// this device's default otherwise.
    pub fn resolve(instance: Option<Settings>) -> Settings {
        instance.unwrap_or_else(Settings::device_default).clamped()
    }

    /// Refuse a setting that cannot mean what it says, before it is written.
    pub fn check(&self) -> Result<()> {
        if self.every_secs < MIN_EVERY_SECS {
            bail!(
                "a snapshot every {} is a busy loop on the disk — {}s is the shortest interval",
                human_duration(self.every_secs),
                MIN_EVERY_SECS
            );
        }
        if self.keep_secs < self.every_secs {
            bail!(
                "keeping snapshots for {} while taking one every {} would delete each \
                 one before the next — raise --keep or lower --every",
                human_duration(self.keep_secs),
                human_duration(self.every_secs)
            );
        }
        Ok(())
    }

    /// The same settings, made usable. Used on values that arrive from a
    /// registry or an environment variable rather than from a command, where
    /// there is nobody left to refuse to.
    fn clamped(self) -> Settings {
        let every_secs = self.every_secs.max(MIN_EVERY_SECS);
        Settings {
            every_secs,
            keep_secs: self.keep_secs.max(every_secs),
        }
    }
}

fn env_duration(name: &str) -> Option<u64> {
    let raw = std::env::var(name).ok()?;
    match parse_duration(raw.trim()) {
        Ok(seconds) => Some(seconds),
        Err(error) => {
            eprintln!("astd: ignoring {name}={raw:?}: {error:#}");
            None
        }
    }
}

// ---- durations -------------------------------------------------------------

/// `20m`, `2h`, `90s`, `1h30m`, `1d` — what a person types when they mean
/// "back a bit".
///
/// Deliberately not a general parser: no fractions, no spaces, no weeks. A
/// bare number is refused rather than assumed to be seconds, because the one
/// thing worse than `ast rewind bot 20` failing is it meaning twenty seconds
/// to the tool and twenty minutes to the person.
pub fn parse_duration(text: &str) -> Result<u64> {
    if text.is_empty() {
        bail!("how far back? try: 20m, 2h, 90s");
    }
    let mut total: u64 = 0;
    let mut digits = String::new();
    let mut units = 0;
    for c in text.chars() {
        if c.is_ascii_digit() {
            digits.push(c);
            continue;
        }
        let seconds = match c {
            's' => 1,
            'm' => 60,
            'h' => 3_600,
            'd' => 86_400,
            other => bail!(
                "{text:?} is not a duration: {other:?} is not one of s, m, h, d \
                 (try 20m, 2h, 90s, 1h30m)"
            ),
        };
        if digits.is_empty() {
            bail!("{text:?} is not a duration: {c:?} has no number in front of it");
        }
        let value: u64 = digits
            .parse()
            .with_context(|| format!("{text:?} is not a duration"))?;
        total = total.saturating_add(value.saturating_mul(seconds));
        digits.clear();
        units += 1;
    }
    if !digits.is_empty() {
        bail!(
            "{text:?} has no unit — say what {digits} is: {digits}s, {digits}m, \
             {digits}h or {digits}d"
        );
    }
    if units == 0 {
        bail!("{text:?} is not a duration: try 20m, 2h, 90s");
    }
    Ok(total)
}

/// A duration as the CLI prints it back: the same vocabulary it accepts, so
/// what is shown can be typed.
pub fn human_duration(seconds: u64) -> String {
    if seconds == 0 {
        return "0s".into();
    }
    let mut left = seconds;
    let mut out = String::new();
    for (unit, size) in [("d", 86_400u64), ("h", 3_600), ("m", 60), ("s", 1)] {
        let count = left / size;
        if count > 0 {
            out.push_str(&format!("{count}{unit}"));
            left -= count * size;
        }
    }
    out
}

// ---- what kind of snapshot this is -----------------------------------------

/// Where a snapshot came from, which is the only thing retention needs to
/// know about it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    /// Taken by the scheduler. Expires.
    Auto,
    /// Taken by `ast snapshot <instance> <tag>`. Kept forever.
    Named,
    /// The state a rewind replaced, so that a rewind can itself be undone.
    /// Rolling: there is only ever one, and it never expires.
    Rewind,
}

impl Kind {
    /// The word the timeline prints in its second column.
    pub fn label(self) -> &'static str {
        match self {
            Kind::Auto => "auto",
            Kind::Named => "named",
            Kind::Rewind => "rewind",
        }
    }
}

/// Prefix that marks a tag as the scheduler's rather than a person's.
pub const AUTO_PREFIX: &str = "auto-";

/// The rolling snapshot of what a rewind replaced.
pub const BEFORE_REWIND: &str = "before-rewind";

/// Where a rewind puts the state it is replacing while it works.
///
/// A rewind has to keep the current state *and* may be rewinding to
/// [`BEFORE_REWIND`] itself — undoing the last rewind is the second thing
/// anybody does with this — so it cannot simply overwrite that snapshot on
/// the way past. It stages the current state under this tag, rolls back,
/// then renames. A crash leaves this behind; the next rewind sweeps it, and
/// the timeline never shows it.
pub const STAGING: &str = "before-rewind.staging";

/// What a tag says about itself.
///
/// The tag is the identity — that is already true of every snapshot in this
/// tree — so this is a function of the name and nothing else. It means a
/// snapshot keeps its kind when its sidecar is lost, which is what makes
/// losing a sidecar harmless.
pub fn kind_of(tag: &str) -> Kind {
    if tag == BEFORE_REWIND {
        Kind::Rewind
    } else if tag.starts_with(AUTO_PREFIX) {
        Kind::Auto
    } else {
        Kind::Named
    }
}

/// The tag an automatic snapshot taken at `unix_secs` gets.
pub fn auto_tag(unix_secs: u64) -> String {
    let (year, month, day) = snapshot::civil_from_days((unix_secs / 86_400) as i64);
    let secs = unix_secs % 86_400;
    format!(
        "{AUTO_PREFIX}{year:04}{month:02}{day:02}T{:02}{:02}{:02}Z",
        secs / 3600,
        (secs % 3600) / 60,
        secs % 60
    )
}

/// Refuse a human-typed tag that would pass for one of ours.
///
/// `ast snapshot dev auto-whatever` would otherwise create a "named"
/// snapshot that retention deletes a day later, which is the opposite of
/// what the person asked for.
pub fn check_human_tag(tag: &str) -> Result<()> {
    snapshot::validate_tag(tag)?;
    if tag.starts_with(AUTO_PREFIX) {
        bail!(
            "{AUTO_PREFIX:?} is how automatic snapshots are named, and those are \
             deleted when they expire — pick another name for one you want kept"
        );
    }
    if tag == BEFORE_REWIND {
        bail!(
            "{BEFORE_REWIND:?} is the snapshot a rewind writes over the state it \
             replaced, so it is overwritten by the next rewind — pick another name"
        );
    }
    Ok(())
}

// ---- what the disk looked like ---------------------------------------------

/// The cheap evidence that a disk has or has not moved since the last
/// snapshot.
///
/// Length and modification time, and that is the honest limit of what a
/// backend tells us. None of the four hypervisors behind
/// [`crate::hv::Hypervisor`] exposes a dirty bitmap through the boundary:
/// VZ writes its raw disk through Virtualization.framework, Cloud Hypervisor
/// and QEMU write theirs through their own block layer, Hyper-V writes a
/// VHDX from the parent partition. What every one of them leaves behind is a
/// file whose mtime moves when the guest writes, so that is what is compared.
///
/// Two consequences worth writing down rather than discovering:
///
/// * A guest that writes the same bytes back still moves the mtime, so this
///   over-reports change. The cost of that is a copy-on-write clone that
///   shares every block — very nearly nothing.
/// * A guest that writes nothing at all leaves the mtime alone, and the tick
///   skips. That is the case this exists for: an agent waiting on a human
///   overnight should not accumulate 144 identical snapshots.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Fingerprint {
    pub len: u64,
    pub mtime_secs: u64,
    pub mtime_nanos: u32,
}

/// What one file looks like right now.
pub fn fingerprint(path: &Path) -> Result<Fingerprint> {
    let meta = std::fs::metadata(path)
        .with_context(|| format!("reading {} to see whether it changed", path.display()))?;
    Ok(from_metadata(&meta))
}

fn from_metadata(meta: &std::fs::Metadata) -> Fingerprint {
    let modified = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok());
    Fingerprint {
        len: meta.len(),
        mtime_secs: modified.map(|d| d.as_secs()).unwrap_or(0),
        mtime_nanos: modified.map(|d| d.subsec_nanos()).unwrap_or(0),
    }
}

/// The same question asked of a directory tree: the total length of every
/// regular file under it, and the newest mtime among them.
///
/// A rename inside the tree that changes no file moves no mtime, so this is
/// combined with the total length; between them a directory whose contents
/// changed is very unlikely to look identical. It is a heuristic and is used
/// as one — the cost of being wrong is a skipped clone of a directory whose
/// files all still say what they said.
pub fn tree_fingerprint(dir: &Path) -> Result<Fingerprint> {
    let mut print = Fingerprint::default();
    let mut count: u64 = 0;
    walk(dir, &mut |path, meta| {
        count += 1;
        let file = from_metadata(meta);
        print.len = print.len.saturating_add(file.len);
        if (file.mtime_secs, file.mtime_nanos) > (print.mtime_secs, print.mtime_nanos) {
            print.mtime_secs = file.mtime_secs;
            print.mtime_nanos = file.mtime_nanos;
        }
        let _ = path;
        Ok(())
    })?;
    // Folded in so that deleting one file and creating another of the same
    // size is not invisible.
    print.len = print.len.wrapping_add(count);
    Ok(print)
}

/// Every regular file under `dir`, depth first. Symlinks are counted as the
/// links they are and never followed: a `/work` with a symlink to `/` in it
/// must not turn a snapshot into a copy of the host.
fn walk(dir: &Path, f: &mut dyn FnMut(&Path, &std::fs::Metadata) -> Result<()>) -> Result<()> {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e).with_context(|| format!("reading {}", dir.display())),
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let meta = match std::fs::symlink_metadata(&path) {
            Ok(meta) => meta,
            // A file that vanished between the listing and the stat is one
            // the guest deleted, which is a change we will see next tick.
            Err(_) => continue,
        };
        if meta.is_dir() {
            walk(&path, f)?;
        } else {
            f(&path, &meta)?;
        }
    }
    Ok(())
}

// ---- the sidecar -----------------------------------------------------------

/// What happened to one of the instance's volumes when a snapshot was taken.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VolumeShot {
    /// The host directory, or the block volume's name on its device.
    pub source: String,
    /// Where it appears inside the guest, when that is known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mount_point: Option<String>,
    /// The directory beside the snapshot holding the clone, when there is
    /// one. Relative to the snapshots directory.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub clone_dir: Option<String>,
    /// Why there is no clone, when there is not. Printed as-is.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_snapshotted: Option<String>,
    /// What the tree looked like, for the next tick's change check.
    #[serde(default)]
    pub print: Fingerprint,
}

impl VolumeShot {
    pub fn is_cloned(&self) -> bool {
        self.clone_dir.is_some()
    }
}

/// The sidecar written beside every snapshot this module takes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Meta {
    pub tag: String,
    pub kind: Kind,
    /// Unix seconds. Authoritative over the file's mtime, which a restore
    /// or a backup round trip can move.
    pub taken_at: u64,
    /// The root disk as it was when this was taken.
    #[serde(default)]
    pub disk: Fingerprint,
    #[serde(default)]
    pub volumes: Vec<VolumeShot>,
    /// How long taking it cost, in milliseconds.
    #[serde(default)]
    pub elapsed_ms: u64,
}

/// Sidecar extension. Not one of [`crate::snapshot`]'s disk formats, which is
/// what keeps the snapshot listing a listing of disks.
const META_EXTENSION: &str = "meta";

/// Prefix of a cloned volume's directory: `<tag>.vol0`, `<tag>.vol1`.
const VOLUME_INFIX: &str = ".vol";

pub fn meta_path(instance_dir: &Path, tag: &str) -> PathBuf {
    snapshot::dir(instance_dir).join(format!("{tag}.{META_EXTENSION}"))
}

pub fn volume_clone_name(tag: &str, index: usize) -> String {
    format!("{tag}{VOLUME_INFIX}{index}")
}

pub fn read_meta(instance_dir: &Path, tag: &str) -> Option<Meta> {
    let text = std::fs::read_to_string(meta_path(instance_dir, tag)).ok()?;
    serde_json::from_str(&text).ok()
}

pub fn write_meta(instance_dir: &Path, meta: &Meta) -> Result<()> {
    let path = meta_path(instance_dir, &meta.tag);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let body = serde_json::to_vec_pretty(meta)?;
    crate::durable::commit(&path, &body).with_context(|| format!("writing {}", path.display()))
}

/// Remove everything that belongs to a snapshot but is not the disk image:
/// the sidecar, and any cloned volume trees.
///
/// Called by [`crate::snapshot::remove`] so that `ast snapshot rm` and this
/// module's own retention leave the same directory behind. Best effort by
/// design — a sidecar that will not unlink must not fail a deletion whose
/// disk image is already gone.
pub fn forget_sidecars(instance_dir: &Path, tag: &str) {
    let _ = std::fs::remove_file(meta_path(instance_dir, tag));
    let dir = snapshot::dir(instance_dir);
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return;
    };
    let prefix = format!("{tag}{VOLUME_INFIX}");
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if name.starts_with(&prefix) && entry.path().is_dir() {
            let _ = std::fs::remove_dir_all(entry.path());
        }
    }
}

// ---- the timeline ----------------------------------------------------------

/// One row of `ast rewind <instance>`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    pub tag: String,
    pub kind: Kind,
    /// Unix seconds.
    pub taken_at: u64,
    /// Blocks the snapshot actually occupies — the disk clone plus any
    /// cloned volume tree. A fresh clone is very nearly free and grows only
    /// as the live disk moves away from it.
    pub bytes: u64,
    #[serde(default)]
    pub volumes: Vec<VolumeShot>,
}

impl Entry {
    /// The volumes this snapshot could not take, if any.
    pub fn missing_volumes(&self) -> Vec<&VolumeShot> {
        self.volumes
            .iter()
            .filter(|v| v.not_snapshotted.is_some())
            .collect()
    }
}

/// Everything `ast rewind <instance>` prints, as data.
///
/// Assembled by the daemon and rendered by the CLI, so the layout is decided
/// once, in [`render`], and tested without a daemon.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Timeline {
    pub instance: String,
    /// Newest first, which is the order they are read in.
    pub entries: Vec<Entry>,
    pub settings: Settings,
    /// Said instead of a timeline when this instance cannot have one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

impl Timeline {
    pub fn total_bytes(&self) -> u64 {
        self.entries.iter().map(|e| e.bytes).sum()
    }

    pub fn find(&self, tag: &str) -> Option<&Entry> {
        self.entries.iter().find(|e| e.tag == tag)
    }

    /// The newest snapshot taken at or before `when`.
    pub fn at_or_before(&self, when: u64) -> Option<&Entry> {
        self.entries.iter().find(|e| e.taken_at <= when)
    }

    pub fn oldest(&self) -> Option<&Entry> {
        self.entries.last()
    }
}

/// What the user asked to rewind to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Target {
    /// `ast rewind bot 20m`.
    Back { seconds: u64 },
    /// `ast rewind bot --to before-refactor`.
    Tag { tag: String },
}

impl std::fmt::Display for Target {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Target::Back { seconds } => write!(f, "{} ago", human_duration(*seconds)),
            Target::Tag { tag } => write!(f, "{tag:?}"),
        }
    }
}

/// Pick the snapshot a target names, or say why there is none — before
/// anything has been stopped, cloned or replaced.
///
/// Every refusal here carries the timeline, because the next thing the person
/// would type is `ast rewind <instance>` and there is no reason to make them.
pub fn select<'a>(timeline: &'a Timeline, target: &Target, now: u64) -> Result<&'a Entry> {
    if timeline.entries.is_empty() {
        bail!(
            "{} has no snapshots yet — the first automatic one is due within {}",
            timeline.instance,
            human_duration(timeline.settings.every_secs)
        );
    }
    match target {
        Target::Tag { tag } => timeline.find(tag).ok_or_else(|| {
            anyhow::anyhow!(
                "no snapshot {tag:?} for {} — the timeline:\n{}",
                timeline.instance,
                render(timeline, now, 0, false)
            )
        }),
        Target::Back { seconds } => {
            let cutoff = now.saturating_sub(*seconds);
            timeline.at_or_before(cutoff).ok_or_else(|| {
                let oldest = timeline.oldest().expect("entries is not empty");
                anyhow::anyhow!(
                    "{} has nothing from {} ago — the oldest snapshot is {} old ({}). \
                     The timeline:\n{}",
                    timeline.instance,
                    human_duration(*seconds),
                    human_duration(now.saturating_sub(oldest.taken_at)),
                    oldest.tag,
                    render(timeline, now, 0, false)
                )
            })
        }
    }
}

/// What a finished rewind did, as the CLI prints it.
///
/// A report rather than a rendered line, so the daemon says what happened and
/// the CLI decides how it reads — the same division the timeline uses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Report {
    pub instance: String,
    /// The snapshot rolled back to.
    pub tag: String,
    /// When that snapshot was taken, unix seconds.
    pub taken_at: u64,
    /// Wall clock the whole thing cost, from the stop to the last published
    /// port, in milliseconds.
    pub elapsed_ms: u64,
    /// The rolling snapshot of the state that was replaced, when one was
    /// taken. Absent when the instance had no disk to save — it had never
    /// been booted — which is the only case that skips it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kept_as: Option<String>,
    /// Whether the guest was running before, and so was started again.
    pub restarted: bool,
    /// Ports re-published on the way back up.
    #[serde(default)]
    pub republished: usize,
    /// Volumes that came back with the root disk, and the ones that did not.
    #[serde(default)]
    pub volumes: Vec<VolumeShot>,
    /// Anything the user has to know that is not a failure: a port that
    /// could not be reclaimed, a volume left where it was.
    #[serde(default)]
    pub warnings: Vec<String>,
}

impl Report {
    /// The line the transcript promised:
    ///
    /// ```text
    /// bot rewound to 14:00 (3.1 s) — current state kept as "before-rewind"
    /// ```
    pub fn render(&self, offset: i64, now: u64) -> String {
        let when = clock(self.taken_at, offset, local_day(now, offset));
        let seconds = self.elapsed_ms as f64 / 1000.0;
        let mut out = format!("{} rewound to {when} ({seconds:.1} s)", self.instance);
        match &self.kept_as {
            Some(kept) => out.push_str(&format!(" — current state kept as {kept:?}")),
            None => out.push_str(" — nothing to keep: it had never been booted"),
        }
        for volume in &self.volumes {
            if let Some(why) = &volume.not_snapshotted {
                out.push_str(&format!("\n{why}"));
            }
        }
        for warning in &self.warnings {
            out.push_str(&format!("\n{warning}"));
        }
        out
    }
}

// ---- retention -------------------------------------------------------------

/// The automatic snapshots that have outlived the retention window.
///
/// Three rules, and all three are about not surprising somebody:
///
/// * A named snapshot never expires. That is what naming one means.
/// * `before-rewind` never expires. It is the undo for the rewind that made
///   it, and a rewind is exactly when somebody is least sure.
/// * The newest automatic snapshot never expires, however old it is. An
///   instance that was busy yesterday and idle since has one snapshot left,
///   and deleting it because it aged out would leave a timeline with nothing
///   on it — which is the one state this feature must never reach.
pub fn expired(entries: &[Entry], now: u64, keep_secs: u64) -> Vec<String> {
    let newest_auto = entries
        .iter()
        .filter(|e| e.kind == Kind::Auto)
        .max_by_key(|e| e.taken_at)
        .map(|e| e.tag.as_str());
    entries
        .iter()
        .filter(|e| e.kind == Kind::Auto)
        .filter(|e| Some(e.tag.as_str()) != newest_auto)
        .filter(|e| now.saturating_sub(e.taken_at) > keep_secs)
        .map(|e| e.tag.clone())
        .collect()
}

/// Is another automatic snapshot due?
pub fn due(newest_auto: Option<u64>, now: u64, every_secs: u64) -> bool {
    match newest_auto {
        None => true,
        Some(taken_at) => now.saturating_sub(taken_at) >= every_secs,
    }
}

// ---- rendering -------------------------------------------------------------

/// The timeline, exactly as `ast rewind <instance>` prints it.
///
/// ```text
///  14:20  auto    (now)
///  14:10  auto
///  14:00  named   before-refactor
///  13:50  auto
/// ```
///
/// Three columns: when, what kind, and what it is called — with the newest
/// row marked `(now)`, because the first question anybody asks a timeline is
/// which end of it they are standing on.
///
/// `offset` is the viewer's UTC offset in seconds; the times are theirs, not
/// the daemon's, and not UTC. The footer is only printed for `--usage`, so
/// the bare listing stays the four lines above.
pub fn render(timeline: &Timeline, now: u64, offset: i64, usage: bool) -> String {
    if let Some(note) = &timeline.note {
        return note.clone();
    }
    if timeline.entries.is_empty() {
        return format!(
            "{} has no snapshots yet — one is taken every {}, and `ast snapshot {} <name>` \
             takes one that is kept forever",
            timeline.instance,
            human_duration(timeline.settings.every_secs),
            timeline.instance
        );
    }
    let today = local_day(now, offset);
    let stamps: Vec<String> = timeline
        .entries
        .iter()
        .map(|entry| clock(entry.taken_at, offset, today))
        .collect();
    let width = stamps.iter().map(String::len).max().unwrap_or(5);
    let mut out = String::new();
    for (index, entry) in timeline.entries.iter().enumerate() {
        let mut note = match entry.kind {
            Kind::Auto => String::new(),
            _ => entry.tag.clone(),
        };
        if index == 0 {
            if note.is_empty() {
                note.push_str("(now)");
            } else {
                note.push_str("  (now)");
            }
        }
        out.push_str(&format!(
            " {:>width$}  {:<8}{}",
            stamps[index],
            entry.kind.label(),
            note,
            width = width
        ));
        // The kind column is padded whether or not anything follows it, so
        // trailing spaces are trimmed rather than shipped to a terminal.
        while out.ends_with(' ') {
            out.pop();
        }
        out.push('\n');
        for missing in entry.missing_volumes() {
            out.push_str(&format!(
                " {:>width$}          {}\n",
                "",
                missing
                    .not_snapshotted
                    .as_deref()
                    .unwrap_or("volume not snapshotted"),
                width = width
            ));
        }
    }
    if usage {
        out.push_str(&format!(
            "\n{} snapshot{}, {} — auto every {}, kept {}\n",
            timeline.entries.len(),
            if timeline.entries.len() == 1 { "" } else { "s" },
            cow::human(timeline.total_bytes()),
            human_duration(timeline.settings.every_secs),
            human_duration(timeline.settings.keep_secs),
        ));
    }
    out
}

/// `14:20` for something from today, `08-26 14:20` for anything older, so a
/// timeline that crosses midnight does not print two rows an hour apart that
/// look ten minutes apart.
fn clock(unix_secs: u64, offset: i64, today: i64) -> String {
    let local = (unix_secs as i64) + offset;
    let day = local.div_euclid(86_400);
    let secs = local.rem_euclid(86_400);
    let (hour, minute) = (secs / 3600, (secs % 3600) / 60);
    if day == today {
        format!("{hour:02}:{minute:02}")
    } else {
        let (_, month, dom) = snapshot::civil_from_days(day);
        format!("{month:02}-{dom:02} {hour:02}:{minute:02}")
    }
}

fn local_day(unix_secs: u64, offset: i64) -> i64 {
    ((unix_secs as i64) + offset).div_euclid(86_400)
}

/// The viewer's offset from UTC, in seconds, at `unix_secs`.
///
/// Asked of the C library rather than computed, because a timezone is a
/// database and this tree is not going to carry one. Windows has no
/// `localtime_r`, so it reads UTC — an honest zero rather than a guess.
pub fn local_offset(unix_secs: u64) -> i64 {
    #[cfg(unix)]
    {
        // SAFETY: `localtime_r` fills a caller-owned `tm` and touches nothing
        // else; the zeroed struct is a valid target, and the result is only
        // read after the call reports success.
        unsafe {
            let time = unix_secs as libc::time_t;
            let mut tm: libc::tm = std::mem::zeroed();
            if libc::localtime_r(&time, &mut tm).is_null() {
                0
            } else {
                tm.tm_gmtoff as i64
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = unix_secs;
        0
    }
}

// ---- reading the directory -------------------------------------------------

/// The root disk of an instance, whatever format its backend chose.
///
/// Found by looking rather than by asking a backend to `prepare()`: preparing
/// resolves and verifies a base image, which is the right thing to do before
/// a boot and much too much to do every ten minutes on an instance that is
/// already running off a disk that plainly exists.
pub fn root_disk(instance_dir: &Path) -> Result<PathBuf> {
    for name in ["disk.raw", "disk.qcow2", "disk.vhdx"] {
        let candidate = instance_dir.join(name);
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    bail!(
        "no root disk in {} — nothing has been booted from this instance yet",
        instance_dir.display()
    )
}

/// Every snapshot of this instance, newest first.
pub fn read_entries(instance_dir: &Path) -> Result<Vec<Entry>> {
    let dir = snapshot::dir(instance_dir);
    let mut entries: Vec<Entry> = Vec::new();
    for listed in snapshot::list(instance_dir)? {
        if listed.tag == STAGING {
            continue;
        }
        let meta = read_meta(instance_dir, &listed.tag);
        let taken_at = match &meta {
            Some(meta) if meta.taken_at > 0 => meta.taken_at,
            _ => file_mtime(&dir, &listed.tag),
        };
        let volumes = meta.map(|m| m.volumes).unwrap_or_default();
        let mut bytes = disk_usage(&dir, &listed.tag);
        for volume in &volumes {
            if let Some(clone) = &volume.clone_dir {
                bytes = bytes.saturating_add(tree_usage(&dir.join(clone)));
            }
        }
        entries.push(Entry {
            kind: kind_of(&listed.tag),
            tag: listed.tag,
            taken_at,
            bytes,
            volumes,
        });
    }
    entries.sort_by(|a, b| b.taken_at.cmp(&a.taken_at).then(a.tag.cmp(&b.tag)));
    Ok(entries)
}

fn snapshot_file(dir: &Path, tag: &str) -> Option<PathBuf> {
    for extension in ["raw", "qcow2", "vhdx"] {
        let candidate = dir.join(format!("{tag}.{extension}"));
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

fn file_mtime(dir: &Path, tag: &str) -> u64 {
    snapshot_file(dir, tag)
        .and_then(|path| fingerprint(&path).ok())
        .map(|print| print.mtime_secs)
        .unwrap_or(0)
}

fn disk_usage(dir: &Path, tag: &str) -> u64 {
    snapshot_file(dir, tag)
        .and_then(|path| cow::usage(&path).ok())
        .unwrap_or(0)
}

/// Blocks occupied by everything under a directory.
pub fn tree_usage(dir: &Path) -> u64 {
    let mut total = 0u64;
    let _ = walk(dir, &mut |path, _| {
        total = total.saturating_add(cow::usage(path).unwrap_or(0));
        Ok(())
    });
    total
}

/// Move a snapshot and everything that belongs to it under a new tag.
///
/// The disk image, the sidecar and any cloned volume directories, all
/// renamed within the snapshots directory — so this is atomic per file and
/// costs nothing, which is what lets a rewind stage the state it is
/// replacing and only claim [`BEFORE_REWIND`] once the rollback has read
/// whatever was there.
pub fn rename(instance_dir: &Path, from: &str, to: &str) -> Result<()> {
    snapshot::validate_tag(from)?;
    snapshot::validate_tag(to)?;
    let dir = snapshot::dir(instance_dir);
    let image = snapshot_file(&dir, from)
        .ok_or_else(|| anyhow::anyhow!("no snapshot {from:?} to rename"))?;
    let extension = image
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("raw")
        .to_owned();
    std::fs::rename(&image, dir.join(format!("{to}.{extension}")))
        .with_context(|| format!("renaming snapshot {from:?} to {to:?}"))?;
    if let Some(mut meta) = read_meta(instance_dir, from) {
        meta.tag = to.to_owned();
        for volume in &mut meta.volumes {
            if let Some(clone) = &volume.clone_dir {
                if let Some(suffix) = clone.strip_prefix(&format!("{from}{VOLUME_INFIX}")) {
                    volume.clone_dir = Some(format!("{to}{VOLUME_INFIX}{suffix}"));
                }
            }
        }
        write_meta(instance_dir, &meta)?;
        let _ = std::fs::remove_file(meta_path(instance_dir, from));
    }
    let prefix = format!("{from}{VOLUME_INFIX}");
    if let Ok(entries) = std::fs::read_dir(&dir) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            let Some(suffix) = name.strip_prefix(&prefix) else {
                continue;
            };
            if entry.path().is_dir() {
                let _ = std::fs::rename(
                    entry.path(),
                    dir.join(format!("{to}{VOLUME_INFIX}{suffix}")),
                );
            }
        }
    }
    Ok(())
}

// ---- cloning a directory volume --------------------------------------------

/// Copy-on-write clone of a whole directory tree.
///
/// Per file, through [`cow::clone_file`], so a `/work` on APFS costs nothing
/// until it is written to and a `/work` on a filesystem without reflinks
/// costs what it holds rather than what it claims. Symlinks are recreated as
/// symlinks and never followed; anything that is neither a file, a directory
/// nor a symlink (a socket an agent left behind, a fifo) is skipped, because
/// a snapshot of a socket is not a thing.
pub fn clone_tree(src: &Path, dst: &Path) -> Result<()> {
    std::fs::create_dir_all(dst)
        .with_context(|| format!("creating {} for a volume snapshot", dst.display()))?;
    let entries = match std::fs::read_dir(src) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e).with_context(|| format!("reading {}", src.display())),
    };
    for entry in entries.flatten() {
        let from = entry.path();
        let Some(name) = from.file_name() else {
            continue;
        };
        let to = dst.join(name);
        let meta = match std::fs::symlink_metadata(&from) {
            Ok(meta) => meta,
            Err(_) => continue,
        };
        if meta.is_dir() {
            clone_tree(&from, &to)?;
        } else if meta.is_file() {
            cow::clone_file(&from, &to).with_context(|| format!("cloning {}", from.display()))?;
        } else if meta.is_symlink() {
            copy_symlink(&from, &to)?;
        }
    }
    Ok(())
}

#[cfg(unix)]
fn copy_symlink(from: &Path, to: &Path) -> Result<()> {
    let target = std::fs::read_link(from)?;
    std::os::unix::fs::symlink(target, to)
        .with_context(|| format!("recreating the symlink {}", to.display()))
}

#[cfg(not(unix))]
fn copy_symlink(from: &Path, _to: &Path) -> Result<()> {
    // Creating a symlink on Windows needs a privilege the daemon does not
    // ask for. Skipping one is better than failing the snapshot of every
    // other file beside it.
    eprintln!(
        "astd: not recreating the link {} in a volume snapshot",
        from.display()
    );
    Ok(())
}

/// Put a directory volume back to what a snapshot holds.
///
/// Built beside the target and swapped in, for the same reason
/// [`crate::snapshot::restore`] clones and renames: a clone that fails
/// halfway leaves the volume exactly as it was, rather than half replaced.
/// The instance is stopped while this runs — the rewind engine stops it —
/// so nothing is holding the directory open.
pub fn restore_tree(snapshot_dir: &Path, target: &Path) -> Result<()> {
    if !snapshot_dir.is_dir() {
        bail!(
            "the volume snapshot at {} is missing",
            snapshot_dir.display()
        );
    }
    let staged = sibling(target, ".rewinding")?;
    let retired = sibling(target, ".rewound")?;
    let _ = std::fs::remove_dir_all(&staged);
    let _ = std::fs::remove_dir_all(&retired);
    clone_tree(snapshot_dir, &staged)?;
    if target.exists() {
        std::fs::rename(target, &retired).with_context(|| {
            format!(
                "moving {} aside to put the snapshot in its place",
                target.display()
            )
        })?;
    }
    match std::fs::rename(&staged, target) {
        Ok(()) => {
            let _ = std::fs::remove_dir_all(&retired);
            Ok(())
        }
        Err(error) => {
            // Put back what was moved aside: a failed rewind must leave the
            // volume where it found it.
            let _ = std::fs::rename(&retired, target);
            let _ = std::fs::remove_dir_all(&staged);
            Err(error).with_context(|| format!("replacing {}", target.display()))
        }
    }
}

fn sibling(path: &Path, suffix: &str) -> Result<PathBuf> {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| anyhow::anyhow!("{} has no name to work beside", path.display()))?;
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("{} has no parent directory", path.display()))?;
    Ok(parent.join(format!("{name}{suffix}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(tag: &str, taken_at: u64) -> Entry {
        Entry {
            kind: kind_of(tag),
            tag: tag.to_owned(),
            taken_at,
            bytes: 0,
            volumes: Vec::new(),
        }
    }

    fn timeline(entries: Vec<Entry>) -> Timeline {
        Timeline {
            instance: "bot".into(),
            entries,
            settings: Settings::default(),
            note: None,
        }
    }

    // ---- durations ---------------------------------------------------------

    #[test]
    fn the_durations_a_person_types_parse() {
        assert_eq!(parse_duration("20m").unwrap(), 1_200);
        assert_eq!(parse_duration("2h").unwrap(), 7_200);
        assert_eq!(parse_duration("90s").unwrap(), 90);
        assert_eq!(parse_duration("1h30m").unwrap(), 5_400);
        assert_eq!(parse_duration("1d").unwrap(), 86_400);
        assert_eq!(parse_duration("1d2h3m4s").unwrap(), 93_784);
    }

    /// A bare number is the dangerous one: it would mean seconds to a parser
    /// and minutes to whoever typed it.
    #[test]
    fn a_number_without_a_unit_is_refused_rather_than_assumed() {
        let error = parse_duration("20").unwrap_err().to_string();
        assert!(error.contains("20m"), "{error}");
        assert!(parse_duration("").is_err());
        assert!(parse_duration("m").is_err());
        assert!(parse_duration("20w").is_err());
        assert!(parse_duration("2 0m").is_err());
    }

    #[test]
    fn a_duration_prints_back_as_something_that_would_parse() {
        for seconds in [1u64, 59, 60, 90, 3_600, 5_400, 86_400, 93_784] {
            let printed = human_duration(seconds);
            assert_eq!(parse_duration(&printed).unwrap(), seconds, "{printed}");
        }
    }

    // ---- kinds -------------------------------------------------------------

    #[test]
    fn a_tag_says_which_kind_of_snapshot_it_is() {
        assert_eq!(kind_of("auto-20260827T142000Z"), Kind::Auto);
        assert_eq!(kind_of(BEFORE_REWIND), Kind::Rewind);
        assert_eq!(kind_of("before-refactor"), Kind::Named);
        assert_eq!(kind_of("nightly"), Kind::Named);
    }

    #[test]
    fn an_auto_tag_sorts_chronologically_and_reads_as_automatic() {
        let early = auto_tag(1_756_300_000);
        let late = auto_tag(1_756_303_600);
        assert!(early < late, "{early} {late}");
        assert_eq!(kind_of(&early), Kind::Auto);
    }

    /// Naming a snapshot is a promise that it is kept. A name that retention
    /// would later delete breaks that promise silently, so it is refused
    /// where it is typed.
    #[test]
    fn a_human_cannot_take_a_name_that_expires() {
        assert!(check_human_tag("before-migration").is_ok());
        assert!(check_human_tag("auto-mine").is_err());
        assert!(check_human_tag(BEFORE_REWIND).is_err());
        assert!(check_human_tag("has space").is_err());
    }

    // ---- retention ---------------------------------------------------------

    #[test]
    fn only_expired_automatic_snapshots_are_pruned() {
        let now = 1_000_000;
        let day = 86_400;
        let entries = vec![
            entry("auto-new", now - 60),
            entry("auto-old", now - day - 60),
            entry("auto-older", now - 2 * day),
            entry("before-refactor", now - 3 * day),
            entry(BEFORE_REWIND, now - 4 * day),
        ];
        let pruned = expired(&entries, now, day);
        assert_eq!(pruned, vec!["auto-old".to_owned(), "auto-older".to_owned()]);
    }

    /// The case that would empty a timeline: one automatic snapshot, older
    /// than the window, and nothing else. Deleting it would leave nothing to
    /// rewind to, which is the one outcome this feature may not produce.
    #[test]
    fn the_newest_automatic_snapshot_outlives_its_own_window() {
        let now = 1_000_000;
        let entries = vec![entry("auto-only", now - 10 * 86_400)];
        assert!(expired(&entries, now, 86_400).is_empty());
    }

    #[test]
    fn a_named_snapshot_never_expires_however_old() {
        let now = 1_000_000;
        let entries = vec![entry("release", 0), entry(BEFORE_REWIND, 0)];
        assert!(expired(&entries, now, 60).is_empty());
    }

    #[test]
    fn the_next_snapshot_is_due_an_interval_after_the_last() {
        assert!(due(None, 1_000, 600));
        assert!(!due(Some(900), 1_000, 600));
        assert!(due(Some(400), 1_000, 600));
        assert!(due(Some(400), 1_000, 600));
    }

    // ---- selection ---------------------------------------------------------

    #[test]
    fn a_duration_picks_the_newest_snapshot_at_or_before_it() {
        let now = 51_600; // 14:20 UTC
        let line = timeline(vec![
            entry("auto-1420", 51_600),
            entry("auto-1410", 51_000),
            entry("before-refactor", 50_400),
            entry("auto-1350", 49_800),
        ]);
        let picked = select(&line, &Target::Back { seconds: 1_200 }, now).unwrap();
        assert_eq!(picked.tag, "before-refactor", "14:20 less 20m is 14:00");
    }

    #[test]
    fn a_named_target_that_is_not_there_is_refused_with_the_timeline() {
        let now = 51_600;
        let line = timeline(vec![entry("auto-1420", 51_600)]);
        let error = select(
            &line,
            &Target::Tag {
                tag: "before-refactor".into(),
            },
            now,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("no snapshot \"before-refactor\""), "{error}");
        assert!(
            error.contains("auto"),
            "the timeline is in the refusal: {error}"
        );
    }

    #[test]
    fn a_duration_older_than_everything_says_how_far_back_it_can_go() {
        let now = 100_000;
        let line = timeline(vec![entry("auto-a", 99_000)]);
        let error = select(&line, &Target::Back { seconds: 86_400 }, now)
            .unwrap_err()
            .to_string();
        assert!(error.contains("the oldest snapshot"), "{error}");
    }

    #[test]
    fn an_empty_timeline_refuses_before_anything_is_stopped() {
        let error = select(&timeline(Vec::new()), &Target::Back { seconds: 60 }, 0)
            .unwrap_err()
            .to_string();
        assert!(error.contains("no snapshots yet"), "{error}");
    }

    // ---- rendering ---------------------------------------------------------

    /// The transcript this feature was designed against, rendered by the
    /// code that prints it.
    #[test]
    fn the_timeline_prints_the_shape_the_product_promised() {
        // 1970-01-01 in UTC, so the offset is zero and the clock is the
        // arithmetic rather than the machine's timezone.
        let now = 51_600; // 14:20
        let line = timeline(vec![
            entry("auto-1420", 51_600),
            entry("auto-1410", 51_000),
            entry("before-refactor", 50_400),
            entry("auto-1350", 49_800),
        ]);
        assert_eq!(
            render(&line, now, 0, false),
            " 14:20  auto    (now)\n \
             14:10  auto\n \
             14:00  named   before-refactor\n \
             13:50  auto\n"
        );
    }

    #[test]
    fn usage_is_a_footer_rather_than_a_column() {
        let now = 51_600;
        let mut only = entry("auto-1420", 51_600);
        only.bytes = 3 * 1024 * 1024;
        let line = timeline(vec![only]);
        assert!(!render(&line, now, 0, false).contains("3.00 MiB"));
        let with_usage = render(&line, now, 0, true);
        assert!(with_usage.contains("1 snapshot, 3.00 MiB"), "{with_usage}");
        assert!(
            with_usage.contains("auto every 10m, kept 1d"),
            "{with_usage}"
        );
    }

    #[test]
    fn a_snapshot_from_another_day_carries_its_date() {
        let now = 2 * 86_400 + 51_600;
        let line = timeline(vec![
            entry("auto-today", now),
            entry("auto-yesterday", 86_400 + 51_000),
        ]);
        let printed = render(&line, now, 0, false);
        assert!(printed.contains("01-02 14:10"), "{printed}");
        // The columns still line up once one of them is wider.
        assert!(printed.contains("      14:20  auto    (now)"), "{printed}");
    }

    #[test]
    fn a_volume_that_could_not_be_snapshotted_says_so_under_its_row() {
        let now = 51_600;
        let mut only = entry("auto-1420", 51_600);
        only.volumes = vec![VolumeShot {
            source: "work".into(),
            mount_point: None,
            clone_dir: None,
            not_snapshotted: Some("volume not snapshotted (block volume on dev5)".into()),
            print: Fingerprint::default(),
        }];
        let printed = render(&timeline(vec![only]), now, 0, false);
        assert!(printed.contains("volume not snapshotted"), "{printed}");
    }

    #[test]
    fn an_instance_with_no_snapshots_is_told_what_would_make_one() {
        let printed = render(&timeline(Vec::new()), 0, 0, false);
        assert!(printed.contains("ast snapshot bot"), "{printed}");
    }

    // ---- settings ----------------------------------------------------------

    #[test]
    fn settings_that_would_delete_every_snapshot_before_the_next_are_refused() {
        assert!(Settings::default().check().is_ok());
        let too_often = Settings {
            every_secs: 5,
            keep_secs: 3_600,
        };
        assert!(too_often.check().is_err());
        let too_short = Settings {
            every_secs: 600,
            keep_secs: 60,
        };
        let error = too_short.check().unwrap_err().to_string();
        assert!(error.contains("--keep"), "{error}");
    }

    #[test]
    fn an_instances_own_settings_win_over_the_devices() {
        let mine = Settings {
            every_secs: 60,
            keep_secs: 3_600,
        };
        assert_eq!(Settings::resolve(Some(mine)), mine);
        assert_eq!(
            Settings::resolve(None).every_secs,
            Settings::device_default().every_secs
        );
    }

    // ---- change detection --------------------------------------------------

    #[test]
    fn a_file_that_has_been_written_to_does_not_look_the_same() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("disk.raw");
        std::fs::write(&path, b"a").unwrap();
        let before = fingerprint(&path).unwrap();
        assert_eq!(fingerprint(&path).unwrap(), before, "nothing wrote to it");
        std::fs::write(&path, b"ab").unwrap();
        assert_ne!(fingerprint(&path).unwrap(), before);
    }

    #[test]
    fn a_directory_that_gained_a_file_does_not_look_the_same() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("one"), b"1").unwrap();
        let before = tree_fingerprint(dir.path()).unwrap();
        assert_eq!(tree_fingerprint(dir.path()).unwrap(), before);
        std::fs::write(dir.path().join("two"), b"2").unwrap();
        assert_ne!(tree_fingerprint(dir.path()).unwrap(), before);
    }

    #[test]
    fn a_missing_directory_fingerprints_as_empty_rather_than_failing() {
        let dir = tempfile::tempdir().unwrap();
        let absent = dir.path().join("never-created");
        assert_eq!(tree_fingerprint(&absent).unwrap(), Fingerprint::default());
    }

    // ---- cloning and restoring a directory volume --------------------------

    #[test]
    fn a_directory_volume_clones_and_comes_back() {
        let root = tempfile::tempdir().unwrap();
        let work = root.path().join("work");
        std::fs::create_dir_all(work.join("src")).unwrap();
        std::fs::write(work.join("src/main.rs"), b"fn main() {}").unwrap();
        std::fs::write(work.join("notes.md"), b"t0").unwrap();

        let shot = root.path().join("shot");
        clone_tree(&work, &shot).unwrap();

        // The agent then does something regrettable.
        std::fs::remove_file(work.join("src/main.rs")).unwrap();
        std::fs::write(work.join("notes.md"), b"t2").unwrap();

        restore_tree(&shot, &work).unwrap();
        assert_eq!(
            std::fs::read_to_string(work.join("src/main.rs")).unwrap(),
            "fn main() {}"
        );
        assert_eq!(
            std::fs::read_to_string(work.join("notes.md")).unwrap(),
            "t0"
        );
        // The snapshot survives its own restore, like a disk snapshot does.
        assert!(shot.join("notes.md").is_file());
    }

    #[test]
    fn a_missing_volume_snapshot_is_refused_rather_than_emptying_the_volume() {
        let root = tempfile::tempdir().unwrap();
        let work = root.path().join("work");
        std::fs::create_dir_all(&work).unwrap();
        std::fs::write(work.join("keep"), b"1").unwrap();
        assert!(restore_tree(&root.path().join("absent"), &work).is_err());
        assert!(work.join("keep").is_file(), "the volume was left alone");
    }

    #[test]
    fn a_symlink_in_a_volume_is_copied_as_a_link_and_never_followed() {
        let root = tempfile::tempdir().unwrap();
        let work = root.path().join("work");
        std::fs::create_dir_all(&work).unwrap();
        std::fs::write(work.join("real"), b"1").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink("/", work.join("escape")).unwrap();
        let shot = root.path().join("shot");
        clone_tree(&work, &shot).unwrap();
        assert!(shot.join("real").is_file());
        #[cfg(unix)]
        assert!(std::fs::symlink_metadata(shot.join("escape"))
            .unwrap()
            .is_symlink());
    }

    // ---- the snapshots directory -------------------------------------------

    #[test]
    fn the_root_disk_is_found_whatever_format_the_backend_chose() {
        let dir = tempfile::tempdir().unwrap();
        assert!(root_disk(dir.path()).is_err());
        std::fs::write(dir.path().join("disk.qcow2"), b"").unwrap();
        assert_eq!(
            root_disk(dir.path()).unwrap(),
            dir.path().join("disk.qcow2")
        );
    }

    #[test]
    fn a_sidecar_is_not_a_snapshot_and_is_read_back_whole() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(snapshot::dir(dir.path())).unwrap();
        let meta = Meta {
            tag: "auto-x".into(),
            kind: Kind::Auto,
            taken_at: 42,
            disk: Fingerprint {
                len: 10,
                mtime_secs: 9,
                mtime_nanos: 8,
            },
            volumes: Vec::new(),
            elapsed_ms: 7,
        };
        write_meta(dir.path(), &meta).unwrap();
        assert_eq!(read_meta(dir.path(), "auto-x").unwrap(), meta);
        // The listing is a listing of disks, and a sidecar is not one.
        assert!(snapshot::list(dir.path()).unwrap().is_empty());
    }

    #[test]
    fn deleting_a_snapshot_takes_its_sidecar_and_its_volume_clone_with_it() {
        let dir = tempfile::tempdir().unwrap();
        let snaps = snapshot::dir(dir.path());
        std::fs::create_dir_all(&snaps).unwrap();
        std::fs::write(snaps.join("auto-x.raw"), b"").unwrap();
        let clone = snaps.join(volume_clone_name("auto-x", 0));
        std::fs::create_dir_all(&clone).unwrap();
        std::fs::write(clone.join("file"), b"").unwrap();
        write_meta(
            dir.path(),
            &Meta {
                tag: "auto-x".into(),
                kind: Kind::Auto,
                taken_at: 1,
                disk: Fingerprint::default(),
                volumes: Vec::new(),
                elapsed_ms: 0,
            },
        )
        .unwrap();

        snapshot::remove(dir.path(), "auto-x").unwrap();
        assert!(!snaps.join("auto-x.raw").exists());
        assert!(!meta_path(dir.path(), "auto-x").exists());
        assert!(!clone.exists(), "the cloned volume outlived its snapshot");
    }

    #[test]
    fn the_timeline_is_read_newest_first_with_its_sidecar_times() {
        let dir = tempfile::tempdir().unwrap();
        let snaps = snapshot::dir(dir.path());
        std::fs::create_dir_all(&snaps).unwrap();
        for (tag, taken_at) in [("auto-a", 100u64), ("auto-b", 300), ("keeper", 200)] {
            std::fs::write(snaps.join(format!("{tag}.raw")), b"x").unwrap();
            write_meta(
                dir.path(),
                &Meta {
                    tag: tag.into(),
                    kind: kind_of(tag),
                    taken_at,
                    disk: Fingerprint::default(),
                    volumes: Vec::new(),
                    elapsed_ms: 0,
                },
            )
            .unwrap();
        }
        let entries = read_entries(dir.path()).unwrap();
        let tags: Vec<&str> = entries.iter().map(|e| e.tag.as_str()).collect();
        assert_eq!(tags, ["auto-b", "keeper", "auto-a"]);
        assert_eq!(entries[1].kind, Kind::Named);
    }

    #[test]
    fn a_finished_rewind_prints_the_line_the_product_promised() {
        let report = Report {
            instance: "bot".into(),
            tag: "auto-1400".into(),
            taken_at: 50_400,
            elapsed_ms: 3_100,
            kept_as: Some(BEFORE_REWIND.into()),
            restarted: true,
            republished: 1,
            volumes: Vec::new(),
            warnings: Vec::new(),
        };
        assert_eq!(
            report.render(0, 51_600),
            "bot rewound to 14:00 (3.1 s) — current state kept as \"before-rewind\""
        );
    }

    #[test]
    fn a_volume_the_rewind_could_not_touch_is_said_out_loud() {
        let report = Report {
            instance: "bot".into(),
            tag: "auto-1400".into(),
            taken_at: 50_400,
            elapsed_ms: 900,
            kept_as: Some(BEFORE_REWIND.into()),
            restarted: false,
            republished: 0,
            volumes: vec![VolumeShot {
                source: "scratch".into(),
                mount_point: None,
                clone_dir: None,
                not_snapshotted: Some("volume not snapshotted (block volume on dev5)".into()),
                print: Fingerprint::default(),
            }],
            warnings: vec!["port 8080 could not be reclaimed".into()],
        };
        let printed = report.render(0, 51_600);
        assert!(printed.contains("volume not snapshotted"), "{printed}");
        assert!(printed.contains("port 8080"), "{printed}");
    }

    #[test]
    fn renaming_a_snapshot_carries_its_sidecar_and_its_volume_clone() {
        let dir = tempfile::tempdir().unwrap();
        let snaps = snapshot::dir(dir.path());
        std::fs::create_dir_all(&snaps).unwrap();
        std::fs::write(snaps.join("staged.raw"), b"disk").unwrap();
        let clone = snaps.join(volume_clone_name("staged", 0));
        std::fs::create_dir_all(&clone).unwrap();
        std::fs::write(clone.join("notes.md"), b"t0").unwrap();
        write_meta(
            dir.path(),
            &Meta {
                tag: "staged".into(),
                kind: Kind::Rewind,
                taken_at: 5,
                disk: Fingerprint::default(),
                volumes: vec![VolumeShot {
                    source: "/work".into(),
                    mount_point: Some("/work".into()),
                    clone_dir: Some(volume_clone_name("staged", 0)),
                    not_snapshotted: None,
                    print: Fingerprint::default(),
                }],
                elapsed_ms: 0,
            },
        )
        .unwrap();

        rename(dir.path(), "staged", BEFORE_REWIND).unwrap();

        assert!(snaps.join(format!("{BEFORE_REWIND}.raw")).is_file());
        assert!(!snaps.join("staged.raw").exists());
        let meta = read_meta(dir.path(), BEFORE_REWIND).unwrap();
        assert_eq!(meta.tag, BEFORE_REWIND);
        assert_eq!(
            meta.volumes[0].clone_dir.as_deref(),
            Some(volume_clone_name(BEFORE_REWIND, 0).as_str())
        );
        assert!(snaps.join(volume_clone_name(BEFORE_REWIND, 0)).is_dir());
        assert!(read_meta(dir.path(), "staged").is_none());
    }

    /// The staging tag is machinery, not a snapshot. A crash that leaves one
    /// behind must not put a row on somebody's timeline.
    #[test]
    fn a_staged_rewind_left_by_a_crash_is_not_on_the_timeline() {
        let dir = tempfile::tempdir().unwrap();
        let snaps = snapshot::dir(dir.path());
        std::fs::create_dir_all(&snaps).unwrap();
        std::fs::write(snaps.join(format!("{STAGING}.raw")), b"x").unwrap();
        std::fs::write(snaps.join("auto-a.raw"), b"x").unwrap();
        let tags: Vec<String> = read_entries(dir.path())
            .unwrap()
            .into_iter()
            .map(|e| e.tag)
            .collect();
        assert_eq!(tags, ["auto-a"]);
    }

    /// A snapshot taken by `ast snapshot` before this module existed has no
    /// sidecar. It is still a snapshot, and the timeline shows it — dated by
    /// its file, which is the only date there is.
    #[test]
    fn a_snapshot_without_a_sidecar_is_still_on_the_timeline() {
        let dir = tempfile::tempdir().unwrap();
        let snaps = snapshot::dir(dir.path());
        std::fs::create_dir_all(&snaps).unwrap();
        std::fs::write(snaps.join("nightly.raw"), b"x").unwrap();
        let entries = read_entries(dir.path()).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].kind, Kind::Named);
        assert!(entries[0].taken_at > 0, "dated by the file it is");
    }
}
