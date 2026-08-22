//! What one build of Asterism will speak to, and what it refuses.
//!
//! Two binaries and any number of devices are upgraded one at a time, never
//! atomically. `brew upgrade` replaces `ast` and `astd` while a daemon from
//! the old pair is still running and still supervising guests; a laptop
//! updates a week before the desktop it shares an orbit with. So there is
//! always a moment where two vintages have to talk, and the only question is
//! whether that moment is *negotiated* or *discovered*.
//!
//! ### Why the crate version is not the answer
//!
//! It was, and it was wrong. `ast` used to compare its own `CARGO_PKG_VERSION`
//! against the daemon's and, on any difference at all, SIGTERM the running
//! daemon and spawn its own sibling. Two things fell out of that:
//!
//! * A patch release with an identical wire forced a daemon replacement, for
//!   nothing. Upgrades were never negotiated, only imposed.
//! * It was symmetric, and it should not have been. An *older* `ast` would
//!   happily kill a *newer* `astd` — and the older daemon that replaced it
//!   would then meet state written at a schema version it does not speak and
//!   refuse to load it. A downgrade, performed silently, discovered only
//!   after the daemon was already gone.
//!
//! So compatibility is its own number here. [`PROTOCOL_VERSION`] moves when
//! the wire changes and at no other time, which is what lets a patch release
//! leave a running daemon alone.
//!
//! ### The window
//!
//! A build speaks its own protocol and the [`SUPPORTED_BACK`] versions before
//! it — N-2, N-1, N. That is a promise about *frames*, not about features: an
//! N-1 daemon in the window is talked to directly, and if it turns out not to
//! know a command it is asked for, `ast` upgrades it then. The window is what
//! makes a rolling upgrade of an orbit possible, because it means a device
//! that has not been touched for two releases is still a peer and not an
//! outage.
//!
//! Outside the window in the *old* direction, the answer is to replace the
//! daemon: this build is newer, and replacing an older process it can restart
//! is an upgrade. Outside it in the *new* direction, the answer is to stop.
//! This build cannot know what a later one recorded, and killing it to take
//! its place is the downgrade described above. See [`Verdict`].
//!
//! ### The home stamp
//!
//! The wire is only half of a skew. The other half is on disk: every store in
//! `$ASTERISM_HOME` carries its own format version, and [`durable`] refuses a
//! single document written by a newer build. But it refuses it at the moment
//! that document is *read*, which is one store into startup — after the
//! staging sweep, after a restore has been converged, in the middle of a
//! sequence that has already changed things.
//!
//! [`stamp_home`] moves that decision to before any of it. One file records
//! which protocol and which store versions last wrote this home, it is checked
//! as the daemon's first act, and a downgrade is refused there — before
//! mutation, naming what it would have had to drop.
//!
//! [`durable`]: crate::durable

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::durable::{self, Loaded};
use crate::instance::now_unix;
use crate::VERSION;

/// The version of the CLI <-> daemon and daemon <-> daemon wire this build
/// speaks.
///
/// Deliberately not the crate version. It moves when a frame is renamed, when
/// a field stops being optional, or when the meaning of an existing frame
/// changes — and it stays put for every release that does none of those, which
/// is most of them.
///
/// 1: the wire as of the first build that carried a number for it. Everything
/// before this answered `Ping` with a `Pong` that had no `protocol` field, and
/// that absence is how such a daemon is recognised — see [`Verdict::Unversioned`].
pub const PROTOCOL_VERSION: u32 = 1;

/// How many versions back this build still speaks: the N-2 of N-2/N-1/N.
pub const SUPPORTED_BACK: u32 = 2;

/// Format version of the home stamp document itself.
pub const STAMP_VERSION: u32 = 1;

/// The secret catalog's on-disk format version.
///
/// Here rather than beside the catalog because [`stores`] has to name every
/// store's version in one place — a table with a hole in it is a downgrade
/// this build would not refuse.
pub const CATALOG_VERSION: u32 = 1;

/// Overrides the protocol version this process claims and accepts.
///
/// A skew test needs two vintages, and this tree has one. Rather than keep a
/// binary from a previous release around to test against — which would test
/// that release's bugs, not this build's negotiation — the e2e runs the same
/// pair of binaries with different numbers on them and walks the matrix that
/// [`ast compat --json`](crate) prints.
///
/// It is read in the shipping binary, like [`crate::durable::faults`] is
/// compiled into it, and for the same reason: a compatibility rule that is
/// only tested in a unit test is a compatibility rule that has never met a
/// socket. Nothing sets it except a test.
const PROTOCOL_ENV: &str = "ASTERISM_PROTOCOL_VERSION";

/// The protocol version this process speaks.
pub fn protocol_version() -> u32 {
    use std::sync::OnceLock;
    static RESOLVED: OnceLock<u32> = OnceLock::new();
    *RESOLVED.get_or_init(|| {
        // 0 is accepted, and is only ever reachable this way: no build claims
        // it, and a process that does sees every peer as newer than itself.
        // That is exactly the shape the `too_old` row of the matrix needs a
        // real daemon to have, and there is no released binary old enough to
        // borrow one from.
        std::env::var(PROTOCOL_ENV)
            .ok()
            .and_then(|s| s.trim().parse::<u32>().ok())
            .unwrap_or(PROTOCOL_VERSION)
    })
}

/// The oldest protocol this process will talk to.
///
/// Clamped at 1 because 0 is not a version: it is what a build that predates
/// the whole idea would report if it reported anything, and such a build is
/// [`Verdict::Unversioned`] rather than merely old.
pub fn min_supported() -> u32 {
    protocol_version().saturating_sub(SUPPORTED_BACK).max(1)
}

/// What to do about the thing on the other end.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// In the window. Send the frame.
    Speak,
    /// It answered without a protocol at all, so it is older than the first
    /// build that had one. Replaceable, and only distinguished from
    /// [`Verdict::TooOld`] so the sentence a user reads is true.
    Unversioned,
    /// Older than this build's window. A daemon here is replaced; a peer here
    /// is refused, because nothing on this device can upgrade another one.
    TooOld { theirs: u32, min: u32 },
    /// Newer than this build. Never replaced, always refused: it holds state
    /// and speaks frames this build does not have, and taking its place would
    /// be a downgrade nobody asked for.
    TooNew { theirs: u32, ours: u32 },
}

impl Verdict {
    /// Whether a frame may be sent on the strength of this.
    pub fn speakable(self) -> bool {
        matches!(self, Verdict::Speak)
    }

    /// The one word the JSON matrix uses, and the e2e asserts on.
    pub fn word(self) -> &'static str {
        match self {
            Verdict::Speak => "speak",
            Verdict::Unversioned => "unversioned",
            Verdict::TooOld { .. } => "too_old",
            Verdict::TooNew { .. } => "too_new",
        }
    }
}

/// Decide what to do about a peer claiming `theirs`, where `None` is a peer
/// that claimed nothing.
pub fn negotiate(theirs: Option<u32>) -> Verdict {
    let ours = protocol_version();
    match theirs {
        None => Verdict::Unversioned,
        Some(t) if t > ours => Verdict::TooNew { theirs: t, ours },
        Some(t) if t < min_supported() => Verdict::TooOld { theirs: t, min: min_supported() },
        Some(_) => Verdict::Speak,
    }
}

/// How a peer too new to talk to is described, wherever that has to be said.
///
/// One sentence, one instruction, and never a suggestion to stop the other
/// side — the whole point of the refusal is that the newer half is the half
/// worth keeping.
pub fn too_new(what: &str, theirs: u32, ours: u32) -> anyhow::Error {
    anyhow::anyhow!(
        "{what} speaks Asterism protocol {theirs}, and this build speaks {ours}. \
         It is newer than this one, so it is left alone rather than replaced — \
         taking its place would downgrade this device and it may hold state this \
         build would drop.\n\
         To repair: upgrade this Asterism (`brew upgrade asterism`) so both halves \
         are the same vintage."
    )
}

// ---- the store table -------------------------------------------------------

/// Every versioned document in `$ASTERISM_HOME`, and the version this build
/// writes.
///
/// One table, because a downgrade is refused by comparing what is recorded
/// against what this build speaks and a store missing from here is a store
/// whose downgrade goes unnoticed. Adding a versioned store means adding a row.
///
/// The two unversioned files in the home are deliberately absent: the shard
/// cache and a move's `moved.json` are caches of something another device is
/// authoritative for, and a build that cannot read one rebuilds it.
pub fn stores() -> BTreeMap<String, u32> {
    [
        ("registry", crate::registry::SHARD_VERSION),
        ("orbit", crate::orbit::ORBIT_VERSION),
        ("volumes", crate::volume::VOLUME_VERSION),
        ("secrets", CATALOG_VERSION),
        ("seed", crate::seed::SEED_TEMPLATE_VERSION),
    ]
    .into_iter()
    .map(|(name, version)| (name.to_owned(), version))
    .collect()
}

// ---- the home stamp --------------------------------------------------------

/// Who last wrote this `$ASTERISM_HOME`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HomeStamp {
    /// This document's own format version, so a later shape is refused by
    /// [`durable::load_json_versioned`] rather than misread.
    pub version: u32,
    /// The wire version that build spoke.
    pub protocol: u32,
    /// Its crate version — not compared against anything, and recorded
    /// because it is the string a user recognises when they are told a
    /// downgrade was refused.
    pub asterism: String,
    /// Each store's format version at that point. Unknown names are carried
    /// through untouched: a store this build has never heard of belongs to a
    /// newer one, and dropping the row would erase the evidence of it.
    pub stores: BTreeMap<String, u32>,
    /// When, so the sentence can say "yesterday" rather than nothing.
    pub written_at: u64,
}

impl HomeStamp {
    /// What this build would write.
    pub fn current() -> Self {
        Self {
            version: STAMP_VERSION,
            protocol: protocol_version(),
            asterism: VERSION.to_owned(),
            stores: stores(),
            written_at: now_unix(),
        }
    }

    /// Every way `self` is ahead of what this build speaks.
    ///
    /// A list rather than a bool: "the registry is at 2 and the volume book is
    /// at 3" is the difference between a user knowing which upgrade they are
    /// missing and a user knowing only that they are missing one.
    fn ahead_of_this_build(&self) -> Vec<String> {
        let mut ahead = Vec::new();
        let ours = protocol_version();
        if self.protocol > ours {
            ahead.push(format!("protocol {} (this build speaks {ours})", self.protocol));
        }
        let mine = stores();
        for (name, found) in &self.stores {
            match mine.get(name) {
                Some(current) if found > current => {
                    ahead.push(format!("{name} format {found} (this build writes {current})"));
                }
                // A store this build does not have. It is not something this
                // build can corrupt — it will never open it — so it is not a
                // refusal on its own, and it stays in the file.
                _ => {}
            }
        }
        ahead
    }
}

/// Where the stamp lives.
pub fn stamp_path(home: &Path) -> PathBuf {
    home.join("home.json")
}

/// Check this home against this build, and record that this build has it.
///
/// The daemon's first act, before the staging sweep, before a restore is
/// converged, before a single store is opened. Everything after this point
/// mutates something; this is the last moment a refusal costs nothing.
///
/// `Ok(Some(note))` is a line worth logging — a home this build had not
/// stamped before. `Ok(None)` is the ordinary case of a home this build
/// already owns.
pub fn stamp_home(home: &Path) -> Result<Option<String>> {
    let path = stamp_path(home);
    let what = "this device's Asterism home stamp";
    let found: Option<HomeStamp> = durable::load_json_versioned(&path, what, STAMP_VERSION)?
        .map(|Loaded { value, repaired }| {
            if let Some(why) = repaired {
                eprintln!("astd: {why}");
            }
            value
        });

    let note = match &found {
        Some(stamp) => {
            let ahead = stamp.ahead_of_this_build();
            if !ahead.is_empty() {
                return Err(downgrade_refused(&path, stamp, &ahead));
            }
            if stamp.protocol == protocol_version() && stamp.stores == stores() {
                // The common case: the same build, again. Nothing to write,
                // so a home that is only ever read stays untouched.
                return Ok(None);
            }
            Some(format!(
                "this home was last written by Asterism {} (protocol {}); \
                 it is now Asterism {} (protocol {})",
                stamp.asterism,
                stamp.protocol,
                VERSION,
                protocol_version(),
            ))
        }
        None => Some(format!(
            "stamped {} as Asterism {VERSION} (protocol {})",
            home.display(),
            protocol_version()
        )),
    };

    // Rows this build has never heard of are a newer build's, and they are
    // kept: dropping them would let the *next* downgrade past, because the
    // evidence of the newer store would have been erased by this one.
    let mut stamp = HomeStamp::current();
    if let Some(previous) = found {
        for (name, version) in previous.stores {
            stamp.stores.entry(name).or_insert(version);
        }
    }
    durable::commit_json(&path, &stamp)?;
    Ok(note)
}

/// The refusal a home written by a newer Asterism gets, before anything in it
/// has been touched.
fn downgrade_refused(path: &Path, stamp: &HomeStamp, ahead: &[String]) -> anyhow::Error {
    anyhow::anyhow!(
        "{} was last written by Asterism {} and this is Asterism {VERSION}, which is \
         older: {}.\n\
         Nothing in this home has been read or changed. Starting anyway would meet \
         state this build does not understand, one store at a time, after it had \
         already begun.\n\
         To repair: upgrade Asterism (`brew upgrade asterism`) back to {} or newer. \
         If you meant to downgrade and are willing to lose whatever the newer build \
         recorded, move {} aside and start again — the stores themselves will then \
         refuse individually, which is the slower version of this sentence.",
        path.display(),
        stamp.asterism,
        ahead.join(", "),
        stamp.asterism,
        path.display(),
    )
}

// ---- the matrix ------------------------------------------------------------

/// One row of the skew matrix: a protocol a peer might claim, and what this
/// build does about it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatrixRow {
    /// What the peer claims. `None` is a peer that claims nothing.
    pub peer_protocol: Option<u32>,
    /// [`Verdict::word`].
    pub verdict: String,
    /// What `ast` does to a *daemon* that answers this way. The e2e asserts
    /// on it, which is what stops the table and the test from drifting apart.
    pub daemon_action: String,
    /// What a daemon does about a *peer* that opens a mesh stream this way.
    pub peer_action: String,
}

/// Everything this build will say about compatibility, as data.
///
/// `ast compat --json` prints this and `scripts/e2e-skew.sh` walks it, so the
/// matrix the test covers is generated from the rule the code follows rather
/// than transcribed beside it. A case added here is a case the e2e runs on the
/// next commit, and a case removed here stops being asserted — which is the
/// only arrangement in which "the matrix is complete" can stay true.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Compat {
    pub asterism: String,
    pub protocol: u32,
    pub min_supported: u32,
    pub supported_back: u32,
    pub stores: BTreeMap<String, u32>,
    pub matrix: Vec<MatrixRow>,
}

impl Compat {
    pub fn current() -> Self {
        let protocol = protocol_version();
        let min = min_supported();
        // Two either side of the window, plus the unversioned case: every
        // class of answer, and one example of each that is not on a boundary.
        //
        // It starts at 0 even though nothing this tree builds claims 0,
        // because something on a socket can, and because it keeps a `too_old`
        // row in the matrix at protocol 1 — where the window has nowhere else
        // to be below, and the e2e would otherwise have no old case to walk.
        let mut claims: Vec<Option<u32>> = vec![None];
        for v in min.saturating_sub(2)..=protocol + 2 {
            claims.push(Some(v));
        }
        let matrix = claims
            .into_iter()
            .map(|peer_protocol| {
                let verdict = negotiate(peer_protocol);
                MatrixRow {
                    peer_protocol,
                    verdict: verdict.word().to_owned(),
                    daemon_action: match verdict {
                        Verdict::Speak => "speak",
                        // Older than us, or from before the number existed:
                        // this build can restart it, and doing so is the
                        // upgrade.
                        Verdict::Unversioned | Verdict::TooOld { .. } => "replace",
                        Verdict::TooNew { .. } => "refuse",
                    }
                    .to_owned(),
                    peer_action: match verdict {
                        Verdict::Speak => "speak",
                        // Nothing on this device can upgrade another one, so
                        // every unspeakable peer is the same answer: say so
                        // in a frame the peer can print.
                        _ => "refuse",
                    }
                    .to_owned(),
                }
            })
            .collect();
        Self {
            asterism: VERSION.to_owned(),
            protocol,
            min_supported: min,
            supported_back: SUPPORTED_BACK,
            stores: stores(),
            matrix,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The env seam is process-wide and `protocol_version` caches, so these
    // all reason about the built-in constant rather than setting it.

    #[test]
    fn the_window_is_n_minus_two_through_n() {
        assert_eq!(negotiate(Some(PROTOCOL_VERSION)), Verdict::Speak);
        for back in 0..=SUPPORTED_BACK {
            let v = PROTOCOL_VERSION.saturating_sub(back).max(1);
            assert_eq!(negotiate(Some(v)), Verdict::Speak, "protocol {v} should be in the window");
        }
    }

    #[test]
    fn a_newer_peer_is_refused_and_never_replaced() {
        let verdict = negotiate(Some(PROTOCOL_VERSION + 1));
        assert!(matches!(verdict, Verdict::TooNew { .. }));
        // The distinction this whole module exists for: the newer half is
        // never the half that gets restarted.
        let row = Compat::current()
            .matrix
            .into_iter()
            .find(|r| r.peer_protocol == Some(PROTOCOL_VERSION + 1))
            .expect("the matrix covers one version past this build");
        assert_eq!(row.daemon_action, "refuse");
        assert_eq!(row.peer_action, "refuse");
    }

    #[test]
    fn a_peer_that_claims_nothing_is_older_than_the_number_itself() {
        assert_eq!(negotiate(None), Verdict::Unversioned);
    }

    #[test]
    fn a_peer_below_the_window_is_replaced_rather_than_spoken_to() {
        let below = min_supported() - 1;
        assert!(matches!(negotiate(Some(below)), Verdict::TooOld { .. }));
        let row = Compat::current()
            .matrix
            .into_iter()
            .find(|r| r.peer_protocol == Some(below))
            .expect("the matrix covers one version below the window");
        assert_eq!(row.daemon_action, "replace");
    }

    #[test]
    fn the_matrix_covers_every_class_of_answer() {
        let matrix = Compat::current().matrix;
        for want in ["speak", "unversioned", "too_old", "too_new"] {
            assert!(
                matrix.iter().any(|r| r.verdict == want),
                "the generated matrix has no {want} case, so the e2e cannot cover one"
            );
        }
    }

    #[test]
    fn every_versioned_store_is_in_the_table() {
        let table = stores();
        for name in ["registry", "orbit", "volumes", "secrets", "seed"] {
            assert!(table.contains_key(name), "{name} is missing from the store table");
        }
        assert_eq!(table.get("registry"), Some(&crate::registry::SHARD_VERSION));
        assert_eq!(table.get("orbit"), Some(&crate::orbit::ORBIT_VERSION));
        assert_eq!(table.get("volumes"), Some(&crate::volume::VOLUME_VERSION));
    }

    #[test]
    fn a_fresh_home_is_stamped_and_then_left_alone() {
        let dir = tempdir();
        let note = stamp_home(&dir).unwrap();
        assert!(note.is_some(), "the first stamp of a home is worth saying");
        assert!(stamp_path(&dir).exists());
        // The same build again writes nothing, so a home that is only read
        // does not acquire a new mtime on every `astd` start.
        assert!(stamp_home(&dir).unwrap().is_none());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_home_written_by_a_newer_build_is_refused_before_anything_is_touched() {
        let dir = tempdir();
        let mut stamp = HomeStamp::current();
        stamp.protocol = PROTOCOL_VERSION + 1;
        stamp.asterism = "9.9.9".into();
        durable::commit_json(&stamp_path(&dir), &stamp).unwrap();

        let err = stamp_home(&dir).unwrap_err().to_string();
        assert!(err.contains("9.9.9"), "the refusal names the build that wrote it: {err}");
        assert!(err.contains("protocol"), "the refusal names what is ahead: {err}");
        assert!(
            err.contains("has been read or changed"),
            "the refusal says nothing was touched: {err}"
        );
        // And it did not stamp over the evidence on its way out.
        let after: HomeStamp =
            serde_json::from_slice(&std::fs::read(stamp_path(&dir)).unwrap()).unwrap();
        assert_eq!(after.asterism, "9.9.9");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_store_ahead_of_this_build_is_refused_by_name() {
        let dir = tempdir();
        let mut stamp = HomeStamp::current();
        stamp.stores.insert("volumes".into(), crate::volume::VOLUME_VERSION + 5);
        durable::commit_json(&stamp_path(&dir), &stamp).unwrap();

        let err = stamp_home(&dir).unwrap_err().to_string();
        assert!(err.contains("volumes format"), "the refusal names the store: {err}");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_store_this_build_has_never_heard_of_is_kept_rather_than_dropped() {
        let dir = tempdir();
        let mut stamp = HomeStamp::current();
        stamp.stores.insert("ledgers".into(), 7);
        durable::commit_json(&stamp_path(&dir), &stamp).unwrap();

        // Not a refusal: this build will never open `ledgers`, so it cannot
        // corrupt it.
        stamp_home(&dir).unwrap();
        let after: HomeStamp =
            serde_json::from_slice(&std::fs::read(stamp_path(&dir)).unwrap()).unwrap();
        assert_eq!(
            after.stores.get("ledgers"),
            Some(&7),
            "the row was dropped, so the next downgrade would not be refused"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    fn tempdir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "ast-compat-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        // Each test gets a clean one even when a previous run left something.
        for entry in std::fs::read_dir(&dir).unwrap().flatten() {
            std::fs::remove_file(entry.path()).ok();
        }
        dir
    }
}
