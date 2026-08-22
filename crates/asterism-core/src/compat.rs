//! What one build of Asterism will speak to, and at which version it speaks.
//!
//! Two binaries and any number of devices are upgraded one at a time, never
//! atomically. A package manager replaces `ast` and `astd` while a daemon
//! from the old pair is still running and still supervising guests; a laptop
//! updates a week before the desktop it shares an orbit with. So there is
//! always a moment where two vintages have to talk, and the only question is
//! whether that moment is *negotiated* or *discovered*.
//!
//! ### Why the crate version is not the answer
//!
//! It was, and it was wrong twice over. `ast` used to compare its own
//! `CARGO_PKG_VERSION` against the daemon's and, on any difference at all,
//! SIGTERM the running daemon and spawn its own sibling:
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
//! ### A range, not a point
//!
//! The number on its own is still not negotiation. A build that only knows
//! *its* version can compare and refuse; it cannot choose. So each side
//! advertises a [`Speaks`] range — the newest wire it knows and the oldest it
//! still serves — and [`select`] picks the newest version inside both. That
//! version is what both ends then speak, and it is the whole mechanism:
//!
//! * A daemon one release behind is *not* replaced. Its range and ours
//!   overlap at its version, so `ast` drops to that version and the command
//!   runs. The upgrade can happen when the user is ready for it.
//! * A daemon one release *ahead* is not refused either, as long as it still
//!   serves the version this build knows. The older half speaks; the newer
//!   half serves down. That is what makes a rolling upgrade of a pair — or of
//!   an orbit — an ordinary morning rather than an outage.
//! * Only a range with no overlap at all is a refusal, and even then the
//!   direction decides what happens: an older *daemon* is replaced, because
//!   restarting a process this build can restart is the upgrade. A newer one
//!   is never signalled, because taking its place is a downgrade and it may
//!   hold state this build would drop.
//!
//! ### What a version buys
//!
//! A selected version is a promise about *frames*: every frame at or below it
//! may be sent, and no frame above it may be. [`crate::protocol::Request`]
//! and [`crate::protocol::Response`] each say which version introduced them
//! (`since`), and both ends check it — so a command a daemon cannot serve is
//! refused by name, in a sentence naming the version it needs, instead of
//! arriving as serde's `unknown variant` and being reported as a bad request
//! the user did not make.
//!
//! ### The window
//!
//! A build serves its own version and the [`SUPPORTED_BACK`] before it:
//! N-2, N-1, N. That is a floor on how far back it will *serve*, not a
//! ceiling on how far forward it will speak — the ceiling is the other side's
//! range, which is why a newer peer is usable.
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
//! which protocol and which store versions last wrote this home, it is
//! checked as the daemon's first act, and a downgrade is refused there —
//! before mutation, naming what it would have had to drop.
//!
//! [`durable`]: crate::durable

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::durable::{self, Loaded};
use crate::instance::now_unix;
use crate::VERSION;

/// The newest version of the CLI <-> daemon and daemon <-> daemon wire this
/// build speaks.
///
/// Deliberately not the crate version. It moves when a frame is renamed, when
/// a field stops being optional, or when the meaning of an existing frame
/// changes — and it stays put for every release that does none of those,
/// which is most of them.
///
/// * **1** — the wire before it had a number: every frame in
///   [`crate::protocol`] as it stood when this module was written. A daemon
///   that answers `Ping` without a `protocol` field is not an unknown
///   quantity, it is exactly this, which is why such a daemon is spoken to
///   rather than replaced.
/// * **2** — this build. `Ping` carries the caller's range, `Pong` carries
///   the daemon's, mesh frames carry both, and [`crate::protocol::Request::Compat`]
///   exists.
pub const PROTOCOL_VERSION: u32 = 2;

/// The wire as it was before it carried a version.
///
/// Not zero: zero is what a peer that has no opinion sends, and the whole
/// point of this constant is that a peer with no opinion *does* have a
/// knowable wire — the one that shipped before negotiation existed. Treating
/// it as a version is what turns "an old daemon" from a thing to be killed
/// into a thing to be spoken to.
pub const FIRST_PROTOCOL: u32 = 1;

/// How many versions back this build still serves: the N-2 of N-2/N-1/N.
pub const SUPPORTED_BACK: u32 = 2;

/// Format version of the home stamp document itself.
pub const STAMP_VERSION: u32 = 1;

/// The secret catalog's on-disk format version.
///
/// Here rather than beside the catalog because [`stores`] has to name every
/// store's version in one place — a table with a hole in it is a downgrade
/// this build would not refuse.
pub const CATALOG_VERSION: u32 = 1;

/// Overrides the newest protocol version this process claims.
///
/// A skew test needs two vintages, and this tree has one. Rather than keep a
/// binary from a previous release around to test against — which would test
/// that release's bugs rather than this build's negotiation — the e2e runs
/// the same pair of binaries with different ranges on them and walks the
/// matrix that `ast compat --json` prints. (It also builds the *real*
/// previous release, for the legs where the point is that a genuine old
/// binary is spoken to.)
///
/// Read in the shipping binary, like [`crate::durable::faults`] is compiled
/// into it, and for the same reason: a compatibility rule that is only ever
/// exercised in a unit test is a compatibility rule that has never met a
/// socket. Nothing sets it except a test.
const MAX_ENV: &str = "ASTERISM_PROTOCOL_VERSION";

/// Overrides the oldest protocol version this process serves.
///
/// The other half of the seam. Without it a stand-in can only be *older* than
/// this build; with it a stand-in can be a build from the future that has
/// dropped support for today's wire, which is the one case where refusing is
/// the right answer and the one case a single number cannot express.
const MIN_ENV: &str = "ASTERISM_MIN_PROTOCOL_VERSION";

/// The range of wire versions one side of a conversation speaks.
///
/// `max` is what it would prefer; `min` is the oldest it will still serve.
/// Everything between is on the table — the protocol has no holes, because a
/// version that could be skipped would be a version no build could select
/// against a peer that has it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Speaks {
    pub min: u32,
    pub max: u32,
}

impl Speaks {
    pub fn new(min: u32, max: u32) -> Self {
        Speaks { min: min.min(max), max }
    }

    /// What a peer that said nothing about versions speaks.
    ///
    /// Exactly [`FIRST_PROTOCOL`], and it is a fact rather than a guess: the
    /// only builds that say nothing are the ones from before the field
    /// existed, and their wire is the one this constant names.
    pub fn unversioned() -> Self {
        Speaks { min: FIRST_PROTOCOL, max: FIRST_PROTOCOL }
    }

    /// The range a peer claimed, given the two numbers off the wire.
    ///
    /// `0` in either position is the absence of the field rather than a
    /// version, so a frame carrying neither is [`Speaks::unversioned`]. A
    /// frame carrying only `max` — which nothing this tree writes, but a
    /// future one might — is read as a build that serves nothing older than
    /// what it prefers.
    pub fn claimed(max: u32, min: u32) -> Self {
        if max == 0 {
            return Speaks::unversioned();
        }
        Speaks::new(if min == 0 { max } else { min }, max)
    }

    pub fn describe(&self) -> String {
        if self.min == self.max {
            format!("protocol {}", self.max)
        } else {
            format!("protocols {} to {}", self.min, self.max)
        }
    }
}

/// The range this process speaks.
pub fn ours() -> Speaks {
    Speaks::new(min_supported(), protocol_version())
}

/// The newest protocol version this process claims.
pub fn protocol_version() -> u32 {
    use std::sync::OnceLock;
    static RESOLVED: OnceLock<u32> = OnceLock::new();
    *RESOLVED.get_or_init(|| env_version(MAX_ENV).unwrap_or(PROTOCOL_VERSION))
}

/// The oldest protocol version this process serves.
///
/// Clamped so it never exceeds what this process prefers: a range with `min`
/// above `max` is not a narrower promise, it is an empty one, and a process
/// that made it could not talk to itself.
pub fn min_supported() -> u32 {
    use std::sync::OnceLock;
    static RESOLVED: OnceLock<u32> = OnceLock::new();
    *RESOLVED.get_or_init(|| {
        let floor = protocol_version().saturating_sub(SUPPORTED_BACK).max(FIRST_PROTOCOL);
        env_version(MIN_ENV).unwrap_or(floor).min(protocol_version())
    })
}

fn env_version(name: &str) -> Option<u32> {
    std::env::var(name).ok()?.trim().parse::<u32>().ok()
}

/// What came of putting two ranges together.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Selection {
    /// Both ends speak this, and it is the newest version both have. Send
    /// frames at or below it.
    Common(u32),
    /// Every version the peer serves is older than every version this build
    /// serves. A *daemon* here is replaced — restarting a process this build
    /// can restart is the upgrade — and a *peer* is refused, because nothing
    /// on this device can upgrade another one.
    TooOld { theirs: Speaks, ours: Speaks },
    /// Every version the peer serves is newer than every version this build
    /// speaks. Never replaced, always refused: it speaks frames this build
    /// does not have and may hold state this build would drop, so taking its
    /// place would be a downgrade nobody asked for.
    TooNew { theirs: Speaks, ours: Speaks },
}

impl Selection {
    /// The version to speak, if there is one.
    pub fn version(self) -> Option<u32> {
        match self {
            Selection::Common(v) => Some(v),
            _ => None,
        }
    }

    /// The one word the JSON matrix uses, and the e2e asserts on.
    pub fn word(self) -> &'static str {
        match self {
            Selection::Common(_) => "speak",
            Selection::TooOld { .. } => "too_old",
            Selection::TooNew { .. } => "too_new",
        }
    }
}

/// Choose the version to speak to a peer whose range is `theirs`.
///
/// The newest version inside both ranges. That is the whole rule, and the two
/// things it deliberately does *not* say are the reason this is negotiation
/// rather than a comparison:
///
/// * A peer with a higher `max` than ours is not "too new". It is a peer we
///   speak to at *our* max, as long as its `min` reaches that far. The
///   asymmetric alternative — refusing anything newer — makes every upgrade a
///   flag day, because the two halves can never be one release apart.
/// * A peer with a lower `max` than ours is not "too old" either, for the
///   mirrored reason: we drop to its version and speak that.
pub fn select(theirs: Speaks) -> Selection {
    select_between(ours(), theirs)
}

/// [`select`], with both ranges given.
///
/// Separated so the rule can be tested at ranges this process does not have,
/// and so the matrix can be generated for a build other than this one.
pub fn select_between(ours: Speaks, theirs: Speaks) -> Selection {
    let ceiling = ours.max.min(theirs.max);
    let floor = ours.min.max(theirs.min);
    if ceiling >= floor {
        Selection::Common(ceiling)
    } else if theirs.max < ours.min {
        Selection::TooOld { theirs, ours }
    } else {
        Selection::TooNew { theirs, ours }
    }
}

/// How a peer too new to talk to is described, wherever that has to be said.
///
/// One sentence, one instruction, and never a suggestion to stop the other
/// side — the whole point of the refusal is that the newer half is the half
/// worth keeping.
pub fn too_new(what: &str, theirs: Speaks, ours: Speaks) -> anyhow::Error {
    anyhow::anyhow!(
        "{what} speaks {}, and this build speaks {}. Nothing is common to both, and \
         it is the newer of the two — so it is left alone rather than replaced. \
         Taking its place would downgrade this device, and it may hold state this \
         build would drop.\n\
         To repair: upgrade this Asterism so both halves are the same vintage.",
        theirs.describe(),
        ours.describe(),
    )
}

/// How a peer too old to talk to is described, when it is a peer rather than
/// a daemon this build could restart.
pub fn too_old(what: &str, theirs: Speaks, ours: Speaks) -> anyhow::Error {
    anyhow::anyhow!(
        "{what} speaks {}, and this build serves nothing older than protocol {}. \
         Nothing on this device can upgrade another one, so this is a refusal rather \
         than a repair.\n\
         To repair: upgrade Asterism on that device.",
        theirs.describe(),
        ours.min,
    )
}

/// How a daemon refuses an `ast` whose whole range is below what it serves.
///
/// Separate from [`too_old`] on purpose. That sentence is about another
/// *device* — "nothing on this device can upgrade another one" — and these
/// two halves are on the same one, where the repair is always local. Sending
/// a user to the wrong machine is worse than saying nothing, so the local
/// skew gets its own words.
///
/// It also has to be written from the reader's side rather than the writer's:
/// the daemon composes it, but the person reading it is at the terminal that
/// ran `ast`, and to them the daemon is "the astd on this device".
pub fn client_too_old(theirs: Speaks, ours: Speaks, daemon: &str) -> anyhow::Error {
    anyhow::anyhow!(
        "the `ast` that called speaks {}, and the astd on this device is Asterism          {daemon}, which speaks {} and serves nothing older. Both halves are on this          machine, so this is a half-finished upgrade rather than a skew between          devices.\n\
         To repair: upgrade `ast` to {daemon}. The daemon is the newer of the two          and has been left running.",
        theirs.describe(),
        ours.describe(),
    )
}

/// How a daemon refuses an `ast` whose whole range is above what it speaks.
///
/// The mirror, and the one a user should almost never see: an `ast` that
/// finds a daemon this far behind replaces it rather than asking, because
/// restarting a process it can restart is the upgrade. Reaching this means
/// the restart did not take — a daemon under a service manager that puts the
/// old binary back, most likely — so the repair names that rather than
/// suggesting another try.
pub fn client_too_new(theirs: Speaks, ours: Speaks, daemon: &str) -> anyhow::Error {
    anyhow::anyhow!(
        "the `ast` that called speaks {}, and the astd on this device is Asterism          {daemon}, which speaks {} — too far behind to serve it. `ast` replaces a          daemon this old rather than asking, so seeing this means the replacement          did not take.\n\
         To repair: upgrade astd on this device to match `ast`, and check whether a          service manager is putting the old binary back.",
        theirs.describe(),
        ours.describe(),
    )
}

/// How a frame newer than the version in force is refused.
///
/// The sentence a user reads instead of `bad request: unknown variant`. It
/// names the thing they asked for, the version it needs, and the version that
/// is in force — which between them is the whole diagnosis.
pub fn frame_too_new(what: &str, needs: u32, spoken: u32, who: &str) -> anyhow::Error {
    anyhow::anyhow!(
        "{what} needs Asterism protocol {needs}, and {who} is speaking protocol \
         {spoken}. Every other command works at {spoken}; this one is the one that \
         does not.\n\
         To repair: upgrade Asterism on {who}."
    )
}

// ---- the store table -------------------------------------------------------

/// Every versioned document in `$ASTERISM_HOME`, and the version this build
/// writes.
///
/// One table, because a downgrade is refused by comparing what is recorded
/// against what this build speaks and a store missing from here is a store
/// whose downgrade goes unnoticed. Adding a versioned store means adding a
/// row.
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
    /// The wire version that build preferred.
    pub protocol: u32,
    /// Its crate version — not compared against anything, and recorded
    /// because it is the string a user recognises when they are told a
    /// downgrade was refused.
    pub asterism: String,
    /// Each store's format version at that point. Unknown names are carried
    /// through untouched: a store this build has never heard of belongs to a
    /// newer one, and dropping the row would erase the evidence of it.
    pub stores: BTreeMap<String, u32>,
    /// When, so the sentence can say when rather than nothing.
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
    /// A list rather than a bool: "the registry is at 2 and the volume book
    /// is at 3" is the difference between a user knowing which upgrade they
    /// are missing and a user knowing only that they are missing one.
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
         To repair: upgrade Asterism back to {} or newer. If you meant to downgrade \
         and are willing to lose whatever the newer build recorded, move {} aside and \
         start again — the stores themselves will then refuse individually, which is \
         the slower version of this sentence.",
        path.display(),
        stamp.asterism,
        ahead.join(", "),
        stamp.asterism,
        path.display(),
    )
}

// ---- the matrix ------------------------------------------------------------

/// One row of the skew matrix: a range a peer might advertise, and what this
/// build does about it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatrixRow {
    /// The oldest version that peer serves.
    pub peer_min: u32,
    /// The newest version it speaks.
    pub peer_max: u32,
    /// The version both ends would then speak, when there is one.
    pub speaks: Option<u32>,
    /// [`Selection::word`].
    pub verdict: String,
    /// What `ast` does to a *daemon* that answers this way. The e2e asserts
    /// on it, which is what stops the table and the test from drifting apart.
    pub daemon_action: String,
    /// What a daemon does about a *peer* that opens a mesh stream this way.
    pub peer_action: String,
    /// What this row is here to prove, in the words the e2e prints.
    pub note: String,
}

/// Everything this build will say about compatibility, as data.
///
/// `ast compat --json` prints this and `scripts/e2e-skew.sh` walks it, so the
/// matrix the test covers is generated from the rule the code follows rather
/// than transcribed beside it. A case added here is a case the e2e runs on
/// the next commit, and a case removed here stops being asserted — which is
/// the only arrangement in which "the matrix is complete" can stay true.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Compat {
    /// This build's crate version.
    pub asterism: String,
    /// The newest wire it speaks.
    pub protocol: u32,
    /// The oldest it serves.
    pub min_supported: u32,
    pub supported_back: u32,
    /// The frames that are newer than [`FIRST_PROTOCOL`], and the version
    /// that introduced each. What a peer at a given version may be sent is
    /// this table read against the selected version.
    pub frames: BTreeMap<String, u32>,
    pub stores: BTreeMap<String, u32>,
    pub matrix: Vec<MatrixRow>,
    /// The version in force with the daemon this device is running, when
    /// there is one and `ast` has asked. Absent in `astd`'s own view.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub daemon: Option<DaemonView>,
}

/// What the daemon on this device answered when it was asked.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonView {
    pub asterism: String,
    pub protocol: u32,
    pub min_supported: u32,
    /// The version `ast` and that daemon are speaking.
    pub speaking: u32,
}

impl Compat {
    pub fn current() -> Self {
        let ours = ours();
        Self {
            asterism: VERSION.to_owned(),
            protocol: ours.max,
            min_supported: ours.min,
            supported_back: SUPPORTED_BACK,
            frames: crate::protocol::versioned_frames(),
            stores: stores(),
            matrix: matrix(ours),
            daemon: None,
        }
    }
}

/// Every class of skew a build speaking `ours` can meet, with one example of
/// each.
///
/// Generated from [`select_between`] rather than written down beside it. The
/// ranges are chosen to put a row on each side of both boundaries and one on
/// each boundary itself, and the `note` on each row is what the e2e prints
/// when that row fails — so a red test names the *behaviour* that broke and
/// not just a pair of numbers.
///
/// Two things this deliberately does not do, because a matrix with fiction in
/// it is worse than a short one:
///
/// * It does not invent a peer below [`FIRST_PROTOCOL`]. Version 0 is the
///   absence of a claim, not a version, so a build whose floor is already the
///   oldest wire there is has *no* peer it would replace — and the honest
///   matrix for such a build has no `too_old` row. The rule still has one;
///   `scripts/e2e-skew.sh` reaches it by raising a stand-in's floor, which is
///   what [`MIN_ENV`] is for.
/// * It does not print the same range twice. Two cases can coincide at a
///   given vintage — today "a build from before the number" and "the oldest
///   version still served" are both protocol 1 — and a row that appears twice
///   reads as two pieces of evidence when it is one.
fn matrix(ours: Speaks) -> Vec<MatrixRow> {
    let n = ours.max;
    let mut cases: Vec<(Speaks, &str)> = vec![
        (
            Speaks::unversioned(),
            "a build from before the wire had a number is spoken to at that wire, \
             not replaced for lacking one",
        ),
        (
            Speaks::new(ours.min, ours.min),
            "the oldest version still served is served, and the daemon is left running",
        ),
        (
            Speaks::new(ours.min, n),
            "the same vintage on both ends speaks the newest wire either has",
        ),
        (
            Speaks::new(ours.min, n + 1),
            "a build one release ahead that still serves this wire is spoken to at \
             this wire — a newer peer is not an error",
        ),
        (
            Speaks::new(n, n + 3),
            "a build several releases ahead is still usable while its floor has not \
             passed us",
        ),
        (
            Speaks::new(n + 1, n + 3),
            "a build whose floor has passed this one is refused and never signalled",
        ),
    ];
    // A peer older than everything this build serves — which only exists once
    // this build's floor has left the oldest wire behind.
    if ours.min > FIRST_PROTOCOL {
        cases.push((
            Speaks::new(FIRST_PROTOCOL, ours.min - 1),
            "a build older than anything this one serves is replaced, because \
             restarting it is the upgrade",
        ));
    }

    let mut seen = std::collections::BTreeSet::new();
    cases
        .into_iter()
        .filter(|(theirs, _)| seen.insert((theirs.min, theirs.max)))
        .map(|(theirs, note)| {
            let selection = select_between(ours, theirs);
            MatrixRow {
                peer_min: theirs.min,
                peer_max: theirs.max,
                speaks: selection.version(),
                verdict: selection.word().to_owned(),
                daemon_action: match selection {
                    Selection::Common(_) => "speak",
                    // Older than anything we serve: this build can restart it,
                    // and doing so is the upgrade.
                    Selection::TooOld { .. } => "replace",
                    Selection::TooNew { .. } => "refuse",
                }
                .to_owned(),
                peer_action: match selection {
                    Selection::Common(_) => "speak",
                    // Nothing on this device can upgrade another one, so every
                    // unspeakable peer is the same answer: say so in a frame
                    // the peer can print.
                    _ => "refuse",
                }
                .to_owned(),
                note: note.to_owned(),
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    // The env seams are process-wide and both resolvers cache, so these
    // reason about explicit ranges through `select_between` rather than
    // setting them.

    const OURS: Speaks = Speaks { min: 1, max: 3 };

    #[test]
    fn the_newest_version_both_ends_have_is_the_one_chosen() {
        assert_eq!(select_between(OURS, Speaks::new(1, 3)), Selection::Common(3));
        assert_eq!(select_between(OURS, Speaks::new(1, 2)), Selection::Common(2));
        assert_eq!(select_between(OURS, Speaks::new(2, 2)), Selection::Common(2));
        assert_eq!(select_between(OURS, Speaks::new(1, 1)), Selection::Common(1));
    }

    /// The whole difference between negotiating and comparing. A peer that
    /// prefers a wire this build has never heard of is not an error as long
    /// as it still serves one this build has.
    #[test]
    fn a_newer_peer_that_still_serves_our_wire_is_spoken_to_at_our_wire() {
        assert_eq!(select_between(OURS, Speaks::new(1, 9)), Selection::Common(3));
        assert_eq!(select_between(OURS, Speaks::new(3, 9)), Selection::Common(3));
    }

    #[test]
    fn a_peer_whose_floor_has_passed_us_is_refused_and_never_replaced() {
        let verdict = select_between(OURS, Speaks::new(4, 9));
        assert!(matches!(verdict, Selection::TooNew { .. }));
        assert_eq!(verdict.version(), None);
        let row = matrix(OURS)
            .into_iter()
            .find(|r| r.verdict == "too_new")
            .expect("the matrix covers a build whose floor has passed this one");
        assert_eq!(row.daemon_action, "refuse", "the newer half is never the half restarted");
        assert_eq!(row.peer_action, "refuse");
    }

    #[test]
    fn a_peer_below_everything_we_serve_is_replaced_rather_than_spoken_to() {
        let ours = Speaks::new(4, 6);
        assert!(matches!(select_between(ours, Speaks::new(1, 3)), Selection::TooOld { .. }));
        let row = matrix(ours)
            .into_iter()
            .find(|r| r.verdict == "too_old")
            .expect("the matrix covers a build older than anything this one serves");
        assert_eq!(row.daemon_action, "replace");
        assert_eq!(row.peer_action, "refuse", "nothing here can upgrade another device");
    }

    /// A daemon from before this module answers `Ping` with no `protocol`
    /// field at all. That is not an unknown quantity and it is not a reason to
    /// kill it: it is [`FIRST_PROTOCOL`], and this build serves that.
    #[test]
    fn a_peer_that_claims_nothing_speaks_the_wire_that_predates_the_number() {
        assert_eq!(Speaks::claimed(0, 0), Speaks::unversioned());
        assert_eq!(
            select_between(ours(), Speaks::unversioned()),
            Selection::Common(FIRST_PROTOCOL),
            "this build must still speak the wire it grew out of"
        );
    }

    #[test]
    fn a_claim_of_one_number_is_a_range_of_one() {
        assert_eq!(Speaks::claimed(7, 0), Speaks::new(7, 7));
        assert_eq!(Speaks::claimed(7, 5), Speaks::new(5, 7));
        // A range the wrong way round is not a narrower promise, it is an
        // empty one; `min` is clamped rather than believed.
        assert_eq!(Speaks::claimed(5, 7), Speaks::new(5, 5));
    }

    #[test]
    fn selection_is_symmetric() {
        // Both ends run this rule independently on the same pair of ranges
        // and must reach the same version, or one of them sends a frame the
        // other will not read.
        for ours_max in 1..6u32 {
            for theirs_max in 1..6u32 {
                for back in 0..3u32 {
                    let a = Speaks::new(ours_max.saturating_sub(back).max(1), ours_max);
                    let b = Speaks::new(theirs_max.saturating_sub(back).max(1), theirs_max);
                    assert_eq!(
                        select_between(a, b).version(),
                        select_between(b, a).version(),
                        "{a:?} and {b:?} disagreed on what to speak"
                    );
                }
            }
        }
    }

    #[test]
    fn this_build_speaks_the_wire_that_predates_the_number() {
        assert!(
            min_supported() <= FIRST_PROTOCOL,
            "a build that cannot serve protocol {FIRST_PROTOCOL} cannot talk to the \
             release before it"
        );
    }

    #[test]
    fn the_window_reaches_n_minus_two() {
        let ours = Speaks::new(10u32.saturating_sub(SUPPORTED_BACK), 10);
        for v in ours.min..=ours.max {
            assert_eq!(
                select_between(ours, Speaks::new(v, v)).version(),
                Some(v),
                "protocol {v} is inside N-{SUPPORTED_BACK}/N and must be served"
            );
        }
        assert!(matches!(
            select_between(ours, Speaks::new(ours.min - 1, ours.min - 1)),
            Selection::TooOld { .. }
        ));
    }

    #[test]
    fn the_matrix_covers_every_class_of_answer() {
        let matrix = Compat::current().matrix;
        for want in ["speak", "too_new"] {
            assert!(
                matrix.iter().any(|r| r.verdict == want),
                "the generated matrix has no {want} case, so the e2e cannot cover one"
            );
        }
        for row in &matrix {
            assert!(!row.note.is_empty(), "every row says what it is there to prove");
            assert!(row.peer_max >= FIRST_PROTOCOL, "version 0 is not a version");
            assert!(row.peer_min >= FIRST_PROTOCOL, "version 0 is not a version");
        }
        // `too_old` is the one verdict a build cannot always reach: it needs a
        // peer below this build's floor, and a build whose floor is already
        // the oldest wire there is has none. The row appears exactly when it
        // is true, and never as a fiction to fill the table.
        let too_old = matrix.iter().any(|r| r.verdict == "too_old");
        assert_eq!(
            too_old,
            min_supported() > FIRST_PROTOCOL,
            "the matrix claims a too-old peer this build could not meet"
        );
    }

    /// And the row does appear for a build whose window has moved on — the
    /// rule has a `too_old` case even in the releases where this build's own
    /// matrix cannot show one.
    #[test]
    fn a_build_whose_floor_has_moved_on_does_have_a_peer_it_would_replace() {
        let later = matrix(Speaks::new(4, 6));
        let row = later
            .iter()
            .find(|r| r.verdict == "too_old")
            .expect("a build with a floor above the oldest wire can meet a peer below it");
        assert_eq!(row.daemon_action, "replace");
        assert_eq!(row.peer_action, "refuse");
        assert_eq!(row.speaks, None);
        assert!(row.peer_max < 4, "the example really is below that build's floor");
    }

    /// No row is printed twice. Two cases coincide at some vintages, and one
    /// range appearing twice reads as two pieces of evidence when it is one.
    #[test]
    fn no_two_rows_describe_the_same_peer() {
        let matrix = Compat::current().matrix;
        let mut seen = std::collections::BTreeSet::new();
        for row in &matrix {
            assert!(
                seen.insert((row.peer_min, row.peer_max)),
                "protocols {}-{} appear twice",
                row.peer_min,
                row.peer_max
            );
        }
    }

    #[test]
    fn every_versioned_store_is_in_the_table() {
        let table = stores();
        for name in ["registry", "orbit", "volumes", "secrets", "seed"] {
            assert!(table.contains_key(name), "{name} is versioned on disk and not in the table");
        }
    }

    #[test]
    fn a_home_written_by_a_newer_build_is_refused_before_it_is_touched() {
        let dir = tempfile::tempdir().unwrap();
        let mut stamp = HomeStamp::current();
        stamp.protocol = protocol_version() + 1;
        stamp.asterism = "9.9.9".to_owned();
        durable::commit_json(&stamp_path(dir.path()), &stamp).unwrap();

        let before = std::fs::read(stamp_path(dir.path())).unwrap();
        let err = stamp_home(dir.path()).unwrap_err();
        let text = format!("{err:#}");
        assert!(text.contains("9.9.9"), "{text}");
        assert!(text.contains("has been read or changed"), "{text}");
        assert_eq!(
            std::fs::read(stamp_path(dir.path())).unwrap(),
            before,
            "a refused downgrade writes nothing at all"
        );
    }

    #[test]
    fn a_store_only_a_newer_build_has_is_kept_rather_than_dropped() {
        let dir = tempfile::tempdir().unwrap();
        let mut stamp = HomeStamp::current();
        stamp.stores.insert("something-later".to_owned(), 4);
        durable::commit_json(&stamp_path(dir.path()), &stamp).unwrap();

        stamp_home(dir.path()).unwrap();

        let after: HomeStamp =
            durable::load_json_versioned(&stamp_path(dir.path()), "stamp", STAMP_VERSION)
                .unwrap()
                .unwrap()
                .value;
        assert_eq!(
            after.stores.get("something-later"),
            Some(&4),
            "erasing the row would let the next downgrade past"
        );
    }

    #[test]
    fn stamping_a_home_this_build_already_owns_writes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        assert!(stamp_home(dir.path()).unwrap().is_some(), "the first stamp is worth a line");
        let written = std::fs::metadata(stamp_path(dir.path())).unwrap().modified().unwrap();
        assert!(stamp_home(dir.path()).unwrap().is_none());
        assert_eq!(
            std::fs::metadata(stamp_path(dir.path())).unwrap().modified().unwrap(),
            written,
            "a home that is only ever read stays untouched"
        );
    }
}
