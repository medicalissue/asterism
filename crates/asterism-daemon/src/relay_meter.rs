//! Per-peer byte counters, split into direct and relayed.
//!
//! # Why the daemon counts at all
//!
//! Two reasons, and they are different enough that either alone would be worth
//! the code.
//!
//! **Billing.** A direct path costs the operator nothing: the packets go from
//! one user's network to another's. A relayed path costs bandwidth on a
//! machine someone pays for, per gigabyte. So "how much did this orbit relay"
//! is the one usage question with money attached, and the answer has to be
//! measured rather than modelled.
//!
//! **Attribution.** `STATUS.md` records a path-speed investigation that could
//! not be closed: two devices measured 68–78 ms where about 5 ms was possible,
//! and the cause was unattributable because a round-trip figure cannot say
//! which socket carried it. A byte count split by path — beside the relay URL
//! that carried the relayed half — turns that from a guess into a reading.
//!
//! # What is counted, and what that means
//!
//! iroh keeps UDP byte counters per *path*, and a path is either an IP address
//! or a relay URL, so the split needs no estimation: read the counters, group
//! by the kind of address they belong to. The numbers are UDP payload bytes as
//! the QUIC stack counted them, which includes acknowledgements and
//! retransmissions. That is deliberate and it is the honest basis: those bytes
//! crossed the relay, and the relay's own `bytes_sent`/`bytes_recv` counters
//! count them too. A figure that excluded them would disagree with the invoice
//! the relay operator receives.
//!
//! # Why it accumulates differences
//!
//! A path's counters are cumulative for as long as that path is open and
//! vanish when it closes; a peer, meanwhile, is reconnected to many times over
//! a daemon's life. Summing whatever the current paths report would therefore
//! reset every reconnection and undercount without ever saying so. So each
//! sample is compared against the last one for the same path on the same
//! connection, and only the difference is added to the running total.
//!
//! The cost of that design is honest and worth naming: a path that opens and
//! closes entirely between two samples is not counted. [`SAMPLE_INTERVAL`]
//! bounds how much can be missed, and the connection this daemon keeps warm
//! per peer is sampled for as long as it lives.
//!
//! # Reset policy
//!
//! Never automatically. The totals are cumulative since [`RelayMeter::since`],
//! the moment the meter file was first created, and nothing in this daemon
//! rolls them over, zeroes them at a month boundary, or forgets a peer that
//! went quiet. Deleting `$ASTERISM_HOME/relay-meter.json` starts a new
//! accounting period, and that is the only reset there is. A consumer that
//! wants monthly figures takes differences of snapshots, which is the only
//! form that survives a daemon that was not running at midnight.

use std::collections::{BTreeMap, HashMap};
use std::path::Path;

use anyhow::Result;
use asterism_core::durable;
use asterism_core::instance::now_unix;
use asterism_mesh::{MeshConnection, PathKind};
use serde::{Deserialize, Serialize};

/// How often the sampler reads every warm connection's path counters.
///
/// Short enough that a path which comes and goes inside one interval is a rare
/// loss rather than the common case, long enough that the reading costs
/// nothing on a device with a dozen peers.
pub const SAMPLE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(10);

/// How often the accumulated totals are written to disk.
///
/// A crash loses at most this much accounting. Writing on every sample would
/// mean a file rewrite every [`SAMPLE_INTERVAL`] forever, on a laptop, for
/// numbers nobody reads that often.
pub const FLUSH_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);

/// The on-disk format version.
const METER_VERSION: u32 = 1;

/// Bytes attributed to one peer, split by how they travelled.
///
/// Sent and received are kept apart because a relay operator's cost is not
/// symmetric — egress is usually the billed direction — and because a peer
/// that only receives is a different usage shape from one that only sends.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerBytes {
    /// Bytes this device sent to the peer over a direct path.
    #[serde(default)]
    pub direct_sent: u64,
    /// Bytes this device received from the peer over a direct path.
    #[serde(default)]
    pub direct_recv: u64,
    /// Bytes this device sent to the peer through a relay.
    #[serde(default)]
    pub relayed_sent: u64,
    /// Bytes this device received from the peer through a relay.
    #[serde(default)]
    pub relayed_recv: u64,
    /// Bytes relayed before hole punching moved a connection onto a direct
    /// path, summed over every connection that made the move.
    ///
    /// This is the *unavoidable* part of the relay bill: the rendezvous. A
    /// relay that is doing its job well has `relayed_total` close to this
    /// number, meaning nearly everything relayed was the cost of meeting. A
    /// `relayed_total` far above it is traffic that never got off the relay,
    /// which is the case worth investigating and the case that scales with
    /// usage rather than with the number of connections.
    #[serde(default)]
    pub relayed_before_direct: u64,
    /// How long the most recent relay-to-direct upgrade took, in
    /// milliseconds, measured from the first sample of that connection.
    ///
    /// `None` means no connection to this peer has been observed making the
    /// move: either they have all been direct from the start, or none of them
    /// ever got off the relay.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_upgrade_millis: Option<u64>,
    /// How many observed connections to this peer moved from relay to direct.
    #[serde(default)]
    pub upgrades: u64,
}

impl PeerBytes {
    /// Everything relayed, in both directions: the billing figure.
    pub fn relayed_total(&self) -> u64 {
        self.relayed_sent.saturating_add(self.relayed_recv)
    }

    /// Everything direct, in both directions.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn direct_total(&self) -> u64 {
        self.direct_sent.saturating_add(self.direct_recv)
    }

    fn add(&mut self, kind: PathKind, sent: u64, recv: u64) {
        match kind {
            PathKind::Direct => {
                self.direct_sent = self.direct_sent.saturating_add(sent);
                self.direct_recv = self.direct_recv.saturating_add(recv);
            }
            PathKind::Relay => {
                self.relayed_sent = self.relayed_sent.saturating_add(sent);
                self.relayed_recv = self.relayed_recv.saturating_add(recv);
            }
        }
    }
}

/// What actually goes in the file.
///
/// Device ids and integers, and nothing else. No addresses — an address is
/// where someone was, which is more than a byte count needs to say — and no
/// device names, which are the user's words for their own machines.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeterFile {
    /// Format version, refused rather than guessed at if it is from the
    /// future.
    pub version: u32,
    /// When this accounting period began: the first time the meter was
    /// written on this device, or the first time after the file was deleted.
    pub since_unix: u64,
    /// When these totals were last written.
    pub updated_unix: u64,
    /// Totals per peer device id. Sorted, so a diff of two snapshots reads.
    pub peers: BTreeMap<String, PeerBytes>,
}

/// The last absolute counters seen for one path of one connection.
///
/// Keyed by connection *and* path, because iroh reuses neither across a
/// reconnection and treating a fresh path as a continuation of an old one
/// would silently subtract history.
#[derive(Debug, Clone, Copy, Default)]
struct Watermark {
    sent: u64,
    recv: u64,
}

/// What one connection has done since this daemon first saw it.
///
/// In memory only, and deliberately: "how long did this connection take to
/// escape the relay" is a fact about a connection, and a connection does not
/// survive a restart. What is persisted is the summary it contributes to
/// [`PeerBytes`].
#[derive(Debug)]
struct Link {
    /// When this daemon first sampled this connection. The clock the upgrade
    /// time is measured against — honest to within one [`SAMPLE_INTERVAL`],
    /// and named as such rather than pretending to be the QUIC handshake.
    first_seen: std::time::Instant,
    /// Bytes relayed on this connection so far, both directions.
    relayed: u64,
    /// Set once, when this connection was first seen carrying bytes direct.
    upgraded_after: Option<std::time::Duration>,
}

/// Per-peer byte totals and the sampling state that keeps them honest.
#[derive(Debug)]
pub struct RelayMeter {
    since_unix: u64,
    totals: HashMap<String, PeerBytes>,
    /// `(device id, connection stable id, path address) -> last reading`.
    watermarks: HashMap<(String, usize, String), Watermark>,
    /// `(device id, connection stable id) -> what that connection has done`.
    links: HashMap<(String, usize), Link>,
    dirty: bool,
}

impl Default for RelayMeter {
    fn default() -> Self {
        Self::new()
    }
}

impl RelayMeter {
    /// An empty meter whose accounting period starts now.
    pub fn new() -> Self {
        Self {
            since_unix: now_unix(),
            totals: HashMap::new(),
            watermarks: HashMap::new(),
            links: HashMap::new(),
            dirty: false,
        }
    }

    /// Reads the meter from disk, or starts a fresh one.
    ///
    /// A file this build cannot read is a reason to start counting again, not
    /// a reason to refuse to run: a device whose byte counter is corrupt is
    /// still a device its owner wants working. The loss is said out loud so
    /// that an operator reconciling an invoice knows a period was truncated.
    pub fn load(path: &Path) -> Self {
        match durable::load_json::<MeterFile>(path, "the relay meter") {
            Ok(Some(loaded)) => {
                if let Some(why) = loaded.repaired {
                    eprintln!("astd: {why}");
                }
                let file = loaded.value;
                if file.version > METER_VERSION {
                    eprintln!(
                        "astd: {} was written by a newer Asterism (format {}, this build reads {METER_VERSION}); \
                         byte counting starts again from zero and the old file is left alone",
                        path.display(),
                        file.version
                    );
                    return Self::new();
                }
                Self {
                    since_unix: if file.since_unix == 0 {
                        now_unix()
                    } else {
                        file.since_unix
                    },
                    totals: file.peers.into_iter().collect(),
                    watermarks: HashMap::new(),
                    links: HashMap::new(),
                    dirty: false,
                }
            }
            Ok(None) => Self::new(),
            Err(error) => {
                eprintln!(
                    "astd: could not read {}: {error}; byte counting starts again from zero",
                    path.display()
                );
                Self::new()
            }
        }
    }

    /// When this accounting period began.
    pub fn since(&self) -> u64 {
        self.since_unix
    }

    /// The totals for one peer, zero for a peer never seen.
    pub fn peer(&self, device_id: &str) -> PeerBytes {
        self.totals.get(device_id).copied().unwrap_or_default()
    }

    /// Folds one connection's current path counters into the peer's totals.
    ///
    /// Idempotent by construction: calling it twice with nothing having moved
    /// adds nothing, because the second call's differences are all zero. So a
    /// caller that wants fresh numbers before answering a question may simply
    /// call it, without coordinating with the background sampler.
    pub fn observe(&mut self, device_id: &str, connection: &MeshConnection) {
        let stable = connection.connection().stable_id();
        let link_key = (device_id.to_owned(), stable);
        let link = self.links.entry(link_key).or_insert_with(|| Link {
            first_seen: std::time::Instant::now(),
            relayed: 0,
            upgraded_after: None,
        });
        let already_upgraded = link.upgraded_after.is_some();
        let since_first_seen = link.first_seen.elapsed();

        let mut relayed_this_sample = 0u64;
        for path in connection.path_bytes() {
            let key = (device_id.to_owned(), stable, path.addr.clone());
            let previous = self.watermarks.get(&key).copied().unwrap_or_default();
            // A counter that went backwards is not a negative amount of
            // traffic; it is a path this daemon is seeing for the first time
            // under a key it has seen before. Take the new reading whole and
            // resume differencing from there.
            let sent = path.bytes_sent.saturating_sub(previous.sent);
            let recv = path.bytes_recv.saturating_sub(previous.recv);
            self.watermarks.insert(
                key,
                Watermark {
                    sent: path.bytes_sent,
                    recv: path.bytes_recv,
                },
            );
            if sent == 0 && recv == 0 {
                continue;
            }
            if path.kind == PathKind::Relay {
                relayed_this_sample = relayed_this_sample
                    .saturating_add(sent)
                    .saturating_add(recv);
            }
            self.totals
                .entry(device_id.to_owned())
                .or_default()
                .add(path.kind, sent, recv);
            self.dirty = true;
        }

        // The upgrade. Bytes relayed before it are the cost of the rendezvous;
        // bytes relayed after it are a connection that came back down to the
        // relay, which is a different fact and is not folded into the same
        // number.
        let link = self
            .links
            .get_mut(&(device_id.to_owned(), stable))
            .expect("inserted above");
        if !already_upgraded {
            link.relayed = link.relayed.saturating_add(relayed_this_sample);
        }

        let carrying_direct = matches!(
            connection.connection_type(),
            asterism_mesh::ConnectionType::Direct | asterism_mesh::ConnectionType::Mixed
        );
        if carrying_direct && !already_upgraded {
            link.upgraded_after = Some(since_first_seen);
            let relayed_first = link.relayed;
            let totals = self.totals.entry(device_id.to_owned()).or_default();
            totals.relayed_before_direct =
                totals.relayed_before_direct.saturating_add(relayed_first);
            totals.last_upgrade_millis =
                Some(since_first_seen.as_millis().min(u64::MAX as u128) as u64);
            totals.upgrades = totals.upgrades.saturating_add(1);
            self.dirty = true;
        }
    }

    /// How long this peer's current connection took to reach a direct path.
    ///
    /// Live, in-memory, and about the connection that is up right now —
    /// unlike [`PeerBytes::last_upgrade_millis`], which is the persisted
    /// summary and may be about a connection that has since closed. `None`
    /// when the current connection has not been seen going direct, which is
    /// both "still relayed" and "was direct from the first sample".
    pub fn upgrade_millis(&self, device_id: &str, connection: &MeshConnection) -> Option<u64> {
        let stable = connection.connection().stable_id();
        self.links
            .get(&(device_id.to_owned(), stable))?
            .upgraded_after
            .map(|d| d.as_millis().min(u64::MAX as u128) as u64)
    }

    /// Forgets a peer entirely: its totals and its sampling state.
    ///
    /// Called when a device leaves the orbit. Keeping a removed device's byte
    /// count would be keeping a record of a relationship the user ended.
    pub fn forget(&mut self, device_id: &str) {
        if self.totals.remove(device_id).is_some() {
            self.dirty = true;
        }
        self.watermarks.retain(|(peer, _, _), _| peer != device_id);
        self.links.retain(|(peer, _), _| peer != device_id);
    }

    /// The current totals, in the on-disk shape.
    pub fn snapshot(&self) -> MeterFile {
        MeterFile {
            version: METER_VERSION,
            since_unix: self.since_unix,
            updated_unix: now_unix(),
            peers: self
                .totals
                .iter()
                .map(|(id, bytes)| (id.clone(), *bytes))
                .collect(),
        }
    }

    /// Writes the totals if anything has moved since the last write.
    ///
    /// Returns whether it wrote. The no-change case costs no I/O at all, which
    /// is what makes a one-minute flush interval acceptable on a laptop that
    /// is idle for days.
    pub fn flush(&mut self, path: &Path) -> Result<bool> {
        if !self.dirty {
            return Ok(false);
        }
        durable::commit_json(path, &self.snapshot())?;
        self.dirty = false;
        Ok(true)
    }
}

/// A one-line summary for the daemon's startup disclosure.
///
/// Said out loud because a running byte meter is a thing a user is entitled to
/// know exists, and because the accounting period's start is the number that
/// makes every other number in the file interpretable.
pub fn describe(meter: &RelayMeter) -> String {
    let peers = meter.totals.len();
    let relayed: u64 = meter
        .totals
        .values()
        .fold(0u64, |sum, bytes| sum.saturating_add(bytes.relayed_total()));
    format!(
        "{peers} peer(s), {} relayed since unix {}",
        asterism_core::orbit::human_bytes(relayed),
        meter.since()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bump(
        meter: &mut RelayMeter,
        peer: &str,
        stable: usize,
        addr: &str,
        kind: PathKind,
        sent: u64,
        recv: u64,
    ) {
        // The differencing rule, exercised without an iroh connection: this is
        // the same arithmetic `observe` performs on one path.
        let link = meter
            .links
            .entry((peer.to_owned(), stable))
            .or_insert_with(|| Link {
                first_seen: std::time::Instant::now(),
                relayed: 0,
                upgraded_after: None,
            });
        let already_upgraded = link.upgraded_after.is_some();

        let key = (peer.to_owned(), stable, addr.to_owned());
        let previous = meter.watermarks.get(&key).copied().unwrap_or_default();
        let d_sent = sent.saturating_sub(previous.sent);
        let d_recv = recv.saturating_sub(previous.recv);
        meter.watermarks.insert(key, Watermark { sent, recv });
        if d_sent != 0 || d_recv != 0 {
            meter
                .totals
                .entry(peer.to_owned())
                .or_default()
                .add(kind, d_sent, d_recv);
            meter.dirty = true;
        }
        if kind == PathKind::Relay && !already_upgraded {
            let link = meter
                .links
                .get_mut(&(peer.to_owned(), stable))
                .expect("inserted above");
            link.relayed = link.relayed.saturating_add(d_sent).saturating_add(d_recv);
        }
    }

    #[test]
    fn a_cumulative_counter_is_counted_once_not_twice() {
        // The bug this design exists to prevent: a path reporting 100 bytes
        // and then 150 has carried 150, not 250.
        let mut meter = RelayMeter::new();
        bump(
            &mut meter,
            "peer",
            1,
            "relay:https://r",
            PathKind::Relay,
            100,
            10,
        );
        bump(
            &mut meter,
            "peer",
            1,
            "relay:https://r",
            PathKind::Relay,
            150,
            20,
        );
        assert_eq!(meter.peer("peer").relayed_sent, 150);
        assert_eq!(meter.peer("peer").relayed_recv, 20);
    }

    #[test]
    fn a_reconnection_adds_to_the_total_rather_than_restarting_it() {
        // Same peer, new connection: iroh's counters start at zero again and
        // the running total must not.
        let mut meter = RelayMeter::new();
        bump(
            &mut meter,
            "peer",
            1,
            "relay:https://r",
            PathKind::Relay,
            1000,
            0,
        );
        bump(
            &mut meter,
            "peer",
            2,
            "relay:https://r",
            PathKind::Relay,
            400,
            0,
        );
        assert_eq!(meter.peer("peer").relayed_sent, 1400);
    }

    #[test]
    fn direct_and_relayed_are_never_mixed() {
        let mut meter = RelayMeter::new();
        bump(
            &mut meter,
            "peer",
            1,
            "1.2.3.4:5",
            PathKind::Direct,
            900,
            800,
        );
        bump(
            &mut meter,
            "peer",
            1,
            "relay:https://r",
            PathKind::Relay,
            70,
            60,
        );
        let bytes = meter.peer("peer");
        assert_eq!(bytes.direct_sent, 900);
        assert_eq!(bytes.direct_recv, 800);
        assert_eq!(bytes.relayed_sent, 70);
        assert_eq!(bytes.relayed_recv, 60);
        assert_eq!(bytes.relayed_total(), 130);
    }

    #[test]
    fn two_peers_are_metered_apart() {
        let mut meter = RelayMeter::new();
        bump(
            &mut meter,
            "a",
            1,
            "relay:https://r",
            PathKind::Relay,
            500,
            0,
        );
        bump(
            &mut meter,
            "b",
            2,
            "relay:https://r",
            PathKind::Relay,
            700,
            0,
        );
        assert_eq!(meter.peer("a").relayed_sent, 500);
        assert_eq!(meter.peer("b").relayed_sent, 700);
        assert_eq!(meter.peer("never-seen"), PeerBytes::default());
    }

    #[test]
    fn a_counter_that_went_backwards_is_not_negative_traffic() {
        let mut meter = RelayMeter::new();
        bump(
            &mut meter,
            "peer",
            1,
            "relay:https://r",
            PathKind::Relay,
            900,
            0,
        );
        bump(
            &mut meter,
            "peer",
            1,
            "relay:https://r",
            PathKind::Relay,
            10,
            0,
        );
        assert_eq!(meter.peer("peer").relayed_sent, 900);
        bump(
            &mut meter,
            "peer",
            1,
            "relay:https://r",
            PathKind::Relay,
            60,
            0,
        );
        assert_eq!(meter.peer("peer").relayed_sent, 950);
    }

    #[test]
    fn a_removed_device_leaves_no_byte_count_behind() {
        let mut meter = RelayMeter::new();
        bump(
            &mut meter,
            "peer",
            1,
            "relay:https://r",
            PathKind::Relay,
            500,
            0,
        );
        meter.forget("peer");
        assert_eq!(meter.peer("peer"), PeerBytes::default());
        assert!(!meter.snapshot().peers.contains_key("peer"));
    }

    #[test]
    fn totals_survive_a_restart_and_the_period_start_does_too() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("relay-meter.json");
        let mut meter = RelayMeter::new();
        bump(
            &mut meter,
            "peer",
            1,
            "relay:https://r",
            PathKind::Relay,
            4096,
            2048,
        );
        assert!(meter.flush(&path).unwrap(), "a changed meter writes");
        assert!(!meter.flush(&path).unwrap(), "an unchanged meter does not");

        let reloaded = RelayMeter::load(&path);
        assert_eq!(reloaded.peer("peer").relayed_sent, 4096);
        assert_eq!(reloaded.peer("peer").relayed_recv, 2048);
        assert_eq!(reloaded.since(), meter.since());
    }

    #[test]
    fn a_missing_file_is_a_first_run_and_not_a_failure() {
        let dir = tempfile::tempdir().unwrap();
        let meter = RelayMeter::load(&dir.path().join("nothing-here.json"));
        assert!(meter.snapshot().peers.is_empty());
        assert!(meter.since() > 0);
    }

    #[test]
    fn the_file_records_device_ids_and_nothing_more_identifying() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("relay-meter.json");
        let mut meter = RelayMeter::new();
        bump(
            &mut meter,
            "abcd1234",
            1,
            "relay:https://relay.example",
            PathKind::Relay,
            10_000,
            0,
        );
        bump(
            &mut meter,
            "abcd1234",
            1,
            "192.168.1.9:41234",
            PathKind::Direct,
            10_000,
            0,
        );
        meter.flush(&path).unwrap();
        let written = std::fs::read_to_string(&path).unwrap();
        assert!(written.contains("abcd1234"));
        // The addresses were the key the differencing was done under; they are
        // not part of the accounting and must not be written down.
        assert!(
            !written.contains("192.168.1.9"),
            "an address leaked: {written}"
        );
        assert!(
            !written.contains("relay.example"),
            "an address leaked: {written}"
        );
    }

    #[test]
    fn the_startup_line_names_the_accounting_period_it_is_reporting() {
        // A relayed total with no "since when" beside it is a number nobody
        // can act on.
        let mut meter = RelayMeter::new();
        bump(
            &mut meter,
            "peer",
            1,
            "relay:https://r",
            PathKind::Relay,
            2048,
            2048,
        );
        let said = describe(&meter);
        assert!(said.contains("1 peer(s)"), "{said}");
        assert!(said.contains("4.0 KiB relayed"), "{said}");
        assert!(said.contains(&meter.since().to_string()), "{said}");
    }

    #[test]
    fn an_upgrade_separates_the_rendezvous_from_the_rest_of_the_bill() {
        // The arithmetic `observe` performs around the relay-to-direct move,
        // exercised without an iroh connection. Relayed bytes before the
        // upgrade are the cost of meeting; relayed bytes after it are a
        // connection that fell back, and the two must not be one number.
        let mut meter = RelayMeter::new();
        bump(
            &mut meter,
            "peer",
            1,
            "relay:https://r",
            PathKind::Relay,
            3000,
            1000,
        );
        let link = meter
            .links
            .get_mut(&("peer".to_owned(), 1))
            .expect("bump created the link");
        assert_eq!(link.relayed, 4000, "everything so far was relayed");

        // Hole punching lands.
        link.upgraded_after = Some(std::time::Duration::from_millis(412));
        let relayed_first = link.relayed;
        let totals = meter.totals.entry("peer".to_owned()).or_default();
        totals.relayed_before_direct = relayed_first;
        totals.last_upgrade_millis = Some(412);
        totals.upgrades = 1;

        // ...and afterwards the traffic goes direct.
        bump(
            &mut meter,
            "peer",
            1,
            "1.2.3.4:5",
            PathKind::Direct,
            900_000,
            0,
        );

        let bytes = meter.peer("peer");
        assert_eq!(bytes.relayed_total(), 4000);
        assert_eq!(bytes.relayed_before_direct, 4000);
        assert_eq!(bytes.direct_sent, 900_000);
        assert_eq!(bytes.last_upgrade_millis, Some(412));
        assert_eq!(bytes.upgrades, 1);
        // The property that matters to a relay operator: nearly a megabyte
        // moved and the relay carried four kilobytes of it.
        assert!(bytes.relayed_total() * 100 < bytes.direct_total());
    }
}
