use serde::{Deserialize, Serialize};

use crate::instance::{Instance, PortForward, Restart, Shape};
use crate::orbit::{Device, DeviceStatus, WakeFacts};
use crate::registry::OrbitRow;
use crate::snapshot::Snapshot;

/// One request per line of JSON over the daemon's unix socket;
/// the daemon answers with one `Response` line.
///
/// The same frames travel between two daemons over a mesh stream, and that is
/// the whole routing story. A request naming an instance is answered by the
/// device holding that instance's shard of the orbit registry, whichever
/// device the user typed it on: the daemon in front of them resolves the name
/// across the orbit and, if that row is on another device, wraps the frame in
/// [`Request::Proxy`] and forwards it. The far daemon unwraps and runs it
/// exactly as if it had come off its own socket, so no command needed a second
/// implementation to work from anywhere.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum Request {
    Ping,
    Create {
        name: String,
        image: String,
        shape: Shape,
        /// Hypervisor to define the instance against, recorded on it and
        /// used for every later boot. `None` takes the device's default,
        /// which is what every `ast create` before `--backend` existed
        /// sent — so an older CLI's frame still parses.
        #[serde(default)]
        backend: Option<String>,
        /// Guest ports to publish on the loopback of the device supplying
        /// cpu/ram (`ast create -p 8080:80`). Empty from a CLI that predates
        /// them, which is every `ast create` of a cloud image.
        #[serde(default)]
        publish: Vec<PortForward>,
    },
    Up {
        name: String,
        /// What the supervisor should do when this guest dies, from
        /// `ast up --restart`. Recorded on the instance and honoured by
        /// every later boot; `None` leaves whatever it already had, which
        /// is what every `ast up` before the flag existed sends.
        #[serde(default)]
        restart: Option<Restart>,
    },
    Down { name: String },
    Remove { name: String },
    /// One device's shard of the orbit registry — the instances whose cpu/ram
    /// it supplies. What one daemon asks another for while assembling
    /// [`Request::ListOrbit`], and what `ast ls --local` prints.
    List,
    /// The whole orbit registry, assembled: every shard the daemon can reach,
    /// plus the last-seen rows of the devices it cannot. This is `ast ls`.
    ListOrbit,
    Status { name: String },
    /// Give an instance a different name. The only command a conflicted
    /// instance answers, because it is the only one that ends the conflict.
    Rename { name: String, new_name: String },
    /// Tell the device holding `name` that the orbit has another instance of
    /// that name on it. Sent daemon-to-daemon when an assembled view finds a
    /// collision a partition had hidden; see `Shard::mark_conflicted` for the
    /// rule that decides which of the two is told.
    MarkConflicted { name: String, other_cpu_device: String },
    AttachVolume {
        name: String,
        path: String,
        host: Option<String>,
        #[serde(default)]
        mount_point: Option<String>,
    },
    /// Attach a block volume — one created with `ast volume create` on
    /// `device` — to an instance.
    ///
    /// A separate frame from [`Request::AttachVolume`] rather than a flag on
    /// it, so that a daemon too old to serve leases refuses with "unknown
    /// variant" instead of quietly recording a directory share named `tank`.
    AttachBlock {
        name: String,
        /// The volume's name on the device that holds its bytes.
        volume: String,
        /// The device that holds them.
        device: String,
    },
    /// Take a volume off an instance: the record goes, and a block volume's
    /// lease is handed back to the device that owns it.
    Detach {
        name: String,
        /// The directory path, or the block volume's name.
        volume: String,
        /// The device it came from. `None` means this one.
        #[serde(default)]
        host: Option<String>,
    },
    Snapshot { name: String, tag: String },
    SnapshotList { name: String },
    SnapshotRestore { name: String, tag: String },
    /// Delete one snapshot. Additive: a daemon too old to know this frame
    /// refuses it by name rather than doing something else with it.
    SnapshotRemove { name: String, tag: String },
    /// The last `lines` lines of an instance's guest console.
    ///
    /// A daemon-side read, so it works when the console log is on another
    /// device's disk. `ast logs -f` still tails the file directly, which is
    /// why following is only offered where the file is.
    Logs { name: String, lines: u32 },
    /// Where to point `ssh` at to reach this instance's guest.
    ///
    /// Answered with a loopback address every time. When the guest's cpu/ram
    /// are on this device that is the hypervisor's own forwarded port; when
    /// they are elsewhere the daemon binds an ephemeral listener and splices
    /// it to the far daemon over the mesh, so `ast ssh dev` is one command
    /// from anywhere and never mentions a device.
    SshEndpoint { name: String },

    // ---- the mesh ----------------------------------------------------------
    //
    // The CLI never opens a mesh connection itself; it asks the daemon on the
    // machine it is sitting at, which is the one holding the always-on
    // endpoint. Everything below therefore travels the unix socket like any
    // other request.
    /// Run `inner` on another device in this orbit and hand back its answer
    /// verbatim.
    ///
    /// Normally nobody types this: the daemon puts a request in this envelope
    /// itself, once it has resolved the instance name to the device holding
    /// that shard. `ast --device <name> <command>` is the manual override, for
    /// asking one specific daemon a question about itself.
    Proxy { device: String, inner: Box<Request> },
    /// The orbit as `ast devices` shows it: every peer plus this device,
    /// with liveness probed as the request is served.
    Devices,
    /// Offer to add a device: mint a ticket and wait for someone to redeem it.
    ///
    /// Answered with more than one line — a [`Response::Ticket`] to print, then
    /// a [`Response::Sas`] once a peer turns up, and the daemon then waits for
    /// a [`Request::PairConfirm`] on the same connection before trusting
    /// anybody.
    DeviceInvite {
        /// What this device should call itself, if not its hostname.
        #[serde(default)]
        name: Option<String>,
        /// How long the ticket stays redeemable, in seconds.
        #[serde(default)]
        ttl_secs: Option<u64>,
    },
    /// Redeem a ticket printed by [`Request::DeviceInvite`] on another device.
    /// Answered with a [`Response::Sas`] and the same confirmation exchange.
    DeviceAdd {
        ticket: String,
        #[serde(default)]
        name: Option<String>,
    },
    /// The human's verdict on the six digits both terminals just printed.
    PairConfirm { accept: bool },
    /// Drop a device from this orbit. Its key stops being trusted at once.
    DeviceRemove { name: String },
    /// Round-trip a mesh stream to one device and time it.
    DevicePing { device: String },

    // ---- power and presence -------------------------------------------------
    /// Wake a sleeping device: `ast device wake <name>`.
    ///
    /// Answered with more than one line, because it is a job rather than a
    /// question — who is going to send the packet, that it was sent, and then
    /// whether the device turned up — each a [`Response::Wake`] as it
    /// happens, ending in one that is `done`.
    DeviceWake { name: String },
    /// Broadcast a magic packet for `mac` on this device's own LAN.
    ///
    /// Daemon-to-daemon, and the reason wake is an orbit operation at all: a
    /// magic packet has to originate inside the sleeper's broadcast domain,
    /// so the device that wants the wake asks one that is standing there.
    /// `lan_id` is the network the asker believes the answerer is on, and the
    /// answerer checks it against its own before broadcasting — a device that
    /// has moved since we last heard from it must decline rather than spray a
    /// stranger's LAN with someone else's MAC.
    WakeBroadcast {
        mac: String,
        #[serde(default)]
        lan_id: Option<String>,
    },
    /// What this device can say about its own place on the wire, as
    /// [`Response::WakeFacts`]. How a peer's record is refreshed after the
    /// pairing that first filled it in.
    DeviceFacts,
    /// This device's wake readiness, honestly reported: `ast device check`.
    DeviceCheck,

    // ---- block volumes ------------------------------------------------------
    //
    // Volumes are a *device's* part of the pool, not an instance's, so none of
    // these resolves through the instance namespace. They are answered by the
    // device that holds the bytes — reached by name, either because the user
    // typed `--device`, or because a consumer's daemon put the frame in a
    // [`Request::Proxy`] envelope aimed at the device an attach named.

    /// Make a new block volume on this device: a sparse raw image and the
    /// bookkeeping that goes with it.
    VolumeCreate { name: String, size_bytes: u64 },
    /// This device's block volumes, with their sizes and leases.
    VolumeList,
    /// Delete a block volume and its bytes. Refused while it is leased.
    VolumeRemove { name: String },
    /// Take or renew the single-writer lease, at a new epoch, and start (or
    /// restart) the NBD export that serves it.
    ///
    /// Sent by the consumer's daemon on attach and again on every boot. The
    /// epoch bump is the fence: the previous export is stopped and its socket
    /// unlinked, so anything still holding the old one dies rather than
    /// writing alongside the new holder.
    VolumeLease {
        volume: String,
        /// The instance that will be writing.
        holder: String,
        /// The device supplying that instance's cpu and ram.
        holder_device: String,
    },
    /// Pick the lease this instance already has back up, at the epoch it
    /// already holds, and make sure the export serving it is running.
    ///
    /// Sent by a consumer's daemon that has just restarted while the guest
    /// it booted kept running. That guest's QEMU was given one export name
    /// on its command line and will ask for exactly that one when it
    /// reconnects, so this must *not* bump the epoch — a bump would rename
    /// the door out from under a guest that is doing nothing wrong.
    ///
    /// Refused, in the same words a stale consumer gets, when the lease has
    /// moved on: same holder and same epoch, or nothing.
    VolumeReconnect { volume: String, holder: String, epoch: u64 },
    /// Hand the lease back and stop the export.
    VolumeRelease { volume: String, holder: String },

    // ---- swapping the cpu part ----------------------------------------------
    //
    // `ast set <instance> cpu <device>` — an offline migration, and in the
    // model's own words a change to one line of an instance's parts table.
    // The daemon in front of the user drives it; the frames below are the
    // steps it drives, each aimed at one named device and therefore each
    // reporting no subject (see [`Request::subject`]).
    /// Swap the device supplying an instance's cpu and ram.
    ///
    /// Answered with a stream of [`Response::Move`] lines, because it is a
    /// job and not a question: bytes crossing a network are worth watching.
    SetCpu {
        name: String,
        /// The device that will supply cpu and ram from here on.
        device: String,
        /// Shut the guest down first, rather than refusing to move a
        /// running instance. Offline migration is the only kind that works
        /// on every backend we have, so this is a real choice and not a
        /// convenience.
        #[serde(default)]
        down: bool,
    },
    /// Ask the device holding an instance what a move of it would carry.
    ///
    /// Read-only: nothing is fenced and nothing moves. This is the preflight
    /// — the file list, their allocated bytes, and the base image's content
    /// address — so the target can be asked whether it could take it before
    /// the instance is taken out of service.
    MoveOffer { name: String },
    /// Ask a device whether it could take this instance: same architecture,
    /// a backend it can actually run, an image reference that means
    /// something here. Read-only.
    MoveProbe { manifest: Box<MoveManifest> },
    /// Fence an instance for a move: mark it `moving`, refuse `up`, and
    /// answer with the manifest as it stands now.
    ///
    /// From here until a commit or an abort, this device holds the only
    /// bootable copy and will not boot it.
    MovePrepare { name: String, to_device: String, epoch: u64 },
    /// The bytes are all here and verified: adopt them. The staging
    /// directory becomes the instance directory and the row is written with
    /// this device supplying cpu, at `epoch`.
    MoveCommitTarget { manifest: Box<MoveManifest>, epoch: u64 },
    /// The target has acked: drop the row and the bytes.
    MoveCommitSource { name: String, epoch: u64 },
    /// The move did not happen. Clear the fence; this row stays
    /// authoritative.
    MoveAbortSource { name: String, epoch: u64 },
    /// The move did not happen. Delete the staging directory, which is the
    /// only place the half-transferred bytes ever were.
    MoveAbortTarget { name: String, epoch: u64 },
}

/// A base image, as one device describes it to another.
///
/// Base images are content-addressed and cached per device: a device that
/// lacks one pulls it from an orbit peer that has it before it would ever
/// reach for the internet (`docs/MODEL.md`, "Where bytes live"). `digest` is
/// what makes that safe — the reference names the image, the digest says
/// which bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BaseImage {
    /// The reference recorded on the instance: `debian:13`, a url, a path.
    pub reference: String,
    /// Length of the base image file.
    pub len: u64,
    /// What it actually occupies — a raw base image converted from a cloud
    /// image is mostly hole, so this is what a peer fetch really costs and
    /// what its progress is measured against.
    #[serde(default)]
    pub allocated: u64,
    /// Content address of its bytes.
    pub digest: String,
}

impl BaseImage {
    /// A reference the source cannot hand over: it does not resolve there, or
    /// the bytes are not on that device either. Not an error — an instance's
    /// disk is a complete file and boots without its base — so this travels
    /// as a fact the target's probe reports rather than as a refusal.
    pub fn absent(reference: String) -> Self {
        BaseImage { reference, len: 0, allocated: 0, digest: String::new() }
    }

    /// What a peer fetch of it would really cost.
    pub fn cost(&self) -> u64 {
        if self.allocated == 0 { self.len } else { self.allocated }
    }
}

/// One file a move will carry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoveFile {
    /// Path relative to the instance directory, `/`-separated.
    pub path: String,
    /// What the file claims to be — 20 GiB, for a root disk.
    pub len: u64,
    /// What it actually holds, and therefore what will cross the wire.
    pub allocated: u64,
    /// Permission bits. `seed.iso` and a disk are not the same secret.
    pub mode: u32,
}

/// Everything a cpu-part swap will carry, computed on the source device
/// before any of it moves.
///
/// This doubles as the estimate the roadmap asks for and as the completeness
/// check the commit turns on: the target counts what arrived against
/// `allocated` per file and refuses to adopt a directory that does not add
/// up.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MoveManifest {
    /// The instance record itself, which the target adopts on commit.
    pub instance: Instance,
    /// The architecture the source is running. A guest built for one
    /// instruction set does not boot on another, and no amount of copying
    /// changes that, so this is checked before a byte moves.
    pub arch: String,
    /// The base image the disk was cloned from, which the target must have.
    pub base: BaseImage,
    /// The files, in the order they will be sent.
    pub files: Vec<MoveFile>,
    /// Guest paths of volumes that are same-device 9p shares on the source.
    /// They do not survive the move as working parts; they survive as rows
    /// with a flag on them.
    #[serde(default)]
    pub local_volumes: Vec<String>,
}

impl MoveManifest {
    /// Total bytes the transfer will really carry.
    pub fn allocated(&self) -> u64 {
        self.files.iter().map(|f| f.allocated).sum()
    }

    /// Total bytes the files claim between them.
    pub fn virtual_size(&self) -> u64 {
        self.files.iter().map(|f| f.len).sum()
    }
}

impl Request {
    /// The instance this request is about, when it is about one.
    ///
    /// This is what makes resolution transparent: a request with a subject can
    /// be answered by whichever device holds that instance's row, so the
    /// daemon looks the name up across the orbit and forwards the frame if
    /// that row is on another device. A request without a subject is about
    /// this device, or about the orbit, and is answered here.
    ///
    /// [`Request::Create`] is deliberately absent. It does not resolve a name,
    /// it *claims* one — a different question, asked of every device rather
    /// than answered by one.
    pub fn subject(&self) -> Option<&str> {
        match self {
            Request::Up { name, .. }
            | Request::Down { name }
            | Request::Remove { name }
            | Request::Status { name }
            | Request::Rename { name, .. }
            | Request::MarkConflicted { name, .. }
            | Request::AttachVolume { name, .. }
            | Request::AttachBlock { name, .. }
            | Request::Detach { name, .. }
            | Request::Snapshot { name, .. }
            | Request::SnapshotList { name }
            | Request::SnapshotRestore { name, .. }
            | Request::SnapshotRemove { name, .. }
            | Request::Logs { name, .. }
            | Request::SshEndpoint { name } => Some(name),
            Request::Ping
            | Request::Create { .. }
            | Request::List
            | Request::ListOrbit
            | Request::Proxy { .. }
            | Request::Devices
            | Request::DeviceInvite { .. }
            | Request::DeviceAdd { .. }
            | Request::PairConfirm { .. }
            | Request::DeviceRemove { .. }
            | Request::DevicePing { .. }
            // About devices, not instances. `ast device wake desktop` names a
            // device on purpose — it is the one command whose subject really
            // is a machine — so it must never be routed as if `desktop` were
            // an instance somebody else holds.
            | Request::DeviceWake { .. }
            | Request::WakeBroadcast { .. }
            | Request::DeviceFacts
            | Request::DeviceCheck
            // A volume belongs to a device, not to an instance, and volume
            // names are not orbit-global — two devices may each have a
            // `tank`. Resolving one through the instance namespace would send
            // it to whoever happens to hold an instance of that name.
            | Request::VolumeCreate { .. }
            | Request::VolumeList
            | Request::VolumeRemove { .. }
            | Request::VolumeLease { .. }
            | Request::VolumeReconnect { .. }
            | Request::VolumeRelease { .. }
            // Every step of a cpu-part swap names one device on purpose and
            // is aimed at it. Half of them go to a device that does *not*
            // hold the row — that is what a move is — so resolving them by
            // instance name would send them back to the wrong end of the
            // transfer, and `set cpu` itself names the destination.
            | Request::SetCpu { .. }
            | Request::MoveOffer { .. }
            | Request::MoveProbe { .. }
            | Request::MovePrepare { .. }
            | Request::MoveCommitTarget { .. }
            | Request::MoveCommitSource { .. }
            | Request::MoveAbortSource { .. }
            | Request::MoveAbortTarget { .. } => None,
        }
    }

    /// Whether an instance in conflict will answer this request.
    ///
    /// `rename` is the remedy, so it must go through. `status` and `down` go
    /// through because refusing them would be a trap: `rename` will not touch
    /// a running guest, so an instance that is both conflicted and running
    /// would have no legal move at all, and a user told to rename something
    /// deserves to be able to look at it first.
    pub fn survives_a_conflict(&self) -> bool {
        matches!(
            self,
            Request::Rename { .. } | Request::Status { .. } | Request::Down { .. }
        )
    }

    /// Whether an instance whose bytes are in flight to another device will
    /// answer this request.
    ///
    /// Only the ones that read. A move fences the source for the length of
    /// the transfer precisely so that there is never a second writer, and a
    /// command that booted, renamed, snapshotted or deleted the instance
    /// underneath a transfer would be exactly that. Looking is fine, and has
    /// to be: the fence is a state a user is entitled to see.
    pub fn survives_a_move(&self) -> bool {
        matches!(self, Request::Status { .. } | Request::Logs { .. })
    }
}

// One variant carries a whole Instance and the rest carry almost nothing,
// which is what a reply type looks like. Boxing it would buy an allocation
// and a pointer hop on a value that is built once per request and
// serialized immediately.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum Response {
    Ok,
    /// Reply to [`Request::Ping`], carrying the daemon's crate version.
    ///
    /// A daemon older than this variant answers `Ping` with plain `Ok`, so
    /// the *absence* of a version is itself the mismatch signal — which is
    /// what makes this a backward-compatible change rather than a break.
    Pong { version: String },
    Instance { instance: Instance },
    /// Reply to [`Request::List`]: one device's shard.
    Instances { instances: Vec<Instance> },
    /// Reply to [`Request::ListOrbit`]: the orbit registry, assembled from
    /// every shard that answered plus the cached rows of those that did not.
    Orbit { rows: Vec<OrbitRow> },
    Snapshots { snapshots: Vec<Snapshot> },
    /// Reply to [`Request::Logs`]. `truncated` says whether older lines were
    /// left behind, so the CLI can offer `--lines` rather than imply the
    /// guest has been quiet.
    Log { text: String, truncated: bool },
    /// Reply to [`Request::SshEndpoint`]: a loopback address `ssh` can be
    /// pointed at right now, and the key file that opens the guest. Whose cpu
    /// is running the guest changes neither field's meaning, which is the
    /// point — both are paths and ports on the machine `ast` is running on.
    SshEndpoint { host: String, port: u16, identity: String },

    // ---- the mesh ----------------------------------------------------------
    /// Reply to [`Request::Devices`].
    Devices { devices: Vec<DeviceStatus> },
    /// The pasteable ticket minted by [`Request::DeviceInvite`], and how long
    /// it stays good for.
    Ticket { ticket: String, expires_in_secs: u64 },
    /// The six digits to compare, and who is on the other end.
    ///
    /// Sent by both halves of pairing, and always followed by the daemon
    /// waiting for a [`Request::PairConfirm`]: no key is trusted until a human
    /// has said the codes match.
    Sas {
        code: String,
        peer: String,
        device_id: String,
    },
    /// A peer that is now in this orbit.
    Paired { device: Device },
    /// Reply to [`Request::DevicePing`].
    DevicePong {
        device: String,
        device_id: String,
        path: String,
        millis: f64,
    },

    // ---- power and presence -------------------------------------------------
    /// One line of a wake in progress, and whether it was the last one.
    ///
    /// A wake is three things a user wants told separately — who is sending
    /// the packet, that it went, and whether the machine turned up — with up
    /// to a minute between the second and the third. One reply at the end
    /// would be a minute of silence, which is the thing the spec is trying to
    /// stop happening.
    Wake {
        text: String,
        #[serde(default)]
        done: bool,
    },
    /// Reply to [`Request::DeviceFacts`]: where this device sits on the wire.
    WakeFacts { facts: WakeFacts },
    /// Reply to [`Request::DeviceCheck`]: `ast device check`, as a table.
    WakeCheck {
        device: String,
        rows: Vec<CheckRow>,
    },

    // ---- block volumes ------------------------------------------------------
    /// Reply to [`Request::VolumeList`], [`Request::VolumeCreate`] and
    /// [`Request::VolumeRemove`]: whatever the device now has to say about
    /// the volumes in question.
    Volumes { volumes: Vec<crate::volume::BlockVolume> },
    /// Reply to [`Request::VolumeLease`]: the lease was granted, at this
    /// epoch, under this export name.
    ///
    /// The socket path is the *provider's* and is reported for diagnostics
    /// only — the consumer never opens it, because it is on another machine.
    /// What the consumer does with this is present the epoch on every splice
    /// and hand the export name to QEMU.
    VolumeLease {
        volume: String,
        epoch: u64,
        export: String,
        socket: String,
        size_bytes: u64,
    },

    // ---- swapping the cpu part ----------------------------------------------
    /// One line of a move in progress, and whether it was the last one.
    ///
    /// Same shape and same reason as [`Response::Wake`]: a move is minutes
    /// of a disk crossing a network, and a user watching a terminal deserves
    /// to see the bytes go rather than a cursor.
    Move {
        text: String,
        #[serde(default)]
        done: bool,
    },
    /// Reply to [`Request::MoveOffer`] and [`Request::MovePrepare`]: what a
    /// move of this instance would carry.
    MoveOffer { manifest: Box<MoveManifest> },
    /// Reply to [`Request::MoveProbe`]: whether this device could take the
    /// instance, and what it would have to fetch first.
    MoveProbe {
        /// The device that answered, so the refusal can name it.
        device: String,
        /// Why it cannot, when it cannot. `None` is a yes.
        #[serde(default)]
        refusal: Option<String>,
        /// True things worth saying that are not refusals — a different
        /// hypervisor version, a volume that will not survive.
        #[serde(default)]
        notes: Vec<String>,
        /// Whether the base image has to be fetched from the source first.
        needs_base: bool,
    },

    Error { message: String },
}

/// One line of `ast device check`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckRow {
    /// What is being reported on: `wake on magic packet`, `interface`, ...
    pub item: String,
    /// How it stands.
    pub verdict: Verdict,
    /// The evidence, or the reason there is none.
    pub detail: String,
}

/// How sure this device is about one line of its own wake readiness.
///
/// [`Verdict::Unknown`] is a first-class answer and gets used a lot, on
/// purpose. Almost nothing about waking can be *verified* from the machine
/// that would be asleep — whether the NIC keeps power after shutdown, whether
/// the switch floods the broadcast, whether a Bonjour proxy is holding the
/// Wi-Fi address — and a check that guessed `ok` at those would be worse than
/// no check at all, because it would be believed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// Verified on this machine, right now.
    Ok,
    /// Verified, and it will not work.
    No,
    /// True as far as it goes, with a caveat that decides whether it works.
    Warn,
    /// Not knowable from here.
    Unknown,
}

impl Verdict {
    /// The word the table prints.
    pub fn label(&self) -> &'static str {
        match self {
            Verdict::Ok => "ok",
            Verdict::No => "no",
            Verdict::Warn => "warn",
            Verdict::Unknown => "?",
        }
    }
}

/// How a daemon that is too old to understand us gives itself away: serde
/// rejects the request variant it has never heard of, and the daemon dutifully
/// reports the parse error. Matching on the text is unlovely, but it is the
/// only signal an old binary can send — and it is stable, because it is
/// serde's own wording for an unknown enum variant.
pub fn is_unknown_variant_error(message: &str) -> bool {
    message.contains("unknown variant")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_pre_pong_daemon_is_recognisable() {
        // What an older astd sends back for Ping.
        let old: Response = serde_json::from_str(r#"{"result":"ok"}"#).unwrap();
        assert!(matches!(old, Response::Ok));
        // What this one sends.
        let new: Response =
            serde_json::from_str(r#"{"result":"pong","version":"0.0.2"}"#).unwrap();
        assert!(matches!(new, Response::Pong { version } if version == "0.0.2"));
    }

    #[test]
    fn the_frames_a_pre_mesh_build_sent_still_parse() {
        // Adding variants must not disturb the ones already on the wire, or a
        // daemon and a CLI from either side of this change stop understanding
        // each other for reasons that have nothing to do with the mesh.
        let list: Request = serde_json::from_str(r#"{"cmd":"list"}"#).unwrap();
        assert!(matches!(list, Request::List));
        let status: Request = serde_json::from_str(r#"{"cmd":"status","name":"dev"}"#).unwrap();
        assert!(matches!(status, Request::Status { name } if name == "dev"));
        let attach: Request = serde_json::from_str(
            r#"{"cmd":"attach_volume","name":"dev","path":"/tank","host":null}"#,
        )
        .unwrap();
        assert!(matches!(attach, Request::AttachVolume { mount_point: None, .. }));
        // A create from before backends could be chosen means "whatever
        // this device uses", not a parse error.
        let create: Request = serde_json::from_str(
            r#"{"cmd":"create","name":"dev","image":"debian:13",
                "shape":{"cpus":2,"mem_mib":2048,"disk_gib":20}}"#,
        )
        .unwrap();
        assert!(matches!(create, Request::Create { backend: None, .. }));
        let Request::Create { publish, .. } = &create else { unreachable!("a create") };
        assert!(publish.is_empty(), "a cloud image publishes nothing");

        // ...and one from a CLI that has `-p` carries what it asked for.
        let published: Request = serde_json::from_str(
            r#"{"cmd":"create","name":"web","image":"nginx",
                "shape":{"cpus":2,"mem_mib":2048,"disk_gib":20},
                "publish":[{"host":8080,"guest":80}]}"#,
        )
        .unwrap();
        let Request::Create { publish, .. } = &published else { unreachable!("a create") };
        assert_eq!(publish, &[PortForward { host: 8080, guest: 80 }]);
    }

    #[test]
    fn a_proxied_request_carries_the_inner_one_unchanged() {
        // `ast --device desktop ls` is `ls` in an envelope; the remote daemon
        // must see the very same frame its own CLI would have sent.
        let wire = serde_json::to_string(&Request::Proxy {
            device: "desktop".into(),
            inner: Box::new(Request::Status { name: "dev".into() }),
        })
        .unwrap();
        assert_eq!(
            wire,
            r#"{"cmd":"proxy","device":"desktop","inner":{"cmd":"status","name":"dev"}}"#
        );

        let Request::Proxy { device, inner } = serde_json::from_str(&wire).unwrap() else {
            panic!("should decode as a proxy");
        };
        assert_eq!(device, "desktop");
        assert!(matches!(*inner, Request::Status { name } if name == "dev"));
    }

    /// Resolution is driven entirely by this: anything with a subject can be
    /// answered by whichever device holds that instance, so anything with a
    /// subject must report one. A new instance command that forgot to would
    /// silently only ever work on the device it was typed on.
    #[test]
    fn every_request_about_one_instance_names_it() {
        let named: Vec<Request> = vec![
            Request::Up { name: "dev".into(), restart: None },
            Request::Down { name: "dev".into() },
            Request::Remove { name: "dev".into() },
            Request::Status { name: "dev".into() },
            Request::Rename { name: "dev".into(), new_name: "dev2".into() },
            Request::MarkConflicted { name: "dev".into(), other_cpu_device: "d".into() },
            Request::AttachVolume {
                name: "dev".into(),
                path: "/t".into(),
                host: None,
                mount_point: None,
            },
            Request::AttachBlock {
                name: "dev".into(),
                volume: "tank".into(),
                device: "desktop".into(),
            },
            Request::Detach { name: "dev".into(), volume: "tank".into(), host: None },
            Request::Snapshot { name: "dev".into(), tag: "t".into() },
            Request::SnapshotList { name: "dev".into() },
            Request::SnapshotRestore { name: "dev".into(), tag: "t".into() },
            Request::Logs { name: "dev".into(), lines: 200 },
            Request::SshEndpoint { name: "dev".into() },
        ];
        for req in &named {
            assert_eq!(req.subject(), Some("dev"), "{req:?} must resolve by name");
        }

        // Create claims a name across the orbit rather than resolving it, so
        // it must not be routed to whoever already answers to that name.
        let create = Request::Create {
            name: "dev".into(),
            image: "debian:13".into(),
            shape: Shape::default(),
            backend: None,
            publish: Vec::new(),
        };
        assert_eq!(create.subject(), None);
        assert_eq!(Request::List.subject(), None);
        assert_eq!(Request::ListOrbit.subject(), None);
        assert_eq!(Request::Devices.subject(), None);

        // `ast device wake desktop` names a *device*. Reporting it as a
        // subject would send the frame off to be resolved against the
        // instance namespace, where "desktop" means nothing.
        assert_eq!(Request::DeviceWake { name: "desktop".into() }.subject(), None);
        assert_eq!(
            Request::WakeBroadcast { mac: "de:ad:be:ef:00:01".into(), lan_id: None }.subject(),
            None
        );
        assert_eq!(Request::DeviceFacts.subject(), None);
        assert_eq!(Request::DeviceCheck.subject(), None);
    }

    /// Wake was added to a protocol already in the field, so it has to be
    /// purely additive: old frames keep parsing, and the new ones parse
    /// without the field a newer daemon would send.
    #[test]
    fn the_wake_frames_are_additive() {
        let wake: Request = serde_json::from_str(r#"{"cmd":"device_wake","name":"desktop"}"#).unwrap();
        assert!(matches!(wake, Request::DeviceWake { name } if name == "desktop"));

        // An `astd` that predates lan-id checking sends the MAC and nothing
        // else; that must not be a parse error on the device being asked.
        let bare: Request =
            serde_json::from_str(r#"{"cmd":"wake_broadcast","mac":"de:ad:be:ef:00:01"}"#).unwrap();
        assert!(matches!(bare, Request::WakeBroadcast { lan_id: None, .. }));

        // Likewise a progress line with no `done` is not the last one.
        let line: Response = serde_json::from_str(r#"{"result":"wake","text":"sent"}"#).unwrap();
        assert!(matches!(line, Response::Wake { done: false, .. }));

        // And a peer that knows only half of its own story still answers.
        let facts: Response =
            serde_json::from_str(r#"{"result":"wake_facts","facts":{"mac":"de:ad:be:ef:00:01"}}"#)
                .unwrap();
        let Response::WakeFacts { facts } = facts else { panic!("should be facts") };
        assert_eq!(facts.mac.as_deref(), Some("de:ad:be:ef:00:01"));
        assert_eq!(facts.lan_id, None);
        assert_eq!(facts.wakeable(), None, "half a story cannot wake anything");
    }

    /// Volumes came to a protocol already in the field, so they are additive
    /// in both directions: old frames keep parsing, and the new ones are new
    /// *variants* — so a daemon too old to hold a lease says "unknown
    /// variant" rather than half-understanding an attach.
    #[test]
    fn the_volume_frames_are_additive_and_distinct() {
        // Everything a pre-volume CLI sent still parses unchanged.
        let attach: Request = serde_json::from_str(
            r#"{"cmd":"attach_volume","name":"dev","path":"/tank","host":null}"#,
        )
        .unwrap();
        assert!(matches!(attach, Request::AttachVolume { .. }));

        // And a block attach is its own frame, not a flag on that one.
        assert_eq!(
            serde_json::to_string(&Request::AttachBlock {
                name: "dev".into(),
                volume: "tank".into(),
                device: "desktop".into(),
            })
            .unwrap(),
            r#"{"cmd":"attach_block","name":"dev","volume":"tank","device":"desktop"}"#
        );

        // A detach without a host means "this device", the way attach does.
        let detach: Request =
            serde_json::from_str(r#"{"cmd":"detach","name":"dev","volume":"/tank"}"#).unwrap();
        assert!(matches!(detach, Request::Detach { host: None, .. }));

        // The lease frames name the instance *and* the device supplying its
        // cpu, because a refusal that cannot say where is not actionable.
        let lease: Request = serde_json::from_str(
            r#"{"cmd":"volume_lease","volume":"tank","holder":"dev","holder_device":"laptop"}"#,
        )
        .unwrap();
        assert!(matches!(lease, Request::VolumeLease { .. }));
        assert_eq!(lease.subject(), None, "a volume is a device's part");
        assert_eq!(Request::VolumeList.subject(), None);
        assert_eq!(
            Request::VolumeCreate { name: "tank".into(), size_bytes: 1 << 30 }.subject(),
            None
        );

        // An instance-scoped one, on the other hand, must resolve by name or
        // it would only ever work on the device it was typed at.
        assert_eq!(
            Request::AttachBlock {
                name: "dev".into(),
                volume: "tank".into(),
                device: "desktop".into()
            }
            .subject(),
            Some("dev")
        );
    }

    /// Every step of a move names one device and is aimed at it, so none of
    /// them may report a subject: half go to a device that does not hold the
    /// row, and resolving them by instance name would send them to the wrong
    /// end of the transfer.
    #[test]
    fn the_move_frames_are_aimed_at_devices_not_resolved_by_name() {
        let manifest = Box::new(MoveManifest {
            instance: Instance::new("dev", "laptop", "debian:13", Shape::default(), None),
            arch: "aarch64".into(),
            base: BaseImage::absent("debian:13".to_owned()),
            files: vec![
                MoveFile { path: "disk.raw".into(), len: 20 << 30, allocated: 1 << 30, mode: 0o600 },
                MoveFile { path: "seed.iso".into(), len: 366 << 10, allocated: 366 << 10, mode: 0o644 },
            ],
            local_volumes: vec!["/mnt/ast/tank".into()],
        });

        assert_eq!(manifest.allocated(), (1 << 30) + (366 << 10));
        assert_eq!(manifest.virtual_size(), (20 << 30) + (366 << 10));
        assert!(
            manifest.allocated() * 4 < manifest.virtual_size(),
            "a root disk is mostly hole, and that is the whole economics of a move"
        );

        for req in [
            Request::SetCpu { name: "dev".into(), device: "desktop".into(), down: false },
            Request::MoveOffer { name: "dev".into() },
            Request::MoveProbe { manifest: manifest.clone() },
            Request::MovePrepare { name: "dev".into(), to_device: "desktop".into(), epoch: 1 },
            Request::MoveCommitTarget { manifest: manifest.clone(), epoch: 1 },
            Request::MoveCommitSource { name: "dev".into(), epoch: 1 },
            Request::MoveAbortSource { name: "dev".into(), epoch: 1 },
            Request::MoveAbortTarget { name: "dev".into(), epoch: 1 },
        ] {
            assert_eq!(req.subject(), None, "{req:?} names a device, not an instance");
            assert!(!req.survives_a_move(), "{req:?} is not a read");
        }

        // `--down` is defaulted, so a CLI that predates it still parses.
        let bare: Request =
            serde_json::from_str(r#"{"cmd":"set_cpu","name":"dev","device":"desktop"}"#).unwrap();
        assert!(matches!(bare, Request::SetCpu { down: false, .. }));

        // A fenced instance answers what reads and nothing that writes.
        assert!(Request::Status { name: "dev".into() }.survives_a_move());
        assert!(Request::Logs { name: "dev".into(), lines: 10 }.survives_a_move());
        assert!(!Request::Up { name: "dev".into(), restart: None }.survives_a_move());
        assert!(!Request::Remove { name: "dev".into() }.survives_a_move());
        assert!(!Request::Snapshot { name: "dev".into(), tag: "t".into() }.survives_a_move());
        assert!(!Request::Rename { name: "dev".into(), new_name: "e".into() }.survives_a_move());
    }

    /// A conflicted instance has to leave a way out, and looking before you
    /// rename is part of the way out.
    #[test]
    fn a_conflict_lets_exactly_the_commands_that_resolve_it_through() {
        assert!(Request::Rename { name: "d".into(), new_name: "e".into() }.survives_a_conflict());
        assert!(Request::Status { name: "d".into() }.survives_a_conflict());
        assert!(Request::Down { name: "d".into() }.survives_a_conflict());
        assert!(!Request::Up { name: "d".into(), restart: None }.survives_a_conflict());
        assert!(!Request::SshEndpoint { name: "d".into() }.survives_a_conflict());
        assert!(!Request::Remove { name: "d".into() }.survives_a_conflict());
    }

    /// `ast ls` and the shard query one daemon sends another are different
    /// questions, and stay different frames — the second is what the first is
    /// assembled from.
    #[test]
    fn the_orbit_view_and_a_single_shard_are_distinct_on_the_wire() {
        assert_eq!(serde_json::to_string(&Request::List).unwrap(), r#"{"cmd":"list"}"#);
        assert_eq!(
            serde_json::to_string(&Request::ListOrbit).unwrap(),
            r#"{"cmd":"list_orbit"}"#
        );
    }

    #[test]
    fn an_old_daemons_parse_error_is_classified() {
        // Verbatim shape of what astd wraps a serde failure in.
        assert!(is_unknown_variant_error(
            "bad request: unknown variant `snapshot_restore`, expected one of `ping`, `create`"
        ));
        assert!(!is_unknown_variant_error("no instance named \"dev\""));
    }
}
