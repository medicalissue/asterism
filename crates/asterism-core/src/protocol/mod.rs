//! The CLI <-> daemon wire, and the daemon <-> daemon wire, which are the
//! same wire.
//!
//! Two serde enums and nothing else: that is the whole protocol. Because they
//! are internally tagged (`{"cmd":"up",...}`), a variant's *name* is the wire
//! and its position in the enum is not — so frames may be reordered and
//! regrouped freely, and only a rename or a field change is a break.
//!
//! This module is a directory rather than a file because the two enums are
//! the one thing every feature branch has to edit. The variants are banded
//! into the same areas the CLI and the daemon are split along, so two branches
//! adding two commands to two different areas edit two different bands and
//! merge cleanly; the payload structs that hang off a band live in that
//! band's own file ([`swap`], [`wake`]), where they take their tests with
//! them.

use serde::{Deserialize, Serialize};

use crate::backup::{ExportReport, RestoreReport};
use crate::device_shell::{
    ShellData, ShellExit, ShellOpen, ShellOutput, ShellPolicyAction, ShellPolicyStatus,
};
use crate::remote_gpu_guest::{GuestFrame, GuestReply};
use crate::hv::GuestHealth;
use crate::image::{ImagePullResult, ImageRow};
use crate::instance::{Instance, PortForward, Restart, Shape};
use crate::orbit::{Device, DeviceStatus, WakeFacts};
use crate::registry::OrbitRow;
use crate::secret::Secret;
use crate::snapshot::Snapshot;

mod egress;
mod swap;
mod wake;

pub use egress::{EgressRequest, EgressResponse, MESH_FRAME_LIMIT};
pub use swap::{BaseImage, MoveFile, MoveManifest};
pub use wake::{CheckRow, Verdict};

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
    // ---- the handshake -------------------------------------------------------
    /// What version of this wire the caller speaks, asked of whoever is
    /// listening — and, in the answer, told.
    ///
    /// The two fields are `#[serde(default)]` and were added after the
    /// variant, so a build that predates them sends `{"cmd":"ping"}` and a
    /// build that predates them *reads* a frame carrying them as the same
    /// bare `Ping` it always did. That is what makes the negotiation itself
    /// backward compatible: the first frame of the conversation is one both
    /// vintages can already read.
    ///
    /// Zero in either position is the absence of the field rather than a
    /// version — see [`compat::Speaks::claimed`].
    ///
    /// [`compat::Speaks::claimed`]: crate::compat::Speaks::claimed
    Ping {
        /// The newest version the caller speaks.
        #[serde(default)]
        protocol: u32,
        /// The oldest it still serves.
        #[serde(default)]
        min_protocol: u32,
    },
    /// What this build speaks, what the daemon speaks, and what they have
    /// settled on: `ast compat`.
    ///
    /// Introduced at protocol 2, and so the one frame in this enum that a
    /// daemon at protocol 1 is not sent. It is also the frame that says so —
    /// which is deliberate, because a build whose only version-aware command
    /// is the one that cannot run against an old peer would be a poor
    /// advertisement for negotiating at all. `ast compat` answers from this
    /// build's own table when the daemon cannot contribute, and says which
    /// half of the answer is missing.
    Compat,

    // ---- instances -----------------------------------------------------------
    //
    // Everything a device answers out of its own shard of the orbit registry.
    // Served by `astd`'s `instance` module.
    Create {
        name: String,
        image: String,
        shape: Shape,
        /// Hypervisor to define the instance against, recorded on it and
        /// used for every later boot. `None` probes VZ first and then QEMU,
        /// choosing the first runnable backend capable of this request. It is
        /// also what every `ast create` before `--backend` existed sent, so
        /// an older CLI's frame still parses.
        #[serde(default)]
        backend: Option<String>,
        /// Guest ports to publish on the loopback of the device supplying
        /// cpu/ram (`ast create -p 8080:80`). Empty from a CLI that predates
        /// them, which is every `ast create` of a cloud image.
        #[serde(default)]
        publish: Vec<PortForward>,
        /// Bootstrap profiles to apply at first boot (`ast create --profile
        /// claude`). Empty from a CLI that predates them, and empty from
        /// every `ast create` that did not ask for one.
        #[serde(default)]
        profiles: Vec<String>,
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
    Down {
        name: String,
    },
    /// Change which bootstrap profiles an instance has (`ast profile dev
    /// claude`). Recorded now, applied by the next boot: the seed is what
    /// carries them, and a seed reaches a guest when that guest starts.
    SetProfiles {
        name: String,
        profiles: Vec<String>,
    },
    Remove {
        name: String,
    },
    /// One device's shard of the orbit registry — the instances whose cpu/ram
    /// it supplies. What one daemon asks another for while assembling
    /// [`Request::ListOrbit`], and what `ast ls --local` prints.
    List,
    /// The whole orbit registry, assembled: every shard the daemon can reach,
    /// plus the last-seen rows of the devices it cannot. This is `ast ls`.
    ListOrbit,
    Status {
        name: String,
    },
    /// Give an instance a different name. The only command a conflicted
    /// instance answers, because it is the only one that ends the conflict.
    Rename {
        name: String,
        new_name: String,
    },
    /// Tell the device holding `name` that the orbit has another instance of
    /// that name on it. Sent daemon-to-daemon when an assembled view finds a
    /// collision a partition had hidden; see `Shard::mark_conflicted` for the
    /// rule that decides which of the two is told.
    MarkConflicted {
        name: String,
        other_cpu_device: String,
    },
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
    /// Bind an orbit secret to one authority an instance may reach.
    ///
    /// A separate frame from [`Request::AttachVolume`] and not a flag on it,
    /// for the same reason [`Request::AttachBlock`] is: a daemon too old to
    /// carry egress must refuse this by name rather than record something
    /// else. Nothing here is or becomes material — the daemon answers with
    /// the instance, and the instance holds a policy and an opaque handle.
    AttachSecret {
        name: String,
        /// The secret's orbit name, as `ast secret ls` prints it.
        secret: String,
        /// The one authority this secret may be used against: `host`, or
        /// `host:port`.
        authority: String,
        /// Where the credential rides on a request. `None` takes the bound
        /// authority's own convention.
        #[serde(default)]
        placement: Option<crate::secret::Placement>,
        /// The environment variable the guest finds its handle in. `None`
        /// takes the secret's name, shouted.
        #[serde(default)]
        env: Option<String>,
        /// Which source device resolves the value. `None` picks one the
        /// secret says holds its current version.
        #[serde(default)]
        source_device: Option<String>,
    },
    /// Revoke a binding: the row goes, the handle stops being honoured, and
    /// the seed that told the guest about it is reissued without it.
    DetachSecret {
        name: String,
        secret: String,
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

    // ---- portable backups ---------------------------------------------------
    /// Export a stopped instance on the device holding its durable bytes.
    BackupExport {
        name: String,
        /// Directory on that device. The CLI canonicalises local paths before
        /// sending so a daemon's working directory never changes the target.
        destination: String,
    },
    /// Restore a verified backup onto this device and claim `name` across the
    /// orbit before publishing any bytes.
    BackupImport {
        source: String,
        name: String,
    },

    // ---- snapshots -----------------------------------------------------------
    //
    // A snapshot lives in the instance's disk rather than in the registry, so
    // these are answered without the shard ever being written.
    Snapshot {
        name: String,
        tag: String,
    },
    SnapshotList {
        name: String,
    },
    SnapshotRestore {
        name: String,
        tag: String,
    },
    /// Delete one snapshot. Additive: a daemon too old to know this frame
    /// refuses it by name rather than doing something else with it.
    SnapshotRemove {
        name: String,
        tag: String,
    },

    // ---- the console, and the way in -----------------------------------------
    /// The last `lines` lines of an instance's guest console.
    ///
    /// A daemon-side read, so it works when the console log is on another
    /// device's disk. `ast logs -f` still tails the file directly, which is
    /// why following is only offered where the file is.
    Logs {
        name: String,
        lines: u32,
    },
    /// Where to point `ssh` at to reach this instance's guest.
    ///
    /// Answered with a loopback address every time. When the guest's cpu/ram
    /// are on this device that is the hypervisor's own forwarded port; when
    /// they are elsewhere the daemon binds an ephemeral listener and splices
    /// it to the far daemon over the mesh, so `ast ssh dev` is one command
    /// from anywhere and never mentions a device.
    SshEndpoint {
        name: String,
    },
    /// Open the user shell offered by one device. Unlike guest SSH this is a
    /// framed conversation on the existing unix socket and mesh stream; it
    /// never creates a TCP listener or invokes sshd.
    DeviceShellOpen {
        device: String,
        open: ShellOpen,
    },
    /// Frames sent after [`Request::DeviceShellOpen`] on the same local
    /// connection. They are invalid as standalone RPC requests.
    DeviceShellInput {
        data: ShellData,
    },
    DeviceShellEof,
    DeviceShellResize {
        cols: u16,
        rows: u16,
    },
    DeviceShellSignal {
        signal: i32,
    },
    DeviceShellClose,
    /// Open the guest NVIDIA projection for one instance. The hypervisor
    /// helper (or a source fixture) carries framed CUDA-semantic calls from
    /// the projected `/dev/nvidia0` onto this unix socket. It is
    /// instance-bound and never a LAN listener.
    GpuGuestOpen {
        name: String,
    },
    /// Frames sent after [`Request::GpuGuestOpen`] on the same local
    /// connection. Invalid as standalone RPC.
    GpuGuestFrame {
        frame: GuestFrame,
    },
    GpuGuestClose,

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
    Proxy {
        device: String,
        inner: Box<Request>,
    },
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
    PairConfirm {
        accept: bool,
    },
    /// Drop a device from this orbit. Its key stops being trusted at once.
    DeviceRemove {
        name: String,
    },
    /// Read this device's shell offer. Unlike policy mutation, this is safe
    /// over authenticated mesh RPC and is the read contract used by remote
    /// and hosted management surfaces.
    DeviceShellStatus,
    /// Change this device's shell offer. The daemon accepts this only from
    /// its private local control socket; a mesh RPC is explicitly refused
    /// even though the enum remains parseable across versions. `Status` is
    /// retained for protocol-4 clients, but new readers use
    /// [`Request::DeviceShellStatus`].
    DeviceShellPolicy {
        action: ShellPolicyAction,
    },
    /// Round-trip a mesh stream to one device and time it.
    DevicePing {
        device: String,
    },

    // ---- power and presence -------------------------------------------------
    /// Wake a sleeping device: `ast device wake <name>`.
    ///
    /// Answered with more than one line, because it is a job rather than a
    /// question — who is going to send the packet, that it was sent, and then
    /// whether the device turned up — each a [`Response::Wake`] as it
    /// happens, ending in one that is `done`.
    DeviceWake {
        name: String,
    },
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
    /// This device's CUDA GPU helper. Token-free: availability, UUID,
    /// generation and whether a live NVIDIA driver executed work. A CPU
    /// reference executor is never reported as a production helper.
    GpuProviderStatus,

    // ---- device-local images -----------------------------------------------
    /// Read this device's structured cloud/OCI image catalog.
    ImageList,
    /// Pull an image into this device's store. The daemon owns the network,
    /// credentials, integrity checks, and atomic adoption.
    ImagePull {
        reference: String,
    },

    // ---- block volumes ------------------------------------------------------
    //
    // Volumes are a *device's* part of the pool, not an instance's, so none of
    // these resolves through the instance namespace. They are answered by the
    // device that holds the bytes — reached by name, either because the user
    // typed `--device`, or because a consumer's daemon put the frame in a
    // [`Request::Proxy`] envelope aimed at the device an attach named.
    /// Make a new block volume on this device: a sparse raw image and the
    /// bookkeeping that goes with it.
    VolumeCreate {
        name: String,
        size_bytes: u64,
    },
    /// This device's block volumes, with their sizes and leases.
    VolumeList,
    /// Delete a block volume and its bytes. Refused while it is leased.
    VolumeRemove {
        name: String,
    },
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
    VolumeReconnect {
        volume: String,
        holder: String,
        epoch: u64,
    },
    /// Hand the lease back and stop the export.
    VolumeRelease {
        volume: String,
        holder: String,
    },

    // ---- secrets ------------------------------------------------------------
    // Public operations are orbit-scoped. `secret_source_*` are the narrow
    // daemon-to-daemon boundary: they run only on the device whose Keychain
    // holds the bytes and are routable over the existing authenticated mesh.
    SecretCreate {
        name: String,
        value: SecretValue,
        #[serde(default)]
        source_device: Option<String>,
    },
    SecretList,
    SecretRemove {
        name: String,
    },
    SecretRotate {
        name: String,
        value: SecretValue,
    },
    SecretSourceList,
    /// Replicate metadata only. This frame can never carry material.
    SecretSourceSync {
        secret: Secret,
    },
    SecretSourcePut {
        secret: Secret,
        value: SecretValue,
    },
    SecretSourceRemove {
        id: crate::secret::SecretId,
    },
    /// Make one outbound request on a guest's behalf, from the device whose
    /// store holds the value.
    ///
    /// The narrowest frame in the protocol and the only one that causes a
    /// daemon to talk to the internet. It arrives with the credential header
    /// blanked; the source resolves `handle`, fills the blank, opens the
    /// connection and answers with what came back. Plaintext exists on this
    /// device, inside this call, and nowhere else — not in the reply, not in
    /// the caller, not on disk.
    ///
    /// `handle` is version- *and* revision-pinned, so a rotation that landed
    /// between the caller selecting it and this frame arriving is refused
    /// here rather than redeemed against whatever bytes the store now holds.
    SecretSourceEgress {
        /// The value to redeem, version- and revision-pinned. `None` is a
        /// request to a bound authority that carried no credential: the
        /// source device still makes the call — so that one instance's
        /// traffic to one API always leaves from one address — but resolves
        /// nothing and fills nothing.
        handle: Option<crate::secret::Handle>,
        request: Box<EgressRequest>,
    },
    SecretSourceRotate {
        id: crate::secret::SecretId,
        version: u64,
        updated_at: u64,
        /// The revision the orbit minted for this rotation, the same one for
        /// every source.  It is required rather than defaulted: a rotation
        /// that left a source's value commitment untouched while advancing
        /// its version is exactly the ambiguity the commitment exists to
        /// prevent, so an older peer's frame must fail to parse, not be
        /// silently accepted.
        revision: crate::secret::ValueRevision,
        value: SecretValue,
    },

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
    MoveOffer {
        name: String,
    },
    /// Ask a device whether it could take this instance: same architecture,
    /// a backend it can actually run, an image reference that means
    /// something here. Read-only.
    MoveProbe {
        manifest: Box<MoveManifest>,
    },
    /// Fence an instance for a move: mark it `moving`, refuse `up`, and
    /// answer with the manifest as it stands now.
    ///
    /// From here until a commit or an abort, this device holds the only
    /// bootable copy and will not boot it.
    MovePrepare {
        name: String,
        to_device: String,
        epoch: u64,
    },
    /// The bytes are all here and verified: adopt them. The staging
    /// directory becomes the instance directory and the row is written with
    /// this device supplying cpu, at `epoch`.
    MoveCommitTarget {
        manifest: Box<MoveManifest>,
        epoch: u64,
    },
    /// The target has acked: drop the row and the bytes.
    MoveCommitSource {
        name: String,
        epoch: u64,
    },
    /// The move did not happen. Clear the fence; this row stays
    /// authoritative.
    MoveAbortSource {
        name: String,
        epoch: u64,
    },
    /// The move did not happen. Delete the staging directory, which is the
    /// only place the half-transferred bytes ever were.
    MoveAbortTarget {
        name: String,
        epoch: u64,
    },
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
    ///
    /// The `None` half is banded by area rather than written as one
    /// or-pattern, so that adding a device command and adding a volume
    /// command are edits to two different places. It stays exhaustive on
    /// purpose: this match is the compiler's one chance to stop a new
    /// instance command from silently only ever working on the device it was
    /// typed on.
    pub fn subject(&self) -> Option<&str> {
        match self {
            Request::Up { name, .. }
            | Request::Down { name }
            | Request::Remove { name }
            | Request::Status { name }
            | Request::SetProfiles { name, .. }
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
            | Request::GpuGuestOpen { name }
            // Binding a secret is an instance command: `ast attach dev
            // --secret anthropic` resolves `dev` across the orbit like every
            // other, and the binding is written on whichever device holds it.
            | Request::AttachSecret { name, .. }
            | Request::DetachSecret { name, .. }
            | Request::BackupExport { name, .. }
            | Request::SshEndpoint { name } => Some(name),

            // The handshake, and the two views of the registry. A list is
            // about every instance, which is not one instance.
            Request::Ping { .. }
            | Request::Compat
            | Request::Create { .. }
            | Request::BackupImport { .. }
            | Request::List
            | Request::ListOrbit => None,

            // About the orbit and the devices in it.
            Request::Proxy { .. }
            | Request::Devices
            | Request::DeviceInvite { .. }
            | Request::DeviceAdd { .. }
            | Request::PairConfirm { .. }
            | Request::DeviceRemove { .. }
            | Request::DevicePing { .. }
            | Request::DeviceShellStatus
            | Request::DeviceShellPolicy { .. }
            | Request::DeviceShellOpen { .. }
            | Request::DeviceShellInput { .. }
            | Request::DeviceShellEof
            | Request::DeviceShellResize { .. }
            | Request::DeviceShellSignal { .. }
            | Request::DeviceShellClose
            | Request::GpuGuestFrame { .. }
            | Request::GpuGuestClose => None,

            // About devices, not instances. `ast device wake desktop` names a
            // device on purpose — it is the one command whose subject really
            // is a machine — so it must never be routed as if `desktop` were
            // an instance somebody else holds.
            Request::DeviceWake { .. }
            | Request::WakeBroadcast { .. }
            | Request::DeviceFacts
            | Request::DeviceCheck
            | Request::GpuProviderStatus
            | Request::ImageList
            | Request::ImagePull { .. } => None,

            // A volume belongs to a device, not to an instance, and volume
            // names are not orbit-global — two devices may each have a
            // `tank`. Resolving one through the instance namespace would send
            // it to whoever happens to hold an instance of that name.
            Request::VolumeCreate { .. }
            | Request::VolumeList
            | Request::VolumeRemove { .. }
            | Request::VolumeLease { .. }
            | Request::VolumeReconnect { .. }
            | Request::VolumeRelease { .. } => None,

            // Secret names are orbit-scoped, but not instance names. Public
            // operations are routed by the secret plane; source operations
            // are explicitly aimed at one source device over the mesh.
            Request::SecretCreate { .. }
            | Request::SecretList
            | Request::SecretRemove { .. }
            | Request::SecretRotate { .. }
            | Request::SecretSourceList
            | Request::SecretSourceSync { .. }
            | Request::SecretSourcePut { .. }
            | Request::SecretSourceRemove { .. }
            | Request::SecretSourceRotate { .. }
            | Request::SecretSourceEgress { .. } => None,

            // Every step of a cpu-part swap names one device on purpose and
            // is aimed at it. Half of them go to a device that does *not*
            // hold the row — that is what a move is — so resolving them by
            // instance name would send them back to the wrong end of the
            // transfer, and `set cpu` itself names the destination.
            Request::SetCpu { .. }
            | Request::MoveOffer { .. }
            | Request::MoveProbe { .. }
            | Request::MovePrepare { .. }
            | Request::MoveCommitTarget { .. }
            | Request::MoveCommitSource { .. }
            | Request::MoveAbortSource { .. }
            | Request::MoveAbortTarget { .. } => None,
        }
    }

    /// The protocol version that introduced this frame.
    ///
    /// What a selected version *means*: every frame at or below it may be
    /// sent, and no frame above it may be. Both ends check this, so a command
    /// the other half cannot serve is refused by name — see
    /// [`compat::frame_too_new`] — rather than arriving as serde's "unknown
    /// variant" and being reported as a bad request the user did not make.
    ///
    /// The default arm is [`compat::FIRST_PROTOCOL`] and is the honest one:
    /// every frame here except the ones listed above it shipped before the
    /// wire had a number, so they are all as old as the wire itself. A frame
    /// added from now on gets an arm here in the same commit that bumps
    /// [`compat::PROTOCOL_VERSION`], and [`versioned_frames`] is where it is
    /// named for `ast compat` and the e2e.
    ///
    /// [`compat::frame_too_new`]: crate::compat::frame_too_new
    /// [`compat::FIRST_PROTOCOL`]: crate::compat::FIRST_PROTOCOL
    /// [`compat::PROTOCOL_VERSION`]: crate::compat::PROTOCOL_VERSION
    pub fn since(&self) -> u32 {
        match self {
            // A proxy is only an address on an otherwise unchanged request.
            // The receiving daemon must parse the enclosed frame, so the
            // envelope cannot be spoken at an earlier protocol than it.
            Request::Proxy { inner, .. } => inner.since(),
            Request::Compat => 2,
            Request::BackupExport { .. } | Request::BackupImport { .. } => 3,
            Request::DeviceShellStatus => 5,
            Request::ImageList | Request::ImagePull { .. } => 6,
            Request::GpuGuestOpen { .. }
            | Request::GpuGuestFrame { .. }
            | Request::GpuGuestClose
            | Request::GpuProviderStatus => 8,
            Request::DeviceShellPolicy { .. }
            | Request::DeviceShellOpen { .. }
            | Request::DeviceShellInput { .. }
            | Request::DeviceShellEof
            | Request::DeviceShellResize { .. }
            | Request::DeviceShellSignal { .. }
            | Request::DeviceShellClose => 4,
            _ => crate::compat::FIRST_PROTOCOL,
        }
    }

    /// What this frame is called on the wire, for the frames whose age is
    /// worth naming.
    ///
    /// Only the versioned ones, because only they are ever refused for their
    /// version, and a refusal that cannot say which command it is about is
    /// half a sentence. Everything else answers `None` and is never in that
    /// position.
    pub fn versioned_name(&self) -> Option<&'static str> {
        match self {
            // Name the frame the user asked for, rather than its transparent
            // routing envelope, in a compatibility refusal.
            Request::Proxy { inner, .. } => inner.versioned_name(),
            Request::Compat => Some("compat"),
            Request::BackupExport { .. } => Some("backup_export"),
            Request::BackupImport { .. } => Some("backup_import"),
            Request::DeviceShellStatus => Some("device_shell_status"),
            Request::DeviceShellPolicy { .. }
            | Request::DeviceShellOpen { .. }
            | Request::DeviceShellInput { .. }
            | Request::DeviceShellEof
            | Request::DeviceShellResize { .. }
            | Request::DeviceShellSignal { .. }
            | Request::DeviceShellClose => Some("device shell"),
            Request::ImageList => Some("image_list"),
            Request::ImagePull { .. } => Some("image_pull"),
            Request::GpuGuestOpen { .. }
            | Request::GpuGuestFrame { .. }
            | Request::GpuGuestClose => Some("gpu_guest"),
            Request::GpuProviderStatus => Some("gpu_provider_status"),
            _ => None,
        }
    }

    /// Whether this frame may be sent to a peer speaking `spoken`.
    pub fn speakable_at(&self, spoken: u32) -> bool {
        self.since() <= spoken
    }

    /// Whether an instance in conflict will answer this request.
    ///
    /// `rename` is the remedy, so it must go through. `status`, `logs`, and
    /// `down` go through because refusing them would be a trap: `rename` will
    /// not touch a running guest, so an instance that is both conflicted and
    /// running would have no legal move at all, and a user told to rename
    /// something deserves to be able to inspect its state and diagnostic
    /// console output first.
    pub fn survives_a_conflict(&self) -> bool {
        matches!(
            self,
            Request::Rename { .. }
                | Request::Status { .. }
                | Request::Logs { .. }
                | Request::Down { .. }
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
    /// Reply to [`Request::Ping`]: the daemon's crate/build identity and the
    /// range of wire versions it speaks.
    ///
    /// A daemon older than this variant answers `Ping` with plain `Ok`, so
    /// the *absence* of a version is itself a signal. One older than the
    /// range answers with `version` and no `protocol`, and that absence is a
    /// signal too — but a precise one: it is
    /// [`compat::FIRST_PROTOCOL`](crate::compat::FIRST_PROTOCOL), the wire as
    /// it stood before it had a number, and this build serves it. That is why
    /// meeting one is an ordinary conversation rather than a restart.
    Pong {
        version: String,
        /// Immutable build identity. Absent from a daemon that predates it;
        /// it is diagnostic evidence, not a compatibility signal.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        build_id: Option<String>,
        /// The newest wire the daemon speaks. Absent from a daemon that
        /// predates the number.
        #[serde(default)]
        protocol: u32,
        /// The oldest it still serves.
        #[serde(default)]
        min_protocol: u32,
    },
    /// Reply to [`Request::Compat`]: what the daemon speaks, and its own copy
    /// of the skew matrix.
    ///
    /// Boxed because it is a table and the rest of this enum is a sentence:
    /// unboxed it would set the size of every reply the daemon ever writes.
    Compat {
        compat: Box<crate::compat::Compat>,
    },

    // ---- instances -----------------------------------------------------------
    Instance {
        instance: Instance,
        /// The guest's own health snapshot, populated for `Status` by a
        /// backend that has an authenticated guest-agent channel. It is not
        /// persisted in the registry: every status request asks again.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        guest_health: Option<Box<GuestHealth>>,
    },
    /// Reply to [`Request::List`]: one device's shard.
    Instances {
        instances: Vec<Instance>,
    },
    /// Reply to [`Request::ImageList`]. These rows are from the answering
    /// device, even when the request arrived through `Proxy`.
    Images {
        images: Vec<ImageRow>,
    },
    /// Reply to [`Request::ImagePull`] after durable adoption. A failed pull
    /// is always [`Response::Error`].
    ImagePulled {
        #[serde(rename = "image")]
        result: Box<ImagePullResult>,
    },
    /// Reply to [`Request::ListOrbit`]: the orbit registry, assembled from
    /// every shard that answered plus the cached rows of those that did not.
    Orbit {
        rows: Vec<OrbitRow>,
    },

    // ---- portable backups ---------------------------------------------------
    BackupExported {
        report: ExportReport,
    },
    BackupRestored {
        report: RestoreReport,
    },

    // ---- snapshots -----------------------------------------------------------
    Snapshots {
        snapshots: Vec<Snapshot>,
    },

    // ---- the console, and the way in -----------------------------------------
    /// Reply to [`Request::Logs`]. `truncated` says whether older lines were
    /// left behind, so the CLI can offer `--lines` rather than imply the
    /// guest has been quiet.
    Log {
        text: String,
        truncated: bool,
    },
    /// Reply to [`Request::SshEndpoint`]: a loopback address `ssh` can be
    /// pointed at right now, and the key file that opens the guest. Whose cpu
    /// is running the guest changes neither field's meaning, which is the
    /// point — both are paths and ports on the machine `ast` is running on.
    SshEndpoint {
        host: String,
        port: u16,
        identity: String,
    },
    /// Read model for `ast device shell status`.
    DeviceShellStatus {
        status: ShellPolicyStatus,
        #[serde(default)]
        revoked: usize,
    },
    /// The first successful reply to [`Request::DeviceShellOpen`].
    DeviceShellAccepted {
        session_id: String,
    },
    /// A policy/protocol/capacity refusal with a stable code for clients.
    DeviceShellRefused {
        code: String,
        message: String,
    },
    /// One bounded output frame. PTY output is merged; non-PTY output keeps
    /// stdout and stderr distinct.
    DeviceShellOutput {
        stream: ShellOutput,
        data: ShellData,
    },
    /// Exactly one terminal result for an accepted session.
    DeviceShellExit {
        exit: ShellExit,
    },
    GpuGuestAccepted {
        session_id: String,
        projection_kind: String,
    },
    GpuGuestRefused {
        code: String,
        message: String,
    },
    GpuGuestReply {
        reply: GuestReply,
    },

    // ---- the mesh ----------------------------------------------------------
    /// Reply to [`Request::Devices`].
    Devices {
        devices: Vec<DeviceStatus>,
    },
    /// The pasteable ticket minted by [`Request::DeviceInvite`], and how long
    /// it stays good for.
    Ticket {
        ticket: String,
        expires_in_secs: u64,
    },
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
    Paired {
        device: Device,
    },
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
    WakeFacts {
        facts: WakeFacts,
    },
    /// Reply to [`Request::DeviceCheck`]: `ast device check`, as a table.
    WakeCheck {
        device: String,
        rows: Vec<CheckRow>,
    },
    /// Reply to [`Request::GpuProviderStatus`]. Token-free.
    GpuProvider {
        available: bool,
        executor: String,
        gpu_uuid: String,
        generation: u64,
        hardware_cuda_executed: bool,
        helper_socket: String,
    },

    // ---- block volumes ------------------------------------------------------
    /// Reply to [`Request::VolumeList`], [`Request::VolumeCreate`] and
    /// [`Request::VolumeRemove`]: whatever the device now has to say about
    /// the volumes in question.
    Volumes {
        volumes: Vec<crate::volume::BlockVolume>,
    },
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

    // ---- secrets ------------------------------------------------------------
    Secrets {
        secrets: Vec<Secret>,
    },
    /// Reply to [`Request::SecretSourceEgress`]: what the upstream said.
    ///
    /// Boxed because it carries a buffered body and every other variant here
    /// is a handful of words; without it every response frame in the daemon
    /// would be sized for this one.
    Egress {
        response: Box<EgressResponse>,
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
    MoveOffer {
        manifest: Box<MoveManifest>,
    },
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

    Error {
        message: String,
    },
}

/// Bytes in flight to or from a platform secret store.
///
/// Debug output is always redacted, and serde represents the material as a
/// byte array instead of embedding plaintext in a JSON string. Persistent
/// metadata types never contain this wrapper at all.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SecretValue(Vec<u8>);

impl SecretValue {
    pub fn new(value: Vec<u8>) -> Self {
        Self(value)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Take the bytes, leaving this wrapper empty.
    ///
    /// The caller owns them from here, and owns wiping them too — which is
    /// why the one caller that does this ([`crate::rewrite::fill`]'s, on the
    /// source device) puts them straight into a `Zeroizing`.
    pub fn into_bytes(mut self) -> Vec<u8> {
        std::mem::take(&mut self.0)
    }
}

/// Wipe material when the wrapper goes.
///
/// Honestly, not completely: a `Vec` that grew has left copies behind at its
/// old addresses, and nothing in safe Rust can reach those. What this does buy
/// is that the buffer a value was *read into* does not sit in the daemon's
/// heap until the allocator happens to reuse it, which is the difference
/// between a core dump taken an hour later holding an API key and not.
impl Drop for SecretValue {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.0.zeroize();
    }
}

impl std::fmt::Debug for SecretValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<redacted>")
    }
}

impl Response {
    /// The protocol version that introduced this frame. The mirror of
    /// [`Request::since`], and checked in the same places: a daemon must not
    /// answer at a version above the one in force, or the reply is a parse
    /// error on a command that worked.
    pub fn since(&self) -> u32 {
        match self {
            Response::Compat { .. } => 2,
            Response::BackupExported { .. } | Response::BackupRestored { .. } => 3,
            Response::Images { .. } | Response::ImagePulled { .. } => 6,
            Response::GpuProvider { .. } => 8,
            Response::DeviceShellStatus { .. }
            | Response::DeviceShellAccepted { .. }
            | Response::DeviceShellRefused { .. }
            | Response::DeviceShellOutput { .. }
            | Response::DeviceShellExit { .. } => 4,
            Response::GpuGuestAccepted { .. }
            | Response::GpuGuestRefused { .. }
            | Response::GpuGuestReply { .. } => 8,
            _ => crate::compat::FIRST_PROTOCOL,
        }
    }

    /// Whether this reply may be sent to a peer speaking `spoken`.
    pub fn speakable_at(&self, spoken: u32) -> bool {
        self.since() <= spoken
    }
}

/// Every frame newer than the wire itself, and the version that brought it.
///
/// Printed by `ast compat` and walked by `scripts/e2e-skew.sh`, so the frames
/// a given version may carry are data rather than a paragraph. A frame here
/// and a frame in [`Request::since`] that disagree is a test failure, not a
/// discovery made on a socket.
pub fn versioned_frames() -> std::collections::BTreeMap<String, u32> {
    [
        ("compat", Request::Compat.since()),
        (
            "backup_export",
            Request::BackupExport {
                name: String::new(),
                destination: String::new(),
            }
            .since(),
        ),
        (
            "backup_import",
            Request::BackupImport {
                source: String::new(),
                name: String::new(),
            }
            .since(),
        ),
        (
            "device-shell",
            Request::DeviceShellPolicy {
                action: ShellPolicyAction::Status,
            }
            .since(),
        ),
        ("device_shell_status", Request::DeviceShellStatus.since()),
        ("gpu_guest", Request::GpuGuestOpen { name: String::new() }.since()),
        ("image_list", Request::ImageList.since()),
        (
            "image_pull",
            Request::ImagePull {
                reference: String::new(),
            }
            .since(),
        ),
        ("gpu_provider_status", Request::GpuProviderStatus.since()),
    ]
    .into_iter()
    .map(|(name, version)| (name.to_owned(), version))
    .collect()
}

/// How a daemon that is too old to understand us gives itself away: serde
/// rejects the request variant it has never heard of, and the daemon dutifully
/// reports the parse error. Matching on the text is unlovely, but it is the
/// only signal an old binary can send — and it is stable, because it is
/// serde's own wording for an unknown enum variant.
///
/// With a negotiated version in force this is a fallback rather than the
/// mechanism: `ast` knows before it sends a frame whether the daemon has it,
/// so the only way to land here is a daemon that was replaced between the
/// handshake and the command. It stays because that race is real.
pub fn is_unknown_variant_error(message: &str) -> bool {
    message.contains("unknown variant")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_instance_reply_carries_optional_fresh_guest_health() {
        let response = Response::Instance {
            instance: Instance::new(
                "dev",
                "desktop",
                "debian:13",
                Shape::default(),
                crate::hv::Machine {
                    backend: "vz".into(),
                    machine_type: "generic".into(),
                    cpu: "host".into(),
                    hv_version: "15.6".into(),
                },
            ),
            guest_health: Some(Box::new(GuestHealth {
                addrs: vec!["192.168.64.7".parse().unwrap()],
                uptime_secs: 125.9,
                ssh: true,
                cloud_init: "done".into(),
                load1: Some(0.42),
                mem_available_kib: Some(1_572_864),
            })),
        };
        let wire = serde_json::to_string(&response).unwrap();
        assert!(wire.contains("guest_health"), "{wire}");
        let Response::Instance {
            guest_health: Some(health),
            ..
        } = serde_json::from_str::<Response>(&wire).unwrap()
        else {
            panic!("the health sample survived the response wire")
        };
        assert_eq!(health.cloud_init, "done");
        assert_eq!(health.mem_available_kib, Some(1_572_864));
    }

    #[test]
    fn a_pre_pong_daemon_is_recognisable() {
        // What an older astd sends back for Ping.
        let old: Response = serde_json::from_str(r#"{"result":"ok"}"#).unwrap();
        assert!(matches!(old, Response::Ok));
        // What this one sends.
        let new: Response = serde_json::from_str(r#"{"result":"pong","version":"0.0.2"}"#).unwrap();
        assert!(matches!(&new, Response::Pong { version, .. } if version == "0.0.2"));
        // ...and it said nothing about its build, which is not the same as
        // having none.
        assert!(matches!(new, Response::Pong { build_id: None, .. }));

        // A daemon new enough to say carries both.
        let both: Response = serde_json::from_str(
            r#"{"result":"pong","version":"0.0.2","build_id":"0.0.2+abc123"}"#,
        )
        .unwrap();
        assert!(matches!(both, Response::Pong { build_id: Some(id), .. } if id == "0.0.2+abc123"));

        let new: Response =
            serde_json::from_str(r#"{"result":"pong","version":"0.0.2","protocol":2}"#).unwrap();
        assert!(matches!(new, Response::Pong { version, protocol, .. }
            if version == "0.0.2" && protocol == 2));
    }

    /// The handshake had to be readable by the builds it is meant to
    /// negotiate with, or the first frame of every conversation would be the
    /// one that broke it. Both directions, against the shapes that actually
    /// exist on disk today.
    #[test]
    fn the_handshake_crosses_the_release_that_introduced_it() {
        // A daemon that predates the range answers with a version and no
        // numbers. That is not an unknown quantity — it is the wire this
        // build grew out of, and `Speaks::claimed` says so.
        let pong: Response =
            serde_json::from_str(r#"{"result":"pong","version":"0.0.1"}"#).unwrap();
        let Response::Pong {
            protocol,
            min_protocol,
            ..
        } = pong
        else {
            panic!("a pong is a pong")
        };
        assert_eq!(
            crate::compat::Speaks::claimed(protocol, min_protocol),
            crate::compat::Speaks::unversioned()
        );

        // And a `Ping` carrying the range is still the bare `Ping` an older
        // daemon reads, because the fields hang off a variant it already
        // parses as a map.
        let wire = serde_json::to_string(&Request::Ping {
            protocol: 2,
            min_protocol: 1,
        })
        .unwrap();
        assert_eq!(wire, r#"{"cmd":"ping","protocol":2,"min_protocol":1}"#);
        // A build with no fields on the variant sees the tag and ignores the
        // rest, which is what this stands in for.
        let back: Request = serde_json::from_str(r#"{"cmd":"ping"}"#).unwrap();
        assert!(matches!(
            back,
            Request::Ping {
                protocol: 0,
                min_protocol: 0
            }
        ));
    }

    #[test]
    fn a_frame_is_as_old_as_the_wire_unless_it_says_otherwise() {
        assert_eq!(Request::List.since(), crate::compat::FIRST_PROTOCOL);
        assert_eq!(
            Request::Ping {
                protocol: 0,
                min_protocol: 0
            }
            .since(),
            1
        );
        assert_eq!(Request::Compat.since(), 2);
        assert!(!Request::Compat.speakable_at(1));
        assert!(Request::Compat.speakable_at(2));
        assert!(Request::List.speakable_at(1));
        assert_eq!(Request::DeviceShellStatus.since(), 5);
        assert_eq!(
            serde_json::to_string(&Request::DeviceShellStatus).unwrap(),
            r#"{"cmd":"device_shell_status"}"#
        );
        assert_eq!(Request::ImageList.since(), 6);
        assert_eq!(
            serde_json::to_string(&Request::ImagePull {
                reference: "ubuntu:24.04".into(),
            })
            .unwrap(),
            r#"{"cmd":"image_pull","reference":"ubuntu:24.04"}"#
        );
    }

    #[test]
    fn a_proxy_inherits_its_inner_frames_protocol_floor_and_name() {
        let proxied_images = Request::Proxy {
            device: "nas".into(),
            inner: Box::new(Request::ImageList),
        };
        assert_eq!(proxied_images.since(), 6);
        assert_eq!(proxied_images.versioned_name(), Some("image_list"));
        assert!(!proxied_images.speakable_at(5));
        assert!(proxied_images.speakable_at(6));

        // Routing does not make an old request newer.
        let proxied_list = Request::Proxy {
            device: "nas".into(),
            inner: Box::new(Request::List),
        };
        assert_eq!(proxied_list.since(), crate::compat::FIRST_PROTOCOL);
        assert_eq!(proxied_list.versioned_name(), None);
        assert!(proxied_list.speakable_at(crate::compat::FIRST_PROTOCOL));
    }

    #[test]
    fn image_frames_are_structured_and_have_a_single_pull_success_reply() {
        let request = Request::ImagePull {
            reference: "ubuntu:24.04".into(),
        };
        let wire = serde_json::to_string(&request).unwrap();
        assert_eq!(wire, r#"{"cmd":"image_pull","reference":"ubuntu:24.04"}"#);
        let response = Response::ImagePulled {
            result: Box::new(ImagePullResult {
                reference: "ubuntu:24.04".into(),
                kind: crate::hv::ImageKind::Disk,
                bytes: 42,
                digest: Some("sha256:abc".into()),
                progress: vec![crate::image::ImageProgress {
                    phase: "stored".into(),
                    bytes: 42,
                    total_bytes: Some(42),
                    done: true,
                }],
                changed: true,
            }),
        };
        let wire = serde_json::to_string(&response).unwrap();
        assert_eq!(
            wire,
            r#"{"result":"image_pulled","image":{"reference":"ubuntu:24.04","kind":"disk","bytes":42,"digest":"sha256:abc","progress":[{"phase":"stored","bytes":42,"total_bytes":42,"done":true}],"changed":true}}"#
        );
        let decoded: Response = serde_json::from_str(&wire).unwrap();
        assert!(matches!(decoded, Response::ImagePulled { .. }));
        assert_eq!(response.since(), 6);
    }

    /// The table `ast compat` prints and the rule the code follows are the
    /// same rule, or the matrix the e2e walks is fiction.
    #[test]
    fn the_frame_table_and_the_frames_agree() {
        let table = versioned_frames();
        assert_eq!(table.get("compat"), Some(&Request::Compat.since()));
        assert_eq!(table.get("backup_export"), Some(&3));
        assert_eq!(table.get("backup_import"), Some(&3));
        assert_eq!(
            table.get("device-shell"),
            Some(&4),
            "a protocol-3 backup daemon cannot parse device-shell variants"
        );
        for (name, version) in &table {
            assert!(
                *version > crate::compat::FIRST_PROTOCOL,
                "{name} is listed as versioned but is as old as the wire"
            );
            assert!(
                *version <= crate::compat::PROTOCOL_VERSION,
                "{name} claims a version this build does not speak"
            );
        }
    }

    #[test]
    fn secret_material_is_redacted_and_not_encoded_as_a_plaintext_string() {
        let request = Request::SecretCreate {
            name: "api".into(),
            value: SecretValue::new(b"literal-sensitive-value".to_vec()),
            source_device: None,
        };
        assert!(!format!("{request:?}").contains("literal-sensitive-value"));
        let wire = serde_json::to_string(&request).unwrap();
        assert!(!wire.contains("literal-sensitive-value"));
        let decoded: Request = serde_json::from_str(&wire).unwrap();
        assert!(matches!(
            decoded,
            Request::SecretCreate { value, .. }
                if value.as_bytes() == b"literal-sensitive-value"
        ));
    }

    #[test]
    fn secret_source_operations_never_route_through_the_instance_namespace() {
        let id = crate::secret::SecretId::from_name("api").unwrap();
        let lineage = crate::secret::ValueRevision::mint();
        let source = crate::secret::SourceDevice {
            device_id: "source-public-key".into(),
            device: "desktop".into(),
            version: 3,
            updated_at: 3,
            origin: lineage.clone(),
            revision: lineage,
        };
        let secret = crate::secret::Secret {
            id,
            name: "api".into(),
            version: 3,
            created_at: 1,
            updated_at: 3,
            sources: vec![source.clone()],
        };
        assert!(Request::SecretSourceList.subject().is_none());
        let sync = Request::SecretSourceSync {
            secret: secret.clone(),
        };
        assert!(sync.subject().is_none());

        // The existing mesh proxy envelope preserves the source operation.
        // It does not consult an instance/cpu device or a global exit.
        let routed = Request::Proxy {
            device: source.device.clone(),
            inner: Box::new(sync),
        };
        let wire = serde_json::to_string(&routed).unwrap();
        let decoded: Request = serde_json::from_str(&wire).unwrap();
        assert!(matches!(
            decoded,
            Request::Proxy { device, inner }
                if device == "desktop"
                    && matches!(&*inner, Request::SecretSourceSync { secret }
                        if secret.sources[0].device_id == "source-public-key"
                            && secret.version == 3)
        ));
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
        assert!(matches!(
            attach,
            Request::AttachVolume {
                mount_point: None,
                ..
            }
        ));
        // A create from before backends could be chosen means "whatever
        // this device uses", not a parse error.
        let create: Request = serde_json::from_str(
            r#"{"cmd":"create","name":"dev","image":"debian:13",
                "shape":{"cpus":2,"mem_mib":2048,"disk_gib":20}}"#,
        )
        .unwrap();
        assert!(matches!(create, Request::Create { backend: None, .. }));
        let Request::Create {
            publish, profiles, ..
        } = &create
        else {
            unreachable!("a create")
        };
        assert!(publish.is_empty(), "a cloud image publishes nothing");
        // ...and nothing about bootstrap profiles, which is the instance
        // that CLI would have made: a stock image and nothing else.
        assert!(profiles.is_empty(), "an older create asks for no profiles");

        // ...and one from a CLI that has `-p` carries what it asked for.
        let published: Request = serde_json::from_str(
            r#"{"cmd":"create","name":"web","image":"nginx",
                "shape":{"cpus":2,"mem_mib":2048,"disk_gib":20},
                "publish":[{"host":8080,"guest":80}]}"#,
        )
        .unwrap();
        let Request::Create { publish, .. } = &published else {
            unreachable!("a create")
        };
        assert_eq!(
            publish,
            &[PortForward {
                host: 8080,
                guest: 80
            }]
        );
    }

    /// Banding the variants by area is a merge-conflict measure, and it is
    /// only free because the tag is the wire. If a regroup ever moved a frame
    /// off its tag this is what would say so.
    #[test]
    fn a_frames_tag_is_its_name_and_not_its_position() {
        assert_eq!(
            serde_json::to_string(&Request::Down { name: "dev".into() }).unwrap(),
            r#"{"cmd":"down","name":"dev"}"#
        );
        assert_eq!(
            serde_json::to_string(&Request::SnapshotRemove {
                name: "dev".into(),
                tag: "nightly".into()
            })
            .unwrap(),
            r#"{"cmd":"snapshot_remove","name":"dev","tag":"nightly"}"#
        );
        assert_eq!(
            serde_json::to_string(&Response::Log {
                text: "boot".into(),
                truncated: true
            })
            .unwrap(),
            r#"{"result":"log","text":"boot","truncated":true}"#
        );
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
            Request::Up {
                name: "dev".into(),
                restart: None,
            },
            Request::Down { name: "dev".into() },
            Request::Remove { name: "dev".into() },
            Request::Status { name: "dev".into() },
            Request::Rename {
                name: "dev".into(),
                new_name: "dev2".into(),
            },
            Request::MarkConflicted {
                name: "dev".into(),
                other_cpu_device: "d".into(),
            },
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
            Request::Detach {
                name: "dev".into(),
                volume: "tank".into(),
                host: None,
            },
            Request::Snapshot {
                name: "dev".into(),
                tag: "t".into(),
            },
            Request::SnapshotList { name: "dev".into() },
            Request::SnapshotRestore {
                name: "dev".into(),
                tag: "t".into(),
            },
            Request::Logs {
                name: "dev".into(),
                lines: 200,
            },
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
            profiles: Vec::new(),
        };
        assert_eq!(create.subject(), None);
        // Changing an instance's profiles is about that instance, so it
        // resolves across the orbit like every other instance command.
        assert_eq!(
            Request::SetProfiles {
                name: "dev".into(),
                profiles: vec!["claude".into()]
            }
            .subject(),
            Some("dev")
        );
        assert_eq!(Request::List.subject(), None);
        assert_eq!(Request::ListOrbit.subject(), None);
        assert_eq!(Request::Devices.subject(), None);

        // `ast device wake desktop` names a *device*. Reporting it as a
        // subject would send the frame off to be resolved against the
        // instance namespace, where "desktop" means nothing.
        assert_eq!(
            Request::DeviceWake {
                name: "desktop".into()
            }
            .subject(),
            None
        );
        assert_eq!(
            Request::WakeBroadcast {
                mac: "de:ad:be:ef:00:01".into(),
                lan_id: None
            }
            .subject(),
            None
        );
        assert_eq!(Request::DeviceFacts.subject(), None);
        assert_eq!(Request::GpuProviderStatus.subject(), None);
        assert_eq!(Request::DeviceCheck.subject(), None);
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
            Request::VolumeCreate {
                name: "tank".into(),
                size_bytes: 1 << 30
            }
            .subject(),
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

    /// A conflicted instance has to leave a way out, and looking at its state
    /// and console before a rename is part of that way out.
    #[test]
    fn a_conflict_admits_its_remedy_and_diagnostic_reads() {
        assert!(Request::Rename {
            name: "d".into(),
            new_name: "e".into()
        }
        .survives_a_conflict());
        assert!(Request::Status { name: "d".into() }.survives_a_conflict());
        assert!(Request::Logs {
            name: "d".into(),
            lines: 10
        }
        .survives_a_conflict());
        assert!(Request::Down { name: "d".into() }.survives_a_conflict());
        assert!(!Request::Up {
            name: "d".into(),
            restart: None
        }
        .survives_a_conflict());
        assert!(!Request::SshEndpoint { name: "d".into() }.survives_a_conflict());
        assert!(!Request::Remove { name: "d".into() }.survives_a_conflict());
    }

    /// `ast ls` and the shard query one daemon sends another are different
    /// questions, and stay different frames — the second is what the first is
    /// assembled from.
    #[test]
    fn the_orbit_view_and_a_single_shard_are_distinct_on_the_wire() {
        assert_eq!(
            serde_json::to_string(&Request::List).unwrap(),
            r#"{"cmd":"list"}"#
        );
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
