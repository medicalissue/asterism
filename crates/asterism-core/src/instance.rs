//! What an instance is made of.
//!
//! The orbit is a pool of parts; an instance is a computer assembled from
//! them. Every part records the device it is sourced from — cpu and ram come
//! as a pair from whichever device runs the hypervisor, a volume comes from
//! whichever device holds the bytes — and the rest default to the same device
//! as cpu because that is the cheapest place to put them, not because that
//! device has any claim on the instance.

use serde::{Deserialize, Serialize};

use crate::hv::{ControlChannel, GuestEndpoint, Handle, ImageKind, Machine};
use crate::remote_gpu::GpuAttachment;
use crate::secret::Binding;

/// Lifecycle state of an instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Defined,
    Running,
    Stopped,
}

impl std::fmt::Display for Status {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Status::Defined => "defined",
            Status::Running => "running",
            Status::Stopped => "stopped",
        };
        f.write_str(s)
    }
}

/// What kind of storage a volume is, which decides how it reaches the guest.
///
/// The two are genuinely different parts, not two settings of one part: a
/// directory is a shared filesystem the host and guest both see, a block
/// volume is a disk with one writer and a filesystem of its own.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VolumeKind {
    /// A host directory, shared through the backend's transport (9p or
    /// virtiofs) and mounted at `mount_point`. Same device only: neither
    /// transport has a network form.
    #[default]
    Dir,
    /// A block volume (`ast volume create`), served as NBD by the device
    /// that holds the bytes and arriving in the guest as a plain virtio-blk
    /// disk. The guest partitions, formats and mounts it itself.
    Block,
}

/// A storage volume attached to an instance. `host` names the device the
/// bytes live on.
///
/// Directory volumes hosted on this device are passed to the guest through
/// the backend's directory-share transport and mounted at `mount_point`.
/// Block volumes name a volume created with `ast volume create` on `host`, and arrive as `/dev/vdX` —
/// over the mesh as NBD when `host` is another device, which the guest has no
/// way of telling.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Volume {
    /// The host directory, for a [`VolumeKind::Dir`]; the volume's name on
    /// `host`, for a [`VolumeKind::Block`].
    pub path: String,
    pub host: String,
    /// Immutable identity of the device behind `host`. Absent on directory
    /// shares and records written before storage authority was identity
    /// bound; new block attachments always populate it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_id: Option<String>,
    /// Absolute path the volume appears at inside the guest. Assigned when
    /// the volume is attached; `None` on records written before mount
    /// points existed, which fall back to [`Volume::guest_path`]'s default,
    /// and on block volumes, which the guest mounts wherever it likes.
    #[serde(default)]
    pub mount_point: Option<String>,
    /// Defaulted, so every volume record written before block volumes
    /// existed loads as the directory share it was.
    #[serde(default)]
    pub kind: VolumeKind,
    /// The lease epoch this instance was last granted on a block volume.
    /// Presented on every splice and checked by the provider; a stale one is
    /// refused rather than served (`docs/ROADMAP.md` Phase 3).
    #[serde(default)]
    pub epoch: Option<u64>,
    /// Attach-saga identity which created this durable block row. It lets
    /// restart reconciliation distinguish this commit from a later attach of
    /// the same human-named volume.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attach_intent_id: Option<String>,
    /// Size of a block volume as its provider reported it, for `ast status`.
    #[serde(default)]
    pub size_bytes: Option<u64>,
    /// What the daemon supplying cpu/ram most recently observed about this
    /// part while the guest was running.
    ///
    /// Runtime-only: registries never populate it, but a `status` reply may.
    /// Keeping it on the part rather than on [`Instance::status`] is what lets
    /// a provider disappear without falsely reporting that the guest died.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime: Option<PartRuntime>,
}

impl Volume {
    /// A directory share on some device.
    pub fn dir(path: &str, host: &str, mount_point: Option<String>) -> Self {
        Volume {
            path: path.to_owned(),
            host: host.to_owned(),
            host_id: None,
            mount_point,
            kind: VolumeKind::Dir,
            epoch: None,
            attach_intent_id: None,
            size_bytes: None,
            runtime: None,
        }
    }

    /// A block volume, named on the device that holds its bytes.
    pub fn block(volume: &str, host: &str, epoch: u64, size_bytes: u64) -> Self {
        Self::block_owned(volume, host, None, epoch, size_bytes)
    }

    pub fn block_owned(
        volume: &str,
        host: &str,
        host_id: Option<String>,
        epoch: u64,
        size_bytes: u64,
    ) -> Self {
        Volume {
            path: volume.to_owned(),
            host: host.to_owned(),
            host_id,
            mount_point: None,
            kind: VolumeKind::Block,
            epoch: Some(epoch),
            attach_intent_id: None,
            size_bytes: Some(size_bytes),
            runtime: None,
        }
    }

    pub fn is_block(&self) -> bool {
        self.kind == VolumeKind::Block
    }

    /// Does this volume live on the device we are running on?
    pub fn is_local(&self) -> bool {
        self.host == local_host()
    }

    /// Where the volume appears inside the guest.
    pub fn guest_path(&self) -> String {
        self.mount_point
            .clone()
            .unwrap_or_else(|| default_mount_point(&self.path))
    }

    /// The virtio filesystem mount tag identifying this share to the guest.
    ///
    /// Derived from host+path with a fixed hash so the tag a guest was
    /// told about survives daemon restarts and toolchain upgrades. Tags
    /// fit the stricter transport's tag limit; this is 15 bytes.
    pub fn mount_tag(&self) -> String {
        format!(
            "ast{:012x}",
            fnv1a(&format!("{}:{}", self.host, self.path)) >> 16
        )
    }
}

/// A measurement of one remotely sourced part, attached to a `status` reply.
///
/// Strings are intentional for `transition_reason` and `recovery_result`:
/// these are diagnostic vocabulary, not protocol gates, so a newer daemon can
/// add a more precise reason without making an older CLI reject the reply.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PartRuntime {
    /// `healthy`, `recovering`, or `degraded`.
    pub state: String,
    /// The selected transport path (`direct`, `relay`, or `local`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// Application-observed or selected-path RTT.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rtt_micros: Option<u64>,
    /// Payload throughput from the most recently completed bridge session.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub throughput_bytes_per_sec: Option<u64>,
    /// Payload bytes in that throughput sample, both directions combined.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transferred_bytes: Option<u64>,
    /// Time from detecting a loss/restart to restoring the part.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_millis: Option<u64>,
    /// Why the current observation replaced the previous one.
    pub transition_reason: String,
    /// `connected`, `reconnected`, `retrying`, or `failed`.
    pub recovery_result: String,
    /// A bounded, user-facing explanation when more detail is useful.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// Unix seconds when the daemon made this observation.
    pub observed_at: u64,
}

impl PartRuntime {
    fn summary(&self) -> String {
        let mut facts = vec![self.state.clone()];
        if let Some(path) = &self.path {
            facts.push(path.clone());
        }
        if let Some(us) = self.rtt_micros {
            facts.push(format!("{:.1}ms RTT", us as f64 / 1_000.0));
        }
        if let Some(bytes_per_sec) = self.throughput_bytes_per_sec {
            facts.push(format!(
                "{:.1} MiB/s",
                bytes_per_sec as f64 / (1024.0 * 1024.0)
            ));
        }
        if let Some(bytes) = self.transferred_bytes {
            facts.push(format!(
                "{} transferred ({bytes} bytes)",
                crate::volume::format_size(bytes)
            ));
        }
        facts.push(format!(
            "{} ({})",
            self.recovery_result, self.transition_reason
        ));
        if let Some(ms) = self.recovery_millis {
            facts.push(format!("recovery {ms}ms"));
        }
        if let Some(detail) = &self.detail {
            facts.push(detail.clone());
        }
        facts.join(" · ")
    }
}

/// Default guest mount point for a host path: `/mnt/ast/<basename>`.
pub fn default_mount_point(path: &str) -> String {
    let base: String = path
        .trim_end_matches('/')
        .rsplit('/')
        .next()
        .unwrap_or("")
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-' {
                c
            } else {
                '-'
            }
        })
        .collect();
    let base = base.trim_matches('-');
    if base.is_empty() {
        format!("/mnt/ast/vol-{:08x}", fnv1a(path) as u32)
    } else {
        format!("/mnt/ast/{base}")
    }
}

/// The hostname of the device we are running on — the `host` recorded on
/// locally-provided volumes, and the fallback name a device answers to in
/// its orbit before anyone has given it a better one.
pub fn local_host() -> String {
    hostname::get()
        .ok()
        .and_then(|h| h.into_string().ok())
        .unwrap_or_else(|| "local".into())
}

/// FNV-1a. Spelled out rather than using `DefaultHasher` because the
/// values end up in guest configuration and on disk, so they must not
/// drift between Rust releases.
pub fn fnv1a(s: &str) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for b in s.as_bytes() {
        hash ^= *b as u64;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

/// A guest port reachable from this device's loopback.
///
/// The model has no network ingress: an instance is reached through the mesh,
/// and nothing dials in from outside. This is not ingress — it is the loopback
/// of the device supplying cpu/ram, the same place `ast ssh` already lands —
/// and it exists because an OCI image's whole point is the port it listens on.
/// A cloud image gets there over ssh; a container image has no ssh to get
/// there over.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortForward {
    pub host: u16,
    pub guest: u16,
}

impl std::str::FromStr for PortForward {
    type Err = String;

    /// `8080:80`, or `8080` for both.
    fn from_str(s: &str) -> Result<Self, String> {
        let bad = || format!("{s:?} is not a port mapping — write it as HOST:GUEST, e.g. 8080:80");
        let (host, guest) = s.split_once(':').unwrap_or((s, s));
        let port = |p: &str| p.parse::<u16>().ok().filter(|p| *p != 0).ok_or_else(bad);
        Ok(PortForward {
            host: port(host)?,
            guest: port(guest)?,
        })
    }
}

impl std::fmt::Display for PortForward {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "127.0.0.1:{} -> :{}", self.host, self.guest)
    }
}

/// What should happen when this instance's guest dies.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Restart {
    /// Bring it back — after a crash, and after a host reboot.
    #[default]
    Always,
    /// Leave it down. For an instance a user boots by hand when they want it.
    Never,
}

impl std::fmt::Display for Restart {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Restart::Always => "always",
            Restart::Never => "never",
        })
    }
}

impl std::str::FromStr for Restart {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "always" => Ok(Restart::Always),
            "never" => Ok(Restart::Never),
            other => Err(format!("restart is `always` or `never` (got {other:?})")),
        }
    }
}

/// Restart budget: how many times a guest that keeps dying is brought back
/// before the daemon stops trying.
pub const MAX_ATTEMPTS: u32 = 3;

/// What the crash supervisor does about this instance, carried on the
/// instance itself.
///
/// It lived in a `policy.json` sidecar until the registry settled, and the
/// files written then are folded in at load and deleted; see
/// [`crate::registry::Shard::load`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Policy {
    #[serde(default)]
    pub restart: Restart,
    #[serde(default = "max_attempts")]
    pub max_attempts: u32,
}

fn max_attempts() -> u32 {
    MAX_ATTEMPTS
}

impl Default for Policy {
    fn default() -> Self {
        Policy {
            restart: Restart::Always,
            max_attempts: MAX_ATTEMPTS,
        }
    }
}

impl Policy {
    /// The policy an instance gets when the default is not the right one.
    ///
    /// An OCI instance is the case: its guest goes down when the image's
    /// entrypoint returns, and from outside the machine that is
    /// indistinguishable from a crash. A container that has finished its work
    /// must not be restarted three times on a backoff, and Asterism cannot
    /// tell "finished" from "fell over" without asking the guest.
    pub fn never() -> Self {
        Policy {
            restart: Restart::Never,
            ..Policy::default()
        }
    }
}

/// Hardware shape of an instance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Shape {
    pub cpus: u32,
    pub mem_mib: u32,
    pub disk_gib: u32,
}

impl Default for Shape {
    fn default() -> Self {
        Shape {
            cpus: 2,
            mem_mib: 2048,
            disk_gib: 20,
        }
    }
}

/// Why an instance refuses to be used until it is renamed.
///
/// Two devices that could not see each other both admitted an instance called
/// `dev`; when the orbit came back together the flat namespace had two rows
/// under one name. The later creation loses and carries this, because the
/// alternative — quietly renaming somebody's instance, or letting the name
/// mean two things — is worse than a command that says what to do.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Conflict {
    /// The device supplying cpu/ram to the other instance of this name.
    pub other_cpu_device: String,
    /// When the orbit noticed, Unix seconds.
    pub found_at: u64,
}

/// The fence a cpu-part swap puts on an instance while its bytes are in
/// flight.
///
/// Swapping the device that supplies cpu and ram means the instance's disk
/// has to move too — one copy, one writer — and for the length of that
/// transfer there are two directories with the same instance's bytes in
/// them. Exactly one of them may ever be booted, so the source records this
/// and refuses `up` until the move either commits or is called off.
///
/// The epoch is the tie-break of last resort. It is monotonic per instance,
/// it is bumped by the move that lands, and it is written on both shards —
/// so a device that was partitioned during a move and comes back believing
/// it still supplies the cpu loses to the higher number, rather than the
/// two of them arguing from equally-plausible rows.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Moving {
    /// The device the cpu part is moving to.
    pub to_device: String,
    /// The epoch this move will land on: one past the current one.
    pub epoch: u64,
    /// When the fence went up, Unix seconds.
    pub started_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Instance {
    pub id: String,
    pub name: String,
    /// The device sourcing this instance's cpu and ram. They come as a pair,
    /// from wherever the hypervisor runs; it is a sourcing fact about two
    /// parts, and every other part defaults to the same device.
    ///
    /// Read from the `anchor` key too, so registries written when this was
    /// framed as an anchoring relationship still load.
    #[serde(alias = "anchor")]
    pub cpu_device: String,
    pub status: Status,
    /// Unix seconds.
    pub created_at: u64,
    pub volumes: Vec<Volume>,
    /// Image reference the instance boots from (`ubuntu:24.04`, a url, a
    /// path, `docker.io/library/nginx:latest`).
    #[serde(default)]
    pub image: Option<String>,
    /// What that image turned out to be when the instance was created: a
    /// bootable disk, or an OCI root filesystem the backend has to bring a
    /// kernel for. `disk` on records written before container images were a
    /// source, which is what they all were.
    #[serde(default)]
    pub image_kind: ImageKind,
    /// Guest ports published on this device's loopback (`ast create -p`).
    #[serde(default)]
    pub publish: Vec<PortForward>,
    #[serde(default)]
    pub shape: Shape,
    /// What the crash supervisor does when this instance's guest dies, and
    /// whether it comes back after a host reboot. `ast up --restart` sets
    /// it; the default brings everything back.
    ///
    /// Defaulted, so a shard written before the policy moved in here loads
    /// as "restart always" — and the `policy.json` such a shard was written
    /// alongside is folded in and deleted at load.
    #[serde(default)]
    pub policy: Policy,
    /// The machine this instance was defined against: backend, machine
    /// type, cpu model, hypervisor version. Recorded at create time and
    /// left alone afterwards — it is what a future live migration has to
    /// match on (BACKENDS.md §5). Creation only succeeds after probing a
    /// runnable backend, so every instance has this identity.
    pub machine: Machine,
    /// The running guest, while there is one.
    #[serde(default)]
    pub handle: Option<Handle>,
    /// Durable fence for a guest launch whose handle is not committed yet.
    ///
    /// The daemon writes this before renewing storage or asking a hypervisor
    /// to boot, and clears it atomically with the running handle. A crash in
    /// that window therefore leaves a row which refuses another launch,
    /// rather than a stopped-looking row beside a possibly live guest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub boot_intent_id: Option<String>,
    /// Set when this instance's name turned out not to be unique in the
    /// orbit. Every command on it refuses until `ast rename` clears it.
    #[serde(default)]
    pub conflict: Option<Conflict>,
    /// How many times this instance's cpu part has been swapped onto a
    /// different device. Monotonic, written on both shards by the swap that
    /// bumps it, and the fence that decides between two rows claiming the
    /// same instance: the higher epoch is the live one.
    #[serde(default)]
    pub move_epoch: u64,
    /// Set while this instance's bytes are in flight to another device.
    /// Refuses `up` — there must never be two bootable copies.
    #[serde(default)]
    pub moving: Option<Moving>,
    /// The device whose guest key opens this instance's guest.
    ///
    /// A cloud-init seed bakes in the ssh key of the device that *built* it,
    /// so the guest trusts that device's key and no other. Until instances
    /// could move that was always the device supplying cpu/ram, because that
    /// is where seeds get built — a cpu-part swap carries the seed rather
    /// than rebuilding it, and then the two are different devices. Recorded
    /// so `ast ssh` presents the key the guest will actually accept,
    /// whichever device the command was typed on.
    ///
    /// `None` on records written before instances could move, and on ones
    /// whose seed has never been built; both fall back to the cpu device,
    /// which is what was true when they were written.
    #[serde(default)]
    pub seed_device: Option<String>,
    /// Secrets bound to this instance's egress.
    ///
    /// A binding is a policy and a stand-in, never a value: the orbit name of
    /// the secret, the one authority it may be used against, where on a
    /// request it rides, and the opaque handle this instance's guest was
    /// given instead of it. That is what makes it safe for this to live in a
    /// shard that is written to disk, printed by `ast status`, and carried
    /// whole to another device by a cpu-part move.
    ///
    /// Defaulted, so every registry written before secrets had a data plane
    /// loads as an instance with none — which is what it was.
    #[serde(default)]
    pub secrets: Vec<Binding>,
    /// Bootstrap profiles this instance was created with, by name.
    ///
    /// Names rather than rendered work, because what a profile *does* is a
    /// property of the version of Asterism applying it: the catalog in
    /// [`crate::profile`] is where `claude` is defined, and an instance that
    /// asked for `claude` should get the current answer to that question at
    /// its next boot rather than the one that was true when it was created.
    ///
    /// Defaulted, so every registry written before profiles existed loads as
    /// an instance with none — which is what it was, and what an instance
    /// created without `--profile` still is.
    #[serde(default)]
    pub profiles: Vec<String>,
    /// Guest paths of volumes the last cpu-part swap left behind.
    ///
    /// A directory share is a same-device part: the hypervisor
    /// shares a directory that is on its own disk. Move the cpu part to
    /// another device and that share has nothing to attach to. The row is
    /// *kept* — it is still what the user asked for, and it becomes true
    /// again the moment the cpu part comes back or the volume is re-sourced
    /// over the mesh — but it is flagged in `ast status` rather than
    /// silently dropped.
    #[serde(default)]
    pub stranded: Vec<String>,
    /// A remote GPU part projected into the guest as `/dev/nvidia0`.
    ///
    /// This is deliberately token-free. The provider lease capability lives
    /// only in the authenticated mesh adapter; persisting it here would turn
    /// an ordinary registry/backup read into authority to execute GPU work.
    #[serde(default)]
    pub gpu: Option<GpuAttachment>,

    // ---- legacy, read once and folded into `handle` ------------------------
    //
    // Registries written before the Handle refactor recorded a bare pid and
    // forwarded port. They are read (so an upgrade does not lose a running
    // guest) and never written back, so the first save migrates the entry.
    #[serde(default, rename = "pid", skip_serializing)]
    legacy_pid: Option<u32>,
    #[serde(default, rename = "ssh_port", skip_serializing)]
    legacy_ssh_port: Option<u16>,
}

impl Instance {
    /// A newly defined instance. The legacy fields exist only to be read
    /// off older registries, so this is the only way to build one.
    pub fn new(name: &str, cpu_device: &str, image: &str, shape: Shape, machine: Machine) -> Self {
        Instance {
            id: uuid::Uuid::new_v4().to_string(),
            name: name.to_owned(),
            cpu_device: cpu_device.to_owned(),
            status: Status::Defined,
            created_at: now_unix(),
            volumes: Vec::new(),
            image: Some(image.to_owned()),
            image_kind: ImageKind::Disk,
            publish: Vec::new(),
            shape,
            policy: Policy::default(),
            machine,
            handle: None,
            boot_intent_id: None,
            conflict: None,
            move_epoch: 0,
            moving: None,
            seed_device: None,
            secrets: Vec::new(),
            profiles: Vec::new(),
            stranded: Vec::new(),
            gpu: None,
            legacy_pid: None,
            legacy_ssh_port: None,
        }
    }

    /// Fold a pre-`Handle` registry entry into the current shape. Called
    /// once at load; a no-op for entries that already carry a handle.
    ///
    /// The reconstructed control channel is the QMP path the old QEMU
    /// backend would have used, which is the one thing about the old
    /// format we can still infer: it was derived from the instance name.
    pub(crate) fn migrate_legacy(&mut self) {
        let legacy_pid = self.legacy_pid.take();
        let legacy_ssh_port = self.legacy_ssh_port.take();
        if self.handle.is_some() {
            return;
        }
        let Some(pid) = legacy_pid else { return };
        // A running entry always had a port; default only so this cannot panic.
        let ssh_port = legacy_ssh_port.unwrap_or(22);
        self.handle = Some(Handle {
            backend: "qemu".to_owned(),
            pid: Some(pid),
            // No identity: this record predates them, and one is never
            // invented from a number. The daemon adopts it at startup if the
            // process at that pid can be proven to be the guest's
            // (`backend::adopt_identities`), and until then nothing signals
            // it.
            proc: None,
            ctl: ControlChannel::Qmp {
                path: crate::paths::qmp_socket_path(&self.name),
            },
            endpoint: GuestEndpoint::HostForward { ssh_port },
            started_at: self.created_at,
        });
    }

    /// Pid of the process hosting the guest, while there is one.
    pub fn pid(&self) -> Option<u32> {
        self.handle.as_ref().and_then(|h| h.pid)
    }

    /// Where `ast ssh` should connect, while the instance is running.
    pub fn endpoint(&self) -> Option<&GuestEndpoint> {
        self.handle.as_ref().map(|h| &h.endpoint)
    }

    /// The device whose guest key this guest trusts. See [`Instance::seed_device`].
    pub fn seeded_by(&self) -> &str {
        self.seed_device.as_deref().unwrap_or(&self.cpu_device)
    }

    /// The parts this instance is assembled from, in the order `ast status`
    /// prints them.
    ///
    /// Every row names the device the part comes from. Most of them name the
    /// cpu device, and say so as a default rather than as a fact about
    /// ownership: the disk is an overlay on that device's filesystem because
    /// that is where it is cheapest, and egress leaves through that device's
    /// uplink because nothing has been asked to route it elsewhere.
    pub fn parts(&self) -> Vec<Part> {
        let mut parts = vec![
            Part {
                kind: "cpu/ram".into(),
                source: self.cpu_device.clone(),
                detail: format!("{} cores · {} MiB", self.shape.cpus, self.shape.mem_mib),
                note: self.moving.as_ref().map(|m| {
                    format!(
                        "moving to {} — this copy will not boot until it lands",
                        m.to_device
                    )
                }),
            },
            Part {
                kind: "disk".into(),
                source: self.cpu_device.clone(),
                detail: format!(
                    "{} GiB · {}",
                    self.shape.disk_gib,
                    self.image.as_deref().unwrap_or("no image")
                ),
                note: Some(match self.image_kind {
                    // Where the image came from changes what the machine is,
                    // so it is a fact about the disk and it is said out loud.
                    ImageKind::OciRootfs => "follows cpu · oci rootfs, direct kernel boot".into(),
                    ImageKind::Disk => "follows cpu".to_owned(),
                }),
            },
        ];
        for v in &self.volumes {
            let (detail, note) = match v.kind {
                // A directory share is same-device by construction, so a
                // cpu-part swap leaves it pointing at a device that is no
                // longer running the guest. That is the more specific fact
                // and it goes first: it is what tells a user why something
                // that used to work does not. The row is kept either way —
                // it is still what they asked for.
                VolumeKind::Dir => (
                    format!("{} -> {}", v.path, v.guest_path()),
                    if self.stranded.iter().any(|p| *p == v.guest_path()) {
                        Some(format!(
                            "stranded by the cpu move — a directory on {}, and \
                             directory shares are same-device only",
                            v.host
                        ))
                    } else {
                        (!v.is_local())
                            .then(|| format!("a directory on {} — same-device shares only", v.host))
                    },
                ),
                VolumeKind::Block => (
                    format!(
                        "{}{} -> a disk in the guest",
                        v.path,
                        v.size_bytes
                            .map(|b| format!(" ({})", crate::volume::format_size(b)))
                            .unwrap_or_default()
                    ),
                    Some(
                        match v.epoch {
                            Some(epoch) if !v.is_local() => {
                                format!("nbd over the mesh · lease epoch {epoch}")
                            }
                            Some(epoch) => format!("nbd on this device · lease epoch {epoch}"),
                            None => "nbd · no lease yet".to_owned(),
                        } + &v
                            .runtime
                            .as_ref()
                            .map(|runtime| format!(" · {}", runtime.summary()))
                            .unwrap_or_default(),
                    ),
                ),
            };
            parts.push(Part {
                kind: "volume".into(),
                source: v.host.clone(),
                detail,
                note,
            });
        }
        for binding in &self.secrets {
            parts.push(Part {
                kind: "secret".into(),
                // The device whose store holds the value, which is where the
                // value is resolved and the only place it ever exists in the
                // clear. It is a sourcing fact like any other part's.
                source: binding.source_device.clone(),
                detail: format!("{} -> {}", binding.secret, binding.authority),
                note: Some(format!(
                    "{} · ${} in the guest, holding {} · bound at v{}",
                    binding.placement,
                    binding.env,
                    binding.guest_handle.hint(),
                    binding.version
                )),
            });
        }
        let published: Vec<String> = self.publish.iter().map(|p| p.to_string()).collect();
        parts.push(Part {
            kind: "network".into(),
            source: self.cpu_device.clone(),
            detail: match published.is_empty() {
                true => "user-mode NAT".to_owned(),
                false => format!("user-mode NAT · {}", published.join(", ")),
            },
            note: Some("exit default: same as cpu".into()),
        });
        parts.push(match &self.gpu {
            Some(gpu) => Part {
                kind: "gpu".into(),
                source: gpu.provider_device.clone(),
                detail: format!(
                    "{} · {} MiB",
                    gpu.guest_path(),
                    gpu.memory_bytes / (1024 * 1024)
                ),
                note: Some(format!(
                    "projected {} endpoint · {} · provider generation {}",
                    gpu.projection_kind(),
                    gpu.provider_gpu_uuid,
                    gpu.provider_generation
                )),
            },
            None => Part {
                kind: "gpu".into(),
                source: "-".into(),
                detail: "none".into(),
                note: None,
            },
        });
        parts
    }
}

/// One part an instance is assembled from, ready to print.
///
/// The orbit is a pool of parts; an instance is a computer assembled from
/// them. This is one row of that assembly: what the part is, which device in
/// the pool supplies it, how big it is, and — where it is worth saying — how
/// it came to be sourced there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Part {
    /// `cpu/ram`, `disk`, `volume`, `network`, `gpu`.
    pub kind: String,
    /// The device supplying it, or `-` when nothing does.
    pub source: String,
    /// Its size or shape, as the user reads it.
    pub detail: String,
    /// Why it comes from where it does, when that is not obvious.
    pub note: Option<String>,
}

pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn machine() -> Machine {
        Machine {
            backend: "qemu".into(),
            machine_type: "virt".into(),
            cpu: "host".into(),
            hv_version: "test".into(),
        }
    }

    fn vol(path: &str, host: &str) -> Volume {
        Volume::dir(path, host, None)
    }

    #[test]
    fn mount_points_come_from_the_basename() {
        assert_eq!(default_mount_point("/tank/media"), "/mnt/ast/media");
        assert_eq!(default_mount_point("/tank/media/"), "/mnt/ast/media");
        assert_eq!(
            default_mount_point("/Users/me/My Stuff"),
            "/mnt/ast/My-Stuff"
        );
        assert!(default_mount_point("/").starts_with("/mnt/ast/vol-"));
    }

    #[test]
    fn mount_tags_are_stable_short_and_distinct() {
        let a = vol("/tank/media", "desktop");
        assert_eq!(a.mount_tag(), a.mount_tag());
        assert_eq!(a.mount_tag(), "astef4a459a31ff");
        assert!(a.mount_tag().len() <= 31);
        assert_ne!(a.mount_tag(), vol("/tank/other", "desktop").mount_tag());
        assert_ne!(a.mount_tag(), vol("/tank/media", "laptop").mount_tag());
    }

    /// A guest trusts the key that is in its seed, and a cpu-part swap
    /// carries the seed rather than rebuilding it — so after a move the
    /// device that opens the guest is not the device running it.
    #[test]
    fn the_key_that_opens_a_guest_follows_the_seed_not_the_cpu() {
        let mut inst = Instance::new("dev", "laptop", "debian:13", Shape::default(), machine());
        // Nothing recorded: the invariant that held before instances could
        // move, which is that the cpu device seeded it.
        assert_eq!(inst.seeded_by(), "laptop");

        inst.seed_device = Some("laptop".into());
        inst.cpu_device = "desktop".into();
        assert_eq!(
            inst.seeded_by(),
            "laptop",
            "the seed did not move with the cpu"
        );
    }

    #[test]
    fn locality_follows_the_recorded_host() {
        assert!(vol("/tank/media", &local_host()).is_local());
        assert!(!vol("/tank/media", "some-other-device").is_local());
    }

    #[test]
    fn explicit_mount_points_win_over_the_default() {
        let mut v = vol("/tank/media", "desktop");
        assert_eq!(v.guest_path(), "/mnt/ast/media");
        v.mount_point = Some("/srv/media".into());
        assert_eq!(v.guest_path(), "/srv/media");
    }

    /// The field was called `anchor` when the model still had one. Registries
    /// written then must load, or an upgrade loses every instance on the
    /// device.
    #[test]
    fn a_registry_that_says_anchor_still_names_the_cpu_device() {
        let inst: Instance = serde_json::from_str(
            r#"{"id":"6f1c","name":"dev","anchor":"desktop","status":"stopped",
                "created_at":1700000000,"volumes":[],"image":"debian:13",
                "machine":{"backend":"qemu","machine_type":"virt","cpu":"host","hv_version":"test"}}"#,
        )
        .unwrap();
        assert_eq!(inst.cpu_device, "desktop");
        assert!(inst.conflict.is_none(), "an old record is not in conflict");

        // ...and it is written back in the parts vocabulary.
        let raw: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&inst).unwrap()).unwrap();
        assert_eq!(raw["cpu_device"], "desktop");
    }

    #[test]
    fn every_part_names_the_device_that_supplies_it() {
        let mut inst = Instance::new("dev", "desktop", "debian:13", Shape::default(), machine());
        inst.volumes.push(vol("/tank/media", "nas"));
        let parts = inst.parts();

        let find = |kind: &str| parts.iter().find(|p| p.kind == kind).expect(kind).clone();
        // cpu and ram come as a pair from one device.
        assert_eq!(find("cpu/ram").source, "desktop");
        assert_eq!(find("cpu/ram").detail, "2 cores · 2048 MiB");
        // Disk and egress default to that same device, and say so.
        assert_eq!(find("disk").source, "desktop");
        assert_eq!(find("disk").note.as_deref(), Some("follows cpu"));
        assert_eq!(find("network").source, "desktop");
        // A volume is sourced wherever its bytes are, which need not be there.
        assert_eq!(find("volume").source, "nas");
        assert_eq!(find("volume").detail, "/tank/media -> /mnt/ast/media");
        // Nothing in the pool is supplying a gpu.
        assert_eq!(find("gpu").source, "-");
        assert_eq!(find("gpu").detail, "none");
    }

    #[test]
    fn an_attached_remote_gpu_is_a_guest_local_device_without_a_persisted_token() {
        let mut inst = Instance::new("dev", "laptop", "debian:13", Shape::default(), machine());
        inst.gpu = Some(GpuAttachment {
            provider_device: "desktop".into(),
            provider_device_id: "a".repeat(64),
            provider_gpu_uuid: "GPU-01234567".into(),
            memory_bytes: 8 * 1024 * 1024 * 1024,
            provider_generation: 4,
            attached_at: 100,
        });

        let gpu = inst
            .parts()
            .into_iter()
            .find(|part| part.kind == "gpu")
            .unwrap();
        assert_eq!(gpu.source, "desktop");
        assert_eq!(gpu.detail, "/dev/nvidia0 · 8192 MiB");
        let note = gpu.note.unwrap();
        assert!(note.contains("provider generation 4"));
        assert!(note.contains("cuse_char_device_plus_generated_libcuda"));

        let persisted = serde_json::to_string(&inst).unwrap();
        assert!(persisted.contains("GPU-01234567"));
        assert!(!persisted.contains("capability"));
        assert!(!persisted.contains("lease_token"));
    }

    /// An instance built from a container image is a machine like any other,
    /// and `ast status` is where that stops being a claim: the disk row says
    /// what the image was, and the network row says what it published.
    #[test]
    fn an_oci_instance_says_what_it_is_made_of() {
        let mut inst = Instance::new(
            "web",
            "desktop",
            "docker.io/library/nginx:latest",
            Shape::default(),
            machine(),
        );
        inst.image_kind = ImageKind::OciRootfs;
        inst.publish = vec![PortForward {
            host: 8080,
            guest: 80,
        }];

        let parts = inst.parts();
        let find = |kind: &str| parts.iter().find(|p| p.kind == kind).expect(kind).clone();
        assert!(find("disk")
            .detail
            .contains("docker.io/library/nginx:latest"));
        assert_eq!(
            find("disk").note.as_deref(),
            Some("follows cpu · oci rootfs, direct kernel boot")
        );
        assert_eq!(
            find("network").detail,
            "user-mode NAT · 127.0.0.1:8080 -> :80"
        );

        // ...and it survives the registry, kind and ports both.
        let json = serde_json::to_string(&inst).unwrap();
        let back: Instance = serde_json::from_str(&json).unwrap();
        assert_eq!(back.image_kind, ImageKind::OciRootfs);
        assert_eq!(back.publish, inst.publish);
    }

    /// A record written before container images were a source is a disk
    /// image, which is what every one of them was.
    #[test]
    fn an_older_record_is_a_disk_with_nothing_published() {
        let inst: Instance = serde_json::from_str(
            r#"{"id":"6f1c","name":"dev","cpu_device":"desktop","status":"stopped",
                "created_at":1700000000,"volumes":[],"image":"debian:13",
                "machine":{"backend":"qemu","machine_type":"virt","cpu":"host","hv_version":"test"}}"#,
        )
        .unwrap();
        assert_eq!(inst.image_kind, ImageKind::Disk);
        assert!(inst.publish.is_empty());
    }

    /// Losing a storage provider degrades that part, not the guest process.
    /// This is the serialization seam the daemon uses for a live observation:
    /// registry records without it remain readable, while `status` can carry
    /// the measurement to a CLI without inventing a lifecycle state.
    #[test]
    fn a_remote_part_can_degrade_without_calling_the_instance_dead() {
        let mut inst = Instance::new("dev", "laptop", "debian:13", Shape::default(), machine());
        inst.status = Status::Running;
        let mut volume = Volume::block("tank", "storage", 7, 4 << 30);
        volume.runtime = Some(PartRuntime {
            state: "degraded".into(),
            path: Some("relay".into()),
            rtt_micros: Some(12_400),
            throughput_bytes_per_sec: Some(64 << 20),
            transferred_bytes: Some(4 << 30),
            recovery_millis: None,
            transition_reason: "provider_loss".into(),
            recovery_result: "retrying".into(),
            detail: Some("the remote NBD session ended".into()),
            observed_at: 1_700_000_000,
        });
        inst.volumes.push(volume);

        assert_eq!(inst.status, Status::Running);
        let note = inst
            .parts()
            .into_iter()
            .find(|part| part.kind == "volume")
            .and_then(|part| part.note)
            .unwrap();
        for fact in [
            "lease epoch 7",
            "degraded",
            "relay",
            "12.4ms RTT",
            "64.0 MiB/s",
            "4G transferred (4294967296 bytes)",
            "retrying (provider_loss)",
        ] {
            assert!(note.contains(fact), "missing {fact:?} from {note:?}");
        }

        let wire = serde_json::to_string(&inst).unwrap();
        let round_trip: Instance = serde_json::from_str(&wire).unwrap();
        assert_eq!(round_trip.volumes[0].runtime, inst.volumes[0].runtime);

        let old: Volume =
            serde_json::from_str(r#"{"path":"tank","host":"storage","kind":"block","epoch":7}"#)
                .unwrap();
        assert_eq!(
            old.runtime, None,
            "old registry rows default to no observation"
        );
    }

    #[test]
    fn port_mappings_are_read_the_way_people_write_them() {
        use std::str::FromStr;
        assert_eq!(
            PortForward::from_str("8080:80").unwrap(),
            PortForward {
                host: 8080,
                guest: 80
            }
        );
        // One number is the same port on both sides.
        assert_eq!(
            PortForward::from_str("5432").unwrap(),
            PortForward {
                host: 5432,
                guest: 5432
            }
        );
        assert_eq!(
            PortForward::from_str("8080:80").unwrap().to_string(),
            "127.0.0.1:8080 -> :80"
        );
        for junk in [
            "",
            "80:",
            ":80",
            "0:80",
            "80:0",
            "http:80",
            "99999:80",
            "8080:80:8080",
        ] {
            assert!(PortForward::from_str(junk).is_err(), "{junk:?}");
        }
    }

    #[test]
    fn volumes_without_a_mount_point_still_deserialize() {
        let v: Volume = serde_json::from_str(r#"{"path":"/tank/media","host":"desktop"}"#).unwrap();
        assert_eq!(v.mount_point, None);
        assert_eq!(v.guest_path(), "/mnt/ast/media");
        // A record written before block volumes existed is a directory
        // share, which is what it always was.
        assert_eq!(v.kind, VolumeKind::Dir);
        assert!(!v.is_block());
    }

    /// A block volume is a disk, and `ast status` has to say so — no mount
    /// point, because the guest decides that, and the lease epoch, because
    /// that is the fact a user needs when something is fenced out.
    #[test]
    fn a_block_volume_reads_as_a_disk_with_a_lease() {
        let mut inst = Instance::new("dev", "laptop", "debian:13", Shape::default(), machine());
        inst.volumes
            .push(Volume::block("tank", "desktop", 7, 10 << 30));
        let part = inst
            .parts()
            .into_iter()
            .find(|p| p.kind == "volume")
            .expect("volume");
        assert_eq!(part.source, "desktop");
        assert_eq!(part.detail, "tank (10G) -> a disk in the guest");
        assert_eq!(
            part.note.as_deref(),
            Some("nbd over the mesh · lease epoch 7")
        );

        // ...and it round-trips, epoch and all.
        let json = serde_json::to_string(&inst.volumes[0]).unwrap();
        let back: Volume = serde_json::from_str(&json).unwrap();
        assert_eq!(back, inst.volumes[0]);
        assert!(back.is_block());
    }
}
