//! ast — the Asterism CLI.
//!
//! Talks to the local `astd` daemon over its unix socket, starting the
//! daemon on demand if it is not running. Image pulls are device-owned RPCs;
//! the daemon reports bounded phase progress after the store is durable.
//!
//! It talks to *that* daemon and no other, ever. `ast up dev` does not know or
//! care which device in the orbit is supplying `dev`'s compute: the
//! instance namespace is flat and orbit-wide, so the name is enough, and the
//! daemon in front of you resolves it and forwards the request if the row
//! lives elsewhere. The CLI holds no device key, opens no mesh connection, and
//! knows nothing about how a peer is reached — all of which lives in `astd`,
//! which is the process that is always running.
//!
//! `--device` survives as a debugging tool, for asking one specific daemon a
//! question about itself, and as the address for the commands that really are
//! about devices: pairing, and the orbit's own membership.

use asterism_core::ipc::Stream;
use std::fs::File;
use std::io::{BufRead, BufReader, IsTerminal, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use zeroize::Zeroize;

use asterism_core::compat;
use asterism_core::device_shell::{
    ShellData, ShellEnv, ShellOpen, ShellOutput, ShellPolicyAction, ShellPolicyState,
    MAX_DATA_BYTES,
};
use asterism_core::hosted_auth::{
    self, BrowserOpener, CredentialStore, DeviceAuthorization, DeviceAuthorizationRequest,
    PollAction, PollFailure, PollPolicy, ProtocolError, Provider, Session,
};
use asterism_core::hv::{GuestHealth, ImageKind};
use asterism_core::instance::{
    now_unix, Instance, PortForward, PortProtocol, Restart, RuntimeKind, Shape,
};
use asterism_core::ipc;
use asterism_core::proc::{ProcId, Signal};
use asterism_core::protocol::{self, Request, Response};
use asterism_core::registry::OrbitRow;
use asterism_core::{
    cow, doctor, image, oci, paths, service, snapshot, verify, windows_host, VERSION,
};

#[derive(Parser)]
#[command(
    name = "ast",
    version,
    about = "Asterism — assemble one computer from your scattered machines."
)]
struct Cli {
    /// Ask one specific device's daemon, instead of the orbit (debugging).
    ///
    /// Instances resolve by name across the whole orbit, so this is never
    /// needed to reach one. It exists for looking at a single device's shard,
    /// and for the commands that are genuinely about devices.
    #[arg(long, global = true, value_name = "NAME")]
    device: Option<String>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Define a new instance, sourcing its compute from this device.
    ///
    /// The name is claimed across the whole orbit, so it means one instance
    /// everywhere.
    Create {
        /// What to call it: ascii letters, digits and `-`. One name means
        /// one instance everywhere in the orbit.
        name: String,
        /// Image to boot: an alias (`ast images`), an https:// url, a path to
        /// a qcow2 or raw disk image, or an OCI/Docker reference such as
        /// `nginx` or `ghcr.io/owner/app:v1`. OCI images boot as Linux
        /// VM/microVM guests through the selected hypervisor backend.
        #[arg(long, default_value = "ubuntu:24.04")]
        image: String,
        /// Publish a guest port on this device's loopback: `-p 8080:80`.
        ///
        /// How an OCI instance is reached: a container image has no ssh
        /// server, so the port it listens on is the way in. Repeatable.
        #[arg(short = 'p', long = "publish", value_name = "HOST:GUEST[/tcp|/udp]")]
        publish: Vec<String>,
        /// How many cores the guest gets.
        #[arg(long, default_value_t = 2)]
        cpus: u32,
        /// Memory, e.g. 2048M or 4G.
        #[arg(long, default_value = "2G")]
        mem: String,
        /// Disk size, e.g. 20G.
        #[arg(long, default_value = "20G")]
        disk: String,
        /// Hypervisor to run this instance on: `chv` (Cloud Hypervisor/KVM),
        /// `vz` (Apple Virtualization.framework), native `hyperv` on Windows,
        /// or `qemu` (compatibility). Omit it to select this device's first
        /// capable native backend. Recorded and used for every later boot.
        ///
        /// The native backend for the host is the product default and is
        /// always tried first. `qemu` is an optional compatibility and
        /// development backend that Asterism never installs and never selects
        /// on its own; install it separately (`brew install qemu` on macOS)
        /// and name it here. It is what covers `-p` port publication and a
        /// qcow2 base image you point at directly.
        #[arg(long, value_name = "NAME")]
        backend: Option<String>,
        /// Bootstrap profile to apply at first boot (`ast profiles` lists
        /// them). Repeatable, and what a profile needs comes with it:
        /// `--profile claude` installs the base tools and Node too.
        ///
        /// The image stays whatever you asked for. Cloud images apply a
        /// profile through their own systemd unit; OCI images apply it from
        /// Asterism's generated init. `ast profile <name> --check` says when
        /// it is done and what it got.
        #[arg(long = "profile", value_name = "NAME")]
        profiles: Vec<String>,
    },
    /// Boot an instance.
    ///
    /// Where its compute comes from is the instance's business, not the
    /// command's: the name resolves across the orbit and the boot happens on
    /// whichever device supplies it.
    Up {
        /// The instance to boot.
        name: String,
        /// What to do when this guest dies: `always` brings it back after a
        /// crash and after a host reboot, `never` leaves it down. Omit this to
        /// keep the instance's recorded policy: cloud-image VMs start as
        /// `always`, while OCI images start as `never` because a completed
        /// entrypoint is a normal exit. The choice persists and shows in
        /// `ast status`.
        #[arg(long, value_name = "always|never")]
        restart: Option<Restart>,
    },
    /// Shut an instance down.
    ///
    /// A deliberate stop, so nothing brings it back: `--restart always` is
    /// about a guest that died, not about one you turned off.
    Down {
        /// The instance to shut down.
        name: String,
    },
    /// Delete a stopped instance: its disk, its snapshots and its record.
    ///
    /// Everything under the instance's own directory goes, snapshots
    /// included — they were always files in there. Block volumes are not
    /// its bytes and are left alone; their leases are handed back to the
    /// devices holding them.
    Rm {
        /// The instance to delete.
        name: String,
    },
    /// Give an instance a different name.
    ///
    /// The new name is claimed across the orbit, the same as at create.
    /// Refused while the guest is running: the instance's directory, its
    /// control socket and its console log are all named after it.
    Rename {
        /// The instance to rename.
        name: String,
        /// What to call it instead.
        new_name: String,
    },
    /// List every instance in this orbit.
    ///
    /// One table, assembled from every device that answers. A row from a
    /// device that did not answer is still listed, with its status
    /// `unknown` — the instance is real, its state is merely stale.
    Ls {
        /// Only the instances this device supplies compute for (debugging).
        #[arg(long)]
        local: bool,
    },
    /// Show one instance and the parts it is assembled from.
    Status {
        /// The instance to look at.
        name: String,
    },
    /// Open a shell in a running instance (or run a command).
    ///
    /// Works from any device in the orbit and never names one: the daemon
    /// in front of you answers with a loopback address, whether the guest
    /// is here or on the far side of the mesh.
    Ssh {
        /// The instance to connect to. Omit it and say --host to open a
        /// device's own explicitly enabled user shell.
        #[arg(required_unless_present = "host", conflicts_with = "host")]
        name: Option<String>,
        /// A device in this orbit, by the name ast devices shows.
        #[arg(long, value_name = "DEVICE")]
        host: Option<String>,
        /// Force a pty for a remote command, like ssh -t.
        #[arg(short = 't', long)]
        tty: bool,
        /// A command to run instead of opening a shell, and its arguments.
        #[arg(last = true)]
        command: Vec<String>,
    },
    /// Run a bounded command inside a running VM through its authenticated
    /// guest-control agent.
    Exec {
        name: String,
        /// Kill the whole command process group after this many seconds.
        #[arg(long, default_value_t = 30)]
        timeout: u64,
        /// Command and arguments; no host or guest shell quoting is inferred.
        #[arg(last = true, required = true)]
        command: Vec<String>,
    },
    /// Compatibility command for a retired experimental native-container row.
    #[command(hide = true)]
    Shell {
        name: String,
        #[arg(last = true)]
        command: Vec<String>,
    },
    /// Print an instance's guest console log.
    Logs {
        /// The instance whose console to print.
        name: String,
        /// Keep printing as the guest writes more. Needs the console log to be
        /// on this device's disk.
        #[arg(short, long)]
        follow: bool,
        /// How many lines to print (0 for all of it).
        #[arg(short = 'n', long, default_value_t = 200)]
        lines: u32,
    },
    /// Snapshot a stopped instance's disk, or delete a snapshot.
    ///
    /// Two forms:
    ///
    ///   ast snapshot <instance> [tag]      take one (default tag: a timestamp)
    ///
    ///   ast snapshot rm <instance> <tag>   delete one
    ///
    /// A snapshot is a copy-on-write clone of the root disk, so it costs
    /// almost nothing until the live disk moves away from it, and deleting
    /// one is an unlink. Both forms need the guest stopped. (An instance
    /// called `rm` would be shadowed by the second form; instance names are
    /// yours to choose.)
    #[command(
        subcommand,
        override_usage = "ast snapshot <INSTANCE> [TAG]\n       \
                          ast snapshot rm <INSTANCE> <TAG>"
    )]
    Snapshot(SnapshotCommand),
    /// List an instance's snapshots.
    ///
    /// Reads only, so it answers while the guest is running.
    Snapshots {
        /// The instance whose snapshots to list.
        name: String,
    },
    /// Roll a stopped instance's disk back to a snapshot.
    ///
    /// The snapshot survives its own restore, so the same one can be rolled
    /// back to again.
    Restore {
        /// The instance to roll back.
        name: String,
        /// The snapshot to roll back to, as `ast snapshots` lists it.
        tag: String,
    },
    /// Export, inspect and restore portable content-addressed backups.
    #[command(subcommand)]
    Backup(BackupCommand),
    /// List known images and whether they are downloaded.
    ///
    /// This device's image store: the aliases it knows and what is already
    /// on its disk. Every device has its own.
    Images {
        /// Re-hash every image in the store and report what no longer
        /// matches what was pulled.
        ///
        /// A boot checks size and mtime and only re-hashes when one of them
        /// has moved, because a base image is a gigabyte and `ast up` should
        /// not spend a second on it. This is the thorough version: it reads
        /// every byte, so it catches a file that was rewritten in place with
        /// its size and timestamp put back.
        #[arg(long)]
        verify: bool,
    },
    /// List the bootstrap profiles this Asterism can apply to a guest.
    Profiles,
    /// Show, change or verify an instance's bootstrap profiles.
    ///
    /// With no profile named, this says what the instance is recorded as
    /// having. Naming profiles replaces that set — they are applied by the
    /// next boot, because the seed is what carries them into the guest.
    ///
    /// `--check` is the other half, and the one worth typing twice: it runs
    /// the guest's own verifier over ssh and prints what it found. Every
    /// profile ends in checks, so this reports the tools it installed, the
    /// versions they answer with, and whether a credential has ended up on
    /// the guest's disk — which is the one thing a bound secret guarantees
    /// and the one thing nothing but a look can confirm.
    Profile {
        /// The instance.
        name: String,
        /// The profiles it should have. Omit to leave them alone.
        #[arg(value_name = "PROFILE")]
        profiles: Vec<String>,
        /// Run the guest's verifier instead of changing anything.
        #[arg(long, conflicts_with = "profiles")]
        check: bool,
    },
    /// Download an image into this device's store.
    Pull {
        /// The image to download: an alias, an https:// url, a path, or an
        /// OCI/Docker reference.
        ///
        /// A url must carry the digest it should have, written as a
        /// fragment: `https://mirror/x.qcow2#sha256:<hex>` — sha256, sha512
        /// and blake3 are accepted. Nothing publishes a digest for an
        /// arbitrary url on the user's behalf, so an unpinned one is refused
        /// before anything is downloaded rather than fetched and hoped for.
        /// A path may carry one too.
        image: String,
    },
    /// Attach a part to an instance: a volume, secret, or hardware GPU.
    ///
    /// Two kinds of volume, and they reach the guest differently.
    ///
    /// A DIRECTORY (`--volume /tank/media`) is shared with the guest and
    /// mounted at a path. Three things have to be true, and each of them is
    /// refused in words rather than discovered later: the directory is on
    /// the same device as the instance's compute (directory sharing has
    /// no network transport), the backend offers a share transport (9p on
    /// qemu or virtiofs on vz), and the guest kernel supports that transport.
    /// Cloud images receive a mount unit in their seed; OCI images receive
    /// the same mount in Asterism's generated pid 1.
    ///
    /// A BLOCK VOLUME (`--volume tank`, made with `ast volume create`) arrives
    /// as a plain disk: /dev/vdb, /dev/vdc and so on. The
    /// guest partitions, formats and mounts it itself, and never learns which
    /// device the bytes are on — put a filesystem on it once with
    /// `mkfs.ext4 /dev/vdb`, then mount it. It can come from any device in
    /// the orbit. One instance may hold it at a time; attaching takes that
    /// lease.
    ///
    /// A SECRET (`--secret anthropic --to api.anthropic.com`, made with `ast
    /// secret create`) is a part like the others, and it is sourced from a
    /// device like the others — but the part that reaches the guest is not
    /// the value. The guest is given an opaque handle, in `$ANTHROPIC_API_KEY`
    /// by default; the daemon routes that one host through a proxy on this
    /// device and swaps the handle for the real value on the source device,
    /// on its way out. The value never enters the guest, the seed, the
    /// registry or this device's disk.
    Attach {
        /// The instance to attach it to.
        name: String,
        /// A directory path, or an orbit block-volume name. `<device>:<name>`
        /// constrains placement to one provider.
        #[arg(long, conflicts_with = "secret")]
        volume: Option<String>,
        /// Device that provides the volume (default: this device).
        #[arg(long, requires = "volume")]
        host: Option<String>,
        /// Refuse a block placement whose measured round trip is slower than
        /// this. A provider without a live measurement is also refused.
        #[arg(long, value_name = "MS", requires = "volume")]
        max_latency_ms: Option<u64>,
        /// Where a directory volume mounts in the guest (default:
        /// /mnt/ast/<name>). Meaningless for a block volume: the guest
        /// decides where its own disks go.
        #[arg(long, value_name = "PATH", requires = "volume")]
        at: Option<String>,
        /// An orbit secret to bind, by the name `ast secret ls` shows.
        #[arg(long, value_name = "NAME")]
        secret: Option<String>,
        /// The one authority the secret may be used against: `host`, or
        /// `host:port`. Required with --secret, and deliberately not spelled
        /// `--host`, which on this command already means the device a volume
        /// comes from.
        #[arg(long, value_name = "AUTHORITY", requires = "secret")]
        to: Option<String>,
        /// Where the credential rides on a request: `bearer`, `x-api-key`,
        /// or `header:<Name>`. Defaults to whatever that authority's own
        /// clients use.
        #[arg(long = "as", value_name = "PLACEMENT", requires = "secret")]
        placement: Option<String>,
        /// The environment variable the guest finds its handle in. Defaults
        /// to the secret's name, shouted.
        #[arg(long, value_name = "VAR", requires = "secret")]
        env: Option<String>,
        /// Which device's store resolves the value, if the secret has more
        /// than one source. Not `--host`, for the same reason as `--to`.
        #[arg(long, value_name = "DEVICE", requires = "secret")]
        from: Option<String>,
        /// Hardware GPU provider device, optionally followed by its UUID:
        /// `desktop` or `desktop:GPU-...`.
        #[arg(long, value_name = "DEVICE[:GPU-UUID]", conflicts_with_all = ["volume", "secret"])]
        gpu: Option<String>,
        /// GPU memory reservation (default 1G).
        #[arg(long, value_name = "SIZE", requires = "gpu")]
        gpu_memory: Option<String>,
    },
    /// Take a volume or a secret off an instance.
    ///
    /// A VOLUME comes off a stopped instance only. Its lease goes back to the
    /// device that holds the bytes, so something else may take it, and
    /// nothing on it is deleted. Refused while the guest is running: neither
    /// backend can pull a disk out from under a live guest, so that would be
    /// a yanked cable.
    ///
    /// A SECRET comes off at any time, and comes off a running guest on
    /// purpose — that is what revoking one means. The handle stops being
    /// honoured at once, including on a connection the guest already has
    /// open; the guest keeps a string in its environment that now buys
    /// nothing, until its next boot reissues the seed without it.
    Detach {
        /// The instance to take it off.
        name: String,
        /// The directory path, or `<device>:<volume>` for a block volume.
        #[arg(long, conflicts_with = "secret")]
        volume: Option<String>,
        /// The device it came from, if the name alone is ambiguous.
        #[arg(long, requires = "volume")]
        host: Option<String>,
        /// The secret to revoke, by its orbit name.
        #[arg(long, value_name = "NAME")]
        secret: Option<String>,
        /// Revoke and detach the instance's GPU part.
        #[arg(long, conflicts_with_all = ["volume", "secret"])]
        gpu: bool,
    },
    /// Change one of an instance's parts.
    ///
    /// Canonical today: `compute`, the orbit device supplying CPU, physical
    /// RAM, and execution state as one placement unit. `cpu`
    /// remains a compatibility alias. The instance's name, id, and snapshots
    /// do not move, because they were never on a device.
    Set {
        /// The instance whose part is changing.
        name: String,
        /// The part to change. `compute` is canonical; `cpu` is an alias.
        #[arg(value_name = "PART")]
        part: String,
        /// The device to source it from.
        //
        // Not called `device`: `--device` is a global flag with that id, and
        // clap would hand this positional's value to it.
        #[arg(value_name = "DEVICE")]
        to: String,
        /// Shut the guest down first. Moving compute is offline on every
        /// backend Asterism has, so a running instance is refused without it.
        #[arg(long)]
        down: bool,
    },
    /// Move an instance's compute to another device.
    ///
    /// Alias of `ast set <instance> compute <device>`.
    Move {
        /// The instance to move.
        name: String,
        /// The device that will supply its compute from here on.
        #[arg(value_name = "DEVICE")]
        to: String,
        /// Shut the guest down first.
        #[arg(long)]
        down: bool,
    },
    /// Create and delete this device's volumes; list orbit storage.
    #[command(subcommand)]
    Volume(VolumeCommand),
    /// Create, list, remove and rotate orbit-scoped secrets.
    ///
    /// Values are read from stdin and are never accepted as arguments.
    #[command(subcommand)]
    Secret(SecretCommand),
    /// List the devices in this orbit.
    Devices,
    /// Add, list and remove the devices in this orbit.
    #[command(subcommand)]
    Device(DeviceCommand),
    /// Time a round trip to another device.
    Ping {
        /// The device to ping, by name.
        #[arg(value_name = "DEVICE")]
        peer: String,
    },
    /// What wire versions this build speaks, what the daemon speaks, and
    /// what the two of them have settled on.
    ///
    /// The command to run when an upgrade is half-done and something is
    /// refusing. It answers from this build's own table even when the daemon
    /// cannot contribute, so it works in exactly the situation it exists for.
    Compat {
        /// Print the whole table, including the skew matrix, as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Sign in to the optional hosted coordinator. Local orbit commands do
    /// not require an account and never consult this session.
    #[command(subcommand)]
    Auth(AuthCommand),
    /// Check or install a release from Asterism's signed update channel.
    ///
    /// The desktop app calls this same command. One updater therefore owns
    /// channel selection, signature policy, staging, activation and rollback
    /// for both surfaces.
    #[command(subcommand)]
    Update(UpdateCommand),
    /// Restart astd after a transactional update and prove the new build is
    /// the process that answered. Used only by the shipped updater.
    #[command(name = "__activate-update", hide = true)]
    ActivateUpdate {
        #[arg(long)]
        build: String,
    },
    /// Flush an updater-owned file/tree and its containing directory.
    /// Used only by the shipped updater at its durability boundaries.
    #[command(name = "__sync-update-path", hide = true)]
    SyncUpdatePath {
        path: PathBuf,
        /// Flush every file and directory below PATH before PATH itself.
        #[arg(long)]
        recursive: bool,
        /// PATH may be absent; flush only the directory containing it.
        #[arg(long, conflicts_with = "recursive")]
        parent_only: bool,
    },
    /// Install, remove or inspect astd as a service the OS keeps running.
    #[command(subcommand)]
    Service(ServiceCommand),
    /// Run the device daemon in the foreground.
    Daemon,
    /// Print exactly which build this is: version, build id, artifact digest.
    ///
    /// `ast --version` answers "which release"; this answers "which binary",
    /// which is the question worth asking when two machines behave
    /// differently on the same release.
    Version,
    /// Everything worth pasting into a bug report, on stdout.
    ///
    /// Identity first (what `ast`, `astd` and the desktop app each are), then
    /// where this device keeps its state and what is running. Nothing here
    /// contacts another device and nothing here prints a secret.
    Bugreport,
    /// Read-only host capability report: service, sleep, secrets, native VMM
    /// helpers, and the Windows Hyper-V/firewall gate.
    ///
    /// Refuses nothing and changes nothing. A machine that cannot run
    /// Asterism still gets a report saying exactly which check failed.
    Doctor,
}

/// `ast snapshot ...` — taking one, and deleting one.
///
/// Taking is the bare form (`ast snapshot dev nightly`), which is what
/// people type and what every script already types, so it stays a bare
/// form rather than becoming `ast snapshot take`. Deleting is a word,
/// because deleting should be.
#[derive(Subcommand)]
enum SnapshotCommand {
    /// Delete one snapshot. The instance has to be stopped, and a snapshot
    /// an interrupted restore is still reading from is refused.
    Rm {
        /// The instance the snapshot belongs to.
        name: String,
        /// The snapshot to delete, as `ast snapshots <instance>` lists it.
        tag: String,
    },
    /// `ast snapshot <instance> [tag]` — take one.
    #[command(external_subcommand)]
    Take(Vec<String>),
}

#[derive(Subcommand)]
enum BackupCommand {
    /// Export a stopped instance's definition, disk and snapshots.
    Export {
        name: String,
        #[arg(value_name = "DIRECTORY")]
        destination: String,
    },
    /// Inspect a backup's redacted manifest without restoring it.
    Inspect {
        #[arg(value_name = "DIRECTORY")]
        source: String,
        /// Print the complete redacted manifest as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Verify and transactionally restore a backup on this device.
    Import {
        #[arg(value_name = "DIRECTORY")]
        source: String,
        /// Restore under another orbit-global name. Identity is preserved.
        #[arg(long)]
        name: Option<String>,
        /// Materialize the restored instance for this backend. Explicit
        /// selection never falls back to another hypervisor.
        #[arg(long, value_name = "NAME")]
        backend: Option<String>,
        /// Build a fresh OCI rootfs for this device's architecture and import
        /// only explicitly portable parts. Mutable root and snapshot bytes
        /// are not translated.
        #[arg(long = "re-materialize")]
        rematerialize_oci: bool,
    },
}

/// `ast volume ...` — block storage devices put in the orbit pool.
///
/// Volumes belong to the device that holds their bytes, and their names are
/// per-device rather than orbit-global: `desktop:tank` and `nas:tank` are two
/// distinct parts. Creation and removal target this device unless `--device`
/// says otherwise; listing without a target assembles the orbit catalog.
#[derive(Subcommand)]
enum VolumeCommand {
    /// Make a new block volume on this device.
    ///
    /// It is a sparse file: it claims its size and occupies what the guest
    /// writes. There is no filesystem on it — the guest that attaches it puts
    /// one there.
    Create {
        /// What to call it: letters, digits, `-` and `_`. Volume names are
        /// per device, so `desktop:tank` and `nas:tank` are two volumes.
        name: String,
        /// How big, e.g. 10G, 500G, 2T.
        #[arg(long)]
        size: String,
    },
    /// List orbit storage, its owners, access latency and attachment policy.
    Ls,
    /// Delete a block volume and its bytes. Refused while it is attached.
    Rm {
        /// The volume to delete, by its name on this device.
        name: String,
    },
}

/// `ast secret ...` — orbit metadata backed by independent source devices.
#[derive(Subcommand)]
enum SecretCommand {
    /// Add this device as a source for a new or existing named secret.
    ///
    /// Pipe the exact bytes on stdin. `--device` selects a different source
    /// device over the existing mesh.
    Create { name: String },
    /// List orbit-visible secret metadata. Values are never shown.
    Ls,
    /// Remove a secret from every reachable source device.
    Rm { name: String },
    /// Replace the value on every reachable source device with stdin.
    Rotate { name: String },
}

#[derive(Subcommand)]
enum ServiceCommand {
    /// Have this device start astd at login and keep it running.
    Install,
    /// Stop the OS from starting astd, and remove the unit it uses.
    Uninstall,
    /// Show whether astd is installed as a service, and running.
    Status,
}

/// `ast update ...` — both CLI and desktop app reach this exact surface.
#[derive(Subcommand)]
enum UpdateCommand {
    /// Show this device's channel, installed version/build, and package owner.
    Status,
    /// Fetch and authenticate the channel manifest without downloading artifacts.
    Check,
    /// Download, verify and transactionally activate the channel release.
    Apply {
        /// Confirm replacement of the installed compatible unit.
        #[arg(long)]
        yes: bool,
    },
    /// Print or change the update channel.
    Channel {
        /// stable, beta, or nightly. Omit to print the current channel.
        name: Option<String>,
    },
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum AuthProvider {
    Google,
    Github,
}

impl From<AuthProvider> for Provider {
    fn from(provider: AuthProvider) -> Self {
        match provider {
            AuthProvider::Google => Self::Google,
            AuthProvider::Github => Self::Github,
        }
    }
}

/// `ast auth ...` — one client for the coordinator seam shared with Desktop.
#[derive(Subcommand)]
enum AuthCommand {
    /// Start a browser device-authorization flow.
    Login {
        /// The only supported identity providers.
        #[arg(long, value_enum)]
        provider: AuthProvider,
        /// Hosted coordinator authority. Useful for a compatible self-hosted Worker.
        #[arg(long, default_value = hosted_auth::DEFAULT_AUTHORITY)]
        coordinator: String,
        /// Print the URL/code without attempting to open a browser.
        #[arg(long)]
        no_browser: bool,
    },
    /// Show the locally stored hosted-account session.
    Status {
        /// Assert that the session belongs to this coordinator. No network
        /// request is made; a mismatch is rejected locally.
        #[arg(long)]
        coordinator: Option<String>,
    },
    /// Revoke the hosted session and remove it from the OS credential store.
    Logout {
        /// Assert the expected coordinator. When omitted, the session's
        /// bound issuer is used.
        #[arg(long)]
        coordinator: Option<String>,
    },
}

#[derive(Subcommand)]
enum DeviceCommand {
    /// Print a single-use ticket and wait for another device to redeem it.
    Invite {
        /// What this device calls itself (default: its hostname).
        #[arg(long)]
        name: Option<String>,
        /// How long the ticket stays good for, in seconds.
        #[arg(long, value_name = "SECS")]
        ttl: Option<u64>,
        /// Confirm the code without asking. For scripts; a human should look.
        #[arg(short = 'y', long)]
        yes: bool,
    },
    /// Redeem a ticket printed by `ast device invite` on another device.
    Add {
        /// The ticket, as the other device printed it.
        ticket: String,
        /// What this device calls itself (default: its hostname).
        #[arg(long)]
        name: Option<String>,
        /// Confirm the code without asking. For scripts; a human should look.
        #[arg(short = 'y', long)]
        yes: bool,
    },
    /// List the devices in this orbit.
    Ls,
    /// Drop a device from this orbit. Its key stops being trusted at once.
    Rm {
        /// The device to drop, by the name `ast devices` shows.
        name: String,
    },
    /// Wake a sleeping device in this orbit.
    ///
    /// A magic packet is a broadcast, so it has to be sent from inside the
    /// sleeping device's own network. This asks an orbit peer that is awake
    /// there to send it — and says so plainly when there is nobody to ask.
    Wake {
        /// The device to wake, by name.
        name: String,
    },
    /// Report whether this device could be woken, and what cannot be checked.
    Check,
    /// Enable, disable or inspect this device's opt-in shell offer.
    ///
    /// Enabling grants every device currently paired into this orbit the
    /// authority of this user account. A later pairing is not included until
    /// enable is run locally again.
    Shell {
        #[command(subcommand)]
        action: Option<DeviceShellCommand>,
    },
}

#[derive(Subcommand)]
enum DeviceShellCommand {
    /// Show policy and active sessions (the default).
    Status,
    /// Locally approve the devices currently in this orbit.
    Enable,
    /// Refuse new sessions and terminate every tracked active session.
    Disable,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let device = cli.device;

    let request = match cli.command {
        Command::Create {
            name,
            image,
            publish,
            cpus,
            mem,
            disk,
            backend,
            profiles,
        } => {
            // Profile names are cheap to validate locally. Image bytes are
            // always pulled by the device that will own the instance.
            asterism_core::profile::resolve(&profiles)?;
            let resolved = ensure_image_on_device(device.as_deref(), &image)?;
            let shape = Shape {
                cpus,
                mem_mib: parse_mem_mib(&mem)?,
                disk_gib: parse_disk_gib(&disk)?,
            };
            let publish = publish
                .iter()
                .map(|p| p.parse::<PortForward>())
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| anyhow::anyhow!(e))?;
            if publish
                .iter()
                .any(|mapping| mapping.protocol == PortProtocol::Udp)
            {
                Request::CreateNetwork {
                    name,
                    image: resolved,
                    shape,
                    backend,
                    profiles,
                    publish,
                }
            } else {
                Request::Create {
                    name,
                    image: resolved,
                    shape,
                    backend,
                    profiles,
                    publish,
                }
            }
        }
        Command::Up { name, restart } => Request::Up { name, restart },
        Command::Down { name } => Request::Down { name },
        Command::Shell { name, command } => return container_shell(&name, command),
        Command::Rm { name } => Request::Remove { name },
        Command::Rename { name, new_name } => Request::Rename { name, new_name },
        // `ast ls` is the orbit's registry; `--local` is one device's shard of
        // it, and `--device X ls` is X's shard. Only the first is the model.
        Command::Ls { local } if local || device.is_some() => Request::List,
        Command::Ls { .. } => Request::ListOrbit,
        Command::Status { name } => Request::Status { name },
        // One flag, two parts. `--volume desktop:tank` names a block volume
        // on a device; anything that looks like a path is a directory share.
        // The two are told apart here rather than by a `--block` flag,
        // because the user already said which they meant by how they wrote
        // it — and because a directory on another device has always had to be
        // an absolute path, so there is nothing ambiguous left over.
        Command::Attach {
            name,
            volume,
            host,
            max_latency_ms,
            at,
            secret,
            to,
            placement,
            env,
            from,
            gpu,
            gpu_memory,
        } => match attaching(volume, secret, gpu)? {
            Attaching::Secret(secret) => Request::AttachSecret {
                name,
                secret,
                authority: to.ok_or_else(|| {
                    anyhow::anyhow!(
                        "a secret is bound to one authority — say which with --to, \
                             e.g. --to api.anthropic.com"
                    )
                })?,
                placement: placement
                    .as_deref()
                    .map(asterism_core::secret::Placement::parse)
                    .transpose()?,
                env,
                source_device: from,
            },
            Attaching::Volume(volume) => match storage_ref(&volume, host.as_deref()) {
                Some((owner_device, volume)) => {
                    if at.is_some() {
                        bail!(
                            "--at is for directory volumes; a block volume arrives as a \
                                 disk and the guest mounts it wherever it likes"
                        );
                    }
                    Request::AttachStorage {
                        name,
                        volume,
                        owner_device,
                        max_latency_ms,
                    }
                }
                None => {
                    if max_latency_ms.is_some() {
                        bail!("--max-latency-ms is for orbit block volumes, not directory shares");
                    }
                    Request::AttachVolume {
                        name,
                        path: volume_path(&volume, host.as_deref())?,
                        host,
                        mount_point: at,
                    }
                }
            },
            Attaching::Gpu(provider) => {
                let (provider_device, gpu_uuid) = provider
                    .split_once(':')
                    .map(|(device, uuid)| (device.to_owned(), Some(uuid.to_owned())))
                    .unwrap_or((provider, None));
                Request::AttachGpu {
                    name,
                    provider_device: Some(provider_device),
                    gpu_uuid,
                    memory_bytes: asterism_core::volume::parse_size(
                        gpu_memory.as_deref().unwrap_or("1G"),
                    )?,
                }
            }
        },
        Command::Detach {
            name,
            volume,
            host,
            secret,
            gpu,
        } => match attaching(volume, secret, gpu.then(String::new))? {
            Attaching::Secret(secret) => Request::DetachSecret { name, secret },
            Attaching::Volume(volume) => match storage_ref(&volume, host.as_deref()) {
                Some((device, volume)) => Request::Detach {
                    name,
                    volume,
                    host: device,
                },
                None => Request::Detach {
                    name,
                    volume: volume_path(&volume, host.as_deref())?,
                    host,
                },
            },
            Attaching::Gpu(_) => Request::DetachGpu { name },
        },
        // A move reports as it goes — a preflight, a fence, a disk crossing a
        // network — so it takes the connection the way pairing and wake do.
        Command::Set {
            name,
            part,
            to,
            down,
        } => {
            local_only("set", device.as_deref())?;
            return set_part(&name, &part, &to, down);
        }
        Command::Move { name, to, down } => {
            local_only("move", device.as_deref())?;
            return set_part(&name, "compute", &to, down);
        }
        // A volume is a device's part of the pool, so these are about the
        // daemon in front of you unless `--device` aims them elsewhere.
        Command::Volume(VolumeCommand::Create { name, size }) => Request::VolumeCreate {
            name,
            size_bytes: asterism_core::volume::parse_size(&size)?,
        },
        Command::Volume(VolumeCommand::Ls) if device.is_some() => Request::VolumeList,
        Command::Volume(VolumeCommand::Ls) => Request::VolumeCatalog,
        Command::Volume(VolumeCommand::Rm { name }) => Request::VolumeRemove { name },
        Command::Secret(cmd) => return secret_command(cmd, device.as_deref()),
        Command::Logs {
            name,
            follow,
            lines,
        } => {
            local_only("logs", device.as_deref())?;
            return logs(&name, follow, lines);
        }
        Command::Snapshot(SnapshotCommand::Rm { name, tag }) => {
            return remove_snapshot(&name, &tag, device.as_deref())
        }
        Command::Snapshot(SnapshotCommand::Take(words)) => {
            let (name, tag) = snapshot_target(&words)?;
            return take_snapshot(name, tag, device.as_deref());
        }
        Command::Snapshots { name } => return print_snapshots(&name, device.as_deref()),
        Command::Restore { name, tag } => return restore_snapshot(&name, &tag, device.as_deref()),
        Command::Backup(BackupCommand::Export { name, destination }) => Request::BackupExport {
            name,
            destination: absolute_path(&destination)?.display().to_string(),
        },
        Command::Backup(BackupCommand::Inspect { source, json }) => {
            local_only("backup inspect", device.as_deref())?;
            return inspect_backup(&source, json);
        }
        Command::Backup(BackupCommand::Import {
            source,
            name,
            backend,
            rematerialize_oci,
        }) => {
            let source = absolute_path(&source)?;
            let manifest = asterism_core::backup::inspect(&source)?;
            let name = name.unwrap_or(manifest.instance.name);
            if backend.is_some() || rematerialize_oci {
                Request::BackupImportV2 {
                    source: source.display().to_string(),
                    name,
                    backend,
                    rematerialize_oci,
                }
            } else {
                Request::BackupImport {
                    source: source.display().to_string(),
                    name,
                }
            }
        }
        // The catalog is this binary's, not a device's: it is what this
        // Asterism knows how to make a guest into.
        Command::Profiles => {
            local_only("profiles", device.as_deref())?;
            return print_profiles();
        }
        // `--check` is not a request at all: the answer is inside the guest,
        // and the way in is the one `ast ssh` already uses.
        Command::Profile {
            name, check: true, ..
        } => {
            local_only("profile --check", device.as_deref())?;
            return check_profiles(&name);
        }
        Command::Profile { name, profiles, .. } if profiles.is_empty() => {
            return show_profiles(&name, device.as_deref());
        }
        Command::Profile { name, profiles, .. } => {
            asterism_core::profile::resolve(&profiles)?;
            Request::SetProfiles { name, profiles }
        }
        // Image state is per device, so `--device` asks that device rather
        // than consulting this process's store.
        Command::Images { verify: true } if device.is_none() => {
            return print_image_rows(&image::catalog_rows_full()?);
        }
        Command::Images { .. } if device.is_none() => return images_here(),
        Command::Images { verify: _ } => Request::ImageList,
        Command::Pull { image } if device.is_none() => return pull_here(&image),
        Command::Pull { image } => Request::ImagePull { reference: image },
        // Which device is running the guest is the daemon's problem, not the
        // user's and not this process's: it answers with a loopback port
        // either way.
        Command::Ssh {
            name,
            host,
            tty,
            command,
        } => {
            local_only("ssh", device.as_deref())?;
            return match host {
                None => ssh(
                    name.as_deref()
                        .ok_or_else(|| anyhow::anyhow!("an instance name is required"))?,
                    &command,
                ),
                Some(host) => device_shell(&host, &command, tty),
            };
        }
        Command::Exec {
            name,
            timeout,
            command,
        } => {
            local_only("exec", device.as_deref())?;
            return guest_exec(&name, command, timeout);
        }
        Command::Devices | Command::Device(DeviceCommand::Ls) => {
            local_only("devices", device.as_deref())?;
            return print_devices();
        }
        // The one device command that is worth asking of another device:
        // "can *you* be woken" is a question about the machine you are not
        // sitting at, which is the only kind that matters.
        Command::Device(DeviceCommand::Check) => return device_check(device.as_deref()),
        Command::Device(cmd) => {
            local_only("device", device.as_deref())?;
            return device_command(cmd);
        }
        Command::Ping { peer } => {
            local_only("ping", device.as_deref())?;
            return ping(&peer);
        }
        Command::Compat { json } => {
            local_only("compat", device.as_deref())?;
            return print_compat(json);
        }
        Command::Auth(command) => {
            local_only("auth", device.as_deref())?;
            return auth_command(command);
        }
        Command::Update(cmd) => {
            local_only("update", device.as_deref())?;
            return update_command(cmd);
        }
        Command::ActivateUpdate { build } => {
            local_only("__activate-update", device.as_deref())?;
            return activate_update(&build);
        }
        Command::SyncUpdatePath {
            path,
            recursive,
            parent_only,
        } => {
            local_only("__sync-update-path", device.as_deref())?;
            return sync_update_path(&path, recursive, parent_only);
        }
        Command::Service(cmd) => {
            local_only("service", device.as_deref())?;
            return service_command(cmd);
        }
        Command::Daemon => {
            local_only("daemon", device.as_deref())?;
            let err = exec_daemon();
            return Err(err).context("running astd");
        }
        Command::Version => {
            local_only("version", device.as_deref())?;
            return print_version();
        }
        Command::Bugreport => {
            local_only("bugreport", device.as_deref())?;
            return print_bugreport();
        }
        Command::Doctor => {
            local_only("doctor", device.as_deref())?;
            return print_doctor();
        }
    };

    match send(&aimed(request.clone(), device.as_deref()))? {
        Response::Ok => {}
        Response::Instance { instance, guest_health } => match request {
            Request::Status { .. } => print_detail(&instance, guest_health.as_deref()),
            Request::SetProfiles { .. } => print_profile_state(&instance),
            Request::Remove { .. } => println!("{}  removed", instance.name),
            Request::Rename { name, .. } => println!("{name}  renamed to {}", instance.name),
            Request::Up { .. } => {
                println!("{}  {}", instance.name, instance.status);
                // An OCI root filesystem always boots as a VM/microVM. It
                // has authenticated guest control, but no implied SSH
                // server; presenting its host-forward as SSH is therefore a
                // false promise even though disk-image guests do use SSH.
                if instance.image_kind == ImageKind::OciRootfs {
                    for p in &instance.publish {
                        println!(
                            "published: 127.0.0.1:{}  ->  guest :{}/{}",
                            p.host, p.guest, p.protocol
                        );
                    }
                    println!(
                        "guest control ready — try: ast exec {} -- /bin/sh -c 'uname -a'",
                        instance.name
                    );
                    println!("output:  ast logs {}", instance.name);
                } else if instance.runtime == RuntimeKind::Container {
                    // Retained only for old experimental registry rows.
                    println!("control: ast shell {} -- /bin/sh", instance.name);
                    println!("output:  ast logs {}", instance.name);
                } else if let Some(endpoint) = instance.endpoint() {
                    println!(
                        "guest booting; ssh on {endpoint} — try: ast ssh {}",
                        instance.name
                    );
                }
            }
            Request::AttachVolume { .. }
            | Request::AttachBlock { .. }
            | Request::AttachStorage { .. }
            | Request::AttachGpu { .. }
            | Request::AttachGpuResolved { .. } => {
                print_attached(&instance)
            }
            Request::AttachSecret { ref secret, .. } => print_bound(&instance, secret),
            Request::DetachSecret { ref secret, .. } => {
                println!("{}  {secret} revoked", instance.name);
                println!(
                    "the handle the guest holds is no longer honoured; it disappears from \
                     the guest on the next boot: ast down {0} && ast up {0}",
                    instance.name
                );
            }
            Request::Detach { volume, .. } => {
                println!("{}  {volume} detached", instance.name)
            }
            Request::DetachGpu { .. } => println!("{}  GPU detached and revoked", instance.name),
            _ => println!("{}  {}", instance.name, instance.status),
        },
        Response::Volumes { volumes } => match request {
            Request::VolumeCreate { .. } => print_volume_made(&volumes),
            Request::VolumeRemove { name } => println!("{name}  removed"),
            _ => print_volumes(&volumes),
        },
        Response::VolumeCatalog { catalog } => print_volume_catalog(&catalog),
        Response::Orbit { rows } => print_table(&rows),
        // One device's shard, asked for by `--local` or `--device`. Rows from
        // a single shard are live by construction: the device answered.
        Response::Instances { instances } => print_table(
            &instances
                .into_iter()
                .map(|instance| OrbitRow { instance, live: true })
                .collect::<Vec<_>>(),
        ),
        Response::Images { images } => print_image_rows(&images)?,
        Response::ImagePulled { result } => print_image_pull(&result)?,
        Response::BackupExported { report } => {
            println!(
                "exported {} file(s), {} logical bytes to {}",
                report.files, report.logical_bytes, report.destination
            );
            println!(
                "{} data chunk(s), {} reused",
                report.data_chunks, report.reused_chunks
            );
        }
        Response::BackupRestored { report } => {
            println!("{}  restored ({})", report.instance, report.id);
            match report.materialization {
                asterism_core::backup::RestoreDisposition::ByteExact => {
                    if let (Some(architecture), Some(backend)) =
                        (&report.target_architecture, &report.target_backend)
                    {
                        println!("materialized byte-exact for {architecture}/{backend}");
                    }
                }
                asterism_core::backup::RestoreDisposition::Qcow2ToRaw => println!(
                    "materialized qcow2 disks as raw for {}/{}",
                    report.target_architecture.as_deref().unwrap_or("unknown"),
                    report.target_backend.as_deref().unwrap_or("unknown")
                ),
                asterism_core::backup::RestoreDisposition::OciRematerialized => println!(
                    "re-materialized OCI rootfs for {}/{}; mutable root and snapshots were not imported",
                    report.target_architecture.as_deref().unwrap_or("unknown"),
                    report.target_backend.as_deref().unwrap_or("unknown")
                ),
            }
            if report.rebind.volumes.is_empty()
                && report.rebind.secrets.is_empty()
                && report.rebind.gpu.is_none()
            {
                println!("no external parts need rebinding");
            } else {
                for volume in report.rebind.volumes {
                    println!(
                        "rebind volume: {}:{} ({:?})",
                        volume.source_device, volume.path, volume.kind
                    );
                }
                for secret in report.rebind.secrets {
                    println!(
                        "rebind secret: {} to {} (previous source: {})",
                        secret.secret, secret.authority, secret.source_device
                    );
                }
                if let Some(gpu) = report.rebind.gpu {
                    println!(
                        "rebind gpu: {} on {} ({} bytes; previous provider generation {})",
                        gpu.provider_gpu_uuid,
                        gpu.provider_device,
                        gpu.memory_bytes,
                        gpu.provider_generation
                    );
                }
            }
        }
        // The handshake owns Pong, `ast snapshots` owns Snapshots, `ast ssh`
        // and `ast logs` return long before here. Any of them arriving is astd
        // answering a different question.
        Response::Snapshots { .. }
        | Response::Log { .. }
        | Response::ContainerExec { .. }
        | Response::Exec { .. }
        | Response::SshEndpoint { .. }
        | Response::DeviceShellStatus { .. }
        | Response::DeviceShellAccepted { .. }
        | Response::DeviceShellRefused { .. }
        | Response::DeviceShellOutput { .. }
        | Response::DeviceShellExit { .. }
        | Response::Pong { .. }
        | Response::Compat { .. }
        | Response::Devices { .. }
        | Response::Ticket { .. }
        | Response::Sas { .. }
        | Response::Paired { .. }
        | Response::DevicePong { .. }
        // `ast device wake`, `ast device check` and `ast move` return long
        // before here.
        | Response::Move { .. }
        | Response::MoveOffer { .. }
        | Response::MoveProbe { .. }
        | Response::Wake { .. }
        | Response::WakeFacts { .. }
        | Response::WakeCheck { .. }
        // A lease is granted daemon-to-daemon, on the way to an attach or a
        // boot. Nobody types a request that gets one back.
        | Response::VolumeLease { .. } => bail!("unexpected reply from astd: {request:?}"),
        // Secret commands return from `secret_command`; an egress reply is
        // daemon-to-daemon, on the inside of a proxied request, and nothing
        // the CLI can ask for.
        Response::Secrets { .. } | Response::Egress { .. } => {
            bail!("unexpected reply from astd: {request:?}")
        }
        Response::Error { message } => bail!(message),
        Response::GpuProviders { providers } => {
            for provider in providers {
                println!(
                    "{}  {}  {} bytes  {:?}",
                    provider.device_name,
                    provider.gpu_uuid,
                    provider
                        .total_memory_bytes
                        .saturating_sub(provider.leased_memory_bytes),
                    provider.health
                );
            }
        }
        Response::GpuGuestAccepted { .. }
        | Response::GpuGuestRefused { .. }
        | Response::GpuGuestReply { .. }
        | Response::GpuProviderAttached { .. } => {
            bail!("GPU guest session response reached the command RPC path")
        }
    }
    Ok(())
}

struct OsCredentialStore;

impl OsCredentialStore {
    fn entry(&self, account: &str) -> Result<keyring::Entry> {
        keyring::Entry::new(hosted_auth::CREDENTIAL_SERVICE, account)
            .context("opening the OS credential store")
    }

    fn read(&self, account: &str) -> Result<Option<String>> {
        match self.entry(account)?.get_password() {
            Ok(value) => Ok(Some(value)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(error) => Err(error).context("reading the OS credential store"),
        }
    }

    fn delete_account(&self, account: &str) -> Result<()> {
        match self.entry(account)?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(error) => Err(error).context("deleting an OS credential-store entry"),
        }
    }

    /// Old clients put an unbound bearer in one global slot. It is impossible
    /// to infer a safe remote destination for that token, so discovery only
    /// clears it locally.
    fn clear_legacy(&self) -> Result<()> {
        self.delete_account(hosted_auth::CREDENTIAL_ACCOUNT)
    }
}

impl CredentialStore for OsCredentialStore {
    fn save(&self, session: &Session) -> Result<()> {
        let issuer = canonical_authority(&session.issuer)?;
        if issuer != session.issuer {
            bail!("the hosted session issuer is not canonical");
        }
        let account = hosted_auth::credential_account(&issuer);
        let previous = self.read(hosted_auth::ACTIVE_ISSUER_ACCOUNT)?;
        let mut encoded = serde_json::to_string(session).context("encoding the hosted session")?;
        let stored = self
            .entry(&account)?
            .set_password(&encoded)
            .context("saving the hosted session in the OS credential store");
        encoded.zeroize();
        stored?;

        if let Err(error) = self
            .entry(hosted_auth::ACTIVE_ISSUER_ACCOUNT)?
            .set_password(&issuer)
            .context("saving the hosted session issuer in the OS credential store")
        {
            let _ = self.delete_account(&account);
            return Err(error);
        }
        self.clear_legacy()?;
        if let Some(previous) = previous.filter(|previous| previous != &issuer) {
            self.delete_account(&hosted_auth::credential_account(&previous))?;
        }
        Ok(())
    }

    fn load(&self) -> Result<Option<Session>> {
        let Some(issuer) = self.read(hosted_auth::ACTIVE_ISSUER_ACCOUNT)? else {
            self.clear_legacy()?;
            return Ok(None);
        };
        let canonical = canonical_authority(&issuer)
            .context("the stored hosted-session issuer is invalid; refusing remote use")?;
        if canonical != issuer {
            bail!("the stored hosted-session issuer is not canonical; refusing remote use");
        }
        let account = hosted_auth::credential_account(&issuer);
        let Some(mut encoded) = self.read(&account)? else {
            self.delete_account(hosted_auth::ACTIVE_ISSUER_ACCOUNT)?;
            self.clear_legacy()?;
            return Ok(None);
        };
        let session: Result<Session> = serde_json::from_str(&encoded)
            .context("reading the hosted session from the OS credential store");
        encoded.zeroize();
        let session = session?;
        if session.issuer != issuer {
            bail!(
                "the hosted session does not match its credential namespace; refusing remote use"
            );
        }
        Ok(Some(session))
    }

    fn delete(&self) -> Result<()> {
        if let Some(issuer) = self.read(hosted_auth::ACTIVE_ISSUER_ACCOUNT)? {
            self.delete_account(&hosted_auth::credential_account(&issuer))?;
        }
        self.delete_account(hosted_auth::ACTIVE_ISSUER_ACCOUNT)?;
        self.clear_legacy()
    }
}

struct SystemBrowser;

impl BrowserOpener for SystemBrowser {
    fn open(&self, url: &str) -> Result<()> {
        #[cfg(target_os = "macos")]
        let mut command = std::process::Command::new("open");
        #[cfg(target_os = "linux")]
        let mut command = std::process::Command::new("xdg-open");
        #[cfg(target_os = "windows")]
        let mut command = {
            let mut command = std::process::Command::new("cmd");
            command.args(["/C", "start", ""]);
            command
        };
        #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
        bail!("this platform has no system-browser opener");

        let status = command
            .arg(url)
            .status()
            .context("opening the system browser")?;
        if !status.success() {
            bail!("the system browser opener exited with {status}");
        }
        Ok(())
    }
}

struct AuthHttp {
    client: reqwest::blocking::Client,
    authority: String,
}

enum AuthReply<T> {
    Ok(T),
    Protocol(ProtocolError),
}

trait CoordinatorClient {
    fn authority(&self) -> &str;
    fn issue(&self, provider: Provider) -> Result<DeviceAuthorization>;
    fn poll(&self, device_code: &str) -> Result<AuthReply<Session>>;
    fn revoke(&self, access_token: &str) -> Result<()>;
}

trait PollSleeper {
    fn sleep(&self, duration: Duration);
}

trait Clock {
    fn now(&self) -> u64;
}

struct SystemTime;

impl PollSleeper for SystemTime {
    fn sleep(&self, duration: Duration) {
        std::thread::sleep(duration);
    }
}

impl Clock for SystemTime {
    fn now(&self) -> u64 {
        unix_seconds()
    }
}

fn canonical_authority(authority: &str) -> Result<String> {
    let parsed = reqwest::Url::parse(authority).context("parsing the hosted coordinator URL")?;
    let local_http =
        parsed.scheme() == "http" && matches!(parsed.host_str(), Some("127.0.0.1" | "::1"));
    if parsed.scheme() != "https" && !local_http {
        bail!("the hosted coordinator must use https (plain http is allowed only on loopback)");
    }
    if parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || !matches!(parsed.path(), "" | "/")
    {
        bail!("the hosted coordinator must be an origin URL without credentials or a path");
    }
    Ok(parsed.origin().ascii_serialization())
}

impl AuthHttp {
    fn new(authority: &str) -> Result<Self> {
        let authority = canonical_authority(authority)?;
        // This binary owns its TLS client. `reqwest` is deliberately linked
        // without an implicit provider so the choice is explicit and matches
        // the ring provider already used elsewhere in the workspace.
        let _ = rustls::crypto::ring::default_provider().install_default();
        Ok(Self {
            client: reqwest::blocking::Client::builder()
                .timeout(Duration::from_secs(10))
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .context("constructing the hosted authorization client")?,
            authority,
        })
    }

    /// The RFC 8628 endpoints read `application/x-www-form-urlencoded` and
    /// identify the caller by `client_id`.
    fn post_form<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        pairs: &[(&'static str, String)],
    ) -> Result<AuthReply<T>> {
        self.send(
            self.client
                .post(format!("{}{path}", self.authority))
                .header("Asterism-Protocol", hosted_auth::PROTOCOL)
                .form(pairs),
        )
    }

    /// The account-management endpoints read JSON and identify the caller by
    /// the bearer alone.
    fn post_json<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        body: &serde_json::Value,
        bearer: &str,
    ) -> Result<AuthReply<T>> {
        self.send(
            self.client
                .post(format!("{}{path}", self.authority))
                .header("Asterism-Protocol", hosted_auth::PROTOCOL)
                .bearer_auth(bearer)
                .json(body),
        )
    }

    fn send<T: serde::de::DeserializeOwned>(
        &self,
        request: reqwest::blocking::RequestBuilder,
    ) -> Result<AuthReply<T>> {
        let response = request
            .send()
            .context("contacting the hosted authorization service")?;
        let status = response.status();
        // The authority does not echo a protocol version, so its absence
        // cannot be a failure. A version that *is* present and disagrees
        // still is: that is a deployment this client cannot read.
        if let Some(advertised) = response
            .headers()
            .get("Asterism-Protocol")
            .and_then(|value| value.to_str().ok())
        {
            if advertised != hosted_auth::PROTOCOL {
                bail!("hosted coordinator protocol is incompatible");
            }
        }
        // Every authorization response is tiny. Capping before deserialization
        // prevents an untrusted coordinator from turning a failure into an
        // unbounded allocation.
        let mut bytes = Vec::new();
        response
            .take(64 * 1024)
            .read_to_end(&mut bytes)
            .context("reading the authorization response")?;
        if status.is_success() {
            serde_json::from_slice(&bytes)
                .map(AuthReply::Ok)
                .context("decoding the authorization response")
        } else {
            let mut error: ProtocolError =
                serde_json::from_slice(&bytes).unwrap_or(ProtocolError {
                    error: "server_error".into(),
                    error_description: None,
                    interval: None,
                });
            if !matches!(
                error.error.as_str(),
                "invalid_request"
                    | "invalid_grant"
                    | "invalid_token"
                    | "authorization_pending"
                    | "slow_down"
                    | "access_denied"
                    | "expired_token"
                    | "temporarily_unavailable"
                    | "server_error"
            ) {
                error.error = "server_error".into();
                error.error_description = None;
                error.interval = None;
            }
            Ok(AuthReply::Protocol(error))
        }
    }

    fn validate_authorization(&self, authorization: &DeviceAuthorization) -> Result<()> {
        if authorization.device_code.is_empty()
            || authorization.device_code.len() > 4096
            || authorization.user_code.is_empty()
            || authorization.user_code.len() > 64
            || !(1..=1800).contains(&authorization.expires_in)
            || !(1..=30).contains(&authorization.interval)
        {
            bail!("hosted coordinator returned an invalid device authorization");
        }
        for candidate in [
            &authorization.verification_uri,
            &authorization.verification_uri_complete,
        ] {
            let url = reqwest::Url::parse(candidate)
                .context("parsing the coordinator verification URL")?;
            if candidate.len() > 8192
                || !url.username().is_empty()
                || url.password().is_some()
                || url.fragment().is_some()
                || url.origin().ascii_serialization() != self.authority
            {
                bail!("hosted coordinator returned a verification URL on another origin");
            }
        }
        Ok(())
    }
}

impl CoordinatorClient for AuthHttp {
    fn authority(&self) -> &str {
        &self.authority
    }

    fn issue(&self, provider: Provider) -> Result<DeviceAuthorization> {
        match self.post_form(
            "/oauth/device/code",
            &DeviceAuthorizationRequest::cli(provider).form_pairs(),
        )? {
            AuthReply::Ok(reply) => {
                self.validate_authorization(&reply)?;
                Ok(reply)
            }
            AuthReply::Protocol(error) => bail!("authorization refused: {}", error.error),
        }
    }

    fn poll(&self, device_code: &str) -> Result<AuthReply<Session>> {
        let reply: AuthReply<hosted_auth::TokenResponse> = self.post_form(
            "/oauth/token",
            &[
                ("client_id", hosted_auth::CLI_CLIENT_ID.to_owned()),
                ("grant_type", hosted_auth::DEVICE_GRANT_TYPE.to_owned()),
                ("device_code", device_code.to_owned()),
            ],
        )?;
        Ok(match reply {
            // The token endpoint answers with a bearer and its scope, not an
            // account document: the account this bearer belongs to is named
            // by the bearer itself.
            AuthReply::Ok(token) => AuthReply::Ok(
                token
                    .into_session(&self.authority, unix_seconds())
                    .context("reading the issued session")?,
            ),
            AuthReply::Protocol(error) => AuthReply::Protocol(error),
        })
    }

    fn revoke(&self, access_token: &str) -> Result<()> {
        match self.post_json::<serde_json::Value>(
            "/api/v1/account/sessions/revoke",
            &serde_json::json!({}),
            access_token,
        )? {
            AuthReply::Ok(_) => Ok(()),
            AuthReply::Protocol(error) => bail!("remote revocation refused: {}", error.error),
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn login_with(
    provider: Provider,
    coordinator: &dyn CoordinatorClient,
    store: &dyn CredentialStore,
    browser: &dyn BrowserOpener,
    sleeper: &dyn PollSleeper,
    clock: &dyn Clock,
    no_browser: bool,
    output: &mut dyn Write,
    errors: &mut dyn Write,
) -> Result<()> {
    let authorization = coordinator.issue(provider)?;
    // Print first: browser launch is convenience and may fail on a headless
    // host. The actionable path is never hidden by it.
    writeln!(output, "Open: {}", authorization.verification_uri)?;
    writeln!(output, "Code: {}", authorization.user_code)?;
    if !no_browser {
        if let Err(error) = browser.open(&authorization.verification_uri_complete) {
            writeln!(errors, "could not open a browser: {error:#}")?;
            writeln!(errors, "continue with the URL and code above")?;
        }
    }

    let mut policy = PollPolicy::new(clock.now(), &authorization)?;
    let mut wait = Duration::from_secs(authorization.interval.clamp(1, 30));
    loop {
        sleeper.sleep(wait);
        let polled = match coordinator.poll(&authorization.device_code) {
            Ok(AuthReply::Ok(session)) => Ok(session),
            Ok(AuthReply::Protocol(error)) => Err(PollFailure::Protocol(error)),
            Err(error) if transient_transport_error(&error) => Err(PollFailure::Offline),
            Err(error) => return Err(error),
        };
        match policy.next(clock.now(), &polled) {
            PollAction::Complete => {
                let mut session = polled.expect("complete means a session reply");
                // The transport origin, not response JSON, is the authority
                // that issued this bearer. Persist that canonical binding as
                // part of the session before it reaches a credential store.
                session.issuer = coordinator.authority().to_owned();
                store.save(&session)?;
                writeln!(
                    output,
                    "signed in as {} ({})",
                    session.account.display_name,
                    session.account.provider.as_str()
                )?;
                return Ok(());
            }
            PollAction::Wait(next) => wait = next,
            PollAction::Denied => bail!("authorization was denied"),
            PollAction::Expired => bail!("authorization expired; run ast auth login again"),
            PollAction::Failed(code) => bail!("authorization failed: {code}"),
        }
    }
}

fn transient_transport_error(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause.downcast_ref::<reqwest::Error>().is_some()
            || cause.downcast_ref::<std::io::Error>().is_some()
    })
}

fn auth_command(command: AuthCommand) -> Result<()> {
    let store = OsCredentialStore;
    match command {
        AuthCommand::Login {
            provider,
            coordinator,
            no_browser,
        } => {
            let http = AuthHttp::new(&coordinator)?;
            login_with(
                provider.into(),
                &http,
                &store,
                &SystemBrowser,
                &SystemTime,
                &SystemTime,
                no_browser,
                &mut std::io::stdout(),
                &mut std::io::stderr(),
            )
        }
        AuthCommand::Status { coordinator } => {
            auth_status_with(&store, coordinator.as_deref(), &mut std::io::stdout())
        }
        AuthCommand::Logout { coordinator } => logout_with(
            &store,
            coordinator.as_deref(),
            &mut std::io::stdout(),
            &mut std::io::stderr(),
        ),
    }
}

fn bound_issuer(session: &Session, expected: Option<&str>) -> Result<String> {
    if session.issuer.is_empty() {
        bail!("legacy hosted session has no bound issuer; refusing remote use");
    }
    let issuer = canonical_authority(&session.issuer)
        .context("the hosted session issuer is invalid; refusing remote use")?;
    if issuer != session.issuer {
        bail!("the hosted session issuer is not canonical; refusing remote use");
    }
    if let Some(expected) = expected {
        let expected = canonical_authority(expected)?;
        if expected != issuer {
            bail!(
                "the requested coordinator {expected} does not match the session issuer {issuer}; refusing before network"
            );
        }
    }
    Ok(issuer)
}

fn auth_status_with(
    store: &dyn CredentialStore,
    expected: Option<&str>,
    output: &mut dyn Write,
) -> Result<()> {
    let Some(session) = store.load()? else {
        writeln!(output, "signed out")?;
        return Ok(());
    };
    let issuer = match bound_issuer(&session, expected) {
        Ok(issuer) => issuer,
        Err(error) if session.issuer.is_empty() => {
            store.delete()?;
            return Err(error).context("legacy session removed locally; sign in again");
        }
        Err(error) => return Err(error),
    };
    writeln!(
        output,
        "signed in  {}  {}  {}",
        session.account.provider.as_str(),
        session.account.display_name,
        issuer
    )?;
    Ok(())
}

fn logout_with(
    store: &dyn CredentialStore,
    expected: Option<&str>,
    output: &mut dyn Write,
    errors: &mut dyn Write,
) -> Result<()> {
    let Some(session) = store.load()? else {
        writeln!(output, "signed out")?;
        return Ok(());
    };
    let issuer = match bound_issuer(&session, expected) {
        Ok(issuer) => issuer,
        Err(error) if session.issuer.is_empty() => {
            store.delete()?;
            return Err(error).context("legacy session removed locally; sign in again");
        }
        Err(error) => return Err(error),
    };

    // Do not construct a client until all local issuer checks have passed.
    // That ordering is the zero-request boundary for a mismatched override.
    let remote = AuthHttp::new(&issuer).and_then(|http| http.revoke(session.access_token.expose()));
    store.delete()?;
    if let Err(error) = remote {
        writeln!(
            errors,
            "local session removed; remote revocation could not be confirmed: {error:#}"
        )?;
    }
    writeln!(output, "signed out")?;
    Ok(())
}

fn unix_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn absolute_path(path: &str) -> Result<std::path::PathBuf> {
    let path = std::path::PathBuf::from(path);
    if path.is_absolute() {
        return Ok(path);
    }
    Ok(std::env::current_dir()?.join(path))
}

fn inspect_backup(source: &str, json: bool) -> Result<()> {
    let source = absolute_path(source)?;
    let manifest = asterism_core::backup::verify(&source)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&manifest)?);
        return Ok(());
    }
    println!("{}  {}", manifest.instance.name, manifest.instance.id);
    println!(
        "{} file(s), {} logical bytes, format {}",
        manifest.files.len(),
        manifest.files.iter().map(|file| file.len).sum::<u64>(),
        manifest.version
    );
    if let Some(image) = manifest.image {
        println!("image: {}  {}", image.reference, image.content);
    }
    if let Some(materialization) = manifest.materialization {
        println!(
            "guest: {}/{}  machine: {}",
            materialization.platform.os,
            materialization.platform.architecture,
            materialization.machine
        );
        if let Some(root) = materialization.root_disk {
            println!("root disk: {} ({})", root.path, root.format);
        }
        if let Some(oci) = materialization.oci {
            println!(
                "OCI manifest: {} for {}/{}",
                oci.manifest_digest, oci.platform.os, oci.platform.architecture
            );
        }
    } else {
        println!("materialization: legacy byte-portable backup (architecture unknown)");
    }
    println!(
        "external parts to rebind: {} volume(s), {} secret(s), {} gpu(s)",
        manifest.rebind.volumes.len(),
        manifest.rebind.secrets.len(),
        usize::from(manifest.rebind.gpu.is_some())
    );
    Ok(())
}

// ---- secrets ---------------------------------------------------------------

fn secret_command(command: SecretCommand, device: Option<&str>) -> Result<()> {
    let request = match command {
        SecretCommand::Create { name } => Request::SecretCreate {
            name,
            value: read_secret_stdin()?,
            source_device: device.map(str::to_owned),
        },
        SecretCommand::Ls => {
            local_only("secret ls", device)?;
            Request::SecretList
        }
        SecretCommand::Rm { name } => {
            local_only("secret rm", device)?;
            Request::SecretRemove { name }
        }
        SecretCommand::Rotate { name } => {
            local_only("secret rotate", device)?;
            Request::SecretRotate {
                name,
                value: read_secret_stdin()?,
            }
        }
    };

    match send(&request)? {
        Response::Secrets { secrets } => match request {
            Request::SecretRemove { name } => println!("{name}  removed from all sources"),
            Request::SecretCreate { ref name, .. } => {
                let secret = secrets.iter().find(|secret| secret.name == *name);
                if let Some(secret) = secret {
                    println!(
                        "{}  version {}  {} source{}",
                        secret.name,
                        secret.version,
                        secret.sources.len(),
                        if secret.sources.len() == 1 { "" } else { "s" }
                    );
                } else {
                    print_secrets(&secrets);
                }
            }
            _ => print_secrets(&secrets),
        },
        Response::Error { message } => bail!(message),
        _ => bail!("unexpected reply from astd: {request:?}"),
    }
    Ok(())
}

fn read_secret_stdin() -> Result<asterism_core::protocol::SecretValue> {
    let mut stdin = std::io::stdin();
    if stdin.is_terminal() {
        bail!(
            "secret values are read from stdin, never argv; pipe the exact bytes, for example: \
             printf %s \"$TOKEN\" | ast secret create NAME"
        );
    }
    let mut value = Vec::new();
    stdin
        .read_to_end(&mut value)
        .context("reading secret value from stdin")?;
    if value.is_empty() {
        bail!("refusing an empty secret value from stdin");
    }
    Ok(asterism_core::protocol::SecretValue::new(value))
}

fn print_secrets(secrets: &[asterism_core::secret::Secret]) {
    println!("{:<28} {:<9} SOURCES", "NAME", "VERSION");
    for secret in secrets {
        let sources = secret
            .sources
            .iter()
            .map(|source| {
                if source.version == secret.version {
                    source.device.clone()
                } else {
                    format!("{}@v{}", source.device, source.version)
                }
            })
            .collect::<Vec<_>>()
            .join(", ");
        println!("{:<28} {:<9} {}", secret.name, secret.version, sources);
    }
}

/// Puts a request in the envelope `--device` implies.
///
/// The envelope is all `--device` is: the far daemon runs the identical frame
/// its own CLI would have handed it, which is why no command needed a second
/// implementation to become remote.
fn aimed(request: Request, device: Option<&str>) -> Request {
    match device {
        Some(name) => Request::Proxy {
            device: name.to_owned(),
            inner: Box::new(request),
        },
        None => request,
    }
}

/// Refuses `--device` on a command that could not mean anything remotely.
fn local_only(what: &str, device: Option<&str>) -> Result<()> {
    match device {
        Some(name) => bail!(
            "ast {what} is about this device, so it cannot be aimed at {name:?} \
             — run it on {name} instead"
        ),
        None => Ok(()),
    }
}

// ---- the orbit -------------------------------------------------------------

/// `ast devices`, in the shape `tailscale status` has: who is here, what
/// they are called, and whether they are answering right now.
fn print_devices() -> Result<()> {
    let devices = match send(&Request::Devices)? {
        Response::Devices { devices } => devices,
        Response::Error { message } => bail!(message),
        other => bail!("unexpected reply from astd: {other:?}"),
    };
    println!(
        "{:<24} {:<14} {:<8} {:<7} {:>8}  {:<34} RECOVERY",
        "NAME", "DEVICE ID", "STATUS", "PATH", "RTT", "TRANSITION"
    );
    for d in &devices {
        let status = if d.online { "online" } else { "offline" };
        let name = if d.is_self {
            format!("{} (this device)", d.name)
        } else {
            d.name.clone()
        };
        let rtt = d
            .rtt_micros
            .map(|us| format!("{:.1}ms", us as f64 / 1_000.0))
            .unwrap_or_else(|| "-".into());
        println!(
            "{:<24} {:<14} {:<8} {:<7} {:>8}  {:<34} {}",
            name,
            d.short_id(),
            status,
            d.path,
            rtt,
            d.transition_reason.as_deref().unwrap_or("-"),
            d.recovery_result.as_deref().unwrap_or("-"),
        );
    }
    if devices.len() == 1 {
        println!("\nno other devices yet — add one with: ast device invite");
    }
    Ok(())
}

fn ping(device: &str) -> Result<()> {
    match send(&Request::DevicePing {
        device: device.into(),
    })? {
        Response::DevicePong {
            device,
            device_id,
            path,
            millis,
        } => {
            let short: String = device_id.chars().take(12).collect();
            println!("pong from {device} ({short}) via {path} in {millis:.1}ms");
            Ok(())
        }
        Response::Error { message } => bail!(message),
        other => bail!("unexpected reply from astd: {other:?}"),
    }
}

/// `ast compat` — what this build speaks, what the daemon speaks, and what
/// the two of them settled on.
///
/// The command a half-finished upgrade sends people to, so it is built to
/// survive one. This build's own table needs nothing but constants; the
/// daemon's half is asked for and may not arrive, and when it does not the
/// output says which half is missing rather than failing whole. The daemon
/// leg is also the one command in this CLI that is newer than the wire it
/// travels on, so it is the working example of a frame being withheld: a
/// daemon at protocol 1 is never sent it.
fn print_compat(json: bool) -> Result<()> {
    let mut table = compat::Compat::current();
    let mut trouble: Option<String> = None;

    match Client::open() {
        Ok(mut client) => {
            let speaking = client.spoken;
            let facts = client.daemon.clone();
            // Ask the daemon for its own table only if the version in force
            // carries the frame. This is the whole mechanism, used on itself.
            let daemon_asterism = if Request::Compat.speakable_at(speaking) {
                match client.ask(&Request::Compat) {
                    Ok(Response::Compat { compat }) => compat.asterism,
                    Ok(Response::Error { message }) => {
                        trouble = Some(message);
                        facts.version.clone()
                    }
                    Ok(other) => {
                        trouble = Some(format!("unexpected reply from astd: {other:?}"));
                        facts.version.clone()
                    }
                    Err(e) => {
                        trouble = Some(format!("{e:#}"));
                        facts.version.clone()
                    }
                }
            } else {
                trouble = Some(format!(
                    "astd {} speaks protocol {speaking}, which predates the compat \
                     frame — the daemon's own table is not available, and everything \
                     below is this build's",
                    facts.version
                ));
                facts.version.clone()
            };
            table.daemon = Some(compat::DaemonView {
                asterism: daemon_asterism,
                protocol: facts.speaks.max,
                min_supported: facts.speaks.min,
                speaking,
            });
        }
        Err(e) => trouble = Some(format!("{e:#}")),
    }

    if json {
        println!("{}", serde_json::to_string_pretty(&table)?);
        return Ok(());
    }

    println!(
        "ast {}  speaks {}",
        table.asterism,
        describe(table.min_supported, table.protocol)
    );
    match &table.daemon {
        Some(daemon) => println!(
            "astd {}  speaks {}  —  talking at protocol {}",
            daemon.asterism,
            describe(daemon.min_supported, daemon.protocol),
            daemon.speaking
        ),
        None => println!("astd       not reachable"),
    }
    if let Some(why) = &trouble {
        println!("\n{why}");
    }

    println!("\nframes newer than the wire itself:");
    for (name, version) in &table.frames {
        println!("  {name:<20} protocol {version}");
    }
    println!("\non-disk formats this build writes:");
    for (name, version) in &table.stores {
        println!("  {name:<20} version {version}");
    }
    println!("\nwhat this build does about a peer that speaks:");
    println!(
        "  {:<18} {:<9} {:<9} then",
        "peer speaks", "as daemon", "as peer"
    );
    for row in &table.matrix {
        println!(
            "  {:<18} {:<9} {:<9} {}",
            describe(row.peer_min, row.peer_max),
            row.daemon_action,
            row.peer_action,
            match row.speaks {
                Some(v) => format!("protocol {v}"),
                None => "nothing in common".to_owned(),
            }
        );
    }
    Ok(())
}

fn describe(min: u32, max: u32) -> String {
    if min == max {
        format!("protocol {max}")
    } else {
        format!("protocols {min}-{max}")
    }
}

fn device_command(cmd: DeviceCommand) -> Result<()> {
    match cmd {
        DeviceCommand::Ls => print_devices(),
        DeviceCommand::Rm { name } => {
            send_ok(&Request::DeviceRemove { name: name.clone() })?;
            println!("{name}  removed from this orbit");
            Ok(())
        }
        DeviceCommand::Invite { name, ttl, yes } => pair(
            Request::DeviceInvite {
                name,
                ttl_secs: ttl,
            },
            yes,
        ),
        DeviceCommand::Add { ticket, name, yes } => pair(Request::DeviceAdd { ticket, name }, yes),
        DeviceCommand::Wake { name } => wake(&name),
        DeviceCommand::Shell { action } => device_shell_policy(action),
        // Routed before this, so that `--device` can aim it.
        DeviceCommand::Check => device_check(None),
    }
}

fn device_shell_policy(action: Option<DeviceShellCommand>) -> Result<()> {
    let action = match action.unwrap_or(DeviceShellCommand::Status) {
        DeviceShellCommand::Status => ShellPolicyAction::Status,
        DeviceShellCommand::Enable => ShellPolicyAction::Enable,
        DeviceShellCommand::Disable => ShellPolicyAction::Disable,
    };
    let response = match action {
        ShellPolicyAction::Status => {
            let mut client = Client::open()?;
            // Protocol 4 already had a local status action. Prefer the new
            // read-only capability, but keep status useful during a rolling
            // upgrade where the local daemon is one version behind.
            let request = if Request::DeviceShellStatus.speakable_at(client.spoken) {
                Request::DeviceShellStatus
            } else {
                Request::DeviceShellPolicy { action }
            };
            client.ask(&request)?
        }
        ShellPolicyAction::Enable | ShellPolicyAction::Disable => {
            send(&Request::DeviceShellPolicy { action })?
        }
    };
    let (status, revoked) = match response {
        Response::DeviceShellStatus { status, revoked } => (status, revoked),
        Response::Error { message } => bail!(message),
        other => bail!("unexpected reply from astd: {other:?}"),
    };
    let state = match status.state {
        ShellPolicyState::Disabled => "disabled",
        ShellPolicyState::EnabledOrbit => "enabled for the approved orbit",
        ShellPolicyState::Active => "active",
        ShellPolicyState::Unavailable => "unavailable",
    };
    println!("device shell: {state}  epoch {}", status.epoch);
    if let Some(reason) = status.unavailable_reason {
        println!("{reason}");
    }
    if matches!(action, ShellPolicyAction::Enable) {
        println!(
            "warning: every device currently in this orbit now has this user account's full \
             authority. Disabling terminates sessions Asterism tracks; it cannot undo files \
             copied, commands already run, or persistence installed by a trusted peer."
        );
    }
    if revoked != 0 {
        println!("device shell disabled — {revoked} active session(s) cut");
    }
    for session in status
        .active
        .into_iter()
        .filter(|_| !matches!(action, ShellPolicyAction::Disable))
    {
        println!(
            "{}  {} ({})  since {}  {}",
            session.session_id,
            session.peer_name,
            session.peer_device_id,
            session.started_at,
            if session.pty { "pty" } else { "command" }
        );
    }
    Ok(())
}

// ---- parts -----------------------------------------------------------------

/// `ast set <instance> compute <device>`, and its aliases `cpu` and `ast move`.
///
/// The daemon does all of it — resolving the instance across the orbit,
/// probing the target, fencing the source, moving the bytes and committing —
/// and reports each step as it happens, because the middle one is a disk
/// crossing a network and takes as long as it takes. All this end does is
/// print. The wire command remains `set_cpu` so older daemons still parse it.
fn set_part(name: &str, part: &str, device: &str, down: bool) -> Result<()> {
    // Compute is one placement unit; CPU and physical RAM cannot be placed
    // independently.
    if !asterism_core::instance::is_compute_part(part) {
        bail!(
            "there is no {part:?} placement part. `ast set <instance> compute <device>` \
             moves whole compute (CPU, physical RAM, and execution state); `cpu` and \
             `ast move` remain aliases. Volumes are changed with \
             `ast attach` and `ast detach`"
        );
    }
    let mut conn = Conversation::open(&Request::SetCpu {
        name: name.to_owned(),
        device: device.to_owned(),
        down,
    })?;
    loop {
        match conn.next()? {
            Response::Move { text, done } => {
                println!("{text}");
                if done {
                    return Ok(());
                }
            }
            Response::Error { message } => bail!(message),
            other => bail!("unexpected reply from astd: {other:?}"),
        }
    }
}

// ---- power and presence ----------------------------------------------------

/// `ast device wake <name>`.
///
/// The daemon does the deciding — who on the sleeper's LAN is awake, and
/// whether that is this device or a peer — and reports each step as it
/// happens, because the last one is a machine booting and takes as long as it
/// takes. All this end does is print, and add the one thing the daemon should
/// not put in an error message: what to do about it.
fn wake(name: &str) -> Result<()> {
    let mut conn = Conversation::open(&Request::DeviceWake { name: name.into() })?;
    loop {
        match conn.next()? {
            Response::Wake { text, done } => {
                println!("{text}");
                if done {
                    return Ok(());
                }
            }
            Response::Error { message } => {
                if message.starts_with("no awake device on ") {
                    eprintln!(
                        "\nA magic packet has to be broadcast from inside {name}'s own\n\
                         network, so waking it needs an orbit device that is awake there.\n\
                         One always-on machine on that LAN — a Raspberry Pi is plenty —\n\
                         makes this work every time; it is the orbit's beacon."
                    );
                }
                bail!(message);
            }
            other => bail!("unexpected reply from astd: {other:?}"),
        }
    }
}

/// `ast device check`, optionally aimed at another device.
///
/// Prints a table whose point is the `?` rows: almost nothing about waking
/// can be verified from the machine that would be the one asleep, and a user
/// about to depend on it deserves the list of what nobody checked.
fn device_check(device: Option<&str>) -> Result<()> {
    let request = aimed(Request::DeviceCheck, device);
    let (device, rows) = match send(&request)? {
        Response::WakeCheck { device, rows } => (device, rows),
        Response::Error { message } => bail!(message),
        other => bail!("unexpected reply from astd: {other:?}"),
    };

    println!("wake readiness for {device}\n");
    let width = rows.iter().map(|r| r.item.len()).max().unwrap_or(0).max(4);
    for r in &rows {
        println!("{:<width$}  {:<4}  {}", r.item, r.verdict.label(), r.detail);
    }
    println!("\n?  means this device cannot check it — not that it is fine");
    Ok(())
}

/// Both halves of pairing, which are the same conversation seen from two
/// terminals: the daemon sends what to print, we print it, and when the six
/// digits arrive we ask the human before anything is written down.
fn pair(request: Request, yes: bool) -> Result<()> {
    let mut conn = Conversation::open(&request)?;
    loop {
        match conn.next()? {
            Response::Ticket {
                ticket,
                expires_in_secs,
            } => {
                println!("give this to the other device, within {expires_in_secs}s:\n");
                println!("  ast device add {ticket}\n");
                println!("waiting for a device to redeem it ...");
            }
            Response::Sas { code, peer, .. } => {
                println!("\ndevice {peer} wants to join this orbit.");
                println!("both terminals must show the same six digits:\n");
                println!("      {code}\n");
                if !confirmed(yes)? {
                    conn.send(&Request::PairConfirm { accept: false })?;
                    // The daemon tells the other device, then answers us.
                    let _ = conn.next();
                    bail!("pairing refused — nothing was added to this orbit");
                }
                conn.send(&Request::PairConfirm { accept: true })?;
            }
            Response::Paired { device } => {
                println!("{}  {}  paired", device.name, device.short_id());
                return Ok(());
            }
            Response::Error { message } => bail!(message),
            other => bail!("unexpected reply from astd: {other:?}"),
        }
    }
}

/// Asks the question a pairing turns on. Refuses to assume a `yes` from
/// anything but a real answer or an explicit `--yes`.
fn confirmed(yes: bool) -> Result<bool> {
    if yes {
        println!("--yes given: taking the codes as matching");
        return Ok(true);
    }
    print!("do they match? [y/N] ");
    std::io::stdout().flush()?;
    let mut answer = String::new();
    if std::io::stdin().read_line(&mut answer)? == 0 {
        return Ok(false);
    }
    Ok(matches!(answer.trim(), "y" | "Y" | "yes" | "YES"))
}

// ---- images ----------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ImagePath {
    DeviceProtocol,
    LocalCore,
}

/// Select the image implementation without opening a connection or touching
/// the image store. Aimed image commands are carried by the outer proxy and
/// negotiate their image frames with the selected device; only a local
/// protocol-1-through-5 daemon needs the core fallback.
fn image_path(device: Option<&str>, spoken: u32) -> ImagePath {
    let image_pull = Request::ImagePull {
        reference: String::new(),
    };
    if device.is_some() || image_pull.speakable_at(spoken) {
        ImagePath::DeviceProtocol
    } else {
        ImagePath::LocalCore
    }
}

fn images_here() -> Result<()> {
    let mut client = Client::open()?;
    match image_path(None, client.spoken) {
        ImagePath::DeviceProtocol => match client.ask(&Request::ImageList)? {
            Response::Images { images } => print_image_rows(&images),
            Response::Error { message } => bail!(message),
            other => bail!("unexpected image catalog reply from astd: {other:?}"),
        },
        ImagePath::LocalCore => print_image_rows(&image::catalog_rows()?),
    }
}

fn pull_here(reference: &str) -> Result<()> {
    let mut client = Client::open()?;
    let result = match image_path(None, client.spoken) {
        ImagePath::DeviceProtocol => pull_image_with_client(&mut client, reference)?,
        ImagePath::LocalCore => pull_image_locally(reference)?,
    };
    print_image_pull(&result)
}

/// Make an image available on the device that will own the next operation.
///
/// A remote create first reads the remote catalog and only then asks that same
/// device to pull. The local catalog is never used as evidence for a remote
/// host, even when both devices happen to share an image reference.
fn ensure_image_on_device(device: Option<&str>, reference: &str) -> Result<String> {
    let canonical = canonical_image_reference(reference);
    if let Some(device) = device {
        let rows = match send(&aimed(Request::ImageList, Some(device)))? {
            Response::Images { images } => images,
            Response::Error { message } => bail!(message),
            other => bail!("unexpected image catalog reply from astd: {other:?}"),
        };
        if rows
            .iter()
            .any(|row| row.reference == canonical && row.pulled && row.verified)
        {
            return Ok(canonical);
        }
        let result = pull_image(Some(device), reference)?;
        return Ok(result.reference);
    }

    // ImageList and ImagePull were added together at protocol 6. A new CLI
    // can still be talking to a local daemon from protocols 1 through 5,
    // where Client::ask must refuse those frames. Keep the device-owned
    // protocol path for a daemon that can speak it, but use the same core
    // pull implementation locally for the rolling-compatibility window.
    let mut client = Client::open()?;
    if image_path(None, client.spoken) == ImagePath::DeviceProtocol {
        let rows = match client.ask(&Request::ImageList)? {
            Response::Images { images } => images,
            Response::Error { message } => bail!(message),
            other => bail!("unexpected image catalog reply from astd: {other:?}"),
        };
        if rows
            .iter()
            .any(|row| row.reference == canonical && row.pulled && row.verified)
        {
            return Ok(canonical);
        }
        let result = pull_image_with_client(&mut client, reference)?;
        return Ok(result.reference);
    }

    let result = pull_image_locally(reference)?;
    Ok(result.reference)
}

fn pull_image(
    device: Option<&str>,
    reference: &str,
) -> Result<asterism_core::image::ImagePullResult> {
    let response = send(&aimed(
        Request::ImagePull {
            reference: reference.to_owned(),
        },
        device,
    ))?;
    match response {
        Response::ImagePulled { result } => {
            report_image_pull(&result);
            Ok(*result)
        }
        Response::Error { message } => bail!(message),
        other => bail!("unexpected image pull reply from astd: {other:?}"),
    }
}

fn pull_image_with_client(
    client: &mut Client,
    reference: &str,
) -> Result<asterism_core::image::ImagePullResult> {
    match client.ask(&Request::ImagePull {
        reference: reference.to_owned(),
    })? {
        Response::ImagePulled { result } => {
            report_image_pull(&result);
            Ok(*result)
        }
        Response::Error { message } => bail!(message),
        other => bail!("unexpected image pull reply from astd: {other:?}"),
    }
}

fn pull_image_locally(reference: &str) -> Result<asterism_core::image::ImagePullResult> {
    let result = image::pull(reference)?;
    report_image_pull(&result);
    Ok(result)
}

fn report_image_pull(result: &asterism_core::image::ImagePullResult) {
    for progress in &result.progress {
        if progress.done {
            eprintln!("{} ({} bytes)", progress.phase, progress.bytes);
        } else {
            eprintln!("{}", progress.phase);
        }
    }
}

fn canonical_image_reference(reference: &str) -> String {
    image::DEFAULTS
        .iter()
        .find(|(bare, _)| *bare == reference)
        .map(|(_, full)| (*full).to_owned())
        .or_else(|| oci::parse(reference).map(|parsed| parsed.canonical()))
        .unwrap_or_else(|| reference.to_owned())
}

/// Only the part every Docker Hub library image shares is dropped, and only
/// for display: `docker.io/library/nginx:latest` is what is recorded, what
/// `ast status` prints, and what `--image` accepts, because it is the name
/// that means one thing everywhere. `nginx:latest` is what a column has room
/// for.
fn short_image(reference: &str) -> String {
    reference
        .strip_prefix("docker.io/library/")
        .unwrap_or(reference)
        .to_owned()
}

fn print_image_rows(images: &[asterism_core::image::ImageRow]) -> Result<()> {
    println!(
        "{:<30} {:<10} {:<8} {:>12} SOURCE",
        "REFERENCE", "KIND", "STATE", "BYTES"
    );
    for image in images {
        let state = if !image.pulled {
            "missing"
        } else if image.verified {
            "ready"
        } else {
            "bad"
        };
        println!(
            "{:<30} {:<10} {:<8} {:>12} {}",
            image.reference, image.kind, state, image.bytes, image.source
        );
    }
    Ok(())
}

fn print_image_pull(result: &asterism_core::image::ImagePullResult) -> Result<()> {
    println!(
        "{}  {} image ready ({} bytes{})",
        result.reference,
        result.kind,
        result.bytes,
        result
            .digest
            .as_deref()
            .map(|digest| format!(", {digest}"))
            .unwrap_or_default()
    );
    Ok(())
}

// ---- volumes ---------------------------------------------------------------

/// Read `--volume` as an orbit storage part, or decide it is a directory.
///
/// `<device>:<volume>` is the written form. A bare name plus `--host` is
/// accepted too, while a path plus a remote `--host` reaches `volume_path`
/// and is refused: directory sharing has no network transport.
fn storage_ref(volume: &str, host: Option<&str>) -> Option<(Option<String>, String)> {
    if let Some((device, name)) = asterism_core::volume::parse_ref(volume) {
        return Some((Some(device), name));
    }
    let looks_like_a_path =
        volume.starts_with('/') || volume.starts_with('.') || volume.starts_with('~');
    (!looks_like_a_path && asterism_core::volume::check_name(volume).is_ok())
        .then(|| (host.map(str::to_owned), volume.to_owned()))
}

/// `ast volume ls`.
fn print_volumes(volumes: &[asterism_core::volume::BlockVolume]) {
    if volumes.is_empty() {
        println!("no volumes on this device — make one: ast volume create tank --size 100G");
        return;
    }
    // No "used" column: the bytes may be on a device this process cannot
    // see, and a column that is right locally and blank remotely teaches the
    // wrong thing about where volumes live.
    println!("{:<20} {:>8}  {:<6} HELD BY", "NAME", "SIZE", "AGE");
    for v in volumes {
        println!(
            "{:<20} {:>8}  {:<6} {}",
            v.name,
            asterism_core::volume::format_size(v.size_bytes),
            age(v.created_at),
            v.holder_summary(),
        );
    }
}

/// `ast volume ls`: one catalog, with provider and access semantics stated
/// on every row instead of making the user query devices one at a time.
fn print_volume_catalog(catalog: &asterism_core::volume::Catalog) {
    if catalog.volumes.is_empty() {
        println!(
            "no volumes in the reachable orbit — make one: ast volume create tank --size 100G"
        );
    } else {
        println!(
            "{:<20} {:<14} {:>8} {:>9} {:<13} {:<14} HELD BY",
            "NAME", "OWNER", "SIZE", "LATENCY", "DURABILITY", "SHARING"
        );
        for part in &catalog.volumes {
            let latency = match part.latency_micros {
                Some(0) => "local".to_owned(),
                Some(us) if us < 1000 => format!("{us}us"),
                Some(us) => format!("{:.1}ms", us as f64 / 1000.0),
                None => "unknown".to_owned(),
            };
            println!(
                "{:<20} {:<14} {:>8} {:>9} {:<13} {:<14} {}",
                part.volume.name,
                part.owner_device,
                asterism_core::volume::format_size(part.volume.size_bytes),
                latency,
                part.volume.durability,
                part.volume.sharing,
                part.volume.holder_summary(),
            );
        }
    }
    for provider in &catalog.unreachable {
        eprintln!(
            "unreachable storage provider {} ({}): {}",
            provider.device,
            provider.device_id.chars().take(12).collect::<String>(),
            provider.reason
        );
    }
}

/// `ast volume create`. Says what the thing is, because an empty block device
/// is not self-explanatory and the next step is not obvious.
fn print_volume_made(volumes: &[asterism_core::volume::BlockVolume]) {
    let Some(v) = volumes.first() else { return };
    println!(
        "{}  {}  created",
        v.name,
        asterism_core::volume::format_size(v.size_bytes)
    );
    println!("no filesystem on it yet — the guest that attaches it puts one there");
}

/// A volume on this device may be named the way the user's shell would name
/// it — relative, or with a `~`. The daemon runs elsewhere with its own
/// working directory, so resolve it here, where the user's cwd is. A volume
/// on another device has to be named absolutely; we cannot see its disk.
fn volume_path(volume: &str, host: Option<&str>) -> Result<String> {
    let remote = host.is_some_and(|h| h != asterism_core::instance::local_host());
    if remote {
        bail!(
            "a directory on another device cannot be attached — create an orbit block volume \
             there and attach it as <device>:<volume>"
        );
    }
    let expanded = match (volume.strip_prefix("~/"), std::env::var("HOME")) {
        (Some(rest), Ok(home)) => format!("{home}/{rest}"),
        _ => volume.to_owned(),
    };
    let path = std::path::PathBuf::from(&expanded);
    if path.is_absolute() {
        return Ok(expanded);
    }
    Ok(std::env::current_dir()
        .context("resolving the volume path against the current directory")?
        .join(path)
        .display()
        .to_string())
}

// ---- ssh -------------------------------------------------------------------

/// Open the explicitly enabled user shell of one device over the existing
/// daemon connection and mesh. No TCP socket and no ssh process is involved.
fn device_shell(device: &str, words: &[String], force_pty: bool) -> Result<()> {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{mpsc, Arc};

    let stdin_is_terminal = std::io::stdin().is_terminal();
    let pty = force_pty || (words.is_empty() && stdin_is_terminal);
    let (cols, rows) = if pty { terminal_size() } else { (0, 0) };
    let command = (!words.is_empty()).then(|| words.join(" "));
    let open = ShellOpen {
        command,
        pty,
        cols,
        rows,
        env: shell_environment(),
    };
    let mut conn = Conversation::open(&Request::DeviceShellOpen {
        device: device.to_owned(),
        open,
    })?;
    match conn.next()? {
        Response::DeviceShellAccepted { .. } => {}
        Response::DeviceShellRefused { code, message } => bail!("{code}: {message}"),
        Response::Error { message } => bail!(message),
        other => bail!("unexpected reply opening a device shell: {other:?}"),
    }

    let raw = if pty && stdin_is_terminal {
        Some(RawTerminal::enter()?)
    } else {
        None
    };
    let Conversation {
        mut write,
        mut read,
    } = conn;
    let (requests, request_rx) = mpsc::sync_channel::<Request>(8);
    let _writer = std::thread::spawn(move || {
        while let Ok(request) = request_rx.recv() {
            if write_line(&mut write, &request).is_err() {
                break;
            }
        }
    });

    let input_requests = requests.clone();
    std::thread::spawn(move || {
        let mut stdin = std::io::stdin();
        let mut buf = vec![0u8; MAX_DATA_BYTES];
        loop {
            match stdin.read(&mut buf) {
                Ok(0) => {
                    let _ = input_requests.send(Request::DeviceShellEof);
                    return;
                }
                Ok(n) => {
                    let data = ShellData::new(buf[..n].to_vec()).expect("stdin reader obeyed cap");
                    if input_requests
                        .send(Request::DeviceShellInput { data })
                        .is_err()
                    {
                        return;
                    }
                }
                Err(_) => {
                    let _ = input_requests.send(Request::DeviceShellClose);
                    return;
                }
            }
        }
    });

    let stop_resize = Arc::new(AtomicBool::new(false));
    if pty && stdin_is_terminal {
        let resize_requests = requests.clone();
        let stop = stop_resize.clone();
        std::thread::spawn(move || {
            let mut previous = terminal_size();
            while !stop.load(Ordering::Relaxed) {
                std::thread::sleep(Duration::from_millis(100));
                let now = terminal_size();
                if now != previous {
                    previous = now;
                    let _ = resize_requests.try_send(Request::DeviceShellResize {
                        cols: now.0,
                        rows: now.1,
                    });
                }
            }
        });
    }

    let exit = loop {
        let response = match read_frame(&mut read)? {
            Some(line) => serde_json::from_str::<Response>(&line)?,
            None => bail!("astd closed the device-shell connection without an exit status"),
        };
        match response {
            Response::DeviceShellOutput { stream, data } => {
                let written = match stream {
                    ShellOutput::Pty | ShellOutput::Stdout => {
                        let mut stdout = std::io::stdout();
                        stdout
                            .write_all(data.as_bytes())
                            .and_then(|()| stdout.flush())
                    }
                    ShellOutput::Stderr => {
                        let mut stderr = std::io::stderr();
                        stderr
                            .write_all(data.as_bytes())
                            .and_then(|()| stderr.flush())
                    }
                };
                if let Err(e) = written {
                    if e.kind() == std::io::ErrorKind::BrokenPipe {
                        let _ = requests.try_send(Request::DeviceShellClose);
                        break asterism_core::device_shell::ShellExit {
                            code: Some(0),
                            signal: None,
                            core_dumped: false,
                            reason: None,
                        };
                    }
                    return Err(e).context("writing device-shell output");
                }
            }
            Response::DeviceShellExit { exit } => break exit,
            Response::DeviceShellRefused { code, message } => bail!("{code}: {message}"),
            Response::Error { message } => bail!(message),
            other => bail!("unexpected reply during a device shell: {other:?}"),
        }
    };

    stop_resize.store(true, Ordering::Relaxed);
    drop(requests);
    // stdin may legitimately still be blocked on an interactive terminal
    // after a remote command exits. The process is about to return the remote
    // status, so waiting for that reader (and therefore for the writer's last
    // sender) would turn a completed command into a hang.
    drop(raw);
    if let Some(reason) = &exit.reason {
        eprintln!("device shell ended: {reason}");
    }
    let code = exit
        .code
        .or_else(|| exit.signal.map(|signal| 128 + signal))
        .unwrap_or(1)
        .clamp(0, 255);
    std::process::exit(code);
}

fn shell_environment() -> Vec<ShellEnv> {
    let mut result = Vec::new();
    let mut bytes = 0usize;
    for (name, value) in std::env::vars() {
        let allowed =
            matches!(name.as_str(), "TERM" | "COLORTERM" | "LANG") || name.starts_with("LC_");
        let next = name.len().saturating_add(value.len());
        if allowed
            && value.len() <= asterism_core::device_shell::MAX_ENV_VALUE_BYTES
            && result.len() < asterism_core::device_shell::MAX_ENV_VARS
            && bytes.saturating_add(next) <= asterism_core::device_shell::MAX_ENV_BYTES
        {
            bytes += next;
            result.push(ShellEnv { name, value });
        }
    }
    result
}

#[cfg(unix)]
fn terminal_size() -> (u16, u16) {
    let fd = libc::STDIN_FILENO;
    let mut size = libc::winsize {
        ws_row: 0,
        ws_col: 0,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    // SAFETY: size is writable and fd is only queried.
    if unsafe { libc::ioctl(fd, libc::TIOCGWINSZ as _, &mut size) } == 0
        && (1..=1000).contains(&size.ws_col)
        && (1..=1000).contains(&size.ws_row)
    {
        (size.ws_col, size.ws_row)
    } else {
        (80, 24)
    }
}

#[cfg(windows)]
fn terminal_size() -> (u16, u16) {
    // The protocol still carries a bounded initial size on Windows. Raw
    // console mode is intentionally left to a future native shell adapter;
    // the current Windows daemon refuses device-shell sessions explicitly.
    (80, 24)
}

#[cfg(unix)]
struct RawTerminal {
    fd: libc::c_int,
    saved: libc::termios,
}

#[cfg(unix)]
impl RawTerminal {
    fn enter() -> Result<Self> {
        let fd = libc::STDIN_FILENO;
        let mut saved = std::mem::MaybeUninit::<libc::termios>::uninit();
        // SAFETY: saved points to valid storage and fd is the terminal already
        // identified by IsTerminal.
        if unsafe { libc::tcgetattr(fd, saved.as_mut_ptr()) } != 0 {
            return Err(std::io::Error::last_os_error()).context("reading terminal mode");
        }
        let saved = unsafe { saved.assume_init() };
        let mut raw = saved;
        unsafe {
            libc::cfmakeraw(&mut raw);
        }
        if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &raw) } != 0 {
            return Err(std::io::Error::last_os_error()).context("entering raw terminal mode");
        }
        Ok(Self { fd, saved })
    }
}

#[cfg(unix)]
impl Drop for RawTerminal {
    fn drop(&mut self) {
        // SAFETY: saved came from this descriptor and remains initialized.
        unsafe {
            libc::tcsetattr(self.fd, libc::TCSANOW, &self.saved);
        }
    }
}

#[cfg(windows)]
struct RawTerminal;

#[cfg(windows)]
impl RawTerminal {
    fn enter() -> Result<Self> {
        Ok(Self)
    }
}

/// `ast ssh <name>`, from anywhere in the orbit.
///
/// The daemon answers with a loopback address whichever device is running the
/// guest: its own forwarded port when the guest is here, or an ephemeral
/// listener spliced over the mesh when it is not. Nothing below this line
/// knows the difference, and neither does the user.
///
/// The connection to the daemon is deliberately held open for the whole
/// session rather than `exec`'d away, because on the spliced path that socket
/// *is* the lease on the listener: when ssh exits and this process drops it,
/// the daemon tears the splice down.
fn ssh(name: &str, command: &[String]) -> Result<()> {
    refuse_ssh_to_an_oci_guest(name)?;
    let mut conn = Conversation::open(&Request::SshEndpoint { name: name.into() })?;
    let (host, port, identity) = match conn.next()? {
        Response::SshEndpoint {
            host,
            port,
            identity,
        } => (host, port, identity),
        Response::Error { message } => bail!(message),
        other => bail!("unexpected reply from astd: {other:?}"),
    };

    // cloud-init needs a little time on first boot. QEMU's user-mode net
    // accepts the TCP connection itself, so a mere connect proves nothing —
    // wait until the guest's sshd actually sends its "SSH-" banner.
    let deadline = std::time::Instant::now() + Duration::from_secs(180);
    let mut waited = false;
    while !ssh_banner_up(&host, port) {
        if std::time::Instant::now() > deadline {
            bail!("guest ssh did not come up within 180s — check: ast logs {name}");
        }
        if !waited {
            eprintln!("waiting for guest ssh (first boot runs cloud-init) ...");
            waited = true;
        }
        std::thread::sleep(Duration::from_millis(750));
    }

    let status = std::process::Command::new("ssh")
        .arg("-i")
        .arg(&identity)
        .args(["-o", "StrictHostKeyChecking=no"])
        .args(["-o", "UserKnownHostsFile=/dev/null"])
        .args(["-o", "LogLevel=ERROR"])
        .args(["-o", "ConnectionAttempts=30"])
        .arg("-p")
        .arg(port.to_string())
        .arg(format!("ast@{host}"))
        .args(command)
        .status()
        .context("running ssh")?;

    // Dropping the daemon connection is the teardown signal, so do it before
    // exiting rather than leaving it to process cleanup.
    drop(conn);
    std::process::exit(status.code().unwrap_or(1));
}

/// `ast ssh` into an OCI instance, said no to early and in full.
///
/// There is no ssh server in a container image and no cloud-init to install
/// one, so the honest answer is this message rather than three minutes of
/// waiting for a banner that is never coming. The answer names the guest
/// control command, console, and any published service ports instead.
fn refuse_ssh_to_an_oci_guest(name: &str) -> Result<()> {
    let Ok(Response::Instance { instance, .. }) = send(&Request::Status { name: name.into() })
    else {
        return Ok(()); // no such instance: let the endpoint request say so
    };
    if instance.image_kind != ImageKind::OciRootfs {
        return Ok(());
    }
    if instance.runtime == RuntimeKind::Container {
        bail!(
            "{name} uses runtime=container and has no SSH endpoint — use `ast shell {name} -- /bin/sh`; output is on `ast logs {name}`"
        );
    }
    let ports: Vec<String> = instance.publish.iter().map(|p| p.to_string()).collect();
    let reach = match ports.is_empty() {
        true => format!(
            "it publishes no ports — recreate it with, say: \
             ast create {name} --image {} -p 8080:80",
            instance.image.as_deref().unwrap_or("<image>")
        ),
        false => format!("it is reachable on {}", ports.join(", ")),
    };
    bail!(
        "{name} boots an OCI image, which has no ssh server in it — \
         run a command with `ast exec {name} -- /bin/sh -c '...'`; \
         its console is `ast logs {name}`, and {reach}"
    )
}

fn ssh_banner_up(host: &str, port: u16) -> bool {
    use std::io::Read;
    use std::net::ToSocketAddrs;
    let Ok(mut addrs) = (host, port).to_socket_addrs() else {
        return false;
    };
    let Some(addr) = addrs.next() else {
        return false;
    };
    let Ok(stream) = std::net::TcpStream::connect_timeout(&addr, Duration::from_millis(500)) else {
        return false;
    };
    let _ = stream.set_read_timeout(Some(Duration::from_secs(3)));
    let mut buf = [0u8; 4];
    let mut stream = stream;
    matches!(stream.read_exact(&mut buf), Ok(())) && &buf == b"SSH-"
}

/// Whether this device's own shard holds `name` — i.e. whether the console
/// log is a file we can open rather than bytes we have to ask for.
fn on_this_device(name: &str) -> Result<bool> {
    match send(&Request::List)? {
        Response::Instances { instances } => Ok(instances.iter().any(|i| i.name == name)),
        Response::Error { message } => bail!(message),
        other => bail!("unexpected reply from astd: {other:?}"),
    }
}

// ---- snapshots -------------------------------------------------------------

/// The instance and tag out of `ast snapshot <instance> [tag]`.
///
/// Hand-checked rather than declared, because the bare form shares its slot
/// with the `rm` subcommand — so the words arrive raw, and the refusals
/// have to be as good as clap's own.
fn snapshot_target(words: &[String]) -> Result<(&str, Option<String>)> {
    match words {
        [name] => Ok((name.as_str(), None)),
        [name, tag] => Ok((name.as_str(), Some(tag.clone()))),
        [] => bail!("which instance? try: ast snapshot <instance> [tag]"),
        [name, tag, extra @ ..] => bail!(
            "a snapshot takes one instance and one tag, so {:?} is {} too many \
             — try: ast snapshot {name} {tag}",
            extra.join(" "),
            extra.len()
        ),
    }
}

fn take_snapshot(name: &str, tag: Option<String>, device: Option<&str>) -> Result<()> {
    let tag = tag.unwrap_or_else(snapshot::timestamped_tag);
    send_ok(&aimed(
        Request::Snapshot {
            name: name.into(),
            tag: tag.clone(),
        },
        device,
    ))?;
    println!("{name}  snapshot {tag}");
    Ok(())
}

fn restore_snapshot(name: &str, tag: &str, device: Option<&str>) -> Result<()> {
    send_ok(&aimed(
        Request::SnapshotRestore {
            name: name.into(),
            tag: tag.into(),
        },
        device,
    ))?;
    println!("{name}  restored to {tag}");
    Ok(())
}

fn remove_snapshot(name: &str, tag: &str, device: Option<&str>) -> Result<()> {
    send_ok(&aimed(
        Request::SnapshotRemove {
            name: name.into(),
            tag: tag.into(),
        },
        device,
    ))?;
    println!("{name}  snapshot {tag} deleted");
    Ok(())
}

fn print_snapshots(name: &str, device: Option<&str>) -> Result<()> {
    let request = aimed(Request::SnapshotList { name: name.into() }, device);
    let snapshots = match send(&request)? {
        Response::Snapshots { snapshots } => snapshots,
        Response::Error { message } => bail!(message),
        other => bail!("unexpected reply from astd: {other:?}"),
    };
    if snapshots.is_empty() {
        println!("no snapshots — take one with: ast snapshot {name}");
        return Ok(());
    }
    // SIZE is what the snapshot occupies, which on a copy-on-write clone
    // starts near zero and grows only as the live disk moves away from it.
    println!("{:<6} {:<26} {:<9} DATE", "ID", "TAG", "SIZE");
    for snap in &snapshots {
        println!(
            "{:<6} {:<26} {:<9} {}",
            snap.id, snap.tag, snap.size, snap.date
        );
    }
    Ok(())
}

// ---- bootstrap profiles ----------------------------------------------------

/// `ast profiles` — what this Asterism knows how to make a guest into.
///
/// The catalog is a constant in this binary rather than something a device
/// holds, so this prints without asking anyone: the daemon is not the
/// authority on what `claude` means, the version of Asterism applying it is.
fn print_profiles() -> Result<()> {
    println!("{:<8} {:<8} WHAT IT ADDS", "PROFILE", "VERSION");
    for profile in asterism_core::profile::CATALOG {
        println!(
            "{:<8} {:<8} {}",
            profile.name, profile.version, profile.summary
        );
        if !profile.requires.is_empty() {
            println!("{:<17} with: {}", "", profile.requires.join(", "));
        }
    }
    println!("\nast create dev --image debian:13 --profile claude");
    println!("ast profile dev --check      # what the guest actually has");
    Ok(())
}

/// `ast profile <instance>` — what this instance is recorded as having.
fn show_profiles(name: &str, device: Option<&str>) -> Result<()> {
    let request = aimed(Request::Status { name: name.into() }, device);
    match send(&request)? {
        Response::Instance { instance, .. } => {
            print_profile_state(&instance);
            Ok(())
        }
        Response::Error { message } => bail!(message),
        other => bail!("unexpected reply from astd: {other:?}"),
    }
}

/// The profile half of an instance, printed after a change and on its own.
///
/// What is printed is what the *record* says, and the record is a promise
/// about the next boot rather than a report on the guest. So a running
/// instance whose set has just changed is told the two commands that make
/// the promise true, and every instance is told where the real answer lives.
fn print_profile_state(inst: &Instance) {
    if inst.profiles.is_empty() {
        println!("{}  no bootstrap profiles", inst.name);
        println!(
            "this guest is whatever its image is — add one with: \
             ast profile {} claude",
            inst.name
        );
        return;
    }
    // Resolved rather than echoed: `claude` on its own is three profiles,
    // and the user should see the three they are getting.
    let resolved = asterism_core::profile::resolve(&inst.profiles);
    let names = match &resolved {
        Ok(profiles) => profiles
            .iter()
            .map(|p| p.name)
            .collect::<Vec<_>>()
            .join(" "),
        // A name this binary does not know is a downgrade, not a typo: the
        // instance was created by a newer Asterism. It is printed as it was
        // recorded, because that is the fact, and the boot that would refuse
        // it says so in its own words.
        Err(_) => inst.profiles.join(" "),
    };
    println!("{}  {names}", inst.name);
    if let Err(e) = &resolved {
        println!("but this ast cannot apply that set: {e:#}");
        return;
    }
    match inst.status {
        asterism_core::instance::Status::Running => println!(
            "the record is what the next boot applies: ast down {0} && ast up {0}",
            inst.name
        ),
        _ => println!("applied at the next boot: ast up {}", inst.name),
    }
    println!(
        "what the guest actually has: ast profile {} --check",
        inst.name
    );
}

/// `ast profile <instance> --check` — ask the guest.
///
/// The verifier is generated into the guest by the same seed that carried
/// the profiles, so it knows exactly what this instance was promised and
/// nothing about what any other one was. Running it over ssh rather than
/// reimplementing it here is the point: the host has opinions about what
/// should be true, and only the guest has facts.
fn check_profiles(name: &str) -> Result<()> {
    // An instance with no profiles has no verifier inside it. Asking the
    // record first turns a later command-not-found into the sentence it
    // should have been, and also selects the control door the image owns.
    let instance = match send(&Request::Status { name: name.into() })? {
        Response::Instance { instance, .. } => instance,
        Response::Error { message } => bail!(message),
        other => bail!("unexpected reply from astd: {other:?}"),
    };
    if instance.profiles.is_empty() {
        bail!(
            "{name} has no bootstrap profiles, so there is nothing in it to ask — \
             ast profile {name} claude, then ast down {name} && ast up {name}"
        );
    }
    // From here the guest answers for itself, and its exit status is this
    // command's. OCI rootfs guests deliberately have no SSH server, so they
    // use the same authenticated bounded guest-control path as `ast exec`;
    // cloud images retain their ordinary SSH path.
    if profile_check_uses_guest_control(instance.image_kind) {
        guest_exec(
            name,
            vec!["/usr/local/sbin/asterism-check".to_owned()],
            asterism_core::guest::MAX_EXEC_TIMEOUT.as_secs(),
        )
    } else {
        ssh(
            name,
            &[
                "sudo".to_owned(),
                "/usr/local/sbin/asterism-check".to_owned(),
            ],
        )
    }
}

fn profile_check_uses_guest_control(kind: ImageKind) -> bool {
    kind == ImageKind::OciRootfs
}

// ---- logs ------------------------------------------------------------------

/// Print the guest's serial console, wherever the guest is.
///
/// When this device is the one supplying the instance's compute, the console
/// is a file in the instance directory and is read straight off disk — which
/// is also the only way `--follow` can work, since following is a file
/// operation and there is no file here otherwise. When compute is elsewhere,
/// the daemon reads it there and sends the tail back.
fn logs(name: &str, follow: bool, lines: u32) -> Result<()> {
    if !on_this_device(name)? {
        if follow {
            bail!(
                "following a console log across the orbit is not built yet — \
                 `ast logs {name}` prints the last lines of it"
            );
        }
        return match send(&Request::Logs {
            name: name.into(),
            lines,
        })? {
            Response::Log { text, truncated } => {
                if truncated {
                    eprintln!("(last {lines} lines — more with: ast logs {name} -n 0)");
                }
                println!("{text}");
                Ok(())
            }
            Response::Error { message } => bail!(message),
            other => bail!("unexpected reply from astd: {other:?}"),
        };
    }
    logs_here(name, follow, lines)
}

/// Execute through a native container's namespace-bound Unix control
/// endpoint. This deliberately shares none of the SSH path.
fn container_shell(name: &str, mut command: Vec<String>) -> Result<()> {
    if command.is_empty() {
        command.push("/bin/sh".into());
    }
    match send(&Request::ContainerExec {
        name: name.into(),
        command,
    })? {
        Response::ContainerExec {
            status,
            stdout,
            stderr,
        } => {
            print!("{stdout}");
            eprint!("{stderr}");
            if status == 0 {
                Ok(())
            } else {
                bail!("container command exited with status {status}")
            }
        }
        Response::Error { message } => bail!(message),
        other => bail!("unexpected reply from astd: {other:?}"),
    }
}

/// Run a command through the VM guest-control protocol and preserve its exit
/// status for scripts. Output was already bounded independently by the guest.
fn guest_exec(name: &str, command: Vec<String>, timeout_secs: u64) -> Result<()> {
    if timeout_secs == 0 || timeout_secs > asterism_core::guest::MAX_EXEC_TIMEOUT.as_secs() {
        bail!(
            "--timeout must be between 1 and {} seconds",
            asterism_core::guest::MAX_EXEC_TIMEOUT.as_secs()
        );
    }
    match send(&Request::Exec {
        name: name.into(),
        command,
        timeout_ms: timeout_secs.saturating_mul(1000),
    })? {
        Response::Exec {
            status,
            stdout,
            stderr,
            stdout_truncated,
            stderr_truncated,
        } => {
            print!("{stdout}");
            eprint!("{stderr}");
            if stdout_truncated {
                eprintln!("ast: guest stdout was truncated at the protocol limit");
            }
            if stderr_truncated {
                eprintln!("ast: guest stderr was truncated at the protocol limit");
            }
            if status == 0 {
                Ok(())
            } else {
                std::process::exit(status.clamp(1, 255));
            }
        }
        Response::Error { message } => bail!(message),
        other => bail!("unexpected reply from astd: {other:?}"),
    }
}

/// The console log as a file on this device's disk.
fn logs_here(name: &str, follow: bool, lines: u32) -> Result<()> {
    let path = paths::instance_dir(name).join("console.log");
    let mut file = File::open(&path).map_err(|_| {
        anyhow::anyhow!(
            "no console log for {name:?} yet — `ast up {name}` starts one at {}",
            path.display()
        )
    })?;

    let mut out = std::io::stdout();
    let (text, truncated) = local_console_tail(&mut file, lines)
        .with_context(|| format!("reading {}", path.display()))?;
    writeln!(out, "{text}")?;
    out.flush()?;
    if truncated {
        eprintln!("(last {lines} lines — more with: ast logs {name} -n 0)");
    }
    if !follow {
        return Ok(());
    }

    // tail -f without the tail: the read cursor stays where the last drain
    // left it, so each poll picks up exactly what the guest appended. A
    // fresh `ast up` truncates the file; that shows up as a shrink, and we
    // reopen rather than sit and wait for the guest to write past the old
    // offset.
    loop {
        std::thread::sleep(Duration::from_millis(250));
        let read_to = file.stream_position()?;
        if std::fs::metadata(&path).map(|m| m.len()).unwrap_or(read_to) < read_to {
            file = File::open(&path)?;
        }
        drain(&mut file, &mut out)?;
    }
}

/// Match the daemon's bounded console-tail contract while retaining the file
/// cursor at EOF so `logs -f` can continue with only newly appended bytes.
fn local_console_tail(file: &mut File, lines: u32) -> Result<(String, bool)> {
    const CONSOLE_TAIL_BYTES: u64 = 4 * 1024 * 1024;

    let size = file.metadata().map(|m| m.len()).unwrap_or(0);
    let from = size.saturating_sub(CONSOLE_TAIL_BYTES);
    let mut clipped = from > 0;
    file.seek(SeekFrom::Start(from))?;

    let mut bytes = Vec::new();
    (&mut *file)
        .take(CONSOLE_TAIL_BYTES)
        .read_to_end(&mut bytes)?;
    let text = String::from_utf8_lossy(&bytes).into_owned();
    let text = if clipped {
        text.split_once('\n')
            .map(|(_, rest)| rest.to_owned())
            .unwrap_or_default()
    } else {
        text
    };
    if lines == 0 {
        return Ok((text, clipped));
    }

    let all: Vec<&str> = text.lines().collect();
    let keep = all.len().min(lines as usize);
    clipped |= keep < all.len();
    Ok((all[all.len() - keep..].join("\n"), clipped))
}

/// Copy everything the file has left to stdout. A closed pipe
/// (`ast logs dev | head`) is a normal way for the reader to stop, not an
/// error to report.
fn drain(file: &mut File, out: &mut std::io::Stdout) -> Result<u64> {
    match std::io::copy(file, out).and_then(|n| out.flush().map(|()| n)) {
        Ok(n) => Ok(n),
        Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => std::process::exit(0),
        Err(e) => Err(e).context("reading the console log"),
    }
}

// ---- daemon plumbing -------------------------------------------------------

/// Send a request to this device's daemon at a version they have agreed on.
///
/// Every connection negotiates. That is one extra round trip on a unix socket
/// per command, and it buys the thing a once-per-process handshake could not:
/// the version in force belongs to the connection carrying the frame, so a
/// daemon replaced between two commands is met by a fresh answer rather than
/// by the last one's.
fn send(request: &Request) -> Result<Response> {
    let mut client = Client::open()?;
    let response = client.ask(request)?;
    // Belt and braces: a daemon that was replaced between the handshake and
    // the request still cannot produce a baffling serde error for the user.
    // The negotiation makes this a race rather than the mechanism, and a race
    // is exactly what a retry is for.
    if let Response::Error { message } = &response {
        if protocol::is_unknown_variant_error(message) {
            return Client::open()?.ask(request);
        }
    }
    Ok(response)
}

/// One connection to this device's daemon, and the wire version it is being
/// spoken at.
struct Client {
    stream: Stream,
    /// The version both ends settled on. Every frame sent on this connection
    /// is at or below it.
    spoken: u32,
    /// What the daemon said about itself, for `ast compat`.
    daemon: DaemonFacts,
}

/// What the daemon answered the handshake with.
#[derive(Clone)]
struct DaemonFacts {
    version: String,
    speaks: asterism_core::compat::Speaks,
}

impl Client {
    /// Connect, agree a version, and be ready to send.
    ///
    /// The daemon that answers may be older than this build, newer than it,
    /// or neither, and the three have three different answers — see
    /// [`asterism_core::compat`]. Only the first is a restart, and it is a
    /// restart because restarting a process this build can restart *is* the
    /// upgrade. A newer daemon is never signalled.
    fn open() -> Result<Client> {
        let (stream, facts) = handshake()?;
        let ours = compat::ours();
        match compat::select(facts.speaks) {
            compat::Selection::Common(spoken) => Ok(Client {
                stream,
                spoken,
                daemon: facts,
            }),
            // Older than anything this build serves. Replace it once, and
            // then insist: a daemon that comes back still too old is a
            // situation only a human can end, and killing it repeatedly is
            // not a plan.
            compat::Selection::TooOld { .. } => {
                eprintln!(
                    "ast: astd {} speaks {}, and this is ast {VERSION} which serves \
                     nothing older than protocol {} — restarting the daemon",
                    facts.version,
                    facts.speaks.describe(),
                    ours.min,
                );
                retire_stale_daemon()?;
                let (stream, facts) = handshake()?;
                match compat::select(facts.speaks) {
                    compat::Selection::Common(spoken) => Ok(Client {
                        stream,
                        spoken,
                        daemon: facts,
                    }),
                    _ => bail!(
                        "astd {} speaks {} after a restart, and this is ast {VERSION} \
                         speaking {}. Stop astd by hand and try again.",
                        facts.version,
                        facts.speaks.describe(),
                        ours.describe(),
                    ),
                }
            }
            // Newer, and with nothing in common. Left alone on purpose.
            compat::Selection::TooNew { theirs, ours } => Err(compat::too_new(
                &format!("astd {}", facts.version),
                theirs,
                ours,
            )),
        }
    }

    /// One request, one reply, at the agreed version.
    ///
    /// No deadline: a command's honest duration is whatever the work takes —
    /// `ast up` on an image that has to be converted is minutes — so a
    /// timeout here would be a timeout on success. The handshake is the one
    /// exchange with a clock on it, and it has already happened.
    fn ask(&mut self, request: &Request) -> Result<Response> {
        self.refuse_unspeakable(request)?;
        self.stream.set_read_timeout(None)?;
        write_line(&mut self.stream, request)?;
        let mut reader = BufReader::new(self.stream.try_clone()?);
        match read_frame(&mut reader)? {
            Some(reply) => Ok(serde_json::from_str(&reply)?),
            None => bail!("astd closed the connection without answering"),
        }
    }

    /// Stop a frame the daemon cannot read before it is written.
    ///
    /// This is what the negotiated version is *for*. Without it the frame
    /// goes out, serde rejects a variant the daemon has never heard of, and
    /// the user is shown `bad request: unknown variant` — a true statement
    /// about nothing they did. With it they are told which command needs
    /// which version, while every other command keeps working.
    fn refuse_unspeakable(&self, request: &Request) -> Result<()> {
        if request.speakable_at(self.spoken) {
            return Ok(());
        }
        let what = request
            .versioned_name()
            .map(|name| format!("`ast {name}`"))
            .unwrap_or_else(|| "that command".to_owned());
        Err(compat::frame_too_new(
            &what,
            request.since(),
            self.spoken,
            &format!("astd {} on this device", self.daemon.version),
        ))
    }
}

/// Open a connection and exchange ranges on it.
///
/// The first frame either way, and the only exchange with a clock on it:
/// astd answers this without touching its registry, so a daemon that will not
/// answer *this* is wedged rather than busy — and since it goes in front of
/// every command, a hang here is a hang everywhere with nothing on the screen
/// to say so.
fn handshake() -> Result<(Stream, DaemonFacts)> {
    let stream = connect()?;
    stream.set_read_timeout(Some(ipc::HANDSHAKE_DEADLINE))?;
    let ours = compat::ours();
    write_line(
        &stream,
        &Request::Ping {
            protocol: ours.max,
            min_protocol: ours.min,
        },
    )?;

    let mut reader = BufReader::new(stream.try_clone()?);
    let reply = match read_frame(&mut reader) {
        Ok(Some(reply)) => reply,
        Ok(None) => bail!("astd closed the connection without answering"),
        Err(e) if timed_out(&e) => return Err(wedged(ipc::HANDSHAKE_DEADLINE)),
        Err(e) => return Err(e),
    };
    let facts = match serde_json::from_str::<Response>(&reply)? {
        Response::Pong {
            version,
            protocol,
            min_protocol,
            ..
        } => DaemonFacts {
            version,
            speaks: compat::Speaks::claimed(protocol, min_protocol),
        },
        // A daemon older than the `Pong` reply answers `Ping` with plain
        // `Ok`, and one older still rejects the variant. Both are the wire
        // that predates the number, which this build serves — so both are
        // spoken to rather than replaced.
        Response::Ok => DaemonFacts {
            version: "(older)".to_owned(),
            speaks: compat::Speaks::unversioned(),
        },
        Response::Error { message } if protocol::is_unknown_variant_error(&message) => {
            DaemonFacts {
                version: "(older)".to_owned(),
                speaks: compat::Speaks::unversioned(),
            }
        }
        // The daemon refused the handshake in words. That is a sentence
        // written for the user — a peer out of the window says why here —
        // so it is passed through rather than summarised.
        Response::Error { message } => bail!(message),
        other => bail!("unexpected reply to ping from astd: {other:?}"),
    };
    Ok((stream, facts))
}

fn write_line<W: Write>(mut out: W, request: &Request) -> Result<()> {
    let mut line = serde_json::to_string(request)?;
    line.push('\n');
    out.write_all(line.as_bytes())?;
    Ok(())
}

/// Open a connection to this home's daemon, starting one if there is none.
///
/// The socket is looked at before it is spoken to. `ast` is about to send it
/// this device's secrets, its orbit membership and every instance command
/// there is, and the socket is a path — so what is at that path being *our*
/// daemon, rather than something a second user on the machine put there, is a
/// thing to establish rather than assume. See
/// [`asterism_core::ipc::audit_socket`].
fn connect() -> Result<Stream> {
    let sock = paths::socket_path();
    if ipc::audit_socket(&sock)? == ipc::SocketState::Ready {
        if let Ok(stream) = ipc::connect(&sock) {
            return Ok(stream);
        }
        // A socket file with nobody behind it: a daemon died without tidying
        // up. Starting one is the recovery — its election clears the
        // leftover path before it binds.
    }
    start_daemon(&sock)
}

/// Start this home's daemon, and be the only `ast` doing so.
///
/// Ten commands typed at once used to find no socket and start ten daemons.
/// One won and the other nine were harmless only by luck: each probed the
/// socket, found nobody, and unlinked the path the winner had just bound.
/// astd's own election closes that from its side; this closes it from ours,
/// so the storm never leaves the ground. Whoever holds this lock starts the
/// daemon and waits for it, and everyone behind them finds it already up.
fn start_daemon(sock: &std::path::Path) -> Result<Stream> {
    let _turn = spawn_turn();
    // Whoever held the lock before us has already started one.
    if let Ok(stream) = ipc::connect(sock) {
        return Ok(stream);
    }
    spawn_daemon()?;
    wait_for_socket(sock)
}

/// The lock that makes a spawn storm one spawn.
///
/// Best effort, and deliberately so: it is an optimisation, not a guarantee —
/// astd's own election is the guarantee — so a home that cannot hold a lock
/// file still gets a daemon rather than a refusal.
fn spawn_turn() -> Option<File> {
    ipc::private_dir(&paths::home_dir()).ok()?;
    // Waiting is the point: whoever holds this is already starting one.
    ipc::lock_file(&paths::spawn_lock_path(), ipc::Wait::Yes)
        .ok()
        .flatten()
}

/// One reply frame, bounded.
///
/// `read_line` is not this: it grows until it finds a newline, so a daemon
/// that has gone wrong — or something that is not a daemon — would choose how
/// much memory `ast` allocates before it fails.
fn read_frame(reader: &mut impl BufRead) -> Result<Option<String>> {
    let mut buf: Vec<u8> = Vec::new();
    loop {
        let chunk = reader.fill_buf()?;
        if chunk.is_empty() {
            if buf.is_empty() {
                return Ok(None);
            }
            bail!("astd stopped in the middle of a reply");
        }
        // What this reply would be if it ended in this chunk: everything kept
        // so far, plus the part of this chunk before its newline. Checked on
        // *both* paths below — the newline path used to skip it, so a reply
        // that reached exactly the cap and then sent its last byte and
        // terminator together came back one byte over. See the daemon's
        // `Frames::next`, which had the same ordering.
        let ends_here = chunk.iter().position(|b| *b == b'\n');
        if buf.len() + ends_here.unwrap_or(chunk.len()) > ipc::MAX_RESPONSE_FRAME {
            bail!(
                "astd sent more than {} bytes without ending a reply",
                ipc::MAX_RESPONSE_FRAME
            );
        }
        if let Some(at) = ends_here {
            buf.extend_from_slice(&chunk[..at]);
            reader.consume(at + 1);
            let line = String::from_utf8(buf).context("astd sent a reply that is not utf-8")?;
            return Ok(if line.trim().is_empty() {
                None
            } else {
                Some(line)
            });
        }
        let taken = chunk.len();
        buf.extend_from_slice(chunk);
        reader.consume(taken);
    }
}

/// The daemon is there and will not answer the one question that has no work
/// behind it.
///
/// astd answers the handshake without touching its registry, so this is not
/// "busy": something is wrong with the process itself. The message names it,
/// because that is the only thing the user can act on.
fn wedged(waited: Duration) -> anyhow::Error {
    let who = match daemon_proc() {
        Some(proc) => format!("astd (pid {})", proc.pid),
        None => "astd".to_owned(),
    };
    anyhow::anyhow!(
        "{who} is listening on {} but did not answer the version handshake in {}s. \
         It is wedged rather than busy — the handshake waits on nothing. Stop it and \
         run this again.",
        paths::socket_path().display(),
        waited.as_secs()
    )
}

fn timed_out(e: &anyhow::Error) -> bool {
    matches!(
        e.downcast_ref::<std::io::Error>().map(|e| e.kind()),
        Some(std::io::ErrorKind::WouldBlock) | Some(std::io::ErrorKind::TimedOut)
    )
}

/// A request the daemon answers with more than one line.
///
/// Pairing is the only one: the daemon has a ticket to print, then a code, and
/// it needs an answer before it will write anything down. The socket is
/// line-delimited JSON in both directions already, so this is the same wire —
/// just a conversation on it rather than a question.
struct Conversation {
    write: Stream,
    read: BufReader<Stream>,
}

impl Conversation {
    fn open(request: &Request) -> Result<Self> {
        // Through the same negotiated door as everything else: a
        // conversation is a longer exchange on the same wire, not a
        // different one, so it settles its version the same way.
        let client = Client::open()?;
        client.refuse_unspeakable(request)?;
        client.stream.set_read_timeout(None)?;
        let stream = client.stream;
        let mut conn = Self {
            write: stream.try_clone()?,
            read: BufReader::new(stream),
        };
        conn.send(request)?;
        Ok(conn)
    }

    fn send(&mut self, request: &Request) -> Result<()> {
        write_line(&mut self.write, request)
    }

    fn next(&mut self) -> Result<Response> {
        match read_frame(&mut self.read)? {
            Some(line) => Ok(serde_json::from_str(&line)?),
            None => bail!("astd closed the connection without answering"),
        }
    }
}

fn wait_for_socket(sock: &std::path::Path) -> Result<Stream> {
    let mut attempt = 0;
    loop {
        match ipc::connect(sock) {
            Ok(s) => return Ok(s),
            Err(e) if attempt >= 50 => return Err(e).context("astd did not come up"),
            Err(_) => {
                attempt += 1;
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }
}

// ---- retiring a daemon this build has outgrown -------------------------------
//
// One direction only, and that asymmetry is the point. A daemon older than
// anything this build serves is replaced, because restarting a process this
// build can restart is what an upgrade *is*. A daemon newer than this build
// is never touched: taking its place would downgrade the device, and it may
// hold state this build would drop. See `asterism_core::compat`.
//
// Neither of those is a version *difference*. A daemon one release behind
// that still serves a wire this build speaks is left running and spoken to at
// that wire — which is what stops a patch release from killing a daemon that
// is supervising live guests for no reason at all.

/// Stop the daemon that is running and start ours in its place.
fn retire_stale_daemon() -> Result<()> {
    let daemon = daemon_proc().with_context(|| {
        // The pid file is not proof, so it is not acted on — but it is the
        // one thing this can hand a human who now has to do it themselves.
        let claimed = std::fs::read_to_string(paths::daemon_pid_path())
            .ok()
            .map(|s| {
                format!(
                    " It last wrote pid {} to {}.",
                    s.trim(),
                    paths::daemon_pid_path().display()
                )
            })
            .unwrap_or_default();
        format!(
            "cannot tell which process is serving the astd socket, so it will not be \
             signalled — stop astd by hand and try again.{claimed}"
        )
    })?;

    daemon.signal(Signal::Term)?;
    if !daemon.wait_gone(Duration::from_secs(10)) {
        // A daemon that will not take a hint. It holds the socket, so the
        // replacement cannot bind until it is gone.
        daemon.signal(Signal::Kill)?;
        daemon.wait_gone(Duration::from_secs(5));
    }
    // A hard-killed daemon leaves both of these behind; astd tolerates a
    // stale socket file, but the pid file would mislead the next restart.
    let _ = std::fs::remove_file(paths::daemon_pid_path());

    spawn_daemon()?;
    wait_for_socket(&paths::socket_path())?;
    Ok(())
}

/// Which process is serving the socket, proven well enough to signal.
///
/// One source, and it is the only one that is evidence. A unix socket path
/// has exactly one listener, so whatever holds this one is by construction
/// the daemon for this `ASTERISM_HOME` and no other — asking about that
/// specific path can never turn up somebody else's.
///
/// The pid file used to be consulted first and is now not consulted at all,
/// because it is a claim rather than evidence: `astd` writes it and a
/// hard-killed daemon does not get to remove it, so what it names on a
/// machine that has rebooted since is whatever the kernel handed that number
/// to next. `astd` is started with no arguments, so unlike a guest's qemu
/// there is nothing on its command line tying a candidate to this home
/// either. With nothing able to prove it, the number is not something to
/// send SIGTERM to; the caller says so and stops.
fn daemon_proc() -> Option<ProcId> {
    let pid = pid_holding(&paths::socket_path())?;
    ProcId::capture(pid).ok()
}

fn pid_holding(sock: &std::path::Path) -> Option<u32> {
    let out = std::process::Command::new("lsof")
        .arg("-t")
        .arg("--")
        .arg(sock)
        .output()
        .ok()?;
    out.stdout
        .split(|b| *b == b'\n')
        .filter_map(|l| String::from_utf8_lossy(l).trim().parse::<u32>().ok())
        .find(|pid| *pid != std::process::id())
}

/// Send a request whose whole answer is "it worked" or why it didn't.
fn send_ok(request: &Request) -> Result<()> {
    match send(request)? {
        Response::Ok => Ok(()),
        Response::Error { message } => bail!(message),
        other => bail!("unexpected reply from astd: {other:?}"),
    }
}

fn spawn_daemon() -> Result<()> {
    let astd = daemon_path()?;
    std::process::Command::new(&astd)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .with_context(|| format!("spawning {}", astd.display()))?;
    Ok(())
}

/// astd normally sits next to the ast binary; fall back to PATH.
fn daemon_path() -> Result<std::path::PathBuf> {
    let names: &[&str] = if cfg!(windows) {
        &["astd.exe", "astd"]
    } else {
        &["astd", "astd.exe"]
    };
    if let Ok(me) = std::env::current_exe() {
        for name in names {
            let sibling = me.with_file_name(name);
            if sibling.exists() {
                return Ok(sibling);
            }
        }
    }
    Ok(std::path::PathBuf::from(names[0]))
}

fn exec_daemon() -> anyhow::Error {
    let astd = match daemon_path() {
        Ok(p) => p,
        Err(e) => return e,
    };
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        std::process::Command::new(astd).exec().into()
    }
    #[cfg(windows)]
    match std::process::Command::new(astd).status() {
        Ok(status) if status.success() => anyhow::anyhow!("astd exited"),
        Ok(status) => anyhow::anyhow!("astd exited with {status}"),
        Err(e) => e.into(),
    }
}

// ---- identity --------------------------------------------------------------
//
// Which release something is, and which *binary* it is, are two questions.
// A version answers the first; every build between two tags shares it, so it
// cannot answer the second. `BUILD_ID` is stamped at compile time and does,
// and the sha256 of the file on disk ties that claim to bytes somebody can
// check against a published `SHA256SUMS` without trusting the binary's own
// account of itself.
//
// These are printed rather than compared here on purpose. The comparison —
// that `ast`, `astd` and the app are one build — belongs to whoever is
// testing a release candidate, and it can only be a real assertion if the
// binaries report what they are without editorialising.

/// One binary's identity, as far as it can be established from outside it.
struct Artifact {
    path: std::path::PathBuf,
    digest: Option<String>,
}

impl Artifact {
    /// Hash a binary if it is there. A missing one is not an error: the
    /// desktop app is a separate download and most devices do not have it.
    fn at(path: std::path::PathBuf) -> Option<Artifact> {
        if !path.exists() {
            return None;
        }
        let digest = verify::Digest::of_file(verify::Algo::Sha256, &path)
            .ok()
            .map(|d| d.to_string());
        Some(Artifact { path, digest })
    }

    fn digest(&self) -> &str {
        self.digest.as_deref().unwrap_or("unreadable")
    }
}

/// `ast version`: three facts, one per line, in the order they get asked for.
///
/// Deliberately not `ast --version`, which stays the one short line a script
/// and a package manager already parse.
fn print_version() -> Result<()> {
    println!("version   {VERSION}");
    println!("build     {}", asterism_core::BUILD_ID);
    match std::env::current_exe().ok().and_then(Artifact::at) {
        Some(a) => println!("artifact  {}  {}", a.digest(), a.path.display()),
        // current_exe() can fail on a binary that was deleted out from under
        // itself; that is worth saying rather than papering over.
        None => println!("artifact  unknown"),
    }
    Ok(())
}

/// The running daemon's `Pong`, without starting one.
///
/// `send` would spawn a daemon to answer, which is the last thing a bug
/// report should do: "is astd running" is one of the facts being collected,
/// and collecting it must not change it.
fn running_daemon() -> Option<(String, Option<String>)> {
    let stream = ipc::connect(&paths::socket_path()).ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(3))).ok()?;
    let mut writer = stream.try_clone().ok()?;
    // Serialized from the type rather than written out by hand: the wire
    // spelling of a request is the protocol's business, and a literal here
    // would be a second copy of it to keep in step.
    let ours = compat::ours();
    let mut line = serde_json::to_string(&Request::Ping {
        protocol: ours.max,
        min_protocol: ours.min,
    })
    .ok()?;
    line.push('\n');
    writer.write_all(line.as_bytes()).ok()?;
    let mut reply = String::new();
    BufReader::new(stream).read_line(&mut reply).ok()?;
    match serde_json::from_str(&reply).ok()? {
        Response::Pong {
            version, build_id, ..
        } => Some((version, build_id)),
        // A daemon too old to send a `Pong` still answered, which is the
        // fact that matters: it is running, and it is old.
        Response::Ok => Some((format!("older than {VERSION}"), None)),
        _ => None,
    }
}

/// Ask an already-running daemon one protocol-1 question without starting
/// or replacing anything.
///
/// The daemon accepts the original, unnumbered wire until a `Ping` settles a
/// newer one, and `List` is part of that first wire. This is deliberately not
/// `Client::open`: a bug report observes whether a daemon exists and must not
/// make one exist while collecting that answer.
fn send_to_running(request: &Request) -> Option<Response> {
    let mut stream = ipc::connect(&paths::socket_path()).ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(3))).ok()?;
    stream
        .set_write_timeout(Some(Duration::from_secs(3)))
        .ok()?;
    write_line(&mut stream, request).ok()?;
    let mut reader = BufReader::new(stream);
    let reply = read_frame(&mut reader).ok()??;
    serde_json::from_str(&reply).ok()
}

/// Where the desktop app lives once it is installed. One place, because a
/// macOS app bundle has one place; a report that guessed at several would
/// have to explain which one it found.
fn gui_binary() -> std::path::PathBuf {
    if cfg!(windows) {
        let mut path = std::env::var_os("LOCALAPPDATA")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| std::path::PathBuf::from(r"C:\Program Files"));
        path.push("Asterism");
        path.push("Asterism.exe");
        path
    } else {
        std::path::PathBuf::from("/Applications/Asterism.app/Contents/MacOS/asterism-gui")
    }
}

/// `ast bugreport`: everything worth pasting, and nothing that needs the
/// network.
///
/// Every section is best-effort. A device with no daemon running, no service
/// installed and no app has a shorter report, not a failed one — the whole
/// point is that it still prints when things are broken.
fn print_bugreport() -> Result<()> {
    println!("asterism bugreport");
    println!();

    // Every line here is `key  value`, and no key is a prefix of another —
    // this section is read by scripts/rc.sh as well as by people, and a
    // format where "which build is the daemon" needs counting columns is a
    // format that will be read wrong.
    println!("[build]");
    println!("ast-version    {VERSION}");
    println!("ast-build      {}", asterism_core::BUILD_ID);
    match std::env::current_exe().ok().and_then(Artifact::at) {
        Some(a) => println!("ast-file       {}  {}", a.digest(), a.path.display()),
        None => println!("ast-file       unknown"),
    }
    // The astd beside this ast is the one `ast` would start. It is hashed
    // rather than run: starting a daemon to ask its version would change the
    // state being reported.
    match daemon_path().ok().and_then(Artifact::at) {
        Some(a) => println!("astd-file      {}  {}", a.digest(), a.path.display()),
        None => println!("astd-file      not found beside ast"),
    }
    match running_daemon() {
        Some((version, Some(build))) => println!("astd-running   {version}  {build}"),
        // A daemon that answered without a build id is old, which is a
        // different fact from no daemon at all and gets a different word.
        Some((version, None)) => println!("astd-running   {version}  build-unknown"),
        None => println!(
            "astd-running   none  ({} is not answering)",
            paths::socket_path().display()
        ),
    }
    match Artifact::at(gui_binary()) {
        Some(a) => println!("app-file       {}  {}", a.digest(), a.path.display()),
        None => println!("app-file       not installed"),
    }
    println!();

    println!("[device]");
    // The same source the daemon names this device by, so a report and the
    // orbit cannot disagree about which machine this is.
    println!("host           {}", asterism_core::instance::local_host());
    println!("os             {}", uname_line());
    println!("arch           {}", std::env::consts::ARCH);
    println!("home           {}", paths::home_dir().display());
    println!("socket         {}", paths::socket_path().display());
    // Named because they change behaviour and are invisible otherwise: a home
    // pointed elsewhere explains a great many "my instance vanished" reports.
    println!(
        "asterism-home  {}",
        std::env::var("ASTERISM_HOME").unwrap_or_else(|_| "unset".into())
    );
    println!(
        "asterism-mesh  {}",
        std::env::var("ASTERISM_MESH").unwrap_or_else(|_| "unset".into())
    );
    println!();

    println!("[service]");
    match service::manager() {
        Ok(manager) => match manager.status() {
            Ok(state) => println!("{}  {}", manager.mechanism(), state.summary()),
            Err(e) => println!("{}  could not be read: {e:#}", manager.mechanism()),
        },
        Err(e) => println!("no service manager on this device: {e:#}"),
    }
    println!();

    println!("[helper]");
    match asterism_core::hyperv::discover_helper() {
        Ok(path) => println!("astd-hyperv    {}", path.display()),
        Err(e) => println!("astd-hyperv    not found ({e:#})"),
    }
    println!();

    for line in windows_host::doctor().lines() {
        println!("{line}");
    }
    println!();

    println!("[instances]");
    // This device's own shard, not the orbit: a bug report that went out on
    // the mesh would hang on a device that is asleep, which is exactly when
    // somebody is writing one.
    // `and_then`, not `and`: do not send the list probe unless the daemon
    // answered the identity probe first. Both helpers connect only to an
    // existing socket and never create or replace a process.
    match running_daemon().and_then(|_| send_to_running(&Request::List)) {
        Some(Response::Instances { instances }) if instances.is_empty() => {
            println!("none on this device")
        }
        Some(Response::Instances { instances }) => {
            for i in instances {
                let profiles = if i.profiles.is_empty() {
                    "-".to_owned()
                } else {
                    i.profiles.join(",")
                };
                println!(
                    "{:<16} {:<9} {:<14} {} profiles={profiles}",
                    i.name, i.status, i.image_kind, i.id
                );
            }
        }
        _ => println!("no daemon to ask"),
    }
    Ok(())
}

/// `ast doctor` — pass/fail host integration, not a bug report.
#[cfg(not(windows))]
fn print_doctor() -> Result<()> {
    let checks = doctor::run();
    for check in &checks {
        println!(
            "{:<4}  {:<18}  {}",
            check.status.as_str(),
            check.name,
            check.detail
        );
    }
    if doctor::all_clear(&checks) {
        println!("doctor: ok");
        Ok(())
    } else {
        bail!("doctor: host integration is incomplete")
    }
}

/// The kernel line, which is how a macOS version gets named in a report
/// somebody else has to reproduce.
fn uname_line() -> String {
    std::process::Command::new("uname")
        .arg("-sr")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| std::env::consts::OS.to_owned())
}

// ---- output ----------------------------------------------------------------

/// `ast ls`: one table, one namespace.
///
/// The COMPUTE column says which device is supplying each instance's compute.
/// It is a column and not a grouping on purpose — the rows are one flat list
/// because the namespace is one flat namespace, and where compute comes from
/// is a property of the instance, like its shape or its age.
fn print_table(rows: &[OrbitRow]) {
    if rows.is_empty() {
        println!("no instances — start with: ast create <name>");
        return;
    }
    println!(
        "{:<14} {:<9} {:<14} {:<16} {:<12} {:<6} ACCESS",
        "NAME", "STATUS", "IMAGE", "SHAPE", "COMPUTE", "AGE"
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
        let access = match (row.live, inst.runtime, inst.handle.as_ref()) {
            (true, RuntimeKind::Vm, _) => inst
                .endpoint()
                .map(ToString::to_string)
                .unwrap_or_else(|| "-".into()),
            (true, RuntimeKind::Container, Some(handle)) if handle.container_control.is_some() => {
                "container-control".into()
            }
            _ => "-".into(),
        };
        println!(
            "{:<14} {:<9} {:<14} {:<16} {:<12} {:<6} {}",
            inst.name,
            status,
            short_image(inst.image.as_deref().unwrap_or("-")),
            shape,
            inst.compute_device(),
            age(inst.created_at),
            access,
        );
    }
    if stale {
        println!("\nunknown: the device supplying that instance's compute is out of touch");
    }
    for name in conflicts {
        println!("\nconflict: {name} shares its name — rename it: ast rename {name} <new-name>");
    }
}

/// `ast status`: the instance, then the parts it is assembled from and where
/// in the pool each of them is sourced.
fn print_detail(inst: &Instance, guest_health: Option<&GuestHealth>) {
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
    // Worth a line only when there are some: an instance with no profiles is
    // the ordinary case and its guest is exactly its image.
    if !inst.profiles.is_empty() {
        println!(
            "profiles: {} (what the guest has: ast profile {} --check)",
            inst.profiles.join(" "),
            inst.name
        );
    }
    if let Some(disk) = local_disk(inst) {
        println!("disk:    {disk}");
    }
    // The machine this instance was defined against. Recorded at create
    // time, and what a live migration would have to match on.
    println!("machine: {}", inst.machine);
    if let Some(h) = &inst.handle {
        let pid = h.pid.map(|p| p.to_string()).unwrap_or_else(|| "-".into());
        match (&h.endpoint, &h.container_control) {
            (Some(endpoint), _) if inst.image_kind == ImageKind::OciRootfs => {
                match endpoint.control_target() {
                    Some((host, port)) => println!(
                        "running: {} pid {pid}, authenticated guest control {host}:{port}",
                        h.backend
                    ),
                    None => println!(
                        "running: {} pid {pid}, guest control endpoint unavailable",
                        h.backend
                    ),
                }
            }
            (Some(endpoint), _) => println!("running: {} pid {pid}, ssh {endpoint}", h.backend),
            (None, Some(control)) => println!(
                "running: {} pid {pid}, container control {}",
                h.backend,
                control.socket.display()
            ),
            (None, None) => println!("running: {} pid {pid}, no endpoint", h.backend),
        }
        println!("control: {}", h.ctl.path().display());
    }
    if let Some(conflict) = &inst.conflict {
        println!(
            "conflict: another instance in this orbit is also called {:?} \
             (compute on {}) — rename this one: ast rename {} <new-name>",
            inst.name, conflict.other_cpu_device, inst.name
        );
    }
    // Only worth a line once it has happened: an instance that has never had
    // its compute placement moved is the ordinary case and does not need
    // telling.
    if inst.move_epoch > 0 {
        println!(
            "moves:   {} (compute has been re-sourced that many times)",
            inst.move_epoch
        );
    }
    // Worth a line only when it is not the obvious answer: a guest trusts
    // the key in its seed, and after a move that is not the device running it.
    if inst.seeded_by() != inst.compute_device() {
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

    for line in guest_health_lines(guest_health) {
        println!("{line}");
    }

    // Every row names the device the part comes from. Most of them name the
    // same device, and say why: the disk follows the cpu because that is the
    // cheapest place for it, not because that device owns the instance.
    println!("\nparts:");
    let parts = inst.parts();
    let kind = parts.iter().map(|p| p.kind.len()).max().unwrap_or(0);
    let source = parts.iter().map(|p| p.source.len()).max().unwrap_or(0);
    for p in &parts {
        let note = p
            .note
            .as_ref()
            .map(|n| format!("  ({n})"))
            .unwrap_or_default();
        println!(
            "  {:<kind$}  {:<source$}  {}{note}",
            p.kind, p.source, p.detail
        );
    }
}

/// Fresh agent observations belong between the durable instance facts and its
/// assembled parts. They are absent for a guest that has not reported yet.
fn guest_health_lines(health: Option<&GuestHealth>) -> Vec<String> {
    let Some(health) = health else {
        return Vec::new();
    };

    let mut guest = Vec::new();
    if !health.addrs.is_empty() {
        guest.push(
            health
                .addrs
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", "),
        );
    }
    guest.push(format!("up {}", duration(health.uptime_secs)));
    guest.push(match health.ssh {
        true => "ssh listening".into(),
        false => "ssh not listening".into(),
    });
    if !health.cloud_init.is_empty() {
        guest.push(format!("cloud-init {}", health.cloud_init));
    }

    let mut resources = Vec::new();
    if let Some(load1) = health.load1 {
        resources.push(format!("load {load1:.2}"));
    }
    if let Some(mem) = health.mem_available_kib {
        resources.push(format!("memory {} available", kib(mem)));
    }

    let mut lines = vec![format!("guest:   {}", guest.join(" · "))];
    if !resources.is_empty() {
        lines.push(format!("health:  {}", resources.join(" · ")));
    }
    lines
}

fn duration(secs: f64) -> String {
    let secs = secs.max(0.0) as u64;
    match secs {
        0..=59 => format!("{secs}s"),
        60..=3_599 => format!("{}m", secs / 60),
        3_600..=86_399 => format!("{}h", secs / 3_600),
        _ => format!("{}d", secs / 86_400),
    }
}

fn kib(value: u64) -> String {
    match value {
        0..=1_023 => format!("{value} KiB"),
        _ => format!("{} MiB", value / 1_024),
    }
}

/// What an instance's root disk is, and what it actually costs today.
///
/// Read off the filesystem rather than the registry, because both halves
/// are facts about the file: a disk cloned from a raw base occupies almost
/// nothing until the guest writes to it, and a `disk.qcow2` says this
/// instance predates raw disks and still takes the old snapshot path
/// (BACKENDS.md §4). Only when this device supplies compute; another
/// device's disks are not ours to stat.
fn local_disk(inst: &Instance) -> Option<String> {
    if inst.compute_device() != asterism_core::instance::local_host() {
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

/// Which part `ast attach` was asked for.
///
/// One flag each, and exactly one of them, checked here rather than left to
/// clap so the refusal can say what the command is *for*. A volume and a
/// secret are both parts an instance is assembled from, but they are not two
/// settings of one flag: they arrive by different mechanisms, are sourced
/// from devices for different reasons, and a command that took both would
/// have to invent an order between them.
enum Attaching {
    Volume(String),
    Secret(String),
    Gpu(String),
}

fn attaching(
    volume: Option<String>,
    secret: Option<String>,
    gpu: Option<String>,
) -> Result<Attaching> {
    match (volume, secret, gpu) {
        (Some(volume), None, None) => Ok(Attaching::Volume(volume)),
        (None, Some(secret), None) => Ok(Attaching::Secret(secret)),
        (None, None, Some(gpu)) => Ok(Attaching::Gpu(gpu)),
        // clap refuses this one first; the arm exists so that adding a third
        // part later cannot make it fall through to "say which".
        (Some(_), Some(_), _) | (Some(_), _, Some(_)) | (_, Some(_), Some(_)) => bail!(
            "--volume, --secret, and --gpu are different parts — attach them one command at a time"
        ),
        (None, None, None) => bail!(
            "say which part: --volume /tank/media, --volume desktop:tank, or \
             --secret anthropic --to api.anthropic.com, or --gpu desktop"
        ),
    }
}

/// Report on the secret that was just bound — the one at the end.
///
/// The handle is printed in full and on purpose. It is what the guest holds,
/// it is worth nothing outside this instance's proxy, and a user who cannot
/// see it cannot check that the thing in `$ANTHROPIC_API_KEY` is the thing
/// this device will honour. The value is not printed because this process
/// never had it.
fn print_bound(inst: &Instance, secret: &str) {
    let Some(binding) = inst.secrets.iter().find(|b| b.secret == secret) else {
        return;
    };
    println!(
        "{}  {secret} -> {}  ({}, from {})",
        inst.name, binding.authority, binding.placement, binding.source_device
    );
    println!(
        "the guest gets ${}={} — an opaque handle, honoured only by this instance's \
         proxy and only for {}. The value stays on {}.",
        binding.env,
        binding.guest_handle.as_str(),
        binding.authority,
        binding.source_device
    );
    if inst.status == asterism_core::instance::Status::Running {
        println!(
            "reaches the guest on the next boot: ast down {0} && ast up {0}",
            inst.name
        );
    }
}

/// Report on the volume that was just attached — the one at the end.
fn print_attached(inst: &Instance) {
    let Some(v) = inst.volumes.last() else { return };
    println!(
        "{}  {}:{}  ->  {}",
        inst.name,
        v.host,
        v.path,
        volume_destination(v)
    );
    if v.is_block() {
        // The guest sees a disk and nothing else — no mount, no share, no
        // hint that the bytes are elsewhere. Saying so here is the difference
        // between a working volume and a confused user, because an unmounted
        // blank disk looks exactly like nothing having happened.
        println!(
            "the guest gets a plain disk (/dev/vdb, /dev/vdc, ...); format and \
             mount it there once:"
        );
        println!(
            "  ast ssh {} -- 'sudo mkfs.ext4 /dev/vdb && sudo mkdir -p /data && \
                  sudo mount /dev/vdb /data'",
            inst.name
        );
    } else if !v.is_local() {
        println!(
            "recorded only — a directory on another device cannot be shared into a \
             guest (directory shares have no network transport); use a block volume instead: \
             ast volume create"
        );
    }
    if inst.status == asterism_core::instance::Status::Running {
        println!(
            "appears in the guest on the next boot: ast down {0} && ast up {0}",
            inst.name
        );
    }
}

/// Where a volume shows up, or why it does not.
fn volume_destination(v: &asterism_core::instance::Volume) -> String {
    if v.is_block() {
        return "a disk in the guest".to_owned();
    }
    if v.is_local() {
        v.guest_path()
    } else {
        format!(
            "{} (a directory on {}, not reachable from here)",
            v.guest_path(),
            v.host
        )
    }
}

fn age(created_at: u64) -> String {
    let secs = now_unix().saturating_sub(created_at);
    match secs {
        0..=59 => format!("{secs}s"),
        60..=3599 => format!("{}m", secs / 60),
        3600..=86_399 => format!("{}h", secs / 3600),
        _ => format!("{}d", secs / 86_400),
    }
}

// ---- parsing ---------------------------------------------------------------

fn parse_mem_mib(s: &str) -> Result<u32> {
    let s = s.trim();
    if let Some(g) = s.strip_suffix(['G', 'g']) {
        return Ok(g.parse::<u32>().context("bad --mem")? * 1024);
    }
    let m = s.strip_suffix(['M', 'm']).unwrap_or(s);
    m.parse::<u32>().context("bad --mem (try 2048M or 4G)")
}

fn parse_disk_gib(s: &str) -> Result<u32> {
    let g = s.trim().strip_suffix(['G', 'g']).unwrap_or(s.trim());
    g.parse::<u32>().context("bad --disk (try 20G)")
}

// ---- signed updates -------------------------------------------------------

/// Hand update policy to the updater shipped by this exact build.
///
/// It is a separate executable because it must remain alive while `ast`
/// itself is renamed. Keeping the policy there also lets the desktop app call
/// the same implementation rather than acquiring a second update backend.
fn update_command(cmd: UpdateCommand) -> Result<()> {
    let ast = std::env::current_exe().context("finding the installed ast binary")?;
    let updater = std::env::var_os("ASTERISM_UPDATER")
        .map(std::path::PathBuf::from)
        .or_else(|| {
            let prefix = ast.parent()?.parent()?;
            // Prefer asterism-update.ps1 on Windows, then .exe, then the POSIX updater.
            windows_host::update::first_reachable_updater(prefix)
        })
        .or_else(|| {
            let prefix = ast.parent()?.parent()?;
            let path = prefix.join("libexec/asterism/asterism-update");
            path.is_file().then_some(path)
        })
        // A source checkout can exercise the same updater without installing
        // into the developer's prefix. Published binaries never need this.
        .or_else(|| {
            let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../packaging/update.ps1");
            path.is_file().then_some(path)
        })
        .or_else(|| {
            let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../packaging/update.sh");
            path.is_file().then_some(path)
        })
        .ok_or_else(|| {
            anyhow::anyhow!(
                "this installation has no asterism-update beside it; reinstall Asterism once, then `ast update` is self-hosting"
            )
        })?;

    let is_powershell = updater
        .extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| ext.eq_ignore_ascii_case("ps1"));
    let mut process = if is_powershell {
        let mut shell = std::process::Command::new(if cfg!(windows) {
            "powershell.exe"
        } else {
            "pwsh"
        });
        shell.arg("-NoProfile").arg("-File").arg(&updater);
        shell
    } else {
        std::process::Command::new(&updater)
    };
    process.env("ASTERISM_UPDATE_AST_PATH", &ast);
    if std::env::var_os("ASTERISM_UPDATE_PUBKEY").is_none() {
        if let Some(pubkey) = option_env!("ASTERISM_UPDATE_PUBKEY") {
            if !pubkey.is_empty() {
                process.env("ASTERISM_UPDATE_PUBKEY", pubkey);
            }
        }
    }
    match cmd {
        UpdateCommand::Status => {
            process.arg("status");
        }
        UpdateCommand::Check => {
            process.arg("check");
        }
        UpdateCommand::Apply { yes } => {
            process.arg("apply");
            if yes {
                process.arg(if is_powershell { "-Yes" } else { "--yes" });
            }
        }
        UpdateCommand::Channel { name } => {
            process.arg("channel");
            if let Some(name) = name {
                process.arg(name);
            }
        }
    }
    let status = process
        .status()
        .with_context(|| format!("running {}", updater.display()))?;
    if !status.success() {
        bail!("update command exited with {status}");
    }
    Ok(())
}

/// Activate the daemon half of an already-committed filesystem transaction.
///
/// Guests are independent qemu/VZ-helper processes and are deliberately not
/// signalled here. The new daemon adopts them through their recorded process
/// evidence, which is the same live-guest-preserving replacement exercised by
/// the version-skew suite.
fn activate_update(want_build: &str) -> Result<()> {
    if ipc::connect(&paths::socket_path()).is_ok() {
        retire_stale_daemon()?;
    } else {
        spawn_daemon()?;
        wait_for_socket(&paths::socket_path())?;
    }
    let Some((version, build)) = running_daemon() else {
        bail!("the replacement astd did not answer after activation");
    };
    match build {
        Some(found) if found == want_build => {
            println!("activated astd {version} build {found}");
            Ok(())
        }
        Some(found) => {
            bail!("the replacement astd answered as build {found}, expected {want_build}")
        }
        None => {
            bail!("the replacement astd {version} cannot report a build id; expected {want_build}")
        }
    }
}

/// Make an updater filesystem boundary survive more than process death.
///
/// Renaming a journal file is atomic but not durable until both the file's
/// bytes and the directory entry naming it have reached stable storage. The
/// updater is POSIX shell, so this tiny hidden capability keeps the actual
/// fsync implementation in the shipped binary instead of depending on a
/// host-specific sync command or on Python being installed.
fn sync_update_path(path: &Path, recursive: bool, parent_only: bool) -> Result<()> {
    if !parent_only {
        sync_update_entry(path, recursive)?;
    }
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    File::open(parent)
        .with_context(|| format!("opening updater directory {}", parent.display()))?
        .sync_all()
        .with_context(|| format!("syncing updater directory {}", parent.display()))
}

fn sync_update_entry(path: &Path, recursive: bool) -> Result<()> {
    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("reading updater path {}", path.display()))?;
    if metadata.file_type().is_symlink() {
        // A symlink has no independently flushable contents. Its containing
        // directory is synced by its caller after the entry walk returns.
        return Ok(());
    }
    if metadata.is_dir() && recursive {
        for entry in std::fs::read_dir(path)
            .with_context(|| format!("reading updater directory {}", path.display()))?
        {
            sync_update_entry(&entry?.path(), true)?;
        }
    }
    File::open(path)
        .with_context(|| format!("opening updater path {}", path.display()))?
        .sync_all()
        .with_context(|| format!("syncing updater path {}", path.display()))
}

#[cfg(windows)]
fn print_doctor() -> Result<()> {
    let report = windows_host::doctor();
    for line in report.lines() {
        println!("{line}");
    }
    println!();
    println!("{}", report.summary());
    if !report.supported {
        bail!("{}", report.summary());
    }
    Ok(())
}

// ---- service ---------------------------------------------------------------

/// `ast service install|uninstall|status`.
///
/// The point of a daemon is that it is already running when you need it,
/// which means the OS starts it — not a terminal. What that takes differs
/// per OS and lives behind `service::Manager`; this prints what the seam
/// did, because a command that edits `~/Library` or `~/.config` should say
/// so line by line.
fn service_command(cmd: ServiceCommand) -> Result<()> {
    let manager = service::manager()?;
    match cmd {
        ServiceCommand::Install => {
            let spec = service::Spec::current()?;
            let report = manager.install(&spec)?;
            println!("astd is installed as a {} service", manager.mechanism());
            for step in &report.steps {
                println!("  {step}");
            }
            println!("it starts on login and comes back if it exits.");
            println!("moved the astd binary? run `ast service install` again.");
            println!("check the rest of this host with: ast doctor");
        }
        ServiceCommand::Uninstall => {
            let report = manager.uninstall()?;
            println!("astd is no longer a {} service", manager.mechanism());
            for step in &report.steps {
                println!("  {step}");
            }
        }
        ServiceCommand::Status => {
            let state = manager.status()?;
            println!("{}  {}", manager.mechanism(), state.summary());
            println!("  unit  {}", state.unit.display());
            if let Some(program) = &state.program {
                println!("  astd  {}", program.display());
            }
            for note in &state.notes {
                println!("  {note}");
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;
    use std::cell::Cell;
    use std::collections::VecDeque;
    use std::sync::Mutex;

    fn parse_cli(args: &[&str]) -> Cli {
        Cli::try_parse_from(std::iter::once("ast").chain(args.iter().copied())).unwrap()
    }

    #[test]
    fn set_compute_is_canonical_and_compatibility_aliases_remain() {
        let Command::Set {
            name,
            part,
            to,
            down,
        } = parse_cli(&["set", "agent", "compute", "desktop"]).command
        else {
            panic!("set compute did not parse as set");
        };
        assert_eq!(
            (name.as_str(), part.as_str(), to.as_str(), down),
            ("agent", "compute", "desktop", false)
        );
        assert!(asterism_core::instance::is_compute_part(&part));

        let Command::Set { part, down, .. } =
            parse_cli(&["set", "agent", "cpu", "desktop", "--down"]).command
        else {
            panic!("set cpu did not parse as the compatibility alias");
        };
        assert_eq!(part, "cpu");
        assert!(down);
        assert!(asterism_core::instance::is_compute_part(&part));

        assert!(matches!(
            parse_cli(&["move", "agent", "desktop", "--down"]).command,
            Command::Move { name, to, down }
                if name == "agent" && to == "desktop" && down
        ));
    }

    #[test]
    fn set_help_uses_compute_as_the_placement_name() {
        use clap::CommandFactory;

        let help = Cli::command()
            .find_subcommand("set")
            .expect("set")
            .clone()
            .render_long_help()
            .to_string();
        assert!(help.contains("compute"), "{help}");
        assert!(help.contains("compatibility alias"), "{help}");
        assert!(!help.contains("cpu/ram"), "{help}");
        assert!(!help.contains("anchor"), "{help}");
    }

    #[test]
    fn ram_names_are_refused_as_separate_compute_placements() {
        for part in ["ram", "cpu/ram"] {
            let error = set_part("agent", part, "desktop", false).unwrap_err();
            let message = format!("{error:#}");
            assert!(message.contains("whole compute"), "{message}");
            assert!(message.contains("CPU, physical RAM"), "{message}");
            assert!(message.contains("compute <device>"), "{message}");
        }
    }

    struct MemoryStore(Mutex<Option<Session>>);

    impl CredentialStore for MemoryStore {
        fn save(&self, session: &Session) -> Result<()> {
            *self.0.lock().unwrap() = Some(session.clone());
            Ok(())
        }

        fn load(&self) -> Result<Option<Session>> {
            Ok(self.0.lock().unwrap().clone())
        }

        fn delete(&self) -> Result<()> {
            *self.0.lock().unwrap() = None;
            Ok(())
        }
    }

    struct FailedBrowser;

    impl BrowserOpener for FailedBrowser {
        fn open(&self, _url: &str) -> Result<()> {
            bail!("no graphical session")
        }
    }

    struct TestTime(Cell<u64>);

    impl Clock for TestTime {
        fn now(&self) -> u64 {
            self.0.get()
        }
    }

    impl PollSleeper for TestTime {
        fn sleep(&self, duration: Duration) {
            self.0.set(self.0.get() + duration.as_secs());
        }
    }

    struct MockCoordinator {
        authority: String,
        authorization: DeviceAuthorization,
        replies: Mutex<VecDeque<Result<AuthReply<Session>>>>,
    }

    impl CoordinatorClient for MockCoordinator {
        fn authority(&self) -> &str {
            &self.authority
        }

        fn issue(&self, _provider: Provider) -> Result<DeviceAuthorization> {
            Ok(self.authorization.clone())
        }

        fn poll(&self, _device_code: &str) -> Result<AuthReply<Session>> {
            self.replies
                .lock()
                .unwrap()
                .pop_front()
                .expect("a mock reply")
        }

        fn revoke(&self, _access_token: &str) -> Result<()> {
            Ok(())
        }
    }

    fn auth_session(provider: Provider) -> Session {
        Session {
            access_token: hosted_auth::Secret::new("token-not-for-logs".into()).unwrap(),
            token_type: "Bearer".into(),
            account: hosted_auth::Account {
                id: "acct_opaque".into(),
                provider,
                display_name: "Octo".into(),
            },
            issued_at: 100,
            issuer: String::new(),
        }
    }

    fn auth_error(code: &str, interval: Option<u64>) -> AuthReply<Session> {
        AuthReply::Protocol(ProtocolError {
            error: code.into(),
            error_description: None,
            interval,
        })
    }

    #[test]
    fn device_login_recovers_offline_and_browser_failure_without_hiding_the_code() {
        let coordinator = MockCoordinator {
            authority: "https://auth.example".into(),
            authorization: DeviceAuthorization {
                device_code: "device-code".into(),
                user_code: "ABCD-EFGH".into(),
                verification_uri: "https://auth.example/oauth/device".into(),
                verification_uri_complete: "https://auth.example/oauth/device?user_code=ABCD-EFGH"
                    .into(),
                expires_in: 120,
                interval: 1,
            },
            replies: Mutex::new(VecDeque::from([
                Err(std::io::Error::new(std::io::ErrorKind::ConnectionReset, "offline").into()),
                Ok(auth_error("authorization_pending", None)),
                Ok(auth_error("slow_down", Some(2))),
                Ok(AuthReply::Ok(auth_session(Provider::Github))),
            ])),
        };
        let store = MemoryStore(Mutex::new(None));
        let time = TestTime(Cell::new(100));
        let mut output = Vec::new();
        let mut errors = Vec::new();
        login_with(
            Provider::Github,
            &coordinator,
            &store,
            &FailedBrowser,
            &time,
            &time,
            false,
            &mut output,
            &mut errors,
        )
        .unwrap();

        let output = String::from_utf8(output).unwrap();
        let errors = String::from_utf8(errors).unwrap();
        assert!(output.contains("Open: https://auth.example/oauth/device"));
        assert!(output.contains("Code: ABCD-EFGH"));
        assert!(output.contains("signed in as Octo (github)"));
        assert!(errors.contains("could not open a browser"));
        assert!(errors.contains("continue with the URL and code above"));
        assert!(!output.contains("token-not-for-logs"));
        assert!(!errors.contains("token-not-for-logs"));
        let stored = store.load().unwrap().unwrap();
        assert_eq!(stored.account.id, "acct_opaque");
        assert_eq!(stored.issuer, "https://auth.example");
    }

    #[test]
    fn device_login_stops_on_denial() {
        let coordinator = MockCoordinator {
            authority: "https://auth.example".into(),
            authorization: DeviceAuthorization {
                device_code: "device-code".into(),
                user_code: "ABCD-EFGH".into(),
                verification_uri: "https://auth.example/oauth/device".into(),
                verification_uri_complete: "https://auth.example/oauth/device?user_code=ABCD-EFGH"
                    .into(),
                expires_in: 120,
                interval: 1,
            },
            replies: Mutex::new(VecDeque::from([Ok(auth_error("access_denied", None))])),
        };
        let store = MemoryStore(Mutex::new(None));
        let time = TestTime(Cell::new(100));
        let error = login_with(
            Provider::Google,
            &coordinator,
            &store,
            &FailedBrowser,
            &time,
            &time,
            true,
            &mut Vec::new(),
            &mut Vec::new(),
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("denied"));
        assert!(store.load().unwrap().is_none());
    }

    #[test]
    fn protocol_incompatibility_is_fatal_instead_of_an_offline_retry() {
        let coordinator = MockCoordinator {
            authority: "https://auth.example".into(),
            authorization: DeviceAuthorization {
                device_code: "device-code".into(),
                user_code: "ABCD-EFGH".into(),
                verification_uri: "https://auth.example/oauth/device".into(),
                verification_uri_complete: "https://auth.example/oauth/device?user_code=ABCD-EFGH"
                    .into(),
                expires_in: 120,
                interval: 1,
            },
            replies: Mutex::new(VecDeque::from([Err(anyhow::anyhow!(
                "hosted coordinator protocol is incompatible"
            ))])),
        };
        let store = MemoryStore(Mutex::new(None));
        let time = TestTime(Cell::new(100));
        let error = login_with(
            Provider::Github,
            &coordinator,
            &store,
            &FailedBrowser,
            &time,
            &time,
            true,
            &mut Vec::new(),
            &mut Vec::new(),
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("protocol is incompatible"));
        assert_eq!(time.now(), 101, "one initial poll, then immediate refusal");
    }

    #[test]
    fn google_and_github_mock_device_flows_both_complete() {
        for provider in [Provider::Google, Provider::Github] {
            let coordinator = MockCoordinator {
                authority: "https://auth.example".into(),
                authorization: DeviceAuthorization {
                    device_code: "device-code".into(),
                    user_code: "ABCD-EFGH".into(),
                    verification_uri: "https://auth.example/oauth/device".into(),
                    verification_uri_complete:
                        "https://auth.example/oauth/device?user_code=ABCD-EFGH".into(),
                    expires_in: 120,
                    interval: 1,
                },
                replies: Mutex::new(VecDeque::from([Ok(AuthReply::Ok(auth_session(provider)))])),
            };
            let store = MemoryStore(Mutex::new(None));
            let time = TestTime(Cell::new(100));
            login_with(
                provider,
                &coordinator,
                &store,
                &FailedBrowser,
                &time,
                &time,
                true,
                &mut Vec::new(),
                &mut Vec::new(),
            )
            .unwrap();
            assert_eq!(store.load().unwrap().unwrap().account.provider, provider);
        }
    }

    #[test]
    fn external_coordinator_request_pins_the_protocol_and_rfc_grant() {
        use std::net::TcpListener;
        use std::sync::mpsc;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (sent, received) = mpsc::channel();
        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut head = String::new();
            let mut content_length = 0;
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                if line == "\r\n" || line.is_empty() {
                    break;
                }
                if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                    content_length = value.trim().parse::<usize>().unwrap();
                }
                head.push_str(&line);
            }
            let mut body = vec![0; content_length];
            reader.read_exact(&mut body).unwrap();
            sent.send((head, String::from_utf8(body).unwrap())).unwrap();
            let response = format!(
                r#"{{"device_code":"opaque","user_code":"ABCD-EFGH","verification_uri":"http://{address}/oauth/device","verification_uri_complete":"http://{address}/oauth/device?user_code=ABCD-EFGH","expires_in":600,"interval":5}}"#
            );
            let mut stream = stream;
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAsterism-Protocol: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                hosted_auth::PROTOCOL,
                response.len(),
                response
            )
            .unwrap();
        });

        let client = AuthHttp::new(&format!("http://{address}")).unwrap();
        let issued = client.issue(Provider::Github).unwrap();
        assert_eq!(issued.user_code, "ABCD-EFGH");
        let (head, body) = received.recv().unwrap();
        assert!(head.starts_with("POST /oauth/device/code HTTP/1.1"));
        let lowercase = head.to_ascii_lowercase();
        assert!(lowercase.contains(&format!("asterism-protocol: {}", hosted_auth::PROTOCOL)));
        // The authority reads a form body and identifies the caller by the
        // registered public client id, not by a JSON document.
        assert!(lowercase.contains("content-type: application/x-www-form-urlencoded"));
        let fields: std::collections::BTreeMap<String, String> = body
            .split('&')
            .map(|pair| {
                let (key, value) = pair.split_once('=').unwrap();
                (key.to_owned(), value.replace("%20", " ").replace('+', " "))
            })
            .collect();
        assert_eq!(
            fields.get("client_id").map(String::as_str),
            Some(hosted_auth::CLI_CLIENT_ID)
        );
        assert_eq!(
            fields.get("scope").map(String::as_str),
            Some(hosted_auth::CLI_SCOPE)
        );
        assert_eq!(fields.get("provider").map(String::as_str), Some("github"));
        server.join().unwrap();
    }

    /// The deployed authority answers the token endpoint with an RFC 6749
    /// token response and no protocol header at all. Neither may stop a
    /// login, and the account still has to come out of the bearer.
    #[test]
    fn token_response_without_a_protocol_header_still_names_the_account() {
        use std::net::TcpListener;
        use std::sync::mpsc;

        const BEARER: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJhc3Rlcmlzb\
S1jbGkiLCJzdWIiOiJ1c2VyLTQyIiwicHJvdmlkZXIiOiJnaXRodWIiLCJuYW1lIjoiT2N0byBDYXQiLCJpYXQiOjE3M\
DAwMDAwMDAsImV4cCI6MTcwMDA0MzIwMCwic2NvcGUiOiJvcGVuaWQifQ.c2lnbmF0dXJl";

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (sent, received) = mpsc::channel();
        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut head = String::new();
            let mut content_length = 0;
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                if line == "\r\n" || line.is_empty() {
                    break;
                }
                if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                    content_length = value.trim().parse::<usize>().unwrap();
                }
                head.push_str(&line);
            }
            let mut body = vec![0; content_length];
            reader.read_exact(&mut body).unwrap();
            sent.send((head, String::from_utf8(body).unwrap())).unwrap();
            let response = format!(
                r#"{{"access_token":"{BEARER}","token_type":"Bearer","expires_in":43200,"scope":"openid"}}"#
            );
            let mut stream = stream;
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                response.len(),
                response
            )
            .unwrap();
        });

        let client = AuthHttp::new(&format!("http://{address}")).unwrap();
        let AuthReply::Ok(session) = client.poll("opaque-device-code").unwrap() else {
            panic!("a token response is not a protocol error");
        };
        assert_eq!(session.account.id, "user-42");
        assert_eq!(session.account.display_name, "Octo Cat");
        assert_eq!(session.account.provider, Provider::Github);
        assert_eq!(session.issued_at, 1_700_000_000);
        assert_eq!(session.issuer, format!("http://{address}"));
        assert!(!format!("{session:?}").contains(BEARER));

        let (head, body) = received.recv().unwrap();
        assert!(head.starts_with("POST /oauth/token HTTP/1.1"));
        assert!(body.contains(&format!("client_id={}", hosted_auth::CLI_CLIENT_ID)));
        assert!(body.contains("device_code=opaque-device-code"));
        assert!(body.contains("grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code"));
        server.join().unwrap();
    }

    #[test]
    fn a_token_logout_b_is_rejected_before_b_sees_a_request_or_token() {
        use std::net::TcpListener;
        use std::sync::mpsc;

        let issuer_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let issuer = format!("http://{}", issuer_listener.local_addr().unwrap());
        let other_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        other_listener.set_nonblocking(true).unwrap();
        let other = format!("http://{}", other_listener.local_addr().unwrap());

        let (sent, received) = mpsc::channel();
        let issuer_server = std::thread::spawn(move || {
            let (stream, _) = issuer_listener.accept().unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut head = String::new();
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                if line == "\r\n" || line.is_empty() {
                    break;
                }
                head.push_str(&line);
            }
            sent.send(head).unwrap();
            let body = "{}";
            let mut stream = stream;
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAsterism-Protocol: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                hosted_auth::PROTOCOL,
                body.len(),
                body
            )
            .unwrap();
        });

        let mut session = auth_session(Provider::Github);
        session.issuer = issuer.clone();
        let store = MemoryStore(Mutex::new(Some(session)));
        let mut output = Vec::new();
        let mut errors = Vec::new();
        let mismatch = logout_with(&store, Some(&other), &mut output, &mut errors).unwrap_err();

        let mismatch = format!("{mismatch:#}");
        assert!(mismatch.contains("does not match the session issuer"));
        assert!(mismatch.contains("refusing before network"));
        assert!(!mismatch.contains("token-not-for-logs"));
        assert!(
            store.load().unwrap().is_some(),
            "mismatch keeps the A session"
        );
        assert_eq!(
            other_listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock,
            "coordinator B must see zero connections and therefore zero token bytes"
        );

        logout_with(&store, None, &mut output, &mut errors).unwrap();
        let issuer_request = received.recv().unwrap().to_ascii_lowercase();
        assert!(issuer_request.starts_with("post /api/v1/account/sessions/revoke http/1.1"));
        assert!(issuer_request.contains("authorization: bearer token-not-for-logs"));
        assert_eq!(
            other_listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock,
            "coordinator B must still see zero connections after issuer-bound logout"
        );
        assert!(!String::from_utf8(output)
            .unwrap()
            .contains("token-not-for-logs"));
        assert!(!String::from_utf8(errors)
            .unwrap()
            .contains("token-not-for-logs"));
        assert!(store.load().unwrap().is_none());
        issuer_server.join().unwrap();
    }

    #[test]
    fn legacy_unbound_session_is_cleared_locally_without_remote_use() {
        let store = MemoryStore(Mutex::new(Some(auth_session(Provider::Google))));
        let mut output = Vec::new();
        let error = logout_with(
            &store,
            Some("http://127.0.0.1:9"),
            &mut output,
            &mut Vec::new(),
        )
        .unwrap_err();
        let error = format!("{error:#}");
        assert!(error.contains("legacy session removed locally"));
        assert!(error.contains("refusing remote use"));
        assert!(!error.contains("token-not-for-logs"));
        assert!(store.load().unwrap().is_none());
        assert!(output.is_empty());
    }

    #[test]
    fn coordinator_and_browser_urls_cannot_escape_the_https_origin() {
        assert!(AuthHttp::new("http://auth.example").is_err());
        assert!(AuthHttp::new("https://user@auth.example").is_err());
        assert!(AuthHttp::new("https://auth.example/a/path").is_err());

        let client = AuthHttp::new("http://127.0.0.1:12345").unwrap();
        let authorization = DeviceAuthorization {
            device_code: "opaque".into(),
            user_code: "ABCD-EFGH".into(),
            verification_uri: "https://attacker.example/oauth/device".into(),
            verification_uri_complete: "https://attacker.example/oauth/device?user_code=ABCD-EFGH"
                .into(),
            expires_in: 600,
            interval: 5,
        };
        assert!(client.validate_authorization(&authorization).is_err());
    }

    #[test]
    fn auth_cli_vocabulary_is_google_github_only_and_local_commands_still_parse() {
        assert!(Cli::try_parse_from(["ast", "auth", "login", "--provider", "google"]).is_ok());
        assert!(Cli::try_parse_from(["ast", "auth", "login", "--provider", "github"]).is_ok());
        assert!(Cli::try_parse_from(["ast", "auth", "login", "--provider", "email"]).is_err());
        assert!(Cli::try_parse_from(["ast", "auth", "status"]).is_ok());
        assert!(Cli::try_parse_from(["ast", "auth", "logout"]).is_ok());
        assert!(Cli::try_parse_from(["ast", "create", "dev"]).is_ok());
        assert!(Cli::try_parse_from(["ast", "devices"]).is_ok());
    }

    #[test]
    fn backup_import_makes_cross_machine_materialization_explicit() {
        let parsed = Cli::try_parse_from([
            "ast",
            "backup",
            "import",
            "/tmp/bundle",
            "--backend",
            "vz",
            "--re-materialize",
        ])
        .unwrap();
        match parsed.command {
            Command::Backup(BackupCommand::Import {
                backend,
                rematerialize_oci,
                ..
            }) => {
                assert_eq!(backend.as_deref(), Some("vz"));
                assert!(rematerialize_oci);
            }
            _ => panic!("parsed the wrong backup command"),
        }
    }

    #[test]
    fn gpu_attach_and_detach_are_unambiguous_parts() {
        let parsed = Cli::try_parse_from([
            "ast",
            "attach",
            "guest",
            "--gpu",
            "desktop:GPU-01234567",
            "--gpu-memory",
            "2G",
        ])
        .unwrap();
        match parsed.command {
            Command::Attach {
                name,
                gpu,
                gpu_memory,
                ..
            } => {
                assert_eq!(name, "guest");
                assert_eq!(gpu.as_deref(), Some("desktop:GPU-01234567"));
                assert_eq!(gpu_memory.as_deref(), Some("2G"));
            }
            _ => panic!("parsed the wrong GPU command"),
        }
        assert!(Cli::try_parse_from([
            "ast", "attach", "guest", "--gpu", "desktop", "--volume", "tank"
        ])
        .is_err());
        assert!(Cli::try_parse_from(["ast", "detach", "guest", "--gpu"]).is_ok());
    }

    #[test]
    fn local_image_path_preserves_protocol_one_through_five() {
        for spoken in 1..=5 {
            assert_eq!(image_path(None, spoken), ImagePath::LocalCore);
            assert_eq!(image_path(Some("nas"), spoken), ImagePath::DeviceProtocol);
        }
        assert_eq!(image_path(None, 6), ImagePath::DeviceProtocol);
    }

    #[test]
    fn create_help_names_every_backend_and_native_default_selection() {
        let mut command = Cli::command();
        let help = command
            .find_subcommand_mut("create")
            .expect("create is a public command")
            .render_long_help()
            .to_string();
        assert!(help.contains("`chv` (Cloud Hypervisor/KVM)"), "{help}");
        assert!(
            help.contains("`vz` (Apple Virtualization.framework)"),
            "{help}"
        );
        assert!(help.contains("native `hyperv` on Windows"), "{help}");
        assert!(help.contains("`qemu` (compatibility)"), "{help}");
        assert!(
            help.contains("select this device's first capable native backend"),
            "{help}"
        );
        // AST-97: the help text is part of the one contract the formula, the
        // install script and the docs also state. QEMU is opt-in, never
        // installed by us, never chosen for the user, and the help names the
        // command that gets it.
        assert!(
            help.contains("never installs and never selects"),
            "--backend help must say QEMU is never auto-selected: {help}"
        );
        assert!(
            help.contains("brew install qemu"),
            "--backend help must name the opt-in install command: {help}"
        );
        assert!(
            Cli::try_parse_from(["ast", "create", "box", "--runtime", "container"]).is_err(),
            "OCI instances no longer accept a host-namespace runtime override"
        );
    }

    #[test]
    fn exec_is_public_argv_only_and_bounded_at_parse_time() {
        let parsed = parse_cli(&[
            "exec",
            "box",
            "--timeout",
            "12",
            "--",
            "/bin/printf",
            "%s",
            "hello",
        ]);
        assert!(matches!(
            parsed.command,
            Command::Exec { name, timeout: 12, command }
                if name == "box" && command == ["/bin/printf", "%s", "hello"]
        ));
        let help = Cli::command().render_long_help().to_string();
        assert!(help.contains("exec"), "{help}");
    }

    #[test]
    fn oci_profile_checks_use_guest_control_and_remote_directories_refuse_locally() {
        assert!(profile_check_uses_guest_control(ImageKind::OciRootfs));
        assert!(!profile_check_uses_guest_control(ImageKind::Disk));

        let remote = format!("{}-remote", asterism_core::instance::local_host());
        let error = volume_path("/srv/data", Some(&remote))
            .unwrap_err()
            .to_string();
        assert!(error.contains("cannot be attached"), "{error}");
        assert!(error.contains("<device>:<volume>"), "{error}");
    }

    #[test]
    fn local_console_tail_matches_remote_line_semantics_and_leaves_eof_cursor() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("console.log");
        std::fs::write(&path, b"one\ntwo\nthree\n").unwrap();
        let mut file = File::open(&path).unwrap();

        let (tail, truncated) = local_console_tail(&mut file, 2).unwrap();
        assert_eq!(tail, "two\nthree");
        assert!(truncated);
        assert_eq!(file.stream_position().unwrap(), 14);

        let mut all = File::open(path).unwrap();
        let (tail, truncated) = local_console_tail(&mut all, 0).unwrap();
        assert_eq!(tail, "one\ntwo\nthree\n");
        assert!(!truncated);
        assert_eq!(all.stream_position().unwrap(), 14);
    }

    #[test]
    fn ssh_guest_and_device_forms_remain_unambiguous() {
        let guest = Cli::try_parse_from(["ast", "ssh", "guest", "--", "uname", "-a"])
            .expect("the existing guest ssh form must keep parsing");
        match guest.command {
            Command::Ssh {
                name,
                host,
                command,
                ..
            } => {
                assert_eq!(name.as_deref(), Some("guest"));
                assert!(host.is_none());
                assert_eq!(command, ["uname", "-a"]);
            }
            _ => panic!("parsed the wrong command"),
        }

        let device = Cli::try_parse_from([
            "ast",
            "ssh",
            "--host",
            "laptop",
            "--",
            "printf",
            "hello world",
        ])
        .expect("the device shell form must parse without an instance name");
        match device.command {
            Command::Ssh {
                name,
                host,
                command,
                ..
            } => {
                assert!(name.is_none());
                assert_eq!(host.as_deref(), Some("laptop"));
                assert_eq!(command, ["printf", "hello world"]);
            }
            _ => panic!("parsed the wrong command"),
        }

        assert!(Cli::try_parse_from(["ast", "ssh", "guest", "--host", "laptop"]).is_err());
    }

    #[test]
    fn updater_sync_flushes_a_tree_and_an_absent_entries_parent() {
        let root = tempfile::tempdir().unwrap();
        let nested = root.path().join("app/Contents/MacOS");
        std::fs::create_dir_all(&nested).unwrap();
        let binary = nested.join("asterism-gui");
        std::fs::write(&binary, b"verified release bytes").unwrap();

        sync_update_path(&root.path().join("app"), true, false).unwrap();
        sync_update_path(&root.path().join("not-created"), false, true).unwrap();
    }

    #[test]
    fn bare_volume_names_are_orbit_parts_and_paths_stay_directories() {
        assert_eq!(storage_ref("tank", None), Some((None, "tank".into())));
        assert_eq!(
            storage_ref("nas:tank", None),
            Some((Some("nas".into()), "tank".into()))
        );
        assert_eq!(
            storage_ref("tank", Some("nas")),
            Some((Some("nas".into()), "tank".into()))
        );
        assert_eq!(storage_ref("/srv/tank", None), None);
        assert_eq!(storage_ref("./tank", None), None);
        assert_eq!(storage_ref("~/tank", None), None);
    }

    /// A reply is a line, and a line the daemon never ends is not a reply.
    /// `read_line` would grow until the newline arrived or the process ran
    /// out of memory, which puts the size of that allocation on the other end
    /// of the socket rather than here.
    #[test]
    fn a_reply_is_bounded_even_when_nothing_ends_it() {
        let one = b"{\"result\":\"pong\"}\nleftovers".to_vec();
        let mut reader = BufReader::new(std::io::Cursor::new(one));
        assert_eq!(
            read_frame(&mut reader).unwrap().as_deref(),
            Some(r#"{"result":"pong"}"#)
        );

        let endless = vec![b'x'; ipc::MAX_RESPONSE_FRAME + 4096];
        let mut reader = BufReader::new(std::io::Cursor::new(endless));
        let refusal = format!("{:#}", read_frame(&mut reader).unwrap_err());
        assert!(refusal.contains("without ending a reply"), "{refusal}");
    }

    /// Exactly the limit is a reply, and one byte past it is not — with the
    /// newline landing in the final buffer, which is where the check used to
    /// be skipped. `read_frame` had the same ordering bug as the daemon's
    /// `Frames::next`: the cap was consulted only on the path where a chunk
    /// carried no newline, so a reply that reached the cap and then sent its
    /// last byte and terminator together came back one byte over.
    ///
    /// The arithmetic is deliberate. `BufReader`'s buffer is 8 KiB and
    /// divides `MAX_RESPONSE_FRAME`, so a payload of exactly the limit fills
    /// whole chunks and the terminator arrives alone; a payload of limit+1
    /// puts the last byte and the terminator in the same final chunk, which
    /// is precisely the case under test.
    #[test]
    fn a_reply_is_measured_up_to_its_newline_and_not_past_it() {
        let mut exact = Vec::with_capacity(ipc::MAX_RESPONSE_FRAME + 1);
        exact.resize(ipc::MAX_RESPONSE_FRAME, b'a');
        exact.push(b'\n');
        let mut reader = BufReader::new(std::io::Cursor::new(exact));
        let line = read_frame(&mut reader)
            .unwrap()
            .expect("a reply at the limit is a reply");
        assert_eq!(line.len(), ipc::MAX_RESPONSE_FRAME);

        let mut over = Vec::with_capacity(ipc::MAX_RESPONSE_FRAME + 2);
        over.resize(ipc::MAX_RESPONSE_FRAME + 1, b'a');
        over.push(b'\n');
        let mut reader = BufReader::new(std::io::Cursor::new(over));
        let refusal = format!("{:#}", read_frame(&mut reader).unwrap_err());
        assert!(refusal.contains("without ending a reply"), "{refusal}");
    }

    /// Nothing at all, and nothing but a newline, are both "astd said
    /// nothing" rather than a reply to parse.
    #[test]
    fn an_empty_reply_is_not_a_reply() {
        let mut nothing = BufReader::new(std::io::Cursor::new(Vec::new()));
        assert!(read_frame(&mut nothing).unwrap().is_none());
        let mut blank = BufReader::new(std::io::Cursor::new(b"\n".to_vec()));
        assert!(read_frame(&mut blank).unwrap().is_none());
    }

    /// A reply that ends in the middle is a broken daemon, not an empty
    /// answer — the difference matters because one of them is a message the
    /// user can act on and the other reads as "nothing is wrong".
    #[test]
    fn a_reply_cut_off_mid_line_is_an_error() {
        let mut cut = BufReader::new(std::io::Cursor::new(b"{\"result\":".to_vec()));
        let refusal = format!("{:#}", read_frame(&mut cut).unwrap_err());
        assert!(refusal.contains("middle of a reply"), "{refusal}");
    }

    #[test]
    fn guest_health_is_compact_and_only_printed_when_reported() {
        assert!(guest_health_lines(None).is_empty());
        assert_eq!(
            guest_health_lines(Some(&GuestHealth {
                addrs: vec!["192.168.64.7".parse().unwrap()],
                uptime_secs: 125.9,
                ssh: true,
                cloud_init: "done".into(),
                load1: Some(0.42),
                mem_available_kib: Some(1_572_864),
            })),
            vec![
                "guest:   192.168.64.7 · up 2m · ssh listening · cloud-init done",
                "health:  load 0.42 · memory 1536 MiB available",
            ]
        );
    }
}
