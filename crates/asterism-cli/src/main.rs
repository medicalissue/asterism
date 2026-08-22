//! ast — the Asterism CLI.
//!
//! Talks to the local `astd` daemon over its unix socket, starting the
//! daemon on demand if it is not running. Image pulls run here in the
//! foreground so the user sees download progress.
//!
//! It talks to *that* daemon and no other, ever. `ast up dev` does not know or
//! care which device in the orbit is supplying `dev`'s cpu and ram: the
//! instance namespace is flat and orbit-wide, so the name is enough, and the
//! daemon in front of you resolves it and forwards the request if the row
//! lives elsewhere. The CLI holds no device key, opens no mesh connection, and
//! knows nothing about how a peer is reached — all of which lives in `astd`,
//! which is the process that is always running.
//!
//! `--device` survives as a debugging tool, for asking one specific daemon a
//! question about itself, and as the address for the commands that really are
//! about devices: pairing, and the orbit's own membership.

use std::fs::File;
use std::io::{BufRead, BufReader, IsTerminal, Read, Seek, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};

use asterism_core::compat;
use asterism_core::device_shell::{
    ShellData, ShellEnv, ShellOpen, ShellOutput, ShellPolicyAction, ShellPolicyState,
    MAX_DATA_BYTES,
};
use asterism_core::hv::ImageKind;
use asterism_core::instance::{now_unix, Instance, PortForward, Restart, Shape};
use asterism_core::ipc;
use asterism_core::proc::{ProcId, Signal};
use asterism_core::protocol::{self, Request, Response};
use asterism_core::registry::OrbitRow;
use asterism_core::{cow, image, oci, paths, service, snapshot, verify, VERSION};

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
    /// Define a new instance, sourcing its cpu and ram from this device.
    ///
    /// The name is claimed across the whole orbit, so it means one instance
    /// everywhere.
    Create {
        /// What to call it: ascii letters, digits and `-`. One name means
        /// one instance everywhere in the orbit.
        name: String,
        /// Image to boot: an alias (`ast images`), an https:// url, a path to
        /// a qcow2 or raw disk image, or an OCI/Docker reference such as
        /// `nginx` or `ghcr.io/owner/app:v1` — which is pulled, unpacked and
        /// booted as a microVM of its own.
        #[arg(long, default_value = "ubuntu:24.04")]
        image: String,
        /// Publish a guest port on this device's loopback: `-p 8080:80`.
        ///
        /// How an OCI instance is reached: a container image has no ssh
        /// server, so the port it listens on is the way in. Repeatable.
        #[arg(short = 'p', long = "publish", value_name = "HOST:GUEST")]
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
        /// Hypervisor to run this instance on: `qemu` (default) or `vz`,
        /// Apple's Virtualization.framework — faster to boot and needing no
        /// `brew install qemu`, on macOS 14+ with a signed helper. Recorded
        /// on the instance and used for every later boot.
        #[arg(long, value_name = "NAME")]
        backend: Option<String>,
        /// Bootstrap profile to apply at first boot (`ast profiles` lists
        /// them). Repeatable, and what a profile needs comes with it:
        /// `--profile claude` installs the base tools and Node too.
        ///
        /// The image stays whatever you asked for. A profile is applied
        /// inside the guest by its own systemd unit, so ssh answers while
        /// the packages are still landing — `ast profile <name> --check`
        /// says when it is done and what it got.
        #[arg(long = "profile", value_name = "NAME")]
        profiles: Vec<String>,
    },
    /// Boot an instance.
    ///
    /// Where its cpu and ram come from is the instance's business, not the
    /// command's: the name resolves across the orbit and the boot happens on
    /// whichever device supplies them.
    Up {
        /// The instance to boot.
        name: String,
        /// What to do when this guest dies: `always` (the default) brings it
        /// back after a crash and after a host reboot, `never` leaves it
        /// down. Recorded on the instance, so it holds for later boots too
        /// and shows up in `ast status`.
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
        /// Only the instances this device supplies cpu for (debugging).
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
    /// Attach a part to an instance: a volume, or a secret.
    ///
    /// Two kinds of volume, and they reach the guest differently.
    ///
    /// A DIRECTORY (`--volume /tank/media`) is shared with the guest and
    /// mounted at a path. Three things have to be true, and each of them is
    /// refused in words rather than discovered later: the directory is on
    /// the same device as the instance's cpu and ram (directory sharing has
    /// no network transport), the backend offers a share transport (9p on
    /// qemu or virtiofs on vz), and the guest boots a cloud image whose
    /// kernel supports that transport (an OCI instance has no init to mount
    /// anything with).
    ///
    /// A BLOCK VOLUME (`--volume desktop:tank`, made with `ast volume
    /// create`) arrives as a plain disk: /dev/vdb, /dev/vdc and so on. The
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
        /// A directory path, or `<device>:<volume>` for a block volume.
        #[arg(long, conflicts_with = "secret")]
        volume: Option<String>,
        /// Device that provides the volume (default: this device).
        #[arg(long, requires = "volume")]
        host: Option<String>,
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
    },
    /// Change one of an instance's parts.
    ///
    /// Today there is one: `cpu`, which is the device supplying cpu and ram.
    /// The orbit is a pool of parts and an instance is a computer assembled
    /// from them, so this really is one line of a parts table — the
    /// instance's name, its id and its snapshots do not move, because they
    /// were never on a device.
    Set {
        /// The instance whose part is changing.
        name: String,
        /// The part to change. `cpu` is the only one today.
        #[arg(value_name = "PART")]
        part: String,
        /// The device to source it from.
        //
        // Not called `device`: `--device` is a global flag with that id, and
        // clap would hand this positional's value to it.
        #[arg(value_name = "DEVICE")]
        to: String,
        /// Shut the guest down first. Moving cpu/ram is offline on every
        /// backend Asterism has, so a running instance is refused without it.
        #[arg(long)]
        down: bool,
    },
    /// Move an instance's cpu and ram to another device.
    ///
    /// The same thing as `ast set <instance> cpu <device>`, spelled the way
    /// people ask for it.
    Move {
        /// The instance to move.
        name: String,
        /// The device that will supply its cpu and ram from here on.
        #[arg(value_name = "DEVICE")]
        to: String,
        /// Shut the guest down first.
        #[arg(long)]
        down: bool,
    },
    /// Create, list and delete this device's block volumes.
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
    },
}

/// `ast volume ...` — the block storage one device puts in the pool.
///
/// Volumes belong to the device that holds their bytes, and their names are
/// per-device rather than orbit-global: `desktop:tank` and `nas:tank` are two
/// volumes. So these commands are about *this* device unless `--device` says
/// otherwise, which is the opposite of how instance commands work and is the
/// honest way round — the bytes are somewhere in particular.
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
    /// List this device's block volumes and who holds each one.
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
            // Resolved here as well as in the daemon, because a mistyped
            // profile should cost the user a message rather than a
            // gigabyte: `ensure_pulled` below downloads the image.
            asterism_core::profile::resolve(&profiles)?;
            // An image for another device has to be on that device: pulling it
            // here would fill this disk and still leave the far one without it.
            let resolved = match &device {
                Some(_) => image.clone(),
                None => ensure_pulled(&image)?,
            };
            Request::Create {
                name,
                image: resolved,
                shape: Shape {
                    cpus,
                    mem_mib: parse_mem_mib(&mem)?,
                    disk_gib: parse_disk_gib(&disk)?,
                },
                backend,
                profiles,
                publish: publish
                    .iter()
                    .map(|p| p.parse::<PortForward>())
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|e| anyhow::anyhow!(e))?,
            }
        }
        Command::Up { name, restart } => Request::Up { name, restart },
        Command::Down { name } => Request::Down { name },
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
            at,
            secret,
            to,
            placement,
            env,
            from,
        } => match attaching(volume, secret)? {
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
            Attaching::Volume(volume) => match block_ref(&volume, host.as_deref()) {
                Some((device, volume)) => {
                    if at.is_some() {
                        bail!(
                            "--at is for directory volumes; a block volume arrives as a \
                                 disk and the guest mounts it wherever it likes"
                        );
                    }
                    warn_if_far(&device);
                    Request::AttachBlock {
                        name,
                        volume,
                        device,
                    }
                }
                None => Request::AttachVolume {
                    name,
                    path: volume_path(&volume, host.as_deref())?,
                    host,
                    mount_point: at,
                },
            },
        },
        Command::Detach {
            name,
            volume,
            host,
            secret,
        } => match attaching(volume, secret)? {
            Attaching::Secret(secret) => Request::DetachSecret { name, secret },
            Attaching::Volume(volume) => match block_ref(&volume, host.as_deref()) {
                Some((device, volume)) => Request::Detach {
                    name,
                    volume,
                    host: Some(device),
                },
                None => Request::Detach {
                    name,
                    volume: volume_path(&volume, host.as_deref())?,
                    host,
                },
            },
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
            return set_part(&name, "cpu", &to, down);
        }
        // A volume is a device's part of the pool, so these are about the
        // daemon in front of you unless `--device` aims them elsewhere.
        Command::Volume(VolumeCommand::Create { name, size }) => Request::VolumeCreate {
            name,
            size_bytes: asterism_core::volume::parse_size(&size)?,
        },
        Command::Volume(VolumeCommand::Ls) => Request::VolumeList,
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
        Command::Backup(BackupCommand::Import { source, name }) => {
            let source = absolute_path(&source)?;
            let manifest = asterism_core::backup::inspect(&source)?;
            Request::BackupImport {
                source: source.display().to_string(),
                name: name.unwrap_or(manifest.instance.name),
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
        // The image store is per device, so both of these are about this one.
        Command::Images { verify } => {
            local_only("images", device.as_deref())?;
            return print_images(verify);
        }
        Command::Pull { image } => {
            local_only("pull", device.as_deref())?;
            ensure_pulled(&image)?;
            return Ok(());
        }
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
    };

    match send(&aimed(request.clone(), device.as_deref()))? {
        Response::Ok => {}
        Response::Instance { instance } => match request {
            Request::Status { .. } => print_detail(&instance),
            Request::SetProfiles { .. } => print_profile_state(&instance),
            Request::Remove { .. } => println!("{}  removed", instance.name),
            Request::Rename { name, .. } => println!("{name}  renamed to {}", instance.name),
            Request::Up { .. } => {
                println!("{}  {}", instance.name, instance.status);
                // An OCI guest has no ssh to offer, so it is told what it
                // does have: its ports, and its console.
                if instance.image_kind == ImageKind::OciRootfs {
                    for p in &instance.publish {
                        println!("published: http://127.0.0.1:{}  ->  guest :{}", p.host, p.guest);
                    }
                    println!("the image's output is on the console — ast logs {}", instance.name);
                } else if let Some(endpoint) = instance.endpoint() {
                    println!(
                        "guest booting; ssh on {endpoint} — try: ast ssh {}",
                        instance.name
                    );
                }
            }
            Request::AttachVolume { .. } | Request::AttachBlock { .. } => {
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
            _ => println!("{}  {}", instance.name, instance.status),
        },
        Response::Volumes { volumes } => match request {
            Request::VolumeCreate { .. } => print_volume_made(&volumes),
            Request::VolumeRemove { name } => println!("{name}  removed"),
            _ => print_volumes(&volumes),
        },
        Response::Orbit { rows } => print_table(&rows),
        // One device's shard, asked for by `--local` or `--device`. Rows from
        // a single shard are live by construction: the device answered.
        Response::Instances { instances } => print_table(
            &instances
                .into_iter()
                .map(|instance| OrbitRow { instance, live: true })
                .collect::<Vec<_>>(),
        ),
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
            if report.rebind.volumes.is_empty() && report.rebind.secrets.is_empty() {
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
            }
        }
        // The handshake owns Pong, `ast snapshots` owns Snapshots, `ast ssh`
        // and `ast logs` return long before here. Any of them arriving is astd
        // answering a different question.
        Response::Snapshots { .. }
        | Response::Log { .. }
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
    }
    Ok(())
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
    println!(
        "external parts to rebind: {} volume(s), {} secret(s)",
        manifest.rebind.volumes.len(),
        manifest.rebind.secrets.len()
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
    let (status, revoked) = match send(&Request::DeviceShellPolicy { action })? {
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

/// `ast set <instance> cpu <device>`, and its alias `ast move`.
///
/// The daemon does all of it — resolving the instance across the orbit,
/// probing the target, fencing the source, moving the bytes and committing —
/// and reports each step as it happens, because the middle one is a disk
/// crossing a network and takes as long as it takes. All this end does is
/// print.
fn set_part(name: &str, part: &str, device: &str, down: bool) -> Result<()> {
    // One part today, and saying which one is better than a flag: the user
    // has to be able to see, from the command, what is being changed.
    if !matches!(part, "cpu" | "cpu/ram" | "ram") {
        bail!(
            "there is no {part:?} part to set. Today `ast set <instance> cpu <device>` \
             moves cpu and ram, which come as a pair; volumes are changed with \
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

/// Resolve an image reference, download it if it is not cached yet, and
/// leave the store holding a raw base image either way.
/// Returns the canonical name to record on the instance.
///
/// Cloud images are published as qcow2 and instances are built from raw
/// (BACKENDS.md §4), so a pull is a download *and* a conversion. Both run
/// here, in the foreground, where the user can see them: the alternative is
/// a mysterious pause inside the first `ast up`.
fn ensure_pulled(reference: &str) -> Result<String> {
    let resolved = image::resolve(reference)?;
    if let Some(image) = &resolved.oci {
        return pull_oci(image);
    }
    // Before anything that could delete a file: a local image is the user's,
    // and the only thing that happens to it here is that its identity is
    // written down, in the store, so a boot can tell whether the file they
    // pointed at is still the file they pointed at.
    let (Some(url), Some(staging)) = (&resolved.url, &resolved.staging) else {
        resolved.record_local()?;
        return Ok(resolved.name);
    };

    if resolved.path.exists() {
        // Present is not the same as sound. A store that was corrupted since
        // the last pull should be repaired by the command whose whole job is
        // to make the image available, not discovered at the next `ast up`.
        // Safe to delete because everything reaching this line is a file
        // this store downloaded and can download again.
        if let Err(e) = resolved.verify_bootable() {
            eprintln!("{}: {e:#}", resolved.name);
            eprintln!("re-pulling it");
            resolved.discard();
        } else {
            return Ok(resolved.name);
        }
    }

    if !staging.exists() {
        if let Some(dir) = staging.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let part = staging.with_extension("qcow2.part");
        let _ = std::fs::remove_file(&part);
        eprintln!("pulling {} ({})", resolved.name, url);
        // Always `Some` by the time a download starts: `image::resolve`
        // refuses a source with nothing to check it against before any of
        // this runs.
        if let Some(want) = &resolved.expected {
            eprintln!("it must hash to {want}");
        }
        let status = std::process::Command::new("curl")
            .arg("--location")
            .arg("--fail")
            .arg("--progress-bar")
            .arg("--output")
            .arg(&part)
            .arg(url)
            .status()
            .context("running curl")?;
        if !status.success() {
            let _ = std::fs::remove_file(&part);
            bail!("download failed for {url}");
        }
        // Verified here, before the download can be mistaken for a resumable
        // one: a `.part` left behind by a poisoned mirror would otherwise be
        // skipped by the `!staging.exists()` above on the next run. Adoption
        // is also where it is forced down before it takes its final name —
        // half a cloud image under the name of a whole one is a boot failure
        // with no clue in it.
        verify::adopt(
            &part,
            staging,
            resolved.expected.as_ref(),
            verify::Source::new("download", url),
        )?;
    }

    // Converting an image already in the store is how a cache written by an
    // older Asterism migrates; `ast pull` is just the polite place to do it.
    eprintln!("converting {} to a raw base image", resolved.name);
    resolved.materialise()?;
    eprintln!("pulled {} -> {}", resolved.name, resolved.path.display());
    Ok(resolved.name)
}

/// Pull an OCI image and leave a bootable filesystem in the store.
///
/// Here rather than in the daemon for the same reason a cloud image download
/// is: it is minutes of network and disk that the user should be able to
/// watch, and a daemon doing it silently inside `ast up` is the version of
/// this that people hate. The guest kernel comes first — the image has none,
/// and finding that out at the first `ast up` would be worse than a slightly
/// longer pull.
fn pull_oci(image: &oci::Reference) -> Result<String> {
    if oci::ensure_kernel(|url, dest| {
        eprintln!("fetching the guest kernel ({url})");
        download(url, dest)
    })? {
        eprintln!("guest kernel ready — every OCI instance on this device shares it");
    }

    eprintln!("pulling {image}");
    let pulled = oci::pull(image, true)?;
    match pulled.built {
        true => eprintln!(
            "pulled {image} -> {} ({})",
            pulled.image.display(),
            pulled.digest
        ),
        false => eprintln!(
            "{image} is already built on this device ({})",
            pulled.digest
        ),
    }
    // What the machine will actually run, said out loud: it is the one thing
    // about a container image that decides whether the instance does anything.
    let argv = pulled.config.argv();
    if !argv.is_empty() {
        eprintln!("entrypoint: {}", argv.join(" "));
    }
    let ports = pulled.config.tcp_ports();
    if let Some(first) = ports.first() {
        let list: Vec<String> = ports.iter().map(|p| p.to_string()).collect();
        // Suggest a host port the user can actually bind: below 1024 needs
        // root on macOS and Linux alike.
        let host = if *first < 1024 { first + 8000 } else { *first };
        eprintln!(
            "the image listens on {} — publish it with: \
             ast create <name> --image {image} -p {host}:{first}",
            list.join(", "),
        );
    }
    Ok(image.canonical())
}

/// An image reference short enough for a table column.
///
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

/// One file off the network, with a progress bar. The same `curl` the cloud
/// image path uses, for the same reason: it is already on every host and it
/// reports progress better than anything worth linking in.
fn download(url: &str, dest: &std::path::Path) -> Result<()> {
    if let Some(dir) = dest.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let status = std::process::Command::new("curl")
        .args(["--location", "--fail", "--progress-bar", "--output"])
        .arg(dest)
        .arg(url)
        .status()
        .context("running curl")?;
    if !status.success() {
        let _ = std::fs::remove_file(dest);
        bail!("download failed for {url}");
    }
    Ok(())
}

fn print_images(full: bool) -> Result<()> {
    let depth = if full {
        verify::Depth::Full
    } else {
        verify::Depth::Quick
    };
    let mut unsound = 0usize;
    // `PULLED` answers two questions at once, because they are the same
    // question to the person reading it: is it here, and can it be booted.
    println!(
        "{:<14} {:<8} SOURCE ({})",
        "NAME",
        "PULLED",
        image::host_arch()
    );
    for entry in image::CATALOG {
        let r = image::resolve(entry.alias)?;
        // An image pulled by an older Asterism is still on this device even
        // though it has not been converted yet, and saying "-" would send
        // the user off to re-download something they already have.
        let pulled = match r.is_pulled() {
            false => "-".to_owned(),
            true => match verify_row(&r.path, &r.record, depth) {
                Ok(()) => "yes".to_owned(),
                Err(e) => {
                    unsound += 1;
                    eprintln!("{}: {e:#}", entry.alias);
                    "BAD".to_owned()
                }
            },
        };
        println!(
            "{:<14} {:<8} {}",
            entry.alias,
            pulled,
            r.url.as_deref().unwrap_or("-")
        );
    }
    // Container images are not a catalog — the catalog is Docker Hub — but
    // the ones this device has built are as real as any row above, and
    // nothing else would tell the user what is taking up the space.
    for reference in oci::built()? {
        let state =
            match image::resolve(&reference).and_then(|r| verify_row(&r.path, &r.record, depth)) {
                Ok(()) => "yes".to_owned(),
                Err(e) => {
                    unsound += 1;
                    eprintln!("{reference}: {e:#}");
                    "BAD".to_owned()
                }
            };
        println!("{:<14} {:<8} {}", short_image(&reference), state, reference);
    }
    if unsound > 0 {
        println!(
            "\n{unsound} image(s) marked BAD: the bytes on disk are not the ones that were \
             pulled.\nThey will be refused at boot. `ast pull <name>` replaces one."
        );
    }
    println!("\nalso accepted: an https:// url, a path to a local qcow2 or raw image, or");
    println!("an OCI/Docker reference — `nginx`, `ghcr.io/owner/app:v1` — booted as a");
    println!("microVM from the image's own filesystem (ast create web --image nginx -p 8080:80)");
    println!("a url must pin its bytes: --image https://mirror/x.qcow2#sha256:<hex>");
    println!("(sha256, sha512 and blake3 are accepted; a path may pin its bytes too)");
    Ok(())
}

/// One row's verdict: is what is on disk still what was pulled?
///
/// An image only half-migrated by an older Asterism — the qcow2 is there and
/// the raw is not — has nothing to check yet, and saying so is not a
/// complaint about it.
fn verify_row(
    path: &std::path::Path,
    record: &std::path::Path,
    depth: verify::Depth,
) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }
    verify::check_recorded(path, record, depth)
}

// ---- volumes ---------------------------------------------------------------

/// Read `--volume` as a block volume, or decide it is a directory.
///
/// `<device>:<volume>` is the written form. A bare name plus `--host` is
/// accepted too, because a directory on another device has always had to be
/// an absolute path — so a relative-looking name with a device attached
/// cannot have meant a directory.
fn block_ref(volume: &str, host: Option<&str>) -> Option<(String, String)> {
    if let Some((device, name)) = asterism_core::volume::parse_ref(volume) {
        return Some((device, name));
    }
    let host = host?;
    let looks_like_a_path =
        volume.starts_with('/') || volume.starts_with('.') || volume.starts_with('~');
    (!looks_like_a_path && asterism_core::volume::check_name(volume).is_ok())
        .then(|| (host.to_owned(), volume.to_owned()))
}

/// Above this, a block volume is worth thinking about rather than assuming.
///
/// NBD does a round trip per I/O the guest's queue cannot hide, so latency is
/// the number that decides whether a remote volume feels like a disk or like
/// a mistake. A LAN is well under a millisecond; a WAN is not.
const SLOW_LINK_MS: f64 = 5.0;

/// Say so, once, if the device holding the bytes is far away.
///
/// A note rather than a refusal: a slow volume is exactly right for an
/// archive and exactly wrong for a database, and only the person attaching it
/// knows which this is. Silent if the device cannot be reached — the attach
/// itself is about to say so much better than a ping could.
fn warn_if_far(device: &str) {
    let Ok(Response::DevicePong { millis, .. }) = send(&Request::DevicePing {
        device: device.to_owned(),
    }) else {
        return;
    };
    if millis > SLOW_LINK_MS {
        eprintln!(
            "note: {device} is {millis:.1}ms away — a volume over a link this slow \
             reads like a slow disk. Fine for archives and backups; poor for a \
             database or a build tree."
        );
    }
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
        if !volume.starts_with('/') {
            bail!("a volume on another device must be given as an absolute path");
        }
        return Ok(volume.to_owned());
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
    let (cols, rows) = if pty {
        terminal_size(libc::STDIN_FILENO)
    } else {
        (0, 0)
    };
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
        Some(RawTerminal::enter(libc::STDIN_FILENO)?)
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
            let mut previous = terminal_size(libc::STDIN_FILENO);
            while !stop.load(Ordering::Relaxed) {
                std::thread::sleep(Duration::from_millis(100));
                let now = terminal_size(libc::STDIN_FILENO);
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

fn terminal_size(fd: libc::c_int) -> (u16, u16) {
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

struct RawTerminal {
    fd: libc::c_int,
    saved: libc::termios,
}

impl RawTerminal {
    fn enter(fd: libc::c_int) -> Result<Self> {
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

impl Drop for RawTerminal {
    fn drop(&mut self) {
        // SAFETY: saved came from this descriptor and remains initialized.
        unsafe {
            libc::tcsetattr(self.fd, libc::TCSANOW, &self.saved);
        }
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
/// waiting for a banner that is never coming. What the user wanted is one of
/// the two things named here: the console, or the port.
fn refuse_ssh_to_an_oci_guest(name: &str) -> Result<()> {
    let Ok(Response::Instance { instance }) = send(&Request::Status { name: name.into() }) else {
        return Ok(()); // no such instance: let the endpoint request say so
    };
    if instance.image_kind != ImageKind::OciRootfs {
        return Ok(());
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
         its output is the console (ast logs {name}), and {reach}"
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
        Response::Instance { instance } => {
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
    // An instance with no profiles has no verifier inside it, and `ssh`
    // would answer that with `command not found` and an exit status. Asking
    // the record first turns that into the sentence it should have been.
    if let Response::Instance { instance } = send(&Request::Status { name: name.into() })? {
        if instance.profiles.is_empty() {
            bail!(
                "{name} has no bootstrap profiles, so there is nothing in it to ask — \
                 ast profile {name} claude, then ast down {name} && ast up {name}"
            );
        }
    }
    // From here the guest answers for itself, and its exit status is this
    // command's: a failed check is a failed command, which is what a script
    // that runs this after a boot needs it to be.
    ssh(
        name,
        &[
            "sudo".to_owned(),
            "/usr/local/sbin/asterism-check".to_owned(),
        ],
    )
}

// ---- logs ------------------------------------------------------------------

/// Print the guest's serial console, wherever the guest is.
///
/// When this device is the one supplying the instance's cpu, the console is a
/// file in the instance directory and is read straight off disk — which is
/// also the only way `--follow` can work, since following is a file operation
/// and there is no file here otherwise. When the cpu is elsewhere, the daemon
/// reads it there and sends the tail back.
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
    logs_here(name, follow)
}

/// The console log as a file on this device's disk.
fn logs_here(name: &str, follow: bool) -> Result<()> {
    let path = paths::instance_dir(name).join("console.log");
    let mut file = File::open(&path).map_err(|_| {
        anyhow::anyhow!(
            "no console log for {name:?} yet — `ast up {name}` starts one at {}",
            path.display()
        )
    })?;

    let mut out = std::io::stdout();
    drain(&mut file, &mut out)?;
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
    stream: UnixStream,
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
fn handshake() -> Result<(UnixStream, DaemonFacts)> {
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
fn connect() -> Result<UnixStream> {
    let sock = paths::socket_path();
    if ipc::audit_socket(&sock)? == ipc::SocketState::Ready {
        if let Ok(stream) = UnixStream::connect(&sock) {
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
fn start_daemon(sock: &std::path::Path) -> Result<UnixStream> {
    let _turn = spawn_turn();
    // Whoever held the lock before us has already started one.
    if let Ok(stream) = UnixStream::connect(sock) {
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
    write: UnixStream,
    read: BufReader<UnixStream>,
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

fn wait_for_socket(sock: &std::path::Path) -> Result<UnixStream> {
    let mut attempt = 0;
    loop {
        match UnixStream::connect(sock) {
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
    if let Ok(me) = std::env::current_exe() {
        let sibling = me.with_file_name("astd");
        if sibling.exists() {
            return Ok(sibling);
        }
    }
    Ok(std::path::PathBuf::from("astd"))
}

fn exec_daemon() -> anyhow::Error {
    use std::os::unix::process::CommandExt;
    let astd = match daemon_path() {
        Ok(p) => p,
        Err(e) => return e,
    };
    std::process::Command::new(astd).exec().into()
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
    let stream = UnixStream::connect(paths::socket_path()).ok()?;
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
    let mut stream = UnixStream::connect(paths::socket_path()).ok()?;
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
    std::path::PathBuf::from("/Applications/Asterism.app/Contents/MacOS/asterism-gui")
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
/// The CPU column says which device is supplying each instance's cpu and ram.
/// It is a column and not a grouping on purpose — the rows are one flat list
/// because the namespace is one flat namespace, and where the cpu comes from
/// is a property of the instance, like its shape or its age.
fn print_table(rows: &[OrbitRow]) {
    if rows.is_empty() {
        println!("no instances — start with: ast create <name>");
        return;
    }
    println!(
        "{:<14} {:<9} {:<14} {:<16} {:<12} {:<6} SSH",
        "NAME", "STATUS", "IMAGE", "SHAPE", "CPU", "AGE"
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
        let ssh = match (row.live, inst.endpoint()) {
            (true, Some(e)) => e.to_string(),
            _ => "-".into(),
        };
        println!(
            "{:<14} {:<9} {:<14} {:<16} {:<12} {:<6} {}",
            inst.name,
            status,
            short_image(inst.image.as_deref().unwrap_or("-")),
            shape,
            inst.cpu_device,
            age(inst.created_at),
            ssh,
        );
    }
    if stale {
        println!("\nunknown: the device supplying that instance's cpu is out of touch");
    }
    for name in conflicts {
        println!("\nconflict: {name} shares its name — rename it: ast rename {name} <new-name>");
    }
}

/// `ast status`: the instance, then the parts it is assembled from and where
/// in the pool each of them is sourced.
fn print_detail(inst: &Instance) {
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
        println!("running: {} pid {pid}, ssh {}", h.backend, h.endpoint);
        println!("control: {}", h.ctl.path().display());
    }
    if let Some(conflict) = &inst.conflict {
        println!(
            "conflict: another instance in this orbit is also called {:?} \
             (cpu/ram on {}) — rename this one: ast rename {} <new-name>",
            inst.name, conflict.other_cpu_device, inst.name
        );
    }
    // Only worth a line once it has happened: an instance that has never had
    // its cpu part swapped is the ordinary case and does not need telling.
    if inst.move_epoch > 0 {
        println!(
            "moves:   {} (cpu/ram has been re-sourced that many times)",
            inst.move_epoch
        );
    }
    // Worth a line only when it is not the obvious answer: a guest trusts
    // the key in its seed, and after a move that is not the device running it.
    if inst.seeded_by() != inst.cpu_device {
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

/// What an instance's root disk is, and what it actually costs today.
///
/// Read off the filesystem rather than the registry, because both halves
/// are facts about the file: a disk cloned from a raw base occupies almost
/// nothing until the guest writes to it, and a `disk.qcow2` says this
/// instance predates raw disks and still takes the old snapshot path
/// (BACKENDS.md §4). Only when this device supplies the cpu/ram; another
/// device's disks are not ours to stat.
fn local_disk(inst: &Instance) -> Option<String> {
    if inst.cpu_device != asterism_core::instance::local_host() {
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
}

fn attaching(volume: Option<String>, secret: Option<String>) -> Result<Attaching> {
    match (volume, secret) {
        (Some(volume), None) => Ok(Attaching::Volume(volume)),
        (None, Some(secret)) => Ok(Attaching::Secret(secret)),
        // clap refuses this one first; the arm exists so that adding a third
        // part later cannot make it fall through to "say which".
        (Some(_), Some(_)) => bail!(
            "--volume and --secret are two different parts — attach them one command at a time"
        ),
        (None, None) => bail!(
            "say which part: --volume /tank/media, --volume desktop:tank, or \
             --secret anthropic --to api.anthropic.com"
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
            let path = prefix.join("libexec/asterism/asterism-update");
            path.is_file().then_some(path)
        })
        // A source checkout can exercise the same updater without installing
        // into the developer's prefix. Published binaries never need this.
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

    let mut process = std::process::Command::new(&updater);
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
                process.arg("--yes");
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
    if UnixStream::connect(paths::socket_path()).is_ok() {
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
}
