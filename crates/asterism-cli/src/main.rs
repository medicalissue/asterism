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
use std::time::Duration;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};

use asterism_core::hv::ImageKind;
use asterism_core::instance::{now_unix, Instance, PortForward, Restart, Shape};
use asterism_core::protocol::{self, Request, Response};
use asterism_core::registry::OrbitRow;
use asterism_core::{cow, image, oci, paths, service, snapshot, VERSION};

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
        /// The instance to connect to.
        name: String,
        /// A command to run instead of opening a shell, and its arguments.
        #[arg(trailing_var_arg = true)]
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
    /// List known images and whether they are downloaded.
    ///
    /// This device's image store: the aliases it knows and what is already
    /// on its disk. Every device has its own.
    Images,
    /// Download an image into this device's store.
    Pull {
        /// The image to download: an alias, an https:// url, a path, or an
        /// OCI/Docker reference.
        image: String,
    },
    /// Attach a part to an instance: a volume, or a secret.
    ///
    /// Two kinds of volume, and they reach the guest differently.
    ///
    /// A DIRECTORY (`--volume /tank/media`) is shared with the guest and
    /// mounted at a path. Three things have to be true, and each of them is
    /// refused in words rather than discovered later: the directory is on
    /// the same device as the instance's cpu and ram (9p has no network
    /// transport and never will), the backend can share one (qemu, today —
    /// not vz), and the guest boots a cloud image whose kernel has 9p in it
    /// (an OCI instance has no init to mount anything with).
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
    /// Install, remove or inspect astd as a service the OS keeps running.
    #[command(subcommand)]
    Service(ServiceCommand),
    /// Run the device daemon in the foreground.
    Daemon,
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
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let device = cli.device;

    let request = match cli.command {
        Command::Create { name, image, publish, cpus, mem, disk, backend } => {
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
        Command::Attach { name, volume, host, at, secret, to, placement, env, from } => {
            match attaching(volume, secret)? {
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
                        Request::AttachBlock { name, volume, device }
                    }
                    None => Request::AttachVolume {
                        name,
                        path: volume_path(&volume, host.as_deref())?,
                        host,
                        mount_point: at,
                    },
                },
            }
        }
        Command::Detach { name, volume, host, secret } => match attaching(volume, secret)? {
            Attaching::Secret(secret) => Request::DetachSecret { name, secret },
            Attaching::Volume(volume) => match block_ref(&volume, host.as_deref()) {
                Some((device, volume)) => {
                    Request::Detach { name, volume, host: Some(device) }
                }
                None => Request::Detach {
                    name,
                    volume: volume_path(&volume, host.as_deref())?,
                    host,
                },
            },
        },
        // A move reports as it goes — a preflight, a fence, a disk crossing a
        // network — so it takes the connection the way pairing and wake do.
        Command::Set { name, part, to, down } => {
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
        Command::Logs { name, follow, lines } => {
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
        Command::Restore { name, tag } => {
            return restore_snapshot(&name, &tag, device.as_deref())
        }
        // The image store is per device, so both of these are about this one.
        Command::Images => {
            local_only("images", device.as_deref())?;
            return print_images();
        }
        Command::Pull { image } => {
            local_only("pull", device.as_deref())?;
            ensure_pulled(&image)?;
            return Ok(());
        }
        // Which device is running the guest is the daemon's problem, not the
        // user's and not this process's: it answers with a loopback port
        // either way.
        Command::Ssh { name, command } => {
            local_only("ssh", device.as_deref())?;
            return ssh(&name, &command);
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
        Command::Service(cmd) => {
            local_only("service", device.as_deref())?;
            return service_command(cmd);
        }
        Command::Daemon => {
            local_only("daemon", device.as_deref())?;
            let err = exec_daemon();
            return Err(err).context("running astd");
        }
    };

    match send(&aimed(request.clone(), device.as_deref()))? {
        Response::Ok => {}
        Response::Instance { instance } => match request {
            Request::Status { .. } => print_detail(&instance),
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
        // The handshake owns Pong, `ast snapshots` owns Snapshots, `ast ssh`
        // and `ast logs` return long before here. Any of them arriving is astd
        // answering a different question.
        Response::Snapshots { .. }
        | Response::Log { .. }
        | Response::SshEndpoint { .. }
        | Response::Pong { .. }
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
        Some(name) => Request::Proxy { device: name.to_owned(), inner: Box::new(request) },
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
    println!("{:<24} {:<14} {:<8} PATH", "NAME", "DEVICE ID", "STATUS");
    for d in &devices {
        let status = if d.online { "online" } else { "offline" };
        let name = if d.is_self {
            format!("{} (this device)", d.name)
        } else {
            d.name.clone()
        };
        println!("{:<24} {:<14} {:<8} {}", name, d.short_id(), status, d.path);
    }
    if devices.len() == 1 {
        println!("\nno other devices yet — add one with: ast device invite");
    }
    Ok(())
}

fn ping(device: &str) -> Result<()> {
    match send(&Request::DevicePing { device: device.into() })? {
        Response::DevicePong { device, device_id, path, millis } => {
            let short: String = device_id.chars().take(12).collect();
            println!("pong from {device} ({short}) via {path} in {millis:.1}ms");
            Ok(())
        }
        Response::Error { message } => bail!(message),
        other => bail!("unexpected reply from astd: {other:?}"),
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
        DeviceCommand::Invite { name, ttl, yes } => {
            pair(Request::DeviceInvite { name, ttl_secs: ttl }, yes)
        }
        DeviceCommand::Add { ticket, name, yes } => {
            pair(Request::DeviceAdd { ticket, name }, yes)
        }
        DeviceCommand::Wake { name } => wake(&name),
        // Routed before this, so that `--device` can aim it.
        DeviceCommand::Check => device_check(None),
    }
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
            Response::Ticket { ticket, expires_in_secs } => {
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
    if resolved.path.exists() {
        return Ok(resolved.name);
    }
    let (Some(url), Some(staging)) = (&resolved.url, &resolved.staging) else {
        return Ok(resolved.name); // local file, used in place
    };

    if !staging.exists() {
        if let Some(dir) = staging.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let part = staging.with_extension("qcow2.part");
        eprintln!("pulling {} ({})", resolved.name, url);
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
        // A base image that everything on this device clones from is worth
        // forcing down before it takes its final name: half a cloud image
        // under the name of a whole one is a boot failure with no clue in it.
        asterism_core::durable::publish_file(&part, staging)?;
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
        false => eprintln!("{image} is already built on this device ({})", pulled.digest),
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

fn print_images() -> Result<()> {
    println!("{:<14} {:<8} SOURCE ({})", "NAME", "PULLED", image::host_arch());
    for (alias, _, _) in image::CATALOG {
        let r = image::resolve(alias)?;
        // An image pulled by an older Asterism is still on this device even
        // though it has not been converted yet, and saying "-" would send
        // the user off to re-download something they already have.
        let pulled = if r.is_pulled() { "yes" } else { "-" };
        println!("{:<14} {:<8} {}", alias, pulled, r.url.as_deref().unwrap_or("-"));
    }
    // Container images are not a catalog — the catalog is Docker Hub — but
    // the ones this device has built are as real as any row above, and
    // nothing else would tell the user what is taking up the space.
    for reference in oci::built()? {
        println!("{:<14} {:<8} {}", short_image(&reference), "yes", reference);
    }
    println!("\nalso accepted: an https:// url, a path to a local qcow2 or raw image, or");
    println!("an OCI/Docker reference — `nginx`, `ghcr.io/owner/app:v1` — booted as a");
    println!("microVM from the image's own filesystem (ast create web --image nginx -p 8080:80)");
    Ok(())
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
    let Ok(Response::DevicePong { millis, .. }) =
        send(&Request::DevicePing { device: device.to_owned() })
    else {
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
        Response::SshEndpoint { host, port, identity } => (host, port, identity),
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
        .arg("-i").arg(&identity)
        .args(["-o", "StrictHostKeyChecking=no"])
        .args(["-o", "UserKnownHostsFile=/dev/null"])
        .args(["-o", "LogLevel=ERROR"])
        .args(["-o", "ConnectionAttempts=30"])
        .arg("-p").arg(port.to_string())
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
    let Some(addr) = addrs.next() else { return false };
    let Ok(stream) = std::net::TcpStream::connect_timeout(&addr, Duration::from_millis(500))
    else {
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
        Request::Snapshot { name: name.into(), tag: tag.clone() },
        device,
    ))?;
    println!("{name}  snapshot {tag}");
    Ok(())
}

fn restore_snapshot(name: &str, tag: &str, device: Option<&str>) -> Result<()> {
    send_ok(&aimed(
        Request::SnapshotRestore { name: name.into(), tag: tag.into() },
        device,
    ))?;
    println!("{name}  restored to {tag}");
    Ok(())
}

fn remove_snapshot(name: &str, tag: &str, device: Option<&str>) -> Result<()> {
    send_ok(&aimed(
        Request::SnapshotRemove { name: name.into(), tag: tag.into() },
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
        println!("{:<6} {:<26} {:<9} {}", snap.id, snap.tag, snap.size, snap.date);
    }
    Ok(())
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
        return match send(&Request::Logs { name: name.into(), lines })? {
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

/// Send a request, having first established that the daemon on the other
/// end speaks our version of the protocol.
fn send(request: &Request) -> Result<Response> {
    ensure_current_daemon()?;
    let response = send_once(request)?;
    // Belt and braces: a daemon that was replaced between the handshake and
    // now still cannot produce a baffling serde error for the user.
    if let Response::Error { message } = &response {
        if protocol::is_unknown_variant_error(message) {
            retire_stale_daemon()?;
            return send_once(request);
        }
    }
    Ok(response)
}

/// Connect to astd, spawning it first if the socket is not answering.
fn send_once(request: &Request) -> Result<Response> {
    let sock = paths::socket_path();
    let stream = match UnixStream::connect(&sock) {
        Ok(s) => s,
        Err(_) => {
            spawn_daemon()?;
            wait_for_socket(&sock)?
        }
    };

    let mut writer = stream.try_clone()?;
    let mut line = serde_json::to_string(request)?;
    line.push('\n');
    writer.write_all(line.as_bytes())?;

    let mut reply = String::new();
    BufReader::new(stream).read_line(&mut reply)?;
    if reply.trim().is_empty() {
        bail!("astd closed the connection without answering");
    }
    Ok(serde_json::from_str(&reply)?)
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
        ensure_current_daemon()?;
        let sock = paths::socket_path();
        let stream = match UnixStream::connect(&sock) {
            Ok(s) => s,
            Err(_) => {
                spawn_daemon()?;
                wait_for_socket(&sock)?
            }
        };
        let mut conn = Self { write: stream.try_clone()?, read: BufReader::new(stream) };
        conn.send(request)?;
        Ok(conn)
    }

    fn send(&mut self, request: &Request) -> Result<()> {
        let mut line = serde_json::to_string(request)?;
        line.push('\n');
        self.write.write_all(line.as_bytes())?;
        Ok(())
    }

    fn next(&mut self) -> Result<Response> {
        let mut line = String::new();
        self.read.read_line(&mut line)?;
        if line.trim().is_empty() {
            bail!("astd closed the connection without answering");
        }
        Ok(serde_json::from_str(&line)?)
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

// ---- version handshake -----------------------------------------------------
//
// The wire protocol is a pair of serde enums, so a daemon left running
// across an upgrade does not fail politely: it rejects the first request
// carrying a variant it has never heard of, and the user sees
// `bad request: unknown variant ...`. That is a true statement about
// nothing the user did. So `ast` asks the daemon its version before
// trusting it, and retires it if the answer is wrong.

/// Once per process: make sure the daemon we are about to talk to is ours.
fn ensure_current_daemon() -> Result<()> {
    use std::sync::OnceLock;
    static CHECKED: OnceLock<()> = OnceLock::new();
    if CHECKED.get().is_some() {
        return Ok(());
    }

    if let Some(found) = stale_version()? {
        eprintln!(
            "ast: astd {found} is running, but this is ast {VERSION} — restarting the daemon"
        );
        retire_stale_daemon()?;
        if let Some(still) = stale_version()? {
            bail!(
                "astd {still} is still running after a restart, but this is ast {VERSION}. \
                 Stop it by hand and try again."
            );
        }
    }

    let _ = CHECKED.set(());
    Ok(())
}

/// The version of the running daemon if it disagrees with ours, or `None`
/// if it matches. Spawns a daemon if none is running.
fn stale_version() -> Result<Option<String>> {
    match send_once(&Request::Ping)? {
        Response::Pong { version } if version == VERSION => Ok(None),
        Response::Pong { version } => Ok(Some(version)),
        // A daemon older than the Pong reply answers Ping with plain Ok.
        // The absence of a version is the mismatch.
        Response::Ok => Ok(Some(format!("older than {VERSION}"))),
        // Older still, or a build whose Ping means something else entirely.
        Response::Error { message } if protocol::is_unknown_variant_error(&message) => {
            Ok(Some(format!("older than {VERSION}")))
        }
        Response::Error { message } => bail!(message),
        other => bail!("unexpected reply to ping from astd: {other:?}"),
    }
}

/// Stop the daemon that is running and start ours in its place.
fn retire_stale_daemon() -> Result<()> {
    let pid = daemon_pid().context(
        "cannot tell which process is serving the astd socket, so it cannot be \
         restarted — stop astd by hand and try again",
    )?;

    signal(pid, "-TERM");
    if !wait_until_gone(pid, Duration::from_secs(10)) {
        // A daemon that will not take a hint. It holds the socket, so the
        // replacement cannot bind until it is gone.
        signal(pid, "-KILL");
        wait_until_gone(pid, Duration::from_secs(5));
    }
    // A hard-killed daemon leaves both of these behind; astd tolerates a
    // stale socket file, but the pid file would mislead the next restart.
    let _ = std::fs::remove_file(paths::daemon_pid_path());

    spawn_daemon()?;
    wait_for_socket(&paths::socket_path())?;
    Ok(())
}

/// Which process is serving the socket.
///
/// The pid file is the answer for any daemon new enough to write one. A
/// daemon from before it existed is still findable, because the socket it
/// holds open is a file with exactly one listener — and asking about that
/// specific path can never turn up somebody else's daemon, which matters
/// when several `ASTERISM_HOME`s are in play on one machine.
fn daemon_pid() -> Option<u32> {
    let pidfile = paths::daemon_pid_path();
    if let Some(pid) = std::fs::read_to_string(&pidfile)
        .ok()
        .and_then(|s| s.trim().parse::<u32>().ok())
    {
        if alive(pid) {
            return Some(pid);
        }
    }
    pid_holding(&paths::socket_path())
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

fn alive(pid: u32) -> bool {
    std::process::Command::new("kill")
        .args(["-0", &pid.to_string()])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn signal(pid: u32, sig: &str) {
    let _ = std::process::Command::new("kill")
        .arg(sig)
        .arg(pid.to_string())
        .output();
}

fn wait_until_gone(pid: u32, budget: Duration) -> bool {
    let deadline = std::time::Instant::now() + budget;
    loop {
        if !alive(pid) {
            return true;
        }
        if std::time::Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
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
        println!("moves:   {} (cpu/ram has been re-sourced that many times)", inst.move_epoch);
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
        let note = p.note.as_ref().map(|n| format!("  ({n})")).unwrap_or_default();
        println!("  {:<kind$}  {:<source$}  {}{note}", p.kind, p.source, p.detail);
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
    println!("{}  {}:{}  ->  {}", inst.name, v.host, v.path, volume_destination(v));
    if v.is_block() {
        // The guest sees a disk and nothing else — no mount, no share, no
        // hint that the bytes are elsewhere. Saying so here is the difference
        // between a working volume and a confused user, because an unmounted
        // blank disk looks exactly like nothing having happened.
        println!(
            "the guest gets a plain disk (/dev/vdb, /dev/vdc, ...); format and \
             mount it there once:"
        );
        println!("  ast ssh {} -- 'sudo mkfs.ext4 /dev/vdb && sudo mkdir -p /data && \
                  sudo mount /dev/vdb /data'", inst.name);
    } else if !v.is_local() {
        println!(
            "recorded only — a directory on another device cannot be shared into a \
             guest (9p has no network transport); use a block volume instead: \
             ast volume create"
        );
    }
    if inst.status == asterism_core::instance::Status::Running {
        println!("appears in the guest on the next boot: ast down {0} && ast up {0}", inst.name);
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
        format!("{} (a directory on {}, not reachable from here)", v.guest_path(), v.host)
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
