//! Volumes, from both ends: attaching one to an instance, and keeping the
//! ones this device puts in the pool.
//!
//! One module, two clap groups, and the split between them is the honest one.
//! `ast attach` and `ast detach` are instance commands — they resolve a name
//! across the orbit like every other — while `ast volume create|ls|rm` is
//! about *this* device, because volume names are per device and the bytes are
//! somewhere in particular. They are here together anyway: they are one
//! subject, and merge conflicts follow subjects rather than clap's help
//! order. The two groups exist so that flattening them back into the command
//! tree leaves `ast --help` reading exactly as it did.
//!
//! The one decision this module encodes is that `--volume` is read rather
//! than flagged: `--volume desktop:tank` is a block volume and `--volume
//! /tank/media` is a directory share, told apart by how the user wrote it
//! ([`block_ref`]). A `--block` flag would have made the user say twice what
//! they already said once.

use anyhow::{bail, Context, Result};
use clap::Subcommand;

use asterism_core::instance::Instance;
use asterism_core::protocol::{Request, Response};

use crate::client;

/// The two commands that change which volumes an instance is assembled from.
#[derive(Subcommand)]
pub(crate) enum Attachment {
    /// Attach a volume to an instance.
    ///
    /// Two kinds of volume, and they reach the guest differently.
    ///
    /// A DIRECTORY (`--volume /tank/media`) is shared with the guest and
    /// mounted at a path. Three things have to be true, and each of them is
    /// refused in words rather than discovered later: the directory is on
    /// the same device as the instance's cpu and ram (directory sharing has
    /// no network transport), the backend offers a share transport (9p on
    /// qemu or virtiofs on vz), and the guest kernel supports that transport.
    /// Cloud images receive a mount unit in their seed; OCI images receive
    /// the same mount in Asterism's generated pid 1.
    ///
    /// A BLOCK VOLUME (`--volume desktop:tank`, made with `ast volume
    /// create`) arrives as a plain disk: /dev/vdb, /dev/vdc and so on. The
    /// guest partitions, formats and mounts it itself, and never learns which
    /// device the bytes are on — put a filesystem on it once with
    /// `mkfs.ext4 /dev/vdb`, then mount it. It can come from any device in
    /// the orbit. One instance may hold it at a time; attaching takes that
    /// lease.
    Attach {
        /// The instance to attach it to.
        name: String,
        /// A directory path, or `<device>:<volume>` for a block volume.
        #[arg(long)]
        volume: String,
        /// Device that provides the volume (default: this device).
        #[arg(long)]
        host: Option<String>,
        /// Where a directory volume mounts in the guest (default:
        /// /mnt/ast/<name>). Meaningless for a block volume: the guest
        /// decides where its own disks go.
        #[arg(long, value_name = "PATH")]
        at: Option<String>,
    },
    /// Take a volume off a stopped instance.
    ///
    /// A block volume's lease goes back to the device that holds the bytes,
    /// so something else may take it. Nothing on the volume is deleted.
    /// Refused while the guest is running: neither backend can pull a disk
    /// out from under a live guest, so that would be a yanked cable.
    Detach {
        /// The instance to take it off.
        name: String,
        /// The directory path, or `<device>:<volume>` for a block volume.
        #[arg(long)]
        volume: String,
        /// The device it came from, if the name alone is ambiguous.
        #[arg(long)]
        host: Option<String>,
    },
}

/// The block storage this device contributes to the pool.
#[derive(Subcommand)]
pub(crate) enum Commands {
    /// Create, list and delete this device's block volumes.
    #[command(subcommand)]
    Volume(VolumeCommand),
}

/// `ast volume ...` — the block storage one device puts in the pool.
///
/// Volumes belong to the device that holds their bytes, and their names are
/// per-device rather than orbit-global: `desktop:tank` and `nas:tank` are two
/// volumes. So these commands are about *this* device unless `--device` says
/// otherwise, which is the opposite of how instance commands work and is the
/// honest way round — the bytes are somewhere in particular.
#[derive(Subcommand)]
pub(crate) enum VolumeCommand {
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

/// `ast attach` and `ast detach`.
///
/// One flag, two parts. `--volume desktop:tank` names a block volume on a
/// device; anything that looks like a path is a directory share. The two are
/// told apart here rather than by a `--block` flag, because the user already
/// said which they meant by how they wrote it — and because a directory on
/// another device has always had to be an absolute path, so there is nothing
/// ambiguous left over.
pub(crate) fn attachment(cmd: Attachment, device: Option<&str>) -> Result<()> {
    let request = match cmd {
        Attachment::Attach { name, volume, host, at } => {
            match block_ref(&volume, host.as_deref()) {
                Some((provider, volume)) => {
                    if at.is_some() {
                        bail!(
                            "--at is for directory volumes; a block volume arrives as a disk \
                             and the guest mounts it wherever it likes"
                        );
                    }
                    warn_if_far(&provider);
                    Request::AttachBlock { name, volume, device: provider }
                }
                None => Request::AttachVolume {
                    name,
                    path: volume_path(&volume, host.as_deref())?,
                    host,
                    mount_point: at,
                },
            }
        }
        Attachment::Detach { name, volume, host } => {
            match block_ref(&volume, host.as_deref()) {
                Some((provider, volume)) => {
                    Request::Detach { name, volume, host: Some(provider) }
                }
                None => Request::Detach {
                    name,
                    volume: volume_path(&volume, host.as_deref())?,
                    host,
                },
            }
        }
    };

    match client::ask(&request, device)? {
        Response::Ok => Ok(()),
        Response::Instance { instance } => {
            match &request {
                Request::Detach { volume, .. } => {
                    println!("{}  {volume} detached", instance.name)
                }
                _ => print_attached(&instance),
            }
            Ok(())
        }
        _ => Err(client::unexpected(&request)),
    }
}

/// `ast volume create|ls|rm`.
///
/// A volume is a device's part of the pool, so these are about the daemon in
/// front of you unless `--device` aims them elsewhere.
pub(crate) fn run(cmd: Commands, device: Option<&str>) -> Result<()> {
    let Commands::Volume(cmd) = cmd;
    let request = match cmd {
        VolumeCommand::Create { name, size } => Request::VolumeCreate {
            name,
            size_bytes: asterism_core::volume::parse_size(&size)?,
        },
        VolumeCommand::Ls => Request::VolumeList,
        VolumeCommand::Rm { name } => Request::VolumeRemove { name },
    };

    match client::ask(&request, device)? {
        Response::Ok => Ok(()),
        Response::Volumes { volumes } => {
            match &request {
                Request::VolumeCreate { .. } => print_volume_made(&volumes),
                Request::VolumeRemove { name } => println!("{name}  removed"),
                _ => print_volumes(&volumes),
            }
            Ok(())
        }
        _ => Err(client::unexpected(&request)),
    }
}

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
        client::send(&Request::DevicePing { device: device.to_owned() })
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
            crate::format::age(v.created_at),
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
             guest (directory shares have no network transport); use a block volume instead: \
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The whole reason there is no `--block` flag: the user says which kind
    /// of volume they mean by how they write it, and getting this wrong in
    /// either direction records a directory share named `tank` or refuses a
    /// perfectly good path.
    #[test]
    fn a_volume_reference_says_which_kind_it_is_without_a_flag() {
        // `<device>:<volume>` is a block volume, and needs no --host.
        assert_eq!(
            block_ref("desktop:tank", None),
            Some(("desktop".to_owned(), "tank".to_owned()))
        );
        // A bare name with --host is one too: a directory on another device
        // has always had to be absolute, so this cannot have meant one.
        assert_eq!(
            block_ref("tank", Some("desktop")),
            Some(("desktop".to_owned(), "tank".to_owned()))
        );
        // Anything that looks like a path is a directory share, --host or not.
        assert_eq!(block_ref("/tank/media", Some("desktop")), None);
        assert_eq!(block_ref("./media", Some("desktop")), None);
        assert_eq!(block_ref("~/media", Some("desktop")), None);
        // And a bare name with nothing to say where the bytes are is a
        // relative directory, which is resolved against the user's cwd.
        assert_eq!(block_ref("tank", None), None);
    }

    /// A directory on another device cannot be resolved from here, so it has
    /// to arrive absolute — and saying so now is better than a daemon
    /// canonicalising a path against its own working directory.
    #[test]
    fn a_directory_on_another_device_has_to_be_named_absolutely() {
        let refusal = volume_path("media", Some("desktop")).unwrap_err().to_string();
        assert!(refusal.contains("absolute path"), "{refusal}");
        assert_eq!(volume_path("/tank/media", Some("desktop")).unwrap(), "/tank/media");
        // On this device an absolute path is taken as written.
        assert_eq!(volume_path("/tank/media", None).unwrap(), "/tank/media");
    }
}
