use std::path::PathBuf;

/// Root directory for Asterism state. Overridable with `ASTERISM_HOME`
/// (used by tests and by anyone running several daemons side by side).
pub fn home_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("ASTERISM_HOME") {
        return PathBuf::from(dir);
    }
    // Windows native shells do not set HOME; USERPROFILE is the documented
    // user-profile root and is what Credential Manager / SCM should agree on.
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .unwrap_or_else(|_| ".".into());
    PathBuf::from(home).join(".asterism")
}

/// This device's shard of the orbit registry: the instances whose cpu and ram
/// it supplies.
pub fn state_path() -> PathBuf {
    home_dir().join("state.json")
}

/// The other devices' shards, as this one last saw them.
///
/// The orbit registry is one namespace assembled from every device's shard, so
/// a device that is asleep would otherwise take its instances out of `ast ls`
/// entirely — which would read as "deleted" rather than "out of touch". This
/// file is what lets those rows still be listed, marked `unknown`, with the
/// device supplying their cpu named. It is a cache and nothing depends on it
/// being present or fresh.
pub fn shard_cache_path() -> PathBuf {
    home_dir().join("orbit-shards.json")
}

pub fn socket_path() -> PathBuf {
    short_socket(home_dir().join("astd.sock"))
}

/// Pid of the running daemon, written at startup and removed on a clean
/// shutdown. The CLI needs it to retire a daemon left over from an older
/// version — unlike the socket, a pid is something it can act on.
///
/// Deliberately *not* run through `short_socket`: it is a regular file, so
/// it has no length limit, and it must stay findable next to the home it
/// belongs to.
pub fn daemon_pid_path() -> PathBuf {
    home_dir().join("astd.pid")
}

/// This device's opt-in shell offer. Absence means disabled.
pub fn device_shell_policy_path() -> PathBuf {
    home_dir().join("shell.json")
}

/// Operational audit for device-shell decisions and session lifetimes.
pub fn device_shell_audit_path() -> PathBuf {
    home_dir().join("shell-audit.jsonl")
}

/// The file whose `flock(2)` is this home's daemon election.
///
/// Held by `astd` for as long as it runs, which is what makes "one daemon per
/// home" a fact the kernel enforces rather than a race between a socket probe
/// and an unlink. See [`crate::ipc::Door::open`].
pub fn daemon_lock_path() -> PathBuf {
    home_dir().join("astd.lock")
}

/// The file whose `flock(2)` serialises `ast`'s "nothing is listening, start
/// one".
///
/// A different file from [`daemon_lock_path`] on purpose: that one is held
/// for the daemon's whole life, so waiting on it would mean waiting for the
/// daemon to exit. This one is held for the length of one spawn, and it is
/// what turns ten commands typed at once into one `astd` rather than ten.
pub fn spawn_lock_path() -> PathBuf {
    home_dir().join("astd.spawn.lock")
}

/// QMP control socket for one instance's QEMU.
pub fn qmp_socket_path(name: &str) -> PathBuf {
    short_socket(instance_dir(name).join("qmp.sock"))
}

/// Control socket of the `astd-vz` helper holding one instance's guest.
///
/// The same shape as the QMP path and for the same reason: it is a socket,
/// so it is subject to the same length cap. Both are recorded on the
/// instance's `Handle` when it boots — this function is where a *new* one
/// gets its name, not how a running one is found again.
pub fn vz_socket_path(name: &str) -> PathBuf {
    short_socket(instance_dir(name).join("vz.sock"))
}

/// The key one instance's guest agent is authenticated with.
///
/// Beside the guest's own disk, because that is what it belongs to: it is
/// minted when the instance's seed is first built and read again on every
/// boot, by the daemon (to put in the seed) and by the helper (to prove
/// itself to the guest). Removed with the instance, like everything else in
/// here.
pub fn guest_agent_key_path(name: &str) -> PathBuf {
    instance_dir(name).join("agent.key")
}

// ---- block volumes ---------------------------------------------------------
//
// A volume is a part this device supplies to the pool, so it lives beside the
// instances rather than inside one: `volumes.json` is the bookkeeping and
// `volumes/<name>/` holds the bytes and whatever is currently serving them.

/// This device's block volumes: sizes, epochs and leases.
pub fn volumes_path() -> PathBuf {
    home_dir().join("volumes.json")
}

/// Consumer-side journal for block-volume attaches which have not yet
/// crossed their acknowledgement boundary.
///
/// This is deliberately separate from [`state_path`]. An attach writes its
/// intent before asking a provider for a lease, then clears it only after the
/// instance row is durable. If the registry commit has an ambiguous result,
/// the journal must remain independently readable so startup can decide
/// whether to finish the row or compensate the provider.
pub fn volume_attach_intents_path() -> PathBuf {
    home_dir().join("volume-attach-intents.json")
}

/// Consumer-side journal for block-volume releases which have not yet
/// crossed their acknowledgement boundary.
///
/// Kept apart from both the instance shard and attach intents so a provider
/// acknowledgement can be replayed after a crash without resurrecting the
/// row from either file's last-known-good copy.
pub fn volume_release_intents_path() -> PathBuf {
    home_dir().join("volume-release-intents.json")
}

pub fn volume_dir(name: &str) -> PathBuf {
    home_dir().join("volumes").join(name)
}

/// The raw image behind one volume. Sparse, and the only file in there that
/// is data rather than plumbing.
pub fn volume_image_path(name: &str) -> PathBuf {
    volume_dir(name).join("disk.raw")
}

/// Where `qemu-storage-daemon` serves one epoch's NBD export.
///
/// The epoch is in the filename on purpose: a new lease is a new socket, so
/// revoking the old one is an unlink and a stale consumer's reconnect finds
/// nothing rather than finding the new owner's disk.
pub fn volume_export_socket(name: &str, epoch: u64) -> PathBuf {
    short_socket(volume_dir(name).join(format!("nbd-e{epoch}.sock")))
}

/// Pidfile of that storage daemon, written by `--pidfile`.
pub fn volume_export_pid(name: &str, epoch: u64) -> PathBuf {
    volume_dir(name).join(format!("nbd-e{epoch}.pid"))
}

/// The local unix socket QEMU connects to for a volume attached to `instance`.
///
/// This end of the splice is always local — that is the local illusion doing
/// its work. QEMU sees a unix socket on the machine it is running on and
/// never learns that the daemon behind it is forwarding to another device.
pub fn volume_bridge_socket(instance: &str, host: &str, volume: &str) -> PathBuf {
    let safe = |s: &str| -> String {
        s.chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                    c
                } else {
                    '-'
                }
            })
            .collect()
    };
    short_socket(instance_dir(instance).join(format!("vol-{}-{}.sock", safe(host), safe(volume))))
}

/// Where a socket goes when its preferred path is too long to bind.
///
/// One directory, `0700`, one per uid, so that the fallback is as private as
/// the home it stands in for. The bare temp dir is not: `/tmp` is writable by
/// everyone on the machine, and a socket path derived from a hash is a path
/// anybody can compute — so the old fallback let a second user create
/// `astd.sock` *first* and be talked to by `ast`. `$TMPDIR` on macOS is
/// already per-user; on Linux it is `/tmp`, and this is what makes the two
/// the same shape.
///
/// Created by whoever binds — [`crate::ipc::Door::open`] for the daemon's
/// own socket, and `astd` at startup for the per-instance ones it hands to a
/// hypervisor. Nothing here creates it, because a path function that touches
/// the filesystem is a path function a refusal path cannot call.
pub fn runtime_dir() -> PathBuf {
    std::env::temp_dir().join(format!("asterism-{}", runtime_uid()))
}

fn runtime_uid() -> String {
    #[cfg(windows)]
    {
        std::env::var("USERNAME").unwrap_or_else(|_| "user".into())
    }
    #[cfg(not(windows))]
    {
        crate::ipc::own_uid().to_string()
    }
}

/// The longest preferred socket path that is bound where it belongs.
///
/// `sockaddr_un.sun_path` is 104 bytes on Apple platforms and 108 on Linux,
/// including the terminator. The margin under that is not decoration: the
/// daemon's own socket is the *short* one, and every other socket in this
/// file is a sibling of a file whose name a user chose.
const SOCKET_PATH_BUDGET: usize = 100;

/// Unix socket paths are capped at ~104 bytes (SUN_LEN); when the
/// preferred path is deep, fall back to a short hashed path in this user's
/// [`runtime_dir`]. The hash covers the full preferred path, so distinct
/// homes (and distinct instances) never collide.
fn short_socket(preferred: PathBuf) -> PathBuf {
    if preferred.as_os_str().len() <= SOCKET_PATH_BUDGET {
        return preferred;
    }
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    preferred.hash(&mut h);
    runtime_dir().join(format!("{:016x}.sock", h.finish()))
}

pub fn images_dir() -> PathBuf {
    home_dir().join("images")
}

pub fn instance_dir(name: &str) -> PathBuf {
    home_dir().join("instances").join(name)
}

/// Dedicated keypair used to reach guests; generated on first use.
pub fn ssh_key_path() -> PathBuf {
    home_dir().join("id_ed25519")
}

/// This device's long-lived mesh identity, generated on first daemon start.
///
/// Deliberately not `id_ed25519`: that key reaches *guests*, this one *is*
/// the device on the mesh. Confusing the two would let a guest key be
/// mistaken for an orbit membership.
pub fn device_key_path() -> PathBuf {
    home_dir().join("id_device")
}

/// The orbit store: which other devices this one trusts, and what they are
/// called. The mesh equivalent of `state.json`.
pub fn orbit_path() -> PathBuf {
    home_dir().join("orbit.json")
}

/// Another device's guest key, cached here so `ast ssh` can open a guest that
/// device seeded.
///
/// A guest only trusts the key of the device that built its cloud-init seed,
/// so reaching it from elsewhere in the orbit means presenting that device's
/// key. This is where the copy lives, at 0600, one file per device.
///
/// **Why this is not an escalation.** An orbit is a set of mutually trusted
/// device keys, and that trust already includes running any command on any of
/// each other's instances — that is what a forwarded request is. A key that
/// opens those same guests grants nothing that membership did not already
/// grant. It travels only over a QUIC stream that is mutually authenticated
/// against the orbit store, and it is refused to anyone else by the same check
/// that refuses them everything else.
pub fn guest_key_cache(device: &str) -> PathBuf {
    // The name comes off the wire, so it becomes a filename and not a path:
    // anything that is not a letter, digit or dash is flattened.
    let safe: String = device
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' {
                c
            } else {
                '-'
            }
        })
        .collect();
    home_dir()
        .join("guest-keys")
        .join(format!("{safe}.id_ed25519"))
}
