//! Block volumes: the bytes a device puts in the pool, and the single-writer
//! lease that decides who may write them.
//!
//! A block volume is a raw image file on the device that created it, living in
//! `$ASTERISM_HOME/volumes/<name>/disk.raw`. It is attachable to any instance
//! in the orbit; when that instance's cpu and ram come from another device the
//! bytes travel over the mesh as NBD (`docs/ROADMAP.md` Phase 3), and the
//! guest still sees nothing but `/dev/vdb`.
//!
//! # The lease
//!
//! A filesystem is not a shared thing. Two guests writing one ext4 destroys
//! it, and they would do it quietly, so the rule is enforced on the provider
//! rather than trusted to the consumer: a volume carries at most one
//! [`Lease`], naming the instance that holds it and the device supplying that
//! instance's cpu, stamped with a monotonic [`BlockVolume::epoch`].
//!
//! Every grant — an attach, and every boot afterwards — bumps the epoch and
//! renames the NBD export accordingly (`tank-e7`). The old export is stopped
//! and its socket unlinked, so a consumer that was partitioned and comes back
//! holding epoch 6 finds nothing to talk to and fails loudly, instead of
//! writing into a filesystem another guest now owns. That is the whole of
//! "epoch fencing": the epoch is not a number we compare politely, it is the
//! name of the door.
//!
//! The epoch never goes backwards, including across a release — releasing
//! clears the holder, not the counter.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::durable::{self, Loaded};
use crate::instance::now_unix;
use crate::proc::{Evidence as ProcEvidence, ProcId};

/// The program that serves a block volume's NBD export. Named here because
/// it is what a lease's recorded process must turn out to be running before
/// this daemon will believe the lease.
pub const EXPORT_BIN: &str = "qemu-storage-daemon";

/// Who holds a volume's single writer slot, and at what epoch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Lease {
    /// The instance that may write. Instance names are orbit-global, so this
    /// is unambiguous without naming a device.
    pub holder: String,
    /// The device supplying that instance's cpu and ram — where the bytes are
    /// going. Recorded so a refusal can say where, not only who.
    pub holder_device: String,
    /// The epoch this grant was made at. Equal to [`BlockVolume::epoch`]
    /// while the lease is current; a consumer holding anything lower has been
    /// fenced out.
    pub epoch: u64,
    /// Unix seconds.
    pub granted_at: u64,
    /// NBD export name this grant is being served under: `<volume>-e<epoch>`.
    pub export: String,
    /// The `qemu-storage-daemon` serving it, when one is running. Kept for
    /// what reads it and cannot act on it; nothing signals it — see
    /// [`Lease::proc`].
    #[serde(default)]
    pub pid: Option<u32>,
    /// Proof of *which* process that pid is.
    ///
    /// Tracked the way a guest's helper is tracked, and for the same reason:
    /// it is a process this daemon started, is responsible for stopping, and
    /// will meet again only after writing it down — which means only after
    /// its pid has stopped being evidence of anything. Absent on leases
    /// written before identities existed; the daemon adopts those at startup
    /// where it safely can, and treats the rest as an export that is simply
    /// not running (which is recoverable: the export is restarted at the
    /// same epoch).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proc: Option<ProcId>,
}

/// One block volume on this device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockVolume {
    pub name: String,
    /// Virtual size. The file is sparse: it claims this and occupies what has
    /// been written, exactly as an instance's own disk does.
    pub size_bytes: u64,
    /// Unix seconds.
    pub created_at: u64,
    /// Highest epoch ever granted on this volume. Monotonic, and persisted,
    /// so it survives a daemon restart — an epoch that reset would un-fence
    /// every consumer that had been shut out.
    #[serde(default)]
    pub epoch: u64,
    #[serde(default)]
    pub lease: Option<Lease>,
}

impl BlockVolume {
    /// The export name a given epoch is served under.
    pub fn export_name(&self, epoch: u64) -> String {
        format!("{}-e{}", self.name, epoch)
    }

    /// What `ast volume ls` says about who has it.
    pub fn holder_summary(&self) -> String {
        match &self.lease {
            Some(l) => format!("{} on {} (epoch {})", l.holder, l.holder_device, l.epoch),
            None => "-".to_owned(),
        }
    }
}

/// The volume book's on-disk format version.
///
/// A file written before the field existed deserialises to 0 and is written
/// back as 1; nothing inside a row changed, so that is the whole migration.
pub const VOLUME_VERSION: u32 = 1;

/// This device's block volumes, as one file next to the instance shard.
///
/// Separate from [`crate::registry::Shard`] on purpose: a volume is a part
/// this device supplies to the pool, not an instance it runs, and the two have
/// different lifetimes — a volume outlives every instance that ever mounted
/// it.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Store {
    #[serde(default)]
    version: u32,
    #[serde(default)]
    volumes: BTreeMap<String, BlockVolume>,
    #[serde(skip)]
    path: PathBuf,
}

impl Store {
    pub fn load(path: &Path) -> Result<Self> {
        let mut store = match durable::load_json_versioned::<Store>(
            path,
            "this device's volumes",
            VOLUME_VERSION,
        )? {
            Some(Loaded { value, repaired }) => {
                if let Some(why) = repaired {
                    // A volume recovered from the backup may be one epoch
                    // behind, which is the one thing a holder needs to know:
                    // its lease will be refused and it will take a new one.
                    eprintln!("astd: {why}");
                }
                value
            }
            None => Store::default(),
        };
        store.version = VOLUME_VERSION;
        store.path = path.to_owned();
        Ok(store)
    }

    pub fn save(&self) -> Result<()> {
        durable::commit_json(&self.path, self)
            .with_context(|| format!("committing {}", self.path.display()))
    }

    pub fn list(&self) -> Vec<BlockVolume> {
        self.volumes.values().cloned().collect()
    }

    pub fn get(&self, name: &str) -> Result<&BlockVolume> {
        self.volumes.get(name).with_context(|| no_such(name))
    }

    /// Record a new volume. The bytes are made by the caller; this is the
    /// bookkeeping half, and it refuses a name that is already spoken for on
    /// this device.
    pub fn create(&mut self, name: &str, size_bytes: u64) -> Result<BlockVolume> {
        check_name(name)?;
        if self.volumes.contains_key(name) {
            bail!("this device already has a volume called {name:?}");
        }
        if size_bytes == 0 {
            bail!("a volume needs a size — try --size 10G");
        }
        let vol = BlockVolume {
            name: name.to_owned(),
            size_bytes,
            created_at: now_unix(),
            epoch: 0,
            lease: None,
        };
        self.volumes.insert(name.to_owned(), vol.clone());
        Ok(vol)
    }

    /// Forget a volume. Refuses one that is leased: deleting bytes out from
    /// under a running guest is not a thing a user can have meant.
    pub fn remove(&mut self, name: &str) -> Result<BlockVolume> {
        let vol = self.volumes.get(name).with_context(|| no_such(name))?;
        if let Some(lease) = &vol.lease {
            bail!("{}", held_by(name, lease));
        }
        Ok(self.volumes.remove(name).expect("just looked it up"))
    }

    /// Take or renew the single-writer lease, at a new epoch.
    ///
    /// The same holder asking again is a renewal and still bumps the epoch:
    /// that is what fences the *previous* connection of that same instance,
    /// which is the case that actually happens (a guest that was killed
    /// leaves a QEMU that may not have noticed yet).
    pub fn lease(&mut self, name: &str, holder: &str, holder_device: &str) -> Result<BlockVolume> {
        let vol = self.volumes.get_mut(name).with_context(|| no_such(name))?;
        if let Some(current) = &vol.lease {
            if current.holder != holder {
                bail!("{}", held_by(name, current));
            }
        }
        vol.epoch += 1;
        let export = format!("{}-e{}", vol.name, vol.epoch);
        vol.lease = Some(Lease {
            holder: holder.to_owned(),
            holder_device: holder_device.to_owned(),
            epoch: vol.epoch,
            granted_at: now_unix(),
            export,
            pid: None,
            proc: None,
        });
        Ok(vol.clone())
    }

    /// Pick up a lease this holder already has, without moving the epoch.
    ///
    /// A renewal ([`Store::lease`]) bumps the epoch because it is meant to
    /// fence the holder's *previous* connection. That is right when a guest
    /// is being booted and wrong when one never stopped: a consumer's astd
    /// that restarts under a live guest has a QEMU with one export name on
    /// its command line, and bumping would rename the door on a guest that
    /// is doing nothing but waiting to reconnect.
    ///
    /// So this is the reconnect: same holder and same epoch, or a refusal in
    /// the same words a stale consumer gets. It grants nothing — it confirms
    /// what is already granted, which is why it can afford not to fence.
    pub fn reconnect(&self, name: &str, holder: &str, epoch: u64) -> Result<BlockVolume> {
        let vol = self.volumes.get(name).with_context(|| no_such(name))?;
        let Some(lease) = &vol.lease else {
            bail!(
                "volume {name:?} is not leased to anything — instance {holder:?} \
                 had it at epoch {epoch} and no longer does"
            );
        };
        if lease.holder != holder {
            bail!("{}", held_by(name, lease));
        }
        if lease.epoch != epoch {
            bail!("{}", fenced(name, holder, epoch, lease.epoch));
        }
        Ok(vol.clone())
    }

    /// Record which process is serving the current lease, and what proves it
    /// is that process.
    pub fn set_export_proc(&mut self, name: &str, proc: Option<ProcId>) -> Result<()> {
        let vol = self.volumes.get_mut(name).with_context(|| no_such(name))?;
        if let Some(lease) = vol.lease.as_mut() {
            lease.pid = proc.as_ref().map(|p| p.pid);
            lease.proc = proc;
        }
        Ok(())
    }

    /// Give a pre-identity lease an identity, once, if the process it names
    /// can be proven to be its export.
    ///
    /// The volume half of the startup migration
    /// (`asterism_core::proc::ProcId::adopt`). Failing is cheap here in a way
    /// it is not for a guest: an export that cannot be proven is treated as
    /// not running and started again at the *same* epoch, which is the same
    /// recovery a provider that restarted already gets.
    pub fn adopt_export(&mut self, name: &str) -> std::result::Result<Option<ProcId>, String> {
        let vol = self.volumes.get_mut(name).ok_or_else(|| no_such(name))?;
        let Some(lease) = vol.lease.as_mut() else {
            return Ok(None);
        };
        if lease.proc.is_some() {
            return Ok(None);
        }
        let Some(pid) = lease.pid else {
            return Ok(None);
        };
        // Both paths carry the volume's name *and* the lease's epoch, and
        // both are on the storage daemon's own command line — `--pidfile`
        // and the unix address it serves the export on. A storage daemon
        // started for anything else cannot be holding either, which is what
        // makes this adoption rest on something a coincidence cannot supply.
        let pidfile = crate::paths::volume_export_pid(name, lease.epoch);
        let socket = crate::paths::volume_export_socket(name, lease.epoch);
        let proc = ProcId::adopt(
            pid,
            lease.granted_at,
            &ProcEvidence {
                exec: &[EXPORT_BIN],
                names: &[&pidfile, &socket],
            },
        )?;
        lease.proc = Some(proc.clone());
        Ok(Some(proc))
    }

    /// Give the lease back. Only the holder may; anyone else is told who has
    /// it. Releasing a volume nobody holds is a no-op, so a detach that is
    /// retried after a crash still succeeds.
    pub fn release(&mut self, name: &str, holder: &str) -> Result<Option<Lease>> {
        let vol = self.volumes.get_mut(name).with_context(|| no_such(name))?;
        match &vol.lease {
            None => Ok(None),
            Some(current) if current.holder == holder => Ok(vol.lease.take()),
            Some(current) => bail!("{}", held_by(name, current)),
        }
    }

    /// Revoke every lease whose writer lives on `device`.
    ///
    /// Device membership is the authority under a remote volume stream. Once
    /// that membership is removed, leaving its lease behind would let a later
    /// device with the same human name resume an epoch it never received.
    /// Clearing the holder while preserving the volume's monotonic epoch is
    /// the durable half of live device revocation; the daemon stops each
    /// returned export after committing this state.
    pub fn revoke_device(&mut self, device: &str) -> Vec<(String, Lease)> {
        let mut revoked = Vec::new();
        for (name, volume) in &mut self.volumes {
            if volume
                .lease
                .as_ref()
                .is_some_and(|lease| lease.holder_device == device)
            {
                revoked.push((
                    name.clone(),
                    volume.lease.take().expect("lease just matched"),
                ));
            }
        }
        revoked
    }

    /// Revokes a device's leases and confirms the result at a durable commit
    /// boundary before returning it to a membership-removal transaction.
    ///
    /// The save is intentional even when no matching lease remains. That can
    /// be the retry of a commit whose rename became visible but whose
    /// directory flush failed; skipping the write would let the caller commit
    /// orbit removal without ever confirming the lease state was durable.
    pub fn revoke_device_durable(&mut self, device: &str) -> Result<Vec<(String, Lease)>> {
        let revoked = self.revoke_device(device);
        if let Err(first) = self.save() {
            *self = Self::load(&self.path).with_context(|| {
                format!(
                    "reloading the volume store after leases for {device:?} could not be \
                     revoked: {first:#}"
                )
            })?;
            let revocation_is_visible = self.volumes.values().all(|volume| {
                volume
                    .lease
                    .as_ref()
                    .is_none_or(|lease| lease.holder_device != device)
            });
            if !revocation_is_visible {
                return Err(first)
                    .with_context(|| format!("revoking volume leases held by device {device:?}"));
            }
        }

        // Recovery from an unreadable live document uses `.bak`. The first
        // commit necessarily leaves the old lease in that backup, so publish
        // the revoked value once more before membership is allowed to vanish.
        self.save().with_context(|| {
            format!(
                "confirming leases for {device:?} are revoked in both the live and recovery \
                 volume stores"
            )
        })?;
        Ok(revoked)
    }
}

/// What this device says when it is asked about a volume it does not have.
///
/// Names the device rather than the orbit, unlike an instance miss: volumes
/// are not a flat orbit-wide namespace. Two devices may each have a `tank`,
/// and `desktop:tank` is how you say which.
fn no_such(name: &str) -> String {
    format!("no volume named {name:?} on this device — see: ast volume ls")
}

/// The refusal a second writer gets. It names the holder, because "it is
/// busy" is not something anybody can act on.
pub fn held_by(name: &str, lease: &Lease) -> String {
    format!(
        "volume {name:?} is held by instance {:?} (cpu/ram on {}) at epoch {} — \
         detach it there first: ast detach {} --volume {name}",
        lease.holder, lease.holder_device, lease.epoch, lease.holder
    )
}

/// What a consumer holding an epoch that has moved on is told.
///
/// It says what it is holding and what is current, and stops there: the way
/// back is to ask for a lease, which is the code path that decides whether
/// this holder may have one.
pub fn fenced(name: &str, holder: &str, held: u64, current: u64) -> String {
    format!(
        "instance {holder:?} is holding a stale lease on volume {name:?} \
         (epoch {held}, current is {current}) — it has been fenced out"
    )
}

/// Volume names go into filenames, NBD export names and CLI arguments, so
/// they are kept to the same shape instance names are.
pub fn check_name(name: &str) -> Result<()> {
    if name.is_empty() || name.len() > 40 {
        bail!("a volume name must be 1-40 characters (got {name:?})");
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        bail!("a volume name may hold letters, digits, - and _ (got {name:?})");
    }
    if name.starts_with('-') {
        bail!("a volume name cannot start with - (got {name:?})");
    }
    Ok(())
}

/// `<device>:<volume>`, the way a remote volume is written on the command
/// line. `None` when this is not that shape — an absolute path, most often,
/// which is a directory volume and goes down the 9p road instead.
pub fn parse_ref(value: &str) -> Option<(String, String)> {
    if value.starts_with('/') || value.starts_with('.') || value.starts_with('~') {
        return None;
    }
    let (device, volume) = value.split_once(':')?;
    if device.is_empty() || volume.is_empty() {
        return None;
    }
    Some((device.to_owned(), volume.to_owned()))
}

/// A size as a human writes it: `10G`, `512M`, `2T`, or plain bytes.
pub fn parse_size(value: &str) -> Result<u64> {
    let v = value.trim();
    let (digits, unit) = match v.chars().last() {
        Some(c) if c.is_ascii_alphabetic() => (&v[..v.len() - 1], c.to_ascii_uppercase()),
        _ => (v, 'B'),
    };
    let n: u64 = digits
        .trim()
        .parse()
        .with_context(|| format!("bad size {value:?} — try 10G"))?;
    let scale: u64 = match unit {
        'B' => 1,
        'K' => 1 << 10,
        'M' => 1 << 20,
        'G' => 1 << 30,
        'T' => 1 << 40,
        other => bail!("unknown size unit {other:?} in {value:?} — use K, M, G or T"),
    };
    n.checked_mul(scale)
        .with_context(|| format!("{value:?} is larger than this machine can address"))
}

/// A size as a human reads it.
pub fn format_size(bytes: u64) -> String {
    const UNITS: [(&str, u64); 4] = [
        ("T", 1 << 40),
        ("G", 1 << 30),
        ("M", 1 << 20),
        ("K", 1 << 10),
    ];
    for (suffix, scale) in UNITS {
        if bytes >= scale {
            let whole = bytes as f64 / scale as f64;
            if (whole - whole.round()).abs() < 0.05 {
                return format!("{}{suffix}", whole.round() as u64);
            }
            return format!("{whole:.1}{suffix}");
        }
    }
    format!("{bytes}B")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> Store {
        Store {
            path: std::env::temp_dir().join(format!("ast-vol-test-{}.json", std::process::id())),
            ..Default::default()
        }
    }

    #[test]
    fn sizes_round_trip_the_way_people_write_them() {
        assert_eq!(parse_size("10G").unwrap(), 10 << 30);
        assert_eq!(parse_size("512M").unwrap(), 512 << 20);
        assert_eq!(parse_size("2T").unwrap(), 2 << 40);
        assert_eq!(parse_size("4096").unwrap(), 4096);
        assert!(parse_size("").is_err());
        assert!(parse_size("10X").is_err());
        assert_eq!(format_size(10 << 30), "10G");
        assert_eq!(format_size(1536 << 20), "1.5G");
        assert_eq!(format_size(900), "900B");
    }

    #[test]
    fn a_device_qualified_reference_is_told_from_a_path() {
        assert_eq!(
            parse_ref("desktop:tank"),
            Some(("desktop".into(), "tank".into()))
        );
        assert_eq!(
            parse_ref("/tank/media"),
            None,
            "an absolute path is a directory"
        );
        assert_eq!(parse_ref("./here"), None);
        assert_eq!(parse_ref("~/here"), None);
        assert_eq!(parse_ref("tank"), None, "no device, no reference");
        assert_eq!(parse_ref("desktop:"), None);
    }

    /// The whole safety property, in one test: one writer, and the epoch only
    /// ever goes up.
    #[test]
    fn one_writer_at_a_time_and_the_epoch_only_climbs() {
        let mut s = store();
        s.create("tank", 10 << 30).unwrap();
        assert!(s.create("tank", 1 << 30).is_err(), "one name, one volume");

        let first = s.lease("tank", "dev", "laptop").unwrap();
        assert_eq!(first.epoch, 1);
        assert_eq!(first.lease.as_ref().unwrap().export, "tank-e1");

        // A second instance is refused, and told who has it and where.
        let err = s.lease("tank", "other", "desktop").unwrap_err().to_string();
        assert!(err.contains("held by instance \"dev\""), "{err}");
        assert!(err.contains("laptop"), "{err}");
        assert!(err.contains("ast detach dev --volume tank"), "{err}");

        // The holder renewing bumps the epoch, which is what fences its own
        // previous connection.
        let renewed = s.lease("tank", "dev", "laptop").unwrap();
        assert_eq!(renewed.epoch, 2);
        assert_eq!(renewed.lease.as_ref().unwrap().export, "tank-e2");

        // Only the holder may release.
        assert!(s.release("tank", "other").is_err());
        let released = s.release("tank", "dev").unwrap().unwrap();
        assert_eq!(released.epoch, 2);
        assert!(
            s.release("tank", "dev").unwrap().is_none(),
            "releasing twice is fine"
        );

        // ...and the counter did not come back down with it.
        let elsewhere = s.lease("tank", "other", "desktop").unwrap();
        assert_eq!(
            elsewhere.epoch, 3,
            "a released volume does not rewind the epoch"
        );
        assert_eq!(elsewhere.export_name(elsewhere.epoch), "tank-e3");
    }

    /// The other half of the epoch rule: a consumer that never lost the
    /// lease, only the daemon holding the bridge, gets to pick it back up
    /// exactly where it was. Bumping would rename the export out from under
    /// a guest whose QEMU already has the old name on its command line.
    #[test]
    fn the_holder_can_pick_up_the_lease_it_still_has_without_moving_the_epoch() {
        let mut s = store();
        s.create("tank", 1 << 30).unwrap();
        let granted = s.lease("tank", "dev", "laptop").unwrap();
        let epoch = granted.epoch;

        let back = s.reconnect("tank", "dev", epoch).unwrap();
        assert_eq!(back.epoch, epoch, "a reconnect is not a renewal");
        assert_eq!(
            back.lease.as_ref().unwrap().export,
            granted.lease.unwrap().export
        );
        // Twice, and it is still the same door: nothing about it is a grant.
        assert_eq!(s.reconnect("tank", "dev", epoch).unwrap().epoch, epoch);
        assert_eq!(s.get("tank").unwrap().epoch, epoch);

        // Somebody else's, and it says who has it.
        let err = s.reconnect("tank", "other", epoch).unwrap_err().to_string();
        assert!(err.contains("held by instance \"dev\""), "{err}");

        // The holder's own stale epoch is refused too — that is a consumer
        // that was fenced while it was away, and it must not be handed the
        // current door just because the name on the lease still matches.
        let err = s
            .reconnect("tank", "dev", epoch - 1)
            .unwrap_err()
            .to_string();
        assert!(err.contains("fenced out"), "{err}");
        assert!(err.contains(&format!("current is {epoch}")), "{err}");

        // And once it has been given back there is nothing to reconnect to.
        s.release("tank", "dev").unwrap();
        let err = s.reconnect("tank", "dev", epoch).unwrap_err().to_string();
        assert!(err.contains("no longer does"), "{err}");
    }

    #[test]
    fn a_leased_volume_cannot_be_deleted() {
        let mut s = store();
        s.create("tank", 1 << 30).unwrap();
        s.lease("tank", "dev", "laptop").unwrap();
        let err = s.remove("tank").unwrap_err().to_string();
        assert!(err.contains("held by instance \"dev\""), "{err}");
        s.release("tank", "dev").unwrap();
        assert_eq!(s.remove("tank").unwrap().name, "tank");
        assert!(s.get("tank").is_err());
    }

    #[test]
    fn removing_a_device_revokes_all_of_its_leases_without_rewinding_epochs() {
        let mut s = store();
        s.create("tank", 1 << 30).unwrap();
        s.create("cache", 1 << 30).unwrap();
        s.create("other", 1 << 30).unwrap();
        s.lease("tank", "dev", "laptop").unwrap();
        s.lease("cache", "build", "laptop").unwrap();
        s.lease("other", "db", "desktop").unwrap();

        let mut revoked = s.revoke_device("laptop");
        revoked.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(revoked.len(), 2);
        assert_eq!(revoked[0].0, "cache");
        assert_eq!(revoked[1].0, "tank");
        assert!(s.get("tank").unwrap().lease.is_none());
        assert!(s.get("cache").unwrap().lease.is_none());
        assert_eq!(
            s.get("tank").unwrap().epoch,
            1,
            "revocation never rewinds a fence"
        );
        assert_eq!(
            s.get("other")
                .unwrap()
                .lease
                .as_ref()
                .unwrap()
                .holder_device,
            "desktop",
            "another device's lease is untouched"
        );

        let next = s.lease("tank", "new", "desktop").unwrap();
        assert_eq!(next.epoch, 2, "the next writer gets a new door");
    }

    /// A save error before publish must restore the in-memory lease as well
    /// as leaving it on disk. Otherwise the retry sees "nothing to revoke",
    /// skips the commit, and permits orbit removal over the still-durable
    /// writer.
    #[test]
    fn failed_durable_revocation_reloads_the_lease_and_retries_cleanly() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("revoke-rollback-volumes.json");
        let mut s = Store::load(&path).unwrap();
        s.create("tank", 1 << 30).unwrap();
        s.lease("tank", "dev", "laptop").unwrap();
        s.save().unwrap();

        let armed = durable::faults::arm(
            "revoke-rollback",
            durable::faults::Point::Rename,
            path.display().to_string(),
            std::io::ErrorKind::Other,
        );
        assert!(s.revoke_device_durable("laptop").is_err());
        assert_eq!(
            s.get("tank")
                .unwrap()
                .lease
                .as_ref()
                .map(|lease| lease.holder_device.as_str()),
            Some("laptop"),
            "memory follows the value which remained committed"
        );
        assert!(
            Store::load(&path)
                .unwrap()
                .get("tank")
                .unwrap()
                .lease
                .is_some(),
            "the failed publish left the durable writer intact"
        );
        drop(armed);

        assert_eq!(s.revoke_device_durable("laptop").unwrap().len(), 1);
        assert!(Store::load(&path)
            .unwrap()
            .get("tank")
            .unwrap()
            .lease
            .is_none());
    }

    /// A directory-flush error happens after rename. The method reads that
    /// state back and recommits it, so it never lets the caller remove orbit
    /// membership on the strength of an unconfirmed rename.
    #[test]
    fn ambiguous_revocation_commit_is_confirmed_at_a_fresh_boundary() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("revoke-sync-volumes.json");
        let mut s = Store::load(&path).unwrap();
        s.create("tank", 1 << 30).unwrap();
        s.lease("tank", "dev", "laptop").unwrap();
        s.save().unwrap();

        let _armed = durable::faults::arm_once(
            "revoke-sync",
            durable::faults::Point::SyncDir,
            dir.path().display().to_string(),
            std::io::ErrorKind::Other,
        );
        assert_eq!(s.revoke_device_durable("laptop").unwrap().len(), 1);
        assert!(Store::load(&path)
            .unwrap()
            .get("tank")
            .unwrap()
            .lease
            .is_none());
    }

    #[test]
    fn recovery_copy_cannot_resurrect_a_revoked_lease() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("revoke-recovery-volumes.json");
        let mut s = Store::load(&path).unwrap();
        s.create("tank", 1 << 30).unwrap();
        s.lease("tank", "dev", "laptop").unwrap();
        s.save().unwrap();
        s.revoke_device_durable("laptop").unwrap();

        std::fs::write(&path, b"{").unwrap();
        let recovered = Store::load(&path).unwrap();
        assert!(
            recovered.get("tank").unwrap().lease.is_none(),
            "last-known-good state must be revoked too"
        );
    }

    /// Mirror the orbit-store confirmation boundary for the lease half of a
    /// device removal. The first publish has cleared the writer but left it
    /// in `.bak`; a failure while staging the confirming publish must remain
    /// retryable after restart, and the retry must make fallback recovery
    /// preserve the revocation.
    #[test]
    fn every_pre_backup_revocation_confirmation_failure_is_retryable() {
        use durable::faults::Point;

        for (tag, point) in [
            ("revoke-confirm-create", Point::Create),
            ("revoke-confirm-write", Point::Write),
            ("revoke-confirm-sync-file", Point::SyncFile),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join(format!("{tag}-volumes.json"));
            let mut store = Store::load(&path).unwrap();
            store.create("tank", 1 << 30).unwrap();
            store.lease("tank", "dev", "laptop").unwrap();
            store.save().unwrap();

            store.revoke_device("laptop");
            store.save().unwrap();
            assert!(store.get("tank").unwrap().lease.is_none(), "{point:?}");
            assert!(
                Store::load(&durable::backup_path(&path))
                    .unwrap()
                    .get("tank")
                    .unwrap()
                    .lease
                    .is_some(),
                "fixture must stop between revocation and confirmation at {point:?}"
            );

            let armed = durable::faults::arm(
                tag,
                point,
                path.display().to_string(),
                std::io::ErrorKind::Other,
            );
            assert!(store.revoke_device_durable("laptop").is_err(), "{point:?}");
            assert!(store.get("tank").unwrap().lease.is_none(), "{point:?}");
            assert!(
                Store::load(&durable::backup_path(&path))
                    .unwrap()
                    .get("tank")
                    .unwrap()
                    .lease
                    .is_some(),
                "the injected failure must precede backup rotation at {point:?}"
            );

            let mut restarted = Store::load(&path).unwrap();
            assert!(restarted.get("tank").unwrap().lease.is_none(), "{point:?}");
            drop(armed);

            assert!(restarted
                .revoke_device_durable("laptop")
                .unwrap()
                .is_empty());
            std::fs::write(&path, b"{").unwrap();
            assert!(
                Store::load(&path)
                    .unwrap()
                    .get("tank")
                    .unwrap()
                    .lease
                    .is_none(),
                "corrupt-live recovery resurrected the lease after {point:?}"
            );
        }
    }

    #[test]
    fn a_missing_volume_is_missing_from_this_device_not_from_the_orbit() {
        let s = store();
        let err = s.get("ghost").unwrap_err().to_string();
        assert!(err.contains("on this device"), "{err}");
        assert!(err.contains("ast volume ls"), "{err}");
    }

    #[test]
    fn names_that_would_not_survive_a_filename_are_refused() {
        assert!(check_name("tank").is_ok());
        assert!(check_name("tank-2_b").is_ok());
        assert!(check_name("").is_err());
        assert!(check_name("../etc").is_err());
        assert!(check_name("a:b").is_err());
        assert!(check_name("-lead").is_err());
    }

    /// The store is written and read back across daemon restarts, and the
    /// epoch is the field that must not be lost.
    #[test]
    fn the_store_round_trips_through_its_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("volumes.json");
        let mut s = Store::load(&path).unwrap();
        s.create("tank", 5 << 30).unwrap();
        s.lease("tank", "dev", "laptop").unwrap();
        s.set_export_proc(
            "tank",
            Some(ProcId {
                pid: 4242,
                started_us: 7,
                exec: None,
            }),
        )
        .unwrap();
        s.save().unwrap();

        let back = Store::load(&path).unwrap();
        let vol = back.get("tank").unwrap();
        assert_eq!(vol.size_bytes, 5 << 30);
        assert_eq!(vol.epoch, 1);
        let lease = vol.lease.as_ref().unwrap();
        assert_eq!(lease.holder, "dev");
        // Both halves survive: the bare pid for anything older reading this
        // file, and the identity that is the only thing signals are gated on.
        assert_eq!(lease.pid, Some(4242));
        assert_eq!(lease.proc.as_ref().map(|p| p.started_us), Some(7));
        assert_eq!(lease.export, "tank-e1");
    }

    /// A lease is a fence, and a fence that half-exists is worse than no
    /// fence: two writers would both believe they hold epoch 2. A commit
    /// killed before it published leaves the epoch where it was, so the
    /// holder's next lease takes the same number and the export socket it
    /// names is the one nobody else is serving.
    #[test]
    fn a_lease_killed_mid_commit_leaves_the_epoch_where_it_was() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("volumes.json");
        let mut s = Store::load(&path).unwrap();
        s.create("tank", 5 << 30).unwrap();
        s.lease("tank", "dev", "laptop").unwrap();
        s.save().unwrap();

        // The renewal that never lands.
        s.lease("tank", "dev", "laptop").unwrap();
        let armed = durable::faults::arm(
            "vol-kill",
            durable::faults::Point::Rename,
            path.display().to_string(),
            std::io::ErrorKind::Other,
        );
        assert!(s.save().is_err());
        drop(armed);

        let back = Store::load(&path).unwrap();
        let vol = back.get("tank").unwrap();
        assert_eq!(
            vol.epoch, 1,
            "the epoch that was committed is the epoch that holds"
        );
        assert_eq!(vol.lease.as_ref().unwrap().export, "tank-e1");
    }

    /// A truncated volume book is repaired from the last-known-good copy,
    /// which may be an epoch behind — and being an epoch behind is safe in
    /// the one direction that matters, because the next lease climbs from
    /// there and the holder is fenced by the export name, not by the number.
    #[test]
    fn a_truncated_volume_book_is_repaired_rather_than_emptied() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("volumes.json");
        let mut s = Store::load(&path).unwrap();
        s.create("tank", 5 << 30).unwrap();
        s.save().unwrap();
        s.lease("tank", "dev", "laptop").unwrap();
        s.save().unwrap();

        let whole = std::fs::read_to_string(&path).unwrap();
        std::fs::write(&path, &whole[..whole.len() / 2]).unwrap();

        let back = Store::load(&path).unwrap();
        let vol = back
            .get("tank")
            .expect("the volume is not forgotten because a page went");
        assert_eq!(vol.size_bytes, 5 << 30);
    }
}
