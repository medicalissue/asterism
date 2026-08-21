//! The orbit registry — one flat namespace of instances — and this device's
//! shard of it.
//!
//! The orbit is a pool of parts; an instance is a computer assembled from
//! them. There is exactly **one** instance registry per orbit, and it is flat:
//! `dev` names one instance, wherever in the pool its cpu and ram are being
//! sourced from today. "The laptop's dev" is not a thing that can be said.
//!
//! That one registry is never stored in one piece, because storing it in one
//! piece would need a device that is always up to store it on. Instead each
//! device persists a [`Shard`] — the rows for the instances whose cpu/ram it
//! supplies — at `$ASTERISM_HOME/state.json`, and the whole registry is
//! assembled at read time by asking every reachable device in the orbit for
//! its shard. `astd`'s mesh module does the assembling; this module is one
//! shard and the rules that hold within it.
//!
//! Two consequences worth stating, because they are the reason for the shape:
//!
//! * **A name is claimed against the orbit, not against a shard.** A shard can
//!   only refuse a name it already holds; refusing a name held elsewhere needs
//!   the other shards, so `ast create` asks them before it gets here.
//! * **A device is not privileged.** It supplies parts. Which device supplies
//!   an instance's cpu and ram is a mutable attribute of the instance, not a
//!   relationship the device has to it.
//!
//! Writes go through [`crate::durable`], so a crash mid-save never leaves a
//! torn shard, a shard that never reached the drive, or a shard with no
//! last-known-good copy beside it.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::durable::{self, Loaded};
use crate::hv::{Handle, ImageKind, Machine};
use crate::instance::{
    self, now_unix, Conflict, Instance, Moving, Policy, PortForward, Restart, Shape, Status,
    Volume,
};
use crate::proc::ProcId;
use crate::secret::Binding;

/// The shard file format this build writes.
///
/// Version 1 is `{"version": 1, "instances": {...}}`. What came before it had
/// no envelope at all — the map on its own — and is still read, then written
/// back in this shape the first time a shard is loaded. There is nothing to
/// convert inside the rows themselves; the envelope exists so that the *next*
/// change of shape can be refused by name instead of arriving as a parse
/// error.
pub const SHARD_VERSION: u32 = 1;

/// One device's shard of the orbit registry, persisted as JSON at `path`.
pub struct Shard {
    path: PathBuf,
    instances: BTreeMap<String, Instance>,
}

/// What a shard file holds.
#[derive(Debug, Serialize, Deserialize)]
struct ShardFile {
    version: u32,
    instances: BTreeMap<String, Instance>,
}

/// Either shape of shard file, decided by what is in the one on disk.
///
/// Deliberately *not* `#[serde(untagged)]`, which would be one line shorter
/// and would replace every diagnosis with "data did not match any variant".
/// A registry that will not load is exactly the moment a user needs to be
/// told that the row for `dev` is missing its `machine`, so the shape is
/// decided by looking for the envelope's `version` key and the chosen shape
/// then reports its own error.
///
/// A file from a *newer* Asterism never reaches here: `durable` reads the
/// version field before the document and refuses it there.
#[derive(Debug)]
enum AnyShard {
    Current(ShardFile),
    /// Written by an Asterism before shards were versioned.
    Legacy(BTreeMap<String, Instance>),
}

impl<'de> Deserialize<'de> for AnyShard {
    fn deserialize<D: serde::Deserializer<'de>>(de: D) -> std::result::Result<Self, D::Error> {
        use serde::de::Error as _;
        let value = serde_json::Value::deserialize(de)?;
        // An envelope has a numeric `version`. An instance called "version"
        // is not a number, so the two cannot be confused.
        if value.get("version").is_some_and(serde_json::Value::is_number) {
            serde_json::from_value(value).map(AnyShard::Current).map_err(D::Error::custom)
        } else {
            serde_json::from_value(value).map(AnyShard::Legacy).map_err(D::Error::custom)
        }
    }
}

impl AnyShard {
    /// Whether reading this shard is itself a migration, and so has to be
    /// written back in the current shape.
    fn is_legacy(&self) -> bool {
        matches!(self, AnyShard::Legacy(_))
    }

    fn into_instances(self) -> BTreeMap<String, Instance> {
        match self {
            AnyShard::Current(file) => file.instances,
            AnyShard::Legacy(instances) => instances,
        }
    }
}

/// One row of the assembled orbit registry, as `ast ls` prints it.
///
/// Separate from [`Instance`] because it carries something the record itself
/// cannot know: whether the device supplying this instance's cpu/ram answered
/// while the view was being assembled. A row that came out of the last-seen
/// cache instead of a live shard says so, and prints its status as `unknown` —
/// the instance is real, its state is merely stale.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrbitRow {
    pub instance: Instance,
    /// Whether the shard this row came from answered just now.
    pub live: bool,
}

impl Shard {
    pub fn load(path: &Path) -> Result<Self> {
        let what = "this device's registry shard";
        let (raw, repaired) = match durable::load_json_versioned::<AnyShard>(
            path,
            what,
            SHARD_VERSION,
        )? {
            Some(Loaded { value, repaired }) => (Some(value), repaired),
            None => (None, None),
        };
        if let Some(why) = &repaired {
            // Loud, and on the daemon's log rather than swallowed: the rows
            // that were in the failed commit are gone, and the user is owed
            // the chance to notice which.
            eprintln!("astd: {why}");
        }
        let migrated = raw.as_ref().is_some_and(AnyShard::is_legacy);
        let mut instances = raw.map(AnyShard::into_instances).unwrap_or_default();
        // Entries written before instances carried a Handle are folded into
        // the current shape here, so nothing downstream has to know that an
        // older format ever existed.
        for inst in instances.values_mut() {
            inst.migrate_legacy();
        }
        let mut shard = Self { path: path.to_owned(), instances };
        // A shard that was recovered from its backup, or that arrived in the
        // pre-envelope shape, is written back now rather than at the next
        // mutation: a daemon that read it and then died would otherwise do
        // the same recovery again, and the second time the backup may be the
        // broken file.
        if repaired.is_some() || migrated {
            if let Err(e) = shard.save() {
                eprintln!("astd: could not write the repaired registry back: {e:#}");
            }
        }
        if let Err(e) = shard.adopt_policy_sidecars() {
            eprintln!("astd: folding policy.json into the registry: {e:#}");
        }
        Ok(shard)
    }

    /// Fold each instance's `policy.json` into the instance, once, and
    /// delete the file.
    ///
    /// The restart policy was a sidecar while the registry was being
    /// rewritten for orbit-global namespaces; it is a field on the instance
    /// now. An upgraded shard reads those files the first time it loads and
    /// keeps what they said, and the files go — leaving one place the policy
    /// lives rather than two that can disagree.
    ///
    /// The directory is derived from the shard's own path rather than from
    /// `ASTERISM_HOME`, so a shard loaded from anywhere reads (and deletes)
    /// only the sidecars that belong to it.
    ///
    /// **The order matters.** The shard is committed *before* a single
    /// sidecar is deleted, so a migration interrupted anywhere is a migration
    /// that runs again from the start: either the policies are in the shard
    /// (and the leftover files say the same thing, and are re-read to the
    /// same values), or they are not and the files are all still there. The
    /// other order — delete, then save — loses a hand-set `never` to a
    /// `kill -9` in between.
    fn adopt_policy_sidecars(&mut self) -> Result<()> {
        let Some(home) = self.path.parent().map(Path::to_owned) else { return Ok(()) };
        let mut adopted: Vec<PathBuf> = Vec::new();
        for (name, inst) in self.instances.iter_mut() {
            let path = home.join("instances").join(name).join("policy.json");
            if !path.exists() {
                continue;
            }
            // A file that will not parse is not a reason to refuse to restart
            // anything: the default is "come back", and losing a hand-edited
            // `never` is the lesser of the two failures.
            match std::fs::read(&path).ok().and_then(|b| serde_json::from_slice(&b).ok()) {
                Some(policy) => {
                    inst.policy = policy;
                    eprintln!(
                        "astd: {} folded into the registry — the restart policy \
                         is a field on the instance now",
                        path.display()
                    );
                }
                None => eprintln!(
                    "astd: {} is not readable as a restart policy — using the \
                     default (restart always)",
                    path.display()
                ),
            }
            adopted.push(path);
        }
        if adopted.is_empty() {
            return Ok(());
        }
        self.save().context("saving the registry after folding in policy.json")?;
        for path in adopted {
            let _ = std::fs::remove_file(path);
        }
        Ok(())
    }

    pub fn save(&self) -> Result<()> {
        let file = ShardFile {
            version: SHARD_VERSION,
            instances: self.instances.clone(),
        };
        durable::commit_json(&self.path, &file)
            .context("committing this device's registry shard")
    }

    /// Define an instance in this shard, sourcing its cpu and ram from
    /// `cpu_device`. `machine` records the runnable backend that was probed
    /// before this row was created.
    ///
    /// The name must already have been claimed against the whole orbit; all
    /// this can see is one shard, so all it can refuse is a name this shard
    /// already holds.
    pub fn create(
        &mut self,
        name: &str,
        cpu_device: &str,
        image: &str,
        shape: Shape,
        machine: Machine,
    ) -> Result<Instance> {
        check_name(name)?;
        if let Some(existing) = self.instances.get(name) {
            bail!("{}", taken(existing));
        }
        let inst = Instance::new(name, cpu_device, image, shape, machine);
        self.instances.insert(name.to_owned(), inst.clone());
        Ok(inst)
    }

    /// Record what the instance's image turned out to be, and the ports it
    /// publishes.
    ///
    /// Separate from [`Shard::create`] because it is decided by resolving the
    /// image rather than by naming it: `--image nginx` is a container image
    /// and `--image debian:13` is a disk, and only the image store can say
    /// which. Set once, at create, alongside the backend and for the same
    /// reason — what an instance was made from is part of its identity, not
    /// something to re-derive at each boot.
    pub fn set_source(
        &mut self,
        name: &str,
        kind: ImageKind,
        publish: Vec<PortForward>,
    ) -> Result<Instance> {
        let inst = self.get_mut(name)?;
        inst.image_kind = kind;
        inst.publish = publish;
        Ok(inst.clone())
    }

    /// Record the bootstrap profiles an instance should have.
    ///
    /// Names only, and unresolved: whether `claude` means anything is a
    /// question for [`crate::profile`], asked by the daemon before this is
    /// called and again by the boot that builds the seed. Writing a name the
    /// catalog does not know would be an instance that cannot boot, which is
    /// why both ends ask.
    pub fn set_profiles(&mut self, name: &str, profiles: Vec<String>) -> Result<Instance> {
        let inst = self.get_mut(name)?;
        inst.profiles = profiles;
        Ok(inst.clone())
    }

    pub fn get(&self, name: &str) -> Result<&Instance> {
        self.instances
            .get(name)
            .with_context(|| format!("no instance named {name:?} in this orbit"))
    }

    /// Whether this shard holds `name`. The cheap half of a name claim.
    pub fn holds(&self, name: &str) -> bool {
        self.instances.contains_key(name)
    }

    pub fn list(&self) -> Vec<Instance> {
        let mut all: Vec<_> = self.instances.values().cloned().collect();
        all.sort_by_key(|i| i.created_at);
        all
    }

    pub fn set_running(&mut self, name: &str, handle: Handle) -> Result<Instance> {
        let inst = self.get_mut(name)?;
        inst.status = Status::Running;
        inst.handle = Some(handle);
        Ok(inst.clone())
    }

    /// Fill in the ownership identity of an already-recorded handle.
    ///
    /// Deliberately narrower than [`Shard::set_running`]: the only field it
    /// can touch is [`Handle::proc`], and only where the handle has none. It
    /// exists for one caller — the daemon's startup migration for registries
    /// written before identities did — and a mutation that could rewrite the
    /// rest of a live guest's handle would be a much bigger thing to hand
    /// out for that.
    pub fn adopt_handle_identity(&mut self, name: &str, proc: ProcId) -> Result<()> {
        let inst = self.get_mut(name)?;
        let Some(handle) = inst.handle.as_mut() else {
            bail!("instance {name:?} has no handle to adopt a process for");
        };
        if handle.proc.is_some() {
            return Ok(());
        }
        if handle.pid != Some(proc.pid) {
            bail!(
                "instance {name:?} records pid {:?}, so an identity for pid {} is not \
                 its guest",
                handle.pid,
                proc.pid
            );
        }
        handle.proc = Some(proc);
        Ok(())
    }

    /// Set what happens when this instance's guest dies.
    ///
    /// Sticky, like every other part of an instance: `ast up --restart never`
    /// says so once and the supervisor honours it for every later boot too.
    pub fn set_policy(&mut self, name: &str, policy: Policy) -> Result<Instance> {
        let inst = self.get_mut(name)?;
        inst.policy = policy;
        Ok(inst.clone())
    }

    /// Change only whether this instance comes back, leaving the rest of its
    /// policy — the restart budget — where it was.
    pub fn set_restart(&mut self, name: &str, restart: Restart) -> Result<Instance> {
        let inst = self.get_mut(name)?;
        inst.policy.restart = restart;
        Ok(inst.clone())
    }

    pub fn set_stopped(&mut self, name: &str) -> Result<Instance> {
        let inst = self.get_mut(name)?;
        inst.status = Status::Stopped;
        inst.handle = None;
        Ok(inst.clone())
    }

    pub fn remove(&mut self, name: &str) -> Result<Instance> {
        if self.get(name)?.status == Status::Running {
            bail!("instance {name:?} is running — `ast down {name}` first");
        }
        Ok(self.instances.remove(name).expect("checked above"))
    }

    /// Give an instance a different name, and clear any conflict on it.
    ///
    /// This is the only way out of a name collision, which is why it is also
    /// the only command a conflicted instance will answer. The new name must
    /// have been claimed against the orbit first, exactly as at create.
    ///
    /// Refused while the guest is running: the instance's directory, its
    /// control socket and its console log are all named after the instance, so
    /// renaming underneath a live guest would leave the running process
    /// pointing at paths that no longer describe it.
    pub fn rename(&mut self, name: &str, new_name: &str) -> Result<Instance> {
        check_name(new_name)?;
        if name == new_name {
            bail!("instance {name:?} is already called that");
        }
        if let Some(existing) = self.instances.get(new_name) {
            bail!("{}", taken(existing));
        }
        let mut inst = self
            .instances
            .remove(name)
            .with_context(|| format!("no instance named {name:?} in this orbit"))?;
        if inst.status == Status::Running {
            let restore = inst.clone();
            self.instances.insert(name.to_owned(), restore);
            bail!("instance {name:?} is running — `ast down {name}` first");
        }
        inst.name = new_name.to_owned();
        inst.conflict = None;
        self.instances.insert(new_name.to_owned(), inst.clone());
        Ok(inst)
    }

    /// Record that this instance's name turned out to be taken elsewhere in
    /// the orbit.
    ///
    /// # The partition rule
    ///
    /// `ast create` claims a name against every device it can reach. Devices
    /// it *cannot* reach are not a reason to refuse — an orbit that stops
    /// accepting work the moment a laptop shuts its lid is not a pool, it is a
    /// quorum — so the claim proceeds and the row is written down. The
    /// collision that was not detectable then is detected when the partition
    /// heals: the next orbit view assembled from both shards sees one name
    /// twice.
    ///
    /// The tie-break is **the newer creation loses**, by `created_at`. It has
    /// to be a total order that both sides compute identically from data they
    /// both hold, or the two devices would disagree about which of them is
    /// broken. Creation time is that, and it also picks the instance a human
    /// is least likely to have grown attached to. The loser is marked here and
    /// refuses every command but `ast rename` until it is given a free name.
    pub fn mark_conflicted(&mut self, name: &str, other_cpu_device: &str) -> Result<Instance> {
        let inst = self.get_mut(name)?;
        inst.conflict = Some(Conflict {
            other_cpu_device: other_cpu_device.to_owned(),
            found_at: now_unix(),
        });
        Ok(inst.clone())
    }

    /// Attach a volume. `mount_point` overrides where it lands in the
    /// guest; by default it lands under `/mnt/ast/` named after the host
    /// path's last component.
    pub fn attach_volume(
        &mut self,
        name: &str,
        path: &str,
        host: &str,
        mount_point: Option<&str>,
    ) -> Result<Instance> {
        let mount_point = mount_point
            .map(str::to_owned)
            .unwrap_or_else(|| instance::default_mount_point(path));
        if !mount_point.starts_with('/') {
            bail!("guest mount point must be an absolute path (got {mount_point:?})");
        }

        let inst = self.get_mut(name)?;
        if inst.volumes.iter().any(|v| v.path == path && v.host == host) {
            bail!("{host}:{path} is already attached to {name:?}");
        }
        // Two volumes at one guest path would silently shadow each other.
        if let Some(clash) = inst.volumes.iter().find(|v| v.guest_path() == mount_point) {
            bail!(
                "{name:?} already mounts {}:{} at {mount_point} — pick another with --at",
                clash.host,
                clash.path
            );
        }
        inst.volumes.push(Volume::dir(path, host, Some(mount_point)));
        Ok(inst.clone())
    }

    /// Record a block volume on an instance, at the epoch its provider just
    /// granted.
    ///
    /// No mount point: a block volume arrives as a disk and the guest decides
    /// what to do with it. Re-attaching one that is already recorded updates
    /// the epoch rather than adding a second row — which is what a renewal
    /// is, and what makes attach idempotent.
    pub fn attach_block(
        &mut self,
        name: &str,
        volume: &str,
        host: &str,
        epoch: u64,
        size_bytes: u64,
    ) -> Result<Instance> {
        let inst = self.get_mut(name)?;
        if let Some(existing) =
            inst.volumes.iter_mut().find(|v| v.path == volume && v.host == host)
        {
            if !existing.is_block() {
                bail!("{host}:{volume} is already attached to {name:?} as a directory");
            }
            existing.epoch = Some(epoch);
            existing.size_bytes = Some(size_bytes);
        } else {
            inst.volumes.push(Volume::block(volume, host, epoch, size_bytes));
        }
        Ok(inst.clone())
    }

    /// Record a secret binding on an instance.
    ///
    /// Attach-time is where a binding is refused, for the same reason a
    /// volume is: an instance that looks configured and whose guest then
    /// finds a handle nothing will honour is worse than a command that says
    /// no. What this function owns is the part of that which is about the
    /// *shard* — one binding per authority, one environment variable per
    /// guest — while whether the secret exists, whether it is in conflict and
    /// whether this backend can carry egress at all belong to the daemon,
    /// which is the only thing that can ask.
    pub fn attach_secret(&mut self, name: &str, binding: Binding) -> Result<Instance> {
        let inst = self.get_mut(name)?;
        if let Some(clash) = inst
            .secrets
            .iter()
            .find(|held| held.authority == binding.authority)
        {
            bail!(
                "{name:?} already sends {:?} to {} — one authority takes one secret, because \
                 a request carries one credential",
                clash.secret,
                clash.authority
            );
        }
        if let Some(clash) = inst.secrets.iter().find(|held| held.env == binding.env) {
            bail!(
                "{name:?} already exports {:?} as ${} — pick another with --env",
                clash.secret,
                clash.env
            );
        }
        inst.secrets.push(binding);
        Ok(inst.clone())
    }

    /// Take a secret off an instance, by its orbit name.
    ///
    /// Returns the binding, because revoking one is more than forgetting a
    /// row: the handle it carried has to stop being honoured by the running
    /// proxy, and the seed that told the guest about it has to be reissued.
    pub fn detach_secret(&mut self, name: &str, secret: &str) -> Result<(Instance, Binding)> {
        let inst = self.get_mut(name)?;
        let Some(index) = inst.secrets.iter().position(|held| held.secret == secret) else {
            bail!("{secret:?} is not attached to {name:?} — see: ast status {name}");
        };
        let removed = inst.secrets.remove(index);
        Ok((inst.clone(), removed))
    }

    /// Take a volume off an instance. Returns the record that was removed, so
    /// the caller knows whether a lease has to be handed back.
    pub fn detach_volume(
        &mut self,
        name: &str,
        volume: &str,
        host: &str,
    ) -> Result<(Instance, Volume)> {
        let inst = self.get_mut(name)?;
        let Some(index) = inst.volumes.iter().position(|v| v.path == volume && v.host == host)
        else {
            bail!(
                "{host}:{volume} is not attached to {name:?} — see: ast status {name}"
            );
        };
        let removed = inst.volumes.remove(index);
        Ok((inst.clone(), removed))
    }

    /// Put the fence up (or take it down) on an instance whose cpu part is
    /// being swapped onto another device.
    ///
    /// While it is up this device holds the only bootable copy and refuses to
    /// boot it: for the length of a transfer there are two directories with
    /// the same instance's bytes in them, and exactly one of them may ever be
    /// booted. See `Instance::moving`.
    pub fn set_moving(&mut self, name: &str, moving: Option<Moving>) -> Result<Instance> {
        let inst = self.get_mut(name)?;
        inst.moving = moving;
        Ok(inst.clone())
    }

    /// Record which device's guest key opens this instance's guest.
    ///
    /// Written by the boot that built the seed, because the seed is where
    /// that key is baked in. See `Instance::seed_device`.
    pub fn set_seed_device(&mut self, name: &str, device: &str) -> Result<Instance> {
        let inst = self.get_mut(name)?;
        inst.seed_device = Some(device.to_owned());
        Ok(inst.clone())
    }

    /// Take on an instance whose cpu part has just been moved here.
    ///
    /// Not [`Shard::create`]: the name was claimed long ago and the id, the
    /// creation time and the snapshots are the ones the instance has always
    /// had. Nothing about its identity moves — only which device supplies a
    /// part of it, which is the whole of what a swap changes.
    ///
    /// The name is refused if this shard already holds it, which is the same
    /// bar `create` clears; the orbit-wide half of the claim was settled
    /// before any bytes moved.
    pub fn adopt(&mut self, instance: Instance) -> Result<Instance> {
        check_name(&instance.name)?;
        if let Some(existing) = self.instances.get(&instance.name) {
            bail!("{}", taken(existing));
        }
        self.instances.insert(instance.name.clone(), instance.clone());
        Ok(instance)
    }

    fn get_mut(&mut self, name: &str) -> Result<&mut Instance> {
        self.instances
            .get_mut(name)
            .with_context(|| format!("no instance named {name:?} in this orbit"))
    }
}

/// What the orbit says when a name is already spoken for.
///
/// One sentence, everywhere, whichever shard the clash was found in: the
/// namespace is orbit-wide, so the refusal names the orbit and then says where
/// the parts of the existing instance are coming from — which is a fact about
/// the instance, not a claim by the device.
pub fn taken(existing: &Instance) -> String {
    format!(
        "instance {:?} already exists in this orbit (cpu/ram on {})",
        existing.name, existing.cpu_device
    )
}

/// What every command on a conflicted instance says instead of running.
pub fn conflicted(inst: &Instance, conflict: &Conflict) -> String {
    format!(
        "instance {:?} shares its name with another instance in this orbit \
         (cpu/ram on {}) — rename this one first: ast rename {} <new-name>",
        inst.name, conflict.other_cpu_device, inst.name
    )
}

/// An instance name has to survive being typed on a command line, compared by
/// eye, and used as a directory name on every device in the orbit.
pub fn check_name(name: &str) -> Result<()> {
    if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
        bail!("instance names are ascii letters, digits and '-' (got {name:?})");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hv::{ControlChannel, GuestEndpoint};

    fn handle(pid: u32, ssh_port: u16) -> Handle {
        Handle {
            backend: "qemu".into(),
            pid: Some(pid),
            proc: Some(ProcId { pid, started_us: 1_700_000_000_000_000, exec: None }),
            ctl: ControlChannel::Qmp { path: "/tmp/qmp.sock".into() },
            endpoint: GuestEndpoint::HostForward { ssh_port },
            started_at: 1_700_000_000,
        }
    }

    fn scratch() -> PathBuf {
        std::env::temp_dir()
            .join(format!("asterism-test-{}", uuid::Uuid::new_v4()))
            .join("state.json")
    }

    fn machine() -> Machine {
        Machine {
            backend: "qemu".into(),
            machine_type: "virt".into(),
            cpu: "host".into(),
            hv_version: "test".into(),
        }
    }

    #[test]
    fn create_save_load_round_trip() {
        let path = scratch();
        let mut shard = Shard::load(&path).unwrap();
        shard.create("dev", "laptop", "ubuntu:24.04", Shape::default(), machine()).unwrap();
        shard.attach_volume("dev", "/tank/media", "desktop", None).unwrap();
        shard.save().unwrap();

        let reloaded = Shard::load(&path).unwrap();
        let inst = reloaded.get("dev").unwrap();
        assert_eq!(inst.cpu_device, "laptop");
        assert_eq!(inst.volumes.len(), 1);
        assert_eq!(inst.volumes[0].guest_path(), "/mnt/ast/media");
        assert_eq!(inst.status, Status::Defined);
    }

    /// The restart policy used to be a `policy.json` beside the instance.
    /// A shard that still has those files reads them once, keeps what they
    /// said, and takes them away — so there is one place the policy lives
    /// rather than two that can disagree.
    #[test]
    fn a_policy_sidecar_is_folded_in_once_and_the_file_goes() {
        let path = scratch();
        let home = path.parent().unwrap().to_owned();
        let mut shard = Shard::load(&path).unwrap();
        for name in ["kept-up", "left-down", "corrupt", "silent"] {
            shard.create(name, "laptop", "ubuntu:24.04", Shape::default(), machine()).unwrap();
        }
        shard.save().unwrap();

        let sidecar = |name: &str| home.join("instances").join(name).join("policy.json");
        for name in ["kept-up", "left-down", "corrupt"] {
            std::fs::create_dir_all(sidecar(name).parent().unwrap()).unwrap();
        }
        std::fs::write(sidecar("kept-up"), r#"{"restart":"always","max_attempts":9}"#).unwrap();
        // A file naming only the part it cared about is what most of them are.
        std::fs::write(sidecar("left-down"), r#"{"restart":"never"}"#).unwrap();
        std::fs::write(sidecar("corrupt"), "{ this is not json").unwrap();

        let reloaded = Shard::load(&path).unwrap();
        let policy = |name: &str| reloaded.get(name).unwrap().policy;
        assert_eq!(policy("kept-up").restart, Restart::Always);
        assert_eq!(policy("kept-up").max_attempts, 9, "the whole file is kept, not half");
        assert_eq!(policy("left-down").restart, Restart::Never);
        assert_eq!(
            policy("left-down").max_attempts,
            instance::MAX_ATTEMPTS,
            "what the file did not say keeps its default"
        );
        // A file that will not parse must not mean "never restart it": the
        // default is to bring things back, and that is the safe way to fail.
        assert_eq!(policy("corrupt").restart, Restart::Always);
        assert_eq!(policy("silent").restart, Restart::Always);

        for name in ["kept-up", "left-down", "corrupt"] {
            assert!(!sidecar(name).exists(), "{name}'s policy.json survived the migration");
        }

        // Load wrote the shard back itself, so what the files said is in
        // `state.json` even though nothing else has mutated the registry
        // since — a daemon that read them and then died has not lost them.
        let json = std::fs::read_to_string(&path).unwrap();
        assert!(json.contains("\"never\""), "{json}");
        let again = Shard::load(&path).unwrap();
        assert_eq!(again.get("left-down").unwrap().policy.restart, Restart::Never);
        assert_eq!(again.get("kept-up").unwrap().policy.max_attempts, 9);
    }

    #[test]
    fn volumes_get_mount_points_and_do_not_collide() {
        let mut shard = Shard::load(&scratch()).unwrap();
        shard.create("dev", "laptop", "ubuntu:24.04", Shape::default(), machine()).unwrap();

        let inst = shard.attach_volume("dev", "/tank/media", "desktop", None).unwrap();
        assert_eq!(inst.volumes[0].mount_point.as_deref(), Some("/mnt/ast/media"));

        // Same host path twice is a duplicate.
        assert!(shard.attach_volume("dev", "/tank/media", "desktop", None).is_err());
        // Different path, same basename: would shadow, so it is refused.
        assert!(shard.attach_volume("dev", "/srv/media", "desktop", None).is_err());
        // ...unless the caller says where to put it.
        let inst = shard
            .attach_volume("dev", "/srv/media", "desktop", Some("/opt/media"))
            .unwrap();
        assert_eq!(inst.volumes[1].guest_path(), "/opt/media");
        // Relative mount points are nonsense inside the guest.
        assert!(shard.attach_volume("dev", "/srv/x", "desktop", Some("rel")).is_err());
    }

    /// A block volume is a disk, so it has no mount point to collide on, and
    /// re-attaching it is a renewal rather than a second disk.
    #[test]
    fn block_volumes_carry_an_epoch_and_re_attach_in_place() {
        let mut shard = Shard::load(&scratch()).unwrap();
        shard.create("dev", "laptop", "ubuntu:24.04", Shape::default(), machine()).unwrap();

        let inst = shard.attach_block("dev", "tank", "desktop", 1, 10 << 30).unwrap();
        assert_eq!(inst.volumes.len(), 1);
        assert!(inst.volumes[0].is_block());
        assert_eq!(inst.volumes[0].epoch, Some(1));
        assert_eq!(inst.volumes[0].mount_point, None, "the guest decides that");

        let inst = shard.attach_block("dev", "tank", "desktop", 2, 10 << 30).unwrap();
        assert_eq!(inst.volumes.len(), 1, "a renewal is not a second disk");
        assert_eq!(inst.volumes[0].epoch, Some(2));

        // Two volumes of the same name on different devices are two volumes.
        let inst = shard.attach_block("dev", "tank", "nas", 1, 1 << 30).unwrap();
        assert_eq!(inst.volumes.len(), 2);

        // Detaching names what came off, so the caller can release the lease.
        let (inst, removed) = shard.detach_volume("dev", "tank", "desktop").unwrap();
        assert!(removed.is_block());
        assert_eq!(removed.epoch, Some(2));
        assert_eq!(inst.volumes.len(), 1);
        let err = shard.detach_volume("dev", "tank", "desktop").unwrap_err().to_string();
        assert!(err.contains("is not attached to \"dev\""), "{err}");

        // A directory and a block volume are different parts, and one cannot
        // quietly become the other.
        shard.attach_volume("dev", "/tank/media", "desktop", None).unwrap();
        let err = shard
            .attach_block("dev", "/tank/media", "desktop", 1, 1 << 30)
            .unwrap_err()
            .to_string();
        assert!(err.contains("as a directory"), "{err}");
    }

    /// A cpu-part swap changes one line of an instance's parts table. The
    /// rest of it — the id, the creation time, the snapshots — is the
    /// instance's own and does not move, because it was never on a device.
    #[test]
    fn adopting_a_moved_instance_keeps_everything_but_the_cpu_device() {
        let mut source = Shard::load(&scratch()).unwrap();
        let mut inst = source
            .create("dev", "laptop", "debian:13", Shape::default(), machine())
            .unwrap();

        // The fence, and the boot it refuses.
        let fenced = source
            .set_moving(
                "dev",
                Some(Moving {
                    to_device: "desktop".into(),
                    epoch: 1,
                    started_at: now_unix(),
                }),
            )
            .unwrap();
        assert_eq!(fenced.moving.unwrap().to_device, "desktop");
        assert!(source.set_moving("dev", None).unwrap().moving.is_none());
        assert!(source.set_moving("ghost", None).is_err());

        // What the target writes down.
        let mut target = Shard::load(&scratch()).unwrap();
        inst.cpu_device = "desktop".into();
        inst.move_epoch = 1;
        inst.seed_device = Some("laptop".into());
        let adopted = target.adopt(inst.clone()).unwrap();
        assert_eq!(adopted.id, source.get("dev").unwrap().id, "one instance, one id");
        assert_eq!(adopted.created_at, source.get("dev").unwrap().created_at);
        assert_eq!(adopted.cpu_device, "desktop", "only the part moved");
        assert_eq!(adopted.move_epoch, 1);
        assert_eq!(adopted.seeded_by(), "laptop", "the seed did not move with the cpu");

        // A shard that already holds the name refuses, in the orbit's words.
        let err = target.adopt(inst).unwrap_err().to_string();
        assert!(err.contains("already exists in this orbit"), "{err}");
    }

    /// A shard can only refuse what it can see — but when it refuses, it
    /// refuses in the orbit's vocabulary, because that is the namespace the
    /// user is being told about.
    #[test]
    fn a_name_this_shard_holds_is_refused_in_the_orbits_words() {
        let mut shard = Shard::load(&scratch()).unwrap();
        shard.create("dev", "laptop", "ubuntu:24.04", Shape::default(), machine()).unwrap();

        let err = shard
            .create("dev", "laptop", "ubuntu:24.04", Shape::default(), machine())
            .unwrap_err()
            .to_string();
        assert_eq!(err, "instance \"dev\" already exists in this orbit (cpu/ram on laptop)");
        assert!(shard.create("has space", "laptop", "u", Shape::default(), machine()).is_err());
        assert!(shard.create("", "laptop", "u", Shape::default(), machine()).is_err());
    }

    #[test]
    fn a_missing_instance_is_missing_from_the_orbit_not_from_a_device() {
        let shard = Shard::load(&scratch()).unwrap();
        let err = shard.get("dev").unwrap_err().to_string();
        assert_eq!(err, "no instance named \"dev\" in this orbit");
    }

    #[test]
    fn lifecycle_transitions() {
        let mut shard = Shard::load(&scratch()).unwrap();
        shard.create("dev", "laptop", "ubuntu:24.04", Shape::default(), machine()).unwrap();
        let inst = shard.set_running("dev", handle(4242, 22022)).unwrap();
        assert_eq!(inst.status, Status::Running);
        assert_eq!(inst.endpoint().unwrap().ssh_target(), ("127.0.0.1".to_owned(), 22022));
        assert_eq!(inst.pid(), Some(4242));
        assert!(shard.remove("dev").is_err());
        let inst = shard.set_stopped("dev").unwrap();
        assert_eq!(inst.status, Status::Stopped);
        assert_eq!(inst.pid(), None);
        assert!(inst.handle.is_none());
        shard.remove("dev").unwrap();
        assert!(shard.get("dev").is_err());
    }

    /// Renaming is the way out of a collision, so it has to clear the mark it
    /// is the remedy for.
    #[test]
    fn renaming_moves_the_row_and_clears_the_conflict() {
        let mut shard = Shard::load(&scratch()).unwrap();
        shard.create("dev", "laptop", "ubuntu:24.04", Shape::default(), machine()).unwrap();
        let marked = shard.mark_conflicted("dev", "desktop").unwrap();
        assert_eq!(marked.conflict.unwrap().other_cpu_device, "desktop");

        let renamed = shard.rename("dev", "dev2").unwrap();
        assert_eq!(renamed.name, "dev2");
        assert!(renamed.conflict.is_none(), "the rename is the remedy");
        assert!(shard.get("dev").is_err(), "the old name is free again");
        assert_eq!(shard.get("dev2").unwrap().cpu_device, "laptop");
    }

    #[test]
    fn a_rename_cannot_collide_or_run_over_a_live_guest() {
        let mut shard = Shard::load(&scratch()).unwrap();
        shard.create("dev", "laptop", "ubuntu:24.04", Shape::default(), machine()).unwrap();
        shard.create("other", "laptop", "ubuntu:24.04", Shape::default(), machine()).unwrap();

        let err = shard.rename("dev", "other").unwrap_err().to_string();
        assert!(err.contains("already exists in this orbit"), "{err}");
        assert!(shard.rename("dev", "has space").is_err());
        assert!(shard.rename("nope", "fine").is_err());

        // A running guest holds paths named after the instance.
        shard.set_running("dev", handle(4242, 22022)).unwrap();
        let err = shard.rename("dev", "dev2").unwrap_err().to_string();
        assert!(err.contains("is running"), "{err}");
        // ...and the failed rename did not lose the row.
        assert_eq!(shard.get("dev").unwrap().status, Status::Running);
    }

    /// The refusal a conflicted instance gives has to contain the command
    /// that fixes it, because it is the only command that will be accepted.
    #[test]
    fn the_conflict_message_says_what_to_do() {
        let mut shard = Shard::load(&scratch()).unwrap();
        shard.create("dev", "laptop", "ubuntu:24.04", Shape::default(), machine()).unwrap();
        let inst = shard.mark_conflicted("dev", "desktop").unwrap();
        let text = conflicted(&inst, inst.conflict.as_ref().unwrap());
        assert!(text.contains("shares its name with another instance in this orbit"), "{text}");
        assert!(text.contains("cpu/ram on desktop"), "{text}");
        assert!(text.contains("ast rename dev <new-name>"), "{text}");
    }

    /// A registry written by a pre-Handle daemon still loads, and the
    /// running guest it describes is not lost in the upgrade.
    #[test]
    fn pre_handle_registries_migrate_on_load() {
        let path = scratch();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(
            &path,
            r#"{"dev":{
                "id":"6f1c","name":"dev","anchor":"laptop","status":"running",
                "created_at":1700000000,"volumes":[],"image":"debian:13",
                "shape":{"cpus":2,"mem_mib":2048,"disk_gib":20},
                "machine":{"backend":"qemu","machine_type":"virt","cpu":"host","hv_version":"9.0.0"},
                "pid":4242,"ssh_port":22022
            }}"#,
        )
        .unwrap();

        let shard = Shard::load(&path).unwrap();
        let inst = shard.get("dev").unwrap();
        assert_eq!(inst.status, Status::Running);
        // The device that was called this instance's anchor is the device
        // supplying its cpu and ram; only the framing changed.
        assert_eq!(inst.cpu_device, "laptop");
        let h = inst.handle.as_ref().expect("the running guest survived the upgrade");
        assert_eq!(h.backend, "qemu", "old entries were all QEMU");
        assert_eq!(h.pid, Some(4242));
        assert_eq!(h.endpoint, GuestEndpoint::HostForward { ssh_port: 22022 });
        // The control path is the one the old backend derived from the name.
        assert_eq!(h.ctl, ControlChannel::Qmp { path: crate::paths::qmp_socket_path("dev") });
        assert_eq!(inst.machine.backend, "qemu");

        // Saving rewrites it in the new shape, and the legacy keys go away.
        // (Checked on the parsed object, because the handle's own endpoint
        // carries a field called `ssh_port` — nested, where it belongs.)
        shard.save().unwrap();
        let raw: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(raw["version"], SHARD_VERSION, "and in the current envelope");
        let saved = &raw["instances"]["dev"];
        assert!(saved.get("handle").is_some());
        assert_eq!(saved["cpu_device"], "laptop");
        assert!(saved.get("anchor").is_none(), "the old key is not written back: {saved}");
        assert!(saved.get("pid").is_none(), "legacy pid is not written back: {saved}");
        assert!(saved.get("ssh_port").is_none(), "legacy port is not written back: {saved}");
        assert_eq!(saved["handle"]["endpoint"]["ssh_port"], 22022);

        // ...and the migrated file loads to the same thing.
        let again = Shard::load(&path).unwrap();
        assert_eq!(again.get("dev").unwrap().handle, shard.get("dev").unwrap().handle);
    }

    // ---- crash recovery ----------------------------------------------------
    //
    // The primitive is proved in `durable`; these are the claims that only
    // mean something at this level, where the value is a registry.

    fn shard_with(path: &Path, names: &[&str]) -> Shard {
        let mut shard = Shard::load(path).unwrap();
        for name in names {
            shard.create(name, "laptop", "debian:13", Shape::default(), machine()).unwrap();
        }
        shard.save().unwrap();
        shard
    }

    /// `kill -9` during the save: the shard on disk is the one committed
    /// before it, every row of it, and the staging file is swept.
    #[test]
    fn a_shard_killed_mid_save_converges_on_the_last_committed_rows() {
        let path = scratch();
        let mut shard = shard_with(&path, &["one"]);
        shard.create("two", "laptop", "debian:13", Shape::default(), machine()).unwrap();

        let armed = durable::faults::arm(
            "shard-kill",
            durable::faults::Point::Rename,
            path.display().to_string(),
            std::io::ErrorKind::Other,
        );
        assert!(shard.save().is_err(), "the commit did not land");
        drop(armed);

        let swept = durable::sweep_temporaries(path.parent().unwrap());
        assert_eq!(swept, vec![durable::tmp_path(&path)]);

        let reloaded = Shard::load(&path).unwrap();
        assert!(reloaded.holds("one"));
        assert!(!reloaded.holds("two"), "a row from a commit that never landed is not a row");
    }

    /// ENOSPC: the save fails and says so, and the registry that was on disk
    /// is untouched. An instance is not silently forgotten because a disk
    /// filled up.
    #[test]
    fn a_full_disk_does_not_cost_the_registry() {
        let path = scratch();
        let mut shard = shard_with(&path, &["one"]);
        shard.create("two", "laptop", "debian:13", Shape::default(), machine()).unwrap();

        let armed = durable::faults::arm_errno(
            "shard-enospc",
            durable::faults::Point::Write,
            path.display().to_string(),
            libc::ENOSPC,
        );
        let err = shard.save().unwrap_err();
        assert!(format!("{err:#}").contains("registry shard"), "{err:#}");
        drop(armed);

        let reloaded = Shard::load(&path).unwrap();
        assert!(reloaded.holds("one"));
        assert!(!reloaded.holds("two"));
    }

    /// A shard truncated by the filesystem is repaired from the copy the last
    /// commit left, and the repaired file is written back — so the next boot
    /// finds a healthy registry rather than doing the same recovery against a
    /// backup that is now the only copy.
    #[test]
    fn a_truncated_shard_is_repaired_and_written_back() {
        let path = scratch();
        let mut shard = shard_with(&path, &["one"]);
        shard.create("two", "laptop", "debian:13", Shape::default(), machine()).unwrap();
        shard.save().unwrap();

        let whole = std::fs::read_to_string(&path).unwrap();
        std::fs::write(&path, &whole[..whole.len() / 3]).unwrap();

        let reloaded = Shard::load(&path).unwrap();
        assert!(reloaded.holds("one"), "the commit before the damage is what survives");
        // Written back on load, in the current shape, with no hand-editing.
        let raw: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(raw["version"], SHARD_VERSION);
        assert!(raw["instances"]["one"].is_object());
    }

    /// Both copies unreadable is the ambiguous case, and it is refused. An
    /// empty shard would tell the rest of the daemon that this device runs
    /// nothing, and the guests would still be running.
    #[test]
    fn a_shard_with_no_readable_copy_is_refused_with_a_repair_path() {
        let path = scratch();
        let mut shard = shard_with(&path, &["one"]);
        shard.create("two", "laptop", "debian:13", Shape::default(), machine()).unwrap();
        shard.save().unwrap();

        std::fs::write(&path, b"{\"instances\": ").unwrap();
        std::fs::write(durable::backup_path(&path), b"neither is this").unwrap();

        let err = Shard::load(&path).err().expect("an unreadable pair is refused");
        let text = format!("{err:#}");
        assert!(text.contains("will not guess"), "{text}");
        assert!(text.contains("To repair"), "{text}");
    }

    /// The policy sidecar migration, interrupted between the save and the
    /// deletes — the window a `kill -9` fits in. Re-running it lands on the
    /// same registry: the files say what the shard already says.
    #[test]
    fn a_half_finished_policy_migration_runs_again_to_the_same_place() {
        let path = scratch();
        let home = path.parent().unwrap().to_owned();
        shard_with(&path, &["kept-up", "left-down"]);

        let sidecar = |name: &str| home.join("instances").join(name).join("policy.json");
        for name in ["kept-up", "left-down"] {
            std::fs::create_dir_all(sidecar(name).parent().unwrap()).unwrap();
        }
        std::fs::write(sidecar("kept-up"), r#"{"restart":"always","max_attempts":9}"#).unwrap();
        std::fs::write(sidecar("left-down"), r#"{"restart":"never"}"#).unwrap();

        // First load folds them in and deletes the files.
        let once = Shard::load(&path).unwrap();
        assert_eq!(once.get("left-down").unwrap().policy.restart, Restart::Never);

        // Now put one back, which is exactly what a crash between the commit
        // and the unlink leaves: the shard already says it, and the file is
        // still there saying the same thing.
        std::fs::create_dir_all(sidecar("left-down").parent().unwrap()).unwrap();
        std::fs::write(sidecar("left-down"), r#"{"restart":"never"}"#).unwrap();

        let twice = Shard::load(&path).unwrap();
        assert_eq!(twice.get("left-down").unwrap().policy.restart, Restart::Never);
        assert_eq!(twice.get("kept-up").unwrap().policy.max_attempts, 9);
        assert!(!sidecar("left-down").exists(), "and the second pass finished the job");
    }

    /// The other half of that ordering: a migration whose commit fails keeps
    /// every sidecar, so nothing has been read and then thrown away.
    #[test]
    fn a_policy_migration_that_cannot_commit_keeps_the_sidecars() {
        let path = scratch();
        let home = path.parent().unwrap().to_owned();
        shard_with(&path, &["left-down"]);
        let sidecar = home.join("instances").join("left-down").join("policy.json");
        std::fs::create_dir_all(sidecar.parent().unwrap()).unwrap();
        std::fs::write(&sidecar, r#"{"restart":"never"}"#).unwrap();

        let armed = durable::faults::arm_errno(
            "policy-enospc",
            durable::faults::Point::Write,
            path.display().to_string(),
            libc::ENOSPC,
        );
        // Load still succeeds — a daemon that will not start because a
        // migration could not be written is worse than one that retries it
        // next time — but it must not have deleted what it could not save.
        let _ = Shard::load(&path).unwrap();
        drop(armed);

        assert!(sidecar.exists(), "the sidecar is the only copy of what it says");
        let retried = Shard::load(&path).unwrap();
        assert_eq!(retried.get("left-down").unwrap().policy.restart, Restart::Never);
        assert!(!sidecar.exists());
    }

    /// A stopped pre-Handle entry has no pid, and must not grow a handle.
    #[test]
    fn a_stopped_legacy_entry_stays_stopped() {
        let path = scratch();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(
            &path,
            r#"{"dev":{"id":"6f1c","name":"dev","anchor":"laptop","status":"stopped",
                "created_at":1700000000,"volumes":[],"image":"debian:13",
                "machine":{"backend":"qemu","machine_type":"virt","cpu":"host","hv_version":"9.0.0"}}}"#,
        )
        .unwrap();
        let shard = Shard::load(&path).unwrap();
        let inst = shard.get("dev").unwrap();
        assert!(inst.handle.is_none());
        assert_eq!(inst.pid(), None);
        assert_eq!(inst.status, Status::Stopped);
        // Shape falls back to the default, as it did before.
        assert_eq!(inst.shape.cpus, Shape::default().cpus);
    }

    #[test]
    fn a_registry_row_without_a_machine_is_rejected() {
        let path = scratch();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(
            &path,
            r#"{"dev":{
                "id":"6f1c","name":"dev","cpu_device":"laptop","status":"defined",
                "created_at":1700000000,"volumes":[],"image":"debian:13"
            }}"#,
        )
        .unwrap();

        let error = Shard::load(&path).err().expect("missing machine must fail");
        let error = format!("{error:#}");
        assert!(error.contains("machine"), "{error}");
    }
}
