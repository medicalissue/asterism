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
//! Writes go through a temp file + rename so a crash mid-save never leaves a
//! torn shard.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::hv::{Handle, ImageKind, Machine};
use crate::instance::{
    self, now_unix, Conflict, Instance, Moving, Policy, PortForward, Restart, Shape, Status,
    Volume,
};

/// One device's shard of the orbit registry, persisted as JSON at `path`.
pub struct Shard {
    path: PathBuf,
    instances: BTreeMap<String, Instance>,
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
        let mut instances: BTreeMap<String, Instance> = match std::fs::read(path) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .with_context(|| format!("corrupt registry shard at {}", path.display()))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => BTreeMap::new(),
            Err(e) => return Err(e).context("reading this device's registry shard"),
        };
        // Entries written before instances carried a Handle are folded into
        // the current shape here, so nothing downstream has to know that an
        // older format ever existed.
        for inst in instances.values_mut() {
            inst.migrate_legacy();
        }
        let mut shard = Self { path: path.to_owned(), instances };
        if shard.adopt_policy_sidecars() {
            // Written back now rather than at the next mutation: the files
            // have just been deleted, and a daemon that read them and then
            // died without saving would have lost what they said.
            if let Err(e) = shard.save() {
                eprintln!("astd: saving the registry after folding in policy.json: {e:#}");
            }
        }
        Ok(shard)
    }

    /// Fold each instance's `policy.json` into the instance, once, and
    /// delete the file. Reports whether anything moved.
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
    fn adopt_policy_sidecars(&mut self) -> bool {
        let Some(home) = self.path.parent().map(Path::to_owned) else { return false };
        let mut moved = false;
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
            let _ = std::fs::remove_file(&path);
            moved = true;
        }
        moved
    }

    pub fn save(&self) -> Result<()> {
        if let Some(dir) = self.path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let tmp = self.path.with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(&self.instances)?)?;
        std::fs::rename(&tmp, &self.path).context("committing this device's registry shard")?;
        Ok(())
    }

    /// Define an instance in this shard, sourcing its cpu and ram from
    /// `cpu_device`. `machine` records what it was defined against — `None`
    /// where no backend could be probed, which keeps `ast create` working on a
    /// device that has not installed a hypervisor yet.
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
        machine: Option<Machine>,
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

    #[test]
    fn create_save_load_round_trip() {
        let path = scratch();
        let mut shard = Shard::load(&path).unwrap();
        shard.create("dev", "laptop", "ubuntu:24.04", Shape::default(), None).unwrap();
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
            shard.create(name, "laptop", "ubuntu:24.04", Shape::default(), None).unwrap();
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
        shard.create("dev", "laptop", "ubuntu:24.04", Shape::default(), None).unwrap();

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
        shard.create("dev", "laptop", "ubuntu:24.04", Shape::default(), None).unwrap();

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
            .create("dev", "laptop", "debian:13", Shape::default(), None)
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
        shard.create("dev", "laptop", "ubuntu:24.04", Shape::default(), None).unwrap();

        let err = shard
            .create("dev", "laptop", "ubuntu:24.04", Shape::default(), None)
            .unwrap_err()
            .to_string();
        assert_eq!(err, "instance \"dev\" already exists in this orbit (cpu/ram on laptop)");
        assert!(shard.create("has space", "laptop", "u", Shape::default(), None).is_err());
        assert!(shard.create("", "laptop", "u", Shape::default(), None).is_err());
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
        shard.create("dev", "laptop", "ubuntu:24.04", Shape::default(), None).unwrap();
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
        shard.create("dev", "laptop", "ubuntu:24.04", Shape::default(), None).unwrap();
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
        shard.create("dev", "laptop", "ubuntu:24.04", Shape::default(), None).unwrap();
        shard.create("other", "laptop", "ubuntu:24.04", Shape::default(), None).unwrap();

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
        shard.create("dev", "laptop", "ubuntu:24.04", Shape::default(), None).unwrap();
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
        // No machine identity was recorded back then; absence is allowed.
        assert!(inst.machine.is_none());

        // Saving rewrites it in the new shape, and the legacy keys go away.
        // (Checked on the parsed object, because the handle's own endpoint
        // carries a field called `ssh_port` — nested, where it belongs.)
        shard.save().unwrap();
        let raw: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        let saved = &raw["dev"];
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

    /// A stopped pre-Handle entry has no pid, and must not grow a handle.
    #[test]
    fn a_stopped_legacy_entry_stays_stopped() {
        let path = scratch();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(
            &path,
            r#"{"dev":{"id":"6f1c","name":"dev","anchor":"laptop","status":"stopped",
                "created_at":1700000000,"volumes":[],"image":"debian:13"}}"#,
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
}
