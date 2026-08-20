//! The orbit: the set of devices this one trusts.
//!
//! An **orbit** is Asterism's device group — Tailscale calls the same idea a
//! tailnet. Membership is a set of Ed25519 public keys, one per device, and it
//! is established by pairing (see `asterism-mesh`), never by a server. This
//! module is the on-disk half of that: `$ASTERISM_HOME/orbit.json`, holding
//! each peer's name, its device id, the addresses it was last reachable on,
//! and when it joined.
//!
//! Two properties matter and are the reason this is a store rather than a
//! cache:
//!
//! * **It is the access-control list.** `astd` serves a mesh connection only if
//!   the peer key that QUIC authenticated appears here. A device removed from
//!   the file is a stranger on its next connection.
//! * **It survives every service being down.** Names, keys and address hints
//!   are all local, so an orbit on a LAN with no coordinator, no relay and no
//!   internet is a fully working orbit.
//!
//! Device *names* are first-class addressing — `ast --device desktop ls` — so
//! the store refuses two devices with the same name, and refuses a peer that
//! wants to be called what this device is already called.
//!
//! The file carries no key material. A device id is a public key; the secret
//! half lives in `id_device`, alone, at mode 0600.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::instance::{local_host, now_unix};

/// Format version of `orbit.json`, so a later shape is distinguishable
/// rather than silently misread.
pub const ORBIT_VERSION: u32 = 1;

/// One peer device in this orbit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Device {
    /// What the user calls it: `ast --device <name> ...`.
    pub name: String,
    /// The peer's Ed25519 public key, hex. This is the identity; the name is
    /// only a label for it.
    pub device_id: String,
    /// Socket addresses the peer was last known to answer on. Hints only —
    /// a peer that has moved is found by discovery, or not at all.
    #[serde(default)]
    pub addrs: Vec<String>,
    /// Relay URLs the peer advertised, for the paths that need one.
    #[serde(default)]
    pub relays: Vec<String>,
    /// When [`addrs`](Self::addrs) and [`relays`](Self::relays) were last
    /// confirmed, Unix seconds. Zero for a record written before this field
    /// existed, or one that has not been confirmed since pairing.
    ///
    /// Address hints go stale silently — a daemon restarts on a new port, a
    /// laptop moves to another network — and the whole failure mode of a
    /// stored address is that it looks exactly as good on disk the day it
    /// stops working. The timestamp is what lets a dial say "this hint is
    /// three weeks old, ask discovery instead" rather than believing it.
    #[serde(default)]
    pub addrs_seen_at: u64,
    /// When it was paired, Unix seconds.
    pub added_at: u64,
    /// What this peer told us about its place on an L2 network, so that some
    /// device sharing that network can wake it. Recorded at pairing and
    /// refreshed whenever the peer is reachable; absent for a peer paired by
    /// an `astd` too old to have said.
    #[serde(default)]
    pub wake: WakeFacts,
}

impl Device {
    /// The short, human-quotable form of the device id.
    pub fn short_id(&self) -> String {
        self.device_id.chars().take(12).collect()
    }
}

/// Where a device sits on the wire: enough to send it a Wake-on-LAN magic
/// packet, and enough to tell whether some *other* device could.
///
/// Both fields are the device's own report about itself. They are stored on
/// the peers' records rather than fetched on demand precisely because the
/// interesting moment — the device is asleep — is the moment it cannot answer
/// a question.
///
/// Every field is optional and defaulted. A record written before this
/// existed loads as [`WakeFacts::default`], which reads as "we do not know",
/// which is exactly right.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WakeFacts {
    /// The MAC of the interface carrying this device's default route, as
    /// lowercase colon-separated hex. This is the address a magic packet is
    /// built from, so it is the address the NIC actually uses on the wire —
    /// not the burned-in one, when a platform has substituted a private MAC.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mac: Option<String>,
    /// A fingerprint of the broadcast domain that interface is on. Two
    /// devices with equal `lan_id` can reach each other with a broadcast;
    /// that is the whole meaning of the field. See [`lan_fingerprint`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lan_id: Option<String>,
    /// The interface those two came from, for `ast device check` to name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iface: Option<String>,
    /// When the device last reported them, Unix seconds. A device that moved
    /// networks and has not been seen since is reporting a stale LAN, and the
    /// timestamp is the only warning of that we can give.
    #[serde(default)]
    pub seen_at: u64,
}

impl WakeFacts {
    /// Whether anything is known at all.
    pub fn is_empty(&self) -> bool {
        self.mac.is_none() && self.lan_id.is_none()
    }

    /// The pair a wake needs: a MAC to aim at and a network to aim it on.
    pub fn wakeable(&self) -> Option<(&str, &str)> {
        Some((self.mac.as_deref()?, self.lan_id.as_deref()?))
    }

    /// Whether this device shares a broadcast domain with `other`.
    ///
    /// Unknown is never a match. A device that cannot say where it is must
    /// not be volunteered as somebody's wake proxy: broadcasting on the wrong
    /// LAN is silent, and silence is what we are trying to stop reporting as
    /// success.
    pub fn shares_lan_with(&self, other: &WakeFacts) -> bool {
        match (&self.lan_id, &other.lan_id) {
            (Some(a), Some(b)) => a == b,
            _ => false,
        }
    }
}

/// Fingerprints the L2 network an interface is attached to.
///
/// The inputs are the **default gateway's MAC** and the **subnet in CIDR
/// form**, and both choices are about surviving a DHCP lease:
///
/// * The gateway's MAC identifies the router itself. Every device on the
///   broadcast domain resolves the same one, and unlike an IP it does not
///   change when a lease is renewed, when the ISP re-delegates a prefix, or
///   when the router is rebooted.
/// * The subnet is the *network* address and prefix — derived from the
///   address and netmask, never the host part — so a device whose own address
///   moves from .55 to .77 fingerprints the same LAN. It is there to separate
///   two VLANs behind one router, which really are different broadcast
///   domains even though they share a gateway MAC.
///
/// Deliberately *not* inputs: this device's own IP or hostname (a lease, not
/// a network), the DHCP server id (often the same box, sometimes not, and it
/// is not asked when a lease is static), the SSID, and the BSSID. The last
/// two are the tempting ones and both are wrong: a roaming client changes
/// BSSID while staying on one bridged L2, and a wired and a wireless client
/// on the same router share a broadcast domain but no SSID at all.
///
/// With no gateway MAC to be had — no default route, or an ARP cache that has
/// not resolved it — the fingerprint falls back to the subnet alone and says
/// so in its prefix, because a `net-` id is genuinely weaker: two houses both
/// on `192.168.1.0/24` share it. The cost of that collision is a magic packet
/// broadcast on a friend's LAN where nothing answers to the MAC — noise, not
/// harm — and the wake then honestly reports that the device did not come
/// online.
///
/// The hash is FNV-1a, not a cryptographic one, and that is a considered
/// choice rather than a shortcut: this is an equality token compared between
/// devices that have already pairwise authenticated, and its inputs are
/// visible to anyone standing on the LAN anyway. Nothing is authorized by
/// knowing a `lan_id`.
pub fn lan_fingerprint(gateway_mac: Option<&str>, subnet: Option<&str>) -> Option<String> {
    match (gateway_mac, subnet) {
        (Some(gw), subnet) => {
            let gw = parse_mac(gw)?;
            let mut h = Fnv::new();
            h.write(b"asterism-lan-v1\0");
            h.write(&gw);
            h.write(b"\0");
            h.write(subnet.unwrap_or("").as_bytes());
            Some(format!("lan-{:016x}", h.finish()))
        }
        (None, Some(subnet)) => {
            let mut h = Fnv::new();
            h.write(b"asterism-net-v1\0");
            h.write(subnet.as_bytes());
            Some(format!("net-{:016x}", h.finish()))
        }
        (None, None) => None,
    }
}

/// FNV-1a, 64-bit. Small enough to keep here rather than take a dependency
/// for, and adequate for what a `lan_id` is: see [`lan_fingerprint`].
struct Fnv(u64);

impl Fnv {
    fn new() -> Self {
        Self(0xcbf2_9ce4_8422_2325)
    }
    fn write(&mut self, bytes: &[u8]) {
        for b in bytes {
            self.0 ^= u64::from(*b);
            self.0 = self.0.wrapping_mul(0x0000_0100_0000_01b3);
        }
    }
    fn finish(&self) -> u64 {
        self.0
    }
}

/// Parses a MAC written any of the ways the platforms write one:
/// `aa:bb:cc:dd:ee:ff`, `AA-BB-CC-DD-EE-FF`, or `aabbccddeeff`.
///
/// Returning the six bytes rather than a tidied string is the point — a magic
/// packet is sixteen copies of exactly these, so anything that cannot be
/// turned into six bytes is not a MAC we can wake and is refused here rather
/// than sent as noise.
pub fn parse_mac(mac: &str) -> Option<[u8; 6]> {
    let hex: String = mac
        .chars()
        .filter(|c| !matches!(c, ':' | '-' | '.' | ' '))
        .collect();
    if hex.len() != 12 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; 6];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

/// The canonical way Asterism writes a MAC down: lowercase, colon-separated.
pub fn format_mac(mac: [u8; 6]) -> String {
    mac.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// One row of `ast devices`.
///
/// Deliberately separate from [`Device`]: this is what the daemon *observed*
/// just now — liveness and path — folded onto what it has stored. It also
/// carries this device itself, which is never a member of its own store.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceStatus {
    /// The device's name.
    pub name: String,
    /// Its device id, hex.
    pub device_id: String,
    /// Whether its daemon answered a mesh ping just now. Always true for self.
    pub online: bool,
    /// How traffic reaches it: `direct`, `relay`, or `-` when it does not.
    pub path: String,
    /// Whether this row is the device the command ran on.
    #[serde(default)]
    pub is_self: bool,
}

impl DeviceStatus {
    /// The short, human-quotable form of the device id.
    pub fn short_id(&self) -> String {
        self.device_id.chars().take(12).collect()
    }
}

/// The orbit store, persisted as JSON at `path`.
///
/// Writes go through a temp file + rename, the same way the instance registry
/// does: a crash mid-save must never leave a device set that is half a set.
#[derive(Debug)]
pub struct Orbit {
    path: PathBuf,
    self_name: String,
    devices: Vec<Device>,
}

/// What actually goes in the file.
#[derive(Debug, Serialize, Deserialize)]
struct OrbitFile {
    version: u32,
    /// What this device calls itself to its peers.
    self_name: String,
    #[serde(default)]
    devices: Vec<Device>,
}

impl Orbit {
    /// Loads the store, or starts an empty one named after this host.
    pub fn load(path: &Path) -> Result<Self> {
        let file: OrbitFile = match std::fs::read(path) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .with_context(|| format!("corrupt orbit store at {}", path.display()))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => OrbitFile {
                version: ORBIT_VERSION,
                self_name: local_host(),
                devices: Vec::new(),
            },
            Err(e) => return Err(e).context("reading the orbit store"),
        };
        if file.version != ORBIT_VERSION {
            bail!(
                "{} is orbit format {}, but this build speaks {ORBIT_VERSION}",
                path.display(),
                file.version
            );
        }
        Ok(Self {
            path: path.to_owned(),
            self_name: file.self_name,
            devices: file.devices,
        })
    }

    /// Persists the store.
    pub fn save(&self) -> Result<()> {
        if let Some(dir) = self.path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let file = OrbitFile {
            version: ORBIT_VERSION,
            self_name: self.self_name.clone(),
            devices: self.devices.clone(),
        };
        let tmp = self.path.with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(&file)?)?;
        std::fs::rename(&tmp, &self.path).context("committing the orbit store")?;
        Ok(())
    }

    /// What this device calls itself.
    pub fn self_name(&self) -> &str {
        &self.self_name
    }

    /// Renames this device.
    ///
    /// Refused if a peer already answers to that name — two devices called
    /// `laptop` would make `ast --device laptop` a coin toss.
    pub fn set_self_name(&mut self, name: &str) -> Result<()> {
        check_name(name)?;
        if let Some(existing) = self.get(name) {
            bail!(
                "this orbit already has a device named {name:?} ({})",
                existing.short_id()
            );
        }
        self.self_name = name.to_owned();
        Ok(())
    }

    /// Every peer, in the order they were added.
    pub fn devices(&self) -> &[Device] {
        &self.devices
    }

    /// The peer with this name.
    pub fn get(&self, name: &str) -> Option<&Device> {
        self.devices.iter().find(|d| d.name == name)
    }

    /// The peer with this device id.
    pub fn by_id(&self, device_id: &str) -> Option<&Device> {
        self.devices.iter().find(|d| d.device_id == device_id)
    }

    /// Whether this device id is a member — the whole authorization check.
    pub fn trusts(&self, device_id: &str) -> bool {
        self.by_id(device_id).is_some()
    }

    /// Adds a paired peer, or refreshes the addresses of one already known.
    ///
    /// Re-pairing a device that is already in the orbit is not an error: it is
    /// how a device that moved networks gets fresh address hints. Its key is
    /// what identifies it, so the name follows the key, not the other way
    /// round.
    pub fn add(&mut self, device: Device) -> Result<()> {
        check_name(&device.name)?;
        if device.name == self.self_name {
            bail!(
                "the other device calls itself {:?}, which is this device's own name \
                 — rename one of them (ast device add --name)",
                device.name
            );
        }
        if let Some(clash) = self
            .devices
            .iter()
            .find(|d| d.name == device.name && d.device_id != device.device_id)
        {
            bail!(
                "this orbit already has a device named {:?} ({}) — rename one of them \
                 (ast device add --name)",
                device.name,
                clash.short_id()
            );
        }
        match self
            .devices
            .iter_mut()
            .find(|d| d.device_id == device.device_id)
        {
            Some(existing) => {
                existing.name = device.name;
                existing.addrs = device.addrs;
                existing.relays = device.relays;
                existing.addrs_seen_at = device.addrs_seen_at;
                // A re-pair that said nothing about the peer's LAN must not
                // erase what we already knew: silence is not news.
                if !device.wake.is_empty() {
                    existing.wake = device.wake;
                }
            }
            None => self.devices.push(device),
        }
        Ok(())
    }

    /// Removes a peer by name, returning it.
    pub fn remove(&mut self, name: &str) -> Result<Device> {
        let Some(i) = self.devices.iter().position(|d| d.name == name) else {
            bail!("no device named {name:?} in this orbit — see: ast devices");
        };
        Ok(self.devices.remove(i))
    }

    /// Records what a peer just said about its own place on the wire.
    ///
    /// Returns whether anything changed, so a caller refreshing every peer at
    /// once can save the store once, or not at all. Empty facts are ignored
    /// for the same reason [`Orbit::add`] ignores them: a peer that cannot
    /// answer the question has not answered it "no".
    pub fn set_wake(&mut self, device_id: &str, wake: WakeFacts) -> bool {
        if wake.is_empty() {
            return false;
        }
        match self.devices.iter_mut().find(|d| d.device_id == device_id) {
            Some(d) if d.wake == wake => false,
            Some(d) => {
                d.wake = wake;
                true
            }
            None => false,
        }
    }

    /// Every peer that says it shares a broadcast domain with `wake`.
    ///
    /// The candidates for relaying a magic packet, before liveness is
    /// considered — which it must be, since the whole point is a device that
    /// is *awake* on the sleeper's LAN.
    pub fn on_lan_with(&self, wake: &WakeFacts) -> Vec<&Device> {
        self.devices
            .iter()
            .filter(|d| d.wake.shares_lan_with(wake))
            .collect()
    }

    /// Records fresh address hints for a peer that just connected, stamped
    /// with the moment they were confirmed.
    ///
    /// Returns whether anything changed, so a caller refreshing several peers
    /// can write the store once. Called after every successful dial: the
    /// addresses a connection actually worked over are the best hints in
    /// existence, and writing them down is what stops the store from decaying
    /// into a list of places a peer used to be.
    ///
    /// Empty `addrs` are ignored — a peer reachable only through a relay has
    /// told us nothing new about its IP addresses and erasing the old ones
    /// would throw away a working LAN shortcut — but the timestamp still moves,
    /// because the record as a whole was just confirmed.
    pub fn refresh_addrs(
        &mut self,
        device_id: &str,
        addrs: Vec<String>,
        relays: Vec<String>,
        seen_at: u64,
    ) -> bool {
        let Some(d) = self.devices.iter_mut().find(|d| d.device_id == device_id) else {
            return false;
        };
        let mut changed = false;
        if !addrs.is_empty() && d.addrs != addrs {
            d.addrs = addrs;
            changed = true;
        }
        if d.relays != relays {
            d.relays = relays;
            changed = true;
        }
        if d.addrs_seen_at != seen_at {
            d.addrs_seen_at = seen_at;
            changed = true;
        }
        changed
    }
}

/// Builds a peer record with `added_at` set to now.
///
/// The addresses come from the pairing exchange, so they were confirmed at the
/// same moment: `addrs_seen_at` starts equal to `added_at` rather than at zero.
pub fn device_now(name: &str, device_id: &str, addrs: Vec<String>, relays: Vec<String>) -> Device {
    let now = now_unix();
    Device {
        name: name.to_owned(),
        device_id: device_id.to_owned(),
        addrs,
        relays,
        addrs_seen_at: now,
        added_at: now,
        wake: WakeFacts::default(),
    }
}

/// A device name has to survive being typed on a command line and compared
/// by eye, so it is held to the same shape a hostname is.
pub fn check_name(name: &str) -> Result<()> {
    if name.is_empty() {
        bail!("a device name cannot be empty");
    }
    if name.len() > 63 {
        bail!("device name {name:?} is longer than 63 characters");
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
    {
        bail!("device name {name:?} may only contain letters, digits, '-', '_' and '.'");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn orbit(dir: &Path) -> Orbit {
        let mut o = Orbit::load(&dir.join("orbit.json")).unwrap();
        o.set_self_name("here").unwrap();
        o
    }

    fn peer(name: &str, id: &str) -> Device {
        device_now(name, id, vec!["127.0.0.1:1".into()], vec![])
    }

    #[test]
    fn a_missing_store_is_an_empty_orbit_named_after_this_host() {
        let dir = tempfile::tempdir().unwrap();
        let o = Orbit::load(&dir.path().join("orbit.json")).unwrap();
        assert!(o.devices().is_empty());
        assert_eq!(o.self_name(), local_host());
    }

    #[test]
    fn devices_round_trip_through_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let mut o = orbit(dir.path());
        o.add(peer("desktop", "aa")).unwrap();
        o.save().unwrap();

        let reloaded = Orbit::load(&dir.path().join("orbit.json")).unwrap();
        assert_eq!(reloaded.self_name(), "here");
        assert_eq!(reloaded.devices(), o.devices());
        assert!(reloaded.trusts("aa"));
        assert!(!reloaded.trusts("bb"));
    }

    #[test]
    fn two_devices_cannot_share_a_name() {
        let dir = tempfile::tempdir().unwrap();
        let mut o = orbit(dir.path());
        o.add(peer("desktop", "aa")).unwrap();

        let err = o.add(peer("desktop", "bb")).unwrap_err().to_string();
        assert!(err.contains("already has a device named"), "{err}");
        assert_eq!(o.devices().len(), 1);
    }

    #[test]
    fn a_peer_cannot_take_this_devices_own_name() {
        let dir = tempfile::tempdir().unwrap();
        let mut o = orbit(dir.path());
        let err = o.add(peer("here", "aa")).unwrap_err().to_string();
        assert!(err.contains("this device's own name"), "{err}");
    }

    #[test]
    fn re_pairing_the_same_key_refreshes_it_rather_than_duplicating_it() {
        let dir = tempfile::tempdir().unwrap();
        let mut o = orbit(dir.path());
        o.add(peer("desktop", "aa")).unwrap();
        o.add(device_now("desk", "aa", vec!["127.0.0.1:2".into()], vec![]))
            .unwrap();

        assert_eq!(o.devices().len(), 1, "one key is one device");
        assert_eq!(o.devices()[0].name, "desk");
        assert_eq!(o.devices()[0].addrs, ["127.0.0.1:2"]);
    }

    #[test]
    fn removing_a_device_makes_it_a_stranger_again() {
        let dir = tempfile::tempdir().unwrap();
        let mut o = orbit(dir.path());
        o.add(peer("desktop", "aa")).unwrap();
        assert!(o.trusts("aa"));

        assert_eq!(o.remove("desktop").unwrap().device_id, "aa");
        assert!(!o.trusts("aa"), "a removed key must not still be trusted");
        assert!(o.remove("desktop").unwrap_err().to_string().contains("no device named"));
    }

    #[test]
    fn names_that_would_be_awkward_to_type_are_refused() {
        assert!(check_name("desktop-1").is_ok());
        assert!(check_name("").is_err());
        assert!(check_name("my laptop").is_err());
        assert!(check_name("rm -rf /").is_err());
    }

    // ---- wake facts --------------------------------------------------------

    fn facts(lan: &str, mac: &str) -> WakeFacts {
        WakeFacts {
            mac: Some(mac.into()),
            lan_id: Some(lan.into()),
            iface: Some("en0".into()),
            seen_at: 1,
        }
    }

    /// The back-compat bar: an orbit.json written before wake existed has to
    /// load, and load as "we do not know" rather than as a wrong answer.
    #[test]
    fn a_store_written_before_wake_existed_still_loads() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("orbit.json");
        std::fs::write(
            &path,
            r#"{"version":1,"self_name":"here","devices":[
                 {"name":"desktop","device_id":"aa","addrs":[],"relays":[],"added_at":7}]}"#,
        )
        .unwrap();
        let o = Orbit::load(&path).unwrap();
        let d = o.get("desktop").unwrap();
        assert!(d.wake.is_empty());
        assert_eq!(d.wake.wakeable(), None);
        // Nobody has confirmed those addresses, and the store says so rather
        // than inventing a time.
        assert_eq!(d.addrs_seen_at, 0);
    }

    #[test]
    fn a_confirmed_address_is_recorded_with_the_moment_it_was_confirmed() {
        let dir = tempfile::tempdir().unwrap();
        let mut o = orbit(dir.path());
        o.add(peer("desktop", "aa")).unwrap();

        assert!(o.refresh_addrs("aa", vec!["10.0.0.4:41641".into()], vec![], 1_700));
        let d = o.get("desktop").unwrap();
        assert_eq!(d.addrs, ["10.0.0.4:41641"]);
        assert_eq!(d.addrs_seen_at, 1_700);

        // The same answer at a later moment is still news: the hint has been
        // reconfirmed, which is the whole point of the timestamp.
        assert!(o.refresh_addrs("aa", vec!["10.0.0.4:41641".into()], vec![], 1_900));
        assert_eq!(o.get("desktop").unwrap().addrs_seen_at, 1_900);
        assert!(!o.refresh_addrs("aa", vec!["10.0.0.4:41641".into()], vec![], 1_900));

        // A peer reached only over a relay says nothing about its IPs, so the
        // working ones survive while the relay hint and the clock move.
        assert!(o.refresh_addrs("aa", vec![], vec!["https://relay.example./".into()], 2_000));
        let d = o.get("desktop").unwrap();
        assert_eq!(d.addrs, ["10.0.0.4:41641"], "a relay is not evidence of no IP");
        assert_eq!(d.relays, ["https://relay.example./"]);
        assert_eq!(d.addrs_seen_at, 2_000);

        assert!(!o.refresh_addrs("bb", vec!["1.2.3.4:5".into()], vec![], 9), "unknown peer");
    }

    #[test]
    fn wake_facts_round_trip_and_refresh_in_place() {
        let dir = tempfile::tempdir().unwrap();
        let mut o = orbit(dir.path());
        o.add(peer("desktop", "aa")).unwrap();
        assert!(o.set_wake("aa", facts("lan-1", "de:ad:be:ef:00:01")));
        // The same facts twice is not a change, so nothing needs saving.
        assert!(!o.set_wake("aa", facts("lan-1", "de:ad:be:ef:00:01")));
        assert!(!o.set_wake("bb", facts("lan-1", "de:ad:be:ef:00:02")), "unknown peer");
        o.save().unwrap();

        let reloaded = Orbit::load(&dir.path().join("orbit.json")).unwrap();
        assert_eq!(
            reloaded.get("desktop").unwrap().wake.wakeable(),
            Some(("de:ad:be:ef:00:01", "lan-1"))
        );
    }

    /// Re-pairing is how a device that moved networks gets fresh hints, but a
    /// peer that says nothing about its LAN must not blank what we had.
    #[test]
    fn re_pairing_without_wake_facts_does_not_erase_them() {
        let dir = tempfile::tempdir().unwrap();
        let mut o = orbit(dir.path());
        o.add(peer("desktop", "aa")).unwrap();
        o.set_wake("aa", facts("lan-1", "de:ad:be:ef:00:01"));

        o.add(peer("desktop", "aa")).unwrap();
        assert_eq!(o.get("desktop").unwrap().wake.lan_id.as_deref(), Some("lan-1"));

        let mut moved = peer("desktop", "aa");
        moved.wake = facts("lan-2", "de:ad:be:ef:00:01");
        o.add(moved).unwrap();
        assert_eq!(o.get("desktop").unwrap().wake.lan_id.as_deref(), Some("lan-2"));
    }

    /// The question `ast device wake` actually asks: who is on the sleeper's
    /// network? An unknown LAN is never an answer to it.
    #[test]
    fn only_a_matching_known_lan_id_counts_as_sharing_a_network() {
        let dir = tempfile::tempdir().unwrap();
        let mut o = orbit(dir.path());
        for (name, id, lan) in [("a", "aa", "lan-1"), ("b", "bb", "lan-2"), ("c", "cc", "lan-1")] {
            o.add(peer(name, id)).unwrap();
            o.set_wake(id, facts(lan, "de:ad:be:ef:00:01"));
        }
        o.add(peer("d", "dd")).unwrap(); // never said

        let target = facts("lan-1", "de:ad:be:ef:00:09");
        let on_lan: Vec<&str> = o.on_lan_with(&target).iter().map(|d| d.name.as_str()).collect();
        assert_eq!(on_lan, ["a", "c"]);

        assert!(!WakeFacts::default().shares_lan_with(&target));
        assert!(!WakeFacts::default().shares_lan_with(&WakeFacts::default()));
    }

    /// The DHCP property the whole design turns on: the fingerprint is made
    /// of the router and the network, never of this device's lease.
    #[test]
    fn a_lan_id_survives_a_new_lease_and_separates_real_networks() {
        let home = lan_fingerprint(Some("58:86:94:ac:56:d0"), Some("192.168.0.0/24"));
        // Same router, same subnet, different host address — the host address
        // was never an input, so this is the same LAN.
        assert_eq!(home, lan_fingerprint(Some("58-86-94-AC-56-D0"), Some("192.168.0.0/24")));
        // Same router, second VLAN: a different broadcast domain, and a
        // broadcast on one does not reach the other.
        assert_ne!(home, lan_fingerprint(Some("58:86:94:ac:56:d0"), Some("192.168.9.0/24")));
        // Different router, identical subnet numbers — the common case for
        // two houses, and the one a subnet-only id would get wrong.
        assert_ne!(home, lan_fingerprint(Some("00:11:22:33:44:55"), Some("192.168.0.0/24")));

        // With no gateway MAC the id is honestly weaker, and says so.
        let weak = lan_fingerprint(None, Some("192.168.0.0/24")).unwrap();
        assert!(weak.starts_with("net-"), "{weak}");
        assert!(home.unwrap().starts_with("lan-"));
        // Knowing nothing produces nothing, rather than a constant that would
        // make every unlocatable device look like a neighbour.
        assert_eq!(lan_fingerprint(None, None), None);
        assert_eq!(lan_fingerprint(Some("not-a-mac"), Some("192.168.0.0/24")), None);
    }

    #[test]
    fn a_mac_is_accepted_however_the_platform_spells_it() {
        let want = [0xde, 0xad, 0xbe, 0xef, 0x00, 0x01];
        for spelling in ["de:ad:be:ef:00:01", "DE-AD-BE-EF-00-01", "deadbeef0001"] {
            assert_eq!(parse_mac(spelling), Some(want), "{spelling}");
        }
        assert_eq!(format_mac(want), "de:ad:be:ef:00:01");
        for junk in ["", "de:ad:be:ef:00", "de:ad:be:ef:00:01:02", "zz:ad:be:ef:00:01"] {
            assert_eq!(parse_mac(junk), None, "{junk}");
        }
    }

    #[test]
    fn a_future_format_version_is_refused_rather_than_misread() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("orbit.json");
        std::fs::write(&path, r#"{"version":99,"self_name":"x","devices":[]}"#).unwrap();
        let err = Orbit::load(&path).unwrap_err().to_string();
        assert!(err.contains("orbit format 99"), "{err}");
    }
}
