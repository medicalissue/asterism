//! The wire between `astd` and one `astd-vz` helper.
//!
//! `VZVirtualMachine` lives and dies with the process that created it, and
//! creating one needs the `com.apple.security.virtualization` entitlement.
//! Both facts point the same way (BACKENDS.md §4): the guest belongs to a
//! small signed helper process, one per instance, and the daemon drives it
//! from outside. This module is that boundary — plain serde types with no
//! Objective-C anywhere near them, so linking it into `astd` costs the
//! daemon neither the framework nor the entitlement.
//!
//! Shape of the conversation, mirroring the QEMU backend's QMP socket:
//! one JSON [`Command`] per line in, one JSON [`Reply`] per line out, over
//! a unix socket the helper owns and whose path is recorded on the
//! [`Handle`](asterism_core::hv::Handle) as `ControlChannel::Rpc`.
//!
//! ```text
//! astd  --spawn-->  astd-vz --config vz.json   (setsid; owns the VM)
//!   |                  |
//!   |  {"cmd":"info"}  |   -> {"reply":"info", state, guest_ip, ...}
//!   |  {"cmd":"stop"}  |   -> {"reply":"stopped", reason:"guest_stopped"}
//! ```
//!
//! The helper outliving `astd` is the point, not an accident: restarting or
//! upgrading the daemon must not kill anybody's guests, so `state()` after a
//! restart is a question asked down this socket rather than anything the
//! daemon remembers.
//!
//! ## Changing this protocol
//!
//! Because a running helper outlives the daemon that spawned it, both ends
//! of this socket are routinely a version apart — most often a new `astd`
//! talking to helpers it did not build. So the wire grows by **addition
//! only**:
//!
//! * New fields are `#[serde(default)]` and skipped when empty, so a
//!   healthy `info` is byte-for-byte what it always was and an older reader
//!   ignores what it does not know.
//! * No existing variant changes meaning, and none is removed.
//! * A new [`State`] *string* is the one change that is not safe on its
//!   own: an older daemon cannot parse it, fails the whole [`Info`], and
//!   falls back to asking whether the helper's pid is alive — which answers
//!   "running" for a guest that is not. Anything an older daemon must act
//!   on is therefore said in a state it already has (see
//!   [`Info::storage_error`], which rides alongside [`State::Error`]).

use std::io::{BufRead, BufReader, Write};
use std::net::IpAddr;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

pub mod guest;

/// Name of the helper binary, as `astd` looks for it and as `codesign`
/// signs it.
pub const HELPER_BIN: &str = "astd-vz";

/// The entitlement Virtualization.framework requires to create a VM.
/// Boolean and unrestricted: an ad-hoc signature carrying it is enough
/// locally, with no Apple approval involved. NBD additionally needs
/// [`NETWORK_CLIENT_ENTITLEMENT`]. Deliberately *not*
/// `com.apple.vm.networking`, which gates bridged networking and does need
/// Apple's blessing — which is why the helper uses NAT.
pub const ENTITLEMENT: &str = "com.apple.security.virtualization";

/// Entitlement required by Virtualization.framework's NBD client.
///
/// This is a normal App Sandbox client entitlement, not the restricted
/// `com.apple.vm.networking` entitlement used by bridged guest networking.
/// The helper needs it even for `nbd+unix` because the framework classifies
/// every network-block attachment as an outgoing connection.
pub const NETWORK_CLIENT_ENTITLEMENT: &str = "com.apple.security.network.client";

/// Everything one helper needs to build and run its guest.
///
/// Written by the daemon into the instance directory as `vz.json` and read
/// back by the helper, rather than passed as a dozen flags: it is also the
/// artefact a human reads when they want to know what a running guest was
/// actually configured with.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    /// Instance name. Also the guest's hostname, which is what makes it
    /// findable in the DHCP lease file.
    pub instance: String,
    /// Raw root disk. VZ has no qcow2, ever.
    pub root: PathBuf,
    /// cloud-init NoCloud seed, attached read-only.
    pub seed: PathBuf,
    /// EFI variable store. Created by the helper on first boot, because
    /// only the framework can initialise one, and reused after.
    pub efi_vars: PathBuf,
    /// A kernel handed directly to Virtualization.framework. Present for an
    /// OCI root filesystem, which has no EFI bootloader of its own; absent
    /// for a cloud-image disk, which boots through `efi_vars` above.
    ///
    /// Additive on the daemon/helper wire: an older config has no field and
    /// therefore keeps taking the EFI path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub direct_kernel: Option<LinuxBoot>,
    /// Where the guest's serial console lands.
    pub console: PathBuf,
    /// Unix socket the helper listens on for [`Command`]s.
    pub ctl: PathBuf,
    /// Extra raw disks, in the order the guest should see them.
    #[serde(default)]
    pub extra_disks: Vec<Disk>,
    pub cpus: u32,
    pub mem_mib: u32,
    /// Pinned, because it is the fallback discovery path's only key into
    /// `/var/db/dhcpd_leases` — a random MAC means no way to guess the
    /// guest's address when the guest cannot be asked for it.
    pub mac: String,
    /// The per-instance key the guest agent is authenticated with
    /// ([`guest::Key`]), as a path rather than as the bytes: this file is
    /// written next to the guest's disk and read by whoever looks at what a
    /// running instance was configured with, and a secret does not belong
    /// in it.
    ///
    /// `None` for a guest booted by a daemon older than the agent, and for
    /// one whose seed could not carry a key. The helper then has no
    /// authenticated channel and falls back to hunting the guest on the
    /// NAT, exactly as it did before.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_key: Option<PathBuf>,
}

/// Virtualization.framework's native Linux boot-loader inputs.
///
/// This is deliberately just data. The daemon obtains and verifies the
/// kernel through the shared OCI store; the signed helper translates these
/// three paths/bytes to `VZLinuxBootLoader`. No QEMU option or device name is
/// part of the helper protocol.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinuxBoot {
    pub kernel: PathBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub initrd: Option<PathBuf>,
    pub cmdline: String,
}

/// One additional disk to put in front of the guest.
///
/// Untagged serialization deliberately keeps the original file-disk JSON
/// shape (`{"path": ..., "readonly": ...}`) readable across daemon/helper
/// upgrades. NBD variants have disjoint keys, so old configs remain
/// unambiguous while a running guest's `vz.json` stays human-readable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Disk {
    File {
        path: PathBuf,
        #[serde(default)]
        readonly: bool,
    },
    Nbd {
        url: String,
        #[serde(default)]
        readonly: bool,
    },
    NbdUnix {
        socket: PathBuf,
        export: String,
        #[serde(default)]
        readonly: bool,
    },
}

impl Config {
    pub fn read(path: &std::path::Path) -> Result<Self> {
        let bytes = std::fs::read(path)
            .with_context(|| format!("reading the vz config at {}", path.display()))?;
        serde_json::from_slice(&bytes)
            .with_context(|| format!("parsing the vz config at {}", path.display()))
    }

    pub fn write(&self, path: &std::path::Path) -> Result<()> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        std::fs::write(path, serde_json::to_vec_pretty(self)?)
            .with_context(|| format!("writing {}", path.display()))
    }
}

/// What the daemon can ask of a running helper.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum Command {
    /// Liveness, identity and the guest's address. The whole of what
    /// `Hypervisor::state` needs, and what `boot` waits on.
    Info,
    /// Ask the guest to power down (ACPI), escalate to a forced stop if it
    /// will not, then exit. Answered once the outcome is known, so the
    /// reply *is* the delegate's confirmation.
    Stop {
        /// How long the guest gets before the request is escalated.
        #[serde(default)]
        timeout_secs: Option<u64>,
    },
    /// Tear the VM down now and exit. The framework's own hard stop; the
    /// daemon's `kill()` reaches for SIGKILL instead when even this cannot
    /// be delivered.
    Kill,
    /// Ask the guest to flush its page cache, and answer when it has.
    ///
    /// A barrier, not a request: when this returns, what the guest had
    /// written is on the disk this host is holding. The one thing a
    /// hypervisor cannot do for a guest, and the reason a snapshot of a
    /// running guest's disk used to be a snapshot of whatever happened to
    /// have been flushed.
    ///
    /// Needs the guest agent. A helper with no session says so rather than
    /// answering a barrier it did not raise.
    Sync {
        #[serde(default)]
        timeout_secs: Option<u64>,
    },
}

/// One line of answer.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "reply", rename_all = "snake_case")]
pub enum Reply {
    Info(Info),
    /// The guest is down and the helper is about to exit.
    Stopped {
        reason: StopReason,
        seconds: f64,
    },
    /// The guest's `sync(2)` returned, and this is how long it took.
    Synced {
        seconds: f64,
    },
    Error {
        message: String,
    },
}

/// What the helper knows about its guest right now.
// No `Eq`: `boot_secs` is a duration in seconds, and seconds are f64.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Info {
    pub instance: String,
    /// The helper's own pid, which is the `Handle::pid` the daemon
    /// recorded. Checked on reconnect: a socket answering with a different
    /// pid is a different helper, and the handle we hold is stale.
    pub pid: u32,
    pub state: State,
    pub mac: String,
    /// Where the guest is, once that is known rather than guessed.
    ///
    /// Normally the guest's own answer, over the authenticated vsock
    /// channel ([`guest`]) — the guest is the only thing that knows this,
    /// and now it is asked. Where there is no agent to ask, it falls back
    /// to what it always was: a DHCP lease candidate proved by an ssh
    /// banner. [`Info::endpoint_via`] says which.
    #[serde(default)]
    pub guest_ip: Option<IpAddr>,
    /// How the address beside it was learned.
    ///
    /// Additive, so an older daemon reading a newer helper's `info` simply
    /// does not see it. Absent also means "a helper from before there was
    /// an agent", which is the same thing as [`Discovery::Ssh`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint_via: Option<Discovery>,
    /// The guest agent's own account of itself, while a session is open.
    ///
    /// Boxed: it is the largest thing here by some way, it is `None` on
    /// every reply that is not an `info`, and `Reply` is passed around by
    /// value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent: Option<Box<AgentInfo>>,
    /// Why there is no session, when the helper knows why.
    ///
    /// A guest with no agent at all leaves this empty and is not an error:
    /// it is an older seed, and the fallback carries it. A guest whose
    /// agent refused the handshake, or speaks a version this helper does
    /// not, says so here — that is a thing a human has to be told rather
    /// than a slow boot.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_error: Option<String>,
    /// Unix seconds when the VM was started.
    pub started_at: u64,
    /// Seconds from `startWithCompletionHandler` to the guest being found:
    /// the agent's first authenticated answer carrying an address, or the
    /// ssh banner where there is no agent.
    #[serde(default)]
    pub boot_secs: Option<f64>,
    pub console: PathBuf,
    /// Set once a disk this guest is running on has failed for good, and
    /// never unset: it is the *reason* for the [`State::Error`] reported
    /// beside it, and the helper is on its way down by the time a daemon
    /// can read it.
    ///
    /// Additive and omitted while everything is healthy, so an older daemon
    /// parses this `info` exactly as before and still reads a state that is
    /// not [live](State::is_live). A newer one can name the disk.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub storage_error: Option<StorageError>,
}

/// A disk attachment that has failed permanently.
///
/// Today this is only ever a network block device: VZ's NBD client calls
/// `attachment:didEncounterError:` when it gives up, and Apple is explicit
/// that "the NBD client will be in a non-functional state after this method
/// is invoked" — there is no reconnect after it and no way to replace the
/// attachment under a running VM. Recoverable trouble never arrives here;
/// it is retried by the framework and shows up as another
/// `attachmentWasConnected:`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageError {
    /// The attachment's URI, as the helper built it — which is what names
    /// the volume a human has to go and fix.
    pub uri: String,
    /// `localizedDescription` of the `NSError` VZ handed the delegate.
    pub message: String,
}

impl std::fmt::Display for StorageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "the disk attached from {} entered a non-recoverable state: {}",
            self.uri, self.message
        )
    }
}

/// How a guest's address came to be known.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Discovery {
    /// The guest said so, over the authenticated vsock channel. One guest
    /// at the other end of one device, and it holds this instance's key.
    Agent,
    /// A `/var/db/dhcpd_leases` candidate that answered with an ssh banner.
    /// Inference, and what this backend did before there was an agent.
    Ssh,
}

impl std::fmt::Display for Discovery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Discovery::Agent => f.write_str("the guest agent"),
            Discovery::Ssh => f.write_str("an ssh banner"),
        }
    }
}

/// The guest agent, as the helper's open session sees it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AgentInfo {
    /// The protocol version the two ends settled on.
    pub version: u32,
    /// What the agent calls itself, e.g. `asterism-guest/1`.
    #[serde(default)]
    pub agent: String,
    #[serde(default)]
    pub hostname: String,
    /// Fresh per boot, so a reconnect and a reboot are different events.
    #[serde(default)]
    pub boot_id: String,
    #[serde(default)]
    pub kernel: String,
    /// Unix seconds when this session was opened.
    pub since: u64,
    /// The last answer to `status`, which is the health of the guest as the
    /// guest sees it rather than as the framework does.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<guest::Status>,
}

/// `VZVirtualMachineState`, as far as anyone outside the helper cares.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum State {
    Starting,
    Running,
    Paused,
    Stopping,
    Stopped,
    /// Either a `VZVirtualMachineState` this helper does not know, or a
    /// guest the helper has decided is no longer healthy — today, one whose
    /// disk failed for good (see [`Info::storage_error`]). Both mean the
    /// same thing to a caller: whatever is left of this guest, it is not
    /// something to keep using.
    Error,
}

impl State {
    /// Is there still a guest to talk to? `Stopping` counts: the VM is
    /// there, it is on its way out.
    pub fn is_live(self) -> bool {
        matches!(
            self,
            State::Starting | State::Running | State::Paused | State::Stopping
        )
    }
}

/// Why the guest went away, as reported by the VZ delegate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum StopReason {
    /// `guestDidStopVirtualMachine:` — the guest powered itself off in
    /// response to the ACPI request. The clean path, and the only one
    /// `ast down` should normally take.
    GuestStopped,
    /// The guest ignored ACPI and `stopWithCompletionHandler:` took it out.
    Forced,
    /// `virtualMachine:didStopWithError:` — VZ tore the VM down itself.
    Failed { message: String },
}

impl std::fmt::Display for StopReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StopReason::GuestStopped => f.write_str("guest powered off"),
            StopReason::Forced => f.write_str("forced (guest ignored ACPI)"),
            StopReason::Failed { message } => write!(f, "failed: {message}"),
        }
    }
}

/// Send one command to a helper and read its answer.
///
/// Deliberately synchronous and short-lived: a connection per command means
/// a wedged helper can never hold a connection the daemon is reusing, and a
/// daemon that restarted has nothing to reconnect.
pub fn call(sock: &std::path::Path, command: &Command, timeout: Duration) -> Result<Reply> {
    let stream = UnixStream::connect(sock)
        .with_context(|| format!("no vz helper listening on {}", sock.display()))?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;

    let mut writer = stream.try_clone()?;
    let mut line = serde_json::to_string(command)?;
    line.push('\n');
    writer.write_all(line.as_bytes())?;
    writer.flush()?;

    let mut reply = String::new();
    BufReader::new(stream).read_line(&mut reply)?;
    if reply.trim().is_empty() {
        bail!("the vz helper closed the connection without answering");
    }
    Ok(serde_json::from_str(&reply)?)
}

/// [`call`], with an [`Reply::Error`] turned into a real error.
pub fn info(sock: &std::path::Path, timeout: Duration) -> Result<Info> {
    match call(sock, &Command::Info, timeout)? {
        Reply::Info(info) => Ok(info),
        Reply::Error { message } => bail!("{message}"),
        other => bail!("the vz helper answered info with {other:?}"),
    }
}

/// [`call`], asking the guest for a file sync barrier.
///
/// Returns how long the guest spent in `sync(2)`. An error here means the
/// barrier was *not* raised — there is no agent, or it did not answer — and
/// a caller that was about to do something to the disk must treat it as
/// such rather than carrying on.
pub fn sync(sock: &std::path::Path, timeout: Duration) -> Result<f64> {
    let asked = Command::Sync {
        timeout_secs: Some(timeout.as_secs()),
    };
    match call(sock, &asked, timeout + Duration::from_secs(5))? {
        Reply::Synced { seconds } => Ok(seconds),
        Reply::Error { message } => bail!("{message}"),
        other => bail!("the vz helper answered sync with {other:?}"),
    }
}

/// A stable, locally-administered MAC for an instance.
///
/// Derived rather than stored, so it survives losing every file but the
/// registry, and pinned rather than random because `/var/db/dhcpd_leases`
/// is the only place the guest's address is written down and the MAC is
/// how you look a record up. `52:54:00` is the QEMU-assigned OUI, which
/// keeps the two backends' guests looking alike on the wire.
pub fn mac_for(instance: &str) -> String {
    let h = fnv1a(instance);
    format!(
        "52:54:00:{:02x}:{:02x}:{:02x}",
        (h >> 16) as u8,
        (h >> 8) as u8,
        h as u8
    )
}

/// FNV-1a, spelled out for the same reason `asterism_core::instance` spells
/// it out: the value ends up in a guest's configuration, so it must not
/// drift between Rust releases.
fn fnv1a(s: &str) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for b in s.as_bytes() {
        hash ^= *b as u64;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn macs_are_stable_local_and_per_instance() {
        let mac = mac_for("dev");
        assert_eq!(mac, mac_for("dev"), "same instance, same address");
        assert_ne!(mac, mac_for("other"));
        assert!(mac.starts_with("52:54:00:"), "{mac}");
        assert_eq!(mac.len(), 17);
        // Locally administered: bit 1 of the first octet is set, so it can
        // never collide with a real card's burned-in address.
        let first = u8::from_str_radix(&mac[..2], 16).unwrap();
        assert_eq!(first & 0b10, 0b10);
        // ...and not multicast, which a guest would refuse.
        assert_eq!(first & 1, 0);
    }

    #[test]
    fn a_config_round_trips_through_the_file_the_helper_reads() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vz.json");
        let config = Config {
            instance: "dev".into(),
            root: "/i/dev/disk.raw".into(),
            seed: "/i/dev/seed.iso".into(),
            efi_vars: "/i/dev/efi-vars.bin".into(),
            console: "/i/dev/console.log".into(),
            ctl: "/i/dev/vz.sock".into(),
            extra_disks: vec![Disk::File {
                path: "/vol/data.raw".into(),
                readonly: true,
            }],
            cpus: 2,
            mem_mib: 2048,
            mac: mac_for("dev"),
            agent_key: Some("/i/dev/agent.key".into()),
        };
        config.write(&path).unwrap();
        assert_eq!(Config::read(&path).unwrap(), config);
    }

    /// An older config, written before extra disks existed, still starts a
    /// guest — the helper and the daemon are separate binaries and a
    /// running helper's config file outlives the daemon that wrote it.
    #[test]
    fn a_config_without_extra_disks_still_parses() {
        let json = r#"{"instance":"dev","root":"/d.raw","seed":"/s.iso",
            "efi_vars":"/e.bin","console":"/c.log","ctl":"/v.sock",
            "cpus":1,"mem_mib":512,"mac":"52:54:00:aa:bb:cc"}"#;
        let config: Config = serde_json::from_str(json).unwrap();
        assert!(config.extra_disks.is_empty());
    }

    #[test]
    fn old_file_disks_and_new_nbd_transports_round_trip() {
        let old: Disk =
            serde_json::from_str(r#"{"path":"/vol/data.raw","readonly":true}"#).unwrap();
        assert_eq!(
            old,
            Disk::File {
                path: "/vol/data.raw".into(),
                readonly: true
            }
        );
        assert_eq!(
            serde_json::to_string(&old).unwrap(),
            r#"{"path":"/vol/data.raw","readonly":true}"#
        );

        let unix = Disk::NbdUnix {
            socket: "/tmp/asterism volume.sock".into(),
            export: "team/working set".into(),
            readonly: false,
        };
        let json = serde_json::to_string(&unix).unwrap();
        assert!(
            json.contains(r#""socket":"/tmp/asterism volume.sock""#),
            "{json}"
        );
        assert!(json.contains(r#""export":"team/working set""#), "{json}");
        assert_eq!(serde_json::from_str::<Disk>(&json).unwrap(), unix);

        let tcp = Disk::Nbd {
            url: "nbd://storage:10809/data".into(),
            readonly: true,
        };
        assert_eq!(
            serde_json::from_str::<Disk>(&serde_json::to_string(&tcp).unwrap()).unwrap(),
            tcp
        );
    }

    #[test]
    fn the_wire_is_one_json_object_per_line() {
        let cmd = serde_json::to_string(&Command::Stop {
            timeout_secs: Some(30),
        })
        .unwrap();
        assert_eq!(cmd, r#"{"cmd":"stop","timeout_secs":30}"#);
        assert!(!cmd.contains('\n'));
        assert_eq!(
            serde_json::from_str::<Command>(r#"{"cmd":"info"}"#).unwrap(),
            Command::Info
        );
        // `stop` with no timeout is legal: the helper has a default.
        assert_eq!(
            serde_json::from_str::<Command>(r#"{"cmd":"stop"}"#).unwrap(),
            Command::Stop { timeout_secs: None }
        );

        let reply = serde_json::to_string(&Reply::Stopped {
            reason: StopReason::GuestStopped,
            seconds: 3.5,
        })
        .unwrap();
        assert_eq!(
            reply,
            r#"{"reply":"stopped","reason":{"kind":"guest_stopped"},"seconds":3.5}"#
        );

        // The barrier, both ways. A helper old enough not to know `sync`
        // answers a `Reply::Error` rather than failing to parse the line,
        // which is what makes asking one safe.
        assert_eq!(
            serde_json::to_string(&Command::Sync {
                timeout_secs: Some(20)
            })
            .unwrap(),
            r#"{"cmd":"sync","timeout_secs":20}"#
        );
        assert_eq!(
            serde_json::from_str::<Command>(r#"{"cmd":"sync"}"#).unwrap(),
            Command::Sync { timeout_secs: None }
        );
        assert_eq!(
            serde_json::to_string(&Reply::Synced { seconds: 0.125 }).unwrap(),
            r#"{"reply":"synced","seconds":0.125}"#
        );
    }

    /// The shape every reader of this protocol depends on, in both
    /// directions at once: a healthy `info` is exactly the JSON it has
    /// always been, and a helper that has lost a disk says so in a state an
    /// older daemon already understands.
    #[test]
    fn a_lost_disk_is_additive_json_an_older_daemon_still_reads_as_not_running() {
        /// `Info` as it was before `storage_error` existed. Serde ignores
        /// unknown fields, so this is what an older `astd` sees.
        #[derive(Deserialize)]
        struct OldInfo {
            state: State,
        }

        let mut info = Info {
            instance: "dev".into(),
            pid: 4242,
            state: State::Running,
            mac: mac_for("dev"),
            guest_ip: Some("192.168.64.7".parse().unwrap()),
            endpoint_via: None,
            agent: None,
            agent_error: None,
            started_at: 1_700_000_000,
            boot_secs: Some(4.25),
            console: "/i/dev/console.log".into(),
            storage_error: None,
        };

        // Healthy: not one byte more on the wire than before the field.
        let healthy = serde_json::to_string(&Reply::Info(info.clone())).unwrap();
        assert!(!healthy.contains("storage_error"), "{healthy}");
        assert_eq!(
            serde_json::from_str::<OldInfo>(&serde_json::to_string(&info).unwrap())
                .unwrap()
                .state,
            State::Running
        );

        // Failed: the detail is new, the state is not.
        info.state = State::Error;
        info.storage_error = Some(StorageError {
            uri: "nbd+unix:///team%2Fdata?socket=%2Ftmp%2Fv.sock".into(),
            message: "Connection reset by peer".into(),
        });
        let json = serde_json::to_string(&info).unwrap();
        assert_eq!(serde_json::from_str::<Info>(&json).unwrap(), info);
        let old = serde_json::from_str::<OldInfo>(&json).unwrap();
        assert_eq!(old.state, State::Error);
        assert!(
            !old.state.is_live(),
            "a daemon that never heard of storage_error must still not call this running"
        );
    }

    /// An `info` from a helper built before this field still parses, which
    /// is the direction that actually happens: helpers outlive the daemon
    /// that spawned them, so a new `astd` reads old JSON every upgrade.
    #[test]
    fn an_info_from_an_older_helper_still_parses() {
        let json = r#"{"instance":"dev","pid":9,"state":"running","mac":"52:54:00:aa:bb:cc",
            "guest_ip":null,"started_at":1,"boot_secs":null,"console":"/c.log"}"#;
        let info: Info = serde_json::from_str(json).unwrap();
        assert!(info.storage_error.is_none());
        assert!(info.state.is_live());
    }

    #[test]
    fn a_storage_error_names_the_volume_and_what_went_wrong() {
        let said = StorageError {
            uri: "nbd://desktop:10809/vol".into(),
            message: "The operation couldn\u{2019}t be completed.".into(),
        }
        .to_string();
        assert!(said.contains("nbd://desktop:10809/vol"), "{said}");
        assert!(said.contains("non-recoverable"), "{said}");
    }

    #[test]
    fn only_a_live_state_means_there_is_still_a_guest() {
        assert!(State::Running.is_live());
        assert!(State::Starting.is_live());
        assert!(State::Stopping.is_live(), "on its way out is still there");
        assert!(!State::Stopped.is_live());
        assert!(
            !State::Error.is_live(),
            "and a guest whose disk went is not one to keep running on"
        );
    }

    #[test]
    fn stop_reasons_read_like_sentences() {
        assert_eq!(StopReason::GuestStopped.to_string(), "guest powered off");
        assert!(StopReason::Forced.to_string().contains("ACPI"));
        assert_eq!(
            StopReason::Failed {
                message: "no disk".into()
            }
            .to_string(),
            "failed: no disk"
        );
    }

    #[test]
    fn calling_a_socket_nobody_is_listening_on_says_so() {
        let dir = tempfile::tempdir().unwrap();
        let err = call(
            &dir.path().join("absent.sock"),
            &Command::Info,
            Duration::from_millis(50),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("no vz helper listening"), "{err}");
    }
}
