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

use std::io::{BufRead, BufReader, Write};
use std::net::IpAddr;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

/// Name of the helper binary, as `astd` looks for it and as `codesign`
/// signs it.
pub const HELPER_BIN: &str = "astd-vz";

/// The one entitlement Virtualization.framework requires. Boolean and
/// unrestricted: an ad-hoc signature carrying it is enough locally, no
/// Apple approval involved. Deliberately *not* `com.apple.vm.networking`,
/// which gates bridged networking and does need Apple's blessing — which is
/// why the helper uses NAT.
pub const ENTITLEMENT: &str = "com.apple.security.virtualization";

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
    /// Where the guest's serial console lands.
    pub console: PathBuf,
    /// Unix socket the helper listens on for [`Command`]s.
    pub ctl: PathBuf,
    /// Extra raw disks, in the order the guest should see them.
    #[serde(default)]
    pub extra_disks: Vec<Disk>,
    pub cpus: u32,
    pub mem_mib: u32,
    /// Pinned, because it is the only key into `/var/db/dhcpd_leases` — a
    /// random MAC means no way to learn the guest's address at all.
    pub mac: String,
}

/// One additional disk to put in front of the guest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Disk {
    pub path: PathBuf,
    #[serde(default)]
    pub readonly: bool,
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
}

/// One line of answer.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "reply", rename_all = "snake_case")]
pub enum Reply {
    Info(Info),
    /// The guest is down and the helper is about to exit.
    Stopped { reason: StopReason, seconds: f64 },
    Error { message: String },
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
    /// Learned from the DHCP lease file and *proved* by an ssh banner, so
    /// `Some` means something answered on port 22 at that address.
    #[serde(default)]
    pub guest_ip: Option<IpAddr>,
    /// Unix seconds when the VM was started.
    pub started_at: u64,
    /// Seconds from `startWithCompletionHandler` to the guest's ssh banner.
    #[serde(default)]
    pub boot_secs: Option<f64>,
    pub console: PathBuf,
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
    Error,
}

impl State {
    /// Is there still a guest to talk to? `Stopping` counts: the VM is
    /// there, it is on its way out.
    pub fn is_live(self) -> bool {
        matches!(self, State::Starting | State::Running | State::Paused | State::Stopping)
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
            extra_disks: vec![Disk { path: "/vol/data.raw".into(), readonly: true }],
            cpus: 2,
            mem_mib: 2048,
            mac: mac_for("dev"),
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
    fn the_wire_is_one_json_object_per_line() {
        let cmd = serde_json::to_string(&Command::Stop { timeout_secs: Some(30) }).unwrap();
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
    }

    #[test]
    fn only_a_live_state_means_there_is_still_a_guest() {
        assert!(State::Running.is_live());
        assert!(State::Starting.is_live());
        assert!(State::Stopping.is_live(), "on its way out is still there");
        assert!(!State::Stopped.is_live());
        assert!(!State::Error.is_live());
    }

    #[test]
    fn stop_reasons_read_like_sentences() {
        assert_eq!(StopReason::GuestStopped.to_string(), "guest powered off");
        assert!(StopReason::Forced.to_string().contains("ACPI"));
        assert_eq!(
            StopReason::Failed { message: "no disk".into() }.to_string(),
            "failed: no disk"
        );
    }

    #[test]
    fn calling_a_socket_nobody_is_listening_on_says_so() {
        let dir = tempfile::tempdir().unwrap();
        let err = call(&dir.path().join("absent.sock"), &Command::Info, Duration::from_millis(50))
            .unwrap_err()
            .to_string();
        assert!(err.contains("no vz helper listening"), "{err}");
    }
}
