//! Host integration diagnostics — `ast doctor`.
//!
//! A supported Linux machine is one that can install from a checksummed
//! archive, keep `astd` running after logout and reboot, prevent idle sleep
//! while guests run, store secrets in Secret Service, and execute the pinned
//! Cloud Hypervisor, virtiofsd, and NBD helper — not merely find them on
//! disk. This module reports those facts as independent checks so a human
//! (or `ast doctor`) can see exactly which one is missing.
//!
//! Every row that can be anything other than `ok` also carries the command
//! that clears it ([`Check::fix`]). That is why the probes here are split in
//! two: a thin function that reads the machine, and a pure one that turns
//! what it read into a [`Check`]. The pure half is what the tests drive, so
//! "every failure names a remedy" is a property this module proves about
//! itself rather than a habit somebody has to remember.

#[cfg(any(test, target_os = "linux"))]
use std::fs::OpenOptions;
use std::path::{Path, PathBuf};
#[cfg(any(test, not(windows)))]
use std::process::Command;

use anyhow::{bail, Result};

use crate::fix::{install_hint, Fix, REINSTALL};

/// Name of the macOS helper that owns Virtualization.framework guests, and
/// the two entitlements it must be signed with.
///
/// They live here, rather than in `asterism-vz` where the helper's protocol
/// is defined, because `ast doctor` has to check the signature on a host
/// whose `ast` does not link that crate at all. `asterism_vz` re-exports
/// these, so there is still one spelling of each.
pub const VZ_HELPER_BIN: &str = "astd-vz";
/// The entitlement Virtualization.framework requires to create a VM.
pub const VZ_ENTITLEMENT: &str = "com.apple.security.virtualization";
/// The entitlement its NBD client requires, even over `nbd+unix`.
pub const VZ_NETWORK_CLIENT_ENTITLEMENT: &str = "com.apple.security.network.client";

/// One row of `ast doctor`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Check {
    pub name: &'static str,
    pub status: Status,
    pub detail: String,
    /// What to run to clear this row.
    ///
    /// A row that names a remedy is the difference between a diagnosis and a
    /// bug report. `None` on an `ok` or `skip` row — there is nothing to
    /// repair — and never on a `warn` or `fail` one, which
    /// `every_failing_row_names_a_command_to_run` holds this module to.
    pub fix: Option<Fix>,
}

impl Check {
    /// Attach the remedy for this row.
    pub fn with_fix(mut self, fix: Fix) -> Self {
        self.fix = Some(fix);
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Ok,
    Warn,
    Fail,
    Skip,
}

impl Status {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Warn => "warn",
            Self::Fail => "fail",
            Self::Skip => "skip",
        }
    }

    pub fn is_fail(self) -> bool {
        matches!(self, Self::Fail)
    }
}

/// Pinned Linux runtime identities, parsed from `linux-components.env`.
///
/// The architecture/checksum contract is exact: every binary URL and digest
/// named here must be present. A truncated lock is refused rather than
/// silently shipping a partial VMM.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxPins {
    pub cloud_hypervisor_version: String,
    pub cloud_hypervisor_aarch64_url: String,
    pub cloud_hypervisor_aarch64_sha256: String,
    pub cloud_hypervisor_x86_64_url: String,
    pub cloud_hypervisor_x86_64_sha256: String,
    pub cloud_hypervisor_source_sha256: String,
    pub virtiofsd_version: String,
    pub virtiofsd_tarball: String,
    pub virtiofsd_tarball_sha256: String,
}

impl LinuxPins {
    /// Parse the lock file the installer and packager both source.
    pub fn parse(text: &str) -> Result<Self> {
        Ok(Self {
            cloud_hypervisor_version: required_pin(text, "CLOUD_HYPERVISOR_VERSION")?,
            cloud_hypervisor_aarch64_url: required_pin(text, "CLOUD_HYPERVISOR_AARCH64_URL")?,
            cloud_hypervisor_aarch64_sha256: required_pin(text, "CLOUD_HYPERVISOR_AARCH64_SHA256")?,
            cloud_hypervisor_x86_64_url: required_pin(text, "CLOUD_HYPERVISOR_X86_64_URL")?,
            cloud_hypervisor_x86_64_sha256: required_pin(text, "CLOUD_HYPERVISOR_X86_64_SHA256")?,
            cloud_hypervisor_source_sha256: required_pin(text, "CLOUD_HYPERVISOR_SOURCE_SHA256")?,
            virtiofsd_version: required_pin(text, "VIRTIOFSD_VERSION")?,
            virtiofsd_tarball: required_pin(text, "VIRTIOFSD_TARBALL")?,
            virtiofsd_tarball_sha256: required_pin(text, "VIRTIOFSD_TARBALL_SHA256")?,
        })
    }
}

fn required_pin(text: &str, key: &str) -> Result<String> {
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        if let Some(value) = line
            .strip_prefix(key)
            .and_then(|rest| rest.strip_prefix('='))
        {
            if value.is_empty() {
                bail!("{key} is empty in the Linux component lock");
            }
            return Ok(value.to_owned());
        }
    }
    bail!("{key} is missing from the Linux component lock")
}

/// `Linger=yes` / `Linger=no` from `loginctl show-user -p Linger`.
pub fn parse_linger_property(text: &str) -> Option<bool> {
    for line in text.lines() {
        if let Some(value) = line.trim().strip_prefix("Linger=") {
            return Some(value.eq_ignore_ascii_case("yes"));
        }
    }
    None
}

/// Where the platform store for secret material lives. Never a file.
pub fn secret_store_name() -> &'static str {
    #[cfg(target_os = "macos")]
    {
        "macOS login Keychain"
    }
    #[cfg(target_os = "linux")]
    {
        "FreeDesktop Secret Service"
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        "unavailable"
    }
}

/// Sleep-inhibition mechanism this host is supposed to use.
pub fn sleep_mechanism_name() -> &'static str {
    #[cfg(target_os = "macos")]
    {
        "IOKit PreventUserIdleSystemSleep"
    }
    #[cfg(target_os = "linux")]
    {
        "systemd-inhibit sleep:idle"
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        "none"
    }
}

/// True when `--version` output names the pinned identity.
pub fn version_probe_matches(stdout: &str, pin: &str) -> bool {
    let pin = pin.trim();
    !pin.is_empty() && stdout.contains(pin)
}

/// True when the NBD helper actually ran: it always prefixes diagnostics
/// with `asterism-nbd:`, including the root-policy refusal.
pub fn nbd_helper_executed(stderr: &str) -> bool {
    stderr.contains("asterism-nbd:")
}

/// True when busctl/dbus output shows the Secret Service name is on the bus.
pub fn secret_service_from_bus(ok: bool, stdout: &str, stderr: &str) -> bool {
    if !ok {
        return false;
    }
    let text = format!("{stdout}\n{stderr}");
    text.contains("org.freedesktop.secrets") || text.contains("Name=")
}

fn sibling(name: &str) -> Option<PathBuf> {
    std::env::current_exe()
        .ok()
        .map(|me| me.with_file_name(name))
}

/// The pinned helper as this installation shipped it, falling back to the
/// flat layout's path so an absent helper is still named in the report
/// rather than dropping the check.
#[cfg(target_os = "linux")]
fn installed_helper(name: &str) -> Option<PathBuf> {
    crate::layout::helper(name).or_else(|| sibling(name))
}

fn prefix_dir() -> Option<PathBuf> {
    std::env::current_exe().ok().and_then(|me| {
        me.parent()
            .map(|bin| bin.parent().unwrap_or(bin).to_owned())
    })
}

fn receipt_path(prefix: &Path) -> PathBuf {
    prefix.join("share/asterism/install-receipt.env")
}

#[cfg(any(test, target_os = "linux"))]
fn run_probe(path: &Path, args: &[&str]) -> std::io::Result<std::process::Output> {
    Command::new(path).args(args).output()
}

#[cfg(any(test, target_os = "linux"))]
fn probe_version_binary(name: &'static str, path: &Path, pin: &str, missing: &str) -> Check {
    // A pinned helper is not in anybody's package repository, so every way
    // this row can fail — absent, wrong version, unexecutable — is repaired
    // by the installer that fetches it by digest.
    let reinstall = || {
        install_hint(name).unwrap_or_else(|| {
            Fix::noted(REINSTALL, format!("{name} is a pinned Asterism component"))
        })
    };
    if !path.is_file() {
        return Check {
            name,
            status: Status::Fail,
            detail: format!("{missing} ({})", path.display()),
            fix: Some(reinstall()),
        };
    }
    match run_probe(path, &["--version"]) {
        Ok(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            if version_probe_matches(&stdout, pin) {
                Check {
                    name,
                    status: Status::Ok,
                    detail: format!(
                        "{} ({})",
                        stdout.trim().lines().next().unwrap_or(pin),
                        path.display()
                    ),
                    fix: None,
                }
            } else {
                Check {
                    name,
                    status: Status::Fail,
                    detail: format!(
                        "{} executed but did not report {}; got {}",
                        path.display(),
                        pin,
                        stdout.trim()
                    ),
                    fix: Some(reinstall()),
                }
            }
        }
        Err(error) => Check {
            name,
            status: Status::Fail,
            detail: format!("could not execute {}: {error}", path.display()),
            fix: Some(reinstall()),
        },
    }
}

#[cfg(not(target_os = "linux"))]
fn skip(name: &'static str, detail: impl Into<String>) -> Check {
    Check {
        name,
        status: Status::Skip,
        detail: detail.into(),
        fix: None,
    }
}

/// Run every host-integration check this device can answer.
pub fn run() -> Vec<Check> {
    let mut checks = Vec::new();

    if let Some(ast) = sibling("ast") {
        checks.push(file_or_exec("ast", &ast, "ast is not beside this binary"));
    }
    if let Some(astd) = sibling("astd") {
        checks.push(file_or_exec(
            "astd",
            &astd,
            "astd is not beside ast; the daemon cannot be started",
        ));
    }

    checks.push(match crate::service::manager() {
        Ok(manager) => match manager.status() {
            Ok(state) => service_row(manager.mechanism(), Ok(&state)),
            Err(error) => service_row(manager.mechanism(), Err(format!("{error:#}"))),
        },
        Err(error) => service_row("no service manager", Err(format!("{error:#}"))),
    });

    checks.push(curl_check());
    checks.push(secret_store_check());
    checks.push(sleep_check());

    #[cfg(target_os = "macos")]
    {
        checks.push(vz_check());
    }

    #[cfg(target_os = "linux")]
    {
        checks.extend(linux_checks());
    }
    #[cfg(not(target_os = "linux"))]
    {
        checks.push(skip(
            "linux-runtime",
            "Cloud Hypervisor packaging is a Linux host concern",
        ));
    }

    if let Some(prefix) = prefix_dir() {
        let receipt = receipt_path(&prefix);
        checks.push(receipt_row(&receipt, receipt.is_file()));
    }

    checks
}

/// The service row: the daemon is only persistent once the OS has it.
fn service_row(mechanism: &str, state: Result<&crate::service::State, String>) -> Check {
    // Both halves of the not-ok answer — a unit that is absent or unloaded,
    // and a service manager that could not be asked — are cleared by the
    // command that writes the unit and loads it.
    let install = || Fix::new("ast service install");
    match state {
        Ok(state) if state.installed && state.loaded => Check {
            name: "service",
            status: Status::Ok,
            detail: format!("{mechanism}: {}", state.summary()),
            fix: None,
        },
        Ok(state) => Check {
            name: "service",
            status: Status::Warn,
            detail: format!("{mechanism}: {}", state.summary()),
            fix: Some(install()),
        },
        Err(error) => Check {
            name: "service",
            status: Status::Fail,
            detail: format!("{mechanism}: {error}"),
            fix: Some(install()),
        },
    }
}

/// The install receipt: present when `install.sh` put this tree here.
fn receipt_row(receipt: &Path, present: bool) -> Check {
    if present {
        return Check {
            name: "receipt",
            status: Status::Ok,
            detail: receipt.display().to_string(),
            fix: None,
        };
    }
    Check {
        name: "receipt",
        status: Status::Warn,
        detail: format!(
            "{} is missing — this tree was not installed by install.sh",
            receipt.display()
        ),
        fix: Some(Fix::noted(
            REINSTALL,
            "the installer writes the receipt; a source build has none and does not need one",
        )),
    }
}

/// `curl` is how every image blob, every guest kernel and every pinned
/// component reaches this device. Without it nothing can be pulled at all,
/// which is a `fail` and not a `warn`: an Asterism that cannot fetch an OCI
/// image cannot start its first instance.
fn curl_check() -> Check {
    curl_row(crate::tools::tool("curl").ok().as_deref())
}

fn curl_row(found: Option<&Path>) -> Check {
    match found {
        Some(path) => Check {
            name: "curl",
            status: Status::Ok,
            detail: path.display().to_string(),
            fix: None,
        },
        None => Check {
            name: "curl",
            status: Status::Fail,
            detail: "not found on PATH — needed to fetch images and kernels".to_owned(),
            fix: install_hint("curl"),
        },
    }
}

fn file_or_exec(name: &'static str, path: &Path, missing: &str) -> Check {
    if path.is_file() {
        Check {
            name,
            status: Status::Ok,
            detail: path.display().to_string(),
            fix: None,
        }
    } else {
        Check {
            name,
            status: Status::Fail,
            detail: format!("{missing} ({})", path.display()),
            // Half an install is not something a user can assemble by hand:
            // the installer is what puts these two beside each other.
            fix: Some(Fix::noted(
                REINSTALL,
                format!("{name} ships with every install lane"),
            )),
        }
    }
}

fn secret_store_check() -> Check {
    #[cfg(target_os = "linux")]
    {
        probe_secret_service()
    }
    #[cfg(target_os = "macos")]
    {
        probe_macos_keychain()
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        Check {
            name: "secrets",
            status: Status::Fail,
            detail: "secret storage is not built for this OS; no plaintext fallback is used".into(),
            fix: Some(unsupported_host_fix()),
        }
    }
}

#[cfg(target_os = "macos")]
fn probe_macos_keychain() -> Check {
    match Command::new("security").arg("list-keychains").output() {
        Ok(out) => macos_keychain_row(
            out.status.success(),
            String::from_utf8_lossy(&out.stderr).trim(),
        ),
        Err(error) => macos_keychain_row(
            false,
            &format!("could not execute security(1) to probe the login Keychain: {error}"),
        ),
    }
}

/// The macOS secret row. A Keychain that will not answer is nearly always a
/// locked one, which is a thing the person at the machine can unlock.
#[cfg(any(test, target_os = "macos"))]
fn macos_keychain_row(answered: bool, stderr: &str) -> Check {
    if answered {
        return Check {
            name: "secrets",
            status: Status::Ok,
            detail: format!(
                "{} answered list-keychains; no file fallback",
                secret_store_name()
            ),
            fix: None,
        };
    }
    Check {
        name: "secrets",
        status: Status::Fail,
        detail: format!("security list-keychains failed: {stderr}"),
        fix: Some(Fix::noted(
            "security unlock-keychain ~/Library/Keychains/login.keychain-db",
            "macOS: the login Keychain has to exist and be unlocked",
        )),
    }
}

#[cfg(target_os = "linux")]
fn probe_secret_service() -> Check {
    let busctl = Command::new("busctl")
        .args(["--user", "status", "org.freedesktop.secrets"])
        .output();
    if let Ok(out) = busctl {
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        if secret_service_from_bus(out.status.success(), &stdout, &stderr) {
            return secret_service_row(BusAnswer::Named);
        }
    }
    let ping = Command::new("dbus-send")
        .args([
            "--session",
            "--dest=org.freedesktop.secrets",
            "--print-reply",
            "/org/freedesktop/secrets",
            "org.freedesktop.DBus.Peer.Ping",
        ])
        .output();
    match ping {
        Ok(out) if out.status.success() => secret_service_row(BusAnswer::Pinged),
        Ok(out) => secret_service_row(BusAnswer::Refused(
            String::from_utf8_lossy(&out.stderr).trim().to_owned(),
        )),
        Err(_) => secret_service_row(BusAnswer::Unprobeable),
    }
}

/// What the session bus said when it was asked for the Secret Service.
#[cfg(any(test, target_os = "linux"))]
enum BusAnswer {
    /// `busctl` reported the well-known name.
    Named,
    /// The service answered `Peer.Ping`.
    Pinged,
    /// The bus is there and nothing owns the name.
    Refused(String),
    /// Neither `busctl` nor `dbus-send` could be run.
    Unprobeable,
}

/// The Linux secret row. Both not-ok answers mean the same missing thing:
/// no process on this session bus implements the Secret Service.
#[cfg(any(test, target_os = "linux"))]
fn secret_service_row(answer: BusAnswer) -> Check {
    let provider = || {
        install_hint("gnome-keyring").unwrap_or_else(|| {
            Fix::noted(
                "sudo apt-get install -y gnome-keyring",
                "or this platform's kwallet / keepassxc package",
            )
        })
    };
    match answer {
        BusAnswer::Named => Check {
            name: "secrets",
            status: Status::Ok,
            detail: format!(
                "{} answered on the session bus; no plaintext fallback",
                secret_store_name()
            ),
            fix: None,
        },
        BusAnswer::Pinged => Check {
            name: "secrets",
            status: Status::Ok,
            detail: format!(
                "{} answered Peer.Ping; no plaintext fallback",
                secret_store_name()
            ),
            fix: None,
        },
        BusAnswer::Refused(stderr) => Check {
            name: "secrets",
            status: Status::Warn,
            detail: format!(
                "{} needs a session bus provider (gnome-keyring, kwallet, or keepassxc): {stderr}",
                secret_store_name(),
            ),
            fix: Some(provider()),
        },
        BusAnswer::Unprobeable => Check {
            name: "secrets",
            status: Status::Warn,
            detail: format!(
                "{} could not be probed (busctl/dbus-send missing). Without a Secret Service provider, secret material cannot be stored.",
                secret_store_name()
            ),
            fix: Some(provider()),
        },
    }
}

fn sleep_check() -> Check {
    #[cfg(target_os = "linux")]
    {
        match Command::new("systemd-inhibit")
            .args([
                "--what=sleep:idle",
                "--who=asterism-doctor",
                "--why=probe",
                "--mode=block",
                "true",
            ])
            .output()
        {
            Ok(out) if out.status.success() => sleep_row(InhibitProbe::Held),
            Ok(out) => sleep_row(InhibitProbe::Refused(
                String::from_utf8_lossy(&out.stderr).trim().to_owned(),
            )),
            Err(_) => sleep_row(InhibitProbe::NotExecutable),
        }
    }
    #[cfg(target_os = "macos")]
    {
        Check {
            name: "sleep",
            status: Status::Ok,
            detail: sleep_mechanism_name().into(),
            fix: None,
        }
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        Check {
            name: "sleep",
            status: Status::Fail,
            detail: "this device cannot prevent sleep yet".into(),
            fix: Some(unsupported_host_fix()),
        }
    }
}

/// What the `systemd-inhibit` probe reported.
#[cfg(any(test, target_os = "linux"))]
enum InhibitProbe {
    /// The inhibitor was taken and released.
    Held,
    /// `systemd-inhibit` ran and refused.
    Refused(String),
    /// It is not on this machine at all.
    NotExecutable,
}

/// The Linux sleep row: without logind there is nothing holding this device
/// awake while a guest runs.
#[cfg(any(test, target_os = "linux"))]
fn sleep_row(probe: InhibitProbe) -> Check {
    match probe {
        InhibitProbe::Held => Check {
            name: "sleep",
            status: Status::Ok,
            detail: format!("{} (inhibit probe succeeded)", sleep_mechanism_name()),
            fix: None,
        },
        InhibitProbe::Refused(stderr) => Check {
            name: "sleep",
            status: Status::Fail,
            detail: format!("systemd-inhibit probe failed: {stderr}"),
            // The binary is there and the call failed, which on every
            // systemd host means logind is not running to take the lock.
            fix: Some(Fix::new("sudo systemctl start systemd-logind")),
        },
        InhibitProbe::NotExecutable => Check {
            name: "sleep",
            status: Status::Fail,
            detail: "systemd-inhibit is not executable, so running guests cannot block idle sleep"
                .into(),
            fix: Some(install_hint("systemd-inhibit").unwrap_or_else(|| {
                Fix::noted(
                    "sudo apt-get install -y systemd",
                    "or this platform's systemd package",
                )
            })),
        },
    }
}

/// The remedy for a host Asterism has no host integration for at all.
///
/// Windows has one — the Hyper-V backend and its own report, which is what
/// `ast doctor` prints there — and reaching it starts with the feature being
/// on, so the command is that report's own. Anything else is not a supported
/// host, and the honest command is the installer, which says so.
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn unsupported_host_fix() -> Fix {
    #[cfg(windows)]
    {
        crate::windows_host::enable_hyperv()
    }
    #[cfg(not(windows))]
    {
        Fix::noted(
            REINSTALL,
            "Asterism integrates with macOS, Linux and Windows hosts; this OS has neither a secret store nor a sleep inhibitor",
        )
    }
}

#[cfg(target_os = "linux")]
fn linux_checks() -> Vec<Check> {
    let mut checks = Vec::new();
    checks.push(probe_kvm(Path::new("/dev/kvm")));

    let pins = prefix_dir().and_then(|prefix| {
        std::fs::read_to_string(prefix.join("share/asterism/linux-components.env"))
            .ok()
            .and_then(|text| LinuxPins::parse(&text).ok())
    });
    let chv_pin = pins
        .as_ref()
        .map(|p| p.cloud_hypervisor_version.as_str())
        .unwrap_or("v53.0");
    let virtio_pin = pins
        .as_ref()
        .map(|p| p.virtiofsd_version.trim_start_matches('v'))
        .unwrap_or("1.14.0");

    // A flat install keeps the pinned helpers beside astd; a native package
    // keeps them under libexec/asterism. Report against whichever this
    // installation actually has, and against the flat path when it has
    // neither, so an absent helper still fails by name.
    if let Some(chv) = installed_helper("cloud-hypervisor") {
        checks.push(probe_version_binary(
            "cloud-hypervisor",
            &chv,
            chv_pin,
            "pinned Cloud Hypervisor is not installed",
        ));
    }
    if let Some(virtiofsd) = installed_helper("virtiofsd") {
        checks.push(probe_version_binary(
            "virtiofsd",
            &virtiofsd,
            virtio_pin,
            "pinned virtiofsd is not installed",
        ));
    }

    if let Some(prefix) = prefix_dir() {
        let lock = prefix.join("share/asterism/linux-components.env");
        checks.push(linux_pins_row(&lock, std::fs::read_to_string(&lock).ok()));
        checks.push(probe_nbd_helper(&crate::layout::nbd_helper()));
    }

    checks.push(linger_check());
    checks
}

/// The pinned component lock, which is what says *which* Cloud Hypervisor
/// and virtiofsd this installation is entitled to.
#[cfg(any(test, target_os = "linux"))]
fn linux_pins_row(lock: &Path, text: Option<String>) -> Check {
    let reinstall = || {
        Fix::noted(
            REINSTALL,
            "the component lock is written by the installer, beside the helpers it pins",
        )
    };
    match text {
        Some(text) => match LinuxPins::parse(&text) {
            Ok(parsed) => Check {
                name: "linux-pins",
                status: Status::Ok,
                detail: format!(
                    "Cloud Hypervisor {} and virtiofsd {}",
                    parsed.cloud_hypervisor_version, parsed.virtiofsd_version
                ),
                fix: None,
            },
            Err(error) => Check {
                name: "linux-pins",
                status: Status::Fail,
                detail: format!("{error:#}"),
                fix: Some(reinstall()),
            },
        },
        None => Check {
            name: "linux-pins",
            status: Status::Warn,
            detail: format!("{} is missing", lock.display()),
            fix: Some(reinstall()),
        },
    }
}

#[cfg(any(test, target_os = "linux"))]
fn probe_nbd_helper(nbd: &Path) -> Check {
    if !nbd.is_file() {
        return Check {
            name: "nbd-helper",
            status: Status::Warn,
            detail: format!(
                "{} is missing; remote volumes cannot attach until install.sh or `ast service install` configures NBD",
                nbd.display()
            ),
            // The root-owned wrapper and its sudoers rule are installed
            // together, and this is the command that installs both.
            fix: Some(Fix::new("ast service install")),
        };
    }
    probe_nbd_helper_through(nbd, Path::new("sudo"))
}

#[cfg(any(test, target_os = "linux"))]
fn probe_nbd_helper_through(nbd: &Path, sudo: &Path) -> Check {
    match Command::new(sudo)
        .arg("-n")
        .arg(nbd)
        .arg("--probe")
        .output()
    {
        Ok(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr);
            if out.status.success() && nbd_helper_executed(&stderr) {
                Check {
                    name: "nbd-helper",
                    status: Status::Ok,
                    detail: format!(
                        "privileged helper probe succeeded through sudo ({})",
                        nbd.display()
                    ),
                    fix: None,
                }
            } else {
                Check {
                    name: "nbd-helper",
                    status: Status::Fail,
                    detail: format!(
                        "sudo -n {} --probe failed or did not identify as asterism-nbd: {}",
                        nbd.display(),
                        stderr.trim()
                    ),
                    fix: Some(Fix::new("ast service install")),
                }
            }
        }
        Err(error) => Check {
            name: "nbd-helper",
            status: Status::Fail,
            detail: format!("could not execute {}: {error}", nbd.display()),
            fix: Some(Fix::new("ast service install")),
        },
    }
}

#[cfg(any(test, target_os = "linux"))]
fn probe_kvm(kvm: &Path) -> Check {
    if !kvm.exists() {
        return Check {
            name: "kvm",
            status: Status::Fail,
            detail: format!("{} is missing; Cloud Hypervisor cannot run", kvm.display()),
            // No device node at all is the module not loaded — or, under it,
            // hardware virtualization switched off where only firmware or a
            // hosting provider can switch it back on.
            fix: Some(Fix::noted(
                "sudo modprobe kvm_intel || sudo modprobe kvm_amd",
                "if that fails, virtualization (VT-x/AMD-V, or nested virtualization on a cloud VM) is off",
            )),
        };
    }
    match OpenOptions::new().read(true).write(true).open(kvm) {
        Ok(_) => Check {
            name: "kvm",
            status: Status::Ok,
            detail: format!("{} opens read-write", kvm.display()),
            fix: None,
        },
        Err(error) => Check {
            name: "kvm",
            status: Status::Fail,
            detail: format!(
                "{} does not open read-write ({error}); add this user to the kvm group and log in again",
                kvm.display()
            ),
            fix: Some(Fix::new("sudo usermod -aG kvm $USER && newgrp kvm")),
        },
    }
}

#[cfg(target_os = "linux")]
fn linger_check() -> Check {
    let user = std::env::var("USER").unwrap_or_default();
    let output = Command::new("loginctl")
        .args(["show-user", "-p", "Linger"])
        .output();
    match output {
        Ok(out) if out.status.success() => {
            linger_row(&user, Some(&String::from_utf8_lossy(&out.stdout)))
        }
        _ => linger_row(&user, None),
    }
}

/// The lingering row, from whatever `loginctl show-user -p Linger` said —
/// `None` when it could not be asked at all.
#[cfg(any(test, target_os = "linux"))]
fn linger_row(user: &str, property: Option<&str>) -> Check {
    // `$USER` when the environment did not name one, because the command
    // still has to be copy-pasteable into the shell that will run it.
    let who = if user.is_empty() { "$USER" } else { user };
    let enable = || Fix::new(format!("loginctl enable-linger {who}"));
    let Some(text) = property else {
        return Check {
            name: "linger",
            status: Status::Fail,
            detail: format!(
                "loginctl is unavailable; enable lingering with: loginctl enable-linger {who}"
            ),
            fix: Some(enable()),
        };
    };
    match parse_linger_property(text) {
        Some(true) => Check {
            name: "linger",
            status: Status::Ok,
            detail: "lingering is on; the user systemd instance survives logout and reboot".into(),
            fix: None,
        },
        Some(false) => Check {
            name: "linger",
            status: Status::Fail,
            detail: format!(
                "lingering is off; astd dies at logout. Enable it with: loginctl enable-linger {who}"
            ),
            fix: Some(enable()),
        },
        None => Check {
            name: "linger",
            status: Status::Warn,
            detail: format!("loginctl did not report Linger ({})", text.trim()),
            fix: Some(enable()),
        },
    }
}

// ---- macOS: the signed helper that owns every guest ------------------------

/// What `codesign` had to say about the helper's entitlements.
#[cfg(any(test, target_os = "macos"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Signature {
    /// Both entitlements Virtualization.framework insists on are there.
    Entitled,
    /// The binary is unsigned, or signed without them — which VZ treats the
    /// same way, and `cargo build` produces on every rebuild.
    Unentitled,
    /// `codesign` could not be run, so nothing can be said either way.
    Unaskable,
}

/// The vz row: on macOS there is no other backend, so a helper that is
/// absent or unsigned is not a degraded device, it is a device that cannot
/// boot anything.
#[cfg(target_os = "macos")]
fn vz_check() -> Check {
    let helper = vz_helper_path();
    let signature = helper.as_deref().map(vz_signature);
    vz_row(helper.as_deref(), signature, guest_artifact())
}

/// Where `astd` looks for its helper: the packaging override, then beside
/// the running binary, then `PATH`.
#[cfg(target_os = "macos")]
fn vz_helper_path() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("ASTERISM_VZ_HELPER") {
        let path = PathBuf::from(path);
        return path.is_file().then_some(path);
    }
    if let Some(beside) = sibling(VZ_HELPER_BIN).filter(|p| p.is_file()) {
        return Some(beside);
    }
    crate::tools::tool(VZ_HELPER_BIN).ok()
}

/// Ask the signature itself rather than trusting the file's provenance.
///
/// `codesign -d --entitlements -` prints the entitlement plist; an unsigned
/// binary, or one cargo rewrote after it was signed, prints an error. Older
/// releases print to stderr and newer ones to stdout, so both are read.
#[cfg(target_os = "macos")]
fn vz_signature(helper: &Path) -> Signature {
    let Ok(out) = Command::new("codesign")
        .args(["-d", "--entitlements", "-"])
        .arg(helper)
        .output()
    else {
        return Signature::Unaskable;
    };
    let printed =
        String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr);
    if printed.contains(VZ_ENTITLEMENT) && printed.contains(VZ_NETWORK_CLIENT_ENTITLEMENT) {
        Signature::Entitled
    } else {
        Signature::Unentitled
    }
}

/// The installed guest-control agent, validated the way a boot validates it.
///
/// Every direct-kernel OCI guest is handed this binary, and a VM whose agent
/// is missing is a VM nothing can talk to — so its absence belongs in the
/// same row as the helper's.
#[cfg(target_os = "macos")]
fn guest_artifact() -> Result<PathBuf, String> {
    if let Some(path) = std::env::var_os("ASTERISM_GUEST_AGENT_ARTIFACT") {
        let path = PathBuf::from(path);
        return match crate::guest::Artifact::from_path(&path) {
            Ok(_) => Ok(path),
            Err(error) => Err(format!("$ASTERISM_GUEST_AGENT_ARTIFACT: {error}")),
        };
    }
    let mut searched = Vec::new();
    for dir in crate::layout::data_dirs() {
        let candidate = dir.join("guest/bin/asterism-guest");
        match crate::guest::Artifact::from_path(&candidate) {
            Ok(_) => return Ok(candidate),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                searched.push(candidate.display().to_string())
            }
            Err(error) => return Err(error.to_string()),
        }
    }
    Err(format!(
        "no guest-control agent at any of {}",
        searched.join(", ")
    ))
}

/// Turn what was read off the machine into the row. Pure, so every way this
/// can fail is reachable from a test on any host.
#[cfg(any(test, target_os = "macos"))]
fn vz_row(
    helper: Option<&Path>,
    signature: Option<Signature>,
    artifact: Result<PathBuf, String>,
) -> Check {
    let row = |status, detail, fix| Check {
        name: "vz",
        status,
        detail,
        fix: Some(fix),
    };
    let Some(helper) = helper else {
        return row(
            Status::Fail,
            format!(
                "{VZ_HELPER_BIN} is not installed beside astd; Virtualization.framework guests \
                 have no process to live in"
            ),
            install_hint(VZ_HELPER_BIN).unwrap_or_else(|| Fix::new(REINSTALL)),
        );
    };
    match signature {
        Some(Signature::Unaskable) => {
            return row(
                Status::Fail,
                format!(
                    "codesign could not be run, so {}'s entitlements cannot be read",
                    helper.display()
                ),
                Fix::noted(
                    "xcode-select --install",
                    "codesign ships with the Command Line Tools",
                ),
            )
        }
        Some(Signature::Unentitled) => {
            return row(
                Status::Fail,
                format!(
                    "{} is not signed with {VZ_ENTITLEMENT} and {VZ_NETWORK_CLIENT_ENTITLEMENT}; \
                     VZ refuses to create a machine without them",
                    helper.display()
                ),
                Fix::noted(
                    "scripts/sign-vz.sh",
                    "in an Asterism checkout — cargo invalidates the signature on every rebuild; \
                     an installed release arrives signed",
                ),
            )
        }
        Some(Signature::Entitled) | None => {}
    }
    match artifact {
        Ok(artifact) => Check {
            name: "vz",
            status: Status::Ok,
            detail: format!(
                "{} carries both entitlements; guest agent {}",
                helper.display(),
                artifact.display()
            ),
            fix: None,
        },
        Err(why) => row(
            Status::Fail,
            format!("{VZ_HELPER_BIN} is signed, but the guest-control agent is unusable: {why}"),
            Fix::noted(
                REINSTALL,
                "the guest agent ships beside the helper in every install lane",
            ),
        ),
    }
}

/// True when every check is ok, warn, or skip — never fail.
pub fn all_clear(checks: &[Check]) -> bool {
    checks.iter().all(|check| !check.status.is_fail())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn linger_yes_and_no_are_read_off_loginctl_properties() {
        assert_eq!(parse_linger_property("Linger=yes\n"), Some(true));
        assert_eq!(parse_linger_property("Linger=no\n"), Some(false));
        assert_eq!(parse_linger_property("Linger=YES\n"), Some(true));
        assert_eq!(parse_linger_property(""), None);
        assert_eq!(parse_linger_property("Name=alice\n"), None);
    }

    #[test]
    fn the_committed_linux_pins_match_the_architecture_checksum_contract() {
        let text = include_str!("../../../packaging/linux-components.env");
        let pins = LinuxPins::parse(text).unwrap();
        assert_eq!(pins.cloud_hypervisor_version, "v53.0");
        assert_eq!(
            pins.cloud_hypervisor_aarch64_sha256,
            "f192b510eea1c710cbc439d716bb0573c223fc463dbe3e6523788a2b7ef62850"
        );
        assert_eq!(
            pins.cloud_hypervisor_x86_64_sha256,
            "448af3d4e59b22c2987f7df94c213ad40fb53a10d437e42b5ee6c4fce7c29ecc"
        );
        assert!(pins
            .cloud_hypervisor_x86_64_url
            .contains("cloud-hypervisor-static"));
        assert!(pins
            .cloud_hypervisor_aarch64_url
            .contains("cloud-hypervisor-static-aarch64"));
        assert_eq!(pins.virtiofsd_version, "v1.14.0");
        assert_eq!(
            pins.virtiofsd_tarball_sha256,
            "52b66e449ca583b4f050a2bff327ff812211a2c349b4130279fcfc6a64540f04"
        );
        assert!(pins.virtiofsd_tarball.contains("virtiofsd-v1.14.0.tar.gz"));
        assert_eq!(
            pins.cloud_hypervisor_source_sha256,
            "7d806fc1ee42dc4cf5af1293925ab0f741c676ccd29b7f1fa6cb798c01c51f1f"
        );
    }

    #[test]
    fn a_truncated_lock_file_is_refused() {
        let err = LinuxPins::parse("CLOUD_HYPERVISOR_VERSION=v53.0\n").unwrap_err();
        assert!(
            err.to_string().contains("CLOUD_HYPERVISOR_AARCH64_URL"),
            "{err}"
        );
    }

    #[test]
    fn an_empty_architecture_digest_is_refused() {
        let err =
            LinuxPins::parse("CLOUD_HYPERVISOR_VERSION=v53.0\nCLOUD_HYPERVISOR_AARCH64_URL=\n")
                .unwrap_err();
        assert!(
            err.to_string().contains("CLOUD_HYPERVISOR_AARCH64_URL"),
            "{err}"
        );
    }

    #[test]
    fn version_probe_requires_the_pin_in_stdout() {
        assert!(version_probe_matches("cloud-hypervisor v53.0\n", "v53.0"));
        assert!(!version_probe_matches("cloud-hypervisor v52.0\n", "v53.0"));
        assert!(!version_probe_matches("cloud-hypervisor v53.0\n", ""));
    }

    #[test]
    fn nbd_helper_identity_is_not_confused_with_unrelated_stderr() {
        assert!(nbd_helper_executed(
            "asterism-nbd: must run as root through the installed sudo policy\n"
        ));
        assert!(nbd_helper_executed(
            "asterism-nbd: refusing to detach /dev/nbd0: it belongs to another owner\n"
        ));
        assert!(!nbd_helper_executed(""));
        assert!(!nbd_helper_executed("nbd-client: not found\n"));
    }

    #[test]
    fn secret_service_probe_requires_a_bus_answer_not_an_env_var() {
        assert!(secret_service_from_bus(
            true,
            "Name=org.freedesktop.secrets\n",
            ""
        ));
        assert!(!secret_service_from_bus(
            false,
            "Name=org.freedesktop.secrets\n",
            ""
        ));
        assert!(!secret_service_from_bus(true, "", ""));
    }

    #[test]
    fn status_words_are_stable_for_scripts() {
        assert_eq!(Status::Ok.as_str(), "ok");
        assert_eq!(Status::Fail.as_str(), "fail");
        assert!(Status::Fail.is_fail());
        assert!(!Status::Warn.is_fail());
    }

    #[test]
    fn a_fixture_binary_version_probe_executes_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("cloud-hypervisor");
        std::fs::write(&bin, "#!/bin/sh\necho 'cloud-hypervisor v53.0'\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let check = probe_version_binary("cloud-hypervisor", &bin, "v53.0", "missing");
        assert_eq!(check.status, Status::Ok, "{}", check.detail);
        assert!(check.detail.contains("v53.0"));

        std::fs::write(&bin, "#!/bin/sh\necho 'cloud-hypervisor v1.0'\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let check = probe_version_binary("cloud-hypervisor", &bin, "v53.0", "missing");
        assert_eq!(check.status, Status::Fail, "{}", check.detail);
    }

    #[test]
    fn a_fixture_nbd_helper_probe_uses_sudo_and_requires_success() {
        let dir = tempfile::tempdir().unwrap();
        let helper = dir.path().join("asterism-nbd");
        let sudo = dir.path().join("sudo");
        std::fs::write(
            &sudo,
            "#!/bin/sh\n[ \"$1\" = -n ] || exit 90\nshift\nexec \"$@\"\n",
        )
        .unwrap();
        std::fs::write(
            &helper,
            "#!/bin/sh\n[ \"$1\" = --probe ] || exit 91\nprintf 'asterism-nbd: privileged boundary probe succeeded\\n' >&2\n",
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&helper, std::fs::Permissions::from_mode(0o755)).unwrap();
            std::fs::set_permissions(&sudo, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let check = probe_nbd_helper_through(&helper, &sudo);
        assert_eq!(check.status, Status::Ok, "{}", check.detail);

        std::fs::write(
            &helper,
            "#!/bin/sh\nprintf 'asterism-nbd: privileged boundary probe failed\\n' >&2\nexit 2\n",
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&helper, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let check = probe_nbd_helper_through(&helper, &sudo);
        assert_eq!(check.status, Status::Fail, "{}", check.detail);
    }

    #[cfg(unix)]
    #[test]
    fn kvm_probe_requires_read_write_not_read_only_access() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let kvm = dir.path().join("kvm");
        std::fs::write(&kvm, b"fixture").unwrap();
        std::fs::set_permissions(&kvm, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(probe_kvm(&kvm).status, Status::Ok);

        std::fs::set_permissions(&kvm, std::fs::Permissions::from_mode(0o400)).unwrap();
        let read_only = probe_kvm(&kvm);
        assert_eq!(read_only.status, Status::Fail, "{}", read_only.detail);
        assert!(read_only.detail.contains("read-write"));
        assert_eq!(
            read_only.fix.map(|fix| fix.command),
            Some("sudo usermod -aG kvm $USER && newgrp kvm".to_owned())
        );
    }

    // ---- every row knows its own remedy -------------------------------------

    fn service_state(installed: bool, loaded: bool) -> crate::service::State {
        crate::service::State {
            unit: PathBuf::from("/nowhere/asterism.service"),
            installed,
            loaded,
            pid: None,
            program: None,
            notes: Vec::new(),
        }
    }

    /// A path that is not on any machine, which is what makes each of these
    /// probes take its failing branch.
    fn absent() -> &'static Path {
        Path::new("/nonexistent/asterism/doctor-fixture")
    }

    /// Every not-ok row this module can produce, driven through the pure
    /// half of each probe with the machine's answer injected.
    ///
    /// Adding a row without adding it here fails
    /// `every_row_this_host_prints_has_a_failure_mode_that_names_a_fix`,
    /// which is the point: a row whose failure has no remedy is a bug report
    /// with an `ast doctor` prefix.
    fn every_failure_mode() -> Vec<Check> {
        let mut modes = vec![
            file_or_exec("ast", absent(), "ast is not beside this binary"),
            file_or_exec("astd", absent(), "astd is not beside ast"),
            service_row("launchd", Err("no service manager here".into())),
            service_row("launchd", Ok(&service_state(false, false))),
            service_row("systemd (user)", Ok(&service_state(true, false))),
            curl_row(None),
            receipt_row(absent(), false),
            // Linux rows. Compiled everywhere in test builds precisely so
            // that a macOS laptop still holds the Linux rows to this.
            probe_kvm(absent()),
            probe_version_binary("cloud-hypervisor", absent(), "v53.0", "not installed"),
            probe_version_binary("virtiofsd", absent(), "1.14.0", "not installed"),
            linux_pins_row(absent(), None),
            linux_pins_row(absent(), Some("CLOUD_HYPERVISOR_VERSION=v53.0\n".into())),
            probe_nbd_helper(absent()),
            linger_row("alice", Some("Linger=no\n")),
            linger_row("alice", Some("Name=alice\n")),
            linger_row("", None),
            secret_service_row(BusAnswer::Refused("no such name".into())),
            secret_service_row(BusAnswer::Unprobeable),
            sleep_row(InhibitProbe::Refused("Failed to connect to bus".into())),
            sleep_row(InhibitProbe::NotExecutable),
            macos_keychain_row(false, "SecKeychainCopySearchList: locked"),
            // The macOS-only row, likewise.
            vz_row(None, None, Ok(PathBuf::from("/unused"))),
            vz_row(
                Some(absent()),
                Some(Signature::Unaskable),
                Ok(PathBuf::from("/unused")),
            ),
            vz_row(
                Some(absent()),
                Some(Signature::Unentitled),
                Ok(PathBuf::from("/unused")),
            ),
            vz_row(
                Some(absent()),
                Some(Signature::Entitled),
                Err("no guest-control agent".into()),
            ),
        ];
        // `sudo -n` against a helper that refuses: the boundary is there and
        // does not answer, which is the other way this row fails.
        let dir = tempfile::tempdir().unwrap();
        let helper = dir.path().join("asterism-nbd");
        std::fs::write(&helper, b"not a helper").unwrap();
        modes.push(probe_nbd_helper_through(&helper, absent()));
        modes
    }

    #[test]
    fn every_failing_row_names_a_command_to_run() {
        for check in every_failure_mode() {
            assert_ne!(
                check.status,
                Status::Ok,
                "{} is not a failure mode",
                check.name
            );
            let fix = check
                .fix
                .as_ref()
                .unwrap_or_else(|| panic!("{}: {} has no fix", check.name, check.detail));
            assert!(
                !fix.command.trim().is_empty(),
                "{}: empty command",
                check.name
            );
            // A remedy is something to type, not a sentence about typing.
            assert!(
                !fix.command.contains('\n'),
                "{}: {} is not one line",
                check.name,
                fix.command
            );
        }
    }

    /// The other half of the promise: what this host actually prints is
    /// covered by the enumeration above, and any row of it that is not `ok`
    /// carries its remedy on the real machine too.
    #[test]
    fn every_row_this_host_prints_has_a_failure_mode_that_names_a_fix() {
        let covered: std::collections::BTreeSet<&str> = every_failure_mode()
            .iter()
            .map(|check| check.name)
            .collect();
        for check in run() {
            if check.status == Status::Skip {
                continue;
            }
            assert!(
                covered.contains(check.name),
                "doctor row {:?} has no enumerated failure mode",
                check.name
            );
            if check.status != Status::Ok {
                assert!(
                    check.fix.is_some(),
                    "{} is {} on this host and names no fix: {}",
                    check.name,
                    check.status.as_str(),
                    check.detail
                );
            }
        }
    }

    /// The vz row is the whole macOS backend story in one line, so each of
    /// its failures has to point at a different command.
    #[test]
    fn the_vz_row_distinguishes_absent_unsigned_and_agentless() {
        let helper = Path::new("/opt/asterism/bin/astd-vz");
        let agent = PathBuf::from("/opt/asterism/lib/asterism/guest/bin/asterism-guest");

        let absent = vz_row(None, None, Ok(agent.clone()));
        assert_eq!(absent.status, Status::Fail);
        assert!(absent.fix.unwrap().command.contains("install.sh"));

        let unsigned = vz_row(Some(helper), Some(Signature::Unentitled), Ok(agent.clone()));
        assert_eq!(unsigned.status, Status::Fail);
        assert!(unsigned.detail.contains(VZ_ENTITLEMENT));
        assert_eq!(unsigned.fix.unwrap().command, "scripts/sign-vz.sh");

        let no_codesign = vz_row(Some(helper), Some(Signature::Unaskable), Ok(agent.clone()));
        assert_eq!(no_codesign.fix.unwrap().command, "xcode-select --install");

        let no_agent = vz_row(
            Some(helper),
            Some(Signature::Entitled),
            Err("nothing under /usr/lib/asterism".into()),
        );
        assert_eq!(no_agent.status, Status::Fail);
        assert!(no_agent.detail.contains("nothing under /usr/lib/asterism"));

        let ready = vz_row(Some(helper), Some(Signature::Entitled), Ok(agent));
        assert_eq!(ready.status, Status::Ok, "{}", ready.detail);
        assert!(ready.fix.is_none());
        assert!(ready.detail.contains("astd-vz"));
    }

    /// The entitlement strings are what `codesign` is grepped for, so they
    /// have to be the same two the helper is actually signed with.
    #[test]
    fn the_entitlements_named_here_are_the_ones_the_helper_is_signed_with() {
        let entitlements = include_str!("../../asterism-vz/vz.entitlements");
        assert!(entitlements.contains(VZ_ENTITLEMENT), "{entitlements}");
        assert!(
            entitlements.contains(VZ_NETWORK_CLIENT_ENTITLEMENT),
            "{entitlements}"
        );
    }

    /// The other side of the promise: a row that is `ok` offers nothing to
    /// run, because there is nothing to repair.
    #[test]
    fn a_working_bus_inhibitor_and_keychain_offer_no_command() {
        for ok in [
            secret_service_row(BusAnswer::Named),
            secret_service_row(BusAnswer::Pinged),
            sleep_row(InhibitProbe::Held),
            macos_keychain_row(true, ""),
            curl_row(Some(Path::new("/usr/bin/curl"))),
            receipt_row(
                Path::new("/opt/asterism/share/asterism/install-receipt.env"),
                true,
            ),
            service_row("launchd", Ok(&service_state(true, true))),
        ] {
            assert_eq!(ok.status, Status::Ok, "{}", ok.detail);
            assert!(ok.fix.is_none(), "{} offers a needless command", ok.name);
        }
    }

    #[test]
    fn lingering_off_is_repaired_by_the_command_for_this_account() {
        let off = linger_row("alice", Some("Linger=no\n"));
        assert_eq!(off.status, Status::Fail);
        assert_eq!(
            off.fix.map(|fix| fix.command),
            Some("loginctl enable-linger alice".to_owned())
        );
        // No account in the environment still leaves something runnable.
        assert_eq!(
            linger_row("", None).fix.map(|fix| fix.command),
            Some("loginctl enable-linger $USER".to_owned())
        );
        assert!(linger_row("alice", Some("Linger=yes\n")).fix.is_none());
    }
}
