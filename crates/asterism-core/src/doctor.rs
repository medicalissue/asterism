//! Host integration diagnostics — `ast doctor`.
//!
//! A supported Linux machine is one that can install from a checksummed
//! archive, keep `astd` running after logout and reboot, prevent idle sleep
//! while guests run, store secrets in Secret Service, and execute the pinned
//! Cloud Hypervisor, virtiofsd, and NBD helper — not merely find them on
//! disk. This module reports those facts as independent checks so a human
//! (or `ast doctor`) can see exactly which one is missing.

use std::path::{Path, PathBuf};
#[cfg(any(test, not(windows)))]
use std::process::Command;

use anyhow::{bail, Result};

/// One row of `ast doctor`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Check {
    pub name: &'static str,
    pub status: Status,
    pub detail: String,
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
    if !path.is_file() {
        return Check {
            name,
            status: Status::Fail,
            detail: format!("{missing} ({})", path.display()),
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
                }
            }
        }
        Err(error) => Check {
            name,
            status: Status::Fail,
            detail: format!("could not execute {}: {error}", path.display()),
        },
    }
}

#[cfg(not(target_os = "linux"))]
fn skip(name: &'static str, detail: impl Into<String>) -> Check {
    Check {
        name,
        status: Status::Skip,
        detail: detail.into(),
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

    match crate::service::manager() {
        Ok(manager) => match manager.status() {
            Ok(state) => {
                let status = if state.installed && state.loaded {
                    Status::Ok
                } else {
                    Status::Warn
                };
                checks.push(Check {
                    name: "service",
                    status,
                    detail: format!("{}: {}", manager.mechanism(), state.summary()),
                });
            }
            Err(error) => checks.push(Check {
                name: "service",
                status: Status::Fail,
                detail: format!("{error:#}"),
            }),
        },
        Err(error) => checks.push(Check {
            name: "service",
            status: Status::Fail,
            detail: format!("{error:#}"),
        }),
    }

    checks.push(secret_store_check());
    checks.push(sleep_check());

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
        if receipt.is_file() {
            checks.push(Check {
                name: "receipt",
                status: Status::Ok,
                detail: receipt.display().to_string(),
            });
        } else {
            checks.push(Check {
                name: "receipt",
                status: Status::Warn,
                detail: format!(
                    "{} is missing — this tree was not installed by install.sh",
                    receipt.display()
                ),
            });
        }
    }

    checks
}

fn file_or_exec(name: &'static str, path: &Path, missing: &str) -> Check {
    if path.is_file() {
        Check {
            name,
            status: Status::Ok,
            detail: path.display().to_string(),
        }
    } else {
        Check {
            name,
            status: Status::Fail,
            detail: format!("{missing} ({})", path.display()),
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
        }
    }
}

#[cfg(target_os = "macos")]
fn probe_macos_keychain() -> Check {
    match Command::new("security").arg("list-keychains").output() {
        Ok(out) if out.status.success() => Check {
            name: "secrets",
            status: Status::Ok,
            detail: format!(
                "{} answered list-keychains; no file fallback",
                secret_store_name()
            ),
        },
        Ok(out) => Check {
            name: "secrets",
            status: Status::Fail,
            detail: format!(
                "security list-keychains failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            ),
        },
        Err(error) => Check {
            name: "secrets",
            status: Status::Fail,
            detail: format!("could not execute security(1) to probe the login Keychain: {error}"),
        },
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
            return Check {
                name: "secrets",
                status: Status::Ok,
                detail: format!(
                    "{} answered on the session bus; no plaintext fallback",
                    secret_store_name()
                ),
            };
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
        Ok(out) if out.status.success() => Check {
            name: "secrets",
            status: Status::Ok,
            detail: format!(
                "{} answered Peer.Ping; no plaintext fallback",
                secret_store_name()
            ),
        },
        Ok(out) => Check {
            name: "secrets",
            status: Status::Warn,
            detail: format!(
                "{} needs a session bus provider (gnome-keyring, kwallet, or keepassxc): {}",
                secret_store_name(),
                String::from_utf8_lossy(&out.stderr).trim()
            ),
        },
        Err(_) => Check {
            name: "secrets",
            status: Status::Warn,
            detail: format!(
                "{} could not be probed (busctl/dbus-send missing). Without a Secret Service provider, secret material cannot be stored.",
                secret_store_name()
            ),
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
            Ok(out) if out.status.success() => Check {
                name: "sleep",
                status: Status::Ok,
                detail: format!("{} (inhibit probe succeeded)", sleep_mechanism_name()),
            },
            Ok(out) => Check {
                name: "sleep",
                status: Status::Fail,
                detail: format!(
                    "systemd-inhibit probe failed: {}",
                    String::from_utf8_lossy(&out.stderr).trim()
                ),
            },
            Err(_) => Check {
                name: "sleep",
                status: Status::Fail,
                detail:
                    "systemd-inhibit is not executable, so running guests cannot block idle sleep"
                        .into(),
            },
        }
    }
    #[cfg(target_os = "macos")]
    {
        Check {
            name: "sleep",
            status: Status::Ok,
            detail: sleep_mechanism_name().into(),
        }
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        Check {
            name: "sleep",
            status: Status::Fail,
            detail: "this device cannot prevent sleep yet".into(),
        }
    }
}

#[cfg(target_os = "linux")]
fn linux_checks() -> Vec<Check> {
    let mut checks = Vec::new();
    let kvm = Path::new("/dev/kvm");
    if kvm.exists() {
        let readable = std::fs::File::open(kvm).is_ok();
        checks.push(Check {
            name: "kvm",
            status: if readable { Status::Ok } else { Status::Fail },
            detail: if readable {
                "/dev/kvm is present and readable".into()
            } else {
                "/dev/kvm exists but is not readable; add this user to the kvm group and log in again"
                    .into()
            },
        });
    } else {
        checks.push(Check {
            name: "kvm",
            status: Status::Fail,
            detail: "/dev/kvm is missing; Cloud Hypervisor cannot run".into(),
        });
    }

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

    if let Some(chv) = sibling("cloud-hypervisor") {
        checks.push(probe_version_binary(
            "cloud-hypervisor",
            &chv,
            chv_pin,
            "pinned Cloud Hypervisor is not installed beside astd",
        ));
    }
    if let Some(virtiofsd) = sibling("virtiofsd") {
        checks.push(probe_version_binary(
            "virtiofsd",
            &virtiofsd,
            virtio_pin,
            "pinned virtiofsd is not installed beside astd",
        ));
    }

    if let Some(prefix) = prefix_dir() {
        let lock = prefix.join("share/asterism/linux-components.env");
        match std::fs::read_to_string(&lock) {
            Ok(text) => match LinuxPins::parse(&text) {
                Ok(parsed) => checks.push(Check {
                    name: "linux-pins",
                    status: Status::Ok,
                    detail: format!(
                        "Cloud Hypervisor {} and virtiofsd {}",
                        parsed.cloud_hypervisor_version, parsed.virtiofsd_version
                    ),
                }),
                Err(error) => checks.push(Check {
                    name: "linux-pins",
                    status: Status::Fail,
                    detail: format!("{error:#}"),
                }),
            },
            Err(_) => checks.push(Check {
                name: "linux-pins",
                status: Status::Warn,
                detail: format!("{} is missing", lock.display()),
            }),
        }
        let nbd = PathBuf::from("/usr/local/libexec/asterism/asterism-nbd");
        checks.push(probe_nbd_helper(&nbd));
    }

    checks.push(linger_check());
    checks
}

#[cfg(any(test, target_os = "linux"))]
fn probe_nbd_helper(nbd: &Path) -> Check {
    if !nbd.is_file() {
        return Check {
            name: "nbd-helper",
            status: Status::Warn,
            detail: format!(
                "{} is missing; remote volumes cannot attach until install.sh configures NBD",
                nbd.display()
            ),
        };
    }
    match run_probe(nbd, &[]) {
        Ok(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr);
            if nbd_helper_executed(&stderr) {
                Check {
                    name: "nbd-helper",
                    status: Status::Ok,
                    detail: format!("helper executed ({})", nbd.display()),
                }
            } else {
                Check {
                    name: "nbd-helper",
                    status: Status::Fail,
                    detail: format!(
                        "{} ran but did not identify as asterism-nbd: {}",
                        nbd.display(),
                        stderr.trim()
                    ),
                }
            }
        }
        Err(error) => Check {
            name: "nbd-helper",
            status: Status::Fail,
            detail: format!("could not execute {}: {error}", nbd.display()),
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
            let text = String::from_utf8_lossy(&out.stdout);
            match parse_linger_property(&text) {
                Some(true) => Check {
                    name: "linger",
                    status: Status::Ok,
                    detail: "lingering is on; the user systemd instance survives logout and reboot"
                        .into(),
                },
                Some(false) => Check {
                    name: "linger",
                    status: Status::Fail,
                    detail: format!(
                        "lingering is off; astd dies at logout. Enable it with: loginctl enable-linger {user}"
                    ),
                },
                None => Check {
                    name: "linger",
                    status: Status::Warn,
                    detail: format!("loginctl did not report Linger ({})", text.trim()),
                },
            }
        }
        _ => Check {
            name: "linger",
            status: Status::Fail,
            detail: format!(
                "loginctl is unavailable; enable lingering with: loginctl enable-linger {user}"
            ),
        },
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
    fn nbd_helper_execution_is_the_identity_prefix_not_a_zero_exit() {
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
    fn a_fixture_nbd_helper_probe_requires_the_identity_prefix() {
        let dir = tempfile::tempdir().unwrap();
        let helper = dir.path().join("asterism-nbd");
        std::fs::write(
            &helper,
            "#!/bin/sh\nprintf 'asterism-nbd: must run as root through the installed sudo policy\\n' >&2\nexit 2\n",
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&helper, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let check = probe_nbd_helper(&helper);
        assert_eq!(check.status, Status::Ok, "{}", check.detail);

        std::fs::write(&helper, "#!/bin/sh\necho silent\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&helper, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let check = probe_nbd_helper(&helper);
        assert_eq!(check.status, Status::Fail, "{}", check.detail);
    }
}
