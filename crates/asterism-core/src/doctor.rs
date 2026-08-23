//! Host integration diagnostics — `ast doctor`.
//!
//! A supported Linux machine is one that can install from a checksummed
//! archive, keep `astd` running after logout and reboot, prevent idle sleep
//! while guests run, store secrets in Secret Service, and find the pinned
//! Cloud Hypervisor and virtiofsd helpers beside the daemon. This module
//! reports those facts as independent checks so a human (or `ast doctor`)
//! can see exactly which one is missing.

use std::path::{Path, PathBuf};

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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxPins {
    pub cloud_hypervisor_version: String,
    pub cloud_hypervisor_aarch64_sha256: String,
    pub cloud_hypervisor_x86_64_sha256: String,
    pub virtiofsd_version: String,
    pub virtiofsd_tarball_sha256: String,
}

impl LinuxPins {
    /// Parse the lock file the installer and packager both source.
    pub fn parse(text: &str) -> Result<Self> {
        Ok(Self {
            cloud_hypervisor_version: required_pin(text, "CLOUD_HYPERVISOR_VERSION")?,
            cloud_hypervisor_aarch64_sha256: required_pin(text, "CLOUD_HYPERVISOR_AARCH64_SHA256")?,
            cloud_hypervisor_x86_64_sha256: required_pin(text, "CLOUD_HYPERVISOR_X86_64_SHA256")?,
            virtiofsd_version: required_pin(text, "VIRTIOFSD_VERSION")?,
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

#[cfg(target_os = "linux")]
fn on_path(name: &str) -> bool {
    std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
        .any(|dir| dir.join(name).is_file())
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

fn file_check(name: &'static str, path: &Path, missing: &str) -> Check {
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
        checks.push(file_check("ast", &ast, "ast is not beside this binary"));
    }
    if let Some(astd) = sibling("astd") {
        checks.push(file_check(
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
                    // A capable host that has not run `ast service install`
                    // yet is incomplete, not broken.
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

fn secret_store_check() -> Check {
    #[cfg(target_os = "linux")]
    {
        let bus = std::env::var_os("DBUS_SESSION_BUS_ADDRESS").is_some()
            || std::env::var_os("XDG_RUNTIME_DIR").is_some();
        if bus {
            Check {
                name: "secrets",
                status: Status::Ok,
                detail: format!(
                    "{} is the Linux store; no plaintext fallback is used",
                    secret_store_name()
                ),
            }
        } else {
            Check {
                name: "secrets",
                status: Status::Warn,
                detail: format!(
                    "{} needs a session bus (gnome-keyring, kwallet, or keepassxc). \
                     Without one, secret material cannot be stored.",
                    secret_store_name()
                ),
            }
        }
    }
    #[cfg(target_os = "macos")]
    {
        Check {
            name: "secrets",
            status: Status::Ok,
            detail: format!(
                "{} holds secret material; no file fallback",
                secret_store_name()
            ),
        }
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

fn sleep_check() -> Check {
    #[cfg(target_os = "linux")]
    {
        if on_path("systemd-inhibit") {
            Check {
                name: "sleep",
                status: Status::Ok,
                detail: sleep_mechanism_name().into(),
            }
        } else {
            Check {
                name: "sleep",
                status: Status::Fail,
                detail: "systemd-inhibit is not on PATH, so running guests cannot block idle sleep"
                    .into(),
            }
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

    let packaged = prefix_dir().map(|prefix| receipt_path(&prefix).is_file()) == Some(true);
    if let Some(chv) = sibling("cloud-hypervisor") {
        checks.push(if packaged {
            file_check(
                "cloud-hypervisor",
                &chv,
                "pinned Cloud Hypervisor is not installed beside astd",
            )
        } else if chv.is_file() {
            file_check("cloud-hypervisor", &chv, "")
        } else {
            Check {
                name: "cloud-hypervisor",
                status: Status::Warn,
                detail: "no install receipt; the packaged Cloud Hypervisor helper is not beside this binary".into(),
            }
        });
    }
    if let Some(virtiofsd) = sibling("virtiofsd") {
        checks.push(if packaged {
            file_check(
                "virtiofsd",
                &virtiofsd,
                "pinned virtiofsd is not installed beside astd",
            )
        } else if virtiofsd.is_file() {
            file_check("virtiofsd", &virtiofsd, "")
        } else {
            Check {
                name: "virtiofsd",
                status: Status::Warn,
                detail:
                    "no install receipt; the packaged virtiofsd helper is not beside this binary"
                        .into(),
            }
        });
    }

    if let Some(prefix) = prefix_dir() {
        let lock = prefix.join("share/asterism/linux-components.env");
        match std::fs::read_to_string(&lock) {
            Ok(text) => match LinuxPins::parse(&text) {
                Ok(pins) => checks.push(Check {
                    name: "linux-pins",
                    status: Status::Ok,
                    detail: format!(
                        "Cloud Hypervisor {} and virtiofsd {}",
                        pins.cloud_hypervisor_version, pins.virtiofsd_version
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
                status: if packaged { Status::Fail } else { Status::Warn },
                detail: format!("{} is missing", lock.display()),
            }),
        }
        let nbd = PathBuf::from("/usr/local/libexec/asterism/asterism-nbd");
        checks.push(if nbd.is_file() {
            Check {
                name: "nbd-helper",
                status: Status::Ok,
                detail: nbd.display().to_string(),
            }
        } else {
            Check {
                name: "nbd-helper",
                status: Status::Warn,
                detail: format!(
                    "{} is missing; remote volumes cannot attach until install.sh configures NBD",
                    nbd.display()
                ),
            }
        });
    }

    checks.push(linger_check());
    checks
}

#[cfg(target_os = "linux")]
fn linger_check() -> Check {
    let user = std::env::var("USER").unwrap_or_default();
    let output = std::process::Command::new("loginctl")
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
    fn the_committed_linux_pins_match_the_adr() {
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
        assert_eq!(pins.virtiofsd_version, "v1.14.0");
        assert_eq!(
            pins.virtiofsd_tarball_sha256,
            "52b66e449ca583b4f050a2bff327ff812211a2c349b4130279fcfc6a64540f04"
        );
    }

    #[test]
    fn a_truncated_lock_file_is_refused() {
        let err = LinuxPins::parse("CLOUD_HYPERVISOR_VERSION=v53.0\n").unwrap_err();
        assert!(
            err.to_string().contains("CLOUD_HYPERVISOR_AARCH64_SHA256"),
            "{err}"
        );
    }

    #[test]
    fn status_words_are_stable_for_scripts() {
        assert_eq!(Status::Ok.as_str(), "ok");
        assert_eq!(Status::Fail.as_str(), "fail");
        assert!(Status::Fail.is_fail());
        assert!(!Status::Warn.is_fail());
    }
}
