//! Errors that know their own remedy.
//!
//! An error message says what went wrong; a [`Fix`] says what to type next.
//! The two travel together so the CLI can print them together, and so
//! `ast doctor` can put the same sentence beside a failing row that
//! `ast pull` puts under a failed pull.
//!
//! The remedy is host-shaped: the package that carries `curl` is named
//! differently by `apt-get`, `dnf`, `pacman`, `zypper`, Homebrew and
//! `winget`, and telling a Fedora user to run `apt-get` is barely better
//! than telling them nothing. [`host_packager`] picks one, and
//! [`install_hint`] turns a tool name into the command for it.
//!
//! Attach a remedy to an error with [`Fixable`], which is a plain
//! [`std::error::Error`] and so survives `anyhow` context as a *cause*
//! rather than displacing the sentence a caller wrapped around it.
//! [`of`] pulls it back out of a finished `anyhow::Error`.

use std::fmt;

/// What to run to repair something, and who the command is written for.
///
/// `note` names the platform whose words these are. It is `None` when the
/// host was identified confidently, and `Some` when the choice was a guess
/// worth admitting to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fix {
    /// The command to run, verbatim. One line, copy-pasteable.
    pub command: String,
    /// Which platform the command is written for, when that is worth saying.
    pub note: Option<String>,
}

impl Fix {
    /// A remedy that needs no caveat.
    pub fn new(command: impl Into<String>) -> Self {
        Self {
            command: command.into(),
            note: None,
        }
    }

    /// A remedy plus the platform it is written for.
    pub fn noted(command: impl Into<String>, note: impl Into<String>) -> Self {
        Self {
            command: command.into(),
            note: Some(note.into()),
        }
    }
}

impl fmt::Display for Fix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.note {
            Some(note) => write!(f, "{}   # {note}", self.command),
            None => f.write_str(&self.command),
        }
    }
}

/// An error that carries the command which repairs it.
///
/// Wrapping this in `anyhow` context keeps it in the chain, so the remedy is
/// still reachable from the outermost error no matter how many layers of
/// "while doing X" a call stack added on the way up.
#[derive(Debug, Clone)]
pub struct Fixable {
    message: String,
    fix: Fix,
}

impl Fixable {
    pub fn new(message: impl Into<String>, fix: Fix) -> Self {
        Self {
            message: message.into(),
            fix,
        }
    }

    pub fn fix(&self) -> &Fix {
        &self.fix
    }
}

impl fmt::Display for Fixable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for Fixable {}

/// The remedy this error chain carries.
///
/// The chain is walked from the outside in and the first [`Fixable`] link
/// wins. In practice that is the leaf — the thing that actually failed is the
/// thing that knows what to do about it, and every `with_context` above it is
/// narration.
pub fn of(error: &anyhow::Error) -> Option<&Fix> {
    error
        .chain()
        .find_map(|link| link.downcast_ref::<Fixable>())
        .map(Fixable::fix)
}

/// The package managers Asterism knows how to speak to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Packager {
    Apt,
    Dnf,
    Pacman,
    Zypper,
    Brew,
    Winget,
}

impl Packager {
    /// The human name of the platform family this packager belongs to.
    pub fn platform(self) -> &'static str {
        match self {
            Self::Apt => "Debian/Ubuntu",
            Self::Dnf => "Fedora/RHEL",
            Self::Pacman => "Arch",
            Self::Zypper => "openSUSE",
            Self::Brew => "Homebrew",
            Self::Winget => "Windows",
        }
    }

    /// `<manager> install <package>`, with the privilege each one needs.
    pub fn install(self, package: &str) -> String {
        match self {
            Self::Apt => format!("sudo apt-get install -y {package}"),
            Self::Dnf => format!("sudo dnf install -y {package}"),
            Self::Pacman => format!("sudo pacman -S --noconfirm {package}"),
            Self::Zypper => format!("sudo zypper install -y {package}"),
            Self::Brew => format!("brew install {package}"),
            Self::Winget => format!("winget install --id {package}"),
        }
    }
}

/// Which package manager to speak to on this host, and whether that was a
/// guess.
///
/// macOS and Windows have one answer each. Linux is read out of
/// `/etc/os-release` — `ID` first, then `ID_LIKE`, which is what a derivative
/// distribution fills in precisely so that a question like this can be
/// answered. When neither names a family we recognise, the manager that is
/// actually installed decides; when even that is silent the answer is a guess
/// and says so.
pub fn host_packager() -> (Packager, bool) {
    #[cfg(target_os = "macos")]
    {
        (Packager::Brew, false)
    }
    #[cfg(windows)]
    {
        (Packager::Winget, false)
    }
    #[cfg(not(any(target_os = "macos", windows)))]
    {
        if let Ok(text) = std::fs::read_to_string("/etc/os-release") {
            if let Some(packager) = packager_from_os_release(&text) {
                return (packager, false);
            }
        }
        for (binary, packager) in [
            ("/usr/bin/apt-get", Packager::Apt),
            ("/usr/bin/dnf", Packager::Dnf),
            ("/usr/bin/pacman", Packager::Pacman),
            ("/usr/bin/zypper", Packager::Zypper),
        ] {
            if std::path::Path::new(binary).exists() {
                return (packager, false);
            }
        }
        (Packager::Apt, true)
    }
}

/// Read a package manager out of the `ID`/`ID_LIKE` lines of `/etc/os-release`.
///
/// Public because it is the only part of [`host_packager`] a test on any host
/// can exercise: the rest reads the machine it is running on.
pub fn packager_from_os_release(text: &str) -> Option<Packager> {
    let mut id = None;
    let mut id_like = None;
    for line in text.lines() {
        let line = line.trim();
        let (key, value) = match line.split_once('=') {
            Some(pair) => pair,
            None => continue,
        };
        let value = value.trim().trim_matches('"').to_ascii_lowercase();
        match key.trim() {
            "ID" => id = Some(value),
            "ID_LIKE" => id_like = Some(value),
            _ => {}
        }
    }
    // `ID` is one word; `ID_LIKE` is a space-separated list, most-similar
    // first, so scanning it in order is what its own spec asks for.
    id.iter()
        .flat_map(|id| id.split_whitespace())
        .chain(id_like.iter().flat_map(|like| like.split_whitespace()))
        .find_map(family_packager)
}

fn family_packager(family: &str) -> Option<Packager> {
    match family {
        "debian" | "ubuntu" | "raspbian" | "linuxmint" | "pop" | "elementary" => {
            Some(Packager::Apt)
        }
        "fedora" | "rhel" | "centos" | "rocky" | "almalinux" | "amzn" => Some(Packager::Dnf),
        "arch" | "archarm" | "manjaro" | "endeavouros" => Some(Packager::Pacman),
        "opensuse" | "opensuse-leap" | "opensuse-tumbleweed" | "suse" | "sles" => {
            Some(Packager::Zypper)
        }
        _ => None,
    }
}

/// How Asterism's own pinned helpers are restored. They are not in anybody's
/// package repository — the installer fetches them by digest.
///
/// Public because it is also the remedy for everything else the installer
/// puts on a device: the guest-control artifact, the component lock, the
/// install receipt. `ast doctor` names it for those rows.
pub const REINSTALL: &str = "curl -fsSL https://asterism.run/install.sh | sh";

/// The package that carries `tool`, in the words of `packager`.
///
/// `None` means Asterism does not know how to install it here, which is an
/// honest answer: a wrong package name costs more than no package name.
fn package_for(tool: &str, packager: Packager) -> Option<&'static str> {
    // Every backend helper's binary name maps to the package a human would
    // actually install, which is rarely the binary's own name.
    let family = match tool {
        "curl" => "curl",
        "gzip" => "gzip",
        "xz" => "xz",
        "xorriso" => "xorriso",
        "ssh-keygen" => "openssh",
        "e2fsck" | "mke2fs" | "debugfs" | "resize2fs" | "dumpe2fs" => "e2fsprogs",
        "unshare" | "nsenter" => "util-linux",
        "newuidmap" | "newgidmap" => "uidmap",
        "slirp4netns" => "slirp4netns",
        "ip" => "iproute2",
        // The Secret Service and the sleep inhibitor are host integration
        // rather than backend tooling, but they are installed the same way
        // and `ast doctor` asks for them by binary name too.
        "gnome-keyring" | "gnome-keyring-daemon" => "gnome-keyring",
        "systemd-inhibit" | "loginctl" => "systemd",
        "qemu-img" => "qemu",
        other if other.starts_with("qemu-system-") => "qemu",
        _ => return None,
    };
    Some(match (family, packager) {
        // Neither of these host-integration packages exists off Linux, and a
        // name that is not there is worse than no name at all.
        ("gnome-keyring" | "systemd", Packager::Brew | Packager::Winget) => return None,
        ("curl", Packager::Winget) => "cURL.cURL",
        ("gzip", Packager::Winget) => "GnuWin32.Gzip",
        ("xz", Packager::Apt) => "xz-utils",
        ("xorriso", Packager::Pacman) => "libisoburn",
        ("openssh", Packager::Apt) => "openssh-client",
        ("openssh", Packager::Dnf) => "openssh-clients",
        ("uidmap", Packager::Dnf) => "shadow-utils",
        ("uidmap", Packager::Pacman | Packager::Zypper) => "shadow",
        ("iproute2", Packager::Dnf) => "iproute",
        ("qemu", Packager::Apt) => "qemu-system",
        ("qemu", Packager::Dnf) => "qemu-system-x86",
        ("qemu", Packager::Winget) => "SoftwareFreedomConservancy.QEMU",
        (family, _) => family,
    })
}

/// How to install the external tool named `tool` on this host.
///
/// Asterism's own pinned helpers get the installer instead of a package
/// manager, because that is where they actually come from.
pub fn install_hint(tool: &str) -> Option<Fix> {
    let stem = tool
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(tool)
        .trim_end_matches(".exe");
    if matches!(
        stem,
        "cloud-hypervisor"
            | "virtiofsd"
            | "asterism-nbd"
            | "asterism-vz-helper"
            // The signed macOS helper, by the name every install lane and
            // `codesign` uses for it.
            | "astd-vz"
            | "ast"
            | "astd"
    ) {
        return Some(Fix::noted(
            REINSTALL,
            format!("{stem} is a pinned Asterism component, not a distro package"),
        ));
    }
    let (packager, guessed) = host_packager();
    let package = package_for(stem, packager)?;
    let command = packager.install(package);
    Some(if guessed {
        Fix::noted(
            command,
            format!("{} — or this platform's equivalent", packager.platform()),
        )
    } else {
        Fix::new(command)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fix_survives_being_wrapped_in_context() {
        let error = anyhow::Error::new(Fixable::new(
            "curl not found — is it installed and on PATH?",
            Fix::new("sudo apt-get install -y curl"),
        ))
        .context("opening docker.io/library/busybox")
        .context("fetching the guest kernel from https://example/vmlinuz");
        assert_eq!(
            of(&error).map(|fix| fix.command.as_str()),
            Some("sudo apt-get install -y curl")
        );
        // Wrapping must not steal the outermost sentence.
        assert_eq!(
            error.to_string(),
            "fetching the guest kernel from https://example/vmlinuz"
        );
    }

    #[test]
    fn an_error_without_a_fix_has_none() {
        let error = anyhow::anyhow!("no idea").context("while trying");
        assert!(of(&error).is_none());
    }

    #[test]
    fn the_leaf_that_failed_is_the_one_that_names_the_fix() {
        // Narration stacks up; the remedy stays with the thing that knows it.
        let error = anyhow::Error::new(Fixable::new("inner", Fix::new("inner-fix")))
            .context("middle")
            .context("outer");
        assert_eq!(
            of(&error).map(|fix| fix.command.as_str()),
            Some("inner-fix")
        );
    }

    #[test]
    fn os_release_id_picks_the_family() {
        assert_eq!(
            packager_from_os_release("ID=ubuntu\nID_LIKE=debian\n"),
            Some(Packager::Apt)
        );
        assert_eq!(
            packager_from_os_release("ID=\"fedora\"\nVERSION_ID=41\n"),
            Some(Packager::Dnf)
        );
        assert_eq!(
            packager_from_os_release("ID=arch\n"),
            Some(Packager::Pacman)
        );
        assert_eq!(
            packager_from_os_release("ID=opensuse-tumbleweed\n"),
            Some(Packager::Zypper)
        );
    }

    #[test]
    fn os_release_falls_back_to_id_like_for_a_derivative() {
        // Nobody has heard of this distribution, but it says what it is like.
        assert_eq!(
            packager_from_os_release("ID=frobnix\nID_LIKE=\"rhel fedora\"\n"),
            Some(Packager::Dnf)
        );
        assert_eq!(packager_from_os_release("ID=frobnix\n"), None);
    }

    #[test]
    fn every_packager_names_curl() {
        for packager in [
            Packager::Apt,
            Packager::Dnf,
            Packager::Pacman,
            Packager::Zypper,
            Packager::Brew,
            Packager::Winget,
        ] {
            let package = package_for("curl", packager).expect("curl is installable everywhere");
            let command = packager.install(package);
            assert!(
                command.to_ascii_lowercase().contains("curl"),
                "{packager:?} does not name curl: {command}"
            );
            assert!(
                command.split_whitespace().count() >= 3,
                "{packager:?} is not a runnable command: {command}"
            );
        }
    }

    #[test]
    fn this_host_can_be_told_how_to_install_curl() {
        let fix = install_hint("curl").expect("curl has a hint on every supported host");
        assert!(fix.command.contains("curl"), "{}", fix.command);
    }

    #[test]
    fn a_pinned_component_points_at_the_installer_not_a_package_manager() {
        let fix = install_hint("cloud-hypervisor").expect("pinned components have a remedy");
        assert!(fix.command.contains("install.sh"), "{}", fix.command);
        // An absolute path is what the backend actually asked for.
        let fix = install_hint("/usr/libexec/asterism/virtiofsd").expect("stem is what matters");
        assert!(fix.command.contains("install.sh"), "{}", fix.command);
    }

    /// The signed macOS helper and the two binaries beside it come from the
    /// installer, not from a package manager that has never heard of them.
    #[test]
    fn the_installed_binaries_point_at_the_installer() {
        for tool in ["astd-vz", "ast", "astd"] {
            let fix = install_hint(tool).unwrap_or_else(|| panic!("{tool} has no remedy"));
            assert!(
                fix.command.contains("install.sh"),
                "{tool}: {}",
                fix.command
            );
        }
    }

    /// Host integration has packages too, but only where such a package
    /// exists: naming a Homebrew formula for `systemd` would be a lie.
    #[test]
    fn host_integration_packages_exist_only_where_they_exist() {
        assert_eq!(
            package_for("systemd-inhibit", Packager::Apt),
            Some("systemd")
        );
        assert_eq!(
            package_for("gnome-keyring", Packager::Dnf),
            Some("gnome-keyring")
        );
        assert_eq!(package_for("systemd-inhibit", Packager::Brew), None);
        assert_eq!(package_for("gnome-keyring", Packager::Winget), None);
    }

    #[test]
    fn an_unknown_tool_gets_no_invented_package() {
        assert!(install_hint("frobnicate").is_none());
    }

    #[test]
    fn a_noted_fix_prints_its_platform_after_the_command() {
        assert_eq!(
            Fix::new("sudo apt-get install -y curl").to_string(),
            "sudo apt-get install -y curl"
        );
        assert_eq!(
            Fix::noted("sudo apt-get install -y curl", "Debian/Ubuntu").to_string(),
            "sudo apt-get install -y curl   # Debian/Ubuntu"
        );
    }
}
