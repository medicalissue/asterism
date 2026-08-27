//! Who owns the files this installation is made of.
//!
//! There are two ways an Asterism reaches `/usr`: `install.sh`, which writes
//! an install receipt beside the binaries, and a native `.deb` or `.rpm`,
//! which writes no receipt at all because dpkg and rpm already keep one —
//! a database of every path they placed, with its digest.
//!
//! Two commands need to know which of those happened. `ast doctor` reported
//! "this tree was not installed by install.sh" for a perfectly good packaged
//! install, because the receipt was the only ownership it could see; and
//! `ast update` must not replace a file dpkg believes it owns, because the
//! next `apt-get` would either revert the update or refuse to proceed over
//! the changed digest. Both questions have the same answer, so it is asked
//! once here.
//!
//! The probe is deliberately the packaging tool itself rather than a guess
//! from the path: `/usr/bin/ast` is where the package puts it *and* where a
//! sufficiently determined `install.sh --prefix /usr` would, and only dpkg
//! or rpm knows which of those actually happened on this machine.

use std::path::Path;
use std::process::Command;

/// A native package family Asterism ships for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// Debian, Ubuntu and their derivatives.
    Dpkg,
    /// Fedora, RHEL, openSUSE and their derivatives.
    Rpm,
}

impl Format {
    /// The name of the database this answer came out of.
    pub fn tool(self) -> &'static str {
        match self {
            Self::Dpkg => "dpkg",
            Self::Rpm => "rpm",
        }
    }

    /// The platform family whose words the upgrade command is written in.
    pub fn platform(self) -> &'static str {
        match self {
            Self::Dpkg => "Debian/Ubuntu",
            Self::Rpm => "Fedora/RHEL",
        }
    }
}

/// The package that owns a path, as its own database describes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Owner {
    pub format: Format,
    /// The package name, e.g. `asterism`.
    pub package: String,
    /// The version string as the package manager spells it.
    pub version: String,
}

impl Owner {
    /// The sentence `ast doctor` prints on the `receipt` row.
    pub fn describe(&self) -> String {
        format!(
            "installed by package {} {} ({})",
            self.package,
            self.version,
            self.format.tool()
        )
    }

    /// The command that upgrades this installation — the one thing a user
    /// whose `ast update` was refused actually wants to type.
    pub fn upgrade(&self) -> String {
        match self.format {
            Format::Dpkg => format!("sudo apt-get install --only-upgrade {}", self.package),
            Format::Rpm => format!("sudo dnf upgrade {}", self.package),
        }
    }

    /// The refusal `ast update apply` prints, with the remedy attached.
    ///
    /// Not a failure of the updater: replacing a file dpkg or rpm records
    /// the digest of would leave the package database describing a tree that
    /// no longer exists, and the next distribution upgrade would either
    /// revert the update or stop on the difference.
    pub fn refusal(&self) -> crate::fix::Fixable {
        crate::fix::Fixable::new(
            format!(
                "this installation belongs to {}: package {} {} owns these files, \
                 and ast update does not replace them",
                self.format.tool(),
                self.package,
                self.version,
            ),
            crate::fix::Fix::noted(self.upgrade(), self.format.platform()),
        )
    }
}

/// The package that owns `path`, or `None` when nothing does.
///
/// `None` is the answer for a source build, for an `install.sh` tree, and
/// for a host with neither packaging tool — all three of which are installs
/// `ast update` may replace in place.
pub fn owner_of(path: &Path) -> Option<Owner> {
    if !cfg!(target_os = "linux") {
        // dpkg and rpm both exist on macOS through Homebrew, and neither has
        // ever placed a file in an Asterism prefix there. Asking would only
        // give a wrong answer slowly.
        return None;
    }
    // dpkg records the path it installed. `/usr/bin/ast` is not a symlink in
    // either package, but a prefix reached through one (`/usr/local` on some
    // hosts) would not match the database as spelled.
    let resolved = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_owned());
    for candidate in [resolved.as_path(), path] {
        if let Some(owner) = dpkg_owner(candidate).or_else(|| rpm_owner(candidate)) {
            return Some(owner);
        }
        if candidate == path {
            break;
        }
    }
    None
}

/// The package that owns the running executable.
pub fn owner_of_current_exe() -> Option<Owner> {
    owner_of(&std::env::current_exe().ok()?)
}

fn output(program: &str, args: &[&str]) -> Option<String> {
    let out = Command::new(program).args(args).output().ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}

fn dpkg_owner(path: &Path) -> Option<Owner> {
    let search = output("dpkg-query", &["-S", path.to_str()?])?;
    let package = parse_dpkg_search(&search)?;
    let version = output("dpkg-query", &["-W", "-f", "${Version}", &package])
        .map(|v| v.trim().to_owned())
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| "unknown".into());
    Some(Owner {
        format: Format::Dpkg,
        package,
        version,
    })
}

fn rpm_owner(path: &Path) -> Option<Owner> {
    let out = output(
        "rpm",
        &["-qf", "--queryformat", "%{NAME}\t%{EVR}", path.to_str()?],
    )?;
    let (package, version) = parse_rpm_query(&out)?;
    Some(Owner {
        format: Format::Rpm,
        package,
        version,
    })
}

/// The package name out of a `dpkg-query -S` line.
///
/// The shape is `package: /path`, `package:arch: /path`, or a comma-joined
/// list of packages when several ship the same path. Diversion lines are
/// prose about a redirected path rather than an owner, and are skipped: the
/// owner line for the same query is printed alongside them.
fn parse_dpkg_search(out: &str) -> Option<String> {
    for line in out.lines() {
        let line = line.trim();
        if line.is_empty()
            || line.starts_with("diversion by")
            || line.starts_with("local diversion")
        {
            continue;
        }
        let (packages, _) = line.rsplit_once(": ")?;
        let first = packages.split(',').next()?.trim();
        // `package:arch` — the architecture qualifier is not part of the name
        // `apt-get install` wants.
        let name = first.split(':').next().unwrap_or(first).trim();
        if !name.is_empty() {
            return Some(name.to_owned());
        }
    }
    None
}

/// The name and version out of `rpm -qf --queryformat '%{NAME}\t%{EVR}'`.
fn parse_rpm_query(out: &str) -> Option<(String, String)> {
    let line = out.lines().next()?.trim();
    let (name, version) = line.split_once('\t')?;
    let (name, version) = (name.trim(), version.trim());
    (!name.is_empty() && !version.is_empty()).then(|| (name.to_owned(), version.to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_plain_dpkg_answer_names_the_package() {
        assert_eq!(
            parse_dpkg_search("asterism: /usr/bin/ast\n").as_deref(),
            Some("asterism")
        );
    }

    /// A multi-arch installation qualifies the name, and `apt-get` wants the
    /// name without the qualifier.
    #[test]
    fn an_architecture_qualifier_is_not_part_of_the_name() {
        assert_eq!(
            parse_dpkg_search("asterism:amd64: /usr/bin/ast\n").as_deref(),
            Some("asterism")
        );
    }

    #[test]
    fn a_diversion_preamble_does_not_displace_the_owner() {
        let out = "diversion by asterism-legacy from: /usr/bin/ast\nasterism: /usr/bin/ast\n";
        assert_eq!(parse_dpkg_search(out).as_deref(), Some("asterism"));
    }

    #[test]
    fn several_owners_of_one_path_answer_with_the_first() {
        assert_eq!(
            parse_dpkg_search("asterism, asterism-doc: /usr/share/asterism\n").as_deref(),
            Some("asterism")
        );
    }

    #[test]
    fn an_unowned_path_has_no_owner() {
        // dpkg-query prints its "no path found" complaint on stderr and
        // exits non-zero, so the empty stdout is what reaches the parser.
        assert_eq!(parse_dpkg_search(""), None);
        assert_eq!(parse_dpkg_search("no path found matching pattern"), None);
    }

    #[test]
    fn rpm_answers_with_a_name_and_a_version() {
        assert_eq!(
            parse_rpm_query("asterism\t0.0.2-1\n"),
            Some(("asterism".into(), "0.0.2-1".into()))
        );
        assert_eq!(parse_rpm_query("file /usr/bin/ast is not owned"), None);
        assert_eq!(parse_rpm_query(""), None);
    }

    #[test]
    fn a_dpkg_owner_is_upgraded_by_apt_and_an_rpm_owner_by_dnf() {
        let deb = Owner {
            format: Format::Dpkg,
            package: "asterism".into(),
            version: "0.0.2-1".into(),
        };
        assert_eq!(
            deb.upgrade(),
            "sudo apt-get install --only-upgrade asterism"
        );
        assert_eq!(
            deb.describe(),
            "installed by package asterism 0.0.2-1 (dpkg)"
        );
        let rpm = Owner {
            format: Format::Rpm,
            package: "asterism".into(),
            version: "0.0.2-1".into(),
        };
        assert_eq!(rpm.upgrade(), "sudo dnf upgrade asterism");
        assert_eq!(
            rpm.describe(),
            "installed by package asterism 0.0.2-1 (rpm)"
        );
    }

    /// The refusal is only useful if the command survives the trip through
    /// `anyhow`, which is what `fix::of` is for.
    #[test]
    fn the_refusal_carries_the_upgrade_command_through_context() {
        let owner = Owner {
            format: Format::Dpkg,
            package: "asterism".into(),
            version: "0.0.2-1".into(),
        };
        let error = anyhow::Error::new(owner.refusal())
            .context("applying an update")
            .context("running ast update");
        let fix = crate::fix::of(&error).expect("the refusal names a command");
        assert_eq!(fix.command, "sudo apt-get install --only-upgrade asterism");
        assert!(
            format!("{error:#}").contains("belongs to dpkg"),
            "{error:#}"
        );
    }

    /// This machine built the test binary, so nothing owns it — on every
    /// host, including a Debian one with dpkg right there.
    #[test]
    fn a_source_build_has_no_package_owner() {
        let me = std::env::current_exe().expect("a test binary has a path");
        assert_eq!(owner_of(&me), None, "{}", me.display());
    }
}
