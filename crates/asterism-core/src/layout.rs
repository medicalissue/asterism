//! Where an installed Asterism keeps the helpers and payloads it ships.
//!
//! Linux now has two installed shapes, and both are first-class:
//!
//! | shape | `astd` | pinned helpers | guest payloads |
//! |---|---|---|---|
//! | flat prefix (`packaging/install.sh`) | `<prefix>/bin/astd` | beside `astd` | beside `astd` |
//! | native package (`.deb`/`.rpm`) | `/usr/bin/astd` | `/usr/libexec/asterism` | `/usr/lib/asterism` |
//!
//! A package may not write into `/usr/local`, and `/usr/bin` is not a place
//! to drop a binary named `cloud-hypervisor` — so the packaged layout has to
//! differ from the flat one. Rather than teach every call site both, every
//! lookup goes through this module: it searches the shape the running
//! executable was installed as first, then the two absolute system shapes.
//! No environment variable is required for a packaged install to find its
//! own components.

use std::path::{Path, PathBuf};

/// The directory the running executable lives in.
fn exe_dir() -> Option<PathBuf> {
    std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(Path::to_path_buf))
}

/// The install prefix of the running executable: `/usr` for `/usr/bin/astd`,
/// `~/.local` for `~/.local/bin/astd`.
fn prefix_dir() -> Option<PathBuf> {
    exe_dir().map(|bin| bin.parent().map(Path::to_path_buf).unwrap_or(bin))
}

/// Directories that can hold a pinned executable helper, most specific
/// first. The flat payload keeps them beside `astd`; a package keeps them
/// under `libexec/asterism`.
pub fn helper_dirs() -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    if let Some(dir) = exe_dir() {
        dirs.push(dir);
    }
    if let Some(prefix) = prefix_dir() {
        dirs.push(prefix.join("libexec/asterism"));
    }
    for absolute in ["/usr/libexec/asterism", "/usr/local/libexec/asterism"] {
        let absolute = PathBuf::from(absolute);
        if !dirs.contains(&absolute) {
            dirs.push(absolute);
        }
    }
    dirs
}

/// Directories that can hold a shipped data payload — the guest-control ELF
/// and the GPU projection artifacts — most specific first.
pub fn data_dirs() -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    if let Some(dir) = exe_dir() {
        dirs.push(dir);
    }
    if let Some(prefix) = prefix_dir() {
        dirs.push(prefix.join("lib/asterism"));
    }
    for absolute in ["/usr/lib/asterism", "/usr/local/lib/asterism"] {
        let absolute = PathBuf::from(absolute);
        if !dirs.contains(&absolute) {
            dirs.push(absolute);
        }
    }
    dirs
}

/// The first installed helper of that name, or `None` when this host has no
/// installed copy. Only regular files count: a directory named
/// `cloud-hypervisor` is not a VMM.
pub fn helper(name: &str) -> Option<PathBuf> {
    helper_dirs()
        .into_iter()
        .map(|dir| dir.join(name))
        .find(|candidate| candidate.is_file())
}

/// The root-owned NBD privilege wrapper.
///
/// The path is not merely where the wrapper is; it is the subject of the
/// installed sudoers rule, so the daemon has to name the same one the
/// installation authorised. Both installed shapes are searched, and when
/// neither is present the flat installer's path is reported so the message
/// names the file an operator would go looking for.
pub const NBD_HELPER_NAME: &str = "asterism-nbd";

/// The path `packaging/install.sh` uses, and the one reported when nothing
/// is installed.
pub const NBD_HELPER_FALLBACK: &str = "/usr/local/libexec/asterism/asterism-nbd";

pub fn nbd_helper() -> PathBuf {
    if let Some(path) = std::env::var_os("ASTERISM_NBD_HELPER") {
        return PathBuf::from(path);
    }
    // The wrapper is deliberately not looked for beside astd: it must be
    // root-owned and root-installed, and the payload copy under
    // share/asterism is a source, not an installed helper.
    let mut dirs = Vec::new();
    if let Some(prefix) = prefix_dir() {
        dirs.push(prefix.join("libexec/asterism"));
    }
    dirs.push(PathBuf::from("/usr/local/libexec/asterism"));
    dirs.push(PathBuf::from("/usr/libexec/asterism"));
    for dir in dirs {
        let candidate = dir.join(NBD_HELPER_NAME);
        if candidate.is_file() {
            return candidate;
        }
    }
    PathBuf::from(NBD_HELPER_FALLBACK)
}

/// The per-account privilege helper a native package ships. It is the only
/// thing that writes `/etc/sudoers.d/asterism-nbd-<uid>`, because a
/// system-wide package cannot know which account will run the daemon.
pub const NBD_POLICY_NAME: &str = "asterism-nbd-policy";

pub fn nbd_policy_helper() -> Option<PathBuf> {
    helper(NBD_POLICY_NAME)
}

/// Where a package or installer put `linux-components.env` and the license
/// texts.
pub fn share_dir() -> Option<PathBuf> {
    prefix_dir().map(|prefix| prefix.join("share/asterism"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn helper_dirs_include_both_installed_shapes_without_duplicates() {
        let dirs = helper_dirs();
        assert!(dirs.contains(&PathBuf::from("/usr/libexec/asterism")));
        assert!(dirs.contains(&PathBuf::from("/usr/local/libexec/asterism")));
        let mut seen = dirs.clone();
        seen.sort();
        seen.dedup();
        assert_eq!(seen.len(), dirs.len(), "{dirs:?} repeats a directory");
    }

    #[test]
    fn data_dirs_include_both_installed_shapes() {
        let dirs = data_dirs();
        assert!(dirs.contains(&PathBuf::from("/usr/lib/asterism")));
        assert!(dirs.contains(&PathBuf::from("/usr/local/lib/asterism")));
    }

    #[test]
    fn an_absent_helper_is_absent_rather_than_a_guess() {
        assert_eq!(helper("asterism-no-such-helper-exists"), None);
    }

    #[test]
    fn the_nbd_helper_env_override_wins() {
        // Serialised with the other env-reading tests by running the whole
        // check inside one guarded block.
        let previous = std::env::var_os("ASTERISM_NBD_HELPER");
        std::env::set_var("ASTERISM_NBD_HELPER", "/tmp/asterism-nbd-test");
        let observed = nbd_helper();
        match previous {
            Some(value) => std::env::set_var("ASTERISM_NBD_HELPER", value),
            None => std::env::remove_var("ASTERISM_NBD_HELPER"),
        }
        assert_eq!(observed, PathBuf::from("/tmp/asterism-nbd-test"));
    }
}
