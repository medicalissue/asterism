//! Finding and running external tools.
//!
//! Shared rather than backend-owned: the seed builder needs `xorriso` and
//! `ssh-keygen` on hosts that may never start a QEMU, and every backend
//! needs the same "run it, and if it fails say what it said" wrapper.

use std::path::PathBuf;
use std::process::Command;

use anyhow::{bail, Context, Result};

use crate::fix::{install_hint, Fixable};

/// Replaces the built-in list of well-known directories `tool` searches
/// beyond `PATH`. A `PATH`-style list, so a host that keeps its tools
/// somewhere unusual — or a test that needs a host with none at all — can say
/// so without patching this table.
const SEARCH_DIRS_ENV: &str = "ASTERISM_TOOL_DIRS";

/// The daemon may be launched with a minimal PATH (launchd, systemd, a
/// double-clicked app), so check the usual spots rather than trusting it.
pub fn tool(name: &str) -> Result<PathBuf> {
    let mut candidates = vec![PathBuf::from(name)];
    if let Some(dirs) = std::env::var_os(SEARCH_DIRS_ENV) {
        candidates.extend(std::env::split_paths(&dirs).map(|dir| dir.join(name)));
    } else {
        candidates.extend(
            ["/opt/homebrew/bin", "/usr/local/bin", "/usr/bin"]
                .iter()
                .map(|dir| PathBuf::from(dir).join(name)),
        );
        if cfg!(windows) {
            if let Some(local) = std::env::var_os("LOCALAPPDATA") {
                candidates.push(PathBuf::from(local).join("Asterism").join("bin").join(name));
            }
            if let Some(pf) = std::env::var_os("ProgramFiles") {
                candidates.push(PathBuf::from(pf).join("Asterism").join("bin").join(name));
            }
            candidates.push(PathBuf::from(r"C:\Windows\System32").join(name));
        }
    }
    for c in &candidates {
        let found = if c.is_absolute() {
            c.exists()
        } else {
            Command::new(c)
                .arg("--version")
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false)
        };
        if found {
            return Ok(c.clone());
        }
    }
    // A missing tool is the one failure where the remedy is completely
    // mechanical, so it travels with the error rather than waiting to be
    // guessed at three containers later.
    let message = format!("{name} not found — is it installed and on PATH?");
    match install_hint(name) {
        Some(fix) => Err(anyhow::Error::new(Fixable::new(message, fix))),
        None => bail!(message),
    }
}

pub fn run(cmd: &mut Command) -> Result<()> {
    output(cmd).map(|_| ())
}

/// Run a tool and hand back what it printed.
pub fn output(cmd: &mut Command) -> Result<String> {
    let out = cmd
        .output()
        .with_context(|| format!("running {:?}", cmd.get_program()))?;
    if !out.status.success() {
        bail!(
            "{:?} failed: {}",
            cmd.get_program(),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}
