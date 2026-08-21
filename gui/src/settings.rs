//! The Settings section: the four things about this device worth changing
//! or worth knowing, and nothing else.
//!
//! Two of them are settings — the login item, and which backend the New
//! Instance window opens on. Two are facts: the daemon's version and the
//! home it is keeping state in, both read-only because changing either from
//! a window would be changing it behind the daemon's back.
//!
//! ## The service pair, and why it spawns `ast`
//!
//! Installing the launchd agent is `asterism-core`'s `service::Manager`, and
//! it bakes an absolute path to `astd` into the plist. That path comes from
//! `service::Spec::current()`, which looks next to the *running binary* — and
//! the running binary here is inside `Asterism.app`, which ships no daemon.
//! An in-process install would therefore write a unit pointing at nothing.
//!
//! `ast` sits next to `astd` wherever Asterism was installed, so spawning
//! `ast service install` gets the seam the right answer to the only question
//! it cannot ask us. Reading is the other way round: [`Manager::status`]
//! reads the unit file and asks launchctl about it, needs no `astd` path at
//! all, and runs here.
//!
//! [`Manager::status`]: asterism_core::service::Manager::status

use anyhow::{bail, Context, Result};
use serde::Serialize;

use asterism_core::paths;
use asterism_core::service;

use crate::client;
use crate::newinstance::{self, Backend, DEFAULT_BACKEND};

/// The one thing this app remembers. Everything else it shows, it asks the
/// daemon for.
const PREFS: &str = "gui.json";

/// The Settings section, whole.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Settings {
    /// Whether the login item is installed, according to the plugin that
    /// owns it. Filled in by the caller, because only a running app can ask.
    pub autostart: bool,
    /// The backends this device can offer. One entry means the row is
    /// clutter pretending to be a choice, and the window draws none.
    pub backends: Vec<Backend>,
    /// Which of them the New Instance window opens on.
    pub default_backend: String,
    /// The running daemon's version, or why we could not ask.
    pub daemon: Option<String>,
    pub daemon_error: Option<String>,
    /// The build the running daemon was compiled from. `None` is a daemon
    /// too old to say, which is not the same as one that is not running —
    /// that shows up as `daemon_error`.
    pub daemon_build: Option<String>,
    /// The build *this app* was compiled from. It is stamped into
    /// `asterism-core` at compile time, so it is here without asking anyone,
    /// and it is here at all because the app and the daemon are shipped
    /// separately and can silently come apart.
    pub app_build: String,
    /// `ASTERISM_HOME`, resolved. The state every other row is about.
    pub home: String,
    pub service: Service,
}

/// `astd` as the OS currently sees it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Service {
    /// What the OS calls this: `launchd`, `systemd (user)`.
    pub mechanism: String,
    /// `running (pid 412)`, `not installed`, or why we could not look.
    pub summary: String,
    pub installed: bool,
    /// The unit file the manager owns.
    pub unit: String,
}

impl Service {
    /// Ask the OS. A device with no service manager we understand reports
    /// that rather than pretending the daemon is not installed.
    pub fn load() -> Service {
        let manager = match service::manager() {
            Ok(manager) => manager,
            Err(e) => return Service::unknown(&format!("{e:#}")),
        };
        let mechanism = manager.mechanism().to_owned();
        match manager.status() {
            Ok(state) => Service {
                mechanism,
                summary: state.summary(),
                installed: state.installed,
                unit: state.unit.display().to_string(),
            },
            Err(e) => Service {
                mechanism,
                summary: format!("could not be read — {e:#}"),
                installed: false,
                unit: String::new(),
            },
        }
    }

    fn unknown(reason: &str) -> Service {
        Service {
            mechanism: "none".to_owned(),
            summary: reason.to_owned(),
            installed: false,
            unit: String::new(),
        }
    }
}

impl Settings {
    /// Read everything the section shows. `autostart` comes in from the
    /// app, which is the only thing that can ask the plugin holding it.
    pub fn load(autostart: bool) -> Settings {
        let (daemon, daemon_build, daemon_error) = match client::daemon_build() {
            Ok((version, build)) => (Some(version), build, None),
            Err(e) => (None, None, Some(format!("{e:#}"))),
        };
        Settings {
            autostart,
            backends: newinstance::backends(),
            default_backend: preferred_backend(),
            daemon,
            daemon_error,
            daemon_build,
            app_build: asterism_core::BUILD_ID.to_owned(),
            home: paths::home_dir().display().to_string(),
            service: Service::load(),
        }
    }

    /// The section as text, for `--dump-main settings`.
    pub fn lines(&self) -> Vec<String> {
        let mut out = vec!["section settings".to_owned()];
        out.push(format!("start-at-login {}", if self.autostart { "[x]" } else { "[ ]" }));
        match self.backends.len() {
            // One backend is no choice, and the window draws no row for it.
            1 => out.push(format!("backend {} (only, no row)", self.default_backend)),
            _ => {
                for backend in &self.backends {
                    let default =
                        if backend.id == self.default_backend { "  (default)" } else { "" };
                    out.push(format!("backend {:<6} {}{default}", backend.id, backend.label));
                }
            }
        }
        out.push(format!("app build {}", self.app_build));
        match (&self.daemon, &self.daemon_error) {
            (Some(version), _) => out.push(format!(
                "daemon {version} build {}",
                self.daemon_build.as_deref().unwrap_or("unknown")
            )),
            (None, Some(reason)) => out.push(format!("daemon unavailable — {reason}")),
            (None, None) => out.push("daemon unavailable".to_owned()),
        }
        out.push(format!("home {}", self.home));
        out.push(format!("service {} {}", self.service.mechanism, self.service.summary));
        out
    }
}

// ---- the one preference ----------------------------------------------------

/// Which backend the New Instance window opens on.
///
/// Falls back to [`DEFAULT_BACKEND`] (`Automatic`) for everything this device
/// can no longer force. A stale preference for `vz` on a machine that lost
/// the helper must not produce a create that fails when pressed.
pub fn preferred_backend() -> String {
    let Some(stored) = read_pref() else {
        return DEFAULT_BACKEND.to_owned();
    };
    match newinstance::backends().iter().any(|b| b.id == stored) {
        true => stored,
        false => DEFAULT_BACKEND.to_owned(),
    }
}

/// Remember a backend, having checked this device can offer it.
pub fn set_preferred_backend(id: &str) -> Result<()> {
    if !newinstance::backends().iter().any(|b| b.id == id) {
        bail!("this device has no {id} backend to default to");
    }
    let dir = paths::home_dir();
    std::fs::create_dir_all(&dir).with_context(|| format!("making {}", dir.display()))?;
    let path = dir.join(PREFS);
    let body = serde_json::json!({ "default_backend": id });
    std::fs::write(&path, serde_json::to_vec_pretty(&body)?)
        .with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

/// The stored id, if there is a readable one. A missing, unreadable or
/// nonsense file is the same answer: no preference.
fn read_pref() -> Option<String> {
    let bytes = std::fs::read(paths::home_dir().join(PREFS)).ok()?;
    let parsed: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    Some(parsed.get("default_backend")?.as_str()?.to_owned())
}

// ---- the service pair ------------------------------------------------------

/// Hand `astd` to the OS, by running the command that does it.
pub fn install() -> Result<()> {
    run_service("install")
}

/// Take it back.
pub fn uninstall() -> Result<()> {
    run_service("uninstall")
}

fn run_service(verb: &str) -> Result<()> {
    let ast = client::ast_path();
    let out = std::process::Command::new(&ast)
        .arg("service")
        .arg(verb)
        .output()
        .with_context(|| format!("running {} service {verb}", ast.display()))?;
    if !out.status.success() {
        // The seam is chatty on failure and the message is the useful part;
        // a status code alone would send the user to a log they do not know
        // about.
        let why = String::from_utf8_lossy(&out.stderr);
        let why = why.trim();
        bail!(
            "{} service {verb} exited with {}{}{}",
            ast.display(),
            out.status,
            if why.is_empty() { "" } else { ": " },
            why
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings() -> Settings {
        Settings {
            autostart: false,
            backends: vec![Backend { id: "qemu".into(), label: "QEMU".into() }],
            default_backend: "qemu".into(),
            daemon: Some("0.0.2".into()),
            daemon_error: None,
            daemon_build: Some("0.0.2+0123456789ab".into()),
            app_build: "0.0.2+0123456789ab".into(),
            home: "/tmp/ast-home".into(),
            service: Service {
                mechanism: "launchd".into(),
                summary: "running (pid 412)".into(),
                installed: true,
                unit: "/Users/x/Library/LaunchAgents/com.asterism.astd.plist".into(),
            },
        }
    }

    #[test]
    fn the_login_item_shows_its_state() {
        let mut s = settings();
        assert!(s.lines().contains(&"start-at-login [ ]".to_owned()));
        s.autostart = true;
        assert!(s.lines().contains(&"start-at-login [x]".to_owned()));
    }

    /// A row offering one backend is clutter pretending to be a choice, and
    /// the section says so rather than drawing it. Same rule as the New
    /// Instance window's, because it is the same choice.
    #[test]
    fn a_lone_backend_gets_no_row() {
        let mut s = settings();
        assert!(s.lines().contains(&"backend qemu (only, no row)".to_owned()));

        s.backends.push(Backend { id: "vz".into(), label: "Apple".into() });
        s.default_backend = "vz".into();
        let lines = s.lines().join("\n");
        assert!(lines.contains("backend qemu   QEMU"), "{lines}");
        assert!(lines.contains("backend vz     Apple  (default)"), "{lines}");
    }

    /// A daemon that did not answer and a daemon with no version are both
    /// worth distinguishing from one that answered.
    #[test]
    fn an_unreachable_daemon_says_so_where_the_version_would_be() {
        let mut s = settings();
        assert!(s
            .lines()
            .contains(&"daemon 0.0.2 build 0.0.2+0123456789ab".to_owned()));

        s.daemon = None;
        s.daemon_error = Some("astd is not answering".into());
        let lines = s.lines().join("\n");
        assert!(lines.contains("daemon unavailable — astd is not answering"), "{lines}");
        assert!(!lines.contains("daemon 0.0.2"), "{lines}");
    }

    /// The two builds are separate facts, and each is reported even when the
    /// other cannot be: the app always knows its own, and a daemon that
    /// answered without one is old rather than absent.
    #[test]
    fn both_builds_are_reported_and_a_missing_one_is_not_a_missing_daemon() {
        let mut s = settings();
        let lines = s.lines().join("\n");
        assert!(lines.contains("app build 0.0.2+0123456789ab"), "{lines}");

        s.daemon_build = None;
        let lines = s.lines().join("\n");
        assert!(lines.contains("daemon 0.0.2 build unknown"), "{lines}");
        // The app still knows its own build; only the daemon's is missing.
        assert!(lines.contains("app build 0.0.2+0123456789ab"), "{lines}");

        s.daemon = None;
        s.daemon_error = Some("astd is not answering".into());
        let lines = s.lines().join("\n");
        assert!(!lines.contains("build unknown"), "{lines}");
    }

    #[test]
    fn the_home_and_the_service_are_reported_as_they_are() {
        let lines = settings().lines().join("\n");
        assert!(lines.contains("home /tmp/ast-home"), "{lines}");
        assert!(lines.contains("service launchd running (pid 412)"), "{lines}");
    }

    /// A device with no service manager we understand must not read as a
    /// device with the daemon not installed: one is a fact about astd, the
    /// other a fact about the OS.
    #[test]
    fn an_os_without_a_manager_says_that_rather_than_not_installed() {
        let mut s = settings();
        s.service = Service::unknown("no service manager for this OS");
        let lines = s.lines().join("\n");
        assert!(lines.contains("service none no service manager for this OS"), "{lines}");
        assert!(!s.service.installed);
    }

    /// The preference is a hint about which row the New Instance window
    /// opens on, and it is only ever honoured for a backend this device can
    /// actually run. A stale `vz` on a machine that lost the helper would
    /// otherwise be a create that fails when pressed.
    #[test]
    fn a_backend_this_device_cannot_offer_is_not_a_default() {
        assert!(set_preferred_backend("nonesuch").is_err());

        let offered = newinstance::backends();
        assert_eq!(offered[0].id, DEFAULT_BACKEND);
        // Whatever is on disk, the answer is always something offered.
        let chosen = preferred_backend();
        assert!(offered.iter().any(|b| b.id == chosen), "{chosen} is not offered: {offered:?}");
    }

    #[test]
    fn the_section_reaches_the_webview_under_the_names_it_reads() {
        let json = serde_json::to_value(settings()).unwrap();
        for key in
            ["autostart", "backends", "default_backend", "daemon", "home", "service"]
        {
            assert!(json.get(key).is_some(), "settings has no {key:?}: {json}");
        }
        assert_eq!(json["service"]["installed"], serde_json::json!(true));
        assert_eq!(json["service"]["mechanism"], serde_json::json!("launchd"));
    }
}
