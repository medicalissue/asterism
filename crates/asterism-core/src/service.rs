//! astd as a login-independent service — the `service::Manager` row of
//! `docs/PLATFORM.md`.
//!
//! "Your agent's home never sleeps" is only true if the daemon comes back
//! by itself: after a host reboot, after a crash, and without anyone
//! opening a terminal. That is the operating system's job, and every OS
//! spells it differently. This module is the seam that owns the
//! difference, so it is one of the few places allowed to carry
//! `#[cfg(target_os)]`.
//!
//! | OS | mechanism | unit |
//! |---|---|---|
//! | macOS | launchd user agent | `~/Library/LaunchAgents/com.asterism.astd.plist` |
//! | Linux | systemd user unit | `~/.config/systemd/user/astd.service` |
//! | Windows | not implemented — the decided row is a Windows Service |
//!
//! **The binary path is baked in.** Both unit formats name an absolute
//! path to `astd`, recorded at install time. Replacing the binary in place
//! (`brew upgrade`, `cargo install --force`) is fine. *Moving* it — a new
//! Homebrew prefix, dragging the app elsewhere, deleting a build directory
//! the unit pointed at — leaves a unit pointing at nothing, and the fix is
//! `ast service install` again. [`Manager::status`] reports the recorded
//! path and whether it still exists, so the failure is legible rather than
//! a daemon that silently never starts.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

/// Reverse-DNS label on macOS, unit name on Linux. One device runs one
/// astd, so this is a constant rather than something per-home: two homes
/// on one login would be two daemons fighting over the same service slot.
pub const LABEL: &str = "com.asterism.astd";

/// A deliberately narrow escape hatch for isolated end-to-end tests. The
/// production service label is fixed, but a harness that owns a temporary
/// ASTERISM_HOME must not replace the user's real login service while proving
/// restart behaviour.
const TEST_LABEL_ENV: &str = "ASTERISM_TEST_SERVICE_LABEL";

fn test_label() -> Result<Option<String>> {
    let value = match std::env::var(TEST_LABEL_ENV) {
        Ok(value) => value,
        Err(std::env::VarError::NotPresent) => return Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => {
            bail!("{TEST_LABEL_ENV} is not valid Unicode")
        }
    };
    validate_test_label(&value)?;
    if std::env::var_os("ASTERISM_HOME").is_none() {
        bail!("{TEST_LABEL_ENV} requires an explicit ASTERISM_HOME");
    }
    Ok(Some(value))
}

fn validate_test_label(value: &str) -> Result<()> {
    const PREFIX: &str = "com.asterism.astd.test.";
    if value.len() > 120
        || !value.starts_with(PREFIX)
        || value.ends_with('.')
        || value.contains("..")
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
    {
        bail!(
            "{TEST_LABEL_ENV} must start with {PREFIX}, use only ASCII letters, digits, dots, or hyphens, and be at most 120 bytes"
        );
    }
    Ok(())
}

/// What to install: which binary, with which environment.
#[derive(Debug, Clone)]
pub struct Spec {
    /// Absolute path to the `astd` binary.
    pub program: PathBuf,
    /// `ASTERISM_HOME` to run against, when it is not the default. Recorded
    /// so a service installed from a shell with a custom home keeps that
    /// home — launchd and systemd start with almost no environment.
    pub home: Option<PathBuf>,
    /// `PATH` the daemon should search for `qemu-system-*`, `ssh` and
    /// `qemu-img`. A launchd agent's default PATH is `/usr/bin:/bin:...`,
    /// which does not include Homebrew, so the daemon would install fine
    /// and then fail to boot anything.
    pub path_env: String,
    /// Where the daemon's own output goes.
    pub log: PathBuf,
}

impl Spec {
    /// The spec for the astd that belongs to the running binary.
    pub fn current() -> Result<Spec> {
        Spec::for_program(&daemon_program()?)
    }

    pub fn for_program(program: &Path) -> Result<Spec> {
        let program = std::fs::canonicalize(program)
            .with_context(|| format!("{} is not a file this device can run", program.display()))?;
        let home = std::env::var_os("ASTERISM_HOME").map(PathBuf::from);
        Ok(Spec {
            program,
            home,
            path_env: std::env::var("PATH").unwrap_or_else(|_| "/usr/bin:/bin".into()),
            log: crate::paths::home_dir().join("astd.log"),
        })
    }
}

/// Where `astd` is, given that the caller is usually `ast` sitting next to
/// it. Absolute, because both unit formats demand it.
pub fn daemon_program() -> Result<PathBuf> {
    if let Ok(me) = std::env::current_exe() {
        let sibling = me.with_file_name("astd");
        if sibling.exists() {
            return Ok(sibling);
        }
    }
    if let Some(path) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&path) {
            let candidate = dir.join("astd");
            if candidate.is_file() {
                return Ok(candidate);
            }
        }
    }
    bail!("cannot find the astd binary next to ast or on PATH")
}

/// What an install or uninstall did, in the order it did it. Printed by
/// the CLI: a service that quietly edits `~/Library` should say so.
#[derive(Debug, Default)]
pub struct Report {
    pub unit: PathBuf,
    pub steps: Vec<String>,
}

impl Report {
    fn step(&mut self, s: impl Into<String>) {
        self.steps.push(s.into());
    }
}

/// The service as the OS currently sees it.
#[derive(Debug)]
pub struct State {
    pub unit: PathBuf,
    /// The unit file exists.
    pub installed: bool,
    /// The service manager has it loaded (launchd bootstrapped, systemd
    /// enabled).
    pub loaded: bool,
    /// Pid of the running daemon, when the service manager reports one.
    pub pid: Option<u32>,
    /// The `astd` path recorded in the unit, and whether it still exists.
    pub program: Option<PathBuf>,
    /// Anything else worth showing a human, mechanism-specific.
    pub notes: Vec<String>,
}

impl State {
    fn missing(unit: PathBuf) -> State {
        State {
            unit,
            installed: false,
            loaded: false,
            pid: None,
            program: None,
            notes: Vec::new(),
        }
    }

    /// One line for `ast service status`.
    pub fn summary(&self) -> String {
        match (self.installed, self.loaded, self.pid) {
            (false, _, _) => "not installed".into(),
            (true, false, _) => "installed, not loaded".into(),
            (true, true, Some(pid)) => format!("running (pid {pid})"),
            (true, true, None) => "loaded, not running".into(),
        }
    }
}

/// Install, remove and inspect the service. One implementation per OS; the
/// CLI holds a `Box<dyn Manager>` and never asks which one it got.
pub trait Manager {
    /// What the OS calls this: "launchd", "systemd (user)".
    fn mechanism(&self) -> &'static str;

    /// The unit file this manager owns.
    fn unit_path(&self) -> PathBuf;

    fn install(&self, spec: &Spec) -> Result<Report>;

    fn uninstall(&self) -> Result<Report>;

    fn status(&self) -> Result<State>;
}

/// The service manager for this device, or why there is not one.
pub fn manager() -> Result<Box<dyn Manager>> {
    imp::manager()
}

// ---- shared helpers --------------------------------------------------------

fn home() -> Result<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .context("no HOME in the environment, so there is no place to put a user service")
}

/// Run a command, returning stdout+stderr and whether it succeeded. Service
/// managers are chatty on failure and the message is the useful part.
#[allow(dead_code)]
fn run(cmd: &mut std::process::Command) -> Result<(bool, String)> {
    let out = cmd
        .output()
        .with_context(|| format!("running {:?}", cmd.get_program()))?;
    let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&out.stderr));
    Ok((out.status.success(), text))
}

// ---- macOS: launchd --------------------------------------------------------

#[cfg(target_os = "macos")]
mod imp {
    use std::path::PathBuf;

    use anyhow::{Context, Result};

    use super::{home, run, test_label, Manager, Report, Spec, State, LABEL};

    pub fn manager() -> Result<Box<dyn Manager>> {
        Ok(Box::new(Launchd {
            label: test_label()?.unwrap_or_else(|| LABEL.to_owned()),
        }))
    }

    pub struct Launchd {
        label: String,
    }

    impl Launchd {
        fn domain(&self) -> Result<String> {
            let (ok, uid) = run(std::process::Command::new("id").arg("-u"))?;
            if !ok {
                anyhow::bail!("cannot read this user's id: {}", uid.trim());
            }
            Ok(format!("gui/{}", uid.trim()))
        }

        fn target(&self) -> Result<String> {
            Ok(format!("{}/{}", self.domain()?, self.label))
        }
    }

    impl Manager for Launchd {
        fn mechanism(&self) -> &'static str {
            "launchd"
        }

        fn unit_path(&self) -> PathBuf {
            home()
                .unwrap_or_else(|_| PathBuf::from("."))
                .join("Library/LaunchAgents")
                .join(format!("{}.plist", self.label))
        }

        fn install(&self, spec: &Spec) -> Result<Report> {
            let unit = self.unit_path();
            let mut report = Report {
                unit: unit.clone(),
                ..Report::default()
            };

            if let Some(dir) = unit.parent() {
                std::fs::create_dir_all(dir)
                    .with_context(|| format!("creating {}", dir.display()))?;
            }
            // launchd opens the log path itself and will not create the
            // directory holding it.
            if let Some(dir) = spec.log.parent() {
                let _ = std::fs::create_dir_all(dir);
            }
            // Committed rather than written: launchd reads this file at
            // login, and a truncated plist is a device that comes back from a
            // reboot with no daemon and no explanation. This is the one piece
            // of Asterism's state that lives outside ASTERISM_HOME, and it
            // gets the same treatment as the rest.
            crate::durable::commit(&unit, plist(spec, &self.label).as_bytes())
                .with_context(|| format!("writing {}", unit.display()))?;
            report.step(format!("wrote {}", unit.display()));

            let target = self.target()?;
            // Replacing an already-loaded agent: bootout first, or
            // bootstrap refuses with "service already loaded".
            let (booted_out, _) = run(std::process::Command::new("launchctl")
                .arg("bootout")
                .arg(&target))?;
            if booted_out {
                report.step(format!("unloaded the previous {}", self.label));
            }

            let (ok, out) = run(std::process::Command::new("launchctl")
                .arg("bootstrap")
                .arg(self.domain()?)
                .arg(&unit))?;
            if !ok {
                anyhow::bail!(
                    "launchctl would not load {}: {}",
                    unit.display(),
                    out.trim()
                );
            }
            report.step(format!("launchctl bootstrap {target}"));
            report.step(format!("astd runs from {}", spec.program.display()));
            report.step(format!("its log is {}", spec.log.display()));
            Ok(report)
        }

        fn uninstall(&self) -> Result<Report> {
            let unit = self.unit_path();
            let mut report = Report {
                unit: unit.clone(),
                ..Report::default()
            };
            let target = self.target()?;
            let (ok, out) = run(std::process::Command::new("launchctl")
                .arg("bootout")
                .arg(&target))?;
            if ok {
                report.step(format!("launchctl bootout {target}"));
            } else {
                report.step(format!("launchd had nothing loaded ({})", out.trim()));
            }
            match std::fs::remove_file(&unit) {
                Ok(()) => report.step(format!("removed {}", unit.display())),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    report.step(format!("{} was not there", unit.display()))
                }
                Err(e) => return Err(e).with_context(|| format!("removing {}", unit.display())),
            }
            // The commit leaves a last-known-good copy beside the unit.
            // Uninstall means uninstall: it goes too, or the next `ls` of
            // that directory would find Asterism still in it.
            let _ = std::fs::remove_file(crate::durable::backup_path(&unit));
            Ok(report)
        }

        fn status(&self) -> Result<State> {
            let unit = self.unit_path();
            if !unit.exists() {
                return Ok(State::missing(unit));
            }
            let text = std::fs::read_to_string(&unit).unwrap_or_default();
            let program = program_from_plist(&text);
            let mut state = State {
                unit,
                installed: true,
                loaded: false,
                pid: None,
                program: program.clone(),
                notes: Vec::new(),
            };
            if let Some(p) = &program {
                if !p.exists() {
                    state.notes.push(format!(
                        "{} is gone — run `ast service install` to point launchd at the \
                         astd you have now",
                        p.display()
                    ));
                }
            }
            let (ok, out) = run(std::process::Command::new("launchctl")
                .arg("print")
                .arg(self.target()?))?;
            state.loaded = ok;
            if ok {
                state.pid = field(&out, "pid = ").and_then(|v| v.parse().ok());
                if let Some(s) = field(&out, "state = ") {
                    state.notes.push(format!("launchd state: {s}"));
                }
            }
            Ok(state)
        }
    }

    /// `key = value` out of `launchctl print`, which is indented but flat.
    fn field(text: &str, key: &str) -> Option<String> {
        text.lines()
            .find_map(|l| l.trim().strip_prefix(key).map(|v| v.trim().to_owned()))
    }

    fn program_from_plist(text: &str) -> Option<PathBuf> {
        let after = text.split("<key>ProgramArguments</key>").nth(1)?;
        let open = after.find("<string>")? + "<string>".len();
        let close = after[open..].find("</string>")? + open;
        Some(PathBuf::from(unescape(&after[open..close])))
    }

    fn escape(s: &str) -> String {
        s.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
    }

    fn unescape(s: &str) -> String {
        s.replace("&lt;", "<")
            .replace("&gt;", ">")
            .replace("&amp;", "&")
    }

    /// KeepAlive plus RunAtLoad is the whole persistence promise in two
    /// keys: start when the user logs in (including after a reboot), and
    /// start again whenever the process exits for any reason.
    ///
    /// A LaunchAgent, not a LaunchDaemon, on purpose: astd runs as the user
    /// whose `~/.asterism` it owns, needs their ssh keys, and boots guests
    /// that a root daemon would run with the wrong ownership.
    fn plist(spec: &Spec, label: &str) -> String {
        let mut env = format!(
            "      <key>PATH</key>\n      <string>{}</string>\n",
            escape(&spec.path_env)
        );
        if let Some(home) = &spec.home {
            env.push_str(&format!(
                "      <key>ASTERISM_HOME</key>\n      <string>{}</string>\n",
                escape(&home.display().to_string())
            ));
        }
        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>{label}</string>
  <key>ProgramArguments</key>
  <array>
    <string>{program}</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>ProcessType</key>
  <string>Background</string>
  <key>EnvironmentVariables</key>
  <dict>
{env}  </dict>
  <key>StandardOutPath</key>
  <string>{log}</string>
  <key>StandardErrorPath</key>
  <string>{log}</string>
</dict>
</plist>
"#,
            label = escape(label),
            program = escape(&spec.program.display().to_string()),
            env = env,
            log = escape(&spec.log.display().to_string()),
        )
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn spec() -> Spec {
            Spec {
                program: PathBuf::from("/opt/homebrew/bin/astd"),
                home: Some(PathBuf::from("/private/tmp/ast home")),
                path_env: "/opt/homebrew/bin:/usr/bin".into(),
                log: PathBuf::from("/private/tmp/ast home/astd.log"),
            }
        }

        #[test]
        fn the_plist_promises_persistence_and_names_the_binary() {
            let text = plist(&spec(), LABEL);
            assert!(text.contains("<key>KeepAlive</key>\n  <true/>"), "{text}");
            assert!(text.contains("<key>RunAtLoad</key>\n  <true/>"), "{text}");
            assert!(text.contains("/opt/homebrew/bin/astd"));
            // The daemon inherits the home and the PATH it was installed
            // with; launchd supplies neither.
            assert!(text.contains("ASTERISM_HOME"));
            assert!(text.contains("/private/tmp/ast home"));
            assert!(text.contains("/opt/homebrew/bin:/usr/bin"));
            assert!(text.contains(LABEL));
        }

        /// Status has to recover the recorded binary path to tell a user
        /// their unit points at something that moved.
        #[test]
        fn the_recorded_program_round_trips() {
            let text = plist(&spec(), LABEL);
            assert_eq!(
                program_from_plist(&text),
                Some(PathBuf::from("/opt/homebrew/bin/astd"))
            );
            assert_eq!(program_from_plist("<plist></plist>"), None);
        }

        #[test]
        fn a_home_with_xml_in_it_cannot_break_the_plist() {
            let mut s = spec();
            s.home = Some(PathBuf::from("/tmp/a<b>&c"));
            let text = plist(&s, LABEL);
            assert!(text.contains("/tmp/a&lt;b&gt;&amp;c"), "{text}");
        }

        #[test]
        fn launchctl_print_fields_are_read_off_the_indented_output() {
            let out = "com.asterism.astd = {\n\tstate = running\n\tpid = 4242\n}";
            assert_eq!(field(out, "pid = "), Some("4242".into()));
            assert_eq!(field(out, "state = "), Some("running".into()));
            assert_eq!(field(out, "nope = "), None);
        }
    }
}

// ---- Linux: systemd user unit ----------------------------------------------

#[cfg(target_os = "linux")]
mod imp {
    use std::path::PathBuf;

    use anyhow::{Context, Result};

    use super::{home, run, test_label, Manager, Report, Spec, State};

    pub fn manager() -> Result<Box<dyn Manager>> {
        let unit =
            test_label()?.map_or_else(|| UNIT.to_owned(), |label| format!("{label}.service"));
        Ok(Box::new(Systemd { unit }))
    }

    pub struct Systemd {
        unit: String,
    }

    const UNIT: &str = "astd.service";

    fn systemctl_present() -> bool {
        std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
            .any(|d| d.join("systemctl").is_file())
    }

    impl Manager for Systemd {
        fn mechanism(&self) -> &'static str {
            "systemd (user)"
        }

        fn unit_path(&self) -> PathBuf {
            let base = std::env::var_os("XDG_CONFIG_HOME")
                .map(PathBuf::from)
                .unwrap_or_else(|| {
                    home()
                        .unwrap_or_else(|_| PathBuf::from("."))
                        .join(".config")
                });
            base.join("systemd/user").join(&self.unit)
        }

        fn install(&self, spec: &Spec) -> Result<Report> {
            let unit = self.unit_path();
            let mut report = Report {
                unit: unit.clone(),
                ..Report::default()
            };
            if let Some(dir) = unit.parent() {
                std::fs::create_dir_all(dir)
                    .with_context(|| format!("creating {}", dir.display()))?;
            }
            crate::durable::commit(&unit, service_unit(spec).as_bytes())
                .with_context(|| format!("writing {}", unit.display()))?;
            report.step(format!("wrote {}", unit.display()));

            // Writing the file is the part that always works. Enabling it
            // needs systemctl, which a container or a non-systemd distro
            // may not have — say so instead of failing the install.
            if !systemctl_present() {
                report.step("systemctl is not on PATH: the unit is written but not enabled");
                return Ok(report);
            }
            let (_, _) =
                run(std::process::Command::new("systemctl").args(["--user", "daemon-reload"]))?;
            report.step("systemctl --user daemon-reload");
            let (ok, out) = run(std::process::Command::new("systemctl")
                .args(["--user", "enable", "--now", &self.unit]))?;
            if !ok {
                anyhow::bail!("systemctl could not enable {}: {}", self.unit, out.trim());
            }
            report.step(format!("systemctl --user enable --now {}", self.unit));
            report.step(enable_linger()?);
            Ok(report)
        }

        fn uninstall(&self) -> Result<Report> {
            let unit = self.unit_path();
            let mut report = Report {
                unit: unit.clone(),
                ..Report::default()
            };
            if systemctl_present() {
                let (ok, out) = run(std::process::Command::new("systemctl")
                    .args(["--user", "disable", "--now", &self.unit]))?;
                report.step(match ok {
                    true => format!("systemctl --user disable --now {}", self.unit),
                    false => format!("systemd had nothing enabled ({})", out.trim()),
                });
            }
            match std::fs::remove_file(&unit) {
                Ok(()) => report.step(format!("removed {}", unit.display())),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    report.step(format!("{} was not there", unit.display()))
                }
                Err(e) => return Err(e).with_context(|| format!("removing {}", unit.display())),
            }
            // The commit leaves a last-known-good copy beside the unit.
            // Uninstall means uninstall: it goes too, or the next `ls` of
            // that directory would find Asterism still in it.
            let _ = std::fs::remove_file(crate::durable::backup_path(&unit));
            if systemctl_present() {
                let _ =
                    run(std::process::Command::new("systemctl").args(["--user", "daemon-reload"]))?;
            }
            Ok(report)
        }

        fn status(&self) -> Result<State> {
            let unit = self.unit_path();
            if !unit.exists() {
                return Ok(State::missing(unit));
            }
            let text = std::fs::read_to_string(&unit).unwrap_or_default();
            let program = text
                .lines()
                .find_map(|l| l.trim().strip_prefix("ExecStart="))
                .map(PathBuf::from);
            let mut state = State {
                unit,
                installed: true,
                loaded: false,
                pid: None,
                program: program.clone(),
                notes: Vec::new(),
            };
            if let Some(p) = &program {
                if !p.exists() {
                    state.notes.push(format!(
                        "{} is gone — run `ast service install` again",
                        p.display()
                    ));
                }
            }
            if !systemctl_present() {
                state.notes.push("systemctl is not on PATH".into());
                return Ok(state);
            }
            let (_, enabled) = run(std::process::Command::new("systemctl").args([
                "--user",
                "is-enabled",
                &self.unit,
            ]))?;
            state.loaded = enabled.trim() == "enabled";
            let (_, props) = run(std::process::Command::new("systemctl").args([
                "--user",
                "show",
                &self.unit,
                "-p",
                "MainPID",
                "-p",
                "ActiveState",
            ]))?;
            for line in props.lines() {
                if let Some(v) = line.strip_prefix("MainPID=") {
                    state.pid = v.trim().parse().ok().filter(|p| *p != 0);
                }
                if let Some(v) = line.strip_prefix("ActiveState=") {
                    state.notes.push(format!("systemd state: {}", v.trim()));
                }
            }
            match linger_state() {
                Ok(true) => state
                    .notes
                    .push("lingering is on: astd survives logout and starts at boot".into()),
                Ok(false) => state.notes.push(format!(
                    "lingering is off — astd dies at logout. Enable it with: loginctl enable-linger {}",
                    user_name()
                )),
                Err(error) => state.notes.push(format!("linger: {error:#}")),
            }
            Ok(state)
        }
    }

    fn user_name() -> String {
        std::env::var("USER").unwrap_or_else(|_| "$USER".into())
    }

    fn linger_state() -> Result<bool> {
        if !std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
            .any(|dir| dir.join("loginctl").is_file())
        {
            anyhow::bail!("loginctl is not on PATH");
        }
        let (ok, out) =
            run(std::process::Command::new("loginctl").args(["show-user", "-p", "Linger"]))?;
        if !ok {
            anyhow::bail!("{}", out.trim());
        }
        crate::doctor::parse_linger_property(&out)
            .ok_or_else(|| anyhow::anyhow!("loginctl did not report Linger"))
    }

    /// A user unit dies at logout unless lingering is on, which is the
    /// difference between "starts when I log in" and "never sleeps".
    fn enable_linger() -> Result<String> {
        let user = user_name();
        match linger_state() {
            Ok(true) => {
                return Ok("lingering is on: astd survives logout and starts at boot".into())
            }
            Ok(false) => {}
            Err(_) => {}
        }
        if !std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
            .any(|dir| dir.join("loginctl").is_file())
        {
            return Ok(format!(
                "for a daemon that survives logout: loginctl enable-linger {user}"
            ));
        }
        let (ok, out) = run(std::process::Command::new("loginctl").args(["enable-linger", &user]))?;
        if ok {
            Ok(format!("loginctl enable-linger {user}"))
        } else {
            Ok(format!(
                "lingering is off ({}); enable it with: loginctl enable-linger {user}",
                out.trim()
            ))
        }
    }

    /// `Restart=always` with a five second gap is the systemd spelling of
    /// launchd's `KeepAlive`; `default.target` is the spelling of
    /// `RunAtLoad`.
    fn service_unit(spec: &Spec) -> String {
        let mut env = format!("Environment=PATH={}\n", spec.path_env);
        if let Some(home) = &spec.home {
            env.push_str(&format!("Environment=ASTERISM_HOME={}\n", home.display()));
        }
        format!(
            "[Unit]\n\
             Description=Asterism device daemon\n\
             After=network.target\n\
             \n\
             [Service]\n\
             Type=simple\n\
             ExecStart={program}\n\
             Restart=always\n\
             RestartSec=5\n\
             {env}\
             \n\
             [Install]\n\
             WantedBy=default.target\n",
            program = spec.program.display(),
            env = env,
        )
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn the_unit_restarts_forever_and_carries_the_home() {
            let unit = service_unit(&Spec {
                program: PathBuf::from("/usr/local/bin/astd"),
                home: Some(PathBuf::from("/srv/asterism")),
                path_env: "/usr/local/bin:/usr/bin".into(),
                log: PathBuf::from("/srv/asterism/astd.log"),
            });
            assert!(unit.contains("ExecStart=/usr/local/bin/astd"));
            assert!(unit.contains("Restart=always"));
            assert!(unit.contains("Environment=ASTERISM_HOME=/srv/asterism"));
            assert!(unit.contains("WantedBy=default.target"));
        }

        #[test]
        fn linger_properties_are_the_loginctl_words() {
            assert_eq!(
                crate::doctor::parse_linger_property("Linger=yes"),
                Some(true)
            );
            assert_eq!(
                crate::doctor::parse_linger_property("Linger=no"),
                Some(false)
            );
        }
    }
}

// ---- Windows: undecided ----------------------------------------------------

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
mod imp {
    use anyhow::{bail, Result};

    use super::Manager;

    pub fn manager() -> Result<Box<dyn Manager>> {
        bail!(
            "installing astd as a service is not built for this OS yet — the \
             Windows row of docs/PLATFORM.md (a Windows Service via \
             `windows-service`) is still to do. Until then, start astd yourself."
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_summary_exists_for_every_shape_of_state() {
        let unit = PathBuf::from("/tmp/unit");
        assert_eq!(State::missing(unit.clone()).summary(), "not installed");
        let mut s = State::missing(unit);
        s.installed = true;
        assert_eq!(s.summary(), "installed, not loaded");
        s.loaded = true;
        assert_eq!(s.summary(), "loaded, not running");
        s.pid = Some(7);
        assert_eq!(s.summary(), "running (pid 7)");
    }

    /// The seam must find the daemon that belongs to *this* build, not
    /// whatever `astd` a PATH happens to hold first — the sibling wins.
    #[test]
    fn the_spec_names_an_absolute_program() {
        let dir = tempfile::tempdir().unwrap();
        let fake = dir.path().join("astd");
        std::fs::write(&fake, b"#!/bin/sh\n").unwrap();
        let spec = Spec::for_program(&fake).unwrap();
        assert!(spec.program.is_absolute());
        assert!(spec.program.ends_with("astd"));
        assert!(!spec.path_env.is_empty());
    }

    #[test]
    fn a_program_that_is_not_there_is_refused_at_install_time() {
        assert!(Spec::for_program(Path::new("/no/such/astd")).is_err());
    }

    #[test]
    fn test_service_labels_are_bounded_and_namespaced() {
        assert!(validate_test_label("com.asterism.astd.test.profile-123").is_ok());
        assert!(validate_test_label(LABEL).is_err());
        assert!(validate_test_label("com.asterism.astd.test.bad/name").is_err());
        assert!(validate_test_label("com.asterism.astd.test.bad..name").is_err());
    }
}
