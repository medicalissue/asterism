//! Saying what happened.
//!
//! A tray app has no window to put an error in, and the threads that do
//! the work have nobody to return one to. So every action ends here:
//!
//! * one line into `$ASTERISM_HOME/gui.log`, success or failure, which is
//!   the record you read afterwards to find out what the app did;
//! * a macOS notification on failure, which is the part the user sees
//!   while it is still relevant.
//!
//! Nothing in this module returns an error or panics. A logger that took
//! the menu bar down when the disk filled up would be a worse bug than
//! anything it could report.

use std::fmt::Write as _;
use std::fs::OpenOptions;
use std::io::Write as _;

use tauri::AppHandle;
use tauri_plugin_notification::NotificationExt;

use asterism_core::instance::now_unix;
use asterism_core::paths;

/// One line of a job in progress, on its way to a window or to a log.
///
/// Three things in this app take long enough to need one — a create, a
/// pairing and a wake — and all three are driven headlessly by a `--via`
/// hook as well as by a button, so what they report to is a parameter
/// rather than a webview.
pub type Progress<'a> = &'a (dyn Fn(&str) + Send + Sync);

/// File name under `ASTERISM_HOME`.
const LOG: &str = "gui.log";
/// A notification body is a banner, not a transcript.
const BODY_WIDTH: usize = 200;

/// Record how an action went, tell the user if it went badly, and hand the
/// reason back.
///
/// The reason is the daemon's own formatted message, and it goes three
/// places from here: the log, the notification banner, and — through this
/// return — the window that asked. A pane that said "failed, see the
/// notification" would be sending the user to another surface to read a
/// sentence this one already has.
pub fn report<T>(app: &AppHandle, action: &str, result: anyhow::Result<T>) -> Result<(), String> {
    match result {
        Ok(_) => {
            log(&format!("ok   {action}"));
            Ok(())
        }
        Err(e) => {
            let reason = reason(&e);
            failed(app, action, &reason);
            Err(reason)
        }
    }
}

/// A failure as one string, with every layer of context the daemon and the
/// client wrapped around it.
///
/// `{:#}` and not `{}`: the plain form prints only the outermost context,
/// which on this client is almost always "starting dev" — true, and not the
/// half anybody needs. The alternate form keeps the daemon's own sentence,
/// which is the half that says why.
pub fn reason(error: &anyhow::Error) -> String {
    format!("{error:#}")
}

/// An action that was not attempted, and why. No notification: nothing
/// happened, nothing failed, and a banner about a frame that was never sent
/// would be noise about a guard doing its job.
pub fn skipped(action: &str, why: &str) {
    log(&format!("skip {action}: {why}"));
}

/// An action that did not happen, and why.
pub fn failed(app: &AppHandle, action: &str, reason: &str) {
    log(&format!("FAIL {action}: {reason}"));
    notify(app, &format!("{action} failed"), reason);
}

/// Post a notification, best effort. An unbundled build (`cargo run`) has
/// no bundle identifier for Notification Center to attribute this to and
/// will refuse it; the log line above has already been written, so the
/// failure is recorded rather than silent.
fn notify(app: &AppHandle, title: &str, body: &str) {
    let result = app
        .notification()
        .builder()
        .title(title)
        .body(one_line(body, BODY_WIDTH))
        .show();
    if let Err(e) = result {
        log(&format!("FAIL notifying {title:?}: {e}"));
    }
}

/// Append one stamped line to the log, and echo it to stderr for whoever
/// is running this from a terminal.
///
/// The file comes first and the echo second, which is not the obvious
/// order: stderr is the half that can be gone (a closed pipe, a parent
/// that exited), and the durable record must not be lost to that.
pub fn log(line: &str) {
    let dir = paths::home_dir();
    let _ = std::fs::create_dir_all(&dir);
    let path = dir.join(LOG);
    match OpenOptions::new().create(true).append(true).open(&path) {
        Ok(mut file) => {
            let _ = writeln!(file, "{} {line}", stamp(now_unix()));
        }
        Err(e) => echo(&format!("could not write {}: {e}", path.display())),
    }
    echo(line);
}

/// `eprintln!` panics when stderr is a closed pipe, and a panic on a
/// worker thread would cost us the very thing that thread was doing. This
/// is the same line, minus the panic.
pub fn echo(line: &str) {
    let _ = writeln!(std::io::stderr(), "{line}");
}

/// `YYYY-MM-DDTHH:MM:SSZ`. UTC, because a log that shifts twice a year is
/// not a log; hand-rolled, because one timestamp does not justify a
/// calendar crate in a menu bar app.
fn stamp(unix_secs: u64) -> String {
    let (year, month, day) = civil_from_days((unix_secs / 86_400) as i64);
    let secs = unix_secs % 86_400;
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        secs / 3600,
        (secs % 3600) / 60,
        secs % 60
    )
}

/// Days since the unix epoch to a civil date (Howard Hinnant's algorithm).
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

/// Daemon errors are context-chained over several lines and can run long.
/// A notification banner shows two or three lines and truncates the rest
/// without saying so, which is how a useful error turns into a mystery.
fn one_line(s: &str, width: usize) -> String {
    let mut out = String::new();
    for (i, part) in s.split('\n').map(str::trim).filter(|p| !p.is_empty()).enumerate() {
        if i > 0 {
            out.push_str(" — ");
        }
        let _ = write!(out, "{part}");
    }
    if out.chars().count() <= width {
        return out;
    }
    let head: String = out.chars().take(width.saturating_sub(1)).collect();
    format!("{head}…")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stamps_are_utc_iso_8601() {
        assert_eq!(stamp(0), "1970-01-01T00:00:00Z");
        assert_eq!(stamp(1_700_000_000), "2023-11-14T22:13:20Z");
        assert_eq!(stamp(1_709_164_800), "2024-02-29T00:00:00Z");
    }

    /// What the window's status row ends up showing. The daemon's refusal
    /// has to survive the trip: a pane that said "failed — see the
    /// notification" would be sending the user to another surface to read a
    /// sentence this one already had.
    #[test]
    fn a_failure_keeps_the_daemons_own_sentence() {
        let daemon = anyhow::anyhow!(
            "instance \"gui-a\" is running — stop it before renaming it"
        );
        let wrapped = daemon.context("renaming gui-a");
        let said = reason(&wrapped);
        assert!(said.contains("stop it before renaming it"), "{said}");
        assert!(said.contains("renaming gui-a"), "{said}");
        assert!(!said.contains("see the notification"), "{said}");
    }

    #[test]
    fn a_chained_error_becomes_one_readable_line() {
        let body = one_line("starting dev\n\ncaused by: no such image\n", BODY_WIDTH);
        assert_eq!(body, "starting dev — caused by: no such image");
    }

    #[test]
    fn a_very_long_error_is_cut_and_says_so() {
        let body = one_line(&"x".repeat(500), BODY_WIDTH);
        assert_eq!(body.chars().count(), BODY_WIDTH);
        assert!(body.ends_with('…'));
    }
}
