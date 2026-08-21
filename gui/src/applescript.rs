//! The one thing this app asks the system to do that has no library call
//! behind it: open a Terminal window on an instance.
//!
//! It goes out through `osascript`, and it crosses two quoting boundaries —
//! AppleScript string literal, then shell word — so the escaping is written
//! once, here, and tested.
//!
//! ## Where the confirmations went
//!
//! Two dialog mechanisms were tried here and neither is what the
//! destructive actions need.
//!
//! `tauri-plugin-dialog` was first, and on this app it does not work. With
//! no parent window to attach to, `rfd` falls back to
//! `CFUserNotificationDisplayAlert`, which in an Accessory-policy process
//! returns the *default* response without ever drawing anything: the
//! confirmation silently answered "yes" and the restore went ahead. A
//! confirmation that cannot fail closed is worse than none.
//!
//! `display dialog` replaced it and does draw, but it is a yes/no box: it
//! cannot ask somebody to type an instance's name, and a snapshot restore
//! and an instance removal both need exactly that. So the confirmations now
//! live in the main window as `ConfirmDialog`, and the token they collect is
//! checked in Rust by `crate::perform` — which is also what makes `--click
//! rm:dev` harmless without `--confirm dev`.

use std::ffi::OsStr;
use std::path::Path;
use std::process::{Command, Output};

use anyhow::{bail, Context, Result};

use crate::client;

/// Open a Terminal.app window running `ast ssh <name>`.
///
/// An app launched from Finder has a `PATH` with no `~/.cargo/bin` in it,
/// so the `ast` we hand over is an absolute path, resolved the same way
/// the daemon is ([`client::ast_path`]).
pub fn open_terminal(name: &str) -> Result<()> {
    let command = ssh_command(&client::ast_path(), name, std::env::var_os("ASTERISM_HOME"));
    run(&tell_terminal(&command)).map(drop)
}

/// The shell line Terminal will run.
///
/// `ASTERISM_HOME` is carried across when it is set: we are talking to a
/// daemon in that home, and a CLI that looked somewhere else would report
/// that the instance does not exist.
fn ssh_command(ast: &Path, name: &str, home: Option<impl AsRef<OsStr>>) -> String {
    let mut line = String::new();
    if let Some(home) = home {
        line.push_str("ASTERISM_HOME=");
        line.push_str(&shell_quote(&home.as_ref().to_string_lossy()));
        line.push(' ');
    }
    line.push_str(&shell_quote(&ast.to_string_lossy()));
    line.push_str(" ssh ");
    line.push_str(&shell_quote(name));
    line
}

/// Wrap a shell line in the AppleScript that puts it in a new window.
///
/// `do script` before `activate`, and not the other way round: when
/// Terminal is not already running, activating it opens an empty window
/// and `do script` then opens a second one.
fn tell_terminal(command: &str) -> String {
    format!(
        "tell application \"Terminal\"\ndo script {}\nactivate\nend tell",
        applescript_string(command)
    )
}

fn run(script: &str) -> Result<Output> {
    let out = Command::new("osascript")
        .arg("-e")
        .arg(script)
        .output()
        .context("running osascript")?;
    if !out.status.success() {
        // osascript puts the useful part on stderr and nothing on stdout.
        let why = String::from_utf8_lossy(&out.stderr);
        let why = why.trim();
        bail!(
            "osascript failed{}{}",
            if why.is_empty() { "" } else { ": " },
            why
        );
    }
    Ok(out)
}

/// One shell word, safe whatever is in it: single quotes take everything
/// literally, and the only character they cannot hold is the single quote
/// itself, which is spliced in as `'\''`.
fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

/// One AppleScript string literal. Backslash first, or the escaping of
/// everything after it would itself be escaped. Newlines are turned into
/// `\n` rather than left alone: inside `do script` a raw newline is not a
/// quoting nicety, it is a second command.
fn applescript_string(s: &str) -> String {
    let escaped = s
        .replace('\\', r"\\")
        .replace('"', "\\\"")
        .replace('\n', r"\n")
        .replace('\r', r"\r");
    format!("\"{escaped}\"")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn a_plain_command_is_an_absolute_ast_and_a_name() {
        let cmd = ssh_command(&PathBuf::from("/opt/homebrew/bin/ast"), "dev", None::<&str>);
        assert_eq!(cmd, "'/opt/homebrew/bin/ast' ssh 'dev'");
    }

    #[test]
    fn the_home_we_are_talking_to_comes_along() {
        let cmd = ssh_command(&PathBuf::from("/bin/ast"), "dev", Some("/tmp/ast home"));
        assert_eq!(cmd, "ASTERISM_HOME='/tmp/ast home' '/bin/ast' ssh 'dev'");
    }

    #[test]
    fn quotes_in_a_path_cannot_break_out_of_the_word() {
        let cmd = ssh_command(&PathBuf::from("/tmp/it's/ast"), "dev", None::<&str>);
        assert_eq!(cmd, r"'/tmp/it'\''s/ast' ssh 'dev'");
        // What the shell would actually see: one word, the path verbatim.
        assert!(!cmd.starts_with("'/tmp/it' "));
    }

    #[test]
    fn applescript_strings_survive_quotes_and_backslashes() {
        assert_eq!(applescript_string(r#"a"b"#), r#""a\"b""#);
        assert_eq!(applescript_string(r"a\b"), r#""a\\b""#);
        // A backslash before a quote must not eat the quote's escape.
        assert_eq!(applescript_string("\\\""), r#""\\\"""#);
    }

    /// A newline that survived into `do script` would be a second command
    /// typed into the user's terminal.
    #[test]
    fn newlines_cannot_smuggle_a_second_command_in() {
        let script = tell_terminal(&ssh_command(
            &PathBuf::from("/bin/ast"),
            "dev\nrm -rf /",
            None::<&str>,
        ));
        let body = script.lines().nth(1).expect("do script is one line");
        assert!(body.starts_with("do script "), "{script}");
        assert!(body.contains(r"\n"), "the newline is escaped, not real: {body}");
        assert_eq!(script.lines().count(), 4, "no extra lines: {script}");
    }

    #[test]
    fn the_script_tells_terminal_to_run_the_command() {
        let script = tell_terminal("'/bin/ast' ssh 'dev'");
        assert!(script.contains("tell application \"Terminal\""));
        assert!(script.contains("activate"));
        assert!(script.contains(r#"do script "'/bin/ast' ssh 'dev'""#), "{script}");
        assert!(script.ends_with("end tell"));
    }

}
