//! The two things this app asks the system to do that have no library
//! call behind them: open a Terminal window on an instance, and put a
//! question on the screen.
//!
//! Both go out through `osascript`, and both cross the same two quoting
//! boundaries — AppleScript string literal, then, for the Terminal, shell
//! word — so the escaping is written once, here, and tested.
//!
//! ## Why not `tauri-plugin-dialog`
//!
//! It was the first thing tried, and on this app it does not work. With
//! no parent window to attach to, `rfd` falls back to
//! `CFUserNotificationDisplayAlert`, which in an Accessory-policy process
//! returns the *default* response without ever drawing anything: the
//! confirmation silently answered "yes" and the restore went ahead. A
//! confirmation that cannot fail closed is worse than none, so the plugin
//! went and `display dialog` — which blocks, needs no Automation
//! permission, and answers with the button that was pressed — stayed.

use std::ffi::OsStr;
use std::path::Path;
use std::process::{Command, Output};

use anyhow::{bail, Context, Result};

use crate::client;

/// How long a question stays on screen before it answers itself with "no".
/// A dialog nobody is there to answer should not park a thread and a
/// window forever.
const ANSWER_WITHIN: u32 = 120;

/// Open a Terminal.app window running `ast ssh <name>`.
///
/// An app launched from Finder has a `PATH` with no `~/.cargo/bin` in it,
/// so the `ast` we hand over is an absolute path, resolved the same way
/// the daemon is ([`client::ast_path`]).
pub fn open_terminal(name: &str) -> Result<()> {
    let command = ssh_command(&client::ast_path(), name, std::env::var_os("ASTERISM_HOME"));
    run(&tell_terminal(&command)).map(drop)
}

/// Ask a yes/no question. `ok` is the label of the button that means yes;
/// the other button is Cancel, and it is the default, because the only
/// thing we ask about is destructive.
///
/// Anything that is not an unambiguous press of `ok` — Cancel, the escape
/// key, the timeout, a broken `osascript` — is a no.
pub fn confirm(title: &str, message: &str, ok: &str) -> Result<bool> {
    let script = format!(
        // `tell me to activate` is what brings the dialog in front of
        // whatever the user was looking at; without it a menu bar app's
        // question can open behind the window it is about.
        "tell me to activate\n\
         display dialog {} with title {} buttons {{\"Cancel\", {}}} \
         default button \"Cancel\" with icon caution giving up after {ANSWER_WITHIN}",
        applescript_string(message),
        applescript_string(title),
        applescript_string(ok),
    );
    match run(&script) {
        Ok(out) => Ok(pressed(&String::from_utf8_lossy(&out.stdout), ok)),
        // Pressing a button literally named Cancel is how AppleScript
        // spells "the user said no": error -128, and not a failure.
        Err(e) if e.to_string().contains("-128") => Ok(false),
        Err(e) => Err(e),
    }
}

/// Did `display dialog`'s answer say that `ok` was pressed? Its output is
/// `button returned:Restore` — or `button returned:, gave up:true` when
/// nobody was there, which is a no.
fn pressed(stdout: &str, ok: &str) -> bool {
    stdout
        .trim()
        .split(", ")
        .filter_map(|field| field.split_once(':'))
        .any(|(key, value)| key == "button returned" && value == ok)
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

    /// Verbatim `display dialog` output, from osascript 2.7 on macOS 15.
    #[test]
    fn only_the_ok_button_is_a_yes() {
        assert!(pressed("button returned:Restore", "Restore"));
        assert!(!pressed("button returned:Cancel", "Restore"));
        // Nobody answered: the dialog gave up on its own.
        assert!(!pressed("button returned:, gave up:true", "Restore"));
        assert!(!pressed("", "Restore"), "silence is not consent");
        assert!(!pressed("button returned:Restore later", "Restore"));
    }

    #[test]
    fn the_question_names_the_instance_and_defaults_to_cancel() {
        // Built the same way `confirm` builds it, without running it.
        let script = format!(
            "display dialog {} with title {} buttons {{\"Cancel\", {}}} default button \"Cancel\"",
            applescript_string("Restore web to nightly?"),
            applescript_string("Restore snapshot"),
            applescript_string("Restore"),
        );
        assert!(script.contains(r#""Restore web to nightly?""#), "{script}");
        assert!(script.contains(r#"default button "Cancel""#), "{script}");
    }
}
