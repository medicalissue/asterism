//! A failed command has to say everything it knows, once.
//!
//! The regression this pins down (AST-141): `ast pull` on a host without
//! `curl` printed `Error: fetching the guest kernel from …` and nothing else,
//! so the sentence that actually named the problem — and the one-line command
//! that fixes it — never reached the terminal.
//!
//! The pull is driven through the protocol-1-through-5 fallback, which is the
//! one path that does the work in this process, so the whole `anyhow` chain
//! really is the CLI's to print.

#![cfg(unix)]

use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::process::{Command, Output};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use serde_json::Value;

/// A daemon old enough that image frames are refused, which sends the CLI
/// down its own in-process pull.
fn legacy_daemon(socket: &Path) -> JoinHandle<()> {
    let listener = UnixListener::bind(socket).unwrap();
    fs::set_permissions(socket, fs::Permissions::from_mode(0o600)).unwrap();
    thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let mut ping = String::new();
        reader.read_line(&mut ping).unwrap();
        writeln!(
            stream,
            r#"{{"result":"pong","version":"ast141-fixture","protocol":5,"min_protocol":1}}"#
        )
        .unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut rest = String::new();
        let _ = reader.read_line(&mut rest);
        drop(stream as UnixStream);
    })
}

/// Run `ast` on a host where `curl` cannot be found anywhere.
fn pull_without_curl(extra: &[&str]) -> Output {
    let home = tempfile::tempdir().unwrap();
    let empty = tempfile::tempdir().unwrap();
    let socket = home.path().join("astd.sock");
    let server = legacy_daemon(&socket);

    let mut args = vec!["pull", "busybox:musl"];
    args.extend_from_slice(extra);
    let output = Command::new(env!("CARGO_BIN_EXE_ast"))
        .env("ASTERISM_HOME", home.path())
        // Both halves of the search have to be emptied: `tool` falls back to
        // `/usr/bin` and friends precisely because a daemon's PATH cannot be
        // trusted, and on a real host `curl` is sitting in one of them.
        .env("PATH", empty.path())
        .env("ASTERISM_TOOL_DIRS", empty.path())
        .args(&args)
        .output()
        .unwrap();
    server.join().unwrap();
    output
}

#[test]
fn a_missing_curl_names_itself_and_the_command_that_installs_it() {
    let output = pull_without_curl(&[]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "the pull should have failed");

    let first = stderr
        .lines()
        .find(|line| line.starts_with("error: "))
        .unwrap_or_else(|| panic!("no error line in:\n{stderr}"));
    // The first line is unchanged from what this bug already printed: the
    // outermost context, verbatim. Everything new is below it.
    assert!(
        first.starts_with("error: fetching the guest kernel from https://"),
        "the first line should still name what was being done: {first}"
    );
    assert!(
        stderr.contains("  caused by: curl not found — is it installed and on PATH?"),
        "the chain was swallowed:\n{stderr}"
    );
    let fix = stderr
        .lines()
        .find(|line| line.starts_with("  fix: "))
        .unwrap_or_else(|| panic!("no fix line in:\n{stderr}"));
    assert!(fix.contains("curl"), "the fix does not name curl: {fix}");
    assert!(
        fix.split_whitespace().count() >= 4,
        "the fix is not a command to run: {fix}"
    );
}

#[test]
fn the_same_failure_in_json_carries_causes_and_fix() {
    let output = pull_without_curl(&["--json"]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "the pull should have failed");

    let line = stderr
        .lines()
        .find(|line| line.trim_start().starts_with('{'))
        .unwrap_or_else(|| panic!("no JSON object in:\n{stderr}"));
    let value: Value = serde_json::from_str(line).unwrap();
    assert!(value["error"].is_string(), "{value}");
    let causes = value["causes"].as_array().expect("causes is an array");
    assert!(
        causes.iter().any(|cause| cause
            .as_str()
            .is_some_and(|c| c.starts_with("curl not found"))),
        "{value}"
    );
    let fix = value["fix"].as_str().expect("a fix for a missing tool");
    assert!(fix.contains("curl"), "{fix}");
}
