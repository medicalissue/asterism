//! The helper's control socket.
//!
//! Everything in here runs on threads that are *not* the VM's queue, which
//! is the entire design constraint: a blocked accept or a half-open client
//! connection must never delay the run loop the guest is running on (spike
//! landmine 9). So the socket threads do nothing but move JSON, and hand
//! every command to the main thread through a channel.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::mpsc::{Receiver, Sender};
use std::time::Duration;

use anyhow::{Context, Result};

use asterism_vz::{Command, Reply};

/// One command, and where its answer goes back to.
pub struct Job {
    pub command: Command,
    pub reply: Sender<Reply>,
}

/// How long a client waits for the main thread to answer. Generous because
/// `stop` legitimately takes as long as a guest takes to shut down; the
/// daemon side sets its own, shorter, read timeout on top of this.
const REPLY_TIMEOUT: Duration = Duration::from_secs(300);

/// Bind the control socket, replacing one left behind by a dead helper.
///
/// Bound *before* the VM starts, so the daemon can connect the moment the
/// process exists and watch the guest come up rather than poll a file into
/// existence.
pub fn listen(path: &Path) -> Result<UnixListener> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    // A leftover socket file blocks bind. A *live* helper would still be
    // accepting on it, and this process is the one instance's owner, so
    // refuse rather than steal the socket from a helper that is already up.
    if path.exists() {
        if UnixStream::connect(path).is_ok() {
            anyhow::bail!(
                "another vz helper is already listening on {} — that guest is running",
                path.display()
            );
        }
        std::fs::remove_file(path)?;
    }
    UnixListener::bind(path).with_context(|| format!("binding {}", path.display()))
}

/// Serve the socket forever on a thread of its own, one thread per client.
///
/// A client thread blocks while the main thread works, which is fine and
/// deliberate: `stop` is a request whose answer *is* the outcome, so the
/// caller waits for the delegate to confirm rather than polling.
pub fn serve(listener: UnixListener, jobs: Sender<Job>) {
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            let jobs = jobs.clone();
            std::thread::spawn(move || {
                if let Err(e) = converse(stream, jobs) {
                    eprintln!("astd-vz: control connection ended: {e:#}");
                }
            });
        }
    });
}

fn converse(stream: UnixStream, jobs: Sender<Job>) -> Result<()> {
    let mut write = stream.try_clone()?;
    let reader = BufReader::new(stream);
    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let reply = match serde_json::from_str::<Command>(&line) {
            Ok(command) => ask(&jobs, command),
            Err(e) => Reply::Error { message: format!("bad command: {e}") },
        };
        let mut out = serde_json::to_vec(&reply)?;
        out.push(b'\n');
        write.write_all(&out)?;
        write.flush()?;
    }
    Ok(())
}

/// Hand one command to the main thread and wait for its answer.
fn ask(jobs: &Sender<Job>, command: Command) -> Reply {
    let (tx, rx): (Sender<Reply>, Receiver<Reply>) = std::sync::mpsc::channel();
    if jobs.send(Job { command, reply: tx }).is_err() {
        // The run loop is gone, which means so is the guest.
        return Reply::Error { message: "the vz helper is shutting down".into() };
    }
    match rx.recv_timeout(REPLY_TIMEOUT) {
        Ok(reply) => reply,
        Err(_) => Reply::Error {
            message: "the vz helper's run loop did not answer in time".into(),
        },
    }
}
