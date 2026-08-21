//! Everything `ast` has to do to get a question in front of a daemon: find
//! it, start it if it is not there, check it is the same vintage as us, and
//! read one line back.
//!
//! Split out from the commands so that a command is only ever the shape of
//! its request and the shape of its output. Nothing in [`crate::cmd`] opens a
//! socket, spawns a process or knows what a pid file is, and a new command
//! therefore cannot get any of that subtly wrong — there is only one copy of
//! it, here.
//!
//! It talks to the daemon in front of it and no other, ever. `--device` is an
//! envelope this module puts a request in ([`aimed`]), never a second
//! connection: the far daemon runs the identical frame its own CLI would have
//! handed it, which is why no command needed a second implementation to
//! become remote.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::time::Duration;

use anyhow::{bail, Context, Result};

use asterism_core::protocol::{self, Request, Response};
use asterism_core::{paths, VERSION};

/// Puts a request in the envelope `--device` implies.
///
/// The envelope is all `--device` is: the far daemon runs the identical frame
/// its own CLI would have handed it, which is why no command needed a second
/// implementation to become remote.
pub(crate) fn aimed(request: Request, device: Option<&str>) -> Request {
    match device {
        Some(name) => Request::Proxy { device: name.to_owned(), inner: Box::new(request) },
        None => request,
    }
}

/// Refuses `--device` on a command that could not mean anything remotely.
pub(crate) fn local_only(what: &str, device: Option<&str>) -> Result<()> {
    match device {
        Some(name) => bail!(
            "ast {what} is about this device, so it cannot be aimed at {name:?} \
             — run it on {name} instead"
        ),
        None => Ok(()),
    }
}

/// Ask, aiming the request where `--device` says, and turn the one reply
/// every command can get into the error the user sees.
///
/// The caller matches on what is left. Keeping the `Error` arm here rather
/// than in each command is not only brevity: a command that forgot it would
/// print "unexpected reply" over the top of a perfectly good sentence from
/// the daemon.
pub(crate) fn ask(request: &Request, device: Option<&str>) -> Result<Response> {
    match send(&aimed(request.clone(), device))? {
        Response::Error { message } => bail!(message),
        reply => Ok(reply),
    }
}

/// What to say when astd answers a question nobody asked.
///
/// It names the *request*, not the reply, on purpose: the useful half of
/// "this daemon and this CLI disagree" is which command was in flight.
pub(crate) fn unexpected(request: &Request) -> anyhow::Error {
    anyhow::anyhow!("unexpected reply from astd: {request:?}")
}

/// Send a request, having first established that the daemon on the other
/// end speaks our version of the protocol.
pub(crate) fn send(request: &Request) -> Result<Response> {
    ensure_current_daemon()?;
    let response = send_once(request)?;
    // Belt and braces: a daemon that was replaced between the handshake and
    // now still cannot produce a baffling serde error for the user.
    if let Response::Error { message } = &response {
        if protocol::is_unknown_variant_error(message) {
            retire_stale_daemon()?;
            return send_once(request);
        }
    }
    Ok(response)
}

/// Send a request whose whole answer is "it worked" or why it didn't.
pub(crate) fn send_ok(request: &Request) -> Result<()> {
    match send(request)? {
        Response::Ok => Ok(()),
        Response::Error { message } => bail!(message),
        other => bail!("unexpected reply from astd: {other:?}"),
    }
}

/// Connect to astd, spawning it first if the socket is not answering.
fn send_once(request: &Request) -> Result<Response> {
    let sock = paths::socket_path();
    let stream = match UnixStream::connect(&sock) {
        Ok(s) => s,
        Err(_) => {
            spawn_daemon()?;
            wait_for_socket(&sock)?
        }
    };

    let mut writer = stream.try_clone()?;
    let mut line = serde_json::to_string(request)?;
    line.push('\n');
    writer.write_all(line.as_bytes())?;

    let mut reply = String::new();
    BufReader::new(stream).read_line(&mut reply)?;
    if reply.trim().is_empty() {
        bail!("astd closed the connection without answering");
    }
    Ok(serde_json::from_str(&reply)?)
}

/// A request the daemon answers with more than one line.
///
/// Pairing was the first: the daemon has a ticket to print, then a code, and
/// it needs an answer before it will write anything down. Waking and moving
/// joined it, for the same reason in a different shape — minutes of work a
/// user should watch rather than wait through. The socket is line-delimited
/// JSON in both directions already, so this is the same wire — just a
/// conversation on it rather than a question.
pub(crate) struct Conversation {
    write: UnixStream,
    read: BufReader<UnixStream>,
}

impl Conversation {
    pub(crate) fn open(request: &Request) -> Result<Self> {
        ensure_current_daemon()?;
        let sock = paths::socket_path();
        let stream = match UnixStream::connect(&sock) {
            Ok(s) => s,
            Err(_) => {
                spawn_daemon()?;
                wait_for_socket(&sock)?
            }
        };
        let mut conn = Self { write: stream.try_clone()?, read: BufReader::new(stream) };
        conn.send(request)?;
        Ok(conn)
    }

    pub(crate) fn send(&mut self, request: &Request) -> Result<()> {
        let mut line = serde_json::to_string(request)?;
        line.push('\n');
        self.write.write_all(line.as_bytes())?;
        Ok(())
    }

    pub(crate) fn next(&mut self) -> Result<Response> {
        let mut line = String::new();
        self.read.read_line(&mut line)?;
        if line.trim().is_empty() {
            bail!("astd closed the connection without answering");
        }
        Ok(serde_json::from_str(&line)?)
    }
}

fn wait_for_socket(sock: &std::path::Path) -> Result<UnixStream> {
    let mut attempt = 0;
    loop {
        match UnixStream::connect(sock) {
            Ok(s) => return Ok(s),
            Err(e) if attempt >= 50 => return Err(e).context("astd did not come up"),
            Err(_) => {
                attempt += 1;
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }
}

// ---- version handshake -----------------------------------------------------
//
// The wire protocol is a pair of serde enums, so a daemon left running
// across an upgrade does not fail politely: it rejects the first request
// carrying a variant it has never heard of, and the user sees
// `bad request: unknown variant ...`. That is a true statement about
// nothing the user did. So `ast` asks the daemon its version before
// trusting it, and retires it if the answer is wrong.

/// Once per process: make sure the daemon we are about to talk to is ours.
fn ensure_current_daemon() -> Result<()> {
    use std::sync::OnceLock;
    static CHECKED: OnceLock<()> = OnceLock::new();
    if CHECKED.get().is_some() {
        return Ok(());
    }

    if let Some(found) = stale_version()? {
        eprintln!(
            "ast: astd {found} is running, but this is ast {VERSION} — restarting the daemon"
        );
        retire_stale_daemon()?;
        if let Some(still) = stale_version()? {
            bail!(
                "astd {still} is still running after a restart, but this is ast {VERSION}. \
                 Stop it by hand and try again."
            );
        }
    }

    let _ = CHECKED.set(());
    Ok(())
}

/// The version of the running daemon if it disagrees with ours, or `None`
/// if it matches. Spawns a daemon if none is running.
fn stale_version() -> Result<Option<String>> {
    match send_once(&Request::Ping)? {
        Response::Pong { version } if version == VERSION => Ok(None),
        Response::Pong { version } => Ok(Some(version)),
        // A daemon older than the Pong reply answers Ping with plain Ok.
        // The absence of a version is the mismatch.
        Response::Ok => Ok(Some(format!("older than {VERSION}"))),
        // Older still, or a build whose Ping means something else entirely.
        Response::Error { message } if protocol::is_unknown_variant_error(&message) => {
            Ok(Some(format!("older than {VERSION}")))
        }
        Response::Error { message } => bail!(message),
        other => bail!("unexpected reply to ping from astd: {other:?}"),
    }
}

/// Stop the daemon that is running and start ours in its place.
fn retire_stale_daemon() -> Result<()> {
    let pid = daemon_pid().context(
        "cannot tell which process is serving the astd socket, so it cannot be \
         restarted — stop astd by hand and try again",
    )?;

    signal(pid, "-TERM");
    if !wait_until_gone(pid, Duration::from_secs(10)) {
        // A daemon that will not take a hint. It holds the socket, so the
        // replacement cannot bind until it is gone.
        signal(pid, "-KILL");
        wait_until_gone(pid, Duration::from_secs(5));
    }
    // A hard-killed daemon leaves both of these behind; astd tolerates a
    // stale socket file, but the pid file would mislead the next restart.
    let _ = std::fs::remove_file(paths::daemon_pid_path());

    spawn_daemon()?;
    wait_for_socket(&paths::socket_path())?;
    Ok(())
}

/// Which process is serving the socket.
///
/// The pid file is the answer for any daemon new enough to write one. A
/// daemon from before it existed is still findable, because the socket it
/// holds open is a file with exactly one listener — and asking about that
/// specific path can never turn up somebody else's daemon, which matters
/// when several `ASTERISM_HOME`s are in play on one machine.
fn daemon_pid() -> Option<u32> {
    let pidfile = paths::daemon_pid_path();
    if let Some(pid) = std::fs::read_to_string(&pidfile)
        .ok()
        .and_then(|s| s.trim().parse::<u32>().ok())
    {
        if alive(pid) {
            return Some(pid);
        }
    }
    pid_holding(&paths::socket_path())
}

fn pid_holding(sock: &std::path::Path) -> Option<u32> {
    let out = std::process::Command::new("lsof")
        .arg("-t")
        .arg("--")
        .arg(sock)
        .output()
        .ok()?;
    out.stdout
        .split(|b| *b == b'\n')
        .filter_map(|l| String::from_utf8_lossy(l).trim().parse::<u32>().ok())
        .find(|pid| *pid != std::process::id())
}

fn alive(pid: u32) -> bool {
    std::process::Command::new("kill")
        .args(["-0", &pid.to_string()])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn signal(pid: u32, sig: &str) {
    let _ = std::process::Command::new("kill")
        .arg(sig)
        .arg(pid.to_string())
        .output();
}

fn wait_until_gone(pid: u32, budget: Duration) -> bool {
    let deadline = std::time::Instant::now() + budget;
    loop {
        if !alive(pid) {
            return true;
        }
        if std::time::Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn spawn_daemon() -> Result<()> {
    let astd = daemon_path()?;
    std::process::Command::new(&astd)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .with_context(|| format!("spawning {}", astd.display()))?;
    Ok(())
}

/// astd normally sits next to the ast binary; fall back to PATH.
fn daemon_path() -> Result<std::path::PathBuf> {
    if let Ok(me) = std::env::current_exe() {
        let sibling = me.with_file_name("astd");
        if sibling.exists() {
            return Ok(sibling);
        }
    }
    Ok(std::path::PathBuf::from("astd"))
}

/// Become astd. Only returns if the exec failed, which is why it returns an
/// error rather than a result.
pub(crate) fn exec_daemon() -> anyhow::Error {
    use std::os::unix::process::CommandExt;
    let astd = match daemon_path() {
        Ok(p) => p,
        Err(e) => return e,
    };
    std::process::Command::new(astd).exec().into()
}
