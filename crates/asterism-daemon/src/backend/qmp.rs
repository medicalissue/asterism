//! QMP, the QEMU control channel.
//!
//! One connection per running guest, held open for as long as the guest
//! lives, with replies matched to the commands that asked for them.
//!
//! ### Why it is held open
//!
//! QEMU's `-qmp unix:…,server,nowait` serves one client at a time and
//! sends events only to whoever is connected. A client that connects per
//! command, as this daemon used to, is disconnected for the whole gap
//! between commands, which is exactly when `SHUTDOWN`, `RESET` and
//! `JOB_STATUS_CHANGE` arrive. Holding the connection is what makes those
//! reachable at all, and it is why the `savevm`-style long-running jobs
//! (`snapshot-save`) become possible: their completion is an event, not a
//! return value.
//!
//! ### Why it is not async
//!
//! [`Hypervisor`](asterism_core::hv::Hypervisor) is a synchronous trait
//! and the daemon calls into it under `block_in_place`; neither backend in
//! this directory names tokio. A QMP client that needed a runtime handle
//! would put one inside the backend layer, and a backend that needs a
//! runtime cannot be tested without one. So the connection owns a reader
//! thread, commands block on a channel, and the async half of the daemon
//! stays on its own side of the trait.
//!
//! ### Correlation
//!
//! Every command carries an `id`. The reader thread routes a message with
//! an `id` to the waiter that registered it and a message with an `event`
//! to [`deliver`]. Nothing depends on replies arriving in the order the
//! commands were sent, because QMP does not promise that.
//!
//! ### What is deliberately not wired yet
//!
//! Events are decoded and logged, and no caller acts on them. Routing
//! `SHUTDOWN` into `persist::note_died` looks like a two-line change and
//! is not: `main::down` cancels a restart *before* it calls `stop`, so a
//! `SHUTDOWN` arriving during a deliberate `ast down` would re-owe the
//! restart it just cancelled and turn every `ast down` into a reboot. The
//! ordering has to be fixed in the same change that consumes the event.

use std::collections::HashMap;
use std::fmt;
use std::io::{BufRead, BufReader, Write};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, RecvTimeoutError, SyncSender};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};

/// How long a connection has to greet us and accept `qmp_capabilities`.
/// A QEMU that has not spoken by now is wedged, and the caller wants to
/// hear that rather than wait on it.
const HANDSHAKE: Duration = Duration::from_secs(3);

/// How long a command waits for its own reply. QMP commands answer at
/// once (a long-running one answers immediately and finishes as a job),
/// so this bounds a wedged guest, not a slow one.
const REPLY: Duration = Duration::from_secs(5);

// ---- events ----------------------------------------------------------------

/// The guest-initiated state changes worth naming.
///
/// QMP emits many more. The ones below are the ones something in this
/// daemon either acts on or will: the first three are the registry
/// learning that a guest went away without being asked, and [`Event::Job`]
/// is how `snapshot-save` and `migrate` report that they finished.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// QEMU is going away. `guest` is true when the guest asked for it
    /// (its own `poweroff`) rather than the ACPI button this daemon presses.
    Shutdown { guest: bool },
    /// The guest rebooted itself. QEMU stays up and the pid does not change.
    Reset,
    /// The guest was paused, which is not the same as being powered off.
    Stopped,
    /// A long-running job changed state: `snapshot-save`, `migrate`.
    Job { id: String, status: String },
    /// Everything else, kept by name so a log line can say what arrived.
    Other(String),
}

impl Event {
    fn parse(name: &str, data: Option<&Value>) -> Event {
        let field = |k: &str| {
            data.and_then(|d| d.get(k))
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned()
        };
        match name {
            "SHUTDOWN" => Event::Shutdown {
                guest: data
                    .and_then(|d| d.get("guest"))
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
            },
            "RESET" => Event::Reset,
            "STOP" => Event::Stopped,
            "JOB_STATUS_CHANGE" => Event::Job {
                id: field("id"),
                status: field("status"),
            },
            other => Event::Other(other.to_owned()),
        }
    }
}

impl fmt::Display for Event {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Event::Shutdown { guest: true } => write!(f, "the guest powered itself down"),
            Event::Shutdown { guest: false } => write!(f, "the guest is powering down"),
            Event::Reset => write!(f, "the guest rebooted"),
            Event::Stopped => write!(f, "the guest was paused"),
            Event::Job { id, status } => write!(f, "job {id} is {status}"),
            Event::Other(name) => write!(f, "{name}"),
        }
    }
}

/// Where a decoded event goes.
///
/// The daemon's log, until something consumes them. The socket names the
/// guest rather than the instance name, because a [`Handle`] carries the
/// control path and not the name it belongs to: which instance owns a
/// control socket is the registry's answer to give, not a convention this
/// module gets to assume.
///
/// [`Handle`]: asterism_core::hv::Handle
fn deliver(sock: &Path, event: Event) {
    eprintln!("astd: qmp {}: {event}", sock.display());
}

// ---- the connection --------------------------------------------------------

pub struct Conn {
    sock: PathBuf,
    /// The write half. A command holds this only while it writes its line.
    write: Mutex<UnixStream>,
    /// Commands waiting on a reply, by the id they sent.
    pending: Mutex<HashMap<u64, SyncSender<Reply>>>,
    next_id: AtomicU64,
    alive: AtomicBool,
}

/// What the reader thread hands back to a waiting command.
type Reply = std::result::Result<Value, String>;

impl fmt::Debug for Conn {
    /// The socket and whether it still answers. The pending table and the
    /// stream itself say nothing a reader of a failure wants to know.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = match self.is_alive() {
            true => "open",
            false => "closed",
        };
        write!(f, "qmp({}, {state})", self.sock.display())
    }
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    // A panic inside one of this module's short critical sections would
    // leave every guest uncontrollable; take the lock anyway rather than
    // poison the daemon over bookkeeping.
    m.lock().unwrap_or_else(|e| e.into_inner())
}

impl Conn {
    /// Run one QMP command and return its `return` value.
    ///
    /// Blocks until the reply with this command's own id arrives, another
    /// message closes the connection, or [`REPLY`] passes.
    pub fn execute(&self, command: &str, arguments: Value) -> Result<Value> {
        if !self.alive.load(Ordering::Acquire) {
            bail!("the control channel for {} is closed", self.sock.display());
        }
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = sync_channel(1);
        lock(&self.pending).insert(id, tx);

        let mut line = json!({ "execute": command, "id": id });
        if !arguments.is_null() {
            line["arguments"] = arguments;
        }
        if let Err(e) = self.write_line(&line.to_string()) {
            lock(&self.pending).remove(&id);
            return Err(e).with_context(|| format!("sending qmp {command}"));
        }

        match rx.recv_timeout(REPLY) {
            Ok(Ok(value)) => Ok(value),
            Ok(Err(desc)) => bail!("qmp {command} failed: {desc}"),
            Err(RecvTimeoutError::Timeout) => {
                lock(&self.pending).remove(&id);
                bail!("qmp {command} went unanswered for {}s", REPLY.as_secs())
            }
            // The reader dropped the sender, which it does on the way out.
            Err(RecvTimeoutError::Disconnected) => {
                bail!("the control channel closed while qmp {command} was in flight")
            }
        }
    }

    fn write_line(&self, line: &str) -> Result<()> {
        let mut stream = lock(&self.write);
        stream.write_all(line.as_bytes())?;
        stream.write_all(b"\n")?;
        stream.flush()?;
        Ok(())
    }

    fn is_alive(&self) -> bool {
        self.alive.load(Ordering::Acquire)
    }

    /// Close this connection and fail everything waiting on it.
    ///
    /// Never touches the connection table: the reader thread calls this,
    /// and so does the loser of a two-thread open race that holds the
    /// table lock while it does.
    fn die(&self, why: &str) {
        if !self.alive.swap(false, Ordering::AcqRel) {
            return;
        }
        // Shutting the socket down is what ends the reader thread's read
        // when the caller is the one closing rather than the guest.
        let _ = lock(&self.write).shutdown(Shutdown::Both);
        for (_, waiter) in lock(&self.pending).drain() {
            let _ = waiter.send(Err(why.to_owned()));
        }
    }

    fn open(sock: &Path) -> Result<Arc<Conn>> {
        let stream = UnixStream::connect(sock)
            .with_context(|| format!("connecting to the control socket at {}", sock.display()))?;
        // A dup'd fd shares the socket's receive timeout, so setting it
        // here bounds the handshake read below and clearing it after
        // leaves the reader thread blocking, which is what it wants.
        stream.set_read_timeout(Some(HANDSHAKE))?;
        let mut reader = BufReader::new(stream.try_clone()?);

        let mut greeting = String::new();
        reader.read_line(&mut greeting)?;
        if !greeting.contains("\"QMP\"") {
            bail!(
                "{} answered, but not with a QMP greeting: {}",
                sock.display(),
                greeting.trim()
            );
        }

        // Capabilities negotiation happens before the reader thread
        // exists, so it is the one exchange this module reads by hand.
        // QEMU sends no events until it is done.
        let conn = Arc::new(Conn {
            sock: sock.to_owned(),
            write: Mutex::new(stream),
            pending: Mutex::new(HashMap::new()),
            next_id: AtomicU64::new(1),
            alive: AtomicBool::new(true),
        });
        conn.write_line(&json!({ "execute": "qmp_capabilities", "id": 0 }).to_string())?;
        loop {
            let mut line = String::new();
            if reader.read_line(&mut line)? == 0 {
                bail!(
                    "{} closed before it accepted qmp_capabilities",
                    sock.display()
                );
            }
            let Ok(msg) = serde_json::from_str::<Value>(&line) else {
                continue;
            };
            if let Some(error) = msg.get("error") {
                bail!("{} refused qmp_capabilities: {error}", sock.display());
            }
            if msg.get("return").is_some() {
                break;
            }
        }

        lock(&conn.write).set_read_timeout(None)?;
        let reading = conn.clone();
        std::thread::Builder::new()
            .name(format!("qmp {}", sock.display()))
            .spawn(move || read_loop(reading, reader))
            .context("starting the qmp reader")?;
        Ok(conn)
    }
}

/// Route every line the guest's monitor writes until it stops writing.
fn read_loop(conn: Arc<Conn>, reader: BufReader<UnixStream>) {
    for line in reader.lines() {
        let Ok(line) = line else { break };
        let Ok(msg) = serde_json::from_str::<Value>(&line) else {
            continue;
        };

        if let Some(id) = msg.get("id").and_then(Value::as_u64) {
            let waiter = lock(&conn.pending).remove(&id);
            if let Some(waiter) = waiter {
                let _ = waiter.send(reply_of(&msg));
            }
            continue;
        }
        if let Some(name) = msg.get("event").and_then(Value::as_str) {
            deliver(&conn.sock, Event::parse(name, msg.get("data")));
        }
    }
    conn.die("the guest's control channel closed");
    // Only evict this connection: a reconnect may already have replaced it.
    let mut table = table();
    if table
        .get(&conn.sock)
        .is_some_and(|live| Arc::ptr_eq(live, &conn))
    {
        table.remove(&conn.sock);
    }
}

fn reply_of(msg: &Value) -> Reply {
    if let Some(error) = msg.get("error") {
        let desc = error
            .get("desc")
            .and_then(Value::as_str)
            .unwrap_or_default();
        return Err(match desc.is_empty() {
            true => error.to_string(),
            false => desc.to_owned(),
        });
    }
    Ok(msg.get("return").cloned().unwrap_or(Value::Null))
}

// ---- the connection table --------------------------------------------------

fn table() -> MutexGuard<'static, HashMap<PathBuf, Arc<Conn>>> {
    static CONNS: OnceLock<Mutex<HashMap<PathBuf, Arc<Conn>>>> = OnceLock::new();
    lock(CONNS.get_or_init(|| Mutex::new(HashMap::new())))
}

/// The connection to a guest's monitor, opening one if there is none.
///
/// Keyed on the socket the [`Handle`] carries rather than on an instance
/// name, so nothing here depends on where a backend chose to put it.
///
/// [`Handle`]: asterism_core::hv::Handle
pub fn on(sock: &Path) -> Result<Arc<Conn>> {
    if let Some(live) = table().get(sock).filter(|c| c.is_alive()).cloned() {
        return Ok(live);
    }
    // Connecting talks to another process, so it happens outside the
    // table lock: one wedged guest must not stall every other guest's
    // commands for the length of the handshake.
    let fresh = Conn::open(sock)?;
    let mut table = table();
    if let Some(live) = table.get(sock).filter(|c| c.is_alive()).cloned() {
        // Another thread opened one while we were connecting. QEMU serves
        // one client, so ours goes away rather than sitting on the socket.
        fresh.die("superseded by a connection opened at the same moment");
        return Ok(live);
    }
    table.insert(sock.to_owned(), fresh.clone());
    Ok(fresh)
}

/// Drop any connection to `sock`.
///
/// Called where this daemon knows the guest behind it is gone or about to
/// be: a hard kill, and a boot that is about to bind the same path for a
/// different guest.
pub fn forget(sock: &Path) {
    let conn = table().remove(sock);
    if let Some(conn) = conn {
        conn.die("the guest it controlled was taken down");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixListener;

    /// A monitor that greets, accepts capabilities, then answers each
    /// command line with whatever `answer` returns for it.
    ///
    /// Returns the socket path and the directory holding it, which the
    /// caller keeps alive for as long as it wants the server.
    fn fake_monitor(
        answer: impl Fn(&Value) -> Vec<String> + Send + 'static,
    ) -> (PathBuf, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("qmp.sock");
        let listener = UnixListener::bind(&sock).unwrap();
        std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut write = stream.try_clone().unwrap();
            let reader = BufReader::new(stream);
            writeln!(write, r#"{{"QMP":{{"version":{{}},"capabilities":[]}}}}"#).unwrap();
            for line in reader.lines() {
                let Ok(line) = line else { break };
                let msg: Value = serde_json::from_str(&line).unwrap();
                if msg["execute"] == json!("qmp_capabilities") {
                    writeln!(write, r#"{{"return":{{}},"id":0}}"#).unwrap();
                    continue;
                }
                for out in answer(&msg) {
                    if writeln!(write, "{out}").is_err() {
                        return;
                    }
                }
            }
        });
        (sock, dir)
    }

    /// Answer every command with an empty `return` carrying its own id.
    fn echo(msg: &Value) -> Vec<String> {
        vec![json!({ "return": {}, "id": msg["id"] }).to_string()]
    }

    #[test]
    fn a_command_gets_its_own_reply() {
        let (sock, _dir) = fake_monitor(echo);
        let conn = on(&sock).unwrap();
        assert_eq!(
            conn.execute("system_powerdown", Value::Null).unwrap(),
            json!({})
        );
        forget(&sock);
    }

    #[test]
    fn arguments_ride_along_and_a_bare_command_sends_none() {
        let (sock, _dir) = fake_monitor(|msg| {
            // Hand the command back as its own return value, so the test
            // can read what actually went over the wire.
            vec![json!({ "return": msg.clone(), "id": msg["id"] }).to_string()]
        });
        let conn = on(&sock).unwrap();

        let sent = conn.execute(
            "human-monitor-command",
            json!({ "command-line": "info status" }),
        );
        assert_eq!(
            sent.unwrap()["arguments"],
            json!({ "command-line": "info status" })
        );

        let bare = conn.execute("query-status", Value::Null).unwrap();
        assert!(
            bare.get("arguments").is_none(),
            "a null argument sends no arguments field"
        );
        forget(&sock);
    }

    #[test]
    fn a_reply_finds_the_command_that_asked_for_it() {
        // The monitor holds the first command's reply back and answers the
        // second one first, which is the case a connection without
        // correlation gets wrong.
        let held = Mutex::new(Vec::<Value>::new());
        let (sock, _dir) = fake_monitor(move |msg| {
            if msg["execute"] == json!("slow") {
                held.lock().unwrap().push(msg["id"].clone());
                return Vec::new();
            }
            let mut out = vec![json!({ "return": { "who": "fast" }, "id": msg["id"] }).to_string()];
            for id in held.lock().unwrap().drain(..) {
                out.push(json!({ "return": { "who": "slow" }, "id": id }).to_string());
            }
            out
        });

        let conn = on(&sock).unwrap();
        let slow = {
            let conn = conn.clone();
            std::thread::spawn(move || conn.execute("slow", Value::Null))
        };
        // Give the slow command time to register before the fast one
        // unblocks it; a late fast command answers an empty queue.
        std::thread::sleep(Duration::from_millis(50));
        let fast = conn.execute("fast", Value::Null).unwrap();

        assert_eq!(
            fast["who"],
            json!("fast"),
            "the fast command got its own reply"
        );
        assert_eq!(slow.join().unwrap().unwrap()["who"], json!("slow"));
        forget(&sock);
    }

    #[test]
    fn an_error_reply_becomes_an_error_with_the_monitors_words_in_it() {
        let (sock, _dir) = fake_monitor(|msg| {
            vec![json!({
                "error": { "class": "GenericError", "desc": "Invalid parameter 'nope'" },
                "id": msg["id"],
            })
            .to_string()]
        });
        let conn = on(&sock).unwrap();
        let err = conn
            .execute("hostfwd_add", Value::Null)
            .unwrap_err()
            .to_string();
        assert!(err.contains("Invalid parameter 'nope'"), "{err}");
        assert!(
            err.contains("hostfwd_add"),
            "the error names the command: {err}"
        );
        forget(&sock);
    }

    #[test]
    fn an_event_never_answers_a_command() {
        let (sock, _dir) = fake_monitor(|msg| {
            vec![
                json!({ "event": "RESET", "data": {} }).to_string(),
                json!({ "event": "JOB_STATUS_CHANGE", "data": { "id": "s0", "status": "concluded" } })
                    .to_string(),
                json!({ "return": { "who": "the reply" }, "id": msg["id"] }).to_string(),
            ]
        });
        let conn = on(&sock).unwrap();
        assert_eq!(
            conn.execute("query-status", Value::Null).unwrap()["who"],
            json!("the reply")
        );
        forget(&sock);
    }

    #[test]
    fn a_monitor_that_hangs_up_fails_the_command_it_was_holding() {
        // A QEMU killed mid-command drops the socket without answering.
        // The waiter has to hear about it rather than sit out the timeout.
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("qmp.sock");
        let listener = UnixListener::bind(&sock).unwrap();
        std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut write = stream.try_clone().unwrap();
            let reader = BufReader::new(stream);
            writeln!(write, r#"{{"QMP":{{"version":{{}},"capabilities":[]}}}}"#).unwrap();
            for line in reader.lines() {
                let Ok(line) = line else { return };
                let msg: Value = serde_json::from_str(&line).unwrap();
                if msg["execute"] == json!("qmp_capabilities") {
                    writeln!(write, r#"{{"return":{{}},"id":0}}"#).unwrap();
                    continue;
                }
                return; // dropping both halves is the hangup
            }
        });

        let conn = on(&sock).unwrap();
        let started = std::time::Instant::now();
        let err = conn
            .execute("system_powerdown", Value::Null)
            .unwrap_err()
            .to_string();
        assert!(err.contains("closed"), "{err}");
        assert!(
            started.elapsed() < REPLY,
            "it heard the hangup instead of waiting out the reply timeout"
        );
        assert!(!conn.is_alive(), "the connection knows it is gone");
        forget(&sock);
    }

    #[test]
    fn a_greeting_that_is_not_qmp_is_refused_at_the_door() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("qmp.sock");
        let listener = UnixListener::bind(&sock).unwrap();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            writeln!(stream, "SSH-2.0-OpenSSH_9.6").unwrap();
            std::thread::sleep(Duration::from_secs(1));
        });
        let err = on(&sock).unwrap_err().to_string();
        assert!(err.contains("not with a QMP greeting"), "{err}");
    }

    #[test]
    fn nothing_is_there_to_connect_to() {
        let dir = tempfile::tempdir().unwrap();
        let err = on(&dir.path().join("absent.sock")).unwrap_err().to_string();
        assert!(err.contains("connecting to the control socket"), "{err}");
    }

    #[test]
    fn one_socket_means_one_connection() {
        let (sock, _dir) = fake_monitor(echo);
        let first = on(&sock).unwrap();
        let second = on(&sock).unwrap();
        assert!(
            Arc::ptr_eq(&first, &second),
            "the second caller reuses the live connection"
        );
        forget(&sock);
        assert!(!first.is_alive(), "forgetting it closes it");
    }

    #[test]
    fn events_decode_to_what_the_daemon_will_act_on() {
        assert_eq!(
            Event::parse("SHUTDOWN", Some(&json!({ "guest": true }))),
            Event::Shutdown { guest: true }
        );
        // QEMU has emitted SHUTDOWN without a `guest` field; the safe read
        // is that this daemon asked for it, not that the guest did.
        assert_eq!(
            Event::parse("SHUTDOWN", None),
            Event::Shutdown { guest: false }
        );
        assert_eq!(Event::parse("RESET", None), Event::Reset);
        assert_eq!(
            Event::parse(
                "JOB_STATUS_CHANGE",
                Some(&json!({ "id": "s0", "status": "concluded" }))
            ),
            Event::Job {
                id: "s0".into(),
                status: "concluded".into()
            }
        );
        assert_eq!(
            Event::parse("RTC_CHANGE", None),
            Event::Other("RTC_CHANGE".into())
        );
        assert_eq!(Event::Reset.to_string(), "the guest rebooted");
    }
}
