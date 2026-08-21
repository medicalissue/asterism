//! The helper's end of the guest agent conversation.
//!
//! One thread per session, and it is a thread for the same reason the
//! control socket and the address prober are: reads block, and blocking the
//! main thread starves the queue the VM is bound to (spike landmine 9). The
//! main thread's only involvement is the connect itself, which VZ requires
//! on that queue, and which is asynchronous anyway.
//!
//! ```text
//! main thread   connectToPort: -> a descriptor, duped
//!    |          holds VZVirtioSocketConnection, so VZ keeps the socket
//!    v
//! session thread   handshake, then status on a timer, and whatever the
//!                  run loop hands over: a sync barrier, a stop request
//! ```
//!
//! Everything the run loop needs to answer `info` with is in [`Shared`],
//! behind one mutex it holds for as long as it takes to clone a struct.

use std::io::BufReader;
use std::net::IpAddr;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::Context;

use asterism_vz::guest::{self, Key, Session};
use asterism_vz::AgentInfo;

/// How long the guest may hold back an answer while a boot is waiting on
/// it. Not a poll interval: the guest answers the moment it is reachable,
/// and this is only how long it may sit on the question before saying so.
///
/// Bounded rather than long, because a session holding an answer is a
/// session not carrying a stop.
const EAGER: Duration = Duration::from_millis(500);

/// ...and after. This is health, not discovery, and the guest has better
/// things to do than answer it.
const SETTLED: Duration = Duration::from_secs(5);

/// A read that takes longer than this is a guest that has stopped
/// answering; the session ends and the run loop opens another. Comfortably
/// longer than any answer here takes, because the cost of being wrong is
/// dropping a working channel.
const REPLY_TIMEOUT: Duration = Duration::from_secs(30);

/// What the session thread knows and the run loop reports.
#[derive(Default)]
pub struct State {
    /// The open session, if the handshake completed.
    pub info: Option<AgentInfo>,
    /// Why there is not one, when we know. Kept after the session ends: a
    /// version mismatch is the explanation for everything that follows it.
    pub error: Option<String>,
    /// The guest's address, as the guest gave it.
    pub addr: Option<IpAddr>,
    /// Seconds from the VM starting to that address being known.
    pub found_secs: Option<f64>,
    /// Is a session thread still running?
    pub live: bool,
    /// Has one ever completed a handshake?
    ///
    /// The difference between "this guest is still booting" and "this guest
    /// has an agent and something is wrong with it", which is the whole of
    /// how often it is worth asking again.
    pub ever: bool,
}

/// One thing the run loop wants done inside the guest.
enum Job {
    Sync(Sender<Result<f64, String>>),
    Stop(Sender<Result<(), String>>),
}

/// The run loop's handle on whatever session currently exists.
#[derive(Default)]
pub struct Agent {
    shared: Arc<Mutex<State>>,
    jobs: Option<Sender<Job>>,
}

impl Agent {
    /// Hand a freshly connected descriptor to a session thread.
    ///
    /// The descriptor is this process's own — [`vm::connect_to_agent`]
    /// duplicated it out of the `VZVirtioSocketConnection` — and the thread
    /// owns it from here.
    ///
    /// [`vm::connect_to_agent`]: super::vm::Machine::connect_to_agent
    pub fn attach(&mut self, fd: RawFd, key: Key, instance: String, t0: Instant) {
        let (tx, rx) = std::sync::mpsc::channel();
        self.jobs = Some(tx);
        {
            let mut state = self.lock();
            state.live = true;
            state.error = None;
        }
        let shared = self.shared.clone();
        std::thread::spawn(move || {
            // SAFETY: the descriptor was duped for this thread and nothing
            // else holds it. `UnixStream` is used as a handle for read,
            // write and SO_RCVTIMEO on a socket — every one of which is
            // address-family-agnostic — rather than as a claim that this is
            // an AF_UNIX socket. It is AF_VSOCK.
            let stream = unsafe { UnixStream::from_raw_fd(fd) };
            let outcome = session(stream, &key, &shared, &rx, t0, &instance);
            let mut state = shared.lock().unwrap_or_else(|e| e.into_inner());
            state.live = false;
            state.info = None;
            if let Err(e) = outcome {
                let said = format!("{e:#}");
                eprintln!("astd-vz: {instance}: guest agent session ended: {said}");
                state.error = Some(said);
            }
        });
    }

    /// Forget the session that has ended, so a new one can be attached.
    pub fn detach(&mut self) {
        self.jobs = None;
    }

    pub fn live(&self) -> bool {
        self.lock().live
    }

    /// Has a session ever opened on this guest?
    pub fn ever_connected(&self) -> bool {
        self.lock().ever
    }

    /// Everything `info` reports about the agent: the session, and the
    /// reason there is not one.
    pub fn reported(&self) -> (Option<AgentInfo>, Option<String>) {
        let state = self.lock();
        (state.info.clone(), state.error.clone())
    }

    /// The guest's address and how long it took, once the guest has said.
    pub fn endpoint(&self) -> Option<(IpAddr, f64)> {
        let state = self.lock();
        Some((state.addr?, state.found_secs.unwrap_or_default()))
    }

    /// Ask the guest to flush its page cache.
    ///
    /// The answer is [`Pending`] rather than a value because the caller is
    /// the run loop: it has to keep pumping the VM's queue while the guest
    /// does this, and a blocking wait here would starve the guest it is
    /// waiting on (spike landmine 9).
    pub fn request_sync(&self) -> Result<Pending<f64>, String> {
        self.ask(Job::Sync)
    }

    /// Ask the guest to power itself off. Answered when the guest has
    /// accepted the request, not when it is down — the delegate says that.
    pub fn request_stop(&self) -> Result<Pending<()>, String> {
        self.ask(Job::Stop)
    }

    /// Hand one job to the session thread.
    fn ask<T>(&self, job: impl FnOnce(Sender<Result<T, String>>) -> Job) -> Result<Pending<T>, String> {
        let jobs = self
            .jobs
            .as_ref()
            .ok_or_else(|| self.why_not().unwrap_or_else(no_agent))?;
        let (tx, rx) = std::sync::mpsc::channel();
        jobs.send(job(tx))
            .map_err(|_| "the guest agent session has ended".to_owned())?;
        Ok(Pending(rx))
    }

    fn why_not(&self) -> Option<String> {
        self.lock().error.clone()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        // A panic in here would be a panic in bookkeeping. Taking the lock
        // anyway can at worst report a stale line; refusing it would take
        // the guest's control channel out over an accounting mistake.
        self.shared.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// An answer the guest has not given yet.
///
/// Deliberately not a blocking handle: everything that asks for one is on
/// the thread the guest itself runs on.
pub struct Pending<T>(Receiver<Result<T, String>>);

impl<T> Pending<T> {
    /// The answer, if it has arrived. `None` means keep pumping.
    pub fn taken(&self) -> Option<Result<T, String>> {
        match self.0.try_recv() {
            Ok(answer) => Some(answer),
            Err(std::sync::mpsc::TryRecvError::Empty) => None,
            Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                Some(Err("the guest agent session ended before it answered".to_owned()))
            }
        }
    }
}

/// What a caller is told when there is no session and no reason recorded.
fn no_agent() -> String {
    format!(
        "this guest has no agent answering on vsock port {} — it was booted from a \
         seed that does not carry one, or it has not come up yet",
        guest::PORT
    )
}

/// One session, from the handshake to whatever ends it.
fn session(
    stream: UnixStream,
    key: &Key,
    shared: &Arc<Mutex<State>>,
    jobs: &Receiver<Job>,
    t0: Instant,
    instance: &str,
) -> anyhow::Result<()> {
    // The descriptor is named in these because they are the two places a
    // session can fail before it has said anything at all — which is what a
    // connection VZ handed over and the guest had already closed under it
    // looks like from here.
    let fd = stream.as_raw_fd();
    stream
        .set_read_timeout(Some(REPLY_TIMEOUT))
        .with_context(|| format!("setting a read timeout on the guest's socket (fd {fd})"))?;
    stream
        .set_write_timeout(Some(REPLY_TIMEOUT))
        .with_context(|| format!("setting a write timeout on the guest's socket (fd {fd})"))?;
    let writer = stream
        .try_clone()
        .context("duplicating the guest's socket to write on")?;
    let mut session = Session::open(BufReader::new(stream), writer, key)?;

    let facts = session.facts().clone();
    let info = AgentInfo {
        version: session.version(),
        agent: facts.agent.clone(),
        hostname: facts.hostname.clone(),
        boot_id: facts.boot_id.clone(),
        kernel: facts.kernel.clone(),
        since: now_unix(),
        status: None,
    };
    let reconnect = {
        let mut state = shared.lock().unwrap_or_else(|e| e.into_inner());
        state.info = Some(info);
        state.error = None;
        let reconnect = state.ever;
        state.ever = true;
        reconnect
    };
    // Every session, not only the first: the ones after it are a guest that
    // rebooted or an agent that was restarted, and both are things whoever
    // reads this log is trying to find out.
    eprintln!(
        "astd-vz: {instance}: guest agent {}answered on vsock port {} after {:.1}s \
         — {} over protocol v{}",
        match reconnect {
            true => "re",
            false => "",
        },
        guest::PORT,
        t0.elapsed().as_secs_f64(),
        match facts.agent.is_empty() {
            true => "an agent that did not name itself",
            false => facts.agent.as_str(),
        },
        session.version(),
    );

    let mut next_status = Instant::now();
    loop {
        // Whatever the run loop wants comes first: a stop is a person
        // waiting, and a barrier is something about to happen to a disk.
        match jobs.recv_timeout(next_status.saturating_duration_since(Instant::now())) {
            Ok(Job::Sync(reply)) => {
                let _ = reply.send(session.sync().map_err(|e| format!("{e:#}")));
            }
            Ok(Job::Stop(reply)) => {
                let asked = session.stop().map_err(|e| format!("{e:#}"));
                let _ = reply.send(asked);
                // The guest is on its way down and will take this socket
                // with it. Anything read after this is the connection
                // closing, which is not a failure worth reporting.
                return Ok(());
            }
            // The helper is going away.
            Err(RecvTimeoutError::Disconnected) => return Ok(()),
            Err(RecvTimeoutError::Timeout) => {}
        }
        if Instant::now() < next_status {
            continue;
        }

        // Before the guest is reachable this blocks *in the guest*, and
        // comes back the moment it is; after that it is a health check on a
        // timer and asks for nothing.
        let status = match shared.lock().unwrap_or_else(|e| e.into_inner()).addr {
            None => session.ready_within(EAGER)?,
            Some(_) => session.status()?,
        };
        let addr = status.endpoint();
        let mut state = shared.lock().unwrap_or_else(|e| e.into_inner());
        if let (Some(addr), None) = (addr, state.addr) {
            let secs = t0.elapsed().as_secs_f64();
            state.found_secs = Some(secs);
            eprintln!("astd-vz: {instance} is at {addr} after {secs:.1}s — the guest said so");
        }
        state.addr = addr;
        if let Some(info) = state.info.as_mut() {
            info.status = Some(status);
        }
        drop(state);
        // Once the guest is reachable there is nothing to wait for, and
        // asking again is health rather than discovery.
        next_status = Instant::now() + if addr.is_some() { SETTLED } else { Duration::ZERO };
    }
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
