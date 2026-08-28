//! `ast`, inside the box.
//!
//! An agent running unattended on somebody's machine has tools for the work
//! and nothing at all for the machine: it cannot snapshot before it does
//! something risky, cannot see what it is spending, cannot tell the person
//! who owns it that a pull request is ready, and cannot ask them a question
//! and wait for the answer. It has a terminal and no channel.
//!
//! This is the channel. Not an approval gate — nothing here can refuse work
//! the agent was going to do anyway, and there is no path by which the human
//! blocks it. The agent gets tools; the human gets a way to be reached.
//!
//! ## Which way the wire points
//!
//! The guest never dials the host. Guest control is host-initiated and stays
//! that way, so the daemon parks one session on a long poll (`agent_next`)
//! and this module hands it whatever the agent has typed since the last one.
//! The answer comes back on the same session (`agent_reply`) and is written
//! to the socket the waiting `ast` is still holding.
//!
//! ```text
//!   agent                 this module              astd (on the host)
//!   ast ask "…"  ---->  queue, block
//!                       <-------------------  agent_next (long poll)
//!                       -------------------->  {id, token, argv}
//!                       <-------------------  agent_reply {id, status: null}
//!   "waiting…"   <----  interim
//!                            … minutes …
//!                       <-------------------  agent_reply {id, status: 0}
//!   "A"          <----  final, socket closes
//! ```
//!
//! ## The token
//!
//! The host arms this agent with a per-instance token over the already
//! authenticated control channel, and it is stamped on every call forwarded
//! from here. **The agent in the box never sees it.** It is not written to
//! any file, so it is in no disk image, no snapshot and no bug report; it
//! lives in this process's memory and in the daemon's, and a reboot, a rewind
//! or a fork mints a new one. What it buys is that the daemon decides which
//! instance a call is about from the token it minted, and never from anything
//! the instance said — which is why `ast snapshot other-bot` inside the box
//! is refused rather than obeyed.
//!
//! The socket itself is deliberately reachable by anything in the guest.
//! Everything in the box *is* the agent, and a call through it can do nothing
//! the instance could not already do to itself.

use std::collections::VecDeque;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::mpsc::{channel, Receiver, RecvTimeoutError, Sender};

use std::sync::{Condvar, Mutex, OnceLock};
use std::time::Duration;

use anyhow::{Context, Result};
use asterism_core::guest::{AgentCall, AgentReply, AGENT_CLI_SOCKET, MAX_FRAME_BYTES};
use data_encoding::BASE64;
use serde::{Deserialize, Serialize};

/// How long a call may sit here with nobody on the host asking for it before
/// the `ast` that made it gives up.
///
/// This is the *delivery* deadline, not the answering one: `ast ask` waits as
/// long as the daemon tells it to, and the daemon owns that clock. This one
/// only catches the case where nothing is polling at all — a daemon that
/// stopped, a session that dropped — and it is short because "nobody is
/// listening" is a thing to be told about quickly.
const DELIVERY_TIMEOUT: Duration = Duration::from_secs(20);

/// A ceiling on a call that was delivered and never answered. Nothing should
/// reach it — the daemon times `ast ask` out itself — but a thread that can
/// wait forever is a thread that eventually does.
const ANSWER_CEILING: Duration = Duration::from_secs(26 * 3600);

/// What `ast` inside the box writes to the socket.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Call {
    argv: Vec<String>,
}

/// What comes back, one line at a time.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Wrote {
    #[serde(default)]
    status: Option<i32>,
    #[serde(default)]
    stdout_b64: String,
    #[serde(default)]
    stderr_b64: String,
}

struct Waiting {
    call: AgentCall,
    answers: Sender<AgentReply>,
}

#[derive(Default)]
struct Channel {
    token: Mutex<Option<String>>,
    queue: Mutex<VecDeque<Waiting>>,
    /// Handed out to the host and not yet answered.
    flight: Mutex<Vec<(u64, Sender<AgentReply>)>>,
    arrived: Condvar,
    next_id: Mutex<u64>,
}

fn channel_state() -> &'static Channel {
    static CHANNEL: OnceLock<Channel> = OnceLock::new();
    CHANNEL.get_or_init(Channel::default)
}

// ---- the host's side --------------------------------------------------------

/// Take the token the host minted for this instance, and start honouring it.
///
/// Re-arming ends every call that was already handed to the host: the only
/// way a second arm happens is that the session carrying those calls went
/// away, and an `ast` that waits forever on an answer that can no longer
/// arrive is worse than one that is told to run the command again.
pub fn arm(token: String) {
    arm_in(channel_state(), token)
}

fn arm_in(state: &Channel, token: String) {
    let stale: Vec<_> = std::mem::take(&mut *state.flight.lock().unwrap());
    *state.token.lock().unwrap() = Some(token);
    for (id, answers) in stale {
        let _ = answers.send(AgentReply::done(
            id,
            1,
            "",
            "error: the channel to the host dropped — run the command again\n",
        ));
    }
}

/// One call the agent made, or nothing if it made none before `wait` ran out.
pub fn next(wait: Duration) -> Option<AgentCall> {
    next_in(channel_state(), wait)
}

fn next_in(state: &Channel, wait: Duration) -> Option<AgentCall> {
    let mut queue = state.queue.lock().unwrap();
    if queue.is_empty() {
        let (guard, _) = state.arrived.wait_timeout(queue, wait).unwrap();
        queue = guard;
    }
    let waiting = queue.pop_front()?;
    drop(queue);
    state
        .flight
        .lock()
        .unwrap()
        .push((waiting.call.id, waiting.answers));
    Some(waiting.call)
}

/// Hand one answer — interim or final — to the `ast` still holding the socket.
pub fn reply(reply: AgentReply) {
    reply_in(channel_state(), reply)
}

fn reply_in(state: &Channel, reply: AgentReply) {
    let mut flight = state.flight.lock().unwrap();
    let Some(index) = flight.iter().position(|(id, _)| *id == reply.id) else {
        // An answer to a call whose caller has gone. Dropping it is right:
        // the work the daemon did is already done, and there is nobody to
        // print it to.
        return;
    };
    let done = reply.status.is_some();
    let sent = flight[index].1.send(reply).is_ok();
    if done || !sent {
        flight.remove(index);
    }
}

// ---- the guest's side -------------------------------------------------------

/// Bind the guest-local socket and answer it forever.
///
/// Non-fatal on purpose, exactly like the egress door: a guest that cannot
/// bind this says so once and goes on serving everything else. `ast` inside
/// the box is a tool the agent gains, and losing it must not cost the
/// instance its control plane.
pub fn start() {
    std::thread::spawn(|| {
        if let Err(error) = serve() {
            eprintln!("asterism-guest: the agent's own channel is not available: {error:#}");
        }
    });
}

fn serve() -> Result<()> {
    if let Some(parent) = std::path::Path::new(AGENT_CLI_SOCKET).parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    // A socket left by the previous boot is a file, not a listener; anything
    // that connects to it gets ECONNREFUSED forever.
    let _ = std::fs::remove_file(AGENT_CLI_SOCKET);
    let listener = UnixListener::bind(AGENT_CLI_SOCKET)
        .with_context(|| format!("binding {AGENT_CLI_SOCKET}"))?;
    std::fs::set_permissions(AGENT_CLI_SOCKET, std::fs::Permissions::from_mode(0o666))
        .with_context(|| format!("opening {AGENT_CLI_SOCKET} to the agent"))?;
    for incoming in listener.incoming() {
        match incoming {
            Ok(stream) => {
                std::thread::spawn(move || {
                    if let Err(error) = carry(stream) {
                        eprintln!("asterism-guest: an `ast` call ended: {error:#}");
                    }
                });
            }
            Err(error) => eprintln!("asterism-guest: agent channel accept failed: {error}"),
        }
    }
    Ok(())
}

fn carry(stream: UnixStream) -> Result<()> {
    let mut writer = stream.try_clone().context("cloning the agent socket")?;
    // One line, and bounded before it is parsed. The caller stays connected
    // waiting for the answer, so reading to end-of-file would be reading
    // until it gave up — which for `ast ask` is hours.
    let mut reader = BufReader::new(stream.take(MAX_FRAME_BYTES as u64 + 1));
    let mut line = String::new();
    reader.read_line(&mut line).context("reading an ast call")?;
    let call: Call = serde_json::from_str(line.trim()).context("that is not an ast call")?;

    let Some(token) = channel_state().token.lock().unwrap().clone() else {
        return say(
            &mut writer,
            AgentReply::done(
                0,
                1,
                "",
                "error: this box's channel to its owner is not open yet — try again in a moment\n",
            ),
        );
    };

    let (answers, from_host) = channel();
    let id = {
        let state = channel_state();
        let mut next = state.next_id.lock().unwrap();
        *next += 1;
        *next
    };
    let state = channel_state();
    state.queue.lock().unwrap().push_back(Waiting {
        call: AgentCall {
            id,
            token,
            argv: call.argv,
        },
        answers,
    });
    state.arrived.notify_one();

    pump(&mut writer, &from_host, id)
}

fn pump(writer: &mut UnixStream, from_host: &Receiver<AgentReply>, id: u64) -> Result<()> {
    let mut deadline = DELIVERY_TIMEOUT;
    loop {
        match from_host.recv_timeout(deadline) {
            Ok(reply) => {
                let done = reply.status.is_some();
                say(writer, reply)?;
                if done {
                    return Ok(());
                }
                // Delivered and being worked on. From here the daemon owns
                // the clock, and this one only exists so a thread cannot live
                // longer than the machine it is on.
                deadline = ANSWER_CEILING;
            }
            Err(RecvTimeoutError::Timeout) => {
                let why = if deadline == DELIVERY_TIMEOUT {
                    "error: nothing on the host is listening to this box — is astd running?\n"
                } else {
                    "error: the host never answered\n"
                };
                return say(writer, AgentReply::done(id, 1, "", why));
            }
            Err(RecvTimeoutError::Disconnected) => {
                return say(
                    writer,
                    AgentReply::done(id, 1, "", "error: the channel to the host closed\n"),
                )
            }
        }
    }
}

fn say(writer: &mut UnixStream, reply: AgentReply) -> Result<()> {
    let wrote = Wrote {
        status: reply.status,
        stdout_b64: reply.stdout_b64,
        stderr_b64: reply.stderr_b64,
    };
    let mut line = serde_json::to_string(&wrote).context("encoding an answer")?;
    line.push('\n');
    writer
        .write_all(line.as_bytes())
        .context("writing an answer")?;
    writer.flush().context("flushing an answer")
}

// ---- `ast`, as the agent runs it -------------------------------------------

/// The whole of `ast` inside the box: hand the words to the socket, print
/// what comes back, exit with what it says.
///
/// It knows nothing about any command. Every sentence the agent reads —
/// including the refusals — is written by the daemon on the host, so there is
/// one place where `ast snapshot` means what it means and no second spelling
/// of it to drift.
pub fn client() -> Result<()> {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let stream = match UnixStream::connect(AGENT_CLI_SOCKET) {
        Ok(stream) => stream,
        Err(_) => {
            eprintln!(
                "error: `ast` here talks to the machine this box is running on, and that channel is not open"
            );
            eprintln!("  fix: ast logs <this instance> --console");
            std::process::exit(1);
        }
    };
    let mut writer = stream.try_clone().context("cloning the agent socket")?;
    let mut reader = BufReader::new(stream);
    let mut line = serde_json::to_string(&Call { argv }).context("encoding the call")?;
    line.push('\n');
    writer.write_all(line.as_bytes()).context("sending it")?;
    writer.flush().context("sending it")?;

    let mut out = String::new();
    loop {
        out.clear();
        let read = reader.read_line(&mut out).context("reading the answer")?;
        if read == 0 {
            eprintln!("error: the host closed the channel without answering");
            std::process::exit(1);
        }
        let wrote: Wrote = serde_json::from_str(out.trim()).context("reading the answer")?;
        print(&wrote.stdout_b64, &mut std::io::stdout())?;
        print(&wrote.stderr_b64, &mut std::io::stderr())?;
        if let Some(status) = wrote.status {
            std::process::exit(status.clamp(0, 255));
        }
    }
}

fn print(b64: &str, sink: &mut impl Write) -> Result<()> {
    if b64.is_empty() {
        return Ok(());
    }
    let bytes = BASE64
        .decode(b64.as_bytes())
        .context("decoding an answer")?;
    sink.write_all(&bytes).context("printing an answer")?;
    sink.flush().context("printing an answer")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_call_reaches_the_host_and_its_answer_reaches_the_caller() {
        let state = Channel::default();
        arm_in(&state, "token-for-this-instance".into());
        let (answers, from_host) = channel();
        state.queue.lock().unwrap().push_back(Waiting {
            call: AgentCall {
                id: 41,
                token: "token-for-this-instance".into(),
                argv: vec!["cost".into()],
            },
            answers,
        });

        let call = next_in(&state, Duration::from_millis(50)).expect("the host sees the call");
        assert_eq!(call.argv, vec!["cost".to_owned()]);
        assert_eq!(
            call.token, "token-for-this-instance",
            "the daemon decides which instance this is from the token it minted"
        );

        reply_in(&state, AgentReply::interim(41, "waiting…\n"));
        let first = from_host.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(first.status.is_none(), "an interim write is not the end");

        reply_in(&state, AgentReply::done(41, 0, "today   $0.06\n", ""));
        let last = from_host.recv_timeout(Duration::from_secs(2)).unwrap();
        assert_eq!(last.status, Some(0));
        assert_eq!(
            String::from_utf8(BASE64.decode(last.stdout_b64.as_bytes()).unwrap()).unwrap(),
            "today   $0.06\n"
        );
        assert!(
            state.flight.lock().unwrap().is_empty(),
            "a finished call is not still in flight"
        );
    }

    #[test]
    fn an_empty_poll_is_the_ordinary_answer() {
        let state = Channel::default();
        assert!(next_in(&state, Duration::from_millis(5)).is_none());
    }

    #[test]
    fn re_arming_ends_calls_whose_session_went_away() {
        let state = Channel::default();
        arm_in(&state, "first".into());
        let (answers, from_host) = channel();
        state.flight.lock().unwrap().push((77, answers.clone()));
        drop(answers);
        arm_in(&state, "second".into());
        let ended = from_host.recv_timeout(Duration::from_secs(2)).unwrap();
        assert_eq!(ended.status, Some(1));
        let text = String::from_utf8(BASE64.decode(ended.stderr_b64.as_bytes()).unwrap()).unwrap();
        assert!(text.contains("run the command again"), "{text}");
        assert_eq!(
            state.token.lock().unwrap().as_deref(),
            Some("second"),
            "a fresh token replaces the one before it, which is how a rewind revokes"
        );
    }
}
