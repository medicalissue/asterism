//! `ast` inside the box, from the host's side — and `ast tell` from the
//! outside.
//!
//! An agent that runs unattended for a week is not short of a shell. It is
//! short of everything *about* the machine: it cannot take a snapshot before
//! it migrates a schema, cannot see what it has spent, cannot say "the PR is
//! open", and cannot ask a question and wait. This module gives it those four
//! verbs and gives the person who owns it a way to answer.
//!
//! # Leverage, not restriction
//!
//! Nothing here can refuse work the agent was going to do anyway. There is no
//! approval gate, no allowlist of tasks, no path by which a human blocks an
//! agent. `ast ask` blocks because the *agent chose to ask*, and it times out
//! on its own. That is the whole shape of the feature and it is deliberate:
//! the moment a daemon can hold an agent's work pending a person, the product
//! is a slower human rather than a faster agent.
//!
//! # How a call gets here
//!
//! Guest control is host-initiated and stays that way — the guest never dials
//! the host. So one blocking task per running instance holds an authenticated
//! guest-control session and long-polls it:
//!
//! ```text
//!   agent in the box        the guest agent            this module
//!   ast cost         --->  queued
//!                          <---------------------  agent_next (400 ms poll)
//!                          ---------------------->  {id, token, ["cost"]}
//!                                                   run it, against the
//!                                                   instance the *token*
//!                                                   names
//!                          <---------------------  agent_reply {id, 0, "…"}
//!   "today   $0.06"  <---  printed
//! ```
//!
//! # The token, and what it is for
//!
//! Every pump mints 32 bytes of fresh randomness at the moment it arms a
//! guest, and hands it over the channel that has already proved the instance
//! key. The guest agent keeps it in memory and stamps it on every call; the
//! agent in the box never sees it and no file in the guest ever holds it, so
//! it is absent from the disk image, from every snapshot, and from a bug
//! report. A reboot, a rewind and a fork each end a pump and start another,
//! which mints a new one and makes the old one meaningless.
//!
//! What it buys is **scope**. The daemon looks up which instance a call is
//! about from the token *it* minted, never from anything the call said. So
//! `ast snapshot other-bot x` inside the box does not become a snapshot of
//! `other-bot`: it becomes a sentence saying that is not this instance. The
//! agent is root in its own machine and this does not pretend otherwise — it
//! says that being root in one machine is not authority over a second one.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use anyhow::{Context, Result};
use asterism_core::guest::{AgentCall, AgentReply};
use asterism_core::inbox::Kind;
use asterism_core::instance::Instance;
use asterism_core::paths;
use asterism_core::protocol::{Request, Response};

use crate::inbox;
use crate::Node;

/// How long one poll of a guest waits before coming back empty.
///
/// Short enough that an answer to `ast ask` reaches the agent promptly, long
/// enough that an idle instance is not a busy loop. Nothing is billed for a
/// poll and nothing in the guest wakes for one.
const POLL: Duration = Duration::from_millis(400);

/// How long an unanswered `ast ask` waits before the agent gets on with it.
///
/// Four hours because the case this exists for is an agent that hits a
/// decision at two in the morning and a person who reads it at breakfast.
/// `--timeout` overrides it per question, and the question stays in the inbox
/// either way: a timeout is the agent carrying on, not the question being
/// thrown away.
const DEFAULT_ASK_TIMEOUT: Duration = Duration::from_secs(4 * 3600);

/// The longest an agent may park on one question.
const MAX_ASK_TIMEOUT: Duration = Duration::from_secs(24 * 3600);

/// The sentence an agent gets when it names a machine that is not its own.
fn not_this_instance(named: &str, instance: &str) -> String {
    format!("error: {named:?} is not this instance — inside the box, ast acts on {instance} only\n")
}

// ---- the pumps -------------------------------------------------------------

fn running() -> &'static Mutex<HashMap<String, Arc<Pump>>> {
    static PUMPS: OnceLock<Mutex<HashMap<String, Arc<Pump>>>> = OnceLock::new();
    PUMPS.get_or_init(Default::default)
}

struct Pump {
    /// The randomness this pump armed its guest with, kept so a call can be
    /// checked against the instance it was minted for.
    token: String,
    alive: Mutex<bool>,
}

/// Watch this device's shard and keep one pump on every instance that can
/// carry one.
///
/// A supervisor rather than a hook on boot, for two reasons: a daemon that
/// restarts finds its guests already up and has to adopt them, and a pump
/// whose session drops for any reason must come back without anybody typing
/// anything. Both are the same loop.
pub(crate) fn supervise(node: Node) {
    tokio::spawn(async move {
        loop {
            reconcile(&node).await;
            tokio::time::sleep(Duration::from_secs(3)).await;
        }
    });
}

async fn reconcile(node: &Node) {
    let candidates: Vec<Instance> = {
        let reg = node.shard.lock().await;
        reg.list().into_iter().filter(carries_a_channel).collect()
    };
    let mut pumps = running().lock().unwrap();
    pumps.retain(|_, pump| *pump.alive.lock().unwrap());
    for inst in candidates {
        if pumps.contains_key(&inst.name) {
            continue;
        }
        let Ok(token) = asterism_core::guest::nonce() else {
            continue;
        };
        let pump = Arc::new(Pump {
            token,
            alive: Mutex::new(true),
        });
        pumps.insert(inst.name.clone(), pump.clone());
        start(node.clone(), inst, pump);
    }
}

/// An OCI-rootfs VM that is up and has a guest-control endpoint. Cloud-image
/// guests run the older Python agent, which does not speak the frames this
/// needs — negotiation refuses it cleanly and no pump is started.
fn carries_a_channel(inst: &Instance) -> bool {
    inst.runtime == asterism_core::instance::RuntimeKind::Vm
        && inst.image_kind == asterism_core::hv::ImageKind::OciRootfs
        && inst
            .handle
            .as_ref()
            .and_then(|handle| handle.endpoint.as_ref())
            .and_then(|endpoint| endpoint.control_target())
            .is_some()
}

fn start(node: Node, inst: Instance, pump: Arc<Pump>) {
    let name = inst.name.clone();
    let Some(target) = inst
        .handle
        .as_ref()
        .and_then(|handle| handle.endpoint.as_ref())
        .and_then(|endpoint| endpoint.control_target())
    else {
        *pump.alive.lock().unwrap() = false;
        return;
    };
    let handle = tokio::runtime::Handle::current();
    tokio::task::spawn_blocking(move || {
        let result = carry(&handle, &node, &name, target, &pump);
        *pump.alive.lock().unwrap() = false;
        if let Err(error) = result {
            // Once, quietly. A guest that went away mid-poll is the ordinary
            // end of a pump, and the supervisor will make another when it
            // comes back.
            eprintln!("astd: {name}'s agent channel ended: {error:#}");
        }
    });
}

fn carry(
    handle: &tokio::runtime::Handle,
    node: &Node,
    name: &str,
    target: (String, u16),
    pump: &Arc<Pump>,
) -> Result<()> {
    use std::io::BufReader;
    use std::net::{TcpStream, ToSocketAddrs};

    let key = asterism_core::guest::Key::read(&paths::guest_agent_key_path(name))
        .with_context(|| format!("reading {name:?}'s guest-control key"))?
        .with_context(|| format!("instance {name:?} has no guest-control key"))?;
    let (host, port) = target;
    let address = (host.as_str(), port)
        .to_socket_addrs()
        .context("resolving the guest-control endpoint")?
        .next()
        .context("the guest-control endpoint has no address")?;
    let stream = TcpStream::connect_timeout(&address, Duration::from_secs(5))
        .with_context(|| format!("connecting to guest control at {host}:{port}"))?;
    // Longer than the poll, and not much: this session's whole job is to sit
    // on a long poll, but a guest that vanished mid-poll must not leave a
    // thread parked on a socket that will never speak again.
    stream.set_read_timeout(Some(POLL + Duration::from_secs(30)))?;
    stream.set_write_timeout(Some(Duration::from_secs(30)))?;
    let reader = BufReader::new(stream.try_clone()?);
    let mut session = asterism_core::guest::Session::open(reader, stream, &key)?;
    if session.version() < 3 {
        // A guest from before this feature. Nothing is wrong and nothing is
        // said: `ast` simply is not in that box.
        return Ok(());
    }
    session.agent_arm(&pump.token)?;

    let (answers, from_workers) = std::sync::mpsc::channel::<AgentReply>();
    loop {
        while let Ok(reply) = from_workers.try_recv() {
            session.agent_reply(reply)?;
        }
        let Some(call) = session.agent_next(POLL)? else {
            continue;
        };
        if call.token != pump.token {
            session.agent_reply(AgentReply::done(
                call.id,
                1,
                "",
                "error: this box was armed by a different daemon — its channel has been replaced\n",
            ))?;
            continue;
        }
        let node = node.clone();
        let name = name.to_owned();
        let answers = answers.clone();
        handle.spawn(async move {
            run(&node, &name, call, answers).await;
        });
    }
}

async fn run(
    node: &Node,
    instance: &str,
    call: AgentCall,
    answers: std::sync::mpsc::Sender<AgentReply>,
) {
    let id = call.id;
    let say = |reply: AgentReply| {
        let _ = answers.send(reply);
    };
    match plan(instance, &call.argv) {
        Err(refusal) => say(AgentReply::done(id, 1, "", &refusal)),
        Ok(Plan::Print(text)) => say(AgentReply::done(id, 0, &text, "")),
        Ok(Plan::Ask { text, timeout }) => {
            let entry = match inbox::say(instance, Kind::Ask, &text) {
                Ok(entry) => entry,
                Err(error) => {
                    return say(AgentReply::done(
                        id,
                        1,
                        "",
                        &format!("error: could not reach your owner: {error:#}\n"),
                    ))
                }
            };
            let waiting = inbox::wait_for(entry.seq);
            say(AgentReply::interim(
                id,
                "waiting for a reply… (your owner has been notified)\n",
            ));
            match tokio::time::timeout(timeout, waiting).await {
                Ok(Ok(answer)) => say(AgentReply::done(id, 0, &format!("{answer}\n"), "")),
                _ => {
                    inbox::give_up(entry.seq);
                    say(AgentReply::done(
                        id,
                        1,
                        "",
                        &format!(
                            "error: nobody answered within {} — carry on without one; the question is still in their inbox\n",
                            asterism_core::rewind::human_duration(timeout.as_secs())
                        ),
                    ))
                }
            }
        }
        Ok(Plan::Notify(text)) => match inbox::say(instance, Kind::Notify, &text) {
            Ok(_) => say(AgentReply::done(id, 0, "", "")),
            Err(error) => say(AgentReply::done(
                id,
                1,
                "",
                &format!("error: could not reach your owner: {error:#}\n"),
            )),
        },
        Ok(Plan::Snapshot(tag)) => match snapshot(node, instance, &tag).await {
            Ok(line) => say(AgentReply::done(id, 0, &line, "")),
            Err(error) => say(AgentReply::done(id, 1, "", &format!("error: {error:#}\n"))),
        },
        Ok(Plan::Frame(request)) => {
            // The same sentence `ast rewind` prints on the outside. What a
            // rewind does *not* touch is the surprising half, and it is the
            // half that keeps `claude --resume` working across one.
            let note = match &request {
                Request::Rewind {
                    include_memory: false,
                    ..
                } => "memory and cache volumes are not rolled back — add --include-memory to roll memory back too\n",
                _ => "",
            };
            // Boxed because `handle` is what got us here: an `ast` in the box
            // is an ordinary frame taking an unusual door in, and the compiler
            // is right that the cycle needs a heap allocation to have a size.
            let response = Box::pin(crate::handle(request, node)).await;
            match render(&response) {
                Ok(text) => say(AgentReply::done(id, 0, &format!("{text}{note}"), "")),
                Err(message) => say(AgentReply::done(id, 1, "", &format!("error: {message}\n"))),
            }
        }
    }
}

// ---- what one `ast …` inside the box means ---------------------------------

/// What the daemon is going to do about one call.
#[derive(Debug)]
enum Plan {
    /// Text the agent asked for and this module already has.
    Print(String),
    Notify(String),
    Ask {
        text: String,
        timeout: Duration,
    },
    Snapshot(String),
    /// An ordinary frame, run against this device exactly as if it had come
    /// off the unix socket — which is why `ast cost` in the box and
    /// `ast cost <name>` outside it can never print different numbers.
    Frame(Request),
}

/// Turn the words after `ast` into a plan, or into the sentence that refuses
/// them.
///
/// `instance` comes from the token the daemon minted, so every name check in
/// here is a comparison against a fact the box did not get a vote on.
fn plan(instance: &str, argv: &[String]) -> Result<Plan, String> {
    let (verb, rest) = match argv.split_first() {
        Some((verb, rest)) => (verb.as_str(), rest),
        None => return Ok(Plan::Print(help(instance))),
    };
    // A name where a name may go. `ast snapshot bot before-x` and
    // `ast snapshot before-x` are the same command from in here, and anything
    // else that looks like a name is the refusal this whole feature turns on.
    let strip_self = |rest: &[String]| -> Vec<String> {
        match rest.split_first() {
            Some((first, tail)) if first == instance => tail.to_vec(),
            _ => rest.to_vec(),
        }
    };
    let is_a_name = |word: &str| !word.starts_with('-');

    match verb {
        "help" | "--help" | "-h" => Ok(Plan::Print(help(instance))),
        "snapshot" => {
            let rest = strip_self(rest);
            // Two words left means the first was a machine's name and it was
            // not this one — the only reading under which `ast snapshot
            // other-bot x` makes sense is the one that must not happen.
            if rest.len() > 1 {
                return Err(not_this_instance(&rest[0], instance));
            }
            let tag = match rest.first() {
                Some(tag) => tag.clone(),
                None => asterism_core::snapshot::timestamped_tag(),
            };
            asterism_core::snapshot::validate_tag(&tag).map_err(|e| format!("error: {e}\n"))?;
            Ok(Plan::Snapshot(tag))
        }
        "rewind" => {
            let rest = strip_self(rest);
            // The same flag `ast rewind` has on the outside, spelled the same
            // way and meaning the same thing: an agent's memory volume is not
            // rolled back unless somebody asks, so that `claude --resume` on
            // the other side of a rewind is still the same conversation.
            let include_memory = rest.iter().any(|word| word == "--include-memory");
            let rest: Vec<String> = rest
                .into_iter()
                .filter(|word| word != "--include-memory")
                .collect();
            let rewind = |to| {
                Ok(Plan::Frame(Request::Rewind {
                    name: instance.to_owned(),
                    to,
                    include_memory,
                }))
            };
            match rest.split_first() {
                None if include_memory => {
                    Err("error: --include-memory says how to rewind, not whether to; give a duration or --to <name>\n".into())
                }
                None => Ok(Plan::Frame(Request::RewindTimeline {
                    name: instance.to_owned(),
                })),
                Some((flag, tail)) if flag == "--to" => {
                    let tag = tail
                        .first()
                        .ok_or_else(|| "error: --to needs a snapshot name\n".to_owned())?;
                    rewind(asterism_core::rewind::Target::Tag { tag: tag.clone() })
                }
                // A lone word is either how far back to go, or somebody
                // else's machine. `30m` is the first; `other-bot` is the
                // second, and gets the sentence rather than a parse error.
                Some((back, [])) => match asterism_core::rewind::parse_duration(back) {
                    Ok(seconds) => rewind(asterism_core::rewind::Target::Back { seconds }),
                    Err(_) if is_a_name(back) => Err(not_this_instance(back, instance)),
                    Err(error) => Err(format!("error: {error}\n")),
                },
                Some((first, _)) if is_a_name(first) => Err(not_this_instance(first, instance)),
                _ => Err(
                    "error: usage: ast rewind [<duration>|--to <name>] [--include-memory]\n".into(),
                ),
            }
        }
        "cost" => {
            let rest = strip_self(rest);
            match rest.first() {
                Some(first) if is_a_name(first) => return Err(not_this_instance(first, instance)),
                Some(_) => return Err("error: usage: ast cost\n".into()),
                None => {}
            }
            let now = asterism_core::instance::now_unix();
            Ok(Plan::Frame(Request::Cost {
                name: Some(instance.to_owned()),
                since: asterism_core::ledger::local_midnight(now),
                window: "today".into(),
            }))
        }
        "notify" => {
            let text = one_line("ast notify", rest)?;
            Ok(Plan::Notify(text))
        }
        "ask" => {
            let (timeout, rest) = ask_timeout(rest)?;
            let text = one_line("ast ask", &rest)?;
            Ok(Plan::Ask { text, timeout })
        }
        // Try N of something at once, and read the answers. An agent that can
        // fork itself is the reason `ast fork` exists at all: the thing that
        // wants three attempts at a refactor is the thing doing the refactor,
        // and until now it had to ask a person to press the button.
        //
        // Scoped exactly like the rest: an agent forks *itself*. The children
        // inherit nothing of this channel — each gets its own pump and its own
        // freshly minted token when it boots, so a fork is not a way to make a
        // copy of somebody's authority.
        "fork" => {
            let rest = strip_self(rest);
            let mut count = 2usize;
            let mut each: Vec<String> = Vec::new();
            let mut stopped = false;
            let mut words = rest.iter();
            while let Some(word) = words.next() {
                match word.as_str() {
                    "--n" | "-n" => {
                        let spec = words
                            .next()
                            .ok_or_else(|| "error: --n needs a number\n".to_owned())?;
                        count = spec
                            .parse()
                            .map_err(|_| format!("error: {spec:?} is not a number of forks\n"))?;
                    }
                    "--each" => {
                        let message = words
                            .next()
                            .ok_or_else(|| "error: --each needs a line\n".to_owned())?;
                        each.push(
                            asterism_core::inbox::check_text("--each", message)
                                .map_err(|message| format!("error: {message}\n"))?,
                        );
                    }
                    "--stopped" => stopped = true,
                    other if is_a_name(other) => return Err(not_this_instance(other, instance)),
                    other => return Err(format!("error: ast fork has no {other:?}\n")),
                }
            }
            if !each.is_empty() && each.len() != count {
                return Err(format!(
                    "error: {count} forks and {} --each lines — give one line per fork, or none\n",
                    each.len()
                ));
            }
            Ok(Plan::Frame(Request::Fork {
                name: instance.to_owned(),
                count,
                each,
                stopped,
                // An agent asking for more than the soft limit has already
                // decided; there is nobody at a terminal to confirm it to, and
                // refusing would be the approval gate this feature does not
                // have. `ast fork` still refuses when the disk cannot take it.
                yes: true,
            }))
        }
        // Said by name rather than swept into "no such command", because an
        // agent that reaches for this is asking a reasonable question and
        // deserves the reason rather than a shrug.
        "secret" | "secrets" | "credential" | "credentials" => Err(format!(
            "error: the values behind this box's credentials are not in it, and `ast` here cannot \
             read them — that is the feature\n  fix: ast ask \"I need <what> to do <why> — can you \
             bind it to {instance}?\"\n"
        )),
        other => Err(format!(
            "error: `ast {other}` is not one of the things this box can do\n{}",
            help(instance)
        )),
    }
}

fn one_line(what: &str, rest: &[String]) -> Result<String, String> {
    if rest.len() != 1 {
        return Err(format!("error: usage: {what} \"…\"\n"));
    }
    asterism_core::inbox::check_text(what, &rest[0])
        .map_err(|message| format!("error: {message}\n"))
}

fn ask_timeout(rest: &[String]) -> Result<(Duration, Vec<String>), String> {
    let mut timeout = DEFAULT_ASK_TIMEOUT;
    let mut words = Vec::new();
    let mut rest = rest.iter();
    while let Some(word) = rest.next() {
        if word == "--timeout" {
            let spec = rest
                .next()
                .ok_or_else(|| "error: --timeout needs a duration, like 30m\n".to_owned())?;
            let seconds =
                asterism_core::rewind::parse_duration(spec).map_err(|e| format!("error: {e}\n"))?;
            timeout = Duration::from_secs(seconds).min(MAX_ASK_TIMEOUT);
            continue;
        }
        words.push(word.clone());
    }
    Ok((timeout, words))
}

fn help(instance: &str) -> String {
    format!(
        "\
ast — the machine {instance} is running on, from inside it

  ast snapshot [name]        keep this disk as it is right now
  ast rewind                 what there is to go back to
  ast rewind --to <name>     go back to it (this machine restarts)
  ast rewind 30m             go back that far, same thing
                             add --include-memory to roll your memory back too
  ast cost                   what {instance} has spent on model calls today
  ast fork --n 3             three copies of this machine, running now
                             --each \"…\" once per fork tells each one what to try
  ast notify \"…\"             tell your owner something; does not wait
  ast ask \"…\"                ask your owner something and wait for the answer

`ast ask` blocks until somebody answers or the timeout runs out, and then you
carry on either way. Nothing here can stop you doing anything.
"
    )
}

// ---- doing it --------------------------------------------------------------

/// A snapshot of a machine that is *running*, which is the only kind an agent
/// can take of itself.
///
/// `ast snapshot <name>` on the host refuses a running guest, for a good
/// reason: a person who takes one is usually about to restore it, and a disk
/// caught mid-write restores to a filesystem that needs a check. From in here
/// the calculus is different and the automatic snapshots behind `ast rewind`
/// already made the same call — the agent is about to do something risky
/// *now*, and a crash-consistent image of now beats a consistent image of
/// never. It is the same path the scheduler uses, and it lands on the same
/// timeline.
async fn snapshot(node: &Node, instance: &str, tag: &str) -> Result<String> {
    let inst = {
        let reg = node.shard.lock().await;
        reg.get(instance)
            .map_err(|error| anyhow::anyhow!("{error:#}"))?
            .clone()
    };
    let meta = crate::rewind::take(&inst, tag, asterism_core::rewind::Kind::Named)?;
    Ok(format!(
        "snapshot {:?} taken ({:.2} s)\n",
        tag,
        meta.elapsed_ms as f64 / 1000.0
    ))
}

/// What one answered frame prints inside the box.
///
/// Deliberately the host's own renderings: `ast cost` in here and `ast cost
/// bot` out there are the same line, because they are the same function.
fn render(response: &Response) -> Result<String, String> {
    match response {
        Response::Ok => Ok(String::new()),
        Response::Cost { reports } => {
            let report = reports.first().ok_or("no cost report came back")?;
            Ok(format!("{}\n", asterism_core::ledger::line(report, true)))
        }
        Response::RewindTimeline { timeline } => {
            let now = asterism_core::instance::now_unix();
            Ok(asterism_core::rewind::render(
                timeline,
                now,
                asterism_core::rewind::local_offset(now),
                false,
            ))
        }
        Response::Rewound { report } => {
            let now = asterism_core::instance::now_unix();
            Ok(format!(
                "{}\n",
                report.render(asterism_core::rewind::local_offset(now), now)
            ))
        }

        Response::Forked { report } => Ok(format!("{}\n", report.render())),
        Response::Error { message } => Err(message.clone()),
        other => Err(format!("the daemon answered with {other:?}")),
    }
}

// ---- `ast tell` ------------------------------------------------------------

/// The argv that types one line into an agent's tmux session.
///
/// Two `send-keys`, not one. `-l` means the message is taken literally — an
/// agent's instruction is full of things tmux would otherwise read as key
/// names, and `run the test suite` should not arrive as three keystrokes and
/// a mystery. Enter is a second call for the same reason: it is a key name,
/// and there is no spelling of it that is also literal text.
pub(crate) fn tell_command(session: &str, message: &str) -> Vec<String> {
    vec![
        "/bin/sh".into(),
        "-c".into(),
        format!(
            "tmux has-session -t {session} 2>/dev/null || exit 66; \
             tmux send-keys -t {session} -l -- {message}; \
             tmux send-keys -t {session} Enter",
            session = shell_quote(session),
            message = shell_quote(message),
        ),
    ]
}

/// Single quotes, with the one escape that survives them.
fn shell_quote(word: &str) -> String {
    format!("'{}'", word.replace('\'', "'\\''"))
}

/// The refusal when there is no session to type into.
fn no_session(name: &str) -> anyhow::Error {
    anyhow::Error::new(asterism_core::fix::Fixable::new(
        format!("{name} has no agent session to type into"),
        asterism_core::fix::Fix::noted(
            format!("ast session {name}"),
            "or make it an agent instance with `ast create --agent`",
        ),
    ))
}

pub(crate) fn claims(req: &Request) -> bool {
    matches!(req, Request::Tell { .. })
}

pub(crate) async fn serve(req: Request, node: &Node) -> Response {
    let Request::Tell { name, message } = req else {
        return Response::Error {
            message: "the agent channel does not answer that".into(),
        };
    };
    let message = match asterism_core::inbox::check_text("ast tell", &message) {
        Ok(message) => message,
        Err(message) => return Response::Error { message },
    };
    let exec = Request::Exec {
        name: name.clone(),
        command: tell_command(&name, &message),
        timeout_ms: 15_000,
    };
    match Box::pin(crate::handle(exec, node)).await {
        Response::Exec { status: 0, .. } => Response::Told { name },
        // 66 is what the script exits when tmux has no such session. Anything
        // else is a guest that could not run tmux at all, and the stderr from
        // it is more useful than a guess.
        Response::Exec { status: 66, .. } => Response::Error {
            message: format!("{:#}", no_session(&name)),
        },
        Response::Exec { status, stderr, .. } => Response::Error {
            message: format!(
                "typing into {name}'s session exited {status}: {}",
                stderr.trim()
            ),
        },
        Response::Error { message } => Response::Error { message },
        other => Response::Error {
            message: format!("the guest answered with {other:?}"),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(words: &[&str]) -> Vec<String> {
        words.iter().map(|word| (*word).to_owned()).collect()
    }

    fn snapshot_tag(plan: Result<Plan, String>) -> String {
        match plan.unwrap() {
            Plan::Snapshot(tag) => tag,
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_snapshot_is_named_and_taken_of_this_instance() {
        assert_eq!(
            snapshot_tag(plan("bot", &argv(&["snapshot", "before-schema-migration"]))),
            "before-schema-migration"
        );
        // The instance may name itself, because a person reading the docs for
        // the host command will type it that way at least once.
        assert_eq!(
            snapshot_tag(plan("bot", &argv(&["snapshot", "bot", "before-x"]))),
            "before-x"
        );
    }

    #[test]
    fn another_instance_is_refused_by_the_sentence_and_nothing_is_taken() {
        let refusal = plan("bot", &argv(&["snapshot", "other-bot", "x"])).unwrap_err();
        assert_eq!(
            refusal,
            "error: \"other-bot\" is not this instance — inside the box, ast acts on bot only\n"
        );
        for words in [
            argv(&["rewind", "other-bot"]),
            argv(&["rewind", "other-bot", "--to", "x"]),
            argv(&["cost", "other-bot"]),
        ] {
            assert_eq!(
                plan("bot", &words).unwrap_err(),
                "error: \"other-bot\" is not this instance — inside the box, ast acts on bot only\n",
                "{words:?}"
            );
        }
    }

    #[test]
    fn a_secret_is_refused_with_the_reason_and_the_way_to_ask_for_one() {
        let refusal = plan("bot", &argv(&["secret", "ls"])).unwrap_err();
        assert!(
            refusal.contains("not in it, and `ast` here cannot read them"),
            "{refusal}"
        );
        assert!(refusal.contains("ast ask"), "{refusal}");
        assert!(
            !refusal.contains("sk-"),
            "a refusal must not be a place a value could appear: {refusal}"
        );
    }

    #[test]
    fn cost_is_this_instance_since_this_devices_midnight() {
        match plan("bot", &argv(&["cost"])).unwrap() {
            Plan::Frame(Request::Cost { name, window, .. }) => {
                assert_eq!(name.as_deref(), Some("bot"));
                assert_eq!(window, "today");
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn rewind_lists_by_default_and_takes_a_target_when_given_one() {
        assert!(matches!(
            plan("bot", &argv(&["rewind"])).unwrap(),
            Plan::Frame(Request::RewindTimeline { .. })
        ));
        match plan("bot", &argv(&["rewind", "--to", "before-x"])).unwrap() {
            Plan::Frame(Request::Rewind {
                to, include_memory, ..
            }) => {
                assert_eq!(
                    to,
                    asterism_core::rewind::Target::Tag {
                        tag: "before-x".into()
                    }
                );
                assert!(
                    !include_memory,
                    "a rewind leaves the agent's memory alone unless it says otherwise"
                );
            }
            other => panic!("{other:?}"),
        }
        match plan(
            "bot",
            &argv(&["rewind", "--to", "before-x", "--include-memory"]),
        )
        .unwrap()
        {
            Plan::Frame(Request::Rewind { include_memory, .. }) => assert!(include_memory),
            other => panic!("{other:?}"),
        }
        match plan("bot", &argv(&["rewind", "30m"])).unwrap() {
            Plan::Frame(Request::Rewind { to, .. }) => {
                assert_eq!(to, asterism_core::rewind::Target::Back { seconds: 1800 })
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn ask_takes_one_line_and_an_optional_deadline() {
        match plan("bot", &argv(&["ask", "now (A) or tomorrow (B)?"])).unwrap() {
            Plan::Ask { text, timeout } => {
                assert_eq!(text, "now (A) or tomorrow (B)?");
                assert_eq!(timeout, DEFAULT_ASK_TIMEOUT);
            }
            other => panic!("{other:?}"),
        }
        match plan("bot", &argv(&["ask", "--timeout", "30m", "A or B?"])).unwrap() {
            Plan::Ask { timeout, .. } => assert_eq!(timeout, Duration::from_secs(1800)),
            other => panic!("{other:?}"),
        }
        assert!(plan("bot", &argv(&["ask"])).is_err());
        assert!(
            plan("bot", &argv(&["ask", "a", "b"])).is_err(),
            "a question is one argument, so that quoting is not optional"
        );
        // A day and a half is capped at a day, rather than refused: the agent
        // asked to wait a long time and it gets to wait a long time.
        match plan("bot", &argv(&["ask", "--timeout", "36h", "A?"])).unwrap() {
            Plan::Ask { timeout, .. } => assert_eq!(timeout, MAX_ASK_TIMEOUT),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn an_agent_forks_itself_and_nothing_else() {
        match plan("bot", &argv(&["fork", "--n", "3"])).unwrap() {
            Plan::Frame(Request::Fork {
                name,
                count,
                each,
                stopped,
                yes,
            }) => {
                assert_eq!(name, "bot");
                assert_eq!(count, 3);
                assert!(each.is_empty() && !stopped);
                assert!(
                    yes,
                    "there is nobody at a terminal to confirm to, and refusing \
                     would be the approval gate this feature does not have"
                );
            }
            other => panic!("{other:?}"),
        }
        match plan(
            "bot",
            &argv(&["fork", "--n", "2", "--each", "try A", "--each", "try B"]),
        )
        .unwrap()
        {
            Plan::Frame(Request::Fork { each, .. }) => {
                assert_eq!(each, vec!["try A".to_owned(), "try B".to_owned()])
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(
            plan("bot", &argv(&["fork", "other-bot"])).unwrap_err(),
            "error: \"other-bot\" is not this instance — inside the box, ast acts on bot only\n"
        );
        let mismatch = plan("bot", &argv(&["fork", "--n", "3", "--each", "one"])).unwrap_err();
        assert!(mismatch.contains("one line per fork"), "{mismatch}");
    }

    #[test]
    fn notify_does_not_wait_for_anything() {
        match plan(
            "bot",
            &argv(&["notify", "PR #42 opened — ready for review"]),
        )
        .unwrap()
        {
            Plan::Notify(text) => assert_eq!(text, "PR #42 opened — ready for review"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn nothing_and_help_both_say_what_there_is() {
        for words in [vec![], argv(&["help"])] {
            match plan("bot", &words).unwrap() {
                Plan::Print(text) => {
                    for verb in ["snapshot", "rewind", "cost", "notify", "ask"] {
                        assert!(text.contains(&format!("ast {verb}")), "{text}");
                    }
                    assert!(text.contains("bot"), "the help names this box: {text}");
                }
                other => panic!("{other:?}"),
            }
        }
        let unknown = plan("bot", &argv(&["rm", "-rf"])).unwrap_err();
        assert!(
            unknown.contains("is not one of the things this box can do"),
            "{unknown}"
        );
        assert!(
            unknown.contains("ast snapshot"),
            "and it says what is: {unknown}"
        );
    }

    #[test]
    fn a_told_line_is_typed_literally_and_then_entered() {
        let command = tell_command("bot", "run the test suite and fix what fails");
        let script = command.last().unwrap();
        assert!(script.contains("tmux has-session -t 'bot'"), "{script}");
        assert!(
            script.contains("send-keys -t 'bot' -l -- 'run the test suite and fix what fails'"),
            "{script}"
        );
        assert!(script.contains("send-keys -t 'bot' Enter"), "{script}");
    }

    #[test]
    fn a_quote_in_the_message_cannot_end_the_message() {
        let message = "it's fine'; rm -rf /; echo '";
        let command = tell_command("bot", message);
        let script = command.last().unwrap();
        // Proved by the shell itself rather than by eye: what comes back out
        // of the quoting is one word, and it is the word that went in.
        let echoed = std::process::Command::new("/bin/sh")
            .arg("-c")
            .arg(format!("printf %s {}", shell_quote(message)))
            .output()
            .unwrap();
        assert_eq!(String::from_utf8(echoed.stdout).unwrap(), message);
        assert_eq!(
            script.matches("tmux ").count(),
            3,
            "one has-session and two send-keys, and nothing the message added: {script}"
        );
    }

    #[test]
    fn a_missing_session_names_the_command_that_makes_one() {
        let error = format!("{:#}", no_session("bot"));
        assert!(error.contains("no agent session"), "{error}");
        let chain = no_session("bot");
        let fix = asterism_core::fix::of(&chain).expect("a refusal with a remedy");
        assert!(fix.to_string().contains("ast session bot"), "{fix}");
    }
}
