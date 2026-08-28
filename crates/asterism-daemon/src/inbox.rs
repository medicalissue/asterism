//! The device's inbox: what its agents said, and what it said back.
//!
//! One append-only file under the Asterism home, plus a per-instance index of
//! the sequence numbers in it, plus — in memory only — the set of `ast ask`
//! calls that are still waiting for an answer.
//!
//! ## Why it is device-local
//!
//! `ast inbox` is answered by the device whose daemon took the message, the
//! way `ast cost --all` is answered by the device whose door read the
//! counters. That is not a limitation to be lifted later: only this device
//! holds the open guest-control session that an `ast ask` is parked on, so
//! only this device can hand an answer back to a waiting agent. Making the
//! listing orbit-wide while the reply was not would be the worse half of both
//! designs.
//!
//! ## What it cannot do
//!
//! Refuse anything. There is no state in here that any other part of Asterism
//! consults before doing work, and nothing an agent runs waits on a human
//! unless the agent itself chose to call `ast ask`.
//!
//! ## The hook a hosted push would use
//!
//! [`Event`] is emitted for every message an agent leaves. Nothing subscribes
//! to it in this build — pushing to a phone is AST-154 and is not here — and
//! it exists so that the client which will do that has one place to attach
//! rather than a reason to reach into this file.

use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use anyhow::{Context, Result};
use asterism_core::inbox::{self, Entry, Kind, Record};
use asterism_core::paths;
use asterism_core::protocol::{Request, Response};

/// Something an agent left for the person who owns it.
///
/// The documented seam for a hosted push (AST-154): a client that wants to
/// ring somebody's phone subscribes here, and nothing else in this module has
/// to know it exists.
// Nothing in this build subscribes — the hosted push that will is AST-154 —
// so the field is written and not yet read here. That is the point of a hook.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub(crate) struct Event {
    pub entry: Entry,
}

type Listener = Box<dyn Fn(&Event) + Send + Sync>;

fn listeners() -> &'static Mutex<Vec<Listener>> {
    static LISTENERS: OnceLock<Mutex<Vec<Listener>>> = OnceLock::new();
    LISTENERS.get_or_init(|| Mutex::new(Vec::new()))
}

/// Be told about every message an agent leaves, from now on.
#[allow(dead_code)]
pub(crate) fn subscribe(listener: Listener) {
    listeners().lock().unwrap().push(listener);
}

fn announce(entry: &Entry) {
    let event = Event {
        entry: entry.clone(),
    };
    for listener in listeners().lock().unwrap().iter() {
        listener(&event);
    }
}

// ---- where the bytes are ---------------------------------------------------

fn file_in(home: &Path) -> PathBuf {
    home.join("inbox.jsonl")
}

/// One file per instance holding the sequence numbers that are its own.
///
/// Not a cache of the entries themselves — that would be a second copy of the
/// truth. It is the answer to "which of these are bot's", which is the only
/// question the log cannot answer without being read end to end, and it is
/// what an `ast logs bot -f` can watch without folding anybody else's inbox.
fn index_in(home: &Path, instance: &str) -> PathBuf {
    home.join("inbox").join(format!("{instance}.idx"))
}

fn read_in(home: &Path) -> Vec<Entry> {
    match std::fs::read_to_string(file_in(home)) {
        Ok(text) => inbox::fold(&text),
        Err(_) => Vec::new(),
    }
}

fn append_in(home: &Path, record: &Record) -> Result<()> {
    let path = file_in(home);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).with_context(|| format!("making {}", parent.display()))?;
    }
    let mut line = serde_json::to_string(record).context("encoding an inbox record")?;
    line.push('\n');
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .with_context(|| format!("opening {}", path.display()))?;
    file.write_all(line.as_bytes())
        .with_context(|| format!("appending to {}", path.display()))?;
    file.flush()
        .with_context(|| format!("flushing {}", path.display()))
}

// ---- writing ---------------------------------------------------------------

/// Write down one thing an agent said, and answer with the entry it became.
pub(crate) fn say(instance: &str, kind: Kind, text: &str) -> Result<Entry> {
    say_in(&paths::home_dir(), instance, kind, text)
}

fn say_in(home: &Path, instance: &str, kind: Kind, text: &str) -> Result<Entry> {
    // The whole file, folded, to find the next sequence number. An inbox is a
    // human-scale list — if it ever is not, the fix is to roll the file, not
    // to keep a counter that can disagree with what is in it.
    let seq = inbox::next_seq(&read_in(home));
    let at = asterism_core::instance::now_unix();
    append_in(
        home,
        &Record::Said {
            seq,
            at,
            instance: instance.to_owned(),
            kind,
            text: text.to_owned(),
        },
    )?;
    let index = index_in(home, instance);
    if let Some(parent) = index.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&index)
    {
        let _ = writeln!(file, "{seq}");
    }
    let entry = Entry {
        seq,
        at,
        instance: instance.to_owned(),
        kind,
        text: text.to_owned(),
        reply: None,
        replied_at: None,
    };
    announce(&entry);
    Ok(entry)
}

/// Answer a question. `true` back means an agent was actually waiting on it.
pub(crate) fn answer(seq: u64, text: &str) -> Result<(Entry, bool)> {
    answer_in(&paths::home_dir(), seq, text)
}

fn answer_in(home: &Path, seq: u64, text: &str) -> Result<(Entry, bool)> {
    let entries = read_in(home);
    let Some(entry) = entries.into_iter().find(|entry| entry.seq == seq) else {
        anyhow::bail!("there is no {seq} in this device's inbox — run `ast inbox` to see what is");
    };
    if entry.kind != Kind::Ask {
        anyhow::bail!("{seq} is a notification, not a question — there is nothing there to answer");
    }
    if let Some(already) = &entry.reply {
        anyhow::bail!("{seq} was already answered {already:?}");
    }
    append_in(
        home,
        &Record::Replied {
            seq,
            at: asterism_core::instance::now_unix(),
            text: text.to_owned(),
        },
    )?;
    let delivered = wake(seq, text);
    Ok((entry, delivered))
}

// ---- the agents that are waiting -------------------------------------------

type Waiters = Mutex<HashMap<u64, tokio::sync::oneshot::Sender<String>>>;

fn waiters() -> &'static Waiters {
    static WAITERS: OnceLock<Waiters> = OnceLock::new();
    WAITERS.get_or_init(Default::default)
}

/// Park on an answer to `seq`. The receiver resolves when somebody replies,
/// and errors if the daemon forgot about it — which the caller reads as a
/// timeout, because from the agent's side it is one.
pub(crate) fn wait_for(seq: u64) -> tokio::sync::oneshot::Receiver<String> {
    let (sender, receiver) = tokio::sync::oneshot::channel();
    waiters().lock().unwrap().insert(seq, sender);
    receiver
}

/// Stop waiting — the agent gave up, or its channel went away.
pub(crate) fn give_up(seq: u64) {
    waiters().lock().unwrap().remove(&seq);
}

fn wake(seq: u64, text: &str) -> bool {
    let Some(sender) = waiters().lock().unwrap().remove(&seq) else {
        return false;
    };
    sender.send(text.to_owned()).is_ok()
}

// ---- the frames ------------------------------------------------------------

pub(crate) fn claims(req: &Request) -> bool {
    matches!(req, Request::Inbox { .. } | Request::InboxReply { .. })
}

pub(crate) fn serve(req: Request) -> Response {
    match req {
        Request::Inbox { name, all } => {
            let mut entries = read_in(&paths::home_dir());
            if let Some(name) = name.as_deref() {
                entries.retain(|entry| entry.instance == name);
            }
            if !all {
                // The default is what is still open plus what has been said
                // recently, because an inbox that shows a month of answered
                // questions is one nobody reads.
                let cutoff = asterism_core::instance::now_unix().saturating_sub(7 * 86_400);
                entries.retain(|entry| entry.waiting() || entry.at >= cutoff);
            }
            Response::Inbox { entries }
        }
        Request::InboxReply { seq, text } => {
            let text = match asterism_core::inbox::check_text("a reply", &text) {
                Ok(text) => text,
                Err(message) => return Response::Error { message },
            };
            match answer(seq, &text) {
                Ok((entry, delivered)) => Response::Replied {
                    name: entry.instance,
                    delivered,
                },
                Err(error) => Response::Error {
                    message: format!("{error:#}"),
                },
            }
        }
        other => Response::Error {
            message: format!("the inbox does not answer {other:?}"),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn home() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    #[test]
    fn what_an_agent_says_is_appended_and_indexed_by_instance() {
        let dir = home();
        let one = say_in(dir.path(), "bot", Kind::Notify, "PR #42 opened").unwrap();
        let two = say_in(dir.path(), "other", Kind::Ask, "A or B?").unwrap();
        let three = say_in(dir.path(), "bot", Kind::Ask, "now or later?").unwrap();
        assert_eq!((one.seq, two.seq, three.seq), (1, 2, 3));

        let entries = read_in(dir.path());
        assert_eq!(entries.len(), 3);
        assert_eq!(
            std::fs::read_to_string(index_in(dir.path(), "bot")).unwrap(),
            "1\n3\n",
            "the index is this instance's sequence numbers and nobody else's"
        );
    }

    #[test]
    fn an_answer_folds_onto_the_question_and_a_second_one_is_refused() {
        let dir = home();
        // Sequence numbers are the key of a process-wide table of waiting
        // agents, so a test that means "nobody is waiting" has to pick one no
        // other test in this binary is parked on.
        for _ in 0..10 {
            say_in(dir.path(), "bot", Kind::Notify, "filler").unwrap();
        }
        say_in(dir.path(), "bot", Kind::Ask, "A or B?").unwrap();
        let (entry, delivered) = answer_in(dir.path(), 11, "A").unwrap();
        assert_eq!(entry.instance, "bot");
        assert!(
            !delivered,
            "nothing was parked on it, and saying so is the honest line"
        );
        assert_eq!(read_in(dir.path())[10].reply.as_deref(), Some("A"));
        let again = answer_in(dir.path(), 11, "B").unwrap_err().to_string();
        assert!(again.contains("already answered"), "{again}");
    }

    #[test]
    fn a_notification_is_not_a_question() {
        let dir = home();
        say_in(dir.path(), "bot", Kind::Notify, "PR #42 opened").unwrap();
        let error = answer_in(dir.path(), 1, "sure").unwrap_err().to_string();
        assert!(error.contains("nothing there to answer"), "{error}");
    }

    #[test]
    fn answering_a_number_that_is_not_there_says_how_to_find_one_that_is() {
        let dir = home();
        let error = answer_in(dir.path(), 9, "A").unwrap_err().to_string();
        assert!(error.contains("ast inbox"), "{error}");
    }

    #[tokio::test]
    async fn an_answer_reaches_the_agent_that_is_parked_on_it() {
        let dir = home();
        say_in(dir.path(), "bot", Kind::Ask, "A or B?").unwrap();
        let waiting = wait_for(1);
        let (_, delivered) = answer_in(dir.path(), 1, "A").unwrap();
        assert!(delivered, "the agent was waiting and got it");
        assert_eq!(waiting.await.unwrap(), "A");
    }

    #[test]
    fn an_agent_that_gave_up_is_not_woken() {
        let _waiting = wait_for(4242);
        give_up(4242);
        assert!(!wake(4242, "A"));
    }

    #[test]
    fn a_hosted_push_has_one_place_to_attach() {
        let dir = home();
        let seen = std::sync::Arc::new(Mutex::new(Vec::new()));
        let sink = seen.clone();
        subscribe(Box::new(move |event: &Event| {
            sink.lock().unwrap().push(event.entry.text.clone())
        }));
        say_in(dir.path(), "bot", Kind::Notify, "PR #42 opened").unwrap();
        assert!(seen
            .lock()
            .unwrap()
            .iter()
            .any(|text| text == "PR #42 opened"));
    }
}
