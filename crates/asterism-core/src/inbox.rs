//! What an agent said to its owner, and what the owner said back.
//!
//! An agent that runs unattended has exactly one thing tmux and ssh cannot
//! give it: a way to reach the person who owns it *without* that person being
//! at a terminal at the time. `ast notify` is that in one direction, `ast ask`
//! is that in both, and this module is the shape of what travels.
//!
//! ## Not an approval gate
//!
//! Nothing here can refuse anything. An agent that calls `ast ask` chose to
//! wait; an agent that does not call it is not stopped, delayed, or asked to
//! justify itself. The channel is leverage the agent picks up, not a fence
//! somebody put around it. That is a design constraint and not an accident:
//! the moment a daemon can hold an agent's work hostage pending a human, the
//! product is a slower human rather than a faster agent.
//!
//! ## The file
//!
//! Append-only JSONL under the Asterism home. Two record shapes, folded on
//! read:
//!
//! ```text
//! {"record":"said","seq":1,"at":1756303320,"instance":"bot","kind":"ask","text":"…"}
//! {"record":"replied","seq":1,"at":1756305180,"text":"A"}
//! ```
//!
//! Append-only because the interesting failure is a crash between "the agent
//! asked" and "the owner answered", and a file that is only ever appended to
//! cannot lose the first half while writing the second. Folding is cheap: an
//! inbox is a human-scale list, not a log.

use serde::{Deserialize, Serialize};

/// Which of the two things an agent did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    /// One line, said and not waited on.
    Notify,
    /// A question the agent is blocked on until somebody answers it.
    Ask,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Notify => "notify",
            Kind::Ask => "ask",
        }
    }
}

/// One line in the inbox, after folding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    pub seq: u64,
    /// Unix seconds, as the device that took the message saw them.
    pub at: u64,
    pub instance: String,
    pub kind: Kind,
    pub text: String,
    /// The owner's answer, once there is one. Always `None` for a notify.
    #[serde(default)]
    pub reply: Option<String>,
    #[serde(default)]
    pub replied_at: Option<u64>,
}

impl Entry {
    /// An ask nobody has answered yet — the only kind of entry that is
    /// holding an agent up.
    pub fn waiting(&self) -> bool {
        self.kind == Kind::Ask && self.reply.is_none()
    }
}

/// One record as it is written to the file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "record", rename_all = "snake_case")]
pub enum Record {
    Said {
        seq: u64,
        at: u64,
        instance: String,
        kind: Kind,
        text: String,
    },
    Replied {
        seq: u64,
        at: u64,
        text: String,
    },
}

/// Fold a file's records into the entries they describe.
///
/// Unparseable lines are skipped rather than fatal: this file is read to
/// answer `ast inbox`, and one corrupt line at the end of a truncated write
/// must not take the rest of somebody's inbox with it.
pub fn fold(text: &str) -> Vec<Entry> {
    let mut entries: Vec<Entry> = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Ok(record) = serde_json::from_str::<Record>(line) else {
            continue;
        };
        match record {
            Record::Said {
                seq,
                at,
                instance,
                kind,
                text,
            } => {
                if entries.iter().any(|entry| entry.seq == seq) {
                    continue;
                }
                entries.push(Entry {
                    seq,
                    at,
                    instance,
                    kind,
                    text,
                    reply: None,
                    replied_at: None,
                });
            }
            Record::Replied { seq, at, text } => {
                if let Some(entry) = entries.iter_mut().find(|entry| entry.seq == seq) {
                    // First answer wins. A second `ast inbox reply` to the
                    // same question is a person changing their mind after the
                    // agent already acted on the first, and rewriting history
                    // would make the transcript disagree with what happened.
                    if entry.reply.is_none() {
                        entry.reply = Some(text);
                        entry.replied_at = Some(at);
                    }
                }
            }
        }
    }
    entries.sort_by_key(|entry| entry.seq);
    entries
}

/// The next sequence number for a file that already holds `entries`.
pub fn next_seq(entries: &[Entry]) -> u64 {
    entries.iter().map(|entry| entry.seq).max().unwrap_or(0) + 1
}

/// `14:02` in the reader's own timezone.
pub fn clock(at: u64, offset: i64) -> String {
    let local = at as i64 + offset;
    let minutes = local.div_euclid(60).rem_euclid(1440);
    format!("{:02}:{:02}", minutes / 60, minutes % 60)
}

/// The table `ast inbox` prints, or the one sentence that says it is empty.
///
/// One line per entry, and the reply command spelled out on any question that
/// is still waiting — because the whole point of the line is that somebody
/// reading it can answer without going to look up how.
pub fn render(entries: &[Entry], offset: i64) -> String {
    if entries.is_empty() {
        return "nothing yet — agents say things here with `ast notify` and `ast ask`".into();
    }
    let width = entries
        .iter()
        .map(|entry| entry.instance.chars().count())
        .max()
        .unwrap_or(0);
    let mut out = String::new();
    for entry in entries {
        out.push_str(&format!(
            " {}  {:width$}  {:<6}  {}",
            clock(entry.at, offset),
            entry.instance,
            entry.kind.as_str(),
            entry.text,
        ));
        match (&entry.reply, entry.kind) {
            (None, Kind::Ask) => {
                out.push_str(&format!("   [reply: ast inbox reply {} …]", entry.seq));
            }
            (Some(reply), _) => out.push_str(&format!("   [replied: {reply}]")),
            (None, Kind::Notify) => {}
        }
        out.push('\n');
    }
    out.pop();
    out
}

/// The one line `ast logs <name> -f` interleaves when an agent says something.
///
/// Prefixed rather than plain so it cannot be mistaken for output the agent
/// itself produced, and carrying the reply command for the same reason the
/// table does.
pub fn stream_line(entry: &Entry) -> String {
    match entry.kind {
        Kind::Notify => format!("── {} notify  {}", entry.instance, entry.text),
        Kind::Ask => format!(
            "── {} ask     {}   [reply: ast inbox reply {} …]",
            entry.instance, entry.text, entry.seq
        ),
    }
}

/// The longest message either verb accepts.
///
/// A notification is a sentence somebody reads on a phone. Anything longer is
/// a log line, and `ast logs` is where log lines already go.
pub const MAX_TEXT_BYTES: usize = 2000;

/// One line, trimmed, and never empty.
pub fn check_text(what: &str, text: &str) -> Result<String, String> {
    let text = text.trim();
    if text.is_empty() {
        return Err(format!("{what} needs something to say"));
    }
    if text.len() > MAX_TEXT_BYTES {
        return Err(format!(
            "{what} is {} bytes, and the limit is {MAX_TEXT_BYTES} — say the short version and put the rest in the repository",
            text.len()
        ));
    }
    // Newlines would make one entry look like several in every rendering of
    // this file, including the one that goes to a phone.
    Ok(text.replace(['\n', '\r'], " "))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn said(seq: u64, at: u64, kind: Kind, text: &str) -> String {
        serde_json::to_string(&Record::Said {
            seq,
            at,
            instance: "bot".into(),
            kind,
            text: text.into(),
        })
        .unwrap()
    }

    #[test]
    fn a_reply_folds_onto_the_question_it_answers() {
        let file = format!(
            "{}\n{}\n{}\n",
            said(1, 1_756_303_320, Kind::Ask, "now (A) or tomorrow (B)?"),
            said(2, 1_756_305_060, Kind::Notify, "PR #42 opened"),
            serde_json::to_string(&Record::Replied {
                seq: 1,
                at: 1_756_305_180,
                text: "A".into(),
            })
            .unwrap()
        );
        let entries = fold(&file);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].reply.as_deref(), Some("A"));
        assert!(!entries[0].waiting());
        assert!(entries[1].reply.is_none());
        assert!(!entries[1].waiting(), "a notify never waits for anything");
        assert_eq!(next_seq(&entries), 3);
    }

    #[test]
    fn a_second_answer_does_not_rewrite_the_one_the_agent_acted_on() {
        let file = format!(
            "{}\n{}\n{}\n",
            said(1, 10, Kind::Ask, "A or B?"),
            serde_json::to_string(&Record::Replied {
                seq: 1,
                at: 20,
                text: "A".into()
            })
            .unwrap(),
            serde_json::to_string(&Record::Replied {
                seq: 1,
                at: 30,
                text: "B".into()
            })
            .unwrap(),
        );
        assert_eq!(fold(&file)[0].reply.as_deref(), Some("A"));
    }

    #[test]
    fn a_torn_last_line_does_not_take_the_inbox_with_it() {
        let file = format!("{}\n{{\"record\":\"sa", said(1, 10, Kind::Notify, "hello"));
        let entries = fold(&file);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].text, "hello");
    }

    #[test]
    fn a_waiting_question_carries_the_command_that_answers_it() {
        let entries = fold(&format!(
            "{}\n{}\n",
            said(1, 1_756_303_320, Kind::Ask, "now (A) or tomorrow (B)?"),
            said(2, 1_756_305_060, Kind::Notify, "PR #42 opened"),
        ));
        let table = render(&entries, 0);
        assert!(table.contains("[reply: ast inbox reply 1 …]"), "{table}");
        assert!(
            !table.lines().nth(1).unwrap().contains("reply:"),
            "a notify is not answerable: {table}"
        );
        assert!(table.contains("ask   "), "{table}");
        assert!(table.contains("notify"), "{table}");
    }

    #[test]
    fn an_empty_inbox_says_what_puts_something_in_it() {
        let text = render(&[], 0);
        assert!(text.contains("ast notify"), "{text}");
        assert!(text.contains("ast ask"), "{text}");
    }

    #[test]
    fn the_clock_is_the_readers_own() {
        // 1756303320 is 2026-08-27T14:02:00Z.
        assert_eq!(clock(1_756_303_320, 0), "14:02");
        assert_eq!(clock(1_756_303_320, 9 * 3600), "23:02");
        assert_eq!(clock(1_756_303_320, -5 * 3600), "09:02");
    }

    #[test]
    fn a_message_is_one_line_and_bounded() {
        assert_eq!(check_text("notify", "  hello  ").unwrap(), "hello");
        assert_eq!(check_text("notify", "a\nb").unwrap(), "a b");
        assert!(check_text("notify", "   ").is_err());
        let long = "x".repeat(MAX_TEXT_BYTES + 1);
        let error = check_text("notify", &long).unwrap_err();
        assert!(error.contains("the limit is"), "{error}");
    }
}
