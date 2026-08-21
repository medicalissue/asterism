//! What waking a device, and asking whether it could be woken, put on the
//! wire.
//!
//! Split out beside [`super::swap`] for the same reason: power and presence
//! is one area of the daemon, so the table `ast device check` prints and the
//! compatibility tests for the wake frames sit in one file that one branch
//! edits.
//!
//! The type that matters here is [`Verdict`], and what matters about it is
//! that it has a fourth value. A wake check run on the machine that would be
//! asleep can verify almost nothing, and this module exists to make saying so
//! as easy as saying `ok`.

use serde::{Deserialize, Serialize};

/// One line of `ast device check`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckRow {
    /// What is being reported on: `wake on magic packet`, `interface`, ...
    pub item: String,
    /// How it stands.
    pub verdict: Verdict,
    /// The evidence, or the reason there is none.
    pub detail: String,
}

/// How sure this device is about one line of its own wake readiness.
///
/// [`Verdict::Unknown`] is a first-class answer and gets used a lot, on
/// purpose. Almost nothing about waking can be *verified* from the machine
/// that would be asleep — whether the NIC keeps power after shutdown, whether
/// the switch floods the broadcast, whether a Bonjour proxy is holding the
/// Wi-Fi address — and a check that guessed `ok` at those would be worse than
/// no check at all, because it would be believed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// Verified on this machine, right now.
    Ok,
    /// Verified, and it will not work.
    No,
    /// True as far as it goes, with a caveat that decides whether it works.
    Warn,
    /// Not knowable from here.
    Unknown,
}

impl Verdict {
    /// The word the table prints.
    pub fn label(&self) -> &'static str {
        match self {
            Verdict::Ok => "ok",
            Verdict::No => "no",
            Verdict::Warn => "warn",
            Verdict::Unknown => "?",
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::protocol::{Request, Response};

    /// Wake was added to a protocol already in the field, so it has to be
    /// purely additive: old frames keep parsing, and the new ones parse
    /// without the field a newer daemon would send.
    #[test]
    fn the_wake_frames_are_additive() {
        let wake: Request = serde_json::from_str(r#"{"cmd":"device_wake","name":"desktop"}"#).unwrap();
        assert!(matches!(wake, Request::DeviceWake { name } if name == "desktop"));

        // An `astd` that predates lan-id checking sends the MAC and nothing
        // else; that must not be a parse error on the device being asked.
        let bare: Request =
            serde_json::from_str(r#"{"cmd":"wake_broadcast","mac":"de:ad:be:ef:00:01"}"#).unwrap();
        assert!(matches!(bare, Request::WakeBroadcast { lan_id: None, .. }));

        // Likewise a progress line with no `done` is not the last one.
        let line: Response = serde_json::from_str(r#"{"result":"wake","text":"sent"}"#).unwrap();
        assert!(matches!(line, Response::Wake { done: false, .. }));

        // And a peer that knows only half of its own story still answers.
        let facts: Response =
            serde_json::from_str(r#"{"result":"wake_facts","facts":{"mac":"de:ad:be:ef:00:01"}}"#)
                .unwrap();
        let Response::WakeFacts { facts } = facts else { panic!("should be facts") };
        assert_eq!(facts.mac.as_deref(), Some("de:ad:be:ef:00:01"));
        assert_eq!(facts.lan_id, None);
        assert_eq!(facts.wakeable(), None, "half a story cannot wake anything");
    }
}
