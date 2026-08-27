//! `ast open NAME:PORT` — the words, the arithmetic and the refusals.
//!
//! The command itself is a listener and a mesh stream, and those live in the
//! daemon. What lives here is everything about it that is a *sentence*: how
//! `bot:3000` is read, what "unknown instance" says, how long ago a device
//! was last seen and how a path is written next to a URL.
//!
//! In `asterism-core` rather than in either binary because both ends need it.
//! The daemon composes the refusals — it is the half that knows the orbit —
//! and the CLI composes the line the user reads, and a refusal that was
//! worded in one place and re-worded in the other is how two builds end up
//! disagreeing about what happened.

use anyhow::{anyhow, bail, Result};

/// Asterism's own guest-control port, as seen from inside an OCI guest.
///
/// `ast open` refuses it for the same reason the publish validation does: it
/// is where the authenticated agent behind `ast exec` and `ast logs` is
/// listening, and no service of the user's is.
pub const GUEST_CONTROL_PORT: u16 = crate::guest::OCI_TCP_PORT;

/// What `NAME:PORT` parsed to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    /// The instance, as it is named anywhere in the orbit.
    pub name: String,
    /// The port that instance's guest serves on, from inside the guest.
    pub port: u16,
}

impl std::fmt::Display for Target {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.name, self.port)
    }
}

/// Reads `bot:3000`.
///
/// Strict about the shape on purpose. `ast open bot` names no port and
/// `ast open bot:http` names no number, and guessing at either would mean
/// binding a listener the user did not ask for.
pub fn parse(spec: &str) -> Result<Target> {
    let Some((name, port)) = spec.rsplit_once(':') else {
        // The remedy is the same words with a port on the end, which is
        // exactly what a [`Fix`] is for: the sentence says what is missing
        // and the fix line is the thing to type.
        return Err(anyhow::Error::new(crate::fix::Fixable::new(
            format!("{spec:?} is not NAME:PORT — say which port the instance serves"),
            crate::fix::Fix::new(format!("ast open {spec}:3000")),
        )));
    };
    if name.is_empty() {
        bail!("{spec:?} names no instance — say which one, as in `ast open bot:3000`");
    }
    let port: u16 = port
        .parse()
        .map_err(|_| anyhow!("{port:?} is not a port number"))?;
    if port == 0 {
        bail!("port 0 is not a port a service listens on");
    }
    Ok(Target {
        name: name.to_owned(),
        port,
    })
}

/// The refusal for a name no device in the orbit answers to.
///
/// The names it *does* answer to come with it. A user who mistyped one is one
/// glance from the right one, and a user whose instance is genuinely missing
/// learns that from the same line.
pub fn unknown_instance(name: &str, orbit: &[String]) -> String {
    if orbit.is_empty() {
        return format!("unknown instance {name:?} (this orbit has no instances)");
    }
    format!(
        "unknown instance {name:?} (orbit has: {})",
        orbit.join(", ")
    )
}

/// The refusal for an instance whose device is not answering.
///
/// Named as a fact about the *device*, because that is the thing to go and
/// fix; the instance is only how the user found out.
///
/// `subject` is what the user asked for, in their words — `bot:3000` from
/// `ast open`, or a bare instance name from a command that has no port in it.
/// The caller supplies it because this refusal belongs to every command that
/// addresses an instance by name, not only to this one.
pub fn device_offline(device: &str, last_seen_secs: Option<u64>, subject: &str) -> String {
    match last_seen_secs {
        Some(age) => format!(
            "{device} is offline (last seen {}) — {subject} is unreachable",
            ago(age)
        ),
        None => format!("{device} is offline — {subject} is unreachable"),
    }
}

/// The refusal for an instance that is not running.
///
/// The same sentence `ast ssh` uses, because it is the same fact and the user
/// should not have to notice which command told them.
pub fn not_running(name: &str) -> String {
    format!("instance {name:?} is not running — `ast up {name}` first")
}

/// The refusal for Asterism's own control port.
pub fn refuse_guest_control_port(port: u16) -> Result<()> {
    if port == GUEST_CONTROL_PORT {
        bail!(
            "guest port {GUEST_CONTROL_PORT} is Asterism's own guest-control endpoint on an OCI \
             instance — `ast exec`, `ast logs` and boot readiness use it, and no service of yours \
             is listening there. Open the port your image actually serves"
        );
    }
    Ok(())
}

/// How long ago, in the coarsest unit that is still true.
///
/// A last-seen is a fact about how worried to be, and seconds of precision on
/// a device that has been gone for a day is precision about nothing.
pub fn ago(secs: u64) -> String {
    match secs {
        0..=1 => "just now".to_owned(),
        2..=59 => format!("{secs} s ago"),
        60..=3599 => format!("{} min ago", secs / 60),
        3600..=86_399 => format!("{} h ago", secs / 3600),
        _ => format!("{} d ago", secs / 86_400),
    }
}

/// The parenthetical after the URL: which path carries the bytes, and how
/// long a round trip on it took when the mesh had already measured one.
///
/// The RTT is omitted rather than invented when nothing measured it. A number
/// beside a path is an attribution, and `ast open` has no business making one
/// up for a link it did not time.
pub fn path_suffix(path: &str, rtt_micros: Option<u64>) -> String {
    match rtt_micros {
        Some(micros) => format!("({path}, {} ms)", millis(micros)),
        None => format!("({path})"),
    }
}

/// Microseconds as whole milliseconds, rounded rather than truncated: a
/// 1.6 ms path that printed `1 ms` would be understating itself every time.
pub fn millis(micros: u64) -> u64 {
    micros.saturating_add(500) / 1000
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_target_is_a_name_and_a_port() {
        assert_eq!(
            parse("bot:3000").unwrap(),
            Target {
                name: "bot".into(),
                port: 3000
            }
        );
        assert_eq!(parse("bot:3000").unwrap().to_string(), "bot:3000");
    }

    #[test]
    fn a_target_without_a_port_says_what_is_missing_and_what_to_type() {
        let e = parse("bot").unwrap_err();
        assert!(e.to_string().contains("NAME:PORT"), "{e}");
        assert_eq!(
            crate::fix::of(&e).map(|fix| fix.command.clone()),
            Some("ast open bot:3000".to_owned())
        );
    }

    #[test]
    fn a_port_that_is_not_a_number_is_refused_rather_than_guessed() {
        assert!(parse("bot:http").is_err());
        assert!(parse("bot:0").is_err());
        assert!(parse(":3000").is_err());
        assert!(parse("bot:99999").is_err());
    }

    #[test]
    fn the_unknown_instance_refusal_lists_the_orbit() {
        let names = vec!["bot".to_owned(), "web".to_owned()];
        assert_eq!(
            unknown_instance("nope", &names),
            r#"unknown instance "nope" (orbit has: bot, web)"#
        );
    }

    #[test]
    fn an_empty_orbit_says_so_rather_than_printing_an_empty_list() {
        assert_eq!(
            unknown_instance("nope", &[]),
            r#"unknown instance "nope" (this orbit has no instances)"#
        );
    }

    #[test]
    fn the_offline_refusal_names_the_device_and_how_stale_it_is() {
        let target = Target {
            name: "bot".into(),
            port: 3000,
        };
        assert_eq!(
            device_offline("dev5", Some(4 * 60 + 12), &target.to_string()),
            "dev5 is offline (last seen 4 min ago) — bot:3000 is unreachable"
        );
        assert_eq!(
            device_offline("dev5", None, &target.to_string()),
            "dev5 is offline — bot:3000 is unreachable"
        );
    }

    #[test]
    fn the_guest_control_port_is_never_opened() {
        let e = refuse_guest_control_port(GUEST_CONTROL_PORT)
            .unwrap_err()
            .to_string();
        assert!(e.contains("guest-control"), "{e}");
        assert!(refuse_guest_control_port(3000).is_ok());
    }

    #[test]
    fn ages_are_coarse() {
        assert_eq!(ago(0), "just now");
        assert_eq!(ago(30), "30 s ago");
        assert_eq!(ago(252), "4 min ago");
        assert_eq!(ago(7_200), "2 h ago");
        assert_eq!(ago(200_000), "2 d ago");
    }

    #[test]
    fn a_path_prints_its_rtt_only_when_one_was_measured() {
        assert_eq!(path_suffix("direct", Some(3_400)), "(direct, 3 ms)");
        assert_eq!(path_suffix("relay", None), "(relay)");
        assert_eq!(millis(1_600), 2);
    }
}
