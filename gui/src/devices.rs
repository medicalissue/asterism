//! The Devices section: who is in this orbit, and the two conversations
//! that change that.
//!
//! Listing is one frame ([`Request::Devices`]) and reads like `ast devices`.
//! Pairing and waking are not: the daemon answers both with several lines
//! over a held-open connection, and pairing wants something back from the
//! human in the middle of it. [`pair`] and [`wake`] drive those exchanges as
//! plain functions over [`client::Conversation`], so `--pair-via-window` and
//! the window's own buttons run the same code against the same daemon.
//!
//! ## Why the store is read off disk
//!
//! [`Request::Devices`] answers who is here and who is answering. It does
//! not carry wake facts, and the moment those matter is the moment the
//! device is asleep and cannot be asked for them. They live on the peer's
//! record in `orbit.json` — written by the daemon at pairing and refreshed
//! whenever the peer is reachable — so that is where the Wake button's
//! condition is read from. Same home, same file the daemon wrote.

use anyhow::{bail, Result};
use serde::Serialize;

use asterism_core::device_shell::{ShellPolicyState, ShellPolicyStatus};
use asterism_core::orbit::{DeviceStatus, Orbit};
use asterism_core::paths;
use asterism_core::protocol::{Request, Response};

use crate::client::{self, Conversation};
use crate::feedback::Progress;

/// One device, as the table sees it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Row {
    pub name: String,
    /// The first twelve characters of the peer's public key. The name is a
    /// label; this is the identity.
    pub short_id: String,
    pub online: bool,
    /// `direct`, a relay, or empty when nobody is answering.
    pub path: String,
    /// The device this app is running on.
    pub is_self: bool,
    /// Whether this orbit knows a MAC and a network to aim a magic packet
    /// at. Offered as a button only when the device is also offline: waking
    /// something that is already awake is a no-op with a minute of waiting
    /// attached.
    pub wakeable: bool,
    /// The daemon's first-class read model, unchanged. A hosted panel and
    /// this local GUI therefore interpret the same tagged state and session
    /// rows rather than maintaining parallel caches.
    pub shell: Shell,
}

impl Row {
    fn of(device: &DeviceStatus, wakeable: bool, status: ShellPolicyStatus) -> Row {
        Row {
            name: device.name.clone(),
            short_id: device.short_id(),
            online: device.online,
            path: device.path.clone(),
            is_self: device.is_self,
            wakeable,
            shell: Shell {
                status,
                access: if device.is_self {
                    ShellAccess::LocalOnly
                } else {
                    ShellAccess::ReadOnly
                },
            },
        }
    }

    /// Whether the row draws a Wake button.
    pub fn can_wake(&self) -> bool {
        self.wakeable && !self.online && !self.is_self
    }
}

/// Device-shell data and the authority this consumer has over its target.
/// `access` is presentation-independent: only the row for this process's
/// local daemon may expose a mutation control.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Shell {
    pub status: ShellPolicyStatus,
    pub access: ShellAccess,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ShellAccess {
    LocalOnly,
    ReadOnly,
}

/// What the daemon has to say about the orbit.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Fleet {
    Unreachable { reason: String },
    Rows { rows: Vec<Row> },
}

/// The Devices section, whole.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Devices {
    pub fleet: Fleet,
}

impl Devices {
    pub fn load() -> Devices {
        match client::devices() {
            Ok(devices) => {
                // Each target is independent. Probe them concurrently so an
                // offline edge costs one mesh timeout, not one timeout for
                // every later row in the orbit.
                let mut statuses = shell_statuses(&devices).into_iter();
                Devices::of_with(&devices, &wakeable_ids(), |_| {
                    statuses.next().expect("one shell status per device")
                })
            }
            Err(e) => Devices { fleet: Fleet::Unreachable { reason: format!("{e:#}") } },
        }
    }

    /// Build a section from an answer somebody else already has.
    #[cfg(test)]
    pub fn of(devices: &[DeviceStatus], wakeable: &[String]) -> Devices {
        Devices::of_with(devices, wakeable, |_| {
            ShellPolicyStatus::unavailable("device-shell status was not probed")
        })
    }

    fn of_with(
        devices: &[DeviceStatus],
        wakeable: &[String],
        mut shell_status: impl FnMut(&DeviceStatus) -> ShellPolicyStatus,
    ) -> Devices {
        Devices {
            fleet: Fleet::Rows {
                rows: devices
                    .iter()
                    .map(|device| {
                        Row::of(
                            device,
                            wakeable.contains(&device.device_id),
                            shell_status(device),
                        )
                    })
                    .collect(),
            },
        }
    }

    /// The section as text, for `--dump-main devices`.
    pub fn lines(&self) -> Vec<String> {
        let mut out = vec!["section devices".to_owned()];
        match &self.fleet {
            Fleet::Unreachable { reason } => out.push(format!("unreachable {reason}")),
            Fleet::Rows { rows } if rows.is_empty() => out.push("empty".to_owned()),
            Fleet::Rows { rows } => {
                for row in rows {
                    out.push(format!(
                        "device {:<20} {:<14} {:<8} path={:<8} self={} wake={} shell={} changed_at={} access={}",
                        row.name,
                        row.short_id,
                        if row.online { "online" } else { "offline" },
                        if row.path.is_empty() { "-" } else { &row.path },
                        yes(row.is_self),
                        yes(row.can_wake()),
                        shell_label(&row.shell.status),
                        row.shell
                            .status
                            .changed_at
                            .map_or_else(|| "-".to_owned(), |at| at.to_string()),
                        match row.shell.access {
                            ShellAccess::LocalOnly => "local_only",
                            ShellAccess::ReadOnly => "read_only",
                        },
                    ));
                }
            }
        }
        out
    }
}

fn shell_statuses(devices: &[DeviceStatus]) -> Vec<ShellPolicyStatus> {
    std::thread::scope(|scope| {
        let probes: Vec<_> = devices
            .iter()
            .map(|device| {
                scope.spawn(move || {
                    if !device.online {
                        return ShellPolicyStatus::unavailable(
                            "device is offline; its shell policy could not be read",
                        );
                    }
                    let target = (!device.is_self).then_some(device.name.as_str());
                    client::device_shell_status(target).unwrap_or_else(|error| {
                        ShellPolicyStatus::unavailable(format!(
                            "device-shell status could not be read: {error:#}"
                        ))
                    })
                })
            })
            .collect();
        probes
            .into_iter()
            .map(|probe| {
                probe.join().unwrap_or_else(|_| {
                    ShellPolicyStatus::unavailable("device-shell status probe died")
                })
            })
            .collect()
    })
}

fn shell_label(status: &ShellPolicyStatus) -> String {
    match status.state {
        ShellPolicyState::Disabled => "disabled".to_owned(),
        ShellPolicyState::EnabledOrbit => "enabled_orbit_members".to_owned(),
        ShellPolicyState::Active => format!("active_{}_sessions", status.active_sessions()),
        ShellPolicyState::Unavailable => "unavailable".to_owned(),
    }
}

fn yes(b: bool) -> &'static str {
    if b {
        "yes"
    } else {
        "no"
    }
}

/// The ids of the peers this orbit could aim a magic packet at.
///
/// A store that will not load is not an error worth showing anywhere: it
/// means no Wake buttons, which is the cautious answer and the same one an
/// orbit that has never paired anything gives.
fn wakeable_ids() -> Vec<String> {
    let Ok(orbit) = Orbit::load(&paths::orbit_path()) else {
        return Vec::new();
    };
    orbit
        .devices()
        .iter()
        .filter(|d| d.wake.wakeable().is_some())
        .map(|d| d.device_id.clone())
        .collect()
}

/// Local GUI mutation seam. It intentionally has no device argument: remote
/// rows and hosted readers can observe policy, but cannot aim a mutation.
pub fn set_shell(enabled: bool) -> Result<Shell> {
    client::set_device_shell(enabled).map(|status| Shell {
        status,
        access: ShellAccess::LocalOnly,
    })
}

// ---- pairing ---------------------------------------------------------------

/// Which half of a pairing this is.
///
/// Two commands, one exchange. The device that invites mints a ticket and
/// waits; the device that adds redeems one. From the six digits onwards they
/// are the same conversation seen from two screens, which is why they share
/// everything below.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Invitation {
    /// Mint a ticket and wait for someone to redeem it.
    Invite { name: Option<String> },
    /// Redeem a ticket printed on another device.
    Add { ticket: String, name: Option<String> },
}

impl Invitation {
    /// The frame that opens the conversation.
    pub fn request(&self) -> Request {
        match self {
            // No ttl: the daemon's own default is the one `ast device
            // invite` uses, and a window inventing a different one would be
            // a second policy.
            Invitation::Invite { name } => {
                Request::DeviceInvite { name: name.clone(), ttl_secs: None }
            }
            Invitation::Add { ticket, name } => {
                Request::DeviceAdd { ticket: ticket.clone(), name: name.clone() }
            }
        }
    }

    /// What this device should call itself, when its hostname will not do.
    ///
    /// The panel never sets this — two machines in one orbit have two
    /// hostnames, and the daemon's default is the right one. A scratch
    /// orbit of two daemons on one machine is the case that needs it, and
    /// `--pair-via-window --as` is how the proof asks for it, through the
    /// same field `ast device invite --name` fills in.
    pub fn named(self, name: Option<String>) -> Invitation {
        match self {
            Invitation::Invite { .. } => Invitation::Invite { name },
            Invitation::Add { ticket, .. } => Invitation::Add { ticket, name },
        }
    }

    /// Read one out of what the window posted: `invite`, or `add:<ticket>`.
    /// Also what `--pair-via-window` takes.
    pub fn parse(spec: &str) -> Option<Invitation> {
        if spec == "invite" {
            return Some(Invitation::Invite { name: None });
        }
        let ticket = spec.strip_prefix("add:")?.trim();
        if ticket.is_empty() {
            return None;
        }
        Some(Invitation::Add { ticket: ticket.to_owned(), name: None })
    }
}

/// Where a pairing has got to, as the panel shows it.
///
/// One state per line the daemon sends, and a `failed` for anything else:
/// an exchange that ends in a frame nobody expected has not paired
/// anything, and saying so beats leaving a spinner up.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum Pairing {
    /// Opened, nothing back yet.
    Waiting,
    /// The pasteable ticket, and how long it stays good for.
    Ticket { ticket: String, expires_in_secs: u64 },
    /// The six digits both screens must show, and who is on the other end.
    Sas { code: String, peer: String },
    Paired { name: String, short_id: String },
    Failed { reason: String },
}

impl Pairing {
    /// Read one frame of the exchange.
    pub fn read(response: &Response) -> Pairing {
        match response {
            Response::Ticket { ticket, expires_in_secs } => Pairing::Ticket {
                ticket: ticket.clone(),
                expires_in_secs: *expires_in_secs,
            },
            Response::Sas { code, peer, .. } => {
                Pairing::Sas { code: code.clone(), peer: peer.clone() }
            }
            Response::Paired { device } => {
                Pairing::Paired { name: device.name.clone(), short_id: device.short_id() }
            }
            Response::Error { message } => Pairing::Failed { reason: message.clone() },
            other => Pairing::Failed { reason: format!("unexpected reply from astd: {other:?}") },
        }
    }

    /// Whether this is the last thing that will happen.
    pub fn is_final(&self) -> bool {
        matches!(self, Pairing::Paired { .. } | Pairing::Failed { .. })
    }

    /// One line, for `--pair-via-window` and for the log.
    pub fn line(&self) -> String {
        match self {
            Pairing::Waiting => "pairing waiting".to_owned(),
            Pairing::Ticket { ticket, expires_in_secs } => {
                format!("pairing ticket {ticket} expires_in={expires_in_secs}s")
            }
            Pairing::Sas { code, peer } => format!("pairing sas {code} peer={peer}"),
            Pairing::Paired { name, short_id } => format!("pairing paired {name} {short_id}"),
            Pairing::Failed { reason } => format!("pairing failed {reason}"),
        }
    }
}

/// The human's verdict on the six digits, asked for however the caller can
/// ask. The window blocks on a channel that its Confirm and Reject buttons
/// send on; `--pair-via-window` answers yes without asking, which is the one
/// thing a script cannot honestly do and so is a hook rather than a default.
pub type Confirm<'a> = &'a (dyn Fn(&str) -> bool + Send + Sync);

/// Run one half of a pairing to its end.
///
/// Nothing is trusted until `confirm` says the codes matched: a `false`
/// sends [`Request::PairConfirm`] with `accept: false`, which is what tells
/// the *other* device to abandon it too.
///
/// `opened` is handed the way to end this from another thread, as soon as
/// there is one. An invite waits for a person at a second machine, so the
/// window's Cancel button has to interrupt a blocking read rather than
/// outlast it.
pub fn pair(
    invitation: &Invitation,
    on_state: &dyn Fn(&Pairing),
    confirm: Confirm,
    opened: &dyn Fn(client::Hangup),
) -> Result<()> {
    let mut conn = Conversation::open(&invitation.request())?;
    opened(conn.hangup()?);
    loop {
        let state = Pairing::read(&conn.next()?);
        on_state(&state);
        if let Pairing::Sas { code, .. } = &state {
            let accept = confirm(code);
            conn.send(&Request::PairConfirm { accept })?;
            if !accept {
                // The daemon tells the other device before it answers us,
                // and what it answers is an error naming the refusal. We
                // already know; do not wait for it.
                bail!("pairing refused — nothing was added to this orbit");
            }
        }
        match state {
            Pairing::Paired { .. } => return Ok(()),
            Pairing::Failed { reason } => bail!("{reason}"),
            // A ticket to show, or a code just answered: keep listening.
            not_yet if !not_yet.is_final() => {}
            ended => bail!("astd ended the pairing at {}", ended.line()),
        }
    }
}

// ---- waking ----------------------------------------------------------------

/// Wake a sleeping device, reporting each line as the daemon sends it.
///
/// A wake is three things worth being told separately — who is going to
/// send the packet, that it went, and whether the machine turned up — with
/// up to a minute between the last two. One line at the end would be a
/// minute of a window saying nothing.
pub fn wake(name: &str, progress: Progress) -> Result<()> {
    let mut conn = Conversation::open(&Request::DeviceWake { name: name.to_owned() })?;
    loop {
        match conn.next()? {
            Response::Wake { text, done } => {
                progress(&text);
                if done {
                    return Ok(());
                }
            }
            Response::Error { message } => bail!(message),
            other => bail!("unexpected reply from astd: {other:?}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use asterism_core::orbit::Device;

    fn shell(state: ShellPolicyState, active: usize) -> ShellPolicyStatus {
        ShellPolicyStatus {
            state,
            epoch: 7,
            changed_at: Some(1_777_777_777),
            enabled_at: Some(1_777_777_700),
            active: (0..active)
                .map(|index| asterism_core::device_shell::ShellSessionStatus {
                    session_id: format!("session-{index}"),
                    peer_device_id: format!("peer-{index}"),
                    peer_name: format!("peer {index}"),
                    started_at: 1_777_777_710 + index as u64,
                    pty: true,
                })
                .collect(),
            unavailable_reason: None,
        }
    }

    fn device(name: &str, online: bool, is_self: bool) -> DeviceStatus {
        DeviceStatus {
            name: name.to_owned(),
            device_id: format!("{name}00000000000000000000000000000000"),
            online,
            path: if online { "direct".to_owned() } else { String::new() },
            rtt_micros: online.then_some(750),
            transition_reason: online.then(|| "stored_address".into()),
            recovery_result: online.then(|| "connected".into()),
            is_self,
        }
    }

    #[test]
    fn a_row_carries_the_identity_as_well_as_the_label() {
        let row = Row::of(
            &device("desktop", true, false),
            false,
            shell(ShellPolicyState::Disabled, 0),
        );
        assert_eq!(row.name, "desktop");
        assert_eq!(row.short_id.chars().count(), 12);
        assert!(row.online && !row.is_self);
        assert_eq!(row.path, "direct");
    }

    /// Wake is offered on exactly one kind of row: a peer that is asleep and
    /// that this orbit knows how to aim a packet at. Anything else is a
    /// button that would do nothing, or wait a minute to find out it did.
    #[test]
    fn wake_is_offered_only_where_it_could_work() {
        let unavailable = || ShellPolicyStatus::unavailable("offline");
        let asleep = Row::of(&device("desktop", false, false), true, unavailable());
        assert!(asleep.can_wake());

        // Awake already.
        assert!(!Row::of(&device("desktop", true, false), true, unavailable()).can_wake());
        // Nothing to aim at.
        assert!(!Row::of(&device("desktop", false, false), false, unavailable()).can_wake());
        // This machine. It is not asleep; it is running this window.
        assert!(!Row::of(&device("laptop", false, true), true, unavailable()).can_wake());
    }

    #[test]
    fn shell_rows_use_one_model_for_all_four_rendered_states() {
        assert_eq!(shell_label(&shell(ShellPolicyState::Disabled, 0)), "disabled");
        assert_eq!(
            shell_label(&shell(ShellPolicyState::EnabledOrbit, 0)),
            "enabled_orbit_members"
        );
        assert_eq!(shell_label(&shell(ShellPolicyState::Active, 3)), "active_3_sessions");
        assert_eq!(
            shell_label(&ShellPolicyStatus::unavailable("old daemon")),
            "unavailable"
        );
    }

    #[test]
    fn only_the_local_row_advertises_mutation_authority() {
        let devices = [device("laptop", true, true), device("desktop", true, false)];
        let model = Devices::of_with(&devices, &[], |_| shell(ShellPolicyState::Disabled, 0));
        let Fleet::Rows { rows } = model.fleet else {
            panic!("expected rows")
        };
        assert_eq!(rows[0].shell.access, ShellAccess::LocalOnly);
        assert_eq!(rows[1].shell.access, ShellAccess::ReadOnly);

        let json = serde_json::to_value(&rows).unwrap();
        assert_eq!(json[0]["shell"]["access"], "local_only");
        assert_eq!(json[1]["shell"]["access"], "read_only");
        assert_eq!(json[0]["shell"]["status"]["changed_at"], 1_777_777_777u64);
    }

    #[test]
    fn dumping_the_section_marks_this_device_and_names_the_path() {
        let devices = [device("laptop", true, true), device("desktop", false, false)];
        let wakeable = vec![devices[1].device_id.clone()];
        let lines = Devices::of(&devices, &wakeable).lines().join("\n");
        assert!(lines.contains("device laptop"), "{lines}");
        assert!(lines.contains("online   path=direct   self=yes wake=no"), "{lines}");
        assert!(lines.contains("offline  path=-        self=no wake=yes"), "{lines}");
    }

    #[test]
    fn an_orbit_of_one_and_an_unreachable_daemon_do_not_look_alike() {
        assert_eq!(Devices::of(&[], &[]).lines(), vec!["section devices", "empty"]);
        let down = Devices { fleet: Fleet::Unreachable { reason: "no socket".into() } };
        assert_eq!(down.lines()[1], "unreachable no socket");
    }

    /// Both halves open with the frame the CLI opens with, field for field.
    /// A window that minted its own ttl would be a second policy about how
    /// long a ticket is good for.
    #[test]
    fn both_halves_send_the_frame_the_cli_sends() {
        let invite = serde_json::to_string(&Invitation::Invite { name: None }.request()).unwrap();
        assert_eq!(invite, r#"{"cmd":"device_invite","name":null,"ttl_secs":null}"#);

        let add = Invitation::Add { ticket: "astdev1abc".into(), name: None };
        assert_eq!(
            serde_json::to_string(&add.request()).unwrap(),
            r#"{"cmd":"device_add","ticket":"astdev1abc","name":null}"#
        );

        // Neither is routed by name: a pairing is about this device.
        assert_eq!(add.request().subject(), None);
        assert_eq!(Invitation::Invite { name: None }.request().subject(), None);
    }

    #[test]
    fn a_pairing_is_asked_for_as_a_word_or_a_ticket() {
        assert_eq!(Invitation::parse("invite"), Some(Invitation::Invite { name: None }));
        assert_eq!(
            Invitation::parse("add:astdev1abc"),
            Some(Invitation::Add { ticket: "astdev1abc".into(), name: None })
        );
        // Whitespace comes with a paste; an empty field is not a ticket.
        assert_eq!(
            Invitation::parse("add:  astdev1abc \n"),
            Some(Invitation::Add { ticket: "astdev1abc".into(), name: None })
        );
        assert_eq!(Invitation::parse("add:"), None);
        assert_eq!(Invitation::parse("add"), None);
        assert_eq!(Invitation::parse("bogus"), None);
    }

    /// The exchange, frame by frame, without a daemon to have it with.
    #[test]
    fn every_line_of_a_pairing_becomes_a_state_the_panel_can_draw() {
        let ticket: Response =
            serde_json::from_str(r#"{"result":"ticket","ticket":"astdev1abc","expires_in_secs":300}"#)
                .unwrap();
        assert_eq!(
            Pairing::read(&ticket),
            Pairing::Ticket { ticket: "astdev1abc".into(), expires_in_secs: 300 }
        );
        assert!(!Pairing::read(&ticket).is_final());

        let sas: Response = serde_json::from_str(
            r#"{"result":"sas","code":"481 902","peer":"desktop","device_id":"ab12"}"#,
        )
        .unwrap();
        assert_eq!(
            Pairing::read(&sas),
            Pairing::Sas { code: "481 902".into(), peer: "desktop".into() }
        );

        let paired = Response::Paired {
            device: Device {
                name: "desktop".into(),
                device_id: "ab12cd34ef56aa".into(),
                addrs: Vec::new(),
                addrs_seen_at: 0,
                relays: Vec::new(),
                added_at: 0,
                wake: Default::default(),
            },
        };
        let state = Pairing::read(&paired);
        assert_eq!(
            state,
            Pairing::Paired { name: "desktop".into(), short_id: "ab12cd34ef56".into() }
        );
        assert!(state.is_final());
    }

    /// A refusal and a frame nobody expected both end the panel, and both
    /// say what happened. A pairing that quietly stopped would leave the
    /// user believing a device had joined.
    #[test]
    fn a_refusal_and_a_surprise_both_end_it_with_a_reason() {
        let refused = Pairing::read(&Response::Error { message: "ticket expired".into() });
        assert_eq!(refused, Pairing::Failed { reason: "ticket expired".into() });
        assert!(refused.is_final());

        let surprise = Pairing::read(&Response::Ok);
        assert!(matches!(surprise, Pairing::Failed { .. }));
        assert!(surprise.line().contains("unexpected reply"));
    }

    #[test]
    fn the_states_reach_the_webview_tagged_by_which_one_they_are() {
        let json = serde_json::to_value(Pairing::Sas {
            code: "481 902".into(),
            peer: "desktop".into(),
        })
        .unwrap();
        assert_eq!(json["state"], serde_json::json!("sas"));
        assert_eq!(json["code"], serde_json::json!("481 902"));

        let waiting = serde_json::to_value(Pairing::Waiting).unwrap();
        assert_eq!(waiting["state"], serde_json::json!("waiting"));
    }

    /// The frame that carries the human's verdict, in both directions. A
    /// window that sent nothing on a Reject would leave the other device
    /// waiting for a person who has already walked away.
    #[test]
    fn a_verdict_is_a_frame_either_way() {
        assert_eq!(
            serde_json::to_string(&Request::PairConfirm { accept: true }).unwrap(),
            r#"{"cmd":"pair_confirm","accept":true}"#
        );
        assert_eq!(
            serde_json::to_string(&Request::PairConfirm { accept: false }).unwrap(),
            r#"{"cmd":"pair_confirm","accept":false}"#
        );
    }

    #[test]
    fn a_wake_is_asked_for_by_device_name_and_not_routed_as_an_instance() {
        let req = Request::DeviceWake { name: "desktop".into() };
        assert_eq!(serde_json::to_string(&req).unwrap(), r#"{"cmd":"device_wake","name":"desktop"}"#);
        assert_eq!(req.subject(), None, "desktop is a device, not an instance");
    }
}
