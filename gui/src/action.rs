//! What pressing a thing means, wherever it was pressed.
//!
//! The tray menu and the main window offer the same verbs on the same
//! instances, so the mapping from an id to a piece of work is written once,
//! here. Every clickable id is `verb` or `verb:argument…`, [`Action::parse`]
//! is the only reader of that form and [`Action::id`] the only writer, and
//! `crate::perform` is the only place that does the work.
//!
//! That is what keeps a second surface from growing a second backend: the
//! window's Up button and the tray's Up item are the same `Action::Up`,
//! reached through the same `--click` hook.
//!
//! ## The three that cannot be undone
//!
//! A restore discards everything written since the snapshot, a snapshot
//! delete throws a checkpoint away, and a removal deletes an instance's
//! disk. Those three carry a [`Action::confirmation`] — the exact tag or
//! name the user has to have typed — and `perform` sends no frame without
//! it. The check is here, in Rust, rather than in the webview: `--click`
//! reaches the same function a button does, and a proof that could remove
//! an instance by omitting an argument would not be proving the button.

use asterism_core::instance::Restart;

/// The project page, opened by the tray's link item and the window's footer.
pub const WEBSITE: &str = "https://asterism.run";

/// What clicking an item means. Ids on the wire are the `verb:rest` form
/// [`Action::parse`] reads; nothing else in the app builds or matches those
/// strings by hand.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    /// Open the main window. The tray item, and ⌘O.
    OpenMain,
    /// Open the New Instance window. Its work happens on the main thread
    /// rather than on a socket (see `crate::window`).
    NewInstance,
    /// Boot an instance. `restart: None` is `ast up` with no flag: keep
    /// whatever policy the instance already has.
    Up { name: String, restart: Option<Restart> },
    Down(String),
    Terminal(String),
    Rename { name: String, new_name: String },
    Remove(String),
    /// Take a snapshot. `tag: None` is the tray's fast path, which names it
    /// after the clock; the window's form sends the name it asked for.
    Snapshot { name: String, tag: Option<String> },
    Restore { name: String, tag: String },
    SnapshotRemove { name: String, tag: String },
    ToggleAutostart,
    /// Hand `astd` to launchd, by running the command that does it.
    ServiceInstall,
    ServiceUninstall,
    Website,
    Quit,
}

impl Action {
    /// The id that produces this action.
    pub fn id(&self) -> String {
        match self {
            Action::OpenMain => "main".to_owned(),
            Action::NewInstance => "new".to_owned(),
            Action::Up { name, restart: None } => format!("up:{name}"),
            Action::Up { name, restart: Some(policy) } => format!("up:{name}:{policy}"),
            Action::Down(name) => format!("down:{name}"),
            Action::Terminal(name) => format!("term:{name}"),
            Action::Rename { name, new_name } => format!("rename:{name}:{new_name}"),
            Action::Remove(name) => format!("rm:{name}"),
            Action::Snapshot { name, tag: None } => format!("snap:{name}"),
            Action::Snapshot { name, tag: Some(tag) } => format!("snap:{name}:{tag}"),
            Action::Restore { name, tag } => format!("restore:{name}:{tag}"),
            Action::SnapshotRemove { name, tag } => format!("snaprm:{name}:{tag}"),
            Action::ToggleAutostart => "autostart".to_owned(),
            Action::ServiceInstall => "service:install".to_owned(),
            Action::ServiceUninstall => "service:uninstall".to_owned(),
            Action::Website => "website".to_owned(),
            Action::Quit => "quit".to_owned(),
        }
    }

    /// Read an id back. `None` for the informational lines, which are
    /// disabled and should never have reached a handler, and for anything
    /// malformed — an unknown restart policy, a segment too many.
    ///
    /// Splitting on `:` is safe both ways round: instance names are
    /// `[a-zA-Z0-9-]` and snapshot tags are those plus `_` and `.`, so
    /// neither can contain the separator.
    pub fn parse(id: &str) -> Option<Action> {
        match id {
            "main" => return Some(Action::OpenMain),
            "new" => return Some(Action::NewInstance),
            "autostart" => return Some(Action::ToggleAutostart),
            "website" => return Some(Action::Website),
            "quit" => return Some(Action::Quit),
            _ => {}
        }
        let (verb, rest) = id.split_once(':')?;
        Some(match verb {
            "up" => match rest.split_once(':') {
                None => Action::Up { name: name(rest)?, restart: None },
                Some((name_part, policy)) => Action::Up {
                    name: name(name_part)?,
                    // An unknown policy is not "the default": it is an id
                    // this app did not write, and it does not boot anything.
                    restart: Some(policy.parse().ok()?),
                },
            },
            "down" => Action::Down(name(rest)?),
            "term" => Action::Terminal(name(rest)?),
            "rm" => Action::Remove(name(rest)?),
            "rename" => {
                let (name_part, new_name) = rest.split_once(':')?;
                Action::Rename { name: name(name_part)?, new_name: name(new_name)? }
            }
            "snap" => match rest.split_once(':') {
                None => Action::Snapshot { name: name(rest)?, tag: None },
                Some((name_part, tag)) => {
                    Action::Snapshot { name: name(name_part)?, tag: Some(name(tag)?) }
                }
            },
            "restore" => {
                let (name_part, tag) = rest.split_once(':')?;
                Action::Restore { name: name(name_part)?, tag: name(tag)? }
            }
            "snaprm" => {
                let (name_part, tag) = rest.split_once(':')?;
                Action::SnapshotRemove { name: name(name_part)?, tag: name(tag)? }
            }
            "service" => match rest {
                "install" => Action::ServiceInstall,
                "uninstall" => Action::ServiceUninstall,
                _ => return None,
            },
            _ => return None,
        })
    }

    /// The exact word the user has to have typed for this to happen, or
    /// `None` for the actions that need no typing.
    ///
    /// A snapshot's identity is its tag and an instance's is its name, so
    /// that is what each asks for. Case-sensitive and exact: matching is the
    /// safety property, and a fuzzy match is not one.
    pub fn confirmation(&self) -> Option<&str> {
        match self {
            Action::Restore { tag, .. } | Action::SnapshotRemove { tag, .. } => Some(tag),
            Action::Remove(name) => Some(name),
            _ => None,
        }
    }

    /// The instance this action is about, for the one-at-a-time rule. Two
    /// GUI mutations of one instance in flight together is a race the daemon
    /// should never be asked to arbitrate.
    pub fn subject(&self) -> Option<&str> {
        match self {
            Action::Up { name, .. }
            | Action::Down(name)
            | Action::Terminal(name)
            | Action::Rename { name, .. }
            | Action::Remove(name)
            | Action::Snapshot { name, .. }
            | Action::Restore { name, .. }
            | Action::SnapshotRemove { name, .. } => Some(name),
            _ => None,
        }
    }

    /// Whether this one changes something the daemon holds. The reads and
    /// the window openers do not queue behind anything.
    pub fn mutates(&self) -> bool {
        matches!(
            self,
            Action::Up { .. }
                | Action::Down(_)
                | Action::Rename { .. }
                | Action::Remove(_)
                | Action::Snapshot { .. }
                | Action::Restore { .. }
                | Action::SnapshotRemove { .. }
        )
    }

    /// What the log and the failure notification call this.
    pub fn describe(&self) -> String {
        match self {
            Action::OpenMain => "opening the Asterism window".to_owned(),
            Action::NewInstance => "opening the New Instance window".to_owned(),
            Action::Up { name, restart: None } => format!("starting {name}"),
            Action::Up { name, restart: Some(Restart::Always) } => {
                format!("starting {name} and keeping it running")
            }
            Action::Up { name, restart: Some(Restart::Never) } => format!("starting {name} once"),
            Action::Down(name) => format!("stopping {name}"),
            Action::Terminal(name) => format!("opening a terminal on {name}"),
            Action::Rename { name, new_name } => format!("renaming {name} to {new_name}"),
            Action::Remove(name) => format!("removing {name}"),
            Action::Snapshot { name, tag: None } => format!("snapshotting {name}"),
            Action::Snapshot { name, tag: Some(tag) } => format!("snapshotting {name} as {tag}"),
            Action::Restore { name, tag } => format!("restoring {name} to {tag}"),
            Action::SnapshotRemove { name, tag } => format!("deleting {name}'s snapshot {tag}"),
            Action::ToggleAutostart => "changing start at login".to_owned(),
            Action::ServiceInstall => "installing the astd service".to_owned(),
            Action::ServiceUninstall => "removing the astd service".to_owned(),
            Action::Website => format!("opening {WEBSITE}"),
            Action::Quit => "quitting".to_owned(),
        }
    }

    /// The present-tense word the window puts on the row while this is in
    /// flight. `None` for the actions that are over before a frame is drawn.
    pub fn verb(&self) -> Option<&'static str> {
        Some(match self {
            Action::Up { .. } => "Starting",
            Action::Down(_) => "Stopping",
            Action::Rename { .. } => "Renaming",
            Action::Remove(_) => "Removing",
            Action::Snapshot { .. } => "Snapshotting",
            Action::Restore { .. } => "Restoring",
            Action::SnapshotRemove { .. } => "Deleting snapshot",
            _ => return None,
        })
    }

    /// Whether this one opens a window, and therefore has to be done on the
    /// main thread and leaves something on screen when it returns.
    pub fn opens_a_window(&self) -> bool {
        matches!(self, Action::OpenMain | Action::NewInstance)
    }
}

/// One segment of an id, refused when it is empty or carries a separator
/// the split would have eaten. An empty name is not a name, and neither
/// `up::always` nor `rename:dev:` is an id this app wrote.
fn name(segment: &str) -> Option<String> {
    if segment.is_empty() || segment.contains(':') {
        return None;
    }
    Some(segment.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all() -> Vec<Action> {
        vec![
            Action::OpenMain,
            Action::NewInstance,
            Action::Up { name: "dev".into(), restart: None },
            Action::Up { name: "dev".into(), restart: Some(Restart::Always) },
            Action::Up { name: "dev".into(), restart: Some(Restart::Never) },
            Action::Down("dev".into()),
            Action::Terminal("dev".into()),
            Action::Rename { name: "dev".into(), new_name: "prod".into() },
            Action::Remove("dev".into()),
            Action::Snapshot { name: "dev".into(), tag: None },
            Action::Snapshot { name: "dev".into(), tag: Some("v1.2_a".into()) },
            Action::Restore { name: "dev".into(), tag: "v1.2_a".into() },
            Action::SnapshotRemove { name: "dev".into(), tag: "v1.2_a".into() },
            Action::ToggleAutostart,
            Action::ServiceInstall,
            Action::ServiceUninstall,
            Action::Website,
            Action::Quit,
        ]
    }

    /// Every action's id has to survive the round trip, because the id is
    /// what crosses the menu, the webview and `--click`.
    #[test]
    fn every_action_round_trips_through_its_id() {
        for action in all() {
            let id = action.id();
            assert_eq!(Action::parse(&id).as_ref(), Some(&action), "{id}");
            assert!(!action.describe().is_empty(), "{id} has nothing to say");
        }
    }

    /// The ids are an interface — the tray writes them, the webview writes
    /// them, and `--click` takes them off a command line — so they are
    /// pinned rather than left to whatever `id()` happens to produce.
    #[test]
    fn the_ids_are_the_exact_forms_the_contract_names() {
        let ids: Vec<String> = all().iter().map(Action::id).collect();
        assert!(ids.contains(&"up:dev".to_owned()));
        assert!(ids.contains(&"up:dev:always".to_owned()));
        assert!(ids.contains(&"up:dev:never".to_owned()));
        assert!(ids.contains(&"down:dev".to_owned()));
        assert!(ids.contains(&"rename:dev:prod".to_owned()));
        assert!(ids.contains(&"rm:dev".to_owned()));
        assert!(ids.contains(&"snap:dev".to_owned()));
        assert!(ids.contains(&"snap:dev:v1.2_a".to_owned()));
        assert!(ids.contains(&"restore:dev:v1.2_a".to_owned()));
        assert!(ids.contains(&"snaprm:dev:v1.2_a".to_owned()));
    }

    #[test]
    fn unknown_ids_are_not_actions() {
        assert_eq!(Action::parse("new:dev"), None, "the window takes no argument");
        assert_eq!(Action::parse("info:version"), None);
        assert_eq!(Action::parse("bogus"), None);
        assert_eq!(Action::parse("restore:dev"), None, "a restore needs a tag");
        assert_eq!(Action::parse("snaprm:dev"), None, "a delete needs a tag");
        assert_eq!(Action::parse("rename:dev"), None, "a rename needs a new name");
        assert_eq!(Action::parse("service:enable"), None, "install or uninstall, nothing else");
    }

    /// A policy segment this app did not write does not boot something on
    /// the default. `up:dev:sometimes` is an id from nowhere, and an
    /// unrecognised argument silently meaning "keep whatever it had" is how
    /// a typo becomes a policy change.
    #[test]
    fn a_restart_policy_is_always_or_never_and_nothing_else() {
        assert_eq!(
            Action::parse("up:dev:always"),
            Some(Action::Up { name: "dev".into(), restart: Some(Restart::Always) })
        );
        assert_eq!(Action::parse("up:dev:sometimes"), None);
        assert_eq!(Action::parse("up:dev:Always"), None, "the daemon's spelling, exactly");
        assert_eq!(Action::parse("up:dev:always:extra"), None, "one segment too many");
    }

    /// An empty segment is not a name and not a tag. `rm:` must not parse
    /// into a removal of the instance called "".
    #[test]
    fn empty_segments_are_refused_everywhere() {
        for id in ["up:", "down:", "rm:", "term:", "snap:", "snap:dev:", "rename::prod",
                   "rename:dev:", "restore:dev:", "restore::v1", "snaprm:dev:"] {
            assert_eq!(Action::parse(id), None, "{id:?} parsed");
        }
    }

    /// The three that cannot be undone ask for the thing's own name, and
    /// nothing else asks for anything.
    #[test]
    fn only_the_irreversible_three_want_a_typed_word() {
        assert_eq!(
            Action::Restore { name: "dev".into(), tag: "t1".into() }.confirmation(),
            Some("t1")
        );
        assert_eq!(
            Action::SnapshotRemove { name: "dev".into(), tag: "t1".into() }.confirmation(),
            Some("t1")
        );
        assert_eq!(Action::Remove("dev".into()).confirmation(), Some("dev"));

        for action in all() {
            let wanted = action.confirmation().is_some();
            let irreversible = matches!(
                action,
                Action::Restore { .. } | Action::SnapshotRemove { .. } | Action::Remove(_)
            );
            assert_eq!(wanted, irreversible, "{}", action.id());
        }
    }

    /// Everything that changes the daemon's mind names the instance it is
    /// about, so two of them on one instance can be kept apart.
    #[test]
    fn every_mutation_names_its_instance() {
        for action in all() {
            if action.mutates() {
                assert!(action.subject().is_some(), "{} mutates but names nobody", action.id());
                assert!(action.verb().is_some(), "{} has no present tense", action.id());
            }
        }
        // Opening a terminal is not a mutation; it is still about an
        // instance, and still worth not doing twice at once.
        assert!(!Action::Terminal("dev".into()).mutates());
        assert_eq!(Action::Terminal("dev".into()).subject(), Some("dev"));
        assert!(!Action::Website.mutates() && Action::Website.subject().is_none());
    }

    /// The two that leave something on screen are the two that have to be
    /// run on the main thread and must not exit the app afterwards.
    #[test]
    fn only_the_window_openers_leave_something_behind() {
        assert!(Action::OpenMain.opens_a_window());
        assert!(Action::NewInstance.opens_a_window());
        assert!(!Action::Up { name: "dev".into(), restart: None }.opens_a_window());
        assert!(!Action::ServiceInstall.opens_a_window());
    }
}
