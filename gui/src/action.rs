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
    Up(String),
    Down(String),
    Terminal(String),
    Snapshot(String),
    Restore { name: String, tag: String },
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
            Action::Up(name) => format!("up:{name}"),
            Action::Down(name) => format!("down:{name}"),
            Action::Terminal(name) => format!("term:{name}"),
            Action::Snapshot(name) => format!("snap:{name}"),
            Action::Restore { name, tag } => format!("restore:{name}:{tag}"),
            Action::ToggleAutostart => "autostart".to_owned(),
            Action::ServiceInstall => "service:install".to_owned(),
            Action::ServiceUninstall => "service:uninstall".to_owned(),
            Action::Website => "website".to_owned(),
            Action::Quit => "quit".to_owned(),
        }
    }

    /// Read an id back. `None` for the informational lines, which are
    /// disabled and should never have reached a handler.
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
            "up" => Action::Up(rest.to_owned()),
            "down" => Action::Down(rest.to_owned()),
            "term" => Action::Terminal(rest.to_owned()),
            "snap" => Action::Snapshot(rest.to_owned()),
            "service" => match rest {
                "install" => Action::ServiceInstall,
                "uninstall" => Action::ServiceUninstall,
                _ => return None,
            },
            "restore" => {
                let (name, tag) = rest.split_once(':')?;
                Action::Restore { name: name.to_owned(), tag: tag.to_owned() }
            }
            _ => return None,
        })
    }

    /// What the log and the failure notification call this.
    pub fn describe(&self) -> String {
        match self {
            Action::OpenMain => "opening the Asterism window".to_owned(),
            Action::NewInstance => "opening the New Instance window".to_owned(),
            Action::Up(name) => format!("starting {name}"),
            Action::Down(name) => format!("stopping {name}"),
            Action::Terminal(name) => format!("opening a terminal on {name}"),
            Action::Snapshot(name) => format!("snapshotting {name}"),
            Action::Restore { name, tag } => format!("restoring {name} to {tag}"),
            Action::ToggleAutostart => "changing start at login".to_owned(),
            Action::ServiceInstall => "installing the astd service".to_owned(),
            Action::ServiceUninstall => "removing the astd service".to_owned(),
            Action::Website => format!("opening {WEBSITE}"),
            Action::Quit => "quitting".to_owned(),
        }
    }

    /// Whether this one opens a window, and therefore has to be done on the
    /// main thread and leaves something on screen when it returns.
    pub fn opens_a_window(&self) -> bool {
        matches!(self, Action::OpenMain | Action::NewInstance)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every action's id has to survive the round trip, because the id is
    /// what crosses the menu, the webview and `--click`.
    #[test]
    fn every_action_round_trips_through_its_id() {
        let all = [
            Action::OpenMain,
            Action::NewInstance,
            Action::Up("dev".into()),
            Action::Down("dev".into()),
            Action::Terminal("dev".into()),
            Action::Snapshot("dev".into()),
            Action::Restore { name: "dev".into(), tag: "v1.2_a".into() },
            Action::ToggleAutostart,
            Action::ServiceInstall,
            Action::ServiceUninstall,
            Action::Website,
            Action::Quit,
        ];
        for action in all {
            let id = action.id();
            assert_eq!(Action::parse(&id).as_ref(), Some(&action), "{id}");
            assert!(!action.describe().is_empty(), "{id} has nothing to say");
        }
    }

    #[test]
    fn unknown_ids_are_not_actions() {
        assert_eq!(Action::parse("new:dev"), None, "the window takes no argument");
        assert_eq!(Action::parse("info:version"), None);
        assert_eq!(Action::parse("bogus"), None);
        assert_eq!(Action::parse("restore:dev"), None, "a restore needs a tag");
        assert_eq!(Action::parse("service:enable"), None, "install or uninstall, nothing else");
    }

    /// The two that leave something on screen are the two that have to be
    /// run on the main thread and must not exit the app afterwards.
    #[test]
    fn only_the_window_openers_leave_something_behind() {
        assert!(Action::OpenMain.opens_a_window());
        assert!(Action::NewInstance.opens_a_window());
        assert!(!Action::Up("dev".into()).opens_a_window());
        assert!(!Action::ServiceInstall.opens_a_window());
    }
}
