//! The tray menu: what it should say, and how to say it to Tauri.
//!
//! [`MenuModel`] is the whole menu as plain data. It is what the poll loop
//! compares against the menu on screen (rebuilding only on a real change,
//! so an open menu is not yanked out from under the pointer every three
//! seconds), what the tests assert on, and what `--dump-menu` prints.
//! [`build`] turns it into a real `Menu`, and is the only part that needs
//! a running app.
//!
//! Every clickable item's id is `verb:argument…`, and [`Action`] is the
//! only place that mapping is written down — the menu cannot grow an item
//! that nothing handles, or a handler for an item nobody can click. The
//! window's buttons carry the same ids to the same handler, so an item here
//! and a button there are one piece of work.

use tauri::menu::{CheckMenuItemBuilder, Menu, MenuBuilder, MenuItemBuilder, SubmenuBuilder};
use tauri::AppHandle;

use asterism_core::instance::{Instance, Status};

use crate::client::{self, Tags};
use crate::instances::Gates;

pub use crate::action::{Action, WEBSITE};

/// Longest daemon error we are willing to put in a menu item.
const REASON_WIDTH: usize = 60;
/// The item that opens the window the fleet lives in. First, because it is
/// what somebody who came to the menu bar to *look* at something wants.
const OPEN_MAIN: &str = "Open Asterism";
/// The item that opens the window that asks a question. The ellipsis is the
/// macOS convention for exactly that.
const NEW_INSTANCE: &str = "New Instance…";

/// One instance, as the menu sees it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Row {
    pub name: String,
    pub status: Status,
    /// What this instance will answer. Resolved by [`Gates`], which is also
    /// where the window's table reads them: a menu and a table that
    /// disagreed about when a snapshot is allowed would be two products.
    ///
    /// The menu lists this device's own shard, so `live` is true — but an
    /// instance in conflict or mid-move is still a thing this device holds,
    /// and the daemon refuses most of what a menu offers on one.
    pub gates: Gates,
    /// The tags on its disk, or why we could not list them. Kept as a
    /// `Result` because "no snapshots" and "we could not look" are
    /// different things to tell somebody.
    pub snapshots: Tags,
}

impl Row {
    pub fn of(instance: &Instance, snapshots: Tags) -> Self {
        Row {
            name: instance.name.clone(),
            status: instance.status,
            gates: Gates::of(instance, true),
            snapshots,
        }
    }

    /// A filled circle is a guest that is up, an empty one a disk that
    /// could be, a dotted one an instance that has never booted.
    fn glyph(&self) -> char {
        match self.status {
            Status::Running => '●',
            Status::Stopped => '○',
            Status::Defined => '◌',
        }
    }

    /// Title of the instance's submenu.
    fn title(&self) -> String {
        format!("{}  {}  —  {}", self.glyph(), self.name, self.status)
    }
}

/// What the daemon has to say, which is most of the menu.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Fleet {
    /// Before the first poll answers.
    Loading,
    /// The daemon could not be reached, with the reason.
    Unreachable(String),
    /// What the daemon says it has; may be empty.
    Instances(Vec<Row>),
}

/// The menu, whole. The fleet is the daemon's business; `autostart` is the
/// app's own, and lives here so that the poll loop's "has anything
/// changed?" comparison covers the check mark too.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MenuModel {
    pub fleet: Fleet,
    pub autostart: bool,
}

impl MenuModel {
    /// The menu shown before the first poll comes back.
    pub fn loading(autostart: bool) -> Self {
        MenuModel { fleet: Fleet::Loading, autostart }
    }

    /// Ask the daemon. Any failure becomes [`Fleet::Unreachable`] — there
    /// is no error path out of here, because a menu bar app that dies when
    /// its daemon hiccups is worse than useless.
    pub fn from_daemon(autostart: bool) -> Self {
        let fleet = match client::list() {
            Ok(instances) => {
                let names: Vec<String> = instances.iter().map(|i| i.name.clone()).collect();
                let mut tags = client::snapshot_tags(&names);
                let rows = instances
                    .iter()
                    .map(|i| {
                        let snapshots = tags
                            .remove(&i.name)
                            .unwrap_or_else(|| Err("not listed yet".to_owned()));
                        Row::of(i, snapshots)
                    })
                    .collect();
                Fleet::Instances(rows)
            }
            Err(e) => Fleet::Unreachable(format!("{e:#}")),
        };
        MenuModel { fleet, autostart }
    }

    /// The menu as text, one line per item, in order, two spaces of indent
    /// per level of submenu. Written for the log and for tests; it is
    /// generated from the same data [`build`] uses, so it cannot describe
    /// a menu other than the one on screen.
    pub fn lines(&self) -> Vec<String> {
        let mut out = vec![
            item(0, &Action::OpenMain, OPEN_MAIN, true),
            item(0, &Action::NewInstance, NEW_INSTANCE, true),
            "[separator]".to_owned(),
        ];
        match &self.fleet {
            Fleet::Loading => out.push("[disabled] checking astd…".to_owned()),
            Fleet::Unreachable(reason) => {
                out.push("[disabled] daemon unreachable".to_owned());
                out.push(format!("[disabled]   {}", ellipsize(reason, REASON_WIDTH)));
            }
            Fleet::Instances(rows) if rows.is_empty() => {
                out.push("[disabled] no instances yet".to_owned());
            }
            Fleet::Instances(rows) => {
                for row in rows {
                    let name = &row.name;
                    let disk = row.gates.can_snapshot;
                    out.push(format!("[submenu] {}", row.title()));
                    let up = Action::Up { name: name.clone(), restart: None };
                    out.push(item(1, &up, "Up", row.gates.can_start));
                    out.push(item(1, &Action::Down(name.clone()), "Down", row.gates.can_stop));
                    out.push(item(
                        1,
                        &Action::Terminal(name.clone()),
                        "Open Terminal",
                        row.gates.can_shell,
                    ));
                    out.push("  [submenu] Snapshots".to_owned());
                    let take = Action::Snapshot { name: name.clone(), tag: None };
                    out.push(item(2, &take, "Take snapshot", disk));
                    out.push("    [separator]".to_owned());
                    match &row.snapshots {
                        Err(reason) => out.push(format!(
                            "    [disabled] snapshots unavailable — {}",
                            ellipsize(reason, REASON_WIDTH)
                        )),
                        Ok(tags) if tags.is_empty() => {
                            out.push("    [disabled] no snapshots yet".to_owned());
                        }
                        Ok(tags) => {
                            for tag in tags {
                                let action =
                                    Action::Restore { name: name.clone(), tag: tag.clone() };
                                out.push(item(2, &action, &format!("Restore {tag}…"), disk));
                            }
                        }
                    }
                    out.push("  [separator]".to_owned());
                    out.push(item(
                        1,
                        &Action::Remove(name.clone()),
                        "Remove…",
                        row.gates.can_remove,
                    ));
                }
            }
        }
        out.push("[separator]".to_owned());
        out.push(format!(
            "{}  {}",
            item(0, &Action::ToggleAutostart, "Start at Login", true),
            if self.autostart { "[x]" } else { "[ ]" }
        ));
        out.push(item(0, &Action::Website, "Open asterism.run", true));
        out.push("[separator]".to_owned());
        out.push(item(0, &Action::Quit, "Quit Asterism", true));
        out.push(format!("[disabled] {}", version()));
        out
    }
}

/// Build the real menu. Must run on the main thread on macOS.
pub fn build(app: &AppHandle, model: &MenuModel) -> tauri::Result<Menu<tauri::Wry>> {
    let open = MenuItemBuilder::with_id(Action::OpenMain.id(), OPEN_MAIN)
        .accelerator("CmdOrCtrl+O")
        .build(app)?;
    let new = MenuItemBuilder::with_id(Action::NewInstance.id(), NEW_INSTANCE)
        .accelerator("CmdOrCtrl+N")
        .build(app)?;
    let mut menu = MenuBuilder::new(app).item(&open).item(&new).separator();
    match &model.fleet {
        Fleet::Loading => menu = menu.item(&disabled(app, "loading", "checking astd…")?),
        Fleet::Unreachable(reason) => {
            menu = menu.item(&disabled(app, "unreachable", "daemon unreachable")?);
            let reason = format!("  {}", ellipsize(reason, REASON_WIDTH));
            menu = menu.item(&disabled(app, "unreachable-why", &reason)?);
        }
        Fleet::Instances(rows) if rows.is_empty() => {
            menu = menu.item(&disabled(app, "empty", "no instances yet")?);
        }
        Fleet::Instances(rows) => {
            for row in rows {
                menu = menu.item(&instance_submenu(app, row)?);
            }
        }
    }
    let autostart = CheckMenuItemBuilder::with_id(Action::ToggleAutostart.id(), "Start at Login")
        .checked(model.autostart)
        .build(app)?;
    let website = clickable(app, &Action::Website, "Open asterism.run", true)?;
    let quit = MenuItemBuilder::with_id(Action::Quit.id(), "Quit Asterism")
        .accelerator("CmdOrCtrl+Q")
        .build(app)?;
    menu.separator()
        .item(&autostart)
        .item(&website)
        .separator()
        .item(&quit)
        .item(&disabled(app, "version", &version())?)
        .build()
}

fn instance_submenu(app: &AppHandle, row: &Row) -> tauri::Result<tauri::menu::Submenu<tauri::Wry>> {
    let name = &row.name;
    let disk = row.gates.can_snapshot;
    let up = Action::Up { name: name.clone(), restart: None };
    let up = clickable(app, &up, "Up", row.gates.can_start)?;
    let down = clickable(app, &Action::Down(name.clone()), "Down", row.gates.can_stop)?;
    let term =
        clickable(app, &Action::Terminal(name.clone()), "Open Terminal", row.gates.can_shell)?;
    // Removing is a typed confirmation, which a menu cannot ask for. The
    // item opens the window on this instance with the dialog up; the ellipsis
    // is the macOS convention for exactly that, and so is the separator that
    // keeps it away from the verbs that just happen.
    let remove = clickable(app, &Action::Remove(name.clone()), "Remove…", row.gates.can_remove)?;

    let take = Action::Snapshot { name: name.clone(), tag: None };
    let take = clickable(app, &take, "Take snapshot", disk)?;
    let mut snapshots = SubmenuBuilder::new(app, "Snapshots").item(&take).separator();
    match &row.snapshots {
        Err(reason) => {
            let text = format!("snapshots unavailable — {}", ellipsize(reason, REASON_WIDTH));
            snapshots = snapshots.item(&disabled(app, &format!("{name}-snapshots"), &text)?);
        }
        Ok(tags) if tags.is_empty() => {
            let id = format!("{name}-snapshots");
            snapshots = snapshots.item(&disabled(app, &id, "no snapshots yet")?);
        }
        Ok(tags) => {
            for tag in tags {
                let action = Action::Restore { name: name.clone(), tag: tag.clone() };
                let item = clickable(app, &action, &format!("Restore {tag}…"), disk)?;
                snapshots = snapshots.item(&item);
            }
        }
    }

    SubmenuBuilder::new(app, row.title())
        .item(&up)
        .item(&down)
        .item(&term)
        .item(&snapshots.build()?)
        .separator()
        .item(&remove)
        .build()
}

fn clickable(
    app: &AppHandle,
    action: &Action,
    text: &str,
    enabled: bool,
) -> tauri::Result<tauri::menu::MenuItem<tauri::Wry>> {
    MenuItemBuilder::with_id(action.id(), text)
        .enabled(enabled)
        .build(app)
}

/// A line that only informs. Tauri keys items by id and a menu may hold
/// several of these, so each caller names its own.
fn disabled(
    app: &AppHandle,
    id: &str,
    text: &str,
) -> tauri::Result<tauri::menu::MenuItem<tauri::Wry>> {
    MenuItemBuilder::with_id(format!("info:{id}"), text)
        .enabled(false)
        .build(app)
}

/// One line of [`MenuModel::lines`] for a clickable item.
fn item(depth: usize, action: &Action, text: &str, enabled: bool) -> String {
    format!(
        "{}[{}] {text}  {}",
        "  ".repeat(depth),
        action.id(),
        if enabled { "(enabled)" } else { "(disabled)" }
    )
}

fn version() -> String {
    format!("Asterism {}", env!("CARGO_PKG_VERSION"))
}

/// Daemon errors are context-chained and can run long; a menu item is not
/// the place to discover that.
fn ellipsize(s: &str, width: usize) -> String {
    let s = s.replace('\n', " ");
    if s.chars().count() <= width {
        return s;
    }
    let head: String = s.chars().take(width.saturating_sub(1)).collect();
    format!("{head}…")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn machine() -> asterism_core::hv::Machine {
        asterism_core::hv::Machine {
            backend: "qemu".into(),
            machine_type: "virt".into(),
            cpu: "host".into(),
            hv_version: "test".into(),
        }
    }

    fn instance(name: &str, status: Status) -> Instance {
        let mut instance =
            Instance::new(name, "test", "debian:13", Default::default(), machine());
        instance.status = status;
        instance
    }

    fn row(name: &str, status: Status, snapshots: Tags) -> Row {
        Row::of(&instance(name, status), snapshots)
    }

    fn fleet(rows: Vec<Row>) -> MenuModel {
        MenuModel { fleet: Fleet::Instances(rows), autostart: false }
    }

    /// The fixed items every menu opens with.
    fn head() -> Vec<String> {
        vec![
            "[main] Open Asterism  (enabled)".to_owned(),
            "[new] New Instance…  (enabled)".to_owned(),
            "[separator]".to_owned(),
        ]
    }

    /// The fixed items every menu ends with, so the per-instance tests can
    /// assert on a whole menu without restating them.
    fn tail(autostart: bool) -> Vec<String> {
        vec![
            "[separator]".to_owned(),
            format!(
                "[autostart] Start at Login  (enabled)  {}",
                if autostart { "[x]" } else { "[ ]" }
            ),
            "[website] Open asterism.run  (enabled)".to_owned(),
            "[separator]".to_owned(),
            "[quit] Quit Asterism  (enabled)".to_owned(),
            format!("[disabled] Asterism {}", env!("CARGO_PKG_VERSION")),
        ]
    }

    #[test]
    fn a_running_instance_can_be_stopped_and_shelled_into_but_not_snapshotted() {
        let model = fleet(vec![row("dev", Status::Running, Ok(vec!["nightly".into()]))]);
        let mut want = head();
        want.extend([
            "[submenu] ●  dev  —  running".to_owned(),
            "  [up:dev] Up  (disabled)".to_owned(),
            "  [down:dev] Down  (enabled)".to_owned(),
            "  [term:dev] Open Terminal  (enabled)".to_owned(),
            "  [submenu] Snapshots".to_owned(),
            "    [snap:dev] Take snapshot  (disabled)".to_owned(),
            "    [separator]".to_owned(),
            "    [restore:dev:nightly] Restore nightly…  (disabled)".to_owned(),
            "  [separator]".to_owned(),
            "  [rm:dev] Remove…  (disabled)".to_owned(),
        ]);
        want.extend(tail(false));
        assert_eq!(model.lines(), want);
    }

    #[test]
    fn a_stopped_instance_can_be_started_and_snapshotted_but_not_shelled_into() {
        let model = fleet(vec![row("dev", Status::Stopped, Ok(vec!["nightly".into()]))]);
        let mut want = head();
        want.extend([
            "[submenu] ○  dev  —  stopped".to_owned(),
            "  [up:dev] Up  (enabled)".to_owned(),
            "  [down:dev] Down  (disabled)".to_owned(),
            "  [term:dev] Open Terminal  (disabled)".to_owned(),
            "  [submenu] Snapshots".to_owned(),
            "    [snap:dev] Take snapshot  (enabled)".to_owned(),
            "    [separator]".to_owned(),
            "    [restore:dev:nightly] Restore nightly…  (enabled)".to_owned(),
            "  [separator]".to_owned(),
            "  [rm:dev] Remove…  (enabled)".to_owned(),
        ]);
        want.extend(tail(false));
        assert_eq!(model.lines(), want);
    }

    /// Removing is offered from the menu, but a menu click never does it:
    /// it opens the window on the instance with the typed confirmation up.
    /// The same holds for every Restore item.
    #[test]
    fn the_menus_destructive_items_are_routes_and_not_work() {
        for id in ["rm:dev", "restore:dev:nightly"] {
            let action = Action::parse(id).expect("an action");
            assert!(action.confirmation().is_some(), "{id} would mutate from a menu click");
            assert!(crate::mainwindow::Route::of(&action).is_some(), "{id} has nowhere to go");
        }
        // Everything else in an instance submenu just happens.
        for id in ["up:dev", "down:dev", "term:dev", "snap:dev"] {
            let action = Action::parse(id).expect("an action");
            assert!(action.confirmation().is_none(), "{id} would need a dialog");
            assert!(crate::mainwindow::Route::of(&action).is_none(), "{id} is not a route");
        }
    }

    /// The daemon refuses `Snapshot` and `SnapshotRestore` on anything
    /// running and nothing else, so the menu must gate on exactly that —
    /// a never-booted instance included.
    #[test]
    fn snapshot_actions_follow_the_daemons_rule_and_not_a_narrower_one() {
        for status in [Status::Stopped, Status::Defined] {
            let model = fleet(vec![row("dev", status, Ok(vec!["nightly".into()]))]);
            let lines = model.lines().join("\n");
            assert!(
                lines.contains("[snap:dev] Take snapshot  (enabled)"),
                "{status} must offer a snapshot:\n{lines}"
            );
            assert!(
                lines.contains("[restore:dev:nightly] Restore nightly…  (enabled)"),
                "{status} must offer a restore:\n{lines}"
            );
        }
    }

    #[test]
    fn statuses_have_their_own_glyph() {
        let glyphs: Vec<char> = [Status::Running, Status::Stopped, Status::Defined]
            .into_iter()
            .map(|s| row("dev", s, Ok(vec![])).glyph())
            .collect();
        assert_eq!(glyphs, ['●', '○', '◌']);
    }

    #[test]
    fn an_instance_without_snapshots_says_so_rather_than_showing_nothing() {
        let model = fleet(vec![row("dev", Status::Stopped, Ok(vec![]))]);
        let lines = model.lines();
        assert!(lines.contains(&"    [disabled] no snapshots yet".to_owned()), "{lines:?}");
    }

    /// An empty list and a failed listing must not look the same: the
    /// first invites you to take one, the second is a bug to chase.
    #[test]
    fn a_failed_listing_is_not_an_empty_one() {
        let model = fleet(vec![row("dev", Status::Stopped, Err("qemu-img not found".into()))]);
        let lines = model.lines().join("\n");
        assert!(lines.contains("snapshots unavailable — qemu-img not found"), "{lines}");
        assert!(!lines.contains("no snapshots yet"), "{lines}");
        // Taking a first one is still offered; the daemon may manage it.
        assert!(lines.contains("[snap:dev] Take snapshot  (enabled)"), "{lines}");
    }

    #[test]
    fn a_long_listing_error_is_cut_to_fit() {
        let model = fleet(vec![row("dev", Status::Stopped, Err("x".repeat(400)))]);
        let line = model
            .lines()
            .into_iter()
            .find(|l| l.contains("snapshots unavailable"))
            .expect("the failure is shown");
        let reason = line.rsplit("— ").next().unwrap();
        assert_eq!(reason.chars().count(), REASON_WIDTH, "{line}");
        assert!(reason.ends_with('…'));
    }

    #[test]
    fn several_instances_each_get_their_own_ids() {
        let model = fleet(vec![
            row("dev", Status::Running, Ok(vec![])),
            row("build", Status::Stopped, Ok(vec!["v1".into()])),
        ]);
        let lines = model.lines().join("\n");
        assert!(lines.contains("[up:dev]") && lines.contains("[up:build]"));
        assert!(lines.contains("[rm:dev]") && lines.contains("[rm:build]"));
        assert!(lines.contains("[restore:build:v1]"));
        assert!(!lines.contains("[restore:dev:"), "dev has no snapshots to restore");
    }

    #[test]
    fn start_at_login_shows_its_state() {
        let mut model = fleet(vec![]);
        assert!(model.lines().contains(&"[autostart] Start at Login  (enabled)  [ ]".to_owned()));
        model.autostart = true;
        assert!(model.lines().contains(&"[autostart] Start at Login  (enabled)  [x]".to_owned()));
    }

    /// The check mark is part of the model precisely so that toggling it
    /// counts as a change worth rebuilding for.
    #[test]
    fn toggling_start_at_login_changes_the_model() {
        let off = fleet(vec![]);
        let mut on = off.clone();
        on.autostart = true;
        assert_ne!(off, on);
    }

    #[test]
    fn an_unreachable_daemon_is_a_menu_line_and_not_a_panic() {
        let model = MenuModel {
            fleet: Fleet::Unreachable("astd is not answering on /tmp/astd.sock".into()),
            autostart: false,
        };
        let lines = model.lines();
        assert_eq!(lines[3], "[disabled] daemon unreachable");
        assert!(lines[4].contains("/tmp/astd.sock"));
        // Quit stays reachable no matter what the daemon is doing, and so
        // do both windows: looking at a fleet and defining an instance do
        // not need a live one.
        assert!(lines.contains(&"[quit] Quit Asterism  (enabled)".to_owned()));
        assert_eq!(lines[0], "[main] Open Asterism  (enabled)");
    }

    #[test]
    fn an_empty_fleet_says_so() {
        assert_eq!(fleet(vec![]).lines()[3], "[disabled] no instances yet");
    }

    /// The two windows are the first things in the menu, above the fleet
    /// they look at and add to, and both are offered whatever the daemon is
    /// doing — the alternative is a menu with nothing to say on the machine
    /// with nothing on it.
    #[test]
    fn every_menu_opens_with_the_two_windows() {
        let models = [
            MenuModel::loading(false),
            fleet(vec![]),
            fleet(vec![row("dev", Status::Running, Ok(vec![]))]),
            MenuModel { fleet: Fleet::Unreachable("no socket".into()), autostart: true },
        ];
        for model in models {
            let lines = model.lines();
            assert_eq!(lines[0], "[main] Open Asterism  (enabled)", "{model:?}");
            assert_eq!(lines[1], "[new] New Instance…  (enabled)", "{model:?}");
            assert_eq!(lines[2], "[separator]", "{model:?}");
        }
    }

    #[test]
    fn the_version_is_the_last_line() {
        let last = fleet(vec![]).lines().last().unwrap().clone();
        assert_eq!(last, format!("[disabled] Asterism {}", env!("CARGO_PKG_VERSION")));
        assert!(last.starts_with("[disabled]"), "the version is not clickable");
    }

    #[test]
    fn long_daemon_errors_are_cut_to_fit() {
        let model = MenuModel {
            fleet: Fleet::Unreachable("x".repeat(400)),
            autostart: false,
        };
        let line = &model.lines()[4];
        let reason = line.trim_start_matches("[disabled]").trim_start();
        assert_eq!(reason.chars().count(), REASON_WIDTH, "{line}");
        assert!(reason.ends_with('…'));
    }

    #[test]
    fn every_id_in_the_menu_parses_back_to_the_action_that_made_it() {
        let model = MenuModel {
            fleet: Fleet::Instances(vec![
                row("dev", Status::Running, Ok(vec!["nightly".into()])),
                row("build", Status::Defined, Err("no disk".into())),
            ]),
            autostart: true,
        };
        let mut seen = 0;
        for line in model.lines() {
            let Some(id) = line.trim().strip_prefix('[').and_then(|l| l.split(']').next()) else {
                continue;
            };
            if id == "separator" || id == "disabled" || id == "submenu" {
                continue;
            }
            let action = Action::parse(id).unwrap_or_else(|| panic!("no action for {id:?}"));
            assert_eq!(action.id(), id, "round trip");
            assert!(!action.describe().is_empty());
            seen += 1;
        }
        // main, new, up/down/term/snap/rm ×2, one restore, autostart,
        // website, quit.
        assert_eq!(seen, 16);
    }

    #[test]
    fn unknown_ids_are_not_actions() {
        assert_eq!(Action::parse("new"), Some(Action::NewInstance));
        assert_eq!(Action::parse("new:dev"), None, "the window takes no argument");
        assert_eq!(Action::parse("info:version"), None);
        assert_eq!(Action::parse("bogus"), None);
        assert_eq!(Action::parse("restore:dev"), None, "a restore needs a tag");
        assert_eq!(
            Action::parse("restore:dev:v1.2_a"),
            Some(Action::Restore { name: "dev".into(), tag: "v1.2_a".into() })
        );
        assert_eq!(Action::parse("rm:dev"), Some(Action::Remove("dev".into())));
    }
}
