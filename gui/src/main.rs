//! Asterism — the menu bar app.
//!
//! A tray icon, a menu of instances with Up / Down / Open Terminal /
//! Snapshots on each, two windows, a login item, and Quit. It is a plain
//! `astd` client: it holds one preference and knows nothing else the CLI
//! does not — the same unix socket, the same `asterism-core` request types.
//! Anything the app can do, `ast` can do, which is the property that keeps
//! a second surface from growing a second backend behind it.
//!
//! Two windows, and they answer different questions. `mainwindow` is where
//! the fleet lives: instances, devices, and how this machine is set up.
//! `window` is the New Instance dialog, which asks the one question a menu
//! cannot and closes as soon as it has an answer. Every verb either offers
//! is an [`Action`], which is what the tray items are too.
//!
//! The headless hooks, which are how all of this is tested without a
//! pointer:
//!
//! * `--dump-menu` prints the menu it would build right now and exits. It
//!   reports the login item as off, because it never starts the app that
//!   owns that setting.
//! * `--dump-form` does the same for the New Instance window: the images,
//!   their pulled state, the backends and the shape it would open on.
//! * `--dump-main [instances|devices|settings]` does it for the main
//!   window, one section or all three.
//! * `--click <id>` — an id out of the menu dump, or off a window button —
//!   starts the app normally, performs that one action, and quits. It does
//!   not check whether the item was enabled: the daemon is the real gate,
//!   and refusing an action is a thing worth being able to test. What it
//!   does check is the confirmation: `--confirm <token>` carries the word a
//!   person would have typed, and a restore, a snapshot delete or a removal
//!   without the exact one sends no frame at all.
//! * `--dump-snapshots <name>` prints the snapshot table the detail pane
//!   draws — tag, date and size — through the same cached listing the
//!   window reads, and without adding a snapshot read to the fleet poll.
//! * `--main` and `--new-instance` start the app with a window already
//!   open, which is how each gets looked at and photographed;
//!   `--section <name>` says which of the three the main window opens on,
//!   and `--instance <name> [--intent remove|restore:<tag>|snapshot-delete:<tag>|snapshots]`
//!   queues the same route a tray click queues — which is how a
//!   confirmation dialog gets photographed without a pointer, and through
//!   the route contract rather than around it;
//!   `--theme dark|light` fixes the appearance of whatever they open so
//!   that both schemes can be photographed without changing the machine's
//!   own setting.
//! * `--create-via-window <json>` runs the window's own create, with the
//!   progress lines going to stderr instead of to a webview.
//! * `--pair-via-window invite|add:<ticket>` runs the Devices panel's own
//!   pairing, printing each state as it arrives and taking the codes as
//!   matching — the one thing a script cannot honestly do, which is why it
//!   is a flag and not the default.
//! * `--wake-via-window <device>` runs the Wake button's conversation.
//!
//! All five `--…-via-window` and `--dump-…` hooks call the same functions
//! the buttons call, so a proof that goes through them goes through the
//! app's code rather than around it.

mod action;
mod applescript;
mod client;
mod devices;
mod feedback;
mod instances;
mod mainwindow;
mod menu;
mod newinstance;
mod settings;
mod shell;
mod volumes;
mod window;

use std::collections::HashSet;
use std::sync::Mutex;
use std::time::Duration;

use tauri::menu::MenuEvent;
use tauri::tray::TrayIconBuilder;
use tauri::{AppHandle, Manager, RunEvent};
use tauri_plugin_autostart::ManagerExt;
use tauri_plugin_notification::{NotificationExt, PermissionState};

use asterism_core::snapshot;
use action::Action;
use menu::MenuModel;

/// What a `--click` was asked to do, and with what authority.
///
/// The token is the word a person would have typed into the confirmation
/// dialog. Carrying it as an argument rather than assuming it is what makes
/// `--click rm:gui-a` a no-op and `--click rm:gui-a --confirm gui-a` a
/// removal — omission safety for a script, not an authentication boundary.
struct Click {
    action: Action,
    confirmation: Option<String>,
}

const TRAY_ID: &str = "asterism-tray";
/// Cheap enough to be live, slow enough to be free: one `List` request
/// over a unix socket every few seconds.
const POLL_INTERVAL: Duration = Duration::from_secs(3);

/// The model the menu on screen was built from. The poller compares
/// against it and does nothing when nothing changed, so an open menu is
/// not rebuilt under the pointer.
#[derive(Default)]
struct Shown(Mutex<Option<MenuModel>>);

/// The instances this app currently has a mutation in flight on.
///
/// One name, one action at a time. A tray item and a window button can be
/// pressed within the same second, and two `Up`s racing on one guest is not
/// something the daemon should be asked to arbitrate — so the second one is
/// refused here, before a frame is written.
///
/// It covers this app only. `ast` on another terminal is not in this set and
/// is not meant to be: the daemon is the lock that matters, and this is the
/// double-click guard in front of it.
#[derive(Debug, Default)]
struct Busy(Mutex<HashSet<String>>);

impl Busy {
    /// Claim an instance, or say who has it. The claim is released when the
    /// returned guard is dropped, including on the way out of a panic.
    fn claim<'a>(&'a self, name: &str) -> Result<Claim<'a>, String> {
        let mut held = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if !held.insert(name.to_owned()) {
            return Err(format!("An action is already in progress for {name}"));
        }
        Ok(Claim { busy: self, name: name.to_owned() })
    }
}

#[derive(Debug)]
struct Claim<'a> {
    busy: &'a Busy,
    name: String,
}

impl Drop for Claim<'_> {
    fn drop(&mut self) {
        self.busy.0.lock().unwrap_or_else(|e| e.into_inner()).remove(&self.name);
    }
}

const USAGE: &str = "usage: [--dump-menu | --dump-form | --dump-main [section] \
                     | --dump-snapshots <name> | --click <id> [--confirm <token>] \
                     | --main [--section <name>] [--instance <name> [--intent <spec>]] \
                     | --new-instance | --theme dark|light \
                     | --create-via-window <json> \
                     | --pair-via-window invite|add:<ticket> [--as <name>] \
                     | --wake-via-window <device>]";

/// How the app was asked to start.
enum Argv {
    /// The tray, with an optional single action to perform on the way in.
    Run(Option<Click>),
    /// Print the menu and exit.
    DumpMenu,
    /// Print the New Instance window's fields and exit.
    DumpForm,
    /// Print one of the main window's sections, or all three, and exit.
    DumpMain(Option<shell::Section>),
    /// Print one instance's snapshot table and exit.
    DumpSnapshots(String),
    /// Run the window's create without a window, and exit.
    CreateViaWindow(newinstance::Wanted),
    /// Run the Devices panel's pairing without a window, and exit.
    PairViaWindow(devices::Invitation),
    /// Run the Wake button's conversation without a window, and exit.
    WakeViaWindow(String),
}

impl Argv {
    fn from_env() -> Argv {
        let mut args = std::env::args().skip(1).peekable();
        let mut click: Option<Action> = None;
        let mut confirmation: Option<String> = None;
        let mut section: Option<shell::Section> = None;
        let mut instance: Option<String> = None;
        let mut intent: Option<String> = None;
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--dump-menu" => return Argv::DumpMenu,
                "--dump-form" => return Argv::DumpForm,
                "--dump-main" => {
                    // The section is optional: no section is all of them.
                    let Some(name) = args.peek().filter(|a| !a.starts_with("--")).cloned() else {
                        return Argv::DumpMain(None);
                    };
                    args.next();
                    match shell::Section::parse(&name) {
                        Some(section) => return Argv::DumpMain(Some(section)),
                        None => die(&format!("--dump-main: {name:?} is not a section")),
                    }
                }
                // Opening a window is a menu action, so asking for one on
                // the command line is asking to click that item — and it
                // stays open afterwards, unlike `--click main`, because a
                // window nobody can look at is not much of a window.
                "--main" => click = Some(Action::OpenMain),
                "--section" => {
                    let name = args.next().unwrap_or_default();
                    match shell::Section::parse(&name) {
                        Some(found) => {
                            section = Some(found);
                            mainwindow::open_on(found);
                        }
                        None => die(&format!("--section: {name:?} is not a section")),
                    }
                }
                // The route half of `--main`: which row, and which dialog on
                // it. Queued exactly as a tray click queues one.
                "--instance" => match args.next() {
                    Some(name) if !name.is_empty() => instance = Some(name),
                    _ => die("--instance: name an instance"),
                },
                "--intent" => match args.next() {
                    Some(spec) if !spec.is_empty() => intent = Some(spec),
                    _ => die("--intent: name an intent"),
                },
                "--dump-snapshots" => match args.next() {
                    Some(name) if !name.is_empty() => return Argv::DumpSnapshots(name),
                    _ => die("--dump-snapshots: name an instance"),
                },
                "--new-instance" => click = Some(Action::NewInstance),
                "--theme" => {
                    let name = args.next().unwrap_or_default();
                    let theme = match name.as_str() {
                        "dark" => tauri::Theme::Dark,
                        "light" => tauri::Theme::Light,
                        other => die(&format!("--theme: {other:?} is not dark or light")),
                    };
                    let _ = FORCED_THEME.set(theme);
                }
                "--create-via-window" => {
                    let json = args.next().unwrap_or_default();
                    match serde_json::from_str(&json) {
                        Ok(wanted) => return Argv::CreateViaWindow(wanted),
                        Err(e) => die(&format!("--create-via-window: {e}")),
                    }
                }
                "--pair-via-window" => {
                    let spec = args.next().unwrap_or_default();
                    // `--as <name>` is what `ast device invite --name` is:
                    // what this device calls itself when its hostname will
                    // not do, which on a scratch orbit of two daemons on one
                    // machine it will not.
                    let named = match args.peek().map(String::as_str) {
                        Some("--as") => {
                            args.next();
                            args.next()
                        }
                        _ => None,
                    };
                    match devices::Invitation::parse(&spec) {
                        Some(invitation) => return Argv::PairViaWindow(invitation.named(named)),
                        None => die(&format!(
                            "--pair-via-window: {spec:?} is not \"invite\" or \"add:<ticket>\""
                        )),
                    }
                }
                "--wake-via-window" => match args.next() {
                    Some(name) if !name.is_empty() => return Argv::WakeViaWindow(name),
                    _ => die("--wake-via-window: name a device"),
                },
                "--click" => {
                    let id = args.next().unwrap_or_default();
                    match Action::parse(&id) {
                        Some(action) => click = Some(action),
                        None => die(&format!("--click: {id:?} is not an id (see --dump-menu)")),
                    }
                }
                // The word a person would have typed. Anything that needs
                // one and does not get it does nothing; see `perform`.
                "--confirm" => match args.next() {
                    Some(token) if !token.is_empty() => confirmation = Some(token),
                    _ => die("--confirm: give the exact name or tag"),
                },
                other => die(&format!("unknown argument {other:?}; {USAGE}")),
            }
        }
        if let Some(instance) = instance {
            mainwindow::queue(mainwindow::Route {
                section: section.unwrap_or(shell::Section::Instances).id().to_owned(),
                instance: Some(instance),
                intent,
            });
        }
        Argv::Run(click.map(|action| Click { action, confirmation }))
    }
}

/// An appearance asked for on the command line, so that both schemes can be
/// looked at and photographed without touching the machine's own setting.
///
/// Unset is the honest default and the only thing a user ever gets: both
/// windows are drawn in `light-dark()` tokens and follow the system.
static FORCED_THEME: std::sync::OnceLock<tauri::Theme> = std::sync::OnceLock::new();

pub(crate) fn forced_theme() -> Option<tauri::Theme> {
    FORCED_THEME.get().copied()
}

/// A bad argument is a bad argument, not a half-started app.
fn die(why: &str) -> ! {
    eprintln!("{why}");
    std::process::exit(2)
}

fn main() {
    match Argv::from_env() {
        Argv::DumpMenu => print_lines(MenuModel::from_daemon(false).lines()),
        Argv::DumpForm => print_lines(newinstance::Form::load().lines()),
        // The login item reads as off here, the way `--dump-menu` reports
        // it: this never starts the app that owns that setting.
        Argv::DumpMain(section) => print_lines(shell::dump(section, false)),
        // The same cached listing the detail pane reads, printed the way
        // its table draws it. A proof that asserted on `ast snapshots`
        // would be proving the CLI.
        Argv::DumpSnapshots(name) => print_lines(mainwindow::snapshot_lines(&name)),
        // No app, no webview, no main thread to borrow: these three are the
        // windows' own functions called directly, which is the point — a
        // proof that goes through the buttons' code rather than around it.
        Argv::CreateViaWindow(wanted) => {
            let progress = |step: &str| feedback::echo(step);
            if let Err(e) = newinstance::create(&wanted, &progress) {
                eprintln!("create failed: {e:#}");
                std::process::exit(1);
            }
            println!("created {}", wanted.name);
        }
        Argv::PairViaWindow(invitation) => {
            let on_state = |state: &devices::Pairing| println!("{}", state.line());
            // Taking the codes as matching is exactly what a script cannot
            // honestly do, and why this is a hook rather than the default.
            let confirm = |_code: &str| true;
            let opened = |_hangup: client::Hangup| {};
            if let Err(e) = devices::pair(&invitation, &on_state, &confirm, &opened) {
                eprintln!("pairing failed: {e:#}");
                std::process::exit(1);
            }
        }
        Argv::WakeViaWindow(name) => {
            let progress = |line: &str| println!("{line}");
            if let Err(e) = devices::wake(&name, &progress) {
                eprintln!("wake failed: {e:#}");
                std::process::exit(1);
            }
        }
        Argv::Run(click) => run(click),
    }
}

fn print_lines(lines: Vec<String>) {
    for line in lines {
        println!("{line}");
    }
}

fn run(click: Option<Click>) {
    let app = tauri::Builder::default()
        .manage(Shown::default())
        // Which instances already have a mutation in flight. Owned by the
        // app because a tray item and a window button reach it from
        // different threads.
        .manage(Busy::default())
        // The pairing in progress, if there is one. Owned by the app rather
        // than by the window, because the thread holding a half-made
        // pairing outlives any one render of the panel showing it.
        .manage(mainwindow::InFlight::default())
        // Everything the two windows may ask for. Nothing else is
        // reachable from a webview.
        .invoke_handler(window::handlers())
        // Failures need somewhere to go that is not stderr nobody reads.
        .plugin(tauri_plugin_notification::init())
        // A LaunchAgent plist, written and removed by the plugin, which is
        // therefore also where the setting lives — we keep no copy.
        .plugin(tauri_plugin_autostart::init(
            tauri_plugin_autostart::MacosLauncher::LaunchAgent,
            None,
        ))
        .setup(move |app| {
            // No Dock icon, no menu bar of our own, no window: this is an
            // accessory to the menu bar and nothing else.
            #[cfg(target_os = "macos")]
            app.set_activation_policy(tauri::ActivationPolicy::Accessory);

            ask_to_notify(app.handle());

            let icon = tauri::image::Image::from_bytes(include_bytes!("../icons/tray.png"))?;
            let first = MenuModel::loading(autostart_enabled(app.handle()));
            TrayIconBuilder::with_id(TRAY_ID)
                .icon(icon)
                // A template image is drawn from its alpha channel, so the
                // glyph follows the menu bar through light, dark and
                // whatever the wallpaper is doing behind a translucent bar.
                .icon_as_template(true)
                .tooltip("Asterism")
                .menu(&menu::build(app.handle(), &first)?)
                .on_menu_event(on_menu_event)
                .build(app)?;

            poll_forever(app.handle().clone());
            if let Some(Click { action, confirmation }) = click {
                let handle = app.handle().clone();
                // Opening the window is the one action that is not over
                // when it returns: something has to keep running for the
                // window to be in. The rest are round trips, and the app
                // leaves as soon as it has made one.
                let stay = action.opens_a_window();
                std::thread::spawn(move || {
                    let _ = perform(&handle, &action, confirmation.as_deref());
                    if !stay {
                        handle.exit(0);
                    }
                });
            }
            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("building the Asterism tray app");

    app.run(|_app, event| {
        // Closing a window can close the last window, and Tauri reads that
        // as "the app is done". It is not: the tray is still there, which
        // is where the app lives. An explicit Quit arrives with a code and
        // is left alone.
        if let RunEvent::ExitRequested { code: None, api, .. } = event {
            api.prevent_exit();
        }
    });
}

/// Refresh the menu on a timer, forever. Runs off the main thread: every
/// poll is a blocking socket round trip and the menu bar must stay
/// responsive while the daemon thinks.
fn poll_forever(app: AppHandle) {
    std::thread::spawn(move || loop {
        refresh(&app);
        std::thread::sleep(POLL_INTERVAL);
    });
}

/// Ask the daemon what it has and put the answer on screen. Never call
/// this from the main thread; it blocks on a socket.
fn refresh(app: &AppHandle) {
    show(app, MenuModel::from_daemon(autostart_enabled(app)));
}

/// Put a model on screen, if it differs from what is already there.
fn show(app: &AppHandle, model: MenuModel) {
    {
        let state = app.state::<Shown>();
        let mut shown = state.0.lock().unwrap_or_else(|e| e.into_inner());
        if shown.as_ref() == Some(&model) {
            return;
        }
        *shown = Some(model.clone());
    }

    // Straight to stderr rather than through `feedback`: this is every
    // item in the menu, on every change, and it would bury the log.
    for line in model.lines() {
        feedback::echo(&format!("menu: {line}"));
    }

    let handle = app.clone();
    // Menus are main-thread-only on macOS; this hands the work over and
    // returns, so the poll thread never waits on the UI.
    let _ = app.run_on_main_thread(move || {
        let Some(tray) = handle.tray_by_id(TRAY_ID) else {
            feedback::log(&format!("FAIL tray {TRAY_ID} is gone"));
            return;
        };
        match menu::build(&handle, &model) {
            Ok(menu) => {
                if let Err(e) = tray.set_menu(Some(menu)) {
                    feedback::log(&format!("FAIL setting the menu: {e}"));
                }
            }
            Err(e) => feedback::log(&format!("FAIL building the menu: {e}")),
        }
    });
}

/// Menu ids are handed to [`Action::parse`]; anything it does not
/// recognise is an informational line that should not have been clickable.
fn on_menu_event(app: &AppHandle, event: MenuEvent) {
    let Some(action) = Action::parse(event.id().as_ref()) else {
        return;
    };
    if action == Action::Quit {
        app.exit(0);
        return;
    }
    // Menu events arrive on the main thread, which is the only thread
    // macOS will build a window on, so these are done where they land
    // rather than handed to a worker that would only hand them back.
    if action.opens_a_window() {
        let opened = match action {
            Action::OpenMain => mainwindow::open(app),
            _ => window::open(app),
        };
        if let Err(e) = opened {
            feedback::failed(app, &action.describe(), &format!("{e}"));
        }
        return;
    }
    // A menu click carries no typed word, and the three that cannot be
    // undone need one. So the menu does not do them: it opens the window on
    // the instance with the matching dialog up, which is where the question
    // can actually be asked. The tray stays the fast path for the verbs that
    // are reversible.
    if let Some(route) = mainwindow::Route::of(&action) {
        if let Err(e) = mainwindow::route(app, route) {
            feedback::failed(app, &action.describe(), &format!("{e:#}"));
        }
        return;
    }
    let app = app.clone();
    // `Up` boots a guest, and that is not a wait the menu bar should take.
    std::thread::spawn(move || perform(&app, &action, None));
}

/// Why a typed word was not good enough.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Refused {
    /// A restore, a snapshot delete or a removal with no token, or with one
    /// that is not exactly the tag or name.
    NotConfirmed,
    /// A token on something that never asks for one. A confirmation on a
    /// `Down` would be a habit that teaches people to type past the ones
    /// that matter, so it is a mistake rather than harmless.
    Unexpected,
}

impl Refused {
    /// The `skip <action>: …` line. Fixed wording: it is what a proof greps
    /// for to show that nothing was sent.
    fn logged(self) -> &'static str {
        match self {
            Refused::NotConfirmed => "confirmation missing or did not match",
            Refused::Unexpected => "unexpected confirmation",
        }
    }

    fn said(self, what: &str) -> String {
        match self {
            Refused::NotConfirmed => {
                format!("{what} needs its exact name typed to confirm, and nothing was sent")
            }
            Refused::Unexpected => format!("{what} takes no confirmation"),
        }
    }
}

/// Whether this action may go ahead on the strength of the word it was
/// given. Exact and case-sensitive, both ways round.
fn consent(action: &Action, confirmation: Option<&str>) -> Result<(), Refused> {
    match (action.confirmation(), confirmation) {
        (Some(expected), Some(given)) if expected == given => Ok(()),
        (Some(_), _) => Err(Refused::NotConfirmed),
        (None, Some(_)) => Err(Refused::Unexpected),
        (None, None) => Ok(()),
    }
}

/// Do what an item says, and say what happened. Returns the daemon's own
/// sentence when it refused, which is what the window's Act command hands
/// to its status row — the tray has nothing to do with the answer, because
/// the notification has already said it.
///
/// This is the one place any of these verbs happens. A tray item, a window
/// button and `--click` all arrive here with the same [`Action`], and pass
/// the same two guards on the way in: the typed word, and the one-at-a-time
/// rule.
fn perform(app: &AppHandle, action: &Action, confirmation: Option<&str>) -> Result<(), String> {
    let what = action.describe();

    // Guard one. Three actions cannot be undone and each asks for the
    // thing's own name; nothing else accepts a token at all.
    if let Err(why) = consent(action, confirmation) {
        feedback::skipped(&what, why.logged());
        return Err(why.said(&what));
    }

    // Guard two. Held for exactly as long as the work, and only for the
    // things that change something: two console reads on one instance are
    // fine, two removals are not.
    let busy = app.state::<Busy>();
    let _claim = match action.subject().filter(|_| action.mutates()) {
        Some(name) => Some(busy.claim(name).inspect_err(|why| feedback::skipped(&what, why))?),
        None => None,
    };

    let done = match action {
        // Opening a window changes nothing the daemon knows about, so
        // these are also the actions that do not end in a refresh.
        Action::OpenMain => {
            return feedback::report(app, &what, mainwindow::open_from_anywhere(app));
        }
        Action::NewInstance => {
            return feedback::report(app, &what, window::open_from_anywhere(app));
        }
        Action::Up { name, restart } => feedback::report(app, &what, client::up(name, *restart)),
        Action::Down(name) => feedback::report(app, &what, client::down(name)),
        Action::Terminal(name) => feedback::report(app, &what, applescript::open_terminal(name)),
        Action::Rename { name, new_name } => {
            feedback::report(app, &what, client::rename(name, new_name))
        }
        Action::Remove(name) => feedback::report(app, &what, client::remove(name)),
        Action::Snapshot { name, tag } => {
            // No tag is the tray's fast path: the same default the CLI
            // uses, for the same reason — a name that sorts
            // chronologically and never collides.
            let tag = tag.clone().unwrap_or_else(snapshot::timestamped_tag);
            feedback::report(app, &what, client::snapshot(name, &tag))
        }
        Action::Restore { name, tag } => {
            feedback::report(app, &what, client::snapshot_restore(name, tag))
        }
        Action::SnapshotRemove { name, tag } => {
            feedback::report(app, &what, client::snapshot_remove(name, tag))
        }
        Action::ToggleAutostart => feedback::report(app, &what, toggle_autostart(app)),
        Action::ServiceInstall => feedback::report(app, &what, settings::install()),
        Action::ServiceUninstall => feedback::report(app, &what, settings::uninstall()),
        Action::Website => feedback::report(app, &what, open_website()),
        // Handled before the thread was ever spawned.
        Action::Quit => return Ok(()),
    };
    // Even a failed action can have moved something (an `Up` that got as
    // far as a guest and then died), so the menu is re-read either way.
    refresh(app);
    done
}

/// Whether the login item is installed, according to the plugin that owns
/// it. A plugin that cannot answer is reported as off, which is what will
/// actually happen at the next login.
pub(crate) fn autostart_enabled(app: &AppHandle) -> bool {
    match app.autolaunch().is_enabled() {
        Ok(on) => on,
        Err(e) => {
            feedback::log(&format!("FAIL reading start at login: {e}"));
            false
        }
    }
}

fn toggle_autostart(app: &AppHandle) -> anyhow::Result<()> {
    let manager = app.autolaunch();
    if manager.is_enabled()? {
        manager.disable()?;
    } else {
        manager.enable()?;
    }
    Ok(())
}

/// `open(1)` rather than a plugin: one URL does not need a dependency, and
/// this is a macOS-only app.
fn open_website() -> anyhow::Result<()> {
    use anyhow::{bail, Context};
    let status = std::process::Command::new("open")
        .arg(menu::WEBSITE)
        .status()
        .context("running open(1)")?;
    if !status.success() {
        bail!("open(1) exited with {status}");
    }
    Ok(())
}

/// Notification Center refuses anything from an app that has not asked.
/// Asking once at startup means the first failure the user sees is the
/// failure, not a silent drop.
fn ask_to_notify(app: &AppHandle) {
    let state = app.notification().permission_state();
    match state {
        Ok(PermissionState::Granted) => {}
        Ok(_) => {
            if let Err(e) = app.notification().request_permission() {
                feedback::log(&format!("FAIL asking to notify: {e}"));
            }
        }
        Err(e) => feedback::log(&format!("FAIL reading notification permission: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The three that cannot be undone go through only on the exact word,
    /// and everything else goes through only without one. Nothing here
    /// reaches a socket: a refusal is a frame that was never written.
    #[test]
    fn the_typed_word_is_exact_or_nothing_is_sent() {
        let remove = Action::Remove("gui-a".into());
        assert_eq!(consent(&remove, Some("gui-a")), Ok(()));
        assert_eq!(consent(&remove, None), Err(Refused::NotConfirmed));
        assert_eq!(consent(&remove, Some("")), Err(Refused::NotConfirmed));
        assert_eq!(consent(&remove, Some("gui-b")), Err(Refused::NotConfirmed));
        assert_eq!(consent(&remove, Some("GUI-A")), Err(Refused::NotConfirmed), "case matters");
        assert_eq!(consent(&remove, Some(" gui-a")), Err(Refused::NotConfirmed), "exact matters");

        // A snapshot's identity is its tag, not the instance's name.
        let restore = Action::Restore { name: "gui-a".into(), tag: "t1".into() };
        assert_eq!(consent(&restore, Some("t1")), Ok(()));
        assert_eq!(consent(&restore, Some("gui-a")), Err(Refused::NotConfirmed));

        let delete = Action::SnapshotRemove { name: "gui-a".into(), tag: "t1".into() };
        assert_eq!(consent(&delete, Some("t1")), Ok(()));
        assert_eq!(consent(&delete, None), Err(Refused::NotConfirmed));

        // And a token on something that never asks for one is a mistake,
        // not a harmless extra.
        let stop = Action::Down("gui-a".into());
        assert_eq!(consent(&stop, None), Ok(()));
        assert_eq!(consent(&stop, Some("gui-a")), Err(Refused::Unexpected));
    }

    /// The log line a proof greps for. `skip` rather than `FAIL`: nothing
    /// happened, and nothing failed.
    #[test]
    fn a_refusal_is_logged_as_a_skip_and_says_what_was_missing() {
        assert_eq!(Refused::NotConfirmed.logged(), "confirmation missing or did not match");
        let said = Refused::NotConfirmed.said("removing gui-a");
        assert!(said.starts_with("removing gui-a"), "{said}");
        assert!(said.contains("nothing was sent"), "{said}");
    }

    /// One name, one action. The second press is refused before a frame is
    /// written, and says which instance is busy rather than which button
    /// was pressed twice.
    #[test]
    fn a_second_action_on_one_instance_is_refused_rather_than_sent() {
        let busy = Busy::default();
        let held = busy.claim("dev").expect("the first claim");

        let second = busy.claim("dev").expect_err("the second claim");
        assert_eq!(second, "An action is already in progress for dev");

        // A different instance is a different queue.
        let other = busy.claim("build").expect("another instance is free");
        drop(other);

        // And the name is free again as soon as the work is over.
        drop(held);
        busy.claim("dev").expect("the claim was released");
    }
}
