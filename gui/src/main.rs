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
//!   and refusing an action is a thing worth being able to test.
//! * `--main` and `--new-instance` start the app with a window already
//!   open, which is how each gets looked at and photographed;
//!   `--section <name>` says which of the three the main window opens on;
//!   and
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

const TRAY_ID: &str = "asterism-tray";
/// Cheap enough to be live, slow enough to be free: one `List` request
/// over a unix socket every few seconds.
const POLL_INTERVAL: Duration = Duration::from_secs(3);

/// The model the menu on screen was built from. The poller compares
/// against it and does nothing when nothing changed, so an open menu is
/// not rebuilt under the pointer.
#[derive(Default)]
struct Shown(Mutex<Option<MenuModel>>);

const USAGE: &str = "usage: [--dump-menu | --dump-form | --dump-main [section] | --click <id> \
                     | --main [--section <name>] | --new-instance | --theme dark|light \
                     | --create-via-window <json> \
                     | --pair-via-window invite|add:<ticket> [--as <name>] \
                     | --wake-via-window <device> | --version]";

/// How the app was asked to start.
enum Argv {
    /// The tray, with an optional single action to perform on the way in.
    Run(Option<Action>),
    /// Print the menu and exit.
    DumpMenu,
    /// Print the New Instance window's fields and exit.
    DumpForm,
    /// Print one of the main window's sections, or all three, and exit.
    DumpMain(Option<shell::Section>),
    /// Run the window's create without a window, and exit.
    CreateViaWindow(newinstance::Wanted),
    /// Run the Devices panel's pairing without a window, and exit.
    PairViaWindow(devices::Invitation),
    /// Run the Wake button's conversation without a window, and exit.
    WakeViaWindow(String),
    /// Print an identity the transactional updater can validate without
    /// starting a tray, a webview, or a daemon.
    Version,
}

impl Argv {
    fn from_env() -> Argv {
        let mut args = std::env::args().skip(1).peekable();
        let mut click = None;
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
                        Some(section) => mainwindow::open_on(section),
                        None => die(&format!("--section: {name:?} is not a section")),
                    }
                }
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
                "-V" | "--version" => return Argv::Version,
                "--click" => {
                    let id = args.next().unwrap_or_default();
                    match Action::parse(&id) {
                        Some(action) => click = Some(action),
                        None => die(&format!("--click: {id:?} is not an id (see --dump-menu)")),
                    }
                }
                other => die(&format!("unknown argument {other:?}; {USAGE}")),
            }
        }
        Argv::Run(click)
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
        Argv::Version => {
            println!("version   {}", env!("CARGO_PKG_VERSION"));
            println!("build     {}", asterism_core::BUILD_ID);
        }
        Argv::Run(click) => run(click),
    }
}

fn print_lines(lines: Vec<String>) {
    for line in lines {
        println!("{line}");
    }
}

fn run(click: Option<Action>) {
    let app = tauri::Builder::default()
        .manage(Shown::default())
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
            if let Some(action) = click {
                let handle = app.handle().clone();
                // Opening the window is the one action that is not over
                // when it returns: something has to keep running for the
                // window to be in. The rest are round trips, and the app
                // leaves as soon as it has made one.
                let stay = action.opens_a_window();
                std::thread::spawn(move || {
                    let _ = perform(&handle, &action);
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
    let app = app.clone();
    // `Up` boots a guest, `Restore` rewrites a disk and the confirmation
    // dialog waits on a human; none of that is a wait the menu bar should
    // take.
    std::thread::spawn(move || perform(&app, &action));
}

/// Do what an item says, and say what happened. Returns whether it worked,
/// which is what the window's Act command reports back to its status row —
/// the tray has nothing to do with the answer, because the notification has
/// already said it.
///
/// This is the one place any of these verbs happens. A tray item, a window
/// button and `--click` all arrive here with the same [`Action`].
fn perform(app: &AppHandle, action: &Action) -> bool {
    let what = action.describe();
    let done = match action {
        // Opening a window changes nothing the daemon knows about, so
        // these are also the actions that do not end in a refresh.
        Action::OpenMain => {
            return feedback::report(app, &what, mainwindow::open_from_anywhere(app));
        }
        Action::NewInstance => {
            return feedback::report(app, &what, window::open_from_anywhere(app));
        }
        Action::Up(name) => feedback::report(app, &what, client::up(name)),
        Action::Down(name) => feedback::report(app, &what, client::down(name)),
        Action::Terminal(name) => feedback::report(app, &what, applescript::open_terminal(name)),
        Action::Snapshot(name) => {
            // The same default the CLI uses, for the same reason: a name
            // that sorts chronologically and never collides.
            let tag = snapshot::timestamped_tag();
            feedback::report(app, &what, client::snapshot(name, &tag))
        }
        Action::Restore { name, tag } => match confirm_restore(name, tag) {
            Ok(true) => feedback::report(app, &what, client::snapshot_restore(name, tag)),
            Ok(false) => {
                feedback::log(&format!("skip {what}: cancelled"));
                // Cancelled is not failed. Reporting it as one would put an
                // error under a button the user deliberately backed out of.
                true
            }
            // We could not ask, so we do not do it.
            Err(e) => {
                feedback::failed(app, &format!("asking about {what}"), &format!("{e:#}"));
                false
            }
        },
        Action::ToggleAutostart => feedback::report(app, &what, toggle_autostart(app)),
        Action::ServiceInstall => feedback::report(app, &what, settings::install()),
        Action::ServiceUninstall => feedback::report(app, &what, settings::uninstall()),
        Action::UpdateCheck => feedback::report(app, &what, settings::update_check()),
        Action::UpdateApply => match applescript::confirm(
            "Install Asterism update",
            "Replace the app, CLI, daemon and VZ helper with the authenticated channel release? Running guests stay up.",
            "Install Update",
        ) {
            Ok(true) => feedback::report(app, &what, settings::update_apply()),
            Ok(false) => true,
            Err(e) => {
                feedback::failed(app, &format!("asking about {what}"), &format!("{e:#}"));
                false
            }
        },
        Action::Website => feedback::report(app, &what, open_website()),
        // Handled before the thread was ever spawned.
        Action::Quit => return true,
    };
    // Even a failed action can have moved something (an `Up` that got as
    // far as a guest and then died), so the menu is re-read either way.
    refresh(app);
    done
}

/// A restore is not undoable: it discards everything written since the
/// snapshot. Nothing else in this menu asks first, and nothing else needs
/// to.
fn confirm_restore(name: &str, tag: &str) -> anyhow::Result<bool> {
    applescript::confirm(
        "Restore snapshot",
        &format!(
            "Restore {name} to {tag}?\n\nEverything written to its disk since that \
             snapshot was taken will be lost."
        ),
        "Restore",
    )
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
