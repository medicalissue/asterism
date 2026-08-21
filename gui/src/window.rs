//! The app's one window, and the three commands it can call.
//!
//! The tray stays what it was: a menu of things that already exist. The
//! window is for the one thing a menu cannot ask — a name, a size, an
//! image — and it closes as soon as it has an answer.
//!
//! ## What the webview is allowed to be
//!
//! It loads `index.html` off the bundle and nothing else. No dev server —
//! `tauri.conf.json` names no `devUrl`, so a built app has nowhere to point
//! at even by mistake. No CDN, no font request, no telemetry: the frontend
//! is one JS file, one CSS file and an HTML file in `ui/dist`, the CSP
//! refuses anything that is not `self`, and the bundle contains no
//! `fetch` call at all. A window that phoned home would be a window that
//! leaked the fleet.
//!
//! ## What it is allowed to do
//!
//! Three commands, all thin. [`form`] reads the catalog, [`name_error`]
//! asks `asterism-core` about a name, and [`create`] runs the same
//! function `--create-via-window` runs. None of them holds state; the
//! daemon holds all of it, and the tray's next poll is how the fleet
//! catches up.
//!
//! ## Why the app does not become a Dock app while it is open
//!
//! `ActivationPolicy::Accessory` stays set. An accessory app can show,
//! focus and type into a window; what it does not get is a Dock tile and a
//! menu bar of its own, which is the whole point of a menu bar app.
//! Closing the window is not quitting — `RunEvent::ExitRequested` with no
//! code is refused in `main` — so the tray survives it.

use tauri::{AppHandle, Emitter, Manager, WebviewUrl, WebviewWindowBuilder};

use crate::feedback;
use crate::newinstance::{self, Form, Wanted};

/// The window's label, and the address the progress events are sent to.
pub const LABEL: &str = "new-instance";
/// One line of a create in progress.
pub const PROGRESS: &str = "new-instance://progress";

/// A utility dialog, sized like one. Fixed, because nothing in it reflows:
/// the form is a fixed number of rows, and the only one that comes and goes
/// is the backend row, which [`height`] accounts for.
const WIDTH: f64 = 760.0;
/// Name, image, the three number fields under their captions, the
/// checkbox, the footer, and 20px of margin at each end.
const HEIGHT: f64 = 640.0;
/// The backend row, when this device has more than one backend to offer.
const BACKEND_ROW: f64 = 0.0;

fn height() -> f64 {
    if newinstance::vz_available() {
        HEIGHT + BACKEND_ROW
    } else {
        HEIGHT
    }
}

/// Show the New Instance window, or bring the open one forward.
///
/// Must run on the main thread; macOS builds no window off it. Callers on
/// a worker thread want [`open_from_anywhere`].
pub fn open(app: &AppHandle) -> tauri::Result<()> {
    if let Some(window) = app.get_webview_window(LABEL) {
        window.show()?;
        window.unminimize()?;
        window.set_focus()?;
        return Ok(());
    }
    // A debug build gets the inspector on a right click, which is where an
    // inspector belongs: opening one on every launch puts a second window
    // over the first and swallows the clicks meant for it.
    WebviewWindowBuilder::new(app, LABEL, WebviewUrl::App("index.html".into()))
        .title("New Instance")
        .inner_size(WIDTH, height())
        .resizable(false)
        .maximizable(false)
        // A dialog you are answering is not a window you put away.
        .minimizable(false)
        .center()
        .focused(true)
        .theme(crate::forced_theme())
        .build()?;
    Ok(())
}

/// [`open`], from whichever thread is holding the handle. The menu event
/// arrives on the main thread and `--click new` does not, and neither
/// should have to know which it is.
pub fn open_from_anywhere(app: &AppHandle) -> anyhow::Result<()> {
    let handle = app.clone();
    app.run_on_main_thread(move || {
        if let Err(e) = open(&handle) {
            feedback::log(&format!("FAIL opening the New Instance window: {e}"));
        }
    })?;
    Ok(())
}

/// Close the window, if it is open. Called after a create succeeds: the
/// question has been answered, so the thing that asked it goes away.
fn close(app: &AppHandle) {
    if let Some(window) = app.get_webview_window(LABEL) {
        if let Err(e) = window.close() {
            feedback::log(&format!("FAIL closing the New Instance window: {e}"));
        }
    }
}

// ---- the commands ----------------------------------------------------------

/// What to put in the fields. Read fresh on every open, because the image
/// store and the fleet both move under us.
#[tauri::command]
pub(crate) fn form() -> Form {
    Form::load()
}

/// Why this name will not do, or `null`. One call per keystroke, and it
/// costs a function call: the rule is `asterism-core`'s, in process, with
/// no socket behind it.
#[tauri::command]
pub(crate) fn name_error(name: String) -> Option<String> {
    newinstance::name_error(&name)
}

/// Create the instance the form describes, reporting each step.
///
/// The work runs on a blocking thread: a pull is a download and a boot
/// waits for sshd, and neither belongs on the runtime that is also
/// delivering the progress events.
#[tauri::command]
pub(crate) async fn create(app: AppHandle, wanted: Wanted) -> Result<(), String> {
    let handle = app.clone();
    let done = tauri::async_runtime::spawn_blocking(move || {
        let emitter = handle.clone();
        let progress = move |step: &str| {
            if let Err(e) = emitter.emit_to(LABEL, PROGRESS, step) {
                feedback::log(&format!("FAIL reporting progress: {e}"));
            }
        };
        newinstance::create(&wanted, &progress)
    })
    .await;

    let result = match done {
        Ok(result) => result,
        // The blocking thread panicked, which is a bug rather than a
        // refusal; say so rather than reporting a create that did not
        // happen as one that did.
        Err(e) => Err(anyhow::anyhow!("the create thread died: {e}")),
    };

    // `newinstance::create` has already written the outcome to the log, so
    // all that is left is what to do with the window. No notification on
    // failure: the window is still open and about to show the reason
    // itself, and two copies of one error is one too many.
    match result {
        Ok(()) => {
            close(&app);
            Ok(())
        }
        Err(e) => Err(format!("{e:#}")),
    }
}

/// Everything both windows may ask for, in one list.
///
/// Tauri takes a single `invoke_handler`, so the three commands above and
/// the seventeen in [`crate::mainwindow`] are named together here — which is
/// also the only place to read what the whole webview surface is.
pub fn handlers() -> impl Fn(tauri::ipc::Invoke) -> bool + Send + Sync + 'static {
    use crate::mainwindow as main;
    tauri::generate_handler![
        // The New Instance dialog.
        form,
        name_error,
        create,
        // The main window: three sections, read one at a time.
        main::instances,
        main::device_rows,
        main::settings_rows,
        main::volume_rows,
        main::snapshots,
        main::snapshot_tag_error,
        main::default_snapshot_tag,
        main::console_tail,
        main::take_route,
        // ... and what its buttons do.
        main::action_label,
        main::act,
        main::copy,
        main::set_default_backend,
        main::pair_start,
        main::pair_confirm,
        main::pair_cancel,
        main::wake
    ]
}
