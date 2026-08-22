//! The main window: a sidebar, a pane, and the commands the pane calls.
//!
//! The tray is still the fastest way to start something. This is the other
//! thing a fleet needs — somewhere to look at all of it, add a device, and
//! see how this machine is set up — and it is one window with three
//! sections rather than a second app.
//!
//! ## What the webview is allowed to be
//!
//! The same as the New Instance window's, because it is the same bundle:
//! `index.html` off the disk, no dev server, no CDN, no font request, one JS
//! file and one CSS file. Which of the two windows a page draws is decided
//! by its own label, so both windows are one build and one CSP.
//!
//! ## What it is allowed to do
//!
//! Everything below, and nothing else. The read commands are the daemon's
//! own frames ([`crate::client`]); the write commands are [`Action`]s, which
//! are the tray's actions, run by the tray's `perform`. A button in this
//! window and an item in that menu are the same piece of work reached by two
//! routes, which is what keeps the second surface from growing a second
//! backend.
//!
//! Pairing and waking are the exception, and only because they are
//! conversations: the daemon answers with several lines and, for a pairing,
//! wants an answer in the middle. Those hold a connection of their own (see
//! [`crate::client::Conversation`]) so that the poll on the pane behind them
//! cannot read a peer's six digits as its own reply.

use std::sync::mpsc::{Receiver, Sender};
use std::sync::Mutex;
use std::time::Duration;

use tauri::{AppHandle, Emitter, Manager, WebviewUrl, WebviewWindowBuilder};

use crate::action::Action;
use crate::client;
use crate::devices::{self, Devices, Invitation, Pairing};
use crate::feedback;
use crate::instances::Instances;
use crate::settings::{self, Settings};
use crate::shell::Section;
use crate::volumes::Volumes;

/// The window's label, and where its events are sent.
pub const LABEL: &str = "main";
/// One state of a pairing in progress.
pub const PAIRING: &str = "main://pairing";
/// One line of a wake in progress.
pub const WAKE: &str = "main://wake";

/// Comfortable rather than roomy: six instance rows and the section header
/// fit without scrolling, and the whole thing still sits on a laptop screen
/// next to a terminal.
const WIDTH: f64 = 1080.0;
const HEIGHT: f64 = 700.0;
/// Narrow enough to park beside an editor, and not so narrow that the
/// table's last column falls off.
const MIN_WIDTH: f64 = 820.0;
const MIN_HEIGHT: f64 = 560.0;

/// How long a pairing waits for somebody to look at the six digits before
/// giving up on its own. Long enough to walk to the other machine.
const VERDICT_WITHIN: Duration = Duration::from_secs(300);

/// The pairing in progress, if there is one.
///
/// Two halves, and both are needed: `verdict` is how Confirm and Reject
/// reach the thread that is blocked waiting for them, and `hangup` is how
/// Cancel reaches one that is blocked waiting for a peer instead.
#[derive(Default)]
pub struct InFlight {
    verdict: Mutex<Option<Sender<bool>>>,
    hangup: Mutex<Option<client::Hangup>>,
}

impl InFlight {
    fn arm(&self, hangup: client::Hangup) {
        *self.hangup.lock().unwrap_or_else(|e| e.into_inner()) = Some(hangup);
    }

    /// Park until somebody answers, or until [`VERDICT_WITHIN`] passes. A
    /// window nobody is standing at must not hold a daemon's pairing open
    /// forever, and silence is a no.
    fn wait_for_verdict(&self) -> bool {
        let (tx, rx): (Sender<bool>, Receiver<bool>) = std::sync::mpsc::channel();
        *self.verdict.lock().unwrap_or_else(|e| e.into_inner()) = Some(tx);
        // Nobody came, or the channel was dropped from under us. Both are
        // a "no", and neither is a reason to keep a daemon waiting.
        let answer = rx.recv_timeout(VERDICT_WITHIN).unwrap_or_default();
        *self.verdict.lock().unwrap_or_else(|e| e.into_inner()) = None;
        answer
    }

    fn clear(&self) {
        *self.verdict.lock().unwrap_or_else(|e| e.into_inner()) = None;
        *self.hangup.lock().unwrap_or_else(|e| e.into_inner()) = None;
    }

    /// Take the verdict channel, if a thread is waiting on one.
    fn take_verdict(&self) -> Option<Sender<bool>> {
        self.verdict.lock().unwrap_or_else(|e| e.into_inner()).take()
    }

    /// Stop whatever is in flight.
    ///
    /// A "no" goes first, in case the thread is sitting on the six digits:
    /// that is the frame that tells the *other* device to stop too. Ending
    /// the conversation is the only way out of a wait for a peer who never
    /// turned up, and it is a no-op on one that already finished.
    fn cancel(&self) {
        if let Some(tx) = self.take_verdict() {
            let _ = tx.send(false);
        }
        let hangup = self.hangup.lock().unwrap_or_else(|e| e.into_inner()).take();
        if let Some(hangup) = hangup {
            hangup.end();
        }
    }
}

// ---- the window ------------------------------------------------------------

/// Which section the window should open on, when something asked.
///
/// The default is Instances, because a fleet view is what somebody opening
/// this came for. `--section` fills this in, which is how the other two get
/// photographed and how a deep link would reach them.
static OPEN_ON: std::sync::OnceLock<Section> = std::sync::OnceLock::new();

pub fn open_on(section: Section) {
    let _ = OPEN_ON.set(section);
}

/// The address the webview is loaded from. A section is a query rather than
/// a command, because the page has to know it before its first render and a
/// command would arrive after.
fn url() -> WebviewUrl {
    match OPEN_ON.get() {
        Some(section) => WebviewUrl::App(format!("index.html?section={}", section.id()).into()),
        None => WebviewUrl::App("index.html".into()),
    }
}

/// Show the main window, or bring the open one forward.
///
/// Must run on the main thread; macOS builds no window off it.
pub fn open(app: &AppHandle) -> tauri::Result<()> {
    if let Some(window) = app.get_webview_window(LABEL) {
        window.show()?;
        window.unminimize()?;
        window.set_focus()?;
        return Ok(());
    }
    let builder = WebviewWindowBuilder::new(app, LABEL, url())
        .title("Asterism")
        .inner_size(WIDTH, HEIGHT)
        .min_inner_size(MIN_WIDTH, MIN_HEIGHT)
        .resizable(true)
        .center()
        .focused(true)
        // Normally `None`, which is "follow the machine". `--theme` is what
        // fills it in, and only so that both schemes can be photographed.
        .theme(crate::forced_theme());
    // The sidebar runs to the top of the window and the traffic lights sit
    // on it, which is what makes this read as an app rather than as a web
    // page in a frame. The pane's own header supplies the title, so the
    // system one would be a second one.
    #[cfg(target_os = "macos")]
    let builder = builder
        .title_bar_style(tauri::TitleBarStyle::Overlay)
        .hidden_title(true);
    builder.build()?;
    Ok(())
}

/// [`open`], from whichever thread is holding the handle.
pub fn open_from_anywhere(app: &AppHandle) -> anyhow::Result<()> {
    let handle = app.clone();
    app.run_on_main_thread(move || {
        if let Err(e) = open(&handle) {
            feedback::log(&format!("FAIL opening the Asterism window: {e}"));
        }
    })?;
    Ok(())
}

// ---- reading ---------------------------------------------------------------
//
// One command per section, rather than one that loads all three. Devices
// probes every peer on the mesh as it is served and Instances does not, so a
// pane nobody is looking at should not be paying for the other's poll.

/// The Instances table. Blocking work off the runtime that is also
/// delivering the pane's events.
#[tauri::command]
pub(crate) async fn instances() -> Result<Instances, String> {
    blocking(Instances::load).await
}

#[tauri::command]
pub(crate) async fn device_rows() -> Result<Devices, String> {
    blocking(Devices::load).await
}

#[tauri::command]
pub(crate) async fn settings_rows(app: AppHandle) -> Result<Settings, String> {
    let autostart = crate::autostart_enabled(&app);
    blocking(move || Settings::load(autostart)).await
}

#[tauri::command]
pub(crate) async fn volume_rows() -> Result<Volumes, String> {
    blocking(Volumes::load).await
}

#[derive(serde::Serialize)]
pub(crate) struct ConsoleTail {
    text: String,
    truncated: bool,
}

/// Read a bounded guest-console tail through the same routed daemon frame as
/// `ast logs`. Following is intentionally not offered across the orbit.
#[tauri::command]
pub(crate) async fn console_tail(name: String, lines: u32) -> Result<ConsoleTail, String> {
    blocking(move || {
        let (text, truncated) = client::logs(&name, lines.min(500))
            .map_err(|error| format!("{error:#}"))?;
        Ok(ConsoleTail { text, truncated })
    })
    .await?
}

/// The tags on one instance's disk, read when the Snapshots popover opens
/// rather than on every poll: listing them costs the daemon a `qemu-img`
/// per instance, and the tray's cache is shared with this
/// ([`client::snapshot_tags`]).
#[tauri::command]
pub(crate) async fn snapshots(name: String) -> Result<Vec<String>, String> {
    blocking(move || {
        client::snapshot_tags(std::slice::from_ref(&name))
            .remove(&name)
            .unwrap_or_else(|| Err("astd did not answer about this instance".to_owned()))
    })
    .await?
}

#[tauri::command]
pub(crate) async fn backup_instance(
    name: String,
) -> Result<asterism_core::backup::ExportReport, String> {
    blocking(move || client::backup(&name).map_err(|error| format!("{error:#}"))).await?
}

#[tauri::command]
pub(crate) async fn restore_instance(
    source: String,
    name: Option<String>,
) -> Result<asterism_core::backup::RestoreReport, String> {
    blocking(move || {
        client::restore_backup(&source, name.as_deref()).map_err(|error| format!("{error:#}"))
    })
    .await?
}

// ---- doing -----------------------------------------------------------------

/// Perform one [`Action`], by id. The same ids the tray uses and the same
/// work behind them, so `--click up:dev` exercises this button.
#[tauri::command]
pub(crate) async fn act(app: AppHandle, id: String) -> Result<(), String> {
    let Some(action) = Action::parse(&id) else {
        return Err(format!("{id:?} is not an action"));
    };
    let what = action.describe();
    let handle = app.clone();
    // `perform` reports its own outcome to the log and to Notification
    // Center, and ends by refreshing the tray. What comes back here is
    // whether the pane should say something too.
    match blocking(move || crate::perform(&handle, &action)).await? {
        true => Ok(()),
        false => Err(format!("{what} failed — see the notification")),
    }
}

/// Put text on the pasteboard, so a ticket can be carried to the other
/// machine. `pbcopy` rather than a plugin: one string does not need a
/// dependency, and this is a macOS-only app.
#[tauri::command]
pub(crate) async fn copy(text: String) -> Result<(), String> {
    blocking(move || {
        use std::io::Write as _;
        let mut child = std::process::Command::new("pbcopy")
            .stdin(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| format!("running pbcopy: {e}"))?;
        child
            .stdin
            .take()
            .ok_or_else(|| "pbcopy took no input".to_owned())?
            .write_all(text.as_bytes())
            .map_err(|e| format!("writing to pbcopy: {e}"))?;
        match child.wait() {
            Ok(status) if status.success() => Ok(()),
            Ok(status) => Err(format!("pbcopy exited with {status}")),
            Err(e) => Err(format!("waiting for pbcopy: {e}")),
        }
    })
    .await?
}

/// Which backend the New Instance window should open on.
#[tauri::command]
pub(crate) async fn set_default_backend(id: String) -> Result<(), String> {
    blocking(move || settings::set_preferred_backend(&id).map_err(|e| format!("{e:#}"))).await?
}

// ---- pairing ---------------------------------------------------------------

/// Start one half of a pairing. Returns as soon as the conversation is
/// running; everything it has to say arrives as [`PAIRING`] events.
#[tauri::command]
pub(crate) fn pair_start(app: AppHandle, spec: String) -> Result<(), String> {
    let Some(invitation) = Invitation::parse(&spec) else {
        return Err(format!("{spec:?} is not a pairing"));
    };
    // Whatever was in flight is over: one window, one pairing.
    app.state::<InFlight>().clear();
    let handle = app.clone();
    std::thread::spawn(move || {
        let done = run_pairing(&handle, &invitation);
        handle.state::<InFlight>().clear();
        if let Err(e) = done {
            let state = Pairing::Failed { reason: format!("{e:#}") };
            feedback::log(&format!("FAIL {}", state.line()));
            emit(&handle, PAIRING, &state);
        }
    });
    Ok(())
}

fn run_pairing(app: &AppHandle, invitation: &Invitation) -> anyhow::Result<()> {
    emit(app, PAIRING, &Pairing::Waiting);
    let on_state = |state: &Pairing| {
        feedback::log(&state.line());
        emit(app, PAIRING, state);
    };
    // The code is already on screen by the time this runs: `on_state` put
    // it there. All this waits for is which button gets pressed.
    let confirm = |_code: &str| app.state::<InFlight>().wait_for_verdict();
    let opened = |hangup: client::Hangup| app.state::<InFlight>().arm(hangup);
    devices::pair(invitation, &on_state, &confirm, &opened)
}

/// The human's verdict on the six digits.
#[tauri::command]
pub(crate) fn pair_confirm(app: AppHandle, accept: bool) -> Result<(), String> {
    match app.state::<InFlight>().take_verdict() {
        Some(tx) => tx.send(accept).map_err(|_| "the pairing already ended".to_owned()),
        None => Err("nothing is waiting for an answer".to_owned()),
    }
}

/// Give up on a pairing, whether it is waiting for a peer or for a verdict.
#[tauri::command]
pub(crate) fn pair_cancel(app: AppHandle) {
    app.state::<InFlight>().cancel();
}

// ---- waking ----------------------------------------------------------------

/// Wake a device, streaming the daemon's own lines into the pane's status
/// row. The last one arrives up to a minute after the first.
#[tauri::command]
pub(crate) async fn wake(app: AppHandle, name: String) -> Result<(), String> {
    let handle = app.clone();
    blocking(move || {
        let progress = |line: &str| {
            feedback::log(&format!("wake {name}: {line}"));
            emit(&handle, WAKE, &line.to_owned());
        };
        devices::wake(&name, &progress).map_err(|e| format!("{e:#}"))
    })
    .await?
}

// ---- plumbing --------------------------------------------------------------

/// Run something that blocks on a socket, off the runtime delivering this
/// window's events.
///
/// The error half is a worker that panicked, which is a bug rather than a
/// refusal — and reporting it as one beats reporting an empty fleet.
async fn blocking<T, F>(work: F) -> Result<T, String>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    tauri::async_runtime::spawn_blocking(work).await.map_err(|e| {
        feedback::log(&format!("FAIL a window worker died: {e}"));
        format!("a window worker died: {e}")
    })
}

fn emit<T: serde::Serialize + Clone>(app: &AppHandle, event: &str, payload: &T) {
    if let Err(e) = app.emit_to(LABEL, event, payload.clone()) {
        feedback::log(&format!("FAIL reporting {event}: {e}"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Arc;

    /// A pairing thread parked on the six digits, and the handle a click
    /// would reach it through. The wait runs on a thread because that is
    /// where it runs in the app: the verdict arrives from a command on
    /// another one.
    fn parked() -> (Arc<InFlight>, std::thread::JoinHandle<bool>) {
        let flight = Arc::new(InFlight::default());
        let asking = Arc::clone(&flight);
        let waiter = std::thread::spawn(move || asking.wait_for_verdict());
        for _ in 0..400 {
            if flight.verdict.lock().unwrap().is_some() {
                return (flight, waiter);
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        panic!("the pairing never asked for a verdict");
    }

    #[test]
    fn a_yes_reaches_the_thread_that_is_waiting_for_it() {
        let (flight, waiter) = parked();
        assert!(pair_verdict(&flight, true).is_ok());
        assert!(waiter.join().unwrap());
    }

    /// Cancel is a no, and it arrives at the parked thread rather than
    /// leaving it there: the frame it produces is what tells the *other*
    /// device to stop waiting too.
    #[test]
    fn cancelling_answers_no_rather_than_leaving_the_pairing_parked() {
        let (flight, waiter) = parked();
        flight.cancel();
        assert!(!waiter.join().unwrap(), "silence is not consent");
        // And there is nothing left for a second click to reach.
        assert!(flight.take_verdict().is_none());
    }

    /// A verdict with nothing waiting for it is a click on a panel that has
    /// already moved on, and saying so beats pretending it landed.
    #[test]
    fn a_verdict_with_nothing_waiting_is_refused() {
        let flight = InFlight::default();
        assert!(pair_verdict(&flight, true).is_err());
    }

    /// What `pair_confirm` does, without an app to hold the state.
    fn pair_verdict(flight: &InFlight, accept: bool) -> Result<(), String> {
        match flight.take_verdict() {
            Some(tx) => tx.send(accept).map_err(|_| "the pairing already ended".to_owned()),
            None => Err("nothing is waiting for an answer".to_owned()),
        }
    }
}
