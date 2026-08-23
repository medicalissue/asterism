#![cfg(windows)]

use std::io::Read;
use std::os::windows::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const ATTACH_PARENT_PROCESS: u32 = u32::MAX;
const CREATE_NEW_CONSOLE: u32 = 0x0000_0010;
const CTRL_C_EVENT: u32 = 0;

#[link(name = "kernel32")]
extern "system" {
    fn AttachConsole(process_id: u32) -> i32;
    fn FreeConsole() -> i32;
    fn GenerateConsoleCtrlEvent(ctrl_event: u32, process_group_id: u32) -> i32;
    fn SetConsoleCtrlHandler(
        handler: Option<unsafe extern "system" fn(ctrl_type: u32) -> i32>,
        add: i32,
    ) -> i32;
}

fn wait_for_exit(child: &mut Child, timeout: Duration) -> Option<std::process::ExitStatus> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait().expect("querying astd") {
            return Some(status);
        }
        if Instant::now() >= deadline {
            return None;
        }
        thread::sleep(Duration::from_millis(50));
    }
}

struct KillOnDrop(Child);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn wait_until_listening(child: &mut Child, pidfile: &std::path::Path) {
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        assert!(
            child.try_wait().expect("querying astd").is_none(),
            "astd exited before publishing its pid file"
        );
        if pidfile.is_file() {
            return;
        }
        thread::sleep(Duration::from_millis(50));
    }
    panic!("astd did not publish its pid file within 30 seconds");
}

fn send_ctrl_c_to(child_pid: u32) {
    unsafe {
        // The test binary may share the runner's console. Detach, join the
        // child's private console, and ignore the event in this sender so the
        // daemon is the only process whose normal handler observes Ctrl-C.
        let _ = FreeConsole();
        assert_ne!(
            AttachConsole(child_pid),
            0,
            "attaching to astd console: {}",
            std::io::Error::last_os_error()
        );
        assert_ne!(
            SetConsoleCtrlHandler(None, 1),
            0,
            "ignoring Ctrl-C in test sender: {}",
            std::io::Error::last_os_error()
        );
        assert_ne!(
            GenerateConsoleCtrlEvent(CTRL_C_EVENT, 0),
            0,
            "sending Ctrl-C to astd console: {}",
            std::io::Error::last_os_error()
        );
        let _ = FreeConsole();
        let _ = AttachConsole(ATTACH_PARENT_PROCESS);
        let _ = SetConsoleCtrlHandler(None, 0);
    }
}

#[test]
fn console_ctrl_c_exits_without_waiting_for_the_scm_latch() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let home = dir.path().join("home");
    let child = Command::new(env!("CARGO_BIN_EXE_astd"))
        .env("ASTERISM_HOME", &home)
        .env("ASTERISM_MESH", "local")
        .creation_flags(CREATE_NEW_CONSOLE)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("starting astd in a private console");
    let mut child = KillOnDrop(child);

    wait_until_listening(&mut child.0, &home.join("astd.pid"));
    send_ctrl_c_to(child.0.id());

    // Before the fix, the Ctrl-C branch finishes but runtime destruction
    // waits forever for the losing spawn_blocking(SCM latch) task. Keep the
    // regression bounded so that failure produces useful Windows CI evidence.
    let status = match wait_for_exit(&mut child.0, Duration::from_secs(15)) {
        Some(status) => status,
        None => panic!("astd remained alive 15 seconds after console Ctrl-C"),
    };

    let mut stderr = String::new();
    child
        .0
        .stderr
        .take()
        .expect("captured astd stderr")
        .read_to_string(&mut stderr)
        .expect("reading astd stderr");
    assert!(status.success(), "astd exited with {status}: {stderr}");
    assert!(
        stderr.contains("astd: shutting down"),
        "astd did not take its clean shutdown path: {stderr}"
    );
    assert!(
        !home.join("astd.pid").exists(),
        "clean Ctrl-C left the daemon pid file behind"
    );
}
