#![cfg(windows)]

use std::io::{self, Read, Write};
use std::time::{Duration, Instant};

use asterism_core::ipc::{self, Door, SocketState};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use windows_sys::Win32::Security::{ImpersonateAnonymousToken, RevertToSelf};
use windows_sys::Win32::System::Threading::GetCurrentThread;

const CHILD_MODE: &str = "ASTERISM_WINDOWS_PIPE_CHILD";

#[tokio::test]
async fn real_named_pipe_round_trip_peer_identity_and_lifetime() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("home");
    let sock = home.join("astd.sock");
    let door = Door::open(&home, &sock).unwrap();
    assert_eq!(ipc::audit_socket(&sock).unwrap(), SocketState::Ready);
    assert!(
        !sock.exists(),
        "a named pipe must not leave an address file"
    );

    let client_sock = sock.clone();
    let client = std::thread::spawn(move || {
        let mut client = ipc::connect(&client_sock).unwrap();
        client.write_all(b"ping").unwrap();
        let mut reply = [0; 4];
        client.read_exact(&mut reply).unwrap();
        reply
    });
    let mut server = door.listener().accept().await.unwrap();
    let refusal = format!(
        "{:#}",
        ipc::refuse_peer_for_conformance(&server).unwrap_err()
    );
    assert!(
        refusal.contains("refusing Windows named-pipe peer SID"),
        "{refusal}"
    );
    assert_eq!(ipc::admit_peer(&server).unwrap(), ipc::own_uid());
    let mut request = [0; 4];
    server.read_exact(&mut request).await.unwrap();
    assert_eq!(&request, b"ping");
    server.write_all(b"pong").await.unwrap();
    assert_eq!(&client.join().unwrap(), b"pong");

    drop(server);
    drop(door);
    let deadline = Instant::now() + Duration::from_secs(2);
    while ipc::audit_socket(&sock).unwrap() != SocketState::Missing {
        // Mio's named-pipe registration shares the kernel handle with the
        // runtime until the reactor processes deregistration.
        assert!(
            Instant::now() < deadline,
            "the pipe name survived its last kernel handle"
        );
        tokio::task::yield_now().await;
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[tokio::test]
async fn pipe_acl_refuses_an_unauthorized_os_token() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("home");
    let sock = home.join("astd.sock");
    let _door = Door::open(&home, &sock).unwrap();
    let attempt = std::thread::spawn(move || {
        if unsafe { ImpersonateAnonymousToken(GetCurrentThread()) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let result = ipc::connect(&sock);
        unsafe {
            RevertToSelf();
        }
        result
    })
    .join()
    .unwrap();
    assert!(
        attempt.is_err(),
        "the current-user SID DACL admitted an anonymous token"
    );
}

#[test]
fn overlapped_client_read_honors_its_deadline() {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("home");
    let sock = home.join("astd.sock");
    let door = runtime.block_on(async { Door::open(&home, &sock).unwrap() });

    let client_sock = sock.clone();
    let client = std::thread::spawn(move || {
        let mut client = ipc::connect(&client_sock).unwrap();
        client
            .set_read_timeout(Some(std::time::Duration::from_millis(50)))
            .unwrap();
        let mut byte = [0; 1];
        client.read(&mut byte).unwrap_err().kind()
    });
    let _server = runtime.block_on(door.listener().accept()).unwrap();
    assert_eq!(client.join().unwrap(), io::ErrorKind::TimedOut);
}

#[test]
fn pipe_identity_is_stable_for_one_home_and_separates_home_paths() {
    let temp = tempfile::tempdir().unwrap();
    let first = temp.path().join("first");
    let second = temp.path().join("second");
    std::fs::create_dir_all(&first).unwrap();
    std::fs::create_dir_all(&second).unwrap();
    let first_sock = first.join("astd.sock");
    let first_again = ipc::pipe_name_for_conformance(&first, &first_sock).unwrap();
    assert_eq!(
        first_again,
        ipc::pipe_name_for_conformance(&first, &first_sock).unwrap()
    );
    assert_ne!(
        first_again,
        ipc::pipe_name_for_conformance(&second, &second.join("astd.sock")).unwrap(),
        "two paths owned by the same SID must still name different pipes"
    );
}

#[test]
fn unexpected_wait_and_cancel_failures_drain_pending_io_in_a_subprocess() {
    if std::env::var(CHILD_MODE).as_deref() == Ok("wait-failure") {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().join("home");
        let sock = home.join("astd.sock");
        let door = runtime.block_on(async { Door::open(&home, &sock).unwrap() });
        let mut client = ipc::connect(&sock).unwrap();
        let _server = runtime.block_on(door.listener().accept()).unwrap();
        std::env::set_var("ASTERISM_TEST_PIPE_WAIT_FAILURE", "1");
        std::env::set_var("ASTERISM_TEST_PIPE_CANCEL_FAILURE", "1");
        let mut byte = [0; 1];
        assert!(client.read(&mut byte).is_err());
        return;
    }

    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "unexpected_wait_and_cancel_failures_drain_pending_io_in_a_subprocess",
            "--nocapture",
        ])
        .env(CHILD_MODE, "wait-failure")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "pending I/O drain child failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn revert_failure_is_fail_stop_in_a_subprocess() {
    if std::env::var(CHILD_MODE).as_deref() == Ok("revert-failure") {
        ipc::force_revert_failure_for_conformance();
    }

    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "revert_failure_is_fail_stop_in_a_subprocess",
            "--nocapture",
        ])
        .env(CHILD_MODE, "revert-failure")
        .output()
        .unwrap();
    assert!(!output.status.success(), "RevertToSelf failure returned alive");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("fatal: RevertToSelf failed"),
        "fail-stop diagnostic was missing: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
