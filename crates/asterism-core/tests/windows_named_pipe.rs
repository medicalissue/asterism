#![cfg(windows)]

use std::io::{self, Read, Write};

use asterism_core::ipc::{self, Door, SocketState};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use windows_sys::Win32::Security::{ImpersonateAnonymousToken, RevertToSelf};
use windows_sys::Win32::System::Threading::GetCurrentThread;

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
    assert_eq!(ipc::audit_socket(&sock).unwrap(), SocketState::Missing);
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
