use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::process::Command;
use std::thread;
use std::time::Duration;

use serde_json::Value;

fn write_pong(stream: &mut UnixStream, protocol: u32) {
    writeln!(
        stream,
        r#"{{"result":"pong","version":"skew-fixture","protocol":{protocol},"min_protocol":1}}"#
    )
    .unwrap();
}

fn read_frame(reader: &mut BufReader<UnixStream>) -> Value {
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    serde_json::from_str(&line).unwrap()
}

#[test]
fn create_uses_core_pull_before_legacy_create_for_protocols_one_through_five() {
    for protocol in 1..=5 {
        let home = tempfile::tempdir().unwrap();
        let image = home.path().join("local.raw");
        fs::write(&image, vec![0x5a; 4096]).unwrap();

        let socket = home.path().join("astd.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        fs::set_permissions(&socket, fs::Permissions::from_mode(0o600)).unwrap();
        let server = thread::spawn(move || {
            // The compatibility probe for image preparation must be the only
            // frame on this connection: the fallback does the pull in core,
            // then drops it before opening the legacy Create connection.
            let (mut first, _) = listener.accept().unwrap();
            let mut first_reader = BufReader::new(first.try_clone().unwrap());
            let ping = read_frame(&mut first_reader);
            assert_eq!(ping["cmd"], "ping");
            write_pong(&mut first, protocol);
            first
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut unexpected = String::new();
            let read = first_reader.read_line(&mut unexpected).unwrap();
            assert_eq!(read, 0, "protocol {protocol} received an image frame");

            let (mut second, _) = listener.accept().unwrap();
            let mut second_reader = BufReader::new(second.try_clone().unwrap());
            let ping = read_frame(&mut second_reader);
            assert_eq!(ping["cmd"], "ping");
            write_pong(&mut second, protocol);
            let create = read_frame(&mut second_reader);
            assert_eq!(create["cmd"], "create");
            writeln!(second, r#"{{"result":"ok"}}"#).unwrap();
        });

        let output = Command::new(env!("CARGO_BIN_EXE_ast"))
            .env("ASTERISM_HOME", home.path())
            .args(["create", "skew", "--image"])
            .arg(&image)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "protocol {protocol} failed: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        server.join().unwrap();
    }
}

#[test]
fn local_images_and_pull_use_core_fallback_for_protocols_one_through_five() {
    for command in ["images", "pull"] {
        for protocol in 1..=5 {
            let home = tempfile::tempdir().unwrap();
            let image = home.path().join("local.raw");
            fs::write(&image, vec![0x33; 4096]).unwrap();

            let socket = home.path().join("astd.sock");
            let listener = UnixListener::bind(&socket).unwrap();
            fs::set_permissions(&socket, fs::Permissions::from_mode(0o600)).unwrap();
            let server = thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let ping = read_frame(&mut reader);
                assert_eq!(ping["cmd"], "ping");
                write_pong(&mut stream, protocol);
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut unexpected = String::new();
                let read = reader.read_line(&mut unexpected).unwrap();
                assert_eq!(read, 0, "{command} sent a protocol-6 image frame");
            });

            let mut args = vec![command.to_owned()];
            if command == "pull" {
                args.push(image.display().to_string());
            }
            let output = Command::new(env!("CARGO_BIN_EXE_ast"))
                .env("ASTERISM_HOME", home.path())
                .args(&args)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{command} protocol {protocol} failed: {}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            server.join().unwrap();
        }
    }
}
