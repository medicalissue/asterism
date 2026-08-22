//! What the door does when a real `astd` is behind it.
//!
//! The unit tests in `transport` and in `asterism_core::ipc` make each rule
//! true in isolation. These make it true of the shipped binary, which is a
//! different claim: a limit that is only enforced on a socket a test built by
//! hand is a limit the daemon does not have. Every test here starts `astd`,
//! talks to it the way `ast` does — one JSON line in, one JSON line back —
//! and then asks the question that matters after any refusal, which is
//! whether the daemon is still serving everybody else.
//!
//! `ASTERISM_MESH=local` on every one of them: these are about the local
//! control plane, and a daemon that publishes itself to a discovery service
//! in a test is a daemon doing something a test did not ask for.

use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use asterism_core::backup;
use asterism_core::hv::Machine;
use asterism_core::instance::{Instance, Shape};
use asterism_core::ipc;
use asterism_core::protocol::{Request, Response};
use asterism_core::registry::Shard;
use asterism_core::verify::{self, Source};

/// An `astd` on a home of its own, killed when the test ends.
struct Daemon {
    child: Child,
    home: PathBuf,
    _dir: tempfile::TempDir,
}

impl Daemon {
    /// Start one on a fresh home and wait until it is answering.
    fn start() -> Daemon {
        let dir = tempfile::tempdir().expect("a temp dir");
        let home = dir.path().join("home");
        Daemon::on(dir, home)
    }

    /// Start one on a home somebody else prepared — the tests about what a
    /// previous daemon left behind.
    fn on(dir: tempfile::TempDir, home: PathBuf) -> Daemon {
        let spawned = spawn_logged(&home, &[]);
        let daemon = Daemon {
            child: spawned.child,
            home,
            _dir: dir,
        };
        let mut daemon = daemon;
        daemon.await_ready();
        daemon
    }

    /// Start one standing in for a build of another vintage.
    ///
    /// The same binary with a different range on it, which is the only way to
    /// hold two vintages in one tree without testing a previous release's
    /// bugs instead of this build's negotiation. See
    /// `asterism_core::compat`.
    fn speaking(min: u32, max: u32) -> Daemon {
        let dir = tempfile::tempdir().expect("a temp dir");
        let home = dir.path().join("home");
        let spawned = spawn_logged(
            &home,
            &[
                ("ASTERISM_MIN_PROTOCOL_VERSION", &min.to_string()),
                ("ASTERISM_PROTOCOL_VERSION", &max.to_string()),
            ],
        );
        let daemon = Daemon {
            child: spawned.child,
            home,
            _dir: dir,
        };
        let mut daemon = daemon;
        daemon.await_ready();
        daemon
    }

    fn sock(&self) -> PathBuf {
        self.home.join("astd.sock")
    }

    fn stderr(&mut self) -> String {
        let Some(mut stderr) = self.child.stderr.take() else {
            return "<stderr was already consumed>".into();
        };
        let mut said = String::new();
        match stderr.read_to_string(&mut said) {
            Ok(_) => said,
            Err(e) => format!("<could not read astd stderr: {e}>"),
        }
    }

    fn fail_startup(&mut self, reason: &str, last_probe: &str) -> ! {
        let status = match self.child.try_wait() {
            Ok(Some(status)) => status,
            Ok(None) => {
                let _ = self.child.kill();
                self.child
                    .wait()
                    .unwrap_or_else(|e| panic!("{reason}; could not reap astd: {e}"))
            }
            Err(e) => panic!("{reason}; could not inspect astd: {e}"),
        };
        panic!(
            "{reason} on {}\nlast readiness probe: {last_probe}\nchild exit: {status}\nchild stderr:\n{}",
            self.sock().display(),
            self.stderr()
        );
    }

    fn await_ready(&mut self) {
        let deadline = Instant::now() + Duration::from_secs(30);
        let mut last_probe = String::from("socket is absent");
        while Instant::now() < deadline {
            match self.child.try_wait() {
                Ok(Some(status)) => self.fail_startup(
                    &format!("astd exited before readiness with {status}"),
                    &last_probe,
                ),
                Ok(None) => {}
                Err(e) => self.fail_startup(
                    &format!("could not inspect astd while waiting for readiness: {e}"),
                    &last_probe,
                ),
            }

            match std::fs::symlink_metadata(self.sock()) {
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    last_probe = "socket is absent".into();
                    std::thread::sleep(Duration::from_millis(50));
                    continue;
                }
                Err(e) => {
                    last_probe = format!("socket metadata failed: {e}");
                    std::thread::sleep(Duration::from_millis(50));
                    continue;
                }
            }

            match ipc::audit_socket(&self.sock()) {
                Ok(ipc::SocketState::Ready) => match readiness_probe(&self.sock()) {
                    Ok(reply) if serde_json::from_str::<Response>(&reply).is_ok() => return,
                    Ok(reply) => last_probe = format!("unexpected ping reply: {reply:?}"),
                    Err(e) => last_probe = format!("socket probe failed: {e}"),
                },
                Ok(ipc::SocketState::Absent) => last_probe = "socket is absent".into(),
                Err(e) => last_probe = format!("socket audit failed: {e:#}"),
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        self.fail_startup("astd did not become ready within 30s", &last_probe);
    }

    /// One request, one reply, on a connection of its own — which is how
    /// `ast` asks, and what makes "is it still serving?" a real question.
    fn ask(&self, line: &str) -> String {
        let mut stream = UnixStream::connect(self.sock()).expect("connecting to astd");
        stream
            .set_read_timeout(Some(Duration::from_secs(30)))
            .unwrap();
        stream.write_all(line.as_bytes()).unwrap();
        stream.write_all(b"\n").unwrap();
        read_line(&mut stream)
    }

    fn ask_request(&self, request: &Request) -> Response {
        let line = serde_json::to_string(request).expect("encoding a request");
        let reply = self.ask(&line);
        serde_json::from_str(&reply).unwrap_or_else(|e| panic!("decoding {reply:?}: {e}"))
    }

    fn ask_current(&self, request: &Request) -> Response {
        let mut stream = UnixStream::connect(self.sock()).expect("connecting to astd");
        stream
            .set_read_timeout(Some(Duration::from_secs(30)))
            .unwrap();
        let ours = asterism_core::compat::ours();
        for request in [
            Request::Ping {
                protocol: ours.max,
                min_protocol: ours.min,
            },
            request.clone(),
        ] {
            let mut line = serde_json::to_vec(&request).unwrap();
            line.push(b'\n');
            stream.write_all(&line).unwrap();
            let reply = read_line(&mut stream);
            if !matches!(request, Request::Ping { .. }) {
                return serde_json::from_str(&reply).unwrap();
            }
        }
        unreachable!()
    }

    /// Still there, still answering, still this version.
    fn assert_serving(&self) {
        let pong = self.ask(r#"{"cmd":"ping"}"#);
        assert!(pong.contains("pong"), "astd stopped serving: {pong:?}");
    }

    fn signal(&self, sig: &str) {
        Command::new("kill")
            .args([sig, &self.child.id().to_string()])
            .status()
            .expect("kill");
    }

    fn wait_until_gone(&mut self) {
        let deadline = Instant::now() + Duration::from_secs(30);
        while Instant::now() < deadline {
            if matches!(self.child.try_wait(), Ok(Some(_))) {
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        panic!("astd did not exit");
    }

    /// Stop this daemon while keeping its home alive for a restart test.
    fn stop_preserving_home(&mut self) -> tempfile::TempDir {
        let _ = self.child.kill();
        let _ = self.child.wait();
        std::mem::replace(&mut self._dir, tempfile::tempdir().unwrap())
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn spawn(home: &Path, extra: &[(&str, &str)]) -> Child {
    let mut command = Command::new(env!("CARGO_BIN_EXE_astd"));
    command
        .env("ASTERISM_HOME", home)
        .env("ASTERISM_MESH", "local");
    for (key, value) in extra {
        command.env(key, value);
    }
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("starting astd")
}

struct LoggedChild {
    child: Child,
}

fn spawn_logged(home: &Path, extra: &[(&str, &str)]) -> LoggedChild {
    let mut command = Command::new(env!("CARGO_BIN_EXE_astd"));
    command
        .env("ASTERISM_HOME", home)
        .env("ASTERISM_MESH", "local");
    for (key, value) in extra {
        command.env(key, value);
    }
    let child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("starting astd");
    LoggedChild { child }
}

fn readiness_probe(sock: &Path) -> io::Result<String> {
    let mut stream = UnixStream::connect(sock)?;
    stream.set_read_timeout(Some(Duration::from_millis(250)))?;
    stream.write_all(b"{\"cmd\":\"ping\"}\n")?;
    let mut reply = String::new();
    BufReader::new(stream).read_line(&mut reply)?;
    Ok(reply)
}

fn read_line(stream: &mut UnixStream) -> String {
    let mut reply = String::new();
    BufReader::new(stream)
        .read_line(&mut reply)
        .expect("reading a reply");
    reply
}

/// Connect, allowing for the kernel's accept queue being briefly full.
///
/// A refused connect on a socket that is bound and being accepted on means
/// the backlog filled, which is a fact about `kern.ipc.somaxconn` and not
/// about the daemon.
fn connect_patiently(sock: &Path) -> UnixStream {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match UnixStream::connect(sock) {
            Ok(stream) => return stream,
            Err(e) if Instant::now() >= deadline => panic!("connecting to astd: {e}"),
            Err(_) => std::thread::sleep(Duration::from_millis(10)),
        }
    }
}

fn mode_of(path: &Path) -> u32 {
    std::fs::symlink_metadata(path)
        .unwrap()
        .permissions()
        .mode()
        & 0o7777
}

/// A move is not allowed to turn an old provenance claim into a new one.
///
/// This goes through the daemon socket and the real `MovePrepare` request,
/// rather than constructing a manifest or calling the verifier directly.
/// The same-length replacement matters: the refusal rests on comparing the
/// bytes, not on noticing that a file became a different size. `MovePrepare`
/// is also the first mutating move frame, so an unchanged registry proves the
/// check is on the safe side of that boundary.
#[test]
fn a_move_refuses_a_mutated_adopted_base_before_fencing_the_source() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    let images = home.join("images");
    std::fs::create_dir_all(&images).unwrap();

    let staged = images.join("debian-13.raw.part");
    let base = images.join("debian-13.raw");
    std::fs::write(&staged, b"trusted").unwrap();
    verify::adopt(
        &staged,
        &base,
        None,
        Source::new("base-image", "test publisher")
            .derived_from([format!("sha256:{}", "a".repeat(64))]),
    )
    .unwrap();

    let state = home.join("state.json");
    let mut shard = Shard::load(&state).unwrap();
    shard
        .create(
            "dev",
            "laptop",
            "debian:13",
            Shape::default(),
            Machine {
                backend: "qemu".into(),
                machine_type: "virt".into(),
                cpu: "host".into(),
                hv_version: "test".into(),
            },
        )
        .unwrap();
    shard.save().unwrap();

    // Same length, different content: only a real provenance verification
    // distinguishes this from what was adopted.
    std::fs::write(&base, b"mutated").unwrap();
    let state_before = std::fs::read(&state).unwrap();

    let astd = Daemon::on(dir, home.clone());
    let reply = astd.ask_request(&Request::MovePrepare {
        name: "dev".into(),
        to_device: "desktop".into(),
        epoch: 1,
    });
    let Response::Error { message } = reply else {
        panic!("a mutated source was offered to the move: {reply:?}");
    };
    assert!(
        message.contains("source bytes cannot be verified"),
        "{message}"
    );
    assert!(
        message.contains("has changed since it was pulled"),
        "{message}"
    );

    assert_eq!(
        std::fs::read(&state).unwrap(),
        state_before,
        "the refused move changed the source shard"
    );
    let Response::Instance { instance } = astd.ask_request(&Request::Status { name: "dev".into() })
    else {
        panic!("the source row could not be read after refusal");
    };
    assert!(
        instance.moving.is_none(),
        "the refused move mutated the source row"
    );
}

/// Import crosses the real socket and publishes bytes and identity once. A
/// second import proves the orbit-wide name gate is on the safe side of every
/// write rather than an overwrite disguised as idempotence.
#[test]
fn a_portable_backup_restores_once_and_refuses_a_name_collision() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("source");
    let export = dir.path().join("portable");
    std::fs::create_dir_all(&source).unwrap();
    let bytes = b"portable root disk\0with bytes";
    std::fs::write(source.join("disk.raw"), bytes).unwrap();
    let mut instance = Instance::new(
        "restored",
        "source-device",
        "debian:13",
        Shape::default(),
        Machine {
            backend: "qemu".into(),
            machine_type: "virt".into(),
            cpu: "host".into(),
            hv_version: "test".into(),
        },
    );
    // Import does not need the base image: its verified provenance is useful
    // for inspection, while the root disk is the complete restorable state.
    instance.image = None;
    backup::export(&instance, &source, &export, None).unwrap();

    let home = dir.path().join("home");
    let astd = Daemon::on(dir, home.clone());
    let request = Request::BackupImport {
        source: export.display().to_string(),
        name: "restored".into(),
    };
    let reply = astd.ask_current(&request);
    let Response::BackupRestored { report } = reply else {
        panic!("backup import was not restored: {reply:?}");
    };
    assert_eq!(report.id, instance.id);
    assert_eq!(
        std::fs::read(home.join("instances/restored/disk.raw")).unwrap(),
        bytes
    );

    let Response::Error { message } = astd.ask_current(&request) else {
        panic!("a second import overwrote the first");
    };
    assert!(
        message.contains("already exists in this orbit"),
        "{message}"
    );
    assert_eq!(
        std::fs::read(home.join("instances/restored/disk.raw")).unwrap(),
        bytes,
        "the collision changed the restored bytes"
    );
}

/// The import's only cross-file crash window is publication before the shard
/// commit. Its receipt makes that state distinguishable from somebody's
/// orphan directory, so the same request can verify and finish it safely.
#[test]
fn a_portable_restore_resumes_after_publication_wins_the_crash() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("source");
    let export = dir.path().join("portable");
    let home = dir.path().join("home");
    std::fs::create_dir_all(&source).unwrap();
    std::fs::write(source.join("disk.raw"), b"survived publication").unwrap();
    let mut instance = Instance::new(
        "recovered",
        "source-device",
        "debian:13",
        Shape::default(),
        Machine {
            backend: "qemu".into(),
            machine_type: "virt".into(),
            cpu: "host".into(),
            hv_version: "test".into(),
        },
    );
    instance.image = None;
    backup::export(&instance, &source, &export, None).unwrap();

    // Exactly what a kill after publish and before `reg.save()` leaves.
    let live = home.join("instances/recovered");
    backup::restore_to(&export, &live, "recovered").unwrap();
    assert!(live.join(".restore-receipt.json").exists());
    assert!(!home.join("state.json").exists());

    let astd = Daemon::on(dir, home.clone());
    let response = astd.ask_current(&Request::BackupImport {
        source: export.display().to_string(),
        name: "recovered".into(),
    });
    let Response::BackupRestored { report } = response else {
        panic!("published restore did not converge: {response:?}");
    };
    assert_eq!(report.id, instance.id);
    assert!(!live.join(".restore-receipt.json").exists());
    let Response::Instance { instance: held } = astd.ask_request(&Request::Status {
        name: "recovered".into(),
    }) else {
        panic!("the recovered row is not in the shard");
    };
    assert_eq!(held.id, instance.id);
}

/// The shape of the whole thing, on the binary that ships: state nobody else
/// can list, behind a socket nobody else can reach.
#[test]
fn the_state_directory_and_the_socket_are_private() {
    let astd = Daemon::start();
    assert_eq!(
        mode_of(&astd.home),
        0o700,
        "the home is listable by other users"
    );
    assert_eq!(
        mode_of(&astd.sock()),
        0o600,
        "the socket is reachable by other users"
    );
    for under in ["instances", "volumes", "guest-keys"] {
        assert_eq!(mode_of(&astd.home.join(under)), 0o700, "{under} is open");
    }
    assert_eq!(mode_of(&astd.home.join("astd.pid")), 0o600);
    assert_eq!(
        ipc::audit_socket(&astd.sock()).unwrap(),
        ipc::SocketState::Ready
    );
}

/// An `$ASTERISM_HOME` from any earlier astd is `0755`, and refusing to start
/// on one would refuse to start for every existing user. It is fixed, and
/// said out loud rather than silently.
#[test]
fn a_home_an_older_daemon_left_open_is_tightened_and_reported() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    std::fs::create_dir(&home).unwrap();
    std::fs::set_permissions(&home, PermissionsExt::from_mode(0o755)).unwrap();
    assert_eq!(mode_of(&home), 0o755, "the fixture home was not opened");

    let mut astd = Daemon::on(dir, home.clone());
    assert_eq!(mode_of(&home), 0o700);

    astd.signal("-TERM");
    astd.wait_until_gone();
    let said = astd.stderr();
    assert!(
        said.contains("0755"),
        "the daemon did not say what it found: {said}"
    );
}

/// The second-daemon race. Six start at once on one home with nothing there
/// yet; five have to lose, and — the half that matters — losing must not
/// disturb the one that won. Probe-then-unlink got both of those wrong: the
/// window between a probe and a bind is wide enough for every one of them to
/// unlink the socket the last one just bound.
#[test]
fn only_one_of_a_storm_of_daemons_takes_the_home() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    let mut racers: Vec<Child> = (0..6).map(|_| spawn(&home, &[])).collect();

    let deadline = Instant::now() + Duration::from_secs(30);
    let mut lost = 0;
    while Instant::now() < deadline && lost < 5 {
        lost = 0;
        for racer in racers.iter_mut() {
            if matches!(racer.try_wait(), Ok(Some(_))) {
                lost += 1;
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    let mut failures = 0;
    let mut alive = 0;
    for racer in racers.iter_mut() {
        match racer.try_wait() {
            Ok(Some(status)) => {
                assert!(
                    !status.success(),
                    "a daemon that lost the home exited as if it won"
                );
                failures += 1;
            }
            _ => alive += 1,
        }
    }
    assert_eq!(alive, 1, "{alive} daemons hold one home");
    assert_eq!(failures, 5);

    let sock = home.join("astd.sock");
    let mut stream = UnixStream::connect(&sock).expect("the winner is still listening");
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .unwrap();
    stream.write_all(b"{\"cmd\":\"ping\"}\n").unwrap();
    assert!(
        read_line(&mut stream).contains("pong"),
        "the losers took the winner's socket"
    );

    for mut racer in racers {
        let _ = racer.kill();
        let _ = racer.wait();
    }
}

/// A daemon told to stop takes its socket and its pid file with it, and the
/// next one starts on a clean home. This is `ast` retiring a daemon across an
/// upgrade, which happens on every user's machine.
#[test]
fn a_daemon_that_is_asked_to_stop_leaves_nothing_behind_for_the_next_one() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    let mut first = Daemon::on(dir, home.clone());
    first.signal("-TERM");
    first.wait_until_gone();

    assert!(
        !home.join("astd.sock").exists(),
        "the socket was left behind"
    );
    assert!(
        !home.join("astd.pid").exists(),
        "the pid file was left behind"
    );

    let second = Daemon::on(tempfile::tempdir().unwrap(), home);
    second.assert_serving();
}

/// A daemon that is killed outright leaves its socket file exactly where it
/// was. It is stale, and it may not stop the next daemon starting — the
/// socket is unlinked under the election, and the election itself is released
/// by the kernel when its holder dies, which is the whole reason it is a lock
/// and not a file with a pid in it.
#[test]
fn a_socket_left_by_a_killed_daemon_does_not_stop_the_next_one() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    let mut killed = Daemon::on(dir, home.clone());
    killed.signal("-KILL");
    killed.wait_until_gone();

    assert!(
        home.join("astd.sock").exists(),
        "this test is about the leftover socket"
    );
    assert!(
        UnixStream::connect(home.join("astd.sock")).is_err(),
        "and about nobody behind it"
    );

    let next = Daemon::on(tempfile::tempdir().unwrap(), home);
    next.assert_serving();
}

/// A peer that starts a line and never ends it must not get to choose how
/// much memory the daemon holds, and must not take anybody else down with it.
#[test]
fn an_oversized_frame_is_refused_in_words_and_the_daemon_keeps_serving() {
    let astd = Daemon::start();
    let mut stream = UnixStream::connect(astd.sock()).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(60)))
        .unwrap();

    let chunk = vec![b'a'; 64 * 1024];
    let mut sent = 0usize;
    // Comfortably past the cap, and never a newline. The write ends either
    // here or when astd drops its end; both are the daemon doing its job.
    while sent < ipc::MAX_REQUEST_FRAME + (1 << 20) {
        if stream.write_all(&chunk).is_err() {
            break;
        }
        sent += chunk.len();
    }
    let refusal = read_line(&mut stream);
    assert!(
        refusal.contains("before its newline"),
        "no refusal came back: {refusal:?}"
    );
    drop(stream);

    astd.assert_serving();
}

/// A request of exactly the limit is served, on the shipped binary.
///
/// The cap is on what a peer may make the daemon hold, so the boundary is on
/// the accepting side of it — and the padding is whitespace because that is
/// what makes a frame of exactly this length still a request the daemon can
/// answer, rather than a refusal that would have looked the same either way.
#[test]
fn a_request_of_exactly_the_limit_is_answered() {
    let astd = Daemon::start();
    let mut frame = String::from(r#"{"cmd":"ping"}"#);
    frame.push_str(&" ".repeat(ipc::MAX_REQUEST_FRAME - frame.len()));
    assert_eq!(frame.len(), ipc::MAX_REQUEST_FRAME);

    let mut stream = UnixStream::connect(astd.sock()).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(60)))
        .unwrap();
    stream.write_all(frame.as_bytes()).unwrap();
    stream
        .write_all(
            b"
",
        )
        .unwrap();
    let reply = read_line(&mut stream);
    assert!(
        reply.contains("pong"),
        "a frame of exactly the limit was refused: {reply:?}"
    );
}

/// The merge queue's own repro, against the shipped binary.
///
/// Exactly the limit, then — once the daemon has taken it — one more byte
/// together with the terminator. The cap used to be consulted only on the
/// path where a chunk carried no newline, so that last byte arrived on the
/// path that counted nothing and a limit+1 frame reached the JSON parser: the
/// tell was `bad request: expected value` where the oversize refusal should
/// have been. Asserting on the refusal alone would not catch a regression
/// that merely changed the parse error, so this asserts on both.
#[test]
fn a_request_that_goes_over_in_the_chunk_carrying_its_newline_is_refused() {
    let astd = Daemon::start();
    let mut stream = UnixStream::connect(astd.sock()).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(60)))
        .unwrap();

    // Exactly the limit, no terminator. `write_all` returns once the daemon
    // has drained it, which leaves its buffer holding exactly the limit.
    stream
        .write_all(&vec![b'a'; ipc::MAX_REQUEST_FRAME])
        .unwrap();
    stream.flush().unwrap();
    std::thread::sleep(Duration::from_millis(200));
    // The byte that goes over, and the newline, in one write.
    stream
        .write_all(
            b"x
",
        )
        .unwrap();

    let reply = read_line(&mut stream);
    assert!(
        !reply.contains("bad request"),
        "a frame one byte over the limit reached the parser: {reply:?}"
    );
    assert!(
        reply.contains("before its newline"),
        "expected the oversize refusal: {reply:?}"
    );
    drop(stream);

    astd.assert_serving();
}

/// A frame that is not JSON is answered and the connection carries on: this
/// is the arm a newer `ast` lands on when it names a request an older daemon
/// has never heard of, and `ast` reads the wording to decide whether to
/// restart the daemon.
#[test]
fn a_frame_that_is_not_json_is_answered_and_the_connection_survives_it() {
    let astd = Daemon::start();
    let mut stream = UnixStream::connect(astd.sock()).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .unwrap();
    let mut reader = BufReader::new(stream.try_clone().unwrap());

    for bad in [
        r#"{"cmd":"#,
        r#"{"cmd":"no-such-command"}"#,
        "not json at all",
    ] {
        stream.write_all(bad.as_bytes()).unwrap();
        stream.write_all(b"\n").unwrap();
        let mut reply = String::new();
        reader.read_line(&mut reply).unwrap();
        assert!(reply.contains("bad request"), "{bad} got {reply}");
    }

    // The same connection, still good for a real request.
    stream.write_all(b"{\"cmd\":\"ping\"}\n").unwrap();
    let mut pong = String::new();
    reader.read_line(&mut pong).unwrap();
    assert!(pong.contains("pong"), "{pong}");
}

/// Empty lines are not frames and are not errors — the wire is
/// line-delimited, and a peer that sends a bare newline has said nothing.
#[test]
fn a_blank_line_is_not_a_request() {
    let astd = Daemon::start();
    let mut stream = UnixStream::connect(astd.sock()).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .unwrap();
    stream.write_all(b"\n   \n{\"cmd\":\"ping\"}\n").unwrap();
    assert!(read_line(&mut stream).contains("pong"));
}

/// The connection cap is a cap on what one peer can make the daemon hold, and
/// a peer that goes past it is turned away with something to read. Slots come
/// back when connections drop, which is what keeps the cap from being a
/// one-way door.
#[test]
fn connections_past_the_cap_are_turned_away_and_the_slots_come_back() {
    let astd = Daemon::start();
    let mut held: Vec<UnixStream> = Vec::new();
    for n in 0..ipc::MAX_CONNECTIONS {
        held.push(connect_patiently(&astd.sock()));
        // Paced, because the kernel's accept queue is smaller than the cap
        // and is nothing to do with it: `kern.ipc.somaxconn` is 128 on a
        // stock macOS, so 256 connects in a tight loop are refused by the
        // backlog before the daemon has been asked anything. What is under
        // test is what the daemon does once it has them.
        if n % 32 == 31 {
            std::thread::sleep(Duration::from_millis(50));
        }
    }
    // A connection takes its slot when it is admitted, which is on the task
    // that will serve it rather than in the accept loop. Give those a moment.
    std::thread::sleep(Duration::from_millis(500));

    let mut over = UnixStream::connect(astd.sock()).expect("the listener still accepts");
    over.set_read_timeout(Some(ipc::ACCEPT_WAIT + Duration::from_secs(30)))
        .unwrap();
    let refusal = read_line(&mut over);
    assert!(
        refusal.contains("limit"),
        "a connection past the cap was served: {refusal:?}"
    );
    drop(over);

    held.clear();
    std::thread::sleep(Duration::from_millis(500));
    astd.assert_serving();
}

// ---- skew: two vintages on one socket ---------------------------------------
//
// The unit tests in `asterism_core::compat` make the selection rule true.
// These make it true of the shipped `astd`, which is the different claim that
// matters: a negotiation that has only ever run in a unit test is a
// negotiation that has never met a socket.
//
// Every leg is a real daemon, started with a real range on it, asked in the
// bytes `ast` really writes.

/// A daemon one release behind — protocol 1, the wire as it was before it had
/// a number — is *spoken to*, at protocol 1, and it serves.
///
/// This is the leg the old behaviour got wrong twice: it compared crate
/// versions, found a difference, and replaced a running daemon that was
/// perfectly able to answer. Here the answer arrives.
#[test]
fn a_daemon_one_release_behind_is_spoken_to_at_its_own_wire() {
    let astd = Daemon::speaking(1, 1);

    // `ast` opens with its range. The old daemon's reply says what it has.
    let pong = astd.ask(r#"{"cmd":"ping","protocol":2,"min_protocol":1}"#);
    assert!(pong.contains(r#""result":"pong""#), "{pong}");
    assert!(
        pong.contains(r#""protocol":1"#),
        "the old daemon says what it speaks: {pong}"
    );

    // And then it serves, because protocol 1 is inside this build's window.
    let listed = astd.ask(r#"{"cmd":"list"}"#);
    assert!(listed.contains(r#""result":"instances""#), "{listed}");

    // The one frame that is newer than that wire is refused by name, in a
    // sentence naming the version it needs — not as a serde error about a
    // variant the user never typed, and not by dropping the connection.
    let refused = astd.ask(r#"{"cmd":"compat"}"#);
    assert!(refused.contains(r#""result":"error""#), "{refused}");
    assert!(
        refused.contains("compat frame"),
        "the refusal names the frame: {refused}"
    );
    assert!(
        refused.contains("protocol 2"),
        "and the version it needs: {refused}"
    );
    assert!(
        refused.contains("Every other command works"),
        "and that it is the one command affected: {refused}"
    );
    assert!(!refused.contains("unknown variant"), "{refused}");

    astd.assert_serving();
}

/// The mirrored leg: an *older* `ast` against a daemon of this build. The old
/// CLI sends the bare `ping` it has always sent, and every command it knows
/// keeps working — at protocol 1, chosen by the daemon from the absence of a
/// range rather than guessed.
#[test]
fn an_older_cli_is_served_at_the_wire_it_has() {
    let astd = Daemon::start();

    let pong = astd.ask(r#"{"cmd":"ping"}"#);
    assert!(pong.contains(r#""result":"pong""#), "{pong}");

    let listed = astd.ask(r#"{"cmd":"list"}"#);
    assert!(listed.contains(r#""result":"instances""#), "{listed}");

    astd.assert_serving();
}

/// A daemon from the future that has dropped this build's wire. Refused in a
/// sentence on the connection that asked — and the connection is the only
/// thing that ends. Nothing is signalled, because taking a newer daemon's
/// place is a downgrade.
#[test]
fn a_daemon_that_has_left_our_wire_behind_refuses_in_words_and_keeps_serving() {
    let astd = Daemon::speaking(40, 41);

    let refusal = astd.ask(r#"{"cmd":"ping","protocol":2,"min_protocol":1}"#);
    assert!(refusal.contains(r#""result":"error""#), "{refusal}");
    assert!(refusal.contains("protocol"), "{refusal}");
    assert!(
        refusal.contains("upgrade"),
        "a refusal with no repair in it is half a sentence: {refusal}"
    );

    // The refusal ended that conversation, not the daemon. A peer of its own
    // vintage is still served.
    let pong = astd.ask(r#"{"cmd":"ping","protocol":41,"min_protocol":40}"#);
    assert!(pong.contains(r#""result":"pong""#), "{pong}");
}

/// The window is a range, so a daemon whose ceiling is *above* ours is not a
/// refusal — it is a conversation at our ceiling, as long as its floor still
/// reaches us. Without this, two halves could never be one release apart and
/// every upgrade would be a flag day.
#[test]
fn a_newer_daemon_that_still_serves_our_wire_is_spoken_to_at_ours() {
    let astd = Daemon::speaking(1, 9);

    let pong = astd.ask(r#"{"cmd":"ping","protocol":2,"min_protocol":1}"#);
    assert!(pong.contains(r#""result":"pong""#), "{pong}");
    assert!(pong.contains(r#""protocol":9"#), "{pong}");

    // Frames at the version we chose are served. The daemon is newer; the
    // conversation is not.
    let listed = astd.ask(r#"{"cmd":"list"}"#);
    assert!(listed.contains(r#""result":"instances""#), "{listed}");

    astd.assert_serving();
}

/// A downgrade is refused before anything is touched.
///
/// The home is stamped by a build from the future, and then a daemon of this
/// vintage is started on it. It must not come up — and it must not come up
/// *without having written anything*, which is the whole difference between
/// refusing at the door and refusing three stores into startup.
#[test]
fn a_home_a_newer_build_wrote_is_refused_before_the_daemon_touches_it() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    let stamped = r#"{"version":1,"protocol":99,"asterism":"99.0.0",
            "stores":{"registry":99,"orbit":1,"volumes":1,"secrets":1,"seed":4},
            "written_at":1700000000}"#;
    std::fs::write(home.join("home.json"), stamped).unwrap();

    let mut child = Command::new(env!("CARGO_BIN_EXE_astd"))
        .env("ASTERISM_HOME", &home)
        .env("ASTERISM_MESH", "local")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("running astd");

    // Bounded on purpose. A daemon that comes up anyway is the regression
    // this test exists to catch, and a regression must fail rather than hang.
    let status = wait_for_exit(&mut child, Duration::from_secs(30))
        .expect("astd started on a home a newer build wrote");
    assert!(!status.success(), "a downgrade started anyway");

    let mut said = String::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut said)
        .unwrap();
    assert!(
        said.contains("registry format 99"),
        "it must name what it would drop: {said}"
    );
    assert!(
        said.contains("99.0.0"),
        "and the build that wrote it: {said}"
    );
    assert!(said.contains("upgrade Asterism"), "and the repair: {said}");

    // Refused *before mutation*: the daemon never got as far as opening a
    // door or writing a store, so the home is exactly as it was found.
    assert!(
        !home.join("astd.sock").exists(),
        "the door was opened before the refusal"
    );
    assert!(
        !home.join("state.json").exists(),
        "a store was written before the refusal"
    );
    assert_eq!(
        std::fs::read_to_string(home.join("home.json")).unwrap(),
        stamped,
        "the stamp itself was rewritten, so the evidence of the newer build is gone"
    );
}

/// And the ordinary case it must not break: a home this build owns is stamped
/// and served, and starting again on the same home writes nothing.
#[test]
fn a_home_this_build_owns_is_stamped_once_and_then_left_alone() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let home = dir.path().join("home");
    let mut astd = Daemon::on(dir, home);
    astd.assert_serving();

    let stamp = std::fs::read_to_string(astd.home.join("home.json"))
        .expect("a daemon that came up stamped the home it came up on");
    let written: asterism_core::compat::HomeStamp = serde_json::from_str(&stamp).unwrap();
    assert_eq!(written.protocol, asterism_core::compat::PROTOCOL_VERSION);
    assert_eq!(written.stores, asterism_core::compat::stores());

    // A second daemon on the same home rewrites nothing: a stamp that churned
    // on every start would be a write on every boot, for no news.
    let home = astd.home.clone();
    let preserved_dir = astd.stop_preserving_home();
    let spawned = spawn_logged(&home, &[]);
    let mut second = Daemon {
        child: spawned.child,
        home: home.clone(),
        _dir: tempfile::tempdir().unwrap(),
    };
    second.await_ready();
    assert_eq!(
        std::fs::read_to_string(home.join("home.json")).unwrap(),
        stamp,
        "the stamp was rewritten for no news"
    );
    drop(second);
    drop(preserved_dir);
}

/// Wait for a child to exit, or give up.
fn wait_for_exit(child: &mut Child, patience: Duration) -> Option<std::process::ExitStatus> {
    let deadline = Instant::now() + patience;
    while Instant::now() < deadline {
        match child.try_wait() {
            Ok(Some(status)) => return Some(status),
            Ok(None) => std::thread::sleep(Duration::from_millis(50)),
            Err(e) => panic!("waiting on astd: {e}"),
        }
    }
    let _ = child.kill();
    let _ = child.wait();
    None
}
