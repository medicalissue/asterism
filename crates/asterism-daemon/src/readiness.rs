//! One answer to "can I reach this guest right now", and one way of getting
//! it.
//!
//! There used to be two. `ast status` printed what the guest said about
//! itself — an agent snapshot read inside the guest from `/proc`, saying
//! that sshd was listening and cloud-init had finished — while `ast ssh` and
//! `ast exec` decided the same question by knocking on the guest's door from
//! this host. Both are true statements and they are not the same statement,
//! so a guest whose host-side networking was broken read as
//! `ssh listening · cloud-init done` on a page whose next line nobody could
//! act on (AST-162).
//!
//! So readiness is measured here, once, the way the commands that use it
//! measure it:
//!
//! * a cloud-image guest is ready when sshd sends its **banner** to this
//!   host — the same proof `ast ssh` waits for, and the reason a mere
//!   accepted connection is not enough (QEMU's user-mode net accepts on the
//!   guest's behalf, and something else can be bound to a forwarded port);
//! * an OCI guest has no sshd, and is ready when its agent completes an
//!   **authenticated** session and answers `status` — the same door
//!   `ast exec` uses;
//! * a native container is ready when its control socket answers.
//!
//! What the guest says about itself stays on the status page, because it is
//! worth reading. It just no longer decides anything.
//!
//! ### The last time it worked
//!
//! A refusal is much more useful next to the last time this guest did
//! answer, so that is remembered — in memory, for the life of the daemon,
//! keyed by instance. It is deliberately not durable: the honest answer
//! after a daemon restart is that this daemon has never seen the guest
//! answer, and writing a probe result into the registry on every `ast
//! status` would make a read command a write command.

use std::collections::BTreeMap;
use std::io::{BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::time::Duration;

use asterism_core::hv::{ImageKind, Readiness};
use asterism_core::instance::{now_unix, Instance, RuntimeKind, Status};

/// Long enough for a guest on the same host, short enough that a status of an
/// unreachable guest is still an interactive command. Both halves are spent
/// only when nothing answers.
const CONNECT: Duration = Duration::from_millis(400);
const REPLY: Duration = Duration::from_millis(600);

fn last_ready() -> MutexGuard<'static, BTreeMap<String, u64>> {
    static SEEN: OnceLock<Mutex<BTreeMap<String, u64>>> = OnceLock::new();
    SEEN.get_or_init(|| Mutex::new(BTreeMap::new()))
        // A panic inside this module's own short critical section would leave
        // bookkeeping unusable; take the table anyway rather than poison a
        // status command over it.
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

/// Forget what is remembered about `name`. Called when an instance is
/// removed, so a later instance of the same name cannot inherit its history.
pub fn forget(name: &str) {
    last_ready().remove(name);
}

/// Probe `inst`, and answer with what was proved and when it last was.
///
/// Blocking, and bounded by [`CONNECT`] + [`REPLY`]. Never mutates the
/// registry: readiness is a sample, and a sample is not a lifecycle event.
pub fn probe(inst: &Instance) -> Readiness {
    let attempt = attempt(inst);
    let mut seen = last_ready();
    match attempt {
        Ok(proof) => {
            let now = now_unix();
            seen.insert(inst.name.clone(), now);
            Readiness {
                ready: true,
                proof: Some(proof),
                reason: None,
                last_ready_unix: Some(now),
            }
        }
        Err(reason) => Readiness {
            ready: false,
            proof: None,
            reason: Some(reason),
            last_ready_unix: seen.get(&inst.name).copied(),
        },
    }
}

/// One probe. `Ok` names the door that answered; `Err` says what went wrong,
/// in the words the reader needs to act on it.
fn attempt(inst: &Instance) -> Result<String, String> {
    if inst.status != Status::Running {
        return Err(format!("{} is not running", inst.name));
    }
    let Some(handle) = &inst.handle else {
        return Err(format!(
            "{} has no guest handle yet, so there is nothing to reach",
            inst.name
        ));
    };
    if inst.runtime == RuntimeKind::Container {
        let Some(control) = &handle.container_control else {
            return Err("this container has no control socket".into());
        };
        #[cfg(unix)]
        return match std::os::unix::net::UnixStream::connect(&control.socket) {
            Ok(_) => Ok(format!("container control on {}", control.socket.display())),
            Err(error) => Err(format!(
                "container control on {}: {error}",
                control.socket.display()
            )),
        };
        #[cfg(not(unix))]
        return Err(format!(
            "this host cannot reach a native container's control socket at {}",
            control.socket.display()
        ));
    }
    let Some(endpoint) = &handle.endpoint else {
        return Err(format!(
            "{} is running with no guest endpoint recorded",
            inst.name
        ));
    };
    if inst.image_kind == ImageKind::OciRootfs {
        let Some((host, port)) = endpoint.control_target() else {
            return Err("this guest has no control endpoint to reach".into());
        };
        return oci_control(&inst.name, &host, port);
    }
    let (host, port) = endpoint.ssh_target();
    ssh_banner(&host, port)
}

/// Does sshd itself answer?
///
/// RFC 4253 has the server send its identification string first, so reading
/// one back proves sshd is serving rather than that something accepted a
/// connection. That distinction is the entire point: it is what `ast ssh`
/// waits for before it hands the session to `ssh`.
fn ssh_banner(host: &str, port: u16) -> Result<String, String> {
    let target = format!("{host}:{port}");
    let addr = resolve(&target)?;
    let probe = (|| -> std::io::Result<String> {
        let mut stream = TcpStream::connect_timeout(&addr, CONNECT)?;
        stream.set_read_timeout(Some(REPLY))?;
        let mut buf = [0u8; 256];
        let read = match stream.read(&mut buf) {
            Ok(read) => read,
            // A read that times out is the case this exists for, and it is
            // not a network error worth quoting an errno about: something
            // accepted the connection and is not sshd.
            Err(error) if silent(&error) => 0,
            Err(error) => return Err(error),
        };
        // Polite, and the same courtesy the vz helper's own hunt extends:
        // sshd logs a clean disconnect rather than a protocol error.
        let _ = stream.write_all(b"SSH-2.0-Asterism\r\n");
        Ok(String::from_utf8_lossy(&buf[..read]).trim().to_owned())
    })();
    match probe {
        Ok(banner) if banner.starts_with("SSH-") => Ok(format!("ssh banner from {target}")),
        // The case that made this worth writing: the port is open, so a
        // liveness check would pass, and nothing behind it is sshd.
        Ok(_) => Err(format!(
            "{target} accepts connections but sent no ssh banner within {}ms",
            REPLY.as_millis()
        )),
        Err(error) => Err(format!("ssh to {target}: {error}")),
    }
}

/// A read that came back with nothing rather than with a failure: the peer is
/// there and is saying nothing. Two spellings, because a socket read timeout
/// surfaces as `WouldBlock` on some platforms and `TimedOut` on others.
fn silent(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
    )
}

/// The authenticated agent door, for a guest that has no sshd at all.
fn oci_control(name: &str, host: &str, port: u16) -> Result<String, String> {
    let target = format!("{host}:{port}");
    let addr = resolve(&target)?;
    let key =
        match asterism_core::guest::Key::read(&asterism_core::paths::guest_agent_key_path(name)) {
            Ok(Some(key)) => key,
            Ok(None) => return Err(format!("{name} has no guest-control key on this device")),
            Err(error) => return Err(format!("reading {name}'s guest-control key: {error:#}")),
        };
    let session = (|| -> anyhow::Result<()> {
        let stream = TcpStream::connect_timeout(&addr, CONNECT)?;
        stream.set_read_timeout(Some(REPLY))?;
        stream.set_write_timeout(Some(REPLY))?;
        let reader = BufReader::new(stream.try_clone()?);
        asterism_core::guest::Session::open(reader, stream, &key)?.status()?;
        Ok(())
    })();
    match session {
        Ok(()) => Ok(format!("authenticated guest control on {target}")),
        Err(error) => Err(format!("guest control on {target}: {error:#}")),
    }
}

fn resolve(target: &str) -> Result<SocketAddr, String> {
    target
        .to_socket_addrs()
        .map_err(|error| format!("{target}: {error}"))?
        .next()
        .ok_or_else(|| format!("{target} resolves to no address"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    fn running(name: &str, port: u16) -> Instance {
        let mut inst: Instance = serde_json::from_str(
            r#"{"id":"i","name":"x","cpu_device":"laptop","status":"running",
                "created_at":0,"volumes":[],
                "machine":{"backend":"qemu","machine_type":"virt","cpu":"host","hv_version":"t"}}"#,
        )
        .unwrap();
        inst.name = name.to_owned();
        inst.handle = Some(asterism_core::hv::Handle {
            backend: "qemu".into(),
            pid: Some(1),
            proc: None,
            ctl: asterism_core::hv::ControlChannel::Qmp {
                path: "/nonexistent/qmp.sock".into(),
            },
            endpoint: Some(asterism_core::hv::GuestEndpoint::HostForward { ssh_port: port }),
            container_control: None,
            started_at: 0,
        });
        inst
    }

    /// The AST-162 regression, in the shape the bug arrived in: something is
    /// bound and accepting, and nothing behind it is a guest anybody can use.
    /// A port-open probe calls that ready. This must not.
    #[test]
    fn an_open_port_that_never_answers_is_not_ready() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        // Accept and say nothing at all, for as long as the probe waits.
        std::thread::spawn(move || {
            let mut held = Vec::new();
            while let Ok((stream, _)) = listener.accept() {
                held.push(stream);
            }
        });

        let inst = running("open-port-silent", port);
        let readiness = probe(&inst);
        assert!(!readiness.ready, "{readiness:?}");
        let reason = readiness.reason.unwrap();
        assert!(reason.contains(&format!("127.0.0.1:{port}")), "{reason}");
        assert!(reason.contains("sent no ssh banner"), "{reason}");
        assert_eq!(
            readiness.last_ready_unix, None,
            "this guest has never answered"
        );
        forget("open-port-silent");
    }

    /// The other half of the same lie: something answers promptly and it is
    /// not sshd. An accepted connection is not a guest, and neither is a
    /// reply that does not identify itself as ssh.
    #[test]
    fn a_port_that_answers_with_something_other_than_ssh_is_not_ready() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let _ = stream.write_all(b"HTTP/1.1 200 OK\r\n\r\n");
                let _ = stream.flush();
                std::thread::sleep(Duration::from_millis(200));
            }
        });

        let inst = running("open-port-wrong", port);
        let readiness = probe(&inst);
        assert!(!readiness.ready, "{readiness:?}");
        let reason = readiness.reason.unwrap();
        assert!(reason.contains("sent no ssh banner"), "{reason}");
        forget("open-port-wrong");
    }

    /// And the other half: something that does speak ssh is ready, and the
    /// moment it did is remembered for the refusal that may follow it.
    #[test]
    fn an_ssh_banner_is_the_proof_and_it_is_remembered() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let _ = stream.write_all(b"SSH-2.0-OpenSSH_9.6\r\n");
                let _ = stream.flush();
                std::thread::sleep(Duration::from_millis(200));
            }
        });

        let inst = running("banner", port);
        let ready = probe(&inst);
        assert!(ready.ready, "{ready:?}");
        assert!(ready.proof.unwrap().starts_with("ssh banner from"));

        // Nothing is listening now, so the next probe fails — and says when
        // it last worked instead of pretending it never did.
        let gone = probe(&inst);
        assert!(!gone.ready, "{gone:?}");
        assert!(gone.last_ready_unix.is_some(), "{gone:?}");
        forget("banner");
    }

    /// A stopped instance is answered from the row, without a probe: there is
    /// nothing to knock on, and saying so is not a network failure.
    #[test]
    fn a_stopped_instance_is_not_ready_and_is_not_probed() {
        let mut inst = running("stopped", 1);
        inst.status = Status::Stopped;
        inst.handle = None;
        let readiness = probe(&inst);
        assert!(!readiness.ready);
        assert!(readiness.reason.unwrap().contains("is not running"));
        forget("stopped");
    }
}
