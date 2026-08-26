//! Static authenticated control plane injected into direct-kernel OCI guests.
//!
//! The image is not expected to contain Python, systemd, sshd, or even a
//! shell. Asterism supplies this one audited binary beside its BusyBox init.
//! It listens only inside the guest, authenticates every connection with the
//! instance key, and keeps command output and lifetime bounded.

#[cfg(target_os = "linux")]
fn main() -> anyhow::Result<()> {
    linux::run()
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("asterism-guest runs only inside a Linux guest");
    std::process::exit(1);
}

#[cfg(target_os = "linux")]
mod linux {
    use std::fs::File;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::{IpAddr, TcpListener, TcpStream};
    use std::os::unix::process::{CommandExt, ExitStatusExt};
    use std::path::Path;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    use anyhow::{bail, Context, Result};
    use asterism_core::guest::{
        Accept, Answer, ExecWireResult, Facts, Hello, Key, Request, Status, Welcome,
        MAX_EXEC_OUTPUT_BYTES, MAX_EXEC_TIMEOUT, MAX_FRAME_BYTES, OCI_TCP_PORT, VERSIONS,
    };
    use data_encoding::BASE64;

    const KEY_PATH: &str = "/etc/asterism/agent.key";

    pub fn run() -> Result<()> {
        let key = Key::read(Path::new(KEY_PATH))?
            .ok_or_else(|| anyhow::anyhow!("no instance key at {KEY_PATH}"))?;
        let listener = TcpListener::bind(("0.0.0.0", OCI_TCP_PORT))
            .with_context(|| format!("binding OCI guest control port {OCI_TCP_PORT}"))?;
        for incoming in listener.incoming() {
            match incoming {
                Ok(stream) => {
                    if let Err(error) = serve(stream, &key) {
                        eprintln!("asterism-guest: session ended: {error:#}");
                    }
                }
                Err(error) => eprintln!("asterism-guest: accept failed: {error}"),
            }
        }
        Ok(())
    }

    fn serve(mut stream: TcpStream, key: &Key) -> Result<()> {
        stream.set_read_timeout(Some(Duration::from_secs(30)))?;
        stream.set_write_timeout(Some(Duration::from_secs(30)))?;
        let mut reader = BufReader::new(stream.try_clone()?);
        let guest_nonce = nonce()?;
        write_frame(
            &mut stream,
            &Hello {
                agent: "asterism".into(),
                versions: VERSIONS.to_vec(),
                nonce: guest_nonce.clone(),
            },
        )?;
        let accept: Accept = read_frame(&mut reader)?;
        if !VERSIONS.contains(&accept.version) {
            write_frame(
                &mut stream,
                &Welcome {
                    ok: false,
                    proof: String::new(),
                    error: Some(format!("unsupported protocol {}", accept.version)),
                    facts: None,
                },
            )?;
            return Ok(());
        }
        let expected = key.proof(accept.version, "host", &guest_nonce, &accept.nonce);
        if !constant_time_eq(&expected, &accept.proof) {
            write_frame(
                &mut stream,
                &Welcome {
                    ok: false,
                    proof: String::new(),
                    error: Some("the host did not prove the instance key".into()),
                    facts: None,
                },
            )?;
            return Ok(());
        }
        write_frame(
            &mut stream,
            &Welcome {
                ok: true,
                proof: key.proof(accept.version, "guest", &guest_nonce, &accept.nonce),
                error: None,
                facts: Some(facts()),
            },
        )?;
        stream.set_read_timeout(None)?;
        stream.set_write_timeout(None)?;

        loop {
            let request: Request = match read_frame(&mut reader) {
                Ok(request) => request,
                Err(error) if is_disconnect(&error) => return Ok(()),
                Err(error) => return Err(error),
            };
            let mut stop = false;
            let answer = match request.op.as_str() {
                "ping" => ok(request.id),
                "status" => Answer {
                    status: Some(status(&stream)),
                    ..ok(request.id)
                },
                "sync" => {
                    let started = Instant::now();
                    unsafe { libc::sync() };
                    Answer {
                        elapsed_ms: Some(started.elapsed().as_secs_f64() * 1000.0),
                        ..ok(request.id)
                    }
                }
                "stop" => {
                    stop = true;
                    ok(request.id)
                }
                "exec" if accept.version >= 2 => match exec(request.argv, request.timeout_ms) {
                    Ok(exec) => Answer {
                        exec: Some(exec),
                        ..ok(request.id)
                    },
                    Err(error) => refused(request.id, format!("{error:#}")),
                },
                "exec" => refused(request.id, "exec requires guest protocol 2".into()),
                other => refused(request.id, format!("this agent has no {other:?}")),
            };
            write_frame(&mut stream, &answer)?;
            if stop && answer.ok {
                unsafe { libc::sync() };
                let _ = Command::new("/.asterism/busybox")
                    .args(["poweroff", "-f"])
                    .spawn();
                return Ok(());
            }
        }
    }

    fn ok(id: u64) -> Answer {
        Answer {
            id,
            ok: true,
            error: None,
            status: None,
            elapsed_ms: None,
            exec: None,
        }
    }

    fn refused(id: u64, error: String) -> Answer {
        Answer {
            id,
            ok: false,
            error: Some(error),
            status: None,
            elapsed_ms: None,
            exec: None,
        }
    }

    fn exec(argv: Vec<String>, timeout_ms: Option<u64>) -> Result<ExecWireResult> {
        if argv.is_empty() {
            bail!("exec needs a non-empty argv");
        }
        let timeout = Duration::from_millis(timeout_ms.unwrap_or(30_000));
        if timeout.is_zero() || timeout > MAX_EXEC_TIMEOUT {
            bail!(
                "exec timeout must be between 1 ms and {} seconds",
                MAX_EXEC_TIMEOUT.as_secs()
            );
        }
        let mut command = Command::new(&argv[0]);
        command
            .args(&argv[1..])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .process_group(0);
        let mut child = command
            .spawn()
            .with_context(|| format!("executing {:?}", argv[0]))?;
        let pid = child.id() as i32;
        let stdout = child.stdout.take().context("exec stdout pipe is absent")?;
        let stderr = child.stderr.take().context("exec stderr pipe is absent")?;
        let out = std::thread::spawn(move || read_capped(stdout));
        let err = std::thread::spawn(move || read_capped(stderr));
        let deadline = Instant::now() + timeout;
        let (status, timed_out) = loop {
            if let Some(status) = child.try_wait()? {
                break (status, false);
            }
            if Instant::now() >= deadline {
                unsafe { libc::kill(-pid, libc::SIGKILL) };
                break (child.wait()?, true);
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        // A background descendant may still hold the capture pipes. Exec is
        // a bounded command, not a process supervisor, so its whole group is
        // retired when the leader returns.
        unsafe { libc::kill(-pid, libc::SIGKILL) };
        let (stdout, stdout_truncated) = out
            .join()
            .map_err(|_| anyhow::anyhow!("stdout capture panicked"))??;
        let (stderr, stderr_truncated) = err
            .join()
            .map_err(|_| anyhow::anyhow!("stderr capture panicked"))??;
        let status = if timed_out {
            124
        } else {
            status
                .code()
                .unwrap_or_else(|| 128 + status.signal().unwrap_or(1))
        };
        Ok(ExecWireResult {
            status,
            stdout_b64: BASE64.encode(&stdout),
            stderr_b64: BASE64.encode(&stderr),
            stdout_truncated,
            stderr_truncated,
        })
    }

    fn read_capped(mut reader: impl Read) -> Result<(Vec<u8>, bool)> {
        let mut kept = Vec::new();
        let mut truncated = false;
        let mut chunk = [0u8; 8192];
        loop {
            let read = reader.read(&mut chunk)?;
            if read == 0 {
                break;
            }
            let room = MAX_EXEC_OUTPUT_BYTES.saturating_sub(kept.len());
            let take = room.min(read);
            kept.extend_from_slice(&chunk[..take]);
            truncated |= take < read;
        }
        Ok((kept, truncated))
    }

    fn facts() -> Facts {
        Facts {
            hostname: hostname::get()
                .ok()
                .and_then(|name| name.into_string().ok())
                .unwrap_or_default(),
            boot_id: read_text("/proc/sys/kernel/random/boot_id"),
            kernel: read_text("/proc/sys/kernel/osrelease"),
            agent: format!("asterism-guest/{}", VERSIONS.last().copied().unwrap_or(1)),
        }
    }

    fn status(stream: &TcpStream) -> Status {
        let addrs = stream
            .local_addr()
            .ok()
            .map(|addr| addr.ip())
            .filter(|addr| !addr.is_unspecified())
            .into_iter()
            .collect::<Vec<IpAddr>>();
        Status {
            addrs,
            uptime_secs: read_text("/proc/uptime")
                .split_whitespace()
                .next()
                .and_then(|value| value.parse().ok())
                .unwrap_or(0.0),
            ssh: false,
            cloud_init: "not_applicable".into(),
            load1: read_text("/proc/loadavg")
                .split_whitespace()
                .next()
                .and_then(|value| value.parse().ok()),
            mem_available_kib: mem_available(),
        }
    }

    fn mem_available() -> Option<u64> {
        read_text("/proc/meminfo").lines().find_map(|line| {
            line.strip_prefix("MemAvailable:")?
                .split_whitespace()
                .next()?
                .parse()
                .ok()
        })
    }

    fn read_text(path: &str) -> String {
        std::fs::read_to_string(path)
            .unwrap_or_default()
            .trim()
            .to_owned()
    }

    fn nonce() -> Result<String> {
        let mut bytes = [0u8; 32];
        File::open("/dev/urandom")?.read_exact(&mut bytes)?;
        Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
    }

    fn constant_time_eq(left: &str, right: &str) -> bool {
        left.len() == right.len()
            && left
                .bytes()
                .zip(right.bytes())
                .fold(0u8, |diff, (a, b)| diff | (a ^ b))
                == 0
    }

    fn write_frame(writer: &mut impl Write, value: &impl serde::Serialize) -> Result<()> {
        let bytes = serde_json::to_vec(value)?;
        if bytes.len() > MAX_FRAME_BYTES {
            bail!("guest-control frame exceeds {MAX_FRAME_BYTES} bytes");
        }
        writer.write_all(&bytes)?;
        writer.write_all(b"\n")?;
        writer.flush()?;
        Ok(())
    }

    fn read_frame<T: serde::de::DeserializeOwned>(reader: &mut impl BufRead) -> Result<T> {
        let bytes = reader.fill_buf()?;
        if bytes.is_empty() {
            bail!("guest-control peer disconnected");
        }
        let mut line = Vec::new();
        loop {
            let available = reader.fill_buf()?;
            if available.is_empty() {
                bail!("guest-control peer disconnected mid-frame");
            }
            let take = available
                .iter()
                .position(|byte| *byte == b'\n')
                .map_or(available.len(), |index| index + 1);
            if line.len() + take > MAX_FRAME_BYTES + 1 {
                bail!("guest-control frame exceeds {MAX_FRAME_BYTES} bytes");
            }
            line.extend_from_slice(&available[..take]);
            reader.consume(take);
            if line.ends_with(b"\n") {
                break;
            }
        }
        Ok(serde_json::from_slice(&line)?)
    }

    fn is_disconnect(error: &anyhow::Error) -> bool {
        error.to_string().contains("disconnected")
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn exec_keeps_streams_separate_and_preserves_exit_status() {
            let result = exec(
                vec![
                    "/bin/sh".into(),
                    "-c".into(),
                    "printf out; printf err >&2; exit 7".into(),
                ],
                Some(2_000),
            )
            .unwrap();
            assert_eq!(result.status, 7);
            assert_eq!(BASE64.decode(result.stdout_b64.as_bytes()).unwrap(), b"out");
            assert_eq!(BASE64.decode(result.stderr_b64.as_bytes()).unwrap(), b"err");
            assert!(!result.stdout_truncated);
            assert!(!result.stderr_truncated);
        }

        #[test]
        fn exec_times_out_a_noisy_process_group_with_bounded_output() {
            let result = exec(
                vec![
                    "/bin/sh".into(),
                    "-c".into(),
                    "while :; do printf 1234567890; done".into(),
                ],
                Some(50),
            )
            .unwrap();
            assert_eq!(result.status, 124);
            assert_eq!(
                BASE64.decode(result.stdout_b64.as_bytes()).unwrap().len(),
                MAX_EXEC_OUTPUT_BYTES
            );
            assert!(result.stdout_truncated);
        }

        #[test]
        fn authenticated_tcp_session_executes_against_the_real_agent() {
            use std::io::BufReader;

            let key = Key::parse(&"11".repeat(32)).unwrap();
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = listener.local_addr().unwrap();
            let server_key = key.clone();
            let server = std::thread::spawn(move || {
                let (stream, _) = listener.accept().unwrap();
                serve(stream, &server_key).unwrap();
            });

            let stream = TcpStream::connect(addr).unwrap();
            let reader = BufReader::new(stream.try_clone().unwrap());
            let mut session = asterism_core::guest::Session::open(reader, stream, &key).unwrap();
            let result = session
                .exec(
                    vec!["/bin/sh".into(), "-c".into(), "printf live".into()],
                    Duration::from_secs(2),
                )
                .unwrap();
            assert_eq!(result.status, 0);
            assert_eq!(result.stdout, b"live");
            drop(session);
            server.join().unwrap();
        }
    }
}
