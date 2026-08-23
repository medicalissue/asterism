//! Guest GPU vsock hop: instance-HMAC on port 1022, then local astd.
//!
//! The helper proves possession of the per-instance key with the
//! `asterism-guest-gpu` transcript, then forwards length-prefixed guest
//! frames onto `astd`'s unix socket. No bearer, no public listener.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::Shutdown;
use std::os::unix::io::{FromRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use asterism_core::paths;
use asterism_core::protocol::{Request, Response};
use asterism_core::remote_gpu_guest::{
    gpu_vsock_host_handshake, read_frame, write_frame, GuestFrame, GuestReply, GUEST_GPU_VSOCK_PORT,
};

pub struct GpuHop {
    live: Arc<AtomicBool>,
}

impl GpuHop {
    pub fn attach(&mut self, fd: RawFd, key: [u8; 32], instance: String) {
        self.live.store(true, Ordering::SeqCst);
        let live = self.live.clone();
        std::thread::spawn(move || {
            let outcome = session(fd, key, &instance);
            live.store(false, Ordering::SeqCst);
            if let Err(err) = outcome {
                eprintln!("astd-vz: {instance}: GPU vsock hop ended: {err:#}");
            }
        });
    }

    pub fn live(&self) -> bool {
        self.live.load(Ordering::SeqCst)
    }
}

impl Default for GpuHop {
    fn default() -> Self {
        Self {
            live: Arc::new(AtomicBool::new(false)),
        }
    }
}

fn session(fd: RawFd, key: [u8; 32], instance: &str) -> Result<()> {
    let vsock = unsafe { UnixStream::from_raw_fd(fd) };
    vsock
        .set_read_timeout(Some(std::time::Duration::from_secs(30)))
        .context("setting the GPU vsock authentication timeout")?;
    let mut reader = BufReader::new(vsock.try_clone().context("cloning GPU vsock")?);
    let mut writer = vsock;
    gpu_vsock_host_handshake(&mut reader, &mut writer, &key, &fresh_nonce()?)
        .map_err(|err| anyhow!(err.message))?;
    writer
        .set_read_timeout(None)
        .context("clearing the GPU vsock authentication timeout")?;

    let mut astd = UnixStream::connect(paths::socket_path())
        .with_context(|| format!("connecting local astd for GPU instance {instance}"))?;
    let open = serde_json::to_vec(&Request::GpuGuestOpen {
        name: instance.to_owned(),
    })?;
    astd.write_all(&open)?;
    astd.write_all(b"\n")?;
    astd.flush()?;
    let mut astd_reader = BufReader::new(astd.try_clone()?);
    let accepted: Response = serde_json::from_str(&read_line(&mut astd_reader)?)
        .context("reading GpuGuestOpen reply")?;
    match accepted {
        Response::GpuGuestAccepted { .. } => {}
        Response::GpuGuestRefused { message, .. } => {
            anyhow::bail!("astd refused GPU guest open: {message}")
        }
        other => anyhow::bail!("unexpected astd reply to GPU guest open: {other:?}"),
    }

    // One pump per direction is load-bearing. Waiting for astd's reply
    // before reading another guest frame made the credit window and Cancel
    // unreachable on the actual VZ path.
    std::thread::scope(|scope| -> Result<()> {
        let upstream = scope.spawn(move || -> Result<()> {
            let outcome = (|| -> Result<()> {
                loop {
                    let frame: GuestFrame =
                        read_frame(&mut reader).map_err(|err| anyhow!(err.message))?;
                    let closing = matches!(frame, GuestFrame::Close);
                    let body = serde_json::to_vec(&Request::GpuGuestFrame { frame })?;
                    astd.write_all(&body)?;
                    astd.write_all(b"\n")?;
                    astd.flush()?;
                    if closing {
                        break;
                    }
                }
                Ok(())
            })();
            // Preserve the read half owned by the downstream clone until it
            // forwards GuestReply::Closed. Shutting down both halves here
            // races and discards the daemon's clean close acknowledgement.
            let _ = astd.shutdown(Shutdown::Write);
            outcome
        });
        let downstream = scope.spawn(move || -> Result<()> {
            let outcome = (|| -> Result<()> {
                loop {
                    let line = match read_line(&mut astd_reader) {
                        Ok(line) => line,
                        Err(err) if err.to_string().contains("closed") => break,
                        Err(err) => return Err(err),
                    };
                    let reply: Response = serde_json::from_str(&line)?;
                    match reply {
                        Response::GpuGuestReply { reply } => {
                            let closed = matches!(reply, GuestReply::Closed);
                            write_frame(&mut writer, &reply).map_err(|err| anyhow!(err.message))?;
                            if closed {
                                break;
                            }
                        }
                        Response::GpuGuestRefused { message, .. } => {
                            write_frame(
                                &mut writer,
                                &GuestReply::Refused {
                                    id: None,
                                    code: "astd".into(),
                                    message,
                                },
                            )
                            .map_err(|err| anyhow!(err.message))?;
                            break;
                        }
                        other => anyhow::bail!("unexpected astd GPU reply: {other:?}"),
                    }
                }
                Ok(())
            })();
            let _ = writer.shutdown(Shutdown::Both);
            outcome
        });
        upstream
            .join()
            .map_err(|_| anyhow!("GPU upstream pump panicked"))??;
        downstream
            .join()
            .map_err(|_| anyhow!("GPU downstream pump panicked"))??;
        Ok(())
    })?;
    let _ = GUEST_GPU_VSOCK_PORT;
    Ok(())
}

fn read_line(reader: &mut impl std::io::BufRead) -> Result<String> {
    let mut line = Vec::new();
    let n = reader
        .take((asterism_core::ipc::MAX_RESPONSE_FRAME + 1) as u64)
        .read_until(b'\n', &mut line)?;
    if n == 0 {
        anyhow::bail!("astd closed the GPU guest session");
    }
    if line.len() > asterism_core::ipc::MAX_RESPONSE_FRAME || !line.ends_with(b"\n") {
        anyhow::bail!("astd GPU guest response exceeded the local frame limit");
    }
    while matches!(line.last(), Some(b'\n' | b'\r')) {
        line.pop();
    }
    String::from_utf8(line).context("astd GPU guest response was not UTF-8")
}

fn fresh_nonce() -> Result<String> {
    asterism_vz::guest::nonce()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_half_close_preserves_the_daemon_close_acknowledgement() {
        let (mut upstream, daemon) = UnixStream::pair().unwrap();
        let mut downstream = BufReader::new(upstream.try_clone().unwrap());
        let daemon_thread = std::thread::spawn(move || {
            let mut reader = BufReader::new(daemon.try_clone().unwrap());
            let request: Request = serde_json::from_str(&read_line(&mut reader).unwrap()).unwrap();
            assert!(matches!(
                request,
                Request::GpuGuestFrame {
                    frame: GuestFrame::Close
                }
            ));
            let mut daemon = daemon;
            serde_json::to_writer(
                &mut daemon,
                &Response::GpuGuestReply {
                    reply: GuestReply::Closed,
                },
            )
            .unwrap();
            daemon.write_all(b"\n").unwrap();
        });

        serde_json::to_writer(
            &mut upstream,
            &Request::GpuGuestFrame {
                frame: GuestFrame::Close,
            },
        )
        .unwrap();
        upstream.write_all(b"\n").unwrap();
        upstream.shutdown(Shutdown::Write).unwrap();

        let response: Response =
            serde_json::from_str(&read_line(&mut downstream).unwrap()).unwrap();
        assert!(matches!(
            response,
            Response::GpuGuestReply {
                reply: GuestReply::Closed
            }
        ));
        daemon_thread.join().unwrap();
    }
}
