//! Guest GPU vsock hop: instance-HMAC on port 1022, then local astd.
//!
//! The helper proves possession of the per-instance key with the
//! `asterism-guest-gpu` transcript, then forwards length-prefixed guest
//! frames onto `astd`'s unix socket. No bearer, no public listener.

use std::io::{BufReader, Write};
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
        .ok();
    let mut reader = BufReader::new(vsock.try_clone().context("cloning GPU vsock")?);
    let mut writer = vsock;
    gpu_vsock_host_handshake(&mut reader, &mut writer, &key, &fresh_nonce()?)
        .map_err(|err| anyhow!(err.message))?;

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

    loop {
        let frame: GuestFrame = read_frame(&mut reader).map_err(|err| anyhow!(err.message))?;
        let closing = matches!(frame, GuestFrame::Close);
        let body = serde_json::to_vec(&Request::GpuGuestFrame { frame })?;
        astd.write_all(&body)?;
        astd.write_all(b"\n")?;
        astd.flush()?;
        let reply: Response = serde_json::from_str(&read_line(&mut astd_reader)?)?;
        match reply {
            Response::GpuGuestReply { reply } => {
                write_frame(&mut writer, &reply).map_err(|err| anyhow!(err.message))?;
            }
            Response::GpuGuestRefused { message, .. } => {
                write_frame(
                    &mut writer,
                    &GuestReply::Refused {
                        code: "astd".into(),
                        message,
                    },
                )
                .map_err(|err| anyhow!(err.message))?;
            }
            other => anyhow::bail!("unexpected astd GPU reply: {other:?}"),
        }
        if closing {
            let _ = serde_json::to_writer(&mut astd, &Request::GpuGuestClose);
            let _ = astd.write_all(b"\n");
            break;
        }
    }
    let _ = GUEST_GPU_VSOCK_PORT;
    Ok(())
}

fn read_line(reader: &mut impl std::io::BufRead) -> Result<String> {
    let mut line = String::new();
    let n = reader.read_line(&mut line)?;
    if n == 0 {
        anyhow::bail!("astd closed the GPU guest session");
    }
    Ok(line)
}

fn fresh_nonce() -> Result<String> {
    asterism_vz::guest::nonce()
}
