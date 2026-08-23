//! Production guest endpoint for the local NVIDIA projection.
//!
//! This process runs inside an attached Linux guest. It owns the CUSE
//! `/dev/nvidia0`, listens only on AF_VSOCK port 1022, authenticates the
//! host helper with the instance key, and pumps framed CUDA calls. There is
//! no TCP listener and no bearer in the guest.

#[cfg(target_os = "linux")]
fn main() -> anyhow::Result<()> {
    linux::run()
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("asterism-gpu-guest runs only inside a Linux guest");
    std::process::exit(1);
}

#[cfg(target_os = "linux")]
mod linux {
    use std::fs::File;
    use std::io::{BufReader, Read};
    use std::os::fd::{FromRawFd, RawFd};
    use std::os::unix::net::UnixStream;
    use std::path::Path;

    use anyhow::{anyhow, bail, Context, Result};
    use asterism_core::remote_gpu_guest::{
        gpu_vsock_guest_handshake, project_guest_device, read_frame, write_frame, GuestDeviceKind,
        GuestFrame, GuestReply, GUEST_GPU_VSOCK_PORT,
    };

    const KEY_PATH: &str = "/etc/asterism/agent.key";

    pub fn run() -> Result<()> {
        let key = read_key(Path::new(KEY_PATH))?;
        let device =
            project_guest_device(Path::new("/")).context("mounting the guest CUSE /dev/nvidia0")?;
        if device.kind != GuestDeviceKind::Cuse {
            bail!("production GPU projection requires /dev/cuse");
        }
        let listener = vsock_listener(GUEST_GPU_VSOCK_PORT)?;
        loop {
            let host = listener.accept().context("accepting GPU host vsock")?;
            if let Err(err) = serve(host, &device, &key) {
                eprintln!("asterism-gpu-guest: session ended: {err:#}");
            }
        }
    }

    fn serve(
        mut host: UnixStream,
        device: &asterism_core::remote_gpu_guest::GuestDevice,
        key: &[u8; 32],
    ) -> Result<()> {
        host.set_read_timeout(Some(std::time::Duration::from_secs(30)))?;
        let mut host_reader = BufReader::new(host.try_clone()?);
        gpu_vsock_guest_handshake(&mut host_reader, &mut host, key, &nonce()?)
            .map_err(|err| anyhow!(err.message))?;
        host.set_read_timeout(None)?;

        let local = device
            .accept()
            .context("accepting libcuda on /dev/nvidia0")?;
        let mut local_reader = BufReader::new(local.try_clone()?);
        let mut local_writer = local;
        std::thread::scope(|scope| -> Result<()> {
            let upstream = scope.spawn(move || -> Result<()> {
                let outcome = (|| -> Result<()> {
                    loop {
                        let frame: GuestFrame =
                            read_frame(&mut local_reader).map_err(|err| anyhow!(err.message))?;
                        let closing = matches!(frame, GuestFrame::Close);
                        write_frame(&mut host, &frame).map_err(|err| anyhow!(err.message))?;
                        if closing {
                            break;
                        }
                    }
                    Ok(())
                })();
                let _ = host.shutdown(std::net::Shutdown::Both);
                outcome
            });
            let downstream = scope.spawn(move || -> Result<()> {
                let outcome = (|| -> Result<()> {
                    loop {
                        let reply: GuestReply =
                            read_frame(&mut host_reader).map_err(|err| anyhow!(err.message))?;
                        let closing = matches!(reply, GuestReply::Closed);
                        write_frame(&mut local_writer, &reply)
                            .map_err(|err| anyhow!(err.message))?;
                        if closing {
                            break;
                        }
                    }
                    Ok(())
                })();
                let _ = local_writer.shutdown(std::net::Shutdown::Both);
                outcome
            });
            upstream
                .join()
                .map_err(|_| anyhow!("device pump panicked"))??;
            downstream
                .join()
                .map_err(|_| anyhow!("host pump panicked"))??;
            Ok(())
        })
    }

    fn read_key(path: &Path) -> Result<[u8; 32]> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading instance key {}", path.display()))?;
        let text = text.trim();
        if text.len() != 64 {
            bail!("instance key must be 64 hexadecimal characters");
        }
        let mut key = [0u8; 32];
        for (index, byte) in key.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&text[index * 2..index * 2 + 2], 16)
                .context("instance key is not hexadecimal")?;
        }
        Ok(key)
    }

    fn nonce() -> Result<String> {
        let mut bytes = [0u8; 32];
        File::open("/dev/urandom")?.read_exact(&mut bytes)?;
        Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
    }

    struct VsockListener(RawFd);

    impl VsockListener {
        fn accept(&self) -> std::io::Result<UnixStream> {
            let fd = unsafe {
                libc::accept4(
                    self.0,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    libc::SOCK_CLOEXEC,
                )
            };
            if fd < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(unsafe { UnixStream::from_raw_fd(fd) })
        }
    }

    impl Drop for VsockListener {
        fn drop(&mut self) {
            unsafe { libc::close(self.0) };
        }
    }

    fn vsock_listener(port: u32) -> Result<VsockListener> {
        let fd = unsafe { libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error()).context("opening AF_VSOCK listener");
        }
        let outcome = bind_vsock(fd, port);
        if outcome.is_err() {
            unsafe { libc::close(fd) };
        }
        outcome?;
        Ok(VsockListener(fd))
    }

    fn bind_vsock(fd: RawFd, port: u32) -> Result<()> {
        let mut address: libc::sockaddr_vm = unsafe { std::mem::zeroed() };
        address.svm_family = libc::AF_VSOCK as libc::sa_family_t;
        address.svm_port = port;
        address.svm_cid = libc::VMADDR_CID_ANY;
        let bound = unsafe {
            libc::bind(
                fd,
                &address as *const libc::sockaddr_vm as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_vm>() as libc::socklen_t,
            )
        };
        if bound < 0 {
            return Err(std::io::Error::last_os_error())
                .with_context(|| format!("binding AF_VSOCK port {port}"));
        }
        if unsafe { libc::listen(fd, 16) } < 0 {
            return Err(std::io::Error::last_os_error()).context("listening on AF_VSOCK");
        }
        Ok(())
    }
}
