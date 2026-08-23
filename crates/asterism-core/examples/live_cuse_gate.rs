//! Fail-closed Linux CUSE lifecycle gate.
//!
//! This is deliberately an example rather than an ordinary test: absence or
//! inaccessibility of `/dev/cuse` is a gate failure, never a skipped test.

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("CUSE LIVE GATE FAIL: host kernel is not Linux");
    std::process::exit(1);
}

#[cfg(target_os = "linux")]
fn main() {
    if let Err(error) = linux::run() {
        eprintln!("CUSE LIVE GATE FAIL: {error}");
        std::process::exit(1);
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::error::Error;
    use std::fs::{self, OpenOptions};
    use std::io::{self, Read, Write};
    use std::os::unix::fs::FileTypeExt;
    use std::os::unix::io::AsRawFd;
    use std::sync::mpsc;
    use std::thread;
    use std::time::{Duration, Instant};

    use asterism_core::remote_gpu_cuse::CuseService;

    unsafe extern "C" fn absorb_signal(_: libc::c_int) {}

    pub fn run() -> Result<(), Box<dyn Error>> {
        let source_commit = std::env::var("ASTERISM_CUSE_TARGET_COMMIT")
            .map_err(|_| "ASTERISM_CUSE_TARGET_COMMIT is required")?;
        println!("target_commit={source_commit}");

        let root = tempfile::tempdir()?;
        let dev_dir = root.path().join("dev");
        fs::create_dir(&dev_dir)?;
        let guest = dev_dir.join("nvidia0");

        let service = CuseService::mount(&guest)
            .map_err(|error| format!("mount /dev/cuse and publish {guest:?}: {error}"))?;
        if !fs::metadata(&guest)?.file_type().is_char_device() {
            return Err(format!("{} is not a character device", guest.display()).into());
        }
        println!("phase=mount result=pass node={}", guest.display());

        thread::scope(|scope| -> Result<(), Box<dyn Error>> {
            let accepted = scope.spawn(|| service.accept());
            let mut client = OpenOptions::new().read(true).write(true).open(&guest)?;
            let mut server = accepted
                .join()
                .map_err(|_| "CUSE accept thread panicked")??;
            require_unix_socket(server.as_raw_fd())?;
            println!("phase=open result=pass transport=AF_UNIX tcp=false");

            client.write_all(b"kernel-write")?;
            let mut written = [0u8; 12];
            server.read_exact(&mut written)?;
            if &written != b"kernel-write" {
                return Err("CUSE write changed payload bytes".into());
            }
            println!("phase=write result=pass bytes={}", written.len());

            server.write_all(b"poll-read")?;
            let mut pollfd = libc::pollfd {
                fd: client.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            let ready = unsafe { libc::poll(&mut pollfd, 1, 1_000) };
            if ready != 1 || pollfd.revents & libc::POLLIN == 0 {
                return Err(format!(
                    "CUSE poll did not report readable data: ready={ready} revents={}",
                    pollfd.revents
                )
                .into());
            }
            println!("phase=poll result=pass revents={}", pollfd.revents);

            let mut reply = [0u8; 9];
            client.read_exact(&mut reply)?;
            if &reply != b"poll-read" {
                return Err("CUSE read changed payload bytes".into());
            }
            println!("phase=read result=pass bytes={}", reply.len());

            let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
            action.sa_sigaction = absorb_signal as *const () as usize;
            action.sa_flags = 0;
            unsafe { libc::sigemptyset(&mut action.sa_mask) };
            let mut previous: libc::sigaction = unsafe { std::mem::zeroed() };
            if unsafe { libc::sigaction(libc::SIGUSR2, &action, &mut previous) } != 0 {
                return Err(io::Error::last_os_error().into());
            }

            let cancelled_client = client.try_clone()?;
            let (thread_tx, thread_rx) = mpsc::sync_channel(1);
            let interrupted = scope.spawn(move || {
                let thread_id = unsafe { libc::pthread_self() };
                thread_tx.send(thread_id).unwrap();
                let mut byte = 0u8;
                let result = unsafe {
                    libc::read(
                        cancelled_client.as_raw_fd(),
                        (&mut byte as *mut u8).cast(),
                        1,
                    )
                };
                (result, io::Error::last_os_error())
            });
            let thread_id = thread_rx.recv()?;
            thread::sleep(Duration::from_millis(50));
            if unsafe { libc::pthread_kill(thread_id, libc::SIGUSR2) } != 0 {
                return Err(io::Error::last_os_error().into());
            }
            let (result, error) = interrupted
                .join()
                .map_err(|_| "interrupted CUSE read thread panicked")?;
            let restore =
                unsafe { libc::sigaction(libc::SIGUSR2, &previous, std::ptr::null_mut()) };
            if restore != 0 {
                return Err(io::Error::last_os_error().into());
            }
            if result != -1 || error.raw_os_error() != Some(libc::EINTR) {
                return Err(format!(
                    "blocked CUSE read was not interrupted: result={result} error={error}"
                )
                .into());
            }
            println!("phase=cancel result=pass kernel_interrupt=EINTR");

            drop(client);
            drop(server);
            Ok(())
        })?;

        let teardown_started = Instant::now();
        drop(service);
        let teardown_ms = teardown_started.elapsed().as_millis();
        if guest.exists() {
            return Err(format!("guest projection survived teardown: {}", guest.display()).into());
        }
        if teardown_ms > 5_000 {
            return Err(format!("CUSE teardown exceeded 5 seconds: {teardown_ms}ms").into());
        }
        println!("phase=teardown result=pass duration_ms={teardown_ms}");
        println!("cuse_live_gate=pass");
        Ok(())
    }

    fn require_unix_socket(fd: libc::c_int) -> io::Result<()> {
        let mut address: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
        let mut length = std::mem::size_of_val(&address) as libc::socklen_t;
        if unsafe {
            libc::getsockname(
                fd,
                (&mut address as *mut libc::sockaddr_storage).cast(),
                &mut length,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        if address.ss_family as libc::c_int != libc::AF_UNIX {
            return Err(io::Error::other(format!(
                "CUSE data channel family {} is not AF_UNIX",
                address.ss_family
            )));
        }
        Ok(())
    }
}
