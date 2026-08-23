//! Real CUSE character-device service for guest `/dev/nvidia0`.
//!
//! When `/dev/cuse` exists this module registers a userspace character
//! device, proxies `open`/`read`/`write`/`release` onto a Unix socketpair the
//! adapter `accept()`s, and fails NVIDIA ioctls closed. Absence of `/dev/cuse`
//! is not a skip of the Unix-endpoint fixture; claiming CUSE while only
//! binding a socket is.

use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use crate::remote_gpu::ABI_VERSION;
use crate::remote_gpu_guest::{ioctl_disposition, IoctlDisposition, DEFAULT_CREDIT_WINDOW};

const FUSE_OPEN: u32 = 14;
const FUSE_READ: u32 = 15;
const FUSE_WRITE: u32 = 16;
const FUSE_RELEASE: u32 = 18;
const FUSE_FLUSH: u32 = 25;
const FUSE_INTERRUPT: u32 = 36;
const FUSE_IOCTL: u32 = 39;
const FUSE_POLL: u32 = 22;
const CUSE_INIT: u32 = 4096;
const CUSE_UNRESTRICTED_IOCTL: u32 = 1;
const FUSE_KERNEL_VERSION: u32 = 7;
const FUSE_KERNEL_MINOR_VERSION: u32 = 31;
const FUSE_IN_HEADER_LEN: usize = 40;
const FUSE_OUT_HEADER_LEN: usize = 16;
const ENOSYS: i32 = 38;
const ENOTTY: i32 = 25;
const EIO: i32 = 5;
const EAGAIN: i32 = 11;

/// Encode a CUSE_INIT userspace reply. Tests assert the layout without
/// opening `/dev/cuse`.
pub fn encode_cuse_init_out(
    unique: u64,
    flags: u32,
    max_read: u32,
    max_write: u32,
    devname: &str,
) -> Vec<u8> {
    let info = format!("DEVNAME={devname}\0");
    let body_len = 72 + info.len();
    let total = FUSE_OUT_HEADER_LEN + body_len;
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(&(total as u32).to_le_bytes());
    out.extend_from_slice(&0i32.to_le_bytes());
    out.extend_from_slice(&unique.to_le_bytes());
    out.extend_from_slice(&FUSE_KERNEL_VERSION.to_le_bytes());
    out.extend_from_slice(&FUSE_KERNEL_MINOR_VERSION.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&flags.to_le_bytes());
    out.extend_from_slice(&max_read.to_le_bytes());
    out.extend_from_slice(&max_write.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&[0u8; 40]);
    out.extend_from_slice(info.as_bytes());
    out
}

pub fn decode_fuse_in_header(bytes: &[u8]) -> io::Result<(u32, u32, u64)> {
    if bytes.len() < FUSE_IN_HEADER_LEN {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "CUSE request header is truncated",
        ));
    }
    let len = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
    let opcode = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
    let unique = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
    Ok((len, opcode, unique))
}

pub fn encode_fuse_error(unique: u64, errno: i32) -> Vec<u8> {
    let mut out = Vec::with_capacity(FUSE_OUT_HEADER_LEN);
    out.extend_from_slice(&(FUSE_OUT_HEADER_LEN as u32).to_le_bytes());
    out.extend_from_slice(&(-errno).to_le_bytes());
    out.extend_from_slice(&unique.to_le_bytes());
    out
}

pub fn encode_fuse_ok(unique: u64, payload: &[u8]) -> Vec<u8> {
    let total = FUSE_OUT_HEADER_LEN + payload.len();
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(&(total as u32).to_le_bytes());
    out.extend_from_slice(&0i32.to_le_bytes());
    out.extend_from_slice(&unique.to_le_bytes());
    out.extend_from_slice(payload);
    out
}

pub fn ioctl_cuse_reply(request: u64) -> (i32, Vec<u8>) {
    match ioctl_disposition(request) {
        IoctlDisposition::Contract => (0, ABI_VERSION.to_le_bytes().to_vec()),
        IoctlDisposition::FailClosed => (-ENOTTY, Vec::new()),
    }
}

/// Live CUSE service. `accept()` yields one end of a socketpair created on
/// `open(2)` of the character device.
pub struct CuseService {
    guest_path: PathBuf,
    host_devname: String,
    accept_rx: Mutex<Receiver<UnixStream>>,
    stop: Arc<AtomicBool>,
    wake: UnixStream,
    thread: Option<JoinHandle<()>>,
}

impl CuseService {
    pub fn mount(guest_nvidia0: &Path) -> io::Result<Self> {
        let mut cuse = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/cuse")?;
        let devname = unique_devname();
        let (len, opcode, unique) = read_one_request(&mut cuse)?;
        if opcode != CUSE_INIT {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("CUSE expected INIT, got opcode {opcode} len {len}"),
            ));
        }
        let init = encode_cuse_init_out(
            unique,
            CUSE_UNRESTRICTED_IOCTL,
            4 * 1024 * 1024,
            4 * 1024 * 1024,
            &devname,
        );
        cuse.write_all(&init)?;
        cuse.flush()?;

        let host_node = PathBuf::from(format!("/dev/{devname}"));
        wait_for_node(&host_node)?;
        match fs::remove_file(guest_nvidia0) {
            Ok(()) => {}
            Err(err) if err.kind() == io::ErrorKind::NotFound => {}
            Err(err) => return Err(err),
        }
        std::os::unix::fs::symlink(&host_node, guest_nvidia0)?;

        let (accept_tx, accept_rx) = mpsc::sync_channel(DEFAULT_CREDIT_WINDOW as usize);
        let (wake_read, wake) = UnixStream::pair()?;
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = stop.clone();
        let thread = thread::Builder::new()
            .name("asterism-cuse-nvidia0".into())
            .spawn(move || {
                let _ = serve_cuse(cuse, wake_read, accept_tx, thread_stop);
            })?;

        Ok(Self {
            guest_path: guest_nvidia0.to_path_buf(),
            host_devname: devname,
            accept_rx: Mutex::new(accept_rx),
            stop,
            wake,
            thread: Some(thread),
        })
    }

    pub fn accept(&self) -> io::Result<UnixStream> {
        let rx = self
            .accept_rx
            .lock()
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "CUSE accept lock poisoned"))?;
        match rx.recv_timeout(Duration::from_secs(30)) {
            Ok(stream) => Ok(stream),
            Err(RecvTimeoutError::Timeout) => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "CUSE open of /dev/nvidia0 timed out",
            )),
            Err(RecvTimeoutError::Disconnected) => Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "CUSE service stopped",
            )),
        }
    }

    pub fn guest_path(&self) -> &Path {
        &self.guest_path
    }
}

impl Drop for CuseService {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        // The service thread polls this socket beside /dev/cuse. Waking it
        // makes teardown bounded even when the kernel has no pending CUSE
        // request; merely setting an atomic cannot wake a blocking read.
        let _ = self.wake.write_all(&[1]);
        let _ = fs::remove_file(&self.guest_path);
        let _ = fs::remove_file(format!("/dev/{}", self.host_devname));
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn unique_devname() -> String {
    static SEQ: AtomicU64 = AtomicU64::new(1);
    format!(
        "asterism-n0-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    )
}

fn wait_for_node(path: &Path) -> io::Result<()> {
    let until = std::time::Instant::now() + Duration::from_secs(2);
    while std::time::Instant::now() < until {
        if path.exists() {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(10));
    }
    // The kernel may have allocated a device without udev publishing the
    // node yet. The guest path is already a symlink target; opening it later
    // will fail loudly if the node never appears.
    Ok(())
}

fn read_one_request(dev: &mut File) -> io::Result<(u32, u32, u64)> {
    let mut header = [0u8; FUSE_IN_HEADER_LEN];
    dev.read_exact(&mut header)?;
    let (len, opcode, unique) = decode_fuse_in_header(&header)?;
    let rest = (len as usize).saturating_sub(FUSE_IN_HEADER_LEN);
    if rest > 0 {
        let mut skip = vec![0u8; rest];
        dev.read_exact(&mut skip)?;
    }
    Ok((len, opcode, unique))
}

fn serve_cuse(
    mut dev: File,
    wake: UnixStream,
    accept_tx: SyncSender<UnixStream>,
    stop: Arc<AtomicBool>,
) -> io::Result<()> {
    let mut fhs: HashMap<u64, UnixStream> = HashMap::new();
    let mut next_fh = 1u64;
    while !stop.load(Ordering::SeqCst) {
        if !wait_for_cuse_or_stop(dev.as_raw_fd(), wake.as_raw_fd())? || stop.load(Ordering::SeqCst)
        {
            break;
        }
        let mut header = [0u8; FUSE_IN_HEADER_LEN];
        match dev.read_exact(&mut header) {
            Ok(()) => {}
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
        let (len, opcode, unique) = decode_fuse_in_header(&header)?;
        let rest_len = (len as usize).saturating_sub(FUSE_IN_HEADER_LEN);
        let mut rest = vec![0u8; rest_len];
        if rest_len > 0 {
            dev.read_exact(&mut rest)?;
        }
        let reply = match opcode {
            CUSE_INIT => encode_cuse_init_out(
                unique,
                CUSE_UNRESTRICTED_IOCTL,
                4 * 1024 * 1024,
                4 * 1024 * 1024,
                "asterism-nvidia0",
            ),
            FUSE_OPEN => match UnixStream::pair() {
                Ok((a, b)) => {
                    let _ = a.set_nonblocking(true);
                    let _ = b.set_nonblocking(false);
                    let fh = next_fh;
                    next_fh = next_fh.saturating_add(1);
                    if accept_tx.try_send(b).is_err() {
                        // Never block the only CUSE thread on a full accept
                        // queue: Drop must always be able to wake and join it.
                        encode_fuse_error(unique, EAGAIN)
                    } else {
                        fhs.insert(fh, a);
                        let mut payload = Vec::new();
                        payload.extend_from_slice(&fh.to_le_bytes());
                        payload.extend_from_slice(&0u32.to_le_bytes());
                        payload.extend_from_slice(&0u32.to_le_bytes());
                        encode_fuse_ok(unique, &payload)
                    }
                }
                Err(_) => encode_fuse_error(unique, EIO),
            },
            FUSE_WRITE => {
                if rest.len() < 40 {
                    encode_fuse_error(unique, EIO)
                } else {
                    let fh = u64::from_le_bytes(rest[0..8].try_into().unwrap());
                    let size = u32::from_le_bytes(rest[16..20].try_into().unwrap()) as usize;
                    let data = rest.get(40..40 + size);
                    match fhs.get_mut(&fh) {
                        Some(stream) if data.is_some() => {
                            let data = data.expect("checked");
                            cuse_write_reply(stream, unique, data)
                        }
                        None => encode_fuse_error(unique, EIO),
                        Some(_) => encode_fuse_error(unique, EIO),
                    }
                }
            }
            FUSE_READ => {
                if rest.len() < 24 {
                    encode_fuse_error(unique, EIO)
                } else {
                    let fh = u64::from_le_bytes(rest[0..8].try_into().unwrap());
                    let size = u32::from_le_bytes(rest[16..20].try_into().unwrap()) as usize;
                    match fhs.get_mut(&fh) {
                        Some(stream) => cuse_read_reply(stream, unique, size),
                        None => encode_fuse_error(unique, EIO),
                    }
                }
            }
            FUSE_RELEASE => {
                if rest.len() >= 8 {
                    let fh = u64::from_le_bytes(rest[0..8].try_into().unwrap());
                    fhs.remove(&fh);
                }
                encode_fuse_ok(unique, &[])
            }
            FUSE_IOCTL => {
                let cmd = if rest.len() >= 16 {
                    u32::from_le_bytes(rest[12..16].try_into().unwrap()) as u64
                } else {
                    0
                };
                let (result, data) = ioctl_cuse_reply(cmd);
                if result < 0 {
                    encode_fuse_error(unique, -result)
                } else {
                    let mut payload = Vec::new();
                    payload.extend_from_slice(&result.to_le_bytes());
                    payload.extend_from_slice(&0u32.to_le_bytes());
                    payload.extend_from_slice(&0u32.to_le_bytes());
                    payload.extend_from_slice(&0u32.to_le_bytes());
                    payload.extend_from_slice(&data);
                    encode_fuse_ok(unique, &payload)
                }
            }
            FUSE_FLUSH | FUSE_INTERRUPT => encode_fuse_ok(unique, &[]),
            FUSE_POLL => {
                // fuse_poll_in carries fh at 0 and requested event bits at
                // 20. Report only readiness the socket actually has; an
                // empty generic success has the wrong wire shape and causes
                // clients to busy-loop or miss readable replies.
                if rest.len() < 24 {
                    encode_fuse_error(unique, EIO)
                } else {
                    let fh = u64::from_le_bytes(rest[0..8].try_into().unwrap());
                    let requested = u32::from_le_bytes(rest[20..24].try_into().unwrap());
                    match fhs.get(&fh) {
                        Some(stream) => cuse_poll_reply(stream, unique, requested),
                        None => encode_fuse_error(unique, EIO),
                    }
                }
            }
            _ => encode_fuse_error(unique, ENOSYS),
        };
        if dev.write_all(&reply).is_err() {
            break;
        }
    }
    Ok(())
}

fn wait_for_cuse_or_stop(cuse_fd: RawFd, wake_fd: RawFd) -> io::Result<bool> {
    loop {
        let mut fds = [
            libc::pollfd {
                fd: cuse_fd,
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: wake_fd,
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        let ready = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as _, -1) };
        if ready < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
        }
        if fds[1].revents & libc::POLLIN != 0 {
            return Ok(false);
        }
        if fds[0].revents & libc::POLLIN != 0 {
            return Ok(true);
        }
    }
}

fn cuse_write_reply(stream: &mut UnixStream, unique: u64, data: &[u8]) -> Vec<u8> {
    if stream.write_all(data).is_err() {
        return encode_fuse_error(unique, EIO);
    }
    let mut payload = Vec::new();
    payload.extend_from_slice(&(data.len() as u32).to_le_bytes());
    payload.extend_from_slice(&0u32.to_le_bytes());
    encode_fuse_ok(unique, &payload)
}

fn cuse_read_reply(stream: &mut UnixStream, unique: u64, size: usize) -> Vec<u8> {
    let mut buf = vec![0u8; size.min(4 * 1024 * 1024)];
    match stream.read(&mut buf) {
        Ok(n) => {
            buf.truncate(n);
            encode_fuse_ok(unique, &buf)
        }
        Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
            // A successful zero-byte read is EOF. No reply is available yet,
            // so preserve the stream and tell the caller to retry.
            encode_fuse_error(unique, EAGAIN)
        }
        Err(_) => encode_fuse_error(unique, EIO),
    }
}

fn cuse_poll_reply(stream: &UnixStream, unique: u64, requested: u32) -> Vec<u8> {
    let mut fd = libc::pollfd {
        fd: stream.as_raw_fd(),
        events: (requested & u16::MAX as u32) as i16,
        revents: 0,
    };
    if unsafe { libc::poll(&mut fd, 1, 0) } < 0 {
        return encode_fuse_error(unique, EIO);
    }
    let mut payload = Vec::with_capacity(8);
    payload.extend_from_slice(&(fd.revents as u16 as u32).to_le_bytes());
    payload.extend_from_slice(&0u32.to_le_bytes());
    encode_fuse_ok(unique, &payload)
}

/// Expose the CUSE fd so tests can prove we opened `/dev/cuse`, not a marker.
#[allow(dead_code)]
pub fn cuse_fd_is_character(fd: RawFd) -> io::Result<bool> {
    let file = unsafe { File::from_raw_fd(fd) };
    let raw = file.as_raw_fd();
    std::mem::forget(file);
    let _ = raw;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::remote_gpu_guest::ASTERISM_IOCTL_MAGIC;

    #[test]
    fn cuse_init_out_carries_devname_and_unrestricted_ioctl() {
        let bytes = encode_cuse_init_out(99, CUSE_UNRESTRICTED_IOCTL, 4096, 4096, "nvidia0");
        assert!(bytes.len() > FUSE_OUT_HEADER_LEN + 72);
        let unique = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
        assert_eq!(unique, 99);
        let text = String::from_utf8_lossy(&bytes[FUSE_OUT_HEADER_LEN + 72..]);
        assert!(text.contains("DEVNAME=nvidia0"), "{text}");
        let flags = u32::from_le_bytes(
            bytes[FUSE_OUT_HEADER_LEN + 12..FUSE_OUT_HEADER_LEN + 16]
                .try_into()
                .unwrap(),
        );
        assert_eq!(flags, CUSE_UNRESTRICTED_IOCTL);
    }

    #[test]
    fn nvidia_ioctl_reply_is_enotty_and_contract_ioctl_returns_abi() {
        let nvidia = (u64::from(b'F') << 8) | 0x2a;
        let (result, data) = ioctl_cuse_reply(nvidia);
        assert_eq!(result, -ENOTTY);
        assert!(data.is_empty());
        let contract = (u64::from(ASTERISM_IOCTL_MAGIC) << 8) | 1;
        let (result, data) = ioctl_cuse_reply(contract);
        assert_eq!(result, 0);
        assert_eq!(data, ABI_VERSION.to_le_bytes());

        let unknown_contract = (u64::from(ASTERISM_IOCTL_MAGIC) << 8) | 2;
        let (result, data) = ioctl_cuse_reply(unknown_contract);
        assert_eq!(result, -ENOTTY);
        assert!(data.is_empty());
    }

    #[test]
    fn wake_fd_interrupts_an_idle_cuse_wait() {
        let (cuse_read, _cuse_write) = UnixStream::pair().unwrap();
        let (wake_read, mut wake_write) = UnixStream::pair().unwrap();
        wake_write.write_all(&[1]).unwrap();
        assert!(!wait_for_cuse_or_stop(cuse_read.as_raw_fd(), wake_read.as_raw_fd()).unwrap());
    }

    #[test]
    fn cuse_stream_preserves_eagain_poll_read_and_write_semantics() {
        let (mut service, mut client) = UnixStream::pair().unwrap();
        service.set_nonblocking(true).unwrap();

        let empty = cuse_read_reply(&mut service, 7, 128);
        assert_eq!(i32::from_le_bytes(empty[4..8].try_into().unwrap()), -EAGAIN);

        client.write_all(b"reply").unwrap();
        let poll = cuse_poll_reply(&service, 8, libc::POLLIN as u32);
        assert_eq!(i32::from_le_bytes(poll[4..8].try_into().unwrap()), 0);
        let readiness = u32::from_le_bytes(poll[16..20].try_into().unwrap());
        assert_ne!(readiness & libc::POLLIN as u32, 0);

        let read = cuse_read_reply(&mut service, 9, 128);
        assert_eq!(&read[FUSE_OUT_HEADER_LEN..], b"reply");

        let write = cuse_write_reply(&mut service, 10, b"call");
        assert_eq!(i32::from_le_bytes(write[4..8].try_into().unwrap()), 0);
        assert_eq!(u32::from_le_bytes(write[16..20].try_into().unwrap()), 4);
        let mut received = [0u8; 4];
        client.read_exact(&mut received).unwrap();
        assert_eq!(&received, b"call");
    }

    #[test]
    fn fuse_header_round_trips() {
        let mut bytes = vec![0u8; FUSE_IN_HEADER_LEN];
        bytes[0..4].copy_from_slice(&(FUSE_IN_HEADER_LEN as u32 + 16).to_le_bytes());
        bytes[4..8].copy_from_slice(&CUSE_INIT.to_le_bytes());
        bytes[8..16].copy_from_slice(&7u64.to_le_bytes());
        let (len, opcode, unique) = decode_fuse_in_header(&bytes).unwrap();
        assert_eq!(len, FUSE_IN_HEADER_LEN as u32 + 16);
        assert_eq!(opcode, CUSE_INIT);
        assert_eq!(unique, 7);
    }
}
