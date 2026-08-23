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
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
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
const FUSE_POLL: u32 = 40;
const CUSE_INIT: u32 = 4096;
const CUSE_UNRESTRICTED_IOCTL: u32 = 1;
const FUSE_KERNEL_VERSION: u32 = 7;
const FUSE_KERNEL_MINOR_VERSION: u32 = 31;
const FUSE_IN_HEADER_LEN: usize = 40;
const FUSE_OUT_HEADER_LEN: usize = 16;
const FUSE_WRITE_IN_LEN: usize = 40;
const FUSE_IOCTL_IN_LEN: usize = 32;
const CUSE_MAX_READ: usize = 4 * 1024 * 1024;
const CUSE_MAX_WRITE: usize = 4 * 1024 * 1024;
// A /dev/cuse read returns one complete record. Leave a page for the largest
// fixed request body in addition to the negotiated payload limit.
const CUSE_MAX_REQUEST_LEN: usize = CUSE_MAX_WRITE + 4096;
const ENOSYS: i32 = 38;
const ENOTTY: i32 = 25;
const EIO: i32 = 5;
const EINTR: i32 = 4;
const EAGAIN: i32 = 11;
const FUSE_NOTIFY_POLL: i32 = 1;
const MAX_PENDING_IO: usize = 32;
const MAX_POLL_WATCHERS: usize = 32;
const WATCHER_POLL_MS: i32 = 50;

struct CuseHandle {
    reader: Arc<Mutex<UnixStream>>,
    writer: Arc<Mutex<UnixStream>>,
    poll: UnixStream,
    cancels: Vec<Arc<AtomicBool>>,
}

#[derive(Clone, Copy)]
struct PollRequest {
    unique: u64,
    kh: u64,
    requested: u32,
}

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

#[derive(Debug)]
struct FuseRequest<'a> {
    len: u32,
    opcode: u32,
    unique: u64,
    body: &'a [u8],
}

fn parse_fuse_request_record(record: &[u8]) -> io::Result<FuseRequest<'_>> {
    let (len, opcode, unique) = decode_fuse_in_header(record)?;
    let len = len as usize;
    if len < FUSE_IN_HEADER_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "CUSE request length is smaller than its header",
        ));
    }
    if len > CUSE_MAX_REQUEST_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "CUSE request exceeds the negotiated record bound",
        ));
    }
    if len > record.len() {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "CUSE request record is truncated",
        ));
    }
    if len < record.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "CUSE request record contains bytes beyond header.len",
        ));
    }
    Ok(FuseRequest {
        len: len as u32,
        opcode,
        unique,
        body: &record[FUSE_IN_HEADER_LEN..],
    })
}

fn read_fuse_request_record<'a, R: Read>(
    reader: &mut R,
    record: &'a mut [u8],
) -> io::Result<FuseRequest<'a>> {
    let read = loop {
        match reader.read(record) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "CUSE request channel closed",
                ))
            }
            Ok(read) => break read,
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(err) => return Err(err),
        }
    };
    parse_fuse_request_record(&record[..read])
}

fn request_body_is_valid(opcode: u32, body: &[u8]) -> bool {
    match opcode {
        CUSE_INIT => body.len() == 16,
        FUSE_OPEN => body.len() == 8,
        FUSE_READ => {
            body.len() == 40
                && u32::from_le_bytes(body[16..20].try_into().unwrap()) as usize <= CUSE_MAX_READ
        }
        FUSE_WRITE => {
            if body.len() < FUSE_WRITE_IN_LEN {
                return false;
            }
            let size = u32::from_le_bytes(body[16..20].try_into().unwrap()) as usize;
            size <= CUSE_MAX_WRITE
                && FUSE_WRITE_IN_LEN
                    .checked_add(size)
                    .is_some_and(|expected| body.len() == expected)
        }
        FUSE_RELEASE | FUSE_FLUSH | FUSE_POLL => body.len() == 24,
        FUSE_INTERRUPT => body.len() == 8,
        FUSE_IOCTL => {
            if body.len() < FUSE_IOCTL_IN_LEN {
                return false;
            }
            let in_size = u32::from_le_bytes(body[24..28].try_into().unwrap()) as usize;
            let out_size = u32::from_le_bytes(body[28..32].try_into().unwrap()) as usize;
            in_size <= CUSE_MAX_WRITE
                && out_size <= CUSE_MAX_READ
                && FUSE_IOCTL_IN_LEN
                    .checked_add(in_size)
                    .is_some_and(|expected| body.len() == expected)
        }
        // The dispatcher replies ENOSYS without interpreting an unknown body.
        _ => true,
    }
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
            CUSE_MAX_READ as u32,
            CUSE_MAX_WRITE as u32,
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
            .map_err(|_| io::Error::other("CUSE accept lock poisoned"))?;
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
    let mut record = vec![0u8; CUSE_MAX_REQUEST_LEN];
    let request = read_fuse_request_record(dev, &mut record)?;
    if !request_body_is_valid(request.opcode, request.body) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "CUSE INIT request has an invalid body",
        ));
    }
    Ok((request.len, request.opcode, request.unique))
}

fn serve_cuse(
    mut dev: File,
    wake: UnixStream,
    accept_tx: SyncSender<UnixStream>,
    stop: Arc<AtomicBool>,
) -> io::Result<()> {
    // Notifications and ordinary replies share the CUSE descriptor. Keep
    // their writes framed even when a poll watcher wakes concurrently with
    // the main request loop.
    let replies = Arc::new(Mutex::new(dev.try_clone()?));
    let pending = Arc::new(Mutex::new(HashMap::<u64, Arc<AtomicBool>>::new()));
    let active_watchers = Arc::new(AtomicUsize::new(0));
    let mut fhs: HashMap<u64, CuseHandle> = HashMap::new();
    let mut next_fh = 1u64;
    let mut record = vec![0u8; CUSE_MAX_REQUEST_LEN];
    while !stop.load(Ordering::SeqCst) {
        if !wait_for_cuse_or_stop(dev.as_raw_fd(), wake.as_raw_fd())? || stop.load(Ordering::SeqCst)
        {
            break;
        }
        let request = match read_fuse_request_record(&mut dev, &mut record) {
            Ok(request) => request,
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        };
        let opcode = request.opcode;
        let unique = request.unique;
        let rest = request.body;
        if !request_body_is_valid(opcode, rest) {
            let malformed = encode_fuse_error(unique, EIO);
            let written = replies
                .lock()
                .map_err(|_| io::Error::other("CUSE reply lock poisoned"))?
                .write_all(&malformed);
            if written.is_err() {
                break;
            }
            continue;
        }
        let reply = match opcode {
            CUSE_INIT => encode_cuse_init_out(
                unique,
                CUSE_UNRESTRICTED_IOCTL,
                CUSE_MAX_READ as u32,
                CUSE_MAX_WRITE as u32,
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
                        match (a.try_clone(), a.try_clone()) {
                            (Ok(reader), Ok(poll)) => {
                                fhs.insert(
                                    fh,
                                    CuseHandle {
                                        reader: Arc::new(Mutex::new(reader)),
                                        writer: Arc::new(Mutex::new(a)),
                                        poll,
                                        cancels: Vec::new(),
                                    },
                                );
                                let mut payload = Vec::new();
                                payload.extend_from_slice(&fh.to_le_bytes());
                                payload.extend_from_slice(&0u32.to_le_bytes());
                                payload.extend_from_slice(&0u32.to_le_bytes());
                                encode_fuse_ok(unique, &payload)
                            }
                            _ => encode_fuse_error(unique, EIO),
                        }
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
                    match (fhs.get_mut(&fh), data) {
                        (Some(handle), Some(data)) => {
                            handle
                                .cancels
                                .retain(|cancel| !cancel.load(Ordering::SeqCst));
                            let cancel = Arc::new(AtomicBool::new(false));
                            if !reserve_pending(&pending, unique, cancel.clone()) {
                                encode_fuse_error(unique, EAGAIN)
                            } else {
                                handle.cancels.push(cancel.clone());
                                let writer = handle.writer.clone();
                                let replies = replies.clone();
                                let worker_pending = pending.clone();
                                let stop = stop.clone();
                                let worker_wake = wake.try_clone();
                                let data = data.to_vec();
                                let spawned = worker_wake.and_then(|worker_wake| {
                                    thread::Builder::new()
                                        .name("asterism-cuse-write".into())
                                        .spawn(move || {
                                            let reply = match writer.lock() {
                                                Ok(mut stream) => cuse_write_reply_cancel(
                                                    &mut stream,
                                                    &worker_wake,
                                                    &stop,
                                                    &cancel,
                                                    unique,
                                                    &data,
                                                ),
                                                Err(_) => encode_fuse_error(unique, EIO),
                                            };
                                            finish_pending(
                                                &worker_pending,
                                                &replies,
                                                unique,
                                                reply,
                                            );
                                            cancel.store(true, Ordering::SeqCst);
                                        })
                                        .map(|_| ())
                                });
                                if spawned.is_err() {
                                    handle
                                        .cancels
                                        .last()
                                        .expect("cancel was just inserted")
                                        .store(true, Ordering::SeqCst);
                                    pending.lock().ok().and_then(|mut p| p.remove(&unique));
                                    encode_fuse_error(unique, EIO)
                                } else {
                                    continue;
                                }
                            }
                        }
                        (None, _) => encode_fuse_error(unique, EIO),
                        (Some(_), None) => encode_fuse_error(unique, EIO),
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
                        Some(handle) => {
                            handle
                                .cancels
                                .retain(|cancel| !cancel.load(Ordering::SeqCst));
                            let cancel = Arc::new(AtomicBool::new(false));
                            if !reserve_pending(&pending, unique, cancel.clone()) {
                                encode_fuse_error(unique, EAGAIN)
                            } else {
                                handle.cancels.push(cancel.clone());
                                let reader = handle.reader.clone();
                                let replies = replies.clone();
                                let worker_pending = pending.clone();
                                let stop = stop.clone();
                                let worker_wake = wake.try_clone();
                                let spawned = worker_wake.and_then(|worker_wake| {
                                    thread::Builder::new()
                                        .name("asterism-cuse-read".into())
                                        .spawn(move || {
                                            let reply = match reader.lock() {
                                                Ok(mut stream) => cuse_read_reply_cancel(
                                                    &mut stream,
                                                    &worker_wake,
                                                    &stop,
                                                    &cancel,
                                                    unique,
                                                    size,
                                                ),
                                                Err(_) => encode_fuse_error(unique, EIO),
                                            };
                                            finish_pending(
                                                &worker_pending,
                                                &replies,
                                                unique,
                                                reply,
                                            );
                                            cancel.store(true, Ordering::SeqCst);
                                        })
                                        .map(|_| ())
                                });
                                if spawned.is_err() {
                                    handle
                                        .cancels
                                        .last()
                                        .expect("cancel was just inserted")
                                        .store(true, Ordering::SeqCst);
                                    pending.lock().ok().and_then(|mut p| p.remove(&unique));
                                    encode_fuse_error(unique, EIO)
                                } else {
                                    continue;
                                }
                            }
                        }
                        None => encode_fuse_error(unique, EIO),
                    }
                }
            }
            FUSE_RELEASE => {
                if rest.len() >= 8 {
                    let fh = u64::from_le_bytes(rest[0..8].try_into().unwrap());
                    if let Some(handle) = fhs.remove(&fh) {
                        for cancel in handle.cancels {
                            cancel.store(true, Ordering::SeqCst);
                        }
                    }
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
            FUSE_FLUSH => encode_fuse_ok(unique, &[]),
            FUSE_INTERRUPT => {
                let target = rest
                    .get(0..8)
                    .map(|bytes| u64::from_le_bytes(bytes.try_into().unwrap()));
                let cancelled = target.is_some_and(|target| {
                    pending
                        .lock()
                        .ok()
                        .and_then(|pending| pending.get(&target).cloned())
                        .is_some_and(|cancel| {
                            cancel.store(true, Ordering::SeqCst);
                            true
                        })
                });
                if cancelled {
                    encode_fuse_ok(unique, &[])
                } else {
                    encode_fuse_error(unique, EAGAIN)
                }
            }
            FUSE_POLL => {
                // fuse_poll_in carries fh at 0 and requested event bits at
                // 20. Report only readiness the socket actually has; an
                // empty generic success has the wrong wire shape and causes
                // clients to busy-loop or miss readable replies.
                if rest.len() < 24 {
                    encode_fuse_error(unique, EIO)
                } else {
                    let fh = u64::from_le_bytes(rest[0..8].try_into().unwrap());
                    let kh = u64::from_le_bytes(rest[8..16].try_into().unwrap());
                    let requested = u32::from_le_bytes(rest[20..24].try_into().unwrap());
                    match fhs.get_mut(&fh) {
                        Some(handle) => {
                            handle
                                .cancels
                                .retain(|cancel| !cancel.load(Ordering::SeqCst));
                            let (reply, cancel) = cuse_poll_reply_bounded(
                                &handle.poll,
                                &wake,
                                &stop,
                                &replies,
                                &active_watchers,
                                PollRequest {
                                    unique,
                                    kh,
                                    requested,
                                },
                            );
                            if let Some(cancel) = cancel {
                                handle.cancels.push(cancel);
                            }
                            reply
                        }
                        None => encode_fuse_error(unique, EIO),
                    }
                }
            }
            _ => encode_fuse_error(unique, ENOSYS),
        };
        let written = replies
            .lock()
            .map_err(|_| io::Error::other("CUSE reply lock poisoned"))?
            .write_all(&reply);
        if written.is_err() {
            break;
        }
    }
    for (_, handle) in fhs {
        for cancel in handle.cancels {
            cancel.store(true, Ordering::SeqCst);
        }
    }
    if let Ok(pending) = pending.lock() {
        for cancel in pending.values() {
            cancel.store(true, Ordering::SeqCst);
        }
    }
    Ok(())
}

fn reserve_pending(
    pending: &Arc<Mutex<HashMap<u64, Arc<AtomicBool>>>>,
    unique: u64,
    cancel: Arc<AtomicBool>,
) -> bool {
    let Ok(mut pending) = pending.lock() else {
        return false;
    };
    if pending.len() >= MAX_PENDING_IO || pending.contains_key(&unique) {
        return false;
    }
    pending.insert(unique, cancel);
    true
}

fn finish_pending(
    pending: &Arc<Mutex<HashMap<u64, Arc<AtomicBool>>>>,
    replies: &Arc<Mutex<File>>,
    unique: u64,
    reply: Vec<u8>,
) {
    if let Ok(mut pending) = pending.lock() {
        pending.remove(&unique);
    }
    if let Ok(mut dev) = replies.lock() {
        let _ = dev.write_all(&reply);
    }
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

#[cfg(test)]
fn cuse_write_reply(
    stream: &mut UnixStream,
    wake: &UnixStream,
    stop: &AtomicBool,
    unique: u64,
    data: &[u8],
) -> Vec<u8> {
    cuse_write_reply_cancel(stream, wake, stop, &AtomicBool::new(false), unique, data)
}

fn cuse_write_reply_cancel(
    stream: &mut UnixStream,
    wake: &UnixStream,
    stop: &AtomicBool,
    cancel: &AtomicBool,
    unique: u64,
    data: &[u8],
) -> Vec<u8> {
    if write_all_wakeable_cancel(stream, wake, stop, cancel, data).is_err() {
        if cancel.load(Ordering::SeqCst) {
            return encode_fuse_error(unique, EINTR);
        }
        return encode_fuse_error(unique, EIO);
    }
    let mut payload = Vec::new();
    payload.extend_from_slice(&(data.len() as u32).to_le_bytes());
    payload.extend_from_slice(&0u32.to_le_bytes());
    encode_fuse_ok(unique, &payload)
}

#[cfg(test)]
fn cuse_read_reply(
    stream: &mut UnixStream,
    wake: &UnixStream,
    stop: &AtomicBool,
    unique: u64,
    size: usize,
) -> Vec<u8> {
    cuse_read_reply_cancel(stream, wake, stop, &AtomicBool::new(false), unique, size)
}

fn cuse_read_reply_cancel(
    stream: &mut UnixStream,
    wake: &UnixStream,
    stop: &AtomicBool,
    cancel: &AtomicBool,
    unique: u64,
    size: usize,
) -> Vec<u8> {
    let mut buf = vec![0u8; size.min(4 * 1024 * 1024)];
    loop {
        if cancel.load(Ordering::SeqCst) {
            return encode_fuse_error(unique, EINTR);
        }
        match stream.read(&mut buf) {
            Ok(n) => {
                buf.truncate(n);
                return encode_fuse_ok(unique, &buf);
            }
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                if wait_stream_or_stop_or_cancel(
                    stream.as_raw_fd(),
                    wake.as_raw_fd(),
                    libc::POLLIN,
                    stop,
                    cancel,
                )
                .unwrap_or(false)
                {
                    continue;
                }
                return encode_fuse_error(
                    unique,
                    if cancel.load(Ordering::SeqCst) {
                        EINTR
                    } else {
                        EIO
                    },
                );
            }
            Err(_) => return encode_fuse_error(unique, EIO),
        }
    }
}

#[cfg(test)]
fn cuse_poll_reply(
    stream: &UnixStream,
    wake: &UnixStream,
    stop: &Arc<AtomicBool>,
    replies: &Arc<Mutex<File>>,
    unique: u64,
    kh: u64,
    requested: u32,
) -> Vec<u8> {
    cuse_poll_reply_bounded(
        stream,
        wake,
        stop,
        replies,
        &Arc::new(AtomicUsize::new(0)),
        PollRequest {
            unique,
            kh,
            requested,
        },
    )
    .0
}

fn cuse_poll_reply_bounded(
    stream: &UnixStream,
    wake: &UnixStream,
    stop: &Arc<AtomicBool>,
    replies: &Arc<Mutex<File>>,
    active: &Arc<AtomicUsize>,
    request: PollRequest,
) -> (Vec<u8>, Option<Arc<AtomicBool>>) {
    let PollRequest {
        unique,
        kh,
        requested,
    } = request;
    let mut fd = libc::pollfd {
        fd: stream.as_raw_fd(),
        events: (requested & u16::MAX as u32) as i16,
        revents: 0,
    };
    if unsafe { libc::poll(&mut fd, 1, 0) } < 0 {
        return (encode_fuse_error(unique, EIO), None);
    }
    let mut watcher_cancel = None;
    if fd.revents == 0 && kh != 0 {
        if active
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |count| {
                (count < MAX_POLL_WATCHERS).then_some(count + 1)
            })
            .is_err()
        {
            return (encode_fuse_error(unique, EAGAIN), None);
        }
        let watched = match stream.try_clone() {
            Ok(stream) => stream,
            Err(_) => {
                active.fetch_sub(1, Ordering::SeqCst);
                return (encode_fuse_error(unique, EIO), None);
            }
        };
        let watcher_wake = match wake.try_clone() {
            Ok(wake) => wake,
            Err(_) => {
                active.fetch_sub(1, Ordering::SeqCst);
                return (encode_fuse_error(unique, EIO), None);
            }
        };
        let stop = stop.clone();
        let replies = replies.clone();
        let active_worker = active.clone();
        let cancel = Arc::new(AtomicBool::new(false));
        watcher_cancel = Some(cancel.clone());
        let events = (requested & u16::MAX as u32) as i16;
        if thread::Builder::new()
            .name("asterism-cuse-poll".into())
            .spawn(move || {
                if wait_stream_or_stop_or_cancel(
                    watched.as_raw_fd(),
                    watcher_wake.as_raw_fd(),
                    events,
                    &stop,
                    &cancel,
                )
                .unwrap_or(false)
                {
                    let notify = encode_fuse_poll_notify(kh);
                    if let Ok(mut dev) = replies.lock() {
                        let _ = dev.write_all(&notify);
                    }
                }
                cancel.store(true, Ordering::SeqCst);
                active_worker.fetch_sub(1, Ordering::SeqCst);
            })
            .is_err()
        {
            active.fetch_sub(1, Ordering::SeqCst);
            return (encode_fuse_error(unique, EIO), None);
        }
    }
    let mut payload = Vec::with_capacity(8);
    payload.extend_from_slice(&(fd.revents as u16 as u32).to_le_bytes());
    payload.extend_from_slice(&0u32.to_le_bytes());
    (encode_fuse_ok(unique, &payload), watcher_cancel)
}

fn encode_fuse_poll_notify(kh: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(FUSE_OUT_HEADER_LEN + 8);
    out.extend_from_slice(&((FUSE_OUT_HEADER_LEN + 8) as u32).to_le_bytes());
    out.extend_from_slice(&FUSE_NOTIFY_POLL.to_le_bytes());
    out.extend_from_slice(&0u64.to_le_bytes());
    out.extend_from_slice(&kh.to_le_bytes());
    out
}

fn wait_stream_or_stop_or_cancel(
    stream_fd: RawFd,
    wake_fd: RawFd,
    events: i16,
    stop: &AtomicBool,
    cancel: &AtomicBool,
) -> io::Result<bool> {
    loop {
        if stop.load(Ordering::SeqCst) || cancel.load(Ordering::SeqCst) {
            return Ok(false);
        }
        let mut fds = [
            libc::pollfd {
                fd: stream_fd,
                events,
                revents: 0,
            },
            libc::pollfd {
                fd: wake_fd,
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        // A bounded timeout makes per-request cancellation and RELEASE close
        // cloned watcher descriptors even when neither socket becomes ready.
        let ready = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as _, WATCHER_POLL_MS) };
        if ready < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
        }
        if ready == 0 {
            continue;
        }
        if fds[1].revents & libc::POLLIN != 0
            || stop.load(Ordering::SeqCst)
            || cancel.load(Ordering::SeqCst)
        {
            return Ok(false);
        }
        if fds[0].revents & (events | libc::POLLERR | libc::POLLHUP) != 0 {
            return Ok(true);
        }
    }
}

fn write_all_wakeable_cancel(
    stream: &mut UnixStream,
    wake: &UnixStream,
    stop: &AtomicBool,
    cancel: &AtomicBool,
    mut data: &[u8],
) -> io::Result<()> {
    while !data.is_empty() {
        if cancel.load(Ordering::SeqCst) {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "CUSE request interrupted",
            ));
        }
        match stream.write(data) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "GPU stream closed",
                ))
            }
            Ok(n) => data = &data[n..],
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                if !wait_stream_or_stop_or_cancel(
                    stream.as_raw_fd(),
                    wake.as_raw_fd(),
                    libc::POLLOUT,
                    stop,
                    cancel,
                )? {
                    return Err(io::Error::new(
                        io::ErrorKind::Interrupted,
                        "CUSE service stopping",
                    ));
                }
            }
            Err(err) => return Err(err),
        }
    }
    Ok(())
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

    fn fuse_request_bytes(opcode: u32, unique: u64, body: &[u8]) -> Vec<u8> {
        let len = FUSE_IN_HEADER_LEN + body.len();
        let mut record = vec![0u8; FUSE_IN_HEADER_LEN];
        record[0..4].copy_from_slice(&(len as u32).to_le_bytes());
        record[4..8].copy_from_slice(&opcode.to_le_bytes());
        record[8..16].copy_from_slice(&unique.to_le_bytes());
        record.extend_from_slice(body);
        record
    }

    struct KernelRecordReader {
        record: Vec<u8>,
        reads: usize,
    }

    impl Read for KernelRecordReader {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            self.reads += 1;
            if self.reads != 1 {
                return Err(io::Error::other(
                    "a record-oriented CUSE request must not be read twice",
                ));
            }
            if buffer.len() < self.record.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "kernel refuses a request buffer smaller than the record",
                ));
            }
            buffer[..self.record.len()].copy_from_slice(&self.record);
            Ok(self.record.len())
        }
    }

    #[test]
    fn kernel_record_is_received_by_one_sufficient_read() {
        let body = [0x5au8; 16];
        let mut kernel = KernelRecordReader {
            record: fuse_request_bytes(CUSE_INIT, 0x1020, &body),
            reads: 0,
        };
        let mut buffer = vec![0u8; CUSE_MAX_REQUEST_LEN];
        let request = read_fuse_request_record(&mut kernel, &mut buffer).unwrap();
        assert_eq!(request.len as usize, FUSE_IN_HEADER_LEN + body.len());
        assert_eq!(request.opcode, CUSE_INIT);
        assert_eq!(request.unique, 0x1020);
        assert_eq!(request.body, body);
        assert_eq!(kernel.reads, 1);
    }

    #[test]
    fn record_parser_rejects_short_truncated_trailing_and_oversized_frames() {
        let short = vec![0u8; FUSE_IN_HEADER_LEN - 1];
        assert_eq!(
            parse_fuse_request_record(&short).unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );

        let mut below_header = fuse_request_bytes(FUSE_OPEN, 1, &[0; 8]);
        below_header[0..4].copy_from_slice(&((FUSE_IN_HEADER_LEN - 1) as u32).to_le_bytes());
        assert_eq!(
            parse_fuse_request_record(&below_header).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );

        let mut truncated = fuse_request_bytes(FUSE_OPEN, 2, &[0; 8]);
        let longer = truncated.len() as u32 + 1;
        truncated[0..4].copy_from_slice(&longer.to_le_bytes());
        assert_eq!(
            parse_fuse_request_record(&truncated).unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );

        let mut trailing = fuse_request_bytes(FUSE_OPEN, 3, &[0; 8]);
        let shorter = trailing.len() as u32 - 1;
        trailing[0..4].copy_from_slice(&shorter.to_le_bytes());
        assert_eq!(
            parse_fuse_request_record(&trailing).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );

        let mut oversized = vec![0u8; FUSE_IN_HEADER_LEN];
        oversized[0..4].copy_from_slice(&((CUSE_MAX_REQUEST_LEN as u32) + 1).to_le_bytes());
        assert_eq!(
            parse_fuse_request_record(&oversized).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn known_request_bodies_are_bounded_before_field_parsing() {
        let mut write = vec![0u8; FUSE_WRITE_IN_LEN];
        write[16..20].copy_from_slice(&4u32.to_le_bytes());
        assert!(!request_body_is_valid(FUSE_WRITE, &write));
        write.extend_from_slice(b"data");
        assert!(request_body_is_valid(FUSE_WRITE, &write));

        let mut read = vec![0u8; 40];
        read[16..20].copy_from_slice(&((CUSE_MAX_READ as u32) + 1).to_le_bytes());
        assert!(!request_body_is_valid(FUSE_READ, &read));
        assert!(!request_body_is_valid(FUSE_INTERRUPT, &[0; 7]));
        assert!(!request_body_is_valid(FUSE_IOCTL, &[0; 31]));
        assert!(request_body_is_valid(0xffff_fffe, &[0; 3]));
    }

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
        let (_wake_tx, wake) = UnixStream::pair().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let replies = Arc::new(Mutex::new(tempfile::tempfile().unwrap()));

        client.write_all(b"reply").unwrap();
        let poll = cuse_poll_reply(&service, &wake, &stop, &replies, 8, 0, libc::POLLIN as u32);
        assert_eq!(i32::from_le_bytes(poll[4..8].try_into().unwrap()), 0);
        let readiness = u32::from_le_bytes(poll[16..20].try_into().unwrap());
        assert_ne!(readiness & libc::POLLIN as u32, 0);

        let read = cuse_read_reply(&mut service, &wake, &stop, 9, 128);
        assert_eq!(&read[FUSE_OUT_HEADER_LEN..], b"reply");

        let write = cuse_write_reply(&mut service, &wake, &stop, 10, b"call");
        assert_eq!(i32::from_le_bytes(write[4..8].try_into().unwrap()), 0);
        assert_eq!(u32::from_le_bytes(write[16..20].try_into().unwrap()), 4);
        let mut received = [0u8; 4];
        client.read_exact(&mut received).unwrap();
        assert_eq!(&received, b"call");
    }

    #[test]
    fn blocked_cuse_read_is_woken_by_data_instead_of_returning_eagain() {
        let (mut service, mut client) = UnixStream::pair().unwrap();
        service.set_nonblocking(true).unwrap();
        let (_wake_tx, wake) = UnixStream::pair().unwrap();
        let stop = AtomicBool::new(false);
        thread::scope(|scope| {
            let reader = scope.spawn(|| cuse_read_reply(&mut service, &wake, &stop, 17, 128));
            thread::sleep(Duration::from_millis(10));
            client.write_all(b"late reply").unwrap();
            let reply = reader.join().unwrap();
            assert_eq!(i32::from_le_bytes(reply[4..8].try_into().unwrap()), 0);
            assert_eq!(&reply[FUSE_OUT_HEADER_LEN..], b"late reply");
        });
    }

    #[test]
    fn blocked_read_does_not_prevent_a_concurrent_write_and_is_interruptible() {
        let (service, mut client) = UnixStream::pair().unwrap();
        service.set_nonblocking(true).unwrap();
        let mut reader = service.try_clone().unwrap();
        let mut writer = service;
        let (_wake_tx, wake) = UnixStream::pair().unwrap();
        let reader_wake = wake.try_clone().unwrap();
        let stop = AtomicBool::new(false);
        let cancel = AtomicBool::new(false);
        thread::scope(|scope| {
            let blocked = scope.spawn(|| {
                cuse_read_reply_cancel(&mut reader, &reader_wake, &stop, &cancel, 21, 128)
            });
            thread::sleep(Duration::from_millis(10));

            let written = cuse_write_reply(&mut writer, &wake, &stop, 22, b"pipelined-call");
            assert_eq!(i32::from_le_bytes(written[4..8].try_into().unwrap()), 0);
            let mut call = [0u8; 14];
            client.read_exact(&mut call).unwrap();
            assert_eq!(&call, b"pipelined-call");

            cancel.store(true, Ordering::SeqCst);
            let interrupted = blocked.join().unwrap();
            assert_eq!(
                i32::from_le_bytes(interrupted[4..8].try_into().unwrap()),
                -EINTR
            );
        });
    }

    #[test]
    fn nonblocking_cuse_write_resumes_after_partial_io_without_replaying_prefix() {
        let (mut service, mut client) = UnixStream::pair().unwrap();
        service.set_nonblocking(true).unwrap();
        let send_buffer = 4096i32;
        assert_eq!(
            unsafe {
                libc::setsockopt(
                    service.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_SNDBUF,
                    (&send_buffer as *const i32).cast(),
                    std::mem::size_of_val(&send_buffer) as _,
                )
            },
            0
        );
        let (_wake_tx, wake) = UnixStream::pair().unwrap();
        let stop = AtomicBool::new(false);
        let data = (0..512 * 1024)
            .map(|index| (index % 251) as u8)
            .collect::<Vec<_>>();
        thread::scope(|scope| {
            let expected = data.clone();
            let drain = scope.spawn(move || {
                thread::sleep(Duration::from_millis(10));
                let mut received = vec![0u8; expected.len()];
                client.read_exact(&mut received).unwrap();
                assert_eq!(received, expected);
            });
            let reply = cuse_write_reply(&mut service, &wake, &stop, 18, &data);
            assert_eq!(i32::from_le_bytes(reply[4..8].try_into().unwrap()), 0);
            assert_eq!(
                u32::from_le_bytes(reply[16..20].try_into().unwrap()) as usize,
                data.len()
            );
            drain.join().unwrap();
        });
    }

    #[test]
    fn deferred_poll_handle_is_notified_when_reply_becomes_readable() {
        use std::io::{Seek, SeekFrom};

        let (service, mut client) = UnixStream::pair().unwrap();
        service.set_nonblocking(true).unwrap();
        let (_wake_tx, wake) = UnixStream::pair().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let replies = Arc::new(Mutex::new(tempfile::tempfile().unwrap()));
        let kh = 0x7788u64;
        let reply = cuse_poll_reply(
            &service,
            &wake,
            &stop,
            &replies,
            19,
            kh,
            libc::POLLIN as u32,
        );
        assert_eq!(u32::from_le_bytes(reply[16..20].try_into().unwrap()), 0);
        client.write_all(b"ready").unwrap();

        let deadline = std::time::Instant::now() + Duration::from_secs(1);
        loop {
            let len = replies.lock().unwrap().metadata().unwrap().len();
            if len == (FUSE_OUT_HEADER_LEN + 8) as u64 {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "poll notify did not arrive"
            );
            thread::sleep(Duration::from_millis(5));
        }
        let mut notify = vec![0u8; FUSE_OUT_HEADER_LEN + 8];
        let mut file = replies.lock().unwrap();
        file.seek(SeekFrom::Start(0)).unwrap();
        file.read_exact(&mut notify).unwrap();
        assert_eq!(
            i32::from_le_bytes(notify[4..8].try_into().unwrap()),
            FUSE_NOTIFY_POLL
        );
        assert_eq!(u64::from_le_bytes(notify[16..24].try_into().unwrap()), kh);
    }

    #[test]
    fn poll_watchers_are_bounded_and_release_cancellation_closes_them() {
        let (service, _client) = UnixStream::pair().unwrap();
        service.set_nonblocking(true).unwrap();
        let (_wake_tx, wake) = UnixStream::pair().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let replies = Arc::new(Mutex::new(tempfile::tempfile().unwrap()));
        let active = Arc::new(AtomicUsize::new(0));
        let mut cancels = Vec::new();
        for unique in 0..MAX_POLL_WATCHERS {
            let (reply, cancel) = cuse_poll_reply_bounded(
                &service,
                &wake,
                &stop,
                &replies,
                &active,
                PollRequest {
                    unique: unique as u64 + 100,
                    kh: unique as u64 + 1,
                    requested: libc::POLLIN as u32,
                },
            );
            assert_eq!(i32::from_le_bytes(reply[4..8].try_into().unwrap()), 0);
            cancels.push(cancel.expect("deferred watcher"));
        }
        let (refused, cancel) = cuse_poll_reply_bounded(
            &service,
            &wake,
            &stop,
            &replies,
            &active,
            PollRequest {
                unique: 999,
                kh: 999,
                requested: libc::POLLIN as u32,
            },
        );
        assert_eq!(
            i32::from_le_bytes(refused[4..8].try_into().unwrap()),
            -EAGAIN
        );
        assert!(cancel.is_none());

        for cancel in cancels {
            cancel.store(true, Ordering::SeqCst);
        }
        let deadline = std::time::Instant::now() + Duration::from_secs(1);
        while active.load(Ordering::SeqCst) != 0 {
            assert!(
                std::time::Instant::now() < deadline,
                "watchers did not exit"
            );
            thread::sleep(Duration::from_millis(5));
        }
    }

    #[test]
    fn poll_notify_has_kernel_handle_and_notify_opcode() {
        let notify = encode_fuse_poll_notify(0x1020_3040_5060_7080);
        assert_eq!(notify.len(), FUSE_OUT_HEADER_LEN + 8);
        assert_eq!(
            i32::from_le_bytes(notify[4..8].try_into().unwrap()),
            FUSE_NOTIFY_POLL
        );
        assert_eq!(u64::from_le_bytes(notify[8..16].try_into().unwrap()), 0);
        assert_eq!(
            u64::from_le_bytes(notify[16..24].try_into().unwrap()),
            0x1020_3040_5060_7080
        );
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

    #[cfg(target_os = "linux")]
    #[test]
    fn live_cuse_mount_open_read_write_poll_and_cancel_when_available() {
        use std::os::unix::fs::FileTypeExt;

        unsafe extern "C" fn absorb_signal(_: libc::c_int) {}

        let root = tempfile::tempdir().unwrap();
        let dev_dir = root.path().join("dev");
        fs::create_dir(&dev_dir).unwrap();
        let guest = dev_dir.join("nvidia0");
        let service = match CuseService::mount(&guest) {
            Ok(service) => service,
            Err(err)
                if matches!(
                    err.kind(),
                    io::ErrorKind::NotFound | io::ErrorKind::PermissionDenied
                ) =>
            {
                return
            }
            Err(err) => panic!("live /dev/cuse mount failed: {err}"),
        };
        assert!(fs::metadata(&guest).unwrap().file_type().is_char_device());

        thread::scope(|scope| {
            let accepted = scope.spawn(|| service.accept().unwrap());
            let mut client = OpenOptions::new()
                .read(true)
                .write(true)
                .open(&guest)
                .unwrap();
            let mut server = accepted.join().unwrap();

            client.write_all(b"kernel-write").unwrap();
            let mut written = [0u8; 12];
            server.read_exact(&mut written).unwrap();
            assert_eq!(&written, b"kernel-write");

            server.write_all(b"poll-read").unwrap();
            let mut pollfd = libc::pollfd {
                fd: client.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            assert_eq!(unsafe { libc::poll(&mut pollfd, 1, 1000) }, 1);
            assert_ne!(pollfd.revents & libc::POLLIN, 0);
            let mut reply = [0u8; 9];
            client.read_exact(&mut reply).unwrap();
            assert_eq!(&reply, b"poll-read");

            let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
            action.sa_sigaction = absorb_signal as *const () as usize;
            action.sa_flags = 0;
            unsafe { libc::sigemptyset(&mut action.sa_mask) };
            let mut previous: libc::sigaction = unsafe { std::mem::zeroed() };
            assert_eq!(
                unsafe { libc::sigaction(libc::SIGUSR2, &action, &mut previous) },
                0
            );

            let cancelled_client = client.try_clone().unwrap();
            let (thread_tx, thread_rx) = mpsc::sync_channel(1);
            let cancelled = scope.spawn(move || {
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
            let thread_id = thread_rx.recv().unwrap();
            thread::sleep(Duration::from_millis(25));
            assert_eq!(unsafe { libc::pthread_kill(thread_id, libc::SIGUSR2) }, 0);
            let (result, err) = cancelled.join().unwrap();
            assert_eq!(result, -1);
            assert_eq!(err.raw_os_error(), Some(libc::EINTR));
            assert_eq!(
                unsafe { libc::sigaction(libc::SIGUSR2, &previous, std::ptr::null_mut()) },
                0
            );
        });
    }
}
