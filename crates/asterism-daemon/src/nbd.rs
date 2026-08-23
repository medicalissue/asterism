//! Native fixed-newstyle Network Block Device exports.
//!
//! This is deliberately a Unix-socket-only server. The caller chooses the
//! image and socket from an already-authorized volume lease; no byte supplied
//! by an NBD client is ever interpreted as a path. Each [`Server`] is one
//! volume epoch. Stopping it closes the listener and every accepted stream
//! before returning, which makes server death the writer fence even for a
//! client that connected before the socket was unlinked.

use std::collections::HashMap;
use std::fs::{File, OpenOptions, Permissions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{FileExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use anyhow::{bail, Context, Result};

use asterism_core::proc::ProcId;

const NBD_MAGIC: u64 = 0x4e42_444d_4147_4943;
const NBD_OPT_MAGIC: u64 = 0x4948_4156_454f_5054;
const NBD_REP_MAGIC: u64 = 0x0003_e889_0455_65a9;
const NBD_REQUEST_MAGIC: u32 = 0x2560_9513;
const NBD_SIMPLE_REPLY_MAGIC: u32 = 0x6744_6698;
const NBD_STRUCTURED_REPLY_MAGIC: u32 = 0x668e_33ef;

const NBD_FLAG_FIXED_NEWSTYLE: u16 = 1;
const NBD_FLAG_NO_ZEROES: u16 = 2;
const NBD_FLAG_C_FIXED_NEWSTYLE: u32 = 1;
const NBD_FLAG_C_NO_ZEROES: u32 = 2;

const NBD_FLAG_HAS_FLAGS: u16 = 1;
const NBD_FLAG_SEND_FLUSH: u16 = 1 << 2;
const NBD_FLAG_SEND_FUA: u16 = 1 << 3;
const NBD_FLAG_SEND_TRIM: u16 = 1 << 5;
const NBD_FLAG_SEND_WRITE_ZEROES: u16 = 1 << 6;
const NBD_FLAG_SEND_DF: u16 = 1 << 7;
const BASE_TRANSMISSION_FLAGS: u16 = NBD_FLAG_HAS_FLAGS
    | NBD_FLAG_SEND_FLUSH
    | NBD_FLAG_SEND_FUA
    | NBD_FLAG_SEND_TRIM
    | NBD_FLAG_SEND_WRITE_ZEROES;

fn transmission_flags(structured: bool) -> u16 {
    BASE_TRANSMISSION_FLAGS | if structured { NBD_FLAG_SEND_DF } else { 0 }
}

const NBD_OPT_EXPORT_NAME: u32 = 1;
const NBD_OPT_ABORT: u32 = 2;
const NBD_OPT_INFO: u32 = 6;
const NBD_OPT_GO: u32 = 7;
const NBD_OPT_STRUCTURED_REPLY: u32 = 8;
const NBD_OPT_LIST_META_CONTEXT: u32 = 9;
const NBD_OPT_SET_META_CONTEXT: u32 = 10;

const NBD_REP_ACK: u32 = 1;
const NBD_REP_INFO: u32 = 3;
const NBD_REP_META_CONTEXT: u32 = 4;
const NBD_REP_ERR_UNSUP: u32 = 0x8000_0001;
const NBD_REP_ERR_INVALID: u32 = 0x8000_0003;
const NBD_REP_ERR_UNKNOWN: u32 = 0x8000_0006;

const NBD_INFO_EXPORT: u16 = 0;
const NBD_INFO_NAME: u16 = 1;
const NBD_INFO_BLOCK_SIZE: u16 = 3;

const NBD_CMD_READ: u16 = 0;
const NBD_CMD_WRITE: u16 = 1;
const NBD_CMD_DISC: u16 = 2;
const NBD_CMD_FLUSH: u16 = 3;
const NBD_CMD_TRIM: u16 = 4;
const NBD_CMD_WRITE_ZEROES: u16 = 6;
const NBD_CMD_BLOCK_STATUS: u16 = 7;

const NBD_CMD_FLAG_FUA: u16 = 1;
const NBD_CMD_FLAG_NO_HOLE: u16 = 1 << 1;
const NBD_CMD_FLAG_DF: u16 = 1 << 2;
const NBD_CMD_FLAG_REQ_ONE: u16 = 1 << 3;

const NBD_REPLY_FLAG_DONE: u16 = 1;
const NBD_REPLY_TYPE_OFFSET_DATA: u16 = 1;
const NBD_REPLY_TYPE_BLOCK_STATUS: u16 = 5;
const NBD_REPLY_TYPE_ERROR: u16 = 0x8001;

const NBD_EIO: u32 = 5;
const NBD_EINVAL: u32 = 22;
const NBD_ENOSPC: u32 = 28;
const NBD_ENOTSUP: u32 = 95;

const META_CONTEXT_ID: u32 = 1;
const BASE_ALLOCATION: &[u8] = b"base:allocation";
const MIN_BLOCK: u32 = 1;
const PREFERRED_BLOCK: u32 = 4096;
const MAX_REQUEST: u32 = 32 * 1024 * 1024;
const MAX_OPTION: u32 = 1024 * 1024;
const MAX_SESSIONS: usize = 8;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

static SERVERS: OnceLock<Mutex<HashMap<PathBuf, Server>>> = OnceLock::new();

fn servers() -> &'static Mutex<HashMap<PathBuf, Server>> {
    SERVERS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Resources whose failure can be established before the durable
/// `export_started` fence is armed.
#[derive(Debug)]
pub(crate) struct Prepared {
    listener: Option<UnixListener>,
    file: Option<File>,
    socket: PathBuf,
    export: Vec<u8>,
    size: u64,
    published: bool,
}

impl Drop for Prepared {
    fn drop(&mut self) {
        if !self.published {
            let _ = std::fs::remove_file(&self.socket);
        }
    }
}

/// Open the image and bind the private socket before the caller records that
/// an exporter may run. A short image is refused rather than exported with a
/// size clients could use to reach past EOF.
pub(crate) fn prepare(image: &Path, socket: &Path, export: &str, size: u64) -> Result<Prepared> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(image)
        .with_context(|| format!("opening volume image {}", image.display()))?;
    let metadata = file
        .metadata()
        .with_context(|| format!("reading volume image metadata at {}", image.display()))?;
    if !metadata.is_file() {
        bail!("volume image {} is not a regular file", image.display());
    }
    if metadata.len() < size {
        bail!(
            "volume image {} is {} bytes, shorter than its advertised {} bytes",
            image.display(),
            metadata.len(),
            size
        );
    }
    if export.len() > MAX_OPTION as usize {
        bail!("volume export name is too long");
    }

    if alive_at(socket) {
        bail!("an NBD exporter is already bound at {}", socket.display());
    }
    std::fs::remove_file(socket).or_else(|error| {
        (error.kind() == io::ErrorKind::NotFound)
            .then_some(())
            .ok_or(error)
    })?;
    let listener = UnixListener::bind(socket)
        .with_context(|| format!("binding volume export socket {}", socket.display()))?;
    let configured = std::fs::set_permissions(socket, Permissions::from_mode(0o600))
        .with_context(|| format!("making volume export socket {} private", socket.display()))
        .and_then(|()| {
            listener
                .set_nonblocking(true)
                .context("making the NBD listener cancellable")
        });
    if let Err(error) = configured {
        drop(listener);
        let _ = std::fs::remove_file(socket);
        return Err(error);
    }

    Ok(Prepared {
        listener: Some(listener),
        file: Some(file),
        socket: socket.to_owned(),
        export: export.as_bytes().to_vec(),
        size,
        published: false,
    })
}

#[derive(Debug)]
struct Shared {
    cancel: AtomicBool,
    running: AtomicBool,
    next_session: AtomicU64,
    sessions: Mutex<HashMap<u64, UnixStream>>,
}

#[derive(Debug)]
struct Server {
    process: ProcId,
    shared: Arc<Shared>,
    thread: JoinHandle<()>,
}

/// Publish a prepared listener as the exact lease epoch's exporter.
pub(crate) fn start(mut prepared: Prepared) -> Result<ProcId> {
    let process = ProcId::capture(std::process::id())
        .context("capturing the native NBD exporter's daemon identity")?;
    let socket = prepared.socket.clone();
    let listener = prepared.listener.take().expect("prepared listener");
    let file = Arc::new(Mutex::new(prepared.file.take().expect("prepared image")));
    let export = Arc::<[u8]>::from(prepared.export.clone());
    let size = prepared.size;
    let shared = Arc::new(Shared {
        cancel: AtomicBool::new(false),
        running: AtomicBool::new(true),
        next_session: AtomicU64::new(1),
        sessions: Mutex::new(HashMap::new()),
    });

    let mut registry = servers().lock().expect("NBD server registry poisoned");
    if registry
        .get(&socket)
        .is_some_and(|server| server.shared.running.load(Ordering::Acquire))
    {
        bail!("an NBD exporter is already running at {}", socket.display());
    }
    if let Some(stale) = registry.remove(&socket) {
        let _ = stale.thread.join();
    }

    let thread_shared = Arc::clone(&shared);
    let thread_socket = socket.clone();
    let thread = thread::Builder::new()
        .name("astd-nbd-listener".into())
        .spawn(move || {
            serve(listener, file, export, size, &thread_shared);
            let _ = std::fs::remove_file(thread_socket);
            thread_shared.running.store(false, Ordering::Release);
        })
        .context("starting the native NBD listener")?;

    prepared.published = true;
    registry.insert(
        socket,
        Server {
            process: process.clone(),
            shared,
            thread,
        },
    );
    Ok(process)
}

/// Stop an in-process server if this daemon owns the exact recorded process.
/// Returning `false` means the socket is not one of this process's runtimes.
pub(crate) fn stop(socket: &Path, expected: Option<&ProcId>) -> Result<bool> {
    let mut registry = servers().lock().expect("NBD server registry poisoned");
    let Some(server) = registry.get(socket) else {
        return Ok(false);
    };
    if expected != Some(&server.process) {
        bail!(
            "refusing to stop native NBD export at {} without its exact daemon identity",
            socket.display()
        );
    }
    let server = registry.remove(socket).expect("server was present");
    drop(registry);

    server.shared.cancel.store(true, Ordering::Release);
    for stream in server
        .shared
        .sessions
        .lock()
        .expect("NBD session registry poisoned")
        .values()
    {
        let _ = stream.shutdown(std::net::Shutdown::Both);
    }
    server
        .thread
        .join()
        .map_err(|_| anyhow::anyhow!("native NBD listener panicked during revocation"))?;
    std::fs::remove_file(socket).or_else(|error| {
        (error.kind() == io::ErrorKind::NotFound)
            .then_some(())
            .ok_or(error)
    })?;
    Ok(true)
}

/// True only for the exact in-process runtime represented by the durable
/// process identity and socket.
pub(crate) fn alive(process: Option<&ProcId>, socket: &Path) -> bool {
    servers()
        .lock()
        .expect("NBD server registry poisoned")
        .get(socket)
        .is_some_and(|server| {
            process == Some(&server.process)
                && server.shared.running.load(Ordering::Acquire)
                && socket.exists()
        })
}

fn alive_at(socket: &Path) -> bool {
    servers()
        .lock()
        .expect("NBD server registry poisoned")
        .get(socket)
        .is_some_and(|server| server.shared.running.load(Ordering::Acquire))
}

fn serve(
    listener: UnixListener,
    file: Arc<Mutex<File>>,
    export: Arc<[u8]>,
    size: u64,
    shared: &Arc<Shared>,
) {
    let mut clients = Vec::new();
    while !shared.cancel.load(Ordering::Acquire) {
        reap_clients(&mut clients);
        match listener.accept() {
            Ok((stream, _)) => {
                // Linux returns a blocking accepted socket from a nonblocking
                // listener, while Darwin inherits O_NONBLOCK. Normalize the
                // session before its framing reads so a momentarily empty
                // socket is never mistaken for a malformed client.
                if let Err(error) = stream.set_nonblocking(false) {
                    let _ = stream.shutdown(std::net::Shutdown::Both);
                    eprintln!("astd: refusing NBD client whose socket mode failed: {error}");
                    continue;
                }
                let id = shared.next_session.fetch_add(1, Ordering::Relaxed);
                let mut sessions = shared.sessions.lock().expect("NBD sessions poisoned");
                if sessions.len() >= MAX_SESSIONS {
                    let _ = stream.shutdown(std::net::Shutdown::Both);
                    continue;
                }
                let Ok(control) = stream.try_clone() else {
                    continue;
                };
                sessions.insert(id, control);
                drop(sessions);

                let client_shared = Arc::clone(shared);
                let client_file = Arc::clone(&file);
                let client_export = Arc::clone(&export);
                match thread::Builder::new()
                    .name("astd-nbd-client".into())
                    .spawn(move || {
                        if let Err(error) = serve_client(
                            stream,
                            client_file,
                            &client_export,
                            size,
                            &client_shared.cancel,
                        ) {
                            eprintln!("astd: closing malformed or failed NBD client: {error:#}");
                        }
                        client_shared
                            .sessions
                            .lock()
                            .expect("NBD sessions poisoned")
                            .remove(&id);
                    }) {
                    Ok(client) => clients.push(client),
                    Err(error) => {
                        shared
                            .sessions
                            .lock()
                            .expect("NBD sessions poisoned")
                            .remove(&id);
                        eprintln!(
                            "astd: refusing NBD client whose worker could not start: {error}"
                        );
                    }
                }
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => {
                eprintln!("astd: native NBD accept failed closed: {error}");
                break;
            }
        }
    }

    shared.cancel.store(true, Ordering::Release);
    for stream in shared
        .sessions
        .lock()
        .expect("NBD sessions poisoned")
        .values()
    {
        let _ = stream.shutdown(std::net::Shutdown::Both);
    }
    for client in clients {
        let _ = client.join();
    }
}

fn reap_clients(clients: &mut Vec<JoinHandle<()>>) {
    let mut index = 0;
    while index < clients.len() {
        if clients[index].is_finished() {
            let client = clients.swap_remove(index);
            let _ = client.join();
        } else {
            index += 1;
        }
    }
}

#[derive(Debug, Default)]
struct Negotiated {
    no_zeroes: bool,
    structured: bool,
    allocation: bool,
}

fn serve_client(
    mut stream: UnixStream,
    file: Arc<Mutex<File>>,
    export: &[u8],
    size: u64,
    cancel: &AtomicBool,
) -> Result<()> {
    stream
        .set_read_timeout(Some(HANDSHAKE_TIMEOUT))
        .context("setting NBD handshake timeout")?;
    write_u64(&mut stream, NBD_MAGIC)?;
    write_u64(&mut stream, NBD_OPT_MAGIC)?;
    write_u16(&mut stream, NBD_FLAG_FIXED_NEWSTYLE | NBD_FLAG_NO_ZEROES)?;
    stream.flush()?;

    let client_flags = read_u32(&mut stream)?;
    if client_flags & NBD_FLAG_C_FIXED_NEWSTYLE == 0
        || client_flags & !(NBD_FLAG_C_FIXED_NEWSTYLE | NBD_FLAG_C_NO_ZEROES) != 0
    {
        bail!("client did not select a supported fixed-newstyle handshake");
    }
    let mut negotiated = Negotiated {
        no_zeroes: client_flags & NBD_FLAG_C_NO_ZEROES != 0,
        ..Negotiated::default()
    };
    if !negotiate(&mut stream, export, size, &mut negotiated)? {
        return Ok(());
    }
    stream.set_read_timeout(None)?;
    transmission(&mut stream, file, size, &negotiated, cancel)
}

/// Returns true when option haggling selected an export.
fn negotiate(
    stream: &mut UnixStream,
    export: &[u8],
    size: u64,
    negotiated: &mut Negotiated,
) -> Result<bool> {
    loop {
        if read_u64(stream)? != NBD_OPT_MAGIC {
            bail!("invalid NBD option magic");
        }
        let option = read_u32(stream)?;
        let length = read_u32(stream)?;
        if length > MAX_OPTION {
            bail!("NBD option payload exceeds {MAX_OPTION} bytes");
        }
        let mut payload = vec![0; length as usize];
        stream.read_exact(&mut payload)?;

        match option {
            NBD_OPT_ABORT => {
                option_reply(stream, option, NBD_REP_ACK, &[])?;
                return Ok(false);
            }
            NBD_OPT_EXPORT_NAME => {
                if payload != export {
                    // EXPORT_NAME predates framed option replies. Its only
                    // unambiguous refusal is to close the connection.
                    bail!("client requested an unauthorized NBD export name");
                }
                write_u64(stream, size)?;
                write_u16(stream, transmission_flags(negotiated.structured))?;
                if !negotiated.no_zeroes {
                    stream.write_all(&[0; 124])?;
                }
                stream.flush()?;
                return Ok(true);
            }
            NBD_OPT_INFO | NBD_OPT_GO => {
                let Ok((name, requested)) = parse_info(&payload) else {
                    option_reply(stream, option, NBD_REP_ERR_INVALID, &[])?;
                    continue;
                };
                if name != export {
                    option_reply(stream, option, NBD_REP_ERR_UNKNOWN, &[])?;
                    continue;
                }
                send_info(
                    stream,
                    option,
                    export,
                    size,
                    &requested,
                    negotiated.structured,
                )?;
                option_reply(stream, option, NBD_REP_ACK, &[])?;
                if option == NBD_OPT_GO {
                    return Ok(true);
                }
            }
            NBD_OPT_STRUCTURED_REPLY if payload.is_empty() => {
                if negotiated.structured {
                    option_reply(stream, option, NBD_REP_ERR_INVALID, &[])?;
                } else {
                    negotiated.structured = true;
                    option_reply(stream, option, NBD_REP_ACK, &[])?;
                }
            }
            NBD_OPT_LIST_META_CONTEXT | NBD_OPT_SET_META_CONTEXT => {
                if option == NBD_OPT_SET_META_CONTEXT {
                    // SET replaces prior selection even when this request is
                    // invalid or ultimately selects nothing.
                    negotiated.allocation = false;
                }
                let Ok((name, queries)) = parse_meta_context(&payload) else {
                    option_reply(stream, option, NBD_REP_ERR_INVALID, &[])?;
                    continue;
                };
                if name != export {
                    option_reply(stream, option, NBD_REP_ERR_UNKNOWN, &[])?;
                    continue;
                }
                if !negotiated.structured {
                    option_reply(stream, option, NBD_REP_ERR_INVALID, &[])?;
                    continue;
                }
                let allocation = if option == NBD_OPT_LIST_META_CONTEXT {
                    queries.is_empty()
                        || queries.iter().any(|query| {
                            *query == BASE_ALLOCATION || BASE_ALLOCATION.starts_with(query)
                        })
                } else {
                    queries.iter().any(|query| *query == BASE_ALLOCATION)
                };
                if option == NBD_OPT_SET_META_CONTEXT {
                    negotiated.allocation = allocation;
                }
                if allocation {
                    let mut context = Vec::with_capacity(4 + BASE_ALLOCATION.len());
                    let context_id = if option == NBD_OPT_LIST_META_CONTEXT {
                        0
                    } else {
                        META_CONTEXT_ID
                    };
                    context.extend_from_slice(&context_id.to_be_bytes());
                    context.extend_from_slice(BASE_ALLOCATION);
                    option_reply(stream, option, NBD_REP_META_CONTEXT, &context)?;
                }
                option_reply(stream, option, NBD_REP_ACK, &[])?;
            }
            _ => option_reply(stream, option, NBD_REP_ERR_UNSUP, &[])?,
        }
    }
}

fn parse_info(payload: &[u8]) -> std::result::Result<(&[u8], Vec<u16>), ()> {
    let mut cursor = Cursor::new(payload);
    let name_len = cursor.u32()? as usize;
    let name = cursor.bytes(name_len)?;
    let count = cursor.u16()? as usize;
    if count > 256 || cursor.remaining() != count.checked_mul(2).ok_or(())? {
        return Err(());
    }
    let mut requested = Vec::with_capacity(count);
    for _ in 0..count {
        requested.push(cursor.u16()?);
    }
    Ok((name, requested))
}

fn parse_meta_context(payload: &[u8]) -> std::result::Result<(&[u8], Vec<&[u8]>), ()> {
    let mut cursor = Cursor::new(payload);
    let name_len = cursor.u32()? as usize;
    let name = cursor.bytes(name_len)?;
    let count = cursor.u32()? as usize;
    if count > 256 {
        return Err(());
    }
    let mut queries = Vec::with_capacity(count);
    for _ in 0..count {
        let length = cursor.u32()? as usize;
        queries.push(cursor.bytes(length)?);
    }
    if cursor.remaining() != 0 {
        return Err(());
    }
    Ok((name, queries))
}

fn send_info(
    stream: &mut UnixStream,
    option: u32,
    export: &[u8],
    size: u64,
    requested: &[u16],
    structured: bool,
) -> io::Result<()> {
    let wants_all = requested.is_empty();
    // The export tuple is mandatory for INFO and GO, even when a client
    // requests only a narrower supplementary info type.
    let mut payload = Vec::with_capacity(12);
    payload.extend_from_slice(&NBD_INFO_EXPORT.to_be_bytes());
    payload.extend_from_slice(&size.to_be_bytes());
    payload.extend_from_slice(&transmission_flags(structured).to_be_bytes());
    option_reply(stream, option, NBD_REP_INFO, &payload)?;
    if wants_all || requested.contains(&NBD_INFO_NAME) {
        let mut payload = Vec::with_capacity(2 + export.len());
        payload.extend_from_slice(&NBD_INFO_NAME.to_be_bytes());
        payload.extend_from_slice(export);
        option_reply(stream, option, NBD_REP_INFO, &payload)?;
    }
    // BLOCK_SIZE is sent even when the client omitted it: GO clients need an
    // explicit request cap before they can safely enter transmission.
    let mut payload = Vec::with_capacity(14);
    payload.extend_from_slice(&NBD_INFO_BLOCK_SIZE.to_be_bytes());
    payload.extend_from_slice(&MIN_BLOCK.to_be_bytes());
    payload.extend_from_slice(&PREFERRED_BLOCK.to_be_bytes());
    payload.extend_from_slice(&MAX_REQUEST.to_be_bytes());
    option_reply(stream, option, NBD_REP_INFO, &payload)
}

fn option_reply(stream: &mut UnixStream, option: u32, kind: u32, payload: &[u8]) -> io::Result<()> {
    write_u64(stream, NBD_REP_MAGIC)?;
    write_u32(stream, option)?;
    write_u32(stream, kind)?;
    write_u32(stream, payload.len() as u32)?;
    stream.write_all(payload)?;
    stream.flush()
}

fn transmission(
    stream: &mut UnixStream,
    file: Arc<Mutex<File>>,
    size: u64,
    negotiated: &Negotiated,
    cancel: &AtomicBool,
) -> Result<()> {
    loop {
        if cancel.load(Ordering::Acquire) {
            return Ok(());
        }
        if read_u32(stream)? != NBD_REQUEST_MAGIC {
            bail!("invalid NBD request magic");
        }
        let flags = read_u16(stream)?;
        let command = read_u16(stream)?;
        let handle = read_u64(stream)?;
        let offset = read_u64(stream)?;
        let length = read_u32(stream)?;
        if length > MAX_REQUEST {
            bail!("NBD request exceeds {MAX_REQUEST} bytes");
        }

        let allowed_flags = NBD_CMD_FLAG_FUA
            | match command {
                NBD_CMD_READ => NBD_CMD_FLAG_DF,
                NBD_CMD_WRITE | NBD_CMD_TRIM => 0,
                NBD_CMD_WRITE_ZEROES => NBD_CMD_FLAG_NO_HOLE,
                NBD_CMD_BLOCK_STATUS => NBD_CMD_FLAG_REQ_ONE,
                NBD_CMD_DISC | NBD_CMD_FLUSH => 0,
                _ => 0,
            };
        if flags & !allowed_flags != 0 || (flags & NBD_CMD_FLAG_DF != 0 && !negotiated.structured) {
            // A WRITE payload follows its header. Closing instead of replying
            // is the only framing-safe rejection of flags we do not know.
            if command == NBD_CMD_WRITE {
                bail!("unsupported flags on NBD WRITE");
            }
            command_error(stream, handle, NBD_EINVAL, command, negotiated.structured)?;
            continue;
        }
        let Some(end) = offset.checked_add(u64::from(length)) else {
            if command == NBD_CMD_WRITE {
                bail!("overflowing NBD WRITE range");
            }
            command_error(stream, handle, NBD_EINVAL, command, negotiated.structured)?;
            continue;
        };
        if end > size {
            if command == NBD_CMD_WRITE {
                // Consume a bounded, known WRITE payload before replying so
                // the next request header remains aligned.
                let mut discard = vec![0; length as usize];
                stream.read_exact(&mut discard)?;
            }
            command_error(stream, handle, NBD_EINVAL, command, negotiated.structured)?;
            continue;
        }
        if matches!(command, NBD_CMD_DISC | NBD_CMD_FLUSH) && (offset != 0 || length != 0) {
            if command == NBD_CMD_DISC {
                bail!("NBD DISC contained a nonzero reserved field");
            }
            command_error(stream, handle, NBD_EINVAL, command, negotiated.structured)?;
            continue;
        }

        match command {
            NBD_CMD_READ => {
                let mut data = vec![0; length as usize];
                let result = {
                    let file = file.lock().expect("NBD image lock poisoned");
                    read_exact_at(&file, &mut data, offset)
                };
                match result {
                    Ok(()) if negotiated.structured && !data.is_empty() => {
                        let mut payload = Vec::with_capacity(8 + data.len());
                        payload.extend_from_slice(&offset.to_be_bytes());
                        payload.extend_from_slice(&data);
                        structured_reply(stream, handle, NBD_REPLY_TYPE_OFFSET_DATA, &payload)?;
                    }
                    Ok(()) if negotiated.structured => {
                        structured_error(stream, handle, NBD_EINVAL)?;
                    }
                    Ok(()) => simple_reply(stream, handle, 0, &data)?,
                    Err(error) if negotiated.structured => {
                        structured_error(stream, handle, nbd_errno(&error))?;
                    }
                    Err(error) => simple_reply(stream, handle, nbd_errno(&error), &[])?,
                }
            }
            NBD_CMD_WRITE => {
                let mut data = vec![0; length as usize];
                stream.read_exact(&mut data)?;
                let result = {
                    let file = file.lock().expect("NBD image lock poisoned");
                    write_all_at(&file, &data, offset).and_then(|()| {
                        if flags & NBD_CMD_FLAG_FUA != 0 {
                            file.sync_data()
                        } else {
                            Ok(())
                        }
                    })
                };
                simple_reply(
                    stream,
                    handle,
                    result.as_ref().err().map_or(0, nbd_errno),
                    &[],
                )?;
            }
            NBD_CMD_DISC => return Ok(()),
            NBD_CMD_FLUSH => {
                let result = file.lock().expect("NBD image lock poisoned").sync_data();
                simple_reply(
                    stream,
                    handle,
                    result.as_ref().err().map_or(0, nbd_errno),
                    &[],
                )?;
            }
            NBD_CMD_TRIM => {
                // TRIM is a hint: retaining the bytes is explicitly valid.
                // FUA still establishes the requested durability boundary.
                let result = if flags & NBD_CMD_FLAG_FUA != 0 {
                    file.lock().expect("NBD image lock poisoned").sync_data()
                } else {
                    Ok(())
                };
                simple_reply(
                    stream,
                    handle,
                    result.as_ref().err().map_or(0, nbd_errno),
                    &[],
                )?;
            }
            NBD_CMD_WRITE_ZEROES => {
                let result = {
                    let file = file.lock().expect("NBD image lock poisoned");
                    write_zeroes(&file, offset, length).and_then(|()| {
                        if flags & NBD_CMD_FLAG_FUA != 0 {
                            file.sync_data()
                        } else {
                            Ok(())
                        }
                    })
                };
                simple_reply(
                    stream,
                    handle,
                    result.as_ref().err().map_or(0, nbd_errno),
                    &[],
                )?;
            }
            NBD_CMD_BLOCK_STATUS => {
                if !negotiated.structured || !negotiated.allocation || length == 0 {
                    command_error(stream, handle, NBD_EINVAL, command, negotiated.structured)?;
                    continue;
                }
                // Reporting allocated is conservative and valid for every
                // regular file, including sparse files. It never promises a
                // hole whose future reads might expose non-zero data.
                let mut payload = Vec::with_capacity(12);
                payload.extend_from_slice(&META_CONTEXT_ID.to_be_bytes());
                payload.extend_from_slice(&length.to_be_bytes());
                payload.extend_from_slice(&0u32.to_be_bytes());
                structured_reply(stream, handle, NBD_REPLY_TYPE_BLOCK_STATUS, &payload)?;
            }
            _ => simple_reply(stream, handle, NBD_ENOTSUP, &[])?,
        }
    }
}

fn simple_reply(stream: &mut UnixStream, handle: u64, error: u32, data: &[u8]) -> io::Result<()> {
    write_u32(stream, NBD_SIMPLE_REPLY_MAGIC)?;
    write_u32(stream, error)?;
    write_u64(stream, handle)?;
    stream.write_all(data)?;
    stream.flush()
}

fn structured_reply(
    stream: &mut UnixStream,
    handle: u64,
    kind: u16,
    payload: &[u8],
) -> io::Result<()> {
    write_u32(stream, NBD_STRUCTURED_REPLY_MAGIC)?;
    write_u16(stream, NBD_REPLY_FLAG_DONE)?;
    write_u16(stream, kind)?;
    write_u64(stream, handle)?;
    write_u32(stream, payload.len() as u32)?;
    stream.write_all(payload)?;
    stream.flush()
}

fn structured_error(stream: &mut UnixStream, handle: u64, error: u32) -> io::Result<()> {
    let mut payload = Vec::with_capacity(6);
    payload.extend_from_slice(&error.to_be_bytes());
    payload.extend_from_slice(&0u16.to_be_bytes());
    structured_reply(stream, handle, NBD_REPLY_TYPE_ERROR, &payload)
}

fn command_error(
    stream: &mut UnixStream,
    handle: u64,
    error: u32,
    command: u16,
    structured: bool,
) -> io::Result<()> {
    if matches!(command, NBD_CMD_READ | NBD_CMD_BLOCK_STATUS) && structured {
        structured_error(stream, handle, error)
    } else {
        simple_reply(stream, handle, error, &[])
    }
}

fn read_exact_at(file: &File, mut data: &mut [u8], mut offset: u64) -> io::Result<()> {
    while !data.is_empty() {
        match file.read_at(data, offset) {
            Ok(0) => return Err(io::Error::from(io::ErrorKind::UnexpectedEof)),
            Ok(read) => {
                offset = offset
                    .checked_add(read as u64)
                    .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
                data = &mut data[read..];
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn write_all_at(file: &File, mut data: &[u8], mut offset: u64) -> io::Result<()> {
    while !data.is_empty() {
        match file.write_at(data, offset) {
            Ok(0) => return Err(io::Error::from(io::ErrorKind::WriteZero)),
            Ok(written) => {
                offset = offset
                    .checked_add(written as u64)
                    .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
                data = &data[written..];
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn write_zeroes(file: &File, mut offset: u64, mut length: u32) -> io::Result<()> {
    const ZEROES: [u8; 1024 * 1024] = [0; 1024 * 1024];
    while length != 0 {
        let chunk = usize::min(length as usize, ZEROES.len());
        write_all_at(file, &ZEROES[..chunk], offset)?;
        offset = offset
            .checked_add(chunk as u64)
            .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
        length -= chunk as u32;
    }
    Ok(())
}

fn nbd_errno(error: &io::Error) -> u32 {
    match error.raw_os_error() {
        Some(libc::ENOSPC) => NBD_ENOSPC,
        Some(libc::EINVAL) => NBD_EINVAL,
        _ => NBD_EIO,
    }
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn remaining(&self) -> usize {
        self.bytes.len() - self.offset
    }

    fn bytes(&mut self, length: usize) -> std::result::Result<&'a [u8], ()> {
        let end = self.offset.checked_add(length).ok_or(())?;
        let value = self.bytes.get(self.offset..end).ok_or(())?;
        self.offset = end;
        Ok(value)
    }

    fn u16(&mut self) -> std::result::Result<u16, ()> {
        Ok(u16::from_be_bytes(self.bytes(2)?.try_into().unwrap()))
    }

    fn u32(&mut self) -> std::result::Result<u32, ()> {
        Ok(u32::from_be_bytes(self.bytes(4)?.try_into().unwrap()))
    }
}

fn read_u16(reader: &mut impl Read) -> io::Result<u16> {
    let mut bytes = [0; 2];
    reader.read_exact(&mut bytes)?;
    Ok(u16::from_be_bytes(bytes))
}

fn read_u32(reader: &mut impl Read) -> io::Result<u32> {
    let mut bytes = [0; 4];
    reader.read_exact(&mut bytes)?;
    Ok(u32::from_be_bytes(bytes))
}

fn read_u64(reader: &mut impl Read) -> io::Result<u64> {
    let mut bytes = [0; 8];
    reader.read_exact(&mut bytes)?;
    Ok(u64::from_be_bytes(bytes))
}

fn write_u16(writer: &mut impl Write, value: u16) -> io::Result<()> {
    writer.write_all(&value.to_be_bytes())
}

fn write_u32(writer: &mut impl Write, value: u32) -> io::Result<()> {
    writer.write_all(&value.to_be_bytes())
}

fn write_u64(writer: &mut impl Write, value: u64) -> io::Result<()> {
    writer.write_all(&value.to_be_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SIZE: u64 = 64 * 1024;
    const EXPORT: &str = "tank-e7";

    struct Fixture {
        _dir: tempfile::TempDir,
        image: PathBuf,
        socket: PathBuf,
        process: Option<ProcId>,
    }

    impl Fixture {
        fn start() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let image = dir.path().join("disk.raw");
            let socket = dir.path().join("nbd.sock");
            let file = File::create(&image).unwrap();
            file.set_len(SIZE).unwrap();
            drop(file);
            let prepared = prepare(&image, &socket, EXPORT, SIZE).unwrap();
            let process = start(prepared).unwrap();
            Self {
                _dir: dir,
                image,
                socket,
                process: Some(process),
            }
        }

        fn stop(&mut self) {
            if let Some(process) = self.process.take() {
                assert!(stop(&self.socket, Some(&process)).unwrap());
            }
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            if let Some(process) = self.process.take() {
                let _ = stop(&self.socket, Some(&process));
            }
        }
    }

    fn client(socket: &Path) -> UnixStream {
        let mut stream = UnixStream::connect(socket).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        assert_eq!(read_u64(&mut stream).unwrap(), NBD_MAGIC);
        assert_eq!(read_u64(&mut stream).unwrap(), NBD_OPT_MAGIC);
        assert_eq!(
            read_u16(&mut stream).unwrap(),
            NBD_FLAG_FIXED_NEWSTYLE | NBD_FLAG_NO_ZEROES
        );
        write_u32(
            &mut stream,
            NBD_FLAG_C_FIXED_NEWSTYLE | NBD_FLAG_C_NO_ZEROES,
        )
        .unwrap();
        stream
    }

    fn send_option(stream: &mut UnixStream, option: u32, payload: &[u8]) {
        write_u64(stream, NBD_OPT_MAGIC).unwrap();
        write_u32(stream, option).unwrap();
        write_u32(stream, payload.len() as u32).unwrap();
        stream.write_all(payload).unwrap();
        stream.flush().unwrap();
    }

    fn option_reply(stream: &mut UnixStream) -> (u32, u32, Vec<u8>) {
        assert_eq!(read_u64(stream).unwrap(), NBD_REP_MAGIC);
        let option = read_u32(stream).unwrap();
        let kind = read_u32(stream).unwrap();
        let length = read_u32(stream).unwrap();
        let mut payload = vec![0; length as usize];
        stream.read_exact(&mut payload).unwrap();
        (option, kind, payload)
    }

    fn go(stream: &mut UnixStream, structured: bool) {
        let mut payload = Vec::new();
        payload.extend_from_slice(&(EXPORT.len() as u32).to_be_bytes());
        payload.extend_from_slice(EXPORT.as_bytes());
        payload.extend_from_slice(&1u16.to_be_bytes());
        payload.extend_from_slice(&NBD_INFO_BLOCK_SIZE.to_be_bytes());
        send_option(stream, NBD_OPT_GO, &payload);

        let mut saw_export = false;
        let mut saw_block_size = false;
        loop {
            let (option, kind, payload) = option_reply(stream);
            assert_eq!(option, NBD_OPT_GO);
            if kind == NBD_REP_ACK {
                break;
            }
            assert_eq!(kind, NBD_REP_INFO);
            match u16::from_be_bytes(payload[..2].try_into().unwrap()) {
                NBD_INFO_EXPORT => {
                    saw_export = true;
                    assert_eq!(u64::from_be_bytes(payload[2..10].try_into().unwrap()), SIZE);
                    assert_eq!(
                        u16::from_be_bytes(payload[10..12].try_into().unwrap()),
                        transmission_flags(structured)
                    );
                }
                NBD_INFO_BLOCK_SIZE => {
                    saw_block_size = true;
                    assert_eq!(
                        u32::from_be_bytes(payload[10..14].try_into().unwrap()),
                        MAX_REQUEST
                    );
                }
                other => panic!("unexpected NBD info {other}"),
            }
        }
        assert!(saw_export && saw_block_size);
    }

    fn structured_and_allocation(stream: &mut UnixStream) {
        send_option(stream, NBD_OPT_STRUCTURED_REPLY, &[]);
        assert_eq!(option_reply(stream).1, NBD_REP_ACK);

        let mut list = Vec::new();
        list.extend_from_slice(&(EXPORT.len() as u32).to_be_bytes());
        list.extend_from_slice(EXPORT.as_bytes());
        list.extend_from_slice(&0u32.to_be_bytes());
        send_option(stream, NBD_OPT_LIST_META_CONTEXT, &list);
        let (_, kind, listed) = option_reply(stream);
        assert_eq!(kind, NBD_REP_META_CONTEXT);
        assert_eq!(u32::from_be_bytes(listed[..4].try_into().unwrap()), 0);
        assert_eq!(option_reply(stream).1, NBD_REP_ACK);

        let mut payload = Vec::new();
        payload.extend_from_slice(&(EXPORT.len() as u32).to_be_bytes());
        payload.extend_from_slice(EXPORT.as_bytes());
        payload.extend_from_slice(&1u32.to_be_bytes());
        payload.extend_from_slice(&(BASE_ALLOCATION.len() as u32).to_be_bytes());
        payload.extend_from_slice(BASE_ALLOCATION);
        send_option(stream, NBD_OPT_SET_META_CONTEXT, &payload);
        let (option, kind, context) = option_reply(stream);
        assert_eq!(option, NBD_OPT_SET_META_CONTEXT);
        assert_eq!(kind, NBD_REP_META_CONTEXT);
        assert_eq!(
            u32::from_be_bytes(context[..4].try_into().unwrap()),
            META_CONTEXT_ID
        );
        assert_eq!(&context[4..], BASE_ALLOCATION);
        assert_eq!(option_reply(stream).1, NBD_REP_ACK);
    }

    fn request(
        stream: &mut UnixStream,
        command: u16,
        flags: u16,
        handle: u64,
        offset: u64,
        length: u32,
        payload: &[u8],
    ) {
        write_u32(stream, NBD_REQUEST_MAGIC).unwrap();
        write_u16(stream, flags).unwrap();
        write_u16(stream, command).unwrap();
        write_u64(stream, handle).unwrap();
        write_u64(stream, offset).unwrap();
        write_u32(stream, length).unwrap();
        stream.write_all(payload).unwrap();
        stream.flush().unwrap();
    }

    fn simple(stream: &mut UnixStream, handle: u64, length: usize) -> (u32, Vec<u8>) {
        assert_eq!(read_u32(stream).unwrap(), NBD_SIMPLE_REPLY_MAGIC);
        let error = read_u32(stream).unwrap();
        assert_eq!(read_u64(stream).unwrap(), handle);
        let mut data = vec![0; length];
        stream.read_exact(&mut data).unwrap();
        (error, data)
    }

    fn structured_data(
        stream: &mut UnixStream,
        handle: u64,
        offset: u64,
        length: usize,
    ) -> Vec<u8> {
        assert_eq!(read_u32(stream).unwrap(), NBD_STRUCTURED_REPLY_MAGIC);
        assert_eq!(read_u16(stream).unwrap(), NBD_REPLY_FLAG_DONE);
        assert_eq!(read_u16(stream).unwrap(), NBD_REPLY_TYPE_OFFSET_DATA);
        assert_eq!(read_u64(stream).unwrap(), handle);
        assert_eq!(read_u32(stream).unwrap(), 8 + length as u32);
        assert_eq!(read_u64(stream).unwrap(), offset);
        let mut data = vec![0; length];
        stream.read_exact(&mut data).unwrap();
        data
    }

    #[test]
    fn fixed_newstyle_commands_and_block_status_round_trip() {
        let mut fixture = Fixture::start();
        let process = fixture.process.as_ref().unwrap();
        assert!(alive(Some(process), &fixture.socket));
        let mut stream = client(&fixture.socket);

        // Unknown options are consumed and rejected without losing option
        // framing; the same connection can continue into GO.
        send_option(&mut stream, 0xfeed, b"bounded unknown payload");
        assert_eq!(option_reply(&mut stream).1, NBD_REP_ERR_UNSUP);
        structured_and_allocation(&mut stream);
        go(&mut stream, true);

        let written = b"native nbd";
        request(
            &mut stream,
            NBD_CMD_WRITE,
            NBD_CMD_FLAG_FUA,
            1,
            4096,
            written.len() as u32,
            written,
        );
        assert_eq!(simple(&mut stream, 1, 0).0, 0);

        request(
            &mut stream,
            NBD_CMD_READ,
            NBD_CMD_FLAG_DF,
            2,
            4096,
            written.len() as u32,
            &[],
        );
        assert_eq!(read_u32(&mut stream).unwrap(), NBD_STRUCTURED_REPLY_MAGIC);
        assert_eq!(read_u16(&mut stream).unwrap(), NBD_REPLY_FLAG_DONE);
        assert_eq!(read_u16(&mut stream).unwrap(), NBD_REPLY_TYPE_OFFSET_DATA);
        assert_eq!(read_u64(&mut stream).unwrap(), 2);
        assert_eq!(read_u32(&mut stream).unwrap(), 8 + written.len() as u32);
        assert_eq!(read_u64(&mut stream).unwrap(), 4096);
        let mut read = vec![0; written.len()];
        stream.read_exact(&mut read).unwrap();
        assert_eq!(read, written);

        request(&mut stream, NBD_CMD_FLUSH, NBD_CMD_FLAG_FUA, 3, 0, 0, &[]);
        assert_eq!(simple(&mut stream, 3, 0).0, 0);
        request(
            &mut stream,
            NBD_CMD_TRIM,
            NBD_CMD_FLAG_FUA,
            4,
            8192,
            4096,
            &[],
        );
        assert_eq!(simple(&mut stream, 4, 0).0, 0);

        request(
            &mut stream,
            NBD_CMD_WRITE_ZEROES,
            NBD_CMD_FLAG_FUA | NBD_CMD_FLAG_NO_HOLE,
            5,
            4096,
            written.len() as u32,
            &[],
        );
        assert_eq!(simple(&mut stream, 5, 0).0, 0);
        request(
            &mut stream,
            NBD_CMD_READ,
            0,
            6,
            4096,
            written.len() as u32,
            &[],
        );
        assert_eq!(
            structured_data(&mut stream, 6, 4096, written.len()),
            vec![0; written.len()]
        );

        request(
            &mut stream,
            NBD_CMD_BLOCK_STATUS,
            NBD_CMD_FLAG_REQ_ONE,
            7,
            0,
            4096,
            &[],
        );
        assert_eq!(read_u32(&mut stream).unwrap(), NBD_STRUCTURED_REPLY_MAGIC);
        assert_eq!(read_u16(&mut stream).unwrap(), NBD_REPLY_FLAG_DONE);
        assert_eq!(read_u16(&mut stream).unwrap(), NBD_REPLY_TYPE_BLOCK_STATUS);
        assert_eq!(read_u64(&mut stream).unwrap(), 7);
        assert_eq!(read_u32(&mut stream).unwrap(), 12);
        assert_eq!(read_u32(&mut stream).unwrap(), META_CONTEXT_ID);
        assert_eq!(read_u32(&mut stream).unwrap(), 4096);
        assert_eq!(read_u32(&mut stream).unwrap(), 0);

        request(&mut stream, NBD_CMD_DISC, 0, 8, 0, 0, &[]);
        drop(stream);
        fixture.stop();
        assert!(!fixture.socket.exists());
    }

    #[test]
    fn export_name_and_abort_are_fixed_newstyle_compatible() {
        let mut fixture = Fixture::start();
        let mut info_client = client(&fixture.socket);
        let mut info = Vec::new();
        info.extend_from_slice(&(EXPORT.len() as u32).to_be_bytes());
        info.extend_from_slice(EXPORT.as_bytes());
        info.extend_from_slice(&0u16.to_be_bytes());
        send_option(&mut info_client, NBD_OPT_INFO, &info);
        let mut info_kinds = Vec::new();
        loop {
            let (_, kind, _) = option_reply(&mut info_client);
            if kind == NBD_REP_ACK {
                break;
            }
            info_kinds.push(kind);
        }
        assert_eq!(info_kinds, vec![NBD_REP_INFO, NBD_REP_INFO, NBD_REP_INFO]);
        send_option(&mut info_client, NBD_OPT_ABORT, &[]);
        assert_eq!(option_reply(&mut info_client).1, NBD_REP_ACK);

        let mut export_client = client(&fixture.socket);
        send_option(&mut export_client, NBD_OPT_EXPORT_NAME, EXPORT.as_bytes());
        assert_eq!(read_u64(&mut export_client).unwrap(), SIZE);
        assert_eq!(
            read_u16(&mut export_client).unwrap(),
            transmission_flags(false)
        );
        request(&mut export_client, NBD_CMD_DISC, 0, 1, 0, 0, &[]);

        let mut aborted = client(&fixture.socket);
        send_option(
            &mut aborted,
            NBD_OPT_ABORT,
            b"ignored compatibility payload",
        );
        let (option, kind, payload) = option_reply(&mut aborted);
        assert_eq!((option, kind), (NBD_OPT_ABORT, NBD_REP_ACK));
        assert!(payload.is_empty());
        let mut byte = [0];
        assert!(matches!(aborted.read(&mut byte), Ok(0) | Err(_)));
        fixture.stop();
    }

    #[test]
    fn out_of_bounds_write_is_consumed_but_oversize_and_bad_flags_close() {
        let mut fixture = Fixture::start();
        let mut stream = client(&fixture.socket);
        go(&mut stream, false);
        request(&mut stream, NBD_CMD_WRITE, 0, 1, SIZE - 2, 4, b"four");
        assert_eq!(simple(&mut stream, 1, 0).0, NBD_EINVAL);
        request(&mut stream, NBD_CMD_READ, 0, 2, 0, 4, &[]);
        assert_eq!(simple(&mut stream, 2, 4), (0, vec![0; 4]));

        let mut oversize = client(&fixture.socket);
        go(&mut oversize, false);
        request(&mut oversize, NBD_CMD_READ, 0, 3, 0, MAX_REQUEST + 1, &[]);
        let mut byte = [0];
        assert!(matches!(oversize.read(&mut byte), Ok(0) | Err(_)));

        let mut bad_flags = client(&fixture.socket);
        go(&mut bad_flags, false);
        request(&mut bad_flags, NBD_CMD_WRITE, 0x8000, 4, 0, 4, b"junk");
        assert!(matches!(bad_flags.read(&mut byte), Ok(0) | Err(_)));
        fixture.stop();
    }

    #[test]
    fn contention_is_refused_and_revocation_disconnects_accepted_sessions() {
        let mut fixture = Fixture::start();
        let competing = prepare(&fixture.image, &fixture.socket, "other-e8", SIZE)
            .unwrap_err()
            .to_string();
        assert!(competing.contains("already bound"), "{competing}");

        let process = fixture.process.as_ref().unwrap().clone();
        let mut stale = process.clone();
        if let Some(ticks) = stale.started_ticks.as_mut() {
            *ticks = ticks.saturating_sub(1);
        } else {
            stale.started_us = stale.started_us.saturating_sub(1);
        }
        assert!(stop(&fixture.socket, Some(&stale)).is_err());
        assert!(alive(Some(&process), &fixture.socket));
        assert!(fixture.socket.exists());

        let mut stream = client(&fixture.socket);
        go(&mut stream, false);
        fixture.stop();
        assert!(!alive(Some(&process), &fixture.socket));
        let mut byte = [0];
        assert!(matches!(stream.read(&mut byte), Ok(0) | Err(_)));
    }

    #[test]
    fn malformed_option_payload_and_wrong_export_fail_closed() {
        let mut fixture = Fixture::start();
        let mut wrong = client(&fixture.socket);
        send_option(
            &mut wrong,
            NBD_OPT_EXPORT_NAME,
            b"client/path/is/not/authority",
        );
        let mut byte = [0];
        assert!(matches!(wrong.read(&mut byte), Ok(0) | Err(_)));

        let mut malformed = client(&fixture.socket);
        send_option(&mut malformed, NBD_OPT_GO, &[0, 0, 1]);
        assert_eq!(option_reply(&mut malformed).1, NBD_REP_ERR_INVALID);
        write_u64(&mut malformed, 0).unwrap();
        malformed.flush().unwrap();
        assert!(matches!(malformed.read(&mut byte), Ok(0) | Err(_)));
        fixture.stop();
    }
}
