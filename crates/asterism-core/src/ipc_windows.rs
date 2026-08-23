//! Windows local control-plane door.
//!
//! `ast` and `astd` use a byte-mode Windows named pipe, never a TCP port. The
//! pipe name is derived from the logical socket path and the current Windows
//! user SID, so distinct users and `ASTERISM_HOME`s cannot collide. Every
//! server instance carries a protected DACL granting access only to that SID,
//! and rejects remote clients in the kernel.
//!
//! The DACL is the first boundary, not the only one. After `ConnectNamedPipe`
//! completes, the daemon asks Windows to impersonate that exact pipe client,
//! reads the client token's `TokenUser` SID, reverts immediately, and compares
//! it with the SID captured when the door was created. No identity asserted on
//! the wire participates in admission.

use std::cell::Cell;
use std::ffi::{c_void, OsStr};
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::mem::size_of;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, RawHandle};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::ptr::{null, null_mut};
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
use tokio::sync::Mutex;
use windows_sys::Win32::Foundation::{
    CloseHandle, LocalFree, ERROR_FILE_NOT_FOUND, ERROR_IO_PENDING, ERROR_PATH_NOT_FOUND,
    ERROR_PIPE_BUSY, ERROR_SEM_TIMEOUT, GENERIC_READ, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE,
    WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{
    GetLengthSid, GetTokenInformation, RevertToSelf, TokenUser, SECURITY_ATTRIBUTES, TOKEN_QUERY,
    TOKEN_USER,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, ReadFile, WriteFile, FILE_FLAG_OVERLAPPED, OPEN_EXISTING, SECURITY_IDENTIFICATION,
    SECURITY_SQOS_PRESENT,
};
use windows_sys::Win32::System::Pipes::{ImpersonateNamedPipeClient, WaitNamedPipeW};
use windows_sys::Win32::System::Threading::{
    CreateEventW, GetCurrentProcess, GetCurrentThread, OpenProcessToken, OpenThreadToken,
    WaitForSingleObject, INFINITE,
};
use windows_sys::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};

pub const MAX_REQUEST_FRAME: usize = crate::protocol::MESH_FRAME_LIMIT;
pub const MAX_RESPONSE_FRAME: usize = 32 * 1024 * 1024;
pub const FRAME_DEADLINE: Duration = Duration::from_secs(30);
pub const WRITE_DEADLINE: Duration = Duration::from_secs(30);
pub const MAX_CONNECTIONS: usize = 256;
pub const ACCEPT_WAIT: Duration = Duration::from_secs(5);
pub const HANDSHAKE_DEADLINE: Duration = Duration::from_secs(20);

/// Synchronous client stream used by `ast`.
///
/// The handle is opened for overlapped I/O so read and write deadlines remain
/// real deadlines instead of advisory fields around a blocking Win32 call.
#[derive(Debug)]
pub struct Stream {
    file: File,
    read_timeout: Cell<Option<Duration>>,
    write_timeout: Cell<Option<Duration>>,
}

impl Stream {
    pub fn try_clone(&self) -> io::Result<Stream> {
        Ok(Stream {
            file: self.file.try_clone()?,
            read_timeout: Cell::new(self.read_timeout.get()),
            write_timeout: Cell::new(self.write_timeout.get()),
        })
    }

    pub fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        validate_timeout(timeout)?;
        self.read_timeout.set(timeout);
        Ok(())
    }

    pub fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        validate_timeout(timeout)?;
        self.write_timeout.set(timeout);
        Ok(())
    }

    fn operation(&self, buf: IoBuffer, timeout: Option<Duration>) -> io::Result<usize> {
        if buf.len() == 0 {
            return Ok(0);
        }
        let event = unsafe { CreateEventW(null(), 1, 0, null()) };
        if event.is_null() {
            return Err(io::Error::last_os_error());
        }
        let event = Handle(event);
        let mut overlapped = OVERLAPPED {
            hEvent: event.0,
            ..Default::default()
        };
        let len = buf.len().min(u32::MAX as usize) as u32;
        let mut transferred = 0;
        let started = unsafe {
            match buf {
                IoBuffer::Read(ptr, _) => ReadFile(
                    self.file.as_raw_handle() as HANDLE,
                    ptr,
                    len,
                    &mut transferred,
                    &mut overlapped,
                ),
                IoBuffer::Write(ptr, _) => WriteFile(
                    self.file.as_raw_handle() as HANDLE,
                    ptr,
                    len,
                    &mut transferred,
                    &mut overlapped,
                ),
            }
        };
        if started != 0 {
            return Ok(transferred as usize);
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(ERROR_IO_PENDING as i32) {
            return Err(error);
        }

        let waited = unsafe { WaitForSingleObject(event.0, timeout_ms(timeout)) };
        if waited == WAIT_TIMEOUT {
            unsafe {
                CancelIoEx(self.file.as_raw_handle() as HANDLE, &overlapped);
                // Keep the buffer and OVERLAPPED alive until cancellation is
                // complete; returning before this wait would be use-after-free.
                WaitForSingleObject(event.0, INFINITE);
            }
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "the named-pipe operation timed out",
            ));
        }
        if waited != WAIT_OBJECT_0 {
            return Err(io::Error::last_os_error());
        }
        let completed = unsafe {
            GetOverlappedResult(
                self.file.as_raw_handle() as HANDLE,
                &overlapped,
                &mut transferred,
                0,
            )
        };
        if completed == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(transferred as usize)
    }
}

impl Read for Stream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.operation(
            IoBuffer::Read(buf.as_mut_ptr(), buf.len()),
            self.read_timeout.get(),
        )
    }
}

impl Write for Stream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.operation(
            IoBuffer::Write(buf.as_ptr(), buf.len()),
            self.write_timeout.get(),
        )
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Write for &Stream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.operation(
            IoBuffer::Write(buf.as_ptr(), buf.len()),
            self.write_timeout.get(),
        )
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[derive(Clone, Copy)]
enum IoBuffer {
    Read(*mut u8, usize),
    Write(*const u8, usize),
}

impl IoBuffer {
    fn len(self) -> usize {
        match self {
            IoBuffer::Read(_, len) | IoBuffer::Write(_, len) => len,
        }
    }
}

fn validate_timeout(timeout: Option<Duration>) -> io::Result<()> {
    if timeout == Some(Duration::ZERO) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "a zero timeout is not valid",
        ));
    }
    Ok(())
}

fn timeout_ms(timeout: Option<Duration>) -> u32 {
    timeout.map_or(INFINITE, |duration| {
        duration.as_millis().clamp(1, (INFINITE - 1) as u128) as u32
    })
}

/// One connected server-side named-pipe instance with its admission SID.
#[derive(Debug)]
pub struct ServerStream {
    pipe: NamedPipeServer,
    owner_sid: Arc<Vec<u8>>,
}

impl AsRawHandle for ServerStream {
    fn as_raw_handle(&self) -> RawHandle {
        self.pipe.as_raw_handle()
    }
}

impl AsyncRead for ServerStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.pipe).poll_read(cx, buf)
    }
}

impl AsyncWrite for ServerStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.pipe).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.pipe).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.pipe).poll_shutdown(cx)
    }
}

/// One unconnected pipe instance is kept available at all times. Windows
/// accepts on an instance handle, so its replacement is created before the
/// connected instance is handed upward.
#[derive(Debug)]
pub struct Listener {
    name: String,
    owner_sid: Arc<Vec<u8>>,
    next: Mutex<Option<NamedPipeServer>>,
}

impl Listener {
    fn bind(sock: &Path) -> Result<Listener> {
        let owner_sid = Arc::new(current_process_sid().context("reading the astd owner SID")?);
        let name = pipe_name(sock, &owner_sid);
        let next = create_server(&name, &owner_sid, true)
            .with_context(|| format!("binding Windows named pipe {name}"))?;
        Ok(Listener {
            name,
            owner_sid,
            next: Mutex::new(Some(next)),
        })
    }

    pub async fn accept(&self) -> io::Result<ServerStream> {
        let mut next = self.next.lock().await;
        let connected = next
            .take()
            .expect("the named-pipe accept mutex always owns one instance");
        if let Err(error) = connected.connect().await {
            *next = Some(create_server(&self.name, &self.owner_sid, false)?);
            return Err(error);
        }
        *next = Some(create_server(&self.name, &self.owner_sid, false)?);
        Ok(ServerStream {
            pipe: connected,
            owner_sid: Arc::clone(&self.owner_sid),
        })
    }
}

pub fn connect(sock: &Path) -> io::Result<Stream> {
    let sid = current_process_sid()?;
    connect_name(&pipe_name(sock, &sid))
}

fn connect_name(name: &str) -> io::Result<Stream> {
    let wide = wide(name);
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            0,
            null(),
            OPEN_EXISTING,
            FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
            null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    let file = unsafe { File::from_raw_handle(handle as RawHandle) };
    Ok(Stream {
        file,
        read_timeout: Cell::new(None),
        write_timeout: Cell::new(None),
    })
}

fn create_server(name: &str, sid: &[u8], first: bool) -> io::Result<NamedPipeServer> {
    let sid = sid_string(sid)?;
    let sddl = wide(format!("O:{sid}D:P(A;;GA;;;{sid})"));
    let mut descriptor = null_mut();
    let converted = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            null_mut(),
        )
    };
    if converted == 0 {
        return Err(io::Error::last_os_error());
    }
    let descriptor = LocalAllocation(descriptor);
    let mut attrs = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: 0,
    };
    let mut options = ServerOptions::new();
    options
        .first_pipe_instance(first)
        .reject_remote_clients(true);
    unsafe {
        options.create_with_security_attributes_raw(
            name,
            (&mut attrs as *mut SECURITY_ATTRIBUTES).cast(),
        )
    }
}

pub fn admit_peer(stream: &ServerStream) -> Result<u32> {
    admit_peer_as(stream, &stream.owner_sid)
}

/// Exercise the refusal half of OS-backed admission against a deliberately
/// mismatched SID. Available only to the hosted Windows conformance build;
/// product builds have no alternate admission identity.
#[cfg(feature = "windows-ipc-conformance")]
pub fn refuse_peer_for_conformance(stream: &ServerStream) -> Result<u32> {
    let mut unauthorized = stream.owner_sid.as_ref().clone();
    let last = unauthorized
        .len()
        .checked_sub(1)
        .context("the Windows user SID was empty")?;
    unauthorized[last] ^= 1;
    admit_peer_as(stream, &unauthorized)
}

fn admit_peer_as(stream: &ServerStream, expected_sid: &[u8]) -> Result<u32> {
    let actual = pipe_client_sid(stream.as_raw_handle() as HANDLE)
        .context("reading the Windows named-pipe client's OS identity")?;
    if actual != expected_sid {
        bail!(
            "refusing Windows named-pipe peer SID {}; astd belongs to SID {}",
            sid_string(&actual).unwrap_or_else(|_| "<unprintable>".into()),
            sid_string(expected_sid).unwrap_or_else(|_| "<unprintable>".into()),
        );
    }
    Ok(sid_hash(&actual))
}

fn pipe_client_sid(pipe: HANDLE) -> io::Result<Vec<u8>> {
    if unsafe { ImpersonateNamedPipeClient(pipe) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let _revert = Revert;
    let mut token = null_mut();
    if unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let token = Handle(token);
    token_sid(token.0)
}

fn current_process_sid() -> io::Result<Vec<u8>> {
    let mut token = null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let token = Handle(token);
    token_sid(token.0)
}

fn token_sid(token: HANDLE) -> io::Result<Vec<u8>> {
    let mut needed = 0;
    unsafe {
        GetTokenInformation(token, TokenUser, null_mut(), 0, &mut needed);
    }
    if needed == 0 {
        return Err(io::Error::last_os_error());
    }
    let words = (needed as usize).div_ceil(size_of::<usize>());
    let mut buffer = vec![0usize; words];
    if unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            buffer.as_mut_ptr().cast(),
            needed,
            &mut needed,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let user = unsafe { &*(buffer.as_ptr().cast::<TOKEN_USER>()) };
    let len = unsafe { GetLengthSid(user.User.Sid) } as usize;
    if len == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { std::slice::from_raw_parts(user.User.Sid.cast::<u8>(), len) }.to_vec())
}

fn sid_string(sid: &[u8]) -> io::Result<String> {
    let mut text = null_mut();
    if unsafe { ConvertSidToStringSidW(sid.as_ptr().cast_mut().cast(), &mut text) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let text = LocalWideString(text);
    let mut len = 0;
    unsafe {
        while *text.0.add(len) != 0 {
            len += 1;
        }
        Ok(String::from_utf16_lossy(std::slice::from_raw_parts(
            text.0, len,
        )))
    }
}

fn pipe_name(sock: &Path, sid: &[u8]) -> String {
    let mut material = Vec::new();
    for unit in sock.as_os_str().encode_wide() {
        material.extend_from_slice(&unit.to_le_bytes());
    }
    material.extend_from_slice(sid);
    let digest = blake3::hash(&material).to_hex();
    let sid = sid_string(sid).unwrap_or_else(|_| format!("uid-{}", sid_hash(sid)));
    format!(
        r"\\.\pipe\asterism-{}-{}",
        sid.replace('-', "_"),
        &digest[..32]
    )
}

fn wide(value: impl AsRef<OsStr>) -> Vec<u16> {
    value.as_ref().encode_wide().chain(Some(0)).collect()
}

fn sid_hash(sid: &[u8]) -> u32 {
    let digest = blake3::hash(sid);
    u32::from_le_bytes(
        digest.as_bytes()[..4]
            .try_into()
            .expect("four digest bytes"),
    )
}

pub fn own_uid() -> u32 {
    current_process_sid().map_or(0, |sid| sid_hash(&sid))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Privacy {
    Already,
    Created,
    Tightened { was: u32 },
}

pub fn private_dir(path: &Path) -> Result<Privacy> {
    if path.is_dir() {
        return Ok(Privacy::Already);
    }
    if path.exists() {
        bail!("{} exists and is not a directory", path.display());
    }
    std::fs::create_dir_all(path).with_context(|| format!("creating {}", path.display()))?;
    Ok(Privacy::Created)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketState {
    Missing,
    Ready,
}

pub fn audit_socket(sock: &Path) -> Result<SocketState> {
    let sid = current_process_sid().context("reading the current Windows user SID")?;
    let name = pipe_name(sock, &sid);
    let name = wide(&name);
    if unsafe { WaitNamedPipeW(name.as_ptr(), 0) } != 0 {
        return Ok(SocketState::Ready);
    }
    let error = io::Error::last_os_error();
    match error.raw_os_error().map(|code| code as u32) {
        Some(ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND) => Ok(SocketState::Missing),
        Some(ERROR_PIPE_BUSY | ERROR_SEM_TIMEOUT) => Ok(SocketState::Ready),
        _ => Err(error).context("auditing the Windows named-pipe door"),
    }
}

#[derive(Debug)]
pub struct Door {
    listener: Listener,
    sock: PathBuf,
    _lock: File,
}

impl Door {
    pub fn open(home: &Path, sock: &Path) -> Result<Door> {
        private_dir(home)?;
        let lock = elect(home)?;
        if let Some(parent) = sock.parent() {
            private_dir(parent)?;
        }
        let listener = Listener::bind(sock)?;
        Ok(Door {
            listener,
            sock: sock.to_path_buf(),
            _lock: lock,
        })
    }

    pub fn listener(&self) -> &Listener {
        &self.listener
    }

    pub fn into_parts(self) -> (Listener, File, PathBuf) {
        (self.listener, self._lock, self.sock)
    }

    pub fn socket(&self) -> &Path {
        &self.sock
    }
}

fn elect(home: &Path) -> Result<File> {
    let path = home.join("astd.lock");
    match lock_file(&path, Wait::No)? {
        Some(file) => Ok(file),
        None => bail!(
            "another astd already holds {} — one daemon serves one ASTERISM_HOME. \
             Stop it, or set ASTERISM_HOME to a different directory.",
            home.display()
        ),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Wait {
    Yes,
    No,
}

pub fn lock_file(path: &Path, wait: Wait) -> Result<Option<File>> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
        .with_context(|| format!("opening {}", path.display()))?;
    match wait {
        Wait::Yes => file
            .lock()
            .map(|()| Some(file))
            .with_context(|| format!("locking {}", path.display())),
        Wait::No => match file.try_lock() {
            Ok(()) => Ok(Some(file)),
            Err(std::fs::TryLockError::WouldBlock) => Ok(None),
            Err(std::fs::TryLockError::Error(error)) => {
                Err(error).with_context(|| format!("locking {}", path.display()))
            }
        },
    }
}

struct Handle(HANDLE);

impl Drop for Handle {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.0);
        }
    }
}

struct LocalAllocation(*mut c_void);

impl Drop for LocalAllocation {
    fn drop(&mut self) {
        unsafe {
            LocalFree(self.0);
        }
    }
}

struct LocalWideString(*mut u16);

impl Drop for LocalWideString {
    fn drop(&mut self) {
        unsafe {
            LocalFree(self.0.cast());
        }
    }
}

struct Revert;

impl Drop for Revert {
    fn drop(&mut self) {
        unsafe {
            RevertToSelf();
        }
    }
}
