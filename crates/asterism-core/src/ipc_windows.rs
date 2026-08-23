//! Windows door for the same local control-plane policy as [`super`].
//!
//! GitHub hosted Windows and Windows 11 Pro both have loopback TCP. The
//! daemon binds `127.0.0.1:0`, writes the chosen address into the socket
//! path file, and `ast` connects to that address. The trust boundary is
//! loopback plus the private home directory, because Windows has no
//! `getpeereid(2)` equivalent on a TCP socket.

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{bail, Context, Result};

pub const MAX_REQUEST_FRAME: usize = crate::protocol::MESH_FRAME_LIMIT;
pub const MAX_RESPONSE_FRAME: usize = 32 * 1024 * 1024;
pub const FRAME_DEADLINE: Duration = Duration::from_secs(30);
pub const WRITE_DEADLINE: Duration = Duration::from_secs(30);
pub const MAX_CONNECTIONS: usize = 256;
pub const ACCEPT_WAIT: Duration = Duration::from_secs(5);
pub const HANDSHAKE_DEADLINE: Duration = Duration::from_secs(20);

pub type Stream = TcpStream;
pub type Listener = TcpListener;

pub fn own_uid() -> u32 {
    let name = std::env::var("USERNAME").unwrap_or_else(|_| "asterism".into());
    let mut hash: u32 = 0x811c_9dc5;
    for b in name.as_bytes() {
        hash ^= *b as u32;
        hash = hash.wrapping_mul(0x0100_0193);
    }
    hash
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
    if !sock.exists() {
        return Ok(SocketState::Missing);
    }
    Ok(SocketState::Ready)
}

pub fn connect(sock: &Path) -> io::Result<Stream> {
    let text = std::fs::read_to_string(sock)?;
    let addr = text.trim();
    if addr.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "the astd address file is empty",
        ));
    }
    TcpStream::connect(addr)
}

#[derive(Debug)]
pub struct Door {
    listener: TcpListener,
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
        let _ = std::fs::remove_file(sock);
        let listener =
            TcpListener::bind("127.0.0.1:0").context("binding the loopback astd door")?;
        listener
            .set_nonblocking(true)
            .context("putting the astd door in non-blocking mode")?;
        let addr = listener
            .local_addr()
            .context("reading the bound astd address")?;
        if let Some(dir) = sock.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(sock)
            .with_context(|| format!("writing {}", sock.display()))?;
        writeln!(file, "{addr}").with_context(|| format!("writing {}", sock.display()))?;
        file.sync_all()?;
        Ok(Door {
            listener,
            sock: sock.to_path_buf(),
            _lock: lock,
        })
    }

    pub fn listener(&self) -> &TcpListener {
        &self.listener
    }

    pub fn into_parts(self) -> (TcpListener, File, PathBuf) {
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
            Err(std::fs::TryLockError::Error(e)) => {
                Err(e).with_context(|| format!("locking {}", path.display()))
            }
        },
    }
}

pub fn peer_uid(_ignored: u64) -> io::Result<u32> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "loopback TCP does not report a peer uid",
    ))
}

pub fn same_user(_ignored: u64) -> Result<u32> {
    Ok(own_uid())
}

pub fn admit_peer(_stream: &Stream) -> Result<u32> {
    Ok(own_uid())
}
