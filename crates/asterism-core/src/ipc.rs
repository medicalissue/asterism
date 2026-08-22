//! The local control plane's door: one unix socket, and one place that says
//! who may come through it and on what terms.
//!
//! `ast` and `astd` talk over `$ASTERISM_HOME/astd.sock` — one JSON request
//! per line, one JSON response per line. That socket is the whole local
//! attack surface: everything the daemon can do to this device's instances,
//! its volumes, its orbit membership and its secrets is reachable through it,
//! and it needs no credential beyond being able to `connect(2)`. So what
//! guards it cannot be a check a command remembered to make. It has to be the
//! door.
//!
//! This module is that door, and it is deliberately the *policy* half rather
//! than the plumbing: no async, no runtime, so both binaries can use the same
//! rules — `astd` before it binds, `ast` before it connects. The daemon's
//! async framing lives on top of it in `astd`'s own `transport` module.
//!
//! # What the door is made of
//!
//! **A private directory.** `$ASTERISM_HOME` holds the registry, the orbit
//! store, this device's mesh key, cached guest keys, the secret catalog, and
//! every staging file a commit passes through. The files are `0600`
//! ([`crate::durable::commit_private`]); the directory was `0755`, which
//! meant a second user on the machine could list every instance name, watch
//! for a predictable staging path, and see the socket. [`private_dir`] is
//! what makes it `0700` — creating it that way, and tightening a directory an
//! older `astd` left open.
//!
//! **A private socket.** `0600`, in that private directory, so nothing but
//! this user can reach it. The mode is a second lock on a door already
//! behind a wall: the parent directory is what makes the window between
//! `bind(2)` and the `chmod` unexploitable, because in that window there is
//! no path another user can even traverse to.
//!
//! **The peer's uid.** Asked of the kernel, not of the peer — `getpeereid(2)`
//! on Apple and the BSDs, `SO_PEERCRED` on Linux. A connection from another
//! uid is refused before its first frame is read. Nothing above should be
//! able to produce such a connection; this is what makes that a fact rather
//! than an argument, and it is what still holds if a future socket is put
//! somewhere shared.
//!
//! **One daemon.** [`elect`] takes an exclusive `flock(2)` on
//! `$ASTERISM_HOME/astd.lock` and holds it for the process's life. Probing
//! the socket and unlinking it if nobody answers — which is what this used to
//! do — is a race with a window wide enough to drive ten daemons through: ten
//! `ast` commands typed at once find no socket, spawn ten daemons, and each
//! of them unlinks the socket the last one just bound. The lock is taken
//! *first*, so a daemon that reaches the unlink is provably the only one
//! alive on this home. That is also why a spawn storm is now harmless: the
//! nine losers exit before touching anything.
//!
//! # What it is not
//!
//! It is not authorisation. Every process of this user is this user, and a
//! unix socket cannot tell `ast` from anything else they run. The uid check
//! draws the line the operating system draws and no finer one.
//!
//! `flock(2)` is also only as good as the filesystem under it: an
//! `ASTERISM_HOME` on NFS may not honour it, and two daemons there would
//! reach the socket race this replaced. Local disks — which is every
//! supported configuration — do honour it.

use std::fs::{File, OpenOptions};
use std::io;
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::io::{AsRawFd, RawFd};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{bail, Context, Result};

// ---- limits ----------------------------------------------------------------
//
// Every one of these exists so that a peer cannot make the daemon spend an
// unbounded amount of something. Memory, in the frame caps; a connection slot,
// in the deadlines; the whole connection table, in the concurrency cap. They
// are constants rather than settings because a value a user can raise is a
// value an attacker can ask them to raise.

/// The largest request frame the daemon will read off the local socket.
///
/// The same ceiling the mesh reads, because it is the same protocol: a
/// [`crate::protocol::Request`] that one daemon may send another over a mesh
/// stream must not be one `ast` cannot send over the socket, or `--device`
/// would mean something different from typing the command on that device.
pub const MAX_REQUEST_FRAME: usize = crate::protocol::MESH_FRAME_LIMIT;

/// The largest reply `ast` will read.
///
/// Larger than a request on purpose, and for exactly one frame:
/// [`crate::protocol::Response::Log`] carries a console tail, and a console
/// is the one thing in this protocol whose size the user chose. It is still
/// bounded — see `console_tail`, which never reads more of the file than
/// this leaves room for.
pub const MAX_RESPONSE_FRAME: usize = 32 * 1024 * 1024;

/// Once a frame has begun arriving, how long the rest of it may take.
///
/// Waiting for a frame to *begin* is deliberately untimed: `ast ssh` holds
/// its connection open and silent for as long as the ssh it started runs,
/// and an idle timeout would cut it. What this bounds is the peer that has
/// started a line and dribbles it — the shape that otherwise pins a
/// connection slot for as long as it likes at no cost to itself.
pub const FRAME_DEADLINE: Duration = Duration::from_secs(30);

/// How long one reply may take to be accepted by the peer.
///
/// A peer that connects, asks, and then never reads fills the socket buffer
/// and leaves `write_all` waiting forever. With a connection cap in front of
/// it, that is the cheapest denial of service there is: open the limit,
/// ask the limit, read nothing.
pub const WRITE_DEADLINE: Duration = Duration::from_secs(30);

/// How many connections one daemon serves at once.
///
/// Generous, because a connection is not always a command in flight: every
/// `ast ssh` holds one open for the life of its ssh session. It is a cap on
/// how much a local peer can make the daemon hold, not a throughput setting.
pub const MAX_CONNECTIONS: usize = 256;

/// How long a connection waits for a slot before it is turned away.
///
/// Turned away rather than queued forever: a refusal a user can read beats a
/// command that never returns, and the wait is long enough that an honest
/// burst never sees it.
pub const ACCEPT_WAIT: Duration = Duration::from_secs(5);

/// How long `ast` waits for the version handshake.
///
/// The handshake is the one exchange with no work behind it — the daemon
/// answers it without touching the registry — so a daemon that will not
/// answer *this* inside twenty seconds is wedged rather than busy, and
/// saying so beats a command that hangs with nothing on the screen. Nothing
/// else `ast` sends is deadlined: `ast up` on a fresh image legitimately
/// takes minutes.
pub const HANDSHAKE_DEADLINE: Duration = Duration::from_secs(20);

/// This process's real uid.
pub fn own_uid() -> u32 {
    // Safe: `getuid` takes nothing, cannot fail, and returns a plain integer.
    unsafe { libc::getuid() }
}

// ---- private directories ---------------------------------------------------

/// What [`private_dir`] had to do, so a caller can say so.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Privacy {
    /// It was already a directory only this user can reach.
    Already,
    /// It did not exist and was created `0700`.
    Created,
    /// It existed with group or other bits, and they were taken away.
    /// Carries the mode it had, which is worth a log line: it is how a home
    /// created by an older `astd` looks, and also how one somebody widened
    /// looks.
    Tightened { was: u32 },
}

/// Make `path` a directory only this user can reach, or prove it is one.
///
/// Created `0700` from the first byte — `create_dir_all` would give it
/// `0777 & !umask`, which on a default login is `0755`, and a state directory
/// that is briefly world-readable is a state directory that was world-
/// readable.
///
/// An existing directory of ours with group or other bits is *tightened*
/// rather than refused. Every `$ASTERISM_HOME` that predates this module is
/// exactly that, and a daemon that refused to start until the user ran
/// `chmod` by hand would be a worse answer to a problem the daemon can simply
/// fix. A directory belonging to somebody else is refused: that is not an
/// upgrade, it is a different user's directory, and taking it over is not
/// this process's business.
pub fn private_dir(path: &Path) -> Result<Privacy> {
    private_dir_as(path, own_uid())
}

/// [`private_dir`], told who "us" is.
///
/// Keeping the uid constant through a recursive creation matters less in
/// production (the real uid cannot change) than it does in the tests that
/// exercise an adversarial creation collision.
fn private_dir_as(path: &Path, ours: u32) -> Result<Privacy> {
    match std::fs::symlink_metadata(path) {
        Ok(md) => audit_dir(path, &md, ours),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            // The parents get the same treatment, one at a time, so that
            // `~/.asterism/guest-keys` cannot be created under a `~/.asterism`
            // this call made world-readable on the way down.
            if let Some(parent) = path.parent() {
                if !parent.as_os_str().is_empty() && !parent.exists() {
                    private_dir_as(parent, ours)?;
                }
            }
            create_private_dir(path, ours)
        }
        Err(e) => Err(e).with_context(|| format!("looking at {}", path.display())),
    }
}

/// Perform the create half of [`private_dir_as`].
///
/// The missing-path check and `mkdir(2)` cannot be one atomic operation. Two
/// independent daemons with different homes still share the per-uid runtime
/// directory, so both can observe it missing and race here. `EEXIST` means
/// only that something won the name; it does *not* prove that the winner was
/// our private directory. Re-auditing the object is what makes a legitimate
/// concurrent creator idempotent without accepting a directory or symlink an
/// attacker placed there first.
fn create_private_dir(path: &Path, ours: u32) -> Result<Privacy> {
    match std::fs::DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => Ok(Privacy::Created),
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
            let md = std::fs::symlink_metadata(path)
                .with_context(|| format!("rechecking {} after it was created", path.display()))?;
            audit_dir(path, &md, ours)
        }
        Err(e) => Err(e).with_context(|| format!("creating {}", path.display())),
    }
}

/// The check half of [`private_dir`], for a directory that already exists.
///
/// `ours` is a parameter rather than a call to [`own_uid`] for one reason:
/// the refusal it guards — a state directory belonging to somebody else — is
/// otherwise only reachable by a test that can create a file as a second
/// user, which is to say by no test at all. Every caller passes [`own_uid`].
fn audit_dir(path: &Path, md: &std::fs::Metadata, ours: u32) -> Result<Privacy> {
    let what = path.display();
    // A symlink where a state directory should be is two different things
    // depending on who made it. One of ours is a user with a small internal
    // disk pointing `$ASTERISM_HOME` at a bigger one, which is a reasonable
    // thing to do and has to keep working. One of somebody else's is the
    // substitution this whole module exists to refuse — everything under it,
    // the registry, the device key, every staging file, would be written to a
    // directory they chose. So the link's own owner decides, and what it
    // points at is then audited on its own terms.
    if md.file_type().is_symlink() {
        let theirs = md.uid();
        if theirs != ours {
            bail!(
                "{what} is a symlink belonging to uid {theirs}, and this process is uid \
                 {ours}. Whatever it points at is a directory somebody else chose, so \
                 Asterism will not keep its state behind it. Remove it, or point \
                 ASTERISM_HOME at a directory of your own."
            );
        }
        let target = std::fs::metadata(path).with_context(|| format!("following {what}"))?;
        return audit_dir_target(path, &target, ours);
    }
    audit_dir_target(path, md, ours)
}

/// The rest of [`audit_dir`], for the directory itself rather than a link to
/// it. Split out so that following one of our own symlinks cannot recurse.
fn audit_dir_target(path: &Path, md: &std::fs::Metadata, ours: u32) -> Result<Privacy> {
    let what = path.display();
    if !md.is_dir() {
        bail!("{what} is not a directory, so Asterism cannot keep its state in it");
    }
    let theirs = md.uid();
    if theirs != ours {
        bail!(
            "{what} belongs to uid {theirs} and this process is uid {ours}. Asterism \
             will not serve another user's state directory — set ASTERISM_HOME to one \
             of your own."
        );
    }
    let mode = md.permissions().mode() & 0o7777;
    if mode & 0o077 == 0 {
        return Ok(Privacy::Already);
    }
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode & !0o077))
        .with_context(|| format!("taking the group and other bits off {what}"))?;
    Ok(Privacy::Tightened { was: mode })
}

// ---- the socket ------------------------------------------------------------

/// What is at a socket path.
///
/// Two answers and not three, because "there is something there that is not
/// astd's socket" is not a state a caller may carry on from — it is a
/// refusal, and it comes back as one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketState {
    /// Nothing is there. Whoever wants a daemon may start one.
    Absent,
    /// A socket of this user's, private, in a private directory.
    Ready,
}

/// What must be true of a socket path before anything is said to it.
///
/// The caller is `ast`, and the question it is really asking is "is the thing
/// listening here the daemon I started, or something a second user on this
/// machine put in its place?". Three answers make it the former: the path is
/// a socket and not a symlink to one, it belongs to this user, and it carries
/// no group or other bits. Behind them, and doing most of the work, is the
/// private parent directory — no other user can create a path in there to be
/// substituted for this one.
///
/// A path with nothing at it is [`SocketState::Absent`] rather than an error:
/// that is every first run, and the daemon that is about to be started is the
/// answer to it.
pub fn audit_socket(sock: &Path) -> Result<SocketState> {
    audit_socket_as(sock, own_uid())
}

/// [`audit_socket`], told who "us" is — see [`audit_dir`] for why that is a
/// parameter.
fn audit_socket_as(sock: &Path, ours: u32) -> Result<SocketState> {
    if let Some(parent) = sock.parent() {
        match std::fs::symlink_metadata(parent) {
            Ok(md) => {
                audit_dir(parent, &md, ours)?;
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(SocketState::Absent),
            Err(e) => return Err(e).with_context(|| format!("looking at {}", parent.display())),
        };
    }
    let what = sock.display();
    let md = match std::fs::symlink_metadata(sock) {
        Ok(md) => md,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(SocketState::Absent),
        Err(e) => return Err(e).with_context(|| format!("looking at {what}")),
    };
    if md.file_type().is_symlink() {
        bail!(
            "{what} is a symlink, not astd's socket. Something has been put in its \
             place; remove it and let astd bind its own."
        );
    }
    if !md.file_type().is_socket() {
        bail!(
            "{what} is not a socket. Something has been put where astd listens; \
             remove it and let astd bind its own."
        );
    }
    let theirs = md.uid();
    if theirs != ours {
        bail!(
            "{what} belongs to uid {theirs} and this is uid {ours} — that is not the \
             astd you started. Refusing to send it anything."
        );
    }
    let mode = md.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        bail!(
            "{what} is mode {mode:04o}, which lets other users on this machine talk \
             to your daemon. Refusing to use it; stop astd, remove the socket, and \
             start it again."
        );
    }
    Ok(SocketState::Ready)
}

/// The one door, bound and proved to be the only one.
///
/// Holding this value *is* the claim that this process is the daemon for its
/// home: the election lock inside it is released only when the process dies,
/// whichever way it dies.
#[derive(Debug)]
pub struct Door {
    listener: UnixListener,
    sock: PathBuf,
    /// The election. Never read; dropping it is what gives the home up.
    _lock: File,
}

impl Door {
    /// Take the home's election, tidy up after whatever died holding it, and
    /// bind.
    ///
    /// The order is the whole point. Nothing below the lock can be racing a
    /// daemon that is still alive, so the socket left behind by one that is
    /// not can be removed without asking anybody whether they are using it —
    /// which is the question the old probe-and-unlink could only ever get a
    /// stale answer to.
    pub fn open(home: &Path, sock: &Path) -> Result<Door> {
        private_dir(home)?;
        let lock = elect(home)?;
        if let Some(parent) = sock.parent() {
            private_dir(parent)?;
        }
        clear_stale(sock)?;
        let listener =
            UnixListener::bind(sock).with_context(|| format!("binding {}", sock.display()))?;
        // `0600` after the bind rather than a umask around it: umask is
        // process-wide and this daemon has a runtime under it, so narrowing
        // it here would narrow it for whatever else happened to be creating a
        // file at the same moment. The window this leaves is inside a `0700`
        // directory, where there is no path another user can traverse.
        std::fs::set_permissions(sock, std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("making {} private", sock.display()))?;
        Ok(Door {
            listener,
            sock: sock.to_path_buf(),
            _lock: lock,
        })
    }

    pub fn listener(&self) -> &UnixListener {
        &self.listener
    }

    /// Split into the parts a runtime wants, keeping the election alive.
    ///
    /// The lock has to outlive the listener — a daemon that gave its home up
    /// while still accepting is exactly the second daemon this prevents — so
    /// it comes back out with it rather than being dropped here.
    pub fn into_parts(self) -> (UnixListener, File, PathBuf) {
        (self.listener, self._lock, self.sock)
    }

    /// The socket this door is behind.
    pub fn socket(&self) -> &Path {
        &self.sock
    }
}

/// Take this home's daemon election, or say who has it.
///
/// The lock is on a file of its own rather than on the socket, because the
/// socket is the thing being contended for and may not exist yet — and
/// because a lock on a path that gets unlinked and rebound is a lock on an
/// inode nobody can find any more.
fn elect(home: &Path) -> Result<File> {
    // The same file [`crate::paths::daemon_lock_path`] names, derived from
    // the home in hand rather than from the environment, so that a caller
    // holding one home cannot take the election of another.
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

/// Whether taking a lock may wait for whoever has it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Wait {
    /// Wait. For a lock held across one short step, by everyone who wants to
    /// take that step — `ast` starting a daemon.
    Yes,
    /// Do not. For a lock held for a process's whole life, where waiting
    /// would mean waiting for that process to exit — the daemon election.
    No,
}

/// Take an exclusive `flock(2)` on `path`, creating it `0600` if it is not
/// there.
///
/// `None` means somebody else has it and [`Wait::No`] was asked for. The
/// returned file *is* the lock: it is released when the file is dropped, and
/// — this is the half that matters — by the kernel when the process dies,
/// however it dies. A lock that survived a `kill -9` would need a human to
/// clear it, which is the failure mode this replaces.
pub fn lock_file(path: &Path, wait: Wait) -> Result<Option<File>> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        // The directory is `0700`, so nobody else can have put a symlink
        // here. Refusing to follow one anyway costs a flag.
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .with_context(|| format!("opening {}", path.display()))?;
    let how = match wait {
        Wait::Yes => libc::LOCK_EX,
        Wait::No => libc::LOCK_EX | libc::LOCK_NB,
    };
    // Safe: a valid fd this call owns, and a constant operation.
    if unsafe { libc::flock(file.as_raw_fd(), how) } == 0 {
        return Ok(Some(file));
    }
    let e = io::Error::last_os_error();
    if e.raw_os_error() == Some(libc::EWOULDBLOCK) {
        return Ok(None);
    }
    Err(e).with_context(|| format!("locking {}", path.display()))
}

/// Remove whatever a dead daemon left at the socket path.
///
/// Only ever reached with the election in hand, which is what makes it safe:
/// nothing alive is listening there. `unlink(2)` removes a symlink itself and
/// never what it points at, so a substituted link is cleared rather than
/// followed.
fn clear_stale(sock: &Path) -> Result<()> {
    let md = match std::fs::symlink_metadata(sock) {
        Ok(md) => md,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e).with_context(|| format!("looking at {}", sock.display())),
    };
    if md.is_dir() {
        bail!(
            "{} is a directory, and astd needs to bind a socket there",
            sock.display()
        );
    }
    std::fs::remove_file(sock)
        .with_context(|| format!("removing the socket left at {}", sock.display()))
}

// ---- who is on the other end -----------------------------------------------

/// The uid the kernel says is on the other end of a connected unix socket.
///
/// Asked of the kernel and never of the peer: this is the one fact in the
/// exchange that a process on the other end cannot choose.
pub fn peer_uid(fd: RawFd) -> io::Result<u32> {
    platform::peer_uid(fd)
}

/// Refuse a peer that is not this user.
///
/// The message is written to be read by whoever tripped it, because the
/// honest case exists: two logins on one machine, one `astd`, and a
/// `sudo ast` that is a different user than the daemon it found.
pub fn same_user(fd: RawFd) -> Result<u32> {
    let ours = own_uid();
    let theirs = match peer_uid(fd) {
        Ok(uid) => uid,
        // A host that will not say is a host where this check cannot be
        // made, and pretending otherwise would be worse than saying so. The
        // socket is still `0600` inside a `0700` directory, which is the
        // guarantee that does not depend on the platform.
        Err(e) if e.kind() == io::ErrorKind::Unsupported => return Ok(ours),
        Err(e) => return Err(e).context("asking the kernel who is on this connection"),
    };
    if theirs != ours {
        bail!(
            "refusing a connection from uid {theirs}: this astd serves uid {ours} and \
             nobody else. Run ast as that user, or start your own astd with \
             ASTERISM_HOME set to a directory you own."
        );
    }
    Ok(theirs)
}

#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly"
))]
mod platform {
    use std::io;
    use std::os::unix::io::RawFd;

    /// `getpeereid(2)`: the BSD and Apple spelling. Effective uid at the time
    /// the peer connected, which is the identity that matters — a process
    /// that drops privileges after connecting does not get them back.
    pub(super) fn peer_uid(fd: RawFd) -> io::Result<u32> {
        let mut uid: libc::uid_t = 0;
        let mut gid: libc::gid_t = 0;
        // Safe: a connected socket fd owned by the caller, and two out
        // parameters this frame owns.
        if unsafe { libc::getpeereid(fd, &mut uid, &mut gid) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(uid)
    }
}

#[cfg(target_os = "linux")]
mod platform {
    use std::io;
    use std::os::unix::io::RawFd;

    /// `SO_PEERCRED`: the Linux spelling of the same question.
    pub(super) fn peer_uid(fd: RawFd) -> io::Result<u32> {
        let mut cred = libc::ucred {
            pid: 0,
            uid: 0,
            gid: 0,
        };
        let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        // Safe: a connected socket fd owned by the caller, and a buffer whose
        // size is what `len` says it is.
        let rc = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                (&mut cred as *mut libc::ucred).cast(),
                &mut len,
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(cred.uid)
    }
}

#[cfg(not(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly",
    target_os = "linux"
)))]
mod platform {
    use std::io;
    use std::os::unix::io::RawFd;

    /// Somewhere that spells it a third way. Saying so is the honest answer;
    /// see [`super::same_user`], which treats it as "not available here"
    /// rather than as a pass or a failure.
    pub(super) fn peer_uid(_fd: RawFd) -> io::Result<u32> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "this host does not report the uid on a unix socket",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixStream;

    fn mode_of(path: &Path) -> u32 {
        std::fs::symlink_metadata(path)
            .unwrap()
            .permissions()
            .mode()
            & 0o7777
    }

    /// A uid that is not this process's, for the refusals that would
    /// otherwise need a second user on the machine to reach.
    fn somebody_else() -> u32 {
        own_uid().wrapping_add(1)
    }

    /// The whole point of the directory half: it is `0700` from the moment it
    /// exists, and not `0755` until something gets round to fixing it.
    #[test]
    fn a_state_directory_is_created_private() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        assert_eq!(private_dir(&home).unwrap(), Privacy::Created);
        assert_eq!(mode_of(&home), 0o700, "created world-readable");
    }

    /// Every parent it had to make is private too. A `guest-keys` at `0700`
    /// under an `.asterism` at `0755` protects nothing: the names in it are
    /// listable and the paths in it are predictable.
    #[test]
    fn the_parents_it_creates_are_private_too() {
        let tmp = tempfile::tempdir().unwrap();
        let deep = tmp.path().join("home").join("guest-keys");
        private_dir(&deep).unwrap();
        assert_eq!(mode_of(&deep), 0o700);
        assert_eq!(
            mode_of(&tmp.path().join("home")),
            0o700,
            "the parent was left open"
        );
    }

    /// Different `ASTERISM_HOME`s still share one short runtime directory.
    /// Drive every racer directly through the missing-path create boundary,
    /// repeatedly: exactly one `mkdir` wins and every `EEXIST` loser must
    /// re-audit that winner as the same private directory rather than fail.
    #[test]
    fn parallel_private_directory_creation_is_idempotent_and_private() {
        const ROUNDS: usize = 64;
        const RACERS: usize = 8;

        let tmp = tempfile::tempdir().unwrap();
        for round in 0..ROUNDS {
            let path = std::sync::Arc::new(tmp.path().join(format!("runtime-{round}")));
            let start = std::sync::Arc::new(std::sync::Barrier::new(RACERS + 1));
            let racers = (0..RACERS)
                .map(|_| {
                    let path = std::sync::Arc::clone(&path);
                    let start = std::sync::Arc::clone(&start);
                    std::thread::spawn(move || {
                        start.wait();
                        create_private_dir(&path, own_uid())
                    })
                })
                .collect::<Vec<_>>();

            start.wait();
            let outcomes = racers
                .into_iter()
                .map(|racer| racer.join().expect("private-dir racer panicked").unwrap())
                .collect::<Vec<_>>();

            assert_eq!(
                outcomes
                    .iter()
                    .filter(|outcome| **outcome == Privacy::Created)
                    .count(),
                1,
                "round {round} did not have exactly one creator: {outcomes:?}"
            );
            assert!(
                outcomes
                    .iter()
                    .all(|outcome| matches!(outcome, Privacy::Created | Privacy::Already)),
                "round {round} changed the already-private winner: {outcomes:?}"
            );
            assert_eq!(mode_of(&path), 0o700, "round {round} left the winner open");
        }
    }

    /// An `EEXIST` collision is not success until the object that won the
    /// name passes the same ownership and symlink checks as any other
    /// pre-existing directory.
    #[test]
    fn a_private_directory_creation_collision_is_reaudited() {
        let tmp = tempfile::tempdir().unwrap();

        let foreign = tmp.path().join("foreign");
        std::fs::create_dir(&foreign).unwrap();
        let refusal = format!(
            "{:#}",
            create_private_dir(&foreign, somebody_else()).unwrap_err()
        );
        assert!(refusal.contains("belongs to uid"), "{refusal}");

        let target = tmp.path().join("target");
        std::fs::create_dir(&target).unwrap();
        let link = tmp.path().join("runtime-link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let refusal = format!(
            "{:#}",
            create_private_dir(&link, somebody_else()).unwrap_err()
        );
        assert!(refusal.contains("symlink belonging to uid"), "{refusal}");
    }

    /// Every `$ASTERISM_HOME` that predates this module is a shared
    /// directory, so refusing to start on one would be refusing to start for
    /// every existing user. It is fixed, and the fact is reported so the
    /// daemon can say it out loud.
    #[test]
    fn a_state_directory_an_older_daemon_left_open_is_tightened() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        std::fs::create_dir(&home).unwrap();
        std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o755)).unwrap();

        assert_eq!(
            private_dir(&home).unwrap(),
            Privacy::Tightened { was: 0o755 }
        );
        assert_eq!(mode_of(&home), 0o700);
        // And it stays fixed, silently, on every start after that.
        assert_eq!(private_dir(&home).unwrap(), Privacy::Already);
    }

    /// A directory somebody else owns is not an upgrade to fix. Taking it
    /// over — `chmod`-ing another user's directory and then keeping this
    /// device's secrets in it — is not this process's business.
    #[test]
    fn a_state_directory_belonging_to_another_user_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        std::fs::create_dir(&home).unwrap();
        let md = std::fs::symlink_metadata(&home).unwrap();

        let refusal = format!("{:#}", audit_dir(&home, &md, somebody_else()).unwrap_err());
        assert!(refusal.contains("belongs to uid"), "{refusal}");
        assert!(
            refusal.contains("ASTERISM_HOME"),
            "the refusal says what to do: {refusal}"
        );
    }

    /// A symlink somebody else made where the state directory should be
    /// points somewhere they chose, and everything under it — the registry,
    /// the device key, every staging file — would be written there.
    #[test]
    fn a_symlink_somebody_else_made_where_the_state_directory_should_be_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let elsewhere = tmp.path().join("elsewhere");
        std::fs::create_dir(&elsewhere).unwrap();
        let home = tmp.path().join("home");
        std::os::unix::fs::symlink(&elsewhere, &home).unwrap();
        let md = std::fs::symlink_metadata(&home).unwrap();

        let refusal = format!("{:#}", audit_dir(&home, &md, somebody_else()).unwrap_err());
        assert!(refusal.contains("symlink belonging to uid"), "{refusal}");
    }

    /// A symlink *we* made is a user with a small internal disk pointing
    /// `$ASTERISM_HOME` at a bigger one. It has to keep working, and what it
    /// points at is then held to the same rules as any other home.
    #[test]
    fn a_symlink_of_our_own_is_followed_and_its_target_is_made_private() {
        let tmp = tempfile::tempdir().unwrap();
        let elsewhere = tmp.path().join("elsewhere");
        std::fs::create_dir(&elsewhere).unwrap();
        std::fs::set_permissions(&elsewhere, std::fs::Permissions::from_mode(0o755)).unwrap();
        let home = tmp.path().join("home");
        std::os::unix::fs::symlink(&elsewhere, &home).unwrap();

        assert_eq!(
            private_dir(&home).unwrap(),
            Privacy::Tightened { was: 0o755 }
        );
        assert_eq!(
            mode_of(&elsewhere),
            0o700,
            "the directory behind the link is still open"
        );
    }

    /// The first run, and the state a stale-socket recovery leaves behind.
    #[test]
    fn nothing_at_the_socket_path_is_absent_rather_than_an_error() {
        let tmp = tempfile::tempdir().unwrap();
        assert_eq!(
            audit_socket(&tmp.path().join("astd.sock")).unwrap(),
            SocketState::Absent
        );
        assert_eq!(
            audit_socket(&tmp.path().join("no-such-home").join("astd.sock")).unwrap(),
            SocketState::Absent,
            "a home that does not exist yet is not a substituted socket"
        );
    }

    /// What the door is for, end to end: bound, `0600`, in a `0700`
    /// directory, and audited as ready by the same rules `ast` applies.
    #[test]
    fn the_door_binds_a_socket_only_this_user_can_reach() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let sock = home.join("astd.sock");
        let door = Door::open(&home, &sock).unwrap();

        assert_eq!(
            mode_of(&sock),
            0o600,
            "the socket is readable by other users"
        );
        assert_eq!(mode_of(&home), 0o700, "the directory it is in is listable");
        assert_eq!(audit_socket(&sock).unwrap(), SocketState::Ready);
        UnixStream::connect(&sock).expect("it is a socket that accepts");
        drop(door);
    }

    /// The election, which is the thing that makes "one daemon per home" a
    /// fact rather than a race: the second one is turned away while the
    /// first is alive, and told which home it lost.
    #[test]
    fn only_one_daemon_holds_a_home() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let sock = home.join("astd.sock");
        let first = Door::open(&home, &sock).unwrap();

        let refusal = format!("{:#}", Door::open(&home, &sock).unwrap_err());
        assert!(refusal.contains("another astd already holds"), "{refusal}");
        assert!(refusal.contains(&home.display().to_string()), "{refusal}");

        // And the first one is still the one listening: a loser must not
        // have unlinked the socket on its way out, which is exactly what
        // probe-then-unlink used to do.
        assert_eq!(audit_socket(&sock).unwrap(), SocketState::Ready);
        UnixStream::connect(&sock).expect("the winner is still accepting");
        drop(first);
    }

    /// A daemon that died — cleanly or not — leaves a socket file at a path
    /// that nothing is listening on. The next one has to take it over, and
    /// with the election in hand it can do that without asking anybody
    /// whether they are using it.
    #[test]
    fn a_socket_left_by_a_dead_daemon_is_taken_over() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let sock = home.join("astd.sock");

        let dead = Door::open(&home, &sock).unwrap();
        drop(dead);
        assert!(
            sock.exists(),
            "this test is about the file a crash leaves behind"
        );
        assert!(
            UnixStream::connect(&sock).is_err(),
            "and about nobody being behind it"
        );

        let door = Door::open(&home, &sock).unwrap();
        UnixStream::connect(&sock).expect("the replacement is accepting");
        assert_eq!(mode_of(&sock), 0o600);
        drop(door);
    }

    /// A symlink at the socket path is cleared rather than followed.
    /// `unlink(2)` removes the link and never its target, so the file the
    /// attacker aimed at is still there afterwards — which is the half of
    /// this that a `remove_file` on the resolved path would get wrong.
    #[test]
    fn a_symlink_where_the_socket_should_be_is_cleared_and_not_followed() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        private_dir(&home).unwrap();
        let bait = tmp.path().join("something-precious");
        std::fs::write(&bait, b"not yours to delete").unwrap();
        let sock = home.join("astd.sock");
        std::os::unix::fs::symlink(&bait, &sock).unwrap();

        let door = Door::open(&home, &sock).unwrap();
        assert!(bait.exists(), "the link's target was deleted");
        assert_eq!(std::fs::read(&bait).unwrap(), b"not yours to delete");
        assert_eq!(audit_socket(&sock).unwrap(), SocketState::Ready);
        drop(door);
    }

    /// The client's side of substitution. Each of these is something that is
    /// not the daemon we started, and `ast` is about to send it this device's
    /// secrets.
    #[test]
    fn ast_refuses_to_talk_to_anything_that_is_not_our_socket() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        private_dir(&home).unwrap();

        let plain = home.join("plain.sock");
        std::fs::write(&plain, b"").unwrap();
        let refusal = format!("{:#}", audit_socket(&plain).unwrap_err());
        assert!(refusal.contains("not a socket"), "{refusal}");

        let real = home.join("real.sock");
        let _listener = UnixListener::bind(&real).unwrap();
        let link = home.join("link.sock");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let refusal = format!("{:#}", audit_socket(&link).unwrap_err());
        assert!(refusal.contains("symlink"), "{refusal}");

        let refusal = format!("{:#}", audit_socket_as(&real, somebody_else()).unwrap_err());
        assert!(refusal.contains("belongs to uid"), "{refusal}");

        std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o666)).unwrap();
        let refusal = format!("{:#}", audit_socket(&real).unwrap_err());
        assert!(refusal.contains("other users"), "{refusal}");
    }

    /// A socket in a directory other users can write to is a socket that
    /// could be replaced tomorrow, so the directory is tightened on the way
    /// past — and anything already substituted in there fails the owner
    /// check behind it.
    #[test]
    fn auditing_a_socket_tightens_the_directory_it_is_in() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        std::fs::create_dir(&home).unwrap();
        std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o777)).unwrap();
        let sock = home.join("astd.sock");
        let _listener = UnixListener::bind(&sock).unwrap();
        std::fs::set_permissions(&sock, std::fs::Permissions::from_mode(0o600)).unwrap();

        assert_eq!(audit_socket(&sock).unwrap(), SocketState::Ready);
        assert_eq!(
            mode_of(&home),
            0o700,
            "a world-writable home was left as it was"
        );
    }

    /// A lock is released by the kernel when its holder dies, however it
    /// dies. Modelled here by dropping it, which is the same thing to
    /// `flock(2)`: a lock that outlived a `kill -9` would need a human to
    /// clear it before the daemon could start again.
    #[test]
    fn the_election_is_given_up_when_its_holder_goes() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        private_dir(&home).unwrap();
        let lock = home.join("astd.lock");

        let held = lock_file(&lock, Wait::No).unwrap().expect("nobody had it");
        assert!(
            lock_file(&lock, Wait::No).unwrap().is_none(),
            "it was handed out twice"
        );
        drop(held);
        assert!(
            lock_file(&lock, Wait::No).unwrap().is_some(),
            "it was never given back"
        );
    }

    /// One protocol, one ceiling. A request a daemon may send another over
    /// the mesh must not be one `ast` cannot send over the socket, or
    /// `--device dev` would mean something different from typing the command
    /// on `dev`.
    #[test]
    fn the_local_frame_limit_is_the_mesh_frame_limit() {
        assert_eq!(MAX_REQUEST_FRAME, crate::protocol::MESH_FRAME_LIMIT);
        const {
            assert!(
                MAX_RESPONSE_FRAME > MAX_REQUEST_FRAME,
                "a console tail has to fit"
            )
        };
    }

    /// The peer check answers with the truth about a connection this process
    /// made to itself, which is the only peer a test has. What it must not
    /// do is fail open on a platform that will not say — see `same_user`.
    #[test]
    fn a_connection_from_this_user_is_this_user() {
        let (a, _b) = UnixStream::pair().unwrap();
        match peer_uid(a.as_raw_fd()) {
            Ok(uid) => assert_eq!(uid, own_uid()),
            Err(e) => assert_eq!(e.kind(), io::ErrorKind::Unsupported, "{e}"),
        }
        assert_eq!(same_user(a.as_raw_fd()).unwrap(), own_uid());
    }
}
