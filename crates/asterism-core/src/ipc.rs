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

#[cfg(unix)]
mod ipc_unix;

#[cfg(unix)]
pub use ipc_unix::*;

#[cfg(windows)]
mod ipc_windows;

#[cfg(windows)]
pub use ipc_windows::*;
