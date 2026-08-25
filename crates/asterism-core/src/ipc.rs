//! Platform-specific local control-plane transport.
//!
//! Unix retains the filesystem socket, ownership, and daemon-election policy;
//! Windows uses named pipes with the equivalent one-daemon and peer-admission
//! contract. Callers consume one shared surface through this module.

#[cfg(unix)]
#[path = "ipc_unix.rs"]
mod ipc_unix;

#[cfg(unix)]
pub use ipc_unix::*;

#[cfg(windows)]
#[path = "ipc_windows.rs"]
mod ipc_windows;

#[cfg(windows)]
pub use ipc_windows::*;
