//! The opt-in shell one device may offer to authenticated orbit peers.
//!
//! Policy lives with the daemon on every host. The PTY/process implementation
//! is Unix-only; Windows keeps the same types so orbit routing still compiles
//! and refuses a shell at the policy seam rather than at a missing module.

#[cfg(unix)]
#[path = "device_shell_unix.rs"]
mod device_shell_unix;

#[cfg(unix)]
pub(crate) use device_shell_unix::*;

#[cfg(windows)]
#[path = "device_shell_windows.rs"]
mod device_shell_windows;

#[cfg(windows)]
pub(crate) use device_shell_windows::*;
