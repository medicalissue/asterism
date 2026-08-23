//! Windows boundary for the Unix-NBD volume transport.
//!
//! Windows' Hyper-V backend advertises `nbd_disks: false`, so placement and
//! attach validation reject block-volume consumers before this module is
//! reached.  A Windows device may still receive volume control frames from a
//! newer peer, however, and the whole daemon must remain buildable there.
//! Keep the unsupported transport behind the same fail-closed interface as
//! the Unix implementation instead of compiling Unix socket APIs on Windows.

use std::path::Path;

use anyhow::{bail, Result};

use asterism_core::proc::ProcId;

/// There is no prepared Unix listener on Windows.
#[derive(Debug)]
pub(crate) struct Prepared;

/// Refuse before recording an export launch fence.
pub(crate) fn prepare(
    _image: &Path,
    _socket: &Path,
    _export: &str,
    _size: u64,
) -> Result<Prepared> {
    bail!(
        "this Windows build cannot export an orbit block volume because its backend has no Unix NBD transport"
    )
}

/// A `Prepared` value cannot be constructed successfully on Windows.
pub(crate) fn start(_prepared: Prepared) -> Result<ProcId> {
    bail!("a Windows NBD export cannot be started")
}

/// No Windows native exporter can belong to this process.
pub(crate) fn stop(_socket: &Path, _expected: Option<&ProcId>) -> Result<bool> {
    Ok(false)
}

/// No Windows native exporter can be alive.
pub(crate) fn alive(_process: Option<&ProcId>, _socket: &Path) -> bool {
    false
}
