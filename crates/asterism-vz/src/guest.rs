//! Re-export of the backend-neutral guest-agent protocol.
//!
//! The types and cloud-init payload live in `asterism_core::guest` so the
//! Hyper-V backend can mint a seed without importing Virtualization.framework
//! Unix APIs.

pub use asterism_core::guest::*;
