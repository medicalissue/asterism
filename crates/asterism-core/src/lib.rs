//! Core types for Asterism.
//!
//! The orbit is a pool of parts; an instance is a computer assembled from
//! them. That sentence is the shape of this crate: [`orbit`] is the set of
//! devices supplying the pool, [`instance`] is what gets assembled and which
//! device each of its parts comes from, [`registry`] is the one flat
//! orbit-wide namespace those instances live in (stored as a shard per
//! device), [`durable`] is how any of that survives a crash, [`hv`] is the
//! hypervisor boundary, [`volume`] is the block
//! storage a device contributes to the pool, [`secret`] and [`rewrite`] are
//! the secrets data plane's model and its one substitution rule, and
//! [`protocol`] is the CLI <-> daemon wire.

pub mod cow;
pub mod durable;
pub mod hv;
pub mod image;
pub mod instance;
pub mod oci;
pub mod orbit;
pub mod paths;
pub mod power;
pub mod protocol;
pub mod registry;
pub mod rewrite;
pub mod seed;
pub mod secret;
pub mod service;
pub mod snapshot;
pub mod tools;
pub mod volume;

/// Version of the `astd`/`ast` pair this binary was built from. The CLI and
/// the daemon must agree on it: the wire protocol is a serde enum, so a
/// daemon left running across an upgrade answers newer requests with an
/// "unknown variant" parse error rather than anything a user could act on.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
