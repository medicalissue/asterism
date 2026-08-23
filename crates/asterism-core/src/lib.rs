//! Core types for Asterism.
//!
//! The orbit is a pool of parts; an instance is a computer assembled from
//! them. Compute is one placement unit from one orbit device; GPU, storage,
//! network, and exit points may attach independently. That sentence is the
//! shape of this crate: [`orbit`] is the set of
//! devices supplying the pool, [`instance`] is what gets assembled and which
//! device each of its parts comes from, [`registry`] is the one flat
//! orbit-wide namespace those instances live in (stored as a shard per
//! device), [`durable`] is how any of that survives a crash, [`hv`] is the
//! hypervisor boundary, [`volume`] is the block
//! storage a device contributes to the pool, [`secret`] and [`rewrite`] are
//! the secrets data plane's model and its one substitution rule, and
//! [`protocol`] is the CLI <-> daemon wire, [`ipc`] is the door that
//! wire arrives through, and [`compat`] is which version of it two vintages
//! settle on. [`remote_gpu`] is the transport-independent CUDA-semantic ABI
//! behind a projected guest GPU device. [`verify`] is the gate every boot
//! input passes through on its way into the store and out of it again, and
//! [`profile`] is what a guest is asked to become once it has booted.

pub mod backup;
pub mod compat;
pub mod cow;
pub mod device_shell;
pub mod doctor;
pub mod durable;
pub mod guest;
pub mod hosted_auth;
pub mod hv;
pub mod hyperv;
pub mod image;
pub mod instance;
pub mod ipc;
pub mod oci;
pub mod orbit;
pub mod paths;
pub mod power;
pub mod proc;
pub mod profile;
pub mod protocol;
pub mod registry;
pub mod remote_gpu;
pub mod rewrite;
pub mod secret;
pub mod seed;
pub mod service;
pub mod snapshot;
pub mod tools;
pub mod verify;
pub mod volume;
pub mod windows_host;

/// Version of the `astd`/`ast` pair this binary was built from.
///
/// Reported and printed; never compared. What decides whether two vintages
/// can talk is [`compat::PROTOCOL_VERSION`], which moves when the wire moves
/// and not when a patch release does — comparing these strings is what used
/// to make every upgrade a forced daemon replacement.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The exact build this binary came from: `<version>+<source>`, where source
/// is the commit it was compiled from (suffixed `.dirty` when the worktree
/// had uncommitted changes), an id the build was handed, or `unknown`.
///
/// A version number cannot tell two builds of the same tag apart, and every
/// build between two tags reports the same one — so "which binary is this"
/// is a question [`VERSION`] cannot answer and this one can. It is stamped at
/// compile time by this crate's build script and nothing at runtime can
/// change it, which is the property that makes it worth asserting on: `ast`,
/// `astd` and the desktop app all link this crate, so when they report
/// different ids they really are different builds.
pub const BUILD_ID: &str = env!("ASTERISM_BUILD_ID");

#[cfg(test)]
mod build_id_tests {
    use super::*;

    #[test]
    fn the_build_id_is_stamped_and_starts_with_the_version() {
        // The stamp is compile-time, so this is really a test of the build
        // script: a missing or malformed one has to fail here rather than in
        // a bug report six weeks later.
        assert!(
            BUILD_ID.starts_with(&format!("{VERSION}+")),
            "build id {BUILD_ID} does not carry version {VERSION}"
        );
        let source = &BUILD_ID[VERSION.len() + 1..];
        assert!(!source.is_empty(), "build id {BUILD_ID} names no source");
        assert!(
            source
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | '+')),
            "build id {BUILD_ID} is not one word"
        );
    }
}
