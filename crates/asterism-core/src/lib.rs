//! Core types for Asterism.
//!
//! The orbit is a pool of parts; an instance is a computer assembled from
//! them. Compute is the one orbit device an instance runs on — its CPU,
//! physical RAM, and GPU. Data parts — block volumes and secrets — attach
//! across devices. That sentence is the
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
//! behind a projected guest GPU device. [`remote_gpu_guest`] is the
//! guest-local `/dev/nvidia0` CUSE + generated libcuda projection.
//! [`remote_gpu_path`] carries CUDA-semantic frames over the authenticated
//! mesh. [`remote_gpu_nvidia`] is the fail-closed NVIDIA inventory/matrix
//! and two-device harness around that ABI. [`verify`] is the gate every boot
//! input passes through on its way
//! into the store and out of it again, and [`profile`] is what a guest is
//! asked to become once it has booted. [`fix`] is how an error carries the
//! command that repairs it, so the CLI and `ast doctor` can say the same
//! sentence about the same missing thing.

pub mod backup;
pub mod compat;
pub mod cow;
pub mod device_shell;
pub mod doctor;
pub mod durable;
pub mod egress_door;
pub mod fix;
pub mod guest;
pub mod hosted_auth;
pub mod hv;
pub mod hyperv;
pub mod image;
pub mod instance;
pub mod ipc;
pub mod layout;
pub mod ledger;
pub mod oci;
pub mod orbit;
pub mod paths;
pub mod power;
pub mod pricing;
pub mod proc;
pub mod profile;
pub mod protocol;
mod qcow2;
pub mod registry;
pub mod remote_gpu;
pub mod remote_gpu_cuda;
#[cfg(unix)]
pub mod remote_gpu_cuse;
pub mod remote_gpu_guest;
pub mod remote_gpu_nvidia;
pub mod remote_gpu_path;
pub mod rewrite;
pub mod secret;
pub mod seed;
pub mod service;
pub mod snapshot;
pub mod tools;
pub mod usage;
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
