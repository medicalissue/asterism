//! What a cpu-part swap carries, described before any of it moves.
//!
//! These types are payloads of the `Move*` frames rather than frames
//! themselves, and they are here rather than beside the enum for the reason
//! this module is a directory at all: a move is one area of the daemon, so
//! its payloads and its wire tests are one file that one branch edits.
//!
//! The manifest doubles as an estimate and as a completeness check. The
//! source computes it, the target checks what arrived against it, and both
//! halves of "did the whole instance get here" reduce to arithmetic on the
//! same numbers.

use serde::{Deserialize, Serialize};

use crate::instance::Instance;

/// Durable target-side state of an authority transfer.
///
/// `Committing` is intentionally not abortable: the target may already have
/// published its directory or row, so recovery completes the transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MoveAuthorityPhase {
    Intent,
    Prepared,
    Committing,
    Committed,
    Aborted,
}

/// A base image, as one device describes it to another.
///
/// Base images are content-addressed and cached per device: a device that
/// lacks one pulls it from an orbit peer that has it before it would ever
/// reach for the internet (`docs/MODEL.md`, "Where bytes live"). `digest` is
/// what makes that safe — the reference names the image, the digest says
/// which bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BaseImage {
    /// The reference recorded on the instance: `debian:13`, a url, a path.
    pub reference: String,
    /// Length of the base image file.
    pub len: u64,
    /// What it actually occupies — a raw base image converted from a cloud
    /// image is mostly hole, so this is what a peer fetch really costs and
    /// what its progress is measured against.
    #[serde(default)]
    pub allocated: u64,
    /// Content address of its bytes.
    pub digest: String,
    /// What the source's own provenance record says these bytes were derived
    /// from — the publisher digest of the cloud image a raw base was
    /// converted out of, the manifest and layers an OCI rootfs was built
    /// from.
    ///
    /// It travels because the target has to be able to write a provenance
    /// record of its own, and a record that dropped this would take a
    /// pinned reference (`debian:13`, whose catalog entry names a published
    /// sha256) out of service on the target: the boot gate asks not only
    /// "are these the bytes that were adopted" but "are they the bytes this
    /// reference asked for", and the second question is answered from here.
    /// Carrying it is not a new claim — the bytes are proved identical to
    /// the source's by `digest`, so the source's record is a record of these
    /// bytes too.
    ///
    /// Empty from a peer running a build older than this field, and empty
    /// for a base that has no record on the source either.
    #[serde(default)]
    pub derived_from: Vec<String>,
}

impl BaseImage {
    /// A reference the source cannot hand over: it does not resolve there, or
    /// the bytes are not on that device either. Not an error — an instance's
    /// disk is a complete file and boots without its base — so this travels
    /// as a fact the target's probe reports rather than as a refusal.
    pub fn absent(reference: String) -> Self {
        BaseImage {
            reference,
            len: 0,
            allocated: 0,
            digest: String::new(),
            derived_from: Vec::new(),
        }
    }

    /// What a peer fetch of it would really cost.
    pub fn cost(&self) -> u64 {
        if self.allocated == 0 {
            self.len
        } else {
            self.allocated
        }
    }
}

/// One file a move will carry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoveFile {
    /// Path relative to the instance directory, `/`-separated.
    pub path: String,
    /// What the file claims to be — 20 GiB, for a root disk.
    pub len: u64,
    /// What it actually holds, and therefore what will cross the wire.
    pub allocated: u64,
    /// Permission bits. `seed.iso` and a disk are not the same secret.
    pub mode: u32,
}

/// Everything a cpu-part swap will carry, computed on the source device
/// before any of it moves.
///
/// This doubles as the estimate the roadmap asks for and as the completeness
/// check the commit turns on: the target counts what arrived against
/// `allocated` per file and refuses to adopt a directory that does not add
/// up.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MoveManifest {
    /// The instance record itself, which the target adopts on commit.
    pub instance: Instance,
    /// The architecture the source is running. A guest built for one
    /// instruction set does not boot on another, and no amount of copying
    /// changes that, so this is checked before a byte moves.
    pub arch: String,
    /// The base image the disk was cloned from, which the target must have.
    pub base: BaseImage,
    /// The files, in the order they will be sent.
    pub files: Vec<MoveFile>,
    /// Guest paths of directory volumes that are same-device shares on the source.
    /// They do not survive the move as working parts; they survive as rows
    /// with a flag on them.
    #[serde(default)]
    pub local_volumes: Vec<String>,
}

impl MoveManifest {
    /// Total bytes the transfer will really carry.
    pub fn allocated(&self) -> u64 {
        self.files.iter().map(|f| f.allocated).sum()
    }

    /// Total bytes the files claim between them.
    pub fn virtual_size(&self) -> u64 {
        self.files.iter().map(|f| f.len).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hv::Machine;
    use crate::instance::Shape;
    use crate::protocol::Request;

    /// Every step of a move names one device and is aimed at it, so none of
    /// them may report a subject: half go to a device that does not hold the
    /// row, and resolving them by instance name would send them to the wrong
    /// end of the transfer.
    #[test]
    fn the_move_frames_are_aimed_at_devices_not_resolved_by_name() {
        let manifest = Box::new(MoveManifest {
            instance: Instance::new(
                "dev",
                "laptop",
                "debian:13",
                Shape::default(),
                Machine {
                    backend: "qemu".into(),
                    machine_type: "virt".into(),
                    cpu: "host".into(),
                    hv_version: "test".into(),
                },
            ),
            arch: "aarch64".into(),
            base: BaseImage::absent("debian:13".to_owned()),
            files: vec![
                MoveFile {
                    path: "disk.raw".into(),
                    len: 20 << 30,
                    allocated: 1 << 30,
                    mode: 0o600,
                },
                MoveFile {
                    path: "seed.iso".into(),
                    len: 366 << 10,
                    allocated: 366 << 10,
                    mode: 0o644,
                },
            ],
            local_volumes: vec!["/mnt/ast/tank".into()],
        });

        assert_eq!(manifest.allocated(), (1 << 30) + (366 << 10));
        assert_eq!(manifest.virtual_size(), (20 << 30) + (366 << 10));
        assert!(
            manifest.allocated() * 4 < manifest.virtual_size(),
            "a root disk is mostly hole, and that is the whole economics of a move"
        );

        for req in [
            Request::SetCpu {
                name: "dev".into(),
                device: "desktop".into(),
                down: false,
            },
            Request::MoveOffer { name: "dev".into() },
            Request::MoveProbe {
                manifest: manifest.clone(),
            },
            Request::MovePrepare {
                name: "dev".into(),
                to_device: "desktop".into(),
                epoch: 1,
                live: false,
            },
            Request::MoveCommitTarget {
                manifest: manifest.clone(),
                epoch: 1,
            },
            Request::MoveCommitSource {
                name: "dev".into(),
                epoch: 1,
            },
            Request::MoveAbortSource {
                name: "dev".into(),
                epoch: 1,
            },
            Request::MoveAbortTarget {
                instance_id: "instance-id".into(),
                name: "dev".into(),
                epoch: 1,
            },
        ] {
            assert_eq!(
                req.subject(),
                None,
                "{req:?} names a device, not an instance"
            );
            assert!(!req.survives_a_move(), "{req:?} is not a read");
        }

        // `--down` is defaulted, so a CLI that predates it still parses.
        let bare: Request =
            serde_json::from_str(r#"{"cmd":"set_cpu","name":"dev","device":"desktop"}"#).unwrap();
        assert!(matches!(bare, Request::SetCpu { down: false, .. }));

        // A fenced instance answers what reads and nothing that writes.
        assert!(Request::Status { name: "dev".into() }.survives_a_move());
        assert!(Request::Logs {
            name: "dev".into(),
            lines: 10
        }
        .survives_a_move());
        assert!(!Request::Up {
            name: "dev".into(),
            restart: None
        }
        .survives_a_move());
        assert!(!Request::Remove { name: "dev".into() }.survives_a_move());
        assert!(!Request::Snapshot {
            name: "dev".into(),
            tag: "t".into()
        }
        .survives_a_move());
        assert!(!Request::Rename {
            name: "dev".into(),
            new_name: "e".into()
        }
        .survives_a_move());
    }

    #[test]
    fn live_preparation_is_versioned_without_changing_offline_move_frames() {
        let old: Request = serde_json::from_str(
            r#"{"cmd":"move_prepare","name":"dev","to_device":"desktop","epoch":1}"#,
        )
        .unwrap();
        assert_eq!(old.since(), crate::compat::FIRST_PROTOCOL);
        let Request::MovePrepare { live, .. } = old else {
            panic!("the old frame changed shape")
        };
        assert!(!live, "an old peer always asked for the offline fence");

        let old_abort: Request =
            serde_json::from_str(r#"{"cmd":"move_abort_target","name":"dev","epoch":1}"#).unwrap();
        let Request::MoveAbortTarget { instance_id, .. } = old_abort else {
            panic!("the old abort frame changed shape")
        };
        assert!(instance_id.is_empty());

        let live = Request::MovePrepare {
            name: "dev".into(),
            to_device: "desktop".into(),
            epoch: 1,
            live: true,
        };
        assert_eq!(live.since(), 6);
        assert_eq!(live.versioned_name(), Some("live migration"));
    }
}
