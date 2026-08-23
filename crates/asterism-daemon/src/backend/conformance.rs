//! One executable contract for every backend registered in this build.
//!
//! These are deliberately not backend unit tests.  They enter through
//! [`Hypervisor`], enumerate [`super::backends`], and run the same assertions
//! for every entry.  Adding a backend to the registry therefore adds it to
//! this suite; the unknown id also has to be given a control-channel profile
//! here before the suite can pass.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::Result;
use asterism_core::hv::{
    BootReq, Capability, Caps, ControlChannel, DiskFormat, DiskSpec, GuestEndpoint, Handle,
    Hypervisor, ImageKind, ImageRef, Machine, MigrationSource, MigrationTarget, Prepared, Ready,
    RunState, SnapshotId,
};
use asterism_core::instance::{Instance, Shape};
use asterism_core::power::{Change, SleepGuard};

use super::{backends, by_id, hyperv};
#[cfg(unix)]
use super::{chv, qemu, vz};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ControlKind {
    Qmp,
    Rpc,
    HttpApi,
    Helper,
}

impl ControlKind {
    fn channel(self, path: PathBuf) -> ControlChannel {
        match self {
            ControlKind::Qmp => ControlChannel::Qmp { path },
            ControlKind::Rpc => ControlChannel::Rpc { path },
            ControlKind::HttpApi => ControlChannel::HttpApi { path },
            ControlKind::Helper => ControlChannel::Helper { path },
        }
    }

    fn wire_name(self) -> &'static str {
        match self {
            ControlKind::Qmp => "qmp",
            ControlKind::Rpc => "rpc",
            ControlKind::HttpApi => "http_api",
            ControlKind::Helper => "helper",
        }
    }
}

/// The backend-specific fact a common fixture cannot infer: what kind of
/// guest control channel a successful boot records.  Keeping this match
/// exhaustive by policy is intentional.  A new registry entry reaches the
/// panic and cannot merge until its handles join the contract.
fn control_kind(id: &str) -> ControlKind {
    match id {
        #[cfg(unix)]
        qemu::ID => ControlKind::Qmp,
        #[cfg(unix)]
        vz::ID => ControlKind::Rpc,
        #[cfg(unix)]
        chv::ID => ControlKind::HttpApi,
        id if id == hyperv::ID => ControlKind::Helper,
        other => panic!("registered backend {other:?} has no conformance profile"),
    }
}

fn each_backend(mut check: impl FnMut(&dyn Hypervisor, ControlKind)) {
    let registered = backends();
    assert!(!registered.is_empty(), "this build must register a backend");
    for backend in registered {
        check(backend.as_ref(), control_kind(backend.id()));
    }
}

struct Fixture {
    _tmp: tempfile::TempDir,
    dir: PathBuf,
    instance: Instance,
    prepared: Prepared,
    control: PathBuf,
}

impl Fixture {
    fn new(backend: &dyn Hypervisor, control_kind: ControlKind) -> Self {
        let tmp = tempfile::tempdir().expect("temporary backend fixture");
        let dir = tmp.path().join(backend.id());
        std::fs::create_dir_all(&dir).unwrap();
        let disk = dir.join("disk.raw");
        std::fs::write(&disk, b"pristine").unwrap();

        let instance = Instance::new(
            "conformance",
            "test-device",
            "test:raw",
            Shape::default(),
            Machine {
                backend: backend.id().to_owned(),
                machine_type: "test-machine".to_owned(),
                cpu: "test-cpu".to_owned(),
                hv_version: "test-version".to_owned(),
            },
        );
        let control = dir.join(format!("guest.{}.sock", control_kind.wire_name()));
        Self {
            _tmp: tmp,
            dir,
            instance,
            prepared: Prepared {
                root: DiskSpec::File {
                    path: disk,
                    format: DiskFormat::Raw,
                    readonly: false,
                },
                firmware: None,
                kernel: None,
            },
            control,
        }
    }

    fn request(&self) -> BootReq<'_> {
        BootReq {
            instance: &self.instance,
            dir: self.dir.clone(),
            base: ImageRef {
                name: "test:raw".to_owned(),
                path: self.dir.join("base.raw"),
                format: DiskFormat::Raw,
                kind: ImageKind::Disk,
            },
            seed: self.dir.join("seed.iso"),
            shares: Vec::new(),
            egress: Default::default(),
            bootstrap: Default::default(),
            extra_disks: Vec::new(),
            // Logs are an input to the mandatory boot method, not something
            // a backend is allowed to relocate by naming convention.
            console: self.dir.join("console.log"),
        }
    }

    fn crashed_handle(&self, backend: &dyn Hypervisor, kind: ControlKind, pid: u32) -> Handle {
        Handle {
            backend: backend.id().to_owned(),
            // The registry format before process identities existed.  A
            // bare pid, whether stale or recycled, cannot authorise a signal.
            pid: Some(pid),
            proc: None,
            ctl: kind.channel(self.control.clone()),
            endpoint: match kind {
                ControlKind::Qmp => GuestEndpoint::HostForward { ssh_port: 22022 },
                ControlKind::Rpc | ControlKind::HttpApi | ControlKind::Helper => {
                    GuestEndpoint::GuestAddr {
                        addr: "192.0.2.1".parse().unwrap(),
                    }
                }
            },
            started_at: 1,
        }
    }

    fn disk_path(&self) -> &Path {
        self.prepared.root_path().unwrap()
    }
}

fn assert_ready_shape(id: &str, ready: &Ready) {
    for (field, value) in [
        ("version", ready.version.as_str()),
        ("accelerator", ready.accel.as_str()),
        ("machine type", ready.machine_type.as_str()),
        ("cpu", ready.cpu.as_str()),
    ] {
        assert!(!value.trim().is_empty(), "{id} returned an empty {field}");
    }
}

fn expected_support(caps: &Caps, capability: Capability) -> bool {
    match capability {
        Capability::LiveSnapshot => caps.live_snapshot,
        Capability::DiskSnapshot => caps.disk_snapshot,
        Capability::LiveMigration => caps.live_migration,
        Capability::DiskHotplug => caps.disk_hotplug,
        Capability::SharedDirectories => caps.shared_dir.is_some(),
        Capability::NbdDisks => caps.nbd_disks,
        Capability::ForeignArchitecture => caps.foreign_arch,
        Capability::DirectKernelBoot => caps.direct_kernel,
        Capability::PortForward => caps.port_forward,
        Capability::GuestEgress => caps.guest_egress.is_some(),
    }
}

fn assert_gate<T: std::fmt::Debug>(supported: bool, result: Result<T>, refusal: String) {
    match (supported, result) {
        (false, Err(error)) => assert_eq!(format!("{error:#}"), refusal),
        (false, Ok(value)) => panic!("unsupported operation succeeded with {value:?}"),
        // A supported capability may still reject this deliberately inert
        // fixture, but it must have overridden the default refusal.
        (true, Err(error)) => assert_ne!(format!("{error:#}"), refusal),
        (true, Ok(_)) => {}
    }
}

#[test]
fn registration_identity_readiness_and_capabilities_share_one_contract() {
    let mut ids = BTreeSet::new();
    each_backend(|backend, _| {
        let id = backend.id();
        assert!(!id.is_empty());
        assert!(
            id.bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'),
            "backend ids are stable wire values: {id:?}"
        );
        assert!(ids.insert(id), "backend id {id:?} is registered twice");
        assert_eq!(by_id(id).unwrap().id(), id);

        match backend.probe() {
            Ok(ready) => assert_ready_shape(id, &ready),
            Err(error) => assert!(
                !format!("{error:#}").trim().is_empty(),
                "{id} readiness refusal must explain itself"
            ),
        }

        let caps = backend.caps();
        for capability in Capability::ALL {
            assert_eq!(
                caps.supports(capability),
                expected_support(&caps, capability),
                "{id} has two answers for {capability:?}"
            );
        }
        assert!(
            caps.disk_formats.contains(&DiskFormat::Raw),
            "{id} cannot consume the orbit's common disk format"
        );
        for (at, format) in caps.disk_formats.iter().enumerate() {
            assert!(
                !caps.disk_formats[..at].contains(format),
                "{id} advertises {format} twice"
            );
        }
    });

    let unknown = by_id("not-a-backend")
        .err()
        .expect("an unregistered backend must be refused")
        .to_string();
    for id in ids {
        assert!(unknown.contains(id), "unknown-backend error omitted {id}");
    }
}

#[test]
fn reloaded_crash_handles_are_stopped_and_never_silently_signalled() {
    each_backend(|backend, kind| {
        let fixture = Fixture::new(backend, kind);
        let mut unrelated = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let handle = fixture.crashed_handle(backend, kind, unrelated.id());
        let encoded = serde_json::to_string(&handle).unwrap();
        assert!(
            encoded.contains(&format!(r#""kind":"{}""#, kind.wire_name())),
            "{} handle has the wrong control channel: {encoded}",
            backend.id()
        );
        let reloaded: Handle = serde_json::from_str(&encoded).unwrap();
        assert_eq!(reloaded.backend, backend.id());
        assert_eq!(reloaded.owned(), None, "a bare pid is not authority");
        assert_eq!(backend.state(&reloaded).unwrap(), RunState::Stopped);

        let stop = backend.stop(&reloaded, Duration::ZERO);
        assert!(
            stop.is_ok() || format!("{:#}", stop.as_ref().unwrap_err()).contains("not proven"),
            "{} must not signal an unproven pid: {stop:?}",
            backend.id()
        );
        let kill = backend.kill(&reloaded);
        assert!(
            kill.is_ok() || format!("{:#}", kill.as_ref().unwrap_err()).contains("not proven"),
            "{} must not signal an unproven pid: {kill:?}",
            backend.id()
        );
        assert_eq!(reloaded.owned(), None, "stop must not invent authority");
        assert!(
            unrelated.try_wait().unwrap().is_none(),
            "{} signalled a process named only by a bare pid",
            backend.id()
        );
        let _ = unrelated.kill();
        let _ = unrelated.wait();
    });
}

#[test]
fn raw_disk_snapshots_have_identical_end_to_end_semantics() {
    each_backend(|backend, kind| {
        let fixture = Fixture::new(backend, kind);
        assert!(
            backend.caps().disk_snapshot,
            "{} must snapshot the common raw disk format",
            backend.id()
        );
        assert!(backend
            .disk_snapshot_list(&fixture.prepared)
            .unwrap()
            .is_empty());

        let snapshot = backend.disk_snapshot(&fixture.prepared, "clean").unwrap();
        assert_eq!(snapshot, SnapshotId("clean".to_owned()));
        let listed = backend.disk_snapshot_list(&fixture.prepared).unwrap();
        assert_eq!(
            listed
                .iter()
                .map(|row| row.tag.as_str())
                .collect::<Vec<_>>(),
            ["clean"]
        );
        assert_eq!(
            backend
                .disk_snapshot(&fixture.prepared, "clean")
                .unwrap_err()
                .to_string(),
            "snapshot \"clean\" already exists"
        );

        std::fs::write(fixture.disk_path(), b"diverged").unwrap();
        let missing = SnapshotId("missing".to_owned());
        assert_eq!(
            backend
                .disk_restore(&fixture.prepared, &missing)
                .unwrap_err()
                .to_string(),
            "no snapshot \"missing\""
        );
        backend.disk_restore(&fixture.prepared, &snapshot).unwrap();
        assert_eq!(std::fs::read(fixture.disk_path()).unwrap(), b"pristine");

        backend
            .disk_snapshot_remove(&fixture.prepared, &snapshot)
            .unwrap();
        assert!(backend
            .disk_snapshot_list(&fixture.prepared)
            .unwrap()
            .is_empty());
        assert_eq!(
            backend
                .disk_snapshot_remove(&fixture.prepared, &snapshot)
                .unwrap_err()
                .to_string(),
            "no snapshot \"clean\""
        );
    });
}

#[test]
fn every_capability_gated_method_has_exact_failure_language() {
    each_backend(|backend, kind| {
        let fixture = Fixture::new(backend, kind);
        let handle = fixture.crashed_handle(backend, kind, u32::MAX);
        let request = fixture.request();
        let disk = DiskSpec::File {
            path: fixture.dir.join("extra.raw"),
            format: DiskFormat::Raw,
            readonly: false,
        };
        let caps = backend.caps();
        let refusal = |operation: &str| format!("the {} backend cannot {operation}", backend.id());

        assert_gate(
            caps.live_snapshot,
            backend.snapshot(&handle, "live"),
            refusal("snapshot a running guest"),
        );
        assert_gate(
            caps.live_snapshot,
            backend.restore(&request, &SnapshotId("live".to_owned())),
            refusal("restore a running guest from a snapshot"),
        );
        assert_gate(
            caps.disk_hotplug,
            backend.attach_disk(&handle, &disk),
            refusal("attach a disk to a running guest"),
        );
        assert_gate(
            caps.live_migration,
            backend.migrate_out(
                &handle,
                MigrationTarget {
                    url: "test://target".to_owned(),
                },
            ),
            refusal("migrate a running guest out"),
        );
        assert_gate(
            caps.live_migration,
            backend.migrate_in(
                &request,
                MigrationSource {
                    url: "test://source".to_owned(),
                },
            ),
            refusal("receive a migrating guest"),
        );
    });
}

#[test]
fn log_share_and_sleep_inputs_stay_outside_host_specific_backends() {
    each_backend(|backend, kind| {
        let fixture = Fixture::new(backend, kind);
        let request = fixture.request();
        assert_eq!(request.console, fixture.dir.join("console.log"));
        assert!(request.shares.is_empty());
        assert_eq!(
            backend.caps().supports(Capability::SharedDirectories),
            backend.caps().shared_dir.is_some()
        );
    });

    // Sleep prevention is a device-level power seam.  Merely registering a
    // backend must not acquire it; the supervisor does that from its common
    // running-instance count.
    let mut guard = SleepGuard::new();
    assert_eq!(guard.set(0), Change::Same);
    assert!(!guard.is_held());
}
