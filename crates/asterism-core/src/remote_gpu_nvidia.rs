//! Fail-closed NVIDIA inventory and the deterministic two-device GPU harness.
//!
//! The production GPU part still executes the CUDA-*semantic* ABI in
//! [`crate::remote_gpu`]. This module is the hardware admission seam around
//! that ABI: parse a provider's NVIDIA inventory, refuse unsupported
//! driver/CUDA/compute-capability combinations, and prove the two-device
//! contract (enumeration, a small kernel, buffer transfer, concurrent lease
//! fencing, provider-daemon restart, guest restart, revoke, version skew)
//! against two admitted GPU identities.
//!
//! Execution inside this harness uses the portable [`Executor::Reference`]
//! state machine. That is deliberate. Advertising `Executor::Cuda` and
//! setting `hardware_cuda_executed=true` is reserved for a provider that
//! actually launched the pinned work on NVIDIA hardware. A CPU reference
//! run is never NVIDIA evidence.

use std::collections::HashSet;

use crate::remote_gpu::{
    vector_add_workload, AbiRange, AuthenticatedPeer, BufferRange, ControlError, ControlErrorCode,
    Executor, GpuAttachment, LeaseAuthority, LeaseLimits, ProductionProvider, Provider,
    ProviderAdvertisement, ProviderHealth, ProviderRoute, Request, Response, ABI_VERSION,
    GUEST_DEVICE_PATH, VECTOR_ADD_PTX,
};
use crate::remote_gpu_cuda::CudaEngine;

/// NVIDIA driver floor for the paid gate. Older branches are refused rather
/// than probed.
pub const MIN_DRIVER_MAJOR: u32 = 550;
/// Oldest CUDA runtime major this gate will admit.
pub const MIN_CUDA_MAJOR: u32 = 12;
/// Oldest CUDA 12 minor this gate will admit (12.4 with driver 550).
pub const MIN_CUDA_MINOR_FOR_12: u32 = 4;
/// Newest CUDA runtime major this gate will admit. 14+ is fail-closed until
/// the matrix is expanded on purpose.
pub const MAX_CUDA_MAJOR: u32 = 13;
/// Compute-capability floor. Matches Turing (T4) and newer, which is also
/// what a CUDA 13 default image can run; the checked-in PTX is `sm_50` but
/// the hardware gate does not reopen Kepler/Maxwell.
pub const MIN_COMPUTE_MAJOR: u32 = 7;
pub const MIN_COMPUTE_MINOR: u32 = 5;

/// One physical NVIDIA GPU as reported by `nvidia-smi`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NvidiaDevice {
    pub index: u32,
    pub uuid: String,
    pub name: String,
    pub memory_bytes: u64,
    pub compute_capability: (u32, u32),
}

/// Provider-local NVIDIA inventory. This is not a lease and not a mesh
/// identity; admission happens before any ABI session is opened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CudaInventory {
    pub driver_version: String,
    pub cuda_runtime_version: String,
    pub devices: Vec<NvidiaDevice>,
}

/// An inventory that passed the fail-closed matrix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmittedNvidiaDevice {
    pub device: NvidiaDevice,
    pub driver_version: String,
    pub cuda_runtime_version: String,
}

/// Two distinct admitted NVIDIA GPUs. Order is UUID-sorted so the harness
/// is deterministic across `nvidia-smi` listing orders.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmittedNvidiaPair {
    pub first: AdmittedNvidiaDevice,
    pub second: AdmittedNvidiaDevice,
}

/// Structured evidence from the deterministic two-device contract. This is
/// not a hardware-pass record: `hardware_cuda_executed` stays false here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HarnessEvidence {
    pub guest_visible_device: &'static str,
    pub abi_version: u32,
    pub executor: Executor,
    pub first_gpu_uuid: String,
    pub second_gpu_uuid: String,
    pub enumerated_devices: u32,
    pub kernel_verified: bool,
    pub buffer_transfer_verified: bool,
    pub concurrent_lease_fencing: bool,
    pub provider_daemon_restart: bool,
    pub guest_restart: bool,
    pub revoke: bool,
    pub version_skew_fail_closed: bool,
    pub unsupported_matrix_fail_closed: bool,
    pub hardware_cuda_executed: bool,
}

impl HarnessEvidence {
    /// Key=value lines a gate script can grep. The CPU harness never claims
    /// CUDA hardware execution.
    pub fn report_lines(&self) -> Vec<String> {
        vec![
            format!("guest_visible_device={}", self.guest_visible_device),
            format!("remote_gpu_abi={}", self.abi_version),
            format!(
                "executor={}",
                match self.executor {
                    Executor::Cuda => "cuda",
                    Executor::Reference => "reference",
                }
            ),
            format!("first_gpu_uuid={}", self.first_gpu_uuid),
            format!("second_gpu_uuid={}", self.second_gpu_uuid),
            format!("enumerated_devices={}", self.enumerated_devices),
            format!("kernel_verified={}", self.kernel_verified),
            format!("buffer_transfer_verified={}", self.buffer_transfer_verified),
            format!("concurrent_lease_fencing={}", self.concurrent_lease_fencing),
            format!("provider_daemon_restart={}", self.provider_daemon_restart),
            format!("guest_restart={}", self.guest_restart),
            format!("revoke={}", self.revoke),
            format!("version_skew_fail_closed={}", self.version_skew_fail_closed),
            format!(
                "unsupported_matrix_fail_closed={}",
                self.unsupported_matrix_fail_closed
            ),
            format!("hardware_cuda_executed={}", self.hardware_cuda_executed),
        ]
    }
}

/// Canonical two-device fixture used by the deterministic harness. These
/// UUIDs are not hardware; they exercise admission and fencing.
pub fn sample_two_device_inventory() -> CudaInventory {
    CudaInventory {
        driver_version: "550.54.15".into(),
        cuda_runtime_version: "12.4".into(),
        devices: vec![
            NvidiaDevice {
                index: 0,
                uuid: "GPU-aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa".into(),
                name: "NVIDIA L4".into(),
                memory_bytes: 24 * 1024 * 1024 * 1024,
                compute_capability: (8, 9),
            },
            NvidiaDevice {
                index: 1,
                uuid: "GPU-bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb".into(),
                name: "NVIDIA L4".into(),
                memory_bytes: 24 * 1024 * 1024 * 1024,
                compute_capability: (8, 9),
            },
        ],
    }
}

/// A fixture the matrix must refuse. Used to prove fail-closed behaviour
/// rather than a skip.
pub fn unsupported_driver_inventory() -> CudaInventory {
    CudaInventory {
        driver_version: "470.82.01".into(),
        cuda_runtime_version: "11.8".into(),
        devices: vec![NvidiaDevice {
            index: 0,
            uuid: "GPU-cccccccc-cccc-cccc-cccc-cccccccccccc".into(),
            name: "Tesla T4".into(),
            memory_bytes: 16 * 1024 * 1024 * 1024,
            compute_capability: (7, 5),
        }],
    }
}

/// Parse the checked-in inventory language. Lines are `driver_version=`,
/// `cuda_runtime_version=`, and `gpu …` records. Unknown lines are errors
/// so a truncated `nvidia-smi` dump cannot silently shrink the device set.
pub fn parse_inventory(text: &str) -> Result<CudaInventory, ControlError> {
    let mut driver_version = None;
    let mut cuda_runtime_version = None;
    let mut devices = Vec::new();
    for (line_no, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(value) = line.strip_prefix("driver_version=") {
            driver_version = Some(value.trim().to_owned());
            continue;
        }
        if let Some(value) = line.strip_prefix("cuda_runtime_version=") {
            cuda_runtime_version = Some(value.trim().to_owned());
            continue;
        }
        if let Some(rest) = line.strip_prefix("gpu ") {
            devices.push(parse_gpu_fields(rest, line_no + 1)?);
            continue;
        }
        return Err(ControlError::new(
            ControlErrorCode::InvalidRequest,
            format!(
                "nvidia inventory line {}: unsupported syntax: {line}",
                line_no + 1
            ),
        ));
    }
    Ok(CudaInventory {
        driver_version: require_field(driver_version, "driver_version")?,
        cuda_runtime_version: require_field(cuda_runtime_version, "cuda_runtime_version")?,
        devices,
    })
}

/// Parse one `nvidia-smi --query-gpu=index,uuid,name,memory.total,compute_cap
/// --format=csv,noheader,nounits` row. Memory is MiB.
pub fn parse_nvidia_smi_gpu_csv(line: &str) -> Result<NvidiaDevice, ControlError> {
    let parts = split_csv(line);
    if parts.len() != 5 {
        return Err(ControlError::new(
            ControlErrorCode::InvalidRequest,
            format!(
                "nvidia-smi gpu csv must have 5 columns, got {}: {line}",
                parts.len()
            ),
        ));
    }
    let index = parse_u32(parts[0], "gpu index")?;
    let uuid = parts[1].to_owned();
    let name = parts[2].to_owned();
    let memory_mib = parse_u64(parts[3], "memory.total")?;
    let compute_capability = parse_compute_capability(parts[4])?;
    Ok(NvidiaDevice {
        index,
        uuid,
        name,
        memory_bytes: memory_mib.saturating_mul(1024 * 1024),
        compute_capability,
    })
}

/// Admit every device in an inventory, or refuse the whole provider. Partial
/// admission would let an unsupported card hide behind a supported neighbour.
pub fn admit_cuda_inventory(
    inventory: &CudaInventory,
) -> Result<Vec<AdmittedNvidiaDevice>, ControlError> {
    admit_driver_and_cuda(&inventory.driver_version, &inventory.cuda_runtime_version)?;
    if inventory.devices.is_empty() {
        return Err(ControlError::new(
            ControlErrorCode::Unavailable,
            "NVIDIA inventory contains no GPUs",
        ));
    }
    let mut admitted = Vec::new();
    let mut seen = HashSet::new();
    for device in &inventory.devices {
        admit_device(device)?;
        if !seen.insert(device.uuid.clone()) {
            return Err(ControlError::new(
                ControlErrorCode::InvalidRequest,
                format!("duplicate NVIDIA GPU UUID {}", device.uuid),
            ));
        }
        admitted.push(AdmittedNvidiaDevice {
            device: device.clone(),
            driver_version: inventory.driver_version.clone(),
            cuda_runtime_version: inventory.cuda_runtime_version.clone(),
        });
    }
    Ok(admitted)
}

/// The paid hardware gate requires two distinct admitted NVIDIA GPUs.
pub fn admit_two_device_gate(
    inventory: &CudaInventory,
) -> Result<AdmittedNvidiaPair, ControlError> {
    let mut admitted = admit_cuda_inventory(inventory)?;
    if admitted.len() < 2 {
        return Err(ControlError::new(
            ControlErrorCode::Unavailable,
            format!(
                "NVIDIA two-device gate requires 2 GPUs; inventory admitted {}",
                admitted.len()
            ),
        ));
    }
    admitted.sort_by(|left, right| left.device.uuid.cmp(&right.device.uuid));
    Ok(AdmittedNvidiaPair {
        first: admitted[0].clone(),
        second: admitted[1].clone(),
    })
}

/// Run the deterministic two-device contract against an admitted inventory.
///
/// This proves the production part seam: guest-visible `/dev/nvidia0`,
/// identity-bound leases, fencing, restart, revoke, and fail-closed skew
/// and driver matrix. It does **not** launch work on NVIDIA hardware.
pub fn prove_two_device_nvidia_contract(
    inventory: &CudaInventory,
) -> Result<HarnessEvidence, ControlError> {
    let pair = admit_two_device_gate(inventory)?;
    if admit_cuda_inventory(&unsupported_driver_inventory()).is_ok() {
        return Err(ControlError::new(
            ControlErrorCode::Unavailable,
            "unsupported NVIDIA driver/CUDA inventory was admitted",
        ));
    }

    let guest_a = harness_peer(0x0a);
    let guest_b = harness_peer(0x0b);
    let guest_c = harness_peer(0x0c);
    let mut left = fixture_production_for(&pair.first, 0x11, 1)?;
    let mut right = fixture_production_for(&pair.second, 0x22, 1)?;

    let (left_cap, left_session, left_attachment) = attach_and_open(
        &mut left,
        &guest_a,
        "instance-left",
        16 * 1024 * 1024,
        1_000,
    )?;
    let (right_cap, right_session, right_attachment) = attach_and_open(
        &mut right,
        &guest_b,
        "instance-right",
        16 * 1024 * 1024,
        1_000,
    )?;
    if left_attachment.guest_path() != GUEST_DEVICE_PATH
        || right_attachment.guest_path() != GUEST_DEVICE_PATH
    {
        return Err(ControlError::new(
            ControlErrorCode::Unavailable,
            "attached GPU must project /dev/nvidia0 into the guest",
        ));
    }

    let kernel_ok = vector_add_on(&mut left, &guest_a, &left_cap, &left_session, 1_010)?;
    let fencing_ok = prove_concurrent_fencing(&mut left, &mut right, &guest_c)?;
    let (restart_ok, new_right_cap) = prove_provider_restart(
        &mut right,
        &guest_b,
        &right_cap,
        &right_session,
        right_attachment.provider_generation,
    )?;
    let guest_restart_ok = prove_guest_restart(&mut left, &guest_a, &left_cap, left_session)?;
    let revoke_ok = prove_revoke(&mut left, &guest_a, &left_cap)?;
    let skew_ok = prove_version_skew(&mut right, &guest_b, &new_right_cap)?;

    require(
        kernel_ok && fencing_ok && restart_ok && guest_restart_ok && revoke_ok && skew_ok,
        "two-device NVIDIA contract incomplete",
    )?;

    Ok(HarnessEvidence {
        guest_visible_device: GUEST_DEVICE_PATH,
        abi_version: ABI_VERSION,
        executor: Executor::Reference,
        first_gpu_uuid: pair.first.device.uuid.clone(),
        second_gpu_uuid: pair.second.device.uuid.clone(),
        enumerated_devices: 2,
        kernel_verified: kernel_ok,
        buffer_transfer_verified: kernel_ok,
        concurrent_lease_fencing: fencing_ok,
        provider_daemon_restart: restart_ok,
        guest_restart: guest_restart_ok,
        revoke: revoke_ok,
        version_skew_fail_closed: skew_ok,
        unsupported_matrix_fail_closed: true,
        hardware_cuda_executed: false,
    })
}

/// Placement advertisements for the two admitted GPUs. The planner still
/// requires CUDA when `require_cuda` is set; the ABI executor behind the
/// harness remains the reference state machine.
pub fn advertisements_for_pair(pair: &AdmittedNvidiaPair) -> [ProviderAdvertisement; 2] {
    [
        advertisement(&pair.first, ProviderRoute::Direct { rtt_us: 120 }),
        advertisement(&pair.second, ProviderRoute::Direct { rtt_us: 180 }),
    ]
}

fn advertisement(admitted: &AdmittedNvidiaDevice, route: ProviderRoute) -> ProviderAdvertisement {
    ProviderAdvertisement {
        device_id: mesh_id_from_uuid(&admitted.device.uuid),
        device_name: admitted.device.name.clone(),
        gpu_uuid: admitted.device.uuid.clone(),
        device_name_cuda: admitted.device.name.clone(),
        executor: Executor::Cuda,
        versions: AbiRange::ours(),
        total_memory_bytes: admitted.device.memory_bytes,
        leased_memory_bytes: 0,
        max_leases: 1,
        active_leases: 0,
        generation: 1,
        health: ProviderHealth::Ready,
        route,
        observed_at: 1_000,
    }
}

pub fn production_for(
    admitted: &AdmittedNvidiaDevice,
    provider_device: &str,
    provider_device_id: &str,
    generation: u64,
    max_leases: u32,
) -> Result<ProductionProvider, ControlError> {
    let authority = LeaseAuthority::new(
        provider_device,
        provider_device_id,
        admitted.device.uuid.clone(),
        generation,
        LeaseLimits {
            total_memory_bytes: admitted.device.memory_bytes,
            max_memory_per_lease: admitted.device.memory_bytes,
            max_leases,
            lease_ttl_secs: 600,
        },
    )?;
    let engine = CudaEngine::open_live(Some(&admitted.device.uuid))?;
    ProductionProvider::connect(authority, engine)
}

/// Deterministic source fixture. It is deliberately private and keeps the
/// reference executor, so synthetic inventory can never escape into product
/// registration or claim hardware execution.
fn fixture_production_for(
    admitted: &AdmittedNvidiaDevice,
    identity_nibble: u8,
    max_leases: u32,
) -> Result<ProductionProvider, ControlError> {
    let authority = LeaseAuthority::new(
        admitted.device.name.clone(),
        mesh_id(identity_nibble),
        admitted.device.uuid.clone(),
        1,
        LeaseLimits {
            total_memory_bytes: admitted.device.memory_bytes,
            max_memory_per_lease: admitted.device.memory_bytes,
            max_leases,
            lease_ttl_secs: 600,
        },
    )?;
    Ok(ProductionProvider::new(
        authority,
        Provider::reference(admitted.device.name.clone()),
    ))
}

fn prove_concurrent_fencing(
    left: &mut ProductionProvider,
    right: &mut ProductionProvider,
    stranger: &AuthenticatedPeer,
) -> Result<bool, ControlError> {
    let third =
        right
            .authority_mut()
            .attach(stranger, "instance-intruder", 16 * 1024 * 1024, 1_020);
    let left_again =
        left.authority_mut()
            .attach(stranger, "instance-left-again", 16 * 1024 * 1024, 1_020);
    Ok(refused(&third, &[ControlErrorCode::LimitExceeded])
        && refused(&left_again, &[ControlErrorCode::LimitExceeded])
        && left.authority().diagnostics().active_leases == 1
        && right.authority().diagnostics().active_leases == 1)
}

fn prove_provider_restart(
    provider: &mut ProductionProvider,
    peer: &AuthenticatedPeer,
    old_capability: &str,
    old_session: &str,
    old_generation: u64,
) -> Result<(bool, String), ControlError> {
    let lost = provider.provider_lost("provider daemon restart");
    provider.authority_mut().recover()?;
    let stale = provider.handle(
        peer,
        old_capability,
        Request::Read {
            session: old_session.to_owned(),
            sequence: 2,
            source: range("gone", 0, 4),
        },
        1_030,
    );
    let (new_capability, _, new_attachment) =
        attach_and_open(provider, peer, "instance-right", 16 * 1024 * 1024, 1_040)?;
    Ok((
        lost == 1
            && refused(
                &stale,
                &[
                    ControlErrorCode::InvalidLease,
                    ControlErrorCode::Revoked,
                    ControlErrorCode::StaleGeneration,
                ],
            )
            && new_attachment.provider_generation > old_generation
            && new_capability != old_capability,
        new_capability,
    ))
}

fn prove_guest_restart(
    provider: &mut ProductionProvider,
    peer: &AuthenticatedPeer,
    capability: &str,
    old_session: String,
) -> Result<bool, ControlError> {
    if !provider.guest_lost("instance-left") {
        return Ok(false);
    }
    let stale = provider.handle(
        peer,
        capability,
        Request::Read {
            session: old_session,
            sequence: 2,
            source: range("gone", 0, 4),
        },
        1_050,
    );
    let Response::SessionOpened { session, .. } =
        provider.open_session(peer, capability, AbiRange::ours(), 1_060)?
    else {
        return Err(ControlError::new(
            ControlErrorCode::Unavailable,
            "restarted guest must reopen an ABI session on the live lease",
        ));
    };
    abi(
        provider,
        peer,
        capability,
        Request::Allocate {
            session,
            sequence: 1,
            bytes: 8,
        },
        1_070,
    )?;
    Ok(refused(&stale, &[ControlErrorCode::InvalidLease])
        && provider.authority().diagnostics().active_leases == 1)
}

fn prove_revoke(
    provider: &mut ProductionProvider,
    peer: &AuthenticatedPeer,
    capability: &str,
) -> Result<bool, ControlError> {
    let revoked = provider.revoke_instance("instance-left");
    let after = provider.open_session(peer, capability, AbiRange::ours(), 1_080);
    Ok(revoked
        && provider.authority().diagnostics().active_leases == 0
        && refused(
            &after,
            &[ControlErrorCode::Revoked, ControlErrorCode::InvalidLease],
        ))
}

fn prove_version_skew(
    provider: &mut ProductionProvider,
    peer: &AuthenticatedPeer,
    capability: &str,
) -> Result<bool, ControlError> {
    let _ = provider.guest_lost("instance-right");
    let skew = provider.open_session(peer, capability, AbiRange { min: 2, max: 2 }, 1_090);
    if skew.is_ok() {
        return Err(ControlError::new(
            ControlErrorCode::Unavailable,
            "ABI version skew opened a session instead of failing closed",
        ));
    }
    Ok(refused(
        &skew,
        &[
            ControlErrorCode::Unavailable,
            ControlErrorCode::UnsupportedVersion,
        ],
    ) && provider.authority().diagnostics().active_leases == 1)
}

fn refused<T>(result: &Result<T, ControlError>, codes: &[ControlErrorCode]) -> bool {
    match result {
        Err(error) => codes.contains(&error.code),
        Ok(_) => false,
    }
}

fn require(ok: bool, message: &str) -> Result<(), ControlError> {
    if ok {
        Ok(())
    } else {
        Err(ControlError::new(ControlErrorCode::Unavailable, message))
    }
}

fn attach_and_open(
    production: &mut ProductionProvider,
    peer: &AuthenticatedPeer,
    instance_id: &str,
    memory_bytes: u64,
    now: u64,
) -> Result<(String, String, GpuAttachment), ControlError> {
    let (lease, attachment) =
        production
            .authority_mut()
            .attach(peer, instance_id, memory_bytes, now)?;
    let response = production.open_session(peer, lease.capability(), AbiRange::ours(), now)?;
    let Response::SessionOpened { session, abi, .. } = response else {
        return Err(ControlError::new(
            ControlErrorCode::Unavailable,
            "hello must open a GPU ABI session",
        ));
    };
    if abi != ABI_VERSION {
        return Err(ControlError::new(
            ControlErrorCode::Unavailable,
            format!("expected ABI {ABI_VERSION}, negotiated {abi}"),
        ));
    }
    Ok((lease.capability().to_owned(), session, attachment))
}

fn vector_add_on(
    production: &mut ProductionProvider,
    peer: &AuthenticatedPeer,
    capability: &str,
    session: &str,
    now: u64,
) -> Result<bool, ControlError> {
    let encode = |values: &[f32]| {
        values
            .iter()
            .flat_map(|value| value.to_le_bytes())
            .collect::<Vec<_>>()
    };
    let lhs_bytes = encode(&[1.0, 2.5, -4.0]);
    let rhs_bytes = encode(&[5.0, -0.5, 10.0]);

    let lhs = match abi(
        production,
        peer,
        capability,
        Request::Allocate {
            session: session.to_owned(),
            sequence: 1,
            bytes: 12,
        },
        now,
    )? {
        Response::Allocated { allocation, .. } => allocation,
        _ => {
            return Err(ControlError::new(
                ControlErrorCode::Unavailable,
                "allocate lhs",
            ))
        }
    };
    let rhs = match abi(
        production,
        peer,
        capability,
        Request::Allocate {
            session: session.to_owned(),
            sequence: 2,
            bytes: 12,
        },
        now,
    )? {
        Response::Allocated { allocation, .. } => allocation,
        _ => {
            return Err(ControlError::new(
                ControlErrorCode::Unavailable,
                "allocate rhs",
            ))
        }
    };
    let output = match abi(
        production,
        peer,
        capability,
        Request::Allocate {
            session: session.to_owned(),
            sequence: 3,
            bytes: 12,
        },
        now,
    )? {
        Response::Allocated { allocation, .. } => allocation,
        _ => {
            return Err(ControlError::new(
                ControlErrorCode::Unavailable,
                "allocate output",
            ))
        }
    };
    abi(
        production,
        peer,
        capability,
        Request::Write {
            session: session.to_owned(),
            sequence: 4,
            destination: range(&lhs, 0, 12),
            data: lhs_bytes,
        },
        now,
    )?;
    abi(
        production,
        peer,
        capability,
        Request::Write {
            session: session.to_owned(),
            sequence: 5,
            destination: range(&rhs, 0, 12),
            data: rhs_bytes,
        },
        now,
    )?;
    let descriptor = vector_add_workload();
    let pin = descriptor.content_blake3.clone();
    abi(
        production,
        peer,
        capability,
        Request::LoadWorkload {
            session: session.to_owned(),
            sequence: 6,
            descriptor,
            image: VECTOR_ADD_PTX.as_bytes().to_vec(),
        },
        now,
    )?;
    abi(
        production,
        peer,
        capability,
        Request::LaunchVectorAdd {
            session: session.to_owned(),
            sequence: 7,
            workload_pin: pin,
            lhs: range(&lhs, 0, 12),
            rhs: range(&rhs, 0, 12),
            output: range(&output, 0, 12),
            elements: 3,
        },
        now,
    )?;
    let response = abi(
        production,
        peer,
        capability,
        Request::Read {
            session: session.to_owned(),
            sequence: 8,
            source: range(&output, 0, 12),
        },
        now,
    )?;
    let Response::Data { data, .. } = response else {
        return Err(ControlError::new(
            ControlErrorCode::Unavailable,
            "vector-add read must return data",
        ));
    };
    let values = data
        .chunks(4)
        .map(|bytes| f32::from_le_bytes(bytes.try_into().unwrap_or([0; 4])))
        .collect::<Vec<_>>();
    Ok(values == vec![6.0, 2.0, 6.0])
}

fn abi(
    production: &mut ProductionProvider,
    peer: &AuthenticatedPeer,
    capability: &str,
    request: Request,
    now: u64,
) -> Result<Response, ControlError> {
    production
        .handle(peer, capability, request, now)
        .and_then(|reply| {
            reply
                .into_result()
                .map_err(|error| ControlError::new(ControlErrorCode::Unavailable, error.message))
        })
}

fn admit_driver_and_cuda(driver: &str, cuda: &str) -> Result<(), ControlError> {
    let driver = parse_dotted_version(driver, "NVIDIA driver")?;
    let cuda = parse_dotted_version(cuda, "CUDA runtime")?;
    if driver.0 < MIN_DRIVER_MAJOR {
        return Err(ControlError::new(
            ControlErrorCode::Unavailable,
            format!(
                "NVIDIA driver {driver} is unsupported; require {MIN_DRIVER_MAJOR}+",
                driver = format_version(driver)
            ),
        ));
    }
    let cuda_ok = match cuda.0 {
        major if major < MIN_CUDA_MAJOR => false,
        12 => cuda.1 >= MIN_CUDA_MINOR_FOR_12,
        major if major <= MAX_CUDA_MAJOR => true,
        _ => false,
    };
    if !cuda_ok {
        return Err(ControlError::new(
            ControlErrorCode::Unavailable,
            format!(
                "CUDA runtime {cuda} is unsupported; require {MIN_CUDA_MAJOR}.{MIN_CUDA_MINOR_FOR_12}..{MAX_CUDA_MAJOR}.x",
                cuda = format_version(cuda)
            ),
        ));
    }
    Ok(())
}

fn admit_device(device: &NvidiaDevice) -> Result<(), ControlError> {
    if device.name.trim().is_empty() {
        return Err(ControlError::new(
            ControlErrorCode::InvalidRequest,
            "NVIDIA GPU name is required",
        ));
    }
    if device.memory_bytes == 0 {
        return Err(ControlError::new(
            ControlErrorCode::InvalidRequest,
            format!("NVIDIA GPU {} reports 0 bytes of memory", device.uuid),
        ));
    }
    if !valid_gpu_uuid(&device.uuid) {
        return Err(ControlError::new(
            ControlErrorCode::InvalidRequest,
            format!(
                "NVIDIA GPU UUID {:?} is not an nvidia-smi GPU- UUID",
                device.uuid
            ),
        ));
    }
    let (major, minor) = device.compute_capability;
    if major < MIN_COMPUTE_MAJOR || (major == MIN_COMPUTE_MAJOR && minor < MIN_COMPUTE_MINOR) {
        return Err(ControlError::new(
            ControlErrorCode::Unavailable,
            format!(
                "GPU {} compute capability {major}.{minor} is unsupported; require {MIN_COMPUTE_MAJOR}.{MIN_COMPUTE_MINOR}+",
                device.uuid
            ),
        ));
    }
    Ok(())
}

fn valid_gpu_uuid(uuid: &str) -> bool {
    let Some(rest) = uuid.strip_prefix("GPU-") else {
        return false;
    };
    !rest.is_empty()
        && rest
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() || byte == b'-')
}

fn parse_gpu_fields(line: &str, line_no: usize) -> Result<NvidiaDevice, ControlError> {
    let index = parse_u32(required_field(line, "index", line_no)?, "index")?;
    let uuid = required_field(line, "uuid", line_no)?.to_owned();
    let memory_bytes = parse_u64(
        required_field(line, "memory_bytes", line_no)?,
        "memory_bytes",
    )?;
    let compute_capability =
        parse_compute_capability(required_field(line, "compute_capability", line_no)?)?;
    let name = required_field(line, "name", line_no)?.to_owned();
    Ok(NvidiaDevice {
        index,
        uuid,
        name,
        memory_bytes,
        compute_capability,
    })
}

fn required_field<'a>(line: &'a str, key: &str, line_no: usize) -> Result<&'a str, ControlError> {
    field(line, key).ok_or_else(|| {
        ControlError::new(
            ControlErrorCode::InvalidRequest,
            format!("nvidia inventory line {line_no} is missing {key}"),
        )
    })
}

fn field<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let needle = format!("{key}=");
    let start = line.find(&needle)?;
    let rest = &line[start + needle.len()..];
    let keys = [
        "index=",
        "uuid=",
        "name=",
        "memory_bytes=",
        "compute_capability=",
    ];
    let mut end = rest.len();
    for other in keys {
        if other == needle.as_str() {
            continue;
        }
        if let Some(at) = rest.find(&format!(" {other}")) {
            end = end.min(at);
        }
    }
    Some(rest[..end].trim())
}

fn require_field(value: Option<String>, name: &str) -> Result<String, ControlError> {
    value.filter(|text| !text.is_empty()).ok_or_else(|| {
        ControlError::new(
            ControlErrorCode::InvalidRequest,
            format!("nvidia inventory is missing {name}"),
        )
    })
}

fn parse_compute_capability(text: &str) -> Result<(u32, u32), ControlError> {
    let version = parse_dotted_version(text, "compute capability")?;
    Ok((version.0, version.1))
}

fn parse_dotted_version(text: &str, what: &str) -> Result<(u32, u32, u32), ControlError> {
    let mut parts = text.split('.');
    let major = parse_u32(parts.next().unwrap_or(""), what)?;
    let minor = match parts.next() {
        Some(text) => parse_u32(text, what)?,
        None => 0,
    };
    let patch = match parts.next() {
        Some(text) => parse_u32(text, what)?,
        None => 0,
    };
    if parts.next().is_some() {
        return Err(ControlError::new(
            ControlErrorCode::InvalidRequest,
            format!("{what} version {text:?} has too many components"),
        ));
    }
    Ok((major, minor, patch))
}

fn parse_u32(text: &str, what: &str) -> Result<u32, ControlError> {
    text.trim().parse::<u32>().map_err(|_| {
        ControlError::new(
            ControlErrorCode::InvalidRequest,
            format!("{what} {text:?} is not a u32"),
        )
    })
}

fn parse_u64(text: &str, what: &str) -> Result<u64, ControlError> {
    text.trim().parse::<u64>().map_err(|_| {
        ControlError::new(
            ControlErrorCode::InvalidRequest,
            format!("{what} {text:?} is not a u64"),
        )
    })
}

fn format_version(version: (u32, u32, u32)) -> String {
    format!("{}.{}.{}", version.0, version.1, version.2)
}

fn split_csv(line: &str) -> Vec<&str> {
    line.split(',').map(str::trim).collect()
}

fn range(allocation: &str, offset: u64, bytes: u64) -> BufferRange {
    BufferRange {
        allocation: allocation.into(),
        offset,
        bytes,
    }
}

fn harness_peer(nibble: u8) -> AuthenticatedPeer {
    AuthenticatedPeer::from_mesh_identity(mesh_id(nibble)).expect("harness peer")
}

fn mesh_id(nibble: u8) -> String {
    format!("{nibble:02x}").repeat(32)
}

fn mesh_id_from_uuid(uuid: &str) -> String {
    let mut hex = uuid
        .bytes()
        .filter(|byte| byte.is_ascii_hexdigit())
        .map(|byte| byte.to_ascii_lowercase() as char)
        .collect::<String>();
    hex.truncate(64);
    while hex.len() < 64 {
        hex.push('0');
    }
    hex
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::remote_gpu::place_provider;
    use crate::remote_gpu::PlacementRequest;

    #[test]
    fn two_device_inventory_is_admitted_and_the_unsupported_matrix_is_not() {
        let pair = admit_two_device_gate(&sample_two_device_inventory()).unwrap();
        assert_eq!(
            pair.first.device.uuid,
            "GPU-aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
        );
        assert_eq!(
            pair.second.device.uuid,
            "GPU-bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
        );
        let error = admit_cuda_inventory(&unsupported_driver_inventory()).unwrap_err();
        assert_eq!(error.code, ControlErrorCode::Unavailable);
        assert!(error.message.contains("NVIDIA driver"));
    }

    #[test]
    fn one_gpu_cannot_satisfy_the_two_device_gate() {
        let mut inventory = sample_two_device_inventory();
        inventory.devices.pop();
        let error = admit_two_device_gate(&inventory).unwrap_err();
        assert_eq!(error.code, ControlErrorCode::Unavailable);
        assert!(error.message.contains("requires 2 GPUs"));
    }

    #[test]
    fn old_compute_capability_and_cuda_14_fail_closed() {
        let mut inventory = sample_two_device_inventory();
        inventory.devices[0].compute_capability = (7, 0);
        let error = admit_cuda_inventory(&inventory).unwrap_err();
        assert!(error.message.contains("compute capability"));

        inventory = sample_two_device_inventory();
        inventory.cuda_runtime_version = "14.0".into();
        let error = admit_cuda_inventory(&inventory).unwrap_err();
        assert!(error.message.contains("CUDA runtime"));
    }

    #[test]
    fn inventory_text_and_nvidia_smi_csv_round_trip_two_devices() {
        let text = "\
driver_version=550.54.15
cuda_runtime_version=12.4
gpu index=1 uuid=GPU-bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb memory_bytes=25769803776 compute_capability=8.9 name=NVIDIA L4
gpu index=0 uuid=GPU-aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa memory_bytes=25769803776 compute_capability=8.9 name=NVIDIA L4
";
        let parsed = parse_inventory(text).unwrap();
        let pair = admit_two_device_gate(&parsed).unwrap();
        assert_eq!(pair.first.device.index, 0);
        assert_eq!(pair.second.device.index, 1);

        let csv = parse_nvidia_smi_gpu_csv(
            "0, GPU-aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa, NVIDIA L4, 24576, 8.9",
        )
        .unwrap();
        assert_eq!(csv.memory_bytes, 24576 * 1024 * 1024);
        assert_eq!(csv.compute_capability, (8, 9));
    }

    #[test]
    fn deterministic_two_device_contract_never_claims_hardware_cuda() {
        let evidence = prove_two_device_nvidia_contract(&sample_two_device_inventory()).unwrap();
        assert_eq!(evidence.guest_visible_device, "/dev/nvidia0");
        assert_eq!(evidence.abi_version, 1);
        assert_eq!(evidence.executor, Executor::Reference);
        assert!(evidence.kernel_verified);
        assert!(evidence.buffer_transfer_verified);
        assert!(evidence.concurrent_lease_fencing);
        assert!(evidence.provider_daemon_restart);
        assert!(evidence.guest_restart);
        assert!(evidence.revoke);
        assert!(evidence.version_skew_fail_closed);
        assert!(evidence.unsupported_matrix_fail_closed);
        assert!(!evidence.hardware_cuda_executed);
        let report = evidence.report_lines().join("\n");
        assert!(report.contains("hardware_cuda_executed=false"));
        assert!(report.contains("guest_visible_device=/dev/nvidia0"));
    }

    #[test]
    fn cuda_13_and_driver_550_are_inside_the_matrix() {
        let mut inventory = sample_two_device_inventory();
        inventory.driver_version = "550.00".into();
        inventory.cuda_runtime_version = "13.0".into();
        admit_two_device_gate(&inventory).unwrap();
    }

    #[test]
    fn placement_still_ranks_two_cuda_providers_without_opening_a_lease() {
        let pair = admit_two_device_gate(&sample_two_device_inventory()).unwrap();
        let ads = advertisements_for_pair(&pair);
        let placed = place_provider(
            &ads,
            PlacementRequest {
                memory_bytes: 1024,
                provider_device: None,
                require_cuda: true,
            },
        )
        .unwrap();
        assert_eq!(placed.provider.gpu_uuid, pair.first.device.uuid);
        assert_eq!(placed.provider.executor, Executor::Cuda);
    }

    #[test]
    fn version_skew_error_is_unsupported_not_a_session() {
        let mut production = fixture_production_for(
            &admit_two_device_gate(&sample_two_device_inventory())
                .unwrap()
                .first,
            0x11,
            1,
        )
        .unwrap();
        let peer = harness_peer(0x0a);
        let (capability, _, _) =
            attach_and_open(&mut production, &peer, "skewed", 16 * 1024 * 1024, 1).unwrap();
        assert!(production.guest_lost("skewed"));
        let error = production
            .open_session(&peer, &capability, AbiRange { min: 2, max: 2 }, 2)
            .unwrap_err();
        assert_eq!(error.code, ControlErrorCode::UnsupportedVersion);
        assert!(
            error.message.contains("no remote GPU ABI is common") || error.message.contains("ABI")
        );
    }
}
