//! Exact real-NVIDIA release gate.
//!
//! This is the integration record that consumes the guest-projection
//! candidate (`as-lvf.13.2`) and the real CUDA provider candidate
//! (`as-lvf.13.3`). A hardware PASS is one end-to-end path:
//!
//! 1. a CUDA application runs inside an Asterism guest/container;
//! 2. it opens the projected `/dev/nvidia0` and injected `libcuda`;
//! 3. operations cross two *named* mesh devices (guest ↔ provider);
//! 4. the provider helper executes on real NVIDIA hardware.
//!
//! The portable [`crate::remote_gpu::Executor::Reference`] loopback proof,
//! a host-direct `nvcc` kernel against the provider's `/dev/nvidia*`, and
//! any mock inventory are ABI or admission evidence only. They cannot
//! satisfy this gate. `hardware_cuda_executed=true` is emitted only after
//! the judge accepts a complete record.

use crate::remote_gpu::{ControlError, ControlErrorCode, Executor, GUEST_DEVICE_PATH};

/// Mesh path the CUDA bytes actually took. Local-direct, reference
/// loopback, and mock are retained so a mis-filed run fails closed
/// instead of being silently dropped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReleasePath {
    GuestMeshProvider,
    MeshDirect,
    MeshRelay,
    LocalDirect,
    ReferenceLoopback,
    Mock,
}

impl ReleasePath {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::GuestMeshProvider => "guest-mesh-provider",
            Self::MeshDirect => "direct",
            Self::MeshRelay => "relay",
            Self::LocalDirect => "local-direct",
            Self::ReferenceLoopback => "reference-loopback",
            Self::Mock => "mock",
        }
    }

    pub fn parse(value: &str) -> Result<Self, ControlError> {
        match value.trim() {
            "guest-mesh-provider" => Ok(Self::GuestMeshProvider),
            "direct" => Ok(Self::MeshDirect),
            "relay" => Ok(Self::MeshRelay),
            "local-direct" => Ok(Self::LocalDirect),
            "reference-loopback" => Ok(Self::ReferenceLoopback),
            "mock" => Ok(Self::Mock),
            other => Err(ControlError::new(
                ControlErrorCode::InvalidRequest,
                format!("unknown NVIDIA release path {other:?}"),
            )),
        }
    }

    fn admits_hardware_pass(self) -> bool {
        matches!(self, Self::GuestMeshProvider)
    }
}

/// How the provider CUDA executor was hosted. In-process reference and
/// mock helpers can never satisfy a hardware PASS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderHelperKind {
    Process,
    InProcessReference,
    Mock,
}

impl ProviderHelperKind {
    pub fn parse(value: &str) -> Result<Self, ControlError> {
        match value.trim() {
            "process" => Ok(Self::Process),
            "in-process-reference" => Ok(Self::InProcessReference),
            "mock" => Ok(Self::Mock),
            other => Err(ControlError::new(
                ControlErrorCode::InvalidRequest,
                format!("unknown NVIDIA provider helper kind {other:?}"),
            )),
        }
    }

    fn admits_hardware_pass(self) -> bool {
        matches!(self, Self::Process)
    }
}

/// Guest-projection candidate consumed from `as-lvf.13.2`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestProjectionCandidate {
    pub device_path: String,
    pub libcuda_path: String,
    pub mesh_device_name: String,
    pub mesh_device_id: String,
}

/// Real CUDA provider candidate consumed from `as-lvf.13.3`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RealProviderCandidate {
    pub executor: Executor,
    pub helper_kind: ProviderHelperKind,
    pub mesh_device_name: String,
    pub mesh_device_id: String,
}

/// One exact hardware-PASS record. Every field is required; the judge
/// never fills gaps from the reference harness or a host-direct kernel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseGateEvidence {
    pub candidate_sha: String,
    pub tree_digest: String,
    pub runner_digest: String,
    pub guest_image_digest: String,
    pub provider_image_digest: String,
    pub guest_container_id: String,
    pub guest: GuestProjectionCandidate,
    pub provider: RealProviderCandidate,
    pub direct_path: bool,
    pub relay_path: bool,
    pub first_gpu_uuid: String,
    pub second_gpu_uuid: String,
    pub driver_version: String,
    pub cuda_runtime_version: String,
    pub guest_output: String,
    pub provider_astd_restarted: bool,
    pub provider_helper_restarted: bool,
    pub guest_restarted: bool,
    pub provider_astd_pid_before: u32,
    pub provider_astd_pid_after: u32,
    pub provider_helper_pid_before: u32,
    pub provider_helper_pid_after: u32,
    pub guest_pid_before: u32,
    pub guest_pid_after: u32,
    pub revoke: bool,
    pub contention: bool,
    pub loss: bool,
    pub version_skew_fresh_session: bool,
    pub version_skew_error: String,
    pub mesh_open_bearer: bool,
    /// Claim from the paid host that CUDA actually ran. The judge still
    /// refuses the claim when any other field is a reference/mock/direct
    /// stand-in.
    pub hardware_cuda_executed: bool,
}

/// Verdict printed by the gate script. `Pass` is the only exit-0 result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReleaseGateVerdict {
    Pass,
    Fail,
}

impl ReleaseGateVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Fail => "fail",
        }
    }
}

/// Judge one evidence record. Returns `Pass` only for the exact guest →
/// projected `/dev/nvidia0`/`libcuda` → two named mesh devices → real
/// NVIDIA helper path, with process-level restarts and the fail-closed
/// lifecycle checks.
pub fn judge_nvidia_release_gate(
    evidence: &ReleaseGateEvidence,
) -> Result<ReleaseGateVerdict, ControlError> {
    refuse_forbidden_stand_ins(evidence)?;
    require_pin(&evidence.candidate_sha, "candidate_sha")?;
    require_pin(&evidence.tree_digest, "tree_digest")?;
    require_digest(&evidence.runner_digest, "runner_digest")?;
    require_digest(&evidence.guest_image_digest, "guest_image_digest")?;
    require_digest(&evidence.provider_image_digest, "provider_image_digest")?;
    require_nonempty(&evidence.guest_container_id, "guest_container_id")?;
    if matches!(
        evidence.guest_container_id.as_str(),
        "mock" | "local" | "host"
    ) {
        return Err(ControlError::new(
            ControlErrorCode::Unavailable,
            "guest_container_id identifies a stand-in, not an Asterism guest/container",
        ));
    }
    require_named_device(&evidence.guest.mesh_device_name, "guest_device_name")?;
    require_named_device(&evidence.provider.mesh_device_name, "provider_device_name")?;
    if evidence.guest.mesh_device_name == evidence.provider.mesh_device_name {
        return Err(ControlError::new(
            ControlErrorCode::InvalidRequest,
            "guest and provider mesh devices must be two distinct named devices",
        ));
    }
    require_mesh_id(&evidence.guest.mesh_device_id, "guest_device_id")?;
    require_mesh_id(&evidence.provider.mesh_device_id, "provider_device_id")?;
    if evidence.guest.device_path != GUEST_DEVICE_PATH {
        return Err(ControlError::new(
            ControlErrorCode::Unavailable,
            format!(
                "guest CUDA application must open {}; got {}",
                GUEST_DEVICE_PATH, evidence.guest.device_path
            ),
        ));
    }
    if evidence.guest.libcuda_path.trim().is_empty()
        || evidence.guest.libcuda_path.contains("mock")
        || evidence.guest.libcuda_path == "/dev/null"
    {
        return Err(ControlError::new(
            ControlErrorCode::Unavailable,
            "guest libcuda path is missing or a mock; projection candidate is required",
        ));
    }
    if evidence.provider.executor != Executor::Cuda {
        return Err(ControlError::new(
            ControlErrorCode::Unavailable,
            "production CUDA executor is required; reference/mock cannot hardware-PASS",
        ));
    }
    if !evidence.provider.helper_kind.admits_hardware_pass() {
        return Err(ControlError::new(
            ControlErrorCode::Unavailable,
            "provider helper must be a restarted process, not an in-process reference",
        ));
    }
    require_gpu_uuid(&evidence.first_gpu_uuid, "first_gpu_uuid")?;
    require_gpu_uuid(&evidence.second_gpu_uuid, "second_gpu_uuid")?;
    if evidence.first_gpu_uuid == evidence.second_gpu_uuid {
        return Err(ControlError::new(
            ControlErrorCode::Unavailable,
            "two-device NVIDIA gate requires distinct GPU UUIDs",
        ));
    }
    require_nonempty(&evidence.driver_version, "driver_version")?;
    require_nonempty(&evidence.cuda_runtime_version, "cuda_runtime_version")?;
    require_nonempty(&evidence.guest_output, "guest_output")?;
    require_flag(evidence.direct_path, "direct mesh path was not exercised")?;
    require_flag(evidence.relay_path, "relay mesh path was not exercised")?;
    require_flag(
        evidence.provider_astd_restarted,
        "provider astd process was not actually restarted",
    )?;
    require_flag(
        evidence.provider_helper_restarted,
        "provider CUDA helper process was not actually restarted",
    )?;
    require_flag(evidence.guest_restarted, "guest was not actually restarted")?;
    require_pid_change(
        evidence.provider_astd_pid_before,
        evidence.provider_astd_pid_after,
        "provider astd",
    )?;
    require_pid_change(
        evidence.provider_helper_pid_before,
        evidence.provider_helper_pid_after,
        "provider helper",
    )?;
    require_pid_change(evidence.guest_pid_before, evidence.guest_pid_after, "guest")?;
    require_flag(evidence.revoke, "revoke was not exercised")?;
    require_flag(evidence.contention, "lease contention was not exercised")?;
    require_flag(evidence.loss, "provider loss was not exercised")?;
    require_flag(
        evidence.version_skew_fresh_session,
        "ABI version skew was not negotiated on a fresh session",
    )?;
    if evidence.version_skew_error != "unsupported_version" {
        return Err(ControlError::new(
            ControlErrorCode::Unavailable,
            "fresh-session skew must fail with UnsupportedVersion, not Conflict",
        ));
    }
    if evidence.mesh_open_bearer {
        return Err(ControlError::new(
            ControlErrorCode::Unauthorized,
            "mesh opening evidence contains a bearer",
        ));
    }
    if !evidence.hardware_cuda_executed {
        return Err(ControlError::new(
            ControlErrorCode::Unavailable,
            "hardware_cuda_executed=false; this is not a NVIDIA hardware PASS",
        ));
    }
    Ok(ReleaseGateVerdict::Pass)
}

fn refuse_forbidden_stand_ins(evidence: &ReleaseGateEvidence) -> Result<(), ControlError> {
    if evidence.provider.executor == Executor::Reference {
        return Err(ControlError::new(
            ControlErrorCode::Unavailable,
            "CPU reference executor cannot satisfy the NVIDIA release gate",
        ));
    }
    Ok(())
}

fn require_pin(value: &str, field: &str) -> Result<(), ControlError> {
    if is_git_oid(value) {
        Ok(())
    } else {
        Err(ControlError::new(
            ControlErrorCode::InvalidRequest,
            format!("{field} must be a 40-character lowercase git object id"),
        ))
    }
}

fn require_digest(value: &str, field: &str) -> Result<(), ControlError> {
    let trimmed = value.trim();
    if trimmed.len() == 71
        && trimmed.starts_with("sha256:")
        && trimmed[7..]
            .chars()
            .all(|ch| matches!(ch, '0'..='9' | 'a'..='f'))
    {
        Ok(())
    } else {
        Err(ControlError::new(
            ControlErrorCode::InvalidRequest,
            format!("{field} must be a content digest, not empty or a placeholder"),
        ))
    }
}

fn require_named_device(value: &str, field: &str) -> Result<(), ControlError> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed == "local" || trimmed == "loopback" || trimmed == "mock" {
        return Err(ControlError::new(
            ControlErrorCode::InvalidRequest,
            format!("{field} must be a named mesh device, not {trimmed:?}"),
        ));
    }
    Ok(())
}

fn require_mesh_id(value: &str, field: &str) -> Result<(), ControlError> {
    if is_git_oid(value) || (value.len() >= 16 && value.chars().all(|ch| ch.is_ascii_hexdigit())) {
        Ok(())
    } else {
        Err(ControlError::new(
            ControlErrorCode::InvalidRequest,
            format!("{field} must be a stable mesh device id"),
        ))
    }
}

fn require_gpu_uuid(value: &str, field: &str) -> Result<(), ControlError> {
    if value.starts_with("GPU-") && value.len() >= 20 {
        Ok(())
    } else {
        Err(ControlError::new(
            ControlErrorCode::InvalidRequest,
            format!("{field} must be an NVIDIA GPU- UUID"),
        ))
    }
}

fn require_nonempty(value: &str, field: &str) -> Result<(), ControlError> {
    if value.trim().is_empty() {
        Err(ControlError::new(
            ControlErrorCode::InvalidRequest,
            format!("{field} is required for a NVIDIA hardware PASS"),
        ))
    } else {
        Ok(())
    }
}

fn require_flag(ok: bool, message: &str) -> Result<(), ControlError> {
    if ok {
        Ok(())
    } else {
        Err(ControlError::new(ControlErrorCode::Unavailable, message))
    }
}

fn require_pid_change(before: u32, after: u32, process: &str) -> Result<(), ControlError> {
    if before == 0 || after == 0 || before == after {
        Err(ControlError::new(
            ControlErrorCode::Unavailable,
            format!("{process} PID did not prove a real restart ({before} -> {after})"),
        ))
    } else {
        Ok(())
    }
}

fn is_git_oid(value: &str) -> bool {
    value.len() == 40 && value.chars().all(|ch| matches!(ch, '0'..='9' | 'a'..='f'))
}

fn take_report_field(
    fields: &mut std::collections::BTreeMap<String, String>,
    key: &str,
) -> Result<String, ControlError> {
    fields.remove(key).ok_or_else(|| {
        ControlError::new(
            ControlErrorCode::InvalidRequest,
            format!("release-gate missing {key}"),
        )
    })
}

fn take_report_flag(
    fields: &mut std::collections::BTreeMap<String, String>,
    key: &str,
) -> Result<bool, ControlError> {
    match take_report_field(fields, key)?.as_str() {
        "true" => Ok(true),
        "false" => Ok(false),
        other => Err(ControlError::new(
            ControlErrorCode::InvalidRequest,
            format!("{key} must be true or false, got {other}"),
        )),
    }
}

fn take_report_pid(
    fields: &mut std::collections::BTreeMap<String, String>,
    key: &str,
) -> Result<u32, ControlError> {
    take_report_field(fields, key)?.parse::<u32>().map_err(|_| {
        ControlError::new(
            ControlErrorCode::InvalidRequest,
            format!("{key} must be a positive process id"),
        )
    })
}

/// Parse `key=value` lines the gate script prints. Unknown keys are
/// errors so a truncated log cannot silently drop a required field.
pub fn parse_release_gate_report(text: &str) -> Result<ReleaseGateEvidence, ControlError> {
    let mut fields = std::collections::BTreeMap::new();
    for (line_no, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with("ok:") {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            return Err(ControlError::new(
                ControlErrorCode::InvalidRequest,
                format!(
                    "release-gate line {}: expected key=value, got {line}",
                    line_no + 1
                ),
            ));
        };
        if fields.insert(key.to_owned(), value.to_owned()).is_some() {
            return Err(ControlError::new(
                ControlErrorCode::InvalidRequest,
                format!("release-gate duplicates key {key}"),
            ));
        }
    }
    let path = ReleasePath::parse(&take_report_field(&mut fields, "path")?)?;
    if !path.admits_hardware_pass() {
        return Err(ControlError::new(
            ControlErrorCode::Unavailable,
            format!(
                "path={} cannot hardware-PASS; require complete guest-mesh-provider path",
                path.as_str()
            ),
        ));
    }
    let executor = match take_report_field(&mut fields, "executor")?.as_str() {
        "cuda" => Executor::Cuda,
        "reference" => Executor::Reference,
        other => {
            return Err(ControlError::new(
                ControlErrorCode::InvalidRequest,
                format!("unknown executor {other}"),
            ))
        }
    };
    let helper_kind =
        ProviderHelperKind::parse(&take_report_field(&mut fields, "provider_helper_kind")?)?;
    let evidence = ReleaseGateEvidence {
        candidate_sha: take_report_field(&mut fields, "candidate_sha")?,
        tree_digest: take_report_field(&mut fields, "tree_digest")?,
        runner_digest: take_report_field(&mut fields, "runner_digest")?,
        guest_image_digest: take_report_field(&mut fields, "guest_image_digest")?,
        provider_image_digest: take_report_field(&mut fields, "provider_image_digest")?,
        guest_container_id: take_report_field(&mut fields, "guest_container_id")?,
        guest: GuestProjectionCandidate {
            device_path: take_report_field(&mut fields, "guest_path")?,
            libcuda_path: take_report_field(&mut fields, "libcuda_path")?,
            mesh_device_name: take_report_field(&mut fields, "guest_device_name")?,
            mesh_device_id: take_report_field(&mut fields, "guest_device_id")?,
        },
        provider: RealProviderCandidate {
            executor,
            helper_kind,
            mesh_device_name: take_report_field(&mut fields, "provider_device_name")?,
            mesh_device_id: take_report_field(&mut fields, "provider_device_id")?,
        },
        direct_path: take_report_flag(&mut fields, "direct_path")?
            || path == ReleasePath::MeshDirect,
        relay_path: take_report_flag(&mut fields, "relay_path")? || path == ReleasePath::MeshRelay,
        first_gpu_uuid: take_report_field(&mut fields, "first_gpu_uuid")?,
        second_gpu_uuid: take_report_field(&mut fields, "second_gpu_uuid")?,
        driver_version: take_report_field(&mut fields, "driver_version")?,
        cuda_runtime_version: take_report_field(&mut fields, "cuda_runtime_version")?,
        guest_output: take_report_field(&mut fields, "guest_output")?,
        provider_astd_restarted: take_report_flag(&mut fields, "provider_astd_restarted")?,
        provider_helper_restarted: take_report_flag(&mut fields, "provider_helper_restarted")?,
        guest_restarted: take_report_flag(&mut fields, "guest_restarted")?,
        provider_astd_pid_before: take_report_pid(&mut fields, "provider_astd_pid_before")?,
        provider_astd_pid_after: take_report_pid(&mut fields, "provider_astd_pid_after")?,
        provider_helper_pid_before: take_report_pid(&mut fields, "provider_helper_pid_before")?,
        provider_helper_pid_after: take_report_pid(&mut fields, "provider_helper_pid_after")?,
        guest_pid_before: take_report_pid(&mut fields, "guest_pid_before")?,
        guest_pid_after: take_report_pid(&mut fields, "guest_pid_after")?,
        revoke: take_report_flag(&mut fields, "revoke")?,
        contention: take_report_flag(&mut fields, "contention")?,
        loss: take_report_flag(&mut fields, "loss")?,
        version_skew_fresh_session: take_report_flag(&mut fields, "version_skew_fresh_session")?,
        version_skew_error: take_report_field(&mut fields, "version_skew_error")?,
        mesh_open_bearer: take_report_flag(&mut fields, "mesh_open_bearer")?,
        hardware_cuda_executed: take_report_flag(&mut fields, "hardware_cuda_executed")?,
    };
    if let Some(key) = fields.keys().next() {
        return Err(ControlError::new(
            ControlErrorCode::InvalidRequest,
            format!("release-gate contains unknown field {key}"),
        ));
    }
    Ok(evidence)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn complete_record() -> ReleaseGateEvidence {
        ReleaseGateEvidence {
            candidate_sha: "f656f017de3a0b34ce710350ee5e55fb2cb2e593".into(),
            tree_digest: "82f7ddea827bb629b73e19a771abd40641b2cbd2".into(),
            runner_digest:
                "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".into(),
            guest_image_digest:
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
            provider_image_digest:
                "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into(),
            guest_container_id: "asterism-guest-1234".into(),
            guest: GuestProjectionCandidate {
                device_path: GUEST_DEVICE_PATH.into(),
                libcuda_path: "/usr/lib/asterism/libcuda.so.1".into(),
                mesh_device_name: "guest-gpu".into(),
                mesh_device_id: "aa".repeat(20),
            },
            provider: RealProviderCandidate {
                executor: Executor::Cuda,
                helper_kind: ProviderHelperKind::Process,
                mesh_device_name: "provider-gpu".into(),
                mesh_device_id: "bb".repeat(20),
            },
            direct_path: true,
            relay_path: true,
            first_gpu_uuid: "GPU-aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa".into(),
            second_gpu_uuid: "GPU-bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb".into(),
            driver_version: "550.54.15".into(),
            cuda_runtime_version: "12.4".into(),
            guest_output: "6.0,2.0,6.0".into(),
            provider_astd_restarted: true,
            provider_helper_restarted: true,
            guest_restarted: true,
            provider_astd_pid_before: 101,
            provider_astd_pid_after: 102,
            provider_helper_pid_before: 201,
            provider_helper_pid_after: 202,
            guest_pid_before: 301,
            guest_pid_after: 302,
            revoke: true,
            contention: true,
            loss: true,
            version_skew_fresh_session: true,
            version_skew_error: "unsupported_version".into(),
            mesh_open_bearer: false,
            hardware_cuda_executed: true,
        }
    }

    #[test]
    fn complete_real_path_is_a_hardware_pass() {
        assert_eq!(
            judge_nvidia_release_gate(&complete_record()).unwrap(),
            ReleaseGateVerdict::Pass
        );
    }

    #[test]
    fn reference_executor_cannot_hardware_pass() {
        let mut evidence = complete_record();
        evidence.provider.executor = Executor::Reference;
        evidence.hardware_cuda_executed = true;
        let error = judge_nvidia_release_gate(&evidence).unwrap_err();
        assert_eq!(error.code, ControlErrorCode::Unavailable);
        assert!(error.message.contains("reference"));
    }

    #[test]
    fn in_process_reference_helper_cannot_hardware_pass() {
        let mut evidence = complete_record();
        evidence.provider.helper_kind = ProviderHelperKind::InProcessReference;
        let error = judge_nvidia_release_gate(&evidence).unwrap_err();
        assert!(error.message.contains("in-process"));
    }

    #[test]
    fn local_direct_path_cannot_hardware_pass() {
        let error = parse_release_gate_report("path=local-direct\nexecutor=cuda\n").unwrap_err();
        assert!(
            error.message.contains("local-direct")
                || error.message.contains("cannot hardware-PASS")
        );
    }

    #[test]
    fn mock_path_cannot_hardware_pass() {
        let error = parse_release_gate_report("path=mock\nexecutor=cuda\n").unwrap_err();
        assert!(error.message.contains("mock") || error.message.contains("cannot hardware-PASS"));
    }

    #[test]
    fn missing_process_restart_cannot_hardware_pass() {
        let mut evidence = complete_record();
        evidence.provider_astd_restarted = false;
        let error = judge_nvidia_release_gate(&evidence).unwrap_err();
        assert!(error.message.contains("astd"));
    }

    #[test]
    fn version_skew_not_on_fresh_session_cannot_hardware_pass() {
        let mut evidence = complete_record();
        evidence.version_skew_fresh_session = false;
        let error = judge_nvidia_release_gate(&evidence).unwrap_err();
        assert!(error.message.contains("fresh session"));
    }

    #[test]
    fn conflict_is_not_version_skew_evidence() {
        let mut evidence = complete_record();
        evidence.version_skew_error = "conflict".into();
        let error = judge_nvidia_release_gate(&evidence).unwrap_err();
        assert!(error.message.contains("UnsupportedVersion"));
    }

    #[test]
    fn unchanged_process_pid_cannot_prove_restart() {
        let mut evidence = complete_record();
        evidence.provider_helper_pid_after = evidence.provider_helper_pid_before;
        let error = judge_nvidia_release_gate(&evidence).unwrap_err();
        assert!(error.message.contains("PID"));
    }

    #[test]
    fn bearer_in_mesh_open_cannot_hardware_pass() {
        let mut evidence = complete_record();
        evidence.mesh_open_bearer = true;
        let error = judge_nvidia_release_gate(&evidence).unwrap_err();
        assert_eq!(error.code, ControlErrorCode::Unauthorized);
    }

    #[test]
    fn one_named_device_cannot_hardware_pass() {
        let mut evidence = complete_record();
        evidence.provider.mesh_device_name = evidence.guest.mesh_device_name.clone();
        let error = judge_nvidia_release_gate(&evidence).unwrap_err();
        assert!(error.message.contains("two distinct"));
    }

    #[test]
    fn hardware_false_is_not_a_pass() {
        let mut evidence = complete_record();
        evidence.hardware_cuda_executed = false;
        let error = judge_nvidia_release_gate(&evidence).unwrap_err();
        assert!(error.message.contains("hardware_cuda_executed=false"));
    }
}
