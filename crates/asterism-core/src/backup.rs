//! Portable, content-addressed instance backups.
//!
//! A backup is a directory, not an opaque archive. `manifest.json` is the
//! redacted instance definition and a deterministic recipe for rebuilding
//! each durable file; `chunks/` is a BLAKE3-addressed store shared by every
//! export written to that directory. Re-running an export therefore resumes
//! at the first missing chunk, and two snapshots containing the same bytes
//! store those bytes once.
//!
//! Host plumbing and credentials never enter the recipe. Seeds, agent keys,
//! process handles, sockets, logs and the egress directory are deliberately
//! absent. Attached volumes, secrets and GPUs survive only as public rebind
//! requirements: restore never silently reconnects an external part from a
//! different orbit.

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::durable;
use crate::hv::{DiskFormat, Machine};
use crate::instance::{Instance, Status, VolumeKind};
use crate::remote_gpu::GpuAttachment;
use crate::secret::Placement;

pub const LEGACY_FORMAT_VERSION: u32 = 1;
pub const FORMAT_VERSION: u32 = 2;
pub const CHUNK_SIZE: usize = 4 * 1024 * 1024;
const MANIFEST: &str = "manifest.json";
const MANIFEST_DIGEST: &str = "manifest.blake3";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImageProvenance {
    pub reference: String,
    pub content: String,
    pub size: u64,
    pub kind: String,
    pub source: String,
    #[serde(default)]
    pub derived_from: Vec<String>,
}

/// Registry-platform identity for an OCI rootfs. Architecture uses OCI's
/// vocabulary (`arm64`, `amd64`), not Rust's host triples.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuestPlatform {
    pub os: String,
    pub architecture: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiskArtifact {
    pub path: String,
    pub format: DiskFormat,
}

/// The immutable OCI recipe needed to build a fresh rootfs for another
/// architecture. The mutable root disk is deliberately not part of it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OciMaterialization {
    pub reference: String,
    pub platform: GuestPlatform,
    pub manifest_digest: String,
    pub config_digest: String,
    #[serde(default)]
    pub layer_digests: Vec<String>,
}

/// Compatibility facts for the mutable machine state carried by a v2
/// backup. These duplicate selected fields from `Instance` on purpose: an
/// importer validates the recipe against the redacted row instead of
/// inferring disk formats from extensions or a CPU architecture from
/// `machine.cpu=host`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Materialization {
    pub platform: GuestPlatform,
    pub machine: Machine,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_disk: Option<DiskArtifact>,
    #[serde(default)]
    pub snapshots: Vec<DiskArtifact>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oci: Option<OciMaterialization>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VolumeRebind {
    pub kind: VolumeKind,
    pub path: String,
    pub source_device: String,
    pub mount_point: Option<String>,
    pub size_bytes: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretRebind {
    pub secret: String,
    pub authority: String,
    pub placement: Placement,
    pub env: String,
    pub source_device: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RebindRequirements {
    #[serde(default)]
    pub volumes: Vec<VolumeRebind>,
    #[serde(default)]
    pub secrets: Vec<SecretRebind>,
    /// Token-free description of the remote GPU that must be placed and
    /// leased again in the destination orbit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gpu: Option<GpuAttachment>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Chunk {
    /// A logical range of zeroes. Restore seeks over it, preserving sparsity.
    Zero { len: u32 },
    /// Bytes held in `chunks/<first two hex>/<remaining hex>`.
    Data { digest: String, len: u32 },
}

impl Chunk {
    fn len(&self) -> u64 {
        match self {
            Chunk::Zero { len } | Chunk::Data { len, .. } => u64::from(*len),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupFile {
    pub path: String,
    pub len: u64,
    pub mode: u32,
    /// Digest of the complete logical file, including zero ranges.
    pub digest: String,
    pub chunks: Vec<Chunk>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub version: u32,
    pub created_at: u64,
    /// Orbit-independent identity and definition. Runtime and external-part
    /// fields have been scrubbed; `id`, `name`, shape, machine and policy are
    /// preserved verbatim.
    pub instance: Instance,
    pub image: Option<ImageProvenance>,
    /// Absent on v1 bundles. Such bundles remain inspectable and may be
    /// restored byte-for-byte to their recorded machine, but cannot request
    /// cross-backend or cross-architecture materialization.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub materialization: Option<Materialization>,
    pub files: Vec<BackupFile>,
    pub rebind: RebindRequirements,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportReport {
    pub destination: String,
    pub files: usize,
    pub logical_bytes: u64,
    pub data_chunks: usize,
    pub reused_chunks: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RestoreReport {
    pub instance: String,
    pub id: String,
    pub files: usize,
    pub logical_bytes: u64,
    pub rebind: RebindRequirements,
    #[serde(default)]
    pub materialization: RestoreDisposition,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_architecture: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_architecture: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_backend: Option<String>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RestoreDisposition {
    #[default]
    ByteExact,
    Qcow2ToRaw,
    OciRematerialized,
}

/// A target selected and probed by the daemon before restore staging begins.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestoreTarget {
    pub architecture: String,
    pub machine: Machine,
    pub disk_formats: Vec<DiskFormat>,
    pub rematerialize_oci: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestorePlan {
    pub disposition: RestoreDisposition,
    pub source_architecture: Option<String>,
    pub target: RestoreTarget,
    drop_firmware_state: bool,
}

/// Convert a verified provenance record into the portable representation.
pub fn image_provenance(instance: &Instance) -> Result<Option<ImageProvenance>> {
    let Some(reference) = instance.image.as_deref() else {
        return Ok(None);
    };
    let resolved = crate::image::resolve(reference)
        .with_context(|| format!("resolving image provenance for {reference:?}"))?;
    let record = resolved
        .verified_provenance(crate::verify::Depth::Full)
        .with_context(|| format!("verifying image provenance for {reference:?}"))?;
    Ok(Some(ImageProvenance {
        reference: reference.to_owned(),
        content: record.content.to_string(),
        size: record.size,
        kind: record.kind,
        source: record.source,
        derived_from: record.derived_from,
    }))
}

/// Export a stopped instance into `destination`.
pub fn export(
    instance: &Instance,
    instance_dir: &Path,
    destination: &Path,
    image: Option<ImageProvenance>,
) -> Result<ExportReport> {
    if instance.status == Status::Running {
        bail!(
            "instance {:?} is running — stop it before exporting a consistent disk",
            instance.name
        );
    }
    std::fs::create_dir_all(destination)
        .with_context(|| format!("creating backup directory {}", destination.display()))?;

    let mut paths = durable_files(instance_dir)?;
    paths.sort();
    let mut files = Vec::with_capacity(paths.len());
    let mut report = ExportReport {
        destination: destination.display().to_string(),
        files: paths.len(),
        logical_bytes: 0,
        data_chunks: 0,
        reused_chunks: 0,
    };
    for path in paths {
        let relative = path
            .strip_prefix(instance_dir)
            .expect("collected below instance root");
        let (file, reused) = export_file(&path, relative, destination)?;
        report.logical_bytes += file.len;
        report.data_chunks += file
            .chunks
            .iter()
            .filter(|chunk| matches!(chunk, Chunk::Data { .. }))
            .count();
        report.reused_chunks += reused;
        files.push(file);
    }

    let mut portable = instance.clone();
    let rebind = requirements(&portable);
    portable.cpu_device.clear();
    portable.status = if portable.status == Status::Defined {
        Status::Defined
    } else {
        Status::Stopped
    };
    portable.handle = None;
    portable.conflict = None;
    portable.moving = None;
    portable.seed_device = None;
    portable.volumes.clear();
    portable.secrets.clear();
    portable.stranded.clear();
    portable.gpu = None;

    let materialization = materialization(&portable, image.as_ref(), &files)?;
    let manifest = Manifest {
        version: FORMAT_VERSION,
        created_at: crate::instance::now_unix(),
        instance: portable,
        image,
        materialization: Some(materialization),
        files,
        rebind,
    };
    let bytes = serde_json::to_vec_pretty(&manifest).context("serialising backup manifest")?;
    durable::commit(&destination.join(MANIFEST), &bytes)?;
    durable::commit(
        &destination.join(MANIFEST_DIGEST),
        format!("{}\n", blake3::hash(&bytes).to_hex()).as_bytes(),
    )?;
    Ok(report)
}

/// Read and integrity-check the redacted manifest. Chunk bytes are checked by
/// [`verify`], allowing inspection to stay cheap while restore remains strict.
pub fn inspect(source: &Path) -> Result<Manifest> {
    let bytes = std::fs::read(source.join(MANIFEST))
        .with_context(|| format!("reading {}", source.join(MANIFEST).display()))?;
    let recorded = std::fs::read_to_string(source.join(MANIFEST_DIGEST))
        .with_context(|| format!("reading {}", source.join(MANIFEST_DIGEST).display()))?;
    let got = blake3::hash(&bytes).to_hex().to_string();
    if recorded.trim() != got {
        bail!(
            "backup manifest is corrupt: expected {}, got {got}",
            recorded.trim()
        );
    }
    let manifest: Manifest = serde_json::from_slice(&bytes).context("reading backup manifest")?;
    if !matches!(manifest.version, LEGACY_FORMAT_VERSION | FORMAT_VERSION) {
        bail!(
            "backup format {} is not supported by this build (supports {} and {})",
            manifest.version,
            LEGACY_FORMAT_VERSION,
            FORMAT_VERSION
        );
    }
    validate_manifest(&manifest)?;
    Ok(manifest)
}

/// Verify every content address referenced by a backup.
pub fn verify(source: &Path) -> Result<Manifest> {
    let manifest = inspect(source)?;
    for file in &manifest.files {
        for chunk in &file.chunks {
            let Chunk::Data { digest, len } = chunk else {
                continue;
            };
            let path = chunk_path(source, digest)?;
            let bytes =
                std::fs::read(&path).with_context(|| format!("reading backup chunk {digest}"))?;
            if bytes.len() != *len as usize || blake3::hash(&bytes).to_hex().as_str() != digest {
                bail!("backup chunk {digest} is corrupt");
            }
        }
    }
    Ok(manifest)
}

/// Rebuild all durable files under a non-live staging directory. Existing
/// complete files and valid partial chunk prefixes are reused, so retrying an
/// interrupted restore resumes rather than starting over.
pub fn restore_to(source: &Path, staging: &Path, name: &str) -> Result<(Instance, RestoreReport)> {
    let manifest = verify(source)?;
    let target = RestoreTarget {
        architecture: manifest
            .materialization
            .as_ref()
            .map(|metadata| metadata.platform.architecture.clone())
            .unwrap_or_default(),
        machine: manifest.instance.machine.clone(),
        disk_formats: manifest
            .materialization
            .as_ref()
            .map(all_disk_formats)
            .unwrap_or_default(),
        rematerialize_oci: false,
    };
    let plan = plan_restore(&manifest, target)?;
    restore_verified_to(source, staging, name, manifest, &plan)
}

/// Decide whether a verified v2 bundle can become a machine on `target`.
/// This function is pure: callers run it before pulling an OCI image,
/// creating a staging directory, or mutating the registry.
pub fn plan_restore(manifest: &Manifest, target: RestoreTarget) -> Result<RestorePlan> {
    let Some(metadata) = manifest.materialization.as_ref() else {
        if target.rematerialize_oci || target.machine != manifest.instance.machine {
            bail!(
                "backup format 1 has no architecture or disk materialization metadata; it can only be restored byte-for-byte to its recorded {} backend",
                manifest.instance.machine.backend
            );
        }
        return Ok(RestorePlan {
            disposition: RestoreDisposition::ByteExact,
            source_architecture: None,
            target,
            drop_firmware_state: false,
        });
    };

    let source_architecture = metadata.platform.architecture.clone();
    let architecture_changed = source_architecture != target.architecture;
    if architecture_changed || target.rematerialize_oci {
        if !target.rematerialize_oci {
            bail!(
                "this backup contains a mutable {} root disk and cannot be restored directly on {}; retry with explicit OCI re-materialization",
                source_architecture,
                target.architecture
            );
        }
        if manifest.instance.image_kind != crate::hv::ImageKind::OciRootfs || metadata.oci.is_none()
        {
            bail!(
                "only an OCI-sourced instance can be re-materialized; this backup has no complete OCI manifest/platform recipe"
            );
        }
        if architecture_changed {
            let oci = metadata.oci.as_ref().expect("checked above");
            let immutable_index = crate::oci::parse(&oci.reference).is_some_and(|reference| {
                matches!(reference.version, crate::oci::Version::Digest(_))
            });
            if !immutable_index {
                bail!(
                    "cross-architecture OCI re-materialization requires an immutable @sha256:... index reference; {:?} could move to unrelated image bytes",
                    oci.reference
                );
            }
        }
        return Ok(RestorePlan {
            disposition: RestoreDisposition::OciRematerialized,
            source_architecture: Some(source_architecture),
            target,
            drop_firmware_state: true,
        });
    }

    let artifacts = metadata
        .root_disk
        .iter()
        .chain(metadata.snapshots.iter())
        .collect::<Vec<_>>();
    let unsupported = artifacts
        .iter()
        .filter(|artifact| !target.disk_formats.contains(&artifact.format))
        .collect::<Vec<_>>();
    let disposition = if unsupported.is_empty() {
        RestoreDisposition::ByteExact
    } else if target.disk_formats.contains(&DiskFormat::Raw)
        && unsupported
            .iter()
            .all(|artifact| artifact.format == DiskFormat::Qcow2)
    {
        RestoreDisposition::Qcow2ToRaw
    } else {
        let artifact = unsupported[0];
        bail!(
            "the target {} backend cannot restore {} as {}; refusing to relabel or mutate backup bytes",
            target.machine.backend,
            artifact.path,
            artifact.format
        );
    };
    Ok(RestorePlan {
        disposition,
        source_architecture: Some(source_architecture),
        drop_firmware_state: target.machine.backend != metadata.machine.backend,
        target,
    })
}

/// Restore according to a plan made against this bundle's verified manifest.
pub fn restore_to_target(
    source: &Path,
    staging: &Path,
    name: &str,
    plan: &RestorePlan,
) -> Result<(Instance, RestoreReport)> {
    let manifest = verify(source)?;
    // Recompute the decision from the freshly verified manifest. A caller
    // cannot inspect one bundle, swap the directory, and apply its plan to
    // another set of bytes.
    let checked = plan_restore(&manifest, plan.target.clone())?;
    if &checked != plan {
        bail!("backup materialization plan changed after verification");
    }
    restore_verified_to(source, staging, name, manifest, plan)
}

fn restore_verified_to(
    source: &Path,
    staging: &Path,
    name: &str,
    manifest: Manifest,
    plan: &RestorePlan,
) -> Result<(Instance, RestoreReport)> {
    crate::registry::check_name(name)?;
    std::fs::create_dir_all(staging)
        .with_context(|| format!("creating restore staging directory {}", staging.display()))?;
    if plan.disposition != RestoreDisposition::OciRematerialized {
        for file in &manifest.files {
            if plan.drop_firmware_state && is_firmware_state(&file.path) {
                continue;
            }
            restore_file(source, staging, file)?;
            if plan.disposition == RestoreDisposition::Qcow2ToRaw
                && disk_format(&file.path) == Some(DiskFormat::Qcow2)
                && !plan.target.disk_formats.contains(&DiskFormat::Qcow2)
            {
                convert_restored_qcow2(staging, &file.path)?;
            }
        }
    }
    let mut instance = manifest.instance.clone();
    instance.name = name.to_owned();
    instance.machine = plan.target.machine.clone();
    instance.status = if plan.disposition == RestoreDisposition::OciRematerialized
        || (instance.status == Status::Defined && manifest.files.is_empty())
    {
        Status::Defined
    } else {
        Status::Stopped
    };
    instance.handle = None;
    instance.cpu_device.clear();
    let restored_files = manifest
        .files
        .iter()
        .filter(|file| {
            plan.disposition != RestoreDisposition::OciRematerialized
                && !(plan.drop_firmware_state && is_firmware_state(&file.path))
        })
        .collect::<Vec<_>>();
    let report = RestoreReport {
        instance: name.to_owned(),
        id: instance.id.clone(),
        files: restored_files.len(),
        logical_bytes: restored_files.iter().map(|file| file.len).sum(),
        rebind: manifest.rebind,
        materialization: plan.disposition,
        source_architecture: plan.source_architecture.clone(),
        target_architecture: (!plan.target.architecture.is_empty())
            .then(|| plan.target.architecture.clone()),
        target_backend: Some(plan.target.machine.backend.clone()),
    };
    durable::commit_json(&staging.join(".restore-receipt.json"), &report)?;
    Ok((instance, report))
}

fn materialization(
    instance: &Instance,
    image: Option<&ImageProvenance>,
    files: &[BackupFile],
) -> Result<Materialization> {
    let mut root_disk = None;
    let mut snapshots = Vec::new();
    let mut snapshot_tags = std::collections::HashSet::new();
    for file in files {
        let Some(format) = disk_format(&file.path) else {
            continue;
        };
        let artifact = DiskArtifact {
            path: file.path.clone(),
            format,
        };
        if file.path.starts_with("disk.") {
            if root_disk.replace(artifact).is_some() {
                bail!(
                    "instance {:?} has more than one root disk format; refusing an ambiguous backup",
                    instance.name
                );
            }
        } else if let Some(tag) = snapshot_tag(&file.path) {
            if !snapshot_tags.insert(tag.to_owned()) {
                bail!(
                    "instance {:?} has snapshot tag {tag:?} in more than one disk format",
                    instance.name
                );
            }
            snapshots.push(artifact);
        }
    }
    snapshots.sort_by(|left, right| left.path.cmp(&right.path));

    let platform = GuestPlatform {
        os: "linux".into(),
        architecture: target_architecture().into(),
    };
    let oci = if instance.image_kind == crate::hv::ImageKind::OciRootfs {
        let provenance = image.context("an OCI backup has no verified image provenance")?;
        if provenance.kind != "oci-rootfs" {
            bail!(
                "OCI instance provenance says {:?} instead of oci-rootfs",
                provenance.kind
            );
        }
        let (manifest_digest, rest) = provenance
            .derived_from
            .split_first()
            .context("OCI provenance names no selected manifest digest")?;
        let (config_digest, layer_digests) = rest
            .split_first()
            .context("OCI provenance names no image config digest")?;
        Some(OciMaterialization {
            reference: provenance.reference.clone(),
            platform: platform.clone(),
            manifest_digest: manifest_digest.clone(),
            config_digest: config_digest.clone(),
            layer_digests: layer_digests.to_vec(),
        })
    } else {
        None
    };
    Ok(Materialization {
        platform,
        machine: instance.machine.clone(),
        root_disk,
        snapshots,
        oci,
    })
}

pub fn target_architecture() -> &'static str {
    match crate::image::host_arch() {
        "aarch64" => "arm64",
        "x86_64" => "amd64",
        other => other,
    }
}

fn all_disk_formats(metadata: &Materialization) -> Vec<DiskFormat> {
    let mut formats = metadata
        .root_disk
        .iter()
        .chain(metadata.snapshots.iter())
        .map(|artifact| artifact.format)
        .collect::<Vec<_>>();
    formats.sort_by_key(|format| format.as_str());
    formats.dedup();
    formats
}

fn disk_format(path: &str) -> Option<DiskFormat> {
    let extension = Path::new(path).extension()?.to_str()?;
    match extension {
        "raw" => Some(DiskFormat::Raw),
        "qcow2" => Some(DiskFormat::Qcow2),
        "asif" => Some(DiskFormat::Asif),
        "vhdx" => Some(DiskFormat::Vhdx),
        _ => None,
    }
}

fn snapshot_tag(path: &str) -> Option<&str> {
    let rest = path.strip_prefix("snapshots/")?;
    rest.rsplit_once('.').map(|(tag, _)| tag)
}

fn is_firmware_state(path: &str) -> bool {
    matches!(path, "efi-vars.fd" | "efi-vars.bin")
}

fn convert_restored_qcow2(staging: &Path, relative: &str) -> Result<()> {
    let source = staging.join(checked_relative(relative)?);
    let destination = source.with_extension("raw");
    if destination.exists() {
        bail!(
            "{} already exists beside {}; refusing to overwrite restored bytes",
            destination.display(),
            source.display()
        );
    }
    let part = destination.with_extension("raw.materialize-part");
    let _ = std::fs::remove_file(&part);
    if let Err(error) = crate::qcow2::materialize(&source, &part) {
        let _ = std::fs::remove_file(&part);
        return Err(error).with_context(|| {
            format!(
                "materializing restored {} as raw for the target backend",
                source.display()
            )
        });
    }
    durable::publish_file(&part, &destination)?;
    std::fs::remove_file(&source)?;
    Ok(())
}

fn requirements(instance: &Instance) -> RebindRequirements {
    RebindRequirements {
        volumes: instance
            .volumes
            .iter()
            .map(|volume| VolumeRebind {
                kind: volume.kind,
                path: volume.path.clone(),
                source_device: volume.host.clone(),
                mount_point: volume.mount_point.clone(),
                size_bytes: volume.size_bytes,
            })
            .collect(),
        secrets: instance
            .secrets
            .iter()
            .map(|secret| SecretRebind {
                secret: secret.secret.clone(),
                authority: secret.authority.clone(),
                placement: secret.placement.clone(),
                env: secret.env.clone(),
                source_device: secret.source_device.clone(),
            })
            .collect(),
        gpu: instance.gpu.clone(),
    }
}

/// Only durable guest state, plus the instance's own cost ledger. The
/// explicit allowlist is also the redaction boundary: a future sidecar does
/// not become portable merely by appearing, and every addition to this list
/// is a decision made here about what a backup is allowed to carry.
fn durable_files(instance_dir: &Path) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    for name in [
        "disk.raw",
        "disk.qcow2",
        "disk.vhdx",
        "efi-vars.fd",
        "efi-vars.bin",
    ] {
        let path = instance_dir.join(name);
        if path.is_file() {
            files.push(path);
        }
    }
    // The cost ledger. It is not guest state — nothing inside the guest
    // wrote it — but it is the only record of what that guest spent, and a
    // backup that dropped it would silently reset an agent's accounting
    // every time somebody moved it between machines. Counters and model
    // names only: `ledger` has a test that no body byte can reach a line.
    let cost = instance_dir.join("cost");
    if let Ok(entries) = std::fs::read_dir(&cost) {
        let mut days = Vec::new();
        for entry in entries {
            let path = entry?.path();
            if path.is_file() && path.extension().is_some_and(|ext| ext == "jsonl") {
                days.push(path);
            }
        }
        // Deterministic order, so re-exporting an unchanged instance
        // produces an unchanged manifest.
        days.sort();
        files.extend(days);
    }
    let snapshots = instance_dir.join("snapshots");
    if let Ok(entries) = std::fs::read_dir(&snapshots) {
        for entry in entries {
            let entry = entry?;
            let path = entry.path();
            if path.is_file()
                && path
                    .extension()
                    .and_then(|ext| ext.to_str())
                    .is_some_and(|ext| matches!(ext, "raw" | "qcow2" | "vhdx"))
            {
                files.push(path);
            }
        }
    }
    Ok(files)
}

fn export_file(path: &Path, relative: &Path, destination: &Path) -> Result<(BackupFile, usize)> {
    if let Some(declared) = relative.to_str().and_then(disk_format) {
        if matches!(declared, DiskFormat::Raw | DiskFormat::Qcow2) {
            let detected = crate::image::detect_format(path)?;
            if detected != declared {
                bail!(
                    "{} is named as a {declared} disk but contains {detected} bytes",
                    path.display()
                );
            }
        }
    }
    let mut input = File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let meta = input.metadata()?;
    let mut whole = blake3::Hasher::new();
    let mut chunks = Vec::new();
    let mut buffer = vec![0u8; CHUNK_SIZE];
    let mut reused = 0;
    loop {
        let read = input.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        let bytes = &buffer[..read];
        whole.update(bytes);
        if bytes.iter().all(|byte| *byte == 0) {
            chunks.push(Chunk::Zero { len: read as u32 });
            continue;
        }
        let digest = blake3::hash(bytes).to_hex().to_string();
        if put_chunk(destination, &digest, bytes)? {
            reused += 1;
        }
        chunks.push(Chunk::Data {
            digest,
            len: read as u32,
        });
    }
    Ok((
        BackupFile {
            path: portable_path(relative)?,
            len: meta.len(),
            mode: mode(&meta),
            digest: whole.finalize().to_hex().to_string(),
            chunks,
        },
        reused,
    ))
}

fn put_chunk(root: &Path, digest: &str, bytes: &[u8]) -> Result<bool> {
    let path = chunk_path(root, digest)?;
    if let Ok(existing) = std::fs::read(&path) {
        if existing.len() == bytes.len() && blake3::hash(&existing).to_hex().as_str() == digest {
            return Ok(true);
        }
        bail!("existing backup chunk {digest} is corrupt; refusing to replace evidence");
    }
    let parent = path.parent().expect("chunk path has parent");
    std::fs::create_dir_all(parent)?;
    let part = path.with_extension("part");
    let _ = std::fs::remove_file(&part);
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&part)?;
    output.write_all(bytes)?;
    output.sync_all()?;
    std::fs::rename(&part, &path)?;
    Ok(false)
}

fn restore_file(source: &Path, staging: &Path, file: &BackupFile) -> Result<()> {
    let relative = checked_relative(&file.path)?;
    let destination = staging.join(relative);
    if complete_file(&destination, file)? {
        return Ok(());
    }
    if let Some(parent) = destination.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let part = destination.with_extension(format!(
        "{}restore-part",
        destination
            .extension()
            .map(|ext| format!("{}.", ext.to_string_lossy()))
            .unwrap_or_default()
    ));
    let mut output = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&part)?;
    let resume = valid_prefix(&mut output, source, file).unwrap_or(0);
    if resume == 0 {
        output.set_len(0)?;
    }
    output.seek(SeekFrom::Start(resume))?;
    let mut offset = 0u64;
    for chunk in &file.chunks {
        let end = offset + chunk.len();
        if end <= resume {
            offset = end;
            continue;
        }
        match chunk {
            Chunk::Zero { len } => {
                output.seek(SeekFrom::Current(i64::from(*len)))?;
            }
            Chunk::Data { digest, .. } => {
                let bytes = std::fs::read(chunk_path(source, digest)?)?;
                output.write_all(&bytes)?;
            }
        };
        offset = end;
    }
    output.set_len(file.len)?;
    output.sync_all()?;
    if !complete_file(&part, file)? {
        bail!("restored file {:?} failed its content digest", file.path);
    }
    set_mode(&part, file.mode)?;
    durable::publish_file(&part, &destination)?;
    Ok(())
}

fn valid_prefix(output: &mut File, source: &Path, file: &BackupFile) -> Result<u64> {
    let have = output.metadata()?.len();
    let mut boundary = 0u64;
    for chunk in &file.chunks {
        if boundary + chunk.len() > have {
            break;
        }
        let mut got = vec![0u8; chunk.len() as usize];
        output.seek(SeekFrom::Start(boundary))?;
        output.read_exact(&mut got)?;
        let valid = match chunk {
            Chunk::Zero { .. } => got.iter().all(|byte| *byte == 0),
            Chunk::Data { digest, .. } => {
                blake3::hash(&got).to_hex().as_str() == digest
                    && std::fs::metadata(chunk_path(source, digest)?)?.len() == chunk.len()
            }
        };
        if !valid {
            return Ok(0);
        }
        boundary += chunk.len();
    }
    Ok(boundary)
}

fn complete_file(path: &Path, file: &BackupFile) -> Result<bool> {
    let Ok(meta) = std::fs::metadata(path) else {
        return Ok(false);
    };
    if meta.len() != file.len {
        return Ok(false);
    }
    let mut input = File::open(path)?;
    let mut hash = blake3::Hasher::new();
    std::io::copy(&mut input, &mut hash_writer(&mut hash))?;
    Ok(hash.finalize().to_hex().as_str() == file.digest)
}

/// `std::io::copy` adapter for BLAKE3 without a second full-file allocation.
fn hash_writer(hash: &mut blake3::Hasher) -> impl Write + '_ {
    struct HashWriter<'a>(&'a mut blake3::Hasher);
    impl Write for HashWriter<'_> {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.update(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    HashWriter(hash)
}

fn validate_manifest(manifest: &Manifest) -> Result<()> {
    crate::registry::check_name(&manifest.instance.name)?;
    if manifest.instance.handle.is_some()
        || !manifest.instance.secrets.is_empty()
        || !manifest.instance.volumes.is_empty()
        || manifest.instance.seed_device.is_some()
    {
        bail!("backup manifest contains runtime or binding material and is not redacted");
    }
    for file in &manifest.files {
        checked_relative(&file.path)?;
        let sum: u64 = file.chunks.iter().map(Chunk::len).sum();
        if sum != file.len {
            bail!(
                "backup file {:?} describes {sum} bytes but claims {}",
                file.path,
                file.len
            );
        }
        for chunk in &file.chunks {
            if let Chunk::Data { digest, .. } = chunk {
                validate_digest(digest)?;
            }
        }
        validate_digest(&file.digest)?;
    }
    match (manifest.version, manifest.materialization.as_ref()) {
        (LEGACY_FORMAT_VERSION, None) => {}
        (LEGACY_FORMAT_VERSION, Some(_)) => {
            bail!("backup format 1 must not claim v2 materialization metadata")
        }
        (FORMAT_VERSION, Some(metadata)) => validate_materialization(manifest, metadata)?,
        (FORMAT_VERSION, None) => bail!("backup format 2 has no materialization metadata"),
        _ => unreachable!("format version checked by inspect"),
    }
    Ok(())
}

fn validate_materialization(manifest: &Manifest, metadata: &Materialization) -> Result<()> {
    if metadata.machine != manifest.instance.machine {
        bail!("backup materialization machine does not match the instance definition");
    }
    if metadata.platform.os != "linux" || metadata.platform.architecture.is_empty() {
        bail!("backup materialization names no supported guest platform");
    }
    let mut declared = metadata
        .root_disk
        .iter()
        .chain(metadata.snapshots.iter())
        .map(|artifact| (artifact.path.as_str(), artifact.format))
        .collect::<Vec<_>>();
    declared.sort_by_key(|(path, _)| *path);
    let mut actual = manifest
        .files
        .iter()
        .filter_map(|file| disk_format(&file.path).map(|format| (file.path.as_str(), format)))
        .collect::<Vec<_>>();
    actual.sort_by_key(|(path, _)| *path);
    if declared != actual {
        bail!("backup materialization disk inventory does not match its files");
    }
    let mut tags = std::collections::HashSet::new();
    for snapshot in &metadata.snapshots {
        let tag = snapshot_tag(&snapshot.path)
            .context("backup materialization contains a disk outside snapshots/")?;
        if !tags.insert(tag) {
            bail!("backup materialization repeats snapshot tag {tag:?}");
        }
    }
    match (&metadata.oci, manifest.instance.image_kind) {
        (Some(oci), crate::hv::ImageKind::OciRootfs) => {
            if oci.reference != manifest.image.as_ref().map_or("", |image| &image.reference)
                || oci.platform != metadata.platform
            {
                bail!("OCI materialization provenance does not match the backup image/platform");
            }
            validate_source_digest(&oci.manifest_digest)?;
            validate_source_digest(&oci.config_digest)?;
            for digest in &oci.layer_digests {
                validate_source_digest(digest)?;
            }
        }
        (None, crate::hv::ImageKind::OciRootfs) => {
            bail!("OCI backup has no re-materialization provenance")
        }
        (Some(_), _) => bail!("non-OCI backup claims OCI materialization provenance"),
        (None, _) => {}
    }
    Ok(())
}

fn validate_source_digest(digest: &str) -> Result<()> {
    let Some((algorithm, hex)) = digest.split_once(':') else {
        bail!("{digest:?} is not a source content digest");
    };
    if !matches!(algorithm, "sha256" | "sha512" | "blake3")
        || hex.is_empty()
        || !hex.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        bail!("{digest:?} is not a supported source content digest");
    }
    Ok(())
}

fn portable_path(path: &Path) -> Result<String> {
    let checked = checked_path(path)?;
    Ok(checked
        .components()
        .map(|part| part.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/"))
}

fn checked_relative(path: &str) -> Result<PathBuf> {
    checked_path(Path::new(path))
}

fn checked_path(path: &Path) -> Result<PathBuf> {
    if path.as_os_str().is_empty()
        || path
            .components()
            .any(|part| !matches!(part, Component::Normal(_)))
    {
        bail!("backup path {:?} is not a safe relative path", path);
    }
    Ok(path.to_owned())
}

fn chunk_path(root: &Path, digest: &str) -> Result<PathBuf> {
    validate_digest(digest)?;
    Ok(root.join("chunks").join(&digest[..2]).join(&digest[2..]))
}

fn validate_digest(digest: &str) -> Result<()> {
    if digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("{digest:?} is not a BLAKE3 content address");
    }
    Ok(())
}

#[cfg(unix)]
fn mode(meta: &std::fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    meta.permissions().mode() & 0o777
}

#[cfg(not(unix))]
fn mode(_meta: &std::fs::Metadata) -> u32 {
    0o600
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hv::Machine;
    use crate::instance::{Shape, Volume};
    use crate::secret::{Binding, GuestHandle, HandleShape, SecretId};

    fn instance(name: &str) -> Instance {
        Instance::new(
            name,
            "old-device",
            "debian:13",
            Shape::default(),
            Machine {
                backend: "qemu".into(),
                machine_type: "virt".into(),
                cpu: "host".into(),
                hv_version: "test".into(),
            },
        )
    }

    fn machine(backend: &str) -> Machine {
        Machine {
            backend: backend.into(),
            machine_type: format!("{backend}-machine"),
            cpu: "host".into(),
            hv_version: "target".into(),
        }
    }

    fn oci_provenance(reference: &str) -> ImageProvenance {
        ImageProvenance {
            reference: reference.into(),
            content: format!("blake3:{}", "a".repeat(64)),
            size: 4096,
            kind: "oci-rootfs".into(),
            source: reference.into(),
            derived_from: vec![
                format!("sha256:{}", "1".repeat(64)),
                format!("sha256:{}", "2".repeat(64)),
                format!("sha256:{}", "3".repeat(64)),
            ],
        }
    }

    fn qcow2_fixture(payload: &[u8]) -> Vec<u8> {
        const CLUSTER: usize = 4096;
        const GUEST_CLUSTERS: usize = 65_536;
        const COPIED: u64 = 1 << 63;
        let mut image = vec![0u8; 6 * CLUSTER];
        image[..4].copy_from_slice(b"QFI\xfb");
        image[4..8].copy_from_slice(&3u32.to_be_bytes());
        image[20..24].copy_from_slice(&12u32.to_be_bytes());
        image[24..32].copy_from_slice(&((GUEST_CLUSTERS * CLUSTER) as u64).to_be_bytes());
        image[36..40].copy_from_slice(&(GUEST_CLUSTERS.div_ceil(CLUSTER / 8) as u32).to_be_bytes());
        image[40..48].copy_from_slice(&(CLUSTER as u64).to_be_bytes());
        image[48..56].copy_from_slice(&(2 * CLUSTER as u64).to_be_bytes());
        image[56..60].copy_from_slice(&1u32.to_be_bytes());
        image[CLUSTER..CLUSTER + 8].copy_from_slice(&((4 * CLUSTER) as u64 | COPIED).to_be_bytes());
        image[2 * CLUSTER..2 * CLUSTER + 8].copy_from_slice(&((3 * CLUSTER) as u64).to_be_bytes());
        for cluster in 0..6 {
            let offset = 3 * CLUSTER + cluster * 2;
            image[offset..offset + 2].copy_from_slice(&1u16.to_be_bytes());
        }
        image[4 * CLUSTER..4 * CLUSTER + 8]
            .copy_from_slice(&((5 * CLUSTER) as u64 | COPIED).to_be_bytes());
        image[5 * CLUSTER..5 * CLUSTER + payload.len()].copy_from_slice(payload);
        image[96..100].copy_from_slice(&4u32.to_be_bytes());
        image[100..104].copy_from_slice(&104u32.to_be_bytes());
        image
    }

    #[test]
    fn export_is_redacted_deduplicated_sparse_and_round_trips() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("instance");
        let backup = temp.path().join("backup");
        let restore = temp.path().join("restore");
        std::fs::create_dir_all(source.join("snapshots")).unwrap();
        let data = vec![7u8; CHUNK_SIZE];
        let mut disk = File::create(source.join("disk.raw")).unwrap();
        disk.write_all(&data).unwrap();
        disk.seek(SeekFrom::Current(CHUNK_SIZE as i64)).unwrap();
        disk.write_all(&data).unwrap();
        disk.set_len((CHUNK_SIZE * 3) as u64).unwrap();
        std::fs::copy(source.join("disk.raw"), source.join("snapshots/clean.raw")).unwrap();
        std::fs::write(source.join("seed.iso"), b"SECRET-SEED").unwrap();
        std::fs::write(source.join("agent.key"), b"SECRET-AGENT").unwrap();

        let mut inst = instance("dev");
        inst.volumes
            .push(Volume::dir("/private/data", "old-device", None));
        let guest_handle = GuestHandle::mint(HandleShape::Opaque);
        let guest_handle_text = guest_handle.as_str().to_owned();
        inst.secrets.push(Binding {
            id: "binding-1".into(),
            secret_id: SecretId::from_name("api").unwrap(),
            secret: "api".into(),
            authority: "api.example.com:443".into(),
            placement: Placement::Authorization {
                scheme: "Bearer".into(),
            },
            guest_handle,
            env: "API_TOKEN".into(),
            source_device_id: "source-id".into(),
            source_device: "source".into(),
            version: 1,
            bound_at: 1,
            provider: None,
            accept: Vec::new(),
            rule: crate::credential::CredentialRule::Substitute,
        });
        inst.gpu = Some(GpuAttachment {
            provider_device: "gpu-box".into(),
            provider_device_id: "a".repeat(64),
            provider_gpu_uuid: "GPU-01234567".into(),
            memory_bytes: 8 << 30,
            provider_generation: 9,
            attached_at: 100,
        });
        let first = export(&inst, &source, &backup, None).unwrap();
        assert_eq!(first.data_chunks, 4);
        assert!(
            first.reused_chunks >= 3,
            "same chunks are reused within the export"
        );
        let second = export(&inst, &source, &backup, None).unwrap();
        assert_eq!(second.reused_chunks, second.data_chunks);

        let manifest = verify(&backup).unwrap();
        let text = std::fs::read_to_string(backup.join(MANIFEST)).unwrap();
        assert!(!text.contains("SECRET"));
        assert!(!text.contains("agent.key"));
        assert!(!text.contains("seed.iso"));
        assert!(!text.contains(&guest_handle_text));
        assert!(manifest.instance.volumes.is_empty());
        assert_eq!(manifest.rebind.volumes.len(), 1);
        assert!(manifest.instance.secrets.is_empty());
        assert_eq!(manifest.rebind.secrets.len(), 1);
        assert_eq!(manifest.rebind.secrets[0].secret, "api");
        assert!(manifest.instance.gpu.is_none());
        assert_eq!(
            manifest.rebind.gpu.as_ref().unwrap().provider_gpu_uuid,
            "GPU-01234567"
        );
        assert!(manifest.files.iter().any(|file| {
            file.chunks
                .iter()
                .any(|chunk| matches!(chunk, Chunk::Zero { .. }))
        }));

        let (restored, report) = restore_to(&backup, &restore, "dev").unwrap();
        assert_eq!(restored.id, inst.id);
        assert_eq!(report.rebind.volumes.len(), 1);
        assert_eq!(
            std::fs::read(source.join("disk.raw")).unwrap(),
            std::fs::read(restore.join("disk.raw")).unwrap()
        );
        assert!(!restore.join("seed.iso").exists());
    }

    #[test]
    fn hyperv_disk_and_backend_formatted_snapshots_are_portable() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("instance");
        let backup = temp.path().join("backup");
        let restore = temp.path().join("restore");
        std::fs::create_dir_all(source.join("snapshots")).unwrap();
        std::fs::write(source.join("disk.vhdx"), b"hyper-v root").unwrap();
        std::fs::write(source.join("snapshots/clean.vhdx"), b"hyper-v snapshot").unwrap();
        std::fs::write(source.join("snapshots/legacy.raw"), b"legacy snapshot").unwrap();

        let mut inst = instance("windows-dev");
        inst.machine.backend = "hyperv".into();
        export(&inst, &source, &backup, None).unwrap();
        let manifest = verify(&backup).unwrap();
        let paths: Vec<&str> = manifest
            .files
            .iter()
            .map(|file| file.path.as_str())
            .collect();
        assert!(paths.contains(&"disk.vhdx"));
        assert!(paths.contains(&"snapshots/clean.vhdx"));
        assert!(paths.contains(&"snapshots/legacy.raw"));

        restore_to(&backup, &restore, "windows-dev").unwrap();
        assert_eq!(
            std::fs::read(restore.join("disk.vhdx")).unwrap(),
            b"hyper-v root"
        );
        assert_eq!(
            std::fs::read(restore.join("snapshots/clean.vhdx")).unwrap(),
            b"hyper-v snapshot"
        );
    }

    #[test]
    fn fifty_seeded_drills_detect_corruption_and_preserve_identity_and_bytes() {
        for seed in 0u8..50 {
            let temp = tempfile::tempdir().unwrap();
            let source = temp.path().join("instance");
            let backup = temp.path().join("backup");
            let restore = temp.path().join("restore");
            std::fs::create_dir_all(&source).unwrap();
            let mut bytes = vec![0u8; 32 * 1024 + usize::from(seed)];
            for (index, byte) in bytes.iter_mut().enumerate().step_by(97) {
                *byte = seed.wrapping_mul(31).wrapping_add(index as u8);
            }
            std::fs::write(source.join("disk.raw"), &bytes).unwrap();
            let inst = instance(&format!("drill-{seed}"));
            export(&inst, &source, &backup, None).unwrap();
            let (restored, _) = restore_to(&backup, &restore, &inst.name).unwrap();
            assert_eq!(restored.id, inst.id, "seed {seed}");
            assert_eq!(
                std::fs::read(restore.join("disk.raw")).unwrap(),
                bytes,
                "seed {seed}"
            );

            let manifest = inspect(&backup).unwrap();
            let digest = manifest.files[0]
                .chunks
                .iter()
                .find_map(|chunk| match chunk {
                    Chunk::Data { digest, .. } => Some(digest),
                    Chunk::Zero { .. } => None,
                })
                .unwrap();
            let chunk = chunk_path(&backup, digest).unwrap();
            let mut corrupt = std::fs::read(&chunk).unwrap();
            corrupt[0] ^= 0xff;
            std::fs::write(chunk, corrupt).unwrap();
            assert!(verify(&backup).is_err(), "seed {seed}");
        }
    }

    #[test]
    fn a_partial_restore_resumes_and_unsafe_paths_are_refused() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("instance");
        let backup = temp.path().join("backup");
        let restore = temp.path().join("restore");
        std::fs::create_dir_all(&source).unwrap();
        let bytes = vec![9u8; CHUNK_SIZE + 17];
        std::fs::write(source.join("disk.raw"), &bytes).unwrap();
        export(&instance("dev"), &source, &backup, None).unwrap();
        let manifest = inspect(&backup).unwrap();
        std::fs::create_dir_all(&restore).unwrap();
        let part = restore.join("disk.raw.restore-part");
        std::fs::write(&part, &bytes[..CHUNK_SIZE]).unwrap();
        restore_to(&backup, &restore, "dev").unwrap();
        assert_eq!(std::fs::read(restore.join("disk.raw")).unwrap(), bytes);

        let mut bad = manifest;
        bad.files[0].path = "../escape".into();
        assert!(validate_manifest(&bad).is_err());
    }

    /// An agent's spending history is worth as much as the disk it ran on,
    /// and it must survive being moved to another machine. Sockets, seeds
    /// and the egress directory beside it must not.
    #[test]
    fn the_cost_ledger_travels_with_a_backup_and_host_plumbing_does_not() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("instance");
        let backup = temp.path().join("backup");
        let restore = temp.path().join("restore");
        std::fs::create_dir_all(source.join("cost")).unwrap();
        std::fs::create_dir_all(source.join("egress")).unwrap();
        std::fs::write(source.join("disk.raw"), b"root").unwrap();
        let line =
            b"{\"ts\":1756300000,\"host\":\"api.anthropic.com\",\"calls\":1,\"input_tokens\":10}\n";
        std::fs::write(source.join("cost/2026-08-27.jsonl"), line).unwrap();
        std::fs::write(source.join("cost/2026-08-26.jsonl"), line).unwrap();
        std::fs::write(source.join("egress/ca.pem"), b"a per-instance CA key").unwrap();
        std::fs::write(source.join("agent.key"), b"the guest agent key").unwrap();

        export(&instance("bot"), &source, &backup, None).unwrap();
        let manifest = verify(&backup).unwrap();
        let paths: Vec<&str> = manifest.files.iter().map(|f| f.path.as_str()).collect();
        assert!(paths.contains(&"cost/2026-08-26.jsonl"), "{paths:?}");
        assert!(paths.contains(&"cost/2026-08-27.jsonl"), "{paths:?}");
        assert!(
            !paths.iter().any(|path| path.starts_with("egress/")),
            "the egress directory is not portable: {paths:?}"
        );
        assert!(!paths.contains(&"agent.key"), "{paths:?}");

        std::fs::create_dir_all(&restore).unwrap();
        restore_to(&backup, &restore, "bot").unwrap();
        assert_eq!(
            std::fs::read(restore.join("cost/2026-08-27.jsonl")).unwrap(),
            line
        );
    }

    #[test]
    fn v2_records_machine_architecture_formats_and_oci_recipe() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("instance");
        let backup = temp.path().join("backup");
        std::fs::create_dir_all(source.join("snapshots")).unwrap();
        std::fs::write(source.join("disk.raw"), b"mutable root").unwrap();
        std::fs::write(source.join("snapshots/clean.raw"), b"snapshot").unwrap();
        let reference = format!("docker.io/example/app@sha256:{}", "9".repeat(64));
        let mut inst = instance("portable");
        inst.image = Some(reference.clone());
        inst.image_kind = crate::hv::ImageKind::OciRootfs;
        let provenance = oci_provenance(&reference);
        export(&inst, &source, &backup, Some(provenance.clone())).unwrap();

        let manifest = verify(&backup).unwrap();
        assert_eq!(manifest.version, FORMAT_VERSION);
        let metadata = manifest.materialization.unwrap();
        assert_eq!(metadata.machine, inst.machine);
        assert_eq!(metadata.platform.architecture, target_architecture());
        assert_eq!(metadata.root_disk.unwrap().format, DiskFormat::Raw);
        assert_eq!(metadata.snapshots[0].path, "snapshots/clean.raw");
        let oci = metadata.oci.unwrap();
        assert_eq!(oci.reference, reference);
        assert_eq!(oci.manifest_digest, provenance.derived_from[0]);
        assert_eq!(oci.config_digest, provenance.derived_from[1]);
        assert_eq!(oci.layer_digests, provenance.derived_from[2..]);
    }

    #[test]
    fn cross_architecture_restore_requires_explicit_immutable_oci_rematerialization() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("instance");
        let backup = temp.path().join("backup");
        let restore_arm = temp.path().join("restore-arm64");
        let restore_x86 = temp.path().join("restore-amd64");
        std::fs::create_dir_all(&source).unwrap();
        std::fs::write(source.join("disk.raw"), b"architecture-specific mutation").unwrap();
        let reference = format!("docker.io/example/app@sha256:{}", "9".repeat(64));
        let mut inst = instance("portable");
        inst.image = Some(reference.clone());
        inst.image_kind = crate::hv::ImageKind::OciRootfs;
        inst.volumes
            .push(Volume::dir("/portable/data", "old-device", None));
        export(&inst, &source, &backup, Some(oci_provenance(&reference))).unwrap();
        let manifest = verify(&backup).unwrap();
        let other_arch = if target_architecture() == "arm64" {
            "amd64"
        } else {
            "arm64"
        };
        let target = RestoreTarget {
            architecture: other_arch.into(),
            machine: machine("vz"),
            disk_formats: vec![DiskFormat::Raw],
            rematerialize_oci: false,
        };
        let error = plan_restore(&manifest, target.clone())
            .unwrap_err()
            .to_string();
        assert!(error.contains("cannot be restored directly"), "{error}");
        assert!(
            !restore_arm.exists() && !restore_x86.exists(),
            "planning must not create staging state"
        );

        let mut explicit = target;
        explicit.rematerialize_oci = true;
        let arm_plan = plan_restore(
            &manifest,
            RestoreTarget {
                architecture: "arm64".into(),
                ..explicit.clone()
            },
        )
        .unwrap();
        let x86_plan = plan_restore(
            &manifest,
            RestoreTarget {
                architecture: "amd64".into(),
                ..explicit
            },
        )
        .unwrap();

        for (restore, plan) in [(&restore_arm, arm_plan), (&restore_x86, x86_plan)] {
            assert_eq!(plan.disposition, RestoreDisposition::OciRematerialized);
            let (restored, report) =
                restore_to_target(&backup, restore, "portable", &plan).unwrap();
            assert_eq!(restored.status, Status::Defined);
            assert_eq!(restored.machine.backend, "vz");
            assert!(restored.volumes.is_empty());
            assert!(!restore.join("disk.raw").exists());
            assert_eq!(report.files, 0);
            assert_eq!(
                report.materialization,
                RestoreDisposition::OciRematerialized
            );
            assert_eq!(report.rebind.volumes.len(), 1);
            assert_eq!(report.rebind.volumes[0].path, "/portable/data");
        }
    }

    #[test]
    fn a_moving_oci_tag_cannot_authorize_cross_architecture_rematerialization() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("instance");
        let backup = temp.path().join("backup");
        std::fs::create_dir_all(&source).unwrap();
        std::fs::write(source.join("disk.raw"), b"architecture-specific mutation").unwrap();
        let reference = "docker.io/example/app:latest";
        let mut inst = instance("tagged");
        inst.image = Some(reference.into());
        inst.image_kind = crate::hv::ImageKind::OciRootfs;
        export(&inst, &source, &backup, Some(oci_provenance(reference))).unwrap();
        let manifest = verify(&backup).unwrap();
        let other_arch = if target_architecture() == "arm64" {
            "amd64"
        } else {
            "arm64"
        };

        let error = plan_restore(
            &manifest,
            RestoreTarget {
                architecture: other_arch.into(),
                machine: machine("vz"),
                disk_formats: vec![DiskFormat::Raw],
                rematerialize_oci: true,
            },
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("immutable @sha256"), "{error}");
    }

    #[test]
    fn disk_format_mismatch_refuses_before_restore_staging() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("instance");
        let backup = temp.path().join("backup");
        let staging = temp.path().join("staging");
        std::fs::create_dir_all(&source).unwrap();
        std::fs::write(source.join("disk.vhdx"), b"vhdx bytes").unwrap();
        let mut inst = instance("windows");
        inst.machine = machine("hyperv");
        export(&inst, &source, &backup, None).unwrap();
        let manifest = verify(&backup).unwrap();
        let error = plan_restore(
            &manifest,
            RestoreTarget {
                architecture: target_architecture().into(),
                machine: machine("qemu"),
                disk_formats: vec![DiskFormat::Raw, DiskFormat::Qcow2],
                rematerialize_oci: false,
            },
        )
        .unwrap_err()
        .to_string();
        assert!(
            error.contains("cannot restore disk.vhdx as vhdx"),
            "{error}"
        );
        assert!(!staging.exists());
    }

    #[test]
    fn same_architecture_qcow2_materializes_as_sparse_raw_for_a_raw_backend() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("instance");
        let backup = temp.path().join("backup");
        let restore = temp.path().join("restore");
        std::fs::create_dir_all(&source).unwrap();
        let payload = b"guest-visible bytes";
        std::fs::write(source.join("disk.qcow2"), qcow2_fixture(payload)).unwrap();
        export(&instance("convert"), &source, &backup, None).unwrap();
        let manifest = verify(&backup).unwrap();
        let plan = plan_restore(
            &manifest,
            RestoreTarget {
                architecture: target_architecture().into(),
                machine: machine("vz"),
                disk_formats: vec![DiskFormat::Raw],
                rematerialize_oci: false,
            },
        )
        .unwrap();
        assert_eq!(plan.disposition, RestoreDisposition::Qcow2ToRaw);
        restore_to_target(&backup, &restore, "convert", &plan).unwrap();
        assert!(!restore.join("disk.qcow2").exists());
        let mut raw = File::open(restore.join("disk.raw")).unwrap();
        let mut got = vec![0; payload.len()];
        raw.read_exact(&mut got).unwrap();
        assert_eq!(got, payload);
        assert_eq!(raw.metadata().unwrap().len(), 65_536 * 4096);
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            assert!(raw.metadata().unwrap().blocks() * 512 < raw.metadata().unwrap().len() / 4);
        }
    }

    #[test]
    fn v1_remains_readable_and_byte_exact_only() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("instance");
        let backup = temp.path().join("backup");
        let restore = temp.path().join("restore");
        std::fs::create_dir_all(&source).unwrap();
        std::fs::write(source.join("disk.raw"), b"legacy bytes").unwrap();
        let inst = instance("legacy");
        export(&inst, &source, &backup, None).unwrap();
        let mut json: serde_json::Value =
            serde_json::from_slice(&std::fs::read(backup.join(MANIFEST)).unwrap()).unwrap();
        json["version"] = LEGACY_FORMAT_VERSION.into();
        json.as_object_mut().unwrap().remove("materialization");
        let bytes = serde_json::to_vec_pretty(&json).unwrap();
        std::fs::write(backup.join(MANIFEST), &bytes).unwrap();
        std::fs::write(
            backup.join(MANIFEST_DIGEST),
            format!("{}\n", blake3::hash(&bytes).to_hex()),
        )
        .unwrap();

        let manifest = inspect(&backup).unwrap();
        assert_eq!(manifest.version, LEGACY_FORMAT_VERSION);
        assert!(manifest.materialization.is_none());
        restore_to(&backup, &restore, "legacy").unwrap();
        assert_eq!(
            std::fs::read(restore.join("disk.raw")).unwrap(),
            b"legacy bytes"
        );
        let error = plan_restore(
            &manifest,
            RestoreTarget {
                architecture: target_architecture().into(),
                machine: machine("vz"),
                disk_formats: vec![DiskFormat::Raw],
                rematerialize_oci: false,
            },
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("format 1"), "{error}");
    }
}
