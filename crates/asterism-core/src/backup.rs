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
use crate::instance::{Instance, Status, VolumeKind};
use crate::remote_gpu::GpuAttachment;
use crate::secret::Placement;

pub const FORMAT_VERSION: u32 = 1;
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

    let manifest = Manifest {
        version: FORMAT_VERSION,
        created_at: crate::instance::now_unix(),
        instance: portable,
        image,
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
    if manifest.version != FORMAT_VERSION {
        bail!(
            "backup format {} is not supported by this build (supports {})",
            manifest.version,
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
    crate::registry::check_name(name)?;
    std::fs::create_dir_all(staging)
        .with_context(|| format!("creating restore staging directory {}", staging.display()))?;
    for file in &manifest.files {
        restore_file(source, staging, file)?;
    }
    let mut instance = manifest.instance.clone();
    instance.name = name.to_owned();
    instance.status = if instance.status == Status::Defined && manifest.files.is_empty() {
        Status::Defined
    } else {
        Status::Stopped
    };
    instance.handle = None;
    instance.cpu_device.clear();
    let report = RestoreReport {
        instance: name.to_owned(),
        id: instance.id.clone(),
        files: manifest.files.len(),
        logical_bytes: manifest.files.iter().map(|file| file.len).sum(),
        rebind: manifest.rebind,
    };
    durable::commit_json(&staging.join(".restore-receipt.json"), &report)?;
    Ok((instance, report))
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

/// Only durable guest state. The explicit allowlist is also the redaction
/// boundary: a future sidecar does not become portable merely by appearing.
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
}
