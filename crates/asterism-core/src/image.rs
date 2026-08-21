//! Image catalog and local image store.
//!
//! An image reference is one of:
//!   - a catalog alias like `ubuntu:24.04` (or bare `ubuntu` for the default)
//!   - an `http(s)://` URL to a cloud image
//!   - a local path to a qcow2 or raw disk image
//!   - an OCI/Docker reference like `docker.io/library/nginx:latest` (or bare
//!     `nginx`), booted as a microVM from an ext4 built out of its layers
//!     ([`crate::oci`])
//!
//! The four are tried in that order, and the first three behave exactly as
//! they always did: an OCI reference is what a string turns out to be when it
//! is not a catalog alias, not a url, and not a file on this disk. Registry
//! grammar does the last bit of deciding, so a mistyped alias is still an
//! error here rather than a doomed pull.
//!
//! Catalog images and URLs are downloaded once into `~/.asterism/images/`;
//! local files are used in place.
//!
//! **Base images in the store are raw** (BACKENDS.md §4). Cloud images ship
//! as qcow2, so a pull downloads one and converts it: `<slug>.qcow2` is a
//! staging file, `<slug>.raw` is the image. Raw is what
//! Virtualization.framework can attach at all, what `clonefile(2)` can share
//! blocks of, and what QEMU reads fastest — the compression qcow2 bought us
//! is worth less than any of those, and a sparse raw file on APFS occupies
//! about what the qcow2 did anyway.
//!
//! Nothing is converted eagerly on upgrade: a store left full of qcow2 by an
//! older Asterism keeps working, and each image is converted the first time
//! it is used ([`Resolved::materialise`]).

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context, Result};

use crate::hv::{DiskFormat, ImageKind};
use crate::oci;
use crate::paths;
use crate::tools::{run, tool};

pub struct Resolved {
    /// Canonical name recorded on the instance.
    pub name: String,
    /// Where the bytes come from, if they need downloading.
    pub url: Option<String>,
    /// Where the base image lives (or will live once pulled and converted).
    pub path: PathBuf,
    /// Format of `path`. Always [`DiskFormat::Raw`] for an image this
    /// store manages; a local file is taken as it is found.
    pub format: DiskFormat,
    /// Where a download lands before it is converted, for images the store
    /// manages. `None` for a local file, which is never rewritten.
    pub staging: Option<PathBuf>,
    /// Set when this reference names a container image rather than a disk.
    /// What is in `path` is then an ext4 filesystem with no bootloader, and
    /// the backend has to bring a kernel ([`crate::oci`]).
    pub oci: Option<oci::Reference>,
}

impl Resolved {
    /// What kind of thing the bytes are — a disk to boot, or a root
    /// filesystem that needs a kernel put in front of it.
    pub fn kind(&self) -> ImageKind {
        match self.oci {
            Some(_) => ImageKind::OciRootfs,
            None => ImageKind::Disk,
        }
    }
}

impl Resolved {
    /// Are the bytes on this device at all — as the image, or still as the
    /// qcow2 an older Asterism (or an interrupted convert) left behind?
    pub fn is_pulled(&self) -> bool {
        self.path.exists() || self.staging.as_ref().is_some_and(|s| s.exists())
    }

    /// Turn whatever was downloaded into the raw base image instances clone
    /// from. Idempotent, and a no-op for a local file or an image that is
    /// already raw — so it is safe to call on every path that is about to
    /// need a base image, which is what makes the migration lazy.
    ///
    /// Returns whether it converted anything, so a foreground caller can
    /// say so and a background one can stay quiet.
    pub fn materialise(&self) -> Result<bool> {
        if self.path.exists() {
            return Ok(false);
        }
        let Some(staging) = self.staging.as_ref().filter(|s| s.exists()) else {
            return Ok(false); // not pulled yet; the caller says so, not us
        };
        let from = detect_format(staging)?;
        if from == DiskFormat::Raw {
            // Some publishers ship raw already; nothing to convert.
            std::fs::rename(staging, &self.path)?;
            return Ok(true);
        }
        convert_to_raw(staging, from, &self.path)
            .with_context(|| format!("converting {} to raw", self.name))?;
        // The staging copy is a cache of a re-downloadable file, and keeping
        // it would double what every image costs. It only ever lives in our
        // own store — a local file is never staged.
        let _ = std::fs::remove_file(staging);
        Ok(true)
    }
}

/// `qemu-img convert` into a sparse raw file, via a `.part` so an
/// interrupted convert cannot be mistaken for a finished image.
///
/// `-S 4k` is what keeps it sparse: a 20 GiB raw disk converted from a
/// 400 MiB qcow2 occupies ~1 GiB of APFS blocks, not 20 GiB.
///
/// A pure-Rust qcow2 reader would remove the last QEMU dependency from this
/// path (BACKENDS.md §4, LICENSING.md); until then this is the one place a
/// non-QEMU backend still needs `qemu-img`, and it runs once per image.
fn convert_to_raw(src: &Path, from: DiskFormat, dst: &Path) -> Result<()> {
    let part = dst.with_extension("raw.part");
    let _ = std::fs::remove_file(&part);
    run(Command::new(tool("qemu-img")?)
        .args(["convert", "-f", from.as_str(), "-O", "raw", "-S", "4k"])
        .arg(src)
        .arg(&part))?;
    std::fs::rename(&part, dst)?;
    Ok(())
}

/// What a file on disk actually is, from its first four bytes.
///
/// Cheaper and more honest than trusting the extension — cloud images are
/// published as `.img`, `.qcow2` and `.raw` with no relation to their
/// contents — and it avoids a `qemu-img info` subprocess on a path that
/// runs before any backend is chosen.
pub fn detect_format(path: &Path) -> Result<DiskFormat> {
    use std::io::Read;
    let mut magic = [0u8; 4];
    let mut file = std::fs::File::open(path)
        .with_context(|| format!("reading {}", path.display()))?;
    match file.read_exact(&mut magic) {
        Ok(()) if &magic == b"QFI\xfb" => Ok(DiskFormat::Qcow2),
        _ => Ok(DiskFormat::Raw),
    }
}

/// Catalog of known cloud images per architecture, newest first.
/// `(alias, aarch64 url, x86_64 url)`
pub const CATALOG: &[(&str, &str, &str)] = &[
    (
        "ubuntu:24.04",
        "https://cloud-images.ubuntu.com/releases/noble/release/ubuntu-24.04-server-cloudimg-arm64.img",
        "https://cloud-images.ubuntu.com/releases/noble/release/ubuntu-24.04-server-cloudimg-amd64.img",
    ),
    (
        "ubuntu:22.04",
        "https://cloud-images.ubuntu.com/releases/jammy/release/ubuntu-22.04-server-cloudimg-arm64.img",
        "https://cloud-images.ubuntu.com/releases/jammy/release/ubuntu-22.04-server-cloudimg-amd64.img",
    ),
    (
        "debian:13",
        "https://cloud.debian.org/images/cloud/trixie/latest/debian-13-generic-arm64.qcow2",
        "https://cloud.debian.org/images/cloud/trixie/latest/debian-13-generic-amd64.qcow2",
    ),
    (
        "debian:12",
        "https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-generic-arm64.qcow2",
        "https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-generic-amd64.qcow2",
    ),
    (
        "fedora:42",
        "https://download.fedoraproject.org/pub/fedora/linux/releases/42/Cloud/aarch64/images/Fedora-Cloud-Base-Generic-42-1.1.aarch64.qcow2",
        "https://download.fedoraproject.org/pub/fedora/linux/releases/42/Cloud/x86_64/images/Fedora-Cloud-Base-Generic-42-1.1.x86_64.qcow2",
    ),
    (
        "alpine:3.22",
        "https://dl-cdn.alpinelinux.org/alpine/v3.22/releases/cloud/nocloud_alpine-3.22.0-aarch64-uefi-cloudinit-r0.qcow2",
        "https://dl-cdn.alpinelinux.org/alpine/v3.22/releases/cloud/nocloud_alpine-3.22.0-x86_64-uefi-cloudinit-r0.qcow2",
    ),
];

/// Bare-name shortcuts to a concrete catalog entry.
pub const DEFAULTS: &[(&str, &str)] = &[
    ("ubuntu", "ubuntu:24.04"),
    ("debian", "debian:13"),
    ("fedora", "fedora:42"),
    ("alpine", "alpine:3.22"),
];

pub fn host_arch() -> &'static str {
    std::env::consts::ARCH
}

pub fn resolve(reference: &str) -> Result<Resolved> {
    let reference = DEFAULTS
        .iter()
        .find(|(bare, _)| *bare == reference)
        .map(|(_, full)| *full)
        .unwrap_or(reference);

    if let Some((_, arm64, amd64)) = CATALOG.iter().find(|(alias, _, _)| *alias == reference) {
        let url = match host_arch() {
            "aarch64" => arm64,
            "x86_64" => amd64,
            other => bail!("no {reference} image for architecture {other}"),
        };
        return Ok(stored(reference, Some((*url).to_owned())));
    }

    if reference.starts_with("http://") || reference.starts_with("https://") {
        return Ok(stored(reference, Some(reference.to_owned())));
    }

    let path = PathBuf::from(shellexpand_home(reference));
    if path.exists() {
        let path = std::fs::canonicalize(&path)?;
        return Ok(Resolved {
            name: path.display().to_string(),
            url: None,
            format: detect_format(&path)?,
            path,
            // A file the user pointed at is theirs: it is booted in the
            // format it is in, and never rewritten in place.
            staging: None,
            oci: None,
        });
    }

    // Last, because everything above is a thing this device already knows
    // about and this is a name on somebody else's registry.
    if let Some(image) = oci::parse(reference) {
        return Ok(oci_resolved(image));
    }

    bail!(
        "unknown image {reference:?} — try an alias from `ast images`, an https:// url, \
         a path to a local qcow2 or raw disk image, or an OCI image reference \
         like docker.io/library/nginx:latest"
    );
}

/// An OCI reference, and where its built filesystem is if this device has
/// built one.
///
/// The path is content-addressed on the *manifest* digest rather than on the
/// reference, so `nginx:latest` moving upstream produces a new file instead
/// of rewriting one that instances are booting from. Until a pull has
/// resolved that digest there is no path to name, and a path that cannot
/// exist is the honest answer — [`Resolved::is_pulled`] then says no, and
/// every caller already knows what to do about that.
fn oci_resolved(image: oci::Reference) -> Resolved {
    let name = image.canonical();
    let path = oci::stored(&image)
        .unwrap_or_else(|| paths::images_dir().join(format!("oci-{}.unpulled", image.slug())));
    Resolved {
        name,
        url: None,
        path,
        format: DiskFormat::Raw,
        staging: None,
        oci: Some(image),
    }
}

/// An image this store owns: raw under `<slug>.raw`, staged through the
/// `<slug>.qcow2` a download (or an older Asterism) leaves there. Both names
/// come off the same slug, so a store written before raw base images is
/// recognised without a manifest to read.
fn stored(reference: &str, url: Option<String>) -> Resolved {
    let dir = paths::images_dir();
    let slug = slug(reference);
    Resolved {
        name: reference.to_owned(),
        url,
        path: dir.join(format!("{slug}.raw")),
        format: DiskFormat::Raw,
        staging: Some(dir.join(format!("{slug}.qcow2"))),
        oci: None,
    }
}

fn slug(s: &str) -> String {
    let mut out: String = s
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '.' { c } else { '-' })
        .collect();
    // Keep url-derived names unique without keeping the whole url around.
    if s.contains("://") {
        use std::hash::{Hash, Hasher};
        let mut h = std::collections::hash_map::DefaultHasher::new();
        s.hash(&mut h);
        out = format!("url-{:016x}", h.finish());
    }
    out
}

fn shellexpand_home(p: &str) -> String {
    match (p.strip_prefix("~/"), std::env::var("HOME")) {
        (Some(rest), Ok(home)) => format!("{home}/{rest}"),
        _ => p.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aliases_resolve() {
        let r = resolve("ubuntu").unwrap();
        assert_eq!(r.name, "ubuntu:24.04");
        assert!(r.url.is_some());
        // The name scheme is the one it always was; only the format moved.
        assert!(r.path.to_string_lossy().ends_with("ubuntu-24.04.raw"));
        assert_eq!(r.format, DiskFormat::Raw);
        assert!(r
            .staging
            .as_ref()
            .unwrap()
            .to_string_lossy()
            .ends_with("ubuntu-24.04.qcow2"));
    }

    #[test]
    fn urls_resolve() {
        let r = resolve("https://example.com/x.qcow2").unwrap();
        assert_eq!(r.url.as_deref(), Some("https://example.com/x.qcow2"));
        assert_eq!(r.format, DiskFormat::Raw, "the store keeps raw, whatever the url says");
    }

    /// A string that is none of the things this device knows about is a name
    /// on a registry — which is what `--image nginx` has to mean — but only
    /// if it could be one. Repository names are lowercase by spec, so a
    /// mistyped alias is still refused here rather than at the end of a pull.
    #[test]
    fn what_is_not_local_is_a_registry_reference_if_it_could_be_one() {
        let r = resolve("nginx").unwrap();
        assert_eq!(r.name, "docker.io/library/nginx:latest");
        assert_eq!(r.kind(), ImageKind::OciRootfs);
        assert!(r.url.is_none(), "an image is pulled from a registry, not downloaded");
        assert!(r.staging.is_none());

        // Whether `nginx` is *pulled* is a fact about whichever store this
        // machine happens to have, not about resolving: on a device that has
        // really pulled one the honest answer is yes. The half of
        // `oci_resolved` worth pinning here is the other one — a reference
        // nothing has built names a path that cannot exist — so ask it about a
        // digest no registry ever served.
        let unbuilt = resolve(&format!("nginx@sha256:{}", "0".repeat(64))).unwrap();
        assert_eq!(unbuilt.kind(), ImageKind::OciRootfs);
        assert!(unbuilt.url.is_none());
        assert!(!unbuilt.is_pulled(), "nothing has been built for that digest");

        assert_eq!(
            resolve("docker.io/library/nginx:latest").unwrap().name,
            resolve("nginx").unwrap().name
        );

        let err = match resolve("Definitely-Not-An-Image") {
            Err(e) => e.to_string(),
            Ok(r) => panic!("capitals are not a repository name: {}", r.name),
        };
        assert!(err.contains("unknown image"), "{err}");
        assert!(resolve("not an image at all").is_err());
    }

    /// The catalog wins over the registry: `alpine` has meant the catalog's
    /// cloud image since before Docker Hub was in the picture, and must not
    /// quietly become a container.
    #[test]
    fn the_catalog_still_owns_the_names_it_had() {
        for alias in ["ubuntu", "debian", "alpine", "fedora", "ubuntu:24.04"] {
            let r = resolve(alias).unwrap();
            assert_eq!(r.kind(), ImageKind::Disk, "{alias}");
            assert!(r.url.is_some(), "{alias} is still a cloud image download");
        }
    }

    /// A qcow2 header is four bytes; everything else is raw as far as a
    /// base image is concerned.
    #[test]
    fn formats_come_off_the_bytes_not_the_name() {
        let dir = tempfile::tempdir().unwrap();
        let lying = dir.path().join("actually-raw.qcow2");
        std::fs::write(&lying, vec![0u8; 4096]).unwrap();
        assert_eq!(detect_format(&lying).unwrap(), DiskFormat::Raw);

        let real = dir.path().join("real.img");
        std::fs::write(&real, b"QFI\xfb\x00\x00\x00\x03").unwrap();
        assert_eq!(detect_format(&real).unwrap(), DiskFormat::Qcow2);

        // Too short to hold a magic number is not a qcow2 either.
        let stub = dir.path().join("stub");
        std::fs::write(&stub, b"ab").unwrap();
        assert_eq!(detect_format(&stub).unwrap(), DiskFormat::Raw);
        assert!(detect_format(&dir.path().join("absent")).is_err());
    }

    /// A local file is the user's: booted in the format it is in, never
    /// rewritten, never staged.
    #[test]
    fn a_local_file_is_used_in_place() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mine.qcow2");
        std::fs::write(&path, b"QFI\xfb rest").unwrap();
        let r = resolve(&path.display().to_string()).unwrap();
        assert_eq!(r.format, DiskFormat::Qcow2);
        assert!(r.staging.is_none());
        assert!(r.url.is_none());
        assert!(r.is_pulled());
        assert!(!r.materialise().unwrap(), "nothing to convert");
        assert!(path.exists(), "the user's file is left alone");
    }

    /// Migration is lazy: an image that only exists as the qcow2 an older
    /// Asterism pulled still counts as pulled, and converts on first use.
    #[test]
    fn a_qcow2_left_by_an_older_store_is_still_the_image() {
        let dir = tempfile::tempdir().unwrap();
        let r = Resolved {
            name: "debian:13".into(),
            url: None,
            path: dir.path().join("debian-13.raw"),
            format: DiskFormat::Raw,
            staging: Some(dir.path().join("debian-13.qcow2")),
            oci: None,
        };
        assert!(!r.is_pulled());
        assert!(!r.materialise().unwrap(), "nothing there to convert yet");

        // Raw bytes under the qcow2 name: no qemu-img needed, so this half
        // of the migration is testable without one installed.
        std::fs::write(r.staging.as_ref().unwrap(), vec![7u8; 1024]).unwrap();
        assert!(r.is_pulled());
        assert!(r.materialise().unwrap());
        assert!(r.path.exists());
        assert!(!r.staging.as_ref().unwrap().exists(), "the staging copy is not kept");
        assert!(!r.materialise().unwrap(), "and again is a no-op");
    }
}
