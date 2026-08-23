//! OCI/Docker images as an instance image source.
//!
//! OCI/Docker is an image format, independent of the instance runtime. A
//! reference like `nginx` is pulled, verified, unpacked, and represented as
//! an ext4 filesystem image. `runtime=vm` boots that filesystem with a guest
//! kernel; `runtime=container` extracts the same verified bytes into a
//! rootless native namespace. Runtime selection never changes image identity.
//!
//! Three things a container image does not come with, and where each comes
//! from:
//!
//! * **A filesystem image.** Layers are tar+gzip; ext4 is what a guest boots.
//!   `mke2fs -d` (e2fsprogs 1.47) builds a populated ext4 from a directory
//!   without root and without a loopback mount, which is the only route on
//!   macOS that does not involve booting a helper VM to run `mkfs` for us.
//!   Ownership is then corrected in one `debugfs` pass, because `mke2fs -d`
//!   can only copy the *host's* ownership and a non-root unpack owns
//!   everything itself.
//!
//! * **A kernel.** An OCI rootfs has no kernel and no bootloader, so the
//!   backend boots one directly (`-kernel/-initrd/-append`). We take Ubuntu's
//!   published cloud-image kernel and its matching initrd — the two files
//!   under `.../releases/noble/release/unpacked/`, which is the same kernel
//!   the catalog's `ubuntu:24.04` runs, downloaded as plain files instead of
//!   dug out of a disk image. It is pinned, ~48 MB for the pair, fetched once
//!   per device, and needs no ext4 reader on the host to obtain (the
//!   alternative, extracting `/boot` from the cached Debian image, needs one).
//!   The initrd is what carries `virtio_blk` and `ext4` as modules, so a
//!   distro kernel can be used as it ships.
//!
//! * **An init.** The image config's Entrypoint/Cmd has to run as pid 1 in a
//!   machine with nothing mounted. [`init_script`] generates
//!   `/asterism-init` into the rootfs: it mounts /proc, /sys, /dev, takes
//!   its address from the kernel cmdline the backend wrote, exports the image's
//!   Env, runs the entrypoint, and powers the machine off when it exits. It
//!   runs under a static busybox copied into the rootfs at `/.asterism/busybox`
//!   — lifted from the `busybox:musl` image with this same puller — so that
//!   the init depends on nothing the image happened to ship, not even a shell.
//!
//! Store layout, under `~/.asterism/images/`:
//! ```text
//! oci/blobs/sha256-<hex>      registry blobs, cached
//! oci/<slug>.digest           what a tag currently points at
//! oci-<hex12>.raw             the ext4 image, named for its manifest digest
//! oci-<hex12>.json            the image config it was built from
//! kernel/<arch>-vmlinuz       guest kernel, shared by every OCI instance
//! kernel/<arch>-vmlinux       verified, uncompressed derivative for VZ
//! kernel/<arch>-initrd
//! kernel/<arch>-<module>.ko   verified modules paired with that kernel
//! ```
//! The `.raw` is content-addressed, so two references to the same digest are
//! one image on disk and a moved tag is a different file rather than a
//! rewritten one.

use std::collections::BTreeMap;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{bail, Context, Result};
use data_encoding::BASE64;
use serde_json::Value;

use crate::durable;
use crate::hv::ShareKind;
use crate::image::host_arch;
use crate::paths;
use crate::profile::Bootstrap;
use crate::seed::{self, Egress, Share};
use crate::tools::{output, run, tool};
use crate::verify::{self, Algo, Depth, Digest, Pinned, Source};

/// Where a bare `nginx` comes from.
pub const DEFAULT_REGISTRY: &str = "docker.io";

/// The static shell every generated init runs under. Pulled through this
/// same code path and copied into the rootfs, so an image with no shell
/// (or no coreutils, or nothing at all) still boots.
const BUSYBOX_IMAGE: &str = "docker.io/library/busybox:musl";

/// Where the busybox and the init land inside the guest.
///
/// The busybox keeps its own name: busybox dispatches on `argv[0]`, and only
/// answers to `argv[1]` when it is called `busybox`. A dot-directory of our
/// own is the one path an image is not going to have opinions about.
pub const GUEST_BUSYBOX: &str = ".asterism/busybox";
pub const GUEST_INIT: &str = "asterism-init";

/// Locations used by older builds. `/sbin` is a symlink to `/usr/sbin` in
/// merged-/usr images, and debugfs deliberately does not follow symlinks, so
/// both spellings must be removed explicitly during an offline refresh.
const LEGACY_GUEST_INIT: &str = "sbin/asterism-init";
const MERGED_USR_GUEST_INIT: &str = "usr/sbin/asterism-init";

/// The legacy standalone DHCP hook. Current guests dispatch udhcpc callbacks
/// through [`GUEST_INIT`] so personalizing a grown ext4 clone allocates only
/// one file; this path is removed when an older private disk is refreshed.
const GUEST_DHCP: &str = ".asterism/udhcpc";

/// The legacy on-disk public egress CA. Current init scripts materialize the
/// public certificate at boot, again avoiding a second debugfs allocation.
const GUEST_EGRESS_CA: &str = ".asterism/egress-ca.pem";

/// The kernel cmdline `init=` the backend must pass.
pub const INIT_PATH: &str = "/asterism-init";

/// Guest kernel and initrd per host architecture.
///
/// Ubuntu publishes the cloud image's kernel and initrd as loose files next
/// to the image itself, with a `SHA256SUMS` covering them. Both are taken
/// from a dated release serial rather than the `release/` name that
/// republishes over itself, so the digest below is a fact about a specific
/// pair of files rather than a snapshot of whatever was there the day a
/// device first asked. Same release as the catalog's `ubuntu:24.04`, so a
/// device is not running a kernel nobody chose.
///
/// This is the artifact where an unverified first fetch would matter most:
/// it is not a filesystem a guest mounts, it is the code the host's
/// hypervisor loads and jumps to.
pub struct GuestKernel {
    pub arch: &'static str,
    pub kernel: Pinned,
    pub initrd: Pinned,
}

pub const KERNELS: &[GuestKernel] = &[
    GuestKernel {
        arch: "aarch64",
        kernel: Pinned {
            url: "https://cloud-images.ubuntu.com/releases/noble/release-20260814/unpacked/ubuntu-24.04-server-cloudimg-arm64-vmlinuz-generic",
            digest: "sha256:9ff21f2798055943e5a28da044a5eb701bc85e1f1817c34bd1bd62729cdeca25",
        },
        initrd: Pinned {
            url: "https://cloud-images.ubuntu.com/releases/noble/release-20260814/unpacked/ubuntu-24.04-server-cloudimg-arm64-initrd-generic",
            digest: "sha256:66b3257ccc43c088f7b7c14ebf74dee30172a9a0eb0e6ccd8db1374e18a281de",
        },
    },
    GuestKernel {
        arch: "x86_64",
        kernel: Pinned {
            url: "https://cloud-images.ubuntu.com/releases/noble/release-20260814/unpacked/ubuntu-24.04-server-cloudimg-amd64-vmlinuz-generic",
            digest: "sha256:76a7f2ef15fcbd2f5c25cd7e7b413f903b2078396063557f1dffb4a0b089a964",
        },
        initrd: Pinned {
            url: "https://cloud-images.ubuntu.com/releases/noble/release-20260814/unpacked/ubuntu-24.04-server-cloudimg-amd64-initrd-generic",
            digest: "sha256:194f73c17ca4795f987f2e1713c7184f8d1bb88f063f79a753dada5da6a9987c",
        },
    },
];

/// Loadable drivers the cloud-image initrd does not carry.
///
/// Ubuntu builds virtiofs and the virtio-vsock transport as modules. Its
/// cloud initrd omits them because ordinary cloud images load matching
/// modules from their root filesystem later. Asterism may direct-boot a
/// Debian disk with this Ubuntu kernel, so the root module tree is not a
/// valid fallback. Keep the exact matching Ubuntu package pinned beside the
/// kernel pair and retain only the small verified derivatives we load.
pub struct GuestModule {
    pub arch: &'static str,
    pub package: Pinned,
}

pub const VIRTIOFS_MODULES: &[GuestModule] = &[
    GuestModule {
        arch: "aarch64",
        package: Pinned {
            url: "https://ports.ubuntu.com/ubuntu-ports/pool/main/l/linux/linux-modules-6.8.0-137-generic_6.8.0-137.137_arm64.deb",
            digest: "sha256:8bd01ff03569d5d60e1abad54fa9cdb2a0e171b9408ced82432b00195803b45b",
        },
    },
    GuestModule {
        arch: "x86_64",
        package: Pinned {
            url: "https://archive.ubuntu.com/ubuntu/pool/main/l/linux/linux-modules-6.8.0-137-generic_6.8.0-137.137_amd64.deb",
            digest: "sha256:f8dabfa49fc27e8d680a264b5c60b9492ef20e95ec32a52d7a03b4cf15ae72f0",
        },
    },
];

const KERNEL_MODULE_NAMES: &[&str] = &[
    "virtiofs",
    "vsock",
    "vmw_vsock_virtio_transport_common",
    "vmw_vsock_virtio_transport",
];

/// One verified loadable module paired with [`kernel`].
pub struct KernelModule {
    /// Linux module name, without the `.ko` suffix.
    pub name: &'static str,
    /// Uncompressed ELF module bytes.
    pub bytes: Vec<u8>,
}

impl KernelModule {
    /// RFC 4648 base64 for carrying the module through a NoCloud seed.
    pub fn base64(&self) -> String {
        BASE64.encode(&self.bytes)
    }
}

/// The platform an image has to offer, in registry vocabulary.
fn platform_arch() -> &'static str {
    match host_arch() {
        "aarch64" => "arm64",
        "x86_64" => "amd64",
        other => other,
    }
}

// ---- references ------------------------------------------------------------

/// A parsed registry reference: `docker.io/library/nginx:latest`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reference {
    pub registry: String,
    pub repository: String,
    /// `:tag` or `@sha256:...`, as written.
    pub version: Version,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Version {
    Tag(String),
    Digest(String),
}

impl Reference {
    /// The name recorded on an instance and printed back to the user. Always
    /// fully qualified: `nginx` and `docker.io/library/nginx:latest` are the
    /// same image, and only one of them says so.
    pub fn canonical(&self) -> String {
        match &self.version {
            Version::Tag(t) => format!("{}/{}:{}", self.registry, self.repository, t),
            Version::Digest(d) => format!("{}/{}@{}", self.registry, self.repository, d),
        }
    }

    /// Filename-safe form of the canonical name, for the tag pointer.
    pub fn slug(&self) -> String {
        self.canonical()
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '.' {
                    c
                } else {
                    '-'
                }
            })
            .collect()
    }

    /// Docker Hub's registry is not at `docker.io`; every other registry is
    /// where it says it is.
    fn api_host(&self) -> &str {
        match self.registry.as_str() {
            DEFAULT_REGISTRY => "registry-1.docker.io",
            other => other,
        }
    }

    fn reference(&self) -> &str {
        match &self.version {
            Version::Tag(t) => t,
            Version::Digest(d) => d,
        }
    }
}

impl std::fmt::Display for Reference {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.canonical())
    }
}

/// Read a reference, or decide this string is not one.
///
/// `None` means "not an OCI reference" rather than "malformed": the caller
/// ([`crate::image::resolve`]) tries the catalog, urls and local files first,
/// and needs a syntactic answer it can fall through on. Registry grammar is
/// what does the deciding — repository components are lowercase by spec, so a
/// mistyped catalog alias with capitals is still rejected outright rather than
/// turning into a doomed network round trip.
pub fn parse(reference: &str) -> Option<Reference> {
    // An explicit scheme says "this is an image, do not guess".
    let body = reference
        .strip_prefix("docker://")
        .or_else(|| reference.strip_prefix("oci://"))
        .unwrap_or(reference);
    if body.is_empty() || body.starts_with('/') || body.ends_with('/') || body.contains("//") {
        return None;
    }

    let (path, version) = match body.split_once('@') {
        Some((path, digest)) => {
            if !is_digest(digest) {
                return None;
            }
            (path, Version::Digest(digest.to_owned()))
        }
        None => match body.rsplit_once(':') {
            // A colon in the first component is a registry port, not a tag.
            Some((path, tag)) if !tag.contains('/') => {
                if !is_tag(tag) {
                    return None;
                }
                (path, Version::Tag(tag.to_owned()))
            }
            _ => (body, Version::Tag("latest".to_owned())),
        },
    };

    let (registry, repository) = match path.split_once('/') {
        // A first component with a dot or a port is a hostname; anything else
        // is the first half of a Docker Hub repository name.
        Some((head, rest)) if head.contains('.') || head.contains(':') || head == "localhost" => {
            (head.to_owned(), rest.to_owned())
        }
        Some(_) => (DEFAULT_REGISTRY.to_owned(), path.to_owned()),
        None => (DEFAULT_REGISTRY.to_owned(), format!("library/{path}")),
    };

    if !repository.split('/').all(is_path_component) {
        return None;
    }
    Some(Reference {
        registry,
        repository,
        version,
    })
}

/// One path component of a repository name, per the distribution spec:
/// lowercase alphanumerics with single separators between them.
fn is_path_component(s: &str) -> bool {
    let mut chars = s.chars().peekable();
    let mut any = false;
    while let Some(c) = chars.next() {
        match c {
            'a'..='z' | '0'..='9' => any = true,
            '.' | '_' | '-' => {
                if !any {
                    return false;
                }
                // A separator run may only be `__`, and never trails.
                if c == '_' && chars.peek() == Some(&'_') {
                    chars.next();
                }
                match chars.peek() {
                    Some('a'..='z') | Some('0'..='9') => {}
                    _ => return false,
                }
            }
            _ => return false,
        }
    }
    any
}

fn is_tag(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.starts_with(|c: char| c.is_ascii_alphanumeric() || c == '_')
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
}

fn is_digest(s: &str) -> bool {
    match s.split_once(':') {
        Some((algo, hex)) => {
            !algo.is_empty()
                && hex.len() >= 32
                && hex
                    .chars()
                    .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        }
        None => false,
    }
}

// ---- the image config ------------------------------------------------------

/// The half of an OCI image config that decides what the machine runs.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Config {
    pub entrypoint: Vec<String>,
    pub cmd: Vec<String>,
    pub env: Vec<String>,
    pub workdir: Option<String>,
    pub user: Option<String>,
    /// `"80/tcp"`, as the image wrote them.
    pub exposed_ports: Vec<String>,
}

impl Config {
    fn from_json(v: &Value) -> Config {
        let c = &v["config"];
        let strings = |key: &str| -> Vec<String> {
            c[key]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|s| s.as_str().map(str::to_owned))
                        .collect()
                })
                .unwrap_or_default()
        };
        let text = |key: &str| -> Option<String> {
            c[key].as_str().filter(|s| !s.is_empty()).map(str::to_owned)
        };
        Config {
            entrypoint: strings("Entrypoint"),
            cmd: strings("Cmd"),
            env: strings("Env"),
            workdir: text("WorkingDir"),
            user: text("User").filter(|u| u != "root" && u != "0"),
            exposed_ports: c["ExposedPorts"]
                .as_object()
                .map(|m| m.keys().cloned().collect())
                .unwrap_or_default(),
        }
    }

    /// The command pid 1 runs: entrypoint then cmd, exactly as a container
    /// runtime composes them.
    pub fn argv(&self) -> Vec<String> {
        let mut argv = self.entrypoint.clone();
        argv.extend(self.cmd.iter().cloned());
        argv
    }

    /// TCP ports the image says it listens on. Informational — Asterism
    /// forwards what `ast create -p` asked for, not what the image hoped for.
    pub fn tcp_ports(&self) -> Vec<u16> {
        self.exposed_ports
            .iter()
            .filter_map(|p| p.split('/').next())
            .filter_map(|p| p.parse().ok())
            .collect()
    }

    fn to_json(&self) -> Value {
        serde_json::json!({
            "config": {
                "Entrypoint": self.entrypoint,
                "Cmd": self.cmd,
                "Env": self.env,
                "WorkingDir": self.workdir,
                "User": self.user,
                "ExposedPorts": self.exposed_ports.iter()
                    .map(|p| (p.clone(), serde_json::json!({})))
                    .collect::<serde_json::Map<_, _>>(),
            }
        })
    }
}

// ---- the store -------------------------------------------------------------

fn oci_dir() -> PathBuf {
    paths::images_dir().join("oci")
}

/// The ext4 image built from one manifest digest.
fn image_path(digest: &str) -> PathBuf {
    paths::images_dir().join(format!("oci-{}.raw", short(digest)))
}

fn config_path(digest: &str) -> PathBuf {
    paths::images_dir().join(format!("oci-{}.json", short(digest)))
}

/// Where a tag's current digest is remembered, so that resolving a reference
/// stays an offline, side-effect-free lookup.
fn pointer_path(reference: &Reference) -> PathBuf {
    oci_dir().join(format!("{}.digest", reference.slug()))
}

fn short(digest: &str) -> String {
    digest
        .rsplit(':')
        .next()
        .unwrap_or(digest)
        .chars()
        .take(16)
        .collect()
}

/// The built image for this reference, if this device has one.
///
/// Offline and pure: it reads the tag pointer a previous pull wrote and
/// nothing else, which is what lets `image::resolve` stay a lookup rather
/// than a network call.
pub fn stored(reference: &Reference) -> Option<PathBuf> {
    let path = image_path(&pointed_digest(reference)?);
    path.exists().then_some(path)
}

/// What a tag currently points at on this device. The pointer's first line
/// is the digest; its second is the reference it was written for, so
/// [`built`] can list the store without turning slugs back into names.
fn pointed_digest(reference: &Reference) -> Option<String> {
    let text = std::fs::read_to_string(pointer_path(reference)).ok()?;
    Some(text.lines().next()?.trim().to_owned())
}

/// Every OCI reference this device has built a filesystem for, canonical
/// and sorted. What `ast images` shows below the catalog.
///
/// Read off the tag pointers rather than off the `.raw` files: an image is
/// only usable if something can still name it, and the pointer is the name.
pub fn built() -> Result<Vec<String>> {
    let mut names = Vec::new();
    let listing = match std::fs::read_dir(oci_dir()) {
        Ok(l) => l,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(names),
        Err(e) => return Err(e).context("reading the image store"),
    };
    for entry in listing.flatten() {
        let path = entry.path();
        if path.extension().is_none_or(|e| e != "digest") {
            continue;
        }
        let Ok(pointer) = std::fs::read_to_string(&path) else {
            continue;
        };
        let mut lines = pointer.lines();
        // Digest first, then the reference it was written for: the file
        // *name* is a slug, and a slug is not a reference.
        let (Some(digest), Some(reference)) = (lines.next(), lines.next()) else {
            continue;
        };
        if image_path(digest.trim()).exists() {
            names.push(reference.trim().to_owned());
        }
    }
    names.sort();
    Ok(names)
}

/// The config the stored image was built from, for `ast status`.
pub fn stored_config(reference: &Reference) -> Option<Config> {
    let text = std::fs::read_to_string(config_path(&pointed_digest(reference)?)).ok()?;
    Some(Config::from_json(
        &serde_json::from_str::<Value>(&text).ok()?,
    ))
}

// ---- pulling ---------------------------------------------------------------

pub struct Pulled {
    pub digest: String,
    pub image: PathBuf,
    pub config: Config,
    /// False when the image was already built on this device.
    pub built: bool,
}

/// Pull a reference and leave a bootable ext4 image in the store.
///
/// Idempotent: a reference whose digest is already built is confirmed against
/// the registry (one small request) and then left alone.
pub fn pull(reference: &Reference, progress: bool) -> Result<Pulled> {
    let registry = Registry::open(reference)?;
    let (digest, manifest) = registry.manifest()?;

    let image = image_path(&digest);
    // Already built here — but "a file with the right name exists" is what
    // the store said before it verified anything. Confirm it is the image
    // that was adopted; if it is not, or if an older Asterism built it and
    // left no record of what it was, fall through and build it again. A
    // rebuild is minutes; booting bytes nobody can account for is worse.
    if image.exists() && verify::check(&image, Depth::from_env()).is_ok() {
        let config = stored_config(reference).unwrap_or_default();
        write_pointer(reference, &digest)?;
        return Ok(Pulled {
            digest,
            image,
            config,
            built: false,
        });
    }

    let config_digest = manifest["config"]["digest"]
        .as_str()
        .context("image manifest names no config")?;
    let config = Config::from_json(&serde_json::from_str::<Value>(&std::fs::read_to_string(
        registry.blob(config_digest, progress)?,
    )?)?);

    let layers: Vec<&Value> = manifest["layers"]
        .as_array()
        .context("image manifest lists no layers")?
        .iter()
        .collect();

    let stage = oci_dir().join(format!("build-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&stage);
    let root = stage.join("rootfs");
    std::fs::create_dir_all(&root)?;
    let built = (|| -> Result<()> {
        let mut tree = Tree::default();
        // Everything this filesystem was made of, recorded so that "what is
        // in this image" has an answer that does not need the registry to
        // still be serving the tag. Each of these was verified as it was
        // fetched; this is the receipt.
        let mut parents = vec![digest.clone(), config_digest.to_owned()];
        for (i, layer) in layers.iter().enumerate() {
            let digest = layer["digest"].as_str().context("layer has no digest")?;
            if progress {
                eprintln!("unpacking layer {}/{}", i + 1, layers.len());
            }
            let blob = registry.blob(digest, progress)?;
            unpack_layer(&blob, &root, &mut tree)
                .with_context(|| format!("unpacking layer {digest}"))?;
            parents.push(digest.to_owned());
        }
        furnish(&root, &config, &mut tree)?;
        build_ext4(&root, &tree, &image, &digest, reference, parents)
    })();
    let _ = std::fs::remove_dir_all(&stage);
    built?;

    std::fs::write(
        config_path(&digest),
        serde_json::to_vec_pretty(&config.to_json())?,
    )?;
    write_pointer(reference, &digest)?;
    Ok(Pulled {
        digest,
        image,
        config,
        built: true,
    })
}

fn write_pointer(reference: &Reference, digest: &str) -> Result<()> {
    let path = pointer_path(reference);
    std::fs::create_dir_all(path.parent().expect("pointer has a directory"))?;
    std::fs::write(path, format!("{digest}\n{}\n", reference.canonical()))?;
    Ok(())
}

/// Where a registry's bytes actually come from.
///
/// `curl` in production, and something else in a test — which is the only
/// way "the mirror served a different layer than the manifest named" becomes
/// a case that can be written down and run on a machine with no network. The
/// verification this file does is the whole point of it, so it has to be
/// testable without asking Docker Hub to misbehave.
trait Transport: Send + Sync {
    /// A document, as text.
    fn get(&self, url: &str, accept: Option<&str>, token: Option<&str>) -> Result<String>;
    /// A blob, into a file, optionally with a progress bar.
    fn fetch(&self, url: &str, token: Option<&str>, dest: &Path, progress: bool) -> Result<()>;
}

/// The real one.
struct Curl {
    curl: PathBuf,
}

impl Curl {
    fn args(&self, token: Option<&str>) -> Command {
        let mut cmd = Command::new(&self.curl);
        cmd.args(["-sS", "--fail", "-L"]);
        if let Some(token) = token {
            cmd.arg("-H").arg(format!("Authorization: Bearer {token}"));
        }
        cmd
    }
}

impl Transport for Curl {
    fn get(&self, url: &str, accept: Option<&str>, token: Option<&str>) -> Result<String> {
        let mut cmd = self.args(token);
        if let Some(accept) = accept {
            cmd.arg("-H").arg(format!("Accept: {accept}"));
        }
        output(cmd.arg(url))
    }

    fn fetch(&self, url: &str, token: Option<&str>, dest: &Path, progress: bool) -> Result<()> {
        let mut cmd = self.args(token);
        if progress {
            cmd.arg("--progress-bar");
        }
        let status = cmd
            .arg("-o")
            .arg(dest)
            .arg(url)
            .status()
            .context("running curl")?;
        if !status.success() {
            let _ = std::fs::remove_file(dest);
            bail!("downloading {url}");
        }
        Ok(())
    }
}

/// One registry, one repository, one anonymous pull token.
struct Registry<'a> {
    reference: &'a Reference,
    token: Option<String>,
    transport: Box<dyn Transport>,
    /// Where verified blobs are cached. A field rather than a call to
    /// [`oci_dir`] so a test can give this a directory of its own without
    /// touching a process-wide `ASTERISM_HOME` that its neighbours share.
    blobs: PathBuf,
}

const MANIFEST_TYPES: &str = "application/vnd.oci.image.index.v1+json, \
     application/vnd.docker.distribution.manifest.list.v2+json, \
     application/vnd.oci.image.manifest.v1+json, \
     application/vnd.docker.distribution.manifest.v2+json";

impl<'a> Registry<'a> {
    fn open(reference: &'a Reference) -> Result<Registry<'a>> {
        let curl = tool("curl")?;
        // Public images pull anonymously, which is still a token: the
        // registry hands one out to anybody who asks for `pull` scope. A
        // registry that needs no token at all simply refuses this, and the
        // requests go out unauthenticated.
        let (host, service) = match reference.registry.as_str() {
            DEFAULT_REGISTRY => ("auth.docker.io", "registry.docker.io"),
            other => (other, other),
        };
        let url = format!(
            "https://{host}/token?service={service}&scope=repository:{}:pull",
            reference.repository
        );
        let transport = Curl { curl };
        let token = transport
            .get(&url, None, None)
            .ok()
            .and_then(|body| serde_json::from_str::<Value>(&body).ok())
            .and_then(|v| {
                v["token"]
                    .as_str()
                    .or_else(|| v["access_token"].as_str())
                    .map(str::to_owned)
            });
        Ok(Registry {
            reference,
            token,
            transport: Box::new(transport),
            blobs: oci_dir().join("blobs"),
        })
    }

    fn get(&self, url: &str, accept: Option<&str>) -> Result<String> {
        self.transport.get(url, accept, self.token.as_deref())
    }

    /// A document the registry named by digest, checked against that digest
    /// before anything reads it.
    ///
    /// A manifest is the root of the whole image: every layer digest, and the
    /// config digest, are only as trustworthy as the document they are listed
    /// in. Verifying it is what turns the rest of the pull into a chain
    /// rather than a sequence of independent hopes.
    fn get_by_digest(&self, url: &str, accept: Option<&str>, digest: &str) -> Result<String> {
        // Parsed before the request, not after: a digest whose algorithm we
        // cannot compute means this image cannot be verified here at all, and
        // saying so before spending the network is the honest order.
        let want = Digest::parse(digest).with_context(|| {
            format!(
                "{} names its manifest with a digest Asterism cannot check",
                self.reference
            )
        })?;
        let body = self.get(url, accept)?;
        want.verify_bytes(
            body.as_bytes(),
            &format!("the manifest for {}", self.reference),
        )?;
        Ok(body)
    }

    /// The manifest for this host's platform, and the digest it is known by.
    ///
    /// A multi-platform reference is an index: this is where `linux/arm64` is
    /// chosen, and where an image that has no build for this machine says so
    /// instead of booting somebody else's architecture.
    fn manifest(&self) -> Result<(String, Value)> {
        let url = format!(
            "https://{}/v2/{}/manifests/{}",
            self.reference.api_host(),
            self.reference.repository,
            self.reference.reference()
        );
        // Asking by digest is the one case where the caller already knows
        // what the bytes must be, so it is checked here rather than trusted.
        let body = match &self.reference.version {
            Version::Digest(d) => self.get_by_digest(&url, Some(MANIFEST_TYPES), d),
            Version::Tag(_) => self.get(&url, Some(MANIFEST_TYPES)),
        }
        .with_context(|| format!("no image {} on {}", self.reference, self.reference.registry))?;
        let doc: Value = serde_json::from_str(&body).context("unreadable image manifest")?;

        let Some(list) = doc["manifests"].as_array() else {
            // A single-platform manifest: its digest is the one we asked by
            // (and just verified), or the content's own hash otherwise.
            let digest = match &self.reference.version {
                Version::Digest(d) => d.clone(),
                Version::Tag(_) => sha256_hex(body.as_bytes()),
            };
            return Ok((digest, doc));
        };

        let want = platform_arch();
        let picked = list
            .iter()
            .find(|m| {
                m["platform"]["os"] == "linux"
                    && m["platform"]["architecture"] == want
                    // Attestations ride in the index under the same shape.
                    && m["annotations"]["vnd.docker.reference.type"].is_null()
            })
            .with_context(|| {
                let have: Vec<String> = list
                    .iter()
                    .filter_map(|m| m["platform"]["architecture"].as_str())
                    .filter(|a| *a != "unknown")
                    .map(str::to_owned)
                    .collect();
                format!(
                    "{} has no linux/{want} build — it publishes {}",
                    self.reference,
                    have.join(", ")
                )
            })?;
        let digest = picked["digest"]
            .as_str()
            .context("index entry has no digest")?;
        let url = format!(
            "https://{}/v2/{}/manifests/{}",
            self.reference.api_host(),
            self.reference.repository,
            digest
        );
        // The index said this digest; the registry has to serve those bytes
        // and not another platform's, another tag's, or a mirror's idea of
        // them. Without this the architecture check above is advice.
        let body = self.get_by_digest(&url, Some(MANIFEST_TYPES), digest)?;
        Ok((digest.to_owned(), serde_json::from_str(&body)?))
    }

    /// A blob, cached by its own digest. Blobs are immutable and shared
    /// between images, so this is the layer cache too.
    fn blob(&self, digest: &str, progress: bool) -> Result<PathBuf> {
        // Before the directory is even made: a blob whose algorithm we
        // cannot compute is an unverifiable source, and this refuses it
        // ahead of any mutation of the store.
        let want = Digest::parse(digest)
            .with_context(|| format!("{} lists a blob Asterism cannot verify", self.reference))?;
        std::fs::create_dir_all(&self.blobs)?;
        let path = self.blobs.join(digest.replace(':', "-"));
        if path.exists() {
            return cached_blob(&path, &want)
                .with_context(|| format!("reusing the cached blob {digest}"));
        }
        let part = path.with_extension("part");
        let url = format!(
            "https://{}/v2/{}/blobs/{}",
            self.reference.api_host(),
            self.reference.repository,
            digest
        );
        let _ = std::fs::remove_file(&part);
        self.transport
            .fetch(&url, self.token.as_deref(), &part, progress)
            .with_context(|| format!("downloading {digest} from {}", self.reference.registry))?;
        // The registry named these bytes; this is where that claim is
        // settled. A truncated transfer and a substituted layer are the same
        // failure here, and neither takes the cache's name — and adoption
        // forces the bytes down before that name exists, because a
        // digest-named file that is half a blob is a lie every later pull
        // would believe.
        verify::adopt(
            &part,
            &path,
            Some(&want),
            Source::new("blob", &format!("{}/{}", self.reference, digest)),
        )?;
        Ok(path)
    }
}

/// A blob already in the cache, confirmed to still be the blob it is named
/// after.
///
/// The filename asserts a digest, and a filename is not evidence. A blob
/// adopted by this Asterism has a provenance record and costs a stat to
/// confirm; one left by an older version has none, so it is hashed against
/// its own name and either adopted properly or thrown away. Throwing it away
/// is the right end for it: the next line re-downloads it, and the
/// alternative is unpacking bytes nobody can vouch for into something a
/// machine boots.
fn cached_blob(path: &Path, want: &Digest) -> Result<PathBuf> {
    // A blob that was adopted here has a record and costs a stat to confirm;
    // one left by an older Asterism has none and is hashed against its own
    // name. Either way a failure ends the same: the file is deleted. A blob
    // is immutable, content-addressed and re-downloadable, so a bad one has
    // no value at all — and leaving it would make every retry hit the same
    // poison, which is the difference between a pull that heals itself and
    // one a user has to go and fix with `rm`.
    let sound = match verify::provenance(path) {
        Some(_) => verify::check(path, Depth::from_env()),
        None => want.verify_file(path, "it").map(|()| {
            // Unaccounted but genuine: adopt it properly so the next pull is
            // a stat rather than another full hash.
            let _ = verify::record(path, path, Source::new("blob", &want.to_string()));
        }),
    };
    if let Err(e) = sound {
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_file(verify::provenance_path(path));
        return Err(e).context(format!(
            "the cached copy of {want} is not that blob — it has been corrupted or \
             tampered with, so it was deleted. Run the pull again to fetch it afresh."
        ));
    }
    Ok(path.to_path_buf())
}

/// Content hash of a manifest we were handed by tag — the digest the image
/// is then named and addressed by.
///
/// In-process rather than through `shasum`: this value decides which file on
/// disk an image *is*, and the subprocess version had a fallback for hosts
/// with no `shasum` that quietly produced a non-cryptographic hash. A
/// forgeable content address is worse than no content address, because
/// everything downstream treats it as one.
fn sha256_hex(bytes: &[u8]) -> String {
    Digest::of_bytes(Algo::Sha256, bytes).to_string()
}

// ---- unpacking -------------------------------------------------------------

/// What the unpacked tree should look like once it is an ext4: the ownership
/// the layers asked for, the modes directories end up with, and how much
/// space it all needs.
///
/// Ownership is tracked rather than applied because a non-root unpack cannot
/// apply it — every file would belong to whoever ran `ast pull`. It is
/// replayed into the filesystem afterwards ([`build_ext4`]).
#[derive(Default)]
struct Tree {
    owners: BTreeMap<String, (u64, u64)>,
    dir_modes: BTreeMap<String, u32>,
    bytes: u64,
    entries: u64,
}

impl Tree {
    fn note(&mut self, path: &str, uid: u64, gid: u64) {
        self.owners.insert(path.to_owned(), (uid, gid));
        self.entries += 1;
    }

    /// A whiteout removes the record along with the files.
    fn forget(&mut self, prefix: &str) {
        let below = format!("{prefix}/");
        self.owners
            .retain(|p, _| p != prefix && !p.starts_with(&below));
        self.dir_modes
            .retain(|p, _| p != prefix && !p.starts_with(&below));
    }

    /// An opaque whiteout empties a directory but keeps the directory.
    fn forget_children(&mut self, dir: &str) {
        let below = if dir.is_empty() {
            String::new()
        } else {
            format!("{dir}/")
        };
        self.owners
            .retain(|p, _| !p.starts_with(&below) || p == dir);
        self.dir_modes
            .retain(|p, _| !p.starts_with(&below) || p == dir);
    }
}

/// Unpack one layer over the tree, honouring whiteouts.
///
/// Layers are applied in order and a later one wins, which is the whole of
/// the OCI layering model. Deletions travel as `.wh.` marker files: `.wh.foo`
/// removes `foo`, and `.wh..wh..opq` empties the directory it sits in.
fn unpack_layer(blob: &Path, root: &Path, tree: &mut Tree) -> Result<()> {
    let mut reader = decompress(blob)?;
    let mut archive = tar::Archive::new(&mut reader);
    archive.set_preserve_mtime(true);
    for entry in archive.entries()? {
        let mut entry = entry?;
        let Some(path) = guest_path(&entry.path()?) else {
            continue; // absolute or `..`: not ours to write
        };
        let (dir, name) = split(&path);

        if let Some(target) = name.strip_prefix(".wh.") {
            if target == ".wh..opq" {
                if let Ok(listing) = std::fs::read_dir(root.join(&dir)) {
                    for e in listing.flatten() {
                        let _ = remove(&e.path());
                    }
                }
                tree.forget_children(&dir);
            } else {
                let victim = join(&dir, target);
                let _ = remove(&root.join(&victim));
                tree.forget(&victim);
            }
            continue;
        }

        let header = entry.header().clone();
        let (uid, gid) = (header.uid().unwrap_or(0), header.gid().unwrap_or(0));
        let mode = header.mode().unwrap_or(0o644);
        let full = root.join(&path);

        if header.entry_type().is_dir() {
            std::fs::create_dir_all(&full)?;
            // Written to by later layers, so it stays writable until the
            // tree is final; the mode the image asked for is applied then.
            set_mode(&full, mode | 0o700)?;
            tree.dir_modes.insert(path.clone(), mode);
            tree.note(&path, uid, gid);
            continue;
        }
        if let Some(parent) = full.parent() {
            std::fs::create_dir_all(parent)?;
        }
        // A path that was something else in an earlier layer is replaced,
        // not merged into.
        if full.symlink_metadata().is_ok() {
            let _ = remove(&full);
        }
        entry.set_preserve_permissions(true);
        // `unpack_in` rather than `unpack`: it resolves hard links against
        // the rootfs the way the archive means them, and refuses on its own
        // account to write outside it.
        match entry.unpack_in(root) {
            Ok(true) => {}
            Ok(false) => continue,
            // Device nodes and fifos need root and mean nothing here: the
            // guest's own devtmpfs supplies /dev.
            Err(_) if !header.entry_type().is_file() && !header.entry_type().is_symlink() => {
                continue
            }
            Err(e) => return Err(e).with_context(|| format!("writing {path}")),
        }
        tree.bytes += header.size().unwrap_or(0);
        tree.note(&path, uid, gid);
    }
    Ok(())
}

/// Layers are tar, usually gzipped. `gzip` is on every unix this runs on and
/// a decompressor crate is not worth its weight for one pipe.
fn decompress(blob: &Path) -> Result<Box<dyn Read>> {
    let mut magic = [0u8; 2];
    let mut file = std::fs::File::open(blob)?;
    let gzipped = file.read_exact(&mut magic).is_ok() && magic == [0x1f, 0x8b];
    if !gzipped {
        // Uncompressed layers are legal and rare. Anything else — zstd, say —
        // fails in the tar reader with an honest message.
        return Ok(Box::new(std::fs::File::open(blob)?));
    }
    let child = Command::new(tool("gzip")?)
        .arg("-dc")
        .arg(blob)
        .stdout(Stdio::piped())
        .spawn()
        .context("running gzip")?;
    Ok(Box::new(child.stdout.expect("piped")))
}

/// A tar entry's path as it will exist in the guest: relative, normalised,
/// and refusing to point outside the rootfs.
fn guest_path(path: &Path) -> Option<String> {
    let mut parts: Vec<String> = Vec::new();
    for part in path.components() {
        match part {
            std::path::Component::Normal(p) => {
                let p = p.to_str()?;
                if p.contains('\n') {
                    return None;
                }
                parts.push(p.to_owned());
            }
            std::path::Component::CurDir => {}
            _ => return None,
        }
    }
    (!parts.is_empty()).then(|| parts.join("/"))
}

fn split(path: &str) -> (String, String) {
    match path.rsplit_once('/') {
        Some((dir, name)) => (dir.to_owned(), name.to_owned()),
        None => (String::new(), path.to_owned()),
    }
}

fn join(dir: &str, name: &str) -> String {
    if dir.is_empty() {
        name.to_owned()
    } else {
        format!("{dir}/{name}")
    }
}

fn remove(path: &Path) -> std::io::Result<()> {
    match path.symlink_metadata() {
        Ok(m) if m.is_dir() => std::fs::remove_dir_all(path),
        Ok(_) => std::fs::remove_file(path),
        Err(e) => Err(e),
    }
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode & 0o7777))?;
    Ok(())
}

#[cfg(windows)]
fn set_mode(_path: &Path, _mode: u32) -> Result<()> {
    // Windows ACLs do not have a Unix mode equivalent. The containing
    // Asterism home is the Windows privacy boundary; keep recording the
    // image's mode in the tree so a later Unix consumer does not lose it.
    Ok(())
}

// ---- making it bootable ----------------------------------------------------

/// Add what a container image does not carry and a machine cannot boot
/// without: the mount points a kernel expects, a static shell, and the init
/// that runs the image's entrypoint.
fn furnish(root: &Path, config: &Config, tree: &mut Tree) -> Result<()> {
    for dir in ["proc", "sys", "dev", "tmp", "run", "etc", "var", "root"] {
        let path = root.join(dir);
        if !path.exists() {
            std::fs::create_dir_all(&path)?;
            set_mode(&path, if dir == "tmp" { 0o1777 } else { 0o755 })?;
            tree.dir_modes
                .insert(dir.to_owned(), if dir == "tmp" { 0o1777 } else { 0o755 });
            tree.note(dir, 0, 0);
        }
    }

    let busybox = busybox_binary()?;
    let target = root.join(GUEST_BUSYBOX);
    std::fs::create_dir_all(target.parent().expect("busybox has a directory"))?;
    std::fs::copy(&busybox, &target)?;
    set_mode(&target, 0o755)?;
    tree.note(".asterism", 0, 0);
    tree.note(GUEST_BUSYBOX, 0, 0);
    tree.bytes += std::fs::metadata(&target)?.len();

    let init = root.join(GUEST_INIT);
    std::fs::create_dir_all(init.parent().expect("init has a directory"))?;
    let script = init_script(config);
    std::fs::write(&init, &script)?;
    set_mode(&init, 0o755)?;
    tree.note(GUEST_INIT, 0, 0);
    tree.bytes += script.len() as u64;
    Ok(())
}

/// The static busybox every generated init runs under, pulled once per
/// device and cached.
///
/// It comes from the registry rather than from the host: a macOS host has no
/// Linux binaries to give, and the puller that fetches every other image is
/// already here. `busybox:musl` is the statically linked build.
fn busybox_binary() -> Result<PathBuf> {
    let cached = oci_dir().join(format!("busybox-{}", host_arch()));
    if cached.exists() {
        // Same reasoning as a built image: a cached copy that cannot be
        // accounted for is lifted again rather than trusted.
        if verify::check(&cached, Depth::from_env()).is_ok() {
            return Ok(cached);
        }
        let _ = std::fs::remove_file(&cached);
    }
    let reference = parse(BUSYBOX_IMAGE).expect("the busybox reference is a constant");
    let registry = Registry::open(&reference)?;
    let (_, manifest) = registry
        .manifest()
        .context("fetching the busybox Asterism boots OCI images with")?;

    let stage = oci_dir().join(format!("busybox-build-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&stage);
    std::fs::create_dir_all(&stage)?;
    let lifted = (|| -> Result<()> {
        let mut tree = Tree::default();
        for layer in manifest["layers"]
            .as_array()
            .context("busybox has no layers")?
        {
            let digest = layer["digest"].as_str().context("layer has no digest")?;
            unpack_layer(&registry.blob(digest, false)?, &stage, &mut tree)?;
        }
        let from = stage.join("bin/busybox");
        if !from.exists() {
            bail!("{BUSYBOX_IMAGE} no longer ships /bin/busybox");
        }
        std::fs::create_dir_all(cached.parent().expect("cache has a directory"))?;
        // This binary becomes pid 1's shell inside every OCI instance on this
        // device, so it gets the same treatment as an image: adopted out of a
        // staged name with a record of where it came from, rather than copied
        // straight into the cache where an interrupted lift would leave half
        // an interpreter behind.
        set_mode(&from, 0o755)?;
        verify::adopt(&from, &cached, None, Source::new("busybox", BUSYBOX_IMAGE))?;
        Ok(())
    })();
    let _ = std::fs::remove_dir_all(&stage);
    lifted?;
    Ok(cached)
}

/// The init that runs an OCI image's entrypoint as pid 1.
///
/// Deliberately a shell script and deliberately generated: what it has to do
/// is exactly what the image config says, so the config is baked in rather
/// than parsed in the guest. It runs under the busybox in `/.asterism`, so
/// nothing here depends on the image shipping a shell — a `FROM scratch`
/// image with one static binary boots the same way nginx does.
///
/// Four jobs, in order:
///   * mount the pseudo-filesystems a container runtime would have mounted;
///   * take the address the backend wrote on the kernel cmdline (the image is
///     shared between instances, so the network cannot be baked in);
///   * run the entrypoint with the image's environment, as a child rather
///     than an exec, because pid 1 exiting is a kernel panic;
///   * power the machine off when the entrypoint exits — or when the power
///     button arrives, which is how `ast down` reaches a guest with no
///     init system to ask.
pub fn init_script(config: &Config) -> String {
    init_script_with_parts(
        config,
        &[],
        None,
        &Egress::default(),
        &Bootstrap::default(),
        None,
        None,
    )
}

/// Generate the per-instance init for an OCI rootfs.
///
/// The stored OCI image remains immutable and shared. Directory mounts and
/// secret handles are instance parts, so they are folded into the copy of
/// this script written to the instance's private root disk immediately
/// before boot.
fn init_script_with_parts(
    config: &Config,
    shares: &[Share],
    share_kind: Option<ShareKind>,
    egress: &Egress,
    bootstrap: &Bootstrap,
    gpu_boot: Option<&str>,
    virtiofs_module: Option<&[u8]>,
) -> String {
    let mut s = String::new();
    s.push_str(&format!("#!/{GUEST_BUSYBOX} sh\n"));
    s.push_str(
        "# Generated by Asterism. Runs an OCI image's entrypoint as pid 1.\n\
         BB=/.asterism/busybox\n\
         # BusyBox udhcpc invokes this same file with `bound` or `renew`.\n\
         # Keep the callback in pid 1's one generated inode: debugfs can\n\
         # allocate the same inode twice when adding files to a grown clone.\n\
         case \"$1\" in\n\
         bound|renew)\n\
         \x20 $BB ifconfig \"$interface\" \"$ip\" netmask \"${subnet:-255.255.255.0}\" up\n\
         \x20 $BB route del default dev \"$interface\" 2>/dev/null || true\n\
         \x20 for gateway in $router; do $BB route add default gw \"$gateway\" dev \"$interface\"; break; done\n\
         \x20 : > /etc/resolv.conf\n\
         \x20 for server in $dns; do echo \"nameserver $server\" >> /etc/resolv.conf; done\n\
         \x20 exit 0\n\
         \x20 ;;\n\
         *) [ -z \"$1\" ] || exit 0 ;;\n\
         esac\n\
         $BB mkdir -p /proc /sys /dev /tmp /run 2>/dev/null\n\
         $BB mount -t proc proc /proc 2>/dev/null\n\
         $BB mount -t sysfs sys /sys 2>/dev/null\n\
         $BB mount -t devtmpfs dev /dev 2>/dev/null\n\
         $BB mkdir -p /dev/pts /dev/shm 2>/dev/null\n\
         $BB mount -t devpts devpts /dev/pts 2>/dev/null\n\
         $BB mount -t tmpfs shm /dev/shm 2>/dev/null\n\
\n\
         # What this machine cannot discover for itself, the backend wrote on\n\
         # the kernel cmdline: either its address or the identity used for\n\
         # DHCP, plus the time (no RTC driver is loaded this early, and without\n\
         # it every line the image logs is dated 1970).\n\
         ip= gw= dns= hostname=\n\
         for w in $($BB cat /proc/cmdline); do\n\
         \x20 case \"$w\" in\n\
         \x20   asterism.ip=*)   ip=${w#asterism.ip=} ;;\n\
         \x20   asterism.gw=*)   gw=${w#asterism.gw=} ;;\n\
         \x20   asterism.dns=*)  dns=${w#asterism.dns=} ;;\n\
         \x20   asterism.hostname=*) hostname=${w#asterism.hostname=} ;;\n\
         \x20   asterism.time=*) $BB date -s \"@${w#asterism.time=}\" >/dev/null 2>&1 ;;\n\
         \x20 esac\n\
         done\n\
         nic=\n\
         for d in /sys/class/net/*; do\n\
         \x20 n=${d##*/}\n\
         \x20 [ \"$n\" = lo ] && continue\n\
         \x20 nic=$n\n\
         \x20 break\n\
         done\n\
         $BB ip link set lo up 2>/dev/null\n\
         if [ -n \"$nic\" ] && [ -n \"$ip\" ]; then\n\
         \x20 $BB ip addr add \"$ip\" dev \"$nic\" 2>/dev/null\n\
         \x20 $BB ip link set \"$nic\" up 2>/dev/null\n\
         \x20 [ -n \"$gw\" ] && $BB ip route add default via \"$gw\" 2>/dev/null\n\
         elif [ -n \"$nic\" ]; then\n\
         \x20 $BB ip link set \"$nic\" up 2>/dev/null\n\
         \x20 [ -n \"$hostname\" ] && $BB hostname \"$hostname\" 2>/dev/null\n\
         \x20 if ! $BB udhcpc -n -q -i \"$nic\" ${hostname:+-x hostname:$hostname} \\\n\
         \x20      -s /asterism-init; then\n\
         \x20   echo \"asterism: DHCP did not give $nic an address\"\n\
         \x20   $BB poweroff -f\n\
         \x20 fi\n\
         fi\n\
         [ -n \"$dns\" ] && echo \"nameserver $dns\" > /etc/resolv.conf 2>/dev/null\n\
         \n\
         # `ast down` asks for a power button; with no init system in the image,\n\
         # this is what hears it. One evdev read blocks until it is pressed.\n\
         powerdown() {\n\
         \x20 [ -n \"$child\" ] && $BB kill -TERM \"$child\" 2>/dev/null\n\
         \x20 i=0\n\
         \x20 while [ $i -lt 100 ] && $BB kill -0 \"$child\" 2>/dev/null; do\n\
         \x20   $BB sleep 0.1\n\
         \x20   i=$((i + 1))\n\
         \x20 done\n\
         \x20 halt\n\
         }\n\
         halt() {\n\
         \x20 $BB sync\n\
         \x20 $BB mount -o remount,ro / 2>/dev/null\n\
         \x20 $BB poweroff -f\n\
         }\n\
         \n",
    );

    if let Some(module) = virtiofs_module {
        s.push_str(
            "# The pinned cloud kernel builds virtiofs as a module, but its\n\
             # cloud initrd omits it and an OCI rootfs has no matching module tree.\n\
             if ! $BB grep -q virtiofs /proc/filesystems; then\n\
             \x20 if ! $BB base64 -d > /run/asterism-virtiofs.ko <<'ASTERISM_VIRTIOFS_MODULE'\n",
        );
        let encoded = BASE64.encode(module);
        for line in encoded.as_bytes().chunks(76) {
            s.push_str(std::str::from_utf8(line).expect("base64 is ASCII"));
            s.push('\n');
        }
        s.push_str(
            "ASTERISM_VIRTIOFS_MODULE\n\
             \x20 then\n\
             \x20   echo 'asterism: could not materialize the virtiofs kernel module'\n\
             \x20   halt\n\
             \x20 fi\n\
             \x20 if ! $BB insmod /run/asterism-virtiofs.ko; then\n\
             \x20   echo 'asterism: could not load the virtiofs kernel module'\n\
             \x20   halt\n\
             \x20 fi\n\
             \x20 $BB rm -f /run/asterism-virtiofs.ko\n\
             fi\n",
        );
    }

    if !shares.is_empty() {
        let kind = share_kind.expect("shares are only passed with a transport");
        for share in shares {
            let (fs, options) = match kind {
                ShareKind::NinePfs => (
                    "9p",
                    "-o trans=virtio,version=9p2000.L,msize=262144,access=client",
                ),
                ShareKind::Virtiofs => ("virtiofs", ""),
            };
            s.push_str(&format!(
                "$BB mkdir -p {where_}\n\
                 if ! $BB mount -t {fs} {options} {tag} {where_}; then\n\
                 \x20 echo {failure}\n\
                 \x20 halt\n\
                 fi\n",
                where_ = sh_quote(&share.guest_path),
                fs = fs,
                options = options,
                tag = sh_quote(&share.tag),
                failure = sh_quote(&format!(
                    "asterism: could not mount volume {} at {}",
                    share.label, share.guest_path
                )),
            ));
        }
    }

    for var in &config.env {
        if let Some((name, value)) = var.split_once('=') {
            if is_env_name(name) {
                s.push_str(&format!("export {name}={}\n", sh_quote(value)));
            }
        }
    }
    // Image Env is untrusted input and may itself name BB, a proxy variable,
    // or a secret's destination. Reassert the runtime path and instance
    // bindings afterwards so the image cannot replace Asterism's control
    // binary or route a handle around the policy proxy.
    s.push_str("BB=/.asterism/busybox\n");
    if !egress.is_empty() {
        s.push_str(
            "# The per-instance CA is public material. Write it from this one\n\
             # generated inode rather than allocating another file with debugfs.\n\
             $BB cat > /.asterism/egress-ca.pem <<'ASTERISM_EGRESS_CA'\n",
        );
        s.push_str(&egress.ca_pem);
        if !egress.ca_pem.ends_with('\n') {
            s.push('\n');
        }
        s.push_str("ASTERISM_EGRESS_CA\n");
        s.push_str(
            "# Install the public egress CA without assuming a distribution.\n\
             for bundle in /etc/ssl/certs/ca-certificates.crt \\\n\
             \x20 /etc/pki/tls/certs/ca-bundle.crt /etc/ssl/cert.pem; do\n\
             \x20 if [ -s \"$bundle\" ]; then\n\
             \x20   $BB cat \"$bundle\" /.asterism/egress-ca.pem > /.asterism/ca-bundle.pem\n\
             \x20   break\n\
             \x20 fi\n\
             done\n\
             [ -s /.asterism/ca-bundle.pem ] || $BB cp /.asterism/egress-ca.pem /.asterism/ca-bundle.pem\n\
             export SSL_CERT_FILE='/.asterism/ca-bundle.pem'\n\
             export CURL_CA_BUNDLE='/.asterism/ca-bundle.pem'\n\
             export REQUESTS_CA_BUNDLE='/.asterism/ca-bundle.pem'\n\
             export NODE_EXTRA_CA_CERTS='/.asterism/egress-ca.pem'\n",
        );
        for (name, value) in seed::egress_environment(egress) {
            s.push_str(&format!("export {name}={}\n", sh_quote(&value)));
        }
    }
    if !bootstrap.is_empty() {
        s.push_str(
            "# OCI guests have no cloud-init or systemd. Materialize the same\n\
             # resolved bootstrap files here and run the shared driver directly.\n\
             $BB mkdir -p /bin /var/log\n\
             [ -e /bin/sh ] || $BB ln -s /.asterism/busybox /bin/sh\n",
        );
        for (index, (path, mode, content)) in bootstrap.files().into_iter().enumerate() {
            let parent = Path::new(&path)
                .parent()
                .and_then(Path::to_str)
                .expect("a bootstrap guest file has an absolute parent");
            let mut delimiter = format!("ASTERISM_BOOTSTRAP_{index}");
            while content.lines().any(|line| line == delimiter) {
                delimiter.push('_');
            }
            s.push_str(&format!(
                "$BB mkdir -p {parent}\n\
                 $BB cat > {path} <<'{delimiter}'\n",
                parent = sh_quote(parent),
                path = sh_quote(&path),
            ));
            s.push_str(&content);
            if !content.ends_with('\n') {
                s.push('\n');
            }
            s.push_str(&format!(
                "{delimiter}\n$BB chmod {mode} {}\n",
                sh_quote(&path)
            ));
        }
        s.push_str(
            "($BB sh /usr/local/sbin/asterism-bootstrap \
               > /var/log/asterism-bootstrap.log 2>&1) &\n",
        );
    }
    if let Some(gpu_boot) = gpu_boot {
        s.push_str("# Materialize the attached guest-local GPU projection.\n");
        s.push_str(gpu_boot);
    }
    if let Some(dir) = &config.workdir {
        s.push_str(&format!(
            "$BB mkdir -p {0} 2>/dev/null\ncd {0} || exit 1\n",
            sh_quote(dir)
        ));
    }

    let argv = config.argv();
    let command = if argv.is_empty() {
        // Nothing to run is not a machine; say so on the console rather than
        // powering off with no explanation.
        "echo 'asterism: this image declares no entrypoint or cmd' ; false".to_owned()
    } else {
        let words: Vec<String> = argv.iter().map(|a| sh_quote(a)).collect();
        match &config.user {
            Some(user) => format!("$BB setuidgid {} {}", sh_quote(user), words.join(" ")),
            None => words.join(" "),
        }
    };
    s.push_str(&format!(
        "echo 'asterism: starting the image entrypoint'\n\
         {command} &\n\
         child=$!\n\
         for e in /dev/input/event*; do\n\
         \x20 [ -e \"$e\" ] || continue\n\
         \x20 ($BB dd if=\"$e\" bs=64 count=1 >/dev/null 2>&1 && powerdown) &\n\
         \x20 break\n\
         done\n\
         wait $child\n\
         status=$?\n\
         echo \"asterism: the entrypoint exited with status $status\"\n\
         halt\n"
    ));
    s
}

/// Refresh the generated init in one instance's private OCI root disk.
///
/// `source` is the verified store image the disk was cloned from. Its JSON
/// sidecar supplies the image's entrypoint and environment; `root` is the
/// writable clone that receives only this instance's parts. The operation is
/// deliberately on the boot path, not `prepare`, because snapshot listing
/// and other disk-only operations must remain read-only.
pub fn configure_instance(
    source: &Path,
    root: &Path,
    shares: &[Share],
    share_kind: Option<ShareKind>,
    egress: &Egress,
    bootstrap: &Bootstrap,
    gpu_boot: Option<&str>,
) -> Result<()> {
    if shares.is_empty() != share_kind.is_none() {
        bail!("an OCI directory share needs exactly one guest transport");
    }
    let sidecar = source.with_extension("json");
    let private_sidecar = root
        .parent()
        .context("an OCI root disk has no directory")?
        .join("oci-config.json");
    let text = match std::fs::read_to_string(&sidecar) {
        Ok(text) => {
            if std::fs::read_to_string(&private_sidecar).ok().as_deref() != Some(text.as_str()) {
                durable::commit(&private_sidecar, text.as_bytes()).with_context(|| {
                    format!("recording OCI config at {}", private_sidecar.display())
                })?;
            }
            text
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            std::fs::read_to_string(&private_sidecar).with_context(|| {
                format!(
                    "the OCI config is absent from both {} and the moved instance at {}",
                    sidecar.display(),
                    private_sidecar.display()
                )
            })?
        }
        Err(e) => {
            return Err(e).with_context(|| format!("reading OCI config at {}", sidecar.display()));
        }
    };
    let doc: Value = serde_json::from_str(&text)
        .with_context(|| format!("reading OCI config at {}", sidecar.display()))?;
    let config = Config::from_json(&doc);
    let module = if share_kind == Some(ShareKind::Virtiofs) {
        Some(virtiofs_module()?)
    } else {
        None
    };
    let init = init_script_with_parts(
        &config,
        shares,
        share_kind,
        egress,
        bootstrap,
        gpu_boot,
        module.as_deref(),
    );
    rewrite_guest_files(root, &init)
        .with_context(|| format!("configuring OCI guest disk {}", root.display()))
}

/// Replace Asterism's generated init inside an ext4 image without mounting it.
/// This is the same e2fsprogs seam pull uses on macOS.
///
/// There is deliberately one write. `debugfs write` has been observed to
/// reuse one newly allocated inode for two directory entries on a filesystem
/// grown after cloning. The init doubles as the DHCP hook and writes the
/// public egress CA at boot, so no second guest file needs allocating here.
fn rewrite_guest_files(root: &Path, init: &str) -> Result<()> {
    const S_IFREG: u32 = 0o100000;
    let e2fsck = e2fs_tool("e2fsck")?;
    let debugfs = e2fs_tool("debugfs")?;
    let dir = root.parent().context("an OCI root disk has no directory")?;
    let suffix = std::process::id();
    let init_host = dir.join(format!(".asterism-init-{suffix}"));
    let commands = dir.join(format!(".asterism-debugfs-{suffix}"));
    for path in [&init_host, &commands] {
        if path.to_string_lossy().contains('"') {
            bail!("{} contains a quote debugfs cannot escape", path.display());
        }
    }

    // The old multi-write implementation could leave two directory entries
    // naming an inode whose link count was one. The filesystem still called
    // itself clean, so force the offline check: this both upgrades those
    // private disks and makes a disk recovered after a hard stop safe to edit.
    let check = || -> Result<()> {
        let checked = Command::new(&e2fsck)
            .args(["-fy"])
            .arg(root)
            .output()
            .with_context(|| format!("checking OCI guest disk {}", root.display()))?;
        if !matches!(checked.status.code(), Some(0 | 1)) {
            bail!(
                "e2fsck could not repair OCI guest disk {} (status {}): {}{}",
                root.display(),
                checked.status,
                String::from_utf8_lossy(&checked.stdout),
                String::from_utf8_lossy(&checked.stderr),
            );
        }
        Ok(())
    };
    check()?;

    let result = (|| -> Result<()> {
        std::fs::write(&init_host, init)?;
        // Deletion and allocation are separate filesystem transactions. A
        // second check closes the orphan/bitmap state left by deleting a
        // legacy aliased inode before the sole new inode is allocated.
        std::fs::write(
            &commands,
            format!(
                "rm /{GUEST_DHCP}\nrm /{GUEST_EGRESS_CA}\n\
                 rm /{LEGACY_GUEST_INIT}\nrm /{MERGED_USR_GUEST_INIT}\nrm /{GUEST_INIT}\n"
            ),
        )?;
        run(Command::new(&debugfs)
            .arg("-w")
            .arg("-f")
            .arg(&commands)
            .arg(root))?;
        check()?;

        let script = format!(
            "write \"{}\" /{GUEST_INIT}\n\
             sif /{GUEST_INIT} mode 0{:o}\nsif /{GUEST_INIT} uid 0\nsif /{GUEST_INIT} gid 0\n",
            init_host.display(),
            S_IFREG | 0o755,
        );
        std::fs::write(&commands, script)?;
        run(Command::new(&debugfs)
            .arg("-w")
            .arg("-f")
            .arg(&commands)
            .arg(root))
    })();
    for path in [&init_host, &commands] {
        let _ = std::fs::remove_file(path);
    }
    result
}

fn is_env_name(name: &str) -> bool {
    !name.is_empty()
        && !name.starts_with(|c: char| c.is_ascii_digit())
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Single-quote for `sh`: everything inside is literal, and the only thing
/// that has to be spelled out is a quote itself.
fn sh_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

// ---- the filesystem --------------------------------------------------------

/// Turn the unpacked tree into a bootable ext4 image.
///
/// `mke2fs -d` populates a filesystem from a directory without root and
/// without a loopback mount — the only route to ext4 on macOS that does not
/// mean booting a helper guest to run `mkfs` for us. It copies the *host's*
/// ownership, which a non-root unpack got wrong by construction, so a single
/// `debugfs` pass replays what the layers actually said.
fn build_ext4(
    root: &Path,
    tree: &Tree,
    image: &Path,
    digest: &str,
    reference: &Reference,
    parents: Vec<String>,
) -> Result<()> {
    let mke2fs = e2fs_tool("mke2fs")?;
    let part = image.with_extension("raw.part");
    let _ = std::fs::remove_file(&part);
    std::fs::create_dir_all(image.parent().expect("the store has a directory"))?;

    // Room for the image plus somewhere for it to write. A container's
    // writable layer is normally the host's problem; here it is this slack,
    // and `ast create --disk` cannot help because the filesystem is built
    // once and shared by every instance made from it.
    let mib = (tree.bytes / (1 << 20)) * 14 / 10 + 256;
    let inodes = tree.entries + tree.entries / 2 + 2048;

    run(Command::new(mke2fs)
        .args(["-q", "-F", "-t", "ext4", "-b", "4096"])
        .args(["-E", "root_owner=0:0"])
        .args(["-N", &inodes.to_string()])
        .args(["-L", "asterism"])
        .arg("-d")
        .arg(root)
        .arg(&part)
        .arg(format!("{mib}M")))
    .with_context(|| format!("building an ext4 filesystem for {digest}"))?;

    apply_ownership(tree, &part)?;
    // No upstream ever published a digest for this file — `mke2fs` made it
    // out of layers that were each verified on the way in. So it is addressed
    // by our own hash, with the manifest, config and layer digests it came
    // out of recorded beside it. That is what makes it accountable at boot,
    // and what stops a half-built image (the `.part` above) from ever being
    // mistaken for a finished one.
    verify::adopt(
        &part,
        image,
        None,
        Source::new("oci-rootfs", &reference.canonical()).derived_from(parents),
    )?;
    Ok(())
}

/// Replay the layers' ownership into the built filesystem.
///
/// `mke2fs -d` has no way to be told "this file belongs to root"; it copies
/// what it sees, and what it sees is whoever ran `ast pull`. `debugfs` can
/// set an inode's fields directly, so the whole tree is corrected in one
/// process with one command file.
/// The `S_IFDIR` half of an inode's mode.
const S_IFDIR: u32 = 0o40000;

fn apply_ownership(tree: &Tree, image: &Path) -> Result<()> {
    let mut script = String::new();
    for (path, (uid, gid)) in &tree.owners {
        // debugfs quotes with `"`, and has no escape for one inside a name.
        if path.contains('"') {
            continue;
        }
        script.push_str(&format!("sif \"/{path}\" uid {uid}\n"));
        script.push_str(&format!("sif \"/{path}\" gid {gid}\n"));
    }
    for (path, mode) in &tree.dir_modes {
        if path.contains('"') {
            continue;
        }
        // Directories were left writable while later layers wrote into them.
        //
        // `mode` here is the whole of ext4's i_mode, type bits and all, so
        // the directory bit goes back in: without it the kernel reads the
        // inode as a corrupt file and refuses the whole tree with "bogus
        // i_mode".
        script.push_str(&format!(
            "sif \"/{path}\" mode 0{:o}\n",
            S_IFDIR | (mode & 0o7777)
        ));
    }
    if script.is_empty() {
        return Ok(());
    }
    let commands = image.with_extension("debugfs");
    std::fs::write(&commands, script)?;
    let result = run(Command::new(e2fs_tool("debugfs")?)
        .arg("-w")
        .arg("-f")
        .arg(&commands)
        .arg(image));
    let _ = std::fs::remove_file(&commands);
    result.context("setting file ownership in the image")
}

/// e2fsprogs is keg-only on Homebrew — its tools are deliberately kept out of
/// `$PATH` so they cannot be mistaken for the system's — so the usual `tool()`
/// search would miss the one install most macOS devices have.
fn e2fs_tool(name: &str) -> Result<PathBuf> {
    let candidates = [
        PathBuf::from("/opt/homebrew/opt/e2fsprogs/sbin").join(name),
        PathBuf::from("/usr/local/opt/e2fsprogs/sbin").join(name),
        PathBuf::from("/sbin").join(name),
        PathBuf::from("/usr/sbin").join(name),
    ];
    for c in candidates {
        if c.exists() {
            return Ok(c);
        }
    }
    tool(name).map_err(|_| {
        anyhow::anyhow!(
            "{name} not found — OCI images are built into an ext4 filesystem \
             with e2fsprogs, which macOS does not ship: brew install e2fsprogs"
        )
    })
}

// ---- the guest kernel ------------------------------------------------------

/// Where the kernel and initrd live once fetched.
pub fn kernel_paths() -> (PathBuf, PathBuf) {
    let dir = paths::images_dir().join("kernel");
    let arch = host_arch();
    (
        dir.join(format!("{arch}-vmlinuz")),
        dir.join(format!("{arch}-initrd")),
    )
}

fn virtiofs_module_path() -> PathBuf {
    kernel_module_path("virtiofs")
}

fn kernel_module_path(name: &str) -> PathBuf {
    paths::images_dir()
        .join("kernel")
        .join(format!("{}-{name}.ko", host_arch()))
}

/// The verified module paired with the OCI guest kernel.
///
/// Only VZ directory shares need this. QEMU supplies 9p instead, so callers
/// that do not select virtiofs never read or embed the module.
fn virtiofs_module() -> Result<Vec<u8>> {
    let module = virtiofs_module_path();
    if !module.exists() {
        bail!(
            "no virtiofs module on this device — refresh the OCI boot inputs: \
             ast pull <image>"
        );
    }
    verify::check(&module, Depth::from_env()).context("the virtiofs module this device fetched")?;
    std::fs::read(&module).with_context(|| format!("reading {}", module.display()))
}

/// Verified loadable modules paired with the direct-boot kernel.
///
/// Returned in load order: virtiofs first, then core socket support, the
/// common virtio transport, and finally the concrete transport Cloud
/// Hypervisor exposes. Direct boot cannot fall back to the root disk's module
/// tree: that disk may be Debian while the running kernel is Ubuntu's pinned
/// cloud kernel.
pub fn direct_boot_modules() -> Result<Vec<KernelModule>> {
    KERNEL_MODULE_NAMES
        .iter()
        .map(|&name| {
            let path = kernel_module_path(name);
            if !path.exists() {
                bail!(
                    "no {name} module on this device — refresh the native Linux boot inputs: ast pull <image>"
                );
            }
            verify::check(&path, Depth::from_env())
                .with_context(|| format!("the {name} module this device fetched"))?;
            Ok(KernelModule {
                name,
                bytes: std::fs::read(&path)
                    .with_context(|| format!("reading {}", path.display()))?,
            })
        })
        .collect()
}

/// The kernel an OCI instance boots, or why this device has not got one.
///
/// Read-only, so the daemon can ask without downloading: fetching is the
/// CLI's job at `ast pull`, in the foreground where the user can see it.
///
/// Verified here rather than only at fetch time, because this is the last
/// thing that happens before a hypervisor is handed a kernel image and told
/// to execute it. Nothing else in the boot path looks at these two files.
pub fn kernel() -> Result<(PathBuf, PathBuf)> {
    let (kernel, initrd) = kernel_paths();
    if !kernel.exists() || !initrd.exists() {
        bail!(
            "no guest kernel on this device — an OCI image has no kernel of its \
             own, so one is fetched once: ast pull <image>"
        );
    }
    let depth = Depth::from_env();
    verify::check(&kernel, depth).context("the guest kernel this device fetched")?;
    verify::check(&initrd, depth).context("the guest initrd this device fetched")?;
    Ok((kernel, initrd))
}

/// The kernel image expected by a native Linux boot loader such as VZ's.
///
/// Ubuntu's arm64 `vmlinuz` is gzip-compressed. QEMU accepts that publisher
/// artifact directly, while Virtualization.framework requires the raw Linux
/// image. Keep the pinned download as the source of truth and account for the
/// decompressed bytes as a derived boot artifact beside it.
pub fn linux_boot_kernel() -> Result<(PathBuf, PathBuf)> {
    let (kernel, initrd) = kernel()?;
    let mut magic = [0u8; 2];
    let mut source = std::fs::File::open(&kernel)?;
    if source.read_exact(&mut magic).is_err() || magic != [0x1f, 0x8b] {
        return Ok((kernel, initrd));
    }

    let parent = verify::provenance(&kernel)
        .context("the verified guest kernel has no provenance record")?
        .content
        .to_string();
    let raw = kernel.with_file_name(format!("{}-vmlinux", host_arch()));
    ensure_uncompressed_kernel(&kernel, &raw, &parent)?;
    Ok((raw, initrd))
}

fn ensure_uncompressed_kernel(source: &Path, dest: &Path, parent: &str) -> Result<()> {
    if dest.exists()
        && verify::check(dest, Depth::from_env()).is_ok()
        && verify::provenance(dest).is_some_and(|record| record.derived_from == [parent])
    {
        return Ok(());
    }

    let _ = std::fs::remove_file(dest);
    let _ = std::fs::remove_file(verify::provenance_path(dest));
    let part = dest.with_extension("part");
    let _ = std::fs::remove_file(&part);
    let output_file =
        std::fs::File::create(&part).with_context(|| format!("creating {}", part.display()))?;
    let result = run(Command::new(tool("gzip")?)
        .arg("-dc")
        .arg(source)
        .stdout(Stdio::from(output_file)))
    .context("decompressing the guest kernel for the native Linux boot loader");
    if let Err(error) = result {
        let _ = std::fs::remove_file(&part);
        return Err(error);
    }

    let origin = source.display().to_string();
    verify::adopt(
        &part,
        dest,
        None,
        Source::new("linux-kernel", &origin).derived_from([parent.to_owned()]),
    )?;
    Ok(())
}

/// Fetch the guest kernel if this device has not got one. Idempotent.
///
/// A file that is present but cannot be accounted for is re-fetched rather
/// than kept: this is the one artifact on the device whose bytes the host
/// hands straight to a hypervisor's kernel loader.
pub fn ensure_kernel(fetch: impl Fn(&str, &Path) -> Result<()>) -> Result<bool> {
    let arch = host_arch();
    let pinned = KERNELS
        .iter()
        .find(|k| k.arch == arch)
        .with_context(|| format!("no guest kernel published for {arch}"))?;
    let (kernel, initrd) = kernel_paths();
    let fetched_kernel = ensure_kernel_at(pinned, &kernel, &initrd, &fetch)?;

    let pinned_module = VIRTIOFS_MODULES
        .iter()
        .find(|module| module.arch == arch)
        .with_context(|| format!("no guest kernel modules published for {arch}"))?;
    let modules: Vec<_> = KERNEL_MODULE_NAMES
        .iter()
        .map(|&name| (name, kernel_module_path(name)))
        .collect();
    let fetched_module = ensure_kernel_modules_at(pinned_module, &modules, &fetch)?;
    Ok(fetched_kernel || fetched_module)
}

/// The whole of [`ensure_kernel`] with the store's paths passed in.
///
/// Split out so the tests can drive it against a temporary directory and a
/// fetcher that misbehaves. There is no other way to check what happens on a
/// *first* fetch — the case where the device has nothing to contradict what
/// arrives — without either a network or a process-wide `ASTERISM_HOME` the
/// neighbouring tests share.
fn ensure_kernel_at(
    pinned: &GuestKernel,
    kernel: &Path,
    initrd: &Path,
    fetch: impl Fn(&str, &Path) -> Result<()>,
) -> Result<bool> {
    std::fs::create_dir_all(kernel.parent().expect("the kernel has a directory"))?;

    let mut fetched = false;
    for (want, dest, kind) in [
        (&pinned.kernel, kernel, "kernel"),
        (&pinned.initrd, initrd, "initrd"),
    ] {
        // Parsed before anything is fetched or removed, so a digest this
        // build cannot compute refuses the whole operation with the store
        // exactly as it was.
        let expected = want.expected(&format!("the guest {kind}"))?;
        if dest.exists() {
            if verify::check(dest, Depth::from_env()).is_ok() {
                continue;
            }
            let _ = std::fs::remove_file(dest);
            let _ = std::fs::remove_file(verify::provenance_path(dest));
        }
        let part = dest.with_extension("part");
        let _ = std::fs::remove_file(&part);
        fetch(want.url, &part)
            .with_context(|| format!("fetching the guest {kind} from {}", want.url))?;
        // A first fetch is checked against what Ubuntu published, not
        // remembered as whatever turned up. This is the line that decides
        // whether a device that has never had a kernel can be given one by
        // anybody who can answer for the mirror.
        verify::adopt(&part, dest, Some(&expected), Source::new(kind, want.url))?;
        fetched = true;
    }
    Ok(fetched)
}

/// Fetch one pinned Ubuntu module package and retain the matching drivers.
fn ensure_kernel_modules_at(
    pinned: &GuestModule,
    modules: &[(&str, PathBuf)],
    fetch: impl Fn(&str, &Path) -> Result<()>,
) -> Result<bool> {
    let expected = pinned.package.expected("the guest kernel module package")?;
    let parent = expected.to_string();
    if modules.iter().all(|(_, module)| {
        module.exists()
            && verify::check(module, Depth::from_env()).is_ok()
            && verify::provenance(module)
                .is_some_and(|record| record.derived_from == [parent.as_str()])
    }) {
        return Ok(false);
    }

    let directory = modules
        .first()
        .and_then(|(_, module)| module.parent())
        .context("the guest module set is empty")?;
    std::fs::create_dir_all(directory)?;
    let package = directory.join(format!("{}-modules.deb.part", pinned.arch));
    let parts: Vec<_> = modules
        .iter()
        .map(|(name, module)| (*name, module.clone(), module.with_extension("ko.part")))
        .collect();
    for (_, module, part) in &parts {
        let _ = std::fs::remove_file(module);
        let _ = std::fs::remove_file(verify::provenance_path(module));
        let _ = std::fs::remove_file(part);
    }
    let _ = std::fs::remove_file(&package);

    let result = (|| -> Result<()> {
        fetch(pinned.package.url, &package).with_context(|| {
            format!(
                "fetching the guest kernel module package from {}",
                pinned.package.url
            )
        })?;
        expected
            .verify_file(&package, "the downloaded guest kernel module package")
            .context("Ubuntu's kernel module package was discarded")?;
        let outputs: Vec<_> = parts
            .iter()
            .map(|(name, _, part)| (*name, part.clone()))
            .collect();
        extract_kernel_modules(&package, &outputs)?;
        for (name, module, part) in &parts {
            let mut magic = [0u8; 4];
            std::fs::File::open(part)?.read_exact(&mut magic)?;
            if magic != *b"\x7fELF" {
                bail!("Ubuntu's {name} module is not an ELF object");
            }
            verify::adopt(
                part,
                module,
                None,
                Source::new("kernel-module", pinned.package.url).derived_from([parent.clone()]),
            )?;
        }
        Ok(())
    })();
    let _ = std::fs::remove_file(&package);
    for (_, _, part) in &parts {
        let _ = std::fs::remove_file(part);
    }
    result?;
    Ok(true)
}

/// A Debian package is a small ar archive. The Ubuntu packages pinned above
/// carry an uncompressed `data.tar` and a zstd-compressed module inside it.
/// Parse the container here instead of requiring `dpkg` or GNU `ar` on macOS.
fn extract_kernel_modules(package: &Path, outputs: &[(&str, PathBuf)]) -> Result<()> {
    let mut package = std::fs::File::open(package)?;
    let mut magic = [0u8; 8];
    package.read_exact(&mut magic)?;
    if magic != *b"!<arch>\n" {
        bail!("the guest kernel module package is not a Debian ar archive");
    }

    loop {
        let mut header = [0u8; 60];
        let first = package.read(&mut header)?;
        if first == 0 {
            break;
        }
        package.read_exact(&mut header[first..])?;
        if &header[58..] != b"`\n" {
            bail!("the guest kernel module package has a malformed ar header");
        }
        let name = std::str::from_utf8(&header[..16])?
            .trim()
            .trim_end_matches('/');
        let size: u64 = std::str::from_utf8(&header[48..58])?.trim().parse()?;
        let data_at = package.stream_position()?;
        if name == "data.tar" {
            let data = (&mut package).take(size);
            return extract_modules_from_tar(data, outputs);
        }
        package.seek(SeekFrom::Start(data_at + size + size % 2))?;
    }
    bail!("the guest kernel module package has no data.tar member")
}

fn extract_modules_from_tar(reader: impl Read, outputs: &[(&str, PathBuf)]) -> Result<()> {
    let mut archive = tar::Archive::new(reader);
    let mut found = vec![false; outputs.len()];
    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?;
        let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        let Some(index) = outputs
            .iter()
            .position(|(name, _)| file_name == format!("{name}.ko.zst"))
        else {
            continue;
        };
        if found[index] {
            continue;
        }
        let (name, dest) = &outputs[index];
        let mut decoder = ruzstd::decoding::StreamingDecoder::new(&mut entry)
            .map_err(|error| anyhow::anyhow!("opening {name}.ko.zst: {error}"))?;
        let mut output = std::fs::File::create(dest)?;
        std::io::copy(&mut decoder, &mut output)
            .with_context(|| format!("decompressing {name}.ko"))?;
        output.flush()?;
        output.sync_all()?;
        found[index] = true;
    }
    let missing: Vec<_> = outputs
        .iter()
        .zip(found)
        .filter_map(|((name, _), found)| (!found).then_some(*name))
        .collect();
    if !missing.is_empty() {
        bail!(
            "Ubuntu's kernel module package is missing: {}",
            missing.join(", ")
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_kernel_package_missing_any_direct_boot_module_is_refused_as_a_set() {
        let mut archive = Vec::new();
        tar::Builder::new(&mut archive).finish().unwrap();
        let root = tempfile::tempdir().unwrap();
        let outputs = [
            ("vsock", root.path().join("vsock.ko")),
            (
                "vmw_vsock_virtio_transport",
                root.path().join("transport.ko"),
            ),
        ];
        let error = extract_modules_from_tar(archive.as_slice(), &outputs)
            .unwrap_err()
            .to_string();
        assert!(error.contains("vsock"), "{error}");
        assert!(error.contains("vmw_vsock_virtio_transport"), "{error}");
    }

    fn r(s: &str) -> Reference {
        parse(s).unwrap_or_else(|| panic!("{s:?} should parse"))
    }

    /// The shorthands a user actually types, and what each one means.
    #[test]
    fn bare_names_are_docker_hub_library_images() {
        assert_eq!(r("nginx").canonical(), "docker.io/library/nginx:latest");
        assert_eq!(r("nginx:1.27").canonical(), "docker.io/library/nginx:1.27");
        assert_eq!(
            r("bitnami/redis").canonical(),
            "docker.io/bitnami/redis:latest"
        );
        assert_eq!(
            r("docker.io/library/nginx:latest").canonical(),
            "docker.io/library/nginx:latest"
        );
        assert_eq!(r("ghcr.io/owner/app:v1").registry, "ghcr.io");
        assert_eq!(r("ghcr.io/owner/app:v1").repository, "owner/app");
        // A scheme is a way to say "this is an image" out loud.
        assert_eq!(
            r("docker://busybox").canonical(),
            "docker.io/library/busybox:latest"
        );
        // Docker Hub is not where Docker Hub's registry is.
        assert_eq!(r("nginx").api_host(), "registry-1.docker.io");
        assert_eq!(r("ghcr.io/o/a").api_host(), "ghcr.io");
    }

    #[test]
    fn digests_and_ports_are_not_tags() {
        let digest = format!("sha256:{}", "a".repeat(64));
        let by_digest = r(&format!("nginx@{digest}"));
        assert_eq!(by_digest.version, Version::Digest(digest.clone()));
        assert_eq!(
            by_digest.canonical(),
            format!("docker.io/library/nginx@{digest}")
        );
        assert_eq!(by_digest.reference(), digest);

        // A colon in the registry is a port; the tag still defaults.
        let local = r("localhost:5000/app");
        assert_eq!(local.registry, "localhost:5000");
        assert_eq!(local.repository, "app");
        assert_eq!(local.version, Version::Tag("latest".into()));
    }

    /// Registry grammar is what tells an image reference from a typo, which
    /// is the only thing standing between a mistyped alias and a network
    /// round trip that was never going to work.
    #[test]
    fn things_that_are_not_references_are_refused() {
        for junk in [
            "Definitely-Not-An-Image", // repositories are lowercase by spec
            "nginx:",
            "nginx:-bad",
            "/nginx",
            "nginx/",
            "one//two",
            "",
            "under_score-ok/but not spaces",
            "nginx@sha256:short",
        ] {
            assert!(parse(junk).is_none(), "{junk:?} is not an image reference");
        }
    }

    /// Two references to the same digest have to be one file in the store,
    /// and a moved tag a different one.
    #[test]
    fn images_are_named_for_their_manifest_digest() {
        let a = format!("sha256:{}", "1".repeat(64));
        let b = format!("sha256:{}", "2".repeat(64));
        assert_eq!(image_path(&a), image_path(&a));
        assert_ne!(image_path(&a), image_path(&b));
        assert!(image_path(&a).to_string_lossy().contains("oci-1111"));
        // The pointer is per reference, so two tags on one digest share bytes.
        assert_ne!(pointer_path(&r("nginx")), pointer_path(&r("nginx:1.27")));
        assert!(pointer_path(&r("nginx"))
            .to_string_lossy()
            .ends_with("docker.io-library-nginx-latest.digest"));
    }

    #[test]
    fn the_config_composes_entrypoint_and_cmd_the_way_a_runtime_does() {
        let doc: Value = serde_json::from_str(
            r#"{"config":{"Entrypoint":["/docker-entrypoint.sh"],
                "Cmd":["nginx","-g","daemon off;"],
                "Env":["PATH=/bin","NGINX_VERSION=1.27"],
                "ExposedPorts":{"80/tcp":{}},"User":"","WorkingDir":""}}"#,
        )
        .unwrap();
        let config = Config::from_json(&doc);
        assert_eq!(
            config.argv(),
            ["/docker-entrypoint.sh", "nginx", "-g", "daemon off;"]
        );
        assert_eq!(config.tcp_ports(), [80]);
        assert_eq!(config.workdir, None, "an empty string is not a directory");
        assert_eq!(config.user, None);

        // Cmd alone is a whole command; root is not a user worth dropping to.
        let doc: Value =
            serde_json::from_str(r#"{"config":{"Cmd":["echo","hi"],"User":"root"}}"#).unwrap();
        assert_eq!(Config::from_json(&doc).argv(), ["echo", "hi"]);
        assert_eq!(Config::from_json(&doc).user, None);
    }

    /// The init is the whole boot contract with the image: the entrypoint
    /// runs with the image's environment, it is a child rather than an exec
    /// so that its exit is not a kernel panic, and the machine goes down when
    /// it does.
    #[test]
    fn the_generated_init_runs_the_entrypoint_and_powers_off() {
        let config = Config {
            entrypoint: vec!["/docker-entrypoint.sh".into()],
            cmd: vec!["nginx".into(), "-g".into(), "daemon off;".into()],
            env: vec![
                "PATH=/bin".into(),
                "GREETING=it's here".into(),
                "bad name=x".into(),
            ],
            workdir: Some("/srv".into()),
            user: None,
            exposed_ports: vec!["80/tcp".into()],
        };
        let script = init_script(&config);
        assert!(script.starts_with("#!/.asterism/busybox sh\n"), "{script}");
        assert!(script.contains("export PATH='/bin'"));
        // Quoting is the difference between an env var and a command.
        assert!(script.contains(r"export GREETING='it'\''s here'"));
        assert!(!script.contains("bad name"), "not a variable name");
        assert!(script.contains("cd '/srv'"));
        // The machine takes its address and its clock off the cmdline: it
        // has no DHCP client and no RTC this early.
        assert!(script.contains("asterism.ip=*)"), "{script}");
        assert!(script.contains("asterism.time=*)"), "{script}");
        assert!(script.contains("'/docker-entrypoint.sh' 'nginx' '-g' 'daemon off;' &"));
        assert!(script.contains("child=$!"));
        assert!(script.contains("wait $child"));
        assert!(script.contains("poweroff -f"));
        // The power button is the only way `ast down` can reach a guest with
        // no init system in it.
        assert!(script.contains("/dev/input/event"));
        assert!(script.contains("kill -TERM"));

        // A non-root USER is honoured rather than quietly ignored.
        let dropped = init_script(&Config {
            cmd: vec!["redis-server".into()],
            user: Some("redis".into()),
            ..Default::default()
        });
        assert!(
            dropped.contains("setuidgid 'redis' 'redis-server' &"),
            "{dropped}"
        );

        // An image with nothing to run says so on the console.
        let empty = init_script(&Config::default());
        assert!(empty.contains("no entrypoint or cmd"));
    }

    /// Instance parts belong in the private root disk, never in the shared
    /// OCI store image. The generated pid 1 mounts the selected transport
    /// and exports only opaque secret handles before starting the image.
    #[test]
    fn a_personalized_init_projects_volumes_and_secret_egress() {
        let config = Config {
            cmd: vec!["/app".into()],
            env: vec![
                "HTTPS_PROXY=http://image.invalid".into(),
                "EXAMPLE_TOKEN=image-value".into(),
                "BB=/tmp/not-asterism".into(),
            ],
            ..Default::default()
        };
        let shares = [Share {
            host_path: "/host/data".into(),
            guest_path: "/mnt/ast/data".into(),
            tag: "ast-deadbeef".into(),
            label: "device:/host/data".into(),
        }];
        let egress = Egress {
            proxy: "http://10.0.2.2:38123".into(),
            ca_pem: "-----BEGIN CERTIFICATE-----\npublic\n-----END CERTIFICATE-----\n".into(),
            authorities: vec!["api.example.com:443".into()],
            handles: vec![("EXAMPLE_TOKEN".into(), "ast-handle-opaque".into())],
        };
        let bootstrap = Bootstrap::resolve(&["base".to_owned()]).unwrap();
        let gpu_boot = "$BB mkdir -p /usr/local/sbin\n\
                        echo gpu-service > /usr/local/sbin/asterism-gpu-guest\n";
        let script = init_script_with_parts(
            &config,
            &shares,
            Some(ShareKind::NinePfs),
            &egress,
            &bootstrap,
            Some(gpu_boot),
            None,
        );
        let dir = tempfile::tempdir().unwrap();
        let init = dir.path().join("asterism-init");
        std::fs::write(&init, &script).unwrap();
        run(Command::new("sh").arg("-n").arg(&init)).expect("the personalized init is valid shell");
        run(Command::new("sh").arg(&init).arg("deconfig"))
            .expect("a non-address DHCP callback exits instead of re-entering pid 1");

        assert!(script.contains("mount -t 9p -o trans=virtio"), "{script}");
        assert!(
            script.contains("'ast-deadbeef' '/mnt/ast/data'"),
            "{script}"
        );
        assert!(script.contains("export EXAMPLE_TOKEN='ast-handle-opaque'"));
        assert!(script.contains("export HTTPS_PROXY='http://10.0.2.2:38123'"));
        assert!(script.contains("SSL_CERT_FILE='/.asterism/ca-bundle.pem'"));
        assert!(script.contains("Materialize the attached guest-local GPU projection"));
        assert!(script.contains("/usr/local/sbin/asterism-gpu-guest"));
        assert!(
            script.find("asterism-gpu-guest").unwrap()
                < script
                    .find("asterism: starting the image entrypoint")
                    .unwrap()
        );
        assert!(
            script.contains("udhcpc -n -q") && script.contains("-s /asterism-init"),
            "the same init can DHCP on vz"
        );
        assert!(
            script.contains("ip link set \"$nic\" up"),
            "the NIC is usable before DHCP: {script}"
        );
        assert!(
            script.contains(&egress.ca_pem),
            "the one generated inode materializes the public CA at boot"
        );
        assert!(script.contains("/usr/local/sbin/asterism-bootstrap"));
        assert!(script.contains("base@1"));
        assert!(
            script.rfind("export HTTPS_PROXY='http://10.0.2.2:38123'")
                > script.rfind("export HTTPS_PROXY='http://image.invalid'"),
            "the instance policy overrides image Env"
        );
        assert!(
            script.rfind("export EXAMPLE_TOKEN='ast-handle-opaque'")
                > script.rfind("export EXAMPLE_TOKEN='image-value'"),
            "an image cannot replace its opaque handle"
        );
        assert!(
            script.rfind("BB=/.asterism/busybox") > script.rfind("export BB='/tmp/not-asterism'"),
            "an image cannot replace Asterism's init runtime"
        );
    }

    #[test]
    fn directory_shares_cannot_be_personalized_without_a_transport() {
        let dir = tempfile::tempdir().unwrap();
        let share = Share {
            host_path: "/host/data".into(),
            guest_path: "/mnt/data".into(),
            tag: "ast-data".into(),
            label: "device:/host/data".into(),
        };
        let err = configure_instance(
            &dir.path().join("source.raw"),
            &dir.path().join("root.raw"),
            &[share],
            None,
            &Egress::default(),
            &Bootstrap::default(),
            None,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("transport"), "{err}");
    }

    /// Exercise the actual ext4 seam, not only the text generator: an image
    /// pulled by an older build already has both files, and boot must replace
    /// them in place without mounting the filesystem or touching the source.
    #[test]
    fn personalization_rewrites_only_the_private_ext4_copy() {
        let (Ok(mke2fs), Ok(resize2fs), Ok(debugfs), Ok(e2fsck)) = (
            e2fs_tool("mke2fs"),
            e2fs_tool("resize2fs"),
            e2fs_tool("debugfs"),
            e2fs_tool("e2fsck"),
        ) else {
            return;
        };
        let dir = tempfile::tempdir().unwrap();
        let tree = dir.path().join("tree");
        std::fs::create_dir_all(tree.join("sbin")).unwrap();
        std::fs::create_dir_all(tree.join(".asterism")).unwrap();
        std::fs::write(tree.join(LEGACY_GUEST_INIT), "old init\n").unwrap();
        std::fs::hard_link(tree.join(LEGACY_GUEST_INIT), tree.join(GUEST_DHCP)).unwrap();
        std::fs::write(tree.join(GUEST_EGRESS_CA), "old ca\n").unwrap();

        let source = dir.path().join("oci-source.raw");
        std::fs::write(
            source.with_extension("json"),
            r#"{"config":{"Cmd":["/app"]}}"#,
        )
        .unwrap();
        let root = dir.path().join("disk.raw");
        run(Command::new(mke2fs)
            .args(["-q", "-F", "-t", "ext4", "-d"])
            .arg(&tree)
            .arg(&root)
            .arg("16M"))
        .unwrap();
        run(Command::new(resize2fs).arg(&root).arg("64M")).unwrap();
        run(Command::new(&debugfs)
            .args(["-w", "-R", "sif /sbin/asterism-init links_count 1"])
            .arg(&root))
        .unwrap();

        let egress = Egress {
            proxy: "http://10.0.2.2:38123".into(),
            ca_pem: "public egress ca\n".into(),
            authorities: vec!["api.example.com:443".into()],
            handles: vec![("EXAMPLE_TOKEN".into(), "ast-handle-opaque".into())],
        };
        let bootstrap = Bootstrap::resolve(&["base".to_owned()]).unwrap();
        configure_instance(&source, &root, &[], None, &egress, &bootstrap, None).unwrap();
        assert!(dir.path().join("oci-config.json").exists());
        std::fs::remove_file(source.with_extension("json")).unwrap();
        configure_instance(&source, &root, &[], None, &egress, &bootstrap, None)
            .expect("a moved instance carries its private OCI config");
        let init = output(
            Command::new(&debugfs)
                .args(["-R", "cat /asterism-init"])
                .arg(&root),
        )
        .unwrap();
        assert!(init.contains("asterism: starting the image entrypoint"));
        assert!(init.contains("'/app' &"));
        assert!(init.contains("ifconfig \"$interface\""));
        assert!(init.contains("public egress ca"));
        assert!(init.contains("asterism: applying bootstrap profiles"));
        run(Command::new(e2fsck).args(["-fn"]).arg(&root))
            .expect("personalization leaves no duplicate inode references");
        assert!(std::fs::read_to_string(dir.path().join("oci-config.json"))
            .unwrap()
            .contains("/app"));
    }

    /// Layer paths are attacker-controlled: a tar entry that climbs out of
    /// the rootfs would be writing on the host that pulled it.
    #[test]
    fn layer_paths_cannot_escape_the_rootfs() {
        assert_eq!(guest_path(Path::new("usr/bin/env")).unwrap(), "usr/bin/env");
        assert_eq!(
            guest_path(Path::new("./usr/bin/env")).unwrap(),
            "usr/bin/env"
        );
        assert!(guest_path(Path::new("../../etc/passwd")).is_none());
        assert!(guest_path(Path::new("/etc/passwd")).is_none());
        assert!(guest_path(Path::new("")).is_none());
    }

    /// Whiteouts are how a layer deletes, and the record has to forget what
    /// the filesystem forgot.
    #[test]
    fn whiteouts_remove_files_and_their_ownership() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir_all(root.join("var/log")).unwrap();
        std::fs::write(root.join("var/log/old.log"), b"x").unwrap();

        let mut tree = Tree::default();
        tree.note("var", 0, 0);
        tree.note("var/log", 0, 0);
        tree.note("var/log/old.log", 0, 0);

        // `.wh.old.log` in var/log removes var/log/old.log.
        let victim = join("var/log", "old.log");
        remove(&root.join(&victim)).unwrap();
        tree.forget(&victim);
        assert!(!root.join("var/log/old.log").exists());
        assert!(tree.owners.contains_key("var/log"));
        assert!(!tree.owners.contains_key("var/log/old.log"));

        // An opaque whiteout empties the directory it sits in.
        std::fs::write(root.join("var/log/new.log"), b"x").unwrap();
        tree.note("var/log/new.log", 0, 0);
        tree.forget_children("var/log");
        assert!(
            tree.owners.contains_key("var/log"),
            "the directory itself stays"
        );
        assert!(!tree.owners.contains_key("var/log/new.log"));
    }

    #[test]
    fn shell_quoting_survives_everything_an_image_can_put_in_a_string() {
        assert_eq!(sh_quote("plain"), "'plain'");
        assert_eq!(sh_quote("daemon off;"), "'daemon off;'");
        assert_eq!(sh_quote("$(rm -rf /)"), "'$(rm -rf /)'");
        assert_eq!(sh_quote("it's"), r"'it'\''s'");
    }

    // ---- verification ------------------------------------------------------
    //
    // Everything below runs against a registry made of a `BTreeMap`, so
    // "the mirror served the wrong bytes" is a line of test setup rather
    // than a thing that has to be arranged with a real one. The blob cache
    // is a tempdir per test, which is why none of this touches
    // `ASTERISM_HOME` and none of it races its neighbours.

    use std::collections::BTreeMap as Map;
    use std::sync::Mutex;

    /// A registry that serves exactly what it is told to, including the
    /// wrong thing.
    #[derive(Default)]
    struct Fake {
        docs: Map<String, String>,
        blobs: Map<String, Vec<u8>>,
        /// Every url asked for, so a test can prove a cached blob was
        /// served without going to the network.
        asked: Mutex<Vec<String>>,
    }

    impl Fake {
        fn doc(mut self, path: &str, body: &str) -> Fake {
            self.docs.insert(path.to_owned(), body.to_owned());
            self
        }

        fn blob(mut self, digest: &str, bytes: &[u8]) -> Fake {
            self.blobs.insert(digest.to_owned(), bytes.to_vec());
            self
        }

        /// The tail of a url, which is all this fake keys on.
        fn key(url: &str) -> String {
            url.rsplit_once("/v2/")
                .map(|(_, r)| r.to_owned())
                .unwrap_or_else(|| url.to_owned())
        }
    }

    impl Transport for Fake {
        fn get(&self, url: &str, _accept: Option<&str>, _token: Option<&str>) -> Result<String> {
            self.asked.lock().unwrap().push(url.to_owned());
            let key = Fake::key(url);
            self.docs
                .get(&key)
                .cloned()
                .with_context(|| format!("404 for {key}"))
        }

        fn fetch(&self, url: &str, _token: Option<&str>, dest: &Path, _p: bool) -> Result<()> {
            self.asked.lock().unwrap().push(url.to_owned());
            let key = Fake::key(url);
            let digest = key.rsplit('/').next().unwrap_or_default();
            let bytes = self
                .blobs
                .get(digest)
                .with_context(|| format!("404 for blob {digest}"))?;
            std::fs::write(dest, bytes)?;
            Ok(())
        }
    }

    fn sha(bytes: &[u8]) -> String {
        Digest::of_bytes(Algo::Sha256, bytes).to_string()
    }

    struct Harness {
        _dir: tempfile::TempDir,
        blobs: PathBuf,
    }

    impl Harness {
        fn new() -> Harness {
            let dir = tempfile::tempdir().unwrap();
            let blobs = dir.path().join("blobs");
            Harness { _dir: dir, blobs }
        }

        fn registry<'a>(&self, reference: &'a Reference, fake: Fake) -> Registry<'a> {
            Registry {
                reference,
                token: None,
                transport: Box::new(fake),
                blobs: self.blobs.clone(),
            }
        }
    }

    /// A layer blob is fetched by its digest, so bytes that hash to anything
    /// else are a substitution — and a substituted layer is arbitrary code
    /// in a filesystem a machine is about to boot.
    #[test]
    fn a_layer_that_is_not_what_the_manifest_named_never_reaches_the_cache() {
        let reference = r("nginx");
        let h = Harness::new();
        let honest = b"the layer the manifest named";
        let digest = sha(honest);
        let fake = Fake::default().blob(&digest, b"a completely different layer");
        let registry = h.registry(&reference, fake);

        let err = format!("{:#}", registry.blob(&digest, false).unwrap_err());
        assert!(err.contains("does not match its published digest"), "{err}");
        let cached = h.blobs.join(digest.replace(':', "-"));
        assert!(
            !cached.exists(),
            "the substituted layer must not take the cache's name"
        );
        assert!(
            !cached.with_extension("part").exists(),
            "nor be left to be resumed"
        );
    }

    /// The config blob decides what pid 1 runs, and it travels the same way
    /// a layer does — so it gets caught by the same check.
    #[test]
    fn a_config_blob_is_verified_like_any_other() {
        let reference = r("nginx");
        let h = Harness::new();
        let config = br#"{"config":{"Entrypoint":["/bin/true"]}}"#;
        let digest = sha(config);

        let good = h.registry(&reference, Fake::default().blob(&digest, config));
        let path = good.blob(&digest, false).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), config);

        let h2 = Harness::new();
        let swapped = br#"{"config":{"Entrypoint":["/bin/somebody-elses-idea"]}}"#;
        let bad = h2.registry(&reference, Fake::default().blob(&digest, swapped));
        assert!(bad.blob(&digest, false).is_err());
    }

    /// A blob whose algorithm this build cannot compute is not a weaker
    /// check, it is no check — so it is refused, and refused before the
    /// store has been touched at all.
    #[test]
    fn a_blob_named_with_an_algorithm_we_cannot_compute_is_refused_before_any_write() {
        let reference = r("nginx");
        let h = Harness::new();
        let registry = h.registry(&reference, Fake::default());
        let err = registry
            .blob("md5:d41d8cd98f00b204e9800998ecf8427e", false)
            .unwrap_err()
            .to_string();
        assert!(err.contains("cannot verify"), "{err}");
        assert!(
            !h.blobs.exists(),
            "not even the cache directory was created"
        );
    }

    /// A cache written by an older Asterism has no provenance beside it. It
    /// is not trusted on the strength of its filename: it is hashed, and it
    /// is either adopted properly or deleted.
    #[test]
    fn a_cache_from_before_provenance_is_hashed_before_it_is_reused() {
        let reference = r("nginx");
        let bytes = b"a layer somebody pulled last year";
        let digest = sha(bytes);

        let h = Harness::new();
        std::fs::create_dir_all(&h.blobs).unwrap();
        let cached = h.blobs.join(digest.replace(':', "-"));
        std::fs::write(&cached, bytes).unwrap();
        let registry = h.registry(&reference, Fake::default());
        assert_eq!(registry.blob(&digest, false).unwrap(), cached);
        assert!(
            verify::provenance(&cached).is_some(),
            "an unaccounted blob that checks out is adopted, not merely allowed"
        );

        // And the same file poisoned: same name, different bytes.
        let h2 = Harness::new();
        std::fs::create_dir_all(&h2.blobs).unwrap();
        let poisoned = h2.blobs.join(digest.replace(':', "-"));
        std::fs::write(&poisoned, b"a layer somebody else substituted").unwrap();
        let registry = h2.registry(&reference, Fake::default());
        let err = format!("{:#}", registry.blob(&digest, false).unwrap_err());
        assert!(err.contains("corrupted or tampered with"), "{err}");
        assert!(
            !poisoned.exists(),
            "a poisoned blob is deleted, not left to be hit again"
        );
    }

    /// A cache poisoned *after* Asterism adopted it — the provenance record
    /// is there and the bytes no longer agree with it.
    #[test]
    fn a_blob_poisoned_after_adoption_is_caught_on_reuse() {
        let reference = r("nginx");
        let bytes = b"the real layer";
        let digest = sha(bytes);
        let h = Harness::new();
        let registry = h.registry(&reference, Fake::default().blob(&digest, bytes));
        let path = registry.blob(&digest, false).unwrap();

        std::fs::write(&path, b"tampered with, at a different length").unwrap();
        let err = format!("{:#}", registry.blob(&digest, false).unwrap_err());
        assert!(
            err.contains("truncated or replaced") || err.contains("has changed"),
            "{err}"
        );
    }

    /// Offline reuse: a blob that was verified when it was fetched is served
    /// out of the cache without a single request. A registry that has gone
    /// away, or a laptop on a train, still boots what it already has.
    #[test]
    fn a_verified_blob_is_reused_without_touching_the_network() {
        let reference = r("nginx");
        let bytes = b"a layer, fetched once";
        let digest = sha(bytes);
        let h = Harness::new();
        h.registry(&reference, Fake::default().blob(&digest, bytes))
            .blob(&digest, false)
            .unwrap();

        // A transport with nothing in it: any request at all is a failure.
        let offline = Fake::default();
        let registry = h.registry(&reference, offline);
        let path = registry.blob(&digest, false).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
    }

    /// Pulling by digest is a promise about the bytes, and the registry has
    /// to keep it. Without this check the digest in `nginx@sha256:...` is
    /// decoration.
    #[test]
    fn a_manifest_asked_for_by_digest_must_be_that_manifest() {
        let honest = r#"{"config":{"digest":"sha256:aa"},"layers":[]}"#;
        let digest = sha(honest.as_bytes());
        let reference = r(&format!("nginx@{digest}"));
        let h = Harness::new();

        let good = Fake::default().doc(&format!("library/nginx/manifests/{digest}"), honest);
        let (got, _) = h.registry(&reference, good).manifest().unwrap();
        assert_eq!(got, digest);

        let liar = Fake::default().doc(
            &format!("library/nginx/manifests/{digest}"),
            r#"{"config":{"digest":"sha256:bb"},"layers":[]}"#,
        );
        let err = h.registry(&reference, liar).manifest().unwrap_err();
        let text = format!("{err:#}");
        assert!(text.contains("does not match its digest"), "{text}");
    }

    /// An index names a digest per platform; the manifest served for that
    /// entry has to be the one it named. Otherwise the architecture choice
    /// below is advice rather than a decision.
    #[test]
    fn an_index_entry_must_serve_the_manifest_it_named() {
        let reference = r("nginx");
        let platform = r#"{"config":{"digest":"sha256:cc"},"layers":[]}"#;
        let digest = sha(platform.as_bytes());
        let index = format!(
            r#"{{"manifests":[{{"digest":"{digest}","platform":{{"os":"linux","architecture":"{}"}}}}]}}"#,
            platform_arch()
        );
        let h = Harness::new();

        let good = Fake::default()
            .doc("library/nginx/manifests/latest", &index)
            .doc(&format!("library/nginx/manifests/{digest}"), platform);
        let (got, doc) = h.registry(&reference, good).manifest().unwrap();
        assert_eq!(got, digest);
        assert_eq!(doc["config"]["digest"], "sha256:cc");

        let liar = Fake::default()
            .doc("library/nginx/manifests/latest", &index)
            .doc(
                &format!("library/nginx/manifests/{digest}"),
                r#"{"config":{"digest":"sha256:dd"},"layers":[]}"#,
            );
        let text = format!("{:#}", h.registry(&reference, liar).manifest().unwrap_err());
        assert!(text.contains("does not match its digest"), "{text}");
    }

    /// An image with no build for this machine says so, and names what it
    /// does publish. Booting somebody else's architecture is a guest that
    /// sits at a blank console, which is the least diagnosable failure
    /// there is.
    #[test]
    fn an_image_with_no_build_for_this_architecture_is_refused_by_name() {
        let reference = r("nginx");
        let other = if platform_arch() == "arm64" {
            "amd64"
        } else {
            "arm64"
        };
        let index = format!(
            r#"{{"manifests":[
                {{"digest":"sha256:{}","platform":{{"os":"linux","architecture":"{other}"}}}},
                {{"digest":"sha256:{}","platform":{{"os":"linux","architecture":"riscv64"}}}}
            ]}}"#,
            "1".repeat(64),
            "2".repeat(64)
        );
        let h = Harness::new();
        let fake = Fake::default().doc("library/nginx/manifests/latest", &index);
        let text = format!("{:#}", h.registry(&reference, fake).manifest().unwrap_err());
        assert!(
            text.contains(&format!("no linux/{}", platform_arch())),
            "{text}"
        );
        assert!(
            text.contains(other),
            "the error has to say what it does publish: {text}"
        );
        assert!(text.contains("riscv64"), "{text}");
    }

    /// A tagged single-platform manifest has no digest of its own to check
    /// against, so the image is named by the hash of what was served — which
    /// has to be a real hash, computed here, and not something that can fall
    /// back to a non-cryptographic one on a host with no `shasum`.
    #[test]
    fn a_tagged_manifest_is_addressed_by_its_own_content() {
        let body = r#"{"config":{"digest":"sha256:ee"},"layers":[]}"#;
        let reference = r("nginx");
        let h = Harness::new();
        let fake = Fake::default().doc("library/nginx/manifests/latest", body);
        let (digest, _) = h.registry(&reference, fake).manifest().unwrap();
        assert_eq!(digest, sha(body.as_bytes()));
        assert!(
            digest.starts_with("sha256:"),
            "never a fallback hash: {digest}"
        );
        assert_eq!(Digest::parse(&digest).unwrap().hex().len(), 64);
    }

    /// The case a pinned kernel exists for: a device that has never had one,
    /// being handed a substituted one by whoever can answer for the mirror.
    /// There is nothing on the device to contradict it — which is exactly
    /// why remembering what arrived is not a check.
    #[test]
    fn a_substituted_first_fetch_of_the_kernel_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let kernel = dir.path().join("aarch64-vmlinuz");
        let initrd = dir.path().join("aarch64-initrd");
        let pinned = KERNELS.iter().find(|k| k.arch == "aarch64").unwrap();

        let err = ensure_kernel_at(pinned, &kernel, &initrd, |_url, dest| {
            std::fs::write(dest, b"not the kernel Ubuntu published")?;
            Ok(())
        })
        .unwrap_err();
        let text = format!("{err:#}");
        assert!(
            text.contains("does not match its published digest"),
            "{text}"
        );
        assert!(
            text.contains(pinned.kernel.digest),
            "the error names what was expected: {text}"
        );
        assert!(!kernel.exists(), "nothing was adopted");
        assert!(!initrd.exists());
        assert!(!verify::provenance_path(&kernel).exists());
        assert!(
            !kernel.with_extension("part").exists(),
            "and the substituted bytes are not left to be resumed"
        );
    }

    /// The same fetch against a pin the test controls: the honest bytes are
    /// adopted, the second call is a no-op, and both files carry a record.
    /// Between this and the test above, the fetch path is pinned in both
    /// directions.
    #[test]
    fn a_first_fetch_that_matches_its_pin_is_adopted_and_then_reused() {
        let dir = tempfile::tempdir().unwrap();
        let kernel = dir.path().join("test-vmlinuz");
        let initrd = dir.path().join("test-initrd");
        let (kbytes, ibytes) = (b"a kernel".as_slice(), b"an initrd".as_slice());
        let kd = sha(kbytes);
        let id = sha(ibytes);
        let pinned = GuestKernel {
            arch: "test",
            kernel: Pinned {
                url: "https://example/vmlinuz",
                digest: leak(kd),
            },
            initrd: Pinned {
                url: "https://example/initrd",
                digest: leak(id),
            },
        };
        let serve = |url: &str, dest: &Path| -> Result<()> {
            let bytes = if url.ends_with("vmlinuz") {
                kbytes
            } else {
                ibytes
            };
            std::fs::write(dest, bytes)?;
            Ok(())
        };

        assert!(ensure_kernel_at(&pinned, &kernel, &initrd, serve).unwrap());
        assert_eq!(std::fs::read(&kernel).unwrap(), kbytes);
        assert_eq!(verify::provenance(&kernel).unwrap().kind, "kernel");
        assert_eq!(verify::provenance(&initrd).unwrap().kind, "initrd");

        // Offline reuse: a fetcher that would fail on any request at all.
        let refuse = |_: &str, _: &Path| -> Result<()> { bail!("the network is not here") };
        assert!(!ensure_kernel_at(&pinned, &kernel, &initrd, refuse).unwrap());

        // And a kernel corrupted after adoption is re-fetched rather than
        // trusted, which is the other half of why the check is at both ends.
        std::fs::write(&kernel, b"tampered with, at a length of its own").unwrap();
        assert!(ensure_kernel_at(&pinned, &kernel, &initrd, serve).unwrap());
        assert_eq!(std::fs::read(&kernel).unwrap(), kbytes);
    }

    #[test]
    fn a_native_loader_gets_an_accounted_uncompressed_kernel() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("test-vmlinuz");
        let raw = dir.path().join("test-vmlinux");
        let input = dir.path().join("input");
        std::fs::write(&input, b"the raw Linux kernel bytes").unwrap();
        let compressed = std::fs::File::create(&source).unwrap();
        run(Command::new(tool("gzip").unwrap())
            .arg("-c")
            .arg(&input)
            .stdout(Stdio::from(compressed)))
        .unwrap();

        ensure_uncompressed_kernel(&source, &raw, "sha256:publisher-kernel").unwrap();
        assert_eq!(std::fs::read(&raw).unwrap(), b"the raw Linux kernel bytes");
        let record = verify::provenance(&raw).unwrap();
        assert_eq!(record.kind, "linux-kernel");
        assert_eq!(record.derived_from, ["sha256:publisher-kernel"]);

        // A cached derivative is executable boot input too: damage must be
        // detected and repaired from the still-verified source.
        std::fs::write(&raw, b"damaged").unwrap();
        ensure_uncompressed_kernel(&source, &raw, "sha256:publisher-kernel").unwrap();
        assert_eq!(std::fs::read(&raw).unwrap(), b"the raw Linux kernel bytes");
    }

    /// A pin is only a pin if the url cannot move under it. Both entries in
    /// the table have to name an artifact that is published once.
    #[test]
    fn every_pinned_kernel_url_is_an_immutable_one() {
        for k in KERNELS {
            for (what, p) in [("kernel", &k.kernel), ("initrd", &k.initrd)] {
                assert!(!p.url.contains("/latest/"), "{} {what}: {}", k.arch, p.url);
                assert!(
                    !p.url.contains("/release/"),
                    "{} {what} points at the name Ubuntu republishes over: {}",
                    k.arch,
                    p.url
                );
                let d = p.expected(what).unwrap();
                assert_eq!(d.algo(), Algo::Sha256, "Ubuntu publishes sha256");
            }
        }
    }

    /// `&'static str` for a digest a test computed at runtime. Only reached
    /// twice, and the alternative is a lifetime on `Pinned` that exists
    /// solely so the tests can borrow.
    fn leak(s: String) -> &'static str {
        Box::leak(s.into_boxed_str())
    }

    /// Every architecture the catalog serves has a kernel to boot OCI images
    /// with, and both files come off the same release.
    #[test]
    fn every_architecture_has_a_pinned_kernel() {
        for k in KERNELS {
            assert!(k.kernel.url.starts_with("https://"), "{}", k.arch);
            assert!(k.initrd.url.starts_with("https://"), "{}", k.arch);
            assert!(
                k.kernel.url.contains("24.04") && k.initrd.url.contains("24.04"),
                "{}",
                k.arch
            );
            // A pin nobody can compute would refuse every OCI boot on that
            // architecture, and it would do it at `ast pull` on a user's
            // machine rather than here. Check the table can be read.
            let kernel = k.kernel.expected("the guest kernel").unwrap();
            let initrd = k.initrd.expected("the guest initrd").unwrap();
            assert_ne!(kernel, initrd, "{}", k.arch);
            // A dated serial, not the `release/` name that republishes over
            // itself: a pinned digest is only a pin if the url cannot move.
            for p in [&k.kernel, &k.initrd] {
                assert!(
                    p.url.contains("/release-2"),
                    "{} is not an immutable url",
                    p.url
                );
            }
        }
        assert!(KERNELS.iter().any(|k| k.arch == host_arch()));
    }
}
