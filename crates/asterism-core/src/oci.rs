//! OCI/Docker images as an instance image source.
//!
//! MODEL.md is the decision this file implements: *"OCI/Docker images are an
//! image SOURCE, booted as microVMs (OCI rootfs + guest kernel), so users get
//! the container ecosystem with VM isolation. No instance ever shares a host
//! kernel."* There is no container runtime here and there never will be. A
//! reference like `nginx` is pulled from a registry, its layers are unpacked,
//! and the result is turned into an ext4 disk that an ordinary microVM boots.
//! From `prepare()` onwards it is a raw disk like any other: it clones,
//! snapshots and takes volumes exactly as a cloud image does.
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
//!   `/sbin/asterism-init` into the rootfs: it mounts /proc, /sys, /dev, takes
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
//! kernel/<arch>-initrd
//! ```
//! The `.raw` is content-addressed, so two references to the same digest are
//! one image on disk and a moved tag is a different file rather than a
//! rewritten one.

use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{bail, Context, Result};
use serde_json::Value;

use crate::durable;
use crate::image::host_arch;
use crate::paths;
use crate::tools::{output, run, tool};

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
pub const GUEST_INIT: &str = "sbin/asterism-init";

/// The kernel cmdline `init=` the backend must pass.
pub const INIT_PATH: &str = "/sbin/asterism-init";

/// Guest kernel and initrd per host architecture: `(arch, kernel, initrd)`.
///
/// Ubuntu publishes the cloud image's kernel and initrd as loose files next
/// to the image itself. Pinned to the release the catalog already carries, so
/// a device is not running a kernel nobody chose.
pub const KERNELS: &[(&str, &str, &str)] = &[
    (
        "aarch64",
        "https://cloud-images.ubuntu.com/releases/noble/release/unpacked/ubuntu-24.04-server-cloudimg-arm64-vmlinuz-generic",
        "https://cloud-images.ubuntu.com/releases/noble/release/unpacked/ubuntu-24.04-server-cloudimg-arm64-initrd-generic",
    ),
    (
        "x86_64",
        "https://cloud-images.ubuntu.com/releases/noble/release/unpacked/ubuntu-24.04-server-cloudimg-amd64-vmlinuz-generic",
        "https://cloud-images.ubuntu.com/releases/noble/release/unpacked/ubuntu-24.04-server-cloudimg-amd64-initrd-generic",
    ),
];

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
            .map(|c| if c.is_ascii_alphanumeric() || c == '.' { c } else { '-' })
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
    Some(Reference { registry, repository, version })
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
        && s.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
}

fn is_digest(s: &str) -> bool {
    match s.split_once(':') {
        Some((algo, hex)) => {
            !algo.is_empty()
                && hex.len() >= 32
                && hex.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
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
                .map(|a| a.iter().filter_map(|s| s.as_str().map(str::to_owned)).collect())
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
    digest.rsplit(':').next().unwrap_or(digest).chars().take(16).collect()
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
        let Ok(pointer) = std::fs::read_to_string(&path) else { continue };
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
    Some(Config::from_json(&serde_json::from_str::<Value>(&text).ok()?))
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
    if image.exists() {
        let config = stored_config(reference).unwrap_or_default();
        write_pointer(reference, &digest)?;
        return Ok(Pulled { digest, image, config, built: false });
    }

    let config_digest = manifest["config"]["digest"]
        .as_str()
        .context("image manifest names no config")?;
    let config = Config::from_json(&serde_json::from_str::<Value>(
        &std::fs::read_to_string(registry.blob(config_digest, progress)?)?,
    )?);

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
        for (i, layer) in layers.iter().enumerate() {
            let digest = layer["digest"].as_str().context("layer has no digest")?;
            if progress {
                eprintln!("unpacking layer {}/{}", i + 1, layers.len());
            }
            let blob = registry.blob(digest, progress)?;
            unpack_layer(&blob, &root, &mut tree)
                .with_context(|| format!("unpacking layer {digest}"))?;
        }
        furnish(&root, &config, &mut tree)?;
        build_ext4(&root, &tree, &image, &digest)
    })();
    let _ = std::fs::remove_dir_all(&stage);
    built?;

    std::fs::write(config_path(&digest), serde_json::to_vec_pretty(&config.to_json())?)?;
    write_pointer(reference, &digest)?;
    Ok(Pulled { digest, image, config, built: true })
}

fn write_pointer(reference: &Reference, digest: &str) -> Result<()> {
    let path = pointer_path(reference);
    std::fs::create_dir_all(path.parent().expect("pointer has a directory"))?;
    std::fs::write(path, format!("{digest}\n{}\n", reference.canonical()))?;
    Ok(())
}

/// One registry, one repository, one anonymous pull token.
struct Registry<'a> {
    reference: &'a Reference,
    token: Option<String>,
    curl: PathBuf,
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
        let token = output(Command::new(&curl).args(["-sS", "--fail", "-L", &url]))
            .ok()
            .and_then(|body| serde_json::from_str::<Value>(&body).ok())
            .and_then(|v| {
                v["token"]
                    .as_str()
                    .or_else(|| v["access_token"].as_str())
                    .map(str::to_owned)
            });
        Ok(Registry { reference, token, curl })
    }

    fn get(&self, url: &str, accept: Option<&str>) -> Result<String> {
        let mut cmd = Command::new(&self.curl);
        cmd.args(["-sS", "--fail", "-L"]);
        if let Some(token) = &self.token {
            cmd.arg("-H").arg(format!("Authorization: Bearer {token}"));
        }
        if let Some(accept) = accept {
            cmd.arg("-H").arg(format!("Accept: {accept}"));
        }
        output(cmd.arg(url))
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
        let body = self.get(&url, Some(MANIFEST_TYPES)).with_context(|| {
            format!("no image {} on {}", self.reference, self.reference.registry)
        })?;
        let doc: Value = serde_json::from_str(&body).context("unreadable image manifest")?;

        let Some(list) = doc["manifests"].as_array() else {
            // A single-platform manifest: its digest is the one we asked by,
            // when that was a digest, or the content's own hash otherwise.
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
        let digest = picked["digest"].as_str().context("index entry has no digest")?;
        let url = format!(
            "https://{}/v2/{}/manifests/{}",
            self.reference.api_host(),
            self.reference.repository,
            digest
        );
        let body = self.get(&url, Some(MANIFEST_TYPES))?;
        Ok((digest.to_owned(), serde_json::from_str(&body)?))
    }

    /// A blob, cached by its own digest. Blobs are immutable and shared
    /// between images, so this is the layer cache too.
    fn blob(&self, digest: &str, progress: bool) -> Result<PathBuf> {
        let dir = oci_dir().join("blobs");
        std::fs::create_dir_all(&dir)?;
        let path = dir.join(digest.replace(':', "-"));
        if path.exists() {
            return Ok(path);
        }
        let part = path.with_extension("part");
        let url = format!(
            "https://{}/v2/{}/blobs/{}",
            self.reference.api_host(),
            self.reference.repository,
            digest
        );
        let mut cmd = Command::new(&self.curl);
        cmd.args(["-sS", "--fail", "-L"]);
        if progress {
            cmd.arg("--progress-bar");
        }
        if let Some(token) = &self.token {
            cmd.arg("-H").arg(format!("Authorization: Bearer {token}"));
        }
        let status = cmd
            .arg("-o")
            .arg(&part)
            .arg(&url)
            .status()
            .context("running curl")?;
        if !status.success() {
            let _ = std::fs::remove_file(&part);
            bail!("downloading {digest} from {}", self.reference.registry);
        }
        // Forced down and then renamed: a blob is addressed by its digest,
        // and a digest-named file that is half a blob is a lie every later
        // pull would believe.
        durable::publish_file(&part, &path)?;
        Ok(path)
    }
}

/// Content hash of a manifest we were handed by tag. `shasum` rather than a
/// crate: it is one hash of one small document, on a path that has already
/// spawned curl.
fn sha256_hex(bytes: &[u8]) -> String {
    use std::io::Write;
    let hashed = (|| -> Result<String> {
        let sha = tool("shasum").or_else(|_| tool("sha256sum"))?;
        let args: &[&str] = if sha.ends_with("shasum") { &["-a", "256"] } else { &[] };
        let mut child = Command::new(sha)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()?;
        child.stdin.take().context("no stdin")?.write_all(bytes)?;
        let out = child.wait_with_output()?;
        let text = String::from_utf8_lossy(&out.stdout).into_owned();
        Ok(text.split_whitespace().next().unwrap_or_default().to_owned())
    })()
    .unwrap_or_default();
    match hashed.len() {
        64 => format!("sha256:{hashed}"),
        // Naming the image after nothing would collide; fall back to a hash
        // of the bytes that cannot.
        _ => format!("fnv:{:016x}", crate::instance::fnv1a(&String::from_utf8_lossy(bytes))),
    }
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
        self.owners.retain(|p, _| p != prefix && !p.starts_with(&below));
        self.dir_modes.retain(|p, _| p != prefix && !p.starts_with(&below));
    }

    /// An opaque whiteout empties a directory but keeps the directory.
    fn forget_children(&mut self, dir: &str) {
        let below = if dir.is_empty() { String::new() } else { format!("{dir}/") };
        self.owners.retain(|p, _| !p.starts_with(&below) || p == dir);
        self.dir_modes.retain(|p, _| !p.starts_with(&below) || p == dir);
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

fn set_mode(path: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode & 0o7777))?;
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
            tree.dir_modes.insert(dir.to_owned(), if dir == "tmp" { 0o1777 } else { 0o755 });
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
    tree.note("sbin", 0, 0);
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
        return Ok(cached);
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
        for layer in manifest["layers"].as_array().context("busybox has no layers")? {
            let digest = layer["digest"].as_str().context("layer has no digest")?;
            unpack_layer(&registry.blob(digest, false)?, &stage, &mut tree)?;
        }
        let from = stage.join("bin/busybox");
        if !from.exists() {
            bail!("{BUSYBOX_IMAGE} no longer ships /bin/busybox");
        }
        std::fs::create_dir_all(cached.parent().expect("cache has a directory"))?;
        std::fs::copy(&from, &cached)?;
        set_mode(&cached, 0o755)
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
    let mut s = String::new();
    s.push_str(&format!("#!/{GUEST_BUSYBOX} sh\n"));
    s.push_str(
        "# Generated by Asterism. Runs an OCI image's entrypoint as pid 1.\n\
         BB=/.asterism/busybox\n\
         $BB mkdir -p /proc /sys /dev /tmp /run 2>/dev/null\n\
         $BB mount -t proc proc /proc 2>/dev/null\n\
         $BB mount -t sysfs sys /sys 2>/dev/null\n\
         $BB mount -t devtmpfs dev /dev 2>/dev/null\n\
         $BB mkdir -p /dev/pts /dev/shm 2>/dev/null\n\
         $BB mount -t devpts devpts /dev/pts 2>/dev/null\n\
         $BB mount -t tmpfs shm /dev/shm 2>/dev/null\n\
\n\
         # What this machine cannot discover for itself, the backend wrote on\n\
         # the kernel cmdline: its address (nothing here speaks DHCP) and the\n\
         # time (no RTC driver is loaded this early, and without it every line\n\
         # the image logs is dated 1970).\n\
         ip= gw= dns=\n\
         for w in $($BB cat /proc/cmdline); do\n\
         \x20 case \"$w\" in\n\
         \x20   asterism.ip=*)   ip=${w#asterism.ip=} ;;\n\
         \x20   asterism.gw=*)   gw=${w#asterism.gw=} ;;\n\
         \x20   asterism.dns=*)  dns=${w#asterism.dns=} ;;\n\
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

    for var in &config.env {
        if let Some((name, value)) = var.split_once('=') {
            if is_env_name(name) {
                s.push_str(&format!("export {name}={}\n", sh_quote(value)));
            }
        }
    }
    if let Some(dir) = &config.workdir {
        s.push_str(&format!("$BB mkdir -p {0} 2>/dev/null\ncd {0} || exit 1\n", sh_quote(dir)));
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
fn build_ext4(root: &Path, tree: &Tree, image: &Path, digest: &str) -> Result<()> {
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
    durable::publish_file(&part, image)?;
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
        script.push_str(&format!("sif \"/{path}\" mode 0{:o}\n", S_IFDIR | (mode & 0o7777)));
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
    (dir.join(format!("{arch}-vmlinuz")), dir.join(format!("{arch}-initrd")))
}

/// The kernel an OCI instance boots, or why this device has not got one.
///
/// Read-only, so the daemon can ask without downloading: fetching is the
/// CLI's job at `ast pull`, in the foreground where the user can see it.
pub fn kernel() -> Result<(PathBuf, PathBuf)> {
    let (kernel, initrd) = kernel_paths();
    if !kernel.exists() || !initrd.exists() {
        bail!(
            "no guest kernel on this device — an OCI image has no kernel of its \
             own, so one is fetched once: ast pull <image>"
        );
    }
    Ok((kernel, initrd))
}

/// Fetch the guest kernel if this device has not got one. Idempotent.
pub fn ensure_kernel(fetch: impl Fn(&str, &Path) -> Result<()>) -> Result<bool> {
    let (kernel, initrd) = kernel_paths();
    if kernel.exists() && initrd.exists() {
        return Ok(false);
    }
    let arch = host_arch();
    let (_, kernel_url, initrd_url) = KERNELS
        .iter()
        .find(|(a, _, _)| *a == arch)
        .with_context(|| format!("no guest kernel published for {arch}"))?;
    std::fs::create_dir_all(kernel.parent().expect("the kernel has a directory"))?;
    for (url, dest) in [(kernel_url, &kernel), (initrd_url, &initrd)] {
        if dest.exists() {
            continue;
        }
        let part = dest.with_extension("part");
        fetch(url, &part).with_context(|| format!("fetching the guest kernel from {url}"))?;
        durable::publish_file(&part, dest)?;
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn r(s: &str) -> Reference {
        parse(s).unwrap_or_else(|| panic!("{s:?} should parse"))
    }

    /// The shorthands a user actually types, and what each one means.
    #[test]
    fn bare_names_are_docker_hub_library_images() {
        assert_eq!(r("nginx").canonical(), "docker.io/library/nginx:latest");
        assert_eq!(r("nginx:1.27").canonical(), "docker.io/library/nginx:1.27");
        assert_eq!(r("bitnami/redis").canonical(), "docker.io/bitnami/redis:latest");
        assert_eq!(
            r("docker.io/library/nginx:latest").canonical(),
            "docker.io/library/nginx:latest"
        );
        assert_eq!(r("ghcr.io/owner/app:v1").registry, "ghcr.io");
        assert_eq!(r("ghcr.io/owner/app:v1").repository, "owner/app");
        // A scheme is a way to say "this is an image" out loud.
        assert_eq!(r("docker://busybox").canonical(), "docker.io/library/busybox:latest");
        // Docker Hub is not where Docker Hub's registry is.
        assert_eq!(r("nginx").api_host(), "registry-1.docker.io");
        assert_eq!(r("ghcr.io/o/a").api_host(), "ghcr.io");
    }

    #[test]
    fn digests_and_ports_are_not_tags() {
        let digest = format!("sha256:{}", "a".repeat(64));
        let by_digest = r(&format!("nginx@{digest}"));
        assert_eq!(by_digest.version, Version::Digest(digest.clone()));
        assert_eq!(by_digest.canonical(), format!("docker.io/library/nginx@{digest}"));
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
        assert_eq!(config.argv(), ["/docker-entrypoint.sh", "nginx", "-g", "daemon off;"]);
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
            env: vec!["PATH=/bin".into(), "GREETING=it's here".into(), "bad name=x".into()],
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
        assert!(dropped.contains("setuidgid 'redis' 'redis-server' &"), "{dropped}");

        // An image with nothing to run says so on the console.
        let empty = init_script(&Config::default());
        assert!(empty.contains("no entrypoint or cmd"));
    }

    /// Layer paths are attacker-controlled: a tar entry that climbs out of
    /// the rootfs would be writing on the host that pulled it.
    #[test]
    fn layer_paths_cannot_escape_the_rootfs() {
        assert_eq!(guest_path(Path::new("usr/bin/env")).unwrap(), "usr/bin/env");
        assert_eq!(guest_path(Path::new("./usr/bin/env")).unwrap(), "usr/bin/env");
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
        assert!(tree.owners.contains_key("var/log"), "the directory itself stays");
        assert!(!tree.owners.contains_key("var/log/new.log"));
    }

    #[test]
    fn shell_quoting_survives_everything_an_image_can_put_in_a_string() {
        assert_eq!(sh_quote("plain"), "'plain'");
        assert_eq!(sh_quote("daemon off;"), "'daemon off;'");
        assert_eq!(sh_quote("$(rm -rf /)"), "'$(rm -rf /)'");
        assert_eq!(sh_quote("it's"), r"'it'\''s'");
    }

    /// Every architecture the catalog serves has a kernel to boot OCI images
    /// with, and both files come off the same release.
    #[test]
    fn every_architecture_has_a_pinned_kernel() {
        for (arch, kernel, initrd) in KERNELS {
            assert!(kernel.starts_with("https://"), "{arch}");
            assert!(initrd.starts_with("https://"), "{arch}");
            assert!(kernel.contains("24.04") && initrd.contains("24.04"), "{arch}");
        }
        assert!(KERNELS.iter().any(|(a, _, _)| *a == host_arch()));
    }
}
