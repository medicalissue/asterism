//! Image catalog and local image store.
//!
//! An image reference is one of:
//!   - a catalog alias like `ubuntu:24.04` (or bare `ubuntu` for the default)
//!   - an `http(s)://` URL to a cloud image, carrying the digest it should
//!     have: `https://mirror/x.qcow2#sha256:<hex>`
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
//! Every one of those has something to be checked against before it is
//! adopted ([`crate::verify`]): a catalog entry carries the digest its
//! publisher published, an OCI reference is checked against the digests its
//! manifest names, and a url has to carry one the user wrote. A url with no
//! digest is refused by [`resolve`] itself — before a directory is made or a
//! byte is fetched — because there would be nothing to compare the download
//! to, and "downloaded successfully" is not a check.
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
use serde::{Deserialize, Serialize};

use crate::hv::{DiskFormat, ImageKind};
use crate::oci;
use crate::paths;
use crate::tools::{run, tool};
use crate::verify::{self, Depth, Digest, Pinned, Source};

/// The largest number of progress observations a pull result may carry.
///
/// Image pulls are currently request/reply operations, including through a
/// [`crate::protocol::Request::Proxy`] envelope. Keeping the observations in
/// the result gives a caller useful phase information without allowing a
/// registry or a layer list to turn one response into an unbounded document.
pub const MAX_PULL_PROGRESS: usize = 64;

/// One bounded observation from an image pull.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageProgress {
    pub phase: String,
    pub bytes: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total_bytes: Option<u64>,
    pub done: bool,
}

/// One device-local image row exposed to management clients.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageRow {
    pub reference: String,
    pub kind: ImageKind,
    pub pulled: bool,
    pub verified: bool,
    pub bytes: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
    /// A display-safe source. Credentials are never copied from an input into
    /// this field.
    pub source: String,
}

/// The durable outcome of a device-owned image pull.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImagePullResult {
    pub reference: String,
    pub kind: ImageKind,
    pub bytes: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
    pub progress: Vec<ImageProgress>,
    /// True when this request changed the device's image store.
    pub changed: bool,
}

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
    /// The digest these bytes must have, when anybody published one: a
    /// catalog entry that pins its image, or a `#sha256:...` the user wrote
    /// on the reference. Checked before the download is adopted, so bytes
    /// that are not what was asked for never reach the store under a name
    /// the boot path would find.
    pub expected: Option<Digest>,
    /// What this image's provenance record is keyed on.
    ///
    /// The image itself for anything the store owns, so the record sits
    /// beside it and the two are deleted together. For a local file it is a
    /// path inside the store instead: the user's directory is theirs, and
    /// writing a record next to their image would be Asterism leaving
    /// litter in it.
    pub record: PathBuf,
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
    /// Confirm these bytes are still the ones that were adopted, before a
    /// hypervisor is handed the path.
    ///
    /// The last gate. Everything upstream of it verifies bytes as they
    /// arrive; this one exists because arriving and booting are separated by
    /// an unbounded amount of time in which a store can be corrupted, pruned
    /// by hand, half-restored from a backup, or written into by something
    /// that had no business there.
    pub fn verify_bootable(&self) -> Result<()> {
        // Not pulled is not the same as not sound, and the fix is different
        // enough that they must not share a sentence.
        if !self.path.exists() {
            bail!(
                "{} is not on this device yet — pull it first: ast pull {}",
                self.name,
                self.name
            );
        }
        verify::check_recorded(&self.path, &self.record, Depth::from_env())
            .with_context(|| format!("{} cannot be booted from", self.name))?;
        self.pin_satisfied()
    }

    /// The store is holding the bytes *this reference* asked for, and not
    /// merely something that is internally consistent.
    ///
    /// The two are different questions and the second one is easy to mistake
    /// for the first. A url is slugged without its pin — deliberately, so
    /// that re-pinning is not a second copy of the same image — which means
    /// `<url>#sha256:aaa` and `<url>#sha256:bbb` name one file in the store.
    /// Without this, asking for the second on a device holding the first is
    /// answered "already pulled", and the digest the user typed does nothing
    /// at all.
    ///
    /// What is compared is the *provenance*, not the file: a pin names the
    /// bytes upstream published, and what is on disk is usually a raw image
    /// converted out of them. The published digest is the record's parent,
    /// which is exactly what `derived_from` is for.
    fn pin_satisfied(&self) -> Result<()> {
        let Some(want) = &self.expected else {
            return Ok(());
        };
        let Some(record) = verify::provenance(&self.record) else {
            return Ok(());
        };
        let want = want.to_string();
        if record.content.to_string() == want || record.derived_from.contains(&want) {
            return Ok(());
        }
        bail!(
            "{} is on this device, but it was pulled from a source that published a \
             different digest than the one asked for.\n\
             \x20 asked for: {want}\n\
             \x20 the copy here came from: {}\n\
             \x20 They are not the same image. Delete it and pull again to fetch the \
             one you named.",
            self.name,
            record
                .derived_from
                .first()
                .cloned()
                .unwrap_or_else(|| record.content.to_string())
        )
    }

    /// Record what a local file is, so that [`Resolved::verify_bootable`] has
    /// something to compare against later.
    ///
    /// A file the user pointed at is theirs: it is never rewritten and never
    /// staged, so it cannot be *adopted*. What can be done is to write down
    /// its identity the first time it is used, in the store rather than
    /// beside it, so that the same path holding different bytes at boot is a
    /// refusal instead of a surprise.
    ///
    /// Re-recording when the file has changed is deliberate, and it is why
    /// this is called from `ast pull` and `ast create` and from nothing that
    /// boots. Naming an image is the user saying "this file, as it is now";
    /// booting one is not. The consequence to know about: two instances
    /// built from one path share one record, so creating the second after
    /// the file has changed re-blesses it for the first as well. That is
    /// inherent in pointing two machines at a path instead of at bytes, and
    /// `--image <path>#sha256:...` is how somebody says they meant the bytes.
    pub fn record_local(&self) -> Result<()> {
        if self.staging.is_some() || self.oci.is_some() || !self.path.exists() {
            return Ok(());
        }
        if verify::check_recorded(&self.path, &self.record, Depth::Quick).is_ok()
            && self.pin_satisfied().is_ok()
        {
            return Ok(());
        }
        // A pin on a local path is the user saying which bytes they mean, so
        // it is checked here — the one moment they said it — rather than
        // written down unexamined and compared to itself forever after.
        let origin = self.path.display().to_string();
        let mut source = Source::new("local-image", &origin);
        if let Some(want) = &self.expected {
            want.verify_file(&self.path, "it")
                .with_context(|| format!("{} is not the file {want} names", self.path.display()))?;
            source = source.derived_from([want.to_string()]);
        }
        verify::record(&self.path, &self.record, source)?;
        Ok(())
    }

    /// Are these bytes the store's to replace?
    ///
    /// True for anything downloaded into `~/.asterism/images/`, which can be
    /// deleted and fetched again at any time. False for a file the user
    /// pointed `--image` at: that one is theirs, it is the only copy, and
    /// nothing in Asterism may remove it. False for an OCI reference too,
    /// whose store is managed by [`crate::oci`].
    pub fn is_ours(&self) -> bool {
        self.staging.is_some() && self.oci.is_none()
    }

    /// Throw away a store-owned image and its record so the next pull
    /// fetches it afresh. Returns whether anything was discarded.
    ///
    /// The guard is the point. "The image in the store is not what it was,
    /// so replace it" and "the file you pointed at is not what it was" look
    /// identical one line earlier and want opposite treatment — and getting
    /// that wrong deletes somebody's disk image. So the decision lives here,
    /// next to the field that decides it, rather than at each call site.
    pub fn discard(&self) -> bool {
        if !self.is_ours() {
            return false;
        }
        let _ = std::fs::remove_file(&self.path);
        let _ = std::fs::remove_file(self.path.with_extension("raw.part"));
        let _ = std::fs::remove_file(verify::provenance_path(&self.record));
        if let Some(staging) = &self.staging {
            let _ = std::fs::remove_file(staging);
            let _ = std::fs::remove_file(verify::provenance_path(staging));
        }
        true
    }

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

        // What the download was, before it is turned into something else.
        // A converted image has no upstream digest of its own — nobody
        // publishes the raw that `qemu-img` will produce — so the only
        // honest answer to "where did these bytes come from" is the digest
        // of the ones they were converted out of, recorded here and carried
        // on the raw image's record for as long as it exists.
        //
        // This is also the second place the download is checked. A store
        // that was interrupted between download and convert holds a staging
        // file that was verified once; verifying it again costs one pass
        // over a file that is about to be read in full anyway.
        let parent = match self.expected.as_ref() {
            Some(want) => {
                want.verify_file(staging, &format!("the download for {}", self.name))
                    .with_context(|| {
                        format!(
                            "the staged download for {} is not what was published — \
                             delete {} and pull again",
                            self.name,
                            staging.display()
                        )
                    })?;
                want.clone()
            }
            None => Digest::of_file(verify::OWN_ALGO, staging)?,
        };
        let source = Source::new("base-image", &self.name).derived_from([parent.to_string()]);

        let from = detect_format(staging)?;
        if from == DiskFormat::Raw {
            // Some publishers ship raw already; nothing to convert, but it
            // still goes through adoption so the image ends up with the same
            // record a converted one has — and adoption is where
            // [`durable::publish_file`] forces it down.
            verify::adopt(staging, &self.path, None, source)?;
            return Ok(true);
        }
        let part = self.path.with_extension("raw.part");
        convert_to_raw(staging, from, &part)
            .with_context(|| format!("converting {} to raw", self.name))?;
        verify::adopt(&part, &self.path, None, source)?;
        // The staging copy is a cache of a re-downloadable file, and keeping
        // it would double what every image costs. It only ever lives in our
        // own store — a local file is never staged.
        let _ = std::fs::remove_file(staging);
        let _ = std::fs::remove_file(verify::provenance_path(staging));
        Ok(true)
    }
}

/// `qemu-img convert` into a sparse raw file at a staged name, which the
/// caller then adopts — so an interrupted convert cannot be mistaken for a
/// finished image, and a finished one arrives with a provenance record.
///
/// The convert runs in a subprocess, so its bytes are only as durable as the
/// page cache when `qemu-img` exits. Forcing them down is [`verify::adopt`]'s
/// job rather than this function's, because the same flush has to happen
/// after the hash and before the rename, and that whole ordering lives in
/// one place.
///
/// `-S 4k` is what keeps it sparse: a 20 GiB raw disk converted from a
/// 400 MiB qcow2 occupies ~1 GiB of APFS blocks, not 20 GiB.
///
/// A pure-Rust qcow2 reader would remove the last QEMU dependency from this
/// path (BACKENDS.md §4, LICENSING.md); until then this is the one place a
/// non-QEMU backend still needs `qemu-img`, and it runs once per image.
fn convert_to_raw(src: &Path, from: DiskFormat, part: &Path) -> Result<()> {
    let _ = std::fs::remove_file(part);
    run(Command::new(tool("qemu-img")?)
        .args(["convert", "-f", from.as_str(), "-O", "raw", "-S", "4k"])
        .arg(src)
        .arg(part))?;
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
    let mut file =
        std::fs::File::open(path).with_context(|| format!("reading {}", path.display()))?;
    match file.read_exact(&mut magic) {
        Ok(()) if &magic == b"QFI\xfb" => Ok(DiskFormat::Qcow2),
        _ => Ok(DiskFormat::Raw),
    }
}

/// One catalog entry: an alias, and where its image is per architecture.
///
/// Architecture is a property of the entry rather than something worked out
/// later, because picking the wrong one is not a boot failure a user can
/// diagnose — an arm64 host handed an amd64 image gets a machine that sits
/// at a blank console. [`resolve`] refuses an architecture the entry has no
/// url for, by name.
pub struct CatalogImage {
    pub alias: &'static str,
    pub aarch64: Pinned,
    pub x86_64: Pinned,
}

impl CatalogImage {
    /// The image for a given architecture, or nothing if this entry does not
    /// publish one.
    pub fn for_arch(&self, arch: &str) -> Option<&Pinned> {
        match arch {
            "aarch64" => Some(&self.aarch64),
            "x86_64" => Some(&self.x86_64),
            _ => None,
        }
    }
}

/// Catalog of known cloud images per architecture, newest first.
///
/// Every url here names an *immutable* artifact — a dated Ubuntu serial, a
/// versioned Debian build, a Fedora compose, an Alpine point release — and
/// carries the digest its publisher published for it. That pairing is the
/// point. These entries used to point at the moving names beside them
/// (`releases/noble/release/`, `cloud/trixie/latest/`), which never needed
/// editing and could never be checked: the first fetch on a device had
/// nothing to contradict it, so whatever a mirror served that day became
/// what that device believed the image was, permanently.
///
/// The cost is that a new distribution release is a change to this table.
/// That is the right cost: a catalog entry is Asterism choosing a source on
/// the user's behalf, and it should not be able to do that without also
/// saying which bytes it means. Refreshing one means fetching the
/// publisher's checksum file for the new serial and pasting two lines.
///
/// Digest algorithms follow whatever each publisher signs — Ubuntu and
/// Fedora publish sha256, Debian and Alpine sha512 — because the point is to
/// carry their number rather than one of ours computed from a download that
/// was never checked.
pub const CATALOG: &[CatalogImage] = &[
    CatalogImage {
        alias: "ubuntu:24.04",
        aarch64: Pinned {
            url: "https://cloud-images.ubuntu.com/releases/noble/release-20260814/ubuntu-24.04-server-cloudimg-arm64.img",
            digest: "sha256:4a281a921b8d7db952895ab619736f10efe9f63e111fa5b5779ed18f023818aa",
        },
        x86_64: Pinned {
            url: "https://cloud-images.ubuntu.com/releases/noble/release-20260814/ubuntu-24.04-server-cloudimg-amd64.img",
            digest: "sha256:6e40c07ae715f744f84af0bec76415cc1987dd115b4b8de437818561f01a3733",
        },
    },
    CatalogImage {
        alias: "ubuntu:22.04",
        aarch64: Pinned {
            url: "https://cloud-images.ubuntu.com/releases/jammy/release-20260807/ubuntu-22.04-server-cloudimg-arm64.img",
            digest: "sha256:b17d9ac9b6249ab30f8c95630acdab3b7a51d76050229ab0ce6c013e303f5ccd",
        },
        x86_64: Pinned {
            url: "https://cloud-images.ubuntu.com/releases/jammy/release-20260807/ubuntu-22.04-server-cloudimg-amd64.img",
            digest: "sha256:ff271290a23279ce764561dbe2e9c3ec29da899535b571a987c37b47970c2ad9",
        },
    },
    CatalogImage {
        alias: "debian:13",
        aarch64: Pinned {
            url: "https://cloud.debian.org/images/cloud/trixie/20260819-2575/debian-13-generic-arm64-20260819-2575.qcow2",
            digest: "sha512:23f829b360500c185ee5923667319b258d5ed2e41e614982e779b87abca6fd7a5903a42e9b62635f7774d4ac4c44e9ee3037f5a9e0f61186f6a8c2e856a6f0c4",
        },
        x86_64: Pinned {
            url: "https://cloud.debian.org/images/cloud/trixie/20260819-2575/debian-13-generic-amd64-20260819-2575.qcow2",
            digest: "sha512:ae204682c015fd026838b71f1ce82585368dbb8c050b779ffd8a21a90a6c94f20648133dd078ee8fca9f0aa956e6901a943899be69ee24480035da6aeecd4f68",
        },
    },
    CatalogImage {
        alias: "debian:12",
        aarch64: Pinned {
            url: "https://cloud.debian.org/images/cloud/bookworm/20260806-2562/debian-12-generic-arm64-20260806-2562.qcow2",
            digest: "sha512:8f872616a25ac6ca7c0d1b169b062931db51cd03fda4c8cbc74f228d045b186edd1c7d105933a7149c3377372cd0196d7659f07574d7bf6425b82b01df323026",
        },
        x86_64: Pinned {
            url: "https://cloud.debian.org/images/cloud/bookworm/20260806-2562/debian-12-generic-amd64-20260806-2562.qcow2",
            digest: "sha512:0b04eda1c80b255d6234ae6fe63c43a6cb0de4afc5c37873acbc82d5b1feba7a619d2402d2341af1cf9e0898fa7d5225be343fef47349b18fe28b838001bd8eb",
        },
    },
    CatalogImage {
        alias: "fedora:42",
        aarch64: Pinned {
            url: "https://download.fedoraproject.org/pub/fedora/linux/releases/42/Cloud/aarch64/images/Fedora-Cloud-Base-Generic-42-1.1.aarch64.qcow2",
            digest: "sha256:e10658419a8d50231037dc781c3155aa94180a8c7a74e5cac2a6b09eaa9342b7",
        },
        x86_64: Pinned {
            url: "https://download.fedoraproject.org/pub/fedora/linux/releases/42/Cloud/x86_64/images/Fedora-Cloud-Base-Generic-42-1.1.x86_64.qcow2",
            digest: "sha256:e401a4db2e5e04d1967b6729774faa96da629bcf3ba90b67d8d9cce9906bec0f",
        },
    },
    CatalogImage {
        alias: "alpine:3.22",
        aarch64: Pinned {
            url: "https://dl-cdn.alpinelinux.org/alpine/v3.22/releases/cloud/nocloud_alpine-3.22.0-aarch64-uefi-cloudinit-r0.qcow2",
            digest: "sha512:30b347397387926eeb939d93c926e09833f5b49c6c6de5cc225ccdfe6e54aba88251c71da264c7e4260e78132b50e34b93409c8b4da2e843e68a4dc35fc6b155",
        },
        x86_64: Pinned {
            url: "https://dl-cdn.alpinelinux.org/alpine/v3.22/releases/cloud/nocloud_alpine-3.22.0-x86_64-uefi-cloudinit-r0.qcow2",
            digest: "sha512:2ebfc0d515dee0b8a0732d77c99f050bf2a413a5d6bc3634ac94cb48f7b31a3e59431f732810edccf4b39cc0045275a947496aff534804f2cac6e7e9d63c7c74",
        },
    },
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

/// Split a `#sha256:<hex>` pin off a reference.
///
/// A user who knows what an image should hash to can say so — `--image
/// https://mirror/x.qcow2#sha256:...` — and that turns an unverifiable
/// source into a verified one. It is a url *fragment*, so it is never sent
/// to the server, and it works on a local path for the same reason.
///
/// A fragment that was meant as a pin and is not one is an error rather than
/// a fallthrough: `#sha256:oops` becoming "unknown image" would send the user
/// looking in entirely the wrong place. A path really containing a `#` still
/// wins, because a file on this disk is a fact and a pin is a guess about
/// what the string meant.
fn split_pin(reference: &str) -> Result<(&str, Option<Digest>)> {
    let Some((base, fragment)) = reference.rsplit_once('#') else {
        return Ok((reference, None));
    };
    if PathBuf::from(shellexpand_home(reference)).exists() {
        return Ok((reference, None));
    }
    // Only a fragment shaped like `<algo>:<...>` is a pin at all; anything
    // else is part of a url or a filename and is left alone.
    if !fragment.contains(':') {
        return Ok((reference, None));
    }
    let digest = Digest::parse(fragment).with_context(|| {
        format!("{reference:?} pins a digest Asterism will not accept, so nothing was pulled")
    })?;
    Ok((base, Some(digest)))
}

pub fn resolve(reference: &str) -> Result<Resolved> {
    let (reference, pin) = split_pin(reference)?;
    let reference = DEFAULTS
        .iter()
        .find(|(bare, _)| *bare == reference)
        .map(|(_, full)| *full)
        .unwrap_or(reference);

    if let Some(entry) = CATALOG.iter().find(|c| c.alias == reference) {
        let arch = host_arch();
        // An entry that publishes nothing for this machine says so here,
        // rather than downloading somebody else's architecture and leaving
        // the user with a guest that never reaches a console.
        let published = entry
            .for_arch(arch)
            .with_context(|| format!("no {reference} image for architecture {arch}"))?;
        // A pin the user wrote wins over the catalog's: they are saying which
        // bytes they mean, and it is how somebody pulls a build newer than
        // this table without waiting for a release of Asterism.
        let expected = match &pin {
            Some(d) => d.clone(),
            None => published.expected(reference)?,
        };
        return Ok(stored(
            reference,
            Some(published.url.to_owned()),
            Some(expected),
        ));
    }

    if reference.starts_with("http://") || reference.starts_with("https://") {
        if url_has_credentials(reference) {
            bail!(
                "image URLs cannot carry credentials; use the device's credential store for registry authentication"
            );
        }
        // The one source nobody has vouched for. A catalog entry carries the
        // digest its publisher published; a registry blob carries the one its
        // manifest names; a file on this disk is already here. A url somebody
        // typed has none of that, and the only thing that can stand behind it
        // is the person who typed it.
        //
        // So it is refused rather than fetched-and-remembered. Refused *here*,
        // in a function that reads a string and touches nothing, so that
        // "unverifiable" is settled before a directory is made, a byte is
        // downloaded, or anything in the store changes — and the caller does
        // not have to be trusted to check first.
        let Some(expected) = pin else {
            bail!(
                "nothing publishes a digest for {reference}, and Asterism will not adopt \
                 bytes it cannot check — nothing was downloaded.\n\
                 \x20 Pin it to the bytes you mean and it will be verified:\n\
                 \x20   {reference}#sha256:<hex>\n\
                 \x20 The digest usually sits next to the image as a SHA256SUMS or \
                 .sha256 file; sha512 and blake3 are accepted too.\n\
                 \x20 Or use an image that comes with one: an alias from `ast images`, \
                 or an OCI reference like docker.io/library/nginx:latest."
            );
        };
        return Ok(stored(
            reference,
            Some(reference.to_owned()),
            Some(expected),
        ));
    }

    let path = PathBuf::from(shellexpand_home(reference));
    if path.exists() {
        let path = std::fs::canonicalize(&path)?;
        // A local file is not adopted — it is never rewritten and never
        // staged — so its record lives in the store, keyed by the path it
        // was resolved from. A pin, if one was written, is what
        // `verify_bootable` will be measured against on top of that.
        let record = paths::images_dir()
            .join("local")
            .join(slug(&path.display().to_string()));
        return Ok(Resolved {
            name: path.display().to_string(),
            url: None,
            format: detect_format(&path)?,
            path,
            // A file the user pointed at is theirs: it is booted in the
            // format it is in, and never rewritten in place.
            staging: None,
            oci: None,
            expected: pin,
            record,
        });
    }

    // Last, because everything above is a thing this device already knows
    // about and this is a name on somebody else's registry.
    if let Some(image) = oci::parse(reference) {
        return Ok(oci_resolved(image));
    }

    bail!(
        "unknown image {reference:?} — try an alias from `ast images`, an https:// url \
         with the digest it should have (`https://mirror/x.qcow2#sha256:<hex>`), \
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
        record: path.clone(),
        path,
        format: DiskFormat::Raw,
        staging: None,
        oci: Some(image),
        // The registry publishes digests for the layers, not for the ext4
        // this device builds out of them; `oci::pull` verifies each of those
        // as it fetches and records them on the built image.
        expected: None,
    }
}

/// An image this store owns: raw under `<slug>.raw`, staged through the
/// `<slug>.qcow2` a download (or an older Asterism) leaves there. Both names
/// come off the same slug, so a store written before raw base images is
/// recognised without a manifest to read.
fn stored(reference: &str, url: Option<String>, expected: Option<Digest>) -> Resolved {
    let dir = paths::images_dir();
    let slug = slug(reference);
    let path = dir.join(format!("{slug}.raw"));
    Resolved {
        name: reference.to_owned(),
        url,
        record: path.clone(),
        path,
        format: DiskFormat::Raw,
        staging: Some(dir.join(format!("{slug}.qcow2"))),
        oci: None,
        expected,
    }
}

/// Pull an image into this device's store, using the same cloud and OCI
/// integrity paths for local and remote callers.
///
/// The daemon owns this operation on the wire, but keeping the implementation
/// here makes the CLI, daemon, and focused store tests share adoption,
/// conversion, registry credentials, and retry behavior. The result carries
/// phase observations rather than raw downloader output, which keeps a
/// proxied response bounded.
pub fn pull(reference: &str) -> Result<ImagePullResult> {
    let resolved = resolve(reference)?;
    let mut progress = Vec::new();
    push_progress(&mut progress, "resolved", 0, None, false);

    if let Some(image) = &resolved.oci {
        push_progress(&mut progress, "kernel", 0, None, false);
        ensure_oci_kernel()?;
        push_progress(&mut progress, "layers", 0, None, false);
        let pulled = oci::pull(image, false)?;
        let bytes = std::fs::metadata(&pulled.image)
            .with_context(|| format!("reading pulled OCI image {}", pulled.image.display()))?
            .len();
        push_progress(&mut progress, "stored", bytes, Some(bytes), true);
        return Ok(ImagePullResult {
            reference: image.canonical(),
            kind: ImageKind::OciRootfs,
            bytes,
            digest: Some(pulled.digest),
            progress,
            changed: pulled.built,
        });
    }

    let (Some(url), Some(staging)) = (&resolved.url, &resolved.staging) else {
        resolved.record_local()?;
        let bytes = file_len(&resolved.path)?;
        push_progress(&mut progress, "local", bytes, Some(bytes), true);
        return Ok(pull_result(&resolved, bytes, progress, false));
    };

    if resolved.path.exists() {
        if resolved.verify_bootable().is_ok() {
            let bytes = file_len(&resolved.path)?;
            push_progress(&mut progress, "already_present", bytes, Some(bytes), true);
            return Ok(pull_result(&resolved, bytes, progress, false));
        }
        // This is a store-owned path, so a corrupt image is safe to replace.
        resolved.discard();
        push_progress(&mut progress, "repair", 0, None, false);
    }

    if !staging.exists() {
        let dir = staging
            .parent()
            .context("image staging path has no parent directory")?;
        std::fs::create_dir_all(dir)?;
        let part = staging.with_extension("qcow2.part");
        let _ = std::fs::remove_file(&part);
        download(url, &part)?;
        push_progress(&mut progress, "downloaded", file_len(&part)?, None, false);
        verify::adopt(
            &part,
            staging,
            resolved.expected.as_ref(),
            Source::new("download", url),
        )?;
        push_progress(&mut progress, "verified", file_len(staging)?, None, false);
    }

    if let Err(error) = resolved.materialise() {
        // A bad staged file must not become a retry trap. The next pull gets
        // a fresh `.part`, while an unrelated local file remains untouched.
        resolved.discard();
        return Err(error);
    }
    resolved.verify_bootable()?;
    let bytes = file_len(&resolved.path)?;
    push_progress(&mut progress, "stored", bytes, Some(bytes), true);
    Ok(pull_result(&resolved, bytes, progress, true))
}

fn ensure_oci_kernel() -> Result<()> {
    oci::ensure_kernel(|url, dest| download(url, dest)).map(|_| ())
}

fn download(url: &str, dest: &Path) -> Result<()> {
    if let Some(dir) = dest.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let status = Command::new("curl")
        .args(["--location", "--fail", "--progress-bar", "--output"])
        .arg(dest)
        .arg(url)
        .status()
        .context("running curl")?;
    if !status.success() {
        let _ = std::fs::remove_file(dest);
        bail!("download failed for {url}");
    }
    Ok(())
}

fn file_len(path: &Path) -> Result<u64> {
    Ok(std::fs::metadata(path)
        .with_context(|| format!("reading {}", path.display()))?
        .len())
}

fn pull_result(
    resolved: &Resolved,
    bytes: u64,
    progress: Vec<ImageProgress>,
    changed: bool,
) -> ImagePullResult {
    ImagePullResult {
        reference: resolved.name.clone(),
        kind: resolved.kind(),
        bytes,
        digest: verify::provenance(&resolved.path).map(|record| {
            record
                .derived_from
                .first()
                .cloned()
                .unwrap_or_else(|| record.content.to_string())
        }),
        progress,
        changed,
    }
}

fn push_progress(
    progress: &mut Vec<ImageProgress>,
    phase: &str,
    bytes: u64,
    total_bytes: Option<u64>,
    done: bool,
) {
    if progress.len() == MAX_PULL_PROGRESS {
        // Preserve the terminal observation even if a future pull gains more
        // phases. This keeps the bound a correctness property, not a best
        // effort allocation hint.
        progress.pop();
    }
    progress.push(ImageProgress {
        phase: phase.to_owned(),
        bytes,
        total_bytes,
        done,
    });
}

/// Return the device-local catalog and its current pulled/verified state.
pub fn catalog_rows() -> Result<Vec<ImageRow>> {
    catalog_rows_at(Depth::Quick)
}

/// The thorough local view used by `ast images --verify`.
pub fn catalog_rows_full() -> Result<Vec<ImageRow>> {
    catalog_rows_at(Depth::Full)
}

fn catalog_rows_at(depth: Depth) -> Result<Vec<ImageRow>> {
    let mut rows = Vec::with_capacity(CATALOG.len());
    for entry in CATALOG {
        rows.push(catalog_row(entry.alias, depth)?);
    }
    for reference in oci::built()? {
        rows.push(catalog_row(&reference, depth)?);
    }
    Ok(rows)
}

fn catalog_row(reference: &str, depth: Depth) -> Result<ImageRow> {
    let resolved = resolve(reference)?;
    let path = if resolved.path.exists() {
        resolved.path.clone()
    } else {
        resolved
            .staging
            .clone()
            .unwrap_or_else(|| resolved.path.clone())
    };
    let pulled = path.exists();
    let verified = resolved.path.exists()
        && verify::check_recorded(&resolved.path, &resolved.record, depth).is_ok()
        && resolved.pin_satisfied().is_ok();
    let bytes = if pulled { file_len(&path)? } else { 0 };
    let digest = if resolved.path.exists() {
        verify::provenance(&resolved.path).map(|record| {
            record
                .derived_from
                .first()
                .cloned()
                .unwrap_or_else(|| record.content.to_string())
        })
    } else {
        resolved.expected.as_ref().map(ToString::to_string)
    };
    let source = resolved
        .url
        .as_deref()
        .map(redact_source)
        .unwrap_or_else(|| resolved.name.clone());
    Ok(ImageRow {
        reference: resolved.name,
        kind: resolved.kind(),
        pulled,
        verified,
        bytes,
        digest,
        source,
    })
}

/// Remove credentials from a source before it crosses a management boundary.
pub fn redact_source(source: &str) -> String {
    let Some(scheme) = source.find("://") else {
        return source.to_owned();
    };
    let authority_start = scheme + 3;
    let authority_end = source[authority_start..]
        .find(&['/', '?', '#'][..])
        .map(|offset| authority_start + offset)
        .unwrap_or(source.len());
    let authority = &source[authority_start..authority_end];
    let public_authority = authority
        .rsplit_once('@')
        .map(|(_, public)| public)
        .unwrap_or(authority);
    format!(
        "{}{}{}",
        &source[..authority_start],
        public_authority,
        &source[authority_end..]
    )
}

fn url_has_credentials(source: &str) -> bool {
    let Some(scheme) = source.find("://") else {
        return false;
    };
    let authority_start = scheme + 3;
    let authority_end = source[authority_start..]
        .find(&['/', '?', '#'][..])
        .map(|offset| authority_start + offset)
        .unwrap_or(source.len());
    source[authority_start..authority_end].contains('@')
}

fn slug(s: &str) -> String {
    let mut out: String = s
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' {
                c
            } else {
                '-'
            }
        })
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
        let pinned = format!("https://example.com/x.qcow2#sha256:{}", "a".repeat(64));
        let r = resolve(&pinned).unwrap();
        assert_eq!(r.url.as_deref(), Some("https://example.com/x.qcow2"));
        assert_eq!(
            r.format,
            DiskFormat::Raw,
            "the store keeps raw, whatever the url says"
        );
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
        assert!(
            r.url.is_none(),
            "an image is pulled from a registry, not downloaded"
        );
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
        assert!(
            !unbuilt.is_pulled(),
            "nothing has been built for that digest"
        );

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

    // ---- verification ------------------------------------------------------

    /// A user who knows what an image should hash to can say so, and then
    /// an arbitrary url stops being an unverifiable source.
    #[test]
    fn a_url_can_pin_the_bytes_it_expects() {
        let hex = "a".repeat(64);
        let r = resolve(&format!("https://mirror.example/x.qcow2#sha256:{hex}")).unwrap();
        assert_eq!(r.url.as_deref(), Some("https://mirror.example/x.qcow2"));
        assert_eq!(
            r.expected.as_ref().unwrap().to_string(),
            format!("sha256:{hex}")
        );
        // The pin is not part of the name, so re-pinning the same url to a
        // digest of a different algorithm is still the same image in the
        // store rather than a second copy of it.
        let same = resolve(&format!("https://mirror.example/x.qcow2#blake3:{hex}")).unwrap();
        assert_eq!(r.path, same.path);
        assert_eq!(r.name, same.name, "the pin is not part of the name either");

        // All three algorithms this build can compute are accepted.
        for algo in ["sha256", "blake3"] {
            let r = resolve(&format!("https://mirror.example/x.qcow2#{algo}:{hex}")).unwrap();
            assert_eq!(r.expected.unwrap().algo().name(), algo);
        }
        let long = "b".repeat(128);
        let r = resolve(&format!("https://mirror.example/x.qcow2#sha512:{long}")).unwrap();
        assert_eq!(r.expected.unwrap().algo(), verify::Algo::Sha512);

        // A catalog alias takes one too: it is how you pull an image whose
        // publisher has moved the url out from under the entry.
        let pinned = resolve(&format!("ubuntu:24.04#blake3:{hex}")).unwrap();
        assert_eq!(pinned.name, "ubuntu:24.04");
        assert_eq!(
            pinned.expected.as_ref().unwrap().algo(),
            verify::Algo::Blake3
        );
    }

    /// A pin Asterism cannot check is refused when the reference is read —
    /// which is before a directory has been made, a url has been opened or
    /// anything in the store has changed.
    #[test]
    fn an_unverifiable_pin_refuses_the_reference_outright() {
        let text =
            match resolve("https://mirror.example/x.qcow2#md5:d41d8cd98f00b204e9800998ecf8427e") {
                Err(e) => format!("{e:#}"),
                Ok(r) => panic!("a digest nothing can compute resolved to {}", r.name),
            };
        assert!(
            text.contains("pins a digest Asterism will not accept"),
            "{text}"
        );
        assert!(text.contains("nothing was pulled"), "{text}");
        assert!(text.contains("unsupported digest algorithm"), "{text}");

        // A mistyped pin is an error about the pin, not "unknown image".
        let text = match resolve("https://m/x.img#sha256:zz") {
            Err(e) => format!("{e:#}"),
            Ok(r) => panic!("a malformed digest resolved to {}", r.name),
        };
        assert!(text.contains("pins a digest"), "{text}");

        // A fragment that is not a digest is not read as one, so the url
        // is simply a url with no pin — and an unpinned url is refused.
        let text = match resolve("https://mirror.example/x.qcow2#anchor") {
            Err(e) => format!("{e:#}"),
            Ok(r) => panic!("an unpinned url resolved to {}", r.name),
        };
        assert!(text.contains("nothing publishes a digest"), "{text}");
    }

    /// Architecture is a property of the catalog entry, and an entry with
    /// nothing for this machine says so by name rather than downloading
    /// somebody else's build.
    #[test]
    fn a_catalog_entry_publishes_per_architecture_and_says_when_it_does_not() {
        let mut digests = std::collections::BTreeSet::new();
        for entry in CATALOG {
            assert!(entry.for_arch("aarch64").is_some(), "{}", entry.alias);
            assert!(entry.for_arch("x86_64").is_some(), "{}", entry.alias);
            assert!(entry.for_arch("riscv64").is_none(), "{}", entry.alias);
            for arch in ["aarch64", "x86_64"] {
                let p = entry.for_arch(arch).unwrap();
                assert!(p.url.starts_with("https://"), "{} {arch}", entry.alias);
                // Every pin has to be one this build can compute, and it has
                // to be checked here rather than on a user's machine halfway
                // through a gigabyte.
                let digest = p.expected(entry.alias).unwrap();
                assert!(
                    digests.insert(digest.to_string()),
                    "{} {arch} repeats a digest another entry already claims",
                    entry.alias
                );
                // A pin is only a pin if the url cannot move under it. These
                // are the two names that republish over themselves.
                assert!(
                    !p.url.contains("/latest/"),
                    "{} {arch}: {}",
                    entry.alias,
                    p.url
                );
                assert!(
                    !p.url.contains("/release/"),
                    "{} {arch} points at a name that republishes: {}",
                    entry.alias,
                    p.url
                );
            }
            // The two builds are different files — an entry that pointed both
            // architectures at one url would boot the wrong one on half the
            // machines in an orbit.
            assert_ne!(
                entry.for_arch("aarch64").unwrap().url,
                entry.for_arch("x86_64").unwrap().url,
                "{}",
                entry.alias
            );
        }
        // What `resolve` picked really is this machine's.
        let r = resolve("ubuntu:24.04").unwrap();
        let want = CATALOG
            .iter()
            .find(|c| c.alias == "ubuntu:24.04")
            .unwrap()
            .for_arch(host_arch())
            .unwrap();
        assert_eq!(r.url.as_deref(), Some(want.url));
    }

    /// A catalog image is a source Asterism chose on the user's behalf, so
    /// the first fetch of one is checked against what its publisher
    /// published — not remembered as whatever the mirror served. This is the
    /// regression for that: substituted bytes on a device that has nothing
    /// to contradict them.
    #[test]
    fn a_substituted_first_fetch_of_a_catalog_image_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let entry = CATALOG.iter().find(|c| c.alias == "ubuntu:24.04").unwrap();
        let published = entry.for_arch("aarch64").unwrap();
        let path = dir.path().join("ubuntu-24.04.raw");
        let staging = dir.path().join("ubuntu-24.04.qcow2");
        let r = Resolved {
            name: "ubuntu:24.04".into(),
            url: Some(published.url.to_owned()),
            record: path.clone(),
            path,
            format: DiskFormat::Raw,
            staging: Some(staging.clone()),
            oci: None,
            expected: Some(published.expected("ubuntu:24.04").unwrap()),
        };

        // The download stage: what `ast pull` hands to `verify::adopt`.
        let part = dir.path().join("ubuntu-24.04.qcow2.part");
        std::fs::write(&part, b"an image somebody else would like you to boot").unwrap();
        let text = format!(
            "{:#}",
            verify::adopt(
                &part,
                &staging,
                r.expected.as_ref(),
                verify::Source::new("download", published.url),
            )
            .unwrap_err()
        );
        assert!(
            text.contains("does not match its published digest"),
            "{text}"
        );
        assert!(
            text.contains(published.digest),
            "the error names the pin: {text}"
        );
        assert!(
            !staging.exists(),
            "the substituted download was not adopted"
        );
        assert!(!part.exists(), "nor left where a retry would resume it");

        // And the conversion stage refuses the same bytes, so a store left
        // holding a staged download from before this check existed cannot
        // finish into a bootable image either.
        std::fs::write(&staging, b"an image somebody else would like you to boot").unwrap();
        let text = format!("{:#}", r.materialise().unwrap_err());
        assert!(text.contains("is not what was published"), "{text}");
        assert!(!r.path.exists());
    }

    /// The pins in the table are the publishers' own numbers, in the
    /// publishers' own algorithms — Ubuntu and Fedora sign sha256, Debian
    /// and Alpine sha512 — because the point is to carry their number rather
    /// than one of ours computed from a download nothing checked.
    #[test]
    fn catalog_pins_are_the_publishers_own_digests() {
        let expect = |alias: &str, algo: verify::Algo| {
            let entry = CATALOG.iter().find(|c| c.alias == alias).unwrap();
            for arch in ["aarch64", "x86_64"] {
                assert_eq!(
                    entry
                        .for_arch(arch)
                        .unwrap()
                        .expected(alias)
                        .unwrap()
                        .algo(),
                    algo,
                    "{alias} {arch}"
                );
            }
        };
        expect("ubuntu:24.04", verify::Algo::Sha256);
        expect("ubuntu:22.04", verify::Algo::Sha256);
        expect("debian:13", verify::Algo::Sha512);
        expect("debian:12", verify::Algo::Sha512);
        expect("fedora:42", verify::Algo::Sha256);
        expect("alpine:3.22", verify::Algo::Sha512);
    }

    /// Resolving a catalog alias always carries a pin, and a user's own pin
    /// replaces it — which is how somebody pulls a build newer than this
    /// table without waiting for a release of Asterism.
    #[test]
    fn a_catalog_alias_always_resolves_with_something_to_check_against() {
        for entry in CATALOG {
            let r = resolve(entry.alias).unwrap();
            let want = entry.for_arch(host_arch()).unwrap();
            assert_eq!(
                r.expected.as_ref().map(|d| d.to_string()),
                Some(want.digest.to_owned()),
                "{}",
                entry.alias
            );
        }
        let mine = format!("blake3:{}", "c".repeat(64));
        let overridden = resolve(&format!("debian:13#{mine}")).unwrap();
        assert_eq!(overridden.name, "debian:13");
        assert_eq!(overridden.expected.unwrap().to_string(), mine);
    }

    /// A converted image is bytes nobody upstream ever published, so what
    /// makes it accountable is the digest of what it came out of. Raw bytes
    /// under the qcow2 name keep this free of `qemu-img`.
    #[test]
    fn a_converted_image_records_what_it_was_converted_from() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("debian-13.raw");
        let staging = dir.path().join("debian-13.qcow2");
        let r = Resolved {
            name: "debian:13".into(),
            url: None,
            record: path.clone(),
            path,
            format: DiskFormat::Raw,
            staging: Some(staging.clone()),
            oci: None,
            expected: None,
        };
        let bytes = vec![7u8; 4096];
        std::fs::write(&staging, &bytes).unwrap();
        assert!(r.materialise().unwrap());

        let record = verify::provenance(&r.path).unwrap();
        assert_eq!(record.kind, "base-image");
        assert_eq!(record.source, "debian:13");
        assert_eq!(
            record.derived_from,
            vec![verify::Digest::of_bytes(verify::OWN_ALGO, &bytes).to_string()],
            "the raw names the download it came out of"
        );
        // And having a record is what makes it bootable.
        r.verify_bootable().unwrap();
        // The staging copy is gone, and so is its own record.
        assert!(!staging.exists());
        assert!(!verify::provenance_path(&staging).exists());
    }

    /// The staged download is checked again on the way through the
    /// conversion, so a store interrupted between download and convert
    /// cannot finish into a bootable image with the wrong bytes in it.
    #[test]
    fn a_poisoned_staging_file_never_becomes_a_base_image() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ubuntu-24.04.raw");
        let staging = dir.path().join("ubuntu-24.04.qcow2");
        let honest = vec![1u8; 2048];
        let r = Resolved {
            name: "ubuntu:24.04".into(),
            url: Some("https://mirror.example/u.img".into()),
            record: path.clone(),
            path,
            format: DiskFormat::Raw,
            staging: Some(staging.clone()),
            oci: None,
            expected: Some(verify::Digest::of_bytes(verify::Algo::Sha256, &honest)),
        };
        std::fs::write(&staging, vec![2u8; 2048]).unwrap();

        let text = format!("{:#}", r.materialise().unwrap_err());
        assert!(text.contains("is not what was published"), "{text}");
        assert!(!r.path.exists(), "nothing bootable was produced");
        assert!(r.verify_bootable().is_err());
    }

    /// Offline reuse: an image adopted once is booted again with no network
    /// and no re-hash of a gigabyte, because size and mtime still agree with
    /// what was written down.
    #[test]
    fn an_adopted_image_is_reused_offline() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("alpine-3.22.raw");
        let staging = dir.path().join("alpine-3.22.qcow2");
        let r = Resolved {
            name: "alpine:3.22".into(),
            url: Some("https://dl-cdn.example/a.qcow2".into()),
            record: path.clone(),
            path,
            format: DiskFormat::Raw,
            staging: Some(staging.clone()),
            oci: None,
            expected: None,
        };
        std::fs::write(&staging, vec![3u8; 1024]).unwrap();
        assert!(r.materialise().unwrap());
        assert!(!r.materialise().unwrap(), "and again is a no-op");
        assert!(r.is_pulled());
        r.verify_bootable().unwrap();
        r.verify_bootable().unwrap();
    }

    /// A file the user pointed at is theirs — never rewritten, never staged —
    /// so what is recorded is its identity, in the store. The case this
    /// exists for is the path holding different bytes at boot than it held
    /// when the instance was created.
    #[test]
    fn a_local_file_that_changes_under_us_is_refused_at_boot() {
        let dir = tempfile::tempdir().unwrap();
        let theirs = dir.path().join("mine.raw");
        std::fs::write(&theirs, vec![4u8; 4096]).unwrap();
        let store = dir.path().join("store").join("mine");

        let mut r = resolve(&theirs.display().to_string()).unwrap();
        assert!(r.staging.is_none(), "the user's file is never staged");
        // The store this test owns, rather than whichever one this machine
        // has: `resolve` picks the real one and nothing here should write
        // into it.
        r.record = store.clone();
        r.record_local().unwrap();
        assert!(
            !verify::provenance_path(&theirs).exists(),
            "nothing is written beside it"
        );
        r.verify_bootable().unwrap();

        // A user who replaces their image replaces its length too, which is
        // the half of the check that costs a stat.
        std::fs::write(&theirs, vec![5u8; 8192]).unwrap();
        let text = format!("{:#}", r.verify_bootable().unwrap_err());
        assert!(text.contains("cannot be booted from"), "{text}");
        assert!(text.contains("truncated or replaced"), "{text}");

        // Same length, and written in the same second so the mtime has not
        // visibly moved: only a full re-hash can see this, which is what
        // `ast images --verify` and ASTERISM_VERIFY=full are for.
        std::fs::write(&theirs, vec![4u8; 4096]).unwrap();
        r.record_local().unwrap();
        std::fs::write(&theirs, vec![6u8; 4096]).unwrap();
        let text = format!(
            "{:#}",
            verify::check_recorded(&r.path, &r.record, verify::Depth::Full).unwrap_err()
        );
        assert!(
            text.contains("is not the file Asterism recorded"),
            "a file the user owns was never pulled from anywhere: {text}"
        );
    }

    /// The store may replace what it downloaded and must never touch what
    /// the user pointed at. These two are one line apart in `ast pull`, and
    /// confusing them deletes somebody's only copy of a disk image.
    #[test]
    fn only_the_stores_own_images_can_be_discarded() {
        let dir = tempfile::tempdir().unwrap();

        let theirs = dir.path().join("precious.raw");
        std::fs::write(&theirs, vec![8u8; 128]).unwrap();
        let local = resolve(&theirs.display().to_string()).unwrap();
        assert!(!local.is_ours());
        assert!(
            !local.discard(),
            "a file the user pointed at is not ours to throw away"
        );
        assert!(theirs.exists(), "and it is still there");

        // An image the store downloaded is ours, and goes when it is told to.
        let path = dir.path().join("debian-13.raw");
        let staging = dir.path().join("debian-13.qcow2");
        let ours = Resolved {
            name: "debian:13".into(),
            url: Some("https://cloud.debian.example/d.qcow2".into()),
            record: path.clone(),
            path,
            format: DiskFormat::Raw,
            staging: Some(staging.clone()),
            oci: None,
            expected: None,
        };
        std::fs::write(&staging, vec![9u8; 64]).unwrap();
        assert!(ours.materialise().unwrap());
        assert!(ours.is_ours());
        assert!(ours.discard());
        assert!(!ours.path.exists());
        assert!(!verify::provenance_path(&ours.path).exists());
        assert!(!staging.exists(), "a half-finished download goes with it");

        // An OCI reference has its own store and is not discarded this way.
        let container = resolve(&format!("nginx@sha256:{}", "0".repeat(64))).unwrap();
        assert!(!container.is_ours());
        assert!(!container.discard());
    }

    /// A url is slugged without its pin, so two pins name one file in the
    /// store. "Is it pulled" and "is the *right* thing pulled" are then
    /// different questions, and answering only the first makes the digest
    /// the user typed do nothing.
    #[test]
    fn a_reference_pinned_to_other_bytes_does_not_accept_what_is_already_there() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("url-abc.raw");
        let staging = dir.path().join("url-abc.qcow2");
        let served = vec![1u8; 512];
        let published = verify::Digest::of_bytes(verify::Algo::Sha256, &served);
        let other = verify::Digest::of_bytes(verify::Algo::Sha256, b"a different build");

        let mut r = Resolved {
            name: "https://mirror.example/x.qcow2".into(),
            url: Some("https://mirror.example/x.qcow2".into()),
            record: path.clone(),
            path,
            format: DiskFormat::Raw,
            staging: Some(staging.clone()),
            oci: None,
            expected: Some(published.clone()),
        };
        std::fs::write(&staging, &served).unwrap();
        assert!(r.materialise().unwrap());
        r.verify_bootable().unwrap();

        // The same store, asked for a different build of the same url.
        r.expected = Some(other.clone());
        let text = format!("{:#}", r.verify_bootable().unwrap_err());
        assert!(text.contains("published a different digest"), "{text}");
        assert!(
            text.contains(&other.to_string()),
            "it names what was asked for: {text}"
        );
        assert!(
            text.contains(&published.to_string()),
            "and what is here: {text}"
        );
        assert!(text.contains("pull again"), "{text}");

        // Which is what makes `ast pull` fetch it: the copy here is the
        // store's own, so it is discardable, and the next pull is a real one.
        assert!(r.is_ours());
        assert!(r.discard());
        assert!(!r.path.exists());
    }

    /// A pin on a local path is checked the moment the user writes it, not
    /// written down unexamined and then compared to itself forever.
    #[test]
    fn a_pin_on_a_local_file_is_checked_when_it_is_recorded() {
        let dir = tempfile::tempdir().unwrap();
        let theirs = dir.path().join("mine.raw");
        std::fs::write(&theirs, b"the bytes they meant").unwrap();
        let right = verify::Digest::of_bytes(verify::Algo::Sha256, b"the bytes they meant");
        let wrong = verify::Digest::of_bytes(verify::Algo::Sha256, b"some other bytes");

        let mut r = resolve(&format!("{}#{right}", theirs.display())).unwrap();
        r.record = dir.path().join("store").join("mine");
        r.record_local().unwrap();
        r.verify_bootable().unwrap();
        assert!(verify::provenance(&r.record)
            .unwrap()
            .derived_from
            .contains(&right.to_string()));

        let mut wrongly = resolve(&format!("{}#{wrong}", theirs.display())).unwrap();
        wrongly.record = r.record.clone();
        let text = format!("{:#}", wrongly.record_local().unwrap_err());
        assert!(text.contains("is not the file"), "{text}");
        assert!(text.contains("does not match its digest"), "{text}");
    }

    /// An image in the store that nothing can account for is not booted, and
    /// the error says how to fix it rather than what went wrong internally.
    #[test]
    fn an_image_with_no_record_is_not_bootable() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("stray.raw");
        std::fs::write(&path, vec![6u8; 512]).unwrap();
        let r = Resolved {
            name: "stray".into(),
            url: None,
            record: path.clone(),
            path,
            format: DiskFormat::Raw,
            staging: None,
            oci: None,
            expected: None,
        };
        let text = format!("{:#}", r.verify_bootable().unwrap_err());
        assert!(text.contains("no provenance record"), "{text}");
        assert!(text.contains("ast pull"), "{text}");
    }

    /// What `ast move` leaves behind when it fetches a base image off an
    /// orbit peer instead of the internet, and what the instance it moved
    /// needs in order to boot from it.
    ///
    /// Both halves are load-bearing, and the peer fetch used to write
    /// neither. Without a record at all the boot gate refuses an image
    /// nobody can account for. Without the parents the peer's own record
    /// named, the *pin* refuses it instead: `debian:13` names the sha256 its
    /// publisher published, and the raw image converted out of that download
    /// hashes to something else entirely — `derived_from` is the only thing
    /// that ties the two together, so it has to cross the wire with the
    /// bytes.
    #[test]
    fn a_base_image_fetched_from_a_peer_boots_and_still_answers_its_pin() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("debian-13.raw");
        let published = verify::Digest::of_bytes(verify::Algo::Sha256, b"the cloud image");
        let r = Resolved {
            name: "debian:13".into(),
            url: None,
            record: path.clone(),
            path,
            format: DiskFormat::Raw,
            staging: Some(dir.path().join("debian-13.qcow2")),
            oci: None,
            expected: Some(published.clone()),
        };

        // The target's half of the fetch: bytes proved against the content
        // address in the move manifest, then adopted with the reference as
        // their origin and the parents the source's record named.
        let bytes = vec![9u8; 8192];
        let staged = dir.path().join("debian-13.raw.moving");
        std::fs::write(&staged, &bytes).unwrap();
        let arrived = verify::Digest::of_bytes(verify::OWN_ALGO, &bytes);
        verify::adopt_recorded(
            &staged,
            &r.path,
            &r.record,
            Some(&arrived),
            Source::new("base-image", &r.name).derived_from([published.to_string()]),
        )
        .unwrap();

        r.verify_bootable().unwrap();

        // Drop the parents — a manifest that did not carry them, or a source
        // with no record of its own — and the same verified bytes stop
        // answering the pin.
        verify::record(&r.path, &r.record, Source::new("base-image", "debian:13")).unwrap();
        let text = format!("{:#}", r.verify_bootable().unwrap_err());
        assert!(
            text.contains("a different digest than the one asked for"),
            "{text}"
        );
    }

    /// Migration is lazy: an image that only exists as the qcow2 an older
    /// Asterism pulled still counts as pulled, and converts on first use.
    #[test]
    fn a_qcow2_left_by_an_older_store_is_still_the_image() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("debian-13.raw");
        let r = Resolved {
            name: "debian:13".into(),
            url: None,
            record: path.clone(),
            path,
            format: DiskFormat::Raw,
            staging: Some(dir.path().join("debian-13.qcow2")),
            oci: None,
            expected: None,
        };
        assert!(!r.is_pulled());
        assert!(!r.materialise().unwrap(), "nothing there to convert yet");

        // Raw bytes under the qcow2 name: no qemu-img needed, so this half
        // of the migration is testable without one installed.
        std::fs::write(r.staging.as_ref().unwrap(), vec![7u8; 1024]).unwrap();
        assert!(r.is_pulled());
        assert!(r.materialise().unwrap());
        assert!(r.path.exists());
        assert!(
            !r.staging.as_ref().unwrap().exists(),
            "the staging copy is not kept"
        );
        assert!(!r.materialise().unwrap(), "and again is a no-op");
    }

    #[test]
    fn catalog_sources_redact_url_credentials() {
        assert_eq!(
            redact_source("https://user:secret@example.test/path#sha256:abc"),
            "https://example.test/path#sha256:abc"
        );
        assert_eq!(
            redact_source("docker.io/library/nginx:latest"),
            "docker.io/library/nginx:latest"
        );
    }

    #[test]
    fn pull_progress_is_bounded_and_keeps_the_latest_observation() {
        let mut progress = Vec::new();
        for i in 0..(MAX_PULL_PROGRESS + 8) {
            push_progress(&mut progress, "phase", i as u64, None, i == MAX_PULL_PROGRESS + 7);
        }
        assert_eq!(progress.len(), MAX_PULL_PROGRESS);
        assert!(progress.last().is_some_and(|item| item.done));
        assert_eq!(
            progress.last().unwrap().bytes,
            (MAX_PULL_PROGRESS + 7) as u64
        );
    }
}
