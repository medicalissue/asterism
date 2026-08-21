//! Content-addressed verification and provenance for every boot input.
//!
//! Everything a guest boots from arrives from somewhere else: a cloud image
//! off an https url, a container image's layers off a registry, a kernel and
//! an initrd off Ubuntu's mirror, a file the user pointed at. Each of those
//! lands in the store as a file, and every one of them used to be adopted on
//! the strength of `curl` exiting zero. That is not a check. A connection cut
//! mid-transfer, a mirror serving the wrong bytes, a cache somebody wrote into
//! by hand — all three produce a file with the right *name*, and a name is
//! what the rest of Asterism trusted.
//!
//! This module is the one place bytes become trusted, and it has two gates.
//!
//! **Adoption.** [`adopt`] is the only way a downloaded or built file takes
//! its durable name in the store. It hashes what is in the `.part`, refuses
//! it if a digest was known and does not match, writes a provenance record,
//! and only then renames. Nothing partially written, and nothing that failed
//! its digest, ever gets the name the boot path looks for — which is what
//! makes an interrupted pull safe to resume rather than a poisoned cache.
//!
//! **Boot.** [`check`] runs before a hypervisor is handed a path. It reads
//! the provenance written at adoption and confirms the file is still that
//! file. A missing record is a refusal, not a shrug: an artifact nobody can
//! account for is exactly the one not to boot.
//!
//! ## What the boot gate actually costs
//!
//! A base image is about a gigabyte and `ast up` is expected to be quick, so
//! [`Depth::Quick`] — the default — re-hashes only when the file's size or
//! mtime has moved off what provenance recorded, and accepts it otherwise.
//! That catches truncation, replacement and in-place corruption, which are
//! the ways a cache actually goes bad. It does not catch an adversary who can
//! already write to `~/.asterism` and takes the trouble to forge an mtime;
//! nothing short of a full hash does, and [`Depth::Full`] is that hash, run
//! by `ast images --verify` and by anything that wants certainty over speed.
//!
//! ## Provenance
//!
//! `<artifact>.provenance` sits next to each adopted file: the digest of its
//! bytes, its size and mtime, where it came from, and what it was derived
//! from. That last field is what makes a converted image accountable — a
//! `<slug>.raw` records the digest of the qcow2 it was converted from, so
//! "where did these bytes come from" has an answer for a file that no
//! upstream ever published.

use std::fmt;
use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

use crate::durable;

/// Hash functions a digest may name.
///
/// Registries speak sha256 and (rarely) sha512; blake3 is what Asterism uses
/// for bytes it addresses itself, because a gigabyte has to be hashed in
/// about a second and it is already in the tree. Anything else is refused
/// rather than assumed — a digest whose algorithm we cannot compute is not a
/// weaker check, it is no check at all, and pretending otherwise is how an
/// unverifiable source gets booted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Algo {
    Sha256,
    Sha512,
    Blake3,
}

impl Algo {
    pub fn name(self) -> &'static str {
        match self {
            Algo::Sha256 => "sha256",
            Algo::Sha512 => "sha512",
            Algo::Blake3 => "blake3",
        }
    }

    /// Hex length of a digest of this algorithm, for the shape check that
    /// catches a truncated digest before it is used to verify anything.
    fn hex_len(self) -> usize {
        match self {
            Algo::Sha256 => 64,
            Algo::Sha512 => 128,
            Algo::Blake3 => 64,
        }
    }

    pub fn parse(name: &str) -> Option<Algo> {
        match name {
            "sha256" => Some(Algo::Sha256),
            "sha512" => Some(Algo::Sha512),
            "blake3" => Some(Algo::Blake3),
            _ => None,
        }
    }
}

impl fmt::Display for Algo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// A content address: an algorithm and the hex it produced.
///
/// Written and read as `sha256:<hex>`, which is the registry's spelling and
/// therefore the one a user has already seen.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Digest {
    algo: Algo,
    hex: String,
}

impl Digest {
    pub fn algo(&self) -> Algo {
        self.algo
    }

    pub fn hex(&self) -> &str {
        &self.hex
    }

    /// Read `sha256:<hex>`.
    ///
    /// The error says which half was wrong, because the two are acted on
    /// differently: an unsupported algorithm means this source cannot be
    /// verified here at all, and a malformed hex means the digest itself was
    /// mistyped.
    pub fn parse(s: &str) -> Result<Digest> {
        let (algo, hex) = s
            .split_once(':')
            .with_context(|| format!("{s:?} is not a digest — write it as sha256:<hex>"))?;
        let algo = Algo::parse(algo).with_context(|| {
            format!(
                "unsupported digest algorithm {algo:?} — Asterism verifies sha256, sha512 \
                 and blake3, and refuses to adopt bytes it cannot check"
            )
        })?;
        let hex = hex.to_ascii_lowercase();
        if hex.len() != algo.hex_len() || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
            bail!(
                "{s:?} is not a {algo} digest — it takes {} hex characters, this has {}",
                algo.hex_len(),
                hex.len()
            );
        }
        Ok(Digest { algo, hex })
    }

    pub fn of_bytes(algo: Algo, bytes: &[u8]) -> Digest {
        let mut h = Hasher::new(algo);
        h.update(bytes);
        h.finish()
    }

    /// Hash a whole file without reading it into memory. A megabyte at a
    /// time: a base image does not fit in ram and a layer blob need not.
    pub fn of_file(algo: Algo, path: &Path) -> Result<Digest> {
        let mut file = std::fs::File::open(path)
            .with_context(|| format!("hashing {}", path.display()))?;
        let mut hasher = Hasher::new(algo);
        let mut buf = vec![0u8; 1 << 20];
        loop {
            let n = file
                .read(&mut buf)
                .with_context(|| format!("hashing {}", path.display()))?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
        Ok(hasher.finish())
    }

    /// Confirm these bytes are the ones this digest names.
    pub fn verify_bytes(&self, bytes: &[u8], what: &str) -> Result<()> {
        self.matched(&Digest::of_bytes(self.algo, bytes), what)
    }

    /// Confirm this file holds the bytes this digest names.
    pub fn verify_file(&self, path: &Path, what: &str) -> Result<()> {
        self.matched(&Digest::of_file(self.algo, path)?, what)
    }

    /// The refusal itself says only what was expected and what arrived; what
    /// it *means* is the caller's to add, because "a download was discarded"
    /// and "an image in the store is no longer bootable" are the same
    /// mismatch and completely different news.
    fn matched(&self, actual: &Digest, what: &str) -> Result<()> {
        if actual == self {
            return Ok(());
        }
        bail!("{what} does not match its digest — expected {self}, got {actual}")
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.algo, self.hex)
    }
}

/// One streaming hash, whichever algorithm was asked for.
enum Hasher {
    Sha256(sha2::Sha256),
    Sha512(sha2::Sha512),
    Blake3(Box<blake3::Hasher>),
}

impl Hasher {
    fn new(algo: Algo) -> Hasher {
        use sha2::Digest as _;
        match algo {
            Algo::Sha256 => Hasher::Sha256(sha2::Sha256::new()),
            Algo::Sha512 => Hasher::Sha512(sha2::Sha512::new()),
            Algo::Blake3 => Hasher::Blake3(Box::new(blake3::Hasher::new())),
        }
    }

    fn update(&mut self, bytes: &[u8]) {
        use sha2::Digest as _;
        match self {
            Hasher::Sha256(h) => h.update(bytes),
            Hasher::Sha512(h) => h.update(bytes),
            Hasher::Blake3(h) => {
                h.update(bytes);
            }
        }
    }

    fn finish(self) -> Digest {
        use sha2::Digest as _;
        let (algo, hex) = match self {
            Hasher::Sha256(h) => (Algo::Sha256, hex(&h.finalize())),
            Hasher::Sha512(h) => (Algo::Sha512, hex(&h.finalize())),
            Hasher::Blake3(h) => (Algo::Blake3, h.finalize().to_hex().to_string()),
        };
        Digest { algo, hex }
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// ---- provenance ------------------------------------------------------------

/// The digest Asterism uses for bytes nobody else published a digest for —
/// a converted raw image, a built ext4, a file on this disk.
pub const OWN_ALGO: Algo = Algo::Blake3;

/// Where an artifact's bytes came from, and what they are.
///
/// A record is written next to every adopted file and read back before it is
/// booted. It is deliberately plain text rather than a serde struct: it is
/// read by a boot path that must not fail obscurely, and a field an older
/// Asterism does not know is skipped rather than fatal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Provenance {
    /// Digest of the adopted bytes.
    pub content: Digest,
    pub size: u64,
    /// Mtime at adoption, as seconds since the epoch. The cheap half of the
    /// boot check.
    pub mtime: i64,
    /// What kind of boot input this is: `base-image`, `oci-rootfs`, `kernel`,
    /// `initrd`, `blob`, `local-image`.
    pub kind: String,
    /// Where it came from, in whatever vocabulary fits: a url, a registry
    /// reference, a local path.
    pub source: String,
    /// Digests these bytes were derived from — the qcow2 a raw was converted
    /// out of, the manifest and layers an ext4 was built from. Empty for
    /// something fetched whole.
    pub derived_from: Vec<String>,
}

impl Provenance {
    fn render(&self) -> String {
        let mut s = String::new();
        s.push_str("asterism-provenance 1\n");
        s.push_str(&format!("content {}\n", self.content));
        s.push_str(&format!("size {}\n", self.size));
        s.push_str(&format!("mtime {}\n", self.mtime));
        s.push_str(&format!("kind {}\n", self.kind));
        // A source is a url or a reference: neither may contain a newline,
        // and one that does would break the record it is written into.
        s.push_str(&format!("source {}\n", one_line(&self.source)));
        for parent in &self.derived_from {
            s.push_str(&format!("derived-from {}\n", one_line(parent)));
        }
        s
    }

    fn parse(text: &str) -> Result<Provenance> {
        let mut content = None;
        let mut size = None;
        let mut mtime = 0i64;
        let mut kind = String::new();
        let mut source = String::new();
        let mut derived_from = Vec::new();
        for line in text.lines() {
            let (key, value) = line.split_once(' ').unwrap_or((line, ""));
            match key {
                "content" => content = Some(Digest::parse(value)?),
                "size" => size = value.parse().ok(),
                "mtime" => mtime = value.parse().unwrap_or(0),
                "kind" => kind = value.to_owned(),
                "source" => source = value.to_owned(),
                "derived-from" => derived_from.push(value.to_owned()),
                _ => {}
            }
        }
        Ok(Provenance {
            content: content.context("provenance record names no content digest")?,
            size: size.context("provenance record names no size")?,
            mtime,
            kind,
            source,
            derived_from,
        })
    }
}

fn one_line(s: &str) -> String {
    s.replace(['\n', '\r'], " ")
}

/// Where an artifact's provenance record lives: beside it, same name plus
/// `.provenance`. Beside rather than in a central index because the two have
/// to be deleted together, and a store somebody pruned by hand should lose
/// both or neither.
pub fn provenance_path(artifact: &Path) -> PathBuf {
    let mut name = artifact.as_os_str().to_owned();
    name.push(".provenance");
    PathBuf::from(name)
}

/// Read what was recorded when this artifact was adopted.
pub fn provenance(artifact: &Path) -> Option<Provenance> {
    let text = std::fs::read_to_string(provenance_path(artifact)).ok()?;
    Provenance::parse(&text).ok()
}

fn mtime_of(meta: &std::fs::Metadata) -> i64 {
    use std::os::unix::fs::MetadataExt;
    meta.mtime()
}

/// A source Asterism fetches from, and the digest it must produce.
///
/// `digest` is `Option` because not every publisher pins one. A url that
/// republishes in place — Ubuntu's `.../releases/noble/release/`, Debian's
/// `latest/` — cannot have a digest written down in this tree without turning
/// every point release into a refusal for anybody who upgraded Asterism but
/// not their store. What stands in for it is the other half of this module:
/// whatever is fetched is hashed, recorded, and checked against that record
/// before every boot, so an artifact is pinned to the bytes this device
/// adopted even when upstream would not pin them for us. A filled-in digest
/// is strictly better and the field is here so it can be filled in, per
/// entry, with no other change anywhere.
pub struct Pinned {
    pub url: &'static str,
    pub digest: Option<&'static str>,
}

impl Pinned {
    /// The digest this entry pins, parsed.
    ///
    /// Called before anything is fetched or removed: a pin this build cannot
    /// compute has to refuse the operation with the store exactly as it was,
    /// rather than after a download has already landed somewhere.
    pub fn expected(&self, what: &str) -> Result<Option<Digest>> {
        self.digest
            .map(Digest::parse)
            .transpose()
            .with_context(|| format!("the pinned digest for {what} is one Asterism cannot check"))
    }
}

// ---- adoption --------------------------------------------------------------

/// How the bytes being adopted arrived, for the record and for the error
/// message when they are refused.
pub struct Source<'a> {
    pub kind: &'a str,
    pub origin: &'a str,
    pub derived_from: Vec<String>,
}

impl<'a> Source<'a> {
    pub fn new(kind: &'a str, origin: &'a str) -> Source<'a> {
        Source { kind, origin, derived_from: Vec::new() }
    }

    pub fn derived_from(mut self, parents: impl IntoIterator<Item = String>) -> Source<'a> {
        self.derived_from = parents.into_iter().collect();
        self
    }
}

/// Give a staged file its durable name, but only once its bytes are accounted
/// for.
///
/// The order is the point:
///
/// 1. hash what is in `staged`;
/// 2. if `expected` was published, refuse anything else — and delete the
///    staged file, so a poisoned mirror cannot be resumed into place by a
///    later run that skips the download because "the part is already there";
/// 3. write the provenance record;
/// 4. rename `staged` to `dest`.
///
/// Step 3 before step 4 is what makes an interrupted adoption safe: the
/// artifact never exists without a record, so [`check`] refusing a record-less
/// file cannot be triggered by a crash. The other order — rename, then
/// record — has a window in which a bootable file has no provenance, and that
/// window is exactly a power cut.
pub fn adopt(
    staged: &Path,
    dest: &Path,
    expected: Option<&Digest>,
    source: Source<'_>,
) -> Result<Provenance> {
    let meta = std::fs::metadata(staged)
        .with_context(|| format!("adopting {}", staged.display()))?;
    let algo = expected.map(|d| d.algo).unwrap_or(OWN_ALGO);
    let content = Digest::of_file(algo, staged)?;

    if let Some(want) = expected {
        if &content != want {
            let _ = std::fs::remove_file(staged);
            bail!(
                "{} does not match its published digest — expected {want}, got {content}. \
                 The download was discarded and nothing in the store was changed; \
                 retry, and if it happens again the source is serving different bytes \
                 than it says it is.",
                source.origin
            );
        }
    }

    let record = Provenance {
        content,
        size: meta.len(),
        mtime: mtime_of(&meta),
        kind: source.kind.to_owned(),
        source: source.origin.to_owned(),
        derived_from: source.derived_from,
    };
    if let Some(dir) = dest.parent() {
        std::fs::create_dir_all(dir)?;
    }
    write_record(dest, &record)?;
    // `publish_file` rather than a bare rename: the staged bytes are forced
    // down before the name that will point at them exists, and the directory
    // entry is forced down after. A base image every instance clones from is
    // worth the one flush, and half a cloud image under the name of a whole
    // one is a boot failure with no clue in it.
    durable::publish_file(staged, dest)?;
    // The rename may have carried an mtime the staged file had; re-read it so
    // the quick check compares against what is actually on disk now.
    if let Ok(after) = std::fs::metadata(dest) {
        let settled = mtime_of(&after);
        if settled != record.mtime {
            let record = Provenance { mtime: settled, ..record.clone() };
            write_record(dest, &record)?;
            return Ok(record);
        }
    }
    Ok(record)
}

fn write_record(artifact: &Path, record: &Provenance) -> Result<()> {
    let path = provenance_path(artifact);
    // Appended, never `with_extension`: that would replace `.raw`, and
    // `<slug>.raw` and `<slug>.qcow2` would then stage their records through
    // one shared name.
    let mut staging = path.as_os_str().to_owned();
    staging.push(".part");
    let staging = PathBuf::from(staging);
    std::fs::write(&staging, record.render())
        .with_context(|| format!("writing {}", path.display()))?;
    durable::publish_file(&staging, &path)?;
    Ok(())
}

/// Record provenance for a file that is already where it belongs.
///
/// For artifacts adopted by an older Asterism, and for the one case where
/// the bytes are not ours to stage: a file the user pointed `--image` at is
/// used in place and never rewritten, so its identity is recorded rather than
/// its adoption. The record then lives in the store, not next to the user's
/// file, which is why this takes the record's path separately.
pub fn record(artifact: &Path, at: &Path, source: Source<'_>) -> Result<Provenance> {
    let meta = std::fs::metadata(artifact)
        .with_context(|| format!("reading {}", artifact.display()))?;
    let record = Provenance {
        content: Digest::of_file(OWN_ALGO, artifact)?,
        size: meta.len(),
        mtime: mtime_of(&meta),
        kind: source.kind.to_owned(),
        source: source.origin.to_owned(),
        derived_from: source.derived_from,
    };
    if let Some(dir) = at.parent() {
        std::fs::create_dir_all(dir)?;
    }
    write_record(at, &record)?;
    Ok(record)
}

// ---- the boot gate ---------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Depth {
    /// Re-hash only if size or mtime moved. What every boot does.
    Quick,
    /// Re-hash regardless. What `ast images --verify` does.
    Full,
}

impl Depth {
    /// `ASTERISM_VERIFY=full` turns every boot into a full re-hash, for
    /// somebody who would rather pay the second than trust an mtime.
    pub fn from_env() -> Depth {
        match std::env::var("ASTERISM_VERIFY").as_deref() {
            Ok("full") => Depth::Full,
            _ => Depth::Quick,
        }
    }
}

/// Confirm an artifact is still the one that was adopted, using the record
/// written beside it.
///
/// The record's path is separate from the artifact's because a local file
/// the user owns is verified against a record kept in the store.
pub fn check_recorded(artifact: &Path, record_at: &Path, depth: Depth) -> Result<()> {
    // Absence first, and separately: "there is nothing here" and "what is
    // here cannot be accounted for" are different problems with different
    // fixes, and folding the first into the second would tell somebody who
    // has simply not pulled an image yet that their store is corrupt.
    let meta = match std::fs::metadata(artifact) {
        Ok(meta) => meta,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            bail!("{} is not on this device", artifact.display())
        }
        Err(e) => {
            return Err(e).with_context(|| format!("verifying {}", artifact.display()))
        }
    };
    let Some(record) = provenance(record_at) else {
        bail!(
            "{} has no provenance record, so there is no way to say whether it is the \
             image that was pulled — Asterism will not boot bytes it cannot account for. \
             Re-pull it (`ast pull`) to adopt it properly.",
            artifact.display()
        );
    };

    if meta.len() != record.size {
        // Size alone already settles it: hashing would only confirm what a
        // stat has proved, and a truncated multi-gigabyte image is not worth
        // reading twice to say so.
        bail!(
            "{} is {} bytes but was adopted at {} — it has been truncated or replaced \
             since it was verified. Delete it and re-pull.",
            artifact.display(),
            meta.len(),
            record.size
        );
    }

    if depth == Depth::Quick && mtime_of(&meta) == record.mtime {
        return Ok(());
    }
    record.content.verify_file(artifact, "it").with_context(|| {
        // A file the user owns was never "pulled from" anywhere, and telling
        // them their own path is where their own path came from is noise.
        match record.kind.as_str() {
            "local-image" => format!(
                "{} is not the file Asterism recorded when the instance was created",
                artifact.display()
            ),
            _ => format!(
                "{} has changed since it was pulled from {}",
                artifact.display(),
                record.source
            ),
        }
    })
}

/// The usual case: the record sits beside the artifact.
pub fn check(artifact: &Path, depth: Depth) -> Result<()> {
    check_recorded(artifact, artifact, depth)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(path: &Path, bytes: &[u8]) {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).unwrap();
        }
        std::fs::write(path, bytes).unwrap();
    }

    /// The vectors everybody knows, so a refactor of the hashing seam cannot
    /// quietly start producing a different content address.
    #[test]
    fn digests_are_the_ones_everyone_else_computes() {
        assert_eq!(
            Digest::of_bytes(Algo::Sha256, b"abc").to_string(),
            "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            Digest::of_bytes(Algo::Sha512, b"abc").to_string(),
            "sha512:ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
             2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
                .replace(char::is_whitespace, "")
                .as_str()
        );
        assert_eq!(
            Digest::of_bytes(Algo::Blake3, b"abc").to_string(),
            "blake3:6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85"
        );

        // A file hashes to the same thing as its bytes, whatever the size.
        let dir = tempfile::tempdir().unwrap();
        let big = dir.path().join("big");
        let bytes = vec![0x5au8; (1 << 20) + 12345];
        write(&big, &bytes);
        assert_eq!(
            Digest::of_file(Algo::Sha256, &big).unwrap(),
            Digest::of_bytes(Algo::Sha256, &bytes),
            "the streaming path must agree with the one-shot one across a buffer boundary"
        );
    }

    /// A digest we cannot compute is refused when it is read, not when it is
    /// checked: the whole point is that such a source never reaches a write.
    #[test]
    fn unsupported_algorithms_are_refused_up_front() {
        let err = Digest::parse("md5:d41d8cd98f00b204e9800998ecf8427e").unwrap_err().to_string();
        assert!(err.contains("unsupported digest algorithm"), "{err}");
        assert!(err.contains("refuses to adopt"), "{err}");

        assert!(Digest::parse("sha256:not-hex").is_err());
        assert!(Digest::parse("sha256:abc").is_err(), "a short digest is not a digest");
        assert!(Digest::parse("deadbeef").is_err(), "no algorithm at all");
        // Registries write digests lowercase; accept either and normalise.
        assert_eq!(
            Digest::parse(&format!("sha256:{}", "AB".repeat(32))).unwrap().hex(),
            "ab".repeat(32)
        );
    }

    #[test]
    fn adoption_verifies_before_it_renames() {
        let dir = tempfile::tempdir().unwrap();
        let staged = dir.path().join("x.part");
        let dest = dir.path().join("x.raw");
        write(&staged, b"the real bytes");
        let want = Digest::of_bytes(Algo::Sha256, b"the real bytes");

        let record = adopt(&staged, &dest, Some(&want), Source::new("base-image", "https://x"))
            .unwrap();
        assert_eq!(record.content, want);
        assert_eq!(record.size, 14);
        assert!(dest.exists());
        assert!(!staged.exists());
        assert!(provenance_path(&dest).exists());
        check(&dest, Depth::Full).unwrap();
    }

    /// The headline case: bytes that are not what was published never take
    /// the name the boot path looks for, and the staged copy is destroyed so
    /// a retry cannot mistake it for a resumable download.
    #[test]
    fn a_digest_mismatch_adopts_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let staged = dir.path().join("x.part");
        let dest = dir.path().join("x.raw");
        write(&staged, b"substituted bytes");
        let want = Digest::of_bytes(Algo::Sha256, b"the real bytes");

        let err = adopt(&staged, &dest, Some(&want), Source::new("base-image", "https://x"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("does not match its published digest"), "{err}");
        assert!(err.contains("nothing in the store was changed"), "{err}");
        assert!(!dest.exists(), "the poisoned bytes must not have the durable name");
        assert!(!provenance_path(&dest).exists());
        assert!(!staged.exists(), "and must not be left to be resumed");
    }

    /// A truncated download hashes to something else, which is the same
    /// refusal — the interesting half is that the store is untouched.
    #[test]
    fn a_truncated_download_is_a_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let staged = dir.path().join("img.part");
        let dest = dir.path().join("img.raw");
        let whole = vec![9u8; 4096];
        write(&staged, &whole[..3000]);
        let want = Digest::of_bytes(Algo::Sha256, &whole);
        assert!(adopt(&staged, &dest, Some(&want), Source::new("base-image", "u")).is_err());
        assert!(!dest.exists());
    }

    /// An artifact with no record is not bootable, however plausible it
    /// looks. This is what an interrupted adoption leaves behind if the
    /// rename is ever reordered ahead of the record, and what a file dropped
    /// into the store by hand looks like.
    #[test]
    fn an_unaccounted_artifact_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let orphan = dir.path().join("mystery.raw");
        write(&orphan, b"where did you come from");
        let err = check(&orphan, Depth::Quick).unwrap_err().to_string();
        assert!(err.contains("no provenance record"), "{err}");
        assert!(err.contains("ast pull"), "the error has to say what to do: {err}");
    }

    /// A cache somebody wrote into after adoption. Size and mtime both move
    /// when a file is rewritten, so even the quick check catches it.
    #[test]
    fn a_poisoned_cache_is_caught_at_the_boot_gate() {
        let dir = tempfile::tempdir().unwrap();
        let staged = dir.path().join("k.part");
        let dest = dir.path().join("kernel");
        write(&staged, b"a kernel, honestly");
        adopt(&staged, &dest, None, Source::new("kernel", "https://mirror")).unwrap();
        check(&dest, Depth::Quick).unwrap();

        write(&dest, b"not a kernel at all");
        let err = check(&dest, Depth::Quick).unwrap_err().to_string();
        assert!(err.contains("truncated or replaced"), "{err}");
    }

    /// Poisoned to exactly the same length, with the mtime put back: the
    /// quick check is a stat and cannot see it, and the full one can. Both
    /// halves of that are load-bearing, so both are pinned.
    #[test]
    fn a_same_size_rewrite_needs_the_full_check() {
        let dir = tempfile::tempdir().unwrap();
        let staged = dir.path().join("r.part");
        let dest = dir.path().join("r.raw");
        write(&staged, b"aaaaaaaaaaaaaaaa");
        let record = adopt(&staged, &dest, None, Source::new("base-image", "src")).unwrap();

        write(&dest, b"bbbbbbbbbbbbbbbb");
        // Put the mtime back the way an adversary with write access would.
        set_mtime(&dest, record.mtime);
        assert!(check(&dest, Depth::Quick).is_ok(), "a stat cannot see this, by design");
        let err = check(&dest, Depth::Full).unwrap_err().to_string();
        assert!(err.contains("has changed since it was pulled"), "{err}");

        // And the env var is the way to demand the expensive one everywhere.
        assert_eq!(Depth::from_env(), Depth::Quick);
    }

    /// Touching a file is enough to make the quick check re-hash, so an
    /// in-place edit that keeps the size is still caught in the normal case.
    #[test]
    fn a_moved_mtime_forces_a_rehash() {
        let dir = tempfile::tempdir().unwrap();
        let staged = dir.path().join("m.part");
        let dest = dir.path().join("m.raw");
        write(&staged, b"0123456789");
        let record = adopt(&staged, &dest, None, Source::new("base-image", "src")).unwrap();
        write(&dest, b"9876543210");
        set_mtime(&dest, record.mtime + 60);
        let err = check(&dest, Depth::Quick).unwrap_err().to_string();
        assert!(err.contains("has changed since it was pulled"), "{err}");
    }

    /// An adoption interrupted at every point it can be interrupted at, and
    /// what is left behind each time. The invariant the ordering buys is
    /// that no state a crash can produce is one where the artifact has its
    /// durable name and no record — so the boot gate's refusal of an
    /// unaccounted file can never be triggered by a power cut.
    #[test]
    fn no_interruption_leaves_something_bootable_that_should_not_be() {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("img.raw");

        // Interrupted during the download: a `.part` and nothing else.
        let staged = dir.path().join("img.part");
        write(&staged, b"half a download");
        assert!(!dest.exists());
        assert!(check(&dest, Depth::Quick).is_err());

        // Interrupted after the record was written and before the rename.
        // The record is an orphan; the artifact still is not there.
        let orphan = Provenance {
            content: Digest::of_bytes(OWN_ALGO, b"whatever this was going to be"),
            size: 29,
            mtime: 0,
            kind: "base-image".into(),
            source: "https://x".into(),
            derived_from: Vec::new(),
        };
        write_record(&dest, &orphan).unwrap();
        assert!(!dest.exists(), "a record is not an image");
        assert!(check(&dest, Depth::Quick).is_err());

        // And the next attempt overwrites the orphan rather than trusting
        // it: the record that survives is the one describing what is
        // actually there.
        write(&staged, b"the whole download");
        adopt(&staged, &dest, None, Source::new("base-image", "https://x")).unwrap();
        check(&dest, Depth::Full).unwrap();
        assert_eq!(provenance(&dest).unwrap().size, 18);

        // A record's staging file is named off the artifact, so two images
        // sharing a stem do not share one.
        let raw = dir.path().join("deb.raw");
        let qcow = dir.path().join("deb.qcow2");
        write(&raw, b"raw");
        write(&qcow, b"qcow");
        record(&raw, &raw, Source::new("base-image", "a")).unwrap();
        record(&qcow, &qcow, Source::new("download", "b")).unwrap();
        assert_eq!(provenance(&raw).unwrap().source, "a");
        assert_eq!(provenance(&qcow).unwrap().source, "b");
    }

    /// Converted and built images have no upstream digest, so what makes
    /// them accountable is the record of what they came out of.
    #[test]
    fn provenance_survives_a_round_trip_with_its_parents() {
        let dir = tempfile::tempdir().unwrap();
        let staged = dir.path().join("c.part");
        let dest = dir.path().join("c.raw");
        write(&staged, b"converted");
        let parents = vec![
            format!("sha256:{}", "1".repeat(64)),
            format!("sha256:{}", "2".repeat(64)),
        ];
        adopt(
            &staged,
            &dest,
            None,
            Source::new("base-image", "debian:13").derived_from(parents.clone()),
        )
        .unwrap();

        let read = provenance(&dest).unwrap();
        assert_eq!(read.kind, "base-image");
        assert_eq!(read.source, "debian:13");
        assert_eq!(read.derived_from, parents);
        assert_eq!(read.content.algo(), OWN_ALGO, "our own bytes get our own hash");
    }

    /// A local file is the user's and is never rewritten, so its identity is
    /// recorded in the store instead and checked from there.
    #[test]
    fn a_local_file_is_recorded_without_being_touched() {
        let dir = tempfile::tempdir().unwrap();
        let theirs = dir.path().join("mine.qcow2");
        write(&theirs, b"QFI\xfb the user's own image");
        let ours = dir.path().join("store").join("local-mine");

        record(&theirs, &ours, Source::new("local-image", &theirs.display().to_string()))
            .unwrap();
        assert!(theirs.exists(), "their file is left exactly where it was");
        assert!(!provenance_path(&theirs).exists(), "and nothing is written beside it");
        check_recorded(&theirs, &ours, Depth::Full).unwrap();

        // The file changing under us between create and boot is the case
        // this exists for.
        write(&theirs, b"QFI\xfb something else entirely");
        let err = check_recorded(&theirs, &ours, Depth::Quick).unwrap_err().to_string();
        assert!(err.contains("truncated or replaced") || err.contains("has changed"), "{err}");
    }

    /// A record with a newline in the source cannot be allowed to forge a
    /// second field, and one an older version wrote without every field must
    /// still read.
    #[test]
    fn records_are_read_defensively() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("a.raw");
        write(&path, b"x");
        record(
            &path,
            &path,
            Source::new("base-image", "https://x/\nsize 999999\nkind kernel"),
        )
        .unwrap();
        let read = provenance(&path).unwrap();
        assert_eq!(read.size, 1, "an injected size line must not win");
        assert_eq!(read.kind, "base-image");

        // An unknown field is skipped, not fatal.
        std::fs::write(
            provenance_path(&path),
            format!("asterism-provenance 1\ncontent {}\nsize 1\nfuture-field yes\n", read.content),
        )
        .unwrap();
        assert!(provenance(&path).is_some());

        // A record with no digest is no record.
        std::fs::write(provenance_path(&path), "asterism-provenance 1\nsize 1\n").unwrap();
        assert!(provenance(&path).is_none());
        assert!(check(&path, Depth::Quick).is_err());
    }

    fn set_mtime(path: &Path, secs: i64) {
        let times = std::fs::FileTimes::new()
            .set_modified(std::time::UNIX_EPOCH + std::time::Duration::from_secs(secs as u64));
        std::fs::OpenOptions::new()
            .write(true)
            .open(path)
            .unwrap()
            .set_times(times)
            .unwrap();
    }
}
