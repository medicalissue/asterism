//! Copy-on-write file clones, and what a file actually costs.
//!
//! With raw base images (BACKENDS.md §4, phase 1) the copy-on-write that a
//! qcow2 backing file used to provide comes from the filesystem instead: on
//! APFS, `clonefile(2)` makes a second file that shares every block with the
//! first until one of them is written to. That is what an instance's root
//! disk is, and what a snapshot of one is — same mechanism, same cost, no
//! format involved.
//!
//! Not every filesystem will do that, and the two that will do not agree on
//! how to ask, so this module is a seam in the sense `power` and `service`
//! are: one [`imp`] per platform, and no `#[cfg(target_os)]` above it.
//!
//! | OS | share mechanism |
//! |---|---|
//! | macOS | `clonefile(2)` |
//! | Linux | `ioctl(dst, FICLONE, src)` — btrfs and XFS with `reflink=1` |
//! | other | none; the sparse copy below is the whole story |
//!
//! Three things follow, and all three are visible in the API:
//!
//! * A share can be refused — the two files may sit on different volumes, or
//!   on a filesystem with no such call at all (ext4 has none). Refusal is not
//!   an error: copying is correct, merely expensive.
//! * A refused share must still not fill in the holes. A disk image is mostly
//!   hole, and `std::fs::copy` writes the zeroes out on Linux, where
//!   `copy_file_range` has no ext4 implementation and the kernel falls back to
//!   splicing. A 10 GiB disk that held 3 GiB came out costing 10. So the
//!   fallback walks the source's extents ([`extents`]) and writes only those,
//!   which is what the far side of a move has always done.
//! * Sizes stop meaning one thing. A 10 GiB sparse disk cloned off a 1 GiB
//!   base occupies almost nothing, so [`usage`] reports allocated blocks
//!   rather than the length of the file.
//!
//! [`Cloned`] says which of the three happened, and it does not flatter: a
//! filesystem that cannot report holes gets a copy that cost the file's whole
//! length, and is told so rather than being called sparse.

use std::fs::File;
use std::path::Path;

use anyhow::{bail, Context, Result};

/// How [`clone_file`] managed to produce the copy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Cloned {
    /// `clonefile(2)` or `FICLONE`: the two files share blocks until one of
    /// them is written to.
    Shared,
    /// Bytes were copied, and the source's holes are holes in the copy too:
    /// the destination costs what the source *held*, not what it claimed.
    ///
    /// `hint` is `Some` only when something about this machine could be
    /// changed to get a share instead. On a filesystem that simply has no
    /// reflink there is nothing to say, and saying it on every `create`
    /// would be noise.
    Sparse { hint: Option<String> },
    /// A dense byte-for-byte copy, and why: either the source had no holes
    /// to skip, or this filesystem would not say where they were. Either
    /// way the destination costs its full length.
    Copied(String),
}

impl Cloned {
    /// `None` when nothing surprising happened, or the sentence worth
    /// logging when this device could not share the blocks.
    pub fn warning(&self, src: &Path, dst: &Path) -> Option<String> {
        match self {
            Cloned::Shared => None,
            Cloned::Sparse { hint } => hint.as_ref().map(|hint| {
                format!(
                    "copied {} to {} rather than sharing its blocks: {hint}",
                    src.display(),
                    dst.display(),
                )
            }),
            Cloned::Copied(why) => Some(format!(
                "copied {} to {} in full ({} bytes), and it will cost that \
                 much until something writes to it: {why}",
                src.display(),
                dst.display(),
                usage(dst).unwrap_or(0),
            )),
        }
    }
}

/// Why a share was refused — or why nothing should be attempted at all.
///
/// The classification is per-platform, because errno numbers are: the same
/// "this filesystem does not do that" is `EOPNOTSUPP` 95 on Linux and 102 on
/// macOS. [`imp`] maps its own; everything above here reads the verdict.
#[derive(Debug)]
enum Refusal {
    /// No such call on this platform, or this filesystem does not implement
    /// it. Copying is the right answer and there is nothing to tell anyone.
    Unsupported(String),
    /// The two paths are on different filesystems. Copying is the right
    /// answer, and a human could change this.
    CrossDevice(String),
    /// Not a refusal at all: a full disk, a permission problem, an I/O
    /// error. Falling back to a copy would fail the same way, only slower
    /// and after writing gigabytes, so this stops here.
    Fatal(String),
}

impl Refusal {
    /// The part of a refusal worth putting in front of a person.
    fn hint(&self) -> Option<String> {
        match self {
            Refusal::CrossDevice(why) => Some(why.clone()),
            _ => None,
        }
    }

    fn why(&self) -> &str {
        match self {
            Refusal::Unsupported(why) | Refusal::CrossDevice(why) | Refusal::Fatal(why) => why,
        }
    }
}

/// Clone `src` to `dst`, sharing blocks if the filesystem can and preserving
/// its holes if it cannot.
///
/// Refuses to overwrite: `clonefile(2)` fails on an existing destination, and
/// neither fallback may quietly behave differently — the destination is
/// opened `create_new`, so the guarantee is the kernel's rather than a check
/// that raced. Callers that mean to replace a file clone next to it and
/// rename over the top, which is also the only way a failed restore leaves
/// the original intact.
///
/// Nothing is left behind on failure. A half-written destination is worse
/// than none: `snapshot::list` would show it as a snapshot.
pub fn clone_file(src: &Path, dst: &Path) -> Result<Cloned> {
    if !src.exists() {
        bail!("nothing to clone at {}", src.display());
    }
    if dst.exists() {
        bail!("{} already exists", dst.display());
    }
    if let Some(parent) = dst.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let refusal = match imp::clone(src, dst) {
        Ok(()) => return Ok(Cloned::Shared),
        // A full disk or an unreadable source is not a refusal, and writing
        // a gigabyte to find that out again helps nobody.
        Err(fatal @ Refusal::Fatal(_)) => {
            bail!(
                "cloning {} to {}: {}",
                src.display(),
                dst.display(),
                fatal.why()
            );
        }
        Err(refusal) => refusal,
    };
    // A refused share may still have left something behind.
    let _ = std::fs::remove_file(dst);
    match copy_preserving_holes(src, dst)? {
        Density::Sparse => Ok(Cloned::Sparse {
            hint: refusal.hint(),
        }),
        Density::Dense => Ok(Cloned::Copied(refusal.why().to_owned())),
    }
}

/// Blocks actually allocated to a file, in bytes.
///
/// `st_blocks`, not `st_size`: a sparse 10 GiB disk that has been written to
/// once costs kilobytes, and a fresh clone costs nothing at all. This is the
/// number a user wants when they ask what a snapshot cost them.
pub fn usage(path: &Path) -> Result<u64> {
    use std::os::unix::fs::MetadataExt;
    Ok(std::fs::metadata(path)?.blocks() * 512)
}

// ---- the sparse copy -------------------------------------------------------

/// How much of the file the copy actually had to write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Density {
    /// Holes were found and skipped: the destination costs less than its
    /// length.
    Sparse,
    /// Every byte was written — either the source had no holes, or this
    /// filesystem would not say where they were.
    Dense,
}

/// What a copy of this file will cost, decided by the walk rather than by
/// hope.
///
/// Pure, and separate from the copy, because it is the one place a sparse
/// claim could become a lie: a walk that was *assumed* rather than reported
/// (a filesystem with no `SEEK_HOLE`) produces one extent covering
/// everything, which is indistinguishable from a solid file unless the
/// support is carried alongside it.
fn density(support: Support, extents: &[Extent], len: u64) -> Density {
    match support {
        Support::Assumed => Density::Dense,
        Support::Reported if allocated(extents) >= len => Density::Dense,
        Support::Reported => Density::Sparse,
    }
}

/// One megabyte, the same unit the mesh moves a disk in.
const COPY_CHUNK: usize = 1 << 20;

/// Copy `src` to `dst` writing only the ranges that hold data.
///
/// The length is set first and the data second, so everything between two
/// extents — and everything after the last one — stays a hole on this side
/// too. That trailing hole is not a detail: every instance disk is a base
/// image truncated up to the shape, so its last byte is always a hole, and a
/// copy that wrote only the extents would come out short.
fn copy_preserving_holes(src: &Path, dst: &Path) -> Result<Density> {
    let meta = std::fs::metadata(src).with_context(|| format!("reading {}", src.display()))?;
    let source = File::open(src).with_context(|| format!("reading {}", src.display()))?;
    let (extents, support) = walk(&source, meta.len());

    into_new_file(dst, |target| {
        target.set_len(meta.len())?;
        for extent in &extents {
            copy_range(&source, target, extent)?;
        }
        // Parity with `std::fs::copy`, which is what this replaced: the
        // destination wears the source's mode. Deliberately not its
        // timestamps — a snapshot's mtime is when it was taken.
        target.set_permissions(meta.permissions())?;
        Ok(())
    })
    .with_context(|| format!("copying {} to {}", src.display(), dst.display()))?;

    Ok(density(support, &extents, meta.len()))
}

/// Create `dst`, hand it to `f`, and leave nothing behind if `f` fails.
///
/// `create_new` is what makes "never overwrite" a fact about the open rather
/// than about the `exists()` check above it. The cleanup is the other half:
/// a destination that exists is taken by every caller to mean a disk, so a
/// copy that died halfway must not leave one.
fn into_new_file<T>(dst: &Path, f: impl FnOnce(&File) -> Result<T>) -> Result<T> {
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(dst)
        .with_context(|| format!("creating {}", dst.display()))?;
    match f(&file) {
        Ok(value) => Ok(value),
        Err(e) => {
            drop(file);
            let _ = std::fs::remove_file(dst);
            Err(e)
        }
    }
}

/// One extent, from wherever it is in the source to the same place in the
/// destination.
fn copy_range(source: &File, target: &File, extent: &Extent) -> Result<()> {
    use std::io::{Read, Seek, SeekFrom, Write};

    let (mut reader, mut writer) = (source, target);
    let mut buf = vec![0u8; COPY_CHUNK];
    let mut offset = extent.offset;
    reader.seek(SeekFrom::Start(offset))?;
    writer.seek(SeekFrom::Start(offset))?;
    while offset < extent.end() {
        let n = ((extent.end() - offset) as usize).min(COPY_CHUNK);
        reader.read_exact(&mut buf[..n])?;
        writer.write_all(&buf[..n])?;
        offset += n as u64;
    }
    Ok(())
}

// ---- extents ---------------------------------------------------------------

/// One allocated range of a sparse file: an offset and a length.
///
/// A disk image is mostly hole. `(offset, len)` pairs are what a transfer
/// has to carry, and the sum of their lengths is what it will really cost —
/// which is a very different number from the file's length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Extent {
    pub offset: u64,
    pub len: u64,
}

impl Extent {
    pub fn end(&self) -> u64 {
        self.offset + self.len
    }
}

/// Whether the walk below was believed or invented.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Support {
    /// The filesystem answered `SEEK_DATA`/`SEEK_HOLE`, so these extents are
    /// where the data is.
    Reported,
    /// It did not, so the whole file is assumed to be data. Correct, and
    /// exactly as expensive as a plain copy — and, crucially, not sparse.
    Assumed,
}

/// Walk a file's allocated ranges with `SEEK_DATA`/`SEEK_HOLE`.
///
/// This is what makes moving an instance affordable. An instance's root
/// disk is a clone of a base image, truncated up to the shape's size; the
/// guest then writes into it. The file *claims* 20 GiB and holds perhaps a
/// tenth of that, and the tenth is the only part a copy — or a transfer —
/// has any reason to touch. Everything between two extents is a hole, and a
/// hole reconstructs itself on the far end: a file created, truncated to the
/// same length and written only at these offsets is byte-for-byte the
/// original, and just as sparse.
///
/// A filesystem that does not implement the two `whence` values answers
/// with something other than `ENXIO`, and the honest fallback is one extent
/// covering the whole file: nothing is lost, it merely costs what a plain
/// copy costs. `ENXIO` is not that case — it is the documented "no more
/// data at or beyond this offset", which is how the walk normally ends and
/// how a file that is *entirely* hole reports itself.
pub fn extents(path: &Path) -> Result<Vec<Extent>> {
    let file = File::open(path).with_context(|| format!("reading {}", path.display()))?;
    let len = file.metadata()?.len();
    Ok(walk(&file, len).0)
}

/// The walk, and whether to believe it. [`extents`] throws the second half
/// away; the copy cannot afford to, or it would call a blind copy sparse.
fn walk(file: &File, len: u64) -> (Vec<Extent>, Support) {
    use std::os::unix::io::AsRawFd;

    let whole = || (vec![Extent { offset: 0, len }], Support::Assumed);
    if len == 0 {
        return (Vec::new(), Support::Reported);
    }

    let fd = file.as_raw_fd();
    let mut out = Vec::new();
    let mut pos = 0u64;
    while pos < len {
        // SAFETY: `fd` is owned by `file`, which outlives the call, and the
        // offsets are in range for a file of this length.
        let data = unsafe { libc::lseek(fd, pos as libc::off_t, imp::SEEK_DATA) };
        if data < 0 {
            return match std::io::Error::last_os_error().raw_os_error() {
                Some(libc::ENXIO) => (out, Support::Reported),
                _ => whole(),
            };
        }
        let hole = unsafe { libc::lseek(fd, data, imp::SEEK_HOLE) };
        if hole < 0 {
            return match std::io::Error::last_os_error().raw_os_error() {
                Some(libc::ENXIO) => (out, Support::Reported),
                _ => whole(),
            };
        }
        // SEEK_HOLE answers with the file's length at the last extent, and
        // a file can grow between the metadata read and here.
        let (start, end) = (data as u64, (hole as u64).min(len));
        if end <= start {
            break;
        }
        out.push(Extent {
            offset: start,
            len: end - start,
        });
        pos = end;
    }
    (out, Support::Reported)
}

/// What a set of extents costs to carry.
pub fn allocated(extents: &[Extent]) -> u64 {
    extents.iter().map(|e| e.len).sum()
}

/// Bytes as `qemu-img` would have written them, so a table of snapshots
/// reads the same whether the rows came from a directory or from qcow2.
pub fn human(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit + 1 < UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.2} {}", UNITS[unit])
    }
}

// ---- macOS: clonefile(2) ---------------------------------------------------

#[cfg(target_os = "macos")]
mod imp {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    use std::path::Path;

    use super::Refusal;

    pub const SEEK_DATA: i32 = libc::SEEK_DATA;
    pub const SEEK_HOLE: i32 = libc::SEEK_HOLE;

    /// `clonefile(2)` creates the destination itself and fails if it is
    /// already there, which is where this module's no-overwrite guarantee
    /// comes from on this platform.
    pub fn clone(src: &Path, dst: &Path) -> Result<(), Refusal> {
        let (Ok(s), Ok(d)) = (
            CString::new(src.as_os_str().as_bytes()),
            CString::new(dst.as_os_str().as_bytes()),
        ) else {
            return Err(Refusal::Fatal("a path with a NUL byte in it".to_owned()));
        };
        // SAFETY: both arguments are NUL-terminated C strings that live until
        // the call returns, and flags=0 asks for the default behaviour.
        let rc = unsafe { libc::clonefile(s.as_ptr(), d.as_ptr(), 0) };
        if rc != 0 {
            return Err(classify(&std::io::Error::last_os_error()));
        }
        Ok(())
    }

    /// Darwin's errno numbers, read as one of three verdicts.
    fn classify(e: &std::io::Error) -> Refusal {
        let why = format!("clonefile: {e}");
        match e.raw_os_error() {
            Some(libc::EXDEV) => Refusal::CrossDevice(
                "these two paths are on different volumes — keeping the image \
                 store and the instance directory on one APFS volume lets the \
                 filesystem share the blocks instead"
                    .to_owned(),
            ),
            Some(libc::ENOTSUP | libc::EOPNOTSUPP | libc::ENOTTY | libc::EINVAL | libc::ENOSYS) => {
                Refusal::Unsupported(why)
            }
            // A full disk, a read-only volume, a permission problem, a bad
            // sector: copying would meet the same wall after writing a
            // gigabyte to get there.
            Some(
                libc::ENOSPC
                | libc::EDQUOT
                | libc::EROFS
                | libc::EPERM
                | libc::EACCES
                | libc::EIO
                | libc::EEXIST
                | libc::ENOENT,
            ) => Refusal::Fatal(why),
            _ => Refusal::Unsupported(why),
        }
    }
}

// ---- Linux: ioctl(FICLONE) -------------------------------------------------

#[cfg(target_os = "linux")]
mod imp {
    use std::fs::{File, OpenOptions};
    use std::os::unix::io::AsRawFd;
    use std::path::Path;

    use super::Refusal;

    pub const SEEK_DATA: i32 = libc::SEEK_DATA;
    pub const SEEK_HOLE: i32 = libc::SEEK_HOLE;

    /// A reflink, on the filesystems that have one: btrfs, and XFS made with
    /// `reflink=1`. ext4 has none and says so, which is a refusal and not a
    /// failure.
    ///
    /// `FICLONE` needs an open, writable destination, so unlike
    /// `clonefile(2)` it has to create the file before it can ask. Same
    /// guarantee, differently obtained: `create_new` refuses an existing
    /// destination, and an ioctl that is refused takes the empty file away
    /// again rather than leaving a zero-length disk behind.
    pub fn clone(src: &Path, dst: &Path) -> Result<(), Refusal> {
        let source = File::open(src).map_err(|e| classify(&e))?;
        let target = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(dst)
            .map_err(|e| classify(&e))?;
        // SAFETY: both descriptors are owned by files that outlive the call.
        // FICLONE's argument is the source descriptor, passed by value, and
        // `libc::FICLONE` is computed for this architecture rather than
        // written down as a number that is only right on some of them.
        let rc = unsafe { libc::ioctl(target.as_raw_fd(), libc::FICLONE, source.as_raw_fd()) };
        if rc != 0 {
            let failed = std::io::Error::last_os_error();
            drop(target);
            let _ = std::fs::remove_file(dst);
            return Err(classify(&failed));
        }
        Ok(())
    }

    /// Linux's errno numbers, read as one of three verdicts. `EOPNOTSUPP` is
    /// what ext4 answers, and it is the common case on this platform rather
    /// than an exception.
    fn classify(e: &std::io::Error) -> Refusal {
        let why = format!("FICLONE: {e}");
        match e.raw_os_error() {
            Some(libc::EXDEV) => Refusal::CrossDevice(
                "these two paths are on different filesystems — keeping the \
                 image store and the instance directory on one filesystem that \
                 can reflink (btrfs, or XFS made with reflink=1) lets it share \
                 the blocks instead"
                    .to_owned(),
            ),
            Some(libc::EOPNOTSUPP | libc::ENOTTY | libc::EINVAL | libc::ENOSYS | libc::EISDIR) => {
                Refusal::Unsupported(why)
            }
            // A full disk, a read-only mount, a permission problem, a bad
            // sector: copying would meet the same wall after writing a
            // gigabyte to get there.
            Some(
                libc::ENOSPC
                | libc::EDQUOT
                | libc::EROFS
                | libc::EPERM
                | libc::EACCES
                | libc::EIO
                | libc::EEXIST
                | libc::ENOENT,
            ) => Refusal::Fatal(why),
            _ => Refusal::Unsupported(why),
        }
    }
}

// ---- everywhere else -------------------------------------------------------

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
mod imp {
    use std::path::Path;

    use super::Refusal;

    // The POSIX-common values; the sparse walk still works wherever the
    // filesystem answers, and falls back to a dense copy where it does not.
    pub const SEEK_DATA: i32 = 3;
    pub const SEEK_HOLE: i32 = 4;

    pub fn clone(_src: &Path, _dst: &Path) -> Result<(), Refusal> {
        Err(Refusal::Unsupported(
            "this platform has no block-sharing clone".to_owned(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::io::{Seek, SeekFrom, Write};
    use std::os::unix::fs::PermissionsExt;

    /// A sparse source: `len` long, holding `writes.len()` small runs and
    /// nothing else. Whether the filesystem *honours* the holes is its
    /// business, and every assertion below that depends on it says so.
    fn sparse_source(path: &Path, len: u64, writes: &[u64]) {
        let mut file = File::create(path).unwrap();
        file.set_len(len).unwrap();
        for offset in writes {
            file.seek(SeekFrom::Start(*offset)).unwrap();
            file.write_all(b"asterism").unwrap();
        }
        file.sync_all().unwrap();
    }

    /// Does this filesystem actually make holes? Every sparseness assertion
    /// is conditioned on the answer, which is what lets one test tell the
    /// truth on APFS, ext4 and tmpfs alike.
    fn keeps_holes(path: &Path, len: u64) -> bool {
        usage(path).unwrap() * 2 < len
    }

    #[test]
    fn a_clone_has_the_same_bytes_however_it_was_made() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("base.raw");
        std::fs::write(&src, b"asterism").unwrap();
        let dst = dir.path().join("sub/disk.raw");

        let how = clone_file(&src, &dst).unwrap();
        assert_eq!(std::fs::read(&dst).unwrap(), b"asterism");
        // The parent directory is created on the way.
        assert!(dst.parent().unwrap().is_dir());
        if cfg!(target_os = "macos") {
            assert_eq!(how, Cloned::Shared, "APFS should clone, not copy");
            assert!(how.warning(&src, &dst).is_none());
        }

        // Divergence is per-file: writing to the clone leaves the base alone.
        std::fs::write(&dst, b"changed").unwrap();
        assert_eq!(std::fs::read(&src).unwrap(), b"asterism");
    }

    #[test]
    fn cloning_never_overwrites() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("base.raw");
        let dst = dir.path().join("disk.raw");
        std::fs::write(&src, b"base").unwrap();
        std::fs::write(&dst, b"precious").unwrap();
        assert!(clone_file(&src, &dst).is_err());
        assert_eq!(std::fs::read(&dst).unwrap(), b"precious");
        assert!(clone_file(&dir.path().join("absent"), &dir.path().join("new")).is_err());
    }

    /// The regression this module was rewritten for. `std::fs::copy` filled
    /// a 10 GiB disk's holes in on ext4 — `copy_file_range` has no
    /// implementation there, so the kernel spliced the zeroes out — and a
    /// move then carried 13 GiB of a 20 GiB claim. Called directly rather
    /// than through `clone_file`, so the path Linux takes is exercised on a
    /// Mac too.
    #[test]
    fn a_hole_survives_a_copy_that_is_not_a_clone() {
        const LEN: u64 = 256 << 20;
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("disk.raw");
        let dst = dir.path().join("copy.raw");
        sparse_source(&src, LEN, &[0, 128 << 20]);

        let density = copy_preserving_holes(&src, &dst).unwrap();

        // True on every filesystem: same length, same bytes where there are
        // bytes, and hole where there was hole.
        assert_eq!(std::fs::metadata(&dst).unwrap().len(), LEN);
        let mut copy = File::open(&dst).unwrap();
        let mut buf = [0u8; 8];
        for offset in [0u64, 128 << 20] {
            copy.seek(SeekFrom::Start(offset)).unwrap();
            std::io::Read::read_exact(&mut copy, &mut buf).unwrap();
            assert_eq!(&buf, b"asterism", "the data moved at {offset}");
        }
        copy.seek(SeekFrom::Start(64 << 20)).unwrap();
        std::io::Read::read_exact(&mut copy, &mut buf).unwrap();
        assert_eq!(buf, [0u8; 8], "a hole reads as zeroes");

        // And where the filesystem does holes at all, the copy must not have
        // filled them in — which is the whole bug.
        if keeps_holes(&src, LEN) {
            assert!(
                keeps_holes(&dst, LEN),
                "a {LEN}-byte sparse source copied to {} allocated bytes",
                usage(&dst).unwrap()
            );
            assert_eq!(density, Density::Sparse, "and it must not be shy about it");
        }
    }

    /// Every instance disk is a base image truncated up to the shape, so its
    /// last byte is always hole. A copy that wrote only the extents would
    /// come out short, and the guest would find a disk that had shrunk.
    #[test]
    fn the_length_survives_a_trailing_hole() {
        const LEN: u64 = 64 << 20;
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("grown.raw");
        let dst = dir.path().join("copy.raw");
        sparse_source(&src, LEN, &[0]);

        copy_preserving_holes(&src, &dst).unwrap();
        assert_eq!(
            std::fs::metadata(&dst).unwrap().len(),
            LEN,
            "the tail is part of the file"
        );
    }

    /// Sparseness is a claim about the *walk*, not about the file, and a
    /// filesystem with no `SEEK_HOLE` produces a walk that looks exactly
    /// like a solid file. Pure, so the honest answer is pinned without
    /// needing such a filesystem to hand.
    #[test]
    fn density_is_decided_by_the_walk_not_by_the_filesystem() {
        const LEN: u64 = 1 << 30;
        let whole = [Extent {
            offset: 0,
            len: LEN,
        }];
        let holed = [
            Extent {
                offset: 0,
                len: 4096,
            },
            Extent {
                offset: 512 << 20,
                len: 4096,
            },
        ];

        // A walk that never happened is a dense copy, whatever it looks like.
        assert_eq!(density(Support::Assumed, &whole, LEN), Density::Dense);
        assert_eq!(density(Support::Assumed, &holed, LEN), Density::Dense);
        // A believed walk that found no hole is also a dense copy: every
        // byte really was written.
        assert_eq!(density(Support::Reported, &whole, LEN), Density::Dense);
        // A believed walk that found holes skipped them.
        assert_eq!(density(Support::Reported, &holed, LEN), Density::Sparse);
        // A file that is entirely hole is the cheapest of all.
        assert_eq!(density(Support::Reported, &[], LEN), Density::Sparse);
        // An empty file has nothing to be sparse about.
        assert_eq!(density(Support::Reported, &[], 0), Density::Dense);
    }

    /// A destination that exists is taken by every caller to mean a disk, so
    /// a copy that died halfway must not leave one behind — `snapshot::list`
    /// would show the stump as a snapshot.
    #[test]
    fn a_failed_write_leaves_no_destination_behind() {
        let dir = tempfile::tempdir().unwrap();
        let dst = dir.path().join("disk.raw");

        let failed: Result<()> = into_new_file(&dst, |_| bail!("boom"));
        assert!(failed.is_err());
        assert!(!dst.exists(), "a failed copy left {} behind", dst.display());

        // The success path does create it...
        into_new_file(&dst, |file| Ok(file.set_len(8)?)).unwrap();
        assert_eq!(std::fs::metadata(&dst).unwrap().len(), 8);
        // ...and the second attempt is refused by the kernel, not by a check.
        assert!(into_new_file(&dst, |_| Ok(())).is_err());
    }

    /// Parity with the `std::fs::copy` this replaced: a base image that is
    /// readable only by its owner does not become a world-readable disk.
    #[test]
    fn permissions_follow_the_source() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("base.raw");
        let dst = dir.path().join("disk.raw");
        std::fs::write(&src, b"asterism").unwrap();
        std::fs::set_permissions(&src, std::fs::Permissions::from_mode(0o600)).unwrap();

        copy_preserving_holes(&src, &dst).unwrap();
        let mode = std::fs::metadata(&dst).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "{mode:o}");
    }

    /// APFS, ext4, tmpfs and btrfs all report their holes, so on any machine
    /// this project runs on a sparse disk must come out either shared or
    /// sparse — never filled in. A `Copied` here means the walk broke.
    #[test]
    fn no_filesystem_this_project_runs_on_needs_a_dense_copy() {
        const LEN: u64 = 64 << 20;
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("base.raw");
        let dst = dir.path().join("disk.raw");
        sparse_source(&src, LEN, &[0]);
        if !keeps_holes(&src, LEN) {
            return; // a filesystem with no holes to preserve; nothing to prove
        }

        let how = clone_file(&src, &dst).unwrap();
        assert!(
            matches!(how, Cloned::Shared | Cloned::Sparse { .. }),
            "a sparse source came back as {how:?}"
        );
        assert_eq!(std::fs::metadata(&dst).unwrap().len(), LEN);
        assert!(keeps_holes(&dst, LEN), "the holes did not survive");
    }

    /// The dense copy is the one outcome that costs the file's whole length,
    /// so it is the one worth a sentence — and that sentence must not tell
    /// somebody on ext4 to go and buy APFS.
    #[test]
    fn a_copy_says_why_it_was_a_copy() {
        let how = Cloned::Copied("FICLONE: Operation not supported (os error 95)".into());
        let warning = how
            .warning(Path::new("/images/x.raw"), Path::new("/i/disk.raw"))
            .unwrap();
        assert!(warning.contains("Operation not supported"), "{warning}");
        assert!(warning.contains("in full"), "{warning}");
        assert!(
            !warning.contains("APFS"),
            "not on this filesystem: {warning}"
        );
    }

    /// Warn about what a person could change, and stay quiet about what they
    /// could not. ext4 has no reflink and never will; saying so on every
    /// `ast create` would be noise, and the disk is sparse either way.
    #[test]
    fn a_cross_device_refusal_is_the_only_one_worth_telling_a_human() {
        let (src, dst) = (Path::new("/images/x.raw"), Path::new("/i/disk.raw"));
        assert!(Cloned::Shared.warning(src, dst).is_none());
        assert!(
            Cloned::Sparse { hint: None }.warning(src, dst).is_none(),
            "a filesystem without reflink is not news"
        );

        let hinted = Cloned::Sparse {
            hint: Some("on different filesystems".into()),
        };
        let warning = hinted.warning(src, dst).unwrap();
        assert!(warning.contains("different filesystems"), "{warning}");
        assert!(warning.contains("/i/disk.raw"), "{warning}");
    }

    /// Each errno is one of three verdicts, and the third one is not a
    /// refusal: a full disk answers a copy exactly as it answered the clone,
    /// only after writing a gigabyte to find out.
    #[test]
    fn a_full_disk_is_not_a_reason_to_try_again_more_slowly() {
        assert!(Refusal::Unsupported("x".into()).hint().is_none());
        assert_eq!(
            Refusal::CrossDevice("move them together".into())
                .hint()
                .as_deref(),
            Some("move them together")
        );
        assert!(Refusal::Fatal("no space left on device".into())
            .hint()
            .is_none());
        assert_eq!(
            Refusal::Fatal("no space left on device".into()).why(),
            "no space left on device"
        );
    }

    /// The whole point of the third verdict: a destination that cannot be
    /// written stops here. Falling back would write a gigabyte to discover
    /// the same permission error, and leave the caller waiting for it.
    #[test]
    fn a_destination_that_cannot_be_written_fails_instead_of_being_copied() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("base.raw");
        std::fs::write(&src, vec![0xab; 64 * 1024]).unwrap();
        let closed = dir.path().join("closed");
        std::fs::create_dir(&closed).unwrap();
        std::fs::set_permissions(&closed, std::fs::Permissions::from_mode(0o500)).unwrap();

        let dst = closed.join("disk.raw");
        let refused = clone_file(&src, &dst);
        // Root can write anywhere, and then there is nothing to assert.
        if refused.is_ok() {
            std::fs::set_permissions(&closed, std::fs::Permissions::from_mode(0o700)).unwrap();
            return;
        }
        let e = format!("{:#}", refused.unwrap_err());
        assert!(e.contains("disk.raw"), "{e}");
        // "cloning", not "copying": the fallback was never entered.
        assert!(
            e.starts_with("cloning "),
            "the copy was attempted anyway: {e}"
        );
        assert!(!dst.exists(), "a refused clone left something behind");
        std::fs::set_permissions(&closed, std::fs::Permissions::from_mode(0o700)).unwrap();
    }

    #[test]
    fn sparse_files_cost_what_they_use_not_what_they_claim() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sparse.raw");
        let file = File::create(&path).unwrap();
        file.set_len(4 * 1024 * 1024 * 1024).unwrap();
        drop(file);
        assert_eq!(std::fs::metadata(&path).unwrap().len(), 4 << 30);
        assert!(usage(&path).unwrap() < 1 << 20, "a hole is not storage");
    }

    /// The number a transfer is priced on. A file that claims a gigabyte
    /// and holds one write costs the one write, and the extent that carries
    /// it lands where the bytes actually are.
    #[test]
    fn a_sparse_file_reports_only_the_ranges_it_really_holds() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("disk.raw");
        sparse_source(&path, 1 << 30, &[512 << 20]);

        let found = extents(&path).unwrap();
        assert!(!found.is_empty(), "the written range has to show up");
        let carried = allocated(&found);
        assert!(
            carried < 4 << 20,
            "a gigabyte of hole and one write must not cost {carried} bytes"
        );
        // Every extent lies inside the file, and they do not overlap.
        let mut last_end = 0;
        for e in &found {
            assert!(e.offset >= last_end, "extents come in order: {found:?}");
            assert!(e.end() <= 1 << 30, "an extent past the end: {found:?}");
            last_end = e.end();
        }
        // The write is inside one of them.
        assert!(
            found
                .iter()
                .any(|e| e.offset <= 512 << 20 && (512 << 20) < e.end()),
            "the written offset is in no extent: {found:?}"
        );
    }

    /// A file with no holes reports itself as one run, and an empty file as
    /// nothing at all — the two ends of the walk.
    #[test]
    fn a_solid_file_is_one_extent_and_an_empty_one_is_none() {
        let dir = tempfile::tempdir().unwrap();
        let solid = dir.path().join("solid.bin");
        std::fs::write(&solid, vec![7u8; 128 * 1024]).unwrap();
        let found = extents(&solid).unwrap();
        assert_eq!(allocated(&found), 128 * 1024, "{found:?}");
        assert_eq!(found[0].offset, 0);

        let empty = dir.path().join("empty.bin");
        std::fs::write(&empty, b"").unwrap();
        assert!(extents(&empty).unwrap().is_empty());

        // A file that is entirely hole is the ENXIO case, and it is not an
        // error: there is simply nothing to carry.
        let hollow = dir.path().join("hollow.raw");
        File::create(&hollow).unwrap().set_len(64 << 20).unwrap();
        let found = extents(&hollow).unwrap();
        assert_eq!(allocated(&found), 0, "a hole is not storage: {found:?}");
    }

    #[test]
    fn sizes_read_like_qemu_imgs() {
        assert_eq!(human(0), "0 B");
        assert_eq!(human(512), "512 B");
        assert_eq!(human(1024), "1.00 KiB");
        assert_eq!(human(1_127_428_915), "1.05 GiB");
    }
}
