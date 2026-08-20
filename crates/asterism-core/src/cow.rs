//! Copy-on-write file clones, and what a file actually costs.
//!
//! With raw base images (BACKENDS.md §4, phase 1) the copy-on-write that a
//! qcow2 backing file used to provide comes from the filesystem instead: on
//! APFS, `clonefile(2)` makes a second file that shares every block with the
//! first until one of them is written to. That is what an instance's root
//! disk is, and what a snapshot of one is — same mechanism, same cost, no
//! format involved.
//!
//! Two things follow, and both are visible in the API:
//!
//! * A clone can be refused — the two files may sit on different volumes, or
//!   on a filesystem with no such call at all. Refusal is not an error: a
//!   full copy is correct, just expensive, so [`clone_file`] falls back and
//!   *says* that it did, leaving the caller to decide whether a human should
//!   hear about it.
//! * Sizes stop meaning one thing. A 10 GiB sparse disk cloned off a 1 GiB
//!   base occupies almost nothing, so [`usage`] reports allocated blocks
//!   rather than the length of the file.

use std::path::Path;

use anyhow::{bail, Context, Result};

/// How [`clone_file`] managed to produce the copy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Cloned {
    /// `clonefile(2)`: the two files share blocks until one is written to.
    Shared,
    /// A full byte-for-byte copy, and why the clone was refused.
    Copied(String),
}

impl Cloned {
    /// `None` when nothing surprising happened, or the sentence worth
    /// logging when the filesystem could not clone.
    pub fn warning(&self, src: &Path, dst: &Path) -> Option<String> {
        match self {
            Cloned::Shared => None,
            Cloned::Copied(why) => Some(format!(
                "copied {} to {} in full ({} bytes) because the filesystem \
                 would not clone it: {why} — keep the image store and the \
                 instance directory on the same APFS volume for copy-on-write",
                src.display(),
                dst.display(),
                usage(dst).unwrap_or(0),
            )),
        }
    }
}

/// Clone `src` to `dst`, sharing blocks if the filesystem can.
///
/// Refuses to overwrite: `clonefile(2)` fails on an existing destination and
/// the fallback must not quietly behave differently. Callers that mean to
/// replace a file clone next to it and rename over the top, which is also
/// the only way a failed restore leaves the original intact.
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
    match clone_native(src, dst) {
        Ok(()) => Ok(Cloned::Shared),
        Err(why) => {
            // The clone may have left a partial destination behind.
            let _ = std::fs::remove_file(dst);
            std::fs::copy(src, dst).with_context(|| {
                format!("copying {} to {}", src.display(), dst.display())
            })?;
            Ok(Cloned::Copied(format!("{why:#}")))
        }
    }
}

/// `clonefile(2)`, straight out of libSystem.
///
/// Declared here rather than taking on the `libc` crate for one symbol: it
/// is a documented, stable syscall wrapper, and this is the only place in
/// Asterism that leaves Rust.
#[cfg(target_os = "macos")]
fn clone_native(src: &Path, dst: &Path) -> Result<()> {
    use std::ffi::{c_char, c_int, CString};
    use std::os::unix::ffi::OsStrExt;

    extern "C" {
        fn clonefile(src: *const c_char, dst: *const c_char, flags: c_int) -> c_int;
    }

    let (s, d) = (
        CString::new(src.as_os_str().as_bytes())?,
        CString::new(dst.as_os_str().as_bytes())?,
    );
    // SAFETY: both arguments are NUL-terminated C strings that live until
    // the call returns, and flags=0 asks for the default behaviour.
    let rc = unsafe { clonefile(s.as_ptr(), d.as_ptr(), 0) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error()).context("clonefile");
    }
    Ok(())
}

/// Everywhere else: Linux reflinks (`FICLONE`) are a btrfs/XFS ioctl and
/// Windows has its own story. Neither is needed while APFS is the reason
/// this exists, so the honest answer is "not here" and a full copy.
#[cfg(not(target_os = "macos"))]
fn clone_native(_src: &Path, _dst: &Path) -> Result<()> {
    bail!("this platform has no clonefile(2)")
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

/// Walk a file's allocated ranges with `SEEK_DATA`/`SEEK_HOLE`.
///
/// This is what makes moving an instance affordable. An instance's root
/// disk is a `clonefile(2)` of a base image, truncated up to the shape's
/// size; the guest then writes into it. The file *claims* 20 GiB and holds
/// perhaps a tenth of that, and the tenth is the only part a copy — or a
/// transfer — has any reason to touch. Everything between two extents is a
/// hole, and a hole reconstructs itself on the far end: a file created,
/// truncated to the same length and written only at these offsets is
/// byte-for-byte the original, and just as sparse.
///
/// A filesystem that does not implement the two `whence` values answers
/// with something other than `ENXIO`, and the honest fallback is one extent
/// covering the whole file: nothing is lost, it merely costs what a plain
/// copy costs. `ENXIO` is not that case — it is the documented "no more
/// data at or beyond this offset", which is how the walk normally ends and
/// how a file that is *entirely* hole reports itself.
pub fn extents(path: &Path) -> Result<Vec<Extent>> {
    let file = std::fs::File::open(path)
        .with_context(|| format!("reading {}", path.display()))?;
    let len = file.metadata()?.len();
    Ok(walk_extents(&file, len))
}

/// `SEEK_HOLE`/`SEEK_DATA` — declared here for the same reason
/// `clonefile(2)` is, and note that the two constants are *swapped*
/// between Darwin and Linux. Getting them the wrong way round would
/// silently produce a transfer that carried the holes and skipped the
/// data, so they are pinned per platform rather than guessed.
#[cfg(target_os = "macos")]
const SEEK_HOLE: i32 = 3;
#[cfg(target_os = "macos")]
const SEEK_DATA: i32 = 4;
#[cfg(not(target_os = "macos"))]
const SEEK_DATA: i32 = 3;
#[cfg(not(target_os = "macos"))]
const SEEK_HOLE: i32 = 4;

/// "No data at or after this offset". The end of the walk, not a failure.
const ENXIO: i32 = 6;

fn walk_extents(file: &std::fs::File, len: u64) -> Vec<Extent> {
    use std::os::unix::io::AsRawFd;

    extern "C" {
        fn lseek(fd: std::ffi::c_int, offset: i64, whence: std::ffi::c_int) -> i64;
    }

    let whole = || vec![Extent { offset: 0, len }];
    if len == 0 {
        return Vec::new();
    }

    let fd = file.as_raw_fd();
    let mut out = Vec::new();
    let mut pos = 0u64;
    while pos < len {
        // SAFETY: `fd` is owned by `file`, which outlives the call, and the
        // offsets are in range for a file of this length.
        let data = unsafe { lseek(fd, pos as i64, SEEK_DATA) };
        if data < 0 {
            return match std::io::Error::last_os_error().raw_os_error() {
                Some(ENXIO) => out,
                _ => whole(),
            };
        }
        let hole = unsafe { lseek(fd, data, SEEK_HOLE) };
        if hole < 0 {
            return match std::io::Error::last_os_error().raw_os_error() {
                Some(ENXIO) => out,
                _ => whole(),
            };
        }
        // SEEK_HOLE answers with the file's length at the last extent, and
        // a file can grow between the metadata read and here.
        let (start, end) = (data as u64, (hole as u64).min(len));
        if end <= start {
            break;
        }
        out.push(Extent { offset: start, len: end - start });
        pos = end;
    }
    out
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

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn a_copy_says_why_it_was_a_copy() {
        let how = Cloned::Copied("cross-device link".into());
        let warning = how.warning(Path::new("/images/x.raw"), Path::new("/i/disk.raw")).unwrap();
        assert!(warning.contains("cross-device link"));
        assert!(warning.contains("APFS"));
    }

    #[test]
    fn sparse_files_cost_what_they_use_not_what_they_claim() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sparse.raw");
        let file = std::fs::File::create(&path).unwrap();
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
        use std::io::{Seek, SeekFrom, Write};

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("disk.raw");
        let mut file = std::fs::File::create(&path).unwrap();
        file.set_len(1 << 30).unwrap();
        file.seek(SeekFrom::Start(512 << 20)).unwrap();
        file.write_all(b"asterism").unwrap();
        file.sync_all().unwrap();
        drop(file);

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
            found.iter().any(|e| e.offset <= 512 << 20 && (512 << 20) < e.end()),
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
        std::fs::File::create(&hollow).unwrap().set_len(64 << 20).unwrap();
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
