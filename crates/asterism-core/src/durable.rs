//! Transactional durable state: how a file on this device survives `kill -9`,
//! a reboot, a full disk, and a rename that was never flushed.
//!
//! Everything Asterism remembers between two runs of `astd` is a file in
//! `$ASTERISM_HOME`: the registry shard, the orbit store, the volume book,
//! the secret catalog. Losing one of them is not losing a cache. It is an
//! instance that cannot be found, a device that is no longer trusted, a
//! volume whose lease nobody holds. So they are written the way a database
//! writes: the new value is built somewhere else, forced to the device, and
//! only then made the file — and the old value is kept until the new one has
//! landed.
//!
//! ### Why a rename on its own is not enough
//!
//! "Write a temp file and rename it over the old one" is the folklore, and it
//! is half of the answer. `rename(2)` is atomic against a *reader*: nobody
//! ever sees a half-written file. It is not atomic against *power*. Two
//! things are missing:
//!
//! * The temp file's bytes may still be in the page cache when the rename is
//!   recorded. A crash then leaves the file present, named right, and empty
//!   or torn. So the bytes are forced down ([`full_sync`]) before the rename
//!   is even attempted.
//! * The rename itself is a directory operation, and the directory is a file
//!   like any other. A crash after the rename returns can leave the directory
//!   entry pointing at the old inode — or at nothing. So the directory is
//!   forced down after the rename.
//!
//! On macOS `fsync(2)` is documented to return once the writes have reached
//! the drive, which the drive is free to interpret as "reached my cache".
//! `F_FULLFSYNC` is the one that means it, and it is what this module asks
//! for first, falling back to `fsync` on filesystems that refuse it.
//!
//! ### Why there is a `.bak`
//!
//! Forcing the bytes down makes a *torn* file impossible. It does not make an
//! unreadable one impossible: a bad block develops, a filesystem repairs
//! itself by zeroing a page, someone hand-edits JSON at 3am and leaves off a
//! brace. Every commit therefore leaves the value it replaced beside it as
//! `<file>.bak`, and [`load_json`] falls back to that copy when the live file
//! will not parse, saying so loudly. Losing the last mutation is recoverable;
//! losing the registry is not.
//!
//! And when *neither* copy can be read, this module refuses. It does not
//! invent an empty registry, because an empty registry is a instruction to
//! every other part of the daemon that the instances are gone. A refusal
//! names both files and stops; see [`unreadable`].
//!
//! ### Crash windows, enumerated
//!
//! A commit is: create the temp file fresh, write it, sync it, link the live
//! file to `.bak`, rename, sync the directory. Cut power at any point and the
//! directory holds one of:
//!
//! | after            | live file | `.bak`  | recovery                       |
//! |------------------|-----------|---------|--------------------------------|
//! | write / sync     | old       | older   | [`sweep_temporaries`] drops the temp |
//! | link             | old       | old     | same                           |
//! | rename           | new *or* old | old  | either is a value that was committed |
//! | directory sync   | new       | old     | nothing to do                  |
//!
//! There is no row where the live file is missing or half a value, which is
//! the whole point. The one ordering subtlety is that the `.bak` link and the
//! rename are both made durable by the *same* trailing directory sync, so a
//! crash between them can lose the link — leaving the new value live and no
//! backup, which is a state with no ambiguity in it.
//!
//! ### What may be at the staging path
//!
//! A staging path is derived from the file being committed, so it is
//! predictable: `secrets.json.tmp` sits next to `secrets.json` in a directory
//! anyone on the machine can list. Whatever is already there is therefore
//! *not* something to open — a mode argument is only applied to a file that
//! `open(2)` creates, and a symlink is followed. Both of those turn "write
//! the secret to a 0600 file" into "write the secret wherever the file that
//! is already there points, at whatever permissions it already has".
//!
//! So the staging file is created with `O_CREAT | O_EXCL | O_NOFOLLOW`, and
//! an occupied path is cleared with `unlink(2)` — which removes a symlink
//! itself and never its target — before a bounded number of retries. See
//! [`create_fresh`], which is where the whole of that argument lives.
//!
//! ### Fault injection
//!
//! None of the above can be tested by hoping. [`faults`] arms a failure at a
//! named step for paths matching a substring, so a test can make the rename
//! return `ENOSPC` and then assert what the directory holds. The check is one
//! relaxed atomic load when nothing is armed, which is why it is compiled
//! into the shipping binary rather than hidden behind a feature that the
//! daemon's own tests could not reach.

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::de::DeserializeOwned;
use serde::Serialize;

/// Suffix of the file a commit builds the new value in.
pub const TMP_SUFFIX: &str = ".tmp";
/// Suffix of the copy of the value the last commit replaced.
pub const BAK_SUFFIX: &str = ".bak";

/// Where a commit to `path` stages its bytes.
pub fn tmp_path(path: &Path) -> PathBuf {
    with_suffix(path, TMP_SUFFIX)
}

/// Where the value `path` held before the last commit is kept.
pub fn backup_path(path: &Path) -> PathBuf {
    with_suffix(path, BAK_SUFFIX)
}

/// `state.json` + `.tmp` is `state.json.tmp`, not `state.tmp`: the suffix is
/// appended rather than substituted, so two stores that differ only in their
/// extension cannot collide on one temp file.
fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(suffix);
    PathBuf::from(name)
}

// ---- committing ------------------------------------------------------------

/// Publish `bytes` at `path`, durably, keeping the value it replaces.
///
/// Returns only once the new value would survive the machine losing power,
/// which is what lets a caller record something to a peer immediately after.
pub fn commit(path: &Path, bytes: &[u8]) -> Result<()> {
    commit_inner(path, bytes, None)
}

/// [`commit`], with the file created `0600` from the first byte.
///
/// For anything a second user on this machine must not read: the secret
/// catalog, a cached guest key, an instance's egress CA key.
///
/// Two things make that true rather than merely intended. The mode is passed
/// to `open(2)` rather than set afterwards, so there is no window in which
/// the file exists and is readable. And the file is one this call *created* —
/// see [`create_fresh`] — because a mode argument does nothing at all for a
/// path that already exists, which is how a predictable staging path turns
/// into a secret in somebody else's file.
pub fn commit_private(path: &Path, bytes: &[u8]) -> Result<()> {
    commit_inner(path, bytes, Some(0o600))
}

/// [`commit`] of a value serialised as pretty JSON.
///
/// Pretty rather than compact on purpose: these files are the ones a user
/// reads when something has gone wrong, and `ast doctor` quoting a line
/// number is worth more than the bytes it costs.
pub fn commit_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(value)
        .with_context(|| format!("serialising {}", path.display()))?;
    commit(path, &bytes)
}

/// [`commit_json`], `0600`.
pub fn commit_json_private<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(value)
        .with_context(|| format!("serialising {}", path.display()))?;
    commit_private(path, &bytes)
}

fn commit_inner(path: &Path, bytes: &[u8], mode: Option<u32>) -> Result<()> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    faults::check(faults::Point::Create, dir)?;
    std::fs::create_dir_all(dir)
        .with_context(|| format!("creating {} to hold {}", dir.display(), path.display()))?;

    // 1. The new value, whole, and on the device before anything points at it.
    let tmp = tmp_path(path);
    write_forced(&tmp, bytes, mode)
        .with_context(|| format!("staging the new {} at {}", path.display(), tmp.display()))?;

    // 2. The value being replaced, kept where `load_json` will look for it.
    //    A failure here is not fatal: it costs the safety net, not the
    //    commit, and refusing to save because the *previous* save cannot be
    //    copied would be the tail wagging the dog.
    if let Err(e) = keep_backup(path, mode) {
        eprintln!(
            "asterism: could not keep a last-known-good copy of {}: {e} — \
             committing anyway",
            path.display()
        );
    }

    // 3. Publish. Nothing is cleaned up if this fails: the temp file left
    //    behind is exactly what a `kill -9` here would leave, and
    //    `sweep_temporaries` is what removes both.
    faults::check(faults::Point::Rename, path)?;
    std::fs::rename(&tmp, path)
        .with_context(|| format!("committing {}", path.display()))?;

    // 4. Make the rename itself survive power loss. Until this returns, the
    //    directory entry is a promise the drive has not made.
    sync_dir(dir).with_context(|| format!("flushing {}", dir.display()))?;
    Ok(())
}

/// Write `bytes` to `path` and force them to the device.
fn write_forced(path: &Path, bytes: &[u8], mode: Option<u32>) -> io::Result<()> {
    let mut file = create_fresh(path, mode)?;

    faults::check_io(faults::Point::Write, path)?;
    file.write_all(bytes)?;

    faults::check_io(faults::Point::SyncFile, path)?;
    full_sync(&file)
}

/// How many times a commit will clear an occupied staging path before it
/// gives up. Three, because the only legitimate occupant is the leftover of
/// one interrupted commit: anything that keeps reappearing is something else,
/// and racing it forever would be the wrong answer.
const STAGING_ATTEMPTS: usize = 3;

/// Open the staging file, and only ever a *new* one, at exactly `mode`.
///
/// `O_CREAT | O_EXCL | O_NOFOLLOW`: create it or do not open anything. This
/// is the whole of the file's security, and each half of it matters.
///
/// **`O_EXCL`, because a mode is only applied to a file that is created.**
/// `open(O_CREAT)` on a path that already exists ignores the mode argument
/// entirely and hands back the existing file with the permissions it already
/// had. A staging path is predictable — `secrets.json.tmp`, next to a
/// world-readable directory — so "create it 0600" written that way means
/// "0600 if nobody got there first", and a `0666` file left by a crash, or
/// put there on purpose, is a file that a secret gets written into and
/// anyone on the machine can read.
///
/// **`O_NOFOLLOW` (and `O_EXCL`, which refuses a symlink of its own accord),
/// because otherwise the bytes go somewhere else.** A symlink at the staging
/// path means `write_all` writes *through* it, to whatever it points at. The
/// rename afterwards moves the link, not the target, so the commit succeeds,
/// the state file looks right, and the secret is sitting in a file the
/// attacker chose.
///
/// An occupied path is cleared with `unlink(2)`, which removes a symlink
/// itself and never what it points at, and the create is retried. That is
/// also what keeps a `kill -9` recoverable: the staging file an interrupted
/// commit left behind is exactly this case, and the next commit clears it and
/// carries on rather than refusing until someone sweeps by hand.
fn create_fresh(path: &Path, mode: Option<u32>) -> io::Result<File> {
    for _ in 0..STAGING_ATTEMPTS {
        faults::check_io(faults::Point::Create, path)?;
        let mut open = OpenOptions::new();
        open.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            // Not `umask`'s business what a private file is: the mode is on
            // the open, and umask can only take bits away from it.
            open.mode(mode.unwrap_or(0o644));
            open.custom_flags(libc::O_NOFOLLOW);
        }
        #[cfg(not(unix))]
        let _ = mode;
        match open.open(path) {
            Ok(file) => return Ok(file),
            // Something is already there — a leftover, a symlink, anything.
            // `O_EXCL` reports a symlink as `EEXIST` on both platforms this
            // runs on, but `O_NOFOLLOW`'s own `ELOOP` is the same answer and
            // is accepted here rather than left to depend on which flag the
            // kernel checks first.
            Err(e)
                if e.kind() == io::ErrorKind::AlreadyExists
                    || e.raw_os_error() == Some(libc::ELOOP) => {}
            Err(e) => return Err(e),
        }
        match std::fs::remove_file(path) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            // A directory at the staging path, or one this user cannot
            // unlink. Not something to keep trying.
            Err(e) => return Err(e),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        format!(
            "{} keeps being re-created between clearing it and staging into it. \
             Asterism will not write into a file it did not create — remove \
             whatever is doing that before running this again.",
            path.display()
        ),
    ))
}

/// Link the live file to its `.bak`, so the value about to be replaced is
/// still readable if the new one turns out not to be.
///
/// A hard link rather than a copy: it is one inode operation whatever the
/// file's size, and it cannot itself run out of disk halfway. Filesystems
/// that will not link (or a `.bak` that is somehow a directory) fall back to
/// a copy, and a first-ever commit has nothing to keep.
fn keep_backup(live: &Path, mode: Option<u32>) -> io::Result<()> {
    // `symlink_metadata`, not `exists`: the question is what is at this path,
    // not what it leads to.
    let meta = match std::fs::symlink_metadata(live) {
        Ok(meta) => meta,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    if meta.file_type().is_symlink() {
        // Following it would copy somebody else's file and call the copy this
        // device's last-known-good state. The commit below replaces the link
        // itself, so the only thing lost by refusing here is the safety net
        // for one commit — and the caller says so out loud.
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} is a symlink, not this device's state file", live.display()),
        ));
    }
    faults::check_io(faults::Point::Backup, live)?;
    let bak = backup_path(live);
    // Unlinked first, which removes a symlink sitting there rather than
    // following it, and which `link(2)` needs anyway: it refuses a
    // destination that exists.
    match std::fs::remove_file(&bak) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    match std::fs::hard_link(live, &bak) {
        // A link shares the inode, and therefore the mode: a backup of a
        // 0600 file cannot come out any more readable than the file.
        Ok(()) => Ok(()),
        // A filesystem that will not link. `fs::copy` is the obvious
        // fallback and the wrong one — it creates the destination at the
        // default mode and fixes it afterwards, which for a secret is a
        // window where the copy is world-readable. This creates it at the
        // right mode instead.
        Err(_) => {
            let bytes = std::fs::read(live)?;
            let mut copy = create_fresh(&bak, mode.or(Some(meta_mode(&meta))))?;
            copy.write_all(&bytes)?;
            full_sync(&copy)
        }
    }
}

/// The permission bits of a file this device already committed.
fn meta_mode(meta: &std::fs::Metadata) -> u32 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        meta.permissions().mode() & 0o777
    }
    #[cfg(not(unix))]
    {
        let _ = meta;
        0o644
    }
}

// ---- publishing bytes somebody else built ----------------------------------

/// Make a file built under a temporary name the real one, durably.
///
/// The same commit as [`commit`] for the case where the bytes were not
/// produced in memory — a download, a `qemu-img convert`, a snapshot clone.
/// There is no `.bak`: these are large and re-derivable, and a second copy of
/// a base image is a gigabyte spent to avoid a re-download.
pub fn publish_file(part: &Path, dest: &Path) -> Result<()> {
    // Opened read-only purely to flush it: whoever wrote it has closed it,
    // and a closed file is not a flushed one.
    match open_no_follow(part) {
        Ok(file) => {
            faults::check_io(faults::Point::SyncFile, part)?;
            full_sync(&file).with_context(|| format!("flushing {}", part.display()))?;
        }
        Err(e) => {
            return Err(e).with_context(|| format!("reading back {}", part.display()));
        }
    }
    publish_rename(part, dest)
}

/// Make a directory built under a staging name the real one, durably.
///
/// Used where a whole instance arrives at once — a cpu-part move, which is
/// staged beside the live instances precisely so that adopting it is a
/// rename. Every file in the tree is forced down before the rename, because
/// a guest booted from a disk still sitting in the page cache is a guest that
/// a power cut turns into a corrupt disk.
///
/// That sync is proportional to the tree, and for a move it is a gigabyte of
/// disk. It is paid once, at the end of a transfer that already cost more
/// than that, and it is the difference between "the move completed" and "the
/// move completed if nothing goes wrong in the next few seconds".
pub fn publish_dir(staging: &Path, dest: &Path) -> Result<()> {
    sync_tree(staging).with_context(|| format!("flushing {}", staging.display()))?;
    publish_rename(staging, dest)
}

/// Rename something into place and make the rename itself durable.
///
/// For the case where there is nothing to flush first because the bytes were
/// never ours — an instance directory being renamed with the instance, a
/// staged tree that has already been synced. The two parent directories are
/// both flushed, because a rename across them is two directory changes and a
/// crash between them is how a directory ends up in neither place.
pub fn publish_rename(from: &Path, to: &Path) -> Result<()> {
    faults::check(faults::Point::Rename, to)?;
    std::fs::rename(from, to)
        .with_context(|| format!("putting {} at {}", from.display(), to.display()))?;
    let source_dir = from.parent().unwrap_or_else(|| Path::new("."));
    let dest_dir = to.parent().unwrap_or_else(|| Path::new("."));
    sync_dir(dest_dir).with_context(|| format!("flushing {}", dest_dir.display()))?;
    if source_dir != dest_dir {
        sync_dir(source_dir).with_context(|| format!("flushing {}", source_dir.display()))?;
    }
    Ok(())
}

/// Open a file for reading, refusing a symlink.
///
/// What is being published here was built under a name this process chose. A
/// symlink at that name is not our staging file, and publishing it would put
/// a link where the caller asked for the bytes.
fn open_no_follow(path: &Path) -> io::Result<File> {
    let mut open = OpenOptions::new();
    open.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        open.custom_flags(libc::O_NOFOLLOW);
    }
    open.open(path)
}

/// Force every file in a tree, and then the directories themselves.
fn sync_tree(root: &Path) -> io::Result<()> {
    let meta = std::fs::symlink_metadata(root)?;
    if meta.is_file() {
        let file = File::open(root)?;
        return full_sync(&file);
    }
    if meta.is_symlink() {
        // Its target is synced on its own if it is in this tree, and is not
        // ours to touch if it is not.
        return Ok(());
    }
    for entry in std::fs::read_dir(root)? {
        sync_tree(&entry?.path())?;
    }
    sync_dir(root)
}

// ---- forcing things down ---------------------------------------------------

/// Force a directory's own contents — its entries — to the device.
///
/// A directory opens read-only and syncs like anything else on both
/// platforms Asterism runs on. Not being able to open it is a real error;
/// not being able to *sync* it after opening it is treated as one too, since
/// the whole reason the call is here is that skipping it loses the rename.
pub fn sync_dir(dir: &Path) -> io::Result<()> {
    faults::check_io(faults::Point::SyncDir, dir)?;
    let handle = File::open(dir)?;
    match handle.sync_all() {
        Ok(()) => Ok(()),
        // Some filesystems (and every one under a container runtime that
        // fakes them) refuse fsync on a directory. The rename is still
        // ordered; it is only the barrier that is missing, and refusing to
        // run there would help nobody.
        Err(e) if matches!(e.raw_os_error(), Some(libc::EINVAL) | Some(libc::ENOTSUP)) => Ok(()),
        Err(e) => Err(e),
    }
}

/// `fsync`, or on macOS the one that actually reaches the platter.
///
/// `fsync(2)` on Darwin returns once the writes have been handed to the
/// drive, which may hold them in a volatile cache; `F_FULLFSYNC` asks the
/// drive to flush that cache. It is the difference between surviving
/// `kill -9` and surviving the power going out, and it is the whole reason
/// this function exists rather than a bare `sync_all` at each call site.
fn full_sync(file: &File) -> io::Result<()> {
    #[cfg(target_os = "macos")]
    {
        use std::os::unix::io::AsRawFd;
        // SAFETY: `file` owns the descriptor for the duration of the call
        // and `F_FULLFSYNC` takes no argument.
        let rc = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_FULLFSYNC) };
        if rc != -1 {
            return Ok(());
        }
        let e = io::Error::last_os_error();
        if !matches!(
            e.raw_os_error(),
            Some(libc::ENOTSUP) | Some(libc::EINVAL) | Some(libc::ENOTTY)
        ) {
            return Err(e);
        }
        // Fall through: the filesystem does not implement it (tmpfs, some
        // network mounts), and fsync is the strongest thing left.
    }
    file.sync_all()
}

// ---- reading ---------------------------------------------------------------

/// A document that was read, and whether it had to be recovered to read it.
#[derive(Debug)]
pub struct Loaded<T> {
    pub value: T,
    /// Set when the live file could not be read and this came from the
    /// last-known-good copy. The caller prints it and commits the value
    /// straight back, so the next reader finds a healthy file.
    pub repaired: Option<String>,
}

/// Read a JSON document, falling back to its last-known-good copy.
///
/// `Ok(None)` means neither file is there — a first run, which is not a
/// failure and which the caller answers with its own empty value. Anything
/// else is either a document or a refusal.
///
/// The fallback is deliberately narrow. A file that will not *parse* is
/// content that cannot be trusted, and the backup is strictly better than
/// nothing. A file that will not *read* — `EIO`, a permission that changed,
/// a mount that went away — is a machine that is having a different problem,
/// and quietly reverting to an older registry there would replace a loud
/// failure with a silent rollback. That refuses.
pub fn load_json<T: DeserializeOwned>(path: &Path, what: &str) -> Result<Option<Loaded<T>>> {
    load_json_versioned(path, what, u32::MAX)
}

/// [`load_json`] for a document that carries a `version` field.
///
/// The version is read *before* the document is, and a file claiming a
/// version this build does not speak is refused on the spot — not repaired
/// from the backup, not parsed as best it can be. A newer Asterism wrote it,
/// it holds state this build would drop, and the backup is no better because
/// it came from the same newer Asterism. See [`from_the_future`].
///
/// Documents with no `version` field at all are the pre-envelope format and
/// are handed to the caller to migrate.
pub fn load_json_versioned<T: DeserializeOwned>(
    path: &Path,
    what: &str,
    current: u32,
) -> Result<Option<Loaded<T>>> {
    let bak = backup_path(path);
    match read_faultily(path) {
        Ok(bytes) => match interpret(&bytes, current) {
            Ok(value) => Ok(Some(Loaded { value, repaired: None })),
            Err(Trouble::FromTheFuture(found)) => {
                Err(from_the_future(what, path, found, current))
            }
            Err(Trouble::Unreadable(parse)) => match from_backup(&bak, current) {
                Some(value) => Ok(Some(Loaded {
                    value,
                    repaired: Some(format!(
                        "{} is not readable as {what} ({parse}) — this device fell \
                         back to the last-known-good copy at {}, which is the state \
                         as of the commit before the one that failed. The unreadable \
                         file has been replaced; nothing else was changed.",
                        path.display(),
                        bak.display()
                    )),
                })),
                None => Err(unreadable(what, path, &parse, &bak)),
            },
        },
        Err(e) if e.kind() == io::ErrorKind::NotFound => match from_backup(&bak, current) {
            // The live file is gone but the backup is not: a crash in the
            // one window where that can happen, or someone deleting the
            // wrong file. Either way the backup is a value this device
            // really committed, so it is used and said out loud.
            Some(value) => Ok(Some(Loaded {
                value,
                repaired: Some(format!(
                    "{} is missing but its last-known-good copy at {} is not — this \
                     device recovered from it. If you deleted that file on purpose, \
                     delete the copy too.",
                    path.display(),
                    bak.display()
                )),
            })),
            None => Ok(None),
        },
        Err(e) => Err(e).with_context(|| format!("reading {} ({what})", path.display())),
    }
}

fn read_faultily(path: &Path) -> io::Result<Vec<u8>> {
    faults::check_io(faults::Point::Read, path)?;
    std::fs::read(path)
}

fn from_backup<T: DeserializeOwned>(bak: &Path, current: u32) -> Option<T> {
    let bytes = std::fs::read(bak).ok()?;
    interpret(&bytes, current).ok()
}

/// Why a document could not be turned into a value.
enum Trouble {
    /// It says it is a version this build does not speak.
    FromTheFuture(u32),
    /// It does not parse, or does not parse as this type.
    Unreadable(String),
}

/// Read the `version` field first, then the document.
fn interpret<T: DeserializeOwned>(bytes: &[u8], current: u32) -> Result<T, Trouble> {
    /// Just enough of any Asterism state file to learn what it claims to be.
    #[derive(serde::Deserialize)]
    struct Probe {
        version: Option<u32>,
    }
    if let Ok(Probe { version: Some(found) }) = serde_json::from_slice::<Probe>(bytes) {
        if found > current {
            return Err(Trouble::FromTheFuture(found));
        }
    }
    serde_json::from_slice(bytes).map_err(|e| Trouble::Unreadable(e.to_string()))
}

/// The refusal a state file gets when neither it nor its backup can be read.
///
/// Deliberately not an empty value. Every one of these files means "what
/// this device has", and an empty one means "this device has nothing" — a
/// claim that would propagate: instances vanish from `ast ls`, a paired
/// device stops being trusted, a volume's lease stops being held. So this
/// stops, names both files, and says what to do.
pub fn unreadable(what: &str, path: &Path, why: &str, bak: &Path) -> anyhow::Error {
    anyhow::anyhow!(
        "{} is not readable as {what} ({why}), and neither is its last-known-good \
         copy at {}.\n\
         Asterism will not guess what they said — an empty {what} would read as \
         \"this device has nothing\", and that is not something to assume.\n\
         To repair: move both files aside (`mv {} {}.broken`), restore them from a \
         backup if you have one, and start astd again. Nothing else on this device \
         has been changed.",
        path.display(),
        bak.display(),
        path.display(),
        path.display(),
    )
}

/// The refusal a state file written by a newer Asterism gets.
///
/// Separate from [`unreadable`] and never repaired over: a file from the
/// future parses fine, it just says more than this build understands, and
/// overwriting it with a backup this build *can* read would silently discard
/// whatever the newer one recorded. Downgrades are the user's decision.
pub fn from_the_future(what: &str, path: &Path, found: u32, current: u32) -> anyhow::Error {
    anyhow::anyhow!(
        "{} is {what} format version {found}, and this build of Asterism speaks \
         {current}. It was written by a newer Asterism and may hold state this one \
         would drop.\n\
         To repair: upgrade Asterism (`brew upgrade asterism`), or move the file \
         aside if you meant to start over.",
        path.display()
    )
}

// ---- crash cleanup ---------------------------------------------------------

/// Delete the staging files a commit interrupted by `kill -9` left behind.
///
/// Run once at daemon start, when this process has proved it is the only
/// daemon on this home. A `.tmp` is by construction not referenced by
/// anything: no reader ever opens one, and the value it holds either landed
/// (in which case the temp is a duplicate) or did not (in which case it is a
/// value this device never committed). Removing it is the whole recovery.
///
/// The `.bak` files are left exactly where they are. They are the safety net,
/// not litter.
///
/// Returns what it removed, so the daemon can say so — an interrupted commit
/// is worth a line in the log even though nothing came of it.
pub fn sweep_temporaries(dir: &Path) -> Vec<PathBuf> {
    let mut swept = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else { return swept };
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        // `.tmp` covers what this module writes; the bare `.part` is what an
        // interrupted download or convert leaves at the top level.
        if !name.ends_with(TMP_SUFFIX) {
            continue;
        }
        if std::fs::remove_file(&path).is_ok() {
            swept.push(path);
        }
    }
    swept.sort();
    swept
}

// ---- fault injection -------------------------------------------------------

/// Making a commit fail on purpose, one step at a time.
///
/// A durability claim that is only argued in a comment is a durability claim
/// that is wrong. This is how the tests in this tree cut the power: arm a
/// failure at a step for a path, run the commit, and look at what the
/// directory holds.
///
/// It is compiled into the shipping binary. Nothing arms a fault except a
/// test — the arming functions are only ever called from `#[cfg(test)]` code
/// — and when nothing is armed the cost is one relaxed atomic load per
/// filesystem step, which is not measurable next to the syscall it guards.
/// The alternative, a cargo feature, would put it out of reach of the daemon
/// crate's tests, which are exactly the ones that exercise a real store.
pub mod faults {
    use std::io;
    use std::path::Path;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Mutex, OnceLock};

    /// A step of a durable commit that can be made to fail.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Point {
        /// Creating the directory, or opening the file to stage into.
        Create,
        /// Writing the staged bytes. Where `ENOSPC` really lands.
        Write,
        /// Forcing the staged bytes down.
        SyncFile,
        /// Keeping the last-known-good copy.
        Backup,
        /// The rename that publishes the value.
        Rename,
        /// Forcing the directory entry down.
        SyncDir,
        /// Reading a document back. Where `EIO` lands.
        Read,
    }

    struct Fault {
        tag: &'static str,
        point: Point,
        path_contains: String,
        kind: io::ErrorKind,
        errno: Option<i32>,
        /// How many more times this fires. `None` is every time.
        remaining: Option<usize>,
    }

    fn table() -> &'static Mutex<Vec<Fault>> {
        static TABLE: OnceLock<Mutex<Vec<Fault>>> = OnceLock::new();
        TABLE.get_or_init(|| Mutex::new(Vec::new()))
    }

    /// Whether anything at all is armed, so the common path never takes the
    /// lock.
    static ANY: AtomicBool = AtomicBool::new(false);

    /// An armed fault, disarmed when it drops.
    ///
    /// Tests run on as many threads as the machine has cores and the table is
    /// process-wide, so a fault is scoped to paths containing a substring —
    /// give each test its own temp directory and two of them cannot see each
    /// other's faults.
    #[must_use = "the fault is disarmed as soon as this is dropped"]
    pub struct Armed {
        tag: &'static str,
    }

    impl Drop for Armed {
        fn drop(&mut self) {
            let mut table = table().lock().unwrap_or_else(|e| e.into_inner());
            table.retain(|f| f.tag != self.tag);
            ANY.store(!table.is_empty(), Ordering::Relaxed);
        }
    }

    /// Fail `point` for every path containing `path_contains`, until the
    /// returned guard drops.
    pub fn arm(
        tag: &'static str,
        point: Point,
        path_contains: impl Into<String>,
        kind: io::ErrorKind,
    ) -> Armed {
        push(tag, point, path_contains.into(), kind, None, None)
    }

    /// [`arm`], but reporting a specific errno — `ENOSPC`, `EIO` — for the
    /// cases where the kind alone does not say which failure is being
    /// modelled.
    pub fn arm_errno(
        tag: &'static str,
        point: Point,
        path_contains: impl Into<String>,
        errno: i32,
    ) -> Armed {
        push(tag, point, path_contains.into(), io::ErrorKind::Other, Some(errno), None)
    }

    /// [`arm`], firing only once — the shape of a transient failure, and how
    /// a test asserts that the second attempt succeeds.
    pub fn arm_once(
        tag: &'static str,
        point: Point,
        path_contains: impl Into<String>,
        kind: io::ErrorKind,
    ) -> Armed {
        push(tag, point, path_contains.into(), kind, None, Some(1))
    }

    fn push(
        tag: &'static str,
        point: Point,
        path_contains: String,
        kind: io::ErrorKind,
        errno: Option<i32>,
        remaining: Option<usize>,
    ) -> Armed {
        let mut table = table().lock().unwrap_or_else(|e| e.into_inner());
        table.retain(|f| f.tag != tag);
        table.push(Fault { tag, point, path_contains, kind, errno, remaining });
        ANY.store(true, Ordering::Relaxed);
        Armed { tag }
    }

    /// The hook every filesystem step in this module calls.
    pub(super) fn check_io(point: Point, path: &Path) -> io::Result<()> {
        if !ANY.load(Ordering::Relaxed) {
            return Ok(());
        }
        let display = path.to_string_lossy().into_owned();
        let mut table = table().lock().unwrap_or_else(|e| e.into_inner());
        let Some(fault) =
            table.iter_mut().find(|f| f.point == point && display.contains(&f.path_contains))
        else {
            return Ok(());
        };
        if let Some(left) = fault.remaining.as_mut() {
            if *left == 0 {
                return Ok(());
            }
            *left -= 1;
        }
        Err(match fault.errno {
            Some(errno) => io::Error::from_raw_os_error(errno),
            None => io::Error::new(fault.kind, "injected fault"),
        })
    }

    pub(super) fn check(point: Point, path: &Path) -> anyhow::Result<()> {
        check_io(point, path).map_err(|e| {
            anyhow::anyhow!("{e}").context(format!("at {}", path.display()))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::faults::Point;
    use super::*;
    use serde::Deserialize;

    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct Doc {
        n: u32,
    }

    fn read(path: &Path) -> String {
        std::fs::read_to_string(path).unwrap()
    }

    #[test]
    fn a_commit_lands_and_can_be_read_back() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("doc.json");
        commit_json(&path, &Doc { n: 1 }).unwrap();
        let loaded: Loaded<Doc> = load_json(&path, "a document").unwrap().unwrap();
        assert_eq!(loaded.value, Doc { n: 1 });
        assert!(loaded.repaired.is_none());
        assert!(!tmp_path(&path).exists(), "the staging file is consumed by the rename");
    }

    #[test]
    fn nothing_on_disk_is_not_a_failure() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("doc.json");
        let loaded: Option<Loaded<Doc>> = load_json(&missing, "a document").unwrap();
        assert!(loaded.is_none(), "a first run reads no document and no error");
    }

    #[test]
    fn the_second_commit_keeps_the_first_as_the_last_known_good() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("doc.json");
        commit_json(&path, &Doc { n: 1 }).unwrap();
        assert!(!backup_path(&path).exists(), "a first commit has nothing to keep");
        commit_json(&path, &Doc { n: 2 }).unwrap();
        let bak: Doc = serde_json::from_str(&read(&backup_path(&path))).unwrap();
        assert_eq!(bak, Doc { n: 1 });
    }

    /// The `.bak` must be a snapshot, not a second name for the live file:
    /// hard-linking and then writing *through* the link would make the backup
    /// track every commit and protect nothing.
    #[test]
    fn the_backup_does_not_follow_later_commits() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("doc.json");
        commit_json(&path, &Doc { n: 1 }).unwrap();
        commit_json(&path, &Doc { n: 2 }).unwrap();
        commit_json(&path, &Doc { n: 3 }).unwrap();
        let bak: Doc = serde_json::from_str(&read(&backup_path(&path))).unwrap();
        assert_eq!(bak, Doc { n: 2 }, "the backup is the value the last commit replaced");
    }

    /// ENOSPC while the new value is being staged. The old value is still
    /// the file, and the caller is told.
    #[test]
    fn a_full_disk_during_the_write_leaves_the_committed_value_alone() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("enospc.json");
        commit_json(&path, &Doc { n: 1 }).unwrap();

        let armed = faults::arm_errno("enospc-write", Point::Write, "enospc.json", libc::ENOSPC);
        let err = commit_json(&path, &Doc { n: 2 }).unwrap_err();
        assert!(format!("{err:#}").contains("staging"), "{err:#}");
        drop(armed);

        let loaded: Loaded<Doc> = load_json(&path, "a document").unwrap().unwrap();
        assert_eq!(loaded.value, Doc { n: 1 }, "the value that was committed is still there");
        assert!(loaded.repaired.is_none(), "and it needed no repair");
    }

    /// `kill -9` between the sync and the rename: the temp file is on disk,
    /// the live file is the old value, and the sweep removes the temp.
    #[test]
    fn a_crash_before_the_rename_converges_on_the_old_value() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("crash-rename.json");
        commit_json(&path, &Doc { n: 1 }).unwrap();

        let armed =
            faults::arm("crash-rename", Point::Rename, "crash-rename.json", io::ErrorKind::Other);
        assert!(commit_json(&path, &Doc { n: 2 }).is_err());
        drop(armed);

        assert!(tmp_path(&path).exists(), "the interrupted commit left its staging file");
        let swept = sweep_temporaries(dir.path());
        assert_eq!(swept, vec![tmp_path(&path)]);
        assert!(!tmp_path(&path).exists());

        let loaded: Loaded<Doc> = load_json(&path, "a document").unwrap().unwrap();
        assert_eq!(loaded.value, Doc { n: 1 });
    }

    /// The directory sync failing is the one step after the value is already
    /// live. The commit reports it — the caller has been told the value may
    /// not survive power loss — and the value is readable either way.
    #[test]
    fn a_failed_directory_flush_is_reported_and_the_value_is_live() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("syncdir.json");
        commit_json(&path, &Doc { n: 1 }).unwrap();

        let armed = faults::arm(
            "syncdir",
            Point::SyncDir,
            dir.path().to_string_lossy().into_owned(),
            io::ErrorKind::Other,
        );
        let err = commit_json(&path, &Doc { n: 2 }).unwrap_err();
        assert!(format!("{err:#}").contains("flushing"), "{err:#}");
        drop(armed);

        let loaded: Loaded<Doc> = load_json(&path, "a document").unwrap().unwrap();
        assert_eq!(loaded.value, Doc { n: 2 }, "the rename had already happened");
    }

    /// A commit whose backup step fails still commits: the safety net is
    /// worth less than the value.
    #[test]
    fn a_commit_survives_losing_its_backup() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nobak.json");
        commit_json(&path, &Doc { n: 1 }).unwrap();

        let armed =
            faults::arm("nobak", Point::Backup, "nobak.json", io::ErrorKind::PermissionDenied);
        commit_json(&path, &Doc { n: 2 }).unwrap();
        drop(armed);

        let loaded: Loaded<Doc> = load_json(&path, "a document").unwrap().unwrap();
        assert_eq!(loaded.value, Doc { n: 2 });
    }

    #[test]
    fn a_truncated_file_is_repaired_from_the_last_known_good() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("doc.json");
        commit_json(&path, &Doc { n: 1 }).unwrap();
        commit_json(&path, &Doc { n: 2 }).unwrap();

        // What a filesystem that lost a page leaves: a prefix.
        let whole = read(&path);
        std::fs::write(&path, &whole[..whole.len() / 2]).unwrap();

        let loaded: Loaded<Doc> = load_json(&path, "a document").unwrap().unwrap();
        assert_eq!(loaded.value, Doc { n: 1 });
        let repaired = loaded.repaired.expect("the fallback is reported");
        assert!(repaired.contains("last-known-good"), "{repaired}");
    }

    #[test]
    fn an_empty_file_is_repaired_from_the_last_known_good() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("doc.json");
        commit_json(&path, &Doc { n: 7 }).unwrap();
        commit_json(&path, &Doc { n: 8 }).unwrap();
        std::fs::write(&path, b"").unwrap();

        let loaded: Loaded<Doc> = load_json(&path, "a document").unwrap().unwrap();
        assert_eq!(loaded.value, Doc { n: 7 });
        assert!(loaded.repaired.is_some());
    }

    #[test]
    fn a_deleted_live_file_is_recovered_from_the_last_known_good() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("doc.json");
        commit_json(&path, &Doc { n: 1 }).unwrap();
        commit_json(&path, &Doc { n: 2 }).unwrap();
        std::fs::remove_file(&path).unwrap();

        let loaded: Loaded<Doc> = load_json(&path, "a document").unwrap().unwrap();
        assert_eq!(loaded.value, Doc { n: 1 });
        assert!(loaded.repaired.is_some());
    }

    /// Both copies gone: this is the ambiguous mutation the epic asks to be
    /// refused. No empty document, and a message naming both files.
    #[test]
    fn two_unreadable_copies_are_refused_with_a_repair_path() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("doc.json");
        commit_json(&path, &Doc { n: 1 }).unwrap();
        commit_json(&path, &Doc { n: 2 }).unwrap();
        std::fs::write(&path, b"{ not json").unwrap();
        std::fs::write(backup_path(&path), b"also not json").unwrap();

        let err = load_json::<Doc>(&path, "a document").unwrap_err();
        let text = format!("{err:#}");
        assert!(text.contains("will not guess"), "{text}");
        assert!(text.contains("To repair"), "{text}");
        assert!(text.contains(&path.display().to_string()), "{text}");
        assert!(text.contains(&backup_path(&path).display().to_string()), "{text}");
    }

    /// EIO reading the live file is a machine with a different problem.
    /// Reverting to an older document there would be a silent rollback, so
    /// it refuses instead.
    #[test]
    fn an_io_error_on_the_live_file_refuses_rather_than_rolling_back() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("eio.json");
        commit_json(&path, &Doc { n: 1 }).unwrap();
        commit_json(&path, &Doc { n: 2 }).unwrap();

        let _armed = faults::arm_errno("eio-read", Point::Read, "eio.json", libc::EIO);
        let err = load_json::<Doc>(&path, "a document").unwrap_err();
        assert!(format!("{err:#}").contains("reading"), "{err:#}");
    }

    /// A transient failure is transient: the retry finds a clean directory
    /// and commits.
    #[test]
    fn a_commit_can_be_retried_after_a_failure() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("retry.json");
        commit_json(&path, &Doc { n: 1 }).unwrap();

        let armed = faults::arm_once("retry", Point::Rename, "retry.json", io::ErrorKind::Other);
        assert!(commit_json(&path, &Doc { n: 2 }).is_err());
        commit_json(&path, &Doc { n: 2 }).unwrap();
        drop(armed);

        let loaded: Loaded<Doc> = load_json(&path, "a document").unwrap().unwrap();
        assert_eq!(loaded.value, Doc { n: 2 });
    }

    #[test]
    fn a_private_commit_is_unreadable_to_anyone_else() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret.json");
        commit_json_private(&path, &Doc { n: 1 }).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "and it was created that way, not chmod'd after");
        }
    }

    // ---- what may be sitting at the staging path ---------------------------
    //
    // A staging path is predictable and it is next to a directory anyone on
    // the machine can list. Everything below is what happens when something
    // is already there, and each of these is a way a secret used to escape.

    #[cfg(unix)]
    fn mode_of(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        // Not `metadata`: the question is what is at this path.
        std::fs::symlink_metadata(path).unwrap().permissions().mode() & 0o777
    }

    const SECRET: &[u8] = b"{\"token\":\"NEVER-READABLE-BY-ANYONE-ELSE\"}";

    /// A `0666` file at the staging path — the leftover of a crash, or one
    /// put there on purpose. `open(O_CREAT)` would hand it back *with its
    /// existing permissions*, mode argument ignored, and the secret would be
    /// written into a world-readable file.
    #[cfg(unix)]
    #[test]
    fn a_permissive_file_at_the_staging_path_cannot_leak_a_private_commit() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secrets.json");
        let tmp = tmp_path(&path);

        std::fs::write(&tmp, b"planted").unwrap();
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o666)).unwrap();
        assert_eq!(mode_of(&tmp), 0o666, "the trap is set");

        commit_private(&path, SECRET).unwrap();

        assert_eq!(mode_of(&path), 0o600, "the committed secret is private");
        assert_eq!(std::fs::read(&path).unwrap(), SECRET);
        assert!(!tmp.exists(), "and the planted file is gone, not written into");
    }

    /// The same trap on the *public* commit path. Nothing secret is at stake
    /// here, but adopting a file this process did not create means adopting
    /// whatever permissions it came with.
    #[cfg(unix)]
    #[test]
    fn a_permissive_file_at_the_staging_path_does_not_set_a_public_commits_mode() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        let tmp = tmp_path(&path);
        std::fs::write(&tmp, b"planted").unwrap();
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o666)).unwrap();

        commit(&path, b"committed").unwrap();

        assert_eq!(std::fs::read(&path).unwrap(), b"committed");
        assert_eq!(mode_of(&path) & 0o022, 0, "not group- or world-writable");
    }

    /// A symlink at the staging path. `open` would follow it and `write_all`
    /// would put the secret in the file it points at; the rename afterwards
    /// moves the *link*, so the commit looks entirely successful.
    #[cfg(unix)]
    #[test]
    fn a_symlink_at_the_staging_path_is_not_written_through() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secrets.json");
        let victim = dir.path().join("victim.txt");
        std::fs::write(&victim, b"victim").unwrap();
        std::os::unix::fs::symlink(&victim, tmp_path(&path)).unwrap();

        commit_private(&path, SECRET).unwrap();

        assert_eq!(
            std::fs::read(&victim).unwrap(),
            b"victim",
            "the secret was written through the symlink"
        );
        assert_eq!(std::fs::read(&path).unwrap(), SECRET);
        assert_eq!(mode_of(&path), 0o600);
        assert!(
            std::fs::symlink_metadata(tmp_path(&path)).is_err(),
            "the symlink was unlinked, not followed"
        );
    }

    /// A symlink at the *live* path. The commit must replace the link itself
    /// — `rename(2)` never follows its destination — and must not have gone
    /// looking through it to make a backup on the way.
    #[cfg(unix)]
    #[test]
    fn a_symlink_at_the_live_path_is_replaced_rather_than_written_through() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secrets.json");
        let victim = dir.path().join("victim.txt");
        std::fs::write(&victim, b"victim").unwrap();
        std::os::unix::fs::symlink(&victim, &path).unwrap();

        commit_private(&path, SECRET).unwrap();

        assert_eq!(std::fs::read(&victim).unwrap(), b"victim", "the victim was overwritten");
        let meta = std::fs::symlink_metadata(&path).unwrap();
        assert!(meta.file_type().is_file(), "the link was replaced by a real file");
        assert_eq!(std::fs::read(&path).unwrap(), SECRET);
        assert_eq!(mode_of(&path), 0o600);
        // And nothing followed the link on the way past: hard-linking the
        // "previous value" would have made the victim's inode reachable as
        // this device's last-known-good state.
        let bak = backup_path(&path);
        if bak.exists() {
            assert_ne!(std::fs::read(&bak).unwrap(), b"victim", "the backup is the victim");
        }
    }

    /// A symlink at the backup path. The last-known-good copy is made by
    /// unlinking whatever is there and linking afresh, so this ends up as a
    /// real file and the victim is untouched.
    #[cfg(unix)]
    #[test]
    fn a_symlink_at_the_backup_path_is_not_written_through() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secrets.json");
        let victim = dir.path().join("victim.txt");
        std::fs::write(&victim, b"victim").unwrap();

        commit_private(&path, b"first").unwrap();
        std::os::unix::fs::symlink(&victim, backup_path(&path)).unwrap();
        commit_private(&path, SECRET).unwrap();

        assert_eq!(std::fs::read(&victim).unwrap(), b"victim", "the victim was overwritten");
        let bak = backup_path(&path);
        assert!(std::fs::symlink_metadata(&bak).unwrap().file_type().is_file());
        assert_eq!(std::fs::read(&bak).unwrap(), b"first");
        assert_eq!(mode_of(&bak), 0o600, "a private file's backup is private too");
    }

    /// A directory at the staging path cannot be cleared, and must be a
    /// refusal rather than a loop.
    #[test]
    fn a_directory_at_the_staging_path_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        std::fs::create_dir_all(tmp_path(&path)).unwrap();
        let err = commit(&path, b"committed").unwrap_err();
        assert!(format!("{err:#}").contains("staging"), "{err:#}");
        assert!(!path.exists(), "and nothing was published");
    }

    /// The other side of clearing an occupied staging path: the leftover of
    /// an interrupted commit must not block the retry. This is the same
    /// requirement as `a_crash_before_the_rename_converges_on_the_old_value`,
    /// asserted without the sweep — a daemon that crashed and came back has
    /// to be able to commit before it next sweeps anything.
    #[test]
    fn the_leftover_of_an_interrupted_commit_does_not_block_the_next_one() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        commit(&path, b"first").unwrap();

        let armed =
            faults::arm("leftover", Point::Rename, "state.json", io::ErrorKind::Other);
        assert!(commit(&path, b"second").is_err());
        drop(armed);
        assert!(tmp_path(&path).exists(), "the interrupted commit left its staging file");

        // No sweep in between: the commit clears it itself.
        commit(&path, b"third").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"third");
        assert!(!tmp_path(&path).exists());
    }

    /// Publishing bytes somebody else built has the same rule: a symlink at
    /// the staging name is not the staging file.
    #[cfg(unix)]
    #[test]
    fn a_symlinked_part_is_not_published() {
        let dir = tempfile::tempdir().unwrap();
        let victim = dir.path().join("victim.raw");
        std::fs::write(&victim, b"victim").unwrap();
        let part = dir.path().join("image.raw.part");
        std::os::unix::fs::symlink(&victim, &part).unwrap();
        let dest = dir.path().join("image.raw");

        assert!(publish_file(&part, &dest).is_err());
        assert!(!dest.exists(), "a symlink was not published as the image");
        assert_eq!(std::fs::read(&victim).unwrap(), b"victim");
    }

    #[test]
    fn publishing_a_staged_file_leaves_no_part_behind() {
        let dir = tempfile::tempdir().unwrap();
        let part = dir.path().join("image.raw.part");
        let dest = dir.path().join("image.raw");
        std::fs::write(&part, b"bytes").unwrap();
        publish_file(&part, &dest).unwrap();
        assert!(!part.exists());
        assert_eq!(std::fs::read(&dest).unwrap(), b"bytes");
    }

    #[test]
    fn publishing_a_staged_directory_moves_the_whole_tree() {
        let dir = tempfile::tempdir().unwrap();
        let staging = dir.path().join("dev.moving.7");
        std::fs::create_dir_all(staging.join("nested")).unwrap();
        std::fs::write(staging.join("disk.raw"), b"disk").unwrap();
        std::fs::write(staging.join("nested/seed.iso"), b"seed").unwrap();
        let live = dir.path().join("dev");
        publish_dir(&staging, &live).unwrap();
        assert!(!staging.exists());
        assert_eq!(std::fs::read(live.join("nested/seed.iso")).unwrap(), b"seed");
    }

    /// A rename that fails while adopting a staged tree leaves the tree
    /// staged and complete — the move can be retried or abandoned.
    #[test]
    fn a_failed_adoption_leaves_the_staging_tree_intact() {
        let dir = tempfile::tempdir().unwrap();
        let staging = dir.path().join("adopt.moving.1");
        std::fs::create_dir_all(&staging).unwrap();
        std::fs::write(staging.join("disk.raw"), b"disk").unwrap();
        let live = dir.path().join("adopt");

        let armed = faults::arm("adopt", Point::Rename, "adopt", io::ErrorKind::Other);
        assert!(publish_dir(&staging, &live).is_err());
        drop(armed);

        assert!(!live.exists(), "nothing was published");
        assert_eq!(std::fs::read(staging.join("disk.raw")).unwrap(), b"disk");
    }

    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct Envelope {
        version: u32,
        n: u32,
    }

    /// A file from a newer Asterism is a refusal, and specifically *not* a
    /// repair: quietly reverting to a backup this build can read would
    /// discard whatever the newer one recorded.
    #[test]
    fn a_document_from_the_future_is_refused_rather_than_repaired() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("doc.json");
        commit_json(&path, &Envelope { version: 1, n: 1 }).unwrap();
        commit_json(&path, &Envelope { version: 9, n: 2 }).unwrap();

        let err = load_json_versioned::<Envelope>(&path, "a document", 1).unwrap_err();
        let text = format!("{err:#}");
        assert!(text.contains("version 9"), "{text}");
        assert!(text.contains("upgrade Asterism"), "{text}");
        assert!(backup_path(&path).exists(), "and the backup is left where it was");
    }

    /// A backup from the future is no better than a live file from the
    /// future, so an unreadable live file does not get repaired from one.
    #[test]
    fn a_backup_from_the_future_is_not_used_as_a_repair() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("doc.json");
        commit_json(&path, &Envelope { version: 9, n: 1 }).unwrap();
        commit_json(&path, &Envelope { version: 1, n: 2 }).unwrap();
        std::fs::write(&path, b"{ torn").unwrap();

        let err = load_json_versioned::<Envelope>(&path, "a document", 1).unwrap_err();
        assert!(format!("{err:#}").contains("will not guess"), "{err:#}");
    }

    /// The pre-envelope format has no `version` field at all, and is handed
    /// to the caller to migrate rather than refused.
    #[test]
    fn a_document_written_before_versions_existed_still_reads() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("doc.json");
        std::fs::write(&path, br#"{"n":4}"#).unwrap();
        let loaded: Loaded<Doc> = load_json_versioned(&path, "a document", 1).unwrap().unwrap();
        assert_eq!(loaded.value, Doc { n: 4 });
    }

    /// The sweep is for staging files only. Deleting a `.bak` would throw
    /// away the safety net at exactly the moment it is most likely to be
    /// needed — the boot after a crash.
    #[test]
    fn the_sweep_leaves_the_backups_and_the_live_files() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("doc.json");
        commit_json(&path, &Doc { n: 1 }).unwrap();
        commit_json(&path, &Doc { n: 2 }).unwrap();
        std::fs::write(tmp_path(&path), b"half a value").unwrap();

        let swept = sweep_temporaries(dir.path());
        assert_eq!(swept, vec![tmp_path(&path)]);
        assert!(path.exists());
        assert!(backup_path(&path).exists());
    }
}
