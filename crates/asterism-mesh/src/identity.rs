//! The device's long-lived identity.
//!
//! Every Asterism device owns exactly one Ed25519 keypair, generated the first
//! time the daemon starts and never rotated in place — rotating it would make
//! the device a stranger to every peer that has already paired with it. The
//! public half is the device's identity on the mesh: iroh dials peers by public
//! key, and `orbit.json` records the keys an orbit trusts.
//!
//! The key is iroh's native [`SecretKey`], which is an Ed25519 signing key, so
//! there is no conversion step between "our" identity and the one QUIC
//! authenticates with. They are the same key, and a connection's peer key is
//! therefore directly comparable against the trusted set.

use std::fmt;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use iroh::{PublicKey, SecretKey, Signature};

/// Magic line prefix for the on-disk key file, so a stray file is never
/// mistaken for a key and a future format change is detectable.
const KEY_FILE_MAGIC: &str = "asterism-device-key/1";

/// Makes temporary key paths distinct across threads in one process.  The
/// process id and current time in [`temp_path`] distinguish restarts.
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// The file mode a private key must have: readable and writable by its owner,
/// invisible to everyone else.
#[cfg(unix)]
const KEY_FILE_MODE: u32 = 0o600;

/// A device's stable public identity, derived from its public key.
///
/// This is what `ast devices` prints and what `orbit.json` stores. It is a
/// newtype over the Ed25519 public key rather than a hash of it: iroh needs the
/// key itself to dial, so hashing would only mean carrying both.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DeviceId(PublicKey);

impl DeviceId {
    /// Derives the device id from a public key.
    pub fn from_public_key(key: PublicKey) -> Self {
        Self(key)
    }

    /// The underlying public key, as iroh's endpoint identifier.
    pub fn public_key(&self) -> PublicKey {
        self.0
    }

    /// The raw 32 bytes of the public key.
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }

    /// A short, human-quotable form: the first 12 characters of the full id.
    ///
    /// Long enough to be unambiguous in an orbit of a few dozen devices, short
    /// enough to fit in a table. Never use it for a trust decision.
    pub fn short(&self) -> String {
        self.to_string().chars().take(12).collect()
    }

    /// Verifies a proof made by this device's private key.  Hosted services
    /// use this only to bind an account enrollment to the key the mesh will
    /// authenticate later; it grants no trust inside an orbit.
    pub fn verify(&self, message: &[u8], signature: &Signature) -> bool {
        self.0.verify(message, signature).is_ok()
    }
}

impl fmt::Display for DeviceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // iroh's `PublicKey: Display` is lowercase hex, and its `FromStr`
        // accepts both that and base32, so this round-trips.
        fmt::Display::fmt(&self.0, f)
    }
}

impl From<PublicKey> for DeviceId {
    fn from(key: PublicKey) -> Self {
        Self(key)
    }
}

impl From<DeviceId> for PublicKey {
    fn from(id: DeviceId) -> Self {
        id.0
    }
}

/// Something went wrong loading or storing the device key.
#[derive(Debug)]
pub enum IdentityError {
    /// The key file could not be read or written.
    Io(io::Error),
    /// The key file exists but is not in the expected format.
    Malformed(&'static str),
    /// The key file is readable by users other than its owner.
    ///
    /// Refusing here rather than silently continuing is deliberate: a private
    /// key that leaked into a group-readable directory should stop the daemon,
    /// not be used with a warning nobody reads.
    Permissions {
        /// Where the offending key lives.
        path: PathBuf,
        /// The mode it was found with.
        mode: u32,
    },
}

impl fmt::Display for IdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "device key i/o failed: {e}"),
            Self::Malformed(why) => write!(f, "device key file is malformed: {why}"),
            Self::Permissions { path, mode } => write!(
                f,
                "device key {} is mode {:04o}; it must be {:04o} (run: chmod 600 {})",
                path.display(),
                mode,
                0o600,
                path.display()
            ),
        }
    }
}

impl std::error::Error for IdentityError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for IdentityError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

/// A device's keypair: its identity on the mesh.
#[derive(Debug, Clone)]
pub struct DeviceIdentity {
    secret: SecretKey,
}

impl DeviceIdentity {
    /// Generates a fresh identity from the operating system's RNG.
    ///
    /// Only useful on its own for tests; real devices go through
    /// [`DeviceIdentity::load_or_create`] so the key survives a restart.
    pub fn generate() -> Self {
        Self {
            secret: SecretKey::generate(),
        }
    }

    /// Wraps an existing secret key.
    pub fn from_secret_key(secret: SecretKey) -> Self {
        Self { secret }
    }

    /// Signs a short-lived, domain-separated enrollment challenge.
    ///
    /// This deliberately exposes signing rather than the private key: an
    /// optional coordinator can prove possession of a device identity without
    /// becoming part of the mesh's trust or pairing path.
    pub fn sign(&self, message: &[u8]) -> Signature {
        self.secret.sign(message)
    }

    /// Loads the device key from `path`, generating and persisting one if the
    /// file does not exist yet.
    ///
    /// This is the call a daemon makes at startup. Parent directories are
    /// created as needed; the key file is written with mode `0600` and an
    /// existing file is rejected if its mode is looser than that.
    pub fn load_or_create(path: impl AsRef<Path>) -> Result<Self, IdentityError> {
        let path = path.as_ref();
        match Self::load(path) {
            Ok(identity) => Ok(identity),
            Err(IdentityError::Io(e)) if e.kind() == io::ErrorKind::NotFound => {
                let identity = Self::generate();
                match identity.install_new(path) {
                    Ok(()) => Ok(identity),
                    // Another daemon won the first-start race.  Its key is the
                    // identity now, and every contender must return it rather
                    // than overwrite it with a different one.
                    Err(IdentityError::Io(e)) if e.kind() == io::ErrorKind::AlreadyExists => {
                        Self::load(path)
                    }
                    Err(e) => Err(e),
                }
            }
            Err(e) => Err(e),
        }
    }

    /// Loads the device key from `path`.
    ///
    /// Fails with [`IdentityError::Permissions`] if the file is accessible to
    /// anyone but its owner.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, IdentityError> {
        let path = path.as_ref();
        let contents = std::fs::read_to_string(path)?;
        check_permissions(path)?;

        let line = contents
            .lines()
            .map(str::trim)
            .find(|line| !line.is_empty() && !line.starts_with('#'))
            .ok_or(IdentityError::Malformed("file is empty"))?;

        let encoded = line
            .strip_prefix(KEY_FILE_MAGIC)
            .ok_or(IdentityError::Malformed(
                "missing the asterism-device-key/1 header",
            ))?
            .trim();

        let bytes = data_encoding::HEXLOWER_PERMISSIVE
            .decode(encoded.as_bytes())
            .map_err(|_| IdentityError::Malformed("key is not valid hex"))?;
        let bytes: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| IdentityError::Malformed("key is not 32 bytes"))?;

        Ok(Self {
            secret: SecretKey::from_bytes(&bytes),
        })
    }

    /// Writes the device key to `path` with mode `0600`.
    ///
    /// The write goes to a temporary file in the same directory and is then
    /// renamed over the destination, so a crash mid-write can never leave a
    /// half-written key where a whole one used to be. The temporary file is
    /// created `0600` from the start — never briefly world-readable.
    pub fn save(&self, path: impl AsRef<Path>) -> Result<(), IdentityError> {
        let path = path.as_ref();
        create_parent(path)?;

        let tmp = temp_path(path);
        write_private(&tmp, self.body().as_bytes())?;
        match std::fs::rename(&tmp, path) {
            // The rename is a change to the *directory*, and until the
            // directory is flushed it is a promise the drive has not made.
            // This device's identity is the one file it cannot regenerate —
            // losing it is losing every pairing — so the barrier is paid.
            Ok(()) => sync_dir(match path.parent() {
                Some(parent) if !parent.as_os_str().is_empty() => parent,
                _ => Path::new("."),
            }),
            Err(e) => {
                let _ = std::fs::remove_file(&tmp);
                Err(e.into())
            }
        }
    }

    /// Installs a first identity without ever replacing another process's
    /// winner.  A hard link is the portable no-clobber publish primitive:
    /// both names are in one directory, and creating the destination fails
    /// atomically when it already exists.
    fn install_new(&self, path: &Path) -> Result<(), IdentityError> {
        create_parent(path)?;
        let tmp = temp_path(path);
        write_private(&tmp, self.body().as_bytes())?;
        match std::fs::hard_link(&tmp, path) {
            Ok(()) => {
                std::fs::remove_file(&tmp)?;
                sync_dir(parent_dir(path))
            }
            Err(e) => {
                let _ = std::fs::remove_file(&tmp);
                Err(e.into())
            }
        }
    }

    fn body(&self) -> String {
        format!(
            "# Asterism device key. Anyone who reads this file can impersonate this device.\n\
             {KEY_FILE_MAGIC} {}\n",
            data_encoding::HEXLOWER.encode(&self.secret.to_bytes()),
        )
    }

    /// The secret key, for binding an iroh endpoint.
    pub fn secret_key(&self) -> &SecretKey {
        &self.secret
    }

    /// The public key.
    pub fn public_key(&self) -> PublicKey {
        self.secret.public()
    }

    /// This device's stable id.
    pub fn device_id(&self) -> DeviceId {
        DeviceId(self.secret.public())
    }
}

/// Flush a directory's entries, so a rename into it survives power loss.
///
/// A filesystem that refuses `fsync` on a directory (some network mounts,
/// most container fakes) is not a reason to refuse to save a key: the rename
/// is still ordered, it is only the barrier that is missing.
fn sync_dir(dir: &Path) -> Result<(), IdentityError> {
    match std::fs::File::open(dir).and_then(|handle| handle.sync_all()) {
        Ok(()) => Ok(()),
        Err(e)
            if matches!(
                e.kind(),
                io::ErrorKind::InvalidInput | io::ErrorKind::Unsupported
            ) =>
        {
            Ok(())
        }
        Err(e) => Err(e.into()),
    }
}

/// Builds the sibling temporary path used for the atomic save.
fn temp_path(path: &Path) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    name.push(format!(".tmp.{}.{nanos}.{sequence}", std::process::id()));
    path.with_file_name(name)
}

fn create_parent(path: &Path) -> Result<(), IdentityError> {
    let parent = parent_dir(path);
    if parent != Path::new(".") {
        std::fs::create_dir_all(parent)?;
    }
    Ok(())
}

fn parent_dir(path: &Path) -> &Path {
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    }
}

#[cfg(unix)]
fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(KEY_FILE_MODE)
        .open(path)?;
    file.write_all(bytes)?;
    // An existing file keeps its old mode, so set it explicitly too.
    file.set_permissions(std::os::unix::fs::PermissionsExt::from_mode(KEY_FILE_MODE))?;
    file.sync_all()
}

#[cfg(not(unix))]
fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    use std::io::Write;

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

#[cfg(unix)]
fn check_permissions(path: &Path) -> Result<(), IdentityError> {
    use std::os::unix::fs::PermissionsExt;

    let mode = std::fs::metadata(path)?.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(IdentityError::Permissions {
            path: path.to_path_buf(),
            mode,
        });
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_permissions(_path: &Path) -> Result<(), IdentityError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_identity_has_matching_public_key_and_device_id() {
        let identity = DeviceIdentity::generate();
        assert_eq!(identity.device_id().public_key(), identity.public_key());
        assert_eq!(
            identity.device_id().as_bytes(),
            identity.public_key().as_bytes()
        );
    }

    #[test]
    fn device_id_round_trips_through_its_string_form() {
        let id = DeviceIdentity::generate().device_id();
        let parsed: PublicKey = id.to_string().parse().expect("device id should parse back");
        assert_eq!(DeviceId::from_public_key(parsed), id);
        assert_eq!(id.short().len(), 12);
        assert!(id.to_string().starts_with(&id.short()));
    }

    #[test]
    fn load_or_create_generates_once_and_is_stable_afterwards() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("device.key");

        let first = DeviceIdentity::load_or_create(&path).unwrap();
        assert!(path.exists(), "the key should have been persisted");

        let second = DeviceIdentity::load_or_create(&path).unwrap();
        assert_eq!(
            first.device_id(),
            second.device_id(),
            "reloading must not mint a new identity"
        );
        assert_eq!(
            first.secret_key().to_bytes(),
            second.secret_key().to_bytes()
        );
    }

    #[test]
    fn concurrent_first_start_installs_one_identity_without_rotation() {
        use std::sync::{Arc, Barrier};

        const STARTERS: usize = 8;
        let dir = tempfile::tempdir().unwrap();
        let path = Arc::new(dir.path().join("device.key"));
        let barrier = Arc::new(Barrier::new(STARTERS));
        let mut threads = Vec::new();
        for _ in 0..STARTERS {
            let path = Arc::clone(&path);
            let barrier = Arc::clone(&barrier);
            threads.push(std::thread::spawn(move || {
                barrier.wait();
                DeviceIdentity::load_or_create(path.as_path())
                    .unwrap()
                    .device_id()
            }));
        }

        let ids: Vec<_> = threads
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .collect();
        assert!(ids.iter().all(|id| *id == ids[0]));
        assert_eq!(DeviceIdentity::load(&*path).unwrap().device_id(), ids[0]);
    }

    #[cfg(unix)]
    #[test]
    fn persisted_key_is_mode_0600() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("device.key");
        DeviceIdentity::load_or_create(&path).unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "found mode {mode:04o}");
    }

    #[cfg(unix)]
    #[test]
    fn a_world_readable_key_is_refused() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("device.key");
        DeviceIdentity::generate().save(&path).unwrap();

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        match DeviceIdentity::load(&path) {
            Err(IdentityError::Permissions { mode, .. }) => assert_eq!(mode, 0o644),
            other => panic!("expected a permissions error, got {other:?}"),
        }
    }

    #[test]
    fn a_malformed_key_file_is_refused_rather_than_reinitialised() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("device.key");
        std::fs::write(&path, "not a key\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }

        assert!(
            matches!(
                DeviceIdentity::load_or_create(&path),
                Err(IdentityError::Malformed(_))
            ),
            "a corrupt key must not be silently replaced"
        );
    }

    #[test]
    fn saving_leaves_no_temporary_file_behind() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("device.key");
        DeviceIdentity::generate().save(&path).unwrap();

        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(Result::ok)
            .map(|e| e.file_name())
            .filter(|name| name.to_string_lossy().contains(".tmp."))
            .collect();
        assert!(leftovers.is_empty(), "stray temp files: {leftovers:?}");
    }
}
