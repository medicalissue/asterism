//! The optional hosted coordination plane.
//!
//! This crate is intentionally not part of the orbit data path.  An orbit is
//! paired and authorised by device keys locally; the hosted plane only gives a
//! signed-in person a place to register those public keys and discover a
//! chosen relay/directory configuration.  Its absence therefore cannot turn
//! an already-paired orbit off.
//!
//! There is no local credential model here: no email address, password, reset
//! token, or magic link.  The only accepted identities are verified Google and
//! GitHub OAuth subjects.  The store receives an opaque, domain-separated hash
//! of that subject, never the provider token, display name, or email address.

pub mod production;

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(test)]
use std::sync::atomic::{AtomicUsize, Ordering};
#[cfg(test)]
use std::sync::Arc;

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use anyhow::{anyhow, bail, Context, Result};
use asterism_mesh::iroh_types::Signature;
use asterism_mesh::{DeviceId, MeshInfra};
use data_encoding::BASE64URL_NOPAD;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

const ENROLLMENT_DOMAIN: &[u8] = b"asterism.coordinator/enroll/1\0";
const IDENTITY_DOMAIN: &[u8] = b"asterism.coordinator/account/1\0";
const ENROLLMENT_CHALLENGE_TTL_SECS: u64 = 10 * 60;
const MAX_ENROLLMENT_CHALLENGES_PER_ACCOUNT: usize = 32;
const MAX_DEVICES_PER_ACCOUNT: usize = 64;
const MAX_DISCOVERY_BYTES: usize = 4 * 1024;
const MAX_ACCOUNTS: usize = 4_096;
const MAX_DURABLE_STATE_BYTES: usize = 16 * 1024 * 1024;

/// OAuth authorities the hosted product supports.  This enum is deliberately
/// closed: adding any authentication surface requires a source change and a
/// review, rather than an environment setting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OAuthProvider {
    /// Google OpenID Connect.
    Google,
    /// GitHub OAuth.
    GitHub,
}

impl OAuthProvider {
    fn issuer(self) -> &'static str {
        match self {
            Self::Google => "https://accounts.google.com",
            Self::GitHub => "https://github.com",
        }
    }
}

/// Claims produced only after the provider has verified an OAuth callback.
/// `subject` is provider-stable but is never persisted in this form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedOAuth {
    /// Which allow-listed provider produced the identity.
    pub provider: OAuthProvider,
    /// The issuer from the signed ID token or provider API.
    pub issuer: String,
    /// Provider subject, not an email/login/display name.
    pub subject: String,
}

/// Boundary implemented by the HTTP OAuth callback adapter.  Keeping provider
/// token exchange outside the state machine makes the persistence and privacy
/// guarantees testable without accepting arbitrary bearer tokens here.
pub trait OAuthVerifier {
    /// Exchanges and verifies an authorization code at an allow-listed OAuth
    /// provider.  Implementations must validate redirect URI, state, PKCE and
    /// issuer before returning claims.
    fn verify_authorization_code(&self, code: &str) -> Result<VerifiedOAuth>;
}

/// Opaque account identifier persisted by the hosted service.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AccountId(String);

impl AccountId {
    /// A stable opaque identifier.  It is safe to show only to the account's
    /// authenticated session; it cannot be reversed into an OAuth subject.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The discovery infrastructure a user deliberately selects for an account.
/// These are public routing endpoints, never an orbit name, member list,
/// instance metadata, or secret.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoveryConfig {
    /// Relay URLs to hand to enrolled devices.
    #[serde(default)]
    pub relays: Vec<String>,
    /// Optional pkarr publish/resolve endpoint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pkarr_relay: Option<String>,
    /// Optional DNS origin used for lookup.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns_origin: Option<String>,
}

impl DiscoveryConfig {
    /// Converts hosted configuration to the existing, optional mesh seam.  A
    /// device keeps this last successful value locally, so an outage means no
    /// config refresh—not lost pairing, ACLs, or existing connections.
    pub fn mesh_infra(&self) -> MeshInfra {
        MeshInfra {
            relays: self.relays.clone(),
            pkarr_relay: self.pkarr_relay.clone(),
            dns_origin: self.dns_origin.clone(),
        }
    }

    fn validate(&self) -> Result<()> {
        if serde_json::to_vec(self)?.len() > MAX_DISCOVERY_BYTES {
            bail!("discovery configuration exceeds {MAX_DISCOVERY_BYTES} bytes");
        }
        for endpoint in self
            .relays
            .iter()
            .chain(self.pkarr_relay.iter())
            .chain(self.dns_origin.iter())
        {
            let endpoint = endpoint.trim();
            if endpoint.is_empty() || endpoint.contains(char::is_whitespace) {
                bail!("discovery endpoints must be non-empty URLs without whitespace");
            }
            if !endpoint.starts_with("https://") {
                bail!("discovery endpoint {endpoint:?} must use https");
            }
        }
        Ok(())
    }
}

/// A public device key enrolled to an account.  There is deliberately no
/// device name or arbitrary client metadata: those belong to the local orbit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrolledDevice {
    /// Asterism mesh public key.
    pub device_id: String,
    /// Account-selected routing configuration, which may be copied locally.
    pub discovery: DiscoveryConfig,
}

/// A challenge issued by the service before enrollment.  It is single-use and
/// proves the account session controls the Ed25519 device key it is binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrollmentChallenge {
    bytes: [u8; 32],
}

impl EnrollmentChallenge {
    /// Opaque wire representation for a one-time enrollment challenge.
    pub fn token(&self) -> String {
        BASE64URL_NOPAD.encode(&self.bytes)
    }

    fn from_token(value: &str) -> Result<Self> {
        let bytes = BASE64URL_NOPAD
            .decode(value.as_bytes())
            .context("decoding enrollment challenge")?;
        let bytes: [u8; 32] = bytes
            .try_into()
            .map_err(|_| anyhow!("enrollment challenge has invalid length"))?;
        Ok(Self { bytes })
    }
}

/// Signed response to an [`EnrollmentChallenge`].
#[derive(Debug, Clone)]
pub struct EnrollmentProof {
    /// The public device identity to bind.
    pub device_id: DeviceId,
    /// The service-issued challenge.
    pub challenge: EnrollmentChallenge,
    /// Ed25519 signature over the domain-separated challenge.
    pub signature: Signature,
}

impl EnrollmentProof {
    /// Parses a JSON API proof without exposing arbitrary signing internals.
    pub fn from_tokens(device_id: &str, challenge: &str, signature: &str) -> Result<Self> {
        use std::str::FromStr;
        let public_key = asterism_mesh::iroh_types::PublicKey::from_str(device_id)
            .map_err(|_| anyhow!("invalid device id"))?;
        let signature = BASE64URL_NOPAD
            .decode(signature.as_bytes())
            .context("decoding enrollment signature")?;
        let signature: [u8; Signature::LENGTH] = signature
            .try_into()
            .map_err(|_| anyhow!("invalid enrollment signature"))?;
        Ok(Self {
            device_id: DeviceId::from_public_key(public_key),
            challenge: EnrollmentChallenge::from_token(challenge)?,
            signature: Signature::from_bytes(&signature),
        })
    }
}

/// Parses the mesh public key form accepted by authenticated device APIs.
pub fn parse_device_id(value: &str) -> Result<DeviceId> {
    use std::str::FromStr;
    let key = asterism_mesh::iroh_types::PublicKey::from_str(value)
        .map_err(|_| anyhow!("invalid device id"))?;
    Ok(DeviceId::from_public_key(key))
}

/// Minimal, portable account export.  OAuth identity and access tokens are
/// intentionally not exportable because this service never stores them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountExport {
    /// Opaque account identifier.
    pub account_id: AccountId,
    /// Public device keys and discovery configuration only.
    pub devices: Vec<EnrolledDevice>,
}

#[derive(Debug, Default, Clone)]
struct Account {
    devices: BTreeMap<String, EnrolledDevice>,
    challenges: BTreeMap<[u8; 32], u64>,
}

/// In-memory coordinator state.  A production HTTP adapter serializes only
/// [`AccountExport`] with [`EncryptedMetadata`]; OAuth callbacks/tokens and
/// plaintext provider subjects must never be put in this structure or log.
#[derive(Debug, Clone)]
pub struct Coordinator {
    accounts: BTreeMap<AccountId, Account>,
    account_id_key: [u8; 32],
    sequence: u64,
    last_transaction: Option<String>,
}

#[cfg(test)]
impl Default for Coordinator {
    fn default() -> Self {
        // Test-only default. A hosted service must call `new` with a KMS
        // managed secret; an unkeyed identifier is deliberately impossible.
        Self::new([0; 32])
    }
}

impl Coordinator {
    /// Creates a coordinator with the secret used to make opaque account ids.
    /// This key must be supplied by a KMS/secret manager and rotated with a
    /// migration, never derived from an OAuth subject.
    pub fn new(account_id_key: [u8; 32]) -> Self {
        Self {
            accounts: BTreeMap::new(),
            account_id_key,
            sequence: 0,
            last_transaction: None,
        }
    }
    /// Signs in using a verified OAuth authorization code.  A provider or
    /// issuer mismatch is refused before any account record is created.
    pub fn sign_in(&mut self, verifier: &impl OAuthVerifier, code: &str) -> Result<AccountId> {
        if code.trim().is_empty() {
            bail!("OAuth authorization code is empty");
        }
        let claims = verifier.verify_authorization_code(code)?;
        self.sign_in_claims(claims)
    }

    /// Records already-validated OAuth claims.  The production HTTP adapter
    /// calls this only after its provider-specific code exchange completes.
    pub fn sign_in_claims(&mut self, claims: VerifiedOAuth) -> Result<AccountId> {
        if claims.issuer != claims.provider.issuer() {
            bail!("OAuth issuer does not match the selected provider");
        }
        if claims.subject.trim().is_empty() {
            bail!("OAuth subject is empty");
        }
        let account_id = account_id(&self.account_id_key, &claims);
        if !self.accounts.contains_key(&account_id) && self.accounts.len() >= MAX_ACCOUNTS {
            bail!("coordinator account capacity reached");
        }
        self.accounts.entry(account_id.clone()).or_default();
        Ok(account_id)
    }

    /// Starts a single-use account-bound enrollment.
    pub fn begin_enrollment(&mut self, account_id: &AccountId) -> Result<EnrollmentChallenge> {
        self.begin_enrollment_at(account_id, unix_seconds()?)
    }

    /// Deterministic-clock variant used by lifecycle tests and production
    /// adapters that own an authoritative clock.
    pub fn begin_enrollment_at(
        &mut self,
        account_id: &AccountId,
        now: u64,
    ) -> Result<EnrollmentChallenge> {
        let account = self.account_mut(account_id)?;
        account.challenges.retain(|_, expiry| *expiry > now);
        if account.challenges.len() >= MAX_ENROLLMENT_CHALLENGES_PER_ACCOUNT {
            bail!("too many enrollment challenges are active");
        }
        loop {
            let challenge = EnrollmentChallenge { bytes: random_32() };
            if account
                .challenges
                .insert(challenge.bytes, now + ENROLLMENT_CHALLENGE_TTL_SECS)
                .is_none()
            {
                return Ok(challenge);
            }
        }
    }

    /// Binds a device key after it proves possession of its private half.
    pub fn enroll(
        &mut self,
        account_id: &AccountId,
        proof: EnrollmentProof,
        discovery: DiscoveryConfig,
    ) -> Result<EnrolledDevice> {
        self.enroll_at(account_id, proof, discovery, unix_seconds()?)
    }

    /// Deterministic-clock variant that rejects expired challenges before any
    /// device mutation.
    pub fn enroll_at(
        &mut self,
        account_id: &AccountId,
        proof: EnrollmentProof,
        discovery: DiscoveryConfig,
        now: u64,
    ) -> Result<EnrolledDevice> {
        discovery.validate()?;
        let account = self.account_mut(account_id)?;
        account.challenges.retain(|_, expiry| *expiry > now);
        if !account.challenges.contains_key(&proof.challenge.bytes) {
            bail!("enrollment challenge is unknown, expired, or already used");
        }
        if !proof
            .device_id
            .verify(&enrollment_message(&proof.challenge), &proof.signature)
        {
            bail!("device enrollment proof is invalid");
        }
        let device_key = proof.device_id.to_string();
        if !account.devices.contains_key(&device_key)
            && account.devices.len() >= MAX_DEVICES_PER_ACCOUNT
        {
            bail!("account device capacity reached");
        }
        account.challenges.remove(&proof.challenge.bytes);
        let device = EnrolledDevice {
            device_id: device_key,
            discovery,
        };
        account
            .devices
            .insert(device.device_id.clone(), device.clone());
        Ok(device)
    }

    /// Revokes a device's hosted configuration and prevents future discovery
    /// refreshes.  It does not alter the local orbit ACL; local removal is an
    /// explicit, peer-signed operation that works while this service is down.
    pub fn revoke_device(&mut self, account_id: &AccountId, device_id: &DeviceId) -> Result<()> {
        let removed = self
            .account_mut(account_id)?
            .devices
            .remove(&device_id.to_string());
        if removed.is_none() {
            bail!("device is not enrolled to this account");
        }
        Ok(())
    }

    /// Retrieves only the selected discovery configuration for an enrolled
    /// device.  A coordinator outage naturally leaves the caller with its
    /// persisted last configuration and a fully independent orbit.
    pub fn discovery_for(
        &self,
        account_id: &AccountId,
        device_id: &DeviceId,
    ) -> Result<DiscoveryConfig> {
        self.accounts
            .get(account_id)
            .and_then(|a| a.devices.get(&device_id.to_string()))
            .map(|d| d.discovery.clone())
            .ok_or_else(|| anyhow!("device is not enrolled to this account"))
    }

    /// Exports the account's minimal hosted metadata.
    pub fn export_account(&self, account_id: &AccountId) -> Result<AccountExport> {
        let account = self
            .accounts
            .get(account_id)
            .ok_or_else(|| anyhow!("account not found"))?;
        Ok(AccountExport {
            account_id: account_id.clone(),
            devices: account.devices.values().cloned().collect(),
        })
    }

    /// Deletes the account and all hosted device configuration.  It cannot
    /// delete a device key, an orbit, or data held by an already-paired peer.
    pub fn delete_account(&mut self, account_id: &AccountId) -> Result<()> {
        self.accounts
            .remove(account_id)
            .map(|_| ())
            .ok_or_else(|| anyhow!("account not found"))
    }

    fn account_mut(&mut self, account_id: &AccountId) -> Result<&mut Account> {
        self.accounts
            .get_mut(account_id)
            .ok_or_else(|| anyhow!("account not found"))
    }

    fn durable(&self) -> DurableCoordinator {
        DurableCoordinator {
            sequence: self.sequence,
            last_transaction: self.last_transaction.clone(),
            accounts: self
                .accounts
                .iter()
                .map(|(id, account)| {
                    (
                        id.clone(),
                        DurableAccount {
                            devices: account.devices.clone(),
                        },
                    )
                })
                .collect(),
        }
    }

    fn from_durable(account_id_key: [u8; 32], state: DurableCoordinator) -> Self {
        Self {
            sequence: state.sequence,
            last_transaction: state.last_transaction,
            accounts: state
                .accounts
                .into_iter()
                .map(|(id, account)| {
                    (
                        id,
                        Account {
                            devices: account.devices,
                            challenges: BTreeMap::new(),
                        },
                    )
                })
                .collect(),
            account_id_key,
        }
    }
}

#[derive(Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
struct DurableCoordinator {
    #[serde(default)]
    sequence: u64,
    #[serde(default)]
    last_transaction: Option<String>,
    accounts: BTreeMap<AccountId, DurableAccount>,
}

#[derive(Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
struct DurableAccount {
    devices: BTreeMap<String, EnrolledDevice>,
}

/// A named encryption key supplied by a deployment KMS adapter.  The version
/// is persisted beside the ciphertext, allowing a new active key to write
/// forward while old versions remain decrypt-only during rotation.
#[derive(Debug, Clone)]
pub struct MetadataKey {
    version: String,
    bytes: [u8; 32],
}

impl MetadataKey {
    /// Builds a versioned key returned by a KMS adapter.  Callers must not log
    /// `bytes`; this type deliberately does not expose it publicly.
    pub fn new(version: impl Into<String>, bytes: [u8; 32]) -> Result<Self> {
        let version = version.into();
        if version.trim().is_empty() || version.len() > 128 {
            bail!("KMS key version is invalid");
        }
        Ok(Self { version, bytes })
    }
}

/// Key loading seam for hosted deployments.  Production adapters may use a
/// cloud KMS, HSM, or a root-owned secret mount; the coordinator never prints
/// a key or accepts a key through an HTTP request.
pub trait MetadataKeyLoader {
    /// Returns the active key and any decrypt-only predecessors.
    fn load_metadata_keys(&self) -> Result<Vec<MetadataKey>>;
}

/// In-memory representation of an already-loaded KMS key set.  The first key
/// is always the write key; all keys are accepted for reads.
#[derive(Debug, Clone)]
pub struct MetadataKeyRing {
    active: MetadataKey,
    readable: BTreeMap<String, [u8; 32]>,
}

impl MetadataKeyRing {
    /// Constructs a rotation-capable key ring. Duplicate versions are refused
    /// so ciphertext always maps to exactly one KMS version.
    pub fn new(
        active: MetadataKey,
        previous: impl IntoIterator<Item = MetadataKey>,
    ) -> Result<Self> {
        let mut readable = BTreeMap::new();
        readable.insert(active.version.clone(), active.bytes);
        for key in previous {
            if readable.insert(key.version.clone(), key.bytes).is_some() {
                bail!("duplicate KMS metadata key version");
            }
        }
        Ok(Self { active, readable })
    }

    /// Loads a ring from a deployment key loader. The first returned key is
    /// active; later keys are decrypt-only for rotation continuity.
    pub fn from_loader(loader: &impl MetadataKeyLoader) -> Result<Self> {
        let mut keys = loader.load_metadata_keys()?;
        if keys.is_empty() {
            bail!("KMS returned no coordinator metadata keys");
        }
        let active = keys.remove(0);
        Self::new(active, keys)
    }

    fn active(&self) -> &MetadataKey {
        &self.active
    }
    fn read(&self, version: &str) -> Result<&[u8; 32]> {
        self.readable
            .get(version)
            .ok_or_else(|| anyhow!("KMS key version is unavailable"))
    }
}

/// A crash-safe encrypted file backing the hosted control-plane metadata.
/// OAuth codes, access tokens, names, and subjects never enter this file.
#[derive(Debug)]
pub struct EncryptedFileStore {
    path: PathBuf,
    keys: MetadataKeyRing,
    #[cfg(test)]
    fault: Option<FaultInjection>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(test), allow(dead_code))]
enum FaultPoint {
    DirectoryParentOpen,
    DirectoryParentFsync,
    TempWrite,
    FileFsync,
    Rename,
    ParentOpen,
    ParentFsync,
    CrashAfterRename,
}

#[cfg(test)]
#[derive(Debug, Clone)]
struct FaultInjection {
    point: FaultPoint,
    remaining: Arc<AtomicUsize>,
    attempts: Arc<AtomicUsize>,
}

#[derive(Debug)]
enum CommitError {
    BeforePublish(anyhow::Error),
}

impl EncryptedFileStore {
    /// Opens an encrypted coordinator-state file at `path`.
    pub fn new(path: impl Into<PathBuf>, keys: MetadataKeyRing) -> Self {
        Self {
            path: path.into(),
            keys,
            #[cfg(test)]
            fault: None,
        }
    }

    #[cfg(test)]
    fn inject(&mut self, point: FaultPoint) {
        self.inject_failures(point, 1);
    }

    #[cfg(test)]
    fn inject_failures(&mut self, point: FaultPoint, failures: usize) -> Arc<AtomicUsize> {
        let attempts = Arc::new(AtomicUsize::new(0));
        self.fault = Some(FaultInjection {
            point,
            remaining: Arc::new(AtomicUsize::new(failures)),
            attempts: Arc::clone(&attempts),
        });
        attempts
    }

    #[cfg(test)]
    fn should_fail(&self, point: FaultPoint) -> bool {
        let Some(fault) = self.fault.as_ref().filter(|fault| fault.point == point) else {
            return false;
        };
        fault.attempts.fetch_add(1, Ordering::SeqCst);
        fault
            .remaining
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
                remaining.checked_sub(1)
            })
            .is_ok()
    }

    #[cfg(test)]
    fn fail_before_publish(&self, point: FaultPoint) -> std::result::Result<(), CommitError> {
        if self.should_fail(point) {
            return Err(CommitError::BeforePublish(anyhow!(
                "injected coordinator persistence fault: {point:?}"
            )));
        }
        Ok(())
    }

    /// Ensures `directory` and every missing ancestor are durable before the
    /// state-file rename can be published. `create_dir_all` is insufficient:
    /// syncing a newly created directory persists entries inside it, but not
    /// the directory's own name in its containing directory.
    fn ensure_directory_durable(&self, directory: &Path) -> Result<()> {
        if directory.as_os_str().is_empty() || directory == Path::new(".") {
            return Ok(());
        }

        match fs::create_dir(directory) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                if !fs::metadata(directory)
                    .with_context(|| format!("inspecting {}", directory.display()))?
                    .is_dir()
                {
                    bail!("{} exists but is not a directory", directory.display());
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let containing = directory
                    .parent()
                    .filter(|parent| !parent.as_os_str().is_empty())
                    .ok_or_else(|| anyhow!("{} has no creatable parent", directory.display()))?;
                self.ensure_directory_durable(containing)?;
                match fs::create_dir(directory) {
                    Ok(()) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                        if !fs::metadata(directory)
                            .with_context(|| format!("inspecting {}", directory.display()))?
                            .is_dir()
                        {
                            bail!("{} exists but is not a directory", directory.display());
                        }
                    }
                    Err(error) => {
                        return Err(error)
                            .with_context(|| format!("creating {}", directory.display()));
                    }
                }
            }
            Err(error) => {
                return Err(error).with_context(|| format!("creating {}", directory.display()));
            }
        }

        // A filesystem root has no directory entry in a containing directory.
        let Some(containing) = directory
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        else {
            return Ok(());
        };
        #[cfg(test)]
        if self.should_fail(FaultPoint::DirectoryParentOpen) {
            bail!("injected coordinator persistence fault: DirectoryParentOpen");
        }
        let handle = File::open(containing)
            .with_context(|| format!("opening {} for directory fsync", containing.display()))?;
        #[cfg(test)]
        if self.should_fail(FaultPoint::DirectoryParentFsync) {
            bail!("injected coordinator persistence fault: DirectoryParentFsync");
        }
        handle
            .sync_all()
            .with_context(|| format!("fsyncing directory ancestor {}", containing.display()))
    }

    fn sync_state_parent(&self, parent: &Path) -> Result<()> {
        #[cfg(test)]
        if self.should_fail(FaultPoint::ParentOpen) {
            bail!("injected coordinator persistence fault: ParentOpen");
        }
        let directory = loop {
            match File::open(parent) {
                Ok(directory) => break directory,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(error) => {
                    return Err(error)
                        .with_context(|| format!("opening {} for fsync", parent.display()));
                }
            }
        };
        #[cfg(test)]
        if self.should_fail(FaultPoint::ParentFsync) {
            bail!("injected coordinator persistence fault: ParentFsync");
        }
        loop {
            match directory.sync_all() {
                Ok(()) => return Ok(()),
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(error) => {
                    return Err(error).with_context(|| format!("fsyncing {}", parent.display()));
                }
            }
        }
    }

    /// A failed barrier after rename has an unknowable commit outcome. Never
    /// retry using a fresh descriptor and never let another request run: an
    /// external supervisor must restart and execute the startup barrier.
    fn sync_state_parent_or_abort(&self, parent: &Path) {
        if self.sync_state_parent(parent).is_err() {
            std::process::abort();
        }
    }

    fn sidecar_path(&self, suffix: &str) -> PathBuf {
        let mut value = self.path.as_os_str().to_os_string();
        value.push(suffix);
        PathBuf::from(value)
    }

    fn cleanup_stale_temporary_files(&self, parent: &Path) -> Result<()> {
        let state_prefix = self
            .path
            .with_extension("tmp-")
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| anyhow!("coordinator state filename is not valid UTF-8"))?
            .to_owned();
        let highwater_prefix = format!(
            "{}.tmp-",
            self.sidecar_path(".highwater")
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or_else(|| anyhow!("coordinator high-watermark filename is not valid UTF-8"))?
        );
        let mut removed = false;
        for entry in fs::read_dir(parent)
            .with_context(|| format!("scanning {} for stale state files", parent.display()))?
        {
            let entry = entry?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            if name.starts_with(&state_prefix) || name.starts_with(&highwater_prefix) {
                fs::remove_file(entry.path()).with_context(|| {
                    format!("removing stale state file {}", entry.path().display())
                })?;
                removed = true;
            }
        }
        if removed {
            File::open(parent)?.sync_all()?;
        }
        Ok(())
    }

    fn read_high_watermark(&self) -> Result<u64> {
        match fs::read_to_string(self.sidecar_path(".highwater")) {
            Ok(value) => value
                .trim()
                .parse()
                .context("parsing coordinator sequence high-watermark"),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(0),
            Err(error) => Err(error).context("reading coordinator sequence high-watermark"),
        }
    }

    fn write_high_watermark(&self, sequence: u64, abort_after_publish: bool) -> Result<()> {
        let parent = self
            .path
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        if parent != Path::new(".") {
            self.ensure_directory_durable(parent)?;
        }
        let destination = self.sidecar_path(".highwater");
        let temporary = self.sidecar_path(&format!(".highwater.tmp-{}", Uuid::new_v4()));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        writeln!(file, "{sequence}")?;
        file.sync_all()?;
        fs::rename(&temporary, &destination)?;
        let barrier = File::open(parent)
            .with_context(|| format!("opening {} for high-watermark fsync", parent.display()))
            .and_then(|directory| {
                directory
                    .sync_all()
                    .with_context(|| format!("fsyncing high-watermark in {}", parent.display()))
            });
        if let Err(error) = barrier {
            if abort_after_publish {
                std::process::abort();
            }
            return Err(error);
        }
        Ok(())
    }

    fn reconcile_startup(&self) -> Result<DurableCoordinator> {
        let parent = self
            .path
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        if parent != Path::new(".") {
            self.ensure_directory_durable(parent)?;
        }
        self.cleanup_stale_temporary_files(parent)?;
        if self.path.exists() {
            File::open(&self.path)
                .with_context(|| format!("opening {} for startup fsync", self.path.display()))?
                .sync_all()
                .with_context(|| format!("fsyncing {} at startup", self.path.display()))?;
            self.sync_state_parent(parent)?;
        }
        let state = self.load()?;
        let high_watermark = self.read_high_watermark()?;
        if state.sequence < high_watermark {
            bail!(
                "coordinator state sequence {} regressed below durable high-watermark {}",
                state.sequence,
                high_watermark
            );
        }
        if state.sequence > high_watermark {
            self.write_high_watermark(state.sequence, false)?;
        }
        Ok(state)
    }

    fn needs_active_key_rewrap(&self) -> Result<bool> {
        match fs::read(&self.path) {
            Ok(bytes) => {
                let encrypted: EncryptedMetadata = serde_json::from_slice(&bytes)
                    .context("parsing encrypted coordinator metadata for key rotation")?;
                Ok(encrypted.key_version != self.keys.active().version)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error).context("reading coordinator metadata for key rotation"),
        }
    }

    fn load(&self) -> Result<DurableCoordinator> {
        match fs::read(&self.path) {
            Ok(bytes) => {
                let encrypted: EncryptedMetadata = serde_json::from_slice(&bytes)
                    .context("parsing encrypted coordinator metadata")?;
                let plaintext = encrypted.open_bytes(self.keys.read(&encrypted.key_version)?)?;
                serde_json::from_slice(&plaintext).context("parsing coordinator metadata")
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                Ok(DurableCoordinator::default())
            }
            Err(error) => Err(error).context("reading encrypted coordinator metadata"),
        }
    }

    fn save(&self, state: &DurableCoordinator) -> std::result::Result<(), CommitError> {
        let plaintext = serde_json::to_vec(state)
            .context("serializing coordinator metadata")
            .map_err(CommitError::BeforePublish)?;
        let active = self.keys.active();
        let encrypted = EncryptedMetadata::seal_bytes(&active.bytes, &active.version, &plaintext)
            .map_err(CommitError::BeforePublish)?;
        let encoded = serde_json::to_vec(&encrypted)
            .context("encoding encrypted coordinator metadata")
            .map_err(CommitError::BeforePublish)?;
        let parent = self
            .path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        if parent != Path::new(".") {
            self.ensure_directory_durable(parent)
                .map_err(CommitError::BeforePublish)?;
        }
        let temporary = self.path.with_extension(format!("tmp-{}", Uuid::new_v4()));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .with_context(|| format!("creating {}", temporary.display()))
            .map_err(CommitError::BeforePublish)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(fs::Permissions::from_mode(0o600))
                .map_err(|error| CommitError::BeforePublish(error.into()))?;
        }
        #[cfg(test)]
        self.fail_before_publish(FaultPoint::TempWrite)?;
        file.write_all(&encoded)
            .map_err(|error| CommitError::BeforePublish(error.into()))?;
        #[cfg(test)]
        self.fail_before_publish(FaultPoint::FileFsync)?;
        file.sync_all()
            .map_err(|error| CommitError::BeforePublish(error.into()))?;
        #[cfg(test)]
        self.fail_before_publish(FaultPoint::Rename)?;
        fs::rename(&temporary, &self.path)
            .with_context(|| format!("publishing {}", self.path.display()))
            .map_err(CommitError::BeforePublish)?;
        #[cfg(test)]
        if self.should_fail(FaultPoint::CrashAfterRename) {
            // Used only by the subprocess crash test below. `exit` skips Rust
            // destructors and terminates before the durability barrier or API
            // acknowledgement, matching abrupt process loss at this boundary.
            std::process::exit(86);
        }
        // `rename` only makes the new name visible.  Syncing its parent makes
        // that directory entry durable across a power loss as well. No error
        // after rename is allowed to escape this barrier.
        self.sync_state_parent_or_abort(parent);
        Ok(())
    }
}

/// Coordinator state coupled to an encrypted durable store. Every account
/// lifecycle mutation is persisted before its success is returned.
#[derive(Debug)]
pub struct PersistentCoordinator {
    store: EncryptedFileStore,
    coordinator: Coordinator,
    _writer_lock: File,
}

impl PersistentCoordinator {
    /// Opens existing encrypted state or creates an empty coordinator.
    pub fn open(
        path: impl Into<PathBuf>,
        keys: MetadataKeyRing,
        account_id_key: [u8; 32],
    ) -> Result<Self> {
        Self::open_inner(path.into(), keys, account_id_key, None)
    }

    fn open_inner(
        path: PathBuf,
        keys: MetadataKeyRing,
        account_id_key: [u8; 32],
        #[cfg_attr(not(test), allow(unused_variables))] fault: Option<FaultPoint>,
    ) -> Result<Self> {
        #[allow(unused_mut)]
        let mut store = EncryptedFileStore::new(path, keys);
        #[cfg(test)]
        if let Some(fault) = fault {
            store.inject(fault);
        }
        let parent = store
            .path
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        if parent != Path::new(".") {
            store.ensure_directory_durable(parent)?;
        }
        let lock_path = store.sidecar_path(".lock");
        let writer_lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&lock_path)
            .with_context(|| format!("opening coordinator writer lock {}", lock_path.display()))?;
        writer_lock.try_lock().with_context(|| {
            format!(
                "coordinator state {} already has an active writer",
                store.path.display()
            )
        })?;
        let durable = store.reconcile_startup()?;
        if store.needs_active_key_rewrap()? {
            store.save(&durable).map_err(|error| match error {
                CommitError::BeforePublish(error) => error,
            })?;
            store.write_high_watermark(durable.sequence, true)?;
        }
        let coordinator = Coordinator::from_durable(account_id_key, durable);
        Ok(Self {
            store,
            coordinator,
            _writer_lock: writer_lock,
        })
    }

    /// Signs in and durably records the account shell if it is new.
    pub fn sign_in_claims(&mut self, claims: VerifiedOAuth) -> Result<AccountId> {
        self.transaction(|candidate| candidate.sign_in_claims(claims))
    }

    /// Begins a short-lived in-memory enrollment challenge.
    pub fn begin_enrollment(&mut self, account: &AccountId) -> Result<EnrollmentChallenge> {
        self.coordinator.begin_enrollment(account)
    }

    /// Enrolls a device and persists it before responding.
    pub fn enroll(
        &mut self,
        account: &AccountId,
        proof: EnrollmentProof,
        discovery: DiscoveryConfig,
    ) -> Result<EnrolledDevice> {
        self.transaction(|candidate| candidate.enroll(account, proof, discovery))
    }

    /// Revokes a device durably.
    pub fn revoke_device(&mut self, account: &AccountId, device: &DeviceId) -> Result<()> {
        self.transaction(|candidate| candidate.revoke_device(account, device))
    }

    /// Returns discovery configuration without requiring an online service.
    pub fn discovery_for(&self, account: &AccountId, device: &DeviceId) -> Result<DiscoveryConfig> {
        self.coordinator.discovery_for(account, device)
    }

    /// Exports minimal metadata.
    pub fn export_account(&self, account: &AccountId) -> Result<AccountExport> {
        self.coordinator.export_account(account)
    }

    /// Deletes hosted data durably.
    pub fn delete_account(&mut self, account: &AccountId) -> Result<()> {
        self.transaction(|candidate| candidate.delete_account(account))
    }

    /// Commits a sequenced transaction. The store cannot return success after
    /// rename until its parent-directory entry is confirmed durable.
    fn transaction<T>(&mut self, mutate: impl FnOnce(&mut Coordinator) -> Result<T>) -> Result<T> {
        let mut candidate = self.coordinator.clone();
        let before = candidate.durable();
        let value = mutate(&mut candidate)?;
        let after = candidate.durable();
        if after == before {
            // Preserve intentional in-memory effects such as consuming a
            // challenge, but do not rewrite the full encrypted state for a
            // durable no-op such as signing into an existing account.
            self.coordinator = candidate;
            return Ok(value);
        }
        candidate.sequence = candidate.sequence.saturating_add(1);
        candidate.last_transaction = Some(Uuid::new_v4().to_string());
        let durable = candidate.durable();
        if serde_json::to_vec(&durable)?.len() > MAX_DURABLE_STATE_BYTES {
            bail!("coordinator durable state capacity reached");
        }
        match self.store.save(&durable) {
            Ok(()) => {
                // The state is durable now, so keep the live image aligned
                // even if publishing the independent rollback fence fails
                // before its rename. No success is returned until both are
                // durable; a post-rename fence failure aborts the process.
                self.coordinator = candidate;
                self.store
                    .write_high_watermark(self.coordinator.sequence, true)?;
                Ok(value)
            }
            Err(CommitError::BeforePublish(error)) => Err(error),
        }
    }
}

/// Encrypts minimal persisted metadata with AES-256-GCM.  The caller owns the
/// 32-byte KMS-managed key; this type never derives it from an OAuth identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedMetadata {
    /// KMS key version used for this ciphertext.
    pub key_version: String,
    /// Random 96-bit AES-GCM nonce.
    pub nonce: [u8; 12],
    /// Authenticated ciphertext, including the GCM tag.
    pub ciphertext: Vec<u8>,
}

impl EncryptedMetadata {
    /// Seals an export for durable storage.
    pub fn seal(key: &[u8; 32], export: &AccountExport) -> Result<Self> {
        let plaintext =
            serde_json::to_vec(export).context("serializing minimal account metadata")?;
        Self::seal_bytes(key, "legacy-test-key", &plaintext)
    }

    fn seal_bytes(key: &[u8; 32], key_version: &str, plaintext: &[u8]) -> Result<Self> {
        let nonce: [u8; 12] = random_32()[..12].try_into().expect("slice has 12 bytes");
        let cipher = Aes256Gcm::new_from_slice(key).expect("AES-256 keys are exactly 32 bytes");
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce), plaintext)
            .map_err(|_| anyhow!("encrypting account metadata failed"))?;
        Ok(Self {
            key_version: key_version.into(),
            nonce,
            ciphertext,
        })
    }

    /// Opens metadata previously sealed by [`Self::seal`].
    pub fn open(&self, key: &[u8; 32]) -> Result<AccountExport> {
        let plaintext = self.open_bytes(key)?;
        serde_json::from_slice(&plaintext)
            .context("encrypted account metadata has an invalid shape")
    }

    fn open_bytes(&self, key: &[u8; 32]) -> Result<Vec<u8>> {
        let cipher = Aes256Gcm::new_from_slice(key).expect("AES-256 keys are exactly 32 bytes");
        cipher
            .decrypt(Nonce::from_slice(&self.nonce), self.ciphertext.as_ref())
            .map_err(|_| anyhow!("account metadata cannot be decrypted"))
    }
}

/// Creates an enrollment proof from an Asterism device identity.
pub fn enrollment_proof(
    identity: &asterism_mesh::DeviceIdentity,
    challenge: EnrollmentChallenge,
) -> EnrollmentProof {
    EnrollmentProof {
        device_id: identity.device_id(),
        signature: identity.sign(&enrollment_message(&challenge)),
        challenge,
    }
}

fn account_id(key: &[u8; 32], claims: &VerifiedOAuth) -> AccountId {
    let mut hash = blake3::Hasher::new_keyed(key);
    hash.update(IDENTITY_DOMAIN);
    hash.update(match claims.provider {
        OAuthProvider::Google => b"google",
        OAuthProvider::GitHub => b"github",
    });
    hash.update(&[0]);
    hash.update(claims.issuer.as_bytes());
    hash.update(&[0]);
    hash.update(claims.subject.as_bytes());
    AccountId(hash.finalize().to_hex().to_string())
}

fn enrollment_message(challenge: &EnrollmentChallenge) -> Vec<u8> {
    [ENROLLMENT_DOMAIN, &challenge.bytes].concat()
}

fn unix_seconds() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

fn random_32() -> [u8; 32] {
    let first = Uuid::new_v4();
    let second = Uuid::new_v4();
    let mut bytes = [0; 32];
    bytes[..16].copy_from_slice(first.as_bytes());
    bytes[16..].copy_from_slice(second.as_bytes());
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    use asterism_core::orbit::{device_now, Orbit};
    use std::process::Command;
    use tempfile::tempdir;

    struct OAuth(OAuthProvider, &'static str, &'static str);
    impl OAuthVerifier for OAuth {
        fn verify_authorization_code(&self, _: &str) -> Result<VerifiedOAuth> {
            Ok(VerifiedOAuth {
                provider: self.0,
                issuer: self.1.into(),
                subject: self.2.into(),
            })
        }
    }

    fn google() -> OAuth {
        OAuth(
            OAuthProvider::Google,
            "https://accounts.google.com",
            "opaque-google-subject",
        )
    }

    #[test]
    fn google_and_github_are_the_only_valid_oauth_authorities() {
        let mut service = Coordinator::new([1; 32]);
        let google_id = service.sign_in(&google(), "code").unwrap();
        let github_id = service
            .sign_in(
                &OAuth(OAuthProvider::GitHub, "https://github.com", "42"),
                "code",
            )
            .unwrap();
        assert_ne!(google_id, github_id);
        assert!(service
            .sign_in(
                &OAuth(OAuthProvider::Google, "https://github.com", "42"),
                "code"
            )
            .is_err());
    }

    #[test]
    fn enrollment_revoke_export_and_deletion_are_account_bound() {
        let mut service = Coordinator::new([1; 32]);
        let account = service.sign_in(&google(), "code").unwrap();
        let device = asterism_mesh::DeviceIdentity::generate();
        let challenge = service.begin_enrollment(&account).unwrap();
        let config = DiscoveryConfig {
            relays: vec!["https://relay.example".into()],
            pkarr_relay: Some("https://directory.example/pkarr".into()),
            dns_origin: None,
        };
        service
            .enroll(
                &account,
                enrollment_proof(&device, challenge.clone()),
                config.clone(),
            )
            .unwrap();
        assert_eq!(
            service
                .discovery_for(&account, &device.device_id())
                .unwrap(),
            config
        );
        assert!(
            service
                .enroll(
                    &account,
                    enrollment_proof(&device, challenge),
                    DiscoveryConfig::default()
                )
                .is_err(),
            "challenges are single use"
        );
        let exported = service.export_account(&account).unwrap();
        assert_eq!(exported.devices.len(), 1);
        assert!(!serde_json::to_string(&exported)
            .unwrap()
            .contains("opaque-google-subject"));
        service
            .revoke_device(&account, &device.device_id())
            .unwrap();
        assert!(service
            .discovery_for(&account, &device.device_id())
            .is_err());
        service.delete_account(&account).unwrap();
        assert!(service.export_account(&account).is_err());
    }

    #[test]
    fn a_forged_proof_cannot_burn_another_devices_enrollment_challenge() {
        let mut service = Coordinator::new([1; 32]);
        let account = service.sign_in(&google(), "code").unwrap();
        let device = asterism_mesh::DeviceIdentity::generate();
        let attacker = asterism_mesh::DeviceIdentity::generate();
        let challenge = service.begin_enrollment(&account).unwrap();
        let forged = EnrollmentProof {
            device_id: device.device_id(),
            challenge: challenge.clone(),
            signature: attacker.sign(&enrollment_message(&challenge)),
        };
        assert!(service
            .enroll(&account, forged, DiscoveryConfig::default())
            .is_err());
        service
            .enroll(
                &account,
                enrollment_proof(&device, challenge),
                DiscoveryConfig::default(),
            )
            .unwrap();
    }

    #[test]
    fn metadata_is_encrypted_and_tamper_evident() {
        let export = AccountExport {
            account_id: AccountId("opaque".into()),
            devices: vec![],
        };
        let sealed = EncryptedMetadata::seal(&[7; 32], &export).unwrap();
        assert!(!String::from_utf8_lossy(&sealed.ciphertext).contains("opaque"));
        assert_eq!(sealed.open(&[7; 32]).unwrap(), export);
        assert!(sealed.open(&[8; 32]).is_err());
    }

    #[test]
    fn encrypted_account_lifecycle_survives_a_process_restart_and_deletion() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("coordinator.enc.json");
        let metadata_key = [7; 32];
        let account_key = [9; 32];
        let device = asterism_mesh::DeviceIdentity::generate();
        let account = {
            let mut service = PersistentCoordinator::open(
                &path,
                MetadataKeyRing::new(MetadataKey::new("test-v1", metadata_key).unwrap(), [])
                    .unwrap(),
                account_key,
            )
            .unwrap();
            let account = service
                .sign_in_claims(VerifiedOAuth {
                    provider: OAuthProvider::Google,
                    issuer: "https://accounts.google.com".into(),
                    subject: "provider-subject-never-on-disk".into(),
                })
                .unwrap();
            let challenge = service.begin_enrollment(&account).unwrap();
            service
                .enroll(
                    &account,
                    enrollment_proof(&device, challenge),
                    DiscoveryConfig {
                        relays: vec!["https://third-party-relay.example".into()],
                        ..Default::default()
                    },
                )
                .unwrap();
            account
        };
        let ciphertext = fs::read_to_string(&path).unwrap();
        assert!(!ciphertext.contains("provider-subject-never-on-disk"));
        let mut restarted = PersistentCoordinator::open(
            &path,
            MetadataKeyRing::new(MetadataKey::new("test-v1", metadata_key).unwrap(), []).unwrap(),
            account_key,
        )
        .unwrap();
        assert_eq!(
            restarted
                .discovery_for(&account, &device.device_id())
                .unwrap()
                .relays,
            vec!["https://third-party-relay.example"]
        );
        assert_eq!(restarted.export_account(&account).unwrap().devices.len(), 1);
        restarted.delete_account(&account).unwrap();
        drop(restarted);
        let after_delete = PersistentCoordinator::open(
            &path,
            MetadataKeyRing::new(MetadataKey::new("test-v1", metadata_key).unwrap(), []).unwrap(),
            account_key,
        )
        .unwrap();
        assert!(after_delete.export_account(&account).is_err());
    }

    #[test]
    fn account_ids_are_keyed_and_not_enumerable_from_the_subject() {
        let claims = VerifiedOAuth {
            provider: OAuthProvider::GitHub,
            issuer: "https://github.com".into(),
            subject: "42".into(),
        };
        assert_ne!(account_id(&[1; 32], &claims), account_id(&[2; 32], &claims));
    }

    #[test]
    fn existing_sign_in_is_a_durable_noop_and_state_caps_are_enforced() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("state.enc");
        let keys = MetadataKeyRing::new(MetadataKey::new("kms-v1", [21; 32]).unwrap(), []).unwrap();
        let claims = VerifiedOAuth {
            provider: OAuthProvider::Google,
            issuer: "https://accounts.google.com".into(),
            subject: "bounded-account".into(),
        };
        let mut service = PersistentCoordinator::open(&path, keys, [22; 32]).unwrap();
        let account = service.sign_in_claims(claims.clone()).unwrap();
        let before = fs::read(&path).unwrap();
        service.sign_in_claims(claims).unwrap();
        assert_eq!(
            fs::read(&path).unwrap(),
            before,
            "no-op sign-in rewrote state"
        );

        let oversized = DiscoveryConfig {
            relays: vec![format!(
                "https://relay.example/{}",
                "x".repeat(MAX_DISCOVERY_BYTES)
            )],
            ..Default::default()
        };
        let device = asterism_mesh::DeviceIdentity::generate();
        let challenge = service.begin_enrollment(&account).unwrap();
        assert!(service
            .enroll(&account, enrollment_proof(&device, challenge), oversized)
            .is_err());

        for _ in 0..MAX_DEVICES_PER_ACCOUNT {
            let device = asterism_mesh::DeviceIdentity::generate();
            let challenge = service.begin_enrollment(&account).unwrap();
            service
                .enroll(
                    &account,
                    enrollment_proof(&device, challenge),
                    DiscoveryConfig::default(),
                )
                .unwrap();
        }
        let extra = asterism_mesh::DeviceIdentity::generate();
        let challenge = service.begin_enrollment(&account).unwrap();
        assert!(service
            .enroll(
                &account,
                enrollment_proof(&extra, challenge),
                DiscoveryConfig::default(),
            )
            .is_err());
    }

    #[test]
    fn metadata_key_rotation_reads_old_ciphertext_then_rewraps_with_the_new_version() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("coordinator.enc.json");
        let claims = VerifiedOAuth {
            provider: OAuthProvider::Google,
            issuer: "https://accounts.google.com".into(),
            subject: "rotation-subject".into(),
        };
        let v1 = MetadataKey::new("kms-v1", [1; 32]).unwrap();
        let v2 = MetadataKey::new("kms-v2", [2; 32]).unwrap();
        {
            let mut service = PersistentCoordinator::open(
                &path,
                MetadataKeyRing::new(v1.clone(), []).unwrap(),
                [9; 32],
            )
            .unwrap();
            service.sign_in_claims(claims.clone()).unwrap();
        }
        {
            let mut service = PersistentCoordinator::open(
                &path,
                MetadataKeyRing::new(v2.clone(), [v1]).unwrap(),
                [9; 32],
            )
            .unwrap();
            service.sign_in_claims(claims).unwrap(); // causes a v2 write
        }
        let wrapped: EncryptedMetadata = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert_eq!(wrapped.key_version, "kms-v2");
        assert!(
            PersistentCoordinator::open(&path, MetadataKeyRing::new(v2, []).unwrap(), [9; 32])
                .is_ok()
        );
    }

    #[test]
    fn failed_persistence_does_not_mutate_the_live_coordinator() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("state/coordinator.enc.json");
        let keys = MetadataKeyRing::new(MetadataKey::new("kms-v1", [3; 32]).unwrap(), []).unwrap();
        let claims = VerifiedOAuth {
            provider: OAuthProvider::GitHub,
            issuer: "https://github.com".into(),
            subject: "99".into(),
        };
        let expected = account_id(&[4; 32], &claims);
        let mut service = PersistentCoordinator::open(&path, keys, [4; 32]).unwrap();
        fs::remove_dir_all(directory.path().join("state")).unwrap_or(());
        // Make the parent a file, so create_dir_all/save fails deterministically.
        fs::write(directory.path().join("state"), b"not a directory").unwrap();
        assert!(service.sign_in_claims(claims).is_err());
        assert!(
            service.export_account(&expected).is_err(),
            "failed transaction must not become live"
        );
    }

    #[test]
    fn every_pre_publish_persistence_boundary_refuses_acknowledgement() {
        for point in [
            FaultPoint::TempWrite,
            FaultPoint::FileFsync,
            FaultPoint::Rename,
        ] {
            let directory = tempdir().unwrap();
            let path = directory.path().join("state.enc");
            let keys =
                MetadataKeyRing::new(MetadataKey::new("kms-v1", [5; 32]).unwrap(), []).unwrap();
            let claims = VerifiedOAuth {
                provider: OAuthProvider::Google,
                issuer: "https://accounts.google.com".into(),
                subject: "fault-matrix".into(),
            };
            let expected = account_id(&[6; 32], &claims);
            let mut service = PersistentCoordinator::open(&path, keys.clone(), [6; 32]).unwrap();
            service.store.inject_failures(point, 1);
            let result = service.sign_in_claims(claims.clone());
            assert!(result.is_err(), "{point:?}");
            assert!(service.export_account(&expected).is_err());
            service.store.fault = None;
            service.sign_in_claims(claims.clone()).unwrap();
            assert!(service.export_account(&expected).is_ok());
            drop(service);
            let restarted = PersistentCoordinator::open(&path, keys, [6; 32]).unwrap();
            assert!(
                restarted.export_account(&expected).is_ok(),
                "restart after {point:?}"
            );
            assert!(
                fs::read_dir(directory.path()).unwrap().all(|entry| !entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with("state.tmp-")),
                "restart must remove the stale temporary file after {point:?}"
            );
        }
    }

    #[test]
    fn clean_host_directory_loss_never_erases_acknowledged_lifecycle_mutations() {
        let directory = tempdir().unwrap();
        let fresh_install = directory.path().join("var/lib/asterism");
        let path = fresh_install.join("coordinator.enc.json");
        let keys = MetadataKeyRing::new(MetadataKey::new("kms-v1", [13; 32]).unwrap(), []).unwrap();
        let account_key = [14; 32];
        let claims = VerifiedOAuth {
            provider: OAuthProvider::Google,
            issuer: "https://accounts.google.com".into(),
            subject: "clean-host-account".into(),
        };
        let account = account_id(&account_key, &claims);

        let mut first_boot = PersistentCoordinator::open(&path, keys.clone(), account_key).unwrap();
        first_boot.store.inject(FaultPoint::DirectoryParentFsync);
        assert!(
            first_boot.sign_in_claims(claims.clone()).is_err(),
            "a new directory whose containing entry was not synced must not acknowledge"
        );
        drop(first_boot);

        // Model a crash/remount dropping the newly created but deliberately
        // unsynced `var` entry. No successful response escaped that boundary.
        fs::remove_dir_all(directory.path().join("var")).unwrap();
        let after_unacknowledged_loss =
            PersistentCoordinator::open(&path, keys.clone(), account_key).unwrap();
        assert!(after_unacknowledged_loss.export_account(&account).is_err());
        drop(after_unacknowledged_loss);

        // A successful clean-host write has synced `var` in the test root,
        // `lib` in `var`, `asterism` in `lib`, and finally the state filename.
        // Each acknowledged lifecycle mutation must then survive a restart.
        let mut service = PersistentCoordinator::open(&path, keys.clone(), account_key).unwrap();
        assert_eq!(service.sign_in_claims(claims).unwrap(), account);
        let device = asterism_mesh::DeviceIdentity::generate();
        let challenge = service.begin_enrollment(&account).unwrap();
        service
            .enroll(
                &account,
                enrollment_proof(&device, challenge),
                DiscoveryConfig::default(),
            )
            .unwrap();
        drop(service);

        let mut restarted = PersistentCoordinator::open(&path, keys.clone(), account_key).unwrap();
        assert!(restarted
            .discovery_for(&account, &device.device_id())
            .is_ok());
        restarted
            .revoke_device(&account, &device.device_id())
            .unwrap();
        drop(restarted);

        let mut restarted = PersistentCoordinator::open(&path, keys.clone(), account_key).unwrap();
        assert!(restarted
            .discovery_for(&account, &device.device_id())
            .is_err());
        restarted.delete_account(&account).unwrap();
        drop(restarted);

        let restarted = PersistentCoordinator::open(&path, keys, account_key).unwrap();
        assert!(restarted.export_account(&account).is_err());
    }

    #[test]
    fn permanent_parent_fsync_helper_aborts_before_acknowledgement() {
        let Some(path) = std::env::var_os("ASTERISM_PERMANENT_FSYNC_STATE").map(PathBuf::from)
        else {
            return;
        };
        let acknowledgment = PathBuf::from(
            std::env::var_os("ASTERISM_PERMANENT_FSYNC_ACK").expect("permanent fault ack path"),
        );
        let mut service = PersistentCoordinator::open(
            path,
            MetadataKeyRing::new(MetadataKey::new("kms-v1", [7; 32]).unwrap(), []).unwrap(),
            [8; 32],
        )
        .unwrap();
        service
            .store
            .inject_failures(FaultPoint::ParentFsync, usize::MAX);
        service
            .sign_in_claims(VerifiedOAuth {
                provider: OAuthProvider::Google,
                issuer: "https://accounts.google.com".into(),
                subject: "must-abort".into(),
            })
            .unwrap();
        fs::write(acknowledgment, b"acknowledged").unwrap();
    }

    #[test]
    fn permanent_post_publish_fsync_failure_aborts_quickly_without_ack() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("state.enc");
        let acknowledgment = directory.path().join("acknowledged");
        let started = std::time::Instant::now();
        let status = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "tests::permanent_parent_fsync_helper_aborts_before_acknowledgement",
                "--nocapture",
            ])
            .env("ASTERISM_PERMANENT_FSYNC_STATE", &path)
            .env("ASTERISM_PERMANENT_FSYNC_ACK", &acknowledgment)
            .status()
            .unwrap();
        assert!(!status.success());
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
        assert!(!acknowledgment.exists());
    }

    #[test]
    fn startup_refuses_a_second_writer_and_cleans_stale_temporary_files() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("state.enc");
        let keys = MetadataKeyRing::new(MetadataKey::new("kms-v1", [15; 32]).unwrap(), []).unwrap();
        let first = PersistentCoordinator::open(&path, keys.clone(), [16; 32]).unwrap();
        assert!(PersistentCoordinator::open(&path, keys.clone(), [16; 32]).is_err());
        drop(first);

        fs::write(directory.path().join("state.tmp-stale"), b"partial").unwrap();
        fs::write(
            directory.path().join("state.enc.highwater.tmp-stale"),
            b"partial",
        )
        .unwrap();
        let restarted = PersistentCoordinator::open(&path, keys, [16; 32]).unwrap();
        assert!(!directory.path().join("state.tmp-stale").exists());
        assert!(!directory
            .path()
            .join("state.enc.highwater.tmp-stale")
            .exists());
        drop(restarted);
    }

    #[test]
    fn crash_helper_after_rename_before_parent_sync() {
        let Some(path) = std::env::var_os("ASTERISM_CRASH_TEST_STATE").map(PathBuf::from) else {
            return;
        };
        let acknowledgment = PathBuf::from(
            std::env::var_os("ASTERISM_CRASH_TEST_ACK").expect("crash test ack path"),
        );
        let mut service = PersistentCoordinator::open(
            path,
            MetadataKeyRing::new(MetadataKey::new("kms-v1", [11; 32]).unwrap(), []).unwrap(),
            [12; 32],
        )
        .unwrap();
        service.store.inject(FaultPoint::CrashAfterRename);
        service
            .sign_in_claims(VerifiedOAuth {
                provider: OAuthProvider::GitHub,
                issuer: "https://github.com".into(),
                subject: "unconfirmed-after-crash".into(),
            })
            .unwrap();
        fs::write(acknowledgment, b"acknowledged").unwrap();
    }

    #[test]
    fn process_crash_and_directory_entry_loss_never_acknowledge_the_visible_rename() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("state.enc");
        let acknowledgment = directory.path().join("acknowledged");
        let keys = MetadataKeyRing::new(MetadataKey::new("kms-v1", [11; 32]).unwrap(), []).unwrap();
        let old_claims = VerifiedOAuth {
            provider: OAuthProvider::Google,
            issuer: "https://accounts.google.com".into(),
            subject: "previously-durable".into(),
        };
        let new_claims = VerifiedOAuth {
            provider: OAuthProvider::GitHub,
            issuer: "https://github.com".into(),
            subject: "unconfirmed-after-crash".into(),
        };
        let new_account = account_id(&[12; 32], &new_claims);
        let mut service = PersistentCoordinator::open(&path, keys.clone(), [12; 32]).unwrap();
        service.sign_in_claims(old_claims).unwrap();
        let previously_durable = fs::read(&path).unwrap();
        drop(service);

        let status = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "tests::crash_helper_after_rename_before_parent_sync",
                "--nocapture",
            ])
            .env("ASTERISM_CRASH_TEST_STATE", &path)
            .env("ASTERISM_CRASH_TEST_ACK", &acknowledgment)
            .status()
            .unwrap();
        assert_eq!(status.code(), Some(86));
        assert!(
            !acknowledgment.exists(),
            "the crashed request was acknowledged"
        );
        assert!(PersistentCoordinator::open_inner(
            path.clone(),
            keys.clone(),
            [12; 32],
            Some(FaultPoint::ParentFsync),
        )
        .is_err());
        let cache_visible = PersistentCoordinator::open(&path, keys.clone(), [12; 32]).unwrap();
        assert!(cache_visible.export_account(&new_account).is_ok());
        drop(cache_visible);

        // Model the remount outcome that motivated this regression: the
        // unsynced renamed directory entry is lost and the prior durable entry
        // returns. Install that old inode image atomically, then restart.
        let rollback = directory.path().join("state.pre-crash");
        fs::write(&rollback, previously_durable).unwrap();
        File::open(&rollback).unwrap().sync_all().unwrap();
        fs::rename(&rollback, &path).unwrap();
        File::open(directory.path()).unwrap().sync_all().unwrap();

        assert!(
            PersistentCoordinator::open(&path, keys, [12; 32]).is_err(),
            "startup must reject a state sequence below its high-watermark"
        );
        assert!(!acknowledgment.exists());
    }

    #[test]
    fn enrollment_challenges_expire_and_have_a_hard_account_bound() {
        let mut service = Coordinator::new([1; 32]);
        let account = service.sign_in(&google(), "code").unwrap();
        let first = service.begin_enrollment_at(&account, 100).unwrap();
        for _ in 1..MAX_ENROLLMENT_CHALLENGES_PER_ACCOUNT {
            service.begin_enrollment_at(&account, 100).unwrap();
        }
        assert!(service.begin_enrollment_at(&account, 100).is_err());
        let device = asterism_mesh::DeviceIdentity::generate();
        assert!(service
            .enroll_at(
                &account,
                enrollment_proof(&device, first),
                DiscoveryConfig::default(),
                100 + ENROLLMENT_CHALLENGE_TTL_SECS
            )
            .is_err());
        assert!(service
            .begin_enrollment_at(&account, 100 + ENROLLMENT_CHALLENGE_TTL_SECS)
            .is_ok());
    }

    #[test]
    fn local_orbit_trust_and_cached_discovery_are_independent_of_the_coordinator() {
        let dir = tempdir().unwrap();
        let orbit_path = dir.path().join("orbit.json");
        let peer = asterism_mesh::DeviceIdentity::generate();
        let mut orbit = Orbit::load(&orbit_path).unwrap();
        orbit.set_self_name("desktop").unwrap();
        orbit
            .add(device_now(
                "laptop",
                &peer.device_id().to_string(),
                vec!["192.0.2.44:7777".into()],
                vec!["https://relay.example".into()],
            ))
            .unwrap();
        orbit.save().unwrap();
        let local = DiscoveryConfig {
            relays: vec!["https://relay.example".into()],
            ..Default::default()
        }
        .mesh_infra();
        let after_outage = Orbit::load(&orbit_path).unwrap();
        assert!(after_outage.trusts(&peer.device_id().to_string()));
        assert_eq!(local.relays, vec!["https://relay.example"]);
    }
}
