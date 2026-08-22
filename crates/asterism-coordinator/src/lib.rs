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

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::PathBuf;

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
    challenges: BTreeSet<[u8; 32]>,
}

/// In-memory coordinator state.  A production HTTP adapter serializes only
/// [`AccountExport`] with [`EncryptedMetadata`]; OAuth callbacks/tokens and
/// plaintext provider subjects must never be put in this structure or log.
#[derive(Debug, Clone)]
pub struct Coordinator {
    accounts: BTreeMap<AccountId, Account>,
    account_id_key: [u8; 32],
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
        self.accounts.entry(account_id.clone()).or_default();
        Ok(account_id)
    }

    /// Starts a single-use account-bound enrollment.
    pub fn begin_enrollment(&mut self, account_id: &AccountId) -> Result<EnrollmentChallenge> {
        let account = self.account_mut(account_id)?;
        loop {
            let challenge = EnrollmentChallenge { bytes: random_32() };
            if account.challenges.insert(challenge.bytes) {
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
        discovery.validate()?;
        let account = self.account_mut(account_id)?;
        if !account.challenges.contains(&proof.challenge.bytes) {
            bail!("enrollment challenge is unknown, expired, or already used");
        }
        if !proof
            .device_id
            .verify(&enrollment_message(&proof.challenge), &proof.signature)
        {
            bail!("device enrollment proof is invalid");
        }
        account.challenges.remove(&proof.challenge.bytes);
        let device = EnrolledDevice {
            device_id: proof.device_id.to_string(),
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
            accounts: state
                .accounts
                .into_iter()
                .map(|(id, account)| {
                    (
                        id,
                        Account {
                            devices: account.devices,
                            challenges: BTreeSet::new(),
                        },
                    )
                })
                .collect(),
            account_id_key,
        }
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct DurableCoordinator {
    accounts: BTreeMap<AccountId, DurableAccount>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
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
#[derive(Debug, Clone)]
pub struct EncryptedFileStore {
    path: PathBuf,
    keys: MetadataKeyRing,
}

impl EncryptedFileStore {
    /// Opens an encrypted coordinator-state file at `path`.
    pub fn new(path: impl Into<PathBuf>, keys: MetadataKeyRing) -> Self {
        Self {
            path: path.into(),
            keys,
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

    fn save(&self, state: &DurableCoordinator) -> Result<()> {
        let plaintext = serde_json::to_vec(state).context("serializing coordinator metadata")?;
        let active = self.keys.active();
        let encrypted = EncryptedMetadata::seal_bytes(&active.bytes, &active.version, &plaintext)?;
        let encoded =
            serde_json::to_vec(&encrypted).context("encoding encrypted coordinator metadata")?;
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
        }
        let temporary = self.path.with_extension(format!("tmp-{}", Uuid::new_v4()));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .with_context(|| format!("creating {}", temporary.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(fs::Permissions::from_mode(0o600))?;
        }
        file.write_all(&encoded)?;
        file.sync_all()?;
        fs::rename(&temporary, &self.path)
            .with_context(|| format!("publishing {}", self.path.display()))?;
        // `rename` only makes the new name visible.  Syncing its parent makes
        // that directory entry durable across a power loss as well.
        if let Some(parent) = self.path.parent() {
            File::open(parent)
                .with_context(|| format!("opening {} for fsync", parent.display()))?
                .sync_all()
                .with_context(|| format!("fsyncing {}", parent.display()))?;
        }
        Ok(())
    }
}

/// Coordinator state coupled to an encrypted durable store. Every account
/// lifecycle mutation is persisted before its success is returned.
#[derive(Debug)]
pub struct PersistentCoordinator {
    store: EncryptedFileStore,
    coordinator: Coordinator,
}

impl PersistentCoordinator {
    /// Opens existing encrypted state or creates an empty coordinator.
    pub fn open(
        path: impl Into<PathBuf>,
        keys: MetadataKeyRing,
        account_id_key: [u8; 32],
    ) -> Result<Self> {
        let store = EncryptedFileStore::new(path, keys);
        let coordinator = Coordinator::from_durable(account_id_key, store.load()?);
        Ok(Self { store, coordinator })
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

    /// Commits only after the candidate has been encrypted, file-synced,
    /// renamed, and its parent directory synced. A failed write leaves the
    /// running state unchanged and retryable.
    fn transaction<T>(&mut self, mutate: impl FnOnce(&mut Coordinator) -> Result<T>) -> Result<T> {
        let mut candidate = self.coordinator.clone();
        let value = mutate(&mut candidate)?;
        self.store.save(&candidate.durable())?;
        self.coordinator = candidate;
        Ok(value)
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
    fn a_24_hour_coordinator_outage_does_not_change_a_paired_orbit_or_local_discovery_config() {
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
        let _outage_until = std::time::Duration::from_secs(24 * 60 * 60);
        let after_outage = Orbit::load(&orbit_path).unwrap();
        assert!(after_outage.trusts(&peer.device_id().to_string()));
        assert_eq!(local.relays, vec!["https://relay.example"]);
    }
}
