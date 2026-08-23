//! The optional hosted coordination plane.
//!
//! This crate is intentionally not part of the orbit data path.  An orbit is
//! paired and authorised by device keys locally; the hosted plane only gives a
//! signed-in person a place to register those public keys and discover a
//! chosen relay/directory configuration.  Its absence therefore cannot turn
//! an already-paired orbit off.
//!
//! Authentication is deliberately outside this crate.  The canonical edge
//! service verifies its allow-listed providers and passes only a verified,
//! provider-neutral identity through this boundary.  This crate never owns a
//! provider client secret, authorization code, callback, browser cookie, or
//! bearer token.  Its store receives an opaque, domain-separated account id,
//! never the external subject, display name, or email address.

use std::collections::BTreeMap;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
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
const ENROLLMENT_GENERATION_DOMAIN: &[u8] = b"asterism.coordinator/enroll-generation/1\0";
const IDENTITY_DOMAIN: &[u8] = b"asterism.coordinator/account/1\0";
const ENROLLMENT_CHALLENGE_TTL_SECS: u64 = 10 * 60;
const MAX_ENROLLMENT_CHALLENGES_PER_ACCOUNT: usize = 32;
const MAX_DEVICES_PER_ACCOUNT: usize = 64;
const MAX_DISCOVERY_BYTES: usize = 4 * 1024;
const MAX_ACCOUNTS: usize = 4_096;
const MAX_DURABLE_STATE_BYTES: usize = 16 * 1024 * 1024;
const AES_GCM_TAG_BYTES: usize = 16;
// serde_json represents Vec<u8> as decimal values separated by commas. Four
// bytes per ciphertext byte plus fixed field overhead is its worst-case size.
const MAX_ENCRYPTED_METADATA_BYTES: usize =
    (MAX_DURABLE_STATE_BYTES + AES_GCM_TAG_BYTES) * 4 + 4 * 1024;
const MAX_HIGH_WATERMARK_BYTES: usize = 32;
const MAX_SESSION_BEARER_BYTES: usize = 8 * 1024;
const MAX_DEVICE_ID_BYTES: usize = 128;

/// Version advertised by both the Cloudflare edge and native clients.
pub const DEVICE_AUTHORIZATION_PROTOCOL: &str = "asterism-device-authorization/1";
/// RFC 8628 grant vocabulary used by the token polling request.
pub const DEVICE_AUTHORIZATION_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:device_code";

/// Provider selection vocabulary at the edge protocol boundary. This does not
/// give the coordinator any provider credential or callback responsibility.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthorizationProvider {
    Google,
    Github,
}

/// Request shared by CLI and Desktop when creating an edge-owned device
/// transaction. Desktop completion carries only a nonce; tokens remain on the
/// polling channel.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceAuthorizationRequest {
    pub provider: AuthorizationProvider,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deep_link_state: Option<String>,
}

impl fmt::Debug for DeviceAuthorizationRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeviceAuthorizationRequest")
            .field("provider", &self.provider)
            .field("redirect_uri", &self.redirect_uri)
            .field(
                "deep_link_state",
                &self.deep_link_state.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

impl DeviceAuthorizationRequest {
    pub fn cli(provider: AuthorizationProvider) -> Self {
        Self {
            provider,
            redirect_uri: None,
            deep_link_state: None,
        }
    }

    pub fn desktop(provider: AuthorizationProvider, state: &str) -> Result<Self> {
        if !(32..=128).contains(&state.len())
            || !state
                .chars()
                .all(|character| character.is_ascii_alphanumeric() || "_-".contains(character))
        {
            bail!("desktop deep-link state must be 32-128 URL-safe characters");
        }
        let request = Self {
            provider,
            redirect_uri: Some("asterism://auth/callback".into()),
            deep_link_state: Some(state.into()),
        };
        request.validate()?;
        Ok(request)
    }

    pub fn validate(&self) -> Result<()> {
        match (&self.redirect_uri, &self.deep_link_state) {
            (None, None) => Ok(()),
            (Some(uri), Some(state))
                if uri == "asterism://auth/callback"
                    && (32..=128).contains(&state.len())
                    && state.chars().all(|character| {
                        character.is_ascii_alphanumeric() || "_-".contains(character)
                    }) =>
            {
                Ok(())
            }
            _ => bail!("device authorization request is not a valid CLI or Desktop flow"),
        }
    }
}

/// RFC 8628-shaped response shared with `ast auth login` and Desktop.
/// The edge service owns the pending transaction and all browser/provider I/O.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceAuthorization {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    pub verification_uri_complete: String,
    pub expires_in: u64,
    pub interval: u64,
}

impl fmt::Debug for DeviceAuthorization {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeviceAuthorization")
            .field("device_code", &"[REDACTED]")
            .field("user_code", &"[REDACTED]")
            .field("verification_uri", &"[REDACTED]")
            .field("verification_uri_complete", &"[REDACTED]")
            .field("expires_in", &self.expires_in)
            .field("interval", &self.interval)
            .finish()
    }
}

impl DeviceAuthorization {
    /// Rejects unbounded or non-TLS responses before a client starts polling.
    pub fn validate(&self) -> Result<()> {
        if self.device_code.is_empty() || self.device_code.len() > 512 {
            bail!("device authorization code is invalid");
        }
        if self.user_code.is_empty() || self.user_code.len() > 64 {
            bail!("device authorization user code is invalid");
        }
        if self.expires_in == 0 || self.expires_in > 15 * 60 {
            bail!("device authorization expiry is outside the supported bound");
        }
        if self.interval == 0 || self.interval > 30 {
            bail!("device authorization polling interval is outside the supported bound");
        }
        for uri in [&self.verification_uri, &self.verification_uri_complete] {
            if !uri.starts_with("https://") || uri.len() > 2_048 {
                bail!("device authorization verification URI must be bounded HTTPS");
            }
        }
        Ok(())
    }
}

/// Wire request made by native clients while polling the edge authority.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceTokenRequest {
    pub device_code: String,
    pub grant_type: String,
}

impl fmt::Debug for DeviceTokenRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeviceTokenRequest")
            .field("device_code", &"[REDACTED]")
            .field("grant_type", &self.grant_type)
            .finish()
    }
}

impl DeviceTokenRequest {
    pub fn new(device_code: impl Into<String>) -> Result<Self> {
        let request = Self {
            device_code: device_code.into(),
            grant_type: DEVICE_AUTHORIZATION_GRANT_TYPE.to_owned(),
        };
        request.validate()?;
        Ok(request)
    }

    pub fn validate(&self) -> Result<()> {
        if self.device_code.is_empty() || self.device_code.len() > 512 {
            bail!("device authorization code is invalid");
        }
        if self.grant_type != DEVICE_AUTHORIZATION_GRANT_TYPE {
            bail!("device authorization grant type is invalid");
        }
        Ok(())
    }
}

/// Identity proven by the canonical edge authority.  `authority` is a stable
/// namespace controlled by the deployment, not provider-specific core logic.
/// Neither field is persisted; both are immediately keyed into an account id.
#[derive(Clone, PartialEq, Eq)]
pub struct VerifiedIdentity {
    pub authority: String,
    pub subject: String,
}

impl fmt::Debug for VerifiedIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedIdentity")
            .field("authority", &self.authority)
            .field("subject", &"[REDACTED]")
            .finish()
    }
}

impl VerifiedIdentity {
    pub fn new(authority: impl Into<String>, subject: impl Into<String>) -> Result<Self> {
        let identity = Self {
            authority: authority.into(),
            subject: subject.into(),
        };
        if identity.authority.trim().is_empty() || identity.authority.len() > 512 {
            bail!("verified identity authority is invalid");
        }
        if identity.subject.trim().is_empty() || identity.subject.len() > 512 {
            bail!("verified identity subject is invalid");
        }
        Ok(identity)
    }
}

/// Capability implemented by the canonical edge service's session verifier.
/// Core code sees the opaque bearer only at this call boundary and never
/// stores it. Implementations must verify signature, audience, expiry and
/// revocation before returning an identity.
pub trait VerifiedIdentitySource {
    fn verify_session(&self, bearer: &str) -> Result<VerifiedIdentity>;
}

/// Opaque account identifier persisted by the hosted service.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AccountId(String);

impl AccountId {
    /// A stable opaque identifier.  It is safe to show only to the account's
    /// authenticated session; it cannot be reversed into an external subject.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Opaque binding placed in an edge-issued session after sign-in.  Generation
/// changes whenever a deleted account is recreated, making every pre-deletion
/// session stale without storing provider tokens or session ids here.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountBinding {
    pub account_id: AccountId,
    pub generation: String,
}

impl fmt::Debug for AccountBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AccountBinding")
            .field("account_id", &self.account_id)
            .field("generation", &"[REDACTED]")
            .finish()
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
#[derive(Clone, PartialEq, Eq)]
pub struct EnrollmentChallenge {
    bytes: [u8; 32],
    generation_binding: [u8; 32],
}

impl fmt::Debug for EnrollmentChallenge {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("EnrollmentChallenge([REDACTED])")
    }
}

impl EnrollmentChallenge {
    /// Opaque wire representation for a one-time enrollment challenge.
    pub fn token(&self) -> String {
        let mut token = [0; 64];
        token[..32].copy_from_slice(&self.bytes);
        token[32..].copy_from_slice(&self.generation_binding);
        BASE64URL_NOPAD.encode(&token)
    }

    fn from_token(value: &str) -> Result<Self> {
        if value.len() != base64url_nopad_encoded_len(64) {
            bail!("enrollment challenge has invalid length");
        }
        let token = BASE64URL_NOPAD
            .decode(value.as_bytes())
            .context("decoding enrollment challenge")?;
        let token: [u8; 64] = token
            .try_into()
            .map_err(|_| anyhow!("enrollment challenge has invalid length"))?;
        let bytes = token[..32].try_into().expect("slice has 32 bytes");
        let generation_binding = token[32..].try_into().expect("slice has 32 bytes");
        Ok(Self {
            bytes,
            generation_binding,
        })
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
        if device_id.len() > MAX_DEVICE_ID_BYTES {
            bail!("invalid device id");
        }
        let public_key = asterism_mesh::iroh_types::PublicKey::from_str(device_id)
            .map_err(|_| anyhow!("invalid device id"))?;
        if signature.len() != base64url_nopad_encoded_len(Signature::LENGTH) {
            bail!("invalid enrollment signature");
        }
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
    if value.len() > MAX_DEVICE_ID_BYTES {
        bail!("invalid device id");
    }
    let key = asterism_mesh::iroh_types::PublicKey::from_str(value)
        .map_err(|_| anyhow!("invalid device id"))?;
    Ok(DeviceId::from_public_key(key))
}

/// Minimal, portable account export. External identity and bearer material are
/// intentionally not exportable because this service never stores them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountExport {
    /// Opaque account identifier.
    pub account_id: AccountId,
    /// Public device keys and discovery configuration only.
    pub devices: Vec<EnrolledDevice>,
}

#[derive(Debug, Clone)]
struct Account {
    generation: String,
    devices: BTreeMap<String, EnrolledDevice>,
    challenges: BTreeMap<[u8; 32], u64>,
}

impl Account {
    fn new() -> Self {
        Self {
            generation: random_token(),
            devices: BTreeMap::new(),
            challenges: BTreeMap::new(),
        }
    }
}

/// In-memory coordinator state.  A production HTTP adapter serializes only
/// [`AccountExport`] with [`EncryptedMetadata`]; callbacks, bearer tokens and
/// plaintext external subjects must never be put in this structure or log.
pub struct Coordinator {
    accounts: BTreeMap<AccountId, Account>,
    account_id_key: [u8; 32],
    sequence: u64,
    last_transaction: Option<String>,
}

impl fmt::Debug for Coordinator {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Coordinator")
            .field("accounts", &self.accounts.len())
            .field("account_id_key", &"[REDACTED]")
            .field("sequence", &self.sequence)
            .field("last_transaction", &self.last_transaction)
            .finish()
    }
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
    /// migration, never derived from an external identity subject.
    pub fn new(account_id_key: [u8; 32]) -> Self {
        Self {
            accounts: BTreeMap::new(),
            account_id_key,
            sequence: 0,
            last_transaction: None,
        }
    }
    /// Verifies an edge-owned session and creates or resumes its account.
    pub fn sign_in(
        &mut self,
        source: &impl VerifiedIdentitySource,
        bearer: &str,
    ) -> Result<AccountBinding> {
        validate_session_bearer(bearer)?;
        self.sign_in_identity(source.verify_session(bearer)?)
    }

    /// Accepts identity claims only after an embedding's trusted verifier has
    /// completed. This method does not parse tokens or know an OAuth provider.
    pub fn sign_in_identity(&mut self, identity: VerifiedIdentity) -> Result<AccountBinding> {
        let identity = VerifiedIdentity::new(identity.authority, identity.subject)?;
        let account_id = account_id(&self.account_id_key, &identity);
        if !self.accounts.contains_key(&account_id) && self.accounts.len() >= MAX_ACCOUNTS {
            bail!("coordinator account capacity reached");
        }
        let account = self
            .accounts
            .entry(account_id.clone())
            .or_insert_with(Account::new);
        Ok(AccountBinding {
            account_id,
            generation: account.generation.clone(),
        })
    }

    #[cfg(test)]
    fn binding_for_test(&self, account_id: &AccountId) -> Result<AccountBinding> {
        let account = self
            .accounts
            .get(account_id)
            .ok_or_else(|| anyhow!("account not found"))?;
        Ok(AccountBinding {
            account_id: account_id.clone(),
            generation: account.generation.clone(),
        })
    }

    /// Resolves an edge-issued binding against current durable account state.
    /// A binding issued before account deletion can never authorize a newly
    /// recreated account with the same opaque id.
    pub fn authorize(&self, binding: &AccountBinding) -> Result<()> {
        self.account(binding).map(|_| ())
    }

    /// Starts a single-use account-bound enrollment.
    pub fn begin_enrollment(&mut self, binding: &AccountBinding) -> Result<EnrollmentChallenge> {
        self.begin_enrollment_at(binding, unix_seconds()?)
    }

    /// Deterministic-clock variant used by lifecycle tests and production
    /// adapters that own an authoritative clock.
    pub fn begin_enrollment_at(
        &mut self,
        binding: &AccountBinding,
        now: u64,
    ) -> Result<EnrollmentChallenge> {
        let account = self.account_mut(binding)?;
        account.challenges.retain(|_, expiry| *expiry > now);
        if account.challenges.len() >= MAX_ENROLLMENT_CHALLENGES_PER_ACCOUNT {
            bail!("too many enrollment challenges are active");
        }
        loop {
            let challenge = EnrollmentChallenge {
                bytes: random_32(),
                generation_binding: enrollment_generation_binding(&account.generation),
            };
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
        binding: &AccountBinding,
        proof: EnrollmentProof,
        discovery: DiscoveryConfig,
    ) -> Result<EnrolledDevice> {
        self.enroll_at(binding, proof, discovery, unix_seconds()?)
    }

    /// Deterministic-clock variant that rejects expired challenges before any
    /// device mutation.
    pub fn enroll_at(
        &mut self,
        binding: &AccountBinding,
        proof: EnrollmentProof,
        discovery: DiscoveryConfig,
        now: u64,
    ) -> Result<EnrolledDevice> {
        discovery.validate()?;
        let account = self.account_mut(binding)?;
        account.challenges.retain(|_, expiry| *expiry > now);
        if proof.challenge.generation_binding != enrollment_generation_binding(&account.generation)
        {
            bail!("enrollment challenge belongs to a stale account generation");
        }
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
    pub fn revoke_device(&mut self, binding: &AccountBinding, device_id: &DeviceId) -> Result<()> {
        let removed = self
            .account_mut(binding)?
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
        binding: &AccountBinding,
        device_id: &DeviceId,
    ) -> Result<DiscoveryConfig> {
        self.account(binding)?
            .devices
            .get(&device_id.to_string())
            .map(|d| d.discovery.clone())
            .ok_or_else(|| anyhow!("device is not enrolled to this account"))
    }

    /// Exports the account's minimal hosted metadata.
    pub fn export_account(&self, binding: &AccountBinding) -> Result<AccountExport> {
        let account = self.account(binding)?;
        Ok(AccountExport {
            account_id: binding.account_id.clone(),
            devices: account.devices.values().cloned().collect(),
        })
    }

    /// Deletes the account and all hosted device configuration.  It cannot
    /// delete a device key, an orbit, or data held by an already-paired peer.
    pub fn delete_account(&mut self, binding: &AccountBinding) -> Result<()> {
        self.authorize(binding)?;
        self.accounts
            .remove(&binding.account_id)
            .map(|_| ())
            .ok_or_else(|| anyhow!("account not found"))
    }

    fn account(&self, binding: &AccountBinding) -> Result<&Account> {
        validate_generation(&binding.generation)
            .and_then(|()| {
                (binding.account_id.0.len() == 64)
                    .then_some(())
                    .ok_or_else(|| anyhow!("account session is stale or revoked"))
            })
            .map_err(|_| anyhow!("account session is stale or revoked"))?;
        let account = self
            .accounts
            .get(&binding.account_id)
            .ok_or_else(|| anyhow!("account session is stale or revoked"))?;
        if account.generation != binding.generation {
            bail!("account session is stale or revoked");
        }
        Ok(account)
    }

    fn account_mut(&mut self, binding: &AccountBinding) -> Result<&mut Account> {
        self.account(binding)?;
        self.accounts
            .get_mut(&binding.account_id)
            .ok_or_else(|| anyhow!("account session is stale or revoked"))
    }

    fn transaction_candidate(&self) -> Self {
        Self {
            accounts: self.accounts.clone(),
            account_id_key: self.account_id_key,
            sequence: self.sequence,
            last_transaction: self.last_transaction.clone(),
        }
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
                            generation: account.generation.clone(),
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
                            generation: account.generation,
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
    generation: String,
    devices: BTreeMap<String, EnrolledDevice>,
}

/// A named encryption key supplied by a deployment KMS adapter.  The version
/// is persisted beside the ciphertext, allowing a new active key to write
/// forward while old versions remain decrypt-only during rotation.
#[derive(Clone)]
pub struct MetadataKey {
    version: String,
    bytes: [u8; 32],
}

impl fmt::Debug for MetadataKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MetadataKey")
            .field("version", &self.version)
            .field("bytes", &"[REDACTED]")
            .finish()
    }
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
#[derive(Clone)]
pub struct MetadataKeyRing {
    active: MetadataKey,
    readable: BTreeMap<String, [u8; 32]>,
}

impl fmt::Debug for MetadataKeyRing {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MetadataKeyRing")
            .field("active", &self.active.version)
            .field(
                "readable_versions",
                &self.readable.keys().collect::<Vec<_>>(),
            )
            .finish()
    }
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
/// Authorization codes, access tokens, names, and subjects never enter this file.
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
        // A single-component relative path is different: `Path::parent()`
        // returns an empty lexical path, but the newly created entry lives in
        // the current directory and `.` must be synced before serving.
        let containing = match directory.parent() {
            Some(parent) if parent.as_os_str().is_empty() => Path::new("."),
            Some(parent) => parent,
            None => return Ok(()),
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
        let Some(bytes) = self.read_bounded_file(
            &self.sidecar_path(".highwater"),
            MAX_HIGH_WATERMARK_BYTES,
            "coordinator sequence high-watermark",
        )?
        else {
            return Ok(0);
        };
        std::str::from_utf8(&bytes)
            .context("decoding coordinator sequence high-watermark")?
            .trim()
            .parse()
            .context("parsing coordinator sequence high-watermark")
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
        let Some(encrypted) = self.read_encrypted_metadata()? else {
            return Ok(false);
        };
        Ok(encrypted.key_version != self.keys.active().version)
    }

    fn load(&self) -> Result<DurableCoordinator> {
        let Some(encrypted) = self.read_encrypted_metadata()? else {
            return Ok(DurableCoordinator::default());
        };
        let plaintext = encrypted.open_bytes(self.keys.read(&encrypted.key_version)?)?;
        if plaintext.len() > MAX_DURABLE_STATE_BYTES {
            bail!("coordinator durable state exceeds {MAX_DURABLE_STATE_BYTES} bytes");
        }
        serde_json::from_slice(&plaintext).context("parsing coordinator metadata")
    }

    fn read_encrypted_metadata(&self) -> Result<Option<EncryptedMetadata>> {
        let Some(bytes) = self.read_bounded_file(
            &self.path,
            MAX_ENCRYPTED_METADATA_BYTES,
            "encrypted coordinator metadata",
        )?
        else {
            return Ok(None);
        };
        let encrypted: EncryptedMetadata =
            serde_json::from_slice(&bytes).context("parsing encrypted coordinator metadata")?;
        encrypted.validate_bounds()?;
        Ok(Some(encrypted))
    }

    fn read_bounded_file(
        &self,
        path: &Path,
        maximum: usize,
        description: &str,
    ) -> Result<Option<Vec<u8>>> {
        let file = match File::open(path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(error).with_context(|| format!("reading {description}"));
            }
        };
        let length = file
            .metadata()
            .with_context(|| format!("inspecting {description}"))?
            .len();
        if length > maximum as u64 {
            bail!("{description} exceeds {maximum} bytes");
        }

        let mut bytes = Vec::with_capacity(length as usize);
        file.take(maximum as u64 + 1)
            .read_to_end(&mut bytes)
            .with_context(|| format!("reading {description}"))?;
        if bytes.len() > maximum {
            bail!("{description} exceeds {maximum} bytes");
        }
        Ok(Some(bytes))
    }

    fn save(&self, state: &DurableCoordinator) -> std::result::Result<(), CommitError> {
        let plaintext = serde_json::to_vec(state)
            .context("serializing coordinator metadata")
            .map_err(CommitError::BeforePublish)?;
        if plaintext.len() > MAX_DURABLE_STATE_BYTES {
            return Err(CommitError::BeforePublish(anyhow!(
                "coordinator durable state exceeds {MAX_DURABLE_STATE_BYTES} bytes"
            )));
        }
        let active = self.keys.active();
        let encrypted = EncryptedMetadata::seal_bytes(&active.bytes, &active.version, &plaintext)
            .map_err(CommitError::BeforePublish)?;
        let encoded = serde_json::to_vec(&encrypted)
            .context("encoding encrypted coordinator metadata")
            .map_err(CommitError::BeforePublish)?;
        if encoded.len() > MAX_ENCRYPTED_METADATA_BYTES {
            return Err(CommitError::BeforePublish(anyhow!(
                "encrypted coordinator metadata exceeds {MAX_ENCRYPTED_METADATA_BYTES} bytes"
            )));
        }
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

impl Drop for PersistentCoordinator {
    fn drop(&mut self) {
        // Closing a lock file normally releases its advisory lock. Explicitly
        // unlock first as well so a concurrently spawned child cannot prolong
        // the writer lifetime with an inherited copy of the descriptor.
        let _ = self._writer_lock.unlock();
    }
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

    /// Verifies an edge session and durably records the account shell if new.
    pub fn sign_in(
        &mut self,
        source: &impl VerifiedIdentitySource,
        bearer: &str,
    ) -> Result<AccountBinding> {
        validate_session_bearer(bearer)?;
        let identity = source.verify_session(bearer)?;
        self.sign_in_identity(identity)
    }

    /// Durably records an identity already verified by the embedding.
    pub fn sign_in_identity(&mut self, identity: VerifiedIdentity) -> Result<AccountBinding> {
        self.transaction(|candidate| candidate.sign_in_identity(identity))
    }

    #[cfg(test)]
    fn binding_for_test(&self, account: &AccountId) -> Result<AccountBinding> {
        self.coordinator.binding_for_test(account)
    }

    /// Checks an edge-issued account binding against current durable state.
    pub fn authorize(&self, binding: &AccountBinding) -> Result<()> {
        self.coordinator.authorize(binding)
    }

    /// Begins a short-lived enrollment challenge after validating the session
    /// generation in the same serialized operation.
    pub fn begin_enrollment(&mut self, binding: &AccountBinding) -> Result<EnrollmentChallenge> {
        self.transaction(|candidate| candidate.begin_enrollment(binding))
    }

    /// Enrolls a device and persists it before responding.
    pub fn enroll(
        &mut self,
        binding: &AccountBinding,
        proof: EnrollmentProof,
        discovery: DiscoveryConfig,
    ) -> Result<EnrolledDevice> {
        self.transaction(|candidate| candidate.enroll(binding, proof, discovery))
    }

    /// Revokes a device durably.
    pub fn revoke_device(&mut self, binding: &AccountBinding, device: &DeviceId) -> Result<()> {
        self.transaction(|candidate| candidate.revoke_device(binding, device))
    }

    /// Returns discovery configuration only after checking the binding against
    /// the same immutable state snapshot used for the read.
    pub fn discovery_for(
        &self,
        binding: &AccountBinding,
        device: &DeviceId,
    ) -> Result<DiscoveryConfig> {
        self.coordinator.discovery_for(binding, device)
    }

    /// Exports minimal metadata.
    pub fn export_account(&self, binding: &AccountBinding) -> Result<AccountExport> {
        self.coordinator.export_account(binding)
    }

    /// Deletes hosted data durably. All bindings immediately fail because the
    /// account no longer exists; a later recreation gets a fresh generation.
    pub fn delete_account(&mut self, binding: &AccountBinding) -> Result<()> {
        self.transaction(|candidate| candidate.delete_account(binding))
    }

    /// Session-authorized deletion combines the generation check and removal
    /// in one bounded durable transaction.
    pub fn delete_account_session(&mut self, binding: &AccountBinding) -> Result<()> {
        self.delete_account(binding)
    }

    /// Commits a sequenced transaction. The store cannot return success after
    /// rename until its parent-directory entry is confirmed durable.
    fn transaction<T>(&mut self, mutate: impl FnOnce(&mut Coordinator) -> Result<T>) -> Result<T> {
        let mut candidate = self.coordinator.transaction_candidate();
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
/// 32-byte KMS-managed key; this type never derives it from an external identity.
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
        self.validate_bounds()?;
        let cipher = Aes256Gcm::new_from_slice(key).expect("AES-256 keys are exactly 32 bytes");
        cipher
            .decrypt(Nonce::from_slice(&self.nonce), self.ciphertext.as_ref())
            .map_err(|_| anyhow!("account metadata cannot be decrypted"))
    }

    fn validate_bounds(&self) -> Result<()> {
        if self.key_version.trim().is_empty() || self.key_version.len() > 128 {
            bail!("encrypted metadata key version is invalid");
        }
        if self.ciphertext.len() > MAX_DURABLE_STATE_BYTES + AES_GCM_TAG_BYTES {
            bail!("encrypted coordinator ciphertext exceeds its durable state bound");
        }
        Ok(())
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

fn account_id(key: &[u8; 32], identity: &VerifiedIdentity) -> AccountId {
    let mut hash = blake3::Hasher::new_keyed(key);
    hash.update(IDENTITY_DOMAIN);
    hash.update(identity.authority.as_bytes());
    hash.update(&[0]);
    hash.update(identity.subject.as_bytes());
    AccountId(hash.finalize().to_hex().to_string())
}

fn enrollment_message(challenge: &EnrollmentChallenge) -> Vec<u8> {
    [
        ENROLLMENT_DOMAIN,
        &challenge.generation_binding,
        &challenge.bytes,
    ]
    .concat()
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

fn random_token() -> String {
    BASE64URL_NOPAD.encode(&random_32())
}

fn enrollment_generation_binding(generation: &str) -> [u8; 32] {
    let mut hash = blake3::Hasher::new();
    hash.update(ENROLLMENT_GENERATION_DOMAIN);
    hash.update(generation.as_bytes());
    *hash.finalize().as_bytes()
}

const fn base64url_nopad_encoded_len(decoded_bytes: usize) -> usize {
    (decoded_bytes * 8).div_ceil(6)
}

fn validate_session_bearer(bearer: &str) -> Result<()> {
    if bearer.trim().is_empty() || bearer.len() > MAX_SESSION_BEARER_BYTES {
        bail!("hosted session bearer is invalid");
    }
    Ok(())
}

fn validate_generation(value: &str) -> Result<()> {
    if value.len() != base64url_nopad_encoded_len(32) {
        bail!("account generation is invalid");
    }
    let decoded = BASE64URL_NOPAD
        .decode(value.as_bytes())
        .map_err(|_| anyhow!("account generation is invalid"))?;
    if decoded.len() != 32 {
        bail!("account generation is invalid");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use asterism_core::orbit::{device_now, Orbit};
    use asterism_mesh::{
        pairing, DeviceIdentity, IssuedTicket, MeshEndpoint, MeshMode, PairingTicket,
        DEFAULT_TICKET_TTL,
    };
    use std::process::Command;
    use std::sync::{Barrier, Mutex};
    use tempfile::tempdir;
    use tokio::time::Duration;

    struct Edge(&'static str, &'static str, bool);
    impl VerifiedIdentitySource for Edge {
        fn verify_session(&self, _: &str) -> Result<VerifiedIdentity> {
            if !self.2 {
                bail!("edge session validation failed");
            }
            VerifiedIdentity::new(self.0, self.1)
        }
    }

    fn google() -> Edge {
        Edge("https://auth.asterism.run/google", "opaque-subject", true)
    }

    fn missing_binding(account_id: AccountId) -> AccountBinding {
        AccountBinding {
            account_id,
            generation: BASE64URL_NOPAD.encode(&[0; 32]),
        }
    }

    #[test]
    fn canonical_edge_is_the_only_identity_authority_core_needs() {
        let mut service = Coordinator::new([1; 32]);
        let google_binding = service.sign_in(&google(), "opaque-session").unwrap();
        let github_binding = service
            .sign_in(
                &Edge("https://auth.asterism.run/github", "42", true),
                "opaque-session",
            )
            .unwrap();
        assert_ne!(google_binding.account_id, github_binding.account_id);
        assert!(service
            .sign_in(&Edge("unused", "unused", false), "forged-session")
            .is_err());
        assert!(VerifiedIdentity::new("", "subject").is_err());
    }

    #[test]
    fn encoded_enrollment_fields_enforce_bounds_before_base64_decode() {
        let mut service = Coordinator::new([1; 32]);
        let binding = service.sign_in(&google(), "opaque-session").unwrap();
        let challenge = service.begin_enrollment(&binding).unwrap().token();
        let device_id = DeviceIdentity::generate().device_id().to_string();
        let signature = BASE64URL_NOPAD.encode(&[0; Signature::LENGTH]);
        let generation = BASE64URL_NOPAD.encode(&[0; 32]);

        assert_eq!(challenge.len(), base64url_nopad_encoded_len(64));
        assert!(EnrollmentChallenge::from_token(&challenge).is_ok());
        assert!(EnrollmentChallenge::from_token(&format!("{challenge}A")).is_err());

        assert_eq!(
            signature.len(),
            base64url_nopad_encoded_len(Signature::LENGTH)
        );
        assert!(EnrollmentProof::from_tokens(&device_id, &challenge, &signature).is_ok());
        assert!(
            EnrollmentProof::from_tokens(&device_id, &challenge, &format!("{signature}A")).is_err()
        );

        assert_eq!(generation.len(), base64url_nopad_encoded_len(32));
        assert!(validate_generation(&generation).is_ok());
        assert!(validate_generation(&format!("{generation}A")).is_err());
    }

    #[test]
    fn persistent_sign_in_enforces_the_session_bearer_limit() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("state.enc");
        let keys = MetadataKeyRing::new(MetadataKey::new("kms-v1", [1; 32]).unwrap(), []).unwrap();
        let mut service = PersistentCoordinator::open(&path, keys, [2; 32]).unwrap();

        assert!(service
            .sign_in(&google(), &"x".repeat(MAX_SESSION_BEARER_BYTES))
            .is_ok());
        assert!(service
            .sign_in(&google(), &"x".repeat(MAX_SESSION_BEARER_BYTES + 1))
            .is_err());
    }

    #[test]
    fn device_authorization_wire_contract_matches_native_clients() {
        assert_eq!(
            DEVICE_AUTHORIZATION_PROTOCOL,
            "asterism-device-authorization/1"
        );
        let response: DeviceAuthorization = serde_json::from_value(serde_json::json!({
            "device_code": "opaque-device-secret",
            "user_code": "ABCD-EFGH",
            "verification_uri": "https://auth.asterism.run/oauth/device",
            "verification_uri_complete": "https://auth.asterism.run/oauth/device?user_code=ABCD-EFGH",
            "expires_in": 600,
            "interval": 5
        }))
        .unwrap();
        response.validate().unwrap();
        assert_eq!(
            serde_json::to_value(DeviceAuthorizationRequest::cli(
                AuthorizationProvider::Github
            ))
            .unwrap(),
            serde_json::json!({ "provider": "github" })
        );
        DeviceAuthorizationRequest::cli(AuthorizationProvider::Github)
            .validate()
            .unwrap();
        assert_eq!(
            serde_json::to_value(DeviceTokenRequest::new(response.device_code.clone()).unwrap())
                .unwrap(),
            serde_json::json!({
                "device_code": "opaque-device-secret",
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code"
            })
        );
        let mut invalid = response;
        invalid.verification_uri = "http://auth.invalid/device".into();
        assert!(invalid.validate().is_err());
        let desktop = DeviceAuthorizationRequest::desktop(
            AuthorizationProvider::Google,
            "0123456789abcdef0123456789abcdef",
        )
        .unwrap();
        assert_eq!(
            desktop.redirect_uri.as_deref(),
            Some("asterism://auth/callback")
        );
        assert!(
            DeviceAuthorizationRequest::desktop(AuthorizationProvider::Google, "short").is_err()
        );
        let wrong_grant = DeviceTokenRequest {
            device_code: "opaque-device-secret".into(),
            grant_type: "authorization_code".into(),
        };
        assert!(wrong_grant.validate().is_err());
    }

    #[test]
    fn identity_session_device_codes_and_kms_keys_are_debug_redacted() {
        let identity = VerifiedIdentity::new("edge", "provider-subject-secret").unwrap();
        let authorization = DeviceAuthorization {
            device_code: "device-code-secret".into(),
            user_code: "ABCD-EFGH".into(),
            verification_uri: "https://auth.asterism.run/oauth/device".into(),
            verification_uri_complete: "https://auth.asterism.run/oauth/device?user_code=ABCD-EFGH"
                .into(),
            expires_in: 600,
            interval: 5,
        };
        let request = DeviceTokenRequest::new("device-code-secret").unwrap();
        let key = MetadataKey::new("kms-v1", [7; 32]).unwrap();
        let debug = format!("{identity:?} {authorization:?} {request:?} {key:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("provider-subject-secret"));
        assert!(!debug.contains("device-code-secret"));
        assert!(!debug.contains("ABCD-EFGH"));
        assert!(!debug.contains("user_code="));
        assert!(!debug.contains("https://auth.asterism.run/oauth/device"));
        assert!(!debug.contains(&format!("{:?}", [7_u8; 32])));
    }

    #[test]
    fn authorized_before_delete_operations_cannot_cross_generation_after_restart() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("state.enc");
        let keys = MetadataKeyRing::new(MetadataKey::new("kms-v1", [31; 32]).unwrap(), []).unwrap();
        let identity = VerifiedIdentity::new("edge-authority", "stable-subject").unwrap();
        let mut service = PersistentCoordinator::open(&path, keys.clone(), [32; 32]).unwrap();
        let old = service.sign_in_identity(identity.clone()).unwrap();
        let account = old.account_id.clone();
        let stale_device = asterism_mesh::DeviceIdentity::generate();
        let stale_challenge = service.begin_enrollment(&old).unwrap();
        let stale_proof = enrollment_proof(&stale_device, stale_challenge);
        let current_device = asterism_mesh::DeviceIdentity::generate();
        let current_device_id = current_device.device_id();

        service.store.inject(FaultPoint::Rename);
        assert!(service.delete_account_session(&old).is_err());
        service.authorize(&old).unwrap();
        service.store.fault = None;

        let shared = Arc::new(Mutex::new(Some(service)));
        let authorized = Arc::new(Barrier::new(2));
        let resume = Arc::new(Barrier::new(2));
        let delayed = {
            let shared = Arc::clone(&shared);
            let authorized = Arc::clone(&authorized);
            let resume = Arc::clone(&resume);
            let old = old.clone();
            std::thread::spawn(move || {
                shared
                    .lock()
                    .unwrap()
                    .as_ref()
                    .unwrap()
                    .authorize(&old)
                    .unwrap();
                authorized.wait();
                resume.wait();
                let mut guard = shared.lock().unwrap();
                let service = guard.as_mut().unwrap();
                [
                    service.begin_enrollment(&old).is_err(),
                    service
                        .enroll(&old, stale_proof, DiscoveryConfig::default())
                        .is_err(),
                    service.revoke_device(&old, &current_device_id).is_err(),
                    service.discovery_for(&old, &current_device_id).is_err(),
                    service.export_account(&old).is_err(),
                    service.delete_account(&old).is_err(),
                ]
            })
        };

        authorized.wait();
        let mut service = shared.lock().unwrap().take().unwrap();
        service.delete_account_session(&old).unwrap();
        drop(service);

        let mut service = PersistentCoordinator::open(&path, keys.clone(), [32; 32]).unwrap();
        assert!(service.authorize(&old).is_err());
        let fresh = service.sign_in_identity(identity).unwrap();
        assert_eq!(fresh.account_id, account);
        assert_ne!(fresh.generation, old.generation);
        let challenge = service.begin_enrollment(&fresh).unwrap();
        let current_config = DiscoveryConfig {
            relays: vec!["https://g2-relay.example".into()],
            ..Default::default()
        };
        service
            .enroll(
                &fresh,
                enrollment_proof(&current_device, challenge),
                current_config.clone(),
            )
            .unwrap();
        drop(service);

        let restarted = PersistentCoordinator::open(&path, keys, [32; 32]).unwrap();
        *shared.lock().unwrap() = Some(restarted);
        resume.wait();
        assert!(delayed.join().unwrap().into_iter().all(|refused| refused));

        let guard = shared.lock().unwrap();
        let restarted = guard.as_ref().unwrap();
        restarted.authorize(&fresh).unwrap();
        assert_eq!(
            restarted
                .discovery_for(&fresh, &current_device.device_id())
                .unwrap(),
            current_config
        );
        assert_eq!(restarted.export_account(&fresh).unwrap().devices.len(), 1);
    }

    #[test]
    fn enrollment_revoke_export_and_deletion_are_account_bound() {
        let mut service = Coordinator::new([1; 32]);
        let binding = service.sign_in(&google(), "code").unwrap();
        let device = asterism_mesh::DeviceIdentity::generate();
        let challenge = service.begin_enrollment(&binding).unwrap();
        assert_eq!(
            EnrollmentChallenge::from_token(&challenge.token()).unwrap(),
            challenge
        );
        let config = DiscoveryConfig {
            relays: vec!["https://relay.example".into()],
            pkarr_relay: Some("https://directory.example/pkarr".into()),
            dns_origin: None,
        };
        service
            .enroll(
                &binding,
                enrollment_proof(&device, challenge.clone()),
                config.clone(),
            )
            .unwrap();
        assert_eq!(
            service
                .discovery_for(&binding, &device.device_id())
                .unwrap(),
            config
        );
        assert!(
            service
                .enroll(
                    &binding,
                    enrollment_proof(&device, challenge),
                    DiscoveryConfig::default()
                )
                .is_err(),
            "challenges are single use"
        );
        let exported = service.export_account(&binding).unwrap();
        assert_eq!(exported.devices.len(), 1);
        assert!(!serde_json::to_string(&exported)
            .unwrap()
            .contains("opaque-google-subject"));
        service
            .revoke_device(&binding, &device.device_id())
            .unwrap();
        assert!(service
            .discovery_for(&binding, &device.device_id())
            .is_err());
        service.delete_account(&binding).unwrap();
        assert!(service.export_account(&binding).is_err());
    }

    #[test]
    fn a_forged_proof_cannot_burn_another_devices_enrollment_challenge() {
        let mut service = Coordinator::new([1; 32]);
        let binding = service.sign_in(&google(), "code").unwrap();
        let device = asterism_mesh::DeviceIdentity::generate();
        let attacker = asterism_mesh::DeviceIdentity::generate();
        let challenge = service.begin_enrollment(&binding).unwrap();
        let forged = EnrollmentProof {
            device_id: device.device_id(),
            challenge: challenge.clone(),
            signature: attacker.sign(&enrollment_message(&challenge)),
        };
        assert!(service
            .enroll(&binding, forged, DiscoveryConfig::default())
            .is_err());
        let mut wrong_generation = challenge.clone();
        wrong_generation.generation_binding[0] ^= 0xff;
        assert!(service
            .enroll(
                &binding,
                enrollment_proof(&device, wrong_generation),
                DiscoveryConfig::default(),
            )
            .is_err());
        service
            .enroll(
                &binding,
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
        let binding = {
            let mut service = PersistentCoordinator::open(
                &path,
                MetadataKeyRing::new(MetadataKey::new("test-v1", metadata_key).unwrap(), [])
                    .unwrap(),
                account_key,
            )
            .unwrap();
            let binding = service
                .sign_in_identity(VerifiedIdentity {
                    authority: "https://accounts.google.com".into(),
                    subject: "provider-subject-never-on-disk".into(),
                })
                .unwrap();
            let challenge = service.begin_enrollment(&binding).unwrap();
            service
                .enroll(
                    &binding,
                    enrollment_proof(&device, challenge),
                    DiscoveryConfig {
                        relays: vec!["https://third-party-relay.example".into()],
                        ..Default::default()
                    },
                )
                .unwrap();
            binding
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
                .discovery_for(&binding, &device.device_id())
                .unwrap()
                .relays,
            vec!["https://third-party-relay.example"]
        );
        assert_eq!(restarted.export_account(&binding).unwrap().devices.len(), 1);
        restarted.delete_account(&binding).unwrap();
        drop(restarted);
        let after_delete = PersistentCoordinator::open(
            &path,
            MetadataKeyRing::new(MetadataKey::new("test-v1", metadata_key).unwrap(), []).unwrap(),
            account_key,
        )
        .unwrap();
        assert!(after_delete.export_account(&binding).is_err());
    }

    #[test]
    fn account_ids_are_keyed_and_not_enumerable_from_the_subject() {
        let claims = VerifiedIdentity {
            authority: "https://github.com".into(),
            subject: "42".into(),
        };
        assert_ne!(account_id(&[1; 32], &claims), account_id(&[2; 32], &claims));
    }

    #[test]
    fn existing_sign_in_is_a_durable_noop_and_state_caps_are_enforced() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("state.enc");
        let keys = MetadataKeyRing::new(MetadataKey::new("kms-v1", [21; 32]).unwrap(), []).unwrap();
        let claims = VerifiedIdentity {
            authority: "https://accounts.google.com".into(),
            subject: "bounded-account".into(),
        };
        let mut service = PersistentCoordinator::open(&path, keys, [22; 32]).unwrap();
        let binding = service.sign_in_identity(claims.clone()).unwrap();
        let before = fs::read(&path).unwrap();
        service.sign_in_identity(claims).unwrap();
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
        let challenge = service.begin_enrollment(&binding).unwrap();
        assert!(service
            .enroll(&binding, enrollment_proof(&device, challenge), oversized)
            .is_err());

        for _ in 0..MAX_DEVICES_PER_ACCOUNT {
            let device = asterism_mesh::DeviceIdentity::generate();
            let challenge = service.begin_enrollment(&binding).unwrap();
            service
                .enroll(
                    &binding,
                    enrollment_proof(&device, challenge),
                    DiscoveryConfig::default(),
                )
                .unwrap();
        }
        let extra = asterism_mesh::DeviceIdentity::generate();
        let challenge = service.begin_enrollment(&binding).unwrap();
        assert!(service
            .enroll(
                &binding,
                enrollment_proof(&extra, challenge),
                DiscoveryConfig::default(),
            )
            .is_err());
    }

    #[test]
    fn metadata_key_rotation_reads_old_ciphertext_then_rewraps_with_the_new_version() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("coordinator.enc.json");
        let claims = VerifiedIdentity {
            authority: "https://accounts.google.com".into(),
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
            service.sign_in_identity(claims.clone()).unwrap();
        }
        {
            let mut service = PersistentCoordinator::open(
                &path,
                MetadataKeyRing::new(v2.clone(), [v1]).unwrap(),
                [9; 32],
            )
            .unwrap();
            service.sign_in_identity(claims).unwrap(); // causes a v2 write
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
        let claims = VerifiedIdentity {
            authority: "https://github.com".into(),
            subject: "99".into(),
        };
        let expected = account_id(&[4; 32], &claims);
        let missing = missing_binding(expected);
        let mut service = PersistentCoordinator::open(&path, keys, [4; 32]).unwrap();
        fs::remove_dir_all(directory.path().join("state")).unwrap_or(());
        // Make the parent a file, so create_dir_all/save fails deterministically.
        fs::write(directory.path().join("state"), b"not a directory").unwrap();
        assert!(service.sign_in_identity(claims).is_err());
        assert!(
            service.export_account(&missing).is_err(),
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
            let claims = VerifiedIdentity {
                authority: "https://accounts.google.com".into(),
                subject: "fault-matrix".into(),
            };
            let expected = account_id(&[6; 32], &claims);
            let missing = missing_binding(expected.clone());
            let mut service = PersistentCoordinator::open(&path, keys.clone(), [6; 32]).unwrap();
            service.store.inject_failures(point, 1);
            let result = service.sign_in_identity(claims.clone());
            assert!(result.is_err(), "{point:?}");
            assert!(service.export_account(&missing).is_err());
            service.store.fault = None;
            let binding = service.sign_in_identity(claims.clone()).unwrap();
            assert_eq!(binding.account_id, expected);
            assert!(service.export_account(&binding).is_ok());
            // Model a descriptor inherited by a concurrently spawned test
            // helper: coordinator teardown must still end this writer's lock.
            let inherited_writer = service._writer_lock.try_clone().unwrap();
            drop(service);
            let restarted = PersistentCoordinator::open(&path, keys, [6; 32]).unwrap();
            assert!(
                restarted.export_account(&binding).is_ok(),
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
            drop(inherited_writer);
        }
    }

    #[test]
    fn clean_host_directory_loss_never_erases_acknowledged_lifecycle_mutations() {
        let directory = tempdir().unwrap();
        let fresh_install = directory.path().join("var/lib/asterism");
        let path = fresh_install.join("coordinator.enc.json");
        let keys = MetadataKeyRing::new(MetadataKey::new("kms-v1", [13; 32]).unwrap(), []).unwrap();
        let account_key = [14; 32];
        let claims = VerifiedIdentity {
            authority: "https://accounts.google.com".into(),
            subject: "clean-host-account".into(),
        };
        let account = account_id(&account_key, &claims);
        let missing = missing_binding(account.clone());

        let mut first_boot = PersistentCoordinator::open(&path, keys.clone(), account_key).unwrap();
        first_boot.store.inject(FaultPoint::DirectoryParentFsync);
        assert!(
            first_boot.sign_in_identity(claims.clone()).is_err(),
            "a new directory whose containing entry was not synced must not acknowledge"
        );
        drop(first_boot);

        // Model a crash/remount dropping the newly created but deliberately
        // unsynced `var` entry. No successful response escaped that boundary.
        fs::remove_dir_all(directory.path().join("var")).unwrap();
        let after_unacknowledged_loss =
            PersistentCoordinator::open(&path, keys.clone(), account_key).unwrap();
        assert!(after_unacknowledged_loss.export_account(&missing).is_err());
        drop(after_unacknowledged_loss);

        // A successful clean-host write has synced `var` in the test root,
        // `lib` in `var`, `asterism` in `lib`, and finally the state filename.
        // Each acknowledged lifecycle mutation must then survive a restart.
        let mut service = PersistentCoordinator::open(&path, keys.clone(), account_key).unwrap();
        let binding = service.sign_in_identity(claims).unwrap();
        assert_eq!(binding.account_id, account);
        let device = asterism_mesh::DeviceIdentity::generate();
        let challenge = service.begin_enrollment(&binding).unwrap();
        service
            .enroll(
                &binding,
                enrollment_proof(&device, challenge),
                DiscoveryConfig::default(),
            )
            .unwrap();
        drop(service);

        let mut restarted = PersistentCoordinator::open(&path, keys.clone(), account_key).unwrap();
        assert!(restarted
            .discovery_for(&binding, &device.device_id())
            .is_ok());
        restarted
            .revoke_device(&binding, &device.device_id())
            .unwrap();
        drop(restarted);

        let mut restarted = PersistentCoordinator::open(&path, keys.clone(), account_key).unwrap();
        assert!(restarted
            .discovery_for(&binding, &device.device_id())
            .is_err());
        restarted.delete_account(&binding).unwrap();
        drop(restarted);

        let restarted = PersistentCoordinator::open(&path, keys, account_key).unwrap();
        assert!(restarted.export_account(&binding).is_err());
    }

    #[test]
    fn relative_clean_host_subprocess_helper() {
        let Some(mode) = std::env::var_os("ASTERISM_RELATIVE_PARENT_MODE") else {
            return;
        };
        let acknowledgment = PathBuf::from(
            std::env::var_os("ASTERISM_RELATIVE_PARENT_ACK")
                .expect("relative-parent acknowledgment path"),
        );
        let path = PathBuf::from("state/coordinator.enc.json");
        let keys = MetadataKeyRing::new(MetadataKey::new("kms-v1", [23; 32]).unwrap(), []).unwrap();
        let account_key = [24; 32];
        let claims = VerifiedIdentity {
            authority: "https://accounts.google.com".into(),
            subject: "relative-clean-host".into(),
        };
        let account = account_id(&account_key, &claims);

        match mode.to_str().expect("relative-parent mode is UTF-8") {
            "fail-directory-sync" => {
                assert!(!Path::new("state").exists());
                assert!(PersistentCoordinator::open_inner(
                    path,
                    keys,
                    account_key,
                    Some(FaultPoint::DirectoryParentFsync),
                )
                .is_err());
            }
            "mutate-then-crash" => {
                assert!(!Path::new("state").exists());
                let mut service = PersistentCoordinator::open(path, keys, account_key).unwrap();
                assert_eq!(
                    service.sign_in_identity(claims).unwrap().account_id,
                    account
                );
                fs::write(acknowledgment, b"acknowledged").unwrap();
                std::process::exit(86);
            }
            "verify-restart" => {
                let service = PersistentCoordinator::open(path, keys, account_key).unwrap();
                let binding = service.binding_for_test(&account).unwrap();
                assert!(service.export_account(&binding).is_ok());
            }
            other => panic!("unexpected relative-parent helper mode: {other}"),
        }
    }

    #[test]
    fn relative_clean_host_parent_is_durable_before_acknowledgement() {
        let directory = tempdir().unwrap();
        let state_directory = directory.path().join("state");
        let acknowledgment = directory.path().join("acknowledged");
        let helper = |mode: &str| {
            Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "tests::relative_clean_host_subprocess_helper",
                    "--nocapture",
                ])
                .current_dir(directory.path())
                .env("ASTERISM_RELATIVE_PARENT_MODE", mode)
                .env("ASTERISM_RELATIVE_PARENT_ACK", &acknowledgment)
                .status()
                .unwrap()
        };

        assert!(!state_directory.exists());
        assert!(helper("fail-directory-sync").success());
        assert!(state_directory.exists());
        assert!(
            !acknowledgment.exists(),
            "an unsynced relative parent must not allow acknowledgment"
        );

        // Model the crash/remount outcome for the deliberately unsynced entry.
        fs::remove_dir_all(&state_directory).unwrap();
        assert!(!state_directory.exists());

        let crashed = helper("mutate-then-crash");
        assert_eq!(crashed.code(), Some(86));
        assert!(acknowledgment.exists());
        assert!(
            state_directory.exists(),
            "the synced relative parent disappeared after the process crash"
        );
        assert!(helper("verify-restart").success());
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
            .sign_in_identity(VerifiedIdentity {
                authority: "https://accounts.google.com".into(),
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
    fn startup_high_watermark_accepts_limit_and_rejects_limit_plus_one() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("state.enc");
        let high_watermark = directory.path().join("state.enc.highwater");
        let keys = MetadataKeyRing::new(MetadataKey::new("kms-v1", [17; 32]).unwrap(), []).unwrap();

        fs::write(&high_watermark, "0".repeat(MAX_HIGH_WATERMARK_BYTES)).unwrap();
        let service = PersistentCoordinator::open(&path, keys.clone(), [18; 32]).unwrap();
        drop(service);

        fs::write(&high_watermark, "0".repeat(MAX_HIGH_WATERMARK_BYTES + 1)).unwrap();
        let error = PersistentCoordinator::open(&path, keys, [18; 32]).unwrap_err();
        assert!(format!("{error:#}").contains("high-watermark exceeds"));
    }

    #[test]
    fn startup_encrypted_envelope_accepts_limit_and_rejects_limit_plus_one() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("state.enc");
        let keys = MetadataKeyRing::new(MetadataKey::new("kms-v1", [19; 32]).unwrap(), []).unwrap();

        File::create(&path)
            .unwrap()
            .set_len(MAX_ENCRYPTED_METADATA_BYTES as u64)
            .unwrap();
        let at_limit = PersistentCoordinator::open(&path, keys.clone(), [20; 32]).unwrap_err();
        let at_limit = format!("{at_limit:#}");
        assert!(at_limit.contains("parsing encrypted coordinator metadata"));
        assert!(!at_limit.contains("exceeds"));

        File::create(&path)
            .unwrap()
            .set_len(MAX_ENCRYPTED_METADATA_BYTES as u64 + 1)
            .unwrap();
        let over_limit = PersistentCoordinator::open(&path, keys, [20; 32]).unwrap_err();
        assert!(format!("{over_limit:#}").contains("encrypted coordinator metadata exceeds"));
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
            .sign_in_identity(VerifiedIdentity {
                authority: "https://github.com".into(),
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
        let old_claims = VerifiedIdentity {
            authority: "https://accounts.google.com".into(),
            subject: "previously-durable".into(),
        };
        let new_claims = VerifiedIdentity {
            authority: "https://github.com".into(),
            subject: "unconfirmed-after-crash".into(),
        };
        let new_account = account_id(&[12; 32], &new_claims);
        let mut service = PersistentCoordinator::open(&path, keys.clone(), [12; 32]).unwrap();
        service.sign_in_identity(old_claims).unwrap();
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
        let new_binding = cache_visible.binding_for_test(&new_account).unwrap();
        assert!(cache_visible.export_account(&new_binding).is_ok());
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
        let binding = service.sign_in(&google(), "code").unwrap();
        let first = service.begin_enrollment_at(&binding, 100).unwrap();
        for _ in 1..MAX_ENROLLMENT_CHALLENGES_PER_ACCOUNT {
            service.begin_enrollment_at(&binding, 100).unwrap();
        }
        assert!(service.begin_enrollment_at(&binding, 100).is_err());
        let device = asterism_mesh::DeviceIdentity::generate();
        assert!(service
            .enroll_at(
                &binding,
                enrollment_proof(&device, first),
                DiscoveryConfig::default(),
                100 + ENROLLMENT_CHALLENGE_TTL_SECS
            )
            .is_err());
        assert!(service
            .begin_enrollment_at(&binding, 100 + ENROLLMENT_CHALLENGE_TTL_SECS)
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

    #[tokio::test(start_paused = true)]
    async fn pre_paired_local_orbit_survives_exact_24_hour_coordinator_outage() {
        let cached_infra = DiscoveryConfig {
            relays: vec!["https://third-party-relay.example".into()],
            pkarr_relay: Some("https://directory.example/pkarr".into()),
            dns_origin: None,
        }
        .mesh_infra();
        let availability = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let unavailable_address = availability.local_addr().unwrap();

        let inviter = MeshEndpoint::bind(&DeviceIdentity::generate(), MeshMode::LocalOnly)
            .await
            .unwrap();
        let joiner = MeshEndpoint::bind(&DeviceIdentity::generate(), MeshMode::LocalOnly)
            .await
            .unwrap();
        let issued = IssuedTicket::new(PairingTicket::issue(
            inviter.direct_addr().await.unwrap(),
            DEFAULT_TICKET_TTL,
        ));
        let ticket = PairingTicket::decode(&issued.ticket().encode()).unwrap();
        let accepting = tokio::spawn(async move {
            let accepted = pairing::accept(&inviter, &issued).await.unwrap();
            (inviter, accepted)
        });
        let paired = pairing::join(&joiner, &ticket).await.unwrap();
        let (inviter, accepted) = accepting.await.unwrap();

        drop(availability);
        assert!(tokio::net::TcpStream::connect(unavailable_address)
            .await
            .is_err());
        let outage_started = tokio::time::Instant::now();
        tokio::time::advance(Duration::from_secs(24 * 60 * 60)).await;
        assert_eq!(outage_started.elapsed(), Duration::from_secs(24 * 60 * 60));
        assert_eq!(
            cached_infra.relays,
            vec!["https://third-party-relay.example"]
        );

        let inbound = paired.connection().accept_stream();
        let mut outbound = accepted.connection().open_stream().await.unwrap();
        outbound
            .send
            .write_all(b"already-paired-after-outage")
            .await
            .unwrap();
        outbound.send.finish().unwrap();
        let mut inbound = inbound.await.unwrap();
        assert_eq!(
            inbound.recv.read_to_end(64).await.unwrap(),
            b"already-paired-after-outage"
        );
        paired.connection().close(b"outage proof complete");
        joiner.close().await;
        inviter.close().await;
    }
}
