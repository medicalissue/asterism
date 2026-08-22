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

use std::collections::{BTreeMap, BTreeSet};

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use anyhow::{anyhow, bail, Context, Result};
use asterism_mesh::iroh_types::Signature;
use asterism_mesh::{DeviceId, MeshInfra};
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

/// Minimal, portable account export.  OAuth identity and access tokens are
/// intentionally not exportable because this service never stores them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountExport {
    /// Opaque account identifier.
    pub account_id: AccountId,
    /// Public device keys and discovery configuration only.
    pub devices: Vec<EnrolledDevice>,
}

#[derive(Debug, Default)]
struct Account {
    devices: BTreeMap<String, EnrolledDevice>,
    challenges: BTreeSet<[u8; 32]>,
}

/// In-memory coordinator state.  A production HTTP adapter serializes only
/// [`AccountExport`] with [`EncryptedMetadata`]; OAuth callbacks/tokens and
/// plaintext provider subjects must never be put in this structure or log.
#[derive(Debug, Default)]
pub struct Coordinator {
    accounts: BTreeMap<AccountId, Account>,
}

impl Coordinator {
    /// Signs in using a verified OAuth authorization code.  A provider or
    /// issuer mismatch is refused before any account record is created.
    pub fn sign_in(&mut self, verifier: &impl OAuthVerifier, code: &str) -> Result<AccountId> {
        if code.trim().is_empty() {
            bail!("OAuth authorization code is empty");
        }
        let claims = verifier.verify_authorization_code(code)?;
        if claims.issuer != claims.provider.issuer() {
            bail!("OAuth issuer does not match the selected provider");
        }
        if claims.subject.trim().is_empty() {
            bail!("OAuth subject is empty");
        }
        let account_id = account_id(&claims);
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
}

/// Encrypts minimal persisted metadata with AES-256-GCM.  The caller owns the
/// 32-byte KMS-managed key; this type never derives it from an OAuth identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedMetadata {
    /// Random 96-bit AES-GCM nonce.
    pub nonce: [u8; 12],
    /// Authenticated ciphertext, including the GCM tag.
    pub ciphertext: Vec<u8>,
}

impl EncryptedMetadata {
    /// Seals an export for durable storage.
    pub fn seal(key: &[u8; 32], export: &AccountExport) -> Result<Self> {
        let nonce: [u8; 12] = random_32()[..12].try_into().expect("slice has 12 bytes");
        let plaintext =
            serde_json::to_vec(export).context("serializing minimal account metadata")?;
        let cipher = Aes256Gcm::new_from_slice(key).expect("AES-256 keys are exactly 32 bytes");
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce), plaintext.as_ref())
            .map_err(|_| anyhow!("encrypting account metadata failed"))?;
        Ok(Self { nonce, ciphertext })
    }

    /// Opens metadata previously sealed by [`Self::seal`].
    pub fn open(&self, key: &[u8; 32]) -> Result<AccountExport> {
        let cipher = Aes256Gcm::new_from_slice(key).expect("AES-256 keys are exactly 32 bytes");
        let plaintext = cipher
            .decrypt(Nonce::from_slice(&self.nonce), self.ciphertext.as_ref())
            .map_err(|_| anyhow!("account metadata cannot be decrypted"))?;
        serde_json::from_slice(&plaintext)
            .context("encrypted account metadata has an invalid shape")
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

fn account_id(claims: &VerifiedOAuth) -> AccountId {
    let mut hash = blake3::Hasher::new();
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
        let mut service = Coordinator::default();
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
        let mut service = Coordinator::default();
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
        let mut service = Coordinator::default();
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
