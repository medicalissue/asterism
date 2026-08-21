//! Orbit-scoped secret metadata.
//!
//! This module intentionally contains no secret material.  A [`Secret`] is
//! the orbit's description of a value, a [`Binding`] says which outbound
//! authority may eventually use it, and a [`Handle`] identifies one concrete
//! source device from which the daemon can resolve it.  The bytes themselves
//! live behind the daemon's `SecretStore` platform seam.

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};

/// Immutable orbit identity of a secret.
///
/// Layer 0 deliberately derives this from the name.  That gives two devices
/// creating the same named secret during a partition the same identity, while
/// leaving a future rename as an explicit metadata migration rather than an
/// accidental identity change.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SecretId(String);

impl SecretId {
    pub fn from_name(name: &str) -> Result<Self> {
        check_name(name)?;
        Ok(Self(name.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// One device that independently holds the value.
///
/// `device_id` is the mesh public key and therefore the identity.  `device`
/// is only the current human-readable route hint and may change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceDevice {
    pub device_id: String,
    pub device: String,
    pub version: u64,
    pub updated_at: u64,
}

/// Orbit-visible metadata for one secret.  There is no value field by design.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Secret {
    pub id: SecretId,
    pub name: String,
    pub version: u64,
    pub created_at: u64,
    pub updated_at: u64,
    #[serde(default)]
    pub sources: Vec<SourceDevice>,
}

/// A traffic match associated with a secret.
///
/// Layer 0 only records the stable policy identity.  It does not install a CA,
/// accept CONNECT, or inject a header; those are later layers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Binding {
    pub id: String,
    pub secret_id: SecretId,
    /// Host or `host:port` authority to which this binding applies.
    pub authority: String,
}

/// A version-pinned reference to one source device.
///
/// This is the input to the mesh-routable source operation.  Pinning the
/// version prevents a request selected under one policy snapshot from silently
/// receiving a later rotation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Handle {
    pub secret_id: SecretId,
    pub source: SourceDevice,
    pub version: u64,
}

impl Secret {
    /// Construct a handle for one of this secret's advertised sources.
    pub fn handle(&self, device_id: &str) -> Option<Handle> {
        self.sources
            .iter()
            .find(|source| source.device_id == device_id && source.version == self.version)
            .cloned()
            .map(|source| Handle {
                secret_id: self.id.clone(),
                version: self.version,
                source,
            })
    }
}

pub fn check_name(name: &str) -> Result<()> {
    if name.is_empty() {
        bail!("a secret name cannot be empty");
    }
    if name.len() > 127 {
        bail!("secret name {name:?} is longer than 127 characters");
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        bail!("secret name {name:?} may only contain letters, digits, '-', '_' and '.'");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_has_no_place_to_serialize_plaintext() {
        let secret = Secret {
            id: SecretId::from_name("github-token").unwrap(),
            name: "github-token".into(),
            version: 1,
            created_at: 1,
            updated_at: 1,
            sources: vec![SourceDevice {
                device_id: "public-key".into(),
                device: "laptop".into(),
                version: 1,
                updated_at: 1,
            }],
        };
        let json = serde_json::to_string(&secret).unwrap();
        assert!(!json.contains("plaintext"));
        assert_eq!(serde_json::from_str::<Secret>(&json).unwrap(), secret);
    }

    #[test]
    fn a_handle_is_pinned_to_a_matching_source_version() {
        let mut secret = Secret {
            id: SecretId::from_name("api").unwrap(),
            name: "api".into(),
            version: 2,
            created_at: 1,
            updated_at: 2,
            sources: vec![SourceDevice {
                device_id: "source-key".into(),
                device: "desktop".into(),
                version: 1,
                updated_at: 1,
            }],
        };
        assert!(secret.handle("source-key").is_none());
        secret.sources[0].version = 2;
        assert_eq!(secret.handle("source-key").unwrap().version, 2);
    }
}
