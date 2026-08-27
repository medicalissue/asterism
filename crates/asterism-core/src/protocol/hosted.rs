//! The hosted-coordinator band of the wire.
//!
//! `ast` holds the hosted session — it owns the OS credential store — and the
//! daemon holds the device key and the mesh endpoint. Enrolling needs both, so
//! the bearer crosses this socket once, in memory, and is never written to
//! disk by the daemon. Everything else in this band is public: an opaque
//! account id, public device keys, and where those devices say they can be
//! reached.

use std::fmt;

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};

/// The longest bearer this socket will carry, matching the coordinator core's
/// own bound so an oversized token is refused before it is parsed anywhere.
const MAX_BEARER_BYTES: usize = 8 * 1024;

/// A hosted session bearer on its way from `ast` to the daemon.
///
/// The only reason this is a newtype is its `Debug`: `Request` derives `Debug`
/// and the daemon prints unexpected frames, so a bare `String` here would be
/// one `{request:?}` away from a token in a log file.
#[derive(Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RedactedBearer(String);

impl RedactedBearer {
    /// Accepts a bounded, non-empty bearer.
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if value.trim().is_empty() || value.len() > MAX_BEARER_BYTES {
            bail!("hosted session bearer is invalid");
        }
        Ok(Self(value))
    }

    /// The only reader. Call it at the request boundary, never before a log.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for RedactedBearer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("[REDACTED]")
    }
}

impl PartialEq for RedactedBearer {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl Eq for RedactedBearer {}

/// Whether the daemon currently holds a live presence socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum HostedPresence {
    /// No coordinator is configured for this device.
    #[default]
    Disabled,
    /// Enrolled, but no session is armed — sign in again with `ast auth login`.
    Unarmed,
    /// Trying, and backing off between attempts.
    Connecting,
    /// A presence socket is open.
    Online,
}

impl HostedPresence {
    /// The word `ast` prints.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::Unarmed => "unarmed",
            Self::Connecting => "connecting",
            Self::Online => "online",
        }
    }
}

/// One other device the account has enrolled.
///
/// `in_orbit` is the honest part: an account may know about a device key that
/// this orbit does not trust, and printing that difference is the point.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostedPeerStatus {
    /// The peer's public mesh key.
    pub device_id: String,
    /// Whether the peer held a presence socket when the list was last read.
    pub online: bool,
    /// Whether this device's `orbit.json` trusts that key.
    pub in_orbit: bool,
    /// Relay endpoints the account selected for that peer.
    #[serde(default)]
    pub relays: Vec<String>,
    /// Socket addresses the peer last advertised to the account.
    #[serde(default)]
    pub addrs: Vec<String>,
    /// When the coordinator last saw that peer's hints change.
    #[serde(default)]
    pub updated_at: u64,
}

/// What the daemon knows about its hosted enrollment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct HostedStatus {
    /// Canonical coordinator origin, when one is configured.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub coordinator: Option<String>,
    /// The coordinator's opaque account identifier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_id: Option<String>,
    /// This device's own public mesh key.
    #[serde(default)]
    pub device_id: String,
    /// Whether this device is enrolled with that account.
    #[serde(default)]
    pub enrolled: bool,
    /// When enrollment last succeeded.
    #[serde(default)]
    pub enrolled_at: u64,
    /// Presence socket state.
    #[serde(default)]
    pub presence: HostedPresence,
    /// Whether account-enrolled keys may enter this orbit's ACL.
    #[serde(default)]
    pub trust_account_devices: bool,
    /// The account's other devices, as of the last successful read.
    #[serde(default)]
    pub peers: Vec<HostedPeerStatus>,
    /// The last coordinator failure, for `ast auth status`. Never a token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bearer_never_reaches_a_debug_line() {
        let bearer = RedactedBearer::new("bearer-not-for-logs").unwrap();
        let debug = format!("{bearer:?}");
        assert_eq!(debug, "[REDACTED]");
        assert!(!debug.contains("bearer-not-for-logs"));
        assert_eq!(bearer.expose(), "bearer-not-for-logs");
    }

    #[test]
    fn an_empty_or_oversized_bearer_is_refused_at_the_boundary() {
        assert!(RedactedBearer::new("").is_err());
        assert!(RedactedBearer::new("   ").is_err());
        assert!(RedactedBearer::new("x".repeat(MAX_BEARER_BYTES + 1)).is_err());
        assert!(RedactedBearer::new("x".repeat(MAX_BEARER_BYTES)).is_ok());
    }

    #[test]
    fn a_bearer_still_round_trips_as_a_transparent_string() {
        let json = serde_json::to_string(&RedactedBearer::new("token").unwrap()).unwrap();
        assert_eq!(json, "\"token\"");
        assert_eq!(
            serde_json::from_str::<RedactedBearer>(&json)
                .unwrap()
                .expose(),
            "token"
        );
    }

    #[test]
    fn presence_vocabulary_is_stable() {
        assert_eq!(HostedPresence::Disabled.as_str(), "disabled");
        assert_eq!(HostedPresence::Unarmed.as_str(), "unarmed");
        assert_eq!(HostedPresence::Connecting.as_str(), "connecting");
        assert_eq!(HostedPresence::Online.as_str(), "online");
    }
}
