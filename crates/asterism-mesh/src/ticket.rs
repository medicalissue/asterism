//! Pairing tickets — Layer 1 identity, with no server involved.
//!
//! `ast device invite` prints one of these; `ast device add <ticket>` on the
//! other device redeems it. The ticket carries everything the second device
//! needs to reach the first and nothing that is worth stealing on its own:
//!
//! * the inviting device's id (its Ed25519 public key),
//! * its direct addresses and relay hints, so the dial can succeed,
//! * an expiry — ten minutes by default,
//! * a single-use 128-bit pairing token.
//!
//! The token is a capability, not a secret key: holding it lets you *attempt*
//! the pairing the inviter just offered, once, within ten minutes. It cannot
//! decrypt anything and it cannot be replayed after the inviter has consumed
//! it. A ticket pasted into a chat window is still worth worrying about, which
//! is why redeeming one also produces a [`SasCode`](crate::sas::SasCode) for a
//! human to compare out of band.
//!
//! # Wire format
//!
//! ```text
//! astdev1<base32 of postcard(TicketPayload)>
//! ```
//!
//! `postcard` because it is compact — varint-length-prefixed, no field names —
//! and lowercase unpadded RFC 4648 base32 because the result survives being
//! read aloud, retyped, wrapped by a mail client, or lowercased by a chat
//! application. Decoding is case-insensitive for the same reason.

use std::fmt;
use std::str::FromStr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use iroh::EndpointAddr;
use serde::{Deserialize, Serialize};

use crate::identity::DeviceId;

/// Human-visible prefix of an encoded ticket. The `1` is the string format
/// version, so a later format can be told apart before decoding.
pub const TICKET_PREFIX: &str = "astdev1";

/// The payload version understood by this build.
pub const TICKET_VERSION: u8 = 1;

/// How long a ticket is valid for by default.
pub const DEFAULT_TICKET_TTL: Duration = Duration::from_secs(10 * 60);

/// Length in bytes of the single-use pairing token.
pub const TOKEN_LEN: usize = 16;

/// A single-use 128-bit pairing secret.
///
/// Compared in constant time, because a pairing attempt is an oracle: an
/// attacker who can measure how long a rejection took could otherwise recover
/// the token a byte at a time.
#[derive(Clone, Copy, Serialize, Deserialize)]
pub struct PairingToken([u8; TOKEN_LEN]);

impl PairingToken {
    /// Draws a fresh token from the operating system's RNG.
    pub fn generate() -> Self {
        // iroh's SecretKey is seeded from the OS RNG; taking 16 bytes of a
        // throwaway one avoids adding a `rand` dependency whose version has to
        // be kept in lockstep with iroh's.
        let mut bytes = [0u8; TOKEN_LEN];
        bytes.copy_from_slice(&iroh::SecretKey::generate().to_bytes()[..TOKEN_LEN]);
        Self(bytes)
    }

    /// Wraps raw token bytes.
    pub fn from_bytes(bytes: [u8; TOKEN_LEN]) -> Self {
        Self(bytes)
    }

    /// The raw token bytes.
    pub fn as_bytes(&self) -> &[u8; TOKEN_LEN] {
        &self.0
    }
}

impl PartialEq for PairingToken {
    fn eq(&self, other: &Self) -> bool {
        // Constant-time comparison: fold every byte into one accumulator so the
        // loop cannot exit early on the first mismatch.
        let mut diff = 0u8;
        for (a, b) in self.0.iter().zip(other.0.iter()) {
            diff |= a ^ b;
        }
        diff == 0
    }
}

impl Eq for PairingToken {}

impl fmt::Debug for PairingToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never print the token: tickets end up in terminal scrollback and bug
        // reports, and a logged token is a redeemable one.
        f.write_str("PairingToken(redacted)")
    }
}

/// What actually gets serialised into the ticket string.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct TicketPayload {
    version: u8,
    addr: EndpointAddr,
    expires_at: u64,
    token: PairingToken,
}

/// A pairing ticket: one device's offer to be added to another's orbit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairingTicket {
    addr: EndpointAddr,
    expires_at: u64,
    token: PairingToken,
}

impl PairingTicket {
    /// Issues a ticket for `addr`, valid for `ttl` from now.
    pub fn issue(addr: EndpointAddr, ttl: Duration) -> Self {
        Self {
            addr,
            expires_at: now_unix().saturating_add(ttl.as_secs()),
            token: PairingToken::generate(),
        }
    }

    /// Rebuilds a ticket from its parts, for tests and for callers that manage
    /// expiry themselves.
    pub fn from_parts(addr: EndpointAddr, expires_at: u64, token: PairingToken) -> Self {
        Self {
            addr,
            expires_at,
            token,
        }
    }

    /// The inviting device's id.
    pub fn device_id(&self) -> DeviceId {
        DeviceId::from_public_key(self.addr.id)
    }

    /// The inviting device's address: id, direct addresses, relay hints.
    pub fn addr(&self) -> &EndpointAddr {
        &self.addr
    }

    /// When the ticket stops being valid, as a Unix timestamp in seconds.
    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }

    /// The single-use pairing token.
    pub fn token(&self) -> &PairingToken {
        &self.token
    }

    /// Whether the ticket has expired, as of now.
    pub fn is_expired(&self) -> bool {
        self.is_expired_at(now_unix())
    }

    /// Whether the ticket has expired as of `now_unix_secs`.
    pub fn is_expired_at(&self, now_unix_secs: u64) -> bool {
        now_unix_secs >= self.expires_at
    }

    /// How long the ticket has left, or `None` if it has expired.
    pub fn time_remaining(&self) -> Option<Duration> {
        self.expires_at
            .checked_sub(now_unix())
            .filter(|secs| *secs > 0)
            .map(Duration::from_secs)
    }

    /// Encodes the ticket as one pasteable string.
    pub fn encode(&self) -> String {
        let payload = TicketPayload {
            version: TICKET_VERSION,
            addr: self.addr.clone(),
            expires_at: self.expires_at,
            token: self.token,
        };
        // postcard only fails here if a type in the payload refuses to
        // serialise, which for these types it cannot.
        let bytes = postcard::to_stdvec(&payload).expect("ticket payload is serialisable");
        format!(
            "{TICKET_PREFIX}{}",
            data_encoding::BASE32_NOPAD.encode(&bytes).to_lowercase()
        )
    }

    /// Decodes a ticket string.
    ///
    /// Surrounding whitespace is ignored and case is not significant, so a
    /// ticket that has been through a chat client still parses.
    pub fn decode(s: &str) -> Result<Self, TicketError> {
        let s = s.trim();
        let body = s
            .strip_prefix(TICKET_PREFIX)
            .or_else(|| s.strip_prefix(&TICKET_PREFIX.to_uppercase()))
            .ok_or(TicketError::MissingPrefix)?;

        let bytes = data_encoding::BASE32_NOPAD
            .decode(body.to_uppercase().as_bytes())
            .map_err(|_| TicketError::NotBase32)?;

        // `from_bytes` rejects trailing data, so a truncated or padded ticket
        // is an error rather than a silently shorter one.
        let payload: TicketPayload =
            postcard::from_bytes(&bytes).map_err(|_| TicketError::Malformed)?;

        if payload.version != TICKET_VERSION {
            return Err(TicketError::UnsupportedVersion(payload.version));
        }

        Ok(Self {
            addr: payload.addr,
            expires_at: payload.expires_at,
            token: payload.token,
        })
    }
}

impl fmt::Display for PairingTicket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.encode())
    }
}

impl FromStr for PairingTicket {
    type Err = TicketError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::decode(s)
    }
}

/// Why a ticket string could not be decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TicketError {
    /// The string does not start with `astdev1`.
    MissingPrefix,
    /// The body is not valid base32.
    NotBase32,
    /// The bytes decoded, but are not a ticket — truncated, padded, or corrupt.
    Malformed,
    /// The ticket was made by a newer version of Asterism.
    UnsupportedVersion(u8),
}

impl fmt::Display for TicketError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingPrefix => write!(f, "not an Asterism ticket (should start with `{TICKET_PREFIX}`)"),
            Self::NotBase32 => write!(f, "ticket contains characters that are not valid here; check it was pasted whole"),
            Self::Malformed => write!(f, "ticket is corrupt or truncated"),
            Self::UnsupportedVersion(v) => write!(
                f,
                "ticket format version {v} is newer than this build understands (expected {TICKET_VERSION}); upgrade Asterism"
            ),
        }
    }
}

impl std::error::Error for TicketError {}

/// Seconds since the Unix epoch, saturating at 0 for clocks set before 1970.
fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::DeviceIdentity;
    use iroh::RelayUrl;

    fn sample_addr() -> EndpointAddr {
        EndpointAddr::new(DeviceIdentity::generate().public_key())
            .with_ip_addr("127.0.0.1:4242".parse().unwrap())
            .with_ip_addr("192.168.1.20:4242".parse().unwrap())
            .with_relay_url(RelayUrl::from_str("https://relay.example/").unwrap())
    }

    #[test]
    fn a_ticket_round_trips_through_its_string_form() {
        let ticket = PairingTicket::issue(sample_addr(), DEFAULT_TICKET_TTL);
        let encoded = ticket.encode();
        let decoded = PairingTicket::decode(&encoded).expect("should decode");

        assert_eq!(decoded, ticket);
        assert_eq!(decoded.device_id(), ticket.device_id());
        assert_eq!(decoded.token(), ticket.token());
        assert_eq!(decoded.expires_at(), ticket.expires_at());
        assert_eq!(decoded.addr(), ticket.addr());
        assert_eq!(decoded.encode(), encoded, "encoding must be deterministic");
    }

    #[test]
    fn addresses_and_relay_hints_survive_the_round_trip() {
        let addr = sample_addr();
        let ticket = PairingTicket::issue(addr.clone(), DEFAULT_TICKET_TTL);
        let decoded = PairingTicket::decode(&ticket.encode()).unwrap();

        let mut expected: Vec<_> = addr.ip_addrs().map(|a| a.to_string()).collect();
        let mut got: Vec<_> = decoded.addr().ip_addrs().map(|a| a.to_string()).collect();
        expected.sort();
        got.sort();
        assert_eq!(got, expected);

        let relays: Vec<_> = decoded.addr().relay_urls().map(|u| u.to_string()).collect();
        assert_eq!(relays.len(), 1, "the relay hint should survive");
    }

    #[test]
    fn a_ticket_is_shaped_like_something_a_human_can_paste() {
        let ticket = PairingTicket::issue(sample_addr(), DEFAULT_TICKET_TTL);
        let encoded = ticket.encode();

        assert!(encoded.starts_with(TICKET_PREFIX));
        assert!(
            encoded
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()),
            "ticket should be lowercase alphanumeric: {encoded}"
        );
        assert!(
            !encoded.contains(char::is_whitespace),
            "a ticket must survive being pasted as one word"
        );
    }

    #[test]
    fn decoding_is_case_insensitive_and_tolerates_stray_whitespace() {
        let ticket = PairingTicket::issue(sample_addr(), DEFAULT_TICKET_TTL);
        let encoded = ticket.encode();

        assert_eq!(
            PairingTicket::decode(&encoded.to_uppercase()).unwrap(),
            ticket
        );
        assert_eq!(
            PairingTicket::decode(&format!("  {encoded}\n")).unwrap(),
            ticket
        );
        assert_eq!(encoded.parse::<PairingTicket>().unwrap(), ticket);
    }

    #[test]
    fn every_ticket_carries_a_fresh_token() {
        let addr = sample_addr();
        let a = PairingTicket::issue(addr.clone(), DEFAULT_TICKET_TTL);
        let b = PairingTicket::issue(addr, DEFAULT_TICKET_TTL);
        assert_ne!(a.token(), b.token(), "tokens must not repeat");
        assert_ne!(a.encode(), b.encode());
    }

    #[test]
    fn garbage_is_rejected_with_a_specific_reason() {
        assert_eq!(
            PairingTicket::decode("hello"),
            Err(TicketError::MissingPrefix)
        );
        assert_eq!(
            PairingTicket::decode("astdev1!!!!"),
            Err(TicketError::NotBase32)
        );
        assert_eq!(
            PairingTicket::decode("astdev1"),
            Err(TicketError::Malformed)
        );
    }

    #[test]
    fn a_truncated_ticket_does_not_decode_to_something_shorter() {
        let encoded = PairingTicket::issue(sample_addr(), DEFAULT_TICKET_TTL).encode();
        let truncated = &encoded[..encoded.len() - 8];
        assert!(
            PairingTicket::decode(truncated).is_err(),
            "a truncated ticket must not parse"
        );
    }

    #[test]
    fn a_ticket_from_a_future_format_is_named_as_such() {
        let payload = TicketPayload {
            version: TICKET_VERSION + 1,
            addr: sample_addr(),
            expires_at: now_unix() + 600,
            token: PairingToken::generate(),
        };
        let bytes = postcard::to_stdvec(&payload).unwrap();
        let encoded = format!(
            "{TICKET_PREFIX}{}",
            data_encoding::BASE32_NOPAD.encode(&bytes).to_lowercase()
        );

        assert_eq!(
            PairingTicket::decode(&encoded),
            Err(TicketError::UnsupportedVersion(TICKET_VERSION + 1))
        );
    }

    #[test]
    fn expiry_is_reported_against_the_clock() {
        let fresh = PairingTicket::issue(sample_addr(), DEFAULT_TICKET_TTL);
        assert!(!fresh.is_expired());
        assert!(fresh.time_remaining().is_some());

        let stale = PairingTicket::from_parts(sample_addr(), 1_000, PairingToken::generate());
        assert!(stale.is_expired());
        assert!(stale.time_remaining().is_none());
        assert!(stale.is_expired_at(1_000), "expiry is inclusive");
        assert!(!stale.is_expired_at(999));
    }

    #[test]
    fn expiry_survives_the_round_trip() {
        let ticket =
            PairingTicket::from_parts(sample_addr(), 1_700_000_000, PairingToken::generate());
        let decoded = PairingTicket::decode(&ticket.encode()).unwrap();
        assert_eq!(decoded.expires_at(), 1_700_000_000);
        assert!(decoded.is_expired_at(1_700_000_001));
    }

    #[test]
    fn a_token_never_appears_in_debug_output() {
        let token = PairingToken::from_bytes([0xAB; TOKEN_LEN]);
        let rendered = format!("{token:?}");
        assert!(
            !rendered.contains("ab"),
            "token leaked into Debug: {rendered}"
        );
        assert!(rendered.contains("redacted"));

        let ticket = PairingTicket::from_parts(sample_addr(), 0, token);
        let rendered = format!("{ticket:?}");
        // A leaked token prints as its bytes, so two adjacent ones are the
        // signal. A bare "171" is not: `sample_addr` carries a freshly
        // generated device key, and three of those hex digits land on
        // "171" about once in seventy runs, which is how this assertion
        // used to fail for a reason that had nothing to do with the token.
        assert!(!rendered.contains("171, 171"), "token leaked into Debug: {rendered}");
        assert!(rendered.contains("redacted"), "the token field is redacted: {rendered}");
    }

    #[test]
    fn tokens_compare_by_value() {
        let bytes = [7u8; TOKEN_LEN];
        assert_eq!(
            PairingToken::from_bytes(bytes),
            PairingToken::from_bytes(bytes)
        );

        let mut other = bytes;
        other[TOKEN_LEN - 1] ^= 1;
        assert_ne!(
            PairingToken::from_bytes(bytes),
            PairingToken::from_bytes(other),
            "a one-bit difference in the last byte must be caught"
        );
    }
}
