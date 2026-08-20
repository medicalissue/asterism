//! Six-digit short authentication strings.
//!
//! A pairing ticket can be intercepted. Someone who gets hold of one before the
//! intended device does can redeem it, and the inviting device would happily
//! trust them: the ticket alone proves possession of the ticket, nothing more.
//! What closes that hole is a channel the attacker does not control — the two
//! humans looking at their two terminals.
//!
//! So both sides derive the same six digits from the pairing, print them, and
//! the user confirms they match. An attacker who terminated two separate
//! connections cannot make both sides show the same number, because the code is
//! bound to the TLS session, not just to the ticket.
//!
//! # What the code commits to
//!
//! ```text
//! transcript = BLAKE3( "asterism/pairing-transcript/1"
//!                    || ALPN || pairing token || expiry
//!                    || RFC 5705 keying material exported from the QUIC session )
//!
//! code       = BLAKE3( "asterism/sas/1" || min(pk_a, pk_b) || max(pk_a, pk_b)
//!                    || transcript ) mod 1_000_000
//! ```
//!
//! The two public keys are sorted before hashing, which is what makes the code
//! *symmetric*: neither side needs to know whether it invited or joined, and
//! both arrive at the same digits from the same facts. Including both keys is
//! what makes it *binding*: a machine-in-the-middle necessarily presents a
//! different key to at least one side, and the digits diverge.
//!
//! # On six digits
//!
//! Six digits is a one-in-a-million chance for an attacker to guess, and the
//! guess has to be made *before* seeing either code, with no retries — a failed
//! comparison aborts the pairing and burns the ticket. That is the same
//! trade-off Matrix's SAS and Bluetooth numeric comparison make, and it is
//! chosen because a code people will not actually compare provides no security
//! at all, however long it is.

use std::fmt;

use iroh::PublicKey;

use crate::identity::DeviceId;
use crate::ticket::PairingTicket;

/// Number of decimal digits in a short authentication string.
pub const SAS_DIGITS: u32 = 6;

/// Domain separator for the SAS derivation.
const SAS_CONTEXT: &[u8] = b"asterism/sas/1";

/// Domain separator for the pairing transcript.
const TRANSCRIPT_CONTEXT: &[u8] = b"asterism/pairing-transcript/1";

/// Label used when exporting keying material from the QUIC session.
pub const SAS_EXPORTER_LABEL: &[u8] = b"asterism pairing sas";

/// Bytes of keying material exported from the QUIC session.
const EXPORTER_LEN: usize = 32;

/// A hash of everything the two devices agreed on while pairing.
///
/// Both sides must compute this from identical inputs, or the resulting
/// [`SasCode`]s will differ — which is the point.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Transcript([u8; 32]);

impl Transcript {
    /// Builds a transcript from raw components.
    ///
    /// Each part is length-prefixed before hashing so that no rearrangement of
    /// the same bytes across two parts can produce the same transcript.
    pub fn from_parts(parts: &[&[u8]]) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(TRANSCRIPT_CONTEXT);
        for part in parts {
            hasher.update(&(part.len() as u64).to_le_bytes());
            hasher.update(part);
        }
        Self(*hasher.finalize().as_bytes())
    }

    /// Builds the transcript for a pairing: the ticket that was redeemed plus
    /// the QUIC session it was redeemed over.
    ///
    /// `exported_keying_material` comes from
    /// [`MeshConnection::export_keying_material`](crate::endpoint::MeshConnection::export_keying_material)
    /// with [`SAS_EXPORTER_LABEL`]; both peers of one connection get identical
    /// bytes, and no third party can produce them.
    pub fn for_pairing(ticket: &PairingTicket, exported_keying_material: &[u8]) -> Self {
        Self::from_parts(&[
            crate::endpoint::ALPN,
            ticket.token().as_bytes(),
            &ticket.expires_at().to_le_bytes(),
            ticket.device_id().as_bytes(),
            exported_keying_material,
        ])
    }

    /// The 32 transcript bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// How many bytes of keying material to export for a pairing transcript.
    pub const fn exporter_len() -> usize {
        EXPORTER_LEN
    }
}

/// A six-digit confirmation code, for a human to read aloud.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SasCode(u32);

impl SasCode {
    /// Derives the code from the two devices' public keys and the transcript.
    ///
    /// Symmetric in `a` and `b`: both sides pass their own key and the peer's,
    /// in whichever order, and get the same answer.
    pub fn derive(a: &PublicKey, b: &PublicKey, transcript: &Transcript) -> Self {
        let (lo, hi) = if a.as_bytes() <= b.as_bytes() {
            (a, b)
        } else {
            (b, a)
        };

        let mut hasher = blake3::Hasher::new();
        hasher.update(SAS_CONTEXT);
        hasher.update(lo.as_bytes());
        hasher.update(hi.as_bytes());
        hasher.update(transcript.as_bytes());
        let digest = hasher.finalize();

        // Modulo bias over a 64-bit draw into a 10^6 range is about 2^-44 —
        // far below the 10^-6 the code is worth to begin with.
        let value = u64::from_le_bytes(digest.as_bytes()[..8].try_into().expect("8 bytes"));
        Self((value % 10u64.pow(SAS_DIGITS)) as u32)
    }

    /// Convenience wrapper taking [`DeviceId`]s.
    pub fn for_devices(a: DeviceId, b: DeviceId, transcript: &Transcript) -> Self {
        Self::derive(&a.public_key(), &b.public_key(), transcript)
    }

    /// The code as a number in `0..1_000_000`.
    pub fn value(&self) -> u32 {
        self.0
    }

    /// The code grouped as `123 456`, which is easier to read aloud correctly.
    pub fn grouped(&self) -> String {
        let s = self.to_string();
        format!("{} {}", &s[..3], &s[3..])
    }
}

impl fmt::Display for SasCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Always six digits, leading zeros included: "042 137" must not become
        // "42 137", or two users comparing codes will disagree about a match.
        write!(f, "{:0width$}", self.0, width = SAS_DIGITS as usize)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::DeviceIdentity;
    use crate::ticket::{PairingTicket, PairingToken, DEFAULT_TICKET_TTL};
    use iroh::EndpointAddr;

    fn transcript(tag: &[u8]) -> Transcript {
        Transcript::from_parts(&[tag])
    }

    fn ticket_for(identity: &DeviceIdentity) -> PairingTicket {
        PairingTicket::issue(
            EndpointAddr::new(identity.public_key())
                .with_ip_addr("127.0.0.1:1234".parse().unwrap()),
            DEFAULT_TICKET_TTL,
        )
    }

    #[test]
    fn the_code_is_symmetric_in_the_two_public_keys() {
        let a = DeviceIdentity::generate().public_key();
        let b = DeviceIdentity::generate().public_key();
        let t = transcript(b"session");

        assert_eq!(
            SasCode::derive(&a, &b, &t),
            SasCode::derive(&b, &a, &t),
            "both sides must reach the same digits"
        );
    }

    #[test]
    fn the_code_is_stable_across_calls() {
        let a = DeviceIdentity::generate().public_key();
        let b = DeviceIdentity::generate().public_key();
        let t = transcript(b"session");

        let first = SasCode::derive(&a, &b, &t);
        for _ in 0..16 {
            assert_eq!(SasCode::derive(&a, &b, &t), first);
        }
    }

    #[test]
    fn a_different_transcript_gives_a_different_code() {
        let a = DeviceIdentity::generate().public_key();
        let b = DeviceIdentity::generate().public_key();

        assert_ne!(
            SasCode::derive(&a, &b, &transcript(b"session-one")),
            SasCode::derive(&a, &b, &transcript(b"session-two")),
        );
    }

    #[test]
    fn a_substituted_key_gives_a_different_code() {
        // This is the machine-in-the-middle case: the attacker holds its own
        // key, so at least one side sees a different peer key and the digits
        // stop matching.
        let honest_a = DeviceIdentity::generate().public_key();
        let honest_b = DeviceIdentity::generate().public_key();
        let attacker = DeviceIdentity::generate().public_key();
        let t = transcript(b"session");

        assert_ne!(
            SasCode::derive(&honest_a, &honest_b, &t),
            SasCode::derive(&honest_a, &attacker, &t),
        );
    }

    #[test]
    fn the_code_is_always_rendered_as_six_digits() {
        for _ in 0..200 {
            let a = DeviceIdentity::generate().public_key();
            let b = DeviceIdentity::generate().public_key();
            let code = SasCode::derive(&a, &b, &transcript(b"t"));

            assert!(code.value() < 1_000_000);
            let rendered = code.to_string();
            assert_eq!(rendered.len(), SAS_DIGITS as usize, "got {rendered}");
            assert!(rendered.chars().all(|c| c.is_ascii_digit()));
            assert_eq!(
                code.grouped(),
                format!("{} {}", &rendered[..3], &rendered[3..])
            );
        }
    }

    #[test]
    fn small_codes_keep_their_leading_zeros() {
        let code = SasCode(42);
        assert_eq!(code.to_string(), "000042");
        assert_eq!(code.grouped(), "000 042");
    }

    #[test]
    fn the_device_id_wrapper_agrees_with_the_public_key_form() {
        let a = DeviceIdentity::generate();
        let b = DeviceIdentity::generate();
        let t = transcript(b"session");

        assert_eq!(
            SasCode::for_devices(a.device_id(), b.device_id(), &t),
            SasCode::derive(&a.public_key(), &b.public_key(), &t),
        );
    }

    #[test]
    fn the_pairing_transcript_commits_to_the_ticket_and_the_session() {
        let inviter = DeviceIdentity::generate();
        let ticket = ticket_for(&inviter);
        let session = [9u8; EXPORTER_LEN];

        let base = Transcript::for_pairing(&ticket, &session);
        assert_eq!(
            base,
            Transcript::for_pairing(&ticket, &session),
            "the transcript must be deterministic"
        );

        // A different ticket token: different transcript.
        let other_ticket = ticket_for(&inviter);
        assert_ne!(base, Transcript::for_pairing(&other_ticket, &session));

        // Same ticket, different QUIC session: different transcript. This is
        // what defeats a relayed handshake.
        let other_session = [10u8; EXPORTER_LEN];
        assert_ne!(base, Transcript::for_pairing(&ticket, &other_session));
    }

    #[test]
    fn the_transcript_survives_a_ticket_round_trip() {
        let inviter = DeviceIdentity::generate();
        let ticket = ticket_for(&inviter);
        let decoded = PairingTicket::decode(&ticket.encode()).unwrap();
        let session = [3u8; EXPORTER_LEN];

        assert_eq!(
            Transcript::for_pairing(&ticket, &session),
            Transcript::for_pairing(&decoded, &session),
            "the joiner works from the decoded ticket and must agree with the inviter"
        );
    }

    #[test]
    fn transcript_parts_cannot_be_shifted_between_fields() {
        // Length prefixing means ("ab", "c") and ("a", "bc") differ.
        assert_ne!(
            Transcript::from_parts(&[b"ab", b"c"]),
            Transcript::from_parts(&[b"a", b"bc"]),
        );
    }

    #[test]
    fn an_expiry_change_changes_the_transcript() {
        let inviter = DeviceIdentity::generate();
        let addr = EndpointAddr::new(inviter.public_key());
        let token = PairingToken::generate();
        let session = [1u8; EXPORTER_LEN];

        let a = PairingTicket::from_parts(addr.clone(), 1_000, token);
        let b = PairingTicket::from_parts(addr, 2_000, token);
        assert_ne!(
            Transcript::for_pairing(&a, &session),
            Transcript::for_pairing(&b, &session),
        );
    }

    #[test]
    fn codes_spread_across_the_whole_range() {
        // A weak derivation that only ever produced, say, low numbers would
        // still pass every test above. Check the digits actually move.
        let t = transcript(b"spread");
        let mut seen = std::collections::HashSet::new();
        let mut buckets = [0usize; 10];

        for _ in 0..500 {
            let a = DeviceIdentity::generate().public_key();
            let b = DeviceIdentity::generate().public_key();
            let code = SasCode::derive(&a, &b, &t);
            seen.insert(code.value());
            buckets[(code.value() / 100_000) as usize] += 1;
        }

        assert!(
            seen.len() > 490,
            "codes should rarely collide: {}",
            seen.len()
        );
        assert!(
            buckets.iter().all(|count| *count > 0),
            "every leading digit should occur: {buckets:?}"
        );
    }
}
