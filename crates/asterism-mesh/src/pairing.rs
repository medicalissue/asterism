//! The pairing exchange: `ast device invite` meets `ast device add <ticket>`.
//!
//! Pairing is what adds a key to the orbit's trusted set, and it involves no
//! server. One device issues a [`PairingTicket`]; the other redeems it over a
//! mesh connection; both end up holding the peer's [`DeviceId`] and the same
//! [`SasCode`], which a human confirms out of band before either side writes
//! anything to `orbit.json`.
//!
//! # The exchange
//!
//! ```text
//! joiner                                        inviter
//!   │  dial (QUIC, ALPN asterism/0)                 │
//!   │─────────────────────────────────────────────▶ │   both sides now know the
//!   │                                               │   peer's key from the
//!   │  open bi stream: [version][16-byte token]     │   TLS handshake
//!   │─────────────────────────────────────────────▶ │
//!   │                                               │   check token (constant time),
//!   │                     [accept] or [reject:why]  │   check expiry, consume ticket
//!   │ ◀───────────────────────────────────────────  │
//!   │                                               │
//!   ▼  both derive the same six digits from the ticket + this TLS session
//! ```
//!
//! The token check is what makes a ticket single-use; the SAS is what makes an
//! intercepted ticket useless. Neither alone is enough, which is why the
//! roadmap specifies both.

use std::fmt;

use crate::endpoint::{MeshConnection, MeshEndpoint};
use crate::identity::DeviceId;
use crate::sas::{SasCode, Transcript, SAS_EXPORTER_LABEL};
use crate::ticket::{PairingTicket, PairingToken, TOKEN_LEN};

/// Wire version of the pairing exchange itself.
const PAIRING_WIRE_VERSION: u8 = 1;

/// How long the inviter waits for the joiner to take delivery of the verdict
/// before giving up and closing anyway.
const REPLY_FLUSH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Server reply: the token was good.
const REPLY_ACCEPT: u8 = 0x01;
/// Server reply: the token was not.
const REPLY_REJECT: u8 = 0x00;

/// Reject reasons, sent as one byte after [`REPLY_REJECT`] so the joiner can
/// say something useful instead of "pairing failed".
const REJECT_BAD_TOKEN: u8 = 0x01;
const REJECT_EXPIRED: u8 = 0x02;
const REJECT_ALREADY_USED: u8 = 0x03;
const REJECT_BAD_VERSION: u8 = 0x04;

/// A peer that completed the pairing exchange.
///
/// Holding one of these does **not** mean the peer should be trusted — it means
/// the exchange succeeded and the human has a code to check. Only after
/// [`sas`](Self::sas) is confirmed should [`device_id`](Self::device_id) be
/// written to the orbit's device set.
#[derive(Debug)]
pub struct PairedPeer {
    device_id: DeviceId,
    sas: SasCode,
    connection: MeshConnection,
}

impl PairedPeer {
    /// The peer's device id, proven by the QUIC handshake.
    pub fn device_id(&self) -> DeviceId {
        self.device_id
    }

    /// The six digits to show the user. Both devices compute the same value.
    pub fn sas(&self) -> SasCode {
        self.sas
    }

    /// The live connection, which stays usable after pairing.
    pub fn connection(&self) -> &MeshConnection {
        &self.connection
    }

    /// Takes ownership of the connection.
    pub fn into_connection(self) -> MeshConnection {
        self.connection
    }
}

/// Why a pairing attempt did not complete.
#[derive(Debug)]
pub enum PairingError {
    /// The ticket had already expired when it was presented.
    Expired,
    /// The token presented did not match the ticket.
    BadToken,
    /// The ticket had already been redeemed. Tickets are single-use.
    AlreadyUsed,
    /// The peer speaks a different version of the pairing exchange.
    VersionMismatch(u8),
    /// The inviter refused, for the reason given.
    Rejected(&'static str),
    /// The peer that connected is not the one the ticket was issued for.
    WrongPeer {
        /// Who the ticket named.
        expected: DeviceId,
        /// Who actually turned up.
        found: DeviceId,
    },
    /// The connection failed, or the peer disappeared mid-exchange.
    Transport(anyhow::Error),
}

impl fmt::Display for PairingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Expired => write!(f, "the pairing ticket has expired; issue a new one"),
            Self::BadToken => write!(f, "the pairing token does not match this ticket"),
            Self::AlreadyUsed => write!(f, "this pairing ticket has already been used"),
            Self::VersionMismatch(v) => write!(
                f,
                "peer speaks pairing version {v}, this device speaks {PAIRING_WIRE_VERSION}"
            ),
            Self::Rejected(why) => write!(f, "the other device refused the pairing: {why}"),
            Self::WrongPeer { expected, found } => write!(
                f,
                "expected device {} but {} connected",
                expected.short(),
                found.short()
            ),
            Self::Transport(e) => write!(f, "pairing connection failed: {e}"),
        }
    }
}

impl std::error::Error for PairingError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Transport(e) => Some(e.as_ref()),
            _ => None,
        }
    }
}

impl From<anyhow::Error> for PairingError {
    fn from(e: anyhow::Error) -> Self {
        Self::Transport(e)
    }
}

/// The joiner's half: `ast device add <ticket>`.
///
/// Dials the device named in the ticket, presents the token, and returns the
/// peer and the code to display. Does not consult or modify any trust store —
/// that is the caller's job, after the user confirms the code.
pub async fn join(
    endpoint: &MeshEndpoint,
    ticket: &PairingTicket,
) -> Result<PairedPeer, PairingError> {
    if ticket.is_expired() {
        return Err(PairingError::Expired);
    }

    let connection = endpoint.connect(ticket.addr().clone()).await?;

    // The dial is by public key, so iroh has already refused to connect to
    // anyone else — but assert it rather than assume it.
    let peer = connection.remote_device_id();
    if peer != ticket.device_id() {
        return Err(PairingError::WrongPeer {
            expected: ticket.device_id(),
            found: peer,
        });
    }

    let mut stream = connection.open_stream().await?;
    let mut request = [0u8; 1 + TOKEN_LEN];
    request[0] = PAIRING_WIRE_VERSION;
    request[1..].copy_from_slice(ticket.token().as_bytes());
    stream
        .send
        .write_all(&request)
        .await
        .map_err(|e| PairingError::Transport(e.into()))?;
    let _ = stream.send.finish();

    let mut reply = [0u8; 2];
    stream
        .recv
        .read_exact(&mut reply)
        .await
        .map_err(|e| PairingError::Transport(e.into()))?;

    if reply[0] != REPLY_ACCEPT {
        return Err(match reply[1] {
            REJECT_BAD_TOKEN => PairingError::BadToken,
            REJECT_EXPIRED => PairingError::Expired,
            REJECT_ALREADY_USED => PairingError::AlreadyUsed,
            REJECT_BAD_VERSION => PairingError::VersionMismatch(PAIRING_WIRE_VERSION),
            _ => PairingError::Rejected("no reason given"),
        });
    }

    let sas = derive_sas(endpoint, &connection, ticket)?;
    Ok(PairedPeer {
        device_id: peer,
        sas,
        connection,
    })
}

/// The inviter's half: what `ast device invite` waits on after printing the
/// ticket.
///
/// Accepts one connection, checks the token it presents against `ticket`, and
/// returns the peer and the code to display. The ticket is consumed whether or
/// not the caller goes on to trust the peer, so a rejected pairing cannot be
/// retried against the same ticket.
pub async fn accept(
    endpoint: &MeshEndpoint,
    ticket: &mut IssuedTicket,
) -> Result<PairedPeer, PairingError> {
    let connection = endpoint
        .accept()
        .await
        .ok_or_else(|| PairingError::Transport(anyhow::anyhow!("endpoint closed while waiting")))?
        .map_err(PairingError::Transport)?;

    accept_connection(endpoint, connection, ticket).await
}

/// The inviter's half, on a connection somebody else already accepted.
///
/// A daemon has exactly one endpoint and one accept loop, so it cannot let
/// [`accept`] take the next connection — that connection might be a peer that
/// paired last week asking for an instance list. It classifies inbound
/// connections itself and routes the unrecognised one here, which is the only
/// path in the whole daemon that serves a device not yet in the orbit. The
/// ticket token is what gates it.
pub async fn accept_connection(
    endpoint: &MeshEndpoint,
    connection: MeshConnection,
    ticket: &mut IssuedTicket,
) -> Result<PairedPeer, PairingError> {
    let sas = accept_on(endpoint, &connection, ticket).await?;
    Ok(PairedPeer {
        device_id: connection.remote_device_id(),
        sas,
        connection,
    })
}

/// Runs the inviter's side of the exchange on an already-accepted connection.
async fn accept_on(
    endpoint: &MeshEndpoint,
    connection: &MeshConnection,
    ticket: &mut IssuedTicket,
) -> Result<SasCode, PairingError> {
    let mut stream = connection.accept_stream().await?;

    let mut request = [0u8; 1 + TOKEN_LEN];
    stream
        .recv
        .read_exact(&mut request)
        .await
        .map_err(|e| PairingError::Transport(e.into()))?;

    let mut token = [0u8; TOKEN_LEN];
    token.copy_from_slice(&request[1..]);
    let presented = PairingToken::from_bytes(token);

    let verdict = ticket.redeem(request[0], &presented);
    let reply = match &verdict {
        Ok(()) => [REPLY_ACCEPT, 0],
        Err(PairingError::BadToken) => [REPLY_REJECT, REJECT_BAD_TOKEN],
        Err(PairingError::Expired) => [REPLY_REJECT, REJECT_EXPIRED],
        Err(PairingError::AlreadyUsed) => [REPLY_REJECT, REJECT_ALREADY_USED],
        Err(PairingError::VersionMismatch(_)) => [REPLY_REJECT, REJECT_BAD_VERSION],
        Err(_) => [REPLY_REJECT, 0],
    };
    stream
        .send
        .write_all(&reply)
        .await
        .map_err(|e| PairingError::Transport(e.into()))?;

    // Make sure the verdict actually lands. A rejected pairing returns an error
    // to the caller, which will typically drop the connection immediately, and
    // a QUIC connection closed with data still in flight discards it — leaving
    // the joiner to report "connection lost" instead of "wrong token". Waiting
    // for the peer to consume the reply costs one round trip at pairing time
    // and buys an accurate message on the other terminal.
    let _ = stream.send.finish();
    let _ = tokio::time::timeout(REPLY_FLUSH_TIMEOUT, stream.send.stopped()).await;

    verdict?;

    derive_sas(endpoint, connection, ticket.ticket())
}

/// A ticket held by the device that issued it, tracking single use.
///
/// The joiner holds a plain [`PairingTicket`] — it has no business deciding
/// whether the ticket has been spent. The inviter holds this, because it does.
#[derive(Debug)]
pub struct IssuedTicket {
    ticket: PairingTicket,
    redeemed: bool,
}

impl IssuedTicket {
    /// Wraps a freshly issued ticket.
    pub fn new(ticket: PairingTicket) -> Self {
        Self {
            ticket,
            redeemed: false,
        }
    }

    /// The underlying ticket, for printing or encoding.
    pub fn ticket(&self) -> &PairingTicket {
        &self.ticket
    }

    /// Whether the ticket has been spent.
    pub fn is_redeemed(&self) -> bool {
        self.redeemed
    }

    /// Checks a presented token and marks the ticket spent.
    ///
    /// The ticket is consumed on *any* well-formed attempt, not just a
    /// successful one: otherwise an attacker holding a stolen ticket could
    /// guess tokens indefinitely.
    fn redeem(&mut self, version: u8, presented: &PairingToken) -> Result<(), PairingError> {
        if version != PAIRING_WIRE_VERSION {
            return Err(PairingError::VersionMismatch(version));
        }
        if self.redeemed {
            return Err(PairingError::AlreadyUsed);
        }
        self.redeemed = true;
        if self.ticket.is_expired() {
            return Err(PairingError::Expired);
        }
        // `PairingToken`'s `PartialEq` is constant time.
        if presented != self.ticket.token() {
            return Err(PairingError::BadToken);
        }
        Ok(())
    }
}

/// Derives the confirmation code both sides will display.
fn derive_sas(
    endpoint: &MeshEndpoint,
    connection: &MeshConnection,
    ticket: &PairingTicket,
) -> Result<SasCode, PairingError> {
    let transcript = pairing_transcript(connection, ticket)?;
    Ok(SasCode::for_devices(
        endpoint.device_id(),
        connection.remote_device_id(),
        &transcript,
    ))
}

/// Builds the transcript both sides hash.
fn pairing_transcript(
    connection: &MeshConnection,
    ticket: &PairingTicket,
) -> Result<Transcript, PairingError> {
    let exported: [u8; 32] = connection
        .export_keying_material(SAS_EXPORTER_LABEL, ticket.token().as_bytes())
        .map_err(PairingError::Transport)?;
    Ok(Transcript::for_pairing(ticket, &exported))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::endpoint::MeshMode;
    use crate::identity::DeviceIdentity;
    use crate::ticket::DEFAULT_TICKET_TTL;

    /// Brings up two loopback endpoints and issues a ticket for the first.
    async fn fixture() -> (MeshEndpoint, MeshEndpoint, IssuedTicket) {
        let inviter = MeshEndpoint::bind(&DeviceIdentity::generate(), MeshMode::LocalOnly)
            .await
            .unwrap();
        let joiner = MeshEndpoint::bind(&DeviceIdentity::generate(), MeshMode::LocalOnly)
            .await
            .unwrap();
        let addr = inviter.direct_addr().await.unwrap();
        let ticket = IssuedTicket::new(PairingTicket::issue(addr, DEFAULT_TICKET_TTL));
        (inviter, joiner, ticket)
    }

    #[tokio::test]
    async fn a_successful_pairing_gives_both_sides_the_same_code() {
        let (inviter, joiner, mut issued) = fixture().await;
        // The joiner only ever sees the encoded string, as a user would.
        let pasted = issued.ticket().encode();
        let ticket = PairingTicket::decode(&pasted).unwrap();

        let inviter_task = tokio::spawn(async move {
            let peer = accept(&inviter, &mut issued).await.unwrap();
            (inviter, peer.device_id(), peer.sas(), issued)
        });

        let peer = join(&joiner, &ticket)
            .await
            .expect("pairing should succeed");
        let (inviter, seen_by_inviter, inviter_sas, issued) = inviter_task.await.unwrap();

        assert_eq!(
            peer.sas(),
            inviter_sas,
            "the whole point: both terminals show the same digits"
        );
        assert_eq!(peer.device_id(), inviter.device_id());
        assert_eq!(seen_by_inviter, joiner.device_id());
        assert!(issued.is_redeemed());

        joiner.close().await;
        inviter.close().await;
    }

    #[tokio::test]
    async fn the_paired_connection_stays_usable_afterwards() {
        let (inviter, joiner, mut issued) = fixture().await;
        let ticket = PairingTicket::decode(&issued.ticket().encode()).unwrap();

        let inviter_task = tokio::spawn(async move {
            let peer = accept(&inviter, &mut issued).await.unwrap();
            let mut stream = peer.connection().accept_stream().await.unwrap();
            let got = stream.recv.read_to_end(16).await.unwrap();
            assert_eq!(&got, b"ping");
            stream.send.write_all(b"pong").await.unwrap();
            stream.send.finish().unwrap();
            peer.connection().connection().closed().await;
            inviter
        });

        let peer = join(&joiner, &ticket).await.unwrap();
        let mut stream = peer.connection().open_stream().await.unwrap();
        stream.send.write_all(b"ping").await.unwrap();
        stream.send.finish().unwrap();
        assert_eq!(stream.recv.read_to_end(16).await.unwrap(), b"pong");

        peer.connection().close(b"done");
        inviter_task.await.unwrap().close().await;
        joiner.close().await;
    }

    #[tokio::test]
    async fn a_ticket_cannot_be_redeemed_twice() {
        let (inviter, joiner, mut issued) = fixture().await;
        let ticket = PairingTicket::decode(&issued.ticket().encode()).unwrap();

        let inviter_task = tokio::spawn(async move {
            let first = accept(&inviter, &mut issued).await;
            let second = accept(&inviter, &mut issued).await;
            (inviter, first.is_ok(), second)
        });

        join(&joiner, &ticket).await.expect("first join succeeds");

        // A second device shows up with the very same ticket string.
        let interloper = MeshEndpoint::bind(&DeviceIdentity::generate(), MeshMode::LocalOnly)
            .await
            .unwrap();
        let replay = join(&interloper, &ticket).await;

        assert!(
            matches!(replay, Err(PairingError::AlreadyUsed)),
            "a replayed ticket must be refused, got {replay:?}"
        );

        let (inviter, first_ok, second) = inviter_task.await.unwrap();
        assert!(first_ok);
        assert!(matches!(second, Err(PairingError::AlreadyUsed)));

        interloper.close().await;
        joiner.close().await;
        inviter.close().await;
    }

    #[tokio::test]
    async fn a_wrong_token_is_refused() {
        let (inviter, joiner, mut issued) = fixture().await;
        // Same address and expiry, but a token the inviter never issued.
        let forged = PairingTicket::from_parts(
            issued.ticket().addr().clone(),
            issued.ticket().expires_at(),
            PairingToken::from_bytes([0xFF; TOKEN_LEN]),
        );

        let inviter_task = tokio::spawn(async move {
            let result = accept(&inviter, &mut issued).await;
            (inviter, result)
        });

        let result = join(&joiner, &forged).await;
        assert!(
            matches!(result, Err(PairingError::BadToken)),
            "expected BadToken, got {result:?}"
        );

        let (inviter, server_result) = inviter_task.await.unwrap();
        assert!(matches!(server_result, Err(PairingError::BadToken)));

        joiner.close().await;
        inviter.close().await;
    }

    #[tokio::test]
    async fn an_expired_ticket_is_refused_before_dialling() {
        let joiner = MeshEndpoint::bind(&DeviceIdentity::generate(), MeshMode::LocalOnly)
            .await
            .unwrap();
        let stale = PairingTicket::from_parts(
            iroh::EndpointAddr::new(DeviceIdentity::generate().public_key()),
            1_000,
            PairingToken::generate(),
        );

        assert!(matches!(
            join(&joiner, &stale).await,
            Err(PairingError::Expired)
        ));
        joiner.close().await;
    }

    #[test]
    fn a_failed_attempt_still_burns_the_ticket() {
        // Otherwise a stolen ticket becomes an unlimited guessing oracle.
        let addr = iroh::EndpointAddr::new(DeviceIdentity::generate().public_key());
        let mut issued = IssuedTicket::new(PairingTicket::issue(addr, DEFAULT_TICKET_TTL));

        let wrong = PairingToken::from_bytes([0x00; TOKEN_LEN]);
        assert!(matches!(
            issued.redeem(PAIRING_WIRE_VERSION, &wrong),
            Err(PairingError::BadToken)
        ));
        assert!(issued.is_redeemed(), "a bad guess must consume the ticket");

        let right = *issued.ticket().token();
        assert!(matches!(
            issued.redeem(PAIRING_WIRE_VERSION, &right),
            Err(PairingError::AlreadyUsed)
        ));
    }

    #[test]
    fn a_mismatched_wire_version_is_refused_without_touching_the_token() {
        let addr = iroh::EndpointAddr::new(DeviceIdentity::generate().public_key());
        let mut issued = IssuedTicket::new(PairingTicket::issue(addr, DEFAULT_TICKET_TTL));
        let token = *issued.ticket().token();

        assert!(matches!(
            issued.redeem(PAIRING_WIRE_VERSION + 1, &token),
            Err(PairingError::VersionMismatch(_))
        ));
        assert!(
            !issued.is_redeemed(),
            "a peer that cannot speak the protocol should not spend the ticket"
        );
        assert!(issued.redeem(PAIRING_WIRE_VERSION, &token).is_ok());
    }
}
