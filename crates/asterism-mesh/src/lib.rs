//! The Asterism device mesh.
//!
//! This crate is the Phase 2 foundation described in `docs/ROADMAP.md`:
//! authenticated, encrypted, NAT-traversing byte streams between `astd`
//! processes, with peers addressed by their Ed25519 public key rather than by
//! IP address. It is built on [iroh], which supplies QUIC, hole punching and
//! relay fallback; this crate supplies the Asterism-specific layers on top.
//!
//! Four pieces, in dependency order:
//!
//! * [`identity`] — the device's long-lived Ed25519 key, persisted once to disk
//!   with `0600` permissions. Its public half *is* the device's identity;
//!   [`DeviceId`] is the stable name derived from it.
//! * [`endpoint`] — a thin wrapper that binds an iroh endpoint to that key under
//!   the [`ALPN`] protocol identifier and hands out bidirectional streams.
//! * [`ticket`] — a [`PairingTicket`]: device id, direct addresses, relay hints,
//!   an expiry and a single-use 128-bit token, encoded as one pasteable string.
//! * [`sas`] — the six-digit short authentication string both terminals print so
//!   a human can confirm out-of-band that nobody sat in the middle of a ticket
//!   that was pasted into a chat window.
//!
//! [`pairing`] ties them together into the `ast device invite` /
//! `ast device add <ticket>` exchange.
//!
//! # Trust model
//!
//! An orbit is a set of mutually trusted device keys. Pairing is what adds a key
//! to that set, and it deliberately involves no server at all: one device issues
//! a ticket, the other redeems it, both display the same [`SasCode`], and the
//! human confirms. Everything here keeps working with no network service in
//! existence — that is the point of Layer 1 in the roadmap.
//!
//! # Reachability, and whose servers provide it
//!
//! Trust needs no server; *reachability* does, once the two devices are not on
//! the same wire. [`MeshMode::Discovery`] — the default — uses relays and a
//! pkarr/DNS directory so two machines behind two different NATs can find each
//! other by key alone. Today those are n0's public servers, which means this
//! device publishes its public key and current addresses somewhere public;
//! [`MeshMode::LocalOnly`] is the opt-out and [`MeshInfra`] is the seam the
//! hosted coordination plane replaces them through. Read
//! [`endpoint`](crate::endpoint) before shipping a device into someone's
//! house.
//!
//! [iroh]: https://docs.rs/iroh

#![warn(missing_docs)]

pub mod endpoint;
pub mod identity;
pub mod pairing;
pub mod sas;
pub mod ticket;

pub use endpoint::{MeshConnection, MeshEndpoint, MeshInfra, MeshMode, MeshStream, PathKind, ALPN};
pub use identity::{DeviceId, DeviceIdentity};
pub use pairing::{IssuedTicket, PairedPeer, PairingError};
pub use sas::SasCode;
pub use ticket::{PairingTicket, PairingToken, TicketError, DEFAULT_TICKET_TTL};

/// Re-exported iroh types that appear in this crate's public API.
pub mod iroh_types {
    pub use iroh::endpoint::{Connection, RecvStream, SendStream};
    pub use iroh::{EndpointAddr, EndpointId, PublicKey, RelayUrl, SecretKey, TransportAddr};
}
