//! The guest-only egress door carried over virtio-socket.
//!
//! QEMU's user-mode NAT hands a guest a private gateway address that is
//! proxied to host loopback, so the secrets proxy can bind `127.0.0.1` and be
//! reachable from exactly one guest ([`crate::hv::GuestEgress::LoopbackGateway`]).
//! Virtualization.framework has no such path: its NAT puts every guest on a
//! shared bridge with an address of its own, and a listener bound on that
//! bridge's host address is reachable by every other guest and, on some
//! configurations, by the LAN.
//!
//! So the door is built the other way round. Nothing new listens on any host
//! interface at all:
//!
//! ```text
//!  guest                          astd-vz helper              astd
//!  -----                          --------------              ----
//!  HTTPS_PROXY=http://127.0.0.1:1021
//!  agent listens on the guest's
//!  own loopback ------------------.
//!                                 | AF_VSOCK connect (CID_HOST, 1021)
//!                                 v
//!                          VZVirtioSocketListener
//!                          prove the per-Instance key  ------.
//!                          (HMAC-SHA256, this label)         |
//!                                                            v
//!                                                  the instance's private
//!                                                  unix socket, owned by
//!                                                  the egress plane
//! ```
//!
//! Three properties fall out of that shape, and they are the whole reason
//! for it:
//!
//! * **Guest-only.** The address the guest is told to use is its own
//!   loopback. Another guest on the same bridge has a different loopback,
//!   and there is no host interface to aim at.
//! * **Instance-only.** A virtio socket belongs to one VM, and the helper
//!   that answers on it owns exactly one instance. The HMAC proof is
//!   belt-and-braces on top of that, and it uses a label of its own so a
//!   control-channel or GPU proof cannot be replayed here.
//! * **Nothing on the wire.** The host end is a unix socket under
//!   `$ASTERISM_HOME`, not a TCP port. There is no port for anything on this
//!   device to connect to either.
//!
//! The frames below are the handshake only. Once both sides have proved the
//! key, the connection carries the guest's HTTP CONNECT bytes verbatim and
//! this module has nothing more to say about them.

use std::io::{BufRead, Read, Write};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Host vsock port the guest agent dials for the egress door.
///
/// One below the guest-control port (1023) and the GPU hop (1022), and in
/// the privileged range for the same reason they are: inside the guest only
/// root may bind it, and root already holds the key.
pub const EGRESS_VSOCK_PORT: u32 = 1021;

/// TCP port the guest agent puts the door on, inside the guest.
///
/// The same number as the vsock port because there is no reason for them to
/// differ and one number is easier to recognise in a `HTTPS_PROXY` than two.
/// It is a per-guest namespace, so this is fixed rather than allocated: two
/// instances never collide, and a daemon restart reclaims it by construction.
pub const EGRESS_GUEST_PORT: u16 = 1021;

/// The address the guest reaches the door on: its own loopback.
pub const EGRESS_GUEST_GATEWAY: &str = "127.0.0.1";

/// Well-known AF_VSOCK context id of the host. Fixed by the vsock ABI.
pub const VMADDR_CID_HOST: u32 = 2;

/// HMAC transcript prefix. Distinct from the guest agent's
/// `asterism-guest` and the GPU hop's `asterism-guest-gpu`, so a proof
/// minted for one hop cannot stand in for another.
pub const EGRESS_PROOF_LABEL: &str = "asterism-guest-egress";

/// What the guest calls itself on this hop.
pub const EGRESS_AGENT: &str = "asterism-egress";

/// The only version.
pub const EGRESS_VERSION: u32 = 1;

/// Longest handshake line either side will read. The frames are three small
/// JSON objects; this only exists so an unauthenticated peer cannot make the
/// other end allocate.
const MAX_LINE: usize = 8 * 1024;

/// Guest's opening frame.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DoorHello {
    pub agent: String,
    pub versions: Vec<u32>,
    pub nonce: String,
}

/// Host's answer, carrying its own proof.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DoorAccept {
    pub version: u32,
    pub nonce: String,
    pub proof: String,
}

/// Guest's confirmation, carrying its proof.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DoorWelcome {
    pub ok: bool,
    #[serde(default)]
    pub proof: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Why a door handshake did not complete. A plain message: nothing here has
/// a value or a handle in it, and both ends log it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DoorError {
    pub message: String,
}

impl DoorError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl std::fmt::Display for DoorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for DoorError {}

impl From<std::io::Error> for DoorError {
    fn from(error: std::io::Error) -> Self {
        Self::new(error.to_string())
    }
}

/// HMAC-SHA256 over this hop's transcript.
pub fn egress_proof(
    key: &[u8; 32],
    version: u32,
    side: &str,
    guest_nonce: &str,
    host_nonce: &str,
) -> String {
    let message = format!("{EGRESS_PROOF_LABEL}/{version} {side} {guest_nonce} {host_nonce}");
    hex(&hmac_sha256(key, message.as_bytes()))
}

pub fn verify_egress_proof(
    key: &[u8; 32],
    version: u32,
    side: &str,
    guest_nonce: &str,
    host_nonce: &str,
    proof: &str,
) -> bool {
    same_proof(
        proof,
        &egress_proof(key, version, side, guest_nonce, host_nonce),
    )
}

/// Host half: read the guest's hello, prove the key, check the guest's proof.
///
/// Returns the negotiated version. Everything after it on this stream is the
/// guest's proxy traffic.
pub fn door_host_handshake(
    reader: &mut impl BufRead,
    writer: &mut impl Write,
    key: &[u8; 32],
    host_nonce: &str,
) -> Result<u32, DoorError> {
    let hello: DoorHello = read_line(reader)?;
    if hello.agent != EGRESS_AGENT {
        return Err(DoorError::new(format!(
            "the caller on vsock port {EGRESS_VSOCK_PORT} calls itself {:?}, not {EGRESS_AGENT}",
            hello.agent
        )));
    }
    if !hello.versions.contains(&EGRESS_VERSION) {
        return Err(DoorError::new(
            "no egress-door protocol version in common with this helper",
        ));
    }
    write_line(
        writer,
        &DoorAccept {
            version: EGRESS_VERSION,
            nonce: host_nonce.to_owned(),
            proof: egress_proof(key, EGRESS_VERSION, "host", &hello.nonce, host_nonce),
        },
    )?;
    let welcome: DoorWelcome = read_line(reader)?;
    if !welcome.ok {
        return Err(DoorError::new(
            welcome
                .error
                .unwrap_or_else(|| "the guest refused the egress door".into()),
        ));
    }
    if !verify_egress_proof(
        key,
        EGRESS_VERSION,
        "guest",
        &hello.nonce,
        host_nonce,
        &welcome.proof,
    ) {
        return Err(DoorError::new(
            "the caller on the egress door did not prove it holds this instance's key",
        ));
    }
    Ok(EGRESS_VERSION)
}

/// Guest half of the same handshake.
pub fn door_guest_handshake(
    reader: &mut impl BufRead,
    writer: &mut impl Write,
    key: &[u8; 32],
    guest_nonce: &str,
) -> Result<u32, DoorError> {
    write_line(
        writer,
        &DoorHello {
            agent: EGRESS_AGENT.into(),
            versions: vec![EGRESS_VERSION],
            nonce: guest_nonce.to_owned(),
        },
    )?;
    let accept: DoorAccept = read_line(reader)?;
    if accept.version != EGRESS_VERSION {
        return Err(DoorError::new(format!(
            "the egress door picked unsupported version {}",
            accept.version
        )));
    }
    if !verify_egress_proof(
        key,
        EGRESS_VERSION,
        "host",
        guest_nonce,
        &accept.nonce,
        &accept.proof,
    ) {
        // Deliberately answered rather than dropped: the other end is this
        // instance's own helper in every case that is not an attack, and a
        // silent close there is a boot nobody can explain.
        let _ = write_line(
            writer,
            &DoorWelcome {
                ok: false,
                proof: String::new(),
                error: Some("the egress door did not prove it holds this instance's key".into()),
            },
        );
        return Err(DoorError::new(
            "the egress door did not prove it holds this instance's key",
        ));
    }
    write_line(
        writer,
        &DoorWelcome {
            ok: true,
            proof: egress_proof(key, EGRESS_VERSION, "guest", guest_nonce, &accept.nonce),
            error: None,
        },
    )?;
    Ok(EGRESS_VERSION)
}

fn read_line<T: for<'de> Deserialize<'de>>(reader: &mut impl BufRead) -> Result<T, DoorError> {
    let mut line = Vec::with_capacity(256);
    let read = reader
        .take((MAX_LINE + 1) as u64)
        .read_until(b'\n', &mut line)?;
    if read == 0 {
        return Err(DoorError::new("the egress door peer closed mid-handshake"));
    }
    if line.len() > MAX_LINE || !line.ends_with(b"\n") {
        return Err(DoorError::new(format!(
            "an egress door handshake line exceeds {MAX_LINE} bytes"
        )));
    }
    while matches!(line.last(), Some(b'\n' | b'\r')) {
        line.pop();
    }
    serde_json::from_slice(&line).map_err(|error| DoorError::new(error.to_string()))
}

fn write_line(writer: &mut impl Write, value: &impl Serialize) -> Result<(), DoorError> {
    let mut line = serde_json::to_vec(value).map_err(|error| DoorError::new(error.to_string()))?;
    line.push(b'\n');
    writer.write_all(&line)?;
    writer.flush()?;
    Ok(())
}

fn same_proof(left: &str, right: &str) -> bool {
    left.len() == right.len()
        && left
            .bytes()
            .zip(right.bytes())
            .fold(0u8, |diff, (a, b)| diff | (a ^ b))
            == 0
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut padded = [0u8; BLOCK];
    if key.len() > BLOCK {
        padded[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        padded[..key.len()].copy_from_slice(key);
    }
    let mut inner = Sha256::new();
    inner.update(padded.map(|byte| byte ^ 0x36));
    inner.update(message);
    let inner = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(padded.map(|byte| byte ^ 0x5c));
    outer.update(inner);
    outer.finalize().into()
}

/// Copy one direction of an already-authenticated door connection.
///
/// Shared by both ends because both do exactly this and getting the
/// half-close wrong is what turns a working proxy into one that hangs on the
/// last response. Returns bytes copied.
pub fn pump(mut from: impl Read, mut to: impl Write) -> std::io::Result<u64> {
    let mut buffer = [0u8; 32 * 1024];
    let mut total = 0u64;
    loop {
        let read = match from.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => read,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        };
        to.write_all(&buffer[..read])?;
        to.flush()?;
        total += read as u64;
    }
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::BufReader;
    use std::os::unix::net::UnixStream;

    fn key(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    #[test]
    fn both_ends_prove_the_instance_key() {
        let (guest, host) = UnixStream::pair().unwrap();
        let guest_key = key(0x11);
        let thread = std::thread::spawn(move || {
            let mut reader = BufReader::new(guest.try_clone().unwrap());
            let mut writer = guest;
            door_guest_handshake(&mut reader, &mut writer, &guest_key, "guest-nonce")
        });
        let mut reader = BufReader::new(host.try_clone().unwrap());
        let mut writer = host;
        let version = door_host_handshake(&mut reader, &mut writer, &key(0x11), "host-nonce")
            .expect("the host half completes");
        assert_eq!(version, EGRESS_VERSION);
        assert_eq!(thread.join().unwrap().unwrap(), EGRESS_VERSION);
    }

    #[test]
    fn a_caller_without_the_instance_key_is_refused() {
        let (guest, host) = UnixStream::pair().unwrap();
        let thread = std::thread::spawn(move || {
            let mut reader = BufReader::new(guest.try_clone().unwrap());
            let mut writer = guest;
            // A guest that holds some other instance's key.
            door_guest_handshake(&mut reader, &mut writer, &key(0x22), "guest-nonce")
        });
        let mut reader = BufReader::new(host.try_clone().unwrap());
        let mut writer = host;
        let refusal = door_host_handshake(&mut reader, &mut writer, &key(0x11), "host-nonce")
            .expect_err("a wrong key is refused");
        assert!(refusal.message.contains("did not prove"), "{refusal}");
        assert!(thread.join().unwrap().is_err());
    }

    /// The three vsock hops share one per-instance key and are separated only
    /// by their transcript label. A proof minted for one must not open
    /// another.
    #[test]
    fn a_control_or_gpu_proof_does_not_open_the_door() {
        let key = key(0x33);
        let door = egress_proof(&key, 1, "host", "g", "h");
        let control = crate::remote_gpu_guest::guest_agent_style_proof(&key, 1, "host", "g", "h");
        let gpu = crate::remote_gpu_guest::gpu_hmac_proof(&key, 1, "host", "g", "h");
        assert_ne!(door, control);
        assert_ne!(door, gpu);
        assert!(!verify_egress_proof(&key, 1, "host", "g", "h", &control));
        assert!(!verify_egress_proof(&key, 1, "host", "g", "h", &gpu));
    }

    #[test]
    fn a_stranger_that_is_not_the_agent_is_named_rather_than_spliced() {
        let (guest, host) = UnixStream::pair().unwrap();
        std::thread::spawn(move || {
            let mut guest = guest;
            let _ = guest.write_all(b"{\"agent\":\"curl\",\"versions\":[1],\"nonce\":\"n\"}\n");
        });
        let mut reader = BufReader::new(host.try_clone().unwrap());
        let mut writer = host;
        let refusal = door_host_handshake(&mut reader, &mut writer, &key(0x11), "host-nonce")
            .expect_err("an unknown caller is refused");
        assert!(refusal.message.contains("curl"), "{refusal}");
    }

    #[test]
    fn a_handshake_line_is_bounded() {
        let (guest, host) = UnixStream::pair().unwrap();
        std::thread::spawn(move || {
            let mut guest = guest;
            let _ = guest.write_all(&vec![b'x'; MAX_LINE * 2]);
        });
        let mut reader = BufReader::new(host.try_clone().unwrap());
        let mut writer = host;
        let refusal = door_host_handshake(&mut reader, &mut writer, &key(0x11), "host-nonce")
            .expect_err("an oversized line is refused");
        assert!(refusal.message.contains("exceeds"), "{refusal}");
    }
}
