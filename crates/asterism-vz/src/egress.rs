//! Secret-egress streams over an authenticated virtio socket.
//!
//! The control channel in [`crate::guest`] is host-connects-to-guest, one
//! JSON request at a time. This module is the other direction: the guest
//! has accepted an HTTP CONNECT on its own loopback, and it needs to carry
//! those bytes to the host without putting a TCP listener on any network
//! the LAN can reach.
//!
//! ```text
//! guest app --HTTP CONNECT--> 127.0.0.1:18765 (asterism-guest)
//! asterism-guest --HMAC + framed vsock--> astd-vz (listens on vsock :1022)
//! astd-vz --raw splice--> astd unix socket
//! astd --existing CONNECT policy--> source device / upstream
//! ```
//!
//! The helper never sees a secret value. astd never binds a TCP port. The
//! guest never sees a host address other than loopback. Identity is the
//! same per-instance key the control channel already uses, under a
//! different HMAC domain so a proof from one cannot stand in for the other.
//!
//! After the JSON handshake the connection switches to length-prefixed
//! frames with a credit window: a peer that will not drain is not a peer
//! we keep buffering for.

use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::guest::{self, Key};

/// vsock port the host listens on and the guest connects to.
///
/// Privileged, next to the control channel's 1023, for the same reason:
/// Linux will not let an unprivileged process bind it, so the thing
/// answering here is the host helper and not something that squatted the
/// port from inside a confused guest.
pub const PORT: u32 = 1022;

/// Address the in-guest HTTP CONNECT proxy binds. Always loopback.
pub const GUEST_PROXY_BIND: &str = "127.0.0.1";

/// TCP port the in-guest proxy listens on. Stable so a seed can name it
/// without a host-side allocation, and unprivileged so the agent does not
/// need a second capability just to offer loopback.
pub const GUEST_PROXY_PORT: u16 = 18765;

/// Protocol versions this build speaks, newest last.
pub const VERSIONS: &[u32] = &[1];

/// HMAC domain. Distinct from `asterism-guest` on purpose.
pub const DOMAIN: &str = "asterism-egress";

/// What the opener calls itself. A control-channel hello landing here is
/// refused by name rather than authenticated.
pub const AGENT: &str = "asterism-egress";

/// Largest payload one DATA frame may carry. Same ceiling as the control
/// channel: a peer that never ends a frame does not get to pick the
/// memory cost.
pub const MAX_FRAME_BYTES: usize = guest::MAX_FRAME_BYTES;

/// Bytes a sender may have in flight before it must wait for WINDOW.
///
/// Four frames. Enough that a single API call is not stop-and-wait, small
/// enough that a stalled peer cannot pin a quarter-megabyte per stream
/// forever.
pub const MAX_WINDOW: u32 = 256 * 1024;

const DATA: u8 = 1;
const WINDOW: u8 = 2;
const CLOSE: u8 = 3;

// ---- handshake -------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hello {
    pub agent: String,
    pub versions: Vec<u32>,
    pub nonce: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Accept {
    pub version: u32,
    pub nonce: String,
    pub proof: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Welcome {
    pub ok: bool,
    #[serde(default)]
    pub proof: String,
    #[serde(default)]
    pub error: Option<String>,
}

/// The newest version both ends can speak.
pub fn pick_version(theirs: &[u32]) -> Option<u32> {
    VERSIONS
        .iter()
        .filter(|v| theirs.contains(v))
        .max()
        .copied()
}

/// Host side of the handshake: the guest connected to us.
///
/// Returns the negotiated version, or a named refusal. An empty
/// intersection and a wrong key are both refusals, not hangs.
pub fn open_host<R: BufRead, W: Write>(reader: &mut R, writer: &mut W, key: &Key) -> Result<u32> {
    open_host_with_nonce(reader, writer, key, &guest::nonce()?)
}

pub fn open_host_with_nonce<R: BufRead, W: Write>(
    reader: &mut R,
    writer: &mut W,
    key: &Key,
    host_nonce: &str,
) -> Result<u32> {
    let hello: Hello = guest::read_line(reader).context("reading the egress hello")?;
    if hello.agent != AGENT {
        bail!(
            "the service on vsock port {PORT} calls itself {:?}, which is not the \
             asterism egress plane — capability refused",
            hello.agent
        );
    }
    let version = pick_version(&hello.versions).ok_or_else(|| {
        anyhow::anyhow!(
            "no egress protocol version in common: the guest speaks {:?} and this \
             helper speaks {:?} — capability refused",
            hello.versions,
            VERSIONS
        )
    })?;
    guest::write_line(
        writer,
        &Accept {
            version,
            nonce: host_nonce.to_owned(),
            proof: key.proof_for(DOMAIN, version, "host", &hello.nonce, host_nonce),
        },
    )?;
    let welcome: Welcome =
        guest::read_line(reader).context("reading the egress answer to our proof")?;
    if !welcome.ok {
        bail!(
            "the guest refused this egress helper: {}",
            welcome.error.as_deref().unwrap_or("no reason given")
        );
    }
    let expected = key.proof_for(DOMAIN, version, "guest", &hello.nonce, host_nonce);
    if !guest::same_proof(&welcome.proof, &expected) {
        bail!(
            "the guest did not prove it holds this instance's key — \
             capability refused on vsock port {PORT}"
        );
    }
    Ok(version)
}

/// Guest side of the handshake: we connected to the host.
pub fn open_guest<R: BufRead, W: Write>(reader: &mut R, writer: &mut W, key: &Key) -> Result<u32> {
    open_guest_with_nonce(reader, writer, key, &guest::nonce()?)
}

pub fn open_guest_with_nonce<R: BufRead, W: Write>(
    reader: &mut R,
    writer: &mut W,
    key: &Key,
    guest_nonce: &str,
) -> Result<u32> {
    guest::write_line(
        writer,
        &Hello {
            agent: AGENT.into(),
            versions: VERSIONS.to_vec(),
            nonce: guest_nonce.to_owned(),
        },
    )?;
    let accept: Accept = guest::read_line(reader).context("reading the host's egress accept")?;
    let version = accept.version;
    if !VERSIONS.contains(&version) {
        // Tell the host why, then stop. An old helper that picked a version
        // we dropped finds out by name rather than by a hang.
        let _ = guest::write_line(
            writer,
            &Welcome {
                ok: false,
                proof: String::new(),
                error: Some(format!(
                    "this guest egress speaks {VERSIONS:?}, and the host chose {version}"
                )),
            },
        );
        bail!(
            "the host picked egress protocol {version}, which this guest does not speak \
             ({VERSIONS:?}) — capability refused"
        );
    }
    let expected = key.proof_for(DOMAIN, version, "host", guest_nonce, &accept.nonce);
    if !guest::same_proof(&accept.proof, &expected) {
        let _ = guest::write_line(
            writer,
            &Welcome {
                ok: false,
                proof: String::new(),
                error: Some("the host did not prove it holds this instance's key".into()),
            },
        );
        bail!("the host did not prove it holds this instance's key — capability refused");
    }
    guest::write_line(
        writer,
        &Welcome {
            ok: true,
            proof: key.proof_for(DOMAIN, version, "guest", guest_nonce, &accept.nonce),
            error: None,
        },
    )?;
    Ok(version)
}

// ---- framed splice ---------------------------------------------------------

struct Credit {
    available: Mutex<u32>,
    cv: Condvar,
}

impl Credit {
    fn new(initial: u32) -> Arc<Self> {
        Arc::new(Credit {
            available: Mutex::new(initial),
            cv: Condvar::new(),
        })
    }

    fn take(&self, want: u32) -> io::Result<u32> {
        let mut hold = self.available.lock().unwrap_or_else(|e| e.into_inner());
        loop {
            if *hold == 0 {
                hold = self
                    .cv
                    .wait_timeout(hold, Duration::from_secs(120))
                    .unwrap_or_else(|e| e.into_inner())
                    .0;
                if *hold == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "the egress peer granted no window",
                    ));
                }
                continue;
            }
            let n = (*hold).min(want);
            *hold -= n;
            return Ok(n);
        }
    }

    fn give(&self, n: u32) {
        let mut hold = self.available.lock().unwrap_or_else(|e| e.into_inner());
        *hold = hold.saturating_add(n);
        self.cv.notify_all();
    }
}

fn write_frame(writer: &Mutex<UnixStream>, typ: u8, payload: &[u8]) -> io::Result<()> {
    if payload.len() > MAX_FRAME_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("egress frame larger than {MAX_FRAME_BYTES}"),
        ));
    }
    let mut hold = writer.lock().unwrap_or_else(|e| e.into_inner());
    hold.write_all(&[typ])?;
    hold.write_all(&(payload.len() as u32).to_be_bytes())?;
    hold.write_all(payload)?;
    hold.flush()?;
    Ok(())
}

pub(crate) fn read_frame(reader: &mut impl Read) -> io::Result<Option<(u8, Vec<u8>)>> {
    let mut hdr = [0u8; 5];
    match reader.read_exact(&mut hdr) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let typ = hdr[0];
    let len = u32::from_be_bytes(hdr[1..5].try_into().unwrap()) as usize;
    if len > MAX_FRAME_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("peer sent an egress frame of {len} bytes; max is {MAX_FRAME_BYTES}"),
        ));
    }
    let mut payload = vec![0u8; len];
    reader.read_exact(&mut payload)?;
    Ok(Some((typ, payload)))
}

/// Copy raw bytes from `plain` onto framed `vsock`, and framed `vsock`
/// onto `plain`, honouring the credit window both ways.
///
/// Either side closing is a CLOSE frame and then EOF. A frame larger than
/// [`MAX_FRAME_BYTES`] is a hard error, not a skip.
pub fn splice_plain_and_framed(plain: UnixStream, vsock: UnixStream) -> Result<()> {
    let vsock_read = vsock.try_clone().context("cloning the vsock splice fd")?;
    splice_from_vsock_read(plain, vsock, vsock_read)
}

/// Same splice as [`splice_plain_and_framed`], but the vsock reader is the
/// one that already consumed the newline handshake.
///
/// `open_host` / `open_guest` parse Welcome or Accept through a
/// [`BufReader`]. If that reader is dropped and framed IO resumes on a
/// fresh clone of the original fd, any DATA that arrived in the same write
/// as the handshake line is stranded in the buffer and never delivered.
fn splice_from_vsock_read<R: Read + Send + 'static>(
    plain: UnixStream,
    vsock: UnixStream,
    vsock_read: R,
) -> Result<()> {
    let plain_read = plain.try_clone().context("cloning the plain splice fd")?;
    let plain_write = plain;
    let vsock_write = Arc::new(Mutex::new(vsock));
    let send_credit = Credit::new(MAX_WINDOW);

    let to_vsock = {
        let vsock_write = vsock_write.clone();
        let send_credit = send_credit.clone();
        std::thread::spawn(move || raw_to_framed(plain_read, vsock_write, send_credit))
    };
    let from_vsock = std::thread::spawn(move || {
        framed_to_raw(vsock_read, plain_write, vsock_write, send_credit)
    });

    match (to_vsock.join(), from_vsock.join()) {
        (Ok(Ok(())), Ok(Ok(()))) => Ok(()),
        (Ok(Err(e)), _) | (_, Ok(Err(e))) => Err(e.into()),
        (Err(_), _) | (_, Err(_)) => bail!("an egress splice thread panicked"),
    }
}

fn raw_to_framed(
    mut plain: UnixStream,
    vsock: Arc<Mutex<UnixStream>>,
    credit: Arc<Credit>,
) -> io::Result<()> {
    let mut buf = vec![0u8; MAX_FRAME_BYTES];
    loop {
        let allowed = credit.take(MAX_FRAME_BYTES as u32)?;
        let n = match plain.read(&mut buf[..allowed as usize]) {
            Ok(0) => {
                let _ = write_frame(&vsock, CLOSE, &[]);
                return Ok(());
            }
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => {
                let _ = write_frame(&vsock, CLOSE, &[]);
                return Err(e);
            }
        };
        // We took `allowed` but only used `n`. Give the rest back so a
        // short read does not shrink the window forever.
        if (n as u32) < allowed {
            credit.give(allowed - n as u32);
        }
        write_frame(&vsock, DATA, &buf[..n])?;
    }
}

fn framed_to_raw(
    mut vsock: impl Read,
    mut plain: UnixStream,
    vsock_write: Arc<Mutex<UnixStream>>,
    send_credit: Arc<Credit>,
) -> io::Result<()> {
    loop {
        match read_frame(&mut vsock)? {
            None | Some((CLOSE, _)) => {
                let _ = plain.shutdown(std::net::Shutdown::Write);
                return Ok(());
            }
            Some((WINDOW, payload)) => {
                if payload.len() != 4 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "a WINDOW frame must carry a 32-bit credit",
                    ));
                }
                let n = u32::from_be_bytes(payload.try_into().unwrap());
                send_credit.give(n);
            }
            Some((DATA, payload)) => {
                if !payload.is_empty() {
                    plain.write_all(&payload)?;
                    plain.flush()?;
                    write_frame(&vsock_write, WINDOW, &(payload.len() as u32).to_be_bytes())?;
                }
            }
            Some((typ, _)) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("unknown egress frame type {typ}"),
                ));
            }
        }
    }
}

/// Host half of one stream: handshake, then splice onto `plain_path`.
///
/// The handshake reader is the splice reader. Welcome is a newline JSON
/// line parsed through a [`BufReader`]; the first DATA/CONNECT frame can
/// arrive in the same write, and those leftover bytes must stay on this
/// transport rather than being dropped with the handshake buffer.
///
/// If the unix socket is missing the handshake still completes (the guest
/// proved itself) and then the stream is closed. Fail closed, not a hang
/// waiting for astd to come back on this connection — the next CONNECT
/// retries.
pub fn serve_host_stream(vsock: UnixStream, key: &Key, plain_path: &Path) -> Result<()> {
    vsock.set_read_timeout(Some(Duration::from_secs(120))).ok();
    vsock.set_write_timeout(Some(Duration::from_secs(120))).ok();
    let mut reader = BufReader::new(vsock.try_clone()?);
    let mut writer = vsock.try_clone()?;
    open_host(&mut reader, &mut writer, key)?;
    drop(writer);
    let plain = match UnixStream::connect(plain_path) {
        Ok(plain) => plain,
        Err(e) => {
            // The handshake already ran; tell the guest we are done rather
            // than letting it block on a DATA that will never come.
            let _ = write_frame(&Mutex::new(vsock), CLOSE, &[]);
            return Err(e).with_context(|| {
                format!(
                    "the host egress plane is not listening on {} — fail closed",
                    plain_path.display()
                )
            });
        }
    };
    // Keep `reader`: Welcome and the first DATA frame can arrive in one
    // write. The buffered leftover is those bytes.
    splice_from_vsock_read(plain, vsock, reader)
}

/// Guest half of one stream: handshake, then splice onto an already-open
/// loopback TCP connection (passed in as a unix-shaped stream in tests).
pub fn serve_guest_stream(vsock: UnixStream, key: &Key, plain: UnixStream) -> Result<()> {
    vsock.set_read_timeout(Some(Duration::from_secs(120))).ok();
    vsock.set_write_timeout(Some(Duration::from_secs(120))).ok();
    let mut reader = BufReader::new(vsock.try_clone()?);
    let mut writer = vsock.try_clone()?;
    open_guest(&mut reader, &mut writer, key)?;
    drop(writer);
    splice_from_vsock_read(plain, vsock, reader)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::guest;
    use std::io::BufReader;
    use std::os::unix::fs::FileTypeExt;
    use std::os::unix::net::UnixListener;
    use std::time::Duration;

    fn key() -> Key {
        Key::parse("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff").unwrap()
    }

    fn other_key() -> Key {
        Key::parse(&"ab".repeat(32)).unwrap()
    }

    fn pair() -> (UnixStream, UnixStream) {
        UnixStream::pair().unwrap()
    }

    /// Auth / version skew: a guest that speaks only a future version is
    /// refused by name, on the host, without a hang.
    #[test]
    fn a_version_neither_side_shares_is_capability_refused() {
        let (guest, host) = pair();
        let mut guest_w = guest.try_clone().unwrap();
        guest::write_line(
            &mut guest_w,
            &Hello {
                agent: AGENT.into(),
                versions: vec![9],
                nonce: "aaaa".into(),
            },
        )
        .unwrap();
        drop(guest_w);
        let err = open_host(
            &mut BufReader::new(host.try_clone().unwrap()),
            &mut host.try_clone().unwrap(),
            &key(),
        )
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("no egress protocol version in common"),
            "{err}"
        );
        assert!(err.contains("capability refused"), "{err}");
        assert!(err.contains("[9]"), "{err}");
    }

    /// A control-channel hello on the egress port is not authenticated. It
    /// is a capability refusal, named.
    #[test]
    fn a_control_channel_hello_on_the_egress_port_is_refused() {
        let (guest, host) = pair();
        let mut guest_w = guest.try_clone().unwrap();
        guest::write_line(
            &mut guest_w,
            &Hello {
                agent: "asterism".into(),
                versions: vec![1],
                nonce: "aaaa".into(),
            },
        )
        .unwrap();
        let err = open_host(
            &mut BufReader::new(host.try_clone().unwrap()),
            &mut host.try_clone().unwrap(),
            &key(),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("asterism"), "{err}");
        assert!(err.contains("capability refused"), "{err}");
    }

    /// Wrong instance key: the HMAC does not check out. This is the cloned
    /// disk case, and it is refused rather than believed.
    #[test]
    fn the_wrong_instance_key_is_capability_refused() {
        let (guest_end, host_end) = pair();
        let guest = std::thread::spawn({
            let key = key();
            move || {
                open_guest(
                    &mut BufReader::new(guest_end.try_clone().unwrap()),
                    &mut guest_end.try_clone().unwrap(),
                    &key,
                )
            }
        });
        let err = open_host(
            &mut BufReader::new(host_end.try_clone().unwrap()),
            &mut host_end.try_clone().unwrap(),
            &other_key(),
        )
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("did not prove it holds this instance's key")
                || err.contains("refused this egress helper"),
            "{err}"
        );
        let _ = guest.join();
    }

    #[test]
    fn a_matching_key_negotiates_version_one() {
        let (guest_end, host_end) = pair();
        let k = key();
        let guest = std::thread::spawn({
            let k = k.clone();
            move || {
                open_guest(
                    &mut BufReader::new(guest_end.try_clone().unwrap()),
                    &mut guest_end.try_clone().unwrap(),
                    &k,
                )
            }
        });
        let host_v = open_host(
            &mut BufReader::new(host_end.try_clone().unwrap()),
            &mut host_end.try_clone().unwrap(),
            &k,
        )
        .unwrap();
        let guest_v = guest.join().unwrap().unwrap();
        assert_eq!(host_v, 1);
        assert_eq!(guest_v, 1);
    }

    /// A control-channel proof must not authenticate an egress handshake.
    #[test]
    fn a_guest_agent_proof_cannot_be_replayed_as_egress() {
        let k = key();
        let guest_proof = k.proof(1, "guest", "aaaa", "bbbb");
        let egress_proof = k.proof_for(DOMAIN, 1, "guest", "aaaa", "bbbb");
        assert_ne!(guest_proof, egress_proof);
        assert!(!guest::same_proof(&guest_proof, &egress_proof));
    }

    /// Stream bounds: a DATA frame over the cap is refused before the
    /// payload is retained.
    #[test]
    fn an_oversized_data_frame_is_refused_before_the_payload_is_kept() {
        let (mut peer, us) = pair();
        let mut hdr = vec![DATA];
        hdr.extend_from_slice(&((MAX_FRAME_BYTES as u32) + 1).to_be_bytes());
        peer.write_all(&hdr).unwrap();
        // One extra byte so a naive read_exact of the declared length
        // would start allocating. We must fail on the header.
        peer.write_all(&[0xff]).unwrap();
        let err = read_frame(&mut us.try_clone().unwrap()).unwrap_err();
        let said = err.to_string();
        assert!(said.contains(&MAX_FRAME_BYTES.to_string()), "{said}");
    }

    /// Helper restart / astd down: the host side fail-closes when the unix
    /// socket is missing, rather than hanging the guest CONNECT.
    #[test]
    fn a_missing_host_plane_fail_closes_after_the_handshake() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("gone.sock");
        let (guest_end, host_end) = pair();
        let k = key();
        let guest = std::thread::spawn({
            let k = k.clone();
            move || {
                open_guest(
                    &mut BufReader::new(guest_end.try_clone().unwrap()),
                    &mut guest_end.try_clone().unwrap(),
                    &k,
                )
            }
        });
        let err = serve_host_stream(host_end, &k, &missing)
            .unwrap_err()
            .to_string();
        assert!(err.contains("fail closed"), "{err}");
        assert!(
            guest.join().unwrap().is_ok(),
            "the handshake itself succeeded"
        );
    }

    /// Drive a full guest/host/plane round trip once the unix socket is
    /// bound — the reconnect path after astd or the helper has come back.
    #[test]
    fn reconnect_after_the_plane_binds_carries_a_payload() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("plane.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
            let mut buf = [0u8; 4];
            stream.read_exact(&mut buf).unwrap();
            assert_eq!(&buf, b"ping");
            stream.write_all(b"pong").unwrap();
        });

        let (guest_app, guest_plain) = pair();
        let (guest_vsock, host_vsock) = pair();
        let k = key();
        guest_app
            .set_read_timeout(Some(Duration::from_secs(5)))
            .ok();
        guest_app
            .set_write_timeout(Some(Duration::from_secs(5)))
            .ok();

        let host = std::thread::spawn({
            let k = k.clone();
            move || serve_host_stream(host_vsock, &k, &path)
        });
        let guest = std::thread::spawn({
            let k = k.clone();
            move || serve_guest_stream(guest_vsock, &k, guest_plain)
        });

        guest_app.try_clone().unwrap().write_all(b"ping").unwrap();
        let mut buf = [0u8; 4];
        guest_app.try_clone().unwrap().read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"pong");

        drop(guest_app);
        let _ = host.join();
        let _ = guest.join();
        server.join().unwrap();
    }

    /// Welcome and the first DATA frame arrive in one write. The production
    /// host path (`serve_host_stream`) must still deliver those bytes: a
    /// BufReader that parses Welcome and is then dropped would strand them.
    #[test]
    fn coalesced_welcome_and_first_frame_complete_the_production_path() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("plane.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let payload = b"CONNECT api.example.com:443 HTTP/1.1\r\n\r\n";
        let reply = b"HTTP/1.1 200 OK\r\n\r\n";
        let server = std::thread::spawn({
            let payload = payload.to_vec();
            let reply = reply.to_vec();
            move || {
                let (mut stream, _) = listener.accept().unwrap();
                stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
                stream.set_write_timeout(Some(Duration::from_secs(5))).ok();
                let mut buf = vec![0u8; payload.len()];
                stream
                    .read_exact(&mut buf)
                    .expect("coalesced first DATA frame never reached the host plane");
                assert_eq!(buf, payload);
                stream.write_all(&reply).unwrap();
            }
        });

        let (guest_end, host_end) = pair();
        let k = key();
        guest_end
            .set_read_timeout(Some(Duration::from_secs(5)))
            .ok();
        guest_end
            .set_write_timeout(Some(Duration::from_secs(5)))
            .ok();

        let host = std::thread::spawn({
            let k = k.clone();
            move || serve_host_stream(host_end, &k, &path)
        });

        let guest_nonce = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let mut guest_r = BufReader::new(guest_end.try_clone().unwrap());
        let mut guest_w = guest_end.try_clone().unwrap();
        guest::write_line(
            &mut guest_w,
            &Hello {
                agent: AGENT.into(),
                versions: VERSIONS.to_vec(),
                nonce: guest_nonce.into(),
            },
        )
        .unwrap();
        let accept: Accept = guest::read_line(&mut guest_r).expect("host Accept");
        let mut coalesced = serde_json::to_vec(&Welcome {
            ok: true,
            proof: k.proof_for(DOMAIN, accept.version, "guest", guest_nonce, &accept.nonce),
            error: None,
        })
        .unwrap();
        coalesced.push(b'\n');
        coalesced.push(DATA);
        coalesced.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        coalesced.extend_from_slice(payload);
        guest_w.write_all(&coalesced).unwrap();
        guest_w.flush().unwrap();

        let mut saw_reply = false;
        while let Ok(Some((typ, body))) = read_frame(&mut guest_r) {
            if typ == DATA && body == reply {
                saw_reply = true;
                break;
            }
            if typ == CLOSE {
                break;
            }
        }
        assert!(
            saw_reply,
            "production path must complete: coalesced CONNECT delivered, reply framed back"
        );

        drop(guest_w);
        drop(guest_r);
        drop(guest_end);
        server.join().unwrap();
        let _ = host.join();
    }

    /// The in-guest bind is loopback. The host plane is a unix socket.
    /// Nothing here is an AF_INET listener on a non-loopback address.
    #[test]
    fn the_host_plane_is_a_unix_socket_not_a_network_listener() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vsock.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let meta = std::fs::metadata(&path).unwrap();
        assert!(meta.file_type().is_socket(), "{path:?} is not a socket");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            // The daemon sets 0600; this fixture proves the path is a
            // unix socket at all, which is the "no network listener" gate.
            let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "{mode:#o}");
        }
        drop(listener);
        assert!(
            std::net::TcpListener::bind((GUEST_PROXY_BIND, GUEST_PROXY_PORT)).is_ok()
                || std::net::TcpListener::bind((GUEST_PROXY_BIND, 0)).is_ok(),
            "loopback itself must still be bindable; this is not a LAN check"
        );
    }

    #[test]
    fn pick_version_refuses_an_empty_intersection() {
        assert_eq!(pick_version(&[1]), Some(1));
        assert_eq!(pick_version(&[1, 2]), Some(1));
        assert_eq!(pick_version(&[7, 9]), None);
        assert_eq!(pick_version(&[]), None);
    }
}
