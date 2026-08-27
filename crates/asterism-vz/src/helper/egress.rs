//! The helper's end of the secret-egress door.
//!
//! A guest connects out on vsock port
//! [`EGRESS_VSOCK_PORT`](asterism_core::egress_door::EGRESS_VSOCK_PORT). VZ
//! offers that connection to the listener delegate installed in
//! [`super::vm`], which duplicates the descriptor and hands it here. This
//! module proves the per-Instance key over the door's own HMAC transcript
//! and then splices the stream to the private unix socket `astd`'s egress
//! plane owns.
//!
//! Nothing here parses, buffers or logs what it carries. The CONNECT line,
//! the TLS after it, the handle inside that — all of it is opaque bytes on
//! this hop. The substitution happens in `astd`, at the far end.
//!
//! Two facts make this a guest-only door rather than a listener:
//!
//! * A virtio socket belongs to one VM. This helper owns one instance, so
//!   the only thing that can arrive here is that instance's guest.
//! * The host end is a unix socket in that instance's directory. There is no
//!   TCP port on this device, so there is nothing for another guest, another
//!   instance, or the LAN to aim at even in principle.

use std::io::{BufReader, Write};
use std::net::Shutdown;
use std::os::unix::io::{FromRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use asterism_core::egress_door::{door_host_handshake, pump};

/// How long the guest may take over the handshake. Short: three small JSON
/// lines on a socket inside one machine.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

/// Run one accepted door connection on a thread of its own.
///
/// `live` is cleared when the session ends, which is how the run loop knows
/// it may release the `VZVirtioSocketConnection` this descriptor came from.
pub fn carry(fd: RawFd, key: [u8; 32], socket: PathBuf, instance: String, live: Arc<AtomicBool>) {
    std::thread::spawn(move || {
        let outcome = session(fd, &key, &socket);
        live.store(false, Ordering::SeqCst);
        if let Err(error) = outcome {
            eprintln!("astd-vz: {instance}: egress door session ended: {error:#}");
        }
    });
}

fn session(fd: RawFd, key: &[u8; 32], socket: &Path) -> Result<()> {
    // SAFETY: the descriptor was duplicated for this session and nothing
    // else holds it. `UnixStream` is used here as a handle for read, write,
    // timeouts and shutdown — all address-family-agnostic — rather than as
    // a claim that this is AF_UNIX. It is AF_VSOCK.
    let guest = unsafe { UnixStream::from_raw_fd(fd) };
    guest
        .set_read_timeout(Some(HANDSHAKE_TIMEOUT))
        .context("setting the egress door handshake timeout")?;
    guest
        .set_write_timeout(Some(HANDSHAKE_TIMEOUT))
        .context("setting the egress door handshake write timeout")?;

    let mut reader = BufReader::new(
        guest
            .try_clone()
            .context("cloning the egress door socket")?,
    );
    let mut writer = guest
        .try_clone()
        .context("cloning the egress door socket to answer on")?;
    door_host_handshake(&mut reader, &mut writer, key, &nonce()?)
        .map_err(|error| anyhow!("{error}"))?;
    // The guest sends its CONNECT immediately after proving the key, so the
    // handshake reader may already hold the first bytes of it. Dropping the
    // reader without replaying them would lose exactly one request head,
    // once, on a fast guest — the kind of bug that looks like an unrelated
    // TLS failure hours later.
    let pending = reader.buffer().to_vec();
    drop(reader);
    guest
        .set_read_timeout(None)
        .context("clearing the egress door handshake timeout")?;
    guest
        .set_write_timeout(None)
        .context("clearing the egress door handshake write timeout")?;

    let proxy = UnixStream::connect(socket).with_context(|| {
        format!(
            "connecting this instance's egress proxy at {}",
            socket.display()
        )
    })?;
    if !pending.is_empty() {
        (&proxy)
            .write_all(&pending)
            .context("forwarding the guest's first bytes to the egress proxy")?;
    }

    std::thread::scope(|scope| {
        scope.spawn(|| {
            let _ = pump(&guest, &proxy);
            let _ = proxy.shutdown(Shutdown::Write);
            let _ = guest.shutdown(Shutdown::Read);
        });
        let _ = pump(&proxy, &guest);
        let _ = guest.shutdown(Shutdown::Write);
        let _ = proxy.shutdown(Shutdown::Read);
    });
    Ok(())
}

fn nonce() -> Result<String> {
    asterism_vz::guest::nonce()
}

#[cfg(test)]
mod tests {
    use super::*;
    use asterism_core::egress_door::door_guest_handshake;
    use std::io::Read;
    use std::os::unix::io::IntoRawFd;
    use std::os::unix::net::UnixListener;

    /// The whole hop, minus VZ: a guest that proves the key has its bytes
    /// delivered to the proxy socket, and the proxy's answer comes back.
    #[test]
    fn an_authenticated_guest_is_spliced_to_the_instance_proxy() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("proxy.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let proxy = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut seen = [0u8; 21];
            stream.read_exact(&mut seen).unwrap();
            assert_eq!(&seen, b"CONNECT api.x:443 \r\n\n");
            stream.write_all(b"HTTP/1.1 200 OK\r\n\r\n").unwrap();
        });

        let (guest, host) = UnixStream::pair().unwrap();
        let key = [0x5au8; 32];
        let live = Arc::new(AtomicBool::new(true));
        carry(
            host.into_raw_fd(),
            key,
            socket.clone(),
            "test".into(),
            live.clone(),
        );

        let mut reader = BufReader::new(guest.try_clone().unwrap());
        let mut writer = guest.try_clone().unwrap();
        door_guest_handshake(&mut reader, &mut writer, &key, "guest-nonce").unwrap();
        writer.write_all(b"CONNECT api.x:443 \r\n\n").unwrap();
        let mut answer = String::new();
        reader.read_to_string(&mut answer).unwrap();
        assert!(answer.ends_with("HTTP/1.1 200 OK\r\n\r\n"), "{answer:?}");
        proxy.join().unwrap();
    }

    /// A caller that does not hold the key never reaches the proxy socket,
    /// and the session ends rather than splicing anything.
    #[test]
    fn a_caller_without_the_key_never_reaches_the_proxy() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("proxy.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        listener.set_nonblocking(true).unwrap();

        let (guest, host) = UnixStream::pair().unwrap();
        let live = Arc::new(AtomicBool::new(true));
        carry(
            host.into_raw_fd(),
            [0x11u8; 32],
            socket.clone(),
            "test".into(),
            live.clone(),
        );

        let mut reader = BufReader::new(guest.try_clone().unwrap());
        let mut writer = guest.try_clone().unwrap();
        // Some other instance's key.
        let _ = door_guest_handshake(&mut reader, &mut writer, &[0x22u8; 32], "guest-nonce");
        for _ in 0..200 {
            if !live.load(Ordering::SeqCst) {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(!live.load(Ordering::SeqCst), "the refused session ended");
        assert!(
            listener.accept().is_err(),
            "nothing connected to the instance proxy"
        );
    }
}
