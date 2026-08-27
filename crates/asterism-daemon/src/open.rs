//! `ast open NAME:PORT` — a port served inside a guest, on this device's
//! loopback, wherever in the orbit that guest actually is.
//!
//! The scene this exists for: an agent has been running all night on the
//! machine with the RAM, it built a UI, and in the morning somebody wants to
//! look at it from the laptop they are holding. The compute does not move —
//! that is the whole point — so what moves is one TCP connection at a time.
//!
//! Structurally this is [`crate::ssh`] with the key taken out and a port put
//! in, and it is answered in the same place and for the same reason: the
//! answer *outlives the reply*. What comes back is an address, and the
//! listener behind it has to still be there when the browser dials it, so the
//! [`Splice`] belongs to the connection that asked and dies with it. `ast`
//! holds its unix socket open until Ctrl-C; dropping it is the teardown, and
//! there is no state anywhere for a crash to leave behind.
//!
//! Nothing here registers with the instance lifecycle, and that is deliberate.
//! `ast down` releases a guest's *published* ports because those belong to the
//! instance's declaration; an opened port belongs to the command that opened
//! it. Connections through it fail the moment the guest stops — which is what
//! a stopped service looks like from a browser — and `ast up` makes the same
//! URL work again without the user retyping anything. The listener goes away
//! when Ctrl-C says so, and at no other time.
//!
//! ### What this is not
//!
//! It is not `ast create -p`. A published port is a durable declaration on
//! the device supplying the compute, bound there, promised by number, and
//! rebuilt across daemon restarts. This is a tunnel: nothing is declared,
//! nothing is written down, the far device's port space is untouched, and
//! opening a port here requires no cooperation from the instance beyond a
//! service that is already listening. That is why `ast open` does not require
//! the port to have been published, and why it never publishes one.
//!
//! Resolving the name — here, or on which peer, or nowhere reachable — is
//! [`crate::resolve`]'s, not this module's. Instance names are unique across
//! an orbit and every command that addresses one by bare name needs the same
//! answer and the same two refusals, so `ast open` was the first caller of
//! that function rather than the owner of it.
//!
//! ### The rules, and where each one is enforced
//!
//! Every refusal happens before a listener exists, because a URL that is
//! printed and then does not work is worse than no URL:
//!
//! * **Unknown instance** — with the names the orbit does have, since the
//!   next thing the user would do is ask for them.
//! * **The device is offline** — named as a fact about the device, with how
//!   long ago it was last heard from.
//! * **The instance is not running** — the same sentence `ast ssh` uses.
//! * **Asterism's guest-control port** — refused exactly as a published
//!   mapping is, and refused *again* on the far side, which is the side the
//!   rule protects.
//!
//! The last one is worth being explicit about: the checks here are a
//! courtesy, so the user gets a sentence instead of a dead socket. The checks
//! that matter are [`crate::mesh::resolve_open_target`]'s, on the device
//! supplying the compute, because that is the device whose guest is at stake.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use anyhow::{bail, Context, Result};

use asterism_core::open::{self, Target};
use asterism_core::protocol::Response;

use crate::mesh::{Mesh, Splice};
use crate::resolve::{self, Located};
use crate::Node;

/// The word for a port whose bytes never leave this device.
///
/// Deliberately in the same field as `direct` and `relay` rather than in a
/// flag beside them: a user reading `(local)` and a user reading `(relay)`
/// are being told the same kind of thing — where their bytes go.
const LOCAL_PATH: &str = "local";

/// Bind a loopback port here that reaches `port` inside `name`'s guest, and
/// say what was bound and where it lands.
///
/// Returns the reply and, when a listener was created, the lease on it. The
/// caller is [`crate::serve`], which keeps the lease for the life of the
/// connection.
pub(crate) async fn endpoint(
    name: &str,
    port: u16,
    local_port: Option<u16>,
    node: &Node,
    mesh: Option<&Arc<Mesh>>,
) -> (Response, Option<Splice>) {
    let target = Target {
        name: name.to_owned(),
        port,
    };
    match open_port(&target, local_port, node, mesh).await {
        Ok((response, splice)) => (response, splice),
        Err(e) => (
            Response::Error {
                message: format!("{e:#}"),
            },
            None,
        ),
    }
}

async fn open_port(
    target: &Target,
    local_port: Option<u16>,
    node: &Node,
    mesh: Option<&Arc<Mesh>>,
) -> Result<(Response, Option<Splice>)> {
    open::refuse_guest_control_port(target.port)?;

    // One question, answered the same way every name-addressed command will
    // answer it: here, somewhere else, or nowhere reachable — with the two
    // refusals already worded. See [`crate::resolve`].
    let located = resolve::locate(&target.name, &target.to_string(), node, mesh).await?;
    let (device, mesh) = match (located, mesh) {
        (Located::Here, _) => {
            let guest = crate::mesh::resolve_open_target(node, &target.name, target.port).await?;
            let (bound, splice) = listen_local(guest, local_port, target).await?;
            return Ok((
                Response::OpenPort {
                    local_port: bound,
                    instance: target.name.clone(),
                    device: node.device_name().await,
                    port: target.port,
                    path: LOCAL_PATH.to_owned(),
                    rtt_micros: None,
                },
                Some(splice),
            ));
        }
        (Located::On(device), Some(mesh)) => (device, mesh),
        // Not reachable: `locate` can only name a peer by asking one. Spelled
        // rather than unwrapped, because a daemon that panics here would take
        // every other instance on this device down with it.
        (Located::On(device), None) => {
            bail!(
                "{:?} is on {device}, which this device cannot reach without a mesh",
                target.name
            )
        }
    };

    let opened = mesh
        .port_splice(&device, &target.name, target.port, local_port)
        .await?;
    Ok((
        Response::OpenPort {
            local_port: opened.local_port,
            instance: target.name.clone(),
            device,
            port: target.port,
            path: opened.path,
            rtt_micros: opened.rtt_micros,
        },
        Some(opened.splice),
    ))
}

/// The listener for a guest whose compute is right here.
///
/// A shorter path than the mesh one and a shorter path than
/// [`crate::publish`]'s too — no declaration, no table, no rebind across
/// restarts. Each accepted connection is spliced straight to the guest's
/// private address, and the whole listener goes away when the [`Splice`] is
/// dropped.
async fn listen_local(
    guest: SocketAddr,
    local_port: Option<u16>,
    target: &Target,
) -> Result<(u16, Splice)> {
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, local_port.unwrap_or(0)))
        .await
        .with_context(|| match local_port {
            Some(port) => format!(
                "binding 127.0.0.1:{port} — another process or instance holds it. Leave \
                 --local-port off to take a free one"
            ),
            None => "binding a local port".to_owned(),
        })?;
    let bound = listener.local_addr()?.port();
    let described = target.to_string();
    let task = tokio::spawn(async move {
        let mut sessions = tokio::task::JoinSet::new();
        loop {
            let Ok((client, _)) = listener.accept().await else {
                return;
            };
            let described = described.clone();
            sessions.spawn(async move {
                if let Err(e) = splice(client, guest).await {
                    eprintln!("astd: opening {described} failed: {e:#}");
                }
            });
            while sessions.try_join_next().is_some() {}
        }
    });
    Ok((bound, Splice::new(task, None)))
}

async fn splice(mut client: tokio::net::TcpStream, guest: SocketAddr) -> Result<()> {
    let mut server = tokio::net::TcpStream::connect(guest)
        .await
        .with_context(|| format!("dialling {guest}"))?;
    let _ = client.set_nodelay(true);
    let _ = server.set_nodelay(true);
    tokio::io::copy_bidirectional(&mut client, &mut server)
        .await
        .map(|_| ())
        .context("splicing an opened connection")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The whole teardown story, in one test: what is bound while the lease
    /// is held carries bytes to the far side, and the moment the lease is
    /// dropped the port is gone. There is nothing else to clean up, which is
    /// why Ctrl-C is a complete answer.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn dropping_the_lease_closes_the_listener_and_frees_the_port() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // Stand in for the guest: an echo server on loopback.
        let guest = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let guest_addr = guest.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = guest.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 64];
                    if let Ok(n) = sock.read(&mut buf).await {
                        let _ = sock.write_all(&buf[..n]).await;
                    }
                });
            }
        });

        let target = Target {
            name: "bot".into(),
            port: guest_addr.port(),
        };
        let (bound, splice) = listen_local(guest_addr, None, &target).await.unwrap();
        assert_ne!(bound, 0, "an ephemeral port is still a port");

        let mut client = tokio::net::TcpStream::connect((Ipv4Addr::LOCALHOST, bound))
            .await
            .unwrap();
        client.write_all(b"hello").await.unwrap();
        let mut back = [0u8; 5];
        client.read_exact(&mut back).await.unwrap();
        assert_eq!(&back, b"hello");

        drop(splice);
        // The abort is a request to the runtime, not an instant close, so
        // give it a moment before asserting the socket is gone — the same
        // allowance `publish` makes when it rebinds.
        let mut freed = false;
        for _ in 0..100 {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            if tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, bound))
                .await
                .is_ok()
            {
                freed = true;
                break;
            }
        }
        assert!(
            freed,
            "the loopback port outlived the command that opened it"
        );
    }

    /// `--local-port` is a promise about one number, exactly as a published
    /// mapping is: if it is taken the command refuses and says so, rather
    /// than quietly handing back a different URL.
    #[tokio::test]
    async fn a_taken_local_port_is_refused_rather_than_moved() {
        let held = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let taken = held.local_addr().unwrap().port();
        let target = Target {
            name: "bot".into(),
            port: 3000,
        };
        let e = match listen_local(target_addr(), Some(taken), &target).await {
            Err(e) => format!("{e:#}"),
            Ok(_) => panic!("a port somebody else holds must not be handed out"),
        };
        assert!(e.contains(&format!("127.0.0.1:{taken}")), "{e}");
        assert!(e.contains("--local-port"), "{e}");
    }

    fn target_addr() -> SocketAddr {
        SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::LOCALHOST), 9)
    }
}
