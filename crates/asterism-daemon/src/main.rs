//! astd — the Asterism device daemon.
//!
//! The orbit is a pool of parts; an instance is a computer assembled from
//! them. This daemon is one device's contribution to that pool: it holds this
//! device's shard of the orbit registry, boots the guests whose cpu and ram it
//! supplies, and serves the `ast` CLI over a unix socket (one JSON request per
//! line, one JSON response per line). Guests are booted through the
//! [`Hypervisor`] boundary: nothing in this daemon names a hypervisor concept
//! outside [`backend`], and optional behaviour is gated on `Caps`.
//!
//! It also holds this device's presence in its orbit — see [`mesh`]. The
//! daemon, not the CLI, is what other devices talk to and what dials them.
//! That is what makes the instance namespace flat: `ast up dev` typed anywhere
//! arrives at the nearest daemon, which resolves `dev` across the orbit and,
//! if some other device holds that row, sends it the very same [`Request`]
//! frame over a mesh stream. The user never names a device, because in a pool
//! of parts there is nothing for them to name.
//!
//! # What this file is, and what it is not
//!
//! This file is the doors and the routing between them, and nothing else. It
//! knows that a request may have to be forwarded, claimed, or answered on the
//! connection that asked; it does not know what any command *does*. Each area
//! owns its own frames in its own module — [`instance`], [`snapshot`],
//! [`volume`], [`swap`], [`orbit`], [`ssh`], [`wake`] — and each offers the
//! same two things: a `claims` predicate and a `serve`. Routing is then a
//! short chain of "is this yours?", which is the shape that lets two branches
//! add two commands to two areas without touching the same lines. The one
//! rule the chain rests on is that each area's predicate and match agree;
//! each module tests its own.

use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Mutex;

use asterism_core::orbit::Orbit;
use asterism_core::protocol::{Request, Response};
use asterism_core::registry::Shard;
use asterism_core::{paths, VERSION};

mod backend;
mod egress;
mod instance;
mod mesh;
mod orbit;
mod persist;
mod secret;
mod snapshot;
mod ssh;
mod swap;
mod volume;
mod wake;

use mesh::{ClientIo, Mesh, Splice};

/// This device's own state: its shard of the orbit registry, and the name the
/// orbit knows it by.
///
/// The two travel together because almost everything needs both — a row is
/// written with the device that supplies its cpu, and that device is named by
/// the orbit, not by its hostname. Two daemons on one machine with different
/// orbit names are two distinct suppliers of parts, and the tests depend on
/// that being true.
#[derive(Clone)]
pub(crate) struct Node {
    pub shard: Arc<Mutex<Shard>>,
    pub orbit: Arc<Mutex<Orbit>>,
}

impl Node {
    /// What this device is called in its orbit.
    pub async fn device_name(&self) -> String {
        self.orbit.lock().await.self_name().to_owned()
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let home = paths::home_dir();
    std::fs::create_dir_all(&home).with_context(|| format!("creating {}", home.display()))?;

    // Before anything is served: a cpu-part swap this device was receiving
    // when it died left a staging directory, and this is the "next contact"
    // that clears it. It was never bootable and no shard row ever pointed at
    // it, so there is nothing to consult first.
    swap::sweep_staging();

    let node = Node {
        shard: Arc::new(Mutex::new(Shard::load(&paths::state_path())?)),
        orbit: Arc::new(Mutex::new(Orbit::load(&paths::orbit_path())?)),
    };

    let sock = paths::socket_path();
    // A leftover socket file from a dead daemon blocks bind; a live daemon
    // would still be accepting, so probe before unlinking.
    if sock.exists() {
        if UnixStream::connect(&sock).await.is_ok() {
            anyhow::bail!("another astd is already running on {}", sock.display());
        }
        std::fs::remove_file(&sock)?;
    }
    let listener =
        UnixListener::bind(&sock).with_context(|| format!("binding {}", sock.display()))?;

    // The pid file is how an `ast` newer than this daemon retires it: the
    // socket says something is listening, but only a pid can be acted on.
    let pidfile = paths::daemon_pid_path();
    std::fs::write(&pidfile, std::process::id().to_string())
        .with_context(|| format!("writing {}", pidfile.display()))?;

    eprintln!("astd {VERSION}: listening on {}", sock.display());

    // The mesh is presence, not plumbing the local commands need: a device
    // whose endpoint will not bind should still run its own instances, and
    // say clearly why the orbit is out of reach.
    let mesh = match Mesh::start(node.clone()).await {
        Ok(mesh) => {
            eprintln!(
                "astd: device {} on the mesh as {:?}",
                mesh.device_id().short(),
                mesh.self_name().await
            );
            Some(mesh)
        }
        Err(e) => {
            eprintln!("astd: the mesh is unavailable: {e:#}");
            None
        }
    };

    // Metadata lives in ASTERISM_HOME; values live behind the platform store
    // (the macOS login Keychain). There is intentionally no file fallback.
    if let Err(e) = secret::init() {
        eprintln!("astd: secrets are unavailable: {e:#}");
    }

    // The volume plane, before anything can be resurrected onto it: an
    // instance coming back up may need a lease taken and a bridge raised
    // before its guest has a disk to boot with.
    if let Err(e) = volume::init(node.clone(), mesh.clone()) {
        eprintln!("astd: block volumes are unavailable: {e:#}");
    }

    // The egress plane, for the same reason and in the same shape: a bound
    // guest's proxy is put up by the boot that builds its seed, and the
    // source half of a bound request arrives from a mesh stream.
    if let Err(e) = egress::init(node.clone(), mesh.clone()) {
        eprintln!("astd: secret egress is unavailable: {e:#}");
    }

    // Moving an instance's cpu part needs the mesh, and the target's half of
    // a move is reached from a mesh stream — so, like the volume plane, it
    // holds a process-wide handle rather than taking one as an argument.
    swap::init(mesh.clone());

    // What this device was running, it runs again — before the first
    // request is served, and then continuously (see `persist`).
    persist::resurrect(&node.shard).await;
    persist::supervise(node.shard.clone());

    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, _) = accepted?;
                let node = node.clone();
                let mesh = mesh.clone();
                tokio::spawn(async move {
                    if let Err(e) = serve(stream, node, mesh).await {
                        eprintln!("astd: connection error: {e:#}");
                    }
                });
            }
            _ = shutdown_signal() => {
                let _ = std::fs::remove_file(&sock);
                let _ = std::fs::remove_file(&pidfile);
                eprintln!("astd: shutting down");
                return Ok(());
            }
        }
    }
}

/// Ctrl-C, or the SIGTERM the CLI sends when it retires a stale daemon.
/// Both have to clean up the socket and pid file, or the replacement
/// daemon refuses to bind.
async fn shutdown_signal() {
    use tokio::signal::unix::{signal, SignalKind};
    let mut term = match signal(SignalKind::terminate()) {
        Ok(s) => s,
        Err(_) => {
            let _ = tokio::signal::ctrl_c().await;
            return;
        }
    };
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = term.recv() => {}
    }
}

/// One connection from the unix socket, for as long as it stays open.
///
/// Most requests are a question and an answer and go straight to
/// [`dispatch`]. The four below are not, and each of them is here for the
/// same reason: it needs something this connection has. Three report as they
/// go and so need somewhere to send progress; the fourth needs to leave a
/// listener standing that dies when this socket does.
async fn serve(stream: UnixStream, node: Node, mesh: Option<Arc<Mesh>>) -> Result<()> {
    let (read, mut write) = stream.into_split();
    let mut lines = BufReader::new(read).lines();

    // Anything this connection asked us to hold open on its behalf. Today
    // that is the loopback listener behind `ast ssh` on a guest whose cpu is
    // elsewhere: `ast` keeps this socket open for exactly as long as ssh is
    // running, so dropping these when the loop ends *is* the teardown.
    let mut splices: Vec<Splice> = Vec::new();

    while let Some(line) = lines.next_line().await? {
        if line.trim().is_empty() {
            continue;
        }
        let request = match serde_json::from_str::<Request>(&line) {
            Ok(req) => req,
            // A CLI newer than this daemon lands here, on a variant we have
            // never heard of. The wording matters: `ast` classifies it and
            // restarts us rather than showing the user a serde error.
            Err(e) => {
                send(&mut write, &Response::Error { message: format!("bad request: {e}") }).await?;
                continue;
            }
        };

        // Pairing is a conversation, not a question — a ticket to print, a
        // code to compare, a verdict to take — so it borrows the connection
        // for as many frames as it needs.
        if let Request::DeviceInvite { .. } | Request::DeviceAdd { .. } = request {
            let mut io = ClientIo { lines: &mut lines, write: &mut write };
            if let Err(e) = orbit::pair(request, mesh.as_ref(), &mut io).await {
                io.send(&Response::Error { message: format!("{e:#}") }).await?;
            }
            continue;
        }

        // A wake is a job rather than a question — who is going to send the
        // packet, that it went, and then up to a minute later whether the
        // machine turned up — so it reports as it goes, which needs the
        // connection the same way pairing does.
        if let Request::DeviceWake { name } = &request {
            let mut io = ClientIo { lines: &mut lines, write: &mut write };
            let woken = match mesh.as_ref() {
                Some(mesh) => mesh.wake(name, &mut io).await,
                None => Err(anyhow::anyhow!("{}", orbit::NO_MESH)),
            };
            if let Err(e) = woken {
                io.send(&Response::Error { message: format!("{e:#}") }).await?;
            }
            continue;
        }

        // A cpu-part swap is a job rather than a question — a preflight, a
        // fence, a disk crossing a network, two commits — so it reports as it
        // goes, on the connection that asked, exactly as a wake does.
        if let Request::SetCpu { name, device, down } = &request {
            let mut io = ClientIo { lines: &mut lines, write: &mut write };
            let moved = swap::run(name, device, *down, &node, mesh.as_ref(), &mut io).await;
            if let Err(e) = moved {
                io.send(&Response::Error { message: format!("{e:#}") }).await?;
            }
            continue;
        }

        // `ast ssh` needs something to outlive its own reply — a listener the
        // CLI is about to point ssh at — so it is answered here, where the
        // connection's lifetime is.
        if let Request::SshEndpoint { name } = &request {
            let (response, splice) = ssh::endpoint(name, &node, mesh.as_ref()).await;
            splices.extend(splice);
            send(&mut write, &response).await?;
            continue;
        }

        let response = dispatch(request, &node, mesh.as_ref()).await;
        send(&mut write, &response).await?;
    }
    Ok(())
}

async fn send(
    write: &mut tokio::net::unix::OwnedWriteHalf,
    response: &Response,
) -> Result<()> {
    let mut out = serde_json::to_vec(response)?;
    out.push(b'\n');
    write.write_all(&out).await?;
    Ok(())
}

/// Routes one request that came off the unix socket.
///
/// Three kinds arrive here, and this is the order they are asked about in.
/// Requests about the orbit itself are answered by [`orbit`] — before
/// anything else, because they are the ones that must never be resolved
/// against the instance namespace. Requests that claim a name have that claim
/// put to every device. Everything left is about one instance, so it is
/// resolved across the orbit and forwarded to whichever device holds that
/// row — which is where `--device` stops being necessary.
async fn dispatch(request: Request, node: &Node, mesh: Option<&Arc<Mesh>>) -> Response {
    if secret::is_orbit_request(&request) {
        return secret::serve(request, node, mesh).await;
    }
    if orbit::claims(&request) {
        return orbit::serve(request, node, mesh).await;
    }
    // A name is claimed before anything is written down, and a claim that
    // fails ends the request here: an instance that could not have the name
    // it asked for must not be created, and one that could not have the name
    // it is being renamed to must keep the one it has.
    if let Some(refusal) = instance::claim_name(&request, node, mesh).await {
        return refusal;
    }
    route(request, node, mesh).await
}

/// Answers a request about one instance from wherever that instance is.
///
/// The name is looked up in this device's shard first — the common case, and
/// the one that must not pay for the mesh — and then across the orbit. A hit
/// elsewhere is forwarded verbatim in a [`Request::Proxy`] envelope, so the
/// far daemon runs the identical frame its own CLI would have handed it.
async fn route(request: Request, node: &Node, mesh: Option<&Arc<Mesh>>) -> Response {
    let Some(name) = request.subject() else {
        return handle(request, node).await;
    };
    if node.shard.lock().await.holds(name) {
        return handle(request, node).await;
    }
    let Some(mesh) = mesh else {
        return handle(request, node).await;
    };
    match mesh.locate(name).await {
        Ok(Some(device)) => orbit::reply_or_error(mesh.proxy(&device, request).await),
        // Nowhere in the orbit answers to it, so the local shard's "no such
        // instance" is both true and the message the user should see.
        Ok(None) => handle(request, node).await,
        Err(e) => Response::Error { message: format!("{e:#}") },
    }
}

/// Runs a request against this device's shard of the orbit registry.
///
/// Reached from the unix socket and from a mesh stream alike — a forwarded
/// request is not a different kind of request, it just arrived by a different
/// door, and that is the whole reason no command needed a second
/// implementation to be answerable from anywhere in the orbit.
///
/// Nothing here consults the orbit. By the time a request gets this far its
/// name has already been resolved (or claimed) against every device, so this
/// is deliberately the shard-local end of the world: it is also what stops a
/// forwarded request from fanning out again on arrival, which is why
/// [`orbit`] is asked in [`dispatch`] and never here.
///
/// The body is a chain of one question — "is this yours?" — asked of each
/// area in turn, ending at [`instance`], which owns both the shard's own
/// commands and the refusal for a frame nobody claimed.
pub(crate) async fn handle(req: Request, node: &Node) -> Response {
    if secret::is_source_request(&req) {
        return secret::serve_source(req).await;
    }
    // Volumes are this device's own part of the pool, not a row in its shard,
    // and they are answered before the shard is touched. That is not only
    // tidiness: `up` holds the shard while it boots, and an instance whose
    // volume is on the very device running it would otherwise ask itself for
    // a lease and wait forever on its own lock.
    if volume::is_plane_request(&req) {
        return volume::serve(req).await;
    }

    let cpu_device = node.device_name().await;
    let mut reg = node.shard.lock().await;
    instance::reconcile(&mut reg);

    // Two states put an instance out of reach whatever is being asked of it —
    // a name that is not unique, and bytes in flight to another device — so
    // they are checked once, here, ahead of every area.
    if let Some(refusal) = instance::refusal(&req, &reg) {
        return refusal;
    }

    if swap::is_step(&req) {
        return swap::serve(req, &mut reg, &cpu_device);
    }
    if snapshot::claims(&req) {
        return snapshot::serve(req, &reg);
    }
    instance::serve(req, &mut reg, &cpu_device).await
}
