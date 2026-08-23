//! The secrets egress data plane: the proxy a bound guest talks to, and the
//! upstream call the source device makes on its behalf.
//!
//! # What is Asterism's, and what is not
//!
//! Almost none of this file is transport. It is somebody else's maintained
//! code doing the work, and this module is the policy holding it together:
//!
//! | job                          | whose code            | licence      |
//! |------------------------------|-----------------------|--------------|
//! | HTTP/1.1 server, CONNECT     | `hyper` + `hyper-util`| MIT          |
//! | request/response types       | `http`                | MIT          |
//! | body framing and its caps    | `http-body-util`      | MIT          |
//! | TLS, both directions         | `rustls`+`tokio-rustls`| MIT/Apache/ISC |
//! | upstream client              | `reqwest`             | MIT/Apache-2 |
//! | X.509 for the per-instance CA| `rcgen`               | MIT/Apache-2 |
//! | the value at rest            | macOS Keychain        | the OS       |
//!
//! Every one of those except `rcgen` was already being compiled in this
//! workspace behind `iroh`, so the whole transport half of this feature added
//! three small crates to the build: `rcgen`, and the `pem` and `yasna` it
//! encodes DER with. `reqwest` is taken with `rustls-no-provider` rather than
//! `rustls` on purpose — the latter would pull `aws-lc-rs` and a C toolchain
//! alongside the `ring` this tree already builds — and the provider it uses is
//! the one [`init`] installs.
//!
//! The operational cost is one idle `TcpListener` on loopback per *bound*
//! instance, one keypair generated once per instance, and one leaf certificate
//! per bound authority held in memory for the life of the proxy.
//!
//! What is left — and it is the whole of what Asterism owns here — is: which
//! authority a secret may be used against, which opaque handle stands in for
//! it, which device resolves it, and the refusals around all three. That
//! lives in [`asterism_core::rewrite`] and [`crate::secret`].
//!
//! # The path a request takes
//!
//! ```text
//!   guest                consumer daemon              source daemon
//!   -----                ---------------              -------------
//!   CONNECT api.x:443 -> bound? mint a leaf,
//!                        terminate TLS
//!   POST /v1/... ------> decide(): allowlist +
//!   x-api-key: <handle>  exact handle match
//!                        strip the handle ---------->  resolve the value
//!                                                      fill the header
//!                                                      TLS to api.x --> …
//!                        <---------------------------  the answer
//!   <-- the answer
//! ```
//!
//! The handle never leaves the consumer; the value never leaves the source.
//! What crosses between them is a request with an empty header in it.
//!
//! # Why this refuses more than it carries
//!
//! A proxy on a host is a way for a guest to borrow the host's position on
//! the network. Everything here that looks like paranoia is about giving back
//! exactly the position the guest already had through its own NAT and no
//! more: loopback bind only, public-unicast destinations only, no redirects,
//! DNS pinned between the check and the connection, and a backend that cannot
//! offer a guest-only door gets refused rather than bound to a wildcard.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex as StdMutex, OnceLock};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use bytes::Bytes;
use http::{Method, StatusCode};
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use zeroize::Zeroizing;

use asterism_core::hv::GuestEgress;
use asterism_core::instance::Instance;
use asterism_core::protocol::{EgressRequest, EgressResponse, Response};
use asterism_core::rewrite::{
    self, Allowlist, Decision, Refusal, MAX_BODY_BYTES, MAX_HEADERS, MAX_RESPONSE_BYTES,
};
use asterism_core::secret::{Binding, Handle};
use asterism_core::{paths, seed};

use crate::mesh::Mesh;
use crate::{backend, Node};

/// How long a guest's whole bound request may take, upstream included.
///
/// Generous, because the traffic is model APIs and a long completion is not a
/// hang. Bounded, because an unbounded wait is a way to pin one of the
/// daemon's tasks per connection for as long as anyone likes.
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(120);

/// How long a guest may take to get from a CONNECT to a request. Short: the
/// TLS handshake and one request head is all that happens in here.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

/// A pinned future, so [`Source`] can be a trait object without pulling in a
/// proc macro for one boundary.
type Fut<'a, T> = std::pin::Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>;

/// The device that holds a bound secret, as the guest's proxy sees it.
///
/// Named as a boundary rather than called directly because it is the seam
/// where "somewhere in the orbit" starts. On one side is a proxy that knows a
/// handle and an authority; on the other is a device with a store, which may
/// be this one or may be a laptop asleep in another room. The proxy never
/// learns which, and never sees a value either way.
pub(crate) trait Source: Send + Sync {
    /// The version- and revision-pinned handle to redeem, selected now.
    fn handle_for<'a>(&'a self, binding: &'a Binding) -> Fut<'a, Result<Handle>>;
    /// Make the call, from wherever the value is.
    fn egress<'a>(
        &'a self,
        binding: &'a Binding,
        handle: Option<Handle>,
        request: EgressRequest,
    ) -> Fut<'a, Result<EgressResponse>>;
}

/// The real one: the orbit, reached through [`crate::secret`].
struct OrbitSource {
    plane: Arc<EgressPlane>,
    instance: String,
}

impl Source for OrbitSource {
    fn handle_for<'a>(&'a self, binding: &'a Binding) -> Fut<'a, Result<Handle>> {
        Box::pin(async move {
            let refreshed =
                crate::secret::refresh(binding, &self.plane.node, self.plane.mesh.as_ref()).await?;
            if let Some(was) = refreshed.rotated_from {
                // Worth one line: a user who rotated a secret wants to know
                // the guest picked it up without being rebooted. Neither the
                // value nor the handle is in it.
                eprintln!(
                    "astd: {} now serves {:?} at version {} (bound at v{was})",
                    self.instance, binding.secret, refreshed.handle.version
                );
            }
            Ok(refreshed.handle)
        })
    }

    fn egress<'a>(
        &'a self,
        binding: &'a Binding,
        handle: Option<Handle>,
        request: EgressRequest,
    ) -> Fut<'a, Result<EgressResponse>> {
        Box::pin(async move {
            crate::secret::egress_via_source(
                binding,
                handle,
                request,
                &self.plane.node,
                self.plane.mesh.as_ref(),
            )
            .await
        })
    }
}

static PLANE: OnceLock<Arc<EgressPlane>> = OnceLock::new();

/// The process-wide egress plane: what is running, and what it needs to reach
/// the rest of the orbit.
struct EgressPlane {
    node: Node,
    mesh: Option<Arc<Mesh>>,
    running: StdMutex<BTreeMap<String, Proxy>>,
}

/// How this instance's proxy is reached from the guest.
enum Listen {
    /// Host TCP loopback, advertised to the guest as `gateway:port`.
    Loopback { port: u16 },
    /// Unix socket the helper splices vsock onto. The guest sees only its
    /// own loopback proxy; this host binds no TCP port at all.
    Unix { path: PathBuf },
}

/// One instance's proxy, while it is up.
struct Proxy {
    listen: Listen,
    ca_pem: String,
    /// Set when this proxy is taken down, and read by every request still in
    /// flight. Aborting the accept loop stops new connections; connections
    /// already open are on tasks of their own, and this is what stops one of
    /// them from being given a value a moment after the binding it belonged
    /// to was revoked.
    revoked: Arc<AtomicBool>,
    /// The accept loop. Dropping the plane's entry aborts it, which is what
    /// makes revoking a binding take effect without waiting for a reboot.
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Proxy {
    fn drop(&mut self) {
        // Order matters only in that both happen: the flag makes a request
        // already inside the policy check fail, and the abort stops any
        // further connection being accepted at all.
        self.revoked.store(true, Ordering::SeqCst);
        self.task.abort();
        // The helper splices onto this path. Removing it is what makes a
        // detach or astd-down fail closed for the *next* vsock connect,
        // rather than hanging on a socket file nothing owns.
        if let Listen::Unix { path } = &self.listen {
            let _ = std::fs::remove_file(path);
        }
    }
}

pub(crate) fn init(node: Node, mesh: Option<Arc<Mesh>>) -> Result<()> {
    // rustls needs one process-wide crypto provider chosen before any config
    // is built. `ring` is the one already in this tree behind iroh.
    let _ = rustls::crypto::ring::default_provider().install_default();
    PLANE
        .set(Arc::new(EgressPlane {
            node,
            mesh,
            running: StdMutex::new(BTreeMap::new()),
        }))
        .map_err(|_| anyhow!("egress plane initialized twice"))
}

fn plane() -> Result<&'static Arc<EgressPlane>> {
    PLANE
        .get()
        .ok_or_else(|| anyhow!("the egress plane is unavailable"))
}

/// The orbit handles this plane holds.
///
/// Attaching a secret has to ask the rest of the orbit which devices hold it,
/// and it has to do that from inside the shard's own lock — exactly as taking
/// a volume lease does. Rather than thread a `Node` and a `Mesh` down through
/// the instance commands for one arm, the plane that already holds them lends
/// them out.
pub(crate) fn orbit() -> Result<(Node, Option<Arc<Mesh>>)> {
    let plane = plane()?;
    Ok((plane.node.clone(), plane.mesh.clone()))
}

// ---- the backend seam ------------------------------------------------------

/// Refuse, at attach time, a binding this instance could never be served.
///
/// Three refusals, and each of them is a thing that would otherwise be
/// discovered as a guest that boots holding a handle nothing honours:
///
/// * A backend with no guest-only door. There is no safe listener to put up,
///   and the alternative — binding a wildcard address and calling the result
///   guest-only — would put an unauthenticated proxy for somebody's API keys
///   on their LAN. See [`GuestEgress`].
///
/// There is deliberately no check that this is the device supplying the
/// instance's cpu part. Reaching here means this device holds the row, which
/// is the same fact — and writing it down a second time would mean comparing
/// an orbit name against a hostname, which are not the same string.
pub(crate) fn check_can_bind(inst: &Instance) -> Result<()> {
    let hv = backend::for_instance(inst)?;
    let offered = hv.caps().guest_egress;
    let usable = hv.caps_for(inst).guest_egress;
    if usable.is_some() {
        return Ok(());
    }
    if offered.is_some() {
        // The backend has a door; this image cannot use it. Refuse even
        // when the hypervisor is not installed on this device — the image
        // will not grow an agent later, and binding now would mutate a
        // record nothing can serve.
        bail!(
            "the {} backend cannot bind a secret on {:?}: this image is a \
             direct-kernel/OCI root filesystem, so it has no guest agent to \
             carry the GuestLoopback route — bind the secret on a cloud image, \
             or run this instance on a backend whose egress does not need one",
            hv.id(),
            inst.name
        );
    }
    // Only a backend we could actually ask is allowed to refuse a
    // backend-wide missing door: on a device where the hypervisor is not
    // installed yet, `caps()` knows nothing, and that must not become a
    // refusal to record a binding the instance will be able to use once it is.
    if hv.probe().is_ok() {
        bail!(
            "the {} backend has no guest-only door into this device, so there is \
             no listener that only {:?} can reach — a bound secret needs one of \
             the routes in GuestEgress, and binding a wildcard address instead \
             would publish a proxy for this secret on your LAN",
            hv.id(),
            inst.name
        );
    }
    Ok(())
}

/// The typed route this instance can actually use, if any.
fn route(inst: &Instance) -> Result<GuestEgress> {
    let hv = backend::for_instance(inst)?;
    hv.caps_for(inst).guest_egress.ok_or_else(|| {
        anyhow!(
            "the {} backend has no guest-only path to this device for {:?}",
            hv.id(),
            inst.name
        )
    })
}

/// The URL a seed writes for a given route.
///
/// For a loopback gateway the host's bound port is part of the URL. For a
/// guest-loopback route the port is inside the guest and does not come
/// from a host bind at all.
fn proxy_url(route: GuestEgress, host_port: Option<u16>) -> Result<String> {
    match route {
        GuestEgress::LoopbackGateway { gateway } => {
            let port = host_port.ok_or_else(|| {
                anyhow!("a loopback-gateway route needs a host TCP port to advertise")
            })?;
            Ok(format!("http://{gateway}:{port}"))
        }
        GuestEgress::GuestLoopback { bind, port } => Ok(format!("http://{bind}:{port}")),
    }
}

// ---- lifecycle -------------------------------------------------------------

/// Bring up (or leave up) this instance's proxy, and say what its seed should
/// tell the guest.
///
/// Called from the boot path, before the seed is built, because the port the
/// listener settles on is one of the things the seed has to say. An instance
/// with no bindings gets an empty [`seed::Egress`] and no listener at all.
pub(crate) fn seed_config(inst: &Instance) -> Result<seed::Egress> {
    if inst.secrets.is_empty() {
        stop(&inst.name);
        return Ok(seed::Egress::default());
    }
    check_can_bind(inst)?;
    let route = route(inst)?;
    let (host_port, ca_pem) = ensure_running(inst, route)?;
    Ok(seed::Egress {
        proxy: proxy_url(route, host_port)?,
        ca_pem,
        authorities: inst
            .secrets
            .iter()
            .map(|binding| binding.authority.clone())
            .collect(),
        handles: inst
            .secrets
            .iter()
            .map(|binding| {
                (
                    binding.env.clone(),
                    binding.guest_handle.as_str().to_owned(),
                )
            })
            .collect(),
    })
}

/// Take an instance's proxy down. Idempotent, and the way a revoked handle
/// stops being honoured immediately rather than at the next boot.
pub(crate) fn stop(name: &str) {
    if let Ok(plane) = plane() {
        let mut running = plane.running.lock().expect("egress plane poisoned");
        running.remove(name);
    }
}

/// Restart an instance's proxy against its current bindings.
///
/// Attach and detach both land here. Restarting rather than mutating is the
/// point: a proxy holds the binding list it was started with, so a revoked
/// handle cannot be honoured by a connection that is already open.
pub(crate) fn refresh_bindings(inst: &Instance) {
    stop(&inst.name);
    if inst.status != asterism_core::instance::Status::Running {
        return;
    }
    // Back up even when nothing is bound any more. A running guest was told
    // to send its traffic here, and it goes on doing that until its next boot
    // reissues the seed — so taking the listener away because the last
    // binding went would break every unbound connection that guest makes, for
    // as long as it stays up. What comes back honours nothing.
    match route(inst) {
        Ok(route) => {
            if let Err(e) = ensure_running(inst, route) {
                eprintln!(
                    "astd: {}'s egress proxy did not come back: {e:#}",
                    inst.name
                );
            }
        }
        Err(e) => eprintln!(
            "astd: {}'s egress proxy did not come back: {e:#}",
            inst.name
        ),
    }
}

/// Bring the listener up for this route. Returns the host TCP port only
/// for [`GuestEgress::LoopbackGateway`]; a guest-loopback route has no
/// host TCP port at all.
fn ensure_running(inst: &Instance, route: GuestEgress) -> Result<(Option<u16>, String)> {
    let plane = plane()?;
    let mut running = plane.running.lock().expect("egress plane poisoned");
    if let Some(proxy) = running.get(&inst.name) {
        if !proxy.task.is_finished() {
            let port = match proxy.listen {
                Listen::Loopback { port } => Some(port),
                Listen::Unix { .. } => None,
            };
            return Ok((port, proxy.ca_pem.clone()));
        }
        running.remove(&inst.name);
    }

    let authority = Authority::load_or_create(&egress_dir(&inst.name), &inst.name)?;
    let ca_pem = authority.ca_pem.clone();

    let revoked = Arc::new(AtomicBool::new(false));
    let ctx = Arc::new(ProxyCtx {
        instance: inst.name.clone(),
        bindings: inst.secrets.clone(),
        authority,
        source: Arc::new(OrbitSource {
            plane: plane.clone(),
            instance: inst.name.clone(),
        }),
        revoked: revoked.clone(),
    });

    let (listen, task) = match route {
        GuestEgress::LoopbackGateway { .. } => {
            // Loopback only, and that is the whole security argument for
            // this listener: QEMU's user-net proxies a guest's connection
            // to `10.0.2.2:p` onto this device's `127.0.0.1:p`, so binding
            // loopback is reachable from the guest and from nothing on the
            // wire. The same door `ast create -p` and `ast ssh` already use.
            let preferred = stable_port(&inst.name);
            let (listener, port) = bind_loopback(preferred)?;
            if preferred != Some(port) {
                let _ = std::fs::write(port_path(&inst.name), port.to_string());
            }
            let task = tokio::runtime::Handle::current().spawn(accept_loop(listener, ctx));
            (Listen::Loopback { port }, task)
        }
        GuestEgress::GuestLoopback { .. } => {
            let path = vsock_path(&inst.name);
            let listener = bind_unix(&path)?;
            let task = tokio::runtime::Handle::current().spawn(accept_unix(listener, ctx));
            (Listen::Unix { path }, task)
        }
    };
    let host_port = match &listen {
        Listen::Loopback { port } => Some(*port),
        Listen::Unix { .. } => None,
    };
    running.insert(
        inst.name.clone(),
        Proxy {
            listen,
            ca_pem: ca_pem.clone(),
            task,
            revoked,
        },
    );
    Ok((host_port, ca_pem))
}

fn egress_dir(instance: &str) -> PathBuf {
    paths::instance_dir(instance).join("egress")
}

fn port_path(instance: &str) -> PathBuf {
    egress_dir(instance).join("port")
}

/// Unix socket the vz helper splices authenticated vsock streams onto.
///
/// Not a TCP port. The helper connects; astd binds. Mode 0600, next to the
/// CA, so a process that cannot read the instance directory cannot present
/// itself as this guest's egress plane.
pub(crate) fn vsock_path(instance: &str) -> PathBuf {
    egress_dir(instance).join("vsock.sock")
}

fn stable_port(instance: &str) -> Option<u16> {
    std::fs::read_to_string(port_path(instance))
        .ok()?
        .trim()
        .parse()
        .ok()
}

/// Bind the port this instance used last time, or any free one.
///
/// Falling back rather than failing: something else on this machine may have
/// taken the port while the guest was down, and a proxy on a new port with a
/// reissued seed is a working instance, where a refusal would be a machine
/// that will not boot.
fn bind_loopback(preferred: Option<u16>) -> Result<(TcpListener, u16)> {
    let std_listener = bind_loopback_with(preferred, std::net::TcpListener::bind)
        .context("binding the guest egress proxy on loopback")?;
    std_listener.set_nonblocking(true)?;
    let port = std_listener.local_addr()?.port();
    Ok((TcpListener::from_std(std_listener)?, port))
}

/// Try the remembered loopback address before asking the OS for a free one.
///
/// The binder is a seam for proving the choice without dropping a real port
/// reservation and racing the machine's parallel ephemeral-port allocator.
fn bind_loopback_with<T>(
    preferred: Option<u16>,
    mut bind: impl FnMut(SocketAddr) -> std::io::Result<T>,
) -> std::io::Result<T> {
    let loopback = |port: u16| SocketAddr::from(([127, 0, 0, 1], port));
    preferred
        .and_then(|port| bind(loopback(port)).ok())
        .map_or_else(|| bind(loopback(0)), Ok)
}

fn bind_unix(path: &Path) -> Result<tokio::net::UnixListener> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    if path.exists() {
        // A leftover file from a previous astd. A *live* listener would
        // still be in the plane's map; we only get here after that entry
        // was dropped. Steal the path rather than refuse a boot.
        let _ = std::fs::remove_file(path);
    }
    let listener = std::os::unix::net::UnixListener::bind(path)
        .with_context(|| format!("binding the guest egress plane at {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    listener.set_nonblocking(true)?;
    Ok(tokio::net::UnixListener::from_std(listener)?)
}

/// What one instance's proxy knows.
struct ProxyCtx {
    instance: String,
    /// The bindings as they were when this proxy started. Held by value on
    /// purpose: revoking one restarts the proxy, so a connection cannot
    /// outlive the policy it was accepted under.
    bindings: Vec<Binding>,
    authority: Authority,
    /// Where the values are. In production this is the orbit; in a test it is
    /// a map, which is the whole reason it is a trait.
    source: Arc<dyn Source>,
    /// Shared with the [`Proxy`] entry that owns this context. See its field.
    revoked: Arc<AtomicBool>,
}

async fn accept_loop(listener: TcpListener, ctx: Arc<ProxyCtx>) {
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            continue;
        };
        tokio::spawn(serve_connect(stream, ctx.clone()));
    }
}

async fn accept_unix(listener: tokio::net::UnixListener, ctx: Arc<ProxyCtx>) {
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            continue;
        };
        tokio::spawn(serve_connect(stream, ctx.clone()));
    }
}

async fn serve_connect<S>(stream: S, ctx: Arc<ProxyCtx>)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    // The outer connection speaks plain HTTP and carries exactly one
    // useful verb, CONNECT. hyper owns the framing, the header caps
    // and every smuggling refusal that goes with them.
    let served = http1::Builder::new()
        .max_headers(MAX_HEADERS)
        .serve_connection(
            TokioIo::new(stream),
            service_fn(move |req| connect_service(req, ctx.clone())),
        )
        .with_upgrades()
        .await;
    if let Err(e) = served {
        // No address and no header: a proxy that logs both has
        // written a map of who talks to whom next to the credentials.
        if !e.is_incomplete_message() {
            eprintln!("astd: an egress connection ended early");
        }
    }
}

// ---- the guest's side ------------------------------------------------------

fn refuse(refusal: &Refusal) -> hyper::Response<Full<Bytes>> {
    let body = EgressResponse::refused(refusal.status(), &refusal.to_string());
    build(&body)
}

fn build(response: &EgressResponse) -> hyper::Response<Full<Bytes>> {
    let mut out = hyper::Response::builder()
        .status(StatusCode::from_u16(response.status).unwrap_or(StatusCode::BAD_GATEWAY));
    if let Some(headers) = out.headers_mut() {
        *headers = response.header_map();
    }
    out.body(Full::new(Bytes::from(response.body.clone())))
        .expect("a status and a buffered body are always a valid response")
}

/// The outer service: one CONNECT, and everything else refused.
///
/// Only `HTTPS_PROXY` is set in the guest, so plain-HTTP proxying never
/// arrives here in normal use — and refusing it in one line is better than
/// carrying a second, unintercepted path that nobody tests.
async fn connect_service(
    req: hyper::Request<Incoming>,
    ctx: Arc<ProxyCtx>,
) -> Result<hyper::Response<Full<Bytes>>, std::convert::Infallible> {
    if req.method() != Method::CONNECT {
        return Ok(refuse(&Refusal::Malformed(
            "this proxy carries CONNECT and nothing else; unbound traffic goes out of the \
             guest's own network",
        )));
    }
    let Some(authority) = req.uri().authority().map(|a| a.to_string()) else {
        return Ok(refuse(&Refusal::Malformed(
            "the CONNECT line names no authority",
        )));
    };

    // Bound: terminate and rewrite. Unbound: a plain tunnel, and only to
    // somewhere the guest could already have reached itself.
    let bound = Allowlist(&ctx.bindings).find(&authority).cloned();
    let pinned = match &bound {
        // A bound authority is dialled by the *source* device, which resolves
        // it and checks it there. Nothing is resolved here.
        Some(_) => None,
        None => match vet(&authority).await {
            Ok(addrs) => Some(addrs),
            Err(refusal) => return Ok(refuse(&refusal)),
        },
    };

    let ctx2 = ctx.clone();
    tokio::spawn(async move {
        let Ok(upgraded) = hyper::upgrade::on(req).await else {
            return;
        };
        let io = TokioIo::new(upgraded);
        match (bound, pinned) {
            (Some(binding), _) => terminate(io, authority, binding, ctx2).await,
            (None, Some(addrs)) => tunnel(io, addrs).await,
            (None, None) => {}
        }
    });
    // hyper turns a 2xx on a CONNECT into the upgrade the guest is waiting for.
    Ok(hyper::Response::new(Full::new(Bytes::new())))
}

/// A guest reaching a host it has no binding for, carried blind.
///
/// No interception, no certificate, nothing read: two sockets and a copy. It
/// exists because setting `HTTPS_PROXY` in a guest routes *everything*
/// through here, and a guest whose package manager stopped working the moment
/// a secret was attached would be a worse machine than one without secrets.
async fn tunnel<I>(mut guest: I, addrs: Vec<SocketAddr>)
where
    I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    for addr in addrs {
        let Ok(Ok(mut upstream)) =
            tokio::time::timeout(HANDSHAKE_TIMEOUT, TcpStream::connect(addr)).await
        else {
            continue;
        };
        let _ = tokio::io::copy_bidirectional(&mut guest, &mut upstream).await;
        return;
    }
}

/// A guest reaching a bound host: terminate its TLS and read one request.
async fn terminate<I>(guest: I, authority: String, binding: Binding, ctx: Arc<ProxyCtx>)
where
    I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let acceptor = match ctx.authority.acceptor(&binding.authority) {
        Ok(acceptor) => acceptor,
        Err(e) => {
            eprintln!("astd: {} has no leaf certificate: {e:#}", ctx.instance);
            return;
        }
    };
    let Ok(Ok(tls)) = tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(guest)).await else {
        // A guest that does not trust the CA lands here. It sees a handshake
        // failure, which is the honest thing for it to see.
        return;
    };
    let served = http1::Builder::new()
        .max_headers(MAX_HEADERS)
        .serve_connection(
            TokioIo::new(tls),
            service_fn(move |req| {
                let (authority, binding, ctx) = (authority.clone(), binding.clone(), ctx.clone());
                async move {
                    Ok::<_, std::convert::Infallible>(
                        bound_service(req, authority, binding, ctx).await,
                    )
                }
            }),
        )
        .await;
    if let Err(e) = served {
        if !e.is_incomplete_message() {
            eprintln!("astd: a bound egress request ended early");
        }
    }
}

/// One request inside a terminated tunnel: decide, strip, send, answer.
async fn bound_service(
    req: hyper::Request<Incoming>,
    authority: String,
    binding: Binding,
    ctx: Arc<ProxyCtx>,
) -> hyper::Response<Full<Bytes>> {
    match carry(req, &authority, &binding, &ctx).await {
        Ok(response) => build(&response),
        Err(refusal) => refuse(&refusal),
    }
}

async fn carry(
    req: hyper::Request<Incoming>,
    authority: &str,
    binding: &Binding,
    ctx: &ProxyCtx,
) -> Result<EgressResponse, Refusal> {
    let (parts, body) = req.into_parts();
    // Checked here rather than only at accept: this connection may have been
    // open when `ast detach --secret` ran, and a request that is inside the
    // policy check at that moment must not come out the other side with a
    // value in it.
    if ctx.revoked.load(Ordering::SeqCst) {
        return Err(Refusal::NotBound);
    }
    // Asterism's own rule, and the only part of this path that is.
    let decision = rewrite::decide(binding, authority, &parts.uri, &parts.headers)?;

    // The cap is `http_body_util`'s, not ours: a guest cannot make this
    // daemon hold more than one bounded body per connection.
    let body = Limited::new(body, MAX_BODY_BYTES)
        .collect()
        .await
        .map_err(|_| Refusal::TooLarge("body"))?
        .to_bytes();

    let mut headers = parts.headers.clone();
    let handle = match decision {
        Decision::Substitute => {
            rewrite::strip(binding, &mut headers)?;
            Some(
                ctx.source
                    .handle_for(binding)
                    .await
                    .map_err(|e| Refusal::Upstream(format!("{e:#}")))?,
            )
        }
        // A request to a bound host that carries no credential still goes out
        // through the source device. That is not laziness: an API that sees
        // one instance's calls arrive from two different addresses depending
        // on whether a key was attached is an API that will eventually
        // decide one of them is fraud.
        Decision::PassThrough => None,
    };

    let request = EgressRequest {
        authority: authority.to_owned(),
        tls: true,
        method: parts.method.as_str().to_owned(),
        target: parts
            .uri
            .path_and_query()
            .map(|pq| pq.as_str().to_owned())
            .unwrap_or_else(|| "/".into()),
        headers: EgressRequest::flatten(&headers),
        placement: binding.placement.clone(),
        body: body.to_vec(),
    };

    ctx.source
        .egress(binding, handle, request)
        .await
        .map_err(|e| Refusal::Upstream(format!("{e:#}")))
}

/// Resolve an authority and refuse it if it is anywhere the guest could not
/// already reach on its own.
///
/// Returns *every* address that passed, and the connection is then made to
/// one of those rather than to a second lookup — which is the window a DNS
/// rebind lands in. All of them, not the first: a dual-stack name whose v6
/// address is unreachable is the ordinary case on a laptop, and pinning one
/// answer would turn "the first address in the list" into "whether this works
/// at all".
async fn vet(authority: &str) -> Result<Vec<SocketAddr>, Refusal> {
    let target = match authority.rsplit_once(':') {
        Some((_, port)) if port.parse::<u16>().is_ok() => authority.to_owned(),
        _ => format!("{authority}:443"),
    };
    let resolved = tokio::net::lookup_host(&target)
        .await
        .map_err(|_| Refusal::Upstream("that name does not resolve".into()))?;
    let mut vetted = Vec::new();
    for addr in resolved {
        // Every answer, not just the one that will be used: a name that
        // resolves to one public address and one private one is the classic
        // way to smuggle a request onto the host's network, and it must be
        // refused whichever of the two a connection would have picked.
        #[cfg(test)]
        let checked = match tests::allow_loopback() {
            true => Ok(()),
            false => rewrite::is_public(addr.ip()),
        };
        #[cfg(not(test))]
        let checked = rewrite::is_public(addr.ip());
        checked?;
        vetted.push(addr);
    }
    match vetted.is_empty() {
        true => Err(Refusal::Upstream("that name resolves to nothing".into())),
        false => Ok(vetted),
    }
}

// ---- the source device's side ----------------------------------------------

/// Make one outbound request, on the device whose store holds the value.
///
/// This is the whole of the plaintext's life: it is read out of the platform
/// store, put in a header, sent, and dropped. It is never written to disk,
/// never returned to the caller, and never printed — `rewrite::fill` marks the
/// header sensitive, so even a `{:?}` of the map says `Sensitive`.
pub(crate) async fn serve_source(handle: Option<Handle>, request: EgressRequest) -> Response {
    match egress(handle, request).await {
        Ok(response) => Response::Egress {
            response: Box::new(response),
        },
        Err(refusal) => Response::Egress {
            response: Box::new(EgressResponse::refused(
                refusal.status(),
                &refusal.to_string(),
            )),
        },
    }
}

async fn egress(handle: Option<Handle>, request: EgressRequest) -> Result<EgressResponse, Refusal> {
    egress_with(handle, request, crate::secret::resolve).await
}

/// The same, with the store it reads from named.
///
/// A parameter rather than a call, because "where the bytes come from" is the
/// one thing about this function that is a property of the *device* rather
/// than of the request — and because it lets the test below prove the whole
/// path without a Keychain in it.
async fn egress_with<R>(
    handle: Option<Handle>,
    request: EgressRequest,
    resolve: R,
) -> Result<EgressResponse, Refusal>
where
    R: FnOnce(&Handle) -> Result<asterism_core::protocol::SecretValue>,
{
    let authority = request.authority.clone();
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) => (
            host.to_owned(),
            port.parse::<u16>()
                .map_err(|_| Refusal::Malformed("the bound authority has no port"))?,
        ),
        None => (authority.clone(), 443),
    };
    let addrs = vet(&format!("{host}:{port}")).await?;

    let mut headers = request.header_map()?;
    // The value's whole life, and it is this long. `Zeroizing` wipes the
    // buffer when this scope ends; the copy that went into the header map is
    // dropped with the request a few lines later.
    if let Some(handle) = handle {
        let material = resolve(&handle).map_err(|e| Refusal::Upstream(format!("{e:#}")))?;
        let value = Zeroizing::new(
            String::from_utf8(material.into_bytes())
                .map_err(|_| Refusal::Malformed("the bound secret is not text"))?,
        );
        rewrite::fill(
            &Binding {
                // Only the placement is read by `fill`; the rest of a binding
                // is the consumer's business and is not on this frame.
                placement: request.placement.clone(),
                ..placeholder()
            },
            &mut headers,
            &value,
        )?;
    }

    let scheme = if request.tls { "https" } else { "http" };
    let url = format!("{scheme}://{host}:{port}{}", request.target);
    let method = Method::from_bytes(request.method.as_bytes())
        .map_err(|_| Refusal::Malformed("that is not an HTTP method"))?;

    let client = client_builder()
        // The addresses this device vetted, and no second lookup — a name
        // that answered publicly once and privately the next time would
        // otherwise reach the host's own network.
        .resolve_to_addrs(&host, &addrs)
        // A redirect is the shortest path from "this key goes to api.x" to
        // "this key went to somewhere api.x named". The guest is handed the
        // 30x and can decide for itself; this connection does not follow it.
        .redirect(reqwest::redirect::Policy::none())
        // The daemon has its own proxy env in some deployments, and it must
        // not send a guest's request through it.
        .no_proxy()
        .timeout(UPSTREAM_TIMEOUT)
        .build()
        .map_err(|e| Refusal::Upstream(format!("{e}")))?;

    let mut response = client
        .request(method, &url)
        .headers(headers)
        .body(request.body)
        .send()
        .await
        .map_err(|e| Refusal::Upstream(upstream_reason(&e)))?;

    let status = response.status().as_u16();
    let headers = EgressRequest::flatten(response.headers());
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|e| Refusal::Upstream(upstream_reason(&e)))?
    {
        if body.len() + chunk.len() > MAX_RESPONSE_BYTES {
            return Err(Refusal::TooLarge("body"));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(EgressResponse {
        status,
        headers,
        body,
    })
}

/// The client every upstream call is made with.
///
/// A function rather than an inline builder so that the one thing a test needs
/// to change — which roots are trusted, so a fake upstream on loopback can be
/// reached — is a `cfg(test)` branch in one place, and does not exist at all
/// in a released binary.
fn client_builder() -> reqwest::ClientBuilder {
    let builder = reqwest::Client::builder();
    #[cfg(test)]
    let builder = match tests::extra_root() {
        Some(pem) => builder.add_root_certificate(
            reqwest::Certificate::from_pem(pem.as_bytes()).expect("a test root"),
        ),
        None => builder,
    };
    builder
}

/// What went wrong upstream, without the url.
///
/// `reqwest`'s `Display` includes the url it was dialling, and that url is a
/// guest's request path — which can carry an identifier the guest would
/// rather this device did not put in a message it hands back. The kind is
/// enough to act on.
fn upstream_reason(e: &reqwest::Error) -> String {
    if e.is_timeout() {
        return "it did not answer in time".into();
    }
    if e.is_connect() {
        return "the connection was refused".into();
    }
    if e.is_body() || e.is_decode() {
        return "its answer could not be read".into();
    }
    "the request could not be made".into()
}

/// A binding with nothing in it but a placement, for [`rewrite::fill`].
///
/// The source device is deliberately not told which instance, which handle or
/// which authority the consumer authenticated: it is told where to put the
/// value it holds, and that is all it needs.
fn placeholder() -> Binding {
    Binding {
        id: String::new(),
        secret_id: asterism_core::secret::SecretId::from_name("placeholder")
            .expect("a constant name"),
        secret: String::new(),
        authority: String::new(),
        placement: asterism_core::secret::Placement::Header { name: "x".into() },
        guest_handle: asterism_core::secret::GuestHandle::mint(
            asterism_core::secret::HandleShape::Opaque,
        ),
        env: String::new(),
        source_device_id: String::new(),
        source_device: String::new(),
        version: 0,
        bound_at: 0,
    }
}

// ---- certificates ----------------------------------------------------------

/// One instance's certificate authority: the key that signs its leaves, and
/// the certificate its guest is told to trust.
///
/// Per instance, and that is the containment: a leaf minted here is accepted
/// by exactly one guest, so the ability to impersonate `api.anthropic.com`
/// that this necessarily creates reaches one machine and stops. The private
/// half never leaves `~/.asterism/instances/<name>/egress/`, at 0600; the
/// seed carries the certificate and nothing else.
struct Authority {
    /// The instance this CA belongs to. Kept because the CA's distinguished
    /// name is a function of it, and a leaf has to be signed by an issuer
    /// whose name matches the certificate the guest already trusts — rebuild
    /// it from anything else and the chain does not build.
    instance: String,
    ca_pem: String,
    key_pem: String,
    /// Leaves, minted on first use for one authority and kept for the life of
    /// the proxy. Minting is milliseconds, but it is milliseconds on the
    /// first byte of every connection.
    leaves: StdMutex<BTreeMap<String, Arc<rustls::ServerConfig>>>,
}

impl Authority {
    fn load_or_create(dir: &std::path::Path, instance: &str) -> Result<Self> {
        std::fs::create_dir_all(dir)?;
        let (cert_path, key_path) = (dir.join("ca.crt"), dir.join("ca.key"));
        if let (Ok(ca_pem), Ok(key_pem)) = (
            std::fs::read_to_string(&cert_path),
            std::fs::read_to_string(&key_path),
        ) {
            return Ok(Self {
                instance: instance.to_owned(),
                ca_pem,
                key_pem,
                leaves: StdMutex::new(BTreeMap::new()),
            });
        }
        let key = rcgen::KeyPair::generate().context("generating this instance's CA key")?;
        let ca = ca_params(instance)?
            .self_signed(&key)
            .context("minting this instance's CA")?;
        let (ca_pem, key_pem) = (ca.pem(), key.serialize_pem());
        write_private(&key_path, &key_pem)?;
        std::fs::write(&cert_path, &ca_pem)?;
        Ok(Self {
            instance: instance.to_owned(),
            ca_pem,
            key_pem,
            leaves: StdMutex::new(BTreeMap::new()),
        })
    }

    /// A TLS acceptor presenting a leaf for one bound authority.
    fn acceptor(&self, authority: &str) -> Result<TlsAcceptor> {
        let host = authority
            .rsplit_once(':')
            .map_or(authority, |(host, _)| host)
            .to_owned();
        if let Some(config) = self
            .leaves
            .lock()
            .expect("egress leaves poisoned")
            .get(&host)
        {
            return Ok(TlsAcceptor::from(config.clone()));
        }
        let config = Arc::new(self.mint(&host)?);
        self.leaves
            .lock()
            .expect("egress leaves poisoned")
            .insert(host, config.clone());
        Ok(TlsAcceptor::from(config))
    }

    fn mint(&self, host: &str) -> Result<rustls::ServerConfig> {
        let ca_key =
            rcgen::KeyPair::from_pem(&self.key_pem).context("reading this instance's CA key")?;
        // Rebuilt rather than parsed back out of the certificate, so rcgen's
        // x509 parser stays out of the build. It has to be rebuilt from the
        // *same* input: an issuer whose distinguished name differs from the
        // CA certificate's subject signs leaves that chain to nothing, and a
        // guest sees `UnknownIssuer` with no way to tell why.
        let issuer = rcgen::Issuer::new(ca_params(&self.instance)?, ca_key);

        let leaf_key = rcgen::KeyPair::generate().context("generating a leaf key")?;
        let mut params = rcgen::CertificateParams::new(vec![host.to_owned()])
            .with_context(|| format!("{host} cannot be a certificate name"))?;
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, host);
        let leaf = params
            .signed_by(&leaf_key, &issuer)
            .with_context(|| format!("minting a leaf for {host}"))?;

        let mut config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(leaf.der().to_vec())],
                PrivateKeyDer::try_from(leaf_key.serialize_der())
                    .map_err(|e| anyhow!("the leaf key is not usable: {e}"))?,
            )
            .context("building the TLS configuration for a bound authority")?;
        // The guest speaks HTTP/1.1 to this proxy; advertising h2 would be
        // advertising something hyper is not configured to serve here.
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(config)
    }
}

/// The CA's parameters, which are a deterministic function of the instance
/// name so that a reload produces a matching issuer.
fn ca_params(instance: &str) -> Result<rcgen::CertificateParams> {
    let mut params = rcgen::CertificateParams::new(Vec::new())?;
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Constrained(0));
    params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::DigitalSignature,
    ];
    params
        .distinguished_name
        .push(rcgen::DnType::OrganizationName, "Asterism");
    // What a human sees in the certificate their guest was told to trust: what
    // it is, and which instance it belongs to.
    params.distinguished_name.push(
        rcgen::DnType::CommonName,
        format!("Asterism egress ({instance})"),
    );
    Ok(params)
}

/// Write a private key where only this user can read it.
///
/// Through the durable commit rather than straight at the path: this is an
/// instance's CA key, the guest is pinned to the certificate it signs, and a
/// key file that is half-written is an instance whose egress proxy will not
/// start until someone deletes it by hand.
fn write_private(path: &std::path::Path, pem: &str) -> Result<()> {
    asterism_core::durable::commit_private(path, pem.as_bytes())
        .with_context(|| format!("writing {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    use asterism_core::protocol::SecretValue;
    use asterism_core::secret::{
        GuestHandle, HandleShape, Placement, SecretId, SourceDevice, ValueRevision,
    };

    /// The value that must never be seen anywhere but inside the upstream's
    /// own request. Distinctive so that a search for it in a file, a log line
    /// or a response body is unambiguous.
    const REAL_VALUE: &str = "sk-ant-THE-REAL-VALUE-0ff1ce";

    // ---- the two `cfg(test)` hooks the production path reads ---------------
    //
    // Both exist because the thing under test is a proxy that deliberately
    // refuses to talk to loopback and deliberately trusts only the public
    // web, and a test upstream is on loopback and is not on the public web.
    // Neither of these compiles into a released binary.

    static ALLOW_LOOPBACK: AtomicBool = AtomicBool::new(false);
    static EXTRA_ROOT: StdMutex<Option<String>> = StdMutex::new(None);

    /// Both hooks above are process-global, and `cargo test` runs these in
    /// parallel — so a test that moves one takes this first. Without it, the
    /// test that proves loopback is refused runs while another has just
    /// allowed it, and passes or fails depending on the scheduler.
    async fn exclusive() -> tokio::sync::MutexGuard<'static, ()> {
        static LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
        LOCK.lock().await
    }

    pub(super) fn allow_loopback() -> bool {
        ALLOW_LOOPBACK.load(Ordering::Relaxed)
    }

    pub(super) fn extra_root() -> Option<String> {
        EXTRA_ROOT.lock().expect("test root poisoned").clone()
    }

    fn provider() {
        let _ = rustls::crypto::ring::default_provider().install_default();
    }

    fn binding(authority: &str) -> Binding {
        Binding {
            id: "b1".into(),
            secret_id: SecretId::from_name("anthropic").unwrap(),
            secret: "anthropic".into(),
            authority: authority.to_owned(),
            placement: Placement::Header {
                name: "x-api-key".into(),
            },
            guest_handle: GuestHandle::mint(HandleShape::Anthropic),
            env: "ANTHROPIC_API_KEY".into(),
            source_device_id: "source-key".into(),
            source_device: "laptop".into(),
            version: 1,
            bound_at: 1,
        }
    }

    fn handle() -> Handle {
        let lineage = ValueRevision::mint();
        Handle {
            secret_id: SecretId::from_name("anthropic").unwrap(),
            version: 1,
            source: SourceDevice {
                device_id: "source-key".into(),
                device: "laptop".into(),
                version: 1,
                updated_at: 1,
                origin: lineage.clone(),
                revision: lineage,
            },
        }
    }

    /// A source device that holds one value in memory, and reaches the
    /// upstream by the same [`egress_with`] the real one uses.
    struct FakeSource {
        /// Every request this source was handed, so the test can assert on
        /// what actually crossed the seam.
        seen: Arc<StdMutex<Vec<EgressRequest>>>,
    }

    impl Source for FakeSource {
        fn handle_for<'a>(&'a self, _binding: &'a Binding) -> Fut<'a, Result<Handle>> {
            Box::pin(async { Ok(handle()) })
        }

        fn egress<'a>(
            &'a self,
            _binding: &'a Binding,
            handle: Option<Handle>,
            request: EgressRequest,
        ) -> Fut<'a, Result<EgressResponse>> {
            self.seen
                .lock()
                .expect("seen poisoned")
                .push(request.clone());
            Box::pin(async move {
                egress_with(handle, request, |_| {
                    Ok(SecretValue::new(REAL_VALUE.as_bytes().to_vec()))
                })
                .await
                .map_err(|refusal| anyhow!("{refusal}"))
            })
        }
    }

    /// A real HTTPS server on loopback that records the headers it is sent.
    struct Upstream {
        port: u16,
        ca_pem: String,
        seen: Arc<StdMutex<Vec<(String, String)>>>,
    }

    async fn upstream() -> Upstream {
        provider();
        // Its own CA and leaf, minted by the same code the proxy uses — so
        // the test's fake service is a real TLS server, not a stub.
        let dir = tempfile::tempdir().expect("a temp dir").keep();
        let authority = Authority::load_or_create(&dir, "upstream").expect("an upstream CA");
        let acceptor = authority
            .acceptor("localhost")
            .expect("a leaf for localhost");
        let ca_pem = authority.ca_pem.clone();

        let listener = TcpListener::bind(("127.0.0.1", 0)).await.expect("a port");
        let port = listener.local_addr().unwrap().port();
        let seen: Arc<StdMutex<Vec<(String, String)>>> = Arc::new(StdMutex::new(Vec::new()));
        let recorder = seen.clone();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    continue;
                };
                let (acceptor, recorder) = (acceptor.clone(), recorder.clone());
                tokio::spawn(async move {
                    let Ok(tls) = acceptor.accept(stream).await else {
                        return;
                    };
                    let _ = http1::Builder::new()
                        .serve_connection(
                            TokioIo::new(tls),
                            service_fn(move |req: hyper::Request<Incoming>| {
                                let recorder = recorder.clone();
                                async move {
                                    for (name, value) in req.headers() {
                                        recorder.lock().expect("seen poisoned").push((
                                            name.as_str().to_owned(),
                                            value.to_str().unwrap_or_default().to_owned(),
                                        ));
                                    }
                                    Ok::<_, std::convert::Infallible>(hyper::Response::new(
                                        Full::new(Bytes::from_static(b"{\"upstream\":\"ok\"}")),
                                    ))
                                }
                            }),
                        )
                        .await;
                });
            }
        });
        Upstream { port, ca_pem, seen }
    }

    /// Start a proxy for one binding, without a registry or a daemon behind
    /// it, and answer with its port and the CA a guest has to trust.
    async fn proxy(bindings: Vec<Binding>, source: Arc<dyn Source>) -> (u16, String, PathBuf) {
        provider();
        let dir = tempfile::tempdir().expect("a temp dir").keep();
        let authority = Authority::load_or_create(&dir, "dev").expect("an instance CA");
        let ca_pem = authority.ca_pem.clone();
        let (listener, port) = bind_loopback(None).expect("a loopback port");
        let ctx = Arc::new(ProxyCtx {
            instance: "dev".into(),
            bindings,
            authority,
            source,
            revoked: Arc::new(AtomicBool::new(false)),
        });
        tokio::spawn(accept_loop(listener, ctx));
        (port, ca_pem, dir)
    }

    /// A client shaped like the one inside a bound guest: it trusts this
    /// instance's CA, and it sends everything through the proxy.
    fn guest(proxy_port: u16, ca_pem: &str) -> reqwest::Client {
        reqwest::Client::builder()
            .add_root_certificate(reqwest::Certificate::from_pem(ca_pem.as_bytes()).unwrap())
            .proxy(reqwest::Proxy::all(format!("http://127.0.0.1:{proxy_port}")).unwrap())
            .timeout(Duration::from_secs(20))
            .build()
            .expect("a guest client")
    }

    /// The end-to-end proof, and the reason the rest of this module exists.
    ///
    /// A real HTTPS client inside a "guest", a real CONNECT, a real TLS
    /// termination against a certificate this device minted, the real policy,
    /// and a real TLS connection out to a real server — with the substitution
    /// in the one place it is supposed to be. What is asserted is not that it
    /// works but *where the value was*: in the upstream's request, and in no
    /// other place the test can reach.
    #[tokio::test]
    async fn the_value_reaches_the_upstream_and_nowhere_else() {
        let _exclusive = exclusive().await;
        ALLOW_LOOPBACK.store(true, Ordering::Relaxed);
        let up = upstream().await;
        *EXTRA_ROOT.lock().unwrap() = Some(up.ca_pem.clone());

        let bound = binding(&format!("localhost:{}", up.port));
        let handle_text = bound.guest_handle.as_str().to_owned();
        let seen = Arc::new(StdMutex::new(Vec::new()));
        let source = Arc::new(FakeSource { seen: seen.clone() });
        let (port, ca_pem, dir) = proxy(vec![bound.clone()], source).await;

        let response = guest(port, &ca_pem)
            .post(format!("https://localhost:{}/v1/messages", up.port))
            // Exactly what a guest's SDK would send, having read the handle
            // out of `$ANTHROPIC_API_KEY`.
            .header("x-api-key", &handle_text)
            .body("{\"hello\":\"world\"}")
            .send()
            .await
            .expect("the proxied request should reach the upstream");
        let status = response.status();
        let body = response.text().await.unwrap();
        assert_eq!(status, 200, "{body}");

        // 1. The upstream got the real value, at the bound placement.
        let received = up.seen.lock().unwrap().clone();
        let key = received
            .iter()
            .find(|(name, _)| name == "x-api-key")
            .map(|(_, value)| value.clone())
            .expect("the upstream should have been sent the bound header");
        assert_eq!(key, REAL_VALUE);
        // 2. And never the handle: the guest's credential stopped at the proxy.
        assert!(
            !received
                .iter()
                .any(|(_, value)| value.contains(&handle_text)),
            "the guest's handle reached the upstream"
        );
        // 3. The guest saw the upstream's answer and not the value.
        assert_eq!(body, "{\"upstream\":\"ok\"}");
        assert!(!body.contains(REAL_VALUE));

        // 4. What crossed the seam to the source device had the credential
        //    header present and *empty*: the handle stays on this side, the
        //    value stays on that one, and the frame between holds neither.
        let crossed = seen.lock().unwrap().clone();
        assert_eq!(crossed.len(), 1);
        let frame = &crossed[0];
        assert_eq!(frame.method, "POST");
        assert_eq!(frame.target, "/v1/messages");
        let carried = frame
            .headers
            .iter()
            .find(|(name, _)| name == "x-api-key")
            .expect("the placement should be named on the frame");
        assert_eq!(carried.1, "", "the handle crossed the seam");
        let json = serde_json::to_string(frame).unwrap();
        assert!(!json.contains(REAL_VALUE), "the value crossed the seam");
        assert!(!json.contains(&handle_text), "the handle crossed the seam");

        // 5. Nothing this instance persisted holds the value — including the
        //    CA, its key, and everything else the proxy wrote.
        for entry in std::fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            let bytes = std::fs::read(&path).unwrap_or_default();
            let text = String::from_utf8_lossy(&bytes);
            assert!(
                !text.contains(REAL_VALUE),
                "{} holds the value",
                path.display()
            );
        }
        // 6. Nor does the seed the guest would be handed. A seed carries the
        //    certificate and the handle, which is the whole design.
        let egress = seed::Egress {
            proxy: format!("http://10.0.2.2:{port}"),
            ca_pem: ca_pem.clone(),
            authorities: vec![bound.authority.clone()],
            handles: vec![(bound.env.clone(), handle_text.clone())],
        };
        assert!(!format!("{egress:?}").contains(REAL_VALUE));
        assert!(!ca_pem.contains(REAL_VALUE));
        assert!(!ca_pem.contains("PRIVATE KEY"));

        let _ = std::fs::remove_dir_all(&dir);
        *EXTRA_ROOT.lock().unwrap() = None;
        ALLOW_LOOPBACK.store(false, Ordering::Relaxed);
    }

    /// The same path, with the wrong credential. Nothing leaves.
    #[tokio::test]
    async fn a_guest_that_presents_the_wrong_handle_is_refused_before_anything_leaves() {
        let _exclusive = exclusive().await;
        ALLOW_LOOPBACK.store(true, Ordering::Relaxed);
        let up = upstream().await;
        *EXTRA_ROOT.lock().unwrap() = Some(up.ca_pem.clone());

        let bound = binding(&format!("localhost:{}", up.port));
        let seen = Arc::new(StdMutex::new(Vec::new()));
        let (port, ca_pem, dir) = proxy(
            vec![bound.clone()],
            Arc::new(FakeSource { seen: seen.clone() }),
        )
        .await;

        let response = guest(port, &ca_pem)
            .post(format!("https://localhost:{}/v1/messages", up.port))
            .header("x-api-key", "sk-ant-someone-elses-guess")
            .send()
            .await
            .expect("a refusal is still a response");
        assert_eq!(response.status(), 401);
        let body = response.text().await.unwrap();
        // The refusal names the rule and not what was sent — echoing a
        // rejected credential writes it into the guest's own logs.
        assert!(body.contains("not this instance's handle"), "{body}");
        assert!(!body.contains("someone-elses-guess"), "{body}");

        assert!(
            seen.lock().unwrap().is_empty(),
            "a refused request was sent on"
        );
        assert!(
            up.seen.lock().unwrap().is_empty(),
            "the upstream was contacted for a refused request"
        );

        let _ = std::fs::remove_dir_all(&dir);
        *EXTRA_ROOT.lock().unwrap() = None;
        ALLOW_LOOPBACK.store(false, Ordering::Relaxed);
    }

    /// A guest asking for a host it has no binding for, with the loopback
    /// allowance off — which is how a released binary always runs.
    #[tokio::test]
    async fn an_unbound_host_on_this_devices_own_network_is_not_tunnelled() {
        let _exclusive = exclusive().await;
        ALLOW_LOOPBACK.store(false, Ordering::Relaxed);
        let seen = Arc::new(StdMutex::new(Vec::new()));
        let (port, _ca, dir) = proxy(
            vec![binding("api.anthropic.com")],
            Arc::new(FakeSource { seen }),
        )
        .await;

        // A plain CONNECT, written by hand so the assertion is about the
        // proxy's answer and not about what a client library made of it.
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut socket = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        socket
            .write_all(b"CONNECT localhost:9 HTTP/1.1\r\nHost: localhost:9\r\n\r\n")
            .await
            .unwrap();
        let mut answer = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(5), socket.read_to_end(&mut answer)).await;
        let answer = String::from_utf8_lossy(&answer);
        assert!(answer.starts_with("HTTP/1.1 403"), "{answer}");
        assert!(answer.contains("loopback"), "{answer}");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Revoking a binding stops a connection that is already open.
    ///
    /// The window this closes: `ast detach --secret` while a guest is holding
    /// a keep-alive connection to a bound host. Tearing down the listener
    /// stops the *next* connection; the flag is what stops this one.
    #[tokio::test]
    async fn a_revoked_binding_is_refused_on_a_connection_that_was_already_open() {
        let _exclusive = exclusive().await;
        ALLOW_LOOPBACK.store(true, Ordering::Relaxed);
        let up = upstream().await;
        *EXTRA_ROOT.lock().unwrap() = Some(up.ca_pem.clone());

        let bound = binding(&format!("localhost:{}", up.port));
        let handle_text = bound.guest_handle.as_str().to_owned();
        let seen = Arc::new(StdMutex::new(Vec::new()));
        let revoked = Arc::new(AtomicBool::new(false));
        let dir = tempfile::tempdir().unwrap().keep();
        let authority = Authority::load_or_create(&dir, "dev").unwrap();
        let ca_pem = authority.ca_pem.clone();
        let (listener, port) = bind_loopback(None).unwrap();
        let ctx = Arc::new(ProxyCtx {
            instance: "dev".into(),
            bindings: vec![bound.clone()],
            authority,
            source: Arc::new(FakeSource { seen: seen.clone() }),
            revoked: revoked.clone(),
        });
        tokio::spawn(accept_loop(listener, ctx));

        // One client, kept alive across both requests, so the second reuses
        // the tunnel the first opened.
        let client = guest(port, &ca_pem);
        let url = format!("https://localhost:{}/v1/messages", up.port);
        let first = client
            .post(&url)
            .header("x-api-key", &handle_text)
            .send()
            .await
            .expect("the first request should go through");
        assert_eq!(first.status(), 200);
        assert_eq!(seen.lock().unwrap().len(), 1);

        // `ast detach --secret` — this is what `Proxy::drop` does.
        revoked.store(true, Ordering::SeqCst);

        let second = client
            .post(&url)
            .header("x-api-key", &handle_text)
            .send()
            .await
            .expect("a refusal is still a response");
        assert_eq!(second.status(), 403);
        assert_eq!(
            seen.lock().unwrap().len(),
            1,
            "a revoked binding was still sent to its source"
        );

        let _ = std::fs::remove_dir_all(&dir);
        *EXTRA_ROOT.lock().unwrap() = None;
        ALLOW_LOOPBACK.store(false, Ordering::Relaxed);
    }

    /// The cap this plane sizes itself against is the cap the mesh enforces.
    #[test]
    fn the_frame_limit_this_plane_sizes_itself_against_is_the_one_the_mesh_reads() {
        assert_eq!(
            asterism_core::protocol::MESH_FRAME_LIMIT,
            crate::mesh::MAX_FRAME,
            "the egress body caps are derived from a number that has moved"
        );
    }

    /// The proxy is on loopback, and that is the whole of why it is safe.
    #[tokio::test]
    async fn the_listener_is_reachable_from_the_guest_and_from_nothing_on_the_wire() {
        let (listener, port) = bind_loopback(None).expect("a loopback port");
        let addr = listener.local_addr().unwrap();
        assert_eq!(addr.port(), port);
        assert!(addr.ip().is_loopback(), "{addr} is not loopback");
        assert!(!addr.ip().is_unspecified(), "{addr} is a wildcard bind");
        drop(listener);
    }

    /// An available remembered port wins without consulting the allocator.
    #[test]
    fn an_available_preferred_port_is_reused_deterministically() {
        let preferred = 39_000;
        let expected = SocketAddr::from(([127, 0, 0, 1], preferred));
        let mut attempts = Vec::new();

        let selected = bind_loopback_with(Some(preferred), |addr| {
            attempts.push(addr);
            Ok(addr)
        })
        .expect("the preferred bind succeeds");

        assert_eq!(selected, expected);
        assert_eq!(attempts, [expected], "the allocator fallback was consulted");
    }

    /// A competing listener keeps the preferred port occupied throughout the
    /// bind, making fallback a deterministic product behavior rather than an
    /// ephemeral-port race in the fixture.
    #[tokio::test]
    async fn an_occupied_preferred_port_falls_back_on_loopback() {
        let occupied = std::net::TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .expect("a reservation for the preferred port");
        let preferred = occupied.local_addr().unwrap().port();

        let (fallback, port) = bind_loopback(Some(preferred)).expect("a fallback loopback port");
        let addr = fallback.local_addr().unwrap();
        assert_ne!(port, preferred, "the occupied port was reused");
        assert_eq!(addr.port(), port);
        assert!(addr.ip().is_loopback(), "{addr} is not loopback");
        assert!(!addr.ip().is_unspecified(), "{addr} is a wildcard bind");

        drop(fallback);
        drop(occupied);
    }

    /// A per-instance CA, and its private half stays here.
    #[tokio::test]
    async fn a_ca_is_per_instance_and_its_key_never_leaves_this_device() {
        provider();
        let dir = tempfile::tempdir().unwrap();
        let one = Authority::load_or_create(dir.path(), "dev").unwrap();
        // Reloading is the same CA — a guest that trusted it once still does.
        let again = Authority::load_or_create(dir.path(), "dev").unwrap();
        assert_eq!(one.ca_pem, again.ca_pem);
        // A second instance is a second CA: a leaf minted for one guest must
        // not be accepted by another.
        let other_dir = tempfile::tempdir().unwrap();
        let other = Authority::load_or_create(other_dir.path(), "prod").unwrap();
        assert_ne!(one.ca_pem, other.ca_pem);

        // The certificate is what goes in a seed; the key is not, and it is
        // written where only this user can read it.
        assert!(one.ca_pem.contains("BEGIN CERTIFICATE"));
        assert!(!one.ca_pem.contains("PRIVATE KEY"));
        let key = dir.path().join("ca.key");
        assert!(key.exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&key).unwrap().permissions().mode();
            assert_eq!(mode & 0o077, 0, "the CA key is readable by someone else");
        }
        // And a leaf for a bound authority chains to it.
        assert!(one.acceptor("api.anthropic.com:443").is_ok());
    }

    #[test]
    fn binding_a_secret_on_vz_oci_is_refused_before_mutation() {
        let mut inst = Instance::new(
            "oci-web",
            "dev",
            "alpine:latest",
            asterism_core::instance::Shape::default(),
            asterism_core::hv::Machine {
                backend: "vz".into(),
                machine_type: "generic".into(),
                cpu: "host".into(),
                hv_version: "test".into(),
            },
        );
        inst.image_kind = asterism_core::hv::ImageKind::OciRootfs;
        let err = check_can_bind(&inst).unwrap_err().to_string();
        assert!(
            err.contains("direct-kernel") || err.contains("OCI"),
            "{err}"
        );
        assert!(err.contains("guest agent"), "{err}");
    }

    #[test]
    fn a_guest_loopback_route_names_a_loopback_proxy_and_no_host_port() {
        let url = proxy_url(
            GuestEgress::GuestLoopback {
                bind: "127.0.0.1",
                port: 18765,
            },
            None,
        )
        .unwrap();
        assert_eq!(url, "http://127.0.0.1:18765");
        assert!(!url.contains("10.0.2.2"));
        assert!(
            proxy_url(
                GuestEgress::LoopbackGateway {
                    gateway: "10.0.2.2"
                },
                None
            )
            .is_err(),
            "a gateway route without a host port is not a URL"
        );
        assert_eq!(
            proxy_url(
                GuestEgress::LoopbackGateway {
                    gateway: "10.0.2.2"
                },
                Some(38123)
            )
            .unwrap(),
            "http://10.0.2.2:38123"
        );
    }

    /// The VZ path must never bind a TCP port, even on loopback: the guest
    /// cannot reach this host's loopback, and a non-loopback bind would be
    /// the LAN listener Caps exists to refuse.
    #[tokio::test]
    async fn a_unix_egress_listener_is_not_a_network_socket() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vsock.sock");
        let listener = bind_unix(&path).expect("a unix plane");
        let meta = std::fs::metadata(&path).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::{FileTypeExt, PermissionsExt};
            assert!(
                meta.file_type().is_socket(),
                "{path:?} is not a unix socket"
            );
            let mode = meta.permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "{mode:#o} is readable by someone else");
        }
        drop(listener);
    }

    /// The unix plane speaks the same CONNECT refusal as TCP: a verb it
    /// does not carry is 400, and nothing is bound to a network port.
    #[tokio::test]
    async fn a_unix_plane_refuses_anything_but_connect_and_never_binds_tcp() {
        let seen = Arc::new(StdMutex::new(Vec::new()));
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("vsock.sock");
        let authority = Authority::load_or_create(dir.path(), "dev").unwrap();
        let listener = bind_unix(&sock).unwrap();
        let ctx = Arc::new(ProxyCtx {
            instance: "dev".into(),
            bindings: vec![binding("api.anthropic.com")],
            authority,
            source: Arc::new(FakeSource { seen }),
            revoked: Arc::new(AtomicBool::new(false)),
        });
        tokio::spawn(accept_unix(listener, ctx));

        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut stream = tokio::net::UnixStream::connect(&sock).await.unwrap();
        stream
            .write_all(b"GET / HTTP/1.1\r\nHost: api.anthropic.com\r\n\r\n")
            .await
            .unwrap();
        let mut answer = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut answer)).await;
        let answer = String::from_utf8_lossy(&answer);
        assert!(answer.starts_with("HTTP/1.1 400"), "{answer}");
        assert!(answer.contains("CONNECT"), "{answer}");
    }
}
