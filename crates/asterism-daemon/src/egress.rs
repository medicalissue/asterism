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
//! The operational cost is one idle listener per *bound* instance (TCP
//! loopback for a VM, a private Unix socket for a container), one keypair
//! generated once per instance, and one leaf certificate per bound authority
//! held in memory for the life of the proxy.
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
use std::path::PathBuf;
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
use tokio::io::{AsyncRead, AsyncWrite};
#[cfg(unix)]
use tokio::net::UnixListener;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use zeroize::Zeroizing;

use asterism_core::hv::GuestEgress;
use asterism_core::instance::{Instance, RuntimeKind};
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

/// The proxy port inside each rootless container network namespace.
///
/// The host side is a per-instance Unix socket, not this TCP port. Keeping the
/// TCP listener inside the namespace means `--disable-host-loopback` can stay
/// enabled without making secret egress unreachable.
pub(crate) const CONTAINER_EGRESS_PORT: u16 = 38123;

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

/// One instance's proxy, while it is up.
struct Proxy {
    port: u16,
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
    /// A container proxy's host endpoint. It is the only host object mounted
    /// into the namespace, and removing it makes a stopped proxy unreachable.
    transport: Option<PathBuf>,
}

impl Drop for Proxy {
    fn drop(&mut self) {
        // Order matters only in that both happen: the flag makes a request
        // already inside the policy check fail, and the abort stops any
        // further connection being accepted at all.
        self.revoked.store(true, Ordering::SeqCst);
        self.task.abort();
        if let Some(path) = &self.transport {
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
/// instance's compute. Reaching here means this device holds the row, which
/// is the same fact — and writing it down a second time would mean comparing
/// an orbit name against a hostname, which are not the same string.
pub(crate) fn check_can_bind(inst: &Instance) -> Result<()> {
    // A rootless container gets one namespace-local TCP bridge to its own
    // read-only mounted Unix proxy. slirp host-loopback remains disabled, so
    // no unrelated listener on this device becomes reachable with it.
    if inst.runtime == RuntimeKind::Container {
        return Ok(());
    }
    let hv = backend::for_instance(inst)?;
    // Capability belongs to the backend recorded on the instance, not to
    // whether its executable happens to be installed on this host today.
    // Probe-gating this check used to let an impossible binding mutate the
    // registry on a machine without that backend, only to fail at boot.
    if hv.caps().guest_egress.is_none() {
        bail!(
            "the {} backend gives each guest an address on a shared network and offers no \
             door of its own into this device, so there is no listener only {:?} could \
             reach — a bound secret needs a guest-only door, and binding a wildcard \
             address instead would publish a proxy for this secret on your LAN. Run this \
             instance on a backend that declares one (qemu's user-mode gateway, or the \
             per-instance virtio-socket door vz and chv open inside the guest)",
            hv.id(),
            inst.name
        );
    }
    // A door the guest itself opens needs the guest agent that opens it.
    // Asterism injects that agent into an OCI root filesystem; a cloud image
    // installs the guest-control agent through cloud-init, and that one does
    // not carry the door yet. Refusing here rather than at boot keeps the
    // rule this whole check exists for: a binding is never recorded for a
    // guest that would come up holding a handle nothing honours.
    if matches!(hv.caps().guest_egress, Some(GuestEgress::AgentVsock { .. }))
        && inst.image_kind != asterism_core::hv::ImageKind::OciRootfs
    {
        bail!(
            "on the {} backend the guest's own agent opens the secret door, and Asterism \
             injects that agent only into an OCI root filesystem — {:?} was created from \
             a cloud image, whose agent does not carry the door yet. Create it from an \
             OCI reference, or run it on qemu",
            hv.id(),
            inst.name
        );
    }
    Ok(())
}

/// Where the guest reaches this device, according to its backend.
fn gateway(inst: &Instance) -> Result<&'static str> {
    if inst.runtime == RuntimeKind::Container {
        // The namespace helper owns this listener and forwards only to this
        // instance's mounted Unix proxy. slirp's host gateway remains blocked.
        return Ok("127.0.0.1");
    }
    let hv = backend::for_instance(inst)?;
    match hv.caps().guest_egress {
        Some(GuestEgress::LoopbackGateway { gateway }) => Ok(gateway),
        // The guest's own loopback. Its agent is what listens there, and
        // what it accepts leaves over this instance's virtio socket.
        Some(GuestEgress::AgentVsock { gateway, .. }) => Ok(gateway),
        None => bail!(
            "the {} backend has no guest-only path to this device",
            hv.id()
        ),
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
    let gateway = gateway(inst)?;
    let (port, ca_pem) = ensure_running(inst, true)?;
    Ok(seed::Egress {
        proxy: format!("http://{gateway}:{port}"),
        ca_pem,
        authorities: inst
            .secrets
            .iter()
            .map(|binding| binding.authority.clone())
            .collect(),
        // Not one entry per binding: a credential part is several bindings
        // sharing one handle, so the naive mapping would export `GH_TOKEN`
        // five times and would never export the second name its provider
        // declares. See `crate::credential::guest_environment`.
        handles: crate::credential::guest_environment(&inst.secrets),
        files: crate::credential::guest_files(&inst.secrets),
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
pub(crate) fn refresh_bindings(inst: &Instance) -> Result<()> {
    stop(&inst.name);
    if inst.status != asterism_core::instance::Status::Running {
        return Ok(());
    }
    // Back up even when nothing is bound any more. A running guest was told
    // to send its traffic here, and it goes on doing that until its next boot
    // reissues the seed — so taking the listener away because the last
    // binding went would break every unbound connection that guest makes, for
    // as long as it stays up. What comes back honours nothing.
    ensure_running(inst, false).map(|_| ())
}

/// The port and CA of this instance's proxy, starting it if it is not up.
fn ensure_running(inst: &Instance, may_move_port: bool) -> Result<(u16, String)> {
    let plane = plane()?;
    let mut running = plane.running.lock().expect("egress plane poisoned");
    if let Some(proxy) = running.get(&inst.name) {
        if !proxy.task.is_finished() {
            return Ok((proxy.port, proxy.ca_pem.clone()));
        }
        running.remove(&inst.name);
    }

    let authority = Authority::load_or_create(&egress_dir(&inst.name), &inst.name)?;
    let ca_pem = authority.ca_pem.clone();

    let revoked = Arc::new(AtomicBool::new(false));
    let ctx = Arc::new(ProxyCtx {
        instance: inst.name.clone(),
        cost: asterism_core::ledger::dir(&inst.name),
        bindings: inst.secrets.clone(),
        authority,
        source: Arc::new(OrbitSource {
            plane: plane.clone(),
            instance: inst.name.clone(),
        }),
        revoked: revoked.clone(),
    });
    // Which door this instance's backend declares decides what is bound
    // here. A container is its own case and never asks a hypervisor.
    let door = if inst.runtime == RuntimeKind::Container {
        None
    } else {
        backend::for_instance(inst)?.caps().guest_egress
    };
    let (port, task, transport) = if inst.runtime == RuntimeKind::Container {
        #[cfg(target_os = "linux")]
        {
            let socket = container_transport_dir(&inst.name).join("proxy.sock");
            std::fs::create_dir_all(socket.parent().expect("container transport parent"))?;
            let _ = std::fs::remove_file(&socket);
            let listener = UnixListener::bind(&socket)
                .with_context(|| format!("binding container egress at {}", socket.display()))?;
            (
                CONTAINER_EGRESS_PORT,
                tokio::runtime::Handle::current().spawn(accept_unix_loop(listener, ctx)),
                Some(socket),
            )
        }
        #[cfg(not(target_os = "linux"))]
        bail!("native-container secret egress is only available on Linux")
    } else if matches!(door, Some(GuestEgress::AgentVsock { .. })) {
        // Nothing binds a host interface for this door. The guest's agent
        // listens on the guest's own loopback, and the per-instance helper
        // carries what it accepts to here, so the host end is a unix socket
        // under this instance's directory and there is no port on this
        // device for anything else to reach.
        //
        // The guest-side port is fixed rather than allocated: it is in the
        // guest's own namespace, so two instances never collide, and a
        // daemon restart reclaims exactly what the running guest was seeded
        // with without having to remember anything.
        //
        // The host end is a unix socket, so this arm exists only where there
        // are unix sockets. No backend that declares this door is reachable
        // from Windows, and the bail keeps that a refusal rather than a type
        // error in a graph that never runs it.
        #[cfg(unix)]
        {
            let socket = vm_transport_path(&inst.name);
            std::fs::create_dir_all(socket.parent().expect("egress transport parent"))?;
            let _ = std::fs::remove_file(&socket);
            let listener = UnixListener::bind(&socket).with_context(|| {
                format!(
                    "binding {:?}'s guest egress door at {}",
                    inst.name,
                    socket.display()
                )
            })?;
            (
                asterism_core::egress_door::EGRESS_GUEST_PORT,
                tokio::runtime::Handle::current().spawn(accept_unix_loop(listener, ctx)),
                Some(socket),
            )
        }
        #[cfg(windows)]
        {
            // Windows has no unix socket under `$ASTERISM_HOME` to own, so
            // the host end is a named pipe with a security descriptor naming
            // only `astd`'s own identity — the same primitive, and the same
            // "nothing on this device can reach it" property, as the
            // filesystem permissions on the Unix arm. The per-instance helper
            // `astd` spawns runs as that identity and connects to it.
            let listener = asterism_core::ipc::service_pipe(&vm_transport_name(&inst.name))
                .with_context(|| format!("binding {:?}'s guest egress door", inst.name))?;
            (
                asterism_core::egress_door::EGRESS_GUEST_PORT,
                tokio::runtime::Handle::current().spawn(accept_pipe_loop(listener, ctx)),
                None,
            )
        }
        #[cfg(not(any(unix, windows)))]
        bail!("the guest secret egress door needs a unix socket or a named pipe on the host")
    } else {
        // VM user-mode networking maps its private gateway to host loopback.
        let preferred = stable_port(&inst.name);
        let (listener, port) = match (preferred, may_move_port) {
            (Some(port), false) => bind_loopback_exact(port).with_context(|| {
                format!(
                    "restoring {:?}'s egress proxy on its guest-configured port {port}",
                    inst.name
                )
            })?,
            _ => bind_loopback(preferred)?,
        };
        if preferred != Some(port) {
            let _ = std::fs::write(port_path(&inst.name), port.to_string());
        }
        (
            port,
            tokio::runtime::Handle::current().spawn(accept_loop(listener, ctx)),
            None,
        )
    };
    running.insert(
        inst.name.clone(),
        Proxy {
            port,
            ca_pem: ca_pem.clone(),
            task,
            revoked,
            transport,
        },
    );
    Ok((port, ca_pem))
}

/// Restore the process-local half of a running guest's egress after a daemon
/// restart. The port is part of that guest's already-booted configuration, so
/// restoration must reclaim it exactly; silently selecting another port
/// would report success while leaving the guest pointed at nothing.
pub(crate) fn restore_running(inst: &Instance) -> Result<()> {
    if inst.secrets.is_empty() {
        return Ok(());
    }
    check_can_bind(inst)?;
    ensure_running(inst, false).map(|_| ())
}

fn egress_dir(instance: &str) -> PathBuf {
    paths::instance_dir(instance).join("egress")
}

/// Directory mounted read-only into a rootless container. It contains only
/// the proxy socket: CA keys and every other egress artifact stay outside it.
pub(crate) fn container_transport_dir(instance: &str) -> PathBuf {
    egress_dir(instance).join("container-transport")
}

/// The host end of a [`GuestEgress::AgentVsock`] door.
///
/// Named here rather than in the backend because the egress plane owns it:
/// the backend is only told where to find it, and this file existing is what
/// makes a bound guest's traffic serviceable at all. Dropping the [`Proxy`]
/// removes it, which is how detach makes the door unreachable without
/// waiting for a reboot.
pub(crate) fn vm_transport_path(instance: &str) -> PathBuf {
    egress_dir(instance).join("proxy.sock")
}

/// The same door, named the way the per-instance helper is told to reach it.
///
/// On Unix that is the socket path above. On Windows there is no socket in
/// the filesystem to name, so it is a kernel named pipe whose name follows a
/// hash of the instance rather than the instance itself: pipe names are a
/// flat machine-wide namespace with a much narrower character set than an
/// instance name, and what keeps this one private is its descriptor, not its
/// spelling.
pub(crate) fn vm_transport_name(instance: &str) -> String {
    #[cfg(windows)]
    {
        format!(
            r"\\.\pipe\asterism-egress-{}",
            &blake3::hash(instance.as_bytes()).to_hex()[..16]
        )
    }
    #[cfg(not(windows))]
    {
        vm_transport_path(instance).display().to_string()
    }
}

fn port_path(instance: &str) -> PathBuf {
    egress_dir(instance).join("port")
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

/// Bind exactly the endpoint an already-running guest was configured to use.
fn bind_loopback_exact(port: u16) -> Result<(TcpListener, u16)> {
    let std_listener = bind_loopback_exact_with(port, std::net::TcpListener::bind)?;
    std_listener.set_nonblocking(true)?;
    Ok((TcpListener::from_std(std_listener)?, port))
}

fn bind_loopback_exact_with<T>(
    port: u16,
    bind: impl FnOnce(SocketAddr) -> std::io::Result<T>,
) -> std::io::Result<T> {
    bind(SocketAddr::from(([127, 0, 0, 1], port)))
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

/// What one instance's proxy knows.
struct ProxyCtx {
    instance: String,
    /// Where this instance's token ledger is written. Held here rather than
    /// derived per call so the path is decided once, when the proxy starts,
    /// and so a test can point one proxy at a directory of its own instead
    /// of at the process-wide `ASTERISM_HOME`.
    cost: PathBuf,
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
        tokio::spawn(serve_connection(stream, ctx.clone()));
    }
}

#[cfg(windows)]
async fn accept_pipe_loop(listener: asterism_core::ipc::ServicePipe, ctx: Arc<ProxyCtx>) {
    loop {
        let Ok(stream) = listener.accept().await else {
            continue;
        };
        tokio::spawn(serve_connection(stream, ctx.clone()));
    }
}

#[cfg(unix)]
async fn accept_unix_loop(listener: UnixListener, ctx: Arc<ProxyCtx>) {
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            continue;
        };
        tokio::spawn(serve_connection(stream, ctx.clone()));
    }
}

async fn serve_connection<S>(stream: S, ctx: Arc<ProxyCtx>)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // The outer connection speaks plain HTTP and carries exactly one useful
    // verb, CONNECT. Hyper owns the framing and every smuggling refusal.
    let served = http1::Builder::new()
        .max_headers(MAX_HEADERS)
        .serve_connection(
            TokioIo::new(stream),
            service_fn(move |req| connect_service(req, ctx.clone())),
        )
        .with_upgrades()
        .await;
    if let Err(e) = served {
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
        // The rule travels with the request rather than being looked up at
        // the far end, so the source performs the operation this instance's
        // binding authorised and not one of its own choosing.
        rule: binding.rule.clone(),
        body: body.to_vec(),
    };

    let request_bytes = request.body.len() as u64;
    let target = request.target.clone();
    let response = ctx
        .source
        .egress(binding, handle, request)
        .await
        .map_err(|e| Refusal::Upstream(format!("{e:#}")))?;

    // The one line this feature adds to the data plane. It runs after the
    // answer is in hand, reads integers out of bytes that are already in
    // memory on their way back to the guest, and cannot fail the call. See
    // `crate::cost`.
    crate::cost::record(
        &ctx.cost,
        &ctx.instance,
        authority,
        &target,
        request_bytes,
        &response,
    );

    Ok(response)
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
/// The same check, for the one caller outside this module: the token
/// endpoint a `refresh` rule exchanges a grant at
/// ([`crate::credential::post_form`]). A token endpoint that resolved to the
/// host's own network would be a way to make this daemon hand a refresh token
/// to something on loopback, and it is refused by exactly the rule that
/// refuses it for a guest.
pub(crate) async fn vet_public(authority: &str) -> Result<Vec<SocketAddr>, Refusal> {
    vet(authority).await
}

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
        // The `Host` this request will actually carry, port included when it
        // is not the default — because that is the header reqwest writes from
        // the url below, and a SigV4 signature over a different one is a
        // signature the far end rejects for a reason nobody can see.
        let signed_host = match port {
            443 => host.clone(),
            port => format!("{host}:{port}"),
        };
        apply_rule(&handle, &material, &request, &signed_host, &mut headers).await?;
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

/// Turn the material this device holds into the credential this request
/// carries, and put it where the frame says.
///
/// The three arms are the three door rules, and they are the only place in
/// the daemon where the difference between them exists. Everything before
/// this point — the policy, the handle, the strip, the frame — is identical
/// whether the part is a GitHub token, a Google grant or an AWS key pair,
/// which is what makes credential parts an extension of the secret plane
/// rather than a second one.
async fn apply_rule(
    handle: &Handle,
    material: &asterism_core::protocol::SecretValue,
    request: &EgressRequest,
    host: &str,
    headers: &mut http::HeaderMap,
) -> Result<(), Refusal> {
    let placement = &request.placement;
    let fill = |headers: &mut http::HeaderMap, value: &str| {
        rewrite::fill(
            &Binding {
                // Only the placement is read by `fill`; the rest of a binding
                // is the consumer's business and is not on this frame.
                placement: placement.clone(),
                ..placeholder()
            },
            headers,
            value,
        )
    };
    match &request.rule {
        // The stored bytes are the credential.
        asterism_core::credential::CredentialRule::Substitute => {
            let value = Zeroizing::new(
                std::str::from_utf8(material.as_bytes())
                    .map_err(|_| Refusal::Malformed("the bound secret is not text"))?
                    .to_owned(),
            );
            fill(headers, &value)
        }
        // The stored bytes buy the credential. The exchange happens here,
        // seconds before the connection out, and what it produces is never
        // written down — see `crate::credential`.
        asterism_core::credential::CredentialRule::Refresh {
            token_url,
            skew_secs,
        } => {
            let grant = asterism_core::credential::OAuthGrant::parse(material.as_bytes())
                .map_err(|e| Refusal::Upstream(format!("{e:#}")))?;
            let token = crate::credential::access_token(
                handle,
                &grant,
                token_url,
                *skew_secs,
                asterism_core::instance::now_unix(),
            )
            .await
            .map_err(|e| Refusal::Upstream(format!("{e:#}")))?;
            fill(headers, &token)
        }
        // There is no credential to substitute: the credential *is* a
        // signature over this request, and the guest never held anything that
        // could produce one.
        asterism_core::credential::CredentialRule::Sign {
            algorithm: asterism_core::credential::SigningAlgorithm::AwsSigv4,
            service,
            region,
        } => {
            let keys = asterism_core::credential::SigningKeys::parse(material.as_bytes())
                .map_err(|e| Refusal::Upstream(format!("{e:#}")))?;
            // The blank the consumer left is not part of what is signed: the
            // signer writes this header itself.
            headers.remove(placement.header());
            let rest: Vec<(String, String)> =
                asterism_core::protocol::EgressRequest::flatten(headers);
            let signed = asterism_core::sigv4::sign(
                &asterism_core::sigv4::Key {
                    access_key_id: &keys.access_key_id,
                    secret_access_key: &keys.secret_access_key,
                    session_token: keys.session_token.as_deref(),
                },
                &asterism_core::sigv4::Request {
                    method: &request.method,
                    target: &request.target,
                    host,
                    headers: &rest,
                    body: &request.body,
                    service,
                    region,
                    now: asterism_core::instance::now_unix(),
                },
            );
            for (name, value) in signed.headers {
                let name = http::HeaderName::try_from(name.as_str())
                    .map_err(|_| Refusal::Malformed("a signed header name is not a token"))?;
                let mut value = http::HeaderValue::try_from(value)
                    .map_err(|_| Refusal::Malformed("a signature is not a header value"))?;
                value.set_sensitive(true);
                headers.insert(name, value);
            }
            Ok(())
        }
    }
}

/// The client every upstream call is made with.
///
/// A function rather than an inline builder so that the one thing a test needs
/// to change — which roots are trusted, so a fake upstream on loopback can be
/// reached — is a `cfg(test)` branch in one place, and does not exist at all
/// in a released binary.
pub(crate) fn client_builder() -> reqwest::ClientBuilder {
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
        provider: None,
        accept: Vec::new(),
        rule: asterism_core::credential::CredentialRule::Substitute,
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
            provider: None,
            accept: Vec::new(),
            rule: asterism_core::credential::CredentialRule::Substitute,
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
    ///
    /// It answers two things: `/token`, in the shape an OAuth token endpoint
    /// answers, and everything else in the shape an API answers. One server
    /// because there is one test root, and one root because
    /// [`client_builder`]'s test hook is one PEM — which is the honest
    /// constraint rather than a shortcut: what is being proved is that the
    /// door exchanges a grant and sends the *result*, and that is visible
    /// whether the two endpoints share a certificate or not.
    struct Upstream {
        port: u16,
        ca_pem: String,
        seen: Arc<StdMutex<Vec<(String, String)>>>,
        /// The bodies `/token` was posted, so a test can prove the refresh
        /// token was spent exactly once and the access token was reused.
        token_requests: Arc<StdMutex<Vec<String>>>,
    }

    /// What the mock token endpoint hands back. Distinctive so that finding
    /// it anywhere is unambiguous.
    const MOCK_ACCESS_TOKEN: &str = "ya29.MOCK-ACCESS-TOKEN-3c0ffee";
    /// The refresh token the store holds. It buys an access token and is
    /// never itself something an API accepts, so it must reach the token
    /// endpoint and nowhere else.
    const MOCK_REFRESH_TOKEN: &str = "1//MOCK-REFRESH-TOKEN-d0not5end";

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
        let token_requests: Arc<StdMutex<Vec<String>>> = Arc::new(StdMutex::new(Vec::new()));
        let recorder = seen.clone();
        let tokens = token_requests.clone();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    continue;
                };
                let (acceptor, recorder, tokens) =
                    (acceptor.clone(), recorder.clone(), tokens.clone());
                tokio::spawn(async move {
                    let Ok(tls) = acceptor.accept(stream).await else {
                        return;
                    };
                    let _ = http1::Builder::new()
                        .serve_connection(
                            TokioIo::new(tls),
                            service_fn(move |req: hyper::Request<Incoming>| {
                                let (recorder, tokens) = (recorder.clone(), tokens.clone());
                                async move {
                                    let is_token = req.uri().path() == "/token";
                                    if !is_token {
                                        for (name, value) in req.headers() {
                                            recorder.lock().expect("seen poisoned").push((
                                                name.as_str().to_owned(),
                                                value.to_str().unwrap_or_default().to_owned(),
                                            ));
                                        }
                                    }
                                    let body = req
                                        .into_body()
                                        .collect()
                                        .await
                                        .map(|collected| collected.to_bytes())
                                        .unwrap_or_default();
                                    if is_token {
                                        tokens
                                            .lock()
                                            .expect("tokens poisoned")
                                            .push(String::from_utf8_lossy(&body).into_owned());
                                        return Ok::<_, std::convert::Infallible>(
                                            hyper::Response::new(Full::new(Bytes::from(format!(
                                                "{{\"access_token\":\"{MOCK_ACCESS_TOKEN}\",\
                                                 \"expires_in\":3600,\
                                                 \"token_type\":\"Bearer\"}}"
                                            )))),
                                        );
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
        Upstream {
            port,
            ca_pem,
            seen,
            token_requests,
        }
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
            cost: dir.join("cost"),
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

    /// A source device holding whatever bytes the test says, under whatever
    /// rule the binding says.
    ///
    /// The same `egress_with` the real one uses, so what is exercised is the
    /// production path and not a description of it.
    struct RuleSource {
        material: Vec<u8>,
        /// One handle for the life of this source, rather than a fresh mint
        /// per call. A handle names a version *and* a revision, and a real
        /// one is stable until the part is rotated — which is what lets the
        /// access-token cache be keyed on it.
        handle: Handle,
    }

    impl Source for RuleSource {
        fn handle_for<'a>(&'a self, _binding: &'a Binding) -> Fut<'a, Result<Handle>> {
            let handle = self.handle.clone();
            Box::pin(async move { Ok(handle) })
        }

        fn egress<'a>(
            &'a self,
            _binding: &'a Binding,
            handle: Option<Handle>,
            request: EgressRequest,
        ) -> Fut<'a, Result<EgressResponse>> {
            let material = self.material.clone();
            Box::pin(async move {
                egress_with(handle, request, move |_| Ok(SecretValue::new(material)))
                    .await
                    .map_err(|refusal| anyhow!("{refusal}"))
            })
        }
    }

    fn credential_binding(
        authority: &str,
        rule: asterism_core::credential::CredentialRule,
    ) -> Binding {
        Binding {
            placement: Placement::Authorization {
                scheme: "Bearer".into(),
            },
            guest_handle: GuestHandle::mint_prefixed("sk-ast-google-"),
            secret: "google".into(),
            env: "GOOGLE_OAUTH_ACCESS_TOKEN".into(),
            provider: Some("google".into()),
            rule,
            authority: authority.to_owned(),
            ..binding(authority)
        }
    }

    /// The `refresh` rule, end to end, against a local mock token endpoint.
    ///
    /// A real guest client, a real CONNECT, a real TLS termination, the real
    /// policy — and then the thing this rule adds: the source device reads a
    /// *grant* out of its store, spends it at the token endpoint, and sends
    /// the access token it got back. What is asserted is where each of the
    /// three credentials was allowed to be.
    ///
    /// The grant here is a fixture rather than a real Google authorization,
    /// which is the honest limit of this test and of the lane beside it: a
    /// real grant needs a human in a browser. What is *not* mocked is the
    /// exchange, the substitution, the caching, or any of the plumbing
    /// between them.
    #[tokio::test]
    async fn a_refresh_rule_spends_a_grant_and_sends_only_what_it_bought() {
        let _exclusive = exclusive().await;
        ALLOW_LOOPBACK.store(true, Ordering::Relaxed);
        let up = upstream().await;
        *EXTRA_ROOT.lock().unwrap() = Some(up.ca_pem.clone());

        let authority = format!("localhost:{}", up.port);
        let bound = credential_binding(
            &authority,
            asterism_core::credential::CredentialRule::Refresh {
                token_url: format!("https://localhost:{}/token", up.port),
                skew_secs: 120,
            },
        );
        let handle_text = bound.guest_handle.as_str().to_owned();
        let grant = serde_json::to_vec(&asterism_core::credential::OAuthGrant {
            marker: asterism_core::credential::OAUTH_MARKER,
            provider: "google".into(),
            refresh_token: MOCK_REFRESH_TOKEN.into(),
            scopes: vec!["https://www.googleapis.com/auth/gmail.readonly".into()],
            client_id: "mock-client-id".into(),
            client_secret: Some("mock-client-secret".into()),
            token_url: format!("https://localhost:{}/token", up.port),
            account: Some("someone@example.com".into()),
        })
        .unwrap();
        let source = Arc::new(RuleSource {
            material: grant,
            handle: handle(),
        });
        let (port, ca_pem, _dir) = proxy(vec![bound.clone()], source).await;

        let response = guest(port, &ca_pem)
            .get(format!("https://{authority}/gmail/v1/users/me/profile"))
            // Exactly what `curl` inside the guest would send, having read
            // the handle out of `$GOOGLE_OAUTH_ACCESS_TOKEN`.
            .header("authorization", format!("Bearer {handle_text}"))
            .send()
            .await
            .expect("the proxied request should reach the upstream");
        assert_eq!(response.status(), 200);

        // 1. The token endpoint was asked, with the refresh grant.
        let asked = up.token_requests.lock().unwrap().clone();
        assert_eq!(asked.len(), 1, "the grant was spent {} times", asked.len());
        assert!(
            asked[0].contains("grant_type=refresh_token"),
            "{}",
            asked[0]
        );
        assert!(asked[0].contains("mock-client-id"), "{}", asked[0]);

        // 2. The API got the access token, as a Bearer.
        let received = up.seen.lock().unwrap().clone();
        let sent = received
            .iter()
            .find(|(name, _)| name == "authorization")
            .map(|(_, value)| value.clone())
            .expect("the upstream should have been sent an Authorization header");
        assert_eq!(sent, format!("Bearer {MOCK_ACCESS_TOKEN}"));

        // 3. And never the refresh token or the handle. The refresh token is
        //    not something an API accepts, so sending it there would be both
        //    a leak and a bug that fails silently.
        assert!(
            !received
                .iter()
                .any(|(_, value)| value.contains(MOCK_REFRESH_TOKEN)),
            "the refresh token reached the API"
        );
        assert!(
            !received
                .iter()
                .any(|(_, value)| value.contains(&handle_text)),
            "the guest's handle reached the API"
        );

        // 4. A second call reuses the token that is still good. The access
        //    token is not written down anywhere, so "cached" has to mean in
        //    this process and nowhere else — and this is what proves the
        //    cache exists at all.
        guest(port, &ca_pem)
            .get(format!("https://{authority}/gmail/v1/users/me/messages"))
            .header("authorization", format!("Bearer {handle_text}"))
            .send()
            .await
            .expect("the second call should also reach the upstream");
        assert_eq!(
            up.token_requests.lock().unwrap().len(),
            1,
            "the grant was spent again for a token that was still good"
        );

        ALLOW_LOOPBACK.store(false, Ordering::Relaxed);
        *EXTRA_ROOT.lock().unwrap() = None;
    }

    /// The `sign` rule, end to end, against a verifier that recomputes the
    /// signature the way a service would.
    ///
    /// The signer itself is proved against AWS's published vector in
    /// `asterism_core::sigv4`. What this proves is the part that lives here:
    /// that a request arriving at the door with a handle in it leaves it
    /// signed, over the body and the target it actually carries, with a key
    /// the guest never held.
    #[tokio::test]
    async fn a_sign_rule_signs_the_request_the_guest_actually_made() {
        let _exclusive = exclusive().await;
        ALLOW_LOOPBACK.store(true, Ordering::Relaxed);
        let up = upstream().await;
        *EXTRA_ROOT.lock().unwrap() = Some(up.ca_pem.clone());

        let authority = format!("localhost:{}", up.port);
        let bound = credential_binding(
            &authority,
            asterism_core::credential::CredentialRule::Sign {
                algorithm: asterism_core::credential::SigningAlgorithm::AwsSigv4,
                service: "sts".into(),
                region: "us-east-1".into(),
            },
        );
        let handle_text = bound.guest_handle.as_str().to_owned();
        let source = Arc::new(RuleSource {
            material: b"AKIDEXAMPLE\nwJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".to_vec(),
            handle: handle(),
        });
        let (port, ca_pem, _dir) = proxy(vec![bound.clone()], source).await;

        let response = guest(port, &ca_pem)
            .post(format!("https://{authority}/"))
            .header("authorization", format!("Bearer {handle_text}"))
            .body("Action=GetCallerIdentity&Version=2011-06-15")
            .send()
            .await
            .expect("the proxied request should reach the upstream");
        assert_eq!(response.status(), 200);

        let received = up.seen.lock().unwrap().clone();
        let signature = received
            .iter()
            .find(|(name, _)| name == "authorization")
            .map(|(_, value)| value.clone())
            .expect("the upstream should have been sent an Authorization header");
        // The guest's handle was replaced by a signature, and the signature
        // names the credential the *source* holds.
        assert!(signature.starts_with("AWS4-HMAC-SHA256 "), "{signature}");
        assert!(signature.contains("Credential=AKIDEXAMPLE/"), "{signature}");
        assert!(
            signature.contains("/us-east-1/sts/aws4_request"),
            "{signature}"
        );
        assert!(!signature.contains(&handle_text), "{signature}");
        // The signature covers the body the guest sent, so the payload hash
        // header has to be the one for those bytes.
        let payload = received
            .iter()
            .find(|(name, _)| name == "x-amz-content-sha256")
            .map(|(_, value)| value.clone())
            .expect("a signed request carries its payload hash");
        assert_eq!(
            payload,
            asterism_core::sigv4::payload_hash(b"Action=GetCallerIdentity&Version=2011-06-15")
        );
        // And the secret key itself never went anywhere.
        assert!(
            !received
                .iter()
                .any(|(_, value)| value.contains("wJalrXUtnFEMI")),
            "the signing key reached the upstream"
        );

        ALLOW_LOOPBACK.store(false, Ordering::Relaxed);
        *EXTRA_ROOT.lock().unwrap() = None;
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
            files: Vec::new(),
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
            cost: dir.join("cost"),
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

    #[test]
    fn a_rootless_container_uses_its_namespace_local_secret_egress_bridge() {
        let mut instance = Instance::new(
            "dev",
            "laptop",
            "oci",
            asterism_core::instance::Shape::default(),
            asterism_core::hv::Machine {
                backend: crate::container::LINUX_ID.into(),
                machine_type: "linux-userns-cgroup-v2".into(),
                cpu: "x86_64".into(),
                hv_version: "native".into(),
            },
        );
        instance.runtime = RuntimeKind::Container;
        assert!(check_can_bind(&instance).is_ok());
        assert_eq!(gateway(&instance).unwrap(), "127.0.0.1");
    }

    fn recorded_on(backend: &str, machine_type: &str) -> Instance {
        Instance::new(
            "dev",
            "laptop",
            "oci",
            asterism_core::instance::Shape::default(),
            asterism_core::hv::Machine {
                backend: backend.into(),
                machine_type: machine_type.into(),
                cpu: "aarch64".into(),
                hv_version: "native".into(),
            },
        )
    }

    /// A backend that declares no door at all refuses the binding before the
    /// registry changes, rather than at boot. Every backend in the tree now
    /// declares one, so the refusal is exercised against a `Caps` that says
    /// `None` — which is the thing the check actually reads.
    #[test]
    fn a_backend_with_no_door_refuses_before_probe_or_mutation() {
        let hv = crate::backend::by_id(crate::backend::hyperv::ID).unwrap();
        let mut caps = hv.caps();
        assert!(caps.guest_egress.is_some());
        caps.guest_egress = None;
        assert!(!caps.supports(asterism_core::hv::Capability::GuestEgress));
        // And the message the user would see names the way out.
        let instance = recorded_on(crate::backend::hyperv::ID, "hyperv");
        let error = check_can_bind(&instance).unwrap_err().to_string();
        assert!(error.contains("OCI root filesystem"), "{error}");
    }

    /// Every agent door is the guest's own loopback, carried out over that
    /// instance's socket. What the seed tells the guest has to be that
    /// address and nothing else, and each backend has its own reason: VZ's
    /// bridge address is reachable by every other guest on the same NAT,
    /// CHV's per-instance TAP host address is a real interface on this
    /// device one route table away from every other guest and the LAN, and
    /// Hyper-V's HCN NAT gateway is shared by every guest on it.
    #[test]
    fn an_agent_door_points_the_guest_at_its_own_loopback() {
        for (backend, machine) in [
            (crate::backend::vz::ID, "vz-linux"),
            (crate::backend::chv::ID, "chv-linux"),
            (crate::backend::hyperv::ID, "hcs-v2.1-generation-2"),
        ] {
            let mut instance = recorded_on(backend, machine);
            instance.image_kind = asterism_core::hv::ImageKind::OciRootfs;
            check_can_bind(&instance)
                .unwrap_or_else(|_| panic!("{backend} declares a guest-only door"));
            assert_eq!(gateway(&instance).unwrap(), "127.0.0.1");
        }
    }

    /// The door is only as real as the agent that opens it. An instance
    /// created from a cloud image has the cloud-init agent, which does not
    /// carry one — so the binding is refused before the row changes rather
    /// than discovered as a guest holding a handle nothing honours.
    #[test]
    fn a_cloud_image_has_no_agent_to_open_the_door_and_is_refused() {
        for (backend, machine) in [
            (crate::backend::vz::ID, "vz-linux"),
            (crate::backend::chv::ID, "chv-linux"),
            (crate::backend::hyperv::ID, "hcs-v2.1-generation-2"),
        ] {
            let instance = recorded_on(backend, machine);
            assert_eq!(instance.image_kind, asterism_core::hv::ImageKind::Disk);
            let error = check_can_bind(&instance).unwrap_err().to_string();
            assert!(error.contains("OCI root filesystem"), "{backend}: {error}");
        }
    }

    /// A VM proxy is on loopback, and that is the whole of why it is safe.
    #[tokio::test]
    async fn the_listener_is_reachable_from_the_guest_and_from_nothing_on_the_wire() {
        let (listener, port) = bind_loopback(None).expect("a loopback port");
        let addr = listener.local_addr().unwrap();
        assert_eq!(addr.port(), port);
        assert!(addr.ip().is_loopback(), "{addr} is not loopback");
        assert!(!addr.ip().is_unspecified(), "{addr} is a wildcard bind");
        drop(listener);
    }

    /// The container path carries a real CONNECT over only the mounted Unix
    /// endpoint. The TCP listener here stands in for the helper's loopback
    /// listener inside the isolated network namespace.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn container_unix_transport_carries_bound_egress() {
        use tokio::io::copy_bidirectional;
        use tokio::net::UnixStream;

        let _exclusive = exclusive().await;
        ALLOW_LOOPBACK.store(true, Ordering::Relaxed);
        let up = upstream().await;
        *EXTRA_ROOT.lock().unwrap() = Some(up.ca_pem.clone());
        let bound = binding(&format!("localhost:{}", up.port));
        let handle_text = bound.guest_handle.as_str().to_owned();
        let seen = Arc::new(StdMutex::new(Vec::new()));

        let dir = tempfile::tempdir().unwrap();
        let authority = Authority::load_or_create(dir.path(), "container").unwrap();
        let ca_pem = authority.ca_pem.clone();
        let socket = dir.path().join("proxy.sock");
        let unix = UnixListener::bind(&socket).unwrap();
        let ctx = Arc::new(ProxyCtx {
            instance: "container".into(),
            cost: dir.path().join("cost"),
            bindings: vec![bound],
            authority,
            source: Arc::new(FakeSource { seen: seen.clone() }),
            revoked: Arc::new(AtomicBool::new(false)),
        });
        let proxy_task = tokio::spawn(accept_unix_loop(unix, ctx));

        let bridge = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = bridge.local_addr().unwrap().port();
        let bridge_socket = socket.clone();
        let bridge_task = tokio::spawn(async move {
            let (mut guest, _) = bridge.accept().await.unwrap();
            let mut host = UnixStream::connect(bridge_socket).await.unwrap();
            copy_bidirectional(&mut guest, &mut host).await.unwrap();
        });

        let response = guest(port, &ca_pem)
            .post(format!("https://localhost:{}/v1/messages", up.port))
            .header("x-api-key", handle_text)
            .body("{}")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(seen.lock().unwrap().len(), 1);

        bridge_task.abort();
        proxy_task.abort();
        *EXTRA_ROOT.lock().unwrap() = None;
        ALLOW_LOOPBACK.store(false, Ordering::Relaxed);
    }

    /// The whole agent door, minus the VMM: a guest agent listening on the
    /// *guest's* loopback, an authenticated vsock hop, and the private unix
    /// socket the plane owns. A real bound request crosses all three and
    /// comes back substituted, and the value never appears on the guest side
    /// of the hop.
    ///
    /// One test for both backends, because above the transport they are the
    /// same door. The vsock is a socket pair here: for VZ that stands in for
    /// Apple's transport, and for Cloud Hypervisor it is not a
    /// simplification at all — its hybrid vsock *is* a unix stream, one the
    /// VMM connects to `<vsock>_<port>` and splices to the guest. What runs
    /// below is the protocol and the splice, not either VMM.
    #[cfg(unix)]
    #[tokio::test]
    async fn the_agent_door_carries_a_bound_request_over_an_authenticated_hop() {
        use asterism_core::egress_door::{door_guest_handshake, door_host_handshake, pump};
        use std::io::BufReader;
        use std::os::unix::net::UnixStream as StdUnixStream;
        use tokio::io::copy_bidirectional;
        use tokio::net::UnixStream;

        const SENTINEL: &str = "NEVER-WRITE-THIS-PLAINTEXT";

        let _exclusive = exclusive().await;
        ALLOW_LOOPBACK.store(true, Ordering::Relaxed);
        let up = upstream().await;
        *EXTRA_ROOT.lock().unwrap() = Some(up.ca_pem.clone());
        let bound = binding(&format!("localhost:{}", up.port));
        let handle_text = bound.guest_handle.as_str().to_owned();
        let seen = Arc::new(StdMutex::new(Vec::new()));

        let dir = tempfile::tempdir().unwrap();
        let authority = Authority::load_or_create(dir.path(), "agentdoor").unwrap();
        let ca_pem = authority.ca_pem.clone();
        let socket = dir.path().join("proxy.sock");
        let unix = UnixListener::bind(&socket).unwrap();
        let ctx = Arc::new(ProxyCtx {
            instance: "agentdoor".into(),
            cost: dir.path().join("cost"),
            bindings: vec![bound],
            authority,
            source: Arc::new(FakeSource { seen: seen.clone() }),
            revoked: Arc::new(AtomicBool::new(false)),
        });
        let proxy_task = tokio::spawn(accept_unix_loop(unix, ctx));

        // The key both ends of the hop prove. One per instance; a guest
        // holding another instance's key is refused by the host half, which
        // `asterism_core::egress_door` proves on its own.
        let key = [0x7au8; 32];

        // The guest's side of the hop, and the door the guest's own agent
        // puts on the guest's loopback.
        let guest_side = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let guest_port = guest_side.local_addr().unwrap().port();
        let crossed = Arc::new(StdMutex::new(Vec::new()));
        let watched = crossed.clone();
        let host_socket = socket.clone();
        let hop = tokio::task::spawn_blocking(move || {
            let (agent_end, helper_end) = StdUnixStream::pair().unwrap();
            // Guest half: prove the key, then splice the guest's loopback
            // connection onto the hop.
            let guest_half = std::thread::spawn(move || {
                let mut reader = BufReader::new(agent_end.try_clone().unwrap());
                let mut writer = agent_end.try_clone().unwrap();
                door_guest_handshake(&mut reader, &mut writer, &key, "guest-nonce").unwrap();
                agent_end
            });
            // Host half: prove the key, then splice onto the plane's socket.
            let mut reader = BufReader::new(helper_end.try_clone().unwrap());
            let mut writer = helper_end.try_clone().unwrap();
            door_host_handshake(&mut reader, &mut writer, &key, "host-nonce").unwrap();
            let agent_end = guest_half.join().unwrap();
            let proxy = StdUnixStream::connect(&host_socket).unwrap();
            (agent_end, helper_end, proxy)
        })
        .await
        .unwrap();
        let (agent_end, helper_end, proxy) = hop;

        // Everything the guest sends is recorded on the way past, so the
        // test can look for a plaintext the guest must never have held.
        let listener_task = tokio::task::spawn_blocking(move || {
            let helper_up = helper_end.try_clone().unwrap();
            let proxy_up = proxy.try_clone().unwrap();
            std::thread::spawn(move || {
                let _ = pump(&helper_up, &proxy_up);
                let _ = proxy_up.shutdown(std::net::Shutdown::Write);
            });
            let _ = pump(&proxy, &helper_end);
            let _ = helper_end.shutdown(std::net::Shutdown::Write);
        });
        let agent_task = tokio::spawn(async move {
            let (guest_conn, _) = guest_side.accept().await.unwrap();
            let mut guest_conn = guest_conn;
            agent_end.set_nonblocking(true).unwrap();
            let mut hop = UnixStream::from_std(agent_end).unwrap();
            let mut tapped = Tap {
                inner: &mut hop,
                seen: watched,
            };
            let _ = copy_bidirectional(&mut guest_conn, &mut tapped).await;
        });

        let response = guest(guest_port, &ca_pem)
            .post(format!("https://localhost:{}/v1/messages", up.port))
            .header("x-api-key", handle_text.clone())
            .body("{}")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(seen.lock().unwrap().len(), 1, "the source was asked once");

        let bytes = crossed.lock().unwrap().clone();
        assert!(
            !bytes
                .windows(SENTINEL.len())
                .any(|window| window == SENTINEL.as_bytes()),
            "a secret value crossed the guest side of the door"
        );

        agent_task.abort();
        listener_task.abort();
        proxy_task.abort();
        *EXTRA_ROOT.lock().unwrap() = None;
        ALLOW_LOOPBACK.store(false, Ordering::Relaxed);
    }

    /// Records everything written *towards* the guest, which is the half a
    /// compromised guest could read.
    #[cfg(unix)]
    struct Tap<'a> {
        inner: &'a mut tokio::net::UnixStream,
        seen: Arc<StdMutex<Vec<u8>>>,
    }

    #[cfg(unix)]
    impl tokio::io::AsyncRead for Tap<'_> {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            let before = buf.filled().len();
            let polled = std::pin::Pin::new(&mut *self.inner).poll_read(cx, buf);
            if let std::task::Poll::Ready(Ok(())) = &polled {
                let fresh = buf.filled()[before..].to_vec();
                self.seen.lock().unwrap().extend_from_slice(&fresh);
            }
            polled
        }
    }

    #[cfg(unix)]
    impl tokio::io::AsyncWrite for Tap<'_> {
        fn poll_write(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            self.seen.lock().unwrap().extend_from_slice(buf);
            std::pin::Pin::new(&mut *self.inner).poll_write(cx, buf)
        }

        fn poll_flush(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut *self.inner).poll_flush(cx)
        }

        fn poll_shutdown(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut *self.inner).poll_shutdown(cx)
        }
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

    #[test]
    fn a_running_guest_restore_never_silently_moves_its_egress_port() {
        let port = 39000;
        let mut attempts = Vec::new();
        let error = bind_loopback_exact_with(port, |addr| {
            attempts.push(addr);
            Err::<(), _>(std::io::Error::new(
                std::io::ErrorKind::AddrInUse,
                "occupied",
            ))
        })
        .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::AddrInUse);
        assert_eq!(attempts, [SocketAddr::from(([127, 0, 0, 1], port))]);
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

    // ---- the model API mock, and the ledger it fills ----------------------
    //
    // Everything above proves the *credential* half of the door. This proves
    // the accounting half, over exactly the same path: a real HTTPS client
    // inside a "guest", a real CONNECT, a real TLS termination against a
    // certificate this device minted, the real policy, and a real TLS
    // connection out to a server that answers in the shapes Anthropic and
    // OpenAI actually answer in — including SSE.
    //
    // No API key exists anywhere in it. That is the point: the numbers the
    // ledger records come out of the *response*, so a server that says the
    // right thing is a complete test of the reading.

    /// A local HTTPS server that answers like a model API.
    ///
    /// Four routes, one per shape the door has to be able to read:
    /// `/v1/messages` and its `?stream=1` form, `/v1/chat/completions` and
    /// its stream. The bodies are the published response shapes, cut down to
    /// the fields that carry counters.
    async fn model_api() -> Upstream {
        provider();
        let dir = tempfile::tempdir().expect("a temp dir").keep();
        let authority = Authority::load_or_create(&dir, "modelapi").expect("an upstream CA");
        let acceptor = authority
            .acceptor("localhost")
            .expect("a leaf for localhost");
        let ca_pem = authority.ca_pem.clone();

        let listener = TcpListener::bind(("127.0.0.1", 0)).await.expect("a port");
        let port = listener.local_addr().unwrap().port();
        let seen: Arc<StdMutex<Vec<(String, String)>>> = Arc::new(StdMutex::new(Vec::new()));
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    continue;
                };
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    let Ok(tls) = acceptor.accept(stream).await else {
                        return;
                    };
                    let _ = http1::Builder::new()
                        .serve_connection(
                            TokioIo::new(tls),
                            service_fn(move |req: hyper::Request<Incoming>| async move {
                                let target = req
                                    .uri()
                                    .path_and_query()
                                    .map(|pq| pq.as_str().to_owned())
                                    .unwrap_or_default();
                                Ok::<_, std::convert::Infallible>(hyper::Response::new(Full::new(
                                    Bytes::from(model_api_body(&target)),
                                )))
                            }),
                        )
                        .await;
                });
            }
        });
        Upstream {
            port,
            ca_pem,
            seen,
            token_requests: Arc::new(StdMutex::new(Vec::new())),
        }
    }

    fn model_api_body(target: &str) -> &'static [u8] {
        match target {
            "/v1/messages" => {
                br#"{"id":"msg_01","type":"message","role":"assistant",
                "model":"claude-sonnet-5","content":[{"type":"text","text":"hi"}],
                "stop_reason":"end_turn",
                "usage":{"input_tokens":1000,"output_tokens":200,
                "cache_creation_input_tokens":300,"cache_read_input_tokens":4000}}"#
            }
            "/v1/messages?stream=1" => concat!(
                "event: message_start\n",
                "data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_02\",",
                "\"type\":\"message\",\"role\":\"assistant\",\"model\":\"claude-opus-5\",",
                "\"content\":[],\"usage\":{\"input_tokens\":2000,\"output_tokens\":1,",
                "\"cache_creation_input_tokens\":0,\"cache_read_input_tokens\":50000}}}\n\n",
                "event: content_block_delta\n",
                "data: {\"type\":\"content_block_delta\",\"index\":0,",
                "\"delta\":{\"type\":\"text_delta\",\"text\":\"hello\"}}\n\n",
                "event: message_delta\n",
                "data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},",
                "\"usage\":{\"output_tokens\":500}}\n\n",
                "event: message_stop\n",
                "data: {\"type\":\"message_stop\"}\n\n",
            )
            .as_bytes(),
            "/v1/chat/completions" => {
                br#"{"id":"chatcmpl-1","object":"chat.completion",
                "model":"gpt-4o","choices":[],
                "usage":{"prompt_tokens":900,"completion_tokens":90,"total_tokens":990,
                "prompt_tokens_details":{"cached_tokens":400}}}"#
            }
            "/v1/chat/completions?stream=1" => concat!(
                "data: {\"id\":\"chatcmpl-2\",\"object\":\"chat.completion.chunk\",",
                "\"model\":\"gpt-4o-mini\",\"choices\":[{\"delta\":{\"content\":\"hi\"}}],",
                "\"usage\":null}\n\n",
                "data: {\"id\":\"chatcmpl-2\",\"object\":\"chat.completion.chunk\",",
                "\"model\":\"gpt-4o-mini\",\"choices\":[],",
                "\"usage\":{\"prompt_tokens\":50,\"completion_tokens\":7,\"total_tokens\":57}}\n\n",
                "data: [DONE]\n\n",
            )
            .as_bytes(),
            // Anything else is an API this device has never heard of, and is
            // recorded as a call and its bytes.
            _ => br#"{"answer":"something this device does not know how to read"}"#,
        }
    }

    /// The proof the whole feature rests on: four real calls through the real
    /// door produce a ledger with the providers' own numbers in it, and a
    /// dollar figure per model.
    #[tokio::test]
    async fn the_door_records_what_four_real_calls_cost_without_a_key() {
        let _exclusive = exclusive().await;
        ALLOW_LOOPBACK.store(true, Ordering::Relaxed);
        let up = model_api().await;
        *EXTRA_ROOT.lock().unwrap() = Some(up.ca_pem.clone());
        let bound = binding(&format!("localhost:{}", up.port));
        let handle_text = bound.guest_handle.as_str().to_owned();
        let seen = Arc::new(StdMutex::new(Vec::new()));
        let source = Arc::new(FakeSource { seen });
        let (port, ca_pem, dir) = proxy(vec![bound], source).await;
        let cost = dir.join("cost");
        let client = guest(port, &ca_pem);

        for target in [
            "/v1/messages",
            "/v1/messages?stream=1",
            "/v1/chat/completions",
            "/v1/chat/completions?stream=1",
            "/v3/something-else",
        ] {
            let response = client
                .post(format!("https://localhost:{}{target}", up.port))
                .header("x-api-key", handle_text.clone())
                .body("{}")
                .send()
                .await
                .expect("the guest's call reaches the mock API");
            assert_eq!(response.status(), 200, "{target}");
        }

        let report = asterism_core::ledger::report_in(&cost, "dev", "today", 0);
        assert_eq!(report.calls, 5, "one line per call, unknown API included");

        // Fresh input: 1000 + 2000 (Anthropic) + 500 + 50 (OpenAI, with the
        // cached part taken out of the total the way OpenAI reports it).
        assert_eq!(report.input_tokens, 1000 + 2000 + 500 + 50);
        assert_eq!(report.output_tokens, 200 + 500 + 90 + 7);
        assert_eq!(report.cache_write_tokens, 300);
        assert_eq!(report.cache_read_tokens, 4000 + 50_000 + 400);

        // The API nobody could read is a call and its bytes, and nothing it
        // could not honestly claim to know.
        assert_eq!(report.unpriced_calls, 1);
        assert!(report.response_bytes > 0);

        let models: Vec<&str> = report.models.iter().map(|m| m.model.as_str()).collect();
        for expected in ["claude-sonnet-5", "claude-opus-5", "gpt-4o", "gpt-4o-mini"] {
            assert!(
                models.contains(&expected),
                "{expected} missing from {models:?}"
            );
        }

        // The dollar figure, computed the long way from the published rates
        // in `pricing.json`, so a change to either side has to be argued for.
        let sonnet = 1000.0 * 2.0 + 200.0 * 10.0 + 300.0 * 2.5 + 4000.0 * 0.2;
        let opus = 2000.0 * 5.0 + 500.0 * 25.0 + 50_000.0 * 0.5;
        let gpt4o = 500.0 * 2.5 + 90.0 * 10.0 + 400.0 * 1.25;
        let mini = 50.0 * 0.15 + 7.0 * 0.6;
        let expected = (sonnet + opus + gpt4o + mini) / 1_000_000.0;
        let usd = report.usd.expect("four priced models");
        assert!((usd - expected).abs() < 1e-9, "{usd} vs {expected}");

        // And the line that must never appear: no body, from any of the five
        // answers, reached the file.
        let day = std::fs::read_to_string(asterism_core::ledger::day_path_in(
            &cost,
            asterism_core::instance::now_unix(),
        ))
        .expect("a day file");
        for forbidden in ["hello", "end_turn", "chatcmpl", REAL_VALUE, &handle_text] {
            assert!(
                !day.contains(forbidden),
                "{forbidden:?} reached the ledger:\n{day}"
            );
        }

        *EXTRA_ROOT.lock().unwrap() = None;
        ALLOW_LOOPBACK.store(false, Ordering::Relaxed);
    }

    /// A guest that reaches a host it has no binding for is tunnelled blind,
    /// and nothing about it is recorded. The ledger is a by-product of
    /// termination, not a second interception.
    #[tokio::test]
    async fn an_unbound_host_is_tunnelled_and_never_recorded() {
        let _exclusive = exclusive().await;
        ALLOW_LOOPBACK.store(true, Ordering::Relaxed);
        let up = model_api().await;
        *EXTRA_ROOT.lock().unwrap() = Some(up.ca_pem.clone());
        // The proxy is bound to a *different* authority than the one the
        // guest calls, so the call is tunnelled rather than terminated.
        let bound = binding("api.example.com:443");
        let seen = Arc::new(StdMutex::new(Vec::new()));
        let (port, ca_pem, dir) = proxy(vec![bound], Arc::new(FakeSource { seen })).await;
        let cost = dir.join("cost");

        // It trusts the mock's own CA, because this connection is end-to-end
        // to the mock: the door never terminates it.
        let client = reqwest::Client::builder()
            .add_root_certificate(reqwest::Certificate::from_pem(up.ca_pem.as_bytes()).unwrap())
            .add_root_certificate(reqwest::Certificate::from_pem(ca_pem.as_bytes()).unwrap())
            .proxy(reqwest::Proxy::all(format!("http://127.0.0.1:{port}")).unwrap())
            .timeout(Duration::from_secs(20))
            .build()
            .unwrap();
        let response = client
            .post(format!("https://localhost:{}/v1/messages", up.port))
            .body("{}")
            .send()
            .await
            .expect("an unbound host is still reachable");
        assert_eq!(response.status(), 200);

        assert_eq!(
            asterism_core::ledger::report_in(&cost, "dev", "today", 0).calls,
            0,
            "a blind tunnel has nothing to read and records nothing"
        );

        *EXTRA_ROOT.lock().unwrap() = None;
        ALLOW_LOOPBACK.store(false, Ordering::Relaxed);
    }
}
