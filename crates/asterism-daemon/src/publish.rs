//! Published service endpoints for a guest that holds an address of its own.
//!
//! QEMU publishes `ast create -p` inside its own user-mode NAT: the mapping
//! becomes a `hostfwd` argument, the VMM binds the host port, and nothing in
//! `astd` is involved. The product backends have no such NAT. A VZ guest sits
//! on macOS's shared NAT bridge and a Cloud Hypervisor guest sits behind a
//! per-instance TAP, and in both cases the guest owns a private IP that the
//! host can route to but that nothing outside this device can name.
//!
//! So on those backends `astd` *is* the forward. For every declared mapping it
//! binds `127.0.0.1:HOST` here and splices what arrives to
//! `<guest private ip>:GUEST` — TCP by copying both directions of an accepted
//! connection, UDP by giving each client flow a socket of its own and letting
//! an idle one expire.
//!
//! ### Rules this module exists to keep
//!
//! * **Loopback only.** Every listener binds [`BIND`]. There is no flag that
//!   widens it, on purpose: a published endpoint is the loopback of the device
//!   supplying compute, the same place `ast ssh` lands, and never LAN ingress.
//! * **Exactly the declared port, or nothing.** The declaration is durable and
//!   is the endpoint a user wrote down. A restart that cannot reclaim
//!   `127.0.0.1:8080` reports that and leaves the mapping down; it never
//!   quietly moves the service somewhere else.
//! * **Bound to the running record.** Listeners come up once the guest's
//!   address is known (which for both native backends is when `boot` returns),
//!   go away on `down` and `rm`, come back on `up`, and are rebuilt from the
//!   registry when a daemon restarts on top of guests that outlived it.
//!
//! The table lives here, process-wide, for the same reason `persist`'s watch
//! table does: deaths and restarts are noticed in more than one place and none
//! of them has a handle to thread through.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex as StdMutex, MutexGuard, OnceLock};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

use asterism_core::hv::{GuestEndpoint, ImageKind};
use asterism_core::instance::{Instance, PortForward, PortProtocol, Status};

/// The only address a published endpoint ever binds.
pub(crate) const BIND: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

/// A UDP flow with no datagram in either direction for this long is closed.
/// UDP has no shutdown, so an unbounded table is the only other option.
const UDP_IDLE: Duration = Duration::from_secs(120);

/// How often the relay looks for flows to expire.
const UDP_SWEEP: Duration = Duration::from_secs(15);

/// Largest datagram the relay will carry. Comfortably above a jumbo frame and
/// far below the point where a per-flow buffer becomes interesting.
const UDP_DATAGRAM: usize = 65_535;

/// How long a rebind waits out this daemon's own just-aborted listener.
const SETTLE: Duration = Duration::from_secs(2);

// ---- the table -------------------------------------------------------------

/// One instance's published endpoints, while they are up.
struct Published {
    /// The guest these forwards point at. A guest that comes back on another
    /// address makes the recorded set stale, which is what `ensure` compares.
    guest: IpAddr,
    /// The declaration these listeners were built from.
    declared: Vec<PortForward>,
    /// One accept/relay loop per mapping. Dropping the entry aborts them,
    /// which is how `down` frees the host ports without waiting for anything.
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl Drop for Published {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

fn table() -> MutexGuard<'static, BTreeMap<String, Published>> {
    static TABLE: OnceLock<StdMutex<BTreeMap<String, Published>>> = OnceLock::new();
    TABLE
        .get_or_init(|| StdMutex::new(BTreeMap::new()))
        // A panic inside this module's short critical sections would make the
        // table unusable for the rest of the process. Take it anyway rather
        // than poison the daemon over bookkeeping, as `persist` does.
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

// ---- what a declaration means on this instance -----------------------------

/// Asterism's own guest-control port, as seen from inside the guest.
///
/// Published mappings may not name it. On an OCI guest it is where the
/// authenticated agent that `ast exec` and `ast logs` go through is listening,
/// so a mapping pointing at it would publish Asterism's control plane under
/// the name of the user's service and would never carry the service.
const PRIVATE_GUEST_PORT: u16 = asterism_core::guest::OCI_TCP_PORT;

/// Refuse a declaration no backend could bind, before an instance row exists.
///
/// TCP and UDP have separate host-port spaces, so the same number may be
/// published once for each. Repeating a protocol+host pair would make QEMU
/// fail at boot, and would make a native backend bind the same host port
/// twice, after create had already promised a usable endpoint.
///
/// The guest side is checked too: Asterism's guest-control port is not a
/// service endpoint, on any backend.
pub(crate) fn validate(publish: &[PortForward], image_kind: ImageKind) -> Result<()> {
    let mut seen = std::collections::HashSet::new();
    for mapping in publish {
        if !seen.insert((mapping.protocol, mapping.host)) {
            bail!(
                "host port {}/{} is published more than once — each protocol and host port may name only one guest endpoint",
                mapping.host,
                mapping.protocol
            );
        }
        if image_kind == ImageKind::OciRootfs && mapping.guest == PRIVATE_GUEST_PORT {
            bail!(
                "guest port {PRIVATE_GUEST_PORT} is Asterism's own guest-control endpoint on an \
                 OCI instance — `ast exec`, `ast logs` and boot readiness use it, and no service \
                 of yours is listening there. Publish the port your image actually serves"
            );
        }
    }
    Ok(())
}

/// The private address this instance's guest holds, when publishing is this
/// daemon's job at all.
///
/// `None` covers three different "nothing to do here" cases with one answer,
/// and every caller wants the same answer for all three:
///
/// * a stopped instance, or one whose guest is not recorded yet — the address
///   is not known, so publication waits for readiness;
/// * a QEMU guest, whose endpoint is a host forward the VMM already bound;
/// * a native container, which records no [`GuestEndpoint`] at all.
pub(crate) fn guest_address(inst: &Instance) -> Option<IpAddr> {
    if inst.status != Status::Running {
        return None;
    }
    match inst.handle.as_ref()?.endpoint.as_ref()? {
        GuestEndpoint::GuestAddr { addr } => Some(*addr),
        GuestEndpoint::HostForward { .. } | GuestEndpoint::HostForwardControl { .. } => None,
    }
}

// ---- lifecycle -------------------------------------------------------------

/// Check the declared host ports are free before a guest is created.
///
/// The point is the order: `ast up` on an instance whose port somebody else
/// took should say so while there is still nothing running, rather than boot a
/// guest and then report that its endpoint is missing. There is a window
/// between this and [`ensure`], and [`ensure`] is the one that decides — this
/// only turns the common case into an early, exact refusal.
pub(crate) fn preflight(inst: &Instance) -> Result<()> {
    if inst.publish.is_empty() {
        return Ok(());
    }
    // Backend-neutral on purpose. Whoever ends up binding the port — this
    // process for a native backend, the VMM for QEMU's `hostfwd` — the port
    // has to be free, and proving it here is the difference between a refusal
    // and a guest that boots without the endpoint it was created for. Each
    // claim is dropped immediately, so nothing is held across the boot.
    if !crate::backend::for_instance(inst)?.caps().port_forward {
        return Ok(());
    }
    for mapping in &inst.publish {
        claim(mapping)
            .with_context(|| format!("{:?} cannot publish {mapping} on this device", inst.name))?;
    }
    Ok(())
}

/// Bring this instance's published endpoints up, or leave them up.
///
/// Idempotent, and safe to call on anything: an instance with no declaration,
/// a QEMU instance and a stopped instance all return without touching the
/// table. A guest that came back on a different address has its old listeners
/// replaced rather than reused.
pub(crate) fn ensure(inst: &Instance) -> Result<()> {
    if inst.publish.is_empty() {
        retire(&inst.name);
        return Ok(());
    }
    let Some(guest) = guest_address(inst) else {
        // Address unknown: publication is deferred until readiness records
        // one. Anything already up belonged to a previous guest.
        retire(&inst.name);
        return Ok(());
    };

    let mut table = table();
    if let Some(existing) = table.get(&inst.name) {
        if existing.guest == guest
            && existing.declared == inst.publish
            && existing.tasks.iter().all(|task| !task.is_finished())
        {
            return Ok(());
        }
        table.remove(&inst.name);
    }

    let runtime = tokio::runtime::Handle::current();
    let mut tasks = Vec::with_capacity(inst.publish.len());
    for mapping in &inst.publish {
        let target = SocketAddr::new(guest, mapping.guest);
        let bound = claim_settling(mapping).with_context(|| {
            format!(
                "publishing {:?}'s {mapping} — the declaration is durable, so this exact port is \
                 the endpoint or there is none",
                inst.name
            )
        })?;
        // Any listener already bound for this instance is dropped with the
        // whole attempt: `tasks` owns them, and its Drop aborts them.
        tasks.push(match bound {
            Bound::Tcp(listener) => runtime.spawn(tcp_forward(listener, target)),
            Bound::Udp(socket) => runtime.spawn(udp_forward(socket, target, UDP_IDLE, UDP_SWEEP)),
        });
    }
    table.insert(
        inst.name.clone(),
        Published {
            guest,
            declared: inst.publish.clone(),
            tasks,
        },
    );
    Ok(())
}

/// Take this instance's published endpoints down. Idempotent, and the way a
/// stopped guest stops holding host ports it is no longer behind.
pub(crate) fn retire(name: &str) {
    table().remove(name);
}

/// Whether anything is published for `name` right now. Diagnostics and tests.
#[cfg(test)]
fn published_ports(name: &str) -> Option<Vec<PortForward>> {
    table().get(name).map(|p| p.declared.clone())
}

// ---- binding ---------------------------------------------------------------

#[derive(Debug)]
enum Bound {
    Tcp(TcpListener),
    Udp(UdpSocket),
}

/// Bind exactly what the mapping says, or say who has it.
///
/// Never falls back to another port. A published endpoint is a promise about
/// one number; moving it would report success while leaving every client that
/// read `ast status` pointed at nothing.
fn claim(mapping: &PortForward) -> Result<Bound> {
    let addr = SocketAddr::new(BIND, mapping.host);
    match mapping.protocol {
        PortProtocol::Tcp => {
            let listener = std::net::TcpListener::bind(addr).with_context(|| {
                format!("binding {addr} — another process or instance holds it")
            })?;
            listener.set_nonblocking(true)?;
            Ok(Bound::Tcp(TcpListener::from_std(listener)?))
        }
        PortProtocol::Udp => {
            let socket = std::net::UdpSocket::bind(addr).with_context(|| {
                format!("binding {addr}/udp — another process or instance holds it")
            })?;
            socket.set_nonblocking(true)?;
            Ok(Bound::Udp(UdpSocket::from_std(socket)?))
        }
    }
}

/// [`claim`], allowing for a listener this daemon has just let go.
///
/// Aborting an accept loop is a request to the runtime, not an instant close
/// of its socket, so a guest that comes back on a new address can reach here
/// microseconds before its own previous listener's file descriptor is gone.
/// That is this process's own transient and is worth waiting out; a port some
/// *other* process holds still fails, just a moment later.
///
/// This blocks, so it needs a runtime with other threads to retire the
/// aborted task on — `astd`'s is `new_multi_thread`, and so are the tests
/// that exercise a rebind.
fn claim_settling(mapping: &PortForward) -> Result<Bound> {
    let deadline = Instant::now() + SETTLE;
    loop {
        match claim(mapping) {
            Ok(bound) => return Ok(bound),
            Err(error) if Instant::now() >= deadline => return Err(error),
            Err(_) => std::thread::sleep(Duration::from_millis(25)),
        }
    }
}

// ---- TCP -------------------------------------------------------------------

/// Accept on the host port and splice each connection to the guest.
///
/// One task per accepted connection, and a connection that cannot reach the
/// guest is closed rather than retried: a service that is not listening inside
/// the guest should look, from the host, exactly like a service that is not
/// listening.
async fn tcp_forward(listener: TcpListener, target: SocketAddr) {
    loop {
        let Ok((client, _)) = listener.accept().await else {
            // A listener that stops accepting is not something this loop can
            // fix; the entry stays in the table and `ensure` rebuilds it when
            // the instance next comes up.
            return;
        };
        tokio::spawn(async move {
            let _ = tcp_splice(client, target).await;
        });
    }
}

async fn tcp_splice(mut client: TcpStream, target: SocketAddr) -> Result<()> {
    let mut guest = TcpStream::connect(target)
        .await
        .with_context(|| format!("dialling {target}"))?;
    // Nagle off on both halves: a published endpoint is usually a request
    // /response service, and the buffering shows up as latency for every one
    // of those round trips.
    let _ = client.set_nodelay(true);
    let _ = guest.set_nodelay(true);
    tokio::io::copy_bidirectional(&mut client, &mut guest)
        .await
        .map(|_| ())
        .context("splicing a published connection")
}

// ---- UDP -------------------------------------------------------------------

/// One client's conversation with the guest.
///
/// UDP has no connection, so "which reply belongs to whom" has to be kept
/// here: each distinct client address gets its own socket, and a datagram
/// arriving back on that socket is sent to that client.
struct Flow {
    /// Connected to the guest endpoint, so replies from anywhere else are
    /// dropped by the kernel rather than forwarded to the client.
    socket: Arc<UdpSocket>,
    /// Aborted when the flow expires.
    task: tokio::task::JoinHandle<()>,
    last: Instant,
}

impl Drop for Flow {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// The relay's flow table, split out so its expiry rule is testable without a
/// clock or a guest.
#[derive(Default)]
struct Flows {
    live: BTreeMap<SocketAddr, Flow>,
}

impl Flows {
    /// Drop every flow with no traffic since `idle` ago, and report how many
    /// went. Aborting their tasks is [`Flow`]'s Drop.
    fn expire(&mut self, now: Instant, idle: Duration) -> usize {
        let before = self.live.len();
        self.live
            .retain(|_, flow| now.duration_since(flow.last) < idle);
        before - self.live.len()
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.live.len()
    }
}

/// Carry datagrams between the host port and the guest, one flow per client.
async fn udp_forward(socket: UdpSocket, target: SocketAddr, idle: Duration, sweep: Duration) {
    let host = Arc::new(socket);
    let mut flows = Flows::default();
    let mut buf = vec![0u8; UDP_DATAGRAM];
    let mut sweeper = tokio::time::interval(sweep);
    // The first tick of an interval completes immediately; that tick would
    // expire nothing, but skipping it keeps the loop honest about its period.
    sweeper.tick().await;
    loop {
        tokio::select! {
            received = host.recv_from(&mut buf) => {
                let Ok((len, client)) = received else { return };
                if let Err(error) = relay_out(&mut flows, &host, client, target, &buf[..len]).await {
                    // One unreachable guest must not take the listener down:
                    // the guest may simply not be listening yet.
                    let _ = error;
                }
            }
            _ = sweeper.tick() => {
                flows.expire(Instant::now(), idle);
            }
        }
    }
}

/// Send one datagram guestwards, opening this client's flow if it is new.
async fn relay_out(
    flows: &mut Flows,
    host: &Arc<UdpSocket>,
    client: SocketAddr,
    target: SocketAddr,
    datagram: &[u8],
) -> Result<()> {
    let now = Instant::now();
    if let Some(flow) = flows.live.get_mut(&client) {
        if !flow.task.is_finished() {
            flow.last = now;
            flow.socket.send(datagram).await?;
            return Ok(());
        }
        flows.live.remove(&client);
    }

    // Ephemeral and *unspecified*, then connected to the guest: the kernel
    // picks a source address that can reach it and does the demultiplexing
    // this relay would otherwise have to do by hand.
    //
    // Not [`BIND`]. The host end of a published endpoint is loopback, but the
    // guest end is on a NAT or a TAP, and a socket bound to 127.0.0.1 has no
    // route to either — the datagram leaves and never arrives, which is
    // exactly as quiet as UDP always is about that.
    let socket = Arc::new(
        UdpSocket::bind(unspecified_for(target))
            .await
            .context("opening a UDP flow")?,
    );
    socket
        .connect(target)
        .await
        .with_context(|| format!("pointing a UDP flow at {target}"))?;
    let task = tokio::spawn(relay_back(socket.clone(), host.clone(), client));
    socket.send(datagram).await?;
    flows.live.insert(
        client,
        Flow {
            socket,
            task,
            last: now,
        },
    );
    Ok(())
}

/// The wildcard address of `target`'s family, port zero.
fn unspecified_for(target: SocketAddr) -> SocketAddr {
    match target {
        SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED), 0),
    }
}

/// Carry the guest's replies on one flow back to the client that opened it.
async fn relay_back(flow: Arc<UdpSocket>, host: Arc<UdpSocket>, client: SocketAddr) {
    let mut buf = vec![0u8; UDP_DATAGRAM];
    loop {
        let Ok(len) = flow.recv(&mut buf).await else {
            return;
        };
        if host.send_to(&buf[..len], client).await.is_err() {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use asterism_core::hv::{ControlChannel, Handle, Machine};
    use asterism_core::instance::Shape;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn mapping(host: u16, guest: u16, protocol: PortProtocol) -> PortForward {
        PortForward {
            host,
            guest,
            protocol,
        }
    }

    fn instance(name: &str, publish: Vec<PortForward>) -> Instance {
        let mut inst = Instance::new(
            name,
            "dev",
            "nginx:alpine",
            Shape::default(),
            Machine {
                backend: "vz".into(),
                machine_type: "virt".into(),
                cpu: "host".into(),
                hv_version: "0".into(),
            },
        );
        inst.image_kind = ImageKind::OciRootfs;
        inst.publish = publish;
        inst.status = Status::Stopped;
        inst
    }

    fn running(mut inst: Instance, endpoint: GuestEndpoint) -> Instance {
        inst.status = Status::Running;
        inst.handle = Some(Handle {
            backend: "vz".into(),
            pid: None,
            proc: None,
            ctl: ControlChannel::Helper {
                path: "/tmp/helper.sock".into(),
            },
            endpoint: Some(endpoint),
            container_control: None,
            started_at: 0,
        });
        inst
    }

    #[test]
    fn the_same_host_port_may_be_published_once_per_transport() {
        validate(
            &[
                mapping(8080, 80, PortProtocol::Tcp),
                mapping(8080, 80, PortProtocol::Udp),
            ],
            ImageKind::OciRootfs,
        )
        .expect("tcp and udp have separate host port spaces");

        let error = validate(
            &[
                mapping(8080, 80, PortProtocol::Tcp),
                mapping(8080, 8080, PortProtocol::Tcp),
            ],
            ImageKind::OciRootfs,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("published more than once"), "{error}");
    }

    #[test]
    fn the_guest_control_port_is_not_a_service_endpoint() {
        let error = validate(
            &[mapping(9000, PRIVATE_GUEST_PORT, PortProtocol::Tcp)],
            ImageKind::OciRootfs,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("guest-control endpoint"), "{error}");

        // A cloud image has no injected agent on that port, and the number is
        // an ordinary one there.
        validate(
            &[mapping(9000, PRIVATE_GUEST_PORT, PortProtocol::Tcp)],
            ImageKind::Disk,
        )
        .expect("a cloud image's 1023 is nobody's control plane");
    }

    #[test]
    fn publication_waits_for_an_address_and_ignores_qemus_own_forwards() {
        let declared = vec![mapping(8080, 80, PortProtocol::Tcp)];
        // Declared, not running: nothing to point at yet.
        assert_eq!(guest_address(&instance("web", declared.clone())), None);

        // Running, but the endpoint is a forward QEMU already bound.
        let qemu = running(
            instance("web", declared.clone()),
            GuestEndpoint::HostForwardControl {
                ssh_port: 22022,
                control_port: 22023,
            },
        );
        assert_eq!(
            guest_address(&qemu),
            None,
            "qemu publishes its own declaration in the VMM"
        );

        // Running on a backend that hands the guest an address.
        let native = running(
            instance("web", declared),
            GuestEndpoint::GuestAddr {
                addr: "192.168.64.7".parse().unwrap(),
            },
        );
        assert_eq!(
            guest_address(&native),
            Some("192.168.64.7".parse::<IpAddr>().unwrap())
        );
    }

    #[tokio::test]
    async fn a_taken_host_port_is_refused_rather_than_moved() {
        let held = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = held.local_addr().unwrap().port();

        let error = claim(&mapping(port, 80, PortProtocol::Tcp))
            .unwrap_err()
            .to_string();
        assert!(
            error.contains(&format!("127.0.0.1:{port}")),
            "the refusal names the port it could not have: {error}"
        );
    }

    /// The declaration is the endpoint across a restart: a fresh table
    /// rebuilt from the same registry row reclaims exactly the recorded port.
    ///
    /// Multi-thread, like `astd`'s own runtime: reclaiming a port this
    /// process just aborted a listener on needs the runtime to be able to
    /// retire that task while the rebind waits.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_declaration_is_recovered_on_exactly_its_own_port() {
        // Stand in for the guest.
        let guest = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let guest_port = guest.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = guest.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 16];
                    let n = stream.read(&mut buf).await.unwrap_or(0);
                    let _ = stream.write_all(&buf[..n]).await;
                });
            }
        });

        let host_port = free_tcp_port();
        let inst = running(
            instance(
                "recovered",
                vec![mapping(host_port, guest_port, PortProtocol::Tcp)],
            ),
            GuestEndpoint::GuestAddr {
                addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            },
        );

        ensure(&inst).expect("first publication");
        assert_eq!(
            published_ports("recovered"),
            Some(vec![mapping(host_port, guest_port, PortProtocol::Tcp)])
        );
        assert_eq!(echo_tcp(host_port, b"one").await, b"one");

        // A daemon restart: the table is gone, the registry row is not.
        retire("recovered");
        ensure(&inst).expect("recovery on the declared port");
        assert_eq!(
            echo_tcp(host_port, b"two").await,
            b"two",
            "recovery reclaimed the same endpoint"
        );

        // ...and taking the instance down frees the host port for good.
        retire("recovered");
        assert_eq!(published_ports("recovered"), None);
        // Aborting the accept loop is not instant; the bind proves it landed.
        for _ in 0..100 {
            if std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, host_port)).is_ok() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("the host port was still held after the instance was retired");
    }

    #[tokio::test]
    async fn a_udp_declaration_carries_datagrams_both_ways() {
        let guest = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let guest_port = guest.local_addr().unwrap().port();
        tokio::spawn(async move {
            let mut buf = [0u8; 64];
            while let Ok((len, from)) = guest.recv_from(&mut buf).await {
                let mut echo = b"echo:".to_vec();
                echo.extend_from_slice(&buf[..len]);
                let _ = guest.send_to(&echo, from).await;
            }
        });

        let host_port = free_udp_port();
        let inst = running(
            instance(
                "udp",
                vec![mapping(host_port, guest_port, PortProtocol::Udp)],
            ),
            GuestEndpoint::GuestAddr {
                addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            },
        );
        ensure(&inst).expect("publishing udp");

        let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        client
            .connect((Ipv4Addr::LOCALHOST, host_port))
            .await
            .unwrap();
        client.send(b"ping").await.unwrap();
        let mut buf = [0u8; 64];
        let len = tokio::time::timeout(Duration::from_secs(5), client.recv(&mut buf))
            .await
            .expect("the relay answered")
            .unwrap();
        assert_eq!(&buf[..len], b"echo:ping");
        retire("udp");
    }

    #[tokio::test]
    async fn an_idle_udp_flow_expires_and_a_busy_one_does_not() {
        let guest = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let target = guest.local_addr().unwrap();
        let host = Arc::new(UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap());

        let mut flows = Flows::default();
        let idle = Instant::now();
        relay_out(
            &mut flows,
            &host,
            "127.0.0.1:40000".parse().unwrap(),
            target,
            b"a",
        )
        .await
        .unwrap();
        assert_eq!(flows.len(), 1);

        // Nothing has expired while the flow is inside its idle window.
        assert_eq!(flows.expire(idle + Duration::from_secs(1), UDP_IDLE), 0);
        assert_eq!(flows.len(), 1);

        // A second datagram is the same flow, not a second one, and it
        // renews the clock.
        relay_out(
            &mut flows,
            &host,
            "127.0.0.1:40000".parse().unwrap(),
            target,
            b"b",
        )
        .await
        .unwrap();
        assert_eq!(flows.len(), 1, "one client is one flow");

        // A different client is a flow of its own.
        relay_out(
            &mut flows,
            &host,
            "127.0.0.1:40001".parse().unwrap(),
            target,
            b"c",
        )
        .await
        .unwrap();
        assert_eq!(flows.len(), 2);

        assert_eq!(
            flows.expire(Instant::now() + UDP_IDLE + Duration::from_secs(1), UDP_IDLE),
            2,
            "both flows are past their idle window"
        );
        assert_eq!(flows.len(), 0);
    }

    /// A UDP flow's own socket must be able to reach the guest.
    ///
    /// It cannot be bound on [`BIND`], however natural that looks beside the
    /// listener that accepted the datagram: the host end of a published
    /// endpoint is loopback and the guest end is on a NAT or a TAP, and a
    /// socket bound to 127.0.0.1 has no route to either. The datagram leaves
    /// and never arrives — as quiet a failure as UDP always gives. This was a
    /// real bug, caught only by a real guest, because every loopback fixture
    /// in this file would pass either way.
    #[test]
    fn a_udp_flow_binds_a_source_address_that_can_reach_the_guest() {
        let v4: SocketAddr = "192.168.64.29:7777".parse().unwrap();
        assert!(
            unspecified_for(v4).ip().is_unspecified(),
            "a flow to a guest on a NAT must not be pinned to loopback"
        );
        assert!(unspecified_for(v4).is_ipv4());

        let v6: SocketAddr = "[fd00::1]:7777".parse().unwrap();
        assert!(unspecified_for(v6).ip().is_unspecified());
        assert!(
            unspecified_for(v6).is_ipv6(),
            "the flow socket has to be of the target's own family"
        );
    }

    #[tokio::test]
    async fn nothing_is_published_for_an_instance_that_declares_nothing() {
        let inst = running(
            instance("bare", Vec::new()),
            GuestEndpoint::GuestAddr {
                addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            },
        );
        ensure(&inst).expect("an empty declaration is not an error");
        assert_eq!(published_ports("bare"), None);
    }

    // ---- helpers ----

    fn free_tcp_port() -> u16 {
        let probe = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        probe.local_addr().unwrap().port()
    }

    fn free_udp_port() -> u16 {
        let probe = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        probe.local_addr().unwrap().port()
    }

    async fn echo_tcp(port: u16, payload: &[u8]) -> Vec<u8> {
        let mut stream = tokio::time::timeout(
            Duration::from_secs(5),
            TcpStream::connect((Ipv4Addr::LOCALHOST, port)),
        )
        .await
        .expect("connecting to the published endpoint")
        .expect("the published endpoint accepted");
        stream.write_all(payload).await.unwrap();
        let mut buf = vec![0u8; payload.len()];
        stream.read_exact(&mut buf).await.unwrap();
        buf
    }
}
