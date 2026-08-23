//! The mesh endpoint: an iroh endpoint bound to this device's key.
//!
//! Every `astd` process brings up exactly one [`MeshEndpoint`]. Peers are dialed
//! by [`DeviceId`] (which is their public key), one QUIC connection per peer,
//! and each unit of work — a control RPC, an NBD attachment, a migration
//! stream, a proxied ssh channel — gets its own bidirectional stream on that
//! connection. That mapping is the whole reason the roadmap chose iroh over an
//! IP-level overlay: we want authenticated streams, not a subnet.
//!
//! # Modes
//!
//! [`MeshMode::Discovery`] is the default and the one a user gets: relays for
//! the cases hole punching cannot solve, and pkarr/DNS address lookup so a
//! device that changed networks is still findable by its key. Two machines on
//! different networks, behind different NATs, with no port forwarded, can pair
//! and talk. [`MeshMode::LocalOnly`] is loopback and nothing else — the tests
//! use it, and it is the roadmap's "bring your own route" case.
//!
//! # Whose infrastructure
//!
//! Discovery mode currently rides **n0's public infrastructure**: their relay
//! fleet (`*.relay.n0.iroh.link`) and their pkarr/DNS server (`dns.iroh.link`,
//! zone `iroh.link`). That is the Phase 2 bootstrap, not the destination —
//! `docs/ROADMAP.md` Phase 2 specifies relays and a device directory we run,
//! and Layer 2's coordination plane replaces the directory half outright.
//!
//! So the choice is a seam rather than a constant. [`MeshInfra`] names the
//! three pieces that will move, each overridable today by an environment
//! variable and later by whatever `ast config set` writes:
//!
//! | variable               | replaces                   | default                          |
//! |------------------------|----------------------------|----------------------------------|
//! | `ASTERISM_RELAY_URL`   | n0's relay fleet           | n0 production relays             |
//! | `ASTERISM_PKARR_RELAY` | n0's pkarr publish/resolve | `https://dns.iroh.link/pkarr`    |
//! | `ASTERISM_DNS_ORIGIN`  | n0's DNS lookup zone       | `dns.iroh.link.`                 |
//!
//! `ASTERISM_RELAY_URL` takes a comma-separated list. Setting any of the three
//! puts the endpoint on the explicit path — same code, different servers —
//! which is the property that lets `astrelay` and the hosted directory land
//! without touching a call site.
//!
//! # Privacy
//!
//! Discovery is not free of disclosure and the default should not pretend
//! otherwise. Under [`MeshMode::Discovery`] this device **publishes its public
//! key together with its current addresses** — LAN addresses, the public
//! address a NAT gives it, and its home relay — to the configured pkarr
//! server, where anyone who knows the key can read them. The record is signed
//! by the device key and carries no instance data, no names, and nothing that
//! decrypts orbit traffic; relays forward ciphertext they cannot read. But the
//! existence of the device, and roughly where on the internet it sits, is
//! public to anyone holding its public key.
//!
//! `ASTERISM_MESH=local` is the opt-out: no relay, no publication, no packet
//! that leaves the host. It is a real mode rather than a test-only flag
//! precisely so that "I already have a route and want no third party in it" is
//! an answer this daemon can give.

use std::fmt;
use std::time::Duration;

use iroh::address_lookup::{DnsAddressLookup, PkarrPublisher, PkarrResolver};
use iroh::endpoint::{presets, Connection, RecvStream, SendStream};
use iroh::{Endpoint, EndpointAddr, RelayMode, RelayUrl, TransportAddr};

use crate::identity::{DeviceId, DeviceIdentity};

/// The ALPN protocol identifier for the Asterism mesh.
///
/// The trailing number is the mesh wire version. A device that speaks only
/// `asterism/0` and one that speaks only `asterism/1` will fail to negotiate a
/// connection rather than misunderstand each other, which is the intent.
pub const ALPN: &[u8] = b"asterism/0";

/// How long [`MeshEndpoint::direct_addr`] waits for the endpoint to discover at
/// least one address it can advertise.
const ADDR_TIMEOUT: Duration = Duration::from_secs(10);

/// How long [`MeshEndpoint::direct_addr`] waits, under
/// [`MeshMode::Discovery`], for a home relay before handing out an address.
///
/// An address with no relay in it is a worse ticket: the peer redeeming it can
/// only reach this device if it can reach one of its IP addresses, which is
/// exactly the assumption discovery mode exists to drop. Waiting is bounded
/// because a machine with no WAN must still be able to print a ticket for the
/// device on the desk next to it.
const RELAY_TIMEOUT: Duration = Duration::from_secs(10);

/// Overrides the relay servers. Comma-separated URLs.
pub const RELAY_ENV: &str = "ASTERISM_RELAY_URL";
/// Overrides the pkarr server addresses are published to and resolved from.
pub const PKARR_ENV: &str = "ASTERISM_PKARR_RELAY";
/// Overrides the DNS zone peer addresses are looked up in.
pub const DNS_ORIGIN_ENV: &str = "ASTERISM_DNS_ORIGIN";

/// Test seam: advertise relay hints only, as if this device's IP addresses
/// were unreachable from everywhere else. See [`MeshEndpoint::direct_addr`].
pub const NO_DIRECT_ENV: &str = "ASTERISM_MESH_NO_DIRECT";

/// How an endpoint reaches the rest of the world.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum MeshMode {
    /// The normal mode, and the default: relay servers plus DNS/pkarr address
    /// lookup, so a device is reachable from behind a NAT with no port
    /// forwarding and findable after it changes networks.
    ///
    /// **This publishes this device's public key and current addresses to a
    /// public discovery service** — n0's, unless [`MeshInfra`] says otherwise.
    /// See this module's privacy note.
    #[default]
    Discovery,
    /// Loopback only: no relays, no discovery, no traffic that leaves the host.
    ///
    /// Peers must be dialed with explicit addresses — which is exactly what a
    /// [`PairingTicket`] carries. Used by the tests and by `pair_demo`, and it
    /// doubles as the "bring your own route" case from the roadmap, where a
    /// user already has a working path and wants no third party involved.
    ///
    /// [`PairingTicket`]: crate::ticket::PairingTicket
    LocalOnly,
}

/// Which relay and discovery servers [`MeshMode::Discovery`] uses.
///
/// The default is n0's public infrastructure, which is the Phase 2 bootstrap.
/// Every field is an override, and the point of the type is that the override
/// is a value passed to [`MeshEndpoint::bind_with`] rather than a constant
/// compiled in — when the hosted coordination plane exists, it supplies one of
/// these and no call site changes. Today the values come from the environment;
/// see the module docs for the variable names.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MeshInfra {
    /// Relay servers, replacing n0's fleet. Empty means n0's.
    pub relays: Vec<String>,
    /// The pkarr server this device publishes its addresses to and resolves
    /// peers from. `None` means n0's.
    pub pkarr_relay: Option<String>,
    /// The DNS zone peer addresses are looked up in. `None` means n0's.
    pub dns_origin: Option<String>,
}

impl MeshInfra {
    /// Reads the overrides from the environment.
    pub fn from_env() -> Self {
        let relays = std::env::var(RELAY_ENV)
            .ok()
            .map(|raw| {
                raw.split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default();
        Self {
            relays,
            pkarr_relay: non_empty(PKARR_ENV),
            dns_origin: non_empty(DNS_ORIGIN_ENV),
        }
    }

    /// Whether this is stock n0 infrastructure, i.e. nothing was overridden.
    pub fn is_n0(&self) -> bool {
        self.relays.is_empty() && self.pkarr_relay.is_none() && self.dns_origin.is_none()
    }

    /// A one-line summary for a startup log, so a user can see whose servers
    /// their device is about to talk to without reading the source.
    pub fn describe(&self) -> String {
        if self.is_n0() {
            return "n0 public infrastructure (relays + dns.iroh.link)".to_owned();
        }
        let relays = if self.relays.is_empty() {
            "n0 relays".to_owned()
        } else {
            self.relays.join(",")
        };
        let lookup = match (&self.pkarr_relay, &self.dns_origin) {
            (None, None) => "n0 dns".to_owned(),
            (pkarr, dns) => format!(
                "pkarr {} / dns {}",
                pkarr.as_deref().unwrap_or("n0"),
                dns.as_deref().unwrap_or("n0")
            ),
        };
        format!("{relays} + {lookup}")
    }
}

fn non_empty(var: &str) -> Option<String> {
    std::env::var(var)
        .ok()
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
}

/// Whether the advertised address should hide this device's IP addresses.
fn hide_direct_addrs() -> bool {
    matches!(
        std::env::var(NO_DIRECT_ENV).as_deref(),
        Ok("1") | Ok("true")
    )
}

/// How a connection's bytes are actually travelling right now.
///
/// Reported by `ast devices` and `ast ping`, and it has to be the truth rather
/// than an assumption: "direct" printed next to a relayed connection would
/// hide exactly the case a user needs to know about, because that is the one
/// with someone else's bandwidth and latency in it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathKind {
    /// Packets go straight to the peer, over a LAN address or a hole punched
    /// through both NATs.
    Direct,
    /// Packets go through a relay, which forwards ciphertext it cannot read.
    Relay,
}

impl PathKind {
    /// The word `ast devices` prints.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::Relay => "relay",
        }
    }
}

impl fmt::Display for PathKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// An iroh endpoint bound to this device's identity, speaking [`ALPN`].
#[derive(Debug, Clone)]
pub struct MeshEndpoint {
    endpoint: Endpoint,
    device_id: DeviceId,
    mode: MeshMode,
    infra: MeshInfra,
}

impl MeshEndpoint {
    /// Binds an endpoint to `identity`, taking any infrastructure overrides
    /// from the environment.
    pub async fn bind(identity: &DeviceIdentity, mode: MeshMode) -> anyhow::Result<Self> {
        Self::bind_with(identity, mode, MeshInfra::from_env()).await
    }

    /// Binds an endpoint to `identity` against explicitly chosen relay and
    /// discovery servers.
    ///
    /// `infra` is ignored under [`MeshMode::LocalOnly`], which by definition
    /// has no servers to point at.
    pub async fn bind_with(
        identity: &DeviceIdentity,
        mode: MeshMode,
        infra: MeshInfra,
    ) -> anyhow::Result<Self> {
        let endpoint = match mode {
            MeshMode::Discovery => discovery_endpoint(identity, &infra).await?,
            // `presets::Minimal` sets only the mandatory crypto provider, so
            // the LocalOnly path adds nothing that talks to the network.
            MeshMode::LocalOnly => {
                Endpoint::builder(presets::Minimal)
                    .secret_key(identity.secret_key().clone())
                    .alpns(vec![ALPN.to_vec()])
                    .relay_mode(RelayMode::Disabled)
                    .clear_ip_transports()
                    .bind_addr("127.0.0.1:0")?
                    .bind()
                    .await?
            }
        };

        Ok(Self {
            device_id: identity.device_id(),
            endpoint,
            mode,
            infra: match mode {
                MeshMode::Discovery => infra,
                MeshMode::LocalOnly => MeshInfra::default(),
            },
        })
    }

    /// This device's id, i.e. the public key the endpoint is bound to.
    pub fn device_id(&self) -> DeviceId {
        self.device_id
    }

    /// The mode this endpoint was bound in.
    pub fn mode(&self) -> MeshMode {
        self.mode
    }

    /// Whose relay and discovery servers this endpoint is using.
    pub fn infra(&self) -> &MeshInfra {
        &self.infra
    }

    /// The underlying iroh endpoint, for anything this wrapper does not expose.
    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    /// This endpoint's address as currently known — id plus whatever direct
    /// addresses and relay hints have been discovered so far.
    ///
    /// Immediately after [`bind`](Self::bind) this may still be empty; use
    /// [`direct_addr`](Self::direct_addr) when the address is about to be
    /// handed to someone else.
    pub fn addr(&self) -> EndpointAddr {
        self.endpoint.addr()
    }

    /// Waits, up to `within`, for the endpoint to be connected to a relay.
    ///
    /// Returns whether it got there. Always true under
    /// [`MeshMode::LocalOnly`], which has no relay to wait for and is
    /// reachable the moment it is bound.
    ///
    /// This is also the moment the device's addresses are first published to
    /// discovery: iroh's pkarr publisher republishes whenever the endpoint's
    /// address changes, and a home relay is the last piece of that address to
    /// arrive.
    pub async fn online(&self, within: Duration) -> bool {
        if self.mode == MeshMode::LocalOnly {
            return true;
        }
        tokio::time::timeout(within, self.endpoint.online())
            .await
            .is_ok()
    }

    /// The relays this endpoint currently holds a connection to.
    ///
    /// Empty under [`MeshMode::LocalOnly`], and empty under
    /// [`MeshMode::Discovery`] until the endpoint has finished picking one.
    pub fn home_relays(&self) -> Vec<String> {
        use iroh::Watcher;

        self.endpoint
            .home_relay_status()
            .get()
            .iter()
            .filter(|status| status.is_connected())
            .map(|status| status.url().to_string())
            .collect()
    }

    /// Waits until the endpoint knows at least one address it can be reached
    /// on, then returns it.
    ///
    /// This is what goes into a pairing ticket, and what a device tells a peer
    /// about itself when they pair. Under [`MeshMode::Discovery`] it first
    /// waits — briefly, see [`RELAY_TIMEOUT`] — for a home relay, because an
    /// address with no relay in it is only redeemable by someone who can reach
    /// one of this device's IP addresses, and that is the assumption discovery
    /// mode exists to drop.
    ///
    /// With [`NO_DIRECT_ENV`] set, the returned address carries relay hints
    /// only. That is a test seam: on one machine every endpoint can reach every
    /// other one's loopback address, so hiding them is the closest a single
    /// host gets to "these two devices are on networks that cannot see each
    /// other". It is ignored under [`MeshMode::LocalOnly`], where it would only
    /// produce an address nobody can use.
    pub async fn direct_addr(&self) -> anyhow::Result<EndpointAddr> {
        use iroh::Watcher;

        if self.mode == MeshMode::Discovery {
            // Best effort: a device with no WAN still has to be able to print
            // a ticket for the machine next to it.
            self.online(RELAY_TIMEOUT).await;
        }

        let mut watcher = self.endpoint.watch_addr();
        let wait = async {
            loop {
                let addr = watcher.get();
                if !addr.is_empty() {
                    return Ok::<_, anyhow::Error>(addr);
                }
                watcher.updated().await?;
            }
        };

        let addr = tokio::time::timeout(ADDR_TIMEOUT, wait)
            .await
            .map_err(|_| {
                anyhow::anyhow!("endpoint found no reachable address within {ADDR_TIMEOUT:?}")
            })??;

        Ok(self.maybe_hide_direct(addr))
    }

    /// Applies [`NO_DIRECT_ENV`], if it is set and there is a relay left to
    /// reach this device by.
    fn maybe_hide_direct(&self, addr: EndpointAddr) -> EndpointAddr {
        if self.mode != MeshMode::Discovery || !hide_direct_addrs() {
            return addr;
        }
        let relays: Vec<RelayUrl> = addr.relay_urls().cloned().collect();
        if relays.is_empty() {
            // Stripping the IPs here would leave an address with nothing in
            // it, which is not a simulation of anything.
            return addr;
        }
        EndpointAddr::from_parts(addr.id, relays.into_iter().map(TransportAddr::Relay))
    }

    /// The addresses discovery and this endpoint's own probing currently
    /// believe `peer` is on.
    ///
    /// This is how the orbit store's address hints stay fresh: after a
    /// connection succeeds, whatever it succeeded through is worth writing
    /// down. `None` when the endpoint has never heard of the peer.
    pub async fn peer_addr(&self, peer: DeviceId) -> Option<EndpointAddr> {
        let info = self.endpoint.remote_info(peer.public_key()).await?;
        let addr = EndpointAddr::from_parts(info.id(), info.into_addrs().map(|a| a.into_addr()));
        (!addr.is_empty()).then_some(addr)
    }

    /// Dials a peer.
    ///
    /// `addr` may be a bare [`DeviceId`]/[`PublicKey`] — which requires
    /// discovery to be able to find it — or a full [`EndpointAddr`] carrying
    /// direct addresses and relay hints, as a pairing ticket provides.
    ///
    /// [`PublicKey`]: iroh::PublicKey
    pub async fn connect(&self, addr: impl Into<EndpointAddr>) -> anyhow::Result<MeshConnection> {
        let conn = self.endpoint.connect(addr, ALPN).await?;
        Ok(MeshConnection { conn })
    }

    /// Dials a peer by key alone, forcing the address to come from discovery.
    ///
    /// The stored hints are deliberately not consulted. That is the point: a
    /// peer whose daemon restarted on a new network is on addresses nobody
    /// wrote down, and asking discovery is the only way to learn them. Fails
    /// immediately under [`MeshMode::LocalOnly`], which has no discovery to
    /// ask.
    pub async fn connect_by_id(&self, peer: DeviceId) -> anyhow::Result<MeshConnection> {
        if self.mode == MeshMode::LocalOnly {
            anyhow::bail!(
                "this device's mesh is in local mode, so a peer can only be reached at an \
                 address already on file (unset ASTERISM_MESH to use discovery)"
            );
        }
        self.connect(EndpointAddr::new(peer.public_key())).await
    }

    /// Accepts the next inbound connection, or `None` once the endpoint closes.
    ///
    /// The connection is authenticated by the time this returns: QUIC's TLS
    /// handshake proved the peer holds the private key for
    /// [`MeshConnection::remote_device_id`]. Whether that key is *trusted* is a
    /// separate question, answered against the orbit's device set.
    pub async fn accept(&self) -> Option<anyhow::Result<MeshConnection>> {
        let incoming = self.endpoint.accept().await?;
        Some(match incoming.await {
            Ok(conn) => Ok(MeshConnection { conn }),
            Err(e) => Err(e.into()),
        })
    }

    /// Closes the endpoint and every connection on it.
    pub async fn close(&self) {
        self.endpoint.close().await;
    }
}

/// Builds the discovery-mode endpoint: relays plus address publication and
/// lookup.
///
/// Stock n0 infrastructure goes through `presets::N0` verbatim rather than
/// through a hand-rolled equivalent, so a change to n0's defaults reaches us
/// the way iroh intended. Any override drops to the explicit path, which
/// assembles the same three services against whichever servers were named.
async fn discovery_endpoint(
    identity: &DeviceIdentity,
    infra: &MeshInfra,
) -> anyhow::Result<Endpoint> {
    if infra.is_n0() {
        let mut builder = Endpoint::builder(presets::N0)
            .secret_key(identity.secret_key().clone())
            .alpns(vec![ALPN.to_vec()]);
        if hide_direct_addrs() {
            builder = builder.clear_ip_transports();
        }
        return Ok(builder.bind().await?);
    }

    let mut builder = Endpoint::builder(presets::Minimal)
        .secret_key(identity.secret_key().clone())
        .alpns(vec![ALPN.to_vec()]);

    // pkarr: publish this device's signed address record, and resolve peers'.
    let pkarr = infra
        .pkarr_relay
        .as_deref()
        .unwrap_or(iroh::address_lookup::N0_DNS_PKARR_RELAY_PROD);
    let pkarr: RelayUrl = pkarr
        .parse()
        .map_err(|e| anyhow::anyhow!("{PKARR_ENV}={pkarr:?} is not a url: {e}"))?;
    builder = builder.address_lookup(PkarrPublisher::builder(pkarr.clone().into()));
    builder = builder.address_lookup(PkarrResolver::builder(pkarr.into()));

    // DNS: the cheaper read path for the same records.
    let origin = infra
        .dns_origin
        .clone()
        .unwrap_or_else(|| iroh::dns::N0_DNS_ENDPOINT_ORIGIN_PROD.to_owned());
    builder = builder.address_lookup(DnsAddressLookup::builder(origin));

    if !infra.relays.is_empty() {
        let mut urls = Vec::with_capacity(infra.relays.len());
        for relay in &infra.relays {
            urls.push(
                relay.parse::<RelayUrl>().map_err(|e| {
                    anyhow::anyhow!("{RELAY_ENV} entry {relay:?} is not a url: {e}")
                })?,
            );
        }
        builder = builder.relay_mode(RelayMode::custom(urls));
    }
    if hide_direct_addrs() {
        builder = builder.clear_ip_transports();
    }

    Ok(builder.bind().await?)
}

/// An authenticated connection to one peer device.
#[derive(Debug, Clone)]
pub struct MeshConnection {
    conn: Connection,
}

impl MeshConnection {
    /// The peer's device id, proven by the QUIC handshake.
    pub fn remote_device_id(&self) -> DeviceId {
        DeviceId::from_public_key(self.conn.remote_id())
    }

    /// Whether this connection's bytes are going direct or through a relay,
    /// right now.
    ///
    /// A QUIC connection in iroh can hold several paths at once — typically a
    /// relay path that came up first and a direct one that hole punching found
    /// afterwards — and exactly one of them is *selected* for application
    /// data. That selected path is the answer, because it is the one the next
    /// byte will take.
    ///
    /// `None` only in the moment before any path is open, which for a
    /// connection that has already carried a request does not happen.
    pub fn path(&self) -> Option<PathKind> {
        let paths = self.conn.paths();
        if let Some(selected) = paths.iter().find(|path| path.is_selected()) {
            return Some(kind_of(selected.remote_addr()));
        }
        // Nothing selected yet: report the best open path rather than nothing,
        // and prefer the honest pessimism of "relay" only when relay is all
        // there is.
        let mut fallback = None;
        for path in paths.iter() {
            match kind_of(path.remote_addr()) {
                PathKind::Direct => return Some(PathKind::Direct),
                PathKind::Relay => fallback = Some(PathKind::Relay),
            }
        }
        fallback
    }

    /// The selected path and its transport RTT estimate.
    ///
    /// Unlike [`Self::path`], this does not invent a fallback before iroh has
    /// selected a transmission path: an RTT only means something for the path
    /// carrying the bytes whose acknowledgements produced it.
    pub fn selected_path_rtt(&self) -> Option<(PathKind, Duration)> {
        let paths = self.conn.paths();
        paths
            .iter()
            .find(|path| path.is_selected())
            .map(|path| (kind_of(path.remote_addr()), path.rtt()))
    }

    /// Opens a new bidirectional stream to the peer.
    ///
    /// iroh, like QUIC generally, does not tell the peer a stream exists until
    /// something is written to it, so the accepting side will not see this
    /// stream until the first bytes are sent.
    pub async fn open_stream(&self) -> anyhow::Result<MeshStream> {
        let (send, recv) = self.conn.open_bi().await?;
        Ok(MeshStream { send, recv })
    }

    /// Accepts the next bidirectional stream the peer opens.
    pub async fn accept_stream(&self) -> anyhow::Result<MeshStream> {
        let (send, recv) = self.conn.accept_bi().await?;
        Ok(MeshStream { send, recv })
    }

    /// Derives shared secret bytes from this connection's TLS session
    /// ([RFC 5705](https://www.rfc-editor.org/rfc/rfc5705)).
    ///
    /// Both peers get identical bytes; an attacker terminating two separate
    /// sessions cannot. That property is what makes the pairing SAS meaningful
    /// — see [`crate::sas`].
    pub fn export_keying_material<const N: usize>(
        &self,
        label: &[u8],
        context: &[u8],
    ) -> anyhow::Result<[u8; N]> {
        let mut out = [0u8; N];
        self.conn
            .export_keying_material(&mut out, label, context)
            // iroh 1.0.3 re-exports this error without a `Display` impl.
            .map_err(|e| anyhow::anyhow!("failed to export keying material: {e:?}"))?;
        Ok(out)
    }

    /// The underlying iroh connection.
    pub fn connection(&self) -> &Connection {
        &self.conn
    }

    /// Closes the connection with an application-level reason.
    pub fn close(&self, reason: &[u8]) {
        self.conn.close(0u32.into(), reason);
    }
}

/// Classifies one open path.
fn kind_of(addr: &TransportAddr) -> PathKind {
    if addr.is_relay() {
        PathKind::Relay
    } else {
        PathKind::Direct
    }
}

/// A bidirectional stream: one unit of work on a mesh connection.
#[derive(Debug)]
pub struct MeshStream {
    /// The write half.
    pub send: SendStream,
    /// The read half.
    pub recv: RecvStream,
}

impl MeshStream {
    /// Splits the stream into its halves, so they can move to separate tasks.
    pub fn into_parts(self) -> (SendStream, RecvStream) {
        (self.send, self.recv)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alpn_is_versioned() {
        assert_eq!(ALPN, b"asterism/0");
    }

    #[tokio::test]
    async fn an_endpoint_binds_to_the_identity_it_was_given() {
        let identity = DeviceIdentity::generate();
        let endpoint = MeshEndpoint::bind(&identity, MeshMode::LocalOnly)
            .await
            .expect("bind should succeed on loopback");

        assert_eq!(endpoint.device_id(), identity.device_id());
        assert_eq!(endpoint.addr().id, identity.public_key());
        endpoint.close().await;
    }

    #[tokio::test]
    async fn local_only_endpoints_advertise_a_loopback_address_and_no_relay() {
        let identity = DeviceIdentity::generate();
        let endpoint = MeshEndpoint::bind(&identity, MeshMode::LocalOnly)
            .await
            .unwrap();

        let addr = endpoint
            .direct_addr()
            .await
            .expect("should find an address");
        assert!(
            addr.relay_urls().next().is_none(),
            "LocalOnly must not advertise a relay: {addr:?}"
        );
        let ips: Vec<_> = addr.ip_addrs().collect();
        assert!(!ips.is_empty(), "expected at least one ip address");
        assert!(
            ips.iter().all(|a| a.ip().is_loopback()),
            "LocalOnly must stay on loopback: {ips:?}"
        );
        endpoint.close().await;
    }

    #[tokio::test]
    async fn two_endpoints_connect_and_exchange_bytes_over_a_stream() {
        let alice_id = DeviceIdentity::generate();
        let bob_id = DeviceIdentity::generate();

        let alice = MeshEndpoint::bind(&alice_id, MeshMode::LocalOnly)
            .await
            .unwrap();
        let bob = MeshEndpoint::bind(&bob_id, MeshMode::LocalOnly)
            .await
            .unwrap();
        let bob_addr = bob.direct_addr().await.unwrap();

        let alice_device_id = alice.device_id();
        let server = tokio::spawn(async move {
            let conn = bob.accept().await.expect("a connection").expect("accepted");
            assert_eq!(conn.remote_device_id(), alice_device_id);

            let mut stream = conn.accept_stream().await.unwrap();
            let got = stream.recv.read_to_end(64).await.unwrap();
            stream.send.write_all(&got).await.unwrap();
            stream.send.finish().unwrap();
            // Hold the connection open until the peer has read the echo.
            conn.connection().closed().await;
            bob
        });

        let conn = alice.connect(bob_addr).await.unwrap();
        assert_eq!(conn.remote_device_id(), bob_id.device_id());

        let mut stream = conn.open_stream().await.unwrap();
        stream.send.write_all(b"ping").await.unwrap();
        stream.send.finish().unwrap();
        let echoed = stream.recv.read_to_end(64).await.unwrap();
        assert_eq!(&echoed, b"ping");

        conn.close(b"done");
        let bob = server.await.unwrap();
        alice.close().await;
        bob.close().await;
    }

    #[tokio::test]
    async fn a_peer_speaking_a_different_alpn_is_refused() {
        let server_id = DeviceIdentity::generate();
        let client_id = DeviceIdentity::generate();

        let server = MeshEndpoint::bind(&server_id, MeshMode::LocalOnly)
            .await
            .unwrap();
        let server_addr = server.direct_addr().await.unwrap();

        let accept = tokio::spawn(async move {
            let _ = server.accept().await;
            server
        });

        // A raw iroh endpoint offering an ALPN the mesh does not speak.
        let client = Endpoint::builder(presets::Minimal)
            .secret_key(client_id.secret_key().clone())
            .relay_mode(RelayMode::Disabled)
            .clear_ip_transports()
            .bind_addr("127.0.0.1:0")
            .unwrap()
            .bind()
            .await
            .unwrap();

        let result = client.connect(server_addr, b"not-asterism/9").await;
        assert!(result.is_err(), "a foreign ALPN must not be accepted");

        client.close().await;
        accept.await.unwrap().close().await;
    }

    #[test]
    fn discovery_is_the_default_mode() {
        // The daemon's default follows this one. Changing it changes whether
        // an unconfigured device publishes to a public discovery service, so
        // it is worth a test that says so out loud.
        assert_eq!(MeshMode::default(), MeshMode::Discovery);
    }

    #[test]
    fn stock_infrastructure_is_n0_and_says_so() {
        let stock = MeshInfra::default();
        assert!(stock.is_n0());
        assert!(stock.describe().contains("n0"), "{}", stock.describe());
    }

    #[test]
    fn any_override_takes_the_endpoint_off_n0() {
        let relayed = MeshInfra {
            relays: vec!["https://relay.asterism.run.".into()],
            ..MeshInfra::default()
        };
        assert!(!relayed.is_n0());
        assert!(
            relayed.describe().contains("relay.asterism.run"),
            "{}",
            relayed.describe()
        );

        let looked_up = MeshInfra {
            pkarr_relay: Some("https://dns.asterism.run/pkarr".into()),
            ..MeshInfra::default()
        };
        assert!(!looked_up.is_n0());
        // Overriding one half leaves the other on n0 rather than turning it
        // off: a coordination plane can arrive in pieces.
        assert!(
            looked_up.describe().contains("n0 relays"),
            "{}",
            looked_up.describe()
        );
    }

    #[test]
    fn a_path_prints_the_word_the_cli_shows() {
        assert_eq!(PathKind::Direct.as_str(), "direct");
        assert_eq!(PathKind::Relay.as_str(), "relay");
        assert_eq!(PathKind::Relay.to_string(), "relay");
    }

    #[tokio::test]
    async fn a_loopback_endpoint_is_not_pointed_at_anyone_elses_servers() {
        let identity = DeviceIdentity::generate();
        // Even with overrides in the environment, LocalOnly has no servers.
        let endpoint = MeshEndpoint::bind_with(
            &identity,
            MeshMode::LocalOnly,
            MeshInfra {
                relays: vec!["https://relay.example.".into()],
                ..MeshInfra::default()
            },
        )
        .await
        .unwrap();

        assert!(endpoint.infra().is_n0());
        assert!(endpoint.home_relays().is_empty());
        assert!(endpoint.online(Duration::from_millis(1)).await);
        endpoint.close().await;
    }

    #[tokio::test]
    async fn a_loopback_connection_reports_a_direct_path() {
        // The mesh e2e asserts "direct" in `ast devices`; this is where that
        // word comes from, and it has to come from the connection rather than
        // from an assumption about the mode.
        let server_id = DeviceIdentity::generate();
        let client_id = DeviceIdentity::generate();

        let server = MeshEndpoint::bind(&server_id, MeshMode::LocalOnly)
            .await
            .unwrap();
        let client = MeshEndpoint::bind(&client_id, MeshMode::LocalOnly)
            .await
            .unwrap();
        let server_addr = server.direct_addr().await.unwrap();

        let accepting = tokio::spawn(async move {
            let conn = server.accept().await.unwrap().unwrap();
            let mut stream = conn.accept_stream().await.unwrap();
            let got = stream.recv.read_to_end(16).await.unwrap();
            stream.send.write_all(&got).await.unwrap();
            stream.send.finish().unwrap();
            let path = conn.path();
            conn.connection().closed().await;
            (server, path)
        });

        let conn = client.connect(server_addr).await.unwrap();
        let mut stream = conn.open_stream().await.unwrap();
        stream.send.write_all(b"ping").await.unwrap();
        stream.send.finish().unwrap();
        assert_eq!(stream.recv.read_to_end(16).await.unwrap(), b"ping");
        assert_eq!(conn.path(), Some(PathKind::Direct));

        conn.close(b"done");
        let (server, server_path) = accepting.await.unwrap();
        assert_eq!(server_path, Some(PathKind::Direct));
        client.close().await;
        server.close().await;
    }

    #[tokio::test]
    async fn a_misconfigured_seam_names_the_variable_that_is_wrong() {
        // The seam is set by hand today, so getting it wrong has to say which
        // hand. Both of these fail before the endpoint binds, so neither one
        // touches a network.
        let identity = DeviceIdentity::generate();

        let err = MeshEndpoint::bind_with(
            &identity,
            MeshMode::Discovery,
            MeshInfra {
                relays: vec!["relay.asterism.run".into()], // no scheme
                ..MeshInfra::default()
            },
        )
        .await
        .expect_err("an unparseable relay must not bind silently")
        .to_string();
        assert!(err.contains(RELAY_ENV), "{err}");
        assert!(err.contains("relay.asterism.run"), "{err}");

        let err = MeshEndpoint::bind_with(
            &identity,
            MeshMode::Discovery,
            MeshInfra {
                pkarr_relay: Some("dns.asterism.run/pkarr".into()),
                ..MeshInfra::default()
            },
        )
        .await
        .expect_err("an unparseable pkarr server must not bind silently")
        .to_string();
        assert!(err.contains(PKARR_ENV), "{err}");
    }

    #[tokio::test]
    async fn local_mode_refuses_to_pretend_it_can_look_a_peer_up() {
        let endpoint = MeshEndpoint::bind(&DeviceIdentity::generate(), MeshMode::LocalOnly)
            .await
            .unwrap();
        let stranger = DeviceIdentity::generate().device_id();

        let err = endpoint
            .connect_by_id(stranger)
            .await
            .expect_err("there is no discovery in local mode")
            .to_string();
        assert!(err.contains("local mode"), "{err}");
        endpoint.close().await;
    }
}
