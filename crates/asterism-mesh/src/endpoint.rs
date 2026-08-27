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
//! [`MeshMode::LocalOnly`] is **the default**: loopback and nothing else, no
//! relay, no directory, no packet that leaves the host. A fresh install is in
//! it, and it is a real mode rather than a test-only flag — it is the
//! roadmap's "bring your own route" case, and the answer to "I already have a
//! path between these machines and want no third party in it".
//!
//! [`MeshMode::Discovery`] is what a device gets once it has somewhere to go:
//! relays for the cases hole punching cannot solve, and pkarr/DNS address
//! lookup so a device that changed networks is still findable by its key. Two
//! machines on different networks, behind different NATs, with no port
//! forwarded, can pair and talk.
//!
//! # Whose infrastructure — nobody's, until you say
//!
//! There is **no default relay fleet and no default directory**. Discovery
//! needs servers, and this crate compiles none in: the three fields of
//! [`MeshInfra`] are empty until something fills them, and an endpoint asked
//! for discovery with an empty `MeshInfra` binds local-only instead.
//!
//! Two things fill them.
//!
//! * **Logging in.** The hosted coordination plane answers "which relays does
//!   this account use, and where is its device directory", and the answer
//!   becomes a [`MeshInfra`] via [`MeshInfra::with_hosted`]. Cross-network
//!   connectivity is a thing an account has, not a thing an installer takes.
//! * **Configuring it yourself.** Three environment variables, and whatever
//!   `ast config set relay` writes. This is the self-hosting path, and it is
//!   first class: `astrelay` is in this repository under the same licence as
//!   everything else.
//!
//! | variable               | sets                        | unset means           |
//! |------------------------|-----------------------------|-----------------------|
//! | `ASTERISM_RELAY_URL`   | relay servers, in order     | no relay              |
//! | `ASTERISM_PKARR_RELAY` | pkarr publish/resolve       | publish nothing       |
//! | `ASTERISM_DNS_ORIGIN`  | DNS lookup zone             | no DNS lookup         |
//!
//! `ASTERISM_RELAY_URL` takes a comma-separated list, first preferred. The
//! environment wins over what a coordinator supplied — see
//! [`MeshInfra::with_env_overrides`] — because that is how someone points a
//! device at their own relay when the coordinator is wrong, unreachable, or
//! not theirs.
//!
//! Earlier builds rode n0's public infrastructure (`*.relay.n0.iroh.link`,
//! `dns.iroh.link`) by default. That was the Phase 2 bootstrap and it is gone:
//! it meant an unconfigured device published its key and its addresses to a
//! public directory run by strangers as a side effect of being installed.
//!
//! # Privacy
//!
//! Discovery is not free of disclosure and nothing here should pretend
//! otherwise. With a pkarr server configured, this device **publishes its
//! public key together with its current addresses** — LAN addresses, the
//! public address a NAT gives it, and its home relay — where anyone who knows
//! the key can read them. The record is signed by the device key and carries
//! no instance data, no names, and nothing that decrypts orbit traffic; relays
//! forward ciphertext they cannot read. But the existence of the device, and
//! roughly where on the internet it sits, is legible to anyone holding its
//! public key.
//!
//! What changed is who chooses. That disclosure now follows from logging in or
//! from setting a variable, and a device that has done neither publishes
//! nothing, anywhere, to anyone.

use std::fmt;
use std::net::SocketAddr;
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

/// Forces every byte through a relay by removing this endpoint's IP transports
/// outright.
///
/// [`NO_DIRECT_ENV`] only hides the addresses this device *advertises*; the
/// peer can still reach it on an address it discovered by other means, and
/// iroh will happily upgrade to the direct path it finds. This one is the
/// stronger statement: with no IP transport bound there is no direct path for
/// iroh to select, so the relayed byte counters are the only ones that can
/// move. That is what makes a single-host relay metering proof mean anything.
///
/// Ignored under [`MeshMode::LocalOnly`], which has no relay to fall back to.
pub const RELAY_ONLY_ENV: &str = "ASTERISM_MESH_RELAY_ONLY";

/// Turns off the UPnP / NAT-PMP / PCP port mapping client.
///
/// **Port mapping is on by default**, and has been since before this variable
/// existed: iroh enables its `portmapper` feature in its default feature set,
/// and `PortmapperConfig::default()` is `Enabled`. That is inherited rather
/// than chosen, so it is worth stating plainly. What it does is ask the local
/// router, over three protocols, to forward a port back to this device — which
/// buys direct connectivity behind NATs that would otherwise force every byte
/// through a relay, and therefore directly reduces what a relay operator pays.
///
/// Its cost is a little SSDP multicast on the LAN and, on macOS, a firewall
/// dialog the first time. Setting this variable is the opt-out for anyone who
/// would rather relay than let the daemon talk to their router. It does not
/// change the default; it declines it.
pub const NO_PORTMAP_ENV: &str = "ASTERISM_MESH_NO_PORTMAP";

/// How an endpoint reaches the rest of the world.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum MeshMode {
    /// Relay servers plus DNS/pkarr address lookup, so a device is reachable
    /// from behind a NAT with no port forwarding and findable after it changes
    /// networks.
    ///
    /// **This publishes this device's public key and current addresses to a
    /// directory.** Which directory is not a default and never n0's: it is
    /// whatever [`MeshInfra`] names, which is either the account directory a
    /// logged-in device was told about or a server the operator configured
    /// themselves. An endpoint asked for this mode with an empty
    /// [`MeshInfra`] has nowhere to publish and nothing to relay through, and
    /// binds as [`MeshMode::LocalOnly`] rather than inventing a third party.
    Discovery,
    /// Loopback only: no relays, no discovery, no traffic that leaves the host.
    ///
    /// **The default**, and what an unconfigured, not-logged-in device does.
    /// Peers must be dialed with explicit addresses — which is exactly what a
    /// [`PairingTicket`] carries. Used by the tests and by `pair_demo`, and it
    /// is also the roadmap's "bring your own route" case, where a user already
    /// has a working path and wants no third party involved.
    ///
    /// [`PairingTicket`]: crate::ticket::PairingTicket
    #[default]
    LocalOnly,
}

/// Which relay and discovery servers [`MeshMode::Discovery`] uses.
///
/// **There is no default fleet.** An empty `MeshInfra` means no relay and no
/// directory, and an endpoint built from one talks to nobody's servers because
/// there are none to talk to. Cross-network connectivity is something a device
/// is *given* — by logging in, which is what tells it about the account
/// directory and the relays that go with it — or something an operator
/// configures, with the environment variables above or `ast config set relay`.
/// It is never something a fresh install helps itself to.
///
/// That is a deliberate reversal. Phase 2 bootstrapped on n0's public
/// infrastructure, which meant an unconfigured device published its public key
/// and its current addresses to a public directory run by strangers, as a side
/// effect of being installed. A device that has not been asked to reach the
/// wider network should not be reaching it.
///
/// The type is the seam: values arrive at [`MeshEndpoint::bind_with`] rather
/// than being compiled in, so the hosted coordination plane supplies one of
/// these — see [`MeshInfra::with_hosted`] — and no call site changes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MeshInfra {
    /// Relay servers, in preference order. Empty means no relay at all.
    pub relays: Vec<String>,
    /// The pkarr server this device publishes its addresses to and resolves
    /// peers from. `None` means no publication and no pkarr lookup.
    pub pkarr_relay: Option<String>,
    /// The DNS zone peer addresses are looked up in. `None` means no DNS
    /// lookup.
    pub dns_origin: Option<String>,
}

/// The directory half of what a logged-in device is told to use.
///
/// Separate from the relay list because the two are separately optional: a
/// self-hoster may run a relay and no directory (peers are dialled from
/// pairing tickets and stored hints), and the hosted plane may one day resolve
/// addresses over its own API with no pkarr zone at all.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HostedDiscovery {
    /// The pkarr relay this device publishes its signed address record to, and
    /// resolves peers from. `None` publishes nothing.
    pub pkarr_relay: Option<String>,
    /// The DNS zone the same records can be read from more cheaply.
    pub dns_origin: Option<String>,
}

impl HostedDiscovery {
    /// No directory: relay only, peers dialled from tickets and stored hints.
    pub fn none() -> Self {
        Self::default()
    }

    /// A pkarr relay, with no DNS read path beside it.
    pub fn pkarr(relay: impl Into<String>) -> Self {
        Self {
            pkarr_relay: Some(relay.into()),
            dns_origin: None,
        }
    }

    /// A pkarr relay to publish to and a DNS zone to read from.
    pub fn pkarr_and_dns(relay: impl Into<String>, origin: impl Into<String>) -> Self {
        Self {
            pkarr_relay: Some(relay.into()),
            dns_origin: Some(origin.into()),
        }
    }

    /// Whether this names any directory at all.
    pub fn is_none(&self) -> bool {
        self.pkarr_relay.is_none() && self.dns_origin.is_none()
    }
}

impl MeshInfra {
    /// Reads the configuration from the environment, over nothing.
    ///
    /// With none of the three variables set this is [`MeshInfra::default`] —
    /// no relay and no directory — which is the correct answer for a device
    /// that has neither logged in nor been configured.
    pub fn from_env() -> Self {
        Self::default().with_env_overrides()
    }

    /// The infrastructure a logged-in device was told to use.
    ///
    /// **This is the function the hosted coordination plane calls.** Once
    /// enrollment has an answer to "which relays does this account use, and
    /// where is its device directory", it builds one of these and hands it to
    /// [`MeshEndpoint::bind_with`]; nothing else in the mesh changes, and no
    /// code in this crate performs the call that produced the answer. The
    /// client lives in `asterism-daemon`'s hosted module — see AST-118.
    ///
    /// `relays` is ordered and carried whole rather than collapsed to one URL:
    /// a fleet with one member is an outage waiting for a maintenance window,
    /// and the order is the preference the account was given.
    ///
    /// Takes [`RelayUrl`] rather than strings because the coordinator's answer
    /// has already been parsed by the time it gets here, and re-stringifying a
    /// parsed URL only to reparse it inside `bind_with` is a chance to lose a
    /// trailing slash.
    ///
    /// The environment still wins over this: see
    /// [`with_env_overrides`](Self::with_env_overrides), and apply it after
    /// this if the caller wants a human's local override to be respected —
    /// which it should.
    pub fn with_hosted(relays: Vec<RelayUrl>, discovery: HostedDiscovery) -> Self {
        Self {
            relays: relays.into_iter().map(|relay| relay.to_string()).collect(),
            pkarr_relay: trimmed(discovery.pkarr_relay),
            dns_origin: trimmed(discovery.dns_origin),
        }
    }

    /// Applies the environment variables on top of this base, field by field.
    ///
    /// The precedence is deliberate and one-directional: a variable a human
    /// set on this machine outranks whatever a coordinator supplied, because
    /// the variable is how someone points a device at their own relay when the
    /// coordinator is wrong, unreachable, or not theirs. A variable that is
    /// unset leaves the base alone rather than clearing it.
    #[must_use]
    pub fn with_env_overrides(mut self) -> Self {
        if let Some(raw) = non_empty(RELAY_ENV) {
            let relays: Vec<String> = raw
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
                .collect();
            if !relays.is_empty() {
                self.relays = relays;
            }
        }
        if let Some(pkarr) = non_empty(PKARR_ENV) {
            self.pkarr_relay = Some(pkarr);
        }
        if let Some(origin) = non_empty(DNS_ORIGIN_ENV) {
            self.dns_origin = Some(origin);
        }
        self
    }

    /// The relay this device should prefer, i.e. the first of the list.
    ///
    /// `None` means there is no relay: this device has no cross-network
    /// fallback and is reachable only where a direct path already works.
    pub fn primary_relay(&self) -> Option<&str> {
        self.relays.first().map(String::as_str)
    }

    /// Whether this names any server at all.
    ///
    /// True is the unconfigured, not-logged-in state, and it is not a
    /// degraded one: it is a device that has been asked to talk to nobody's
    /// servers and is not talking to nobody's servers.
    pub fn is_empty(&self) -> bool {
        self.relays.is_empty() && self.pkarr_relay.is_none() && self.dns_origin.is_none()
    }

    /// A one-line summary for a startup log, so a user can see whose servers
    /// their device is about to talk to without reading the source.
    pub fn describe(&self) -> String {
        if self.is_empty() {
            return "no relay and no directory".to_owned();
        }
        let relays = if self.relays.is_empty() {
            "no relay".to_owned()
        } else {
            self.relays.join(",")
        };
        let lookup = match (&self.pkarr_relay, &self.dns_origin) {
            (None, None) => "no directory".to_owned(),
            (pkarr, dns) => format!(
                "pkarr {} / dns {}",
                pkarr.as_deref().unwrap_or("none"),
                dns.as_deref().unwrap_or("none")
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

/// Trims a configured string and treats an empty one as absent.
fn trimmed(value: Option<String>) -> Option<String> {
    value.map(|s| s.trim().to_owned()).filter(|s| !s.is_empty())
}

/// Whether the advertised address should hide this device's IP addresses.
fn hide_direct_addrs() -> bool {
    matches!(
        std::env::var(NO_DIRECT_ENV).as_deref(),
        Ok("1") | Ok("true")
    )
}

/// Whether this endpoint must bind no IP transport at all. See
/// [`RELAY_ONLY_ENV`].
fn relay_only() -> bool {
    matches!(
        std::env::var(RELAY_ONLY_ENV).as_deref(),
        Ok("1") | Ok("true")
    )
}

/// Whether the router should be asked for a port mapping. See
/// [`NO_PORTMAP_ENV`]; the answer is yes unless someone said otherwise.
pub fn portmapping_enabled() -> bool {
    !matches!(
        std::env::var(NO_PORTMAP_ENV).as_deref(),
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

/// What a connection's set of open paths adds up to.
///
/// [`PathKind`] answers "where is the next byte going"; this answers "what
/// shape is this connection in", and the difference is the whole story of a
/// relay's job. A connection starts [`ConnectionType::Relay`] — the relay is
/// the rendezvous, the only place two devices behind NATs can meet — and hole
/// punching then moves the *same* QUIC connection onto a direct path,
/// producing [`ConnectionType::Mixed`]: bytes go direct, the relay path stays
/// open underneath as the fallback if the direct path dies.
///
/// So [`ConnectionType::Mixed`] is the healthy steady state, not a warning,
/// and a connection that stays [`ConnectionType::Relay`] is the one costing
/// the relay operator money. Reporting them as one word would hide exactly
/// that distinction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionType {
    /// A direct path is selected and no relay path is open. Nothing is being
    /// relayed and nothing would be if the path failed.
    Direct,
    /// A direct path is selected with a relay path still open beside it: hole
    /// punching succeeded and the fallback is warm. The normal upgraded state.
    Mixed,
    /// A relay path is carrying the bytes. Either hole punching has not
    /// finished yet, or it failed and this is what the connection costs.
    Relay,
    /// No path is open. The moment before a connection has settled.
    None,
}

impl ConnectionType {
    /// The word `ast ping` prints.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::Mixed => "mixed",
            Self::Relay => "relay",
            Self::None => "-",
        }
    }
}

impl fmt::Display for ConnectionType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The bytes QUIC has counted on one open path of one connection.
///
/// A snapshot: cumulative for as long as *this* path stays open, and gone from
/// [`MeshConnection::path_bytes`] once it closes. The numbers are UDP payload
/// bytes as the QUIC stack counted them, so they include the protocol's own
/// acknowledgements and retransmissions — which is the honest basis for
/// billing relayed bandwidth, because that is what the relay forwarded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathBytes {
    /// The remote transport address, as a string. Stable for the path's life,
    /// so it doubles as the key a running total is accumulated under.
    pub addr: String,
    /// Whether this path is direct or relayed.
    pub kind: PathKind,
    /// The relay's URL, when [`Self::kind`] is [`PathKind::Relay`].
    pub relay_url: Option<String>,
    /// Whether this is the path currently carrying application data.
    pub selected: bool,
    /// UDP payload bytes sent on this path.
    pub bytes_sent: u64,
    /// UDP payload bytes received on this path.
    pub bytes_recv: u64,
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

    /// Bind a local-only endpoint to an exact address.
    ///
    /// Asterism persists the first ephemeral loopback port and supplies it on
    /// later daemon starts. With no discovery service in this mode, that
    /// stable address is what lets paired peers find a restarted daemon.
    pub async fn bind_local(
        identity: &DeviceIdentity,
        address: SocketAddr,
    ) -> anyhow::Result<Self> {
        Self::bind_local_with(identity, address, MeshInfra::default()).await
    }

    /// Binds an endpoint to `identity` against explicitly chosen relay and
    /// discovery servers.
    ///
    /// `infra` is ignored under [`MeshMode::LocalOnly`], which by definition
    /// has no servers to point at.
    ///
    /// [`MeshMode::Discovery`] with an *empty* `infra` binds local-only, and
    /// reports [`MeshMode::LocalOnly`] afterwards. There is no fallback fleet
    /// to reach for: a device that was asked to be discoverable and given
    /// nowhere to be discovered is local, and saying so is better than
    /// publishing its key to whichever public directory happened to be
    /// compiled in.
    pub async fn bind_with(
        identity: &DeviceIdentity,
        mode: MeshMode,
        infra: MeshInfra,
    ) -> anyhow::Result<Self> {
        let mode = match mode {
            MeshMode::Discovery if infra.is_empty() => MeshMode::LocalOnly,
            other => other,
        };
        let endpoint = match mode {
            MeshMode::Discovery => discovery_endpoint(identity, &infra).await?,
            // `presets::Minimal` sets only the mandatory crypto provider, so
            // the LocalOnly path adds nothing that talks to the network.
            MeshMode::LocalOnly => {
                return Self::bind_local_with(
                    identity,
                    "127.0.0.1:0".parse().expect("constant socket address"),
                    infra,
                )
                .await;
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

    async fn bind_local_with(
        identity: &DeviceIdentity,
        address: SocketAddr,
        _infra: MeshInfra,
    ) -> anyhow::Result<Self> {
        let endpoint = Endpoint::builder(presets::Minimal)
            .secret_key(identity.secret_key().clone())
            .alpns(vec![ALPN.to_vec()])
            .relay_mode(RelayMode::Disabled)
            .clear_ip_transports()
            .bind_addr(address)?
            .bind()
            .await?;
        Ok(Self {
            device_id: identity.device_id(),
            endpoint,
            mode: MeshMode::LocalOnly,
            infra: MeshInfra::default(),
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

/// Builds the discovery-mode endpoint: the relays and the directory that
/// `infra` named, and nothing it did not.
///
/// Every service here is built from an explicit value. `presets::Minimal` sets
/// only the mandatory crypto provider, so a field left `None` in `infra`
/// produces *no* service rather than a default one — which is the whole point
/// of the login-only model. A caller reaches this function only with a
/// non-empty `infra`; [`MeshEndpoint::bind_with`] binds local-only otherwise.
async fn discovery_endpoint(
    identity: &DeviceIdentity,
    infra: &MeshInfra,
) -> anyhow::Result<Endpoint> {
    let mut builder = Endpoint::builder(presets::Minimal)
        .secret_key(identity.secret_key().clone())
        .alpns(vec![ALPN.to_vec()]);

    // pkarr: publish this device's signed address record, and resolve peers'.
    // Absent means this device publishes nothing about itself anywhere.
    if let Some(pkarr) = infra.pkarr_relay.as_deref() {
        let pkarr: RelayUrl = pkarr
            .parse()
            .map_err(|e| anyhow::anyhow!("{PKARR_ENV}={pkarr:?} is not a url: {e}"))?;
        builder = builder.address_lookup(PkarrPublisher::builder(pkarr.clone().into()));
        builder = builder.address_lookup(PkarrResolver::builder(pkarr.into()));
    }

    // DNS: the cheaper read path for the same records.
    if let Some(origin) = infra.dns_origin.clone() {
        builder = builder.address_lookup(DnsAddressLookup::builder(origin));
    }

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
    } else {
        // A directory but no relay: findable, and reachable wherever a direct
        // path works. Deliberately not "and n0's fleet for the rest".
        builder = builder.relay_mode(RelayMode::Disabled);
    }

    if relay_only() {
        // No IP transport means no direct path exists to be selected: every
        // byte this endpoint sends or receives is relayed, by construction.
        builder = builder.clear_ip_transports();
    }

    if !portmapping_enabled() {
        // The default stays `Enabled`; this is the declining of it. Every byte
        // a port mapping keeps off a relay is a byte the relay operator does
        // not pay for, so turning it off is a real cost, freely chosen.
        builder = builder.portmapper_config(iroh::endpoint::PortmapperConfig::Disabled);
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

    /// What this connection's open paths add up to right now.
    ///
    /// See [`ConnectionType`] for why this is four words rather than two: the
    /// difference between "relayed" and "direct, with the relay warm behind
    /// it" is the difference between a connection that costs the relay
    /// operator money and one that does not.
    pub fn connection_type(&self) -> ConnectionType {
        let paths = self.conn.paths();
        let mut has_relay = false;
        let mut has_direct = false;
        let mut selected = None;
        for path in paths.iter() {
            let kind = kind_of(path.remote_addr());
            match kind {
                PathKind::Direct => has_direct = true,
                PathKind::Relay => has_relay = true,
            }
            if path.is_selected() {
                selected = Some(kind);
            }
        }
        match selected {
            Some(PathKind::Direct) if has_relay => ConnectionType::Mixed,
            Some(PathKind::Direct) => ConnectionType::Direct,
            Some(PathKind::Relay) => ConnectionType::Relay,
            // Nothing selected yet. Report what is open rather than nothing,
            // and never claim "direct" on the strength of an unselected path.
            None if has_relay => ConnectionType::Relay,
            None if has_direct => ConnectionType::Direct,
            None => ConnectionType::None,
        }
    }

    /// The relay this connection is currently reachable through, if any.
    ///
    /// The selected path's relay when a relay is carrying the bytes, and
    /// otherwise the relay that is still open beside the direct path — a
    /// direct connection normally keeps its relay path alive as the fallback
    /// it came in on. `None` when there is no relay path at all, which is the
    /// loopback and `ASTERISM_MESH=local` case.
    ///
    /// This is the field a latency investigation needs and could not get: a
    /// millisecond figure with no relay named beside it cannot say whether the
    /// route was three hops or three continents.
    pub fn relay_url(&self) -> Option<String> {
        let paths = self.conn.paths();
        let mut fallback = None;
        for path in paths.iter() {
            if let TransportAddr::Relay(url) = path.remote_addr() {
                if path.is_selected() {
                    return Some(url.to_string());
                }
                fallback.get_or_insert_with(|| url.to_string());
            }
        }
        fallback
    }

    /// One entry per open path, with the bytes QUIC has counted on each.
    ///
    /// This is the metering primitive. iroh keeps UDP byte counters per path
    /// rather than per connection, and a path is either an IP address or a
    /// relay URL — so splitting a peer's traffic into "direct" and "relayed"
    /// is a matter of reading the counters and grouping by the kind of address
    /// they belong to, with no estimation anywhere.
    ///
    /// Two properties a caller has to respect. The counters are cumulative
    /// *for the life of one path*, so a reader that wants a running total
    /// across reconnections must accumulate differences rather than sums. And
    /// a path that closes leaves this list, taking its final counts with it,
    /// so a reader that samples too rarely undercounts. `MeshConnection` is
    /// deliberately not the thing that remembers either: see
    /// `asterism-daemon`'s relay meter.
    pub fn path_bytes(&self) -> Vec<PathBytes> {
        self.conn
            .paths()
            .iter()
            .map(|path| {
                let addr = path.remote_addr();
                let stats = path.stats();
                PathBytes {
                    addr: addr.to_string(),
                    kind: kind_of(addr),
                    relay_url: match addr {
                        TransportAddr::Relay(url) => Some(url.to_string()),
                        _ => None,
                    },
                    selected: path.is_selected(),
                    bytes_sent: stats.udp_tx.bytes,
                    bytes_recv: stats.udp_rx.bytes,
                }
            })
            .collect()
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
    fn local_only_is_the_default_mode() {
        // The daemon's default follows this one. Changing it changes whether
        // an unconfigured device publishes anything about itself anywhere, so
        // it is worth a test that says so out loud.
        assert_eq!(MeshMode::default(), MeshMode::LocalOnly);
    }

    #[test]
    fn an_unconfigured_device_names_no_servers_at_all() {
        // The load-bearing property of the login-only model: nothing is
        // compiled in, so nothing is contacted.
        let stock = MeshInfra::default();
        assert!(stock.is_empty());
        assert!(stock.relays.is_empty());
        assert_eq!(stock.pkarr_relay, None);
        assert_eq!(stock.dns_origin, None);
        assert!(stock.primary_relay().is_none());
        let said = stock.describe();
        assert!(said.contains("no relay"), "{said}");
        assert!(
            !said.to_ascii_lowercase().contains("n0"),
            "no third party may appear in the default disclosure: {said}"
        );
    }

    #[test]
    fn configuring_one_half_does_not_conjure_the_other() {
        let relayed = MeshInfra {
            relays: vec!["https://relay.asterism.run.".into()],
            ..MeshInfra::default()
        };
        assert!(!relayed.is_empty());
        assert_eq!(relayed.primary_relay(), Some("https://relay.asterism.run."));
        let said = relayed.describe();
        assert!(said.contains("relay.asterism.run"), "{said}");
        // A relay and no directory is a coherent configuration — peers are
        // dialled from tickets and stored hints — and must not silently
        // acquire someone else's directory.
        assert!(said.contains("no directory"), "{said}");

        let looked_up = MeshInfra {
            pkarr_relay: Some("https://dns.asterism.run/pkarr".into()),
            ..MeshInfra::default()
        };
        assert!(!looked_up.is_empty());
        assert!(
            looked_up.describe().contains("no relay"),
            "{}",
            looked_up.describe()
        );
    }

    #[test]
    fn a_coordinator_supplies_the_same_struct_the_environment_does() {
        // The seam AST-118 calls. A relay list arriving over the network and
        // one arriving from a variable have to reach `bind_with` as the same
        // type, or the hosted path would be a second code path to maintain.
        let relays: Vec<RelayUrl> = vec![
            "https://relay-sel.asterism.run./".parse().unwrap(),
            "https://relay-fra.asterism.run./".parse().unwrap(),
        ];
        let hosted = MeshInfra::with_hosted(
            relays,
            HostedDiscovery::pkarr_and_dns("https://dns.asterism.run/pkarr", "dns.asterism.run."),
        );
        assert!(!hosted.is_empty());
        assert_eq!(hosted.relays.len(), 2);
        // Order is preference, and preference is the coordinator's to state.
        assert!(
            hosted.primary_relay().unwrap().contains("relay-sel"),
            "{:?}",
            hosted.relays
        );
        assert_eq!(hosted.dns_origin.as_deref(), Some("dns.asterism.run."));
    }

    #[test]
    fn a_relay_only_account_is_a_coherent_answer() {
        let hosted = MeshInfra::with_hosted(
            vec!["https://relay.asterism.run./".parse().unwrap()],
            HostedDiscovery::none(),
        );
        assert!(!hosted.is_empty());
        assert!(hosted.pkarr_relay.is_none());
        assert!(HostedDiscovery::none().is_none());
    }

    #[tokio::test]
    async fn discovery_with_nothing_configured_binds_local_rather_than_reaching_out() {
        // The whole reversal in one assertion: asking for discovery without
        // having been given anywhere to be discovered must not fall back to
        // somebody's public fleet.
        let identity = DeviceIdentity::generate();
        let endpoint =
            MeshEndpoint::bind_with(&identity, MeshMode::Discovery, MeshInfra::default())
                .await
                .unwrap();
        assert_eq!(endpoint.mode(), MeshMode::LocalOnly);
        assert!(endpoint.home_relays().is_empty());
        endpoint.close().await;
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

        assert!(endpoint.infra().is_empty());
        assert!(endpoint.home_relays().is_empty());
        assert!(endpoint.online(Duration::from_millis(1)).await);
        endpoint.close().await;
    }

    #[tokio::test]
    async fn local_mode_can_rebind_the_same_advertised_address_after_restart() {
        let reservation = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let address = reservation.local_addr().unwrap();
        drop(reservation);
        let identity = DeviceIdentity::generate();

        let first = MeshEndpoint::bind_local(&identity, address).await.unwrap();
        assert!(first
            .direct_addr()
            .await
            .unwrap()
            .ip_addrs()
            .any(|a| *a == address));
        first.close().await;
        drop(first);

        // `close` returns when the endpoint is done with the socket, not when
        // the kernel has finished releasing it, and the gap is real enough on a
        // loaded CI runner to fail the bind that is the point of this test. The
        // claim being made is that nothing holds the port permanently, so a
        // bounded retry proves it and a single attempt only races the teardown.
        let mut restarted = None;
        for attempt in 0..50 {
            match MeshEndpoint::bind_local(&identity, address).await {
                Ok(endpoint) => {
                    restarted = Some(endpoint);
                    break;
                }
                Err(error) => {
                    assert!(
                        attempt < 49,
                        "the advertised address was never released: {error:#}"
                    );
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            }
        }
        let restarted = restarted.expect("rebinding the advertised address");
        assert!(restarted
            .direct_addr()
            .await
            .unwrap()
            .ip_addrs()
            .any(|a| *a == address));
        restarted.close().await;
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
