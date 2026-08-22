//! The mesh half of `astd`: this device's presence in its orbit.
//!
//! The shape here is deliberately Tailscale's. The CLI never opens a mesh
//! connection — it talks to the daemon on the machine the user is sitting at,
//! over the same unix socket as always, and *that* daemon holds the always-on
//! endpoint and dials peers. So `ast --device desktop ls` is one unix socket
//! round trip plus one mesh stream, and a command that reaches another device
//! never has to bind an endpoint, wait for a hole punch, or hold a key.
//!
//! Three jobs:
//!
//! * **Accept.** One inbound loop classifies every connection by the peer key
//!   QUIC authenticated. In the orbit store: serve it. Not in the store, but a
//!   pairing ticket is outstanding: hand it to the pairing task, which is the
//!   only unauthenticated path in the daemon and is gated by that ticket's
//!   token. Neither: close it with a reason and log it.
//! * **Dial.** Peers are dialed by name — the name is looked up in the orbit
//!   store, which yields the key to dial and the addresses to try.
//! * **Assemble.** The orbit registry is one flat namespace of instances, but
//!   it is stored as a shard per device. Reading it whole, claiming a name in
//!   it, and finding which device holds a given row are all done here, by
//!   asking every peer for its shard.
//! * **Pair.** Drives `ast device invite` / `ast device add` end to end,
//!   including the exchange of device names, and writes to the orbit store only
//!   after both humans have confirmed the same six digits.
//! * **Wake.** A magic packet is a broadcast and cannot be routed to a
//!   sleeping machine, so waking one is a matter of finding a device that is
//!   already standing on its LAN and asking it to shout. See [`Mesh::wake`],
//!   and [`crate::wake`] for the packet and the platform truths.
//!
//! # Framing
//!
//! Every mesh stream carries length-prefixed JSON frames: a four-byte
//! big-endian length, then that many bytes. The RPC frame wraps
//! [`Request`]/[`Response`] *verbatim* — the same enums the unix socket
//! carries — which is what makes a proxied command the same code path as a
//! local one rather than a parallel implementation of it.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, Mutex};

use asterism_core::cow;
use asterism_core::durable;
use asterism_core::instance::Instance;
use asterism_core::orbit::{self, Device, DeviceStatus, Orbit, WakeFacts};
use asterism_core::paths;
use asterism_core::protocol::{MoveManifest, Request, Response};
use asterism_core::registry::OrbitRow;
use asterism_core::verify::{self, Source};

use crate::{swap, Node};

use asterism_mesh::iroh_types::{EndpointAddr, PublicKey, RecvStream, SendStream};
use asterism_mesh::{
    pairing, DeviceId, DeviceIdentity, IssuedTicket, MeshConnection, MeshEndpoint, MeshMode,
    PairedPeer, PairingTicket, PathKind, DEFAULT_TICKET_TTL,
};

/// How long a peer has to answer a liveness probe before `ast devices` calls
/// it offline. Generous for a LAN, short enough that a table of ten dead
/// devices still prints promptly.
const PROBE_TIMEOUT: Duration = Duration::from_secs(3);

/// How long to spend dialling a peer before giving up on a command aimed at
/// it. Covers the dial and nothing after it: the work the far daemon then does
/// is not on a clock here, because `ast --device desktop create` can
/// legitimately take minutes.
const DIAL_TIMEOUT: Duration = Duration::from_secs(10);

/// How long the pairing exchange waits on the peer's half after the code has
/// been shown. This is a human's reading-and-typing time, not a network one.
const PAIR_TIMEOUT: Duration = Duration::from_secs(300);

/// Largest mesh frame we will read. An instance list is the big one and it is
/// nowhere near this; the cap exists so a peer cannot ask for an allocation.
pub(crate) const MAX_FRAME: usize = 4 * 1024 * 1024;

/// What the daemon says when it closes a connection from a stranger.
const REFUSAL: &[u8] = b"not in this orbit";

/// What either side of a pairing says when the other one backed out.
const REFUSED: &str = "the other device did not confirm the pairing";

/// How long to wait for a pairing frame to reach the peer before closing
/// anyway. The peer commits on some of these, so losing one is worse than
/// spending a round trip on making sure it arrived.
const FLUSH_TIMEOUT: Duration = Duration::from_secs(5);

/// Selects the mesh mode. `ASTERISM_MESH=local` opts out of discovery, and is
/// what the tests set.
const MESH_MODE_ENV: &str = "ASTERISM_MESH";

/// How old a stored address hint has to be before a dial asks discovery first.
/// See [`hint_is_stale`].
const STALE_ADDR_AGE: Duration = Duration::from_secs(24 * 60 * 60);

/// How long the startup announcement waits for a home relay before saying so.
///
/// Bounded because it is a log line, not a dependency: a daemon with no WAN
/// runs its own instances and serves its own LAN exactly as before.
const ANNOUNCE_TIMEOUT: Duration = Duration::from_secs(15);

/// How long `ast device wake` watches for the woken device to check in.
///
/// A minute is a machine's honest worst case: firmware, then a kernel, then a
/// network stack, then astd. Waiting less would report failure at devices
/// that were on their way; waiting more would sit on a terminal long after
/// the answer stopped being in doubt.
const WAKE_WAIT: Duration = Duration::from_secs(60);

/// How often to look, inside that window. Each look is a mesh dial and a
/// round trip, so this is not free, and a device that has just woken is not
/// going to answer a second sooner for being asked more often.
const WAKE_POLL: Duration = Duration::from_secs(2);

/// Shortens (or, at `0`, skips) the wait for a woken device. The e2e sets it,
/// because a test that proves the *packet* has nothing to gain from a minute
/// of watching a machine that was never asleep.
const WAKE_WAIT_ENV: &str = "ASTERISM_WAKE_WAIT";

fn wake_wait() -> Duration {
    match std::env::var(WAKE_WAIT_ENV).ok().and_then(|s| s.parse().ok()) {
        Some(secs) => Duration::from_secs(secs),
        None => WAKE_WAIT,
    }
}

// ---- wire ------------------------------------------------------------------

/// What one mesh stream asks for.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum MeshRequest {
    /// A daemon request, exactly as the unix socket would carry it.
    Rpc { request: Request },
    /// A round trip and nothing else: `ast ping`.
    Ping,
    /// This device's guest key, so the asker can open guests it seeded.
    ///
    /// Answered only to a peer already in the orbit — the accept loop has
    /// checked that before this frame is ever read. See
    /// [`paths::guest_key_cache`] for why membership is the right bar.
    GuestKey,
    /// Hand this stream to the guest's ssh port and stop framing it.
    ///
    /// One of two requests that turn a mesh stream into a pipe. One reply
    /// frame says whether the far side found a running guest to connect to;
    /// after that the stream carries ssh's own bytes in both directions until
    /// either end hangs up.
    SshSplice { name: String },
    /// Hand this stream to a block volume's NBD export and stop framing it.
    ///
    /// The other pipe, and the fenced one: the far side checks `holder` and
    /// `epoch` against the volume's lease before it connects anything, so a
    /// consumer that has been fenced out gets a refusal frame rather than a
    /// second writer's worth of I/O. After the reply this carries NBD's own
    /// bytes, which neither daemon looks at.
    VolumeSplice {
        volume: String,
        /// The instance the bytes are for — the lease holder.
        holder: String,
        /// The epoch that lease was granted at.
        epoch: u64,
    },

    // ---- moving an instance's cpu part --------------------------------------
    //
    // Three streams, and none of them is a request/reply. A move is bulk, so
    // past the opening frame these carry [`MoveFrame`]s — control frames with
    // raw bytes behind the ones that have bytes.
    /// Send me this instance's directory, sparsely.
    ///
    /// Fenced: the far side serves this only while that instance is marked
    /// `moving` at exactly this epoch, so nobody can pull a live instance's
    /// disk off a device by asking nicely.
    MoveExport { name: String, epoch: u64 },
    /// Send me this base image.
    ///
    /// The peer fetch `docs/MODEL.md` asks for: a device that lacks an image
    /// takes it from an orbit peer that has it before it would reach for the
    /// internet. Nothing is fenced here because nothing is exclusive — a base
    /// image is immutable and content-addressed, and every device in the
    /// orbit is entitled to a copy.
    MoveBase { reference: String },
    /// Fetch this instance from `from_device` into staging, and tell me how
    /// it is going.
    ///
    /// Sent by the daemon in front of the user to the *target*, which then
    /// opens its own [`MeshRequest::MoveExport`] to the source. The bytes go
    /// source to target directly; what comes back on this stream is progress.
    MoveImport {
        manifest: Box<MoveManifest>,
        epoch: u64,
        from_device: String,
    },
}

/// One frame on a move's data stream.
///
/// A [`MoveFrame::Data`] frame is followed immediately by exactly `len` raw
/// bytes — no base64, no JSON envelope around a megabyte. That is the whole
/// reason a move does not reuse the RPC framing: the control words stay
/// legible and the payload stays payload.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "frame", rename_all = "snake_case")]
enum MoveFrame {
    /// A file is starting. `len` is what it claims to be; almost none of that
    /// will be sent, because almost all of it is hole.
    File { path: String, len: u64, mode: u32 },
    /// `len` raw bytes follow, to be written at `offset` of the open file.
    Data { offset: u64, len: u64 },
    /// That file is done, and this is what it really cost.
    Done { path: String, written: u64 },
    /// Every file is done.
    End { files: u64, bytes: u64 },
    /// One line for the terminal the user is watching.
    Progress { text: String, bytes: u64 },
    /// The far side could not, and this is why. Sent instead of anything
    /// else, so a failure is a sentence rather than a truncated stream.
    Failed { message: String },
}

/// What one mesh stream answers.
//
// `Response` is much bigger than a pong, for the same reason it is bigger than
// an `Ok`: one variant carries a whole instance. Boxing it would buy an
// allocation on a value that is built once per stream and serialized
// immediately.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum MeshReply {
    Rpc { response: Response },
    Pong,
    /// The last framed message on a stream that is becoming a pipe — an ssh
    /// session, or a volume's NBD connection.
    SpliceReady,
    /// The private half of this device's guest key, in OpenSSH format.
    GuestKey { key: String },
}

/// One side's half of the name exchange that follows a confirmed SAS.
///
/// Pairing proves two keys belong to two willing devices; it says nothing
/// about what either is called. Names are how the orbit is addressed
/// afterwards, so they are exchanged here — along with the addresses each side
/// can be reached on, which is what lets the *inviter* dial the joiner later
/// (the ticket only ever pointed one way).
#[derive(Debug, Serialize, Deserialize)]
struct Hello {
    /// Whether this side's human confirmed the code.
    accepted: bool,
    /// What this device calls itself.
    name: String,
    /// Addresses this device answers on.
    #[serde(default)]
    addrs: Vec<String>,
    /// Relay URLs it advertises.
    #[serde(default)]
    relays: Vec<String>,
    /// Why it refused, when it did.
    #[serde(default)]
    error: Option<String>,
    /// Where this device sits on the wire, so the other side can wake it.
    ///
    /// Enrollment is the right moment for this because it is the one moment
    /// both devices are definitely awake and definitely talking. Optional and
    /// defaulted, so pairing with an `astd` that predates wake still works
    /// and simply leaves the field unknown.
    #[serde(default)]
    wake: WakeFacts,
}

/// The joiner's last word, so neither side writes a peer the other rejected.
#[derive(Debug, Serialize, Deserialize)]
struct Ack {
    ok: bool,
    #[serde(default)]
    error: Option<String>,
}

// ---- the mesh --------------------------------------------------------------

/// This daemon's mesh presence.
pub struct Mesh {
    endpoint: MeshEndpoint,
    orbit: Arc<Mutex<Orbit>>,
    /// Where the accept loop sends a connection from a device that is not in
    /// the orbit, while a ticket is outstanding. `None` the rest of the time,
    /// which is what makes an unpaired connection a refusal.
    pending: Arc<Mutex<Option<mpsc::Sender<MeshConnection>>>>,
    /// One connection per peer, kept warm. Keyed by device id.
    conns: Mutex<HashMap<String, MeshConnection>>,
}

impl Mesh {
    /// Brings the endpoint up and starts accepting.
    ///
    /// The identity is loaded from `$ASTERISM_HOME/id_device`, generated on
    /// first run and never rotated: rotating it would make this device a
    /// stranger to every peer that has already paired with it.
    pub async fn start(node: Node) -> Result<Arc<Self>> {
        let identity = DeviceIdentity::load_or_create(paths::device_key_path())
            .context("loading this device's mesh identity")?;
        let endpoint = MeshEndpoint::bind(&identity, mesh_mode())
            .await
            .context("binding the mesh endpoint")?;

        let mesh = Arc::new(Self {
            endpoint,
            orbit: node.orbit.clone(),
            pending: Arc::new(Mutex::new(None)),
            conns: Mutex::new(HashMap::new()),
        });

        tokio::spawn(accept_loop(mesh.clone(), node));
        // Enrollment recorded where each peer was at pairing time; devices
        // move. Asking again at startup is what keeps `ast device wake` from
        // choosing a broadcaster that is no longer on the sleeper's LAN — and
        // it is best effort by design, because most peers will be asleep,
        // which is the situation this whole feature is about.
        let refreshing = mesh.clone();
        tokio::spawn(async move {
            refreshing.refresh_facts().await;
        });
        // Says whose relay and directory this device just joined, or that it
        // joined none. Spawned rather than awaited: a daemon must come up on a
        // machine with no WAN exactly as fast as on one with.
        tokio::spawn(mesh.clone().announce());
        Ok(mesh)
    }

    /// This device's id — its public key.
    pub fn device_id(&self) -> DeviceId {
        self.endpoint.device_id()
    }

    /// What this device calls itself.
    pub async fn self_name(&self) -> String {
        self.orbit.lock().await.self_name().to_owned()
    }

    /// The orbit as `ast devices` prints it: this device first, then every
    /// peer, each probed for liveness as the answer is assembled.
    pub async fn devices(self: &Arc<Self>) -> Vec<DeviceStatus> {
        let (self_name, peers) = {
            let orbit = self.orbit.lock().await;
            (orbit.self_name().to_owned(), orbit.devices().to_vec())
        };

        let mut probes = tokio::task::JoinSet::new();
        for (i, peer) in peers.iter().enumerate() {
            let mesh = self.clone();
            let name = peer.name.clone();
            probes.spawn(async move { (i, mesh.probe_path(&name).await) });
        }
        let mut seen: Vec<Option<Option<PathKind>>> = vec![None; peers.len()];
        while let Some(Ok((i, path))) = probes.join_next().await {
            seen[i] = path;
        }

        let mut rows = vec![DeviceStatus {
            name: self_name,
            device_id: self.device_id().to_string(),
            online: true,
            // A device does not reach itself over a path.
            path: "-".into(),
            is_self: true,
        }];
        rows.extend(peers.iter().zip(seen).map(|(peer, path)| DeviceStatus {
            name: peer.name.clone(),
            device_id: peer.device_id.clone(),
            online: path.is_some(),
            // Whatever the live connection says, and a dash when there is no
            // connection to ask.
            path: path_word(path.flatten()),
            is_self: false,
        }));
        rows
    }

    /// Drops a device from the orbit. Its key stops being trusted at once —
    /// the accept loop reads the same store this writes.
    pub async fn remove_device(&self, name: &str) -> Result<Device> {
        let mut orbit = self.orbit.lock().await;
        let removed = orbit.remove(name)?;
        orbit.save()?;
        self.conns.lock().await.remove(&removed.device_id);
        Ok(removed)
    }

    /// Times a round trip to one device: `ast ping`.
    pub async fn ping(&self, name: &str) -> Result<Response> {
        let device = self.device(name).await?;
        // Time the round trip on a connection that is already up, the way
        // `tailscale ping` does: a first packet that had to punch a hole says
        // more about the dial than about the path.
        let connection = self.live_connection(&device).await?;
        let started = Instant::now();
        match ask(&connection, &MeshRequest::Ping).await? {
            MeshReply::Pong => {}
            other => bail!("device {name:?} answered a ping with {other:?}"),
        }
        Ok(Response::DevicePong {
            device: device.name,
            device_id: device.device_id,
            // Read after the round trip, so it describes the path the round
            // trip actually took rather than the one the dial started on: a
            // connection that came up through a relay and then hole punched
            // reports the direct path it ended on, which is the true answer to
            // "how am I reaching this device".
            path: path_word(connection.path()),
            millis: started.elapsed().as_secs_f64() * 1000.0,
        })
    }

    /// Runs a request on another device and returns its answer verbatim.
    pub async fn proxy(&self, name: &str, inner: Request) -> Result<Response> {
        if matches!(inner, Request::Proxy { .. }) {
            bail!("a request cannot be proxied through two devices");
        }
        let device = self.device(name).await?;
        let connection = self.live_connection(&device).await?;
        // Deliberately unbounded from here: `ast --device desktop create` can
        // legitimately spend minutes pulling an image, and a timeout on the
        // far device's work would turn slow into broken.
        match ask(&connection, &MeshRequest::Rpc { request: inner })
            .await
            .with_context(|| format!("device {name:?} stopped answering"))?
        {
            MeshReply::Rpc { response } => Ok(response),
            other => bail!("device {name:?} answered a request with {other:?}"),
        }
    }

    // ---- wake ---------------------------------------------------------------

    /// Wakes a sleeping device: `ast device wake <name>`.
    ///
    /// A magic packet cannot be routed to a sleeping machine — it has to be
    /// broadcast inside that machine's own L2 network — so this is an orbit
    /// operation end to end. The daemon in front of the user finds a device
    /// that is *awake on the sleeper's LAN* and asks it to do the shouting.
    /// This device is a candidate like any other, and when it qualifies the
    /// packet goes out here with no mesh hop at all.
    ///
    /// Reports as it goes rather than at the end, because the last step is up
    /// to a minute of waiting for a machine to finish booting its network
    /// stack, and a minute of silence is what the whole feature is trying not
    /// to be.
    pub async fn wake(self: &Arc<Self>, name: &str, io: &mut ClientIo<'_>) -> Result<()> {
        // `device` gives the "no device named ..." refusal every other
        // device command gives, before anything else is attempted.
        let target = self.device(name).await?;

        if self.probe(name).await {
            return io
                .send(&Response::Wake {
                    text: format!("{name} is already online — nothing to wake"),
                    done: true,
                })
                .await;
        }

        // Everything below turns on the peers' recorded facts being current,
        // and a peer that is reachable right now can simply be asked.
        self.refresh_facts().await;

        let target = self
            .orbit
            .lock()
            .await
            .by_id(&target.device_id)
            .cloned()
            .unwrap_or(target);
        let Some((mac, lan_id)) = target.wake.wakeable() else {
            bail!(
                "nothing is recorded about {name}'s network, so there is no packet to \
                 send and nobody to send it — bring {name} online once with an astd \
                 that reports its MAC, or pair it again"
            );
        };

        let sender = self.wake_sender(name, &target.wake).await?;
        let sent = match &sender {
            // No mesh hop: this device is standing on the right LAN.
            None => {
                io.send(&Response::Wake {
                    text: format!("this device is on {name}'s network ({lan_id})"),
                    done: false,
                })
                .await?;
                crate::wake::broadcast(mac, None)?
            }
            Some(peer) => {
                io.send(&Response::Wake {
                    text: format!("{peer} is awake on {name}'s network ({lan_id}) — asking it to broadcast"),
                    done: false,
                })
                .await?;
                match self
                    .proxy(peer, Request::WakeBroadcast {
                        mac: mac.to_owned(),
                        lan_id: Some(lan_id.to_owned()),
                    })
                    .await?
                {
                    Response::Wake { text, .. } => vec![text],
                    Response::Error { message } => bail!("{peer} could not broadcast: {message}"),
                    other => bail!("{peer} answered a wake with {other:?}"),
                }
            }
        };

        io.send(&Response::Wake {
            text: format!("magic packet for {mac} sent to {}", sent.join(", ")),
            done: false,
        })
        .await?;

        self.await_presence(name, io).await
    }

    /// Which device is going to broadcast: `None` for this one, `Some(peer)`
    /// for a peer, and an error naming the spec's refusal when neither.
    ///
    /// The refusal wording is exact and load bearing. "Timed out" would be a
    /// lie about a working system: the packet was never sendable, because
    /// nothing awake is standing on that network, and the fix is a device
    /// that stays on — which is the argument for a beacon.
    async fn wake_sender(self: &Arc<Self>, name: &str, target: &WakeFacts) -> Result<Option<String>> {
        if crate::wake::facts().shares_lan_with(target) {
            return Ok(None);
        }
        let candidates: Vec<String> = self
            .orbit
            .lock()
            .await
            .on_lan_with(target)
            .into_iter()
            .map(|d| d.name.clone())
            .filter(|n| n != name)
            .collect();

        let mut probing = tokio::task::JoinSet::new();
        for candidate in candidates {
            let mesh = self.clone();
            probing.spawn(async move {
                let up = mesh.probe(&candidate).await;
                (candidate, up)
            });
        }
        let mut awake: Vec<String> = Vec::new();
        while let Some(Ok((candidate, up))) = probing.join_next().await {
            if up {
                awake.push(candidate);
            }
        }
        // Stable, so the same orbit picks the same sender twice running.
        awake.sort();
        match awake.into_iter().next() {
            Some(peer) => Ok(Some(peer)),
            None => bail!("no awake device on {name}'s network"),
        }
    }

    /// Waits for the woken device to turn up on the mesh, and says either way.
    ///
    /// Presence is the only honest confirmation available: the magic packet
    /// has no acknowledgement, and a NIC that ignored it is
    /// indistinguishable, from here, from one that took the packet and is
    /// still POSTing. So the report is about what we can see — a daemon
    /// answering — and never about what we sent.
    async fn await_presence(self: &Arc<Self>, name: &str, io: &mut ClientIo<'_>) -> Result<()> {
        let wait = wake_wait();
        if wait.is_zero() {
            return io
                .send(&Response::Wake {
                    text: format!("not waiting to see whether {name} comes online"),
                    done: true,
                })
                .await;
        }
        io.send(&Response::Wake {
            text: format!("waiting up to {}s for {name} to check in ...", wait.as_secs()),
            done: false,
        })
        .await?;

        let started = Instant::now();
        while started.elapsed() < wait {
            if self.probe(name).await {
                return io
                    .send(&Response::Wake {
                        text: format!("{name} is online after {}s", started.elapsed().as_secs()),
                        done: true,
                    })
                    .await;
            }
            tokio::time::sleep(WAKE_POLL).await;
        }
        bail!(
            "{name} has not come online within {}s. The packet went out; whether it \
             arrived, and whether {name} was asleep rather than shut down, is not \
             something this device can see — try: ast --device {name} device check",
            wait.as_secs()
        )
    }

    /// Asks every reachable peer where it is on the wire, and records it.
    ///
    /// A pull rather than a push, and best effort throughout. Every daemon
    /// runs this at startup and before a wake, which is what keeps a peer
    /// that changed networks from being remembered on the old one for long —
    /// and a peer that cannot be reached simply keeps the facts it had, since
    /// stale facts about a LAN are still the best guess available.
    pub async fn refresh_facts(self: &Arc<Self>) -> usize {
        let peers = self.orbit.lock().await.devices().to_vec();
        let mut asking = tokio::task::JoinSet::new();
        for peer in peers {
            let mesh = self.clone();
            asking.spawn(async move {
                // On the same clock `ast devices` uses to call a peer
                // offline, and for the same reason: a device that cannot
                // answer within the liveness window is not a device that
                // could broadcast for us either, so waiting out a full dial
                // timeout on it would only make every wake ten seconds
                // slower for no better answer.
                let asked = tokio::time::timeout(
                    PROBE_TIMEOUT,
                    mesh.proxy(&peer.name, Request::DeviceFacts),
                )
                .await;
                let facts = match asked {
                    Ok(Ok(Response::WakeFacts { facts })) => Some(facts),
                    _ => None,
                };
                (peer.device_id, facts)
            });
        }

        // Collect first, then take the lock. Those tasks are dialling peers,
        // and dialling a peer now touches the orbit store — it looks the peer
        // up, and writes down where the peer answered from. Holding the lock
        // across the wait would leave every one of them queued behind this
        // function until its own probe timed out, which is the slowest
        // possible way to learn nothing.
        let mut answers = Vec::new();
        while let Some(Ok(answer)) = asking.join_next().await {
            answers.push(answer);
        }

        let mut changed = 0;
        let mut orbit = self.orbit.lock().await;
        for (device_id, facts) in answers {
            if let Some(facts) = facts {
                if orbit.set_wake(&device_id, facts) {
                    changed += 1;
                }
            }
        }
        if changed > 0 {
            if let Err(e) = orbit.save() {
                eprintln!("astd: could not record what peers said about their networks: {e:#}");
            }
        }
        changed
    }

    // ---- the orbit registry -------------------------------------------------
    //
    // One flat namespace of instances, stored as a shard per device. These
    // four are everything the rest of the daemon needs of it: read it whole,
    // claim a name in it, find which device holds a row, and splice a pipe to
    // a guest that is not here. All four work by asking peers for their shard
    // and none of them lets the user name a device.

    /// The whole orbit registry, assembled: this device's shard plus every
    /// peer's, with the last-seen cache standing in for peers that do not
    /// answer.
    ///
    /// A device that is asleep must not make its instances vanish from
    /// `ast ls` — that would read as "deleted" rather than "out of touch" —
    /// so its rows are listed from cache, marked not live, with the device
    /// supplying their cpu still named. Assembling the view is also the moment
    /// two shards are compared, so this is where a name collision that a
    /// partition hid comes to light.
    pub async fn orbit_registry(self: &Arc<Self>, node: &Node) -> Result<Response> {
        let mine: Vec<Instance> = {
            let mut shard = node.shard.lock().await;
            crate::instance::reconcile(&mut shard);
            shard.list()
        };
        let peers = self.orbit.lock().await.devices().to_vec();

        let mut asking = tokio::task::JoinSet::new();
        for peer in &peers {
            let (mesh, name) = (self.clone(), peer.name.clone());
            asking.spawn(async move {
                let shard = mesh.shard_of(&name).await;
                (name, shard)
            });
        }

        let mut cache = ShardCache::load();
        let mut rows: Vec<OrbitRow> = mine
            .into_iter()
            .map(|instance| OrbitRow { instance, live: true })
            .collect();
        while let Some(Ok((device, answer))) = asking.join_next().await {
            match answer {
                Ok(instances) => {
                    cache.remember(&device, &instances);
                    rows.extend(
                        instances.into_iter().map(|instance| OrbitRow { instance, live: true }),
                    );
                }
                // Out of touch, not gone.
                Err(_) => rows.extend(
                    cache
                        .last_seen(&device)
                        .into_iter()
                        .map(|instance| OrbitRow { instance, live: false }),
                ),
            }
        }
        let _ = cache.save();

        // One instance, two devices: a move that half-committed. The epoch
        // settles it and the stale row leaves the view, because an orbit that
        // listed somebody's instance twice would be inviting them to boot the
        // wrong one.
        let stale: std::collections::HashSet<usize> = superseded(&rows).into_iter().collect();
        if !stale.is_empty() {
            for &i in &stale {
                eprintln!(
                    "astd: {:?} has a stale copy on {} at move epoch {} — an interrupted \
                     move left it, and the higher epoch is the live one",
                    rows[i].instance.name,
                    rows[i].instance.cpu_device,
                    rows[i].instance.move_epoch
                );
            }
            rows = rows
                .into_iter()
                .enumerate()
                .filter(|(i, _)| !stale.contains(i))
                .map(|(_, row)| row)
                .collect();
        }

        self.settle_collisions(node, &mut rows).await;
        rows.sort_by(|a, b| {
            a.instance
                .created_at
                .cmp(&b.instance.created_at)
                .then_with(|| a.instance.id.cmp(&b.instance.id))
        });
        Ok(Response::Orbit { rows })
    }

    /// Claims a name against every device that answers.
    ///
    /// `Some(instance)` is a refusal, carrying the instance already using the
    /// name so the caller can say where its parts come from. `None` means no
    /// reachable device objects — which is not the same as "the name is free",
    /// and deliberately so: see `Shard::mark_conflicted` for what an
    /// unreachable device's objection costs and when it is collected.
    pub async fn claim(self: &Arc<Self>, name: &str) -> Result<Option<Instance>> {
        Ok(self.find(name).await.into_iter().next().map(|(_, inst)| inst))
    }

    /// Which device holds the row for `name`, if any reachable one does.
    pub async fn locate(self: &Arc<Self>, name: &str) -> Result<Option<String>> {
        Ok(self.find(name).await.into_iter().next().map(|(device, _)| device))
    }

    /// Every reachable device whose shard holds `name`. More than one is a
    /// collision, and the reason this returns a list rather than an option.
    async fn find(self: &Arc<Self>, name: &str) -> Vec<(String, Instance)> {
        let peers = self.orbit.lock().await.devices().to_vec();
        let mut asking = tokio::task::JoinSet::new();
        for peer in &peers {
            let (mesh, device, name) = (self.clone(), peer.name.clone(), name.to_owned());
            asking.spawn(async move {
                let found = match mesh.proxy(&device, Request::Status { name }).await {
                    Ok(Response::Instance { instance }) => Some(instance),
                    _ => None,
                };
                (device, found)
            });
        }
        let mut hits = Vec::new();
        while let Some(Ok((device, found))) = asking.join_next().await {
            if let Some(instance) = found {
                hits.push((device, instance));
            }
        }
        // Stable regardless of which peer answered first, so two devices
        // running this at the same moment agree about what they saw.
        hits.sort_by(|a, b| a.0.cmp(&b.0));
        hits
    }

    /// One peer's shard.
    async fn shard_of(self: &Arc<Self>, device: &str) -> Result<Vec<Instance>> {
        match self.proxy(device, Request::List).await? {
            Response::Instances { instances } => Ok(instances),
            Response::Error { message } => bail!(message),
            other => bail!("device {device:?} answered a shard query with {other:?}"),
        }
    }

    /// Applies the partition rule to an assembled view: where one name appears
    /// twice, mark the newer creation and tell whoever holds it.
    ///
    /// The rule and its justification live on `Shard::mark_conflicted`;
    /// [`collisions`] computes it. This is only its execution.
    async fn settle_collisions(self: &Arc<Self>, node: &Node, rows: &mut [OrbitRow]) {
        let here = node.device_name().await;
        for (i, winner_device) in collisions(rows) {
            let (name, holder) = (
                rows[i].instance.name.clone(),
                rows[i].instance.cpu_device.clone(),
            );
            if rows[i].instance.conflict.is_none() {
                rows[i].instance.conflict = Some(asterism_core::instance::Conflict {
                    other_cpu_device: winner_device.clone(),
                    found_at: asterism_core::instance::now_unix(),
                });
            }
            // A row that came from the cache belongs to a device that is not
            // listening; it will find out when it is.
            if !rows[i].live {
                continue;
            }
            if holder == here {
                let mut shard = node.shard.lock().await;
                if shard.mark_conflicted(&name, &winner_device).is_ok() {
                    let _ = shard.save();
                }
            } else {
                let _ = self
                    .proxy(
                        &holder,
                        Request::MarkConflicted {
                            name,
                            other_cpu_device: winner_device,
                        },
                    )
                    .await;
            }
        }
    }

    /// A loopback port on *this* device that reaches the guest of an instance
    /// whose cpu and ram come from another one.
    ///
    /// This is `ast ssh dev` when `dev` is not here. The local daemon binds an
    /// ephemeral 127.0.0.1 listener and hands the CLI its port; every
    /// connection to it opens a mesh stream to the device supplying the
    /// guest's cpu, whose daemon connects to the guest's own forwarded ssh
    /// port and splices the two together. ssh's bytes are encrypted twice —
    /// once by ssh, once by QUIC — and nothing is exposed beyond loopback at
    /// either end.
    ///
    /// `None` when no device in the orbit has the instance at all; otherwise
    /// the local port, the key file that opens the guest, and the lease on the
    /// listener.
    #[allow(clippy::type_complexity)]
    pub async fn ssh_splice(
        self: &Arc<Self>,
        name: &str,
    ) -> Result<Option<(u16, String, Splice)>> {
        let Some(device) = self.locate(name).await? else {
            return Ok(None);
        };
        // Ask before binding anything, so "it is not running" is an error
        // about the instance rather than a connection that refuses later.
        let instance = match self.proxy(&device, Request::Status { name: name.to_owned() }).await? {
            Response::Instance { instance } => {
                if instance.endpoint().is_none() {
                    bail!("instance {name:?} is not running — `ast up {name}` first");
                }
                instance
            }
            Response::Error { message } => bail!(message),
            other => bail!("device {device:?} answered with {other:?}"),
        };

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .context("binding a local port for ssh")?;
        let port = listener.local_addr()?.port();

        // The guest only trusts the key of the device that *seeded* it, which
        // is not always the device running it: a cpu-part swap carries the
        // seed rather than rebuilding it. So the key comes from the seeding
        // device — which may well be this one.
        let seeder = instance.seeded_by().to_owned();
        let identity = if seeder == self.self_name().await {
            asterism_core::seed::ensure_asterism_key()
                .context("preparing this device's guest key")?;
            paths::ssh_key_path().display().to_string()
        } else {
            self.guest_key_of(&seeder).await?
        };

        let (mesh, name) = (self.clone(), name.to_owned());
        let task = tokio::spawn(async move {
            // A JoinSet, so that aborting this task takes every live ssh
            // session with it: the listener's lifetime is the command's.
            let mut sessions = tokio::task::JoinSet::new();
            loop {
                let Ok((tcp, _)) = listener.accept().await else { return };
                let (mesh, device, name) = (mesh.clone(), device.clone(), name.clone());
                sessions.spawn(async move {
                    if let Err(e) = splice_to_guest(&mesh, &device, &name, tcp).await {
                        eprintln!("astd: ssh splice to {name:?} failed: {e:#}");
                    }
                });
                // Reap finished sessions without waiting on any.
                while sessions.try_join_next().is_some() {}
            }
        });
        Ok(Some((port, identity, Splice::new(task, None))))
    }

    /// Carry one QEMU-to-NBD connection to the device holding a block volume.
    ///
    /// The same shape as [`Mesh::ssh_splice`]'s inner half, and deliberately
    /// so: one frame that says which volume, who is asking and at what epoch,
    /// one frame back that says yes or why not, and then a pipe. The fence is
    /// checked on the far side, where the lease is, because a check on this
    /// side would be a check by the party it is meant to constrain.
    pub async fn volume_splice(
        self: &Arc<Self>,
        device: &str,
        volume: &str,
        holder: &str,
        epoch: u64,
        local: tokio::net::UnixStream,
    ) -> Result<()> {
        let peer = self.device(device).await?;
        let connection = self.live_connection(&peer).await.with_context(|| {
            format!("{}: {device}", crate::volume::UNREACHABLE)
        })?;
        let mut stream = connection.open_stream().await?;
        write_frame(
            &mut stream.send,
            &MeshRequest::VolumeSplice {
                volume: volume.to_owned(),
                holder: holder.to_owned(),
                epoch,
            },
        )
        .await?;
        match read_frame::<MeshReply>(&mut stream.recv).await? {
            MeshReply::SpliceReady => {}
            MeshReply::Rpc { response: Response::Error { message } } => bail!(message),
            other => bail!("device {device:?} would not serve volume {volume:?}: {other:?}"),
        }
        pump(local, stream).await
    }

    // ---- moving an instance's cpu part --------------------------------------

    /// Is `name` a device this orbit has heard of?
    pub async fn knows(&self, name: &str) -> bool {
        self.orbit.lock().await.get(name).is_some()
    }

    /// Is it answering right now? The preflight a move runs before it takes
    /// an instance out of service.
    pub async fn online(self: &Arc<Self>, name: &str) -> bool {
        self.probe(name).await
    }

    /// Have `target` pull an instance's bytes from `source`, and relay what it
    /// says about it to the terminal.
    ///
    /// The bytes never come through here. This daemon is the one in front of
    /// the user, which may be neither end of the transfer; all it does is ask
    /// the target to fetch and then forward the progress. When it *is* the
    /// target, the fetch happens right here and the same lines come out.
    ///
    /// The corollary, and it is worth saying out loud: the source and the
    /// target have to be able to reach *each other*, not merely both reach
    /// whoever typed the command. An orbit is a set of mutually paired
    /// devices, so they normally can; when they cannot, the target's refusal
    /// arrives as "no device named ..." and nothing has moved.
    pub async fn move_import(
        self: &Arc<Self>,
        target: &str,
        source: &str,
        manifest: &MoveManifest,
        epoch: u64,
        io: &mut ClientIo<'_>,
    ) -> Result<()> {
        if target == self.self_name().await {
            let mut report = Reporter::Client(io);
            return import(self, manifest, epoch, source, &mut report).await;
        }

        let peer = self.device(target).await?;
        let connection = self.live_connection(&peer).await?;
        let mut stream = connection.open_stream().await?;
        write_frame(
            &mut stream.send,
            &MeshRequest::MoveImport {
                manifest: Box::new(manifest.clone()),
                epoch,
                from_device: source.to_owned(),
            },
        )
        .await?;
        let _ = stream.send.finish();

        loop {
            match read_frame::<MoveFrame>(&mut stream.recv)
                .await
                .with_context(|| format!("device {target:?} stopped answering mid-transfer"))?
            {
                MoveFrame::Progress { text, .. } => io.send(&swap::line(text)).await?,
                MoveFrame::End { .. } => return Ok(()),
                MoveFrame::Failed { message } => bail!(message),
                other => bail!("device {target:?} answered an import with {other:?}"),
            }
        }
    }

    /// Another device's guest key, cached on this one.
    ///
    /// Refreshed on every use rather than trusted once: a device that has
    /// regenerated its key would otherwise leave this holding one that no
    /// guest accepts, and the failure would look like a broken splice. A
    /// device that will not answer falls back to whatever was cached, which is
    /// the right answer if it is the same key and no worse than nothing if it
    /// is not.
    pub(crate) async fn guest_key_of(self: &Arc<Self>, device: &str) -> Result<String> {
        let path = paths::guest_key_cache(device);
        let peer = self.device(device).await?;
        let fetched = async {
            let connection = self.live_connection(&peer).await.ok()?;
            match ask(&connection, &MeshRequest::GuestKey).await.ok()? {
                MeshReply::GuestKey { key } => Some(key),
                _ => None,
            }
        }
        .await;

        if let Some(key) = fetched {
            // Written unreadable, then filled: ssh refuses a key file anyone
            // else on this machine could have read in the meantime — so the
            // mode is on the `open(2)`, not a `chmod` after it — and the
            // commit is durable, because a torn key file is an `ast ssh` that
            // fails with a parse error rather than a permission one.
            durable::commit_private(&path, key.as_bytes())?;
        }
        if !path.exists() {
            bail!(
                "device {device:?} would not share the key that opens {:?}'s guests",
                device
            );
        }
        set_private(&path)?;
        Ok(path.display().to_string())
    }

    /// The inviter's half of pairing: mint a ticket, print it, wait.
    ///
    /// Takes over the CLI connection for several frames — the ticket, then the
    /// code, then the verdict — because that is what the user's terminal is
    /// doing: printing, waiting, and asking.
    pub async fn invite(
        self: &Arc<Self>,
        name: Option<String>,
        ttl_secs: Option<u64>,
        io: &mut ClientIo<'_>,
    ) -> Result<()> {
        if let Some(name) = name {
            self.rename_self(&name).await?;
        }
        let ttl = ttl_secs.map(Duration::from_secs).unwrap_or(DEFAULT_TICKET_TTL);
        let addr = self.endpoint.direct_addr().await?;
        let mut issued = IssuedTicket::new(PairingTicket::issue(addr.clone(), ttl));

        let (tx, mut rx) = mpsc::channel(1);
        *self.pending.lock().await = Some(tx.clone());

        io.send(&Response::Ticket {
            ticket: issued.ticket().encode(),
            expires_in_secs: ttl.as_secs(),
        })
        .await?;

        let connection = tokio::time::timeout(ttl, rx.recv()).await;
        // The ticket is single-use, so the window closes on the first taker
        // whether or not the pairing then succeeds — but only *this* invite's
        // window: a second `ast device invite` has taken the slot over, and
        // closing that one on this one's way out would strand it.
        self.withdraw(&tx).await;
        let connection = connection
            .map_err(|_| anyhow!("nobody redeemed the ticket within {}s", ttl.as_secs()))?
            .ok_or_else(|| {
                anyhow!("this invitation was replaced by another `ast device invite`")
            })?;

        let peer = pairing::accept_connection(&self.endpoint, connection, &mut issued).await?;
        self.settle(peer, addr, Role::Inviter, io).await
    }

    /// The joiner's half of pairing: redeem a ticket someone else printed.
    pub async fn add(
        self: &Arc<Self>,
        ticket: &str,
        name: Option<String>,
        io: &mut ClientIo<'_>,
    ) -> Result<()> {
        let ticket = PairingTicket::decode(ticket)
            .map_err(|e| anyhow!("that does not look like a pairing ticket: {e}"))?;
        if let Some(name) = name {
            self.rename_self(&name).await?;
        }
        let addr = self.endpoint.direct_addr().await?;
        let peer = pairing::join(&self.endpoint, &ticket).await?;
        self.settle(peer, addr, Role::Joiner, io).await
    }

    /// Shows the user the code, waits for the verdict, exchanges names, and —
    /// only if both sides said yes — writes the peer to the orbit store.
    async fn settle(
        self: &Arc<Self>,
        peer: PairedPeer,
        my_addr: EndpointAddr,
        role: Role,
        io: &mut ClientIo<'_>,
    ) -> Result<()> {
        let peer_id = peer.device_id().to_string();
        io.send(&Response::Sas {
            code: peer.sas().grouped(),
            peer: peer.device_id().short(),
            device_id: peer_id.clone(),
        })
        .await?;

        let accepted = match io.next_request().await? {
            Request::PairConfirm { accept } => accept,
            other => bail!("expected a pairing confirmation, got {other:?}"),
        };

        let (addrs, relays) = addr_strings(&my_addr);
        let mine = Hello {
            accepted,
            name: self.self_name().await,
            addrs,
            relays,
            error: (!accepted).then(|| "the other device did not confirm the code".to_owned()),
            wake: crate::wake::facts(),
        };

        let theirs = tokio::time::timeout(
            PAIR_TIMEOUT,
            self.exchange(peer.connection(), mine, role, &peer_id),
        )
        .await
        .map_err(|_| anyhow!("the other device did not finish pairing in time"))??;

        peer.connection().close(b"paired");
        io.send(&Response::Paired { device: theirs }).await
    }

    /// The name exchange, and the orbit write it guards.
    ///
    /// Three frames rather than two, so that neither device ends up trusting a
    /// peer that did not trust it back: the joiner speaks, the inviter answers,
    /// the joiner acknowledges. A name clash or a declined code on *either*
    /// device aborts the pairing on *both*, which is the only version of this
    /// that leaves an orbit a set of mutual relationships.
    async fn exchange(
        &self,
        connection: &MeshConnection,
        mine: Hello,
        role: Role,
        peer_id: &str,
    ) -> Result<Device> {
        match role {
            Role::Joiner => self.exchange_as_joiner(connection, mine, peer_id).await?,
            Role::Inviter => self.exchange_as_inviter(connection, mine, peer_id).await?,
        }
        self.orbit
            .lock()
            .await
            .by_id(peer_id)
            .cloned()
            .ok_or_else(|| anyhow!("the paired device went missing from the orbit store"))
    }

    /// The joiner opened the pairing connection, so it opens this stream too
    /// and speaks first.
    async fn exchange_as_joiner(
        &self,
        connection: &MeshConnection,
        mine: Hello,
        peer_id: &str,
    ) -> Result<()> {
        let mut stream = connection.open_stream().await?;
        write_frame(&mut stream.send, &mine).await?;
        let theirs: Hello = read_frame(&mut stream.recv).await?;

        let outcome = if !mine.accepted {
            Err(anyhow!("you did not confirm the code"))
        } else if !theirs.accepted {
            Err(anyhow!("{}", theirs.error.as_deref().unwrap_or(REFUSED)))
        } else {
            self.stage(&theirs, peer_id).await
        };

        let ack = match &outcome {
            Ok(()) => Ack { ok: true, error: None },
            Err(e) => Ack { ok: false, error: Some(e.to_string()) },
        };
        write_frame(&mut stream.send, &ack).await?;
        let _ = stream.send.finish();
        // The inviter commits on this frame, so it has to land before the
        // connection goes away: a QUIC stream closed with data in flight
        // discards it.
        let _ = tokio::time::timeout(FLUSH_TIMEOUT, stream.send.stopped()).await;
        outcome
    }

    /// The inviter answers, and stages the peer before it knows whether the
    /// joiner will accept, then takes that back if it does not.
    async fn exchange_as_inviter(
        &self,
        connection: &MeshConnection,
        mine: Hello,
        peer_id: &str,
    ) -> Result<()> {
        let mut stream = connection.accept_stream().await?;
        let theirs: Hello = read_frame(&mut stream.recv).await?;

        let mut reply = mine;
        if !theirs.accepted {
            reply.accepted = false;
            reply.error = Some(theirs.error.clone().unwrap_or_else(|| REFUSED.to_owned()));
        } else if reply.accepted {
            if let Err(e) = self.stage(&theirs, peer_id).await {
                reply.accepted = false;
                reply.error = Some(e.to_string());
            }
        }

        // Answer whatever the verdict is: a refusal the joiner never receives
        // reads on its terminal as a hang.
        write_frame(&mut stream.send, &reply).await?;
        if !reply.accepted {
            let _ = stream.send.finish();
            let _ = tokio::time::timeout(FLUSH_TIMEOUT, stream.send.stopped()).await;
            bail!("{}", reply.error.unwrap_or_else(|| REFUSED.to_owned()));
        }

        let ack: Ack = read_frame(&mut stream.recv).await?;
        let _ = stream.send.finish();
        if !ack.ok {
            self.unstage(peer_id).await?;
            bail!("{}", ack.error.unwrap_or_else(|| REFUSED.to_owned()));
        }
        Ok(())
    }

    /// Takes back a staged peer, for when the other device refuses after this
    /// one has already written it down.
    async fn unstage(&self, peer_id: &str) -> Result<()> {
        let mut orbit = self.orbit.lock().await;
        let Some(name) = orbit.by_id(peer_id).map(|d| d.name.clone()) else {
            return Ok(());
        };
        orbit.remove(&name)?;
        orbit.save()
    }

    /// Writes a freshly paired peer to the orbit store.
    async fn stage(&self, hello: &Hello, peer_id: &str) -> Result<()> {
        let mut orbit = self.orbit.lock().await;
        let mut device = orbit::device_now(
            &hello.name,
            peer_id,
            hello.addrs.clone(),
            hello.relays.clone(),
        );
        device.wake = hello.wake.clone();
        orbit.add(device)?;
        orbit.save()
    }

    /// Closes the pairing window, if it is still the one `tx` opened.
    async fn withdraw(&self, tx: &mpsc::Sender<MeshConnection>) {
        let mut pending = self.pending.lock().await;
        if pending.as_ref().is_some_and(|held| held.same_channel(tx)) {
            *pending = None;
        }
    }

    /// Renames this device, refusing a name a peer already answers to.
    async fn rename_self(&self, name: &str) -> Result<()> {
        let mut orbit = self.orbit.lock().await;
        orbit.set_self_name(name)?;
        orbit.save()
    }

    /// The stored record for a device name.
    async fn device(&self, name: &str) -> Result<Device> {
        self.orbit
            .lock()
            .await
            .get(name)
            .cloned()
            .ok_or_else(|| anyhow!("no device named {name:?} in this orbit — see: ast devices"))
    }

    /// Whether a peer's daemon answers right now.
    async fn probe(&self, name: &str) -> bool {
        self.probe_path(name).await.is_some()
    }

    /// Whether a peer's daemon answers right now, and how its bytes get here.
    ///
    /// The path is read off the live connection rather than inferred from the
    /// mode, because inferring it is how `ast devices` ends up printing
    /// "direct" next to a link that is really costing somebody relay
    /// bandwidth. `Some(None)` cannot happen in practice — a connection that
    /// has just answered a ping has an open path — but it is representable, so
    /// it is spelled rather than unwrapped.
    async fn probe_path(&self, name: &str) -> Option<Option<PathKind>> {
        let device = self.device(name).await.ok()?;
        match tokio::time::timeout(PROBE_TIMEOUT, self.live_connection(&device)).await {
            Ok(Ok(connection)) => Some(connection.path()),
            _ => None,
        }
    }

    /// A connection to `device` that has just proved it is answering.
    ///
    /// The proof costs one sub-millisecond round trip and is what keeps a
    /// daemon that died while we held a warm connection from being discovered
    /// only when QUIC's idle timeout expires — half a minute later, in the
    /// middle of a command the user is watching. A cached connection that does
    /// not answer promptly is stale by definition, so it is dropped and the
    /// peer dialed again.
    async fn live_connection(&self, device: &Device) -> Result<MeshConnection> {
        let cached = self.conns.lock().await.get(&device.device_id).cloned();
        if let Some(cached) = cached {
            if let Ok(Ok(MeshReply::Pong)) =
                tokio::time::timeout(PROBE_TIMEOUT, ask(&cached, &MeshRequest::Ping)).await
            {
                return Ok(cached);
            }
            self.conns.lock().await.remove(&device.device_id);
        }

        let connection = self.dial(device).await?;
        tokio::time::timeout(PROBE_TIMEOUT, ask(&connection, &MeshRequest::Ping))
            .await
            .map_err(|_| {
                anyhow!("device {:?} answered the dial but not the mesh", device.name)
            })?
            // A device that refuses us closes the connection here, and its
            // reason ("not in this orbit") is the useful half of the message.
            .with_context(|| format!("could not reach device {:?}", device.name))?;

        self.conns
            .lock()
            .await
            .insert(device.device_id.clone(), connection.clone());
        // The address this connection came up on is the freshest fact about
        // the peer anyone has. Write it down before the next restart makes it
        // guesswork again.
        self.record_addrs(device).await;
        Ok(connection)
    }

    /// Dials `device` at the addresses the orbit store remembers, and — if
    /// that fails — at whatever discovery says about it now.
    ///
    /// The stored addresses are hints, and hints rot. A peer's daemon restarts
    /// on a new UDP port; a laptop moves from the office to a café; a router
    /// hands out a different lease. Under [`MeshMode::LocalOnly`] there was
    /// nothing to do about that and a moved peer was simply gone. Under
    /// discovery there is: the peer republishes its address record under its
    /// public key, so a dial by key alone finds it wherever it went. Declaring
    /// a device offline without having asked would be reporting a stale file
    /// as a fact about the world.
    ///
    /// Order matters for latency, not for correctness. A hint that still works
    /// is the fastest path there is, so it goes first — unless it is old
    /// enough ([`hint_is_stale`]) that waiting out a dial timeout on it is the
    /// likelier outcome, in which case discovery goes first and the hint is
    /// the fallback.
    async fn dial(&self, device: &Device) -> Result<MeshConnection> {
        let by_hint = endpoint_addr(device)?;
        let has_hints = !by_hint.is_empty();
        let discovery = self.endpoint.mode() == MeshMode::Discovery;

        if !discovery {
            return self.dial_addr(device, by_hint).await;
        }

        let peer = DeviceId::from_public_key(by_hint.id);
        if !has_hints || hint_is_stale(device) {
            match self.dial_discovered(device, peer).await {
                Ok(conn) => return Ok(conn),
                Err(e) if !has_hints => return Err(e),
                Err(_) => return self.dial_addr(device, by_hint).await,
            }
        }

        match self.dial_addr(device, by_hint).await {
            Ok(conn) => Ok(conn),
            Err(stored) => self.dial_discovered(device, peer).await.map_err(|found| {
                // Both messages matter: the first says the address on file did
                // not answer, the second says nobody knows a better one. Only
                // together do they mean "offline".
                anyhow!(
                    "{stored:#}; and discovery had no fresher address for it either: {found:#}"
                )
            }),
        }
    }

    /// One dial at one address.
    async fn dial_addr(&self, device: &Device, addr: EndpointAddr) -> Result<MeshConnection> {
        tokio::time::timeout(DIAL_TIMEOUT, self.endpoint.connect(addr))
            .await
            .map_err(|_| {
                anyhow!(
                    "device {:?} did not answer within {}s — is its astd running?",
                    device.name,
                    DIAL_TIMEOUT.as_secs()
                )
            })?
            .with_context(|| format!("could not reach device {:?}", device.name))
    }

    /// One dial by key alone, so the address comes from discovery.
    async fn dial_discovered(&self, device: &Device, peer: DeviceId) -> Result<MeshConnection> {
        tokio::time::timeout(DIAL_TIMEOUT, self.endpoint.connect_by_id(peer))
            .await
            .map_err(|_| {
                anyhow!(
                    "discovery did not find device {:?} within {}s",
                    device.name,
                    DIAL_TIMEOUT.as_secs()
                )
            })?
            .with_context(|| format!("could not reach device {:?} through discovery", device.name))
    }

    /// Writes down where a peer actually turned out to be.
    ///
    /// Called after every dial that worked, which is what keeps the store from
    /// decaying into a list of places peers used to be — and what makes the
    /// hint written at pairing time survive the peer's next restart on a
    /// different port. Best effort: a store that cannot be written is worth a
    /// line on stderr and nothing more, since the connection it would have
    /// described is up and working.
    async fn record_addrs(&self, device: &Device) {
        let Ok(key) = device.device_id.parse::<PublicKey>() else {
            return;
        };
        let Some(addr) = self.endpoint.peer_addr(DeviceId::from_public_key(key)).await else {
            return;
        };
        let (addrs, relays) = addr_strings(&addr);
        let mut orbit = self.orbit.lock().await;
        if orbit.refresh_addrs(
            &device.device_id,
            addrs,
            relays,
            asterism_core::instance::now_unix(),
        ) {
            if let Err(e) = orbit.save() {
                eprintln!("astd: could not record where {:?} answered from: {e:#}", device.name);
            }
        }
    }

    /// Says, once, where this device can be reached and whose infrastructure
    /// it is using to be reachable there.
    ///
    /// Under discovery this is also the moment the device's address record
    /// reaches the public directory — iroh's publisher republishes whenever
    /// the endpoint's address changes, and the home relay is the last part of
    /// that address to arrive. Printing it is how a user finds out, without
    /// reading the source, that their key and addresses are now on somebody's
    /// server.
    async fn announce(self: Arc<Self>) {
        if self.endpoint.mode() != MeshMode::Discovery {
            eprintln!("astd: mesh mode local — no relay, no discovery, nothing published");
            return;
        }
        let online = self.endpoint.online(ANNOUNCE_TIMEOUT).await;
        let infra = self.endpoint.infra().describe();
        if !online {
            eprintln!(
                "astd: discovery: no relay reachable yet via {infra} — peers on this LAN still \
                 work; set ASTERISM_MESH=local to stop trying"
            );
            return;
        }
        let relays = self.endpoint.home_relays().join(", ");
        eprintln!(
            "astd: discovery: published this device's key and addresses via {infra} \
             (home relay {relays}) — ASTERISM_MESH=local opts out"
        );
    }
}

/// Which rows in an assembled view lost a name collision, and which device
/// supplies cpu for the instance that beat them.
///
/// The rule is `Shard::mark_conflicted`'s: **the newer creation loses**. The
/// tie-break after `created_at` is the instance id, and that detail is load
/// bearing rather than tidy — two daemons assembling the same pair of shards
/// have to name the same loser, or each would decide the other's instance was
/// the broken one and both would demand a rename.
fn collisions(rows: &[OrbitRow]) -> Vec<(usize, String)> {
    let mut order: Vec<usize> = (0..rows.len()).collect();
    order.sort_by(|&a, &b| {
        let (a, b) = (&rows[a].instance, &rows[b].instance);
        a.name
            .cmp(&b.name)
            .then_with(|| a.created_at.cmp(&b.created_at))
            .then_with(|| a.id.cmp(&b.id))
    });

    let mut losers = Vec::new();
    for pair in order.windows(2) {
        let (winner, loser) = (&rows[pair[0]].instance, &rows[pair[1]].instance);
        if winner.name != loser.name || winner.id == loser.id {
            // Different names, or one row that turned up twice.
            continue;
        }
        losers.push((pair[1], winner.cpu_device.clone()));
    }
    losers
}

/// Which rows in an assembled view are stale copies of an instance that has
/// since moved: same instance id, lower move epoch.
///
/// This is not the name collision above, and the difference matters. Two
/// instances that happen to share a *name* are two computers and one of them
/// must be renamed. Two rows with the same *id* are one computer, seen twice
/// — a move whose source never got the word that the target had committed —
/// and there is nothing for a human to decide: the epoch was bumped by the
/// commit, so the higher one is where the instance is now.
///
/// A row with no epoch to compare (both at zero, which is every instance that
/// has never moved) is left alone: that is the id turning up twice for some
/// other reason, and dropping one on a guess would hide it.
fn superseded(rows: &[OrbitRow]) -> Vec<usize> {
    let mut best: HashMap<&str, (u64, usize)> = HashMap::new();
    let mut stale = Vec::new();
    for (i, row) in rows.iter().enumerate() {
        let epoch = row.instance.move_epoch;
        match best.get(row.instance.id.as_str()) {
            None => {
                best.insert(&row.instance.id, (epoch, i));
            }
            Some(&(held, at)) if epoch > held => {
                stale.push(at);
                best.insert(&row.instance.id, (epoch, i));
            }
            Some(&(held, _)) if epoch < held => stale.push(i),
            // Equal epochs on one id: not a move, and not ours to resolve.
            Some(_) => {}
        }
    }
    stale.sort_unstable();
    stale
}

// ---- splicing through the mesh ----------------------------------------------

/// A local listener spliced to another device's daemon, alive for exactly as
/// long as somebody holds this.
///
/// For `ast ssh` that holder is the unix connection that asked for it, and
/// `ast` keeps that connection open for exactly as long as `ssh` is running.
/// So the teardown is a drop: ssh exits, `ast` exits, the socket closes,
/// `serve` returns, this is dropped, the accept task is aborted, the listener
/// is unbound and every session under it goes with it.
///
/// For a block volume the holder is the daemon's own table of live bridges,
/// and the drop happens at `ast down`. A unix listener also leaves a file
/// behind, so that comes off here too — a socket nothing is listening on is a
/// trap for the next boot.
pub struct Splice {
    task: tokio::task::JoinHandle<()>,
    /// The unix socket to unlink on the way out, when the listener was one.
    socket: Option<std::path::PathBuf>,
}

impl Splice {
    pub fn new(task: tokio::task::JoinHandle<()>, socket: Option<std::path::PathBuf>) -> Self {
        Splice { task, socket }
    }
}

impl Drop for Splice {
    fn drop(&mut self) {
        self.task.abort();
        if let Some(socket) = &self.socket {
            let _ = std::fs::remove_file(socket);
        }
    }
}

/// One accepted loopback connection, carried to the guest's ssh port on
/// whichever device is supplying that guest's cpu.
async fn splice_to_guest(
    mesh: &Arc<Mesh>,
    device: &str,
    name: &str,
    tcp: tokio::net::TcpStream,
) -> Result<()> {
    let peer = mesh.device(device).await?;
    let connection = mesh.live_connection(&peer).await?;
    let mut stream = connection.open_stream().await?;
    write_frame(&mut stream.send, &MeshRequest::SshSplice { name: name.to_owned() }).await?;
    match read_frame::<MeshReply>(&mut stream.recv).await? {
        MeshReply::SpliceReady => {}
        MeshReply::Rpc { response: Response::Error { message } } => bail!(message),
        other => bail!("device {device:?} would not splice: {other:?}"),
    }
    pump(tcp, stream).await
}

/// Copies bytes both ways between a local connection and a mesh stream until
/// either end is done, then closes the other.
///
/// Deliberately dumb: past the one reply frame this is a pipe, and neither
/// daemon parses, buffers or logs what goes through it. ssh is already an
/// end-to-end encrypted protocol and we are not a party to it; NBD is a block
/// protocol and reading it would mean caring what a guest keeps on its disk.
///
/// Generic over the local side because there are two of them now — a TCP
/// socket for ssh, a unix socket for a volume — and the splice is the same
/// piece of plumbing either way.
pub(crate) async fn pump<L>(local: L, stream: asterism_mesh::MeshStream) -> Result<()>
where
    L: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + 'static,
{
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let (mut local_read, mut local_write) = tokio::io::split(local);
    let (mut send, mut recv) = stream.into_parts();

    let up = async move {
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let n = local_read.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            send.write_all(&buf[..n]).await?;
        }
        let _ = send.finish();
        Ok::<(), anyhow::Error>(())
    };
    let down = async move {
        let mut buf = vec![0u8; 64 * 1024];
        while let Some(n) = recv.read(&mut buf).await? {
            if n == 0 {
                break;
            }
            local_write.write_all(&buf[..n]).await?;
        }
        let _ = local_write.shutdown().await;
        Ok::<(), anyhow::Error>(())
    };

    // Whichever direction finishes first ends the session: an ssh that has
    // hung up, or a QEMU that has closed its NBD connection, is not waiting
    // for anything from the other side.
    tokio::select! {
        r = up => r,
        r = down => r,
    }
}

/// The far end of a splice: connect to the guest and become a pipe.
async fn serve_splice(
    mut stream: asterism_mesh::MeshStream,
    node: &Node,
    name: &str,
) -> Result<()> {
    // Resolved through the ordinary request path, so a conflicted or missing
    // instance refuses here in exactly the words it refuses everywhere else.
    let target = match crate::handle(Request::Status { name: name.to_owned() }, node).await {
        Response::Instance { instance } => instance
            .endpoint()
            .map(|e| e.ssh_target())
            .ok_or_else(|| anyhow!("instance {name:?} is not running — `ast up {name}` first")),
        Response::Error { message } => Err(anyhow!("{message}")),
        other => Err(anyhow!("{name:?} resolved to {other:?}")),
    };

    let (host, port) = match target {
        Ok(target) => target,
        Err(e) => {
            let refusal = MeshReply::Rpc {
                response: Response::Error { message: format!("{e:#}") },
            };
            write_frame(&mut stream.send, &refusal).await?;
            let _ = stream.send.finish();
            return Ok(());
        }
    };

    let tcp = tokio::net::TcpStream::connect((host.as_str(), port))
        .await
        .with_context(|| format!("connecting to {name:?}'s guest on {host}:{port}"))?;
    write_frame(&mut stream.send, &MeshReply::SpliceReady).await?;
    pump(tcp, stream).await
}

/// The provider's end of a volume splice: check the lease, then become a pipe.
///
/// A refusal goes back as an ordinary error frame, which is what makes a
/// fenced consumer's failure legible — QEMU sees its NBD connection close and
/// the reason is in the consumer's daemon log, in a sentence.
async fn serve_volume_splice(
    mut stream: asterism_mesh::MeshStream,
    volume: &str,
    holder: &str,
    epoch: u64,
) -> Result<()> {
    let export = match crate::volume::open_export(volume, holder, epoch).await {
        Ok(export) => export,
        Err(e) => {
            let refusal = MeshReply::Rpc {
                response: Response::Error { message: format!("{e:#}") },
            };
            write_frame(&mut stream.send, &refusal).await?;
            let _ = stream.send.finish();
            return Ok(());
        }
    };
    write_frame(&mut stream.send, &MeshReply::SpliceReady).await?;
    pump(export, stream).await
}

// ---- moving an instance's bytes ---------------------------------------------
//
// Sparse-aware, one file at a time, with the holes never leaving the source.
// See `crate::swap` for what a move is and why the bytes are the easy half.

/// How much payload rides behind one [`MoveFrame::Data`] frame.
///
/// A megabyte: large enough that the JSON control frame in front of it is
/// noise, small enough that a progress line is never more than a moment away
/// and neither daemon holds much of somebody's disk in memory.
const MOVE_CHUNK: usize = 1 << 20;

/// How often to say something while bytes are going past.
const MOVE_REPORT_EVERY: u64 = 32 << 20;

/// Where a move's progress lines go: to the terminal, or back up the import
/// stream to the daemon that is holding one.
enum Reporter<'a, 'b> {
    Client(&'a mut ClientIo<'b>),
    Stream(&'a mut SendStream),
}

impl Reporter<'_, '_> {
    async fn progress(&mut self, text: String, bytes: u64) -> Result<()> {
        match self {
            Reporter::Client(io) => io.send(&swap::line(text)).await,
            Reporter::Stream(send) => {
                write_frame(send, &MoveFrame::Progress { text, bytes }).await
            }
        }
    }
}

/// The target's half of a move: fetch the base if it is missing, then pull
/// the instance's directory into staging and write down what arrived.
///
/// Nothing this produces is bootable. The staging directory is named so that
/// no instance could be called that, no shard row points at it, and a daemon
/// that dies here leaves something the next start sweeps — which is the whole
/// reason a half-move cannot yield two bootable copies.
async fn import(
    mesh: &Arc<Mesh>,
    manifest: &MoveManifest,
    epoch: u64,
    from_device: &str,
    report: &mut Reporter<'_, '_>,
) -> Result<()> {
    let name = manifest.instance.name.clone();
    let staging = swap::staging_dir(&name, epoch);
    // An earlier attempt at this same epoch is not something to resume: the
    // manifest may have moved on and a half-file is worse than no file.
    let _ = std::fs::remove_dir_all(&staging);
    std::fs::create_dir_all(&staging)
        .with_context(|| format!("making {}", staging.display()))?;

    if swap::base_wanted(&manifest.base).unwrap_or(false) {
        fetch_base(mesh, from_device, manifest, report).await?;
    }

    let peer = mesh.device(from_device).await?;
    let connection = mesh.live_connection(&peer).await?;
    let mut stream = connection.open_stream().await?;
    write_frame(
        &mut stream.send,
        &MeshRequest::MoveExport { name: name.clone(), epoch },
    )
    .await?;
    let _ = stream.send.finish();

    let expected = manifest.allocated();
    let mut receipt = swap::Receipt {
        epoch,
        from_device: from_device.to_owned(),
        bytes: 0,
        files: Default::default(),
    };
    receive_into(&mut stream.recv, &staging, expected, &mut receipt, report).await?;

    if receipt.bytes != expected {
        bail!(
            "{} arrived and {} were expected — {from_device} and this device do not \
             agree about what {name:?} is made of",
            cow::human(receipt.bytes),
            cow::human(expected)
        );
    }
    receipt.save(&staging)?;
    report
        .progress(
            format!(
                "{} staged on this device in {} file(s), not yet adopted",
                cow::human(receipt.bytes),
                receipt.files.len()
            ),
            receipt.bytes,
        )
        .await
}

/// Pull a base image off the source rather than off the internet.
async fn fetch_base(
    mesh: &Arc<Mesh>,
    from_device: &str,
    manifest: &MoveManifest,
    report: &mut Reporter<'_, '_>,
) -> Result<()> {
    let base = &manifest.base;
    report
        .progress(
            format!(
                "fetching base image {} ({}) from {from_device} — an orbit peer that \
                 has it, not the internet",
                base.reference,
                cow::human(base.cost())
            ),
            0,
        )
        .await?;

    // Both before a byte moves: a digest this build cannot check, or a
    // reference that does not resolve here, has to refuse the fetch with the
    // store exactly as it was rather than after a gigabyte has landed in it.
    let expected = swap::wire_digest(&base.digest)?;
    let (path, record_at) = swap::base_landing(&base.reference)?;
    let staging = path.with_extension("raw.moving");
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let _ = std::fs::remove_file(&staging);

    let peer = mesh.device(from_device).await?;
    let connection = mesh.live_connection(&peer).await?;
    let mut stream = connection.open_stream().await?;
    write_frame(
        &mut stream.send,
        &MeshRequest::MoveBase { reference: base.reference.clone() },
    )
    .await?;
    let _ = stream.send.finish();

    let dir = staging.parent().unwrap_or(Path::new(".")).to_owned();
    let leaf = staging
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "base.moving".into());
    let mut receipt = swap::Receipt::default();
    // The wire name is ignored: a base image lands where *this* device's
    // image store says it goes, never where the sender says.
    receive_into_as(&mut stream.recv, &dir, &leaf, base.cost(), &mut receipt, report)
        .await?;

    // Adopted, not merely published. [`verify::adopt_recorded`] hashes the
    // staged file once against the manifest's digest, discards it and leaves
    // the store untouched if it does not match, commits the provenance record
    // durably, and only then gives the bytes the name the boot path looks
    // for. That ordering is the point: this is a peer fetch, so it is the one
    // adoption path in the tree that could reach the image store, and doing
    // the digest check by hand and renaming afterwards is exactly how it
    // used to land a base image nothing could account for — verified on
    // arrival, unbootable a second later.
    let source = Source::new("base-image", &base.reference)
        // The source's parents, on bytes proved identical to the source's.
        // Without them a reference the catalog pins would adopt cleanly and
        // still refuse to boot, because a pin is measured against what the
        // record says the bytes were derived from.
        .derived_from(base.derived_from.clone());
    verify::adopt_recorded(&staging, &path, &record_at, Some(&expected), source).with_context(
        || format!("adopting the base image {} fetched from {from_device}", base.reference),
    )?;
    report
        .progress(format!("base image {} verified and stored", base.reference), 0)
        .await
}

/// Read a stream of [`MoveFrame`]s into `root`, honouring the sender's paths.
async fn receive_into(
    recv: &mut RecvStream,
    root: &Path,
    expected: u64,
    receipt: &mut swap::Receipt,
    report: &mut Reporter<'_, '_>,
) -> Result<()> {
    receive(recv, root, None, expected, receipt, report).await
}

/// The same, but every byte goes into one file this device chose the name of.
async fn receive_into_as(
    recv: &mut RecvStream,
    root: &Path,
    leaf: &str,
    expected: u64,
    receipt: &mut swap::Receipt,
    report: &mut Reporter<'_, '_>,
) -> Result<()> {
    receive(recv, root, Some(leaf), expected, receipt, report).await
}

async fn receive(
    recv: &mut RecvStream,
    root: &Path,
    rename_to: Option<&str>,
    expected: u64,
    receipt: &mut swap::Receipt,
    report: &mut Reporter<'_, '_>,
) -> Result<()> {
    use std::io::{Seek, SeekFrom, Write};

    let mut open: Option<(String, std::fs::File)> = None;
    let mut buf = vec![0u8; MOVE_CHUNK];
    let mut next_report = MOVE_REPORT_EVERY;

    loop {
        match read_frame::<MoveFrame>(recv).await? {
            MoveFrame::File { path, len, mode } => {
                let leaf = rename_to.map(str::to_owned).unwrap_or_else(|| path.clone());
                let target = safe_join(root, &leaf)?;
                if let Some(dir) = target.parent() {
                    std::fs::create_dir_all(dir)?;
                }
                let file = std::fs::File::create(&target)
                    .with_context(|| format!("creating {}", target.display()))?;
                // The length first, then only the data: everything between
                // two extents stays a hole on this side too, which is why a
                // 10 GiB disk lands as a 10 GiB disk that costs a fraction of
                // it.
                file.set_len(len)?;
                set_mode(&target, mode)?;
                open = Some((path, file));
            }
            MoveFrame::Data { offset, len } => {
                let Some((_, file)) = open.as_mut() else {
                    bail!("a move sent bytes before it said what file they were for");
                };
                if len as usize > MOVE_CHUNK {
                    bail!("a move sent a {len}-byte chunk, larger than this daemon reads");
                }
                let n = len as usize;
                recv.read_exact(&mut buf[..n]).await?;
                file.seek(SeekFrom::Start(offset))?;
                file.write_all(&buf[..n])?;
                receipt.bytes += len;
                if receipt.bytes >= next_report {
                    next_report = receipt.bytes + MOVE_REPORT_EVERY;
                    report
                        .progress(
                            format!(
                                "{} of {} moved",
                                cow::human(receipt.bytes),
                                cow::human(expected)
                            ),
                            receipt.bytes,
                        )
                        .await?;
                }
            }
            MoveFrame::Done { path, written } => {
                let Some((open_path, file)) = open.take() else {
                    bail!("a move finished a file it had not started");
                };
                file.sync_all()?;
                if open_path != path {
                    bail!("a move finished {path:?} while {open_path:?} was open");
                }
                receipt.files.insert(path.clone(), written);
                report
                    .progress(
                        format!("{path}: {} carried", cow::human(written)),
                        receipt.bytes,
                    )
                    .await?;
            }
            MoveFrame::End { .. } => return Ok(()),
            MoveFrame::Failed { message } => bail!(message),
            MoveFrame::Progress { .. } => {}
        }
    }
}

/// A path off the wire becomes a path under `root`, or it becomes an error.
///
/// Every component has to be an ordinary name. `..`, an absolute path and a
/// symlink-shaped component are all refused rather than normalised, because a
/// move is one device writing into another's home directory and "probably
/// fine" is not a security property.
fn safe_join(root: &Path, relative: &str) -> Result<std::path::PathBuf> {
    let candidate = Path::new(relative);
    if relative.is_empty() || candidate.is_absolute() {
        bail!("a move named a file as {relative:?}, which is not a path inside an instance");
    }
    let mut out = root.to_path_buf();
    for part in candidate.components() {
        match part {
            std::path::Component::Normal(name) => out.push(name),
            _ => bail!("a move named a file as {relative:?}, which does not stay put"),
        }
    }
    Ok(out)
}

fn set_mode(path: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    // Whatever the sender says, never more than the owner. A disk image is
    // the guest's whole filesystem.
    let mode = mode & 0o700;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode | 0o600))
        .with_context(|| format!("setting permissions on {}", path.display()))
}

/// Send one file's allocated ranges and nothing else.
async fn send_file(send: &mut SendStream, path: &Path, wire_name: &str) -> Result<u64> {
    use std::io::{Read, Seek, SeekFrom};
    use std::os::unix::fs::PermissionsExt;

    let meta = std::fs::metadata(path)
        .with_context(|| format!("reading {}", path.display()))?;
    let extents = cow::extents(path)?;
    write_frame(
        send,
        &MoveFrame::File {
            path: wire_name.to_owned(),
            len: meta.len(),
            mode: meta.permissions().mode() & 0o777,
        },
    )
    .await?;

    let mut file = std::fs::File::open(path)?;
    let mut buf = vec![0u8; MOVE_CHUNK];
    let mut written = 0u64;
    for extent in extents {
        let mut offset = extent.offset;
        while offset < extent.end() {
            let n = ((extent.end() - offset) as usize).min(MOVE_CHUNK);
            file.seek(SeekFrom::Start(offset))?;
            file.read_exact(&mut buf[..n])?;
            write_frame(send, &MoveFrame::Data { offset, len: n as u64 }).await?;
            send.write_all(&buf[..n]).await?;
            offset += n as u64;
            written += n as u64;
        }
    }
    write_frame(send, &MoveFrame::Done { path: wire_name.to_owned(), written }).await?;
    Ok(written)
}

/// The source's half: prove the fence, then send the instance's directory.
///
/// The fence is the point. This device will only hand over an instance that
/// it has itself marked `moving` at exactly this epoch — which it does only
/// in answer to a `MovePrepare` — so an instance's disk cannot be pulled off
/// a device by a peer that merely asks for it.
async fn serve_move_export(
    mut stream: asterism_mesh::MeshStream,
    node: &Node,
    name: &str,
    epoch: u64,
) -> Result<()> {
    let instance = {
        let reg = node.shard.lock().await;
        reg.get(name).cloned()
    };
    let fenced = instance.and_then(|inst| match &inst.moving {
        Some(moving) if moving.epoch == epoch => Ok(inst),
        Some(moving) => Err(anyhow!(
            "instance {name:?} is being moved at epoch {}, not {epoch}",
            moving.epoch
        )),
        None => Err(anyhow!(
            "instance {name:?} is not being moved from this device — its bytes are \
             not on offer"
        )),
    });

    let instance = match fenced {
        Ok(instance) => instance,
        Err(e) => return fail(&mut stream.send, e).await,
    };

    let manifest = match swap::manifest(&instance) {
        Ok(manifest) => manifest,
        Err(e) => return fail(&mut stream.send, e).await,
    };
    let dir = paths::instance_dir(name);
    let mut bytes = 0u64;
    for file in &manifest.files {
        match send_file(&mut stream.send, &dir.join(&file.path), &file.path).await {
            Ok(written) => bytes += written,
            Err(e) => return fail(&mut stream.send, e).await,
        }
    }
    write_frame(
        &mut stream.send,
        &MoveFrame::End { files: manifest.files.len() as u64, bytes },
    )
    .await?;
    let _ = stream.send.finish();
    let _ = tokio::time::timeout(FLUSH_TIMEOUT, stream.send.stopped()).await;
    Ok(())
}

/// The peer fetch: hand a base image to another device in this orbit.
async fn serve_move_base(
    mut stream: asterism_mesh::MeshStream,
    reference: &str,
) -> Result<()> {
    let base = match crate::backend::image_ref(reference) {
        Ok(base) if base.path.exists() => base,
        Ok(base) => {
            return fail(
                &mut stream.send,
                anyhow!("this device has no copy of {} to hand over", base.name),
            )
            .await
        }
        Err(e) => return fail(&mut stream.send, e).await,
    };
    // Named by its reference rather than by this device's filename: the asker
    // puts it wherever its own image store says, and the name on the wire is
    // only there so a progress line can say which image is going past.
    if let Err(e) = send_file(&mut stream.send, &base.path, &base.name).await {
        return fail(&mut stream.send, e).await;
    }
    write_frame(&mut stream.send, &MoveFrame::End { files: 1, bytes: 0 }).await?;
    let _ = stream.send.finish();
    let _ = tokio::time::timeout(FLUSH_TIMEOUT, stream.send.stopped()).await;
    Ok(())
}

/// The target's half, driven from the daemon in front of the user: fetch, and
/// report up this stream as it goes.
async fn serve_move_import(
    mut stream: asterism_mesh::MeshStream,
    manifest: &MoveManifest,
    epoch: u64,
    from_device: &str,
) -> Result<()> {
    let mesh = match crate::swap::mesh() {
        Ok(mesh) => mesh,
        Err(e) => return fail(&mut stream.send, e).await,
    };
    let mut report = Reporter::Stream(&mut stream.send);
    let outcome = import(&mesh, manifest, epoch, from_device, &mut report).await;
    match outcome {
        Ok(()) => {
            write_frame(
                &mut stream.send,
                &MoveFrame::End {
                    files: manifest.files.len() as u64,
                    bytes: manifest.allocated(),
                },
            )
            .await?
        }
        Err(e) => {
            // Whatever is staged is not bootable, but leaving it would be
            // litter: the abort that follows removes it, and so does the next
            // daemon start if the abort never arrives.
            return fail(&mut stream.send, e).await;
        }
    }
    let _ = stream.send.finish();
    let _ = tokio::time::timeout(FLUSH_TIMEOUT, stream.send.stopped()).await;
    Ok(())
}

/// End a data stream with a sentence rather than a truncation.
async fn fail(send: &mut SendStream, e: anyhow::Error) -> Result<()> {
    write_frame(send, &MoveFrame::Failed { message: format!("{e:#}") }).await?;
    let _ = send.finish();
    let _ = tokio::time::timeout(FLUSH_TIMEOUT, send.stopped()).await;
    Ok(())
}

/// Locks a key file down to mode 0600. ssh refuses one that anyone else on the
/// machine can read, and it is right to.
fn set_private(path: &std::path::Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .with_context(|| format!("securing {}", path.display()))
}

/// This device's guest key, for a peer that needs to open a guest we seeded.
fn guest_key() -> Result<String> {
    asterism_core::seed::ensure_asterism_key().context("preparing this device's guest key")?;
    std::fs::read_to_string(paths::ssh_key_path()).context("reading this device's guest key")
}

/// The peers' shards as this device last saw them.
///
/// A cache and nothing more: losing it costs a device's instances their row in
/// `ast ls` while that device is unreachable, and nothing else. It is written
/// whenever a peer answers, so it is as fresh as the last time anybody looked.
#[derive(Debug, Default, Serialize, Deserialize)]
struct ShardCache {
    #[serde(default)]
    shards: std::collections::BTreeMap<String, Vec<Instance>>,
}

impl ShardCache {
    fn load() -> Self {
        std::fs::read(paths::shard_cache_path())
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }

    fn remember(&mut self, device: &str, instances: &[Instance]) {
        self.shards.insert(device.to_owned(), instances.to_vec());
    }

    fn last_seen(&self, device: &str) -> Vec<Instance> {
        self.shards.get(device).cloned().unwrap_or_default()
    }

    /// Committed like everything else, and read back with none of the
    /// ceremony: this is the one file in `ASTERISM_HOME` that really is a
    /// cache. A shard cache that will not parse costs a row printed as
    /// `unknown` until the device it names answers again, so [`Self::load`]
    /// starts empty rather than refusing or reaching for the copy the commit
    /// leaves beside it.
    fn save(&self) -> Result<()> {
        durable::commit_json(&paths::shard_cache_path(), self)
    }
}

/// Which end of a pairing this daemon is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Role {
    /// Printed the ticket.
    Inviter,
    /// Redeemed it.
    Joiner,
}

// ---- accepting -------------------------------------------------------------

/// The inbound loop: every connection is classified before it is served.
async fn accept_loop(mesh: Arc<Mesh>, node: Node) {
    while let Some(incoming) = mesh.endpoint.accept().await {
        let connection = match incoming {
            Ok(c) => c,
            Err(e) => {
                eprintln!("astd: mesh connection failed: {e:#}");
                continue;
            }
        };
        let peer = connection.remote_device_id();
        let peer_id = peer.to_string();

        if mesh.orbit.lock().await.trusts(&peer_id) {
            tokio::spawn(serve_peer(connection, node.clone()));
            continue;
        }

        // The one unauthenticated path in the daemon, and it exists only while
        // a ticket this device minted is outstanding. The token in that ticket
        // is what actually authorizes the peer; this only routes it.
        let waiting = mesh.pending.lock().await.take();
        if let Some(tx) = waiting {
            if tx.send(connection).await.is_ok() {
                continue;
            }
            eprintln!("astd: a device turned up after the invite had gone away");
            continue;
        }

        eprintln!(
            "astd: refusing a mesh connection from {} — not in this orbit",
            peer.short()
        );
        connection.close(REFUSAL);
    }
}

/// Serves streams from one trusted peer until it goes away.
async fn serve_peer(connection: MeshConnection, node: Node) {
    let peer = connection.remote_device_id().short();
    loop {
        let stream = match connection.accept_stream().await {
            Ok(s) => s,
            // The normal end of a peer's visit.
            Err(_) => return,
        };
        let node = node.clone();
        let peer = peer.clone();
        tokio::spawn(async move {
            if let Err(e) = serve_stream(stream, node).await {
                eprintln!("astd: mesh stream from {peer} failed: {e:#}");
            }
        });
    }
}

/// One request frame in, one reply frame out — except a splice, which answers
/// once and then stops being a request/reply stream at all.
async fn serve_stream(mut stream: asterism_mesh::MeshStream, node: Node) -> Result<()> {
    let reply = match read_frame::<MeshRequest>(&mut stream.recv).await? {
        MeshRequest::Ping => MeshReply::Pong,
        MeshRequest::SshSplice { name } => return serve_splice(stream, &node, &name).await,
        MeshRequest::VolumeSplice { volume, holder, epoch } => {
            return serve_volume_splice(stream, &volume, &holder, epoch).await
        }
        // Bulk, not request/reply: each of these stops being a framed RPC
        // after this line and becomes a stream of `MoveFrame`s.
        MeshRequest::MoveExport { name, epoch } => {
            return serve_move_export(stream, &node, &name, epoch).await
        }
        MeshRequest::MoveBase { reference } => {
            return serve_move_base(stream, &reference).await
        }
        MeshRequest::MoveImport { manifest, epoch, from_device } => {
            return serve_move_import(stream, &manifest, epoch, &from_device).await
        }
        MeshRequest::GuestKey => match guest_key() {
            Ok(key) => MeshReply::GuestKey { key },
            Err(e) => MeshReply::Rpc {
                response: Response::Error { message: format!("{e:#}") },
            },
        },
        MeshRequest::Rpc { request } => MeshReply::Rpc {
            response: match request {
                // A device serves its own shard, never somebody else's:
                // relaying would make the orbit a network we would then have
                // to write routing for. It is also what stops a forwarded
                // request from resolving all over again when it lands.
                Request::Proxy { device, .. } => Response::Error {
                    message: format!("this device cannot pass a request on to {device:?}"),
                },
                // About this device's NIC rather than about its shard, so
                // they stop here instead of going on to `crate::handle`. The
                // membership check they rest on is the accept loop's: this
                // stream exists only because the peer's key is in the orbit
                // store, which is the same bar every other forwarded request
                // clears.
                Request::WakeBroadcast { mac, lan_id } => {
                    match crate::wake::broadcast(&mac, lan_id.as_deref()) {
                        Ok(sent) => Response::Wake { text: sent.join(", "), done: true },
                        Err(e) => Response::Error { message: format!("{e:#}") },
                    }
                }
                Request::DeviceFacts => Response::WakeFacts { facts: crate::wake::facts() },
                Request::DeviceCheck => Response::WakeCheck {
                    device: node.device_name().await,
                    rows: crate::wake::check(),
                },
                request => crate::handle(request, &node).await,
            },
        },
    };
    write_frame(&mut stream.send, &reply).await?;
    let _ = stream.send.finish();
    Ok(())
}

/// Asks one question on a new stream and reads the answer.
async fn ask(connection: &MeshConnection, request: &MeshRequest) -> Result<MeshReply> {
    let mut stream = connection.open_stream().await?;
    write_frame(&mut stream.send, request).await?;
    let _ = stream.send.finish();
    read_frame(&mut stream.recv).await
}

// ---- the CLI end of a conversation -----------------------------------------

/// The unix socket, for the requests that are a conversation rather than a
/// question: `ast device invite` prints a ticket, then a code, then asks.
pub struct ClientIo<'a> {
    /// Frames the CLI has yet to send, bounded and deadlined by the same
    /// seam every other request comes through — a conversation is a longer
    /// visit through the same door, not a second door.
    pub frames: &'a mut crate::transport::Frames,
    /// The reply half.
    pub write: &'a mut crate::transport::Writer,
}

impl ClientIo<'_> {
    /// Sends one response line.
    pub async fn send(&mut self, response: &Response) -> Result<()> {
        self.write.send(response).await
    }

    /// Reads the CLI's next request.
    async fn next_request(&mut self) -> Result<Request> {
        use crate::transport::Framing;
        loop {
            let line = match self.frames.next().await? {
                Framing::Frame(line) => line,
                Framing::Eof => bail!("ast closed the connection mid-pairing"),
                Framing::Refused(why) => bail!("{why}"),
            };
            if line.trim().is_empty() {
                continue;
            }
            return serde_json::from_str(&line).context("bad request");
        }
    }
}

// ---- plumbing --------------------------------------------------------------

/// How this daemon reaches the world.
///
/// The default is discovery: relays and address lookup, so two devices on
/// different networks behind different NATs can pair and talk without anyone
/// forwarding a port. That is the mode a user gets and the mode Phase 2 is
/// about.
///
/// `ASTERISM_MESH=local` is loopback only — the mode the tests want, the
/// roadmap's "bring your own route", and the opt-out from publishing this
/// device's key and addresses to a public discovery service. Anything else,
/// including an unreadable value, is discovery, because a typo must not
/// silently strand a device in a mode where nothing outside the house can
/// reach it.
///
/// Whose relays and whose directory is a separate question, answered by
/// `MeshInfra` in `asterism-mesh` — today n0's, with the environment seam that
/// lets our own take over.
fn mesh_mode() -> MeshMode {
    mesh_mode_from(std::env::var(MESH_MODE_ENV).ok().as_deref())
}

/// The rule itself, separated from where the string comes from so it can be
/// tested without a process-global environment variable.
fn mesh_mode_from(setting: Option<&str>) -> MeshMode {
    match setting {
        Some("local") => MeshMode::LocalOnly,
        _ => MeshMode::Discovery,
    }
}

/// Rebuilds a dialable address from what the orbit store remembers.
fn endpoint_addr(device: &Device) -> Result<EndpointAddr> {
    let key: PublicKey = device
        .device_id
        .parse()
        .map_err(|e| anyhow!("device {:?} has an unreadable device id: {e}", device.name))?;
    let mut addr = EndpointAddr::new(key);
    for hint in &device.addrs {
        let socket = hint
            .parse()
            .map_err(|e| anyhow!("device {:?} has an unreadable address {hint:?}: {e}", device.name))?;
        addr = addr.with_ip_addr(socket);
    }
    for relay in &device.relays {
        let url = relay
            .parse()
            .map_err(|e| anyhow!("device {:?} has an unreadable relay {relay:?}: {e}", device.name))?;
        addr = addr.with_relay_url(url);
    }
    Ok(addr)
}

/// The word `ast devices` and `ast ping` print for a path.
///
/// A dash is "no path", which is a different statement from "direct" and has
/// to stay distinguishable from it: the first means the device did not answer,
/// the second means it did.
fn path_word(path: Option<PathKind>) -> String {
    path.map(|p| p.as_str()).unwrap_or("-").to_owned()
}

/// Whether a stored address hint is old enough that discovery should be asked
/// first rather than second.
///
/// Not a correctness rule — a stale hint that still works is still a working
/// hint, and dialling it costs nothing. It is a latency rule: a hint from
/// three weeks ago is more likely to be a dead port than a live one, and
/// spending [`DIAL_TIMEOUT`] finding that out before asking discovery is the
/// slow path taken in the common case of a laptop that has moved.
fn hint_is_stale(device: &Device) -> bool {
    let now = asterism_core::instance::now_unix();
    // A record written before `addrs_seen_at` existed has nothing to say about
    // its own age; treat it as current rather than as ancient, since it is the
    // pairing address and pairing addresses usually work.
    device.addrs_seen_at != 0 && now.saturating_sub(device.addrs_seen_at) > STALE_ADDR_AGE.as_secs()
}

/// Flattens an address into the strings the orbit store keeps.
fn addr_strings(addr: &EndpointAddr) -> (Vec<String>, Vec<String>) {
    (
        addr.ip_addrs().map(|a| a.to_string()).collect(),
        addr.relay_urls().map(|r| r.to_string()).collect(),
    )
}

async fn write_frame<T: Serialize>(send: &mut SendStream, value: &T) -> Result<()> {
    let bytes = serde_json::to_vec(value)?;
    send.write_all(&(bytes.len() as u32).to_be_bytes()).await?;
    send.write_all(&bytes).await?;
    Ok(())
}

async fn read_frame<T: serde::de::DeserializeOwned>(recv: &mut RecvStream) -> Result<T> {
    let mut len = [0u8; 4];
    recv.read_exact(&mut len).await?;
    let len = u32::from_be_bytes(len) as usize;
    if len > MAX_FRAME {
        bail!("a mesh frame of {len} bytes is larger than this daemon will read");
    }
    let mut buf = vec![0u8; len];
    recv.read_exact(&mut buf).await?;
    Ok(serde_json::from_slice(&buf)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_machine() -> asterism_core::hv::Machine {
        asterism_core::hv::Machine {
            backend: "qemu".into(),
            machine_type: "virt".into(),
            cpu: "host".into(),
            hv_version: "test".into(),
        }
    }

    fn device(addrs: &[&str], relays: &[&str]) -> Device {
        orbit::device_now(
            "desktop",
            &DeviceIdentity::generate().device_id().to_string(),
            addrs.iter().map(|s| s.to_string()).collect(),
            relays.iter().map(|s| s.to_string()).collect(),
        )
    }

    #[test]
    fn a_stored_device_round_trips_into_a_dialable_address() {
        let stored = device(&["127.0.0.1:4242"], &[]);
        let addr = endpoint_addr(&stored).unwrap();
        assert_eq!(addr.id.to_string(), stored.device_id);

        let (addrs, relays) = addr_strings(&addr);
        assert_eq!(addrs, ["127.0.0.1:4242"]);
        assert!(relays.is_empty());
    }

    #[test]
    fn a_corrupt_address_hint_names_the_device_it_came_from() {
        let stored = device(&["not-an-address"], &[]);
        let err = endpoint_addr(&stored).unwrap_err().to_string();
        assert!(err.contains("desktop"), "{err}");
        assert!(err.contains("unreadable address"), "{err}");
    }

    #[test]
    fn the_mesh_reaches_the_world_unless_told_to_stay_home() {
        // Discovery is the default because an orbit whose devices are on two
        // networks is the product; a device that could only ever talk to its
        // own LAN unless a variable was set would be a toy. The cost is that
        // the default publishes this device's key and addresses to a public
        // directory, which `local` is the way out of, and which the daemon
        // says on stderr at startup rather than leaving to be discovered.
        assert_eq!(mesh_mode_from(None), MeshMode::Discovery);
        assert_eq!(mesh_mode_from(Some("discovery")), MeshMode::Discovery);
        assert_eq!(mesh_mode_from(Some("local")), MeshMode::LocalOnly);
        // A typo must not strand a device where nothing can reach it. It is
        // the loud, reachable mode that is safe to guess wrong.
        assert_eq!(mesh_mode_from(Some("locall")), MeshMode::Discovery);
        assert_eq!(mesh_mode_from(Some("")), MeshMode::Discovery);
    }

    #[test]
    fn a_pairing_address_is_trusted_until_it_is_a_day_old() {
        let now = asterism_core::instance::now_unix();

        let mut fresh = device(&["127.0.0.1:4242"], &[]);
        fresh.addrs_seen_at = now;
        assert!(!hint_is_stale(&fresh));

        let mut old = device(&["127.0.0.1:4242"], &[]);
        old.addrs_seen_at = now - (2 * 24 * 60 * 60);
        assert!(hint_is_stale(&old), "a two-day-old hint is worth a lookup first");

        // A store written before the timestamp existed says nothing about its
        // own age, and "unknown" must not read as "ancient": that record is
        // the pairing address, which usually still works.
        let mut silent = device(&["127.0.0.1:4242"], &[]);
        silent.addrs_seen_at = 0;
        assert!(!hint_is_stale(&silent));
    }

    #[test]
    fn a_path_is_a_dash_only_when_there_is_no_path() {
        assert_eq!(path_word(Some(PathKind::Direct)), "direct");
        assert_eq!(path_word(Some(PathKind::Relay)), "relay");
        assert_eq!(path_word(None), "-");
    }

    #[test]
    fn an_rpc_frame_carries_the_request_enum_unchanged() {
        let frame = serde_json::to_string(&MeshRequest::Rpc { request: Request::List }).unwrap();
        assert_eq!(frame, r#"{"kind":"rpc","request":{"cmd":"list"}}"#);
    }

    /// Two endpoints on loopback, one serving a shard, the other asking.
    async fn wired() -> (MeshEndpoint, MeshConnection, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let node = Node {
            shard: Arc::new(Mutex::new(
                asterism_core::registry::Shard::load(&dir.path().join("state.json")).unwrap(),
            )),
            orbit: Arc::new(Mutex::new(
                Orbit::load(&dir.path().join("orbit.json")).unwrap(),
            )),
        };

        let server = MeshEndpoint::bind(&DeviceIdentity::generate(), MeshMode::LocalOnly)
            .await
            .unwrap();
        let client = MeshEndpoint::bind(&DeviceIdentity::generate(), MeshMode::LocalOnly)
            .await
            .unwrap();
        let addr = server.direct_addr().await.unwrap();

        tokio::spawn(async move {
            let conn = server.accept().await.unwrap().unwrap();
            serve_peer(conn, node).await;
        });

        let connection = client.connect(addr).await.unwrap();
        (client, connection, dir)
    }

    #[tokio::test]
    async fn a_request_survives_the_trip_over_a_mesh_stream() {
        let (client, connection, _dir) = wired().await;

        // The point of the whole design: the far daemon answers the frame the
        // near one would have answered, so `ls` needed no remote counterpart.
        let reply = ask(&connection, &MeshRequest::Rpc { request: Request::List })
            .await
            .unwrap();
        match reply {
            MeshReply::Rpc { response: Response::Instances { instances } } => {
                assert!(instances.is_empty(), "a fresh registry has no instances");
            }
            other => panic!("expected an instance list, got {other:?}"),
        }

        assert!(matches!(
            ask(&connection, &MeshRequest::Ping).await.unwrap(),
            MeshReply::Pong
        ));

        connection.close(b"done");
        client.close().await;
    }

    fn row(name: &str, cpu_device: &str, created_at: u64, live: bool) -> OrbitRow {
        let mut instance = Instance::new(
            name,
            cpu_device,
            "debian:13",
            Default::default(),
            test_machine(),
        );
        instance.created_at = created_at;
        OrbitRow { instance, live }
    }

    /// The partition rule, which is the whole of what happens when two
    /// devices that could not see each other both admitted the same name.
    #[test]
    fn the_newer_of_two_instances_sharing_a_name_is_the_one_that_loses() {
        let rows = vec![
            row("dev", "desktop", 100, true),
            row("dev", "laptop", 200, true),
            row("other", "laptop", 150, true),
        ];
        let losers = collisions(&rows);
        assert_eq!(losers.len(), 1, "one collision, one loser");
        assert_eq!(losers[0].0, 1, "the later creation loses");
        assert_eq!(losers[0].1, "desktop", "and is told where the winner's cpu is");
    }

    /// Both devices compute this independently and must agree, or each would
    /// decide the other's instance was the broken one.
    #[test]
    fn two_instances_created_in_the_same_second_still_have_one_loser() {
        let mut rows = vec![row("dev", "desktop", 100, true), row("dev", "laptop", 100, true)];
        rows[0].instance.id = "aaaa".into();
        rows[1].instance.id = "bbbb".into();

        let forward = collisions(&rows);
        rows.swap(0, 1);
        let backward = collisions(&rows);

        assert_eq!(forward.len(), 1);
        assert_eq!(backward.len(), 1);
        // Whichever order the shards arrived in, the same instance loses.
        assert_eq!(rows[backward[0].0].instance.id, "bbbb");
        assert_eq!(forward[0].1, backward[0].1, "and agrees on the winner");
    }

    /// A move that half-committed leaves one instance on two devices. That
    /// is not a name collision — it is one computer seen twice — and the
    /// epoch the commit bumped says which sighting is current.
    #[test]
    fn the_higher_move_epoch_settles_two_rows_for_one_instance() {
        let mut rows = vec![row("dev", "laptop", 100, true), row("dev", "desktop", 100, true)];
        rows[0].instance.id = "same".into();
        rows[1].instance.id = "same".into();
        rows[1].instance.move_epoch = 1;

        assert_eq!(superseded(&rows), vec![0], "the stale copy is the older epoch");
        // And whichever order the shards answered in.
        rows.swap(0, 1);
        assert_eq!(superseded(&rows), vec![1]);

        // Two rows at the same epoch are not a move, and guessing between
        // them would hide whatever they really are.
        rows[1].instance.move_epoch = 1;
        assert!(superseded(&rows).is_empty());

        // Nor is a plain collision: two different instances, two ids.
        let separate = vec![row("dev", "laptop", 100, true), row("dev", "desktop", 200, true)];
        assert!(superseded(&separate).is_empty());
        assert_eq!(collisions(&separate).len(), 1, "that one is the rename case");
    }

    #[test]
    fn a_name_that_appears_once_is_never_a_collision() {
        let rows = vec![
            row("dev", "desktop", 100, true),
            row("build", "laptop", 200, false),
        ];
        assert!(collisions(&rows).is_empty());

        // Nor is one row that turned up in two answers.
        let dup = vec![rows[0].clone(), rows[0].clone()];
        assert!(collisions(&dup).is_empty(), "the same instance is not its own rival");
    }

    /// A device that is out of touch keeps its instances in the listing. The
    /// alternative — dropping them — reads as "deleted", which is a lie.
    #[test]
    fn the_shard_cache_stands_in_for_a_device_that_is_not_answering() {
        let mut cache = ShardCache::default();
        assert!(cache.last_seen("desktop").is_empty());

        let shard = vec![Instance::new(
            "dev",
            "desktop",
            "debian:13",
            Default::default(),
            test_machine(),
        )];
        cache.remember("desktop", &shard);
        assert_eq!(cache.last_seen("desktop")[0].name, "dev");
        assert_eq!(cache.last_seen("desktop")[0].cpu_device, "desktop");

        // It is a snapshot of that device, so a later answer replaces it
        // rather than accumulating rows that no longer exist.
        cache.remember("desktop", &[]);
        assert!(cache.last_seen("desktop").is_empty());
    }

    /// The one frame that turns a stream into a pipe has to refuse in words
    /// before it stops speaking words — a splice that just hangs would look
    /// to the user like ssh dialling into nothing.
    #[tokio::test]
    async fn a_splice_to_an_instance_that_is_not_here_is_refused_in_words() {
        let (client, connection, _dir) = wired().await;

        let mut stream = connection.open_stream().await.unwrap();
        write_frame(&mut stream.send, &MeshRequest::SshSplice { name: "ghost".into() })
            .await
            .unwrap();
        let reply: MeshReply = read_frame(&mut stream.recv).await.unwrap();

        match reply {
            MeshReply::Rpc { response: Response::Error { message } } => {
                assert!(message.contains("ghost"), "{message}");
                assert!(message.contains("in this orbit"), "{message}");
            }
            other => panic!("expected a refusal, got {other:?}"),
        }

        connection.close(b"done");
        client.close().await;
    }

    #[tokio::test]
    async fn a_device_will_not_pass_a_request_on_to_a_third() {
        let (client, connection, _dir) = wired().await;

        let reply = ask(
            &connection,
            &MeshRequest::Rpc {
                request: Request::Proxy {
                    device: "somewhere-else".into(),
                    inner: Box::new(Request::List),
                },
            },
        )
        .await
        .unwrap();

        match reply {
            MeshReply::Rpc { response: Response::Error { message } } => {
                assert!(message.contains("somewhere-else"), "{message}");
            }
            other => panic!("relaying must be refused, got {other:?}"),
        }

        connection.close(b"done");
        client.close().await;
    }
}
