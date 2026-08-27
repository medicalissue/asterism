//! The optional hosted coordinator client.
//!
//! Signing in buys one thing: a private directory. An enrolled device publishes
//! the addresses it currently answers on to its own account and resolves its
//! peers from that same account, so two machines on different networks find
//! each other without anyone publishing a key to a public directory. Not
//! signing in means no directory and no relay unless the operator configured
//! one explicitly. Neither mode changes who is trusted.
//!
//! Three rules shape everything here.
//!
//! 1. The coordinator never sees a key that can decrypt orbit traffic. It sees
//!    public mesh keys, chosen endpoints, and presence.
//! 2. Nothing blocks on it. Every call is best effort on a background task; a
//!    coordinator that is down is a directory that does not refresh, not an
//!    orbit that stops working.
//! 3. It cannot grant trust. Enrollment tells this device that the account
//!    knows a key. Only a pairing ticket — or an explicit opt-in recorded
//!    here — puts a key in `orbit.json`.
//!
//! The bearer is deliberately not persisted. `ast` owns the OS credential
//! store and hands the daemon a session in memory; a daemon restart therefore
//! keeps the enrollment (which is durable on both sides) and loses only the
//! live session, which `ast auth login` or `ast auth enroll` re-arms.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use asterism_coordinator::{DiscoveryConfig, EndpointHints};
use asterism_core::instance::now_unix;
use asterism_core::paths;
use asterism_core::protocol::{
    HostedPeerStatus, HostedPresence, HostedStatus, RedactedBearer, Request, Response,
};
use asterism_mesh::{DeviceIdentity, MeshInfra};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use crate::mesh::Mesh;
use crate::Node;

/// Format version of `hosted.json`.
const HOSTED_VERSION: u32 = 1;
/// How often the account's device list is re-read while a session is armed.
const SYNC_INTERVAL: Duration = Duration::from_secs(60);
/// The first reconnect wait, doubled up to [`MAX_BACKOFF`].
const BASE_BACKOFF: Duration = Duration::from_secs(2);
/// The longest this device waits between presence attempts.
const MAX_BACKOFF: Duration = Duration::from_secs(120);
/// Every hosted HTTP call is bounded by this.
const HTTP_TIMEOUT: Duration = Duration::from_secs(10);
/// The largest hosted response body this client will read.
const MAX_BODY_BYTES: usize = 64 * 1024;
/// The largest presence frame this client will look at.
const MAX_PRESENCE_FRAME_BYTES: usize = 4 * 1024;

/// The daemon's durable hosted record.
///
/// Public routing material only. There is deliberately no field for a bearer,
/// a session id, or an account display name: a reader of this file learns
/// which account id this device is enrolled to and where its peers say they
/// are, and nothing that would let them act as the account.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct HostedRecord {
    #[serde(default)]
    version: u32,
    /// Canonical coordinator origin.
    #[serde(default)]
    coordinator: String,
    /// The coordinator's opaque account identifier.
    #[serde(default)]
    account_id: String,
    /// This device's own public mesh key, as enrolled.
    #[serde(default)]
    device_id: String,
    #[serde(default)]
    enrolled_at: u64,
    /// Whether account-enrolled keys may enter this orbit's ACL. Off by
    /// default: a compromised coordinator must not be able to add a device.
    #[serde(default)]
    trust_account_devices: bool,
    #[serde(default)]
    peers: Vec<HostedPeer>,
    #[serde(default)]
    synced_at: u64,
}

/// One peer, exactly as the account described it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct HostedPeer {
    device_id: String,
    #[serde(default)]
    discovery: DiscoveryConfig,
    #[serde(default)]
    endpoints: EndpointHints,
    #[serde(default)]
    online: bool,
    #[serde(default)]
    updated_at: u64,
}

/// A hosted session, held in memory for as long as this process runs.
struct Session {
    coordinator: String,
    bearer: RedactedBearer,
}

/// The client and everything it remembers.
pub(crate) struct Hosted {
    node: Node,
    mesh: Option<Arc<Mesh>>,
    path: PathBuf,
    record: Mutex<HostedRecord>,
    session: Mutex<Option<Session>>,
    presence: Mutex<HostedPresence>,
    last_error: Mutex<Option<String>>,
    client: reqwest::Client,
    /// Woken whenever a session is armed or the record changes.
    wake: tokio::sync::Notify,
}

static HOSTED: OnceLock<Arc<Hosted>> = OnceLock::new();

/// Whether this frame belongs to the hosted band.
pub(crate) fn claims(request: &Request) -> bool {
    matches!(
        request,
        Request::HostedEnroll { .. } | Request::HostedStatus | Request::HostedForget
    )
}

/// Serves one hosted frame. A daemon that never started the client answers
/// with an empty, honest status rather than an error.
pub(crate) async fn serve(request: Request) -> Response {
    let Some(hosted) = HOSTED.get() else {
        return Response::Error {
            message: "this daemon has no hosted coordinator client".into(),
        };
    };
    match request {
        Request::HostedStatus => Response::Hosted {
            hosted: hosted.status().await,
        },
        Request::HostedForget => match hosted.forget().await {
            Ok(()) => Response::Hosted {
                hosted: hosted.status().await,
            },
            Err(error) => Response::Error {
                message: format!("{error:#}"),
            },
        },
        Request::HostedEnroll {
            coordinator,
            bearer,
            trust_account_devices,
        } => match hosted.arm(coordinator, bearer, trust_account_devices).await {
            Ok(()) => Response::Hosted {
                hosted: hosted.status().await,
            },
            Err(error) => Response::Error {
                message: format!("{error:#}"),
            },
        },
        other => Response::Error {
            message: format!("hosted cannot serve {other:?}"),
        },
    }
}

/// Starts the client and its background task.
///
/// Failure is never fatal: a device with no hosted client is a device with a
/// working orbit and no directory refresh.
pub(crate) fn init(node: Node, mesh: Option<Arc<Mesh>>) -> Result<()> {
    let path = hosted_path();
    let record = read_record(&path)?;
    let client = reqwest::Client::builder()
        .timeout(HTTP_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .context("constructing the hosted coordinator client")?;
    let hosted = Arc::new(Hosted {
        node,
        mesh,
        path,
        record: Mutex::new(record),
        session: Mutex::new(None),
        presence: Mutex::new(HostedPresence::Disabled),
        last_error: Mutex::new(None),
        client,
        wake: tokio::sync::Notify::new(),
    });
    if HOSTED.set(hosted.clone()).is_err() {
        bail!("the hosted coordinator client is already running");
    }
    tokio::spawn(hosted.clone().supervise());
    Ok(())
}

/// The relay list and discovery seam an enrolled account supplies.
///
/// This is the seam AST-119 fills in: when the account selects relays, they
/// arrive here and become the `MeshInfra` the endpoint binds with. Until then
/// an enrolled account with no selected relay yields an empty override, which
/// means "use whatever the operator configured", not "use a public default".
pub(crate) fn account_mesh_infra() -> Option<MeshInfra> {
    let hosted = HOSTED.get()?;
    let record = hosted.record.try_lock().ok()?;
    if record.account_id.is_empty() {
        return None;
    }
    let own = record
        .peers
        .iter()
        .find(|peer| peer.device_id == record.device_id)?;
    Some(own.discovery.mesh_infra())
}

/// Where `hosted.json` lives.
fn hosted_path() -> PathBuf {
    paths::home_dir().join("hosted.json")
}

fn read_record(path: &PathBuf) -> Result<HostedRecord> {
    let raw = match std::fs::read_to_string(path) {
        Ok(raw) => raw,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(HostedRecord::default())
        }
        Err(error) => return Err(error).context("reading the hosted coordinator record"),
    };
    if raw.len() > MAX_BODY_BYTES {
        bail!("the hosted coordinator record is implausibly large");
    }
    let record: HostedRecord =
        serde_json::from_str(&raw).context("parsing the hosted coordinator record")?;
    if record.version > HOSTED_VERSION {
        bail!(
            "hosted.json was written by a newer Asterism (format {} > {HOSTED_VERSION})",
            record.version
        );
    }
    Ok(record)
}

/// Canonicalizes a coordinator origin, refusing anything that is not a bare
/// https origin — or a loopback http one, which is how a local Worker is
/// developed against.
fn canonical_authority(authority: &str) -> Result<String> {
    let trimmed = authority.trim();
    if trimmed.is_empty() || trimmed.len() > 512 || trimmed.contains(char::is_whitespace) {
        bail!("coordinator must be a bare https origin");
    }
    let (scheme, rest) = trimmed
        .split_once("://")
        .ok_or_else(|| anyhow!("coordinator must be a bare https origin"))?;
    if rest.contains('@') || rest.contains('?') || rest.contains('#') {
        bail!("coordinator must carry no credentials, query, or fragment");
    }
    let host = rest.trim_end_matches('/');
    if host.is_empty() || host.contains('/') {
        bail!("coordinator must be an origin, not a path");
    }
    let loopback =
        host.starts_with("127.0.0.1") || host.starts_with("localhost") || host.starts_with("[::1]");
    match scheme {
        "https" => {}
        "http" if loopback => {}
        _ => bail!("coordinator must use https"),
    }
    Ok(format!("{scheme}://{host}"))
}

impl Hosted {
    async fn status(&self) -> HostedStatus {
        let record = self.record.lock().await;
        let armed = self.session.lock().await.is_some();
        let orbit = self.node.orbit.lock().await;
        let peers = record
            .peers
            .iter()
            .filter(|peer| peer.device_id != record.device_id)
            .map(|peer| HostedPeerStatus {
                device_id: peer.device_id.clone(),
                online: peer.online,
                in_orbit: orbit.trusts(&peer.device_id),
                relays: peer.discovery.relays.clone(),
                addrs: peer.endpoints.addrs.clone(),
                updated_at: peer.updated_at,
            })
            .collect();
        HostedStatus {
            coordinator: (!record.coordinator.is_empty()).then(|| record.coordinator.clone()),
            account_id: (!record.account_id.is_empty()).then(|| record.account_id.clone()),
            device_id: record.device_id.clone(),
            enrolled: !record.account_id.is_empty(),
            enrolled_at: record.enrolled_at,
            presence: if armed {
                *self.presence.lock().await
            } else if record.account_id.is_empty() {
                HostedPresence::Disabled
            } else {
                HostedPresence::Unarmed
            },
            trust_account_devices: record.trust_account_devices,
            peers,
            last_error: self.last_error.lock().await.clone(),
        }
    }

    /// Accepts a session from `ast` and enrolls this device.
    ///
    /// The enrollment itself is done here rather than on the background task
    /// so `ast auth login` can print a real confirmation or a real reason.
    async fn arm(
        &self,
        coordinator: String,
        bearer: RedactedBearer,
        trust_account_devices: bool,
    ) -> Result<()> {
        let coordinator = canonical_authority(&coordinator)?;
        *self.session.lock().await = Some(Session {
            coordinator: coordinator.clone(),
            bearer,
        });
        {
            let mut record = self.record.lock().await;
            record.version = HOSTED_VERSION;
            record.coordinator = coordinator;
            record.trust_account_devices = trust_account_devices;
        }
        let result = self.enroll().await;
        match &result {
            Ok(()) => {
                *self.last_error.lock().await = None;
                // Say whose infrastructure this account has selected, in the
                // same words the endpoint uses at startup, so signing in never
                // silently changes who this device talks to.
                if let Some(infra) = account_mesh_infra() {
                    eprintln!("astd: hosted discovery — {}", infra.describe());
                }
            }
            Err(error) => *self.last_error.lock().await = Some(format!("{error:#}")),
        }
        self.wake.notify_waiters();
        result
    }

    /// Drops the session and the local record. It does not revoke: `ast auth
    /// logout` revokes at the bound issuer, and hosted revocation is a
    /// separate, explicit act.
    async fn forget(&self) -> Result<()> {
        *self.session.lock().await = None;
        *self.record.lock().await = HostedRecord::default();
        *self.presence.lock().await = HostedPresence::Disabled;
        *self.last_error.lock().await = None;
        match std::fs::remove_file(&self.path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error).context("removing the hosted coordinator record"),
        }
    }

    /// The whole enrollment: get a challenge, sign it with the device key this
    /// mesh already authenticates with, and hand back the public half.
    async fn enroll(&self) -> Result<()> {
        let identity = DeviceIdentity::load(paths::device_key_path())
            .map_err(|error| anyhow!("reading this device's key: {error}"))?;
        let device_id = identity.device_id().to_string();
        let begun = self
            .post("/api/v1/devices/enroll/begin", serde_json::json!({}))
            .await
            .context("starting hosted enrollment")?;
        let challenge = begun
            .get("challenge")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| anyhow!("the coordinator returned no enrollment challenge"))?;
        let signature = asterism_coordinator::sign_enrollment_challenge(&identity, challenge)?;
        let endpoints = self.local_endpoints().await;
        let completed = self
            .post(
                "/api/v1/devices/enroll/complete",
                serde_json::json!({
                    "device_id": device_id,
                    "challenge": challenge,
                    "signature": signature,
                    "endpoints": endpoints,
                }),
            )
            .await
            .context("completing hosted enrollment")?;
        let enrolled_at = completed
            .get("device")
            .and_then(|device| device.get("enrolled_at"))
            .and_then(serde_json::Value::as_u64)
            .unwrap_or_else(now_unix);
        let account_id = self.read_account_id().await?;
        {
            let mut record = self.record.lock().await;
            record.version = HOSTED_VERSION;
            record.device_id = device_id;
            record.account_id = account_id;
            record.enrolled_at = enrolled_at;
        }
        self.commit().await
    }

    /// Reads the account id the same way every other client does: from the
    /// device list, which is the only place it appears.
    async fn read_account_id(&self) -> Result<String> {
        Ok(self
            .get("/api/v1/devices")
            .await?
            .get("account_id")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_owned())
    }

    /// The addresses and relay this device currently answers on.
    async fn local_endpoints(&self) -> EndpointHints {
        let Some(mesh) = &self.mesh else {
            return EndpointHints::default();
        };
        let addr = mesh.endpoint().addr();
        EndpointHints {
            addrs: addr
                .ip_addrs()
                .map(|addr| addr.to_string())
                .take(24)
                .collect(),
            relay_url: mesh
                .endpoint()
                .home_relays()
                .into_iter()
                .find(|relay| relay.starts_with("https://")),
        }
    }

    /// One pass of the refresh: publish where this device is, read where its
    /// peers are, and merge that into local state.
    async fn sync(&self) -> Result<()> {
        let device_id = self.record.lock().await.device_id.clone();
        if device_id.is_empty() {
            return Ok(());
        }
        let endpoints = self.local_endpoints().await;
        if !endpoints.is_empty() {
            self.post(
                "/api/v1/devices/hints",
                serde_json::json!({ "device_id": device_id, "endpoints": endpoints }),
            )
            .await
            .context("publishing this device's routing hints")?;
        }
        let listed = self
            .get("/api/v1/devices")
            .await
            .context("reading the account's devices")?;
        let peers = parse_devices(&listed);
        {
            let mut record = self.record.lock().await;
            if let Some(account) = listed.get("account_id").and_then(serde_json::Value::as_str) {
                record.account_id = account.to_owned();
            }
            record.peers = peers;
            record.synced_at = now_unix();
        }
        self.merge_into_orbit().await?;
        self.commit().await
    }

    /// Merges the account's view into local state.
    ///
    /// A peer this orbit already trusts gets its routing hints refreshed —
    /// that is a dial hint and grants nothing. A peer this orbit does not
    /// trust stays out of `orbit.json` unless the operator opted in, because
    /// the pairing ticket is the trust root and a coordinator must not be able
    /// to add a device to an orbit.
    async fn merge_into_orbit(&self) -> Result<()> {
        let record = self.record.lock().await.clone();
        let mut orbit = self.node.orbit.lock().await;
        let mut changed = false;
        for peer in &record.peers {
            if peer.device_id == record.device_id {
                continue;
            }
            if !orbit.trusts(&peer.device_id) {
                // Known to the account, not a member of this orbit. `ast
                // devices` shows it; nothing dials it.
                continue;
            }
            let relays: Vec<String> = peer
                .discovery
                .relays
                .iter()
                .chain(peer.endpoints.relay_url.iter())
                .cloned()
                .collect();
            changed |= orbit.set_hints(&peer.device_id, peer.endpoints.addrs.clone(), relays);
        }
        if changed {
            orbit.save()?;
        }
        Ok(())
    }

    /// Durably writes the record, minus anything secret, because there is
    /// nothing secret in it.
    async fn commit(&self) -> Result<()> {
        let record = self.record.lock().await.clone();
        let encoded = serde_json::to_vec_pretty(&record)?;
        asterism_core::durable::commit(&self.path, &encoded)
            .context("writing the hosted coordinator record")
    }

    async fn post(&self, path: &str, body: serde_json::Value) -> Result<serde_json::Value> {
        let (origin, bearer) = self.session_parts().await?;
        let response = self
            .client
            .post(format!("{origin}{path}"))
            .header("content-type", "application/json")
            .bearer_auth(bearer.expose())
            .body(serde_json::to_vec(&body)?)
            .send()
            .await
            .with_context(|| format!("POST {path}"))?;
        read_json(response, path).await
    }

    async fn get(&self, path: &str) -> Result<serde_json::Value> {
        let (origin, bearer) = self.session_parts().await?;
        let response = self
            .client
            .get(format!("{origin}{path}"))
            .bearer_auth(bearer.expose())
            .send()
            .await
            .with_context(|| format!("GET {path}"))?;
        read_json(response, path).await
    }

    async fn session_parts(&self) -> Result<(String, RedactedBearer)> {
        let session = self.session.lock().await;
        let session = session
            .as_ref()
            .ok_or_else(|| anyhow!("no hosted session is armed; run ast auth login"))?;
        Ok((session.coordinator.clone(), session.bearer.clone()))
    }

    /// The background task. It never propagates a failure: a coordinator that
    /// is unreachable is a directory that does not refresh.
    async fn supervise(self: Arc<Self>) {
        let mut backoff = BASE_BACKOFF;
        loop {
            if self.session.lock().await.is_none() {
                *self.presence.lock().await = HostedPresence::Unarmed;
                self.wake.notified().await;
                backoff = BASE_BACKOFF;
                continue;
            }
            self.sync_reporting().await;
            match self.hold_presence().await {
                // A clean close is the far side hibernating or restarting.
                // Come back promptly rather than punishing it with backoff.
                Ok(()) => backoff = BASE_BACKOFF,
                Err(error) => {
                    *self.last_error.lock().await = Some(format!("presence: {error:#}"));
                }
            }
            if self.session.lock().await.is_some() {
                *self.presence.lock().await = HostedPresence::Connecting;
            }
            tokio::select! {
                () = tokio::time::sleep(with_jitter(backoff)) => {}
                () = self.wake.notified() => backoff = BASE_BACKOFF,
            }
            backoff = (backoff * 2).min(MAX_BACKOFF);
        }
    }

    async fn sync_reporting(&self) {
        match self.sync().await {
            Ok(()) => *self.last_error.lock().await = None,
            Err(error) => *self.last_error.lock().await = Some(format!("{error:#}")),
        }
    }

    /// Holds one presence socket for as long as it lives.
    ///
    /// Hibernation on the far side is invisible from here: the socket stays
    /// open and quiet, and the periodic ping keeps it that way. A
    /// `devices.changed` frame is only a hint, so it triggers a re-read of the
    /// device list rather than carrying any device data itself.
    async fn hold_presence(&self) -> Result<()> {
        use futures_util::{SinkExt, StreamExt};

        let (origin, device_id) = {
            let record = self.record.lock().await;
            (record.coordinator.clone(), record.device_id.clone())
        };
        if origin.is_empty() || device_id.is_empty() {
            return Ok(());
        }
        let (_, bearer) = self.session_parts().await?;
        let scheme = if origin.starts_with("https://") {
            "wss"
        } else {
            "ws"
        };
        let host = origin
            .split_once("://")
            .map(|(_, rest)| rest)
            .unwrap_or(&origin);
        let uri: http::Uri =
            format!("{scheme}://{host}/api/v1/devices/presence?device_id={device_id}")
                .parse()
                .context("building the presence socket address")?;
        let authorization = http::HeaderValue::from_str(&format!("Bearer {}", bearer.expose()))
            .map_err(|_| anyhow!("the hosted session cannot be sent as a header"))?;
        let (mut socket, _) = tokio_websockets::ClientBuilder::from_uri(uri)
            .add_header(http::header::AUTHORIZATION, authorization)
            .map_err(|error| anyhow!("preparing the presence socket: {error}"))?
            .connect()
            .await
            .map_err(|error| anyhow!("opening the presence socket: {error}"))?;
        *self.presence.lock().await = HostedPresence::Online;
        *self.last_error.lock().await = None;

        let result = loop {
            tokio::select! {
                frame = socket.next() => match frame {
                    None => break Ok(()),
                    Some(Err(error)) => break Err(anyhow!("presence socket failed: {error}")),
                    Some(Ok(message)) => {
                        if message.is_close() {
                            break Ok(());
                        }
                        let Some(text) = message.as_text() else { continue };
                        if text.len() > MAX_PRESENCE_FRAME_BYTES {
                            break Err(anyhow!("the coordinator sent an oversized presence frame"));
                        }
                        // Only a hint is ever acted on. The socket carries no
                        // device data this client would trust.
                        if serde_json::from_str::<serde_json::Value>(text)
                            .ok()
                            .as_ref()
                            .and_then(|value| value.get("type"))
                            .and_then(serde_json::Value::as_str)
                            == Some("devices.changed")
                        {
                            self.sync_reporting().await;
                        }
                    }
                },
                () = tokio::time::sleep(SYNC_INTERVAL) => {
                    if socket.send(tokio_websockets::Message::text("{\"type\":\"ping\"}")).await.is_err() {
                        break Ok(());
                    }
                    self.sync_reporting().await;
                }
                () = self.wake.notified() => break Ok(()),
            }
        };
        let _ = socket.close().await;
        if self.session.lock().await.is_some() {
            *self.presence.lock().await = HostedPresence::Connecting;
        }
        result
    }
}

/// Spreads reconnects so a coordinator restart does not bring every device of
/// every account back in the same second.
fn with_jitter(base: Duration) -> Duration {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| u64::from(elapsed.subsec_nanos()))
        .unwrap_or_default();
    let spread = base.as_millis() as u64 / 4;
    base + Duration::from_millis(if spread == 0 { 0 } else { nanos % spread })
}

/// Reads a bounded JSON body, turning a coordinator error into a message that
/// never carries request material.
async fn read_json(response: reqwest::Response, path: &str) -> Result<serde_json::Value> {
    let status = response.status();
    let body = response
        .bytes()
        .await
        .with_context(|| format!("reading {path}"))?;
    if body.len() > MAX_BODY_BYTES {
        bail!("the coordinator returned an implausibly large response for {path}");
    }
    let value: serde_json::Value = if body.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null)
    };
    if !status.is_success() {
        let code = value
            .get("error")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("unexpected_status");
        bail!(
            "the coordinator refused {path}: {code} ({})",
            status.as_u16()
        );
    }
    Ok(value)
}

/// Parses `GET /api/v1/devices` into the record's peer shape.
fn parse_devices(listed: &serde_json::Value) -> Vec<HostedPeer> {
    let Some(devices) = listed.get("devices").and_then(serde_json::Value::as_array) else {
        return Vec::new();
    };
    let mut peers = BTreeMap::new();
    for device in devices {
        let Some(device_id) = device.get("device_id").and_then(serde_json::Value::as_str) else {
            continue;
        };
        if device_id.len() != 64 || !device_id.chars().all(|c| c.is_ascii_hexdigit()) {
            continue;
        }
        peers.insert(
            device_id.to_owned(),
            HostedPeer {
                device_id: device_id.to_owned(),
                discovery: device
                    .get("discovery")
                    .and_then(|value| serde_json::from_value(value.clone()).ok())
                    .unwrap_or_default(),
                endpoints: device
                    .get("endpoints")
                    .and_then(|value| serde_json::from_value(value.clone()).ok())
                    .unwrap_or_default(),
                online: device
                    .get("presence")
                    .and_then(|value| value.get("status"))
                    .and_then(serde_json::Value::as_str)
                    == Some("online"),
                updated_at: device
                    .get("endpoints_updated_at")
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or_default(),
            },
        );
    }
    peers.into_values().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_coordinator_origin_must_be_https_or_loopback() {
        assert_eq!(
            canonical_authority("https://asterism.run/").unwrap(),
            "https://asterism.run"
        );
        assert_eq!(
            canonical_authority("http://127.0.0.1:8787").unwrap(),
            "http://127.0.0.1:8787"
        );
        assert!(canonical_authority("http://asterism.run").is_err());
        assert!(canonical_authority("https://user:pass@asterism.run").is_err());
        assert!(canonical_authority("https://asterism.run/api").is_err());
        assert!(canonical_authority("https://asterism.run?a=b").is_err());
        assert!(canonical_authority("asterism.run").is_err());
        assert!(canonical_authority("").is_err());
    }

    #[test]
    fn a_device_list_becomes_peers_and_ignores_anything_malformed() {
        let listed = serde_json::json!({
            "account_id": "usr_abc",
            "devices": [
                {
                    "device_id": "a".repeat(64),
                    "discovery": { "relays": ["https://relay.example"] },
                    "endpoints": { "addrs": ["192.0.2.1:41641"], "relay_url": "https://relay.example" },
                    "endpoints_updated_at": 42,
                    "presence": { "status": "online", "updated_at": 43 }
                },
                { "device_id": "short" },
                { "discovery": { "relays": [] } }
            ]
        });
        let peers = parse_devices(&listed);
        assert_eq!(peers.len(), 1);
        assert!(peers[0].online);
        assert_eq!(peers[0].endpoints.addrs, vec!["192.0.2.1:41641".to_owned()]);
        assert_eq!(peers[0].updated_at, 42);
    }

    #[test]
    fn the_durable_record_has_no_place_to_put_a_bearer() {
        let encoded = serde_json::to_string(&HostedRecord {
            version: HOSTED_VERSION,
            coordinator: "https://asterism.run".into(),
            account_id: "usr_abc".into(),
            device_id: "a".repeat(64),
            enrolled_at: 1,
            trust_account_devices: false,
            peers: Vec::new(),
            synced_at: 2,
        })
        .unwrap();
        for forbidden in ["bearer", "token", "authorization", "secret", "password"] {
            assert!(
                !encoded.to_lowercase().contains(forbidden),
                "hosted.json carried {forbidden}: {encoded}"
            );
        }
    }
}
