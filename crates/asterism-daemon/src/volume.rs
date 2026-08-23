//! Block volumes: the provider that serves them, the lease that fences them,
//! and the bridge that carries them to a guest on another device.
//!
//! One device is the **provider** — the bytes are on its disk. It runs
//! a native fixed-newstyle NBD exporter **on a unix socket** under the
//! volume's own directory. Never a TCP port: nothing about a volume is
//! reachable from the LAN, at either end, ever.
//!
//! Another device is the **consumer** — its hypervisor is running the guest.
//! Its `astd` binds a *local* unix socket next to the instance and splices
//! every connection on it over an authenticated QUIC stream to the provider's
//! export socket. VZ consumes that socket directly; Cloud Hypervisor
//! materializes it as a host NBD block device behind its backend seam; QEMU
//! remains an optional compatible consumer. The guest sees a local disk:
//!
//! ```text
//! hypervisor ─unix─ astd(consumer) ═QUIC/mesh═ astd(provider/NBD) ─ disk
//! ```
//!
//! It is the same splice `ast ssh` uses, aimed at a different socket, which is
//! the point: one piece of plumbing, tested twice.
//!
//! # One writer, and how it is enforced
//!
//! The lease lives on the provider ([`asterism_core::volume`]). Attaching
//! takes it; booting renews it; both bump a monotonic epoch. Every bump
//! renames the export (`tank-e7`), stops the previous listener and every
//! accepted session, and unlinks its socket — so a consumer that was
//! partitioned and comes back holding epoch 6 has nothing to reconnect to.
//! The refusal a second instance gets names the holder and the device its cpu
//! comes from, because "busy" is not something anybody can act on.
//!
//! # The plane
//!
//! [`init`] installs this device's one volume plane, once, at daemon start.
//! It is reached from `up`, which is called both from a request and from the
//! crash supervisor, and neither of those can be handed a mesh — so it is a
//! process-wide handle rather than an argument, in the same way the backends
//! are.
//!
//! # A guest outlives this process
//!
//! Everything on the consumer's side of that diagram belongs to *this*
//! process: the local socket is one it binds, the accept loop is one it
//! runs. The guest is not — it is its own process, and an `astd` restart
//! does not touch it. So a restart takes the disk away from a guest that
//! never went anywhere, and the backend's NBD client sits retrying the socket for
//! `RECONNECT_DELAY_SECS` before it starts failing the guest's I/O.
//!
//! [`reattach`] is what closes that: at startup, every running instance
//! whose guest is still alive gets its bridges raised again, at the epoch it
//! already holds. Not a fresh lease — the running backend was handed one
//! export name in its boot configuration, and a bump would rename that door
//! out from under a guest doing nothing wrong. See
//! [`Request::VolumeReconnect`].

use std::collections::HashMap;
use std::path::Path;
#[cfg(test)]
use std::process::Command;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use tokio::sync::Mutex;

use asterism_core::hv::{DiskSpec, Hypervisor};
use asterism_core::instance::{Instance, PartRuntime, Status, Volume};
use asterism_core::orbit::{Device, Orbit};
use asterism_core::paths;
use asterism_core::proc::{Ownership, ProcId, Signal};
use asterism_core::protocol::{Request, Response};
use asterism_core::volume::{
    self, BlockVolume, Catalog, CatalogVolume, Locality, PlacementPolicy, Store, UnreachableStorage,
};
use asterism_mesh::PathKind;

use crate::mesh::{self, Mesh, Splice, TransferStats};
use crate::nbd;
use crate::Node;

/// What a consumer is told when the provider's daemon is not answering.
/// Named because the e2e asserts on it: an honest failure is a feature here,
/// and a wall of backend errors is not one.
pub const UNREACHABLE: &str = "could not reach the device holding it";

/// The launch admission bound for a remote block device.
///
/// NBD performs a network round trip for I/O the guest cannot make local, so
/// the roadmap treats five milliseconds as a placement boundary rather than
/// a cosmetic warning.  This is deliberately an admission rule: an unsuitable
/// link is refused before a lease epoch, instance record, bridge socket, or
/// guest is mutated.
pub const REMOTE_VOLUME_MAX_RTT: Duration = Duration::from_millis(5);

// ---- the plane -------------------------------------------------------------

struct Plane {
    node: Node,
    mesh: Option<Arc<Mesh>>,
    device_id: String,
    store: Mutex<Store>,
    /// Live bridges, keyed by instance name. Dropping one unbinds its socket
    /// and kills every session on it.
    bridges: Mutex<HashMap<String, Vec<Splice>>>,
    /// Runtime observations keyed by the instance and exact sourced part.
    /// These are deliberately not registry state: after a restart [`reattach`]
    /// measures them again before the first request is served.
    health: Mutex<HashMap<HealthKey, HealthEntry>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct HealthKey {
    instance: String,
    device: String,
    volume: String,
}

#[derive(Debug, Clone)]
struct HealthEntry {
    runtime: PartRuntime,
    /// Monotonic clock for a recovery duration. Never serialized.
    degraded_since: Option<Instant>,
    /// Runtime-only generation of the accepted NBD session. A late completion
    /// from an older session must not degrade the one which replaced it.
    session: u64,
}

impl HealthEntry {
    fn begin_session(&mut self) -> u64 {
        self.session = self.session.saturating_add(1);
        self.session
    }

    fn owns_session(&self, session: u64) -> bool {
        self.session == session
    }
}

static PLANE: OnceLock<Plane> = OnceLock::new();

/// Install this device's volume plane. Called once, from `main`.
pub fn init(node: Node, mesh: Option<Arc<Mesh>>) -> Result<()> {
    let store = Store::load(&paths::volumes_path()).context("loading this device's volumes")?;
    sweep_orphan_volume_dirs(&store)?;
    let device_id = match &mesh {
        Some(mesh) => mesh.device_id().to_string(),
        None => asterism_mesh::DeviceIdentity::load(paths::device_key_path())
            .context("loading this device's immutable storage identity")?
            .device_id()
            .to_string(),
    };
    let _ = PLANE.set(Plane {
        node,
        mesh,
        device_id,
        store: Mutex::new(store),
        bridges: Mutex::new(HashMap::new()),
        health: Mutex::new(HashMap::new()),
    });
    Ok(())
}

/// Finish the byte-deletion half of an acknowledged catalog removal. A
/// create uses `create_new`, so these directories can never be mistaken for
/// a fresh volume before startup gets here.
fn sweep_orphan_volume_dirs(store: &Store) -> Result<()> {
    let root = paths::home_dir().join("volumes");
    let entries = match std::fs::read_dir(&root) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e).with_context(|| format!("reading {}", root.display())),
    };
    let known: std::collections::BTreeSet<String> =
        store.list().into_iter().map(|volume| volume.name).collect();
    for entry in entries {
        let entry = entry?;
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if !known.contains(&name) && entry.file_type()?.is_dir() {
            std::fs::remove_dir_all(entry.path()).with_context(|| {
                format!("finishing removal of orphan volume directory {name:?}")
            })?;
        }
    }
    Ok(())
}

fn health_key(instance: &str, vol: &Volume) -> HealthKey {
    HealthKey {
        instance: instance.to_owned(),
        device: vol.host.clone(),
        volume: vol.path.clone(),
    }
}

/// Add live part observations to a status reply without mutating the shard.
///
/// The instance lifecycle remains the backend's fact. A missing provider
/// changes only the sourced volume row, never `running` to `stopped`.
pub(crate) async fn annotate_runtime(inst: &mut Instance) {
    let Ok(plane) = plane() else { return };

    // A quiet NBD session has no bytes with which to discover that its peer
    // disappeared. Status is already asking for a live observation, so probe
    // each remote provider here and degrade only that sourced part when it no
    // longer answers. Run the probes together: several disks on sleeping
    // devices cost one bounded probe interval, not one interval per disk.
    if inst.status == Status::Running {
        if let Some(mesh) = plane.mesh.clone() {
            let mut probes = tokio::task::JoinSet::new();
            for vol in inst
                .volumes
                .iter()
                .filter(|vol| vol.is_block() && !vol.is_local())
                .cloned()
            {
                let mesh = mesh.clone();
                probes.spawn(async move {
                    let reachable = mesh.measure_link(&vol.host).await.is_some();
                    (vol, reachable)
                });
            }
            while let Some(result) = probes.join_next().await {
                if let Ok((vol, false)) = result {
                    mark_degraded(
                        &inst.name,
                        &vol,
                        "provider_loss",
                        "the provider did not answer the status liveness probe".into(),
                        None,
                        None,
                    )
                    .await;
                }
            }
        }
    }

    let health = plane.health.lock().await;
    for vol in inst.volumes.iter_mut().filter(|vol| vol.is_block()) {
        vol.runtime = health
            .get(&health_key(&inst.name, vol))
            .map(|entry| entry.runtime.clone());
    }
}

async fn mark_healthy(
    instance: &str,
    vol: &Volume,
    reason: &str,
    result: &str,
    measured_recovery: Option<Duration>,
    measured_link: Option<mesh::LinkObservation>,
) {
    let Ok(plane) = plane() else { return };
    let link = match measured_link {
        Some(link) => Some((
            link.path.map(|path| path.as_str().to_owned()),
            link.rtt_micros,
        )),
        None => match (&plane.mesh, vol.is_local()) {
            (_, true) => Some((Some("local".to_owned()), Some(0))),
            (Some(mesh), false) => mesh.link_observation(&vol.host).await.map(|link| {
                (
                    link.path.map(|path| path.as_str().to_owned()),
                    link.rtt_micros,
                )
            }),
            (None, false) => None,
        },
    };
    let key = health_key(instance, vol);
    let mut health = plane.health.lock().await;
    let previous = health.get(&key).cloned();
    let recovery = measured_recovery.or_else(|| {
        previous
            .as_ref()
            .and_then(|entry| entry.degraded_since.map(|since| since.elapsed()))
    });
    let runtime = PartRuntime {
        state: "healthy".into(),
        path: link
            .as_ref()
            .and_then(|(path, _)| path.clone())
            .or_else(|| {
                previous
                    .as_ref()
                    .and_then(|entry| entry.runtime.path.clone())
            }),
        rtt_micros: link
            .as_ref()
            .and_then(|(_, rtt)| *rtt)
            .or_else(|| previous.as_ref().and_then(|entry| entry.runtime.rtt_micros)),
        throughput_bytes_per_sec: previous
            .as_ref()
            .and_then(|entry| entry.runtime.throughput_bytes_per_sec),
        transferred_bytes: previous
            .as_ref()
            .and_then(|entry| entry.runtime.transferred_bytes),
        recovery_millis: recovery.map(duration_millis),
        transition_reason: reason.to_owned(),
        recovery_result: result.to_owned(),
        detail: None,
        observed_at: asterism_core::instance::now_unix(),
    };
    eprintln!(
        "astd: remote_part instance={instance:?} device={:?} volume={:?} state=healthy path={} rtt_us={} transition={reason} recovery={result} recovery_ms={}",
        vol.host,
        vol.path,
        runtime.path.as_deref().unwrap_or("-"),
        runtime.rtt_micros.map(|n| n.to_string()).unwrap_or_else(|| "-".into()),
        runtime.recovery_millis.map(|n| n.to_string()).unwrap_or_else(|| "-".into()),
    );
    health.insert(
        key,
        HealthEntry {
            runtime,
            degraded_since: None,
            session: previous.as_ref().map(|entry| entry.session).unwrap_or(0),
        },
    );
}

async fn mark_degraded(
    instance: &str,
    vol: &Volume,
    reason: &str,
    detail: String,
    transfer: Option<TransferStats>,
    ended_session: Option<u64>,
) {
    let Ok(plane) = plane() else { return };
    let key = health_key(instance, vol);
    let mut health = plane.health.lock().await;
    let previous = health.get(&key).cloned();
    if ended_session.is_some_and(|session| {
        previous
            .as_ref()
            .is_some_and(|entry| !entry.owns_session(session))
    }) {
        return;
    }
    let degraded_since = previous
        .as_ref()
        .and_then(|entry| entry.degraded_since)
        .or_else(|| Some(Instant::now()));
    let throughput = transfer.and_then(TransferStats::bytes_per_second);
    let transferred = transfer.map(TransferStats::total_bytes);
    let detail = detail.chars().take(512).collect::<String>();
    let runtime = PartRuntime {
        state: "degraded".into(),
        path: previous
            .as_ref()
            .and_then(|entry| entry.runtime.path.clone()),
        rtt_micros: previous.as_ref().and_then(|entry| entry.runtime.rtt_micros),
        throughput_bytes_per_sec: throughput.or_else(|| {
            previous
                .as_ref()
                .and_then(|entry| entry.runtime.throughput_bytes_per_sec)
        }),
        transferred_bytes: transferred.or_else(|| {
            previous
                .as_ref()
                .and_then(|entry| entry.runtime.transferred_bytes)
        }),
        recovery_millis: None,
        transition_reason: reason.to_owned(),
        recovery_result: "retrying".into(),
        detail: Some(detail.clone()),
        observed_at: asterism_core::instance::now_unix(),
    };
    eprintln!(
        "astd: remote_part instance={instance:?} device={:?} volume={:?} state=degraded path={} bytes={} throughput_Bps={} transition={reason} recovery=retrying detail={detail:?}",
        vol.host,
        vol.path,
        runtime.path.as_deref().unwrap_or("-"),
        runtime.transferred_bytes.map(|n| n.to_string()).unwrap_or_else(|| "-".into()),
        runtime.throughput_bytes_per_sec.map(|n| n.to_string()).unwrap_or_else(|| "-".into()),
    );
    health.insert(
        key,
        HealthEntry {
            runtime,
            degraded_since,
            session: previous.as_ref().map(|entry| entry.session).unwrap_or(0),
        },
    );
}

fn duration_millis(duration: Duration) -> u64 {
    duration.as_millis().min(u64::MAX as u128) as u64
}

fn plane() -> Result<&'static Plane> {
    PLANE
        .get()
        .context("this daemon's volume plane was never started")
}

// ---- the provider's half ---------------------------------------------------

/// Is this a request the volume plane answers rather than the instance shard?
///
/// Asked before the shard is locked, because a lease request arriving while
/// this device is booting an instance must not wait on that boot — and
/// because a consumer whose provider is *itself* would otherwise deadlock
/// against the lock its own `up` is holding.
pub fn is_plane_request(req: &Request) -> bool {
    matches!(
        req,
        Request::VolumeCreate { .. }
            | Request::VolumeList
            | Request::VolumeRemove { .. }
            | Request::VolumeLease { .. }
            | Request::VolumeReconnect { .. }
            | Request::VolumeRelease { .. }
    )
}

/// Requests whose answer is assembled from every storage provider rather
/// than read from this device's provider store.
pub fn is_orbit_request(req: &Request) -> bool {
    matches!(req, Request::VolumeCatalog)
}

/// Answer the orbit-visible storage read model.
pub async fn serve_orbit(req: Request, node: &Node, mesh: Option<&Arc<Mesh>>) -> Response {
    let result = match req {
        Request::VolumeCatalog => catalog(node, mesh)
            .await
            .map(|catalog| Response::VolumeCatalog { catalog }),
        other => Err(anyhow!("{other:?} is not an orbit storage request")),
    };
    reply(result)
}

/// Assemble every reachable provider into one catalog. Provider rows remain
/// authoritative; latency and path are observations from this device now.
pub async fn catalog(node: &Node, mesh: Option<&Arc<Mesh>>) -> Result<Catalog> {
    let plane = plane()?;
    let here = node.device_name().await;
    let here_id = plane.device_id.clone();
    let local = plane.store.lock().await.list();
    let mut catalog = Catalog {
        volumes: local
            .into_iter()
            .map(|volume| CatalogVolume {
                owner_device: here.clone(),
                owner_device_id: here_id.clone(),
                locality: Locality::Local,
                path: "local".into(),
                latency_micros: Some(0),
                volume,
            })
            .collect(),
        unreachable: Vec::new(),
    };

    let Some(mesh) = mesh else {
        return Ok(catalog);
    };
    let peers = node.orbit.lock().await.devices().to_vec();
    let mut asking = tokio::task::JoinSet::new();
    for peer in peers {
        let mesh = mesh.clone();
        asking.spawn(async move {
            let route = match mesh.ping(&peer.name).await {
                Ok(Response::DevicePong { path, millis, .. }) => {
                    let micros = (millis * 1000.0).round().clamp(0.0, u64::MAX as f64) as u64;
                    (path, Some(micros))
                }
                _ => ("remote".to_owned(), None),
            };
            let response = mesh.proxy(&peer.name, Request::VolumeList).await;
            (peer, route, response)
        });
    }
    while let Some(result) = asking.join_next().await {
        let Ok((peer, (path, latency_micros), response)) = result else {
            continue;
        };
        match response {
            Ok(Response::Volumes { volumes }) => {
                catalog
                    .volumes
                    .extend(volumes.into_iter().map(|volume| CatalogVolume {
                        owner_device: peer.name.clone(),
                        owner_device_id: peer.device_id.clone(),
                        locality: Locality::Remote,
                        path: path.clone(),
                        latency_micros,
                        volume,
                    }));
            }
            Ok(Response::Error { message }) => catalog.unreachable.push(UnreachableStorage {
                device: peer.name,
                device_id: peer.device_id,
                reason: message,
            }),
            Ok(other) => catalog.unreachable.push(UnreachableStorage {
                device: peer.name,
                device_id: peer.device_id,
                reason: format!("unexpected storage reply {other:?}"),
            }),
            Err(error) => catalog.unreachable.push(UnreachableStorage {
                device: peer.name,
                device_id: peer.device_id,
                reason: format!("{error:#}"),
            }),
        }
    }
    catalog.volumes.sort_by(|a, b| {
        (&a.volume.name, &a.owner_device_id).cmp(&(&b.volume.name, &b.owner_device_id))
    });
    catalog
        .unreachable
        .sort_by(|a, b| a.device_id.cmp(&b.device_id));
    Ok(catalog)
}

/// Resolve an attach against the catalog before taking a provider lease.
/// The lease operation below remains the final race-safe single-writer gate.
pub async fn place(
    volume: &str,
    owner_device: Option<&str>,
    holder: &str,
    max_latency_ms: Option<u64>,
) -> Result<(String, String)> {
    let plane = plane()?;
    let catalog = catalog(&plane.node, plane.mesh.as_ref()).await?;
    let max_latency_micros = max_latency_ms
        .map(|millis| {
            millis
                .checked_mul(1000)
                .context("latency ceiling is too large")
        })
        .transpose()?;
    let selected = catalog.place(
        volume,
        owner_device,
        holder,
        PlacementPolicy {
            max_latency_micros,
            ..PlacementPolicy::default()
        },
    )?;
    Ok((
        selected.owner_device.clone(),
        selected.owner_device_id.clone(),
    ))
}

/// Resolve a routed device name to the immutable authority identity used by
/// storage intents and provider leases.
pub async fn provider_identity(device: &str) -> Result<String> {
    let plane = plane()?;
    if device == plane.node.device_name().await {
        return Ok(plane.device_id.clone());
    }
    plane
        .node
        .orbit
        .lock()
        .await
        .get(device)
        .map(|peer| peer.device_id.clone())
        .with_context(|| format!("no device named {device:?} in this orbit"))
}

pub fn consumer_device_id() -> Result<String> {
    Ok(plane()?.device_id.clone())
}

/// Answer one volume request against this device's own volumes.
pub async fn serve(req: Request) -> Response {
    reply(serve_for(req, None).await)
}

/// Answer a volume request which arrived from an authenticated mesh peer.
///
/// Volume administration is orbit-wide, but a writer lease is narrower: its
/// device field says which authenticated peer may renew, release, or open the
/// export.  The peer does not get to supply that identity for itself.
pub async fn serve_authenticated(
    req: Request,
    requester_device: &str,
    requester_device_id: &str,
) -> Response {
    // Refuse an attempted name substitution before consulting the plane. It
    // is both the clearest error and keeps this check independent of volume
    // availability.
    if let Request::VolumeLease {
        holder_device,
        holder_device_id,
        ..
    } = &req
    {
        if holder_device != requester_device || holder_device_id != requester_device_id {
            return reply(Err(anyhow!(
                "authenticated device {requester_device:?} ({requester_device_id}) cannot request \
                 a volume lease for device {holder_device:?} ({holder_device_id})"
            )));
        }
    }

    let result = async {
        let plane = plane()?;
        // Removal takes this same lock before the volume lock. Holding it
        // through the operation makes the ordering total: a request which
        // got here first is included in revocation, while one which got here
        // second observes the missing exact key and cannot grant or resume.
        let membership = plane.node.orbit.lock().await;
        authorize_peer(&membership, requester_device, requester_device_id)?;
        let response = serve_for(req, Some((requester_device, requester_device_id))).await;
        drop(membership);
        response
    }
    .await;
    reply(result)
}

async fn serve_for(req: Request, requester: Option<(&str, &str)>) -> Result<Response> {
    match req {
        Request::VolumeCreate { name, size_bytes } => create(&name, size_bytes).await,
        Request::VolumeList => list().await,
        Request::VolumeRemove { name } => remove(&name).await,
        Request::VolumeLease {
            volume,
            holder,
            holder_id,
            holder_device,
            holder_device_id,
            intent_id,
        } => {
            if holder_id.is_empty() || holder_device_id.is_empty() {
                bail!("volume lease requires immutable holder and consumer-device identities");
            }
            grant(
                &volume,
                &holder,
                &holder_id,
                requester.map_or(holder_device.as_str(), |(name, _)| name),
                &holder_device_id,
                intent_id.as_deref(),
            )
            .await
        }
        Request::VolumeReconnect {
            volume,
            holder,
            holder_id,
            epoch,
        } => {
            if holder_id.is_empty() {
                bail!("volume reconnect requires an immutable holder identity");
            }
            resume(&volume, &holder, &holder_id, epoch, requester).await
        }
        Request::VolumeRelease {
            volume,
            holder,
            holder_id,
            epoch,
            intent_id,
            release_intent_id: _,
        } => {
            if holder_id.is_empty() {
                bail!("volume release requires an immutable holder identity");
            }
            release(
                &volume,
                &holder,
                &holder_id,
                epoch,
                intent_id.as_deref(),
                requester,
            )
            .await
        }
        other => Err(anyhow!("{other:?} is not a volume request")),
    }
}

fn reply(result: Result<Response>) -> Response {
    match result {
        Ok(response) => response,
        Err(e) => Response::Error {
            message: format!("{e:#}"),
        },
    }
}

fn authorize_peer(orbit: &Orbit, requester_device: &str, requester_device_id: &str) -> Result<()> {
    match orbit.by_id(requester_device_id) {
        Some(device) if device.name == requester_device => Ok(()),
        Some(device) => bail!(
            "authenticated key {requester_device_id} now belongs to device {:?}, not \
             {requester_device:?}",
            device.name
        ),
        None => {
            bail!("device {requester_device:?} ({requester_device_id}) is no longer in this orbit")
        }
    }
}

async fn create(name: &str, size_bytes: u64) -> Result<Response> {
    let plane = plane()?;
    let mut store = plane.store.lock().await;
    let mut next = store.clone();
    let vol = next.create(name, size_bytes)?;

    // The bytes, then the bookkeeping: a saved record with no image behind it
    // would be a volume that exists until you use it.
    let dir = paths::volume_dir(name);
    std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    let image = paths::volume_image_path(name);
    let file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&image)
        .with_context(|| format!("creating {}", image.display()))?;
    // Sparse: it claims its size and occupies what has been written, the same
    // deal an instance's own disk gets.
    file.set_len(size_bytes)?;
    drop(file);

    if let Err(error) = next.save_confirmed() {
        match Store::load(&paths::volumes_path()) {
            Ok(reloaded) if reloaded.get(name).is_ok() => {
                *store = reloaded;
                store
                    .save_confirmed()
                    .context("confirming an ambiguously committed volume creation")?;
                return Ok(Response::Volumes { volumes: vec![vol] });
            }
            Ok(reloaded) => *store = reloaded,
            Err(reload) => {
                bail!("committing volume creation: {error:#}; reloading it: {reload:#}")
            }
        }
        let _ = std::fs::remove_file(&image);
        let _ = std::fs::remove_dir(&dir);
        return Err(error).context("committing volume creation");
    }
    *store = next;
    Ok(Response::Volumes { volumes: vec![vol] })
}

async fn list() -> Result<Response> {
    let plane = plane()?;
    let store = plane.store.lock().await;
    Ok(Response::Volumes {
        volumes: store.list(),
    })
}

async fn remove(name: &str) -> Result<Response> {
    let plane = plane()?;
    let mut store = plane.store.lock().await;
    let mut next = store.clone();
    let vol = next.remove(name)?;
    next.save_confirmed()?;
    *store = next;
    let dir = paths::volume_dir(name);
    if dir.exists() {
        std::fs::remove_dir_all(&dir).with_context(|| format!("removing {}", dir.display()))?;
    }
    Ok(Response::Volumes { volumes: vec![vol] })
}

/// Take or renew the lease, and (re)start the export that serves it.
///
/// The order matters: the epoch is bumped and persisted first, then the old
/// export is stopped, then the new one is started. A crash anywhere in there
/// leaves a volume whose epoch has moved and whose export is missing, which
/// the next grant fixes — the failure mode we must not have is an old export
/// still serving under a lease somebody else now holds.
async fn grant(
    name: &str,
    holder: &str,
    holder_id: &str,
    holder_device: &str,
    holder_device_id: &str,
    intent_id: Option<&str>,
) -> Result<Response> {
    let plane = plane()?;
    let mut store = plane.store.lock().await;
    let previous = store.get(name).ok().and_then(|v| v.lease.clone());
    let mut next = store.clone();
    let vol = next.lease_with_intent(
        name,
        holder,
        holder_id,
        holder_device,
        holder_device_id,
        intent_id,
    )?;
    let lease = vol.lease.clone().expect("a grant leaves a lease");
    let replay = previous
        .as_ref()
        .is_some_and(|old| old.epoch == lease.epoch && old.intent_id == lease.intent_id);
    if !replay {
        if let Some(old) = &previous {
            // Death is the fence, not unlink. Retire the previous writer
            // before publishing or acknowledging a new authority epoch.
            stop_export(name, old)?;
        }
    }
    if let Err(error) = next.save_confirmed() {
        store.reload().with_context(|| {
            format!("reloading the volume store after lease commit failed: {error:#}")
        })?;
        return Err(error).context("committing the provider lease");
    }
    *store = next;

    let socket = paths::volume_export_socket(name, lease.epoch);
    let pidfile = paths::volume_export_pid(name, lease.epoch);
    if !export_alive(lease.proc.as_ref(), &socket, &pidfile) {
        retire_unhealthy_export(&mut store, name, &lease)?;
        let (lease, launch) = prepare_export_start(&mut store, &vol)?;
        start_export(&mut store, name, &lease, launch)?;
    }

    let vol = store.get(name)?.clone();
    let lease = vol.lease.clone().expect("a grant leaves a lease");

    Ok(Response::VolumeLease {
        volume: vol.name.clone(),
        epoch: lease.epoch,
        export: lease.export,
        socket: paths::volume_export_socket(name, lease.epoch)
            .display()
            .to_string(),
        size_bytes: vol.size_bytes,
    })
}

/// Confirm a lease the holder still has, and make sure something is serving
/// it.
///
/// The mirror of [`grant`] with the fence left alone: no bump, no revocation
/// of the previous export, because there is no previous export to revoke —
/// the consumer is holding this very one. The export may still need
/// starting, for the same reason [`open_export`] may find it missing: a
/// provider that restarted has a lease on disk and no process behind it.
async fn resume(
    name: &str,
    holder: &str,
    holder_id: &str,
    epoch: u64,
    requester: Option<(&str, &str)>,
) -> Result<Response> {
    let plane = plane()?;
    let mut store = plane.store.lock().await;
    let vol = store.reconnect_holder(name, holder, holder_id, epoch)?;
    let lease = vol.lease.clone().expect("reconnect checked the lease");
    authorize_lease_device(name, &lease, requester)?;

    let socket = paths::volume_export_socket(name, lease.epoch);
    let pidfile = paths::volume_export_pid(name, lease.epoch);
    if !export_alive(lease.proc.as_ref(), &socket, &pidfile) {
        retire_unhealthy_export(&mut store, name, &lease)?;
        let (lease, launch) = prepare_export_start(&mut store, &vol)?;
        start_export(&mut store, name, &lease, launch)?;
    }
    Ok(Response::VolumeLease {
        volume: vol.name.clone(),
        epoch: lease.epoch,
        export: lease.export,
        socket: socket.display().to_string(),
        size_bytes: vol.size_bytes,
    })
}

async fn release(
    name: &str,
    holder: &str,
    holder_id: &str,
    expected_epoch: Option<u64>,
    intent_id: Option<&str>,
    requester: Option<(&str, &str)>,
) -> Result<Response> {
    let plane = plane()?;
    let mut store = plane.store.lock().await;
    if let Some(lease) = store.get(name)?.lease.as_ref() {
        // Preserve Store::release's useful holder mismatch below.  The device
        // check applies once this request names the actual holder.
        if lease.holder_id == holder_id || (lease.holder_id.is_empty() && lease.holder == holder) {
            authorize_lease_device(name, lease, requester)?;
        }
    }
    let mut next = store.clone();
    let released = next.release_holder(name, holder, holder_id, intent_id, expected_epoch)?;
    if let Some(lease) = &released {
        // Do not publish a free volume until every old NBD client has lost
        // its server and process death has been observed.
        stop_export(name, lease)?;
    }
    if let Err(error) = next.save_confirmed() {
        store.reload().with_context(|| {
            format!("reloading the volume store after release commit failed: {error:#}")
        })?;
        return Err(error).context("committing the provider lease release");
    }
    *store = next;
    Ok(Response::Volumes {
        volumes: vec![store.get(name)?.clone()],
    })
}

fn authorize_lease_device(
    volume: &str,
    lease: &volume::Lease,
    requester: Option<(&str, &str)>,
) -> Result<()> {
    if let Some((requester_name, requester_id)) = requester {
        let same_device = if lease.holder_device_id.is_empty() {
            lease.holder_device == requester_name
        } else {
            lease.holder_device_id == requester_id
        };
        if !same_device {
            bail!(
                "volume {volume:?} is leased to device {:?} ({}), not authenticated device \
                 {requester_name:?} ({requester_id})",
                lease.holder_device,
                lease.holder_device_id,
            );
        }
    }
    Ok(())
}

/// Durably revoke a device's local leases before durably removing its orbit
/// membership.
///
/// This order is the transaction: every crash boundary is either (member,
/// leased), (member, revoked), or (removed, revoked). There is deliberately no
/// path to (removed, leased), because a new key can later pair under the same
/// human name. The caller already holds the orbit lock, and authenticated
/// volume operations take that same lock before the store lock, so an
/// in-flight grant is either committed before this revocation or refused
/// after removal.
pub async fn remove_device(orbit: &mut Orbit, device: &Device) -> Result<Device> {
    match PLANE.get() {
        Some(plane) => {
            let mut store = plane.store.lock().await;
            remove_device_from_store(orbit, &mut store, device, stop_revoked_exports)
        }
        None => {
            // If volume-plane startup failed, the on-disk leases still exist
            // and are more important, not less. Load them directly and fail
            // closed if they cannot be read or committed.
            let volume_path = orbit.path().with_file_name("volumes.json");
            let mut store =
                Store::load(&volume_path).context("loading volumes before removing a device")?;
            remove_device_from_store(orbit, &mut store, device, stop_revoked_exports)
        }
    }
}

fn remove_device_from_store(
    orbit: &mut Orbit,
    store: &mut Store,
    device: &Device,
    before_revocation: impl FnOnce(&[(String, volume::Lease)]) -> Result<()>,
) -> Result<Device> {
    match orbit.by_id(&device.device_id) {
        Some(current) if current.name != device.name => bail!(
            "device key {} is currently named {:?}, not {:?}; refusing to substitute one \
             identity in a removal",
            device.short_id(),
            current.name,
            device.name
        ),
        _ => {}
    };
    let mut next = store.clone();
    let revoked = next.revoke_device_authority(&device.name, &device.device_id);
    // Process death precedes the durable free state. A failed or unprovable
    // shutdown leaves both membership and the authoritative lease intact.
    before_revocation(&revoked)?;
    next.save_confirmed()
        .context("confirming device lease revocation")?;
    *store = next;
    orbit.remove_durable(device)
}

fn stop_revoked_exports(revoked: &[(String, volume::Lease)]) -> Result<()> {
    for (volume, lease) in revoked {
        stop_export(volume, lease)?;
    }
    Ok(())
}

/// Connect to the export serving `volume` at `epoch`, on behalf of `holder`.
///
/// This is the far end of a splice, and it is where the fence is checked: a
/// holder that is not the one on the lease, or an epoch that is not the
/// current one, gets a refusal rather than a pipe. Nothing about the reply
/// tells a stale consumer what the new epoch is; it has to go and ask for a
/// lease, which is the code path that decides whether it may have one.
pub async fn open_export(
    volume: &str,
    holder: &str,
    holder_id: &str,
    epoch: u64,
    requester_device: &str,
    requester_device_id: &str,
) -> Result<tokio::net::UnixStream> {
    open_export_for(
        volume,
        holder,
        holder_id,
        epoch,
        requester_device,
        Some(requester_device_id),
    )
    .await
}

async fn open_export_for(
    volume: &str,
    holder: &str,
    holder_id: &str,
    epoch: u64,
    requester_device: &str,
    requester_device_id: Option<&str>,
) -> Result<tokio::net::UnixStream> {
    let plane = plane()?;
    let membership = if let Some(requester_device_id) = requester_device_id {
        let membership = plane.node.orbit.lock().await;
        authorize_peer(&membership, requester_device, requester_device_id)?;
        Some(membership)
    } else {
        None
    };
    let mut store = plane.store.lock().await;
    let vol = store.get(volume)?.clone();
    let Some(lease) = vol.lease.clone() else {
        bail!("volume {volume:?} is not leased to anything — attach it first");
    };
    if lease.holder_id.is_empty() {
        if lease.holder != holder {
            bail!("{}", volume::held_by(volume, &lease));
        }
    } else if lease.holder_id != holder_id {
        bail!(
            "volume {volume:?} is leased to immutable instance identity {:?}, not {:?}",
            lease.holder_id,
            holder_id
        );
    }
    let same_consumer = match requester_device_id {
        Some(requester_id) if !lease.holder_device_id.is_empty() => {
            lease.holder_device_id == requester_id
        }
        _ => lease.holder_device == requester_device,
    };
    if !same_consumer {
        bail!(
            "volume {volume:?} is leased to device {:?}, not authenticated device {:?}",
            lease.holder_device,
            requester_device
        );
    }
    if lease.epoch != epoch {
        bail!("{}", volume::fenced(volume, holder, epoch, lease.epoch));
    }

    // The export may be gone even though the lease is not: the provider's
    // daemon may have restarted, taking its in-process exporter with it.
    // Restarting it at the *same* epoch is safe, because the epoch is what
    // decides who may write and it has not moved.
    let socket = paths::volume_export_socket(volume, lease.epoch);
    let pidfile = paths::volume_export_pid(volume, lease.epoch);
    if !export_alive(lease.proc.as_ref(), &socket, &pidfile) {
        retire_unhealthy_export(&mut store, volume, &lease)?;
        let (lease, launch) = prepare_export_start(&mut store, &vol)?;
        start_export(&mut store, volume, &lease, launch)?;
    }
    drop(store);

    let connected = tokio::net::UnixStream::connect(&socket)
        .await
        .with_context(|| format!("connecting to the export for volume {volume:?}"));
    drop(membership);
    connected
}

/// Durably bind a prospective in-process server to this exact daemon before
/// its listener can accept. Unlike a child process, a native export cannot
/// outlive this identity; a crash between this commit and thread start is
/// therefore safely recoverable once the recorded daemon is proven gone.
fn arm_export_start(store: &mut Store, name: &str) -> Result<volume::Lease> {
    let mut starting = store.clone();
    let process = ProcId::capture(std::process::id())
        .context("capturing the daemon identity for a native NBD launch fence")?;
    starting.set_export_proc(name, Some(process))?;
    if let Err(error) = starting.save_confirmed() {
        store.reload().with_context(|| {
            format!("reloading the volume store after export launch-fence failure: {error:#}")
        })?;
        return Err(error).context("committing the native export launch fence");
    }
    *store = starting;
    Ok(store
        .get(name)?
        .lease
        .clone()
        .expect("an export launch fence requires a lease"))
}

#[derive(Debug)]
struct ExportStart {
    prepared: nbd::Prepared,
}

/// Resolve every definitely pre-spawn dependency before publishing the
/// conservative server-may-run marker. Opening the image and binding the
/// socket happen before the marker; the prepared listener accepts nothing
/// until after the marker is durable.
fn prepare_export_start(
    store: &mut Store,
    vol: &BlockVolume,
) -> Result<(volume::Lease, ExportStart)> {
    prepare_export_start_with(
        store,
        vol,
        &paths::volume_image_path(&vol.name),
        &paths::volume_export_socket(
            &vol.name,
            vol.lease
                .as_ref()
                .expect("an exported volume has a lease")
                .epoch,
        ),
        &paths::volume_export_pid(
            &vol.name,
            vol.lease
                .as_ref()
                .expect("an exported volume has a lease")
                .epoch,
        ),
    )
}

fn prepare_export_start_with(
    store: &mut Store,
    vol: &BlockVolume,
    image: &Path,
    socket: &Path,
    pidfile: &Path,
) -> Result<(volume::Lease, ExportStart)> {
    let lease = vol.lease.as_ref().expect("an exported volume has a lease");
    let prepared = nbd::prepare(image, socket, &lease.export, vol.size_bytes)?;
    std::fs::remove_file(pidfile).or_else(|error| {
        (error.kind() == std::io::ErrorKind::NotFound)
            .then_some(())
            .ok_or(error)
    })?;
    let lease = arm_export_start(store, &vol.name)?;
    Ok((lease, ExportStart { prepared }))
}

/// Clear a launch fence only after `stop_export` proved process death.
fn clear_export_start(store: &mut Store, name: &str) -> Result<()> {
    let mut cleared = store.clone();
    cleared.set_export_proc(name, None)?;
    if let Err(error) = cleared.save_confirmed() {
        store.reload().with_context(|| {
            format!("reloading the volume store after export-fence cleanup failed: {error:#}")
        })?;
        return Err(error).context("clearing the stopped export's launch fence");
    }
    *store = cleared;
    Ok(())
}

/// Retire every trace of an exporter which failed the combined runtime,
/// process-identity, socket, and legacy-pidfile liveness check. A missing
/// socket is not permission to start beside a still-live server: this path
/// first shuts that server down (or refuses when death is not provable), then
/// durably clears its identity before another listener is prepared.
fn retire_unhealthy_export(store: &mut Store, name: &str, lease: &volume::Lease) -> Result<()> {
    if !lease.export_started {
        return Ok(());
    }
    stop_export(name, lease)?;
    clear_export_start(store, name)
}

/// Give every pre-identity lease on this device an identity, once.
///
/// The volume half of the startup migration, run beside
/// [`crate::backend::adopt_identities`] and for the same reason: a lease
/// written by an older daemon names its storage daemon by pid alone, and a
/// pid that has outlived a daemon restart is not evidence of anything.
///
/// A legacy lease that cannot be adopted remains conservatively marked as an
/// export which may still be running. Reconnect and renewal then refuse to
/// start or publish another writer until an operator can prove the old one is
/// dead; absence of modern process identity is not evidence of death.
pub async fn adopt_export_identities() {
    let Ok(plane) = plane() else { return };
    let mut store = plane.store.lock().await;
    let mut changed = false;
    for vol in store.list() {
        match store.adopt_export(&vol.name) {
            Ok(Some(proc)) => {
                eprintln!(
                    "astd: volume {:?} was exported before process identities existed — \
                     adopting {proc}",
                    vol.name
                );
                changed = true;
            }
            Ok(None) => {}
            Err(why) => eprintln!(
                "astd: volume {:?}'s recorded export cannot be proven to still be running \
                 ({why}) — its writer fence remains closed",
                vol.name
            ),
        }
    }
    if changed {
        if let Err(e) = store.save_confirmed() {
            eprintln!("astd: saving volumes after adopting export identities: {e:#}");
        }
    }
}

// ---- native NBD exporter ---------------------------------------------------

/// Start the in-process server behind an already-durable daemon identity.
/// Thread-start failure is known not to have published a runtime, so it may
/// clear that marker immediately. Once start succeeds, the exact runtime is
/// the second half of every later liveness and revocation decision.
fn start_export(
    store: &mut Store,
    name: &str,
    armed: &volume::Lease,
    launch: ExportStart,
) -> Result<()> {
    let process = match nbd::start(launch.prepared) {
        Ok(process) => process,
        Err(error) => {
            return match clear_export_start(store, name) {
                Ok(()) => Err(error).context("starting the native NBD exporter"),
                Err(clear) => Err(error).context(format!(
                    "starting the native NBD exporter; no server was published but its durable \
                     launch fence could not be cleared: {clear:#}"
                )),
            };
        }
    };
    if armed.proc.as_ref() != Some(&process) {
        let socket = paths::volume_export_socket(name, armed.epoch);
        let stop = nbd::stop(&socket, Some(&process));
        let clear = clear_export_start(store, name);
        bail!(
            "native NBD runtime identity differed from its durable launch fence \
             (stop={stop:?}, clear={clear:?})"
        );
    }
    Ok(())
}

/// Stop an export and take its socket with it.
///
/// Process death is the revocation. Only after it is proven are the stale
/// socket and pidfile removed, because unlinking a Unix socket does not close
/// clients which were already connected to the old server.
///
/// The signals go only to a process this daemon can still prove is the
/// export it started ([`ProcId`]). A lease whose recorded process cannot be
/// proven is not touched and keeps its authority row: whatever is at that pid
/// now is not safe to signal, while unlinking alone would falsely acknowledge
/// a revocation without ending old clients.
fn stop_export(name: &str, lease: &volume::Lease) -> Result<()> {
    stop_export_at(
        name,
        lease,
        &paths::volume_export_socket(name, lease.epoch),
        &paths::volume_export_pid(name, lease.epoch),
    )
}

fn stop_export_at(name: &str, lease: &volume::Lease, socket: &Path, pidfile: &Path) -> Result<()> {
    let stopped_native = nbd::stop(socket, lease.proc.as_ref())?;
    match lease.proc.as_ref() {
        Some(_) if stopped_native => {}
        // Native exports deliberately have no pidfile: the process identity
        // is a crash fence, never permission to signal a whole daemon. Only
        // kernel proof that the recorded daemon is gone permits cleanup when
        // its in-memory runtime is unavailable.
        Some(proc) if !pidfile.exists() => match proc.check() {
            Ownership::Gone | Ownership::Foreign(_) => {}
            Ownership::Ours => bail!(
                "volume {name:?}'s native export runtime is missing inside its recorded daemon; \
                 refusing to unlink or advance the writer fence"
            ),
            Ownership::Unknown(why) => bail!(
                "volume {name:?}'s native export process identity cannot prove whether its \
                 daemon ended ({why}); \
                 refusing to unlink or advance the writer fence"
            ),
        },
        Some(proc) if !is_legacy_export_process(proc) => bail!(
            "volume {name:?}'s legacy pidfile names {proc}, which is not a \
             qemu-storage-daemon; refusing to signal or advance the writer fence"
        ),
        Some(proc) => {
            if proc.signal(Signal::Term)? && !proc.wait_gone(Duration::from_secs(5)) {
                proc.signal(Signal::Kill)?;
                if !proc.wait_gone(Duration::from_secs(5)) {
                    bail!(
                        "volume {name:?}'s old export {proc} did not die after SIGKILL; the \
                         writer fence was not advanced"
                    );
                }
            }
            if !proc.wait_gone(Duration::ZERO) {
                bail!(
                    "volume {name:?}'s old export {proc} cannot be proven dead; the writer \
                     fence was not advanced"
                );
            }
        }
        None if lease.export_started => bail!(
            "volume {name:?}'s epoch {} may still have an export but has no process identity; \
             refusing to advance or release its writer fence",
            lease.epoch
        ),
        None => {}
    }
    std::fs::remove_file(socket).or_else(|e| {
        (e.kind() == std::io::ErrorKind::NotFound)
            .then_some(())
            .ok_or(e)
    })?;
    std::fs::remove_file(pidfile).or_else(|e| {
        (e.kind() == std::io::ErrorKind::NotFound)
            .then_some(())
            .ok_or(e)
    })?;
    Ok(())
}

/// Is the export for this lease still being served?
///
/// Both halves, and neither is redundant: a socket file outlives whoever
/// bound it, and a recorded process may since have become somebody else's.
fn export_alive(proc: Option<&ProcId>, socket: &Path, legacy_pidfile: &Path) -> bool {
    nbd::alive(proc, socket)
        || legacy_pidfile.exists()
            && proc.is_some_and(|process| is_legacy_export_process(process) && process.alive())
            && socket.exists()
}

fn is_legacy_export_process(process: &ProcId) -> bool {
    process
        .exec
        .as_deref()
        .and_then(Path::file_name)
        .is_some_and(|name| name == std::ffi::OsStr::new(volume::LEGACY_EXPORT_BIN))
}

// ---- the consumer's half ---------------------------------------------------

/// What one boot leased and raised.
#[derive(Debug, Default)]
pub struct Raised {
    /// The disks the backend should boot with.
    pub disks: Vec<DiskSpec>,
    /// The lease each block volume was granted, for the caller to write
    /// back onto the instance.
    pub leases: Vec<Leased>,
}

/// One block volume's lease, as the boot that took it saw it.
///
/// Recorded on the instance because two things read it later and both need
/// the *live* number rather than the one the attach happened to get:
/// `ast status`, which would otherwise print an epoch that stopped being
/// true at the first boot, and the next daemon to start under a guest this
/// one booted, which has to reconnect at the epoch that guest's QEMU is
/// using ([`reattach`]).
#[derive(Debug)]
pub struct Leased {
    pub volume: String,
    pub device: String,
    pub epoch: u64,
    pub size_bytes: u64,
}

/// Take the leases and raise the bridges an instance's block volumes need,
/// and hand back the disks its backend should boot with.
///
/// Called from `up`, inside `block_in_place`, and everything it does is
/// undone by [`take_down`] — including on its own failure, so a boot that
/// cannot get one of two volumes does not leave the other half-attached.
pub fn bring_up(inst: &Instance, hv: &dyn Hypervisor, boot_intent_id: &str) -> Result<Raised> {
    let blocks: Vec<Volume> = inst
        .volumes
        .iter()
        .filter(|v| v.is_block())
        .cloned()
        .collect();
    if blocks.is_empty() {
        return Ok(Raised::default());
    }
    check_backend(hv)?;

    let name = inst.name.clone();
    // Called from inside `block_in_place`, which is what makes blocking on
    // the runtime here legal: the worker thread has already been handed back.
    tokio::runtime::Handle::current().block_on(async {
        // Validate every provider before taking the first renewed lease.
        // Doing this inside `raise_all`'s per-volume loop would let a later
        // unsuitable provider refuse the boot only after earlier lease epochs
        // moved.
        preflight_all(&blocks).await?;
        match raise_all(inst, &blocks, boot_intent_id).await {
            Ok(disks) => Ok(disks),
            Err(e) => {
                take_down(&name).await;
                Err(e)
            }
        }
    })
}

/// Prove that every established remote block device still has a measurable
/// direct path before any boot-side mutation begins.
///
/// The direct/<=5ms placement SLO was enforced when `attach` created this
/// holder/provider/lease context. A reboot renews that same context; applying
/// the placement threshold again after sustained I/O would confuse temporary
/// queueing with a changed placement and strand the current holder. A path
/// which has actually fallen back to a relay is still refused here.
async fn preflight_all(blocks: &[Volume]) -> Result<()> {
    for volume in blocks {
        if volume.host_id.is_none() {
            bail!(
                "volume {}:{} predates immutable provider identities; refusing to route it by a reusable device name until its original provider authority is explicitly repaired",
                volume.host,
                volume.path
            );
        }
        preflight_existing_remote_volume(&volume.host)
            .await
            .with_context(|| format!("leasing volume {}:{}", volume.host, volume.path))?;
    }
    Ok(())
}

/// Admit one remote block-volume placement.
///
/// The peer probe is a real exchange over the currently selected QUIC path.
/// A relay remains valid for ordinary orbit control and recovery, but it is
/// not suitable for the synchronous NBD data plane.  Absence of a selected
/// path or measured RTT is also a refusal: guessing would turn an SLO into a
/// label.
pub async fn preflight_remote_volume(device: &str) -> Result<()> {
    if device == plane()?.node.device_name().await {
        return Ok(());
    }
    let observation = measure_remote_volume_link(device).await?;
    admit_remote_volume_link(device, &observation)
}

/// Validate continuity for an attachment whose provider and holder were
/// already admitted. The path must remain direct and measurable, but a busy
/// established volume is not a new placement decision and is not rejected on
/// a transient RTT sample.
async fn preflight_existing_remote_volume(device: &str) -> Result<()> {
    if device == plane()?.node.device_name().await {
        return Ok(());
    }
    let observation = measure_remote_volume_link(device).await?;
    resume_remote_volume_link(device, &observation)
}

async fn measure_remote_volume_link(device: &str) -> Result<mesh::LinkObservation> {
    let plane = plane()?;
    let mesh = plane
        .mesh
        .as_ref()
        .context("this daemon has no mesh endpoint, so it cannot reach another device's volumes")?;
    let observation = mesh
        .measure_link(device)
        .await
        .ok_or_else(|| anyhow!("{UNREACHABLE}: {device}"))?;
    Ok(observation)
}

fn admit_remote_volume_link(device: &str, observation: &mesh::LinkObservation) -> Result<()> {
    let path = observation.path.ok_or_else(|| {
        anyhow!(
            "remote volume placement on {device} refused before mutation: the selected path is \
             not measurable; a direct path with at most {}ms RTT is required",
            REMOTE_VOLUME_MAX_RTT.as_millis()
        )
    })?;
    if path != PathKind::Direct {
        bail!(
            "remote volume placement on {device} refused before mutation: selected path is \
             {path}; remote volumes require a direct path with at most {}ms RTT",
            REMOTE_VOLUME_MAX_RTT.as_millis()
        );
    }
    let rtt = observation.rtt_micros.ok_or_else(|| {
        anyhow!(
            "remote volume placement on {device} refused before mutation: direct-path RTT is \
             not measurable; at most {}ms is required",
            REMOTE_VOLUME_MAX_RTT.as_millis()
        )
    })?;
    if rtt > REMOTE_VOLUME_MAX_RTT.as_micros() as u64 {
        bail!(
            "remote volume placement on {device} refused before mutation: direct-path RTT is \
             {:.1}ms; at most {}ms is required",
            rtt as f64 / 1_000.0,
            REMOTE_VOLUME_MAX_RTT.as_millis()
        );
    }
    Ok(())
}

fn resume_remote_volume_link(device: &str, observation: &mesh::LinkObservation) -> Result<()> {
    let path = observation.path.ok_or_else(|| {
        anyhow!(
            "remote volume resume on {device} refused before mutation: the selected path is \
             not measurable; an existing remote volume still requires a direct path"
        )
    })?;
    if path != PathKind::Direct {
        bail!(
            "remote volume resume on {device} refused before mutation: selected path is \
             {path}; an existing remote volume still requires a direct path"
        );
    }
    if observation.rtt_micros.is_none() {
        bail!(
            "remote volume resume on {device} refused before mutation: direct-path RTT is \
             not measurable"
        );
    }
    Ok(())
}

/// Drop every bridge an instance holds. The lease stays: it belongs to the
/// attachment, not to the boot, so `ast down` followed by `ast up` finds the
/// volume still theirs.
pub async fn take_down(instance: &str) {
    let Ok(plane) = plane() else { return };
    plane.bridges.lock().await.remove(instance);
    plane
        .health
        .lock()
        .await
        .retain(|key, _| key.instance != instance);
}

/// Raise the bridges again for a guest that outlived this daemon.
///
/// A bridge is a unix socket this process binds and an accept loop this
/// process runs, so it dies with the process — and the guest does not. Its
/// backend NBD client is told to keep retrying a dropped volume for
/// `RECONNECT_DELAY_SECS` before it starts failing the guest's I/O, so the
/// window this has to land in is a real one but it is not generous:
/// re-establishing here, before the accept loop opens, is what turns an
/// astd restart into a pause rather than a disk that goes away.
///
/// Deliberately *not* a boot. Nothing is leased at a new epoch, because
/// nothing was lost: the running backend has one export name in its boot
/// configuration and asking the provider for a fresh one would fence the
/// guest that is doing nothing wrong. See [`confirm_lease`].
///
/// Per-volume failures are reported and the rest go up: one unreachable
/// provider must not cost the guest the disks whose providers are awake.
pub async fn reattach(inst: &Instance) {
    let blocks: Vec<Volume> = inst
        .volumes
        .iter()
        .filter(|v| v.is_block())
        .cloned()
        .collect();
    if blocks.is_empty() {
        return;
    }
    let Ok(plane) = plane() else { return };
    let mut raised = Vec::new();
    for vol in &blocks {
        let started = Instant::now();
        let Some(epoch) = vol.epoch else {
            eprintln!(
                "astd: {}:{} is attached to {:?} with no lease recorded, so there \
                 is nothing to reconnect — it will be leased at the next boot",
                vol.host, vol.path, inst.name
            );
            continue;
        };
        match reattach_one(inst, vol, epoch).await {
            Ok((splice, Ok(_export))) => {
                mark_healthy(
                    &inst.name,
                    vol,
                    "daemon_restart",
                    "reconnected",
                    Some(started.elapsed()),
                    None,
                )
                .await;
                eprintln!(
                    "astd: {:?} kept running through this restart — its volume {}:{} \
                     is bridged again at epoch {epoch}",
                    inst.name, vol.host, vol.path
                );
                raised.push(splice);
            }
            Ok((splice, Err(e))) => {
                mark_degraded(
                    &inst.name,
                    vol,
                    "daemon_restart",
                    format!(
                        "reconnect failed after {}ms: {e:#}",
                        duration_millis(started.elapsed())
                    ),
                    None,
                    None,
                )
                .await;
                eprintln!(
                    "astd: could not put {:?}'s volume {}:{} back ({e:#}) — the guest's \
                     writes to that disk are paused; its local bridge is listening and will \
                     reconnect at epoch {epoch} when the provider returns",
                    inst.name, vol.host, vol.path
                );
                // The local socket is the recovery seam. QEMU keeps retrying
                // it; each accepted session asks the provider to validate the
                // same holder and epoch, so a provider which returns can
                // recover this part without a new lease or another restart.
                raised.push(splice);
            }
            Err(e) => {
                mark_degraded(
                    &inst.name,
                    vol,
                    "daemon_restart",
                    format!(
                        "could not restore the local bridge after {}ms: {e:#}",
                        duration_millis(started.elapsed())
                    ),
                    None,
                    None,
                )
                .await;
                eprintln!(
                    "astd: could not bind {:?}'s local bridge for {}:{} ({e:#})",
                    inst.name, vol.host, vol.path
                );
            }
        }
    }
    if !raised.is_empty() {
        plane
            .bridges
            .lock()
            .await
            .entry(inst.name.clone())
            .or_default()
            .extend(raised);
    }
}

async fn reattach_one(
    instance: &Instance,
    vol: &Volume,
    epoch: u64,
) -> Result<(Splice, Result<String>)> {
    // The provider is asked first: an export that is not running comes back
    // here, and a lease that has moved on says so now rather than only as a
    // wall of NBD errors when the guest next writes. Failure does not prevent
    // the local listener from being restored: every later QEMU retry repeats
    // the provider-side epoch check, which is both the safety fence and the
    // path by which a temporarily absent provider recovers.
    let confirmed = confirm_lease(
        &vol.path,
        &vol.host,
        vol.host_id.as_deref(),
        &instance.name,
        &instance.id,
        epoch,
    )
    .await
    .with_context(|| format!("reconnecting to volume {}:{}", vol.host, vol.path));
    let socket = paths::volume_bridge_socket(&instance.name, &vol.host, &vol.path);
    let splice = bridge(&instance.name, &instance.id, vol, epoch, &socket).await?;
    Ok((splice, confirmed))
}

/// Hand back every lease this instance holds — what `ast rm` owes the devices
/// that were keeping bytes for it.
///
/// Every provider must acknowledge its exact volume as free before the
/// immutable instance row may be deleted. A sleeping or refusing provider
/// leaves the row intact; otherwise a same-name replacement would have no
/// authority to release the old identity's lease.
pub async fn release_all(inst: &Instance) -> Result<()> {
    // Validate every immutable authority before releasing the first one. A
    // later legacy row must not leave earlier provider leases released while
    // the instance removal itself is refused.
    let blocks: Vec<(&Volume, &str)> = inst
        .volumes
        .iter()
        .filter(|vol| vol.is_block())
        .map(|vol| {
            let provider_id = vol.host_id.as_deref().with_context(|| {
                format!(
                    "cannot remove {:?}: attached block volume {}:{} has no immutable provider \
                     identity, so its device name may have been reused; preserving every lease and row",
                    inst.name, vol.host, vol.path
                )
            })?;
            Ok((vol, provider_id))
        })
        .collect::<Result<_>>()?;

    for (vol, provider_id) in blocks {
        let response = ask_authority(
            &vol.host,
            Some(provider_id),
            Request::VolumeRelease {
                volume: vol.path.clone(),
                holder: inst.name.clone(),
                holder_id: inst.id.clone(),
                epoch: vol.epoch,
                intent_id: None,
                release_intent_id: None,
            },
        )
        .await
        .with_context(|| {
            format!(
                "releasing {}:{} before instance removal",
                vol.host, vol.path
            )
        })?;
        match response {
            Response::Volumes { volumes }
                if volumes
                    .iter()
                    .any(|candidate| candidate.name == vol.path && candidate.lease.is_none()) => {}
            Response::Error { message } => bail!(message),
            other => bail!(
                "device {:?} did not acknowledge release of volume {:?}: {other:?}",
                vol.host,
                vol.path
            ),
        }
    }
    Ok(())
}

/// Take (or renew) the lease on one volume, from the device that holds it.
///
/// This is what `ast attach` calls, and what every boot calls again. The
/// answer carries the epoch the consumer must present on every splice.
pub async fn take_lease(
    volume: &str,
    device: &str,
    provider_device_id: Option<&str>,
    holder: &str,
    holder_id: &str,
    intent_id: Option<&str>,
) -> Result<(u64, String, u64)> {
    let plane = plane()?;
    let holder_device = plane.node.device_name().await;
    let response = ask_authority(
        device,
        provider_device_id,
        Request::VolumeLease {
            volume: volume.to_owned(),
            holder: holder.to_owned(),
            holder_id: holder_id.to_owned(),
            holder_device,
            holder_device_id: plane.device_id.clone(),
            intent_id: intent_id.map(str::to_owned),
        },
    )
    .await?;
    match response {
        Response::VolumeLease {
            epoch,
            export,
            size_bytes,
            ..
        } => Ok((epoch, export, size_bytes)),
        Response::Error { message } => bail!(message),
        other => bail!("device {device:?} answered a lease request with {other:?}"),
    }
}

/// Confirm the lease this instance already holds, at the epoch it already
/// holds it at, and get the export behind it running again if it is not.
///
/// What a restarted consumer asks, rather than [`take_lease`]: the guest is
/// still up and its backend will ask for the export name it was booted with.
pub(crate) async fn confirm_lease(
    volume: &str,
    device: &str,
    provider_device_id: Option<&str>,
    holder: &str,
    holder_id: &str,
    epoch: u64,
) -> Result<String> {
    match ask_authority(
        device,
        provider_device_id,
        Request::VolumeReconnect {
            volume: volume.to_owned(),
            holder: holder.to_owned(),
            holder_id: holder_id.to_owned(),
            epoch,
        },
    )
    .await?
    {
        Response::VolumeLease { export, .. } => Ok(export),
        Response::Error { message } => bail!(message),
        other => bail!("device {device:?} answered a reconnect with {other:?}"),
    }
}

/// Replay the provider half of a durable user detach.
///
/// A lost success reply is indistinguishable from a refusal caused by a
/// later epoch unless the provider is inspected. Only the exact old
/// holder/device/epoch means the release is still pending; any other state
/// proves this intent no longer owns a writer fence and lets the consumer row
/// be removed without touching the newer authority.
pub async fn release_lease(intent: &asterism_core::volume::ReleaseIntent) -> Result<()> {
    let response = ask_authority(
        &intent.device,
        Some(&intent.provider_device_id),
        Request::VolumeRelease {
            volume: intent.volume.clone(),
            holder: intent.instance.clone(),
            holder_id: intent.instance_id.clone(),
            epoch: Some(intent.epoch),
            intent_id: None,
            release_intent_id: Some(intent.intent_id.clone()),
        },
    )
    .await?;
    match response {
        Response::Error { message } => {
            match ask_authority(
                &intent.device,
                Some(&intent.provider_device_id),
                Request::VolumeList,
            )
            .await?
            {
                Response::Volumes { volumes } => {
                    let exact_lease_remains = volumes
                        .iter()
                        .find(|candidate| candidate.name == intent.volume)
                        .and_then(|candidate| candidate.lease.as_ref())
                        .is_some_and(|lease| {
                            lease.holder_id == intent.instance_id && lease.epoch == intent.epoch
                        });
                    if exact_lease_remains {
                        bail!(message);
                    }
                    Ok(())
                }
                Response::Error { message: listing } => {
                    bail!("{message}; checking release state: {listing}")
                }
                other => bail!(
                    "{message}; device {:?} answered release inspection with {other:?}",
                    intent.device
                ),
            }
        }
        Response::Volumes { volumes }
            if volumes
                .iter()
                .any(|candidate| candidate.name == intent.volume && candidate.lease.is_none()) =>
        {
            Ok(())
        }
        other => bail!(
            "device {:?} did not acknowledge release of volume {:?}: {other:?}",
            intent.device,
            intent.volume
        ),
    }
}

/// Compensate a grant whose reply or consumer commit was ambiguous.
///
/// A release is idempotent when the volume is free. If it is refused because
/// another holder owns the current lease, this intent cannot own anything to
/// release either; confirm that from the provider's authoritative row and
/// regard compensation as complete. A transport failure or a lease still
/// held by this instance remains an error, leaving the consumer intent for
/// startup to retry.
pub async fn compensate_lease(intent: &asterism_core::volume::AttachIntent) -> Result<()> {
    let response = ask_authority(
        &intent.device,
        Some(&intent.provider_device_id),
        Request::VolumeRelease {
            volume: intent.volume.clone(),
            holder: intent.instance.clone(),
            holder_id: intent.instance_id.clone(),
            epoch: None,
            intent_id: Some(intent.intent_id.clone()),
            release_intent_id: None,
        },
    )
    .await?;
    match response {
        Response::Error { message } => {
            match ask_authority(
                &intent.device,
                Some(&intent.provider_device_id),
                Request::VolumeList,
            )
            .await?
            {
                Response::Volumes { volumes } => {
                    let still_ours = volumes
                        .iter()
                        .find(|candidate| candidate.name == intent.volume)
                        .and_then(|candidate| candidate.lease.as_ref())
                        .is_some_and(|lease| {
                            lease.holder_id == intent.instance_id
                                && lease.intent_id.as_deref() == Some(intent.intent_id.as_str())
                        });
                    if still_ours {
                        bail!(message);
                    }
                    Ok(())
                }
                Response::Error { message: listing } => {
                    bail!("{message}; checking compensation state: {listing}")
                }
                other => bail!(
                    "{message}; device {:?} answered compensation inspection with {other:?}",
                    intent.device
                ),
            }
        }
        Response::Volumes { volumes }
            if volumes
                .iter()
                .any(|candidate| candidate.name == intent.volume && candidate.lease.is_none()) =>
        {
            Ok(())
        }
        other => bail!(
            "device {:?} did not acknowledge compensation for volume {:?}: {other:?}",
            intent.device,
            intent.volume
        ),
    }
}

/// Ask a device about one of its volumes — itself, or a peer over the mesh.
///
/// The self case is answered here rather than forwarded, and not only to save
/// a round trip: `up` holds the instance shard while it runs, and a request
/// that went out and came back through the ordinary door would land on that
/// same lock.
async fn ask(device: &str, request: Request) -> Result<Response> {
    let plane = plane()?;
    if device == plane.node.device_name().await {
        return Ok(serve(request).await);
    }
    let mesh = plane
        .mesh
        .as_ref()
        .context("this daemon has no mesh endpoint, so it cannot reach another device's volumes")?;
    mesh.proxy(device, request)
        .await
        .with_context(|| format!("{UNREACHABLE}: {device}"))
}

/// Route by the human name only after proving it still denotes the immutable
/// provider selected by placement. This closes device-name reuse between a
/// durable intent/row and a later retry.
async fn ask_authority(
    device: &str,
    expected_device_id: Option<&str>,
    request: Request,
) -> Result<Response> {
    if let Some(expected) = expected_device_id {
        let actual = provider_identity(device).await?;
        if actual != expected {
            bail!(
                "storage authority {device:?} is now device {actual}, not recorded device \
                 {expected}; refusing to route the volume operation"
            );
        }
    }
    ask(device, request).await
}

/// The backend has to be able to consume an NBD disk. Gated on the
/// capability, never on which backend it is. VZ and Cloud Hypervisor both
/// implement this seam; QEMU remains an optional compatibility consumer.
pub fn check_backend(hv: &dyn Hypervisor) -> Result<()> {
    if hv.probe().is_ok() && !hv.caps().nbd_disks {
        bail!(
            "the {} backend cannot attach a block volume because it has no Unix NBD disk \
             capability",
            hv.id()
        );
    }
    Ok(())
}

async fn raise_all(instance: &Instance, blocks: &[Volume], boot_intent_id: &str) -> Result<Raised> {
    let plane = plane()?;
    // Whatever was bridged for this instance before is gone — a crash
    // supervisor's restart lands here with the dead boot's listeners still in
    // the table, and they own the socket paths this boot is about to bind.
    // Dropping them first is what keeps the unlink on the way out from
    // deleting the new listener's socket.
    plane.bridges.lock().await.remove(&instance.name);

    let mut out = Raised::default();
    let mut raised = Vec::new();
    for vol in blocks {
        let (epoch, export, size_bytes) = take_lease(
            &vol.path,
            &vol.host,
            vol.host_id.as_deref(),
            &instance.name,
            &instance.id,
            Some(boot_intent_id),
        )
        .await
        .with_context(|| format!("leasing volume {}:{}", vol.host, vol.path))?;
        let socket = paths::volume_bridge_socket(&instance.name, &vol.host, &vol.path);
        let splice = bridge(&instance.name, &instance.id, vol, epoch, &socket).await?;
        mark_healthy(&instance.name, vol, "guest_boot", "connected", None, None).await;
        raised.push(splice);
        out.disks.push(DiskSpec::NbdUnix {
            socket,
            export,
            readonly: false,
        });
        out.leases.push(Leased {
            volume: vol.path.clone(),
            device: vol.host.clone(),
            epoch,
            size_bytes,
        });
    }
    plane
        .bridges
        .lock()
        .await
        .insert(instance.name.clone(), raised);
    Ok(out)
}

/// Revoke every provider lease a failed boot intent could have renewed.
///
/// Providers inspect an intent mismatch before treating it as compensated,
/// so this is safe both for volumes the attempt reached and for later ones it
/// never touched. A transport failure remains an error and leaves the
/// consumer's durable boot fence in place.
pub async fn compensate_boot_leases(instance: &Instance, boot_intent_id: &str) -> Result<()> {
    let holder_device_id = plane()?.device_id.clone();
    for vol in instance.volumes.iter().filter(|vol| vol.is_block()) {
        let provider_device_id = vol.host_id.as_deref().with_context(|| {
            format!(
                "volume {}:{} has no immutable provider identity",
                vol.host, vol.path
            )
        })?;
        let mut intent = asterism_core::volume::AttachIntent::new(
            &instance.name,
            &instance.id,
            &vol.path,
            &vol.host,
            provider_device_id,
            &holder_device_id,
        );
        intent.intent_id = boot_intent_id.to_owned();
        compensate_lease(&intent)
            .await
            .with_context(|| format!("compensating boot lease {}:{}", vol.host, vol.path))?;
    }
    take_down(&instance.name).await;
    Ok(())
}

/// Bind the local socket the selected backend will connect to, and splice every connection on
/// it to the provider's export.
///
/// One accept loop per volume, one mesh stream per connection — the same
/// shape `ast ssh` uses, and for the same reason: past the first frame this
/// is a pipe, and neither daemon reads what goes through it.
async fn bridge(
    instance: &str,
    instance_id: &str,
    vol: &Volume,
    epoch: u64,
    socket: &Path,
) -> Result<Splice> {
    if let Some(dir) = socket.parent() {
        std::fs::create_dir_all(dir)?;
    }
    // A socket file from a guest that was killed blocks the bind; the process
    // that owned it is gone with the guest.
    let _ = std::fs::remove_file(socket);
    let listener = tokio::net::UnixListener::bind(socket)
        .with_context(|| format!("binding {} for volume {}", socket.display(), vol.path))?;

    let (device, volume, holder, holder_id) = (
        vol.host.clone(),
        vol.path.clone(),
        instance.to_owned(),
        instance_id.to_owned(),
    );
    let socket_path = socket.to_owned();
    let task = tokio::spawn(async move {
        // A JoinSet, so dropping the bridge takes every live NBD session with
        // it — which is exactly what a revoked lease has to look like.
        let mut sessions = tokio::task::JoinSet::new();
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let (device, volume, holder, holder_id) = (
                device.clone(),
                volume.clone(),
                holder.clone(),
                holder_id.clone(),
            );
            sessions.spawn(async move {
                if let Err(e) =
                    splice_one(&device, &volume, &holder, &holder_id, epoch, stream).await
                {
                    eprintln!(
                        "astd: volume {device}:{volume} for {holder:?} could not be \
                         served: {e:#}"
                    );
                }
            });
            while sessions.try_join_next().is_some() {}
        }
    });
    Ok(Splice::new(task, Some(socket_path)))
}

/// One backend NBD connection, carried to the provider's export.
async fn splice_one(
    device: &str,
    volume: &str,
    holder: &str,
    holder_id: &str,
    epoch: u64,
    mut stream: tokio::net::UnixStream,
) -> Result<()> {
    let plane = plane()?;
    let local_device = plane.node.device_name().await;
    if device == local_device {
        // The provider is this device. There is nothing for the mesh to do:
        // connect the guest's socket to the export socket directly. Same
        // lease, same epoch check, one less hop — `fast and light` is a rule,
        // not a preference (docs/MODEL.md).
        let mut export =
            open_export_for(volume, holder, holder_id, epoch, &local_device, None).await?;
        tokio::io::copy_bidirectional(&mut stream, &mut export).await?;
        return Ok(());
    }
    let mesh = plane
        .mesh
        .as_ref()
        .context("this daemon has no mesh endpoint, so it cannot reach a remote volume")?;
    let vol = Volume::block(volume, device, epoch, 0);
    let opened = mesh
        .open_volume_splice(device, volume, holder, holder_id, epoch)
        .await;
    let (remote, observation) = match opened {
        Ok(opened) => opened,
        Err(e) => {
            mark_degraded(
                holder,
                &vol,
                "provider_loss",
                format!("provider connection failed: {e:#}"),
                None,
                None,
            )
            .await;
            return Err(e);
        }
    };
    let session = mark_session_ready(holder, &vol, observation).await;
    match mesh::pump(stream, remote).await {
        Ok(stats) => {
            mark_degraded(
                holder,
                &vol,
                "provider_loss",
                "the remote NBD session ended; the backend is retrying the local bridge".into(),
                Some(stats),
                Some(session),
            )
            .await;
            Ok(())
        }
        Err(e) => {
            mark_degraded(
                holder,
                &vol,
                "provider_loss",
                format!("remote NBD session failed: {e:#}"),
                None,
                Some(session),
            )
            .await;
            Err(e)
        }
    }
}

async fn mark_session_ready(
    instance: &str,
    vol: &Volume,
    observation: mesh::LinkObservation,
) -> u64 {
    let Ok(plane) = plane() else { return 0 };
    let key = health_key(instance, vol);
    let mut health = plane.health.lock().await;
    let entry = health.entry(key).or_insert_with(|| HealthEntry {
        runtime: PartRuntime {
            state: "healthy".into(),
            path: None,
            rtt_micros: None,
            throughput_bytes_per_sec: None,
            transferred_bytes: None,
            recovery_millis: None,
            transition_reason: "volume_session_ready".into(),
            recovery_result: "connected".into(),
            detail: None,
            observed_at: asterism_core::instance::now_unix(),
        },
        degraded_since: None,
        session: 0,
    });
    let degraded = entry.runtime.state == "degraded";
    let path_changed = entry.runtime.path.as_deref() != observation.path.map(|path| path.as_str());

    if degraded {
        entry.runtime.state = "healthy".into();
        entry.runtime.transition_reason = "provider_returned".into();
        entry.runtime.recovery_result = "reconnected".into();
        entry.runtime.recovery_millis = entry
            .degraded_since
            .map(|since| duration_millis(since.elapsed()));
        entry.runtime.detail = None;
        entry.degraded_since = None;
    } else if path_changed {
        entry.runtime.transition_reason = "selected_path_changed".into();
        entry.runtime.recovery_result = "healthy".into();
    }

    // The control request which opened this bridge measured an application
    // ping. Once the NBD stream is selected, replace that estimate with the
    // transport RTT of the path carrying the volume's bytes without erasing
    // the transition that explains how we got here.
    entry.runtime.path = observation.path.map(|path| path.as_str().to_owned());
    entry.runtime.rtt_micros = observation.rtt_micros;
    entry.runtime.observed_at = asterism_core::instance::now_unix();
    entry.begin_session()
}

#[cfg(test)]
mod tests {
    use super::*;

    use asterism_core::hv::{Caps, DiskFormat};
    use std::io::Read;
    use std::os::unix::net::{UnixListener, UnixStream};

    /// A backend that says what we tell it to about NBD, so the refusal can
    /// be tested without either real hypervisor being installed.
    struct Fake(bool);

    impl Hypervisor for Fake {
        fn id(&self) -> &'static str {
            "vz"
        }
        fn probe(&self) -> Result<asterism_core::hv::Ready> {
            Ok(asterism_core::hv::Ready {
                version: "15.6".into(),
                accel: "vz".into(),
                machine_type: "generic".into(),
                cpu: "host".into(),
            })
        }
        fn caps(&self) -> Caps {
            Caps {
                live_snapshot: false,
                disk_snapshot: false,
                live_migration: false,
                disk_hotplug: false,
                shared_dir: None,
                nbd_disks: self.0,
                foreign_arch: false,
                direct_kernel: false,
                port_forward: false,
                guest_egress: None,
                disk_formats: &[DiskFormat::Raw],
            }
        }
        fn prepare(&self, _: &asterism_core::hv::BootReq) -> Result<asterism_core::hv::Prepared> {
            unimplemented!()
        }
        fn boot(
            &self,
            _: &asterism_core::hv::BootReq,
            _: &asterism_core::hv::Prepared,
        ) -> Result<asterism_core::hv::Handle> {
            unimplemented!()
        }
        fn stop(&self, _: &asterism_core::hv::Handle, _: Duration) -> Result<()> {
            unimplemented!()
        }
        fn kill(&self, _: &asterism_core::hv::Handle) -> Result<()> {
            unimplemented!()
        }
        fn state(&self, _: &asterism_core::hv::Handle) -> Result<asterism_core::hv::RunState> {
            unimplemented!()
        }
    }

    /// A backend without the NBD capability is refused before boot in a
    /// sentence rather than through a backend-specific failure.
    #[test]
    fn a_backend_without_an_nbd_client_refuses_in_words() {
        let err = check_backend(&Fake(false)).unwrap_err().to_string();
        assert!(err.contains("has no Unix NBD disk capability"), "{err}");
        assert!(err.contains("vz"), "{err}");
        assert!(check_backend(&Fake(true)).is_ok());
    }

    #[test]
    fn remote_volume_admission_requires_a_measured_direct_path_within_the_slo() {
        let direct_at_limit = mesh::LinkObservation {
            path: Some(PathKind::Direct),
            rtt_micros: Some(REMOTE_VOLUME_MAX_RTT.as_micros() as u64),
        };
        assert!(admit_remote_volume_link("provider", &direct_at_limit).is_ok());

        let relay = mesh::LinkObservation {
            path: Some(PathKind::Relay),
            rtt_micros: Some(100),
        };
        let error = admit_remote_volume_link("provider", &relay)
            .unwrap_err()
            .to_string();
        assert!(error.contains("refused before mutation"), "{error}");
        assert!(error.contains("selected path is relay"), "{error}");

        let slow = mesh::LinkObservation {
            path: Some(PathKind::Direct),
            rtt_micros: Some(REMOTE_VOLUME_MAX_RTT.as_micros() as u64 + 1),
        };
        let error = admit_remote_volume_link("provider", &slow)
            .unwrap_err()
            .to_string();
        assert!(error.contains("direct-path RTT"), "{error}");
        assert!(error.contains("at most 5ms"), "{error}");

        for unmeasured in [
            mesh::LinkObservation {
                path: None,
                rtt_micros: Some(100),
            },
            mesh::LinkObservation {
                path: Some(PathKind::Direct),
                rtt_micros: None,
            },
        ] {
            let error = admit_remote_volume_link("provider", &unmeasured)
                .unwrap_err()
                .to_string();
            assert!(error.contains("not measurable"), "{error}");
        }
    }

    #[test]
    fn an_existing_lease_requires_direct_continuity_but_not_readmission() {
        let busy_direct = mesh::LinkObservation {
            path: Some(PathKind::Direct),
            rtt_micros: Some(REMOTE_VOLUME_MAX_RTT.as_micros() as u64 + 50_000),
        };
        assert!(
            admit_remote_volume_link("provider", &busy_direct).is_err(),
            "a new placement must still enforce the <=5ms SLO"
        );
        assert!(
            resume_remote_volume_link("provider", &busy_direct).is_ok(),
            "a transient RTT sample must not strand an existing holder"
        );

        let relay = mesh::LinkObservation {
            path: Some(PathKind::Relay),
            rtt_micros: Some(100),
        };
        let error = resume_remote_volume_link("provider", &relay)
            .unwrap_err()
            .to_string();
        assert!(error.contains("refused before mutation"), "{error}");
        assert!(error.contains("selected path is relay"), "{error}");

        for unmeasured in [
            mesh::LinkObservation {
                path: None,
                rtt_micros: Some(100),
            },
            mesh::LinkObservation {
                path: Some(PathKind::Direct),
                rtt_micros: None,
            },
        ] {
            let error = resume_remote_volume_link("provider", &unmeasured)
                .unwrap_err()
                .to_string();
            assert!(error.contains("not measurable"), "{error}");
        }
    }

    /// Volume requests must be recognisable *before* the instance shard is
    /// locked, or a consumer whose provider is itself deadlocks on its own
    /// boot.
    #[test]
    fn the_planes_requests_are_told_apart_from_the_shards() {
        assert!(is_plane_request(&Request::VolumeList));
        assert!(is_orbit_request(&Request::VolumeCatalog));
        assert!(!is_plane_request(&Request::VolumeCatalog));
        assert!(is_plane_request(&Request::VolumeCreate {
            name: "tank".into(),
            size_bytes: 1
        }));
        assert!(is_plane_request(&Request::VolumeLease {
            volume: "tank".into(),
            holder: "dev".into(),
            holder_id: "instance-id".into(),
            holder_device: "laptop".into(),
            holder_device_id: "laptop-id".into(),
            intent_id: Some("intent-id".into()),
        }));
        assert!(!is_plane_request(&Request::List));
        assert!(!is_plane_request(&Request::AttachBlock {
            name: "dev".into(),
            volume: "tank".into(),
            device: "desktop".into(),
        }));
        assert!(!is_orbit_request(&Request::VolumeList));
    }

    #[tokio::test]
    async fn a_mesh_peer_cannot_mint_a_lease_in_another_devices_name() {
        let response = serve_authenticated(
            Request::VolumeLease {
                volume: "tank".into(),
                holder: "dev".into(),
                holder_id: "instance-id".into(),
                holder_device: "victim".into(),
                holder_device_id: "victim-key".into(),
                intent_id: Some("intent-id".into()),
            },
            "attacker",
            "attacker-key",
        )
        .await;
        match response {
            Response::Error { message } => {
                assert!(
                    message.contains("authenticated device \"attacker\""),
                    "{message}"
                );
                assert!(message.contains("device \"victim\""), "{message}");
            }
            other => panic!("an impersonated lease returned {other:?}"),
        }
    }

    #[test]
    fn an_existing_lease_accepts_only_its_authenticated_device() {
        let lease = volume::Lease {
            holder: "dev".into(),
            holder_id: "instance-id".into(),
            holder_device: "laptop".into(),
            holder_device_id: "laptop-id".into(),
            intent_id: Some("intent-id".into()),
            epoch: 1,
            granted_at: 0,
            export: "tank-e1".into(),
            pid: None,
            proc: None,
            export_started: true,
        };
        assert!(authorize_lease_device("tank", &lease, None).is_ok());
        assert!(authorize_lease_device("tank", &lease, Some(("laptop", "laptop-id"))).is_ok());
        let error = authorize_lease_device("tank", &lease, Some(("desktop", "desktop-id")))
            .unwrap_err()
            .to_string();
        assert!(error.contains("leased to device \"laptop\""), "{error}");
        assert!(
            error.contains("authenticated device \"desktop\""),
            "{error}"
        );
    }

    /// Exercise both durable boundaries of the cross-store transition. A
    /// failed volume commit leaves membership and its lease intact; a failed
    /// orbit commit can leave membership intact only after the lease is gone.
    /// Retrying converges, and a different key paired under the old display
    /// name cannot resume the old epoch.
    #[test]
    fn removal_faults_fail_closed_and_same_name_repair_cannot_resume() {
        use asterism_core::durable;

        let dir = tempfile::tempdir().unwrap();
        let orbit_path = dir.path().join("orbit.json");
        let volume_path = dir.path().join("volumes.json");
        let mut orbit = Orbit::load(&orbit_path).unwrap();
        orbit.set_self_name("provider").unwrap();
        orbit
            .add(asterism_core::orbit::device_now(
                "laptop",
                "old-key",
                Vec::new(),
                Vec::new(),
            ))
            .unwrap();
        orbit.save().unwrap();
        let old_device = orbit.get("laptop").unwrap().clone();
        let mut store = Store::load(&volume_path).unwrap();
        store.create("tank", 1 << 30).unwrap();
        let old_epoch = store
            .lease_with_intent("tank", "dev", "instance-id", "laptop", "old-key", None)
            .unwrap()
            .lease
            .unwrap()
            .epoch;
        store.save().unwrap();

        let volume_fault = durable::faults::arm(
            "remove-volume-boundary",
            durable::faults::Point::Rename,
            volume_path.display().to_string(),
            std::io::ErrorKind::Other,
        );
        assert!(remove_device_from_store(&mut orbit, &mut store, &old_device, |_| Ok(())).is_err());
        assert!(orbit.trusts("old-key"));
        assert!(Store::load(&volume_path)
            .unwrap()
            .get("tank")
            .unwrap()
            .lease
            .is_some());
        drop(volume_fault);

        let orbit_fault = durable::faults::arm(
            "remove-orbit-boundary",
            durable::faults::Point::Rename,
            orbit_path.display().to_string(),
            std::io::ErrorKind::Other,
        );
        assert!(remove_device_from_store(&mut orbit, &mut store, &old_device, |_| Ok(())).is_err());
        assert!(
            Orbit::load(&orbit_path).unwrap().trusts("old-key"),
            "a failed membership publish rolls membership back"
        );
        assert!(
            Store::load(&volume_path)
                .unwrap()
                .get("tank")
                .unwrap()
                .lease
                .is_none(),
            "the only intermediate durable state is fail-closed"
        );
        drop(orbit_fault);

        remove_device_from_store(&mut orbit, &mut store, &old_device, |_| Ok(())).unwrap();
        orbit
            .add(asterism_core::orbit::device_now(
                "laptop",
                "new-key",
                Vec::new(),
                Vec::new(),
            ))
            .unwrap();
        orbit.save().unwrap();

        let refusal = authorize_peer(&orbit, "laptop", "old-key")
            .unwrap_err()
            .to_string();
        assert!(refusal.contains("no longer in this orbit"), "{refusal}");
        authorize_peer(&orbit, "laptop", "new-key").unwrap();
        assert!(
            store.reconnect("tank", "dev", old_epoch).is_err(),
            "the old writer's epoch has no lease to resume"
        );
        let next = store
            .lease_with_intent("tank", "dev", "instance-id", "laptop", "new-key", None)
            .unwrap();
        assert_eq!(next.epoch, old_epoch + 1);
    }

    #[test]
    fn exact_old_key_confirmation_preserves_same_name_replacement_authority() {
        let dir = tempfile::tempdir().unwrap();
        let orbit_path = dir.path().join("orbit.json");
        let volume_path = dir.path().join("volumes.json");
        let mut orbit = Orbit::load(&orbit_path).unwrap();
        orbit.set_self_name("provider").unwrap();
        orbit
            .add(asterism_core::orbit::device_now(
                "laptop",
                "old-key",
                Vec::new(),
                Vec::new(),
            ))
            .unwrap();
        orbit.save().unwrap();
        let old = orbit.get("laptop").unwrap().clone();

        let mut store = Store::load(&volume_path).unwrap();
        store.create("tank", 1 << 30).unwrap();
        store
            .lease_with_intent(
                "tank",
                "old-writer",
                "old-instance",
                "laptop",
                "old-key",
                None,
            )
            .unwrap();
        store.save().unwrap();
        store
            .revoke_device_durable_authority("laptop", "old-key")
            .unwrap();
        orbit.remove("laptop").unwrap();
        orbit.save().unwrap();

        orbit
            .add(asterism_core::orbit::device_now(
                "laptop",
                "new-key",
                Vec::new(),
                Vec::new(),
            ))
            .unwrap();
        orbit.save().unwrap();
        let replacement = store
            .lease_with_intent(
                "tank",
                "new-writer",
                "new-instance",
                "laptop",
                "new-key",
                None,
            )
            .unwrap();
        store.save().unwrap();

        remove_device_from_store(&mut orbit, &mut store, &old, |_| Ok(())).unwrap();
        assert!(orbit.trusts("new-key"));
        assert_eq!(orbit.get("laptop").unwrap().device_id, "new-key");
        assert_eq!(
            store
                .get("tank")
                .unwrap()
                .lease
                .as_ref()
                .map(|lease| (&*lease.holder, lease.epoch)),
            Some(("new-writer", replacement.epoch)),
            "confirming old-key must not revoke a lease granted to new-key"
        );
    }

    /// The exact-key membership guard and the volume-store lock are held in
    /// one order on both sides. A grant already inside the guard finishes
    /// first and is then revoked; removal can never slip between its check and
    /// save and leave the newly granted lease behind.
    #[tokio::test]
    async fn an_in_flight_grant_is_included_before_membership_is_removed() {
        let dir = tempfile::tempdir().unwrap();
        let orbit_path = dir.path().join("orbit.json");
        let volume_path = dir.path().join("volumes.json");
        let mut initial_orbit = Orbit::load(&orbit_path).unwrap();
        initial_orbit.set_self_name("provider").unwrap();
        initial_orbit
            .add(asterism_core::orbit::device_now(
                "laptop",
                "old-key",
                Vec::new(),
                Vec::new(),
            ))
            .unwrap();
        initial_orbit.save().unwrap();
        let mut initial_store = Store::load(&volume_path).unwrap();
        initial_store.create("tank", 1 << 30).unwrap();
        initial_store.save().unwrap();

        let orbit = Arc::new(Mutex::new(initial_orbit));
        let store = Arc::new(Mutex::new(initial_store));
        let (inside_tx, inside_rx) = tokio::sync::oneshot::channel();
        let (continue_tx, continue_rx) = tokio::sync::oneshot::channel();

        let granting_orbit = Arc::clone(&orbit);
        let granting_store = Arc::clone(&store);
        let grant = tokio::spawn(async move {
            let membership = granting_orbit.lock().await;
            authorize_peer(&membership, "laptop", "old-key").unwrap();
            inside_tx.send(()).unwrap();
            continue_rx.await.unwrap();
            let mut volumes = granting_store.lock().await;
            volumes
                .lease_with_intent("tank", "dev", "instance-id", "laptop", "old-key", None)
                .unwrap();
            volumes.save().unwrap();
            drop(volumes);
            drop(membership);
        });
        inside_rx.await.unwrap();

        let removing_orbit = Arc::clone(&orbit);
        let removing_store = Arc::clone(&store);
        let removal = tokio::spawn(async move {
            let mut membership = removing_orbit.lock().await;
            let mut volumes = removing_store.lock().await;
            let device = membership.removal_target("laptop").unwrap();
            remove_device_from_store(&mut membership, &mut volumes, &device, |_| Ok(())).unwrap();
        });
        tokio::task::yield_now().await;
        continue_tx.send(()).unwrap();
        grant.await.unwrap();
        removal.await.unwrap();

        assert!(!orbit.lock().await.trusts("old-key"));
        assert!(store.lock().await.get("tank").unwrap().lease.is_none());
    }

    /// A dead export leaves its socket file behind, so liveness is never the
    /// file on its own.
    #[test]
    fn export_liveness_requires_an_exact_runtime_or_legacy_executable_evidence() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("nbd-e1.sock");
        let pidfile = dir.path().join("nbd-e1.pid");
        let me = ProcId::capture(std::process::id()).unwrap();

        assert!(
            !export_alive(None, &socket, &pidfile),
            "nothing recorded, nothing running"
        );
        std::fs::write(&socket, b"").unwrap();
        assert!(
            !export_alive(Some(&me), &socket, &pidfile),
            "a native export needs its exact in-process runtime"
        );
        std::fs::write(&pidfile, me.pid.to_string()).unwrap();
        assert!(
            !export_alive(Some(&me), &socket, &pidfile),
            "a forged legacy pidfile must not turn astd into its own exporter child"
        );
        std::fs::remove_file(&socket).unwrap();
        assert!(
            !export_alive(Some(&me), &socket, &pidfile),
            "a live process with no socket is not an export"
        );
    }

    /// Image admission and socket binding happen before the durable
    /// server-may-run transition. Their definite failure therefore leaves no
    /// imaginary writer, and fixing the image reaches the launch boundary on
    /// the next attempt without manual lease repair.
    #[test]
    fn missing_export_dependencies_are_retryable_before_the_launch_fence() {
        let dir = tempfile::tempdir().unwrap();
        let store_path = dir.path().join("volumes.json");
        let image = dir.path().join("disk.raw");
        let socket = dir.path().join("nbd-e1.sock");
        let pidfile = dir.path().join("nbd-e1.pid");
        let mut store = Store::load(&store_path).unwrap();
        store.create("tank", 1 << 30).unwrap();
        store
            .lease_with_intent("tank", "dev", "instance-id", "laptop", "laptop-id", None)
            .unwrap();
        store.save_confirmed().unwrap();
        let vol = store.get("tank").unwrap().clone();

        let missing_image = prepare_export_start_with(&mut store, &vol, &image, &socket, &pidfile)
            .unwrap_err()
            .to_string();
        assert!(
            missing_image.contains("opening volume image"),
            "{missing_image}"
        );
        assert!(
            !store
                .get("tank")
                .unwrap()
                .lease
                .as_ref()
                .unwrap()
                .export_started
        );

        std::fs::write(&image, b"").unwrap();
        let short_image = prepare_export_start_with(&mut store, &vol, &image, &socket, &pidfile)
            .unwrap_err()
            .to_string();
        assert!(
            short_image.contains("shorter than its advertised"),
            "{short_image}"
        );

        std::fs::OpenOptions::new()
            .write(true)
            .open(&image)
            .unwrap()
            .set_len(1 << 30)
            .unwrap();
        let (armed, launch) =
            prepare_export_start_with(&mut store, &vol, &image, &socket, &pidfile).unwrap();
        assert!(armed.export_started, "retry did not reach launch admission");
        assert!(
            armed
                .proc
                .as_ref()
                .is_some_and(|process| process.pid == std::process::id()),
            "the native launch was not fenced to this exact daemon"
        );
        assert!(socket.exists(), "the admitted listener was not bound");

        // This test deliberately stops at the launch boundary. Since no
        // process was invoked, clearing the marker is proven-safe and shows
        // the retry does not leave a permanent fence behind either.
        drop(launch);
        clear_export_start(&mut store, "tank").unwrap();
        assert!(
            !store
                .get("tank")
                .unwrap()
                .lease
                .as_ref()
                .unwrap()
                .export_started
        );
    }

    /// Removal validates the whole set before contacting any provider. A
    /// pinned first volume must not be released and left dangling in the row
    /// merely because a later legacy row makes deletion unsafe.
    #[tokio::test]
    async fn release_all_fails_on_legacy_authority_before_any_provider_call() {
        let mut inst: Instance = serde_json::from_str(
            r#"{"id":"instance-id","name":"dev","cpu_device":"laptop","status":"stopped",
                "created_at":0,"volumes":[],
                "machine":{"backend":"qemu","machine_type":"virt","cpu":"host","hv_version":"test"}}"#,
        )
        .unwrap();
        inst.volumes.push(Volume::block_owned(
            "pinned",
            "nas",
            Some("nas-id".into()),
            4,
            1 << 30,
        ));
        inst.volumes
            .push(Volume::block("legacy", "old-nas-name", 9, 1 << 30));

        let error = release_all(&inst).await.unwrap_err().to_string();
        assert!(error.contains("legacy"), "{error}");
        assert!(error.contains("preserving every lease and row"), "{error}");
        assert!(
            !error.contains("volume plane was never started"),
            "a provider call happened before full preflight: {error}"
        );
    }

    /// A process that has exec'd `sleep` and will stay there for the test.
    ///
    /// `Command::spawn` returns after the fork, before the child is
    /// necessarily past `exec`. Capturing its identity in that gap can record
    /// the test binary as the executable; once the child becomes `sleep`, the
    /// identity check correctly calls that a replacement. Wait for the
    /// fixture's actual executable before handing its pid to a test.
    fn sleeper() -> std::process::Child {
        let mut child = Command::new("sleep").arg("30").spawn().unwrap();
        let pid = child.id();
        let deadline = Instant::now() + Duration::from_secs(5);

        let failure = loop {
            if let Ok(id) = ProcId::capture(pid) {
                let is_sleep = id
                    .exec
                    .as_deref()
                    .and_then(Path::file_name)
                    .is_some_and(|name| name == "sleep");
                if is_sleep && id.check().is_ours() {
                    return child;
                }
            }

            match child.try_wait() {
                Ok(Some(status)) => {
                    break format!("sleep fixture exited before readiness: {status}")
                }
                Ok(None) => {}
                Err(error) => break format!("checking sleep fixture {pid}: {error}"),
            }
            if Instant::now() >= deadline {
                break format!("sleep fixture {pid} did not exec within five seconds");
            }
            std::thread::sleep(Duration::from_millis(10));
        };

        let _ = child.kill();
        let _ = child.wait();
        panic!("{failure}");
    }

    /// The provider's half of the recycled-pid problem. A lease written
    /// before identities existed names a storage daemon by number; that
    /// number has since been handed to something else, and revoking the
    /// lease used to mean SIGTERM then SIGKILL to whatever holds it.
    #[test]
    fn a_recycled_export_pid_is_neither_believed_nor_signalled() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("nbd-e1.sock");
        let pidfile = dir.path().join("nbd-e1.pid");
        std::fs::write(&socket, b"").unwrap();

        let mut sleeper = sleeper();
        let real = ProcId::capture(sleeper.id()).unwrap();
        let mut stale = real.clone();
        if let Some(ticks) = stale.started_ticks.as_mut() {
            *ticks -= 1;
        } else {
            stale.started_us -= 1;
        }

        assert!(
            !export_alive(Some(&stale), &socket, &pidfile),
            "not our export any more"
        );
        let stale_pid = stale.pid;
        let lease = volume::Lease {
            holder: "dev".into(),
            holder_id: "instance-id".into(),
            holder_device: "laptop".into(),
            holder_device_id: "laptop-id".into(),
            intent_id: None,
            epoch: 1,
            granted_at: 0,
            export: "tank-e1".into(),
            pid: Some(stale.pid),
            proc: Some(stale),
            export_started: true,
        };
        std::fs::write(&pidfile, stale_pid.to_string()).unwrap();
        let error = stop_export_at("tank", &lease, &socket, &pidfile)
            .unwrap_err()
            .to_string();
        assert!(error.contains("refusing to send"), "{error}");
        assert!(socket.exists(), "an unproven writer lost its socket name");
        assert!(pidfile.exists(), "an unproven writer lost its pid evidence");
        assert!(real.alive(), "nobody else was killed to close the door");

        let _ = sleeper.kill();
        let _ = sleeper.wait();
    }

    /// A lease from an older daemon carries a pid and no identity. It reads
    /// as unproven, not dead, and keeps the writer fence closed.
    #[test]
    fn a_pre_identity_lease_is_not_believed() {
        let json = format!(
            r#"{{"holder":"dev","holder_device":"laptop","epoch":1,"granted_at":0,
                 "export":"tank-e1","pid":{}}}"#,
            std::process::id()
        );
        let lease: volume::Lease = serde_json::from_str(&json).unwrap();
        assert_eq!(lease.pid, Some(std::process::id()));
        assert_eq!(lease.proc, None, "a pid is not an identity");
        assert!(lease.export_started, "legacy authority fails closed");

        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("nbd-e1.sock");
        let pidfile = dir.path().join("nbd-e1.pid");
        std::fs::write(&socket, b"").unwrap();
        assert!(!export_alive(lease.proc.as_ref(), &socket, &pidfile));
        std::fs::write(&pidfile, lease.pid.unwrap().to_string()).unwrap();
        assert!(stop_export_at("tank", &lease, &socket, &pidfile).is_err());
        assert!(
            socket.exists(),
            "unproven death must not masquerade as revocation"
        );
    }

    /// Subprocess half of `revocation_kills_the_server_before_unlinking`.
    #[test]
    fn export_process_fixture() {
        let Ok(socket) = std::env::var("ASTERISM_TEST_EXPORT_SOCKET") else {
            return;
        };
        let listener = UnixListener::bind(socket).unwrap();
        let (_client, _) = listener.accept().unwrap();
        loop {
            std::thread::park();
        }
    }

    /// A connected Unix client survives unlink, so revocation must terminate
    /// the serving process first. Exercise that boundary with a real child
    /// process and a connection opened before the release.
    #[test]
    fn revocation_kills_the_server_before_unlinking() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("nbd-e7.sock");
        let pidfile = dir.path().join("nbd-e7.pid");
        let legacy_exporter = dir.path().join(volume::LEGACY_EXPORT_BIN);
        std::fs::copy(std::env::current_exe().unwrap(), &legacy_exporter).unwrap();
        let mut child = std::process::Command::new(&legacy_exporter)
            .arg("--exact")
            .arg("volume::tests::export_process_fixture")
            .arg("--nocapture")
            .env("ASTERISM_TEST_EXPORT_SOCKET", &socket)
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut old_client = loop {
            match UnixStream::connect(&socket) {
                Ok(client) => break client,
                Err(error) => {
                    if let Some(status) = child.try_wait().unwrap() {
                        panic!("export fixture exited before accepting a client: {status}");
                    }
                    assert!(
                        Instant::now() < deadline,
                        "export fixture did not accept a client: {error}"
                    );
                    std::thread::sleep(Duration::from_millis(10));
                }
            }
        };
        old_client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let proc = ProcId::capture(child.id()).unwrap();
        std::fs::write(&pidfile, proc.pid.to_string()).unwrap();
        let lease = volume::Lease {
            holder: "dev".into(),
            holder_id: "instance-id".into(),
            holder_device: "laptop".into(),
            holder_device_id: "laptop-id".into(),
            intent_id: Some("boot-intent".into()),
            epoch: 7,
            granted_at: 0,
            export: "tank-e7".into(),
            pid: Some(proc.pid),
            proc: Some(proc.clone()),
            export_started: true,
        };

        stop_export_at("tank", &lease, &socket, &pidfile).unwrap();
        assert!(!proc.alive(), "release acknowledged while its server lived");
        assert!(!socket.exists(), "dead export socket was not removed");
        assert!(!pidfile.exists(), "dead export pidfile was not removed");
        let mut byte = [0u8; 1];
        match old_client.read(&mut byte) {
            Ok(0) | Err(_) => {}
            Ok(n) => panic!("old client read {n} bytes after revocation"),
        }
        child.wait().unwrap();
    }

    #[test]
    fn a_new_volume_session_fences_a_late_disconnect_observation() {
        let runtime = PartRuntime {
            state: "healthy".into(),
            path: Some("direct".into()),
            rtt_micros: Some(500),
            throughput_bytes_per_sec: None,
            transferred_bytes: None,
            recovery_millis: None,
            transition_reason: "guest_boot".into(),
            recovery_result: "connected".into(),
            detail: None,
            observed_at: 1,
        };
        let mut entry = HealthEntry {
            runtime,
            degraded_since: None,
            session: 0,
        };

        let old = entry.begin_session();
        let current = entry.begin_session();
        assert!(!entry.owns_session(old));
        assert!(entry.owns_session(current));
    }
}
