//! Block volumes: the provider that serves them, the lease that fences them,
//! and the bridge that carries them to a guest on another device.
//!
//! One device is the **provider** — the bytes are on its disk. It runs
//! `qemu-storage-daemon`, which exports the volume as NBD **on a unix socket**
//! under the volume's own directory. Never a TCP port: nothing about a volume
//! is reachable from the LAN, at either end, ever.
//!
//! Another device is the **consumer** — its hypervisor is running the guest.
//! Its `astd` binds a *local* unix socket next to the instance and splices
//! every connection on it over an authenticated QUIC stream to the provider's
//! export socket. QEMU is pointed at the local socket with
//! `-blockdev nbd,server.type=unix,...`, and the guest sees `/dev/vdb`:
//!
//! ```text
//! QEMU ─unix─ astd(consumer) ═QUIC/mesh═ astd(provider) ─unix─ qemu-storage-daemon ─ disk
//! ```
//!
//! It is the same splice `ast ssh` uses, aimed at a different socket, which is
//! the point: one piece of plumbing, tested twice.
//!
//! # One writer, and how it is enforced
//!
//! The lease lives on the provider ([`asterism_core::volume`]). Attaching
//! takes it; booting renews it; both bump a monotonic epoch. Every bump
//! renames the export (`tank-e7`), stops the previous `qemu-storage-daemon`
//! and unlinks the socket it was on — so a consumer that was partitioned and
//! comes back holding epoch 6 has nothing to reconnect to. The refusal a
//! second instance gets names the holder and the device its cpu comes from,
//! because "busy" is not something anybody can act on.
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
//! never went anywhere, and QEMU sits retrying the socket for
//! `RECONNECT_DELAY_SECS` before it starts failing the guest's I/O.
//!
//! [`reattach`] is what closes that: at startup, every running instance
//! whose guest is still alive gets its bridges raised again, at the epoch it
//! already holds. Not a fresh lease — the running QEMU was handed one export
//! name on its command line, and a bump would rename that door out from
//! under a guest doing nothing wrong. See [`Request::VolumeReconnect`].

use std::collections::HashMap;
use std::path::Path;
use std::process::Command;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use tokio::sync::Mutex;

use asterism_core::hv::{DiskSpec, Hypervisor};
use asterism_core::instance::{Instance, PartRuntime, Status, Volume};
use asterism_core::paths;
use asterism_core::proc::{ProcId, Signal};
use asterism_core::protocol::{Request, Response};
use asterism_core::tools::{run, tool};
use asterism_core::volume::{self, BlockVolume, Store};

use crate::mesh::{self, Mesh, Splice, TransferStats};
use crate::Node;

/// How long to wait for a freshly started export to put its socket on disk.
/// `qemu-storage-daemon --daemonize` returns once startup is complete, so
/// this is a guard against a slow filesystem, not a poll for readiness.
const EXPORT_READY: Duration = Duration::from_secs(5);

/// What a consumer is told when the provider's daemon is not answering.
/// Named because the e2e asserts on it: an honest failure is a feature here,
/// and a wall of QEMU errors is not one.
pub const UNREACHABLE: &str = "could not reach the device holding it";

// ---- the plane -------------------------------------------------------------

struct Plane {
    node: Node,
    mesh: Option<Arc<Mesh>>,
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
    let _ = PLANE.set(Plane {
        node,
        mesh,
        store: Mutex::new(store),
        bridges: Mutex::new(HashMap::new()),
        health: Mutex::new(HashMap::new()),
    });
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

/// Answer one volume request against this device's own volumes.
pub async fn serve(req: Request) -> Response {
    let result = match req {
        Request::VolumeCreate { name, size_bytes } => create(&name, size_bytes).await,
        Request::VolumeList => list().await,
        Request::VolumeRemove { name } => remove(&name).await,
        Request::VolumeLease {
            volume,
            holder,
            holder_device,
        } => grant(&volume, &holder, &holder_device).await,
        Request::VolumeReconnect {
            volume,
            holder,
            epoch,
        } => resume(&volume, &holder, epoch).await,
        Request::VolumeRelease { volume, holder } => release(&volume, &holder).await,
        other => Err(anyhow!("{other:?} is not a volume request")),
    };
    match result {
        Ok(response) => response,
        Err(e) => Response::Error {
            message: format!("{e:#}"),
        },
    }
}

async fn create(name: &str, size_bytes: u64) -> Result<Response> {
    let plane = plane()?;
    let mut store = plane.store.lock().await;
    let vol = store.create(name, size_bytes)?;

    // The bytes, then the bookkeeping: a saved record with no image behind it
    // would be a volume that exists until you use it.
    let dir = paths::volume_dir(name);
    std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    let image = paths::volume_image_path(name);
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&image)
        .with_context(|| format!("creating {}", image.display()))?;
    // Sparse: it claims its size and occupies what has been written, the same
    // deal an instance's own disk gets.
    file.set_len(size_bytes)?;
    drop(file);

    store.save()?;
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
    let vol = store.remove(name)?;
    store.save()?;
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
async fn grant(name: &str, holder: &str, holder_device: &str) -> Result<Response> {
    let plane = plane()?;
    let mut store = plane.store.lock().await;
    let previous = store.get(name).ok().and_then(|v| v.lease.clone());
    let vol = store.lease(name, holder, holder_device)?;
    store.save()?;

    if let Some(old) = previous {
        stop_export(name, old.epoch, old.proc.as_ref());
    }
    let lease = vol.lease.clone().expect("a grant leaves a lease");
    let proc = start_export(&vol, lease.epoch, &lease.export)?;
    store.set_export_proc(name, Some(proc))?;
    store.save()?;

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
async fn resume(name: &str, holder: &str, epoch: u64) -> Result<Response> {
    let plane = plane()?;
    let mut store = plane.store.lock().await;
    let vol = store.reconnect(name, holder, epoch)?;
    let lease = vol.lease.clone().expect("reconnect checked the lease");

    let socket = paths::volume_export_socket(name, lease.epoch);
    if !export_alive(lease.proc.as_ref(), &socket) {
        let proc = start_export(&vol, lease.epoch, &lease.export)?;
        store.set_export_proc(name, Some(proc))?;
        store.save()?;
    }
    Ok(Response::VolumeLease {
        volume: vol.name.clone(),
        epoch: lease.epoch,
        export: lease.export,
        socket: socket.display().to_string(),
        size_bytes: vol.size_bytes,
    })
}

async fn release(name: &str, holder: &str) -> Result<Response> {
    let plane = plane()?;
    let mut store = plane.store.lock().await;
    let released = store.release(name, holder)?;
    store.save()?;
    if let Some(lease) = released {
        stop_export(name, lease.epoch, lease.proc.as_ref());
    }
    Ok(Response::Volumes {
        volumes: vec![store.get(name)?.clone()],
    })
}

/// Connect to the export serving `volume` at `epoch`, on behalf of `holder`.
///
/// This is the far end of a splice, and it is where the fence is checked: a
/// holder that is not the one on the lease, or an epoch that is not the
/// current one, gets a refusal rather than a pipe. Nothing about the reply
/// tells a stale consumer what the new epoch is; it has to go and ask for a
/// lease, which is the code path that decides whether it may have one.
pub async fn open_export(volume: &str, holder: &str, epoch: u64) -> Result<tokio::net::UnixStream> {
    let plane = plane()?;
    let mut store = plane.store.lock().await;
    let vol = store.get(volume)?.clone();
    let Some(lease) = vol.lease.clone() else {
        bail!("volume {volume:?} is not leased to anything — attach it first");
    };
    if lease.holder != holder {
        bail!("{}", volume::held_by(volume, &lease));
    }
    if lease.epoch != epoch {
        bail!("{}", volume::fenced(volume, holder, epoch, lease.epoch));
    }

    // The export may be gone even though the lease is not: the provider's
    // daemon may have restarted, or its storage daemon may have been killed.
    // Restarting it at the *same* epoch is safe, because the epoch is what
    // decides who may write and it has not moved.
    let socket = paths::volume_export_socket(volume, lease.epoch);
    if !export_alive(lease.proc.as_ref(), &socket) {
        let proc = start_export(&vol, lease.epoch, &lease.export)?;
        store.set_export_proc(volume, Some(proc))?;
        store.save()?;
    }
    drop(store);

    tokio::net::UnixStream::connect(&socket)
        .await
        .with_context(|| format!("connecting to the export for volume {volume:?}"))
}

/// Give every pre-identity lease on this device an identity, once.
///
/// The volume half of the startup migration, run beside
/// [`crate::backend::adopt_identities`] and for the same reason: a lease
/// written by an older daemon names its storage daemon by pid alone, and a
/// pid that has outlived a daemon restart is not evidence of anything.
///
/// A lease that cannot be adopted is left with no identity, which reads as
/// an export that is not running — and that is a state this plane already
/// recovers from by starting the export again at the *same* epoch, so
/// nothing is fenced and no consumer notices.
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
                 ({why}) — it will be started again when something asks for it",
                vol.name
            ),
        }
    }
    if changed {
        if let Err(e) = store.save() {
            eprintln!("astd: saving volumes after adopting export identities: {e:#}");
        }
    }
}

// ---- qemu-storage-daemon ---------------------------------------------------

/// Start the storage daemon for one epoch's export.
///
/// Tracked exactly the way the vz helper is: an identity captured from the
/// pidfile it writes at startup, and a socket that answers. Neither alone is
/// enough — a socket file outlives the process that bound it, and a pid on
/// its own proves nothing at all once this daemon has restarted — so
/// liveness is both.
fn start_export(vol: &BlockVolume, epoch: u64, export: &str) -> Result<ProcId> {
    let qsd = tool("qemu-storage-daemon").context(
        "qemu-storage-daemon is what serves a block volume, and it is not installed \
         on this device (it ships with qemu)",
    )?;
    let image = paths::volume_image_path(&vol.name);
    if !image.exists() {
        bail!(
            "volume {:?} has lost its image at {}",
            vol.name,
            image.display()
        );
    }
    let socket = paths::volume_export_socket(&vol.name, epoch);
    let pidfile = paths::volume_export_pid(&vol.name, epoch);
    // A socket file left by a killed daemon blocks the bind.
    let _ = std::fs::remove_file(&socket);
    let _ = std::fs::remove_file(&pidfile);

    run(Command::new(&qsd)
        .arg("--daemonize")
        .arg("--pidfile")
        .arg(&pidfile)
        .arg("--blockdev")
        .arg(format!(
            "driver=file,node-name=vol,filename={}",
            image.display()
        ))
        .arg("--nbd-server")
        .arg(format!("addr.type=unix,addr.path={}", socket.display()))
        .arg("--export")
        .arg(format!(
            "type=nbd,id=exp,node-name=vol,name={export},writable=on"
        )))
    .with_context(|| format!("exporting volume {:?} as {export}", vol.name))?;

    let deadline = std::time::Instant::now() + EXPORT_READY;
    loop {
        if socket.exists() && pidfile.exists() {
            break;
        }
        if std::time::Instant::now() >= deadline {
            bail!(
                "qemu-storage-daemon did not put an export socket at {}",
                socket.display()
            );
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let pid: u32 = std::fs::read_to_string(&pidfile)
        .context("qemu-storage-daemon did not write its pidfile")?
        .trim()
        .parse()
        .context("unparseable qemu-storage-daemon pidfile")?;
    // Captured while the process is still known to be the one just started.
    // Everything later done to this export — including the SIGKILL that ends
    // a revoked lease — is authorised by this and nothing else.
    ProcId::capture(pid).with_context(|| {
        format!(
            "qemu-storage-daemon wrote pid {pid} for volume {:?} and was gone before it \
             could be recorded",
            vol.name
        )
    })
}

/// Stop an export and take its socket with it.
///
/// The unlink is the revocation: `qemu-storage-daemon` leaves its socket file
/// behind when it dies, and a socket file that outlives its export is a thing
/// a fenced consumer could keep knocking at forever.
///
/// The signals go only to a process this daemon can still prove is the
/// export it started ([`ProcId`]). A lease whose recorded process cannot be
/// proven gets the unlink and nothing else: whatever is at that pid now, it
/// is not this export, and a revocation is not worth a stranger's SIGKILL.
fn stop_export(name: &str, epoch: u64, proc: Option<&ProcId>) {
    if let Some(proc) = proc {
        match proc.signal(Signal::Term) {
            Ok(true) => {
                if !proc.wait_gone(Duration::from_secs(5)) {
                    let _ = proc.signal(Signal::Kill);
                }
            }
            // Already gone: the unlink below is the rest of the revocation.
            Ok(false) => {}
            Err(e) => eprintln!("astd: not stopping the export for volume {name:?}: {e:#}"),
        }
    }
    let _ = std::fs::remove_file(paths::volume_export_socket(name, epoch));
    let _ = std::fs::remove_file(paths::volume_export_pid(name, epoch));
}

/// Is the export for this lease still being served?
///
/// Both halves, and neither is redundant: a socket file outlives whoever
/// bound it, and a recorded process may since have become somebody else's.
fn export_alive(proc: Option<&ProcId>, socket: &Path) -> bool {
    proc.is_some_and(|p| p.alive()) && socket.exists()
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
pub fn bring_up(inst: &Instance, hv: &dyn Hypervisor) -> Result<Raised> {
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
        match raise_all(&name, &blocks).await {
            Ok(disks) => Ok(disks),
            Err(e) => {
                take_down(&name).await;
                Err(e)
            }
        }
    })
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
/// QEMU is told to keep retrying a dropped volume for
/// `RECONNECT_DELAY_SECS` before it starts failing the guest's I/O, so the
/// window this has to land in is a real one but it is not generous:
/// re-establishing here, before the accept loop opens, is what turns an
/// astd restart into a pause rather than a disk that goes away.
///
/// Deliberately *not* a boot. Nothing is leased at a new epoch, because
/// nothing was lost: the running QEMU has one export name on its command
/// line and asking the provider for a fresh one would fence the guest that
/// is doing nothing wrong. See [`confirm_lease`].
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
        match reattach_one(&inst.name, vol, epoch).await {
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
    instance: &str,
    vol: &Volume,
    epoch: u64,
) -> Result<(Splice, Result<String>)> {
    // The provider is asked first: an export that is not running comes back
    // here, and a lease that has moved on says so now rather than only as a
    // wall of NBD errors when the guest next writes. Failure does not prevent
    // the local listener from being restored: every later QEMU retry repeats
    // the provider-side epoch check, which is both the safety fence and the
    // path by which a temporarily absent provider recovers.
    let confirmed = confirm_lease(&vol.path, &vol.host, instance, epoch)
        .await
        .with_context(|| format!("reconnecting to volume {}:{}", vol.host, vol.path));
    let socket = paths::volume_bridge_socket(instance, &vol.host, &vol.path);
    let splice = bridge(instance, vol, epoch, &socket).await?;
    Ok((splice, confirmed))
}

/// Hand back every lease this instance holds — what `ast rm` owes the devices
/// that were keeping bytes for it.
///
/// Best effort by design: a provider that is asleep must not stop someone
/// deleting an instance. What that leaves behind is a lease held by a name
/// nothing answers to any more, and the way out of it is that a lease is
/// keyed by that *name*: an instance created with it again may take the same
/// lease (that is what makes every boot a renewal), and detaching then gives
/// it back. Narrow, and it costs a record rather than a byte of anybody's
/// data.
pub async fn release_all(inst: &Instance) {
    for vol in inst.volumes.iter().filter(|v| v.is_block()) {
        if let Err(e) = ask(
            &vol.host,
            Request::VolumeRelease {
                volume: vol.path.clone(),
                holder: inst.name.clone(),
            },
        )
        .await
        {
            eprintln!(
                "astd: could not hand {}:{} back ({e:#}) — it stays leased to {:?}",
                vol.host, vol.path, inst.name
            );
        }
    }
}

/// Take (or renew) the lease on one volume, from the device that holds it.
///
/// This is what `ast attach` calls, and what every boot calls again. The
/// answer carries the epoch the consumer must present on every splice.
pub async fn take_lease(volume: &str, device: &str, holder: &str) -> Result<(u64, String, u64)> {
    let plane = plane()?;
    let holder_device = plane.node.device_name().await;
    let response = ask(
        device,
        Request::VolumeLease {
            volume: volume.to_owned(),
            holder: holder.to_owned(),
            holder_device,
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
/// still up and its QEMU will ask for the export name it was booted with.
async fn confirm_lease(volume: &str, device: &str, holder: &str, epoch: u64) -> Result<String> {
    match ask(
        device,
        Request::VolumeReconnect {
            volume: volume.to_owned(),
            holder: holder.to_owned(),
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

/// Give one volume's lease back.
pub async fn give_lease_back(volume: &str, device: &str, holder: &str) -> Result<()> {
    match ask(
        device,
        Request::VolumeRelease {
            volume: volume.to_owned(),
            holder: holder.to_owned(),
        },
    )
    .await?
    {
        Response::Error { message } => bail!(message),
        _ => Ok(()),
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

/// The backend has to be able to consume an NBD disk. Gated on the
/// capability, never on which backend it is — except that today exactly one
/// says yes, and the refusal should say so plainly rather than in the
/// abstract.
pub fn check_backend(hv: &dyn Hypervisor) -> Result<()> {
    if hv.probe().is_ok() && !hv.caps().nbd_disks {
        bail!(
            "the {} backend cannot attach a block volume — remote volumes ride the \
             qemu backend today",
            hv.id()
        );
    }
    Ok(())
}

async fn raise_all(instance: &str, blocks: &[Volume]) -> Result<Raised> {
    let plane = plane()?;
    // Whatever was bridged for this instance before is gone — a crash
    // supervisor's restart lands here with the dead boot's listeners still in
    // the table, and they own the socket paths this boot is about to bind.
    // Dropping them first is what keeps the unlink on the way out from
    // deleting the new listener's socket.
    plane.bridges.lock().await.remove(instance);

    let mut out = Raised::default();
    let mut raised = Vec::new();
    for vol in blocks {
        let (epoch, export, size_bytes) = take_lease(&vol.path, &vol.host, instance)
            .await
            .with_context(|| format!("leasing volume {}:{}", vol.host, vol.path))?;
        let socket = paths::volume_bridge_socket(instance, &vol.host, &vol.path);
        let splice = bridge(instance, vol, epoch, &socket).await?;
        mark_healthy(instance, vol, "guest_boot", "connected", None, None).await;
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
        .insert(instance.to_owned(), raised);
    Ok(out)
}

/// Bind the local socket QEMU will connect to, and splice every connection on
/// it to the provider's export.
///
/// One accept loop per volume, one mesh stream per connection — the same
/// shape `ast ssh` uses, and for the same reason: past the first frame this
/// is a pipe, and neither daemon reads what goes through it.
async fn bridge(instance: &str, vol: &Volume, epoch: u64, socket: &Path) -> Result<Splice> {
    if let Some(dir) = socket.parent() {
        std::fs::create_dir_all(dir)?;
    }
    // A socket file from a guest that was killed blocks the bind; the process
    // that owned it is gone with the guest.
    let _ = std::fs::remove_file(socket);
    let listener = tokio::net::UnixListener::bind(socket)
        .with_context(|| format!("binding {} for volume {}", socket.display(), vol.path))?;

    let (device, volume, holder) = (vol.host.clone(), vol.path.clone(), instance.to_owned());
    let socket_path = socket.to_owned();
    let task = tokio::spawn(async move {
        // A JoinSet, so dropping the bridge takes every live NBD session with
        // it — which is exactly what a revoked lease has to look like.
        let mut sessions = tokio::task::JoinSet::new();
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let (device, volume, holder) = (device.clone(), volume.clone(), holder.clone());
            sessions.spawn(async move {
                if let Err(e) = splice_one(&device, &volume, &holder, epoch, stream).await {
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

/// One QEMU connection, carried to the provider's export.
async fn splice_one(
    device: &str,
    volume: &str,
    holder: &str,
    epoch: u64,
    mut stream: tokio::net::UnixStream,
) -> Result<()> {
    let plane = plane()?;
    if device == plane.node.device_name().await {
        // The provider is this device. There is nothing for the mesh to do:
        // connect the guest's socket to the export socket directly. Same
        // lease, same epoch check, one less hop — `fast and light` is a rule,
        // not a preference (docs/MODEL.md).
        let mut export = open_export(volume, holder, epoch).await?;
        tokio::io::copy_bidirectional(&mut stream, &mut export).await?;
        return Ok(());
    }
    let mesh = plane
        .mesh
        .as_ref()
        .context("this daemon has no mesh endpoint, so it cannot reach a remote volume")?;
    let vol = Volume::block(volume, device, epoch, 0);
    let opened = mesh.open_volume_splice(device, volume, holder, epoch).await;
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
                "the remote NBD session ended; QEMU is retrying the local bridge".into(),
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

    /// vz has `VZNetworkBlockDeviceStorageDeviceAttachment` and this backend
    /// does not drive it, so `Caps::nbd_disks` is false and the refusal has
    /// to be a sentence rather than a hypervisor error.
    #[test]
    fn a_backend_without_an_nbd_client_refuses_in_words() {
        let err = check_backend(&Fake(false)).unwrap_err().to_string();
        assert!(
            err.contains("remote volumes ride the qemu backend today"),
            "{err}"
        );
        assert!(err.contains("vz"), "{err}");
        assert!(check_backend(&Fake(true)).is_ok());
    }

    /// Volume requests must be recognisable *before* the instance shard is
    /// locked, or a consumer whose provider is itself deadlocks on its own
    /// boot.
    #[test]
    fn the_planes_requests_are_told_apart_from_the_shards() {
        assert!(is_plane_request(&Request::VolumeList));
        assert!(is_plane_request(&Request::VolumeCreate {
            name: "tank".into(),
            size_bytes: 1
        }));
        assert!(is_plane_request(&Request::VolumeLease {
            volume: "tank".into(),
            holder: "dev".into(),
            holder_device: "laptop".into(),
        }));
        assert!(!is_plane_request(&Request::List));
        assert!(!is_plane_request(&Request::AttachBlock {
            name: "dev".into(),
            volume: "tank".into(),
            device: "desktop".into(),
        }));
    }

    /// A dead export leaves its socket file behind, so liveness is never the
    /// file on its own.
    #[test]
    fn an_export_is_alive_only_when_both_halves_are() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("nbd-e1.sock");
        let me = ProcId::capture(std::process::id()).unwrap();

        assert!(
            !export_alive(None, &socket),
            "nothing recorded, nothing running"
        );
        std::fs::write(&socket, b"").unwrap();
        // Our own process is certainly alive, and the file is there.
        assert!(export_alive(Some(&me), &socket));
        std::fs::remove_file(&socket).unwrap();
        assert!(
            !export_alive(Some(&me), &socket),
            "a live process with no socket is not an export"
        );
    }

    /// The provider's half of the recycled-pid problem. A lease written
    /// before identities existed names a storage daemon by number; that
    /// number has since been handed to something else, and revoking the
    /// lease used to mean SIGTERM then SIGKILL to whatever holds it.
    #[test]
    fn a_recycled_export_pid_is_neither_believed_nor_signalled() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("nbd-e1.sock");
        std::fs::write(&socket, b"").unwrap();

        let mut sleeper = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let real = ProcId::capture(sleeper.id()).unwrap();
        let stale = ProcId {
            started_us: real.started_us - 1,
            ..real.clone()
        };

        assert!(
            !export_alive(Some(&stale), &socket),
            "not our export any more"
        );
        // Revocation still runs — the unlink of the lease's own socket is
        // the fence, and it does not depend on any process — but the
        // stranger holding the number is left alone.
        stop_export("tank", 1, Some(&stale));
        assert!(real.alive(), "nobody else was killed to close the door");

        let _ = sleeper.kill();
        let _ = sleeper.wait();
    }

    /// A lease from an older daemon carries a pid and no identity, and that
    /// is not evidence of anything: the export reads as not running, which
    /// this plane recovers from by starting it again at the same epoch.
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

        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("nbd-e1.sock");
        std::fs::write(&socket, b"").unwrap();
        assert!(!export_alive(lease.proc.as_ref(), &socket));
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
