//! Live health for the network exit-point part.
//!
//! Durable policy lives in `asterism_core::network`; this module contributes
//! only current mesh observations to `ast status`. The registry is never
//! mutated with them, matching the remote-volume health seam.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use asterism_core::hv::GuestNetwork;
use asterism_core::instance::{now_unix, Instance, PartRuntime};
use asterism_core::network::{
    guest_macs, Availability, DnsPolicy, ExitGrant, ExitHealth, ExitPoint, PathKind,
    ProviderObservation, GUEST_DNS, GUEST_GATEWAY,
};
use asterism_mesh::PathKind as MeshPathKind;
use futures::{SinkExt, StreamExt};
use netstack_smoltcp::StackBuilder;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{watch, Semaphore};

use crate::mesh::Mesh;

static MESH: OnceLock<Option<Arc<Mesh>>> = OnceLock::new();
static PLANES: OnceLock<Mutex<HashMap<String, Plane>>> = OnceLock::new();
static SELECTIONS: OnceLock<Mutex<HashMap<String, StickySelection>>> = OnceLock::new();
static UDP_FLOWS: OnceLock<
    tokio::sync::Mutex<HashMap<UdpFlowKey, Arc<tokio::sync::Mutex<crate::mesh::ExitUdpSession>>>>,
> = OnceLock::new();
static LOCAL_UDP_FLOWS: OnceLock<
    tokio::sync::Mutex<HashMap<LocalUdpFlowKey, Arc<tokio::sync::Mutex<tokio::net::UdpSocket>>>>,
> = OnceLock::new();

const EDGE_MTU: usize = 1500;
const MAX_FRAME: usize = EDGE_MTU + 14;
const FLOW_TIMEOUT: Duration = Duration::from_secs(30);
const FLOW_LIFETIME: Duration = Duration::from_secs(10 * 60);
const MAX_TCP_FLOWS: usize = 512;
const MAX_UDP_DATAGRAMS: usize = 1024;
pub(crate) const EDGE_GENERATION: &str = "unix-restricted-v1";

struct Plane {
    instance_id: String,
    endpoint: PathBuf,
    policy: Arc<RwLock<Option<ExitPoint>>>,
    generation: watch::Sender<u64>,
    task: tokio::task::JoinHandle<()>,
}

struct StickySelection {
    provider: String,
    checked_at: Instant,
    failures: u8,
    recovery_candidate: Option<(String, Instant)>,
}

#[derive(Clone, PartialEq, Eq, Hash)]
struct UdpFlowKey {
    provider: String,
    instance_id: String,
    generation: u64,
    remote: SocketAddr,
    system_dns: bool,
}

#[derive(Clone, PartialEq, Eq, Hash)]
struct LocalUdpFlowKey {
    instance_id: String,
    remote: SocketAddr,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ExitTransition {
    expected_exit: bool,
    expected_grants: BTreeMap<String, ExitGrant>,
    #[serde(default)]
    pending: BTreeMap<String, ExitGrant>,
    #[serde(default)]
    pending_scopes: BTreeSet<String>,
    revoke: BTreeMap<String, ExitGrant>,
}

pub(crate) fn init(mesh: Option<Arc<Mesh>>) {
    let _ = MESH.set(mesh);
}

/// Deterministic process-crash coordination for the real acceptance lane.
/// It is inert unless the daemon owner supplies a private directory and arms
/// one exact point by creating `<point>.arm`; production has no timing branch
/// and an unarmed test daemon has only the environment lookup.
pub(crate) async fn test_pause(point: &str) {
    let Some(dir) = std::env::var_os("ASTERISM_EXIT_TEST_PAUSE_DIR").map(PathBuf::from) else {
        return;
    };
    let arm = dir.join(format!("{point}.arm"));
    if std::fs::remove_file(&arm).is_err() {
        return;
    }
    let ready = dir.join(format!("{point}.ready"));
    let release = dir.join(format!("{point}.release"));
    if std::fs::create_dir_all(&dir).is_err() || std::fs::write(&ready, b"ready\n").is_err() {
        return;
    }
    while !release.exists() {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let _ = std::fs::remove_file(release);
    let _ = std::fs::remove_file(ready);
}

/// Obtain every remote provider's durable consent before publishing policy
/// in the instance shard. A partial failure is rolled back best-effort and
/// the old policy remains authoritative.
pub(crate) async fn grant(inst: &Instance, mut exit: ExitPoint) -> Result<ExitPoint> {
    exit.routes.normalize().map_err(anyhow::Error::msg)?;
    exit.dns.normalize().map_err(anyhow::Error::msg)?;
    exit.grants.clear();
    exit.validate().map_err(anyhow::Error::msg)?;
    let remote: Vec<String> = exit
        .providers
        .iter()
        .filter(|provider| *provider != &inst.cpu_device)
        .cloned()
        .collect();
    let mesh = if remote.is_empty() {
        None
    } else {
        Some(
            MESH.get()
                .and_then(Option::as_ref)
                .context("remote exit providers require the authenticated mesh")?,
        )
    };
    let mut pending_scopes = BTreeSet::new();
    for provider in remote {
        if !mesh
            .expect("remote providers established a mesh")
            .knows(&provider)
            .await
        {
            let rollback = abort_transition(inst, &exit).await;
            let error = anyhow::anyhow!("the orbit has no exit provider named {provider:?}");
            return Err(match rollback {
                Ok(()) => error,
                Err(rollback) => error.context(format!(
                    "also failed to roll back newly issued exit grants: {rollback:#}"
                )),
            });
        }
        pending_scopes.insert(provider.clone());
        if let Err(error) = stage_transition_with_scopes(inst, Some(&exit), &pending_scopes) {
            let rollback = abort_transition(inst, &exit).await;
            return Err(match rollback {
                Ok(()) => error,
                Err(rollback) => error.context(format!(
                    "also failed to roll back newly issued exit grants: {rollback:#}"
                )),
            });
        }
        match mesh
            .expect("remote providers established a mesh")
            .request_exit_grant(&provider, &inst.id, &exit.routes, &exit.dns)
            .await
        {
            Ok(grant) => {
                exit.grants.insert(provider.clone(), grant.clone());
                if let Err(error) = stage_transition_with_scopes(inst, Some(&exit), &pending_scopes)
                {
                    let rollback = abort_transition(inst, &exit).await;
                    return Err(match rollback {
                        Ok(()) => error,
                        Err(rollback) => error.context(format!(
                            "also failed to roll back newly issued exit grants: {rollback:#}"
                        )),
                    });
                }
            }
            Err(error) => {
                let rollback = abort_transition(inst, &exit).await;
                let error = error.context("the exit provider did not grant this attachment");
                return Err(match rollback {
                    Ok(()) => error,
                    Err(rollback) => error.context(format!(
                        "also failed to roll back newly issued exit grants: {rollback:#}"
                    )),
                });
            }
        }
    }
    // Also records removal of old providers when the new policy is entirely
    // local (and refreshes the final expected map after incremental staging).
    if let Err(error) = stage_transition_with_scopes(inst, Some(&exit), &pending_scopes) {
        let rollback = abort_transition(inst, &exit).await;
        return Err(match rollback {
            Ok(()) => error,
            Err(rollback) => error.context(format!(
                "also failed to roll back newly issued exit grants: {rollback:#}"
            )),
        });
    }
    Ok(exit)
}

pub(crate) fn stage_transition(inst: &Instance, next: Option<&ExitPoint>) -> Result<()> {
    stage_transition_with_scopes(inst, next, &BTreeSet::new())
}

fn stage_transition_with_scopes(
    inst: &Instance,
    next: Option<&ExitPoint>,
    pending_scopes: &BTreeSet<String>,
) -> Result<()> {
    let old = inst
        .exit_point
        .as_ref()
        .map(|exit| exit.grants.clone())
        .unwrap_or_default();
    let Some(transition) = plan_transition(&old, next, pending_scopes) else {
        let _ = std::fs::remove_file(transition_path(inst));
        return Ok(());
    };
    asterism_core::durable::commit_json_private(&transition_path(inst), &transition)
        .context("staging exit revocations behind the registry commit")
}

fn plan_transition(
    old: &BTreeMap<String, ExitGrant>,
    next: Option<&ExitPoint>,
    pending_scopes: &BTreeSet<String>,
) -> Option<ExitTransition> {
    let expected = next.map(|exit| exit.grants.clone()).unwrap_or_default();
    let revoke = old
        .iter()
        .filter(|(provider, grant)| expected.get(*provider) != Some(*grant))
        .map(|(provider, grant)| (provider.clone(), grant.clone()))
        .collect::<BTreeMap<_, _>>();
    let pending = expected
        .into_iter()
        .filter(|(provider, grant)| old.get(provider) != Some(grant))
        .collect::<BTreeMap<_, _>>();
    if revoke.is_empty() && pending.is_empty() && pending_scopes.is_empty() {
        return None;
    }
    Some(ExitTransition {
        expected_exit: next.is_some(),
        expected_grants: next.map(|exit| exit.grants.clone()).unwrap_or_default(),
        pending,
        pending_scopes: pending_scopes.clone(),
        revoke,
    })
}

fn transition_path(inst: &Instance) -> PathBuf {
    asterism_core::paths::instance_dir(&inst.name).join("exit-transition.json")
}

/// Activate grants after the consumer shard containing their exact policy is
/// durable. Startup calls this again for recorded policy, making a crash
/// between save and activation a fail-closed retry rather than an orphan
/// authority.
pub(crate) async fn activate(inst: &Instance) -> Result<()> {
    if let Some(exit) = &inst.exit_point {
        for (provider, grant) in &exit.grants {
            let mesh = MESH
                .get()
                .and_then(Option::as_ref)
                .context("remote exit activation requires the authenticated mesh")?;
            mesh.activate_exit_grant(provider, &inst.id, grant.generation)
                .await
                .with_context(|| format!("activating exit grant on {provider:?}"))?;
        }
    }
    reconcile_transition(inst).await?;
    Ok(())
}

async fn reconcile_transition(inst: &Instance) -> Result<()> {
    let path = transition_path(inst);
    let Ok(bytes) = std::fs::read(&path) else {
        return Ok(());
    };
    let transition: ExitTransition =
        serde_json::from_slice(&bytes).context("reading staged exit transition")?;
    let current = inst
        .exit_point
        .as_ref()
        .map(|exit| exit.grants.clone())
        .unwrap_or_default();
    if transition.expected_exit != inst.exit_point.is_some()
        || transition.expected_grants != current
    {
        discard_pending_scopes(inst, &transition.pending_scopes).await?;
        revoke_grants(
            inst,
            &transition.pending,
            "rolling back uncommitted exit provider",
        )
        .await?;
        std::fs::remove_file(&path).context("discarding an uncommitted exit transition")?;
        return Ok(());
    }
    revoke_grants(
        inst,
        &transition.revoke,
        "reconciling removed exit provider",
    )
    .await?;
    std::fs::remove_file(&path).context("clearing reconciled exit transition")?;
    Ok(())
}

fn newly_issued(inst: &Instance, next: &ExitPoint) -> BTreeMap<String, ExitGrant> {
    let old = inst
        .exit_point
        .as_ref()
        .map(|exit| &exit.grants)
        .cloned()
        .unwrap_or_default();
    next.grants
        .iter()
        .filter(|(provider, grant)| old.get(*provider) != Some(*grant))
        .map(|(provider, grant)| (provider.clone(), grant.clone()))
        .collect()
}

async fn revoke_grants(
    inst: &Instance,
    grants: &BTreeMap<String, ExitGrant>,
    action: &str,
) -> Result<()> {
    if grants.is_empty() {
        return Ok(());
    }
    let mesh = MESH
        .get()
        .and_then(Option::as_ref)
        .context("exit grant rollback requires the authenticated mesh")?;
    let mut failures = Vec::new();
    for (provider, grant) in grants {
        if let Err(error) = mesh
            .revoke_exit_grant(provider, &inst.id, grant.generation)
            .await
        {
            failures.push(format!("{action} {provider:?}: {error:#}"));
        }
    }
    if !failures.is_empty() {
        anyhow::bail!(failures.join("; "));
    }
    Ok(())
}

async fn discard_pending_scopes(inst: &Instance, providers: &BTreeSet<String>) -> Result<()> {
    if providers.is_empty() {
        return Ok(());
    }
    let mesh = MESH
        .get()
        .and_then(Option::as_ref)
        .context("pending exit cleanup requires the authenticated mesh")?;
    let mut failures = Vec::new();
    for provider in providers {
        if let Err(error) = mesh.discard_pending_exit_grants(provider, &inst.id).await {
            failures.push(format!(
                "discarding pending exit grants on {provider:?}: {error:#}"
            ));
        }
    }
    if !failures.is_empty() {
        anyhow::bail!(failures.join("; "));
    }
    Ok(())
}

/// Undo grants not present in the old durable shard. The transition is
/// cleared only after every provider confirms revocation; otherwise startup
/// retains the durable retry record.
pub(crate) async fn abort_transition(inst: &Instance, next: &ExitPoint) -> Result<()> {
    let path = transition_path(inst);
    if let Ok(bytes) = std::fs::read(&path) {
        let transition: ExitTransition =
            serde_json::from_slice(&bytes).context("reading exit transition for rollback")?;
        discard_pending_scopes(inst, &transition.pending_scopes).await?;
    }
    revoke_grants(
        inst,
        &newly_issued(inst, next),
        "rolling back newly issued exit provider",
    )
    .await?;
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).context("clearing rolled-back exit transition"),
    }
}

/// Provider revocation is part of detach, not eventual cleanup. Returning
/// before the grant is gone would leave long-lived privacy flows alive after
/// the operator was told the attachment had been removed.
pub(crate) async fn revoke(inst: &Instance) -> Result<()> {
    let Some(exit) = &inst.exit_point else {
        return Ok(());
    };
    for (provider, grant) in &exit.grants {
        let mesh = MESH
            .get()
            .and_then(Option::as_ref)
            .context("remote exit revocation requires the authenticated mesh")?;
        mesh.revoke_exit_grant(provider, &inst.id, grant.generation)
            .await
            .with_context(|| format!("revoking exit grant from {provider:?}"))?;
    }
    Ok(())
}

/// Raise the stable guest edge before the hypervisor starts.
///
/// The listener is loopback-only and the backend receives only its endpoint
/// plus stable NIC identities. Policy is held separately so attach, failover,
/// and detach can change the provider without changing anything in the guest.
pub(crate) fn bring_up(inst: &Instance) -> Result<GuestNetwork> {
    bring_up_inner(inst)
}

/// Reattach only a guest proved to have been booted with the deterministic
/// Unix edge and restricted primary slirp. An older live QEMU must be fenced
/// and rebooted; binding a new socket beside it would leave a privacy bypass.
pub(crate) fn reattach(inst: &Instance) -> Result<GuestNetwork> {
    if !restart_compatible(inst) {
        anyhow::bail!("legacy packet edge requires a security-fenced guest restart");
    }
    bring_up_inner(inst)
}

pub(crate) fn restart_compatible(inst: &Instance) -> bool {
    inst.handle
        .as_ref()
        .and_then(|handle| handle.packet_edge_generation.as_deref())
        == Some(EDGE_GENERATION)
}

fn bring_up_inner(inst: &Instance) -> Result<GuestNetwork> {
    let planes = PLANES.get_or_init(|| Mutex::new(HashMap::new()));
    let mut planes = planes.lock().expect("network-plane table poisoned");
    if let Some(plane) = planes.get(&inst.name) {
        *plane.policy.write().expect("network policy poisoned") = inst.exit_point.clone();
        let (primary_mac, edge_mac) = guest_macs(&inst.id);
        return Ok(GuestNetwork {
            endpoint: plane.endpoint.clone(),
            primary_mac,
            edge_mac,
        });
    }

    let endpoint = asterism_core::paths::exit_socket(&inst.name);
    if let Some(parent) = endpoint.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating packet-edge directory {}", parent.display()))?;
    }
    match std::fs::remove_file(&endpoint) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error).context("removing the stale guest packet edge"),
    }
    let listener = tokio::net::UnixListener::bind(&endpoint)
        .with_context(|| format!("binding guest packet edge {}", endpoint.display()))?;
    std::fs::set_permissions(&endpoint, std::fs::Permissions::from_mode(0o600))
        .context("restricting the guest packet edge to the daemon user")?;
    let policy = Arc::new(RwLock::new(inst.exit_point.clone()));
    let (generation, generation_rx) = watch::channel(1_u64);
    let task = tokio::spawn(accept_guest_edges(
        listener,
        inst.name.clone(),
        inst.cpu_device.clone(),
        inst.id.clone(),
        policy.clone(),
        generation_rx,
        guest_macs(&inst.id).1,
    ));
    planes.insert(
        inst.name.clone(),
        Plane {
            instance_id: inst.id.clone(),
            endpoint: endpoint.clone(),
            policy,
            generation,
            task,
        },
    );
    let (primary_mac, edge_mac) = guest_macs(&inst.id);
    Ok(GuestNetwork {
        endpoint,
        primary_mac,
        edge_mac,
    })
}

/// Change only the provider policy behind an already-running guest edge.
pub(crate) fn update(name: &str, policy: Option<ExitPoint>) {
    let Some(planes) = PLANES.get() else { return };
    let planes = planes.lock().expect("network-plane table poisoned");
    if let Some(plane) = planes.get(name) {
        *plane.policy.write().expect("network policy poisoned") = policy;
        if let Some(selections) = SELECTIONS.get() {
            selections
                .lock()
                .expect("exit selection table poisoned")
                .remove(&plane.instance_id);
        }
        plane
            .generation
            .send_modify(|generation| *generation = generation.saturating_add(1));
    }
}

/// Drop the listener and all packet/flow tasks owned by an instance.
pub(crate) fn take_down(name: &str) {
    let Some(planes) = PLANES.get() else { return };
    if let Some(plane) = planes
        .lock()
        .expect("network-plane table poisoned")
        .remove(name)
    {
        plane.task.abort();
        if let Some(selections) = SELECTIONS.get() {
            selections
                .lock()
                .expect("exit selection table poisoned")
                .remove(&plane.instance_id);
        }
        let _ = std::fs::remove_file(plane.endpoint);
    }
}

async fn accept_guest_edges(
    listener: tokio::net::UnixListener,
    name: String,
    cpu_device: String,
    instance_id: String,
    policy: Arc<RwLock<Option<ExitPoint>>>,
    generation: watch::Receiver<u64>,
    guest_mac: [u8; 6],
) {
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            return;
        };
        let name = name.clone();
        let cpu_device = cpu_device.clone();
        let instance_id = instance_id.clone();
        let policy = policy.clone();
        let generation = generation.clone();
        let mut active = tokio::spawn(async move {
            if let Err(error) = run_guest_edge(
                stream,
                &cpu_device,
                &instance_id,
                policy,
                generation,
                guest_mac,
            )
            .await
            {
                eprintln!("astd: packet edge for {name:?} stopped: {error:#}");
            }
        });
        // One QEMU owns an instance edge. Refuse extra local clients while
        // it is connected instead of giving each one its own network stack.
        loop {
            tokio::select! {
                _ = &mut active => break,
                accepted = listener.accept() => match accepted {
                    Ok((extra, _)) => drop(extra),
                    Err(_) => {
                        active.abort();
                        return;
                    }
                }
            }
        }
    }
}

async fn run_guest_edge(
    stream: tokio::net::UnixStream,
    cpu_device: &str,
    instance_id: &str,
    policy: Arc<RwLock<Option<ExitPoint>>>,
    generation: watch::Receiver<u64>,
    guest_mac: [u8; 6],
) -> Result<()> {
    let (stack, runner, udp, tcp) = StackBuilder::default()
        .enable_tcp(true)
        .enable_udp(true)
        .enable_icmp(true)
        .mtu(EDGE_MTU)
        .add_ip_filter_fn({
            let policy = policy.clone();
            move |_source, destination| permits(&policy, *destination)
        })
        .build()
        .context("building the guest userspace network stack")?;
    let runner_task = runner.map(tokio::spawn);

    let (mut stack_sink, mut stack_stream) = stack.split();
    let (mut reader, mut writer) = stream.into_split();
    let (frames_tx, mut frames_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(256);

    let mut to_guest = tokio::spawn(async move {
        while let Some(frame) = frames_rx.recv().await {
            write_qemu_frame(&mut writer, &frame).await?;
        }
        Ok::<(), anyhow::Error>(())
    });
    let mut stack_to_guest = tokio::spawn({
        let frames_tx = frames_tx.clone();
        async move {
            while let Some(packet) = stack_stream.next().await {
                let packet = packet?;
                frames_tx
                    .send(ethernet_ip_frame(guest_mac, &packet)?)
                    .await
                    .map_err(|_| anyhow::anyhow!("guest packet writer stopped"))?;
            }
            Ok::<(), anyhow::Error>(())
        }
    });
    let mut guest_to_stack = tokio::spawn({
        let frames_tx = frames_tx.clone();
        async move {
            loop {
                let frame = read_qemu_frame(&mut reader).await?;
                match ethernet_payload(&frame)? {
                    EthernetPayload::Ip(packet) => stack_sink.send(packet.to_vec()).await?,
                    EthernetPayload::ArpRequest {
                        sender_mac,
                        sender_ip,
                        target_ip,
                    } => {
                        frames_tx
                            .send(arp_reply(sender_mac, sender_ip, target_ip))
                            .await
                            .map_err(|_| anyhow::anyhow!("guest packet writer stopped"))?;
                    }
                    EthernetPayload::Ignore => {}
                }
            }
            #[allow(unreachable_code)]
            Ok::<(), anyhow::Error>(())
        }
    });

    let tcp = tcp.context("TCP was enabled without a listener")?;
    let udp = udp.context("UDP was enabled without a socket")?;
    let mut tcp_task = tokio::spawn(forward_tcp(
        tcp,
        cpu_device.to_owned(),
        instance_id.to_owned(),
        policy.clone(),
        generation.clone(),
        Arc::new(Semaphore::new(MAX_TCP_FLOWS)),
    ));
    let mut udp_task = tokio::spawn(forward_udp(
        udp,
        cpu_device.to_owned(),
        instance_id.to_owned(),
        policy,
        generation,
        Arc::new(Semaphore::new(MAX_UDP_DATAGRAMS)),
    ));

    let result: Result<()> = tokio::select! {
        result = &mut to_guest => result
            .context("guest packet writer task failed")
            .and_then(|result| result),
        result = &mut stack_to_guest => result
            .context("userspace stack output task failed")
            .and_then(|result| result),
        result = &mut guest_to_stack => result
            .context("guest packet reader task failed")
            .and_then(|result| result),
        result = &mut tcp_task => match result {
            Ok(()) => Err(anyhow::anyhow!("exit TCP listener stopped")),
            Err(error) => Err(error).context("exit TCP listener task failed"),
        },
        result = &mut udp_task => match result {
            Ok(()) => Err(anyhow::anyhow!("exit UDP listener stopped")),
            Err(error) => Err(error).context("exit UDP listener task failed"),
        },
    };
    to_guest.abort();
    stack_to_guest.abort();
    guest_to_stack.abort();
    tcp_task.abort();
    udp_task.abort();
    if let Some(runner_task) = runner_task {
        runner_task.abort();
    }
    result
}

fn permits(policy: &RwLock<Option<ExitPoint>>, destination: IpAddr) -> bool {
    if destination == GUEST_DNS {
        return true;
    }
    if is_edge_control(destination) {
        return false;
    }
    policy
        .read()
        .expect("network policy poisoned")
        .as_ref()
        .is_none_or(|exit| {
            let explicit_resolver = matches!(
                &exit.dns,
                DnsPolicy::Custom(servers) if servers.contains(&destination)
            );
            (asterism_core::network::is_public_unicast(destination) || explicit_resolver)
                && exit.routes.permits(destination, false)
        })
}

fn is_edge_control(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            let octets = address.octets();
            octets[0..3] == [100, 64, 0]
        }
        IpAddr::V6(address) => address.segments()[0..3] == [0xfd64, 0x6173, 0x7400],
    }
}

async fn forward_tcp(
    mut listener: netstack_smoltcp::TcpListener,
    cpu_device: String,
    instance_id: String,
    policy: Arc<RwLock<Option<ExitPoint>>>,
    generation: watch::Receiver<u64>,
    permits: Arc<Semaphore>,
) {
    while let Some((stream, _local, remote)) = listener.next().await {
        let cpu_device = cpu_device.clone();
        let policy = policy.clone();
        let mut generation = generation.clone();
        let instance_id = instance_id.clone();
        let Ok(permit) = permits.clone().try_acquire_owned() else {
            eprintln!("astd: refusing exit TCP flow: per-instance limit reached");
            continue;
        };
        tokio::spawn(async move {
            let _permit = permit;
            let forwarding = forward_one_tcp(stream, &cpu_device, &instance_id, policy, remote);
            let result = tokio::select! {
                result = forwarding => result,
                _ = generation.changed() => Err(anyhow::anyhow!("exit policy generation changed")),
            };
            if let Err(error) = result {
                eprintln!("astd: exit TCP flow to {remote} failed: {error:#}");
            }
        });
    }
}

async fn forward_one_tcp(
    mut guest: netstack_smoltcp::TcpStream,
    cpu_device: &str,
    instance_id: &str,
    policy: Arc<RwLock<Option<ExitPoint>>>,
    remote: SocketAddr,
) -> Result<()> {
    let snapshot = policy.read().expect("network policy poisoned").clone();
    let (provider, remote, system_dns, grant) =
        select_flow(&snapshot, cpu_device, instance_id, remote).await?;
    if provider == cpu_device {
        let remote = resolve_dns_target(remote, system_dns)?;
        let mut upstream =
            tokio::time::timeout(FLOW_TIMEOUT, tokio::net::TcpStream::connect(remote))
                .await
                .context("exit TCP connect timed out")??;
        tokio::time::timeout(
            FLOW_LIFETIME,
            tokio::io::copy_bidirectional(&mut guest, &mut upstream),
        )
        .await
        .context("exit TCP flow reached its lifetime limit")??;
    } else {
        let mesh = MESH
            .get()
            .and_then(Option::as_ref)
            .context("the selected remote exit has no mesh transport")?;
        let grant = grant.context("the selected remote exit has no attachment grant")?;
        let stream = mesh
            .open_exit_tcp(&provider, instance_id, &grant, remote, system_dns)
            .await?;
        tokio::time::timeout(FLOW_LIFETIME, crate::mesh::pump(guest, stream))
            .await
            .context("exit TCP flow reached its lifetime limit")??;
    }
    Ok(())
}

async fn forward_udp(
    socket: netstack_smoltcp::UdpSocket,
    cpu_device: String,
    instance_id: String,
    policy: Arc<RwLock<Option<ExitPoint>>>,
    generation: watch::Receiver<u64>,
    permits: Arc<Semaphore>,
) {
    let (mut inbound, mut outbound) = socket.split();
    let (reply_tx, mut reply_rx) = tokio::sync::mpsc::channel(256);
    tokio::spawn(async move {
        while let Some(reply) = reply_rx.recv().await {
            if outbound.send(reply).await.is_err() {
                return;
            }
        }
    });
    while let Some((payload, local, remote)) = inbound.next().await {
        let cpu_device = cpu_device.clone();
        let policy = policy.clone();
        let mut generation = generation.clone();
        let instance_id = instance_id.clone();
        let reply_tx = reply_tx.clone();
        let Ok(permit) = permits.clone().try_acquire_owned() else {
            eprintln!("astd: refusing exit UDP datagram: per-instance limit reached");
            continue;
        };
        tokio::spawn(async move {
            let _permit = permit;
            let forwarding = forward_one_udp(&cpu_device, &instance_id, policy, remote, payload);
            let result = tokio::select! {
                result = forwarding => result,
                _ = generation.changed() => Err(anyhow::anyhow!("exit policy generation changed")),
            };
            match result {
                Ok(payload) => {
                    let _ = reply_tx.send((payload, remote, local)).await;
                }
                Err(error) => eprintln!("astd: exit UDP flow to {remote} failed: {error:#}"),
            }
        });
    }
}

async fn forward_one_udp(
    cpu_device: &str,
    instance_id: &str,
    policy: Arc<RwLock<Option<ExitPoint>>>,
    remote: SocketAddr,
    payload: Vec<u8>,
) -> Result<Vec<u8>> {
    let snapshot = policy.read().expect("network policy poisoned").clone();
    let (provider, remote, system_dns, grant) =
        select_flow(&snapshot, cpu_device, instance_id, remote).await?;
    if provider != cpu_device {
        let mesh = MESH
            .get()
            .and_then(Option::as_ref)
            .context("the selected remote exit has no mesh transport")?;
        let grant = grant.context("the selected remote exit has no attachment grant")?;
        let key = UdpFlowKey {
            provider: provider.clone(),
            instance_id: instance_id.to_owned(),
            generation: grant.generation,
            remote,
            system_dns,
        };
        let flows = UDP_FLOWS.get_or_init(|| tokio::sync::Mutex::new(HashMap::new()));
        let session = {
            let mut table = flows.lock().await;
            if let Some(session) = table.get(&key) {
                session.clone()
            } else {
                if table.len() >= MAX_UDP_DATAGRAMS {
                    if let Some(oldest) = table.keys().next().cloned() {
                        table.remove(&oldest);
                    }
                }
                drop(table);
                let opened = mesh
                    .open_exit_udp(&provider, instance_id, &grant, remote, system_dns)
                    .await?;
                let opened = Arc::new(tokio::sync::Mutex::new(opened));
                let mut table = flows.lock().await;
                table.entry(key.clone()).or_insert(opened).clone()
            }
        };
        let result = session.lock().await.exchange(payload).await;
        if result.is_err() {
            flows.lock().await.remove(&key);
        }
        return result;
    }
    let remote = resolve_dns_target(remote, system_dns)?;
    let key = LocalUdpFlowKey {
        instance_id: instance_id.to_owned(),
        remote,
    };
    let flows = LOCAL_UDP_FLOWS.get_or_init(|| tokio::sync::Mutex::new(HashMap::new()));
    let socket = {
        let mut flows = flows.lock().await;
        if let Some(socket) = flows.get(&key) {
            socket.clone()
        } else {
            if flows.len() >= MAX_UDP_DATAGRAMS {
                if let Some(oldest) = flows.keys().next().cloned() {
                    flows.remove(&oldest);
                }
            }
            let bind = if remote.is_ipv4() {
                "0.0.0.0:0"
            } else {
                "[::]:0"
            };
            let opened = tokio::net::UdpSocket::bind(bind).await?;
            opened.connect(remote).await?;
            let opened = Arc::new(tokio::sync::Mutex::new(opened));
            flows.insert(key.clone(), opened.clone());
            opened
        }
    };
    let socket = socket.lock().await;
    socket.send(&payload).await?;
    let mut reply = vec![0; EDGE_MTU];
    let count = tokio::time::timeout(FLOW_TIMEOUT, socket.recv(&mut reply))
        .await
        .context("exit UDP reply timed out")??;
    reply.truncate(count);
    Ok(reply)
}

async fn select_flow(
    policy: &Option<ExitPoint>,
    cpu_device: &str,
    instance_id: &str,
    remote: SocketAddr,
) -> Result<(String, SocketAddr, bool, Option<ExitGrant>)> {
    if remote.ip() == GUEST_DNS && remote.port() != 53 {
        anyhow::bail!("the virtual DNS endpoint accepts only port 53");
    }
    let Some(exit) = policy else {
        return Ok((
            cpu_device.to_owned(),
            remote,
            remote.ip() == GUEST_DNS,
            None,
        ));
    };
    let dns_flow = remote.ip() == GUEST_DNS;
    if dns_flow && exit.dns == DnsPolicy::CpuDevice {
        return Ok((cpu_device.to_owned(), remote, true, None));
    }
    let provider = select_sticky(exit, cpu_device, instance_id).await?;
    let (remote, system_dns) = match (&exit.dns, dns_flow) {
        (DnsPolicy::Custom(servers), true) => {
            let server = servers.first().context("custom DNS has no resolver")?;
            (SocketAddr::new(*server, remote.port()), false)
        }
        (DnsPolicy::ExitPoint, true) => (remote, true),
        _ => (remote, false),
    };
    let grant = (provider != cpu_device)
        .then(|| exit.grants.get(&provider).cloned())
        .flatten();
    Ok((provider, remote, system_dns, grant))
}

async fn select_sticky(exit: &ExitPoint, cpu_device: &str, instance_id: &str) -> Result<String> {
    let selections = SELECTIONS.get_or_init(|| Mutex::new(HashMap::new()));
    if let Some(provider) = selections
        .lock()
        .expect("exit selection table poisoned")
        .get(instance_id)
        .filter(|selection| {
            selection.checked_at.elapsed() < Duration::from_secs(1)
                && exit.providers.contains(&selection.provider)
        })
        .map(|selection| selection.provider.clone())
    {
        return Ok(provider);
    }

    let observations = observations(exit, cpu_device, instance_id).await;
    let selected = exit
        .select(cpu_device, &observations)
        .ok()
        .map(|selection| selection.provider.to_owned());
    let now = Instant::now();
    let mut changed = false;
    let result = {
        let mut selections = selections.lock().expect("exit selection table poisoned");
        match selections.get_mut(instance_id) {
            None => match selected {
                Some(provider) => {
                    selections.insert(
                        instance_id.to_owned(),
                        StickySelection {
                            provider: provider.clone(),
                            checked_at: now,
                            failures: 0,
                            recovery_candidate: None,
                        },
                    );
                    Ok(provider)
                }
                None => Err(anyhow::anyhow!(
                    "no healthy exit provider; traffic is failed closed"
                )),
            },
            Some(current) => {
                current.checked_at = now;
                if !exit.providers.contains(&current.provider) {
                    changed = true;
                    current.failures = 0;
                    current.recovery_candidate = None;
                    match selected {
                        Some(provider) => {
                            current.provider = provider.clone();
                            Ok(provider)
                        }
                        None => Err(anyhow::anyhow!(
                            "configured exit providers are unavailable; traffic is failed closed"
                        )),
                    }
                } else {
                    let current_healthy = observations.iter().any(|observation| {
                        observation.device == current.provider
                            && observation.availability == Availability::Awake
                            && observation.path.is_some()
                            && (matches!(exit.dns, DnsPolicy::CpuDevice) || observation.dns_healthy)
                    });
                    if !current_healthy {
                        current.failures = current.failures.saturating_add(1);
                        current.recovery_candidate = None;
                        if current.failures < 3 {
                            Ok(current.provider.clone())
                        } else if let Some(provider) = selected {
                            changed = provider != current.provider;
                            current.provider = provider.clone();
                            current.failures = 0;
                            Ok(provider)
                        } else {
                            changed = true;
                            Err(anyhow::anyhow!(
                            "no healthy exit provider after three probes; traffic is failed closed"
                        ))
                        }
                    } else if let Some(provider) = selected {
                        current.failures = 0;
                        if provider == current.provider {
                            current.recovery_candidate = None;
                            Ok(current.provider.clone())
                        } else {
                            let ready = match &current.recovery_candidate {
                                Some((candidate, since)) if candidate == &provider => {
                                    since.elapsed() >= Duration::from_secs(30)
                                }
                                _ => {
                                    current.recovery_candidate = Some((provider.clone(), now));
                                    false
                                }
                            };
                            if ready {
                                changed = true;
                                current.provider = provider.clone();
                                current.recovery_candidate = None;
                                Ok(provider)
                            } else {
                                Ok(current.provider.clone())
                            }
                        }
                    } else {
                        Ok(current.provider.clone())
                    }
                }
            }
        }
    };
    if changed {
        bump_generation(instance_id);
    }
    result
}

fn bump_generation(instance_id: &str) {
    let Some(planes) = PLANES.get() else { return };
    if let Some(plane) = planes
        .lock()
        .expect("network-plane table poisoned")
        .values()
        .find(|plane| plane.instance_id == instance_id)
    {
        plane
            .generation
            .send_modify(|generation| *generation = generation.saturating_add(1));
    }
}

async fn observations(
    exit: &ExitPoint,
    cpu_device: &str,
    instance_id: &str,
) -> Vec<ProviderObservation> {
    let mesh = MESH.get().and_then(Option::as_ref);
    let mut observations = Vec::with_capacity(exit.providers.len());
    for provider in &exit.providers {
        let resolver = match &exit.dns {
            DnsPolicy::Custom(servers) => servers.first().copied(),
            _ => None,
        };
        if provider == cpu_device {
            observations.push(ProviderObservation {
                device: provider.clone(),
                availability: Availability::Awake,
                path: Some(PathKind::Local),
                dns_healthy: matches!(exit.dns, DnsPolicy::CpuDevice)
                    || dns_healthy(resolver).await,
            });
            continue;
        }
        let measured = match mesh {
            Some(mesh) => mesh.measure_link(provider).await,
            None => None,
        };
        observations.push(match measured {
            Some(measured) => ProviderObservation {
                device: provider.clone(),
                availability: Availability::Awake,
                path: measured.path.map(|path| match path {
                    MeshPathKind::Direct => PathKind::Direct,
                    MeshPathKind::Relay => PathKind::Relay,
                }),
                dns_healthy: if matches!(exit.dns, DnsPolicy::CpuDevice) {
                    true
                } else {
                    match (mesh, exit.grants.get(provider)) {
                        (Some(mesh), Some(grant)) => mesh
                            .probe_exit_dns(provider, instance_id, grant)
                            .await
                            .unwrap_or(false),
                        _ => false,
                    }
                },
            },
            None => ProviderObservation {
                device: provider.clone(),
                availability: Availability::Unreachable,
                path: None,
                dns_healthy: false,
            },
        });
    }
    observations
}

/// Probe the resolver the provider would actually use. A successful socket
/// bind is not health; this sends a bounded DNS question and requires a reply.
pub(crate) async fn dns_healthy(resolver: Option<IpAddr>) -> bool {
    let target = match resolver {
        Some(address) => SocketAddr::new(address, 53),
        None => match resolve_dns_target(SocketAddr::new(GUEST_DNS, 53), true) {
            Ok(target) => target,
            Err(_) => return false,
        },
    };
    let bind = if target.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let Ok(socket) = tokio::net::UdpSocket::bind(bind).await else {
        return false;
    };
    if socket.connect(target).await.is_err() {
        return false;
    }
    // Standard query for the root NS set: tiny, cacheable, and independent
    // of any application hostname.
    let query = [
        0x41, 0x53, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
        0x00, 0x01,
    ];
    if socket.send(&query).await.is_err() {
        return false;
    }
    let mut reply = [0_u8; 512];
    tokio::time::timeout(Duration::from_secs(1), socket.recv(&mut reply))
        .await
        .is_ok_and(|result| result.is_ok_and(|count| valid_dns_health_reply(&reply[..count])))
}

fn valid_dns_health_reply(reply: &[u8]) -> bool {
    reply.len() >= 12 && reply[0..2] == [0x41, 0x53] && reply[2] & 0x80 != 0 && reply[3] & 0x0f == 0
}

pub(crate) fn resolve_dns_target(remote: SocketAddr, system_dns: bool) -> Result<SocketAddr> {
    if !system_dns {
        return Ok(remote);
    }
    if remote.ip() != GUEST_DNS || remote.port() != 53 {
        anyhow::bail!("system DNS resolution requires the virtual DNS endpoint on port 53");
    }
    let resolv =
        std::fs::read_to_string("/etc/resolv.conf").context("reading system DNS policy")?;
    let address = resolv
        .lines()
        .filter_map(|line| {
            line.split_whitespace()
                .collect::<Vec<_>>()
                .get(0..2)
                .map(|v| (v[0], v[1]))
        })
        .find_map(|(kind, value)| {
            (kind == "nameserver")
                .then(|| value.parse::<IpAddr>().ok())
                .flatten()
        })
        .context("system DNS policy has no IP resolver")?;
    Ok(SocketAddr::new(address, remote.port()))
}

enum EthernetPayload<'a> {
    Ip(&'a [u8]),
    ArpRequest {
        sender_mac: [u8; 6],
        sender_ip: Ipv4Addr,
        target_ip: Ipv4Addr,
    },
    Ignore,
}

fn ethernet_payload(frame: &[u8]) -> Result<EthernetPayload<'_>> {
    if frame.len() < 14 {
        anyhow::bail!("short Ethernet frame")
    }
    match u16::from_be_bytes([frame[12], frame[13]]) {
        0x0800 | 0x86dd => Ok(EthernetPayload::Ip(&frame[14..])),
        0x0806 if frame.len() >= 42 && frame[20..22] == [0, 1] => {
            let sender_mac = frame[22..28].try_into().expect("six-byte MAC slice");
            let sender_ip = Ipv4Addr::new(frame[28], frame[29], frame[30], frame[31]);
            let target_ip = Ipv4Addr::new(frame[38], frame[39], frame[40], frame[41]);
            if IpAddr::V4(target_ip) == GUEST_GATEWAY || IpAddr::V4(target_ip) == GUEST_DNS {
                Ok(EthernetPayload::ArpRequest {
                    sender_mac,
                    sender_ip,
                    target_ip,
                })
            } else {
                Ok(EthernetPayload::Ignore)
            }
        }
        _ => Ok(EthernetPayload::Ignore),
    }
}

fn ethernet_ip_frame(guest_mac: [u8; 6], packet: &[u8]) -> Result<Vec<u8>> {
    let ethertype = match packet.first().map(|byte| byte >> 4) {
        Some(4) => [0x08, 0x00],
        Some(6) => [0x86, 0xdd],
        _ => anyhow::bail!("userspace stack emitted a non-IP packet"),
    };
    let mut frame = Vec::with_capacity(14 + packet.len());
    frame.extend_from_slice(&guest_mac);
    frame.extend_from_slice(&asterism_core::network::EDGE_GATEWAY_MAC);
    frame.extend_from_slice(&ethertype);
    frame.extend_from_slice(packet);
    Ok(frame)
}

fn arp_reply(guest_mac: [u8; 6], guest_ip: Ipv4Addr, target_ip: Ipv4Addr) -> Vec<u8> {
    let gateway_mac = asterism_core::network::EDGE_GATEWAY_MAC;
    let mut frame = Vec::with_capacity(42);
    frame.extend_from_slice(&guest_mac);
    frame.extend_from_slice(&gateway_mac);
    frame.extend_from_slice(&[0x08, 0x06, 0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x02]);
    frame.extend_from_slice(&gateway_mac);
    frame.extend_from_slice(&target_ip.octets());
    frame.extend_from_slice(&guest_mac);
    frame.extend_from_slice(&guest_ip.octets());
    frame
}

async fn read_qemu_frame(reader: &mut (impl AsyncRead + Unpin)) -> Result<Vec<u8>> {
    let len = reader.read_u32().await? as usize;
    if !(14..=MAX_FRAME).contains(&len) {
        anyhow::bail!("invalid QEMU packet frame length {len}")
    }
    let mut frame = vec![0; len];
    reader.read_exact(&mut frame).await?;
    Ok(frame)
}

async fn write_qemu_frame(writer: &mut (impl AsyncWrite + Unpin), frame: &[u8]) -> io::Result<()> {
    writer.write_u32(frame.len() as u32).await?;
    writer.write_all(frame).await
}

/// Add one fresh selection/health observation to a status-only clone.
pub(crate) async fn annotate_runtime(inst: &mut Instance) {
    let Some(policy) = inst.exit_point.as_ref().cloned() else {
        return;
    };
    let mesh = MESH.get().and_then(Option::as_ref);
    let mut rtts: HashMap<String, u64> = HashMap::new();
    let mut observations = Vec::with_capacity(policy.providers.len());
    let resolver = match &policy.dns {
        DnsPolicy::Custom(servers) => servers.first().copied(),
        _ => None,
    };

    for provider in &policy.providers {
        if provider == &inst.cpu_device {
            observations.push(ProviderObservation {
                device: provider.clone(),
                availability: Availability::Awake,
                path: Some(PathKind::Local),
                dns_healthy: matches!(policy.dns, DnsPolicy::CpuDevice)
                    || dns_healthy(resolver).await,
            });
            continue;
        }
        let measured = match mesh {
            Some(mesh) => mesh.measure_link(provider).await,
            None => None,
        };
        if let Some(measured) = measured {
            if let Some(rtt) = measured.rtt_micros {
                rtts.insert(provider.clone(), rtt);
            }
            observations.push(ProviderObservation {
                device: provider.clone(),
                availability: Availability::Awake,
                path: measured.path.map(|path| match path {
                    MeshPathKind::Direct => PathKind::Direct,
                    MeshPathKind::Relay => PathKind::Relay,
                }),
                dns_healthy: if matches!(policy.dns, DnsPolicy::CpuDevice) {
                    true
                } else {
                    match (mesh, policy.grants.get(provider)) {
                        (Some(mesh), Some(grant)) => mesh
                            .probe_exit_dns(provider, &inst.id, grant)
                            .await
                            .unwrap_or(false),
                        _ => false,
                    }
                },
            });
        } else {
            observations.push(ProviderObservation {
                device: provider.clone(),
                availability: Availability::Unreachable,
                path: None,
                dns_healthy: false,
            });
        }
    }

    let runtime = match policy.select(&inst.cpu_device, &observations) {
        Ok(selected) => PartRuntime {
            state: match selected.health {
                ExitHealth::Healthy => "healthy",
                ExitHealth::Degraded => "degraded",
                ExitHealth::Failover => "recovering",
            }
            .into(),
            path: Some(
                match selected.path {
                    PathKind::Local => "local",
                    PathKind::Direct => "direct",
                    PathKind::Relay => "relay",
                }
                .into(),
            ),
            rtt_micros: rtts.get(selected.provider).copied(),
            throughput_bytes_per_sec: None,
            transferred_bytes: None,
            recovery_millis: None,
            transition_reason: if selected.health == ExitHealth::Failover {
                "provider_failover"
            } else {
                "status_probe"
            }
            .into(),
            recovery_result: if selected.health == ExitHealth::Failover {
                "reconnected"
            } else {
                "connected"
            }
            .into(),
            detail: Some(format!("selected exit {}", selected.provider)),
            observed_at: now_unix(),
        },
        Err(unavailable) => PartRuntime {
            state: "failed_closed".into(),
            path: None,
            rtt_micros: None,
            throughput_bytes_per_sec: None,
            transferred_bytes: None,
            recovery_millis: None,
            transition_reason: "provider_unavailable_failed_closed".into(),
            recovery_result: "failed".into(),
            detail: Some(unavailable.to_string()),
            observed_at: now_unix(),
        },
    };
    if let Some(exit) = inst.exit_point.as_mut() {
        exit.runtime = Some(runtime);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use asterism_core::hv::{ControlChannel, GuestEndpoint, Handle, Machine};
    use asterism_core::instance::Shape;
    use asterism_core::network::{DnsPolicy, ExitPoint, RoutePolicy};
    use asterism_core::proc::ProcId;

    #[test]
    fn packet_edge_proof_is_bound_to_each_persisted_guest_handle() {
        let mut instance = Instance::new(
            "dev",
            "laptop",
            "debian:13",
            Shape::default(),
            Machine {
                backend: "qemu".into(),
                machine_type: "virt".into(),
                cpu: "host".into(),
                hv_version: "test".into(),
            },
        );
        let handle = |started_us, generation: Option<&str>| Handle {
            backend: "qemu".into(),
            pid: Some(42),
            proc: Some(ProcId {
                pid: 42,
                started_us,
                exec: None,
            }),
            ctl: ControlChannel::Qmp {
                path: "/tmp/test-qmp".into(),
            },
            endpoint: GuestEndpoint::HostForward { ssh_port: 22 },
            packet_edge_generation: generation.map(str::to_owned),
            started_at: 1,
        };

        instance.handle = Some(handle(1, Some(EDGE_GENERATION)));
        assert!(restart_compatible(&instance));
        // A rolled-back writer launches a different process and omits the
        // new field. A stale proof elsewhere cannot bless this new handle.
        instance.handle = Some(handle(2, None));
        assert!(!restart_compatible(&instance));
    }

    #[tokio::test]
    async fn a_local_exit_is_observed_without_a_mesh_or_a_persisted_sample() {
        let mut instance = Instance::new(
            "dev",
            "laptop",
            "debian:13",
            Shape::default(),
            Machine {
                backend: "qemu".into(),
                machine_type: "virt".into(),
                cpu: "host".into(),
                hv_version: "test".into(),
            },
        );
        instance.exit_point = Some(
            ExitPoint::new(
                "laptop".into(),
                vec![],
                RoutePolicy::default(),
                DnsPolicy::ExitPoint,
            )
            .unwrap(),
        );

        annotate_runtime(&mut instance).await;
        let runtime = instance.exit_point.unwrap().runtime.unwrap();
        assert_eq!(runtime.state, "healthy");
        assert_eq!(runtime.path.as_deref(), Some("local"));
        assert_eq!(runtime.recovery_result, "connected");
    }

    #[test]
    fn the_packet_filter_cannot_leak_excluded_or_orbit_control_routes() {
        let policy = ExitPoint::new(
            "laptop".into(),
            vec![],
            RoutePolicy {
                include: vec!["0.0.0.0/0".parse().unwrap()],
                exclude: vec!["10.0.0.0/8".parse().unwrap()],
            },
            DnsPolicy::ExitPoint,
        )
        .unwrap();
        let policy = RwLock::new(Some(policy));
        assert!(permits(&policy, "1.1.1.1".parse().unwrap()));
        assert!(!permits(&policy, "10.1.2.3".parse().unwrap()));
        assert!(!permits(&policy, "100.64.0.8".parse().unwrap()));
        assert!(permits(&policy, GUEST_DNS));
    }

    #[tokio::test]
    async fn dns_policy_changes_the_resolver_not_the_stable_guest_address() {
        let policy = ExitPoint::new(
            "laptop".into(),
            vec![],
            RoutePolicy::default(),
            DnsPolicy::Custom(vec!["1.1.1.1".parse().unwrap()]),
        )
        .unwrap();
        let guest_dns = SocketAddr::new(GUEST_DNS, 53);
        let (provider, target, system_dns, grant) =
            select_flow(&Some(policy), "laptop", "instance-id", guest_dns)
                .await
                .unwrap();
        assert_eq!(provider, "laptop");
        assert_eq!(target, "1.1.1.1:53".parse().unwrap());
        assert!(!system_dns);
        assert!(grant.is_none());
    }

    #[tokio::test]
    async fn detach_returns_flows_to_cpu_behind_the_same_virtual_dns() {
        let guest_dns = SocketAddr::new(GUEST_DNS, 53);
        let (provider, target, system_dns, grant) =
            select_flow(&None, "laptop", "instance-id", guest_dns)
                .await
                .unwrap();
        assert_eq!(provider, "laptop");
        assert_eq!(target, guest_dns);
        assert!(system_dns);
        assert!(grant.is_none());
    }

    #[tokio::test]
    async fn virtual_dns_refuses_non_dns_ports_before_any_resolution() {
        let address = SocketAddr::new(GUEST_DNS, 80);
        assert!(select_flow(&None, "laptop", "instance-id", address)
            .await
            .is_err());
        let policy = ExitPoint::new(
            "laptop".into(),
            vec![],
            RoutePolicy::default(),
            DnsPolicy::Custom(vec!["10.0.0.53".parse().unwrap()]),
        )
        .unwrap();
        assert!(select_flow(&Some(policy), "laptop", "instance-id", address)
            .await
            .is_err());
    }

    #[test]
    fn dns_health_requires_a_matching_success_response_not_echo_or_junk() {
        assert!(!valid_dns_health_reply(&[]));
        assert!(!valid_dns_health_reply(&[
            0x41, 0x53, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0,
        ]));
        assert!(!valid_dns_health_reply(&[
            0x99, 0x99, 0x81, 0x00, 0, 1, 0, 0, 0, 0, 0, 0,
        ]));
        assert!(valid_dns_health_reply(&[
            0x41, 0x53, 0x81, 0x00, 0, 1, 0, 0, 0, 0, 0, 0,
        ]));
    }

    #[test]
    fn transition_saga_tracks_new_pending_and_old_active_generations() {
        let old_grant = ExitGrant {
            provider_device_id: "old-id".into(),
            generation: 1,
        };
        let new_grant = ExitGrant {
            provider_device_id: "new-id".into(),
            generation: 2,
        };
        let old = BTreeMap::from([("old".into(), old_grant.clone())]);
        let mut next = ExitPoint::new(
            "new".into(),
            Vec::new(),
            RoutePolicy::default(),
            DnsPolicy::ExitPoint,
        )
        .unwrap();
        next.grants.insert("new".into(), new_grant.clone());
        let scopes = BTreeSet::from(["new".to_owned()]);
        let transition = plan_transition(&old, Some(&next), &scopes).unwrap();
        assert_eq!(transition.pending.get("new"), Some(&new_grant));
        assert_eq!(transition.revoke.get("old"), Some(&old_grant));
        assert!(transition.pending_scopes.contains("new"));

        // Before the shard commit, recovery sees the old map and revokes
        // `pending`; after it, recovery sees expected_grants and revokes
        // `revoke`. Both maps survive serialization across the crash.
        let encoded = serde_json::to_vec(&transition).unwrap();
        let decoded: ExitTransition = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(decoded.pending, transition.pending);
        assert_eq!(decoded.revoke, transition.revoke);
        assert_eq!(decoded.expected_grants, next.grants);
    }
}
