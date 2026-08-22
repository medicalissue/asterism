//! Live health for the network exit-point part.
//!
//! Durable policy lives in `asterism_core::network`; this module contributes
//! only current mesh observations to `ast status`. The registry is never
//! mutated with them, matching the remote-volume health seam.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::time::Duration;

use anyhow::{Context, Result};
use asterism_core::hv::GuestNetwork;
use asterism_core::instance::{now_unix, Instance, PartRuntime};
use asterism_core::network::{
    guest_macs, Availability, DnsPolicy, ExitHealth, ExitPoint, PathKind, ProviderObservation,
    GUEST_DNS, GUEST_GATEWAY,
};
use asterism_mesh::PathKind as MeshPathKind;
use futures::{SinkExt, StreamExt};
use netstack_smoltcp::StackBuilder;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::mesh::Mesh;

static MESH: OnceLock<Option<Arc<Mesh>>> = OnceLock::new();
static PLANES: OnceLock<Mutex<HashMap<String, Plane>>> = OnceLock::new();

const MAX_FRAME: usize = 65_535;
const EDGE_MTU: usize = 1500;
const FLOW_TIMEOUT: Duration = Duration::from_secs(30);

struct Plane {
    endpoint: SocketAddr,
    policy: Arc<RwLock<Option<ExitPoint>>>,
    task: tokio::task::JoinHandle<()>,
}

pub(crate) fn init(mesh: Option<Arc<Mesh>>) {
    let _ = MESH.set(mesh);
}

/// Raise the stable guest edge before the hypervisor starts.
///
/// The listener is loopback-only and the backend receives only its endpoint
/// plus stable NIC identities. Policy is held separately so attach, failover,
/// and detach can change the provider without changing anything in the guest.
pub(crate) fn bring_up(inst: &Instance) -> Result<GuestNetwork> {
    let planes = PLANES.get_or_init(|| Mutex::new(HashMap::new()));
    let mut planes = planes.lock().expect("network-plane table poisoned");
    if let Some(plane) = planes.get(&inst.name) {
        *plane.policy.write().expect("network policy poisoned") = inst.exit_point.clone();
        let (primary_mac, edge_mac) = guest_macs(&inst.id);
        return Ok(GuestNetwork {
            endpoint: plane.endpoint,
            primary_mac,
            edge_mac,
        });
    }

    let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .context("binding the guest packet edge")?;
    listener.set_nonblocking(true)?;
    let endpoint = listener.local_addr()?;
    let listener = tokio::net::TcpListener::from_std(listener)?;
    let policy = Arc::new(RwLock::new(inst.exit_point.clone()));
    let task = tokio::spawn(accept_guest_edges(
        listener,
        inst.name.clone(),
        inst.cpu_device.clone(),
        policy.clone(),
        guest_macs(&inst.id).1,
    ));
    planes.insert(
        inst.name.clone(),
        Plane {
            endpoint,
            policy,
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
    }
}

async fn accept_guest_edges(
    listener: tokio::net::TcpListener,
    name: String,
    cpu_device: String,
    policy: Arc<RwLock<Option<ExitPoint>>>,
    guest_mac: [u8; 6],
) {
    loop {
        let Ok((stream, peer)) = listener.accept().await else {
            return;
        };
        if !peer.ip().is_loopback() {
            continue;
        }
        let name = name.clone();
        let cpu_device = cpu_device.clone();
        let policy = policy.clone();
        tokio::spawn(async move {
            if let Err(error) = run_guest_edge(stream, &cpu_device, policy, guest_mac).await {
                eprintln!("astd: packet edge for {name:?} stopped: {error:#}");
            }
        });
    }
}

async fn run_guest_edge(
    stream: tokio::net::TcpStream,
    cpu_device: &str,
    policy: Arc<RwLock<Option<ExitPoint>>>,
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
    let mut tcp_task = tokio::spawn(forward_tcp(tcp, cpu_device.to_owned(), policy.clone()));
    let mut udp_task = tokio::spawn(forward_udp(udp, cpu_device.to_owned(), policy));

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
        .is_none_or(|exit| exit.routes.permits(destination, false))
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
    policy: Arc<RwLock<Option<ExitPoint>>>,
) {
    while let Some((stream, _local, remote)) = listener.next().await {
        let cpu_device = cpu_device.clone();
        let policy = policy.clone();
        tokio::spawn(async move {
            if let Err(error) = forward_one_tcp(stream, &cpu_device, policy, remote).await {
                eprintln!("astd: exit TCP flow to {remote} failed: {error:#}");
            }
        });
    }
}

async fn forward_one_tcp(
    mut guest: netstack_smoltcp::TcpStream,
    cpu_device: &str,
    policy: Arc<RwLock<Option<ExitPoint>>>,
    remote: SocketAddr,
) -> Result<()> {
    let snapshot = policy.read().expect("network policy poisoned").clone();
    let (provider, remote, system_dns) = select_flow(&snapshot, cpu_device, remote).await?;
    if provider == cpu_device {
        let remote = resolve_dns_target(remote, system_dns)?;
        let mut upstream =
            tokio::time::timeout(FLOW_TIMEOUT, tokio::net::TcpStream::connect(remote))
                .await
                .context("exit TCP connect timed out")??;
        tokio::io::copy_bidirectional(&mut guest, &mut upstream).await?;
    } else {
        let mesh = MESH
            .get()
            .and_then(Option::as_ref)
            .context("the selected remote exit has no mesh transport")?;
        let stream = mesh.open_exit_tcp(&provider, remote, system_dns).await?;
        crate::mesh::pump(guest, stream).await?;
    }
    Ok(())
}

async fn forward_udp(
    socket: netstack_smoltcp::UdpSocket,
    cpu_device: String,
    policy: Arc<RwLock<Option<ExitPoint>>>,
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
        let reply_tx = reply_tx.clone();
        tokio::spawn(async move {
            match forward_one_udp(&cpu_device, policy, remote, payload).await {
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
    policy: Arc<RwLock<Option<ExitPoint>>>,
    remote: SocketAddr,
    payload: Vec<u8>,
) -> Result<Vec<u8>> {
    let snapshot = policy.read().expect("network policy poisoned").clone();
    let (provider, remote, system_dns) = select_flow(&snapshot, cpu_device, remote).await?;
    if provider != cpu_device {
        let mesh = MESH
            .get()
            .and_then(Option::as_ref)
            .context("the selected remote exit has no mesh transport")?;
        return mesh
            .send_exit_udp(&provider, remote, system_dns, payload)
            .await;
    }
    let remote = resolve_dns_target(remote, system_dns)?;
    let bind = if remote.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let socket = tokio::net::UdpSocket::bind(bind).await?;
    socket.connect(remote).await?;
    socket.send(&payload).await?;
    let mut reply = vec![0; 65_507];
    let count = tokio::time::timeout(FLOW_TIMEOUT, socket.recv(&mut reply))
        .await
        .context("exit UDP reply timed out")??;
    reply.truncate(count);
    Ok(reply)
}

async fn select_flow(
    policy: &Option<ExitPoint>,
    cpu_device: &str,
    remote: SocketAddr,
) -> Result<(String, SocketAddr, bool)> {
    let Some(exit) = policy else {
        return Ok((cpu_device.to_owned(), remote, remote.ip() == GUEST_DNS));
    };
    let dns_flow = remote.ip() == GUEST_DNS;
    if dns_flow && exit.dns == DnsPolicy::CpuDevice {
        return Ok((cpu_device.to_owned(), remote, true));
    }
    let observations = observations(exit, cpu_device).await;
    let provider = exit.select(cpu_device, &observations)?.provider.to_owned();
    let (remote, system_dns) = match (&exit.dns, dns_flow) {
        (DnsPolicy::Custom(servers), true) => {
            let server = servers.first().context("custom DNS has no resolver")?;
            (SocketAddr::new(*server, remote.port()), false)
        }
        (DnsPolicy::ExitPoint, true) => (remote, true),
        _ => (remote, false),
    };
    Ok((provider, remote, system_dns))
}

async fn observations(exit: &ExitPoint, cpu_device: &str) -> Vec<ProviderObservation> {
    let mesh = MESH.get().and_then(Option::as_ref);
    let mut observations = Vec::with_capacity(exit.providers.len());
    for provider in &exit.providers {
        if provider == cpu_device {
            observations.push(ProviderObservation {
                device: provider.clone(),
                availability: Availability::Awake,
                path: Some(PathKind::Local),
                dns_healthy: true,
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
                dns_healthy: true,
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

pub(crate) fn resolve_dns_target(remote: SocketAddr, system_dns: bool) -> Result<SocketAddr> {
    if !system_dns {
        return Ok(remote);
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

async fn read_qemu_frame(reader: &mut tokio::net::tcp::OwnedReadHalf) -> Result<Vec<u8>> {
    let len = reader.read_u32().await? as usize;
    if !(14..=MAX_FRAME).contains(&len) {
        anyhow::bail!("invalid QEMU packet frame length {len}")
    }
    let mut frame = vec![0; len];
    reader.read_exact(&mut frame).await?;
    Ok(frame)
}

async fn write_qemu_frame(
    writer: &mut tokio::net::tcp::OwnedWriteHalf,
    frame: &[u8],
) -> io::Result<()> {
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

    for provider in &policy.providers {
        if provider == &inst.cpu_device {
            observations.push(ProviderObservation {
                device: provider.clone(),
                availability: Availability::Awake,
                path: Some(PathKind::Local),
                // The CPU-device/exit resolver is reached locally. Custom
                // resolver reachability belongs to the packet plane; the
                // policy selector can consume that probe when it exists.
                dns_healthy: true,
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
                dns_healthy: true,
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
            state: "degraded".into(),
            path: None,
            rtt_micros: None,
            throughput_bytes_per_sec: None,
            transferred_bytes: None,
            recovery_millis: None,
            transition_reason: "provider_unavailable".into(),
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
    use asterism_core::hv::Machine;
    use asterism_core::instance::Shape;
    use asterism_core::network::{DnsPolicy, ExitPoint, RoutePolicy};

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
        let (provider, target, system_dns) = select_flow(&Some(policy), "laptop", guest_dns)
            .await
            .unwrap();
        assert_eq!(provider, "laptop");
        assert_eq!(target, "1.1.1.1:53".parse().unwrap());
        assert!(!system_dns);
    }

    #[tokio::test]
    async fn detach_returns_flows_to_cpu_behind_the_same_virtual_dns() {
        let guest_dns = SocketAddr::new(GUEST_DNS, 53);
        let (provider, target, system_dns) = select_flow(&None, "laptop", guest_dns).await.unwrap();
        assert_eq!(provider, "laptop");
        assert_eq!(target, guest_dns);
        assert!(system_dns);
    }
}
