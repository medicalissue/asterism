//! Wake-on-LAN: the packet, the network facts behind it, and an honest
//! account of whether either will work.
//!
//! A magic packet is an L2 broadcast. It cannot be routed, relayed, or
//! tunnelled to the machine it is for — it has to be put on the wire *inside*
//! that machine's broadcast domain by something already standing there. That
//! single fact is why waking is an orbit operation and not a local one, and
//! it is why this module is mostly about *networks* rather than about
//! packets: the packet is 102 bytes of memcpy, and everything difficult is
//! deciding who is close enough to send it.
//!
//! Three jobs:
//!
//! * **Facts.** [`facts`] answers "where is this device on the wire" — the
//!   MAC a packet would have to name, and a [`lan_fingerprint`] of the
//!   broadcast domain it sits in. Peers store each other's, because the
//!   moment they are needed is the moment the device cannot be asked.
//! * **Send.** [`broadcast`] builds the frame and puts it on 255.255.255.255
//!   and on the subnet's own broadcast address, both on UDP 9.
//! * **Check.** [`check`] reports what this platform can actually promise,
//!   including — loudly — the parts it cannot verify at all.
//!
//! # Test hooks
//!
//! Three environment variables, and they exist because the honest test of a
//! wake is otherwise "put a real machine to sleep", which no CI can do:
//!
//! * `ASTERISM_LAN_ID` — pretend this device is on that broadcast domain. Two
//!   daemons on one host share a LAN in reality; this is how a test makes
//!   them *disagree* about it, which is the case the routing logic is for.
//! * `ASTERISM_WAKE_MAC` — pretend this device's NIC has that address, so a
//!   captured packet has a known MAC to be checked against.
//! * `ASTERISM_WAKE_PORT` — send to a port other than 9. UDP 9 is privileged,
//!   so a test listener cannot bind it; the packet bytes are identical either
//!   way, and the bytes are what is being proved.
//!
//! None of them change what is sent, only where and about whom, and all three
//! are read at the moment of use so nothing has to be restarted to set them.

use std::net::{Ipv4Addr, UdpSocket};
use std::time::Duration;

use anyhow::{bail, Context, Result};

use asterism_core::instance::now_unix;
use asterism_core::orbit::{format_mac, lan_fingerprint, parse_mac, WakeFacts};
use asterism_core::protocol::{CheckRow, Verdict};

/// The port a magic packet is conventionally sent to. Nothing listens on it:
/// the NIC's firmware matches the frame's payload, not its port, so 7 and 9
/// are equally correct and 9 is the one everybody uses.
pub const WOL_PORT: u16 = 9;

/// Pretend to be on this broadcast domain. Test hook; see the module docs.
const LAN_ID_ENV: &str = "ASTERISM_LAN_ID";
/// Pretend this device's NIC has this address. Test hook.
const MAC_ENV: &str = "ASTERISM_WAKE_MAC";
/// Send magic packets to this port instead of 9. Test hook.
const PORT_ENV: &str = "ASTERISM_WAKE_PORT";

/// How long to give a shelled-out network tool before deciding this device
/// cannot say where it is. These all answer in milliseconds or never.
const PROBE_TIMEOUT: Duration = Duration::from_secs(3);

// ---- the packet ------------------------------------------------------------

/// The magic packet: six 0xFF bytes, then the target's MAC sixteen times.
///
/// 102 bytes exactly, and the shape has been fixed since AMD wrote it down in
/// 1995 — a sleeping NIC scans every frame it receives for this pattern
/// anywhere in the payload, which is why the packet needs no header, no
/// checksum and no reply.
pub fn magic_packet(mac: [u8; 6]) -> [u8; 102] {
    let mut frame = [0xFFu8; 102];
    for chunk in frame[6..].chunks_mut(6) {
        chunk.copy_from_slice(&mac);
    }
    frame
}

/// Broadcasts a magic packet for `mac` on this device's LAN.
///
/// `expect_lan` is the network the *asker* believed this device was on. It is
/// checked rather than trusted: a device that has since moved must decline,
/// because a broadcast onto the wrong LAN is indistinguishable from a
/// successful one and would turn "we woke it" into a lie.
///
/// Returns the addresses it was sent to, which is what the requester reports
/// to the user. Both are sent because neither is reliably enough on its own:
/// 255.255.255.255 is never forwarded by anything but is what most switches
/// flood, while the subnet-directed address is the one some drivers and
/// virtual interfaces prefer.
pub fn broadcast(mac: &str, expect_lan: Option<&str>) -> Result<Vec<String>> {
    let Some(bytes) = parse_mac(mac) else {
        bail!("{mac:?} is not a MAC address");
    };
    // One look at the wire, answering all three of the questions below: is
    // this still the LAN the asker meant, which address should the packet be
    // sent from, and which broadcast addresses should it be sent to.
    let net = interface();
    if let Some(expected) = expect_lan {
        let mine = facts_from(net.as_ref());
        match mine.lan_id.as_deref() {
            Some(id) if id == expected => {}
            Some(id) => bail!(
                "this device is on {id}, not {expected} — it has moved networks since \
                 you last heard from it, so its broadcast would not reach that LAN"
            ),
            None => {
                bail!("this device cannot tell which network it is on, so it will not broadcast")
            }
        }
    }

    let frame = magic_packet(bytes);
    // Pinned to the LAN interface's own address: the other half of choosing
    // an interface, and the half without which the choosing does nothing.
    let socket = broadcast_socket(net.as_ref().and_then(|n| n.addr))?;

    let port = wol_port();
    let mut sent = Vec::new();
    let mut last: Option<std::io::Error> = None;
    for target in broadcast_targets(net.as_ref()) {
        match socket.send_to(&frame, (target, port)) {
            Ok(_) => sent.push(format!("{target}:{port}")),
            Err(e) => last = Some(e),
        }
    }
    if sent.is_empty() {
        let why = last
            .map(|e| e.to_string())
            .unwrap_or_else(|| "no broadcast address".into());
        bail!("could not broadcast a magic packet: {why}");
    }
    Ok(sent)
}

/// A broadcast socket pinned to the interface the packet has to leave by.
///
/// Choosing the LAN out of the routing table does nothing on its own, because
/// a tunnel does not only take the default route. With an exit node up, the
/// machine this was found on had its own LAN prefix claimed twice:
///
/// ```text
/// 192.168.50         link#25            UCS                 utun4
/// 192.168.50         link#14            UCSI                  en0      !
/// ```
///
/// The tunnel holds the plain route; the wire's copy is *ifscoped*, meaning
/// it applies only to traffic already pinned to en0. An unbound socket is not
/// pinned to anything, so both broadcast addresses resolve to the tunnel —
/// 255.255.255.255 does not even get that far and fails to send at all, which
/// is what `ast device wake` was reporting as "could not broadcast a magic
/// packet". Naming the interface's own address as the source is the pin: with
/// 192.168.50.109 as the source, the en0 routes are the ones that match, and
/// both frames leave by the wire.
///
/// The wildcard is for exactly one case: a device that could not read its own
/// address at all, where an unpinned socket is still right everywhere there
/// is no tunnel to be confused by.
///
/// It is emphatically *not* a fallback for a pin that failed. An address is
/// only ever passed in here because it is the wire the packet has to leave
/// by; quietly binding 0.0.0.0 instead would put the frame back in the tunnel
/// and then report the send as a success, which is the silent failure this
/// module exists to refuse. So a chosen address that cannot be bound is an
/// error, and it names the address, because "the interface went down between
/// the look and the bind" is the thing that actually happened and the thing
/// the user needs to be told.
fn broadcast_socket(source: Option<Ipv4Addr>) -> Result<UdpSocket> {
    let socket = match source {
        Some(source) => UdpSocket::bind((source, 0)).with_context(|| {
            format!(
                "binding a udp socket to {source}, this device's own address on the \
                 LAN the packet has to leave by — it was there a moment ago, so the \
                 interface has most likely just gone down or changed address"
            )
        })?,
        None => UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).context("binding a udp socket")?,
    };
    socket
        .set_broadcast(true)
        .context("asking for broadcast on a udp socket")?;
    Ok(socket)
}

/// Where a magic packet goes: the subnet's own broadcast address when this
/// device knows its subnet, and the limited broadcast address always.
///
/// Both are sent because neither is reliable enough alone — 255.255.255.255
/// is never forwarded by anything but is what most switches flood, while the
/// subnet-directed address is the one some drivers and virtual interfaces
/// prefer. The directed one goes first because it is the one that still has a
/// route of its own when a tunnel has taken the default.
fn broadcast_targets(net: Option<&Interface>) -> Vec<Ipv4Addr> {
    let mut targets = Vec::new();
    if let Some(bcast) = net.and_then(|n| n.broadcast) {
        if bcast != Ipv4Addr::BROADCAST {
            targets.push(bcast);
        }
    }
    targets.push(Ipv4Addr::BROADCAST);
    targets
}

fn wol_port() -> u16 {
    std::env::var(PORT_ENV)
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(WOL_PORT)
}

// ---- this device's place on the wire ---------------------------------------

/// What this device would tell a peer about itself, so the peer can wake it.
///
/// Recomputed on each call rather than cached: a laptop changes networks
/// between one command and the next, and a cached `lan_id` is exactly the
/// stale answer that makes a wake fail silently.
pub fn facts() -> WakeFacts {
    facts_from(interface().as_ref())
}

/// The same, from an interface that has already been looked up.
///
/// Every probe behind [`interface`] shells out, so the two callers that want
/// the facts *and* the interface itself ask once and pass it down rather than
/// running `netstat`, `ifconfig` and `arp` twice over.
fn facts_from(net: Option<&Interface>) -> WakeFacts {
    let mac = std::env::var(MAC_ENV)
        .ok()
        .filter(|m| parse_mac(m).is_some())
        .map(|m| format_mac(parse_mac(&m).expect("just checked")))
        .or_else(|| net.and_then(|n| n.mac.clone()));
    let lan_id = std::env::var(LAN_ID_ENV)
        .ok()
        .filter(|id| !id.trim().is_empty())
        .or_else(|| {
            let net = net?;
            lan_fingerprint(net.gateway_mac.as_deref(), net.subnet().as_deref())
        });

    WakeFacts {
        mac,
        lan_id,
        iface: net.map(|n| n.name.clone()),
        seen_at: now_unix(),
    }
}

/// An interface carrying a default route, and what is known about it.
#[derive(Debug, Default, Clone)]
struct Interface {
    name: String,
    mac: Option<String>,
    addr: Option<Ipv4Addr>,
    netmask: Option<Ipv4Addr>,
    broadcast: Option<Ipv4Addr>,
    gateway: Option<Ipv4Addr>,
    gateway_mac: Option<String>,
    /// Named like a tunnel — see [`is_tunnel_iface`]. Read off the routing
    /// table before anything is probed, because the whole point is not to
    /// treat this interface as a LAN.
    tunnel: bool,
    /// Has one peer rather than a domain full of neighbours: BSD prints
    /// `inet A --> B`, iproute2 prints `inet A peer B/32`.
    point_to_point: bool,
}

impl Interface {
    /// The network in CIDR form — address masked, host bits dropped. This is
    /// the half of a `lan_id` that survives a new DHCP lease.
    fn subnet(&self) -> Option<String> {
        let (addr, mask) = (self.addr?, self.netmask?);
        let network = Ipv4Addr::from(u32::from(addr) & u32::from(mask));
        Some(format!("{network}/{}", u32::from(mask).count_ones()))
    }
}

/// An interface's IPv4 configuration, as its own platform reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Inet {
    addr: Ipv4Addr,
    netmask: Ipv4Addr,
    broadcast: Option<Ipv4Addr>,
    point_to_point: bool,
}

/// The interface a magic packet has to be broadcast on, and the names of the
/// default-route interfaces that were passed over to reach it.
///
/// The default route is *nearly* the right interface: it is the one the
/// orbit's own traffic uses, so it is the one a peer that can reach us is
/// reaching us on. What it is not is a promise of a broadcast domain. A VPN —
/// a Tailscale exit node, WireGuard, an IPsec or OpenVPN client — installs a
/// default route of its own and takes priority, and on a Mac with an exit
/// node up `route -n get default` answers `utun4`: a point-to-point /32 with
/// no broadcast address and no neighbours. Fingerprinting that as the LAN
/// produces a `lan_id` no other device will ever match, and broadcasting onto
/// it puts the packet into a tunnel that drops it. Neither failure says a
/// word — which is the exact failure mode this module exists to refuse.
///
/// A magic packet cannot be tunnelled, so a tunnel is never the answer. The
/// LAN is whichever physical default route is still sitting underneath it —
/// on the machine this was found on, `192.168.50.1 on en0`, present in
/// `netstat -rn` the whole time and still the wire the sleeper is on.
///
/// So: take every default route, drop the ones that cannot carry an L2
/// broadcast — first by interface name, then by what the interface's own
/// address turns out to look like — and keep the best of what is left. When
/// nothing is left, say so. A device whose only way out is a tunnel is on no
/// LAN a peer could broadcast on, and that is a fact `ast device check`
/// should print rather than paper over with a route that looks like one.
fn lan_route() -> (Option<Interface>, Vec<String>) {
    let routes = default_routes();
    let mut skipped: Vec<String> = routes
        .iter()
        .filter(|r| r.tunnel)
        .map(|r| r.name.clone())
        .collect();

    for mut iface in routes.into_iter().filter(|r| !r.tunnel) {
        iface.mac = iface_mac(&iface.name);
        if let Some(inet) = iface_inet(&iface.name) {
            iface.addr = Some(inet.addr);
            iface.netmask = Some(inet.netmask);
            iface.broadcast = inet.broadcast;
            iface.point_to_point = inet.point_to_point;
        }
        if !carries_broadcast(&iface) {
            skipped.push(iface.name);
            continue;
        }
        if let Some(gw) = iface.gateway {
            iface.gateway_mac = neighbour_mac(gw, &iface.name);
        }
        return (Some(iface), skipped);
    }
    (None, skipped)
}

fn interface() -> Option<Interface> {
    lan_route().0
}

/// Whether this interface's own address says it is on a broadcast domain.
///
/// A tunnel this code does not recognise by name still gives itself away
/// here: a point-to-point link has a peer instead of neighbours, and a /31 or
/// /32 has no host range for a broadcast address to be the top of. Both are
/// what a VPN interface looks like from the inside.
///
/// Absence of evidence is not evidence: an interface whose address could not
/// be read at all is kept, because `ifconfig` failing to answer is not a
/// reason to decide a device has no LAN.
fn carries_broadcast(iface: &Interface) -> bool {
    !iface.point_to_point
        && iface
            .netmask
            .is_none_or(|m| u32::from(m).count_ones() <= 30)
}

/// Interface-name prefixes that are never a broadcast LAN, whatever priority
/// the routing table gives them.
///
/// `utun` and `ipsec` are what macOS calls its tunnels — Tailscale, WireGuard
/// and every IKEv2 client show up there; `tun`, `tap`, `wg`, `nordlynx` and
/// `proton` are the Linux spellings of the same idea; `ppp` is point-to-point
/// by name; `zt` and `ham` are overlay networks; `awdl` and `llw` are Apple's
/// peer-to-peer radios, which are not VPNs but are not the LAN either and do
/// carry routes.
///
/// Matched as prefixes on purpose: these are all numbered in the order they
/// came up (`utun4`, `tun0`, `wg0`), and nothing that is a real wire is
/// spelled this way — physical interfaces are `en*`, `eth*`, `enp*`, `wlan*`,
/// `wlp*`, `eno*`, `br*`, `bond*`. The risk of matching is a false positive
/// that nobody has; the risk of not matching is every wake failing silently.
const TUNNEL_PREFIXES: &[&str] = &[
    "utun",
    "tun",
    "tap",
    "ipsec",
    "ppp",
    "wg",
    "gpd",
    "nordlynx",
    "proton",
    "tailscale",
    "zt",
    "ham",
    "awdl",
    "llw",
];

fn is_tunnel_iface(name: &str) -> bool {
    TUNNEL_PREFIXES
        .iter()
        .any(|prefix| name.starts_with(prefix))
}

// ---- platform probes -------------------------------------------------------
//
// Shelled out rather than done through libc, because every one of these is a
// text format that has not changed in twenty years, and the alternative is a
// per-platform FFI surface (getifaddrs, sysctl NET_RT_DUMP, netlink) for
// facts we read a handful of times a day. Everything below returns `Option`
// and nothing panics on a format it does not recognise: a device that cannot
// say where it is says so, and `ast device check` reports that honestly.

/// Every IPv4 default route this Mac has, best LAN candidate first.
///
/// `netstat -rn` rather than `route -n get default`, and that is the fix: the
/// second question means "where would a packet to the internet go", which is
/// the tunnel and is not what is being asked. The first lists *all* of them,
/// which on a machine with an exit node up is the tunnel and the physical
/// wire both, and lets the choice be made here instead of by route priority.
#[cfg(target_os = "macos")]
fn default_routes() -> Vec<Interface> {
    match run("netstat", &["-rn", "-f", "inet"]) {
        Some(listing) => netstat_defaults(&listing),
        // Nothing else lists more than one default route, so without netstat
        // the only answer available is the single one the kernel prefers.
        // It is returned as it is found, tunnel flag and all, and dropped by
        // the caller if that is what it turns out to be — a device that can
        // only see the tunnel is on no LAN, and should say so.
        None => run("route", &["-n", "get", "default"])
            .as_deref()
            .and_then(route_get_default)
            .into_iter()
            .collect(),
    }
}

/// Reads the default routes out of `netstat -rn -f inet`.
///
/// ```text
/// Destination        Gateway            Flags               Netif Expire
/// default            link#25            UCSg                utun4
/// default            192.168.50.1       UGScIg                en0
/// ```
///
/// Two defaults, listed in the kernel's own priority order, and the second is
/// the one a magic packet has to go out of. `link#25` is not a next hop —
/// it is the interface saying "the destination is me" — so it parses as no
/// gateway at all, which is the honest reading and gives a route with one
/// less thing to fingerprint a LAN with.
///
/// The columns are found from the header rather than counted: this listing
/// grew `Refs` and `Use` columns in older macOS and lost them again, and the
/// names have stayed put through all of it.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn netstat_defaults(listing: &str) -> Vec<Interface> {
    let (flags_col, netif_col) = netstat_columns(listing);
    let mut routes: Vec<Interface> = Vec::new();
    for line in listing.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if !matches!(f.first(), Some(&"default") | Some(&"0.0.0.0")) {
            continue;
        }
        // A route that is not up cannot carry anything.
        if f.get(flags_col).is_some_and(|flags| !flags.contains('U')) {
            continue;
        }
        let Some(name) = f
            .get(netif_col)
            .filter(|n| n.starts_with(|c: char| c.is_ascii_alphabetic()))
        else {
            continue;
        };
        routes.push(Interface {
            name: (*name).to_owned(),
            gateway: f.get(1).and_then(|gw| gw.parse().ok()),
            tunnel: is_tunnel_iface(name),
            ..Interface::default()
        });
    }
    // Stable, so the kernel's ordering survives inside each rank: a real
    // gateway first, because its MAC is what makes a strong `lan_id`.
    routes.sort_by_key(|r| (r.tunnel, r.gateway.is_none()));
    routes
}

/// Which token index the `Flags` and `Netif` columns are at, from the header
/// line. Falls back to where they sit in every macOS this has been seen on.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn netstat_columns(listing: &str) -> (usize, usize) {
    for line in listing.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.first() != Some(&"Destination") {
            continue;
        }
        if let (Some(flags), Some(netif)) = (
            f.iter().position(|c| *c == "Flags"),
            f.iter().position(|c| *c == "Netif"),
        ) {
            return (flags, netif);
        }
    }
    (2, 3)
}

/// `route -n get default`, kept only for the case where netstat cannot be
/// run at all. It answers with one route and no way to ask for another.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn route_get_default(out: &str) -> Option<Interface> {
    let mut iface = Interface::default();
    for line in out.lines() {
        match line.split_once(':').map(|(k, v)| (k.trim(), v.trim())) {
            Some(("interface", v)) => iface.name = v.to_owned(),
            Some(("gateway", v)) => iface.gateway = v.parse().ok(),
            _ => {}
        }
    }
    iface.tunnel = is_tunnel_iface(&iface.name);
    (!iface.name.is_empty()).then_some(iface)
}

/// Linux keeps the routing table in a file, so no binary has to exist for
/// this to work.
#[cfg(not(target_os = "macos"))]
fn default_routes() -> Vec<Interface> {
    match std::fs::read_to_string("/proc/net/route") {
        Ok(table) => proc_net_route_defaults(&table),
        Err(_) => Vec::new(),
    }
}

/// Reads the default routes out of `/proc/net/route`.
///
/// ```text
/// Iface  Destination  Gateway   Flags  RefCnt  Use  Metric  Mask      MTU  Window  IRTT
/// tun0   00000000     0108080A  0003   0       0    50      00000000  0    0       0
/// eth0   00000000     0132A8C0  0003   0       0    100     00000000  0    0       0
/// ```
///
/// The same shape as the Mac's, and the same answer: a tunnel can hold the
/// main table's default route — OpenVPN and a plain `ip route add default dev
/// tun0` both do it — so `eth0` is the wire, not `tun0`. Tailscale and
/// WireGuard on Linux usually route by fwmark in a table of their own and
/// never appear here at all, which is why this bug shows on a Mac first; the
/// rule has to hold either way, so it is applied either way.
///
/// A default route is destination *and* mask both zero, and up. Metric is the
/// kernel's own ranking between two of them and is used as ours, under
/// whether there is a gateway to fingerprint. Addresses are little-endian
/// hex; a malformed line is skipped rather than ending the scan, because one
/// unreadable route is not a reason to miss the wire in the row below it.
#[cfg_attr(target_os = "macos", allow(dead_code))]
fn proc_net_route_defaults(table: &str) -> Vec<Interface> {
    const RTF_UP: u32 = 0x1;
    const RTF_GATEWAY: u32 = 0x2;

    let mut ranked: Vec<(bool, bool, u32, Interface)> = Vec::new();
    for line in table.lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 8 || f[1] != "00000000" || f[7] != "00000000" {
            continue;
        }
        let Ok(flags) = u32::from_str_radix(f[3], 16) else {
            continue;
        };
        if flags & RTF_UP == 0 {
            continue;
        }
        let gateway = (flags & RTF_GATEWAY != 0)
            .then(|| {
                u32::from_str_radix(f[2], 16)
                    .ok()
                    .map(|gw| Ipv4Addr::from(gw.to_be()))
            })
            .flatten()
            .filter(|gw| !gw.is_unspecified());
        let iface = Interface {
            name: f[0].to_owned(),
            gateway,
            tunnel: is_tunnel_iface(f[0]),
            ..Interface::default()
        };
        let metric = f[6].parse().unwrap_or(u32::MAX);
        ranked.push((iface.tunnel, iface.gateway.is_none(), metric, iface));
    }
    ranked.sort_by_key(|(tunnel, no_gateway, metric, _)| (*tunnel, *no_gateway, *metric));
    ranked.into_iter().map(|(.., iface)| iface).collect()
}

#[cfg(target_os = "macos")]
fn iface_mac(name: &str) -> Option<String> {
    let out = run("ifconfig", &[name])?;
    let raw = out.lines().find_map(|l| l.trim().strip_prefix("ether "))?;
    Some(format_mac(parse_mac(raw.trim())?))
}

#[cfg(not(target_os = "macos"))]
fn iface_mac(name: &str) -> Option<String> {
    let raw = std::fs::read_to_string(format!("/sys/class/net/{name}/address")).ok()?;
    Some(format_mac(parse_mac(raw.trim())?))
}

/// The interface's IPv4 configuration, from whatever the platform will say.
#[cfg(target_os = "macos")]
fn iface_inet(name: &str) -> Option<Inet> {
    ifconfig_inet(&run("ifconfig", &[name])?)
}

/// Reads an `inet` line out of `ifconfig`:
///
/// ```text
/// inet 192.168.50.109 netmask 0xffffff00 broadcast 192.168.50.255
/// inet 100.121.213.11 --> 100.121.213.11 netmask 0xffffffff
/// ```
///
/// The first is a wire. The second is the Tailscale tunnel on the same
/// machine, and it disqualifies itself twice over: `-->` is the interface
/// saying it has exactly one peer and no domain, and a /32 has no host range
/// for a broadcast address to sit at the top of. Between them they catch a
/// VPN whose interface name this code has never heard of.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn ifconfig_inet(out: &str) -> Option<Inet> {
    for line in out.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.first() != Some(&"inet") || f.len() < 4 {
            continue;
        }
        let addr: Ipv4Addr = f[1].parse().ok()?;
        // BSD prints the mask as 0xffffff00.
        let netmask = f
            .iter()
            .position(|w| *w == "netmask")
            .and_then(|i| f.get(i + 1))
            .and_then(|m| u32::from_str_radix(m.trim_start_matches("0x"), 16).ok())
            .map(Ipv4Addr::from)?;
        let broadcast = f
            .iter()
            .position(|w| *w == "broadcast")
            .and_then(|i| f.get(i + 1))
            .and_then(|b| b.parse().ok());
        return Some(Inet {
            addr,
            netmask,
            broadcast,
            point_to_point: f.get(2) == Some(&"-->"),
        });
    }
    None
}

#[cfg(not(target_os = "macos"))]
fn iface_inet(name: &str) -> Option<Inet> {
    ip_addr_inet(&run("ip", &["-4", "-o", "addr", "show", "dev", name])?)
}

/// Reads an `inet` field out of `ip -4 -o addr show dev NAME`:
///
/// ```text
/// 2: eth0  inet 192.168.1.50/24 brd 192.168.1.255 scope global dynamic eth0
/// 5: tun0  inet 10.8.0.2 peer 10.8.0.1/32 scope global tun0
/// ```
///
/// iproute2 writes the peer form without a prefix on the local address, which
/// is the same thing BSD's `-->` says: one neighbour, no domain.
#[cfg_attr(target_os = "macos", allow(dead_code))]
fn ip_addr_inet(out: &str) -> Option<Inet> {
    let f: Vec<&str> = out.split_whitespace().collect();
    let i = f.iter().position(|w| *w == "inet")?;
    let point_to_point = f.get(i + 2) == Some(&"peer");
    // With a peer, the prefix that follows belongs to the far end; the local
    // address is bare, and is a host address either way.
    let (addr, prefix) = match f.get(i + 1)?.split_once('/') {
        Some((addr, prefix)) => (addr, prefix.parse().ok()?),
        None => (*f.get(i + 1)?, 32u32),
    };
    let addr: Ipv4Addr = addr.parse().ok()?;
    let netmask = Ipv4Addr::from(if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix.min(32))
    });
    let broadcast = f[i..]
        .iter()
        .position(|w| *w == "brd")
        .and_then(|b| f.get(i + b + 1))
        .and_then(|b| b.parse().ok());
    Some(Inet {
        addr,
        netmask,
        broadcast,
        point_to_point,
    })
}

/// The gateway's MAC, from whatever the platform calls its ARP cache.
///
/// It is there because this device is routing through the gateway right now;
/// if it is not, we have no default route either and never got this far.
#[cfg(target_os = "macos")]
fn neighbour_mac(ip: Ipv4Addr, _iface: &str) -> Option<String> {
    // `? (192.168.0.1) at 58:86:94:ac:56:d0 on en1 ifscope [ethernet]`
    let out = run("arp", &["-n", &ip.to_string()])?;
    let raw = out.split(" at ").nth(1)?.split_whitespace().next()?;
    Some(format_mac(parse_mac(raw)?))
}

#[cfg(not(target_os = "macos"))]
fn neighbour_mac(ip: Ipv4Addr, iface: &str) -> Option<String> {
    let table = std::fs::read_to_string("/proc/net/arp").ok()?;
    let wanted = ip.to_string();
    for line in table.lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() >= 6 && f[0] == wanted && f[5] == iface {
            return Some(format_mac(parse_mac(f[3])?));
        }
    }
    None
}

/// Runs a probe and hands back its stdout, or nothing at all.
///
/// A missing binary, a non-zero exit and a hang are the same answer here —
/// "this device cannot tell you" — and every caller is written to accept it.
fn run(program: &str, args: &[&str]) -> Option<String> {
    use std::io::Read;

    let mut child = std::process::Command::new(program)
        .args(args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .ok()?;

    // Drained on a thread rather than after the wait. `netstat -rn` on a host
    // with a large tailnet prints more than a pipe buffer holds, and a child
    // blocked writing while we block waiting is a deadlock that the timeout
    // below would report as "this device cannot tell you".
    let mut pipe = child.stdout.take()?;
    let reader = std::thread::spawn(move || {
        let mut out = Vec::new();
        let _ = pipe.read_to_end(&mut out);
        out
    });

    let deadline = std::time::Instant::now() + PROBE_TIMEOUT;
    let status = loop {
        match child.try_wait().ok()? {
            Some(status) => break status,
            None if std::time::Instant::now() > deadline => {
                let _ = child.kill();
                return None;
            }
            None => std::thread::sleep(Duration::from_millis(20)),
        }
    };
    let out = reader.join().ok()?;
    status
        .success()
        .then(|| String::from_utf8_lossy(&out).into_owned())
}

// ---- ast device check ------------------------------------------------------

/// This device's wake readiness, as a table.
///
/// The design rule is that a row only says `ok` about something this machine
/// just observed. Everything else that decides whether a wake works — the
/// switch, the AP, whether the NIC keeps power after a shutdown — gets a row
/// too, marked `?`, because a user who is about to rely on wake deserves the
/// list of things nobody checked rather than a green tick that covered them
/// by implication.
pub fn check() -> Vec<CheckRow> {
    let (net, tunnels) = lan_route();
    let mut rows = platform_rows(net.as_ref());

    let facts = facts_from(net.as_ref());
    rows.push(
        match (&facts.mac, net.as_ref().and_then(|n| n.mac.as_ref())) {
            (Some(mac), _) if is_locally_administered(mac) => row(
                "mac address",
                Verdict::Warn,
                format!(
                    "{mac} is a private (locally administered) address — the platform \
                 made it up per network, so a peer that recorded it on one LAN will \
                 not match it on another"
                ),
            ),
            (Some(mac), _) => row("mac address", Verdict::Ok, mac.clone()),
            (None, _) => row(
                "mac address",
                Verdict::Unknown,
                "no address found for the default-route interface — nothing can be \
             addressed to this device"
                    .into(),
            ),
        },
    );

    rows.push(match facts.lan_id.as_deref() {
        Some(id) if id.starts_with("net-") => row(
            "lan id",
            Verdict::Warn,
            format!(
                "{id} — the default gateway's MAC could not be read, so this is a \
                 fingerprint of the subnet alone and two different networks using \
                 the same address range would look identical"
            ),
        ),
        Some(id) => row(
            "lan id",
            Verdict::Ok,
            match net.as_ref().and_then(|n| n.subnet()) {
                Some(subnet) => format!("{id} ({subnet} via {})", gateway_of(net.as_ref())),
                None => id.to_owned(),
            },
        ),
        None => row(
            "lan id",
            Verdict::No,
            "no usable default route, so this device is on no LAN a peer could \
             broadcast on — a tunnel holding the default route is not one, because a \
             magic packet cannot be tunnelled"
                .into(),
        ),
    });

    // Only when there is something to say. On the Mac this was found on, an
    // active Tailscale exit node put `utun4` ahead of `en0` in the routing
    // table, and a user reading a wake that never lands deserves to be told
    // which interface was chosen instead of the one the rest of their traffic
    // is using.
    if !tunnels.is_empty() {
        let held = tunnels.join(", ");
        rows.push(match net.as_ref() {
            Some(n) => row(
                "tunnel",
                Verdict::Warn,
                format!(
                    "{held} holds a default route here — a VPN, most likely. A magic \
                     packet cannot be tunnelled, so wake ignores it and broadcasts on \
                     {} instead; that is the LAN a peer has to be standing on",
                    n.name
                ),
            ),
            None => row(
                "tunnel",
                Verdict::No,
                format!(
                    "{held} holds the only default route here, and a magic packet \
                     cannot be tunnelled. Nothing on this device can broadcast onto a \
                     LAN until a physical network is up"
                ),
            ),
        });
    }

    rows.push(row(
        "broadcast reaches here",
        Verdict::Unknown,
        "whether a peer's broadcast crosses the switch or access point to this NIC \
         cannot be tested from the machine that would be asleep — the only proof is \
         a wake that works"
            .into(),
    ));

    rows.push(row(
        "beacon",
        Verdict::Unknown,
        "a wake needs some device on this LAN to be awake and in the orbit. One \
         always-on machine — a Pi is enough — is what makes that reliable"
            .into(),
    ));

    rows
}

#[cfg(target_os = "macos")]
fn platform_rows(net: Option<&Interface>) -> Vec<CheckRow> {
    let pmset = run("pmset", &["-g"]).unwrap_or_default();
    let womp = pmset.lines().find_map(|l| {
        l.split_whitespace()
            .nth(1)
            .filter(|_| l.trim().starts_with("womp "))
    });

    let mut rows = vec![match womp {
        Some("1") => row("wake on magic packet", Verdict::Ok, "pmset womp = 1".into()),
        Some("0") => row(
            "wake on magic packet",
            Verdict::No,
            "pmset womp = 0 — turn it on with: sudo pmset -a womp 1".into(),
        ),
        Some(other) => row(
            "wake on magic packet",
            Verdict::Unknown,
            format!("pmset womp = {other}"),
        ),
        None => row(
            "wake on magic packet",
            Verdict::Unknown,
            "this Mac's pmset does not report womp at all, which is what Apple \
             silicon laptops do — they wake for a magic packet on AC and never on \
             battery"
                .into(),
        ),
    }];

    // The single most misleading thing about Wake-on-LAN on a Mac, so it gets
    // its own row rather than a footnote: over Ethernet it works, over Wi-Fi
    // it depends on a Bonjour Sleep Proxy that may or may not be there.
    let name = net.map(|n| n.name.as_str()).unwrap_or("-");
    let ports = run("networksetup", &["-listallhardwareports"]).unwrap_or_default();
    let kind = hardware_port(&ports, name);
    rows.push(match kind.as_deref() {
        Some(k) if k.contains("Wi-Fi") || k.contains("AirPort") => row(
            "interface",
            Verdict::Warn,
            format!(
                "{name} is {k} — a Mac wakes over Wi-Fi only if a Bonjour Sleep Proxy \
                 is on the network holding its address, and only on AC power. Wire it \
                 to Ethernet if the wake has to be dependable"
            ),
        ),
        Some(k) => row("interface", Verdict::Ok, format!("{name} is {k}")),
        None => row(
            "interface",
            Verdict::Unknown,
            format!("{name} — could not tell whether this is Ethernet or Wi-Fi"),
        ),
    });

    rows.push(match run("pmset", &["-g", "batt"]) {
        Some(out) if out.contains("AC Power") => {
            row("power source", Verdict::Ok, "AC power".into())
        }
        Some(out) if out.contains("Battery Power") => row(
            "power source",
            Verdict::No,
            "on battery — a Mac asleep on battery does not wake for a magic packet, \
             full stop. Plug it in"
                .into(),
        ),
        _ => row(
            "power source",
            Verdict::Unknown,
            "pmset could not say".into(),
        ),
    });

    rows.push(row(
        "sleep vs shutdown",
        Verdict::Warn,
        "this wakes a sleeping Mac. A Mac that was shut down cannot be woken over \
         the network at all — the NIC is unpowered — so `ast device wake` on one \
         that was turned off will report, truthfully, that nothing came online"
            .into(),
    ));
    rows
}

/// Which hardware port a BSD interface name belongs to, from
/// `networksetup -listallhardwareports`'s paragraph-per-port output.
#[cfg(target_os = "macos")]
fn hardware_port(listing: &str, iface: &str) -> Option<String> {
    let mut port: Option<&str> = None;
    for line in listing.lines() {
        if let Some(name) = line.strip_prefix("Hardware Port: ") {
            port = Some(name.trim());
        }
        if let Some(dev) = line.strip_prefix("Device: ") {
            if dev.trim() == iface {
                return port.map(|p| p.to_owned());
            }
        }
    }
    None
}

#[cfg(not(target_os = "macos"))]
fn platform_rows(net: Option<&Interface>) -> Vec<CheckRow> {
    let name = net.map(|n| n.name.as_str()).unwrap_or("-");
    let Some(out) = run("ethtool", &[name]) else {
        return vec![
            row(
                "wake on magic packet",
                Verdict::Unknown,
                format!(
                    "ethtool is not installed (or would not answer for {name}), so the \
                     NIC's wake-on flags cannot be read. Install it and run: \
                     ethtool {name}"
                ),
            ),
            row("interface", Verdict::Unknown, name.to_string()),
        ];
    };

    let flags = |prefix: &str| -> Option<String> {
        out.lines()
            .find_map(|l| l.trim().strip_prefix(prefix))
            .map(|v| v.trim().to_owned())
    };
    let supports = flags("Supports Wake-on: ");
    let current = flags("Wake-on: ");

    let mut rows = vec![match (&current, &supports) {
        (Some(c), _) if c.contains('g') => {
            row("wake on magic packet", Verdict::Ok, format!("ethtool wake-on = {c}"))
        }
        (Some(c), Some(s)) if s.contains('g') => row(
            "wake on magic packet",
            Verdict::No,
            format!("ethtool wake-on = {c}, but this NIC supports {s} — turn it on with: sudo ethtool -s {name} wol g"),
        ),
        (Some(c), Some(s)) => row(
            "wake on magic packet",
            Verdict::No,
            format!("ethtool wake-on = {c} and this NIC supports only {s} — it cannot be woken by a magic packet"),
        ),
        _ => row(
            "wake on magic packet",
            Verdict::Unknown,
            format!("ethtool answered for {name} but did not report a wake-on flag"),
        ),
    }];

    if current.as_deref().is_some_and(|c| c.contains('g')) {
        rows.push(row(
            "wake-on persistence",
            Verdict::Warn,
            format!(
                "many boards drop `wol g` across a reboot or a link-down. If a wake \
                 stops working after a restart, re-apply it: sudo ethtool -s {name} wol g"
            ),
        ));
    }
    rows.push(row("interface", Verdict::Ok, name.to_owned()));
    rows
}

fn gateway_of(net: Option<&Interface>) -> String {
    net.and_then(|n| n.gateway)
        .map(|g| g.to_string())
        .unwrap_or_else(|| "-".into())
}

/// Whether a MAC has the locally-administered bit set — the mark of an
/// address a platform generated rather than a vendor burned in, and therefore
/// one that can change out from under a peer that wrote it down.
fn is_locally_administered(mac: &str) -> bool {
    parse_mac(mac).is_some_and(|m| m[0] & 0x02 != 0)
}

fn row(item: &str, verdict: Verdict, detail: String) -> CheckRow {
    CheckRow {
        item: item.to_owned(),
        verdict,
        detail,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The one thing about a magic packet that is not a matter of taste. A
    /// sleeping NIC does a byte comparison, so this is a byte test.
    #[test]
    fn a_magic_packet_is_six_ff_bytes_then_the_mac_sixteen_times() {
        let mac = [0xde, 0xad, 0xbe, 0xef, 0x00, 0x01];
        let frame = magic_packet(mac);

        assert_eq!(frame.len(), 102);
        assert_eq!(&frame[..6], &[0xFF; 6]);
        for (i, chunk) in frame[6..].chunks(6).enumerate() {
            assert_eq!(chunk, &mac, "repeat {i} is not the target's mac");
        }
        assert_eq!(
            frame[6..].len() / 6,
            16,
            "sixteen repeats, not fifteen or seventeen"
        );
    }

    #[test]
    fn a_packet_can_only_be_built_for_something_that_is_a_mac() {
        let err = broadcast("not-a-mac", None).unwrap_err().to_string();
        assert!(err.contains("is not a MAC address"), "{err}");
    }

    /// A device that has moved must refuse, rather than broadcast onto a LAN
    /// the requester did not mean and let the wake look like it worked.
    #[test]
    fn a_device_that_moved_networks_declines_to_broadcast() {
        let err = broadcast("de:ad:be:ef:00:01", Some("lan-somewhere-else"))
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("it has moved networks") || err.contains("cannot tell which network"),
            "{err}"
        );
    }

    /// The subnet is the *network*, with the host bits gone — that is what
    /// makes a `lan_id` survive a new DHCP lease.
    #[test]
    fn a_subnet_drops_the_host_part() {
        let iface = Interface {
            addr: Some(Ipv4Addr::new(192, 168, 0, 55)),
            netmask: Some(Ipv4Addr::new(255, 255, 255, 0)),
            ..Interface::default()
        };
        assert_eq!(iface.subnet().as_deref(), Some("192.168.0.0/24"));

        let moved = Interface {
            addr: Some(Ipv4Addr::new(192, 168, 0, 77)),
            ..iface.clone()
        };
        assert_eq!(moved.subnet(), iface.subnet());

        let wider = Interface {
            netmask: Some(Ipv4Addr::new(255, 255, 0, 0)),
            ..iface
        };
        assert_eq!(wider.subnet().as_deref(), Some("192.168.0.0/16"));
        assert_eq!(Interface::default().subnet(), None);
    }

    /// The bug, in the exact shape it was found in: a Tailscale exit node up
    /// on a Mac, `utun4` ahead of `en0` in the routing table, and `route -n
    /// get default` therefore answering with the tunnel. Both defaults are in
    /// the table the whole time; the wire is the second one.
    #[test]
    fn a_tunnel_does_not_get_to_be_the_lan() {
        let listing = "\
Routing tables

Internet:
Destination        Gateway            Flags               Netif Expire
default            link#25            UCSg                utun4
default            192.168.50.1       UGScIg                en0
100.100.100.100    link#25            UHWIig              utun4
192.168.50.1/32    link#14            UCS                   en0
";
        let routes = netstat_defaults(listing);
        assert_eq!(
            routes.len(),
            2,
            "both defaults, and only the defaults: {routes:?}"
        );
        assert_eq!(routes[0].name, "en0", "the wire is preferred: {routes:?}");
        assert_eq!(routes[0].gateway, Some(Ipv4Addr::new(192, 168, 50, 1)));
        assert!(!routes[0].tunnel);
        assert_eq!(routes[1].name, "utun4");
        assert!(
            routes[1].tunnel,
            "a utun is a tunnel whatever priority it has"
        );
        assert_eq!(routes[1].gateway, None, "`link#25` is not a next hop");
    }

    /// And when the tunnel is all there is, the answer is nothing rather than
    /// the tunnel: a device routed only through a VPN is on no LAN a peer
    /// could broadcast on, and pretending otherwise is the silent failure.
    #[test]
    fn a_machine_whose_only_way_out_is_a_tunnel_is_on_no_lan() {
        let listing = "\
Internet:
Destination        Gateway            Flags               Netif Expire
default            link#25            UCSg                utun4
";
        let routes = netstat_defaults(listing);
        assert_eq!(routes.len(), 1);
        assert!(routes.iter().all(|r| r.tunnel), "{routes:?}");
    }

    /// This listing has grown `Refs` and `Use` columns and lost them again
    /// across macOS releases. The names have not moved, so they are what is
    /// read.
    #[test]
    fn the_netstat_columns_are_found_by_name_not_by_counting() {
        let old = "\
Internet:
Destination        Gateway            Flags        Refs      Use   Netif Expire
default            10.0.0.1           UGSc           31        0     en1
default            link#8             UCS             0        0    utun0
";
        assert_eq!(netstat_columns(old), (2, 5));
        let routes = netstat_defaults(old);
        assert_eq!(routes[0].name, "en1");
        assert_eq!(routes[0].gateway, Some(Ipv4Addr::new(10, 0, 0, 1)));
        assert!(routes[1].tunnel, "utun0 is still a tunnel two columns over");
    }

    /// Two wires, one of which cannot say what its next hop is. The one that
    /// can wins: the gateway's MAC is what makes a `lan_id` strong enough to
    /// tell two networks on 192.168.50.0/24 apart.
    #[test]
    fn a_route_with_a_gateway_outranks_one_without_and_a_dead_route_is_dropped() {
        let listing = "\
Internet:
Destination        Gateway            Flags               Netif Expire
default            link#14            UCSg                  en5
default            192.168.9.1        GSc                   en3
default            192.168.50.1       UGScIg                en0
";
        let routes = netstat_defaults(listing);
        let names: Vec<&str> = routes.iter().map(|r| r.name.as_str()).collect();
        assert_eq!(names, ["en0", "en5"], "en3's route is not up: {routes:?}");
    }

    /// The fallback for a Mac that cannot run netstat at all: one route, no
    /// choice, and the tunnel flag is the only thing between it and the bug.
    #[test]
    fn the_single_route_fallback_still_names_a_tunnel_as_one() {
        let vpn = "   route to: default\ndestination: default\n  interface: utun4\n      flags: <UP,DONE,CLONING,STATIC,GLOBAL>\n";
        let iface = route_get_default(vpn).expect("a route");
        assert_eq!(iface.name, "utun4");
        assert!(iface.tunnel);
        assert_eq!(iface.gateway, None, "no gateway line means no gateway");

        let wire = "   route to: default\n  interface: en0\n    gateway: 192.168.50.1\n";
        let iface = route_get_default(wire).expect("a route");
        assert_eq!(iface.name, "en0");
        assert!(!iface.tunnel);
        assert_eq!(iface.gateway, Some(Ipv4Addr::new(192, 168, 50, 1)));

        assert!(route_get_default("route: writing to routing socket: not in table").is_none());
    }

    /// The two interfaces the bug was found between, as their own `ifconfig`
    /// describes them.
    #[test]
    fn an_ifconfig_inet_line_says_whether_there_is_a_domain_or_a_peer() {
        let wire = "en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500\n\tether 84:2f:57:80:9b:fd\n\tinet6 fe80::18f3:30cd:576a:cd40%en0 prefixlen 64 secured scopeid 0xe\n\tinet 192.168.50.109 netmask 0xffffff00 broadcast 192.168.50.255\n";
        let inet = ifconfig_inet(wire).expect("an address");
        assert_eq!(inet.addr, Ipv4Addr::new(192, 168, 50, 109));
        assert_eq!(inet.netmask, Ipv4Addr::new(255, 255, 255, 0));
        assert_eq!(inet.broadcast, Some(Ipv4Addr::new(192, 168, 50, 255)));
        assert!(!inet.point_to_point);

        let tunnel = "utun4: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1280\n\tinet6 fe80::7487:a49c:3993:547c%utun4 prefixlen 64 scopeid 0x19\n\tinet 100.121.213.11 --> 100.121.213.11 netmask 0xffffffff\n";
        let inet = ifconfig_inet(tunnel).expect("an address");
        assert!(
            inet.point_to_point,
            "`-->` is one peer, not a broadcast domain"
        );
        assert_eq!(inet.netmask, Ipv4Addr::new(255, 255, 255, 255));
        assert_eq!(inet.broadcast, None);
    }

    /// The name list is a heuristic. This is the check that does not depend
    /// on what a VPN decided to call itself.
    #[test]
    fn an_address_with_no_room_for_neighbours_is_not_a_lan() {
        let wire = Interface {
            addr: Some(Ipv4Addr::new(192, 168, 50, 109)),
            netmask: Some(Ipv4Addr::new(255, 255, 255, 0)),
            ..Interface::default()
        };
        assert!(carries_broadcast(&wire));

        let slash_32 = Interface {
            netmask: Some(Ipv4Addr::new(255, 255, 255, 255)),
            ..wire.clone()
        };
        assert!(
            !carries_broadcast(&slash_32),
            "a /32 has no broadcast address"
        );

        let slash_31 = Interface {
            netmask: Some(Ipv4Addr::new(255, 255, 255, 254)),
            ..wire.clone()
        };
        assert!(
            !carries_broadcast(&slash_31),
            "a /31 is a point-to-point link"
        );

        let peered = Interface {
            point_to_point: true,
            ..wire.clone()
        };
        assert!(!carries_broadcast(&peered), "a peer is not a domain");

        // Nothing read is not the same as nothing there: an `ifconfig` that
        // would not answer must not decide a device has no LAN.
        let unread = Interface {
            netmask: None,
            ..wire
        };
        assert!(carries_broadcast(&unread));
    }

    #[test]
    fn a_tunnel_is_recognised_by_name_and_a_wire_is_not() {
        for name in [
            "utun4",
            "tun0",
            "tap0",
            "wg0",
            "ipsec1",
            "ppp0",
            "tailscale0",
            "ztabc123",
            "awdl0",
        ] {
            assert!(is_tunnel_iface(name), "{name} is a tunnel");
        }
        for name in [
            "en0", "en5", "eth0", "enp3s0", "wlan0", "wlp2s0", "eno1", "bridge0", "br0", "bond0",
        ] {
            assert!(!is_tunnel_iface(name), "{name} is a wire");
        }
    }

    /// Linux gets the same rule and needs it for the same reason: OpenVPN and
    /// a bare `ip route add default dev tun0` both put a tunnel in the main
    /// table. Tailscale and WireGuard there route by fwmark in a table of
    /// their own and never show up in this file at all — which is why the Mac
    /// hit this first, and is not a reason for the two platforms to disagree.
    #[test]
    fn linux_prefers_the_wire_to_the_tunnel_too() {
        let table = "\
Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT
tun0\t00000000\t0108080A\t0003\t0\t0\t50\t00000000\t0\t0\t0
eth0\t00000000\t0132A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0
eth0\t0032A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0
";
        let routes = proc_net_route_defaults(table);
        assert_eq!(
            routes.len(),
            2,
            "the on-link route is not a default: {routes:?}"
        );
        assert_eq!(
            routes[0].name, "eth0",
            "the tunnel is listed first and still loses"
        );
        assert_eq!(routes[0].gateway, Some(Ipv4Addr::new(192, 168, 50, 1)));
        assert!(routes[1].tunnel);
    }

    /// Between two wires the kernel has already expressed a preference, and
    /// the metric is where it wrote it down.
    #[test]
    fn linux_takes_the_kernels_own_ranking_between_two_wires() {
        let table = "\
Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT
wlan0\t00000000\t0132A8C0\t0003\t0\t0\t600\t00000000\t0\t0\t0
eth0\t00000000\t0132A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0
";
        let routes = proc_net_route_defaults(table);
        let names: Vec<&str> = routes.iter().map(|r| r.name.as_str()).collect();
        assert_eq!(names, ["eth0", "wlan0"]);
    }

    /// One unreadable line is not a reason to miss the wire in the line below
    /// it — the old code returned `None` from the whole scan on a bad field.
    /// A default route with no next hop is still a route, ranked under one
    /// that has a gateway to fingerprint.
    #[test]
    fn linux_skips_what_it_cannot_read_and_keeps_scanning() {
        let table = "\
Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT
junk\t00000000\tZZZZZZZZ\txxxx\t0\t0\t0\t00000000\t0\t0\t0
down0\t00000000\t0132A8C0\t0002\t0\t0\t0\t00000000\t0\t0\t0
eth1\t00000000\t00000000\t0001\t0\t0\t0\t00000000\t0\t0\t0
eth0\t00000000\t0132A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0
";
        let routes = proc_net_route_defaults(table);
        let names: Vec<&str> = routes.iter().map(|r| r.name.as_str()).collect();
        assert_eq!(
            names,
            ["eth0", "eth1"],
            "junk is unparseable and down0 is not up"
        );
        assert_eq!(
            routes[1].gateway, None,
            "`default dev eth1` has no next hop"
        );
    }

    #[test]
    fn an_ip_addr_line_says_whether_there_is_a_domain_or_a_peer() {
        let wire = "2: eth0    inet 192.168.1.50/24 brd 192.168.1.255 scope global dynamic eth0\\       valid_lft 84331sec preferred_lft 84331sec";
        let inet = ip_addr_inet(wire).expect("an address");
        assert_eq!(inet.addr, Ipv4Addr::new(192, 168, 1, 50));
        assert_eq!(inet.netmask, Ipv4Addr::new(255, 255, 255, 0));
        assert_eq!(inet.broadcast, Some(Ipv4Addr::new(192, 168, 1, 255)));
        assert!(!inet.point_to_point);

        let tunnel = "5: tun0    inet 10.8.0.2 peer 10.8.0.1/32 scope global tun0\\       valid_lft forever preferred_lft forever";
        let inet = ip_addr_inet(tunnel).expect("an address");
        assert!(inet.point_to_point, "a peer is what BSD spells `-->`");
        assert_eq!(inet.addr, Ipv4Addr::new(10, 8, 0, 2));
        assert_eq!(inet.broadcast, None);

        let wireguard = "4: wg0    inet 10.9.0.2/32 scope global wg0\\       valid_lft forever preferred_lft forever";
        let inet = ip_addr_inet(wireguard).expect("an address");
        assert!(
            !inet.point_to_point,
            "no peer field — and a /32 all the same"
        );
        assert_eq!(inet.netmask, Ipv4Addr::new(255, 255, 255, 255));
    }

    /// The subnet-directed broadcast goes first: it is the one that still has
    /// a route of its own when a tunnel has taken the default.
    #[test]
    fn the_subnet_broadcast_is_tried_before_the_limited_one() {
        let net = Interface {
            addr: Some(Ipv4Addr::new(192, 168, 50, 109)),
            broadcast: Some(Ipv4Addr::new(192, 168, 50, 255)),
            ..Interface::default()
        };
        assert_eq!(
            broadcast_targets(Some(&net)),
            [Ipv4Addr::new(192, 168, 50, 255), Ipv4Addr::BROADCAST]
        );
        assert_eq!(broadcast_targets(None), [Ipv4Addr::BROADCAST]);

        let odd = Interface {
            broadcast: Some(Ipv4Addr::BROADCAST),
            ..Interface::default()
        };
        assert_eq!(
            broadcast_targets(Some(&odd)),
            [Ipv4Addr::BROADCAST],
            "not twice"
        );
    }

    /// An address reaches [`broadcast_socket`] only because it is the wire the
    /// packet has to leave by, so a pin that cannot be bound has to be heard
    /// about. Falling back to the wildcard would put the frame back in the
    /// tunnel and then report a successful broadcast — the silent failure the
    /// interface is chosen to avoid in the first place.
    #[test]
    fn a_pin_that_cannot_be_bound_is_an_error_rather_than_a_wildcard() {
        // TEST-NET-1: reserved for documentation, and therefore an address no
        // host is holding, so the bind fails the same way everywhere.
        let unheld = Ipv4Addr::new(192, 0, 2, 1);
        let err = broadcast_socket(Some(unheld)).unwrap_err();
        let err = format!("{err:#}");
        assert!(
            err.contains("192.0.2.1"),
            "the error has to name the address: {err}"
        );

        // A pin that *can* be bound is the socket that comes back — the point
        // of the error above is the pin, not a refusal to bind at all.
        let pinned = broadcast_socket(Some(Ipv4Addr::LOCALHOST)).expect("a pinned socket");
        assert_eq!(pinned.local_addr().unwrap().ip(), Ipv4Addr::LOCALHOST);
    }

    /// The wildcard still belongs to the one case it is for: a device that
    /// never had an address to pin to.
    #[test]
    fn a_device_with_no_address_to_pin_to_still_gets_a_socket() {
        let socket = broadcast_socket(None).expect("a wildcard socket");
        assert_eq!(socket.local_addr().unwrap().ip(), Ipv4Addr::UNSPECIFIED);
        assert!(
            socket.broadcast().unwrap(),
            "a socket that cannot broadcast is no use here"
        );
    }

    /// A private Wi-Fi address is the quiet way a recorded MAC goes stale, so
    /// the check has to be able to spot one.
    #[test]
    fn a_locally_administered_mac_is_recognised() {
        assert!(is_locally_administered("3a:f1:68:c5:0b:89"));
        assert!(!is_locally_administered("d0:11:e5:e0:92:b1"));
        assert!(!is_locally_administered("58:86:94:ac:56:d0"));
        assert!(!is_locally_administered("nonsense"));
    }

    /// Every row has to carry its own evidence: a table of bare verdicts is
    /// exactly the thing this command exists not to be.
    #[test]
    fn check_reports_something_about_every_row_and_names_what_it_cannot_know() {
        let rows = check();
        assert!(rows.len() >= 4, "{rows:?}");
        for r in &rows {
            assert!(!r.item.is_empty());
            assert!(
                !r.detail.is_empty(),
                "{} has a verdict and no evidence",
                r.item
            );
        }
        assert!(
            rows.iter().any(|r| r.verdict == Verdict::Unknown),
            "a check that claims to know everything is not honest: {rows:?}"
        );
        assert!(rows.iter().any(|r| r.item == "wake on magic packet"));
        assert!(rows.iter().any(|r| r.item == "lan id"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn a_bsd_interface_name_is_matched_to_its_hardware_port() {
        let listing = "\nHardware Port: Ethernet\nDevice: en0\nEthernet Address: d0:11:e5:e0:92:b1\n\nHardware Port: Wi-Fi\nDevice: en1\nEthernet Address: d0:11:e5:dc:49:4d\n";
        assert_eq!(hardware_port(listing, "en0").as_deref(), Some("Ethernet"));
        assert_eq!(hardware_port(listing, "en1").as_deref(), Some("Wi-Fi"));
        assert_eq!(hardware_port(listing, "en9"), None);
    }

    /// The test hooks have to actually take effect, or the e2e proves nothing
    /// about the code path a real wake uses.
    #[test]
    fn the_test_hooks_override_what_this_device_says_about_itself() {
        // Deliberately not run in parallel with anything else that reads the
        // environment; these are the only tests that touch it, and they are
        // in one test so they cannot race each other.
        std::env::set_var(MAC_ENV, "DE-AD-BE-EF-00-09");
        std::env::set_var(LAN_ID_ENV, "lan-pretend");
        std::env::set_var(PORT_ENV, "19999");

        let facts = facts();
        assert_eq!(
            facts.mac.as_deref(),
            Some("de:ad:be:ef:00:09"),
            "normalised, not echoed"
        );
        assert_eq!(facts.lan_id.as_deref(), Some("lan-pretend"));
        assert_eq!(wol_port(), 19999);

        std::env::remove_var(MAC_ENV);
        std::env::remove_var(LAN_ID_ENV);
        std::env::remove_var(PORT_ENV);
    }
}
