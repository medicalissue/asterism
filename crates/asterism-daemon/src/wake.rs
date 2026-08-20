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
    if let Some(expected) = expect_lan {
        let mine = facts();
        match mine.lan_id.as_deref() {
            Some(id) if id == expected => {}
            Some(id) => bail!(
                "this device is on {id}, not {expected} — it has moved networks since \
                 you last heard from it, so its broadcast would not reach that LAN"
            ),
            None => bail!("this device cannot tell which network it is on, so it will not broadcast"),
        }
    }

    let frame = magic_packet(bytes);
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).context("binding a udp socket")?;
    socket.set_broadcast(true).context("asking for broadcast on a udp socket")?;

    let port = wol_port();
    let mut sent = Vec::new();
    let mut last: Option<std::io::Error> = None;
    for target in broadcast_targets() {
        match socket.send_to(&frame, (target, port)) {
            Ok(_) => sent.push(format!("{target}:{port}")),
            Err(e) => last = Some(e),
        }
    }
    if sent.is_empty() {
        let why = last.map(|e| e.to_string()).unwrap_or_else(|| "no broadcast address".into());
        bail!("could not broadcast a magic packet: {why}");
    }
    Ok(sent)
}

/// Where a magic packet goes: the limited broadcast address always, and the
/// subnet's own when this device knows what its subnet is.
fn broadcast_targets() -> Vec<Ipv4Addr> {
    let mut targets = vec![Ipv4Addr::BROADCAST];
    if let Some(net) = interface() {
        if let Some(bcast) = net.broadcast {
            if bcast != Ipv4Addr::BROADCAST {
                targets.push(bcast);
            }
        }
    }
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
    let net = interface();
    let mac = std::env::var(MAC_ENV)
        .ok()
        .filter(|m| parse_mac(m).is_some())
        .map(|m| format_mac(parse_mac(&m).expect("just checked")))
        .or_else(|| net.as_ref().and_then(|n| n.mac.clone()));
    let lan_id = std::env::var(LAN_ID_ENV)
        .ok()
        .filter(|id| !id.trim().is_empty())
        .or_else(|| {
            let net = net.as_ref()?;
            lan_fingerprint(net.gateway_mac.as_deref(), net.subnet().as_deref())
        });

    WakeFacts {
        mac,
        lan_id,
        iface: net.as_ref().map(|n| n.name.clone()),
        seen_at: now_unix(),
    }
}

/// The interface carrying this device's default route, and what is known
/// about it.
///
/// The default route is the right interface by definition: it is the one the
/// orbit's own traffic uses, so it is the one a peer that can reach us is
/// reaching us on, and therefore the one whose broadcast domain matters.
#[derive(Debug, Default, Clone)]
struct Interface {
    name: String,
    mac: Option<String>,
    addr: Option<Ipv4Addr>,
    netmask: Option<Ipv4Addr>,
    broadcast: Option<Ipv4Addr>,
    gateway: Option<Ipv4Addr>,
    gateway_mac: Option<String>,
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

fn interface() -> Option<Interface> {
    let mut iface = default_route()?;
    iface.mac = iface_mac(&iface.name);
    if let Some((addr, mask, bcast)) = iface_inet(&iface.name) {
        iface.addr = Some(addr);
        iface.netmask = Some(mask);
        iface.broadcast = bcast;
    }
    if let Some(gw) = iface.gateway {
        iface.gateway_mac = neighbour_mac(gw, &iface.name);
    }
    Some(iface)
}

// ---- platform probes -------------------------------------------------------
//
// Shelled out rather than done through libc, because every one of these is a
// text format that has not changed in twenty years, and the alternative is a
// per-platform FFI surface (getifaddrs, sysctl NET_RT_DUMP, netlink) for
// facts we read a handful of times a day. Everything below returns `Option`
// and nothing panics on a format it does not recognise: a device that cannot
// say where it is says so, and `ast device check` reports that honestly.

#[cfg(target_os = "macos")]
fn default_route() -> Option<Interface> {
    let out = run("route", &["-n", "get", "default"])?;
    let mut iface = Interface::default();
    for line in out.lines() {
        match line.split_once(':').map(|(k, v)| (k.trim(), v.trim())) {
            Some(("interface", v)) => iface.name = v.to_owned(),
            Some(("gateway", v)) => iface.gateway = v.parse().ok(),
            _ => {}
        }
    }
    (!iface.name.is_empty()).then_some(iface)
}

/// Linux keeps the routing table in a file, so no binary has to exist for
/// this to work. Destination 0 with the UP|GATEWAY flags is the default
/// route; both addresses are little-endian hex.
#[cfg(not(target_os = "macos"))]
fn default_route() -> Option<Interface> {
    let table = std::fs::read_to_string("/proc/net/route").ok()?;
    for line in table.lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 4 || f[1] != "00000000" {
            continue;
        }
        let flags = u32::from_str_radix(f[3], 16).ok()?;
        if flags & 0x2 == 0 {
            continue; // not a gateway route
        }
        let gw = u32::from_str_radix(f[2], 16).ok()?;
        return Some(Interface {
            name: f[0].to_owned(),
            gateway: Some(Ipv4Addr::from(gw.to_be())),
            ..Interface::default()
        });
    }
    None
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

/// The interface's address, netmask and broadcast address.
#[cfg(target_os = "macos")]
fn iface_inet(name: &str) -> Option<(Ipv4Addr, Ipv4Addr, Option<Ipv4Addr>)> {
    let out = run("ifconfig", &[name])?;
    for line in out.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.first() != Some(&"inet") || f.len() < 4 {
            continue;
        }
        let addr: Ipv4Addr = f[1].parse().ok()?;
        // BSD prints the mask as 0xffffff00.
        let mask = f
            .iter()
            .position(|w| *w == "netmask")
            .and_then(|i| f.get(i + 1))
            .and_then(|m| u32::from_str_radix(m.trim_start_matches("0x"), 16).ok())
            .map(Ipv4Addr::from)?;
        let bcast = f
            .iter()
            .position(|w| *w == "broadcast")
            .and_then(|i| f.get(i + 1))
            .and_then(|b| b.parse().ok());
        return Some((addr, mask, bcast));
    }
    None
}

#[cfg(not(target_os = "macos"))]
fn iface_inet(name: &str) -> Option<(Ipv4Addr, Ipv4Addr, Option<Ipv4Addr>)> {
    let out = run("ip", &["-4", "-o", "addr", "show", "dev", name])?;
    let f: Vec<&str> = out.split_whitespace().collect();
    let i = f.iter().position(|w| *w == "inet")?;
    let (addr, prefix) = f.get(i + 1)?.split_once('/')?;
    let addr: Ipv4Addr = addr.parse().ok()?;
    let prefix: u32 = prefix.parse().ok()?;
    let mask = Ipv4Addr::from(if prefix == 0 { 0 } else { u32::MAX << (32 - prefix.min(32)) });
    let bcast = f
        .iter()
        .position(|w| *w == "brd")
        .and_then(|i| f.get(i + 1))
        .and_then(|b| b.parse().ok());
    Some((addr, mask, bcast))
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
    let mut child = std::process::Command::new(program)
        .args(args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .ok()?;

    let deadline = std::time::Instant::now() + PROBE_TIMEOUT;
    loop {
        match child.try_wait().ok()? {
            Some(_) => break,
            None if std::time::Instant::now() > deadline => {
                let _ = child.kill();
                return None;
            }
            None => std::thread::sleep(Duration::from_millis(20)),
        }
    }
    let out = child.wait_with_output().ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).into_owned())
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
    let net = interface();
    let mut rows = platform_rows(net.as_ref());

    let facts = facts();
    rows.push(match (&facts.mac, net.as_ref().and_then(|n| n.mac.as_ref())) {
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
    });

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
            "no default route, so this device is on no LAN a peer could broadcast on"
                .into(),
        ),
    });

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
    let womp = pmset
        .lines()
        .find_map(|l| l.split_whitespace().nth(1).filter(|_| l.trim().starts_with("womp ")));

    let mut rows = vec![match womp {
        Some("1") => row("wake on magic packet", Verdict::Ok, "pmset womp = 1".into()),
        Some("0") => row(
            "wake on magic packet",
            Verdict::No,
            "pmset womp = 0 — turn it on with: sudo pmset -a womp 1".into(),
        ),
        Some(other) => row("wake on magic packet", Verdict::Unknown, format!("pmset womp = {other}")),
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
        _ => row("power source", Verdict::Unknown, "pmset could not say".into()),
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
    CheckRow { item: item.to_owned(), verdict, detail }
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
        assert_eq!(frame[6..].len() / 6, 16, "sixteen repeats, not fifteen or seventeen");
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

        let moved = Interface { addr: Some(Ipv4Addr::new(192, 168, 0, 77)), ..iface.clone() };
        assert_eq!(moved.subnet(), iface.subnet());

        let wider = Interface { netmask: Some(Ipv4Addr::new(255, 255, 0, 0)), ..iface };
        assert_eq!(wider.subnet().as_deref(), Some("192.168.0.0/16"));
        assert_eq!(Interface::default().subnet(), None);
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
            assert!(!r.detail.is_empty(), "{} has a verdict and no evidence", r.item);
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
        assert_eq!(facts.mac.as_deref(), Some("de:ad:be:ef:00:09"), "normalised, not echoed");
        assert_eq!(facts.lan_id.as_deref(), Some("lan-pretend"));
        assert_eq!(wol_port(), 19999);

        std::env::remove_var(MAC_ENV);
        std::env::remove_var(LAN_ID_ENV);
        std::env::remove_var(PORT_ENV);
    }
}
