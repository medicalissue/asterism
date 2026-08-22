//! Finding the guest on the NAT network, and knocking on port 22.
//!
//! This is the concrete form of `GuestEndpoint::GuestAddr`. QEMU's user-net
//! hands out a host-side forwarded port and therefore a guaranteed answer;
//! VZ's NAT gives the guest a real address on a bridge macOS owns, and the
//! only public record of which address that is lives in `bootpd`'s lease
//! file. There is no API — Apple exposes none — so parsing the lease file is
//! what every VZ-based tool ends up doing.
//!
//! Lifted from `crates/asterism-vz-spike/src/net.rs` together with its
//! tests, whose fixture is a verbatim slice of a real `/var/db/dhcpd_leases`
//! captured mid-spike.

use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::path::Path;
use std::time::Duration;

/// macOS's DHCP server for the shared/NAT networks writes here.
pub const LEASES: &str = "/var/db/dhcpd_leases";

/// Look up the addresses `bootpd` may have handed a guest, by MAC *or* by
/// hostname.
///
/// The file is a sequence of `{ ... }` records with `ip_address`,
/// `hw_address` and `name`. Four traps, all of which the spike hit:
///
/// 1. The MAC is stored *without* leading zeros per octet (`a:b:c`, not
///    `0a:0b:0c`), so a literal compare against the address you configured
///    never matches.
/// 2. The value is prefixed with the ARP hardware type (`1,` for Ethernet),
///    which is not part of the address.
/// 3. **The MAC is frequently not there at all.** A Debian 13 guest's DHCP
///    client sends an RFC 4361 client identifier (a DUID plus an IAID)
///    rather than its hardware address, and `bootpd` records exactly what it
///    was sent: `hw_address=ff,<17 bytes of DUID>`. Hardware type `ff` means
///    "this is a client identifier", and the MAC is unrecoverable from it.
///    The only usable key for such a guest is the hostname it sent — which,
///    for an Asterism instance, is the instance name the seed set.
/// 4. **Records are never removed and hostnames repeat.** Rebuild an
///    instance's disk and its DUID changes, so `bootpd` writes a *second*
///    record with the same `name=` and a different address, leaving the dead
///    one in place. Taking the first hostname match hands out the previous
///    generation's address — live-looking, and nothing answers on it. The
///    `lease=` field (a big-endian hex unix expiry) is the tiebreak.
///
/// So the lease file only ever produces *candidates*, never an answer: match
/// on MAC and on hostname, order by lease freshness, and let the caller
/// prove which one is really the guest by talking to it.
pub fn lease_candidates(mac: &str, hostname: &str) -> Vec<IpAddr> {
    let Ok(text) = std::fs::read_to_string(Path::new(LEASES)) else {
        return Vec::new();
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    candidates(&text, mac, hostname, now)
}

/// Split out from the file read so it can be tested against a real lease
/// file. Returns best-first: MAC matches before hostname matches, newest
/// lease first.
fn candidates(text: &str, mac: &str, hostname: &str, now: u64) -> Vec<IpAddr> {
    let want = normalize(mac);
    let (mut ip, mut hw, mut name, mut expiry) = (None, None, None, 0u64);
    // rank 1 = matched the MAC (unambiguous), rank 0 = matched the hostname.
    let mut found: Vec<(u8, u64, IpAddr)> = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line == "{" {
            (ip, hw, name, expiry) = (None, None, None, 0);
        } else if line == "}" {
            if let Some(ip) = ip {
                let rank = if hw.as_deref() == Some(want.as_str()) {
                    Some(1)
                } else if name.as_deref() == Some(hostname) {
                    Some(0)
                } else {
                    None
                };
                // An expiry of 0 means we could not parse one; keep the
                // record rather than drop a lease we would otherwise use.
                if let Some(rank) = rank {
                    if expiry == 0 || expiry >= now {
                        found.push((rank, expiry, ip));
                    }
                }
            }
        } else if let Some(v) = line.strip_prefix("ip_address=") {
            ip = v.trim().parse().ok();
        } else if let Some(v) = line.strip_prefix("hw_address=") {
            // Only hardware type 1 (Ethernet) carries an actual MAC.
            hw = v.trim().strip_prefix("1,").map(normalize);
        } else if let Some(v) = line.strip_prefix("name=") {
            name = Some(v.trim().to_owned());
        } else if let Some(v) = line.strip_prefix("lease=") {
            expiry = v
                .trim()
                .strip_prefix("0x")
                .and_then(|h| u64::from_str_radix(h, 16).ok())
                .unwrap_or(0);
        }
    }
    found.sort_by_key(|c| std::cmp::Reverse((c.0, c.1)));
    found.into_iter().map(|(_, _, ip)| ip).collect()
}

/// Strip leading zeros per octet and lowercase, so the two spellings of the
/// same MAC compare equal.
fn normalize(mac: &str) -> String {
    mac.split(':')
        .map(|o| o.trim_start_matches('0'))
        .map(|o| if o.is_empty() { "0" } else { o })
        .collect::<Vec<_>>()
        .join(":")
        .to_ascii_lowercase()
}

/// Connect to `ip:22` and read the SSH identification string.
///
/// RFC 4253 has the server send its banner first, so a successful read
/// proves sshd is actually serving rather than that something bound a port.
/// That distinction is the whole reason the endpoint is discovered this way:
/// a stale lease record points at an address that may well accept a TCP
/// connection from somebody else's guest.
pub fn ssh_banner(ip: IpAddr, timeout: Duration) -> Option<String> {
    let addr = SocketAddr::new(ip, 22);
    let mut stream = TcpStream::connect_timeout(&addr, timeout).ok()?;
    stream.set_read_timeout(Some(timeout)).ok()?;
    let mut buf = [0u8; 256];
    let n = stream.read(&mut buf).ok()?;
    if n == 0 {
        return None;
    }
    let banner = String::from_utf8_lossy(&buf[..n]).trim().to_owned();
    if !banner.starts_with("SSH-") {
        return None;
    }
    // Be polite: identify back, so sshd logs a clean disconnect rather than
    // a protocol error on every probe.
    let _ = stream.write_all(b"SSH-2.0-Asterism\r\n");
    Some(banner)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn macs_compare_regardless_of_leading_zeros() {
        assert_eq!(normalize("0A:0B:0C:01:02:03"), "a:b:c:1:2:3");
        assert_eq!(normalize("a:b:c:1:2:3"), "a:b:c:1:2:3");
        // An all-zero octet must survive as "0", not vanish.
        assert_eq!(normalize("00:11:00:22:00:33"), "0:11:0:22:0:33");
    }

    #[test]
    fn a_client_identifier_lease_yields_no_mac() {
        // Hardware type ff is a DUID, not an Ethernet address; treating its
        // trailing bytes as a MAC would match the wrong guest.
        let hw = "ff,f1:f5:dd:7f:0:2:0:0:ab:11:5f:eb:70:8:c6:9f:8c:b7";
        assert!(hw.strip_prefix("1,").is_none());
        assert_eq!(
            "1,a:b:c:1:2:3".strip_prefix("1,").map(normalize).as_deref(),
            Some("a:b:c:1:2:3")
        );
    }

    /// Taken verbatim from /var/db/dhcpd_leases mid-spike: two generations
    /// of the same instance, neither carrying a usable MAC.
    const REAL: &str = "\
{
\tname=vzspike
\tip_address=192.168.64.7
\thw_address=ff,f1:f5:dd:7f:0:2:0:0:ab:11:dc:f5:f1:37:69:8f:af:e2
\tlease=0x6a870e83
}
{
\tname=vzspike
\tip_address=192.168.64.6
\thw_address=ff,f1:f5:dd:7f:0:2:0:0:ab:11:5f:eb:70:8:c6:9f:8c:b7
\tlease=0x6a870d19
}
{
\tname=linux
\tip_address=192.168.64.4
\thw_address=1,52:54:0:ad:81:1a
\tlease=0x685ee1bc
}
";

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn both_generations_are_offered_newest_first() {
        // 0x6a870e83 is newer than 0x6a870d19. Both are returned, because
        // the newest lease is a good guess and not a guarantee — only the
        // one that answers on :22 is the live guest.
        let got = candidates(REAL, "52:54:00:a5:73:11", "vzspike", 0x6a87_0000);
        assert_eq!(got, vec![ip("192.168.64.7"), ip("192.168.64.6")]);
    }

    #[test]
    fn expired_leases_are_ignored() {
        assert!(candidates(REAL, "52:54:00:a5:73:11", "vzspike", 0x7000_0000).is_empty());
    }

    #[test]
    fn a_mac_match_outranks_any_hostname_match() {
        // The `linux` record's MAC, asked under the `vzspike` hostname: the
        // older-but-exact MAC record must still come first.
        let got = candidates(REAL, "52:54:00:ad:81:1a", "vzspike", 0x6000_0000);
        assert_eq!(got.first(), Some(&ip("192.168.64.4")));
    }

    #[test]
    fn an_unrelated_guest_is_never_a_candidate() {
        assert!(candidates(REAL, "aa:bb:cc:dd:ee:ff", "other", 0x6a87_0000).is_empty());
    }

    #[test]
    fn a_missing_lease_file_is_no_candidates_rather_than_an_error() {
        assert!(lease_candidates("52:54:00:00:00:01", "definitely-not-a-guest").is_empty());
    }

    /// A candidate that is not there has to be given up on quickly. This is
    /// not a nicety: the probe runs on its own thread precisely because a
    /// blocking connect on the VM's queue starves the guest, and a slow
    /// probe would still delay every other candidate behind it.
    /// 192.0.2.0/24 is TEST-NET-1 (RFC 5737) — reserved, and routed
    /// nowhere.
    #[test]
    fn a_dead_address_produces_no_banner() {
        let started = std::time::Instant::now();
        assert!(ssh_banner(ip("192.0.2.1"), Duration::from_millis(150)).is_none());
        assert!(started.elapsed() < Duration::from_secs(2));
    }
}
