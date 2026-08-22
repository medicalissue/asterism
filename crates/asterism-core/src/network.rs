//! The network exit-point part: policy recorded on an instance, and the
//! transport-independent decision that binds that policy to a live device.
//!
//! A guest has one stable virtual network edge. Changing the device behind
//! that edge must not change the guest's gateway, DNS address or interface;
//! it only changes where packets leave the orbit. This module deliberately
//! stops at that narrow seam. A backend projects the edge into a guest, while
//! the mesh supplies observations saying whether a provider is local, direct
//! or relayed. Neither concern is encoded as a host-specific conditional in
//! the instance model.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::instance::PartRuntime;

/// The guest-visible edge. These addresses are part of Asterism's private
/// virtual link, not an address on the CPU device or exit-point device.
/// Consequently attach, failover and detach never require guest changes.
pub const GUEST_GATEWAY: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(100, 64, 0, 1));
pub const GUEST_DNS: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(100, 64, 0, 53));
pub const GUEST_ADDRESS: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(100, 64, 0, 2));
pub const GUEST_GATEWAY_V6: IpAddr = IpAddr::V6(std::net::Ipv6Addr::new(
    0xfd64, 0x6173, 0x7400, 0, 0, 0, 0, 1,
));
pub const GUEST_DNS_V6: IpAddr = IpAddr::V6(std::net::Ipv6Addr::new(
    0xfd64, 0x6173, 0x7400, 0, 0, 0, 0, 0x53,
));
pub const GUEST_ADDRESS_V6: IpAddr = IpAddr::V6(std::net::Ipv6Addr::new(
    0xfd64, 0x6173, 0x7400, 0, 0, 0, 0, 2,
));

/// Hard wire and persistence bounds for one exit attachment. These limits are
/// enforced again by the provider: an authenticated peer is still untrusted
/// input and must not be able to turn a grant into a multi-megabyte policy.
pub const MAX_EXIT_PROVIDERS: usize = 16;
pub const MAX_EXIT_ROUTE_PREFIXES: usize = 128;
pub const MAX_EXIT_DNS_SERVERS: usize = 16;

/// Locally administered MAC used by the daemon side of every guest edge.
pub const EDGE_GATEWAY_MAC: [u8; 6] = [0x02, 0x41, 0x53, 0x54, 0x00, 0x01];

/// Whether a provider may open an ordinary outbound socket to this address.
///
/// Exit traffic is public-unicast by default. Provider-local namespaces are
/// never inherited merely because a paired peer can reach the mesh: that
/// would turn the packet plane into an SSRF and LAN-scanning oracle.
pub fn is_public_unicast(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            let octets = address.octets();
            !address.is_unspecified()
                && !address.is_loopback()
                && !address.is_private()
                && !address.is_link_local()
                && !address.is_multicast()
                && !address.is_broadcast()
                && !address.is_documentation()
                && !(octets[0] == 100 && (64..=127).contains(&octets[1]))
                && !(octets[0] == 198 && (octets[1] == 18 || octets[1] == 19))
                && !(octets[0] == 192 && octets[1] == 0 && octets[2] == 0)
                && octets[0] != 0
                && octets[0] < 240
        }
        IpAddr::V6(address) => {
            if let Some(mapped) = address.to_ipv4_mapped() {
                return is_public_unicast(IpAddr::V4(mapped));
            }
            !address.is_unspecified()
                && !address.is_loopback()
                && !address.is_multicast()
                && !address.is_unique_local()
                && !address.is_unicast_link_local()
                && address.segments()[..2] != [0x2001, 0x0db8]
        }
    }
}

/// Stable primary and edge NIC identities derived from the durable instance
/// id. The two different fourth octets keep the devices distinct while a
/// move preserves both identities with the instance.
pub fn guest_macs(instance_id: &str) -> ([u8; 6], [u8; 6]) {
    let hash = crate::instance::fnv1a(instance_id);
    let tail = hash.to_be_bytes();
    (
        [0x52, 0x54, 0x00, tail[5], tail[6], tail[7]],
        [0x52, 0x54, 0x01, tail[5], tail[6], tail[7]],
    )
}

/// One canonical IP prefix used by route policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct IpPrefix {
    pub network: IpAddr,
    pub bits: u8,
}

impl IpPrefix {
    pub fn contains(self, address: IpAddr) -> bool {
        match (self.network, address) {
            (IpAddr::V4(network), IpAddr::V4(address)) => {
                let bits = self.bits.min(32);
                let mask = if bits == 0 {
                    0
                } else {
                    u32::MAX << (32 - bits)
                };
                u32::from(network) & mask == u32::from(address) & mask
            }
            (IpAddr::V6(network), IpAddr::V6(address)) => {
                let bits = self.bits.min(128);
                let mask = if bits == 0 {
                    0
                } else {
                    u128::MAX << (128 - bits)
                };
                u128::from(network) & mask == u128::from(address) & mask
            }
            _ => false,
        }
    }
}

impl FromStr for IpPrefix {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (address, bits) = value
            .split_once('/')
            .ok_or_else(|| format!("{value:?} is not a CIDR prefix (try 0.0.0.0/0)"))?;
        let address = address
            .parse::<IpAddr>()
            .map_err(|_| format!("{value:?} has no valid IP address"))?;
        let bits = bits
            .parse::<u8>()
            .map_err(|_| format!("{value:?} has no valid prefix length"))?;
        let width = if address.is_ipv4() { 32 } else { 128 };
        if bits > width {
            return Err(format!("{value:?} has a prefix longer than {width} bits"));
        }
        let network = match address {
            IpAddr::V4(address) => {
                let mask = if bits == 0 {
                    0
                } else {
                    u32::MAX << (32 - bits)
                };
                IpAddr::V4((u32::from(address) & mask).into())
            }
            IpAddr::V6(address) => {
                let mask = if bits == 0 {
                    0
                } else {
                    u128::MAX << (128 - bits)
                };
                IpAddr::V6((u128::from(address) & mask).into())
            }
        };
        Ok(IpPrefix { network, bits })
    }
}

impl std::fmt::Display for IpPrefix {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.network, self.bits)
    }
}

/// Which guest destinations are carried through the exit point.
///
/// Exclusions win over inclusions. Orbit control traffic is never eligible:
/// allowing a guest's default route to capture the mesh carrying that same
/// route would be both a leak and a recursive tunnel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoutePolicy {
    #[serde(default = "default_routes")]
    pub include: Vec<IpPrefix>,
    #[serde(default)]
    pub exclude: Vec<IpPrefix>,
}

fn default_routes() -> Vec<IpPrefix> {
    vec![
        "0.0.0.0/0".parse().expect("constant CIDR"),
        "::/0".parse().expect("constant CIDR"),
    ]
}

impl Default for RoutePolicy {
    fn default() -> Self {
        RoutePolicy {
            include: default_routes(),
            exclude: Vec::new(),
        }
    }
}

impl RoutePolicy {
    /// Validate the raw wire shape before sorting and de-duplicating it.
    /// Counting before de-duplication also bounds work on repeated entries.
    pub fn normalize(&mut self) -> Result<(), String> {
        self.validate()?;
        self.include.sort();
        self.include.dedup();
        self.exclude.sort();
        self.exclude.dedup();
        Ok(())
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.include.len().saturating_add(self.exclude.len()) > MAX_EXIT_ROUTE_PREFIXES {
            return Err(format!(
                "an exit route policy may contain at most {MAX_EXIT_ROUTE_PREFIXES} prefixes"
            ));
        }
        for prefix in self.include.iter().chain(&self.exclude) {
            let width = if prefix.network.is_ipv4() { 32 } else { 128 };
            if prefix.bits > width {
                return Err(format!("{prefix} has a prefix longer than {width} bits"));
            }
            let canonical: IpPrefix = prefix.to_string().parse()?;
            if canonical != *prefix {
                return Err(format!("{prefix} is not a canonical network prefix"));
            }
        }
        Ok(())
    }

    pub fn permits(&self, destination: IpAddr, orbit_control: bool) -> bool {
        !orbit_control
            && self
                .include
                .iter()
                .any(|prefix| prefix.contains(destination))
            && !self
                .exclude
                .iter()
                .any(|prefix| prefix.contains(destination))
    }

    pub fn summary(&self) -> String {
        let include = self
            .include
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(",");
        if self.exclude.is_empty() {
            format!("routes {include}")
        } else {
            format!(
                "routes {include} except {}",
                self.exclude
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(",")
            )
        }
    }
}

/// Where guest DNS questions are resolved.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "mode", content = "servers")]
pub enum DnsPolicy {
    /// Resolve on the selected exit device. This is the default and prevents
    /// a remote exit's traffic from being paired with CPU-device DNS.
    #[default]
    ExitPoint,
    /// Explicitly keep DNS on the device supplying CPU/RAM.
    CpuDevice,
    /// Send virtual-DNS traffic through the selected exit to the first
    /// resolver. Additional entries are explicitly authorized for guests
    /// that address them directly on port 53; they are not automatic health
    /// failovers, so the first entry alone controls provider DNS health.
    Custom(Vec<IpAddr>),
}

impl DnsPolicy {
    pub fn normalize(&mut self) -> Result<(), String> {
        self.validate()?;
        if let DnsPolicy::Custom(servers) = self {
            let mut seen = BTreeSet::new();
            servers.retain(|server| seen.insert(*server));
        }
        Ok(())
    }

    pub fn validate(&self) -> Result<(), String> {
        if let DnsPolicy::Custom(servers) = self {
            if servers.is_empty() {
                return Err("custom DNS needs at least one resolver address".into());
            }
            if servers.len() > MAX_EXIT_DNS_SERVERS {
                return Err(format!(
                    "custom DNS may contain at most {MAX_EXIT_DNS_SERVERS} resolver addresses"
                ));
            }
        }
        Ok(())
    }
}

/// Validate the cross-field grant policy. A custom resolver is an explicit
/// private-destination exception on port 53, so it must also be inside the
/// attachment's route policy; otherwise a health probe would become a
/// provider-local resolver oracle for a destination traffic itself forbids.
pub fn validate_exit_policy(routes: &RoutePolicy, dns: &DnsPolicy) -> Result<(), String> {
    routes.validate()?;
    dns.validate()?;
    if let DnsPolicy::Custom(servers) = dns {
        for server in servers {
            if !routes.permits(*server, false) {
                return Err(format!(
                    "custom DNS resolver {server} is outside the authorized exit routes"
                ));
            }
        }
    }
    Ok(())
}

/// Immutable provider identity and the provider-issued generation fencing one
/// attachment. Names remain UI labels; neither authorization nor revocation
/// follows a later device that happens to reuse one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExitGrant {
    pub provider_device_id: String,
    pub generation: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExitProviderAction {
    Status,
    Enable,
    Disable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExitProviderStatus {
    pub enabled: bool,
    pub epoch: u64,
    pub grants: usize,
}

/// A durable network part attached to an instance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExitPoint {
    /// Ordered providers. The first is primary; later entries are explicit
    /// failovers. There is no implicit CPU-device fallback because that would
    /// turn a sleeping privacy exit into a route leak.
    pub providers: Vec<String>,
    #[serde(default)]
    pub routes: RoutePolicy,
    #[serde(default)]
    pub dns: DnsPolicy,
    /// Provider-issued, attachment-scoped grants keyed by display name. The
    /// value carries the immutable device id checked on every mesh flow.
    #[serde(default)]
    pub grants: BTreeMap<String, ExitGrant>,
    /// Runtime-only: populated on a status reply from current mesh
    /// observations, never by a registry row.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime: Option<PartRuntime>,
}

impl ExitPoint {
    pub fn new(
        primary: String,
        failover: Vec<String>,
        mut routes: RoutePolicy,
        mut dns: DnsPolicy,
    ) -> Result<Self, String> {
        routes.normalize()?;
        dns.normalize()?;
        let providers: Vec<String> = std::iter::once(primary).chain(failover).collect();
        let exit = ExitPoint {
            providers,
            routes,
            dns,
            grants: BTreeMap::new(),
            runtime: None,
        };
        exit.validate()?;
        Ok(exit)
    }

    /// Defend the persisted/wire shape as well as values built through
    /// [`ExitPoint::new`]. Serde fields are data, not an invariant boundary.
    pub fn validate(&self) -> Result<(), String> {
        let providers = &self.providers;
        if providers.is_empty() {
            return Err("an exit point needs at least one provider device".into());
        }
        if providers.len() > MAX_EXIT_PROVIDERS {
            return Err(format!(
                "an exit point may contain at most {MAX_EXIT_PROVIDERS} providers"
            ));
        }
        if providers.iter().any(|provider| provider.trim().is_empty()) {
            return Err("an exit-point device name cannot be empty".into());
        }
        for provider in providers {
            crate::orbit::check_name(provider).map_err(|error| format!("{error:#}"))?;
        }
        let unique: BTreeSet<&str> = providers.iter().map(String::as_str).collect();
        if unique.len() != providers.len() {
            return Err("an exit-point device may appear only once in its failover order".into());
        }
        validate_exit_policy(&self.routes, &self.dns)?;
        if self.grants.keys().any(|name| !providers.contains(name)) {
            return Err("an exit grant names a device outside the provider order".into());
        }
        Ok(())
    }

    pub fn primary(&self) -> &str {
        self.providers.first().map(String::as_str).unwrap_or("-")
    }

    /// Select the first healthy provider in the recorded order.
    ///
    /// DNS health gates a provider only when DNS belongs to that provider.
    /// With CPU-device DNS, the exit remains usable even if its resolver is
    /// unhealthy because it is not the resolver the policy chose.
    pub fn select<'a>(
        &'a self,
        cpu_device: &str,
        observations: &'a [ProviderObservation],
    ) -> Result<ExitSelection<'a>, ExitUnavailable> {
        for (position, provider) in self.providers.iter().enumerate() {
            let Some(observation) = observations.iter().find(|seen| seen.device == *provider)
            else {
                continue;
            };
            if observation.availability != Availability::Awake {
                continue;
            }
            let Some(path) = observation.path else {
                continue;
            };
            if matches!(self.dns, DnsPolicy::ExitPoint | DnsPolicy::Custom(_))
                && !observation.dns_healthy
            {
                continue;
            }
            let locality = if provider == cpu_device {
                Locality::Local
            } else {
                Locality::Remote
            };
            return Ok(ExitSelection {
                provider,
                path,
                locality,
                health: if position > 0 {
                    ExitHealth::Failover
                } else if path == PathKind::Relay {
                    ExitHealth::Degraded
                } else {
                    ExitHealth::Healthy
                },
            });
        }
        Err(ExitUnavailable {
            providers: self.providers.clone(),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Availability {
    Awake,
    Asleep,
    Unreachable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathKind {
    Local,
    Direct,
    Relay,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderObservation {
    pub device: String,
    pub availability: Availability,
    pub path: Option<PathKind>,
    pub dns_healthy: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Locality {
    Local,
    Remote,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitHealth {
    Healthy,
    Degraded,
    Failover,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExitSelection<'a> {
    pub provider: &'a str,
    pub path: PathKind,
    pub locality: Locality,
    pub health: ExitHealth,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExitUnavailable {
    pub providers: Vec<String>,
}

impl std::fmt::Display for ExitUnavailable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "no configured exit point is healthy (tried {}) — traffic remains closed",
            self.providers.join(", ")
        )
    }
}

impl std::error::Error for ExitUnavailable {}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(primary: &str, failover: &[&str]) -> ExitPoint {
        ExitPoint::new(
            primary.into(),
            failover.iter().map(|name| (*name).into()).collect(),
            RoutePolicy::default(),
            DnsPolicy::ExitPoint,
        )
        .unwrap()
    }

    fn seen(
        device: &str,
        availability: Availability,
        path: Option<PathKind>,
        dns_healthy: bool,
    ) -> ProviderObservation {
        ProviderObservation {
            device: device.into(),
            availability,
            path,
            dns_healthy,
        }
    }

    #[test]
    fn a_direct_remote_path_is_healthy_and_explicitly_remote() {
        let exit = policy("desktop", &[]);
        let observations = [seen(
            "desktop",
            Availability::Awake,
            Some(PathKind::Direct),
            true,
        )];
        let selected = exit.select("laptop", &observations).unwrap();
        assert_eq!(selected.path, PathKind::Direct);
        assert_eq!(selected.locality, Locality::Remote);
        assert_eq!(selected.health, ExitHealth::Healthy);
    }

    #[test]
    fn a_relay_path_remains_usable_but_reports_degraded_health() {
        let exit = policy("desktop", &[]);
        let observations = [seen(
            "desktop",
            Availability::Awake,
            Some(PathKind::Relay),
            true,
        )];
        let selected = exit.select("laptop", &observations).unwrap();
        assert_eq!(selected.path, PathKind::Relay);
        assert_eq!(selected.health, ExitHealth::Degraded);
    }

    #[test]
    fn route_exclusions_and_orbit_control_cannot_leak_into_the_exit() {
        let routes = RoutePolicy {
            include: vec!["0.0.0.0/0".parse().unwrap()],
            exclude: vec!["10.0.0.0/8".parse().unwrap()],
        };
        assert!(routes.permits("1.1.1.1".parse().unwrap(), false));
        assert!(!routes.permits("10.20.30.40".parse().unwrap(), false));
        assert!(!routes.permits("1.1.1.1".parse().unwrap(), true));
    }

    #[test]
    fn a_sleeping_provider_fails_closed_instead_of_using_the_cpu_uplink() {
        let exit = policy("desktop", &[]);
        let observations = [seen("desktop", Availability::Asleep, None, false)];
        let refusal = exit.select("laptop", &observations).unwrap_err();
        assert!(refusal.to_string().contains("traffic remains closed"));
    }

    #[test]
    fn an_explicit_second_provider_takes_over_without_changing_policy_order() {
        let exit = policy("desktop", &["phone"]);
        let observations = [
            seen("desktop", Availability::Asleep, None, false),
            seen("phone", Availability::Awake, Some(PathKind::Direct), true),
        ];
        let selected = exit.select("laptop", &observations).unwrap();
        assert_eq!(selected.provider, "phone");
        assert_eq!(selected.health, ExitHealth::Failover);
        assert_eq!(exit.providers, ["desktop", "phone"]);
    }

    #[test]
    fn exit_owned_dns_health_is_part_of_health_but_cpu_dns_is_not() {
        let observations = [seen(
            "desktop",
            Availability::Awake,
            Some(PathKind::Direct),
            false,
        )];
        assert!(policy("desktop", &[])
            .select("laptop", &observations)
            .is_err());

        let cpu_dns = ExitPoint::new(
            "desktop".into(),
            vec![],
            RoutePolicy::default(),
            DnsPolicy::CpuDevice,
        )
        .unwrap();
        assert!(cpu_dns.select("laptop", &observations).is_ok());
    }

    #[test]
    fn cidr_input_is_canonical_and_family_safe() {
        let prefix: IpPrefix = "10.9.8.7/16".parse().unwrap();
        assert_eq!(prefix.to_string(), "10.9.0.0/16");
        assert!(prefix.contains("10.9.255.1".parse().unwrap()));
        assert!(!prefix.contains("10.10.0.1".parse().unwrap()));
        assert!(!prefix.contains("::1".parse().unwrap()));
    }

    #[test]
    fn provider_sockets_reject_private_and_ipv4_mapped_private_addresses() {
        assert!(is_public_unicast("1.1.1.1".parse().unwrap()));
        assert!(!is_public_unicast("127.0.0.1".parse().unwrap()));
        assert!(!is_public_unicast("10.0.0.1".parse().unwrap()));
        assert!(!is_public_unicast("192.0.2.1".parse().unwrap()));
        assert!(!is_public_unicast("240.0.0.1".parse().unwrap()));
        assert!(!is_public_unicast("2001:db8::1".parse().unwrap()));
        assert!(!is_public_unicast("::ffff:127.0.0.1".parse().unwrap()));
        assert!(!is_public_unicast("::ffff:10.0.0.1".parse().unwrap()));
    }

    #[test]
    fn exit_policy_bounds_raw_vectors_before_deduplicating_them() {
        let duplicate: IpPrefix = "1.1.1.0/24".parse().unwrap();
        let mut routes = RoutePolicy {
            include: vec![duplicate; MAX_EXIT_ROUTE_PREFIXES + 1],
            exclude: Vec::new(),
        };
        assert!(routes.normalize().is_err());

        routes.include.truncate(MAX_EXIT_ROUTE_PREFIXES);
        routes.normalize().unwrap();
        assert_eq!(routes.include, [duplicate]);

        let mut dns = DnsPolicy::Custom(vec!["1.1.1.1".parse().unwrap(); MAX_EXIT_DNS_SERVERS + 1]);
        assert!(dns.normalize().is_err());

        let first: IpAddr = "8.8.8.8".parse().unwrap();
        let second: IpAddr = "1.1.1.1".parse().unwrap();
        let mut ordered = DnsPolicy::Custom(vec![first, second, first]);
        ordered.normalize().unwrap();
        assert_eq!(ordered, DnsPolicy::Custom(vec![first, second]));
    }

    #[test]
    fn exit_policy_rejects_noncanonical_wire_prefixes() {
        let mut routes = RoutePolicy {
            include: vec![IpPrefix {
                network: "10.9.8.7".parse().unwrap(),
                bits: 16,
            }],
            exclude: Vec::new(),
        };
        let error = routes.normalize().unwrap_err();
        assert!(error.contains("not a canonical network prefix"), "{error}");
    }

    #[test]
    fn custom_dns_must_also_be_inside_the_authorized_routes() {
        let error = ExitPoint::new(
            "desktop".into(),
            Vec::new(),
            RoutePolicy {
                include: vec!["1.1.1.0/24".parse().unwrap()],
                exclude: Vec::new(),
            },
            DnsPolicy::Custom(vec!["10.0.0.53".parse().unwrap()]),
        )
        .unwrap_err();
        assert!(
            error.contains("outside the authorized exit routes"),
            "{error}"
        );
    }
}
