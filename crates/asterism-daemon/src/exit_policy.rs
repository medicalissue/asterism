//! Provider-local consent and attachment-scoped exit grants.
//!
//! Orbit membership authenticates a device, but it does not authorize that
//! device to turn every other member into an outbound proxy. This policy is
//! disabled by default, snapshots immutable peer ids when enabled, persists
//! every grant, and provides a revocation signal held by each live flow.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, Weak};

use anyhow::{bail, Context, Result};
use asterism_core::durable;
use asterism_core::instance::now_unix;
use asterism_core::network::{
    is_public_unicast, validate_exit_policy, DnsPolicy, ExitGrant, ExitProviderStatus, RoutePolicy,
    GUEST_DNS,
};
use serde::{Deserialize, Serialize};
use tokio::sync::watch;

const POLICY_VERSION: u32 = 1;
const MAX_GRANTS: usize = 4096;
const MAX_GRANTS_PER_CONSUMER: usize = 256;
const MAX_ALLOWED_DEVICE_IDS: usize = 4096;
const MAX_GRANT_POLICY_BYTES: usize = 16 * 1024;
const MAX_POLICY_FILE_BYTES: usize = 16 * 1024 * 1024;
const PENDING_GRANT_TTL_SECS: u64 = 10 * 60;
const MAX_ID_BYTES: usize = 256;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct GrantRecord {
    consumer_device_id: String,
    instance_id: String,
    generation: u64,
    granted_at: u64,
    routes: RoutePolicy,
    dns: DnsPolicy,
    active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PolicyFile {
    version: u32,
    enabled: bool,
    epoch: u64,
    next_generation: u64,
    #[serde(default)]
    allowed_device_ids: Vec<String>,
    #[serde(default)]
    grants: BTreeMap<String, GrantRecord>,
}

impl Default for PolicyFile {
    fn default() -> Self {
        Self {
            version: POLICY_VERSION,
            enabled: false,
            epoch: 0,
            next_generation: 1,
            allowed_device_ids: Vec::new(),
            grants: BTreeMap::new(),
        }
    }
}

impl PolicyFile {
    fn policy_grant(
        &self,
        consumer_device_id: &str,
        instance_id: &str,
        routes: &RoutePolicy,
        dns: &DnsPolicy,
    ) -> Option<&GrantRecord> {
        self.grants.values().find(|grant| {
            grant.consumer_device_id == consumer_device_id
                && grant.instance_id == instance_id
                && grant.routes == *routes
                && grant.dns == *dns
        })
    }
}

struct ActiveFlow {
    grant_key: String,
    revoke: watch::Sender<bool>,
}

struct State {
    policy: PolicyFile,
    unavailable: Option<String>,
    next_flow_id: u64,
    active: HashMap<u64, ActiveFlow>,
}

pub(crate) struct Manager {
    path: PathBuf,
    state: Mutex<State>,
}

impl Manager {
    pub(crate) fn load() -> Arc<Self> {
        Self::load_at(&asterism_core::paths::exit_provider_policy_path())
    }

    pub(crate) fn load_at(path: &Path) -> Arc<Self> {
        let oversized = std::fs::metadata(path)
            .ok()
            .is_some_and(|metadata| metadata.len() > MAX_POLICY_FILE_BYTES as u64);
        let (policy, unavailable) = if oversized {
            (
                PolicyFile::default(),
                Some(format!(
                    "{} exceeds the {MAX_POLICY_FILE_BYTES}-byte exit-provider policy limit",
                    path.display()
                )),
            )
        } else {
            match std::fs::read(path) {
                Ok(bytes) if bytes.len() > MAX_POLICY_FILE_BYTES => (
                    PolicyFile::default(),
                    Some(format!(
                        "{} exceeds the {MAX_POLICY_FILE_BYTES}-byte exit-provider policy limit",
                        path.display()
                    )),
                ),
                Ok(bytes) => {
                    match serde_json::from_slice::<PolicyFile>(&bytes) {
                        Ok(policy)
                            if policy.version == POLICY_VERSION
                                && validate_policy_file(&policy).is_ok() =>
                        {
                            (policy, None)
                        }
                        Ok(policy) => (
                            PolicyFile::default(),
                            Some(format!(
                                "{} has an unsupported or unsafe exit-provider policy (version {}, reader {})",
                                path.display(),
                                policy.version,
                                POLICY_VERSION
                            )),
                        ),
                        Err(error) => (
                            PolicyFile::default(),
                            Some(format!(
                                "{} is not readable as exit-provider policy ({error})",
                                path.display()
                            )),
                        ),
                    }
                },
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    (PolicyFile::default(), None)
                }
                Err(error) => (
                    PolicyFile::default(),
                    Some(format!("{} cannot be read ({error})", path.display())),
                ),
            }
        };
        Arc::new(Self {
            path: path.to_path_buf(),
            state: Mutex::new(State {
                policy,
                unavailable,
                next_flow_id: 1,
                active: HashMap::new(),
            }),
        })
    }

    pub(crate) fn status(&self) -> ExitProviderStatus {
        let state = self.state.lock().expect("exit-provider policy poisoned");
        ExitProviderStatus {
            enabled: state.unavailable.is_none() && state.policy.enabled,
            epoch: state.policy.epoch,
            grants: state.policy.grants.len(),
        }
    }

    pub(crate) fn enable(&self, mut allowed_device_ids: Vec<String>) -> Result<ExitProviderStatus> {
        allowed_device_ids.sort();
        allowed_device_ids.dedup();
        if allowed_device_ids.len() > MAX_ALLOWED_DEVICE_IDS {
            bail!("exit provider allowlist is at its bounded capacity");
        }
        for id in &allowed_device_ids {
            validate_id("allowed device", id)?;
        }
        let mut state = self.state.lock().expect("exit-provider policy poisoned");
        if let Some(reason) = &state.unavailable {
            bail!(reason.clone());
        }
        let mut next = state.policy.clone();
        next.enabled = true;
        next.epoch = next.epoch.saturating_add(1);
        next.allowed_device_ids = allowed_device_ids;
        next.grants.clear();
        commit_policy(&self.path, &next).context("committing exit-provider policy")?;
        state.policy = next;
        revoke_active(&mut state, None);
        drop(state);
        Ok(self.status())
    }

    pub(crate) fn disable(&self) -> Result<ExitProviderStatus> {
        let mut state = self.state.lock().expect("exit-provider policy poisoned");
        let mut next = state.policy.clone();
        next.enabled = false;
        next.epoch = next.epoch.saturating_add(1);
        next.allowed_device_ids.clear();
        next.grants.clear();
        commit_policy(&self.path, &next).context("committing disabled exit-provider policy")?;
        state.policy = next;
        revoke_active(&mut state, None);
        drop(state);
        Ok(self.status())
    }

    pub(crate) fn grant(
        &self,
        consumer_device_id: &str,
        instance_id: &str,
        provider_device_id: String,
        mut routes: RoutePolicy,
        mut dns: DnsPolicy,
    ) -> Result<ExitGrant> {
        validate_id("consumer device", consumer_device_id)?;
        validate_id("instance", instance_id)?;
        validate_id("provider device", &provider_device_id)?;
        routes.normalize().map_err(anyhow::Error::msg)?;
        dns.normalize().map_err(anyhow::Error::msg)?;
        validate_grant_policy(&routes, &dns)?;

        let mut state = self.state.lock().expect("exit-provider policy poisoned");
        if let Some(reason) = &state.unavailable {
            bail!(reason.clone());
        }
        if !state.policy.enabled {
            bail!("exit service is disabled on the provider — run `ast device exit enable` there");
        }
        if !state
            .policy
            .allowed_device_ids
            .iter()
            .any(|id| id == consumer_device_id)
        {
            bail!("this consumer device was not approved by the provider's current exit policy");
        }
        let now = now_unix();
        let mut next = state.policy.clone();
        next.grants.retain(|_, grant| {
            grant.active || now.saturating_sub(grant.granted_at) <= PENDING_GRANT_TTL_SECS
        });
        if let Some(existing) = next.policy_grant(consumer_device_id, instance_id, &routes, &dns) {
            let generation = existing.generation;
            if next.grants.len() != state.policy.grants.len() {
                commit_policy(&self.path, &next).context("pruning expired pending exit grants")?;
                state.policy = next;
            }
            return Ok(ExitGrant {
                provider_device_id,
                generation,
            });
        }

        // One active and at most one pending generation may coexist for an
        // attachment. A new intent atomically replaces an older pending one;
        // the active generation remains authoritative until activation.
        next.grants.retain(|_, grant| {
            grant.active
                || grant.consumer_device_id != consumer_device_id
                || grant.instance_id != instance_id
        });
        let consumer_grants = next
            .grants
            .values()
            .filter(|grant| grant.consumer_device_id == consumer_device_id)
            .count();
        if consumer_grants >= MAX_GRANTS_PER_CONSUMER {
            bail!("this consumer's exit grant table is at its bounded capacity");
        }
        if next.grants.len() >= MAX_GRANTS {
            bail!("exit provider grant table is at its bounded capacity");
        }
        let generation = next.next_generation;
        if generation == u64::MAX {
            bail!("exit provider generation space is exhausted");
        }
        let key = grant_key(consumer_device_id, instance_id, generation);
        next.next_generation += 1;
        next.grants.insert(
            key,
            GrantRecord {
                consumer_device_id: consumer_device_id.to_owned(),
                instance_id: instance_id.to_owned(),
                generation,
                granted_at: now,
                routes,
                dns,
                active: false,
            },
        );
        commit_policy(&self.path, &next).context("committing exit grant")?;
        state.policy = next;
        Ok(ExitGrant {
            provider_device_id,
            generation,
        })
    }

    pub(crate) fn activate(
        &self,
        consumer_device_id: &str,
        instance_id: &str,
        generation: u64,
    ) -> Result<()> {
        let key = grant_key(consumer_device_id, instance_id, generation);
        let mut state = self.state.lock().expect("exit-provider policy poisoned");
        let Some(record) = state.policy.grants.get(&key) else {
            bail!("no pending exit grant to activate");
        };
        if record.active {
            return Ok(());
        }
        let mut next = state.policy.clone();
        next.grants.get_mut(&key).expect("grant was present").active = true;
        let superseded: Vec<String> = next
            .grants
            .iter()
            .filter(|(other_key, grant)| {
                *other_key != &key
                    && grant.consumer_device_id == consumer_device_id
                    && grant.instance_id == instance_id
            })
            .map(|(key, _)| key.clone())
            .collect();
        for old in &superseded {
            next.grants.remove(old);
        }
        commit_policy(&self.path, &next).context("activating exit grant")?;
        state.policy = next;
        for old in superseded {
            revoke_active(&mut state, Some(&old));
        }
        Ok(())
    }

    pub(crate) fn revoke(
        &self,
        consumer_device_id: &str,
        instance_id: &str,
        generation: u64,
    ) -> Result<()> {
        let key = grant_key(consumer_device_id, instance_id, generation);
        let mut state = self.state.lock().expect("exit-provider policy poisoned");
        if !state.policy.grants.contains_key(&key) {
            return Ok(());
        }
        let mut next = state.policy.clone();
        next.grants.remove(&key);
        commit_policy(&self.path, &next).context("revoking exit grant")?;
        state.policy = next;
        revoke_active(&mut state, Some(&key));
        Ok(())
    }

    pub(crate) fn discard_pending(
        &self,
        consumer_device_id: &str,
        instance_id: &str,
    ) -> Result<()> {
        validate_id("consumer device", consumer_device_id)?;
        validate_id("instance", instance_id)?;
        let mut state = self.state.lock().expect("exit-provider policy poisoned");
        let mut next = state.policy.clone();
        next.grants.retain(|_, grant| {
            grant.active
                || grant.consumer_device_id != consumer_device_id
                || grant.instance_id != instance_id
        });
        if next.grants.len() == state.policy.grants.len() {
            return Ok(());
        }
        commit_policy(&self.path, &next).context("discarding pending exit grants")?;
        state.policy = next;
        Ok(())
    }

    pub(crate) fn authorize(
        self: &Arc<Self>,
        consumer_device_id: &str,
        instance_id: &str,
        generation: u64,
    ) -> Result<FlowLease> {
        let key = grant_key(consumer_device_id, instance_id, generation);
        let mut state = self.state.lock().expect("exit-provider policy poisoned");
        if !state.policy.enabled {
            bail!("exit service is disabled on the provider");
        }
        let Some(grant) = state.policy.grants.get(&key) else {
            bail!("no attachment-scoped exit grant for this instance and consumer");
        };
        if grant.consumer_device_id != consumer_device_id || grant.instance_id != instance_id {
            bail!("exit grant identity or generation mismatch");
        }
        if !grant.active {
            bail!("exit grant is pending consumer registry commit");
        }
        let routes = grant.routes.clone();
        let dns = grant.dns.clone();
        let id = state.next_flow_id;
        state.next_flow_id = state.next_flow_id.saturating_add(1);
        let (revoke, revoked) = watch::channel(false);
        state.active.insert(
            id,
            ActiveFlow {
                grant_key: key,
                revoke,
            },
        );
        Ok(FlowLease {
            id,
            revoked,
            routes,
            dns,
            manager: Arc::downgrade(self),
        })
    }

    pub(crate) fn revoke_peer(&self, consumer_device_id: &str) -> Result<usize> {
        let mut state = self.state.lock().expect("exit-provider policy poisoned");
        let removed: Vec<String> = state
            .policy
            .grants
            .iter()
            .filter(|(_, grant)| grant.consumer_device_id == consumer_device_id)
            .map(|(key, _)| key.clone())
            .collect();
        let mut next = state.policy.clone();
        next.allowed_device_ids
            .retain(|id| id != consumer_device_id);
        for key in &removed {
            next.grants.remove(key);
        }
        commit_policy(&self.path, &next).context("revoking removed device's exit authority")?;
        state.policy = next;
        for key in &removed {
            revoke_active(&mut state, Some(key));
        }
        Ok(removed.len())
    }
}

fn grant_key(consumer_device_id: &str, instance_id: &str, generation: u64) -> String {
    format!("{consumer_device_id}:{instance_id}:{generation}")
}

fn validate_id(kind: &str, value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > MAX_ID_BYTES
        || value.contains(':')
        || value.chars().any(|character| character.is_control())
    {
        bail!("invalid {kind} id in exit grant");
    }
    Ok(())
}

fn validate_grant_policy(routes: &RoutePolicy, dns: &DnsPolicy) -> Result<()> {
    validate_exit_policy(routes, dns).map_err(anyhow::Error::msg)?;
    let bytes = serde_json::to_vec(&(routes, dns)).context("serializing exit grant policy")?;
    if bytes.len() > MAX_GRANT_POLICY_BYTES {
        bail!("serialized exit grant policy exceeds {MAX_GRANT_POLICY_BYTES} bytes");
    }
    Ok(())
}

fn commit_policy(path: &Path, policy: &PolicyFile) -> Result<()> {
    validate_policy_file(policy)?;
    let bytes = serde_json::to_vec_pretty(policy).context("measuring exit-provider policy")?;
    if bytes.len() > MAX_POLICY_FILE_BYTES {
        bail!("exit-provider policy exceeds {MAX_POLICY_FILE_BYTES} serialized bytes");
    }
    durable::commit_json_private(path, policy)
}

fn validate_policy_file(policy: &PolicyFile) -> Result<()> {
    if policy.next_generation == 0
        || policy
            .grants
            .values()
            .any(|grant| grant.generation >= policy.next_generation)
    {
        bail!("exit-provider generation counter is not ahead of every durable grant");
    }
    if policy.allowed_device_ids.len() > MAX_ALLOWED_DEVICE_IDS {
        bail!("exit-provider allowlist exceeds its bounded capacity");
    }
    if policy.grants.len() > MAX_GRANTS {
        bail!("exit-provider grant table exceeds its bounded capacity");
    }
    for id in &policy.allowed_device_ids {
        validate_id("allowed device", id)?;
    }

    let mut by_consumer = HashMap::<&str, usize>::new();
    let mut by_scope = HashMap::<(&str, &str), (usize, usize)>::new();
    for (key, grant) in &policy.grants {
        validate_id("consumer device", &grant.consumer_device_id)?;
        validate_id("instance", &grant.instance_id)?;
        if key
            != &grant_key(
                &grant.consumer_device_id,
                &grant.instance_id,
                grant.generation,
            )
        {
            bail!("exit-provider grant key does not match its durable identity");
        }
        validate_grant_policy(&grant.routes, &grant.dns)?;
        *by_consumer
            .entry(grant.consumer_device_id.as_str())
            .or_default() += 1;
        let scope = by_scope
            .entry((
                grant.consumer_device_id.as_str(),
                grant.instance_id.as_str(),
            ))
            .or_default();
        if grant.active {
            scope.0 += 1;
        } else {
            scope.1 += 1;
        }
    }
    if by_consumer
        .values()
        .any(|count| *count > MAX_GRANTS_PER_CONSUMER)
    {
        bail!("one consumer exceeds its exit-provider grant capacity");
    }
    if by_scope
        .values()
        .any(|(active, pending)| *active > 1 || *pending > 1)
    {
        bail!("one attachment has multiple active or pending exit grants");
    }
    Ok(())
}

fn revoke_active(state: &mut State, only: Option<&str>) {
    state.active.retain(|_, flow| {
        if only.is_none_or(|key| key == flow.grant_key) {
            let _ = flow.revoke.send(true);
            false
        } else {
            true
        }
    });
}

pub(crate) struct FlowLease {
    id: u64,
    pub(crate) revoked: watch::Receiver<bool>,
    routes: RoutePolicy,
    dns: DnsPolicy,
    manager: Weak<Manager>,
}

impl FlowLease {
    pub(crate) fn allows(&self, destination: std::net::SocketAddr, system_dns: bool) -> bool {
        if system_dns {
            return destination.ip() == GUEST_DNS
                && destination.port() == 53
                && matches!(self.dns, DnsPolicy::ExitPoint);
        }
        if destination.port() == 53
            && matches!(&self.dns, DnsPolicy::Custom(servers) if servers.contains(&destination.ip()))
        {
            return self.routes.permits(destination.ip(), false);
        }
        is_public_unicast(destination.ip()) && self.routes.permits(destination.ip(), false)
    }

    pub(crate) fn resolver(&self) -> Option<std::net::IpAddr> {
        match &self.dns {
            // Custom DNS semantics are intentionally first-authoritative:
            // virtual DNS and provider health use this address. Remaining
            // grant-bound entries are allowed only when the guest addresses
            // them directly on port 53; they are not implicit failovers.
            DnsPolicy::Custom(servers) => servers.first().copied(),
            _ => None,
        }
    }
}

impl Drop for FlowLease {
    fn drop(&mut self) {
        if let Some(manager) = self.manager.upgrade() {
            manager
                .state
                .lock()
                .expect("exit-provider policy poisoned")
                .active
                .remove(&self.id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oversized_durable_policy_is_rejected_before_reading_or_parsing_it() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("exit.json");
        let file = std::fs::File::create(&path).unwrap();
        file.set_len(MAX_POLICY_FILE_BYTES as u64 + 1).unwrap();
        let manager = Manager::load_at(&path);
        assert!(!manager.status().enabled);
        let error = manager.enable(vec!["consumer-id".into()]).unwrap_err();
        assert!(error.to_string().contains("exceeds"), "{error:#}");
    }

    #[test]
    fn disabled_by_default_and_revocation_aborts_live_flows() {
        let dir = tempfile::tempdir().unwrap();
        let manager = Manager::load_at(&dir.path().join("exit.json"));
        assert!(!manager.status().enabled);
        manager.enable(vec!["consumer-id".into()]).unwrap();
        let grant = manager
            .grant(
                "consumer-id",
                "instance-id",
                "provider-id".into(),
                RoutePolicy::default(),
                DnsPolicy::ExitPoint,
            )
            .unwrap();
        assert!(manager
            .authorize("consumer-id", "instance-id", grant.generation)
            .is_err());
        manager
            .activate("consumer-id", "instance-id", grant.generation)
            .unwrap();
        let lease = manager
            .authorize("consumer-id", "instance-id", grant.generation)
            .unwrap();
        assert!(lease.allows("100.64.0.53:53".parse().unwrap(), true));
        assert!(!lease.allows("100.64.0.53:80".parse().unwrap(), true));
        manager
            .revoke("consumer-id", "instance-id", grant.generation)
            .unwrap();
        assert!(*lease.revoked.borrow());
        assert!(manager
            .authorize("consumer-id", "instance-id", grant.generation)
            .is_err());
    }

    #[test]
    fn pending_reconfiguration_keeps_the_old_active_generation_until_activation() {
        let dir = tempfile::tempdir().unwrap();
        let manager = Manager::load_at(&dir.path().join("exit.json"));
        manager.enable(vec!["consumer-id".into()]).unwrap();
        let first = manager
            .grant(
                "consumer-id",
                "instance-id",
                "provider-id".into(),
                RoutePolicy::default(),
                DnsPolicy::ExitPoint,
            )
            .unwrap();
        manager
            .activate("consumer-id", "instance-id", first.generation)
            .unwrap();
        let old_lease = manager
            .authorize("consumer-id", "instance-id", first.generation)
            .unwrap();

        let routes = RoutePolicy {
            include: vec![
                "1.1.1.0/24".parse().unwrap(),
                "10.0.0.53/32".parse().unwrap(),
            ],
            exclude: Vec::new(),
        };
        let pending = manager
            .grant(
                "consumer-id",
                "instance-id",
                "provider-id".into(),
                routes,
                DnsPolicy::Custom(vec!["10.0.0.53".parse().unwrap()]),
            )
            .unwrap();
        assert_ne!(first.generation, pending.generation);
        assert!(manager
            .authorize("consumer-id", "instance-id", first.generation)
            .is_ok());
        assert!(manager
            .authorize("consumer-id", "instance-id", pending.generation)
            .is_err());

        manager
            .activate("consumer-id", "instance-id", pending.generation)
            .unwrap();
        assert!(*old_lease.revoked.borrow());
        let new_lease = manager
            .authorize("consumer-id", "instance-id", pending.generation)
            .unwrap();
        assert!(new_lease.allows("10.0.0.53:53".parse().unwrap(), false));
        assert!(!new_lease.allows("10.0.0.53:80".parse().unwrap(), false));
        assert!(new_lease.allows("1.1.1.1:443".parse().unwrap(), false));
        assert!(!new_lease.allows("1.0.0.1:443".parse().unwrap(), false));
        assert!(!new_lease.allows("100.64.0.53:53".parse().unwrap(), true));
    }

    #[test]
    fn raw_provider_grants_reject_oversized_and_noncanonical_policies() {
        let dir = tempfile::tempdir().unwrap();
        let manager = Manager::load_at(&dir.path().join("exit.json"));
        manager.enable(vec!["consumer-id".into()]).unwrap();
        let prefix = "1.1.1.0/24".parse().unwrap();
        let oversized = RoutePolicy {
            include: vec![prefix; asterism_core::network::MAX_EXIT_ROUTE_PREFIXES + 1],
            exclude: Vec::new(),
        };
        assert!(manager
            .grant(
                "consumer-id",
                "oversized-routes",
                "provider-id".into(),
                oversized,
                DnsPolicy::ExitPoint,
            )
            .is_err());

        let noncanonical = RoutePolicy {
            include: vec![asterism_core::network::IpPrefix {
                network: "10.9.8.7".parse().unwrap(),
                bits: 16,
            }],
            exclude: Vec::new(),
        };
        assert!(manager
            .grant(
                "consumer-id",
                "noncanonical",
                "provider-id".into(),
                noncanonical,
                DnsPolicy::ExitPoint,
            )
            .is_err());

        let too_many_dns = DnsPolicy::Custom(vec![
            "1.1.1.1".parse().unwrap();
            asterism_core::network::MAX_EXIT_DNS_SERVERS + 1
        ]);
        assert!(manager
            .grant(
                "consumer-id",
                "oversized-dns",
                "provider-id".into(),
                RoutePolicy::default(),
                too_many_dns,
            )
            .is_err());
        assert!(manager
            .grant(
                "consumer-id",
                "resolver-outside-routes",
                "provider-id".into(),
                RoutePolicy {
                    include: vec!["1.1.1.0/24".parse().unwrap()],
                    exclude: Vec::new(),
                },
                DnsPolicy::Custom(vec!["10.0.0.53".parse().unwrap()]),
            )
            .is_err());
        assert_eq!(manager.status().grants, 0);
    }

    #[test]
    fn provider_deduplicates_wire_policy_and_bounds_pending_per_instance() {
        let dir = tempfile::tempdir().unwrap();
        let manager = Manager::load_at(&dir.path().join("exit.json"));
        manager.enable(vec!["consumer-id".into()]).unwrap();
        let prefix = "1.1.1.0/24".parse().unwrap();
        let duplicate = manager
            .grant(
                "consumer-id",
                "instance-id",
                "provider-id".into(),
                RoutePolicy {
                    include: vec![prefix, prefix],
                    exclude: Vec::new(),
                },
                DnsPolicy::ExitPoint,
            )
            .unwrap();
        let normalized = manager
            .grant(
                "consumer-id",
                "instance-id",
                "provider-id".into(),
                RoutePolicy {
                    include: vec![prefix],
                    exclude: Vec::new(),
                },
                DnsPolicy::ExitPoint,
            )
            .unwrap();
        assert_eq!(duplicate.generation, normalized.generation);
        manager
            .activate("consumer-id", "instance-id", normalized.generation)
            .unwrap();

        for octet in 2..8 {
            let pending = manager
                .grant(
                    "consumer-id",
                    "instance-id",
                    "provider-id".into(),
                    RoutePolicy {
                        include: vec![format!("1.1.{octet}.0/24").parse().unwrap()],
                        exclude: Vec::new(),
                    },
                    DnsPolicy::ExitPoint,
                )
                .unwrap();
            assert_ne!(pending.generation, normalized.generation);
            assert_eq!(manager.status().grants, 2);
        }
    }

    #[test]
    fn scope_cleanup_discards_pending_without_touching_active_authority() {
        let dir = tempfile::tempdir().unwrap();
        let manager = Manager::load_at(&dir.path().join("exit.json"));
        manager.enable(vec!["consumer-id".into()]).unwrap();
        let active = manager
            .grant(
                "consumer-id",
                "instance-id",
                "provider-id".into(),
                RoutePolicy::default(),
                DnsPolicy::ExitPoint,
            )
            .unwrap();
        manager
            .activate("consumer-id", "instance-id", active.generation)
            .unwrap();
        let pending = manager
            .grant(
                "consumer-id",
                "instance-id",
                "provider-id".into(),
                RoutePolicy {
                    include: vec!["1.1.1.0/24".parse().unwrap()],
                    exclude: Vec::new(),
                },
                DnsPolicy::ExitPoint,
            )
            .unwrap();
        assert_eq!(manager.status().grants, 2);
        manager
            .discard_pending("consumer-id", "instance-id")
            .unwrap();
        assert_eq!(manager.status().grants, 1);
        assert!(manager
            .authorize("consumer-id", "instance-id", active.generation)
            .is_ok());
        assert!(manager
            .authorize("consumer-id", "instance-id", pending.generation)
            .is_err());
    }

    #[test]
    fn expired_pending_grants_are_pruned_before_new_persistence() {
        let dir = tempfile::tempdir().unwrap();
        let manager = Manager::load_at(&dir.path().join("exit.json"));
        manager.enable(vec!["consumer-id".into()]).unwrap();
        let expired = manager
            .grant(
                "consumer-id",
                "expired-instance",
                "provider-id".into(),
                RoutePolicy::default(),
                DnsPolicy::ExitPoint,
            )
            .unwrap();
        {
            let mut state = manager.state.lock().unwrap();
            state.policy.grants.values_mut().next().unwrap().granted_at = 0;
        }
        manager
            .grant(
                "consumer-id",
                "new-instance",
                "provider-id".into(),
                RoutePolicy::default(),
                DnsPolicy::ExitPoint,
            )
            .unwrap();
        assert_eq!(manager.status().grants, 1);
        assert!(manager
            .authorize("consumer-id", "expired-instance", expired.generation)
            .is_err());
    }
}
