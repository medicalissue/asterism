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
    is_public_unicast, DnsPolicy, ExitGrant, ExitProviderStatus, RoutePolicy, GUEST_DNS,
};
use serde::{Deserialize, Serialize};
use tokio::sync::watch;

const POLICY_VERSION: u32 = 1;
const MAX_GRANTS: usize = 4096;
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
        let (policy, unavailable) = match std::fs::read(path) {
            Ok(bytes) => match serde_json::from_slice::<PolicyFile>(&bytes) {
                Ok(policy) if policy.version == POLICY_VERSION => (policy, None),
                Ok(policy) => (
                    PolicyFile::default(),
                    Some(format!(
                        "{} is exit-provider policy version {}, but this daemon reads {}",
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
            },
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                (PolicyFile::default(), None)
            }
            Err(error) => (
                PolicyFile::default(),
                Some(format!("{} cannot be read ({error})", path.display())),
            ),
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
        let mut state = self.state.lock().expect("exit-provider policy poisoned");
        if let Some(reason) = &state.unavailable {
            bail!(reason.clone());
        }
        let mut next = state.policy.clone();
        next.enabled = true;
        next.epoch = next.epoch.saturating_add(1);
        next.allowed_device_ids = allowed_device_ids;
        next.grants.clear();
        durable::commit_json_private(&self.path, &next)
            .context("committing exit-provider policy")?;
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
        durable::commit_json_private(&self.path, &next)
            .context("committing disabled exit-provider policy")?;
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
        routes: RoutePolicy,
        dns: DnsPolicy,
    ) -> Result<ExitGrant> {
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
        validate_id("consumer device", consumer_device_id)?;
        validate_id("instance", instance_id)?;
        if let Some(existing) = state.policy.grants.values().find(|grant| {
            grant.consumer_device_id == consumer_device_id
                && grant.instance_id == instance_id
                && grant.routes == routes
                && grant.dns == dns
        }) {
            return Ok(ExitGrant {
                provider_device_id,
                generation: existing.generation,
            });
        }
        if state.policy.grants.len() >= MAX_GRANTS {
            bail!("exit provider grant table is at its bounded capacity");
        }
        let generation = state.policy.next_generation;
        let key = grant_key(consumer_device_id, instance_id, generation);
        let mut next = state.policy.clone();
        next.next_generation = next.next_generation.saturating_add(1);
        next.grants.insert(
            key.clone(),
            GrantRecord {
                consumer_device_id: consumer_device_id.to_owned(),
                instance_id: instance_id.to_owned(),
                generation,
                granted_at: now_unix(),
                routes,
                dns,
                active: false,
            },
        );
        durable::commit_json_private(&self.path, &next).context("committing exit grant")?;
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
        durable::commit_json_private(&self.path, &next).context("activating exit grant")?;
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
        durable::commit_json_private(&self.path, &next).context("revoking exit grant")?;
        state.policy = next;
        revoke_active(&mut state, Some(&key));
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
        durable::commit_json_private(&self.path, &next)
            .context("revoking removed device's exit authority")?;
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
        || value.chars().any(|character| character.is_control())
    {
        bail!("invalid {kind} id in exit grant");
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
}
