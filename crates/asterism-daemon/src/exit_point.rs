//! Live health for the network exit-point part.
//!
//! Durable policy lives in `asterism_core::network`; this module contributes
//! only current mesh observations to `ast status`. The registry is never
//! mutated with them, matching the remote-volume health seam.

use std::collections::HashMap;
use std::sync::{Arc, OnceLock};

use asterism_core::instance::{now_unix, Instance, PartRuntime};
use asterism_core::network::{Availability, ExitHealth, PathKind, ProviderObservation};
use asterism_mesh::PathKind as MeshPathKind;

use crate::mesh::Mesh;

static MESH: OnceLock<Option<Arc<Mesh>>> = OnceLock::new();

pub(crate) fn init(mesh: Option<Arc<Mesh>>) {
    let _ = MESH.set(mesh);
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
}
