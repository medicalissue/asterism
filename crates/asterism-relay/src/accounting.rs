//! Relay-side accounting: who connected, how often, and how many are on now.
//!
//! # What a relay can and cannot count
//!
//! The relay's own byte counters — `relayserver_bytes_sent` and
//! `relayserver_bytes_recv`, which iroh-relay 1.0.3 maintains and this binary
//! serves unchanged — are **process-global**. iroh-relay's public API exposes
//! no per-client byte counter and no hook on the forwarding path where one
//! could be kept, so a per-key byte figure is not something this process can
//! produce today without forking the crate, which AST-119 decided against.
//!
//! What it can produce is the connection lifecycle, because
//! [`AccessControl`](iroh_relay::server::AccessControl) is called with the
//! client's proven endpoint id on every connect and every disconnect. That is
//! what this module counts.
//!
//! # So where does the billing figure come from
//!
//! The device. `asterism-daemon`'s relay meter reads QUIC's own per-path byte
//! counters and knows, per peer, exactly how much went over a relay. The relay
//! is the *corroborating* meter, not the primary one: its global byte totals
//! should agree with the sum of what the devices report, and
//! `scripts/e2e-relay.sh` asserts they agree within ±5%. Two independent
//! meters that agree is a stronger claim than one meter nobody can check.
//!
//! # Label cardinality
//!
//! Per-client metrics carry the device's public key as a Prometheus label, and
//! a public relay meets an unbounded number of them. An unbounded label set is
//! how a metrics endpoint turns into an outage. So they are off by default and
//! capped when on: past the cap, new keys are counted in the aggregate and not
//! given a label of their own, and `astrelay_clients_untracked` says how often
//! that happened rather than letting the cap hide.

use std::{
    borrow::Cow,
    collections::HashSet,
    sync::{Arc, Mutex},
};

use iroh_base::EndpointId;
use iroh_metrics::{Counter, EncodeLabelSet, Family, LabelPair, LabelValue, MetricsGroup};
use iroh_relay::server::{Access, AccessControl, ClientRequest, ConnectionId, DynAccessControl};

/// One client, identified by the public key the relay handshake proved.
#[derive(Clone, Hash, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct ClientLabel {
    client: String,
}

impl EncodeLabelSet for ClientLabel {
    fn encode_label_pairs(&self) -> Vec<LabelPair<'_>> {
        vec![("client", LabelValue::Str(Cow::Borrowed(&self.client)))]
    }
}

/// Counters this binary adds on top of iroh-relay's own.
#[derive(Debug, Default, MetricsGroup)]
#[metrics(name = "astrelay")]
pub struct ClientMetrics {
    /// Connections admitted, over all clients.
    #[metrics(help = "Client connections admitted.")]
    pub connections_admitted: Counter,
    /// Connections refused by the access policy.
    #[metrics(help = "Client connections refused by the access policy.")]
    pub connections_denied: Counter,
    /// Admitted connections that have since ended. Open connections are
    /// `connections_admitted - connections_closed`.
    #[metrics(help = "Client connections that have ended.")]
    pub connections_closed: Counter,
    /// Distinct client keys seen since this process started.
    #[metrics(help = "Distinct client keys seen since startup.")]
    pub clients_seen: Counter,
    /// Connections from a client that arrived after the per-client label cap
    /// was reached, and so were counted only in the aggregates above.
    #[metrics(help = "Connections not given a per-client label, because the cap was reached.")]
    pub clients_untracked: Counter,
    /// Connections admitted, per client key. Empty unless per-client metrics
    /// were enabled; capped, see the module docs.
    #[metrics(help = "Connections admitted, by client key.")]
    pub client_connections: Family<ClientLabel, Counter>,
    /// Connections ended, per client key. Open connections for a client are
    /// this subtracted from `client_connections`.
    #[metrics(help = "Connections ended, by client key.")]
    pub client_disconnects: Family<ClientLabel, Counter>,
}

/// How much per-client detail to keep.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PerClient {
    /// Aggregates only. The default, and the only safe setting for a relay
    /// that strangers may use.
    Off,
    /// Per-key labels, for at most this many distinct keys.
    Capped(usize),
}

/// Wraps an access policy and counts what it decides.
///
/// Composition rather than replacement: the decision stays with whatever
/// policy the operator configured, and this only observes it. A counting layer
/// that could also deny would be a second place to look when a client is
/// refused.
#[derive(Debug)]
pub struct Accounting {
    inner: Arc<dyn DynAccessControl>,
    metrics: Arc<ClientMetrics>,
    per_client: PerClient,
    /// The keys that have been given a label, so the cap is on distinct keys
    /// rather than on connections.
    tracked: Mutex<HashSet<String>>,
}

impl Accounting {
    /// Wraps `inner`, recording into `metrics`.
    pub fn new(
        inner: Arc<dyn DynAccessControl>,
        metrics: Arc<ClientMetrics>,
        per_client: PerClient,
    ) -> Self {
        Self {
            inner,
            metrics,
            per_client,
            tracked: Mutex::new(HashSet::new()),
        }
    }

    /// Whether this key gets a label of its own, admitting it to the tracked
    /// set if there is room. Also the place `clients_seen` is counted, because
    /// "distinct keys" is the same question.
    fn label_for(&self, endpoint: EndpointId) -> Option<ClientLabel> {
        let key = endpoint.to_string();
        let cap = match self.per_client {
            PerClient::Off => {
                // Still worth knowing how many distinct devices use this
                // relay; that number is one value, not one series per device.
                let mut tracked = self.tracked.lock().expect("accounting mutex");
                if tracked.insert(key) {
                    self.metrics.clients_seen.inc();
                }
                return None;
            }
            PerClient::Capped(cap) => cap,
        };

        let mut tracked = self.tracked.lock().expect("accounting mutex");
        if tracked.contains(&key) {
            return Some(ClientLabel { client: key });
        }
        if tracked.len() >= cap {
            self.metrics.clients_untracked.inc();
            return None;
        }
        tracked.insert(key.clone());
        self.metrics.clients_seen.inc();
        Some(ClientLabel { client: key })
    }
}

impl AccessControl for Accounting {
    async fn on_connect(&self, request: &ClientRequest) -> Access {
        let decision = self.inner.on_connect(request).await;
        match &decision {
            Access::Allow => {
                self.metrics.connections_admitted.inc();
                if let Some(label) = self.label_for(request.endpoint_id()) {
                    self.metrics.client_connections.get_or_create(&label).inc();
                }
            }
            Access::Deny { .. } => {
                // A denied connection gets no per-client label: the label set
                // would then be attacker-controlled, which is the cardinality
                // problem in its worst form.
                self.metrics.connections_denied.inc();
            }
        }
        decision
    }

    fn on_disconnect(&self, endpoint_id: EndpointId, connection_id: ConnectionId) {
        self.metrics.connections_closed.inc();
        // Only for a key already tracked: a disconnect must never be the event
        // that creates a label, or the cap would be enforced on one side of a
        // pair and the two series would not subtract.
        let key = endpoint_id.to_string();
        let known = {
            let tracked = self.tracked.lock().expect("accounting mutex");
            tracked.contains(&key)
        };
        if known && matches!(self.per_client, PerClient::Capped(_)) {
            self.metrics
                .client_disconnects
                .get_or_create(&ClientLabel { client: key })
                .inc();
        }
        self.inner.on_disconnect(endpoint_id, connection_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A policy that admits everyone, so the wrapper's own behaviour is what
    /// the tests are looking at.
    #[derive(Debug)]
    struct Yes;

    impl AccessControl for Yes {
        async fn on_connect(&self, _request: &ClientRequest) -> Access {
            Access::Allow
        }
    }

    fn key(seed: u8) -> EndpointId {
        iroh_base::SecretKey::from_bytes(&[seed; 32]).public()
    }

    fn accounting(per_client: PerClient) -> (Accounting, Arc<ClientMetrics>) {
        let metrics = Arc::new(ClientMetrics::default());
        (
            Accounting::new(Arc::new(Yes), metrics.clone(), per_client),
            metrics,
        )
    }

    #[test]
    fn aggregates_are_kept_even_with_per_client_metrics_off() {
        let (acc, metrics) = accounting(PerClient::Off);
        assert!(acc.label_for(key(1)).is_none());
        assert!(acc.label_for(key(2)).is_none());
        assert!(acc.label_for(key(1)).is_none(), "the same key again");
        // Two distinct devices, counted once each, with no series per device.
        assert_eq!(metrics.clients_seen.get(), 2);
        assert_eq!(metrics.clients_untracked.get(), 0);
    }

    #[test]
    fn the_label_cap_bounds_the_series_and_says_when_it_bit() {
        // The property that keeps a public relay's metrics endpoint from
        // becoming an outage: a stranger cannot add a time series.
        let (acc, metrics) = accounting(PerClient::Capped(2));
        assert!(acc.label_for(key(1)).is_some());
        assert!(acc.label_for(key(2)).is_some());
        assert!(
            acc.label_for(key(3)).is_none(),
            "the third key is past the cap"
        );
        assert!(
            acc.label_for(key(1)).is_some(),
            "an already-tracked key keeps its label"
        );
        assert_eq!(metrics.clients_seen.get(), 2);
        assert_eq!(metrics.clients_untracked.get(), 1);
    }

    #[tokio::test]
    async fn a_denied_client_never_becomes_a_time_series() {
        /// A policy that refuses everyone, which is the shape an attacker
        /// meets.
        #[derive(Debug)]
        struct No;

        impl AccessControl for No {
            async fn on_connect(&self, _request: &ClientRequest) -> Access {
                Access::Deny { reason: None }
            }
        }

        let metrics = Arc::new(ClientMetrics::default());
        let acc = Accounting::new(Arc::new(No), metrics.clone(), PerClient::Capped(64));
        let request = ClientRequest::new(
            key(9),
            iroh_relay::http::ProtocolVersion::V2,
            http::Request::builder()
                .uri("/relay")
                .body(())
                .unwrap()
                .into_parts()
                .0,
        );
        assert!(matches!(
            AccessControl::on_connect(&acc, &request).await,
            Access::Deny { .. }
        ));
        assert_eq!(metrics.connections_denied.get(), 1);
        assert_eq!(metrics.connections_admitted.get(), 0);
        assert_eq!(
            metrics.clients_seen.get(),
            0,
            "a refused key must not be admitted to the tracked set"
        );
    }

    #[tokio::test]
    async fn an_admitted_connection_is_counted_and_so_is_its_end() {
        let metrics = Arc::new(ClientMetrics::default());
        let acc = Accounting::new(Arc::new(Yes), metrics.clone(), PerClient::Capped(64));
        let endpoint = key(4);
        let request = ClientRequest::new(
            endpoint,
            iroh_relay::http::ProtocolVersion::V2,
            http::Request::builder()
                .uri("/relay")
                .body(())
                .unwrap()
                .into_parts()
                .0,
        );
        assert_eq!(
            AccessControl::on_connect(&acc, &request).await,
            Access::Allow
        );
        assert_eq!(metrics.connections_admitted.get(), 1);
        AccessControl::on_disconnect(&acc, endpoint, request.connection_id());
        assert_eq!(metrics.connections_closed.get(), 1);
        // Open connections are the difference of the two, which is the shape a
        // Prometheus query wants and needs both halves to be present for.
        assert_eq!(
            metrics.connections_admitted.get() - metrics.connections_closed.get(),
            0
        );
    }
}
