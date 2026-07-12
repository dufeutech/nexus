use std::sync::atomic::{AtomicBool, AtomicU64};
use std::sync::Arc;
use std::sync::LazyLock;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use moka::future::Cache;
use opentelemetry::metrics::{Counter, Gauge, Histogram};
use opentelemetry::{global, KeyValue};
use tracing::warn;

use router_core::cache::SharedCache;
use router_core::domain::RoutingDecision;
use router_core::normalize::{normalize_host, parent_domain};
use router_core::store::RoutingStore;

// --------------------------------------------------------------------------- //
// Metrics (first-party-telemetry): the RED baseline + operational gauges, emitted
// through the OTel meter (push path via router_core::telemetry). Counter names DROP
// the Prometheus `_total` suffix — Prometheus's OTLP receiver re-appends it, so the
// stored series keep their names (router_ext_proc_requests_total, …) and dashboards
// keep working. The duration histogram carries the same explicit buckets as before,
// so `histogram_quantile(0.99, sum by (le) (rate(..._bucket[5m])))` is unchanged.
// --------------------------------------------------------------------------- //
pub(crate) struct Metrics {
    pub(crate) ext_proc_duration: Histogram<f64>,
    pub(crate) ext_proc_requests: Counter<u64>,
    pub(crate) cache_hits: Counter<u64>,
    pub(crate) cache_misses: Counter<u64>,
    pub(crate) invalidations: Counter<u64>,
    pub(crate) authorize: Counter<u64>,
    pub(crate) cache_entries: Gauge<u64>,
    pub(crate) ready: Gauge<u64>,
    pub(crate) last_invalidation: Gauge<f64>,
    pub(crate) time_to_warm: Gauge<f64>,
}

pub(crate) static METRICS: LazyLock<Metrics> = LazyLock::new(|| {
    let meter = global::meter("tenant-router");
    Metrics {
        ext_proc_duration: meter
            .f64_histogram("router_ext_proc_duration_seconds")
            .with_unit("s")
            .with_boundaries(vec![
                0.00005, 0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05,
                0.1, 0.25, 0.5, 1.0, 2.5, 5.0,
            ])
            .build(),
        ext_proc_requests: meter.u64_counter("router_ext_proc_requests").build(),
        cache_hits: meter.u64_counter("router_cache_hits").build(),
        cache_misses: meter.u64_counter("router_cache_misses").build(),
        invalidations: meter.u64_counter("router_invalidations").build(),
        authorize: meter.u64_counter("router_authorize").build(),
        cache_entries: meter.u64_gauge("router_cache_entries").build(),
        ready: meter.u64_gauge("router_ready").build(),
        last_invalidation: meter
            .f64_gauge("router_last_invalidation_timestamp_seconds")
            .build(),
        time_to_warm: meter.f64_gauge("router_time_to_warm_seconds").build(),
    }
});

pub(crate) fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

#[derive(Clone)]
pub(crate) struct AppState {
    /// L1: per-edge bounded working-set cache of decisions (RFC §6.3 / decision 9).
    pub(crate) l1: Cache<String, Arc<RoutingDecision>>,
    /// L2: OPTIONAL shared tier (RFC decision 9) — pure optimization.
    pub(crate) l2: Option<Arc<dyn SharedCache>>,
    /// Bounded negative-authorization cache for the on-demand-TLS `ask`
    /// (certificate-issuance-authorization). A host the gate refuses is
    /// remembered here for a short TTL so a flood of unknown SNIs is served the
    /// remembered refusal without re-hitting the store or the CA. `max_capacity`
    /// bounds the memory a flood of DISTINCT unknown hosts can occupy (LRU
    /// eviction), so the refusal memory cannot itself become the DoS.
    pub(crate) neg: Cache<String, ()>,
    pub(crate) store: Arc<dyn RoutingStore>,
    pub(crate) l2_ttl: u64,
    pub(crate) ready: Arc<AtomicBool>,
    pub(crate) last_apply_ms: Arc<AtomicU64>, // epoch millis of the last applied invalidation
    pub(crate) warm_ms: Arc<AtomicU64>,
    pub(crate) start: Instant,
}

impl AppState {
    /// Resolve a request host to a Routing Decision. L1 hit → in-memory read; on a
    /// miss, a single coalesced load that consults the optional L2 then the store
    /// (one exact lookup, then one wildcard-parent lookup, RFC C14). Returns
    /// `None` for an unresolved/unverified host — which the caller turns into an
    /// edge rejection (C18), never a default tenant. A negative is an `Err` in the
    /// loader, so it is not cached as a positive mapping (RFC §3.10).
    pub(crate) async fn resolve(&self, host: &str) -> Option<Arc<RoutingDecision>> {
        let key = normalize_host(host);
        if key.is_empty() {
            return None;
        }
        if let Some(d) = self.l1.get(&key).await {
            METRICS.cache_hits.add(1, &[KeyValue::new("tier", "l1")]);
            return Some(d);
        }
        METRICS.cache_misses.add(1, &[KeyValue::new("tier", "l1")]);

        let store = self.store.clone();
        let l2 = self.l2.clone();
        let l2_ttl = self.l2_ttl;
        let key2 = key.clone();
        self.l1
            .try_get_with(key, async move {
                // L2 (optional shared tier).
                if let Some(l2) = &l2 {
                    match l2.get(&key2).await {
                        Ok(Some(d)) => {
                            METRICS.cache_hits.add(1, &[KeyValue::new("tier", "l2")]);
                            return Ok(Arc::new(d));
                        }
                        Ok(None) => {
                            METRICS.cache_misses.add(1, &[KeyValue::new("tier", "l2")]);
                        }
                        Err(e) => warn!(error = %e, "L2 get failed; falling through to store"),
                    }
                }

                // Authoritative store: one exact point read, then one wildcard
                // parent point read (RFC C14 — never a scan).
                let workspace = match store.lookup_domain(&key2, false).await {
                    Ok(Some(t)) => Some(t),
                    Ok(None) => match parent_domain(&key2) {
                        Some(parent) => {
                            store.lookup_domain(&parent, true).await.map_err(|e| e.to_string())?
                        }
                        None => None,
                    },
                    Err(e) => return Err(e.to_string()),
                };
                let Some(workspace_id) = workspace else {
                    // Unknown/unverified host → not cached, surfaced as a miss the
                    // caller rejects (C18).
                    return Err("no_tenant".to_owned());
                };
                let cfg = match store.get_workspace(&workspace_id).await {
                    Ok(Some(c)) => c,
                    Ok(None) => return Err("no_tenant_config".to_owned()),
                    Err(e) => return Err(e.to_string()),
                };
                // Fold the workspace's per-route auth policy (RFC N4) into the cached
                // decision: one extra point read on the miss path, then resolved
                // per-request against the request path with no further lookup. It
                // rides the same domain-keyed invalidation as the rest of the
                // decision (a policy change invalidates the workspace's domains).
                let auth = match store.get_auth_policy(&workspace_id).await {
                    Ok(p) => p,
                    Err(e) => return Err(e.to_string()),
                };
                let decision = RoutingDecision {
                    workspace_id: cfg.workspace_id,
                    plan: cfg.plan,
                    pool: cfg.target_pool,
                    features: cfg.features,
                    auth,
                };
                if let Some(l2) = &l2
                    && let Err(e) = l2.put(&key2, &decision, l2_ttl).await
                {
                    warn!(error = %e, "L2 put failed");
                }
                Ok(Arc::new(decision))
            })
            .await
            .ok()
    }
}
