use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, AtomicU64};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use moka::future::Cache;
use opentelemetry::metrics::{Counter, Gauge, Histogram};
use opentelemetry::{global, KeyValue};
use tracing::{debug, warn};

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

/// An L1 entry: the cached decision plus when it was loaded from the store, so
/// keep-warm can tell a resident value has aged past its refresh point. This is
/// the stale-while-revalidate stamp (RFC 5861): reads always get the decision;
/// the timestamp only drives the background refresh (decision D1/D2).
#[derive(Clone)]
pub(crate) struct Cached {
    pub(crate) decision: Arc<RoutingDecision>,
    fetched_at: Instant,
}

impl Cached {
    fn new(decision: Arc<RoutingDecision>) -> Self {
        Self {
            decision,
            fetched_at: Instant::now(),
        }
    }
}

/// The keep-warm refresh point (D2): half the cache entry lifetime, so a resident,
/// actively-read entry refreshes once it is halfway to expiry — leaving the rest of
/// the lifetime as margin to complete the refresh off the request path before hard
/// expiry. The single home for the "derive from the existing TTL" rule, shared by
/// `main` and the tests; deliberately not a separate operational knob.
pub(crate) fn refresh_point(ttl: Duration) -> Duration {
    ttl.checked_div(2).unwrap_or(ttl)
}

#[derive(Clone)]
pub(crate) struct AppState {
    /// L1: per-edge bounded working-set cache of decisions (RFC §6.3 / decision 9).
    pub(crate) l1: Cache<String, Cached>,
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
    /// Keep-warm refresh point (D2): a resident, actively-read entry older than
    /// this is refreshed in the background before its L1 lifetime expires, so no
    /// live request pays a store refill for a host already held. Derived from the
    /// L1 lifetime at construction — not a separate operational knob.
    pub(crate) refresh_after: Duration,
    /// Keys with a background keep-warm refresh in flight — collapses a burst of
    /// reads to at most one refresh per key (the spec's coalescing requirement).
    pub(crate) refreshing: Arc<Mutex<HashSet<String>>>,
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
        if let Some(cached) = self.l1.get(&key).await {
            METRICS.cache_hits.add(1, &[KeyValue::new("tier", "l1")]);
            // Keep-warm (D1, stale-while-revalidate): a resident value that has aged
            // past the refresh point is refreshed in the BACKGROUND while this request
            // is answered from the value already held — so no live request pays the
            // store refill for a host the cache already knows (N16 fix #2). A refresh
            // re-inserts, which also resets the L1 lifetime, so a continuously-read key
            // never reaches hard expiry on the request path.
            if cached.fetched_at.elapsed() >= self.refresh_after {
                self.spawn_refresh(&key);
            }
            return Some(cached.decision);
        }
        METRICS.cache_misses.add(1, &[KeyValue::new("tier", "l1")]);

        // Miss (first-ever host, or one that finally hard-expired): a single coalesced
        // synchronous load. Concurrent misses for the same key collapse to one
        // execution (RFC C14). A negative is an `Err`, so it is not cached (RFC §3.10)
        // and the caller rejects the host (C18).
        let store = self.store.clone();
        let l2 = self.l2.clone();
        let l2_ttl = self.l2_ttl;
        let key2 = key.clone();
        self.l1
            .try_get_with(key, load_decision(store, l2, l2_ttl, key2))
            .await
            .ok()
            .map(|c| c.decision)
    }

    /// Spawn a background keep-warm refresh for a resident key, collapsing a burst
    /// of reads to at most one in-flight refresh per key (the spec's coalescing
    /// requirement). On success the fresh value is re-inserted (renewing both the
    /// value and the L1 lifetime); on failure the last good value is left in place
    /// to be retried on the next read, and — if the store stays down past the L1
    /// lifetime — the entry hard-expires and the next request resolves it on demand
    /// (the spec's bounded-staleness fallback). Never blocks or fails a request.
    fn spawn_refresh(&self, key: &str) {
        {
            let mut inflight = self.refreshing.lock().unwrap();
            if !inflight.insert(key.to_owned()) {
                return; // a refresh for this key is already running.
            }
        }
        let store = self.store.clone();
        let l2 = self.l2.clone();
        let l2_ttl = self.l2_ttl;
        let l1 = self.l1.clone();
        let refreshing = self.refreshing.clone();
        let key = key.to_owned();
        // Detached: the refresh runs off the request path and its result reaches
        // readers via the L1 re-insert below, never through this handle.
        let _refresh = tokio::spawn(async move {
            match load_decision(store, l2, l2_ttl, key.clone()).await {
                Ok(cached) => l1.insert(key.clone(), cached).await,
                Err(e) => {
                    debug!(key = %key, error = %e, "keep-warm refresh failed; serving last good value");
                }
            }
            let _ = refreshing.lock().unwrap().remove(&key);
        });
    }
}

/// Load a decision from the optional L2 then the authoritative store — the single
/// path shared by the on-miss synchronous load and the background keep-warm
/// refresh, so both produce an identically-shaped, freshly-stamped [`Cached`].
/// One exact point read, then one wildcard-parent point read (RFC C14 — never a
/// scan). Returns `Err` for an unknown/unverified host (never cached, RFC §3.10)
/// or on a store error.
async fn load_decision(
    store: Arc<dyn RoutingStore>,
    l2: Option<Arc<dyn SharedCache>>,
    l2_ttl: u64,
    key: String,
) -> Result<Cached, String> {
    // L2 (optional shared tier).
    if let Some(l2) = &l2 {
        match l2.get(&key).await {
            Ok(Some(d)) => {
                METRICS.cache_hits.add(1, &[KeyValue::new("tier", "l2")]);
                return Ok(Cached::new(Arc::new(d)));
            }
            Ok(None) => {
                METRICS.cache_misses.add(1, &[KeyValue::new("tier", "l2")]);
            }
            Err(e) => warn!(error = %e, "L2 get failed; falling through to store"),
        }
    }

    // Authoritative store: one exact point read, then one wildcard parent point
    // read (RFC C14 — never a scan).
    let workspace = match store.lookup_domain(&key, false).await {
        Ok(Some(t)) => Some(t),
        Ok(None) => match parent_domain(&key) {
            Some(parent) => store.lookup_domain(&parent, true).await.map_err(|e| e.to_string())?,
            None => None,
        },
        Err(e) => return Err(e.to_string()),
    };
    let Some(workspace_id) = workspace else {
        // Unknown/unverified host → not cached, surfaced as a miss the caller
        // rejects (C18).
        return Err("no_tenant".to_owned());
    };
    let cfg = match store.get_workspace(&workspace_id).await {
        Ok(Some(c)) => c,
        Ok(None) => return Err("no_tenant_config".to_owned()),
        Err(e) => return Err(e.to_string()),
    };
    // Fold the workspace's per-route auth policy (RFC N4) into the cached decision:
    // one extra point read on the load path, then resolved per-request against the
    // request path with no further lookup. It rides the same domain-keyed
    // invalidation as the rest of the decision (a policy change invalidates the
    // workspace's domains).
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
        && let Err(e) = l2.put(&key, &decision, l2_ttl).await
    {
        warn!(error = %e, "L2 put failed");
    }
    Ok(Cached::new(Arc::new(decision)))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use tokio::time::sleep;

    use super::AppState;
    use crate::test_support::{build_state, FakeStore};

    /// N16 fix #2 (workload arm) — the reproduction test that drives the whole
    /// change. A single hot host, resolved once and then read continuously faster
    /// than the cache lifetime, MUST never pay a store refill on the request path:
    /// an already-resident, actively-read key is kept warm in the background, so no
    /// live request eats the cold path.
    ///
    /// Fails against the lazy-on-miss cache (one refill per lifetime window — the
    /// structural `1/7` slow-request ratio N16 measured); passes once keep-warm
    /// lands. This also settles the mechanism empirically: the periodic slow hit is
    /// the cache re-cooling on the request path, not an external cause.
    #[tokio::test]
    async fn resident_hot_key_never_refills_on_the_request_path() {
        let host = "app.dufeut.com";
        let store = Arc::new(FakeStore::new([((host.to_owned(), false), "ws_live".to_owned())]));
        // Short L1 lifetime so several windows elapse within the test; the reads
        // below pace faster than both the lifetime and its derived refresh point.
        let ttl = Duration::from_millis(120);
        let state = build_state(store.clone(), ttl);

        // Populate: the first-ever lookup resolves on demand (acceptable cold cost).
        assert!(state.resolve(host).await.is_some(), "seed resolution must succeed");
        let seed_lookups = store.lookups();

        // Read continuously across several lifetime windows. Count only fetches that
        // land ON the request path: snapshot the store counter immediately around
        // each `resolve().await`. A background refresh is spawned but — on the
        // single-threaded test runtime — cannot run until this task yields at the
        // sleep below, so its store fetch lands OUTSIDE the bracket. A synchronous
        // lazy-on-miss refill runs inside the await and IS counted.
        let mut request_path_refills = 0_usize;
        for _ in 0..30 {
            let before = store.lookups();
            assert!(state.resolve(host).await.is_some(), "steady-state resolution must succeed");
            request_path_refills += store.lookups() - before;
            sleep(Duration::from_millis(25)).await;
        }

        assert_eq!(
            request_path_refills, 0,
            "a resident, actively-read key must never pay a store refill on the request path \
             (saw {request_path_refills} refills after {seed_lookups} seed lookups)",
        );
    }

    /// Read the resolved workspace id, or `None` if the host did not resolve.
    async fn resolved_ws(state: &AppState, host: &str) -> Option<String> {
        state.resolve(host).await.map(|d| d.workspace_id.clone())
    }

    /// First-ever lookups still resolve on demand — keep-warm only applies to a key
    /// the cache already holds; a never-seen host is fetched for the caller.
    #[tokio::test]
    async fn first_ever_lookup_resolves_on_demand() {
        let host = "new.example.com";
        let store = Arc::new(FakeStore::new([((host.to_owned(), false), "ws_new".to_owned())]));
        let state = build_state(store.clone(), Duration::from_millis(500));

        let before = store.lookups();
        assert_eq!(resolved_ws(&state, host).await.as_deref(), Some("ws_new"));
        assert!(store.lookups() > before, "a first-ever host must be fetched from the store on demand");
    }

    /// A resident value that ages past the refresh point is refreshed in the
    /// BACKGROUND: the triggering read is answered from the current value with no
    /// request-path fetch, and a later read observes the refreshed value.
    #[tokio::test]
    async fn resident_value_refreshes_in_background_without_blocking() {
        let host = "app.example.com";
        let store = Arc::new(FakeStore::new([((host.to_owned(), false), "ws_a".to_owned())]));
        // refresh point = 100ms, hard expiry = 200ms.
        let state = build_state(store.clone(), Duration::from_millis(200));
        assert_eq!(resolved_ws(&state, host).await.as_deref(), Some("ws_a"));

        // The store's answer changes; a background refresh should pick it up.
        store.set_domain(host, "ws_b");

        // Cross the refresh point but stay within the hard lifetime.
        sleep(Duration::from_millis(130)).await;

        // The triggering read serves the still-resident value with no request-path fetch.
        let before = store.lookups();
        let served = resolved_ws(&state, host).await;
        assert_eq!(store.lookups(), before, "the refresh-triggering read must not fetch on the request path");
        assert_eq!(served.as_deref(), Some("ws_a"), "the triggering read is served the current value");

        // Let the background refresh run, then observe the refreshed value.
        sleep(Duration::from_millis(40)).await;
        assert_eq!(
            resolved_ws(&state, host).await.as_deref(),
            Some("ws_b"),
            "a later read observes the value the background refresh installed",
        );
    }

    /// A background refresh that fails must not evict the entry or fail the request:
    /// within the lifetime the last good value keeps being served.
    #[tokio::test]
    async fn refresh_failure_serves_last_good_within_lifetime() {
        let host = "app.example.com";
        let store = Arc::new(FakeStore::new([((host.to_owned(), false), "ws_a".to_owned())]));
        // refresh point = 150ms, hard expiry = 300ms.
        let state = build_state(store.clone(), Duration::from_millis(300));
        assert_eq!(resolved_ws(&state, host).await.as_deref(), Some("ws_a"));

        store.set_fail(true); // every refresh from now on errors

        // Past the refresh point, before hard expiry: the read triggers a doomed
        // background refresh but is still answered from the last good value.
        sleep(Duration::from_millis(180)).await;
        let before = store.lookups();
        let served = resolved_ws(&state, host).await;
        assert_eq!(store.lookups(), before, "a resident read must not fetch on the request path even when refresh will fail");
        assert_eq!(served.as_deref(), Some("ws_a"), "a failed refresh must not fail the request");

        // Let the failed refresh complete; the entry is NOT evicted.
        sleep(Duration::from_millis(20)).await;
        assert_eq!(
            resolved_ws(&state, host).await.as_deref(),
            Some("ws_a"),
            "a failed refresh must leave the last good value in place",
        );
    }

    /// A control-plane invalidation (the NOTIFY path) evicts the key; the next
    /// request re-resolves it from the store and serves the fresh value.
    #[tokio::test]
    async fn invalidated_key_is_re_resolved() {
        let host = "app.example.com";
        let store = Arc::new(FakeStore::new([((host.to_owned(), false), "ws_a".to_owned())]));
        let state = build_state(store.clone(), Duration::from_secs(30));
        assert_eq!(resolved_ws(&state, host).await.as_deref(), Some("ws_a"));

        // The mapping changes and the control plane invalidates the key.
        store.set_domain(host, "ws_b");
        state.l1.invalidate(host).await;

        // The next request re-resolves from the store (miss → on-demand load).
        let before = store.lookups();
        assert_eq!(
            resolved_ws(&state, host).await.as_deref(),
            Some("ws_b"),
            "an invalidated key must be re-resolved to the fresh value",
        );
        assert!(store.lookups() > before, "re-resolution after invalidation reads the store");
    }

    /// An idle key (no longer read) is NOT kept warm: it ages out at the lifetime,
    /// and the next request after that resolves it fresh from the store.
    #[tokio::test]
    async fn idle_key_is_not_kept_warm() {
        let host = "app.example.com";
        let store = Arc::new(FakeStore::new([((host.to_owned(), false), "ws_a".to_owned())]));
        let state = build_state(store.clone(), Duration::from_millis(100));
        assert!(state.resolve(host).await.is_some());

        // Go quiet for longer than the lifetime — no reads means no keep-warm.
        sleep(Duration::from_millis(160)).await;

        // The entry has aged out; the next read must fetch from the store again.
        let before = store.lookups();
        assert!(state.resolve(host).await.is_some());
        assert!(
            store.lookups() > before,
            "an idle key must age out and be re-fetched, not be kept warm in the background",
        );
    }

    /// Bounded staleness: once refreshes fail past the lifetime, the entry
    /// hard-expires rather than serving an unboundedly old value, and the next
    /// request falls back to on-demand resolution (which, with the store down,
    /// fails closed rather than lying).
    #[tokio::test]
    async fn persistent_failure_falls_back_to_on_demand_past_lifetime() {
        let host = "app.example.com";
        let store = Arc::new(FakeStore::new([((host.to_owned(), false), "ws_a".to_owned())]));
        // refresh point = 75ms, hard expiry = 150ms.
        let state = build_state(store.clone(), Duration::from_millis(150));
        assert_eq!(resolved_ws(&state, host).await.as_deref(), Some("ws_a"));

        store.set_fail(true);

        // Read continuously across the lifetime; refreshes keep failing so the entry
        // is never renewed and hard-expires at the lifetime, after which a read must
        // attempt an on-demand load (which fails closed while the store is down).
        let mut fell_back = false;
        for _ in 0..12 {
            sleep(Duration::from_millis(30)).await;
            let before = store.lookups();
            let served = state.resolve(host).await;
            let did_request_path_fetch = store.lookups() > before;
            if served.is_none() && did_request_path_fetch {
                fell_back = true;
                break;
            }
            // Before hard expiry the last good value is served with no request-path
            // fetch (the failed refresh runs in the background).
            assert_eq!(served.map(|d| d.workspace_id.clone()).as_deref(), Some("ws_a"));
            assert!(!did_request_path_fetch, "within the lifetime the request path must not fetch");
        }
        assert!(
            fell_back,
            "past the lifetime a persistently-failing key must fall back to on-demand resolution, not serve stale forever",
        );
    }
}
