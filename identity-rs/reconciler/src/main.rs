//! Reconciler (Rust) — the self-healing half of the sync pipeline (RFC C8).
//!
//! The `IdP` does not retry failed webhooks, so a dropped delivery would leave KV
//! stale. The Reconciler converges KV toward the `IdP`'s authoritative state on a
//! periodic timer (and at startup). It uses the SHARED mapping/diff in
//! `identity_core::reconcile` (same logic as the sync-worker's writes).
//!
//! Sharding seam (RFC C8 at scale): full enumeration of ~1B identities in one
//! pass is infeasible, so the work is partitioned. `SHARD_TOTAL`/`SHARD_INDEX`
//! select a hash-slice of subjects this instance owns; an instance only upserts
//! and only deletes keys it owns. Default `SHARD_TOTAL=1` ⇒ one instance owns
//! the whole keyspace (the small-scale reference behavior). NOTE: true 1B-scale
//! reconciliation also requires *partitioned enumeration* at the `IdP` adapter
//! (server-side key-range paging or a change-data feed); client-side hashing
//! here is the seam, not the whole answer.

use std::collections::hash_map::DefaultHasher;
use std::collections::{HashMap, HashSet};
use std::env::var;
use std::error::Error;
use std::fs;
use std::hash::{Hash, Hasher};
use std::str::FromStr;
use std::sync::Arc;
use std::sync::LazyLock;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
#[cfg(not(unix))]
use std::future::pending;

use reqwest::header::HOST;
use reqwest::redirect::Policy;
use serde_json::{json, Value};
use tokio::signal;
use tokio::sync::watch;
use tokio::time::sleep;
use tracing::{error, info, info_span, warn};
// first-party-telemetry: each background pass roots its own trace (no edge context).
use tracing::Instrument as _;
use opentelemetry::global;
use opentelemetry::metrics::{Counter, Gauge, Histogram};

use identity_core::telemetry;
use identity_core::reconcile::{differs, reconciled_profile};
use identity_core::store::{BoxError, ProfileStore};
use identity_core::Profile;
use store_postgres::PgProfileStore;

fn env(key: &str, default: &str) -> String {
    var(key).unwrap_or_else(|_| default.to_owned())
}
fn env_num<T: FromStr>(key: &str, default: T) -> T {
    var(key).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}
fn now_secs() -> f64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0.0, |d| d.as_secs_f64())
}

// --------------------------------------------------------------------------- //
// Metrics (first-party-telemetry): the per-pass operational gauges + counters +
// duration histogram, emitted through the OTel meter (push path via
// identity_core::telemetry). Counter names DROP the Prometheus `_total` suffix —
// Prometheus's OTLP receiver re-appends it, so the stored series keep their names
// (reconcile_passes_total, …). Gauges and the histogram keep their exact names.
// --------------------------------------------------------------------------- //
struct Metrics {
    scanned: Gauge<u64>,
    last_drift_upserts: Gauge<u64>,
    last_orphan_deletes: Gauge<u64>,
    last_pass_timestamp: Gauge<f64>,
    passes: Counter<u64>,
    pass_errors: Counter<u64>,
    pass_duration: Histogram<f64>,
}

static METRICS: LazyLock<Metrics> = LazyLock::new(|| {
    let meter = global::meter("reconciler");
    Metrics {
        scanned: meter.u64_gauge("reconcile_scanned").build(),
        last_drift_upserts: meter.u64_gauge("reconcile_last_drift_upserts").build(),
        last_orphan_deletes: meter.u64_gauge("reconcile_last_orphan_deletes").build(),
        last_pass_timestamp: meter
            .f64_gauge("reconcile_last_pass_timestamp_seconds")
            .build(),
        passes: meter.u64_counter("reconcile_passes").build(),
        pass_errors: meter.u64_counter("reconcile_pass_errors").build(),
        pass_duration: meter
            .f64_histogram("reconcile_pass_duration_seconds")
            .with_unit("s")
            .with_boundaries(vec![
                0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0, 120.0, 300.0,
            ])
            .build(),
    }
});

#[derive(Clone)]
struct Shard {
    total: u64,
    index: u64,
}
impl Shard {
    /// Does this instance own the given subject key?
    fn owns(&self, key: &str) -> bool {
        if self.total <= 1 {
            return true;
        }
        let mut h = DefaultHasher::new();
        key.hash(&mut h);
        h.finish() % self.total == self.index
    }
}

struct Idp {
    client: reqwest::Client,
    internal_url: String,
    host: String,
    pat: String,
    page: u64,
    /// Safety cap on pages fetched per list (so a runaway/loop can't spin
    /// forever). Hitting it means the enumeration is INCOMPLETE — callers must
    /// then suppress deletions/role-downgrades, never treat a short read as
    /// proof of absence.
    max_pages: u64,
}

impl Idp {
    async fn post(&self, path: &str, body: Value) -> Result<Value, reqwest::Error> {
        self.client
            .post(format!("{}{}", self.internal_url, path))
            .bearer_auth(&self.pat)
            .header(HOST, &self.host)
            .json(&body)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await
    }

    /// Page through a `query: {offset, limit}` list endpoint, accumulating
    /// `result[]`. Returns `(rows, complete)`; `complete = false` means the
    /// page cap was hit before the list was exhausted (so absence is unproven).
    async fn list_paged(&self, path: &str) -> Result<(Vec<Value>, bool), reqwest::Error> {
        let page = self.page.max(1);
        let mut all = Vec::new();
        let mut offset = 0_u64;
        for _ in 0..self.max_pages {
            let r = self
                .post(path, json!({"query": {"offset": offset, "limit": page}}))
                .await?;
            let batch = r.get("result").and_then(|v| v.as_array()).cloned().unwrap_or_default();
            let n = batch.len() as u64;
            all.extend(batch);
            if n < page {
                return Ok((all, true)); // short page ⇒ list exhausted.
            }
            offset += n;
        }
        Ok((all, false)) // page cap hit ⇒ incomplete.
    }

    /// All authoritative users. `(users, complete)` — see [`Idp::list_paged`].
    async fn list_users(&self) -> Result<(Vec<Value>, bool), reqwest::Error> {
        self.list_paged("/v2/users").await
    }

    /// userId -> sorted roleKeys, fully paged. `(grants, complete)`; on request
    /// failure returns an empty map with `complete = false` so roles are not
    /// downgraded this pass (preserves the prior best-effort behavior).
    async fn list_grants(&self) -> (HashMap<String, Vec<String>>, bool) {
        let mut out: HashMap<String, Vec<String>> = HashMap::new();
        let complete = match self.list_paged("/management/v1/users/grants/_search").await {
            Ok((rows, complete)) => {
                for g in rows {
                    if let Some(uid) = g.get("userId").and_then(|v| v.as_str()) {
                        let roles: Vec<String> = g
                            .get("roleKeys")
                            .and_then(|v| v.as_array())
                            .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
                            .unwrap_or_default();
                        out.entry(uid.to_owned()).or_default().extend(roles);
                    }
                }
                complete
            }
            Err(e) => {
                warn!(error = %e, "grant search failed; roles not reconciled this pass");
                false
            }
        };
        for v in out.values_mut() {
            v.sort();
            v.dedup();
        }
        (out, complete)
    }
}

async fn reconcile_pass(idp: &Idp, store: &dyn ProfileStore, shard: &Shard) -> Result<(), BoxError> {
    let (users, users_complete) = idp.list_users().await?;
    let (grants, grants_complete) = idp.list_grants().await;

    // One scan of stored profiles (this shard's keyspace at scale); diff against
    // the authoritative list and derive orphans from the same snapshot.
    let stored: HashMap<String, Profile> = store
        .scan_all()
        .await?
        .into_iter()
        .map(|p| (p.sub.clone(), p))
        .collect();

    let mut authoritative: HashSet<String> = HashSet::new();
    let mut upserted = 0_u64;
    for u in &users {
        let Some(uid) = u.get("userId").and_then(|v| v.as_str()) else { continue };
        if !shard.owns(uid) {
            continue;
        }
        authoritative.insert(uid.to_owned());
        // Roles: prefer the fetched grants. If the grant enumeration was
        // INCOMPLETE and this user had no fetched grant, we cannot prove they
        // have no roles — carry the stored roles forward rather than wiping them
        // (a user on users-page-1 whose grant fell on an unreached grant-page).
        let roles = match grants.get(uid) {
            Some(r) => r.clone(),
            None if !grants_complete => {
                stored.get(uid).map(|p| p.roles.clone()).unwrap_or_default()
            }
            None => Vec::new(),
        };
        // Carry the stored membership projection forward so this identity/role
        // reconcile never clobbers nexus-native memberships (reconciled separately
        // by the membership-sync worker). `differs` ignores memberships, so this
        // does not cause spurious upserts.
        let desired = reconciled_profile(u, roles, stored.get(uid));
        if differs(&desired, stored.get(uid)) {
            store.put(&desired).await?;
            upserted += 1;
        }
    }

    // Orphan deletes: only safe when the (sharded) user list was complete — a
    // page-cap shortfall can't prove absence, so deletions are skipped that pass.
    let mut deleted = 0_u64;
    if users_complete {
        for k in stored.keys() {
            if shard.owns(k) && !authoritative.contains(k) {
                store.delete(k).await?;
                deleted += 1;
            }
        }
    } else {
        warn!(page = idp.page, max_pages = idp.max_pages, "user list incomplete (page cap); skipping deletions this pass");
    }

    METRICS.scanned.record(users.len() as u64, &[]);
    METRICS.last_drift_upserts.record(upserted, &[]);
    METRICS.last_orphan_deletes.record(deleted, &[]);
    METRICS.last_pass_timestamp.record(now_secs(), &[]);
    info!(scanned = users.len(), drift_upserts = upserted, orphan_deletes = deleted, "pass");
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let term = async {
        if let Ok(mut s) = signal::unix::signal(signal::unix::SignalKind::terminate()) {
            s.recv().await;
        }
    };
    #[cfg(not(unix))]
    let term = pending::<()>();
    tokio::select! { () = ctrl_c => {}, () = term => {} }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    // Shared telemetry (first-party-telemetry): honors RUST_LOG/LOG_LEVEL/LOG_FORMAT
    // as before, plus OTLP export when the endpoint env is set. Each reconcile pass
    // roots its own trace; held for the process lifetime.
    let _telemetry = telemetry::init("reconciler");
    // Metrics now push via the OTel meter (first-party-telemetry); the old
    // Prometheus exporter listener is retired — the collector's metrics pipeline
    // forwards to the store, no per-box scrape job.

    let pg_url = env("PROFILE_PG_URL", "postgres://postgres:postgres@postgres:5432/identitydb");
    let interval = Duration::from_secs(env_num("RECONCILE_INTERVAL", 600_u64));
    let shard = Shard { total: env_num("SHARD_TOTAL", 1_u64).max(1), index: env_num("SHARD_INDEX", 0_u64) };

    let pat = fs::read_to_string(env("PAT_FILE", "/secrets/zitadel-admin-sa.pat"))?.trim().to_owned();
    let idp = Idp {
        client: reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            // Fixed trusted ZITADEL upstream — don't follow redirects that could
            // steer egress elsewhere.
            .redirect(Policy::none())
            .build()?,
        internal_url: env("ZITADEL_INTERNAL_URL", "http://zitadel:8080"),
        host: env("ZITADEL_HOST", "localhost:8088"),
        pat,
        page: env_num("RECONCILE_PAGE_LIMIT", 1000_u64),
        // Cap pages/list so a misbehaving feed can't spin forever; default
        // 1000 pages × 1000/page = 1M identities before a pass declares itself
        // incomplete (and conservatively skips deletions). Raise for >1M tenants.
        max_pages: env_num("RECONCILE_MAX_PAGES", 1000_u64).max(1),
    };

    // The reconciler is an authoritative writer, so it owns idempotent schema
    // setup on startup before the first pass backfills profiles from the IdP.
    let store: Arc<PgProfileStore> = loop {
        match PgProfileStore::connect(&pg_url).await {
            Ok(s) => match s.init_schema().await {
                Ok(()) => break Arc::new(s),
                Err(e) => warn!(error = %e, "schema init failed; retrying"),
            },
            Err(e) => warn!(error = %e, "waiting for Postgres"),
        }
        sleep(Duration::from_secs(2)).await;
    };
    let store: Arc<dyn ProfileStore> = store;
    info!(interval_s = interval.as_secs(), shard_total = shard.total, shard_index = shard.index, "started");

    let (tx, mut rx) = watch::channel(false);
    tokio::spawn(async move {
        shutdown_signal().await;
        let _ = tx.send(true);
    });

    loop {
        let started = Instant::now();
        // Root a trace for this pass so its logs correlate (spec: a reconcile pass is
        // investigable, its records correlatable to the pass's trace).
        let span = info_span!("reconcile.pass", otel.kind = "internal");
        match reconcile_pass(&idp, store.as_ref(), &shard)
            .instrument(span)
            .await
        {
            Ok(()) => METRICS.passes.add(1, &[]),
            Err(e) => {
                METRICS.pass_errors.add(1, &[]);
                error!(error = %e, "pass error");
            }
        }
        METRICS.pass_duration.record(started.elapsed().as_secs_f64(), &[]);

        tokio::select! {
            () = sleep(interval) => {}
            _ = rx.changed() => break,
        }
    }

    info!("shutdown signal received; stopped");
    Ok(())
}
