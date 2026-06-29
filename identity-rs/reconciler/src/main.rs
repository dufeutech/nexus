//! Reconciler (Rust) — the self-healing half of the sync pipeline (RFC C8).
//!
//! The IdP does not retry failed webhooks, so a dropped delivery would leave KV
//! stale. The Reconciler converges KV toward the IdP's authoritative state on a
//! periodic timer (and at startup). It uses the SHARED mapping/diff in
//! `identity_core::reconcile` (same logic as the sync-worker's writes).
//!
//! Sharding seam (RFC C8 at scale): full enumeration of ~1B identities in one
//! pass is infeasible, so the work is partitioned. `SHARD_TOTAL`/`SHARD_INDEX`
//! select a hash-slice of subjects this instance owns; an instance only upserts
//! and only deletes keys it owns. Default `SHARD_TOTAL=1` ⇒ one instance owns
//! the whole keyspace (the small-scale reference behavior). NOTE: true 1B-scale
//! reconciliation also requires *partitioned enumeration* at the IdP adapter
//! (server-side key-range paging or a change-data feed); client-side hashing
//! here is the seam, not the whole answer.

use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use metrics::{counter, gauge, histogram};
use metrics_exporter_prometheus::PrometheusBuilder;
use serde_json::{json, Value};
use tracing::{error, info, warn};

use identity_core::reconcile::{build_profile_from_user, differs};
use identity_core::store::{BoxError, ProfileStore};
use identity_core::Profile;
use store_postgres::PgProfileStore;

fn env(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}
fn env_num<T: std::str::FromStr>(key: &str, default: T) -> T {
    std::env::var(key).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}
fn now_secs() -> f64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0)
}

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
        let mut h = std::collections::hash_map::DefaultHasher::new();
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
}

impl Idp {
    async fn post(&self, path: &str, body: Value) -> Result<Value, reqwest::Error> {
        self.client
            .post(format!("{}{}", self.internal_url, path))
            .bearer_auth(&self.pat)
            .header(reqwest::header::HOST, &self.host)
            .json(&body)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await
    }

    async fn list_users(&self) -> Result<Vec<Value>, reqwest::Error> {
        let r = self.post("/v2/users", json!({"query": {"limit": self.page}})).await?;
        Ok(r.get("result").and_then(|v| v.as_array()).cloned().unwrap_or_default())
    }

    /// userId -> sorted roleKeys. Best-effort: on failure, roles are not
    /// reconciled this pass (logged), matching the prior behavior.
    async fn list_grants(&self) -> HashMap<String, Vec<String>> {
        let mut out: HashMap<String, Vec<String>> = HashMap::new();
        match self
            .post("/management/v1/users/grants/_search", json!({"query": {"limit": self.page}}))
            .await
        {
            Ok(r) => {
                for g in r.get("result").and_then(|v| v.as_array()).cloned().unwrap_or_default() {
                    if let Some(uid) = g.get("userId").and_then(|v| v.as_str()) {
                        let roles: Vec<String> = g
                            .get("roleKeys")
                            .and_then(|v| v.as_array())
                            .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
                            .unwrap_or_default();
                        out.entry(uid.to_string()).or_default().extend(roles);
                    }
                }
            }
            Err(e) => warn!(error = %e, "grant search failed; roles not reconciled this pass"),
        }
        for v in out.values_mut() {
            v.sort();
            v.dedup();
        }
        out
    }
}

async fn reconcile_pass(idp: &Idp, store: &dyn ProfileStore, shard: &Shard) -> Result<(), BoxError> {
    let users = idp.list_users().await?;
    let grants = idp.list_grants().await;

    // One scan of stored profiles (this shard's keyspace at scale); diff against
    // the authoritative list and derive orphans from the same snapshot.
    let stored: HashMap<String, Profile> = store
        .scan_all()
        .await?
        .into_iter()
        .map(|p| (p.sub.clone(), p))
        .collect();

    let mut authoritative: HashSet<String> = HashSet::new();
    let mut upserted = 0u64;
    for u in &users {
        let Some(uid) = u.get("userId").and_then(|v| v.as_str()) else { continue };
        if !shard.owns(uid) {
            continue;
        }
        authoritative.insert(uid.to_string());
        let desired = build_profile_from_user(u, grants.get(uid).cloned().unwrap_or_default());
        if differs(&desired, stored.get(uid)) {
            store.put(&desired).await?;
            upserted += 1;
        }
    }

    // Orphan deletes: only safe when the (sharded) list was complete — a page
    // shortfall can't prove absence, so deletions are skipped that pass.
    let mut deleted = 0u64;
    if users.len() as u64 >= idp.page {
        warn!(page = idp.page, "user list hit page limit; skipping deletions this pass");
    } else {
        for k in stored.keys() {
            if shard.owns(k) && !authoritative.contains(k) {
                store.delete(k).await?;
                deleted += 1;
            }
        }
    }

    gauge!("reconcile_scanned").set(users.len() as f64);
    gauge!("reconcile_last_drift_upserts").set(upserted as f64);
    gauge!("reconcile_last_orphan_deletes").set(deleted as f64);
    gauge!("reconcile_last_pass_timestamp_seconds").set(now_secs());
    info!(scanned = users.len(), drift_upserts = upserted, orphan_deletes = deleted, "pass");
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let term = async {
        if let Ok(mut s) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            s.recv().await;
        }
    };
    #[cfg(not(unix))]
    let term = std::future::pending::<()>();
    tokio::select! { _ = ctrl_c => {}, _ = term => {} }
}

fn init_tracing() {
    use tracing_subscriber::EnvFilter;
    let level = env("LOG_LEVEL", "info");
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level));
    if env("LOG_FORMAT", "") == "json" {
        tracing_subscriber::fmt().with_env_filter(filter).json().init();
    } else {
        tracing_subscriber::fmt().with_env_filter(filter).init();
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    init_tracing();
    let metrics_port: u16 = env_num("METRICS_PORT", 9000u16);
    PrometheusBuilder::new()
        .with_http_listener(([0, 0, 0, 0], metrics_port))
        .install()?;
    info!(port = metrics_port, "metrics listener up");

    let pg_url = env("PROFILE_PG_URL", "postgres://postgres:postgres@postgres:5432/zitadel");
    let interval = Duration::from_secs(env_num("RECONCILE_INTERVAL", 600u64));
    let shard = Shard { total: env_num("SHARD_TOTAL", 1u64).max(1), index: env_num("SHARD_INDEX", 0u64) };

    let pat = std::fs::read_to_string(env("PAT_FILE", "/secrets/zitadel-admin-sa.pat"))?.trim().to_string();
    let idp = Idp {
        client: reqwest::Client::builder().timeout(Duration::from_secs(30)).build()?,
        internal_url: env("ZITADEL_INTERNAL_URL", "http://zitadel:8080"),
        host: env("ZITADEL_HOST", "localhost:8088"),
        pat,
        page: env_num("RECONCILE_PAGE_LIMIT", 1000u64),
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
        tokio::time::sleep(Duration::from_secs(2)).await;
    };
    let store: Arc<dyn ProfileStore> = store;
    info!(interval_s = interval.as_secs(), shard_total = shard.total, shard_index = shard.index, "started");

    let (tx, mut rx) = tokio::sync::watch::channel(false);
    tokio::spawn(async move {
        shutdown_signal().await;
        let _ = tx.send(true);
    });

    loop {
        let started = Instant::now();
        match reconcile_pass(&idp, store.as_ref(), &shard).await {
            Ok(()) => counter!("reconcile_passes_total").increment(1),
            Err(e) => {
                counter!("reconcile_pass_errors_total").increment(1);
                error!(error = %e, "pass error");
            }
        }
        histogram!("reconcile_pass_duration_seconds").record(started.elapsed().as_secs_f64());

        tokio::select! {
            _ = tokio::time::sleep(interval) => {}
            _ = rx.changed() => break,
        }
    }

    info!("shutdown signal received; stopped");
    Ok(())
}
