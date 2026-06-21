//! Redis adapter for the OPTIONAL shared L2 cache tier (`SharedCache` port,
//! RFC decision 9). Shared across edge instances to raise aggregate hit rate and
//! absorb miss-load fan-out — but a pure optimization: every method is fallible
//! and the router falls back to L1 + the store on any error, so the plane stays
//! correct with L2 absent or down.
//!
//! Decisions are stored as JSON under a `routing:` key prefix with a TTL (the L2
//! staleness backstop). `ConnectionManager` reconnects transparently.
//!
//! **Every operation is bounded by a short timeout** (default 100ms, override via
//! `REDIS_OP_TIMEOUT_MS`). This is load-bearing for decision 9: without it, a
//! Redis outage makes `ConnectionManager` block on reconnect, so a cache MISS —
//! which consults L2 before the store — stalls until Envoy's `ext_proc` deadline
//! and returns 504, including for unknown-host rejections (C18). With the timeout
//! a dead/slow L2 returns an error fast, the loader falls through to the store,
//! and only the hot L1 working set is unaffected. A degraded optimization MUST
//! NOT become a hot-path outage.

use std::time::Duration;

use async_trait::async_trait;
use redis::aio::ConnectionManager;
use redis::AsyncCommands;
use tokio::time::timeout;

use router_core::cache::SharedCache;
use router_core::domain::RoutingDecision;
use router_core::store::BoxError;

const DEFAULT_OP_TIMEOUT_MS: u64 = 100;

#[derive(Clone)]
pub struct RedisCache {
    conn: ConnectionManager,
    prefix: String,
    op_timeout: Duration,
}

impl RedisCache {
    pub async fn connect(url: &str) -> Result<Self, BoxError> {
        let client = redis::Client::open(url)?;
        let conn = ConnectionManager::new(client).await?;
        let ms = std::env::var("REDIS_OP_TIMEOUT_MS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(DEFAULT_OP_TIMEOUT_MS);
        Ok(Self {
            conn,
            prefix: "routing:".to_string(),
            op_timeout: Duration::from_millis(ms),
        })
    }

    fn key(&self, k: &str) -> String {
        format!("{}{}", self.prefix, k)
    }

    /// Run an L2 op under the op timeout. A timeout is returned as an error so the
    /// caller degrades to L1 + the store (decision 9) instead of blocking the hot
    /// path on a slow/dead Redis.
    async fn bounded<F, T>(&self, what: &str, fut: F) -> Result<T, BoxError>
    where
        F: std::future::Future<Output = Result<T, BoxError>>,
    {
        match timeout(self.op_timeout, fut).await {
            Ok(res) => res,
            Err(_) => Err(format!("l2 {what} timed out after {:?}", self.op_timeout).into()),
        }
    }
}

#[async_trait]
impl SharedCache for RedisCache {
    async fn get(&self, key: &str) -> Result<Option<RoutingDecision>, BoxError> {
        let mut conn = self.conn.clone();
        let k = self.key(key);
        let raw: Option<String> = self
            .bounded("get", async move { Ok(conn.get(k).await?) })
            .await?;
        // A decode failure is treated as a miss, not a hard error — a stale/garbled
        // L2 entry must never wedge the hot path.
        Ok(raw.and_then(|s| serde_json::from_str(&s).ok()))
    }

    async fn put(
        &self,
        key: &str,
        decision: &RoutingDecision,
        ttl_secs: u64,
    ) -> Result<(), BoxError> {
        let mut conn = self.conn.clone();
        let k = self.key(key);
        let payload = serde_json::to_string(decision)?;
        self.bounded("put", async move {
            conn.set_ex::<_, _, ()>(k, payload, ttl_secs).await?;
            Ok(())
        })
        .await
    }

    async fn invalidate(&self, key: &str) -> Result<(), BoxError> {
        let mut conn = self.conn.clone();
        let k = self.key(key);
        self.bounded("invalidate", async move {
            conn.del::<_, ()>(k).await?;
            Ok(())
        })
        .await
    }
}
