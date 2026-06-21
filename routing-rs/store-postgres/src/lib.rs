//! PostgreSQL adapter for the `RoutingStore` + `Invalidations` ports
//! (RFC §3.10/§3.11/§3.13, C16).
//!
//! - The authoritative routing state is written by the control plane and read
//!   (point lookups only) by the tenant-router. Reuses the lab's existing
//!   Postgres server under a dedicated `routing` schema so it never collides
//!   with the IdP's own tables (RFC decision 14: the routing plane reuses an
//!   authoritative store the control plane writes).
//! - Invalidation is delivered over Postgres `LISTEN/NOTIFY`: every control-plane
//!   mutation issues `pg_notify('routing_invalidations', <domain>)`; the router
//!   subscribes and evicts that key from every cache tier (RFC C16). LISTEN/NOTIFY
//!   is sufficient here because routing has no per-second revocation requirement
//!   (decision 14) — a missed signal self-heals within the cache staleness bound.
//! - All access is point-read/point-write by key (no request-path scans, §3.10).

use async_trait::async_trait;
use futures::stream::StreamExt;
use sqlx::postgres::{PgConnectOptions, PgListener, PgPoolOptions};
use sqlx::{PgPool, Row};

use router_core::domain::{Pool, TenantConfig};
use router_core::store::{BoxError, InvalidationFeed, Invalidations, RoutingStore};

/// The NOTIFY channel the control plane publishes invalidations on.
pub const INVALIDATION_CHANNEL: &str = "routing_invalidations";

#[derive(Clone)]
pub struct PgRoutingStore {
    pool: PgPool,
}

impl PgRoutingStore {
    pub async fn connect(url: &str) -> Result<Self, BoxError> {
        // Disable sqlx's prepared-statement cache so this pool is safe through a
        // transaction-mode pooler (PgBouncer): cached prepared statements break
        // there ("prepared statement already exists"). The router's read pool may
        // point at such a pooler (ROUTING_PG_READ_URL); the queries here are
        // trivial point reads, so the cache buys nothing and turning it off makes
        // the pool pooler-safe everywhere (the control plane, direct, is low
        // volume and unaffected). The LISTEN feed is a separate connection and is
        // never pooled — see `PgInvalidations`.
        let opts = url
            .parse::<PgConnectOptions>()?
            .statement_cache_capacity(0);
        let pool = PgPoolOptions::new()
            .max_connections(8)
            .connect_with(opts)
            .await?;
        Ok(Self { pool })
    }

    /// Idempotent schema bootstrap. The control plane owns this on startup; the
    /// router only reads, so it never creates schema.
    pub async fn init_schema(&self) -> Result<(), BoxError> {
        sqlx::query("CREATE SCHEMA IF NOT EXISTS routing")
            .execute(&self.pool)
            .await?;
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS routing.tenants (\
                 tenant_id  text PRIMARY KEY, \
                 plan       text NOT NULL DEFAULT 'free', \
                 target_pool text NOT NULL DEFAULT 'application', \
                 features   text[] NOT NULL DEFAULT '{}', \
                 updated_at timestamptz NOT NULL DEFAULT now())",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS routing.domains (\
                 domain      text PRIMARY KEY, \
                 tenant_id   text NOT NULL REFERENCES routing.tenants(tenant_id) ON DELETE CASCADE, \
                 is_wildcard boolean NOT NULL DEFAULT false, \
                 verified    boolean NOT NULL DEFAULT false, \
                 updated_at  timestamptz NOT NULL DEFAULT now())",
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Publish a cache invalidation for a normalized domain key (RFC C16). Called
    /// by the control plane after every mutation.
    pub async fn notify_invalidation(&self, domain: &str) -> Result<(), BoxError> {
        sqlx::query("SELECT pg_notify($1, $2)")
            .bind(INVALIDATION_CHANNEL)
            .bind(domain)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

#[async_trait]
impl RoutingStore for PgRoutingStore {
    async fn lookup_domain(
        &self,
        domain: &str,
        wildcard: bool,
    ) -> Result<Option<String>, BoxError> {
        // Point read on the `domain` primary key. `verified = true` enforces
        // RFC C16: an unverified domain MUST NOT resolve on protected routes.
        let row = sqlx::query(
            "SELECT tenant_id FROM routing.domains \
             WHERE domain = $1 AND is_wildcard = $2 AND verified = true",
        )
        .bind(domain)
        .bind(wildcard)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|r| r.get::<String, _>("tenant_id")))
    }

    async fn get_tenant(&self, tenant_id: &str) -> Result<Option<TenantConfig>, BoxError> {
        let row = sqlx::query(
            "SELECT tenant_id, plan, target_pool, features, updated_at::text AS updated_at \
             FROM routing.tenants WHERE tenant_id = $1",
        )
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await?;
        let Some(r) = row else { return Ok(None) };
        let target: String = r.get("target_pool");
        let Some(pool) = Pool::parse(&target) else {
            // Configuration MUST resolve to one of the finite pools (RFC §3.11);
            // an invalid selector is a config defect, surfaced as an error rather
            // than silently invented into a destination.
            return Err(format!(
                "tenant '{tenant_id}' has invalid target_pool '{target}'"
            )
            .into());
        };
        Ok(Some(TenantConfig {
            tenant_id: r.get("tenant_id"),
            plan: r.get("plan"),
            target_pool: pool,
            features: r.get::<Vec<String>, _>("features"),
            updated_at: r.get::<Option<String>, _>("updated_at"),
        }))
    }

    async fn upsert_tenant(&self, cfg: &TenantConfig) -> Result<(), BoxError> {
        sqlx::query(
            "INSERT INTO routing.tenants (tenant_id, plan, target_pool, features, updated_at) \
             VALUES ($1, $2, $3, $4, now()) \
             ON CONFLICT (tenant_id) DO UPDATE SET \
                 plan = EXCLUDED.plan, target_pool = EXCLUDED.target_pool, \
                 features = EXCLUDED.features, updated_at = now()",
        )
        .bind(&cfg.tenant_id)
        .bind(&cfg.plan)
        .bind(cfg.target_pool.as_str())
        .bind(&cfg.features)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn upsert_domain(
        &self,
        domain: &str,
        tenant_id: &str,
        wildcard: bool,
        verified: bool,
    ) -> Result<(), BoxError> {
        sqlx::query(
            "INSERT INTO routing.domains (domain, tenant_id, is_wildcard, verified, updated_at) \
             VALUES ($1, $2, $3, $4, now()) \
             ON CONFLICT (domain) DO UPDATE SET \
                 tenant_id = EXCLUDED.tenant_id, is_wildcard = EXCLUDED.is_wildcard, \
                 verified = EXCLUDED.verified, updated_at = now()",
        )
        .bind(domain)
        .bind(tenant_id)
        .bind(wildcard)
        .bind(verified)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn set_domain_verified(&self, domain: &str, verified: bool) -> Result<(), BoxError> {
        sqlx::query("UPDATE routing.domains SET verified = $2, updated_at = now() WHERE domain = $1")
            .bind(domain)
            .bind(verified)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn delete_domain(&self, domain: &str) -> Result<(), BoxError> {
        sqlx::query("DELETE FROM routing.domains WHERE domain = $1")
            .bind(domain)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn domains_for_tenant(&self, tenant_id: &str) -> Result<Vec<String>, BoxError> {
        let rows = sqlx::query("SELECT domain FROM routing.domains WHERE tenant_id = $1")
            .bind(tenant_id)
            .fetch_all(&self.pool)
            .await?;
        Ok(rows.into_iter().map(|r| r.get::<String, _>("domain")).collect())
    }
}

/// `LISTEN/NOTIFY`-backed invalidation feed. A dedicated listener connection is
/// opened per subscription (reopened by the caller on error).
pub struct PgInvalidations {
    url: String,
}

impl PgInvalidations {
    pub fn new(url: impl Into<String>) -> Self {
        Self { url: url.into() }
    }
}

#[async_trait]
impl Invalidations for PgInvalidations {
    async fn subscribe(&self) -> Result<InvalidationFeed, BoxError> {
        let mut listener = PgListener::connect(&self.url).await?;
        listener.listen(INVALIDATION_CHANNEL).await?;
        // Built over `recv()` so each yielded item is the notification payload
        // (the normalized domain key) or a recoverable error the caller reopens on.
        let stream = futures::stream::unfold(listener, |mut l| async move {
            let item = match l.recv().await {
                Ok(n) => Ok(n.payload().to_string()),
                Err(e) => Err(Box::new(e) as BoxError),
            };
            Some((item, l))
        });
        Ok(stream.boxed())
    }
}
