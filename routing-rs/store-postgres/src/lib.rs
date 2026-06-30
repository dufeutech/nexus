//! `PostgreSQL` adapter for the `RoutingStore` + `Invalidations` ports
//! (RFC §3.10/§3.11/§3.13, C16).
//!
//! - The authoritative routing state is written by the control plane and read
//!   (point lookups only) by the tenant-router. Reuses the lab's existing
//!   Postgres server under a dedicated `routing` schema so it never collides
//!   with the `IdP`'s own tables (RFC decision 14: the routing plane reuses an
//!   authoritative store the control plane writes).
//! - Invalidation is delivered over Postgres `LISTEN/NOTIFY`: every control-plane
//!   mutation issues `pg_notify('routing_invalidations', <domain>)`; the router
//!   subscribes and evicts that key from every cache tier (RFC C16). LISTEN/NOTIFY
//!   is sufficient here because routing has no per-second revocation requirement
//!   (decision 14) — a missed signal self-heals within the cache staleness bound.
//! - All access is point-read/point-write by key (no request-path scans, §3.10).

use async_trait::async_trait;
use futures::stream::{unfold, StreamExt};
use sqlx::pool::PoolConnection;
use sqlx::postgres::{PgConnectOptions, PgListener, PgPoolOptions};
use sqlx::{PgPool, Postgres, Row};

use router_core::auth::{AuthPolicy, PathRule, RouteAuth};
use router_core::domain::{Pool, TenantConfig};
use router_core::store::{
    BoxError, Challenge, ChallengeStore, DomainRecord, InvalidationFeed, Invalidations, RoutingStore,
};

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
        // Keyed by (domain, is_wildcard), NOT domain alone: a domain string may
        // exist as both an apex/exact row (is_wildcard=false) AND a
        // wildcard-subdomain row (is_wildcard=true) for the same tenant — the
        // apex+wildcard coexistence the explicit model forbids today but a future
        // wildcard tier needs (see nexus-upstream-requirements.md §N3). Choosing
        // the composite key now is free while the table is small; retrofitting it
        // onto a populated, hot table later is a migration we avoid by deciding it
        // here. The self-service lifecycle still only ever creates exact rows
        // (declare forces is_wildcard=false); wildcard rows are admin-seeded.
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS routing.domains (\
                 domain      text NOT NULL, \
                 tenant_id   text NOT NULL REFERENCES routing.tenants(tenant_id) ON DELETE CASCADE, \
                 is_wildcard boolean NOT NULL DEFAULT false, \
                 verified    boolean NOT NULL DEFAULT false, \
                 updated_at  timestamptz NOT NULL DEFAULT now(), \
                 PRIMARY KEY (domain, is_wildcard))",
        )
        .execute(&self.pool)
        .await?;
        // Ownership-proof challenges (RFC C4). Separate from `domains` so the
        // challenge lifecycle never touches the hot read path; cascades away with
        // its domain. `gen_random_uuid()` is built in (no extension). Carries
        // is_wildcard so the FK can reference the composite domains key and the
        // cascade survives; a challenge belongs to the EXACT declared variant
        // (is_wildcard=false), since only self-service exact declares are ever
        // challenged (wildcard rows are admin-seeded already-verified).
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS routing.domain_challenges (\
                 domain      text NOT NULL, \
                 is_wildcard boolean NOT NULL DEFAULT false, \
                 tenant_id   text NOT NULL, \
                 token       text NOT NULL, \
                 expires_at  timestamptz NOT NULL, \
                 updated_at  timestamptz NOT NULL DEFAULT now(), \
                 PRIMARY KEY (domain, is_wildcard), \
                 FOREIGN KEY (domain, is_wildcard) \
                     REFERENCES routing.domains(domain, is_wildcard) ON DELETE CASCADE)",
        )
        .execute(&self.pool)
        .await?;
        // Per-route authentication policy (RFC N4). One row per (tenant, path
        // prefix); the per-tenant default is the `prefix = '/'` row. Absence of any
        // row for a tenant is "public" (pass-through) — the read path returns the
        // default, so no backfill is needed when this table is introduced. Cascades
        // away with its tenant.
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS routing.auth_routes (\
                 tenant_id     text NOT NULL REFERENCES routing.tenants(tenant_id) ON DELETE CASCADE, \
                 path_prefix   text NOT NULL, \
                 auth_required boolean NOT NULL, \
                 updated_at    timestamptz NOT NULL DEFAULT now(), \
                 PRIMARY KEY (tenant_id, path_prefix))",
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

    /// Try to claim the singleton verification-poll leadership via a session-level
    /// advisory lock held on a dedicated connection (RFC C4): only one
    /// control-plane instance polls, so replicas don't all resolve DNS for every
    /// pending domain. `Some(lease)` if claimed (hold it to keep leadership — the
    /// lock frees when the lease drops or the connection dies, enabling
    /// failover), `None` if another instance already leads. Coordination is an
    /// infra concern, so it lives in this adapter, not the vendor-free core
    /// (rules §2/§5).
    pub async fn try_acquire_leader(&self, key: i64) -> Result<Option<LeaderLease>, BoxError> {
        let mut conn = self.pool.acquire().await?;
        let got: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock($1)")
            .bind(key)
            .fetch_one(&mut *conn)
            .await?;
        Ok(got.then(|| LeaderLease { conn }))
    }
}

/// A held verification-poll leadership lease. Holding it keeps the advisory lock;
/// dropping it (or losing the connection) releases leadership so another instance
/// can take over.
pub struct LeaderLease {
    conn: PoolConnection<Postgres>,
}

impl LeaderLease {
    /// Cheap liveness ping. `false` means the lease's connection — and thus the
    /// lock — was lost; the caller MUST drop this lease and re-acquire.
    pub async fn alive(&mut self) -> bool {
        sqlx::query("SELECT 1").execute(&mut *self.conn).await.is_ok()
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
        // The read path trusts the stored selector: the control plane validated it
        // against the data-driven allow-list (PoolSet) at write time, so re-checking
        // here would only couple the store to that config. If a pool is later
        // removed from the allow-list, the edge route table's default cluster is the
        // backstop (an unknown x-route-pool falls through to `application`).
        let target: String = r.get("target_pool");
        Ok(Some(TenantConfig {
            tenant_id: r.get("tenant_id"),
            plan: r.get("plan"),
            target_pool: Pool::new(target),
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
             ON CONFLICT (domain, is_wildcard) DO UPDATE SET \
                 tenant_id = EXCLUDED.tenant_id, \
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

    async fn get_domain(&self, domain: &str) -> Result<Option<DomainRecord>, BoxError> {
        let row = sqlx::query(
            "SELECT tenant_id, is_wildcard, verified FROM routing.domains WHERE domain = $1",
        )
        .bind(domain)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|r| DomainRecord {
            tenant_id: r.get("tenant_id"),
            wildcard: r.get("is_wildcard"),
            verified: r.get("verified"),
        }))
    }

    async fn count_domains_for_tenant(&self, tenant_id: &str) -> Result<u32, BoxError> {
        // verified + pending: every row the tenant holds (RFC C3/I6).
        let row = sqlx::query("SELECT count(*) AS n FROM routing.domains WHERE tenant_id = $1")
            .bind(tenant_id)
            .fetch_one(&self.pool)
            .await?;
        let n: i64 = row.get("n");
        Ok(n.max(0) as u32)
    }

    async fn pending_domains(&self) -> Result<Vec<String>, BoxError> {
        let rows = sqlx::query("SELECT domain FROM routing.domains WHERE verified = false")
            .fetch_all(&self.pool)
            .await?;
        Ok(rows.into_iter().map(|r| r.get::<String, _>("domain")).collect())
    }

    async fn expire_pending_domains(&self, ttl_secs: i64) -> Result<Vec<String>, BoxError> {
        // `updated_at` for a pending row is its declare time (an idempotent
        // re-declare touches only the challenge, not this row). The challenge
        // cascades away with the domain.
        let rows = sqlx::query(
            "DELETE FROM routing.domains \
             WHERE verified = false AND updated_at < now() - make_interval(secs => $1) \
             RETURNING domain",
        )
        .bind(ttl_secs as f64)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(|r| r.get::<String, _>("domain")).collect())
    }

    async fn get_auth_policy(&self, tenant_id: &str) -> Result<AuthPolicy, BoxError> {
        // Point read of the tenant's rule set. No rows -> the default (pass-through)
        // falls out of an empty `AuthPolicy`, so a tenant with no policy is public.
        let rows = sqlx::query(
            "SELECT path_prefix, auth_required FROM routing.auth_routes WHERE tenant_id = $1",
        )
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await?;
        let rules = rows
            .into_iter()
            .map(|r| PathRule {
                prefix: r.get::<String, _>("path_prefix"),
                auth: RouteAuth { required: r.get::<bool, _>("auth_required") },
            })
            .collect();
        Ok(AuthPolicy::new(rules))
    }

    async fn upsert_auth_route(
        &self,
        tenant_id: &str,
        prefix: &str,
        required: bool,
    ) -> Result<(), BoxError> {
        sqlx::query(
            "INSERT INTO routing.auth_routes (tenant_id, path_prefix, auth_required, updated_at) \
             VALUES ($1, $2, $3, now()) \
             ON CONFLICT (tenant_id, path_prefix) DO UPDATE SET \
                 auth_required = EXCLUDED.auth_required, updated_at = now()",
        )
        .bind(tenant_id)
        .bind(prefix)
        .bind(required)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn delete_auth_route(&self, tenant_id: &str, prefix: &str) -> Result<(), BoxError> {
        sqlx::query("DELETE FROM routing.auth_routes WHERE tenant_id = $1 AND path_prefix = $2")
            .bind(tenant_id)
            .bind(prefix)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

#[async_trait]
impl ChallengeStore for PgRoutingStore {
    async fn mint_or_get_challenge(
        &self,
        domain: &str,
        tenant_id: &str,
        ttl_secs: i64,
    ) -> Result<Challenge, BoxError> {
        // Idempotent (RFC C3): insert a fresh token if absent; on conflict, keep
        // the existing token while it is live and re-issue only once expired
        // (RFC C4: re-issuable). RETURNING reflects the resulting row, so a
        // re-issue returns `expired = false`.
        // is_wildcard is fixed false: a challenge always proves the EXACT declared
        // domain (the only thing self-service declares), so it keys to the
        // (domain, false) row the declare flow created just before this call.
        let row = sqlx::query(
            "INSERT INTO routing.domain_challenges (domain, is_wildcard, tenant_id, token, expires_at, updated_at) \
             VALUES ($1, false, $2, replace(gen_random_uuid()::text, '-', ''), now() + make_interval(secs => $3), now()) \
             ON CONFLICT (domain, is_wildcard) DO UPDATE SET \
                 token = CASE WHEN routing.domain_challenges.expires_at < now() \
                              THEN replace(gen_random_uuid()::text, '-', '') \
                              ELSE routing.domain_challenges.token END, \
                 expires_at = CASE WHEN routing.domain_challenges.expires_at < now() \
                              THEN now() + make_interval(secs => $3) \
                              ELSE routing.domain_challenges.expires_at END, \
                 tenant_id = EXCLUDED.tenant_id, \
                 updated_at = now() \
             RETURNING domain, token, (expires_at < now()) AS expired",
        )
        .bind(domain)
        .bind(tenant_id)
        .bind(ttl_secs as f64)
        .fetch_one(&self.pool)
        .await?;
        Ok(Challenge {
            domain: row.get("domain"),
            token: row.get("token"),
            expired: row.get("expired"),
        })
    }

    async fn get_challenge(&self, domain: &str) -> Result<Option<Challenge>, BoxError> {
        let row = sqlx::query(
            "SELECT domain, token, (expires_at < now()) AS expired \
             FROM routing.domain_challenges WHERE domain = $1 AND is_wildcard = false",
        )
        .bind(domain)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|r| Challenge {
            domain: r.get("domain"),
            token: r.get("token"),
            expired: r.get("expired"),
        }))
    }

    async fn delete_challenge(&self, domain: &str) -> Result<(), BoxError> {
        sqlx::query("DELETE FROM routing.domain_challenges WHERE domain = $1 AND is_wildcard = false")
            .bind(domain)
            .execute(&self.pool)
            .await?;
        Ok(())
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
        let stream = unfold(listener, |mut l| async move {
            let item = match l.recv().await {
                Ok(n) => Ok(n.payload().to_owned()),
                Err(e) => Err(Box::new(e) as BoxError),
            };
            Some((item, l))
        });
        Ok(stream.boxed())
    }
}
