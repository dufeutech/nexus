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

use std::time::Duration;

use async_trait::async_trait;
use futures::stream::{unfold, StreamExt};
use sqlx::postgres::{PgConnectOptions, PgListener, PgPoolOptions};
use sqlx::{PgConnection, PgPool, Row};

use router_core::auth::{AuthPolicy, PathRule, RouteAuth};
use router_core::domain::{Pool, WorkspaceConfig};
use router_core::store::{
    Account, AccountMember, BoxError, Challenge, ChallengeStore, DomainRecord, InvalidationFeed,
    Invalidations, Membership, MembershipStore, OwnershipStore, RoutingStore,
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
            .statement_cache_capacity(0)
            // Cap any single statement server-side so a slow/stuck query can't
            // pin a pooled connection (and stall every coalesced waiter) forever.
            .options([("statement_timeout", "5000")]);
        let pool = PgPoolOptions::new()
            .max_connections(8)
            // Bound the wait for a free connection so pool exhaustion surfaces as
            // a fast error instead of an unbounded hang on the request path.
            .acquire_timeout(Duration::from_secs(5))
            .connect_with(opts)
            .await?;
        Ok(Self { pool })
    }

    /// Idempotent schema bootstrap. The control plane owns this on startup; the
    /// router only reads, so it never creates schema.
    ///
    /// There is no migration framework here (RFC decision 14: the routing plane
    /// reuses a store the control plane bootstraps): schema is created idempotently
    /// with `CREATE ... IF NOT EXISTS`. The BREAKING `tenant_id → workspace_id`
    /// rename (nexus-owned-workspace-tenancy) therefore ships as an explicit,
    /// guarded in-place migration for already-provisioned databases — `CREATE TABLE
    /// IF NOT EXISTS` alone would never alter an existing table — followed by the
    /// new-shape `CREATE`s that a fresh database gets directly.
    pub async fn init_schema(&self) -> Result<(), BoxError> {
        sqlx::query("CREATE SCHEMA IF NOT EXISTS routing")
            .execute(&self.pool)
            .await?;
        // --- BREAKING migration: tenant_id → workspace_id (guarded, idempotent).
        // Renames the pre-existing `tenants` table and every `tenant_id` column to
        // the workspace vocabulary. Postgres carries FK/PK constraints across a
        // RENAME automatically, so the FKs below need no rebuild. Each step is
        // guarded on the OLD name still existing, so this whole block is a no-op on
        // a fresh database (new-shape `CREATE`s below make it) and on an
        // already-migrated one (the old names are gone).
        sqlx::query(
            "DO $$ \
             BEGIN \
                 IF to_regclass('routing.tenants') IS NOT NULL THEN \
                     ALTER TABLE routing.tenants RENAME TO workspaces; \
                 END IF; \
                 IF EXISTS (SELECT 1 FROM information_schema.columns \
                            WHERE table_schema='routing' AND table_name='workspaces' \
                              AND column_name='tenant_id') THEN \
                     ALTER TABLE routing.workspaces RENAME COLUMN tenant_id TO workspace_id; \
                 END IF; \
                 IF EXISTS (SELECT 1 FROM information_schema.columns \
                            WHERE table_schema='routing' AND table_name='domains' \
                              AND column_name='tenant_id') THEN \
                     ALTER TABLE routing.domains RENAME COLUMN tenant_id TO workspace_id; \
                 END IF; \
                 IF EXISTS (SELECT 1 FROM information_schema.columns \
                            WHERE table_schema='routing' AND table_name='domain_challenges' \
                              AND column_name='tenant_id') THEN \
                     ALTER TABLE routing.domain_challenges RENAME COLUMN tenant_id TO workspace_id; \
                 END IF; \
                 IF EXISTS (SELECT 1 FROM information_schema.columns \
                            WHERE table_schema='routing' AND table_name='auth_routes' \
                              AND column_name='tenant_id') THEN \
                     ALTER TABLE routing.auth_routes RENAME COLUMN tenant_id TO workspace_id; \
                 END IF; \
             END $$",
        )
        .execute(&self.pool)
        .await?;
        // --- Ownership: an Account owns Workspaces and is a member container
        // (nexus-owned-workspace-tenancy). Created before `workspaces` so the
        // `workspace.account_id` FK resolves. `payer_ref` is the billing/payer of
        // record, which switches on a transfer (plan travels with the workspace,
        // payer travels with the account); nullable until billing is wired.
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS routing.accounts (\
                 account_id text PRIMARY KEY, \
                 name       text NOT NULL DEFAULT '', \
                 payer_ref  text, \
                 updated_at timestamptz NOT NULL DEFAULT now())",
        )
        .execute(&self.pool)
        .await?;
        // Account membership. Owner-only in v1 (roles beyond `owner` are additive);
        // a solo account is simply a one-member account (no personal|org type).
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS routing.account_members (\
                 account_id text NOT NULL REFERENCES routing.accounts(account_id) ON DELETE CASCADE, \
                 user_sub   text NOT NULL, \
                 role       text NOT NULL DEFAULT 'owner', \
                 updated_at timestamptz NOT NULL DEFAULT now(), \
                 PRIMARY KEY (account_id, user_sub))",
        )
        .execute(&self.pool)
        .await?;
        // Workspaces — the stable-ID routing pivot (formerly `tenants`). Fresh
        // databases get this shape directly; a migrated database already has the
        // renamed table, so this `CREATE IF NOT EXISTS` is a no-op and the
        // `ADD COLUMN IF NOT EXISTS` below backfills its `account_id`. `account_id`
        // is a plain reference (NOT cascade): deleting an account that still owns
        // workspaces must fail — transfer first — never silently drop routing.
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS routing.workspaces (\
                 workspace_id text PRIMARY KEY, \
                 account_id   text REFERENCES routing.accounts(account_id), \
                 plan         text NOT NULL DEFAULT 'free', \
                 target_pool  text NOT NULL DEFAULT 'application', \
                 features     text[] NOT NULL DEFAULT '{}', \
                 updated_at   timestamptz NOT NULL DEFAULT now())",
        )
        .execute(&self.pool)
        .await?;
        // Add `account_id` to a workspaces table migrated from the old `tenants`
        // (which had no ownership column). No-op on a fresh DB where the CREATE
        // above already included it; tied to column existence, so it is idempotent.
        sqlx::query(
            "ALTER TABLE routing.workspaces \
             ADD COLUMN IF NOT EXISTS account_id text REFERENCES routing.accounts(account_id)",
        )
        .execute(&self.pool)
        .await?;
        // Keyed by (domain, is_wildcard), NOT domain alone: a domain string may
        // exist as both an apex/exact row (is_wildcard=false) AND a
        // wildcard-subdomain row (is_wildcard=true) for the same workspace — the
        // apex+wildcard coexistence the explicit model forbids today but a future
        // wildcard tier needs (see nexus-upstream-requirements.md §N3). Choosing
        // the composite key now is free while the table is small; retrofitting it
        // onto a populated, hot table later is a migration we avoid by deciding it
        // here. The self-service lifecycle still only ever creates exact rows
        // (declare forces is_wildcard=false); wildcard rows are admin-seeded.
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS routing.domains (\
                 domain       text NOT NULL, \
                 workspace_id text NOT NULL REFERENCES routing.workspaces(workspace_id) ON DELETE CASCADE, \
                 is_wildcard  boolean NOT NULL DEFAULT false, \
                 verified     boolean NOT NULL DEFAULT false, \
                 updated_at   timestamptz NOT NULL DEFAULT now(), \
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
                 domain       text NOT NULL, \
                 is_wildcard  boolean NOT NULL DEFAULT false, \
                 workspace_id text NOT NULL, \
                 token        text NOT NULL, \
                 expires_at   timestamptz NOT NULL, \
                 updated_at   timestamptz NOT NULL DEFAULT now(), \
                 PRIMARY KEY (domain, is_wildcard), \
                 FOREIGN KEY (domain, is_wildcard) \
                     REFERENCES routing.domains(domain, is_wildcard) ON DELETE CASCADE)",
        )
        .execute(&self.pool)
        .await?;
        // Per-route authentication policy (RFC N4). One row per (workspace, path
        // prefix); the per-workspace default is the `prefix = '/'` row. Absence of
        // any row for a workspace is "public" (pass-through) — the read path returns
        // the default, so no backfill is needed when this table is introduced.
        // Cascades away with its workspace.
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS routing.auth_routes (\
                 workspace_id  text NOT NULL REFERENCES routing.workspaces(workspace_id) ON DELETE CASCADE, \
                 path_prefix   text NOT NULL, \
                 auth_required boolean NOT NULL, \
                 updated_at    timestamptz NOT NULL DEFAULT now(), \
                 PRIMARY KEY (workspace_id, path_prefix))",
        )
        .execute(&self.pool)
        .await?;
        // Memberships — the live authz source of record (nexus-owned-workspace-
        // tenancy): who acts in a workspace, as which type (staff|customer) and
        // role. The identity plane resolves it fail-closed on the hot path (behind
        // the `MembershipResolver` port); the control plane writes it here and it
        // rides the existing change feed. Keyed (user_sub, workspace_id) — a user
        // holds at most one membership per workspace. `member_type` is constrained
        // to the two modeled kinds; `status` is left open for the lifecycle
        // (active/suspended/…). Cascades away with its workspace.
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS routing.memberships (\
                 user_sub     text NOT NULL, \
                 workspace_id text NOT NULL REFERENCES routing.workspaces(workspace_id) ON DELETE CASCADE, \
                 member_type  text NOT NULL CHECK (member_type IN ('staff', 'customer')), \
                 role         text NOT NULL DEFAULT 'member', \
                 status       text NOT NULL DEFAULT 'active', \
                 updated_at   timestamptz NOT NULL DEFAULT now(), \
                 PRIMARY KEY (user_sub, workspace_id))",
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
        if !got {
            return Ok(None);
        }
        // Detach from the pool so the lease OWNS its connection. A session-level
        // advisory lock is released only when its session ends — so if a lease
        // dropped while still pooled, the connection would return to the pool
        // STILL holding the lock, and leadership would stay claimed (blocking
        // failover) until that physical connection happened to be recycled.
        // Owning the connection means dropping the lease closes the session,
        // which releases the lock promptly.
        Ok(Some(LeaderLease { conn: conn.detach() }))
    }
}

/// A held verification-poll leadership lease. Holding it keeps the advisory lock;
/// dropping it (or losing the connection) releases leadership so another instance
/// can take over — the lease owns its connection, so a drop ends the session and
/// Postgres releases the session-level advisory lock.
pub struct LeaderLease {
    conn: PgConnection,
}

impl LeaderLease {
    /// Cheap liveness ping. `false` means the lease's connection — and thus the
    /// lock — was lost; the caller MUST drop this lease and re-acquire.
    pub async fn alive(&mut self) -> bool {
        sqlx::query("SELECT 1").execute(&mut self.conn).await.is_ok()
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
            "SELECT workspace_id FROM routing.domains \
             WHERE domain = $1 AND is_wildcard = $2 AND verified = true",
        )
        .bind(domain)
        .bind(wildcard)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|r| r.get::<String, _>("workspace_id")))
    }

    async fn get_workspace(&self, workspace_id: &str) -> Result<Option<WorkspaceConfig>, BoxError> {
        let row = sqlx::query(
            "SELECT workspace_id, plan, target_pool, features, updated_at::text AS updated_at \
             FROM routing.workspaces WHERE workspace_id = $1",
        )
        .bind(workspace_id)
        .fetch_optional(&self.pool)
        .await?;
        let Some(r) = row else { return Ok(None) };
        // The read path trusts the stored selector: the control plane validated it
        // against the data-driven allow-list (PoolSet) at write time, so re-checking
        // here would only couple the store to that config. If a pool is later
        // removed from the allow-list, the edge route table's default cluster is the
        // backstop (an unknown x-route-pool falls through to `application`).
        let target: String = r.get("target_pool");
        Ok(Some(WorkspaceConfig {
            workspace_id: r.get("workspace_id"),
            plan: r.get("plan"),
            target_pool: Pool::new(target),
            features: r.get::<Vec<String>, _>("features"),
            updated_at: r.get::<Option<String>, _>("updated_at"),
        }))
    }

    async fn upsert_workspace(&self, cfg: &WorkspaceConfig) -> Result<(), BoxError> {
        sqlx::query(
            "INSERT INTO routing.workspaces (workspace_id, plan, target_pool, features, updated_at) \
             VALUES ($1, $2, $3, $4, now()) \
             ON CONFLICT (workspace_id) DO UPDATE SET \
                 plan = EXCLUDED.plan, target_pool = EXCLUDED.target_pool, \
                 features = EXCLUDED.features, updated_at = now()",
        )
        .bind(&cfg.workspace_id)
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
        workspace_id: &str,
        wildcard: bool,
        verified: bool,
    ) -> Result<(), BoxError> {
        sqlx::query(
            "INSERT INTO routing.domains (domain, workspace_id, is_wildcard, verified, updated_at) \
             VALUES ($1, $2, $3, $4, now()) \
             ON CONFLICT (domain, is_wildcard) DO UPDATE SET \
                 workspace_id = EXCLUDED.workspace_id, \
                 verified = EXCLUDED.verified, updated_at = now()",
        )
        .bind(domain)
        .bind(workspace_id)
        .bind(wildcard)
        .bind(verified)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn create_pending_domain(
        &self,
        domain: &str,
        workspace_id: &str,
    ) -> Result<bool, BoxError> {
        // INSERT ... ON CONFLICT DO NOTHING never reassigns an existing row's
        // workspace_id, so two workspaces racing the same new domain can't steal it:
        // the loser's insert is a no-op (rows_affected == 0) and the caller resolves
        // it as `domain_taken`. Exact (non-wildcard), unverified by construction.
        let res = sqlx::query(
            "INSERT INTO routing.domains (domain, workspace_id, is_wildcard, verified, updated_at) \
             VALUES ($1, $2, false, false, now()) \
             ON CONFLICT (domain, is_wildcard) DO NOTHING",
        )
        .bind(domain)
        .bind(workspace_id)
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected() > 0)
    }

    async fn set_domain_verified(&self, domain: &str, verified: bool) -> Result<(), BoxError> {
        sqlx::query(
            "UPDATE routing.domains SET verified = $2, updated_at = now() \
             WHERE domain = $1 AND is_wildcard = false",
        )
        .bind(domain)
        .bind(verified)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn delete_domain(&self, domain: &str, wildcard: bool) -> Result<(), BoxError> {
        sqlx::query("DELETE FROM routing.domains WHERE domain = $1 AND is_wildcard = $2")
            .bind(domain)
            .bind(wildcard)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn domains_for_workspace(&self, workspace_id: &str) -> Result<Vec<String>, BoxError> {
        let rows = sqlx::query("SELECT domain FROM routing.domains WHERE workspace_id = $1")
            .bind(workspace_id)
            .fetch_all(&self.pool)
            .await?;
        Ok(rows.into_iter().map(|r| r.get::<String, _>("domain")).collect())
    }

    async fn get_domain(
        &self,
        domain: &str,
        wildcard: bool,
    ) -> Result<Option<DomainRecord>, BoxError> {
        let row = sqlx::query(
            "SELECT workspace_id, is_wildcard, verified FROM routing.domains \
             WHERE domain = $1 AND is_wildcard = $2",
        )
        .bind(domain)
        .bind(wildcard)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|r| DomainRecord {
            workspace_id: r.get("workspace_id"),
            wildcard: r.get("is_wildcard"),
            verified: r.get("verified"),
        }))
    }

    async fn count_domains_for_workspace(&self, workspace_id: &str) -> Result<u32, BoxError> {
        // verified + pending: every row the workspace holds (RFC C3/I6).
        let row = sqlx::query("SELECT count(*) AS n FROM routing.domains WHERE workspace_id = $1")
            .bind(workspace_id)
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

    async fn get_auth_policy(&self, workspace_id: &str) -> Result<AuthPolicy, BoxError> {
        // Point read of the workspace's rule set. No rows -> the default (pass-
        // through) falls out of an empty `AuthPolicy`, so a workspace with no policy
        // is public.
        let rows = sqlx::query(
            "SELECT path_prefix, auth_required FROM routing.auth_routes WHERE workspace_id = $1",
        )
        .bind(workspace_id)
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
        workspace_id: &str,
        prefix: &str,
        required: bool,
    ) -> Result<(), BoxError> {
        sqlx::query(
            "INSERT INTO routing.auth_routes (workspace_id, path_prefix, auth_required, updated_at) \
             VALUES ($1, $2, $3, now()) \
             ON CONFLICT (workspace_id, path_prefix) DO UPDATE SET \
                 auth_required = EXCLUDED.auth_required, updated_at = now()",
        )
        .bind(workspace_id)
        .bind(prefix)
        .bind(required)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn delete_auth_route(&self, workspace_id: &str, prefix: &str) -> Result<(), BoxError> {
        sqlx::query("DELETE FROM routing.auth_routes WHERE workspace_id = $1 AND path_prefix = $2")
            .bind(workspace_id)
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
        workspace_id: &str,
        ttl_secs: i64,
    ) -> Result<Challenge, BoxError> {
        // Mint a fresh ownership-proof token: 256 bits from the OS CSPRNG (ring's
        // `SystemRandom`), hex-encoded (DNS-safe charset, so it drops straight into
        // a TXT record). Minted here in security-aware Rust rather than via SQL
        // `gen_random_uuid()` so the token's entropy does not depend on the
        // database build's RNG configuration.
        fn mint_challenge_token() -> Result<String, BoxError> {
            use ring::rand::{SecureRandom, SystemRandom};
            let mut bytes = [0_u8; 32];
            SystemRandom::new()
                .fill(&mut bytes)
                .map_err(|_| "csprng failure")?;
            Ok(hex::encode(bytes))
        }
        // Idempotent (RFC C3): insert a fresh token if absent; on conflict, keep
        // the existing token while it is live and re-issue only once expired
        // (RFC C4: re-issuable). RETURNING reflects the resulting row, so a
        // re-issue returns `expired = false`. The freshly minted $4 is used only
        // when inserting or re-issuing an expired row; a live row keeps its token.
        // is_wildcard is fixed false: a challenge always proves the EXACT declared
        // domain (the only thing self-service declares), so it keys to the
        // (domain, false) row the declare flow created just before this call.
        let token = mint_challenge_token()?;
        let row = sqlx::query(
            "INSERT INTO routing.domain_challenges (domain, is_wildcard, workspace_id, token, expires_at, updated_at) \
             VALUES ($1, false, $2, $4, now() + make_interval(secs => $3), now()) \
             ON CONFLICT (domain, is_wildcard) DO UPDATE SET \
                 token = CASE WHEN routing.domain_challenges.expires_at < now() \
                              THEN $4 \
                              ELSE routing.domain_challenges.token END, \
                 expires_at = CASE WHEN routing.domain_challenges.expires_at < now() \
                              THEN now() + make_interval(secs => $3) \
                              ELSE routing.domain_challenges.expires_at END, \
                 workspace_id = EXCLUDED.workspace_id, \
                 updated_at = now() \
             RETURNING domain, token, (expires_at < now()) AS expired",
        )
        .bind(domain)
        .bind(workspace_id)
        .bind(ttl_secs as f64)
        .bind(&token)
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

#[async_trait]
impl OwnershipStore for PgRoutingStore {
    async fn create_account(
        &self,
        account_id: &str,
        name: &str,
        payer_ref: Option<&str>,
    ) -> Result<bool, BoxError> {
        // Idempotent provision (ON CONFLICT DO NOTHING): a repeat signup for an
        // already-provisioned account is a no-op and never clobbers its name/payer.
        let res = sqlx::query(
            "INSERT INTO routing.accounts (account_id, name, payer_ref, updated_at) \
             VALUES ($1, $2, $3, now()) \
             ON CONFLICT (account_id) DO NOTHING",
        )
        .bind(account_id)
        .bind(name)
        .bind(payer_ref)
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected() > 0)
    }

    async fn get_account(&self, account_id: &str) -> Result<Option<Account>, BoxError> {
        let row = sqlx::query(
            "SELECT account_id, name, payer_ref, updated_at::text AS updated_at \
             FROM routing.accounts WHERE account_id = $1",
        )
        .bind(account_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|r| Account {
            account_id: r.get("account_id"),
            name: r.get("name"),
            payer_ref: r.get::<Option<String>, _>("payer_ref"),
            updated_at: r.get::<Option<String>, _>("updated_at"),
        }))
    }

    async fn add_account_member(
        &self,
        account_id: &str,
        user_sub: &str,
        role: &str,
    ) -> Result<(), BoxError> {
        sqlx::query(
            "INSERT INTO routing.account_members (account_id, user_sub, role, updated_at) \
             VALUES ($1, $2, $3, now()) \
             ON CONFLICT (account_id, user_sub) DO UPDATE SET \
                 role = EXCLUDED.role, updated_at = now()",
        )
        .bind(account_id)
        .bind(user_sub)
        .bind(role)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn account_members(&self, account_id: &str) -> Result<Vec<AccountMember>, BoxError> {
        let rows = sqlx::query(
            "SELECT account_id, user_sub, role FROM routing.account_members WHERE account_id = $1",
        )
        .bind(account_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| AccountMember {
                account_id: r.get("account_id"),
                user_sub: r.get("user_sub"),
                role: r.get("role"),
            })
            .collect())
    }

    async fn set_workspace_account(
        &self,
        workspace_id: &str,
        account_id: &str,
    ) -> Result<bool, BoxError> {
        // Create-time ownership assignment: repoint ONLY `account_id`, no staff
        // reset (a brand-new workspace has none). An ownership CHANGE goes through
        // `transfer_workspace`, which also resets staff atomically.
        let res = sqlx::query(
            "UPDATE routing.workspaces SET account_id = $2, updated_at = now() \
             WHERE workspace_id = $1",
        )
        .bind(workspace_id)
        .bind(account_id)
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected() > 0)
    }

    async fn transfer_workspace(
        &self,
        workspace_id: &str,
        account_id: &str,
    ) -> Result<Option<u64>, BoxError> {
        // One transaction: repoint ownership AND reset staff together, so a crash
        // between the two can never leave the previous owner's staff with access.
        // Customer memberships (member_type <> 'staff') are deliberately left, and
        // domains/data ride through on the unchanged workspace_id.
        let mut tx = self.pool.begin().await?;
        let moved = sqlx::query(
            "UPDATE routing.workspaces SET account_id = $2, updated_at = now() \
             WHERE workspace_id = $1",
        )
        .bind(workspace_id)
        .bind(account_id)
        .execute(&mut *tx)
        .await?;
        if moved.rows_affected() == 0 {
            // Unknown workspace — nothing to transfer; roll back so no partial state.
            tx.rollback().await?;
            return Ok(None);
        }
        let cleared = sqlx::query(
            "DELETE FROM routing.memberships WHERE workspace_id = $1 AND member_type = 'staff'",
        )
        .bind(workspace_id)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(Some(cleared.rows_affected()))
    }
}

#[async_trait]
impl MembershipStore for PgRoutingStore {
    async fn upsert_membership(&self, m: &Membership) -> Result<(), BoxError> {
        sqlx::query(
            "INSERT INTO routing.memberships \
                 (user_sub, workspace_id, member_type, role, status, updated_at) \
             VALUES ($1, $2, $3, $4, $5, now()) \
             ON CONFLICT (user_sub, workspace_id) DO UPDATE SET \
                 member_type = EXCLUDED.member_type, role = EXCLUDED.role, \
                 status = EXCLUDED.status, updated_at = now()",
        )
        .bind(&m.user_sub)
        .bind(&m.workspace_id)
        .bind(&m.member_type)
        .bind(&m.role)
        .bind(&m.status)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn delete_membership(
        &self,
        user_sub: &str,
        workspace_id: &str,
    ) -> Result<(), BoxError> {
        sqlx::query(
            "DELETE FROM routing.memberships WHERE user_sub = $1 AND workspace_id = $2",
        )
        .bind(user_sub)
        .bind(workspace_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn memberships_for_workspace(
        &self,
        workspace_id: &str,
    ) -> Result<Vec<Membership>, BoxError> {
        let rows = sqlx::query(
            "SELECT user_sub, workspace_id, member_type, role, status \
             FROM routing.memberships WHERE workspace_id = $1",
        )
        .bind(workspace_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| Membership {
                user_sub: r.get("user_sub"),
                workspace_id: r.get("workspace_id"),
                member_type: r.get("member_type"),
                role: r.get("role"),
                status: r.get("status"),
            })
            .collect())
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
