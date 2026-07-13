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

use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::{PgConnection, PgPool};

use router_core::store::BoxError;

mod admin_audit;
mod challenge_store;
mod invalidations;
mod membership_store;
mod ownership_store;
mod routing_store;

pub use admin_audit::{AdminTokenHasher, IssuedAdminToken, PgAdminTokenStore, PgAuditMaintenance};
pub use invalidations::PgInvalidations;

/// The NOTIFY channel the control plane publishes invalidations on.
pub const INVALIDATION_CHANNEL: &str = "routing_invalidations";

/// The NOTIFY channel the control plane publishes membership changes on. The
/// identity plane's membership-sync worker LISTENs here to refresh its Profile
/// projection. Best-effort (like invalidations): the payload is just the affected
/// `user_sub` — a hint to re-read the source of record, never the authoritative
/// state — and a missed signal self-heals via the reconcile backstop.
pub const MEMBERSHIP_CHANNEL: &str = "routing_membership_changes";

#[derive(Clone)]
pub struct PgRoutingStore {
    pub(crate) pool: PgPool,
}

/// Open a pooler-safe pool with `max` connections.
///
/// Disables sqlx's prepared-statement cache so the pool is safe through a
/// transaction-mode pooler (PgBouncer): cached prepared statements break there
/// ("prepared statement already exists"). The router's read pool may point at
/// such a pooler (`ROUTING_PG_READ_URL`); the queries here are trivial point
/// reads, so the cache buys nothing and turning it off makes the pool
/// pooler-safe everywhere. The LISTEN feed is a separate connection and is
/// never pooled — see `PgInvalidations`. A server-side statement timeout caps
/// any single statement so a slow/stuck query can't pin a pooled connection
/// (and stall every coalesced waiter) forever, and the acquire timeout bounds
/// the wait for a free connection so pool exhaustion surfaces as a fast error
/// instead of an unbounded hang.
pub(crate) async fn connect_pool(url: &str, max: u32) -> Result<PgPool, BoxError> {
    let opts = url
        .parse::<PgConnectOptions>()?
        .statement_cache_capacity(0)
        .options([("statement_timeout", "5000")]);
    let pool = PgPoolOptions::new()
        .max_connections(max)
        .acquire_timeout(Duration::from_secs(5))
        .connect_with(opts)
        .await?;
    Ok(pool)
}

impl PgRoutingStore {
    pub async fn connect(url: &str) -> Result<Self, BoxError> {
        Ok(Self { pool: connect_pool(url, 8).await? })
    }

    /// Open a handle WITHOUT probing the database (connections are established
    /// on first use, so every query against an unreachable server errors).
    /// For tests that must exercise store-failure paths (e.g. "a failed denial
    /// write still returns 401"); services use [`PgRoutingStore::connect`].
    pub fn connect_lazy(url: &str) -> Result<Self, BoxError> {
        let opts = url.parse::<PgConnectOptions>()?.statement_cache_capacity(0);
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(Duration::from_secs(5))
            .connect_lazy_with(opts);
        Ok(Self { pool })
    }

    /// Idempotent schema bootstrap. The control plane owns this on startup; the
    /// router only reads, so it never creates schema.
    ///
    /// There is no migration framework here (RFC decision 14: the routing plane
    /// reuses a store the control plane bootstraps): schema is created idempotently
    /// with `CREATE ... IF NOT EXISTS`. A pre-server-minted-ids lab database (old
    /// column set) is NOT migrated in place — recreate it via the compose stack's
    /// normal volume reset (greenfield: 0 deployments, server-minted-ids design).
    pub async fn init_schema(&self) -> Result<(), BoxError> {
        sqlx::query("CREATE SCHEMA IF NOT EXISTS routing")
            .execute(&self.pool)
            .await?;
        // --- Ownership: an Account owns Workspaces and is a member container
        // (nexus-owned-workspace-tenancy). Created before `workspaces` so the
        // `workspace.account_id` FK resolves. `payer_ref` is the billing/payer of
        // record, which switches on a transfer (plan travels with the workspace,
        // payer travels with the account); nullable until billing is wired.
        // `idempotency_key` is the caller's replay guard (provisioning-idempotency):
        // UNIQUE but nullable — Postgres treats NULLs as distinct, so a keyless
        // create never conflicts and the key stays genuinely optional.
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS routing.accounts (\
                 account_id      text PRIMARY KEY, \
                 name            text NOT NULL DEFAULT '', \
                 payer_ref       text, \
                 idempotency_key text UNIQUE, \
                 updated_at      timestamptz NOT NULL DEFAULT now())",
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
        // Workspaces — the stable-ID routing pivot. `account_id` is a plain
        // reference (NOT cascade): deleting an account that still owns workspaces
        // must fail — transfer first — never silently drop routing. `name` is the
        // display label (workspace-tenancy: NO identity or uniqueness semantics);
        // `idempotency_key` mirrors the accounts column above.
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS routing.workspaces (\
                 workspace_id    text PRIMARY KEY, \
                 account_id      text REFERENCES routing.accounts(account_id), \
                 name            text NOT NULL DEFAULT '', \
                 plan            text NOT NULL DEFAULT 'free', \
                 target_pool     text NOT NULL DEFAULT 'application', \
                 features        text[] NOT NULL DEFAULT '{}', \
                 idempotency_key text UNIQUE, \
                 updated_at      timestamptz NOT NULL DEFAULT now())",
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
        // Phase-2 requirement fields (N4): optional per-rule role / entitlement /
        // minimum-AAL. NULL = no requirement = the phase-1 behavior, so the
        // additive columns are inert for existing rows and phase-1 binaries.
        sqlx::query(
            "ALTER TABLE routing.auth_routes \
                 ADD COLUMN IF NOT EXISTS requires_role text, \
                 ADD COLUMN IF NOT EXISTS requires_entitlement text, \
                 ADD COLUMN IF NOT EXISTS min_aal smallint",
        )
        .execute(&self.pool)
        .await?;
        // identity-existence-hiding: mark a protected route as account-scoped
        // (reachable without a workspace membership). Additive + defaulted false, so
        // existing rows and phase-1/2 binaries are unaffected — a protected route is
        // workspace-scoped (membership-gated) unless a rule explicitly opts out.
        sqlx::query(
            "ALTER TABLE routing.auth_routes \
                 ADD COLUMN IF NOT EXISTS account_scoped boolean NOT NULL DEFAULT false",
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
        // Admin audit ledger (admin-action-audit D1/D3): every mutating admin
        // action records one event IN THE SAME TRANSACTION as the mutation.
        // Append-only: the application has no UPDATE/DELETE over this table, and
        // migrations/0002_admin_audit.sql withholds those grants from the service
        // role (this bootstrap mirrors tables only — roles/grants are deployment
        // DDL). `event_id` is `aev_<uuidv7>`, so PK order IS time order.
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS routing.admin_audit_events (\
                 event_id          text PRIMARY KEY, \
                 occurred_at       timestamptz NOT NULL DEFAULT now(), \
                 surface           text NOT NULL, \
                 action            text NOT NULL, \
                 actor_token_id    text NOT NULL, \
                 asserted_operator text, \
                 target_kind       text, \
                 target_id         text, \
                 outcome           text NOT NULL, \
                 detail            jsonb NOT NULL DEFAULT '{}'::jsonb, \
                 trace_id          text, \
                 source_ip         text, \
                 idempotency_key   text)",
        )
        .execute(&self.pool)
        .await?;
        // The read surface filters by time, actor, and target (design D6).
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS admin_audit_events_time_idx \
             ON routing.admin_audit_events (occurred_at)",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS admin_audit_events_actor_idx \
             ON routing.admin_audit_events (actor_token_id, event_id)",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS admin_audit_events_target_idx \
             ON routing.admin_audit_events (target_id, event_id)",
        )
        .execute(&self.pool)
        .await?;
        // Named admin credentials (admin-action-audit D4): one row per caller,
        // peppered-HMAC hash only (never the secret), rotation lineage via
        // `rotated_from`, revocation as a status flip.
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS routing.admin_tokens (\
                 token_id     text PRIMARY KEY, \
                 name         text NOT NULL, \
                 token_hash   text NOT NULL UNIQUE, \
                 status       text NOT NULL DEFAULT 'active', \
                 rotated_from text, \
                 created_at   timestamptz NOT NULL DEFAULT now(), \
                 updated_at   timestamptz NOT NULL DEFAULT now())",
        )
        .execute(&self.pool)
        .await?;
        // The per-request verification lookup: by hash, active only.
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS admin_tokens_active_hash_idx \
             ON routing.admin_tokens (token_hash) WHERE status = 'active'",
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

    /// Publish a membership-change signal for a subject on [`MEMBERSHIP_CHANNEL`].
    /// Called by the control plane after a membership upsert/delete commits. The
    /// payload carries only `user_sub` (a hint); the identity consumer re-reads the
    /// source of record to derive the subject's full membership set, so a coalesced
    /// or lost signal costs latency, never correctness (the reconcile backstop heals
    /// it). Best-effort by design — never blocks or fails the CRUD write.
    pub async fn notify_membership_change(&self, user_sub: &str) -> Result<(), BoxError> {
        sqlx::query("SELECT pg_notify($1, $2)")
            .bind(MEMBERSHIP_CHANNEL)
            .bind(user_sub)
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
