//! Admin audit ledger + named admin tokens — Postgres adapter for the identity
//! plane (admin-action-audit D1–D7), the twin of routing-rs's `admin_audit.rs`.
//!
//! The ledger (`identity.admin_audit_events`) is written by [`record`] INSIDE
//! the same transaction as the mutation it describes — the fail-closed
//! invariant ("unrecorded ⇒ uncommitted") lives here, where the transaction
//! lives. Denials have no transaction (nothing mutated), so they use a
//! standalone best-effort insert. Append-only: this adapter has no
//! UPDATE/DELETE over events, and `migrations/0003_admin_audit.sql` withholds
//! those grants from the service role; retention purge (the only deleter) runs
//! under the separate maintenance role via [`PgAuditMaintenance`].
//!
//! Named admin tokens (`identity.admin_tokens`, design D4) extend the proven
//! customer-api-keys machinery: the same peppered-HMAC [`SecretHasher`], a
//! UNIQUE hash index for one-lookup verification, rotation lineage, and
//! status-flip revocation.

use std::fmt;
use std::sync::Arc;

use serde_json::{json, Value};
use sqlx::postgres::PgRow;
use sqlx::{PgPool, Row};

use identity_core::audit::{
    is_known_action, AuditCtx, AuditEventRecord, AuditQuery, DenialEvent, InvalidQueryBound,
    ACTION_ADMIN_TOKEN_ISSUE, ACTION_ADMIN_TOKEN_REVOKE, ACTION_ADMIN_TOKEN_ROTATE,
    ACTION_AUTH_DENIED, ACTOR_UNAUTHENTICATED, OUTCOME_OK, SURFACE_AUTHZ_ADMIN,
};
use identity_core::ids::mint_audit_event_id;
use identity_core::store::BoxError;
use identity_core::SecretHasher;

use crate::api_keys::connect_pool;

/// One audit event as a mutation transaction records it: the action semantics
/// the store method owns. Transport facts ride in via [`AuditCtx`]; the id is
/// minted and the time stamped at insert.
pub(crate) struct NewAuditEvent<'a> {
    pub(crate) action: &'static str,
    pub(crate) target_kind: &'a str,
    pub(crate) target_id: &'a str,
    /// `ok`, `replay`, or an error class.
    pub(crate) outcome: &'a str,
    /// Request semantics minus secrets. NEVER a bearer token, api-key
    /// plaintext, hash, or key material.
    pub(crate) detail: Value,
    pub(crate) idempotency_key: Option<&'a str>,
}

/// Insert one audit event on `executor` — called with the mutation's own
/// transaction so the event commits (or rolls back) WITH the mutation
/// (design D2). Refuses an action outside the closed vocabulary.
pub(crate) async fn record<'e, E>(
    executor: E,
    actx: &AuditCtx,
    event: &NewAuditEvent<'_>,
) -> Result<(), BoxError>
where
    E: sqlx::Executor<'e, Database = sqlx::Postgres>,
{
    if !is_known_action(event.action) {
        return Err(format!("audit action '{}' is not in the closed vocabulary", event.action).into());
    }
    sqlx::query(
        "INSERT INTO identity.admin_audit_events \
             (event_id, occurred_at, surface, action, actor_token_id, asserted_operator, \
              target_kind, target_id, outcome, detail, trace_id, source_ip, idempotency_key) \
         VALUES ($1, now(), $2, $3, $4, $5, $6, $7, $8, $9::jsonb, $10, $11, $12)",
    )
    .bind(mint_audit_event_id())
    .bind(SURFACE_AUTHZ_ADMIN)
    .bind(event.action)
    .bind(&actx.actor)
    .bind(actx.asserted_operator.as_deref())
    .bind(event.target_kind)
    .bind(event.target_id)
    .bind(event.outcome)
    .bind(event.detail.to_string())
    .bind(actx.trace_id.as_deref())
    .bind(actx.source_ip.as_deref())
    .bind(event.idempotency_key)
    .execute(executor)
    .await?;
    Ok(())
}

/// Map a Postgres data exception (SQLSTATE class 22 — e.g. an unparseable
/// `from`/`to` timestamp) to the typed [`InvalidQueryBound`] so the read
/// surface answers 400, not 500, for a malformed filter.
fn classify_query_error(err: sqlx::Error) -> BoxError {
    if let sqlx::Error::Database(db) = &err
        && db.code().is_some_and(|code| code.starts_with("22"))
    {
        return Box::new(InvalidQueryBound);
    }
    Box::new(err)
}

/// Decode one ledger row into the core record shape.
fn row_to_record(row: &PgRow) -> Result<AuditEventRecord, BoxError> {
    let detail: String = row.try_get("detail")?;
    Ok(AuditEventRecord {
        event_id: row.try_get("event_id")?,
        occurred_at: row.try_get("occurred_at")?,
        surface: row.try_get("surface")?,
        action: row.try_get("action")?,
        actor_token_id: row.try_get("actor_token_id")?,
        asserted_operator: row.try_get("asserted_operator")?,
        target_kind: row.try_get("target_kind")?,
        target_id: row.try_get("target_id")?,
        outcome: row.try_get("outcome")?,
        detail: serde_json::from_str(&detail)?,
        trace_id: row.try_get("trace_id")?,
        source_ip: row.try_get("source_ip")?,
        idempotency_key: row.try_get("idempotency_key")?,
    })
}

/// The identity plane's audit surface: schema bootstrap, best-effort denial
/// inserts, and the read/query path (design D6). Shares the identity database
/// (`PROFILE_PG_URL`); its pool is also lent to [`PgAdminTokenStore`].
#[derive(Clone)]
pub struct PgAdminAuditStore {
    pool: PgPool,
}

impl fmt::Debug for PgAdminAuditStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PgAdminAuditStore").finish_non_exhaustive()
    }
}

impl PgAdminAuditStore {
    /// Open the audit pool (small — denial inserts + review queries).
    pub async fn connect(url: &str) -> Result<Self, BoxError> {
        Ok(Self { pool: connect_pool(url, 4).await? })
    }

    /// Idempotent schema bootstrap for the ledger + admin-token tables, run by
    /// authz-admin at startup. Tables only — the append-only grants and the
    /// maintenance role are deployment DDL (`migrations/0003_admin_audit.sql`;
    /// keep the two in lockstep).
    pub async fn init_schema(&self) -> Result<(), BoxError> {
        sqlx::query("CREATE SCHEMA IF NOT EXISTS identity")
            .execute(&self.pool)
            .await?;
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS identity.admin_audit_events (\
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
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS admin_audit_events_time_idx \
             ON identity.admin_audit_events (occurred_at)",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS admin_audit_events_actor_idx \
             ON identity.admin_audit_events (actor_token_id, event_id)",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS admin_audit_events_target_idx \
             ON identity.admin_audit_events (target_id, event_id)",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS identity.admin_tokens (\
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
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS admin_tokens_active_hash_idx \
             ON identity.admin_tokens (token_hash) WHERE status = 'active'",
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Best-effort denial record for the 401 path (spec: "Denied admin access
    /// is recorded"). No mutation transaction exists, so this is a standalone
    /// insert; the CALLER treats a failure as log-and-continue — a failed
    /// denial write never converts the denial into an acceptance. Never
    /// carries the presented credential material.
    pub async fn record_auth_denial(&self, denial: &DenialEvent) -> Result<(), BoxError> {
        sqlx::query(
            "INSERT INTO identity.admin_audit_events \
                 (event_id, occurred_at, surface, action, actor_token_id, outcome, detail, \
                  trace_id, source_ip) \
             VALUES ($1, now(), $2, $3, $4, 'denied', $5::jsonb, $6, $7)",
        )
        .bind(mint_audit_event_id())
        .bind(SURFACE_AUTHZ_ADMIN)
        .bind(ACTION_AUTH_DENIED)
        .bind(ACTOR_UNAUTHENTICATED)
        .bind(json!({ "credential": denial.kind.as_str() }).to_string())
        .bind(denial.trace_id.as_deref())
        .bind(denial.source_ip.as_deref())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// The read surface over the ledger (design D6): filterable by time range,
    /// actor, and target; time-ordered by `event_id` (UUIDv7 order IS time
    /// order); cursor-paginated. Read-only — no mutation path over events
    /// exists anywhere.
    pub async fn query_audit_events(
        &self,
        query: &AuditQuery,
    ) -> Result<Vec<AuditEventRecord>, BoxError> {
        let limit = i64::from(query.limit.unwrap_or(100).clamp(1, 1000));
        let rows = sqlx::query(
            "SELECT event_id, occurred_at::text AS occurred_at, surface, action, \
                    actor_token_id, asserted_operator, target_kind, target_id, outcome, \
                    detail::text AS detail, trace_id, source_ip, idempotency_key \
             FROM identity.admin_audit_events \
             WHERE ($1::text IS NULL OR occurred_at >= $1::timestamptz) \
               AND ($2::text IS NULL OR occurred_at < $2::timestamptz) \
               AND ($3::text IS NULL OR actor_token_id = $3) \
               AND ($4::text IS NULL OR target_id = $4) \
               AND ($5::text IS NULL OR event_id > $5) \
             ORDER BY event_id \
             LIMIT $6",
        )
        .bind(query.from.as_deref())
        .bind(query.to.as_deref())
        .bind(query.actor.as_deref())
        .bind(query.target.as_deref())
        .bind(query.cursor.as_deref())
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(classify_query_error)?;
        rows.into_iter().map(|row| row_to_record(&row)).collect()
    }
}

// --------------------------------------------------------------------------- //
// Named admin tokens (design D4/D5) — extending the customer-api-keys pattern.
// --------------------------------------------------------------------------- //

/// The one-time result of issuing (or rotating) an admin token: the plaintext
/// secret is returned HERE and never again (only its hash is persisted).
#[derive(Clone)]
pub struct IssuedAdminToken {
    /// The public token id (`atk_…`) — the attribution handle every audit
    /// event carries.
    pub token_id: String,
    /// The plaintext bearer secret. Shown once; never stored, never logged.
    pub secret: String,
}

impl fmt::Debug for IssuedAdminToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The one-time secret must never leak through Debug formatting.
        f.debug_struct("IssuedAdminToken")
            .field("token_id", &self.token_id)
            .finish_non_exhaustive()
    }
}

/// Mint a fresh admin credential: a public `atk_` token id and a high-entropy
/// (256-bit) `nexus_admin_`-prefixed secret — greppable and unmistakable in
/// logs/leaks. Same CSPRNG as the customer-PAT mint.
fn generate_admin_credential() -> Result<(String, String), BoxError> {
    let mut id_bytes = [0_u8; 12];
    let mut secret_bytes = [0_u8; 32];
    getrandom::getrandom(&mut id_bytes).map_err(|e| Box::new(e) as BoxError)?;
    getrandom::getrandom(&mut secret_bytes).map_err(|e| Box::new(e) as BoxError)?;
    Ok((
        format!("atk_{}", hex::encode(id_bytes)),
        format!("nexus_admin_{}", hex::encode(secret_bytes)),
    ))
}

/// Read-write access to `identity.admin_tokens` for authz-admin: issue /
/// rotate / revoke (each audited atomically) and the per-request hash lookup.
/// Verification is one indexed lookup by the peppered HMAC — deterministic HMAC
/// comparison leaks nothing without the pepper (the same argument as the
/// customer-api-keys hasher).
#[derive(Clone)]
pub struct PgAdminTokenStore {
    pool: PgPool,
    hasher: Arc<dyn SecretHasher>,
}

impl fmt::Debug for PgAdminTokenStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PgAdminTokenStore").finish_non_exhaustive()
    }
}

impl PgAdminTokenStore {
    /// Share the audit store's pool, keyed with `hasher` for minting/lookup.
    #[must_use]
    pub fn new(audit: &PgAdminAuditStore, hasher: Arc<dyn SecretHasher>) -> Self {
        Self { pool: audit.pool.clone(), hasher }
    }

    /// Issue a named credential for one caller. Persists ONLY the secret's
    /// hash and returns the plaintext once; records `admin_token.issue` in the
    /// same transaction.
    pub async fn issue(&self, name: &str, actx: &AuditCtx) -> Result<IssuedAdminToken, BoxError> {
        let (token_id, secret) = generate_admin_credential()?;
        let token_hash = self.hasher.hash(&secret);
        let mut tx = self.pool.begin().await?;
        sqlx::query(
            "INSERT INTO identity.admin_tokens (token_id, name, token_hash, status) \
             VALUES ($1, $2, $3, 'active')",
        )
        .bind(&token_id)
        .bind(name)
        .bind(&token_hash)
        .execute(&mut *tx)
        .await?;
        record(
            &mut *tx,
            actx,
            &NewAuditEvent {
                action: ACTION_ADMIN_TOKEN_ISSUE,
                target_kind: "admin_token",
                target_id: &token_id,
                outcome: OUTCOME_OK,
                detail: json!({ "name": name }),
                idempotency_key: None,
            },
        )
        .await?;
        tx.commit().await?;
        Ok(IssuedAdminToken { token_id, secret })
    }

    /// Rotate `token_id`: mint a NEW active credential under the same name,
    /// record the lineage (`rotated_from`), and revoke the old one — all in
    /// one audited transaction. `Ok(None)` if `token_id` is not active.
    pub async fn rotate(
        &self,
        token_id: &str,
        actx: &AuditCtx,
    ) -> Result<Option<IssuedAdminToken>, BoxError> {
        let mut tx = self.pool.begin().await?;
        let Some(row) = sqlx::query(
            "SELECT name FROM identity.admin_tokens \
             WHERE token_id = $1 AND status = 'active' FOR UPDATE",
        )
        .bind(token_id)
        .fetch_optional(&mut *tx)
        .await?
        else {
            return Ok(None);
        };
        let name: String = row.try_get("name")?;
        let (new_token_id, secret) = generate_admin_credential()?;
        let new_hash = self.hasher.hash(&secret);
        sqlx::query(
            "INSERT INTO identity.admin_tokens (token_id, name, token_hash, status, rotated_from) \
             VALUES ($1, $2, $3, 'active', $4)",
        )
        .bind(&new_token_id)
        .bind(&name)
        .bind(&new_hash)
        .bind(token_id)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "UPDATE identity.admin_tokens SET status = 'revoked', updated_at = now() \
             WHERE token_id = $1",
        )
        .bind(token_id)
        .execute(&mut *tx)
        .await?;
        record(
            &mut *tx,
            actx,
            &NewAuditEvent {
                action: ACTION_ADMIN_TOKEN_ROTATE,
                target_kind: "admin_token",
                target_id: &new_token_id,
                outcome: OUTCOME_OK,
                detail: json!({ "name": name, "rotated_from": token_id }),
                idempotency_key: None,
            },
        )
        .await?;
        tx.commit().await?;
        Ok(Some(IssuedAdminToken { token_id: new_token_id, secret }))
    }

    /// Revoke `token_id` (status flip — every other caller's credential keeps
    /// working). `true` if an active token was revoked, `false` if it was
    /// already revoked or unknown (idempotent; no state change ⇒ no event).
    pub async fn revoke(&self, token_id: &str, actx: &AuditCtx) -> Result<bool, BoxError> {
        let mut tx = self.pool.begin().await?;
        let res = sqlx::query(
            "UPDATE identity.admin_tokens SET status = 'revoked', updated_at = now() \
             WHERE token_id = $1 AND status = 'active'",
        )
        .bind(token_id)
        .execute(&mut *tx)
        .await?;
        if res.rows_affected() == 0 {
            return Ok(false);
        }
        record(
            &mut *tx,
            actx,
            &NewAuditEvent {
                action: ACTION_ADMIN_TOKEN_REVOKE,
                target_kind: "admin_token",
                target_id: token_id,
                outcome: OUTCOME_OK,
                detail: json!({}),
                idempotency_key: None,
            },
        )
        .await?;
        tx.commit().await?;
        Ok(true)
    }

    /// Resolve a presented bearer secret to its token id, if it is an active
    /// named credential. One indexed lookup by the peppered hash; a revoked or
    /// unknown secret simply matches no row (fail-closed).
    pub async fn lookup(&self, presented_secret: &str) -> Result<Option<String>, BoxError> {
        let token_hash = self.hasher.hash(presented_secret);
        let row = sqlx::query(
            "SELECT token_id FROM identity.admin_tokens \
             WHERE token_hash = $1 AND status = 'active'",
        )
        .bind(&token_hash)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|found| found.get::<String, _>("token_id")))
    }
}

// --------------------------------------------------------------------------- //
// Retention (design D7): purge is the ONLY deleter, run under the separate
// maintenance role — never the service role, which holds INSERT/SELECT only.
// --------------------------------------------------------------------------- //

/// The maintenance-role connection that runs the retention purge. Deliberately
/// a separate handle: in a locked-down deployment its URL authenticates as the
/// maintenance role (the only identity granted DELETE on the ledger).
#[derive(Clone)]
pub struct PgAuditMaintenance {
    pool: PgPool,
}

impl fmt::Debug for PgAuditMaintenance {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PgAuditMaintenance").finish_non_exhaustive()
    }
}

impl PgAuditMaintenance {
    /// Connect the maintenance pool (small — one periodic statement).
    pub async fn connect(url: &str) -> Result<Self, BoxError> {
        Ok(Self { pool: connect_pool(url, 2).await? })
    }

    /// Delete events older than the retention window. Returns the purged count.
    pub async fn purge_events_older_than_days(&self, days: u32) -> Result<u64, BoxError> {
        let res = sqlx::query(
            "DELETE FROM identity.admin_audit_events \
             WHERE occurred_at < now() - make_interval(days => $1)",
        )
        .bind(i32::try_from(days).unwrap_or(i32::MAX))
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected())
    }
}

#[cfg(test)]
mod tests {
    use super::generate_admin_credential;

    #[test]
    fn credentials_are_prefixed_unique_and_high_entropy() {
        let (id1, sec1) = generate_admin_credential().expect("csprng");
        let (id2, sec2) = generate_admin_credential().expect("csprng");
        assert!(id1.starts_with("atk_"), "token ids are typed: {id1}");
        assert!(sec1.starts_with("nexus_admin_"), "secrets are greppable: {sec1}");
        assert_ne!(id1, id2, "token ids must be unique");
        assert_ne!(sec1, sec2, "secrets must be unique");
        assert_eq!(sec1.trim_start_matches("nexus_admin_").len(), 64, "256-bit secret");
    }
}
