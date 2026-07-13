//! Admin audit ledger + named admin tokens — Postgres adapter
//! (admin-action-audit D1–D7).
//!
//! The ledger (`routing.admin_audit_events`) is written by [`record`] INSIDE the
//! same transaction as the mutation it describes — the fail-closed invariant
//! ("unrecorded ⇒ uncommitted") lives here, where the transaction lives. Denials
//! have no transaction (nothing mutated), so they use a standalone best-effort
//! insert. The ledger is append-only: this adapter has no UPDATE/DELETE over
//! events, and the migration withholds those grants from the service role;
//! retention purge (the only deleter) runs under the separate maintenance role
//! via [`PgAuditMaintenance`].
//!
//! Named admin tokens (`routing.admin_tokens`, design D4) extend the proven
//! customer-api-keys pattern: a peppered HMAC-SHA256 hash (never the secret) is
//! stored under a UNIQUE index, so verification is one indexed lookup; rotation
//! records lineage; revocation is a status flip that leaves every other caller's
//! credential untouched.

use std::fmt;

use ring::hmac::{sign, Key, HMAC_SHA256};
use ring::rand::{SecureRandom, SystemRandom};
use serde_json::{json, Value};
use sqlx::postgres::PgRow;
use sqlx::{PgPool, Row};

use router_core::audit::{
    is_known_action, AuditCtx, AuditEventRecord, AuditQuery, DenialEvent, InvalidQueryBound,
    ACTION_ADMIN_TOKEN_ISSUE, ACTION_ADMIN_TOKEN_REVOKE, ACTION_ADMIN_TOKEN_ROTATE,
    ACTION_AUTH_DENIED, ACTOR_UNAUTHENTICATED, OUTCOME_OK, SURFACE_CONTROL_PLANE,
};
use router_core::ids::mint_audit_event_id;
use router_core::store::BoxError;

use crate::{connect_pool, PgRoutingStore};

/// One audit event as a mutation transaction records it: the action semantics
/// this store method owns. The transport facts ride in alongside via
/// [`AuditCtx`]; the id is minted and the time stamped at insert.
pub(crate) struct NewAuditEvent<'a> {
    pub(crate) action: &'static str,
    pub(crate) target_kind: &'a str,
    pub(crate) target_id: &'a str,
    /// `ok`, `replay`, or an error class.
    pub(crate) outcome: &'a str,
    /// Request semantics minus secrets. NEVER a bearer token, key material, or
    /// any other credential.
    pub(crate) detail: Value,
    pub(crate) idempotency_key: Option<&'a str>,
}

/// Insert one audit event on `executor` — called with the mutation's own
/// transaction so the event commits (or rolls back) WITH the mutation
/// (design D2). Refuses an action outside the closed vocabulary, so nothing
/// unreviewed can enter the ledger.
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
        "INSERT INTO routing.admin_audit_events \
             (event_id, occurred_at, surface, action, actor_token_id, asserted_operator, \
              target_kind, target_id, outcome, detail, trace_id, source_ip, idempotency_key) \
         VALUES ($1, now(), $2, $3, $4, $5, $6, $7, $8, $9::jsonb, $10, $11, $12)",
    )
    .bind(mint_audit_event_id())
    .bind(SURFACE_CONTROL_PLANE)
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
/// `from`/`to` timestamp) to the typed [`InvalidQueryBound`] so the read surface
/// answers 400, not 500, for a malformed filter.
fn classify_query_error(err: sqlx::Error) -> BoxError {
    if let sqlx::Error::Database(db) = &err
        && db.code().is_some_and(|code| code.starts_with("22"))
    {
        return Box::new(InvalidQueryBound);
    }
    Box::new(err)
}

impl PgRoutingStore {
    /// Best-effort denial record for the 401 path (spec: "Denied admin access is
    /// recorded"). No mutation transaction exists, so this is a standalone
    /// insert; the CALLER treats a failure as log-and-continue — a failed denial
    /// write never converts the denial into an acceptance. Never carries the
    /// presented credential material.
    pub async fn record_auth_denial(&self, denial: &DenialEvent) -> Result<(), BoxError> {
        sqlx::query(
            "INSERT INTO routing.admin_audit_events \
                 (event_id, occurred_at, surface, action, actor_token_id, outcome, detail, \
                  trace_id, source_ip) \
             VALUES ($1, now(), $2, $3, $4, 'denied', $5::jsonb, $6, $7)",
        )
        .bind(mint_audit_event_id())
        .bind(SURFACE_CONTROL_PLANE)
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
    /// order); cursor-paginated (resume strictly after the previous page's last
    /// id). Read-only — no mutation path over events exists anywhere.
    pub async fn query_audit_events(
        &self,
        query: &AuditQuery,
    ) -> Result<Vec<AuditEventRecord>, BoxError> {
        let limit = i64::from(query.limit.unwrap_or(100).clamp(1, 1000));
        let rows = sqlx::query(
            "SELECT event_id, occurred_at::text AS occurred_at, surface, action, \
                    actor_token_id, asserted_operator, target_kind, target_id, outcome, \
                    detail::text AS detail, trace_id, source_ip, idempotency_key \
             FROM routing.admin_audit_events \
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

// --------------------------------------------------------------------------- //
// Named admin tokens (design D4/D5).
// --------------------------------------------------------------------------- //

/// HMAC-SHA256 hasher keyed by the server-held pepper (`ADMIN_TOKEN_PEPPER`).
/// Deterministic, so a presented secret resolves with ONE indexed lookup by its
/// hash — the same adopted pattern as the customer-api-keys hasher. Comparing
/// HMAC outputs by index equality leaks nothing useful: without the pepper an
/// attacker cannot compute the hash of any candidate secret. Backed by `ring`
/// (already in-tree), never hand-rolled.
#[derive(Clone)]
pub struct AdminTokenHasher {
    key: Key,
}

impl fmt::Debug for AdminTokenHasher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never render the pepper — it is a secret.
        f.debug_struct("AdminTokenHasher").finish_non_exhaustive()
    }
}

impl AdminTokenHasher {
    /// Build a hasher keyed by `pepper` (a server-held secret).
    #[must_use]
    pub fn new(pepper: &[u8]) -> Self {
        Self { key: Key::new(HMAC_SHA256, pepper) }
    }

    /// The hex HMAC of `secret` under the pepper — the only form ever stored.
    #[must_use]
    pub fn hash(&self, secret: &str) -> String {
        hex::encode(sign(&self.key, secret.as_bytes()).as_ref())
    }
}

/// The one-time result of issuing (or rotating) an admin token: the plaintext
/// secret is returned HERE and never again (only its hash is persisted).
#[derive(Clone)]
pub struct IssuedAdminToken {
    /// The public token id (`atk_…`) — the attribution handle every audit event
    /// carries.
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
/// logs/leaks. OS CSPRNG via `ring`, mirroring the ownership-proof token mint.
fn generate_admin_credential() -> Result<(String, String), BoxError> {
    let rng = SystemRandom::new();
    let mut id_bytes = [0_u8; 12];
    let mut secret_bytes = [0_u8; 32];
    rng.fill(&mut id_bytes).map_err(|_| "csprng failure")?;
    rng.fill(&mut secret_bytes).map_err(|_| "csprng failure")?;
    Ok((
        format!("atk_{}", hex::encode(id_bytes)),
        format!("nexus_admin_{}", hex::encode(secret_bytes)),
    ))
}

/// Read-write access to `routing.admin_tokens` for the control plane: issue /
/// rotate / revoke (each audited atomically) and the per-request hash lookup.
#[derive(Clone)]
pub struct PgAdminTokenStore {
    pool: PgPool,
    hasher: AdminTokenHasher,
}

impl fmt::Debug for PgAdminTokenStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PgAdminTokenStore").finish_non_exhaustive()
    }
}

impl PgAdminTokenStore {
    /// Share the routing store's pool, keyed with `hasher` for minting/lookup.
    #[must_use]
    pub fn new(store: &PgRoutingStore, hasher: AdminTokenHasher) -> Self {
        Self { pool: store.pool.clone(), hasher }
    }

    /// Issue a named credential for one caller. Persists ONLY the secret's hash
    /// and returns the plaintext once; records `admin_token.issue` in the same
    /// transaction.
    pub async fn issue(&self, name: &str, actx: &AuditCtx) -> Result<IssuedAdminToken, BoxError> {
        let (token_id, secret) = generate_admin_credential()?;
        let token_hash = self.hasher.hash(&secret);
        let mut tx = self.pool.begin().await?;
        sqlx::query(
            "INSERT INTO routing.admin_tokens (token_id, name, token_hash, status) \
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
    /// record the lineage (`rotated_from`), and revoke the old one — all in one
    /// audited transaction. `Ok(None)` if `token_id` is not an active token.
    pub async fn rotate(
        &self,
        token_id: &str,
        actx: &AuditCtx,
    ) -> Result<Option<IssuedAdminToken>, BoxError> {
        let mut tx = self.pool.begin().await?;
        let Some(row) = sqlx::query(
            "SELECT name FROM routing.admin_tokens \
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
            "INSERT INTO routing.admin_tokens (token_id, name, token_hash, status, rotated_from) \
             VALUES ($1, $2, $3, 'active', $4)",
        )
        .bind(&new_token_id)
        .bind(&name)
        .bind(&new_hash)
        .bind(token_id)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "UPDATE routing.admin_tokens SET status = 'revoked', updated_at = now() \
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
            "UPDATE routing.admin_tokens SET status = 'revoked', updated_at = now() \
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
            "SELECT token_id FROM routing.admin_tokens \
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
/// a separate handle from [`PgRoutingStore`]: in a locked-down deployment its
/// URL authenticates as the maintenance role (the only identity granted DELETE
/// on the ledger).
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
            "DELETE FROM routing.admin_audit_events \
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
    use super::{generate_admin_credential, AdminTokenHasher};

    #[test]
    fn hash_is_deterministic_peppered_hex() {
        let hasher = AdminTokenHasher::new(b"pepper");
        let first = hasher.hash("nexus_admin_secret");
        let second = hasher.hash("nexus_admin_secret");
        assert_eq!(first, second, "same secret must hash identically (indexed lookup)");
        assert_eq!(first.len(), 64, "HMAC-SHA256 -> 32 bytes -> 64 hex chars");
        let other_pepper = AdminTokenHasher::new(b"other");
        assert_ne!(first, other_pepper.hash("nexus_admin_secret"), "the pepper keys the hash");
    }

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
