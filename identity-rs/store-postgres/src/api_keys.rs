//! `identity.api_keys` adapters — the Personal Access Token store (`customer-api-keys`).
//!
//! Two least-privilege adapters over one table, mirroring the profile store's
//! reader/writer split:
//!   - [`PgApiKeyReader`] — SELECT-only, used by the **sidecar** to resolve a presented
//!     key on the request path. Every resolve is a fresh, filtered query (`status =
//!     'active' AND unexpired`), so revocation/expiry take effect on the **next request**
//!     with no cache to invalidate (design.md `/opsx:decide`).
//!   - [`PgApiKeyStore`] — read-write, used by **authz-admin** to issue / rotate / revoke
//!     keys and to own the idempotent schema bootstrap.
//!
//! The secret is NEVER stored — only its keyed HMAC (`key_hash`, see [`crate::hasher`]),
//! under a UNIQUE index so the reader resolves it with a single indexed lookup. The
//! plaintext exists only in the one-time issuance response.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::{PgPool, Row};

use identity_core::api_key::{ApiKeyCandidate, ApiKeyReader, ApiKeyScope};
use identity_core::store::BoxError;
use identity_core::SecretHasher;

/// The NOTIFY channel every `identity.api_keys` mutation publishes a wakeup on (kept in
/// lockstep with the trigger in `migrations/0002_api_keys.sql`). The sidecar resolves keys
/// live per request, so it does not currently LISTEN here — the channel ships for parity
/// with `platform.services` and a future opt-in cache/audit-tap.
pub const API_KEY_CHANGE_CHANNEL: &str = "api_key_changes";

/// Open a pooler-safe pool with `max` connections (statement cache disabled + a
/// server-side statement timeout, matching the other identity adapters).
async fn connect_pool(url: &str, max: u32) -> Result<PgPool, BoxError> {
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

/// Parse the stored `scopes` jsonb (a JSON array of workspace-id strings) into the scope
/// set. A malformed/absent value yields an EMPTY scope (fail-closed: a key we can't read
/// scopes for admits nothing), never an error that would drop the whole lookup.
fn parse_scopes(json: &str) -> ApiKeyScope {
    ApiKeyScope::new(serde_json::from_str::<Vec<String>>(json).unwrap_or_default())
}

// --------------------------------------------------------------------------- //
// Reader (sidecar): SELECT-only resolve of a presented key's hash.
// --------------------------------------------------------------------------- //

/// Read-only resolver of live api keys out of `identity.api_keys`.
pub struct PgApiKeyReader {
    pool: PgPool,
}

impl PgApiKeyReader {
    /// Open a read-only pool to the api-key store.
    pub async fn connect(url: &str) -> Result<Self, BoxError> {
        Ok(Self { pool: connect_pool(url, 4).await? })
    }
}

#[async_trait]
impl ApiKeyReader for PgApiKeyReader {
    async fn lookup(&self, key_hash: &str) -> Result<Option<ApiKeyCandidate>, BoxError> {
        // The WHERE clause is the fail-closed enforcement point: a revoked, expired, or
        // unknown key simply matches no row. now() is the DB clock, so expiry needs no
        // Rust time type (this crate builds without sqlx's chrono/time feature).
        let row = sqlx::query(
            "SELECT key_id, creator_sub, scopes::text AS scopes \
             FROM identity.api_keys \
             WHERE key_hash = $1 AND status = 'active' \
               AND (expires_at IS NULL OR expires_at > now())",
        )
        .bind(key_hash)
        .fetch_optional(&self.pool)
        .await?;
        match row {
            Some(r) => Ok(Some(ApiKeyCandidate {
                key_id: r.try_get("key_id")?,
                creator_sub: r.try_get("creator_sub")?,
                scope: parse_scopes(&r.try_get::<String, _>("scopes")?),
            })),
            None => Ok(None),
        }
    }
}

// --------------------------------------------------------------------------- //
// Store (authz-admin): issue / rotate / revoke + schema bootstrap.
// --------------------------------------------------------------------------- //

/// The one-time result of issuing (or rotating) a key: the plaintext secret is returned
/// HERE and never again (it is not persisted — only its hash is).
#[derive(Clone, Debug)]
pub struct IssuedKey {
    /// The public key id (audit / management handle).
    pub key_id: String,
    /// The plaintext secret the caller presents as `x-api-key`. Shown once.
    pub secret: String,
    /// Absolute expiry, epoch seconds; `None` when the key does not expire.
    pub expires_at: Option<i64>,
}

/// Read-write access to `identity.api_keys` for the authoring surface.
#[derive(Clone)]
pub struct PgApiKeyStore {
    pool: PgPool,
    hasher: Arc<dyn SecretHasher>,
}

impl fmt::Debug for PgApiKeyStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PgApiKeyStore").finish_non_exhaustive()
    }
}

impl PgApiKeyStore {
    /// Open a read-write pool, keyed with `hasher` for minting/hashing secrets.
    pub async fn connect(
        url: &str,
        hasher: Arc<dyn SecretHasher>,
    ) -> Result<Self, BoxError> {
        Ok(Self { pool: connect_pool(url, 4).await?, hasher })
    }

    /// Idempotent schema bootstrap for `identity.api_keys` (+ its lookup index and the
    /// change-notify trigger). The authoring surface owns this, mirroring
    /// `PgProfileStore::init_schema`. Assumes the `identity` schema already exists (the
    /// profile store creates it); creates it defensively too.
    pub async fn init_schema(&self) -> Result<(), BoxError> {
        sqlx::query("CREATE SCHEMA IF NOT EXISTS identity")
            .execute(&self.pool)
            .await?;
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS identity.api_keys (\
                 key_id       text        PRIMARY KEY, \
                 key_hash     text        NOT NULL UNIQUE, \
                 creator_sub  text        NOT NULL, \
                 scopes       jsonb       NOT NULL DEFAULT '[]'::jsonb, \
                 expires_at   timestamptz, \
                 status       text        NOT NULL DEFAULT 'active', \
                 rotated_from text, \
                 created_at   timestamptz NOT NULL DEFAULT now(), \
                 updated_at   timestamptz NOT NULL DEFAULT now())",
        )
        .execute(&self.pool)
        .await?;
        // The reader resolves by key_hash filtered to active — keep that lookup cheap.
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS api_keys_active_hash_idx \
             ON identity.api_keys (key_hash) WHERE status = 'active'",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS api_keys_creator_idx ON identity.api_keys (creator_sub)",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE OR REPLACE FUNCTION identity.notify_api_key_change() RETURNS trigger \
             LANGUAGE plpgsql AS $$ BEGIN \
                 PERFORM pg_notify('api_key_changes', COALESCE(NEW.key_id, OLD.key_id)); \
                 RETURN NULL; END; $$",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query("DROP TRIGGER IF EXISTS api_keys_change_notify ON identity.api_keys")
            .execute(&self.pool)
            .await?;
        sqlx::query(
            "CREATE TRIGGER api_keys_change_notify \
             AFTER INSERT OR UPDATE OR DELETE ON identity.api_keys \
             FOR EACH ROW EXECUTE FUNCTION identity.notify_api_key_change()",
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Issue a new key for `creator_sub` scoped to `scopes`, optionally expiring
    /// `expires_in_seconds` from now. Persists ONLY the secret's hash and returns the
    /// plaintext once. The caller is responsible for the human-only + "may not exceed the
    /// creator" issuance checks (authz-admin) — this is the persistence primitive.
    pub async fn issue(
        &self,
        creator_sub: &str,
        scopes: &[String],
        expires_in_seconds: Option<i64>,
        now_epoch: i64,
    ) -> Result<IssuedKey, BoxError> {
        let (key_id, secret) = generate_credential()?;
        let key_hash = self.hasher.hash(&secret);
        let scopes_json = serde_json::to_string(scopes)?;
        let expires_at = expires_in_seconds.map(|ttl| now_epoch.saturating_add(ttl));
        insert_key(
            &self.pool,
            &NewKeyRow {
                key_id: &key_id,
                key_hash: &key_hash,
                creator_sub,
                scopes_json: &scopes_json,
                expires_at,
                rotated_from: None,
            },
        )
        .await?;
        Ok(IssuedKey { key_id, secret, expires_at })
    }

    /// Rotate `key_id`: mint a NEW active key under the same creator, scopes, and expiry
    /// (no widening), record the lineage (`rotated_from`), and revoke the old key — all in
    /// one transaction. Returns the new key's one-time secret, or `Ok(None)` if `key_id`
    /// is not an active key.
    pub async fn rotate(&self, key_id: &str) -> Result<Option<IssuedKey>, BoxError> {
        let mut tx = self.pool.begin().await?;
        // Read the key being rotated (must be active). Copy its scopes/creator/expiry
        // verbatim so the new key never widens authority.
        let Some(row) = sqlx::query(
            "SELECT creator_sub, scopes::text AS scopes, \
                    (CASE WHEN expires_at IS NULL THEN NULL \
                          ELSE extract(epoch FROM expires_at)::bigint END) AS exp \
             FROM identity.api_keys WHERE key_id = $1 AND status = 'active' FOR UPDATE",
        )
        .bind(key_id)
        .fetch_optional(&mut *tx)
        .await?
        else {
            return Ok(None);
        };
        let creator_sub: String = row.try_get("creator_sub")?;
        let scopes_json: String = row.try_get("scopes")?;
        let expires_at: Option<i64> = row.try_get("exp")?;

        let (new_key_id, secret) = generate_credential()?;
        let new_hash = self.hasher.hash(&secret);
        insert_key(
            &mut *tx,
            &NewKeyRow {
                key_id: &new_key_id,
                key_hash: &new_hash,
                creator_sub: &creator_sub,
                scopes_json: &scopes_json,
                expires_at,
                rotated_from: Some(key_id),
            },
        )
        .await?;
        sqlx::query(
            "UPDATE identity.api_keys SET status = 'revoked', updated_at = now() WHERE key_id = $1",
        )
        .bind(key_id)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(Some(IssuedKey { key_id: new_key_id, secret, expires_at }))
    }

    /// Revoke `key_id` (flip to `revoked`). Returns `true` if an active key was revoked,
    /// `false` if it was already revoked or unknown (idempotent).
    pub async fn revoke(&self, key_id: &str) -> Result<bool, BoxError> {
        let res = sqlx::query(
            "UPDATE identity.api_keys SET status = 'revoked', updated_at = now() \
             WHERE key_id = $1 AND status = 'active'",
        )
        .bind(key_id)
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected() > 0)
    }
}

/// The column values for one inserted key row (bundled so [`insert_key`] stays within the
/// argument budget). `expires_at` is an absolute epoch (seconds) or `None`.
struct NewKeyRow<'a> {
    key_id: &'a str,
    key_hash: &'a str,
    creator_sub: &'a str,
    scopes_json: &'a str,
    expires_at: Option<i64>,
    rotated_from: Option<&'a str>,
}

/// Insert one key row over any executor (pool or transaction). `expires_at` is
/// materialized to `timestamptz` via `to_timestamp` so the reader's `expires_at > now()`
/// filter runs entirely in the DB (no Rust time type needed).
async fn insert_key<'e, E>(executor: E, row: &NewKeyRow<'_>) -> Result<(), BoxError>
where
    E: sqlx::Executor<'e, Database = sqlx::Postgres>,
{
    sqlx::query(
        "INSERT INTO identity.api_keys \
             (key_id, key_hash, creator_sub, scopes, expires_at, status, rotated_from) \
         VALUES ($1, $2, $3, $4::jsonb, \
                 CASE WHEN $5::bigint IS NULL THEN NULL ELSE to_timestamp($5::bigint) END, \
                 'active', $6)",
    )
    .bind(row.key_id)
    .bind(row.key_hash)
    .bind(row.creator_sub)
    .bind(row.scopes_json)
    .bind(row.expires_at)
    .bind(row.rotated_from)
    .execute(executor)
    .await?;
    Ok(())
}

/// Mint a fresh credential: a public `key_id` and a high-entropy `secret` (256-bit,
/// hex-encoded, `nexus_pat_`-prefixed so it is greppable and unmistakable in logs/leaks).
/// The secret is what a client presents; the sidecar never sees the `key_id`.
fn generate_credential() -> Result<(String, String), BoxError> {
    let mut id_bytes = [0_u8; 12];
    let mut secret_bytes = [0_u8; 32];
    getrandom::getrandom(&mut id_bytes).map_err(|e| Box::new(e) as BoxError)?;
    getrandom::getrandom(&mut secret_bytes).map_err(|e| Box::new(e) as BoxError)?;
    let key_id = format!("pak_{}", hex::encode(id_bytes));
    let secret = format!("nexus_pat_{}", hex::encode(secret_bytes));
    Ok((key_id, secret))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_scope_array() {
        let s = parse_scopes(r#"["ws-1","ws-2"]"#);
        assert!(s.admits("ws-1") && s.admits("ws-2"));
        assert!(!s.admits("ws-3"));
    }

    #[test]
    fn empty_or_malformed_scopes_admit_nothing() {
        // Fail-closed: a key whose scopes we can't read admits nothing.
        assert!(parse_scopes("[]").is_empty());
        assert!(parse_scopes("not json").is_empty());
        assert!(parse_scopes("{}").is_empty());
        assert!(parse_scopes("null").is_empty());
    }

    #[test]
    fn generated_credentials_are_prefixed_unique_and_high_entropy() {
        let (id1, sec1) = generate_credential().expect("getrandom");
        let (id2, sec2) = generate_credential().expect("getrandom");
        assert!(id1.starts_with("pak_") && sec1.starts_with("nexus_pat_"));
        assert_ne!(sec1, sec2, "secrets must be unique");
        assert_ne!(id1, id2, "key ids must be unique");
        // 32 random bytes -> 64 hex chars after the prefix.
        assert_eq!(sec1.trim_start_matches("nexus_pat_").len(), 64);
    }
}
