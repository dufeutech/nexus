-- customer API keys — the Personal Access Token store (capability: customer-api-keys).
--
-- A customer automation credential (a PAT) acts ON BEHALF OF its creating human, bounded
-- by the key's scopes. This table is the source of record for a key's identity, scopes,
-- expiry, rotation lineage, and revocation. It lives in the identity database alongside
-- identity.profiles and platform.services.
--
-- Ownership: WRITTEN by authz-admin (issue/rotate/revoke); READ SELECT-only by the
-- identity sidecar, which resolves a presented key LIVE on each request
-- (`status = 'active' AND unexpired`), so revocation/expiry take effect on the next
-- request. Idempotent: safe to re-run (matches PgApiKeyStore::init_schema — keep the two
-- in lockstep; this file is the canonical source for K8s, where a migration job applies
-- it, and authz-admin also runs the same DDL at startup for the compose lab).
--
-- Secrets are NEVER stored in plaintext: only `key_hash`, the keyed HMAC-SHA256 of the
-- secret under a server-held pepper (see identity-rs/store-postgres/src/hasher.rs). The
-- hash is deterministic, so the sidecar resolves a presented secret with a single indexed
-- lookup by `key_hash`.

CREATE SCHEMA IF NOT EXISTS identity;

CREATE TABLE IF NOT EXISTS identity.api_keys (
    -- The public, stable key id — an audit/management handle (rotate/revoke by it), NOT
    -- the secret. The sidecar never sees this; a client presents only the secret.
    key_id       text        PRIMARY KEY,
    -- HMAC-SHA256(pepper, secret), hex. The plaintext secret exists ONLY in the one-time
    -- issuance response. UNIQUE so the sidecar's resolve is a single indexed lookup.
    key_hash     text        NOT NULL UNIQUE,
    -- The creating user's subject; the key acts on behalf of them (the `on_behalf_of`
    -- claim / x-user-on-behalf-of header, and the audit binding).
    creator_sub  text        NOT NULL,
    -- The key's scope vocabulary: a JSON array of workspace ids the key may act in. The
    -- effective authority is this ∩ the creator's LIVE membership (nexus-resolved), so a
    -- key can never exceed its creator. Empty admits nothing (issuance requires >= 1).
    scopes       jsonb       NOT NULL DEFAULT '[]'::jsonb,
    -- Absolute expiry; NULL = no expiry. The sidecar filters `expires_at > now()` in SQL,
    -- so expiry is live (no cached copy to invalidate).
    expires_at   timestamptz,
    -- Lifecycle: only 'active' rows confer authority. Flipping to 'revoked' denies the key
    -- on its next request (the fail-closed revocation path).
    status       text        NOT NULL DEFAULT 'active',
    -- Rotation lineage: the key id this key superseded (NULL for an originally-issued key).
    -- A rotate mints a new active key pointing back here and revokes the old one.
    rotated_from text,
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now()
);

-- The sidecar resolves by key_hash filtered to active — a partial index keeps that lookup
-- cheap even as revoked history accumulates. (The column is also UNIQUE overall.)
CREATE INDEX IF NOT EXISTS api_keys_active_hash_idx
    ON identity.api_keys (key_hash) WHERE status = 'active';

-- List/manage a user's keys.
CREATE INDEX IF NOT EXISTS api_keys_creator_idx ON identity.api_keys (creator_sub);

-- Live change feed (parity with platform.services): every mutation emits a best-effort
-- wakeup on api_key_changes. The sidecar resolves keys live per request, so it does not
-- currently LISTEN here — the channel ships for a future opt-in cache/audit-tap. The
-- payload is the affected key_id (advisory only).
CREATE OR REPLACE FUNCTION identity.notify_api_key_change() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    PERFORM pg_notify('api_key_changes', COALESCE(NEW.key_id, OLD.key_id));
    RETURN NULL;
END;
$$;

DROP TRIGGER IF EXISTS api_keys_change_notify ON identity.api_keys;
CREATE TRIGGER api_keys_change_notify
    AFTER INSERT OR UPDATE OR DELETE ON identity.api_keys
    FOR EACH ROW EXECUTE FUNCTION identity.notify_api_key_change();
