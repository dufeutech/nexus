-- customer API keys bootstrap (capability: customer-api-keys) — compose-lab hook.
--
-- Runs ONCE on fresh cluster init (empty data dir) via the postgres image's
-- /docker-entrypoint-initdb.d hook, AFTER 10-create-nexus-databases.sql created
-- `identitydb`. Applies the same DDL as
-- identity-rs/store-postgres/migrations/0002_api_keys.sql (the canonical source for K8s,
-- where a migration job applies it, and which authz-admin also runs at startup).
--
-- Keep the DDL in lockstep with the migration file and PgApiKeyStore::init_schema. No dev
-- seed here: a real key's `key_hash` is a keyed HMAC over the sidecar's APIKEY_HMAC_PEPPER,
-- so seeding a working key would couple this file to a secret. The e2e ISSUES a key
-- through authz-admin instead (scripts/customer-api-keys-e2e.sh).

\connect identitydb

CREATE SCHEMA IF NOT EXISTS identity;

CREATE TABLE IF NOT EXISTS identity.api_keys (
    key_id       text        PRIMARY KEY,
    key_hash     text        NOT NULL UNIQUE,
    creator_sub  text        NOT NULL,
    scopes       jsonb       NOT NULL DEFAULT '[]'::jsonb,
    expires_at   timestamptz,
    status       text        NOT NULL DEFAULT 'active',
    rotated_from text,
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS api_keys_active_hash_idx
    ON identity.api_keys (key_hash) WHERE status = 'active';

CREATE INDEX IF NOT EXISTS api_keys_creator_idx ON identity.api_keys (creator_sub);

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
