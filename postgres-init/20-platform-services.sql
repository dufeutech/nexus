-- platform-service registry bootstrap + dev seed (capability: platform-service-authz).
--
-- Runs ONCE on fresh cluster init (empty data dir) via the postgres image's
-- /docker-entrypoint-initdb.d hook, AFTER 10-create-nexus-databases.sql has created
-- `identitydb`. The `platform.services` table lives in the identity database alongside
-- identity.profiles (the sidecar reads it SELECT-only; there is no per-request writer in
-- v1), so this connects to identitydb and applies the same DDL as
-- identity-rs/store-postgres/migrations/0001_platform_services.sql, then seeds ONE dev
-- service so the compose stack has an active service to exercise the service path.
--
-- Keep the DDL in lockstep with the migration file (the canonical source for K8s, where
-- a migration job applies it instead of this hook).

\connect identitydb

CREATE SCHEMA IF NOT EXISTS platform;

CREATE TABLE IF NOT EXISTS platform.services (
    service_id  text        PRIMARY KEY,
    permissions jsonb       NOT NULL DEFAULT '[]'::jsonb,
    status      text        NOT NULL DEFAULT 'active',
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS services_status_idx ON platform.services (status);

CREATE OR REPLACE FUNCTION platform.notify_service_change() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    PERFORM pg_notify('platform_service_changes', COALESCE(NEW.service_id, OLD.service_id));
    RETURN NULL;
END;
$$;

DROP TRIGGER IF EXISTS services_change_notify ON platform.services;
CREATE TRIGGER services_change_notify
    AFTER INSERT OR UPDATE OR DELETE ON platform.services
    FOR EACH ROW EXECUTE FUNCTION platform.notify_service_change();

-- Dev seed: one active core service with a least-privilege permission set. The
-- service_id matches the `sub` the dev ServiceAccount token carries
-- (scripts/service-identity-e2e.sh), so the sidecar resolves it to a Platform authority.
INSERT INTO platform.services (service_id, permissions, status)
VALUES ('system:serviceaccount:nexus:events-writer', '["events:write"]'::jsonb, 'active')
ON CONFLICT (service_id) DO NOTHING;
