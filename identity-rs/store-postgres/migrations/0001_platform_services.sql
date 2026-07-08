-- platform-service registry (capability: platform-service-authz).
--
-- A core platform service is authorized from a PLATFORM-level, least-privilege
-- permission set it owns — cross-workspace, NOT per-workspace membership rows
-- (ADR-3). This is the source of record for that set. It is resolved LIVE by the
-- identity sidecar and refreshed on the change feed below, so registering, changing,
-- or revoking a service takes effect within seconds without the service
-- re-authenticating (platform-service-authz spec R3).
--
-- Ownership: this schema is written by an out-of-band admin/migration path (there is
-- no per-request writer in v1). The identity sidecar reads it SELECT-only under a
-- least-privilege connection — it never creates or writes this schema. In the compose
-- lab the DDL + a dev seed are applied by postgres-init on fresh init; in K8s a
-- migration job applies this file.
--
-- Idempotent: safe to re-run (CREATE ... IF NOT EXISTS / OR REPLACE).

CREATE SCHEMA IF NOT EXISTS platform;

CREATE TABLE IF NOT EXISTS platform.services (
    -- The service identity the infra-trust credential proves. For a K8s projected
    -- ServiceAccount token this is the token `sub`
    -- (`system:serviceaccount:<ns>:<name>`); the sidecar treats it as opaque.
    service_id  text        PRIMARY KEY,
    -- The least-privilege named-permission set (a JSON array of strings, e.g.
    -- `["events:write"]`). NOT a boolean — an operation whose permission is absent is
    -- refused even for a registered, authenticated service (platform-service-authz R2).
    permissions jsonb       NOT NULL DEFAULT '[]'::jsonb,
    -- Lifecycle: only 'active' rows confer authority. Flipping to 'revoked' (or any
    -- non-active value) denies the service on its next request within seconds — the
    -- fail-closed revocation path.
    status      text        NOT NULL DEFAULT 'active',
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now()
);

-- The reader filters `WHERE status = 'active'`; keep that projection cheap even as
-- rows accumulate revoked history.
CREATE INDEX IF NOT EXISTS services_status_idx ON platform.services (status);

-- Live change feed (ADR-7): every registry mutation emits a best-effort wakeup on the
-- platform_service_changes channel, so the sidecar reloads the small active set within
-- sub-second. A lost NOTIFY self-heals on the sidecar's periodic poll fallback — same
-- best-effort-feed philosophy as identity.profiles. The payload is the affected
-- service_id (advisory only; the sidecar re-reads the whole active set).
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
