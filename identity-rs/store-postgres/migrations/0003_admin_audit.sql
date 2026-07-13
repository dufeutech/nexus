-- Administrative audit ledger + named admin tokens — identity plane
-- (capability: admin-action-audit). Twin of routing-rs's 0002_admin_audit.sql:
-- the two planes share the CONVENTION (record shape, `aev_` ids, append-only
-- discipline), not a schema or a crate.
--
-- `identity.admin_audit_events` is authz-admin's append-only record of every
-- mutating admin action (roles, entitlements, suspension, api keys, admin
-- tokens, the bootstrap grant): written IN THE SAME TRANSACTION as the mutation
-- it describes (fail-closed — an unrecorded mutation does not commit, design
-- D1/D2), plus best-effort denial events on the 401 path. NOT telemetry.
--
-- `identity.admin_tokens` makes admin credentials individually identifiable
-- (design D4): one row per named caller, storing ONLY the peppered HMAC-SHA256
-- of the secret (env ADMIN_TOKEN_PEPPER — a separate secret from the customer
-- APIKEY_HMAC_PEPPER, same adopted hasher), with rotation lineage and
-- status-flip revocation.
--
-- Idempotent (CREATE ... IF NOT EXISTS): safe to re-run. Canonical source for
-- K8s (a migration job applies this file); authz-admin runs the same table DDL
-- at startup (PgAdminAuditStore::init_schema — keep the two in lockstep). The
-- role/grant DDL below exists ONLY here: append-only is DB-enforced by
-- withholding UPDATE/DELETE on the ledger from the role the service connects
-- as, and retention purge — the only permitted deletion (design D7) — runs as
-- the separate maintenance role (env AUDIT_MAINTENANCE_PG_URL).

CREATE SCHEMA IF NOT EXISTS identity;

CREATE TABLE IF NOT EXISTS identity.admin_audit_events (
    -- `aev_<uuidv7>`: self-describing and lexicographically time-ordered, so the
    -- primary-key order IS the event-time order (query surface + cursor rely on it).
    event_id          text PRIMARY KEY,
    occurred_at       timestamptz NOT NULL DEFAULT now(),
    -- Which admin surface recorded it ('authz-admin' here).
    surface           text NOT NULL,
    -- Closed action vocabulary (identity_core::audit::ACTIONS) — the application
    -- refuses to record anything outside it.
    action            text NOT NULL,
    -- The acting credential's id (`atk_…`) or a reserved actor id
    -- (`legacy-shared`, `auth-disabled`, `bootstrap`, `unauthenticated`).
    actor_token_id    text NOT NULL,
    -- Caller-asserted human operator (`x-acting-operator`), stored VERBATIM and
    -- marked asserted by this column's name; never influences authorization.
    asserted_operator text,
    target_kind       text,
    target_id         text,
    -- 'ok' | 'replay' | 'denied' | an error class. Never raw error detail.
    outcome           text NOT NULL,
    -- Request semantics minus secrets: never a bearer token, api-key plaintext,
    -- hash, or key material.
    detail            jsonb NOT NULL DEFAULT '{}'::jsonb,
    trace_id          text,
    source_ip         text,
    idempotency_key   text
);

-- The read surface filters by time range, actor, and target (design D6);
-- (…, event_id) keeps each filtered scan in time order without a sort.
CREATE INDEX IF NOT EXISTS admin_audit_events_time_idx
    ON identity.admin_audit_events (occurred_at);
CREATE INDEX IF NOT EXISTS admin_audit_events_actor_idx
    ON identity.admin_audit_events (actor_token_id, event_id);
CREATE INDEX IF NOT EXISTS admin_audit_events_target_idx
    ON identity.admin_audit_events (target_id, event_id);

CREATE TABLE IF NOT EXISTS identity.admin_tokens (
    -- The public token id (`atk_…`) — the attribution handle audit events carry.
    token_id     text PRIMARY KEY,
    -- The named caller this credential identifies (e.g. 'signup-broker', 'ci').
    name         text NOT NULL,
    -- HMAC-SHA256(pepper, secret), hex. The plaintext exists only in the one-time
    -- issuance response. UNIQUE so verification is a single indexed lookup.
    token_hash   text NOT NULL UNIQUE,
    status       text NOT NULL DEFAULT 'active',
    -- Rotation lineage: the token this one replaced.
    rotated_from text,
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS admin_tokens_active_hash_idx
    ON identity.admin_tokens (token_hash) WHERE status = 'active';

-- --------------------------------------------------------------------------- --
-- Append-only enforcement + retention roles (design D7). NOLOGIN group roles:
-- a deployment grants them to the LOGIN users its connection URLs authenticate
-- as (the compose lab connects as the superuser, which bypasses grants — this
-- enforcement is for locked-down deployments).
--   * identity_admin_service — what authz-admin runs as: INSERT/SELECT on the
--     ledger, NO UPDATE/DELETE (events are immutable to the service).
--   * identity_audit_maintenance — what the retention purge runs as: the ONLY
--     identity that may DELETE events (and only the purge does).
-- --------------------------------------------------------------------------- --

DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'identity_admin_service') THEN
        CREATE ROLE identity_admin_service NOLOGIN;
    END IF;
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'identity_audit_maintenance') THEN
        CREATE ROLE identity_audit_maintenance NOLOGIN;
    END IF;
END
$$;

REVOKE ALL ON identity.admin_audit_events FROM PUBLIC;
REVOKE ALL ON identity.admin_tokens FROM PUBLIC;

GRANT USAGE ON SCHEMA identity TO identity_admin_service, identity_audit_maintenance;

-- The service appends and reads — it can never alter or remove an event.
GRANT SELECT, INSERT ON identity.admin_audit_events TO identity_admin_service;
-- Token lifecycle needs status flips (rotate/revoke) — UPDATE stays granted here.
GRANT SELECT, INSERT, UPDATE ON identity.admin_tokens TO identity_admin_service;
-- Retention purge is the only deleter, under the maintenance role only.
GRANT SELECT, DELETE ON identity.admin_audit_events TO identity_audit_maintenance;
