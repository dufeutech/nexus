-- Administrative audit ledger + named admin tokens (capability: admin-action-audit).
--
-- `routing.admin_audit_events` is the control plane's append-only record of every
-- mutating admin action: written IN THE SAME TRANSACTION as the mutation it
-- describes (fail-closed — an unrecorded mutation does not commit, design D1/D2),
-- plus best-effort denial events on the 401 path. Events carry typed, time-ordered
-- ids (`aev_<uuidv7>`), the acting credential id, the caller-asserted operator
-- (recorded verbatim, confers nothing), target, outcome, correlation data, and a
-- secret-free JSON detail. NOT telemetry: this ledger never rides the fail-open
-- collection layer.
--
-- `routing.admin_tokens` makes admin credentials individually identifiable
-- (design D4): one row per named caller (broker, ops CLI, CI), storing ONLY the
-- peppered HMAC-SHA256 of the secret (env ADMIN_TOKEN_PEPPER; see
-- routing-rs/store-postgres/src/admin_audit.rs), with rotation lineage and
-- status-flip revocation.
--
-- Idempotent (CREATE ... IF NOT EXISTS): safe to re-run. Canonical source for K8s
-- (a migration job applies this file); the control plane runs the same table DDL
-- at startup (PgRoutingStore::init_schema — keep the two in lockstep). The
-- role/grant DDL below exists ONLY here: append-only is DB-enforced by withholding
-- UPDATE/DELETE on the ledger from the role the service connects as, and retention
-- purge — the only permitted deletion (design D7) — runs as the separate
-- maintenance role (env AUDIT_MAINTENANCE_PG_URL).

\connect routing

CREATE SCHEMA IF NOT EXISTS routing;

CREATE TABLE IF NOT EXISTS routing.admin_audit_events (
    -- `aev_<uuidv7>`: self-describing and lexicographically time-ordered, so the
    -- primary-key order IS the event-time order (query surface + cursor rely on it).
    event_id          text PRIMARY KEY,
    occurred_at       timestamptz NOT NULL DEFAULT now(),
    -- Which admin surface recorded it ('control-plane' here; the identity plane's
    -- twin table records 'authz-admin').
    surface           text NOT NULL,
    -- Closed action vocabulary (router_core::audit::ACTIONS) — the application
    -- refuses to record anything outside it.
    action            text NOT NULL,
    -- The acting credential's id (`atk_…`) or a reserved actor id
    -- (`legacy-shared`, `auth-disabled`, `system:*`, `unauthenticated`).
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
    ON routing.admin_audit_events (occurred_at);
CREATE INDEX IF NOT EXISTS admin_audit_events_actor_idx
    ON routing.admin_audit_events (actor_token_id, event_id);
CREATE INDEX IF NOT EXISTS admin_audit_events_target_idx
    ON routing.admin_audit_events (target_id, event_id);

CREATE TABLE IF NOT EXISTS routing.admin_tokens (
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
    ON routing.admin_tokens (token_hash) WHERE status = 'active';

-- --------------------------------------------------------------------------- --
-- Append-only enforcement + retention roles (design D7). NOLOGIN group roles:
-- a deployment grants them to the LOGIN users its connection URLs authenticate
-- as (the compose lab connects as the superuser, which bypasses grants — this
-- enforcement is for locked-down deployments).
--   * routing_control_service — what the control plane runs as: INSERT/SELECT
--     on the ledger, NO UPDATE/DELETE (events are immutable to the service).
--   * routing_audit_maintenance — what the retention purge runs as: the ONLY
--     identity that may DELETE events (and only the purge does).
-- --------------------------------------------------------------------------- --

DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'routing_control_service') THEN
        CREATE ROLE routing_control_service NOLOGIN;
    END IF;
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'routing_audit_maintenance') THEN
        CREATE ROLE routing_audit_maintenance NOLOGIN;
    END IF;
END
$$;

REVOKE ALL ON routing.admin_audit_events FROM PUBLIC;
REVOKE ALL ON routing.admin_tokens FROM PUBLIC;

GRANT USAGE ON SCHEMA routing TO routing_control_service, routing_audit_maintenance;

-- The service appends and reads — it can never alter or remove an event.
GRANT SELECT, INSERT ON routing.admin_audit_events TO routing_control_service;
-- Token lifecycle needs status flips (rotate/revoke) — UPDATE stays granted here.
GRANT SELECT, INSERT, UPDATE ON routing.admin_tokens TO routing_control_service;
-- Retention purge is the only deleter, under the maintenance role only.
GRANT SELECT, DELETE ON routing.admin_audit_events TO routing_audit_maintenance;
