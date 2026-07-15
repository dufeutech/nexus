-- Admin-token scopes (capability: admin-plane-authorization).
--
-- Adds the per-credential grant to `routing.admin_tokens`: the scope set the
-- authorization gate evaluates every admin action against (deny-by-default).
-- The vocabulary is closed (router_core::admin_authz::SCOPES — the application
-- refuses anything else at write time):
--   * read        — GETs: tenancy/domain/auth-route reads, audit query/export
--   * provision   — mutations of platform data (accounts, workspaces,
--                   memberships, domains, auth-route rules)
--   * token-admin — admin-credential administration (mint/rotate/revoke/list);
--                   distinguished: no other scope includes it, so an ordinary
--                   credential can never expand its own grant.
--
-- The backfill grants every credential existing at cutover the FULL scope set
-- (spec "Cutover preserves existing callers": parity first, narrowing is an
-- explicit operator act afterward). It targets empty-scoped rows only, which
-- keeps the file idempotent: post-cutover the application enforces a non-empty
-- scope set at mint, so no legitimately-narrowed token can ever match again.
--
-- Canonical source for K8s (a migration job applies this file); the control
-- plane runs the same DDL at startup (PgRoutingStore::init_schema — keep the
-- two in lockstep). Additive only: an old binary ignores the column (rollback
-- is reverting the image, no data rollback).

\connect routing

ALTER TABLE routing.admin_tokens
    ADD COLUMN IF NOT EXISTS scopes text[] NOT NULL DEFAULT '{}';

UPDATE routing.admin_tokens
    SET scopes = ARRAY['read', 'provision', 'token-admin'], updated_at = now()
    WHERE cardinality(scopes) = 0;
