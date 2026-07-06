-- nexus-owned databases (capability: identity-data-residency).
--
-- nexus stores its authorization-relevant data in its OWN databases on this
-- Postgres server, never inside the identity provider's `zitadel` database. The
-- server already creates `zitadel` (POSTGRES_DB) for ZITADEL itself; this script
-- adds the nexus-owned databases alongside it.
--
-- Runs ONCE, on first cluster init (empty data directory), via the postgres
-- image's /docker-entrypoint-initdb.d hook. The stores create their `identity` /
-- `routing` SCHEMAS idempotently on startup (init_schema()), so these databases
-- only need to exist — they are created empty and the writers repopulate them
-- (rebuildable-projection rollout; see the change's design.md).
--
-- Postgres has no `CREATE DATABASE IF NOT EXISTS`; a plain CREATE is safe here
-- because the hook only runs against a fresh, empty data directory.

CREATE DATABASE identitydb;
CREATE DATABASE routing;
