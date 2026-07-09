-- CertMagic certificate store bootstrap (capability: certificate-store-durability)
-- — compose-lab hook.
--
-- Runs ONCE on fresh cluster init (empty data dir) via the postgres image's
-- /docker-entrypoint-initdb.d hook, AFTER 10-create-nexus-databases.sql created the
-- `routing` database. Applies the same DDL as the canonical migration
-- routing-rs/store-postgres/migrations/0001_certmagic_store.sql (the source of truth
-- for K8s, where a migration job applies it).
--
-- Keep the DDL in lockstep with that migration file. These tables are the adopted
-- CertMagic `storage postgres` module's own key/value + lock schema; owning the DDL
-- here lets the lab lock the Caddy DB role down and set `disable_ddl true` once the
-- tables exist (see deploy/caddy/README.md). No seed rows: certs are obtained on
-- demand on first handshake for an authorized host; the e2e drives that path
-- (scripts/custom-domains-tls-e2e.sh).

\connect routing

CREATE TABLE IF NOT EXISTS certmagic_data (
    key      text PRIMARY KEY,
    value    bytea,
    modified timestamptz DEFAULT current_timestamp
);

CREATE TABLE IF NOT EXISTS certmagic_locks (
    key     text PRIMARY KEY,
    expires timestamptz DEFAULT current_timestamp
);
