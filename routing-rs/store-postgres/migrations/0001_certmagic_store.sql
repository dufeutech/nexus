-- CertMagic on-demand-TLS certificate store (capability: certificate-store-durability).
--
-- The fleet-shared, durable store behind the Caddy/certmagic front tier that
-- terminates customer-domain ("bring-your-own-domain") TLS. Every edge node points
-- its CertMagic `storage postgres` adapter at THIS schema, so:
--   * any node serves any customer domain from one shared store (no per-node files);
--   * `certmagic_locks` is the distributed lock that single-flights issuance across
--     the fleet — concurrent first-demand for a brand-new host yields ONE CA order;
--   * a lost node loses no certificate — the cert is recoverable here, not re-issued.
--
-- Ownership: these two tables are the adopted CertMagic Storage interface's OWN
-- key/value + lock schema (module `github.com/yroc92/postgres-storage`, the Caddy
-- `storage postgres` provider; schema-identical to `certmagic-sqlstorage`). We own
-- the DDL here — rather than letting the module CREATE it on first run — so the
-- Caddy DB role can be locked down to DML-only and the storage block set to
-- `disable_ddl true` (see deploy/caddy/README.md). The column shapes below MUST
-- track the pinned module; re-verify on any module bump before flipping DDL off.
--
-- Location: this lives in the `routing` database's PUBLIC schema (the same managed
-- Postgres as the routing store — one backup/HA story, per docs/on-demand-tls.md),
-- deliberately SEPARATE from the `routing.*` schema so cert blobs never collide with
-- nexus's routing tables. The tables are PUBLIC-schema-qualified EXPLICITLY (infra N14):
-- applied as a role whose search_path prepends its own same-named schema (e.g. the
-- `routing` DB owner, when a `routing` schema exists), an UNqualified CREATE would land
-- in `routing.*` — and Caddy's role, resolving `public`, then can't see them. Leaf
-- certificates, private keys, OCSP staples and issuance
-- metadata are all CertMagic key/value blobs in `certmagic_data.value` (bytea); the
-- long-lived ACME ACCOUNT key is NOT here — it is custodied in OpenBao Transit (D8).
--
-- Idempotent (CREATE ... IF NOT EXISTS): safe to re-run. Canonical source for K8s
-- (a migration job applies this file) and mirrored by the compose-lab hook
-- postgres-init/40-certmagic-store.sql. There is no in-app init_schema for this
-- store — the writer is the adopted Go module, not a nexus Rust crate.

\connect routing

-- Key/value blob store: one row per CertMagic storage key (cert, key, metadata,
-- OCSP staple). `key` is CertMagic's storage path; `value` is the opaque blob;
-- `modified` drives CertMagic's freshness/stat checks.
CREATE TABLE IF NOT EXISTS public.certmagic_data (
    key      text PRIMARY KEY,
    value    bytea,
    modified timestamptz DEFAULT current_timestamp
);

-- Distributed lock rows: the mechanism behind fleet single-flight. CertMagic takes
-- a lock keyed by the issuance path before ordering a certificate; peers wait on it
-- and then serve the resulting cert rather than each placing their own CA order.
-- `expires` bounds a lock so a crashed holder cannot wedge issuance forever.
CREATE TABLE IF NOT EXISTS public.certmagic_locks (
    key     text PRIMARY KEY,
    expires timestamptz DEFAULT current_timestamp
);
