# Customer-domain TLS front tier (Caddy / CertMagic)

The TLS-terminating front tier for **tenant custom domains** (bring-your-own-domain).
It obtains a public certificate **on demand** on first handshake for an authorized
hostname, serves it, and renews it ahead of expiry — then forwards cleartext to the
existing identity/authz **Envoy edge**. It changes nothing downstream (identity
enrichment, the auth gate, tenant resolution are untouched).

This is **adopted** infra (design D1): Caddy embeds CertMagic, which is purpose-built
for on-demand TLS + an `ask` gate + fleet-shared storage. It enters the system only
through two contracts — the **`ask` HTTP endpoint** and the **Postgres Storage
interface** — so nexus core has no compile-time dependency on it. See the change
`openspec/changes/custom-domains-tls/` and the edge spec `docs/on-demand-tls.md`.

> Scope: the **tenant-custom-domain** path only (arbitrary `app.acme.com` declared at
> runtime). First-party ingress (`api.example.com`, `*.example.com`) is a finite known
> set terminated by cert-manager / your LB — out of scope here (see `../README.md`).

## Files

| File | Purpose |
|------|---------|
| `Caddyfile` | Native front-tier config (mounted read-only). On-demand TLS + `ask` gate + ECDSA P-256 + Let's Encrypt issuer + Postgres storage. |
| `acme-account-transit-init.sh` | Provision/inject the ACME **account key** in OpenBao Transit (design D8). |
| `../../routing-rs/store-postgres/migrations/0001_certmagic_store.sql` | Canonical cert-store schema (`certmagic_data`, `certmagic_locks`). We own the DDL. |

## Build (the Postgres storage module is not in stock Caddy)

```bash
xcaddy build --with github.com/yroc92/postgres-storage
```

Bake that into the edge image. Pin the module to a commit and re-verify it still tracks
current CertMagic before bumping Caddy. (`certmagic-sqlstorage` is a schema-identical
alternative — same `certmagic_data` / `certmagic_locks` tables — so the migration and
`disable_ddl true` posture below apply to either; the Storage interface is the seam.)

## Environment contract

```bash
# SHARED cert store — the SAME Postgres that holds the routing store (one managed DB,
# one backup/HA story). Cert blobs live in CertMagic's own tables (public schema),
# separate from routing.* — no collision. Use a SESSION/direct connection (CertMagic
# uses locks); never a transaction-mode pooler.
CADDY_STORAGE_PG_URL=postgres://caddy:***@pg-primary:5432/routing?sslmode=verify-full

# The LOCAL tenant-router's Caddy-`ask`-compatible endpoint, co-located per edge host.
# Answers in ~ms from its in-memory cache; fail-closed (403) for unknown SNI.
AUTHORIZE_URL=http://127.0.0.1:9300/authorize

# The tenant-first Envoy edge this tier forwards cleartext to.
EDGE_UPSTREAM=127.0.0.1:10000

# ACME: Let's Encrypt production directory + the account email. ARI is automatic on
# Caddy 2.8+ (do not disable) — renewals ride LE's rate-limit exemption.
ACME_CA_DIR=https://acme-v02.api.letsencrypt.org/directory
ACME_EMAIL=tls-ops@your-org.example

# ACME account key, injected by-key from OpenBao Transit at boot (see below).
ACME_ACCOUNT_KEY_FILE=/run/secrets/acme-account.key
```

## ACME account key (OpenBao Transit — design D8)

The long-lived **account** key (authenticates the platform to the CA for every order /
renewal) is custodied in OpenBao Transit, consistent with the identity signing-key
custody (`../compose/signing`). **Leaf** certificates and their private keys stay in
Postgres (`certmagic_data`); only this one account key comes from Transit.

```bash
# 1. Provision the exportable account key (once):
BAO_ADDR=http://127.0.0.1:8200 BAO_TOKEN=root ./acme-account-transit-init.sh

# 2. At front-tier boot, export it by-key into the tmpfs secret Caddy mounts:
RUN_EXPORT=1 ACME_ACCOUNT_KEY_FILE=/run/secrets/acme-account.key ./acme-account-transit-init.sh
```

The front-tier entrypoint seeds `ACME_ACCOUNT_KEY_FILE` into CertMagic's ACME account
before `caddy run`, so CertMagic adopts THIS account rather than registering a fresh
one into Postgres. The key is referenced by-name, materialized to tmpfs, and never
written into the image or committed. (The exact seed step is finalized during lab
bring-up — task 5.1 — against the pinned xcaddy build.)

## Store schema & role lockdown

Apply the canonical migration once, then lock the Caddy DB role to DML-only and keep
`disable_ddl true` in the `Caddyfile` storage block:

```bash
psql "$CADDY_STORAGE_PG_URL" -f ../../routing-rs/store-postgres/migrations/0001_certmagic_store.sql
```

The `certmagic_locks` table is the distributed lock that single-flights issuance across
the fleet — concurrent first-demand for a brand-new host yields exactly **one** CA
order; peers wait and serve the resulting cert (`certificate-store-durability`).

## Wiring

- **Compose lab:** the `caddy` service in `../compose/docker-compose.yaml` mounts this
  `Caddyfile`, depends on `tenant-router` (for `ask`) and `envoy` (the upstream), and
  publishes `:443`/`:80`.
- **Helm:** shipped by the `edge-platform` umbrella under `frontTier.*` (closes infra
  finding N12). A vendored copy of this `Caddyfile` (`edge-platform/files/caddy/Caddyfile`,
  kept in sync — its only divergence is a Helm-guarded `listener_wrappers` block) is
  mounted from a ConfigMap; the chart adds a front-tier Deployment + Service on `:443`/`:80`,
  a dedicated `ask` Service fronting `tenant-router:9300`, and injects
  `ACME_ACCOUNT_KEY_FILE` and `CADDY_STORAGE_PG_URL` from Secrets. The ACME account key is
  delivered **out-of-band** via `frontTier.acmeAccount.existingSecret` (ESO / OpenBao Secrets
  Operator / a Kubernetes-auth role — the chart bundles no secrets operator, mirroring
  identity signing). Enable with `frontTier.enabled=true`; see the chart `values.yaml`
  `frontTier` block and `deploy/helm/edge-platform/tests/front-tier_test.yaml`.

## Adding a second CA (config-only — design D4)

ZeroSSL (or any ACME CA) is a **second `cert_issuer` line** in the `Caddyfile` and
nothing else — issuers are tried in order. ZeroSSL needs `eab <key_id> <mac_key>`; its
ARI exemption is unconfirmed (LE-specific), so it stays deferred until onboarding
volume or outage-risk justifies it.

## Operational notes

- `/authorize` must be reachable from Caddy on every edge host and stay fail-closed; a
  5xx/timeout there blocks issuance — correct (never issue a cert you can't authorize).
- Route `CADDY_STORAGE_PG_URL` to the primary on a direct/session connection.
- An **issuer outage degrades only new-domain onboarding** — every host with a valid
  stored cert keeps serving from Postgres. This is the "certificate automation is a
  side tool" invariant (design goal).
