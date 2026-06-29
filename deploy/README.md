# deploy/ — production topology (first-party services only)

> [!IMPORTANT]
> **TLS is handled *before* this service — it is not in scope here.** These
> services resolve per-request tenant + identity context and attach trusted
> headers; they are intended to run **behind** a TLS-terminating layer (an
> ingress controller, load balancer, or reverse proxy) on a trusted network. The
> edge listener speaks **plaintext** by design. Do **not** expose it directly to
> the public internet — terminate north–south TLS upstream and forward to it.
> This is a deliberate scope boundary, not an omission (see `../INFO.md` §6
> anti-scope).

This directory deploys **only what this repo owns**: the two Rust resolution
planes (`../identity-rs`, `../routing-rs`) and the Envoy edge. Every **stateful**
dependency is **external** and operated outside this project:

| External dependency | Used by            | Why it's external                                  |
| ------------------- | ------------------ | -------------------------------------------------- |
| **PostgreSQL**      | identity sidecar / sync-worker / reconciler | identity store + LISTEN/NOTIFY change feed (RFC C4); session connection required; app creates the `identity` schema |
| **PostgreSQL**      | tenant-router / control-plane | authoritative routing store (RFC decision 14)      |
| **Redis** (optional) | tenant-router     | OPTIONAL L2 cache (RFC decision 9) — never a correctness dependency |
| **ZITADEL** (IdP) + its DB | edge jwt_authn / sync-worker / reconciler | credential issuer; run its own chart / a managed instance |
| **Backend pools**   | edge router        | your applications — the finite set routing selects among (RFC C15) |

Two equivalent topologies, **same images, same env-var contract** (topology
independence, `../INFO.md` §4/§7):

```
deploy/
  helm/
    identity-plane/   identity edge + sync-worker + reconciler   (external Postgres)
    routing-plane/    routing edge + control-plane               (external Postgres, optional Redis)
    edge-platform/    umbrella: both planes, one tenant-first edge (RFC C17)
  compose/
    docker-compose.yaml  the same services as a compose stack
    .env.example         external endpoints (Postgres/Redis/ZITADEL)
    envoy/envoy.yaml     the combined tenant-first edge config
    secrets/             mount point for the ZITADEL admin PAT (gitignored)
```

> The all-in-one **test** lab that bundles the stateful deps lives at
> `../docker-compose.yaml`. The previous, store-bundling charts are kept for
> reference under `../deploy_old/` (Helm with in-chart Mongo/Postgres/Redis, plus
> the `kind/` and `load/` harnesses).

---

## Build the images

All five images come from the two Rust workspaces, selected by Docker build
target (each workspace shares one `core` crate). They are published to **public
GHCR**, so clusters pull them with no registry credentials and no `imagePullSecret`.

### In CI (recommended) — GitHub Actions → GHCR

The `Build images` workflow (`.github/workflows/build-images.yml`) builds all five
and pushes them to GitHub Container Registry. It runs automatically on a `v*` tag,
and has a **manual "Run workflow" button**: GitHub → **Actions** → **Build images**
→ **Run workflow** (optionally enter a tag like `0.1.0`; the short commit SHA is
always tagged). Auth uses the built-in `GITHUB_TOKEN` — no secrets to set up. The
images land at `ghcr.io/<owner>/{identity-sidecar-rs,identity-sync-worker,identity-reconciler,tenant-router,control-plane}`.

[![Build images](https://github.com/OWNER/REPO/actions/workflows/build-images.yml/badge.svg)](https://github.com/OWNER/REPO/actions/workflows/build-images.yml)

> Replace `OWNER/REPO` in the badge above.
>
> **Make each package public — a one-time step per package** (GitHub has no API to
> flip package visibility). After the first push, open each package at
> `https://github.com/users/<owner>/packages/container/<name>/settings` (or the
> org equivalent) → **Danger Zone → Change visibility → Public**. Once public they
> stay public for every later push. Optionally link each to this repo from the same
> page so it inherits the repo's README and access.

### Locally

```bash
# identity plane
docker build --target sidecar     -t REGISTRY/identity-sidecar-rs:0.1.0  ../identity-rs
docker build --target sync-worker -t REGISTRY/identity-sync-worker:0.1.0 ../identity-rs
docker build --target reconciler  -t REGISTRY/identity-reconciler:0.1.0  ../identity-rs
# routing plane
docker build --target tenant-router -t REGISTRY/tenant-router:0.1.0 ../routing-rs
docker build --target control-plane -t REGISTRY/control-plane:0.1.0 ../routing-rs
docker push REGISTRY/...   # all five
```

(The compose stack can build them for you — see below.)

---

## Option A — docker compose

Runs the full first-party stack against your external infrastructure.

```bash
cd compose
cp .env.example .env                      # fill in Postgres / Redis / ZITADEL
printf '%s' '<zitadel-admin-PAT>' > secrets/zitadel-admin-sa.pat
$EDITOR envoy/envoy.yaml                   # set zitadel_jwks + pool_* upstreams
docker compose up -d --build               # builds from ../../identity-rs and ../../routing-rs
```

The edge listens on `:10000` (override `EDGE_PORT`). The control-plane admin API
is bound to `127.0.0.1:9400` — an administrative boundary, never public.

## Option B — Helm

Each plane chart is independently deployable; `edge-platform` composes both onto
one tenant-first edge. North–south TLS is terminated by your ingress controller
(cert-manager), which is why the planes carry no in-app TLS.

```bash
# Identity plane (external Postgres required; session connection)
helm install identity ./helm/identity-plane -n identity --create-namespace \
  --set images.sidecar.repository=REGISTRY/identity-sidecar-rs \
  --set images.syncWorker.repository=REGISTRY/identity-sync-worker \
  --set images.reconciler.repository=REGISTRY/identity-reconciler \
  --set postgres.existingSecret=identity-pg \
  --set zitadel.issuer=https://auth.example.com \
  --set zitadel.internalUrl=http://zitadel.zitadel.svc.cluster.local:8080 \
  --set zitadel.patSecret.existingSecret=zitadel-pat \
  --set backend.host=myapp.default.svc.cluster.local \
  --set edge.ingress.host=api.example.com

# Routing plane (external Postgres required; Redis optional)
helm install routing ./helm/routing-plane -n routing --create-namespace \
  --set images.tenantRouter.repository=REGISTRY/tenant-router \
  --set images.controlPlane.repository=REGISTRY/control-plane \
  --set postgres.existingSecret=routing-pg \
  --set pools.application.host=app-backend.default.svc.cluster.local \
  --set edge.ingress.hosts='{*.example.com}'

# Both planes, one combined edge (umbrella)
helm dependency build ./helm/edge-platform
helm install edge ./helm/edge-platform -n edge --create-namespace -f my-values.yaml
```

Create the credential Secrets out-of-band (preferred over inline values):

```bash
kubectl -n identity create secret generic zitadel-pat --from-file=pat=./zitadel-admin-sa.pat
kubectl -n identity create secret generic identity-pg --from-literal=url='postgres://user:pass@host:5432/identitydb'
kubectl -n routing  create secret generic routing-pg  --from-literal=url='postgres://user:pass@host:5432/routing'
```

A `values-prod.yaml` in your own config repo beats a wall of `--set`. See each
chart's `values.yaml` for every tunable and its `NOTES.txt` for post-install
checks.

---

## Why no in-app TLS / no bundled stores

- **North–south TLS** is terminated at the ingress (Helm) or your LB (compose);
  Envoy receives plaintext over the trusted network. East–west mTLS, if your
  threat model needs it, is a service-mesh concern — nothing here blocks it.
- **Stateful systems are external** so their lifecycle (HA, backups, failover,
  upgrades) is owned by the team/operator that runs them, not coupled to a
  deploy of this code. The env-var contract is the only binding interface; keep
  it in sync across `helm/*/values.yaml` and `compose/.env.example`.

## External Postgres requirements (routing store)

The routing plane uses Postgres for two things: the authoritative store (point
reads/writes by key) **and** a cache-invalidation feed over **`LISTEN/NOTIFY`**.
Every control-plane mutation runs `pg_notify('routing_invalidations', <domain>)`
(`../routing-rs/store-postgres/src/lib.rs`); the tenant-router holds a dedicated
listener connection (`LISTEN routing_invalidations`) and evicts that key from
every cache tier (RFC C16). This shapes what your external/managed Postgres must
provide:

- **`ROUTING_PG_URL` must reach the primary on a *session* connection — never a
  transaction-mode pooler.** `LISTEN/NOTIFY` is session-scoped, so a
  transaction/statement-mode pooler (PgBouncer default, Supabase's `:6543` pool,
  some RDS Proxy setups) **silently swallows `LISTEN`**: the router connects
  without error and simply never receives invalidations. The only symptom is
  domains staying stale for a full TTL. The control-plane and the tenant-router's
  `LISTEN` feed both use this direct URL.
- **Want to pool the read load? Use the opt-in `ROUTING_PG_READ_URL`.** The
  tenant-router's *cache-miss point reads* (the only high-volume DB traffic) can
  run through a transaction-mode pooler via this separate variable, while the
  `LISTEN` feed stays on the direct `ROUTING_PG_URL`. Leave it empty and reads use
  the direct URL too. The read pool disables sqlx's prepared-statement cache so it
  is safe through PgBouncer (the point reads are trivial, so the cache buys
  nothing). Helm: `postgres.readExistingSecret` / `postgres.readUrl`. Compose:
  `ROUTING_PG_READ_URL`. The control-plane is a low-volume admin writer and always
  stays on the direct URL.
- **NOTIFY is emitted by the primary and not delivered by physical replicas** —
  another reason the listener must target the writer, not a read replica.
- **The control-plane role needs `CREATE`.** On startup it runs
  `CREATE SCHEMA IF NOT EXISTS routing` + `CREATE TABLE …` (idempotent). On a
  locked-down managed DB, either grant the control-plane role `CREATE ON DATABASE`,
  or pre-create the `routing` schema and grant table privileges. The tenant-router
  only point-reads — it never creates schema. No special grant is needed for
  `LISTEN`/`NOTIFY` themselves (any role may).
- **This feed is best-effort by design.** A dropped NOTIFY is not a correctness
  problem: the L1/L2 entry self-heals at `ROUTING_CACHE_TTL` (default 600s). So a
  broken listener degrades to "domain changes take up to one TTL to take effect,"
  never wrong routing — but in production you want the feed working so changes
  land in seconds, which is exactly why the pooler caveat above matters.

(The identity plane now uses the **same `LISTEN/NOTIFY` mechanism** as routing —
its sidecar holds a listener on channel **`identity_changes`** and advances a
`seq` cursor to keep its cache fresh (RFC C4). So everything in this section
applies to the identity store too: `PROFILE_PG_URL` must be a direct/session
connection to the primary (never a transaction-mode pooler), and the identity
role needs `CREATE` so the app can run `CREATE SCHEMA IF NOT EXISTS identity` on
startup. No replica set is required.)

## The non-negotiables still apply

When you add a trusted header, add it to the C3 strip list in **every** edge
config (`compose/envoy/envoy.yaml` and the three `helm/*/templates/edge-configmap.yaml`).
A forgotten strip is a privilege-escalation bug. See `../INFO.md` §4.
