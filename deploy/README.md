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

Before a first production rollout, walk the **[Production deployment
checklist](#production-deployment-checklist)** below — the repo's CI gate
certifies the platform's behavior; the checklist covers the operator-owned
half (real origin enforcement, secrets, pins, stores, monitoring).

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
  --set zitadel.internalUrl=https://zitadel.zitadel.svc.cluster.local:8443 \
  --set zitadel.patSecret.existingSecret=zitadel-pat \
  --set zitadel.jwksTls.enabled=true \
  --set originEnforcement.networkPolicy.enabled=true \
  --set originEnforcement.networkPolicy.backendSelector.app=myapp \
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

## BREAKING — upgrading to the fail-closed edge guards

Two guards now make previously-implicit security choices explicit. A chart
render that used to succeed will **refuse to render** until each choice is
made — that refusal is the feature (fail closed), not a packaging bug.

### 1. JWKS trust-anchor integrity (`edge-trust-anchor-integrity`)

Earlier versions fetched the ZITADEL JWKS — the keys ALL token verification
rests on — over plaintext HTTP, silently. An on-path attacker who substitutes
that response owns every "verified" identity. Now the stamping edges
(identity-plane, edge-platform umbrella) require one of:

- **`zitadel.jwksTls.enabled=true`** (preferred): the JWKS is fetched over TLS
  with server-cert verification (trusted CA + SNI + SAN pin). Point
  `zitadel.internalUrl` at a TLS port; for a private CA, mount your bundle
  into the Envoy pod and set `zitadel.jwksTls.caFile`; set
  `zitadel.jwksTls.sni` when the cert is issued for a name other than the
  dialed host.
- **`zitadel.jwksPlaintextTrustedPath=true`**: an explicit assertion that the
  edge→ZITADEL hop is a trusted path (e.g. genuinely in-cluster and assessed).
  This is an acknowledgment, not a control — prefer TLS.

Migration for a deployment currently on plaintext JWKS over an untrusted hop:
enable TLS on ZITADEL's serving endpoint (or front it with a TLS hop you
trust), then set `zitadel.jwksTls.enabled=true`. Until then, upgrading the
chart without either value is a hard render error by design.

(On the umbrella, both values live under the `identity-plane:` block.)

### 2. Origin enforcement (`edge-origin-trust`)

The `x-workspace-*`/`x-user-*`/`x-identity-contract` headers are unforgeable
ONLY because backends accept requests exclusively via the edge — the stamp is
a drift/version signal, not an authentication boundary. Topologies rendering
identity enrichment now require one of:

- **`originEnforcement.networkPolicy.enabled=true`** plus
  `originEnforcement.networkPolicy.backendSelector.<label>=<value>`: ships a
  NetworkPolicy restricting the backend pods' ingress to the edge pods (same
  namespace; the CNI must enforce NetworkPolicy — probe it with a
  direct-to-backend request, which must be refused).
- **`originEnforcement.external=true`**: the invariant is enforced outside the
  chart (backends in another namespace/cluster/network you police). The
  absence of any origin control is a misconfiguration, never a default-safe
  state.

## Production deployment checklist

The platform itself is gated: every spec-asserted security boundary is enforced
and regression-tested (render guards, unit/integration, and the CI e2e release
gate against the reference topology). What the gate can NOT certify is *your*
deployment of it — these are the operator-owned items to walk before the first
production rollout. Each is a one-line check; the details live in the section
or values comment referenced.

**Security invariants you must make true (the charts enforce the *choice*, you
supply the *truth*):**

- [ ] **Origin enforcement is real, not asserted.** If the backends run in the
      chart's namespace, use `originEnforcement.networkPolicy.*` and verify your
      CNI enforces NetworkPolicy by probing: a direct-to-backend request bearing
      forged `x-workspace-id`/`x-identity-contract` must be REFUSED (see
      `../scripts/tenancy-edge-e2e.sh` §6 for the shape of the probe). If you set
      `originEnforcement.external=true`, that is an assertion — you own the
      network control (policy/mesh/firewall) that makes it true, and you should
      run the same probe against it.
- [ ] **JWKS over verified TLS.** `zitadel.jwksTls.enabled=true` with a CA the
      Envoy pod can read (`jwksTls.caFile`) and the right `jwksTls.sni`. Use
      `jwksPlaintextTrustedPath=true` ONLY for a genuinely in-cluster hop you
      have assessed — it is an acknowledgment, not a control.
- [ ] **The consuming backend implements its half of the stamp contract.** Nexus
      emits `x-identity-contract` and the spec scopes the rule, but rejecting an
      absent/unknown stamp on identity-enriched routes is the BACKEND's code
      (deliberately out of this repo's test surface). If you own the backend,
      that check is its backlog item, not an assumption.
- [ ] **Control-plane reachability matches C16.** Broker-only NetworkPolicy on
      :9400 (`controlPlane.networkPolicy.*`), scrapers/kubelet on the ops port
      :9401 only; `CONTROL_AUTH_TOKEN` from a Secret, never `CONTROL_AUTH_DISABLED`.

**Config hygiene:**

- [ ] **Secrets via `existingSecret` everywhere** (postgres, routingPg, ZITADEL
      PAT, control token) — inline `*.url`/`value` land in the release manifest.
- [ ] **Pin every image.** First-party images to a concrete tag you built; the
      Envoy image to a concrete patch version (`images.envoy.tag` floats on
      `v1.34-latest` by default — the values file says pin it; do). The lab
      pins ZITADEL for the same reason (a floating tag broke the CI gate).
- [ ] **Issuer single-sourced (D7).** `zitadel.issuer` must equal the `iss`
      ZITADEL mints AND the value the workers derive — drift is silent-but-fatal
      (sync works, every authenticated request 401s). The lab guards this in
      `../scripts/helm-guards-test.sh`; re-check it for your values file.
- [ ] **TLS/ingress values are real**: `edge.ingress.host(s)`, cert-manager
      issuer annotations, TLS secret names.
- [ ] **Postgres URLs follow the session-connection rules** — see “External
      Postgres requirements” below (txn-mode poolers silently swallow the
      LISTEN feeds); `?sslmode=verify-full` on both stores.

**Operations (never exercised by the repo's gate):**

- [ ] **Store lifecycle is owned**: HA, backups, restore-tested, failover for
      the routing + identity databases (external by design — see below).
- [ ] **Monitoring wired**: `metrics.serviceMonitor.*` per chart; alert at least
      on edge 5xx/`ext_proc` failures, sidecar/router invalidation-feed staleness
      (`*_last_apply` metrics), and control-plane auth failures.
- [ ] **Load/scale validated for your traffic** — the gate proves correctness,
      not capacity. Size sidecar memory to the resident profile population and
      revisit `edge.replicas`/HPA.
- [ ] **Upgrades from pre-gate versions scheduled** — the fail-closed guards are
      BREAKING by design; see the section above for the two choices every
      existing deployment must make before it renders again.

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

### Cross-plane: membership-sync reads the routing store (read-only)

The identity plane's **membership-sync** worker is the one component that reaches
**across** planes: it holds a **read-only** connection to the ROUTING database
(`ROUTING_PG_RO_URL`) to `LISTEN` on channel **`routing_membership_changes`** and
`SELECT routing.memberships`, projecting them into `Profile.memberships` (which the
sidecar resolves the acting workspace against). Notes:

- **Direction is one-way and least-privilege.** The identity plane only READS
  routing; the routing store stays the single writer/source of record. Grant the
  credential `SELECT` on `routing.memberships` + `LISTEN` only — no write, no other
  tables. Routing never writes identity profiles.
- **Same pooler caveat.** `ROUTING_PG_RO_URL` must be a direct/session connection
  (a txn-mode pooler swallows `LISTEN`). In production this is a **separate
  database** from `PROFILE_PG_URL`; in the dev compose both collapse onto one server.
- **Best-effort + backstop.** A dropped `routing_membership_changes` NOTIFY is not a
  correctness problem: a periodic backstop (`MEMBERSHIP_BACKSTOP_INTERVAL`) re-derives
  every subject's memberships from the source of record (and backfills on first run).
- Wire it in Helm via `routingPg.existingSecret`/`routingPg.url` (identity-plane
  chart), or set `membershipSync.enabled: false` to skip the worker entirely.

## The non-negotiables still apply

When you add a trusted header, add it to the C3 strip list in **every** edge
config (`compose/envoy/envoy.yaml` and the three `helm/*/templates/edge-configmap.yaml`).
A forgotten strip is a privilege-escalation bug. See `../INFO.md` §4.
