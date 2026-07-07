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
| **PostgreSQL** (`identitydb`) | identity sidecar / authz-admin / membership-sync | nexus-owned identity store + LISTEN/NOTIFY change feed (RFC C4); session connection required; app creates the `identity` schema. Separate database from the IdP (identity-data-residency) |
| **PostgreSQL** (`routing`) | tenant-router / control-plane | nexus-owned authoritative routing store (RFC decision 14); separate database from the IdP |
| **Redis** (optional) | tenant-router     | OPTIONAL L2 cache (RFC decision 9) — never a correctness dependency |
| **OIDC provider** (IdP) | edge jwt_authn | credential issuer; ANY conformant OIDC provider by config (oidc-provider-independence). Owns ONLY authentication (JWKS for token verification) — NOT authorization and not nexus's data (`nexus-native-authorization`). No admin PAT / directory integration. Run its own chart / a managed instance |
| **Backend pools**   | edge router        | your applications — the finite set routing selects among (RFC C15) |

Two equivalent topologies, **same images, same env-var contract** (topology
independence, `../INFO.md` §4/§7):

```
deploy/
  helm/
    identity-plane/   identity edge + authz-admin + membership-sync   (external Postgres)
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
images land at `ghcr.io/<owner>/{identity-sidecar-rs,identity-authz-admin,identity-membership-sync,tenant-router,control-plane}`.

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
docker build --target sidecar         -t REGISTRY/identity-sidecar-rs:0.1.0      ../identity-rs
docker build --target authz-admin     -t REGISTRY/identity-authz-admin:0.1.0     ../identity-rs
docker build --target membership-sync -t REGISTRY/identity-membership-sync:0.1.0 ../identity-rs
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
cp .env.example .env                       # fill in Postgres / Redis; set IDENTITY_ADMIN_TOKEN
                                           # (authz-admin) + CONTROL_AUTH_TOKEN (control-plane)
$EDITOR envoy/envoy.yaml                    # set oidc_jwks + pool_* upstreams
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
  --set images.authzAdmin.repository=REGISTRY/identity-authz-admin \
  --set images.membershipSync.repository=REGISTRY/identity-membership-sync \
  --set postgres.existingSecret=identity-pg \
  --set oidc.issuer=https://auth.example.com \
  --set oidc.jwksInternalUrl=https://zitadel.zitadel.svc.cluster.local:8443 \
  --set authzAdmin.existingSecret=identity-authz-admin \
  --set oidc.jwksTls.enabled=true \
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
# MANDATORY before every install/upgrade: re-vendor the subcharts. The subcharts are
# LOCAL path dependencies, so edge-platform/charts/*.tgz are snapshots — `update`
# regenerates Chart.lock AND repackages the CURRENT subchart source. Skipping it (or
# using `dependency build`, which only restores a possibly-stale lock) renders the OLD
# subchart templates — e.g. a removed template reappears or a new value is ignored.
# The tarballs are gitignored (never committed), so a fresh checkout MUST run this.
helm dependency update ./helm/edge-platform
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

## Tracing (edge-rooted, N6)

The edge is the **sole root of trace context** on the internal network: client
`traceparent`/`tracestate` are stripped before Envoy's tracing decision, the
edge makes the head-sampling decision, and injects W3C trace context toward the
backend pools (unsampled requests carry a *not-sampled* `traceparent`; boxes
continue the trace when present, root their own when absent — **bring-up order
stays flexible in either direction**). Export is OTLP/gRPC to an **OTel
Collector — the single telemetry egress**: producers know only the collector;
only the collector's config knows the trace store (Tempo → Grafana). Export is
**fail-open**: an unreachable collector never affects request handling.

- **Compose:** the `otel_collector` cluster in `compose/envoy/envoy.yaml` is an
  EXTERNAL upstream like the pools — point it at your collector's OTLP/gRPC
  endpoint. Sampling knob: `TRACE_SAMPLING_PCT` in `.env` (whole percent,
  0–100; overrides at runtime via the compose command, no config edit). The
  test lab (`../docker-compose.yaml` + `../monitoring/`) bundles a working
  collector + Tempo + Grafana datasource to copy from.
- **Helm:** `edge.tracing.*` on the `edge-platform` umbrella —
  `enabled`, `collectorHost`/`collectorPort`, `samplingPercent`. The collector
  and Tempo are EXTERNAL to the charts, exactly like Prometheus
  (ServiceMonitors → your operator). Enable it: a topology that can trace,
  should.
- **Hygiene is enforced in the stanza, not by policy:** span attributes are the
  access-log-allowed set only (method/path/status/durations, route pool,
  workspace id). Adding a `custom_tags` entry for a credential or `x-user-*`
  header is a spec violation (`edge-request-tracing`).
- Log↔trace correlation shipped with the box telemetry contract (below);
  service spans and retention/SLO policy remain on the roadmap in the
  `box-telemetry-contract` change's `design.md`.

## Telemetry — all signals (the box telemetry contract)

Tracing above is one signal of three. The OTel Collector accepts **traces,
metrics, and logs** on the same OTLP endpoint — the single telemetry egress for
every producer on the internal network. Only the collector's config knows the
stores (traces → Tempo, pushed metrics → Prometheus's native OTLP receiver,
logs → Loki), and all three are explored in the same Grafana with a two-way
logs↔traces pivot by trace ID. The consumer-facing half — what a compliant box
must emit — is the "Box telemetry contract" section of
`nexus-upstream-requirements.md`.

- **Cluster (helm) pattern — identical to how tracing shipped:** the collector
  and ALL stores are EXTERNAL to the charts, exactly like Prometheus. A box's
  workload spec carries exactly one telemetry address — the collector's OTLP
  endpoint (for SDK-instrumented boxes, the standard
  `OTEL_EXPORTER_OTLP_ENDPOINT` env var). No chart code changes exist or are
  needed: there is no per-box scrape config to coordinate (box metrics are
  pushed), no log-shipper sidecar (logs are pushed), and no store address in
  any workload manifest. Swapping or fanning out a store is a collector-config
  edit, invisible to every box.
- **Compose/lab knobs:** the lab (`../docker-compose.yaml` + `../monitoring/`)
  bundles the full stack to copy from — collector pipelines in
  `monitoring/otel-collector/otel-collector.yaml` (store endpoints via
  `TEMPO_OTLP_ENDPOINT` / `LOKI_OTLP_ENDPOINT` / `PROMETHEUS_OTLP_ENDPOINT`
  env), the log store in `monitoring/loki/loki.yaml` (retention default 7d —
  `limits_config.retention_period`; traces stay at 48h), and pinned store
  images (`LOKI_VERSION`, `PROMETHEUS_VERSION` in `.env`) because native OTLP
  ingestion is version-gated in both stores. Bump pins deliberately and re-run
  the telemetry smoke checks.
- **First-party services now push, not scrape (Change B — `first-party-telemetry`,
  shipped):** the Rust services (tenant-router, control-plane, identity sidecar,
  authz-admin, membership-sync) emit RED + operational metrics through
  the OTel meter to the collector — the same push path as any box. Their Prometheus
  scrape jobs and ServiceMonitors were retired; only Envoy's own admin stats
  (`:9901`) remain scrape-based (Envoy is outside the box telemetry contract). Metric
  **names are unchanged** (OTel counters drop the `_total` suffix that Prometheus's
  OTLP receiver re-appends), so existing dashboard queries keep working. First-party
  spans also join the edge-rooted trace and their logs carry the trace id.
- **Bring-up order is flexible and everything is fail-open:** a down collector
  or store never affects request handling; boxes buffer/drop telemetry and
  resume on their own when the collector returns. Producers deliberately do
  not `depends_on` the collector.
- **Nexus ships its alert rules + dashboards as code (opt-in chart artifacts).**
  The engine evaluates; nexus authors the content (it needs domain knowledge of the
  metrics). Enable per chart:
  - `metrics.prometheusRule.enabled=true` → a `PrometheusRule` CR of app-SLO alerts
    (edge 5xx ratio, routing/enrich p99, authz-gate 403/fail-closed spike,
    membership-sync/control-plane errors). Consumed by the Prometheus Operator **or**
    the VictoriaMetrics operator/vmalert. Tune the `> X` values under
    `metrics.prometheusRule.thresholds`. On the umbrella, enable it on each subchart
    (`identity-plane.metrics.prometheusRule.enabled`, `routing-plane…`) plus the
    edge-platform block for the combined edge.
  - `dashboards.enabled=true` → Grafana dashboards as ConfigMaps labelled for the
    Grafana sidecar's auto-discovery (kube-prometheus-stack / grafana chart).
  - **Collector caveat:** the `result`/`op`/`tier` metric attributes several rules and
    dashboard panels key on are LOW-cardinality nexus RED dimensions. Your OTel
    collector MUST keep them (nexus's lab collector does — `monitoring/otel-collector`);
    a `keep_keys` allow-list that drops them makes those rules silently under-fire and
    `by (result)` panels collapse. The edge (Envoy) rules are scraped, so unaffected.

## Telemetry cost controls (the cost posture of the stack)

The stack above is functionally complete; this is its **cost shape** (change
`telemetry-cost-controls`). Two bill problems are solved by standard
configuration of the stores/collector already running — nothing hand-built, no
producer change: the **baseline** (volume × retention × storage tier) and the
**worst case** (one box adds an unbounded label or a chatty log and the series
count / log volume explode). It is config-first and rolls back to local disk by
reverting config only; the emission contract and every producer are untouched.

**Cluster (helm) pattern — identical to how tracing and the box contract
shipped: the object-storage tier is EXTERNAL to the charts, exactly like
Prometheus/Postgres.** There are **no chart code changes** and none are needed:

- **Object storage is an external dependency you operate.** Point the stores at
  your cloud object store (S3/GCS) or a self-hosted SeaweedFS via the **same
  store config the lab uses**, differing only by endpoint + credentials supplied
  through env / a Secret — never a literal in a manifest. The stores are the only
  clients; producers never learn the address (single-egress discipline).

  | Env (both stores)        | Lab default            | Production                              |
  | ------------------------ | ---------------------- | --------------------------------------- |
  | `TELEMETRY_S3_ENDPOINT`  | `seaweedfs:8333`       | your S3/GCS endpoint (or self-hosted)   |
  | `TELEMETRY_S3_ACCESS_KEY`/`_SECRET_KEY` | well-known lab creds | from a Secret, never inline |
  | `TELEMETRY_S3_REGION`    | `us-east-1`            | your region                             |
  | `TELEMETRY_S3_INSECURE`  | `true` (lab http)      | `false` (https)                         |
  | `TEMPO_S3_BUCKET` / `LOKI_S3_BUCKET` | `tempo-traces` / `loki-chunks` | your buckets (pre-create them) |

- **The lab bundles a self-contained S3 tier** (SeaweedFS + a one-shot bucket
  seeder in `../docker-compose.yaml`) so a clean `docker compose up` runs the
  **same cost topology** with no cloud account. Production is the same config
  with the env above repointed. (SeaweedFS is the mature, Apache-2.0 MinIO
  replacement after MinIO Community Edition was archived; adopt, never build.)

- **Pin the collector image.** Cost control graduated the collector **core →
  contrib** (the metric cardinality guard uses the contrib-only `transform`
  processor). Pin `otel/opentelemetry-collector-contrib` to a concrete tag
  (`OTELCOL_VERSION` in compose; the image tag in your workload spec) — a
  deliberate, provenance-changing bump, re-run the cost-ceiling checks.

**The cost model — what you are paying for and the knobs that bound it:**

- **Storage tier:** all three signals on object storage (Tempo blocks + Loki
  chunks/index on S3; Prometheus keeps its local TSDB — object-store/downsampled
  metrics via Mimir/Thanos is the deferred successor). ~10–20× cheaper per GB
  than host disk and decoupled from any one host.

- **Per-signal retention — an owned budget, not a default** (each a config value;
  the store reclaims past the window automatically):

  | Signal  | Store      | Retention (env)                        | Why                                   |
  | ------- | ---------- | -------------------------------------- | ------------------------------------- |
  | Traces  | Tempo (S3) | **48h** (`TEMPO_BLOCK_RETENTION`)      | short-lived debugging signal          |
  | Logs    | Loki (S3)  | **7d** (`LOKI_RETENTION_PERIOD`)       | investigation trail                   |
  | Metrics | Prometheus | **15d** (`PROM_RETENTION`)             | cheapest by volume → longest window   |

- **Egress cost ceiling — bounds what any one producer can cost, so a misbehaving
  box degrades its OWN fidelity, never the shared bill/store/request path:**
  - **Metric cardinality guard** (collector `transform`/`keep_keys`): a datapoint's
    attributes are collapsed to an **allow-list** — identity (`service.*`) + RED
    (`http.request.method`, `http.response.status_code`, `http.route`,
    `rpc.grpc.status_code`, …). An unbounded label (`user_id`, raw path, request
    id) is dropped at the egress before Prometheus. The allow-list lives in one
    place (`monitoring/otel-collector/otel-collector.yaml`) — start permissive,
    tighten with evidence; a change is a config edit, never a producer redeploy.
  - **Log volume/noise caps** (Loki `limits_config`): per-stream ingestion-rate +
    burst, max streams, max label names, max line size (`LOKI_*` env). A chatty
    box's excess is refused (429 → its exporter buffers/drops, fail-open).
  - **`memory_limiter`** on the collector so a volume flood can't OOM it.
  - **An engaged ceiling is observable, never a silent gap:** the collector
    exports its own pipeline counters (`otelcol_processor_*` — accepted / refused /
    dropped points) on `:8888`, and Loki reports `loki_discarded_samples_total`
    `{reason="rate_limited"}`; both are scraped (`monitoring/prometheus/prometheus.yml`).

- **Trace cost stays head-governed.** The edge's head-sampling decision
  (`TRACE_SAMPLING_PCT`) remains the trace cost ceiling — it saves generation +
  transport + storage. There is **no tail sampling** and no downstream
  trace-buffering stage (an explicit non-goal): lowering trace cost is the
  head-sampling rate and the storage tier, nothing stateful added.

## BREAKING — upgrading to the fail-closed edge guards

Two guards now make previously-implicit security choices explicit. A chart
render that used to succeed will **refuse to render** until each choice is
made — that refusal is the feature (fail closed), not a packaging bug.

### 1. JWKS trust-anchor integrity (`edge-trust-anchor-integrity`)

Earlier versions fetched the ZITADEL JWKS — the keys ALL token verification
rests on — over plaintext HTTP, silently. An on-path attacker who substitutes
that response owns every "verified" identity. Now the stamping edges
(identity-plane, edge-platform umbrella) require one of:

- **`oidc.jwksTls.enabled=true`** (preferred): the JWKS is fetched over TLS
  with server-cert verification (trusted CA + SNI + SAN pin). Point
  `oidc.jwksInternalUrl` at a TLS port; for a private CA, mount your bundle
  into the Envoy pod and set `oidc.jwksTls.caFile`; set
  `oidc.jwksTls.sni` when the cert is issued for a name other than the
  dialed host.
- **`oidc.jwksPlaintextTrustedPath=true`**: an explicit assertion that the
  edge→provider hop is a trusted path (e.g. genuinely in-cluster and assessed).
  This is an acknowledgment, not a control — prefer TLS.

Migration for a deployment currently on plaintext JWKS over an untrusted hop:
enable TLS on the OIDC provider's serving endpoint (or front it with a TLS hop you
trust), then set `oidc.jwksTls.enabled=true`. Until then, upgrading the
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

**Probe that your CNI actually enforces the policy** (many clusters render a
NetworkPolicy that the CNI silently ignores — Calico/Cilium enforce, some
managed defaults do not). From a throwaway pod *in the backend namespace*,
hit the backend directly, bypassing the edge, with a forged stamp — it MUST
be refused (timeout/connection-refused), not answered:

```sh
# NS = backend namespace, BACKEND_SVC:PORT = the pod the policy protects
kubectl -n "$NS" run np-probe --rm -it --restart=Never --image=curlimages/curl -- \
  curl -sS --max-time 5 \
    -H 'x-workspace-id: forged' -H 'x-identity-contract: v1' \
    http://BACKEND_SVC:PORT/ ; echo "exit=$?"
# PASS = curl fails (exit 28 timeout / 7 refused). FAIL = HTTP response => the
# CNI is NOT enforcing NetworkPolicy; the trusted-header family is forgeable.
```

### 3. Nexus-native authorization + deny-by-default cutover (`nexus-native-authorization`)

The OIDC provider now answers ONLY "who am I" (authentication + basic profile);
**nexus authors ALL authorization** — roles, entitlements, and suspension — itself.
The provider is never an authorization source: a `roles` claim in the token confers
**nothing**, and the ZITADEL directory integration (the `reconciler`, `sync-worker`,
admin PAT, and Actions webhook) is **deleted**. This removes `ZITADEL_HOST`,
`ZITADEL_INTERNAL_URL`, `PAT_FILE`/`WEBHOOK_SELF_URL` env and the `oidc.patSecret` /
`oidc.internalUrl` Helm values (the JWKS dial is now `oidc.jwksInternalUrl`).

**BREAKING (operational) — deny-by-default.** A subject nexus holds no authorization
facts about is authenticated but **unprivileged** (no roles, no entitlements, not
suspended). Any elevated access that previously rode on an IdP-sourced role now
requires an explicit **nexus grant**. At cutover, every such user has **zero** nexus
roles until re-provisioned — provision the grants *before or with* the cutover.

**Authoring surface.** The identity-plane **`authz-admin`** service (`:9300`,
auth-gated by `IDENTITY_ADMIN_TOKEN` fail-closed, like the control-plane's
`CONTROL_AUTH_TOKEN`) is the single source of record. It resolves live and revokes
within seconds over the existing change feed (no new token):

```sh
# T = IDENTITY_ADMIN_TOKEN, SUB = the subject's `sub`
curl -sf -X PUT  -H "Authorization: Bearer $T" -H 'content-type: application/json' \
     -d '{"role":"admin"}' http://authz-admin:9300/authz/$SUB/roles      # assign role
curl -sf -X POST -H "Authorization: Bearer $T" http://authz-admin:9300/authz/$SUB/suspend    # suspend
curl -sf -X DELETE -H "Authorization: Bearer $T" http://authz-admin:9300/authz/$SUB/roles/admin  # revoke
curl -sf -H "Authorization: Bearer $T" http://authz-admin:9300/authz/$SUB    # read effective facts
```

**Bootstrap (from an empty store).** Set `AUTHZ_BOOTSTRAP_ADMIN_SUB` (Helm
`authzAdmin.bootstrapAdminSub`) to a subject `sub`: it is granted `AUTHZ_ADMIN_ROLE`
at startup **iff no administrator exists yet** — idempotent break-glass, so the
surface is never unreachable. Rotate/disable the bootstrap secret once a real admin
has been authored.

**Provisioning migration (pre-prod).** Re-author the grants your users previously
received from the IdP directly through `authz-admin` (a re-provision, not an ETL —
the store is rebuildable pre-prod). There is no enumerate/backfill pass without the
reconciler by design: a subject nexus has no opinion about is the safe (absent) row.

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
- [ ] **JWKS over verified TLS.** `oidc.jwksTls.enabled=true` with a CA the
      Envoy pod can read (`jwksTls.caFile`) and the right `jwksTls.sni`. Use
      `jwksPlaintextTrustedPath=true` ONLY for a genuinely in-cluster hop you
      have assessed — it is an acknowledgment, not a control.
- [ ] **Nexus authorization is provisioned (deny-by-default).** The OIDC provider
      is NOT an authorization source; every privileged subject needs an explicit
      nexus grant (`nexus-native-authorization`, §3 above). Set the `authz-admin`
      token (`authzAdmin.adminToken`/`.existingSecret`, fail-closed), bootstrap the
      first admin (`authzAdmin.bootstrapAdminSub`), and re-author existing users'
      grants before cutover — until then they are authenticated but unprivileged.
- [ ] **The consuming backend implements its half of the stamp contract.** Nexus
      emits `x-identity-contract` and the spec scopes the rule, but rejecting an
      absent/unknown stamp on identity-enriched routes is the BACKEND's code
      (deliberately out of this repo's test surface). If you own the backend,
      that check is its backlog item, not an assumption. The full consumer
      contract — every injected header and the exact reject rules — is in
      [`../docs/box-consumer-contract.md`](../docs/box-consumer-contract.md).
- [ ] **Control-plane reachability matches C16.** Broker-only NetworkPolicy on
      :9400 (`controlPlane.networkPolicy.*`), scrapers/kubelet on the ops port
      :9401 only; `CONTROL_AUTH_TOKEN` from a Secret, never `CONTROL_AUTH_DISABLED`.
- [ ] **N4 phase-2 rollout order: enforcer before emitter.** Roll the identity
      sidecar (which 403-enforces the `x-auth-requires-*` signals) before or
      with the tenant-router that emits them. A newer router beside an older
      sidecar leaves requirement rules silently unenforced; the reverse order is
      safe (a sidecar that sees no signals enforces nothing).

**Config hygiene:**

- [ ] **Secrets via `existingSecret` everywhere** (postgres, routingPg, ZITADEL
      PAT, control token) — inline `*.url`/`value` land in the release manifest.
- [ ] **Pin every image.** First-party images to a concrete tag you built. The
      Envoy image now ships pinned to a concrete patch version + digest
      (`images.envoy.tag: v1.34.14@sha256:…`); on a bump, re-resolve the digest
      (`docker buildx imagetools inspect envoyproxy/envoy:<tag> | grep Digest`)
      and re-verify span export. The lab pins ZITADEL for the same reason (a
      floating tag broke the CI gate).
- [ ] **Issuer single-sourced (D7).** `oidc.issuer` must equal the `iss`
      the provider mints AND the value the workers derive — drift is silent-but-fatal
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

The trace-context headers (`traceparent`/`tracestate`) are stripped in **two**
places per edge: the `early_header_mutation_extensions` (before Envoy's
join-vs-root tracing decision — removing only the filter-level strip would let
a client-forged trace be silently JOINED) and the C3 filter strip
(defense-in-depth for the backend-facing guarantee). Keep both.
