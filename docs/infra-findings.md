# Infra integration findings (from `infra-v1`)

Findings surfaced while integrating the nexus edge platform into the `infra-v1` fleet
(k3s / ArgoCD / OpenBao). Each is something infra hit that is **nexus-side** to resolve.
Numbering continues the `N` series (N1–N10 are prior integration findings).

---

## N11 — the `edge-platform` umbrella's COMBINED edge does not wire contract signing

**Status:** resolved (`edge-platform` `0.2.1`, change `edge-platform-signing`, commit `284ac46`) ·
**Found:** 2026-07-15, rendering `edge-platform` `0.2.0` (chart @ `f42554f`, appVersion `0.0.7`) ·
**Severity:** blocks a **signed** go-live via the umbrella.

> **Resolution (2026-07-15):** the combined edge now wires identity-contract signing identically
> to the standalone edge, gated on `identity-plane.sidecar.signing.enabled` — signing env (Transit
> + break-glass), the public `:9210` JWKS port on the pod **and** the combined-edge Service, and
> the break-glass volumes (consuming the identity subchart's `<release>-identity-plane-signing-*`
> resources). The env is single-sourced in a shared `identity-plane.signingEnv` template so the two
> edges cannot drift again, and `scripts/helm-guards-test.sh` now asserts both edges mint + publish
> when signing is on. The invariant is captured in the `identity-contract-signing` spec
> ("enabled signing takes effect in every edge topology"). Chart-only — no image change
> (appVersion stays `0.0.7`); infra picks it up by re-vendoring the `edge-platform` chart at
> `0.2.1`.

### What

The umbrella's **combined** edge (`deploy/helm/edge-platform/templates/edge-deployment.yaml`)
co-locates the identity sidecar, but that container is **not** given any signing configuration:

- **No** `SIGNING_TRANSIT_KEY` / `SIGNING_TRANSIT_MOUNT` / `BAO_TOKEN` env.
- **No** `JWKS_LISTEN` env and **no** `:9210` container port (its ports are only
  `id-ext-proc:50051`, `id-profile:9200`, `id-metrics:9202`).
- `edge-platform/values.yaml` has **no** signing block.

Contract signing (`SIGNING_TRANSIT_*`, `BAO_TOKEN`, `JWKS_LISTEN`, the `:9210` jwks port) is wired
**only** in the identity-plane **standalone** edge
(`deploy/helm/identity-plane/templates/edge-deployment.yaml`, ~lines 75–112, gated on
`sidecar.signing.enabled`) — which the umbrella **disables** (`identity-plane.edge.enabled: false`)
to run its single combined edge. Setting `identity-plane.sidecar.signing.*` on the umbrella therefore
renders **nothing** on the combined edge.

### Why it matters

Deploying via the umbrella (the documented production topology — one combined tenant-first edge)
brings the planes up **UNSIGNED**: no `x-identity-contract` ES256 signature and no JWKS served on
`:9210`. That contradicts:

- `docs/box-signing-handoff.md` (boxes verify a signed contract and fetch the JWKS at
  `http://<identity-plane-host>:9210/.well-known/jwks.json`), and
- the go-live checklist's "verify JWKS + a signed contract" step.

On the infra side this blocks consuming the OpenBao **Transit** signing custody that has already been
provisioned for it (the `identity-contract-signing` key, a least-privilege policy, and a
Kubernetes-auth role are ready) — there is simply nowhere on the combined edge to feed the token.

### Evidence (reproduce)

```
helm template edge deploy/helm/edge-platform \
  --set identity-plane.sidecar.signing.enabled=true \
  --set identity-plane.sidecar.signing.transit.enabled=true \
  --set identity-plane.sidecar.signing.transit.tokenExistingSecret=identity-plane-bao-token
# -> the combined-edge identity-sidecar container has NO SIGNING_TRANSIT_*/BAO_TOKEN env
#    and NO :9210 port. Grep the rendered output for SIGNING_TRANSIT / 9210 -> empty.
```

### Suggested fix (nexus-side)

Wire the identity-plane signing config into the **combined**-edge identity-sidecar in
`edge-platform/templates/edge-deployment.yaml`, driven by `identity-plane.sidecar.signing.*`
(or a dedicated `edge.signing` passthrough on the umbrella):

- add `JWKS_LISTEN`, `SIGNING_TRANSIT_KEY`, `SIGNING_TRANSIT_MOUNT` env and the `BAO_TOKEN`
  `secretKeyRef` (from `transit.tokenExistingSecret`), plus the `pollSeconds` / `maxClockSkewSeconds`
  the standalone edge passes;
- expose the `:9210` (`jwks`) container port on the combined-edge pod + its Service;
- ensure the break-glass path (`signing.yaml`'s Secret/ConfigMap for `existingSecret` / `jwks`) is
  mounted/consumed by the combined edge as well.

After the fix, the `helm template` above should render `SIGNING_TRANSIT_*` env + a `:9210` port on
the combined-edge sidecar.

_Raised by infra-v1 (change `edge-platform-deploy`). Infra's overlay already carries the intended
signing config; it is inert until this is wired._

---

## N12 — the Helm path ships no TLS-terminating front tier, so custom-domain TLS is unreachable on k8s

**Status:** open ·
**Found:** 2026-07-19, against `edge-platform` `0.3.0` (chart @ `976d182`, appVersion `0.0.7`) ·
**Severity:** blocks the **public `:443` cutover** for a Kubernetes deployment, and with it the
tenant custom-domain feature entirely.

### What

The on-demand customer-domain TLS front tier (`65d3e53`, "add on-demand customer-domain TLS front
tier") exists **only as a Docker Compose service**. There is no Kubernetes packaging of it:

- `grep -ril caddy deploy/helm/` → **zero matches**.
- The only thing in the repo that binds `:443` is the compose `caddy` service
  (`deploy/compose/docker-compose.yaml:333-358`, `"${TLS_PORT:-443}:443"`).
- `deploy/caddy/README.md:99-104` states this outright as unbuilt future work: *"**Helm:** mount
  this `Caddyfile` via a ConfigMap …, **add a front-tier Deployment/Service**, and inject
  `ACME_ACCOUNT_KEY_FILE`…"*. That Deployment/Service does not exist.
- `openspec/changes/custom-domains-tls/` is still unarchived, and a grep for `helm|kubernetes|k8s`
  across the whole change directory returns nothing — the design never covered the k8s path.

What the Helm chart actually exposes is a plaintext HTTP data plane:

- `edge-platform/templates/edge-service.yaml:9-18` — `ClusterIP`, single data-plane port `http: 80`.
- `edge-platform/templates/edge-deployment.yaml:168-169` — Envoy container ports are `http: 10000`
  and `admin: 9901` only.
- `edge-platform/templates/edge-configmap.yaml:50` — the Envoy listener is `0.0.0.0:10000` with **no
  downstream `transport_socket`**. The only TLS contexts (`:358-363`) are *upstream* (JWKS/OIDC).
  Envoy does not terminate TLS.
- `edge-platform/templates/edge-ingress.yaml:15-19` — a stock Ingress expecting a **pre-existing**
  `secretName`, defaulted to a cert-manager wildcard (`values.yaml:154-164`). That is a **finite**
  host set issued ahead of time — not on-demand issuance, no `ask` gate, no CertMagic store.

### Why it matters

For a Kubernetes deployment there is **nothing that can serve a tenant's custom domain**. The
documented operator instruction — `docs/runbook-custom-domains-tls.md:20-23`, *"point customer DNS at
the front tier's public address (the caddy `:443` listener / its load balancer), **NOT** at Envoy
directly"* — has no referent on k8s. `docs/on-demand-tls.md:3-11` scopes the feature to "the
TLS-terminating edge (**Caddy today, in the ingress/infra layer**)", but the chart the ingress layer
is told to front does not include it.

This is currently blocking infra's public `:443` cutover. Infra's L4 SNI router is live and already
owns `:80/:443` on every node, pre-positioned to hand customer/tenant domains to a nexus-owned
front tier — which is the boundary `deploy/README.md` and infra's own `entry-layer` spec both
describe. There is no service to hand them to, so the edge is deployed but **not publicly exposed**.

There is also an ambiguity worth resolving explicitly, because the two docs point opposite ways:
`deploy/README.md:4-9,631-634` says *"TLS is handled **before** this service — it is not in scope
here"*, which reads as **infra owns all TLS**; but on-demand issuance for customer domains is not
something infra *can* own — it requires the `ask` callback into `tenant-router` and the shared
CertMagic store, both nexus-side concerns. So "not in scope here" is true for first-party domains and
**not** true for tenant custom domains, and today nothing owns the latter on k8s.

### Two blockers, not one

Even if infra were to build the front tier itself, the chart does not currently permit it:

1. **The `ask` gate is unreachable.** `tenant-router` serves `/authorize` on `:9300`, which
   `edge-service.yaml:13-14` **deliberately** keeps off the Service (*"the sidecar/router debug +
   metrics ports are deliberately NOT here"*). An external front tier has no supported address to
   call for on-demand authorization.
2. **No PROXY-protocol listener filter is ever configured.** Envoy itself *supports* PROXY protocol
   (via the `proxy_protocol` listener filter — the `envoy-types` crate vendors its descriptor), but
   `edge-configmap.yaml`'s listener declares **no `listener_filters` at all**, and the chart exposes
   no value to add one. Infra's SNI router sends `send-proxy` to every backend, so today a front
   tier must either terminate the PROXY header itself or infra must special-case the backend and
   lose the real client IP.

   This one may be cheap to close: exposing a `listener_filters` passthrough (or simply a
   `proxy_protocol: enabled` flag) on the edge listener would let an L4 router front the edge
   directly with the client IP preserved — useful independently of the custom-domain question.

### Evidence (reproduce)

```
grep -ril caddy deploy/helm/                    # -> no matches (compose-only feature)

# no PROXY-protocol listener filter is configured anywhere in the charts or compose config:
grep -ri "proxy_protocol" deploy/       # -> no matches
grep -ri "listener_filters" deploy/     # -> no matches (the edge listener declares none at all)
# NB: scope to deploy/ (all Envoy config lives there). An unscoped `grep -ri proxy_protocol .`
# also hits identity-rs/target/**/envoy_types-*.d — Cargo build artifacts for the vendored
# envoy-types crate (Envoy's own xDS descriptors), not nexus configuration.

helm template edge deploy/helm/edge-platform \
  --set identity-plane.sidecar.signing.enabled=true
# -> the edge Service exposes http:80 (+ jwks:9210); no :443, no TLS listener,
#    no :9300 authorize port. Envoy listener is 0.0.0.0:10000, plaintext.
```

### Suggested fix (nexus-side)

Preferred — **ship the front tier in Helm**, as `deploy/caddy/README.md:99-104` already anticipates:

- a front-tier Deployment + Service binding `:443`, with the `Caddyfile` mounted from a ConfigMap;
- on-demand TLS pointed at the existing `ask` endpoint, with the CertMagic Postgres store
  (`certmagic_data` / `certmagic_locks`) wired from the same config the compose tier uses;
- `ACME_ACCOUNT_KEY_FILE` injectable from a Secret;
- **PROXY protocol accepted on `:443`** (`servers.listener_wrappers: [{proxy_protocol}, {tls}]`), so
  an L4 SNI router in front preserves the client IP;
- forward cleartext to the edge Service on `:80` with the original `Host` preserved.

If that is not the intended direction, the alternative is to **declare the k8s custom-domain path
explicitly out of scope** and document the contract an operator must satisfy to build it — in which
case please also expose `tenant-router`'s `/authorize` (`:9300`) on a Service (a dedicated one is
fine; it need not join the data-plane Service), since without it the `ask` gate cannot be reached
and the feature is not implementable downstream at all.

Either resolution unblocks infra. What does not work is the current state, where the runbook
instructs operators to point DNS at a `:443` listener that a Helm install never creates.

_Raised by infra-v1 (entry-layer `:443` cutover). Infra's SNI router is live and pre-positioned; the
cutover is held until there is a nexus front tier to point it at, or an explicit statement that infra
should build one._

**RESOLVED** (change `helm-front-tier-tls`) — the preferred resolution shipped. The `edge-platform`
umbrella now renders the front tier under `frontTier.*`: a front-tier Deployment + Service on
`:443`/`:80` (the vendored `Caddyfile` mounted from a ConfigMap), a dedicated `ask` ClusterIP Service
exposing `tenant-router:9300` for on-demand issuance (the deliberate local-only posture of the
admin/metrics ports is preserved), the CertMagic Postgres store and `ACME_ACCOUNT_KEY_FILE` wired
from Secrets, and **opt-in PROXY-protocol acceptance** at both the front tier's `:443` and the edge
Envoy listener (`edge.proxyProtocol.enabled`) so an L4 SNI router preserves the real client IP.
Default off — an existing release is unaffected until `frontTier.enabled=true`. Remaining before the
cutover: a lab bring-up (chart `frontTier` enabled end-to-end, incl. the ACME account-key seed) and
flipping `frontTier.acme.caDir` from LE staging to production.

## N13 — the front-tier Caddy image is never published, so `frontTier.enabled=true` cannot pull

### What

The N12 front tier ships as Helm templates + a `Dockerfile`, but the **image itself is not published
to any registry**. `build-images.yml` builds only the five Rust planes (`identity-sidecar-rs`,
`identity-authz-admin`, `identity-membership-sync`, `tenant-router`, `control-plane`); the Caddy
front-tier image (`deploy/caddy/Dockerfile` — stock Caddy + the `xcaddy` `postgres-storage` module)
is built **only locally for the compose lab** (`deploy/caddy/docker-compose.lab.yaml` →
`caddy-front/caddy:lab`). The chart default `frontTier.image.repository: caddy-front/caddy`
(`deploy/helm/edge-platform/values.yaml`) is a bare name that resolves to nothing on a cluster.

### Why it matters

It is the exact analogue of the N12 chart gap, one layer down: the *capability* is code-complete but
the *artifact a cluster consumes* was never produced. On a real k8s bring-up the front-tier pods go
straight to `ImagePullBackOff` — the feature cannot run. Stock `caddy:2.8` cannot substitute: without
the `postgres-storage` module the `storage postgres { … }` global option fails to load, so the shared
CertMagic store (the whole point of N12) is unavailable. So today `frontTier.enabled=true` is a
non-starter downstream regardless of how correct the templates are.

### Evidence (reproduce)

```bash
# the front-tier image is not in the build matrix (only the 5 planes are):
grep -A2 'matrix' .github/workflows/build-images.yml | grep -E 'name:'
# -> identity-sidecar-rs, identity-authz-admin, identity-membership-sync, tenant-router, control-plane
#    (no caddy / caddy-front)

# it exists only as a local lab build, never pushed:
grep -rn 'caddy-front' deploy/caddy/*.yaml deploy/helm/edge-platform/values.yaml
# -> compose builds caddy-front/caddy:lab; the chart default repository is the bare `caddy-front/caddy`

# live symptom on the infra cluster after frontTier.enabled=true:
#   kubectl -n edge get pods -l app.kubernetes.io/component=front-tier
#   -> edge-…-front-tier-…  0/1  ImagePullBackOff   (caddy-front/caddy:<appVersion> is unpullable)
```

### Suggested fix (nexus-side)

**Publish the front-tier image alongside the five planes.** All three nexus-side parts are done in
this change:

- **build matrix** — `- { name: caddy-front, context: deploy/caddy, target: caddy }` in
  `build-images.yml` (the Dockerfile's final stage is named `caddy` for a clean build target), so a
  `v*` tag / manual dispatch publishes `ghcr.io/<owner>/caddy-front`;
- **chart default** — `frontTier.image.repository: ghcr.io/dufeutech/caddy-front` (was the bare
  `caddy-front/caddy`, which resolves to docker.io → `ImagePullBackOff`), so `frontTier.enabled=true`
  pulls without an operator override; the tag resolves to the umbrella's appVersion (`0.0.7`); and
- **module pin** — the Dockerfile pins `postgres-storage@276797aefe401b738781692d278a158c53b99208`
  (the module HEAD that introduced the optional-DDL flag the `disable_ddl true` posture depends on),
  so the published image is reproducible and the DML-only-role posture stays verified against a known
  module. The compose lab shares this Dockerfile, so lab and cluster build the same module.

### Note — image publish trigger

`build-images.yml` fires on `v*` tags (and manual dispatch), but the front tier landed under the
`charts-2026-07-20` tag, not a `v*`. The chart pulls `caddy-front:0.0.7` (appVersion), but `v0.0.7`
was cut before the `caddy-front` matrix entry existed, so that image tag has no build yet. Producing
it: **manual "Run workflow" on build-images with `tag=0.0.7`, push enabled**. This is safe to run
from `main` — no commit has touched `identity-rs/` or `routing-rs/` since `v0.0.7`, so the five Rust
planes rebuild byte-for-byte identical and only the missing `caddy-front:0.0.7` is genuinely new (no
existing release image is mutated). Alternatively cut a fresh `v*` (which also rebuilds all six).

_Raised by infra-v1 (entry-layer `:443` cutover, change `edge-front-tier-cutover`). The infra side is
complete and **verified green on the live cluster** — the CertMagic schema + DML-only `caddy` role,
the ACME account + store Secrets (ESO), the front-tier/ask Services and NetworkPolicy all come up; only
the pods can't pull. `frontTier.enabled` is held at `false` (cluster kept healthy, substrate ready) and
flips to `true` the moment `ghcr.io/dufeutech/caddy-front` exists and is pinned._

## N14 — the CertMagic migration is search_path-dependent, so tables land in the wrong schema

**Status:** resolved (this change) · **Found:** 2026-07-21, front tier live on the infra cluster ·
**Severity:** front-tier `CrashLoopBackOff` — the customer-domain TLS terminator cannot start.

### What

`routing-rs/store-postgres/migrations/0001_certmagic_store.sql` (and its compose mirror
`postgres-init/40-certmagic-store.sql`) `CREATE`s its tables **unqualified**:

```sql
\connect routing
CREATE TABLE IF NOT EXISTS certmagic_data ( … );
CREATE TABLE IF NOT EXISTS certmagic_locks ( … );
```

Where an unqualified `CREATE` lands depends on the applying role's `search_path` (`"$user", public`).
On a database where the store is owned by a dedicated role **and a schema of that role's name exists**
— e.g. infra runs the routing store as owner `routing`, and a `routing` schema exists — `"$user"`
resolves to `routing`, so the tables are created in **`routing.*`**, not `public`. The Caddy DB role
(`caddy`), whose `search_path` resolves to `public`, then cannot see them:

```
Error: loading initial config: … creating storage value: pq: relation "certmagic_data" does not exist
```

The migration's own header says these live "in the routing database's **PUBLIC** schema" — the intent
was always public; the SQL just didn't enforce it. The compose lab doesn't hit this because its store
role's `search_path` resolves straight to `public` (no same-named schema in front of it).

### Why it matters

It's a silent, environment-dependent placement bug: the same migration "succeeds" (exit 0, tables
created) yet puts the tables where the consumer can't find them, and only on a realistic multi-schema
/ dedicated-owner deployment — exactly the k8s target. The front tier then crash-loops on startup with
a confusing "relation does not exist" despite a green migration.

### Evidence (reproduce)

```bash
# as a role `r` that owns a schema named `r`, apply the migration, then look:
psql -d routing -c "\dt routing.certmagic_*"   # -> tables ARE here (unintended)
psql -d routing -c "\dt public.certmagic_*"    # -> "Did not find any relation" (where Caddy looks)
# Caddy (storage postgres, role caddy) then: pq: relation "certmagic_data" does not exist
```

### Suggested fix (nexus-side)

**Schema-qualify the DDL** (done in this change): `CREATE TABLE IF NOT EXISTS public.certmagic_data …`
/ `… public.certmagic_locks …` in both the migration and the compose mirror, so placement is
deterministic regardless of the applying role's `search_path`. (Equivalent alternatives: a leading
`SET search_path TO public;`, or `SELECT set_config('search_path','public',false)`.) The Caddy DB role
already needs only `USAGE` on `public` + DML on those two tables — which now matches where they live.

_Raised by infra-v1 (change `edge-front-tier-cutover`). Infra worked around it in its provisioning Job
(forces `search_path=public` via `PGOPTIONS`, drops the mis-placed tables, grants on `public.*`) and
the front tier is now live + healthy on staging; this schema-qualification is the durable upstream fix._
