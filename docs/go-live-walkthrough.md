# Go-live walkthrough

An ordered runbook for taking a nexus deployment to production. It **sequences**
the existing artifacts — it does not restate them:

- Per-item detail & the authoritative checkboxes → [`../deploy/README.md`](../deploy/README.md) ("Production deployment checklist").
- The runnable checks → [`../scripts/go-live-smoke.sh`](../scripts/go-live-smoke.sh).
- Admin operations (provisioning) → [`admin-apis.md`](admin-apis.md) / [`openapi/`](openapi/README.md).

**Scope:** this covers a **single-region** rollout. Multi-region HA (DB fork, NATS
transport) is still at exploration stage (`openspec/changes/platform-ha-and-hardening/`)
and is out of scope here. If your launch requires HA, stop — that work isn't built yet.

Work top-to-bottom. Each step gates the next.

---

## Step 0 — Confirm scope & freeze

- [ ] Single-region is acceptable for launch (see scope note above).
- [ ] Custom-domain (BYO-TLS) onboarding is either in scope (then the Let's Encrypt
      account steps in `openspec/changes/custom-domains-tls/tasks.md` 4.6/5.2 must be
      done) or explicitly deferred.
- [ ] Pick the image tags you will ship and freeze them (concrete tags + Envoy digest).

## Step 1 — Stand up prod-representative staging

The walkthrough is validated on staging first. Three things **must match production**
or the checks below give false confidence:

- [ ] **CNI that actually enforces NetworkPolicy** — the origin-enforcement probe is
      meaningless on a CNI that ignores policy.
- [ ] **Managed Postgres in session mode** (no transaction-mode pooler — it silently
      swallows the `LISTEN/NOTIFY` invalidation feed) with `?sslmode=verify-full`, for
      both the routing and identity stores.
- [ ] **The real OIDC provider** (issuer, JWKS-over-TLS) you will use in prod.
- [ ] An **OTel collector + Prometheus/Thanos** (metrics are OTLP-only; there is no
      service `/metrics` to scrape).

## Step 2 — Deploy via Helm

Use the charts under `deploy/helm/` (identity-plane, routing-plane, edge-platform).
Before install, satisfy the **config-hygiene** items in the checklist:

- [ ] Secrets via `existingSecret` everywhere (no inline `*.url`/`value`).
- [ ] Every image pinned (first-party tags you built; Envoy tag + digest).
- [ ] `oidc.issuer` single-sourced (equals what the provider mints AND what workers derive).
- [ ] `oidc.jwksTls.enabled=true` with a CA the Envoy pod can read and the right SNI.
- [ ] Real ingress/TLS values (`edge.ingress.host(s)`, cert-manager annotations, secret names).
- [ ] Postgres URLs follow the session-connection rules (Step 1).

Detail for each: `deploy/README.md` → "Config hygiene".

## Step 3 — Run the smoke-test harness

Point [`../scripts/go-live-smoke.sh`](../scripts/go-live-smoke.sh) at staging. Start
read-only, then run the opt-in checks:

```sh
# read-only: reachability, JWKS-over-verified-TLS, fail-closed admin auth, metrics pipeline
EDGE=https://edge.staging AUTHZ=https://authz.staging \
CONTROL_PLANE=https://cp.staging PROM_URL=https://prom.staging \
scripts/go-live-smoke.sh

# origin enforcement — run from a pod OFF the edge network; a forged direct
# request to the backend must fail to connect (HTTP 000)
BACKEND_URL=http://backend.internal/ scripts/go-live-smoke.sh

# authz grant -> effect -> revoke over LISTEN/NOTIFY (needs a test end-user JWT)
RUN_MUTATING=1 TOKEN="$STAGING_USER_JWT" EDGE=https://edge.staging AUTHZ=https://authz.staging \
scripts/go-live-smoke.sh
```

- [ ] Read-only run is all green.
- [ ] Origin probe (`BACKEND_URL`) refuses the forged direct request.
- [ ] Grant round-trip (`RUN_MUTATING=1`) converges (proves the invalidation feed is live).

A green run proves the *mechanics*. The next step is what the script cannot judge.

## Step 4 — Manual sign-offs (no script can certify these)

- [ ] **Backend enforces its half of the stamp contract** — on identity-enriched routes
      it REJECTS an absent/unknown `x-identity-contract`. This lives in the backend's
      code ([`box-consumer-contract.md`](box-consumer-contract.md)), outside this repo.
- [ ] **Store lifecycle owned** — HA, backups, **restore-tested**, failover for both DBs.
- [ ] **Load/capacity validated for your traffic** — the CI gate proves correctness, not
      capacity. Size sidecar memory to the resident profile population; set `edge.replicas`/HPA.
      Harness: `scripts/load/`.
- [ ] **Monitoring wired** — alerts on edge 5xx / `ext_proc` failures, invalidation-feed
      staleness (`router_last_invalidation_timestamp_seconds`,
      `sidecar_kv_last_apply_timestamp_seconds`), and control-plane auth failures
      (`control_mutations{op="unauthorized"}`, `authz_admin_mutations{op="unauthorized"}`).

## Step 5 — Provision authorization (deny-by-default cutover)

nexus is deny-by-default: the OIDC provider is **not** an authorization source, so every
privileged subject is unprivileged until granted. Do this **before** opening production
traffic. Uses the authz-admin API ([`admin-apis.md`](admin-apis.md)).

- [ ] `authz-admin` token set (`authzAdmin.adminToken`/`.existingSecret`, fail-closed).
- [ ] Bootstrap the first admin (`authzAdmin.bootstrapAdminSub`) — idempotent break-glass;
      rotate/disable the bootstrap secret once a real admin exists.
- [ ] **Re-author existing users' grants** (roles/entitlements) that previously came from
      the IdP. This is a re-provision, not an ETL — there is no enumerate/backfill pass by
      design. Until re-granted, users are authenticated but unprivileged.
- [ ] Domains (if in scope) declared and **verified** (declare → publish TXT → verify).

## Step 5b — Admin-token migration (admin-action-audit; BREAKING)

The shared admin tokens no longer authenticate by themselves — each caller needs
its own named token, and every admin mutation lands in the per-surface audit
ledger. Full detail: [`admin-apis.md`](admin-apis.md) → "Admin credentials & the
audit ledger". Rollback at any step = re-enable the flag.

- [ ] Deploy with `ADMIN_TOKEN_PEPPER` set (both surfaces; a separate secret from
      `APIKEY_HMAC_PEPPER`) AND `ADMIN_LEGACY_TOKEN_OK=true` (dual-mode: the shared
      tokens keep working, attributed `legacy-shared`).
- [ ] Confirm `AUDIT_RETENTION_DAYS` (default 450; floor 365 — the services refuse
      to start below it) and decide who runs the retention purge
      (`AUDIT_MAINTENANCE_PG_URL` in-service, or an external job as the
      maintenance role).
- [ ] Apply the ledger migrations' role grants
      (`routing-rs/store-postgres/migrations/0002_admin_audit.sql`,
      `identity-rs/store-postgres/migrations/0003_admin_audit.sql`) and point each
      service's DB user at its `*_service` role (append-only enforcement);
      enable **pgAudit** on both admin databases (out-of-band access trail).
- [ ] Mint a named token per real caller on EACH surface (signup broker, ops CLI,
      CI): `POST /admin-tokens {"name":"…"}` — store each one-time secret in the
      caller's secret store.
- [ ] Update every caller to its own token; watch the logs for
      "legacy shared admin token used" warnings until they stop.
- [ ] Flip `ADMIN_LEGACY_TOKEN_OK=false` (the default) and redeploy; verify via
      `GET /audit/events` denial events that nothing still presents the old token;
      then remove `CONTROL_AUTH_TOKEN`/`IDENTITY_ADMIN_TOKEN` from config.
- [ ] Spot-check the ledger on both surfaces: a mutation you just made is
      queryable (`GET /audit/events?actor=<your atk_…>`) and the export streams
      (`GET /audit/events/export`).

## Step 6 — Production rollout (N4 order: enforcer before emitter)

> The fail-closed edge guards are **BREAKING** for pre-gate deployments — see
> `deploy/README.md` → "BREAKING" before you render. New deployments are unaffected.

- [ ] Roll the **identity sidecar** (which 403-enforces the `x-auth-requires-*` signals)
      **before or with** the tenant-router that emits them. A newer router beside an older
      sidecar leaves requirement rules silently unenforced; the reverse order is safe.
- [ ] Control-plane reachability matches C16: broker-only NetworkPolicy on `:9400`,
      scrapers/kubelet on the ops port `:9401` only, `CONTROL_AUTH_TOKEN` from a Secret,
      `CONTROL_AUTH_DISABLED` never set.
- [ ] Cut production DNS/ingress over to the edge.

## Step 7 — Post-rollout verification

- [ ] Re-run the read-only smoke-test against **production** (`EDGE=`/`AUTHZ=`/`CONTROL_PLANE=`/`PROM_URL=` → prod).
- [ ] Confirm the monitoring alerts from Step 4 are firing on real signals (not silently misconfigured).
- [ ] Spot-check: a privileged user reaches a gated route; an unprivileged/forged request is refused.

**Rollback:** the N4 order is reversible-safe — a sidecar that sees no signals enforces
nothing, so rolling the router back first (or the whole edge) fails safe. Keep the prior
pinned image tags handy for a fast `helm rollback`.

---

## Sign-off record

| Step | Owner | Date / commit | Notes |
|---|---|---|---|
| 0 Scope frozen | | | |
| 1 Staging represents prod | | | |
| 2 Helm config hygiene | | | |
| 3 Smoke-test green (+opt-in) | | | |
| 4 Manual sign-offs | | | |
| 5 Authz provisioned | | | |
| 5b Admin tokens migrated, audit live | | | |
| 6 Production rollout | | | |
| 7 Post-rollout verified | | | |

Go-live is authorized only when every row is signed by someone who did the work — not
inherited from staging.
