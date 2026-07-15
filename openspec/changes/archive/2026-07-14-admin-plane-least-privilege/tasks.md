## 1. Ratify decisions

- [x] 1.1 Run `/opsx:decide` to ratify D1 (reuse adopted `cedar-policy` via a new thin `routing-rs/policy-cedar` adapter crate — vs hand-rolled scope check / cross-workspace dependency); record the outcome in design.md

## 2. Grant storage and provisioning (admin-plane-authorization: explicit grants, cutover parity, last-admin guard)

- [x] 2.1 Add the scopes column + full-scope backfill of existing tokens as one native SQL migration file under `routing-rs/store-postgres/migrations/`, loaded via the existing migration adapter
- [x] 2.2 Extend `PgAdminTokenStore`: `lookup` returns the actor's scopes with its token id (one query, no second round-trip); mint persists an explicit scope set; list exposes scopes without secret material
- [x] 2.3 Enforce explicit non-empty scopes at mint (400 on unscoped requests) and reject unknown scope names at write time
- [x] 2.4 Implement the last-credential-administrator guard: refuse a revoke that would leave zero active `token-admin` credentials, with a lockout-hazard reason (advisory-lock serialized; typed 409 at the API)
- [x] 2.5 Verify: unscoped mint is refused; scopes are visible on list; revoking the final `token-admin` credential is refused while a second one makes it succeed — integration test `grants_are_explicit_reviewable_and_lockout_guarded` PASSES against live Postgres (19/19); migration 0002→0003 applied cleanly, backfill = full grant, idempotent re-run does NOT re-widen a narrowed grant

## 3. Decision port and Cedar adapter (authorization is fail-closed)

- [x] 3.1 Define the vendor-agnostic decision port in `router-core` (request in → decision {effect, reason} out; deny-by-default; includes a deny-all implementation for fail-closed installs) — `router_core::admin_authz`
- [x] 3.2 Create the `routing-rs/policy-cedar` adapter crate: `admin.cedarschema` + `admin.cedar` as data files (principal with a scopes set; actions grouped read/provision/token-admin; permit iff the action's class is in the principal's scopes), validated at construction, construction failure → caller installs deny-all
- [x] 3.3 Verify (in-crate tests): grant-with-scope permits, grant-without-scope denies with a reason, empty scopes deny everything, malformed policy/schema fails construction — 7 tests pass

## 4. Enforcement at the admin surface (deny-by-default, distinguished token-admin)

- [x] 4.1 Classify every admin route into read / provision / token-admin — AS-BUILT (design D4 refinement): a declarative `(method, route template) → class` table (`authz_gate::ROUTE_CLASSES`) read via `MatchedPath`, because per-sub-router extension tags are invisible to a shared gate layer in axum; strictly stronger — an unlisted route denies at runtime
- [x] 4.2 Add the authorization middleware after `require_auth`: classify the matched route, read the actor's scopes, ask the PDP, 403 with the decision reason on deny; an unclassified route denies for every actor; `auth-disabled` bypasses; `legacy-shared` holds all scopes while `ADMIN_LEGACY_TOKEN_OK` lives
- [x] 4.3 Wire composition in `main.rs`: construct the Cedar PDP from `ADMIN_POLICY_PATH` (deploy overlays: `deploy/compose/policy/admin.*` + compose mount/env, `deploy/helm/edge-platform/files/policy/admin.*`), install deny-all on load failure, keep `/healthz` outside the gate
- [x] 4.4 Add the route-classification completeness test: table is duplicate-free, `token-admin` class is exactly the `/admin-tokens*` set, no mutating method carries `read`, unclassified denies even the full grant
- [x] 4.5 Verify (in-process, over the real policy set): a `read`-only grant is refused on every mutation and the credential surface, and permitted on reads; the full grant passes every classified route (parity); the empty grant passes nothing; deny-all refuses everything — end-to-end HTTP re-verified in 6.1

## 5. Audit ledger (admin-action-audit delta)

- [x] 5.1 Add the authorization-denial event kind (`authz.denied`): actor id, surface, attempted action class, decision reason — never credential material; recording failure keeps the request denied (mirror the existing authn-denial posture, per-actor rate-limited)
- [x] 5.2 Carry the permitting decision reason on recorded action events (`AuditCtx.authz_reason` → event `detail.authz_reason`)
- [x] 5.3 Verify: an authorization refusal leaves an attributed ledger trace with the reason; a failed denial write stays a denial; authn-denial recording is unchanged — integration test `grants_are_explicit_reviewable_and_lockout_guarded` (runs against `STORE_PG_TEST_URL`; exercised live in 6.1)

## 6. Rollout

- [x] 6.1 Run parity e2e against the lab stack: existing admin flows unchanged post-migration; a deliberately narrowed test token exercises the denial + ledger path end-to-end — new binary deployed to the live lab (startup ran the lockstep migration); `admin-plane-authz-e2e.sh` 18/18, `admin-audit-e2e.sh` 17/17, `n4-e2e.sh` 19/19
- [x] 6.2 Document grant narrowing, the lockout guard, and the break-glass/bootstrap path in the admin runbook; note the additive-column rollback — `docs/admin-apis.md` (scope table, authorization semantics, cutover/narrowing/break-glass) + `docs/openapi/control-plane.yaml` (scopes on mint, GET /admin-tokens, 403 Forbidden, 409 lockout guard; validates OK)
- [ ] 6.3 Mint narrowed tokens for real callers, cut them over one at a time using the ledger to confirm each caller's actual action classes, then de-scope over-broad tokens — PRODUCTION-ROLLOUT step: no real (non-lab) callers exist pre-go-live; the procedure is documented in `docs/admin-apis.md` (cutover & narrowing) and the lab deliberately stays in legacy migration mode

---

## Status (this apply)

**19/20 done; 6.3 is the go-live-time operational step** (no production callers exist
yet to narrow; procedure documented). Build + tests + live-Postgres integration +
live-lab e2e all pass:

- **Store/migration:** 0002→0003 applies cleanly; the backfill grants pre-existing
  tokens the full set; a re-run is idempotent and never re-widens a narrowed grant.
  Integration suite 19/19 against a real Postgres (incl. the new
  `grants_are_explicit_reviewable_and_lockout_guarded`).
- **Engine:** `routing-policy-cedar` (the same adopted `cedar-policy` 4.11 in a new
  thin adapter, D1 as ratified) — 7/7 in-crate tests; strict schema validation at
  load; deny-all installed on failure (embedded set observed loading at lab startup).
- **Gate:** one middleware after `require_auth` over the declarative
  `(method, template) → class` table — design D4 as-built refinement (recorded in
  design.md): runtime-denies unclassified routes, which the original sub-router
  sketch could not. Completeness + gate-core tests 5/5; clippy clean.
- **Live lab (real HTTP, real DB, new image):** parity — legacy/full-grant flows
  unchanged (`n4-e2e.sh` 19/19; `admin-audit-e2e.sh` 17/17, its cleanup now
  guard-aware); gate — `admin-plane-authz-e2e.sh` 18/18: unscoped/unknown mint 400,
  read-only token reads 200 while every mutation AND the credential surface 403 with
  a reason (no self-escalation), `authz.denied` attributed in the ledger with the
  reason, the permitted mint's event carries `authz_reason`, and 401 always precedes
  403. The lockout guard fired genuinely over HTTP when an e2e token was the last
  credential administrator (409, credential retained).
- **BREAKING honored:** `POST /admin-tokens` now REQUIRES `scopes` (spec: an unscoped
  mint is refused — no implicit default). Updated the one existing mint caller
  (`scripts/admin-audit-e2e.sh`), the OpenAPI spec, and the proposal's stale
  "additive" wording to match the ratified spec.
