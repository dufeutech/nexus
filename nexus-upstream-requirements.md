# Nexus upstream integration requirements

Features/patches the **nexus** stack (`dufeutech/nexus` — first-party, we own it) should
absorb so the infra side (`toolify` entry + stores) stays thin and the _authoritative_
domain logic lives in the platform. Hand this to the nexus agents.

> Why upstream, not in toolify: the entry layer currently ships a sidecar
> (`services/entry/templates/authz.py`) that re-implements "is this a known, verified
> tenant domain?" by reading `routing.domains` directly — only because nexus exposes no
> per-host read of that predicate (the control-plane admin API is a loopback singleton on
> ctrl-1). That duplication already caused a divergence in testing (2026-06-21): a
> wildcard row authorized a cert the tenant-router then `404`'d. Moving the decision into
> nexus removes the duplicate and makes the cert gate and the router the **same decision**.

Background the infra side already provides (do not rebuild): on-demand, authorization-gated
TLS at the edge (Caddy), a **shared Postgres certificate store** (any balancer serves any
domain), a stable ingress name `edge.<base_domain>` (a DNS-only A-pool of the balancer IPs)
that tenants `CNAME` to, and the product model below. See `docs/on-demand-tls.md`
(edge TLS + shared cert store + the `ask` → `/authorize` wiring) and `docs/backend-pools.md`.

Product model (decided): tenants **declare each (sub)domain explicitly**; the per-tenant
domain **count is plan-gated** (the upsell lever). Once a domain is `verified`, the infra
mechanics are already **fully automatic** (verify → authorize → on-demand issue → share to
all balancers → route), zero operator touch. So self-service only has to automate the one
human-trust step (`verified`) and the quota.

---

## Status (2026-06-29)

| Req    | State                | Where                                                                                 |
| ------ | -------------------- | ------------------------------------------------------------------------------------- |
| **N1** | ✅ SHIPPED            | `routing-rs/tenant-router/src/main.rs` — `GET /authorize` on `:9300` (`api::authorize`) |
| **N2** | ✅ SHIPPED            | `routing-rs/control-plane/src/main.rs` — `/domains/declare`, `/domains/{d}/verify`, poll |
| **N3** | finding only         | no work — captured below in case wildcard tiers are ever wanted                        |
| **N4** | ~ Phase 1 in repo    | auth gate shipped (`x-auth-required` → jwt_authn `allow_missing`); role/entitlement/AAL gate (phase 2) still open |

Infra follow-up now unblocked by N1: point Caddy `on_demand_tls { ask … }` at the local
tenant-router and **delete** `services/entry/templates/authz.py` + `Dockerfile.authz` + the
`pg_*` read refs (the doc's "interim shim" no longer applies — see `docs/on-demand-tls.md`).

---

## N1 — tenant-router: per-host domain-authorization endpoint (retire the infra gate)

> **✅ SHIPPED.** Live as `GET /authorize?domain=<sni>` on the tenant-router's `:9300` HTTP
> API (`routing-rs/tenant-router/src/main.rs`, `api::authorize`). It resolves with the SAME
> `resolve()` path as routing and fails closed (`403`) on empty/unknown/pending/not-ready.

**Problem.** Caddy on-demand TLS needs a per-host HTTP `ask`. nexus exposes none, so the
infra ships `authz.py`, duplicating the router's routing predicate.

**Ask.** The **tenant-router** (already replicated on every edge host) exposes a tiny HTTP
endpoint, **Caddy-`ask`-compatible**:

```
GET /authorize?domain=<sni>      ->  2xx  if <sni> is a known, VERIFIED, routable domain
                                     403  otherwise   (fail-closed)
```

- Same predicate the router uses to resolve `host → tenant → pool` — so a domain that
  authorizes a certificate is, by construction, a domain the router will route (no more
  "cert issued, then 404").
- Read-only, fast (it's already in the router's cache), bound to the host, no new store.

**Effect on infra.** Point Caddy `on_demand_tls { ask … }` at the local tenant-router and
**delete** `services/entry/templates/authz.py` + `Dockerfile.authz` + the `pg_*` read refs.
(N1 has shipped, so this deletion is unblocked — the `authz.py` shim is no longer required.)

---

## N2 — control-plane: self-service domain lifecycle (declare + TXT-verify + quota)

> **✅ SHIPPED.** `routing-rs/control-plane/src/main.rs`: `POST /domains/declare` (quota gate
> via data-driven `ROUTING_PLAN_LIMITS`, structured `402 quota_exceeded`, idempotent
> challenge, pending-TTL sweep), `POST /domains/{domain}/verify` + a leader-elected
> background poll (TXT proof → `verified` + `pg_notify('routing_invalidations', …)` → retire
> challenge). N2a/N2b/N2c are all covered. The spec below is retained as the contract.

The control-plane owns the `routing` schema, the domain API, and the invalidation NOTIFY —
so the declare/verify/quota lifecycle belongs here. Keep using the existing
`routing_invalidations` NOTIFY; do not add a second invalidation path.

### N2a — Declare (with quota)

An endpoint the self-service/dashboard layer calls:

```
declare(tenant_id, domain):
  - QUOTA: reject if the tenant's (verified + pending) domain count >= plan limit;
           return a structured `quota_exceeded` error carrying {plan, limit, used}
           (the dashboard turns this into an upgrade prompt).
  - create an UNVERIFIED routing.domains row for `domain` under `tenant_id`.
  - mint a verification token; return the expected DNS record the tenant must add:
        name  = _nexus-challenge.<domain>
        type  = TXT
        value = <token>
  - idempotent: re-declaring a pending domain returns the SAME challenge.
```

### N2b — Verify (TXT — the strongest proof)

```
verify(domain) [periodic poll of pending domains, and/or a tenant-triggered "check now"]:
  - resolve TXT _nexus-challenge.<domain>; on token match:
       set verified = true  AND  pg_notify('routing_invalidations', domain)
       (routers + the cert gate converge in seconds; mechanics take over automatically).
  - token has a TTL + can be re-issued; clear/retire the challenge on success.
```

TXT proves the tenant controls the domain's DNS — required before `verified`, or tenant A
could claim `victim.com`. The challenge name is a _subdomain_ label, so it coexists with an
apex `CNAME`-flattened record.

### N2c — Plan → limit

Data-driven config (`plan name → max domains`), not hardcoded, so billing tiers map to it
(e.g. free=1, pro=N, enterprise=∞). The declare quota check reads this.

---

## N3 — (optional / future) wildcard apex coexistence + canonical matching

Not needed for the explicit model above (each domain is its own exact row). Capture the
**finding** so it's known if wildcard tiers are ever wanted (verified live 2026-06-21):

- One row per `domain` string. `is_wildcard=true` routes **subdomains** (`blog.x.com` → ok)
  but **not the apex** (`x.com` → 404). `is_wildcard=false` routes **only the apex**. A
  literal `*.x.com` row does not match (the router strips the left label and looks up the
  bare parent). So **apex + wildcard-subdomains cannot coexist** for one domain.
- If wildcard tiers are wanted: key domains by `(domain, is_wildcard)` **or** let a wildcard
  also cover its own apex; and publish **one** canonical matching spec that BOTH the
  tenant-router **and** any remaining infra gate implement identically.

---

## N4 — per-route auth policy (anonymous pass-through + declarative "private" modes)

> **~ Phase 1 in repo.** The authentication gate is implemented: `router-core::auth`
> (policy types + longest-prefix `resolve`), `routing.auth_routes` (per-tenant path-prefix
> rules; default = the `/` row, absence = pass-through), control-plane CRUD at
> `PUT/GET/DELETE /tenants/{id}/auth-routes`, tenant-router emits `x-auth-required` from the
> resolved `(domain, path)` policy, and `edge/envoy.yaml` branches jwt_authn on it
> (`provider` vs `allow_missing`) with the header in the C3 strip list. **Phase 2 (open):**
> the `x-auth-requires-role` / `-entitlement` / `x-auth-min-aal` emission + the 403
> enforcement step (identity sidecar or Envoy RBAC) — deferred (it crosses into identity-rs).

**Problem.** `jwt_authn` ships a single static rule (`match: "/" requires: provider zitadel`),
so **every** route demands a valid token — a customer's site is all-or-nothing (no public
marketing page + private app on the same domain). The only per-route lever today is a `/public`
path prefix, which is **unacceptable** (forces tenants to restructure their URLs). Meanwhile the
identity sidecar **already** supports anonymous (no credential → `x-auth-anonymous: true`,
emitted on every request); the _only_ thing blocking pass-through is jwt_authn's unconditional
`requires`. (Found while rehearsing the k3s migration, 2026-06-29.)

**Two-knob separation (the model).**

- **Authentication METHOD** (password / passkey / MFA / social / SSO) stays in **ZITADEL**
  (per-org login policy). The edge is method-agnostic — out of scope here.
- **Route PROTECTION** is this requirement: a **declarative per-route policy** the tenant-router
  resolves (exactly as it resolves host→tenant→pool) and the edge enacts.
- **Resource ownership** ("does this user own THIS order") stays in the **backend**.

**Ask.** tenant-router resolves a policy per `(domain, path-pattern)` and emits authoritative,
**C3-stripped** headers the edge branches on:

- `x-auth-required: true|false` → jwt_authn uses `requires: provider` vs `requires: { allow_missing: {} }`.
  Use **`allow_missing`, NOT `allow_missing_or_failed`**: a _missing_ token → anonymous pass-through;
  a _present-but-invalid/expired_ token still **401s**.
- optional `x-auth-requires-role` / `x-auth-requires-entitlement` / `x-auth-min-aal` → a thin authz
  step (Envoy RBAC filter or the identity sidecar) returns **403** when the already-injected
  `x-user-roles` / `x-user-entitlements` / `x-auth-method` don't satisfy; else pass to the backend.

**Default = `auth: none` (pass-through)** so any customer site works with zero URL constraints;
authenticated / role / entitlement gating is opt-in (the membership/plan upsell). The dynamic
branch is safe because tenant-router runs BEFORE jwt_authn (C17) and every `x-auth-*` policy header
is in the C3 strip list (clients cannot self-assert) — **add `x-auth-required` + any new policy
headers to that strip list.**

**Data model.** Auth policy in routing config: a per-tenant default + optional per-path-pattern
overrides (`{path_glob, auth_required, requires_role?, requires_entitlement?, min_aal?}`). Lives in
the `routing` schema, resolved + cached by tenant-router, invalidated via the existing
`routing_invalidations` NOTIFY; CRUD on the control-plane API (alongside N2).

**Effect on infra.** Removes the all-or-nothing edge: public + private coexist on one domain;
membership/plan gates run at the edge on existing enrichment; no `/public` hack.

---

## Ownership after these land

| Concern                                                                                                       | Owner                                                                       |
| ------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------- |
| declare, quota, TXT verify, invalidation NOTIFY                                                               | **nexus control-plane**                                                     |
| routing match + per-host `/authorize` endpoint (N1)                                                           | **nexus tenant-router**                                                     |
| per-route auth policy resolution + `x-auth-*` emit + role/entitlement gate (N4)                               | **nexus tenant-router** (resolve/enforce) + **control-plane** (policy CRUD) |
| authentication method (password/passkey/MFA/social/SSO)                                                       | **ZITADEL** (per-org login policy)                                          |
| ingress name `edge.<base_domain>`, shared cert store, Caddy on-demand wiring, deploy/HA, seeding `plan→limit` | **toolify / infra**                                                         |
| `CNAME <domain> → edge.<base_domain>` + the `_nexus-challenge` TXT                                            | **tenant**                                                                  |

N1 has shipped: the tenant-router `/authorize` endpoint is the on-demand gate.
`services/entry/templates/authz.py` is now removable (infra follow-up).
✅ Done in toolify 2026-06-30: `authz.py` + `Dockerfile.authz` deleted, authz sidecar + `pg_read_db`
removed, Caddy `on_demand_tls { ask }` → `http://tenant-router:9300/authorize`, tenant-router joined the
`edge` network. Deploy order: `nexus-edge` then `entry` (not yet deployed).
