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
that tenants `CNAME` to, and the product model below. See `docs/nexus-platform.md` §11–12.

Product model (decided): tenants **declare each (sub)domain explicitly**; the per-tenant
domain **count is plan-gated** (the upsell lever). Once a domain is `verified`, the infra
mechanics are already **fully automatic** (verify → authorize → on-demand issue → share to
all balancers → route), zero operator touch. So self-service only has to automate the one
human-trust step (`verified`) and the quota.

---

## N1 — tenant-router: per-host domain-authorization endpoint (retire the infra gate)

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
Until N1 ships, `authz.py` stays as the interim shim.

---

## N2 — control-plane: self-service domain lifecycle (declare + TXT-verify + quota)

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

## Ownership after these land

| Concern                                                                                                       | Owner                   |
| ------------------------------------------------------------------------------------------------------------- | ----------------------- |
| declare, quota, TXT verify, invalidation NOTIFY                                                               | **nexus control-plane** |
| routing match + per-host `/authorize` endpoint (N1)                                                           | **nexus tenant-router** |
| ingress name `edge.<base_domain>`, shared cert store, Caddy on-demand wiring, deploy/HA, seeding `plan→limit` | **toolify / infra**     |
| `CNAME <domain> → edge.<base_domain>` + the `_nexus-challenge` TXT                                            | **tenant**              |

Interim until N1: `services/entry/templates/authz.py` remains the on-demand gate.
