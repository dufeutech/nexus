# On-demand TLS for tenant custom domains — edge spec (#3)

How the TLS-terminating edge (Caddy today, in the ingress/infra layer) must be
configured to issue certificates for **unbounded, self-service tenant custom
domains** — gated by nexus's authorization predicate and backed by a **shared**
certificate store so every balancer can serve every domain.

> Scope: this is the **tenant-custom-domain** path (arbitrary `app.acme.com`
> declared at runtime). The **first-party** ingress (`api.example.com`,
> `*.example.com` — a finite, known set) is terminated by cert-manager / your LB
> and is out of scope here (see `../deploy/README.md`).

The two non-negotiables, and why:

1. **Shared/clustered cert storage** — so adding an edge node is "join the pool,"
   never "re-issue every cert." Decide this **before the second balancer exists**;
   retrofitting diverged per-node file stores onto a running fleet is painful.
2. **`ask` → nexus `/authorize`** — Caddy must ask nexus per-host before issuing,
   so a cert is issued **iff** the host is one the router will actually route (the
   same predicate, no "cert issued, then 404"). See `nexus-upstream-requirements.md`
   §N1; the endpoint is live in `routing-rs/tenant-router/src/main.rs`.

---

## Caddyfile (global options)

```caddyfile
{
    # (1) SHARED cert store — every Caddy instance pointed at the same Postgres
    # forms one cluster: CertMagic coordinates issuance and shares the certs,
    # OCSP staples and lock state across all of them automatically. "Any balancer
    # serves any domain" falls out of this for free.
    storage postgres {
        connection_string {$CADDY_STORAGE_PG_URL}
        # disable_ddl true   # set once the cert tables exist + the role is locked down
    }

    # (2) On-demand issuance, authorization-gated. Caddy GETs
    #   {ask}?domain=<sni>
    # and issues IFF the response is 2xx. nexus /authorize is fail-closed (403
    # for unknown / unverified / pending / not-ready), so this is safe to expose
    # to arbitrary SNI. Point it at the LOCAL tenant-router on every edge host —
    # it answers from its in-memory cache in ~milliseconds (the doc's perf rule).
    on_demand_tls {
        ask {$AUTHORIZE_URL}
    }
}

# The tenant-domain listener. `on_demand` ENABLES on-demand for this site; the
# global block above only configures it. Without `on_demand` here, nothing is
# issued on demand.
https:// {
    tls {
        on_demand
    }
    reverse_proxy {$EDGE_UPSTREAM}   # -> the nexus tenant-first edge (Envoy)
}
```

Environment:

```bash
# Reuse the SAME Postgres that holds the routing store (one managed DB, one
# backup/HA story). Cert blobs live in CertMagic's own tables — separate from
# routing.* — so they never collide with nexus's schema.
CADDY_STORAGE_PG_URL=postgres://caddy:***@pg-primary:5432/routing?sslmode=verify-full

# The LOCAL tenant-router's Caddy-`ask`-compatible endpoint (co-located per edge).
# The router serves /authorize, /resolve, /healthz on :9300 (see
# tenant-router/src/main.rs — "resolve/health API on :9300").
AUTHORIZE_URL=http://127.0.0.1:9300/authorize

EDGE_UPSTREAM=127.0.0.1:10000          # the Envoy tenant-first edge
```

## Build (the Postgres storage module is not in stock Caddy)

```bash
xcaddy build --with github.com/yroc92/postgres-storage
```

Bake that into the edge image. (Pin the module to a commit; verify it still
tracks current CertMagic before bumping Caddy.)

---

## Why these choices

- **Postgres storage, not Redis/file** — you already operate Postgres for the
  routing store, so cert storage adds **no new stateful dependency**: same managed
  DB, same backups, same HA. CertMagic's locking + sharing across instances is the
  mechanism behind "any balancer serves any domain."
- **`ask` = the router's own predicate** — `/authorize` resolves with the SAME
  code path as routing, so the cert gate and the router converge by construction.
  (N1 shipped; the interim `services/entry/templates/authz.py` shim and its
  `pg_*` reads were deleted from the infra side 2026-06-30.)
- **The quota gate is the issuance-rate governor** — on-demand issues one cert per
  domain on first handshake; renewals recur (~60d) for every live cert. The
  per-tenant plan quota (control-plane `declare`, already shipped) caps how fast
  the domain set — and therefore the ACME issuance/renewal load — can grow. This
  is what keeps the naive 1-cert-per-domain model under Let's Encrypt limits
  without extra machinery, and the seam where SAN-packing / multi-account ACME
  slots in later if the curve ever demands it.

## Operational notes

- **Session connection, not a transaction-mode pooler** for `CADDY_STORAGE_PG_URL`
  — CertMagic uses locks; route it to the primary on a direct/session connection,
  consistent with the `ROUTING_PG_URL` caveat in `../deploy/README.md`.
- **Grant `CREATE` on first run** so the module can create its cert tables, then
  flip `disable_ddl true` and lock the role down (mirrors the control-plane's
  schema-bootstrap posture).
- **`/authorize` must be reachable from Caddy on every edge host** and must stay
  fail-closed; a 5xx or timeout there blocks issuance (correct — never issue a
  cert you can't authorize).

## Go-live gates (before onboarding volume)

Two external prerequisites carried over from the `custom-domains-tls` rollout — they
gate the *production* switch, not the implementation (which is shipped), and clear
against live infrastructure / Let's Encrypt:

- **Request the LE per-account new-order rate-limit override** before onboarding real
  volume. On-demand issues one order per net-new domain on first handshake; the default
  per-account new-order limit throttles a fast onboarding curve. File the override with
  Let's Encrypt for the production ACME account ahead of the ramp. (Renewals ride the ARI
  exemption and are not governed by this limit.)
- **Observe an ARI-driven renewal in production**: confirm a certificate nearing expiry
  renews in advance and that renewal does **not** consume net-new issuance budget (the ARI
  exemption is actually in effect), before relying on unattended renewal at population scale.

## Kubernetes cutover (Helm `edge-platform`, `frontTier.*`)

The front tier ships in the `edge-platform` umbrella (change `helm-front-tier-tls`,
closing infra finding N12). In k8s the front tier is a **separate Deployment/Service**
from the combined edge — Caddy reaches `/authorize` through a dedicated in-cluster `ask`
Service (`<release>-edge-platform-ask:9300`), not loopback.

1. **Prereqs.** Apply the CertMagic schema
   (`routing-rs/store-postgres/migrations/0001_certmagic_store.sql`) to the routing DB and
   create a DML-only role; put its **session/direct** URL in a Secret
   (`frontTier.storage.existingSecret`). Deliver the ACME account key **out-of-band** into
   `frontTier.acmeAccount.existingSecret` (ESO / OpenBao Secrets Operator / a K8s-auth role).
2. **Enable, staging first.** `frontTier.enabled=true`, `frontTier.acme.email=…`; leave
   `frontTier.acme.caDir` at the LE **staging** default. Bring up a lab, drive an authorized
   host end-to-end (handshake → `ask` → issue → serve), confirm an unauthorized host fails
   the handshake closed.
3. **Client IP (optional).** If an L4 SNI router fronts `:443`, set
   `frontTier.proxyProtocol.enabled=true` (and `edge.proxyProtocol.enabled=true` if the
   router fronts the edge directly) **in lockstep with the router** — an enabled listener
   rejects un-framed connections.
4. **Go live.** Flip `frontTier.acme.caDir` to the LE **production** directory, then point
   the SNI router / customer DNS at the front-tier Service `:443`. The combined edge stays
   up alongside (`:10000`), so this is a parallel run.
5. **Rollback.** Point the router/DNS back at the prior entry point and set
   `frontTier.enabled=false`. The edge never went down; issued certs persist in the shared
   store for a re-cutover.
