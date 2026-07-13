# Backend pools — where they live and how to change them

A **pool** is one of a small, **finite** set of backend destinations the routing
decision selects among (RFC C15 / decision 13). A tenant is assigned to exactly
one pool; the edge forwards that tenant's traffic to it. Configuration never
invents a new destination at request time — the set is fixed and reviewed.

> **A pool is not a load balancer, it's a *destination class*.** nexus decides
> *which pool* a request belongs to (by `host → tenant → pool`); **Envoy
> load-balances across the instances *within* that pool** (`lb_policy` +
> `lb_endpoints`). See `./on-demand-tls.md` and the architecture notes for the
> decision-vs-enforcement split.

## The request path (how a pool gets chosen)

```
request ─► Envoy edge
            header_mutation     strip client-supplied x-route-pool / x-* (C3)
            tenant-router        host → tenant → sets  x-route-pool: <pool>   (C18)
                                 + resolves (domain, path) → x-auth-required    (N4)
            jwt_authn            branch on x-auth-required: verify credential, or
                                 allow_missing (anonymous pass-through)         (N4)
            identity ext_proc    inject x-user-*
            router               x-route-pool ─match─► cluster pool_<name> ─► your backend
```

The tenant-router emits `x-route-pool` from the tenant's `target_pool`; Envoy's
route table matches that header to a `pool_<name>` cluster; that cluster holds the
real backend address and the load-balancing policy.

## The two things that MUST agree (no recompile)

The pool allow-list is **data-driven** (loaded from config, mirroring
`ROUTING_PLAN_LIMITS`), so adding a pool is a config + edge-cluster change — **not
a Rust rebuild**. A pool is usable when both line up:

| # | What | Where | Role |
|---|------|-------|------|
| 1 | **Pool allow-list** (validation) | Control plane env **`ROUTING_POOLS`** (JSON array). **K8s:** auto-derived from `keys .Values.pools` (see `helm/routing-plane/templates/control-plane.yaml`). **Compose:** `ROUTING_POOLS` in `.env`; empty → the built-in default `["application","api","checkout","assets"]`. Parsed by `load_pools()` → `PoolSet` in `routing-rs/router-core/src/domain.rs`. | `PoolSet::parse` **rejects** any `target_pool` not in the set, so the control plane refuses to assign a tenant to an unknown pool ("invalid target_pool", with the allowed list in the error). |
| 2 | **Envoy clusters + routes** (destination) | **K8s:** `deploy/helm/routing-plane/values.yaml` → `pools:`; the three `helm/*/templates/edge-configmap.yaml` render the `pool_*` clusters + routes from it. **Compose:** hand-edited `deploy/compose/envoy/envoy.yaml` (and `edge/envoy.yaml`). | Each `pool_<name>` cluster carries the **backend address** + **`lb_policy`**; the route table maps `x-route-pool: <name>` → `cluster: pool_<name>`. |

> **On Kubernetes there is effectively ONE source of truth: `.Values.pools`.** It
> renders the Envoy clusters *and* routes *and* the control plane's `ROUTING_POOLS`
> allow-list. Add a key to `pools:` and the pool is accepted **and** routable — one
> edit, no recompile.
>
> **On compose, two must agree:** the `pool_*` clusters in `envoy.yaml` and the
> `ROUTING_POOLS` allow-list (which defaults to the four shipped clusters). Keep
> them in lockstep — and keep the trusted-header strip list in sync across the
> compose `envoy.yaml` and all three configmaps (a forgotten strip is a
> privilege-escalation bug — RFC C3 / INFO.md §4).

## Common operations

| Task | Where | Rebuild? |
|------|-------|----------|
| **Re-point** an existing pool at your backend | Compose: the `pool_<name>` cluster `socket_address` in `deploy/compose/envoy/envoy.yaml`. K8s: `pools.<name>.host/port` in `values.yaml`. | No |
| **Tune load balancing** within a pool | Add `lb_endpoints` and/or change `lb_policy` (`ROUND_ROBIN`, `LEAST_REQUEST`, …) in that `pool_<name>` cluster. `STRICT_DNS` already spreads across the hostname's A-records. | No |
| **Assign a workspace** to a pool | `PUT /workspaces/{id} {…, "target_pool": "api"}` on the control-plane — **data**, not config. | No |
| **Add a brand-new pool** | K8s: one edit to `pools:`. Compose: `envoy.yaml` cluster + `ROUTING_POOLS`. See the runbook. | **No** |

## Runbook: add a new pool (e.g. `media`)

A new pool is config only — the control plane validates against `ROUTING_POOLS`,
and the edge routes by the `pool_*` cluster set. No source change, no rebuild.

**Kubernetes (single edit):**
1. Add `media: { host: media-backend.svc, port: 80 }` under `pools:` in
   `deploy/helm/routing-plane/values.yaml` (and the `edge-platform` umbrella).
2. `helm upgrade`. The edge gets a `pool_media` cluster + route, and the control
   plane's `ROUTING_POOLS` picks up `media` — both from that one key.
3. `PUT /workspaces/{id} {"plan": "...", "target_pool": "media", ...}` (or set it at create).

**Compose (two edits, in lockstep):**
1. Add a `pool_media` cluster (backend address + `lb_policy`) and an
   `x-route-pool: media` → `cluster: pool_media` route in
   `deploy/compose/envoy/envoy.yaml` (mirror into `edge/envoy.yaml` if used).
2. Set `ROUTING_POOLS=["application","api","checkout","assets","media"]` in `.env`
   (the default omits `media`, so it must be listed explicitly here).
3. `docker compose up -d`, then
   `PUT /workspaces/{id} {"plan": "...", "target_pool": "media", ...}` (or set it at create).

**Verify:** a request for that workspace's domain lands on the `media` backend; an
unknown `target_pool` is rejected at `/workspaces` with the allowed list (the
guardrail working).

## Why the set is finite (but no longer compiled)

RFC C15 / decision 13: routing selects among a **finite, reviewed** set of
destinations so a misconfiguration (or a compromised control-plane write) can
never point traffic at an arbitrary, unvetted upstream. That safety property is
preserved — the allow-list is still explicit and fail-closed (an unknown pool is
rejected; an empty/invalid `ROUTING_POOLS` falls back to the built-in default,
never to "any destination"). What changed: the list is now **loaded from config**
instead of compiled into a Rust `enum`, so adding a pool is a config + edge-cluster
change rather than a rebuild. The `Pool` type is now a validated name
(`PoolSet::parse`), not a hardcoded variant.
