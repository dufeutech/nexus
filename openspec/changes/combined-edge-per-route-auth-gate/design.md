# Design — combined-edge per-route auth gate

## Context

The per-route auth machinery is already deployed end-to-end; only the edge's
`jwt_authn.rules` consumer is unwired. The relevant pieces, today:

```
CONTROL PLANE                 DATA PLANE (tenant-router)        EDGE (jwt_authn)
auth_routes CRUD  ──────────► resolve(path) ► RouteAuth ──────► (this change wires
POST /tenants/{id}/auth-routes  emits x-auth-required (always)   the consumer)
                                true|false
```

`router-core::auth::AuthPolicy::resolve` is longest-prefix-wins and returns
`PASS_THROUGH { required: false }` when no rule matches — i.e. **public by default**,
the SaaS shape (marketing public, `/app` protected via a carve-out). The tenant-
router (`tenant-router/src/main.rs:434`) **always** emits `x-auth-required` on a
resolved host, and *rejects* (never passes through) on unknown-host/not-ready.

Affected edges are only the **combined** ones — a single Envoy whose chain is
`header-strip → tenant-router ext_proc → jwt_authn → identity ext_proc`:

| Config | Topology | tenant-router inline? | This change |
|---|---|---|---|
| `edge/envoy.yaml` (canonical) | combined | yes | backport inverted catch-all |
| `deploy/compose/envoy/envoy.yaml` | combined | yes (cluster `tenant_router`) | swap rules |
| `edge-platform` configmap | combined | yes | swap rules |
| `identity-plane` configmap | auth+enrich only | **no** | **out of scope** (see below) |
| `routing-plane` configmap | routing only, no `jwt_authn` | yes | unchanged (auth-less) |

## Goals / Non-goals

- **Goal**: a request to a public tenant route succeeds anonymously; a protected
  route requires a valid credential; an invalid credential always fails.
- **Goal**: the gate is fail-closed if the `x-auth-required` signal is ever absent.
- **Non-goal**: changing the public-by-default *policy* polarity in `auth.rs` — the
  product wants public-by-default; we only make the *edge's failure mode* fail-safe.
- **Non-goal**: the identity-plane / split-topology handoff (separate design below).
- **Non-goal**: N4 phase-2 (role/entitlement/AAL).

## Decision: inverted, fail-safe catch-all

`jwt_authn.rules` are first-match. The canonical config uses
`[x-auth-required==true → verify, prefix:/ → allow_missing]` — catch-all is
`allow_missing`, so an *absent* signal opens the route. We invert it:

```yaml
rules:
  - match: { prefix: "/", headers: [{ name: x-auth-required, string_match: { exact: "false" } }] }
    requires: { allow_missing: {} }       # explicit "false" → public (invalid token still 401s)
  - match: { prefix: "/" }
    requires: { provider_name: zitadel }  # "true" OR ABSENT → verify  (fail-safe catch-all)
```

| Scenario | tenant-router emits | canonical (allow_missing catch-all) | inverted (verify catch-all) |
|---|---|---|---|
| zero-config tenant | `false` | public ✅ | public ✅ |
| protected `/app` | `true` | verify ✅ | verify ✅ |
| signal absent | *(absent)* | 🔓 public | 🔒 verify (fail-safe) |

### Why inverted, given `failureModeAllow: false` already makes "absent" unreachable?

Confirmed: every ext_proc in every plane is `failure_mode_allow: false`, and the
tenant-router always emits the header on a routed request. So today the "absent"
column is unreachable in the combined edge — **B (canonical polarity) and C
(inverted) are behaviorally identical right now.** We still choose inverted because:

1. It makes the strip load-bearing in a self-documenting way and removes the
   latent fail-open that would activate the instant someone sets
   `failureModeAllow: true` (a plausible availability tuning) or a future ext_proc
   refactor drops the header.
2. It aligns the edge with the fail-closed posture used everywhere else in nexus.
3. Cost is one extra rule. No runtime/behavioral regression.

This is a security-sensitive correctness concern realized in **configuration we
own** (Envoy `jwt_authn`, a mature adopted component) — not hand-written logic — so
it sits at the "Adopt/Extend" tier; no new build. (Recorded for /opsx:decide.)

### Load-bearing invariant

The inverted catch-all trusts `x-auth-required` absolutely. A forged
`x-auth-required: "false"` would open a protected route, so the header_mutation
strip of the client copy (which runs *before* the tenant-router emits the
authoritative value) is a hard precondition — re-asserted as a spec requirement.

## Decisions

### Decision: per-route auth-gate enforcement — Extend Envoy `jwt_authn` rules

- **Status**: approved
- **Why**: `jwt_authn` natively expresses per-route conditional requirements via
  first-match, header-matched `rules` + `allow_missing`, with verification done
  locally (no per-request external call). Config-only, zero new dependencies, and
  already the pattern in use across every plane — the tenant-router has already
  reduced the policy to a single trusted header, so no external authz logic is
  needed.
- **Considered**: (a) `ext_authz` + OPA/custom authz service — adds a per-request
  network hop and a new component to run/secure; justified only for complex authz
  we don't have. (b) bespoke Lua/Wasm filter — reinvents native rule-matching,
  more code to maintain and security-review.
- **Isolation**: the Envoy `jwt_authn` filter config in each combined-edge configmap
  (`deploy/compose/envoy/envoy.yaml`, `edge-platform` configmap, canonical
  `edge/envoy.yaml`). The fail-safe polarity lives entirely in the rule ordering;
  no application code touches it.

## ADR: edge auth gate — adopt N4 per-route gate at the combined edge

- **Status**: proposed
- **Decision**: Replace blanket hard-require with the N4 per-route `jwt_authn`
  branch at the combined edge (compose + edge-platform), using an inverted fail-safe
  catch-all, and backport it to canonical `edge/envoy.yaml`.
- **Why**: the product serves public tenant custom domains; hard-require makes those
  return 401. The per-route machinery already exists; only the consumer was unwired.
- **Consequences**: unconfigured tenants become public by default (intended; opt-in
  protection via `auth_routes`). Operator note required. No code or dependency
  change. Invalid tokens still rejected everywhere. Fail-closed on signal loss.
- **Alternatives**: (A) status quo — rejected, breaks N1 public sites. (B) canonical
  polarity verbatim — rejected as the default because it is latently fail-open if
  `failureModeAllow` is ever flipped; C is strictly safer at equal cost.

## Follow-up (separate change): identity-plane / split-topology handoff

identity-plane's chain is `header-strip → jwt_authn(hard-require) → identity
ext_proc → router→single backend`. It has **no tenant-router**, nothing emits
`x-auth-required`, and its header_mutation *strips* `x-auth-required` at ingress.
So per-route adoption there is **not** a rules swap — it needs one of:

- **(i)** add a tenant-router ext_proc to the identity-plane chain (make it a
  combined edge), or
- **(ii)** in the split `routing-plane → identity-plane` topology, establish a
  trusted boundary so identity-plane *stops stripping* `x-auth-required` and
  consumes the routing-plane's emitted value — which requires guaranteeing the
  routing-plane is the only ingress (so the value can't be client-forged).

Either is a trust-boundary design with its own risks; it must not be bundled into
this config swap. Tracked here as the next exploration thread. Note: the
routing-plane ingress strip and the sidecar self-strip (belt-and-suspenders C3)
were already implemented and verified in the session that produced this change, so
the defense-in-depth layer is in place regardless of which option (i)/(ii) is taken.
