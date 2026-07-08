# Design — identity-existence-hiding

> Coordination: this change edits the sidecar enrich path (`identity-rs/sidecar/src/main.rs`)
> shared with `normalized-principal`, `workspace-plan-tier`, and `customer-api-keys`. It **owns the
> unresolved/forbidden branch (404-vs-403)** and adds **no contract claim**. Sync order and
> edit-region ownership are canonical in `normalized-principal/design.md` **ADR-10**.

## Context (resolved in `/opsx:explore`)

The sidecar is an Envoy **`ext_proc`** service (not `ext_authz`): allow = pass-through with header
mutations; deny = `ImmediateResponse`. Today the only deny is `forbidden_403()` (`main.rs:830`),
emitted when `enforce_route_requirements` returns `Err(reason)` (`main.rs:1055`). There is **no 404
path** and no generic status+body+header builder — only the 503-fixed `immediate_503` and the
bespoke `forbidden_403`.

**Key structural fact:** the sidecar never asks "does workspace `W` exist." It only asks "is *this
caller* a member of `ws`?" via `resolve_membership(ws)` (`profile.rs:71`) → `Some(..)` / `None`. It
returns `None` for both "W doesn't exist" and "W exists but you're not in it" — so collapsing them
to one 404 is both honest and leak-free **by construction**. This is why no separate existence
lookup (and no timing correlation between the two) exists.

### Observable rule (three states → two responses)

```
  caller state                                   observable response
  ─────────────────────────────────────────────  ───────────────────
  member, route requirement satisfied         →  ALLOW (enrich, pass through)
  member, lacks role/entitlement/AAL for op    →  403   (existence already disclosed — honest)
  NOT a member (whether or not W exists)       →  404   (hide existence)
  workspace does not exist                     →  404   (identical envelope to the line above)
```

Invariant to make crisp in `specs/`: *for any caller who is not an authorized member of `W`, the
response is identical — status, body, headers, timing — to the response for a `W` that does not
exist.* 403 survives only for the member-who-lacks-a-specific-privilege case.

### Surgical shape (maps to real lines)

The change is a single split at the deny point (`main.rs:1055`), reordered so membership is checked
before the requirement reason is surfaced:

```
  enforce_route_requirements(...) → Err(reason)
        ├─ resolve_membership(ws) is None   → not_found_404()   (outsider ≡ nonexistent)
        └─ resolve_membership(ws) is Some    → forbidden_403()   (member lacks this privilege)
```

## Q1 — boundary trigger (resolved in `/opsx:propose`): implicit default-deny + explicit opt-out

The membership-404 gate fires for **any** request carrying an authoritative workspace context —
non-member → 404 — regardless of whether the route declares role/entitlement requirements
(**option B**). Public / pre-membership routes must **explicitly** opt out of the gate; a route
that omits the opt-out is gated (fail-closed). Chosen over the explicit-declared-requirement gate
(option A) because boxes no longer double-check membership: leaving the guarantee to route-config
discipline means a forgotten annotation is a silent passthrough hole — the exact failure existence-
hiding exists to prevent. The reordered decision therefore becomes:

```
  enriched route?  (x-auth-required: true)
    ├─ no  → public / non-enriched (websites, public app routes) → existing flow, no gate
    └─ yes → workspace-scoped?  (acting on a single routed workspace, not account-scoped)
               ├─ no  → account-scoped private (/me, list-my-workspaces) → existing flow, no gate
               └─ yes → resolve_membership(ws)
                          ├─ None → not_found_404()      (hide existence; ≡ nonexistent W)
                          └─ Some → enforce_route_requirements(...)
                                      ├─ Err → forbidden_403()   (member lacks this privilege)
                                      └─ Ok  → ALLOW (enrich)
```

**The gate keys off existing signals — no new client-facing control.** `x-auth-required`
(trusted-emitted, C3-stripped at the edge, `edge/envoy.yaml:234`) already separates enriched
(private) from non-enriched (public) routes, and is already fail-closed ("treated as enriched unless
*explicitly* designated non-enriched" — `identity-workspace-authz`). Existence-hiding reuses it
rather than inventing an exemption header. The three front-line surfaces map directly:

| Surface | `x-auth-required` | `x-workspace-id` role | Gate |
|---------|-------------------|-----------------------|------|
| Websites (public)    | `false`   | routing/tenant only   | not gated (nonexistent tenant → ordinary 404) |
| API (private)        | `true`    | acting scope          | gated → non-member 404 |
| Apps (public/private)| per-route | per-route             | public routes not gated; private workspace routes gated |

**Workspace-scoped vs account-scoped** is the one distinction not carried by `x-auth-required` alone:
a tenant-routed `/me` is enriched and carries a tenant `x-workspace-id`, yet must not require
membership. So the gate additionally requires the route to be *workspace-scoped* (membership of the
routed workspace is the access basis). Fail-closed default: an enriched route is workspace-scoped
(gated) unless explicitly designated account-scoped — a forgotten designation denies, never leaks;
account routes are few, well-known, and their breakage is loud rather than silent.

## Decisions (build-vs-adopt gate — `/opsx:decide`)

### Decision: Existence-hiding policy (404-vs-403 semantics) — Adopt the HTTP standard

- **Status**: approved
- **Why**: Returning 404 to hide a forbidden resource is a blessed HTTP semantic
  (**RFC 9110 §15.5.4**) with mature precedent (GitHub private-repo 404s, AWS S3 `ListBucket`-gated
  403/404, OWASP enumeration guidance). We implement a standard behavior, not a hand-rolled policy.
- **Considered**: inventing a bespoke status/redirect scheme (rejected — reinvents a solved,
  standardized semantic and invites drift from what clients/proxies already expect).
- **Isolation**: the deny-point branch in `enrich()` (`main.rs:1055`); the policy lives entirely in
  that one reorder, not spread across components.

### Decision: Timing side-channel closure — Adopt the existing equal-work architecture (add no mechanism)

- **Status**: approved
- **Why**: Outsider-403 and nonexistent-404 traverse the **same branch doing the same work**
  (`resolve_membership → None` after the principal resolution that both pay identically), so timing
  converges structurally. The existence decision compares **no secret** — it is a boolean membership
  gate — so constant-time comparison is the wrong tool. Sub-millisecond network-timing side-channels
  are explicitly **out of v1 scope**, documented rather than mitigated with weak measures.
- **Considered**: `subtle`/`constant_time_eq` (already in-tree for PAT hash compare, but solves
  secret-comparison — misapplied to a boolean gate); latency jitter/padding on the deny path
  (rejected — statistically defeatable, adds latency and moving parts to every deny).
- **Isolation**: no new mechanism; the invariant is "both not-authorized outcomes share one branch,"
  enforced by keeping principal resolution ahead of and independent of the allow/deny decision.

### Decision: Uniform not-found envelope across the edge — align the tenant-router's unknown-host 404

- **Status**: approved (decided during apply)
- **Why**: A second `404` exists at `tenant-router::reject_unknown_host()` (unknown host → no tenant).
  Left with its old body (`"unknown tenant for host"`) an **authenticated** prober could distinguish
  "tenant does not exist" from "tenant exists, not a member" (sidecar `"not found"`) by body. Aligning
  both to the same minimal `"not found"` makes the two nexus-authored existence 404s byte-identical.
- **Scope boundary (documented, not closed)**: host/tenant-level existence is only *partly* hidden —
  the unauthenticated **401** (known host, no creds) vs **404** (unknown host) boundary is unchanged,
  and tenant subdomains are discoverable via DNS / TLS SNI / certificate transparency regardless. The
  in-scope, closable part (the authenticated response *body*) is aligned; the rest is out of v1 scope.
- **Isolation**: a one-line body change in `reject_unknown_host()`; operational detail (which host,
  why) stays in logs/metrics, mirroring the `forbidden_403()` "name nothing" principle.

### Decision: 404 response envelope — Build a minimal bespoke `not_found_404()` helper

- **Status**: approved
- **Why**: A ~5-line `ImmediateResponse` literal mirroring `forbidden_403()` (`main.rs:830`):
  minimal body, no distinctive headers, byte-identical every emission. A minimal body **is** the
  leak-avoiding choice — nothing distinguishes it from a plain not-found.
- **Considered**: RFC 7807 `application/problem+json` via a crate (rejected — a distinctive
  structured body would make the sidecar's 404 distinguishable from a plain box 404, re-opening the
  very leak this change closes; plus a new dependency for a tiny surface).
- **Isolation**: one helper alongside the existing `forbidden_403`/`immediate_503` literals; the
  sidecar remains the single author of both the 404 and the 403 (outsiders never reach a box, so no
  cross-envelope comparison is possible).
