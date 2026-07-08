## Context

nexus resolves an inbound hostname to a workspace in exactly one place: `AppState::resolve`
(`tenant-router/src/main.rs:177-193`), backed by `normalize_host`/`parent_domain`
(`router-core/src/normalize.rs`) and `PgRoutingStore::lookup_domain`. The store keys domains on the
composite `PRIMARY KEY (domain, is_wildcard)` (`store-postgres/src/lib.rs:212-220`), so an apex row
and a wildcard row for the same domain string already coexist. The `/authorize` cert gate
(`tenant-router/src/main.rs:756-771`) calls the same `resolve()`, and `router-core::auth` matches
request *paths* only — so there is exactly one host matcher today.

The behavior is correct and industry-standard, but it exists only in code and schema comments:
`openspec/specs/` says nothing about host matching, and no test pins apex-vs-wildcard or
exact-vs-wildcard precedence (`store-postgres/tests/integration.rs` exercises exact rows only). This
change writes the canonical spec and adds the guard tests. It changes no production code.

## Goals / Non-Goals

**Goals:**
- Specify the existing exact → single-label-wildcard → no-tenant matching lattice as a durable,
  language-agnostic contract, including apex/wildcard coexistence and most-specific-wins.
- Pin the security-relevant behavior with tests so a future `resolve()` refactor fails loudly.
- Make the "one matcher for routing and cert authorization" invariant explicit and tested.
- Correct the stale N3 doc.

**Non-Goals:**
- Self-service wildcard declaration (stays admin-seeded).
- Plan-tier depth gating, PSL/eTLD+1 handling, multi-label/nested wildcards, downgrade semantics.
- Any change to `resolve()`, `normalize`, or the `routing.domains` schema.

## Decisions

### Decision: Wildcard matcher — Build (keep the existing single-hop `resolve()`), no change

- **Status**: approved
- **Why**: The shipped exact-then-single-label-wildcard matcher already meets every industry-standard
  property (most-specific-wins, apex ≠ wildcard, single matcher shared with `/authorize`); the work is
  to ratify and guard it, not to rebuild it.
- **Considered**: Multi-hop "greedy depth" matcher (rejected — diverges from TLS-cert single-label
  semantics and pushes plan/depth logic into the hot path); adopting an external routing/host-match
  library (rejected — the matcher is a few lines and tightly coupled to the store's two-point-read
  contract).
- **Isolation**: `AppState::resolve` + `router-core::normalize`; the store port `lookup_domain`.

### Decision: Registrable-domain / eTLD+1 (Public Suffix List) — not adopted (out of scope)

- **Status**: approved
- **Why**: The PSL/eTLD+1 boundary only matters when tenants can declare wildcards themselves (to
  block `*.co.uk` and to measure depth fairly). At this level there is no self-service wildcard: the
  single platform wildcard is admin-seeded and trusted, and tenant custom domains are exact and
  TXT-verified, so the ownership boundary is already enforced by verification.
- **Considered**: Adopt a pinned-snapshot PSL crate now (rejected — no risk surface to justify the
  dependency yet). Recorded for the future: if Cloudflare-level gated self-service wildcards are ever
  built, adopt a pinned-snapshot PSL crate (deliberate/reviewable updates over auto-syncing; speed is
  irrelevant at declare-time) behind a `RegistrableDomain` port in `router-core`, keeping PSL out of
  the `resolve()` hot path.
- **Isolation**: N/A now; future `RegistrableDomain` port at the declare/write boundary.

### Decision: Depth entitlement / plan-tier gating — not built (out of scope)

- **Status**: approved
- **Why**: There are no wildcard-depth tiers at the Shopify/Wix/WordPress level this change targets,
  so there is nothing to gate.
- **Considered**: Build a new depth gate now (rejected — no feature to gate). Recorded for the future:
  if depth tiers are wanted, **Extend** the existing N2 declare-time plan-quota gate
  (`ROUTING_PLAN_LIMITS`, `402 quota_exceeded`) with a max-wildcard-depth dimension rather than build a
  second gate, keeping enforcement at write-time so `resolve()` stays plan-free.
- **Isolation**: future — the existing `ROUTING_PLAN_LIMITS` config + `/domains/declare` handler.

## Risks / Trade-offs

- **[Ratifying behavior that could still have a latent bug]** → The guard tests are written against
  the *intended* contract (apex ≠ wildcard, exact > wildcard, single-label depth, `/authorize` parity),
  not merely to mirror current output, so a pre-existing deviation would surface as a failing test
  rather than be silently blessed.
- **[Spec constrains a future gated-wildcard tier]** → The single-label and no-multi-label
  requirements are stated as the *current* contract; a future tier would land as an explicit spec
  delta (and the composite `(domain, is_wildcard)` schema already forward-provisions it), so this is a
  deliberate scoping line, not a bridge burned.
- **[Perceived low value — "just spec + tests"]** → Accepted: the value is closing an
  undocumented/untested state on a routing + cert-auth security boundary, which is exactly where silent
  drift is most costly.

## Migration Plan

No deployment or data migration. Spec and tests only; production code and schema are untouched, so
there is nothing to roll back beyond reverting the commit.

## Open Questions

None. The two policy questions raised during exploration (depth-measurement rule, downgrade
semantics) are deferred with the gated-wildcard tier and are not part of this change.
