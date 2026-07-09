## Why

`edge-auth-gate`'s authorization decision — the post-enrichment step that emits **403** unless the
request's injected roles / entitlements / assurance-level satisfy the resolved per-route requirements
— is **hand-coded comparison logic**. For a multi-product platform (per
`openspec/changes/authz-engine-strategy/EXPLORATION.md`), that authorization surface only grows:
per-service entitlements, richer context (geo/residency, suspension), more requirement kinds. Growing
it as bespoke Rust comparisons re-implements a correctness-critical, solved problem and scatters authz
logic across surfaces. This change adopts **a policy decision point (PDP)** as the platform's L2
authorization layer: decisions become **declarative policies-as-data**, deny-by-default and
fail-closed, decoupled from the enforcement surfaces. The first slice is **behavioral parity** with
today's gate — same 401/403/pass outcomes — establishing the L2 seam that future authz work (and,
later, the L3 ReBAC engine) plugs into. The concrete engine is chosen at `/opsx:decide` (the
exploration recorded **Cedar** — Rust-native, policy-as-data, formally analyzable).

## What Changes

- **Introduce a Policy Decision Point (PDP)** — a vendor-agnostic authorization decision boundary that
  evaluates a request's **(principal, action, resource, context)** against declarative policies and
  returns permit/deny **with a reason**, denying by default.
- **Policies are data**, loaded via an adapter, versioned and per-environment — not compiled-in
  comparison code. Changing a policy changes decisions without a code change.
- **Re-point `edge-auth-gate`'s requirement-satisfaction step to the PDP.** The role/entitlement/AAL
  (and suspension) comparison that currently yields 403 is computed by evaluating policy, at strict
  behavioral parity: identical outcomes, the same fail-closed semantics (requirement present +
  enrichment absent/unparseable → deny), and `identity-existence-hiding` / 401-vs-403 behavior
  preserved.
- **Sit behind the existing `AuthzResolver`/authz port boundary** so the engine is an adapter swap
  (reversible, matches CLAUDE.md build-vs-adopt).
- **Explicitly unchanged (this slice):** the per-route `auth_routes` rule *resolution*
  (longest-prefix path → requirement signals) stays as tenant-authored data that supplies decision
  **context** — it is NOT folded into policies here. Path canonicalization, client-header stripping,
  fail-safe signal handling, and credential verification are untouched.
- **Non-goals:** OpenFGA / L3 resource-level ReBAC (parked, coupled to the multi-region DB fork);
  moving tenant route rules into policies; adding new requirement kinds or expanding authz scope; the
  commerce/entitlement (L1) plane.

## Capabilities

### New Capabilities
- `authorization-policy-engine`: the platform decides authorization by applying declarative
  policies-as-data to a request's principal/action/resource/context — **deny-by-default**,
  **fail-closed** on missing or unparseable input, each decision carrying an **auditable reason**, and
  a policy change taking effect **as data** (no code change). The decision is **decoupled** from the
  enforcement surface that requests it (the edge gate is its first consumer). This is the L2 seam the
  authz-engine strategy records; it is the correctness-critical concern gated at `/opsx:decide`.

### Modified Capabilities
<!-- None. edge-auth-gate keeps its observable behavior (parity); delegating its decision to the PDP
     is a HOW change recorded in design.md, not a requirement change. -->

## Impact

- **New crate/module:** the PDP adapter (the policy engine) behind the authz port, plus **policy files
  as data** (a `policies/` set loaded via an adapter). New Cargo dependency: the chosen engine crate
  (Cedar, pending `/opsx:decide`).
- **Enforcement call site:** the `edge-auth-gate` requirement-satisfaction step (the Rust component
  that runs after enrichment) calls the PDP instead of comparing headers by hand.
- **Deploy:** policy files shipped per-environment (Helm/compose), loaded at startup + on change.
- **Verification:** parity tests against the current gate's 401/403/pass matrix; policy unit tests;
  fail-closed and existence-hiding behavior re-asserted.
- **Independence:** does not depend on and is not blocked by `b-floor-trust-hardening`. Builds on the
  `authz-engine-strategy` exploration; leaves L3/OpenFGA parked.
