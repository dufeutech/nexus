## Why

Boxes (e.g. `evenout`) have offloaded membership/authorization to nexus: they no longer
double-check whether a caller belongs to a workspace. That makes **existence-hiding**
nexus's job — the 404-vs-403 nuance that avoids revealing whether a workspace exists to a
caller who isn't a member. Today the identity sidecar returns a **blanket 403**
(`forbidden_403`) when route requirements aren't satisfied, which can leak existence
(403 "you may not" vs 404 "no such thing" are distinguishable). This was deliberately
deferred from `sign-identity-contract-jwt` because it is behavioral authz with a different
risk profile than signing.

## What Changes

- nexus owns the **404-vs-403 decision** at the identity/edge boundary: a caller who is not
  an authorized member of a workspace SHOULD be unable to distinguish "forbidden" from
  "does not exist" for workspaces they have no relationship with.
- The response must not leak existence through **status code, body shape, timing, or
  headers** — the hiding has to be uniform across those channels.
- Preserve the box's backstop: a box still rejects a body `workspace_id` that disagrees with
  `x-workspace-id`, without leaking.

## Capabilities

### New Capabilities
- `identity-existence-hiding`: the observable rule for when nexus returns not-found vs
  forbidden vs authorized, such that a non-member cannot infer a workspace's existence.
  Critical concern (correctness/security): the **non-leaking** guarantee across status,
  body, timing, and headers is the thing to get right — a partial implementation that hides
  the status but leaks via latency or error shape is a defect.

### Modified Capabilities
- `identity-workspace-authz` (likely): the current blanket-403 behavior on unsatisfied
  requirements becomes existence-aware. Confirm during specs whether this is a modification
  here or fully owned by the new capability.

## Impact

- **Code:** `identity-rs/sidecar` (`forbidden_403` / the enrich decision path); possibly the
  edge routing for the 404 shape.
- **Contract/docs:** `docs/box-consumer-contract.md` (§ on who owns existence-hiding),
  `nexus-upstream-requirements.md`.

## Resolved decisions (from `/opsx:explore` + `/opsx:decide`)

1. **Boundary (Q1) — implicit default-deny with explicit opt-out.** Any request carrying an
   authoritative workspace context requires membership: a non-member SHALL receive a 404,
   regardless of whether the route declares role/entitlement requirements. Public /
   pre-membership routes (invite-accept, public read) must **explicitly** opt out of the
   membership gate; a route that omits the opt-out is gated (fail-closed) — a forgotten marker
   denies rather than leaks. Chosen because boxes no longer double-check membership, so the
   guarantee must live at the sidecar, not in route-config discipline.
2. **Timing (Q2) — structural equal-work convergence, no constant-time mechanism.** Outsider-403
   and nonexistent-404 are the same branch doing the same work (`resolve_membership → None`), so
   timing converges by construction; the decision compares no secret. Sub-millisecond network
   timing is explicitly out of v1 scope (documented, not mitigated with weak measures).
3. **404 shape ownership (Q3) — the sidecar authors both the 404 and the 403,** byte-identical
   minimal envelope (mirroring `forbidden_403()`); outsiders never reach a box, so there is no
   cross-envelope comparison to leak through.

> Full rationale and the build-vs-adopt gate results are in `design.md`.

> **Coordination:** this change edits the sidecar enrich path shared with `normalized-principal`,
> `workspace-plan-tier`, and `customer-api-keys`. It **owns the unresolved/forbidden branch
> (404-vs-403)** and adds **no contract claim**. Sync order and edit-region ownership are recorded
> canonically in `normalized-principal/design.md` **ADR-10**.
