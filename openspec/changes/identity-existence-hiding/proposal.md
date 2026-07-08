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

## Open questions (resolve in `/opsx:explore` → `/opsx:decide` before implementing)

1. **Where is the boundary drawn** — does nexus 404 for *any* non-member, or only when the
   workspace genuinely doesn't exist vs. exists-but-not-a-member? (The latter is harder to
   hide and may need a uniform 404 for both.)
2. **Timing/side-channel** — is constant-time / uniform-latency treatment in scope, or is
   status+body uniformity enough for v1? (Adopt vs build for any constant-time comparison.)
3. **404 shape ownership** — sidecar `ImmediateResponse` vs the edge. Does the box see a
   nexus-authored 404, or does the edge synthesize it?

> Status: **proposal only.** Run `/opsx:explore identity-existence-hiding` (or
> `/opsx:propose` to regenerate full artifacts) to take it forward — the design turns on the
> open questions above.

> **Coordination:** this change edits the sidecar enrich path shared with `normalized-principal`,
> `workspace-plan-tier`, and `customer-api-keys`. It **owns the unresolved/forbidden branch
> (404-vs-403)** and adds **no contract claim**. Sync order and edit-region ownership are recorded
> canonically in `normalized-principal/design.md` **ADR-10**.
