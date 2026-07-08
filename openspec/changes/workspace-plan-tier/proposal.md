## Why

Boxes drive storage-cap / feature policy from the workspace **plan tier** (e.g. `free`,
`pro`), delivered as `x-workspace-plan`. Today that header has **no producer**: nexus has no
plan/tier concept in its data model (only entitlements), the sidecar never authors it, and
the edge only *strips* it. The `sign-identity-contract-jwt` change reserved a `plan` claim
in the signed contract but left it unpopulated. This change gives the plan tier a real home
and a producer, then populates both the header and the reserved claim.

## What Changes

- Introduce a workspace **plan tier** as a first-class, nexus-resolved attribute of the
  acting workspace.
- Author `x-workspace-plan` on enriched requests, sourced live (like the other nexus-authored
  facts), and populate the reserved `plan` claim in the signed `x-identity-contract`.
- Absent/unknown plan remains a defined, safe state (boxes already treat it as
  not-provisioned) — so partial rollout fails closed on provisioning, not open.

## Capabilities

### New Capabilities
- `workspace-plan-tier`: the observable behavior of resolving and emitting a workspace's plan
  tier. Critical concern (correctness): the plan must be **live/revocation-consistent** with
  the rest of the acting-scope resolution (a downgrade/upgrade takes effect promptly, like
  membership and suspension), and it must be nexus-authored (never client- or token-asserted).

### Modified Capabilities
- `identity-contract-signing`: flip the `plan` claim from reserved to populated (no shape
  change — a value appears where it was omitted).
- `nexus-native-authorization` or `workspace-tenancy` (TBD): plan tier likely belongs with
  the workspace/tenancy facts nexus already authors; confirm which capability owns it.

## Impact

- **Data model / store:** where the plan tier lives (workspace record? billing projection?)
  and how it is written — the main open question below.
- **Code:** `identity-rs/core` (the workspace/plan attribute + resolver), `identity-rs/sidecar`
  (author `x-workspace-plan` + set the `plan` claim), possibly `authz-admin` or a billing
  projection as the writer.
- **Contract/docs:** `docs/box-consumer-contract.md` (`x-workspace-plan` gains a producer),
  the signing docs (`plan` now populated).

## Open questions (resolve in `/opsx:explore` → `/opsx:decide` before implementing)

1. **Source of truth for plan** — is plan an attribute nexus stores on the workspace, or a
   projection of an external billing system? This decides the writer and the freshness model.
2. **Vocabulary** — the set of plan tiers and their mapping to box policy (is it an open
   string, or an enum nexus owns?).
3. **Relationship to entitlements** — plan tier vs. the existing `x-user-entitlements`: is
   plan a coarse label that *derives* entitlements, or an independent axis? Avoid two
   overlapping authorization inputs.

> Status: **proposal only.** Run `/opsx:explore workspace-plan-tier` first — the data-model
> question (source of truth) genuinely blocks a good design and should not be guessed.

> **Coordination:** this change shares `identity-contract-signing` and the sidecar enrich path with
> `normalized-principal`, `identity-existence-hiding`, and `customer-api-keys`. It **owns only the
> `plan` claim**. Sync order and claim ownership are recorded canonically in
> `normalized-principal/design.md` **ADR-10**.
