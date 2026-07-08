## Why

Boxes drive storage-cap / feature policy from the workspace **plan tier** (e.g. `free`,
`pro`), delivered as `x-workspace-plan`. The plan **already exists as a first-class,
nexus-owned fact**: `routing.workspaces.plan` (`text NOT NULL DEFAULT 'free'`), written by
the control plane, with a config-driven `router-core::PlanLimits` vocabulary and the payer of
record isolated on `routing.accounts.payer_ref` (vendor-free — Stripe et al. attach only
there, never on the wire). What is missing is only the **cross-plane hop**: the identity
sidecar never projects that plan onto enriched requests, so `x-workspace-plan` has no producer
and the `plan` claim reserved by `sign-identity-contract-jwt` stays unpopulated
(`signer.rs:127` hardcodes `plan: None`). This change adds that projection — nothing more.

## What Changes

- Project the existing routing-plane plan into the identity plane: a read-only
  `WorkspacePlanReader` over `routing.workspaces` (identity already reads `routing.memberships`
  SELECT-only), kept live via LISTEN/NOTIFY like the other nexus-authored facts.
- Author `x-workspace-plan` on enriched requests keyed by the acting `workspace_id`, and
  populate the reserved `plan` claim in the signed `x-identity-contract`.
- Absent/unknown plan remains a defined, safe state (boxes already treat it as
  not-provisioned) — so a resolution miss or store-unavailable case omits the claim and fails
  closed on provisioning, not open. (A provisioned workspace always has at least `'free'`.)
- **Out of scope:** no new schema, no plan writer, no billing/Stripe integration — the plan
  column, its vocabulary, and its write path already ship on the routing plane.

## Capabilities

### New Capabilities
- `workspace-plan-tier`: the observable behavior of resolving and emitting a workspace's plan
  tier. Critical concern (correctness): the plan must be **live/revocation-consistent** with
  the rest of the acting-scope resolution (a downgrade/upgrade takes effect promptly, like
  membership and suspension), and it must be nexus-authored (never client- or token-asserted).

### Modified Capabilities
- `identity-contract-signing`: flip the `plan` claim from reserved to populated (no shape
  change — a value appears where it was omitted). ADDED delta per ADR-10 (owns the `plan` claim).

## Impact

- **Data model / store:** none. Plan already lives on `routing.workspaces.plan` with its write
  path and config-driven vocabulary. This change only adds a SELECT-only identity-side reader.
- **Code:** `identity-rs/core` (a `WorkspacePlanReader` port + resident resolution),
  `identity-rs/store-postgres` (`PgWorkspacePlanReader` — a near-verbatim clone of
  `PgPlatformServiceReader`), `identity-rs/sidecar` (hold the resident snapshot, author
  `x-workspace-plan`, fill `plan: None` at `signer.rs:127`).
- **Contract/docs:** `docs/box-consumer-contract.md` (`x-workspace-plan` gains a producer),
  the signing docs (`plan` now populated).

## Resolved questions (see `design.md` for the decisions)

1. **Source of truth** — RESOLVED: `routing.workspaces.plan`, control-plane-written,
   `DEFAULT 'free'`. Not a billing mirror; the payer/vendor seam is `routing.accounts.payer_ref`
   and never reaches the contract.
2. **Vocabulary** — RESOLVED: open string on the wire (keeps `plan: Option<String>`
   forward-compatible), nexus-owned set via the existing config-driven `PlanLimits`, validated
   at the control-plane write boundary (mirrors the `membership kinds` house pattern).
3. **Relationship to entitlements** — RESOLVED: independent axis. Entitlements are
   subject-scoped on `Profile`; plan is workspace-scoped. No derivation; the box reads both.

> Status: **decided — ready for specs + tasks.** Source-of-truth resolved by existing
> architecture; build-vs-adopt gate passed — *Extend* the in-house LISTEN/NOTIFY projection
> (clone `PgPlatformServiceReader`), recorded in `design.md`.

> **Coordination:** this change shares `identity-contract-signing` and the sidecar enrich path with
> `normalized-principal`, `identity-existence-hiding`, and `customer-api-keys`. It **owns only the
> `plan` claim**. Sync order and claim ownership are recorded canonically in
> `normalized-principal/design.md` **ADR-10**.
