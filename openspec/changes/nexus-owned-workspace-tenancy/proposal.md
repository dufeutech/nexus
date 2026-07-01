## Why

nexus is single-org today: a user's `Profile.org_id` is a fixed **home org**, emitted
as `x-user-org`, and the routing plane's `tenant_id` is derived from the request
domain. Neither models the product we want: a user is a member of **many
workspaces** and acts in one at a time, in one of two capacities — **staff** (they
operate the workspace) or **customer** (they use its app). Authorization for "which
workspace may this user act in, and as what" is live, per-request state that must be
owned by nexus, not baked into a token and not delegated to the IdP. ZITADEL should
authenticate (prove `sub`, login/MFA/session) and nothing more.

## What Changes

- **Ownership model (nexus-owned).** Introduce **Account** (a member-container; a
  solo user is a 1-member account presented as "personal") that **owns** one or more
  **Workspaces**. A Workspace is the stable-ID pivot (= today's routing "tenant",
  = the product's "project"); **domains are many-to-one aliases onto a
  `workspace_id`**, never the key. Ownership is a mutable `workspace.account_id`, so
  **sell/transfer is a one-field repoint** (also the SMB→enterprise path).
- **Typed memberships (the new authz layer).** `Membership(user_sub, workspace_id,
  type: staff|customer, role)`. The identity plane resolves `(sub, workspace)` →
  membership **live** and **fail-closed**, and emits the authoritative acting scope.
- **Header contract redesign.** Retire the ambiguous `x-tenant-*`. Emit
  `x-workspace-id` (authoritative, nexus-resolved), `x-user-type` (staff|customer),
  `x-user-role` (workspace-scoped), `x-user-id`. The backend trusts these opaquely
  and flips staff-mode vs customer-mode on `x-user-type`. Client copies are
  edge-stripped (C3); a client may *hint* a workspace but never *assert* one.
- **BREAKING — rename `tenant_id` → `workspace_id`** across the routing store, the
  control-plane API, the `x-tenant-*` headers, and the shipped auth-gate wiring.
- **ZITADEL becomes authentication-only.** Memberships are nexus-native CRUD (like
  the control-plane's domain lifecycle), NOT synced from ZITADEL orgs/grants. The
  reconciler keeps syncing *users* (identity); it no longer sources tenancy.
- Migration: `Profile.org_id` (home org) → seed a `staff` membership per existing
  user for their org's workspace; keep `home_org` as informational/default only.

## Capabilities

### New Capabilities
- `workspace-tenancy` — the ownership + addressing model: Account owns Workspace,
  Workspace is a stable-ID unit, domains resolve many-to-one to a `workspace_id`,
  ownership is transferable by repointing, plan lives on the workspace and the payer
  on the account. Critical concern (correctness/reliability): the **transferable
  ownership store** and the **domain→workspace resolution** — build-vs-adopt to be
  recorded in `/opsx:decide` (this extends the existing routing store).
- `identity-workspace-authz` — the identity plane resolves `(sub, workspace)` to a
  typed membership and emits the authoritative acting scope, live and fail-closed.
  Critical concern (security): the **live membership authorization** on the hot path
  — build-vs-adopt in `/opsx:decide` (this extends the existing identity/sidecar
  resolution + push cache).

### Modified Capabilities
- `edge-auth-gate` — the auth gate's header contract changes (`x-tenant-*` →
  `x-workspace-id`/`x-user-type`/`x-user-role`), and the C3 strip list gains the
  `x-workspace-id`/`x-requested-workspace` family. A delta spec updates the
  unforgeability/strip requirement to the new header names.

## Impact

- **Data model & stores:** new Account / Workspace / Membership schema; the routing
  `tenant_id` column and API rename to `workspace_id`; `Profile` grows a
  `memberships` projection (denormalized for the hot path) and `home_org`.
- **Identity plane:** sidecar `enrich_response` resolves and emits the workspace
  scope + `x-user-type` + workspace-scoped role instead of the fixed `x-user-org`.
- **Control plane:** new membership + account/workspace CRUD; transfer operation.
- **Edge configs:** header-strip and any `x-tenant-*` references across the Envoy
  edge/compose/Helm configs update to the new header names.
- **Security-sensitive & BREAKING:** the header rename and the fail-closed
  membership gate change the trust contract with the backend; migration must seed
  memberships so existing users keep access.
- Out of scope: the staff multi-workspace *console* (cross-workspace switching UI),
  org-account admin/billing roles beyond the owner (additive later), and any ZITADEL
  org/grant usage.
