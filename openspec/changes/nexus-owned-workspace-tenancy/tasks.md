# Tasks — nexus-owned-workspace-tenancy

> Large, BREAKING change. Run `/opsx:decide` first (membership-storage strategy is
> draft). Sequence to keep the running edge coherent: schema + control plane first,
> then identity-plane resolution, then the header/edge rename as the cut-over.

## 0. Decide

- [x] 0.1 `/opsx:decide` done: authz mechanism = **Extend the identity plane behind a
  `MembershipResolver` port** (v1 adapter = denormalized-into-Profile lookup; adopt
  OpenFGA/SpiceDB later only if nexus needs resource-level/graph authz); ownership +
  workspace store = **Extend the existing Postgres store**. See design.md Decisions.
- [ ] 0.2 Still open (settle in apply): the non-member policy per surface (reject vs
  self-signup-as-customer vs anonymous).

## 1. Data model & stores

- [ ] 1.1 Rename routing `tenant_id → workspace_id` (store column, indexes, queries,
  `TenantConfig`→`WorkspaceConfig`, `domains.tenant_id`→`workspace_id`). Domains stay
  many-to-one onto `workspace_id`.
- [ ] 1.2 Add `accounts` (id, name, payer/billing ref) + `account_members`
  (account_id, user_sub, role; owner-only in v1) + `workspace.account_id`.
- [ ] 1.3 Add `memberships` (user_sub, workspace_id, type: staff|customer, role,
  status) as the authz source of record.
- [~] 1.4 `Profile`: added the `memberships` projection (identity-core) + kept the
  reconciler from authoring/clobbering it (`differs` excludes it; TODO on the write
  path to PRESERVE memberships once CRUD populates them). Still to do: `home_org`
  (defer to the header cut-over) and wiring membership CRUD into the change feed.

## 2. Control plane (management surface, not hot path)

- [ ] 2.1 Account provisioning: auto-create a 1-member account on first signup.
- [ ] 2.2 Workspace CRUD keyed by `workspace_id`; `/tenants*` → `/workspaces*`.
- [ ] 2.3 Membership CRUD (grant/revoke staff & customer, role changes).
- [ ] 2.4 Transfer op: repoint `workspace.account_id` (+ reset staff); assert
  workspace_id/domains/customers/data untouched.

## 3. Identity plane (the live authz resolution)

- [x] 3.1 Defined the `MembershipResolver` port + the v1 resolution logic in
  `identity-core` (`membership.rs`: `MemberType`, `Membership`, `ResolvedMembership`,
  `MembershipResolver`; `Profile::resolve_membership` fail-closed) with unit tests.
  (Wiring the store-backed adapter into the sidecar hot path lands with 3.2.)
- [ ] 3.2 `enrich_response`: emit `x-workspace-id` (authoritative), `x-user-type`,
  `x-user-role` (workspace-scoped), `x-user-id`; drop the fixed `x-user-org` (→
  `home_org` informational only). Unit tests for the member/non-member/typed matrix.

## 4. Header contract & edge

- [ ] 4.1 Retire `x-tenant-*`; add `x-workspace-id`/`x-user-type`/`x-user-role` to the
  emitted set and to the C3 strip family (+ treat `x-requested-workspace` as a hint).
  Update every Envoy edge/compose/Helm config (strip lists + any `x-tenant-*` refs).
- [ ] 4.2 Reconcile with the shipped auth-gate wiring (the gate keys on
  `x-auth-required`; ensure the rename/strip changes don't regress it).

## 5. Migration

- [ ] 5.1 Backfill: one account per existing owner; one `staff` membership per user for
  their `org_id`'s workspace; `tenant_id → workspace_id` data migration.
- [ ] 5.2 Cut-over plan for the header rename (data-plane contract change coordinated
  with the running edge).

## 6. Verify

- [ ] 6.1 Both workspaces: clippy `--all-targets --locked` 0-deny, cargo-deny, tests
  (identity-rs needs `PROTOC`).
- [ ] 6.2 Real edge test (extend the Envoy harness): member → authoritative
  `x-workspace-id`+role reaches the backend; non-member → fail-closed; forged
  `x-workspace-id`/`x-user-type` on a non-member request → stripped, no access.
- [ ] 6.3 Transfer test: repoint account_id; confirm routing + customer memberships +
  data intact.

## Out of scope (do NOT do here)

- Staff multi-workspace console / cross-workspace switch UI.
- Account admin/billing roles beyond owner.
- Any ZITADEL org/grant usage (ZITADEL stays authentication-only).
