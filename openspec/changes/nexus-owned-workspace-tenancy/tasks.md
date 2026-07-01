# Tasks — nexus-owned-workspace-tenancy

> Large, BREAKING change. Run `/opsx:decide` first (membership-storage strategy is
> draft). Sequence to keep the running edge coherent: schema + control plane first,
> then identity-plane resolution, then the header/edge rename as the cut-over.

## 0. Decide

- [x] 0.1 `/opsx:decide` done: authz mechanism = **Extend the identity plane behind a
  `MembershipResolver` port** (v1 adapter = denormalized-into-Profile lookup; adopt
  OpenFGA/SpiceDB later only if nexus needs resource-level/graph authz); ownership +
  workspace store = **Extend the existing Postgres store**. See design.md Decisions.
- [x] 0.2 Non-member policy per surface — **derived from the route auth policy** (N4),
  not a separate knob: anonymous pass-through on public routes, fail-closed 403 on
  protected routes; self-signup out of scope for the edge. See design.md Decisions.

## 1. Data model & stores

- [x] 1.1 Rename routing `tenant_id → workspace_id` (store column, indexes, queries,
  `TenantConfig`→`WorkspaceConfig`, `domains.tenant_id`→`workspace_id`). Domains stay
  many-to-one onto `workspace_id`. DONE: `router-core` types (`WorkspaceConfig`,
  `RoutingDecision.workspace_id`, `DomainRecord.workspace_id`) + `RoutingStore` port
  methods (`get_workspace`/`upsert_workspace`/`domains_for_workspace`/
  `count_domains_for_workspace`, `workspace_id` params) + the Postgres adapter
  (`routing.tenants`→`workspaces`, every `tenant_id` column, all SQL) + the
  `tenant-router` hot path. Ships a guarded, idempotent in-place `ALTER … RENAME`
  migration for pre-provisioned DBs (no migration framework here). DEFERRED by design:
  the `x-tenant-*` **wire header names** (→ 4.1 cut-over; internal field renamed, name
  held), the `/tenants*` **HTTP paths** + `tenant_id` **JSON body/response fields**
  (→ 2.2; a migration seam maps `body.tenant_id`→`WorkspaceConfig.workspace_id` in the
  control plane), and the `tenant-router` **crate name** (separate decision).
- [x] 1.2 Add `accounts` (id, name, payer/billing ref) + `account_members`
  (account_id, user_sub, role; owner-only in v1) + `workspace.account_id`. DONE:
  DDL in `PgRoutingStore::init_schema` (accounts before workspaces for the FK;
  `account_id` is a plain reference, NOT cascade, so deleting an owning account
  fails — transfer first). `ADD COLUMN IF NOT EXISTS account_id` backfills a
  migrated `workspaces`. Rust CRUD (provisioning/transfer) is stage 2.
- [x] 1.3 Add `memberships` (user_sub, workspace_id, type: staff|customer, role,
  status) as the authz source of record. DONE: DDL in `init_schema`
  (`member_type` CHECK-constrained to staff|customer, PK `(user_sub, workspace_id)`,
  cascades with its workspace). Membership CRUD + hot-path resolution wiring is
  stages 2.3 / 3.2.
- [~] 1.4 `Profile`: added the `memberships` projection (identity-core) + kept the
  reconciler from authoring/clobbering it (`differs` excludes it; TODO on the write
  path to PRESERVE memberships once CRUD populates them). Still to do: `home_org`
  (defer to the header cut-over) and wiring membership CRUD into the change feed.

## 2. Control plane (management surface, not hot path)

> Ports: added `OwnershipStore` (accounts + members + workspace ownership/transfer)
> and `MembershipStore` (membership CRUD) in `router-core` — split OUT of the
> hot-path `RoutingStore` so the resolver's port stays lean — both impl'd by
> `PgRoutingStore`. Control plane holds the concrete store so it calls all three.
> IDs are caller-supplied (trusted-broker model, matching today's `tenant_id`).

- [x] 2.1 Account provisioning: `POST /accounts` (idempotent) creates the account +
  its `owner` member; safe to call unconditionally on first signup. `GET
  /accounts/{id}` returns the account + members. The *trigger* (calling it on
  signup) is the broker/identity's job — the control plane exposes the idempotent
  op.
- [x] 2.2 Workspace CRUD keyed by `workspace_id`: `POST /workspaces`
  (`WorkspaceBody{workspace_id, account_id?, plan, target_pool, features}`; pool
  allow-list validated; unknown `account_id` → clean 404; create-time ownership via
  `set_workspace_account`; invalidates the workspace's domains), `GET
  /workspaces/{id}`, plus `/workspaces/{id}/auth-routes` reusing the auth-route
  handlers. `/tenants*` KEPT as **deprecated account-less aliases** (frozen for the
  running broker/e2e; removed in a later archive step) rather than a hard break —
  the non-breaking cut-over the change emphasizes.
- [x] 2.3 Membership CRUD: `PUT /workspaces/{id}/members`
  (`MembershipBody{user_sub, member_type∈{staff,customer}, role, status}`;
  `member_type` validated against `MEMBER_TYPES` + DB CHECK; unknown workspace →
  clean 404), `DELETE /workspaces/{id}/members/{sub}`, `GET
  /workspaces/{id}/members`. Writes the source-of-record row; propagation to the
  identity `Profile` projection is the change-feed wiring (stage 1.4 remainder / 3.2)
  — no routing invalidation (membership isn't in the routing decision).
- [x] 2.4 Transfer op: `POST /workspaces/{id}/transfer` (`{account_id}`) →
  `OwnershipStore::transfer_workspace` repoints `account_id` AND resets **staff**
  memberships in ONE Postgres transaction (a half-applied transfer can't leave the
  old owner's staff with access). Target account must exist (clean 404); unknown
  workspace → 404. `workspace_id`, domains, data, and **customer** memberships ride
  through untouched. Returns `staff_removed`.

> Verify note: clippy `--all-targets` 0-deny + 43 tests green. Runtime smoke of the
> new endpoints needs a throwaway Postgres (deferred to §6); no DB-free unit tests
> were added (the handlers are integration-level).

## 3. Identity plane (the live authz resolution)

- [x] 3.1 Defined the `MembershipResolver` port + the v1 resolution logic in
  `identity-core` (`membership.rs`: `MemberType`, `Membership`, `ResolvedMembership`,
  `MembershipResolver`; `Profile::resolve_membership` fail-closed) with unit tests.
  (Wiring the store-backed adapter into the sidecar hot path lands with 3.2.)
- [x] 3.2 `enrich_response` (`identity-sidecar`): now takes the acting workspace and
  authors the live-resolved acting scope. Emits `x-workspace-id` (authoritative),
  `x-user-type`, `x-user-role` (workspace-scoped) ONLY when
  `Profile::resolve_membership(ws)` matches — sourced from the live Profile, never
  the token, so a revoked membership takes effect within seconds. `x-user-id` was
  already emitted. **`x-user-org` retired**: never authored, always stripped (the
  fixed home org is no longer an authz input; `home_org` stays deferred to 1.4 as
  informational-only). The plural `x-user-roles` (coarse token/profile roles) is
  kept alongside the new singular workspace-scoped `x-user-role`.
  - **Acting workspace input**: read from the trusted routing header via new
    `extract_acting_workspace` — prefers `x-workspace-id` (post-4.1 name), falls
    back to the routing plane's current `x-tenant-id`, so it works across the header
    cut-over. `handle` now plumbs the `RequestHeaders` payload (previously dropped as
    `_`) into enrich.
  - **Non-member = fail-closed (decision, not 503)**: `resolve_membership` → `None`
    (non-member, absent profile, or no resolved workspace) authors NO scope and
    STRIPS any forged `x-workspace-id`/`x-user-type`/`x-user-role`, so a client can
    never smuggle an acting scope past the sidecar. The reject-vs-anonymous-vs-signup
    choice for a non-member is left to the backend/surface (open question 0.2). The
    existing `Unavailable` → 503 (can't-decide) path is unchanged.
  - Tests: member(staff)/member(customer)/non-member matrix + authored-not-stripped +
    the `extract_acting_workspace` precedence/empty cases; updated the
    defense-in-depth + suspension tests for the new signature and retired `x-user-org`.
    identity-rs: clippy `--all-targets` 0-deny + 35 tests green (protoc NOT needed —
    envoy-types ships pre-generated, no build.rs).

## 4. Header contract & edge

- [x] 4.1 Retire `x-tenant-*`; add `x-workspace-id`/`x-user-type`/`x-user-role` to the
  emitted set and to the C3 strip family (+ treat `x-requested-workspace` as a hint).
  DONE: tenant-router `route_response` now emits `x-workspace-id`/`x-workspace-plan`/
  `x-workspace-features` (was `x-tenant-*`); the identity sidecar already authors
  `x-user-type`/`x-user-role` (3.2). Every Envoy C3 strip list updated across all 5
  configs (`edge/envoy.yaml`, `deploy/compose/envoy/envoy.yaml`, and the routing-plane
  / edge-platform / identity-plane Helm `edge-configmap.yaml`s): renamed the three
  `x-tenant-*` strips → `x-workspace-*` and ADDED `x-user-type`/`x-user-role` (and
  `x-workspace-id` to the identity-plane list). `x-requested-workspace` is deliberately
  NOT stripped — it stays an allowed non-authoritative hint (v1 consumes nothing; the
  authoritative `x-workspace-id` is what's stripped+re-authored). Access-log keys
  (`tenant_id`→`workspace_id`, sourcing `X-WORKSPACE-ID`), filter-order comments, and
  the two NOTES.txt smoke-test greps updated; `x-user-org` retired in the
  identity-plane NOTES.
  - **Header handoff (the resolved-`x-workspace-id` collision, by design)**: filter
    order is C3-strip → tenant-router → jwt_authn → identity-sidecar → router. The
    router PROPOSES `x-workspace-id` (the domain's resolved workspace); the sidecar,
    running after, OVERWRITES it authoritatively for a member or STRIPS it for a
    non-member — so the value the backend sees is always membership-authorized. The
    sidecar's `x-tenant-id` fallback (3.2) is kept for mid-rollout compat.
- [x] 4.2 Reconcile with the shipped auth-gate wiring: `x-auth-required` emit
  (tenant-router), strip (every C3 list), and jwt_authn branch are UNTOUCHED — the
  rename only moved `x-tenant-*` and the additions are new strip entries, so the N4
  gate is preserved. Verified: routing-rs clippy `--all-targets` 0-deny + 43 tests;
  `helm lint` + `helm template` clean on all three charts (routing-plane,
  identity-plane, edge-platform umbrella — the only template failures were
  pre-existing required-value guards: postgres.url / patSecret / control-auth token);
  both plain-YAML Envoy configs parse. Caught+fixed a Go-template pitfall: `x-user-*/`
  inside the umbrella's `{{/* */}}` comment closed it early.

## 5. Migration

- [ ] 5.1 Backfill: one account per existing owner; one `staff` membership per user for
  their `org_id`'s workspace; `tenant_id → workspace_id` data migration.
- [ ] 5.2 Cut-over plan for the header rename (data-plane contract change coordinated
  with the running edge).

## 6. Verify

- [x] 6.1 Both workspaces: clippy `--all-targets --locked` 0-deny, cargo-deny, tests
  (identity-rs needs `PROTOC`). DONE 2026-07-01: routing-rs clippy+tests+deny green;
  identity-rs clippy+deny green, 35 tests pass (PROTOC=libprotoc 35.0).
- [ ] 6.2 Real edge test (extend the Envoy harness): member → authoritative
  `x-workspace-id`+role reaches the backend; non-member → fail-closed; forged
  `x-workspace-id`/`x-user-type` on a non-member request → stripped, no access.
- [ ] 6.3 Transfer test: repoint account_id; confirm routing + customer memberships +
  data intact.

## Out of scope (do NOT do here)

- Staff multi-workspace console / cross-workspace switch UI.
- Account admin/billing roles beyond owner.
- Any ZITADEL org/grant usage (ZITADEL stays authentication-only).
