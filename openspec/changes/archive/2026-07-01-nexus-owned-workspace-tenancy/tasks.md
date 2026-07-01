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
- [x] 4.3 Versioned `x-identity-contract` stamp (see design.md Decision + the
  `identity-workspace-authz` / `edge-auth-gate` deltas). DONE: the identity sidecar
  emits `x-identity-contract: v1` (new `IDENTITY_CONTRACT_VERSION` const) on EVERY
  enriched path — member, non-member, profile-miss, anonymous — authored in `set`
  (OverwriteIfExistsOrAdd), so it is order-independent and needs no `remove` entry.
  Added `x-identity-contract` to the C3 strip family in all 5 Envoy configs
  (`edge/envoy.yaml`, `deploy/compose/envoy/envoy.yaml`, and the routing-plane /
  identity-plane / edge-platform Helm `edge-configmap.yaml`s), grouped with
  `x-auth-required` as a trusted-emitted unforgeable header. The consuming backend/box
  requiring a version it accepts (+ rejecting absent/unrecognized, and treating a `v1`
  request missing the authoritative `x-workspace-id`/`x-user-type` as invalid) is the
  cross-repo counterpart — out of this repo. NOTE: `v1` is the shared cross-repo
  contract number; coordinate with the box before bumping. Verify: identity-sidecar
  clippy `--all-targets` 0-deny + 9 tests green (new
  `contract_stamp_is_emitted_on_every_enriched_path`); both plain Envoy YAMLs parse;
  all 3 Helm charts render exactly one `x-identity-contract` strip.

## 5. Migration

- [x] 5.1 Backfill: one account per existing owner; one `staff` membership per user for
  their `org_id`'s workspace; `tenant_id → workspace_id` data migration. DONE: the
  `tenant_id → workspace_id` **data** migration is the guarded in-place `ALTER … RENAME`
  in `init_schema` (task 1.1). Added the **account backfill** to `init_schema` (idempotent,
  guarded on `account_id IS NULL`): every workspace migrated from the old single-org
  `tenants` shape gets a solo owning account keyed by its `workspace_id` (the old model was
  one owner per tenant/workspace, so 1:1 is faithful; this is the "personal" account the UI
  presents). The **user→`staff`-membership seed is NOT a routing-side ETL** — the routing
  schema holds no user roster; like the identity `Profile` projection it is a rebuildable,
  broker-seeded native CRUD write (see MIGRATION.md's "no ETL" model + design.md Migration).
  Verified against a throwaway Postgres:
  `init_schema_backfills_a_solo_account_for_an_ownerless_workspace` (ownerless legacy row →
  auto-owned + idempotent on a second pass) — `store-postgres` integration suite green.
- [x] 5.2 Cut-over plan for the header rename (data-plane contract change coordinated
  with the running edge). MECHANISM: the versioned `x-identity-contract` stamp (4.3) is
  the coordination gate — bump the version when the header shape changes so a
  half-deployed rename fails closed rather than being silently misread by the backend.
  DONE: wrote the ordered **Cut-over sequence** in design.md (Migration section) — a
  single coordinated cut (pre-production, per MIGRATION.md's rebuildable-projection
  model): (1) schema+account-backfill on startup, wire name still `x-tenant-*`; (2) seed
  memberships (native CRUD, not ETL) BEFORE flipping surfaces protected; (3) roll the
  sidecar+router emit to `x-workspace-*` and stamp `v1` (the sidecar reads either header
  name mid-roll); (4) roll the edge C3 strips (3→4 safe: stripped-not-authored = absent =
  fail-closed); (5) backend requires `v1`, bump the version on any future shape change.
  Rollback = `git revert` (no live data rollback — rebuildable projection).

## 6. Verify

- [x] 6.1 Both workspaces: clippy `--all-targets --locked` 0-deny, cargo-deny, tests
  (identity-rs needs `PROTOC`). DONE 2026-07-01: routing-rs clippy+tests+deny green;
  identity-rs clippy+deny green, 35 tests pass (PROTOC=libprotoc 35.0).
- [x] 6.2 Real edge test (extend the Envoy harness): member → authoritative
  `x-workspace-id`+role reaches the backend; non-member → fail-closed; forged
  `x-workspace-id`/`x-user-type` on a non-member request → stripped, no access.
  Also assert the contract stamp (4.3): enriched request carries `x-identity-contract: v1`;
  a client-supplied `x-identity-contract` is stripped; a request bypassing the edge lacks
  it and the backend rejects. DONE: new `scripts/tenancy-edge-e2e.sh` (extends
  `scripts/n4-e2e.sh`; asserts against the `traefik/whoami` backend, which echoes the
  headers it received). **Ran LIVE against the real `docker compose` edge (Envoy +
  tenant-router + identity-sidecar), 8/8 green:** the contract stamp reaches the backend
  as `v1` even when the client sends `x-identity-contract: vFORGED` (stripped + re-
  authored); client-forged `x-workspace-id`/`x-user-type`/`x-user-role` on a non-member
  are stripped (backend sees `<none>`); public route → 200 pass-through; protected route →
  401 fail-closed (non-member can't reach the backend). The POSITIVE **member** path
  (authoritative scope from a live membership) requires a ZITADEL-minted JWT + a seeded
  membership Profile — layered onto the same script via a bearer token (procedure in
  design.md's cut-over section); its authoring logic is unit-covered by the sidecar tests
  (`member_gets_authoritative_workspace_scope`, `member_type_and_role_are_workspace_
  scoped`). The backend's reject-on-absent-stamp is the consuming box's contract (cross-
  repo), not nexus-emitted. NOTE: `init_schema` (incl. the §5.1 account backfill) also ran
  clean inside the containerized control-plane against its Postgres.
- [x] 6.3 Transfer test: repoint account_id; confirm routing + customer memberships +
  data intact. DONE: new `routing-rs/store-postgres/tests/integration.rs` (gated on
  `STORE_PG_TEST_URL`, mirroring identity-rs). `transfer_repoints_ownership_and_resets_
  staff_only` seeds a workspace owned by `acct_old` with a verified domain + one staff +
  one customer membership, transfers to `acct_new`, and asserts: `staff_removed == 1`,
  `account_id` repointed, the domain still resolves the workspace (routing intact), and
  ONLY the customer membership survives. `transfer_of_unknown_workspace_is_none` covers
  the clean-404 path. Verified end-to-end against a throwaway Postgres 16 (3/3 green).

## Out of scope (do NOT do here)

- Staff multi-workspace console / cross-workspace switch UI.
- Account admin/billing roles beyond owner.
- Any ZITADEL org/grant usage (ZITADEL stays authentication-only).
