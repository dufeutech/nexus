# Design — nexus-owned-workspace-tenancy

## Context

nexus has two independent "tenant/org" axes today: the routing plane resolves
`domain → tenant_id → pool` (infra), and the identity plane carries `Profile.org_id`
(a fixed home org) → `x-user-org`. Neither models a user who belongs to many
workspaces and acts in one per request as either staff or customer. Ownership must be
nexus-owned and transferable; ZITADEL authenticates only.

```
  Account (member container; solo = 1 member)      ← owns; transfer = repoint account_id
     │ owns
     ▼
  Workspace { id, account_id, plan, pool, features }   ← STABLE-ID pivot (= today's tenant_id, = "project")
     ├─ Domain     { domain, workspace_id }              ← many → one alias (already how routing works)
     └─ Membership { user_sub, workspace_id, type: staff|customer, role }   ← the live authz layer

  data plane (hot): resolve(domain)→W ; resolve(sub,W)→{type,role} ; emit x-workspace-id/x-user-type/x-user-role
  control plane:    Account, ownership/transfer, payer, workspace + membership CRUD
```

## Goals / Non-goals

- **Goal:** nexus owns tenancy + authorization; the identity plane authorizes the
  acting workspace live and fail-closed; the backend trusts opaque headers.
- **Goal:** ownership is transferable as a one-field repoint (also the SMB→enterprise
  path); no data/domain/routing churn on transfer.
- **Non-goal (this change):** the staff multi-workspace *console* (cross-workspace
  switch UI), org account admin/billing roles beyond the owner, any ZITADEL org/grant
  usage.

## Decisions

### Decision: Own authorization in nexus; ZITADEL is authentication-only
- **Status**: approved
- **Why**: "which workspace, as what role" is live, revocation-sensitive state — the
  same reason nexus already sources `is_suspended`/`entitlements` from the live
  Profile, not the token. Coupling tenancy to an IdP's org/grant model would bind the
  product's core domain to an external system and force token re-mints on every
  workspace switch.
- **Considered**: ZITADEL org-scoped tokens/grants (couples tenancy to the IdP;
  re-mint per switch; rejected). A nexus-minted session grant (Strategy 3 below).

### Decision: Ownership is an Account; every account is a member container (no personal|org type)
- **Status**: approved
- **Why**: the `personal|org` type is the classic source of special-casing and the
  painful personal→org *conversion* migration. Making every account a 1..N member
  container removes the branch and the conversion: SMB→enterprise is just "invite more
  members." It is also more consistent with the decoupling — a user is never an owner,
  a user is a *member of* an account that owns workspaces (no person/owner conflation).
- **Considered**: typed `personal|org` (rejected — conversion pain, dual code paths).
  Owner = raw user `sub` (rejected — not durable for enterprise; reintroduces the
  person-is-owner conflation). Segment differences (limits/legal entity) become
  *attributes/flags* on the account, not a structural type.
- **Isolation**: `workspace.account_id` is a plain pointer; solo accounts are
  auto-provisioned on signup and presented as "personal" in the UI (a frontend
  concern; the schema is identical).

### Decision: Workspace is the stable-ID pivot; transfer repoints ownership
- **Status**: approved
- **Why**: keying everything (domains, memberships, customer data, plan) off a stable
  `workspace_id` makes sell/transfer a two-field repoint (`account_id` + reset staff)
  with no routing/DNS/cert churn and the customer base intact. Keying by domain or
  owner would make a transfer a data migration + routing outage.
- **Consequence**: plan lives on the workspace (travels with the sale); the payer of
  record lives on the account (switches on transfer).

### Decision: authorization mechanism — Extend the identity plane behind a `MembershipResolver` port
- **Status**: approved
- **Why**: nexus's authz is a **flat** membership+role point lookup, not a relationship
  graph — the identity plane already resolves it from a push-updated, `sub`-keyed cache
  sub-millisecond and fail-closed at 1B scale. A Zanzibar engine (OpenFGA/SpiceDB) buys
  graph/hierarchical/resource-level authz nexus doesn't need, at 5–20 ms/check plus a
  new stateful service; its power would go unused. Fine-grained authz belongs to the
  backend (it owns the resources) and can adopt an engine there independently.
- **Considered**: Adopt self-hosted OpenFGA/SpiceDB (graph power unused; latency + ops
  tax on a hot path that's currently sub-ms); Rent WorkOS/Clerk tenancy SaaS (holds the
  data — contradicts the approved "nexus owns tenancy" premise).
- **Isolation**: resolution lives behind a `MembershipResolver` port
  (`resolve(sub, workspace) -> {type, role}`). The v1 adapter is the denormalized-
  into-`Profile` lookup (a user belongs to few workspaces; the sub-keyed cache stays a
  single lookup, fail-closed), and membership CRUD rides the existing change feed.
  Swapping to an OpenFGA/SpiceDB adapter later is an adapter change, not a
  re-architecture.
- **Adopt-later trigger**: when nexus itself must answer "can user X perform action A on
  resource R" (not just "is user a member of workspace W"), adopt a ReBAC engine behind
  this same port.

### Decision: ownership + workspace store — Extend the existing Postgres routing store
- **Status**: approved
- **Why**: "Accounts own Workspaces; workspaces have domains and a transferable owner"
  is the product's own domain data — no framework owns that concept. The routing store
  already models `domain → tenant` (many-to-one) in Postgres via `sqlx`; add the
  `accounts` / `memberships` tables and the `tenant_id → workspace_id` rename there.
- **Considered**: Rent a B2B tenancy SaaS (WorkOS/Clerk) — reverses the approved own-it
  scope. A dedicated tenancy microservice — premature; it is a few tables + CRUD.
- **Isolation**: the existing `sqlx`/Postgres store adapter behind the control-plane
  API; transfer is a repoint of `workspace.account_id`.

### Decision: Header contract — retire `x-tenant-*`, emit explicit scope headers
- **Status**: approved
- **Why**: `x-tenant-id` today means "domain owner" (routing); the workspace the
  backend authorizes on is a different value. Emit `x-workspace-id` (authoritative,
  nexus-resolved), `x-user-type` (staff|customer), `x-user-role` (workspace-scoped),
  `x-user-id`. `x-requested-workspace` is a client hint (non-authoritative). All are
  edge-stripped from client input (C3) — see the `edge-auth-gate` delta.

### Decision: A versioned `x-identity-contract` stamp gates the edge→backend header contract
- **Status**: approved
- **Why**: the backend needs to know the identity headers it receives were produced by
  the current, trusted edge — not by a bypass and not under a drifted shape. Two shapes
  were weighed: a narrow semantic sentinel (`x-workspace-scope: acting`, trips only on the
  acting-org gap) vs. a versioned contract stamp (`x-identity-contract: vN`, trips on ANY
  drift). Adopt the **versioned stamp** as the primary guard: one gate covers all future
  drift, it doubles as a bypass detector (absent header → reject), and it directly
  de-risks the breaking header rename (a version bump makes a half-deployed rename fail
  closed instead of silently misread — see Migration / task 5.2).
- **Acting-scope is folded INTO the contract**, not a separate header: a well-formed `vN`
  request carries the authoritative `x-workspace-id`/`x-user-type`, so a same-version
  request missing acting scope is not a valid `vN` request and is rejected. This closes
  the one gap a version stamp alone misses (a same-version semantic bug) without a
  standalone sentinel that rots.
- **Trust**: emitted by the identity sidecar; added to the edge C3 strip list (same rule
  as `x-auth-required`/`x-workspace-id`) so a client can neither forge a version nor
  present its own by bypassing the edge.
- **Shared contract**: the version number is the coordination primitive between nexus and
  the consuming backend/box — both sides must agree on it (cross-repo).

### Decision: Non-member policy is derived from the route auth policy, not a separate knob
- **Status**: approved (settles open question 0.2)
- **Why**: "reject vs. anonymous vs. self-signup" is the same question the N4 per-route
  auth policy (`routing.auth_routes`) already answers — adding a second setting would be
  an overlapping source of truth for the same decision. Bind non-member behavior to the
  resolved route policy instead:
  - **Public route** (`auth_required: false`, the N4 default `auth: none`): a non-member
    (including anonymous) **passes through** with no workspace-scope headers emitted —
    the website case. One domain can serve a public marketing surface this way.
  - **Protected route** (`auth_required: true`, or `requires_role`/`requires_entitlement`):
    a non-member **fails closed (403)**, matching the fail-closed authz this change
    enforces everywhere else — the app case.
- The same domain therefore serves "websites and web apps alike," decided per-surface by
  the auth-routes config the tenant already controls; no new column, one policy resolver.
- **Self-signup-as-customer is out of scope for the edge** — it is an onboarding/product
  flow (couples the data plane to membership provisioning/billing), not an edge policy.

## Migration (BREAKING)

- Rename routing `tenant_id → workspace_id`: the routing store column/queries, the
  control-plane API (`/tenants` → `/workspaces`, body fields), the `x-tenant-*`
  headers, and the shipped auth-gate/edge configs. Coordinate with the running edge
  (a header rename is a data-plane contract change).
- Seed memberships: for each existing user, create a `staff` membership for their
  `org_id`'s workspace; keep `home_org` informational/default only.
- `Profile` gains `memberships` (projection) and `home_org`; `enrich_response` emits
  the resolved workspace scope + `x-user-type` instead of the fixed `x-user-org`.

### Cut-over sequence (task 5.2 — header rename coordinated with the running edge)

The header rename is a data-plane **contract change**; the versioned
`x-identity-contract` stamp (task 4.3) is the coordination gate that makes a
half-deployed rename fail **closed** rather than be silently misread. Because the
project is **pre-production** (see `identity-rs/MIGRATION.md`: the Mongo→Postgres cut
was a single hard cutover, and the store is a rebuildable projection), the plan below
is a single coordinated cut, not a long dual-run — but each step is ordered so the
running edge stays coherent at every point.

1. **Schema + backfill first (no wire change).** Deploy the control plane / routing
   store: the guarded in-place `ALTER … RENAME` (`tenant_id → workspace_id`) and the
   idempotent account backfill run in `init_schema` on startup. Internal field is
   renamed; the **wire** `x-tenant-*` name is still emitted. No edge coordination
   needed — this is backward-compatible at the header layer.
2. **Seed memberships (rebuildable, not ETL).** Memberships are nexus-native CRUD, so
   there is no routing-side ETL: the broker seeds one `staff` membership per existing
   user for their `org_id`'s workspace (the same "let the projection rebuild" model as
   the Profile store). Until a user has a membership, the fail-closed resolver emits no
   acting scope for them — so seed **before** flipping any surface to protected.
3. **Roll the identity sidecar + routing emit together to `x-workspace-*` and stamp
   `v1`.** The sidecar reads the acting workspace from EITHER `x-workspace-id`
   (post-rename) or `x-tenant-id` (pre-rename) — see `extract_acting_workspace` — so
   the sidecar tolerates both router versions during the roll. It emits the new
   `x-workspace-*`/`x-user-type`/`x-user-role` set and `x-identity-contract: v1`.
4. **Roll the edge C3 strip lists** (all 5 Envoy configs) to strip the new
   `x-workspace-*`/`x-user-*`/`x-identity-contract` family. Order 3→4 is safe: a
   stripped-but-not-yet-authored header is simply absent (fail-closed), never a forged
   client value.
5. **Backend requires `v1`.** The consuming box starts requiring `x-identity-contract:
   v1` (rejecting absent/unrecognized, and treating a `v1` request missing the
   authoritative `x-workspace-id`/`x-user-type` as invalid). Coordinate this version
   number cross-repo. If a future rename changes the header shape, **bump the version**
   — the mismatch makes the request fail closed until both edge and backend reach the
   new version, which is exactly the property this whole plan is built on.

**Rollback:** `git revert` the roll; because the store is a rebuildable projection and
this is pre-production, there is no live data rollback to manage (mirrors the
Mongo→Postgres cut). A version bump is the forward-fix for any drift caught in prod.

## Open questions (carry into decide/apply)

- ~~Non-member policy on a resolved workspace~~ — **RESOLVED** (see the Decision above):
  derived from the route auth policy (anonymous on public routes, fail-closed on
  protected routes; self-signup out of scope for the edge).
- Whether customer surface and staff surface are distinct domains/paths (routing can
  then hint the expected membership type).
- `AccountMember` roles beyond `owner` (admin/billing) — additive; owner-only in v1.
