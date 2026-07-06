## Context

After change 1, nexus verifies any OIDC provider and stores its data in its own DB —
but the IdP is still nexus's *authorization* source. Two binaries carry that coupling
(`identity-rs/reconciler` enumerates ZITADEL users → `build_profile_from_user`;
`identity-rs/sync-worker` consumes ZITADEL Actions → `core/sync.rs`), and the sidecar
even prefers a `roles` **claim from the token** (`extract_identity`). Verified against
the code (exploration §7.2):

- `roles` — token-claim primary, Profile fallback. **Must flip to nexus-only.**
- `entitlements` — `Profile.entitlements`, but **no producer exists** today
  (`reconcile.rs` sets `Vec::new()`, `sync.rs` never sets it). First producer here.
- `is_suspended` — ZITADEL Actions → sync-worker. **The one signal that breaks** when
  the binaries are deleted; needs a nexus-native home.
- `memberships` — already nexus-native (`control-plane` authors `routing.memberships`
  → `membership-sync` projects → `Profile.memberships`). **Unchanged** — and it is the
  proven template (`membership-projection-sync` spec).
- name/email — from OIDC claims, display-only; the sidecar never reads them on the hot
  path.

The user's boundary: **OIDC = "who am I" (authn + basic profile); nexus = "what may I
do here" (authorization).** A future policy/ReBAC engine (OpenFGA / Cedar) is possible
but explicitly *not now* — the job is to get the port/adapter seam right so that is an
adapter swap, not a rewrite. Full reasoning: `EXPLORATION.md` §7.

## Goals / Non-Goals

**Goals:**

- Make roles/entitlements/suspension nexus-authored, authoritative, resolved live
  (revocation within seconds), deny-by-default.
- Remove the token-`roles` authorization path; `x-user-roles` comes from nexus.
- Delete the ZITADEL directory integration (reconciler, sync-worker, `core/reconcile`,
  `core/sync`, PAT/webhook, directory env/Helm).
- Put authorization behind `AuthzAuthoring` (write) + `AuthzResolver` (read) ports so a
  future engine is an adapter swap; ship a nexus-native Postgres adapter.

**Non-Goals:**

- Adopting OpenFGA/Cedar now (deferred — see the decide block).
- Fine-grained / resource-level authorization (a future *new* enforcement layer behind
  the same ports; the coarse edge gate stays attribute-matching).
- Changing membership (`membership-projection-sync`) or the edge gate's
  compare-injected-to-required contract (`edge-auth-gate`).
- Changing OIDC verification, `sub`, or the DB residency from change 1.

## Decisions

Layering: two new **ports in `core`** — `AuthzAuthoring` (create/revoke role,
grant/revoke entitlement, suspend/reactivate) and `AuthzResolver` (resolve a subject's
effective authorization facts / answer authorization questions). Enforcement and
enrichment depend ONLY on these ports, never on `Profile.roles` directly. Concrete
storage enters through an adapter. Four disciplines from the exploration (§7.4):
(1) enforcement depends on the port, header-injection is just how today's coarse
decisions reach the edge; (2) the coarse edge gate stays attribute-based, a decision
engine earns its keep later at resource level as a *new* layer; (3) attribute-vs-
decision is a shape change, so the ports are shaped as authorization *questions*, not
column reads; (4) no OpenFGA/Cedar scaffolding until it is real.

### D1 — Model 1: the identity plane owns the interim authorization store

The nexus-native adapter stores global authz facts (roles/entitlements/is_suspended)
in the **identity plane's own store**, authored via a new identity-plane admin surface,
resolved via `AuthzResolver`, and propagated to the sidecar over the **existing
seq-cursor `LISTEN/NOTIFY` change feed** (instant revocation, warm cache — reused, not
rebuilt). Memberships continue to project in from routing, unchanged.

- **Alternative — Model 2 (author in routing control-plane, project into identity like
  membership):** keeps identity a pure projection and reuses `membership-sync`, but
  puts *user-level* attributes in the *routing* DB (conceptually the wrong home) and
  adds a table + projection worker. Rejected: user authz is an identity-plane concern,
  and the "identity is a pure projection" property existed to enable rebuild-from-
  ZITADEL, which this change retires. M1 is simpler and, behind the ports, its
  evolution is contained — when an engine is adopted it becomes the source of record
  and the Profile reverts to a projection of it (a D2-shaped adapter), without touching
  enforcement.
- **Trade-off:** identity gains an admin-write path beyond the projection; "sole writer
  = projection" becomes "writers = membership projection + authz authoring", both
  bounded and both feeding the same change feed.

### D2 — Provisioning surface lives in the identity plane; bootstrap by config

The authoring surface is a small **identity-plane admin API** (auth-gated like the
control-plane's `CONTROL_AUTH_TOKEN`: fail-closed, bearer token from a Secret), writing
its own store. It is separate from the control-plane's routing/membership admin because
it writes the identity DB (M1). **Bootstrap:** a configured bootstrap-admin subject
(env/secret) is granted the admin role at startup if no administrator exists yet —
break-glass, documented, idempotent — so the surface is never unreachable from empty.

- **Alternative — reuse the control-plane admin API:** rejected under M1 (it would make
  the routing control-plane write the identity DB, breaking plane/DB ownership).

### D3 — Sidecar sources roles via the resolver, not the token

`extract_identity` stops reading the `roles` claim; `x-user-roles` (and
`x-user-entitlements`, `x-user-suspended`) come from `AuthzResolver` over the live
Profile/feed. The edge gate is unchanged (still compares injected → required). Absent
facts → headers stripped → deny-by-default, which the gate already treats as "requirement
not satisfied → 403".

### D4 — Deletion scope

Delete `reconciler` + `sync-worker` binaries, `core/reconcile.rs`, `core/sync.rs`, the
ZITADEL Management-API/Actions/PAT/webhook code, the Helm reconciler/sync-worker
templates + `secret-pat.yaml`, the `oidc.internalUrl`/`oidc.patSecret` values, and
`ZITADEL_HOST`/`ZITADEL_INTERNAL_URL`/`PAT_FILE` env across compose + Helm (the
directory surface change 1 deliberately left). `core/profile.rs` sheds `org_id`
(IdP-only); `home_org` stays informational per `identity-workspace-authz`. Keep: Envoy
OIDC verification, `sub`, the membership plane, `ProfileStore` + `PgProfileStore`,
`membership-sync`, the change feed.

## Build-vs-Adopt Decisions

### Decision: authorization engine — Build nexus-native flat RBAC (behind ports), defer OpenFGA/Cedar

- **Status**: approved (`/opsx:decide` 2026-07-06)
- **Why**: today's need is coarse flat roles/entitlements/suspension matched at the
  edge — textbook RBAC. Mature engines (OpenFGA — CNCF Incubation ReBAC service; Cedar —
  Rust-native ABAC/policy) solve a heavier, different problem (fine-grained ReBAC/policy)
  not yet present; current guidance is "start with RBAC, adopt an engine on role
  explosion or complex sharing." The ports make future adoption an adapter swap, not a
  rewrite (Adopt-when-real).
- **Considered**: Adopt OpenFGA now — production-grade but a separate Go service + graph
  store, no first-class Rust SDK; overkill for flat roles. Adopt Cedar now — embeds as a
  Rust crate with formal analysis, but ABAC/policy-shaped and you still build the grant
  store; overkill until attribute rules exist.
- **Isolation**: `AuthzAuthoring` + `AuthzResolver` ports in `core`; nexus-native
  Postgres adapter now. A future OpenFGA/Cedar adapter is a `/opsx:decide` pick behind
  the same ports (Cedar embeds; OpenFGA is an external service + HTTP client).
- **Tier**: Build (behind a port) now → planned future Adopt.

## Risks / Trade-offs

- **[Deny-by-default breaks existing users at cutover]** → every user currently relying
  on IdP-sourced roles has zero nexus roles until provisioned. Mitigation: pre-prod +
  rebuildable; provision nexus grants before/with cutover; the bootstrap admin seeds the
  first grants. Document as the operational BREAKING change.
- **[No enumerate/backfill pass without the reconciler]** → nothing auto-populates
  profiles. Mitigation: this is intended (Profile = "subjects nexus has an opinion
  about"); absent row is the safe default; suspension/grants create rows on authoring.
- **[Suspension propagation regresses vs. ZITADEL Actions]** → Mitigation: reuse the
  seq-cursor `LISTEN/NOTIFY` feed (same within-seconds guarantee as membership); assert
  in verify.
- **[Token still carries a `roles` claim that silently influences authz]** → Mitigation:
  D3 removes the claim read entirely; add a test asserting a role-claiming token confers
  nothing (spec scenario).
- **[Port shaped as an attribute-fetch, fighting a future decision engine]** →
  Mitigation: shape `AuthzResolver` around authorization questions (§7.4 discipline 3),
  keep the coarse gate attribute-based so the engine slots in as a new layer.
- **[Bootstrap admin becomes a standing backdoor]** → Mitigation: bootstrap grant is
  idempotent and only when no admin exists; rotate/disable the bootstrap secret after
  first real admin is authored; document.

## Migration Plan

1. Land the authz store + `AuthzAuthoring`/`AuthzResolver` ports + nexus-native adapter;
   wire the admin API (auth-gated) and the change-feed hook; bootstrap-admin seed.
2. Point the sidecar at `AuthzResolver` for roles/entitlements/suspension (D3); keep the
   edge gate untouched.
3. Provision nexus grants for existing users (re-author from the current ZITADEL grants;
   pre-prod, so re-provision rather than ETL).
4. Delete the ZITADEL directory integration (D4) once the sidecar no longer depends on
   Profile fields the binaries populated.
5. Verify: suspend → denied within seconds (no re-auth); grant role → route passes;
   role-claiming token confers nothing; deleted binaries leave the edge gate green.

**Rollback:** the deletion (step 4) is the point of no easy return; stage it last, after
steps 1–3 verify. Before step 4, `git revert` restores the ZITADEL path; the authz store
is additive until then.
