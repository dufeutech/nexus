# Tenancy & Identity — the model and the flows

One-stop orientation for how nexus thinks about **who is acting**, **where they act**,
and **who owns/pays** — and what actually happens when an account or workspace is
created. This is descriptive (an ADD); the normative statements live in the
[`openspec/specs/`](../openspec/specs/) capabilities linked throughout.

---

## 1. The three axes (Actor ≠ Account ≠ Workspace)

Three concepts that other systems often blur are kept structurally separate:

| Axis                  | Question it answers                 | Identified by                                     | Minted by                          |
| --------------------- | ----------------------------------- | ------------------------------------------------- | ---------------------------------- |
| **Actor (Principal)** | who is acting _right now_?          | federated `sub` (OIDC), api-key id, or service id | the IdP / key issuer — never nexus |
| **Workspace**         | _where_ is the action happening?    | `ws_<uuidv7>` — stable, never a domain            | nexus (server-minted)              |
| **Account**           | who _owns and pays_ for workspaces? | `acct_<uuidv7>`                                   | nexus (server-minted)              |

```
Account ──owns (workspace.account_id)──▶ Workspace ──has──▶ Membership rows
   │                                                              │
   └── account_members (administrative,                           └── bind a subject to the
       role: "owner" in v1)                                           workspace: (user_sub,
                                                                      member_type, role, status)
```

An account's owner and a workspace's member both ultimately point at a person, but
through **different relationships** — account membership is administrative
(who controls the container); workspace membership is the request-time acting scope.

### Actor / Principal

Every authenticator normalizes into one `Principal`
([`identity-rs/core/src/principal.rs`](../identity-rs/core/src/principal.rs),
spec: [`principal-model`](../openspec/specs/principal-model/spec.md)):

- `kind` — **what authenticated**: `user` | `apikey` | `service`.
- `subject` — the federated identifier (plus `on_behalf_of` for api-keys, for audit).
- `authority` — exactly one of:
  - **Workspace authority** (`ResolvedMembership {workspace_id, member_type, role}`) —
    users and api-keys, resolved from a **live membership row**, never from the token.
  - **Platform authority** (`PlatformScope`) — core services; a least-privilege named
    permission set, cross-workspace, _not_ a membership
    (spec: [`platform-service-authz`](../openspec/specs/platform-service-authz/spec.md)).

`PrincipalKind` (an authN output) is **orthogonal** to `MemberType` (an authz fact):
a staff operator and a customer are both `kind=user`; a service holds no member type.

### Workspace

The tenancy/routing pivot
(spec: [`workspace-tenancy`](../openspec/specs/workspace-tenancy/spec.md)).
Identified only by its stable `workspace_id`; **domains are many-to-one aliases**, never
identity. Carries `plan`, `target_pool`, `features`, and an optional owning
`account_id`. This id is what propagates downstream verbatim as the `tenant` value.

### Account

The ownership/billing container. Two deliberate design rules:

- **No structural personal-vs-organization split** — a solo user is a one-member account.
- **A user is never an owner directly** — ownership always flows through an account the
  user is a member of.

Plan lives on the **workspace** (travels with a transfer); payer lives on the
**account** (a transfer switches who is charged).

### Membership (the edge)

`(user_sub, workspace_id, member_type, role, status)` in `routing.memberships`.
`member_type` is a closed set:

- **`staff`** — operates the workspace (admin surfaces, settings).
- **`customer`** — uses the workspace's app.

Backends flip staff-mode vs customer-mode on the emitted `x-user-type`. `role` is
scoped to `(workspace, member_type)`.

### ID scheme

All workspace/account ids are **server-minted, typed, time-ordered**
([`routing-rs/router-core/src/ids.rs`](../routing-rs/router-core/src/ids.rs)):
`ws_`/`acct_` prefix + UUIDv7. Callers can never supply an id — create bodies reject
unknown fields (422), so the prefix is a structural collision guard every downstream
system inherits, and ids are self-describing in logs.

---

## 2. Flow: creating an account

`POST /accounts` on the control-plane surface (`:9400`, `CONTROL_AUTH_TOKEN`) — see
[`admin-apis.md`](admin-apis.md) and
[`openapi/control-plane.yaml`](openapi/control-plane.yaml).
Spec: [`provisioning-idempotency`](../openspec/specs/provisioning-idempotency/spec.md).

```
signup broker ──POST /accounts {owner_sub, name?, payer_ref?, idempotency_key?}──▶ control-plane
                                                                                       │
                 1. validate idempotency key (optional; opaque to nexus)               │
                 2. mint acct_<uuidv7>                                                 │
                 3. insert-only create — replay of the same key returns the            │
                    ORIGINAL account id with created:false, never overwrites           │
                 4. re-assert owner membership (idempotent upsert)                     │
                                                                                       ▼
                                                  {result:"ok", account_id, created}
```

There is no state machine beyond exists/doesn't-exist: an account is born complete,
with its owner member attached. **Auto-provision on signup** is the broker's job — by
convention it uses `signup:<sub>` as the idempotency key, making "one auto-provisioned
account per subject" a replay-safe no-op on retry. Nexus never interprets the key.

## 3. Flow: creating a workspace

`POST /workspaces` on the same surface:

```
caller ──POST /workspaces {name, account_id?, plan?, target_pool, features?, idempotency_key?}──▶
              │
              1. validate target_pool against the pool allow-list (fail-closed)
              2. if account_id given: account must already exist (else 404)
              3. mint ws_<uuidv7>
              4. create-only insert — replay returns the original, untouched
              5. attach ownership ONLY on a real insert (a replay never re-owns)
              ▼
   {result:"ok", workspace_id, created}
```

Actors attach **afterwards and separately** via workspace membership:

- `PUT /workspaces/{id}/members` upserts the membership row, then fires a best-effort
  change notification to the identity plane; a dropped signal is healed by the periodic
  reconcile backstop (spec:
  [`membership-projection-sync`](../openspec/specs/membership-projection-sync/spec.md)).
  The routing store is the **single source of record**; the identity plane only
  projects it.
- `PUT /workspaces/{id}` (reconfigure) is **update-only** — an unknown id is a 404,
  never an implicit create, so a typo cannot mint a ghost workspace. Only
  `plan`/`target_pool`/`features` are reconfigurable here; name and ownership are not.
- `POST /workspaces/{id}/transfer` repoints `account_id` **and deletes all staff
  memberships in one transaction** — the seller's staff can never survive a
  half-applied transfer. Customers, domains, and data ride through unchanged.

## 4. Request time: how the actor meets the workspace

The identity-plane sidecar resolves the acting scope **live, fail-closed, from
membership — never from the token** — so revocation lands in seconds
([`identity-rs/sidecar/src/enrich.rs`](../identity-rs/sidecar/src/enrich.rs), spec:
[`identity-workspace-authz`](../openspec/specs/identity-workspace-authz/spec.md)):

1. Authenticate → normalize to a `Principal`.
2. Resolve authority by kind: user/api-key → live membership lookup (api-key authority =
   the creating user's live memberships **intersected** with the key's scopes); service →
   live platform permissions.
3. For an authorized member, emit nexus-authored headers `x-workspace-id`,
   `x-user-type`, `x-user-role` — and **strip any client-forged copies**. A client-sent
   `x-workspace-id` is only an unauthorized _hint_; it can never self-authorize.
4. Non-members get nothing authored, plus existence-hiding 404s on account-scoped routes.
5. Coarse global facts — roles, entitlements, suspension — ride **only** inside the
   signed `x-identity-contract` assertion, which backends verify fail-closed
   (specs: [`nexus-native-authorization`](../openspec/specs/nexus-native-authorization/spec.md),
   [`identity-contract-signing`](../openspec/specs/identity-contract-signing/spec.md)).
   These facts are nexus-owned and authored only via the authz-admin surface (`:9300`);
   the IdP answers only "who am I."

## 5. The layered authorization picture

Two orthogonal questions, deliberately never merged:

```
access == ENTITLED(account, service) AND AUTHORIZED(principal, action)
```

Entitlement changes when payment changes; authorization changes when a grant changes.

| Layer              | Question                                                                   | Answered by                                                                                                |
| ------------------ | -------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------- |
| L0 authentication  | who is this?                                                               | OIDC / api-key / service identity                                                                          |
| L1 entitlement     | does the **account** pay for this feature?                                 | commerce plane (projected into `entitlements`)                                                             |
| L2 policy gate     | does this request satisfy the rule (role · entitlement · AAL · suspended)? | PDP — Cedar (spec: [`authorization-policy-engine`](../openspec/specs/authorization-policy-engine/spec.md)) |
| L3 resource access | can THIS principal touch THIS object?                                      | OpenFGA/Zanzibar — seam designed, **parked**                                                               |

Per-route requirements are tenant-authored `auth_routes` rules (path prefix,
`auth_required`, `requires_role`, `requires_entitlement`, `min_aal`, `account_scoped`),
matched longest-prefix and fed to the gate as decision context.

---

## Where the normative truth lives

| Topic                                                          | Canonical spec                                                                         |
| -------------------------------------------------------------- | -------------------------------------------------------------------------------------- |
| Account/workspace ownership, typed server-minted ids, transfer | [`workspace-tenancy`](../openspec/specs/workspace-tenancy/spec.md)                     |
| Idempotent provisioning semantics                              | [`provisioning-idempotency`](../openspec/specs/provisioning-idempotency/spec.md)       |
| Normalized principal (kind × authority)                        | [`principal-model`](../openspec/specs/principal-model/spec.md)                         |
| Live membership gate, header authoring/stripping               | [`identity-workspace-authz`](../openspec/specs/identity-workspace-authz/spec.md)       |
| Nexus-owned roles/entitlements/suspension                      | [`nexus-native-authorization`](../openspec/specs/nexus-native-authorization/spec.md)   |
| Platform authority for services                                | [`platform-service-authz`](../openspec/specs/platform-service-authz/spec.md)           |
| Source-of-record → identity projection                         | [`membership-projection-sync`](../openspec/specs/membership-projection-sync/spec.md)   |
| L2 policy engine (Cedar slice)                                 | [`authorization-policy-engine`](../openspec/specs/authorization-policy-engine/spec.md) |

Key implementations: [`routing-rs/control-plane/src/tenancy.rs`](../routing-rs/control-plane/src/tenancy.rs)
(account/workspace/membership handlers) ·
[`routing-rs/router-core/src/ids.rs`](../routing-rs/router-core/src/ids.rs) (id minting) ·
[`identity-rs/core/src/principal.rs`](../identity-rs/core/src/principal.rs) /
[`membership.rs`](../identity-rs/core/src/membership.rs) (domain types) ·
[`identity-rs/sidecar/src/enrich.rs`](../identity-rs/sidecar/src/enrich.rs) (live enrichment).

API how-to with curl examples: [`admin-apis.md`](admin-apis.md). Cross-repo vocabulary
(nexus **Workspace** == runlet-js `tenant` == event-logs `Tenant`) and the id-scheme
decision record: `Nexus-IDS.md` at the repo root.
