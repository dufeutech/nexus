# Design — normalized-principal

> HOW for this change. Records the architectural decisions reached in `/opsx:explore` and their
> rationale. The formal build-vs-adopt gate (`/opsx:decide`) still runs for the items marked
> **pending** below — this file front-loads the calls already made so `/opsx:decide` inherits them
> instead of re-litigating.

## Architecture — the seam

Authentication varies by trust boundary and produces one **normalized principal**; authorization
consumes that principal and is blind to how the caller authenticated.

```
        AUTHENTICATION  (varies by trust boundary — pluggable)
  ┌──────────────────────────────────────────────────────────────┐
  │ Human               → ZITADEL OIDC JWT → jwt_authn  (EXISTS)  │
  │ Core internal svc   → infra trust (K8s SA / mTLS)   (v1 BUILD)│
  │ Customer automation → API key (PAT)                 (DEFERRED)│
  │ Cross-boundary      → SPIFFE / ZITADEL svc-acct     (FUTURE)  │
  └───────────────────────────────┬──────────────────────────────┘
                                  ▼
                    ┌───────────────────────────┐
                    │   NORMALIZED PRINCIPAL     │
                    └─────────────┬─────────────┘
                                  ▼
        AUTHORIZATION  (uniform — credential-agnostic)
        resolve authority → author x-user-* + mint x-identity-contract (principal_kind)
```

Core type (in `identity-rs/core`):

```
Principal {
  kind: User | ApiKey | Service,
  subject:      String,          // sub | key-id | service-id
  on_behalf_of: Option<Sub>,     // ApiKey only — the creating user (audit)
  authority:
      Workspace(ResolvedMembership)   // User, ApiKey, tenant svc — from rows
    | Platform(PlatformScope),        // core Service — from platform registry
}
```

The contract (`identity-rs/core/contract.rs`) gains a `principal_kind` claim; for a `Platform`
authority it carries the acting `workspace_id` (from `x-workspace-id`) + the platform permission set,
and has no membership `member_type`/`role`.

---

## ADR-1 — Normalized principal, authentication pluggable by trust boundary

**Context.** The code has no explicit principal; the sidecar reads a verified `sub` and assumes human
(`main.rs:253-274`). The original proposal bolted on a single "service" kind.

**Decision.** Introduce one normalized `Principal`. Authentication is **pluggable by trust boundary**
(one mechanism per boundary), each authenticator producing the same principal. Authorization operates on
the principal only.

**Why.** Keeps ZITADEL focused on human identity, API keys on customer automation, and internal-service
auth as an infrastructure concern — while the authz layer stays credential-agnostic and gains new kinds
without rework. `extract_identity` becomes an authenticator chain instead of a `sub`-only read.

**Status.** Decided.

## ADR-2 — `principal_kind` is orthogonal to `member_type`

**Context.** The proposal offered three shapes: a third `member_type: service`, an orthogonal
`principal_kind`, or a separate record.

**Decision.** `principal_kind ∈ {user, apikey, service}` is an **authN output, orthogonal** to
`member_type` (staff/customer), which stays an authz/role fact scoped to a workspace.

**Why.** Kind (who/what authenticated) and member_type (role-family within a workspace) are different
axes; conflating them jams a cross-workspace concept into a per-workspace table. Kind is what evenout
branches on at its write door.

**Status.** Decided.

## ADR-3 — Core platform services get a `Platform` authority, not membership rows  *(decision "(b)")*

**Context.** A core platform service may legitimately touch all workspaces; per-workspace membership
rows can't express "the platform service," and enumerating a row per workspace is wrong.

**Decision.** A core platform service authenticates as a **Platform Service** and receives a
**platform-level, least-privilege permission set** (e.g. `events:write`), cross-workspace, resolved from
a platform registry — **not** per-workspace membership rows. Membership rows remain for principals
constrained to workspaces (users, API keys, external integrations, tenant-owned services).

**Why.** Core services are implementation details of the single trusted platform, not actors within the
tenancy model. This keeps the authz model clean: *User/ApiKey → membership rows; Platform Service →
platform permissions*. Least-privilege (a named permission set, not a boolean) bounds the blast radius
of a compromised internal service. Non-core / cross-boundary services are a **separate** future decision
(ADR-8).

**Status.** Decided.

## ADR-4 — Two authoritative resolution paths; generalized mint guard

**Context.** Resolution today is `resolve_membership(workspace_id)`; the mint guard requires
`acting = Some(membership)` (`main.rs:501-503`, `520-539`), so a principal without a row fails closed.

**Decision.** Resolution **branches on kind**: `Workspace` from membership rows, `Platform` from the
service registry. The mint guard generalizes from "has a membership" to "has a **resolved authority**
(Workspace or Platform)." The contract always names the acting `workspace_id` from `x-workspace-id`.

**Why.** A platform service must mint a contract despite having no membership. Fail-closed is preserved:
a verified credential resolving to **no** authority (no row, or service absent from the registry) still
mints nothing and is rejected.

**Status.** Decided.

## ADR-5 — Reject OAuth2 client-credentials-per-service; ZITADEL stays human-only

**Context.** An earlier option was adopting ZITADEL client-credentials for services (the edge already
verifies any token from the pinned issuer — no `audiences` restriction, `envoy.yaml:277-337`).

**Decision.** Do **not** introduce OAuth client-credentials for internal services. ZITADEL remains the
source of truth for **human** identity only. Internal-service auth is an **infrastructure** concern.

**Why.** Avoids per-service OAuth app sprawl and coupling core infra identity to the human IdP. Matches
"avoid client credentials unless there is a clear security or operational need."

**Status.** Decided.

### ADR-5a — Audience-pinning on the human `oidc` provider is NOT enabled (redundant under a single-audience edge)

**Context.** ADR-5 originally carried a side-note to "independently tighten `audiences`" on the human
`oidc` provider (it was unrestricted — any token from the pinned issuer verifies). Implementation
(task 3.2) surfaced the question of *which* audience value to pin, and then the deeper question of
whether the check is needed at all.

**Decision.** Do **not** enable an `audiences` restriction on the `oidc` provider at this time. The
`aud` claim is minted by the **authorization server (ZITADEL)**, not by us; the edge can only enforce a
match against whatever ZITADEL is configured to stamp. More importantly, an `aud` check only earns its
keep when **one issuer mints tokens for more than one audience** — its purpose is to stop a token minted
for relying party A from being replayed at relying party B. That condition does not hold here:

- The **edge is the sole consumer** of ZITADEL access tokens. Boxes never verify the raw ZITADEL token —
  they verify the nexus-minted `x-identity-contract`. So every ZITADEL token has exactly one intended
  recipient.
- The **`iss` pin already fully scopes** the token population; within our single issuer there is only one
  audience, so `aud` has nothing left to disambiguate.

The mechanism + exact enablement instructions are left **commented** in both `edge/envoy.yaml` and
`deploy/compose/envoy/envoy.yaml`, pointing at this ADR.

**Why.** Under the current architecture the check is redundant belt-and-suspenders, and pinning a
concrete value would require (a) defining a stable edge audience identifier and (b) configuring ZITADEL
to mint it deterministically (RFC 8707 `resource`, or a project/API app audience) — real work for no
security gain while the edge is the only relying party. Recording the decision (not a silent skip) keeps
the rationale discoverable.

**Revisit when.** ZITADEL gains a **second first-party audience** — e.g. a box or service that verifies
its *own* ZITADEL token rather than the nexus contract. Then: define the edge audience, wire ZITADEL to
emit it, and uncomment `audiences:` in both edge configs.

**Status.** Decided (not enabled).

## ADR-6 — Infra-trust mechanism: K8s ServiceAccount token as a second `jwt_authn` provider

**Context.** Options for infra trust: private-network trust, K8s ServiceAccounts, mTLS, or a signed
internal JWT. The mechanism must be verifiable at the nexus edge, because the service's request traverses
the edge to get a minted `x-identity-contract`.

**Decision (recommended, pending `/opsx:decide`).** A **K8s projected ServiceAccount token** verified by
a **second `jwt_authn` provider** in `envoy.yaml`. SA tokens are OIDC-verifiable JWTs with a JWKS, so
this **reuses the existing `jwt_authn` pattern** (issuer + `remote_jwks`) with zero new verification
code; `sub = system:serviceaccount:ns:name`. In compose-dev, stub with a dev-issuer-signed internal JWT.

**Why.** Adopt over build — no hand-rolled credential verification (the change's stated critical
concern). mTLS peer identity remains a viable alternative/upgrade (closer to SPIFFE). Caveat: prod is
**compose today, K8s later** — v1 likely ships the dev-issuer stub with the K8s provider as the target.

**Status.** **Approved** at `/opsx:decide` — see Decisions gate below.

## ADR-7 — Platform registry is live and revocation-consistent

**Context.** Humans get "revoke within seconds" via the `routing.memberships` change feed (Postgres
LISTEN/NOTIFY, `main.rs:783-831`). A platform service needs an equivalent.

**Decision (recommended, pending).** Store platform services in a small `platform.services` table
(`service_id`, permission set, `status`), projected and **watched through the same LISTEN/NOTIFY feed**
— not static env config.

**Why.** Static config can't revoke a compromised/rotated service quickly. Reusing the existing liveness
machinery keeps the "within seconds" guarantee and the fail-closed-on-store-unavailable behavior
(`must_fail_closed`, `main.rs:241-243`) uniform across principal kinds.

**Status.** **Approved** at `/opsx:decide` — see Decisions gate below.

## ADR-8 — Split `service-identity` into three changes

**Context.** The original change fused first-party services, tenant backends, and API keys.

**Decision.** Split: **`normalized-principal`** (v1 — seam + User + Platform Service) → this change;
**`customer-api-keys`** (fast-follow — PAT model, `Workspace(membership ∩ scopes)`, on-behalf-of audit);
**workload identities** (future — SPIFFE / ZITADEL service accounts for non-core/cross-boundary).

**Why.** evenout only needs the Service kind; bundling the tenant-facing API-key data model delays it for
no reason. Different risk profiles and stores deserve separate `/opsx:decide` gates. The seam is designed
for all three kinds so API keys slot in later without rework.

**Status.** Decided.

## ADR-9 — Contract signing stays `jsonwebtoken` ES256; add `principal_kind`

**Context.** `x-identity-contract` is a per-request ES256 JWT signed with `jsonwebtoken`, isolated in
`identity-rs/sidecar/src/signer.rs`; claims in `contract.rs:24-57` (incl. a reserved `plan`).

**Decision.** Keep the existing signer and crate. Add a `principal_kind` claim; allow `member_type`/
`role` to be absent for a `Platform` authority; carry the platform permission set.

**Why.** No reason to change a working, adopted signing path; the change is additive to the claim set and
the mint guard, not to the crypto.

**Status.** Decided.

## ADR-10 — Identity-change family: sync order & contract-claim ownership  *(canonical coordination record)*

**Context.** Four in-flight changes touch the same two hot files (`identity-rs/sidecar/src/main.rs`
enrich/authoring, `identity-rs/core/src/contract.rs` claims) and overlapping capabilities
(`identity-contract-signing`, `nexus-native-authorization`) **before any is synced**. Left uncoordinated
they collide on the same `ContractClaims` struct and rewrite the same requirements from a human-only
base. This ADR is the single canonical home for their coordination (one home, one owner).

**Decision — sync order (later changes are authored against the earlier state):**

```
  1. normalized-principal   (this change — establishes Principal, mint-guard generalization, principal_kind)
  2. workspace-plan-tier    (populates the reserved `plan` claim; independent of kind)
  3. identity-existence-hiding (behavioral authz on the enrich path; no contract claim)
  4. customer-api-keys      (adds the apikey kind on top of the seam)
```

`normalized-principal` is a hard prerequisite for `customer-api-keys`. `workspace-plan-tier` and
`identity-existence-hiding` are independent of principal kind and may land in any order relative to
each other, but their `contract.rs`/`main.rs` edits rebase onto whatever landed first.

**Decision — contract-claim ownership (each claim has exactly one owning change):**

| Claim / field (`contract.rs`)      | Owner change            |
|------------------------------------|-------------------------|
| `principal_kind`                   | normalized-principal    |
| platform permission set (Service)  | normalized-principal    |
| `member_type` / `role` optionality | normalized-principal    |
| `plan` (reserved → populated)      | workspace-plan-tier     |
| `on_behalf_of`                     | customer-api-keys       |

**Decision — merge discipline:** shared capabilities are extended with **ADDED** requirements, not
MODIFIED rewrites, wherever a change only *adds* a path (a kind, a claim). MODIFIED is reserved for
`normalized-principal`'s genuine reshaping of the resolution/mint behavior. Additive deltas from the
other three then merge without clobbering that base at `/opsx:sync`.

**Decision — enrich-path edits (`main.rs`):** `identity-existence-hiding` owns the unresolved/forbidden
branch (404-vs-403); `normalized-principal` owns the authenticator chain and mint guard;
`customer-api-keys` adds one authenticator branch; `workspace-plan-tier` adds one authored header. Each
touches a distinct region — reviewers should confirm no two changes edit the same guard in the same pass.

**Why.** Makes the overlap explicit and orderable instead of discovered at sync/rebase time; gives each
claim a single owner so no change silently drops another's field.

**Status.** Decided (coordination). Referenced by `workspace-plan-tier`, `identity-existence-hiding`, and
`customer-api-keys`.

## Decisions (build-vs-adopt gate — `/opsx:decide`)

### Decision: Platform-service authentication — Adopt Kubernetes projected ServiceAccount token via a second Envoy `jwt_authn` provider

- **Status**: approved
- **Why**: K8s bound SA tokens (1.22+) are audience-bound, short-lived, and auto-rotated; the API server
  publishes OIDC discovery + a JWKS, so a second `jwt_authn` provider verifies them with **zero new
  verification code** — reusing the exact edge path that already verifies human OIDC tokens. No
  hand-rolled crypto (the concern's hard requirement).
- **Considered**: SPIFFE/SPIRE mTLS via Envoy SDS (stronger X.509 SVIDs + cross-cluster federation, but
  a SPIRE control plane to operate — disproportionate for single-cluster core services; kept as the
  documented upgrade path for the deferred cross-boundary case). Hand-rolled internal JWT/shared secret
  (rejected — hand-rolling credential verification is the defect this gate exists to prevent).
- **Isolation**: Envoy `jwt_authn` (a second provider in `edge/envoy.yaml`, selected per-route via
  `requires_any`); the sidecar authenticator-chain branch treats the verified `sub`
  (`system:serviceaccount:ns:name`) as an opaque service identity. Compose-dev swaps only the *issuer*
  (a dev OIDC issuer / static JWKS) — the verification mechanism is unchanged across environments.
- **Tier**: Adopt (Rent the verification infra: Envoy + the K8s OIDC issuer).

### Decision: Platform-service scope registry — Rent Postgres + reuse the existing LISTEN/NOTIFY projection

- **Status**: approved
- **Why**: The scope store is infrastructure (decision matrix → Rent), and an in-repo
  `membership-projection-sync` change feed already delivers "revoke within seconds." A `platform.services`
  projection reuses it, keeping the liveness guarantee and the fail-closed-on-store-unavailable behavior
  (`must_fail_closed`, `main.rs:241-243`) uniform across principal kinds. One source of truth, no new
  system.
- **Considered**: static config/env (rejected — no prompt revocation; fails the live/revocation-consistent
  concern). External policy engine such as OPA/OpenFGA (rejected now — new infra + a second source of
  truth for a small registry the existing feed already covers).
- **Isolation**: a read-only `PlatformServiceReader` port over Postgres (`SELECT`-only pool), watched by
  the existing `watch_store`/LISTEN-NOTIFY adapter; the DDL lives in a `.sql` migration, not inline.
- **Tier**: Rent (Postgres) + reuse in-house projection pattern.
