## Why

A box behind the edge treats its **event-write surface** as a system-of-record: the principal that
legitimately *writes* is a **non-human caller** (a first-party platform service, later a tenant's own
backend or automation). Human end-users write *commands* to an application tier, which authorizes them
and emits events on the user's behalf — the end-user is a *subject inside* events, never a *writer of*
them.

nexus today models identity as **humans only** — `member_type ∈ {staff, customer}` over a `sub`-keyed
Profile — with no representation of a non-human principal, and no explicit *principal* abstraction at
all: the sidecar reads a verified `sub` and assumes human. A machine (client-credentials) token is not
rejected but **flattened**: the sidecar resolves no membership, authors no acting scope, and mints no
signed `x-identity-contract`, so the caller fails closed at the box.

The fix is **not** a single "service" bolt-on. It is a **normalized principal**: authentication varies
by trust boundary and produces one uniform principal; authorization operates on that principal and does
not care how the caller authenticated. The consequence for consumers is concrete — evenout (the
event-log box) reports that until a service can be represented and carried in the signed contract, its
write door admits only staff-admins, so the real service write path is blocked. This change gives a
non-human principal a first-class place in the identity model and the injected contract.

> Origin: cross-repo request from evenout. The full architectural rationale (users write commands,
> services write events), the trust-tier model, option trade-offs, and precedents (Google
> BeyondProd/BeyondCorp, SPIFFE, OAuth2 client-credentials, CQRS/BFF) live in evenout's
> `openspec/changes/trust-nexus-edge-identity/nexus-service-identity-request.md`. Adjacent to
> `workspace-plan-tier` and `sign-identity-contract-jwt`. (Renamed from `service-identity` — the
> scope grew from "a service kind" to "the normalized principal seam.")

## What Changes

- Introduce a **normalized `Principal`** with a `kind ∈ {user, apikey, service}`, produced by
  authentication and consumed by authorization **independent of credential type**. `principal_kind` is
  orthogonal to `member_type` (staff/customer stays a role fact, not a principal kind).
- Split **authentication by trust boundary** (one mechanism per boundary, not one for everything):
  humans → ZITADEL OIDC (exists); **core platform services → infrastructure-level trust** (not
  ZITADEL); customer automation → API keys (*carved out — separate change*); cross-boundary workloads →
  SPIFFE / ZITADEL service accounts (*deferred — future extension*).
- Give a principal one of **two authoritative authorities**, selected by kind:
  - **`Workspace`** — resolved from live per-workspace membership **rows** (user, apikey, tenant svc).
  - **`Platform`** — a **platform-level, least-privilege permission set**, cross-workspace, **NOT**
    membership rows (core platform services are implementation details of the platform, not actors in
    the tenancy model).
- Author the principal kind + resolved authority on enriched requests, and mint an `x-identity-contract`
  variant carrying a **`principal_kind`** claim (edge-injected, nexus-authoritative, never
  client-asserted). The box keys its write door on the kind.
- Preserve fail-closed: a caller whose credential verifies but resolves to **no** authority (no
  membership row, or a service not in the platform registry) is rejected, never admitted open.

## Scope

**v1 (this change) — unblocks evenout:** the normalized-principal seam + `User` (exists) + **Platform
Service** (new, infra-trust authN, `Platform` authority). The `Principal` abstraction is *designed* for
all three kinds and both authorities, but only the two we have today are *implemented*.

**Carved out (separate changes):**
- `customer-api-keys` — Personal Access Tokens: own IDs, scopes, expiry, rotation, revocation; resolves
  to `Workspace(membership ∩ key-scopes)`; audit records both the key and the creating user. Slots into
  the seam as "just another authenticator producing a `Workspace` authority."
- Workload identities (SPIFFE/SPIRE or ZITADEL service accounts) for non-core / cross-boundary services
  — a future extension, decided separately from the core platform architecture.

## Capabilities

### New Capabilities

- `principal-model`: the observable behavior of producing a **normalized principal** (kind + subject +
  resolved authority) from a verified credential, and authoring it uniformly. Absorbs and supersedes the
  former `service-identity` capability.
  - **Critical concern (security — authN of a non-human principal):** how a core service *proves* it is
    who it claims, via **infrastructure-level trust** (not ZITADEL). Build-vs-adopt deferred to
    `/opsx:decide`; credential verification MUST NOT be hand-rolled.
- `platform-service-authz`: the observable behavior of resolving a core service's **platform-level
  permission set** and revoking it live.
  - **Critical concern (correctness — scope authority):** the platform permissions must be
    **nexus-resolved and live** (revocation-consistent like membership/suspension — "within seconds"),
    never client- or token-asserted, and **least-privilege** (a named permission set, not god-mode).

### Modified Capabilities

- `nexus-native-authorization`: resolution **branches on principal kind** — `Workspace` authority from
  membership rows (user/apikey/tenant), `Platform` authority from the service registry (core service).
- `identity-contract-signing`: the signed `x-identity-contract` gains a **`principal_kind`** claim and
  must be mintable for a `Platform` authority (which has no membership `member_type`/`role`); the mint
  guard generalizes from "has a membership" to "has a resolved authority."

## Impact

- **Data model / store:** a new `platform.services` registry (service_id, permission set, status),
  projected and watched like `routing.memberships` so revocation is live. No change to the human
  membership path.
- **Code:** `identity-rs/core` (the `Principal` type + `Authority {Workspace|Platform}` + a platform
  resolver alongside `MembershipResolver`); `identity-rs/sidecar` (turn `extract_identity` into an
  authenticator chain; generalize the mint guard at `main.rs:520-539`; author `principal_kind`);
  `identity-rs/core/contract.rs` (`principal_kind` + platform-permission claims); `edge/envoy.yaml` (a
  **second `jwt_authn` provider** for the infra-trust token; tighten `audiences` on the human `oidc`
  provider regardless).
- **Contract/docs:** `docs/box-consumer-contract.md` gains the principal-kind shape and how a box
  authorizes each kind — the missing counterpart to the human `x-user-*` contract.
- **Consumers:** boxes can then authorize service writers. evenout keys its write door on principal kind
  — service → writer, staff → per role, customer → reject.

## Open questions (resolve in `/opsx:decide` before implementing)

1. **Infra-trust mechanism for v1** — recommended: **K8s projected ServiceAccount token as a second
   `jwt_authn` provider** (adopts the existing verification pattern; `sub = system:serviceaccount:ns:name`;
   no ZITADEL). Alternatives: mTLS peer identity, or a dev-signed internal JWT. Note: prod is
   **compose today, K8s later** — v1 may need a dev-issuer stub. Build-vs-adopt.
2. **Platform registry mechanism** — `platform.services` table + LISTEN/NOTIFY (recommended, matches the
   membership liveness) vs. static config (no live revocation — weaker).
3. **Platform permission vocabulary** — the named permission set a core service carries (e.g.
   `events:write`) and how a box maps it to policy.
4. **Contract shape for `Platform`** — the acting `workspace_id` still comes from `x-workspace-id` (the
   service acts *on* one workspace per request); confirm whether a platform-wide operation may omit it.
5. **Revocation / rotation** — how infra-trust credentials rotate/revoke and how fast the platform
   registry reflects a revocation (target: seconds, like the human path).

## Decided during exploration (recorded in `design.md`)

- Normalized principal with **authentication pluggable by trust boundary**; authorization uniform.
- `principal_kind` is **orthogonal** to `member_type` (not a third `member_type`).
- Core platform services get a **`Platform` authority**, **not** per-workspace membership rows
  (decision "(b)"); least-privilege permission set.
- **Reject** OAuth2 client-credentials-per-service; ZITADEL stays human-only.
- **Split** the original `service-identity` into `normalized-principal` (v1) + `customer-api-keys`
  (fast-follow) + workload-identity (future).

> Status: **proposal only.** The seam and the platform-vs-workspace split are decided; the infra-trust
> mechanism and registry are the remaining build-vs-adopt calls for `/opsx:decide`.
