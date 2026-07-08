# Design — customer-api-keys

> HOW for this change. Builds directly on the `normalized-principal` seam (a hard prerequisite). The
> family sync-order and contract-claim ownership are recorded canonically in
> `normalized-principal/design.md` **ADR-10** — this change conforms to it rather than restating it.

## Context

`normalized-principal` introduces the `Principal { kind, subject, on_behalf_of, authority }` type, a
pluggable authenticator chain (`extract_identity` → chain), a generalized mint guard, and the
`principal_kind` contract claim. That change implements two kinds (`User→Workspace`, `Service→Platform`)
and *designs* the seam for the third. This change fills the third: **`ApiKey→Workspace`**.

Today an API key has no home: a caller is a human ZITADEL `sub` or fails closed. Customer automation
needs a long-lived credential that acts on behalf of a human, bounded by scopes.

## Goals / Non-Goals

**Goals:**
- A PAT lifecycle — issue (human-only), scope, expire, rotate, revoke — with hashed-secret storage.
- An `ApiKey` authenticator that plugs into the seam and produces `Workspace(membership ∩ scopes)`.
- Live, fail-closed revocation/expiry consistent with membership liveness.
- `principal_kind: apikey` + `on_behalf_of` in the contract; audit records both principals.

**Non-Goals:**
- The principal seam itself, the mint-guard generalization, or `principal_kind` — owned by
  `normalized-principal`.
- Platform-service identity (that is the `Platform` authority, a different change).
- Cross-boundary / workload identities (SPIFFE) — future.

## Decisions

**Core vs adapters, dependency direction (inward-only):**
- **Core** (`identity-rs/core`): an `ApiKeyAuthenticator` port + a `ScopeIntersectionResolver` that
  composes the existing `MembershipResolver` output with a key's scopes. Core holds the
  intersection *behavior*; it never imports a hashing crate or a DB type.
- **Adapters** (isolate every external system): the key **store** (`identity.api_keys` in Postgres,
  projected/watched like `routing.memberships`) behind a reader port; the **hasher** behind a port; the
  **credential extractor** in the sidecar (recognizes the API-key scheme and hands core an opaque
  presented-secret). Composition wiring stays in the sidecar `build_*` startup path, matching the
  existing `build_signer`/`watch_store` pattern.

**Build-vs-adopt (`/opsx:decide` — RESOLVED 2026-07-07):**

- *Secret storage & verification* → **ADOPT `hmac` + `sha2` (RustCrypto) behind a `SecretHasher` port;
  do not build, do not adopt a password-hash.** A PAT secret is a **high-entropy random token**, not a
  low-entropy password, so the password-hash threat model (offline brute-force of a weak secret) does
  not apply — the industry norm for API tokens (GitHub, GitLab, Stripe) is a **fast keyed hash**, not
  argon2/bcrypt. Decisive factor: verification happens on the **sidecar ext_proc hot path** in front of
  every request; argon2 is deliberately CPU-heavy (tens of ms/verify) and would need a verified-key
  cache to be viable, whereas a keyed HMAC is microseconds and needs none. Chosen construction:
  `key_hash = HMAC-SHA256(server_pepper, secret)`, hex-encoded, stored under a **UNIQUE index**. This
  makes the hash **deterministic**, so the sidecar resolves a presented key with a single indexed
  lookup (`WHERE key_hash = $1`) — a per-row salt (argon2/bcrypt) would forbid lookup and force a
  key-id-prefix scheme. The keyed pepper means a stolen DB alone cannot brute-force secrets offline.
  "Not hand-rolled" is satisfied: HMAC/SHA-256 come from audited RustCrypto crates already in-tree
  (`hmac`, `sha2`, `hex`), and the post-lookup equality is `subtle::ConstantTimeEq`, not a hand-written
  compare. *Rejected: argon2/bcrypt (Adopt) — correct for passwords, wrong workload here; hot-path cost
  + per-row salt breaks the single-lookup resolve.*
- *Effective authority* → **REUSE** the live membership resolver + feed; intersection is pure core
  logic (not a critical adopt). The sidecar resolves the **creator's** live Profile (existing cache
  path) and intersects `profile.resolve_membership(acting_ws)` with the key's scope set — no new I/O
  primitive.

**Credential presentation (`/opsx:decide` — RESOLVED):** a PAT is not a ZITADEL JWT, so `jwt_authn`
cannot verify it. **Chosen: a distinct `x-api-key` request header** carrying the opaque secret, verified
in the **sidecar authenticator chain after the JWT branch** (human JWT → api-key → service). The edge
stays a thin JWT gate; key verification lives with the resolver that already talks to the live store.
The sidecar strips `x-api-key` before the backend (defense-in-depth), so the raw secret never reaches a
box. *Rejected: edge-side verification (heavier, splits key logic across planes); `Authorization: Bearer`
(collides with `jwt_authn`, which would 401 a non-JWT bearer at the edge before the sidecar sees it).*

**Live revocation without a resident cache (`/opsx:decide` — RESOLVED):** the sidecar resolves each
api-key request with a **fresh, filtered SELECT** (`status = 'active' AND (expires_at IS NULL OR
expires_at > now())`) against a SELECT-only pool — so revocation/expiry take effect on the **very next
request**, strictly stronger than the "within seconds" a resident-cache + `LISTEN/NOTIFY` feed gives.
The `api_keys` table still ships a NOTIFY trigger (parity with `platform.services`) for a future
opt-in cache/audit-tap, but correctness does not depend on it. *Rejected: resident-map + feed — would
only weaken the revocation guarantee here (keys are a large, per-request-miss-loaded set like profiles,
not a small resident set like the service registry).*

**Issuance surface (`/opsx:decide` — RESOLVED):** create/rotate/revoke live in the existing
**`authz-admin`** binary (already the identity-plane authoring surface, admin-token gated, off the hot
path). The create endpoint takes the creating user's `sub` + requested scopes; "a key may not exceed
its creator" is enforced **at issuance** (requested scopes ⊆ the creator's live membership workspaces,
read from the creator's Profile) **and** **at resolve time** (the sidecar intersection, fail-closed) —
the resolve-time check is the real guarantee, issuance is fast-fail UX.

**Data-is-not-code:** the `api_keys` table DDL lives in a `.sql` migration loaded by the store adapter,
never inlined. Scope vocabulary is config/data, not literals in code.

**Conformance to ADR-10 (family coordination):**
- Sync **after** `normalized-principal`. Its deltas establish the post-human contract/authorization
  shape; this change's deltas are authored on top of that state.
- Shared capabilities use **ADDED** requirements (the apikey path, the `on_behalf_of` claim), not
  MODIFIED rewrites — additive requirements merge without colliding with sibling deltas.
- Contract-claim ownership: this change owns **only** `principal_kind: apikey` + `on_behalf_of`. It does
  not touch `plan` (workspace-plan-tier) or the `Platform` claims (normalized-principal).

## Risks / Trade-offs

- **A key is a bearer secret.** Leakage = impersonation until revoked. Mitigated by short-ish default
  expiry, hashed storage, one-time display, and within-seconds revocation. Rotation lineage lets a leaked
  key be cut without disrupting the automation's identity.
- **Intersection semantics can surprise.** A key looks authorized until the creator loses a membership,
  then silently narrows. This is the intended least-privilege behavior but must be observable in audit.
- **On-behalf-of widens the audit surface.** Every key action must carry both principals or attribution
  breaks; the contract omitting `on_behalf_of` for non-keys keeps the shape unambiguous.
- **Ordering coupling.** Authored against the post-`normalized-principal` spec state; if that change's
  contract shape shifts, revisit the two ADDED deltas here.
