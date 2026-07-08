## Why

Customer automation — scripts, CI/CD, and customer backend integrations — needs a first-class,
long-lived credential that is neither a human OIDC session nor a core-platform service identity. Today
nexus has no such credential: a caller is either a human (ZITADEL `sub`) or fails closed. The
`normalized-principal` change introduces the `apikey` principal **kind** and the authentication seam;
this change fills that kind with a real **Personal Access Token (PAT)** lifecycle — issue, scope,
expire, rotate, revoke — that acts *on behalf of* its creating user, narrowed by the key's scopes, with
audit recording both.

> Sequenced **after** `normalized-principal` (the seam is a hard prerequisite). Coordination with the
> rest of the identity-change family (sync order, contract-claim ownership) is recorded canonically in
> `normalized-principal/design.md` **ADR-10**.

## What Changes

- Introduce **Personal Access Tokens** as first-class credentials: each has its own ID, scopes,
  expiration, rotation lineage, and revocation — created by an **authenticated human** after ZITADEL
  login.
- Add the **`apikey` authenticator** to the principal seam: a presented key verifies to a normalized
  `Principal { kind: apikey, subject: key-id, on_behalf_of: creator-sub, authority: Workspace(...) }`.
- **Effective authority = the creating user's live memberships ∩ the key's scopes** (least-privilege — a
  key can never exceed its creator, and follows the creator's revocation).
- Author `principal_kind: apikey` and an `on_behalf_of` claim in the signed `x-identity-contract`; the
  audit trail records **both** the key ID and the creating user.
- Revocation and expiry are **live and fail-closed**: a revoked/expired key resolves to no authority →
  no contract → rejected, consistent with the membership-liveness guarantee.
- Additive — no breaking change to the human path.

## Capabilities

### New Capabilities

- `customer-api-keys`: the observable lifecycle of a PAT — issuance (by an authenticated human),
  scoping, expiry, rotation, revocation, verification of a presented key, and the on-behalf-of audit
  binding.
  - **Critical concern (security — secret storage & verification):** key secrets MUST be stored and
    verified as **hashed** secrets (never plaintext), and the hashing/verification MUST NOT be
    hand-rolled. Build-vs-adopt deferred to `/opsx:decide`.
  - **Critical concern (correctness — effective authority):** the key's authority MUST be the creator's
    **live** memberships ∩ key scopes — nexus-resolved and revocation-consistent, never key-asserted.

### Modified Capabilities

> These use **ADDED** requirements (additive paths), not MODIFIED rewrites, so they merge cleanly with
> `normalized-principal`'s deltas at sync time. They assume `normalized-principal` is synced first.

- `nexus-native-authorization`: add the **apikey resolution path** — `Workspace(membership ∩ scopes)`
  with an on-behalf-of subject.
- `identity-contract-signing`: the contract additionally carries `principal_kind: apikey` and an
  `on_behalf_of` claim.

> Extends `principal-model` (introduced by `normalized-principal`) with the apikey authenticator. That
> capability is not yet in `openspec/specs/`, so it carries **no delta here** — the apikey
> authenticator's behavior lives in the `customer-api-keys` capability and plugs into the seam.

## Impact

- **Data model / store:** a new `identity.api_keys` table (key-id, **hashed** secret, creator `sub`,
  scopes, `expires_at`, `status`, rotation lineage), projected and watched like `routing.memberships`
  for live revocation.
- **Code:** `identity-rs/core` (an `ApiKey` authenticator + a scope-intersection resolver alongside the
  membership resolver); `identity-rs/sidecar` (recognize the API-key credential, author `on_behalf_of`);
  a **key-management surface** (an authenticated issue/rotate/revoke endpoint — likely `authz-admin`).
- **Contract/docs:** `docs/box-consumer-contract.md` (`apikey` kind + `on_behalf_of`), key-management
  runbook.
- **Sequencing:** after `normalized-principal`; see its `design.md` ADR-10 for the family sync order and
  contract-claim ownership.

## Open questions (resolve in `/opsx:decide` before implementing)

1. **Credential presentation** — how a key is carried on the request (a distinct scheme/header, since a
   PAT is not a ZITADEL JWT that `jwt_authn` verifies) and **where it is verified** (edge vs sidecar).
2. **Hashing choice** — the adopted password/secret hash for key verification (build-vs-adopt).
3. **Scope vocabulary** — the shape of a key's scopes and how they intersect workspace memberships
   (per-workspace? per-permission? both?).
4. **Issuance surface** — which service owns create/rotate/revoke and how one-time secret display works.
