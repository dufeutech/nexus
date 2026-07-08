> Prerequisite: `normalized-principal` implemented and synced (the principal seam, mint guard, and
> `principal_kind` claim). These tasks build on it. See `normalized-principal/design.md` ADR-10.

## 1. Key store & migration (adapter)

- [x] 1.1 Add an `identity.api_keys` migration (`.sql`): key-id, hashed secret, creator `sub`, scopes,
      `expires_at`, `status`, rotation lineage, timestamps. Index for lookup by key-id.
- [x] 1.2 Implement a read-only `ApiKeyReader` adapter over the store (project active, unexpired keys),
      mirroring `PgSourceMembershipReader` (`SELECT`-only pool).
- [x] 1.3 Wire the key store into the live change feed (LISTEN/NOTIFY) so revocation/expiry propagate
      within seconds, reusing the `watch_store` pattern.
      > Implemented as a **live per-request SELECT** (`status='active' AND unexpired`) instead of a
      > resident cache + feed — revocation/expiry then take effect on the **next request** (stronger
      > than "within seconds"), and a large per-request-miss key set is the wrong shape for a resident
      > map. The `api_key_changes` NOTIFY trigger + channel ship for a future opt-in cache. See
      > design.md `/opsx:decide` "Live revocation without a resident cache".

## 2. Hashing (adopted adapter)

- [x] 2.1 Per `/opsx:decide`, add the chosen password-hash crate behind a `SecretHasher` port
      (`hash`, `verify`). No hand-rolled comparison.
- [x] 2.2 Unit-test hash/verify, including reject-on-mismatch and constant-time verify guarantees.

## 3. Core — apikey authenticator & resolver

- [x] 3.1 Define the `ApiKeyAuthenticator` port that turns a presented secret into a candidate
      `Principal { kind: apikey, subject: key-id, on_behalf_of: creator-sub }`.
- [x] 3.2 Implement `ScopeIntersectionResolver`: compose the existing `MembershipResolver` for the
      creator with the key's scopes → `Authority::Workspace(membership ∩ scopes)`; empty = fail closed.
- [x] 3.3 Unit-test intersection: subset, revocation cascade, no-intersection rejection, scope never
      widens beyond creator.

## 4. Sidecar — credential extraction & authoring

- [x] 4.1 Add the API-key branch to the authenticator chain (after the JWT branch): recognize the
      credential scheme, extract the opaque secret, hand it to the authenticator.
- [x] 4.2 On a resolved apikey principal, author `on_behalf_of` and let the generalized mint guard mint
      the contract with `principal_kind: apikey`.
- [x] 4.3 Ensure a revoked/expired/unresolved key strips all acting-scope headers and mints no contract
      (fail closed), matching the human unresolved path.

## 5. Contract claims (ADDED delta)

- [x] 5.1 Extend `ContractClaims` with `on_behalf_of: Option<String>` (skip-if-none); set `principal_kind`
      to `apikey` for key principals. Own only these claims (no `plan`, no platform claims).
- [x] 5.2 Assert non-key principals omit `on_behalf_of`.

## 6. Key-management surface (issue / rotate / revoke)

- [x] 6.1 Add an authenticated issue endpoint (human-only): create key, persist hash, return secret once.
- [x] 6.2 Add rotate (supersede under lineage, no widening) and revoke (flip status) endpoints.
- [x] 6.3 Enforce "a key may not exceed its creator" at issuance and at resolve time.

## 7. Audit & docs

- [x] 7.1 Emit audit records carrying both key-id and creating user for every key-authenticated request.
- [x] 7.2 Update `docs/box-consumer-contract.md` (apikey kind + `on_behalf_of`) and add a key-management
      runbook.

## 8. Verification

- [x] 8.1 End-to-end: issue a key → call through the edge → box receives an `apikey` contract with
      `on_behalf_of` → revoke → next call rejected within seconds.
- [x] 8.2 Negative: expired key, scope outside creator memberships, creator-membership revoked mid-flight
      — all fail closed.
