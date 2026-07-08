> Decisions settled at `/opsx:decide` (see `design.md` Decisions gate): platform-service authN =
> **K8s projected SA token via a 2nd Envoy `jwt_authn` provider**; scope registry = **Postgres
> `platform.services` + reuse the LISTEN/NOTIFY projection**. Family sync order: this change first
> (ADR-10).

## 1. Core — the normalized Principal

- [x] 1.1 Introduce a `Principal { kind: PrincipalKind, subject, on_behalf_of: Option<_>, authority:
      Authority }` type in `identity-rs/core`; `PrincipalKind ∈ {User, ApiKey, Service}` (ApiKey defined
      now, wired later by `customer-api-keys`).
- [x] 1.2 Define `Authority = Workspace(ResolvedMembership) | Platform(PlatformScope)`; `PlatformScope`
      is a named-permission set (least-privilege), not a boolean.
- [x] 1.3 Keep `PrincipalKind` orthogonal to `MemberType` (do not add `service` to `MemberType`).
- [x] 1.4 Unit-test principal construction for each kind and both authority variants.

## 2. Platform-service registry (adapter — Rent Postgres + reuse projection)

- [x] 2.1 Add a `platform.services` migration (`.sql`): `service_id`, permission set, `status`,
      timestamps. Index by `service_id`.
- [x] 2.2 Implement a read-only `PlatformServiceReader` port over Postgres (project `active` services
      only; `SELECT`-only pool), mirroring `PgSourceMembershipReader`.
- [x] 2.3 Wire it into the existing `watch_store` LISTEN/NOTIFY feed so revocation/permission changes
      propagate within seconds; unavailable store → fail closed (`must_fail_closed`).
      _(Impl: a resident-snapshot watcher `watch_platform_services` + `PgPlatformServiceReader::watch_active`
      LISTEN feed; cold start with the store down leaves the map empty → services fail closed.)_
- [x] 2.4 Implement `resolve_platform_scope(service_id)` → `Authority::Platform`; absent/inactive = None
      (fail closed). _(`AppState::resolve_platform_scope`.)_

## 3. Edge — second authN provider (Adopt: K8s SA token via `jwt_authn`)

- [x] 3.1 Add a second `jwt_authn` provider in `edge/envoy.yaml` for the service token (issuer +
      `remote_jwks`), selected per-route via `requires_any` alongside the human `oidc` provider.
      _(Added `service_account` provider to `edge/envoy.yaml` + `deploy/compose/envoy/envoy.yaml`;
      catch-all rule now `requires_any` oidc|service_account.)_
- [x] 3.2 Tighten `audiences` on the human `oidc` provider (was unrestricted) — independent hardening.
      _(DECIDED: NOT enabled — redundant under a single-audience edge. The `aud` check only matters when
      one issuer serves multiple audiences; here the edge is ZITADEL's sole relying party (boxes verify
      the nexus contract, not the raw token), so the `iss` pin already fully scopes tokens. Mechanism +
      instructions kept COMMENTED in both envoy configs, pointing at ADR-5a in design.md. Revisit if a
      second first-party audience appears.)_
- [x] 3.3 Provide a compose-dev issuer/JWKS stub so the mechanism is exercisable without a cluster
      (only the issuer differs from prod; verification path is identical).
      _(Dev issuer `https://sa.nexus.local` + inline `local_jwks` stub; prod swaps to `remote_jwks` →
      cluster OIDC JWKS. Verification path identical.)_

## 4. Sidecar — authenticator chain & generalized mint

- [x] 4.1 Turn `extract_identity` (`main.rs:253-274`) into an authenticator chain: human JWT branch →
      `User`; service-token branch (2nd provider metadata) → `Service`. Emit the normalized `Principal`.
      _(`extract_identity` + new `extract_service` reading `SVC_PAYLOAD_KEY`; human branch wins.)_
- [x] 4.2 Branch resolution on kind: `User` → `resolve_membership` (existing); `Service` →
      `resolve_platform_scope` (new). _(Kind-branched `enrich` producing an `Enriched` bundle.)_
- [x] 4.3 Generalize the mint guard (`main.rs:520-539`) from "has membership" to "has resolved
      authority (Workspace or Platform)"; mint for a platform service using the acting `x-workspace-id`.
- [x] 4.4 Author `x-user-type: service` (or the principal-kind header) and strip acting-scope headers on
      the unresolved path (fail closed), matching the human unresolved behavior.

## 5. Contract claims

- [x] 5.1 Add `principal_kind` to `ContractClaims` (`contract.rs:24-57`); own only this + the platform
      permission claims (no `plan`, no `on_behalf_of` — those are sibling changes per ADR-10).
      _(Added `principal_kind` + `permissions`; made `member_type`/`role` `Option`.)_
- [x] 5.2 For a `Platform` authority, populate acting workspace + platform permissions; omit
      `member_type`/`role`. Keep signing unchanged (ES256 / `jsonwebtoken`, ADR-9).
      _(signer `MintInput` generalized; `service_contract_conveys_platform_authority_not_a_member_role`.)_
- [x] 5.3 Assert a caller cannot assert its own kind/authority (nexus-authored only).

## 6. Consumer contract & docs

- [x] 6.1 Update `docs/box-consumer-contract.md`: the `service` principal kind, how a box authorizes it
      (kind → policy), and the platform-permission shape — the counterpart to the human `x-user-*`
      contract. _(New §1a-ter principal-kind table; `x-user-type` now `staff|customer|service`;
      `principal_kind`/`permissions` in the contract-claims section.)_

## 7. Verification

- [x] 7.1 End-to-end (compose): a stubbed service token → through the edge → box receives a contract
      with `principal_kind: service` + acting workspace + platform permissions; a staff token still
      resolves as before. _(In-process Rust tests cover the resolution + minting + header authoring;
      `scripts/service-identity-e2e.sh` + `scripts/mint-dev-sa-token.py` drive the LIVE edge. The live
      compose run is a CI/manual step per the apply plan.)_
- [x] 7.2 Fail-closed: a verified service token for a service **absent from the registry** mints no
      contract and is rejected; revoking a registered service denies it within seconds.
      _(Rust: `resolved_service_mints_a_contract_unresolved_fails_closed`, `resolve_platform_scope_...`;
      e2e case 2 (unregistered) + a documented revoke check. Revocation liveness = the NOTIFY-reload feed.)_
- [x] 7.3 Regression: human user/staff/customer paths and the anonymous path are unchanged.
      _(User path is behavior-preserving — all pre-existing sidecar/signer tests pass unchanged;
      existing `contract-signing-e2e.sh` / `tenancy-edge-auth-e2e.sh` exercise the human path.)_
