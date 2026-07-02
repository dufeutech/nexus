## Why

An end-to-end verification pass (anonymous edge e2e: 16/16 green) confirmed the happy path works, but also surfaced gaps that block a truthful "production-ready" claim: two HIGH-severity design gaps where a security boundary is asserted in a spec but not actually provided, one spec whose behavior is contradicted by the deployment config, whole requirements with no automated test, and a reference topology that no longer boots. This change is the gate that closes those gaps before a release is cut — while the findings are concrete and named, not after an incident makes them concrete for us.

## What Changes

- **Reframe the `x-identity-contract` stamp** from an asserted *bypass/authentication boundary* to what it actually is — a drift/misconfiguration detector — and make the real control it depends on (backends reachable only via the edge) an explicit, testable invariant instead of an unstated assumption.
- **Require integrity protection for the edge's JWT trust anchor (JWKS)** so a substituted-key MITM cannot forge verification — today the fetch is plaintext HTTP, an acknowledged full-auth-bypass vector gated only behind an unimplemented TODO. **BREAKING** for any deployment currently pointing the edge at a plaintext JWKS endpoint over an untrusted hop.
- **Reconcile the "reject absent contract stamp" rule with public/degradable routes** that legitimately reach the backend unstamped, so the invariant has no silent exceptions.
- **Backfill verification** so every spec requirement is exercised by an automated test: the authenticated-member positive scope path (e2e, not unit-only), the request-timeout / ext_proc-exemption resilience guarantees (currently zero tests), encoded-path-traversal downgrade resistance, and plan/payer travel on workspace transfer.
- **Restore the reference local topology to a bootable, fail-closed state** so the documented local e2e path works and matches the production auth posture.
- **Eliminate config drift on shared endpoints** — the ZITADEL issuer/host is duplicated across the edge (token verification) and the workers (sync) with a mismatched default (`8080` vs `8088`), so the edge can reject tokens the workers happily synced ("sync works but every authenticated request 401s"). Define deployment-varying values once and reference them instead of embedding drifting literals; keep protocol invariants (header names, NOTIFY channel names, contract version) as owned code constants.

## Capabilities

### New Capabilities
- `edge-origin-trust`: Tenant backends accept identity-enriched requests only via the edge; the network path is the enforcing control, and the `x-identity-contract` stamp is defined as a drift/misconfiguration signal — explicitly NOT an authentication or anti-bypass boundary. Names the deployment invariant the entire trusted-header model rests on. *(Critical/security concern — the edge→backend origin-enforcement mechanism is a build-vs-adopt decision deferred to /opsx:decide.)*
- `edge-trust-anchor-integrity`: The edge's JWT signature-verification keys are obtained over an integrity-protected channel such that an on-path attacker cannot substitute signing keys; a non-integrity-protected trust-anchor fetch fails closed rather than shipping silently. *(Critical/security concern — the integrity mechanism is a build-vs-adopt decision deferred to /opsx:decide.)*

### Modified Capabilities
- `identity-workspace-authz`: Downgrade the stated security semantics of the contract stamp to reference `edge-origin-trust` (stop asserting it proves edge origin), and add an explicit carve-out reconciling the "backend rejects an absent stamp" requirement with anonymous/public/degradable routes that carry no stamp by design.

## Impact

- **Specs**: new `edge-origin-trust`, new `edge-trust-anchor-integrity`, modified `identity-workspace-authz`. (`edge-auth-gate`, `http-request-resilience`, `workspace-tenancy` requirements are unchanged — only their test coverage is.)
- **Deploy/config**: edge configmaps in `deploy/helm/edge-platform` and `deploy/helm/identity-plane` (JWKS transport); a NetworkPolicy / origin control for edge→backend (currently only the control-plane ships one); root `docker-compose.yaml` control-plane auth wiring (the boot regression); the ZITADEL issuer/endpoint, currently duplicated between `edge/envoy.yaml` (jwt_authn `issuer` + `remote_jwks`) and the worker env (`ZITADEL_HOST`) with the `8080`/`8088` mismatch — consolidated to one source.
- **Tests**: new e2e assertions for the authenticated-member path (requires the ZITADEL JWT + seeded-membership fixture), resilience/timeout tests across the four HTTP servers, an encoded-traversal edge assertion, and a transfer-preserves-plan/payer store test. CI must run the Postgres integration tests (they silently skip unless `STORE_PG_TEST_URL` is set).
- **Docs**: the design docs that describe the stamp as a bypass detector.
- **No application-code API changes** to the request hot path beyond the resilience/edge config; the stamp reframing is semantic + deployment-enforcement, not a wire-format change.
