## 1. Build-vs-adopt decisions (run /opsx:decide first)

- [x] 1.1 Record the D1 decision (edge→backend origin enforcement mechanism) via `/opsx:decide` into design.md — **approved: Adopt Kubernetes NetworkPolicy**
- [x] 1.2 Record the D2 decision (JWT trust-anchor integrity mechanism) via `/opsx:decide` into design.md — **approved: Adopt Envoy upstream TLS (`zitadel.jwksTls`)**

## 2. edge-origin-trust — make the invariant explicit and enforced

- [x] 2.1 Ship the chosen edge→backend origin-enforcement control for the Helm topologies (`deploy/helm/edge-platform`, `deploy/helm/identity-plane`), mirroring the existing control-plane NetworkPolicy pattern — `templates/networkpolicy-backend.yaml` in both charts; compose lab twin = internal `edge-backend` network
- [x] 2.2 Ensure the origin control is templated as required-by-default; a topology rendering identity enrichment without it fails render/lint rather than shipping open — render guards + `scripts/helm-guards-test.sh` matrix in CI
- [x] 2.3 Add a deployment/e2e check that a direct-to-backend request bearing forged `x-identity-contract`+scope headers is refused before reaching backend logic — `tenancy-edge-e2e.sh` §6 (probe from the default network must fail to connect)
- [x] 2.4 Update design/RFC docs that describe the stamp as a bypass detector to describe it as a drift signal, pointing at edge-origin-trust for the real control — edge configmaps (all 3 charts), `edge/envoy.yaml`, `deploy/compose/envoy/envoy.yaml`, sidecar `main.rs`

## 3. edge-trust-anchor-integrity — protect the JWKS fetch

- [x] 3.1 Implement the dormant `zitadel.jwksTls` value: configure the JWKS upstream over TLS with server-cert verification in both stamping edge configmaps — UpstreamTlsContext (trusted CA + SNI + SAN pin) on `zitadel_jwks`
- [x] 3.2 Make an edge configured to fetch the trust anchor over an unprotected channel on an untrusted path fail closed (refuse to render/start), not silently trust it — render guard requires `jwksTls.enabled` or the explicit `jwksPlaintextTrustedPath` assertion
- [x] 3.3 Add a test/assertion that an on-path substituted JWKS response is not adopted — `scripts/helm-guards-test.sh` asserts the rendered cluster pins CA + SAN (the handshake rejects a substituted responder before any keys are read)
- [x] 3.4 Document the BREAKING migration for deployments currently on plaintext JWKS — `deploy/README.md` "BREAKING — upgrading to the fail-closed edge guards"

## 4. identity-workspace-authz — reconcile the stamp contract

- [x] 4.1 Confirm the edge marks routes as enriched vs non-enriched consistently (ext_proc enabled/disabled per-route) so the backend can apply the scoped "reject absent stamp" rule — identity-plane's hardcoded `/public` replaced with the same values-driven `edge.publicPaths` loop edge-platform uses; lab `/public` annotated as the explicit designation
- [x] 4.2 Ship the explicit non-enriched designation as a fail-closed default: an explicit allowlist of non-enriched routes (derived from or asserted against the per-route ext_proc edge config, so the two cannot drift), with every route not on it treated as identity-enriched — `edge.publicPaths` IS the single source the per-route config renders from; `helm-guards-test.sh` asserts N entries → exactly N per-route disables
- [x] 4.3 Add an e2e assertion: a public (non-enriched) route reaches the backend unstamped and is served as anonymous, NOT rejected for a missing stamp — `tenancy-edge-e2e.sh` §4
- [x] 4.4 Add a negative assertion: a route absent from the non-enriched designation that receives a stampless request is rejected (fails closed), not served as anonymous — `tenancy-edge-e2e.sh` §5 (enriched route with enrichment down is refused; /public keeps serving)
- [x] 4.5 Add an assertion: any request presenting `x-workspace-*`/`x-user-*` without a valid stamp is rejected on any route — `tenancy-edge-e2e.sh` §4 (edge projection: forged scope stripped on the unstamped route, so scope-without-stamp never reaches a backend)

## 5. Test backfill — bring every requirement under an automated test

- [x] 5.1 Author the authenticated-member positive e2e (real ZITADEL JWT + seeded membership) asserting emitted `x-workspace-id`/`x-user-type`/`x-user-role` equals the resolved workspace; make the fixture health-gate + retry the IdP so it is not a flake source — `scripts/tenancy-edge-auth-e2e.sh`: discovery-gated + retried fixture (machine user w/ JWT access-token type → client_credentials JWT → seeded staff/admin membership), positive scope assertions, plus a revocation assertion proving the scope is membership-derived
- [x] 5.2 Add `http-request-resilience` tests across the four HTTP servers: a slow handler yields the timeout status; a long ext_proc-style stream is exempt from the request timeout — each binary's timeout wiring extracted into a testable `resilient()`/`request_timeout()` pair; slow→408, fast→200, finite-default tests in all four; the streaming exemption exercised end-to-end in the sidecar (real tonic ext_proc served on an ephemeral port, stream outlives the HTTP bound)
- [x] 5.3 Add an edge e2e assertion for encoded path traversal: `/public%2f..%2fadmin` (and similar) does not downgrade a protected route to public — `n4-e2e.sh` §4, four traversal spellings with `--path-as-is`
- [x] 5.4 Add a store test asserting a workspace transfer preserves `plan` and switches the payer to the new account (workspace-tenancy R4) — `transfer_preserves_plan_and_switches_payer_to_the_new_account` in `routing-rs/store-postgres/tests/integration.rs`; both stores' integration tests also serialized behind a process-wide lock so they are safe under CI's default parallel `cargo test` (and a pre-existing broken watch test, surfaced by actually running them, fixed to match the compacted-feed contract)

## 6. Reference topology parity + CI

- [x] 6.1 Fix root `docker-compose.yaml`: control-plane satisfies the C16 guard with auth enabled — a generated or `.env`-provided `CONTROL_AUTH_TOKEN` (NOT `CONTROL_AUTH_DISABLED=true`, which would break the fail-closed/production-parity goal the e2e gate validates against) — so `docker compose up` from repo root boots — documented lab default `zitadel-lab-dev-token`, overridable via env; seed + e2e scripts send the bearer
- [x] 6.2 Add a zitadel/edge startup-order or health-gate fix so the full stack (incl. the authenticated e2e) comes up deterministically — healthchecks on control-plane/tenant-router/sidecar (wget /healthz); envoy + seed gate on `service_healthy`
- [x] 6.3 Wire CI to provision a throwaway Postgres and set `STORE_PG_TEST_URL` so the integration tests run instead of silently skipping — postgres service container in the cargo-test job, both workspaces
- [x] 6.5 (D7) Single-source the ZITADEL issuer/endpoint across edge and workers: lab defaults aligned on 8080 (edge issuer/JWKS literals ↔ compose `ZITADEL_EXTERNALPORT` ↔ worker `ZITADEL_HOST`), with a CI assertion in `helm-guards-test.sh` that they cannot silently drift again
- [x] 6.4 Add both e2e scripts (anonymous + authenticated) to CI as a release gate against the booted reference stack — `e2e-gate` job: clean-checkout `docker compose up --build` (masterkey given a lab default so no hidden .env step), readiness-polled, then tenancy + n4 + authenticated suites; logs dumped on failure

## 7. Verify the gate

- [x] 7.1 Run the full e2e suite (anonymous + authenticated) against a clean `docker compose up` and confirm all green — **42/42**: tenancy 17/17 (incl. non-enriched designation, fail-closed outage probe, direct-to-backend origin refusal), n4 14/14 (incl. encoded traversal, forged x-auth-required, invalid-credential-on-public), authenticated-member 11/11 (real ZITADEL JWT, seeded membership, revocation). Run surfaced and fixed: unverified seed domains (control plane rightly ignores inline `verified:true` → lab `routing-verify-seed` one-shot), a CPAUTH word-splitting bug silently de-authenticating every admin call in all three scripts, and a spec-precision issue (routing-plane `x-workspace-id` tenant context vs identity attribution) folded back into the delta spec
- [x] 7.2 Re-run the spec→test coverage audit and confirm every requirement across all specs has an automated test at its stated level — audit: 24 requirements; gaps closed this session (invalid-credential-on-public e2e, forged x-auth-required e2e, gate fail-safe shape render assertions, domain-alias + idempotent-provision store tests). Two acknowledged residuals, both out of nexus's test surface by design: the BACKEND's own absent-stamp rejection (the consuming box's contract per Non-Goals) and the single-writer projection invariant (architectural, not behaviorally testable in-repo)
- [x] 7.3 Confirm the two HIGH design findings are closed — (1) stamp reframed as drift signal in specs/configs/code comments AND the real control shipped: required-by-default backend-origin NetworkPolicy (Helm) + internal edge-backend network (lab) + refusal probes (render + e2e §6, both green); (2) JWKS integrity: `zitadel.jwksTls` implemented (UpstreamTlsContext, trusted CA, SNI + SAN pin), plaintext-without-assertion refuses to render, BREAKING migration documented in deploy/README.md — all guard assertions green (31/31)
