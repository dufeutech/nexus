## 0. Gate (do first)

- [x] 0.1 Run `/opsx:decide` and record the ADR in `design.md`: formally **Adopt Cedar** as the policy engine (vs. keep the hand-rolled comparison / another engine), consistent with `authz-engine-strategy` EXPLORATION.md. Do not start section 2+ until recorded. → **Recorded as Decision 0 (approved).**

## 1. The PDP port (WHAT, in core)

- [x] 1.1 Add a vendor-agnostic `PolicyDecisionPoint` port to `identity-rs/core` (new module, e.g. `policy.rs`): a `decide(request) -> Decision { effect: Permit|Deny, reason }` contract, deny-by-default, with request types carrying principal/action/resource/context. No engine types in `core`.
- [x] 1.2 Define the decision request built from existing domain types — `AuthzFacts` (`core/src/authz.rs`) for the principal, `RouteRequirements` (the resolved `x-auth-*` requirements) for the resource — so the sidecar only translates, never decides.

## 2. The Cedar adapter (HOW, isolated crate)

- [x] 2.1 Create crate `identity-rs/policy-cedar` implementing the `PolicyDecisionPoint` port; add it to the `identity-rs` workspace with the `cedar-policy` dependency isolated here (not in `core`/`sidecar`). Match the workspace's strict lints (edition 2024, `panic="deny"`, `unwrap_in_result="deny"`).
- [x] 2.2 Author the parity Cedar **schema** + **policy** as data (`.cedar` files): the single permit per design Decision 2 — `requires_role`/`requires_entitlement` empty-string short-circuit, `aal >= min_aal`, deny-by-default; geo/plan/method/suspension present in schema but unreferenced (inert).
- [x] 2.3 Load + **validate** policies against the schema at startup via an adapter (path-configurable per environment; default set in-crate); a malformed/unvalidatable set fails closed (refuse to serve gated routes), never evaluates an empty/partial set.
- [x] 2.4 Map the engine result to the port `Decision`, carrying an auditable reason (which policy permitted, or "no permit"). Ensure a missing/unparseable attribute yields Deny (fail-closed), never Permit.

## 3. Wire into the sidecar enforcement point (parity)

- [x] 3.1 In `identity-rs/sidecar/src/main.rs`, change `enforce_route_requirements` (:564-577) to build the PDP request from the in-process Profile + `RouteRequirements` and call the port, mapping `Deny → forbidden_403()`. Keep the call at the **exact** existing 403 decision point (:1136-1143) — after the 503 fail-closed and after `hide_nonmember_as_404` (:1122/1128), so ordering is preserved.
- [x] 3.2 Keep `authorize_route` (:530-557) in place initially as the parity oracle; select the PDP via an adapter/flag so both paths can run in tests.
- [x] 3.3 Confirm requirement headers are still stripped before the backend (:674-679) and that the PDP path never leaks policy/context downstream.

## 4. Parity verification (the oracle)

- [x] 4.1 Add a parity test harness that runs the full gate input matrix (role/entitlement/AAL present·absent·mismatch, empty requirements, unparseable AAL, absent enrichment) through BOTH `authorize_route` and the PDP and asserts **identical** effects.
- [x] 4.2 Assert decision ordering: non-member of a private workspace-scoped route → 404 (unchanged); member lacking a required role → 403 (now via PDP); 503 fail-closed unchanged.
- [x] 4.3 Re-run and keep green the existing oracles: `router-core/src/auth.rs` matcher tests, sidecar `authorize_route`/`enforce_route_requirements`/AAL/response-shape/header-strip tests, control-plane `auth_route_validation_tests`, store `auth_route_requirement_fields_round_trip`.
- [x] 4.4 Test the PDP capability directly: deny-by-default, forbid-overrides-permit, fail-closed on missing/unparseable input, auditable reason present, and malformed-policy-set → fail closed at load.

## 5. Cut over & close

- [x] 5.1 Switch `enforce_route_requirements` to the PDP by default; remove `authorize_route` once the parity test subsumes it (or keep as an explicitly-labeled test oracle per the design Open Question).
- [x] 5.2 Ship policy files per environment (`deploy/helm/identity-plane`, `deploy/compose`) with the configured policy path; verify fail-closed on a deliberately malformed set.
- [x] 5.3 Confirm no hot-path latency regression on the sidecar plane using the `service-slo-policy` burn-rate instrument; run clippy clean across `identity-rs`.
- [x] 5.4 `openspec validate adopt-cedar-policy-gate`; then `/opsx:sync` the new capability spec and `/opsx:archive`.
