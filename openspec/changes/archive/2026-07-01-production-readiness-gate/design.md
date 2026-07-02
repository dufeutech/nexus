## Context

A pre-release verification pass produced three artifacts of evidence: (1) both anonymous
edge e2e scripts pass 16/16 against a live stack; (2) a spec→test coverage audit; (3) a
design-soundness review. The green result covers the anonymous/negative path only. The
audit and review together identified the gaps this change closes. Current state that
constrains the design:

- The trusted-header model's real anti-forgery control (backends reachable only via the
  edge) is implemented today only for the control-plane admin API (one NetworkPolicy);
  edge→backend origin enforcement is unspecified and unshipped.
- The `x-identity-contract` stamp is an unsigned constant; the spec previously described it
  as proof of edge origin, which it cannot provide.
- Both stamping edges fetch ZITADEL JWKS over plaintext `http://`; TLS is an unimplemented
  `TODO(hardening)` behind an unused `zitadel.jwksTls` value.
- Several spec requirements are implemented but untested (`http-request-resilience` has zero
  tests; the authenticated-member positive path is unit-only; edge-auth-gate path-traversal
  R5 and workspace-tenancy transfer R4 are unasserted).
- The root `docker-compose.yaml` no longer boots: the control-plane's C16 refuse-to-start-open
  guard is not satisfied by that file (no `CONTROL_AUTH_TOKEN`/`CONTROL_AUTH_DISABLED`),
  though Helm and `deploy/compose` handle it correctly.

## Goals / Non-Goals

**Goals:**
- Make the deployment invariant the trusted-header model rests on explicit and enforced
  (`edge-origin-trust`), and stop overstating what the stamp provides.
- Guarantee the edge's JWT trust anchor cannot be substituted on the wire
  (`edge-trust-anchor-integrity`).
- Reconcile the "reject absent stamp" rule with legitimately unstamped public routes.
- Bring every spec requirement under an automated test, run in CI.
- Restore the reference local topology to a bootable, fail-closed state.

**Non-Goals:**
- Signing the identity-contract stamp / turning it into a real capability token — out of
  scope; the origin-enforcement control is the chosen mechanism, and the stamp stays a
  drift signal.
- Changing the `x-workspace-*`/`x-user-*` wire format or bumping the contract version.
- The backend's own enforcement of the stamp (that is the consuming service's contract);
  this change specifies what nexus emits and the deployment invariant, not backend code.
- Making everything configurable. Only deployment-varying values (endpoints, external
  domain, ports, tunables) become config; protocol invariants (header names, NOTIFY channel
  names, the identity-contract version) stay as owned code constants next to the concept that
  owns them. "Configurable" here means single-source, not universally externalized.

## Decisions

### Decision: D1 edge→backend origin enforcement — Adopt Kubernetes NetworkPolicy

- **Status**: approved
- **Why**: the native segmentation primitive covers the invariant (backend ingress
  restricted to the edge) with zero new dependencies, mirrors the control-plane admin-API
  policy already shipped, and its one weakness — a CNI that silently ignores policies — is
  covered by the required direct-to-backend e2e refusal probe (task 2.3). Compose topologies
  use the analog: internal networks. Current zero-trust guidance treats NetworkPolicy as the
  first-line control, with mesh mTLS as an additional layer, not a replacement.
- **Considered**: service-mesh mTLS (Istio Ambient/Linkerd) — cryptographically stronger
  workload identity, but a whole mesh's operational footprint for one invariant; documented
  as the upgrade path, not chosen. Signed/HMAC edge token verified by the backend (Build) —
  topology-independent but moves trust back into a header nexus must own end-to-end (keys,
  rotation, verify code), the exact failure mode this change removes from the stamp.
- **Isolation**: lives entirely in the deployment layer (Helm templates for
  `edge-platform`/`identity-plane`, compose network config); no application code sees or
  depends on the mechanism. The spec names only the abstract invariant; swapping to mesh
  mTLS later changes templates, not code or specs.

### Decision: D2 JWT trust-anchor integrity — Adopt Envoy upstream TLS for the JWKS fetch

- **Status**: approved
- **Why**: Envoy's first-class pattern — `UpstreamTlsContext` with a `validation_context`
  (trusted CA) and SNI on the `jwks_cluster` — integrity-protects the fetch as pure proxy
  config, implementing the dormant `zitadel.jwksTls` value with no custom fetch/verify/cache
  code, and key rotation keeps working through the existing `remote_jwks` cache. Fail-closed
  is satisfied by refusing to render/start an edge configured to fetch the anchor over an
  unprotected channel on an untrusted path.
- **Considered**: `local_jwks` pinning (Extend) — removes the runtime fetch entirely, but
  key rotation becomes a manual redeploy, a staleness/outage vector worse than the risk it
  removes. In-cluster trusted-hop assertion — plaintext allowed only where the IdP is
  genuinely in-cluster on an explicitly asserted path; retained solely as the documented
  lab-topology exception, not the mechanism.
- **Isolation**: lives in the two stamping-edge configmaps (Helm values →
  `zitadel.jwksTls`); the core and workers never see the transport choice. The spec states
  only "integrity-protected channel, fail closed"; the TLS wiring is swappable per topology.

### D3 — Public-route carve-out lives in the spec contract, not backend heuristics
Reconciliation is expressed as a route designation (enriched vs non-enriched) in the
`identity-workspace-authz` contract, so the "reject absent stamp" rule is scoped to enriched
routes. This keeps the rule a single source of truth rather than special-casing `/public`
prefixes in backend code. The designation is **fail-closed by default**: non-enriched status
exists only by explicit designation (an allowlist of non-enriched routes), and any route not
on it inherits the enriched "reject absent stamp" rule — so a route omitted by config gap or
typo fails closed instead of being served anonymously. The edge config already distinguishes
these routes (ext_proc enabled vs disabled per-route); the spec now names the distinction,
and the explicit non-enriched designation must derive from / be asserted against that same
per-route edge config so the two cannot drift.

### D4 — Test backfill is DO-only; no new requirements for the tested behaviors
`http-request-resilience`, `edge-auth-gate` R5, and `workspace-tenancy` R4 requirements are
unchanged — only their coverage is. Tests attach to the existing behavior: resilience tests
across the four HTTP servers (assert 408 on a slow handler; assert an ext_proc-style long
stream is exempt), an edge assertion for encoded traversal (`/public%2f..%2fadmin` must not
downgrade a protected route), and a store test asserting a transfer preserves `plan` and
switches the payer. The authenticated-member positive e2e reuses the fixture the
`tenancy-edge-e2e.sh` header already documents (a real ZITADEL JWT + seeded membership).

### D5 — Reference topology parity
The root `docker-compose.yaml` control-plane service is brought to parity with `deploy/compose`
and Helm: it must satisfy the C16 guard explicitly **with auth enabled** — a generated (or
`.env`-provided) `CONTROL_AUTH_TOKEN`, the same shape production uses — so `docker compose up`
from the repo root boots without a hidden manual step. `CONTROL_AUTH_DISABLED=true` is
rejected as the parity mechanism: this change's goal is a fail-closed reference topology that
matches the production auth posture, and the e2e release gate (D6/6.4) runs against this
stack — validating against an auth-disabled topology would give false confidence. This is
config parity, not a behavior change — the guard itself already works (it is what surfaced
the regression).

### D6 — CI actually runs the integration tests
The Postgres integration tests silently skip unless `STORE_PG_TEST_URL` is set. CI SHALL
provision a throwaway Postgres and set that variable, so "integration coverage" is real
rather than skipped-green.

### D7 — Single source of truth for the ZITADEL issuer/endpoints (correctness/drift)
The value Envoy's `jwt_authn` uses to validate the token `iss` (and to fetch `remote_jwks`)
and the value the workers use to reach/identify ZITADEL currently exist as two independent
literals that have already drifted (`8080` vs `8088`). Because verification (edge) and sync
(workers) sit on opposite sides of this value, drift is silent: sync succeeds while every
authenticated request 401s at the edge. **Recommendation: Adopt** the existing config
mechanisms as the single source — one Helm value / one compose `.env` key for the ZITADEL
issuer + endpoint, from which BOTH the edge configmap (`issuer`/`remote_jwks`) and the worker
env (`ZITADEL_HOST`/issuer) render — rather than introducing a new config system or leaving
two hand-maintained literals. Add a render-time/CI assertion that the edge issuer and the
worker issuer resolve to the same string, so this class of drift fails the build instead of
production. Boundary (per Non-Goals): this consolidation covers deployment-varying endpoints
only; header names, the `identity_changes`/`routing_membership_changes` NOTIFY channels, and
the `x-identity-contract` version remain owned code constants, single-sourced in code, not
turned into config.

## Risks / Trade-offs

- **[D1 origin enforcement crosses into tenant-owned backend infra]** → nexus can specify and
  ship the control for topologies it owns (Helm), and specify the invariant for those it does
  not; the spec makes the absence of the control a named misconfiguration rather than a silent
  default. It cannot enforce a control inside infra it does not deploy — documented as a
  deployment responsibility.
- **[D2 fail-closed could break an existing plaintext-JWKS deployment]** → this is the intended
  BREAKING behavior; migration is to configure TLS (or explicitly assert an in-cluster trusted
  hop). Called out in the proposal as BREAKING.
- **[Authenticated-member e2e depends on ZITADEL, which flaked during verification on a Docker
  DNS blip]** → the fixture must be resilient (health-gate + retry on the IdP) or the test is
  itself a flake source; the resilience backfill (D4) and a startup-order fix reduce this.
- **[Scope creep: this change bundles security-design fixes with test backfill and a config
  bug]** → they are grouped only as the release gate; D1/D2/D3 are the spec-changing core,
  D4/D5/D6 are mechanical. If review prefers, D4–D6 can split into a follow-up without blocking
  the security decisions.
