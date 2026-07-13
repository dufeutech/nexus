# admin-action-audit — proposal

## Why

The two admin surfaces (authz-admin `:9300`, control-plane `:9400`) author the most
security-sensitive facts in the platform — roles, entitlements, suspension, api keys,
tenancy, memberships, routing rules, domains — yet each is gated by a single shared
bearer token and keeps no durable record of what was done, by whom, or when. Every
mutation is attributable only to "something holding the token." SOC 2 (CC6.1–6.3 access
provisioning, CC7.2 denial monitoring, CC8.1 change management) requires an
administrative audit trail with actor attribution, and the data plane nobody can forge
already has better attribution than the control plane that governs it.

## What Changes

- Every mutating admin call on both surfaces produces a durable, append-only audit
  event recorded **in the same transaction as the mutation** — an unrecorded admin
  mutation does not commit (fail-closed, the opposite of the fail-open telemetry path,
  which this ledger deliberately does not ride).
- Admin credentials become **individually identifiable**: each caller (signup broker,
  ops CLI, CI) holds its own named token; the shared single-token mode is retired for
  attribution purposes. **BREAKING** for deployments that pass one shared token to
  multiple callers — each caller needs its own credential.
- An authenticated admin caller MAY assert the human operator it acts for; the
  assertion is recorded verbatim, marked as asserted, and never used for authorization.
- Failed admin authentications (401s) are recorded as denial events.
- Non-HTTP administrative events are covered: the bootstrap-admin startup grant is
  recorded; signing-key rotation is explicitly delegated to the secrets manager's own
  audit trail (referenced, not duplicated).
- Idempotency-key replays are recorded as events (`created:false`) — attempted
  re-provisioning is audit-relevant.
- Each surface exposes a read/query endpoint over its own ledger (by time, actor,
  target) plus an export path, providing the evidence-of-review enabler.
- Audit events carry typed, self-describing ids (`aev_` prefix, time-ordered),
  consistent with the platform id scheme.

## Capabilities

### New Capabilities

- `admin-action-audit`: the administrative audit ledger — event vocabulary and record
  shape (actor, target, outcome, correlation), same-transaction fail-closed recording,
  append-only integrity and retention, denial events, query/export surface, and
  individually identifiable admin credentials with optional recorded-but-untrusted
  operator assertion.

Critical concerns whose realization is a build-vs-adopt decision (deferred to
`/opsx:decide`): ledger storage & append-only integrity enforcement; named admin
credential issuance/rotation (relationship to the existing customer-api-keys
machinery); out-of-band database access auditing (compensating control); export
format for external audit consumers.

### Modified Capabilities

<!-- none — the ledger wraps existing surfaces; no existing spec's requirements change.
     Telemetry specs are unaffected: this ledger is not telemetry and does not use the
     collection layer. -->

## Impact

- **Code**: routing-rs control-plane (`app.rs` auth layer, `tenancy.rs` and domain
  handlers), identity-rs authz-admin service (auth layer, role/entitlement/suspension/
  apikey handlers), one migration per plane store (ledger table + insert-only grants),
  id minting (`aev_` type).
- **APIs**: new `GET /audit/events` (+ export) on both admin surfaces; all mutating
  endpoints gain in-transaction event writes; optional `x-acting-operator` request
  header; 401 paths gain denial recording.
- **Operations**: per-caller token provisioning replaces the two shared env tokens
  (migration path required); retention/export configuration; runbook updates
  (`admin-apis.md`, OpenAPI specs `openapi/authz-admin.yaml`,
  `openapi/control-plane.yaml`).
- **Compliance**: provides the SOC 2 CC6.x/CC7.2/CC8.1 administrative-action evidence;
  OpenBao audit device remains the record for signing-key custody events.
- **Unaffected**: request-time data plane (enrichment, contracts, headers), telemetry
  contracts (`box-telemetry-contract`, `edge-request-tracing`, `first-party-telemetry`),
  in-flight `custom-domains-tls` change (its endpoints join the event vocabulary;
  no conflict).
