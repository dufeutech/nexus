## Why

The control plane's admin surface authenticates every caller as an individually
identifiable actor (named admin tokens, `admin-action-audit`) but authorizes nothing:
every accepted token can perform every admin action — including minting new admin
tokens and revoking existing ones. One leaked token is therefore a full control-plane
takeover with self-persistence, and the blast radius of the least-trusted caller equals
the most-trusted. The platform already has a decision layer whose contract says
enforcement surfaces obtain decisions from declarative policy rather than ad-hoc checks
(`authorization-policy-engine`, with the edge gate as "the first consumer") — the admin
plane is the anticipated second consumer, and connecting it closes the gap that
`admin-action-audit` (attribution without authorization) left half-finished.

## What Changes

- Every admin action on the control plane's admin surface is authorized against the
  authenticated actor's granted scope — after authentication, before the handler runs.
  Deny-by-default and fail-closed: an actor with no grant, an unresolvable grant, or a
  degraded decision input is denied, never waved through.
- Token administration (minting, revoking, listing admin credentials) becomes a
  distinguished scope that ordinary scopes do not include — an actor cannot escalate or
  persist by creating credentials unless explicitly granted that power.
- Scopes are attached to the admin credential at provisioning time and are readable in
  the audit trail; the authorization decision (including its reason) is recorded on the
  existing action/denial ledger, so a denied-but-authenticated action leaves an
  attributed trace, exactly as denied authentication already does.
- Migration is parity-first: existing tokens continue to work with full power at
  cutover (an explicit full grant), then narrow; no admin caller breaks on deploy.
- The decision mechanism is the platform's existing L2 policy layer
  (policy-as-data, not a hand-rolled permission check) — the concrete wiring is a
  design/decide concern.

## Capabilities

### New Capabilities

- `admin-plane-authorization`: scoped, deny-by-default authorization of authenticated
  admin actors on the control plane's admin surface — grant model, fail-closed
  evaluation, privileged separation of credential administration, and parity-safe
  migration. Critical concern (security): the decision evaluation itself is a
  build-vs-adopt call recorded at `/opsx:decide` (the platform's adopted L2 policy
  engine is the presumptive answer; do not hand-roll a second rule evaluator).

### Modified Capabilities

- `admin-action-audit`: the "denied admin access is recorded" requirement extends
  beyond rejected authentication — an authenticated actor denied by authorization SHALL
  also leave a ledger trace, attributed to the actor and carrying the decision reason.

## Impact

- **Code:** `routing-rs/control-plane` — the admin-token gate (`require_auth` /
  `resolve_actor` in `app.rs`), admin-token provisioning routes and store
  (`routing.admin_tokens` gains a grant attribute), and the audit ledger event model
  (a new authorization-denial event kind). The policy assets live as data files loaded
  via an adapter, consistent with the existing L2 policy deployment.
- **APIs:** admin-token provisioning gains a REQUIRED scope field (the spec refuses an
  unscoped mint — fail-closed, no implicit default), so mint callers must be updated —
  **BREAKING** for provisioning scripts; parity applies to existing *credentials*
  (full-grant backfill), not to unscoped mint requests. Admin routes can newly answer
  403 for authenticated-but-unauthorized callers — reachable only for operators who
  narrow a token's grant; cutover behavior for existing tokens is parity.
- **Specs:** new `admin-plane-authorization`; delta on `admin-action-audit`.
  `authorization-policy-engine` requirements are already enforcement-surface-agnostic
  and need no change — this adds a consumer, not a rule.
- **Ops:** a migration/backfill assigns the full grant to existing tokens; runbook note
  for narrowing grants and for the 503-on-unconfigured posture staying unchanged.
