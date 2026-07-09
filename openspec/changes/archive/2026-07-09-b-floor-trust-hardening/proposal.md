## Why

The edge→box trust boundary has one anti-bypass control — an L3 NetworkPolicy — and its most
security-sensitive signals are the least protected. The two headers that gate *"is this user cut
off right now"* (`x-user-entitlements`, `x-user-suspended`) ride **bare, unsigned trust**; the
edge's client-header strip is a **denylist**, so any trusted header nobody remembered to enumerate
is forgeable. (A third B-floor gap — signing keys rotate by a **manual openssl runbook** — is
addressed in the sibling change `automate-signing-key-rotation`, split out because it is a larger
key-management workstream that needs a live OpenBao to validate.) None of
this depends on going multi-region — it is pure hardening ROI that carries over regardless. It is
the "B-floor" tranche isolated in `openspec/changes/platform-ha-and-hardening/EXPLORATION.md §1`,
sequenced to land now that the observability instrument (tranche A, `service-slo-policy`) has
shipped and can verify these changes are safe. Cross-region mTLS (B-gate) and the multi-region
program (D) stay parked.

## What Changes

- **Close the bare-trust gap on the revocation-sensitive headers.** A box SHALL be able to trust
  that `x-user-entitlements` and `x-user-suspended` were authored by nexus and were **not forged**
  by a client or on-path party — while preserving their freshness guarantee (they exist precisely
  *because* they must reflect a live revocation decision, which is why the signed identity contract
  deliberately excludes them today). Whether this is realized by extending the signed contract
  (accepting a staleness window bounded by the token TTL) or by a box-side cross-check that keeps
  them live is a build-vs-adopt / design tension deferred to `/opsx:decide`.
- **Flip the edge trusted-header strip from denylist to allowlist.** The edge SHALL default-drop
  the entire client-supplied trusted-header family and pass only an explicitly enumerated safe set,
  so completeness stops being a maintenance invariant — a newly added trusted header a box reads is
  safe-by-default instead of forgeable-until-someone-adds-it-to-the-denylist.
- **Non-goals (explicitly out of scope):** edge↔box mTLS, replacing the `pg_notify` invalidation
  transport, and any multi-region / DB (CNPG) work — these are B-gate + D, parked for a later
  change. **Automated signing-key rotation was split into its own change**
  (`automate-signing-key-rotation`): it is a larger key-management workstream that depends on a live
  OpenBao to validate end-to-end and, by design, lands independently (the manual `SIGNING_KEY_PATH`
  PEM stays the break-glass fallback throughout).

## Capabilities

### New Capabilities
- `identity-revocation-integrity`: A box can trust that the revocation-sensitive headers
  (`x-user-entitlements`, `x-user-suspended`) are nexus-authored, unforgeable, and fresh — closing
  the gap that today leaves the "is this user cut off right now" signal on bare network trust,
  without sacrificing the liveness that made them unsigned in the first place.
- `edge-trusted-header-strip`: The edge admits client-supplied headers in the trusted family only
  by explicit allowlist and default-drops the rest, so no un-enumerated trusted header can reach a
  box — replacing the denylist whose completeness was an unbounded maintenance invariant.

### Modified Capabilities
- _(none — the `identity-contract-signing` automated-rotation delta moved to
  `automate-signing-key-rotation`.)_

## Impact

- **Identity plane (sidecar):** `identity-rs/core/src/contract.rs` (signed `entitlements`/`suspended`
  claims) and `identity-rs/sidecar/src/{signer.rs,main.rs}` (mint the claims; retire the bare
  `x-user-entitlements`/`x-user-suspended`/`x-user-roles` mirrors).
- **Edge:** the authoritative allowlist prefix-strip in the tenant-router ext_proc
  (`routing-rs/tenant-router/src/main.rs`); the `edge/envoy.yaml` + mirrored configmap denylists and
  the sidecar defense-in-depth re-strip demoted to coarse layers.
- **Docs:** `docs/box-consumer-contract.md` / `docs/box-signing-handoff.md` — boxes read
  entitlement/suspension from the verified contract claim and must not cache past `exp`.
- **Verification:** the shipped `service-slo-policy` burn-rate instrument (tranche A) is the safety
  net for confirming these boundary changes don't regress the hot path.
- **No API/behavior change for well-behaved clients;** the header-strip flip is observable only to a
  client that was smuggling trusted-family headers (which was always a misuse).
