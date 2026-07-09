## Why

Signing-key rotation for the `x-identity-contract` is a **manual openssl runbook**
(`docs/runbook-contract-signing-keys.md`): an operator generates an EC P-256 PEM, hand-builds
the JWKS ConfigMap, keeps the `kid` in sync by hand, and performs a 4-step overlap by editing
files. There is no automation, no managed key custody, and no expiry tracking in code — so
rotation is error-prone and, in practice, rarely done.

This is the third tranche of the B-floor hardening, **split out of `b-floor-trust-hardening`**
(which shipped the revocation-integrity signing + the allowlist header strip). It was separated
because it is a distinct, larger key-management workstream that depends on a live **OpenBao**
instance to validate end-to-end, and by design lands independently: the manual `SIGNING_KEY_PATH`
PEM stays a supported break-glass fallback throughout, so this change is revertible on its own.
Cross-region mTLS (B-gate) and the multi-region program (D) stay parked.

## What Changes

- **Automate signing-key rotation / adopt managed key material.** Signing-key rotation SHALL no
  longer require a manual operator runbook; key material lifecycle (generation, overlap rotation,
  retirement) SHALL be automated. The mechanism was decided at `/opsx:decide` (carried over from
  the parent change): **Adopt OpenBao Transit, Mode B (the plane pulls key material and signs
  locally)** — see design.md Decision 1.
- **Generate the JWKS from Transit** rather than hand-syncing it, so the `kid` ↔ JWKS drift the
  manual runbook risks is eliminated: each Transit key version is a `kid`, and the published key
  set is derived from Transit's exportable public keys.
- **Preserve the in-flight overlap guarantee under automation:** both key versions stay published
  across an overlap window ≥ `CONTRACT_TOKEN_TTL_SECONDS` + max clock skew, so no in-flight token
  is rejected during rotation; support on-demand rotation for suspected compromise.
- **Non-goals (explicitly out of scope):** the revocation-sensitive-header signing and the edge
  allowlist strip (both landed in `b-floor-trust-hardening`); edge↔box mTLS; and any multi-region
  / DB (CNPG) work — B-gate + D, parked for a later change.

## Capabilities

### Modified Capabilities
- `identity-contract-signing`: Adds a requirement that signing-key rotation be **automated** and
  key material lifecycle **managed** (no manual runbook), tightening the existing "keys are
  published and rotated without breaking in-flight tokens" and runtime-secret requirements.

## Impact

- **Identity plane (sidecar):** the signer + key-loading path (`identity-rs/sidecar/src/signer.rs`,
  `build_signer`, `identity-rs/sidecar/src/jwks.rs`) move from a **static** one-key load to a
  **dynamic** rotation manager: the active signer and the published JWKS become swap-able across an
  overlap window. A new `vaultrs`-backed OpenBao Transit adapter behind a key-provider port; the
  manual `SIGNING_KEY_PATH` PEM path is retained as a break-glass fallback.
- **Ops / deploy:** OpenBao wired into `deploy/helm/identity-plane/templates/signing.yaml` +
  `values.yaml` and `deploy/compose/signing/` (Transit mount + key config + the plane's Bao
  auth/role); `docs/runbook-contract-signing-keys.md` replaced with the automated flow (manual
  fallback kept documented for break-glass).
- **Verification:** requires a live OpenBao to validate the rotation end-to-end; unit tests exercise
  the overlap/retire/`kid`-consistency invariants against a fake Transit port. The shipped
  `service-slo-policy` burn-rate instrument confirms the hot path (local per-request signing) does
  not regress.
- **No box-side change:** the JWKS contract and token shape are unchanged; only how nexus manages
  and publishes keys changes. Boxes keep fetching `/.well-known/jwks.json` and selecting by `kid`.
