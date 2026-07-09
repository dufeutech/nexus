## 0. Gate (do first)

- [x] 0.1 Run `/opsx:decide` and record the ADR block in `design.md`. **Approved (carried from `b-floor-trust-hardening`):** Adopt OpenBao Transit, Mode B (local signing) via `vaultrs`.

## 1. Automated key rotation (`identity-contract-signing`)

- [ ] 1.1 Define a key-provider **port** (list versions / export public + private key material / rotate) and refactor `AppState.signer` + the JWKS from static one-key values to a swap-able active signer + a generated, republish-able key set. Keep the manual `SIGNING_KEY_PATH` PEM as a break-glass fallback provider.
- [ ] 1.2 Implement the **OpenBao Transit** adapter (Mode B) via `vaultrs`: versioned keys as `kid`, JWKS generated from Transit's exportable public keys (no hand-sync); the plane pulls key material and signs **locally** per request (no per-request Bao hop). Add a fake in-memory provider (generates EC P-256 keys) behind the port for tests.
- [ ] 1.3 Enforce the two-key overlap window ≥ `CONTRACT_TOKEN_TTL_SECONDS` + max clock skew so no in-flight token is rejected during rotation; retire the old version only after the window; support on-demand rotation for suspected compromise.
- [ ] 1.4 Wire OpenBao into deploy (`deploy/helm/identity-plane/templates/signing.yaml` + `values.yaml`, `deploy/compose/signing/`): Transit mount + key config + the plane's Bao auth/role; the manual `SIGNING_KEY_PATH` PEM stays a supported break-glass fallback.
- [ ] 1.5 Replace the manual procedure in `docs/runbook-contract-signing-keys.md` with the automated flow (keep the manual fallback documented for break-glass).
- [ ] 1.6 Tests (against the fake provider): a rotation publishes both keys during overlap and a token signed by either verifies; retirement only after TTL+skew; `kid`/JWKS stay consistent across a rotation; startup falls back to the PEM when the provider is unreachable.

## 2. Verify & close

- [ ] 2.1 Run the full identity-rs test suite; confirm clippy-clean.
- [ ] 2.2 Validate end-to-end against a **live OpenBao**: one clean automated rotation (new `kid` published → signs → old retired after TTL+skew), a box verifies tokens from either key during overlap, and the `service-slo-policy` burn-rate instrument shows no hot-path latency regression (local signing).
- [ ] 2.3 Run `openspec validate --change automate-signing-key-rotation`; then `/opsx:sync` the delta spec and `/opsx:archive`.
