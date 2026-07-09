## Context

Split out of `b-floor-trust-hardening` (which shipped the signed revocation-sensitive claims and
the allowlist header strip). Verified current state:

- **Signing.** One signer — `identity-rs/sidecar/src/signer.rs` (`jsonwebtoken`, ES256), minting
  `x-identity-contract` per request with a ~60s TTL (`CONTRACT_TOKEN_TTL_SECONDS`). Built ONCE at
  startup by `build_signer` in `identity-rs/sidecar/src/main.rs` from an operator-supplied EC P-256
  PEM at `SIGNING_KEY_PATH`, with a single `SIGNING_KID`. `AppState.signer` is a static
  `Option<Arc<Signer>>` read on the hot path.
- **JWKS.** `identity-rs/sidecar/src/jwks.rs` serves an operator-supplied JWKS document **verbatim**
  from `JWKS_FILE` (loaded once, static `Arc<String>`). The `kid` is kept in sync with the signer
  **by hand**.
- **Rotation.** A manual 4-step overlap runbook (`docs/runbook-contract-signing-keys.md`): generate a
  PEM, hand-build the JWKS ConfigMap, edit `SIGNING_KID`, keep the retired key published until its
  tokens expire. No automation, no KMS, no expiry tracking in code.

**Infra input (memory `infra-openbao-secrets`):** the target infra will run **OpenBao** (LF fork of
Vault) for secrets regardless of this change — so it is the natural Adopt choice with no new service
to operate.

## Goals / Non-Goals

**Goals:**
- Signing-key rotation becomes **automated** (no manual runbook), preserving the in-flight overlap
  guarantee (a new key is published before it signs; a retired key stays published until its tokens
  expire).
- The published JWKS is **generated** from the key source, killing the manual `kid` ↔ JWKS drift.
- Rotation runs on a **schedule or on demand** (suspected compromise) with no hand-editing of key
  files, identifiers, or the published key set.

**Non-Goals:**
- The revocation-sensitive-header signing + the edge allowlist strip (landed in
  `b-floor-trust-hardening`).
- edge↔box mTLS / cross-region transport (B-gate); any DB / multi-region / CNPG work (D).
- Changing the box-side verifier: the JWKS contract + token shape are unchanged; only nexus's key
  management and publication change.

## Decisions

### Decision 1 — Automate key rotation via **OpenBao Transit**, Mode B local signing (APPROVED)

**Infra input:** OpenBao runs in-infra regardless, so it is the natural **Adopt** choice and
collapses the tier question (no new service to operate — same reasoning as NATS in the D program).
Its **Transit** engine covers this nearly turnkey: versioned keys = rotation (each version is a
`kid`; `min_decryption_version` retires old ones on a schedule or on demand), `ecdsa-p256` matches
the existing ES256 signer, and public keys are exportable so `/.well-known/jwks.json` is
**generated** from Transit rather than hand-synced.

**Decision: Mode B (Bao as key source + rotation, local signing).** `vaultrs` (maintained async
Rust client) covers the Transit calls. Transit's `ecdsa-p256` + `"jws"` marshaling confirm Mode A is
also feasible, but Mode B is chosen for the hot path. Modes considered:

- **Mode A — Transit remote signing:** key never leaves OpenBao; `signer.rs` calls Transit to sign
  each contract. Strongest custody, but adds a **per-request network hop on the hot path** + a hard
  dependency on Bao availability for signing, and requires assembling the compact JWS from a Transit
  signature instead of `jsonwebtoken::encode`. Reserve for a requirement that the key must never be
  in the plane's memory.
- **Mode B (recommended) — Bao holds/generates/rotates the key; the plane pulls it and signs
  locally** (today's fast in-process path). Bao drives rotation cadence + custody-at-rest + JWKS
  publication; the hot path stays local with no per-request Bao dependency. Preferred because
  contracts are minted per-request under tranche-A latency SLOs.
- *Rejected:* cloud KMS (AWS/GCP) — redundant with OpenBao already in-infra; a hand-built in-plane
  rotation loop (Build tier) — unnecessary now that Transit provides versioned rotation.
- *Constraint from spec:* the private key stays a runtime-injected secret held only by the identity
  plane; rotation must never reject an in-flight token (both key versions valid across the overlap).

**Structure (abstraction discipline).** A key-provider **port** isolates the dependency: the
rotation manager depends on the port, the `vaultrs` Transit client is the adapter, and a fake
in-memory provider (generates EC keys) backs the unit tests — so the overlap/retire/`kid`-consistency
invariants are testable without a live OpenBao. `AppState.signer` moves from a static
`Option<Arc<Signer>>` to a swap-able active signer, and the JWKS from a static document to a
generated, republish-able key set. The manual `SIGNING_KEY_PATH` PEM path is retained as a
break-glass fallback (the plane still boots + signs if Bao is unreachable at startup).

#### Decision: Signing-key rotation — Adopt (OpenBao Transit, Mode B local signing)

- **Status**: approved (carried over from `b-floor-trust-hardening` /opsx:decide)
- **Why**: OpenBao is in-infra (no new service); Transit gives versioned-key rotation (`kid` =
  version) + exportable public keys for auto-generated JWKS. Mode B keeps per-request signing local,
  off the hot path and independent of Bao uptime.
- **Considered**: Mode A Transit remote signing — strongest custody but a per-request Bao hop +
  hot-path dependency; cloud KMS — redundant with OpenBao; hand-built rotation loop (Build) —
  unnecessary given Transit.
- **Isolation**: key lifecycle behind a key-provider port; `vaultrs` Transit adapter + a fake for
  tests; the plane pulls key material and signs locally; manual `SIGNING_KEY_PATH` PEM retained as
  break-glass fallback.

## Risks / Trade-offs

- **[Automated rotation cuts over mid-flight and rejects tokens]** → enforce the two-key overlap
  window ≥ TTL + max clock skew; verify with the tranche-A burn-rate SLO on the verify path or a
  signing self-test.
- **[Bao unreachable at startup]** → fall back to the break-glass `SIGNING_KEY_PATH` PEM so the plane
  still boots and signs; log loudly. Never silently drop to unsigned.
- **[Mode B holds the key in plane memory]** → accepted for the hot-path latency SLO; Mode A is the
  documented escalation if custody must exclude plane memory.
- **[Dynamic signer/JWKS swap introduces a data race]** → the active signer + published key set are
  swapped atomically (arc-swap / watch), never mutated in place on the hot path.

## Migration Plan

1. Stand up automated rotation **in parallel** with the manual key still valid; the plane pulls from
   Transit but the `SIGNING_KEY_PATH` PEM remains a working fallback.
2. Observe one clean automated rotation (new `kid` published → signs → old retired after TTL+skew)
   before retiring the manual runbook to break-glass-only.
3. Rollback: fall back to `SIGNING_KEY_PATH` manual key; no data migration.

## Open Questions

- Rotation cadence default (e.g. daily vs weekly) and where it's configured (Transit auto-rotate vs a
  plane-side schedule) — settle at apply-time against the live OpenBao.
- Whether the plane polls Transit for new versions or is pushed (Transit has no push); a bounded poll
  interval is the likely v1.
