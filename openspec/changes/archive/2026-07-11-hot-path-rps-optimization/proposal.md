## Why

A capacity ramp against the enriched edge hot path showed the sustainable knee move from ~4k to ~5–6k rps on a single co-located box **purely by removing operational contention** (stopping the monitoring stack, cutting trace sampling 100%→1%) — no edge code changed. That exhausts the free "ops" wins. The remaining per-request cost is in the code: on every resolved request the identity sidecar mints a fresh ES256 identity-contract JWT, and on cache-hit requests that local P-256 signature is the dominant CPU operation. Two runtimes (both sidecars) also default their worker pools to *all* cores, so when the edge and planes share a node they oversubscribe CPU and thrash. This change removes that avoidable per-request CPU and the oversubscription, raising RPS-per-core without weakening any trust guarantee.

## What Changes

- **Reuse signed identity contracts within a bounded window.** The identity sidecar caches a minted contract keyed on the identity facts that fully determine it, and reuses that signed token for a short window (well under the contract's validity) instead of signing a new one per request. A cache hit skips the ES256 signature entirely. The cache is invalidated/flushed on signing-key rotation so a rotated-out key's tokens are never served. Underlying identity-fact freshness (membership, plan, suspension, revocation) is unchanged — it is still enforced by the existing profile cache + change feed.
  - **Observable relaxation:** the per-request `jti` is no longer guaranteed unique — a reused contract carries the same `jti`/`iat`/`exp` on multiple requests within the window. Replay is still defeated by `aud` + `exp` (the existing contract guarantees). Consumers must not depend on `jti` being unique per HTTP request.
- **Make async worker-pool sizing explicit (perf-only, no behavior change).** Both Rust sidecars stop defaulting their Tokio worker pool to all cores and instead read an env-configured size, and the Envoy worker `concurrency` becomes configurable. This lets a co-located deployment stop the edge and planes from fighting for the same cores. No observable behavior changes; this is a deployment/config concern only.

Explicitly **out of scope** (deferred to later changes): the API-key resolve cache, and Envoy hot-path trims (ext_proc `message_timeout`, access-log filtering, header-strip pruning). Explicitly **not touched** (security invariants): ext_proc `failure_mode_allow: false` (fail-closed), headers-only body modes, path normalization, and the tenant→jwt→identity filter ordering.

## Capabilities

### New Capabilities
<!-- none -->

### Modified Capabilities
- `identity-contract-signing`: A signed identity contract MAY be reused across requests within a bounded window shorter than its validity; consequently the contract's `jti` is not guaranteed unique per request. The contract's integrity, audience-binding, expiry, and reflection of current identity facts are unchanged. Reuse MUST NOT cross a signing-key rotation (a token signed by a superseded key is never served).

## Impact

- **Code:** `identity-rs/sidecar` (contract mint/enrich path + signer; add an in-process token cache invalidated on key rotation); `identity-rs/sidecar` and `routing-rs/tenant-router` `main.rs` (env-configurable Tokio worker threads); Envoy launch config (`edge/envoy.yaml` / compose / Helm edge chart) for configurable `--concurrency`.
- **Behavior contract:** `identity-contract-signing` spec gains the bounded-reuse / non-unique-`jti` statement; the box-consumer contract doc must reflect that `jti` is not a per-request nonce.
- **Dependencies:** no new dependencies — reuses the already-adopted `moka` (in-process cache); the moka-vs-Redis tier choice is recorded in design.md.
- **Deployment:** new optional env knobs (worker-thread counts, Envoy concurrency, contract-cache TTL/size); safe defaults preserve current behavior.
- **Validation:** the existing contract-signing e2e (`scripts/contract-signing-e2e.sh`) must still pass; the capacity ramp (`scripts/load/run-ramp.sh`) is the before/after measure.
