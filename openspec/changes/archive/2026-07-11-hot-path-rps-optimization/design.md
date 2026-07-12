## Context

A capacity ramp (`scripts/load/run-ramp.sh`, enriched path) on a single co-located box moved the SLO-compliant knee from ~4k to ~5–6k rps by stopping the monitoring stack and cutting Envoy trace sampling 100%→1% — pure ops, no code. With that contention removed, the dominant *per-request code cost* on a cache-hit request is the ES256 signature the identity sidecar computes to mint `x-identity-contract` (`identity-rs/sidecar/enrich.rs:255` → `signer.rs:158` `encode(...)`). Everything else on a resolved request is in-memory map lookups (profile cache hit, plan/scope resolution). Signing is always **local** even under Transit "Mode B" rotation (`rotation.rs`), so it is CPU, not a network call — but it is recomputed on every resolved request with no reuse.

Secondarily, both Rust sidecars are bare `#[tokio::main]` (`tenant-router/main.rs:55`, `sidecar/main.rs:73`) and default their worker pool to all logical cores; Envoy has no `--concurrency` set. Co-located, these runtimes oversubscribe cores and thrash.

Constraints: this is a **security-critical** capability (`identity-contract-signing`). The origin-trust and audience+expiry guarantees are load-bearing and must be preserved exactly. Freshness of identity facts is already handled by the profile cache + LISTEN/NOTIFY change feed and must not regress.

## Goals / Non-Goals

**Goals:**
- Eliminate the per-request ES256 signature on steady-state resolved traffic by reusing a signed contract for a short, safe window.
- Make worker-pool sizing explicit so a co-located deployment can stop the edge and planes from fighting for cores.
- Preserve every existing `identity-contract-signing` guarantee (integrity, audience, issuer, expiry, rotation overlap, freshness).

**Non-Goals:**
- API-key resolve cache (deferred to a later change).
- Envoy hot-path trims: `message_timeout`, access-log filtering, header-strip pruning (deferred).
- Any change to ext_proc `failure_mode_allow: false`, headers-only body modes, path normalization, or the tenant→jwt→identity ordering.
- Cross-instance sharing of signed contracts.

## Decisions

### Decision: contract-token reuse cache — Extend `moka` (in-process)

- **Status**: approved (`/opsx:decide`, 2026-07-11)
- **Why**: Already the repo's adopted in-process cache (profile + routing-decision caches); mature/maintained; full TTL/TTI plus `invalidate_all` for the rotation flush. Redis rejected for this tier — a network round-trip costs more than the local ES256 sign we're avoiding, and sharing signed contracts widens the credential blast radius for zero latency gain.
- **Considered**: `quick_cache` (Adopt — lighter but partial/no TTL, no invalidation hooks → hand-rolled expiry); hand-rolled TTL map (Build — reinvents a concurrent TTL cache, rejected).
- **Isolation**: the cache sits behind the sidecar signer/enrich layer in front of `signer.mint`; the rest of the system is unaware it exists. Rotation invalidation is driven off the existing `rotation.rs` `watch` channel.

Full rationale (tier-matching rule): the token cache avoids a **local** compute cost (ES256, ~tens of µs), so it stays in-process (moka); a **remote-store** cost (Postgres) is the case that would justify an optional shared L2 (Redis) — that is the deferred API-key cache, not this one. Consistency: the repo uses `moka` in-process and reserves Redis as an optional Postgres L2 in the routing plane only, never as a bus (NATS owns that). This change reuses that established pattern.

General rule recorded for later work: **local-compute cost → in-process (moka); remote-store (Postgres) cost → optional shared L2 (Redis).** The deferred API-key cache is the Postgres-cost case and MAY use moka-L1 + optional Redis-L2 later; the token cache is the local-compute case and MUST stay moka-only.

### Decision 2: Cache key = the contract-determining identity facts, excluding time/nonce
Key the cache on the tuple that fully determines the signed claims **except** the per-mint fields (`jti`, `iat`, `exp`): `(sub, aud, workspace_id, principal_kind, member_type/role, plan, roles-hash, permissions-hash, entitlements-hash, suspended, on_behalf_of)`. Two requests with an identical tuple are cryptographically interchangeable within the window. Roles/permissions/entitlements are hashed into the key (not listed) to bound key size. The `aud` (per-backend audience) is part of the key, so a contract is never reused across audiences.

### Decision 3: Reuse window ≪ contract validity, and expiry-safe
Reuse TTL is a small value (default ~5s, configurable) and strictly less than the contract validity (~60s). On a hit, the sidecar serves the cached token **only if its remaining validity exceeds a safety skew**; otherwise it re-mints. This guarantees no request is ever stamped with an expired/near-expired contract even though `exp` is fixed at mint time. Because the reuse window is far shorter than the profile-freshness path, a fact change is reflected on the next request after the profile cache updates.

### Decision 4: Freshness & rotation invalidation
- **Facts:** the cache is keyed on the resolved facts, so any fact change produces a different key → a new mint. The existing profile cache + change feed remain the freshness authority; the token cache never extends staleness beyond its own short TTL.
- **Rotation:** the signer is swapped via the existing `rotation.rs` `watch` channel. The token cache SHALL be flushed (or generation-tagged with the active key id) on every signer swap, so a contract signed by a superseded key is never served after cut-over. Simplest correct approach: include the active key id in the cache key, or clear the cache on the watch-channel change. Clearing is preferred (bounded memory, unambiguous).

### Decision 5: Worker-pool sizing is config, not code (single source of truth)
Replace bare `#[tokio::main]` with an explicit multi-thread runtime whose `worker_threads` is read from an env var (e.g. `TOKIO_WORKER_THREADS`), defaulting to current behavior (all cores) when unset so nothing regresses. Envoy `--concurrency` becomes a config value threaded through `edge/envoy.yaml`/compose/Helm the same way `TRACE_SAMPLING_PCT` already is. These are deployment tunables, centralized as config, not magic literals — no observable behavior change, so no spec.

## Risks / Trade-offs

- **[Reused `jti` breaks a consumer that treats it as a per-request nonce]** → The spec now states `jti` is not per-request-unique and replay is defeated by `aud`+`exp` (already true per `signer.rs:75-76`); update `docs/box-consumer-contract.md` to say so explicitly. Audit downstream/e2e for any `jti`-uniqueness assumption before enabling.
- **[Stale contract served after a fact change]** → Bounded by the short reuse TTL and the facts-in-key design; worst case a change is visible one reuse-window later, which is ≤ the existing freshness envelope. Set the default TTL conservatively (~5s).
- **[Token served across a key rotation]** → Cache is cleared on signer swap (Decision 4); add a test that rotates mid-load and asserts no superseded-key token is emitted.
- **[Under-sizing worker threads starves throughput]** → Default stays all-cores when the env var is unset; the knob is opt-in per deployment, validated with the ramp.
- **[Cache memory growth]** → moka `max_capacity` + short TTL bound it; key cardinality ≈ distinct active principals per window, which is small.
- **[Measurement on a co-located box understates gains]** → The ramp generator shares the host; treat before/after as directional. Real validation is off-box with CPU limits.

## Migration Plan

1. Land behind safe defaults (worker env unset = all cores; contract cache can ship enabled with a small TTL, or gated by an env flag for a cautious rollout).
2. Run `scripts/contract-signing-e2e.sh` (correctness must still pass) and the rotation-under-load test.
3. Re-run `scripts/load/run-ramp.sh` before/after for the RPS delta.
4. Rollback: disable the cache via its env flag / set TTL 0 (falls back to sign-per-request); revert worker env. No data migration, no schema change.

## Open Questions

_Resolved:_
- **Rollout:** env flag, **default ON**, TTL configurable; setting TTL=0 (or disabling the flag) falls back to sign-per-request for instant rollback.
- **Default reuse TTL:** **5s** (≪ ~60s contract validity), with a remaining-validity safety floor so a cached token near expiry forces a re-mint. Confirm against the contract TTL actually configured in the target deployment before rollout.
