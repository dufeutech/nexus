## 1. Ratify decisions (decide gate)

- [x] 1.1 Run `/opsx:decide` and record the token-cache build-vs-adopt outcome (Extend `moka`; Redis rejected for the token tier) into design.md
- [x] 1.2 Resolve the two Open Questions in design.md (env flag default ON; reuse TTL 5s + remaining-validity safety floor)
- [ ] 1.3 Audit downstream consumers and e2e for any dependency on per-request-unique `jti` (grep boxes/docs/e2e); confirm none, or list what must change

## 2. Contract token reuse cache (identity sidecar)

- [x] 2.1 Define the cache key type from the contract-determining facts (`sub, aud, workspace_id, principal_kind, member_type/role, plan, roles-hash, permissions-hash, entitlements-hash, suspended, on_behalf_of`); hash the list-valued fields → `token_cache::CacheKey`
- [x] 2.2 Add an in-process `moka` token cache to the sidecar signer/enrich layer (bounded `max_capacity`, TTL = configurable reuse window), sitting in front of `signer.mint` → `token_cache::ContractTokenCache` (moka `sync`), used from `enrich_response`
- [x] 2.3 On cache hit, serve the cached token only if remaining validity > safety floor; otherwise re-mint (expiry-safe reuse per design Decision 3)
- [x] 2.4 Rotation-safe by construction: the active signing-key `kid` is PART of the cache key, so a post-rotation lookup misses and re-mints — a superseded-key token is never served after cut-over, with NO cross-thread flush race (improves on the "flush on `watch`" sketch in design Decision 4)
- [x] 2.5 Wire config: `CONTRACT_CACHE_ENABLED` (default on), `CONTRACT_CACHE_TTL_SECONDS` (5), `CONTRACT_CACHE_MAX_CAPACITY` (100000) — env-injected, safe defaults, built in `main.rs`
- [x] 2.6 Emit metrics: `sidecar_contract_cache_hits` / `sidecar_contract_cache_mints` so the reuse rate (the RPS win) is observable

## 3. Worker-pool sizing (perf-only, no behavior change)

- [x] 3.1 Replace bare `#[tokio::main]` in `identity-rs/sidecar/src/main.rs` with an explicit multi-thread runtime whose `worker_threads` reads `TOKIO_WORKER_THREADS`, defaulting to all cores when unset
- [x] 3.2 Same for `routing-rs/tenant-router/src/main.rs`
- [x] 3.3 Make Envoy `--concurrency` configurable via env, threaded through `docker-compose.yaml` / `deploy/compose` (`ENVOY_CONCURRENCY`) and `deploy/helm/edge-platform` (`edge.concurrency`); default `0` = auto preserves current behavior

## 4. Tests

- [x] 4.1 Unit: identical facts within the window reuse one token; a fact change yields a new token; near-expiry forces a re-mint → `token_cache::tests`
- [x] 4.2 Unit: a rotated signing key (new `kid`) is never reused across the cut-over → `a_rotated_signing_key_is_never_reused_across_the_cut_over`
- [ ] 4.3 Ensure `scripts/contract-signing-e2e.sh` still passes with the cache enabled — DEFERRED: the local lab runs with signing OFF (`SIGNING_KEY_PATH` unset), which the rebuilt binary correctly reports (`reuse cache OFF`), so the member/JWKS path can't run here. Covered by the contract unit/integration tests (reuse, rotation-safety, expiry-safe, signer round-trip) and by CI's auth-enabled e2e release gate; run against a signing-enabled stack to close.
- [x] 4.4 Reused contract is a real minted token (returned verbatim from `signer.mint`, proven to verify by the signer round-trip tests); distinct-subject/plan tests confirm no cross-identity reuse

## 5. Docs & validation

- [x] 5.1 Update `docs/box-consumer-contract.md`: `jti` is not a per-request nonce; replay is defeated by `aud`+`exp`; a contract may repeat within a bounded window
- [x] 5.2 Note the new env knobs (`TOKIO_WORKER_THREADS`, `ENVOY_CONCURRENCY`/`edge.concurrency`, `CONTRACT_CACHE_*`) in `deploy/README.md`
- [~] 5.3 Ran `run-ramp.sh` (enriched) on the rebuilt image: NO REGRESSION vs the prior run (1k p99 6.5ms, 3k 30ms, 4k 70ms; knee ~5k). NOTE: the enriched ramp path is ANONYMOUS, and a contract is signed only for a resolved identity, so this ramp does NOT exercise the signing cache — it confirms the worker/runtime changes don't regress the hot path. Quantifying the cache's RPS win needs an AUTHENTICATED ramp scenario (member/service token) + the `sidecar_contract_cache_hits`/`_mints` metrics; tracked as follow-up.
- [ ] 5.4 `openspec validate hot-path-rps-optimization` clean; run `/opsx:sync` then `/opsx:archive` when complete
