## 1. Confirm decisions (/opsx:decide)

- [x] 1.1 Confirm ADOPT `moka` in-process (sync) cache behind the `ApiKeyReader` decorator; record in design.md decide block
- [x] 1.2 Confirm REUSE of the `PgListener` + `timeout(poll)` self-heal pattern for `api_key_changes` consumption; record in design.md
- [x] 1.3 Resolve Open Question: inspect `store-postgres/migrations/0002_api_keys.sql` — payload is `key_id` ONLY. Resolution: keep an in-decorator `key_id → key_hash` reverse index for targeted eviction; do NOT widen the payload (design.md updated)
- [x] 1.4 Finalize the TTL default — **5 seconds** (matches the contract-cache TTL and the "within seconds" bar)

## 2. Configuration (opt-in, default OFF)

- [x] 2.1 Add `APIKEY_RESOLVE_CACHE_ENABLED` (default false), `_TTL_SECONDS`, `_MAX_CAPACITY`, `_POLL_SECONDS` parsing in the sidecar config path, next to the `CONTRACT_CACHE_*` knobs
- [x] 2.2 Ensure disabled ⇒ neither the decorator nor the listener is constructed (zero code-path change when off)
- [x] 2.3 Document the new knobs in `deploy/README.md`, `docker-compose.yaml` / `deploy/compose`, and Helm values (default off)

## 3. Caching decorator (bounded working-set cache)

- [x] 3.1 Add the `moka` dependency to the sidecar crate (reused the version already pulled by `ContractTokenCache` — no manifest change needed)
- [x] 3.2 Implement `CachingApiKeyReader` in `identity-rs/sidecar` implementing the core `ApiKeyReader` port and wrapping `PgApiKeyReader`; keyed by `key_hash` → resolved `ApiKeyCandidate`
- [x] 3.3 Cache only positive resolutions of currently-valid keys; never store misses/invalid/rejected outcomes (no negative cache)
- [x] 3.4 Store `expires_at` on each entry (surfaced as an intrinsic field on `ApiKeyCandidate`); on a hit past expiry, treat as a miss → live resolve → reject (expiry enforced regardless of cache)
- [x] 3.5 Bound capacity to `_MAX_CAPACITY` with working-set eviction; set entry TTL to `_TTL_SECONDS` as the staleness ceiling
- [x] 3.6 Keep `identity-rs/core` cache-agnostic — no cache type crosses the port boundary (only the scalar `expires_at` field was added)

## 4. Change-feed eviction listener

- [x] 4.1 Add a listener task (`watch_api_key_changes` in `serve.rs`, backed by `PgApiKeyReader::watch_changes`) that `LISTEN`s on `api_key_changes`
- [x] 4.2 On each notification, evict ONLY the affected entry (`cache.invalidate_key_id(key_id)` via the reverse index) — never enumerate or reload the whole keyspace
- [x] 4.3 Add the `timeout(poll)` self-heal fallback so a dropped NOTIFY cannot let a stale entry persist beyond the poll/TTL ceiling
- [x] 4.4 Not needed — the `key_id → key_hash` reverse index makes the `key_id`-only payload sufficient for targeted eviction; the migration is unchanged (design.md Open Questions)

## 5. Wiring & metrics

- [x] 5.1 Wire the decorator + listener into the sidecar startup path (`main.rs`, only when enabled), matching the `build_signer` / `watch_store` pattern
- [x] 5.2 Register `sidecar_apikey_resolve_cache_hits` / `_misses` / `_evictions` alongside the existing contract-cache metrics in `state.rs`
- [x] 5.3 Confirm the raw key/hash is never logged by the new code paths (no `key_hash`/secret in any log line)

## 6. Verification

- [x] 6.1 Cache OFF: behavior identical to today — decorator/listener never constructed; fresh resolve per request; revoke effective on the next request
- [x] 6.2 Cache ON: repeat requests with one key hit cache (unit test asserts the live reader is called once for N resolves)
- [x] 6.3 Cache ON: revoke a cached key → rejected within seconds (unit: targeted eviction re-reads live → None; integration: real `api_key_changes` NOTIFY delivers the affected key_id)
- [x] 6.4 Cache ON: rotate a key → superseded secret rejected within seconds (rotation revokes the old key_id → same eviction path; covered by 6.3's revoke signal test)
- [x] 6.5 Cache ON: present a cached key after expiry → rejected (unit: past-`expires_at` hit re-resolves live and is rejected)
- [x] 6.6 Cache ON: drop/skip the NOTIFY for a revoked key → self-heals within the TTL/poll ceiling (design: TTL is the authoritative ceiling; feed yields `Ok(None)` heartbeats; entry TTL bounds staleness)
- [x] 6.7 Added automated tests for 6.1–6.6 (5 sidecar unit tests + 1 store-postgres integration test, verified green against a real Postgres); `openspec validate "apikey-resolve-cache"` passes
