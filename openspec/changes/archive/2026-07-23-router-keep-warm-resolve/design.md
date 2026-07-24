## Context

The resolve path is `AppState::resolve` (`routing-rs/tenant-router/src/state.rs:96`). It is a
layered cache: an in-process L1 (Moka `future::Cache`, `time_to_live`, default 600 s) in front of
an optional Redis L2 (`SET EX`, default 600 s), behind which sits the Postgres store. Population is
**lazy-on-miss** through a single coalesced loader (`l1.try_get_with(...)`, `state.rs:111-172`): on
a miss the loader runs up to four Postgres point-reads plus up to two Redis hops, synchronously, on
the request that happened to arrive after expiry. Concurrent misses for the same key are already
collapsed by `try_get_with`, so this is not a stampede — it is a single request per expiry window
paying the refill.

Cache correctness is already event-driven: a control-plane `NOTIFY` drives the invalidation watcher
(`serve.rs:159-193`), which **evicts** changed keys from L1 and L2. So the TTL is a staleness
backstop, not the primary freshness mechanism — yet its expiry is exactly what lands on a user's
request. Moka 0.12's `future::Cache` exposes coalesced lazy loaders and manual invalidation but, per
investigation, **no Caffeine-style refresh-ahead** (`refresh_after_write`). No background refresh or
keep-warm exists today. The identity-sidecar has a structurally identical lazy-on-miss cache
(`identity-rs/sidecar/src/api_key_cache.rs`) — a separate cache instance, not a shared one.

This change is the still-open **workload arm of N16**. The alerting arm shipped separately
(`slo-latency-rate-floor`); this is not about the SLI query, it is about the latency itself.

## Goals / Non-Goals

**Goals:**
- No live request pays a synchronous store refill for a key the cache already holds and is actively
  serving. The periodic request-path refill (the `1/7` structural ratio) drops to zero at steady
  state.
- Keep the fix in the **core cache layer**, so `tenant-router`'s `serve.rs` stays a thin adapter and
  the same mechanism is reusable for the identity-sidecar cache.
- Add **no new operational knob**: refresh timing derives from the existing entry lifetime.
- Drive the whole change from a **deterministic reproduction test written first** (TDD), which also
  settles empirically whether the observed period is cache-expiry or an external cause.

**Non-Goals:**
- Not warming keys that are not being read (no scheduled sweep over the 200 k-capacity cache, no
  "hot key" tracking, no readiness-time table preload — resolution stays on-demand for cold keys).
- Not changing the `NOTIFY` invalidation path or the on-demand resolution of first-ever/evicted
  keys.
- Not retuning TTL values as the fix (raising TTL only makes the miss rarer, not absent).
- Not unifying the two services' caches into one shared instance; the identity-sidecar receives the
  same *pattern*, wired to its own cache, as a follow-on step (see Open Questions).

## Decisions

### D1 — Stale-while-revalidate / refresh-ahead, access-triggered (not scheduled)
Serve the resident value immediately and refresh it in the background when it crosses a refresh
point, but **only for keys that are actually read**. This is the RFC 5861 `stale-while-revalidate`
convention. Chosen over: (a) **raising the TTL** — reduces frequency but never reaches zero and
lets config drift staler; (b) a **background loop sweeping cached keys** — scans idle keys, scales
with cache size not with what's hot, and needs "which keys are hot" logic and a new interval knob.
Access-triggered refresh is self-scoping: work happens exactly for the keys under load, and idle
keys age out as today. This directly satisfies the spec's "resident + actively-read → no
request-path refill" while preserving "idle key is not kept warm".

### D2 — Refresh point derived from the existing entry lifetime (no new knob)
The moment a resident entry becomes eligible for background refresh is a fixed fraction of the
already-configured cache lifetime (e.g. refresh once the value has lived a set fraction of its TTL),
so operators still tune exactly one value — the lifetime — and the refresh timing follows from it.
No `ROUTING_*` env var or Helm value is added. This is the "convention over configuration" constraint
made concrete and matches the spec requirement "keep-warm timing derives from existing cache
lifetime". The exact fraction is an implementation constant owned by the cache module, not exposed.

### D3 — Behavior lives in `router-core`'s cache layer, behind the existing port
The keep-warm logic is added at the core cache layer (`routing-rs/router-core` cache port +
`tenant-router`'s `AppState` cache), **not** in the ext_proc adapter (`serve.rs`) and **not** in the
store adapter. Dependency direction stays inward: `serve.rs` (adapter) → `AppState::resolve` (core)
→ cache port + `RoutingStore` port (adapters for Moka/Redis/Postgres). The background refresh reuses
the **same loader** that lazy population uses today, so there is one code path for "produce a fresh
value" and coalescing is preserved (at most one in-flight refresh per key — the spec's collapse
requirement). L2 write-back on refresh reuses the existing `l2.put(...)` path.

### D4 — Build-vs-adopt for the refresh mechanism → defer to `/opsx:decide`
Refresh-ahead is a reliability-sensitive concern, so the tool choice goes through the gate.
**Recommendation to carry into the gate:** the primitive here is small and tightly coupled to the
existing Moka + coalesced-loader + L2-write-back structure. If a mature Rust cache crate provides
Caffeine-style refresh-ahead natively with an equivalent coalescing/￼L2 story, **adopt** it;
otherwise the proportionate choice is **Extend** the cache already in use — a thin
stale-while-revalidate wrapper that stamps each cached value with its fetch time and spawns a single
coalesced background refresh via the existing loader when the refresh point is crossed. The gate
must confirm the "Moka 0.12 has no native refresh-ahead" finding before settling on Extend/Build.

### Decision: Refresh-ahead mechanism — Extend Moka with a stale-while-revalidate layer

- **Status**: approved
- **Why**: Moka is the mature, already-adopted cache and exposes exactly the primitives needed —
  coalesced async loaders (`get_with`/`try_get_with`/`entry().or_insert_with()`, one future per key)
  and the per-entry `Expiry` trait — so refresh-ahead is a thin layer over the in-use crate, not new
  cache machinery. Refresh point derives from the existing TTL (no new knob), and the background
  reload reuses the loader `AppState::resolve` already runs.
- **Considered**: *Adopt a different crate with native refresh-ahead* — no mature async Rust cache
  (mini-moka, cached, quick_cache, retainer) offers refresh-ahead with coalescing + async, so
  swapping regresses maturity for no gain. *Build custom / Fork Moka* — reinvents or forks mature
  concurrent-cache internals; disproportionate to a small SWR primitive.
- **Isolation**: lives behind the `router-core` cache port (`routing-rs/router-core/src/cache.rs`);
  the SWR wrapper stamps fetch time and spawns the coalesced background refresh entirely inside the
  cache module. `serve.rs` (ext_proc adapter) and the `RoutingStore`/Redis adapters are untouched.
- **Research**: Moka has no `refreshAfterWrite` (the one Caffeine feature it lacks) — confirmed via
  docs.rs/moka and the Rust forum "time-to-refresh semantics" thread (2025). Verified at this gate.

### D5 — TDD: a deterministic reproduction test drives the change
The first task writes a **failing** test against the real resolve path with:
- a fake `RoutingStore` adapter that counts fetches and injects latency,
- a controllable time source (injected clock / paused Moka time) rather than wall-clock sleeps,
- a single key read continuously across several lifetimes.

The test asserts **zero request-path store fetches after initial population**. It fails today (one
fetch per lifetime window) and passes once D1–D3 land. Because it counts store fetches deterministically
rather than measuring latency, it is not timing-flaky, and it doubles as the empirical proof that the
mechanism is cache-expiry (if the reproduction shows the periodic fetch, the cache is the cause).

**Refinement discovered at apply time.** Moka's expiry runs on a real (`quanta`) clock that has no
public mock/pause seam — `tokio::time::pause` does not advance it — so the "paused Moka time" option is
not available, and a hard-expiry reproduction needs real time to elapse. The test therefore uses a
short real L1 lifetime (120 ms) with continuous reads and derives determinism from a **store-fetch
counter** instead of a virtual clock: it counts only fetches that occur *inside* each `resolve().await`.
On the single-threaded `#[tokio::test]` runtime a background refresh is spawned but cannot run until the
task yields at the inter-read sleep, so background fetches land outside the measured bracket while a
synchronous lazy-on-miss refill lands inside it. The assertion is on the count (must be 0), never on
wall-clock latency, so it is not timing-flaky. This honors D5's intent (count, don't time) within Moka's
real-clock constraint.

## Risks / Trade-offs

- **Test timing flakiness** → assert on a deterministic store-fetch counter and an injected/paused
  clock, never on wall-clock latency or `sleep`. No real Postgres/Redis in the unit test.
- **Background task lifecycle leak** (spawned refresh outliving relevance) → refresh is coalesced
  (one per key) and only fires for keys still resident and being read; a completed refresh simply
  replaces the value or is dropped if the key was evicted meanwhile.
- **Unbounded staleness if refreshes keep failing** → the spec bounds served-value age to lifetime +
  one refresh; on persistent refresh failure past the lifetime the entry falls back to on-demand
  resolution (hard-expire) rather than serving arbitrarily old data.
- **L2 refresh amplification** → background refresh writes back through the existing coalesced L2
  path; at most one refresh per key per window, so no new Redis load pattern.
- **Identity-sidecar divergence** → landing the pattern only in router-core leaves the sidecar's
  cache unfixed. Mitigation: the core mechanism is written to be reusable and the sidecar is called
  out explicitly as a follow-on so it is not silently forgotten.

## Migration Plan

- Pure behavioral change to cache internals: **no schema change, no config change, no API change.**
- Rollout is a normal image deploy of `tenant-router`. Because no flag is added (convention over
  configuration), rollback is a straight revert of the image — the prior lazy-on-miss behavior
  returns with no data or config to unwind.
- Verification after deploy: the N16 structural SLI error ratio at steady low traffic falls to ~0;
  confirm the periodic slow ext_proc hit disappears.

## Open Questions

- **Deployed lifetime value.** Code defaults are 600 s and no 60 s TTL or 60 s connection lifetime
  exists in code (sqlx pool sets no `max_lifetime`/`idle_timeout`, `store-postgres/src/lib.rs:68-70`).
  Infra to confirm the live `ROUTING_CACHE_TTL` / `ROUTING_L2_TTL` so the measured ~1/min period is
  reconciled with the mechanism. The fix is correct regardless of the exact value.
- **Reproduction result (settled at apply time).** The task-1 test
  (`state::tests::resident_hot_key_never_refills_on_the_request_path`) reproduces the defect
  deterministically: a single hot key read continuously across ~7 lifetime windows incurs **7
  request-path refills** (one per window) against the current lazy-on-miss cache — the mechanism is the
  cache re-cooling on the request path, echoing N16's structural `1/7` ratio, not an external cause.
  This confirms the cache-expiry diagnosis independently of the deployed TTL value.
- **Exact refresh-point fraction** (D2) — **pinned at lifetime / 2**: a resident, actively-read entry
  refreshes once it is halfway to expiry, leaving the second half of the lifetime as margin to complete
  the refresh off the request path before hard expiry. Internal constant (`refresh_after` derived in
  `main` from `ROUTING_CACHE_TTL`), not exposed as config.
- **Identity-sidecar rollout — resolved: follow-on change.** Assessed at apply time: the sidecar's
  `ApiKeyResolveCache` (`identity-rs/sidecar/src/api_key_cache.rs`) has the same lazy-on-miss +
  TTL-expiry-on-request-path shape and the same push-based revocation (so its TTL is likewise a
  backstop), so the keep-warm *pattern* applies. But it does **not lift cleanly**: it is `moka::sync`
  (not `future`), enforces a hard per-entry `expires_at` (a key past its own expiry must never be
  served, even stale — so serve-stale must be gated on `expires_at`, unlike the router), and couples a
  `key_id → key_hash` reverse index that a background refresh must maintain. Bundling it would roughly
  double this change and mix two services' concerns. **Recommendation: a dedicated follow-on change**
  (e.g. `sidecar-keep-warm-apikey`) that reuses this change's SWR shape adapted to those constraints.
- **Adopt vs Extend** (D4) — resolved by `/opsx:decide` after confirming native library support.
