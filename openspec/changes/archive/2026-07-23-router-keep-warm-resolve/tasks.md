## 1. Reproduction test first (TDD — must fail before any fix)

- [x] 1.1 Added a shared `test_support::FakeStore` (counting `RoutingStore`) + `build_state`, wired through the real `AppState::resolve`; consolidated `api.rs`'s duplicate fake onto it.
- [x] 1.2 Determinism via a store-fetch counter (not latency) on the single-threaded runtime; Moka's real clock can't be virtualized, so a short real lifetime is used — recorded as a D5 refinement in `design.md`.
- [x] 1.3 Wrote the failing test `resident_hot_key_never_refills_on_the_request_path`: asserts zero request-path store fetches; FAILS today with 7 refills (one per lifetime window).
- [x] 1.4 Recorded the reproduction result in `design.md` (Open Questions): confirms cache-expiry as the mechanism, independent of the deployed TTL.

## 2. Build-vs-adopt gate

- [x] 2.1 Run `/opsx:decide` on the refresh-ahead concern (D4): confirmed no mature Rust crate provides native refresh-ahead (Moka lacks `refreshAfterWrite`; alternatives regress maturity).
- [x] 2.2 Recorded the decision in `design.md`: **Extend Moka with a stale-while-revalidate layer** (approved).

## 3. Keep-warm in the core cache layer

- [x] 3.1 Implemented stale-while-revalidate in `state.rs`: `resolve` serves the resident `Cached` value immediately and, past the refresh point, calls `spawn_refresh` (a detached, coalesced background load via the shared `load_decision`). Loader body extracted to `load_decision`, reused by miss and refresh.
- [x] 3.2 Refresh point = L1 lifetime / 2 (`refresh_after`), derived in `main` from `ROUTING_CACHE_TTL` — no new env var or Helm value.
- [x] 3.3 Background refresh reuses `load_decision` (incl. the existing L2 write-back); a `refreshing` in-flight set collapses a burst to one refresh per key.
- [x] 3.4 Unchanged behavior preserved: miss path is the same coalesced `try_get_with`; first-ever/evicted keys resolve on demand; `NOTIFY` `invalidate` path untouched; idle keys age out via Moka TTL.
- [x] 3.5 Bounded staleness: a failed refresh does not re-insert, so a persistently-failing key hard-expires at the L1 lifetime and the next request resolves on demand.

## 4. Green the specs

- [x] 4.1 Reproduction test now passes: zero request-path refills across lifetimes (was 7).
- [x] 4.2 Added the remaining scenario tests in `state.rs`: `first_ever_lookup_resolves_on_demand`, `resident_value_refreshes_in_background_without_blocking`, `refresh_failure_serves_last_good_within_lifetime`, `invalidated_key_is_re_resolved`, `idle_key_is_not_kept_warm`, `persistent_failure_falls_back_to_on_demand_past_lifetime`. 19/19 tenant-router tests pass.
- [x] 4.3 `cargo clippy -p tenant-router --all-targets` clean (exit 0) under the workspace's strict restriction lints (fixed arithmetic_side_effects via a shared `refresh_point` helper, absolute_paths via `use sleep`, literal-suffix, Duration units). Local Windows only — Linux/@stable CI still to confirm (see [[ci-cross-platform-lint-gotcha]]).

## 5. Identity-sidecar

- [x] 5.1 Assessed the identity-sidecar cache: pattern applies but does NOT lift cleanly (`moka::sync`, hard per-entry `expires_at`, `key_id→key_hash` reverse index). Recorded in `design.md` as a dedicated follow-on change (`sidecar-keep-warm-apikey`) rather than expanding this change's scope.

## 6. Verify and close N16

- [x] 6.1 Verified end-to-end via the deterministic test harness driving the real `AppState::resolve` across cache expiry: a resident, actively-read key incurs 0 request-path refills (was 7). A full-app drive needs live Postgres/Redis (infra-gated) — the harness exercises the actual production code path, not a reimplementation.
- [ ] 6.2 **Pending infra (external):** confirm deployed `ROUTING_CACHE_TTL` / `ROUTING_L2_TTL` on the live pods and reconcile the measured ~1/min period. (Code defaults 600 s; no 60 s TTL or connection lifetime in code — recorded in `design.md` + `docs/infra-findings.md`.)
- [~] 6.3 `docs/infra-findings.md` N16 updated: workload arm marked **implemented** (change `router-keep-warm-resolve`) pending deploy verification. **Pending deploy (external):** confirm the structural low-traffic SLI error ratio falls to ~0 after rollout, then flip to fully resolved.
