## Why

At steady state the router serves almost every request from a warm in-process cache, but
whenever a resident entry hits its TTL the **next live request** pays the full refill —
up to four Postgres point-reads plus two Redis hops — synchronously on the ext_proc hot
path (100–250 ms). With one live tenant this pins a structural ~1 slow-request-per-window
on real user traffic regardless of volume: the still-open **workload arm of infra finding
N16** (`docs/infra-findings.md`, the `1/7` structural ratio). Cache correctness is already
event-driven — a control-plane `NOTIFY` evicts changed keys — so the TTL is only a
staleness backstop, yet its expiry is what lands on a user's request. Every window, some
visitor eats the cold path for a host the router already knew about. That is a real UX
cost, not a metrics artifact, and closing it is what remains of N16.

## What Changes

- Introduce a **keep-warm / refresh-ahead** behavior for the resolve cache: an entry that
  is *resident and actively being read* is refreshed in the background **before** its
  staleness deadline, so no live request ever triggers a synchronous store refill for a
  host the cache already holds.
- Preserve the two behaviors that must not regress: a **brand-new host's first-ever visit**
  still resolves on demand (nothing to keep warm yet — acceptable), and a **real config
  change** still takes effect promptly via the existing `NOTIFY` eviction path.
- Refresh is **scoped to keys actually read** — no full-cache sweep, no background loop over
  idle keys, no "which keys are hot" configuration. Idle entries simply age out as today.
- The keep-warm timing is **derived from the cache's existing TTL**, adding no new tunable
  knob to the operational surface (convention over configuration).
- Applies to the tenant-router resolve path first; the same behavior is in scope for the
  identity-sidecar resolve/api-key cache, which exhibits the same lazy-on-miss shape.

## Capabilities

### New Capabilities
- `resolve-cache-keep-warm`: Steady-state resolution of an already-resident, actively-read
  key incurs no synchronous store refill on the request path; the cache refreshes such
  entries in the background ahead of their staleness deadline, while first-ever lookups and
  `NOTIFY`-driven invalidations behave unchanged.

### Modified Capabilities
<!-- None. domain-host-resolution and routing-invalidation-propagation describe resolution
     correctness and change-propagation; this change adds an orthogonal liveness property in
     its own spec and does not alter their requirements. -->

## Impact

- **Behavioral realization (build-vs-adopt, defer to `/opsx:decide`):** the refresh-ahead
  mechanism is a reliability-sensitive concern. The gate decides whether a mature cache
  library provides Caffeine-style refresh-ahead natively (adopt) or whether a small
  stale-while-revalidate wrapper is added over the cache already in use (build). No tool is
  chosen in this proposal.
- **Code:** the shared router-core cache layer (`routing-rs/router-core`) and its use in
  `tenant-router`'s resolve path; the equivalent identity-sidecar cache is in scope for the
  same treatment.
- **No new operational config:** timing derives from the existing TTL; no new env var or
  Helm value is introduced.
- **Observability:** closes the workload arm of N16 — the structural low-traffic SLI error
  ratio should fall to ~0 once resident hosts stop paying periodic request-path refills.
- **Non-code follow-up:** infra to confirm the deployed `ROUTING_CACHE_TTL` / `ROUTING_L2_TTL`
  on the live pods (code defaults are 600 s; no 60 s TTL and no 60 s connection lifetime
  exist in code) to reconcile the measured ~1/min period with the mechanism.
