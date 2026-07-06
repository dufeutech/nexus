# Design: telemetry-cost-controls

## Context

The telemetry stack is functionally complete: the edge roots traces, the box
telemetry contract defines one OTLP egress into per-signal stores, and the
first-party services comply. But the stores run the **lab default** end to end:

- **Tempo** — `backend: local` (disk), 48h block retention.
- **Loki** — `filesystem` storage, 7d (`retention_period: 168h`), structured metadata.
- **Prometheus** — local TSDB, native OTLP receiver, a 30m out-of-order window.
- **Collector** — the **core** distribution (only `batch`), the single egress every
  producer knows; store addresses live only in its config (env-driven).

That is correct but not cost-shaped: storage is tied to a host's disk, retention is
an implicit default rather than an owned budget, and nothing bounds what one producer
can cost. This change graduates the stores to the standard production cost posture the
prior designs deferred, and adds a fail-safe cost ceiling at the egress we already
own. It is config-first by intent — like N6, A, and B, the wiring lives in
native-format config under `monitoring/`, no application code.

## Goals / Non-Goals

**Goals:**

- All three stores on an object-storage tier (cheap, scalable, decoupled from host
  disk), each with an explicit, owned retention bound.
- A cost ceiling at the single egress: metric-series cardinality and log/telemetry
  volume are bounded per producer, so abuse degrades the abuser's fidelity, not the
  bill or the store.
- A clean-checkout lab that runs the *same* cost topology with no cloud account (a
  self-contained S3-compatible tier locally; prod points the same config at real
  object storage via env).
- Head sampling stays the trace cost ceiling; the change adds no downstream trace
  buffering.

**Non-Goals (successor changes):**

- Long-term metric retention / downsampling (Mimir or Thanos) — metrics are the
  cheapest signal by volume; defer until a real history need exists.
- SLO targets + multi-window burn-rate alerting on the RED baseline.
- Tail / error-biased trace retention (explicitly ruled out; see the decision).
- Per-tenant cost attribution / chargeback.

## Architecture

```
 producers ──OTLP──▶  OTel Collector (single egress)            unchanged for
                       │  + memory_limiter (don't OOM)           producers
                       │  + cost-ceiling processors:
                       │      · metric cardinality guard
                       │      · log volume/noise guard
                       ▼
        traces ▼     metrics ▼      logs ▼
         Tempo       Prometheus      Loki
           └────────────┴─────────────┘
                        │  storage backend = OBJECT STORAGE
                        ▼        (S3-compatible)
             ┌──────────────────────────┐
             │  lab:  self-hosted S3     │   same config,
             │  prod: cloud object store │   endpoint+creds via env
             └──────────────────────────┘
                        ▲
             per-signal retention = owned budget (config value)
```

Dependency direction is unchanged and inward-only. Enforcement of the cost ceiling
sits at the collector (or store limits) — downstream of producers, so no producer
changes. Store backends repoint via env (`*_ENDPOINT`/bucket/creds), exactly the
single-egress discipline already in force.

## Decisions

<!-- Resolved via /opsx:decide 2026-07-06; options researched against current
     (July 2026) mature-tooling state. Key finding: MinIO Community Edition was
     ARCHIVED Feb 2026 (read-only, no security patches, no binaries) and Grafana
     deprecated its bundled MinIO subchart — a hard reject on the "abandoned /
     unpatched" maturity criterion, which reshaped the object-storage decision. -->

### Decision: object-storage backend + local-dev emulation — Adopt S3-compatible; SeaweedFS as the emulator

- **Status**: approved
- **Why**: one S3-compatible backend abstraction (Tempo and Loki both natively
  support S3; Prometheus's local TSDB stays — long-term/object-store metrics is the
  deferred Mimir/Thanos change). The clean-checkout lab runs **SeaweedFS** — Apache
  2.0, 12+ years active, production-mature, single-command local, a genuine
  drop-in MinIO replacement — with a seeded bucket + well-known lab credentials;
  production points the identical store config at a cloud object store (S3/GCS) via
  env, or self-hosts SeaweedFS. One backend type, two endpoints.
- **Considered**: MinIO (HARD REJECT — Community Edition archived Feb 2026,
  unpatched, bundled subchart deprecated; adopting an abandoned storage server is the
  exact failure the maturity gate prevents); Garage (AGPL-v3 — fine as an external
  dependency but a governance flag, and less battle-tested than SeaweedFS); a
  test-only s3mock emulator (no self-host-prod parity; not a real store); keeping
  local disk (the status quo this change replaces).
- **Isolation**: a `storage` block per store config file + one SeaweedFS service in
  the lab compose; endpoint/bucket/creds are env, known only to the stores.

### Decision: cardinality & volume control mechanism — Adopt hybrid (Loki limits + collector transform/filter)

- **Status**: approved
- **Why**: enforce where each store is strongest — **Loki's built-in `limits_config`**
  (per-stream ingestion rate, max label names, volume caps) bounds log volume/streams
  store-side (mature) — plus **collector `transform`/`filter`** to drop
  high-cardinality metric attributes at the egress before they reach Prometheus
  (whose native-OTLP path has weaker built-in cardinality control). Both are standard
  configuration. Prefer the mature `transform`/`filter` over the purpose-built but
  **alpha** `cardinality_guardian` processor until the latter matures.
- **Considered**: collector-only for everything (one enforcement point, but Loki's
  store-side log limits are more mature than collector-side log volume control);
  store-only (leaves metric cardinality under-protected — Prometheus OTLP lacks
  Loki-grade limits); the alpha `cardinality_guardian` (revisit when it graduates);
  a hand-written guard (reject — reliability-critical build where mature config exists).
- **Isolation**: `limits_config` in the store config files + processor blocks in the
  collector config; producers unchanged.

### Decision: collector distribution — Adopt contrib

- **Status**: approved
- **Why**: the metric cardinality guard uses the collector `transform` processor,
  which lives in the **contrib** distribution (`filter` is in core, but attribute
  dropping needs `transform`), so this change graduates the collector core → contrib —
  for *cost control*, exactly as the box-telemetry-contract design foresaw ("the
  contrib switch rides a change that needs it"). Image provenance changes deliberately
  and is pinned here.
- **Considered**: stay on core + push all cardinality control store-side (avoids
  contrib but under-protects metric cardinality); a custom processor (build where
  contrib exists).
- **Isolation**: the collector image tag in compose/helm; swapping distributions is
  invisible to every producer.

### Decision: no tail sampling for cost — record as non-goal

- **Status**: approved (pinned by spec)
- **Why**: trace cost stays governed by the head decision + storage tier. Tail
  sampling saves only storage (which object storage makes cheap), costs full ingest +
  a stateful contrib stage, and violates the shipped "head decision is the ceiling,
  the collector may only subtract" invariant. Recorded so a future "keep every error
  trace" want is recognized as a *signal-quality* feature (its own change), not a cost
  lever bolted on here.
- **Considered**: tail sampling as the trace cost lever (more cost + complexity for
  less saving once storage is cheap; breaks the head-ceiling invariant).
- **Isolation**: a contract/non-goal, not a component.

## Risks / Trade-offs

- [Object-storage latency vs local disk for hot queries] → traces/logs are
  write-heavy, read-rarely; the stores' local caches cover hot reads. Size the cache;
  accept slightly higher cold-query latency for a large cost win.
- [Cardinality guard drops a label an operator wanted] → allow-list is explicit and
  lives in one config file; start permissive, tighten with evidence. Dropping is at
  the egress, so a mistake is a config edit, not a producer redeploy.
- [Retention set too short loses an investigation] → retention is an owned, documented
  value per signal; the point is that it is *chosen*, not defaulted. Revisit with real
  incident data.
- [Contrib collector = larger image / bigger surface] → the deliberate, pinned
  graduation; provenance change is scoped to this change that needs it.
- [Lab emulator diverges from real cloud object storage] → use an S3-compatible
  emulator so the wire protocol is identical; prod differs only by endpoint + creds.
- [A cost ceiling that engaged silently could hide data loss] → bounding emits its own
  telemetry (what was dropped/aggregated) so an engaged ceiling is observable, not a
  silent gap.

## Migration Plan

1. Lab first: stand up the object-storage emulator; repoint Tempo/Loki backends at it
   with seeded buckets; verify each signal writes and reads end-to-end on the new
   tier. Add the collector cost-ceiling processors + store limits; verify a synthetic
   cardinality bomb / log flood is bounded and self-reported.
2. Set explicit retention per signal as config values; verify old data is reclaimed.
3. Docs: cost model + retention table + egress knobs in `deploy/README.md`; contract
   note in `nexus-upstream-requirements.md`.
4. Rollback: repoint backends to local disk (config only); the emission contract and
   all producers are untouched throughout.

## Roadmap (recorded, out of scope)

- **Long-term metrics:** graduate Prometheus → Mimir/Thanos (object-store-backed,
  downsampling, long retention) when metric history need is real.
- **SLO layer:** SLO targets + multi-window burn-rate alerts on the first-party RED
  baseline (now contract-shaped and accurate).
- **Signal-quality trace retention:** if "keep every error trace" is wanted, that is a
  distinct change (tail sampling or span-level keep), justified by signal, not cost.

## Open Questions

- Retention windows: traces settled at 48h; logs 7d today — is 7d right, or
  tier hot(short)/cold(long) on object storage? Decide with volume/$ evidence at apply.
- Cardinality budget: what's the target ceiling on total metric series, and which
  attributes are the allow-list? Start from the contract's identity set + RED labels.
- Object-storage single-node durability in the lab is best-effort (an emulator) —
  fine for dev; prod relies on the cloud store's durability. Confirm no test depends on
  lab object-storage durability across restarts.
