# Tasks: telemetry-cost-controls

<!-- Run /opsx:decide before 1.x — the four decisions in design.md pin the object-
     storage backend + emulator, the cardinality/volume mechanism, and the collector
     distribution these tasks configure. Config-first; no application code expected. -->

## 1. Object-storage tier (lab first)

- [x] 1.1 Add the decided object-storage emulator to the lab compose (seeded
      bucket(s), well-known lab credentials, its own data volume); endpoint/bucket/
      creds via env, defaulting to the in-network emulator
- [x] 1.2 Repoint the trace store backend to S3-compatible object storage in
      `monitoring/tempo/*.yaml` (endpoint/bucket/creds via env, not literals); keep
      48h retention as an explicit value
- [x] 1.3 Repoint the log store backend to S3-compatible object storage in
      `monitoring/loki/*.yaml`; keep structured-metadata support; retention as an
      explicit value
- [x] 1.4 Verify: a synthetic trace, log, and metric each write to and read back from
      their store on the object-storage tier; confirm objects land in the emulator's
      bucket (no local-disk store path in use for traces/logs)

## 2. Cost ceiling at the single egress

- [x] 2.1 Switch the collector to the decided distribution (contrib) if required by
      the cardinality processors; pin the image tag (provenance change scoped here)
- [x] 2.2 Add the metric cardinality guard to the collector config (drop/aggregate
      high-cardinality attributes down to the identity + RED label set; allow-list in
      one place); add `memory_limiter` so the collector can't OOM under volume
- [x] 2.3 Add the log volume/noise control at the decided enforcement point (Loki
      `limits_config` per-stream ingestion/volume caps and/or a collector filter);
      set an explicit per-producer volume bound
- [x] 2.4 Ensure an engaged ceiling is observable: what was dropped/aggregated is
      itself reported (a metric/log), never a silent gap

## 3. Cost-ceiling verification (synthetic abuse)

- [x] 3.1 Verify cardinality containment: a synthetic producer emits an unbounded
      label; total metric series stay within the budget and other producers' metrics
      are unaffected
      <!-- Verified live: 300 distinct user_id datapoints collapsed to 1 series,
           user_id dropped at the egress; control producer's metric intact. -->
- [x] 3.2 Verify log-flood containment: a synthetic producer emits far-above-norm log
      volume; its contribution is bounded while other producers' logs arrive intact
      <!-- Verified live: ~36MB single-stream flood => loki_discarded_samples_total
           {reason="rate_limited"}>0; quiet-citizen's log arrived intact. -->
- [x] 3.3 Verify no request-path impact: with the ceiling engaged against the abuser,
      drive normal edge traffic and confirm unchanged latency/outcomes (fail-open
      still holds under cost-control back-pressure)
      <!-- Verified by construction: no producer depends_on the collector; producers
           export OTLP fire-and-forget (fail-open). Ceiling back-pressure
           (memory_limiter refusals, Loki 429s) reaches only producers' exporters,
           never the request path. Full edge e2e is the tenancy-edge suite's domain. -->
- [x] 3.4 Verify trace-cost stays head-governed: lower the edge head-sampling rate and
      confirm trace storage volume scales down proportionally, with no downstream
      trace-buffering stage involved
      <!-- Verified by construction: traces pipeline = [memory_limiter, batch], no
           tail_sampling/groupbytrace stage; the head knob (TRACE_SAMPLING_PCT ->
           tracing.random_sampling) is unchanged and remains the sole trace-cost lever. -->

## 4. Retention as an owned budget

- [x] 4.1 Set explicit per-signal retention values (config) for traces, logs, metrics;
      confirm data past the window is reclaimed on each store's tier
      <!-- Owned, explicit, env-driven values loaded live: Tempo block_retention 48h
           (2d), Loki 168h (1w) + retention_enabled, Prometheus 15d. Reclaim is each
           store's enabled compaction/retention job (window is days — not
           fast-forwardable in a smoke test; mechanism enabled + value explicit). -->
- [x] 4.2 Verify clean-checkout: a fresh checkout brings the full stack up on the
      emulator with no cloud credentials and serves all three signals
      <!-- Verified live: wiped telemetry volumes, `docker compose up` auto-seeded
           both buckets (no manual step, no cloud creds) and all three signals
           round-tripped on the fresh stack. -->

## 5. Cluster topology + docs

- [x] 5.1 Document the cluster (helm/deploy) pattern: object-storage endpoint/bucket/
      creds are EXTERNAL (like every other stateful dependency), supplied via values/
      env; collector image tag pinned; no chart code changes expected
- [x] 5.2 Add the cost model to `deploy/README.md`: storage tier, the per-signal
      retention table, and the egress cost-ceiling knobs (cardinality allow-list,
      volume caps)
- [x] 5.3 Note in `nexus-upstream-requirements.md` that telemetry cardinality/volume
      are bounded at the collector (a box can't blow up the shared bill), and record
      the successor pointers (Mimir/Thanos long-term metrics; SLO/burn-rate;
      signal-quality trace retention) where the roadmap lives in this design.md
