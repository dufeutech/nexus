# Edge load / capacity harness

The CI e2e release gate proves the edge is **correct** (it enforces the trust
contract, per-route auth, fail-closed behavior). It says nothing about **capacity** —
how much traffic the edge sustains, and at what tail latency. This harness closes
that gap so an operator can validate capacity before a production rollout.

## What it measures

A fixed **offered load** (open model, so a stall shows as latency, not vanished
requests) driven through the real Envoy filter chain, across three cost paths:

| Scenario | Route | What it exercises |
| --- | --- | --- |
| `baseline_public` | `/public` | pure proxy cost — ext_proc disabled |
| `enriched_anon` | `/` | tenant-router + identity sidecar ext_proc (the hot path) |
| `protected_401` | (set `PATH_PROTECTED`) | the auth-gate 401 path, no credential |

Reports throughput and `p95`/`p99` latency, and **gates** against operator-set SLOs
(exit non-zero when a threshold is crossed — so it is CI-gateable).

## Why k6

Capacity numbers are only trustworthy if the load model avoids coordinated omission
and the percentiles are correct. Per the repo's build-vs-adopt gate, that
measurement-correctness-critical work is **adopted** (k6's constant-arrival-rate
executor + thresholds), not hand-rolled in shell.

## Run it

```sh
# 1. bring the target up
docker compose up -d            # local lab: edge on :10000

# 2. install k6 -> https://k6.io/docs/get-started/installation/

# 3. run (defaults target the local lab)
scripts/load/run-load.sh

# tune offered load + SLOs for your infra
RATE=500 DURATION=120s SLO_P95_MS=120 SLO_P99_MS=250 scripts/load/run-load.sh

# against a real deployment
EDGE=https://edge.example.com HOST=acme.example.com \
  RATE=1000 SLO_ERROR_RATE=0.001 scripts/load/run-load.sh
```

Each run also writes `load-summary.json` (override with `SUMMARY_OUT=`) for
trend-tracking across runs.

## Knobs (all via env)

| Var | Default | Meaning |
| --- | --- | --- |
| `EDGE` | `http://localhost:10000` | edge base URL |
| `HOST` | `localhost` | Host header → seeded workspace |
| `RATE` | `200` | offered requests/sec **per scenario** |
| `DURATION` | `60s` | measured window |
| `PREALLOC_VUS` / `MAX_VUS` | `50` / `500` | VU pool for the arrival-rate executor |
| `PATH_PUBLIC` / `PATH_ENRICHED` / `PATH_PROTECTED` | `/public` / `/` / *(off)* | route overrides |
| `SLO_P95_MS` / `SLO_P99_MS` | `150` / `300` | latency SLOs (**placeholders — set real ones**) |
| `SLO_ERROR_RATE` | `0.001` | max non-expected-status fraction |

## Caveats — read before trusting a number

- **The default SLOs are placeholders.** A capacity test without a real target is
  just a number. Set `SLO_*` to your actual objectives before treating the exit
  code as a gate.
- **Run the generator off-box.** k6 on the same host as the edge competes for CPU
  and skews the tail. For real numbers, drive from a separate machine/pod close in
  network terms to the edge.
- **Warm-up matters.** The harness sends 20 priming requests, but pools, JITless
  Rust is already warm, connection reuse, and any upstream autoscaling still need
  a few seconds — prefer `DURATION>=60s` and ignore the first run after a cold
  start.
- **This drives the edge, not your backend.** The whoami/echo backend in the lab
  is intentionally trivial; capacity of *your* box is a separate measurement.
- **Not wired into CI by default.** Capacity gating belongs in a scheduled/perf
  job against a production-like environment, not the per-PR gate (which must stay
  fast and hermetic). Wire `run-load.sh` there once you have stable SLOs.
