## Why

N15 floored the tenant-router and identity-sidecar burn-rate SLIs with a **per-window
sample count** — `and (increase(<denom>[{{.window}}]) > 60)`. That guard is
window-length-dependent, so it is a near no-op on the long windows that drive the
slow-burn page: `60` samples over a 6h window is `0.0028 req/s`, three orders of magnitude
below the `0.2 req/s` significance bar (`routingMinRps`) the change itself cited. A day
after N15 shipped, `TenantRouterLatency` is **still paging** (both `page` and `ticket`) on
`app.dufeut.com` — at ~0.12 req/s the 30m/6h denominators (~210 / ~1525) sit far above the
flat `60` floor, so the floor never engages, yet the traffic is still far too low for a
1%-budget latency page to carry signal (infra finding **N16**).

The fix N16 prescribes is narrow and single-layer: make the floor **window-independent** —
a rate (`req/s`) rather than a per-window count — so it means the same `0.2 req/s` on every
evaluation window. The `service-slo-policy` spec's own scenarios already phrase the floor
as a "minimum sample **rate**"; N15's sample-count implementation diverged from that
wording. This change aligns the implementation with the spec and sharpens the spec to
forbid a window-length-dependent count.

## What Changes

- **Replace the per-window sample-count floor with a window-independent rate floor** in
  the two existing `monitoring/slo/*.slo.yaml` sources: swap each
  `and (... increase(<denom>[{{.window}}]) > 60)` for
  `and (... rate(<denom>[{{.window}}]) > 0.2)`. Applied to **all four SLIs** — availability
  and latency on both `tenant-router` and `identity-sidecar` — so every burn-rate window
  gates on the same `0.2 req/s` bar instead of a count that grows with window length.
- **Regenerate** via the existing `monitoring/slo/generate.sh` (refreshes
  `monitoring/prometheus/rules/*` and the Helm-vendored `files/slo/*` copies); the
  generated rules are never hand-edited.
- **Extend the burn-rate unit tests** (`monitoring/slo/tests/`) so a long-window,
  above-old-count-floor / below-rate-floor case (the exact N16 scenario: ~0.12 req/s on a
  6h window) is now **suppressed**, while a genuinely-above-`0.2 req/s` case still fires.
- **N16's scope is alerting only.** The router's ~1/min ext_proc cold-miss (finding fix #2,
  a workload change) is explicitly **out of scope** for this change.
- Move N16 in `docs/infra-findings.md` toward resolved for the alerting arm, noting the
  cold-miss remains open as separate workload scope.

## Capabilities

### New Capabilities
<!-- none — this corrects an existing requirement's realization -->

### Modified Capabilities

- `service-slo-policy`: the existing "Ratio and rate-quantile alerts do not fire below a
  minimum sample volume" requirement is sharpened so the floor is a **request-rate**
  (`req/s`) threshold that is **identical across every evaluation window**, explicitly
  ruling out a per-window sample **count** (which varies with window length and so fails to
  floor the long windows). A scenario is added: a low-traffic service whose long-window
  sample *count* clears an equivalent count but whose *rate* is below the floor SHALL still
  be withheld.

<!-- portable-monitoring-delivery is NOT modified: single-source generation, reproducible
     output, and CI drift-detection already exist and already carry the changed floor. -->

<!-- Critical concern deferred to /opsx:decide: the floor model — reliability-sensitive;
     the choice is rate-vs-count, recorded in design.md Decisions. -->

## Impact

- **Sources (in-scope):** `monitoring/slo/tenant-router.slo.yaml`,
  `monitoring/slo/identity-sidecar.slo.yaml` — floor changes from `increase(...) > 60` to
  `rate(...) > 0.2` on all four SLIs.
- **Generated output (regenerated, not hand-edited):** `monitoring/prometheus/rules/*` and
  the staged `deploy/helm/{routing-plane,identity-plane}/files/slo/*.rules.yaml`.
- **Tests:** `monitoring/slo/tests/tenant-router.slo_test.yaml` — add the N16 long-window
  below-rate-floor suppression case; keep above-floor firing green.
- **Config:** the floor is single-sourced per objective as a literal in the Sloth source
  (`rate(...) > 0.2`; `0.2` = the repo's existing `routingMinRps` req/s bar).
- **Out of scope:** the router's ~1/min ext_proc cold-miss (N16 fix #2, workload); no
  producer changes; no measured service redeployed.
- **Alerting behaviour:** the long-window idle pages that survived N15 stop; objectives,
  error budgets, and genuinely-above-`0.2 req/s` behaviour unchanged. Availability outage
  coverage is still preserved via the readiness backstop (`NexusRoutingNotReady`, etc.).
- **Docs:** N16 in `docs/infra-findings.md` — alerting arm resolved; cold-miss noted as
  open workload scope.
