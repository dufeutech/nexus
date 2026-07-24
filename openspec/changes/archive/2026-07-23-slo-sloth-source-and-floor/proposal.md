## Why

The multi-window burn-rate SLO alerts for the tenant-router and identity-sidecar
(`TenantRouterLatency/Availability`, `IdentitySidecarLatency/Availability`) carry **no
minimum-sample floor**, so at idle traffic a handful of slow or not-ready samples
dominate the ratio and a `severity: page` alert fires with no user-visible problem. This
already paged for a non-incident on `app.dufeut.com` go-live day (infra finding **N15**;
749 req / 6h ≈ 0.035 req/s). The `service-slo-policy` spec **already requires** these
ratio/quantile alerts to be floored — but the prior change (`slo-low-traffic-guards`) only
floored the hand-authored threshold alerts in `_monitoring.tpl`; the Sloth-generated
burn-rate family was left as the known remaining gap.

The Sloth **source of truth already exists** at `monitoring/slo/*.slo.yaml`, with a
`generate.sh` (regenerates `monitoring/prometheus/rules/` and stages the Helm-vendored
copies) and CI drift/validation already wired. N15's claim that the source "is not in the
repo" was mistaken — only the *floor* was never authored into those sources. So the fix is
narrow: add the floor to the existing sources and regenerate, letting the existing
toolchain carry it into every delivery form.

## What Changes

- **Author a minimum-sample traffic floor into each burn-rate SLI** in the two existing
  `monitoring/slo/*.slo.yaml` sources, applied **per evaluation window** as a minimum
  sample count, so below the floor the SLI yields no samples and the page cannot fire on
  statistical noise — while behaviour above the floor, and the 99% / 99.9% objectives
  themselves, are unchanged.
- **Floor both latency and availability SLOs**, relying on the existing
  traffic-independent readiness alerts (`NexusRoutingNotReady`,
  `NexusIdentitySidecarNotReady`, `router_ready == 0` style, `severity: critical`) as the
  backstop that still catches an up-but-broken outage when traffic is near zero.
- **Regenerate** via the existing `monitoring/slo/generate.sh` and **extend the existing
  burn-rate unit tests** (`monitoring/slo/tests/`) so they exercise above-floor firing and
  a new below-floor suppression case. Generation, drift-check, and promtool validation
  already run in CI — no new CI is added.
- Record the residual gap (no `up == 0` / metric-absent alert catches total process death,
  where the readiness gauge goes *absent* rather than `0`) as a follow-up; it is
  pre-existing and likely platform/infra scope, not fixed here.

## Capabilities

### New Capabilities
<!-- none — this realizes an existing contract for the generated burn-rate family -->

### Modified Capabilities

- `service-slo-policy`: the existing "ratio and rate-quantile alerts do not fire below a
  minimum sample volume" requirement is extended to the **multi-window burn-rate** SLO
  family (currently unfloored), with the floor applied per evaluation window against the
  objective's own denominator. Adds a **safety requirement**: when an availability/ratio
  SLO is floored, its unavailability must remain observable through a traffic-independent
  signal, so a near-zero-traffic outage is not masked by the floor.

<!-- portable-monitoring-delivery is NOT modified: single-source generation, reproducible
     output, and CI drift-detection already exist and already satisfy that spec. -->

<!-- Critical concern deferred to /opsx:decide (already recorded in design.md Decisions):
     the min-sample floor model — reliability-sensitive; sample-count per-window floor. -->

## Impact

- **Sources (in-scope):** `monitoring/slo/tenant-router.slo.yaml`,
  `monitoring/slo/identity-sidecar.slo.yaml` — gain the floor.
- **Generated output (regenerated, not hand-edited):** `monitoring/prometheus/rules/*` and
  the staged `deploy/helm/{routing-plane,identity-plane}/files/slo/*.rules.yaml`.
- **Tests:** `monitoring/slo/tests/tenant-router.slo_test.yaml` — above-floor firing kept
  green; new below-floor suppression case added.
- **Config:** the floor is single-sourced per objective as a literal in the Sloth source
  (`increase(...) > 60`; 60 = the repo's existing "≈60 req/5m" bar).
- **Out of scope:** edge-platform (no `files/slo/`, not a burn-rate consumer); the
  residual absent-target gap (pre-existing, likely infra).
- **Alerting behaviour:** idle-window pages on the four burn-rate alerts stop; objectives,
  error budgets, and above-floor behaviour unchanged. Availability outage coverage is
  preserved via the readiness backstop.
- **Docs:** N15 in `docs/infra-findings.md` moves to resolved (correcting its "source not
  in repo" claim). No producer changes; no measured service redeployed.
