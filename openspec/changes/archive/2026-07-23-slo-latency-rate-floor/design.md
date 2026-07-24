# Design — slo-latency-rate-floor

## Context

N15 (`slo-sloth-source-and-floor`) floored the four tenant-router / identity-sidecar
burn-rate SLIs with a **per-window minimum sample count**, appended to each SLO's
`total_query`:

```
total_query: (<existing total>) and (sum by (deployment_environment_name) (increase(<denom>[{{.window}}])) > 60)
```

`60` was chosen as "the repo's existing bar" — `routingMinRps: 0.2` documented as
"≈ 60 req / 5m". The flaw N16 surfaced: `increase(...) > 60` is a *count*, and a count is
**window-length-dependent**. It reproduces 0.2 req/s only on the 5m window; on the longer
windows that drive the slow-burn page it collapses to a near-zero rate (6h → 0.0028 req/s,
~three orders of magnitude below 0.2 req/s). So the long windows are effectively unfloored.

Live evidence (N16, one day after N15, `app.dufeut.com` at ~0.12 req/s):
`TenantRouterLatency` is **still paging** (`page` and `ticket`). The 30m/6h denominators
(~210 / ~1525) sit far above `60`, so the floor never engages — yet 0.12 req/s is far too
low for a 1%-budget latency page to carry signal. Worse, the surviving page now *looks*
real because it clears the count floor. (The underlying 1/7 error ratio is a structural
artifact of a fixed ~1/min ext_proc cold miss — real, but a workload bug, not an SLO
event; that's N16 fix #2, out of scope here.)

The full toolchain is unchanged from N15 and stays in place:
- Sources: `monitoring/slo/{tenant-router,identity-sidecar}.slo.yaml`
- Generator: `monitoring/slo/generate.sh` (pinned `ghcr.io/slok/sloth:v0.16.0`) → writes
  `monitoring/prometheus/rules/*` and **stages** each into `deploy/helm/<chart>/files/slo/*`.
- Validation: `monitoring/slo/check.sh` (promtool `check rules` + `test rules`).
- CI: `ci.yml` `monitoring-delivery` runs generate → `git diff --exit-code` (drift) → check.

Constraints (unchanged): floor lives in the *source* only (generated output is
`# DO NOT EDIT`); `generate.sh`/`check.sh` are docker-based POSIX `sh` handling the Windows
Git-Bash / CI nonroot-bind-mount quirks ([[ci-windows-script-exec-and-bindmount]]);
edge-platform has no `files/slo/` so it is not a consumer.

## Goals / Non-Goals

**Goals**
- The long-window idle pages that survived N15 stop; the floor means the same 0.2 req/s on
  every evaluation window (5m through 6h/3d).
- Objectives (99% latency / 99.9% availability), windows, burn factors, and above-floor
  behaviour unchanged.
- Availability outage coverage for the near-zero-traffic case still preserved by the
  readiness backstop.
- The burn-rate unit tests stay green and gain a long-window below-rate-floor suppression
  case (the exact N16 scenario).

**Non-Goals**
- No new source layout, generator, or CI — reuse N15's pipeline verbatim.
- No change to objectives, windows, or burn factors; no new telemetry; no producer redeploy.
- **Not** fixing the router's ~1/min ext_proc cold miss (N16 fix #2 — a workload change).
  This change is the alerting arm only.
- Not touching the total-process-death gap (readiness gauge goes *absent*, not `0`) —
  pre-existing platform-layer concern, unchanged from N15.

## Decisions

### D1 — Swap the per-window sample **count** for a window-independent **rate** floor.

Replace, in every SLI `total_query` on both services:

```
and (sum by (deployment_environment_name) (increase(<denom>[{{.window}}])) > 60)
→ and (sum by (deployment_environment_name) (rate(<denom>[{{.window}}])) > 0.2)
```

`rate()` yields per-second volume, so `> 0.2` is the identical 0.2 req/s bar on every
window `{{.window}}` Sloth substitutes — 5m, 30m, 1h, 2h, 6h, 1d, 3d. Below 0.2 req/s on a
window the `and` empties that window's `slo:sli_error:ratio_rateXX` series, so the
`(short) and (long)` burn-rate alert cannot fire from it. No alert-rule edit; the guard
stays in `total_query` exactly as N15 placed it, only the expression changes.

- **Denominator unchanged** — the objective's own total series, already in each
  `total_query`: `router_ext_proc_requests_total` (routing availability),
  `router_ext_proc_duration_seconds_count{result="hit"}` (routing latency), and the
  `sidecar_ext_proc_*` equivalents with the identity result-matchers. No new metric.
- **`0.2` single-sourced per objective** as one literal per `total_query`, same as the `60`
  it replaces — tunable, and now the *same* number the hand-authored `_monitoring.tpl`
  threshold alerts already floor on (`routingMinRps`/`enrichMinRps: 0.2`), so both alert
  families share one significance bar instead of two representations of it.

### D2 — This deliberately reverses N15's D2 "why not uniform per-second" rationale.

N15's design rejected a uniform per-second floor with: *"a flat rate over-floors long
windows and would suppress the long-window ticket arm for a low-but-steady tenant even
though it has ample samples over 6h/3d."* N16 shows that reasoning is exactly backwards for
this SLO:

- "Ample samples over 6h" does **not** make a ratio meaningful when the *rate* is 0.12 req/s.
  The page carries no signal at that volume regardless of how many samples accumulate — a
  1%-budget latency objective at 0.12 req/s is dominated by a single structural slow event.
- The thing N15 wanted to preserve — the long-window ticket arm firing for a "low-but-steady
  tenant" — is precisely the false page N16 is filing. "Low-but-steady" below 0.2 req/s is
  the regime where the ratio is not trustworthy; keeping it alertable is the defect, not a
  feature.
- The `service-slo-policy` spec's own scenarios already say "minimum sample **rate**" and
  "once the request **rate** exceeds the floor" — N15's count implementation was already out
  of step with the written contract. This aligns them.

Fairness to N15: its "ample samples over 6h/3d" rationale is a real industry position —
GitLab metrics-catalog holds it too and defaults to a sample *count* (3,600) for exactly
that reason. It holds when the error is *volume*-proportional (more samples genuinely
dilute a transient). It does **not** hold for nexus's failure here, which is
*time*-proportional: a fixed ≈1/min cold miss pins the ratio at 1/7 no matter how many
samples accumulate, so "more samples over a long window" adds no signal — only a higher
actual request *rate* dilutes it. That specificity, plus the 5m→3d scale-invariance
argument, is why the call is re-decided in favour of rate. See the /opsx:decide block below.

### D3 — Apply to all four SLIs; availability still backstopped by the readiness gauge.

The rate floor goes on availability and latency, both services — same four `total_query`
lines N15 floored. Flooring availability remains safe because the **traffic-independent**
backstop is untouched: `NexusRoutingNotReady` / `NexusIdentitySidecarNotReady`
(`router_ready == 0`, `severity: critical`, `for: 10m`) still fire on sustained unreadiness
regardless of volume (satisfies the `service-slo-policy` backstop requirement). The
residual absent-metric gap (process fully dead → gauge absent, not `0`) is unchanged from
N15 and stays out of scope.

### D4 — Reuse the existing generation/CI; extend the burn-rate unit tests.

Edit the two `*.slo.yaml`, run `generate.sh`, commit the regenerated
`monitoring/prometheus/rules/*` and staged `deploy/helm/*/files/slo/*` (diff = the floor
expression only). `check.sh` and CI `monitoring-delivery` are unchanged.

- **Test impact:** N15's tests assert firing under synthetic traffic sized against the *count*
  floor. Re-express those fixtures against the *rate* floor: the above-floor firing cases
  must drive > 0.2 req/s on the relevant windows (a total-outage ratio still fires). Then
  **add the N16 case**: a long window (e.g. 6h) at ~0.12 req/s with a bad ratio — a sample
  *count* that clears an equivalent 60-count but a *rate* below 0.2 — asserts **no alert
  fires**. This is the regression that would have caught N16.

## Decisions (build-vs-adopt, /opsx:decide)

### Decision: Multi-window burn-rate rule generation — Adopt Sloth v0.16.0 (unchanged)

- **Status**: approved (carried from N15)
- **Why**: Correctness-critical burn-rate math; Sloth is the already-adopted generator with a
  working generate/validate/drift pipeline. This change is a one-token edit to its existing
  sources — no reason to revisit the tool.
- **Isolation**: floor lives in `monitoring/slo/*.slo.yaml`; Sloth invoked only by the
  existing `generate.sh`; output vendored behind `.Files.Get`.

### Decision: Min-sample floor model — Adopt GitLab's `minimumOpsRateForMonitoring` (request-**rate**) primitive, valued at nexus's `0.2 req/s` bar

- **Status**: approved (supersedes N15's "Extend the repo's 60-sample threshold" decision)
- **Tier**: Adopt (established pattern) — not Build. The rate floor is exactly GitLab
  metrics-catalog's `minimumOpsRateForMonitoring` knob (average ops-rate per window),
  instantiated at the significance bar nexus already documents (`routingMinRps` = 0.2 req/s).
- **Why**: A multi-window burn-rate family spans 5m→3d (an 864× range). No single sample
  **count** is correct across it — a count sized for the 5m window (~60) is ~864× too lax on
  3d; a count sized for 3d (GitLab's 3,600) demands **12 req/s** on the 5m window and would
  suppress legitimate fast-burn pages. Only a **rate** is scale-invariant across the span, so
  one `rate(<denom>[{{.window}}]) > 0.2` literal floors 0.12 req/s on *every* window (fixing
  N16) without over-flooring the short window. It also matches the wording the
  `service-slo-policy` spec already used ("minimum sample **rate**").
- **Research (industry standards, 2026)**:
  - *Google SRE Workbook (Alerting on SLOs)* names the low-traffic problem but prescribes
    **no numeric floor** — it suggests synthetic traffic, service aggregation, product
    changes, or relaxing the SLO. So there is no canonical count *or* rate to copy; the
    primitive choice is ours to make against nexus's failure mode.
  - *GitLab metrics-catalog* exposes **both** primitives — `minimumOpsRateForMonitoring`
    (rate) and `minimumSamplesForMonitoring` (count, default **3,600**) — and migrated *from*
    a fixed 1 RPS rate to counts to keep low-traffic services monitorable over long windows.
    Honest correction to N15: its `60` was not just "the wrong model" but ~60× below GitLab's
    count — GitLab's own 3,600 count would have floored N16's 6h case (~2,592 < 3,600). We
    still choose rate over "raise the count" because of the 5m→3d scale-invariance above, and
    because nexus's failure is a *time-proportional* structural miss (≈1/min cold miss) that
    more samples never dilute — only a higher actual rate does.
- **Considered**:
  - *Count floor raised to GitLab's 3,600 (`increase > 3600`):* fixes N16's 6h case but is
    scale-variant — over-floors the 5m window (needs 12 req/s), under-floors 3d (0.014 req/s).
    No single count fits the multi-window span.
  - *Both primitives (`rate > 0.2 and increase > N`):* mirrors GitLab exposing both knobs;
    redundant once the rate arm is scale-invariant — two literals per objective, second tuning
    surface, no extra coverage of nexus's single failure mode.
- **Isolation**: one `0.2` literal per objective in the source `total_query`; expanded to all
  windows by generation. Single source of truth for the burn-rate floor, and now the *same*
  `0.2 req/s` value the hand-authored `_monitoring.tpl` threshold alerts already floor on.

## Risks / Trade-offs

- **A genuinely-degrading tenant that is truly below 0.2 req/s on all windows is now
  unfloored-out of the burn-rate page.** → This is intended (below 0.2 req/s the ratio isn't
  trustworthy), and the availability outage case is still caught by the traffic-independent
  readiness backstop (D3). Latency at sub-0.2-req/s has no user-scale impact worth a page.
- **N15's tests assume the count floor** (D4) → re-size the firing fixtures against rate and
  add the below-rate-floor suppression case; `check.sh` must stay green.
- **Generated-output diff churn** → the only intended change is `increase(...) > 60` →
  `rate(...) > 0.2` on each `slo:sli_error:ratio_rateXX` `total_query`; review both
  `monitoring/prometheus/rules/*` and the staged Helm copies for exactly that.
- **`0.2` may still be low if nexus scales** → tunable per objective, same as the `60` it
  replaces; it is the repo's documented significance bar, so it stays consistent with the
  threshold-alert family until deliberately revised.

## Migration Plan

1. Edit both `monitoring/slo/*.slo.yaml` (four `total_query` lines); run
   `monitoring/slo/generate.sh`; commit the regenerated `monitoring/prometheus/rules/*` and
   staged `deploy/helm/*/files/slo/*` (diff = floor expression only).
2. Update `tests/tenant-router.slo_test.yaml`; run `monitoring/slo/check.sh` → green.
3. Rules-only change (no producer redeploy). **Rollback:** revert the source edit +
   regenerate; the previous `> 60` rules return.
4. Validate: at 0.12 req/s on 30m/6h the SLI now yields no series (page silenced); above
   0.2 req/s SLI values and objectives are unchanged; readiness alerts unaffected.
5. In `docs/infra-findings.md`, mark N16's **alerting arm** resolved; leave the ~1/min
   ext_proc cold miss (fix #2) open as workload scope.

## Open Questions

- None blocking. The cold-miss workload fix (N16 #2) is tracked separately in the finding
  and is out of scope for this change.
