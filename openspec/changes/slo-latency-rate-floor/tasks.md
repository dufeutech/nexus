# Tasks — slo-latency-rate-floor

## 1. Swap the count floor for a rate floor in the sources

- [x] 1.1 `monitoring/slo/tenant-router.slo.yaml`: in both SLOs' `total_query`, replace
  `and (sum by (deployment_environment_name) (increase(<denom>[{{.window}}])) > 60)` with
  `and (sum by (deployment_environment_name) (rate(<denom>[{{.window}}])) > 0.2)` — `<denom>`
  = `router_ext_proc_requests_total` (availability) and
  `router_ext_proc_duration_seconds_count{result="hit"}` (latency).
- [x] 1.2 `monitoring/slo/identity-sidecar.slo.yaml`: same swap, with
  `sidecar_ext_proc_requests_total` (availability) and
  `sidecar_ext_proc_duration_seconds_count{result!~"not_ready|unavailable_closed"}` (latency).
- [x] 1.3 Keep the floor single-sourced: one `0.2` literal per objective (design D1/D2;
  `0.2` = the repo's `routingMinRps`/`enrichMinRps` req/s bar, tunable), and update each
  SLI's inline floor comment from the "≈60 req/5m sample count" wording to the
  window-independent `0.2 req/s` rate.

## 2. Regenerate via the existing toolchain

- [x] 2.1 Run `monitoring/slo/generate.sh` (pinned `ghcr.io/slok/sloth:v0.16.0`); it rewrites
  `monitoring/prometheus/rules/*.rules.yaml` and re-stages `deploy/helm/*/files/slo/*`.
- [x] 2.2 Review the diff: the only change is `increase(...) > 60` → `rate(...) > 0.2` on each
  `slo:sli_error:ratio_rateXX` `total_query` in both output locations; alerts, labels,
  objectives, and burn factors unchanged.
- [x] 2.3 Confirm the floor is now identical across every window (5m…6h/3d) — `rate() > 0.2`
  is window-independent, unlike the prior count.

## 3. Update the burn-rate unit tests

- [x] 3.1 `monitoring/slo/tests/tenant-router.slo_test.yaml`: re-size the existing
  above-floor firing case(s) against the **rate** floor — drive > 0.2 req/s on the relevant
  windows so the outage still asserts page + ticket (and staging still asserts its SLI).
- [x] 3.2 Add the **N16 regression** case: a long window (e.g. 6h) at ~0.12 req/s with a bad
  error ratio — a sample *count* that clears an equivalent 60-count but a *rate* below 0.2 —
  asserts **no alert fires**. This is the case the count floor let through.
- [x] 3.3 Keep/repoint any below-floor case from N15 so both the short-window and the new
  long-window suppression paths are covered.

## 4. Validate

- [x] 4.1 Run `monitoring/slo/check.sh` — promtool `check rules` (PromQL portability) and
  `test rules` (burn-rate unit tests) both green.
- [x] 4.2 Render both charts under `files` and `operator` delivery (as CI does) and confirm
  each `slo:sli_error:ratio_rateXX` carries the `rate(...) > 0.2` floor and the four alerts
  are otherwise unchanged.
- [x] 4.3 Confirm no drift: a second `generate.sh` run leaves a clean `git diff` (mirrors the
  CI `monitoring-delivery` drift check).

## 5. Docs + close-out

- [x] 5.1 In `docs/infra-findings.md`, mark N16's **alerting arm** resolved (link this
  change); explicitly leave the ~1/min ext_proc cold miss (fix #2) open as workload scope.
- [x] 5.2 If the `*MinRps` low-traffic floor note in `deploy/README.md` references the
  burn-rate family's floor, update it to say the burn-rate floor is now a window-independent
  `0.2 req/s` rate (was a per-window 60-sample count); otherwise leave as-is.
