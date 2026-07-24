# Tasks — slo-sloth-source-and-floor

## 1. Author the floor into the existing sources

- [x] 1.1 `monitoring/slo/tenant-router.slo.yaml`: append the floor to both SLOs'
  `total_query` — `... and (sum by (deployment_environment_name) (increase(<denom>[{{.window}}])) > 60)`
  where `<denom>` is `router_ext_proc_requests_total` (availability) and
  `router_ext_proc_duration_seconds_count{result="hit"}` (latency).
- [x] 1.2 `monitoring/slo/identity-sidecar.slo.yaml`: same, with `sidecar_ext_proc_requests_total`
  (availability) and `sidecar_ext_proc_duration_seconds_count{result!~"not_ready|unavailable_closed"}`
  (latency).
- [x] 1.3 Keep the floor single-sourced: one `60` literal per objective (design D2; 60 = the
  repo's existing "≈60 req/5m" bar, tunable).

## 2. Regenerate via the existing toolchain

- [x] 2.1 Run `monitoring/slo/generate.sh` (pinned `ghcr.io/slok/sloth:v0.16.0`); it rewrites
  `monitoring/prometheus/rules/*.rules.yaml` and re-stages `deploy/helm/*/files/slo/*`.
- [x] 2.2 Review the diff: the only change is `and (... increase ... > 60)` on each
  `slo:sli_error:ratio_rateXX` in both output locations; alerts, labels, objectives, and
  burn factors unchanged.
- [x] 2.3 Confirm the 5m window reproduces the prior ~0.2-rps floor (60 samples / 300s).

## 3. Update the burn-rate unit tests

- [x] 3.1 `monitoring/slo/tests/tenant-router.slo_test.yaml` test 1: raise the synthetic
  traffic above the floor (≥60 samples/5m for both production and staging series) so the
  outage still asserts the page + ticket and staging still asserts SLI = 0.
- [x] 3.2 Add a **below-floor suppression** case: a bad error ratio at near-idle traffic
  (<60 samples/window) asserts **no alert fires** — the direct N15 behaviour.
- [x] 3.3 (Optional) mirror a minimal above/below-floor case for identity if a test file is
  added; otherwise rely on the shared floor mechanism proven by the routing tests.

## 4. Validate

- [x] 4.1 Run `monitoring/slo/check.sh` — promtool `check rules` (PromQL portability) and
  `test rules` (burn-rate unit tests) both green.
- [x] 4.2 Render both charts under `files` and `operator` delivery (as CI does) and confirm
  each `slo:sli_error:ratio_rateXX` carries the floor and the four alerts are otherwise
  unchanged.
- [x] 4.3 Confirm no drift: a second `generate.sh` run leaves a clean `git diff` (mirrors the
  CI `monitoring-delivery` drift check).

## 5. Docs + close-out

- [x] 5.1 Mark N15 resolved in `docs/infra-findings.md` — correct its "source spec is not in
  the repo" claim, link this change, and record the residual absent-metric/`up == 0` gap as
  the D3 follow-up.
- [x] 5.2 If the `*MinRps` low-traffic floor doc in `deploy/README.md` needs a pointer to the
  burn-rate family's floor, add a one-line note; otherwise leave as-is.
