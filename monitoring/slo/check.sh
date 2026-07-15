#!/usr/bin/env sh
# Validate the generated SLO rule files (change: victoriametrics-delivery — Adopt
# promtool). Two gates, both via the PINNED promtool (bundled in the Prometheus image);
# no live stack needed — deterministic, CI-friendly.
#
#   ./monitoring/slo/check.sh
#
#   1. `promtool check rules` — syntax + PromQL validity over the generated rules. This
#      IS the PORTABILITY guard (portable-monitoring-delivery): a VictoriaMetrics-only
#      MetricsQL construct is not valid PromQL and fails here, so the shipped rules stay
#      portable across ANY PromQL backend (Prometheus AND VictoriaMetrics).
#   2. `promtool test rules` — the SLO unit tests in tests/*.slo_test.yaml: synthetic
#      series -> asserted ALERTS, so burn-rate FIRING is checked, not just parsed. The
#      same rules the lab's vmalert evaluates operator-lessly.
#
# Requires: docker. Keep PROMTOOL_VERSION aligned with the lab (docker-compose.yaml).
set -eu

export MSYS_NO_PATHCONV=1
export MSYS2_ARG_CONV_EXCL="*"

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
PROMTOOL_IMAGE="prom/prometheus:${PROMTOOL_VERSION:-v3.5.0}"

echo "== promtool check rules (syntax + PromQL portability guard) =="
# `sh -c` so the container shell expands the *.rules.yaml glob (promtool takes no glob).
docker run --rm --entrypoint sh \
  -v "$ROOT/monitoring/prometheus/rules:/rules:ro" \
  "$PROMTOOL_IMAGE" -c 'promtool check rules /rules/*.rules.yaml'

echo "== promtool test rules (SLO burn-rate unit tests) =="
# Mount the repo root so each test's relative rule_files (../../prometheus/rules/...)
# resolves the same way it does from tests/.
docker run --rm --entrypoint sh \
  -v "$ROOT:/w:ro" \
  "$PROMTOOL_IMAGE" -c 'promtool test rules /w/monitoring/slo/tests/*.slo_test.yaml'

echo "OK: rules are valid portable PromQL and the SLO burn-rate tests pass."
