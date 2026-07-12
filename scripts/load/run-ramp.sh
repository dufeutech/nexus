#!/usr/bin/env sh
# Capacity-CURVE harness for the nexus edge — finds the KNEE (offered rate at which
# the tail breaks the SLO), which the fixed-rate run-load.sh cannot show.
#
# It sweeps a ladder of offered rates (STEPS) through ONE cost path at a time and
# prints a capacity table + the first SLO-breaching step. Same open-model k6 core
# as run-load.sh (no coordinated omission); we only add the stepping.
#
# Prereqs:
#   1. The target stack is up and reachable at $EDGE (local lab: docker compose up -d).
#   2. k6 on PATH, OR set K6_DOCKER=1 to run via the grafana/k6 container.
#
# Usage:
#   scripts/load/run-ramp.sh                                  # enriched path, default ladder
#   PATH_MODE=public scripts/load/run-ramp.sh                 # ramp the proxy-only path
#   STEPS="200,500,1000,2000,5000" STEP_DURATION=45s \
#     SLO_P99_MS=250 scripts/load/run-ramp.sh                 # custom ladder + SLO
#   EDGE=https://edge.example.com HOST=acme.example.com \
#     STEPS="500,1000,2000,4000,8000" scripts/load/run-ramp.sh  # real deployment
#
# Exit code: k6's — non-zero if ANY step breached a per-step threshold (so a
# scheduled perf job can gate on "did we hold SLO up to the target rate?").
set -u

EDGE="${EDGE:-http://localhost:10000}"
HOST="${HOST:-localhost}"
PATH_MODE="${PATH_MODE:-enriched}"
STEPS="${STEPS:-100,250,500,1000,2000,4000}"
STEP_DURATION="${STEP_DURATION:-30s}"
HERE="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
SCRIPT="$HERE/edge-load-ramp.js"

echo "== nexus edge capacity-curve harness =="
echo "   target : $EDGE   (Host: $HOST)"
echo "   path   : $PATH_MODE"
echo "   ladder : $STEPS req/s  (each step $STEP_DURATION)"
echo "   SLOs   : p95<${SLO_P95_MS:-150}ms  p99<${SLO_P99_MS:-300}ms  err<${SLO_ERROR_RATE:-0.001}"
echo

# Probe path depends on which path we ramp (protected expects 401, others 200).
PROBE_PATH="/public"
[ "$PATH_MODE" = "enriched" ] && PROBE_PATH="/"
[ "$PATH_MODE" = "protected" ] && PROBE_PATH="${PATH_PROTECTED:-/protected}"

probe="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 5 \
  -H "Host: $HOST" "$EDGE$PROBE_PATH" 2>/dev/null || echo "000")"
if [ "$probe" = "000" ]; then
  echo "ERROR: $EDGE is not reachable (Host: $HOST). Is the stack up?" >&2
  echo "  local lab:  docker compose up -d   (then re-run)" >&2
  exit 1
fi
echo "preflight: edge reachable (GET $PROBE_PATH -> HTTP $probe)"

# Warm-up so the first step isn't cold-start-skewed.
i=0
while [ "$i" -lt 20 ]; do
  curl -sS -o /dev/null --max-time 5 -H "Host: $HOST" "$EDGE/" || true
  i=$((i + 1))
done
echo "warm-up: 20 priming requests sent"
echo

ENV_ARGS="-e EDGE=$EDGE -e HOST=$HOST -e PATH_MODE=$PATH_MODE -e STEPS=$STEPS \
  -e STEP_DURATION=$STEP_DURATION -e STEP_GAP=${STEP_GAP:-5s} -e MAX_VUS=${MAX_VUS:-2000} \
  -e PATH_PUBLIC=${PATH_PUBLIC:-/public} -e PATH_ENRICHED=${PATH_ENRICHED:-/} \
  -e PATH_PROTECTED=${PATH_PROTECTED:-/protected} \
  -e SLO_P95_MS=${SLO_P95_MS:-150} -e SLO_P99_MS=${SLO_P99_MS:-300} \
  -e SLO_ERROR_RATE=${SLO_ERROR_RATE:-0.001} -e SUMMARY_OUT=${SUMMARY_OUT:-ramp-summary.json}"

# k6 on PATH is preferred; fall back to the official container (K6_DOCKER=1).
if command -v k6 >/dev/null 2>&1; then
  # shellcheck disable=SC2086
  exec k6 run $ENV_ARGS "$SCRIPT"
elif [ "${K6_DOCKER:-0}" = "1" ] || command -v docker >/dev/null 2>&1; then
  echo "k6 not on PATH -> running via grafana/k6 container"
  # host.docker.internal lets the container reach an edge published on the host.
  # If EDGE points at localhost, rewrite it for the container's network view.
  DOCKER_EDGE="$(printf '%s' "$EDGE" | sed 's#//localhost#//host.docker.internal#; s#//127.0.0.1#//host.docker.internal#')"
  DENV="$(printf '%s' "$ENV_ARGS" | sed "s#$EDGE#$DOCKER_EDGE#")"
  # shellcheck disable=SC2086
  exec docker run --rm -i --add-host host.docker.internal:host-gateway \
    -v "$HERE:/scripts" -w /scripts \
    grafana/k6 run $DENV "/scripts/$(basename "$SCRIPT")"
else
  echo "ERROR: neither k6 nor docker found. Install k6: https://k6.io/docs/get-started/installation/" >&2
  exit 127
fi
