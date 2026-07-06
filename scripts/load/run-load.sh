#!/usr/bin/env sh
# Load / capacity harness for the nexus edge.
#
# The CI e2e gate proves CORRECTNESS (does the edge enforce the contract). It does
# NOT prove CAPACITY (how much traffic the edge sustains and at what tail latency).
# This harness fills that gap: it drives a fixed OFFERED load through the real
# Envoy filter chain (tenant-router + identity sidecar ext_proc) and reports
# throughput + p95/p99, gating against operator-set SLOs.
#
# Prereqs:
#   1. The reference stack (or your target) is up and reachable at $EDGE.
#      For the local lab:  docker compose up -d   (edge on :10000)
#   2. k6 is installed (https://k6.io/docs/get-started/installation/). We adopt k6
#      rather than hand-roll a loop so the percentiles + open-model arrival rate
#      (no coordinated omission) and the pass/fail exit code are trustworthy.
#
# Usage:
#   scripts/load/run-load.sh                       # defaults (local lab)
#   RATE=500 DURATION=120s SLO_P99_MS=250 scripts/load/run-load.sh
#   EDGE=https://edge.example.com HOST=acme.example.com \
#     SLO_P95_MS=120 SLO_P99_MS=250 SLO_ERROR_RATE=0.001 \
#     scripts/load/run-load.sh
#
# Exit code is k6's: 0 = every SLO threshold held, non-zero = a threshold was
# crossed (so this is CI-gateable once you have real SLO numbers).
set -u

EDGE="${EDGE:-http://localhost:10000}"
HOST="${HOST:-localhost}"
RATE="${RATE:-200}"
DURATION="${DURATION:-60s}"
HERE="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
SCRIPT="$HERE/edge-load.js"

echo "== nexus edge load/capacity harness =="
echo "   target : $EDGE   (Host: $HOST)"
echo "   offered: $RATE req/s per scenario for $DURATION"
echo "   SLOs   : p95<${SLO_P95_MS:-150}ms  p99<${SLO_P99_MS:-300}ms  err<${SLO_ERROR_RATE:-0.001}"
echo

# --- Preflight: k6 present -----------------------------------------------------
if ! command -v k6 >/dev/null 2>&1; then
  echo "ERROR: k6 not found on PATH." >&2
  echo "Install it: https://k6.io/docs/get-started/installation/" >&2
  echo "  macOS:  brew install k6" >&2
  echo "  Debian: sudo gpg -k && ... apt-get install k6   (see docs)" >&2
  echo "  Docker: run 'grafana/k6 run - <$SCRIPT' (mount + --network host)" >&2
  exit 127
fi

# --- Preflight: target reachable ----------------------------------------------
# A capacity run against a down stack just measures connection-refused. Fail fast
# with a clear message instead.
probe="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 5 \
  -H "Host: $HOST" "$EDGE/public" 2>/dev/null || echo "000")"
if [ "$probe" = "000" ]; then
  echo "ERROR: $EDGE is not reachable (Host: $HOST). Is the stack up?" >&2
  echo "  local lab:  docker compose up -d   (then re-run)" >&2
  exit 1
fi
echo "preflight: edge reachable (GET /public -> HTTP $probe)"
echo

# --- Warm-up: prime pools/caches so the measured window is steady-state --------
i=0
while [ "$i" -lt 20 ]; do
  curl -sS -o /dev/null --max-time 5 -H "Host: $HOST" "$EDGE/" || true
  i=$((i + 1))
done
echo "warm-up: 20 priming requests sent"
echo

# --- Run -----------------------------------------------------------------------
# All tuning is passed through as env (edge-load.js reads __ENV.*). Summary is
# written to a JSON file too, for trend-tracking across runs.
SUMMARY="${SUMMARY_OUT:-load-summary.json}"
exec k6 run \
  --summary-export "$SUMMARY" \
  -e EDGE="$EDGE" \
  -e HOST="$HOST" \
  -e RATE="$RATE" \
  -e DURATION="$DURATION" \
  -e PREALLOC_VUS="${PREALLOC_VUS:-50}" \
  -e MAX_VUS="${MAX_VUS:-500}" \
  -e PATH_PUBLIC="${PATH_PUBLIC:-/public}" \
  -e PATH_ENRICHED="${PATH_ENRICHED:-/}" \
  -e PATH_PROTECTED="${PATH_PROTECTED:-}" \
  -e SLO_P95_MS="${SLO_P95_MS:-150}" \
  -e SLO_P99_MS="${SLO_P99_MS:-300}" \
  -e SLO_ERROR_RATE="${SLO_ERROR_RATE:-0.001}" \
  "$SCRIPT"
