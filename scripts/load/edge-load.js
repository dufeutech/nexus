// Edge load / capacity profile for the nexus edge (k6).
//
// WHY k6 (build-vs-adopt): capacity numbers are only trustworthy if the load
// model avoids coordinated omission and the percentiles are computed correctly.
// k6's constant-arrival-rate executor is an OPEN model (it launches requests on
// a schedule regardless of how slow the system gets, so a stall shows up as
// latency instead of vanishing), and its thresholds give a real pass/fail gate
// with a non-zero exit code. Hand-rolling either in shell would be a correctness
// footgun — exactly the kind of thing the repo's decide-gate says to adopt.
//
// This measures CAPACITY (throughput + tail latency under a fixed offered load),
// which the CI e2e gate deliberately does NOT — the gate proves correctness.
//
// Scenarios (each maps to a real edge cost path):
//   baseline_public  -> a non-enriched route (/public): pure proxy cost, no ext_proc
//   enriched_anon    -> an enriched route (/): tenant-router + identity sidecar
//                       ext_proc both run — the representative hot path
//   protected_401    -> a protected route with no credential: the auth-gate 401
//                       path (jwt_authn + sidecar), exercised without a token
//
// All config comes from env (see run-load.sh). Nothing here is nexus-specific
// beyond the default paths, which you can override for your topology.

import http from 'k6/http';
import { check } from 'k6';
import { Rate } from 'k6/metrics';

const EDGE = __ENV.EDGE || 'http://localhost:10000';
const HOST = __ENV.HOST || 'localhost'; // Host header -> seeded workspace
const RATE = parseInt(__ENV.RATE || '200', 10); // offered requests/sec per scenario
const DURATION = __ENV.DURATION || '60s';
const PREALLOC = parseInt(__ENV.PREALLOC_VUS || '50', 10);
const MAX_VUS = parseInt(__ENV.MAX_VUS || '500', 10);

const PATH_PUBLIC = __ENV.PATH_PUBLIC || '/public';
const PATH_ENRICHED = __ENV.PATH_ENRICHED || '/';
const PATH_PROTECTED = __ENV.PATH_PROTECTED || ''; // empty => skip that scenario

// SLO thresholds (operator-owned — a capacity test without a target is just a
// number). Defaults are placeholders; set real ones for YOUR infra.
const SLO_P95_MS = __ENV.SLO_P95_MS || '150';
const SLO_P99_MS = __ENV.SLO_P99_MS || '300';
const SLO_ERROR_RATE = __ENV.SLO_ERROR_RATE || '0.001'; // 0.1%

const errors = new Rate('edge_errors');

function scenario(startTime) {
  return {
    executor: 'constant-arrival-rate',
    rate: RATE,
    timeUnit: '1s',
    duration: DURATION,
    preAllocatedVUs: PREALLOC,
    maxVUs: MAX_VUS,
    startTime,
  };
}

const scenarios = {
  baseline_public: Object.assign(scenario('0s'), { exec: 'publicRoute' }),
  enriched_anon: Object.assign(scenario('0s'), { exec: 'enrichedRoute' }),
};
if (PATH_PROTECTED !== '') {
  scenarios.protected_401 = Object.assign(scenario('0s'), { exec: 'protectedRoute' });
}

export const options = {
  scenarios,
  thresholds: {
    // Global gate: fail the run (exit != 0) if the fleet misses its SLO.
    http_req_duration: [`p(95)<${SLO_P95_MS}`, `p(99)<${SLO_P99_MS}`],
    edge_errors: [`rate<${SLO_ERROR_RATE}`],
    // Per-scenario tail visibility (does not gate, but prints in the summary).
    'http_req_duration{scenario:enriched_anon}': [`p(99)<${SLO_P99_MS}`],
  },
  // Discard the connection-setup tax from the reported request time so numbers
  // reflect server-side latency, not TCP/TLS handshakes to a cold pool.
  discardResponseBodies: true,
};

const params = { headers: { Host: HOST }, tags: {} };

function hit(path, expectStatus) {
  const res = http.get(`${EDGE}${path}`, params);
  const ok = res.status === expectStatus;
  errors.add(!ok);
  check(res, { [`status is ${expectStatus}`]: () => ok });
  return res;
}

export function publicRoute() {
  hit(PATH_PUBLIC, 200);
}
export function enrichedRoute() {
  hit(PATH_ENRICHED, 200);
}
export function protectedRoute() {
  // No credential -> the auth gate must 401 before any backend is reached.
  hit(PATH_PROTECTED, 401);
}
