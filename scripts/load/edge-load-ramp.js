// Edge CAPACITY-CURVE profile for the nexus edge (k6).
//
// edge-load.js answers "does the edge hold SLO at ONE offered rate?". This script
// answers the capacity question the operator checklist actually needs: "at what
// offered rate does the tail break?" — i.e. it finds the KNEE of the latency curve.
//
// HOW: instead of one constant-arrival-rate window, it runs a SEQUENCE of
// constant-arrival-rate steps at increasing offered rates (STEPS), each for
// STEP_DURATION, back to back. Every request is tagged with its step, so the
// per-step p95/p99/error-rate fall out as sub-metrics and handleSummary() prints
// a capacity table + the first step that violates the SLO (the knee).
//
// WHY still k6 / still open-model (build-vs-adopt): same reasoning as edge-load.js
// — the arrival-rate executor issues requests on a schedule regardless of how slow
// the edge gets, so a stall shows as latency, not as vanished load (no coordinated
// omission). We only add the stepping on top; the measurement core stays adopted.
//
// This ramps ONE cost path at a time (default: the enriched hot path — the binding
// constraint, since it runs both ext_proc round-trips + store/cache reads). Pick
// the path with PATH_MODE=public|enriched|protected. Ramping paths independently
// keeps each curve clean; a mixed run hides which path knees first.

import http from 'k6/http';
import exec from 'k6/execution';
import { check } from 'k6';
import { Rate } from 'k6/metrics';

const EDGE = __ENV.EDGE || 'http://localhost:10000';
const HOST = __ENV.HOST || 'localhost';

// The offered-rate ladder (req/s), ascending. Override for your infra's range.
const STEPS = (__ENV.STEPS || '100,250,500,1000,2000,4000')
  .split(',')
  .map((s) => parseInt(s.trim(), 10))
  .filter((n) => Number.isFinite(n) && n > 0);
const STEP_DURATION = __ENV.STEP_DURATION || '30s';
const STEP_GAP = __ENV.STEP_GAP || '5s'; // cooldown between steps (drain in-flight)
const MAX_VUS = parseInt(__ENV.MAX_VUS || '2000', 10);

// Which single cost path to ramp.
const PATH_MODE = (__ENV.PATH_MODE || 'enriched').toLowerCase();
const PATHS = {
  public: { path: __ENV.PATH_PUBLIC || '/public', status: 200 },
  enriched: { path: __ENV.PATH_ENRICHED || '/', status: 200 },
  protected: { path: __ENV.PATH_PROTECTED || '/protected', status: 401 },
};
const TARGET = PATHS[PATH_MODE];
if (!TARGET) throw new Error(`PATH_MODE must be one of ${Object.keys(PATHS).join('|')}`);

// SLOs the knee is measured against (operator-owned; defaults are PLACEHOLDERS).
const SLO_P95_MS = parseFloat(__ENV.SLO_P95_MS || '150');
const SLO_P99_MS = parseFloat(__ENV.SLO_P99_MS || '300');
const SLO_ERROR_RATE = parseFloat(__ENV.SLO_ERROR_RATE || '0.001');

const errors = new Rate('edge_errors');

// Parse "30s"/"500ms"/"2m" -> seconds (for throughput math in the summary).
function toSeconds(d) {
  const m = /^([\d.]+)(ms|s|m|h)$/.exec(String(d).trim());
  if (!m) return NaN;
  const v = parseFloat(m[1]);
  return { ms: v / 1000, s: v, m: v * 60, h: v * 3600 }[m[2]];
}
const STEP_SECS = toSeconds(STEP_DURATION);
const GAP_SECS = toSeconds(STEP_GAP) || 0;

// Build one constant-arrival-rate scenario per step, chained via startTime so they
// run strictly one after another (a step's load must not bleed into the next).
const scenarios = {};
const perStepThresholds = {};
let offset = 0;
for (const rate of STEPS) {
  const name = `step_${rate}`;
  scenarios[name] = {
    executor: 'constant-arrival-rate',
    rate,
    timeUnit: '1s',
    duration: STEP_DURATION,
    // Give each step enough VUs to actually offer `rate` even if the edge is slow;
    // capped by MAX_VUS. preAlloc scales with the step so we don't stall at ramp.
    preAllocatedVUs: Math.min(MAX_VUS, Math.max(50, Math.ceil(rate * 0.2))),
    maxVUs: MAX_VUS,
    startTime: `${offset}s`,
    exec: 'ramp',
    tags: { step: name },
    env: { STEP_RATE: String(rate) },
  };
  // Defining per-step thresholds forces k6 to emit per-step sub-metrics in the
  // summary. `abortOnFail:false` — we WANT every step to run so the whole curve is
  // measured; the knee is computed in handleSummary, not by aborting early.
  perStepThresholds[`http_req_duration{step:${name}}`] = [
    { threshold: `p(99)<${SLO_P99_MS}`, abortOnFail: false },
  ];
  perStepThresholds[`edge_errors{step:${name}}`] = [
    { threshold: `rate<${SLO_ERROR_RATE}`, abortOnFail: false },
  ];
  offset += STEP_SECS + GAP_SECS;
}

export const options = {
  scenarios,
  thresholds: perStepThresholds,
  discardResponseBodies: true,
  // k6's default trend summary omits p(99) and count — we need both (p99 to judge
  // the SLO, count to derive achieved throughput per step), so request them here.
  summaryTrendStats: ['avg', 'min', 'med', 'max', 'p(90)', 'p(95)', 'p(99)', 'count'],
};

const params = { headers: { Host: HOST } };

export function ramp() {
  const step = exec.scenario.name; // e.g. "step_500"
  const res = http.get(`${EDGE}${TARGET.path}`, {
    ...params,
    tags: { step },
  });
  const ok = res.status === TARGET.status;
  errors.add(!ok, { step });
  check(res, { [`status ${TARGET.status}`]: () => ok });
}

// ---- Capacity table + knee detection -----------------------------------------
function pct(metric, p) {
  if (!metric || !metric.values) return NaN;
  return metric.values[`p(${p})`];
}
function fmt(n, unit = '') {
  return Number.isFinite(n) ? `${n.toFixed(1)}${unit}` : '   -  ';
}

export function handleSummary(data) {
  const rows = [];
  let knee = null;
  for (const rate of STEPS) {
    const dm = data.metrics[`http_req_duration{step:step_${rate}}`];
    const em = data.metrics[`edge_errors{step:step_${rate}}`];
    const count = dm && dm.values ? dm.values.count : 0;
    const achieved = STEP_SECS > 0 ? count / STEP_SECS : NaN; // actual RPS served
    const p95 = pct(dm, 95);
    const p99 = pct(dm, 99);
    const errRate = em && em.values ? em.values.rate : NaN;
    const pass =
      p95 < SLO_P95_MS && p99 < SLO_P99_MS && !(errRate >= SLO_ERROR_RATE);
    if (!pass && knee === null) knee = rate;
    rows.push({ rate, achieved, p95, p99, errRate, pass });
  }

  const bar = '─'.repeat(72);
  let out = `\n${bar}\n`;
  out += `nexus edge capacity curve — path=${PATH_MODE} (${TARGET.path})  host=${HOST}\n`;
  out += `SLO gate: p95<${SLO_P95_MS}ms  p99<${SLO_P99_MS}ms  err<${SLO_ERROR_RATE}\n`;
  out += `${bar}\n`;
  out += ` offered  achieved     p95      p99    err%   verdict\n`;
  out += ` (rps)    (rps)       (ms)     (ms)\n`;
  out += `${'-'.repeat(72)}\n`;
  for (const r of rows) {
    out +=
      ` ${String(r.rate).padStart(6)}  ${fmt(r.achieved).padStart(8)}  ` +
      `${fmt(r.p95).padStart(7)}  ${fmt(r.p99).padStart(7)}  ` +
      `${fmt(r.errRate * 100).padStart(5)}   ${r.pass ? 'ok' : 'BREACH'}\n`;
  }
  out += `${bar}\n`;
  if (knee === null) {
    const top = STEPS[STEPS.length - 1];
    out += `KNEE: not reached — edge held SLO through the top step (${top} rps).\n`;
    out += `      Raise STEPS to find the real ceiling.\n`;
  } else {
    const idx = STEPS.indexOf(knee);
    const lastOk = idx > 0 ? STEPS[idx - 1] : null;
    out += `KNEE: SLO first breached at ${knee} rps offered.\n`;
    out += lastOk
      ? `      Highest SLO-compliant step measured: ${lastOk} rps.\n`
      : `      Even the lowest step (${knee} rps) breached — lower STEPS or fix the edge.\n`;
  }
  out += `${bar}\n`;
  out += `NOTE: offered!=achieved means the generator or edge could not sustain the\n`;
  out += `rate — treat that step's latency as generator-bound, not edge capacity.\n`;
  out += `Run the generator OFF-BOX for numbers you can trust.\n${bar}\n`;

  const summaryOut = __ENV.SUMMARY_OUT || 'ramp-summary.json';
  return {
    stdout: out,
    [summaryOut]: JSON.stringify(
      { path: PATH_MODE, slo: { SLO_P95_MS, SLO_P99_MS, SLO_ERROR_RATE }, knee, rows },
      null,
      2,
    ),
  };
}
