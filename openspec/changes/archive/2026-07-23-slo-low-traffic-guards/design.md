## Context

Two distinct rule families carry the SLO alerts, authored in different places:

1. **Hand-authored threshold alerts** — in three Helm helpers, thresholds sourced from `.Values.monitoring.thresholds`:
   - `deploy/helm/edge-platform/templates/_monitoring.tpl` — `edge-platform.edgeSloGroups` (L13), group `nexus-edge.slo`.
   - `deploy/helm/identity-plane/templates/_monitoring.tpl` — `identity-plane.appSloGroups` (L13), group `nexus-identity.slo` **plus a duplicated `nexus-edge.slo`**.
   - `deploy/helm/routing-plane/templates/_monitoring.tpl` — `routing-plane.appSloGroups` (L13), group `nexus-routing.slo` **plus a duplicated `nexus-edge.slo`**.
   The two edge alerts are emitted in **all three** helpers behind `{{- if .Values.edge.enabled }}`.
2. **Sloth-generated burn-rate alerts** — from `monitoring/slo/{identity-sidecar,tenant-router}.slo.yaml`, compiled by `./monitoring/slo/generate.sh` (Sloth v0.16.0, Docker) into `monitoring/prometheus/rules/*.rules.yaml`, staged into `deploy/helm/*/files/slo/`. Generated files are not hand-edited.

Current state: **no alert in the repo carries a traffic floor.** The `> 0.2 req/s` guard that exists on `NexusRoutingLatencyHigh` lives only in the *infra vendored copy* — a local patch that `generate.sh`/re-vendor would revert. This change brings the guard upstream and reconciles that drift.

Exact denominator series (already emitted; no telemetry change):

| Alert | Kind | Floor series |
|---|---|---|
| `NexusEdge5xxHigh` | ratio | `sum(rate(envoy_http_downstream_rq_xx{envoy_http_conn_manager_prefix="edge"}[5m]))` (the in-expr denominator) |
| `NexusEdgeLatencyHigh` | quantile | `envoy_http_downstream_rq_time_count{envoy_http_conn_manager_prefix="edge"}` |
| `NexusIdentityEnrichLatencyHigh` | quantile | `sidecar_ext_proc_duration_seconds_count` |
| `NexusRoutingLatencyHigh` | quantile | `router_ext_proc_duration_seconds_count` |

## Goals / Non-Goals

**Goals:**
- Every ratio/rate-quantile threshold alert has a single-sourced, tunable minimum-sample floor, authored here so it survives regeneration and downstream vendoring.
- Reconcile the `NexusRoutingLatencyHigh` drift so infra can drop its local patch and re-vendor cleanly.
- Keep the rendered edge alert identical across all three helpers.

**Non-Goals:**
- Not changing any objective, budget, threshold value, or metric/telemetry shape.
- Not necessarily flooring the Sloth burn-rate alerts — that is a decision (see D3), because MWMB logic already dampens single-sample spikes.
- Not restructuring the monitoring delivery mechanism (`operator` vs `files`) or de-duplicating the edge alerts beyond what's needed for a consistent floor.

## Decisions

### D1 — Floor expression: append an `and` guard on the denominator rate

Mirror the (downstream-proven) pattern: append to each expr

```
  and
sum(rate(<count-series>[5m])) > {{ $t.<objective>MinRps }}
```

For `NexusEdge5xxHigh` the denominator is already in the expr, so the guard reuses that same `sum(rate(envoy_http_downstream_rq_xx{...edge}[5m]))`. Window matches the rule's existing `[5m]`.

**Alternative considered:** a recording rule for "is this service above floor" reused across alerts — rejected as over-engineered for four rules; the inline `and` is legible and local.

### D2 — Floor value: one `*MinRps` knob per objective under `monitoring.thresholds`

Add to each subchart's `values.yaml` (`monitoring.thresholds`, ~L305/352/444):
- `edgeMinRps` (shared by both edge alerts — same edge traffic denominator class)
- `enrichMinRps` (identity)
- `routingMinRps` (routing)

Default **0.2** (≈60 requests / 5m) — the value the downstream patch settled on. Single-sourced per objective; the helper reads `{{ $t.<x>MinRps }}` exactly like the existing threshold knobs, so there is no magic literal in the template. Because the edge alerts are duplicated across three helpers, all three must read the **same** `edgeMinRps` key (identical default in all three `values.yaml`) so the rendered rule is identical regardless of source — the spec's "duplicated alerts carry an identical floor" scenario.

**Alternative considered:** deduplicate the edge alerts into one shared helper so there is a single source. Cleaner long-term, but a larger refactor with its own review surface; kept as an optional follow-up (task 5), not a prerequisite for the floor.

### D3 — Burn-rate SLI floor → /opsx:decide

The Sloth burn-rate alerts (availability + latency, identity + routing) are error/total ratios over MWMB windows. On truly idle traffic `rate=0/0` yields no sample and does not fire; the fast-burn path already requires **both** a short (5m) and long (1h) window to breach simultaneously, which dampens single-sample spikes. So the exposure is materially lower than the instantaneous threshold alerts.

Options:
- **(a) No explicit floor** — rely on inherent MWMB dampening; document the reasoning. Zero added fragility.
- **(b) Floor via the SLI queries** — adding a floor to `total_query`/`error_query` does not actually gate firing (both scale with traffic; the ratio stays noisy at low N), so this does not solve it. Rejected as ineffective.
- **(c) Wrap the generated alert with an `and <total-rate> > floor`** — effective, but Sloth owns the generated expr; a post-generate wrap fights the tool and must be re-applied every regeneration. High maintenance.

**Recommendation: (a)** unless the burn-rate alerts are observed firing on idle traffic. `/opsx:decide` records this; if (c) is later required, it becomes its own change so the post-generate step is designed deliberately, not bolted on.

**DECIDED (2026-07-23): (a) — no explicit burn-rate floor.** The MWMB short-AND-long-window logic already dampens single-sample spikes, and on truly idle traffic `rate=0/0` yields no sample so the alert cannot fire; there is no observed instance of a burn-rate alert firing on idle traffic. (b) is ineffective and (c) fights the generator and must be re-applied every regeneration. Consequence: **no Sloth regeneration is needed for this change** (task 4 is skipped, and the SLO specs are untouched). If a burn-rate alert is later observed firing on idle traffic, (c) becomes its own change so the post-generate wrap is designed deliberately.

**`*MinRps` default (task 1.2): 0.2 rps (≈60 req/5m) for every objective, no per-plane override.** 0.2 rps is the value the downstream routing patch settled on; it is low enough that any real production edge/identity/routing traffic clears it immediately and the floor only bites in the pre-traffic idle window. Uniform across planes keeps the three `edgeMinRps` copies identical (required by D2) and avoids a magic per-plane split with no evidence behind it. Tunable per objective later if a plane's steady-state floor is shown to differ.

### D4 — Delivery paths stay as-is

The floor is inside the helper-rendered expr, so it flows through **both** the `operator` (`prometheusrule.yaml`) and `files` (`monitoring-rules-files.yaml`) delivery forms automatically — no change to the delivery switch.

## Risks / Trade-offs

- **[Edge alert edited in one helper but not the others]** → the rendered rule silently differs by source. Mitigation: task checklist edits all three; validation step diff-compares the rendered `nexus-edge.slo` group across the three charts and asserts byte-equality.
- **[Floor set too high hides a real early failure]** → 0.2 rps ≈ 60 req/5m is low enough that any real production edge clears it immediately; the floor only bites in the pre-traffic idle window. Tunable per objective if a service's normal floor differs.
- **[Downstream forgets to reconcile]** → the infra `alert-noise-retune` change owns dropping its local routing patch and re-vendoring; called out explicitly there and in task 6.
- **[generate.sh unavailable (no Docker)]** → only matters if D3 picks (c) and the SLO specs change. With the recommended (a), no regeneration is needed for this change at all.

## Migration Plan

1. `/opsx:decide` on D3 (burn-rate floor: recommend (a)); record here.
2. Add `*MinRps` defaults to the three `values.yaml`; add the `and`-guard to each alert in all three `_monitoring.tpl` helpers (including every duplicated edge copy).
3. `helm template` each subchart; assert the guarded exprs render and the `nexus-edge.slo` group is identical across the three.
4. If D3 = (c) only: edit SLO specs, run `generate.sh`, commit regenerated rules.
5. Merge upstream. **Rollback:** revert the helper/values commit — pure chart change, no state.
6. Signal infra to drop its local `NexusRoutingLatencyHigh` patch and re-vendor (`files/nexus-rules/*.yml`).

## Open Questions

- Is 0.2 rps the right default for the identity/edge denominators, or only validated for routing? (Confirm against expected steady-state rates per plane.)
- Should the edge-alert duplication be resolved now (D2 alternative) or deferred? Deferring is fine for this change but leaves three copies to keep in sync.
