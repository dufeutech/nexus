## Why

nexus emits a RED metrics baseline but cannot answer its most basic reliability
question — *"is a service meeting its objective, and how fast is it burning its error
budget?"* The hot-path latency histograms fuse success and error latency into one
distribution, so the canonical availability SLO ("99.9% of non-error requests under
X ms") is un-expressible; the alert scaffold is single-window thresholds with no error
budget; and the per-environment identity an SLO must be scoped by is an optional
operator convenience, not a guaranteed invariant. This is the always-ship safety net:
it is the instrument that later trust-hardening and multi-region work are verified
against, it is half-built, and it has a real defect worth fixing now.

## What Changes

- Fix the outcome-blind latency defect: the hot-path request-duration histograms carry
  the request **outcome** as a low-cardinality dimension, so latency is sliceable by
  success vs. error. Availability and latency SLOs become expressible against
  non-error traffic. (Confirmed to stay within the existing collector cardinality
  allow-list — no cost-control change.)
- Make **deployment environment** a required, verified telemetry invariant for
  first-party services rather than an optional operator-supplied attribute, so
  per-environment SLOs are well-defined and a service cannot ship telemetry that an
  SLO layer cannot scope.
- Introduce a **service SLO policy** as first-class behavior: each in-scope service has
  a stated objective and an error budget, and alerting fires on the **rate of budget
  burn across multiple time windows** (fast-burn for pages, slow-burn for tickets)
  rather than on instantaneous threshold breaches — with the objectives and burn
  policy expressed as data, and exercisable on a clean local checkout.
- Out of scope (parked, per exploration): trust-boundary hardening (B) and
  multi-region/HA (D). The recorded multi-region driver is failure-survival → CNPG,
  but no B/D behavior is proposed here. This change is deliberately shippable
  independent of that fork.

## Capabilities

### New Capabilities
- `service-slo-policy`: nexus services carry stated service-level objectives and error
  budgets; alerting is driven by multi-window error-budget burn rate, not single-window
  thresholds; objectives and burn policy live as operator-owned data and are
  exercisable locally. The correctness of the burn-rate/error-budget evaluation is a
  reliability-critical concern subject to a build-vs-adopt decision (deferred to
  `/opsx:decide`).

### Modified Capabilities
- `first-party-telemetry`: the RED request-duration signal SHALL be outcome-aware
  (sliceable by success vs. error), and deployment-environment resource identity SHALL
  be a required, verified invariant on every first-party signal rather than an optional
  operator convenience — the two behaviors an SLO layer depends on.

## Impact

- **Emitters**: the two hot-path ext_proc duration histograms
  (`router_ext_proc_duration_seconds`, `sidecar_ext_proc_duration_seconds`) gain an
  outcome attribute at record time.
- **Deploy invariant**: first-party deployment must guarantee a valid deployment
  environment attribute is present before telemetry is accepted (fail-closed on
  absence), replacing today's best-effort `OTEL_RESOURCE_ATTRIBUTES` convention.
- **Alerting/SLO layer**: recording rules + multi-window burn-rate alerts on the
  existing default-off alert-rule scaffold; the lab metrics stack gains rule loading so
  the same policy runs on a clean checkout.
- **No change** to the collector cardinality allow-list, to request handling or
  resolution (telemetry stays fail-open and non-blocking), or to any B/D concern.
- **Critical concern for `/opsx:decide`**: the burn-rate/error-budget evaluation
  engine — adopt the mature Prometheus recording-rule + multi-window-burn-rate pattern
  vs. build bespoke. Deferred to the decide gate; no tool picked here.
