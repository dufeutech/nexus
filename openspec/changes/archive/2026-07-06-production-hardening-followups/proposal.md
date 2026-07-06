## Why

A production-readiness review surfaced a handful of gaps that sit *outside* what the CI e2e
gate can certify: the edge ran on a mutable image tag, there was no way to validate capacity
(the gate proves correctness, not throughput/tail-latency), the two edge configs had drifted
in what they strip, and the "what a box must implement" contract plus a front-door README were
missing. These are the last operator-facing items before the Helm path is production-ready;
this change closes them and — per the repo's own discipline — records the build-vs-adopt
decision they entail (a capacity harness is a measurement-correctness-critical concern).

## What Changes

- **New: an operator-runnable edge load/capacity validation** that drives a fixed offered
  load through the real Envoy filter chain and gates throughput + p95/p99 against
  operator-set SLOs (exit-coded, CI-gateable). Fills the capacity gap the correctness gate
  leaves open.
- **Pin the edge image.** The Envoy image is pinned to a concrete patch version + immutable
  digest (`v1.34.14@sha256:…`) across both compose files, both `.env`s, and both Helm
  `values.yaml`; the umbrella inherits via the routing-plane subchart. Re-resolution
  procedure documented in place.
- **Reconcile the two edge configs.** `edge/envoy.yaml` and `deploy/compose/envoy/envoy.yaml`
  now strip an identical trusted-header set (the compose twin was missing the phase-2
  `x-auth-requires-*`/`x-auth-min-aal` removes). Defense-in-depth already covered these at the
  sidecar; this makes the published strip contract literally identical in both edges.
- **Publish the box consumer contract.** A single, complete reference of every injected
  header (format + reject rules + origin-trust prerequisite + telemetry), cross-linked from
  the canonical requirements doc.
- **Add a front-door README** describing the system, planes, deploy paths, and doc index.
- **Operator guidance:** a copy-pasteable CNI-enforcement probe for the origin-trust
  NetworkPolicy, added to the deploy checklist.
- **Verify a latent hardening item:** determine whether the read-only-rootfs containers that
  lack a writable `/tmp` actually write there, and add an `emptyDir` mount only where a binary
  needs it (no blanket change).

## Capabilities

### New Capabilities
- `edge-load-capacity`: the platform provides an operator-runnable capacity validation of the
  edge — a fixed offered load across representative cost paths (non-enriched, enriched,
  auth-gate), reporting throughput and tail latency and passing/failing against explicit SLO
  thresholds. Measurement correctness (open-model load, correct percentiles) is a
  build-vs-adopt concern to settle in `/opsx:decide`.

### Modified Capabilities
<!-- None. The image pin, edge-config strip reconciliation, consumer-contract doc, README,
     and CNI probe are implementation/ops/documentation of EXISTING requirements
     (edge-origin-trust, edge-auth-gate, box-telemetry-contract) — no requirement text
     changes, so no delta specs. -->

## Impact

- **New files:** `scripts/load/` (harness), `docs/box-consumer-contract.md`, `README.md`.
- **Edited:** `docker-compose.yaml`, `deploy/compose/docker-compose.yaml`, `.env`,
  `deploy/compose/.env.example`, `deploy/compose/envoy/envoy.yaml`,
  `deploy/helm/{identity,routing}-plane/values.yaml`, `deploy/README.md`,
  `nexus-upstream-requirements.md`.
- **New tool dependency (operator-side only):** a load generator, adopted rather than built
  (settled in `/opsx:decide`). Not added to any service image; run from an operator host.
- **No product-code behavior change** and **no API/store/schema change.** Envoy edits are
  header-strip config; the rest is images, docs, and ops tooling.
