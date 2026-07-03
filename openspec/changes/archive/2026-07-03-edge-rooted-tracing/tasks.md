# Tasks: edge-rooted-tracing

## 1. Phase 0 — trace-context integrity (standalone-safe, can ship alone)

- [x] 1.1 Add `traceparent` and `tracestate` to the C3 header_mutation strip list in
      `deploy/compose/envoy/envoy.yaml`
- [x] 1.2 Add the same strip entries to the helm edge configmaps (`edge-platform`,
      `identity-plane`, `routing-plane`) and the reference `edge/envoy.yaml`
- [x] 1.3 Verify: a request sent with a forged `traceparent` reaches the backend pool
      with the header absent (compose smoke test)

## 2. Collection layer + trace store (compose topology)

- [x] 2.1 Add an OTel Collector service to the compose monitoring stack — OTLP/gRPC
      receiver, exporter → Tempo; config in its own native-format file
      (`otel-collector.yaml`), endpoint/ports via compose env, not literals
- [x] 2.2 Add a Tempo service — local-disk storage, short default retention; config in
      its own `tempo.yaml`
- [x] 2.3 Add Tempo as a Grafana datasource (provisioned datasource file, not manual)
- [x] 2.4 Verify: OTLP test span sent to the collector is queryable by trace ID in
      Grafana

## 3. Edge tracing (compose topology)

- [x] 3.1 Add the OpenTelemetry tracing stanza to the compose Envoy config: OTel
      tracer → collector cluster (OTLP/gRPC), head sampling rate externalized as an
      env-driven value, spans limited to the allowed attribute set (no header values,
      no `x-user-*`, no bodies — parity with the access-log hygiene rule)
- [x] 3.2 Pin/confirm the Envoy image version supporting the OTel tracer; note it in
      the compose file comment
- [x] 3.3 Verify end-to-end: a sampled request produces one trace with edge span,
      tenant-router ext_proc span, identity ext_proc span, and upstream span; an
      unsampled request propagates a not-sampled `traceparent` to the box
- [x] 3.4 Verify fail-open: stop the collector; requests route/authenticate normally
- [x] 3.5 Verify hygiene: inspect a sampled authenticated request's spans — no
      credential, `x-user-*`, or body content in any attribute

## 4. Helm parity

- [x] 4.1 Add collector + Tempo to the helm monitoring topology (or chart values
      documenting the external endpoints, matching how Prometheus is deployed)
- [x] 4.2 Add the tracing stanza to the helm edge configmap(s), sampling rate and
      collector endpoint via `values.yaml`
- [x] 4.3 Parity check: diff compose vs helm tracing behavior (span structure,
      strip list, hygiene) — same guarantees in both topologies

## 5. Docs + contract close-out

- [x] 5.1 Update `nexus-upstream-requirements.md`: N6 row → shipped (with change name
      + date), header-contract table `traceparent` row → shipped
- [x] 5.2 Update `deploy/README.md`: collector/Tempo bring-up, sampling-rate knob,
      note that box bring-up order remains flexible
- [x] 5.3 Record the phase 2–4 roadmap pointer where monitoring docs live (one line,
      pointing at this change's design.md)
