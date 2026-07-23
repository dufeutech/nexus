{{/*
Hand-authored application-SLO alert rule GROUPS (first-party-telemetry), as a
portable Prometheus/PromQL rules body. Single source: both the operator-form
PrometheusRule (templates/prometheusrule.yaml) and the operator-independent
files-form ConfigMap (templates/monitoring-rules-files.yaml) render THIS, so the two
delivery forms carry byte-identical rule content. nexus AUTHORS these (they need
domain knowledge of which metrics exist); the engine EVALUATES them.

The `result`/`op` rules select a metric ATTRIBUTE the OTel collector must KEEP
(nexus's lab collector keeps result/op/tier); a stripping collector under-fires them.
The edge rules use Envoy's scraped admin stats, so they are collector-independent.
*/}}
{{- define "routing-plane.appSloGroups" -}}
{{- $t := .Values.monitoring.thresholds -}}
groups:
  - name: nexus-routing.slo
    rules:
      - alert: NexusRoutingNotReady
        expr: router_ready == 0
        for: 10m
        labels: { severity: critical, plane: routing }
        annotations:
          summary: "Tenant-router not ready"
          description: >-
            The tenant-router has reported not-ready (warming, or its routing store is
            unreachable) for 10m. Host→workspace resolution fails closed while it is
            down, so requests cannot be routed.
      - alert: NexusRoutingLatencyHigh
        expr: histogram_quantile(0.99, sum by (le) (rate(router_ext_proc_duration_seconds_bucket[5m]))) > {{ $t.routingP99Seconds }} and sum(rate(router_ext_proc_duration_seconds_count[5m])) > {{ $t.routingMinRps }}
        for: 10m
        labels: { severity: warning, plane: routing }
        annotations:
          summary: "Routing decision p99 latency high"
          description: >-
            Tenant-router ext_proc p99 has been above {{ $t.routingP99Seconds }}s for
            10m — the routing decision (a cache lookup, or a store read on a miss) is
            slow and sits in front of every request.
      - alert: NexusRoutingRejectSpike
        expr: sum(rate(router_ext_proc_requests_total{result="reject"}[5m])) > {{ $t.rejectPerSecond }}
        for: 10m
        labels: { severity: warning, plane: routing }
        annotations:
          summary: "Routing unknown-host reject spike"
          description: >-
            The edge is rejecting requests for unknown/unverified hosts (404, C18)
            above {{ $t.rejectPerSecond }}/s for 10m — a missing/unverified domain
            registration or host-probing. Needs the `result` attribute kept by your
            collector.
      - alert: NexusControlPlaneUnauthorizedSpike
        expr: sum(rate(control_mutations_total{op="unauthorized"}[5m])) > {{ $t.unauthorizedPerSecond }}
        for: 10m
        labels: { severity: warning, plane: routing }
        annotations:
          summary: "Control-plane unauthorized (401) spike"
          description: >-
            The routing control plane is rejecting admin requests (401) above
            {{ $t.unauthorizedPerSecond }}/s for 10m — a bad/rotated CONTROL_AUTH_TOKEN
            or unauthorized attempts against the routing store. Needs the `op`
            attribute kept by your collector.
{{- if .Values.edge.enabled }}
  - name: nexus-edge.slo
    rules:
      - alert: NexusEdge5xxHigh
        expr: |
          sum(rate(envoy_http_downstream_rq_xx{envoy_response_code_class="5",envoy_http_conn_manager_prefix="edge"}[5m]))
            / sum(rate(envoy_http_downstream_rq_xx{envoy_http_conn_manager_prefix="edge"}[5m]))
            > {{ $t.edge5xxRatio }}
            and sum(rate(envoy_http_downstream_rq_xx{envoy_http_conn_manager_prefix="edge"}[5m])) > {{ $t.edgeMinRps }}
        for: 5m
        labels: { severity: critical, plane: edge }
        annotations:
          summary: "Edge 5xx ratio high"
          description: >-
            More than {{ $t.edge5xxRatio }} of edge responses were 5xx over 5m — the
            edge or a backend pool is failing. Envoy admin stats (scraped).
      - alert: NexusEdgeLatencyHigh
        expr: histogram_quantile(0.99, sum by (le) (rate(envoy_http_downstream_rq_time_bucket{envoy_http_conn_manager_prefix="edge"}[5m]))) > {{ $t.edgeP99Milliseconds }} and sum(rate(envoy_http_downstream_rq_time_count{envoy_http_conn_manager_prefix="edge"}[5m])) > {{ $t.edgeMinRps }}
        for: 10m
        labels: { severity: warning, plane: edge }
        annotations:
          summary: "Edge request p99 latency high"
          description: >-
            Edge downstream request p99 has been above {{ $t.edgeP99Milliseconds }}ms
            for 10m (Envoy `downstream_rq_time` is in milliseconds).
{{- end }}
{{- end -}}
