{{/*
Hand-authored SLO alert rule GROUPS for the COMBINED edge (Envoy — the tenant-first
data plane this umbrella owns), as a portable Prometheus/PromQL rules body. Single
source: both the operator-form PrometheusRule (templates/prometheusrule.yaml) and the
operator-independent files-form ConfigMap (templates/monitoring-rules-files.yaml) render
THIS, so the two delivery forms carry byte-identical rule content. nexus AUTHORS these;
the engine EVALUATES them.

Envoy admin stats are SCRAPED, so these rules are collector-independent. The per-plane
Rust-service rules (identity + routing) are shipped by the subcharts — enable them with
identity-plane.monitoring.delivery / routing-plane.monitoring.delivery.
*/}}
{{- define "edge-platform.edgeSloGroups" -}}
{{- $t := .Values.monitoring.thresholds -}}
groups:
  - name: nexus-edge.slo
    rules:
      - alert: NexusEdge5xxHigh
        expr: |
          sum(rate(envoy_http_downstream_rq_xx{envoy_response_code_class="5",envoy_http_conn_manager_prefix="edge"}[5m]))
            / sum(rate(envoy_http_downstream_rq_xx{envoy_http_conn_manager_prefix="edge"}[5m]))
            > {{ $t.edge5xxRatio }}
        for: 5m
        labels: { severity: critical, plane: edge }
        annotations:
          summary: "Edge 5xx ratio high"
          description: >-
            More than {{ $t.edge5xxRatio }} of combined-edge responses were 5xx over
            5m — the edge or a backend pool is failing. Envoy admin stats (scraped).
      - alert: NexusEdgeLatencyHigh
        expr: histogram_quantile(0.99, sum by (le) (rate(envoy_http_downstream_rq_time_bucket{envoy_http_conn_manager_prefix="edge"}[5m]))) > {{ $t.edgeP99Milliseconds }}
        for: 10m
        labels: { severity: warning, plane: edge }
        annotations:
          summary: "Edge request p99 latency high"
          description: >-
            Combined-edge downstream request p99 has been above
            {{ $t.edgeP99Milliseconds }}ms for 10m (Envoy `downstream_rq_time` is ms).
{{- end -}}
