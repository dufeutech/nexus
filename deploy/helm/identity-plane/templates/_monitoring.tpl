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
{{- define "identity-plane.appSloGroups" -}}
{{- $t := .Values.monitoring.thresholds -}}
groups:
  - name: nexus-identity.slo
    rules:
      - alert: NexusIdentitySidecarNotReady
        expr: sidecar_ready == 0
        for: 10m
        labels: { severity: critical, plane: identity }
        annotations:
          summary: "Identity sidecar not ready"
          description: >-
            The identity sidecar has reported not-ready (still warming, or the
            profile store is unreachable) for 10m. Enriched routes fail closed
            (503) while it is down.
      - alert: NexusIdentityEnrichLatencyHigh
        expr: histogram_quantile(0.99, sum by (le) (rate(sidecar_ext_proc_duration_seconds_bucket[5m]))) > {{ $t.enrichP99Seconds }}
        for: 10m
        labels: { severity: warning, plane: identity }
        annotations:
          summary: "Identity enrichment p99 latency high"
          description: >-
            Sidecar ext_proc p99 has been above {{ $t.enrichP99Seconds }}s for 10m —
            the enrichment hop is slow and adds to every authenticated request.
      - alert: NexusAuthzGateFailClosed
        expr: sum(rate(sidecar_ext_proc_requests_total{result="unavailable_closed"}[5m])) > {{ $t.failClosedPerSecond }}
        for: 5m
        labels: { severity: critical, plane: identity }
        annotations:
          summary: "Authz gate failing closed (store unreadable)"
          description: >-
            The sidecar is refusing authenticated requests with 503 because the
            profile store is unreadable ({{ $t.failClosedPerSecond }}/s for 5m).
            Roles/suspension can't be resolved — check Postgres reachability. Needs
            the `result` metric attribute kept by your collector.
      - alert: NexusAuthzGateForbiddenSpike
        expr: sum(rate(sidecar_ext_proc_requests_total{result="forbidden"}[5m])) > {{ $t.forbiddenPerSecond }}
        for: 10m
        labels: { severity: warning, plane: identity }
        annotations:
          summary: "Authz gate 403 spike"
          description: >-
            The edge is denying requests (403 — role/entitlement/AAL requirement
            unmet) above {{ $t.forbiddenPerSecond }}/s for 10m: a misconfigured route
            requirement, a revoked cohort, or probing. Needs the `result` attribute
            kept by your collector.
      - alert: NexusMembershipSyncErrors
        expr: sum(rate(membership_sync_errors_total[5m])) > {{ $t.membershipErrorsPerSecond }}
        for: 10m
        labels: { severity: warning, plane: identity }
        annotations:
          summary: "membership-sync errors elevated"
          description: >-
            membership-sync is erroring above {{ $t.membershipErrorsPerSecond }}/s for
            10m — the acting-workspace projection may drift from the routing source of
            record.
      - alert: NexusMembershipSyncBackstopStalled
        expr: rate(membership_sync_backstop_passes_total[30m]) == 0
        for: 30m
        labels: { severity: warning, plane: identity }
        annotations:
          summary: "membership-sync backstop stalled"
          description: >-
            No membership-sync backstop pass completed in 30m — a missed NOTIFY would
            not self-heal. Check the worker and its read-only routing connection.
      - alert: NexusAuthzAdminUnauthorizedSpike
        expr: sum(rate(authz_admin_mutations_total{op="unauthorized"}[5m])) > {{ $t.unauthorizedPerSecond }}
        for: 10m
        labels: { severity: warning, plane: identity }
        annotations:
          summary: "authz-admin unauthorized (401) spike"
          description: >-
            The authz-admin authoring surface is rejecting requests (401) above
            {{ $t.unauthorizedPerSecond }}/s for 10m — a bad/rotated admin token or
            unauthorized attempts against the authorization store. Needs the `op`
            attribute kept by your collector.
{{- if .Values.edge.enabled }}
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
            More than {{ $t.edge5xxRatio }} of edge responses were 5xx over 5m — the
            edge or a backend pool is failing. Envoy admin stats (scraped), so
            unaffected by the OTLP collector.
      - alert: NexusEdgeLatencyHigh
        expr: histogram_quantile(0.99, sum by (le) (rate(envoy_http_downstream_rq_time_bucket{envoy_http_conn_manager_prefix="edge"}[5m]))) > {{ $t.edgeP99Milliseconds }}
        for: 10m
        labels: { severity: warning, plane: edge }
        annotations:
          summary: "Edge request p99 latency high"
          description: >-
            Edge downstream request p99 has been above {{ $t.edgeP99Milliseconds }}ms
            for 10m (Envoy `downstream_rq_time` is in milliseconds).
{{- end }}
{{- end -}}
