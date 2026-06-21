{{/*
Chart name / fullname helpers.
*/}}
{{- define "routing-plane.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "routing-plane.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name (include "routing-plane.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "routing-plane.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: routing-plane
{{- end -}}

{{/*
Per-component selector labels. Call with (dict "ctx" . "component" "edge").
*/}}
{{- define "routing-plane.selectorLabels" -}}
app.kubernetes.io/name: {{ include "routing-plane.name" .ctx }}
app.kubernetes.io/instance: {{ .ctx.Release.Name }}
app.kubernetes.io/component: {{ .component }}
{{- end -}}

{{/*
Image ref: ("repo" "tag" ctx) -> repo:tag, defaulting tag to AppVersion.
*/}}
{{- define "routing-plane.image" -}}
{{- $tag := .tag | default .ctx.Chart.AppVersion -}}
{{- printf "%s:%s" .repo $tag -}}
{{- end -}}

{{/*
Postgres is EXTERNAL by design — this chart does not run a database. The router +
control-plane read ROUTING_PG_URL from a Secret. Either you supply your own
(postgres.existingSecret — preferred, works with ExternalSecrets/SealedSecrets),
or the chart wraps an inline postgres.url in a managed Secret.
*/}}
{{- define "routing-plane.pgSecretName" -}}
{{- if .Values.postgres.existingSecret -}}
{{- .Values.postgres.existingSecret -}}
{{- else -}}
{{- printf "%s-pg" (include "routing-plane.fullname" .) -}}
{{- end -}}
{{- end -}}

{{- define "routing-plane.pgSecretKey" -}}
{{- if .Values.postgres.existingSecret -}}
{{- .Values.postgres.existingSecretKey -}}
{{- else -}}
url
{{- end -}}
{{- end -}}

{{/*
Whether the chart manages its own pg Secret (true) vs using an existing one.
*/}}
{{- define "routing-plane.ownsPgSecret" -}}
{{- if .Values.postgres.existingSecret -}}false{{- else -}}true{{- end -}}
{{- end -}}

{{/*
The ROUTING_PG_URL the chart-managed Secret holds (the inline external URL). Not
used when postgres.existingSecret is supplied.
*/}}
{{- define "routing-plane.pgUrl" -}}
{{- required "postgres.url is required (external Postgres URL) when postgres.existingSecret is not set" .Values.postgres.url -}}
{{- end -}}

{{/*
OPTIONAL pooled read endpoint for the tenant-router (ROUTING_PG_READ_URL). Enabled
when postgres.readExistingSecret OR postgres.readUrl is set; empty otherwise (the
router reads over the direct URL). The control plane + LISTEN feed never use it.
*/}}
{{- define "routing-plane.hasPgReadUrl" -}}
{{- if or .Values.postgres.readExistingSecret .Values.postgres.readUrl -}}true{{- else -}}false{{- end -}}
{{- end -}}

{{- define "routing-plane.pgReadSecretName" -}}
{{- if .Values.postgres.readExistingSecret -}}
{{- .Values.postgres.readExistingSecret -}}
{{- else -}}
{{- printf "%s-pg-read" (include "routing-plane.fullname" .) -}}
{{- end -}}
{{- end -}}

{{- define "routing-plane.pgReadSecretKey" -}}
{{- if .Values.postgres.readExistingSecret -}}
{{- .Values.postgres.readExistingSecretKey -}}
{{- else -}}
url
{{- end -}}
{{- end -}}

{{/*
Whether the chart manages its own pg-read Secret (i.e. an inline readUrl with no
readExistingSecret). Only meaningful when hasPgReadUrl is true.
*/}}
{{- define "routing-plane.ownsPgReadSecret" -}}
{{- if and .Values.postgres.readUrl (not .Values.postgres.readExistingSecret) -}}true{{- else -}}false{{- end -}}
{{- end -}}

{{/*
The REDIS_URL the router dials, or "" when the optional L2 is disabled. Redis is
an OPTIONAL external cache tier (RFC decision 9) — never a correctness dependency.
*/}}
{{- define "routing-plane.redisUrl" -}}
{{- if .Values.redis.enabled -}}
{{- required "redis.url is required when redis.enabled=true (external Redis L2)" .Values.redis.url -}}
{{- end -}}
{{- end -}}
