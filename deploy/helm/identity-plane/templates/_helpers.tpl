{{/*
Chart name / fullname helpers.
*/}}
{{- define "identity-plane.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "identity-plane.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name (include "identity-plane.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "identity-plane.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: identity-plane
{{- end -}}

{{/*
Per-component selector labels. Call with (dict "ctx" . "component" "edge").
*/}}
{{- define "identity-plane.selectorLabels" -}}
app.kubernetes.io/name: {{ include "identity-plane.name" .ctx }}
app.kubernetes.io/instance: {{ .ctx.Release.Name }}
app.kubernetes.io/component: {{ .component }}
{{- end -}}

{{/*
Image ref: ("repo" "tag" ctx) -> repo:tag, defaulting tag to AppVersion.
*/}}
{{- define "identity-plane.image" -}}
{{- $tag := .tag | default .ctx.Chart.AppVersion -}}
{{- printf "%s:%s" .repo $tag -}}
{{- end -}}

{{/*
Postgres is EXTERNAL by design — this chart does not run a database. The sidecar,
sync-worker and reconciler read PROFILE_PG_URL from a Secret. Either you supply
your own (postgres.existingSecret — preferred, works with ExternalSecrets/
SealedSecrets), or the chart wraps an inline postgres.url in a managed Secret.
*/}}
{{- define "identity-plane.pgSecretName" -}}
{{- if .Values.postgres.existingSecret -}}
{{- .Values.postgres.existingSecret -}}
{{- else -}}
{{- printf "%s-pg" (include "identity-plane.fullname" .) -}}
{{- end -}}
{{- end -}}

{{- define "identity-plane.pgSecretKey" -}}
{{- if .Values.postgres.existingSecret -}}
{{- .Values.postgres.existingSecretKey -}}
{{- else -}}
url
{{- end -}}
{{- end -}}

{{/*
Whether the chart manages its own pg Secret (true) vs using an existing one.
*/}}
{{- define "identity-plane.ownsPgSecret" -}}
{{- if .Values.postgres.existingSecret -}}false{{- else -}}true{{- end -}}
{{- end -}}

{{/*
The PROFILE_PG_URL the chart-managed Secret holds (the inline external URL). Not
used when postgres.existingSecret is supplied.
*/}}
{{- define "identity-plane.pgUrl" -}}
{{- required "postgres.url is required (external Postgres URL) when postgres.existingSecret is not set" .Values.postgres.url -}}
{{- end -}}

{{/*
Issuer authority (host[:port]) — used as the JWKS Host header default.
*/}}
{{- define "identity-plane.jwksHost" -}}
{{- if .Values.zitadel.jwksHost -}}
{{- .Values.zitadel.jwksHost -}}
{{- else -}}
{{- .Values.zitadel.issuer | trimPrefix "https://" | trimPrefix "http://" | trimSuffix "/" -}}
{{- end -}}
{{- end -}}

{{/*
Name of the Secret holding the ZITADEL admin PAT (created or pre-existing).
*/}}
{{- define "identity-plane.patSecretName" -}}
{{- if .Values.zitadel.patSecret.existingSecret -}}
{{- .Values.zitadel.patSecret.existingSecret -}}
{{- else -}}
{{- printf "%s-zitadel-pat" (include "identity-plane.fullname" .) -}}
{{- end -}}
{{- end -}}
