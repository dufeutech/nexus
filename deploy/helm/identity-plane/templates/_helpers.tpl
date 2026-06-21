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
MongoDB URI every component dials. This project does NOT run a database — the
store is an EXTERNAL replica set you operate (a managed service or the Mongo
Community Operator). Change streams (RFC C4) require a replica set, so the URI
must include ?replicaSet=...
*/}}
{{- define "identity-plane.mongoUri" -}}
{{- required "mongo.uri is required: external MongoDB replica set URI (must include ?replicaSet=...)" .Values.mongo.uri -}}
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
