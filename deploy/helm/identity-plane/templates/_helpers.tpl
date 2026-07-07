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
Image ref: ("repo" "tag" ctx) -> repo:tag. Tag resolution order (first non-empty
wins), so an operator overrides ALL images with ONE value instead of every per-image
tag: the per-image `tag` -> the chart-wide `images.tag` -> the umbrella-wide
`global.image.tag` -> the chart `appVersion`.
*/}}
{{- define "identity-plane.image" -}}
{{- $tag := .tag | default .ctx.Values.images.tag | default (dig "image" "tag" "" (.ctx.Values.global | default dict)) | default .ctx.Chart.AppVersion -}}
{{- printf "%s:%s" .repo $tag -}}
{{- end -}}

{{/*
Postgres is EXTERNAL by design — this chart does not run a database. The sidecar,
authz-admin and membership-sync read PROFILE_PG_URL from a Secret. Either you supply
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
Routing-plane membership store — a READ-ONLY connection the membership-sync worker
holds to LISTEN on `routing_membership_changes` and SELECT routing.memberships. A
SEPARATE database from PROFILE_PG in production; least privilege (SELECT + LISTEN).
Same existingSecret-vs-inline pattern as the pg Secret above.
*/}}
{{- define "identity-plane.routingPgSecretName" -}}
{{- if .Values.routingPg.existingSecret -}}
{{- .Values.routingPg.existingSecret -}}
{{- else -}}
{{- printf "%s-routing-ro" (include "identity-plane.fullname" .) -}}
{{- end -}}
{{- end -}}

{{- define "identity-plane.routingPgSecretKey" -}}
{{- if .Values.routingPg.existingSecret -}}
{{- .Values.routingPg.existingSecretKey -}}
{{- else -}}
url
{{- end -}}
{{- end -}}

{{- define "identity-plane.ownsRoutingPgSecret" -}}
{{- if .Values.routingPg.existingSecret -}}false{{- else -}}true{{- end -}}
{{- end -}}

{{- define "identity-plane.routingPgUrl" -}}
{{- required "routingPg.url is required (read-only routing DB URL) when routingPg.existingSecret is not set" .Values.routingPg.url -}}
{{- end -}}

{{/*
OTLP telemetry endpoint (first-party-telemetry): the chart-local
`telemetry.otlpEndpoint` if set, else the umbrella-wide `global.telemetry.otlpEndpoint`
— so a combined (edge-platform) deploy sets ONE knob and both planes inherit it.
Empty => the Rust planes export nothing (stdout logs only, fail-open).
*/}}
{{- define "identity-plane.otlpEndpoint" -}}
{{- .Values.telemetry.otlpEndpoint | default (dig "telemetry" "otlpEndpoint" "" (.Values.global | default dict)) -}}
{{- end -}}

{{/*
Issuer authority (host[:port]) — used as the JWKS Host header default.
*/}}
{{- define "identity-plane.jwksHost" -}}
{{- if .Values.oidc.jwksHost -}}
{{- .Values.oidc.jwksHost -}}
{{- else -}}
{{- .Values.oidc.issuer | trimPrefix "https://" | trimPrefix "http://" | trimSuffix "/" -}}
{{- end -}}
{{- end -}}

{{/*
authz-admin bearer token (nexus-native-authorization) — the fail-closed admin gate
on the authoring surface. Same existingSecret-vs-inline pattern as the pg Secret;
the chart manages the Secret only when neither an existingSecret nor authDisabled is
set (so a token is always required unless auth is explicitly turned off).
*/}}
{{- define "identity-plane.authzAdminSecretName" -}}
{{- if .Values.authzAdmin.existingSecret -}}
{{- .Values.authzAdmin.existingSecret -}}
{{- else -}}
{{- printf "%s-authz-admin" (include "identity-plane.fullname" .) -}}
{{- end -}}
{{- end -}}

{{- define "identity-plane.authzAdminSecretKey" -}}
{{- if .Values.authzAdmin.existingSecret -}}
{{- .Values.authzAdmin.existingSecretKey -}}
{{- else -}}
token
{{- end -}}
{{- end -}}

{{- define "identity-plane.ownsAuthzAdminSecret" -}}
{{- if or .Values.authzAdmin.existingSecret .Values.authzAdmin.authDisabled -}}false{{- else -}}true{{- end -}}
{{- end -}}
