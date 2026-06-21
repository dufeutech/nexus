{{/*
Name / fullname / labels.
*/}}
{{- define "edge-platform.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "edge-platform.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name (include "edge-platform.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "edge-platform.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: edge-platform
{{- end -}}

{{- define "edge-platform.selectorLabels" -}}
app.kubernetes.io/name: {{ include "edge-platform.name" .ctx }}
app.kubernetes.io/instance: {{ .ctx.Release.Name }}
app.kubernetes.io/component: {{ .component }}
{{- end -}}

{{/*
Subchart fullnames (subchart fullname = <release>-<chartName> with no override).
*/}}
{{- define "edge-platform.routingFullname" -}}
{{- printf "%s-routing-plane" .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- define "edge-platform.identityFullname" -}}
{{- printf "%s-identity-plane" .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
ROUTING_PG_URL Secret name/key the combined edge's tenant-router reads. Default
to the routing subchart's managed Secret; honour an external existingSecret it
points at, or an explicit compose override.
*/}}
{{- define "edge-platform.routingPgSecret" -}}
{{- $rv := index .Values "routing-plane" -}}
{{- if .Values.compose.routingPgSecret -}}
{{- .Values.compose.routingPgSecret -}}
{{- else if $rv.postgres.existingSecret -}}
{{- $rv.postgres.existingSecret -}}
{{- else -}}
{{- printf "%s-pg" (include "edge-platform.routingFullname" .) -}}
{{- end -}}
{{- end -}}

{{- define "edge-platform.routingPgSecretKey" -}}
{{- $rv := index .Values "routing-plane" -}}
{{- if .Values.compose.routingPgSecretKey -}}
{{- .Values.compose.routingPgSecretKey -}}
{{- else if $rv.postgres.existingSecret -}}
{{- $rv.postgres.existingSecretKey -}}
{{- else -}}
url
{{- end -}}
{{- end -}}

{{/*
OPTIONAL pooled read endpoint (ROUTING_PG_READ_URL) for the combined edge's
tenant-router. Enabled when the routing subchart sets postgres.readExistingSecret
or postgres.readUrl (or a compose override is given). The LISTEN feed + control
plane keep using the direct routing Pg secret.
*/}}
{{- define "edge-platform.hasRoutingPgRead" -}}
{{- $rv := index .Values "routing-plane" -}}
{{- if or .Values.compose.routingPgReadSecret $rv.postgres.readExistingSecret $rv.postgres.readUrl -}}true{{- else -}}false{{- end -}}
{{- end -}}

{{- define "edge-platform.routingPgReadSecret" -}}
{{- $rv := index .Values "routing-plane" -}}
{{- if .Values.compose.routingPgReadSecret -}}
{{- .Values.compose.routingPgReadSecret -}}
{{- else if $rv.postgres.readExistingSecret -}}
{{- $rv.postgres.readExistingSecret -}}
{{- else -}}
{{- printf "%s-pg-read" (include "edge-platform.routingFullname" .) -}}
{{- end -}}
{{- end -}}

{{- define "edge-platform.routingPgReadSecretKey" -}}
{{- $rv := index .Values "routing-plane" -}}
{{- if .Values.compose.routingPgReadSecretKey -}}
{{- .Values.compose.routingPgReadSecretKey -}}
{{- else if $rv.postgres.readExistingSecret -}}
{{- $rv.postgres.readExistingSecretKey -}}
{{- else -}}
url
{{- end -}}
{{- end -}}

{{/*
MONGO_URL the combined edge's identity sidecar dials — the identity subchart's
EXTERNAL replica set URI (or a compose override).
*/}}
{{- define "edge-platform.mongoUrl" -}}
{{- $iv := index .Values "identity-plane" -}}
{{- if .Values.compose.mongoUrl -}}
{{- .Values.compose.mongoUrl -}}
{{- else -}}
{{- required "identity-plane.mongo.uri is required (external MongoDB replica set URI)" $iv.mongo.uri -}}
{{- end -}}
{{- end -}}

{{/*
REDIS_URL the combined edge's tenant-router dials, or "" for L1-only. Redis is an
OPTIONAL external L2 — empty unless routing-plane.redis is enabled.
*/}}
{{- define "edge-platform.redisUrl" -}}
{{- $rv := index .Values "routing-plane" -}}
{{- if .Values.compose.redisUrl -}}
{{- .Values.compose.redisUrl -}}
{{- else if $rv.redis.enabled -}}
{{- required "routing-plane.redis.url is required when routing-plane.redis.enabled=true" $rv.redis.url -}}
{{- end -}}
{{- end -}}

{{/*
ZITADEL JWKS Host header (issuer authority) for the combined edge's jwt_authn.
*/}}
{{- define "edge-platform.jwksHost" -}}
{{- $iv := index .Values "identity-plane" -}}
{{- if $iv.zitadel.jwksHost -}}
{{- $iv.zitadel.jwksHost -}}
{{- else -}}
{{- $iv.zitadel.issuer | trimPrefix "https://" | trimPrefix "http://" | trimSuffix "/" -}}
{{- end -}}
{{- end -}}

{{/*
Image ref helper: (dict "repo" R "tag" T "ctx" .) -> R:T (tag defaults to AppVersion).
*/}}
{{- define "edge-platform.image" -}}
{{- $tag := .tag | default .ctx.Chart.AppVersion -}}
{{- printf "%s:%s" .repo $tag -}}
{{- end -}}
