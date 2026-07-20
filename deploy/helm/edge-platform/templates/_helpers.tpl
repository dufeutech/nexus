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
PROFILE_PG_URL Secret name/key the combined edge's identity sidecar reads. Default
to the identity subchart's managed Secret; honour an external existingSecret it
points at, or an explicit compose override. This is the direct/session URL the
sidecar's LISTEN/NOTIFY change feed (channel `identity_changes`) uses.
*/}}
{{- define "edge-platform.identityPgSecret" -}}
{{- $iv := index .Values "identity-plane" -}}
{{- if .Values.compose.identityPgSecret -}}
{{- .Values.compose.identityPgSecret -}}
{{- else if $iv.postgres.existingSecret -}}
{{- $iv.postgres.existingSecret -}}
{{- else -}}
{{- printf "%s-pg" (include "edge-platform.identityFullname" .) -}}
{{- end -}}
{{- end -}}

{{- define "edge-platform.identityPgSecretKey" -}}
{{- $iv := index .Values "identity-plane" -}}
{{- if .Values.compose.identityPgSecretKey -}}
{{- .Values.compose.identityPgSecretKey -}}
{{- else if $iv.postgres.existingSecret -}}
{{- $iv.postgres.existingSecretKey -}}
{{- else -}}
url
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
OTLP resource attributes for the combined edge's Rust containers (first-party-telemetry).
`deployment.environment.name` is a REQUIRED, verified invariant whenever export is ON: a
per-environment SLO is undefined without it, so render FAILS CLOSED when
global.telemetry.environment is empty — mirroring the Rust services' startup guard. Only
invoked inside the `if …otlpEndpoint` block, so export-off deploys are unaffected. Call with
root context ($), since the container env lists reference $.Values.global directly.
*/}}
{{- define "edge-platform.otelResourceAttributes" -}}
{{- $env := required "global.telemetry.environment is REQUIRED when global.telemetry.otlpEndpoint is set: every first-party signal must carry deployment.environment.name for per-environment SLOs (first-party-telemetry), e.g. \"production\"." (dig "telemetry" "environment" "" (.Values.global | default dict)) -}}
deployment.environment.name={{ $env }}
{{- end -}}

{{/*
ZITADEL JWKS Host header (issuer authority) for the combined edge's jwt_authn.
*/}}
{{- define "edge-platform.jwksHost" -}}
{{- $iv := index .Values "identity-plane" -}}
{{- if $iv.oidc.jwksHost -}}
{{- $iv.oidc.jwksHost -}}
{{- else -}}
{{- $iv.oidc.issuer | trimPrefix "https://" | trimPrefix "http://" | trimSuffix "/" -}}
{{- end -}}
{{- end -}}

{{/*
Image ref helper: (dict "repo" R "tag" T "ctx" .) -> R:T. Tag resolution order (first
non-empty wins), so ONE value tags the whole combined edge: per-image `tag` -> the
umbrella-wide `global.image.tag` -> the chart `appVersion`.
*/}}
{{- define "edge-platform.image" -}}
{{- $tag := .tag | default (dig "image" "tag" "" (.ctx.Values.global | default dict)) | default .ctx.Chart.AppVersion -}}
{{- printf "%s:%s" .repo $tag -}}
{{- end -}}

{{/*
Customer-domain TLS front tier (deployment-front-tier-parity). Names for its own
Deployment/Service and the dedicated ask Service that fronts tenant-router :9300.
*/}}
{{- define "edge-platform.frontTierFullname" -}}
{{- printf "%s-front-tier" (include "edge-platform.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- define "edge-platform.askServiceName" -}}
{{- printf "%s-ask" (include "edge-platform.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Front-tier CertMagic Postgres store Secret (D4). existingSecret wins; otherwise the
chart-managed <fullname>-front-tier-storage Secret rendered from frontTier.storage.url
(dev convenience). MUST resolve to a session/direct routing-DB URL for a DML-only role.
*/}}
{{- define "edge-platform.frontTierStorageSecret" -}}
{{- $ft := .Values.frontTier -}}
{{- if $ft.storage.existingSecret -}}
{{- $ft.storage.existingSecret -}}
{{- else -}}
{{- printf "%s-storage" (include "edge-platform.frontTierFullname" .) -}}
{{- end -}}
{{- end -}}
{{- define "edge-platform.frontTierStorageSecretKey" -}}
{{- $ft := .Values.frontTier -}}
{{- if $ft.storage.existingSecret -}}
{{- $ft.storage.existingSecretKey | default "url" -}}
{{- else -}}
url
{{- end -}}
{{- end -}}

{{/*
Front-tier ACME account-key Secret (D5). existingSecret — populated OUT-OF-BAND (ESO /
OpenBao Secrets Operator / a K8s-auth role), mirroring identity signing — wins; otherwise
the chart-managed <fullname>-front-tier-acme Secret from frontTier.acmeAccount.keyPem (dev).
*/}}
{{- define "edge-platform.frontTierAcmeSecret" -}}
{{- $ft := .Values.frontTier -}}
{{- if $ft.acmeAccount.existingSecret -}}
{{- $ft.acmeAccount.existingSecret -}}
{{- else -}}
{{- printf "%s-acme" (include "edge-platform.frontTierFullname" .) -}}
{{- end -}}
{{- end -}}
{{- define "edge-platform.frontTierAcmeSecretKey" -}}
{{- $ft := .Values.frontTier -}}
{{- if $ft.acmeAccount.existingSecret -}}
{{- $ft.acmeAccount.existingSecretKey | default "account.key" -}}
{{- else -}}
account.key
{{- end -}}
{{- end -}}
