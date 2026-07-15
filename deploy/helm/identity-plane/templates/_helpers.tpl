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
OTLP resource attributes (first-party-telemetry). `deployment.environment.name` is a
REQUIRED, verified invariant whenever telemetry export is ON: a per-environment SLO is
undefined without it, so render FAILS CLOSED here when it is empty — mirroring the Rust
services' startup guard. Only invoked inside the `if $otlp` block, so export-off deploys
are unaffected. Inherits the umbrella global.telemetry.environment when the subchart's is unset.
*/}}
{{- define "identity-plane.otelResourceAttributes" -}}
{{- $env := .Values.telemetry.environment | default (dig "telemetry" "environment" "" (.Values.global | default dict)) -}}
{{- $env = required "telemetry.environment is REQUIRED when telemetry.otlpEndpoint is set: every first-party signal must carry deployment.environment.name for per-environment SLOs (first-party-telemetry). Set telemetry.environment (or global.telemetry.environment), e.g. \"production\"." $env -}}
deployment.environment.name={{ $env }}
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

{{/*
identity-contract-signing: the sidecar's signing env, single-sourced so the standalone
identity edge and the umbrella's COMBINED edge stay in lockstep (they drifted once — infra
finding N11 — and a co-located edge that omits this silently serves UNSIGNED traffic).

Call with (dict "signing" <signing-values> "fullname" <plane-fullname>); the CALLER gates on
`<signing>.enabled` and applies indentation via `| nindent`. `fullname` names the default
BAO_TOKEN Secret (`<fullname>-bao-token`) the plane's signing.yaml renders — pass the identity
plane's fullname even from the umbrella so both consume the SAME token Secret.
*/}}
{{- define "identity-plane.signingEnv" -}}
{{- $s := .signing -}}
# identity-contract-signing: mint x-identity-contract (ES256) + publish the
# public keys on :9210. `aud` is derived from x-route-pool, not configured.
- { name: SIGNING_ISSUER, value: {{ $s.issuer | quote }} }
- { name: CONTRACT_TOKEN_TTL_SECONDS, value: {{ $s.tokenTtlSeconds | quote }} }
- { name: JWKS_LISTEN, value: {{ $s.jwksListen | quote }} }
{{- if $s.transit.enabled }}
# automate-signing-key-rotation: managed custody + AUTOMATED rotation via
# OpenBao Transit (Mode B local signing). The sidecar pulls versioned keys,
# GENERATES the JWKS from Transit's public keys, and rotates on schedule /
# on demand. If Bao is unreachable at startup it falls back to the break-glass
# PEM below (when provided) rather than running unsigned.
- { name: SIGNING_TRANSIT_KEY, value: {{ required "sidecar.signing.transit.keyName is required when transit is enabled" $s.transit.keyName | quote }} }
- { name: SIGNING_TRANSIT_MOUNT, value: {{ $s.transit.mount | quote }} }
- { name: BAO_ADDR, value: {{ required "sidecar.signing.transit.address is required when transit is enabled" $s.transit.address | quote }} }
- name: BAO_TOKEN
  valueFrom:
    secretKeyRef:
      name: {{ $s.transit.tokenExistingSecret | default (printf "%s-bao-token" .fullname) }}
      key: token
- { name: SIGNING_KEY_POLL_SECONDS, value: {{ $s.transit.pollSeconds | quote }} }
- { name: CONTRACT_MAX_CLOCK_SKEW_SECONDS, value: {{ $s.transit.maxClockSkewSeconds | quote }} }
{{- with $s.transit.rotationPeriodSeconds }}
- { name: SIGNING_ROTATION_PERIOD_SECONDS, value: {{ . | quote }} }
{{- end }}
{{- end }}
{{- if $s.kid }}
# Break-glass MANUAL key (the pre-rotation path; also the Transit startup
# fallback). Present whenever manual key material is configured.
- { name: SIGNING_KEY_PATH, value: /etc/nexus/signing-key/key.pem }
- { name: SIGNING_KID, value: {{ $s.kid | quote }} }
- { name: JWKS_FILE, value: /etc/nexus/signing-jwks/jwks.json }
{{- end }}
{{- end -}}
