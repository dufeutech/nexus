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
{{/*
Image ref. Tag resolution order (first non-empty wins), so ONE value overrides ALL
images: per-image `tag` -> chart-wide `images.tag` -> umbrella `global.image.tag` ->
chart `appVersion`.
*/}}
{{- define "routing-plane.image" -}}
{{- $tag := .tag | default .ctx.Values.images.tag | default (dig "image" "tag" "" (.ctx.Values.global | default dict)) | default .ctx.Chart.AppVersion -}}
{{- printf "%s:%s" .repo $tag -}}
{{- end -}}

{{/*
OTLP telemetry endpoint (first-party-telemetry): the chart-local
`telemetry.otlpEndpoint` if set, else the umbrella-wide `global.telemetry.otlpEndpoint`
— so a combined (edge-platform) deploy sets ONE knob and both planes inherit it.
Empty => the Rust planes export nothing (stdout logs only, fail-open).
*/}}
{{- define "routing-plane.otlpEndpoint" -}}
{{- .Values.telemetry.otlpEndpoint | default (dig "telemetry" "otlpEndpoint" "" (.Values.global | default dict)) -}}
{{- end -}}

{{/*
OTLP resource attributes (first-party-telemetry). `deployment.environment.name` is a
REQUIRED, verified invariant whenever telemetry export is ON: a per-environment SLO is
undefined without it, so render FAILS CLOSED here when it is empty — mirroring the Rust
services' startup guard. Only invoked inside the `if $otlp` block, so export-off deploys
are unaffected. Inherits the umbrella global.telemetry.environment when the subchart's is unset.
*/}}
{{- define "routing-plane.otelResourceAttributes" -}}
{{- $env := .Values.telemetry.environment | default (dig "telemetry" "environment" "" (.Values.global | default dict)) -}}
{{- $env = required "telemetry.environment is REQUIRED when telemetry.otlpEndpoint is set: every first-party signal must carry deployment.environment.name for per-environment SLOs (first-party-telemetry). Set telemetry.environment (or global.telemetry.environment), e.g. \"production\"." $env -}}
deployment.environment.name={{ $env }}
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
Control-plane admin-token Secret name/key (RFC C16). Uses an existing Secret when
controlPlane.auth.existingSecret is set, otherwise the chart-managed Secret.
*/}}
{{- define "routing-plane.controlAuthSecretName" -}}
{{- if .Values.controlPlane.auth.existingSecret -}}
{{- .Values.controlPlane.auth.existingSecret -}}
{{- else -}}
{{- printf "%s-control-auth" (include "routing-plane.fullname" .) -}}
{{- end -}}
{{- end -}}

{{- define "routing-plane.controlAuthSecretKey" -}}
{{- if .Values.controlPlane.auth.existingSecret -}}
{{- .Values.controlPlane.auth.existingSecretKey -}}
{{- else -}}
token
{{- end -}}
{{- end -}}

{{/*
Whether the chart manages its own control-auth Secret (true) vs an existing one.
Only meaningful when a legacy token is configured (posture 2); an existingSecret or a
pepper-only install renders no managed token Secret.
*/}}
{{- define "routing-plane.ownsControlAuthSecret" -}}
{{- if and .Values.controlPlane.auth.token (not .Values.controlPlane.auth.existingSecret) -}}true{{- else -}}false{{- end -}}
{{- end -}}

{{/*
Control-plane admin-token PEPPER Secret name/key (posture 1, named tokens). Uses an
existing Secret when tokenPepper.existingSecret is set, else the chart-managed Secret.
The pepper is HMAC key material distinct from the legacy bearer token.
*/}}
{{- define "routing-plane.controlPepperSecretName" -}}
{{- if .Values.controlPlane.auth.tokenPepper.existingSecret -}}
{{- .Values.controlPlane.auth.tokenPepper.existingSecret -}}
{{- else -}}
{{- printf "%s-control-pepper" (include "routing-plane.fullname" .) -}}
{{- end -}}
{{- end -}}

{{- define "routing-plane.controlPepperSecretKey" -}}
{{- if .Values.controlPlane.auth.tokenPepper.existingSecret -}}
{{- .Values.controlPlane.auth.tokenPepper.existingSecretKey -}}
{{- else -}}
pepper
{{- end -}}
{{- end -}}

{{/*
Whether the chart manages its own pepper Secret (inline value, no existingSecret).
*/}}
{{- define "routing-plane.ownsControlPepperSecret" -}}
{{- if and .Values.controlPlane.auth.tokenPepper.value (not .Values.controlPlane.auth.tokenPepper.existingSecret) -}}true{{- else -}}false{{- end -}}
{{- end -}}

{{/*
Admin-auth env block (admin-plane-authorization) — the fail-closed posture selector,
mirroring routing-rs/control-plane/src/main.rs:144-203. Emits the env vars for the
selected posture and FAILS render if none is valid, so an unstartable config is caught
at `helm template`, not at pod crash. Call with root context and `| nindent <n>`.

NOTE (admin-plane-authorization drift): this logic is intentionally DUPLICATED in the
identity-plane chart (different env names / gate polarity). Helm scopes named templates
to one chart tree, so a shared partial would break standalone render. The two copies are
locked against drift by golden tests (helm-unittest), which are the source of truth.
*/}}
{{- define "routing-plane.adminAuthEnv" -}}
{{- $auth := .Values.controlPlane.auth -}}
{{- $pepperSet := or $auth.tokenPepper.existingSecret $auth.tokenPepper.value -}}
{{- $legacySet := or $auth.existingSecret $auth.token -}}
{{- if not $auth.enabled -}}
- name: CONTROL_AUTH_DISABLED
  value: "true"
{{- else -}}
{{- if and $auth.legacyTokenOk (not $legacySet) -}}
{{- fail "controlPlane.auth.legacyTokenOk=true but no legacy token is set — set controlPlane.auth.token or controlPlane.auth.existingSecret (mirrors control-plane's 'missing CONTROL_AUTH_TOKEN for legacy mode' refusal)." -}}
{{- end -}}
{{- if and (not $pepperSet) (not $auth.legacyTokenOk) -}}
{{- fail "no admin auth posture selected for control-plane. Set controlPlane.auth.tokenPepper.* (named tokens), or controlPlane.auth.legacyTokenOk=true with a legacy token (migration), or controlPlane.auth.enabled=false (trusted-network/dev only)." -}}
{{- end -}}
{{- if $pepperSet }}
- name: ADMIN_TOKEN_PEPPER
  valueFrom:
    secretKeyRef:
      name: {{ include "routing-plane.controlPepperSecretName" . }}
      key: {{ include "routing-plane.controlPepperSecretKey" . }}
{{- end }}
{{- if $auth.legacyTokenOk }}
- name: ADMIN_LEGACY_TOKEN_OK
  value: "true"
{{- end }}
{{- if $legacySet }}
- name: CONTROL_AUTH_TOKEN
  valueFrom:
    secretKeyRef:
      name: {{ include "routing-plane.controlAuthSecretName" . }}
      key: {{ include "routing-plane.controlAuthSecretKey" . }}
{{- end }}
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

{{/*
The NATS_URL the router dials for cross-region invalidation delivery, or "" when
disabled. NATS is the OPTIONAL invalidation transport (track D): setting it routes
invalidations over NATS instead of pg_notify (single-server). Default-off — an
unset NATS_URL keeps the router on the pg_notify feed, so single-region
deployments are unaffected. Core NATS (fire-and-forget); a dropped signal
self-heals within router.cacheTtlSeconds, exactly as pg_notify already tolerates.
*/}}
{{- define "routing-plane.natsUrl" -}}
{{- if .Values.nats.enabled -}}
{{- required "nats.url is required when nats.enabled=true (cross-region invalidation transport)" .Values.nats.url -}}
{{- end -}}
{{- end -}}
