#!/usr/bin/env bash
# Render-level guard + wiring assertions for the production-readiness gate.
#
# Proves, without a cluster:
#   1. Fail-closed guards (edge-origin-trust / edge-trust-anchor-integrity): a
#      topology that renders identity enrichment WITHOUT an explicit
#      origin-enforcement choice, or whose JWKS trust-anchor fetch has no
#      transport-integrity choice, REFUSES to render — it cannot ship open.
#   2. Enforcing config is really emitted: the valid render carries the
#      backend-origin NetworkPolicy, and the oidc_jwks cluster carries the
#      TLS transport_socket (trusted CA + SNI + SAN pin) — the mechanism by
#      which an on-path substituted JWKS response is NOT adopted (the TLS
#      handshake fails against the pinned CA/SAN before any keys are read).
#   3. The explicit non-enriched designation (edge.publicPaths) is the single
#      source of the per-route ext_proc disables: N list entries -> exactly N
#      disabled blocks; nothing else is non-enriched (fail-closed default).
#   4. D7 lab issuer consistency: the edge's hardcoded issuer/JWKS authority
#      equals the compose default ZITADEL_EXTERNALPORT — drift here is
#      silent-but-fatal (sync works, every authenticated request 401s).
#
# Runs in CI (helm-lint job) and locally: bash scripts/helm-guards-test.sh
set -u
cd "$(dirname "$0")/.."

HELM=${HELM:-helm}
CHARTS=deploy/helm
pass=0; fail=0
ok() { if [ "$1" = "1" ]; then echo "  PASS  $2"; pass=$((pass+1)); else echo "  FAIL  $2"; fail=$((fail+1)); fi; }

# render <chart> <args...> -> stdout (manifests) ; rc in $?
render() { chart=$1; shift; $HELM template rel "$CHARTS/$chart" "$@" 2>&1; }
# expect_fail <label> <needle-in-error> <chart> <args...>
expect_fail() {
  label=$1; needle=$2; chart=$3; shift 3
  out=$(render "$chart" "$@"); rc=$?
  if [ $rc -ne 0 ] && printf '%s' "$out" | grep -qi "$needle"; then ok 1 "$label"
  else ok 0 "$label (rc=$rc)"; fi
}

# Minimum viable values per chart (mirrors ci.yml).
IP_BASE=(--set postgres.url=postgres://u:p@h:5432/identity
         --set authzAdmin.adminToken=ci-dummy
         --set routingPg.url=postgres://u:p@h:5432/routing)
IP_ORIGIN_NP=(--set originEnforcement.networkPolicy.enabled=true
              --set originEnforcement.networkPolicy.backendSelector.app=backend)
IP_ORIGIN_EXT=(--set originEnforcement.external=true)
IP_JWKS_TLS=(--set oidc.jwksTls.enabled=true)
IP_JWKS_TRUST=(--set oidc.jwksPlaintextTrustedPath=true)

echo "== identity-plane: fail-closed guards =="
expect_fail "no origin-enforcement choice refuses to render" "origin-enforcement" \
  identity-plane "${IP_BASE[@]}" "${IP_JWKS_TLS[@]}"
expect_fail "no JWKS transport-integrity choice refuses to render" "trust anchor" \
  identity-plane "${IP_BASE[@]}" "${IP_ORIGIN_EXT[@]}"
expect_fail "networkPolicy without backendSelector refuses to render" "backendSelector" \
  identity-plane "${IP_BASE[@]}" "${IP_JWKS_TLS[@]}" --set originEnforcement.networkPolicy.enabled=true
expect_fail "both origin choices at once refuses to render" "pick ONE" \
  identity-plane "${IP_BASE[@]}" "${IP_JWKS_TLS[@]}" "${IP_ORIGIN_NP[@]}" "${IP_ORIGIN_EXT[@]}"

echo "== identity-plane: valid render carries the enforcing config =="
OUT=$(render identity-plane "${IP_BASE[@]}" "${IP_ORIGIN_NP[@]}" "${IP_JWKS_TLS[@]}") ; rc=$?
ok "$([ $rc -eq 0 ] && echo 1 || echo 0)" "NetworkPolicy + jwksTls topology renders"
ok "$(printf '%s' "$OUT" | grep -q 'kind: NetworkPolicy' && echo 1 || echo 0)" "backend-origin NetworkPolicy emitted"
ok "$(printf '%s' "$OUT" | grep -q 'backend-origin' && echo 1 || echo 0)" "policy is the backend-origin policy"
ok "$(printf '%s' "$OUT" | grep -q 'UpstreamTlsContext' && echo 1 || echo 0)" "oidc_jwks cluster carries UpstreamTlsContext"
ok "$(printf '%s' "$OUT" | grep -q 'trusted_ca' && echo 1 || echo 0)" "server chain verified against a trusted CA"
ok "$(printf '%s' "$OUT" | grep -q 'match_typed_subject_alt_names' && echo 1 || echo 0)" "presented SAN is pinned (substituted-key MITM fails the handshake)"
ok "$(printf '%s' "$OUT" | grep -q 'uri: "https://' && echo 1 || echo 0)" "JWKS fetched over https"

echo "== identity-plane: explicit trusted-path assertion renders plaintext =="
OUT=$(render identity-plane "${IP_BASE[@]}" "${IP_ORIGIN_EXT[@]}" "${IP_JWKS_TRUST[@]}") ; rc=$?
ok "$([ $rc -eq 0 ] && echo 1 || echo 0)" "external + trusted-path topology renders"
ok "$(printf '%s' "$OUT" | grep -q 'UpstreamTlsContext' && echo 0 || echo 1)" "no TLS transport on the asserted-trusted path"
ok "$(printf '%s' "$OUT" | grep -q 'kind: NetworkPolicy' && echo 0 || echo 1)" "no NetworkPolicy when enforcement is external"

echo "== identity-plane: publicPaths is the single source of the non-enriched designation =="
# Default allowlist (one entry: /public) -> exactly one per-route disable.
N=$(printf '%s' "$OUT" | grep -c 'ext_proc.v3.ExtProcPerRoute')
ok "$([ "$N" = "1" ] && echo 1 || echo 0)" "default allowlist renders exactly 1 non-enriched route (got $N)"
OUT2=$(render identity-plane "${IP_BASE[@]}" "${IP_ORIGIN_EXT[@]}" "${IP_JWKS_TRUST[@]}" \
  --set 'edge.publicPaths={/public,/assets}')
N=$(printf '%s' "$OUT2" | grep -c 'ext_proc.v3.ExtProcPerRoute')
ok "$([ "$N" = "2" ] && echo 1 || echo 0)" "2-entry allowlist renders exactly 2 non-enriched routes (got $N)"
OUT3=$(render identity-plane "${IP_BASE[@]}" "${IP_ORIGIN_EXT[@]}" "${IP_JWKS_TRUST[@]}" \
  --set-json 'edge.publicPaths=[]')
N=$(printf '%s' "$OUT3" | grep -c 'ext_proc.v3.ExtProcPerRoute')
ok "$([ "$N" = "0" ] && echo 1 || echo 0)" "empty allowlist renders 0 non-enriched routes — everything enriched (got $N)"

echo "== edge-platform (umbrella): same guards on the combined edge =="
$HELM dependency update "$CHARTS/edge-platform" >/dev/null
EP_BASE=(--set identity-plane.postgres.url=postgres://u:p@h:5432/identity
         --set identity-plane.authzAdmin.adminToken=ci-dummy
         --set identity-plane.routingPg.url=postgres://u:p@h:5432/routing
         --set routing-plane.postgres.url=postgres://u:p@h:5432/routing
         --set routing-plane.controlPlane.auth.token=ci-dummy)
EP_ORIGIN_NP=(--set originEnforcement.networkPolicy.enabled=true
              --set originEnforcement.networkPolicy.backendSelector.app=backend)
expect_fail "umbrella: no origin-enforcement choice refuses to render" "origin-enforcement" \
  edge-platform "${EP_BASE[@]}" --set identity-plane.oidc.jwksTls.enabled=true
expect_fail "umbrella: no JWKS transport-integrity choice refuses to render" "trust anchor" \
  edge-platform "${EP_BASE[@]}" "${EP_ORIGIN_NP[@]}"
OUT=$(render edge-platform "${EP_BASE[@]}" "${EP_ORIGIN_NP[@]}" --set identity-plane.oidc.jwksTls.enabled=true) ; rc=$?
ok "$([ $rc -eq 0 ] && echo 1 || echo 0)" "umbrella valid topology renders"
ok "$(printf '%s' "$OUT" | grep -q 'backend-origin' && echo 1 || echo 0)" "umbrella emits the backend-origin NetworkPolicy"
ok "$(printf '%s' "$OUT" | grep -q 'match_typed_subject_alt_names' && echo 1 || echo 0)" "umbrella pins the JWKS SAN"

echo "== edge-auth-gate fail-safe polarity: every edge config keeps the fail-closed gate shape =="
# R2/R3: `allow_missing` opens a route to a MISSING credential only — an
# invalid one still 401s. `allow_missing_or_failed` would accept garbage
# tokens, and losing the catch-all provider rule would turn "signal absent"
# into "public". Assert the shape on the rendered umbrella edge AND both
# static edge configs (lab + compose twin).
# (Comments legitimately NAME allow_missing_or_failed while banning it —
# strip comment lines and look for it as actual config.)
ok "$(printf '%s' "$OUT" | grep -v '^[[:space:]]*#' | grep -q 'allow_missing_or_failed' && echo 0 || echo 1)" "rendered edge never uses allow_missing_or_failed"
ok "$(printf '%s' "$OUT" | grep -q 'provider_name: oidc' && echo 1 || echo 0)" "rendered edge keeps the catch-all provider rule (absent signal fails closed)"
# The provider_name referenced by the rule MUST match a DECLARED provider — a
# rename that touches one but not the other silently breaks jwt_authn (no such
# provider → every request errors). Assert the provider directly under
# `providers:` is `oidc`, the same name the rule requires.
ok "$(printf '%s' "$OUT" | grep -qE '^[[:space:]]+oidc:[[:space:]]*$' && echo 1 || echo 0)" "rendered edge DECLARES the 'oidc' provider the rule references (no dangling provider_name)"
for CFG in edge/envoy.yaml deploy/compose/envoy/envoy.yaml; do
  ok "$(grep -v '^[[:space:]]*#' "$CFG" | grep -q 'allow_missing_or_failed' && echo 0 || echo 1)" "$CFG never uses allow_missing_or_failed"
  ok "$(grep -q 'provider_name: oidc' "$CFG" && echo 1 || echo 0)" "$CFG keeps the catch-all provider rule"
  ok "$(grep -qE '^[[:space:]]+oidc:[[:space:]]*$' "$CFG" && echo 1 || echo 0)" "$CFG declares the 'oidc' provider the rule references"
done

echo "== D7: lab issuer does not drift from the compose default =="
ISS=$(grep -oE 'issuer: "http://localhost:[0-9]+"' edge/envoy.yaml | grep -oE '[0-9]+')
JWKS=$(grep -oE 'uri: "http://localhost:[0-9]+/oauth/v2/keys"' edge/envoy.yaml | grep -oE ':[0-9]+' | grep -oE '[0-9]+')
CPORT=$(grep -oE 'ZITADEL_EXTERNALPORT:-[0-9]+' docker-compose.yaml | grep -oE '[0-9]+' | sort -u)
ok "$([ "$ISS" = "$JWKS" ] && echo 1 || echo 0)" "edge issuer port ($ISS) == edge JWKS port ($JWKS)"
ok "$([ "$(printf '%s\n' "$CPORT" | wc -l)" = "1" ] && echo 1 || echo 0)" "compose uses ONE ZITADEL_EXTERNALPORT default (got: $(printf '%s ' $CPORT))"
ok "$([ "$ISS" = "$CPORT" ] && echo 1 || echo 0)" "edge issuer port ($ISS) == compose ZITADEL_EXTERNALPORT default ($CPORT)"

echo
echo "RESULT: $pass passed, $fail failed"
[ "$fail" = 0 ]
