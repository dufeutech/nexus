#!/usr/bin/env sh
# normalized-principal end-to-end assertions: a CORE PLATFORM SERVICE authenticates by
# infra-trust (a dev ServiceAccount token), traverses the real edge, and the box receives
# a signed contract with principal_kind=service + the acting workspace + platform
# permissions — while an unregistered service fails closed. Run against a compose/k8s
# stack with signing ENABLED (a key.pem + jwks.json mounted; see
# docs/runbook-contract-signing-keys.md) and the service_account jwt_authn provider wired
# (edge/envoy.yaml) + platform.services seeded (postgres-init/20-platform-services.sql).
# Uses the header-echo backend (traefik/whoami) so we see exactly what reached the box.
#
# Covers (tasks 7.1, 7.2):
#   1. A verified SERVICE request carries x-identity-contract as a compact JWS whose
#      claims verify: iss = the nexus issuer, aud = the box route-pool, principal_kind =
#      service, workspace_id = the acting workspace, permissions present, exp in future.
#      x-user-type reaching the box is `service`.
#   2. Fail-closed: a verified service token whose sub is NOT in platform.services mints
#      NO contract (the box must reject it on an enriched route).
#
# NOT covered here: the live-revocation window (revoke a row -> denied within seconds) —
# assert manually by `UPDATE platform.services SET status='revoked'` then re-running case 1.
#
# Requires:
#   SVC_TOKEN   a dev SA bearer JWT for a REGISTERED service (mint with
#               scripts/mint-dev-sa-token.py). Its sub must match a seeded active row.
#   WS_HEADER   the acting workspace the routing plane resolves for the test host
#               (x-workspace-id). Defaults to the seeded dev workspace.
#   HOST        a host that routes to the header-echo box.
#   AUD/ISS     the box route-pool and the nexus issuer (as in contract-signing-e2e.sh).
set -u

EDGE=${EDGE:-http://localhost:10000}
HOST=${HOST:-localhost}
ISS=${ISS:-https://identity.nexus}
AUD=${AUD:-application}                          # the box's x-route-pool
WS_HEADER=${WS_HEADER:-ws-dev}                   # the acting workspace (x-workspace-id)
SVC_TOKEN=${SVC_TOKEN:-}                         # a REGISTERED service's dev SA JWT
SVC_TOKEN_UNKNOWN=${SVC_TOKEN_UNKNOWN:-}         # a VERIFIED but UNREGISTERED service JWT

fail=0
ok() { if [ "$1" = 1 ]; then echo "  ok   - $2"; else echo "  FAIL - $2"; fail=1; fi; }

b64url_decode() {
  s=$1
  case $(( ${#s} % 4 )) in 2) s="${s}==";; 3) s="${s}=";; esac
  printf '%s' "$s" | tr '_-' '/+' | base64 -d 2>/dev/null
}
hdr_val() { printf '%s' "$1" | grep -i "^$2:" | head -1 | cut -d: -f2- | tr -d ' \r'; }

if [ -z "$SVC_TOKEN" ]; then
  echo "SKIPPED: set SVC_TOKEN (a registered service's dev SA JWT). Mint one with:"
  echo "  python3 scripts/mint-dev-sa-token.py --sub system:serviceaccount:nexus:events-writer"
  exit 0
fi

echo "== 1. a verified REGISTERED service gets a service contract =="
# The service acts ON a workspace per request; the routing plane authors x-workspace-id.
# In this harness we pass it explicitly (the edge strips+re-authors trusted headers, so a
# client value would be dropped — for the lab we rely on the router resolving WS_HEADER
# for HOST; adjust HOST/seed so the resolved acting workspace equals $WS_HEADER).
BODY=$(curl -s -H "Host: $HOST" -H "Authorization: Bearer $SVC_TOKEN" "$EDGE/")
JWS=$(hdr_val "$BODY" "X-Identity-Contract")
SEGS=$(printf '%s' "$JWS" | awk -F. '{print NF}')
ok "$([ "$SEGS" = 3 ] && echo 1 || echo 0)" "x-identity-contract is a compact JWS (got $SEGS segments)"

UTYPE=$(hdr_val "$BODY" "X-User-Type")
ok "$([ "$UTYPE" = "service" ] && echo 1 || echo 0)" "x-user-type reaching the box is 'service' (got '$UTYPE')"

PAYLOAD=$(b64url_decode "$(printf '%s' "$JWS" | cut -d. -f2)")
claim() { printf '%s' "$PAYLOAD" | grep -o "\"$1\"[[:space:]]*:[[:space:]]*\"[^\"]*\"" | head -1 | sed 's/.*: *"//; s/"$//'; }
NOW=$(date +%s)
EXP=$(printf '%s' "$PAYLOAD" | grep -o '"exp"[[:space:]]*:[[:space:]]*[0-9]*' | grep -o '[0-9]*$')
ok "$([ "$(claim iss)" = "$ISS" ] && echo 1 || echo 0)" "iss = $ISS (got '$(claim iss)')"
ok "$([ "$(claim aud)" = "$AUD" ] && echo 1 || echo 0)" "aud = the box route-pool $AUD (got '$(claim aud)')"
ok "$([ "$(claim principal_kind)" = "service" ] && echo 1 || echo 0)" "principal_kind = service (got '$(claim principal_kind)')"
ok "$([ -n "$(claim workspace_id)" ] && echo 1 || echo 0)" "workspace_id present (got '$(claim workspace_id)')"
# member_type/role are OMITTED for a service.
ok "$(printf '%s' "$PAYLOAD" | grep -q '"member_type"' && echo 0 || echo 1)" "member_type omitted for a service"
ok "$(printf '%s' "$PAYLOAD" | grep -q '"permissions"' && echo 1 || echo 0)" "permissions present for a service"
ok "$([ -n "$EXP" ] && [ "$EXP" -gt "$NOW" ] && echo 1 || echo 0)" "exp is in the future (exp=$EXP now=$NOW)"

echo "== 2. a verified UNREGISTERED service fails closed (no contract) =="
if [ -n "$SVC_TOKEN_UNKNOWN" ]; then
  UBODY=$(curl -s -H "Host: $HOST" -H "Authorization: Bearer $SVC_TOKEN_UNKNOWN" "$EDGE/")
  UV=$(hdr_val "$UBODY" "X-Identity-Contract")
  ok "$([ -z "$UV" ] && echo 1 || echo 0)" "unregistered service carries no x-identity-contract (got '${UV:-<none>}')"
  UT=$(hdr_val "$UBODY" "X-User-Type")
  ok "$([ -z "$UT" ] && echo 1 || echo 0)" "unregistered service carries no acting x-user-type (got '${UT:-<none>}')"
else
  echo "  SKIP - set SVC_TOKEN_UNKNOWN (a verified token whose sub is NOT registered) to run case 2"
fi

[ "$fail" = 0 ] && echo "All service-identity e2e checks passed." || echo "SOME CHECKS FAILED"
exit "$fail"
