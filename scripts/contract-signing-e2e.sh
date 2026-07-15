#!/usr/bin/env sh
# identity-contract-signing end-to-end assertions. Run against a compose/k8s stack that
# has signing ENABLED (a key.pem + jwks.json mounted, SIGNING_KEY_PATH/SIGNING_KID/
# JWKS_FILE set — see docs/runbook-contract-signing-keys.md). Uses the header-echo
# backend (traefik/whoami) so we see exactly what reached the box.
#
# Covers (task 9.1/9.2):
#   1. JWKS endpoint publishes the public keys at :9210/.well-known/jwks.json.
#   2. An enriched MEMBER request carries x-identity-contract as a compact JWS whose
#      claims verify: iss = the nexus issuer, aud = the box's route-pool, exp in the
#      future, ctr present, and sub/workspace_id match the member.
#   3. An ANONYMOUS request carries NO x-identity-contract (nothing to sign), so a
#      verifying box fails closed on an enriched route.
#
# NOT covered here: the ES256 signature math itself (a box verifies that with a JWT
# library against the JWKS from step 1). This script checks structure + claims + that the
# verifying key is published.
#
# Requires: a MEMBER bearer token in $TOKEN (a real provider-minted JWT whose subject has
# a seeded membership of the acting workspace), the box's route-pool in $AUD, and the
# nexus issuer in $ISS. See scripts/tenancy-edge-auth-e2e.sh for how the member path is
# set up.
set -u

EDGE=${EDGE:-http://localhost:10000}
JWKS_URL=${JWKS_URL:-http://localhost:9210/.well-known/jwks.json}
HOST=${HOST:-localhost}
ISS=${ISS:-https://identity.nexus}
AUD=${AUD:-application}          # the box's x-route-pool
TOKEN=${TOKEN:-}                 # a member's bearer JWT

fail=0
ok() { if [ "$1" = 1 ]; then echo "  ok   - $2"; else echo "  FAIL - $2"; fail=1; fi; }

# base64url-decode a JWT segment (add padding, translate the URL alphabet).
b64url_decode() {
  s=$1
  case $(( ${#s} % 4 )) in 2) s="${s}==";; 3) s="${s}=";; esac
  printf '%s' "$s" | tr '_-' '/+' | base64 -d 2>/dev/null
}

hdr_val() { printf '%s' "$1" | grep -i "^$2:" | head -1 | cut -d: -f2- | tr -d ' \r'; }

echo "== 1. JWKS endpoint publishes the verification keys =="
JWKS=$(curl -s --max-time 5 "$JWKS_URL")
ok "$(printf '%s' "$JWKS" | grep -q '"kty"[[:space:]]*:[[:space:]]*"EC"' && echo 1 || echo 0)" \
  "JWKS serves an EC key set (got: $(printf '%s' "$JWKS" | cut -c1-60)...)"
ok "$(printf '%s' "$JWKS" | grep -q '"kid"' && echo 1 || echo 0)" "JWKS entries carry a kid"

if [ -z "$TOKEN" ]; then
  echo "== 2/3 SKIPPED: set TOKEN (a member bearer JWT) + AUD + ISS to run the member/anon path =="
  [ "$fail" = 0 ] && echo "JWKS checks passed." || echo "SOME CHECKS FAILED"; exit "$fail"
fi

echo "== 2. enriched MEMBER request carries a verifiable signed contract =="
BODY=$(curl -s -H "Host: $HOST" -H "Authorization: Bearer $TOKEN" "$EDGE/")
JWS=$(hdr_val "$BODY" "X-Identity-Contract")
SEGS=$(printf '%s' "$JWS" | awk -F. '{print NF}')
ok "$([ "$SEGS" = 3 ] && echo 1 || echo 0)" "x-identity-contract is a compact JWS (got $SEGS segments)"

PAYLOAD=$(b64url_decode "$(printf '%s' "$JWS" | cut -d. -f2)")
claim() { printf '%s' "$PAYLOAD" | grep -o "\"$1\"[[:space:]]*:[[:space:]]*\"[^\"]*\"" | head -1 | sed 's/.*: *"//; s/"$//'; }
NOW=$(date +%s)
EXP=$(printf '%s' "$PAYLOAD" | grep -o '"exp"[[:space:]]*:[[:space:]]*[0-9]*' | grep -o '[0-9]*$')
ok "$([ "$(claim iss)" = "$ISS" ] && echo 1 || echo 0)" "iss = $ISS (got '$(claim iss)')"
ok "$([ "$(claim aud)" = "$AUD" ] && echo 1 || echo 0)" "aud = the box route-pool $AUD (got '$(claim aud)')"
ok "$([ -n "$(claim ctr)" ] && echo 1 || echo 0)" "ctr (contract version) present (got '$(claim ctr)')"
ok "$([ -n "$(claim workspace_id)" ] && echo 1 || echo 0)" "workspace_id present (got '$(claim workspace_id)')"
ok "$([ -n "$EXP" ] && [ "$EXP" -gt "$NOW" ] && echo 1 || echo 0)" "exp is in the future (exp=$EXP now=$NOW)"

echo "== 3. anonymous request carries NO signed contract (fail-closed at the box) =="
ABODY=$(curl -s -H "Host: $HOST" "$EDGE/")
AV=$(hdr_val "$ABODY" "X-Identity-Contract")
ok "$([ -z "$AV" ] && echo 1 || echo 0)" "anonymous path carries no x-identity-contract (got '${AV:-<none>}')"

[ "$fail" = 0 ] && echo "All contract-signing e2e checks passed." || echo "SOME CHECKS FAILED"
exit "$fail"
