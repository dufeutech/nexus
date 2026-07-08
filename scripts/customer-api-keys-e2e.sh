#!/usr/bin/env sh
# customer-api-keys end-to-end assertions: a customer PERSONAL ACCESS TOKEN (PAT) is issued
# by the admin surface, presented at the real edge via x-api-key, and the box receives a
# signed contract with principal_kind=apikey + on_behalf_of=the creating user, bounded by
# the key's scopes — while revoked / expired / out-of-scope keys fail closed. Run against a
# compose/k8s stack with signing ENABLED (a key.pem + jwks.json mounted) and api-key auth
# configured (APIKEY_PG_RO_URL + a shared APIKEY_HMAC_PEPPER on the sidecar and authz-admin;
# the compose lab sets both). Uses the header-echo backend (traefik/whoami) so we see
# exactly what reached the box.
#
# Covers (tasks 8.1, 8.2):
#   1. Issue a key -> call through the edge -> the box receives an `apikey` contract whose
#      claims verify: principal_kind=apikey, sub=key-id, on_behalf_of=creator, workspace_id
#      = the acting workspace, exp in the future; x-user-type reaching the box is the
#      creator's relationship (staff|customer). Then REVOKE -> the next call is rejected
#      (no contract) within seconds.
#   2. Negatives, all fail closed:
#      2a. An EXPIRED key (issued with a 1s TTL) mints no contract.
#      2b. A scope OUTSIDE the creator's memberships is refused AT ISSUANCE (400).
#      2c. (manual) Creator-membership revoked mid-flight -> the key's authority is
#          withdrawn: revoke the creator's routing membership, then re-run case 1.
#
# Requires:
#   CREATOR_SUB   a ZITADEL sub that IS a live member of $WS_HEADER (so a key may be scoped
#                 to it). Seed the membership via the routing plane + membership-sync.
#   IDENTITY_ADMIN_TOKEN   the authz-admin bearer (compose default: zitadel-lab-dev-token).
#   WS_HEADER     the acting workspace the routing plane resolves for $HOST (x-workspace-id).
#   HOST          a host that routes to the header-echo box.
#   AUD/ISS       the box route-pool and the nexus issuer.
set -u

EDGE=${EDGE:-http://localhost:10000}
AUTHZ_ADMIN=${AUTHZ_ADMIN:-http://localhost:9303}   # authz-admin host mapping (compose 9303->9300)
HOST=${HOST:-localhost}
ISS=${ISS:-https://identity.nexus}
AUD=${AUD:-application}                              # the box's x-route-pool
WS_HEADER=${WS_HEADER:-ws-dev}                       # the acting workspace (x-workspace-id)
CREATOR_SUB=${CREATOR_SUB:-}                          # a live member of $WS_HEADER
ADMIN_TOKEN=${IDENTITY_ADMIN_TOKEN:-zitadel-lab-dev-token}

fail=0
ok() { if [ "$1" = 1 ]; then echo "  ok   - $2"; else echo "  FAIL - $2"; fail=1; fi; }

b64url_decode() {
  s=$1
  case $(( ${#s} % 4 )) in 2) s="${s}==";; 3) s="${s}=";; esac
  printf '%s' "$s" | tr '_-' '/+' | base64 -d 2>/dev/null
}
hdr_val() { printf '%s' "$1" | grep -i "^$2:" | head -1 | cut -d: -f2- | tr -d ' \r'; }
json_str() { printf '%s' "$1" | grep -o "\"$2\"[[:space:]]*:[[:space:]]*\"[^\"]*\"" | head -1 | sed 's/.*: *"//; s/"$//'; }

# Issue a key: $1 scopes JSON array, $2 expires_in_seconds (or empty). Echoes the raw JSON.
issue_key() {
  ttl=""
  [ -n "$2" ] && ttl=",\"expires_in_seconds\":$2"
  curl -s -X POST "$AUTHZ_ADMIN/apikeys" \
    -H "authorization: Bearer $ADMIN_TOKEN" -H 'content-type: application/json' \
    -d "{\"creator_sub\":\"$CREATOR_SUB\",\"scopes\":$1$ttl}"
}

if [ -z "$CREATOR_SUB" ]; then
  echo "SKIPPED: set CREATOR_SUB (a live member of \$WS_HEADER=$WS_HEADER). Then:"
  echo "  CREATOR_SUB=<sub> WS_HEADER=<ws> sh scripts/customer-api-keys-e2e.sh"
  exit 0
fi

echo "== 1. issue -> call -> apikey contract with on_behalf_of; revoke -> rejected =="
ISSUE=$(issue_key "[\"$WS_HEADER\"]" "")
KEY_ID=$(json_str "$ISSUE" key_id)
SECRET=$(json_str "$ISSUE" secret)
if [ -z "$SECRET" ]; then
  echo "  SKIP - issuance did not return a secret (is api-key management configured, and is"
  echo "         $CREATOR_SUB a live member of $WS_HEADER?). Response: $ISSUE"
  exit 0
fi
ok 1 "issued key $KEY_ID (secret shown once)"

BODY=$(curl -s -H "Host: $HOST" -H "x-api-key: $SECRET" "$EDGE/")
JWS=$(hdr_val "$BODY" "X-Identity-Contract")
SEGS=$(printf '%s' "$JWS" | awk -F. '{print NF}')
ok "$([ "$SEGS" = 3 ] && echo 1 || echo 0)" "x-identity-contract is a compact JWS (got $SEGS segments)"

OBO=$(hdr_val "$BODY" "X-User-On-Behalf-Of")
ok "$([ "$OBO" = "$CREATOR_SUB" ] && echo 1 || echo 0)" "x-user-on-behalf-of reaching the box = creator (got '$OBO')"
UID_H=$(hdr_val "$BODY" "X-User-Id")
ok "$([ "$UID_H" = "$KEY_ID" ] && echo 1 || echo 0)" "x-user-id reaching the box = key id (got '$UID_H')"
# The raw credential must never reach the box.
XAK=$(hdr_val "$BODY" "X-Api-Key")
ok "$([ -z "$XAK" ] && echo 1 || echo 0)" "raw x-api-key is stripped before the box (got '${XAK:-<none>}')"

PAYLOAD=$(b64url_decode "$(printf '%s' "$JWS" | cut -d. -f2)")
claim() { printf '%s' "$PAYLOAD" | grep -o "\"$1\"[[:space:]]*:[[:space:]]*\"[^\"]*\"" | head -1 | sed 's/.*: *"//; s/"$//'; }
NOW=$(date +%s)
EXP=$(printf '%s' "$PAYLOAD" | grep -o '"exp"[[:space:]]*:[[:space:]]*[0-9]*' | grep -o '[0-9]*$')
ok "$([ "$(claim principal_kind)" = "apikey" ] && echo 1 || echo 0)" "principal_kind = apikey (got '$(claim principal_kind)')"
ok "$([ "$(claim sub)" = "$KEY_ID" ] && echo 1 || echo 0)" "sub = the key id (got '$(claim sub)')"
ok "$([ "$(claim on_behalf_of)" = "$CREATOR_SUB" ] && echo 1 || echo 0)" "on_behalf_of = creator (got '$(claim on_behalf_of)')"
ok "$([ "$(claim workspace_id)" = "$WS_HEADER" ] && echo 1 || echo 0)" "workspace_id = acting ws (got '$(claim workspace_id)')"
ok "$([ "$(claim aud)" = "$AUD" ] && echo 1 || echo 0)" "aud = the box route-pool $AUD (got '$(claim aud)')"
ok "$([ "$(claim iss)" = "$ISS" ] && echo 1 || echo 0)" "iss = $ISS (got '$(claim iss)')"
ok "$([ -n "$EXP" ] && [ "$EXP" -gt "$NOW" ] && echo 1 || echo 0)" "exp is in the future (exp=$EXP now=$NOW)"

# Revoke -> the next call is rejected (no contract) within seconds (live resolve).
curl -s -X POST "$AUTHZ_ADMIN/apikeys/$KEY_ID/revoke" -H "authorization: Bearer $ADMIN_TOKEN" >/dev/null
RBODY=$(curl -s -H "Host: $HOST" -H "x-api-key: $SECRET" "$EDGE/")
RJWS=$(hdr_val "$RBODY" "X-Identity-Contract")
ok "$([ -z "$RJWS" ] && echo 1 || echo 0)" "a revoked key mints no contract (got '${RJWS:-<none>}')"

echo "== 2a. an EXPIRED key fails closed (no contract) =="
EISSUE=$(issue_key "[\"$WS_HEADER\"]" "1")
ESECRET=$(json_str "$EISSUE" secret)
if [ -n "$ESECRET" ]; then
  sleep 2
  EBODY=$(curl -s -H "Host: $HOST" -H "x-api-key: $ESECRET" "$EDGE/")
  EJWS=$(hdr_val "$EBODY" "X-Identity-Contract")
  ok "$([ -z "$EJWS" ] && echo 1 || echo 0)" "an expired key carries no x-identity-contract (got '${EJWS:-<none>}')"
else
  echo "  SKIP - could not issue a short-lived key"
fi

echo "== 2b. a scope OUTSIDE the creator's memberships is refused at issuance =="
BAD=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$AUTHZ_ADMIN/apikeys" \
  -H "authorization: Bearer $ADMIN_TOKEN" -H 'content-type: application/json' \
  -d "{\"creator_sub\":\"$CREATOR_SUB\",\"scopes\":[\"ws-not-a-member-$$\"]}")
ok "$([ "$BAD" = 400 ] && echo 1 || echo 0)" "issuing a key beyond the creator's memberships is 400 (got $BAD)"

echo "== 2c. (manual) creator-membership revoked mid-flight -> key withdrawn =="
echo "  SKIP - revoke $CREATOR_SUB's routing membership for $WS_HEADER, then re-run case 1:"
echo "         a still-valid key resolves to NO authority (no contract) within seconds."

[ "$fail" = 0 ] && echo "All customer-api-keys e2e checks passed." || echo "SOME CHECKS FAILED"
exit "$fail"
