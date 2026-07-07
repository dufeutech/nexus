#!/usr/bin/env sh
# Authenticated-member POSITIVE e2e (run after `docker compose up`): the other
# half of scripts/tenancy-edge-e2e.sh. Proves that a REAL ZITADEL-minted JWT plus
# a seeded membership yields the AUTHORITATIVE acting scope at the backend —
# emitted `x-workspace-id`/`x-user-type`/`x-user-role` equal the resolved
# workspace and the seeded membership, sourced from the live membership check.
#
# Fixture (identity-workspace-authz / design 5.1 — health-gated + retried so the
# IdP is not a flake source):
#   1. Wait for ZITADEL's OIDC discovery (proves the issuer serves AND that the
#      D7 single-source issuer is live) and for the admin PAT file the lab mounts.
#   2. Create a machine user with a JWT access-token type + a client secret,
#      then mint a client_credentials access token (a ZITADEL-signed JWT).
#   3. Seed a staff/admin membership for that user in workspace `acme` via the
#      control plane; membership-sync projects it into the identity Profile
#      (NOTIFY within seconds; 30s backstop in the lab heals a missed signal).
#   4. Assert the whoami echo shows the authoritative scope headers.
set -u

EDGE=http://localhost:10000
CP=http://localhost:9400
ZITADEL="http://localhost:${ZITADEL_EXTERNALPORT:-8080}"
HOST=localhost          # seeded + verified -> workspace `acme`
PAT_FILE="${PAT_FILE:-./machinekey/zitadel-admin-sa.pat}"
JSON='-H content-type:application/json'
# Control-plane admin auth (RFC C16): the lab control plane runs with auth
# ENABLED (production parity); default to the documented lab token.
CONTROL_AUTH_TOKEN="${CONTROL_AUTH_TOKEN:-zitadel-lab-dev-token}"
# curl wrapper carrying the control-plane bearer as ONE quoted header arg - an
# unquoted $CPAUTH-style expansion would word-split "Bearer <token>" into two
# args and silently send an invalid header (unauthenticated 401s).
cpcurl() { curl -s -H "authorization: Bearer $CONTROL_AUTH_TOKEN" "$@"; }
pass=0; fail=0

ok()  { if [ "$1" = "1" ]; then echo "  PASS  $2"; pass=$((pass+1)); else echo "  FAIL  $2"; fail=$((fail+1)); fi; }
die() { echo "FATAL: $1" >&2; echo; echo "RESULT: $pass passed, $((fail+1)) failed"; exit 1; }
hdr_val() { printf '%s\n' "$1" | grep -i "^$2:" | head -n1 | sed 's/^[^:]*: *//' | tr -d '\r'; }

# Top-level JSON field extractor (stdin -> value or empty): jq when present,
# python fallback so the script also runs on minimal dev shells.
if command -v jq >/dev/null 2>&1; then
  json_get() { jq -r ".$1 // empty"; }
elif command -v python >/dev/null 2>&1; then
  json_get() { python -c "import sys,json;print(json.load(sys.stdin).get('$1') or '')"; }
else
  die "jq or python is required (JSON parsing of the ZITADEL admin API)"
fi

echo "== 0. health-gate the IdP (retry — the fixture must not be a flake source) =="
tries=0
until curl -sf "$ZITADEL/.well-known/openid-configuration" >/dev/null 2>&1; do
  tries=$((tries+1)); [ "$tries" -ge 60 ] && die "ZITADEL discovery not serving after 120s ($ZITADEL)"
  sleep 2
done
tries=0
until [ -s "$PAT_FILE" ]; do
  tries=$((tries+1)); [ "$tries" -ge 30 ] && die "admin PAT not found at $PAT_FILE"
  sleep 2
done
PAT=$(tr -d '\r\n' < "$PAT_FILE")
ok 1 "ZITADEL serving discovery + admin PAT present"

echo "== 1. fixture: machine user with a JWT access token =="
# Unique per run so reruns never collide; deleted in cleanup.
UNAME="e2e-member-$$"
CREATE=$(curl -sf -X POST "$ZITADEL/management/v1/users/machine" \
  -H "Authorization: Bearer $PAT" $JSON \
  -d "{\"userName\":\"$UNAME\",\"name\":\"E2E Member\",\"description\":\"tenancy-edge-auth-e2e fixture\",\"accessTokenType\":\"ACCESS_TOKEN_TYPE_JWT\"}") \
  || die "create machine user failed"
USER_ID=$(printf '%s' "$CREATE" | json_get userId)
[ -n "$USER_ID" ] || die "no userId in create response: $CREATE"
cleanup() {
  curl -sf -X DELETE "$ZITADEL/management/v1/users/$USER_ID" -H "Authorization: Bearer $PAT" >/dev/null 2>&1
  cpcurl $JSON -X DELETE "$CP/workspaces/acme/members/$USER_ID" >/dev/null 2>&1
}
trap cleanup EXIT

SECRET=$(curl -sf -X PUT "$ZITADEL/management/v1/users/$USER_ID/secret" \
  -H "Authorization: Bearer $PAT" $JSON -d '{}') || die "create user secret failed"
CLIENT_ID=$(printf '%s' "$SECRET" | json_get clientId)
CLIENT_SECRET=$(printf '%s' "$SECRET" | json_get clientSecret)
[ -n "$CLIENT_ID" ] && [ -n "$CLIENT_SECRET" ] || die "no client credentials in: $SECRET"

# Retry the token mint too (the OIDC layer can lag user creation by a beat).
TOKEN=""; tries=0
while [ -z "$TOKEN" ]; do
  TOKEN=$(curl -sf -X POST "$ZITADEL/oauth/v2/token" -u "$CLIENT_ID:$CLIENT_SECRET" \
    -d "grant_type=client_credentials&scope=openid" | json_get access_token)
  [ -n "$TOKEN" ] && break
  tries=$((tries+1)); [ "$tries" -ge 15 ] && die "could not mint a client_credentials token"
  sleep 2
done
DOTS=$(printf '%s' "$TOKEN" | tr -cd '.' | wc -c | tr -d ' ')
ok "$([ "$DOTS" = "2" ] && echo 1 || echo 0)" "minted access token is a JWT (header.payload.signature)"

echo "== 2. fixture: seed the membership (staff/admin in workspace acme) =="
SEED=$(cpcurl -o /dev/null -w '%{http_code}' $JSON -X PUT "$CP/workspaces/acme/members" \
  -d "{\"user_sub\":\"$USER_ID\",\"member_type\":\"staff\",\"role\":\"admin\"}")
ok "$([ "$SEED" = "200" ] || [ "$SEED" = "201" ] || [ "$SEED" = "204" ] && echo 1 || echo 0)" \
  "membership seeded via control plane (HTTP $SEED)"

echo "== 3. the member's request carries the AUTHORITATIVE acting scope =="
# Retry until the projection lands (NOTIFY is seconds; the 30s lab backstop is
# the ceiling) — polling here is the health-gate, not a fixed sleep.
BODY=""; tries=0
while :; do
  BODY=$(curl -s -H "Host: $HOST" -H "Authorization: Bearer $TOKEN" "$EDGE/")
  WS=$(hdr_val "$BODY" "X-Workspace-Id")
  [ "$WS" = "acme" ] && break
  tries=$((tries+1)); [ "$tries" -ge 45 ] && break   # ~90s ceiling
  sleep 2
done

CODE=$(curl -s -o /dev/null -w '%{http_code}' -H "Host: $HOST" -H "Authorization: Bearer $TOKEN" "$EDGE/")
ok "$([ "$CODE" = "200" ] && echo 1 || echo 0)" "authenticated member request -> 200 (got $CODE)"

# identity-contract-signing: x-identity-contract is a SIGNED token (no plain-string `v1`),
# minted only for a resolved member when signing is configured. This suite runs with
# signing ENABLED (CI mounts a test key), so the member carries a verifiable JWS; it stays
# correct with signing off too (no contract at all — the legacy `v1` is gone).
b64url_decode() { s=$1; case $(( ${#s} % 4 )) in 2) s="${s}==";; 3) s="${s}=";; esac; printf '%s' "$s" | tr '_-' '/+' | base64 -d 2>/dev/null; }
V=$(hdr_val "$BODY" "X-Identity-Contract")
if [ -n "$V" ]; then
  SEGS=$(printf '%s' "$V" | awk -F. '{print NF}')
  ok "$([ "$SEGS" = 3 ] && echo 1 || echo 0)" "member x-identity-contract is a signed JWS (got $SEGS segments)"
  PAYLOAD=$(b64url_decode "$(printf '%s' "$V" | cut -d. -f2)")
  ok "$(printf '%s' "$PAYLOAD" | grep -q '"workspace_id":"acme"' && echo 1 || echo 0)" "signed contract carries workspace_id=acme"
  JWKS=$(curl -s --max-time 5 http://localhost:9210/.well-known/jwks.json)
  ok "$(printf '%s' "$JWKS" | grep -q '\"kty\"' && echo 1 || echo 0)" "JWKS endpoint publishes the verification keys"
else
  ok 1 "signing disabled -> no plain contract (legacy v1 removed)"
fi

ANON=$(hdr_val "$BODY" "X-Auth-Anonymous")
ok "$([ "$ANON" = "false" ] && echo 1 || echo 0)" "x-auth-anonymous is false (got '${ANON:-<none>}')"

UID_H=$(hdr_val "$BODY" "X-User-Id")
ok "$([ "$UID_H" = "$USER_ID" ] && echo 1 || echo 0)" "x-user-id equals the token subject (got '${UID_H:-<none>}')"

WS=$(hdr_val "$BODY" "X-Workspace-Id")
ok "$([ "$WS" = "acme" ] && echo 1 || echo 0)" "x-workspace-id equals the RESOLVED workspace (got '${WS:-<none>}')"

UT=$(hdr_val "$BODY" "X-User-Type")
ok "$([ "$UT" = "staff" ] && echo 1 || echo 0)" "x-user-type equals the seeded membership type (got '${UT:-<none>}')"

UR=$(hdr_val "$BODY" "X-User-Role")
ok "$([ "$UR" = "admin" ] && echo 1 || echo 0)" "x-user-role equals the seeded membership role (got '${UR:-<none>}')"

echo "== 4. the scope is MEMBERSHIP-derived, not token-derived: revoke and it disappears =="
cpcurl $JSON -X DELETE "$CP/workspaces/acme/members/$USER_ID" >/dev/null 2>&1
REVOKED=0; tries=0
while [ "$tries" -lt 45 ]; do
  BODY2=$(curl -s -H "Host: $HOST" -H "Authorization: Bearer $TOKEN" "$EDGE/")
  WS2=$(hdr_val "$BODY2" "X-Workspace-Id")
  if [ "$WS2" != "acme" ]; then REVOKED=1; break; fi
  tries=$((tries+1)); sleep 2
done
ok "$REVOKED" "after revocation the acting workspace scope is no longer emitted"

echo
echo "RESULT: $pass passed, $fail failed"
[ "$fail" = 0 ]
