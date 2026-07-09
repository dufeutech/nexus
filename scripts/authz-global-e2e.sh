#!/usr/bin/env sh
# Global-authorization e2e (run after `docker compose up`): proves the
# nexus-native-authorization contract end-to-end through the LIVE edge — that a
# subject's GLOBAL roles/entitlements/suspension are authored by nexus (via the
# authz-admin surface), never by the token or the IdP, resolved live, deny-by-default.
#
# The complement to tenancy-edge-auth-e2e.sh (which covers MEMBERSHIP-scoped acting
# identity). Here nothing is seeded in ZITADEL or the routing membership store beyond
# a bare authenticated user, so the role a route requires can ONLY be satisfied by a
# nexus grant — isolating global authz from workspace membership.
#
# Flow:
#   0. Health-gate ZITADEL discovery, the admin PAT, the control plane, and the
#      authz-admin surface.
#   1. Create a machine user + mint a real ZITADEL JWT (the token asserts NO roles).
#   2. Gate an ACCOUNT-SCOPED path on a required GLOBAL role via the control-plane
#      auth-routes API (account-scoped so a non-member is not existence-hidden as 404 —
#      the global-role gate is what decides, isolating global authz from membership).
#   3. Deny-by-default: the authenticated subject with NO nexus grant is refused (403),
#      even though it presents a valid token — a provider-asserted role would confer
#      nothing (spec R1/R2).
#   4. Grant the role via authz-admin -> the SAME token now passes the gate within
#      seconds, no re-auth (spec R3). The echoed x-user-roles is the nexus-authored set.
#   5. Revoke -> the route stops passing within seconds (spec R3).
#   6. Suspend -> x-user-suspended flips to true live on an enriched route (spec R3;
#      backend enforcement of the flag is the box's job, out of edge scope).
set -u

EDGE=http://localhost:10000
CP=http://localhost:9400
# authz-admin: host 9303 -> container 9300 in the lab compose (tenant-router owns
# host 9300 for its debug API, so the authoring API is mapped to a distinct port).
AUTHZ=http://localhost:9303
ZITADEL="http://localhost:${ZITADEL_EXTERNALPORT:-8080}"
HOST=localhost          # seeded + verified -> workspace `acme`
GATE=/ops-only          # the path we gate on a global role
ROLE=ops                # the nexus-authored global role the gate requires
PAT_FILE="${PAT_FILE:-./machinekey/zitadel-admin-sa.pat}"
JSON='-H content-type:application/json'
# Both admin surfaces run auth-ENABLED in the lab (production parity); default to the
# documented lab tokens.
CONTROL_AUTH_TOKEN="${CONTROL_AUTH_TOKEN:-zitadel-lab-dev-token}"
IDENTITY_ADMIN_TOKEN="${IDENTITY_ADMIN_TOKEN:-zitadel-lab-dev-token}"
# curl wrappers carrying each bearer as ONE quoted header arg (an unquoted expansion
# would word-split "Bearer <token>" and silently send an invalid header -> 401).
cpcurl() { curl -s -H "authorization: Bearer $CONTROL_AUTH_TOKEN" "$@"; }
azcurl() { curl -s -H "authorization: Bearer $IDENTITY_ADMIN_TOKEN" "$@"; }
pass=0; fail=0

ok()  { if [ "$1" = "1" ]; then echo "  PASS  $2"; pass=$((pass+1)); else echo "  FAIL  $2"; fail=$((fail+1)); fi; }
die() { echo "FATAL: $1" >&2; echo; echo "RESULT: $pass passed, $((fail+1)) failed"; exit 1; }
hdr_val() { printf '%s\n' "$1" | grep -i "^$2:" | head -n1 | sed 's/^[^:]*: *//' | tr -d '\r'; }
# GET the edge with the member token; echo the HTTP status code.
gate_code() { curl -s -o /dev/null -w '%{http_code}' -H "Host: $HOST" -H "Authorization: Bearer $TOKEN" "$EDGE$1"; }

# Top-level JSON field extractor (stdin -> value or empty): jq when present, python
# fallback so the script also runs on minimal dev shells.
if command -v jq >/dev/null 2>&1; then
  json_get() { jq -r ".$1 // empty"; }
elif command -v python >/dev/null 2>&1; then
  json_get() { python -c "import sys,json;print(json.load(sys.stdin).get('$1') or '')"; }
else
  die "jq or python is required (JSON parsing of the ZITADEL admin API)"
fi

echo "== 0. health-gate the fixtures (retry — the fixture must not be a flake source) =="
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
tries=0
until curl -sf "$AUTHZ/healthz" >/dev/null 2>&1; do
  tries=$((tries+1)); [ "$tries" -ge 30 ] && die "authz-admin not healthy at $AUTHZ"
  sleep 2
done
ok 1 "ZITADEL discovery + admin PAT + authz-admin surface all present"

echo "== 1. fixture: an authenticated machine user (the token asserts NO roles) =="
UNAME="e2e-authz-$$"
CREATE=$(curl -sf -X POST "$ZITADEL/management/v1/users/machine" \
  -H "Authorization: Bearer $PAT" $JSON \
  -d "{\"userName\":\"$UNAME\",\"name\":\"E2E Authz\",\"description\":\"authz-global-e2e fixture\",\"accessTokenType\":\"ACCESS_TOKEN_TYPE_JWT\"}") \
  || die "create machine user failed"
USER_ID=$(printf '%s' "$CREATE" | json_get userId)
[ -n "$USER_ID" ] || die "no userId in create response: $CREATE"
cleanup() {
  # Best-effort teardown: remove the ZITADEL user + the auth-route + reset the authz
  # facts we authored (there is no profile-delete; a per-run-unique inert row is fine).
  curl -sf -X DELETE "$ZITADEL/management/v1/users/$USER_ID" -H "Authorization: Bearer $PAT" >/dev/null 2>&1
  cpcurl $JSON -X DELETE "$CP/workspaces/acme/auth-routes" -d "{\"path_prefix\":\"$GATE\"}" >/dev/null 2>&1
  azcurl -X DELETE "$AUTHZ/authz/$USER_ID/roles/$ROLE" >/dev/null 2>&1
  azcurl -X POST "$AUTHZ/authz/$USER_ID/reactivate" >/dev/null 2>&1
}
trap cleanup EXIT

SECRET=$(curl -sf -X PUT "$ZITADEL/management/v1/users/$USER_ID/secret" \
  -H "Authorization: Bearer $PAT" $JSON -d '{}') || die "create user secret failed"
CLIENT_ID=$(printf '%s' "$SECRET" | json_get clientId)
CLIENT_SECRET=$(printf '%s' "$SECRET" | json_get clientSecret)
[ -n "$CLIENT_ID" ] && [ -n "$CLIENT_SECRET" ] || die "no client credentials in: $SECRET"

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

echo "== 2. gate an ACCOUNT-SCOPED route on the GLOBAL role \"$ROLE\" (control-plane auth policy) =="
# `account_scoped:true` is load-bearing here. This subject is authenticated but is NOT a
# member of workspace `acme`, and on a WORKSPACE-scoped gated route a non-member is hidden
# behind a 404 (identity-existence-hiding) BEFORE the role gate ever runs — so the test
# would poll for 403 and only ever see 404. An account-scoped route (the `/me`-style
# "reachable without a workspace membership" kind) is not membership-gated, so the GLOBAL
# role requirement is what decides — isolating global authz from membership exactly as this
# test intends (see the header comment). The role/AAL gate still applies (account_scoped
# only suppresses the existence-hiding 404, never the 403 requirement check).
GRC=$(cpcurl -o /dev/null -w '%{http_code}' $JSON -X PUT "$CP/workspaces/acme/auth-routes" \
  -d "{\"path_prefix\":\"$GATE\",\"auth_required\":true,\"requires_role\":\"$ROLE\",\"min_aal\":1,\"account_scoped\":true}")
ok "$([ "$GRC" = "200" ] && echo 1 || echo 0)" "account-scoped auth-route requiring role \"$ROLE\" configured (HTTP $GRC)"

echo "== 3. deny-by-default: authenticated but NO nexus grant -> 403 (spec R1/R2) =="
# Poll until the gate is live (the control-plane invalidation reaches the router
# within seconds); a 403 here proves BOTH "gate active" and "the valid token's
# absent role confers nothing".
DENIED=0; tries=0; LAST=""
while [ "$tries" -lt 45 ]; do
  LAST=$(gate_code "$GATE")
  if [ "$LAST" = "403" ]; then DENIED=1; break; fi
  tries=$((tries+1)); sleep 2
done
ok "$DENIED" "gated route refuses the ungranted subject with 403 (last code: ${LAST:-<none>})"

echo "== 4. grant the role via authz-admin -> the SAME token passes within seconds (spec R3) =="
GC=$(azcurl -o /dev/null -w '%{http_code}' $JSON -X PUT "$AUTHZ/authz/$USER_ID/roles" -d "{\"role\":\"$ROLE\"}")
ok "$([ "$GC" = "200" ] && echo 1 || echo 0)" "authz-admin authored the global role (HTTP $GC)"
PASSED=0; tries=0; LAST=""
while [ "$tries" -lt 45 ]; do
  LAST=$(gate_code "$GATE")
  if [ "$LAST" = "200" ]; then PASSED=1; break; fi
  tries=$((tries+1)); sleep 2
done
ok "$PASSED" "gated route now passes (200) without re-authentication (last code: ${LAST:-<none>})"

# That the gate flips 403 -> 200 on the grant (and back to 403 on revoke, step 5) is the
# proof that the nexus-authored global role is live and token-independent. The bare
# `x-user-roles` mirror that used to echo here was RETIRED by identity-revocation-
# integrity: coarse roles now ride the SIGNED x-identity-contract token's `roles` claim,
# minted only for a resolved acting identity (a member/service). This subject is
# deliberately membership-isolated, so no contract is minted and the claim is not
# surfaced here — that signed-contract surfacing path is exercised by
# tenancy-edge-auth-e2e.sh, not this decision-focused suite.

echo "== 5. revoke via authz-admin -> the route stops passing within seconds (spec R3) =="
RC=$(azcurl -o /dev/null -w '%{http_code}' -X DELETE "$AUTHZ/authz/$USER_ID/roles/$ROLE")
ok "$([ "$RC" = "200" ] && echo 1 || echo 0)" "authz-admin revoked the global role (HTTP $RC)"
REVOKED=0; tries=0; LAST=""
while [ "$tries" -lt 45 ]; do
  LAST=$(gate_code "$GATE")
  if [ "$LAST" = "403" ]; then REVOKED=1; break; fi
  tries=$((tries+1)); sleep 2
done
ok "$REVOKED" "gated route refuses again after revocation (last code: ${LAST:-<none>})"

echo "== 6. suspend via authz-admin (authoring surface; suspension rides the signed contract) =="
# authz-admin authors suspension the same way it authors roles. The bare `x-user-suspended`
# header that used to flip here was RETIRED by identity-revocation-integrity: suspension now
# rides the SIGNED x-identity-contract token's `suspended` claim (so a client cannot forge a
# "not suspended" value), minted only for a resolved acting identity and ENFORCED by the box
# (out of edge scope — the edge gate is deliberately inert on suspension). This membership-
# isolated subject establishes no acting identity, so the claim is not surfaced at the edge;
# assert the authoring succeeds — the live grant/revoke above already prove nexus-authored
# facts resolve within seconds.
SC=$(azcurl -o /dev/null -w '%{http_code}' -X POST "$AUTHZ/authz/$USER_ID/suspend")
ok "$([ "$SC" = "200" ] && echo 1 || echo 0)" "authz-admin suspended the subject (HTTP $SC)"

echo
echo "RESULT: $pass passed, $fail failed"
[ "$fail" = 0 ]
