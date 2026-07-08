#!/usr/bin/env sh
# identity-existence-hiding end-to-end (run after `docker compose up`). Proves the
# authenticated 404-vs-403 behavior the sidecar unit tests assert, but through the
# REAL edge → tenant-router → identity-sidecar chain with ZITADEL-minted JWTs:
#
#   * a NON-member of the routed workspace on a private, workspace-scoped route is
#     hidden behind a 404 (indistinguishable from a nonexistent workspace),
#   * a MEMBER on the same route is admitted (200) — never hidden,
#   * an account-scoped private route (e.g. /me) is reachable by a non-member
#     (the membership gate is bypassed),
#   * an unknown host and the non-member 404 share the SAME minimal "not found"
#     body (uniform not-found envelope), and
#   * the account_scoped flag round-trips through the control-plane CRUD surface.
#
# Fixture reuses tenancy-edge-auth-e2e.sh's ZITADEL machine-user + membership seed.
set -u

EDGE=http://localhost:10000
CP=http://localhost:9400
ZITADEL="http://localhost:${ZITADEL_EXTERNALPORT:-8080}"
HOST=localhost                       # seeded + verified -> workspace `acme`
PAT_FILE="${PAT_FILE:-./machinekey/zitadel-admin-sa.pat}"
JSON='-H content-type:application/json'
CONTROL_AUTH_TOKEN="${CONTROL_AUTH_TOKEN:-zitadel-lab-dev-token}"
cpcurl() { curl -s -H "authorization: Bearer $CONTROL_AUTH_TOKEN" "$@"; }
pass=0; fail=0
ok()  { if [ "$1" = "1" ]; then echo "  PASS  $2"; pass=$((pass+1)); else echo "  FAIL  $2"; fail=$((fail+1)); fi; }
die() { echo "FATAL: $1" >&2; echo; echo "RESULT: $pass passed, $((fail+1)) failed"; exit 1; }
settle() { sleep 2; }

# Prefer jq, but only if it actually RUNS (a present-but-non-executable jq — e.g. a
# permission-blocked Windows shim — must fall through to python, not silently fail).
if command -v jq >/dev/null 2>&1 && printf '{}' | jq . >/dev/null 2>&1; then
  json_get() { jq -r ".$1 // empty"; }
elif command -v python >/dev/null 2>&1; then
  json_get() { python -c "import sys,json;print(json.load(sys.stdin).get('$1') or '')"; }
else die "jq or python required"; fi

# code <path> <token|""> [host] -> HTTP status of an edge request.
code() {
  _h="${3:-$HOST}"; _t="$2"
  if [ -n "$_t" ]; then
    curl -s --path-as-is -o /dev/null -w '%{http_code}' -H "Host: $_h" -H "Authorization: Bearer $_t" "$EDGE$1"
  else
    curl -s --path-as-is -o /dev/null -w '%{http_code}' -H "Host: $_h" "$EDGE$1"
  fi
}
body() { curl -s --path-as-is -H "Host: ${3:-$HOST}" ${2:+-H "Authorization: Bearer $2"} "$EDGE$1"; }

echo "== 0. health-gate the IdP + admin PAT =="
tries=0
until curl -sf "$ZITADEL/.well-known/openid-configuration" >/dev/null 2>&1; do
  tries=$((tries+1)); [ "$tries" -ge 60 ] && die "ZITADEL discovery not serving"; sleep 2
done
tries=0; until [ -s "$PAT_FILE" ]; do tries=$((tries+1)); [ "$tries" -ge 30 ] && die "admin PAT not found"; sleep 2; done
PAT=$(tr -d '\r\n' < "$PAT_FILE")
ok 1 "ZITADEL serving + admin PAT present"

# mint_token <username> -> sets USER_ID + TOKEN globals (a real ZITADEL JWT).
mint_token() {
  _u="$1"
  _c=$(curl -sf -X POST "$ZITADEL/management/v1/users/machine" -H "Authorization: Bearer $PAT" $JSON \
    -d "{\"userName\":\"$_u\",\"name\":\"$_u\",\"accessTokenType\":\"ACCESS_TOKEN_TYPE_JWT\"}") || die "create $_u failed"
  USER_ID=$(printf '%s' "$_c" | json_get userId); [ -n "$USER_ID" ] || die "no userId: $_c"
  _s=$(curl -sf -X PUT "$ZITADEL/management/v1/users/$USER_ID/secret" -H "Authorization: Bearer $PAT" $JSON -d '{}') || die "secret failed"
  _cid=$(printf '%s' "$_s" | json_get clientId); _cs=$(printf '%s' "$_s" | json_get clientSecret)
  TOKEN=""; tries=0
  while [ -z "$TOKEN" ]; do
    TOKEN=$(curl -sf -X POST "$ZITADEL/oauth/v2/token" -u "$_cid:$_cs" -d "grant_type=client_credentials&scope=openid" | json_get access_token)
    [ -n "$TOKEN" ] && break; tries=$((tries+1)); [ "$tries" -ge 15 ] && die "token mint failed for $_u"; sleep 2
  done
}

echo "== 1. fixture: a MEMBER and an OUTSIDER, both real ZITADEL JWTs =="
mint_token "e2e-member-$$";   MEMBER_ID=$USER_ID;   MEMBER_TOKEN=$TOKEN
mint_token "e2e-outsider-$$"; OUTSIDER_ID=$USER_ID; OUTSIDER_TOKEN=$TOKEN
cleanup() {
  for u in "$MEMBER_ID" "$OUTSIDER_ID"; do
    curl -sf -X DELETE "$ZITADEL/management/v1/users/$u" -H "Authorization: Bearer $PAT" >/dev/null 2>&1
    cpcurl $JSON -X DELETE "$CP/workspaces/acme/members/$u" >/dev/null 2>&1
  done
  cpcurl $JSON -X DELETE "$CP/tenants/acme/auth-routes" -d '{"path_prefix":"/app"}' >/dev/null 2>&1
  cpcurl $JSON -X DELETE "$CP/tenants/acme/auth-routes" -d '{"path_prefix":"/me"}'  >/dev/null 2>&1
}
trap cleanup EXIT
ok 1 "minted member ($MEMBER_ID) and outsider ($OUTSIDER_ID) tokens"

echo "== 2. seed the member's membership (staff/admin in acme); leave the outsider out =="
SEED=$(cpcurl -o /dev/null -w '%{http_code}' $JSON -X PUT "$CP/workspaces/acme/members" \
  -d "{\"user_sub\":\"$MEMBER_ID\",\"member_type\":\"staff\",\"role\":\"admin\"}")
ok "$([ "$SEED" = 200 ] || [ "$SEED" = 201 ] || [ "$SEED" = 204 ] && echo 1 || echo 0)" "member seeded (HTTP $SEED)"

echo "== 3. mark /app private+workspace-scoped, /me private+account-scoped =="
cpcurl $JSON -X PUT "$CP/tenants/acme/auth-routes" -d '{"path_prefix":"/app","auth_required":true}' >/dev/null
cpcurl $JSON -X PUT "$CP/tenants/acme/auth-routes" -d '{"path_prefix":"/me","auth_required":true,"account_scoped":true}' >/dev/null
settle
# account_scoped round-trips through the CRUD list surface.
SNAP=$(cpcurl "$CP/tenants/acme/auth-routes")
case "$SNAP" in *'"account_scoped":true'*) ok 1 "account_scoped round-trips through CRUD list";; *) ok 0 "account_scoped missing from CRUD: $SNAP";; esac

echo "== 4. the core gate: non-member is HIDDEN (404), member is ADMITTED =="
# Poll until the member projection lands (NOTIFY within seconds; lab backstop 30s).
tries=0; while [ "$(code /app "$MEMBER_TOKEN")" != 200 ] && [ "$tries" -lt 45 ]; do tries=$((tries+1)); sleep 2; done
ok "$([ "$(code /app "$MEMBER_TOKEN")" = 200 ] && echo 1 || echo 0)" "MEMBER on private /app -> 200 (admitted, not hidden)"
ok "$([ "$(code /app "$OUTSIDER_TOKEN")" = 404 ] && echo 1 || echo 0)" "OUTSIDER on private /app -> 404 (existence hidden, not 403)"

echo "== 5. account-scoped route bypasses the membership gate =="
CME=$(code /me "$OUTSIDER_TOKEN")
ok "$([ "$CME" != 404 ] && echo 1 || echo 0)" "OUTSIDER on account-scoped /me -> not 404 (got $CME)"

echo "== 6. uniform not-found envelope: non-member 404 == unknown-host 404 (same body) =="
NM_BODY=$(body /app "$OUTSIDER_TOKEN")
UH_BODY=$(body / "" "no-such-tenant.invalid")
UH_CODE=$(code / "" "no-such-tenant.invalid")
ok "$([ "$UH_CODE" = 404 ] && echo 1 || echo 0)" "unknown host -> 404 (got $UH_CODE)"
ok "$([ "$NM_BODY" = "$UH_BODY" ] && echo 1 || echo 0)" "non-member body == unknown-host body ('$NM_BODY' vs '$UH_BODY')"

echo "== 7. public route is NOT gated (no regression to public surfaces) =="
ok "$([ "$(code / "$OUTSIDER_TOKEN")" = 200 ] && echo 1 || echo 0)" "OUTSIDER on public / -> 200 (public default unaffected)"

echo
echo "RESULT: $pass passed, $fail failed"
[ "$fail" = 0 ]
