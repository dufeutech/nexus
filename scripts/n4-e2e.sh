#!/usr/bin/env sh
# N4 Phase 1 end-to-end assertions (run after `docker compose up`).
# Proves jwt_authn branches on the x-auth-required header the tenant-router emits
# from the resolved (domain, path) policy — anonymous (no token) throughout, so a
# 200 means "passed through" and a 401 means "credential demanded".
set -u

EDGE=http://localhost:10000
CP=http://localhost:9400
HOST=localhost          # seeded + verified -> tenant `acme`
JSON='-H content-type:application/json'
# Control-plane admin auth (RFC C16): the lab control plane runs with auth
# ENABLED (production parity); default to the documented lab token from
# docker-compose.yaml, override via env for a real deployment.
CONTROL_AUTH_TOKEN="${CONTROL_AUTH_TOKEN:-zitadel-lab-dev-token}"
# curl wrapper carrying the control-plane bearer as ONE quoted header arg - an
# unquoted $CPAUTH-style expansion would word-split "Bearer <token>" into two
# args and silently send an invalid header (unauthenticated 401s).
cpcurl() { curl -s -H "authorization: Bearer $CONTROL_AUTH_TOKEN" "$@"; }

# server-minted-ids: workspace ids are SERVER-MINTED (`ws_<uuidv7>`) — resolve the
# seeded lab workspace by replaying the seed's idempotency key (the replay returns
# the ORIGINAL id, so this is a stable lookup handle, never a duplicate create).
. "$(dirname "$0")/provision-lib.sh"
nexus_resolve_lab_workspaces
pass=0; fail=0

# --path-as-is: curl must NOT resolve dot segments client-side — the encoded
# traversal assertions below exist to prove the EDGE normalizes before the gate.
code() { curl -s --path-as-is -o /dev/null -w '%{http_code}' -H "Host: $HOST" "$EDGE$1"; }
expect() { # <path> <want> <label>
  c=$(code "$1")
  if [ "$c" = "$2" ]; then echo "  PASS  $3 ($1 -> $c)"; pass=$((pass+1));
  else echo "  FAIL  $3 ($1 -> $c, want $2)"; fail=$((fail+1)); fi
}
settle() { sleep 2; }  # let the invalidation NOTIFY evict the router's cache

echo "== reset: clear any policy from a prior run =="
cpcurl $JSON -X DELETE "$CP/workspaces/$ACME_WS/auth-routes" -d '{"path_prefix":"/"}'    >/dev/null
cpcurl $JSON -X DELETE "$CP/workspaces/$ACME_WS/auth-routes" -d '{"path_prefix":"/blog"}' >/dev/null
settle

echo "== 1. no policy => public by default (anonymous pass-through) =="
expect "/"    200 "anon / is public"
expect "/app" 200 "anon /app is public"

echo "== 2. PUT {/, required} => whole site demands a credential =="
cpcurl $JSON -X PUT "$CP/workspaces/$ACME_WS/auth-routes" -d '{"path_prefix":"/","auth_required":true}' >/dev/null
settle
expect "/"    401 "anon / now 401"
expect "/app" 401 "anon /app now 401"

# edge-auth-gate R4: a CLIENT-set x-auth-required must never forge the gate —
# the C3 strip runs before the tenant-router re-emits the authoritative value,
# so self-declaring the route public must still 401.
FORGED=$(curl -s --path-as-is -o /dev/null -w '%{http_code}' -H "Host: $HOST" -H "x-auth-required: false" "$EDGE/")
if [ "$FORGED" = "401" ]; then echo "  PASS  client-forged x-auth-required cannot open a private route (-> $FORGED)"; pass=$((pass+1));
else echo "  FAIL  client-forged x-auth-required opened a private route (-> $FORGED, want 401)"; fail=$((fail+1)); fi

echo "== 3. PUT {/blog, public} => carve a public path out of a private site =="
cpcurl $JSON -X PUT "$CP/workspaces/$ACME_WS/auth-routes" -d '{"path_prefix":"/blog","auth_required":false}' >/dev/null
settle
expect "/blog"        200 "anon /blog is public (override)"
expect "/blog/post-1" 200 "anon /blog subtree is public"
expect "/app"         401 "anon /app still private (default)"
expect "/"            401 "anon / still private (default)"

# edge-auth-gate R2: public means a MISSING credential passes — a PRESENT but
# invalid credential must still be rejected (allow_missing, never
# allow_missing_or_failed). A garbage bearer on the public path must 401.
BADTOK=$(curl -s --path-as-is -o /dev/null -w '%{http_code}' -H "Host: $HOST" -H "Authorization: Bearer not.a.validjwt" "$EDGE/blog")
if [ "$BADTOK" = "401" ]; then echo "  PASS  invalid credential on a PUBLIC route is still rejected (-> $BADTOK)"; pass=$((pass+1));
else echo "  FAIL  invalid credential on a public route was accepted (-> $BADTOK, want 401)"; fail=$((fail+1)); fi

echo "== 4. encoded path traversal does NOT downgrade a protected route to public =="
# edge-auth-gate R5: the edge canonicalizes :path (normalize_path + merge_slashes
# + UNESCAPE_AND_FORWARD) BEFORE the gate reads it, so a path spelled to look like
# the public /blog prefix but resolving into the private subtree must still 401 —
# the gate and the backend can never see two different routes.
expect "/blog%2f..%2fapp"   401 "encoded %2f traversal (/blog%2f..%2fapp) stays private"
expect "/blog/../app"       401 "dot-segment traversal (/blog/../app) stays private"
expect "/blog/..%2fapp"     401 "mixed traversal (/blog/..%2fapp) stays private"
expect "/blog/%2e%2e/app"   401 "encoded-dot traversal (/blog/%2e%2e/app) stays private"

echo "== 5. phase 2 (edge-role-entitlement-gate): requirement fields =="
# Spec "Inconsistent rule is rejected at write time": a requirement with
# auth_required=false must 400 and store nothing.
BADRULE=$(cpcurl $JSON -o /dev/null -w '%{http_code}' -X PUT "$CP/workspaces/$ACME_WS/auth-routes" \
  -d '{"path_prefix":"/members","auth_required":false,"requires_entitlement":"pro"}')
if [ "$BADRULE" = "400" ]; then echo "  PASS  requirement + auth_required=false is rejected (-> $BADRULE)"; pass=$((pass+1));
else echo "  FAIL  inconsistent rule accepted (-> $BADRULE, want 400)"; fail=$((fail+1)); fi

# Spec "Anonymous caller gets 401, not 403": a valid gated rule (role-required)
# demands a credential first — anonymous sees the AUTHENTICATION outcome, and the
# authorization policy is never disclosed. (The authenticated 403 leg needs a
# real token; covered by sidecar unit tests.)
cpcurl $JSON -X PUT "$CP/workspaces/$ACME_WS/auth-routes" \
  -d '{"path_prefix":"/members","auth_required":true,"requires_role":"admin","min_aal":1}' >/dev/null
settle
expect "/members"      401 "anon gated route -> 401 (never 403)"
expect "/members/area" 401 "anon gated subtree -> 401"
# The site-wide {/, required} rule from step 2 is still active here, so the
# public /blog carve-out is the "unaffected" probe (/ itself is legitimately 401).
expect "/blog"         200 "public carve-out unaffected by the gated rule"

# The requirement fields round-trip through the CRUD list surface.
SNAP=$(cpcurl "$CP/workspaces/$ACME_WS/auth-routes")
case "$SNAP" in
  *'"requires_role":"admin"'*) echo "  PASS  list surface returns the requirement fields"; pass=$((pass+1));;
  *) echo "  FAIL  requirement fields missing from list surface: $SNAP"; fail=$((fail+1));;
esac
cpcurl $JSON -X DELETE "$CP/workspaces/$ACME_WS/auth-routes" -d '{"path_prefix":"/members"}' >/dev/null

echo "== policy snapshot =="
cpcurl "$CP/workspaces/$ACME_WS/auth-routes"; echo

echo "== cleanup =="
cpcurl $JSON -X DELETE "$CP/workspaces/$ACME_WS/auth-routes" -d '{"path_prefix":"/"}'    >/dev/null
cpcurl $JSON -X DELETE "$CP/workspaces/$ACME_WS/auth-routes" -d '{"path_prefix":"/blog"}' >/dev/null

echo
echo "RESULT: $pass passed, $fail failed"
[ "$fail" = 0 ]
