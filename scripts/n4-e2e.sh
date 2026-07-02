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
cpcurl $JSON -X DELETE "$CP/tenants/acme/auth-routes" -d '{"path_prefix":"/"}'    >/dev/null
cpcurl $JSON -X DELETE "$CP/tenants/acme/auth-routes" -d '{"path_prefix":"/blog"}' >/dev/null
settle

echo "== 1. no policy => public by default (anonymous pass-through) =="
expect "/"    200 "anon / is public"
expect "/app" 200 "anon /app is public"

echo "== 2. PUT {/, required} => whole site demands a credential =="
cpcurl $JSON -X PUT "$CP/tenants/acme/auth-routes" -d '{"path_prefix":"/","auth_required":true}' >/dev/null
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
cpcurl $JSON -X PUT "$CP/tenants/acme/auth-routes" -d '{"path_prefix":"/blog","auth_required":false}' >/dev/null
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

echo "== policy snapshot =="
cpcurl "$CP/tenants/acme/auth-routes"; echo

echo "== cleanup =="
cpcurl $JSON -X DELETE "$CP/tenants/acme/auth-routes" -d '{"path_prefix":"/"}'    >/dev/null
cpcurl $JSON -X DELETE "$CP/tenants/acme/auth-routes" -d '{"path_prefix":"/blog"}' >/dev/null

echo
echo "RESULT: $pass passed, $fail failed"
[ "$fail" = 0 ]
