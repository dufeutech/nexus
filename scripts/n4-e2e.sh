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
# Control-plane admin auth (RFC C16): send the bearer token when CONTROL_AUTH_TOKEN
# is exported (matches the deploy default). Leave unset only against an instance
# started with CONTROL_AUTH_DISABLED=true.
CPAUTH=""
[ -n "${CONTROL_AUTH_TOKEN:-}" ] && CPAUTH="-H Authorization:Bearer ${CONTROL_AUTH_TOKEN}"
pass=0; fail=0

code() { curl -s -o /dev/null -w '%{http_code}' -H "Host: $HOST" "$EDGE$1"; }
expect() { # <path> <want> <label>
  c=$(code "$1")
  if [ "$c" = "$2" ]; then echo "  PASS  $3 ($1 -> $c)"; pass=$((pass+1));
  else echo "  FAIL  $3 ($1 -> $c, want $2)"; fail=$((fail+1)); fi
}
settle() { sleep 2; }  # let the invalidation NOTIFY evict the router's cache

echo "== reset: clear any policy from a prior run =="
curl -s $JSON $CPAUTH -X DELETE "$CP/tenants/acme/auth-routes" -d '{"path_prefix":"/"}'    >/dev/null
curl -s $JSON $CPAUTH -X DELETE "$CP/tenants/acme/auth-routes" -d '{"path_prefix":"/blog"}' >/dev/null
settle

echo "== 1. no policy => public by default (anonymous pass-through) =="
expect "/"    200 "anon / is public"
expect "/app" 200 "anon /app is public"

echo "== 2. PUT {/, required} => whole site demands a credential =="
curl -s $JSON $CPAUTH -X PUT "$CP/tenants/acme/auth-routes" -d '{"path_prefix":"/","auth_required":true}' >/dev/null
settle
expect "/"    401 "anon / now 401"
expect "/app" 401 "anon /app now 401"

echo "== 3. PUT {/blog, public} => carve a public path out of a private site =="
curl -s $JSON $CPAUTH -X PUT "$CP/tenants/acme/auth-routes" -d '{"path_prefix":"/blog","auth_required":false}' >/dev/null
settle
expect "/blog"        200 "anon /blog is public (override)"
expect "/blog/post-1" 200 "anon /blog subtree is public"
expect "/app"         401 "anon /app still private (default)"
expect "/"            401 "anon / still private (default)"

echo "== policy snapshot =="
curl -s $CPAUTH "$CP/tenants/acme/auth-routes"; echo

echo "== cleanup =="
curl -s $JSON $CPAUTH -X DELETE "$CP/tenants/acme/auth-routes" -d '{"path_prefix":"/"}'    >/dev/null
curl -s $JSON $CPAUTH -X DELETE "$CP/tenants/acme/auth-routes" -d '{"path_prefix":"/blog"}' >/dev/null

echo
echo "RESULT: $pass passed, $fail failed"
[ "$fail" = 0 ]
