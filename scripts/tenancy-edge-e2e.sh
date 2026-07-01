#!/usr/bin/env sh
# nexus-owned-workspace-tenancy end-to-end edge assertions (run after
# `docker compose up`). Proves the edge's identity-header trust contract at the
# real Envoy filter chain, using the `traefik/whoami` backend, which ECHOES the
# request headers it received back in its response body — so we can see exactly
# what reached the backend.
#
# What this covers (checkable WITHOUT a token, on the anonymous path):
#   1. Contract stamp: an enriched request carries `x-identity-contract: v1`
#      (authored by the identity sidecar on every enriched request, task 4.3).
#   2. Unforgeable stamp: a CLIENT-supplied `x-identity-contract` is stripped at
#      the edge (C3) — the backend never sees the forged version.
#   3. Unforgeable acting scope: client-supplied `x-workspace-id`/`x-user-type`/
#      `x-user-role` on a NON-member (anonymous) request are stripped — no forged
#      authoritative scope reaches the backend.
#   4. Non-member fail-closed on a PROTECTED route: with an auth-route requiring a
#      credential, the anonymous request is rejected (401) before the backend
#      (the non-member policy derived from the route auth policy, design 0.2).
#
# NOT covered here (requires the full identity stack — a real ZITADEL-minted JWT
# plus a seeded membership Profile): the POSITIVE member path, where a member's
# request yields an AUTHORITATIVE `x-workspace-id`+`x-user-type`+`x-user-role`
# sourced from the live membership check. Procedure for that live run is in the
# change's design.md (Migration / cut-over) — it layers a bearer token onto the
# same assertions below and additionally checks the emitted scope equals the
# resolved workspace. The backend's rejection of an ABSENT stamp (a request that
# bypassed the edge) is the consuming box's contract, not nexus's to emit.
set -u

EDGE=http://localhost:10000
CP=http://localhost:9400
HOST=localhost          # seeded + verified -> workspace `acme` (public by default)
JSON='-H content-type:application/json'
CPAUTH=""
[ -n "${CONTROL_AUTH_TOKEN:-}" ] && CPAUTH="-H Authorization:Bearer ${CONTROL_AUTH_TOKEN}"
pass=0; fail=0

# Fetch the whoami echo body for a request carrying the given extra `-H` args.
echo_body() { curl -s -H "Host: $HOST" "$@" "$EDGE/"; }
# Case-insensitive grep of one echoed header line from a whoami body.
has_hdr() { printf '%s\n' "$1" | grep -iq "^$2:"; }
hdr_val() { printf '%s\n' "$1" | grep -i "^$2:" | head -n1 | sed 's/^[^:]*: *//' | tr -d '\r'; }
code() { curl -s -o /dev/null -w '%{http_code}' -H "Host: $HOST" "$@" "$EDGE/"; }
ok()   { if [ "$1" = "1" ]; then echo "  PASS  $2"; pass=$((pass+1)); else echo "  FAIL  $2"; fail=$((fail+1)); fi; }
settle() { sleep 2; }   # let an invalidation NOTIFY evict the router's cache

echo "== reset: ensure the site is public (no auth-route) =="
curl -s $JSON $CPAUTH -X DELETE "$CP/workspaces/acme/auth-routes" -d '{"path_prefix":"/"}' >/dev/null 2>&1 \
  || curl -s $JSON $CPAUTH -X DELETE "$CP/tenants/acme/auth-routes" -d '{"path_prefix":"/"}' >/dev/null 2>&1
settle

echo "== 1. enriched anonymous request carries the contract stamp, forged copies stripped =="
BODY=$(echo_body \
  -H "x-identity-contract: vFORGED" \
  -H "x-workspace-id: ws_forged" \
  -H "x-user-type: staff" \
  -H "x-user-role: admin")

# The sidecar stamps v1 on every enriched request...
V=$(hdr_val "$BODY" "X-Identity-Contract")
ok "$([ "$V" = "v1" ] && echo 1 || echo 0)" "contract stamp is v1 at the backend (got '${V:-<none>}')"

# ...and the client's forged stamp never survives (it is stripped, then re-authored
# to v1 above — so the value is v1, never vFORGED).
ok "$([ "$V" != "vFORGED" ] && echo 1 || echo 0)" "client-forged x-identity-contract is stripped"

# A non-member (anonymous) may not assert an acting scope: the forged workspace/
# type/role must NOT reach the backend as the client's values.
WS=$(hdr_val "$BODY" "X-Workspace-Id")
UT=$(hdr_val "$BODY" "X-User-Type")
UR=$(hdr_val "$BODY" "X-User-Role")
ok "$([ "$WS" != "ws_forged" ] && echo 1 || echo 0)" "forged x-workspace-id stripped (got '${WS:-<none>}')"
ok "$([ "$UT" != "staff" ] && echo 1 || echo 0)" "forged x-user-type stripped (got '${UT:-<none>}')"
ok "$([ "$UR" != "admin" ] && echo 1 || echo 0)" "forged x-user-role stripped (got '${UR:-<none>}')"

# The enrichment definitely ran (proves the stamp isn't just a pass-through).
ok "$(has_hdr "$BODY" "X-Auth-Anonymous" && echo 1 || echo 0)" "enrichment ran (x-auth-anonymous present)"

echo "== 2. public route: the anonymous request passes through (200) =="
ok "$([ "$(code)" = "200" ] && echo 1 || echo 0)" "anonymous / is public -> 200"

echo "== 3. protected route: a non-member (anonymous) is fail-closed BEFORE the backend =="
curl -s $JSON $CPAUTH -X PUT "$CP/workspaces/acme/auth-routes" -d '{"path_prefix":"/","auth_required":true}' >/dev/null 2>&1 \
  || curl -s $JSON $CPAUTH -X PUT "$CP/tenants/acme/auth-routes" -d '{"path_prefix":"/","auth_required":true}' >/dev/null 2>&1
settle
ok "$([ "$(code)" = "401" ] && echo 1 || echo 0)" "anonymous non-member on a protected route -> 401 (fail-closed)"

echo "== cleanup =="
curl -s $JSON $CPAUTH -X DELETE "$CP/workspaces/acme/auth-routes" -d '{"path_prefix":"/"}' >/dev/null 2>&1 \
  || curl -s $JSON $CPAUTH -X DELETE "$CP/tenants/acme/auth-routes" -d '{"path_prefix":"/"}' >/dev/null 2>&1

echo
echo "RESULT: $pass passed, $fail failed"
[ "$fail" = 0 ]
