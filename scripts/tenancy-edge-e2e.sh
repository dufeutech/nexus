#!/usr/bin/env sh
# nexus-owned-workspace-tenancy end-to-end edge assertions (run after
# `docker compose up`). Proves the edge's identity-header trust contract at the
# real Envoy filter chain, using the `traefik/whoami` backend, which ECHOES the
# request headers it received back in its response body — so we can see exactly
# what reached the backend.
#
# What this covers (checkable WITHOUT a token, on the anonymous path):
#   1. No contract for the anonymous path: x-identity-contract is a SIGNED token
#      minted only for a resolved member (identity-contract-signing), so an
#      anonymous request carries none.
#   2. Unforgeable contract: a CLIENT-supplied `x-identity-contract` is stripped at
#      the edge (C3) — the backend never sees the forged value.
#   3. Unforgeable acting scope: client-supplied `x-workspace-id`/`x-user-type`/
#      `x-user-role` on a NON-member (anonymous) request are stripped — no forged
#      authoritative scope reaches the backend.
#   4. Non-member fail-closed on a PROTECTED route: with an auth-route requiring a
#      credential, the anonymous request is rejected (401) before the backend
#      (the non-member policy derived from the route auth policy, design 0.2).
#   5. Explicit non-enriched designation (identity-workspace-authz): /public is
#      served anonymous + UNSTAMPED by design (never rejected for the missing
#      stamp), and forged scope headers are stripped there too — a request can
#      never reach the backend with scope headers but no stamp.
#   6. Fail-closed default: an UNDESIGNATED (enriched) route with enrichment
#      unavailable is refused, never forwarded stampless as anonymous, while the
#      designated /public route keeps serving (C10).
#   7. Origin enforcement (edge-origin-trust): a direct-to-backend request from
#      off the edge, carrying a forged stamp + scope, fails to CONNECT — the
#      network path, not any header value, is the anti-forgery control.
#
# NOT covered here (requires the full identity stack — a real ZITADEL-minted JWT
# plus a seeded membership Profile): the POSITIVE member path, where a member's
# request yields an AUTHORITATIVE `x-workspace-id`+`x-user-type`+`x-user-role`
# sourced from the live membership check — that is scripts/tenancy-edge-auth-e2e.sh.
# The backend's rejection of an ABSENT stamp (a request that bypassed the edge)
# is the consuming box's contract, not nexus's to emit.
set -u

EDGE=http://localhost:10000
CP=http://localhost:9400
HOST=localhost          # seeded + verified -> workspace `acme` (public by default)
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

# Fetch the whoami echo body for a request carrying the given extra `-H` args.
echo_body() { curl -s -H "Host: $HOST" "$@" "$EDGE/"; }
# Case-insensitive grep of one echoed header line from a whoami body.
has_hdr() { printf '%s\n' "$1" | grep -iq "^$2:"; }
hdr_val() { printf '%s\n' "$1" | grep -i "^$2:" | head -n1 | sed 's/^[^:]*: *//' | tr -d '\r'; }
code() { curl -s -o /dev/null -w '%{http_code}' -H "Host: $HOST" "$@" "$EDGE/"; }
ok()   { if [ "$1" = "1" ]; then echo "  PASS  $2"; pass=$((pass+1)); else echo "  FAIL  $2"; fail=$((fail+1)); fi; }
settle() { sleep 2; }   # let an invalidation NOTIFY evict the router's cache

echo "== reset: ensure the site is public (no auth-route) =="
cpcurl $JSON -X DELETE "$CP/workspaces/$ACME_WS/auth-routes" -d '{"path_prefix":"/"}' >/dev/null 2>&1 \
  || cpcurl $JSON -X DELETE "$CP/workspaces/$ACME_WS/auth-routes" -d '{"path_prefix":"/"}' >/dev/null 2>&1
settle

echo "== 1. enriched anonymous request carries NO contract, forged copies stripped =="
BODY=$(echo_body \
  -H "x-identity-contract: vFORGED" \
  -H "x-workspace-id: ws_forged" \
  -H "x-user-type: staff" \
  -H "x-user-role: admin")

# identity-contract-signing: x-identity-contract is a SIGNED token minted ONLY for a
# resolved member — there is no plain-string form. An anonymous request has no identity to
# sign, so the sidecar authors NO contract and STRIPS any client copy. The member path
# (a verifiable signed token) is scripts/contract-signing-e2e.sh.
V=$(hdr_val "$BODY" "X-Identity-Contract")
ok "$([ -z "$V" ] && echo 1 || echo 0)" "anonymous path carries no contract (got '${V:-<none>}')"

# In particular the client's forged stamp never survives (stripped, never re-authored).
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
cpcurl $JSON -X PUT "$CP/workspaces/$ACME_WS/auth-routes" -d '{"path_prefix":"/","auth_required":true}' >/dev/null 2>&1 \
  || cpcurl $JSON -X PUT "$CP/workspaces/$ACME_WS/auth-routes" -d '{"path_prefix":"/","auth_required":true}' >/dev/null 2>&1
# Poll rather than a fixed settle: the invalidation NOTIFY usually evicts the
# router's cached decision within a beat, but the assertion must not race it.
i=0; C=$(code)
while [ "$C" != "401" ] && [ "$i" -lt 10 ]; do sleep 1; C=$(code); i=$((i+1)); done
ok "$([ "$C" = "401" ] && echo 1 || echo 0)" "anonymous non-member on a protected route -> 401 (fail-closed, got $C)"

echo "== cleanup =="
cpcurl $JSON -X DELETE "$CP/workspaces/$ACME_WS/auth-routes" -d '{"path_prefix":"/"}' >/dev/null 2>&1 \
  || cpcurl $JSON -X DELETE "$CP/workspaces/$ACME_WS/auth-routes" -d '{"path_prefix":"/"}' >/dev/null 2>&1
settle

echo "== 4. explicitly designated non-enriched route: unstamped + anonymous BY DESIGN =="
# identity-workspace-authz: /public is on the lab's explicit non-enriched
# allowlist (identity ext_proc disabled per-route), so it reaches the backend
# with NO stamp and NO identity attribution and is served as anonymous — NOT
# rejected for the missing stamp. Forged headers are still stripped; the only
# x-workspace-id that may appear is the ROUTING plane's re-authored tenant
# context (the route stays tenant-routed, C10) — never the client's value, and
# never the identity acting scope (x-user-*), which requires the stamp.
PBODY=$(curl -s --path-as-is -H "Host: $HOST" -H "x-workspace-id: ws_forged" -H "x-user-type: staff" -H "x-identity-contract: vFORGED" "$EDGE/public")
PCODE=$(curl -s --path-as-is -o /dev/null -w '%{http_code}' -H "Host: $HOST" "$EDGE/public")
ok "$([ "$PCODE" = "200" ] && echo 1 || echo 0)" "non-enriched /public served anonymous -> 200, not rejected for a missing stamp"
ok "$(has_hdr "$PBODY" "X-Identity-Contract" && echo 0 || echo 1)" "non-enriched /public reaches the backend UNSTAMPED (by design)"
PWS=$(hdr_val "$PBODY" "X-Workspace-Id")
ok "$([ "$PWS" != "ws_forged" ] && echo 1 || echo 0)" "forged x-workspace-id stripped on /public (got '${PWS:-<none>}' — routing context, not the client value)"
ok "$(has_hdr "$PBODY" "X-User-Type" && echo 0 || echo 1)" "no identity attribution without a stamp: forged x-user-type never reaches /public"
ok "$(has_hdr "$PBODY" "X-User-Id" && echo 0 || echo 1)" "no identity attribution without a stamp: no x-user-id on the unstamped route"

echo "== 5. undesignated route with enrichment unavailable FAILS CLOSED, never anonymous =="
# identity-workspace-authz fail-closed default: a route NOT on the non-enriched
# allowlist requires enrichment (failure_mode_allow: false). With the sidecar
# down, the enriched route must be REFUSED — not forwarded stampless and served
# as anonymous — while the designated /public route keeps serving (C10).
if command -v docker >/dev/null 2>&1; then
  docker compose stop identity-sidecar-rs >/dev/null 2>&1
  FCODE=$(code)
  ok "$([ "$FCODE" != "200" ] && echo 1 || echo 0)" "enriched route with enrichment down is refused (got $FCODE, not 200)"
  PCODE=$(curl -s --path-as-is -o /dev/null -w '%{http_code}' -H "Host: $HOST" "$EDGE/public")
  ok "$([ "$PCODE" = "200" ] && echo 1 || echo 0)" "designated non-enriched /public still serves during the outage (got $PCODE)"
  docker compose start identity-sidecar-rs >/dev/null 2>&1
  i=0; until [ "$(code)" = "200" ] || [ "$i" -ge 30 ]; do sleep 2; i=$((i+1)); done
  ok "$([ "$(code)" = "200" ] && echo 1 || echo 0)" "stack recovered after sidecar restart"
else
  echo "  SKIP  docker unavailable: fail-closed outage probe not run"
fi

echo "== 6. origin enforcement: a direct-to-backend request is REFUSED (edge-origin-trust) =="
# The backends live only on the internal edge-backend network. A peer on the
# default network presenting a forged stamp + scope headers must fail to
# connect at all — the header values are irrelevant, the PATH is the control.
if command -v docker >/dev/null 2>&1; then
  DCODE=$(docker compose run --rm --no-deps --quiet-pull --entrypoint sh routing-seed -c \
    "curl -s -o /dev/null -w '%{http_code}' --max-time 5 -H 'x-identity-contract: v1' -H 'x-workspace-id: ws_forged' http://backend:80/" 2>/dev/null || true)
  ok "$([ "${DCODE:-000}" = "000" ] && echo 1 || echo 0)" "direct-to-backend with forged stamp+scope refused before backend logic (got '${DCODE:-000}')"
else
  echo "  SKIP  docker unavailable: direct-to-backend origin probe not run"
fi

echo
echo "RESULT: $pass passed, $fail failed"
[ "$fail" = 0 ]
