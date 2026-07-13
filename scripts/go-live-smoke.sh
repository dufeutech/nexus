#!/usr/bin/env sh
# go-live-smoke.sh — walk the operator go-live checklist against a running
# nexus deployment (staging that mirrors prod, or the local lab).
#
# This turns the `verify` steps in deploy/README.md's "Production deployment
# checklist" into commands. It is SAFE BY DEFAULT: every default check is
# read-only. The two checks that mutate state or need a specific network
# position are opt-in (RUN_MUTATING=1, BACKEND_URL=...).
#
# It does NOT replace the checklist — a green run means the mechanics are wired;
# a human still signs off the items a script cannot judge (backend stamp
# enforcement, store HA/backups, capacity for YOUR traffic).
#
# Usage:
#   scripts/go-live-smoke.sh
#   EDGE=https://edge.staging AUTHZ=https://authz.staging \
#     CONTROL_PLANE=https://cp.staging PROM_URL=https://prom.staging \
#     scripts/go-live-smoke.sh
#
# Endpoints (env var : default = local lab):
#   EDGE            http://localhost:10000     edge listener (Host header selects workspace)
#   EDGE_HOST       localhost                  Host header sent to the edge
#   JWKS_URL        http://localhost:9210/.well-known/jwks.json
#   AUTHZ           http://localhost:9303      authz-admin (identity plane, :9300 in-cluster)
#   CONTROL_PLANE   http://localhost:9400      control-plane admin API
#   CONTROL_OPS     http://localhost:9401      control-plane ops /healthz (kubelet)
#   TENANT_ROUTER   http://localhost:9300      tenant-router health/resolve
#   SIDECAR         http://localhost:9201      identity sidecar profile/health (:9200 in-cluster)
#   PROM_URL        (unset)                    Prometheus/Thanos base for metric-pipeline checks
#
# Auth (env var : default = lab dev token):
#   IDENTITY_ADMIN_TOKEN   zitadel-lab-dev-token
#   CONTROL_AUTH_TOKEN     zitadel-lab-dev-token
#
# Opt-in checks:
#   BACKEND_URL     if set, probe a direct-to-backend request from THIS host and
#                   require it to be refused (run from a pod OFF the edge network).
#   ECHO_PATH       if set, an edge route whose backend echoes request headers;
#                   used to prove the edge strips forged identity headers.
#   RUN_MUTATING=1  run the authz grant->effect->revoke round-trip and the
#                   auth-route invalidation flip. Needs TOKEN + a throwaway sub.
#   TOKEN           a valid end-user JWT for the edge (required by RUN_MUTATING).
#   SMOKE_SUB       throwaway subject for the grant round-trip (default smoke-<pid>).
#   GATE_PATH       edge path gated by a role, for the grant->effect poll (default /ops-only).
#   GATE_ROLE       role to grant/observe (default ops).
#
# Exit code: 0 iff every non-skipped check passed.

set -u

EDGE=${EDGE:-http://localhost:10000}
EDGE_HOST=${EDGE_HOST:-localhost}
JWKS_URL=${JWKS_URL:-http://localhost:9210/.well-known/jwks.json}
AUTHZ=${AUTHZ:-http://localhost:9303}
CONTROL_PLANE=${CONTROL_PLANE:-http://localhost:9400}
CONTROL_OPS=${CONTROL_OPS:-http://localhost:9401}
TENANT_ROUTER=${TENANT_ROUTER:-http://localhost:9300}
SIDECAR=${SIDECAR:-http://localhost:9201}
PROM_URL=${PROM_URL:-}

IDENTITY_ADMIN_TOKEN=${IDENTITY_ADMIN_TOKEN:-zitadel-lab-dev-token}
CONTROL_AUTH_TOKEN=${CONTROL_AUTH_TOKEN:-zitadel-lab-dev-token}

BACKEND_URL=${BACKEND_URL:-}
ECHO_PATH=${ECHO_PATH:-}
RUN_MUTATING=${RUN_MUTATING:-0}
TOKEN=${TOKEN:-}
SMOKE_SUB=${SMOKE_SUB:-smoke-$$}
GATE_PATH=${GATE_PATH:-/ops-only}
GATE_ROLE=${GATE_ROLE:-ops}

pass=0; fail=0; skip=0
ok()   { if [ "$1" = "1" ]; then echo "  PASS  $2"; pass=$((pass+1)); else echo "  FAIL  $2"; fail=$((fail+1)); fi; }
skip() { echo "  SKIP  $1"; skip=$((skip+1)); }
section() { echo; echo "== $1 =="; }

# Quote the whole "Bearer <token>" as ONE -H arg; unquoted expansion word-splits
# into an invalid header and silently 401s.
azcurl() { curl -s -H "authorization: Bearer $IDENTITY_ADMIN_TOKEN" "$@"; }
cpcurl() { curl -s -H "authorization: Bearer $CONTROL_AUTH_TOKEN" "$@"; }
# HTTP status only.
code()      { curl -s -o /dev/null -w '%{http_code}' --max-time 8 "$@"; }
edge_code() { curl -s -o /dev/null -w '%{http_code}' --max-time 8 -H "Host: $EDGE_HOST" "$@"; }

# ---------------------------------------------------------------------------
section "0. reachability & readiness (health probes are open by design)"
for pair in \
  "edge:$EDGE/healthz" \
  "control-plane ops:$CONTROL_OPS/healthz" \
  "authz-admin:$AUTHZ/healthz" \
  "tenant-router:$TENANT_ROUTER/healthz" \
  "sidecar:$SIDECAR/healthz"
do
  name=${pair%%:*}; url=${pair#*:}
  c=$(code "$url")
  ok "$([ "$c" = "200" ] && echo 1 || echo 0)" "$name /healthz reachable (HTTP $c) [$url]"
done

# ---------------------------------------------------------------------------
section "1. JWKS is fetched over verified TLS"
case "$JWKS_URL" in
  https://*)
    # No -k: the cert MUST verify against the system trust store. If your
    # JWKS is signed by a private CA, point CURL_CA_BUNDLE at it before running.
    BODY=$(curl -s --max-time 8 "$JWKS_URL"); C=$?
    ok "$([ "$C" = "0" ] && echo 1 || echo 0)" "JWKS TLS certificate verifies (curl exit $C, no -k)"
    ok "$(printf '%s' "$BODY" | grep -q '\"kty\"' && echo 1 || echo 0)" "JWKS publishes verification keys (\"kty\" present)"
    ;;
  http://*)
    BODY=$(curl -s --max-time 8 "$JWKS_URL")
    ok "$(printf '%s' "$BODY" | grep -q '\"kty\"' && echo 1 || echo 0)" "JWKS reachable & publishes keys (\"kty\" present)"
    skip "JWKS_URL is http:// — acceptable ONLY for an assessed in-cluster hop (jwksPlaintextTrustedPath). Not a verified-TLS pass."
    ;;
  *) skip "JWKS_URL has no scheme; set JWKS_URL to the real endpoint" ;;
esac

# ---------------------------------------------------------------------------
section "2. admin surfaces are fail-closed (reject the unauthenticated caller)"
# A missing/blank bearer must be refused. 401/403 = fail-closed; 200 = OPEN DOOR.
UC=$(code -X GET "$AUTHZ/authz/$SMOKE_SUB")
ok "$([ "$UC" = "401" ] || [ "$UC" = "403" ] && echo 1 || echo 0)" "authz-admin rejects no-token request (HTTP $UC; must not be 200)"
UCP=$(code -X GET "$CONTROL_PLANE/workspaces/smoke-nonexistent")
ok "$([ "$UCP" = "401" ] || [ "$UCP" = "403" ] || [ "$UCP" = "404" ] && [ "$UCP" != "200" ] && echo 1 || echo 0)" "control-plane rejects no-token request (HTTP $UCP; must not be 200)"
# And the token we hold actually authenticates (guards a mis-set token/env).
AC=$(azcurl -o /dev/null -w '%{http_code}' --max-time 8 -X GET "$AUTHZ/authz/$SMOKE_SUB")
ok "$([ "$AC" != "401" ] && [ "$AC" != "403" ] && echo 1 || echo 0)" "IDENTITY_ADMIN_TOKEN is accepted by authz-admin (HTTP $AC)"

# ---------------------------------------------------------------------------
section "3. origin enforcement — direct-to-backend is refused (edge-origin-trust)"
if [ -n "$BACKEND_URL" ]; then
  # Proves the network PATH is the control: a caller off the edge network must
  # fail to reach the backend at all. HTTP 000 = could not connect (the pass).
  DC=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 \
        -H 'x-identity-contract: v1' -H 'x-workspace-id: ws_forged' \
        "$BACKEND_URL" 2>/dev/null || true)
  ok "$([ "${DC:-000}" = "000" ] && echo 1 || echo 0)" "direct-to-backend with forged stamp+scope refused before backend (got '${DC:-000}')"
else
  skip "set BACKEND_URL and run this from a pod OFF the edge network; a forged direct request must fail to connect (HTTP 000)"
fi

if [ -n "$ECHO_PATH" ]; then
  # Forge identity headers THROUGH the edge; the edge must strip them so the
  # backend never sees attacker-controlled values.
  OUT=$(curl -s --max-time 8 -H "Host: $EDGE_HOST" \
          -H 'x-identity-contract: vFORGED' -H 'x-workspace-id: ws_forged' \
          -H 'x-user-type: staff' -H 'x-user-role: admin' \
          "$EDGE$ECHO_PATH")
  ok "$(printf '%s' "$OUT" | grep -qi 'vFORGED\|ws_forged' && echo 0 || echo 1)" "edge strips forged identity headers before the backend"
else
  skip "set ECHO_PATH to a route whose backend echoes headers to verify the edge strips forged x-identity-*/x-workspace-id"
fi

# ---------------------------------------------------------------------------
section "4. metrics pipeline is wired (alerting substrate can see the signals)"
if [ -n "$PROM_URL" ]; then
  # Metrics are OTLP-only (no service /metrics); assert the collector->Prom path
  # carries the series your go-live alerts depend on. Series present = wired.
  prom_has() { # $1 = promQL selector; success iff a non-empty result set
    R=$(curl -s -G --max-time 8 "$PROM_URL/api/v1/query" --data-urlencode "query=$1")
    printf '%s' "$R" | grep -q '"status":"success"' || return 1
    printf '%s' "$R" | grep -q '"result":\[\]' && return 1
    return 0
  }
  for m in \
    "router_last_invalidation_timestamp_seconds" \
    "sidecar_kv_last_apply_timestamp_seconds" \
    "control_mutations" \
    "authz_admin_mutations"
  do
    prom_has "$m" && ok 1 "metric present in Prometheus: $m" || ok 0 "metric present in Prometheus: $m (needed for staleness/auth-failure alerts)"
  done
  echo "  NOTE  wire alerts on: time()-max(router_last_invalidation_timestamp_seconds) & sidecar_kv_last_apply_timestamp_seconds (feed staleness); rate(control_mutations{op=\"unauthorized\"}[5m]) & rate(authz_admin_mutations{op=\"unauthorized\"}[5m]) (auth failures)."
else
  skip "set PROM_URL to assert the OTLP->Prometheus pipeline carries router_last_invalidation_timestamp_seconds, sidecar_kv_last_apply_timestamp_seconds, control_mutations, authz_admin_mutations"
fi

# ---------------------------------------------------------------------------
section "5. authz grant -> effect -> revoke round-trip (LISTEN/NOTIFY liveness)"
if [ "$RUN_MUTATING" = "1" ]; then
  if [ -z "$TOKEN" ]; then
    skip "RUN_MUTATING=1 needs TOKEN (a valid end-user JWT for the edge) to observe the grant taking effect"
  else
    GATE="$EDGE$GATE_PATH"
    echo "  .. granting role '$GATE_ROLE' to '$SMOKE_SUB' and polling $GATE for effect"
    GC=$(azcurl -o /dev/null -w '%{http_code}' -H 'content-type: application/json' \
          -X PUT "$AUTHZ/authz/$SMOKE_SUB/roles" -d "{\"role\":\"$GATE_ROLE\"}")
    ok "$([ "$GC" = "200" ] && echo 1 || echo 0)" "authz-admin authored the role (HTTP $GC)"
    # The write must propagate to the edge over the identity_changes feed; poll
    # rather than sleep. Convergence here IS the LISTEN/NOTIFY liveness proof.
    SAW=0; tries=0
    while [ "$tries" -lt 45 ]; do
      LAST=$(curl -s -o /dev/null -w '%{http_code}' --max-time 8 -H "Host: $EDGE_HOST" -H "authorization: Bearer $TOKEN" "$GATE")
      if [ "$LAST" = "200" ]; then SAW=1; break; fi
      tries=$((tries+1)); sleep 2
    done
    ok "$SAW" "grant took effect at the edge within $((tries*2))s (invalidation feed live; last HTTP ${LAST:-n/a})"
    # Always attempt cleanup so a throwaway grant never lingers.
    RC=$(azcurl -o /dev/null -w '%{http_code}' -X DELETE "$AUTHZ/authz/$SMOKE_SUB/roles/$GATE_ROLE")
    ok "$([ "$RC" = "200" ] && echo 1 || echo 0)" "cleanup: role revoked (HTTP $RC)"
  fi
else
  skip "set RUN_MUTATING=1 (with TOKEN) to author a throwaway grant and prove it propagates to the edge over LISTEN/NOTIFY; skipped to stay read-only"
fi

# ---------------------------------------------------------------------------
section "6. admin action audit — denials and mutations land in the ledger (admin-action-audit)"
# Section 2's unauthenticated probes were 401'd; each surface records a denial
# event (actor 'unauthenticated', action 'auth.denied') — and never the
# presented credential. Read-only: the probes already happened above.
AZD=$(azcurl --max-time 8 "$AUTHZ/audit/events?actor=unauthenticated&limit=5")
ok "$(printf '%s' "$AZD" | grep -q '"action":"auth.denied"' && echo 1 || echo 0)" "authz-admin recorded a denial event for the unauthenticated probe"
CPD=$(cpcurl --max-time 8 "$CONTROL_PLANE/audit/events?actor=unauthenticated&limit=5")
ok "$(printf '%s' "$CPD" | grep -q '"action":"auth.denied"' && echo 1 || echo 0)" "control-plane recorded a denial event for the unauthenticated probe"
if [ "$RUN_MUTATING" = "1" ] && [ -n "$TOKEN" ]; then
  # The section-5 grant/revoke are admin mutations — both must be queryable in
  # the authz-admin ledger, attributed to the acting credential.
  AZE=$(azcurl --max-time 8 "$AUTHZ/audit/events?target=$SMOKE_SUB")
  ok "$(printf '%s' "$AZE" | grep -q '"action":"role.assign"' && echo 1 || echo 0)" "the role grant produced a queryable audit event (role.assign, target $SMOKE_SUB)"
  ok "$(printf '%s' "$AZE" | grep -q '"action":"role.revoke"' && echo 1 || echo 0)" "the cleanup revoke produced a queryable audit event (role.revoke)"
else
  skip "RUN_MUTATING=1 also proves a mutation lands in the ledger (role.assign/revoke events for the smoke sub)"
fi

# ---------------------------------------------------------------------------
echo
echo "RESULT: $pass passed, $fail failed, $skip skipped"
echo
echo "A green run proves the mechanics are wired. It does NOT certify the items"
echo "no script can judge — walk these by hand in deploy/README.md's checklist:"
echo "  - backend enforces its half of the x-identity-contract stamp"
echo "  - store lifecycle: HA, backups, restore-tested, failover"
echo "  - load/capacity validated for YOUR traffic shape"
echo "  - Postgres uses session-mode connections (no txn pooler) & sslmode=verify-full"
[ "$fail" = 0 ]
