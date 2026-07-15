#!/usr/bin/env sh
# admin-plane-authz-e2e.sh — end-to-end proof of the admin-plane-authorization
# contract against a running deployment (the local compose lab by default).
#
# What it proves (spec scenarios, over real HTTP):
#   1. Parity: a full-grant credential (and the legacy shared token, which holds
#      the full grant while ADMIN_LEGACY_TOKEN_OK=true) behaves exactly as
#      before the gate existed.
#   2. Grants are explicit at provisioning: an unscoped mint and an unknown
#      scope word are 400s; nothing is created.
#   3. A narrowed (read-only) credential succeeds on reads and is refused with
#      403 {"error":"forbidden"} on every mutation — including the credential
#      surface (token-admin is distinguished; read+provision cannot mint).
#   4. An authorization refusal leaves an attributed authz.denied ledger event
#      carrying the actor and the machine-readable decision reason; a permitted
#      mutation's event carries the permitting reason (authz_reason).
#   5. Authentication still precedes authorization: a bad credential is a 401,
#      never a 403.
#
# Needs ADMIN_TOKEN_PEPPER on the control plane and a credential that can mint
# tokens — the lab's legacy shared token (ADMIN_LEGACY_TOKEN_OK=true) by default.
#
# Endpoints (env var : default = local lab):
#   CONTROL_PLANE        http://localhost:9400
#   CONTROL_AUTH_TOKEN   zitadel-lab-dev-token   (bootstrap credential for minting)
#
# Exit code: 0 iff every check passed.

set -u

CONTROL_PLANE=${CONTROL_PLANE:-http://localhost:9400}
CONTROL_AUTH_TOKEN=${CONTROL_AUTH_TOKEN:-zitadel-lab-dev-token}

pass=0; fail=0
ok() { if [ "$1" = "1" ]; then echo "  PASS  $2"; pass=$((pass+1)); else echo "  FAIL  $2"; fail=$((fail+1)); fi; }
section() { echo; echo "== $1 =="; }
jfield() { printf '%s' "$1" | sed -n "s/.*\"$2\":\"\\([^\"]*\\)\".*/\\1/p" | head -n 1; }

boot() { curl -s --max-time 8 -H "authorization: Bearer $CONTROL_AUTH_TOKEN" "$@"; }
JSON='content-type: application/json'

RUN=authz-$$

# ---------------------------------------------------------------------------
section "1. parity — the legacy (full-grant) credential passes reads and mutations"
LC=$(boot -o /dev/null -w '%{http_code}' "$CONTROL_PLANE/audit/events?limit=1")
ok "$([ "$LC" = "200" ] && echo 1 || echo 0)" "legacy read (audit/events) → HTTP $LC"
LM=$(boot -H "$JSON" -X POST "$CONTROL_PLANE/accounts" \
     -d "{\"owner_sub\":\"$RUN-owner\",\"name\":\"$RUN parity\",\"idempotency_key\":\"$RUN:parity\"}")
PAR_ACCT=$(jfield "$LM" account_id)
ok "$([ -n "$PAR_ACCT" ] && echo 1 || echo 0)" "legacy mutation (POST /accounts) succeeded ($PAR_ACCT)"

# ---------------------------------------------------------------------------
section "2. grants are explicit at provisioning"
UC=$(boot -o /dev/null -w '%{http_code}' -H "$JSON" -X POST "$CONTROL_PLANE/admin-tokens" \
     -d "{\"name\":\"$RUN-unscoped\",\"scopes\":[]}")
ok "$([ "$UC" = "400" ] && echo 1 || echo 0)" "empty scope set is refused (HTTP $UC)"
UK=$(boot -o /dev/null -w '%{http_code}' -H "$JSON" -X POST "$CONTROL_PLANE/admin-tokens" \
     -d "{\"name\":\"$RUN-badscope\",\"scopes\":[\"root\"]}")
ok "$([ "$UK" = "400" ] && echo 1 || echo 0)" "unknown scope word is refused (HTTP $UK)"
LIST=$(boot "$CONTROL_PLANE/admin-tokens")
ok "$(printf '%s' "$LIST" | grep -q "$RUN-unscoped\|$RUN-badscope" && echo 0 || echo 1)" "refused mints created nothing"

# ---------------------------------------------------------------------------
section "3. a narrowed (read-only) credential is scoped, deny-by-default"
RD=$(boot -H "$JSON" -X POST "$CONTROL_PLANE/admin-tokens" -d "{\"name\":\"$RUN-read\",\"scopes\":[\"read\"]}")
RD_ID=$(jfield "$RD" token_id); RD_SECRET=$(jfield "$RD" secret)
ok "$([ -n "$RD_ID" ] && [ -n "$RD_SECRET" ] && echo 1 || echo 0)" "read-only token minted ($RD_ID)"
if [ -z "$RD_SECRET" ]; then
  echo "  ABORT cannot continue without the minted token"
  echo; echo "RESULT: $pass passed, $((fail+1)) failed"; exit 1
fi
rd() { curl -s --max-time 8 -H "authorization: Bearer $RD_SECRET" "$@"; }

RR=$(rd -o /dev/null -w '%{http_code}' "$CONTROL_PLANE/audit/events?limit=1")
ok "$([ "$RR" = "200" ] && echo 1 || echo 0)" "read within grant → HTTP $RR"
RM_BODY=$(rd -H "$JSON" -X POST "$CONTROL_PLANE/accounts" -d "{\"owner_sub\":\"$RUN-x\",\"name\":\"x\"}")
RM=$(rd -o /dev/null -w '%{http_code}' -H "$JSON" -X POST "$CONTROL_PLANE/accounts" -d "{\"owner_sub\":\"$RUN-x2\",\"name\":\"x\"}")
ok "$([ "$RM" = "403" ] && echo 1 || echo 0)" "mutation outside grant → HTTP $RM"
ok "$(printf '%s' "$RM_BODY" | grep -q '"error":"forbidden"' && echo 1 || echo 0)" "refusal names forbidden + a machine-readable reason ($(jfield "$RM_BODY" reason))"
TM=$(rd -o /dev/null -w '%{http_code}' -H "$JSON" -X POST "$CONTROL_PLANE/admin-tokens" \
     -d "{\"name\":\"$RUN-escalate\",\"scopes\":[\"read\",\"provision\",\"token-admin\"]}")
ok "$([ "$TM" = "403" ] && echo 1 || echo 0)" "credential mint without token-admin → HTTP $TM (no self-escalation)"
TL=$(rd -o /dev/null -w '%{http_code}' "$CONTROL_PLANE/admin-tokens")
ok "$([ "$TL" = "403" ] && echo 1 || echo 0)" "credential list without token-admin → HTTP $TL"
ok "$(boot "$CONTROL_PLANE/admin-tokens" | grep -q "$RUN-escalate" && echo 0 || echo 1)" "the refused mint created nothing"

# ---------------------------------------------------------------------------
section "4. the ledger records the authorization outcome"
DEN=$(boot "$CONTROL_PLANE/audit/events?actor=$RD_ID")
ok "$(printf '%s' "$DEN" | grep -q '"action":"authz.denied"' && echo 1 || echo 0)" "authz.denied event attributed to $RD_ID"
ok "$(printf '%s' "$DEN" | grep -q '"reason":"deny:no-permit"' && echo 1 || echo 0)" "…carrying the decision reason (deny:no-permit)"
ok "$(printf '%s' "$DEN" | grep -q "$RD_SECRET" && echo 0 || echo 1)" "…and never the credential"
ISS=$(boot "$CONTROL_PLANE/audit/events?target=$RD_ID")
ok "$(printf '%s' "$ISS" | grep -q '"authz_reason":"permit:' && echo 1 || echo 0)" "the permitted mint's event carries its permitting reason"

# ---------------------------------------------------------------------------
section "5. authentication precedes authorization"
BC=$(curl -s -o /dev/null -w '%{http_code}' --max-time 8 \
     -H "authorization: Bearer nexus_admin_definitely_wrong" "$CONTROL_PLANE/accounts/whatever")
ok "$([ "$BC" = "401" ] && echo 1 || echo 0)" "invalid credential → HTTP $BC (never 403)"

# ---------------------------------------------------------------------------
section "6. cleanup"
CV=$(boot -X POST "$CONTROL_PLANE/admin-tokens/$RD_ID/revoke")
ok "$(printf '%s' "$CV" | grep -q '"revoked":true' && echo 1 || echo 0)" "read-only token revoked (unguarded — it holds no token-admin)"

echo
echo "RESULT: $pass passed, $fail failed"
[ "$fail" = 0 ]
