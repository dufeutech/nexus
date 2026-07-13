#!/usr/bin/env sh
# admin-audit-e2e.sh — end-to-end proof of the admin-action-audit contract
# against a running deployment (the local compose lab by default).
#
# What it proves (spec scenarios, over real HTTP):
#   1. Two named admin tokens are individually identifiable: mutations made with
#      each carry DIFFERENT actor ids in the ledger.
#   2. Revoking one caller's token rejects it (401) while the other keeps working.
#   3. An idempotency-key replay is recorded as outcome="replay", distinguishable
#      from the original creation.
#   4. The asserted operator (x-acting-operator) is recorded verbatim — and an
#      invalid credential + assertion is rejected identically (the assertion
#      confers nothing).
#   5. No ledger event ever carries a token secret.
#
# Needs ADMIN_TOKEN_PEPPER configured on the control plane (the lab compose sets
# a dev default) and a credential that can mint tokens — the lab's legacy shared
# token (ADMIN_LEGACY_TOKEN_OK=true) by default.
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

# Crude JSON field extraction (no jq dependency): first "field":"value" match.
jfield() { printf '%s' "$1" | sed -n "s/.*\"$2\":\"\\([^\"]*\\)\".*/\\1/p" | head -n 1; }

boot() { curl -s --max-time 8 -H "authorization: Bearer $CONTROL_AUTH_TOKEN" "$@"; }

RUN=e2e-$$

# ---------------------------------------------------------------------------
section "0. mint two named tokens (attribution handles)"
ALPHA=$(boot -H 'content-type: application/json' -X POST "$CONTROL_PLANE/admin-tokens" -d "{\"name\":\"$RUN-alpha\"}")
BETA=$(boot  -H 'content-type: application/json' -X POST "$CONTROL_PLANE/admin-tokens" -d "{\"name\":\"$RUN-beta\"}")
ALPHA_ID=$(jfield "$ALPHA" token_id); ALPHA_SECRET=$(jfield "$ALPHA" secret)
BETA_ID=$(jfield "$BETA" token_id);   BETA_SECRET=$(jfield "$BETA" secret)
ok "$([ -n "$ALPHA_ID" ] && [ -n "$ALPHA_SECRET" ] && echo 1 || echo 0)" "token alpha minted ($ALPHA_ID)"
ok "$([ -n "$BETA_ID" ] && [ -n "$BETA_SECRET" ] && echo 1 || echo 0)" "token beta minted ($BETA_ID)"
ok "$([ "$ALPHA_ID" != "$BETA_ID" ] && echo 1 || echo 0)" "the two callers hold distinct credential ids"
if [ -z "$ALPHA_SECRET" ] || [ -z "$BETA_SECRET" ]; then
  echo "  ABORT cannot continue without minted tokens (is ADMIN_TOKEN_PEPPER set on the control plane?)"
  echo; echo "RESULT: $pass passed, $((fail+1)) failed"; exit 1
fi
alpha() { curl -s --max-time 8 -H "authorization: Bearer $ALPHA_SECRET" "$@"; }
beta()  { curl -s --max-time 8 -H "authorization: Bearer $BETA_SECRET" "$@"; }

# ---------------------------------------------------------------------------
section "1. two callers are distinguishable in the ledger"
# Each caller provisions its own account; alpha also asserts a human operator.
A_OUT=$(alpha -H 'content-type: application/json' -H "x-acting-operator: alice@$RUN.example" \
        -X POST "$CONTROL_PLANE/accounts" \
        -d "{\"owner_sub\":\"$RUN-owner-a\",\"name\":\"$RUN A\",\"idempotency_key\":\"$RUN:alpha\"}")
B_OUT=$(beta -H 'content-type: application/json' \
        -X POST "$CONTROL_PLANE/accounts" \
        -d "{\"owner_sub\":\"$RUN-owner-b\",\"name\":\"$RUN B\",\"idempotency_key\":\"$RUN:beta\"}")
A_ACCT=$(jfield "$A_OUT" account_id); B_ACCT=$(jfield "$B_OUT" account_id)
ok "$([ -n "$A_ACCT" ] && echo 1 || echo 0)" "alpha's mutation succeeded ($A_ACCT)"
ok "$([ -n "$B_ACCT" ] && echo 1 || echo 0)" "beta's mutation succeeded ($B_ACCT)"

A_EV=$(alpha "$CONTROL_PLANE/audit/events?actor=$ALPHA_ID&target=$A_ACCT")
B_EV=$(alpha "$CONTROL_PLANE/audit/events?actor=$BETA_ID&target=$B_ACCT")
ok "$(printf '%s' "$A_EV" | grep -q '"action":"account.provision"' && echo 1 || echo 0)" "alpha's event is in the ledger under $ALPHA_ID"
ok "$(printf '%s' "$B_EV" | grep -q '"action":"account.provision"' && echo 1 || echo 0)" "beta's event is in the ledger under $BETA_ID"
ok "$(printf '%s' "$A_EV" | grep -q "\"asserted_operator\":\"alice@$RUN.example\"" && echo 1 || echo 0)" "the asserted operator was recorded verbatim (and marked asserted by its field)"
ok "$(printf '%s' "$A_EV" | grep -q "$ALPHA_SECRET\|$BETA_SECRET" && echo 0 || echo 1)" "no event carries a credential secret"

# ---------------------------------------------------------------------------
section "2. an idempotency-key replay is recorded as a replay"
R_OUT=$(alpha -H 'content-type: application/json' -X POST "$CONTROL_PLANE/accounts" \
        -d "{\"owner_sub\":\"$RUN-owner-a\",\"name\":\"$RUN imposter\",\"idempotency_key\":\"$RUN:alpha\"}")
ok "$(printf '%s' "$R_OUT" | grep -q '"created":false' && echo 1 || echo 0)" "the replay returned the ORIGINAL account (created:false)"
RE_EV=$(alpha "$CONTROL_PLANE/audit/events?actor=$ALPHA_ID&target=$A_ACCT")
ok "$(printf '%s' "$RE_EV" | grep -q '"outcome":"replay"' && echo 1 || echo 0)" "the replay is in the ledger as outcome=replay"
ok "$(printf '%s' "$RE_EV" | grep -q '"outcome":"ok"' && echo 1 || echo 0)" "…distinguishable from the original creation (outcome=ok also present)"

# ---------------------------------------------------------------------------
section "3. revoking one caller leaves the other working"
RV=$(alpha -X POST "$CONTROL_PLANE/admin-tokens/$BETA_ID/revoke")
ok "$(printf '%s' "$RV" | grep -q '"revoked":true' && echo 1 || echo 0)" "beta revoked by alpha (audited: admin_token.revoke)"
BC=$(beta -o /dev/null -w '%{http_code}' "$CONTROL_PLANE/audit/events?limit=1")
ok "$([ "$BC" = "401" ] && echo 1 || echo 0)" "beta's credential is now rejected (HTTP $BC)"
AC=$(alpha -o /dev/null -w '%{http_code}' "$CONTROL_PLANE/audit/events?limit=1")
ok "$([ "$AC" = "200" ] && echo 1 || echo 0)" "alpha's credential still works (HTTP $AC)"

# An invalid credential + operator assertion is rejected IDENTICALLY — the
# assertion confers nothing.
IC=$(curl -s -o /dev/null -w '%{http_code}' --max-time 8 \
      -H "authorization: Bearer $BETA_SECRET" -H 'x-acting-operator: root@example.com' \
      "$CONTROL_PLANE/audit/events?limit=1")
ok "$([ "$IC" = "401" ] && echo 1 || echo 0)" "a revoked credential + operator assertion is still a 401 (HTTP $IC)"

# ---------------------------------------------------------------------------
section "4. cleanup"
CV=$(boot -X POST "$CONTROL_PLANE/admin-tokens/$ALPHA_ID/revoke")
ok "$(printf '%s' "$CV" | grep -q '"revoked":true' && echo 1 || echo 0)" "alpha revoked (throwaway tokens never linger)"

# ---------------------------------------------------------------------------
echo
echo "RESULT: $pass passed, $fail failed"
[ "$fail" = 0 ]
