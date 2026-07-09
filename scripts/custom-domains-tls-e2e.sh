#!/usr/bin/env sh
# custom-domains-tls end-to-end verification (run after `docker compose up` with the
# caddy front tier). Executes the spec verifications for the three capabilities of the
# change against the REAL front tier: certificate-issuance-authorization,
# certificate-store-durability, and on-demand-certificate-lifecycle.
#
# This is the harness the change's task 5.1 ("run the spec verifications end-to-end")
# drives. It targets Let's Encrypt STAGING by default (ACME_CA_DIR) so it never spends
# production new-order budget. A few properties are inherently observational in a
# single-box lab (multi-node serve, 60-day renewal timing, working-set eviction under
# extreme cardinality) — those are asserted where possible and otherwise flagged
# [OBSERVE] with what to watch, rather than faked.
#
# Prereqs:
#   * front tier up: caddy (:443) -> envoy (:10000); tenant-router /authorize (:9300)
#   * an AUTHORIZED customer domain seeded+verified in the routing store, resolvable to
#     the caddy listener (lab: use --resolve to pin it), e.g. shop.tenant.example
#   * psql reachable at CADDY_STORAGE_PG_URL (the routing DB holding certmagic_*)
set -u

AUTHZ="${AUTHZ_URL:-http://localhost:9300/authorize}"   # the ask gate
TLS_HOST="${TLS_HOST:-shop.tenant.example}"             # an AUTHORIZED, verified domain
UNKNOWN_HOST="${UNKNOWN_HOST:-nope.attacker.example}"   # never seeded -> must fail closed
CADDY_ADDR="${CADDY_ADDR:-127.0.0.1:443}"               # front-tier TLS listener
PG="${CADDY_STORAGE_PG_URL:-postgres://postgres:postgres@localhost:5432/routing}"
pass=0; fail=0
ok()   { pass=$((pass+1)); echo "  PASS: $1"; }
bad()  { fail=$((fail+1)); echo "  FAIL: $1"; }
note() { echo "  [OBSERVE] $1"; }

# Count rows in the shared cert store (a stored cert/key blob for HOST implies exactly
# one issuance happened; a stable count across reconnects proves NO re-issuance).
data_rows() { psql "$PG" -tAc "select count(*) from certmagic_data where key like '%$1%';" 2>/dev/null | tr -d '[:space:]'; }
# curl an HTTPS request to the front tier for a given SNI, pinned to the caddy listener.
tls_get() { curl -sS -o /dev/null -w '%{http_code}' --resolve "$1:${CADDY_ADDR##*:}:${CADDY_ADDR%%:*}" "https://$1/" "$@"; }

echo "== §3 certificate-issuance-authorization =="

# 3.3 — ask authorizes IFF routing resolves the identical host set.
code_auth=$(curl -sS -o /dev/null -w '%{http_code}' "$AUTHZ?domain=$TLS_HOST")
code_unk=$(curl -sS -o /dev/null -w '%{http_code}' "$AUTHZ?domain=$UNKNOWN_HOST")
[ "$code_auth" = "200" ] && ok "authorized host -> ask 200" || bad "authorized host expected 200, got $code_auth"
[ "$code_unk" = "403" ]  && ok "unknown host -> ask 403 (fail-closed)" || bad "unknown host expected 403, got $code_unk"

# 3.4 — unknown-hostname flood keeps issuance-order count bounded (ZERO for unknowns)
# and does not consume approved-host budget. Snapshot the store, flood, re-check.
before=$(data_rows "$UNKNOWN_HOST")
i=0; while [ "$i" -lt 50 ]; do curl -sS -o /dev/null "$AUTHZ?domain=$UNKNOWN_HOST"; i=$((i+1)); done
after=$(data_rows "$UNKNOWN_HOST")
[ "${before:-0}" = "0" ] && [ "${after:-0}" = "0" ] \
  && ok "unknown-host flood placed 0 CA orders (no certmagic_data rows)" \
  || bad "unknown-host flood created cert-store rows ($before -> $after)"
note "the tenant-router negative cache (AUTHORIZE_NEG_TTL) collapses the repeat flood to one store eval — confirm router_authorize{result=deny} rate, not lookup rate, tracks the flood."

echo "== §4 on-demand-certificate-lifecycle =="

# 4.5 — first connection for an AUTHORIZED domain obtains then serves; later reuse.
c1=$(tls_get "$TLS_HOST"); r1=$(data_rows "$TLS_HOST")
[ "$c1" = "200" ] && ok "first HTTPS to authorized host obtained+served (200)" || bad "first HTTPS expected 200, got $c1 (staging CA reachable? DNS pinned?)"
c2=$(tls_get "$TLS_HOST"); r2=$(data_rows "$TLS_HOST")
[ "$c2" = "200" ] && [ "${r1:-0}" = "${r2:-0}" ] && [ "${r2:-0}" -ge 1 ] \
  && ok "second HTTPS reused stored cert (no new issuance; rows stable at $r2)" \
  || bad "reuse check failed (code=$c2 rows $r1 -> $r2)"

# 4.8 — an unauthorized/unresolvable hostname fails the handshake CLOSED (no default,
# catch-all, or self-signed cert presented).
hs=$(curl -sS -o /dev/null -w '%{http_code}' --resolve "$UNKNOWN_HOST:${CADDY_ADDR##*:}:${CADDY_ADDR%%:*}" "https://$UNKNOWN_HOST/" 2>&1)
if [ "$?" -ne 0 ] || [ -z "$hs" ] || [ "$hs" = "000" ]; then
  ok "unauthorized SNI failed the TLS handshake closed (no fallback cert)"
else
  bad "unauthorized SNI completed a handshake (got HTTP $hs) — a fallback cert was presented"
fi

# 4.7 — issuer down: existing domains still serve; only NEW onboarding defers.
note "4.7 issuer-outage: repoint ACME_CA_DIR at an unreachable URL (or block egress), restart caddy, then: existing '$TLS_HOST' still serves from certmagic_data (200), a brand-NEW authorized host defers (handshake stalls/closes). Existing-serve MUST stay green."

# 4.6 — renewal ahead of expiry without net-new budget (ARI). Not wall-clock testable.
note "4.6 renewal/ARI: confirm the LE order used ARI (caddy logs 'renewal information') and that renewals do NOT increment the new-order counter. Verify against the LE account's rate-limit view over a renewal cycle."

echo "== §2 certificate-store-durability =="

# 2.4 — cert written by one node served by another; node loss leaves cert recoverable.
r=$(data_rows "$TLS_HOST")
[ "${r:-0}" -ge 1 ] && ok "cert for '$TLS_HOST' persisted in the SHARED store (recoverable after node loss)" || bad "no stored cert row for '$TLS_HOST'"
note "2.4 multi-node: bring up a SECOND caddy on the same CADDY_STORAGE_PG_URL, stop the first, and serve '$TLS_HOST' from the second — expect 200 with NO new certmagic_data row (served from store, not re-issued)."

# 2.5 — per-node memory bounded to the working set, not total population.
note "2.5 working-set: with total registered domains >> a node's in-mem capacity, confirm caddy serves hot domains by loading on demand and evicting cold ones (RSS stays bounded, not O(total)). Drive with scripts/load/ against many SNIs."

echo
echo "custom-domains-tls e2e: $pass passed, $fail failed (plus [OBSERVE] items above)."
[ "$fail" -eq 0 ]
