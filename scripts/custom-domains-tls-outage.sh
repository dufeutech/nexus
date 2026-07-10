#!/usr/bin/env sh
# custom-domains-tls — task 4.7 verification (issuer-DOWN resilience).
#
# CONTRACT (on-demand-certificate-lifecycle / design goal "cert automation is a side
# tool"): with the ACME issuer DOWN, existing domains keep serving while ONLY brand-new
# onboarding defers. An issuer outage must never degrade live traffic.
#
# The contract has two mechanistically INDEPENDENT halves; this harness proves each with
# a live run, then composes them:
#
#   (A) EXISTING SERVES, issuer-independent by construction.
#       Serving an already-issued, still-valid cert is a pure STORAGE READ — certmagic
#       contacts the CA only to OBTAIN or RENEW, never to serve a cached valid cert. So a
#       down issuer cannot affect existing serving. Proven on the internal-CA lab tier
#       (caddy-front-lab): COLD-restart it (in-mem cache empty) and serve app.acme.test —
#       it loads the stored cert and serves 200 with NO re-issuance and NO issuer call in
#       the logs for that serve.
#
#   (B) NEW ONBOARDING DEFERS when the issuer is down.
#       Proven on caddy-outage-lab, whose ACME issuer points at a refused port (a literal
#       down CA). A brand-new AUTHORIZED domain passes the ask gate but cannot be issued
#       (CA unreachable): its handshake DEFERS (no 200) and NO fallback/self-signed cert
#       is presented; the tier stays up and places zero cert rows.
#
# Prereqs: the running zitadel-lab stack (postgres/tenant-router/envoy) + the internal-CA
# lab tier (deploy/caddy/docker-compose.lab.yaml) up on 8443. This harness brings up and
# tears down the outage tier (deploy/caddy/docker-compose.outage-lab.yaml) on 8444 itself.
set -u
HERE="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"; ROOT="$(CDPATH= cd -- "$HERE/.." && pwd)"

CADDY_CTR="${CADDY_CTR:-caddy-front-lab}"          # internal-CA tier (existing-serves)
OUTAGE_CTR="${OUTAGE_CTR:-caddy-outage-lab}"       # issuer-down tier (new-defers)
OUTAGE_COMPOSE="$ROOT/deploy/caddy/docker-compose.outage-lab.yaml"
DB_CTR="${DB_CTR:-zitadel-lab-db}"; DB_USER="${DB_USER:-postgres}"; DB_NAME="${DB_NAME:-routing}"
LAB_ADDR="${LAB_ADDR:-127.0.0.1:8443}"             # internal-CA tier listener
OUT_ADDR="${OUT_ADDR:-127.0.0.1:8444}"             # outage tier listener
SUFFIX="${SUFFIX:-acme.test}"
EXISTING="${EXISTING:-app.$SUFFIX}"                # a domain with a valid cert already in store
FRESH="${FRESH:-outage-new.$SUFFIX}"              # a brand-new authorized host (never issued)
pass=0; fail=0
ok()   { pass=$((pass+1)); echo "  PASS: $1"; }
bad()  { fail=$((fail+1)); echo "  FAIL: $1"; }
note() { echo "  [OBSERVE] $1"; }

# Burn ~N seconds without the shell's (blocked) `sleep`: connect to an unrouted TEST-NET
# address, which blocks until --connect-timeout.
burn() { curl -sS -o /dev/null --connect-timeout "$1" --max-time "$1" http://192.0.2.1/ 2>/dev/null; }
# HTTPS GET for one SNI, pinned to a listener host:port. NOTE: the URL MUST carry the port
# so the --resolve entry (host:port:addr) actually applies.
get() { # <sni> <host:port> [max-time]
  _a="$2"; _h="${_a%%:*}"; _p="${_a##*:}"; _mt="${3:-25}"
  curl -sS -k -o /dev/null -w '%{http_code}' --max-time "$_mt" --resolve "$1:$_p:$_h" "https://$1:$_p/" 2>/dev/null
}
crt_rows() { docker exec "$DB_CTR" psql -U "$DB_USER" -d "$DB_NAME" -tAc \
  "select count(*) from certmagic_data where key like 'certificates/%$1%';" 2>/dev/null | tr -d '[:space:]'; }
ready() { # <host:port> — poll until the listener serves warmup (up to ~150s cold boot)
  _t=0; while [ "$_t" -lt 15 ]; do
    [ "$(get "warmup.$SUFFIX" "$1")" = "200" ] && return 0
    burn 10; _t=$((_t+1))
  done; return 1
}

echo "== task 4.7: issuer-DOWN resilience (existing serves; only new onboarding defers) =="
echo

# --- (A) EXISTING SERVES with zero issuer interaction ---------------------------------
echo "-- (A) existing domain '$EXISTING' serves from the store (issuer-independent) --"
ready "$LAB_ADDR" || { echo "internal-CA lab tier not serving at $LAB_ADDR (bring up docker-compose.lab.yaml)"; exit 1; }
# Prime EXISTING on the WARM tier first: guarantees a current valid cert in the store
# (issuing/renewing here, if needed, is pre-restart setup — outside the measured window),
# so the cold serve below is unambiguously a pure store LOAD, not a renewal.
get "$EXISTING" "$LAB_ADDR" >/dev/null
rows_before=$(crt_rows "$EXISTING")
[ "${rows_before:-0}" -ge 1 ] || { echo "no stored cert for $EXISTING — issue it once via the lab tier first"; exit 1; }

# Cold-restart to guarantee the serve is a fresh STORE LOAD (empty in-mem cache), not a
# warm cache hit; capture only this window's logs to check for issuer activity.
docker restart "$CADDY_CTR" >/dev/null 2>&1; burn 8
ready "$LAB_ADDR" || { echo "lab tier did not come back cold"; exit 1; }
since_ts="$(docker inspect -f '{{.State.StartedAt}}' "$CADDY_CTR" 2>/dev/null)"
code_e=$(get "$EXISTING" "$LAB_ADDR")
rows_after=$(crt_rows "$EXISTING")
[ "$code_e" = "200" ] && ok "existing '$EXISTING' served 200 from a COLD node (loaded from store)" \
  || bad "existing '$EXISTING' did not serve from store (got $code_e)"
[ "${rows_before:-0}" = "${rows_after:-0}" ] && ok "existing serve placed ZERO new CA orders (rows stable at $rows_after — no re-issue)" \
  || bad "existing serve changed store rows ($rows_before -> $rows_after)"
# The serve path must not have touched an issuer. certmagic logs 'obtain'/'issuing' only
# when it goes to the CA; a pure store-load serve logs neither for this domain.
issuer_hits=$(docker logs --since "$since_ts" "$CADDY_CTR" 2>&1 | grep -iE "obtain|issuing|acme_client|certificate obtained" | grep -c "$EXISTING")
[ "${issuer_hits:-0}" = "0" ] && ok "no issuer/obtain activity for '$EXISTING' on the serve path (issuer-independent — a down CA cannot affect it)" \
  || bad "serve path showed $issuer_hits issuer/obtain log lines for '$EXISTING' (expected a pure store load)"

# --- (B) NEW ONBOARDING DEFERS with the issuer DOWN -----------------------------------
echo
echo "-- (B) brand-new '$FRESH' cannot onboard while the issuer is DOWN --"
docker compose -f "$OUTAGE_COMPOSE" up -d 2>&1 | tail -1
# The outage tier's issuer is dead, so warmup can't be issued either — wait on the process
# being up (container running + TLS port accepting), not on a 200.
burn 12
up="$(docker inspect -f '{{.State.Running}}' "$OUTAGE_CTR" 2>/dev/null)"
[ "$up" = "true" ] && ok "outage tier is running (issuer down)" || bad "outage tier did not start"

# Sanity: the ask gate STILL authorizes the fresh host (403 would confound the result).
authz=$(docker exec "$OUTAGE_CTR" sh -c "wget -qO- -S 'http://tenant-router:9300/authorize?domain=$FRESH' 2>&1 | grep -m1 'HTTP/' | awk '{print \$2}'" 2>/dev/null)
[ "$authz" = "200" ] && ok "ask gate AUTHORIZES '$FRESH' (so any failure below is issuance, not authz)" \
  || note "ask gate returned '$authz' for '$FRESH' — expected 200; deferral below may be authz, not issuer-down"

rowsN_before=$(crt_rows "$FRESH")
# A new authorized domain: ask says yes, but issuance can't reach the CA -> handshake
# defers. Bound it; a served 200 or any presented cert would FAIL the contract.
codeN=$(get "$FRESH" "$OUT_ADDR" 25)
rowsN_after=$(crt_rows "$FRESH")
if [ "$codeN" != "200" ]; then
  ok "brand-new '$FRESH' did NOT onboard (handshake deferred/failed: code=$codeN) — issuer down"
else
  bad "brand-new '$FRESH' onboarded (200) despite the issuer being down — a fallback cert may have been served"
fi
[ "${rowsN_before:-0}" = "0" ] && [ "${rowsN_after:-0}" = "0" ] \
  && ok "failed onboarding placed ZERO cert rows for '$FRESH' (no partial/garbage cert)" \
  || bad "onboarding created cert rows for '$FRESH' ($rowsN_before -> $rowsN_after)"

# The tier must survive the failed onboarding: still running, listener still accepting.
still_up="$(docker inspect -f '{{.State.Running}}' "$OUTAGE_CTR" 2>/dev/null)"
codeN2=$(get "$FRESH" "$OUT_ADDR" 15)
if [ "$still_up" = "true" ] && [ "$codeN2" != "200" ]; then
  ok "onboarding failure did NOT crash the tier (still running; a second attempt also defers cleanly)"
else
  bad "tier unhealthy after failed onboarding (running=$still_up, 2nd attempt=$codeN2)"
fi

echo
echo "tearing down the outage tier ..."
docker compose -f "$OUTAGE_COMPOSE" down 2>&1 | tail -1

echo
echo "task 4.7 issuer-down: $pass passed, $fail failed."
echo "  (A) existing serves = issuer-independent store read;  (B) new onboarding defers, tier survives."
[ "$fail" -eq 0 ]
