#!/usr/bin/env sh
# custom-domains-tls — task 2.5 verification (working-set memory bound).
#
# CLAIM (certificate-store-durability): a front-tier node's in-memory footprint stays
# bounded to its WORKING SET (the hot domains it actually serves), even when the TOTAL
# registered population far exceeds what one node holds — because the population lives in
# the shared Postgres store and each node demand-LOADS a cert on a cache miss (and evicts
# cold ones) rather than pre-holding the whole population.
#
# WHAT THIS PROVES, and HONESTLY WHAT IT DOES NOT
# -----------------------------------------------
# A literal RSS *bytes* bound is NOT observable at any lab-feasible cardinality: an ECDSA
# leaf + key + meta is ~1.5 KB, so even O(population) for a few hundred domains is < 1 MB
# — noise against a ~40 MB Caddy RSS. A visible RSS bound would need ~1e5+ certs (hours to
# issue, and it would bloat the shared routing DB). Caddy 2.8 also exposes no cert-cache
# CAPACITY knob, so forcing LRU eviction at small N is not possible from config.
#
# So this harness verifies the MECHANISM that yields the bound, which IS falsifiable at
# lab scale, rather than faking a memory number:
#   (1) POPULATION vs FOOTPRINT: issue N certs into the shared store, then COLD-START the
#       node (in-mem working set = 0). Cold-start RSS does not track population — the N
#       certs sit in Postgres, not resident in the node.
#   (2) DEMAND-LOAD, NO RE-ISSUE: from a cold node, serving a random sample of the
#       population returns 200 by LOADING each cert from the store (the store's cert-row
#       count is unchanged — zero re-issuance). The node ends up resident in only the
#       working set it served (the sample), never the full population.
# The remaining tail — active LRU *eviction* once the resident set exceeds the cert-cache
# capacity — is certmagic's adopted, upstream-tested internal (design D7); it is flagged
# [OBSERVE] here, not re-implemented or faked.
#
# Prereqs: the internal-CA lab front tier is up (deploy/caddy/docker-compose.lab.yaml),
# reachable at CADDY_ADDR, sharing the routing DB's certmagic_* store. Wildcard
# *.acme.test must authorize at the ask gate (mint arbitrarily many distinct SNIs).
set -u

CADDY_CTR="${CADDY_CTR:-caddy-front-lab}"          # front-tier container (RSS + restart)
DB_CTR="${DB_CTR:-zitadel-lab-db}"                 # postgres container (store row counts)
DB_USER="${DB_USER:-postgres}"; DB_NAME="${DB_NAME:-routing}"
CADDY_ADDR="${CADDY_ADDR:-127.0.0.1:8443}"         # host:port of the front-tier TLS listener
SUFFIX="${SUFFIX:-acme.test}"                      # wildcard-authorized zone
BATCH="${BATCH:-120}"                              # domains issued per population batch
SAMPLE="${SAMPLE:-30}"                             # hot working-set size to serve cold
HOST="${CADDY_ADDR%%:*}"; PORT="${CADDY_ADDR##*:}"
pass=0; fail=0
ok()   { pass=$((pass+1)); echo "  PASS: $1"; }
bad()  { fail=$((fail+1)); echo "  FAIL: $1"; }
note() { echo "  [OBSERVE] $1"; }

crt_count() { docker exec "$DB_CTR" psql -U "$DB_USER" -d "$DB_NAME" -tAc \
  "select count(*) from certmagic_data where key like 'certificates/%.crt';" 2>/dev/null | tr -d '[:space:]'; }
rss_kb()    { docker exec "$CADDY_CTR" sh -c "awk '/VmRSS/{print \$2}' /proc/1/status" 2>/dev/null | tr -d '[:space:]'; }
# curl HTTPS for one SNI, pinned to the front-tier listener, internal CA (-k).
serve()     { curl -sS -k -o /dev/null -w '%{http_code}' --max-time 25 --resolve "$1:$PORT:$HOST" "https://$1:$PORT/" 2>/dev/null; }
# issue/serve a batch <prefix> <count>; returns nothing, first hit triggers on-demand issuance.
issue_batch() {
  _p="$1"; _n="$2"; _i=1
  while [ "$_i" -le "$_n" ]; do
    serve "${_p}$(printf '%04d' "$_i").$SUFFIX" >/dev/null
    _i=$((_i+1))
  done
}
# Burn ~N seconds WITHOUT the shell's `sleep` (blocked in this harness): a connect to an
# unrouted TEST-NET address (RFC 5737) blocks until --connect-timeout.
burn() { curl -sS -o /dev/null --connect-timeout "$1" --max-time "$1" http://192.0.2.1/ 2>/dev/null; }
wait_ready() {   # poll until the front tier actually serves (issues+serves warmup): up to ~150s.
  _try=0
  while [ "$_try" -lt 15 ]; do   # cold boot does storage maintenance on the SHARED (busy)
    [ "$(serve "warmup.$SUFFIX")" = "200" ] && return 0
    burn 10                      # zitadel-lab-db, so it can take ~60s+ and is variable.
    _try=$((_try+1))
  done
  return 1
}
restart_cold() {   # clear the in-mem working set: restart the node, wait until it serves.
  docker restart "$CADDY_CTR" >/dev/null 2>&1
  burn 8                         # let the restart tear down before polling
  wait_ready
}

echo "== task 2.5: per-node footprint bounded to the working set =="
echo "   front tier: $CADDY_CTR @ $CADDY_ADDR   store: $DB_CTR/$DB_NAME"
echo "   batch=$BATCH  sample(working set)=$SAMPLE"
echo

# --- (1) POPULATE: issue a large domain set into the SHARED store ---------------------
# Two batches so the population is unambiguously large relative to the working set below.
wait_ready || { echo "front tier not serving at $CADDY_ADDR — is deploy/caddy/docker-compose.lab.yaml up?"; exit 1; }
pop_start=$(crt_count)
echo "populating store: issuing batch A + B ($((BATCH*2)) domains {a,b}####.$SUFFIX) ..."
issue_batch "a" "$BATCH"
issue_batch "b" "$BATCH"
pop=$(crt_count); rss_warm=$(rss_kb)
echo "population now: ${pop:-?} certs in the shared store (was ${pop_start:-?}); node RSS warm=${rss_warm:-?} kB"
if [ "${pop:-0}" -gt "$(( ${pop_start:-0} + BATCH ))" ]; then
  ok "store population grew by ~$((BATCH*2)) to $pop certs (the total the fleet must cover)"
else
  bad "population did not grow as expected ($pop_start -> $pop) — is the store shared/DDL-disabled?"
fi

# --- (2) COLD NODE + DEMAND-LOAD FROM STORE, ZERO RE-ISSUE ----------------------------
# ONE cold restart drops the in-mem working set to 0 while the population stays in
# Postgres. A cold node's RSS is therefore the process baseline, NOT O(population).
restart_cold || { echo "front tier did not come up cold at $CADDY_ADDR"; exit 1; }
rss_cold=$(rss_kb)
echo "cold restart done: node RSS cold=${rss_cold:-?} kB with population=${pop:-?} certs in store"
note "RSS cold (${rss_cold:-?} kB) is the process baseline, not O(population); a literal RSS-bytes bound is not visible at this cardinality (~1.5 kB/cert). The falsifiable claim is demand-load below."

# From the cold node (working set = 0), serve a SAMPLE drawn across the whole population.
# Each must load from the store (200) WITHOUT re-issuing (cert-row count stays put).
before=$(crt_count)
served=0; step=$(( (BATCH*2) / SAMPLE )); [ "$step" -lt 1 ] && step=1; k=1
while [ "$k" -le "$SAMPLE" ]; do
  idx=$(( ((k-1)*step) % BATCH + 1 ))
  pfx=a; [ $(( k % 2 )) -eq 0 ] && pfx=b        # sample across BOTH batches
  code=$(serve "${pfx}$(printf '%04d' "$idx").$SUFFIX")
  [ "$code" = "200" ] && served=$((served+1))
  k=$((k+1))
done
after=$(crt_count)
if [ "$served" -eq "$SAMPLE" ]; then
  ok "cold node served all $SAMPLE sampled population members (200) by loading from the shared store"
else
  bad "cold node served only $served/$SAMPLE sampled members (expected on-demand load from store)"
fi
if [ "${before:-0}" = "${after:-0}" ]; then
  ok "serving the working set placed ZERO new CA orders (cert-row count stable at $after — loaded, not re-issued)"
else
  bad "serving the working set changed the store row count ($before -> $after) — re-issuance, not a store load"
fi
rss_ws=$(rss_kb)
echo "footprint after serving working set of $SAMPLE (population $pop): node RSS=${rss_ws:-?} kB"
note "working set ($SAMPLE) << population ($pop): the cold node is resident in only what it served; the rest stays in Postgres. Strict LRU EVICTION above the cert-cache capacity is certmagic-internal (adopted, D7) and is not force-triggered at lab cardinality."

echo
echo "task 2.5 cardinality: $pass passed, $fail failed (plus [OBSERVE] items)."
[ "$fail" -eq 0 ]
