#!/usr/bin/env sh
# custom-domains-tls — task 4.6 OBSERVATION (ARI-driven renewal), local half.
#
# Task 4.6: "a certificate nearing expiry renews in advance AND renewal does not consume
# net-new issuance budget (ARI exemption observed)."
#
# The task has two halves with different reachability:
#   * RENEWS IN ADVANCE, ARI-DRIVEN  -> observable locally against an ARI-capable test CA.
#   * DOES NOT CONSUME NEW-ORDER BUDGET (the ARI *exemption*) -> a Let's-Encrypt-ACCOUNT
#     rate-limit property; Pebble has no such budget, so this half is NOT reproducible
#     locally and remains gated on the real LE issuer (see design.md D4).
#
# This harness proves the local half end-to-end: it stands up Pebble (an ACME CA that
# implements ARI, draft-ietf-acme-ari) + the front tier pointed at it, obtains a REAL ACME
# cert (not the internal CA), and observes certmagic (a) FETCH the CA's renewalInfo and
# (b) RENEW the cert in advance, driven by that ARI window. The Pebble default validity is
# shortened (deploy/caddy/ari-lab/pebble-config.json) so the cert is immediately inside its
# ARI window and the advance renewal fires within one maintenance interval.
#
# Prereqs: the running zitadel-lab stack (postgres/tenant-router/envoy). This harness
# brings up and tears down the ARI stack (deploy/caddy/docker-compose.ari-lab.yaml) itself.
set -u
HERE="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"; ROOT="$(CDPATH= cd -- "$HERE/.." && pwd)"
# Run from repo root and use a RELATIVE compose path: under Git Bash/MSYS an absolute
# /c/... path passed to docker.exe gets mis-resolved, but a relative path is passed through
# untouched and docker resolves it against cwd.
cd "$ROOT" || exit 1
COMPOSE="deploy/caddy/docker-compose.ari-lab.yaml"
CADDY_CTR="${CADDY_CTR:-caddy-ari-lab}"; PEBBLE_CTR="${PEBBLE_CTR:-ari-pebble}"
DB_CTR="${DB_CTR:-zitadel-lab-db}"; DB_USER="${DB_USER:-postgres}"; DB_NAME="${DB_NAME:-routing}"
ADDR="${ADDR:-127.0.0.1:8445}"; SUFFIX="${SUFFIX:-acme.test}"
DOMAIN="${DOMAIN:-ari-test.$SUFFIX}"
RENEW_BUDGET_TRIES="${RENEW_BUDGET_TRIES:-36}"   # x30s ~= 18 min; renewal fires on the
                                                 # first ~10-min tick with the 900s validity
pass=0; fail=0
ok()   { pass=$((pass+1)); echo "  PASS: $1"; }
bad()  { fail=$((fail+1)); echo "  FAIL: $1"; }
note() { echo "  [OBSERVE] $1"; }

burn() { curl -sS -o /dev/null --connect-timeout "$1" --max-time "$1" http://192.0.2.1/ 2>/dev/null; }
get()  { _h="${ADDR%%:*}"; _p="${ADDR##*:}"; curl -sS -k -o /dev/null -w '%{http_code}' \
         --max-time "${2:-40}" --resolve "$1:$_p:$_h" "https://$1:$_p/" 2>/dev/null; }
pebble_issues() { docker logs "$PEBBLE_CTR" 2>&1 | grep -c "Issued certificate serial"; }
caddy_has()     { docker logs "$CADDY_CTR" 2>&1 | grep -iE "$1"; }

cleanup() {
  echo; echo "tearing down the ARI stack ..."
  docker compose -f "$COMPOSE" down 2>&1 | tail -1
  # Remove the Pebble-issued cert rows AND the Pebble ACME account from the SHARED store.
  docker exec "$DB_CTR" psql -U "$DB_USER" -d "$DB_NAME" -tAc \
    "delete from certmagic_data where key like '%$DOMAIN%' or key like 'acme/%pebble%';" >/dev/null 2>&1
}
trap cleanup EXIT

echo "== task 4.6: ARI-driven advance renewal (local half; budget-exemption is LE-only) =="
echo

purge_pebble_store() {   # each fresh Pebble has a new account namespace; a cached ACME
  # account/cert from a prior run is stale ("accountDoesNotExist"). Clear both so certmagic
  # registers fresh. (Pebble/ARI leaf certs live under the pebble issuer prefix.)
  docker exec "$DB_CTR" psql -U "$DB_USER" -d "$DB_NAME" -tAc \
    "delete from certmagic_data where key like 'acme/%pebble%' or key like '%$DOMAIN%';" >/dev/null 2>&1
}

echo "bringing up Pebble (ARI CA) + front tier ..."
docker compose -f "$COMPOSE" up -d 2>&1 | tail -1
burn 12
purge_pebble_store   # remove any stale ACME account/cert from a previous Pebble run

# --- Obtain a REAL ACME cert from Pebble ----------------------------------------------
issues0=$(pebble_issues)
code=$(get "$DOMAIN")
[ "$code" = "200" ] && ok "obtained+served '$DOMAIN' via the ACME CA (HTTP 200)" \
  || { bad "issuance failed (code=$code)"; caddy_has 'error|obtain' | tail -4; exit 1; }
caddy_has "certificate obtained successfully.*$DOMAIN|issuer.:.pebble" >/dev/null \
  && ok "cert came from the Pebble ACME issuer (a real ACME order, not the internal CA)" \
  || bad "could not confirm the cert came from the ACME issuer"

# --- ARI fetch observed ---------------------------------------------------------------
if caddy_has "got renewal info.*$DOMAIN" >/dev/null; then
  ok "certmagic FETCHED ARI renewalInfo for '$DOMAIN' (renewal window obtained from the CA)"
  caddy_has "got renewal info.*$DOMAIN" | tail -1 | sed 's/^/    /'
else
  bad "no ARI renewalInfo fetch observed (expected 'got renewal info')"
fi
caddy_has "ari_cert_id" >/dev/null \
  && ok "renewal decision is ARI-window-driven (certmagic logged ari_cert_id + window_start/window_end)" \
  || note "no ari_cert_id line yet — ARI window may be logged only at the renewal check"

# --- Advance RENEWAL fires, ARI-driven ------------------------------------------------
# An ON-DEMAND cert renews on next ACCESS once it enters its ARI window (renewal_cutoff),
# not purely via background maintenance — so we GET the domain each iteration to trigger
# the renewal check, and watch for a SECOND Pebble issuance (a new serial). certmagic
# renews while the old cert is still valid (renews-in-advance).
echo "driving the ARI-window renewal (GET each ~30s until certmagic renews) ..."
i=0; renewed=0
while [ "$i" -lt "$RENEW_BUDGET_TRIES" ]; do
  get "$DOMAIN" 20 >/dev/null           # each access re-checks renewal against the ARI window
  now=$(pebble_issues)
  if [ "${now:-0}" -gt "${issues0:-0}" ]; then renewed=1; break; fi
  burn 30; i=$((i+1))
done
if [ "$renewed" = "1" ]; then
  ok "cert RENEWED IN ADVANCE of expiry — Pebble issued a 2nd cert (issuances ${issues0} -> $(pebble_issues))"
  if caddy_has "certificate needs renewal based on ARI window.*$DOMAIN" >/dev/null; then
    ok "the renewal was explicitly ARI-WINDOW-DRIVEN (certmagic: 'certificate needs renewal based on ARI window')"
    caddy_has "certificate needs renewal based on ARI window.*$DOMAIN" | tail -1 | sed 's/^/    /'
  else
    bad "renewal fired but no 'needs renewal based on ARI window' line — was it ARI-driven?"
  fi
  docker logs "$PEBBLE_CTR" 2>&1 | grep "Issued certificate serial" | sed 's/^/    /'
else
  bad "no advance renewal observed within budget (Pebble issuances still ${issues0})"
fi

note "ARI EXEMPTION (renewal not consuming net-new order budget) is a Let's-Encrypt-account property and is NOT reproducible here — Pebble has no rate-limit budget. That half stays gated on the real LE issuer (task 4.6 remains open; design.md D4)."

echo
echo "task 4.6 ARI observation: $pass passed, $fail failed (plus [OBSERVE] notes)."
[ "$fail" -eq 0 ]
