#!/usr/bin/env sh
# Shared provisioning helpers (server-minted-ids): nexus mints workspace/account
# ids (`ws_<uuidv7>` / `acct_<uuidv7>`), so fixtures and e2e scripts can no longer
# hard-code an id like `acme`. Instead, every caller provisions through these
# helpers with a STABLE IDEMPOTENCY KEY: the first call creates, every later call
# with the same key replays and receives the ORIGINAL id (provisioning-idempotency).
# That replay IS the lookup — the seed and the e2e scripts share a key (e.g.
# `seed:acme`) and therefore always converge on the same workspace.
#
# POSIX sh + curl + sed only (no jq): the compose seed runs in curlimages/curl,
# which has no jq — sed keeps ONE code path for the container and the host.
#
# Callers set:
#   CP                  control-plane admin base URL (e.g. http://localhost:9400)
#   CONTROL_AUTH_TOKEN  admin bearer (lab default: zitadel-lab-dev-token)

# Extract a top-level string field from a one-object JSON response.
# $1 = field name, stdin = JSON. Emits nothing if absent.
nexus_json_field() {
  sed -n "s/.*\"$1\":\"\([^\"]*\)\".*/\1/p"
}

# Fail loudly: provisioning is the fixture bedrock — a silent empty id would
# cascade into baffling downstream failures (server-minted-ids risk note).
nexus_provision_die() {
  echo "provision-lib: $1" >&2
  exit 1
}

# nexus_provision_account KEY OWNER_SUB NAME -> prints the acct_… id.
# Replay-safe: same KEY always returns the same account.
nexus_provision_account() {
  _key=$1 _owner=$2 _name=$3
  _resp=$(curl -sf -H "content-type: application/json" \
    -H "authorization: Bearer $CONTROL_AUTH_TOKEN" \
    -X POST "$CP/accounts" \
    -d "{\"owner_sub\":\"$_owner\",\"name\":\"$_name\",\"idempotency_key\":\"$_key\"}") \
    || nexus_provision_die "POST /accounts failed for key '$_key'"
  _id=$(printf '%s' "$_resp" | nexus_json_field account_id)
  [ -n "$_id" ] || nexus_provision_die "no account_id in response for key '$_key': $_resp"
  printf '%s\n' "$_id"
}

# nexus_provision_workspace KEY NAME PLAN POOL FEATURES_JSON [ACCOUNT_ID]
#   -> prints the ws_… id. FEATURES_JSON is a JSON array (e.g. '["beta"]').
# Replay-safe: same KEY always returns the same workspace.
nexus_provision_workspace() {
  _key=$1 _name=$2 _plan=$3 _pool=$4 _features=$5 _account=${6:-}
  _acct_field=""
  [ -n "$_account" ] && _acct_field=",\"account_id\":\"$_account\""
  _resp=$(curl -sf -H "content-type: application/json" \
    -H "authorization: Bearer $CONTROL_AUTH_TOKEN" \
    -X POST "$CP/workspaces" \
    -d "{\"name\":\"$_name\",\"plan\":\"$_plan\",\"target_pool\":\"$_pool\",\"features\":$_features,\"idempotency_key\":\"$_key\"$_acct_field}") \
    || nexus_provision_die "POST /workspaces failed for key '$_key'"
  _id=$(printf '%s' "$_resp" | nexus_json_field workspace_id)
  [ -n "$_id" ] || nexus_provision_die "no workspace_id in response for key '$_key': $_resp"
  printf '%s\n' "$_id"
}

# The lab fixtures every e2e script builds on (same keys as the compose seed —
# replaying them here resolves the SAME workspaces the seed created).
# Sets: ACME_WS, GLOBEX_WS.
nexus_resolve_lab_workspaces() {
  ACME_WS=$(nexus_provision_workspace "seed:acme" "Acme (lab)" pro application '["beta"]') || exit 1
  GLOBEX_WS=$(nexus_provision_workspace "seed:globex" "Globex (lab)" enterprise api '[]') || exit 1
}
