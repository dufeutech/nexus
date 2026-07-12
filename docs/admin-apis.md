# Admin APIs

Nexus has **no unified admin console** and **no OpenAPI/Swagger spec**. Administration
is done through **two independent, token-gated REST surfaces**, each fail-closed on its
own bearer token (constant-time compared; each process refuses to start without its
token unless auth is explicitly disabled):

| Surface | Plane | Port (in-cluster) | Token env | Authors… |
|---|---|---|---|---|
| **authz-admin** | identity | `9300` | `IDENTITY_ADMIN_TOKEN` | who a subject is *allowed to be* — roles, entitlements, suspension, customer API keys |
| **control-plane** | routing | `9400` | `CONTROL_AUTH_TOKEN` | tenancy & routing — accounts, workspaces, members, auth-routes, domains |

Two admin concerns are deliberately **not** HTTP APIs:

- **Signing-key rotation** → out-of-band via OpenBao Transit — see
  [`runbook-contract-signing-keys.md`](runbook-contract-signing-keys.md). The only HTTP
  surface is the *public* JWKS document (`GET /.well-known/jwks.json`, sidecar `:9210`).
- **Bootstrap admin** → not an endpoint. Set `AUTHZ_BOOTSTRAP_ADMIN_SUB`
  (Helm `authzAdmin.bootstrapAdminSub`): the subject is granted the admin role at startup
  **iff no admin exists yet** — idempotent break-glass. Rotate the bootstrap secret once a
  real admin has been authored.

Related runbooks: [`customer-api-keys-runbook.md`](customer-api-keys-runbook.md),
[`runbook-custom-domains-tls.md`](runbook-custom-domains-tls.md).

---

## Conventions

Set base URLs and tokens once. The examples use the in-cluster ports; the local compose
lab remaps authz-admin to host `:9303` (the tenant-router owns host `:9300`).

```sh
AUTHZ=https://authz.internal:9300           # lab: http://localhost:9303
CP=https://control-plane.internal:9400      # lab: http://localhost:9400
IDENTITY_ADMIN_TOKEN=…                       # authz-admin bearer
CONTROL_AUTH_TOKEN=…                          # control-plane bearer
```

- **Auth header** — always quote the whole value as ONE argument; an unquoted
  `Bearer $TOKEN` word-splits into an invalid header and silently 401s:
  ```sh
  -H "authorization: Bearer $IDENTITY_ADMIN_TOKEN"
  ```
- **No workspace header** on either surface.
- **Response envelope** — every success carries `"result":"ok"`; there are no typed
  response structs (responses are inline JSON), so fields are exactly as shown.
- **Auth failure** — missing/wrong token → `401 {"error":"unauthorized"}`.

---

## authz-admin (`:9300`, `IDENTITY_ADMIN_TOKEN`)

The single source of record for a subject's authorization. Grants are deny-by-default:
a subject nexus has no opinion about reads back as the zero value, not a 404.

### Read effective facts — `GET /authz/{sub}`

```sh
curl -s -H "authorization: Bearer $IDENTITY_ADMIN_TOKEN" \
  "$AUTHZ/authz/user-123"
```
```json
{ "sub": "user-123", "roles": ["admin"], "entitlements": ["billing:read"], "is_suspended": false }
```
Always `200`, even for an unknown subject (empty arrays, `is_suspended:false`).

### Assign / revoke a role

```sh
# assign
curl -s -H "authorization: Bearer $IDENTITY_ADMIN_TOKEN" -H 'content-type: application/json' \
  -X PUT "$AUTHZ/authz/user-123/roles" -d '{"role":"admin"}'
# revoke
curl -s -H "authorization: Bearer $IDENTITY_ADMIN_TOKEN" \
  -X DELETE "$AUTHZ/authz/user-123/roles/admin"
```
`{"role":"..."}` required. Success `200 {"result":"ok"}`.

### Grant / revoke an entitlement

```sh
# grant
curl -s -H "authorization: Bearer $IDENTITY_ADMIN_TOKEN" -H 'content-type: application/json' \
  -X PUT "$AUTHZ/authz/user-123/entitlements" -d '{"entitlement":"billing:read"}'
# revoke
curl -s -H "authorization: Bearer $IDENTITY_ADMIN_TOKEN" \
  -X DELETE "$AUTHZ/authz/user-123/entitlements/billing:read"
```
`{"entitlement":"..."}` required. Success `200 {"result":"ok"}`.

### Suspend / reactivate a subject

```sh
curl -s -H "authorization: Bearer $IDENTITY_ADMIN_TOKEN" -X POST "$AUTHZ/authz/user-123/suspend"
curl -s -H "authorization: Bearer $IDENTITY_ADMIN_TOKEN" -X POST "$AUTHZ/authz/user-123/reactivate"
```
No body. Success `200 {"result":"ok"}`.

### Customer API keys — `POST /apikeys`, `/apikeys/{key_id}/rotate`, `/revoke`

> Requires `APIKEY_HMAC_PEPPER` to be set on the service. Unset → all three endpoints
> return `503 {"error":"api key management not configured"}`. See
> [`customer-api-keys-runbook.md`](customer-api-keys-runbook.md).

```sh
# issue — the plaintext secret is returned ONCE, in "secret". Store it now.
curl -s -H "authorization: Bearer $IDENTITY_ADMIN_TOKEN" -H 'content-type: application/json' \
  -X POST "$AUTHZ/apikeys" \
  -d '{"creator_sub":"user-123","scopes":["ws-1"],"expires_in_seconds":3600}'
```
```json
{ "key_id": "…", "secret": "<plaintext-once>", "expires_at": 1700000000 }
```
- `creator_sub` **required**.
- `scopes` = the workspace ids the key may act on; effectively **required** (empty/absent →
  `400`), and each must be a workspace the creator is a *live member* of.
- `expires_in_seconds` optional (`i64`); omit for a non-expiring key (`expires_at: null`).
- Success `201`.

```sh
# rotate — no body; issues a new secret, revokes the old, keeps scopes. 201, same shape.
curl -s -H "authorization: Bearer $IDENTITY_ADMIN_TOKEN" -X POST "$AUTHZ/apikeys/$KEY_ID/rotate"
# revoke — no body; idempotent. 200 {"result":"ok","revoked":true}
curl -s -H "authorization: Bearer $IDENTITY_ADMIN_TOKEN" -X POST "$AUTHZ/apikeys/$KEY_ID/revoke"
```

---

## control-plane (`:9400`, `CONTROL_AUTH_TOKEN`)

Tenancy and routing. `/tenants*` is a **deprecated** account-less alias — use `/workspaces*`.

### Provision an account — `POST /accounts`

```sh
curl -s -H "authorization: Bearer $CONTROL_AUTH_TOKEN" -H 'content-type: application/json' \
  -X POST "$CP/accounts" \
  -d '{"account_id":"acct-1","owner_sub":"user-123","name":"Acme","payer_ref":"stripe_cus_x"}'
```
- `account_id`, `owner_sub` **required** (owner becomes the first member); `name`, `payer_ref` optional.
- Success `200 {"result":"ok","account_id":"acct-1","created":true}` (`created:false` on idempotent repeat).
- Read back: `GET /accounts/acct-1`.

### Upsert a workspace — `POST /workspaces`

```sh
curl -s -H "authorization: Bearer $CONTROL_AUTH_TOKEN" -H 'content-type: application/json' \
  -X POST "$CP/workspaces" \
  -d '{"workspace_id":"ws-1","account_id":"acct-1","plan":"pro","target_pool":"application","features":["beta"]}'
```
- `workspace_id`, `target_pool` **required** (`target_pool` must be in the pool allow-list, else `400`).
- `account_id` optional — the owning account (must exist, else `404 unknown_account`); omit on a
  config-only update to leave ownership unchanged. `plan` optional (default `"free"`); `features` optional.
- **No `name`/`owner` field** — ownership changes go through `/transfer`.
- Success `200 {"result":"ok","workspace_id":"ws-1"}`. Read back: `GET /workspaces/ws-1`.

### Transfer a workspace — `POST /workspaces/{id}/transfer`

```sh
curl -s -H "authorization: Bearer $CONTROL_AUTH_TOKEN" -H 'content-type: application/json' \
  -X POST "$CP/workspaces/ws-1/transfer" -d '{"account_id":"acct-2"}'
```
`account_id` required (must exist). Success `200 {"result":"ok","workspace_id":"ws-1","account_id":"acct-2","staff_removed":3}`.

### Members — `GET/PUT /workspaces/{id}/members`, `DELETE …/{sub}`

```sh
# upsert
curl -s -H "authorization: Bearer $CONTROL_AUTH_TOKEN" -H 'content-type: application/json' \
  -X PUT "$CP/workspaces/ws-1/members" \
  -d '{"user_sub":"user-123","member_type":"staff","role":"admin","status":"active"}'
# list / remove
curl -s -H "authorization: Bearer $CONTROL_AUTH_TOKEN" "$CP/workspaces/ws-1/members"
curl -s -H "authorization: Bearer $CONTROL_AUTH_TOKEN" -X DELETE "$CP/workspaces/ws-1/members/user-123"
```
- `user_sub`, `member_type` **required**; `member_type` ∈ {`staff`,`customer`} (else `400 invalid_member_type`).
- `role` optional (default `"member"`); `status` optional (default `"active"`).
- Success `200 {"result":"ok","workspace_id":"ws-1","user_sub":"user-123"}`.

### Auth-routes — `GET/PUT/DELETE /workspaces/{id}/auth-routes`

Per-workspace route rules the edge enforces.

```sh
curl -s -H "authorization: Bearer $CONTROL_AUTH_TOKEN" -H 'content-type: application/json' \
  -X PUT "$CP/workspaces/ws-1/auth-routes" \
  -d '{"path_prefix":"/admin","auth_required":true,"requires_role":"admin","requires_entitlement":"billing","min_aal":2,"account_scoped":false}'
# delete a rule
curl -s -H "authorization: Bearer $CONTROL_AUTH_TOKEN" -H 'content-type: application/json' \
  -X DELETE "$CP/workspaces/ws-1/auth-routes" -d '{"path_prefix":"/admin"}'
```
- `path_prefix` **required** (must start with `/`), `auth_required` **required** (bool).
- `requires_role`, `requires_entitlement` (nullable strings), `min_aal` (`u8`), `account_scoped`
  (bool, default false) all optional. Any requirement with `auth_required:false` → `400 requirements_need_auth`.
- `account_scoped:true` existence-hides non-members as `404` *before* the role gate — set it on
  tenant-scoped routes so a non-member can't probe for the route's existence.
- Success `200` echoing the stored rule.

### Custom domains — `POST /domains`, `/domains/declare`, `/domains/{domain}/verify`, `DELETE`

The owner field is spelled **`tenant_id`** (= workspace id). A domain only routes once
**verified**; `POST /domains` always creates it `verified:false`. The normal path is
declare → publish the TXT record → verify. Full operational context:
[`runbook-custom-domains-tls.md`](runbook-custom-domains-tls.md).

```sh
# 1. declare — returns the DNS proof record to publish
curl -s -H "authorization: Bearer $CONTROL_AUTH_TOKEN" -H 'content-type: application/json' \
  -X POST "$CP/domains/declare" -d '{"tenant_id":"ws-1","domain":"shop.example.com"}'
```
```json
{
  "result": "ok", "domain": "shop.example.com", "verified": false,
  "dns_record": { "name": "_nexus-challenge.shop.example.com", "type": "TXT", "value": "<token>" }
}
```
```sh
# 2. publish the TXT record at your DNS provider, then:
curl -s -H "authorization: Bearer $CONTROL_AUTH_TOKEN" \
  -X POST "$CP/domains/shop.example.com/verify"
```
```json
{ "result": "ok", "domain": "shop.example.com", "verified": true }
```
```sh
# remove
curl -s -H "authorization: Bearer $CONTROL_AUTH_TOKEN" -X DELETE "$CP/domains/shop.example.com"
```
- **declare** errors: `400 invalid_domain`, `404 unknown_tenant`, `409 domain_taken`,
  `402 quota_exceeded {plan,limit,used}`. Already-verified → `200 {…,"verified":true}` (no `dns_record`).
- **verify** errors: `404 no_challenge`, `410 challenge_expired`, `422 proof_not_found`, `503 resolution_failed`.
- `POST /domains` (direct upsert) takes `{"domain","tenant_id","wildcard":false}` and always
  returns `verified:false` — declare→verify is what makes a domain route.

---

## Health / metrics (not admin)

Health endpoints are **open by design** (kubelet probes; no secrets, no mutation):

| Endpoint | Port |
|---|---|
| `GET /healthz` | authz-admin `9300`, control-plane admin `9400` & ops `9401`, tenant-router `9300`, sidecar `9200` |
| `GET /.well-known/jwks.json` | sidecar `9210` (public verification keys) |

There is **no `/metrics` endpoint** — telemetry is pushed over OTLP to a collector, not scraped.

---

## Quick smoke test

[`../scripts/go-live-smoke.sh`](../scripts/go-live-smoke.sh) exercises both surfaces
(reachability, fail-closed auth, and — opt-in — a grant→effect→revoke round-trip), and doubles
as a live check that these endpoints behave as documented.
