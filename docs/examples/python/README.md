# Python examples

Hand-written examples for the two token-gated admin surfaces. The prose
reference (per-endpoint semantics, error codes) is [`../../admin-apis.md`](../../admin-apis.md);
the machine-readable specs are in [`../../openapi/`](../../openapi/README.md) — if you
want a full generated client instead of these thin adapters, use
openapi-generator as described there.

| File | Shows |
|---|---|
| [`nexus_client.py`](nexus_client.py) | Thin clients for both surfaces: bearer auth, error handling, audit pagination, NDJSON export |
| [`example_onboarding.py`](example_onboarding.py) | Account → workspace → member → auth-route, with idempotency keys |
| [`example_authz.py`](example_authz.py) | Roles, entitlements, suspension, customer API keys |
| [`example_domains.py`](example_domains.py) | Custom domain declare → publish TXT → poll verify |
| [`example_audit.py`](example_audit.py) | Query the audit ledger with cursor pagination; cross-plane NDJSON export/merge |
| [`example_admin_tokens.py`](example_admin_tokens.py) | Mint/list/rotate/revoke named admin credentials with scoped grants |
| [`box_server.py`](box_server.py) | A backend ("box") **receiving** requests from the edge: verifies the signed `x-identity-contract`, fails closed, ownership checks only |

## Setup

```sh
pip install httpx

# Local compose lab (authz-admin is remapped to host :9303 — the
# tenant-router owns host :9300; in-cluster it's :9300):
export AUTHZ_URL=http://localhost:9303
export CP_URL=http://localhost:9400
export IDENTITY_ADMIN_TOKEN=...     # authz-admin bearer
export CONTROL_AUTH_TOKEN=...      # control-plane bearer (named token secret)

python example_onboarding.py
```

## Conventions the client encodes

- **Bearer auth** on every data route; missing/wrong token → `401
  {"error":"unauthorized"}` (raised as `NexusError`, and a denial event lands
  in that surface's audit ledger). On the control plane, an authenticated
  caller whose grant lacks the route's scope gets `403 forbidden`.
- **Server-minted ids** — creates return `account_id`/`workspace_id`; capture
  them from the response, never invent one.
- **Idempotency keys** — pass `idempotency_key` on creates to make retries
  safe; a replay returns the original resource with `created: False`.
- **One-time secrets** — API-key and admin-token issue/rotate responses carry
  the plaintext secret exactly once. The examples deliberately never print it.
- **`x-acting-operator`** — pass `acting_operator=` to attribute mutations to
  a human in the audit ledger; it is recorded verbatim and never used for
  authentication or authorization.
- **Errors are typed** — `NexusError.code` holds the machine-readable `error`
  field (`domain_taken`, `quota_exceeded`, `last_token_admin`, ...); the
  examples branch on it rather than on prose.

## The other direction: receiving requests from nexus

The files above *call* nexus. `box_server.py` is the opposite side — a small
FastAPI backend sitting in a pool behind the edge, implementing the MUSTs of
[`../../box-consumer-contract.md`](../../box-consumer-contract.md): verify the
ES256-signed `x-identity-contract` against the nexus JWKS (`:9210`), check
`iss`/`aud`/`exp`/`ctr`, read entitlements and suspension from the verified
claims only, fail closed on enriched routes, and keep just the
resource-ownership checks the edge cannot do. Remember the prerequisite that
makes any of it safe: the box must be reachable **only through the edge**
(NetworkPolicy or equivalent).

```sh
pip install fastapi uvicorn "PyJWT[crypto]"
export NEXUS_JWKS_URL=http://localhost:9210/.well-known/jwks.json
export NEXUS_ISSUER=https://identity.nexus
export BOX_NAME=application        # the pool name nexus routes to you as
uvicorn box_server:app --port 8080
```
