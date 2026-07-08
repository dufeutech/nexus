# Customer API keys (Personal Access Tokens) — operations runbook

**Audience:** operators of the nexus identity plane. This is the how-to for the
`customer-api-keys` capability: issuing, rotating, and revoking a Personal Access Token (PAT), how a
key is presented and resolved, and the configuration + security model. Behavioral authority lives in
`openspec/specs/customer-api-keys`.

## What a PAT is

A long-lived customer-automation credential (scripts, CI/CD, customer backends) that acts **on behalf
of** a human, bounded by the key's scopes. It is neither a human OIDC session nor a core-platform
service identity — it is the third principal kind (`apikey`).

- **Effective authority = the creating user's LIVE workspace memberships ∩ the key's scopes.** A key can
  never exceed its creator and follows the creator's revocation (least-privilege, fail-closed).
- **Secrets are stored hashed, never in plaintext.** The store holds only `HMAC-SHA256(pepper, secret)`;
  the plaintext is shown exactly once, at issuance.
- **Revocation and expiry are live.** The sidecar resolves each key with a fresh, filtered query, so a
  revoked/expired key (or a key whose creator lost the membership) is rejected on its **next request**.

## Configuration

| Component | Env var | Purpose |
| --- | --- | --- |
| identity-sidecar | `APIKEY_PG_RO_URL` | SELECT-only URL to the api-key store (the identity DB). **Set enables** api-key resolution. |
| identity-sidecar | `APIKEY_HMAC_PEPPER` | The server-held HMAC key. **Must match authz-admin's.** Unset ⇒ api-key auth OFF. |
| authz-admin | `APIKEY_HMAC_PEPPER` | Same pepper — used to hash secrets at issuance. Unset ⇒ the `/apikeys` endpoints answer 503. |
| authz-admin | `PROFILE_PG_URL` | Read-write identity DB; the api-key store shares it and owns idempotent schema setup. |

> **The pepper is a secret.** Provision it from a Secret (not committed), rotate it deliberately, and
> keep the sidecar's and authz-admin's values identical — a mismatch makes every key fail to verify
> (fail-closed). Because the pepper keys the stored hash, a stolen database alone cannot brute-force
> secrets.

The `identity.api_keys` table is created idempotently by authz-admin at startup; the canonical DDL is
`identity-rs/store-postgres/migrations/0002_api_keys.sql` (and `postgres-init/30-api-keys.sql` for the
compose lab). Keep the three in lockstep.

## Lifecycle — authz-admin endpoints

All endpoints require the admin bearer token (`IDENTITY_ADMIN_TOKEN`), like the rest of authz-admin.
Issuance is human-scoped: the endpoint records the creating user and enforces that the requested scopes
are a subset of that user's live memberships (a key may not exceed its creator).

### Issue

```sh
curl -sS -X POST "$AUTHZ_ADMIN/apikeys" \
  -H "authorization: Bearer $IDENTITY_ADMIN_TOKEN" \
  -H 'content-type: application/json' \
  -d '{"creator_sub":"<zitadel-sub>","scopes":["<workspace-id>"],"expires_in_seconds":2592000}'
# -> 201 { "key_id": "pak_…", "secret": "nexus_pat_…", "expires_at": <epoch|null> }
```

The `secret` is returned **once** — capture it now; it is never recoverable. `scopes` is a list of
workspace ids (at least one, each a workspace the creator is a live member of). Omit
`expires_in_seconds` for a non-expiring key.

### Rotate

```sh
curl -sS -X POST "$AUTHZ_ADMIN/apikeys/<key_id>/rotate" \
  -H "authorization: Bearer $IDENTITY_ADMIN_TOKEN"
# -> 201 { "key_id": "pak_<new>", "secret": "nexus_pat_<new>", "expires_at": … }
```

Mints a new secret under a preserved lineage (`rotated_from`) with the **same** scopes and expiry (no
widening) and revokes the old key. Swap the automation to the new secret, then the old one is already
dead. `404` if the key id is not an active key.

### Revoke

```sh
curl -sS -X POST "$AUTHZ_ADMIN/apikeys/<key_id>/revoke" \
  -H "authorization: Bearer $IDENTITY_ADMIN_TOKEN"
# -> 200 { "result": "ok", "revoked": true|false }
```

Idempotent (`revoked: false` if it was already revoked/unknown). The sidecar rejects the key on its
next request.

## Presenting a key (the client side)

The client sends the secret in the dedicated **`x-api-key`** request header (a PAT is not a JWT, so it
does not go in `Authorization`):

```sh
curl "$EDGE/some/route" -H "x-api-key: nexus_pat_…"
```

The sidecar hashes it, resolves the live key, intersects the creator's membership with the key's
scopes, and — on success — mints a signed contract with `principal_kind: apikey`, the key id as `sub`,
and `on_behalf_of` = the creating user (see `docs/box-consumer-contract.md` §1a-ter). The raw
`x-api-key` is stripped before the backend. A revoked/expired/out-of-scope key resolves to no
authority: no contract, request rejected (fail-closed).

## Audit

Every key-authenticated request logs **both** the key id and the creating user (`on_behalf_of`) — never
the secret — so an action is attributable to the human behind the automation. Issuance/rotation/
revocation are logged (by key id) and counted (`authz_admin_mutations{op=issue_api_key|…}`).

## Troubleshooting

- **Every key fails to verify** → the sidecar's and authz-admin's `APIKEY_HMAC_PEPPER` differ, or the
  sidecar's `APIKEY_PG_RO_URL` is unset. A pepper mismatch means the stored hash can never match.
- **`/apikeys` returns 503** → authz-admin has no `APIKEY_HMAC_PEPPER` (key management disabled).
- **A valid key is suddenly rejected** → the creator lost the membership the key's scope names
  (revocation cascades), or the key expired/was revoked. This is the intended least-privilege behavior.
- **Issue returns 400 "scope … exceeds the creator's memberships"** → the requested workspace is not one
  the creator is a live member of. Grant the membership first, or scope the key narrower.
