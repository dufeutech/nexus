# Box handoff — verifying the signed `x-identity-contract`

Concrete values + checklist for a box (e.g. `evenout`) to verify the signed contract.
The full behavioral reference is `box-consumer-contract.md` §1a-bis; this page is the
short "what to pin and check" for the integration.

## Concrete values

| Thing | Value | Confirm before go-live |
|---|---|---|
| Header | `x-identity-contract` — a compact **ES256 JWS** (`header.payload.signature`) | — |
| `iss` | `https://identity.nexus` | ⚠️ **swap for the real public identity-plane host** and pin the exact string |
| `aud` | the box's **`x-route-pool`** value (what nexus routes to you as) | ⚠️ confirm the pool name for this box (e.g. `evenout` / `application`) |
| `exp` | short (~60s, minted per request) | verify with a small skew leeway (~60s) |
| `ctr` | contract version (currently `v1`) | reject unknown values |
| JWKS URL | `http://<identity-plane-host>:9210/.well-known/jwks.json` | ⚠️ confirm you have a **network path** to it (in-cluster Service DNS or public host) |
| Algorithm | ES256 (P-256) | your JWT lib must select the key by the JWS header `kid` |

Identity claims you may read from the verified token (mirror the headers):
`sub` (= `x-user-id`), `workspace_id` (= `x-workspace-id`), `role` (= `x-user-role`),
`roles`, `plan` (= `x-workspace-plan`). `plan` is the acting workspace's
**plan tier** (`workspace-plan-tier`), nexus-authored and signed into the token; it is
**omitted** (not defaulted) when no plan resolves — treat an absent `plan` as not-provisioned.

**Signed-only, no bare header (identity-revocation-integrity):** `roles`, **`entitlements`**
(string array), and **`suspended`** (bool) ride **only** the token now — the bare `x-user-roles` /
`x-user-entitlements` / `x-user-suspended` headers are **retired**. `entitlements`/`suspended` are
**omitted** when nexus has no resolved profile (and for a `service` principal): treat an absent
`suspended` as **unknown → fail safe, never `false`**; a `suspended: true` MUST hard-block.
**Do not cache the contract past its `exp`** — `exp` (~60s) is the revocation freshness bound, so a
just-suspended user is honored as suspended within the TTL. Re-read the next request's contract.

## Verification steps (per request, on an enriched route)

1. **Fetch + cache** the JWKS once; select the key by the token header's `kid`; refresh on
   an unknown `kid` (keys rotate with overlap).
2. **Verify the ES256 signature** against that key. Reject if it fails.
3. **Check claims:** `iss` == the pinned nexus issuer; `aud` == this box; `exp` in the
   future (with leeway); `ctr` is a version you understand. Reject on any mismatch.
4. **Absent or unverifiable on an enriched route → reject (fail closed).** nexus mints the
   token only for an authenticated member, so a non-member/anonymous request arrives with
   no token — that is a reject, not an anonymous pass (anonymous is only for your explicitly
   public/non-enriched routes).

## What does NOT change

- Most raw `x-user-*` / `x-workspace-*` headers are still emitted; you may read identity from
  the token or the headers — **except** the retired `x-user-roles` / `x-user-entitlements` /
  `x-user-suspended`, which are now token-only (read `roles`/`entitlements`/`suspended` from the
  verified claim; see *Concrete values* above).
- **Origin trust stays the primary control.** Keep your ingress restricted to the edge
  (NetworkPolicy) — the signature is defense-in-depth, not a replacement.

## Go-live checklist (nexus ↔ box)

- [ ] nexus: real issuer host decided; `SIGNING_ISSUER` set to it.
- [ ] nexus: keypair generated + JWKS published (`docs/runbook-contract-signing-keys.md`);
      `signing.enabled: true` with a valid key (a broken key fails the sidecar fast).
- [ ] box: JWKS URL reachable + cached; `iss`/`aud` pinned to the agreed values.
- [ ] box: verifies signature + `iss` + `aud` + `exp` + `ctr`; rejects absent/invalid on
      enriched routes.
- [ ] joint smoke test: `scripts/contract-signing-e2e.sh` (member token → verifiable JWS;
      anonymous → no token).
