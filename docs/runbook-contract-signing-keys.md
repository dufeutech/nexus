# Runbook — identity-contract signing keys (identity-contract-signing)

The identity sidecar signs `x-identity-contract` as an **ES256** JWS. The private key is
a runtime secret held only by the identity plane; the public key is published as a JWKS
document that boxes fetch and verify against. This runbook covers **generating** the
keypair and **rotating** it with zero downtime.

The sidecar never derives the public key from the private one — you supply **both**
(the private PEM and the public JWKS JSON), generated together here. Keep the two in
sync: the JWKS `kid` MUST equal the sidecar's `SIGNING_KID`.

## Configuration (sidecar env)

| Var | Meaning | Example |
|-----|---------|---------|
| `SIGNING_KEY_PATH` | Path to the mounted **private** PEM (secret). Unset → signing disabled. | `/etc/nexus/signing/key.pem` |
| `SIGNING_KID` | Key id; MUST match the JWKS entry's `kid` and rides in the JWS header. | `nexus-2026-07` |
| `SIGNING_ISSUER` | The `iss` claim; boxes pin this exact string. | `https://identity.nexus` |
| `CONTRACT_TOKEN_TTL_SECONDS` | Token lifetime (short — minted per request). | `60` |
| `JWKS_FILE` | Path to the mounted **public** JWKS JSON (served verbatim). | `/etc/nexus/signing/jwks.json` |
| `JWKS_LISTEN` | Dedicated public JWKS listener bind. | `0.0.0.0:9210` |

`aud` is not configured — it is derived per request from `x-route-pool` (the destination
box), so a token minted for one box cannot be replayed at another.

## Generate a keypair (`KID` = the new key id)

```sh
KID="nexus-$(date +%Y-%m)"          # e.g. nexus-2026-07 — pass the date in; do not hard-code

# 1) Private key — EC P-256, PKCS#8 PEM. This is the SECRET (mount as key.pem).
openssl ecparam -genkey -name prime256v1 -noout \
  | openssl pkcs8 -topk8 -nocrypt -out key.pem

# 2) Public JWK coordinates (x, y) as base64url, from the private key.
PUBHEX=$(openssl pkey -in key.pem -pubout \
  | openssl pkey -pubin -text -noout \
  | sed -n '/pub:/,/ASN1 OID/p' | tr -d ' \n:' | sed 's/pub//; s/ASN1OID.*//')
b64url() { xxd -r -p | base64 | tr '+/' '-_' | tr -d '='; }
X=$(printf '%s' "${PUBHEX:2:64}" | b64url)
Y=$(printf '%s' "${PUBHEX:66:64}" | b64url)

# 3) Public JWKS document (served verbatim; NOT secret). kid MUST equal SIGNING_KID.
printf '{"keys":[{"kty":"EC","crv":"P-256","alg":"ES256","use":"sig","kid":"%s","x":"%s","y":"%s"}]}\n' \
  "$KID" "$X" "$Y" > jwks.json
```

Deliver `key.pem` as a Secret and `jwks.json` as config; set `SIGNING_KID=$KID`.

## Rotate with zero downtime (overlap window)

The order matters — **publish the new public key before signing with it**, and keep the
old one until its last token has expired:

1. Generate a new keypair with a new `KID` (above).
2. **Add** the new JWK to `jwks.json` so it has BOTH keys (a two-entry `keys` array), and
   roll the JWKS out first. Boxes now accept either key.
3. Swap the sidecar's `SIGNING_KEY_PATH`/`SIGNING_KID` to the new key and roll it out.
   New tokens carry the new `kid`; boxes already trust it.
4. After `CONTRACT_TOKEN_TTL_SECONDS` (plus clock-skew leeway) has passed, **remove** the
   old JWK from `jwks.json` and roll out. No in-flight token references it any more.

Rollback at any step is safe: because network origin-trust is unchanged underneath,
reverting the sidecar to the previous key (or disabling signing) never regresses the
existing security guarantee — the `x-user-*` headers are still emitted.

## Verify

- `GET http://<identity-plane>:9210/.well-known/jwks.json` returns the document with the
  expected `kid`(s).
- A live enriched request to a data door carries an `x-identity-contract` JWS whose header
  `kid` is present in the JWKS and whose `iss`/`aud`/`exp` verify.
