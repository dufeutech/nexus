# Runbook — identity-contract signing keys (identity-contract-signing)

The identity sidecar signs `x-identity-contract` as an **ES256** JWS. The private key is a
runtime secret held only by the identity plane; the public key is published as a JWKS
document that boxes fetch and verify against.

Since **automate-signing-key-rotation** the key lifecycle is **automated** via **OpenBao
Transit** — generation, overlap rotation, and retirement happen with **no manual runbook**.
The plane pulls key material and signs **locally** (Mode B), and the JWKS is **generated**
from Transit's public keys (no hand-synced `kid` ↔ JWKS step to drift). The manual PEM flow
below is retained as a **break-glass fallback** only.

## 1. Automated rotation via OpenBao Transit (the normal path)

### How it works

- The Transit key is `ecdsa-p256` with `exportable=true`. **Each Transit key version is a
  `kid`.** The sidecar exports the latest version's private key to sign locally, and
  exports every published version's public key to build `/.well-known/jwks.json`.
- On rotation the plane cuts the active signer over to the new version and keeps the
  previous key **published for an overlap window** = `CONTRACT_TOKEN_TTL_SECONDS` +
  `CONTRACT_MAX_CLOCK_SKEW_SECONDS`, so no in-flight token is rejected. After the window
  the old key drops from the JWKS automatically.
- The plane discovers rotations by **polling** (`SIGNING_KEY_POLL_SECONDS`), so a rotation
  triggered at the source — Transit auto-rotate, a plane-side schedule, or an operator on
  suspected compromise — is adopted within one poll interval with **no hand-editing**.

### Configuration (sidecar env)

| Var | Meaning | Example |
|-----|---------|---------|
| `SIGNING_TRANSIT_KEY` | Transit key name; presence enables the managed path. | `identity-contract-signing` |
| `SIGNING_TRANSIT_MOUNT` | Transit engine mount. | `transit` |
| `BAO_ADDR` / `VAULT_ADDR` | OpenBao API URL. | `http://openbao.openbao:8200` |
| `BAO_TOKEN` / `VAULT_TOKEN` | The plane's OpenBao token (a least-privilege role). | *(from a Secret)* |
| `SIGNING_ISSUER` | The `iss` claim; boxes pin this exact string. | `https://identity.nexus` |
| `CONTRACT_TOKEN_TTL_SECONDS` | Token lifetime (short — minted per request). | `60` |
| `CONTRACT_MAX_CLOCK_SKEW_SECONDS` | Skew budget; overlap = TTL + this. | `60` |
| `SIGNING_KEY_POLL_SECONDS` | How fast a source rotation is adopted. | `30` |
| `SIGNING_ROTATION_PERIOD_SECONDS` | Optional plane-driven rotation cadence. Unset ⇒ source-driven only. | `86400` |
| `JWKS_LISTEN` | Dedicated public JWKS listener bind. | `0.0.0.0:9210` |

`aud` is not configured — it is derived per request from `x-route-pool` (the destination
box), so a token minted for one box cannot be replayed at another.

### Provision the Transit key (once)

The plane's token needs a policy that can, on this one key only: `read` the key, `export`
the `public-key` and `signing-key`, and (if the plane drives rotation) `rotate`.

```sh
# Enable Transit and create the exportable signing key (Mode B — local signing).
bao secrets enable -path=transit transit
bao write -f transit/keys/identity-contract-signing type=ecdsa-p256 exportable=true

# Least-privilege policy for the identity plane.
bao policy write identity-signing - <<'EOF'
path "transit/keys/identity-contract-signing"                 { capabilities = ["read"] }
path "transit/export/public-key/identity-contract-signing/*"  { capabilities = ["read"] }
path "transit/export/signing-key/identity-contract-signing/*" { capabilities = ["read"] }
path "transit/keys/identity-contract-signing/rotate"          { capabilities = ["update"] }
EOF
```

In production bind that policy to a **Kubernetes-auth role** for the plane's service
account rather than issuing a static token. Locally, `deploy/compose/signing/transit-init.sh`
does the enable + key create against the bundled dev OpenBao.

### Rotate

- **Scheduled:** set `SIGNING_ROTATION_PERIOD_SECONDS` (plane-driven), or configure Transit
  `auto_rotate_period` on the key. Nothing else to do — the plane publishes the new `kid`,
  signs with it, and retires the old one after the overlap window.
- **On demand (suspected compromise):** rotate at the source; the plane adopts it on its
  next poll.

  ```sh
  bao write -f transit/keys/identity-contract-signing/rotate
  ```

Rollback is safe at any point: reverting to a prior key (or to break-glass) never regresses
the guarantee — the `x-user-*` headers are still emitted, and boxes trust whatever `kid`s
the JWKS currently publishes.

## 2. Break-glass fallback (manual PEM)

If OpenBao is unreachable at startup the plane falls back to a manual PEM (fail loud, never
unsigned). It is also the path for environments not yet running OpenBao. Provide **both**
the private PEM and the public JWKS (the sidecar does not derive one from the other on this
path); the JWKS `kid` MUST equal `SIGNING_KID`.

| Var | Meaning | Example |
|-----|---------|---------|
| `SIGNING_KEY_PATH` | Path to the mounted **private** PEM (secret). | `/etc/nexus/signing/key.pem` |
| `SIGNING_KID` | Key id; MUST match the JWKS entry's `kid`. | `nexus-2026-07` |
| `JWKS_FILE` | Path to the mounted **public** JWKS JSON (served verbatim). | `/etc/nexus/signing/jwks.json` |

```sh
KID="nexus-$(date +%Y-%m)"          # pass the date in; do not hard-code

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

Manual zero-downtime rotation follows the same overlap discipline the automation enforces:
**publish the new public key before signing with it**, and keep the old one until its last
token has expired — (1) generate a new `KID`; (2) add its JWK to `jwks.json` (a two-entry
`keys` array) and roll out first; (3) swap `SIGNING_KEY_PATH`/`SIGNING_KID` and roll out;
(4) after `CONTRACT_TOKEN_TTL_SECONDS` + clock-skew leeway, remove the old JWK and roll out.

## Verify

- `GET http://<identity-plane>:9210/.well-known/jwks.json` returns the document with the
  expected `kid`(s) — two during an overlap window.
- A live enriched request to a data door carries an `x-identity-contract` JWS whose header
  `kid` is present in the JWKS and whose `iss`/`aud`/`exp` verify.
- Across a rotation: the JWKS shows the new `kid` (alongside the old for the overlap
  window), fresh tokens carry the new `kid`, and a token minted just before cut-over still
  verifies until it expires.
