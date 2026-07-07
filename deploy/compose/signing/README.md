# Compose signing material (identity-contract-signing)

This directory is bind-mounted into the identity sidecar at `/etc/nexus/signing` (read
only). It is **empty by default** so `docker compose up` works with signing disabled.

To enable signed `x-identity-contract` locally, generate a keypair per
`docs/runbook-contract-signing-keys.md` and drop the two files here:

- `key.pem` — the ES256 PKCS#8 private key (the secret)
- `jwks.json` — the public JWKS document (served on `:9210`)

Then set, in your `.env` or shell:

```sh
SIGNING_KEY_PATH=/etc/nexus/signing/key.pem
SIGNING_KID=<the kid in jwks.json>
JWKS_FILE=/etc/nexus/signing/jwks.json
```

**Never commit `key.pem`** (or any real private key). Only this README is tracked.
