# Compose signing material (identity-contract-signing)

The signed `x-identity-contract` can be produced two ways. See
`docs/runbook-contract-signing-keys.md` for the full flow.

## 1. OpenBao Transit — managed, automated rotation (recommended)

Key custody + rotation live in OpenBao; the sidecar pulls key material and signs locally
(Mode B), and the public JWKS is **generated** from Transit — there is no `jwks.json` to
hand-sync. A bundled dev OpenBao ships behind the `signing` compose profile.

```sh
# from deploy/compose/
docker compose --profile signing up -d openbao          # dev OpenBao (in-memory, root token)
BAO_ADDR=http://127.0.0.1:8200 BAO_TOKEN=root ./signing/transit-init.sh
```

Then set, in your `.env` or shell, and (re)start the sidecar:

```sh
SIGNING_TRANSIT_KEY=identity-contract-signing
BAO_ADDR=http://openbao:8200     # the in-network address the sidecar reaches Bao at
BAO_TOKEN=root
# optional: SIGNING_ROTATION_PERIOD_SECONDS=86400  (plane-driven daily rotation)
```

Rotate on demand (suspected compromise) — the sidecar adopts it on the next poll and keeps
the old key published for the overlap window:

```sh
docker compose exec openbao bao write -f transit/keys/identity-contract-signing/rotate
```

> The dev OpenBao is **in-memory and unsealed with a root token — never a production
> posture.** In production run OpenBao properly (sealed, Kubernetes-auth role scoped to
> export/rotate this one key) and inject `BAO_TOKEN` from that role.

## 2. Break-glass manual PEM (fallback)

This directory is bind-mounted into the sidecar at `/etc/nexus/signing` (read only). It is
**empty by default**. To sign from a manual key (also the Transit-mode startup fallback if
Bao is unreachable), generate a keypair per the runbook and drop the two files here:

- `key.pem` — the ES256 PKCS#8 private key (the secret)
- `jwks.json` — the public JWKS document (served on `:9210`)

Then set:

```sh
SIGNING_KEY_PATH=/etc/nexus/signing/key.pem
SIGNING_KID=<the kid in jwks.json>
JWKS_FILE=/etc/nexus/signing/jwks.json
```

**Never commit `key.pem`** (or any real private key). Only this README + `transit-init.sh`
are tracked.
