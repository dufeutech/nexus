# compose/secrets/

The sync-worker and reconciler mount this directory read-only at `/secrets` and
read the ZITADEL admin service-account PAT from `zitadel-admin-sa.pat`.

Place the real token here (the file is gitignored):

```
printf '%s' '<your-zitadel-admin-sa-PAT>' > zitadel-admin-sa.pat
```

This PAT can register webhooks and list every user — treat it as a high-privilege
secret. In a hardened deployment, source it from your secret manager (Vault,
Docker/Swarm secrets) rather than a file on disk.
