# identity-rs

The identity plane of [Nexus](https://github.com/dufeutech/nexus): a multi-tenant
identity and authorization service.

## Members

| Crate | Description |
|-------|-------------|
| `identity-core` | Core identity domain types and reconciliation logic. |
| `store-postgres` | PostgreSQL store adapter (authoritative store + LISTEN/NOTIFY change feed). |
| `identity-sidecar` | Envoy `ext_authz` sidecar serving identity decisions. |
| `sync-worker` | Worker that syncs identity profile changes. |
| `reconciler` | Reconciliation worker. |

## License

MIT
