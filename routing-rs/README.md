# routing-rs

The routing plane of [Nexus](https://github.com/dufeutech/nexus): a multi-tenant
request router with a Postgres-backed control plane and an optional Redis L2 cache.

## Members

| Crate | Description |
|-------|-------------|
| `router-core` | Core routing domain types. |
| `store-postgres` | PostgreSQL store adapter (authoritative, control-plane-written) + invalidation feed. |
| `cache-redis` | Optional shared L2 cache tier. |
| `dns-resolver` | DNS ownership-proof (TXT) resolver. |
| `tenant-router` | Per-tenant routing sidecar. |
| `control-plane` | Control-plane API. |

## License

MIT
