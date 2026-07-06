# identity-rs

The identity plane of [Nexus](https://github.com/dufeutech/nexus): a multi-tenant
identity and authorization service.

## Members

| Crate | Description |
|-------|-------------|
| `identity-core` | Core identity domain types + the authorization ports (`AuthzResolver`/`AuthzAuthoring`). |
| `store-postgres` | PostgreSQL store adapter (authoritative store + LISTEN/NOTIFY change feed; nexus-native authz adapter). |
| `identity-sidecar` | Envoy `ext_proc` sidecar serving identity + nexus-authored authorization decisions. |
| `authz-admin` | Nexus-native authorization authoring surface (roles/entitlements/suspension). |
| `membership-sync` | Projects routing-plane memberships into `Profile.memberships`. |

## License

MIT
