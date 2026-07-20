## 1. Confirm decisions (`/opsx:decide`) and ordering

- [x] 1.1 Run `/opsx:decide` and record: D3 (Rent k8s Service), D5 (Extend `existingSecret` convention, delivery out-of-band), D6 (Adopt native PROXY-protocol, default off). Carry-over adopts (Caddy/CertMagic/postgres-storage from `custom-domains-tls`) reaffirmed, not re-litigated.
- [ ] 1.2 Confirm change ordering: this change packages the `custom-domains-tls` specs and MUST land after that change syncs to `openspec/specs/`; note the dependency for sync/archive.

## 2. Front-tier packaging in the `edge-platform` umbrella

- [x] 2.1 Vendor the existing `deploy/caddy/Caddyfile` into `edge-platform/files/caddy/` and render it as a ConfigMap via `tpl (.Files.Get …)` (the `.Files.Glob` pattern from `identity-policy-configmap.yaml:18` can't gate the opt-in PROXY block, so `tpl` is used; the vendored copy diverges from the compose source only by that one Helm-guarded block, mirroring the Cedar policy dual-copy) (D2).
- [x] 2.2 Pin `Host` preservation explicitly in the `Caddyfile` `reverse_proxy` rather than relying on Caddy's implicit default, so the parity spec's Host contract is test-visible (D8).
- [x] 2.3 Add the front-tier `Deployment` (image via the chart's tag-only convention, D7; containers bind `:443` and `:80`; mount `emptyDir{medium: Memory}` for the account-key path and Caddy data/config dirs to satisfy `readOnlyRootFilesystem` + `runAsNonRoot`, D5). Front tier adds `NET_BIND_SERVICE` (privileged ports); edge still drops ALL.
- [x] 2.4 Add the front-tier `Service` binding `:443` (and `:80`) as the customer-domain HTTPS entry point.
- [x] 2.5 Add `values.yaml` config following existing conventions: `frontTier.enabled` toggle, image repo/tag, and env (`AUTHORIZE_URL`, `EDGE_UPSTREAM` → edge `http`/`:80`, `ACME_CA_DIR`, `ACME_EMAIL`) plus secret references (§4).

## 3. Ask-gate reachability

- [x] 3.1 Add a dedicated ClusterIP `Service` exposing `tenant-router` `:9300` (`targetPort: rt-debug`), selecting the edge pod and kept separate from the public data-plane Service so the deliberate local-only posture of admin/debug/metrics stays intact (D3).
- [x] 3.2 Add or extend a `NetworkPolicy` to admit only the front-tier pod → edge `:9300`. Opt-in (`frontTier.askNetworkPolicy.enabled`); written additive-safe so `:10000`/`:9210` reachability is unchanged.
- [x] 3.3 Point the front tier's `AUTHORIZE_URL` at that Service's in-cluster DNS name.

## 4. Certificate store and ACME account material

- [x] 4.1 Wire `CADDY_STORAGE_PG_URL` behind `existingSecret`/`existingSecretKey` against the same `routing` Postgres; set `disable_ddl true`; document that the connection MUST be session/direct (not a transaction-mode pooler), per D4.
- [x] 4.2 Provision (or document as an operator prerequisite) the DML-only Caddy Postgres role, and ensure the committed CertMagic schema (`0001_certmagic_store.sql`) is applied to that DB. Documented as a prereq in `values.yaml` + the runbook (schema migration already committed).
- [x] 4.3 Wire `ACME_ACCOUNT_KEY_FILE` from the `existingSecret` (delivered out-of-band, D5 — NOT bundled ESO) mounted into an in-memory volume.

## 5. Client-IP preservation (PROXY protocol), opt-in / default off

- [x] 5.1 Add opt-in `servers.listener_wrappers: [{proxy_protocol}, {tls}]` to the `Caddyfile` global options (Helm-guarded via `tpl`, default off).
- [x] 5.2 Add an opt-in `proxy_protocol` `listener_filter` to the edge Envoy ConfigMap behind a `values.yaml` toggle, default off (the listener declares none today).
- [x] 5.3 Verify `edge-client-ip-preservation` at template level (unit tests): enabled edge listener gets the `proxy_protocol` filter; enabled front tier renders the `listener_wrappers` block; both absent by default. Runtime "un-framed rejected" is Envoy's strict default (`allow_requests_without_proxy_protocol: false`); end-to-end reject observed in the lab (6.3).

## 6. Chart validation and end-to-end verification

- [x] 6.1 `helm template` renders the front tier with defaults: `:443`/`:80` Service, Caddyfile ConfigMap, ask Service present; PROXY toggles off; existing edge output unchanged (16 docs off → 20 on; off render has no `listener_filters`).
- [x] 6.2 Add a chart test asserting the front-tier pod boots under the hardened SecurityContext (`readOnlyRootFilesystem` + in-memory volumes). `tests/front-tier_test.yaml`, 11 cases; full suite 14/14 green, `helm lint` clean.
- [ ] 6.3 Lab: deploy the front tier alongside the running edge (`:10000` stays up); run the `custom-domains-tls` spec verifications end-to-end against the Helm-rendered tier — cover the `deployment-front-tier-parity` scenarios (HTTPS entry point exists; forwards to edge with Host preserved). **(needs a live cluster — deferred to lab bring-up.)**
- [ ] 6.4 Verify fail-closed: with the ask Service unreachable, first-seen-hostname issuance is refused and no unauthorized certificate is ever issued (`deployment-front-tier-parity`). **(runtime; needs a live cluster — the misconfiguration guards are unit-tested, this is the ask-unreachable runtime path.)**

## 7. Docs and close-out

- [x] 7.1 Update `deploy/caddy/README.md` Helm section to reference the real chart artifacts instead of the "to be added" note.
- [x] 7.2 Update the go-live / `docs/on-demand-tls.md` runbook with the Helm `:443` cutover and rollback steps.
- [x] 7.3 Mark finding **N12** resolved in `docs/infra-findings.md`, linking this change.
- [x] 7.4 No memory change needed — deployment coverage of customer-domain TLS is now derivable from the shipped chart + specs (promote-or-discard: it lives in the code, not a memory snapshot). The `nexus-scope-boundary` memory does not currently exist.
