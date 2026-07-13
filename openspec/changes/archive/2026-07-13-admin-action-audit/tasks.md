# admin-action-audit — tasks

## 1. Decide gate

- [x] 1.1 Run `/opsx:decide` for the four flagged concerns (ledger integrity
      enforcement, named-token machinery, out-of-band DB auditing, export format)
      and record the ADRs in design.md
- [x] 1.2 Confirm the retention floor (assumed 365d) and pin it in design.md
      (floor 365d, default 450d — covers a Type II observation window + buffer)

## 2. Schema & migrations (per plane)

- [x] 2.1 control-plane: `.sql` migration adding `admin_audit_events` (columns per
      D3), `admin_tokens` (per D4), insert/select-only grants for the service role,
      and the maintenance (purge) role
- [x] 2.2 authz-admin: equivalent `.sql` migration in the identity store
- [x] 2.3 Add the `aev_` typed-id mint alongside each plane's existing id helpers,
      following the `Nexus-IDS.md` convention

## 3. Core recording (per plane)

- [x] 3.1 Audit event type (closed action vocabulary as constants) + secret-free
      `detail` construction; unit tests that key/token material never serializes
- [x] 3.2 `record(event, &mut tx)` store function; wire into every mutating
      control-plane handler transaction (accounts, workspaces, reconfigure,
      transfer, members, auth-routes, domains) with replay outcomes on
      idempotent hits
- [x] 3.3 Wire into every mutating authz-admin handler transaction (roles,
      entitlements, suspend/reactivate, apikey issue/rotate/revoke)
- [x] 3.4 Bootstrap grant event in the existing startup grant transaction; no-op
      startup writes nothing
- [x] 3.5 Failure-path test per plane: audit insert forced to fail ⇒ mutation rolls
      back and the caller gets an error

## 4. Named tokens & auth layer (per plane)

- [x] 4.1 Token issuance/rotation/revocation store functions (peppered HMAC,
      lineage) + minimal admin CLI or endpoint for provisioning, per the D4 ADR
- [x] 4.2 Replace single-token verification with token-table lookup; multiple
      concurrent tokens; constant-time compare preserved
- [x] 4.3 Legacy mode: `ADMIN_LEGACY_TOKEN_OK` gate, reserved `legacy-shared`
      attribution, per-use deprecation warning; default off
- [x] 4.4 `x-acting-operator` capture: length-cap, store verbatim, never influences
      auth; test that an invalid credential + assertion is rejected identically

## 5. Denial events

- [x] 5.1 Best-effort denial insert on both surfaces' 401 paths (time, surface,
      source, absent-vs-invalid; no credential material), rate-limited per source
- [x] 5.2 Test: failed denial write still returns 401; credential value absent from
      the stored event

## 6. Query, export, retention

- [x] 6.1 `GET /audit/events` (filters: from/to/actor/target; time-ordered;
      cursor-paginated) on both surfaces, read-only
- [x] 6.2 `GET /audit/events/export` NDJSON stream for a time range
- [x] 6.3 Retention config (`AUDIT_RETENTION_DAYS`, startup-validated floor) +
      periodic purge job under the maintenance role; purge is the only deleter

## 7. Docs & rollout

- [x] 7.1 Update `openapi/control-plane.yaml` and `openapi/authz-admin.yaml`
      (audit endpoints, `x-acting-operator` header, token provisioning)
- [x] 7.2 Update `docs/admin-apis.md` and add the token-migration steps to the
      go-live runbook (dual-mode → provision → flag off → remove env tokens)
- [x] 7.3 Extend `scripts/go-live-smoke.sh`: a mutation produces a queryable event;
      a 401 produces a denial event
- [x] 7.4 E2E: two named tokens are distinguishable in the ledger; revoking one
      leaves the other working; replay records `outcome=replay`
