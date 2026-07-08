# Tasks — identity-existence-hiding

> Primary edit: the sidecar enrich path (`identity-rs/sidecar/src/main.rs`), shared with the ADR-10
> family — this change owns **only** the unresolved/forbidden branch (404-vs-403), adds no contract
> claim, and does not touch the authenticator chain, mint guard, or authored headers.
>
> **Signal shape (refined during apply):** the per-route flag is `account_scoped: bool` on
> `router-core::RouteAuth` (default `false` = workspace-scoped = gated = fail-closed), emitted as
> `x-auth-account-scoped: true` **only when set** — matching the existing requirement-signal pattern,
> so wire-absence is the fail-closed gated state (cleaner than an always-emitted `workspace_scoped`).
> Persistence runs through relational columns (not JSON), so the flag needed a `store-postgres`
> column + `control-plane` CRUD field — the change spans router-core → tenant-router → edge →
> store/control-plane → sidecar, in emit→strip→read order. See `design.md`.

## 1. Response envelope (sidecar)

- [x] 1.1 `not_found_404()` helper in `identity-rs/sidecar/src/main.rs` — immediate `404`, fixed
  body `b"not found"`, no header mutation; byte-identical on every emission.
- [x] 1.2 Unit test `not_found_404_is_a_uniform_immediate_404` (404 + fixed body + no headers + two
  emissions equal), plus `hidden_404_and_honest_403_are_distinct`.

## 2. Route-scope signal (router-core → tenant-router → edge → persistence)

- [x] 2.1 `account_scoped: bool` field on `router-core::RouteAuth` (serde default `false`,
  `skip_serializing_if` so absence = workspace-scoped); added to `PASS_THROUGH`; tests
  `account_scoped_defaults_to_false_and_rides_the_rule`, `account_scoped_is_wire_absent_when_false`.
- [x] 2.2 Emit `x-auth-account-scoped` from `tenant-router::auth_signals()` only when set; test
  `account_scoped_rule_emits_its_signal_only_when_set`.
- [x] 2.3 Strip client copies of `x-auth-account-scoped` at the edge — added to the C3 remove list in
  `edge/envoy.yaml`, `deploy/compose/envoy/envoy.yaml`, and the three helm edge configmaps
  (edge-platform, routing-plane, identity-plane).
- [x] 2.4 Persist the flag: `store-postgres` `account_scoped` column (idempotent `ADD COLUMN IF NOT
  EXISTS ... DEFAULT false`) + SELECT/INSERT wiring; `control-plane` `AuthRouteBody.account_scoped`
  CRUD field; store round-trip covered in `integration.rs`.

## 3. Membership-404 gate (sidecar) — enriched & workspace-scoped → default-deny

- [x] 3.1 `enrich()` reads trusted `x-auth-required` and `x-auth-account-scoped` via `trusted_flag`
  (absent → `false`; account-scoped absence is fail-closed gated).
- [x] 3.2 Membership resolved uniformly across principal kinds via `enriched.acting` (human, api-key,
  service, anonymous all funnel to "acting authority for `ws` resolved?").
- [x] 3.3 Gate inserted before the 403 requirements check as a pure predicate
  `hide_nonmember_as_404(auth_required, account_scoped, has_ws, acting_resolved)`: non-member →
  `not_found_404()`; member falls through to the honest `forbidden_403()`.
- [x] 3.4 Public (`x-auth-required:false`) and account-scoped routes are never gated (predicate false);
  today's non-workspace / public flows unchanged.

## 4. Timing convergence (no new mechanism — assert the invariant)

- [x] 4.1 Confirmed: principal resolution stays ahead of and independent of the gate; the non-member
  and nonexistent-workspace outcomes are one branch (`not_found_404`). No constant-time crate, no
  jitter added.
- [x] 4.2 `not_found_404_is_a_uniform_immediate_404` locks the byte-identical envelope (status + body
  + no headers), so non-member ≡ nonexistent leaks nothing through shape.

## 5. Tests (spec scenarios → cases)

- [x] 5.1–5.8 Covered by `existence_hiding_gate_truth_table` (non-member private→404; member→not
  hidden/403; public→not gated; account-scoped→not gated; fail-closed on absence; no-workspace→not
  gated) and `trusted_flag_reads_only_literal_true` (client cannot forge/suppress the gate). Store
  round-trip of `account_scoped` in `store-postgres/tests/integration.rs`.

## 6. Contract docs

- [x] 6.1 `docs/box-consumer-contract.md` §1b′: nexus owns the existence-hiding 404; boxes must not
  re-derive workspace existence and must keep a non-leaking body-`workspace_id` backstop.
- [x] 6.2 `nexus-upstream-requirements.md` N4 Phase 3: workspace-scoped-by-default membership gate,
  the `account_scoped` opt-out, C3 strip, and the fail-closed rollout note.

## 7. Verify

- [x] 7.1 `cargo test` green: sidecar 50/50 (incl. new existence-hiding tests), router-core 48,
  tenant-router 6, control-plane; both workspaces build clean (pre-existing warnings only).

## 8. Uniform not-found envelope across the edge (decided during apply: align)

- [x] 8.1 Aligned `tenant-router::reject_unknown_host()`'s `404` body to `"not found"`, byte-identical
  to the sidecar's `not_found_404()`, so an *authenticated* host/tenant prober cannot distinguish
  "tenant does not exist" from "tenant exists, not a member" by body. (Host-level existence remains
  partly inferable pre-auth via the 401-vs-404 boundary and public DNS/TLS — bounded, documented in
  `design.md`; this closes the authenticated-body leak, which is the in-scope part.)
