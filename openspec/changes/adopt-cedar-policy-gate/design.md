## Context

`edge-auth-gate` is three cooperating stages (verified via code map):

```
  1. RESOLVE (tenant-router ext_proc)   host→workspace, longest-prefix path match against the
     routing-rs/router-core::AuthPolicy  tenant's routing.auth_routes rules → emits x-auth-required
                                         + x-auth-requires-role/-entitlement/-min-aal/-account-scoped
        │  (unchanged by this change — stays tenant-authored data)
        ▼
  2. 401 (Envoy jwt_authn)              branches on x-auth-required; invalid/absent credential → 401
        │  (unchanged — authentication, not authorization)
        ▼
  3. ENFORCE (identity sidecar ext_proc) AFTER enrichment. Order: 503 fail-closed → 404 existence-hide
     identity-rs/sidecar/src/main.rs      (hide_nonmember_as_404, :875) → **403 requirement check**
                                          (authorize_route, :530-557) → else pass
```

**The single thing this change replaces:** stage-3's `authorize_route` — the hand-coded comparison
`required_role ∈ roles ∧ required_entitlement ∈ entitlements ∧ method_aal ≥ min_aal`, each check
fail-closed. Everything else (resolve, 401, 503, 404, ordering, header-stripping, path canonicalization,
write-time rule validation, the LISTEN/NOTIFY rule-invalidation feed) stays byte-for-byte.

The seam already exists: principal facts are projected to `AuthzFacts` (`identity-rs/core/src/authz.rs`,
deny-by-default zero value) behind the `AuthzResolver` port, whose docstring already anticipates "a
future policy/ReBAC engine (OpenFGA/Cedar)." The requirement context arrives as the trusted `x-auth-*`
headers (`RouteRequirements`, sidecar :499-523).

## Goals / Non-Goals

**Goals:**
- Introduce a Policy Decision Point (PDP) port + adapter; move the stage-3 requirement decision into it.
- Strict **behavioral parity**: the existing 401/403/404/503 matrix and fail-closed semantics are the
  oracle (the tests at `router-core/src/auth.rs`, sidecar `authorize_route`/`enforce_route_requirements`,
  control-plane validation, store round-trip must all still pass, plus new parity tests).
- Policies as **data** (`.cedar` files + schema), loaded via an adapter, per-environment, fail-closed
  on malformed load.

**Non-Goals:**
- Touching stages 1–2, the 404/503 logic, or their ordering. Cedar decides **only** the 403 step.
- Modeling tenant `auth_routes` rules as Cedar policies (they stay DB rows resolved by tenant-router).
- Adding a decision dimension not enforced today: **HTTP method** (only feeds AAL), **geo**, **plan**,
  and **suspension** are carried but NOT decided on — they stay inert in the parity policy.
- L3 / OpenFGA / `MembershipResolver` ReBAC (parked, D-coupled).

## Decisions

> The **policy engine** is the correctness-critical concern gated at `/opsx:decide`; the formal
> Adopt call is **Decision 0** below. The placement/port/schema decisions (1–3) are this change's HOW.

### Decision 0 — Policy engine: **Adopt Cedar** (`cedar-policy` 4.10.x)

- **Status**: approved
- **Why**: Rust-native crate with in-process microsecond eval, policy-as-data with a schema
  validator that fails closed at load, and formal analyzability — the right fit for a correctness-
  critical L2 gate on the sidecar hot path, and it makes the hand-rolled comparison declarative.
- **Considered**: *OPA/Rego* — mature/CNCF but a Go engine, embeddable only via a WASM runtime or a
  service sidecar (extra footprint, non-native eval on the hot path); *Build (keep hand-rolled)* —
  no new dependency but re-implements a solved, correctness-critical problem and keeps authz logic
  scattered — the exact anti-pattern this gate prevents.
- **Isolation**: the `cedar-policy` dependency lives only in the new `identity-rs/policy-cedar`
  crate, behind the `PolicyDecisionPoint` port in `identity-rs/core` (Decision 1) — reversible as
  an adapter swap; `core` and `sidecar` never import the engine.

### Decision 1 — A new `PolicyDecisionPoint` port in `identity-rs/core`; Cedar adapter in a new `identity-rs/policy-cedar` crate

Fact *resolution* (`AuthzResolver` → `AuthzFacts`) and the *decision* are different concerns, so the
decision gets its own vendor-agnostic port (`decide(request) -> Decision { effect, reason }`,
deny-by-default) rather than overloading `AuthzResolver`. The Cedar dependency is isolated in its own
crate (`identity-rs/policy-cedar`) implementing the core port — matching CLAUDE.md "an adapter isolates
every dependency," and keeping the `cedar-policy` crate out of `core` and the sidecar. The sidecar's
`enforce_route_requirements` becomes a thin translator: build the request from the in-process Profile +
`RouteRequirements`, call the port, map `deny → 403`.

- *Alternative (rejected):* plug Cedar directly behind `AuthzResolver` — conflates data resolution with
  decision, and leaks the engine into the fact-projection path.

### Decision 2 — PARC mapping (parity-exact)

```
  Principal  User    { roles: Set<String>, entitlements: Set<String>,
                       aal: Long (from x-auth-method via SIDECAR_AAL_LEVELS),
                       suspended: Bool (carried, unused in parity), kind }
  Action     access  (single action — no per-method dimension today)
  Resource   Route   { requires_role: String("" = none), requires_entitlement: String("" = none),
                       min_aal: Long(0 = none), account_scoped: Bool }
  Context    —       (requirements modeled on Resource; geo/plan present but unreferenced)
```

Parity policy (one permit, deny-by-default): permit when
`(resource.requires_role == "" || resource.requires_role in principal.roles)
 && (resource.requires_entitlement == "" || resource.requires_entitlement in principal.entitlements)
 && principal.aal >= resource.min_aal`.

- **Fail-closed falls out of Cedar semantics:** a condition that reads a missing/unparseable attribute
  errors → the permit does not apply → deny. This reproduces "requirement present, enrichment absent →
  403." Principal facts are always populated (possibly empty sets) so a set requirement against empty
  enrichment denies, while an *empty requirement* (`""`/`0`) short-circuits to permit — matching
  `RouteAuth`'s `Option` = None = no-requirement.

### Decision 3 — Policies are `.cedar` files loaded via an adapter, validated at startup (fail-closed)

Policy + Cedar schema live as data files, path-configured per environment (Helm/compose), loaded and
**validated** against the schema at startup; a malformed/unvalidatable set makes the sidecar refuse to
serve gated routes (fail-closed) rather than run on an empty/partial set. Because the parity decision
reads requirements from per-request headers (not the rule DB), **tenant rule propagation is untouched**
— it still rides the existing LISTEN/NOTIFY feed via tenant-router; only the *platform* policy files are
a deploy artifact.

## Risks / Trade-offs

- **[Subtle parity drift — a Cedar edge case differs from `authorize_route`]** → the existing gate tests
  are the oracle; add a parity test that runs the same input matrix through both the old comparison and
  the PDP and asserts identical effects before deleting the old path.
- **[Decision ordering regression — Cedar 403 fires before the 404 existence-hide]** → the PDP call must
  stay at the *exact* existing decision point (after `hide_nonmember_as_404`, after the 503 fail-closed);
  a test asserts a non-member still gets 404, a member-lacking-role gets 403.
- **[Hot-path cost of engine eval per request]** → Cedar eval is in-process and microsecond-scale;
  policies compiled/validated once at load. Confirm with the tranche-A latency SLO on the sidecar plane.
- **[Fail-closed inversion — a missing attribute accidentally permits]** → assert deny-on-missing in
  tests for every attribute; never default an absent requirement-satisfying attribute to a permissive
  value.
- **[Scope creep — signing suspension/geo/method into the decision]** → explicitly inert in the parity
  policy; any new dimension is a *later* change against the now-existing PDP, not this one.

## Migration Plan

1. Land the `PolicyDecisionPoint` port + `policy-cedar` adapter + parity `.cedar` policy, wired behind a
   flag/adapter selection, with the old `authorize_route` still present.
2. Run both in a parity test harness over the gate's full input matrix; confirm identical effects.
3. Cut `enforce_route_requirements` to call the PDP; keep `authorize_route` only as the test oracle, then
   remove it once parity is green.
4. Ship policy files per environment; verify fail-closed on a deliberately malformed policy set.
5. Rollback: the adapter selection reverts to the in-code comparison; no data migration, no schema change.

## Open Questions

- ~~Resolved at `/opsx:decide`: formally record **Adopt: Cedar** (vs. keep hand-rolled / another engine).~~
  **Resolved → Decision 0: Adopt Cedar (`cedar-policy` 4.10.x), approved.**
- Exact home for the `.cedar` files: in the `policy-cedar` crate (`policies/`) vs. a deploy-config path.
  Leaning: a default set in-crate, overridable by a configured path per environment.
- Do we keep `authorize_route` as a permanent parity oracle in tests, or delete after cutover? (Leaning
  delete once the PDP parity test subsumes it.)
