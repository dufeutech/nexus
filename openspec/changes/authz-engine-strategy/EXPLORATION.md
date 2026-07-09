# Exploration — Authorization engine strategy (Cedar + OpenFGA)

Captures a platform-authz direction discovered while normalizing the edge→box trusted-header
contract. **This is a strategy exploration, not an implementation change.** The near-term
implementation slice (adopt Cedar for the policy-gate layer) is spun out as its own change —
see *Next steps*.

## 0. Framing — nexus is a multi-product platform

nexus offers many services under one account (hosting / drive / store / ERP / … — Hostinger-,
Google-Drive-, Shopify-, Odoo-shaped). At that scale, "access" is a **composition of two
orthogonal questions**, and conflating them is the core failure mode:

```
  access  ==  ENTITLED(account, service/feature)   AND   AUTHORIZED(principal, action)
              └─ commerce / licensing (L1) ─┘             └─ access control (L2/L3) ─┘
                 changes on PAYMENT                          changes on a GRANT
```

- You can be `admin` (authorized) of a workspace not entitled to the store → locked out.
- You can be entitled to the store but a `viewer` → can look, can't edit.

Neither subsumes the other. This is the Google-Workspace / Shopify / Odoo grid (SKU/plan ×
role/permission). See the sibling licensing thread: `entitlements` is the *resolved projection*
of per-service subscriptions + add-ons, and belongs to a **commerce plane (L1)**, NOT to any
authorization engine — its output is fed to L2 as policy **context**.

## 1. The layered model — one home per concern

```
  L0  AUTHENTICATION   who is this?                         OIDC              (have it)
  L1  ENTITLEMENT      does the ACCOUNT hold the service/    commerce plane    (separate; feeds L2)
                       feature/quota?                        NOT an authz engine
  L2  POLICY GATE      does this request satisfy the rule?   CEDAR             ← adopt now
                       role · entitlement · AAL · suspended
                       · geo/residency (context-rich)
  L3  RESOURCE ACCESS  can THIS principal touch THIS object? OPENFGA (Zanzibar) ← seam-ready, later
                       nested, inherited, per-resource
```

## 2. Why both engines — they answer different questions (not redundant)

| | Cedar (AWS) | OpenFGA / Zanzibar (Google model) |
|---|---|---|
| Kind | Policy **language** + eval engine | Relationship **store** + check API |
| Model | PARC: Principal·Action·Resource·**Context** | tuples: `user:anne editor doc:123` + graph traversal |
| Best at | context-rich **rules**, ABAC+RBAC, conditions | deeply-nested, inherited, per-resource sharing |
| Data | you bring entities/context to eval | it *is* the data (millions of tuples) |
| Footprint | **Rust-native crate — embed it** | stateful distributed service — operate it |
| Verifiability | formal analysis / policy validation | schema + tuple tests |

The tell: **Google-Drive-style "who can see this file, inherited folder→folder→group" IS the
Zanzibar paper** → L3 → OpenFGA. "This route requires role X *and* entitlement Y *and* AAL≥2
*and* not-suspended" is a contextual **policy** → L2 → Cedar — and that is exactly what
`edge-auth-gate` hand-rolls today (`x-auth-requires-role` / `x-auth-requires-entitlement` /
`x-auth-min-aal`). Discipline: **never let the two overlap**, or we recreate the
`entitlements`/`plan` muddle at engine scale.

## 3. The codebase already built the seams (adapter-swap, reversible)

- `identity-rs/core/src/membership.rs`: the `MembershipResolver` port exists so "a future
  adapter can delegate to a **ReBAC engine (OpenFGA/SpiceDB)** without changing the sidecar." → L3.
- `identity-rs/core/src/profile.rs`: current model is **"Model 1 … the Profile is the
  nexus-native authorization store,"** read/written via `AuthzResolver` / `AuthzAuthoring` ports. → L2.

```
  AuthzResolver port       today: roles/entitlements/suspension   →  Cedar entities + context   (L2)
  MembershipResolver port  today: Profile.memberships projection  →  OpenFGA tuples             (L3)
```

Adopting either is a port adapter swap — matches CLAUDE.md's build-vs-adopt (Adopt behind a thin,
reversible boundary). De-risks both.

## 4. Asymmetric cost drives sequencing

- **Cedar = adopt a Rust crate.** Policy-as-data (matches "data is not code"), formally
  analyzable, **no new service to operate** → cheap, near-term. Replaces edge-auth-gate's
  hand-rolled rule logic with declared policies.
- **OpenFGA = adopt + operate a stateful datastore** with its own consistency model. Its backing
  store lands **on the parked D fork**: OpenFGA needs a cross-region-consistent DB (Postgres/CNPG,
  or CockroachDB/Spanner for global) — so "adopt OpenFGA" is partly the *same* decision as the
  multi-region DB choice (CNPG vs Cockroach). Do not scope the ReBAC store before D is decided.

## 5. Decisions (recorded)

- **Adopt Cedar for L2 (now).** Rust-native embed, policy-as-data, replaces the hand-rolled
  edge-auth-gate rule evaluation; behind the `AuthzResolver`/policy boundary so it's reversible.
- **Adopt OpenFGA for L3 (seam-ready, later).** Timed to (a) a product that actually has
  deeply-nested per-resource sharing AND (b) the D multi-region DB decision. Until then the
  `MembershipResolver` ReBAC adapter stays unimplemented; the Profile projection remains L3.
- **Entitlement/licensing is NOT an authz engine (L1).** It's a commerce plane; its resolved
  output is fed to Cedar as context. Keep it out of both Cedar policies and OpenFGA tuples.
- **Non-overlap invariant.** L2 (Cedar) decides *policy/context* rules; L3 (OpenFGA) decides
  *resource-graph* relationships; they compose, they do not duplicate a decision.

## 6. Open decisions (resolve at propose / decide for the Cedar slice)

1. **Cedar placement:** which component embeds the engine (the tenant-router ext_proc? the
   identity sidecar? a dedicated authz component)? It must sit where the route rule is evaluated.
2. **Policy storage/loading:** policies as Cedar policy files loaded via an adapter (data-is-not-code);
   authoring/versioning path; how policies deploy per-environment.
3. **Entity + context schema:** map principal (from the signed contract), action, resource (route/
   service), context (entitlements, AAL, geo/residency, suspension) into Cedar's PARC.
4. **First slice = parity, not expansion:** replace edge-auth-gate's current rule matching with
   equivalent Cedar policies (same observable behavior), then extend. Don't change authz scope in
   the adoption change.
5. **OpenFGA timing input:** do any first-wave products have real nested/inherited per-resource
   sharing, or are they flat RBAC-per-workspace for now? (Decides near-term vs seam-only for L3.)

## Next steps

1. `/opsx:propose adopt-cedar-policy-gate` — implement L2: embed Cedar, model policies as data,
   achieve behavioral parity with `edge-auth-gate`, behind the existing authz port.
2. `/opsx:decide` on that change — formally record **Adopt: Cedar** (+ the open decisions in §6).
3. Leave L3/OpenFGA parked here until §6.5 and the D DB fork resolve.
4. Unrelated and independent: `b-floor-trust-hardening` proceeds on its own (it does not depend on
   the authz-engine work).
