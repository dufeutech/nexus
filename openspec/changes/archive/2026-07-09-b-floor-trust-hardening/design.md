## Context

B-floor hardens the edge→box trust boundary. Verified current state (see
`platform-ha-and-hardening/EXPLORATION.md §2-B` and the code map):

- **Signing.** Exactly one signer — `identity-rs/sidecar/src/signer.rs` (`jsonwebtoken`, ES256),
  minting `x-identity-contract` per request with a ~60s TTL and `aud` scoped to the destination box.
  Signed claims live in `identity-rs/core/src/contract.rs::ContractClaims` (`sub`, `workspace_id`,
  `principal_kind`, `roles[]`, `permissions[]`, `plan?`, …). `roles` is signed; its unsigned header
  twin `x-user-roles` also exists.
- **The gap.** `x-user-entitlements` and `x-user-suspended` are authored as **bare** headers in
  `identity-rs/sidecar/src/main.rs` `enrich_response` (~L794–808), sourced from
  `identity-rs/core/src/profile.rs` (`Profile.entitlements`, `Profile.is_suspended`). They have **no
  signed counterpart at all** — the two signals gating "is this user cut off right now" are the least
  protected. They were left out deliberately: they must stay live for revocation freshness.
- **Strip.** A **denylist** of ~35 exact header names removed at the edge before ext_proc
  (`edge/envoy.yaml` L179–262, mirrored into 3 Helm `edge-configmap.yaml` + `deploy/compose`), plus a
  defense-in-depth denylist re-strip in the sidecar. A trusted header nobody enumerated passes through.

The third B-floor gap — **manual signing-key rotation** — is addressed separately in the sibling
change `automate-signing-key-rotation` (a larger key-management workstream needing a live OpenBao).

Tranche A (`service-slo-policy`, burn-rate SLOs) has shipped and is the instrument for verifying these
boundary changes don't regress the hot path. B-gate (edge↔box mTLS) and D (multi-region, CNPG) are
out of scope.

## Goals / Non-Goals

**Goals:**
- The revocation-sensitive signals (`x-user-entitlements`, `x-user-suspended`) become
  nexus-authenticated and unforgeable **without** losing their freshness guarantee.
- The edge admits client-supplied trusted-family headers only by **allowlist / default-drop**, so
  completeness stops being a maintenance invariant.

**Non-Goals:**
- **Automated signing-key rotation** — split into `automate-signing-key-rotation` (depends on a live
  OpenBao; lands independently).
- edge↔box mTLS / cross-region transport (B-gate). The single-cluster L3 NetworkPolicy stays the
  primary anti-bypass control; this change is defense-in-depth layered on top.
- Any DB / multi-region / CNPG work (D).
- Changing the box-side verifier (external); we only change what nexus emits.

## Decisions

> Each decision below is a **critical (security) concern** run through the `/opsx:decide` gate
> (Rent > Adopt > Extend > Fork > Build). Both are **approved** — the ADR records are at the end of
> this section under *Decision Records*; the prose below carries the rationale and the alternatives
> considered. (A third decision — automate signing-key rotation via OpenBao Transit, Mode B — was
> **split into the sibling change `automate-signing-key-rotation`** along with its spec delta and
> tasks; its ADR lives there.)

### Decision 1 — Protect entitlements/suspended by extending the signed contract (APPROVED)

**Decision: Extend** the existing JWS. Add `entitlements: Vec<String>` and `suspended: bool`
(nexus-authored) to `ContractClaims`, minted from the same per-request `Profile` that already authors
the bare headers. The bare `x-user-entitlements` / `x-user-suspended` headers either move inside the
signed token or remain as a convenience mirror that boxes are told (in `docs/box-consumer-contract.md`)
**not** to trust without the signed claim.

- *Why:* reuses one mature, already-audited signing path (Extend tier). The signals are already
  resolved fresh per request and the token is already minted fresh per request, so the only staleness
  is **token replay within the ~60s TTL** — the exact window that already bounds every other claim.
  The freshness spec (`identity-revocation-integrity`) is satisfied by keeping the TTL as the bound and
  requiring boxes not to cache the contract past `exp`.
- *Alternative — box-side cross-check (rejected as default):* box calls back to nexus to verify
  suspension live. Maximally fresh, but adds a per-request network hop + a new endpoint + couples every
  box to nexus at request time. Reserve only if a sub-TTL freshness bound is later required.
- *Tension recorded (Open Decision 3):* signing them reintroduces a staleness window bounded by TTL.
  Mitigation: TTL is already short (60s, `CONTRACT_TOKEN_TTL_SECONDS`); if tighter revocation is
  needed, lower the TTL rather than adopting cross-check.

### Decision 2 — Allowlist strip by trusted-namespace prefix, authoritatively in the Rust ext_proc (APPROVED)

**Decision:** default-drop the whole trusted namespace by **prefix** (`x-user-*`,
`x-workspace-*`, `x-geo-*`, `x-identity-*`, `x-auth-*`, `x-route-*`, `x-routed-by`, `x-enriched-*`, …)
from **client input**, and pass only an explicit small allowlist of permitted hints (today:
`x-requested-workspace`). The edge re-authors its own trusted headers *after* the strip, so nexus
values are unaffected.

**Where (settled):** the **authoritative** default-drop lives in the **tenant-router ext_proc (Rust)** —
the first component every box-bound request crosses. Prefix matching is trivial and unit-testable there,
and the prefix set + client-hint allowlist become a single shared Rust constant. The existing edge and
sidecar denylists stay as coarse **defense-in-depth**, but stop being the load-bearing control, so the
denylist maintenance invariant is retired.

- *Considered — Envoy Lua at the edge (rejected as authoritative):* strips at the true boundary and is
  adopt-native, but Envoy `header_mutation.remove` is exact-name only (confirmed: envoy#21054), so prefix
  semantics need Lua — i.e. **logic embedded in YAML**, harder to unit-test and duplicated across the 4
  mirrored configmaps. In-pod localhost between Envoy and the ext_proc is not a meaningful attack surface
  (the NetworkPolicy already restricts pod ingress to the edge), so "authoritative in Rust, coarse at the
  edge" loses nothing.
- *Considered — exhaustive prefix enumeration in Envoy config (rejected):* still a maintenance invariant,
  just coarser.
- *Single-source-of-truth:* the current denylist is duplicated across 4+ files; the new allowlist/prefix
  set lives **once** as a Rust constant and is referenced, never copy-pasted.

### Decision 3 — Automate key rotation (MOVED)

Automate signing-key rotation via **OpenBao Transit, Mode B (local signing)** was approved at
`/opsx:decide` and has been **moved, with its `identity-contract-signing` spec delta and
implementation tasks, into the sibling change `automate-signing-key-rotation`** — it is a larger
key-management workstream that depends on a live OpenBao to validate end-to-end and lands
independently (the manual `SIGNING_KEY_PATH` PEM stays a break-glass fallback). See that change's
`design.md` for the full rationale, the Mode A/B comparison, and the ADR record.

### Decision Records

#### Decision: Revocation-header integrity — Extend (the existing ES256 identity contract)

- **Status**: approved
- **Why**: reuses the one audited JWS path; the signals are already resolved & signed per request, so the only staleness is token replay within the ~60s TTL that already bounds every claim.
- **Considered**: box-side cross-check endpoint (Build) — sub-TTL freshness but a per-request hop + new endpoint + box↔nexus request-time coupling.
- **Isolation**: `ContractClaims` (`identity-rs/core/src/contract.rs`) + `Signer::mint` (`signer.rs`); boxes read from the verified claim, bare headers deprecated to an untrusted mirror.

#### Decision: Trusted-header strip — Extend (allowlist-by-prefix in the tenant-router ext_proc, Rust)

- **Status**: approved
- **Why**: the first component all box-bound traffic crosses; prefix default-drop is trivial, unit-testable, and single-sourced as a Rust constant — retiring the denylist maintenance invariant.
- **Considered**: Envoy Lua at the edge (Adopt) — logic-in-YAML, hard to test, duplicated ×4, and Envoy has no native prefix removal (envoy#21054); exhaustive prefix denylist in config — still a maintenance invariant.
- **Isolation**: a single shared prefix/allowlist constant in the ext_proc; edge + sidecar denylists demoted to coarse defense-in-depth.

> The signing-key-rotation ADR (Adopt OpenBao Transit, Mode B) moved to the sibling change
> `automate-signing-key-rotation`.

## Risks / Trade-offs

- **[Signing entitlements/suspended widens the signed payload / TTL staleness]** → keep TTL short; boxes
  MUST NOT cache the contract past `exp`; document in `box-consumer-contract.md`. A box reading the old
  bare header instead of the new claim would miss the protection → deprecate the bare headers explicitly.
- **[Allowlist over-strips a header a box legitimately needs]** → the allowlist is the same
  enumeration effort as the old denylist but fails **safe** (drop) instead of **open** (pass); catch
  regressions with the existing sidecar strip tests extended to assert default-drop of an unknown
  `x-user-*`.
- **[Config drift across the 4 mirrored envoy files]** → the allowlist/prefix set is single-sourced
  as one Rust constant in the tenant-router ext_proc (the authoritative control); the mirrored
  configmap denylists are demoted to coarse defense-in-depth, so their drift is no longer
  load-bearing.

_(Rotation-related risks moved to `automate-signing-key-rotation`.)_

## Migration Plan

1. Land Decision-1 claims additively (entitlements/suspended omitted-when-unresolved, like the existing
   `plan` claim) so the token shape change is "a value appears where one was absent," not a break.
2. Ship the allowlist strip behind the existing edge filter ordering; keep the sidecar defense-in-depth
   strip. Roll out edge config first, verify no legitimate header is dropped, then remove the old
   denylist entries superseded by the prefix default-drop.
3. Rollback: each of the two is independently revertible (revert the claim addition; restore the
   denylist config). No data migration. (Automated rotation ships separately in
   `automate-signing-key-rotation`, itself revertible to the manual `SIGNING_KEY_PATH` key.)

## Open Questions

- ✅ Resolved at `/opsx:decide`: D1 = Extend the signed contract; D2 = allowlist-by-prefix in the Rust
  tenant-router ext_proc. See *Decision Records*. (D3 = Adopt OpenBao Transit, Mode B — moved to
  `automate-signing-key-rotation`.)
- ✅ Resolved at apply-time (task 1.3): the bare `x-user-entitlements`/`x-user-suspended` headers are
  **removed entirely** once signed (no untrusted-mirror deprecation cycle) — they ride the signed
  contract only and any client copy is unconditionally stripped.
- ✅ Resolved at apply-time: `x-user-roles` **is** in scope — it is retired the same way (dropped +
  always stripped); the coarse `roles` ride the signed contract's `roles` claim only. This removes the
  last unsigned mirror of a signed identity claim.
