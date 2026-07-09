## 0. Gate (do first)

- [x] 0.1 Run `/opsx:decide` and record ADR blocks in `design.md`. **Approved:** D1 = Extend the signed contract; D2 = allowlist-by-prefix authoritatively in the Rust tenant-router ext_proc; D3 = Adopt OpenBao Transit, Mode B (local signing).

## 1. Revocation-integrity: sign entitlements & suspended (`identity-revocation-integrity`)

- [x] 1.1 Add `entitlements: Vec<String>` and `suspended: bool` (nexus-authored, omitted-when-unresolved like the existing `plan` claim) to `ContractClaims` in `identity-rs/core/src/contract.rs`. *(Modeled as `Option<Vec<String>>` / `Option<bool>` so "unresolved" is omission and an absent `suspended` reads as unknown, never `false`.)*
- [x] 1.2 Populate the new claims in `Signer::mint` (`identity-rs/sidecar/src/signer.rs`) from the same per-request `Profile` (`identity-rs/core/src/profile.rs`) that authors the bare headers today.
- [x] 1.3 In `enrich_response` (`identity-rs/sidecar/src/main.rs` ~L794–808), stop emitting the bare `x-user-entitlements` / `x-user-suspended` as trusted signals. **Resolved:** DROP them entirely (and `x-user-roles` too) — all three are unconditionally stripped and ride the signed contract only; the profile-miss path omits the signed claim (absence == unknown).
- [x] 1.4 Update `docs/box-consumer-contract.md` / `docs/box-signing-handoff.md`: the box MUST read entitlement/suspension from the verified contract claim and MUST NOT cache the contract past `exp`; document the TTL as the freshness bound.
- [x] 1.5 Tests: minted contract carries entitlements+suspended over the signature; claims omitted when the profile is unresolved; a request that mutates the bare headers cannot influence the signed claim (nexus-authored only). Cover the freshness bound (replay past `exp` rejected — existing verify path).

## 2. Allowlist strip (`edge-trusted-header-strip`)

- [x] 2.1 Define the trusted-namespace prefixes + the client-hint allowlist (e.g. `x-requested-workspace`) as ONE shared Rust constant in the tenant-router ext_proc — not copy-pasted per configmap. *(`TRUSTED_HEADER_PREFIXES` + `TRUSTED_HEADER_EXACT` + `CLIENT_HINT_ALLOWLIST` in `routing-rs/tenant-router/src/main.rs`.)*
- [x] 2.2 Implement authoritative default-drop-by-prefix of the trusted family from client input in the tenant-router ext_proc (Rust), keeping nexus-authored headers (set after the strip) intact. *(`trusted_family_strip` excludes authored names so `set_headers` overwrite stays apply-order-independent.)*
- [x] 2.3 Demote the edge (`edge/envoy.yaml` + 3 Helm `edge-configmap.yaml` + `deploy/compose/envoy/envoy.yaml`) and sidecar denylists to coarse defense-in-depth; the Rust prefix drop is now the load-bearing control, retiring the denylist maintenance invariant. *(Comments demoted; entries retained as belt-and-suspenders.)*
- [x] 2.4 Extend the strip tests to assert an unknown/un-enumerated `x-user-*` header from a client is dropped by default, and that an allowlisted hint survives. *(Authoritative check lives in the tenant-router — single-source, per D2 — so its tests carry the un-enumerated-drop + allowlist-survives assertions; the sidecar test asserts the hint survives its coarse denylist.)*

> **Automated key rotation (former Section 3) was split into the sibling change
> `automate-signing-key-rotation`** (Adopt OpenBao Transit, Mode B) — it depends on a live OpenBao to
> validate end-to-end and lands independently. Its tasks + `identity-contract-signing` spec delta live
> there.

## 3. Verify & close

- [x] 3.1 Run the full identity-rs + routing-rs test suites; confirm clippy-clean. *(core 23, sidecar 53, authz-admin 5, tenant-router 10 — all green; the changed code is clippy-clean, only a pre-existing `telemetry.rs` baseline lint remains in both workspaces.)*
- [ ] 3.2 Exercise the boundary end-to-end (drive a suspended-user request through edge→sidecar→a stub box) and confirm: signed suspension honored, forged bare header ignored, unknown client trusted-header dropped. Use the `service-slo-policy` burn-rate instrument to confirm no hot-path latency regression.
- [x] 3.3 Run `openspec validate` (passes); `/opsx:sync` folded both delta specs into `openspec/specs/` (created `identity-revocation-integrity` + `edge-trusted-header-strip` main specs); `/opsx:archive`.
