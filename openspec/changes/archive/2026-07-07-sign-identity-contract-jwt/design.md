## Context

Today the `x-identity-contract` header is a plain version string (`IDENTITY_CONTRACT_VERSION = "v1"`, `identity-rs/sidecar/src/main.rs:119`), stamped on every enriched request (`main.rs:423`). Trust that the whole `x-workspace-*`/`x-user-*` family is authentic rests entirely on `edge-origin-trust` (edge-only ingress + the three-layer client-header strip); `docs/box-consumer-contract.md:22` states "There is no signature to check."

JWT today exists **only at the edge**: Envoy's native `jwt_authn` filter verifies the *user's* OIDC bearer against the provider's JWKS and writes the `sub` claim to dynamic metadata (`edge/envoy.yaml:277-311`). The identity sidecar only *reads* that verified `sub` (`main.rs:106-107, 227-260`); it does not parse or mint tokens. There is **no JWT/JWS crate in either Rust workspace** (confirmed absent from both `Cargo.toml`/`Cargo.lock`).

A consuming box (`evenout`) is being built now to require a *verifiable* assertion — signed by nexus, verified against a nexus JWKS, carrying `iss`/`aud`/`exp` — so that origin trust is no longer the sole control. The user chose **augment, not replace**: origin enforcement stays; the signature is defense-in-depth.

## Goals / Non-Goals

**Goals:**
- The identity plane mints `x-identity-contract` as an asymmetrically-signed token over the resolved identity (subject, acting workspace, role), verifiable by any box against nexus-published public keys.
- nexus publishes a JWKS endpoint and rotates keys (`kid`, overlap window).
- Each token is issuer-identified, audience-scoped (per destination box), and short-lived.
- The contract version moves from the header value into a token claim; the header value becomes the compact signed token.
- The signed token joins the sidecar's strip-unauthored discipline.
- Signing happens only for authenticated, membership-resolved requests; anonymous stays the box's decision.
- Migration is non-breaking under a coordinated version bump; the individual `x-user-*`/`x-workspace-*` headers keep being emitted so boxes move header→token at their own pace.

**Non-Goals:**
- Replacing or relaxing `edge-origin-trust`. NetworkPolicy + header-strip remain the primary anti-bypass boundary.
- Changing how the *user's* OIDC bearer is verified at the edge (`jwt_authn` is untouched).
- **Existence-hiding (404-vs-403) ownership at nexus** — separate change (see Out-of-Scope Follow-ups).
- **`x-workspace-plan` producer / plan-tier data model** — separate change; the token schema only *reserves* the `plan` claim.

## Decisions

### Core vs adapters (dependency direction)
- **`identity-rs/core`** owns a `ContractSigner` **port** (trait: resolved-identity claims → signed token string) and the claim/identity types. No crypto library type appears in core's public surface.
- The **concrete signer adapter** wraps the adopted JWS library + key material and implements the port. The crypto tool enters the system *only* through this adapter.
- The **sidecar entry point** (`main.rs`) carries no crypto: it assembles claims from the already-resolved identity and calls the port to mint the token, then stamps the header. This preserves the existing "sidecar is a thin ext_proc adapter" shape.
- **JWKS publication** is a second thin adapter that serves the public half of the same key material at a stable path.
- Config (issuer, audience-derivation rule, token lifetime, key reference, active `kid`) is centralized behind the existing config adapter; the **private key is a runtime-injected secret referenced by key**, never config or a literal.

### Critical concerns — build-vs-adopt (ratified; ADR blocks below)
- **JWS signing primitive → ADOPT.** Never hand-roll signing/verification. Recommended: the `jsonwebtoken` crate (mature, widely used, supports ES256/EdDSA). Alternative considered: `josekit` (fuller JOSE, heavier) — overkill for minting one compact token shape. **BUILD is a defect here.**
- **Signing algorithm → ES256 (ECDSA P-256).** Asymmetric is mandatory (a box must verify but never mint — HMAC/shared-secret is rejected outright, as one compromised box could forge for the fleet). ES256 chosen over: **RS256** (~1ms/sign — too slow to mint per-request on the hot path; verify is cheap but we sign far more than any single box verifies), **EdDSA/Ed25519** (fastest, smallest — but box-side JWT library support is less universal than ES256; revisit if we control all box runtimes).
- **Key management + rotation → ADOPT infra.** Private key delivered as a Kubernetes Secret (compose: mounted file); `kid` in the token header; publish-new-before-sign / retire-after-expiry overlap. No bespoke keystore.
- **JWKS serving → EXTEND existing surface.** The identity plane already runs an axum admin/echo server (`main.rs:819`). Serve `/.well-known/jwks.json` from an identity-plane HTTP surface rather than standing up a new service. (Which exact surface — sidecar admin vs `authz-admin` — is an Open Question below.)

### Decision: JWS signing library — Adopt `jsonwebtoken`

- **Status**: approved
- **Why**: Pure-Rust (via `ring`), no native OpenSSL DLL dependency; supports ES256/EdDSA; its `jwk` module also serializes the JWKS, so one crate covers both signing and key publication.
- **Considered**: `josekit` (fuller JOSE but links OpenSSL 1.1.1+ — extra runtime + CVE surface for a single token shape); hand-writing JWS over `ring`/`ed25519-dalek` (Build — rejected: hand-rolling a security primitive a mature crate does well is a defect).
- **Isolation**: enters only through the `ContractSigner` adapter in `identity-rs`; no `jsonwebtoken` type appears in the `identity-rs/core` port surface.

### Decision: Signing algorithm — ES256 (ECDSA P-256)

- **Status**: approved
- **Why**: 2026 default for asymmetric JWT with the broadest box-side library support; asymmetric so boxes verify but cannot mint; fast enough to sign per-request on the hot path.
- **Considered**: EdDSA/Ed25519 (faster/smaller but less universal box-side support — revisit only if we control all box runtimes); RS256 (~1ms/sign too slow per-request, larger tokens).
- **Isolation**: algorithm + `kid` are config behind the config adapter; the core port is algorithm-agnostic.

### Decision: Key management + rotation — Rent (Kubernetes Secret + operational overlap)

- **Status**: approved
- **Why**: Infrastructure concern — the private key is a runtime-injected secret referenced by key; rotation is an operational publish-new-before-sign / retire-after-expiry overlap. No library owns key custody.
- **Considered**: bespoke in-process keystore (Build — unnecessary; adds attack surface); external KMS/HSM (Rent — heavier than needed for v1, can adopt later without contract change).
- **Isolation**: key material loaded once at startup into the warm signing context inside the signer adapter; never in config, image, or `specs/`.

### Decision: JWKS publication — Extend the existing identity-plane axum surface

- **Status**: approved
- **Why**: Serve `jsonwebtoken::jwk::JwkSet` at `/.well-known/jwks.json` from the axum server the identity plane already runs (`main.rs:819`); no new service, no extra dependency (the signing crate already provides the JWK types).
- **Considered**: a dedicated JWKS crate such as `jwk_kit` (Adopt — redundant with `jsonwebtoken`'s JWK types); a standalone JWKS service (Build — more deploy surface than a near-static key document warrants).
- **Isolation**: a thin JWKS adapter derives the public JWK set from the same key material the signer uses; the HTTP handler is a pure adapter with no crypto logic.

### Token shape
- Header value = compact signed token. Claims:
  - `iss` = configured nexus issuer (e.g. `https://identity.nexus`; box pins the exact string; JWKS discoverable under it).
  - `aud` = **destination box's canonical name**, derived at the sidecar from the route pool (`x-route-pool`); for `evenout` → `aud: "evenout"`. Scopes replay per box.
  - `exp` = `iat + ~60s` (minted per request, never reused → short window kills replay); `iat`, `jti` present.
  - `kid` in the token header for key selection/rotation.
  - `ctr` = the contract version (supersedes the old `v1` string).
  - Identity: `sub` (= `x-user-id`), `workspace_id` (= `x-workspace-id`), `role` (= `x-user-role`), `roles` (= `x-user-roles`).
  - **`plan` reserved** (populated by the separate plan-tier change; absent today, boxes treat absent as not-provisioned).
- Dual-emit during migration: the individual `x-user-*`/`x-workspace-*` headers continue to be authored, so a box can read identity from either the token or the headers until it fully cuts over.

### Strip discipline
- `x-identity-contract` is already always-authored and never in the strip list (enforced by `main.rs:1229-1237`). Since the value is now a signed token, a client copy is overwritten/stripped exactly as before — a forged token additionally fails signature verification at the box.

## Risks / Trade-offs

- **Per-request signing cost on the hot path** → ES256 signs in tens of µs; reuse a warm signing context (key parsed once at startup, not per request); measure added p99 latency before rollout.
- **JWKS reachability from boxes** → boxes must fetch+cache nexus's JWKS (in-cluster Service DNS and/or public host). A box that cannot fetch keys cannot verify; because origin trust remains underneath, a box MAY fail-closed on verify-unavailable without a security regression — but this is a new box-side dependency to document.
- **Clock skew across boxes** → short `exp` needs modest verification leeway (small `nbf`/`exp` tolerance) documented in the box contract.
- **Signing-key compromise** → short token lifetime + `kid` rotation limit blast radius; private key never leaves the identity plane; rotate on suspected exposure.
- **Coordinated version bump breaks a string-only box** → the header value stops being `v1`. Any box still doing literal `== v1` breaks the instant nexus emits a token. Mitigated by the contract's version mechanism + deploy ordering (below); `evenout` is being built for the token from the start.
- **Two representations of identity (headers + token claims) during migration** → keep them authored from the *same* resolved values in one place in the sidecar so they cannot drift; retire headers only after all boxes verify the token.

## Migration Plan

1. Land the signer + JWKS endpoint; nexus emits the signed token in `x-identity-contract` **and** keeps emitting the `x-user-*`/`x-workspace-*` headers (additive; origin trust unchanged).
2. Publish `iss`/`aud` convention + JWKS location in `docs/box-consumer-contract.md` and `nexus-upstream-requirements.md`.
3. Boxes (starting with `evenout`) fetch+cache JWKS and verify signature/`iss`/`aud`/`exp` + `ctr` on enriched routes.
4. Once all boxes verify the token, optionally demote the individual headers to derived/defense-in-depth (future change).
- **Rollback:** revert nexus to stamping the prior plain version string; because origin trust never changed, boxes that hadn't cut over are unaffected, and boxes that had cut over fall back to header-reading (headers were still emitted throughout).

## Refinements confirmed during apply

- **Mint only when resolved.** A signed assertion is emitted ONLY when the request is authenticated AND a member of the acting workspace (`resolve_membership` is `Some`). On non-member / profile-miss / anonymous paths there is no identity to sign, so `x-identity-contract` is **not** authored and any client copy is **stripped** — a verifying box then fails closed on enriched routes. Non-members are thus rejected at the box by an absent assertion, consistent with evenout offloading membership to nexus.
- **~~Legacy `v1` fallback~~ — REMOVED in follow-up (no consumers yet).** An earlier revision preserved a plain-string `v1` stamp when signing was disabled, for a non-breaking rollout. Since nothing consumes the contract yet, that dual-behavior was dropped: `x-identity-contract` is now **signed-token-only** — there is no plain-string form. When no signer is configured (or the identity is unresolved), no contract is authored and any client copy is stripped (fail-closed). This matches the `identity-workspace-authz` spec, which only ever describes the signed assertion.
- **JWKS is operator-supplied, not computed.** The runbook generates the P-256 keypair AND the public JWKS JSON together. The sidecar signs with the mounted private PEM (secret) and serves the mounted public JWKS JSON **verbatim** — no EC-parsing dependency beyond `jsonwebtoken`; the JWKS is native-format data loaded through an adapter. Rotation = update both mounted files (overlap: publish the new key in the JWKS before signing with its `kid`).
- **JWKS on a dedicated public listener.** Served at `/.well-known/jwks.json` on a NEW sidecar port, separate from the `:9200` profile API (which stays internal — it exposes `/profile/{sub}`). Deploy exposes only the JWKS port to boxes.

## Resolved / verified

- **`aud` granularity:** per-box, derived from `x-route-pool` (confirmed: the tenant-router injects it and it reaches the sidecar). The box pins the exact `aud` string.
- **Non-enriched route probes:** confirm infra probes (`GET /health`, `/ready`) are not routed through identity enrichment (edge-routing check; one-line verify in `apply`).

## Out-of-Scope Follow-ups (tracked, not bundled)

- **Change B — existence-hiding (404-vs-403) at nexus.** Net-new authz behavior; different risk profile (avoid leaking existence via status/body/latency). The sidecar currently blanket-403s (`forbidden_403`, `main.rs:540/640`). The box keeps its disagreeing-`workspace_id` backstop, so this can land separately without regression.
- **Change C — `x-workspace-plan` producer + plan-tier data model.** No plan/tier concept exists in nexus today (only entitlements; `main.rs:1317`). The `plan` claim is reserved here; a later change models the tier and flips it from reserved to populated.
