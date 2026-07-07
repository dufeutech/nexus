## Why

Today a box (e.g. `evenout`) trusts the identity headers nexus injects **only because of the network path** — the edge is the sole ingress and it strips any client-supplied copy. `docs/box-consumer-contract.md` states this plainly: *"There is no signature to check."* That makes edge origin a single point of trust: anything that reaches a box off the edge path (misconfigured NetworkPolicy, a sidecar/mesh bug, a future direct route) can forge identity, and the box has no way to detect it. The consuming box is being built now to require a **verifiable** assertion, so trust rests on a signature rather than solely on reachability.

## What Changes

- nexus signs the identity contract as a **JWT** carrying the resolved identity claims, verifiable against a nexus-published JWKS. This is **defense-in-depth**: network origin-trust (NetworkPolicy + the three-layer header strip) stays exactly as-is underneath.
- **BREAKING (coordinated version bump):** the `x-identity-contract` header value changes from a plain version string (`v1`) to a signed JWS compact token. The version stamp moves *inside* the token as a claim. Boxes doing a literal string check must switch to verifying the token — nexus and box cut over together, which is what the contract's versioning mechanism exists for.
- nexus exposes a **JWKS endpoint** so boxes fetch its public keys (the analogue of how the edge already fetches the OIDC provider's JWKS), with `kid`-based key rotation.
- The signed token joins the sidecar's **strip-unauthored** discipline, so a client cannot smuggle in its own `x-identity-contract` token.
- Signing is stamped only on **enriched (authenticated, membership-resolved) data-plane requests** — infra probes carry no identity and get no token. Anonymous/public access stays the box's decision (nexus signs nothing without a resolved subject).

Out of scope, tracked as separate follow-up changes (recorded in `design.md`):
- **Existence-hiding (404-vs-403) ownership at nexus** — net-new authz behavior with a different risk profile; the box keeps its disagreeing-`workspace_id` backstop, so nothing regresses if it lands separately.
- **`x-workspace-plan` producer + plan-tier data model** — nexus has no plan/tier concept today (only entitlements). The JWT schema **reserves** a `plan` claim so populating it later is non-breaking; the box already treats absent plan as not-provisioned.

## Capabilities

### New Capabilities
- `identity-contract-signing`: nexus mints a signed, short-lived JWT over the resolved identity (subject, acting workspace, role) with issuer/audience/expiry, publishes the verifying keys via JWKS, and rotates keys — so a box can cryptographically confirm a request originated from nexus. Names the build-vs-adopt concerns to settle at `/opsx:decide`: the JWS signing primitive, asymmetric key management + rotation, and JWKS publication/serving.

### Modified Capabilities
- `identity-workspace-authz`: the `x-identity-contract` stamp changes from a plain version string to a signed assertion (the version moves into a token claim), and the backend's requirement becomes "verify the signature + version," not "match a known string." The stamp gains a second meaning — a verifiable proof of nexus origin — while `edge-origin-trust` origin enforcement stays the primary anti-bypass control (augment, not replace). `edge-origin-trust` itself is unchanged; it already delegates the stamp's meaning to this capability.

## Impact

- **Code:** `identity-rs/sidecar` (the signer — runs last, authoritative; adds per-request minting on the hot path and extends the strip set); a new JWKS-serving surface in the identity plane; `identity-rs/core` claim/identity types.
- **Contract/docs:** `docs/box-consumer-contract.md`, `nexus-upstream-requirements.md` — the `x-identity-contract` row moves from version-string semantics to signed-token semantics; publish the `iss`/`aud` convention and JWKS location.
- **Deploy:** private signing key delivered as a runtime secret (never committed); JWKS reachable by boxes (in-cluster Service DNS and/or public host); Helm/compose wiring for the key + endpoint.
- **New dependency:** a vetted JWS/JWT library in the identity workspace (no JWT crate exists today — verification currently lives entirely in Envoy's native `jwt_authn`). Concrete choice deferred to `/opsx:decide`.
- **Consumers:** boxes must fetch+cache the nexus JWKS and verify `iss`/`aud`/`exp`/signature on enriched routes; this is a coordinated cutover from the plain-string version check.
