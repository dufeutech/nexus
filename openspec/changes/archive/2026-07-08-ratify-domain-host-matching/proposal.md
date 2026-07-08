## Why

nexus already resolves an inbound hostname to a workspace with the industry-standard model —
exact host beats a single-label wildcard, apex and wildcard coexist, and the `/authorize` cert
gate shares the router's matcher — but that behavior is **unspecified** (it lives only in code and
schema comments, nothing in `openspec/specs/`) and **unguarded** (no test pins apex-vs-wildcard or
exact-vs-wildcard precedence). This is a routing **and** cert-authorization boundary, so
undocumented, untested behavior is a real drift risk: a refactor of `resolve()` could silently
change which hostnames route or get certs, with no failing test to catch it.

## What Changes

- Introduce a canonical **domain-host-resolution** capability that specifies the existing matching
  model as a durable contract: exact-first, then single-label wildcard, else fail-closed no-tenant;
  apex and wildcard independent and coexisting; most-specific-wins; single-label depth only; one
  matcher shared identically by routing and cert authorization.
- Add guard tests that pin the security-relevant behavior (apex ≠ wildcard, exact beats wildcard,
  single-label depth, apex+wildcard coexistence, and `/authorize` == router host-set parity),
  filling today's gap where no test exercises wildcard resolution at all.
- Correct the stale N3 section of `nexus-upstream-requirements.md`, which still describes the
  retired single-row-per-domain schema.
- **No behavior change and no routing-code change.** This ratifies and guards what already ships.

## Capabilities

### New Capabilities
- `domain-host-resolution`: how nexus maps an inbound hostname (SNI / Host) to a workspace — the
  exact-then-single-label-wildcard matching lattice, apex/wildcard coexistence, fail-closed no-match,
  and the invariant that routing and cert authorization resolve the identical host set.

### Modified Capabilities
<!-- None. workspace-tenancy states "domains are many-to-one aliases" but says nothing about host
     matching; the matching contract is genuinely new spec surface, not a change to an existing
     requirement. -->

## Impact

- **Specs**: new `specs/domain-host-resolution/spec.md`.
- **Tests** (guard-only, no production code touched): `router-core` (`normalize`/`resolve` unit
  coverage), `store-postgres/tests/integration.rs` (wildcard-row lookups, currently exact-only),
  and a `/authorize`-vs-router parity test in `tenant-router`.
- **Docs**: `nexus-upstream-requirements.md` §N3 corrected.
- **Explicitly out of scope**: self-service wildcard declaration, plan-tier depth gating, PSL/eTLD+1
  adoption, multi-label/nested wildcards, downgrade semantics, and any change to `resolve()` or the
  `routing.domains` schema. The composite `(domain, is_wildcard)` key already forward-provisions a
  future gated-wildcard tier; this change deliberately does not build it.
