## 1. Spec

- [ ] 1.1 Confirm the new `domain-host-resolution` delta spec captures the shipped behavior (exact → single-label wildcard → fail-closed; apex/wildcard coexistence; most-specific-wins; single-label depth; router==/authorize parity) and `openspec validate ratify-domain-host-matching --type change` passes.

## 2. Guard tests (no production code changes)

- [ ] 2.1 `router-core`: unit-test the resolution ordering intent directly against `normalize`/`parent_domain` — assert single-label parent derivation and that a non-conforming host normalizes to no-match.
- [ ] 2.2 `store-postgres/tests/integration.rs`: add wildcard-row coverage (today exact-only) — seed an apex exact row and a wildcard row for the same domain; assert the apex resolves to workspace A and a subdomain resolves to workspace B (apex ≠ wildcard, coexistence).
- [ ] 2.3 `store-postgres` integration: assert exact-beats-wildcard — an exact `shop.example.com` row wins over a covering `example.com` wildcard.
- [ ] 2.4 `store-postgres` integration: assert single-label depth — `a.b.example.com` does NOT resolve via a `example.com` wildcard (no `b.example.com` row), and DOES resolve via a `b.example.com` wildcard.
- [ ] 2.5 `store-postgres` integration: assert fail-closed no-match — an unknown host resolves to no tenant (never a default).
- [ ] 2.6 `tenant-router`: add a `/authorize`-vs-router parity test — for a set of hosts (exact hit, wildcard-covered subdomain, nested miss, unknown), assert `authorize` allows exactly the hosts `resolve` routes and denies the rest.

## 3. Documentation

- [x] 3.1 Correct the stale N3 section in `nexus-upstream-requirements.md`: replace the "one row per domain string" description with the shipped composite `(domain, is_wildcard)` model, note apex+wildcard coexistence + most-specific-wins + single-label semantics, and point to the new `domain-host-resolution` spec + guard tests as the canonical, now-tested contract.

## 4. Close-out

- [ ] 4.1 Run the full test suite for the touched crates (`router-core`, `store-postgres`, `tenant-router`) and confirm green.
- [ ] 4.2 `/opsx:sync` the `domain-host-resolution` delta into main specs, then `/opsx:archive` the change.
