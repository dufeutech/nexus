## Context

Two admin surfaces — `routing-plane/control-plane` and `identity-plane/authz-admin` — share
one runtime auth contract (fail-closed 4-way precedence: `AUTH_DISABLED` → `ADMIN_TOKEN_PEPPER`
→ legacy token + `ADMIN_LEGACY_TOKEN_OK` → refuse) implemented in
`routing-rs/control-plane/src/main.rs:144-203` and `identity-rs/authz-admin/src/main.rs:705-763`.
The Helm charts wire only the legacy-token and disabled branches, so the pepper posture is
unreachable and the legacy posture is half-wired (token without the `_OK` flag = refuse). The
`edge-platform` umbrella is pure subchart value passthrough (top-level `routing-plane:` /
`identity-plane:` keys), so no umbrella template change is needed — surfacing the values in the
subcharts surfaces them upward automatically.

The two charts do **not** share an auth-values shape, and the gate polarity is inverted:

| | identity-plane (`authzAdmin`) | routing-plane (`controlPlane.auth`) |
|---|---|---|
| Gate | `authDisabled: false` (disable) | `auth.enabled: true` (enable) |
| Token | flat `adminToken` / `existingSecret` | nested `auth.token` / `auth.existingSecret` |
| Owns-secret helper | `ownsAuthzAdminSecret` | `ownsControlAuthSecret` |
| Secret template | `secret-authz-admin.yaml` | `secret-control-auth.yaml` |
| Env names | `IDENTITY_ADMIN_TOKEN` / `IDENTITY_ADMIN_AUTH_DISABLED` | `CONTROL_AUTH_TOKEN` / `CONTROL_AUTH_DISABLED` |

This whole incident is a drift bug: the chart fell behind the binary's contract. The precedence
rule already lives in two binary copies; the naive fix adds two more hand-mirrored chart copies.
Every copy is a new drift surface.

## Goals / Non-Goals

**Goals:**
- Make every runtime-supported admin-auth posture (disabled / pepper / legacy-migration)
  expressible in both charts and passthrough-able from the umbrella.
- Fail closed at `helm template` when no valid posture — or an incomplete one — is selected,
  mirroring the binary's startup refusal (including `legacyTokenOk` with no legacy token).
- Keep existing installs behavior-compatible: new fields default off; disabled/legacy-token
  paths that were valid before stay valid (a plain legacy token now needs `legacyTokenOk`, which
  is the binary's own BREAKING change we are exposing, not one we introduce).
- Author the posture/guard logic **once**, not per template, to close the drift surface.

**Non-Goals:**
- No binary changes; `appVersion` stays `0.0.7`.
- Not provisioning the named tokens themselves (done via the admin API post-startup) — the chart
  only delivers the pepper.
- Not unifying the two charts onto a single `mode:` enum values shape (breaking; wrong moment for
  a go-live unblock — see Decisions).
- No new umbrella template logic.

## Decisions

Concerns flagged for `/opsx:decide` are marked **[DECIDE]**; the recommendation below is the
default carried in unless the gate overrides it.

### D1 — Values surface: additive fields, not a `mode:` enum **[RESOLVED → adopt existing pattern]**
Add `tokenPepper.{existingSecret, existingSecretKey, value}` and `legacyTokenOk: false` into
each chart's **existing** block (`authzAdmin.*` and `controlPlane.auth.*`), preserving current
fields. Rejected alternative: a unified `adminAuth.mode: disabled|pepper|legacy` enum across both
charts — cleaner and self-documenting, but a breaking values migration for every current install,
which is unacceptable risk on the go-live this change exists to unblock. Additive now; a mode
enum can be a later, deliberately-migrated change. **Recommendation: additive (A).**

### D2 — Anti-drift lives in the test oracle, not a shared template **[RESOLVED → Build/duplicate + Adopt tests]**
Each chart keeps its **own** named template in `_helpers.tpl` (posture env selection + fail-closed
guard), parameterized by the plane's env-var names. The two copies are ~20 lines and are locked
against drift by golden tests (D6), not by physical sharing. A single shared partial is impossible
without breaking the standalone-render requirement: Helm merges named templates into one namespace
**only within one chart tree**, so a partial defined in the umbrella or a sibling subchart is absent
when a subchart renders on its own (which the acceptance criteria require). The remaining adopt
option — a Helm **library chart** (`bitnami/common` model) declared as a dependency by each
subchart — works standalone but is over-machinery for two charts, and carries a documented
umbrella hazard: multiple subcharts depending on distinct library versions collide on
identically-named templates. **Recommendation: duplicate the small template per chart; make the
golden test suite the single source of truth. Revisit a library chart only if a third admin surface
appears.**

### D3 — Pepper is key material, handled like the token
`ADMIN_TOKEN_PEPPER` is an HMAC key distinct from the legacy bearer. Prod path:
`tokenPepper.existingSecret` (ESO/OpenBao-seeded), env sourced via `secretKeyRef`. Dev path: inline
`tokenPepper.value`, wrapped in a chart-managed Secret exactly as `adminToken` is today — so the
`ownsSecret` helpers extend to "owns a pepper secret" symmetrically. Pepper and legacy token can
coexist (binary: pepper is the verifier, legacy only honored under `legacyTokenOk`); the template
emits both env vars when both are configured and lets the binary apply precedence.

### D4 — Render guard mirrors the binary's exact precedence
The guard `fail`s unless one holds: `authDisabled`/`!auth.enabled`; OR pepper configured; OR
(`legacyTokenOk` AND a legacy token present). It also fails on `legacyTokenOk` with no legacy
token (the binary's `"missing ..._TOKEN for legacy mode"` case). The guard message names the
three postures, matching the binary's stderr so operators see one consistent contract.

### D5 — Versioning
Minor-bump `identity-plane` (0.1.0→0.1.1 or 0.2.0), `routing-plane` (0.2.0→0.2.1 or 0.3.0), and
`edge-platform` (0.2.1→0.2.2); `appVersion` unchanged everywhere. Regenerate
`edge-platform/Chart.lock` via `helm dependency update`. Exact increments settled at apply.

### D6 — Acceptance harness: adopt `helm-unittest` **[RESOLVED → Adopt]**
No chart test tooling exists today. Adopt `helm-unittest` (org `helm-unittest/helm-unittest`,
actively maintained; the `lrills`/`quintush` forks are superseded) — the de-facto standard for
golden/assertion tests over rendered Helm templates, runnable in CI as a plugin. It is the
mechanism that makes D2's per-chart duplication safe: each chart's rendered auth env for all three
postures + both guard-failure cases becomes a locked fixture; a drifted copy turns a test red.
Adopt-before-build points here directly over a hand-rolled `helm template | grep` script (rejected:
fragile, reinvents an established tool) and over documented manual checks (rejected: not
enforced). **Recommendation: adopt `helm-unittest`.**

### Gate decisions (/opsx:decide)

#### Decision: Admin-auth values surface — Adopt existing chart pattern (additive fields)

- **Status**: approved
- **Why**: The mature-chart convention (Bitnami et al.) for a secret-bearing knob is `existingSecret` + inline value gated by a boolean — the pattern these charts already use; a `mode:` enum is a breaking values change (Helm-semver major + per-release migration), unacceptable on a go-live unblock.
- **Considered**: Unified `adminAuth.mode: disabled|pepper|legacy` enum (cleaner, self-documenting, but breaking).
- **Isolation**: Values live in each chart's `values.yaml`; the binary contract stays behind the env vars the template emits.

#### Decision: Precedence/guard drift prevention — Build (duplicate per-chart template) + Adopt tests as the oracle

- **Status**: approved
- **Why**: Charts must render standalone, and Helm scopes named templates to one chart tree — a truly shared partial is impossible without breaking standalone render. The ~20-line template is duplicated per chart and locked by golden tests; the test suite, not the template, is the single source of truth.
- **Considered**: Single shared `_helpers.tpl` `define` (breaks standalone render); Helm library chart / `bitnami/common` model (works standalone but over-machinery for two charts, and multi-subchart umbrellas collide on identically-named templates across library versions).
- **Isolation**: Guard + posture selection confined to each chart's `_helpers.tpl` named template; consumers `include` it.

#### Decision: Acceptance harness — Adopt `helm-unittest`

- **Status**: approved
- **Why**: De-facto standard for golden/assertion tests over rendered Helm templates, actively maintained (`helm-unittest/helm-unittest`, 2026), CI-runnable as a plugin; it is what makes the D2 duplication drift-safe. "Adopt before build" points here over a hand-rolled script.
- **Considered**: `helm template | grep` script (fragile, reinvents the tool); documented manual checks (unenforced).
- **Isolation**: Tests live under each chart's `tests/`; no runtime/product dependency — dev/CI tooling only.

## Risks / Trade-offs

- **[Drift resurfaces]** → D2's single authored partial; guard message string-matched to the
  binary's so a future binary-side wording change is a visible diff.
- **[Silent behavior change for existing legacy-token installs]** → a plain legacy-token install
  now fails render (needs `legacyTokenOk`). This is the binary's own BREAKING change; the guard
  makes it a clear render-time message naming the fix, not a silent CrashLoop. Called out in
  each chart's `values.yaml` docs and Chart.yaml changelog comment.
- **[Pepper delivered but no named tokens minted]** → plane starts but every admin call 401s
  until tokens are provisioned via the admin API. Operational sequencing, documented in NOTES.txt;
  see Open Questions on bootstrap.
- **[Inline pepper/token in values]** → dev-only; prod uses `existingSecret`. Same posture the
  charts already take for the legacy token.

## Migration Plan

1. Land chart changes + version bumps; regenerate `edge-platform/Chart.lock`.
2. Infra re-vendors the umbrella (`helm dependency update` on `k3s/platform/edge`), re-pins digests.
3. Infra picks a posture: prod → seed pepper into OpenBao, ESO-materialize, set
   `*.tokenPepper.existingSecret`; fastest-to-green → set `*.legacyTokenOk: true` with the
   existing legacy tokens.
4. Rollback: revert to prior chart version; disabled/legacy postures unaffected. No data migration.

## Open Questions

- **Bootstrap chicken-and-egg (pepper mode) — RESOLVED.** Both planes gate `POST /admin-tokens`
  behind `require_auth` + `require_authz` (token-admin scope), so neither can bootstrap
  pepper-only from an empty `admin_tokens` store — the first named token must be minted by an
  already-authenticated caller, and the only credential available then is the legacy shared token
  (full-scope at cutover). **Bootstrap path (both planes):** deploy with pepper AND
  `legacyTokenOk: true` + a legacy token *together* → mint named tokens via the admin API →
  remove the legacy token / set `legacyTokenOk: false`, leaving pepper-only. Chart implication:
  pepper and legacy MUST be settable simultaneously and the guard must NOT treat them as mutually
  exclusive (D4's guard is an OR, so it already allows this). `authz-admin`'s `bootstrapAdminSub`
  bootstraps the authz *grant*, which is orthogonal — it does not mint a token. Documented in each
  chart's `values.yaml` + `NOTES.txt`.
- **Shared-partial placement (D2):** can the two independently-vendored charts reference one file,
  or must the canonical partial be copied by build tooling? Settle at apply.
- **Chart.yaml increment size (D5):** minor vs patch — depends on whether `legacyTokenOk` being
  required for plain-token installs counts as breaking at the chart level (it reflects a binary
  BREAKING already shipped in 0.0.7).
