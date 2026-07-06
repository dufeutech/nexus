# Box consumer contract

**Audience:** anyone building or operating a "box" — a backend that sits behind the nexus
edge (jsbox, runlet, or any Python/Node/Go service). This is the complete wire reference for
the trusted headers the edge injects and what your box must do with them.

This document is the **header-level companion** to the canonical
[`nexus-upstream-requirements.md`](../nexus-upstream-requirements.md) (which owns the
cross-repo narrative and status). Where the requirements doc lists the identity subset, this
page enumerates **every** injected header with its exact format. Behavioral authority lives in
the specs: `openspec/specs/identity-workspace-authz`, `edge-origin-trust`, `edge-auth-gate`,
`edge-request-tracing`, and `box-telemetry-contract`.

---

## 0. The one prerequisite that makes everything else safe

**Your box MUST be reachable only through the edge.** The trusted headers below are
unforgeable *because of the network path* — not because of anything in the header values.
There is no signature to check; the edge strips every client-supplied copy of these headers
(§3) and re-injects its own, so the only way a header can carry a value is if the edge put it
there. That guarantee holds **only** while the box's ingress is restricted to the edge.

- In Kubernetes: a `NetworkPolicy` (enforced by your CNI) that allows box ingress only from
  the edge pods. The Helm charts ship this fail-closed — see
  [`deploy/README.md`](../deploy/README.md) and `networkpolicy-backend.yaml`.
- Anywhere else: an equivalent, inspectable control (security group, mesh authz, etc.).

Absence of this control is a **misconfiguration, not a default-safe state**
(`edge-origin-trust/spec.md`). If your box is reachable directly, a client can forge every
header on this page.

---

## 1. Headers the edge injects (complete reference)

All values are **raw ASCII strings** — no JWT, no base64, no JSON. Plural fields are
comma-joined. Two planes author headers; the identity sidecar runs **last**, so its identity
headers are authoritative over any earlier copy.

### 1a. Identity — authored by the identity sidecar (`identity-rs/sidecar`)

Emitted on **every** enriched request, including the anonymous/no-credential path, so your box
must **never infer state from a header's absence** — read the explicit flag instead.

| Header | Meaning | Format | Box uses it for |
| --- | --- | --- | --- |
| `x-identity-contract` | **The stamp.** Version of the header-contract shape. Currently `v1`. | `vN` | **Require + validate** (§2). |
| `x-workspace-id` | The **authorized acting workspace** (set only after a live membership check). | id string | Primary tenant scope. Prefer over legacy `x-tenant-id`. |
| `x-user-id` | Verified subject (`sub`). | id string | Audit / ownership checks. |
| `x-user-type` | Acting relationship in this workspace. | `staff` \| `customer` | Acting-scope decisions. |
| `x-user-role` | Workspace-scoped role (not global). | role string | Acting-scope decisions. |
| `x-user-roles` | Coarse roles (token first, else Profile). | comma-joined | Enrichment. |
| `x-user-roles-source` | Provenance of `x-user-roles`. | `token` \| `profile` \| `none` | Diagnostics. |
| `x-user-entitlements` | Entitlements from the live Profile. | comma-joined | Feature checks. |
| `x-user-suspended` | Suspension flag (always from live Profile — revocation-sensitive). | `true` \| `false` | Hard block. |
| `x-user-enriched-by` | Provenance marker. | `identity-sidecar-rs` \| `identity-sidecar-rs:miss` | Diagnostics. |
| `x-auth-anonymous` | Is the caller anonymous. | `true` \| `false` | Branch on identity. |
| `x-auth-method` | Auth method used. | `bearer` \| `none` | Diagnostics / step-up. |

### 1b. Tenant / routing — authored by the tenant-router (`routing-rs/tenant-router`)

| Header | Meaning | Format |
| --- | --- | --- |
| `x-workspace-plan` | Tenant plan tier. | string |
| `x-workspace-features` | Enabled feature flags. | comma-joined |
| `x-route-pool` | Backend pool the edge routed to. | `api` \| `checkout` \| `assets` \| `application` |
| `x-routed-by` | Provenance marker. | literal `tenant-router` |

`x-workspace-id` is also authored here first, then **re-asserted or stripped** by the sidecar
after the membership check — treat the sidecar's value as authoritative.

### 1c. Geo context — `x-geo-*` (only when Cloudflare fronted the request)

Present only if the request arrived via Cloudflare (mapped from `cf-*`). Absent otherwise —
do not require them.

`x-geo-source` (literal `cloudflare`), `x-geo-country`, `x-geo-continent`, `x-geo-region`,
`x-geo-city`, `x-geo-postal-code`, `x-geo-timezone`, `x-geo-latitude`, `x-geo-longitude`,
`x-geo-client-ip`. Formats: ISO country/continent codes, normalized text, decimal coords.

### 1d. Request context (derived from client request, always present)

`x-locale` / `x-lang` (BCP-47 from `Accept-Language`), `x-currency` (ISO-4217, derived from
country), `x-privacy-gpc` / `x-privacy-dnt` (`true`/`false` from `Sec-GPC` / `DNT`),
`x-device-type` (`mobile` \| `desktop` \| `unknown`).

### 1e. Tracing

`traceparent` / `tracestate` — W3C trace context, **always edge-rooted**. Client copies are
stripped before Envoy makes its head-sampling decision; the sampled flag *is* the edge's
decision. See §4.

### Non-authoritative / retired — do not rely on

| Header | Status |
| --- | --- |
| `x-requested-workspace` | Client **hint**, deliberately *not* stripped. Never authoritative, never affects emitted scope. Ignore for authz. |
| `x-tenant-id` | Legacy read-fallback only. Pin the rename to `x-workspace-id`. |
| `x-user-org` | **Retired.** Never authored; always stripped. |
| `x-auth-required`, `x-auth-requires-role`, `x-auth-requires-entitlement`, `x-auth-min-aal` | **Edge-internal.** Stripped at the sidecar; never reach your box (see §2 rule 3). |

---

## 2. What your box MUST do

1. **Require and validate `x-identity-contract` on every identity-enriched route.** Reject
   (fail closed) if it is absent or an unrecognized version. A valid `vN` request by
   definition carries the acting `x-workspace-id` + `x-user-type`; a same-version request
   missing acting scope is invalid — reject it. There is no standalone acting-scope header.
2. **Fail closed by default.** Treat *every* route as enriched (require the stamp) unless a
   route is *explicitly* designated non-enriched (public/degradable). At the edge, the
   `/public` prefix is the only such designation (ext_proc disabled). Do not invert this — an
   undesignated route missing the stamp is an error, not a public request.
3. **Never trust the `x-auth-*` policy signals.** `x-auth-required` / `x-auth-requires-*` /
   `x-auth-min-aal` are the *edge's* per-route gate inputs. They are stripped at the sidecar
   and never reach you. Role/plan/AAL gating is the edge's job (it returns 401/403 before your
   box is reached). Your box keeps only **resource-ownership** checks — "does *this* user own
   *this* order" — which the edge cannot know.
4. **Read `x-workspace-id`, not `x-tenant-id`,** as the acting workspace. Read `x-user-id`
   for audit and `x-user-type` / `x-user-role` for the acting relationship.
5. **The stamp is version-drift coordination, not an auth boundary.** Its presence is not
   proof of edge origin — §0's network control is. When the header shape changes, `v1`→`v2`
   is bumped in both repos together.

---

## 3. Why the headers are trustworthy: the strip (anti-forgery)

The edge removes all client-supplied copies of the trusted family in **three independent
layers**, so a forged inbound header cannot survive to your box:

1. **Early header mutation** — `traceparent` / `tracestate` are removed *before* Envoy's
   tracer makes its root-vs-join decision, so a forged `traceparent` can't graft the request
   onto a client-rooted trace.
2. **The C3 strip filter** — the first HTTP filter, running before any resolution, removes the
   entire trusted family (`x-workspace-*`, `x-route-pool`, `x-routed-by`, all `x-geo-*`, the
   `x-locale`/`x-currency`/`x-privacy-*`/`x-device-type` family, all `x-user-*`, `x-auth-*`,
   `x-identity-contract`, and `traceparent`/`tracestate` again).
3. **Sidecar defense-in-depth** — the identity sidecar adds to its own remove-list any
   identity header it does not author on the current path, independent of Envoy's filter
   order.

Both ext_proc filters run `failure_mode_allow: false` — a plane failure **fails closed**.

> **Maintainer note — keep the two edge configs in sync.** `edge/envoy.yaml` (lab) and
> `deploy/compose/envoy/envoy.yaml` (compose) strip the *same* header list — this is a
> maintained invariant (39 `remove:` entries, identical in both). When you add or remove a
> trusted header, update **both** files. Verify with:
>
> ```sh
> diff <(grep -oE -- '- remove: "[^"]+"' edge/envoy.yaml | sort -u) \
>      <(grep -oE -- '- remove: "[^"]+"' deploy/compose/envoy/envoy.yaml | sort -u)
> ```

---

## 4. Tracing (fail-open)

- **Continue** the edge-rooted `traceparent` when present; root a new trace only when absent.
- **No box-side tail sampling** — the edge already made the head decision.
- Telemetry is **fail-open**: a collector/store outage never affects request handling.

---

## 5. Telemetry: what your box emits

nexus exposes **one** telemetry endpoint — the OTel Collector, accepting **traces, metrics,
and logs** over OTLP (gRPC `:4317` / HTTP `:4318`). Your box knows only this endpoint; the
collector alone knows the stores (traces → Tempo, metrics → Prometheus, logs → Loki).

**Onboarding is one env var:** run standard OTel SDK / auto-instrumentation and set
`OTEL_EXPORTER_OTLP_ENDPOINT=<collector>`. Unset ⇒ telemetry off, fail-open.

A compliant box emits (full spec: `box-telemetry-contract/spec.md`):

- **Resource identity** on every signal — `service.name`, `service.version`,
  `deployment.environment.name` — identical across traces/metrics/logs.
- **Traces:** continue the edge-rooted `traceparent`; no tail sampling.
- **Logs:** structured + severity-tagged, stamped with the active `trace_id` / `span_id`
  during a traced request (enables the logs↔traces pivot).
- **RED metrics:** rate, errors, duration as an **aggregatable histogram** (so fleet-wide
  p50/p95/p99 are computable across replicas). Metrics MUST be independent of trace
  sampling — deriving them from sampled traces is a defect.
- **PII hygiene:** no credentials, no bodies, no user identifiers beyond the permitted
  trusted-header set, in any span attribute, metric label, or log field.

Collector-side cost guards (metric-attribute allow-list, per-stream log rate limits,
retention: traces 48h / logs 7d / metrics 15d) mean a misbehaving box degrades only its own
telemetry.

---

## 6. Open box-side action (N5)

Nexus already emits `x-identity-contract: v1`. Boxes that still gate on a `x-tenant-scope ==
acting` check must switch to the **`x-identity-contract` version check** described in §2. This
is the remaining consumer-side work; the edge side is shipped.
