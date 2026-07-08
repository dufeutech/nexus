# identity-existence-hiding

## ADDED Requirements

### Requirement: A non-member cannot distinguish "forbidden" from "does not exist"

For a caller who is **not an authorized member** of a workspace `W`, the identity plane SHALL
return a response that is **indistinguishable** — across HTTP status code, response body, response
headers, and processing time — from the response it returns for a workspace that does not exist.
The response SHALL be **404 Not Found**. "Forbidden" and "not found" therefore collapse to a single
observable outcome for any caller who has no membership relationship with `W`, whether or not `W`
actually exists. This is the reference `404`-to-hide semantic of RFC 9110 §15.5.4.

The identity plane never performs a distinct "does `W` exist" lookup: it resolves only *this
caller's* membership of `W`, which is absent both when `W` does not exist and when `W` exists but
the caller is not a member. The single 404 branch is therefore the same code path for both cases.

#### Scenario: Non-member on an existing workspace is told "not found"
- **WHEN** an authenticated caller who is not a member of an existing workspace `W` sends a
  request in `W`'s authoritative workspace context
- **THEN** the identity plane SHALL return `404 Not Found`, NOT `403 Forbidden`, and SHALL NOT emit
  any authoritative acting scope for `W`

#### Scenario: Nonexistent workspace yields the identical response
- **WHEN** the same caller sends a request whose authoritative workspace context names a workspace
  that does not exist
- **THEN** the identity plane SHALL return a `404 Not Found` **byte-identical** (status, body, and
  headers) to the non-member 404 above, so the caller cannot infer which of the two situations
  occurred

#### Scenario: The 404 envelope carries no distinguishing signal
- **WHEN** the identity plane returns the existence-hiding `404`
- **THEN** the response body SHALL be a fixed, minimal payload and the response SHALL carry no
  header that varies with whether the workspace exists, the caller's identity, or the reason for
  refusal

#### Scenario: Existence is not leaked through timing
- **WHEN** a caller probes many workspace identifiers, some existing-but-not-theirs and some
  nonexistent
- **THEN** the identity plane SHALL process both classes on the same resolution-and-decision path
  with no existence-dependent additional work, so response time SHALL NOT distinguish an existing
  workspace from a nonexistent one; the plane SHALL NOT introduce a separate existence lookup, cache
  tier, or branch whose cost depends on `W`'s existence

### Requirement: A member who lacks a specific privilege receives an honest 403

When a caller **is** an authorized member of `W` but does not satisfy a specific route requirement
(role, entitlement, or authentication assurance level), the identity plane SHALL return
`403 Forbidden`, NOT `404`. Existence is already disclosed to a member, so hiding it serves no
purpose and a `404` would wrongly imply the workspace is absent from a caller who is inside it.

#### Scenario: Member lacking a required role is forbidden, not hidden
- **WHEN** a caller who is a member of `W` sends a request to a route that requires a role,
  entitlement, or minimum assurance level the caller does not hold
- **THEN** the identity plane SHALL return `403 Forbidden`, and SHALL NOT substitute a `404`

#### Scenario: The 403 does not name the unmet requirement
- **WHEN** the identity plane returns the `403` for an under-privileged member
- **THEN** the response body SHALL NOT disclose which specific role, entitlement, or assurance level
  was required, keeping policy detail out of the response

### Requirement: Private, workspace-scoped requests are membership-gated by default (fail-closed)

The existence-hiding `404` gate SHALL apply to a request that is BOTH (a) on a route requiring
authentication (`x-auth-required: true` — an *enriched* route) AND (b) **workspace-scoped**, i.e. a
route whose access is based on membership of the routed workspace and which would receive an
authoritative acting workspace scope. For such a request, a non-member SHALL receive the
existence-hiding `404` **regardless** of whether the route declares any role or entitlement
requirement.

Two request classes are NOT membership-gated and SHALL flow under their own auth policy:

1. **Public (non-enriched) routes** (`x-auth-required: false`) — e.g. public websites and the public
   parts of apps (landing, login, invite-acceptance). Their `x-workspace-id` is trusted-emitted
   *routing* context, not an acting scope; a nonexistent tenant on such a route MAY return an
   ordinary `404` (public existence is not a secret) and an anonymous caller SHALL NOT be refused
   for non-membership.
2. **Account-scoped private routes** (`x-auth-required: true` but not scoped to a single workspace)
   — e.g. `/me`, account settings, list-the-workspaces-I-belong-to. These are authenticated but not
   membership-gated on any one workspace; a caller SHALL reach them without a workspace membership.

The designation SHALL be **fail-closed**: an enriched request is treated as workspace-scoped (and so
gated) unless it is *explicitly* designated public or account-scoped, so a missing or mistyped
designation denies rather than leaks. All such designations (`x-auth-required` and the
public/account-scoped route markers) are trusted-emitted, stripped from client input at the edge,
and SHALL NOT be settable by the client — reusing the existing enriched/non-enriched route
designation rather than a new client-facing control.

#### Scenario: Non-member on a private workspace route with no declared requirement is 404'd
- **WHEN** a non-member sends a request to an enriched, workspace-scoped route (`x-auth-required:
  true`, scoped to `W`) that declares no role or entitlement requirement
- **THEN** the identity plane SHALL return the existence-hiding `404` rather than admitting the
  request to the backend (closing the former passthrough-to-box path for non-members)

#### Scenario: A public (non-enriched) route is not membership-gated
- **WHEN** a request reaches a route designated non-enriched (`x-auth-required: false`), carrying at
  most the routing plane's tenant `x-workspace-id`
- **THEN** the identity plane SHALL NOT apply the existence-hiding `404` on the basis of
  non-membership, and SHALL handle the request under that route's own (possibly anonymous) policy

#### Scenario: An account-scoped private route does not require workspace membership
- **WHEN** an authenticated caller reaches an enriched route explicitly designated account-scoped
  (e.g. list-my-workspaces), not scoped to a single workspace
- **THEN** the identity plane SHALL NOT return the existence-hiding `404` for lack of a workspace
  membership; the caller SHALL reach the route so they can, for example, discover the workspaces
  they belong to

#### Scenario: An enriched route missing its designation fails closed
- **WHEN** an enriched request reaches a route that should have been public or account-scoped but
  whose designation is absent or malformed
- **THEN** the identity plane SHALL treat the route as workspace-scoped and apply the membership
  check, returning the existence-hiding `404` for a non-member rather than serving the request

#### Scenario: A client cannot self-exempt from the gate
- **WHEN** an inbound request carries a client-set copy of the enriched/route-scope designation
- **THEN** the edge SHALL strip the client-supplied value before resolution, and the identity plane
  SHALL apply the gate based only on the trusted-emitted designation
