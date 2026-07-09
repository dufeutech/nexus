// Parity authorization policy for the L2 gate (adopt-cedar-policy-gate, design
// Decision 2). ONE permit, deny-by-default: a request no policy permits is denied.
// This is the declarative form of the sidecar's former hand-coded `authorize_route`
// comparison — same 403/pass outcomes, same fail-closed semantics.
//
// A permit applies only when EVERY resolved requirement is satisfied by the
// enrichment the sidecar itself computed:
//
//   role         — no requirement ("") short-circuits; else the required role must be
//                  in the principal's nexus-authored roles.
//   entitlement  — no requirement ("") short-circuits; else the required entitlement
//                  must be in the principal's nexus-authored entitlements.
//   min-AAL      — no requirement (has_min_aal = false) short-circuits; else the
//                  requirement must be parseable AND the principal must carry a mapped
//                  assurance level (`principal has aal`) that meets it. A present-but-
//                  unparseable requirement, or an unmapped method, denies (fail-closed).
//
// Everything else — suspension, geo, plan, method, account_scoped — is carried but NOT
// decided on here (parity Non-Goals): adding a dimension is a later change against this
// policy, not a code change.
permit(
  principal is User,
  action == Action::"access",
  resource is Route
)
when {
  (resource.requires_role == "" || principal.roles.contains(resource.requires_role))
  &&
  (resource.requires_entitlement == "" || principal.entitlements.contains(resource.requires_entitlement))
  &&
  (!resource.has_min_aal || (resource.min_aal_parseable && principal has aal && principal.aal >= resource.min_aal))
};
