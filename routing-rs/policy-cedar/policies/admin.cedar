// Admin-plane grant policy (admin-plane-least-privilege D3) — the parity set.
//
// An action is permitted iff the credential's grant contains the action's
// class word. Deny-by-default does the rest: no forbid rules are needed, and
// an actor whose grant lacks the class (or whose scopes are empty) matches no
// permit. `token-admin` is distinguished simply by being its own class — no
// other policy's condition can satisfy it (spec "Credential administration is
// a distinguished privilege").
//
// Per-tenant narrowing later is a data change HERE (a `resource` condition on
// these or additional policies), not a code change (design D6).

@id("scope-read")
permit (
  principal,
  action == Action::"read",
  resource
)
when { principal.scopes.contains("read") };

@id("scope-provision")
permit (
  principal,
  action == Action::"provision",
  resource
)
when { principal.scopes.contains("provision") };

@id("scope-token-admin")
permit (
  principal,
  action == Action::"token-admin",
  resource
)
when { principal.scopes.contains("token-admin") };
