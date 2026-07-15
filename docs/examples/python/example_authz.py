"""Author a subject's authorization on the identity plane (authz-admin).

Roles, entitlements, suspension, and customer API keys. Grants are
deny-by-default: reading an unknown subject returns the zero value (empty
arrays, is_suspended=False), never a 404.

  export AUTHZ_URL=http://localhost:9303       # lab remaps 9300 -> host 9303
  export IDENTITY_ADMIN_TOKEN=...
  python example_authz.py
"""

import os

from nexus_client import AuthzAdmin, NexusError

authz = AuthzAdmin(
    os.environ.get("AUTHZ_URL", "http://localhost:9303"),
    os.environ["IDENTITY_ADMIN_TOKEN"],
    acting_operator="alice@example.com",
)

SUB = "user-123"

# Grant a role and an entitlement (role = who they are, entitlement = what
# they've paid for — separate axes).
authz.assign_role(SUB, "admin")
authz.grant_entitlement(SUB, "billing:read")

facts = authz.get_subject(SUB)
print(f"{facts['sub']}: roles={facts['roles']} "
      f"entitlements={facts['entitlements']} suspended={facts['is_suspended']}")

# Suspend and reactivate.
authz.suspend(SUB)
assert authz.get_subject(SUB)["is_suspended"]
authz.reactivate(SUB)

# Revoke again.
authz.revoke_role(SUB, "admin")
authz.revoke_entitlement(SUB, "billing:read")

# ---------------------------------------------------------------------------
# Customer API keys — requires APIKEY_HMAC_PEPPER on the service, else 503.
# Scopes are workspace ids the creator is a live member of.
# ---------------------------------------------------------------------------
try:
    key = authz.issue_api_key(
        creator_sub=SUB,
        workspace_scopes=["ws_0190f7e0-0000-7000-8000-000000000000"],
        expires_in_seconds=3600,
    )
except NexusError as e:
    if e.status == 503:
        print("API key management not configured on this deployment (no pepper set)")
        raise SystemExit(0)
    raise

# The plaintext secret appears in this response ONLY — persist it now.
print(f"issued key {key['key_id']} (expires_at={key['expires_at']})")
store_secret_somewhere_safe = key["secret"]  # noqa: F841 — never printed/logged

# Rotation issues a new secret, revokes the old one, and keeps the scopes.
rotated = authz.rotate_api_key(key["key_id"])
print(f"rotated -> {rotated['key_id']}")

# Revocation is idempotent.
print(authz.revoke_api_key(rotated["key_id"]))
