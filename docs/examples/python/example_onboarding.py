"""End-to-end tenant onboarding against the control plane.

Provision an account -> create a workspace under it -> add a staff member ->
protect a path with an auth-route. Safe to re-run: both creates carry an
idempotency key, so a retry returns the ORIGINAL resource (created=False)
instead of minting a duplicate.

  export CP_URL=http://localhost:9400          # lab default
  export CONTROL_AUTH_TOKEN=nexus_admin_...    # needs provision+read scopes
  python example_onboarding.py
"""

import os

from nexus_client import ControlPlane

cp = ControlPlane(
    os.environ.get("CP_URL", "http://localhost:9400"),
    os.environ["CONTROL_AUTH_TOKEN"],
    acting_operator="alice@example.com",  # optional; lands in the audit ledger
)

# 1. Provision the account. The id is server-minted — capture it from the
#    response; you cannot choose one. Keyed on the signup flow so a blind
#    retry (network blip, crashed worker) cannot double-provision.
acct = cp.provision_account(
    owner_sub="user-123",
    name="Acme",
    payer_ref="stripe_cus_x",
    idempotency_key="signup:user-123",
)
account_id = acct["account_id"]
print(f"account {account_id} (created={acct['created']})")

# 2. Create a workspace owned by that account. target_pool is required and
#    must be in the service's pool allow-list.
ws = cp.create_workspace(
    target_pool="application",
    name="Acme Shop",
    account_id=account_id,
    plan="pro",
    features=["beta"],
    idempotency_key="onboard:acme-shop",
)
workspace_id = ws["workspace_id"]
print(f"workspace {workspace_id} (created={ws['created']})")

# 3. Add a staff admin.
cp.upsert_member(workspace_id, "user-123", "staff", role="admin")

# 4. Gate /admin: authenticated admins with AAL2, and hide the route's very
#    existence from non-members of the owning account.
rule = cp.upsert_auth_route(
    workspace_id, "/admin", True,
    requires_role="admin", min_aal=2, account_scoped=True,
)
print(f"auth-route stored: {rule['path_prefix']} (auth_required={rule['auth_required']})")

# Read everything back.
print(cp.get_workspace(workspace_id))
for m in cp.list_members(workspace_id):
    print(f"  member {m['user_sub']}: {m['member_type']}/{m['role']} ({m['status']})")
