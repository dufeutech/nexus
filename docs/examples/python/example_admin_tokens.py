"""Manage named admin credentials on the control plane.

Every caller (signup broker, ops CLI, CI) gets its own token so audit events
name who acted. On the control plane a token also carries its GRANT — an
explicit scope set (read / provision / token-admin), deny-by-default, checked
on every request. The credential running this script needs token-admin;
requires ADMIN_TOKEN_PEPPER on the service (else 503).

  export CP_URL=http://localhost:9400
  export CONTROL_AUTH_TOKEN=...                # a token-admin credential
  python example_admin_tokens.py
"""

import os

from nexus_client import ControlPlane, NexusError

cp = ControlPlane(
    os.environ.get("CP_URL", "http://localhost:9400"),
    os.environ["CONTROL_AUTH_TOKEN"],
    acting_operator="alice@example.com",
)

# Mint a least-privilege credential for the signup broker. Scopes are
# REQUIRED and explicit — no default, and 'token-admin' is never implied,
# so this token can never mint its own successor.
issued = cp.issue_admin_token("signup-broker", ["provision", "read"])
print(f"issued {issued['token_id']}")
# `secret` (nexus_admin_...) appears in this response ONLY. Deliver it to the
# broker's secret store now; the service keeps just a peppered HMAC.
hand_off_to_secret_store = issued["secret"]  # noqa: F841 — never printed/logged

# Review every credential's grant, status and rotation lineage.
for t in cp.list_admin_tokens():
    lineage = f" (rotated_from {t['rotated_from']})" if t.get("rotated_from") else ""
    print(f"  {t['token_id']}  {t['name']:<16} {t['status']:<8} "
          f"scopes={t['scopes']}{lineage}")

# Rotate: new secret under the same name AND grant (rotation changes the
# secret, never the authorization); the old credential is dead immediately.
rotated = cp.rotate_admin_token(issued["token_id"])
print(f"rotated {issued['token_id']} -> {rotated['token_id']}")

# Revoke is idempotent and per-caller: every other token keeps working.
try:
    print(cp.revoke_admin_token(rotated["token_id"]))
except NexusError as e:
    if e.code == "last_token_admin":
        # Lockout guard: refuses to kill the last active token-admin credential.
        print("refused: that is the only credential that can administer tokens")
    else:
        raise
