"""Thin Python clients for the two nexus admin surfaces.

- AuthzAdmin      -> identity plane  (:9300, IDENTITY_ADMIN_TOKEN / named token)
- ControlPlane    -> routing plane   (:9400, CONTROL_AUTH_TOKEN / named token)

These are deliberately thin adapters over the HTTP API described in
docs/admin-apis.md and docs/openapi/*.yaml. For a fully generated client, see
docs/openapi/README.md (openapi-generator).

Requires: pip install httpx
"""

from __future__ import annotations

import urllib.parse
from typing import Any, Iterator, Optional

import httpx


class NexusError(Exception):
    """Non-2xx response. `code` is the machine-readable "error" field."""

    def __init__(self, status: int, code: str, body: Any):
        self.status = status
        self.code = code
        self.body = body
        super().__init__(f"{status} {code}")


class _Surface:
    """Shared plumbing: bearer auth, envelope handling, operator assertion."""

    def __init__(self, base_url: str, token: str, acting_operator: Optional[str] = None):
        # Quote as one header value — a word-split "Bearer <token>" silently 401s.
        self.session = httpx.Client(
            base_url=base_url.rstrip("/"),
            headers={"authorization": f"Bearer {token}"},
        )
        # Optional human attribution, recorded verbatim in audit events
        # (asserted_operator). Never used for authentication or authorization.
        self.acting_operator = acting_operator

    def _headers(self, method: str) -> dict:
        if self.acting_operator and method != "GET":
            return {"x-acting-operator": self.acting_operator}
        return {}

    @staticmethod
    def _raise_for_status(resp: httpx.Response) -> None:
        if resp.is_success:
            return
        try:
            body = resp.json()
        except ValueError:
            body = resp.text
        code = body.get("error", "unknown") if isinstance(body, dict) else "unknown"
        raise NexusError(resp.status_code, code, body)

    def _json(self, method: str, path: str, *, json: Any = None,
              params: Optional[dict] = None) -> dict:
        resp = self.session.request(method, path, json=json, params=params,
                                    headers=self._headers(method))
        self._raise_for_status(resp)
        return resp.json()

    # ------------------------------------------------------------------
    # Admin credentials + audit ledger — identical machinery on BOTH
    # surfaces (per-plane ledgers and token tables).
    # ------------------------------------------------------------------

    def issue_admin_token(self, name: str, scopes: list[str]) -> dict:
        """Mint a named admin credential. The plaintext `secret` is returned
        ONCE — store it immediately. Control-plane scopes: read | provision |
        token-admin (required, non-empty). Requires the token-admin scope."""
        return self._json("POST", "/admin-tokens", json={"name": name, "scopes": scopes})

    def list_admin_tokens(self) -> list[dict]:
        """Every credential's grant/status/lineage — never secret material."""
        return self._json("GET", "/admin-tokens")["tokens"]

    def rotate_admin_token(self, token_id: str) -> dict:
        """New secret, same name AND grant; old credential dies. Returns the
        NEW {token_id, secret} (secret shown once)."""
        return self._json("POST", f"/admin-tokens/{token_id}/rotate")

    def revoke_admin_token(self, token_id: str) -> dict:
        """Idempotent. Raises NexusError(409, 'last_token_admin') rather than
        locking you out of credential administration."""
        return self._json("POST", f"/admin-tokens/{token_id}/revoke")

    def iter_audit_events(self, *, from_: Optional[str] = None, to: Optional[str] = None,
                          actor: Optional[str] = None, target: Optional[str] = None,
                          limit: int = 100) -> Iterator[dict]:
        """Walk the append-only ledger, following cursor pagination until an
        empty page. Filters AND-compose; timestamps are RFC 3339."""
        params: dict[str, Any] = {"limit": limit}
        if from_:
            params["from"] = from_
        if to:
            params["to"] = to
        if actor:
            params["actor"] = actor
        if target:
            params["target"] = target
        while True:
            page = self._json("GET", "/audit/events", params=params)
            if not page["events"]:
                return
            yield from page["events"]
            params["cursor"] = page["next_cursor"]

    def export_audit_ndjson(self, dest_path: str, *, from_: Optional[str] = None,
                            to: Optional[str] = None) -> int:
        """Stream the NDJSON export to a file; returns the line count."""
        params = {}
        if from_:
            params["from"] = from_
        if to:
            params["to"] = to
        lines = 0
        with self.session.stream("GET", "/audit/events/export", params=params) as resp:
            if not resp.is_success:
                resp.read()  # buffer the body so _raise_for_status can parse it
            self._raise_for_status(resp)
            with open(dest_path, "w", encoding="utf-8", newline="\n") as f:
                for line in resp.iter_lines():
                    if line:
                        f.write(line + "\n")
                        lines += 1
        return lines


class AuthzAdmin(_Surface):
    """identity plane (:9300; local compose lab remaps to host :9303).

    Single source of record for who a subject is ALLOWED TO BE. Grants are
    deny-by-default: unknown subjects read back as the zero value, not 404.
    """

    # -- effective facts ------------------------------------------------

    def get_subject(self, sub: str) -> dict:
        """{sub, roles, entitlements, is_suspended} — always 200."""
        return self._json("GET", f"/authz/{urllib.parse.quote(sub)}")

    # -- roles / entitlements -------------------------------------------

    def assign_role(self, sub: str, role: str) -> dict:
        return self._json("PUT", f"/authz/{urllib.parse.quote(sub)}/roles",
                          json={"role": role})

    def revoke_role(self, sub: str, role: str) -> dict:
        return self._json("DELETE",
                          f"/authz/{urllib.parse.quote(sub)}/roles/{urllib.parse.quote(role)}")

    def grant_entitlement(self, sub: str, entitlement: str) -> dict:
        return self._json("PUT", f"/authz/{urllib.parse.quote(sub)}/entitlements",
                          json={"entitlement": entitlement})

    def revoke_entitlement(self, sub: str, entitlement: str) -> dict:
        # ':' is a legal path character (e.g. billing:read) — keep it unescaped.
        ent = urllib.parse.quote(entitlement, safe=":")
        return self._json("DELETE", f"/authz/{urllib.parse.quote(sub)}/entitlements/{ent}")

    # -- suspension ------------------------------------------------------

    def suspend(self, sub: str) -> dict:
        return self._json("POST", f"/authz/{urllib.parse.quote(sub)}/suspend")

    def reactivate(self, sub: str) -> dict:
        return self._json("POST", f"/authz/{urllib.parse.quote(sub)}/reactivate")

    # -- customer API keys (requires APIKEY_HMAC_PEPPER on the service) ---

    def issue_api_key(self, creator_sub: str, workspace_scopes: list[str],
                      expires_in_seconds: Optional[int] = None) -> dict:
        """201 {key_id, secret, expires_at}. The plaintext `secret` is returned
        ONCE. Scopes are workspace ids the creator is a live member of."""
        body: dict[str, Any] = {"creator_sub": creator_sub, "scopes": workspace_scopes}
        if expires_in_seconds is not None:
            body["expires_in_seconds"] = expires_in_seconds
        return self._json("POST", "/apikeys", json=body)

    def rotate_api_key(self, key_id: str) -> dict:
        """New secret, same scopes, old secret revoked. 201, same shape as issue."""
        return self._json("POST", f"/apikeys/{key_id}/rotate")

    def revoke_api_key(self, key_id: str) -> dict:
        """Idempotent: {result: ok, revoked: true}."""
        return self._json("POST", f"/apikeys/{key_id}/revoke")


class ControlPlane(_Surface):
    """routing plane (:9400). Tenancy & routing: accounts, workspaces,
    members, auth-routes, custom domains.

    Ids are SERVER-MINTED (acct_<uuidv7> / ws_<uuidv7>): capture them from the
    create response — a create body carrying an id field is rejected (422).
    """

    # -- accounts ---------------------------------------------------------

    def provision_account(self, owner_sub: str, *, name: str = "",
                          payer_ref: Optional[str] = None,
                          idempotency_key: Optional[str] = None) -> dict:
        """{result, account_id, created}. created=false means an
        idempotency-key replay returned the ORIGINAL account."""
        body: dict[str, Any] = {"owner_sub": owner_sub, "name": name}
        if payer_ref is not None:
            body["payer_ref"] = payer_ref
        if idempotency_key is not None:
            body["idempotency_key"] = idempotency_key
        return self._json("POST", "/accounts", json=body)

    def get_account(self, account_id: str) -> dict:
        """{account, members}."""
        return self._json("GET", f"/accounts/{account_id}")

    # -- workspaces -------------------------------------------------------

    def create_workspace(self, target_pool: str, *, name: str = "",
                         account_id: Optional[str] = None, plan: str = "free",
                         features: Optional[list[str]] = None,
                         idempotency_key: Optional[str] = None) -> dict:
        """{result, workspace_id, created}. Create-only — never overwrites."""
        body: dict[str, Any] = {"target_pool": target_pool, "name": name, "plan": plan}
        if account_id is not None:
            body["account_id"] = account_id
        if features is not None:
            body["features"] = features
        if idempotency_key is not None:
            body["idempotency_key"] = idempotency_key
        return self._json("POST", "/workspaces", json=body)

    def get_workspace(self, workspace_id: str) -> dict:
        return self._json("GET", f"/workspaces/{workspace_id}")

    def reconfigure_workspace(self, workspace_id: str, *, plan: str, target_pool: str,
                              features: Optional[list[str]] = None) -> dict:
        """Full desired config — plan and target_pool are both REQUIRED here
        (no silent downgrade). Update-only: unknown id -> 404, never a create."""
        body: dict[str, Any] = {"plan": plan, "target_pool": target_pool}
        if features is not None:
            body["features"] = features
        return self._json("PUT", f"/workspaces/{workspace_id}", json=body)

    def transfer_workspace(self, workspace_id: str, account_id: str) -> dict:
        """{result, workspace_id, account_id, staff_removed}."""
        return self._json("POST", f"/workspaces/{workspace_id}/transfer",
                          json={"account_id": account_id})

    # -- members ------------------------------------------------------------

    def list_members(self, workspace_id: str) -> list[dict]:
        return self._json("GET", f"/workspaces/{workspace_id}/members")["memberships"]

    def upsert_member(self, workspace_id: str, user_sub: str, member_type: str,
                      *, role: str = "member", status: str = "active") -> dict:
        """member_type must be 'staff' or 'customer'."""
        return self._json("PUT", f"/workspaces/{workspace_id}/members", json={
            "user_sub": user_sub, "member_type": member_type,
            "role": role, "status": status,
        })

    def remove_member(self, workspace_id: str, user_sub: str) -> dict:
        return self._json(
            "DELETE",
            f"/workspaces/{workspace_id}/members/{urllib.parse.quote(user_sub)}")

    # -- auth-routes ----------------------------------------------------------

    def list_auth_routes(self, workspace_id: str) -> list[dict]:
        return self._json("GET", f"/workspaces/{workspace_id}/auth-routes")["routes"]

    def upsert_auth_route(self, workspace_id: str, path_prefix: str, auth_required: bool,
                          *, requires_role: Optional[str] = None,
                          requires_entitlement: Optional[str] = None,
                          min_aal: Optional[int] = None,
                          account_scoped: bool = False) -> dict:
        """Any requirement with auth_required=False is a 400
        (requirements_need_auth). account_scoped=True existence-hides the
        route from non-members (404 before the role gate)."""
        return self._json("PUT", f"/workspaces/{workspace_id}/auth-routes", json={
            "path_prefix": path_prefix, "auth_required": auth_required,
            "requires_role": requires_role, "requires_entitlement": requires_entitlement,
            "min_aal": min_aal, "account_scoped": account_scoped,
        })

    def delete_auth_route(self, workspace_id: str, path_prefix: str) -> dict:
        return self._json("DELETE", f"/workspaces/{workspace_id}/auth-routes",
                          json={"path_prefix": path_prefix})

    # -- custom domains (declare -> publish TXT -> verify) --------------------

    def declare_domain(self, workspace_id: str, domain: str) -> dict:
        """Starts DNS-ownership verification. The response's `dns_record`
        ({name, type: TXT, value}) is what you publish at the DNS provider;
        it is absent when the domain is already verified."""
        return self._json("POST", "/domains/declare",
                          json={"workspace_id": workspace_id, "domain": domain})

    def verify_domain(self, domain: str) -> dict:
        """Raises NexusError on 404 no_challenge / 410 challenge_expired /
        422 proof_not_found (TXT not visible yet) / 503 resolution_failed."""
        return self._json("POST", f"/domains/{domain}/verify")

    def delete_domain(self, domain: str, *, wildcard: Optional[bool] = None) -> dict:
        params = {"wildcard": str(wildcard).lower()} if wildcard is not None else None
        return self._json("DELETE", f"/domains/{domain}", params=params)
