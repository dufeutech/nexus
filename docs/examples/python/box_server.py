"""Example "box" — a little backend that receives requests FROM the nexus edge.

Implements the consumer side of docs/box-consumer-contract.md:

  * verifies the signed `x-identity-contract` (ES256 JWS) against the nexus
    JWKS, checking iss / aud / exp / ctr, and fails CLOSED on every
    identity-enriched route (Sec.2 rule 1-2);
  * reads identity from the VERIFIED claims — entitlements and suspension ride
    only the contract, never bare headers (they were retired);
  * keeps only resource-ownership checks — role/plan/AAL gating already
    happened at the edge (Sec.2 rule 3);
  * keeps the body-workspace_id backstop without leaking existence (Sec.1b');
  * branches on the explicit `x-auth-anonymous` flag, never on a header's
    absence.

PREREQUISITE (Sec.0): this server must be reachable ONLY through the edge
(NetworkPolicy / security group). The headers are trustworthy because the edge
strips every client-supplied copy — that guarantee holds only on that network
path. The signature on the contract is a second gate, not a substitute.

Run:
  pip install fastapi uvicorn "PyJWT[crypto]"

  export NEXUS_JWKS_URL=http://localhost:9210/.well-known/jwks.json
  export NEXUS_ISSUER=https://identity.nexus
  export BOX_NAME=application            # the pool nexus routes to you as
  uvicorn box_server:app --port 8080
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Optional

import jwt
from fastapi import Depends, FastAPI, HTTPException, Request
from jwt import PyJWKClient

JWKS_URL = os.environ.get(
    "NEXUS_JWKS_URL", "http://localhost:9210/.well-known/jwks.json"
)
ISSUER = os.environ.get("NEXUS_ISSUER", "https://identity.nexus")
# aud is YOUR box's name — the value nexus routes to you as x-route-pool.
# A contract minted for another box will not verify here.
BOX_NAME = os.environ.get("BOX_NAME", "application")
ACCEPTED_CONTRACT_VERSIONS = {1}  # `ctr` claim — reject versions you don't understand

# PyJWKClient caches the key set and refetches on an unknown `kid`,
# which is exactly the rotation behavior the contract asks for (Sec.1a-bis.1).
_jwks = PyJWKClient(JWKS_URL, cache_keys=True)

app = FastAPI(title="example nexus box")


@dataclass
class Identity:
    """The verified acting identity, read from the contract's claims."""

    sub: str  # user sub / service id / api-key id
    workspace_id: str  # the AUTHORIZED acting workspace
    principal_kind: str  # user | apikey | service
    role: Optional[str] = None  # workspace-scoped; absent for a service
    roles: list[str] = field(default_factory=list)
    entitlements: list[str] = field(default_factory=list)
    permissions: list[str] = field(default_factory=list)  # service principals only
    plan: Optional[str] = None  # absent => NOT provisioned, never a default tier
    on_behalf_of: Optional[str] = None  # apikey only: the creating human


def _verify_contract(token: str) -> Identity:
    """Verify the compact JWS and map claims -> Identity. Raises 401 on any
    failure — an unverifiable contract on an enriched route means reject."""
    try:
        key = _jwks.get_signing_key_from_jwt(token).key
        claims = jwt.decode(
            token,
            key,
            algorithms=["ES256"],
            issuer=ISSUER,
            audience=BOX_NAME,
            leeway=60,  # small clock-skew allowance on exp
            options={"require": ["exp", "iss", "aud"]},
        )
    except jwt.PyJWTError:
        raise HTTPException(401, "invalid identity contract")

    # ctr is the drift tripwire for the whole header/claim shape.
    if claims.get("ctr") not in ACCEPTED_CONTRACT_VERSIONS:
        raise HTTPException(401, "unrecognized contract version")

    # NOTE: `jti` may legitimately repeat across requests within the token's
    # short lifetime — it is audit correlation, NOT a replay nonce. Freshness
    # is bounded by `exp`; never cache these claims past it (a just-suspended
    # user must not keep acting on a stale contract).

    kind = claims.get("principal_kind", "user")
    suspended = claims.get("suspended")  # bool, or ABSENT
    if kind != "service":
        # Absent suspended = unknown -> fail safe; true = hard block.
        # A service is not a suspendable user, so absence is normal there.
        if suspended is None:
            raise HTTPException(403, "suspension state unknown")
        if suspended:
            raise HTTPException(403, "suspended")

    return Identity(
        sub=claims["sub"],
        workspace_id=claims["workspace_id"],
        principal_kind=kind,
        role=claims.get("role"),
        roles=claims.get("roles", []),
        entitlements=claims.get("entitlements", []),
        permissions=claims.get("permissions", []),
        plan=claims.get("plan"),
        on_behalf_of=claims.get("on_behalf_of"),
    )


def require_identity(request: Request) -> Identity:
    """Dependency for identity-enriched routes: contract absent -> reject.

    Fail closed by default — every route is enriched unless explicitly
    designated public (at the edge, the /public prefix is the only such
    designation). nexus mints the contract only for a resolved authority, so
    an unauthorized caller never reaches you with a valid one."""
    token = request.headers.get("x-identity-contract")
    if not token:
        raise HTTPException(401, "missing identity contract")
    return _verify_contract(token)


def optional_identity(request: Request) -> Optional[Identity]:
    """For enriched routes that ALLOW anonymous browsing: branch on the
    explicit x-auth-anonymous flag — never on a header's absence."""
    if request.headers.get("x-auth-anonymous") == "true":
        return None
    return require_identity(request)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@app.get("/public/health")
def health():
    """/public/* is the edge's only non-enriched designation (ext_proc off):
    no contract to require here. Everything else fails closed."""
    return {"status": "ok"}


@app.get("/whoami")
def whoami(request: Request, who: Identity = Depends(require_identity)):
    """Echo the verified identity plus a few informational raw headers."""
    return {
        # From the VERIFIED contract (authoritative):
        "sub": who.sub,
        "workspace_id": who.workspace_id,
        "principal_kind": who.principal_kind,
        "role": who.role,
        "entitlements": who.entitlements,
        # apikey principals act for a human — attribute to BOTH.
        "on_behalf_of": who.on_behalf_of,
        # plan absent => not provisioned: grant no tier, don't default to free.
        "plan_tier": who.plan or "not-provisioned",
        # Informational request context the edge derives (Sec.1d):
        "locale": request.headers.get("x-locale"),
        "device": request.headers.get("x-device-type"),
        # Geo is present only when Cloudflare fronted the request — optional.
        "country": request.headers.get("x-geo-country"),
    }


@app.get("/catalog")
def catalog(who: Optional[Identity] = Depends(optional_identity)):
    """An enriched route that allows anonymous browsing."""
    items = [{"sku": "widget-1", "price": 999}]
    if who and "catalog:wholesale" in who.entitlements:
        # Entitlements come ONLY from the signed contract — the bare
        # x-user-entitlements header is retired and never emitted.
        items.append({"sku": "widget-1-bulk", "price": 799})
    return {"items": items, "anonymous": who is None}


# Toy datastore, keyed by (workspace, order) — every row is workspace-scoped.
ORDERS = {
    ("ws_demo", "order-1"): {
        "order_id": "order-1",
        "owner_sub": "user-123",
        "total": 4200,
    },
}


@app.get("/orders/{order_id}")
def get_order(order_id: str, who: Identity = Depends(require_identity)):
    """The box's ONLY remaining authz job is resource ownership — "does THIS
    user own THIS order". Role/entitlement/AAL gating already happened at the
    edge, and a non-member of the workspace never reaches us (the sidecar
    already served them nexus's existence-hiding 404)."""
    order = ORDERS.get((who.workspace_id, order_id))
    if order is None:
        raise HTTPException(404, "order not found")
    if who.principal_kind != "service" and order["owner_sub"] != who.sub:
        # A member merely lacking access gets an honest 403 — membership
        # already disclosed the workspace's existence.
        raise HTTPException(403, "not your order")
    return order


@app.post("/orders")
async def create_order(request: Request, who: Identity = Depends(require_identity)):
    body = await request.json()
    # Backstop (Sec.1b'): a body workspace_id disagreeing with the
    # authoritative x-workspace-id is rejected WITHOUT revealing whether the
    # body's workspace exists — mirror our own not-found shape, never a
    # distinguishable 403.
    if body.get("workspace_id") not in (None, who.workspace_id):
        raise HTTPException(404, "order not found")
    order_id = f"order-{len(ORDERS) + 1}"
    ORDERS[(who.workspace_id, order_id)] = {
        "order_id": order_id,
        "owner_sub": who.on_behalf_of or who.sub,  # attribute automation to its human
        "total": body.get("total", 0),
    }
    return {"order_id": order_id}


@app.post("/events")
async def write_event(request: Request, who: Identity = Depends(require_identity)):
    """The write door for platform services: authorize a `service` principal
    by its least-privilege `permissions` set, not by role (it has none)."""
    if who.principal_kind != "service" or "events:write" not in who.permissions:
        raise HTTPException(403, "events:write permission required")
    event = await request.json()
    return {"accepted": True, "workspace_id": who.workspace_id, "event": event}


# Telemetry (Sec.5): run the standard OTel SDK / auto-instrumentation with
# OTEL_EXPORTER_OTLP_ENDPOINT=<collector>. It continues the edge-rooted
# traceparent automatically (no box-side tail sampling) and is fail-open —
# leave the env var unset and telemetry is simply off.
