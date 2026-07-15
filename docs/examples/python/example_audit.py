"""Read the admin-action audit ledgers.

Each surface keeps its own append-only ledger with identical machinery.
This walks the control-plane ledger with cursor pagination, then exports
both planes as NDJSON and merge-sorts them into one cross-plane view
(aev_ ids are UUIDv7 — lexicographic order IS time order).

  export CP_URL=http://localhost:9400
  export AUTHZ_URL=http://localhost:9303
  export CONTROL_AUTH_TOKEN=...                # needs the read scope
  export IDENTITY_ADMIN_TOKEN=...
  python example_audit.py
"""

import json
import os

from nexus_client import AuthzAdmin, ControlPlane

cp = ControlPlane(os.environ.get("CP_URL", "http://localhost:9400"),
                  os.environ["CONTROL_AUTH_TOKEN"])
authz = AuthzAdmin(os.environ.get("AUTHZ_URL", "http://localhost:9303"),
                   os.environ["IDENTITY_ADMIN_TOKEN"])

# ---------------------------------------------------------------------------
# Query with filters (AND-composed) — e.g. everything one credential did to
# one workspace this month. iter_audit_events follows next_cursor for you.
# ---------------------------------------------------------------------------
for ev in cp.iter_audit_events(from_="2026-07-01T00:00:00Z", limit=200):
    who = ev["asserted_operator"] or ev["actor_token_id"]
    print(f"{ev['occurred_at']}  {ev['action']:<24} {ev['outcome']:<7} "
          f"by {who}  -> {ev.get('target_id')}")

# Denials are first-class events: actor 'unauthenticated' for bad credentials,
# outcome 'denied' with detail.credential = absent|invalid; scope refusals
# land as authz.denied attributed to the real actor.
denials = [ev for ev in cp.iter_audit_events(actor="unauthenticated")]
print(f"\n{len(denials)} authentication denials on the control plane")

# ---------------------------------------------------------------------------
# Export both planes and merge for auditors. Exporting changes nothing —
# no endpoint anywhere updates or deletes an event.
# ---------------------------------------------------------------------------
window = {"from_": "2026-01-01T00:00:00Z", "to": "2027-01-01T00:00:00Z"}
cp.export_audit_ndjson("cp-audit.ndjson", **window)
authz.export_audit_ndjson("authz-audit.ndjson", **window)

events = []
for path in ("cp-audit.ndjson", "authz-audit.ndjson"):
    with open(path, encoding="utf-8") as f:
        events.extend(json.loads(line) for line in f)
events.sort(key=lambda ev: ev["event_id"])  # UUIDv7: id order == time order

with open("merged-audit.ndjson", "w", encoding="utf-8") as f:
    for ev in events:
        f.write(json.dumps(ev) + "\n")
print(f"merged {len(events)} events across both planes -> merged-audit.ndjson")
