"""Attach a customer's custom domain: declare -> publish TXT -> verify.

A domain only routes once VERIFIED. Declaring returns the DNS proof record;
after the customer publishes it, poll verify until the TXT propagates.
Operational context: docs/runbook-custom-domains-tls.md.

  export CP_URL=http://localhost:9400
  export CONTROL_AUTH_TOKEN=...
  python example_domains.py ws_<uuidv7> shop.example.com
"""

import os
import sys
import time

from nexus_client import ControlPlane, NexusError

workspace_id, domain = sys.argv[1], sys.argv[2]

cp = ControlPlane(
    os.environ.get("CP_URL", "http://localhost:9400"),
    os.environ["CONTROL_AUTH_TOKEN"],
)

# 1. Declare. Handle each documented failure explicitly.
try:
    declared = cp.declare_domain(workspace_id, domain)
except NexusError as e:
    if e.code == "domain_taken":          # 409 — owned by another workspace
        raise SystemExit(f"{domain} is already claimed")
    if e.code == "quota_exceeded":        # 402 — plan limit; body has plan/limit/used
        raise SystemExit(f"domain quota: {e.body}")
    raise                                  # invalid_domain, unknown_workspace, ...

if declared["verified"]:
    print(f"{domain} is already verified — nothing to do")
    raise SystemExit(0)

# 2. Hand the proof record to whoever controls the DNS zone.
rec = declared["dns_record"]
print("publish this TXT record, then verification can proceed:")
print(f"  {rec['name']}  IN  TXT  \"{rec['value']}\"")

# 3. Poll verify. 422 proof_not_found just means the TXT isn't visible yet
#    (propagation); 503 resolution_failed is a transient resolver problem.
#    Anything else is terminal for this challenge.
for attempt in range(20):
    try:
        result = cp.verify_domain(domain)
        print(f"verified: {result}")
        break
    except NexusError as e:
        if e.code in ("proof_not_found", "resolution_failed"):
            print(f"  not yet ({e.code}), retrying in 30s...")
            time.sleep(30)
            continue
        if e.code == "challenge_expired":  # 410 — re-declare to get a fresh token
            raise SystemExit("challenge expired; run this script again to re-declare")
        raise
else:
    raise SystemExit("gave up waiting for DNS propagation")
