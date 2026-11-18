"""Writes abac_policies.json: exactly three ABAC policies.
  1. ip-range         allow only cluster->cluster/services traffic (everything else: default deny)
  2. time-window      untrusted nodes are denied outside 08:00-17:00
  3. malicious-node   deny any sender whose strike score is >= 3
"""
import json
START, END = 8, 17
RAFT = ["raft_message", "request_vote", "append_entries"]

def P(uid, desc, effect, prio, **rules):
    return {"uid": uid, "description": desc, "effect": effect, "rules": rules, "targets": {}, "priority": prio}

policies = [
    P("policy-1-ip-range", "Allow Raft/cert traffic only from the cluster zone to the cluster or services zone",
      "allow", 1,
      subject={"$.zone": {"condition": "IsIn", "values": ["cluster"]}},
      resource={"$.zone": {"condition": "IsIn", "values": ["cluster", "services"]}},
      action={"$.type": {"condition": "IsIn", "values": RAFT + ["cert_request"]}}),
    P("policy-2-time-window", f"Untrusted nodes may talk only between {START:02d}:00 and {END:02d}:00", "deny", 10,
      subject={"$.trust": {"condition": "Equals", "value": "untrusted"}},
      context={"$.hour": {"condition": "AnyOf", "values": [
          {"condition": "Lt", "value": START}, {"condition": "Gte", "value": END}]}}),
    P("policy-3-malicious-node", "Deny any sender with a strike score of 3 or more", "deny", 10,
      context={"$.strikes": {"condition": "Gte", "value": 3}}),
]
json.dump(policies, open("abac_policies.json", "w"), indent=2)
print(len(policies), "policies written")
