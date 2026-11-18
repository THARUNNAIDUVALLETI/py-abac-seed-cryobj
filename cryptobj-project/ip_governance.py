#!/usr/bin/env python3
"""Policy 1 support: IP registry -> blackhole list, drift audit, self-test."""
import ipaddress as ip, json, os, subprocess, sys
REG = "/app/ip_registry.json"
if not os.path.exists(REG):
    REG = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ip_registry.json")
reg = json.load(open(REG))

def range_blocks():
    """Everything in the supernet that is not in a zone, plus the denied external ranges."""
    nets = [ip.ip_network(reg["supernet"])]
    for z in reg["zones"].values():
        a, out = ip.ip_network(z["cidr"]), []
        for n in nets:
            if a == n or n.subnet_of(a): continue
            out += list(n.address_exclude(a)) if a.subnet_of(n) else [n]
        nets = out
    return sorted({str(n) for n in nets} | {str(ip.ip_network(d)) for d in reg["denied"]})

def my_ip():
    out = subprocess.run(["ip", "-4", "-o", "addr", "show", "net0"], capture_output=True, text=True).stdout
    return out.split()[3].split("/")[0] if out else None

def audit():
    me, bad = my_ip(), 0
    owner = next(((z, n) for z, d in reg["zones"].items() for n, a in d["members"].items() if a == me), None)
    print(f"[GOVERNANCE] my ip {me}: " + (f"registered as {owner[1]} in zone {owner[0]}" if owner else "NOT IN REGISTRY"))
    bad += owner is None
    have = set()
    for l in subprocess.run(["ip", "route", "show", "type", "blackhole"], capture_output=True, text=True).stdout.splitlines():
        p = l.split()
        if len(p) > 1: have.add(str(ip.ip_network(p[1], strict=False)))
    missing = set(range_blocks()) - have
    print("[GOVERNANCE] expected ranges blocked:", "all" if not missing else f"MISSING {sorted(missing)}")
    bad += bool(missing)
    for z in reg["zones"].values():
        for n in have:
            if ip.ip_network(n).overlaps(ip.ip_network(z["cidr"])):
                print(f"[GOVERNANCE] WARNING: blackhole {n} overlaps allowed zone {z['cidr']}"); bad += 1
    print("[GOVERNANCE] audit", "FAILED" if bad else "OK")
    return 1 if bad else 0

def selftest():
    from enforce_ip_policy import load_pdp, decide, NODES
    pdp = load_pdp(); n1, n2, n3, n4 = (NODES[k] for k in ("node001", "node002", "node003", "node004"))
    cases = [(n1, n2, "raft_message", True), (n2, n3, "request_vote", True), (n3, n1, "append_entries", True),
             (n4, n1, "raft_message", True), (n1, "10.166.0.71", "cert_request", True),
             (n1, "10.166.0.254", "raft_message", False), (n1, "10.100.0.100", "raft_message", False),
             ("10.100.0.100", n1, "raft_message", False), (n1, "10.166.0.200", "raft_message", False),
             ("10.166.0.77", n1, "append_entries", False)]
    bad = 0
    for s, d, a, exp in cases:
        got = decide(pdp, s, d, a, 12); bad += got != exp
        print("PASS" if got == exp else "FAIL", s, "->", d, a, "allowed:", got)
    print(f"{len(cases) - bad}/{len(cases)} passed"); return 1 if bad else 0

if __name__ == "__main__":
    c = sys.argv[1] if len(sys.argv) > 1 else "ranges"
    sys.exit({"audit": audit, "selftest": selftest}.get(c, lambda: print("\n".join(range_blocks())) or 0)())
