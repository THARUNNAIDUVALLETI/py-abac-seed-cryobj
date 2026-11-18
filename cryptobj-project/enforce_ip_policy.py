#!/usr/bin/env python3
"""ABAC -> kernel enforcement (three policies: IP range, time window, malicious node)."""
import datetime, ipaddress, json, os, socket, subprocess, sys, threading, time
from py_abac import PDP, Policy, AccessRequest
from py_abac.storage.memory import MemoryStorage
import zt_common as zt

POLICY_FILE = os.environ.get("ABAC_FILE", "/app/abac_policies.json")
LOG_FILE = "/app/nohup.out"
HOUR_OVERRIDE = "/app/hour_override"
COMPROMISED = "/app/compromised"       # marker: this node has turned malicious and stops policing itself

NODES = zt.NODES
ALIASES = {"node1": "node001", "node2": "node002", "node3": "node003", "node4": "node004"}
EXTERNAL = {"10.100.0.0/24": "10.100.0.100"}
ACTIONS = ["raft_message", "request_vote", "append_entries", "cert_request"]
SELF_IP = None


def log(msg, tag="POLICY"):
    line = f"[{tag}] {msg}"
    print(line, flush=True)
    try:
        with open(LOG_FILE, "a") as f:
            f.write(line + "\n")
    except OSError:
        pass

def current_hour():
    try:
        return int(open(HOUR_OVERRIDE).read().strip())
    except (OSError, ValueError):
        return datetime.datetime.now().hour

def load_pdp(path=POLICY_FILE):
    if not os.path.exists(path):
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "abac_policies.json")
    storage = MemoryStorage()
    for p in json.load(open(path)):
        storage.add(Policy.from_json(p))
    return PDP(storage)

def zone_of(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return "outside"
    for name, net in (("cluster", "10.166.0.72/30"), ("services", "10.166.0.64/29"),
                      ("gateway", "10.166.0.254/32"), ("external", "10.100.0.0/24"),
                      ("unassigned", "10.166.0.0/24")):
        if a in ipaddress.ip_network(net):
            return name
    return "outside"

def trust_of(ip):
    return "trusted" if ip in zt.CORE_IPS else "untrusted"

def decide(pdp, src_ip, dst_ip, action, hour=None, strikes=0):
    ids = {ip: n for n, ip in NODES.items()}
    req = AccessRequest(
        subject={"id": ids.get(src_ip, "unknown"),
                 "attributes": {"node_id": ids.get(src_ip, "unknown"), "ip": src_ip,
                                "zone": zone_of(src_ip), "trust": trust_of(src_ip)}},
        resource={"id": ids.get(dst_ip, "unknown"),
                  "attributes": {"target_node": ids.get(dst_ip, "unknown"), "ip": dst_ip, "zone": zone_of(dst_ip)}},
        action={"id": action, "attributes": {"type": action}},
        context={"hour": current_hour() if hour is None else hour, "strikes": strikes})
    return pdp.is_allowed(req)


# ---------- detection reporting (used by the guard, the honeypot and notices) ----------
def report(ip, reason):
    """Quarantine ip locally, then tell every other core node and the router."""
    if ip in zt.PROTECTED or ip == SELF_IP:
        return False
    new = zt.add_quarantine(ip)
    if new:
        log(f"{ip} ISOLATED reason={reason}", tag="MALICIOUS")
        targets = [x for x in list(zt.CORE_IPS) + [zt.ROUTER_IP] if x not in (ip, SELF_IP)]
        threading.Thread(target=zt.send_notice, args=(ip, reason, targets), daemon=True).start()
    return new


# ---------- enforcement ----------
def desired_blocks(pdp, self_id, quarantined=None, hour=None):
    """Returns (networks to blackhole, peer ips to drop in both directions)."""
    me = NODES[self_id]
    hour = current_hour() if hour is None else hour
    quarantined = zt.quarantined() if quarantined is None else quarantined
    nets, drop = set(), set()
    for net, probe in EXTERNAL.items():
        if not any(decide(pdp, me, probe, a, hour) for a in ACTIONS):
            nets.add(net)
    for n, ip in NODES.items():
        if ip == me:
            continue
        strikes = 99 if ip in quarantined else 0
        out_ok = any(decide(pdp, me, ip, a, hour) for a in ACTIONS)
        in_ok = any(decide(pdp, ip, me, a, hour, strikes) for a in ACTIONS)
        if not (out_ok and in_ok):
            drop.add(ip)
    drop |= {q for q in quarantined if q != me}
    try:
        from ip_governance import range_blocks
        nets |= set(range_blocks())
    except Exception as e:
        log(f"governance unavailable: {e}")
    nets |= {ip + "/32" for ip in drop}
    return {str(ipaddress.ip_network(x)) for x in nets}, drop

def sh(cmd):
    return subprocess.run(cmd, capture_output=True, text=True)

def current_blackholes():
    have = set()
    for line in sh(["ip", "route", "show", "type", "blackhole"]).stdout.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0] == "blackhole":
            have.add(str(ipaddress.ip_network(parts[1], strict=False)))
    return have

def reconcile(pdp, self_id):
    if os.path.exists(COMPROMISED):
        want, drop = set(), set()          # a compromised node does not police itself
    else:
        want, drop = desired_blocks(pdp, self_id)
    have = current_blackholes()
    for net in sorted(want - have):
        r = sh(["ip", "route", "replace", "blackhole", net])
        log(f"{self_id} BLOCK {net} rc={r.returncode}")
    for net in sorted(have - want):
        sh(["ip", "route", "del", "blackhole", net])
        log(f"{self_id} ALLOW {net}")
    zt.ipt_sync(drop)

def _forever(fn):
    """Run fn forever; if it raises, log and start it again."""
    def run():
        while True:
            try:
                fn()
            except Exception as e:
                log(f"{fn.__name__} crashed: {e!r}; restarting", tag="ERROR")
                time.sleep(1)
    return run

def notice_listener():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", zt.NOTICE_PORT))
    allowed = zt.CORE_IPS | {zt.ROUTER_IP}
    while True:
        raw, addr = s.recvfrom(4096)
        try:
            if addr[0] not in allowed or addr[0] == SELF_IP:
                continue
            m = zt.verify_notice(raw)
            if m and m["ip"] not in zt.PROTECTED and m["ip"] != SELF_IP and zt.add_quarantine(m["ip"]):
                log(f"{m['ip']} ISOLATED (notice from {addr[0]}: {m.get('reason')})", tag="MALICIOUS")
        except Exception as e:
            log(f"bad notice from {addr[0]}: {e!r}", tag="ERROR")

def honeypot():
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", zt.HONEYPOT_PORT))
    s.listen(16)
    while True:
        c, a = s.accept()
        c.close()
        try:
            if a[0] != SELF_IP and a[0] not in zt.CORE_IPS:
                log(f"unauthorised access attempt to {SELF_IP}:{zt.HONEYPOT_PORT} from {a[0]}", tag="MALICIOUS")
                report(a[0], "unauthorised-access")
        except Exception as e:
            log(f"honeypot error: {e!r}", tag="ERROR")

def start_enforcer(node_name, policy="0", interval=2):
    global SELF_IP
    self_id = ALIASES.get(node_name, node_name)
    SELF_IP = NODES[self_id]
    pdp = load_pdp()
    if self_id in zt.CORE:
        threading.Thread(target=_forever(notice_listener), daemon=True).start()
        threading.Thread(target=_forever(honeypot), daemon=True).start()
    def loop():
        while True:
            try:
                reconcile(pdp, self_id)
            except Exception as e:
                log(f"enforcer error: {e}")
            time.sleep(interval)
    threading.Thread(target=loop, daemon=True).start()
    log(f"{self_id} enforcer started ({SELF_IP}, {zt.ipt_bin() or 'no iptables'})")
    return pdp


def selftest():
    pdp = load_pdp()
    n1, n2, n3, n4 = NODES["node001"], NODES["node002"], NODES["node003"], NODES["node004"]
    ca, ext = "10.166.0.71", "10.100.0.100"
    cases = [  # src, dst, action, hour, strikes, expected
        (n1, n2, "raft_message", 12, 0, True), (n2, n3, "request_vote", 12, 0, True),
        (n3, n1, "append_entries", 3, 0, True),                       # trusted: any hour
        (n1, n4, "raft_message", 12, 0, True),
        (n4, n1, "raft_message", 12, 0, True),                        # untrusted inside window
        (n4, n1, "raft_message", 8, 0, True), (n4, n1, "raft_message", 16, 0, True),
        (n4, n1, "raft_message", 7, 0, False), (n4, n1, "raft_message", 17, 0, False),
        (n4, n3, "append_entries", 3, 0, False),                      # untrusted outside window
        ("10.166.0.77", n1, "append_entries", 12, 0, False),          # unregistered, outside cluster zone
        (n1, ext, "raft_message", 12, 0, False), (ext, n1, "raft_message", 12, 0, False),
        (n1, "10.166.0.200", "raft_message", 12, 0, False),
        (n1, ca, "cert_request", 12, 0, True),
        (n1, n2, "admin_access", 12, 0, False),
        (n2, n1, "raft_message", 12, 2, True), (n2, n1, "raft_message", 12, 3, False),
        (n4, n1, "raft_message", 12, 3, False),
    ]
    bad = 0
    for s, d, a, h, k, exp in cases:
        got = decide(pdp, s, d, a, h, k)
        bad += got != exp
        print("PASS" if got == exp else "FAIL", f"{s} -> {d} {a} hour={h} strikes={k} allowed={got}")
    # what a core node would block
    for hr, q, expect in ((12, set(), False), (3, set(), True), (12, {n4}, True)):
        nets, drop = desired_blocks(pdp, "node001", q, hr)
        got = (n4 in drop)
        bad += got != expect
        print("PASS" if got == expect else "FAIL", f"node001 hour={hr} quarantined={sorted(q)} drops node004: {got}")
    nets, drop = desired_blocks(pdp, "node001", set(), 12)
    ok = "10.100.0.0/24" in nets and not ({n2, n3} & drop)
    bad += not ok
    print("PASS" if ok else "FAIL", "node001 blocks the external range and keeps node002/node003")
    total = len(cases) + 4
    print(f"{total - bad}/{total} passed")
    return 1 if bad else 0


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "selftest"
    if cmd == "selftest":
        sys.exit(selftest())
    elif cmd == "status":
        print("quarantined:", sorted(zt.quarantined()) or "none")
        print("blackholes :", sorted(current_blackholes()))
        print("iptables   :", sorted(zt.ipt_drop_set()) if zt.ipt_bin() else "not installed")
    elif cmd == "release":
        zt.release(sys.argv[2])
        print("released", sys.argv[2])
    elif cmd == "report":
        SELF_IP = sys.argv[3] if len(sys.argv) > 3 else None
        print(report(sys.argv[2], "manual"))
        time.sleep(1)
