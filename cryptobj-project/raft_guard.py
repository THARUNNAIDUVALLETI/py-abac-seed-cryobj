"""raft_guard.py - runtime enforcement of the three policies on live Raft messages.
Hooks pysyncobj's transport callback. Modes (file /app/guard_mode): off | monitor | enforce (default).
Detection signals feed a strike score; policy 3 denies a sender at 3 strikes and the sender is isolated.
  invalid identity (unregistered id, or missing/expired/invalid certificate)  +3
  message flood (more than the flood limit per 10 s)                           +1 per message
Fail-open: any internal error lets the message through."""
import os, sys, time, datetime, collections, ipaddress
from py_abac import AccessRequest
import enforce_ip_policy as E

MODE_FILE = "/app/guard_mode"
FLOOD_FILE = "/app/flood_limit"
FLOOD_DEFAULT = 3000          # messages per 10 s from one sender
THRESHOLD = 3
STRIKE_WINDOW = 60
RATE_WINDOW = 10
GRACE_SECS = 90               # a certificate that is not fetched yet is not held against a node at start-up
CERT_DIR = "/app"
ACTION_MAP = {"append_entries": "append_entries", "request_vote": "request_vote"}
INV_ALIASES = {v: k for k, v in E.ALIASES.items()}
IP_TO_NODE = {ip: n for n, ip in E.NODES.items()}


class RaftGuard:
    def __init__(self, obj, leader_state, node_name, pdp=None, clock=time.time):
        self.obj, self.leader_state, self.clock = obj, leader_state, clock
        self.self_name = E.ALIASES.get(node_name, node_name)
        self.self_ip = E.NODES[self.self_name]
        E.SELF_IP = self.self_ip
        self.pdp = pdp or E.load_pdp()
        self.rate = collections.defaultdict(collections.deque)
        self.strikes = collections.defaultdict(collections.deque)    # ip -> deque[(time, weight)]
        self.stats = collections.defaultdict(lambda: {"msgs": 0, "max_rate": 0, "would_drop": 0, "dropped": 0})
        self._mode = ("enforce", 0.0)
        self._certs = {}
        self._lastlog = {}
        self._laststat = clock()
        self._flood = (FLOOD_DEFAULT, 0.0)
        self.t0 = clock()

    def mode(self):
        if os.path.exists(E.COMPROMISED):
            return "off"
        now = self.clock()
        if now - self._mode[1] > 2:
            try:
                m = open(MODE_FILE).read().strip() or "enforce"
            except OSError:
                m = "enforce"
            self._mode = (m if m in ("off", "monitor", "enforce") else "enforce", now)
        return self._mode[0]

    def flood_limit(self):
        now = self.clock()
        if now - self._flood[1] > 5:
            try:
                v = int(open(FLOOD_FILE).read().strip())
            except (OSError, ValueError):
                v = FLOOD_DEFAULT
            self._flood = (v, now)
        return self._flood[0]

    def cert_status(self, name):
        now = self.clock()
        c = self._certs.get(name)
        if c and now - c[1] < (10 if c[0] == "missing" else 60):
            return c[0]
        path = os.path.join(CERT_DIR, INV_ALIASES.get(name, name) + "_certificate.pem")
        try:
            from cryptography import x509
            cert = x509.load_pem_x509_certificate(open(path, "rb").read())
            t = datetime.datetime.now(datetime.timezone.utc)
            st = "valid" if cert.not_valid_before_utc <= t <= cert.not_valid_after_utc else "expired"
        except FileNotFoundError:
            st = "missing"
        except Exception:
            st = "invalid"
        self._certs[name] = (st, now)
        return st

    def evaluate(self, sip, message):
        """Returns (allow, strikes, reason, message type)."""
        now = self.clock()
        d = message if isinstance(message, dict) else {}
        mtype = d.get("type", "unknown")
        action = ACTION_MAP.get(mtype, "raft_message")
        name = IP_TO_NODE.get(sip)
        dq = self.rate[sip]; dq.append(now)
        while dq and now - dq[0] > RATE_WINDOW: dq.popleft()
        sq = self.strikes[sip]
        while sq and now - sq[0][0] > STRIKE_WINDOW: sq.popleft()
        signals = []
        if name is None:
            signals.append(("invalid-identity:unregistered", 3))
        else:
            cs = self.cert_status(name)
            if cs != "valid" and not (cs == "missing" and now - self.t0 < GRACE_SECS):
                signals.append((f"invalid-identity:cert={cs}", 3))
        if len(dq) > self.flood_limit():
            signals.append(("message-flood", 1))
        for _, w in signals:
            sq.append((now, w))
        strikes = min(99, sum(w for _, w in sq))
        allow = E.decide(self.pdp, sip, self.self_ip, action, E.current_hour(), strikes)
        if allow:
            reason = ""
        elif strikes >= THRESHOLD:
            reason = "malicious-node(" + ",".join(s for s, _ in signals or [("repeat-offender", 0)]) + f",strikes={strikes})"
        elif E.trust_of(sip) == "untrusted":
            reason = "time-window"
        else:
            reason = "ip-range"
        return allow, strikes, reason, mtype

    def _log_violation(self, m, mtype, sip, strikes, reason):
        now = self.clock()
        key = (sip, reason.split("(")[0])
        if now - self._lastlog.get(key, 0) < 2:
            return
        self._lastlog[key] = now
        verb = "DROP" if m == "enforce" else "would DROP"
        E.log(f"{self.self_name} {verb} {mtype} from {IP_TO_NODE.get(sip, sip)} [{reason}] strikes={strikes}", tag="GUARD")

    def _isolate(self, m, sip, reason):
        if m != "enforce":
            E.log(f"{self.self_name} would ISOLATE {sip} [{reason}]", tag="GUARD")
            return
        try:
            ipaddress.ip_address(sip)
        except ValueError:
            E.log(f"{self.self_name} cannot isolate non-IP identity {sip!r} [{reason}]", tag="GUARD")
            return
        E.report(sip, reason)

    def _maybe_stats(self):
        now = self.clock()
        if now - self._laststat < 30:
            return
        self._laststat = now
        for ip, st in self.stats.items():
            E.log(f"{self.self_name} guard[{self.mode()}] from {IP_TO_NODE.get(ip, ip)}: msgs={st['msgs']} "
                  f"peak_rate={st['max_rate']}/10s would_drop={st['would_drop']} dropped={st['dropped']}", tag="GUARD")

    def check(self, node, message):
        m = self.mode()
        if m == "off":
            return True
        sip = str(getattr(node, "id", node)).split(":")[0]
        allow, strikes, reason, mtype = self.evaluate(sip, message)
        st = self.stats[sip]
        st["msgs"] += 1
        st["max_rate"] = max(st["max_rate"], len(self.rate[sip]))
        if not allow:
            st["dropped" if m == "enforce" else "would_drop"] += 1
            self._log_violation(m, mtype, sip, strikes, reason)
            if strikes >= THRESHOLD:
                self._isolate(m, sip, reason)
        self._maybe_stats()
        return allow or m != "enforce"


def install_guard(obj, leader_state, node_name):
    g = RaftGuard(obj, leader_state, node_name)
    tr = obj._SyncObj__transport
    orig = tr._onMessageReceivedCallback

    def wrapped(node, message):
        try:
            ok = g.check(node, message)
        except Exception as e:           # fail-open
            E.log(f"guard error (message passed through): {e!r}", tag="GUARD")
            ok = True
        if ok:
            return orig(node, message)

    tr.setOnMessageReceivedCallback(wrapped)
    E.log(f"{g.self_name} guard installed (mode file {MODE_FILE}, default enforce)", tag="GUARD")
    return g


def selftest():
    import enforce_ip_policy
    pdp = E.load_pdp()
    class Fake: pass
    hour = [12]
    E.current_hour = lambda: hour[0]
    def mk():
        o = Fake(); o._SyncObj__raftCurrentTerm = 5; o._SyncObj__raftState = "follower"
        t = [1000.0]
        g = RaftGuard(o, "leader", "node1", pdp=pdp, clock=lambda: t[0])
        g.cert_status = lambda n: "valid"
        return g, t
    N2, N4, X = "10.166.0.73", "10.166.0.75", "10.166.0.50"
    res = []
    def case(label, expect, g, ip, msg=None):
        allow, strikes, reason, _ = g.evaluate(ip, msg or {"type": "append_entries", "term": 5})
        ok = allow == expect; res.append(ok)
        print("PASS" if ok else "FAIL", "-", label, "->", "allow" if allow else "deny " + reason)
    hour[0] = 12
    g, t = mk(); case("core node, normal message", True, g, N2)
    g, t = mk(); case("node004 inside the time window", True, g, N4)
    hour[0] = 20
    g, t = mk(); case("node004 outside the time window", False, g, N4)
    g, t = mk(); case("core node outside the window (trusted)", True, g, N2)
    hour[0] = 12
    g, t = mk(); case("unregistered sender (invalid identity)", False, g, X)
    g, t = mk(); g.cert_status = lambda n: "expired"; case("expired certificate", False, g, N4)
    g, t = mk(); g.cert_status = lambda n: "invalid"; case("forged/invalid certificate", False, g, N4)
    g, t = mk(); g.cert_status = lambda n: "missing"; case("missing certificate during start-up grace", True, g, N4)
    t[0] += 200; case("missing certificate after the grace period", False, g, N4)
    g, t = mk(); ok = all(g.evaluate(N4, {"type": "append_entries", "term": 5})[0] for _ in range(3000)); res.append(ok)
    print("PASS" if ok else "FAIL", "- 3000 msgs in 10 s allowed (flood limit)")
    case("message flood: 3001st message", True, g, N4)
    case("message flood: 3002nd", True, g, N4)
    case("message flood: 3003rd -> 3 strikes", False, g, N4)
    t[0] += 61; t[0] += 11; case("recovers after the strike window", True, g, N4)
    g, t = mk(); g.flood_limit = lambda: 50
    for _ in range(50): g.evaluate(N4, {"type": "request_vote", "term": 5})
    for _ in range(2): g.evaluate(N4, {"type": "request_vote", "term": 5})
    case("custom flood limit trips at strike 3", False, g, N4)
    g, t = mk(); case("control message from a core node", True, g, N2, {"type": "next_node_idx", "reset": False})
    print(f"\nRESULT {sum(res)}/{len(res)} pass")
    sys.exit(0 if all(res) else 1)


if __name__ == "__main__" and len(sys.argv) > 1 and sys.argv[1] == "selftest":
    selftest()
