#!/usr/bin/env python3
"""Shared helpers: quarantine list, signed notices, iptables isolation. Stdlib only."""
import hashlib, hmac, json, os, socket, subprocess, threading, time

SECRET = b"SecureRaft2026"
QFILE = os.environ.get("ZT_QFILE", "/app/quarantine.txt")
NOTICE_PORT = 9998          # UDP: signed "quarantine this ip" notices
HONEYPOT_PORT = 9999        # TCP: decoy admin port, nobody legitimate uses it
FOREVER = 365 * 86400
ROUTER_IP = "10.166.0.254"
CA_IP = "10.166.0.71"
PROTECTED = {ROUTER_IP, CA_IP}
NODES = {"node001": "10.166.0.72", "node002": "10.166.0.73",
         "node003": "10.166.0.74", "node004": "10.166.0.75"}
CORE = ["node001", "node002", "node003"]          # trusted members
CORE_IPS = {NODES[n] for n in CORE}


# ---------- quarantine list ("ip expiry" per line) ----------
def _read():
    now, cur = time.time(), {}
    try:
        with open(QFILE) as f:
            for line in f:
                p = line.split()
                if len(p) >= 2 and float(p[1]) > now:
                    cur[p[0]] = float(p[1])
    except (OSError, ValueError):
        pass
    return cur

_LOCK = threading.RLock()

def _write(cur):
    with _LOCK:
        tmp = f"{QFILE}.{os.getpid()}.{threading.get_ident()}.tmp"
        with open(tmp, "w") as f:
            for ip, exp in cur.items():
                f.write(f"{ip} {exp}\n")
        os.replace(tmp, QFILE)

def quarantined():
    return set(_read())

def add_quarantine(ip, secs=FOREVER):
    with _LOCK:
        cur = _read()
        if ip in cur:
            return False
        cur[ip] = time.time() + secs
        _write(cur)
        return True

def release(ip):
    with _LOCK:
        cur = _read()
        cur.pop(ip, None)
        _write(cur)


# ---------- signed notices ----------
def _sign(ip, ts):
    return hmac.new(SECRET, f"{ip}|{ts}".encode(), hashlib.sha256).hexdigest()

def send_notice(ip, reason, targets, repeat=3):
    ts = int(time.time())
    msg = json.dumps({"ip": ip, "reason": reason, "ts": ts, "sig": _sign(ip, ts)}).encode()
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    for _ in range(repeat):
        for t in targets:
            try:
                s.sendto(msg, (t, NOTICE_PORT))
            except OSError:
                pass
        time.sleep(0.2)
    s.close()

def verify_notice(raw):
    try:
        m = json.loads(raw)
        if abs(time.time() - m["ts"]) < 120 and hmac.compare_digest(m["sig"], _sign(m["ip"], m["ts"])):
            return m
    except Exception:
        pass
    return None


# ---------- iptables (two-way isolation, in a dedicated chain) ----------
_BIN = [None]

def ipt_bin():
    if _BIN[0] is None:
        _BIN[0] = ""
        for b in ("iptables", "iptables-legacy"):
            try:
                if subprocess.run([b, "-S"], capture_output=True, text=True).returncode == 0:
                    _BIN[0] = b
                    break
            except FileNotFoundError:
                pass
    return _BIN[0] or None

def ipt(*a):
    b = ipt_bin()
    return subprocess.run([b, *a], capture_output=True, text=True) if b else None

_HOOKED = set()

def ipt_setup(chain="ZT", hooks=("INPUT", "OUTPUT", "FORWARD")):
    if not ipt_bin():
        return False
    if chain in _HOOKED:
        return True
    ipt("-N", chain)
    for h in hooks:
        if ipt("-C", h, "-j", chain).returncode != 0:
            ipt("-I", h, "-j", chain)
    _HOOKED.add(chain)
    return True

def ipt_drop_set(chain="ZT"):
    have, r = set(), ipt("-S", chain)
    if r:
        for l in r.stdout.splitlines():
            p = l.split()
            if p[:2] == ["-A", chain] and "-s" in p:
                have.add(p[p.index("-s") + 1].split("/")[0])
    return have

def ipt_sync(want, chain="ZT"):
    """Make the chain drop traffic from AND to exactly the ips in want."""
    if not ipt_setup(chain):
        return False
    have = ipt_drop_set(chain)
    for ip in want - have:
        ipt("-A", chain, "-s", ip, "-j", "DROP")
        ipt("-A", chain, "-d", ip, "-j", "DROP")
    for ip in have - want:
        ipt("-D", chain, "-s", ip, "-j", "DROP")
        ipt("-D", chain, "-d", ip, "-j", "DROP")
    return True
