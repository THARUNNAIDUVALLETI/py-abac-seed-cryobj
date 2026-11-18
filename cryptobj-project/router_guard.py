#!/usr/bin/env python3
"""Runs on the AS166 router. Enforces the isolation at the network edge:
 - counts packets from cluster nodes towards the IX/internet range (should never happen)
   -> that source is reported as malicious
 - accepts signed quarantine notices from the core nodes
 - drops everything from/to a quarantined ip (to the router itself and through it)"""
import os, socket, subprocess, sys, threading, time
import zt_common as zt

LOG = "/app/router_guard.log"
EXTERNAL = "10.100.0.0/24"
WATCH = sorted(zt.NODES.values())

def log(msg):
    line = f"[ROUTER-GUARD] {time.strftime('%H:%M:%S')} {msg}"
    print(line, flush=True)          # start command already redirects stdout to the log file

def quarantine(ip, why):
    if ip in zt.PROTECTED:
        return
    if zt.add_quarantine(ip):
        log(f"{ip} ISOLATED from the network ({why})")
        targets = [x for x in zt.CORE_IPS if x != ip]
        threading.Thread(target=zt.send_notice, args=(ip, why, targets), daemon=True).start()

def listener():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", zt.NOTICE_PORT))
    while True:
        raw, addr = s.recvfrom(4096)
        if addr[0] not in zt.CORE_IPS:
            continue
        m = zt.verify_notice(raw)
        if m and m["ip"] not in zt.PROTECTED and zt.add_quarantine(m["ip"]):
            log(f"{m['ip']} ISOLATED (notice from {addr[0]}: {m.get('reason')})")

def setup_probe_chain():
    zt.ipt_setup("ZT")
    zt.ipt("-N", "ZTEXT")
    if zt.ipt("-C", "FORWARD", "-j", "ZTEXT").returncode != 0:
        zt.ipt("-A", "FORWARD", "-j", "ZTEXT")
    have = zt.ipt("-S", "ZTEXT").stdout
    for ip in WATCH:
        if f"-s {ip}/32 -d {EXTERNAL}" not in have:
            zt.ipt("-A", "ZTEXT", "-s", ip, "-d", EXTERNAL, "-j", "DROP")

def probe_counters():
    out = zt.ipt("-L", "ZTEXT", "-n", "-v", "-x").stdout.splitlines()
    res = {}
    for l in out[2:]:
        p = l.split()
        if len(p) >= 8 and p[2] == "DROP":
            res[p[7]] = int(p[0])
    return res

def main():
    if not zt.ipt_bin():
        log("iptables not available: cannot enforce")
        while True: time.sleep(3600)
    setup_probe_chain()
    def _forever():
        while True:
            try:
                listener()
            except Exception as e:
                log(f"listener crashed: {e!r}; restarting")
                time.sleep(1)
    threading.Thread(target=_forever, daemon=True).start()
    log("router guard running: watching cluster nodes for traffic towards " + EXTERNAL)
    last = {}
    while True:
        try:
            for ip, pk in probe_counters().items():
                if pk > last.get(ip, 0):
                    log(f"{ip} tried to reach {EXTERNAL} ({pk} packets dropped)")
                    quarantine(ip, "internet-access-attempt")
                last[ip] = pk
            zt.ipt_sync(zt.quarantined())
        except Exception as e:
            log(f"error: {e}")
        time.sleep(1)

if __name__ == "__main__":
    if len(sys.argv) > 2 and sys.argv[1] == "release":
        zt.release(sys.argv[2]); print("released", sys.argv[2])
    elif len(sys.argv) > 1 and sys.argv[1] == "status":
        print("quarantined:", sorted(zt.quarantined()) or "none")
        print("iptables ZT:", sorted(zt.ipt_drop_set()))
        print("probe counters:", probe_counters())
    else:
        main()
