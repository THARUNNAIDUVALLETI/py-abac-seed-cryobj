#!/usr/bin/env python3
"""Run INSIDE node004 to turn it malicious.  usage: attack_node4.py <identity|flood|probe|all|stop|status>
  identity : connect to the cluster as an unregistered (read-only) node  -> invalid identity
  flood    : node004 starts flooding the cluster with Raft commands       -> message flood
  probe    : try the decoy admin port on node1/node3 and the IX range     -> unauthorised access
All modes first mark the node as compromised (it stops policing itself)."""
import os, socket, subprocess, sys, time
sys.path.insert(0, "/app")
PEERS = ["10.166.0.72", "10.166.0.73", "10.166.0.74"]

def compromise():
    open("/app/compromised", "w").write("1")
    print("[ATTACK] node004 is now compromised (own enforcer and guard off)")
    time.sleep(4)          # let the enforcer drop node004's own blackhole routes

def tcp(ip, port, label):
    s = socket.socket(); s.settimeout(2)
    try:
        s.connect((ip, port)); print(f"[ATTACK] {label} {ip}:{port} -> CONNECTED")
    except Exception as e:
        print(f"[ATTACK] {label} {ip}:{port} -> failed ({e})")
    finally:
        s.close()

def internet():
    subprocess.run(["ip", "route", "replace", "default", "via", "10.166.0.254"])
    for _ in range(5):
        tcp("10.100.0.100", 80, "access internet")
        subprocess.run(["ping", "-c", "1", "-W", "1", "10.100.0.100"], capture_output=True)
        time.sleep(1)

def probe():
    subprocess.run(["ip", "route", "replace", "default", "via", "10.166.0.254"])
    for rnd in range(3):
        for ip in ("10.166.0.72", "10.166.0.74"):
            tcp(ip, 9999, "access node")
        tcp("10.100.0.100", 80, "access internet")
        subprocess.run(["ping", "-c", "1", "-W", "1", "10.100.0.100"], capture_output=True)
        time.sleep(1)

def identity():
    from pysyncobj import SyncObj, SyncObjConf
    conf = SyncObjConf(password="SecureRaft2026", connectionTimeout=5.0)
    rogue = SyncObj(None, [p + ":45025" for p in PEERS], conf)      # read-only, unregistered identity
    print("[ATTACK] rogue read-only member connecting for 30 s ...")
    for _ in range(30):
        try:
            rogue.getStatus()
        except Exception:
            pass
        time.sleep(1)

def status():
    for f in ("/app/compromised", "/app/attack_mode"):
        print(f, "exists" if os.path.exists(f) else "absent")
    print(subprocess.run(["ip", "route", "show", "type", "blackhole"], capture_output=True, text=True).stdout or "no blackhole routes")

def stop():
    for f in ("/app/compromised", "/app/attack_mode"):
        try: os.remove(f)
        except OSError: pass
    subprocess.run(["ip", "route", "del", "default"], capture_output=True)
    print("[ATTACK] stopped; node004 behaves normally again")

if __name__ == "__main__":
    m = sys.argv[1] if len(sys.argv) > 1 else "all"
    if m == "stop": stop()
    elif m == "status": status()
    else:
        compromise()
        if m in ("flood", "all"):
            open("/app/attack_mode", "w").write("flood"); print("[ATTACK] flooding the cluster with Raft commands")
        if m in ("identity", "all"):
            import threading; threading.Thread(target=identity, daemon=True).start()
        if m in ("probe", "all"): probe()
        if m == "internet": internet()
        if m in ("identity", "all"): time.sleep(32)
