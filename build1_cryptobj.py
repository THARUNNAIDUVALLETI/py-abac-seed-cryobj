#!/usr/bin/env python3
"""AS166 Raft cluster: node001-003 (trusted) + node004 (untrusted member that turns malicious).
Three policies: IP range, time window, malicious-node detection."""
from seedemu import *
import os

PROJECT_DIR = "/home/kali/Desktop/seed-emulator/examples/cryptobj-project"
ASYM_CIPHER, KEY_SIZE, SYM_CIPHER = "RSA", "2048", "AES"


def build_network():
    emu = Emulator()
    base, routing, ebgp, ibgp, ospf = Base(), Routing(), Ebgp(), Ibgp(), Ospf()

    ix = base.createInternetExchange(100)
    ix.getPeeringLan().setDisplayName('CryptObj-Network')
    as166 = base.createAutonomousSystem(166)

    ca_node = as166.createHost('ca_node')
    node1 = as166.createHost('node001')
    node2 = as166.createHost('node002')
    node3 = as166.createHost('node003')
    node4 = as166.createHost('node004')

    router = as166.createRouter('router0')
    router.joinNetwork('ix100')
    as166.createNetwork('net0')
    router.joinNetwork('net0')

    ca_node.joinNetwork('net0')
    node1.joinNetwork('net0')
    node2.joinNetwork('net0')
    node3.joinNetwork('net0')
    node4.joinNetwork('net0', address='10.166.0.75')

    for layer in (base, routing, ebgp, ibgp, ospf):
        emu.addLayer(layer)

    nodes = [("ca_node", ca_node), ("node1", node1), ("node2", node2), ("node3", node3), ("node4", node4)]
    for name, node in nodes:
        print(f"configuring {name}")
        for file in os.listdir(PROJECT_DIR):
            fp = os.path.join(PROJECT_DIR, file)
            if os.path.isfile(fp) and file.endswith(('.py', '.json', '.txt')):
                node.importFile(fp, f"/app/{file}")
        node.addBuildCommand("apt update && apt install -y python3-pip iptables")
        node.addBuildCommand(
            "pip install --break-system-packages pysyncobj colorama cryptography requests pycryptodome pandas flask gunicorn py-abac")

    ca_node.appendStartCommand("cd /app && sleep 5 && python3 ca_server.py &")
    for name, node in nodes[1:]:
        node.appendStartCommand(
            f"cd /app && sleep 15 && python3 cryptobj.py {name} {ASYM_CIPHER} {KEY_SIZE} {SYM_CIPHER}")

    # router: enforces the isolation at the network edge
    for f in ("router_guard.py", "zt_common.py"):
        router.importFile(os.path.join(PROJECT_DIR, f), f"/app/{f}")
    router.addBuildCommand("apt update && apt install -y python3 iptables")
    router.appendStartCommand("cd /app && python3 router_guard.py >> /app/router_guard.log 2>&1", fork=True)

    emu.render()
    emu.compile(Docker(), './output', override=True)
    print("network built. run: cd output && sudo docker compose up -d --build")


if __name__ == "__main__":
    build_network()
