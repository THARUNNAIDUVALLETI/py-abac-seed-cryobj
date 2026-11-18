import sys, signal, time, json, threading, subprocess, os, datetime
from colorama import Fore, Style
from pysyncobj import SyncObj, replicated, SyncObjConf, FAIL_REASON, _RAFT_STATE
from pki_setup import PKI
from request import get_ca_status, submit_csr_to_ca, fetch_all_certificates
from encryptor import AsymmetricEncryptor
from digital_signature import DigitalSignature
from latency_monitor import LatencyMonitor
from py_abac import PDP, Policy, AccessRequest
from py_abac.storage.memory import MemoryStorage

# ─────────────────────────────────────────────────────────────────────
# Py-ABAC PDP Setup
# ─────────────────────────────────────────────────────────────────────
def setup_abac():
    storage = MemoryStorage()
    with open('abac_policies.json', 'r') as f:
        policies_json = json.load(f)
    for p_json in policies_json:
        policy = Policy.from_json(p_json)
        storage.add(policy)
    return PDP(storage)

# ─────────────────────────────────────────────────────────────────────
# Network Policy Fallback (for IP-based blocking)
# ─────────────────────────────────────────────────────────────────────
# ─────────────────────────────────────────────────────────────────────
# Main Raft Node Logic
# ─────────────────────────────────────────────────────────────────────
if __name__ == '__main__':
    NO_CRYPTO = '--no-crypto' in sys.argv
    if NO_CRYPTO: sys.argv.remove('--no-crypto')

    NETWORK_POLICY = None
    if '--policy' in sys.argv:
        idx = sys.argv.index('--policy')
        NETWORK_POLICY = sys.argv[idx + 1]
        del sys.argv[idx:idx + 2]

    BOOTSTRAP_ITERATIONS = None
    if '--bootstrap' in sys.argv:
        idx = sys.argv.index('--bootstrap')
        BOOTSTRAP_ITERATIONS = int(sys.argv[idx + 1])
        del sys.argv[idx:idx + 2]

    RUN_DURATION_SECONDS = None
    if '--duration' in sys.argv:
        idx = sys.argv.index('--duration')
        RUN_DURATION_SECONDS = float(sys.argv[idx + 1])
        del sys.argv[idx:idx + 2]

    with open('scale_nodes.json', 'r') as f: nodes = json.load(f)
    with open('asymmetric_ciphers.json', 'r') as f: config = json.load(f)
    with open('rsa_keys.json', 'r') as f: rsa_keys = json.load(f)
    with open('ecc_curves.json', 'r') as f: curves = json.load(f)
    with open('ciphers.json', 'r') as f: ciphers = json.load(f)

    if len(sys.argv) < 5:
        print(Fore.YELLOW + f'Usage: {sys.argv[0]} node_name, asymmetric_cipher, key_size/curve, symmetric_cipher')
        sys.exit(-1)

    node_name = sys.argv[1]
    os.environ['NODE_NAME'] = node_name

    # Initialize Py-ABAC
    pdp = setup_abac()
    print(Fore.GREEN + f"[ABAC] PDP initialized with {len(list(pdp._storage.get_all(100, 0)))} policies.")

    # Apply IP-based network policy if specified
    from enforce_ip_policy import start_enforcer
    start_enforcer(node_name, NETWORK_POLICY or "0")

    # CA Status Check
    status = get_ca_status()
    print(Fore.YELLOW + f'CA Status: {status}')

    election_monitor = LatencyMonitor()
    _election_start = [None]

    def onStateChanged(o, n):
        if n == _RAFT_STATE.CANDIDATE: _election_start[0] = time.perf_counter()
        elif n == _RAFT_STATE.LEADER and _election_start[0]:
            latency_ms = (time.perf_counter() - _election_start[0]) * 1000
            label = f'leader_election_{node_name}' + ('_no_crypto' if NO_CRYPTO else '')
            election_monitor._results_list.append({'measurement': len(election_monitor._results_list) + 1, 'label': label, 'latency_ms': round(latency_ms, 6)})
            print(Fore.CYAN + f"  election [{label}]: {latency_ms:.3f} ms")
            election_monitor.append_last('election_measurements')
            _election_start[0] = None
        elif n == _RAFT_STATE.FOLLOWER: _election_start[0] = None

    class Raft(SyncObj):
        def __init__(self, selfNodeAddr, otherNodeAddrs, nodes_data, node_name):
            print("\n" + "="*60 + f"\n RAFT NODE  [{node_name}]  starting up\n" + "="*60 + "\n")
            conf = SyncObjConf()
            conf.password = None if NO_CRYPTO else "SecureRaft2026"
            conf.node_name = node_name
            conf.connectionTimeout = 30.0
            conf.onStateChanged = onStateChanged
            super(Raft, self).__init__(selfNodeAddr, otherNodeAddrs, conf)
            self.__counter = 0
            self.nodes_data = nodes_data
            self._last_leader = None

        @replicated
        def addValue(self, value, cn):
            self.__counter += value
            print(f"\n  RAFT LOG ENTRY  [{node_name}]  seq={cn} | counter: {self.__counter}\n")
            return self.__counter, cn

        def _getNodeName(self):
            return os.environ.get('NODE_NAME', 'unknown')

        def _getLeader(self):
            leader = super()._getLeader()
            if leader != self._last_leader:
                if leader:
                    try: self_addr = self._selfAddress
                    except: self_addr = None
                    is_me = (self_addr is not None and leader == self_addr)
                    role_label = "THIS NODE" if is_me else f"peer (I am {self_addr or '?'})"
                    print(f"\n  RAFT LEADER  ->  {leader}  [{role_label}]\n")
                self._last_leader = leader
            return leader

    if node_name not in nodes:
        print(Fore.RED + f'Error: Node {node_name} not found in nodes.json'); sys.exit(-1)

    self_node = nodes[node_name]
    self_addr = f"{self_node['addr']}:{self_node['port']}"
    partner_addrs = [f"{info['addr']}:{info['port']}" for name, info in nodes.items() if name != node_name]

    asymmetric_cipher = sys.argv[2]
    key_param = sys.argv[3]
    selected_ciphers = sys.argv[4]

    # ... (PKI and Signing key generation logic remains the same, omitted for brevity but assumed present) ...
    # You can copy the original PKI block from your previous cryptobj.py here.
    if not os.path.exists('pki_private_key.pem'):
        print(Fore.YELLOW + 'No private key found, generating...')
        pki = PKI()
        if asymmetric_cipher == 'RSA': pki.generate_keys(int(key_param))
        else: pki.generate_ecc_keys(key_param)
        pki.generate_csr(node_name)
        submit_csr_to_ca(node_name)
        fetch_all_certificates(node_name)
        print(Fore.GREEN + 'All certificates fetched — starting Raft!')
    if not os.path.exists('signing_private_key.pem'):
        signer = DigitalSignature()
        if asymmetric_cipher == 'RSA': signer.generate_Private_Key(int(key_param))
        else: signer.generate_Private_Key(key_param)
        signer.serialize_Private_key(); signer.serialize_Public_key()

    o = Raft(self_addr, partner_addrs, nodes, node_name)
    from raft_guard import install_guard
    install_guard(o, _RAFT_STATE.LEADER, node_name)
    latency_monitor = LatencyMonitor()
    print(Fore.YELLOW + f'[{node_name}] Waiting for leader election...')
    while o._getLeader() is None: time.sleep(1)
    print(Fore.GREEN + f'[{node_name}] Leader found — waiting 10s for network to stabilise...')
    time.sleep(10)

    seq = 0
    try:
        while True:
            while o._getLeader() is None: time.sleep(0.5)
            if os.path.exists('/app/attack_mode') and open('/app/attack_mode').read().strip() == 'flood':
                for _ in range(200):
                    o.addValue(10, seq); seq += 1
                time.sleep(0.05)
                continue
            done = threading.Event(); outcome = {}
            def callback(res, err): outcome['t'] = time.perf_counter(); outcome['err'] = err; done.set()
            start = time.perf_counter(); o.addValue(10, seq, callback=callback)
            if done.wait(timeout=10) and outcome.get('err') in (None, FAIL_REASON.SUCCESS):
                latency_ms = (outcome['t'] - start) * 1000
                latency_monitor._results_list.append({'measurement': len(latency_monitor._results_list) + 1, 'label': f'raft_roundtrip_seq{seq}', 'latency_ms': round(latency_ms, 6)})
                print(f"  roundtrip [{seq}]: {latency_ms:.3f} ms")
            seq += 1
    except KeyboardInterrupt: print("Stopped.")
