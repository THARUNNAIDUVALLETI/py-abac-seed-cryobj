#!/usr/bin/env bash
# usage: bash test_three_policies.sh ip | time | attack | reset | all
dx() { local c; c=$(docker ps --format '{{.Names}}' | grep -E "$1" | head -1); shift; docker exec "$c" "$@"; }
N1=node001; N2=node002; N3=node003; N4=node004; RT=router0
cores() { for n in $N1 $N2 $N3; do "$@" $n; done; }
hdr() { echo; echo "=================== $* ==================="; }

t_ip() {
  hdr "POLICY 1: IP RANGE"
  for n in $N1 $N2 $N3; do echo "--- $n"; dx $n python3 /app/ip_governance.py audit 2>&1 | grep GOVERNANCE; done
  echo "--- node001 -> internet range (must fail)"; dx $N1 ping -c1 -W1 10.100.0.100 2>&1 | tail -2
  echo "--- node001 -> unassigned 10.166.0.200 (must fail)"; dx $N1 ping -c1 -W1 10.166.0.200 2>&1 | tail -2
  echo "--- node001 -> node002 (must work)"; dx $N1 ping -c1 -W1 10.166.0.73 2>&1 | tail -2
}
t_time() {
  hdr "POLICY 2: TIME WINDOW (node004 only inside 08:00-17:00)"
  echo "--- hour = 12 : node004 allowed"
  for n in $N1 $N2 $N3 $N4; do dx $n sh -c 'echo 12 > /app/hour_override'; done; sleep 5
  dx $N1 ping -c1 -W1 10.166.0.75 2>&1 | tail -2
  echo "--- hour = 22 : node004 must be cut off, core nodes unaffected"
  for n in $N1 $N2 $N3 $N4; do dx $n sh -c 'echo 22 > /app/hour_override'; done; sleep 6
  dx $N1 python3 /app/enforce_ip_policy.py status
  echo "ping node001 -> node004 (must fail):"; dx $N1 ping -c1 -W1 10.166.0.75 2>&1 | tail -2
  echo "ping node001 -> node002 (must work):"; dx $N1 ping -c1 -W1 10.166.0.73 2>&1 | tail -2
  echo "--- back to real time"
  for n in $N1 $N2 $N3 $N4; do dx $n rm -f /app/hour_override; done; sleep 6
  echo "ping node001 -> node004:"; dx $N1 ping -c1 -W1 10.166.0.75 2>&1 | tail -2
}
t_attack() {
  hdr "POLICY 3: MALICIOUS NODE (node004 attacks)"
  echo "--- before: node004 reaches everything"
  for ip in 10.166.0.72 10.166.0.74 10.166.0.254; do dx $N4 ping -c1 -W1 $ip 2>&1 | grep -E "bytes from|100% packet loss" | head -1; done
  echo "--- launching attack (flood + rogue identity + probing node1/node3/internet), ~40 s"
  dx $N4 python3 /app/attack_node4.py all 2>&1 | grep ATTACK
  sleep 8
  hdr "RESULT"
  for n in $N1 $N2 $N3; do echo "--- $n"; dx $n python3 /app/enforce_ip_policy.py status; dx $n grep -h MALICIOUS /app/nohup.out | tail -3; done
  echo "--- router"; dx $RT python3 /app/router_guard.py status; dx $RT tail -4 /app/router_guard.log
  echo; echo "--- node004 -> router / node1 / node3 / node2 / internet (ALL must fail)"
  for ip in 10.166.0.254 10.166.0.72 10.166.0.74 10.166.0.73 10.100.0.100; do
    printf "%-14s " $ip; dx $N4 ping -c1 -W1 $ip >/dev/null 2>&1 && echo "REACHABLE (bad)" || echo "blocked"; done
  echo "--- node004 -> honeypot port again"; dx $N4 python3 -c "import socket;s=socket.socket();s.settimeout(2);print(s.connect_ex(('10.166.0.72',9999)))"
  echo "--- cluster still alive without node004 (latest roundtrips on node001):"
  docker logs --tail 3 $(docker ps --format '{{.Names}}' | grep $N1 | head -1) 2>&1 | tail -3
}
t_reset() {
  hdr "RESET"
  for n in $N1 $N2 $N3 $N4 $RT; do dx $n sh -c 'rm -f /app/quarantine.txt /app/hour_override /app/compromised /app/attack_mode'; done
  dx $N4 python3 /app/attack_node4.py stop
  sleep 6; for n in $N1 $N2 $N3; do dx $n python3 /app/enforce_ip_policy.py status | head -1; done
}
case "${1:-all}" in ip) t_ip;; time) t_time;; attack) t_attack;; reset) t_reset;; all) t_ip; t_time; t_attack;; esac
