#!/bin/bash
# usage: bash scenario.sh leader|follower run.csv
cd ~/Desktop/seed-emulator/examples/output
N=(as166h-node001-10.166.0.72 as166h-node002-10.166.0.73 as166h-node003-10.166.0.74)
MODE=${1:-leader}; OUT=${2:-run.csv}; EV=${OUT%.csv}.events
setp() { for i in 0 1 2; do docker exec ${N[$i]} sh -c "echo $1 > /app/policy_override"; shift; done; }
cnt() { docker logs --tail 40 $1 2>&1 | grep -o "counter: [0-9]*" | tail -1 | grep -o "[0-9]*"; }
leader() { docker logs ${N[0]} 2>&1 | grep "RAFT LEADER" | tail -1 | grep -o "10\.166\.0\.[0-9]*"; }
mark() { echo "$(date +%T.%N | cut -c1-12) $1" | tee -a $EV; }
: > $EV; echo "time,node1,node2,node3" > $OUT
setp 0 0 0; sleep 12
case $(leader) in 10.166.0.72) L=0;; 10.166.0.73) L=1;; 10.166.0.74) L=2;; esac
if [ "$MODE" = leader ]; then IDX=$L; else IDX=$(( (L+1) % 3 )); fi
A=(0 0 0); A[$IDX]=11
( while true; do echo "$(date +%T.%N | cut -c1-12),$(cnt ${N[0]}),$(cnt ${N[1]}),$(cnt ${N[2]})" >> $OUT; sleep 0.3; done ) &
SP=$!
mark "START leader_idx=$L isolating_idx=$IDX"; sleep 20
mark "ISOLATE"; setp ${A[@]}; sleep 60
mark "HEAL"; setp 0 0 0; sleep 40
kill $SP; mark "END"
for i in 0 1 2; do docker logs ${N[$i]} 2>&1 | grep "RAFT LEADER" | tail -1; done
