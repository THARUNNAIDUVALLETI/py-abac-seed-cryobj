# Experiments (fault injection on the 3-node Raft cluster)
- data/    7 clean runs (leader_1..3, leader_run, follower_1..3): .csv samples + .events markers.
           leader_2.csv is trimmed to the run window; leader_2.csv.full is the original.
- scripts/ scenario.sh (run one experiment), analyze.py (metrics table), test_*.sh (policy tests),
           test_guard_live.sh (E/H quarantine test), pf.py (preflight check used by it)
- logs/    outputs of the policy and guard live tests
