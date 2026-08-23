#!/usr/bin/env bash
# Phase 8 orchestrator (unprivileged). Interleaves the conditions per trial so
# any slow drift (thermal, frequency) hits both similarly and cancels in the
# delta. In-session (a) runs as a CHILD OF THE AGENT via /run -- the only way
# into cgid 11451 (moving a process in is denied by cgroup delegation). The same
# binary run directly from this shell is out-of-session (b). With leashd down it
# is the no-program floor (c).
#
#   run_bench.sh live    -> (a) in-session + (b) out-of-session, 5 trials
#   run_bench.sh floor   -> (c) no-program floor, 5 trials  (leashd MUST be down)
set -euo pipefail

MODE="${1:-live}"
LEASH="$HOME/leash"; DEMO="$HOME/leash-demo"
MICRO="$LEASH/bench/microbench"
RES="$LEASH/bench/results"
EV="$DEMO/leashd.events.jsonl"
PY="$LEASH/.venv/bin/python"
FILE_TARGET="$DEMO/docs/report_clean.txt"
CONN_TARGET="127.0.0.1:11434"
SESSION_CGID=11451
NFILE=100000; WARMF=2000
NCONN=5000;   WARMC=500
TRIALS=5

mkdir -p "$RES"
[[ -x "$MICRO" ]] || (cd "$LEASH/bench" && make >/dev/null)

allow_count() {  # KIND_ALLOW egress events at the session cgid -- the in-session witness
  "$PY" - "$EV" "$SESSION_CGID" <<'P'
import json,sys
ev,cg=sys.argv[1],int(sys.argv[2]); n=0
try:
  for l in open(ev):
    try: e=json.loads(l)
    except: continue
    if e.get("type")=="allow" and e.get("layer")=="egress" and e.get("cgid")==cg and e.get("port")==11434: n+=1
except OSError: pass
print(n)
P
}

drive_in_session() {  # $1=trial ; writes raw_*_in_run$1.csv ; returns 0 on success
  local k="$1" tries=0
  cat > "$DEMO/rbench.sh" <<EOF
#!/bin/sh
$MICRO file    $NFILE $FILE_TARGET $DEMO/isfile.csv $WARMF
$MICRO connect $NCONN $CONN_TARGET $DEMO/isconn.csv $WARMC
EOF
  while [[ $tries -lt 3 ]]; do
    tries=$((tries+1))
    rm -f "$DEMO/isfile.csv" "$DEMO/isconn.csv"
    local before; before=$(allow_count)
    curl -s "http://127.0.0.1:8000/run" -H 'Content-Type: application/json' \
      -d "{\"task\":\"Use the run_shell tool exactly once with cmd: sh $DEMO/rbench.sh  Then stop.\",\"max_steps\":6}" \
      >/dev/null || true
    sleep 0.6
    local frows=0 crows=0
    [[ -f "$DEMO/isfile.csv" ]] && frows=$(wc -l < "$DEMO/isfile.csv")
    [[ -f "$DEMO/isconn.csv" ]] && crows=$(wc -l < "$DEMO/isconn.csv")
    local after; after=$(allow_count); local emitted=$((after-before))
    if [[ "$frows" -ge "$NFILE" && "$crows" -ge "$NCONN" && "$emitted" -ge $((NCONN*9/10)) ]]; then
      mv "$DEMO/isfile.csv" "$RES/raw_file_in_run$k.csv"
      mv "$DEMO/isconn.csv" "$RES/raw_conn_in_run$k.csv"
      echo "  trial $k in-session OK (file=$frows conn=$crows, $emitted KIND_ALLOW at cgid $SESSION_CGID)"
      rm -f "$DEMO/rbench.sh"; return 0
    fi
    echo "  trial $k attempt $tries: file=$frows conn=$crows emitted=$emitted -- retrying"
  done
  rm -f "$DEMO/rbench.sh"
  echo "  trial $k in-session FAILED after 3 attempts"; return 1
}

if [[ "$MODE" == "floor" ]]; then
  if pgrep -f '[d]aemon/leashd.py' >/dev/null; then
    echo "ABORT: leashd is UP. Floor (c) needs NO program attached -- Ctrl-C it first."; exit 3
  fi
  echo "condition (c): no-program floor, $TRIALS trials"
  for k in $(seq 1 $TRIALS); do
    "$MICRO" file    $NFILE $FILE_TARGET "$RES/raw_file_floor_run$k.csv" $WARMF
    "$MICRO" connect $NCONN $CONN_TARGET "$RES/raw_conn_floor_run$k.csv" $WARMC
  done
  echo "floor done -> $RES"
  exit 0
fi

# live: (a) in-session + (b) out-of-session, interleaved
pgrep -f '[d]aemon/leashd.py' >/dev/null || { echo "ABORT: leashd not running; (a)/(b) need the live session."; exit 3; }
curl -sf http://127.0.0.1:8000/health >/dev/null || { echo "ABORT: agent not reachable."; exit 3; }
echo "conditions (a) in-session + (b) out-of-session, $TRIALS interleaved trials"
for k in $(seq 1 $TRIALS); do
  echo "trial $k/$TRIALS:"
  "$MICRO" file    $NFILE $FILE_TARGET "$RES/raw_file_out_run$k.csv" $WARMF >/dev/null
  "$MICRO" connect $NCONN $CONN_TARGET "$RES/raw_conn_out_run$k.csv" $WARMC >/dev/null
  drive_in_session "$k"
done
echo "live done -> $RES"
