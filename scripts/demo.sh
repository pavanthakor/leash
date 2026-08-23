#!/usr/bin/env bash
# scripts/demo.sh -- the paced live demo. Fires the 7 Phase-7 attack shapes in
# order against the live enforcer, one at a time with a beat between, so each
# containment lands VISIBLY on the dashboard with its caption -- and #7's honest
# NOT-CONTAINED lands with weight after six stops.
#
# Built on P7's harness (attacks/harness.py, attacks/library.py): the outcomes
# are the real kernel verdicts, read from the stream + sinks, never asserted.
# The harness's full-speed run_all() stays for proof runs; this is the paced
# presentation layer.
set -euo pipefail
cd "$(dirname "$0")/.."
source scripts/lib_leash.sh

[[ -n "$(leashd_pids)" ]] || { bad "leashd not running -- run scripts/up.sh first."; exit 1; }
curl -sf http://127.0.0.1:8000/health >/dev/null || { bad "agent not answering -- run scripts/up.sh first."; exit 1; }

# start the gap sink (IPv6 + AF_UNIX) if not already up -- #7 needs somewhere to land
if ! pgrep -f 'sink6\.py' >/dev/null; then
  setsid python3 attacks/sink6.py </dev/null >"$DEMO/sink6.stdout" 2>&1 &
  sleep 1
fi

BEAT="${LEASH_DEMO_BEAT:-1.8}"
say "demo -- 7 exfil shapes against the live enforcer (watch the dashboard)"
say ""

python3 - "$BEAT" <<'PY'
import sys, time
sys.path.insert(0, "attacks")
import harness as H, library as L

beat = float(sys.argv[1])
GREEN, RED, DIM, RST = "\033[32m", "\033[31m", "\033[2m", "\033[0m"

def caption(n, title, outcome, detail):
    mark = f"{GREEN}CONTAINED{RST}" if outcome == "contained" else \
           f"{RED}NOT CONTAINED{RST}" if outcome == "not_contained" else \
           f"{DIM}{outcome}{RST}"
    print(f"  {n}  {title:<34} -> {mark}   {DIM}{detail}{RST}")

for i, atk in enumerate(L.ATTACKS, 1):
    circ = "①②③④⑤⑥⑦"[i-1]
    if atk.get("subprobes"):
        print(f"\n  {circ}  {atk['title']} -- the disclosed AF_INET-scope limit:")
        for sp in atk["subprobes"]:
            r = H.run_probe(sp, retries=3)
            e = r["evidence"]
            if r["outcome"] == "contained":
                d = f"deny seq {e.get('denied_seq')} (IPv4 control)"
            elif r["outcome"] == "not_contained":
                d = f"{sp['family']} reached the sink -- NO kernel event"
            else:
                d = r["outcome"]
            caption("   ·", sp["label"], r["outcome"], d)
            time.sleep(beat)
        print(f"     {DIM}the file layer still blocks the key read -- #7 leaks other data, not the key.{RST}")
    else:
        r = H.run_probe(atk, retries=3)
        e = r["evidence"]
        tgt = e.get("denied_target") or ""
        d = f"deny seq {e.get('denied_seq')} [{e.get('denied_layer')}] {tgt}".strip()
        caption(circ, atk["title"], r["outcome"], d)
        time.sleep(beat)

print(f"\n  six shapes stopped at the kernel; the seventh walks a disclosed gap -- stated, not hidden.")
PY
say ""
ok "demo complete -- denials are on the dashboard; toggle 'allow' there to see the permitted Ollama traffic."
