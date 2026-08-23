#!/usr/bin/env bash
# Read leashd's event stream and answer the proof questions.
#   leashd_check.sh resync    exit 0 iff a resync (old_cgid != new_cgid) fired  (restart-survival gate)
#   leashd_check.sh denies    list every deny event (which layer stopped what)
#   leashd_check.sh failopen  list down/failopen/reattach/session_end (fail-open windows)
#   leashd_check.sh tail [N]  raw tail of the stream
EV="${LEASH_EVENTS:-$HOME/leash-demo/leashd.events.jsonl}"
PY="$HOME/leash/.venv/bin/python"
case "${1:-}" in
  resync)
    "$PY" - "$EV" <<'P'
import json,sys
evs=[json.loads(l) for l in open(sys.argv[1])]
r=[e for e in evs if e["type"]=="resync" and e.get("old_cgid")!=e.get("new_cgid")]
for e in r: print(f"  seq={e['seq']} {e['layer']}: cgid {e['old_cgid']} -> {e['new_cgid']} (re-synced)")
print(f"  => {len(r)} resync event(s)")
sys.exit(0 if r else 1)
P
    ;;
  denies)
    "$PY" -c "import json;[print(f\"  seq={e['seq']} {e['layer']:6} deny pid={e.get('pid')} comm={e.get('comm')} -> {e.get('path') or str(e.get('ip'))+':'+str(e.get('port'))}\") for e in map(json.loads,open('$EV')) if e['type']=='deny']" ;;
  failopen)
    "$PY" -c "import json;[print(f\"  seq={e['seq']} {e['layer']:6} {e['type']} {e.get('window','')} {e.get('reason','')}\") for e in map(json.loads,open('$EV')) if e['type'] in ('down','failopen','reattach','session_end')]" ;;
  tail) tail -n "${2:-20}" "$EV" ;;
  *) echo "usage: leashd_check.sh <resync|denies|failopen|tail [N]>"; exit 2 ;;
esac
