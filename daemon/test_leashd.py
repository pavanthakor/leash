#!/usr/bin/env python3
"""Unprivileged tests for leashd (no BPF). Two parts:
  A) parser: feed BYTE-IDENTICAL recorded loader output -> assert correct JSON.
  B) supervision: run leashd against stub loaders -> multiplex, restart/fail-open
     surfacing, resync parsing, and PDEATHSIG (kill -9 leashd -> children die)."""
import io, json, os, signal, subprocess, sys, time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "daemon"))
import leashd

def _capture_parse(layer, sample):
    """Run the LineParser over a sample file, return the emitted events."""
    buf = io.StringIO()
    leashd._fh = buf
    leashd._seq = 0
    st = {}
    p = leashd.LineParser(layer, st)
    for line in open(os.path.join(ROOT, "daemon", "stubs", sample)).read().split("\n"):
        if line == "" and False: continue
        p.feed(line)
    return [json.loads(l) for l in buf.getvalue().splitlines()]

def part_a():
    print("== A) parser vs byte-identical recorded loader output ==")
    ok = True
    fe = _capture_parse("file", "sample_file.txt")
    types = [e["type"] for e in fe]
    deny = next((e for e in fe if e["type"] == "deny"), None)
    debug = next((e for e in fe if e["type"] == "debug"), None)
    resync = next((e for e in fe if e["type"] == "resync"), None)
    checks = [
        ("file deny parsed", deny is not None),
        ("file deny dev/ino", deny and deny.get("dev")==264241152 and deny.get("ino")==920726),
        ("file deny path", deny and deny.get("path")=="/home/pavan/leash-demo/secrets/api_key.txt"),
        ("file deny cgid stamped", deny and deny.get("cgid")==8378),
        ("file deny has seq", deny and "seq" in deny),
        ("file debug MATCH", debug and debug.get("match") is True),
        ("file resync 8378->8500", resync and resync.get("old_cgid")==8378 and resync.get("new_cgid")==8500),
        ("file attached parsed", "attached" in types),
        ("file nothing dropped (log passthrough present)", "log" in types or "session" in types),
    ]
    ee = _capture_parse("egress", "sample_egress.txt")
    allow = next((e for e in ee if e["type"]=="allow"), None)
    edeny = next((e for e in ee if e["type"]=="deny"), None)
    checks += [
        ("egress allow 11434 MATCH", allow and allow.get("port")==11434 and allow.get("match") is True),
        ("egress allow cgid stamped", allow and allow.get("cgid")==8378),
        ("egress deny 9000", edeny and edeny.get("port")==9000 and edeny.get("verdict")=="-EPERM"),
        ("egress deny ip", edeny and edeny.get("ip")=="127.0.0.1"),
    ]
    for name, cond in checks:
        print(f"  [{'PASS' if cond else 'FAIL'}] {name}"); ok = ok and bool(cond)
    return ok

def _read_events(path):
    try: return [json.loads(l) for l in open(path)]
    except FileNotFoundError: return []

def _alive(pid):
    try: os.kill(pid, 0); return True
    except OSError: return False

def part_b():
    print("== B) supervision: leashd + stub loaders (no BPF) ==")
    stubdir = os.path.join(ROOT, "daemon", "stubs")
    evfile = "/tmp/leashd_test_events.jsonl"
    if os.path.exists(evfile): os.remove(evfile)
    # distinct names so each child derives its layer from argv[0]
    env = dict(os.environ,
               LEASH_ENFORCE_BIN=os.path.join(stubdir, "stub_file"),
               LEASH_CONNECT_BIN=os.path.join(stubdir, "stub_connect"),
               LEASH_EVENTS=evfile)
    ok = True
    proc = subprocess.Popen([sys.executable, os.path.join(ROOT,"daemon","leashd.py")],
                            env=env)
    try:
        time.sleep(4)
        evs = _read_events(evfile)
        types = [(e["layer"], e["type"]) for e in evs]
        ss = evs and evs[0].get("type") == "session_start" and evs[0].get("seq") == 0
        print(f"  [{'PASS' if ss else 'FAIL'}] session_start is line 1 with seq=0"); ok = ok and ss
        attached_layers = {e["layer"] for e in evs if e["type"]=="attached"}
        multi = {"file","egress"} <= attached_layers
        print(f"  [{'PASS' if multi else 'FAIL'}] BOTH layers attached (multiplex): {attached_layers}"); ok = ok and multi
        denies = {e["layer"] for e in evs if e["type"]=="deny"}
        dboth = {"file","egress"} <= denies
        print(f"  [{'PASS' if dboth else 'FAIL'}] deny events from BOTH layers: {denies}"); ok = ok and dboth
        seqs = [e["seq"] for e in evs]
        mono = seqs == sorted(seqs) and len(set(seqs))==len(seqs)
        print(f"  [{'PASS' if mono else 'FAIL'}] seq is monotonic and unique"); ok = ok and mono

        # kill ONE child (file layer) -> expect down/failopen(open)/reattach
        spawns = {e["layer"]: e["pid"] for e in evs if e["type"]=="spawn"}
        os.kill(spawns["file"], signal.SIGKILL)
        time.sleep(3)
        evs = _read_events(evfile)
        got = {e["type"] for e in evs if e["layer"]=="file"}
        surfaced = "down" in got and any(e["type"]=="failopen" and e.get("window")=="open"
                                         for e in evs if e["layer"]=="file")
        reatt = any(e["type"]=="reattach" and e["layer"]=="file" for e in evs)
        print(f"  [{'PASS' if surfaced else 'FAIL'}] killed loader surfaced down + failopen(open)"); ok = ok and surfaced
        print(f"  [{'PASS' if reatt else 'FAIL'}] loader was restarted (reattach)"); ok = ok and reatt

        # SIGHUP a child -> resync event
        spawns2 = {e["layer"]: e["pid"] for e in evs if e["type"]=="spawn"}
        os.kill(spawns2["egress"], signal.SIGHUP)
        time.sleep(1.5)
        evs = _read_events(evfile)
        resync = any(e["type"]=="resync" and e.get("old_cgid")==8378 and e.get("new_cgid")==8500 for e in evs)
        print(f"  [{'PASS' if resync else 'FAIL'}] resync event surfaced (old->new cgid)"); ok = ok and resync

        # PDEATHSIG: kill -9 leashd -> children must die (fail open on leashd death)
        cur = {e["layer"]: e["pid"] for e in _read_events(evfile) if e["type"]=="spawn"}
        child_pids = list(cur.values())
        os.kill(proc.pid, signal.SIGKILL)
        time.sleep(2)
        dead = all(not _alive(p) for p in child_pids)
        print(f"  [{'PASS' if dead else 'FAIL'}] kill -9 leashd -> all loader children gone (pids {child_pids})"); ok = ok and dead
    finally:
        if proc.poll() is None: proc.kill()
        for e in _read_events(evfile):
            if e["type"]=="spawn" and _alive(e["pid"]):
                try: os.kill(e["pid"], signal.SIGKILL)
                except OSError: pass
    return ok

if __name__ == "__main__":
    a = part_a(); print(); b = part_b()
    print(f"\nRESULT: part A {'PASS' if a else 'FAIL'}, part B {'PASS' if b else 'FAIL'}")
    sys.exit(0 if (a and b) else 1)
