#!/usr/bin/env python3
"""leashd -- Phase 6a supervisor. Orchestrates the PROVEN pieces; touches none.

Run (privileged, by the operator):   sudo python3 daemon/leashd.py [policy.yaml]

It (a) auto-discovers the agent's session cgroup from the STABLE unit name, not a
pasted path; (b) compiles policy.yaml via the existing policc and launches BOTH
proven loaders (leash_enforce + leash_connect) from it; (c) multiplexes their
stdout into ONE JSON-lines event stream; (d) leans on the loaders' own cgid
re-sync so an agent restart needs no human action. Fail-open is honest: a loader
that dies is restarted but its down-window is surfaced; and PR_SET_PDEATHSIG ties
the loaders' lives to leashd's own -- if leashd dies, they die, enforcement
vanishes (charter invariant 3).

Does NOT import yaml or reimplement any loader logic. policc is called by
absolute venv-python path (leashd runs as root; PATH is not trusted).
"""
import ctypes
import glob
import json
import os
import re
import signal
import subprocess
import sys
import threading
import time

LEASH_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VENV_PY   = os.path.join(LEASH_ROOT, ".venv", "bin", "python")     # absolute (refinement 6)
POLICC    = os.path.join(LEASH_ROOT, "daemon", "policc.py")
DEMO      = os.path.join(os.path.dirname(LEASH_ROOT), "leash-demo")
EVENTS    = os.environ.get("LEASH_EVENTS", os.path.join(DEMO, "leashd.events.jsonl"))
ENFORCE_BIN = os.environ.get("LEASH_ENFORCE_BIN", os.path.join(LEASH_ROOT, "bpf", "leash_enforce"))
CONNECT_BIN = os.environ.get("LEASH_CONNECT_BIN", os.path.join(LEASH_ROOT, "bpf", "leash_connect"))
UNIT      = os.environ.get("LEASH_UNIT", "leash-agent.service")

# ------------------------------------------------------------------ event stream
_seq_lock = threading.Lock()
_seq = 0
_fh = None

def _open_stream():
    """Fresh stream per leashd start (refinement 4): truncate + session_start."""
    global _fh
    os.makedirs(os.path.dirname(EVENTS), exist_ok=True)
    _fh = open(EVENTS, "w")           # truncates
    try:
        os.chmod(EVENTS, 0o644)        # world-readable so the unprivileged dashboard can tail it
    except OSError:
        pass

def emit(layer, etype, **fields):
    """Write one JSON-lines event. seq is monotonic across the whole stream."""
    global _seq
    with _seq_lock:
        ev = {"seq": _seq, "ts": time.time(), "layer": layer, "type": etype}
        ev.update(fields)
        _seq += 1
        _fh.write(json.dumps(ev) + "\n")
        _fh.flush()
    return ev

# ------------------------------------------------------------------ discovery
def _procs_nonempty(cgdir):
    try:
        with open(os.path.join(cgdir, "cgroup.procs")) as f:
            return any(line.strip() for line in f)
    except OSError:
        return False

def discover_cgroup(timeout=30.0):
    """Resolve the STABLE unit name -> cgroup path by reading cgroupfs directly
    (works as root; `systemctl --user` would target root's manager). Handles a
    transient >1 match during a restart by picking the LIVE dir (non-empty
    cgroup.procs) and logging that multiple were seen (refinement 3)."""
    seen = set()
    deadline = time.time() + timeout
    while time.time() < deadline:
        matches = [m for m in glob.glob(f"/sys/fs/cgroup/**/{UNIT}", recursive=True)
                   if os.path.isdir(m)]
        for m in matches:
            seen.add(m)
        if len(matches) > 1:
            emit("leashd", "log", msg=f"multiple cgroup dirs for {UNIT}: {sorted(matches)}")
        live = [m for m in matches if _procs_nonempty(m)]
        if live:
            return sorted(live)[0]
        time.sleep(0.2)
    emit("leashd", "log", msg=f"discovery timeout: no live cgroup for {UNIT} (seen={sorted(seen)})")
    return None

# ------------------------------------------------------------------ policy compile
def _policc(sub, policy):
    return subprocess.run([VENV_PY, POLICC, sub, policy],
                          capture_output=True, text=True)

def compile_policy(policy):
    """Validate the WHOLE policy, then return (files, egress). Refuse (None) on
    any error -- inherits Phase 5's all-or-nothing gate; nothing is launched."""
    v = _policc("validate", policy)
    if v.returncode != 0:
        emit("leashd", "policy_rejected", detail=v.stderr.strip())
        sys.stderr.write(v.stderr)
        return None
    files  = [l for l in _policc("files", policy).stdout.splitlines() if l.strip()]
    egress = [l for l in _policc("egress", policy).stdout.splitlines() if l.strip()]
    return files, egress

# ------------------------------------------------------------------ stdout parser
# Matched against the loaders' EXACT print formats (byte-identical). Events span
# TWO lines (a header + a continuation), so the parser is a tiny per-child state
# machine. cgid is tracked per layer and stamped onto every deny/allow/debug
# (refinement 5). Unrecognized lines pass through as type:"log" (nothing dropped).
RE = {
  "sessioncgid": re.compile(r"^session cgid = (\d+)$"),
  "resync":      re.compile(r"^>>> session cgid changed (\d+) -> (\d+) \(re-synced\)$"),
  "attached":    re.compile(r"^ATTACHED (.+?)  loader pid = (\d+)$"),
  "sigusr1":     re.compile(r"^>>> SIGUSR1: sessions cleared"),
  "detach":      re.compile(r"^detaching -- "),
  # two-line headers. NOTE: comm is the kernel comm in a fixed-width padded field
  # and may contain SPACES (e.g. "AnyIO worker th"), so it is matched non-greedily
  # up to each line's own delimiter (" dev=", " -> ", end-of-line) -- never \S+.
  "f_debug1":    re.compile(r"^  DEBUG   in-session open of protected inode  pid=(\d+)\s+comm=(.+?)\s*$"),
  "f_deny1":     re.compile(r"^  DENIED  file_open  pid=(\d+)\s+uid=(\d+)\s+comm=(.+?)\s+dev=(\d+) ino=(\d+)\s*$"),
  "e_allow1":    re.compile(r"^  ALLOW   socket_connect  pid=(\d+)\s+comm=(.+?)\s+-> (\S+):(\d+) \(kernel-read\)$"),
  "e_deny1":     re.compile(r"^  DENIED  socket_connect  pid=(\d+)\s+uid=(\d+)\s+comm=(.+?)\s+-> (\S+):(\d+) \(kernel-read\)$"),
  # continuations:
  "f_debug2":    re.compile(r"^          kernel-read dev=(\d+) ino=(\d+) \| map-stored dev=(\d+)  ->  (MATCH|MISMATCH.*)$"),
  "f_deny2":     re.compile(r"^          path=(.+?)  ->  -EPERM$"),
  "e_allow2":    re.compile(r"^          == allowlisted (\S+):(\d+)  ->  MATCH \(permitted\)$"),
  "e_deny2":     re.compile(r"^          not on allowlist  ->  -EPERM$"),
}

class LineParser:
    """Per-child: fixed layer, tracks cgid, joins two-line events."""
    def __init__(self, layer, state):
        self.layer = layer
        self.state = state          # shared dict for attach-count -> reattach
        self.cgid = None
        self.pending = None         # (kind, groups) awaiting a continuation

    def feed(self, line):
        L, lay = self, self.layer
        # continuation of a pending two-line event?
        if self.pending:
            kind, g = self.pending
            self.pending = None
            if kind == "f_debug":
                m = RE["f_debug2"].match(line)
                if m:
                    emit(lay, "debug", cgid=self.cgid, pid=int(g[0]), comm=g[1],
                         dev=int(m.group(1)), ino=int(m.group(2)),
                         map_dev=int(m.group(3)), match=m.group(4).startswith("MATCH"),
                         raw=self._raw2(g[-1], line)); return
            elif kind == "f_deny":
                m = RE["f_deny2"].match(line)
                if m:
                    emit(lay, "deny", cgid=self.cgid, pid=int(g[0]), uid=int(g[1]), comm=g[2],
                         dev=int(g[3]), ino=int(g[4]), path=m.group(1), verdict="-EPERM",
                         raw=self._raw2(g[-1], line)); return
            elif kind == "e_allow":
                m = RE["e_allow2"].match(line)
                if m:
                    emit(lay, "allow", cgid=self.cgid, pid=int(g[0]), comm=g[1],
                         ip=g[2], port=int(g[3]), match=True,
                         raw=self._raw2(g[-1], line)); return
            elif kind == "e_deny":
                m = RE["e_deny2"].match(line)
                if m:
                    emit(lay, "deny", cgid=self.cgid, pid=int(g[0]), uid=int(g[1]), comm=g[2],
                         ip=g[3], port=int(g[4]), verdict="-EPERM",
                         raw=self._raw2(g[-1], line)); return
            # continuation didn't match: don't drop the header -- log it, fall through
            emit(lay, "log", raw=g[-1])

        m = RE["sessioncgid"].match(line)
        if m: self.cgid = int(m.group(1)); emit(lay, "session", cgid=self.cgid, raw=line); return
        m = RE["resync"].match(line)
        if m:
            self.cgid = int(m.group(2))
            emit(lay, "resync", old_cgid=int(m.group(1)), new_cgid=int(m.group(2)),
                 cgid=self.cgid, raw=line); return
        m = RE["attached"].match(line)
        if m:
            n = self.state.setdefault("attach", {}).get(lay, 0) + 1
            self.state["attach"][lay] = n
            emit(lay, "attached", pid=int(m.group(2)), detail=m.group(1), raw=line)
            if n > 1:  # a respawn attached -> fail-open window closes
                emit(lay, "reattach", raw=line)
                emit(lay, "failopen", window="closed", of=lay, raw=line)
            return
        if RE["sigusr1"].match(line): emit(lay, "failopen", window="open", reason="sigusr1", raw=line); return
        if RE["detach"].match(line):  emit(lay, "failopen", window="open", reason="detach", raw=line); return
        # two-line headers -> stash and wait
        for kind in ("f_debug", "f_deny", "e_allow", "e_deny"):
            m = RE[kind + "1"].match(line)
            if m: self.pending = (kind, m.groups() + (line,)); return
        emit(lay, "log", raw=line)   # nothing recognized -> never dropped

    @staticmethod
    def _raw2(h, c): return h + "\n" + c

# ------------------------------------------------------------------ supervisor
_shutdown = threading.Event()
_children = {}
_state = {}
libc = ctypes.CDLL("libc.so.6", use_errno=True)

def _set_pdeathsig():
    # child, post-fork/pre-exec: die if leashd dies (fail-open on leashd death).
    libc.prctl(1, signal.SIGKILL)         # PR_SET_PDEATHSIG = 1
    if os.getppid() == 1:                 # parent already gone in the race window
        os._exit(1)

def supervise(layer, argv):
    backoff = 0.5
    while not _shutdown.is_set():
        try:
            proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    text=True, bufsize=1, preexec_fn=_set_pdeathsig)
        except Exception as ex:
            emit(layer, "log", level="error", msg=f"spawn failed: {ex}")
            time.sleep(backoff); backoff = min(backoff * 2, 5); continue
        _children[layer] = proc
        emit(layer, "spawn", pid=proc.pid, argv=argv)
        # drain stderr in the background so errors are never lost
        threading.Thread(target=_drain_stderr, args=(layer, proc), daemon=True).start()
        parser = LineParser(layer, _state)
        for line in proc.stdout:
            parser.feed(line.rstrip("\n"))
        rc = proc.wait()
        _children[layer] = None
        if _shutdown.is_set():
            break
        emit(layer, "down", returncode=rc)
        emit(layer, "failopen", window="open", reason="loader_exited", of=layer)
        time.sleep(backoff); backoff = min(backoff * 2, 5)
        emit(layer, "log", msg=f"respawning {layer} loader")
    # loop exits only on shutdown

def _drain_stderr(layer, proc):
    for line in proc.stderr:
        emit(layer, "log", level="stderr", raw=line.rstrip("\n"))

def _shutdown_handler(signum, frame):
    _shutdown.set()
    emit("leashd", "session_end", signal=signum)
    for layer, proc in list(_children.items()):
        if proc and proc.poll() is None:
            try: proc.send_signal(signal.SIGINT)   # loaders detach -> fail open
            except Exception: pass
    time.sleep(0.5)
    try: _fh.flush()
    except Exception: pass
    os._exit(0)

def main(argv):
    policy = argv[1] if len(argv) > 1 else os.path.join(LEASH_ROOT, "policy", "policy.yaml")
    _open_stream()
    emit("leashd", "session_start", pid=os.getpid(), policy=policy,
         enforce_bin=ENFORCE_BIN, connect_bin=CONNECT_BIN)

    compiled = compile_policy(policy)
    if compiled is None:
        emit("leashd", "log", level="fatal", msg="policy invalid -- refusing to attach anything")
        sys.stderr.write("leashd: policy invalid; nothing attached.\n")
        return 2
    files, egress = compiled
    emit("leashd", "policy", files=files, egress=egress)

    cg = discover_cgroup()
    if not cg:
        sys.stderr.write(f"leashd: could not discover cgroup for {UNIT} (is the agent up?)\n")
        return 3
    emit("leashd", "discover", cgroup=cg, unit=UNIT)

    signal.signal(signal.SIGINT, _shutdown_handler)
    signal.signal(signal.SIGTERM, _shutdown_handler)

    threads = []
    for layer, binpath, entries in (("file", ENFORCE_BIN, files), ("egress", CONNECT_BIN, egress)):
        t = threading.Thread(target=supervise, args=(layer, [binpath, cg, *entries]), daemon=True)
        t.start(); threads.append(t)

    emit("leashd", "up", cgroup=cg, layers=["file", "egress"])
    while not _shutdown.is_set():
        time.sleep(0.5)
    return 0

if __name__ == "__main__":
    sys.exit(main(sys.argv))
