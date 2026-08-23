#!/usr/bin/env python3
"""Stub loader for leashd's UNPRIVILEGED supervision test. Replays BYTE-IDENTICAL
recorded loader output (daemon/stubs/sample_<layer>.txt, generated from the real
printf format strings) and responds to the same signals as the real loaders:
  SIGHUP  -> emit a resync line (simulate agent-restart cgid drift)
  SIGINT/SIGTERM -> emit the detaching line and exit (fail open)
It ignores its argv (cgroup path + entries) exactly as an orchestrated child would
be launched. No BPF, no privilege -- it exists solely to exercise leashd's
discovery/compile/multiplex/supervision/pdeathsig paths against real bytes.
"""
import os, signal, sys, time

_name = os.path.basename(sys.argv[0])
if "connect" in _name or "egress" in _name:
    layer = "egress"
elif "enforce" in _name or "file" in _name:
    layer = "file"
else:
    layer = "file"
here = os.path.dirname(os.path.abspath(__file__))
lines = open(os.path.join(here, f"sample_{layer}.txt")).read().split("\n")
if lines and lines[-1] == "": lines.pop()

# split the recorded stream into startup / event-pairs / resync / detach
ev_start = next(i for i, l in enumerate(lines) if l.startswith("  DEBUG") or l.startswith("  ALLOW"))
startup = lines[:ev_start]
events  = lines[ev_start:ev_start + 4]                       # the two 2-line events
resync  = next(l for l in lines if l.startswith(">>> session cgid changed"))
detach  = next(l for l in lines if l.startswith("detaching -- "))

def out(s): sys.stdout.write(s + "\n"); sys.stdout.flush()

def on_hup(*_): out(resync)
def on_term(*_): out(""); out(detach); sys.exit(0)
signal.signal(signal.SIGHUP, on_hup)
signal.signal(signal.SIGINT, on_term)
signal.signal(signal.SIGTERM, on_term)

for l in startup: out(l)                                     # attach banner (incl. ATTACHED)
while True:                                                  # steady traffic: one event-pair set / tick
    for l in events: out(l)
    time.sleep(0.7)
