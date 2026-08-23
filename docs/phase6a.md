# Phase 6a — leashd (the daemon)

**Goal:** one supervisor replaces the hand-pasted cgroup path and the two separate
foreground enforcer runs. It (a) auto-discovers the session cgroup from a STABLE
handle, (b) compiles policy.yaml via policc and launches BOTH proven loaders from
it, (c) multiplexes their events into one JSON-lines stream, (d) survives an agent
restart with no human action. It ORCHESTRATES the proven pieces; it does not touch
`bpf/`, the two loaders, or `policc`.

## How it works
- **Discovery (stable handle):** `find`-style glob of cgroupfs for the unit dir
  `leash-agent.service` — works as root (unlike `systemctl --user`, which as root
  targets root's own manager). On a transient >1 match (old+new during a restart)
  it picks the LIVE dir (non-empty `cgroup.procs`) and logs that multiple were seen.
- **Compile:** calls `policc validate|files|egress` by ABSOLUTE venv-python path
  (leashd runs as root; PATH is not trusted). Invalid policy -> refuse, attach
  nothing (inherits Phase 5's all-or-nothing gate).
- **Launch:** spawns `leash_enforce <cgpath> <files...>` and `leash_connect
  <cgpath> <ip:ports...>` as children (leashd is already root; no `sudo` prefix,
  no loader change). The loaders re-sync the drifting cgid from the fixed path.
- **Multiplex:** one reader thread per child parses their EXACT stdout (a two-line
  state machine) into JSON-lines. Every event has a monotonic `seq`; every
  deny/allow/debug carries the session `cgid`. Unrecognized lines pass through as
  `type:"log"` with `raw` text -- nothing is ever dropped.
- **Fail-open, honest:**
  - a loader that dies is restarted, but its down-window is SURFACED
    (`down` -> `failopen{window:open}` -> `reattach` -> `failopen{window:closed}`).
  - **leashd's own death** ties to the loaders via `PR_SET_PDEATHSIG(SIGKILL)`:
    if leashd dies (even `kill -9`, no clean handler), the loaders get SIGKILL,
    detach, and enforcement vanishes (charter invariant 3).

## Event stream: JSON-lines file
`~/leash-demo/leashd.events.jsonl`, chosen over a loopback socket: durable and
replayable (whole session survives), a clean one-way privilege bridge (root writes
0644; the unprivileged 6b dashboard just tails it -- no unprivileged client into a
root process), minimal attack surface. Fresh per start: truncated at startup with
a `session_start` (seq=0) marker so a cold demo never replays yesterday's denials.
6b's WebSocket server tails this file.

## Event schema (one JSON object per line)
`seq` (monotonic), `ts`, `layer` (`file|egress|leashd`), `type`, plus fields.
Types: `session_start, policy, discover, up, spawn, attached, session, deny,
debug, allow, resync, down, failopen, reattach, log, session_end`.
`deny`/`allow`/`debug` carry `cgid`.

## Files (nothing under bpf/, no loader/policc change)
- `daemon/leashd.py` — the supervisor.
- `daemon/stubs/` — `stub_loader.py` + byte-identical `sample_{file,egress}.txt`
  (generated from the loaders' exact printf strings) + `stub_file`/`stub_connect`.
- `daemon/test_leashd.py` — parser + supervision tests (no BPF).
- `scripts/leashd_check.sh` — reads the stream (resync/denies/failopen/tail).
- `~/leash-demo/leashd.events.jsonl` — the event stream.

## Proven without sudo (`daemon/test_leashd.py`)
- **A) parser vs byte-identical recorded loader output:** deny (dev/ino/path/cgid/
  seq), debug MATCH, resync (old->new), egress allow 11434 + deny 9000. Nothing dropped.
- **B) supervision (leashd + stubs):** session_start seq=0; BOTH layers attached
  (multiplex); deny from both; seq monotonic/unique; killed loader surfaces
  `down`+`failopen(open)`+`reattach`; SIGHUP -> `resync`; **`kill -9` leashd ->
  both loader children die (PDEATHSIG)** — the leashd-death fail-open MECHANISM,
  proven unprivileged. Discovery resolves the real path; policy compiles via policc.

## Operator sudo sequence — the four hardware proofs
```
# Terminal A: session up
scripts/launch_session.sh
# Terminal B (SUDO): ONE supervisor, both layers from policy
sudo python3 daemon/leashd.py
   # -> discover cgroup; policy files/egress; both loaders ATTACH; note leashd PID
```
**Proof 1 — deny on BOTH layers from policy-compiled leashd.** In Terminal C:
```
scripts/enforce_probe.sh      # file: in-session read of key -> -EPERM
scripts/egress_probe.sh       # egress: connect :9000 -> -EPERM (BOTH shapes); :11434 ALLOW
scripts/leashd_check.sh denies # the stream shows both layers' denies
```
**Proof 2 — restart survival (self-checked on resync).** Do NOT touch leashd:
```
systemctl --user restart leash-agent
scripts/enforce_probe.sh && scripts/egress_probe.sh   # STILL denied
scripts/leashd_check.sh resync                          # MUST exit 0 (old_cgid -> new_cgid fired)
```
Pass IFF the probes are denied AND resync fired. (Absent resync + "denied" would be
the transient-path failure — a fixed path that changed on restart would strand the
loaders and fail open; the resync gate catches that honestly instead of hiding it.)
**Proof 3c — leashd-death fail-open at the worst case:**
```
sudo kill -9 <leashd PID>
pgrep -a leash_enforce; pgrep -a leash_connect   # BOTH gone (PDEATHSIG, no clean handler ran)
scripts/enforce_probe.sh --failopen              # previously-denied read now SUCCEEDS
```
**Proof 4 — out-of-session unaffected throughout:** `enforce_probe.sh`/`egress_probe.sh`
already run an out-of-session read/connect that must SUCCEED — confirm it does before
AND after the restart (it is never in the agent's cgroup, so the session gate never
sees it).

## How to verify

- Start the supervisor (`sudo .venv/bin/python daemon/leashd.py`); the stream at
  `~/leash-demo/leashd.events.jsonl` records `session_start`, both `attached`,
  denies, `resync`, fail-open windows and `session_end`.
- `scripts/leashd_check.sh resync` — gate the restart-survival resync (old→new
  cgid); the proofs 3a/3b/3c and 4 above are the fail-open and
  out-of-session-unaffected checks.
- Frozen captures: `fixtures/session-full.jsonl` (restart + resync 9066→9205),
  `fixtures/session-reattach.jsonl` (unexpected-death + reattach, cgid 7963).
