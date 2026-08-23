# Architecture

How the pieces that already exist fit together. This describes the built system;
it designs nothing new. `bpf/`, `daemon/`, and `policy/` are sealed.

## One decision, made in the kernel

Every containment decision is one question asked at a syscall, on arguments the
kernel has already resolved: **is this process in the leashed session, and does
policy permit what it is about to do?** If yes, the syscall proceeds; if no, the
hook returns `-EPERM` and the syscall fails. The agent's language never enters
the decision.

```
            ┌──────────────────────────────────────────────────────────────┐
            │  agent process tree  (cgroup: leash-agent.service)            │
            │                                                                │
            │   uvicorn ──fork──▶ sh ──fork──▶ curl        read_file / httpx │
            │      │                 │            │              │           │
            └──────┼─────────────────┼────────────┼──────────────┼──────────┘
                   │ open()          │            │ connect()    │ open()/connect()
                   ▼                 ▼            ▼              ▼
        ┌───────────────────────────────────────────────────────────────────┐
        │  KERNEL — eBPF LSM hooks  (fire for EVERY such syscall, host-wide)  │
        │                                                                     │
        │  lsm/file_open           leash_enforce_open   (bpf/leash_enforce.*) │
        │  lsm/socket_connect      leash_connect        (bpf/leash_connect.*) │
        │                                                                     │
        │   1. cgid = bpf_get_current_cgroup_id()                             │
        │   2. sessions map lookup ── miss ─▶ return 0   (out-of-session:     │
        │        │                                        the early return    │
        │        hit                                      every other process │
        │        ▼                                        on the host hits)   │
        │   3. file:  (st_dev,st_ino) ∈ protected_files ?  ─▶ -EPERM / allow  │
        │      egress: (ip,port)      ∈ allowed_dests   ?  ─▶ allow / -EPERM  │
        │   4. emit one record to the `denies` ring buffer (deny; egress also │
        │      emits the self-verifying allow)                                │
        └───────────────────────────┬─────────────────────────────────────────┘
                                     │ ring buffer
                                     ▼
        ┌───────────────────────────────────────────────────────────────────┐
        │  USERSPACE (root)                                                   │
        │                                                                     │
        │  C loaders  leash_enforce / leash_connect  (bpf/*.c)                │
        │    · resolve the session cgid, populate the maps from policy        │
        │    · poll the ring buffer, print each event as text                 │
        │    · follow cgid drift on an agent restart → re-sync the sessions   │
        │      map (this is restart-survival)                                 │
        │                                                                     │
        │  leashd  (daemon/leashd.py)  — supervisor                           │
        │    · discovers the cgroup from the STABLE unit name                 │
        │    · compiles policy.yaml via policc, launches BOTH loaders         │
        │    · multiplexes their stdout into ONE JSON-lines event stream      │
        │    · PR_SET_PDEATHSIG: if leashd dies, the loaders die → fail-open  │
        └───────────────────────────┬─────────────────────────────────────────┘
                                     │ ~/leash-demo/leashd.events.jsonl  (append)
                                     ▼
        ┌───────────────────────────────────────────────────────────────────┐
        │  DASHBOARD (unprivileged, read-only)                               │
        │    bridge (dashboard/bridge/leash_bridge.py) tails the stream → SSE │
        │    React console: posture · session · causal chain · event log     │
        └───────────────────────────────────────────────────────────────────┘
```

## Session attribution = cgroup

The agent runs in a dedicated cgroup (`leash-agent.service`, created unprivileged
by `scripts/launch_session.sh` via the systemd user manager). Every LSM hook
reads `bpf_get_current_cgroup_id()` and checks it against the `sessions` map,
which holds exactly that one cgid. Child processes inherit the cgroup by kernel
guarantee, so a forked `sh → curl` is in-session with no cooperation — the kernel
sees it, not a wrapper. Because the hooks are global, *every* process on the host
runs step 1–2; a non-session process misses the `sessions` map and returns
immediately (this early return is the ~19 ns/open host-wide cost measured in
Phase 8).

## The two hooks and their maps

| hook | program | decision map | identity |
|------|---------|--------------|----------|
| `lsm/file_open` | `leash_enforce_open` | `protected_files` | `(st_dev, st_ino)` — survives a rename/hardlink; path is report-only |
| `lsm/socket_connect` | `leash_connect` | `allowed_dests` | `(ip, port)`, IPv4 only — the kernel-resolved sockaddr |

Both share the `sessions` map (the session gate) and a `denies` ring buffer (the
evidence stream). The file program also keeps `debug_inos` to emit a
self-verifying `(dev,ino)` MATCH line on a protected-inode open. Egress is
**default-deny**: a destination not on the allowlist is `-EPERM`, so the attacker
must land on a destination the task explicitly permitted — which by construction
excludes their sink.

## Restart-survival (the resync)

systemd recreates the agent's cgroup with a **new** inode id on relaunch (same
path, new cgid). The loaders poll for that drift and re-sync the `sessions` map
old→new, so enforcement follows the restarted agent with no human action. In the
event stream this is a `resync` event (e.g. `9066→9205` at seq 91 in
`fixtures/session-full.jsonl`), after which every deny is stamped with the new
cgid — the proof that enforcement moved with the session.

## Fail-open, by construction

Safety comes from asymmetry: enforcement exists only while the whole chain is
live. `leashd` sets `PR_SET_PDEATHSIG(SIGKILL)` on each loader, so if leashd dies
the loaders die and the programs leave the kernel — enforcement vanishes and
nothing is blocked. A loader that exits on its own is respawned, but its
down-window is surfaced as an explicit `failopen`/`reattach` pair in the stream,
never hidden. Clearing the `sessions` map (SIGUSR1) has the same effect: nobody
is in-session, so nothing is denied.

## Policy

`policy/policy.yaml` is the single source: a file protect-list and an egress
allowlist (`default: deny`). `daemon/policc.py` validates and compiles it into
the exact `(dev,ino)` and `(ip,port)` entries the loaders load into their maps —
all-or-nothing, so an invalid policy attaches nothing.

## What is downstream and cannot affect enforcement

The dashboard and its bridge are strictly read-only consumers of the event
stream file. The bridge opens the JSON-lines file `"r"` only; it never signals
leashd, never touches a map, never writes the stream. Killing the dashboard
changes nothing about what the kernel permits. The measurement harness
(`bench/`) and the attack library (`attacks/`) are likewise ordinary
unprivileged processes driven through the agent — they exercise the enforcer,
they are not part of it.

## Map of the code

| component | files |
|-----------|-------|
| eBPF programs | `bpf/leash_enforce.bpf.c`, `bpf/leash_connect.bpf.c` |
| C loaders | `bpf/leash_enforce.c`, `bpf/leash_connect.c` |
| supervisor + compiler | `daemon/leashd.py`, `daemon/policc.py` |
| policy | `policy/policy.yaml` |
| agent + attacks | `agent/`, `attacks/` |
| dashboard | `dashboard/bridge/leash_bridge.py`, `dashboard/src/` |
| lifecycle | `scripts/up.sh`, `demo.sh`, `down.sh`, `uninstall.sh` |
