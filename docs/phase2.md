# Phase 2 — Session attribution

**Exit criterion:** run the Phase 1 attack under a launcher that puts the agent
in a dedicated cgroup, and reconstruct the agent's full process tree — parent,
children, grandchildren, including the forked exfil process — from kernel events
alone (no /proc walking, no agent cooperation).

## Mechanism
- **Dedicated cgroup, no sudo.** The systemd *user* manager delegates a writable
  subtree (`user@1000.service`). `launch_session.sh` starts the agent as a
  transient unit `leash-agent.service` there via `systemd-run --user`, so it gets
  its own cgroup. (A hand-rolled `mkdir`+move is denied by cgroup v2's ancestor
  rule — systemd owns the delegation.) The attacker listener runs as a *separate*
  unit, so it is out of the session by construction.
- **Attribution = cgroup id.** `leash_session.bpf.c` hooks `sched_process_fork`
  and `sched_process_exec`. Each reads `bpf_get_current_cgroup_id()` and checks
  the `sessions` map (populated by userspace with the agent cgroup's id). A
  non-session process `return 0`s immediately — the perf + blast-radius guarantee.
  Children inherit the cgroup by kernel guarantee, so a forked `sh`/`curl` is
  attributed with no cooperation.
- **Tree source = fork/exec tracepoints (not a cgroup snapshot).** The exit
  criterion forbids /proc walking and the exfil `curl` is short-lived; only a live
  event stream captures it with real parent→child edges. Tree *nodes* are built
  from EXEC events (authoritative comm + `real_parent` edge; threads never exec, so
  no thread clutter); FORK events are the ordered "every spawn seen live" log.
- **cgroup id → 64-bit match.** The loader resolves the cgroup path with
  `name_to_handle_at()` (verified equal to the value the kernel matches).

## Two exfil shapes (see charter)
`report.txt` (P1) leaks in-process via `http_get` (no fork). `report_fork.txt`
(P2) leaks via `run_shell` → `sh` → `collect_helper.sh` → `curl`, a forked child
the kernel must attribute. Deliberate, complementary attack-library coverage.

## Files
- `bpf/leash_session.bpf.c`, `bpf/leash_session.c` (+ Makefile targets)
- `scripts/launch_session.sh`   start/stop the dedicated-cgroup session (no sudo)
- `scripts/run_attack_p2.sh`     BPF-gated attack + long-lived negative control
- `scripts/cgroup_precheck.sh`   unprivileged proof → `~/leash-demo/cgroup_proof.log`
- `~/leash-demo/docs/report_fork.txt`, `~/leash-demo/docs/collect_helper.sh`

## How to run (the sudo boundary is the loader)
```
# Terminal A (no sudo)
scripts/launch_session.sh                 # prints CGROUP, AGENTPID, loader cmd

# Terminal B (SUDO — operator)
cd bpf && make leash_session
sudo ./leash_session <CGROUP> <AGENTPID>  # attaches, writes readiness, streams

# Terminal C (no sudo)
scripts/run_attack_p2.sh                  # HARD-GATES on readiness, then attacks
```

### Expected result
- **Positive:** the loader prints a tree rooted at the agent, e.g.
  ```
  agent(uvicorn)(<AGENTPID>)   <- session root
     sh(<pid>)
        sh(<pid>)              (collect_helper.sh)
           curl(<pid>)         <- THE FORKED EXFIL PROCESS
           sleep(<pid>)
  ```
  and `~/leash-demo/exfil.log` shows the decoy key.
- **Negative:** `run_attack_p2.sh` starts a long-lived out-of-session process
  (PID printed) that is alive during the run but MUST be absent from the tree —
  the session gate excluded it. Absence of a *live* process is the discriminating
  proof (a short-lived absence would be indistinguishable from a missed event).

### Hard gate (attach-before-spawn)
`run_attack_p2.sh` refuses to fire until the loader writes
`~/leash-demo/session_ready` (after tracepoints are attached and the session cgid
is loaded). If the root fork happened before attach, the tree would be silently
wrong — so the attack cannot start until attach is confirmed.

## Unprivileged evidence (no BPF needed): `~/leash-demo/cgroup_proof.log`
`scripts/cgroup_precheck.sh` proves the ground truth the kernel relies on:
(A) the agent is in `leash-agent.service`; (B) the forked exfil chain
(`sh → collect_helper.sh → curl/sleep`) is all in that same cgroup and the key
transits; (C) a long-lived outsider is in a different cgroup. This explains the
mechanism without re-running the BPF stack.

## How to verify

- `scripts/cgroup_precheck.sh` → `~/leash-demo/cgroup_proof.log` — the
  unprivileged ground truth (agent and the forked `sh → collect_helper.sh →
  curl` chain share the session cgroup; a long-lived outsider does not), no BPF
  required.
- `scripts/run_attack_p2.sh` — the full session attack, gated on attach-before-spawn.
