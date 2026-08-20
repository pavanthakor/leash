# Leash — Project Charter

Kernel-level behavioural containment for AI agents. Prompt-injection
succeeds at the language layer, where classifiers can be bypassed. Leash
enforces below the agent: eBPF LSM programs decide what the agent's
processes may *do* (which files they open, where they connect), and return
-EPERM when a task steps outside its policy. Language gets no vote.

Pitch: "A prompt firewall reads the attacker's sentence. Leash watches the
agent's hands."

## Non-negotiable invariants (hold in every phase)

1. **Real, never mocked.** No simulated data, no faked demo. Every claim is
   backed by something that actually ran and was observed. If it wasn't
   measured, it isn't true yet.
2. **Compiles != correct.** Every behavioural change ships with a positive
   control (the thing it should allow/detect) AND a negative control (the
   thing it must not). A test that only proves the happy path is a hole.
3. **The tool must be safe to install.** Leash's own attack surface is a
   first-class concern. Fail-open (if the daemon dies, enforcement
   vanishes, nothing is blocked). Removable (uninstall leaves nothing
   attached). Loopback-only APIs by default. No real credentials anywhere
   in the repo, ever — decoys only.
4. **No unattended privilege.** You may run build and test commands. You may
   NOT run sudo, edit GRUB, load BPF, or mount filesystems. Those are the
   operator's to run by hand and read the output. Ask before anything
   privileged or system-level.
5. **Small, reviewed, reversible steps.** Propose the plan before writing
   code. One logical change per commit. The operator reads each phase's
   files before moving on — write for that reader.

## Stack

- **Kernel side:** C + libbpf (clang -target bpf -> bpftool gen skeleton ->
  loader). NOT Rust/aya — its LLVM/bpf-linker version coupling was
  unworkable here. Same design: LSM hooks, maps, ring buffer, cgroup
  session tagging.
- **Agent side:** Python 3 + FastAPI, venv at ~/leash/.venv. Local Ollama
  (llama3.2:3b) on 127.0.0.1:11434.
- **Dashboard (later):** React.
- **Target kernel:** 7.0.0-30-generic, BPF LSM enabled.

## Repo layout

- bpf/        eBPF programs + C loader (Phase 0, present)
- agent/      vulnerable agent harness + attack library
- daemon/     policy compiler, ring-buffer reader, WebSocket server
- dashboard/  React UI
- policy/     YAML policies + schema
- scripts/    setup, uninstall, measurement
- docs/       design doc, phase notes

## Design anchors (why, so choices stay consistent)

- **Session attribution = cgroup.** Agent runs in a dedicated cgroup;
  bpf_get_current_cgroup_id() tags events; children inherit by kernel
  guarantee. Non-session processes exit the program immediately (perf +
  blast-radius).
- **File identity = (st_dev, st_ino)**, not path strings — survives
  symlinks and hardlinks. Report paths with bpf_d_path(&file->f_path, ...).
- **Egress = socket_connect** read after the kernel resolves the sockaddr;
  compare against an (ip, port) allowlist.
- **Why LSM not seccomp:** seccomp can't dereference user pointers, so it
  can't see the path in openat() or the destination in connect(). LSM hooks
  fire after the kernel has resolved them. That's the whole technical
  argument — don't undercut it.

## Roadmap (each phase has ONE exit criterion; do not advance without it)

- P0 Environment — BPF LSM prog attaches; negative control passes. [DONE]
- P1 Vulnerable agent — attack succeeds: decoy key POSTed to local listener.
- P2 Session attribution — full process tree printed from kernel events alone.
- P3 File enforcement — first real -EPERM; fail-open + teardown proven.
- P4 Egress enforcement — connect to attacker host fails; allowed host succeeds.
- P5 Policy layer — YAML parsed, validated, compiled; every bad input rejected.
- P6 Daemon + dashboard — attack legible on screen with no narration.
- P7 Attack library — 7 attacks; #7 deliberately succeeds (honest limits).
- P8 Measurement — hyperfine numbers in CSV; non-session processes unaffected.
- P9 Hardening + submission — uninstall tested; 3 clean cold demo runs.

## Working rhythm

Plan -> operator approves -> write -> operator runs & reads output ->
positive + negative control -> commit -> operator reads the files ->
next step. Commit messages state what was proven, not just what changed.
