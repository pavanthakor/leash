# Phase 3 — File enforcement (the first real -EPERM)

**Exit criterion:** an LSM `file_open` program denies the agent's read of the
protected decoy key; the Phase 1/2 exfil chain breaks at step one; and this is
demonstrated with a positive control, a scoped negative control, and BOTH
fail-open modes — all on the running kernel.

## Mechanism
- **Hook:** `lsm/file_open` (same hook P0 proved attachable). It fires once per
  `open()` after path resolution, for reads too; a negative return becomes the
  syscall's errno, so the fd is never created and the read cannot happen.
- **File identity = (st_dev, st_ino).** Inode identity, per the charter anchor —
  a symlink/hardlink to the key cannot dodge it. The loader stats the file at
  load and inserts `(dev,ino)`; `dev` is the kernel `dev_t` = `MKDEV(major,minor)`
  = `(major<<20)|minor` — the value BPF reads off `i_sb->s_dev` (252:0 → 264241152,
  confirmed live by the self-verifying debug line, not calculated on paper). Caveat: the file must exist at load; if it is deleted/recreated
  the enforcer must be reloaded (setup's `>` truncates in place, so the inode is
  stable across re-runs).
- **Session gate FIRST (Phase 2), then deny.** Order in `leash_enforce.bpf.c`:
  1) respect any earlier LSM deny; 2) `bpf_get_current_cgroup_id()` not in
  `sessions` → `return 0`; 3) `(dev,ino)` in `protected_files` → emit a deny
  event and `return -EPERM`; 4) else allow. The gate at step 2 delivers **both**
  scoping (a non-session process never reaches step 3) and fail-open (empty
  `sessions` → nobody in-session → nothing denied).
- **Path reporting is done in userspace, not `bpf_d_path`.** The deny only ever
  fires on a *known-protected* inode, so the loader resolves `(dev,ino)→path`
  from what it loaded. This is exact and avoids `bpf_d_path`'s LSM-hook allowlist
  risk (which can only be confirmed at load, i.e. with sudo). Path reporting for
  arbitrary files via `bpf_d_path` can return in a later phase, tested live.

## Session id is kept in sync (systemd churns the cgroup id)

systemd recreates `leash-agent.service`'s cgroup on every relaunch: the path is
reused but the kernel assigns a NEW id (observed: 7525 -> 8378 across a restart).
The loader therefore RE-SYNCS the `sessions` map to the live cgroup id (re-resolves
the path ~1/s and swaps the key on change), so enforcement follows a relaunch
instead of silently stranding on a dead id. `SIGUSR1` (proof 3a) sets a PERMANENT
freeze for that process: it clears the map and stops re-syncing for good, so a
simulated daemon-death never resurrects enforcement on a later tick -- re-enforcing
requires a fresh enforcer (that is exactly proof 3b's re-attach).

## Dev encoding (the bug that hid the first -EPERM)

`file_open` reads `file->f_inode->i_sb->s_dev`, a KERNEL `dev_t` =
`MKDEV(major,minor)` = `(major<<20)|minor`. The map MUST hold that same value.
An earlier version stored `new_encode_dev` (the userspace/`stat` form, 64512) and
the `(dev,ino)` lookup always missed -> the open was allowed and no `-EPERM` ever
fired. Fixed: the loader stores `(major<<20)|(minor&0xFFFFF)` = 264241152. To stop
this ever hiding again, the program emits a self-verifying DEBUG record with the
`(dev,ino)` the KERNEL actually read for in-session opens of the protected inode,
so `kernel-read dev == map-stored dev` is proven on the running kernel, not paper.

## Layered defence (why "key never reaches the listener", not "zero packets")
Blocking the *file read* stops the key at its source. In the forked attack the
helper's `TOKEN=$(cat key)` yields empty, so an emptied `curl` may still *connect*
to the listener — carrying no key. That residual connection is exactly what
**Phase 4 (egress)** stops, at `connect()`. Two layers, two different attacks:
Phase 3 denies the read; Phase 4 denies the connection. The security-meaningful
claim here is the strong one: **the decoy key never reaches the listener.**

## Files
- `bpf/leash_enforce.bpf.c`, `bpf/leash_enforce.c` (+ Makefile targets)
- `scripts/enforce_precheck.sh` → `~/leash-demo/enforce_precheck.log` (baseline, no sudo)
- `scripts/enforce_probe.sh` — proof driver (no sudo)

## How the operator runs the full sequence

```
# Terminal A (no sudo): session up (reuses Phase 2 launcher)
scripts/launch_session.sh                      # prints CGROUP, AGENTPID

# Terminal B (SUDO): attach the enforcer (leave it running; it streams denials)
cd bpf && make leash_enforce
sudo ./leash_enforce '<CGROUP>' ~/leash-demo/secrets/api_key.txt
   # prints: session cgid; protected (dev=264241152 ino=920726); loader pid=<PID>

# Terminal C (no sudo): PROOF 1 (in-session deny + key absent) THEN PROOF 2
scripts/enforce_probe.sh
```
**Proof 1 (positive):** Terminal B logs `DENIED file_open ... comm=... ino=920726 -> -EPERM`;
the probe's in-session `read_file` returns `PermissionError (EPERM)`; the forked
attack runs but the decoy key is **absent** from `exfil.log`. Contrast the
baseline in `enforce_precheck.log`, where the key reached the listener.

**Proof 2 (negative, scoped — ordered):** the probe only reaches proof 2 *after*
proof 1 confirms the deny is live in this same enforcer session; it then runs a
plain `cat` of the SAME file from a non-session shell, which **succeeds**. Same
file, different cgroup → allowed. Leash didn't break the file for the box.

Each fail-open proof starts from a *confirmed-enforcing* state (proof 1 above
established that). Because 3a empties the map, re-attach before 3b so 3b is
demonstrated fresh.

```
# PROOF 3a (SUDO): session state lost -> fail open via the map-empty path
sudo kill -USR1 <PID>                # enforcer clears its sessions map (still attached)
scripts/enforce_probe.sh --failopen  # in-session read now SUCCEEDS -> fails open

# re-establish enforcement so 3b starts from a denying state
#   Terminal B: Ctrl-C the enforcer, then re-run the same attach command; it prints a new pid=<PID2>
scripts/enforce_probe.sh             # confirm proof 1 denies again (deny is live)

# PROOF 3b (SUDO): daemon death -> fail open via the no-program path
sudo kill -INT <PID2>                # kills the enforcer; the BPF program detaches, hook gone
scripts/enforce_probe.sh --failopen  # in-session read SUCCEEDS again -> fails open
```
**3a** proves losing session state unblocks (map-empty path, program still loaded).
**3b** proves killing the whole enforcer unblocks (program detaches — the "what if
the entire daemon crashes, not just the map" case). Both are real daemon-death
scenarios; a tool that failed *closed* would deny everything when it crashes —
Leash fails **open** in both. (Invariant 3, non-negotiable.)

## Unprivileged evidence: `~/leash-demo/enforce_precheck.log`
Records the exact protected identity `(dev=264241152, ino=920726)`, the baseline that
the in-session agent currently CAN read the key and the forked attack DOES deliver
it (the "before" proof 1 breaks), and that the compiled object carries the
`file_open` prog + `sessions`/`protected_files`/`denies` maps.
