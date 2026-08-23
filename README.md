# Leash — kernel-level behavioural containment for AI agents

> A prompt firewall reads the attacker's sentence. **Leash watches the agent's hands.**

Prompt injection succeeds at the language layer, where classifiers can be talked
around. Leash enforces *below* the agent: eBPF LSM programs decide what the
agent's processes may **do** — which files they open, where they connect — and
return `-EPERM` when a task steps outside its policy. Language gets no vote.

The decision is made on the kernel's own resolved arguments (the inode behind an
`open`, the address behind a `connect`), after the kernel has resolved them and
regardless of how the agent was talked into the syscall. Injection can change
what the agent *tries*; it cannot change what the kernel *permits*.

## The problem

A hijacked agent leaks a secret in two structurally different ways: its own
process makes the network call (in-process httpx), or it shells out and a child
does (`sh`→`curl`). A language-layer classifier reads the poisoned prompt and
can be talked past it. Leash never reads the prompt; it watches the syscalls the
agent's process tree actually makes.

## The approach

- **Session attribution = cgroup.** The agent runs in a dedicated cgroup;
  `bpf_get_current_cgroup_id()` tags every event; children inherit it by kernel
  guarantee, so a forked `curl` is in-session with no cooperation. Non-session
  processes hit an early return in the hook.
- **Two LSM hooks.** `lsm/file_open` compares the opened file's `(st_dev,
  st_ino)` against a protect-list; `lsm/socket_connect` compares the
  kernel-resolved destination against an egress allowlist. Outside policy →
  `-EPERM`.
- **Why LSM, not seccomp.** seccomp can't dereference user pointers, so it can't
  see the path in `openat()` or the destination in `connect()`. LSM hooks fire
  *after* the kernel resolved them. That's the whole technical argument.
- **leashd** supervises the two proven loaders as sealed subprocesses,
  multiplexes their output into one JSON-lines event stream, and ties their
  lives to its own (`PR_SET_PDEATHSIG`) so enforcement fails open if the daemon
  dies. Architecture: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## What's proven → where to verify it

Every row is a real observation on this machine (kernel 7.0.0-30-generic, BPF
LSM enabled), never simulated. Numbers are quoted as measured — not rounded to a
headline, not called "negligible".

| claim | the real number / fact | verify in |
|-------|------------------------|-----------|
| session attribution follows the fork | a forked `curl` is denied under the **session cgid**, no cooperation | [`docs/phase2.md`](docs/phase2.md) |
| file read of the protected key is blocked | in-session open of `dev=264241152 ino=920726` → `-EPERM` (first deny **seq 24**) | [`docs/phase3.md`](docs/phase3.md); [`fixtures/session-full.jsonl`](fixtures/session-full.jsonl) |
| identity is the inode, not the path | a hardlink alias (a name the policy never lists) is blocked on `(dev,ino)`; the alias shows `links=2`, same inode | [`docs/phase7.md`](docs/phase7.md) (#2) |
| egress default-deny, both exfil shapes | in-process httpx and forked `curl` to `:9000` denied; `:11434` (Ollama) allowed; deny is session-scoped | [`docs/phase4.md`](docs/phase4.md); [`docs/phase7.md`](docs/phase7.md) (#3, #4) |
| fail-open on daemon death | loaders carry `PR_SET_PDEATHSIG`; the down→failopen→reattach window is captured explicitly | [`docs/phase6a.md`](docs/phase6a.md); [`fixtures/session-reattach.jsonl`](fixtures/session-reattach.jsonl) |
| enforcement survives an agent restart | resync **9066→9205** at **seq 91**; every post-resync deny is stamped with the new cgid | [`fixtures/session-full.jsonl`](fixtures/session-full.jsonl); [`docs/phase6a.md`](docs/phase6a.md) |
| six shapes contained, #7 is a disclosed gap | 6 of 7 contained; #7 (IPv6 / AF_UNIX) **NOT CONTAINED** — `socket_connect` inspects only `AF_INET` | [`docs/phase7.md`](docs/phase7.md); reproduce with `attacks/harness.py` |
| file-enforcement overhead (in-session) | **~299 ns/open**, positive in all 5 paired trials | [`bench/results/summary.csv`](bench/results/summary.csv); [`docs/phase8.md`](docs/phase8.md) |
| host-wide tax of merely loading leash | **~19 ns/open** (out-of-session vs no-program), consistent across 5 trials | [`bench/results/summary.csv`](bench/results/summary.csv); [`docs/phase8.md`](docs/phase8.md) |
| connect-enforcement overhead | **~2 µs point estimate, noise-limited** — the emit + daemon-drain variance means it is not cleanly resolvable; connect host-tax is below measurement resolution | [`docs/phase8.md`](docs/phase8.md) |

## Quick start — three commands

Prerequisites: a BPF-LSM kernel, the Python venv (`~/leash/.venv`), local Ollama
(`llama3.2:3b` on `127.0.0.1:11434`), Node LTS for the dashboard (via nvm), and
the loaders built (`cd bpf && make`).

```bash
scripts/up.sh            # agent + dashboard + attach leashd   (root ONCE, here)
#                          then open http://127.0.0.1:8765
scripts/demo.sh          # fire the 7 attack shapes, paced, onto the dashboard
scripts/down.sh          # tear down and PROVE the kernel is clean (bpftool)
```

`up.sh` is the one conscious privileged grant — attaching a kernel enforcer is a
deliberate act, so there is no auto-attach on boot; `down.sh` reuses that same
cached credential. `scripts/uninstall.sh` leaves the machine as leash found it.
Full walkthrough and troubleshooting: [`docs/runbook.md`](docs/runbook.md).

On the dashboard you'll see: the file read and both egress shapes stopped at the
kernel, the causal chain forming with real seq numbers, the injection drawn as
an explicit *unevidenced* node ("not observed by leash, by design"), and #7
landing as an honest **NOT CONTAINED**. The console folds the permitted Ollama
chatter by default so the `-EPERM` denials stand out; one toggle reveals it.

## Reproduce it yourself

From a state with nothing up, run the full cycle three times:

```bash
scripts/up.sh            # ends at "leash is UP", both enforcers attached
#   open http://127.0.0.1:8765
scripts/demo.sh          # denials stream live; #7 shows NOT CONTAINED
scripts/down.sh          # ends at "VERIFIED CLEAN"
```

Three consecutive clean cold runs is the packaging bar. To confirm the kernel is
clean yourself:

```bash
sudo bpftool prog show | grep -E 'leash_enforce|leash_connect'   # empty == clean
```

Match leash's **own program names** (`leash_enforce`, `leash_connect`). Do **not**
use `grep -i lsm`: Ubuntu ships a resident `restrict_filesystems` LSM program
that is not leash and will look like a leftover. The overhead numbers reproduce
with `python3 bench/aggregate.py` (reads the committed raw samples); the attack
outcomes with `python3 attacks/harness.py` against a live session.

## Repo layout

| dir | what | status |
|-----|------|--------|
| `bpf/` | eBPF LSM programs (`file_open`, `socket_connect`) + C loaders | **sealed** since P4 |
| `daemon/` | leashd supervisor + policy compiler (`policc`) | **sealed** |
| `policy/` | the YAML policy (protect-list + egress allowlist) | **sealed** |
| `agent/` | the vulnerable agent harness + attack library | |
| `attacks/` | Phase 7 taxonomy: 7 shapes, harness, gap sink | |
| `bench/` | Phase 8 microbenchmark + raw data + summary | |
| `dashboard/` | read-only React console + SSE bridge | |
| `fixtures/` | frozen real event captures (restart, unexpected-death) | |
| `scripts/` | lifecycle (`up`/`demo`/`down`/`uninstall`) + proof drivers | |
| `docs/` | per-phase notes, architecture, runbook, slide outline | |

## Honest limitations (owned, up front)

- **Egress enforces only `AF_INET` (IPv4).** `AF_INET6` and `AF_UNIX`
  destinations pass unhooked — Phase 7 #7 demonstrates it live, the dashboard
  sidebar labels the scope, and a real deployment must attach the IPv6 path (and
  decide a policy for unix sockets). An undisclosed bypass is worse than a
  disclosed one.
- **The demo attack is IPv4 loopback.** The proofs are sound for it precisely
  because it cannot reach the AF_INET gap above; they do not claim coverage of
  traffic the demo never exercises.
- **Single host.** Everything is one machine, loopback only (charter invariant
  3). There is no distributed or multi-host story here, and none is claimed.
- **The injection itself is never observed.** Leash watches the agent's hands,
  not the attacker's sentence — the prompt injection is by design outside what
  the event stream sees, and the dashboard draws it as an explicit unevidenced
  node rather than implying Leash detected it.
- **Overhead is measured, not "zero".** ~299 ns/open in-session, ~19 ns/open
  host-wide; the connect path is noise-limited (see the table). Loopback, warm
  caches, one pinned CPU, this kernel/hardware — the deltas generalise, the
  absolute numbers are best-case-for-low-latency.

## License

Userspace code (agent, daemon, dashboard, scripts, benchmarks, docs) is **MIT**
— see [`LICENSE`](LICENSE). The eBPF programs in `bpf/` are **GPL**, because the
kernel requires it: an LSM BPF program must declare a GPL-compatible license tag
(`char LICENSE[] SEC("license") = "GPL";`) to call the helpers it uses. MIT
covers the userspace; GPL covers the in-kernel BPF — stated plainly so MIT is
never read as making the BPF permissive when the kernel forces GPL.

## Phase index

Each phase has one exit criterion and is documented where it was actually built.

| phase | what | documented in |
|-------|------|---------------|
| P0 | environment — BPF LSM attaches, negative control passes | commit `4cd19eb` |
| P1 | vulnerable agent — decoy key exfiltrated to the listener | commit `d5d23f7`; [`agent/README.md`](agent/README.md) |
| P2 | session attribution — process tree from kernel events alone | [`docs/phase2.md`](docs/phase2.md) |
| P3 | file enforcement — first real `-EPERM`; fail-open proven | [`docs/phase3.md`](docs/phase3.md) |
| P4 | egress enforcement — attacker host fails, allowed host succeeds | [`docs/phase4.md`](docs/phase4.md) |
| P5 | policy layer — YAML validated/compiled; every bad input rejected | [`docs/phase5.md`](docs/phase5.md) |
| P6a | leashd — supervises the sealed loaders, one event stream | [`docs/phase6a.md`](docs/phase6a.md) |
| P6b | dashboard — read-only console + SSE bridge | [`dashboard/README.md`](dashboard/README.md) |
| P7 | attack library — 7 shapes; #7 deliberately succeeds (honest limit) | [`docs/phase7.md`](docs/phase7.md); [`attacks/README.md`](attacks/README.md) |
| P8 | measurement — per-syscall overhead, scoped to the session | [`docs/phase8.md`](docs/phase8.md); [`bench/README.md`](bench/README.md) |
| P9 | hardening + packaging — one-command lifecycle, kernel-clean uninstall | [`docs/runbook.md`](docs/runbook.md); `scripts/` |

## The non-negotiable invariants

1. **Real, never mocked.** If it wasn't measured, it isn't true yet.
2. **Compiles ≠ correct.** Every change ships a positive *and* a negative control.
3. **Safe to install.** Fail-open, removable, loopback-only, decoys only — no real
   credentials in the repo, ever.
4. **No unattended privilege.** sudo is the operator's to run and read.
5. **Small, reviewed, reversible steps.** One logical change per commit.
