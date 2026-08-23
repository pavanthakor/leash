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

## What is proven, on real hardware

Every claim here was measured and observed on this machine (kernel
7.0.0-30-generic, BPF LSM enabled) — never simulated. See the per-phase notes in
`docs/`.

- **Session attribution = cgroup.** The agent runs in a dedicated cgroup;
  `bpf_get_current_cgroup_id()` tags every event; children inherit it by kernel
  guarantee, so a forked `curl` is caught with no cooperation. Non-session
  processes hit an early return.
- **File containment** (`lsm/file_open`): an in-session open of the protected
  file returns `-EPERM`. Identity is `(st_dev, st_ino)`, not the path — a
  hardlink alias under a name the policy never mentions is still blocked
  (Phase 7 #2).
- **Egress containment** (`lsm/socket_connect`): default-deny allowlist; the two
  exfil shapes (in-process httpx, forked `sh`→`curl`) are denied, Ollama
  `127.0.0.1:11434` is permitted, and the deny is session-scoped.
- **Fail-open, honest** (charter invariant 3): if leashd dies the loaders die
  with it (`PR_SET_PDEATHSIG`) and enforcement vanishes — nothing is blocked.
  Captured and rendered as an explicit window, never hidden.
- **Restart-survival:** an agent restart churns the cgroup id; the loaders
  re-sync and enforcement follows the new session — proven by post-resync denies
  stamped with the new cgid (`fixtures/session-full.jsonl`).
- **7-attack taxonomy** (Phase 7): six exfil shapes contained; **#7 deliberately
  succeeds** through a *disclosed* limit (`socket_connect` inspects only
  `AF_INET`; IPv6 / AF_UNIX pass). Honest limits, stated not unshown.
- **Overhead, measured** (Phase 8): enforcement adds ~**0.3 µs** to an in-session
  `open()` and low-single-digit µs to a `connect()`, and it is **scoped to the
  leashed session** — an out-of-session process pays ~**19 ns/open** and a
  connect tax below measurement resolution. The rest of the host pays a tax we
  can barely detect.

## Quick start — three commands

Prerequisites: a BPF-LSM kernel, the Python venv (`~/leash/.venv`), local Ollama
(`llama3.2:3b` on `127.0.0.1:11434`), and Node LTS for the dashboard (via nvm).

```bash
scripts/up.sh            # agent + dashboard + attach leashd  (root ONCE, here)
#                          open http://127.0.0.1:8765
scripts/demo.sh          # fire the 7 attack shapes, paced, onto the dashboard
scripts/down.sh          # tear down and PROVE the kernel is clean (bpftool)
```

`up.sh` is the one conscious privileged grant — launching a kernel enforcer is a
deliberate act, so there is no auto-attach on boot. `down.sh` reuses that same
credential. `scripts/uninstall.sh` leaves the machine as leash found it (nothing
attached, generated artifacts removed, source intact). Full walkthrough and
troubleshooting: [`docs/runbook.md`](docs/runbook.md).

## The demo, in one screen

`up.sh` → open the dashboard → `demo.sh`. Denials stream in live: the file read
and both egress shapes stopped at the kernel, the causal chain forming with real
seq numbers, the injection drawn as an explicit *unevidenced* node ("not observed
by leash, by design"), and #7 landing as an honest **NOT CONTAINED**. The
console folds the permitted Ollama chatter by default so the `-EPERM` denials
stand out; one toggle reveals it.

## Repo layout

| dir | what | status |
|-----|------|--------|
| `bpf/` | eBPF LSM programs (file_open, socket_connect) + C loaders | sealed since P4 |
| `daemon/` | leashd supervisor + policy compiler (`policc`) | sealed |
| `policy/` | the YAML policy (protect-list + egress allowlist) | sealed |
| `agent/` | the vulnerable agent harness + attack library | |
| `attacks/` | Phase 7 taxonomy: 7 shapes, harness, gap sink | |
| `bench/` | Phase 8 microbenchmark + raw data + summary | |
| `dashboard/` | read-only React console + SSE bridge | |
| `fixtures/` | frozen real event captures (restart, unexpected-death) | |
| `scripts/` | lifecycle (`up`/`demo`/`down`/`uninstall`) + proof drivers | |
| `docs/` | per-phase notes, runbook, slide outline | |

## The non-negotiable invariants

1. **Real, never mocked.** If it wasn't measured, it isn't true yet.
2. **Compiles ≠ correct.** Every change ships a positive *and* a negative control.
3. **Safe to install.** Fail-open, removable, loopback-only, decoys only — no real
   credentials in the repo, ever.
4. **No unattended privilege.** sudo is the operator's to run and read.
5. **Small, reviewed, reversible steps.** One logical change per commit.

## Phase index

P0 environment · P1 vulnerable agent · P2 session attribution · P3 file
enforcement · P4 egress enforcement · P5 policy layer · P6a leashd · P6b
dashboard · P7 attack library · P8 measurement · P9 hardening + packaging.
Per-phase evidence in `docs/phase*.md`.

## Disclosed limitations (owned, not hidden)

- **Egress enforces only `AF_INET` (IPv4).** `AF_INET6` and `AF_UNIX` pass
  unhooked — Phase 7 #7 demonstrates it, the dashboard sidebar labels the scope,
  and a real deployment must attach the IPv6 path. An undisclosed bypass is worse
  than a disclosed one.
