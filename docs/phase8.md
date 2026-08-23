# Phase 8 — Measurement

**Exit criterion:** measure leash's real enforcement overhead and prove it is
negligible AND scoped to the leashed session — so the Scalability claim
("enforcement adds negligible per-syscall latency, and only inside the leashed
session; the rest of the host pays nothing") rests on measured numbers, not
assertion.

`bpf/`, `daemon/`, `policy/`, `attacks/` are sealed — this phase only measures.
Every number below is a real syscall latency from this machine; the method and
the raw samples are committed (`bench/results/raw_*.csv.gz`), and the
distribution is reported rather than one cherry-picked figure.

## Method

**A tight C microbenchmark, not hyperfine.** hyperfine times whole commands, so
process spawn (~ms) would swamp a ~µs syscall. `bench/microbench.c` runs N
syscalls in one warm, CPU-pinned process, timing each call individually with
`clock_gettime(CLOCK_MONOTONIC)` (vDSO, ~20 ns — a common-mode bias that cancels
in every delta). Raw per-sample latencies are written out so the distribution is
the product.

Both hooks are measured on their **ALLOW path** — the cost every syscall pays,
not the rare deny path (a deny returns `-EPERM`, a different and less-travelled
branch):

- **`file_open`**: `open()` of a **non-protected**, cache-warm file
  (`docs/report_clean.txt`), `close()` untimed. Read of the hook confirms a
  non-protected in-session open takes the full check (cgid hit → read
  `(dev,ino)` → two map misses → allow) and emits **nothing**.
- **`socket_connect`**: `connect()` to the allowlisted `127.0.0.1:11434` on a
  **non-blocking** socket. `security_socket_connect` fires at the start of
  `connect()`, before the handshake, regardless of `O_NONBLOCK`; a non-blocking
  socket returns `EINPROGRESS` right after the hook, so the timed region is
  `[syscall + hook]`, not the loopback TCP round-trip. Note: **every in-session
  connect emits a `KIND_ALLOW` ringbuf event**, so this path's cost legitimately
  includes `ringbuf_reserve/submit` — and, during the in-session run, `leashd`
  is concurrently draining thousands of those events. That contention is the
  source of this hook's higher variance (below).

### Three conditions, and the LSM insight that frames them

LSM BPF hooks are **global** — `file_open` / `socket_connect` fire for *every*
such syscall on the host once leash is loaded; the program then reads the cgroup
id and returns early if it is not the leashed session. So:

| | how | isolates |
|---|---|---|
| (a) in-session | bench runs as a **child of the agent** (via `/run` → `run_shell`), inheriting cgid 11451 | the full enforcement check |
| (b) out-of-session | same binary from an ordinary shell (`session-15.scope`) | the hook's early-return gate — what *other* processes hit |
| (c) no program | same binary, **leashd torn down** | the absolute syscall floor |

Getting into the session is only possible as a descendant of the agent — moving
a process into cgid 11451 directly is denied by cgroup-v2 delegation (verified).
This is the same attribution path the Phase 7 attacks used.

- **(a) − (b)** = the **enforcement cost**, and the fact that (b) is cheap is the
  proof it is *scoped to the session*.
- **(b) − (c)** = the **host-wide tax** of merely having leash loaded — every
  process on the box pays the global hook's gate. This, not (b) alone, is the
  "rest of the host pays nothing" claim, because (b) already includes that tax.

**Validity check (real, not asserted):** each in-session trial had to emit ~N
`KIND_ALLOW` events at **cgid 11451** or the run was void — proving the bench
truly ran in-session. All five trials showed 5502 (5000 bench + ~500 the agent's
own model calls).

**Design:** 5 trials per condition, in/out **interleaved** so slow drift
(thermal, frequency) hits both and cancels in the paired delta. N = 100 000 for
`file_open`, 5 000 for `connect` (kept modest because it emits). This kernel
(7.0.0-30-generic), this hardware, loopback, warm caches, one pinned CPU.

## Results

Median-of-per-run-medians, with run-to-run spread (the measurement resolution):

| hook | condition | median | run-spread | p90 | p99 |
|------|-----------|-------:|-----------:|----:|----:|
| `file_open` open() | (a) in-session | 1307 ns | 295 ns | 1480 ns | 1696 ns |
| `file_open` open() | (b) out-of-session | 1011 ns | 26 ns | 1066 ns | 1480 ns |
| `file_open` open() | (c) no-program | 992 ns | 18 ns | 1052 ns | 1474 ns |
| `socket_connect` connect() | (a) in-session | 8753 ns | 3818 ns | 17016 ns | 104888 ns |
| `socket_connect` connect() | (b) out-of-session | 6656 ns | 584 ns | 10392 ns | 41441 ns |
| `socket_connect` connect() | (c) no-program | 6845 ns | 1100 ns | 9673 ns | 27682 ns |

Raw: `bench/results/raw_<hook>_<cond>_run<k>.csv.gz`. Reproduce with
`python3 bench/aggregate.py`.

### The deltas — paired per trial (the interleaving's payoff)

Pairing in-vs-out within each trial cancels per-trial drift and is stronger than
comparing pooled medians:

| delta | per-trial (ns) | reading |
|-------|----------------|---------|
| `file_open` (a)−(b) enforcement | `104, 102, 366, 299, 382` | **~299 ns/syscall, positive in all 5 trials** — a clean, consistent signal |
| `file_open` (b)−(c) host tax | `19, 19, 29, 17, 17` | **~19 ns/syscall, positive in all 5** — tiny but real |
| `socket_connect` (a)−(b) enforcement | `2529, −135, 3774, 2817, 255` | ~2 µs median but **not consistently positive** — at/near the noise floor |
| `socket_connect` (b)−(c) host tax | `58, 475, −610, −383, −37` | mixed signs → **below resolution (~1 µs)**, not measurable |

## What the numbers say

**Enforcement cost (scoped to the leashed session), condition (a) − (b):**

- **`file_open`: ~299 ns per open()** — consistent across all five trials. This
  is the hook's real work: read the file's `(dev,ino)` and two map lookups. Sub-
  microsecond, ~30 % on top of a ~1 µs open, and **only** in-session.
- **`socket_connect`: a ~2 µs point estimate, but at the run-to-run noise floor**
  (one of five trials was negative). The `KIND_ALLOW` emit on every connect, plus
  `leashd` draining those events concurrently, dominates the variance. Honest
  bound: **low single-digit microseconds, not precisely resolvable** here.

**Host-wide tax of having leash loaded, condition (b) − (c) — the Scalability
claim:**

- **`file_open`: ~19 ns per open()** — consistent across all five trials, so
  real, but ~2 % of a 1 µs open: for practical purposes negligible. This is the
  cost the *entire host* pays per open for the global LSM hook to fire, read the
  cgroup id, miss the `sessions` map, and return.
- **`socket_connect`: below our measurement resolution (~1 µs)** — the per-trial
  tax has mixed signs, so **the host-wide connect tax is not measurable at this
  N and hardware.** Stated as a bound, not a fake-precise zero.

**Grounded Scalability claim:** enforcement adds a **sub-microsecond, consistent
~0.3 µs to an in-session `open()`** and **low single-digit µs to an in-session
`connect()`** — and it is **scoped to the leashed session**: an out-of-session
process pays only the global hook's gate, measured at **~19 ns per open() and
below ~1 µs per connect()** — i.e. at or below our measurement resolution. The
rest of the host pays a tax we can barely detect.

## Honest caveats

- **The connect enforcement delta is noise-limited here.** The point estimate
  (~2 µs) is plausible but the emit + daemon-drain variance means we do not claim
  it to sub-µs precision. `file_open` (quiet allow path) is the clean number.
- **Loopback, warm caches, one pinned CPU, this kernel/hardware.** These are
  best-case-for-low-latency conditions; absolute numbers will differ elsewhere.
  The *deltas* — the enforcement cost — are what generalise, and they are small.
- **`clock_gettime` adds ~20 ns per sample**, present in every condition, so it
  cancels in the deltas but slightly inflates all absolute medians.
- **We do not claim "zero."** We measured ~299 ns (file enforcement), ~19 ns
  (file host-tax), ~2 µs (connect enforcement, noise-limited), and
  connect host-tax below resolution — and report exactly those.

## Files

- `bench/microbench.c`, `bench/Makefile` — the C microbenchmark
- `bench/run_bench.sh` — orchestrator (`live` = a+b; `floor` = c); unprivileged
- `bench/aggregate.py` — raw → `summary.csv` + paired deltas (reads the .gz)
- `bench/results/` — `summary.csv` + `raw_*.csv.gz` (all 30 raw sample sets)
