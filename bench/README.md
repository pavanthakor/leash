# bench/ — Phase 8 measurement

Per-syscall latency of leash's two LSM hooks, and proof the overhead is scoped
to the leashed session. Full method, numbers, and caveats in
[`../docs/phase8.md`](../docs/phase8.md). Unprivileged; measures only.

## Reproduce

```bash
cd ~/leash/bench && make

# (a) in-session + (b) out-of-session, against a LIVE leashd session:
./run_bench.sh live

# (c) no-program floor, with leashd torn DOWN:
./run_bench.sh floor

# distribution + paired enforcement/host-tax deltas (reads results/*.csv.gz):
python3 aggregate.py
```

`run_bench.sh live` drives the in-session case through the agent's `/run`
(the only path into the session cgroup) and voids any trial that did not emit
~N `KIND_ALLOW` events at the session cgid — the in-session witness.

## Headline (this kernel/hardware, loopback, warm caches)

- **file_open enforcement (in-session):** ~299 ns/open, consistent
- **file_open host-wide tax (leash merely loaded):** ~19 ns/open, ~2 % of a 1 µs open
- **socket_connect enforcement:** ~2 µs point estimate, at the noise floor
- **socket_connect host-wide tax:** below measurement resolution (~1 µs)

Scoped to the leashed session; the rest of the host pays a tax we can barely
measure.
