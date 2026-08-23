# Event-stream fixtures

Frozen `leashd` event streams (JSON-lines) captured on real hardware against the
real eBPF LSM enforcers. Nothing here is synthesised — every line was emitted by
`daemon/leashd.py` parsing the loaders' stdout while they were attached to the
kernel (charter invariant 1).

They exist so the dashboard can be built and demoed without a privileged
attach. `leashd` truncates its live stream on every start, so these copies are
the record.

Source of truth for both: `~/leash-demo/leashd.events.jsonl`, copied at the end
of each run. Neither file contains key material (the decoy value never enters
the stream — denies carry `path`/`dev`/`ino`, not contents).

| file | lines | capture | cgid(s) |
|---|---|---|---|
| `session-full.jsonl`     | 172 | agent **restart** + cgid resync | 9066 → 9205 |
| `session-reattach.jsonl` | 128 | loader **unexpected death** + reattach | 7963 |

## session-full.jsonl — the primary fixture (restart capture)

Full policy vocabulary across an agent restart. Captured 2026-08-23.

Shape: `session_start` (seq 0) → `policy` → `discover` → `up` → both loaders
`spawn` + `attached` → full probe vocabulary under **cgid 9066** → agent
restarted via `scripts/launch_session.sh` → **`resync` on both layers,
9066 → 9205** (seq 91 file, seq 92 egress) → full probe vocabulary again under
**cgid 9205** → `session_end` (SIGINT, seq 167) → both layers `failopen`.

The restart used `launch_session.sh`, which tears the unit down and re-runs
`systemd-run` so systemd allocates a **new cgroup inode**. `systemctl --user
restart` reuses the inode, produces no cgid change, and is therefore a no-op
that cannot exercise resync — do not substitute it.

What the resync proves is not the log line but the enforcement: every
`deny`/`allow` before seq 91 is stamped `cgid 9066`, every one after is stamped
`cgid 9205`. Enforcement followed the session to its new cgroup with no human
action.

Contents: file denies on the protected inode (`dev=264241152 ino=920726`, 16);
egress denies to `:9000` in **both exfil shapes** — `comm=AnyIO worker th`
(agent `http_get`) and `comm=curl` (`run_shell` → curl), 10 total; `:11434`
allow `MATCH` (73); DNS `:53` denies (28); 2 × `resync`; 2 × `attached`.

## session-reattach.jsonl — unexpected-death capture

The complementary failure path: `down` → `failopen window=open` → loader
respawn → `reattach` → `failopen window=closed` → `session_end`. Single session,
**cgid 7963**, no restart and so no resync — which is exactly the gap
`session-full.jsonl` fills.

Post-reattach denies (first at **seq 87**, 12 in total, including the **seq 110**
deny to `127.0.0.1:9000`) are the load-bearing lines: enforcement is
genuinely re-established after the fail-open window, not merely re-announced.

**Known artifact:** the fail-open window reads as ~32 minutes. That is capture
time, not mechanism time — the run was paused mid-diagnosis with the loader
down. Real respawn is sub-second (`leashd` backoff starts at 0.5 s). The
ordering and the mechanism are correct; treat the window *duration* as
unrepresentative. A dashboard should not present it as a latency measurement.

**Second artifact (timestamps):** this file was captured before the stdout
buffering fix below, so its `attached` events are stamped at first-deny time
(+226 s egress, +237 s file) rather than at attach. Event *order* is correct —
the pipe flushes in order — only those timestamps are late. `session-full.jsonl`
is unaffected and shows true attach latency (+0.01 s / +0.02 s).

## Note: stdout buffering fix (2026-08-23)

Both loaders print their attach banner and then block in the ring-buffer poll
loop. Under `leashd` stdout is a pipe, so glibc fully buffers it (4 KB) and the
banner — only ~400 bytes — sat unflushed until the first kernel event forced a
flush. `attached` therefore could not be observed until something was already
denied, which makes "wait for attach, then probe" a deadlock.

Fixed by `setvbuf(stdout, NULL, _IOLBF, 0)` at the top of `main()` in
`bpf/leash_enforce.c` and `bpf/leash_connect.c` (I/O only, no logic change).
Attach is now observable at ~0.02 s.

Consequence for anything that waits on this stream: real attach latency is
~0.02 s, not the ~15 s folklore figure — that number was read off the
pre-fix `session-reattach.jsonl` and measured buffer flush, not attach. Poll for
the `attached` events; never fixed-sleep.
