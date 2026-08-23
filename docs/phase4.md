# Phase 4 — Egress enforcement (the second layer)

**Exit criterion:** an `lsm/socket_connect` program denies an in-session process
from connecting to a disallowed destination; `connect()` returns `-EPERM`; the
connection fails; nothing reaches the listener — for BOTH exfil shapes. Plus a
scoped + discriminating negative, and both fail-open paths, all on the kernel.

This closes the gap Phase 3 left open on purpose: Phase 3 blocks the file *read*,
but an emptied `curl` can still *connect* carrying nothing. Phase 4 kills that
connection too. Two independent layers, each provable alone.

## Policy model: allowlist (default-deny) — and why
The threat is prompt injection where the **attacker chooses the exfil
destination**. A blocklist can only stop destinations you already anticipated —
exactly what this threat denies you. An allowlist inverts the burden: the
attacker must land on a destination you *explicitly permitted for the task*,
which by construction excludes their sink. The cost (enumerate legitimate egress)
is small for a contained agent — here the legitimate set is exactly one:
Ollama `127.0.0.1:11434`. Demo allowlist = `{127.0.0.1:11434}`: every model call
passes; both exfil shapes to `:9000` are denied; and so would ANY other port the
attacker might pick — that is the whole point over a blocklist.

## Mechanism
- **Hook:** `lsm/socket_connect(sock, address, addrlen)`. `address` is the
  **kernel-resolved** sockaddr (the LSM-vs-seccomp argument: seccomp can't
  dereference it; the LSM hook fires after the kernel resolved it).
- **Session gate FIRST (P2/P3 verbatim):** `bpf_get_current_cgroup_id()` not in
  `sessions` -> `return 0`. Scoping and fail-open are consequences of this
  ordering, not separate logic.
- **Decision (default-deny):** read `(ip,port)`; if `(ip,port)` in
  `allowed_dests` -> allow; else `return -EPERM`.
- **Byte order (the P3-class trap):** `sin_addr.s_addr` and `sin_port` are
  NETWORK order. The IP is compared **raw** (network order) on both sides —
  `inet_pton()` yields the identical `__be32`, so nothing is converted and
  nothing can be gotten wrong. The port is normalised to **host** order on both
  sides (`bpf_ntohs` in kernel; the loader stores the integer directly).
- **Self-verifying debug:** one event per in-session AF_INET connect carries the
  `(ip,port)` the KERNEL read plus the verdict. The loader prints, for an allowed
  connect, `ALLOW ... -> 127.0.0.1:11434 (kernel-read) == allowlisted ... MATCH`,
  and for a denied one `DENIED ... -> 127.0.0.1:9000 (kernel-read) -> -EPERM`.
  The MATCH line proves the bytes/endianness are right on the running kernel.
- **Loader:** mirrors P3 — cgid re-sync follows systemd's relaunch churn; SIGUSR1
  permanently freezes + clears (fail-open 3a); kill/detach (fail-open 3b).

## KNOWN GAP — only AF_INET (IPv4) is enforced  ⚠️
`socket_connect` here inspects only `AF_INET`. **`AF_INET6` (IPv6) and `AF_UNIX`
destinations are NOT enforced — an in-session process connecting over IPv6 or a
unix socket is allowed through.** This demo's attack is IPv4 loopback
(`curl`/httpx to `127.0.0.1`), which cannot reach the gap, so the proofs are
sound for it. But a real deployment MUST also attach the `AF_INET6` path (and
consider `AF_UNIX`), or an attacker who targets an IPv6 destination walks out.
This is a disclosed limitation, not a silent one — an undisclosed bypass is worse.
(Also recorded in CLAUDE.md "Known limitations".)

## Files
- `bpf/leash_connect.bpf.c`, `bpf/leash_connect.c` (+ Makefile targets)
- `scripts/egress_precheck.sh` -> `~/leash-demo/egress_precheck.log` (no sudo)
- `scripts/egress_probe.sh` — proof driver (no sudo)

## How the operator runs the proofs
```
# Terminal A: session up
scripts/launch_session.sh                      # prints CGROUP, AGENTPID
# Terminal B (SUDO): attach, allow ONLY Ollama
cd bpf && make leash_connect
sudo ./leash_connect '<CGROUP>' 127.0.0.1:11434
   # prints: allow: 127.0.0.1:11434 ...; loader pid=<PID>
# Terminal C: proofs
scripts/egress_probe.sh
```
**Proof 1 (both shapes):** the in-session `http_get` to `:9000` returns a connect
error (`-EPERM`); then both attack reports run and the decoy key is **absent** from
`exfil.log` (http_get shape AND run_shell->curl shape). Terminal B logs
`DENIED socket_connect ... 127.0.0.1:9000 -> -EPERM` (comm `python` and `curl`).

**Proof 2b (policy discriminates — ordered/simultaneous):** the very http_get task
in proof 1 required the agent to reach Ollama `:11434` to answer — so window B
shows an `ALLOW ... 11434 -> MATCH` **and** a `DENIED ... 9000 -> -EPERM` for the
SAME process under the SAME live enforcer. That simultaneity is the proof it's a
policy, not a blanket block and not a dead enforcer.

**Proof 2a (scoped, ordered):** only after proof 1 confirms the deny is live, a
plain `curl 127.0.0.1:9000` from a non-session shell **succeeds** (reaches the
listener). Same dest, different cgroup -> allowed.

```
# Proof 3a (SUDO): map cleared -> fails open
sudo kill -USR1 <PID>;   scripts/egress_probe.sh --failopen
# re-attach in Terminal B (Ctrl-C, re-run attach -> pid=<PID2>), confirm deny live:
scripts/egress_probe.sh
# Proof 3b (SUDO): kill enforcer -> program detaches -> fails open
sudo kill -INT <PID2>;   scripts/egress_probe.sh --failopen
```

## Unprivileged evidence: `~/leash-demo/egress_precheck.log`
The allowlist byte representation (`ip_be=0x0100007f`, ports host-order), the
agent's actual egress (only `:11434`), the baseline that BOTH exfil shapes reach
the listener with no enforcer, and the compiled object's `socket_connect` prog +
`sessions`/`allowed_dests`/`denies` maps.
