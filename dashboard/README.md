# Phase 6b — containment console

A read-only React console over `leashd`'s event stream. It makes the containment
story legible: what the agent tried, what the kernel refused, and whether
enforcement is in effect *right now*.

**It is strictly downstream.** The bridge opens the JSON-lines stream with mode
`"r"` and never writes it, never signals `leashd`, never touches a BPF map or a
loader. Killing the console changes nothing about enforcement. Nothing here runs
privileged; the HTTP server binds `127.0.0.1` only.

Every number on screen comes from the stream. There is no seeded state, no demo
mode, and no placeholder — if the stream does not say it, the console renders
`—`.

## Run it live

```bash
# 1. Node (no system install; nvm lives in ~/.nvm)
export NVM_DIR="$HOME/.nvm" && . "$NVM_DIR/nvm.sh"
nvm use --lts

# 2. build
cd ~/leash/dashboard
npm install
npm run build

# 3. bridge (unprivileged; reads ~/leash-demo/leashd.events.jsonl)
python3 bridge/leash_bridge.py
#    -> http://127.0.0.1:8765

# 4. open http://127.0.0.1:8765 and drive a probe in another shell
~/leash/scripts/enforce_probe.sh
~/leash/scripts/egress_probe.sh
```

`leashd` itself is started by the operator under `sudo`, as always — the console
neither starts nor needs it. With no `leashd` running you get the empty state,
which names which of the two things is missing rather than inventing events.

Point it at a frozen capture instead of the live stream to demo without a
privileged attach:

```bash
python3 bridge/leash_bridge.py --events ../fixtures/session-full.jsonl
```

## Tests

```bash
npm run test:all      # 35 node tests + 12 bridge tests
```

Both suites run against the two **real** captures in `../fixtures` — referenced,
not copied, so they cannot drift from the canonical files. No event in any test
is hand-written (charter invariant 1), and each behaviour carries a positive and
a negative control (invariant 2).

| suite | covers |
|---|---|
| `tests/chains.test.mjs` | the chain builder: exact chains for both captures, resync stitching, fail-open barriers, gate arithmetic, purity |
| `tests/posture.test.mjs` | status-bar and sidebar values, verdict mapping, empty stream |
| `tests/render.test.mjs` | the components actually put the real numbers on screen (SSR) |
| `bridge/test_bridge.py` | tailing, partial lines, and session-reset detection |

## What it shows

- **status bar** — `leashd` pid and uptime, one dot per enforcer: green attached,
  red while a fail-open window is open, grey before any attach is observed.
- **session panel** — live cgid (and the cgid it re-synced from), unit, the
  protected inode's `dev`/`ino` **as the kernel reported them**, the policy
  protect-list and egress allow-list, and deny/allow/resync counts.
- **containment chain** — the most recent multi-layer chain, falling back to the
  most recent chain. Real seq numbers and Δt on every step.
- **event log** — columnar `seq · hook · verdict · comm·pid · target · cgid`,
  thin left-border severity accents, verdicts as `EPERM` / `ALLOW` / `RESYNC` /
  `FAILOPEN` / `DOWN` / `REATTACH` / `ATTACHED`.
- **fail-open banner** — loud, and *only* while a window is genuinely open.

## Three claims the console refuses to make

These are deliberate, and the tests enforce them.

1. **No policy hash.** The mockup carried a `policy sha 4a9c1f` field. `leashd`
   emits no hash of any kind, so rendering one would fabricate an integrity
   guarantee. Only the real `v1` from the `policy` event is shown.
2. **The injection is drawn as unevidenced.** Leash watches the agent's hands,
   not the attacker's sentence — the prompt injection is not in this stream and
   never will be. It appears as a dashed node labelled *"not observed by leash,
   by design"*, because silently omitting it would let a reader assume Leash saw
   the whole attack.
3. **The terminal node does not say "the secret never left".** What the stream
   proves is narrower: *no successful read of the protected inode; no egress to
   a non-allowlisted destination*. `AF_INET6` and `AF_UNIX` are unenforced
   (disclosed Phase 4 gap), so an unobserved path is possible. The chain also
   carries a footnote that its steps are correlated by session and adjacency,
   **not proven causally linked**.

## Chain builder

`src/lib/chains.js` is pure — no I/O, no DOM, no clock — and is the piece under
the heaviest test. Validated against both captures:

```
1. cgids joined by a resync are unioned into one LOGICAL AGENT (lifecycle
   continuity across an agent restart).
2. walk seq order over deny + resync + down/failopen/reattach.
3. a deny OPENS a chain; a later deny is ABSORBED iff same logical agent
   AND dseq <= 8 AND dt <= 2.0s, measured from the last absorbed DENY.
4. resync / down / failopen / reattach are BARRIERS -- they close the chain
   and become their own lifecycle node.
5. consecutive identical denies collapse to one step with a count (DNS
   arrives as 4 denies at dt 0.00).
6. promoted to a chain only if >= 2 collapsed steps or any step count > 1;
   a lone deny is a row in the log, not a chain.
```

Three things it deliberately does **not** do, each because the real data showed
the alternative was wrong:

- **Chains are denies only.** An earlier draft absorbed `allow` events too, and
  every chain then ended `EPERM → ALLOW 127.0.0.1:11434` — which reads as
  "blocked, then let out". That allow is the next, unrelated model call ~10 ms
  later. Allows are context in the log, never a chain step.
- **Chains never span a resync.** The barrier is explicit, not a side effect of
  the Δ gates. The pre-restart `cat`+`curl` attack (seq 29–30 @ 9066) and the
  post-restart one (seq 101–102 @ 9205) render as two chains under two cgids —
  that *is* the restart-survival story.
- **Chains are labelled with the event's cgid**, not the union-find root, which
  would mislabel every post-resync chain as 9066.

## Session-reset detection

`leashd` truncates its stream on every start, so the console must never splice
two sessions. Detection needs three conditions, not the two that seem obvious:

```
reset  <=>  st_ino changed                      (a different file)
        OR  st_size < bytes already consumed    (truncated shorter)
        OR  line 1 differs from the line 1 we started from
```

The third is load-bearing. `leashd` calls `open(path, "w")`, which truncates
**in place**, so the inode is routinely reused; and if the new session is
*longer* than what was already consumed, the size test does not fire either.
Replaying the two real captures in that order — reattach (37,891 B) then full
(54,859 B), same inode — reproduces it: without the content anchor the tailer
resumes mid-file and merges two sessions into one stream. Covered by
`test_bridge.py::test_reset_on_truncate_in_place_same_inode`.

The client re-checks independently: a `session_start` at seq 0 inside any batch
clears the view. Whichever notices first, the console never splices.
