# Slide + story outline (for the PPT and demo video)

You build the deck and record the video; this is the arc, in the order that
lands, with the one measured/real number per beat so nothing is hand-waved. The
live demo is the spine — slides frame it, the dashboard carries it.

## The one-line thesis (open and close on this)

> A prompt firewall reads the attacker's sentence. **Leash watches the agent's hands.**

Injection wins at the language layer. Leash moves the decision *below* the agent,
to the kernel, on arguments the kernel already resolved. Language gets no vote.

## Slide flow

1. **The problem (30s).** Prompt injection bypasses classifiers because it lives
   in language. Show a poisoned document (`docs/report_fork.txt`) that tells the
   agent to exfiltrate a key. The model obeys. *Classifiers guard the sentence;
   the attack is in the hands.*

2. **The idea (1 slide).** eBPF LSM hooks decide what the agent's processes may
   *do*. `file_open` and `socket_connect` return `-EPERM` outside policy. Why LSM
   not seccomp: seccomp can't dereference the path or the sockaddr; the LSM hook
   fires *after* the kernel resolved them. That's the whole technical argument.

3. **Session attribution (1 slide).** The agent lives in a dedicated cgroup;
   `bpf_get_current_cgroup_id()` tags every event; children inherit it by kernel
   guarantee — so a forked `curl` is caught with no cooperation. Non-session
   processes hit an early return (this is also the scalability story, slide 8).

4. **LIVE DEMO — the money shot (3-4 min).** `up.sh` (root once, on camera —
   make the point that attaching an enforcer is a conscious act), open the
   dashboard, `demo.sh`. Narrate as denials stream:
   - file read of the key → `-EPERM`, chain forms;
   - both egress shapes → denied; Ollama still reachable (policy, not a blanket
     block — toggle `allow` to show the permitted traffic);
   - the injection node is drawn dashed, *"not observed by leash, by design"* —
     we never claim to see the prompt;
   - the terminal node's honest wording: *no successful read of the protected
     inode; no egress to a non-allowlisted destination.*

5. **Identity is the inode, not the path (1 slide).** Attack #2: hardlink the key
   to a new name the policy never mentions, read *that* — still blocked, because
   identity is `(st_dev, st_ino)`. A path-based guard would miss it.

6. **Honest limits — the 7th attack (1 slide, do not skip).** Six shapes
   contained; **#7 walks out** through a *disclosed* gap (`socket_connect`
   inspects only `AF_INET`; IPv6 / AF_UNIX pass). Show the controlled experiment:
   same curl technique, IPv4 denied vs IPv6 delivered — only the address family
   changed. And the layered-defence point: the file layer still blocks the key
   read, so #7 leaks *other* data, not the key. *An undisclosed bypass is worse
   than a disclosed one.*

7. **Fail-open + restart-survival (1 slide).** If leashd dies, the loaders die
   with it and enforcement vanishes — shown as an explicit window, not hidden
   (safe to install). And an agent restart churns the cgroup id; the loaders
   re-sync and enforcement follows the new session (real post-resync denies under
   the new cgid).

8. **It's cheap, and scoped (1 slide — the numbers).** Measured, not cited:
   enforcement adds ~**0.3 µs** to an in-session `open()`, low-single-digit µs to
   a `connect()`. Out-of-session — every other process on the box — pays
   ~**19 ns/open** and a connect tax *below measurement resolution*. The rest of
   the host pays a tax we can barely detect. (Distribution + method in
   `docs/phase8.md`; we never claim "zero".)

9. **Safe to install (1 slide).** Fail-open, removable (`uninstall.sh` →
   bpftool-verified clean), loopback-only, decoys only. `down.sh` proves the
   kernel is clean by asking the kernel, not the process table.

10. **Close.** Back to the thesis. Injection can change what the agent *tries*;
    it cannot change what the kernel *permits*.

## Numbers to put on screen (all real, all in the repo)

| claim | number | source |
|-------|--------|--------|
| file enforcement cost (in-session) | ~299 ns/open | `bench/results/summary.csv` |
| host-wide tax (leash merely loaded) | ~19 ns/open | Phase 8 (b)-(c) |
| connect host-wide tax | below resolution | Phase 8 |
| attacks contained | 6 of 7 | `attacks/`, Phase 7 |
| #7 outcome | NOT CONTAINED (disclosed) | Phase 7 |

## Demo hygiene (so it never fumbles on camera)

- Run `scripts/down.sh` before recording and confirm **VERIFIED CLEAN** — start
  from nothing.
- `LEASH_DEMO_BEAT=2.5 scripts/demo.sh` slows the pacing for narration.
- Keep the dashboard's `allow` fold **on** while narrating denials; toggle it
  open once, deliberately, to show Ollama was reachable the whole time.
- Have a second terminal ready with `sudo bpftool prog show | grep leash` to
  prove, live, that the programs really are on (and after `down.sh`, gone).
