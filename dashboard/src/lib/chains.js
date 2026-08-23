// Containment-chain builder. PURE: no I/O, no DOM, no clock. Everything it
// reports is derived from the event stream leashd wrote -- it never invents a
// step, never infers an event the kernel did not report, and never claims a
// causal link the stream cannot support (see CORRELATION_NOTE).
//
// Shape of the algorithm (validated against the two real captures in
// ../../fixtures -- see tests/chains.test.mjs, which asserts the exact chains):
//
//   1. cgids joined by a resync are unioned into one LOGICAL AGENT, so the
//      lifecycle (down/reattach) stays continuous across an agent restart.
//   2. Walk seq order over deny + resync + down/failopen/reattach.
//   3. A deny OPENS a chain. A following deny is ABSORBED iff it is the same
//      logical agent AND dseq <= 8 AND dt <= 2.0s, measured from the last
//      absorbed DENY (allows are not chain steps -- see WHY_DENIES_ONLY).
//   4. resync / down / failopen / reattach are BARRIERS: they close any open
//      chain and become their own lifecycle node. The barrier is explicit --
//      a chain never spans a resync even though the dseq/dt gates would also
//      force the split. Pre- and post-restart attacks are two chains under two
//      cgids: that IS the restart-survival story.
//   5. Consecutive identical (layer, comm, target) denies collapse to one step
//      with a count (the DNS bursts arrive as 4 denies at dt 0.00).
//   6. A run is promoted to a CHAIN only if it has >= 2 collapsed steps or any
//      step with count > 1. A single isolated deny is a lone deny, not a chain.
//
// WHY_DENIES_ONLY: an earlier draft absorbed `allow` events too. Every chain
// then ended "EPERM -> ALLOW 127.0.0.1:11434", which reads as "blocked, then
// let out" -- but that allow is the next, unrelated model call ~10ms later.
// Allows belong in the event table as context, never as a chain step.

export const CHAIN_DSEQ = 8;      // max seq distance between absorbed denies
export const CHAIN_DT = 2.0;      // max wall-clock distance, seconds

export const BARRIER_TYPES = new Set(['down', 'failopen', 'reattach']);

// Leash observes the agent's hands, not the attacker's sentence. The injection
// that starts a chain happens at the language layer and is NOT in this stream.
export const UNEVIDENCED_ROOT = {
  kind: 'unevidenced',
  label: 'injection / language layer',
  note: 'not observed by leash, by design',
};

// What the stream actually proves when a chain ends with everything denied.
// Deliberately NOT "the secret never left the cgroup": AF_INET6 and AF_UNIX
// are unenforced (disclosed Phase 4 gaps), so an unobserved path is possible.
export const CONTAINED_LABEL =
  'contained · no successful read of the protected inode; ' +
  'no egress to a non-allowlisted destination';

export const CORRELATION_NOTE =
  'steps are correlated by session + adjacency, not proven causally linked';

function makeAgentIndex(events) {
  const parent = new Map();
  const find = (x) => {
    if (!parent.has(x)) parent.set(x, x);
    let r = x;
    while (parent.get(r) !== r) r = parent.get(r);
    while (parent.get(x) !== r) { const n = parent.get(x); parent.set(x, r); x = n; }
    return r;
  };
  const union = (a, b) => { const ra = find(a), rb = find(b); if (ra !== rb) parent.set(rb, ra); };
  for (const e of events) {
    if (e.type === 'resync' && e.old_cgid != null && e.new_cgid != null) {
      union(e.old_cgid, e.new_cgid);
    }
  }
  return find;
}

export function targetOf(e) {
  if (e.layer === 'file') return e.path ?? null;
  if (e.ip != null && e.port != null) return `${e.ip}:${e.port}`;
  return null;
}

export function hookOf(e) {
  if (e.layer === 'file') return 'file_open';
  if (e.layer === 'egress') return 'connect';
  return 'supervisor';
}

// Consecutive identical denies -> one step carrying a count.
function collapse(denies) {
  const steps = [];
  for (const e of denies) {
    const prev = steps[steps.length - 1];
    if (prev && prev.layer === e.layer && prev.comm === e.comm && prev.target === targetOf(e)) {
      prev.count += 1;
      prev.lastSeq = e.seq;
      prev.lastTs = e.ts;
      continue;
    }
    steps.push({
      seq: e.seq, lastSeq: e.seq, ts: e.ts, lastTs: e.ts,
      layer: e.layer, hook: hookOf(e), verdict: 'EPERM',
      comm: e.comm ?? null, pid: e.pid ?? null, uid: e.uid ?? null,
      target: targetOf(e), dev: e.dev ?? null, ino: e.ino ?? null,
      cgid: e.cgid ?? null, count: 1,
    });
  }
  return steps;
}

function finishChain(run, find) {
  const steps = collapse(run.denies);
  const promoted = steps.length >= 2 || steps.some((s) => s.count > 1);
  const cgids = [...new Set(run.denies.map((d) => d.cgid))];
  const layers = new Set(steps.map((s) => s.layer));
  const first = run.denies[0];
  const last = run.denies[run.denies.length - 1];
  return {
    kind: promoted ? 'chain' : 'lone_deny',
    id: `c${first.seq}`,
    // Display cgid is the cgid these events actually carried -- NOT the
    // union-find root, which would mislabel every post-resync chain.
    cgid: cgids[0] ?? null,
    agent: run.agent,
    stitched: run.agent !== cgids[0],
    firstSeq: first.seq, lastSeq: last.seq,
    firstTs: first.ts, lastTs: last.ts,
    dt: last.ts - first.ts,
    denyCount: run.denies.length,
    steps,
    multiLayer: layers.size > 1,
    contained: true,   // every step is an EPERM; nothing in the run succeeded
  };
}

/**
 * @param {Array<object>} events raw leashd events, any order
 * @returns {{nodes:Array, chains:Array, loneDenies:Array, agents:Map}}
 */
export function buildChains(events) {
  const evs = [...events].sort((a, b) => a.seq - b.seq);
  const find = makeAgentIndex(evs);
  const nodes = [];
  let run = null;

  const flush = () => {
    if (!run) return;
    nodes.push(finishChain(run, find));
    run = null;
  };

  for (const e of evs) {
    const t = e.type;
    if (t === 'resync' || BARRIER_TYPES.has(t)) {
      flush();
      nodes.push({
        kind: t,
        id: `${t}${e.seq}`,
        seq: e.seq, ts: e.ts, layer: e.layer,
        oldCgid: e.old_cgid ?? null, newCgid: e.new_cgid ?? null,
        window: e.window ?? null, reason: e.reason ?? null,
        returncode: e.returncode ?? null,
        verdict: t === 'resync' ? 'RESYNC' : t === 'failopen' ? 'FAILOPEN'
               : t === 'down' ? 'DOWN' : 'REATTACH',
      });
      continue;
    }
    if (t !== 'deny') continue;

    if (run) {
      const last = run.denies[run.denies.length - 1];
      const sameAgent = e.cgid != null && find(e.cgid) === run.agent;
      if (sameAgent && e.seq - last.seq <= CHAIN_DSEQ && e.ts - last.ts <= CHAIN_DT) {
        run.denies.push(e);
        continue;
      }
      flush();
    }
    run = { denies: [e], agent: find(e.cgid) };
  }
  flush();

  return {
    nodes,
    chains: nodes.filter((n) => n.kind === 'chain'),
    loneDenies: nodes.filter((n) => n.kind === 'lone_deny'),
  };
}

/** Hero panel: most recent multi-layer chain, else most recent chain. */
export function heroChain(chains) {
  if (!chains.length) return null;
  const multi = chains.filter((c) => c.multiLayer);
  const pool = multi.length ? multi : chains;
  return pool[pool.length - 1];
}
