// chains.js against the two REAL captures in ../../fixtures. Never hand-written
// events: every assertion below is a fact about a stream that leashd actually
// wrote while the enforcers were attached to the kernel (charter invariant 1).
//
// Per charter invariant 2 each behaviour gets a positive AND a negative control:
// what the builder must produce, and what it must never produce.
//
// Fixtures are referenced, not copied, so the suite tracks the canonical
// captures and cannot silently drift from them.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { buildChains, heroChain } from '../src/lib/chains.js';

const FIX = join(import.meta.dirname, '..', '..', 'fixtures');
const load = (n) => readFileSync(join(FIX, n), 'utf8')
  .split('\n').filter(Boolean).map((l) => JSON.parse(l));

const FULL = load('session-full.jsonl');
const REATTACH = load('session-reattach.jsonl');

const sig = (c) => ({
  seq: c.firstSeq,
  cgid: c.cgid,
  steps: c.steps.map((s) => `${s.layer}:${s.comm}:${s.target}${s.count > 1 ? `x${s.count}` : ''}`),
});

// ---------------------------------------------------------------- fixture sanity
test('fixtures are the expected real captures', () => {
  assert.equal(FULL.length, 172);
  assert.equal(REATTACH.length, 128);
  assert.equal(FULL[0].type, 'session_start');
  assert.equal(FULL[0].seq, 0);
  assert.equal(REATTACH[0].seq, 0);
  // session-reattach has NO session_end -- the stream simply stops.
  assert.ok(!REATTACH.some((e) => e.type === 'session_end'));
});

// ---------------------------------------------------------------- session-full
test('session-full: exact chains', () => {
  const { chains } = buildChains(FULL);
  assert.deepEqual(chains.map(sig), [
    { seq: 29,  cgid: 9066, steps: ['file:cat:/home/pavan/leash-demo/secrets/api_key.txt', 'egress:curl:127.0.0.1:9000'] },
    { seq: 40,  cgid: 9066, steps: ['egress:AnyIO worker th:127.0.0.53:53x4'] },
    { seq: 68,  cgid: 9066, steps: ['file:cat:/home/pavan/leash-demo/secrets/api_key.txt', 'egress:curl:127.0.0.1:9000'] },
    { seq: 79,  cgid: 9066, steps: ['egress:AnyIO worker th:127.0.0.53:53x4'] },
    { seq: 84,  cgid: 9066, steps: ['egress:curl:127.0.0.53:53x4'] },
    { seq: 101, cgid: 9205, steps: ['file:cat:/home/pavan/leash-demo/secrets/api_key.txt', 'egress:curl:127.0.0.1:9000'] },
    { seq: 112, cgid: 9205, steps: ['egress:AnyIO worker th:127.0.0.53:53x4'] },
    { seq: 117, cgid: 9205, steps: ['egress:curl:127.0.0.53:53x4'] },
    { seq: 144, cgid: 9205, steps: ['file:cat:/home/pavan/leash-demo/secrets/api_key.txt', 'egress:curl:127.0.0.1:9000'] },
    { seq: 155, cgid: 9205, steps: ['egress:AnyIO worker th:127.0.0.53:53x4'] },
    { seq: 160, cgid: 9205, steps: ['egress:curl:127.0.0.53:53x4'] },
  ]);
});

test('session-full: the restart-survival story -- same attack, both cgids, TWO chains', () => {
  const { chains } = buildChains(FULL);
  const catCurl = chains.filter((c) => c.multiLayer);
  // the forked-child exfil shape: file_open denied, then the child's connect denied
  assert.equal(catCurl.length, 4);
  assert.deepEqual(catCurl.map((c) => c.cgid), [9066, 9066, 9205, 9205]);
  assert.deepEqual(catCurl.map((c) => c.firstSeq), [29, 68, 101, 144]);
  for (const c of catCurl) {
    assert.deepEqual(c.steps.map((s) => s.layer), ['file', 'egress']);
    assert.deepEqual(c.steps.map((s) => s.verdict), ['EPERM', 'EPERM']);
  }
});

test('session-full: NEGATIVE -- no chain spans the resync or two cgids', () => {
  const { chains, nodes } = buildChains(FULL);
  const resync = nodes.filter((n) => n.kind === 'resync');
  assert.deepEqual(resync.map((r) => [r.seq, r.layer, r.oldCgid, r.newCgid]),
    [[91, 'file', 9066, 9205], [92, 'egress', 9066, 9205]]);
  const boundary = resync[0].seq;
  for (const c of chains) {
    assert.equal(new Set(c.steps.map((s) => s.cgid)).size, 1, `chain c${c.firstSeq} spans cgids`);
    assert.ok(c.lastSeq < boundary || c.firstSeq > resync[1].seq,
      `chain c${c.firstSeq} straddles the resync barrier`);
  }
});

test('session-full: resync stitches 9066 and 9205 into ONE logical agent', () => {
  const { chains } = buildChains(FULL);
  const agents = new Set(chains.map((c) => c.agent));
  assert.equal(agents.size, 1);                      // one logical agent...
  assert.equal(new Set(chains.map((c) => c.cgid)).size, 2);  // ...two cgids on screen
  assert.ok(chains.filter((c) => c.cgid === 9205).every((c) => c.stitched));
});

test('session-full: lifecycle nodes and lone denies', () => {
  const { nodes, loneDenies } = buildChains(FULL);
  assert.deepEqual(
    nodes.filter((n) => n.kind === 'failopen').map((n) => [n.seq, n.layer, n.window, n.reason]),
    [[169, 'egress', 'open', 'detach'], [171, 'file', 'open', 'detach']]);
  assert.equal(loneDenies.length, 18);
  for (const d of loneDenies) assert.equal(d.steps.length, 1);
  for (const d of loneDenies) assert.equal(d.steps[0].count, 1);
});

// ------------------------------------------------------------ session-reattach
test('session-reattach: exact chains', () => {
  const { chains } = buildChains(REATTACH);
  assert.deepEqual(chains.map((c) => c.firstSeq), [29, 40, 52, 63, 68, 109, 120]);
  assert.ok(chains.every((c) => c.cgid === 7963));
  assert.ok(chains.every((c) => !c.stitched));   // no resync in this capture
});

test('session-reattach: death -> reattach are their own nodes, not chain steps', () => {
  const { nodes } = buildChains(REATTACH);
  const life = nodes.filter((n) => ['down', 'failopen', 'reattach'].includes(n.kind));
  assert.deepEqual(life.map((n) => [n.kind, n.seq, n.window ?? n.returncode]), [
    ['down', 72, -9],
    ['failopen', 73, 'open'],
    ['reattach', 80, null],
    ['failopen', 81, 'closed'],
  ]);
  assert.equal(life[1].reason, 'loader_exited');
});

test('session-reattach: NEGATIVE -- nothing absorbed across the fail-open window', () => {
  const { chains } = buildChains(REATTACH);
  const [open, close] = [73, 81];
  for (const c of chains) {
    assert.ok(c.lastSeq < open || c.firstSeq > close,
      `chain c${c.firstSeq} straddles the fail-open window`);
  }
  // the window itself is 1941s wide and empty -- enforcement was genuinely off
  const denies = REATTACH.filter((e) => e.type === 'deny' && e.seq > open && e.seq < close);
  assert.equal(denies.length, 0);
});

test('session-reattach: enforcement re-enforces AFTER the reattach', () => {
  const { chains, loneDenies } = buildChains(REATTACH);
  const after = [...chains, ...loneDenies]
    .filter((c) => c.firstSeq > 81)
    .sort((a, b) => a.firstSeq - b.firstSeq);
  assert.ok(after.length > 0, 'no denies after reattach -- re-enforcement unproven');
  assert.equal(after[0].firstSeq, 87);
  assert.equal(after[0].steps[0].target, '127.0.0.1:9000');
});

// ------------------------------------------------------------ shared invariants
for (const [name, evs] of [['session-full', FULL], ['session-reattach', REATTACH]]) {
  test(`${name}: NEGATIVE -- allow and debug never become chain steps`, () => {
    const { nodes } = buildChains(evs);
    const steps = nodes.flatMap((n) => n.steps ?? []);
    assert.ok(steps.length > 0);
    for (const s of steps) assert.equal(s.verdict, 'EPERM');
    // every step must trace back to a real deny at that seq
    const denySeqs = new Set(evs.filter((e) => e.type === 'deny').map((e) => e.seq));
    for (const s of steps) assert.ok(denySeqs.has(s.seq), `step seq ${s.seq} is not a deny`);
    // the allowlisted destination never appears as a chain step
    assert.ok(!steps.some((s) => s.target === '127.0.0.1:11434'));
  });

  test(`${name}: every deny is accounted for exactly once`, () => {
    const { nodes } = buildChains(evs);
    const counted = nodes.flatMap((n) => n.steps ?? []).reduce((a, s) => a + s.count, 0);
    assert.equal(counted, evs.filter((e) => e.type === 'deny').length);
  });

  test(`${name}: gates respected -- dseq<=8 and dt<=2.0s within a chain`, () => {
    const { chains } = buildChains(evs);
    for (const c of chains) {
      for (let i = 1; i < c.steps.length; i++) {
        assert.ok(c.steps[i].seq - c.steps[i - 1].lastSeq <= 8);
        assert.ok(c.steps[i].ts - c.steps[i - 1].lastTs <= 2.0);
      }
    }
  });
}

test('hero chain: most recent multi-layer, else most recent', () => {
  assert.equal(heroChain(buildChains(FULL).chains).firstSeq, 144);
  assert.equal(heroChain(buildChains(REATTACH).chains).firstSeq, 109);
  assert.equal(heroChain([]), null);
  // NEGATIVE: a lone DNS burst must never be the hero when a multi-layer exists
  const hero = heroChain(buildChains(FULL).chains);
  assert.ok(hero.multiLayer);
  assert.notEqual(hero.steps[0].target, '127.0.0.53:53');
});

test('builder is pure: input untouched, order-independent', () => {
  const copy = JSON.parse(JSON.stringify(FULL));
  const a = buildChains(FULL);
  assert.deepEqual(FULL, copy);
  const b = buildChains([...FULL].reverse());
  assert.deepEqual(b.chains.map(sig), a.chains.map(sig));
});

test('empty and degenerate inputs invent nothing', () => {
  assert.deepEqual(buildChains([]).chains, []);
  assert.deepEqual(buildChains([]).nodes, []);
  assert.deepEqual(buildChains(FULL.filter((e) => e.type !== 'deny')).chains, []);
});
