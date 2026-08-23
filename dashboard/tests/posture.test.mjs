// derivePosture + normalize against the two REAL captures. These are the values
// the status bar and sidebar put on screen, so they are asserted against the
// fixtures rather than trusted.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { derivePosture, fmtUptime } from '../src/lib/posture.js';
import { toRows } from '../src/lib/normalize.js';

const FIX = join(import.meta.dirname, '..', '..', 'fixtures');
const load = (n) => readFileSync(join(FIX, n), 'utf8')
  .split('\n').filter(Boolean).map((l) => JSON.parse(l));
const FULL = load('session-full.jsonl');
const REATTACH = load('session-reattach.jsonl');

test('session-full: posture is the real capture', () => {
  const p = derivePosture(FULL);
  assert.equal(p.leashd.pid, 10407);
  assert.deepEqual(p.leashd.ended, { ts: FULL.find((e) => e.type === 'session_end').ts, signal: 2 });
  assert.equal(p.session.cgid, 9205);
  assert.equal(p.session.prevCgid, 9066);
  assert.equal(p.session.unit, 'leash-agent.service');
  assert.equal(p.session.dev, 264241152);
  assert.equal(p.session.ino, 920726);
  assert.deepEqual(p.policy.protect, ['/home/pavan/leash-demo/secrets/api_key.txt']);
  assert.deepEqual(p.policy.allow, ['127.0.0.1:11434']);
  assert.equal(p.policy.defaultEgress, 'deny');
  assert.deepEqual(p.counts, { deny: 54, allow: 73, resync: 2 });
});

test('session-full: NEGATIVE -- no policy hash is ever surfaced', () => {
  const p = derivePosture(FULL);
  assert.equal(p.policy.version, 1);
  assert.ok(!('sha' in p.policy) && !('hash' in p.policy));
  // and nothing in the stream could supply one
  assert.ok(!FULL.some((e) => JSON.stringify(e).match(/sha|hash|digest/i)));
});

test('session-full: both enforcers end detached after clean shutdown', () => {
  const p = derivePosture(FULL);
  assert.equal(p.layers.file.attached, false);
  assert.equal(p.layers.egress.attached, false);
  assert.equal(p.failOpen, true);       // enforcement genuinely gone...
  assert.ok(p.leashd.ended);            // ...but by a clean session_end, so the
                                        // banner suppresses (see AlertBanner)
});

test('session-reattach: enforcers up at the end, no false alarm', () => {
  const p = derivePosture(REATTACH);
  assert.equal(p.session.cgid, 7963);
  assert.equal(p.session.prevCgid, null);   // no resync in this capture
  assert.equal(p.layers.egress.attached, true);   // reattached at seq 80
  assert.equal(p.layers.file.attached, true);     // never died
  assert.equal(p.failOpen, false);
  assert.equal(p.leashd.ended, null);             // stream just stops
});

test('session-reattach: mid-window posture shows the open fail-open', () => {
  const mid = REATTACH.filter((e) => e.seq <= 75);   // after down, before reattach
  const p = derivePosture(mid);
  assert.equal(p.failOpen, true);
  assert.deepEqual(p.openWindows.map((w) => w.layer), ['egress']);
  assert.equal(p.openWindows[0].reason, 'loader_exited');
  assert.equal(p.layers.file.attached, true);   // file layer never stopped enforcing
});

test('rows: newest first, debug flagged, allow carries no uid', () => {
  const rows = toRows(FULL);
  assert.equal(rows[0].seq, Math.max(...rows.map((r) => r.seq)));
  const allow = rows.find((r) => r.verdict === 'ALLOW');
  assert.equal(allow.uid, null);
  const deny = rows.find((r) => r.verdict === 'EPERM');
  assert.equal(deny.uid, 1000);
  assert.equal(rows.filter((r) => r.isDebug).length, 16);
  assert.ok(rows.every((r) => r.verdict !== 'ALLOW' || r.layer === 'egress'));
});

test('rows: resync and failopen render as verdicts, not raw types', () => {
  const rows = toRows(FULL);
  const rs = rows.find((r) => r.verdict === 'RESYNC');
  assert.equal(rs.target, 'cgid 9066 → 9205');
  const fo = rows.find((r) => r.verdict === 'FAILOPEN');
  assert.match(fo.target, /enforcement down — detach/);
  const re = toRows(REATTACH).find((r) => r.verdict === 'REATTACH');
  assert.equal(re.target, 'loader respawned and attached');
});

test('empty stream produces empty posture, invents nothing', () => {
  const p = derivePosture([]);
  assert.equal(p.leashd.pid, null);
  assert.equal(p.session.cgid, null);
  assert.deepEqual(p.policy.protect, []);
  assert.equal(p.failOpen, false);
  assert.deepEqual(toRows([]), []);
});

test('fmtUptime', () => {
  assert.equal(fmtUptime(null), '—');
  assert.equal(fmtUptime(-1), '—');
  assert.equal(fmtUptime(61), '01:01');
  assert.equal(fmtUptime(3661), '1:01:01');
});
