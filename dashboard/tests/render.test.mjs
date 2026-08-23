// Positive control for the UI itself: the components must put the REAL numbers
// from the capture on screen. Catches render-time crashes and any value that
// silently becomes undefined. Requires `npm run build:ssr` first.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';

const BUNDLE = join(import.meta.dirname, 'ssr', 'dist', 'entry.js');
if (!existsSync(BUNDLE)) {
  test('ssr bundle missing -- run `npm run build:ssr`', () => assert.fail(BUNDLE));
}
const mod = await import(BUNDLE);
// React's SSR inserts `<!-- -->` separators between adjacent text expressions.
// They are invisible in the browser; strip them so assertions match what a
// reader actually sees on screen.
const strip = (h) => h.replace(/<!-- -->/g, '');
const renderConsole = (...a) => strip(mod.renderConsole(...a));
const renderEmpty = (...a) => strip(mod.renderEmpty(...a));

const FIX = join(import.meta.dirname, '..', '..', 'fixtures');
const load = (n) => readFileSync(join(FIX, n), 'utf8')
  .split('\n').filter(Boolean).map((l) => JSON.parse(l));
const FULL = load('session-full.jsonl');
const REATTACH = load('session-reattach.jsonl');

test('console renders the real session-full numbers', () => {
  const html = renderConsole(FULL);
  for (const needle of [
    'leashd', 'pid 10407',            // status bar, from session_start
    '9205', '9066',                   // current cgid and the one it re-synced from
    'leash-agent',                    // unit, from discover
    'api_key.txt', '264241152', '920726',   // protected inode as the kernel reported it
    '127.0.0.1:11434',                // allowlisted egress
    'EPERM', 'RESYNC',                // verdicts
    'cgid 9066 → 9205',               // the resync row
  ]) {
    assert.ok(html.includes(needle), `missing from render: ${needle}`);
  }
});

test('hero chain renders the cat+curl pair with real seqs', () => {
  const html = renderConsole(FULL);
  assert.ok(html.includes('lsm/file_open'));
  assert.ok(html.includes('lsm/connect'));
  assert.ok(html.includes('127.0.0.1:9000'));
  assert.ok(html.includes('seq 144') || html.includes('144'));
});

test('the injection node is rendered, dashed and explicitly unevidenced', () => {
  const html = renderConsole(FULL);
  assert.ok(html.includes('injection / language layer'));
  assert.ok(html.includes('not observed by leash, by design'));
  assert.ok(html.includes('unevidenced'));
});

test('NEGATIVE: the terminal node never overclaims, and no policy hash appears', () => {
  const html = renderConsole(FULL);
  assert.ok(html.includes('no successful read of the protected inode'));
  assert.ok(html.includes('no egress to a non-allowlisted destination'));
  // the bare overclaiming phrasing must not appear anywhere
  assert.ok(!/secret never left/i.test(html));
  // the mockup's fabricated integrity field must not appear
  assert.ok(!/policy sha|4a9c1f/i.test(html));
  // nor any number from the mockup's old capture
  assert.ok(!html.includes('7729'), 'mockup cgid leaked into the render');
  assert.ok(!/\bseq 245\b/.test(html), 'mockup seq leaked into the render');
});

test('fail-open banner: loud mid-window, silent after clean shutdown', () => {
  const mid = REATTACH.filter((e) => e.seq <= 75);      // egress loader dead
  assert.ok(/fail-open/i.test(renderConsole(mid)));
  assert.ok(/enforcement is NOT in effect/.test(renderConsole(mid)));
  // full capture ends with a clean session_end -> detached by design, no alarm
  assert.ok(!/enforcement is NOT in effect/.test(renderConsole(FULL)));
  // and a healthy stream shows no banner at all
  assert.ok(!/fail-open/i.test(renderConsole(REATTACH)));
});

test('sidebar states the AF_INET scope disclosure (not stream-derived)', () => {
  const html = renderConsole(FULL);
  assert.ok(html.includes('scope AF_INET'));
  assert.ok(html.includes('IPv6/UNIX unenforced'));
  // it is a coverage caveat, not an active alarm -- the fail-open banner text
  // must not appear just because this label is present
  assert.ok(!/enforcement is NOT in effect/.test(html));
});

test('debug rows are present but hidden by default', () => {
  const html = renderConsole(FULL);
  assert.ok(html.includes('debug hidden (16)'));
  assert.ok(!html.includes('>DEBUG<'));
});

test('allow chatter is folded by default, denials always shown', () => {
  const html = renderConsole(FULL);
  // session-full has 73 allow events -> the toggle reports them, but no ALLOW
  // row renders in the default demo view
  assert.ok(html.includes('allow hidden (73)'));
  assert.ok(!html.includes('>ALLOW<'));
  // the -EPERM denials are NEVER folded -- the story stays visible
  assert.ok(html.includes('>EPERM<'));
  // lifecycle likewise stays: the resync verdict is present
  assert.ok(html.includes('>RESYNC<'));
});

test('empty states name the actual problem and invent no events', () => {
  assert.ok(renderEmpty(false, null).includes('bridge not reachable'));
  assert.ok(renderEmpty(true, false).includes('no event stream on disk'));
  assert.ok(renderEmpty(true, true).includes('stream is empty'));
  const html = renderConsole([]);
  assert.ok(!html.includes('EPERM'));
});
