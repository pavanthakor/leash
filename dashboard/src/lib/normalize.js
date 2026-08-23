// Raw leashd event -> one columnar log row. Renames nothing that carries
// meaning and invents nothing that is not in the event.
import { hookOf, targetOf } from './chains.js';

// Rows the console shows. `log`, `spawn`, `session`, `discover`, `up`, `policy`
// and `session_start`/`session_end` are lifecycle plumbing surfaced elsewhere
// (status bar / sidebar), not log rows.
const ROW_TYPES = new Set([
  'deny', 'allow', 'resync', 'failopen', 'down', 'reattach', 'attached', 'debug',
]);

export const SEVERITY = {
  deny: 'danger',
  allow: 'success',
  failopen: 'warning',
  down: 'warning',
  resync: 'accent',
  reattach: 'accent',
  attached: 'muted',
  debug: 'muted',
};

export function verdictOf(e) {
  switch (e.type) {
    case 'deny': return 'EPERM';        // the loaders only ever report -EPERM
    case 'allow': return 'ALLOW';
    case 'resync': return 'RESYNC';
    case 'failopen': return 'FAILOPEN';
    case 'down': return 'DOWN';
    case 'reattach': return 'REATTACH';
    case 'attached': return 'ATTACHED';
    case 'debug': return 'DEBUG';
    default: return e.type.toUpperCase();
  }
}

function targetText(e) {
  switch (e.type) {
    case 'resync': return `cgid ${e.old_cgid} → ${e.new_cgid}`;
    case 'failopen':
      return e.window === 'closed'
        ? 'enforcement re-established'
        : `enforcement down — ${e.reason ?? 'unknown reason'}`;
    case 'down': return `loader exited (rc ${e.returncode})`;
    case 'reattach': return 'loader respawned and attached';
    case 'attached': return e.detail ?? 'attached';
    case 'debug': return e.path ?? `dev ${e.dev} ino ${e.ino}`;
    default: return targetOf(e) ?? '';
  }
}

export function normalize(e) {
  return {
    seq: e.seq,
    ts: e.ts,
    type: e.type,
    layer: e.layer,
    hook: hookOf(e),
    verdict: verdictOf(e),
    comm: e.comm ?? (e.layer === 'leashd' ? null : e.layer),
    pid: e.pid ?? null,
    uid: e.uid ?? null,            // deny only; allow genuinely has no uid
    target: targetText(e),
    cgid: e.cgid ?? null,
    dev: e.dev ?? null,
    ino: e.ino ?? null,
    severity: SEVERITY[e.type] ?? 'muted',
    isDebug: e.type === 'debug',
  };
}

/** Table rows, newest first. `debug` is included but flagged (hidden by default). */
export function toRows(events) {
  return events
    .filter((e) => ROW_TYPES.has(e.type))
    .map(normalize)
    .sort((a, b) => b.seq - a.seq);
}

export function shortPath(p) {
  if (!p) return '';
  const parts = p.split('/');
  return parts.length > 2 ? `…/${parts[parts.length - 1]}` : p;
}
