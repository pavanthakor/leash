import React, { useState } from 'react';
import { shortPath } from '../lib/normalize.js';

// Two classes of real-but-noisy events are FOLDED by default so the demo stream
// reads as the containment story -- denials and lifecycle -- rather than the
// steady background of a working agent. Neither is ever dropped; each is one
// toggle away for a proof run.
//
//   debug : the file loader's self-verifying (dev,ino) MATCH line, one per
//           protected-inode open (P3 debug_inos).
//   allow : every in-session connect the egress loader PERMITTED -- almost all
//           of it the agent's own 127.0.0.1:11434 Ollama chatter (P4 KIND_ALLOW,
//           self-verifying MATCH evidence). During a live demo the model makes
//           dozens of these; folding them lets the -EPERM denials stand out.
//
// Denies, resync, failopen, down, reattach and attached are ALWAYS shown -- the
// story is never folded.
export function EventTable({ rows }) {
  const [showDebug, setShowDebug] = useState(false);
  const [showAllow, setShowAllow] = useState(false);

  const debugCount = rows.filter((r) => r.isDebug).length;
  const allowCount = rows.filter((r) => r.verdict === 'ALLOW').length;

  const visible = rows.filter((r) => {
    if (r.isDebug && !showDebug) return false;
    if (r.verdict === 'ALLOW' && !showAllow) return false;
    return true;
  });

  return (
    <div className="log">
      <div className="toolbar">
        <span>event log</span>
        <span className="right">
          <button
            className="toggle"
            aria-pressed={showAllow}
            onClick={() => setShowAllow((v) => !v)}
            title="in-session connects the egress loader permitted (mostly Ollama :11434); folded so denials stand out"
          >
            allow {showAllow ? 'shown' : 'hidden'} ({allowCount})
          </button>
          <button
            className="toggle"
            aria-pressed={showDebug}
            onClick={() => setShowDebug((v) => !v)}
            title="file-layer debug events mirror each deny; hidden by default"
          >
            debug {showDebug ? 'shown' : 'hidden'} ({debugCount})
          </button>
        </span>
      </div>

      <div className="cols">
        <span>seq</span><span>hook</span><span>verdict</span>
        <span>comm · pid</span><span>target</span><span>cgid</span>
      </div>

      <div className="scroll">
        {visible.length === 0 && (
          <div className="empty" style={{ padding: '18px 12px' }}>
            {rows.length === 0 ? 'no events'
              : 'only allow/debug events so far — toggle above to show them'}
          </div>
        )}
        {visible.map((r) => (
          <div key={r.seq} className={`row ${r.severity}${r.isDebug ? ' isdebug' : ''}`}>
            <span className="seq">{r.seq}</span>
            <span className="hook">{r.hook}</span>
            <span className={`v ${r.severity}`}>{r.verdict}</span>
            <span className="comm">{r.comm ?? '—'}{r.pid != null ? `·${r.pid}` : ''}</span>
            <span className="target" title={r.target}>
              {r.layer === 'file' && r.type !== 'attached' ? shortPath(r.target) : r.target}
            </span>
            <span className="cgid">{r.cgid ?? '—'}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
