import React, { useState } from 'react';
import { shortPath } from '../lib/normalize.js';

// `debug` rows are real events the file loader emitted (one per protected-inode
// open, mirroring each deny). They are excluded from chains and hidden here by
// default so the working view stays clean -- but they are never dropped, only
// folded behind the toggle.
export function EventTable({ rows }) {
  const [showDebug, setShowDebug] = useState(false);
  const visible = showDebug ? rows : rows.filter((r) => !r.isDebug);
  const debugCount = rows.length - rows.filter((r) => !r.isDebug).length;

  return (
    <div className="log">
      <div className="toolbar">
        <span>event log</span>
        <span className="right">
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
          <div className="empty" style={{ padding: '18px 12px' }}>no events</div>
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
