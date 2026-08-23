import React from 'react';
import { UNEVIDENCED_ROOT, CONTAINED_LABEL, CORRELATION_NOTE } from '../lib/chains.js';
import { shortPath } from '../lib/normalize.js';

const fmtDt = (s) => (s < 0.001 ? '<1ms' : s < 1 ? `${Math.round(s * 1000)}ms` : `${s.toFixed(2)}s`);

function Rail({ kind, last }) {
  return (
    <div className="rail">
      <span className={`node ${kind}`} />
      {!last && <span className={`line${kind === 'unevidenced' ? ' dashed' : ''}`} />}
    </div>
  );
}

export function CausalChain({ chain }) {
  if (!chain) {
    return (
      <div className="chain">
        <div className="title"><span className="cap">containment chain</span></div>
        <div className="meta" style={{ color: 'var(--text-muted)' }}>
          no multi-step denial observed yet — nothing to chain
        </div>
      </div>
    );
  }

  const steps = chain.steps;
  return (
    <div className="chain">
      <div className="title">
        <span className="cap">containment chain</span>
        <span>
          · session {chain.cgid}
          {chain.stitched ? ' (re-synced)' : ''}
          {' · '}seq {chain.firstSeq}–{chain.lastSeq}
          {' · '}Δt {fmtDt(chain.dt)}
        </span>
      </div>

      <div className="grid">
        {/* The injection is NOT in the stream. Leash watches the agent's hands,
            never the attacker's sentence -- so it is drawn, dashed, as an
            explicitly unevidenced node rather than silently omitted. */}
        <Rail kind="unevidenced" />
        <div className="cell unevidenced">
          {UNEVIDENCED_ROOT.label}
          <span className="why"> — {UNEVIDENCED_ROOT.note}</span>
        </div>

        {steps.map((s, i) => (
          <React.Fragment key={`${s.seq}-${i}`}>
            <Rail kind="deny" />
            <div className="cell">
              <div>
                <span className="verdict deny">
                  EPERM{s.count > 1 ? ` ×${s.count}` : ''}
                </span>{' '}
                <span className="hook">lsm/{s.hook}</span>
              </div>
              <div className="meta">
                {s.comm} → {s.layer === 'file' ? shortPath(s.target) : s.target}
                {' · seq '}{s.count > 1 ? `${s.seq}–${s.lastSeq}` : s.seq}
              </div>
            </div>
          </React.Fragment>
        ))}

        <Rail kind="ok" last />
        <div className="cell last">
          <span className="verdict ok">contained</span>
          <span className="hook">
            {CONTAINED_LABEL.replace(/^contained · /, ' · ')}
          </span>
        </div>
      </div>

      <div className="footnote">{CORRELATION_NOTE}</div>
    </div>
  );
}
