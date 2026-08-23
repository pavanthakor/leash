import React from 'react';

const base = (p) => (p ? p.split('/').pop() : '—');

export function SessionSidebar({ posture }) {
  const { session, policy, counts } = posture;
  return (
    <div className="sidebar">
      <div className="head">session</div>
      <div className="row"><span className="k">cgid</span><span>{session.cgid ?? '—'}</span></div>
      <div className="row"><span className="k">unit</span>
        <span>{session.unit ? session.unit.replace(/\.service$/, '') : '—'}</span></div>
      {session.prevCgid != null && (
        <div className="row"><span className="k">prev</span>
          <span className="sub">{session.prevCgid}</span></div>
      )}

      <div className="head group">files · protect</div>
      {policy.protect.length === 0 && <div className="sub">—</div>}
      {policy.protect.map((p) => <div key={p} className="val">{base(p)}</div>)}
      {/* dev/ino as the KERNEL reported them, not derived from the policy path */}
      <div className="sub">dev {session.dev ?? '—'}</div>
      <div className="sub">ino {session.ino ?? '—'}</div>

      <div className="head group">egress · allow</div>
      {policy.allow.length === 0 && <div className="sub">—</div>}
      {policy.allow.map((a) => <div key={a}><span className="ok">{a}</span></div>)}
      <div className="sub">default {policy.defaultEgress ?? '—'}</div>

      <div className="rule" />
      <div className="row"><span className="k">deny</span>
        <span className="danger">{counts.deny}</span></div>
      <div className="row"><span className="k">allow</span>
        <span className="ok">{counts.allow}</span></div>
      <div className="row"><span className="k">resync</span>
        <span>{counts.resync}</span></div>
    </div>
  );
}
