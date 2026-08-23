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
      {/* SCOPE DISCLOSURE -- the one label in this console NOT derived from the
          event stream. socket_connect enforces AF_INET only; AF_INET6 and
          AF_UNIX pass unhooked and so emit no event at all (docs/phase4.md,
          docs/phase7.md #7). The stream structurally cannot show coverage it
          never sees, so a reader could mistake IPv4 enforcement for total
          enforcement -- this states what the green egress dot does NOT cover. */}
      <div className="scope" title="socket_connect inspects AF_INET only; IPv6 and unix-domain destinations are not enforced (disclosed gap, docs/phase7.md #7)">
        scope AF_INET <span className="sub">· IPv6/UNIX unenforced</span>
      </div>

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
