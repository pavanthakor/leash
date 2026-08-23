import React from 'react';
import { fmtUptime } from '../lib/posture.js';

function Enforcer({ layer, state }) {
  const cls = state.since == null ? 'unknown' : state.attached ? 'up' : 'down';
  const title = state.since == null
    ? `${layer}: no attach observed yet`
    : state.attached ? `${layer}: attached` : `${layer}: ${state.reason ?? 'not enforcing'}`;
  return (
    <span className={`pill ${cls}`} title={title}>
      {layer}&nbsp;<span className="dot" />
    </span>
  );
}

export function StatusBar({ posture, now, connected }) {
  const { leashd, layers, policy } = posture;
  const running = leashd.pid != null && !leashd.ended;
  const uptime = leashd.startedTs != null
    ? fmtUptime((leashd.ended?.ts ?? now) - leashd.startedTs)
    : null;

  return (
    <div className="statusbar">
      <span className="name">leashd</span>
      {running ? (
        <span className="pill up"><span className="dot" />active</span>
      ) : leashd.ended ? (
        <span className="pill down"><span className="dot" />
          ended (signal {leashd.ended.signal})
        </span>
      ) : (
        <span className="pill unknown"><span className="dot" />no session</span>
      )}
      <span className="muted">pid {leashd.pid ?? '—'}</span>
      <span className="muted">uptime {uptime ?? '—'}</span>
      <span className="sep">|</span>
      <span style={{ color: 'var(--text-secondary)' }}>enforcers</span>
      <Enforcer layer="file" state={layers.file} />
      <Enforcer layer="egress" state={layers.egress} />
      <span className="right">
        {connected ? '' : 'bridge disconnected · '}
        {/* leashd emits no policy hash; rendering one would fabricate an
            integrity guarantee. Only the real version is shown. */}
        policy {policy.version != null ? `v${policy.version}` : '—'}
      </span>
    </div>
  );
}
