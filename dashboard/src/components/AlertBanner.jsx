import React from 'react';

// Loud ONLY while a fail-open window is open AND leashd is still running.
// A closed window is history, not an alarm. And a window opened by leashd's own
// clean shutdown is fail-open BY DESIGN (charter invariant 3) -- the status bar
// already says "ended"; screaming about it would cry wolf and train the operator
// to ignore the banner that matters.
export function AlertBanner({ posture, now }) {
  if (!posture.failOpen || posture.leashd.ended) return null;
  return (
    <div className="banner" role="alert">
      <span className="label">fail-open</span>
      <span>enforcement is NOT in effect</span>
      <span className="detail">
        {posture.openWindows.map((w) => (
          <span key={w.layer}>
            {w.layer}: {w.reason ?? 'down'}
            {Number.isFinite(now - w.since) ? ` · ${Math.max(0, Math.round(now - w.since))}s` : ''}
            {'  '}
          </span>
        ))}
      </span>
    </div>
  );
}
