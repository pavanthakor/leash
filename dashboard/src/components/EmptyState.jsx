import React from 'react';

// Never invents events. States exactly which of the two things is missing.
export function EmptyState({ connected, present }) {
  return (
    <div className="empty">
      {!connected ? (
        <>
          <div className="lead">bridge not reachable</div>
          <div>start it with <code>python3 bridge/leash_bridge.py</code></div>
        </>
      ) : present === false ? (
        <>
          <div className="lead">no event stream on disk</div>
          <div>leashd has not run yet — it creates the stream on start</div>
        </>
      ) : (
        <>
          <div className="lead">stream is empty</div>
          <div>waiting for leashd to emit its first event</div>
        </>
      )}
    </div>
  );
}
