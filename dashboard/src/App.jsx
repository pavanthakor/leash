import React, { useEffect, useMemo, useState } from 'react';
import { useEventStream } from './hooks/useEventStream.js';
import { buildChains, heroChain } from './lib/chains.js';
import { toRows } from './lib/normalize.js';
import { derivePosture } from './lib/posture.js';
import { StatusBar } from './components/StatusBar.jsx';
import { AlertBanner } from './components/AlertBanner.jsx';
import { SessionSidebar } from './components/SessionSidebar.jsx';
import { CausalChain } from './components/CausalChain.jsx';
import { EventTable } from './components/EventTable.jsx';
import { EmptyState } from './components/EmptyState.jsx';

export default function App() {
  const { events, connected, present } = useEventStream();
  const [now, setNow] = useState(() => Date.now() / 1000);

  useEffect(() => {
    const id = setInterval(() => setNow(Date.now() / 1000), 1000);
    return () => clearInterval(id);
  }, []);

  const posture = useMemo(() => derivePosture(events), [events]);
  const rows = useMemo(() => toRows(events), [events]);
  const hero = useMemo(() => heroChain(buildChains(events).chains), [events]);

  return (
    <div className="console">
      <h1 className="sr-only">leash containment console</h1>
      <StatusBar posture={posture} now={now} connected={connected} />
      <AlertBanner posture={posture} now={now} />
      {events.length === 0 ? (
        <EmptyState connected={connected} present={present} />
      ) : (
        <>
          <div className="body">
            <SessionSidebar posture={posture} />
            <CausalChain chain={hero} />
          </div>
          <EventTable rows={rows} />
        </>
      )}
    </div>
  );
}
