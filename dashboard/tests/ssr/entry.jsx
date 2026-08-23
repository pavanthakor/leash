// SSR harness: renders the real presentational components with props derived
// from a real capture, so the render path is exercised without a browser.
// Feeds the components directly (not through useEventStream, which needs
// EventSource) -- the hook is covered separately by the bridge tests.
import React from 'react';
import { renderToString } from 'react-dom/server';
import { StatusBar } from '../../src/components/StatusBar.jsx';
import { AlertBanner } from '../../src/components/AlertBanner.jsx';
import { SessionSidebar } from '../../src/components/SessionSidebar.jsx';
import { CausalChain } from '../../src/components/CausalChain.jsx';
import { EventTable } from '../../src/components/EventTable.jsx';
import { EmptyState } from '../../src/components/EmptyState.jsx';
import { derivePosture } from '../../src/lib/posture.js';
import { toRows } from '../../src/lib/normalize.js';
import { buildChains, heroChain } from '../../src/lib/chains.js';

export function renderConsole(events, now = 0) {
  const posture = derivePosture(events);
  const hero = heroChain(buildChains(events).chains);
  return renderToString(
    <div className="console">
      <StatusBar posture={posture} now={now} connected />
      <AlertBanner posture={posture} now={now} />
      <div className="body">
        <SessionSidebar posture={posture} />
        <CausalChain chain={hero} />
      </div>
      <EventTable rows={toRows(events)} />
    </div>,
  );
}

export function renderEmpty(connected, present) {
  return renderToString(<EmptyState connected={connected} present={present} />);
}
