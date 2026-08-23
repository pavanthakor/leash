import { useEffect, useRef, useState } from 'react';

// Subscribes to the bridge's SSE stream. Holds exactly what the stream sent --
// on reset it drops everything rather than merging two sessions, and it never
// fabricates an event to cover a gap.
export function useEventStream(url = '/api/stream') {
  const [events, setEvents] = useState([]);
  const [connected, setConnected] = useState(false);
  const [present, setPresent] = useState(null);   // null = not yet known
  const seen = useRef(new Set());

  useEffect(() => {
    const es = new EventSource(url);

    const reset = () => { seen.current = new Set(); setEvents([]); };

    es.onopen = () => setConnected(true);
    es.onerror = () => setConnected(false);

    es.addEventListener('reset', () => reset());

    es.addEventListener('beat', (m) => {
      try { setPresent(JSON.parse(m.data).present); } catch { /* ignore */ }
    });

    es.addEventListener('batch', (m) => {
      let batch;
      try { batch = JSON.parse(m.data); } catch { return; }
      if (!Array.isArray(batch) || !batch.length) return;
      setPresent(true);

      // A session_start at seq 0 means a new leashd run: the previous session's
      // events are not part of this one. Belt-and-braces with the bridge's own
      // reset detection -- whichever notices first, the console never splices.
      const startIdx = batch.findIndex((e) => e.type === 'session_start' && e.seq === 0);
      if (startIdx !== -1) {
        seen.current = new Set();
        const tail = batch.slice(startIdx);
        tail.forEach((e) => seen.current.add(e.seq));
        setEvents(tail);
        return;
      }

      const fresh = batch.filter((e) => !seen.current.has(e.seq));
      if (!fresh.length) return;
      fresh.forEach((e) => seen.current.add(e.seq));
      setEvents((prev) => [...prev, ...fresh].sort((a, b) => a.seq - b.seq));
    });

    return () => es.close();
  }, [url]);

  return { events, connected, present };
}
