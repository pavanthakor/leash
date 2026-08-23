// Enforcement posture derived from the stream. Every field is observed; when
// the stream does not say, the value is null and the UI renders "—" rather
// than guessing.
export function derivePosture(events) {
  const start = events.find((e) => e.type === 'session_start') ?? null;
  const policy = events.find((e) => e.type === 'policy') ?? null;
  const discover = events.find((e) => e.type === 'discover') ?? null;
  const end = events.find((e) => e.type === 'session_end') ?? null;

  // Per-layer enforcer state. attached -> up; down / failopen(open) -> down;
  // reattach / failopen(closed) -> up again. Last event wins.
  const layers = {};
  for (const l of ['file', 'egress']) layers[l] = { attached: false, since: null, reason: null };
  for (const e of events) {
    const L = layers[e.layer];
    if (!L) continue;
    if (e.type === 'attached' || e.type === 'reattach') {
      L.attached = true; L.since = e.ts; L.reason = null;
    } else if (e.type === 'down') {
      L.attached = false; L.since = e.ts; L.reason = `loader exited (rc ${e.returncode})`;
    } else if (e.type === 'failopen') {
      if (e.window === 'open') { L.attached = false; L.since = e.ts; L.reason = e.reason ?? 'fail-open'; }
      else { L.attached = true; L.since = e.ts; L.reason = null; }
    }
  }

  const openWindows = Object.entries(layers)
    .filter(([, v]) => !v.attached && v.since != null)
    .map(([layer, v]) => ({ layer, since: v.since, reason: v.reason }));

  // cgid history: the session event announces it, each resync moves it.
  const cgids = [];
  for (const e of events) {
    if (e.type === 'session' && e.cgid != null && !cgids.includes(e.cgid)) cgids.push(e.cgid);
    if (e.type === 'resync') {
      if (!cgids.includes(e.old_cgid)) cgids.push(e.old_cgid);
      if (!cgids.includes(e.new_cgid)) cgids.push(e.new_cgid);
    }
  }
  // Protected inode identity as the kernel reported it (not from the policy path).
  const fileEvent = events.find((e) => (e.type === 'deny' || e.type === 'debug') && e.layer === 'file');

  const counts = { deny: 0, allow: 0, resync: 0 };
  for (const e of events) if (counts[e.type] !== undefined) counts[e.type] += 1;

  return {
    leashd: {
      pid: start?.pid ?? null,
      startedTs: start?.ts ?? null,
      policyPath: start?.policy ?? null,
      ended: end ? { ts: end.ts, signal: end.signal } : null,
    },
    policy: {
      version: policy ? 1 : null,     // policy.yaml is version: 1; leashd emits no hash
      protect: policy?.files ?? [],
      allow: policy?.egress ?? [],
      defaultEgress: policy ? 'deny' : null,
    },
    session: {
      unit: discover?.unit ?? null,
      cgroup: discover?.cgroup ?? null,
      cgid: cgids.length ? cgids[cgids.length - 1] : null,
      prevCgid: cgids.length > 1 ? cgids[cgids.length - 2] : null,
      dev: fileEvent?.dev ?? null,
      ino: fileEvent?.ino ?? null,
    },
    layers,
    openWindows,
    failOpen: openWindows.length > 0,
    counts,
  };
}

export function fmtUptime(seconds) {
  if (seconds == null || !Number.isFinite(seconds) || seconds < 0) return '—';
  const s = Math.floor(seconds);
  const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60), sec = s % 60;
  return h > 0
    ? `${h}:${String(m).padStart(2, '0')}:${String(sec).padStart(2, '0')}`
    : `${String(m).padStart(2, '0')}:${String(sec).padStart(2, '0')}`;
}
