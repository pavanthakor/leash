#!/usr/bin/env python3
"""leash-bridge -- read-only SSE view of leashd's event stream.

Strictly downstream. It opens the JSON-lines stream with mode "r" and never
writes it, never signals leashd, never touches a BPF map or a loader. If this
process dies, enforcement is completely unaffected -- that asymmetry is the
point (charter invariant 3). Loopback only, no authentication because nothing
here is privileged and nothing is mutable.

  python3 leash_bridge.py [--port 8765] [--events PATH] [--dist DIR]

Session-reset detection. leashd calls open(EVENTS, "w"), which truncates in
place, so the inode is frequently REUSED across restarts -- watching st_ino
alone silently concatenates two sessions into one. Watching size alone misses a
rotation that lands on the same length. But inode+size is ALSO insufficient:
replaying the two real captures showed a session whose replacement is LARGER
than the bytes already consumed (reattach 37891B -> full 54859B, same inode)
trips neither test, and the tailer resumes mid-file, splicing two sessions into
one stream. So identity is anchored in the CONTENT of line 1 -- leashd's
session_start, unique per run by pid and ts:

    reset  <=>  st_ino changed
            OR  st_size < bytes already consumed
            OR  line 1 differs from the line 1 we started reading from

See test_bridge.py::test_reset_on_truncate_in_place_same_inode.

Empty stream, missing file, and a stream that simply stops (session-reattach
has no session_end) are all rendered as themselves. The bridge never
synthesises an event to fill a gap.
"""
import argparse
import json
import os
import sys
import threading
import time
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler

POLL_SECONDS = 0.25
DEFAULT_EVENTS = os.path.expanduser("~/leash-demo/leashd.events.jsonl")


class Tailer:
    """Follows one JSON-lines file. Read-only, restart-aware."""

    ANCHOR_BYTES = 1024        # line 1 (session_start) is ~250B; 1KB is ample

    def __init__(self, path):
        self.path = path
        self.offset = 0
        self.inode = None
        self.partial = ""
        self.anchor = None     # first line of the session currently being read

    def _read_anchor(self):
        """First line of the file, or None if not yet readable/complete."""
        try:
            with open(self.path, "r") as fh:
                head = fh.read(self.ANCHOR_BYTES)
        except OSError:
            return None
        line, sep, _ = head.partition("\n")
        return line if sep else None

    def _stat(self):
        try:
            st = os.stat(self.path)
            return st.st_ino, st.st_size
        except OSError:
            return None, None

    def poll(self):
        """-> (events, reset, present). Never raises on a missing or half-written file."""
        inode, size = self._stat()
        if inode is None:
            was = self.inode is not None
            self.offset, self.inode, self.partial = 0, None, ""
            return [], was, False

        anchor = self._read_anchor()
        reset = False
        if self.inode is not None:
            rotated = inode != self.inode                       # a different file
            shrank = size < self.offset                         # truncated shorter
            # Same inode, same-or-larger size, but a different session_start line:
            # leashd truncated in place and wrote a longer run. Only content sees it.
            rewritten = (self.anchor is not None and anchor is not None
                         and anchor != self.anchor)
            if rotated or shrank or rewritten:
                reset = True
                self.offset, self.partial, self.anchor = 0, "", None
        else:
            self.offset, self.partial, self.anchor = 0, "", None
        self.inode = inode
        if self.anchor is None and anchor is not None:
            self.anchor = anchor

        if size == self.offset:
            return [], reset, True

        try:
            with open(self.path, "r") as fh:      # read-only, always
                fh.seek(self.offset)
                chunk = fh.read()
                self.offset = fh.tell()
        except OSError:
            return [], reset, True

        data = self.partial + chunk
        lines = data.split("\n")
        self.partial = lines.pop()                # trailing partial line, if any

        events = []
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                continue                          # half-flushed line; it will not reappear
            if ev.get("type") == "session_start" and ev.get("seq") == 0 and events:
                reset = True                      # a fresh session began mid-batch
                events = []
            events.append(ev)
        return events, reset, True


class Handler(SimpleHTTPRequestHandler):
    events_path = DEFAULT_EVENTS
    dist_dir = None

    def log_message(self, fmt, *args):            # quiet; this is a demo surface
        pass

    def translate_path(self, path):
        if self.dist_dir:
            rel = path.split("?", 1)[0].lstrip("/") or "index.html"
            full = os.path.normpath(os.path.join(self.dist_dir, rel))
            if not full.startswith(os.path.abspath(self.dist_dir)):
                return self.dist_dir            # no traversal out of dist/
            if not os.path.exists(full):
                return os.path.join(self.dist_dir, "index.html")   # SPA fallback
            return full
        return super().translate_path(path)

    def do_GET(self):
        route = self.path.split("?", 1)[0]
        if route == "/api/health":
            return self._json({
                "ok": True,
                "events_path": self.events_path,
                "present": os.path.exists(self.events_path),
                "readonly": True,
            })
        if route == "/api/stream":
            return self._sse()
        if self.dist_dir is None:
            return self._json({"error": "no dist/ built; run npm run build"}, code=404)
        return super().do_GET()

    def _json(self, payload, code=200):
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _sse(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.send_header("X-Accel-Buffering", "no")
        self.end_headers()

        tailer = Tailer(self.events_path)
        last_beat = 0.0
        try:
            while True:
                events, reset, present = tailer.poll()
                if reset:
                    self._emit("reset", {"reason": "new session detected"})
                if events:
                    self._emit("batch", events)
                now = time.monotonic()
                if now - last_beat > 10:
                    self._emit("beat", {"present": present})
                    last_beat = now
                time.sleep(POLL_SECONDS)
        except (BrokenPipeError, ConnectionResetError):
            return

    def _emit(self, name, payload):
        self.wfile.write(f"event: {name}\ndata: {json.dumps(payload)}\n\n".encode())
        self.wfile.flush()


def main(argv=None):
    ap = argparse.ArgumentParser(description="read-only SSE bridge for leashd events")
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--events", default=os.environ.get("LEASH_EVENTS", DEFAULT_EVENTS))
    ap.add_argument("--dist", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "dist"))
    args = ap.parse_args(argv)

    dist = os.path.abspath(args.dist)
    Handler.events_path = os.path.abspath(os.path.expanduser(args.events))
    Handler.dist_dir = dist if os.path.isdir(dist) else None

    srv = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)   # loopback only
    print(f"leash-bridge  http://127.0.0.1:{args.port}")
    print(f"  events : {Handler.events_path} (read-only)")
    print(f"  dist   : {Handler.dist_dir or '(not built -- run npm run build)'}")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nbridge down (enforcement unaffected -- this process never touched it)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
