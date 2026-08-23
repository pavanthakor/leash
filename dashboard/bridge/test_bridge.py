#!/usr/bin/env python3
"""Bridge tests. The two REAL captures are replayed as two genuine sessions --
no hand-written events anywhere (charter invariant 1). Positive and negative
controls for each behaviour (invariant 2).

    python3 bridge/test_bridge.py
"""
import json
import os
import shutil
import tempfile
import unittest

from leash_bridge import Tailer

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURES = os.path.abspath(os.path.join(HERE, "..", "..", "fixtures"))
FULL = os.path.join(FIXTURES, "session-full.jsonl")
REATTACH = os.path.join(FIXTURES, "session-reattach.jsonl")


def lines(path):
    with open(path) as fh:
        return [l for l in fh.read().split("\n") if l.strip()]


class TailerTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="leash-bridge-test-")
        self.path = os.path.join(self.dir, "leashd.events.jsonl")
        self.addCleanup(shutil.rmtree, self.dir)

    def write(self, src_lines, mode="w"):
        """Mimic leashd exactly: open(path, 'w') truncates IN PLACE."""
        with open(self.path, mode) as fh:
            for l in src_lines:
                fh.write(l + "\n")

    # ------------------------------------------------------------ empty states
    def test_missing_file_invents_nothing(self):
        t = Tailer(self.path)
        events, reset, present = t.poll()
        self.assertEqual(events, [])
        self.assertFalse(present)
        self.assertFalse(reset)

    def test_empty_file_invents_nothing(self):
        open(self.path, "w").close()
        events, reset, present = Tailer(self.path).poll()
        self.assertEqual(events, [])
        self.assertTrue(present)

    # ------------------------------------------------------------ plain tail
    def test_reads_whole_real_capture(self):
        full = lines(FULL)
        self.write(full)
        events, reset, present = Tailer(self.path).poll()
        self.assertEqual(len(events), 172)
        self.assertEqual(events[0]["type"], "session_start")
        self.assertEqual(events[0]["seq"], 0)
        self.assertEqual([e["seq"] for e in events], list(range(172)))
        self.assertTrue(present)

    def test_incremental_append_yields_only_new(self):
        full = lines(FULL)
        self.write(full[:50])
        t = Tailer(self.path)
        first, _, _ = t.poll()
        self.assertEqual(len(first), 50)
        self.write(full[50:], mode="a")
        second, reset, _ = t.poll()
        self.assertEqual(len(second), 122)
        self.assertFalse(reset)                       # NEGATIVE: append is not a reset
        self.assertEqual(second[0]["seq"], 50)

    def test_partial_line_is_held_until_complete(self):
        full = lines(FULL)
        self.write(full[:10])
        with open(self.path, "a") as fh:
            fh.write(full[10][:40])                   # half a line, mid-flush
        t = Tailer(self.path)
        events, _, _ = t.poll()
        self.assertEqual(len(events), 10)             # NEGATIVE: no torn event emitted
        with open(self.path, "a") as fh:
            fh.write(full[10][40:] + "\n")
        events2, _, _ = t.poll()
        self.assertEqual(len(events2), 1)
        self.assertEqual(events2[0]["seq"], 10)

    # ------------------------------------------------- session reset detection
    def test_reset_on_truncate_in_place_same_inode(self):
        """The case that matters: leashd's open('w') reuses the inode."""
        self.write(lines(REATTACH))
        t = Tailer(self.path)
        first, _, _ = t.poll()
        self.assertEqual(len(first), 128)
        ino_before = os.stat(self.path).st_ino

        self.write(lines(FULL))                       # truncate in place, new session
        ino_after = os.stat(self.path).st_ino
        self.assertEqual(ino_before, ino_after,
                         "test premise: inode was reused, so size must catch it")

        second, reset, _ = t.poll()
        self.assertTrue(reset, "same-inode truncate must be detected as a reset")
        self.assertEqual(len(second), 172)
        self.assertEqual(second[0]["seq"], 0)

    def test_reset_on_inode_swap(self):
        self.write(lines(FULL))
        t = Tailer(self.path)
        t.poll()
        os.remove(self.path)                          # replaced by a different file
        self.write(lines(REATTACH))
        self.assertNotEqual(t.inode, os.stat(self.path).st_ino)
        events, reset, _ = t.poll()
        self.assertTrue(reset)
        self.assertEqual(len(events), 128)

    def test_shrink_to_shorter_session_detected(self):
        """Larger session replaced by a smaller one: size < consumed offset."""
        self.write(lines(FULL))                       # 172 lines
        t = Tailer(self.path)
        t.poll()
        self.write(lines(REATTACH))                   # 128 lines, in place
        events, reset, _ = t.poll()
        self.assertTrue(reset)
        self.assertEqual(len(events), 128)

    def test_no_false_reset_on_steady_stream(self):
        """NEGATIVE: nothing about a normal growing file may look like a reset."""
        full = lines(FULL)
        t = Tailer(self.path)
        self.write(full[:1])
        t.poll()
        for i in range(1, len(full)):
            self.write([full[i]], mode="a")
            _, reset, _ = t.poll()
            self.assertFalse(reset, f"false reset while appending line {i}")

    def test_file_disappearing_then_returning(self):
        self.write(lines(FULL))
        t = Tailer(self.path)
        t.poll()
        os.remove(self.path)
        events, reset, present = t.poll()
        self.assertFalse(present)
        self.assertTrue(reset)
        self.assertEqual(events, [])                  # NEGATIVE: no invented events
        self.write(lines(REATTACH))
        events, _, present = t.poll()
        self.assertTrue(present)
        self.assertEqual(len(events), 128)

    # ------------------------------------------------------------ read-only
    def test_tailer_never_writes(self):
        self.write(lines(FULL))
        before = os.stat(self.path)
        t = Tailer(self.path)
        for _ in range(5):
            t.poll()
        after = os.stat(self.path)
        self.assertEqual(before.st_size, after.st_size)
        self.assertEqual(before.st_mtime_ns, after.st_mtime_ns)
        self.assertEqual(before.st_ino, after.st_ino)

    def test_read_only_file_is_still_tailable(self):
        """A stream owned by root and mode 0644 must be readable by this user."""
        self.write(lines(FULL))
        os.chmod(self.path, 0o444)
        events, _, _ = Tailer(self.path).poll()
        self.assertEqual(len(events), 172)


if __name__ == "__main__":
    unittest.main(verbosity=2)
