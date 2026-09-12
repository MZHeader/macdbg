import json
from pathlib import Path
import tempfile
import unittest

from macdbg.core.trace_log import TraceLog


class TraceLogTests(unittest.TestCase):
    def test_live_window_is_bounded_and_full_export_is_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            log = TraceLog(lambda: directory, capacity=3)
            for n in range(10):
                log.append("FILE", "open({})".format(n), pid=7, tid=9, caller="0x1234")
            replay = log.snapshot()
            self.assertEqual([row["n"] for row in replay["hits"]], [8, 9, 10])
            self.assertEqual(replay["first_available"], 8)
            rows = [json.loads(line) for line in Path(replay["path"]).read_text().splitlines()]
            self.assertEqual(len(rows), 10)
            self.assertEqual(rows[0]["caller"], "0x1234")
            self.assertTrue(rows[0]["timestamp"])
            self.assertEqual(Path(replay["path"]).stat().st_mode & 0o777, 0o600)
            self.assertEqual(len(log.snapshot(since=9)["hits"]), 1)
            log.reset()
            self.assertEqual(log.snapshot()["hits"], [])
            self.assertTrue(Path(replay["path"]).is_file())
            self.assertNotEqual(log.epoch, replay["epoch"])
