import contextlib
import io
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from macdbg.agent import __main__ as agent_main


class AgentStartupCleanupTests(unittest.TestCase):
    def test_pre_metadata_timeout_terminates_and_reaps_owned_daemon(self):
        real_popen = subprocess.Popen
        started = []

        def start_sleeper(_argv, **_kwargs):
            proc = real_popen(
                [sys.executable, "-c", "import time; time.sleep(60)"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                start_new_session=True)
            started.append(proc)
            return proc

        with tempfile.TemporaryDirectory() as tmp:
            session_dir = Path(tmp) / "pre_meta_timeout"
            session_dir.mkdir()
            ns = SimpleNamespace(attach=None, program=None, args=[],
                                 boot_timeout=0.01)
            try:
                with mock.patch.object(agent_main.subprocess, "Popen",
                                       side_effect=start_sleeper):
                    with contextlib.redirect_stdout(io.StringIO()):
                        result = agent_main._cmd_start_locked(
                            ns, "pre_meta_timeout", str(session_dir))

                self.assertEqual(result, 1)
                self.assertEqual(len(started), 1)
                pid = started[0].pid
                self.assertIsNotNone(
                    started[0].poll(),
                    "pre-metadata timeout left owned daemon pid {} alive".format(
                        pid))
                with self.assertRaises(ProcessLookupError):
                    os.kill(pid, 0)
                self.assertFalse((session_dir / "meta.json").exists())
                self.assertFalse((session_dir / "ctl.sock").exists())
            finally:
                for proc in started:
                    if proc.poll() is None:
                        proc.terminate()
                        try:
                            proc.wait(timeout=2)
                        except subprocess.TimeoutExpired:
                            proc.kill()
                            proc.wait(timeout=2)


if __name__ == "__main__":
    unittest.main()
