import contextlib
import io
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from macdbg.agent import __main__ as agent_main


class AgentStartupCleanupTests(unittest.TestCase):
    def test_stop_cleans_stale_metadata_even_if_pid_has_been_reused(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(agent_main, "SESSIONS_ROOT", tmp):
            directory = Path(tmp, "stale")
            directory.mkdir()
            meta = directory / "meta.json"
            meta.write_text(json.dumps({"pid": os.getpid(), "socket": str(directory / "ctl.sock")}))
            with mock.patch.object(os, "kill") as kill, contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(agent_main.cmd_stop(SimpleNamespace(session="stale")), 0)
            kill.assert_not_called()
            self.assertFalse(meta.exists())

    def test_unresponsive_session_keeps_its_control_files(self):
        from macdbg.agent.client import ClientError

        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(agent_main, "SESSIONS_ROOT", tmp):
            directory = Path(tmp, "busy")
            directory.mkdir()
            meta = directory / "meta.json"
            meta.write_text(json.dumps({"pid": os.getpid(), "socket": str(directory / "ctl.sock")}))
            with mock.patch("macdbg.agent.client.send_command", side_effect=ClientError("timeout")), \
                    mock.patch.object(os, "kill") as kill, contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(agent_main.cmd_stop(SimpleNamespace(session="busy")), 1)
            kill.assert_not_called()
            self.assertTrue(meta.exists())

    def test_start_checks_the_socket_even_when_metadata_is_missing(self):
        with tempfile.TemporaryDirectory(dir="/private/tmp") as tmp, mock.patch.object(agent_main, "SESSIONS_ROOT", tmp):
            directory = Path(tmp, "busy")
            directory.mkdir()
            path = directory / "ctl.sock"
            args = SimpleNamespace(session="busy", program=None, attach=None)
            with socket.socket(socket.AF_UNIX) as listener:
                listener.bind(str(path))
                listener.listen()
                with mock.patch.object(agent_main, "_cmd_start_locked") as launch, contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(agent_main.cmd_start(args), 1)
                launch.assert_not_called()
                self.assertTrue(path.exists())

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
