import contextlib
import json
import os
from pathlib import Path
import queue
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch

import lldb
from GUI.server.engine import Engine
from macdbg.core import state
from macdbg.core.address import resolve
from .support import AgentProcess, FIXTURE_DIR, ROOT, run_core_probe

FIXTURE = FIXTURE_DIR / "workflow_fixture"


class WorkflowTests(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory(prefix="md-workflow-", dir="/private/tmp")
        self.addCleanup(self.scratch.cleanup)
        self.directory = Path(self.scratch.name)
        state_patch = patch.object(state, "STATE_DIR", str(self.directory))
        state_patch.start()
        self.addCleanup(state_patch.stop)
        self.env = {"MACDBG_STATE_DIR": str(self.directory), "PYTHONDONTWRITEBYTECODE": "1"}

    @contextlib.contextmanager
    def gui(self, mode="io"):
        engine = Engine(str(FIXTURE), [mode])
        engine.start()
        events = engine.subscribe()
        try:
            self.until(events, lambda e: e.get("t") == "state" and e.get("pc"))
            yield engine, events
        finally:
            engine.shutdown()

    def until(self, events, predicate, timeout=15):
        deadline = time.monotonic() + timeout
        tail = []
        while time.monotonic() < deadline:
            try:
                event = events.get(timeout=0.25)
            except queue.Empty:
                continue
            tail.append(event)
            if predicate(event):
                return event
        self.fail("Missing event: {!r}".format(tail[-3:]))

    def sync(self, engine, name, args=None):
        engine.command(name, args or {})
        return engine._run_sync(lambda: None)

    def test_classic_exec_pending_decision_blocks_every_resume_path(self):
        with self.gui("exec") as (engine, events):
            self.sync(engine, "defense", {"key": "exec_sandbox"})
            self.sync(engine, "defense", {"key": "exec_interactive"})
            engine.command("cont", {})
            prompt = self.until(events, lambda e: e.get("t") == "prompt")
            self.assertEqual(prompt["name"], "system")
            pc = engine._run_sync(engine.dbg.pc)
            for command, args in (("cont", {}), ("step_in", {}), ("step_over", {}),
                                  ("step_out", {}), ("run_to", {"addr": pc + 4}),
                                  ("run_cmd", {"cmd": "c"}), ("run_cmd", {"cmd": "run"})):
                with self.subTest(command=command, args=args):
                    self.sync(engine, command, args)
                    self.assertEqual(engine._run_sync(engine.dbg.pc), pc)
                    self.assertIsNotNone(engine._pending_exec)
            with self.assertRaisesRegex(RuntimeError, "decision is pending"):
                engine._run_sync(engine.dbg.cont)
            ok, _, error = engine._run_sync(engine.dbg.handle_command, "script print('UNEXPECTED')")
            self.assertFalse(ok)
            self.assertIn("decision is pending", error)
            engine.command("decide_exec", {"decision": "fake", "token": prompt["token"]})
            exited = self.until(events, lambda e: e.get("process_state") == "exited")
            self.assertEqual(exited["exit_code"], 0)
            self.assertIsNone(exited["pending_decision"])

    def test_breakpoints_autosave_restore_and_survive_target_replacement(self):
        with self.gui() as (engine, events):
            address = engine._run_sync(resolve, engine.dbg, "workflow_marker")[0]["addr"]
            self.sync(engine, "toggle_bp", {"addr": address})
            path = Path(engine.dbg.state.file_path())
            stored = json.loads(path.read_text())
            self.assertEqual(stored["breakpoints"][0]["addr"], address)
            self.sync(engine, "open_target", {"path": str(FIXTURE), "args": ["io"]})
            rows = engine._run_sync(lambda: engine.dbg.breakpoints(engine._hidden_bp_ids()))
            self.assertEqual(len(rows), 1, rows)
            engine.command("cont", {})
            stopped = self.until(events, lambda e: e.get("process_state") == "stopped" and e.get("pc") == int(address, 16))
            self.assertEqual(stopped["pc"], int(address, 16))
        with self.gui() as (engine, events):
            rows = engine._run_sync(lambda: engine.dbg.breakpoints(engine._hidden_bp_ids()))
            self.assertEqual(len(rows), 1, rows)

    def test_exit_snapshot_has_terminal_state_and_restart_action(self):
        with self.gui() as (engine, events):
            engine.command("cont", {})
            exited = self.until(events, lambda e: e.get("process_state") == "exited")
            self.assertEqual(exited["exit_code"], 0)
            self.assertTrue(exited["can_restart"])
            self.assertFalse(exited["running"])

    def test_navigation_resolves_symbols_and_register_offsets_without_executing(self):
        with self.gui() as (engine, events):
            pc = engine._run_sync(engine.dbg.pc)
            values = engine.command("resolve_address", {"expression": "$pc + 4"})
            self.assertEqual(values["result"][0]["addr"], hex(pc + 4))
            symbol = engine.command("resolve_address", {"expression": "workflow_marker"})
            self.assertEqual(len(symbol["result"]), 1, symbol)
            self.sync(engine, "follow_disasm", {"addr": symbol["result"][0]["addr"]})
            self.assertEqual(engine._run_sync(engine.dbg.pc), pc)
            failed = engine.command("resolve_address", {"expression": "system(\"echo no\")"})
            self.assertFalse(failed["ok"])
            self.assertEqual(engine._run_sync(engine.dbg.pc), pc)
            for expression in ("-1", "0x10000000000000000"):
                self.assertFalse(engine.command("resolve_address", {"expression": expression})["ok"])

    def test_trace_and_console_are_replayed_to_a_late_subscriber(self):
        with self.gui() as (engine, events):
            self.sync(engine, "trace_toggle")
            engine.command("cont", {})
            self.until(events, lambda e: e.get("process_state") == "exited")
            replay = engine.subscribe()
            try:
                trace = self.until(replay, lambda e: e.get("t") == "trace_snapshot")
                self.assertGreaterEqual(trace["total"], 4)
                self.assertEqual(len(Path(trace["path"]).read_text().splitlines()), trace["total"])
                self.assertTrue(trace["hits"][0]["caller"])
                self.assertGreater(trace["hits"][0]["pid"], 0)
                console = self.until(replay, lambda e: e.get("t") == "console_snapshot")
                text = "\n".join(row["text"] for row in console["rows"])
                self.assertIn("launched ", text)
                self.assertIn("WORKFLOW_COMPLETE", text)
            finally:
                engine.unsubscribe(replay)

    def test_memory_scan_cancellation_leaves_target_stopped(self):
        with self.gui() as (engine, events):
            pc = engine._run_sync(engine.dbg.pc)
            with self.assertRaisesRegex(InterruptedError, "cancelled"):
                engine._run_sync(lambda: engine.dbg.memory_search(b"needle", scope="all", cancelled=lambda: True))
            self.assertEqual(engine._run_sync(engine.dbg.pc), pc)

    def test_loader_stop_can_protect_constructor_ptrace(self):
        result = run_core_probe('''
            import json, os
            from macdbg.agent.session import AgentSession
            from tests.integration.test_workflow import FIXTURE
            os.environ['MACDBG_TEST_EARLY_PTRACE'] = '1'
            s = AgentSession(str(FIXTURE), ['io'], stop_at='loader')
            try:
                boot = s.start()
                assert boot['event'] == 'stop', boot
                assert s.cmd_status()['before_initializers']
                assert s.dispatch('defense_enable', {'name':'anti_ptrace'})['ok']
                result = s.dispatch('continue', {'timeout':10})
                print(json.dumps(result))
            finally:
                s.shutdown(save=False)
        ''')
        self.assertEqual(result["event"], "exited", result)
        self.assertEqual(result["exit"]["code"], 0, result)
        self.assertIn("blocked ptrace", result["console"])

    def test_loader_syscall_hooks_resolve_without_leaking_user_breakpoints(self):
        result = run_core_probe('''
            import json, os
            from macdbg.agent.session import AgentSession
            from tests.integration.test_workflow import FIXTURE
            os.environ['MACDBG_TEST_EARLY_PTRACE'] = 'syscall'
            s = AgentSession(str(FIXTURE), ['io'], stop_at='loader')
            try:
                assert s.start()['event'] == 'stop'
                assert s.dispatch('defense_enable', {'name':'anti_ptrace'})['ok']
                result = s.dispatch('continue', {'timeout':10})
                result['saved_user_bps'] = len(s.dbg.snapshot_user_breakpoints(s._hidden_bp_ids()))
                print(json.dumps(result))
            finally:
                s.shutdown(save=False)
        ''')
        self.assertEqual(result['event'], 'exited', result)
        self.assertEqual(result['exit']['code'], 0, result)
        self.assertIn('via syscall()', result['console'])
        self.assertEqual(result['saved_user_bps'], 0)

    def test_fstat_is_decoded_as_a_descriptor(self):
        with AgentProcess(FIXTURE, "io", env=self.env) as agent:
            self.assertTrue(agent.cmd("tracer_enable")["ok"])
            result = agent.continue_to_exit()
            self.assertEqual(result["exit"]["code"], 0, result)
            rows = agent.cmd("trace_hits")["hits"]
            calls = [row["call"] for row in rows]
            self.assertTrue(any(call.startswith("fstat(fd=") for call in calls), calls)
            self.assertFalse(any('stat("<unreadable>")' in call for call in calls), calls)

    def test_headless_exec_and_fork_choices_resume_after_explicit_decision(self):
        for mode, defense, decision in (("exec", "exec_sandbox", "fake"), ("fork", "fork_identity", "child")):
            with self.subTest(mode=mode), AgentProcess(FIXTURE, mode, env=self.env) as agent:
                self.assertTrue(agent.cmd("defense_enable", {"name": defense})["ok"])
                self.assertTrue(agent.cmd(mode + "_mode", {"interactive": True})["ok"])
                stopped = agent.continue_to_exit()
                self.assertEqual(stopped["event"], "pending_decision", stopped)
                self.assertFalse(agent.cmd("continue", {"timeout": 1})["ok"])
                result = agent.cmd("decide_" + mode, {"decision": decision})
                self.assertEqual(result["event"], "exited", result)
                self.assertEqual(result["exit"]["code"], 0, result)
                if mode == "fork":
                    self.assertIn("BENIGN_CHILD_PATH", result["console"])
                else:
                    self.assertNotIn("BENIGN_EXECUTED", result["console"])

    def test_shipped_interposer_preserves_modes_errno_and_invalid_pointer_errors(self):
        def run(path, interpose):
            env = os.environ.copy()
            if interpose:
                env.update(DYLD_INSERT_LIBRARIES=str(ROOT / "macdbg/native/interpose.dylib"),
                           MACDBG_TRACE_OUT=str(self.directory / "trace.tsv"))
            return subprocess.run([str(FIXTURE), "create", str(path)], env=env,
                                  capture_output=True, text=True, timeout=10)
        baseline = run(self.directory / "baseline", False)
        traced = run(self.directory / "traced", True)
        self.assertEqual(baseline.returncode, 0, baseline.stderr)
        self.assertEqual(traced.returncode, 0, traced.stderr)
        self.assertEqual(traced.stdout, baseline.stdout)
        self.assertIn("mode=0600", traced.stdout)
        self.assertIn("\topen\t", (self.directory / "trace.tsv").read_text())


if __name__ == "__main__":
    unittest.main()
