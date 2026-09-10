import sys
import types
import unittest
from unittest import mock


FAKE_LLDB = types.SimpleNamespace(
    eStopReasonBreakpoint=3,
    eStateStopped=5,
    eStateCrashed=8,
    eStateExited=10,
)

with mock.patch.dict(sys.modules, {"lldb": FAKE_LLDB}):
    from GUI.server.engine import Engine
    from macdbg.agent.session import AgentSession
    from macdbg.core.events import StopEvent


CRITICAL = "sysctlbyname(hw.model) could not write result buffer; cloak failed"


class FakeCloak:
    def validate_resume(self):
        return False, CRITICAL


class FakeThread:
    def IsValid(self):
        return True

    def GetStopReason(self):
        return FAKE_LLDB.eStopReasonBreakpoint

    def GetStopReasonDataCount(self):
        return 2

    def GetStopReasonDataAtIndex(self, index):
        return 91 if index == 0 else 1


class FakeProcess:
    def __init__(self):
        self.thread = FakeThread()

    def IsValid(self):
        return True

    def GetState(self):
        return FAKE_LLDB.eStateStopped

    def GetSelectedThread(self):
        return self.thread


class FakeDebugger:
    def __init__(self):
        self.process = FakeProcess()
        self.analysis_cloak = FakeCloak()
        self.exec_bp_ids = {}
        self.exec_interactive = False
        self.fork_bp_ids = []
        self.fork_interactive = False

    def in_user_step(self):
        return False

    def handle_self_trap(self, _thread):
        return None

    def handle_analysis_cloak_hit(self, bp_id):
        return CRITICAL if bp_id == 91 else None

    def cont(self):
        raise AssertionError("critical cloak error resumed the process")


class HeadlessCloakFailureTests(unittest.TestCase):
    def test_stop_handler_surfaces_critical_cloak_stop(self):
        session = AgentSession.__new__(AgentSession)
        session.dbg = FakeDebugger()
        session._console = []

        auto_continued = session._try_auto_anti_debug()

        self.assertFalse(auto_continued)
        self.assertIn("[anti-analysis] " + CRITICAL, session._console)

    def test_dispatch_rejects_next_resume_without_entering_event_pump(self):
        session = AgentSession.__new__(AgentSession)
        session.dbg = FakeDebugger()
        session._pending = None
        session._pump = mock.Mock(return_value={"ok": True, "event": "running"})

        result = session.dispatch("continue", {}, poll_cb=None)

        self.assertEqual(result, {"ok": False, "error": CRITICAL})
        session._pump.assert_not_called()


class GuiCloakFailureTests(unittest.TestCase):
    def make_engine(self):
        engine = Engine.__new__(Engine)
        engine.dbg = FakeDebugger()
        engine.tracer = types.SimpleNamespace(enabled=False)
        engine._resuming = False
        engine._disasm_follow = 0x1234
        engine._pending_exec = None
        engine._pending_fork = None
        engine._console = mock.Mock()
        engine._emit = mock.Mock()
        engine._emit_state = mock.Mock()
        return engine

    def test_stop_handler_emits_stopped_state_for_critical_cloak_error(self):
        engine = self.make_engine()

        handled = engine._handle_anti_debug_hit()

        self.assertTrue(handled)
        engine._console.assert_called_once_with(
            "[anti-analysis] " + CRITICAL, error=True
        )
        engine._emit_state.assert_called_once_with()
        self.assertFalse(engine._resuming)

    def test_resume_gate_rejects_critical_error_before_running_state(self):
        engine = self.make_engine()

        allowed = engine._begin_resume()

        self.assertFalse(allowed)
        self.assertFalse(engine._resuming)
        self.assertEqual(engine._disasm_follow, 0x1234)
        engine._console.assert_called_once_with(
            "[anti-analysis] " + CRITICAL, error=True
        )
        engine._emit_state.assert_called_once_with()


class GuiStopEventTests(unittest.TestCase):
    def test_raw_relaunch_forgets_stop_identity_even_when_command_fails(self):
        engine = Engine.__new__(Engine)
        engine.dbg = mock.Mock()
        engine.dbg.process = None
        engine.dbg.handle_command.return_value = (False, "", "launch failed")
        engine.dbg.ensure_listening.return_value = False
        engine._last_stop_event_key = (2079, 42)
        engine._console = mock.Mock()

        engine._c_run_cmd({"cmd": "run"})

        self.assertIsNone(engine._last_stop_event_key)

    def test_failed_restart_forgets_stop_identity_before_launch(self):
        engine = Engine.__new__(Engine)
        engine.attach_pid = None
        engine.program_args = []
        engine.dbg = mock.Mock()
        engine.dbg.target.IsValid.return_value = True
        engine.dbg.process = None
        engine.dbg.launch.side_effect = RuntimeError("launch failed")
        engine._interpose_stop = mock.Mock()
        engine._interpose_thread = None
        engine._hidden_bp_ids = mock.Mock(return_value=set())
        engine._last_stop_event_key = (2079, 42)
        engine._console = mock.Mock()

        engine._c_restart({})

        self.assertIsNone(engine._last_stop_event_key)

    def test_target_change_forgets_previous_stop_identity(self):
        engine = Engine.__new__(Engine)
        engine.tracer = types.SimpleNamespace(enabled=False)
        engine._pending_exec = None
        engine._pending_fork = None
        engine._resuming = False
        engine._prev_regs = {}
        engine._annot_cache = {}
        engine._strings_bin = []
        engine._strings_live = []
        engine._mem_follow = None
        engine._disasm_follow = None
        engine._last_stop_event_key = (2079, 42)

        engine._prepare_target_change()

        self.assertIsNone(engine._last_stop_event_key)

    def test_duplicate_internal_stop_is_not_exposed_as_user_stop(self):
        process = mock.Mock()
        process.IsValid.return_value = True
        process.GetState.return_value = FAKE_LLDB.eStateStopped
        process.GetProcessID.return_value = 2079
        process.GetStopID.return_value = 42

        debugger = mock.Mock()
        debugger.process = process
        debugger.analysis_cloak.validate_integrity.return_value = (True, "ok")
        debugger.in_user_step.return_value = False
        debugger.in_fork_shield.return_value = False

        engine = Engine.__new__(Engine)
        engine.dbg = debugger
        engine.tracer = types.SimpleNamespace(enabled=False, hardware_bp_ids=set())
        engine._resuming = False
        engine._last_stop_event_key = None
        engine._console = mock.Mock()
        engine._emit_state = mock.Mock()
        engine._handle_possible_trace_hit = mock.Mock(return_value=False)
        engine._handle_anti_debug_hit = mock.Mock(side_effect=(True, False))

        event = StopEvent(
            state=FAKE_LLDB.eStateStopped,
            description="stopped",
            process_id=2079,
            stop_id=42,
        )
        engine._on_stop_event(event)
        engine._on_stop_event(event)

        engine._handle_anti_debug_hit.assert_called_once_with()
        engine._console.assert_not_called()
        engine._emit_state.assert_not_called()
        self.assertFalse(engine._resuming)


if __name__ == "__main__":
    unittest.main()
