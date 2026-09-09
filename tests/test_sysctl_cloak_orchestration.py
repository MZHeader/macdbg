import sys
import types
import unittest
from unittest import mock


FAKE_LLDB = types.SimpleNamespace(
    eStopReasonBreakpoint=3,
    eStateStopped=5,
)

with mock.patch.dict(sys.modules, {"lldb": FAKE_LLDB}):
    from GUI.server.engine import Engine
    from macdbg.agent.session import AgentSession


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


if __name__ == "__main__":
    unittest.main()
