import unittest
from unittest.mock import Mock
from macdbg.agent.session import AgentSession
from GUI.server.engine import Engine


class PendingDecisionTests(unittest.TestCase):
    def test_failed_headless_decisions_remain_pending(self):
        for kind, symbol, decision in (("exec", "system", "fake"), ("fork", "fork", "child")):
            with self.subTest(kind=kind):
                session = AgentSession.__new__(AgentSession)
                pending = {"kind": kind, "symbol": symbol, "bp_id": 1}
                session._pending = pending
                session.dbg = Mock()
                getattr(session.dbg, "resolve_" + kind).side_effect = RuntimeError("cannot return")
                session._pump = lambda resume, **kwargs: resume()
                with self.assertRaisesRegex(RuntimeError, "cannot return"):
                    getattr(session, "_decide_" + kind)(decision, 1, None)
                self.assertIs(session._pending, pending)

    def test_gui_invalid_or_failed_fork_choice_does_not_clear_decision(self):
        engine = Engine.__new__(Engine)
        engine._pending_fork = ("fork",)
        engine.dbg = Mock()
        engine._console = Mock()
        engine._emit_subscriber_state = Mock()
        engine._c_decide_fork({"decision": "typo"})
        engine.dbg.resolve_fork.assert_not_called()
        self.assertEqual(engine._pending_fork, ("fork",))
        engine.dbg.resolve_fork.side_effect = RuntimeError("cannot return")
        engine._c_decide_fork({"decision": "child"})
        self.assertEqual(engine._pending_fork, ("fork",))
