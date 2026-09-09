from pathlib import Path
import types
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
ENGINE_SOURCE = (ROOT / "GUI/server/engine.py").read_text()
APP_SOURCE = (ROOT / "GUI/web/app.js").read_text()
INCOMPATIBLE = "analysis cloak is incompatible with fork-tree tracing in v1"


class SurfaceContractTests(unittest.TestCase):
    def test_gui_exposes_analysis_cloak(self):
        self.assertIn("['analysis_cloak', 'Analysis cloak'", APP_SOURCE)
        self.assertIn(
            "environment · parent · VM/hardware · images · "
            "text integrity · timing",
            APP_SOURCE,
        )

    def test_frontend_renders_cloak_safety_and_error_status(self):
        self.assertIn("analysis_cloak_safe", APP_SOURCE)
        self.assertIn("analysis_cloak_error", APP_SOURCE)
        self.assertIn("unsafe ·", APP_SOURCE)

    def test_engine_exposes_toggle_and_all_status_fields(self):
        self.assertIn('"analysis_cloak": Engine._t_analysis_cloak', ENGINE_SOURCE)
        for field in (
            "analysis_cloak",
            "analysis_cloak_safe",
            "analysis_cloak_resolved",
            "analysis_cloak_deferred",
            "analysis_cloak_error",
        ):
            self.assertIn('"{}"'.format(field), ENGINE_SOURCE)

    def test_existing_cloak_safety_hooks_remain_in_gui_dispatch(self):
        hidden = ENGINE_SOURCE.index("ids.update(d.analysis_cloak.hidden_bp_ids())")
        cloak_hit = ENGINE_SOURCE.index(
            "self.dbg.handle_analysis_cloak_hit(bp_id)")
        ordinary_hit = ENGINE_SOURCE.index(
            "self.dbg.handle_anti_ptrace_hit")
        integrity = ENGINE_SOURCE.index(
            "self.dbg.analysis_cloak.validate_integrity(")
        begin_resume = ENGINE_SOURCE.index("def _begin_resume")
        self.assertGreater(hidden, 0)
        self.assertLess(cloak_hit, ordinary_hit)
        self.assertLess(integrity, begin_resume)
        self.assertIn(
            "self.dbg.analysis_cloak.validate_integrity(",
            ENGINE_SOURCE[begin_resume:],
        )


class FakeCloak:
    def __init__(self, *, enabled=False, safe=True, error=None,
                 resolved=4, deferred=1):
        self.enabled = enabled
        self.safe = safe
        self.error = error
        self.resolved = resolved
        self.deferred = deferred

    def status(self):
        return {
            "enabled": self.enabled,
            "resolved": self.resolved,
            "deferred": self.deferred,
            "error": self.error,
        }

    def validate_resume(self):
        return self.safe, self.error or "analysis cloak ready"

    def validate_integrity(self, hardware_ids):
        return self.safe, self.error or "target __text integrity protected"

    def hidden_bp_ids(self):
        return {77}


def make_engine(*, enabled=False, safe=True, error=None):
    from tests.test_sysctl_cloak_orchestration import Engine

    engine = Engine.__new__(Engine)
    cloak = FakeCloak(enabled=enabled, safe=safe, error=error)
    calls = []

    def operation(name, state=None, result=(True, "ok")):
        def run():
            calls.append(name)
            if state is not None:
                setattr(debugger, state[0], state[1])
            return result
        return run

    debugger = types.SimpleNamespace(
        analysis_cloak=cloak,
        anti_ptrace_bp_id=1,
        direct_syscall_bp_ids={2},
        anti_mach_bp_id=3,
        anti_sysctl_bp_id=4,
        anti_csops_bp_id=5,
        anti_timing_bp_ids={6},
        _scrub_parent=True,
        anti_sigtrap_on=True,
        hw_breakpoints=False,
        fork_mode="none",
        fork_interactive=False,
        interpose_enabled=False,
        exec_bp_ids={},
        exec_interactive=False,
    )
    debugger.enable_analysis_cloak = operation(
        "enable_analysis_cloak", ("analysis_cloak", cloak))
    debugger.disable_analysis_cloak = operation(
        "disable_analysis_cloak", ("analysis_cloak", cloak))
    for name in (
        "anti_ptrace", "direct_syscall_scan", "anti_mach_ports",
        "anti_sysctl", "anti_csops", "anti_timing", "anti_parent",
        "anti_sigtrap",
    ):
        setattr(debugger, "enable_" + name, operation("enable_" + name))
        setattr(debugger, "disable_" + name, operation("disable_" + name))

    engine.dbg = debugger
    engine.tracer = types.SimpleNamespace(hardware=False, hardware_bp_ids=set())
    engine.attach_pid = None
    engine._console = mock.Mock()
    engine._emit_state = mock.Mock()
    engine._c_restart = mock.Mock()
    engine._calls = calls
    return engine


class GuiBehaviorTests(unittest.TestCase):
    def test_toggle_enable_failure_is_exact_error_then_state_refresh(self):
        engine = make_engine()
        engine.dbg.enable_analysis_cloak = mock.Mock(
            return_value=(False, "synthetic cloak failure"))

        engine._c_defense({"key": "analysis_cloak"})

        engine.dbg.enable_analysis_cloak.assert_called_once_with()
        engine._console.assert_called_once_with(
            "synthetic cloak failure", error=True)
        engine._emit_state.assert_called_once_with()

    def test_toggle_uses_enable_then_disable_pair(self):
        engine = make_engine()
        engine.dbg.enable_analysis_cloak = mock.Mock(
            side_effect=lambda: (setattr(engine.dbg.analysis_cloak,
                                         "enabled", True) or
                                 (True, "analysis cloak enabled")))
        engine.dbg.disable_analysis_cloak = mock.Mock(
            return_value=(True, "analysis cloak disabled"))

        engine._c_defense({"key": "analysis_cloak"})
        engine._c_defense({"key": "analysis_cloak"})

        engine.dbg.enable_analysis_cloak.assert_called_once_with()
        engine.dbg.disable_analysis_cloak.assert_called_once_with()

    def test_all_anti_enables_cloak_after_individual_defenses(self):
        engine = make_engine()
        engine.dbg.analysis_cloak.enabled = False
        engine.dbg.anti_ptrace_bp_id = 0

        engine._t_all_anti()

        self.assertEqual(engine._calls[-1], "enable_analysis_cloak")

    def test_defense_status_reports_safe_and_error_fields(self):
        engine = make_engine(
            enabled=True, safe=False, error="software breakpoint modifies text")

        status = engine._defense_states()

        self.assertTrue(status.get("analysis_cloak"))
        self.assertIs(status.get("analysis_cloak_safe"), False)
        self.assertEqual(status.get("analysis_cloak_resolved"), 4)
        self.assertEqual(status.get("analysis_cloak_deferred"), 1)
        self.assertEqual(
            status.get("analysis_cloak_error"),
            "software breakpoint modifies text",
        )

    def test_fork_trace_is_rejected_immediately_while_cloak_enabled(self):
        engine = make_engine(enabled=True)

        engine._c_fork_trace({})

        self.assertFalse(engine.dbg.interpose_enabled)
        engine._c_restart.assert_not_called()
        engine._console.assert_called_once_with(INCOMPATIBLE, error=True)
        engine._emit_state.assert_called_once_with()

    def test_cloak_incompatibility_wins_for_attached_process_too(self):
        engine = make_engine(enabled=True)
        engine.attach_pid = 123

        engine._c_fork_trace({})

        engine._console.assert_called_once_with(INCOMPATIBLE, error=True)
        engine._emit_state.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
