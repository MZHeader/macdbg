from pathlib import Path
import types
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
ENGINE_SOURCE = (ROOT / "GUI/server/engine.py").read_text()
APP_SOURCE = (ROOT / "GUI/web/app.js").read_text()
README_SOURCE = (ROOT / "README.md").read_text()
AGENT_SKILL_SOURCE = (ROOT / ".claude/skills/macdbg-agent/SKILL.md").read_text()
GUI_README_SOURCE = (ROOT / "GUI/README-GUI.md").read_text()
PYPROJECT_SOURCE = (ROOT / "pyproject.toml").read_text()
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


class DocumentationContractTests(unittest.TestCase):
    def test_readme_documents_analysis_cloak_contract(self):
        for term in (
            "analysis_cloak",
            "kern.hv_vmm_present",
            "IOPlatformUUID",
            "hardware breakpoints",
            "fork-tree",
        ):
            self.assertIn(term, README_SOURCE)

    def test_agent_skill_documents_analysis_cloak_command(self):
        self.assertIn("`analysis_cloak`", AGENT_SKILL_SOURCE)

    def test_dump_docs_state_capture_bounds(self):
        for document in (README_SOURCE, AGENT_SKILL_SOURCE):
            with self.subTest(document="README" if document is README_SOURCE
                              else "agent skill"):
                for term in ("1 MiB", "8,192", "unreadable", "shortened"):
                    self.assertIn(term, document)

    def test_docs_publish_synthetic_fixture_verification_commands(self):
        commands = (
            "tests.test_anti_analysis_policy tests.test_analysis_cloak_surfaces",
            "make -C tests/integration clean all",
            "tests.integration.test_analysis_cloak",
            "test_combined_checks_recover_exact_chacha20_payload",
            "./agent.sh list",
            "synthetic fixture plaintext",
        )
        for document in (README_SOURCE, AGENT_SKILL_SOURCE):
            with self.subTest(document="README" if document is README_SOURCE
                              else "agent skill"):
                for term in commands:
                    self.assertIn(term, document)

    def test_project_metadata_describes_current_frontends(self):
        self.assertIn("GUI and headless", PYPROJECT_SOURCE)
        self.assertNotIn("Textual TUI", PYPROJECT_SOURCE)
        self.assertNotIn('"tui"', PYPROJECT_SOURCE)

    def test_gui_readme_uses_repository_root_app_path(self):
        self.assertIn("produces macdbg.app", GUI_README_SOURCE)
        self.assertNotIn("GUI/macdbg.app", GUI_README_SOURCE)


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


class AllAntiDebugger:
    """Stateful GUI boundary fake that models breakpoint mode and ownership."""

    def __init__(self, *, preenabled_direct=False):
        self.calls = []
        self.analysis_cloak = FakeCloak()
        self.analysis_cloak.debugger = self
        self.anti_ptrace_bp_id = 0
        self.direct_syscall_bp_ids = {40} if preenabled_direct else set()
        self.direct_syscall_hardware = False if preenabled_direct else None
        self.anti_mach_bp_id = 0
        self.anti_sysctl_bp_id = 0
        self.anti_csops_bp_id = 0
        self.anti_timing_bp_ids = set()
        self._scrub_parent = False
        self.anti_sigtrap_on = False
        self.hw_breakpoints = False
        self.fork_mode = "none"
        self.fork_interactive = False
        self.interpose_enabled = False
        self.exec_bp_ids = {}
        self.exec_interactive = False
        self._next_direct_id = 41

        def validate_integrity(_hardware_ids):
            safe = (not self.direct_syscall_bp_ids
                    or self.direct_syscall_hardware is True)
            return (safe, "target __text integrity protected" if safe else
                    "software breakpoint modifies target __text")

        self.analysis_cloak.validate_integrity = validate_integrity

    def _set(self, call, attr, value):
        self.calls.append(call)
        setattr(self, attr, value)
        return True, call

    def enable_analysis_cloak(self):
        self.calls.append("enable_analysis_cloak")
        self.analysis_cloak.enabled = True
        return True, "analysis cloak enabled"

    def disable_analysis_cloak(self):
        self.calls.append("disable_analysis_cloak")
        self.analysis_cloak.enabled = False
        return True, "analysis cloak disabled"

    def enable_direct_syscall_scan(self):
        self.calls.append("enable_direct_syscall_scan")
        if self.direct_syscall_bp_ids:
            return True, "already armed"
        self.direct_syscall_bp_ids = {self._next_direct_id}
        self._next_direct_id += 1
        self.direct_syscall_hardware = self.analysis_cloak.enabled
        return True, "direct scan enabled"

    def disable_direct_syscall_scan(self):
        self.calls.append("disable_direct_syscall_scan")
        self.direct_syscall_bp_ids = set()
        self.direct_syscall_hardware = None
        return True, "direct scan disabled"

    def enable_anti_ptrace(self):
        return self._set("enable_anti_ptrace", "anti_ptrace_bp_id", 1)

    def disable_anti_ptrace(self):
        return self._set("disable_anti_ptrace", "anti_ptrace_bp_id", 0)

    def enable_anti_mach_ports(self):
        return self._set("enable_anti_mach_ports", "anti_mach_bp_id", 2)

    def disable_anti_mach_ports(self):
        return self._set("disable_anti_mach_ports", "anti_mach_bp_id", 0)

    def enable_anti_sysctl(self):
        return self._set("enable_anti_sysctl", "anti_sysctl_bp_id", 3)

    def disable_anti_sysctl(self):
        return self._set("disable_anti_sysctl", "anti_sysctl_bp_id", 0)

    def enable_anti_csops(self):
        return self._set("enable_anti_csops", "anti_csops_bp_id", 4)

    def disable_anti_csops(self):
        return self._set("disable_anti_csops", "anti_csops_bp_id", 0)

    def enable_anti_timing(self):
        return self._set("enable_anti_timing", "anti_timing_bp_ids", {5})

    def disable_anti_timing(self):
        return self._set("disable_anti_timing", "anti_timing_bp_ids", set())

    def enable_anti_parent(self):
        return self._set("enable_anti_parent", "_scrub_parent", True)

    def disable_anti_parent(self):
        return self._set("disable_anti_parent", "_scrub_parent", False)

    def enable_anti_sigtrap(self):
        return self._set("enable_anti_sigtrap", "anti_sigtrap_on", True)

    def disable_anti_sigtrap(self):
        return self._set("disable_anti_sigtrap", "anti_sigtrap_on", False)


def make_all_anti_engine(*, preenabled_direct=False):
    from tests.test_sysctl_cloak_orchestration import Engine

    engine = Engine.__new__(Engine)
    engine.dbg = AllAntiDebugger(preenabled_direct=preenabled_direct)
    engine.tracer = types.SimpleNamespace(hardware=False, hardware_bp_ids=set())
    engine._console = mock.Mock()
    return engine


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

    def test_all_anti_creates_safe_direct_scan_and_reverse_cleanup(self):
        engine = make_all_anti_engine()

        engine._t_all_anti()

        status = engine._defense_states()
        self.assertTrue(status["all_anti"])
        self.assertTrue(status["analysis_cloak_safe"])
        self.assertTrue(engine.dbg.direct_syscall_hardware)

        # The cloak must not own the independently armed constituent defenses.
        engine._t_analysis_cloak()
        self.assertTrue(engine.dbg.anti_sysctl_bp_id)
        self.assertTrue(engine.dbg._scrub_parent)
        self.assertTrue(engine.dbg.anti_timing_bp_ids)
        engine._t_analysis_cloak()

        engine._t_all_anti()

        self.assertFalse(engine.dbg.analysis_cloak.enabled)
        self.assertFalse(engine.dbg.direct_syscall_bp_ids)
        self.assertFalse(engine.dbg.anti_sysctl_bp_id)
        self.assertFalse(engine.dbg._scrub_parent)
        self.assertFalse(engine.dbg.anti_timing_bp_ids)
        self.assertGreater(
            engine.dbg.calls.index("disable_direct_syscall_scan"),
            engine.dbg.calls.index("enable_direct_syscall_scan"),
        )

    def test_all_anti_recreates_preenabled_direct_scan_as_hardware(self):
        engine = make_all_anti_engine(preenabled_direct=True)

        engine._t_all_anti()

        self.assertNotIn(40, engine.dbg.direct_syscall_bp_ids)
        self.assertTrue(engine.dbg.direct_syscall_hardware)
        self.assertTrue(engine._defense_states()["analysis_cloak_safe"])

    def test_all_anti_restores_preenabled_scan_if_cloak_enable_fails(self):
        engine = make_all_anti_engine(preenabled_direct=True)
        engine.dbg.enable_analysis_cloak = mock.Mock(
            return_value=(False, "synthetic cloak failure"))

        engine._t_all_anti()

        self.assertTrue(engine.dbg.direct_syscall_bp_ids)
        self.assertIs(engine.dbg.direct_syscall_hardware, False)
        engine._console.assert_any_call("synthetic cloak failure", error=True)

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
