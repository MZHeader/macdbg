import unittest

from macdbg.core.anti_analysis import AnalysisCloak


class FakeBreakpoint:
    def __init__(self, bp_id):
        self.bp_id = bp_id

    def GetID(self):
        return self.bp_id


class FakeTarget:
    def __init__(self, bp_ids=()):
        self.breakpoints = [FakeBreakpoint(bp_id) for bp_id in bp_ids]

    def GetNumBreakpoints(self):
        return len(self.breakpoints)

    def GetBreakpointAtIndex(self, index):
        return self.breakpoints[index]

    def BreakpointDelete(self, bp_id):
        before = len(self.breakpoints)
        self.breakpoints = [bp for bp in self.breakpoints
                            if bp.GetID() != bp_id]
        return len(self.breakpoints) != before

    def add(self, bp_id):
        self.breakpoints.append(FakeBreakpoint(bp_id))

    def ids(self):
        return {bp.GetID() for bp in self.breakpoints}


class FakeDebugger:
    DEFENSE_IDS = {
        "anti_sysctl": 101,
        "anti_parent": 102,
    }

    def __init__(self, *, stopped_at_entry=True, preenabled=(),
                 fail_defense=None, fail_scrub=False,
                 partial_failure_bp=None, extra_success_bp=None):
        self.calls = []
        self.target = FakeTarget({7})
        self.stopped_at_entry = stopped_at_entry
        self.fail_defense = fail_defense
        self.fail_scrub = fail_scrub
        self.partial_failure_bp = partial_failure_bp
        self.extra_success_bp = extra_success_bp
        self._scrub_ptraced = "anti_sysctl" in preenabled
        self._scrub_parent = "anti_parent" in preenabled
        for name in preenabled:
            self.target.add(self.DEFENSE_IDS[name])

    def is_stopped_at_entry_point(self):
        return self.stopped_at_entry

    def _enable(self, name):
        self.calls.append("enable_" + name)
        if self.fail_defense == name:
            if self.partial_failure_bp is not None:
                self.target.add(self.partial_failure_bp)
            return False, "synthetic {} failure".format(name)
        bp_id = self.DEFENSE_IDS[name]
        self.target.add(bp_id)
        if name == "anti_sysctl":
            self._scrub_ptraced = True
        elif name == "anti_parent":
            self._scrub_parent = True
            if self.extra_success_bp is not None:
                self.target.add(self.extra_success_bp)
        return True, "enabled"

    def _disable(self, name):
        self.calls.append("disable_" + name)
        bp_id = self.DEFENSE_IDS[name]
        self.target.BreakpointDelete(bp_id)
        if name == "anti_sysctl":
            self._scrub_ptraced = False
        elif name == "anti_parent":
            self._scrub_parent = False
        return True, "disabled"

    def enable_anti_sysctl(self):
        return self._enable("anti_sysctl")

    def disable_anti_sysctl(self):
        return self._disable("anti_sysctl")

    def enable_anti_parent(self):
        return self._enable("anti_parent")

    def disable_anti_parent(self):
        return self._disable("anti_parent")

    def handle_command(self, _command):
        if self.fail_scrub:
            return False, "", "synthetic scrub failure"
        return True, "", ""


class AnalysisCloakControllerTests(unittest.TestCase):
    def test_composite_does_not_enable_synthetic_timing(self):
        debugger = FakeDebugger()

        self.assertTrue(AnalysisCloak(debugger).enable()[0])

        self.assertNotIn("enable_anti_timing", debugger.calls)

    def test_rejects_enable_away_from_entry_without_changes(self):
        debugger = FakeDebugger(stopped_at_entry=False)
        cloak = AnalysisCloak(debugger)

        ok, message = cloak.enable()

        self.assertFalse(ok)
        self.assertIn("entry point", message)
        self.assertFalse(cloak.enabled)
        self.assertEqual(debugger.target.ids(), {7})

    def test_disable_releases_owned_defenses_and_stops_filtering(self):
        debugger = FakeDebugger()
        cloak = AnalysisCloak(debugger)
        entries = ["PATH=/usr/bin", "NSZombieEnabled=YES"]

        self.assertTrue(cloak.enable()[0])
        self.assertEqual(cloak.filter_launch_environment(entries),
                         ["PATH=/usr/bin"])
        self.assertTrue(cloak.disable()[0])

        self.assertFalse(cloak.enabled)
        self.assertEqual(cloak.filter_launch_environment(entries), entries)
        self.assertFalse(debugger._scrub_ptraced)
        self.assertFalse(debugger._scrub_parent)
        self.assertEqual(debugger.target.ids(), {7})

    def test_disable_preserves_a_preenabled_defense(self):
        debugger = FakeDebugger(preenabled={"anti_parent"})
        cloak = AnalysisCloak(debugger)

        self.assertTrue(cloak.enable()[0])
        self.assertTrue(cloak.disable()[0])

        self.assertTrue(debugger._scrub_parent)
        self.assertIn(FakeDebugger.DEFENSE_IDS["anti_parent"],
                      debugger.target.ids())
        self.assertEqual(debugger.target.ids(), {7, 102})

    def test_acquisition_failure_removes_partial_breakpoints_and_rolls_back(self):
        debugger = FakeDebugger(fail_defense="anti_parent",
                                partial_failure_bp=999)
        cloak = AnalysisCloak(debugger)

        ok, message = cloak.enable()

        self.assertFalse(ok)
        self.assertIn("anti_parent", message)
        self.assertFalse(cloak.enabled)
        self.assertFalse(debugger._scrub_ptraced)
        self.assertFalse(debugger._scrub_parent)
        self.assertEqual(debugger.target.ids(), {7})

    def test_scrub_failure_rolls_back_acquired_defenses(self):
        debugger = FakeDebugger(fail_scrub=True)
        cloak = AnalysisCloak(debugger)

        ok, message = cloak.enable()

        self.assertFalse(ok)
        self.assertIn("could not unset", message)
        self.assertFalse(cloak.enabled)
        self.assertFalse(debugger._scrub_ptraced)
        self.assertFalse(debugger._scrub_parent)
        self.assertEqual(debugger.target.ids(), {7})

    def test_disable_removes_untracked_breakpoint_from_successful_acquisition(self):
        debugger = FakeDebugger(extra_success_bp=888)
        cloak = AnalysisCloak(debugger)

        self.assertTrue(cloak.enable()[0])
        self.assertIn(888, debugger.target.ids())
        self.assertTrue(cloak.disable()[0])

        self.assertEqual(debugger.target.ids(), {7})


if __name__ == "__main__":
    unittest.main()
